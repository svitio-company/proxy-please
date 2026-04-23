// Transparent proxy with TLS pass-through (SNI routing, no decryption)
// - Intercepts HTTP (port 8080 ← iptables redirect from 80) and
//   HTTPS (port 8443 ← iptables redirect from 443)
// - Denies all traffic by default; whitelist via ALLOWED_HOSTS env var
// - For HTTP: extracts Host header for allow/deny
// - For HTTPS: extracts SNI from TLS ClientHello (no decryption)

use std::collections::HashSet;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;

/// Port where HTTP traffic is redirected (iptables: 80 → 8080)
const HTTP_PROXY_PORT: u16 = 8080;
/// Port where HTTPS traffic is redirected (iptables: 443 → 8443)
const HTTPS_PROXY_PORT: u16 = 8443;

/// Max bytes to buffer while searching for HTTP headers
const HTTP_HEADER_BUF: usize = 8192;
/// Max bytes to peek for TLS ClientHello SNI extraction
const TLS_PEEK_BUF: usize = 4096;

/// Linux netfilter SO_ORIGINAL_DST socket option (value 80, IPPROTO_IP level)
#[cfg(target_os = "linux")]
const SO_ORIGINAL_DST: libc::c_int = 80;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Config {
    /// Lowercase host patterns; supports exact ("example.com") and
    /// single-level wildcard ("*.example.com")
    allowed_hosts: HashSet<String>,
}

impl Config {
    fn from_env() -> Self {
        let raw = env::var("ALLOWED_HOSTS").unwrap_or_default();
        let allowed_hosts = raw
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect::<HashSet<_>>();
        Self { allowed_hosts }
    }

    fn is_allowed(&self, host: &str) -> bool {
        let host = host.to_lowercase();
        let host = strip_port(&host);

        // Exact match
        if self.allowed_hosts.contains(host) {
            return true;
        }

        // Iterative wildcard match: match *.example.com, *.com, etc.
        let mut parts: Vec<&str> = host.split('.').collect();
        while !parts.is_empty() {
            parts.remove(0);
            if parts.is_empty() {
                break;
            }
            let wildcard = format!("*.{}", parts.join("."));
            if self.allowed_hosts.contains(&wildcard) {
                return true;
            }
        }

        false
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config = Arc::new(Config::from_env());

    if config.allowed_hosts.is_empty() {
        tracing::warn!("ALLOWED_HOSTS is not set – all traffic will be denied");
    } else {
        tracing::info!("Allowed hosts: {:?}", config.allowed_hosts);
    }

    let http_listener = TcpListener::bind(("0.0.0.0", HTTP_PROXY_PORT))
        .await
        .unwrap_or_else(|e| panic!("Failed to bind HTTP proxy port {HTTP_PROXY_PORT}: {e}"));

    let https_listener = TcpListener::bind(("0.0.0.0", HTTPS_PROXY_PORT))
        .await
        .unwrap_or_else(|e| panic!("Failed to bind HTTPS proxy port {HTTPS_PROXY_PORT}: {e}"));

    tracing::info!("HTTP  proxy listening on :{HTTP_PROXY_PORT}  (redirected from :80)");
    tracing::info!("HTTPS proxy listening on :{HTTPS_PROXY_PORT} (redirected from :443)");

    let cfg_h = config.clone();
    let cfg_s = config.clone();

    // Limit max concurrent connections to prevent resource exhaustion
    let semaphore = Arc::new(Semaphore::new(10000));

    tokio::join!(
        accept_loop(http_listener, cfg_h, false, semaphore.clone()),
        accept_loop(https_listener, cfg_s, true, semaphore),
    );
}

// ---------------------------------------------------------------------------
// Accept loop
// ---------------------------------------------------------------------------

async fn accept_loop(listener: TcpListener, config: Arc<Config>, tls: bool, semaphore: Arc<Semaphore>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let cfg = config.clone();
                let sem = semaphore.clone();
                tokio::spawn(async move {
                    let _permit = sem.acquire().await.ok();
                    handle_connection(stream, peer, cfg, tls).await;
                });
            }
            Err(e) => tracing::error!("Accept error: {e}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Connection handler dispatcher
// ---------------------------------------------------------------------------

async fn handle_connection(stream: TcpStream, peer: SocketAddr, config: Arc<Config>, tls: bool) {
    let original_dst = match get_original_dst(&stream) {
        Some(d) => d,
        None => {
            tracing::warn!(%peer, "Could not read SO_ORIGINAL_DST – dropping connection");
            return;
        }
    };

    if tls {
        handle_https(stream, peer, original_dst, config).await;
    } else {
        handle_http(stream, peer, original_dst, config).await;
    }
}

// ---------------------------------------------------------------------------
// HTTP handler
// ---------------------------------------------------------------------------

async fn handle_http(
    mut client: TcpStream,
    peer: SocketAddr,
    dst: SocketAddr,
    config: Arc<Config>,
) {
    let mut buf = vec![0u8; HTTP_HEADER_BUF];
    let mut total = 0usize;

    // Accumulate data until we see the end-of-headers marker \r\n\r\n
    loop {
        if total == buf.len() {
            break; // buffer full – proceed with what we have
        }
        let read_future = client.read(&mut buf[total..]);
        match timeout(Duration::from_secs(10), read_future).await {
            Ok(Ok(0)) => return, // client disconnected
            Ok(Ok(n)) => total += n,
            Ok(Err(e)) => {
                tracing::debug!(%peer, "HTTP read error: {e}");
                return;
            }
            Err(_) => {
                tracing::warn!(%peer, "HTTP read timeout");
                return;
            }
        }
        if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let host = match parse_http_host(&buf[..total]) {
        Some(h) => h,
        None => {
            tracing::warn!(%peer, %dst, "No Host header – denying");
            let _ = client
                .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
            return;
        }
    };

    if !config.is_allowed(&host) {
        tracing::info!(%peer, %dst, host = %host, "DENIED  HTTP");
        let _ = client
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
        return;
    }

    tracing::info!(%peer, %dst, host = %host, "ALLOWED HTTP");

    let mut upstream = match TcpStream::connect(dst).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(%dst, "Upstream connect failed: {e}");
            let _ = client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
            return;
        }
    };

    // Forward the already-read bytes first
    if upstream.write_all(&buf[..total]).await.is_err() {
        return;
    }

    proxy_bidirectional(client, upstream).await;
}

// ---------------------------------------------------------------------------
// HTTPS handler (TLS pass-through, SNI-based routing)
// ---------------------------------------------------------------------------

async fn handle_https(
    mut client: TcpStream,
    peer: SocketAddr,
    dst: SocketAddr,
    config: Arc<Config>,
) {
    let mut buf = vec![0u8; TLS_PEEK_BUF];
    let mut total = 0usize;
    let mut sni = None;

    // Buffer data until we can parse SNI or buffer fills
    loop {
        if total == buf.len() {
            break;
        }

        let read_future = client.read(&mut buf[total..]);
        match timeout(Duration::from_secs(10), read_future).await {
            Ok(Ok(0)) => return,
            Ok(Ok(n)) => {
                total += n;
                // Try parsing SNI with the accumulated data
                if let Some(s) = parse_sni(&buf[..total]) {
                    sni = Some(s);
                    break;
                }
            }
            Ok(Err(_)) | Err(_) => return, // Handle error or timeout identically: drop socket
        }
    }

    let sni = match sni {
        Some(s) => s,
        None => {
            tracing::warn!(%peer, %dst, "No SNI in ClientHello (or malformed) – denying");
            return;
        }
    };

    if !config.is_allowed(&sni) {
        tracing::info!(%peer, %dst, sni = %sni, "DENIED  HTTPS");
        return; // close connection silently (no TLS error possible without decryption)
    }

    tracing::info!(%peer, %dst, sni = %sni, "ALLOWED HTTPS");

    let mut upstream = match TcpStream::connect(dst).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(%dst, "Upstream connect failed: {e}");
            return;
        }
    };

    // Forward the accumulated bytes first
    if upstream.write_all(&buf[..total]).await.is_err() {
        return;
    }

    proxy_bidirectional(client, upstream).await;
}

// ---------------------------------------------------------------------------
// Bidirectional byte-level proxy
// ---------------------------------------------------------------------------

async fn proxy_bidirectional(client: TcpStream, upstream: TcpStream) {
    let (mut cr, mut cw) = client.into_split();
    let (mut ur, mut uw) = upstream.into_split();

    let to_upstream = tokio::spawn(async move {
        let _ = io::copy(&mut cr, &mut uw).await;
        let _ = uw.shutdown().await;
    });
    let to_client = tokio::spawn(async move {
        let _ = io::copy(&mut ur, &mut cw).await;
        let _ = cw.shutdown().await;
    });

    let _ = tokio::join!(to_upstream, to_client);
}

// ---------------------------------------------------------------------------
// HTTP Host header parser
// ---------------------------------------------------------------------------

fn parse_http_host(data: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(data).ok()?;
    for line in text.lines() {
        if line.len() > 5 && line[..5].eq_ignore_ascii_case("host:") {
            let value = line[5..].trim();
            return Some(strip_port(value).to_string());
        }
    }
    None
}

fn strip_port(host: &str) -> &str {
    if host.starts_with('[') {
        if let Some(end) = host.rfind(']') {
            return &host[1..end];
        }
    }
    if let Some((h, _)) = host.rsplit_once(':') {
        h
    } else {
        host
    }
}

// ---------------------------------------------------------------------------
// TLS ClientHello SNI parser
// ---------------------------------------------------------------------------

/// Extract the SNI hostname from a raw TLS ClientHello record.
/// Returns `None` if the record is incomplete, malformed, or contains no SNI.
fn parse_sni(data: &[u8]) -> Option<String> {
    // ---- TLS record layer ----
    // [0]      content type  (22 = handshake)
    // [1..2]   legacy version
    // [3..4]   record length
    if data.len() < 5 || data[0] != 22 {
        return None;
    }

    // ---- Handshake header ----
    // [5]      handshake type (1 = ClientHello)
    // [6..8]   handshake length (3 bytes, big-endian)
    if data.len() < 9 || data[5] != 1 {
        return None;
    }

    let mut pos = 9usize; // beginning of ClientHello body

    macro_rules! need {
        ($n:expr) => {
            if pos + $n > data.len() {
                return None;
            }
        };
    }

    // client_version: 2 bytes
    need!(2);
    pos += 2;

    // random: 32 bytes
    need!(32);
    pos += 32;

    // session_id: 1-byte length prefix
    need!(1);
    let sid_len = data[pos] as usize;
    pos += 1;
    need!(sid_len);
    pos += sid_len;

    // cipher_suites: 2-byte length prefix
    need!(2);
    let cs_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    need!(cs_len);
    pos += cs_len;

    // compression_methods: 1-byte length prefix
    need!(1);
    let cm_len = data[pos] as usize;
    pos += 1;
    need!(cm_len);
    pos += cm_len;

    // extensions: 2-byte total length
    need!(2);
    let ext_total = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_total;

    // Walk extensions looking for type 0x0000 (SNI)
    while pos + 4 <= ext_end && pos + 4 <= data.len() {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 {
            // SNI extension body:
            // [0..1]  server_name_list length
            // [2]     name_type (0 = host_name)
            // [3..4]  name length
            // [5..]   name bytes
            if pos + 5 > data.len() {
                return None;
            }
            let name_type = data[pos + 2];
            if name_type != 0 {
                return None;
            }
            let name_len = u16::from_be_bytes([data[pos + 3], data[pos + 4]]) as usize;
            pos += 5;
            if pos + name_len > data.len() {
                return None;
            }
            return std::str::from_utf8(&data[pos..pos + name_len])
                .ok()
                .map(|s| s.to_string());
        }

        pos += ext_len;
    }

    None
}

// ---------------------------------------------------------------------------
// SO_ORIGINAL_DST – recover the pre-NAT destination address
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn get_original_dst(stream: &TcpStream) -> Option<SocketAddr> {
    use std::net::{IpAddr, Ipv4Addr};
    use std::os::unix::io::AsRawFd;

    let fd = stream.as_raw_fd();
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len: libc::socklen_t = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_IP,
            SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };

    if rc != 0 {
        return None;
    }

    let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    let port = u16::from_be(addr.sin_port);
    Some(SocketAddr::new(IpAddr::V4(ip), port))
}

/// Stub for non-Linux platforms (development only)
#[cfg(not(target_os = "linux"))]
fn get_original_dst(stream: &TcpStream) -> Option<SocketAddr> {
    // For local development on macOS/Windows, normally you'd use a fixed target via env 
    // or just assume local port 8080 forwards to some specific host.
    // For simplicity, we just use the stream's local address.
    stream.local_addr().ok()
}
