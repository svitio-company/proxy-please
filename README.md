# proxy-please

> *Your packets, please.* — A transparent egress proxy inspired by Papers, Please.

A transparent TCP proxy written in Rust. Designed to sit on a VM that receives traffic via an **Azure User-Defined Route (UDR)** and enforce an egress whitelist for HTTP and HTTPS traffic.

- **Default-deny** — all traffic is blocked unless the destination hostname is explicitly whitelisted via `ALLOWED_HOSTS`
- **HTTP** — allows/denies based on the `Host` request header
- **HTTPS** — allows/denies based on the **SNI hostname** extracted from the TLS `ClientHello` (Option A: TLS pass-through, no decryption)
- Runs in Docker with `network_mode: host` so iptables rules affect the real host network stack

---

## Architecture

```
Subnet VM / client
       │
       │  Azure UDR routes 0.0.0.0/0 → proxy VM
       ▼
Proxy VM — eth0
       │
       │  iptables PREROUTING (nat table)
       │    TCP :80  → REDIRECT :8080
       │    TCP :443 → REDIRECT :8443
       ▼
Rust proxy (this application)
       │
       ├── HTTP  (port 8080)
       │     Read first 8 KB, parse "Host:" header
       │     ✓ allowed → forward to original dst
       │     ✗ denied  → 403 Forbidden
       │
       └── HTTPS (port 8443)
             Peek first 4 KB, parse TLS ClientHello SNI extension
             ✓ allowed → forward to original dst (raw TLS bytes, no decryption)
             ✗ denied  → silent TCP close
                    │
                    ▼
             Original destination server
             (recovered via SO_ORIGINAL_DST)
```

### Why `SO_ORIGINAL_DST`?

When iptables redirects a packet, the destination IP/port changes to `127.0.0.1:<proxy-port>`. `SO_ORIGINAL_DST` is a Linux netfilter socket option that lets the proxy recover the **original** destination (the real server IP and port) so it can open the upstream connection correctly.

### No redirect loop

iptables PREROUTING rules only match **incoming** traffic. The proxy's own outgoing connections to the upstream server travel through the `OUTPUT` chain, which has no redirect rules, so there is no loop.

### TLS pass-through (Option A)

The proxy never terminates TLS. It only peeks at the first few bytes of the stream to read the SNI hostname from the `ClientHello` record. The peeked bytes remain in the kernel buffer and are forwarded verbatim once the connection is allowed. The upstream server's certificate is presented directly to the client.

---

## Repository structure

```
.
├── Cargo.toml                  Rust manifest (dependencies)
├── Dockerfile                  Multi-stage build → debian-slim runtime image
├── docker-compose.yml          Service definition
├── scripts/
│   └── entrypoint.sh           Installs iptables rules, then exec's the proxy
└── src/
    └── main.rs                 Proxy implementation
```

---

## Configuration

All configuration is via environment variables.

| Variable | Default | Description |
|---|---|---|
| `ALLOWED_HOSTS` | *(empty)* | Comma-separated list of allowed hostnames. Empty = deny all. |
| `RUST_LOG` | `info` | Log level: `error`, `warn`, `info`, `debug`, `trace` |

### `ALLOWED_HOSTS` syntax

| Pattern | Matches |
|---|---|
| `example.com` | Exact hostname only |
| `*.example.com` | Any single-level subdomain: `sub.example.com`, `api.example.com` |

Multiple entries are comma-separated, whitespace around entries is trimmed.

```
ALLOWED_HOSTS=example.com,*.microsoft.com,api.github.com,storage.googleapis.com
```

> **Note:** `*.example.com` does **not** match `example.com` itself (no implicit apex). Add both if needed.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Linux VM | Required for `SO_ORIGINAL_DST` and iptables |
| Docker + Docker Compose | v2+ |
| `NET_ADMIN` capability | Granted automatically by `docker-compose.yml` |
| IP forwarding enabled on host | See below |

### Enable IP forwarding on the VM

The VM must forward packets between network interfaces:

```bash
# Temporary (until reboot)
sysctl -w net.ipv4.ip_forward=1

# Permanent
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
sysctl -p
```

---

## Deployment

### 1. Clone the repository

```bash
git clone <repo-url>
cd proxy-please
```

### 2. Configure allowed hosts

Edit `docker-compose.yml`:

```yaml
environment:
  ALLOWED_HOSTS: "example.com,*.microsoft.com"
  RUST_LOG: "info"
```

Or create a `.env` file and uncomment `env_file: .env` in `docker-compose.yml`:

```bash
# .env
ALLOWED_HOSTS=example.com,*.microsoft.com
RUST_LOG=info
```

### 3. Build and start

```bash
docker compose up -d --build
```

### 4. Verify

```bash
# Check the container is running
docker compose ps

# Watch live logs
docker compose logs -f

# Confirm iptables rules are installed (run on the host)
iptables -t nat -L PREROUTING -n -v
```

### 5. Configure Azure UDR

In the Azure portal (or via CLI), add a route to the subnet(s) whose traffic should be inspected:

| Field | Value |
|---|---|
| Address prefix | `0.0.0.0/0` (or a specific CIDR) |
| Next hop type | Virtual appliance |
| Next hop IP | Private IP of the proxy VM |

---

## Azure VM setup notes

### Disable source/destination check

Azure VMs by default drop packets not addressed to themselves. For the VM to act as a router, enable **IP forwarding** on the NIC:

```bash
az network nic update \
  --resource-group <rg> \
  --name <nic-name> \
  --ip-forwarding true
```

Or set it in the portal: VM → Networking → Network Interface → IP configurations → IP forwarding = **Enabled**.

---

## How each protocol is handled

### HTTP

1. Proxy accepts the TCP connection on port `8080`.
2. Reads up to 8 KB until `\r\n\r\n` (end of headers).
3. Parses the `Host:` header value (port stripped).
4. Checks against `ALLOWED_HOSTS`:
   - **Denied** → responds with `HTTP/1.1 403 Forbidden` and closes.
   - **Allowed** → opens TCP connection to the original destination (via `SO_ORIGINAL_DST`), forwards the already-read bytes, then proxies bidirectionally.

### HTTPS (TLS pass-through)

1. Proxy accepts the TCP connection on port `8443`.
2. **Peeks** (does not consume) up to 4 KB from the stream.
3. Parses the TLS record layer and `ClientHello` handshake message to extract the SNI extension hostname.
4. Checks against `ALLOWED_HOSTS`:
   - **Denied** → closes the connection silently (no TLS alert is possible without decryption).
   - **Allowed** → opens TCP connection to the original destination, then proxies bidirectionally. The peeked bytes are still in the socket buffer and flow naturally as the first bytes of the proxied stream.

---

## Logging

Logs are written to stdout in a structured format. Control verbosity with `RUST_LOG`:

```
2026-04-23T10:00:01Z  INFO ALLOWED HTTP  peer=10.0.1.5:54321 dst=93.184.216.34:80  host=example.com
2026-04-23T10:00:02Z  INFO DENIED  HTTPS peer=10.0.1.5:54322 dst=1.2.3.4:443       sni=blocked.com
```

---

## Building from source (without Docker)

Requires Rust 1.75+ on Linux:

```bash
cargo build --release
# Binary: ./target/release/proxy-please
```

The binary requires `NET_ADMIN` capability and iptables rules to be set up manually (see `scripts/entrypoint.sh` for the exact commands).

---

## Dependencies

| Crate | Version | Purpose |
|---|---|---|
| `tokio` | 1 (full) | Async runtime, TCP sockets |
| `libc` | 0.2 | `SO_ORIGINAL_DST` socket option |
| `tracing` | 0.1 | Structured logging |
| `tracing-subscriber` | 0.3 | Log output with `RUST_LOG` env filter |

---

## Security notes

- Traffic that cannot be parsed (no `Host` header, no SNI, malformed TLS) is **denied by default**.
- The proxy never reads, stores, or logs the content of any HTTP body or TLS payload.
- `ALLOWED_HOSTS` patterns are normalised to lowercase before comparison.
- The container requires `NET_ADMIN` and `NET_RAW` capabilities and `network_mode: host`. It should be run on a dedicated VM, not alongside untrusted workloads.

---

## Limitations

- **IPv4 only** — `SO_ORIGINAL_DST` as implemented uses `sockaddr_in` (IPv4). IPv6 support requires `IPV6_ORIGINAL_DST` (`getsockopt` level `IPPROTO_IPV6`, option `80`).
- **Single-level wildcards only** — `*.example.com` matches one subdomain level. `*.*.example.com` is not supported.
- **HTTP/1.x only** — HTTP/2 cleartext (h2c) is not handled; it would be treated as unknown and the `Host` header may not be present in the expected format.
- **Linux only** — `SO_ORIGINAL_DST` is a Linux kernel feature. The binary compiles on macOS for development but returns no original destination and drops all connections.
