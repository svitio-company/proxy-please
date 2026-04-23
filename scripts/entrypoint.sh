#!/usr/bin/env bash
# entrypoint.sh – Set up iptables redirect rules then exec the proxy.
# Runs inside the container with NET_ADMIN capability and network_mode: host.
set -euo pipefail

# ---------------------------------------------------------------------------
# Helper: clean up rules on exit so re-starts don't duplicate them
# ---------------------------------------------------------------------------
cleanup() {
    echo "[entrypoint] Removing iptables redirect rules…"
    iptables -t nat -D PREROUTING -p tcp --dport 80  -j REDIRECT --to-port 8080 2>/dev/null || true
    iptables -t nat -D PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8443 2>/dev/null || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Flush any stale rules from a previous run
# ---------------------------------------------------------------------------
iptables -t nat -D PREROUTING -p tcp --dport 80  -j REDIRECT --to-port 8080 2>/dev/null || true
iptables -t nat -D PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8443 2>/dev/null || true

# ---------------------------------------------------------------------------
# Intercept inbound HTTP and HTTPS traffic and redirect to proxy ports.
#
# Traffic path (Azure UDR scenario):
#   Subnet client → UDR → this VM → PREROUTING REDIRECT → proxy (8080/8443)
#   Proxy → upstream server   (proxy's own connections go through OUTPUT,
#                               NOT PREROUTING, so no redirect loop)
# ---------------------------------------------------------------------------
iptables -t nat -A PREROUTING -p tcp --dport 80  -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8443

echo "[entrypoint] iptables rules installed:"
echo "  TCP :80  → :8080"
echo "  TCP :443 → :8443"

# ---------------------------------------------------------------------------
# Start the proxy (replaces this shell process)
# ---------------------------------------------------------------------------
exec /usr/local/bin/proxy
