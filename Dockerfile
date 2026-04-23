# syntax=docker/dockerfile:1

# ---- Build ----
FROM rust:1-slim-bookworm AS builder

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Layer-cache dependencies: compile a stub binary first so dep crates are cached
RUN mkdir src && echo 'fn main() {}' > src/main.rs
RUN cargo build --release
# Remove stub artifacts so the real source rebuild is not skipped
RUN rm -f target/release/deps/proxy_please* \
         target/release/proxy-please \
         target/release/proxy-please.d

# Build the real binary
COPY src ./src
RUN cargo build --release

# Strip debug symbols to minimise image size
RUN strip target/release/proxy-please

# ---- Runtime ----
# debian-slim is required (not distroless) because the entrypoint runs bash + iptables
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends iptables iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/proxy-please /usr/local/bin/proxy
COPY scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Proxy listen ports (iptables redirects :80→:8080 and :443→:8443)
EXPOSE 8080 8443

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
