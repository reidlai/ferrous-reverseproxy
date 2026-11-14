# syntax=docker/dockerfile:1.4

# Stage 1: Build Pure-Rust Reverse Proxy Binary (Target: x86_64-unknown-linux-musl)
FROM rust:alpine AS builder
RUN apk add --no-cache musl-dev build-base perl ca-certificates
WORKDIR /build

COPY Cargo.toml Cargo.lock* ./
RUN mkdir -p src && echo "fn main() {}" > src/main.rs && echo "pub fn lib() {}" > src/lib.rs && cargo build --release --target x86_64-unknown-linux-musl || true

COPY src ./src
COPY config ./config
RUN cargo build --release --target x86_64-unknown-linux-musl

# Stage 2: Minimal Zero-OS Hardened Runtime (< 45MB FROM scratch, AD-24)
FROM scratch

# Copy Root CA Certificates for upstream TLS validation
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Synthetic unprivileged user/group (10001:10001)
COPY <<EOF /etc/passwd
ferrous:x:10001:10001:Ferrous ReverseProxy User:/:/bin/false
EOF

COPY <<EOF /etc/group
ferrous:x:10001:
EOF

WORKDIR /app

# Copy compiled static reverse proxy binary
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/ferrous-reverseproxy /app/ferrous-reverseproxy

# Copy default configuration and WAF CRS rules
COPY --from=builder /build/config /etc/zentinel

USER 10001:10001

EXPOSE 80 443

ENV RUST_LOG=info \
    ZENTINEL_CONFIG=/etc/zentinel/zentinel.yaml

HEALTHCHECK --interval=10s --timeout=3s --retries=3 CMD ["/app/ferrous-reverseproxy", "--healthcheck", "--health-port", "443"]

ENTRYPOINT ["/app/ferrous-reverseproxy"]
CMD ["--config", "/etc/zentinel/zentinel.yaml"]
