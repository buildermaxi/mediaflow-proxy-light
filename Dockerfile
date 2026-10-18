# ---------------------------------------------------------------------------
# Multi-stage Dockerfile — builds from source.
#
# Multi-arch (linux/amd64 + linux/arm64) is handled by Docker buildx (slower
# under QEMU for arm64). CI publishes from prebuilt binaries instead, see
# Dockerfile.prebuilt.
#
# TLS backend: `tls-rustls` (the crate default) → no system OpenSSL needed.
# ---------------------------------------------------------------------------

FROM rust:1.95-slim-bookworm AS builder

WORKDIR /usr/src/app

# Build deps: a C toolchain for `ring` (rustls' crypto backend).
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        && rm -rf /var/lib/apt/lists/*

# Dependency-only prebuild for layer caching.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    echo "pub fn add(l: usize, r: usize) -> usize { l + r }" > src/lib.rs && \
    cargo build --release && \
    rm -rf src target/release/deps/mediaflow*

# Real build. The dashboard pages in `static/` are embedded into the binary
# with `include_str!`, so they must be present at compile time even though
# nothing reads them at runtime.
COPY src    ./src
COPY static ./static
RUN cargo build --release

# ---------------------------------------------------------------------------
# Runtime — distroless (glibc only, no shell/apt/etc.)
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/cc-debian12

WORKDIR /app

COPY --from=builder /usr/src/app/target/release/mediaflow-proxy-light /app/
COPY config-example.toml /app/config.toml

ENV RUST_LOG=info
ENV CONFIG_PATH=/app/config.toml

EXPOSE 8888

ENTRYPOINT ["/app/mediaflow-proxy-light"]
