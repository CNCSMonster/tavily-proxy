# syntax=docker/dockerfile:1

# ------------------------------------------------------------------------------
# 1. Builder Stage
# ------------------------------------------------------------------------------
FROM rust:slim-bookworm AS builder

WORKDIR /usr/src/app

# Install build dependencies required for OpenSSL / native-tls
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
 && rm -rf /var/lib/apt/lists/*

# Copy workspace sources
COPY . .

# Build the open-source proxy binary in release mode
RUN cargo build --release -p tavily-proxy

# ------------------------------------------------------------------------------
# 2. Runtime Stage
# ------------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    libssl3 \
 && rm -rf /var/lib/apt/lists/*

# Non-root user setup for security
RUN useradd -u 10001 -m -d /home/appuser -s /bin/bash appuser && \
    mkdir -p /app /home/appuser/.local/state/tavily-proxy && \
    chown -R appuser:appuser /app /home/appuser

WORKDIR /app

# Copy compiled binary from builder
COPY --from=builder /usr/src/app/target/release/tavily-proxy /usr/local/bin/tavily-proxy
COPY config.example.toml /app/config.example.toml

USER appuser

EXPOSE 3456

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://127.0.0.1:3456/health || exit 1

ENTRYPOINT ["tavily-proxy"]
CMD ["--config", "/app/config.toml", "serve"]
