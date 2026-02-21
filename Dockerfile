# Multi-stage Dockerfile for InferaDB Control
#
# This Dockerfile builds a minimal, secure production image using:
# - Multi-stage build to minimize final image size
# - Debian slim base image for compatibility
# - Official Rust Docker images only
# - Security scanning ready

# ============================================================================
# Stage 1: Builder - Build the application
# ============================================================================
FROM rustlang/rust:nightly-bookworm-slim AS builder
WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    clang \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy source code
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Build the application in release mode
RUN cargo build --release --bin inferadb-control

# Strip debug symbols to reduce binary size
RUN strip /app/target/release/inferadb-control

# ============================================================================
# Stage 2: Runtime - Minimal Debian slim image
# ============================================================================
FROM debian:bookworm-slim

# Metadata labels
LABEL org.opencontainers.image.title="InferaDB Control"
LABEL org.opencontainers.image.description="InferaDB Control Plane API"
LABEL org.opencontainers.image.vendor="InferaDB"
LABEL org.opencontainers.image.licenses="BSL-1.1"
LABEL org.opencontainers.image.source="https://github.com/inferadb/inferadb"
LABEL org.opencontainers.image.documentation="https://docs.inferadb.com"

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user and data directory for master key
RUN useradd -r -u 65532 -s /sbin/nologin nonroot \
    && mkdir -p /data && chown nonroot:nonroot /data

USER nonroot:nonroot

WORKDIR /app

# Copy the binary from builder
COPY --from=builder --chown=nonroot:nonroot /app/target/release/inferadb-control /app/inferadb-control

# Expose HTTP port
EXPOSE 9090

# Health check configuration
HEALTHCHECK NONE

# Set environment variables for production
ENV INFERADB__CONTROL__LOG_LEVEL=info
ENV RUST_BACKTRACE=1

VOLUME ["/data"]

# Run the binary
ENTRYPOINT ["/app/inferadb-control"]

# ============================================================================
# Build Instructions:
#
# Build the image:
#   docker build -t inferadb-control:latest .
#
# Build with specific tag:
#   docker build -t inferadb-control:v1.0.0 .
#
# Run the container:
#   docker run -p 9090:9090 \
#     -e INFERADB__CONTROL__STORAGE=memory \
#     -v inferadb-data:/data \
#     inferadb-control:latest
# ============================================================================
