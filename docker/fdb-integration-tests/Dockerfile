# Dockerfile for FoundationDB Integration Tests
# This container runs InferaDB Management API tests against a real FDB instance
# For integration testing only - not for production use

FROM rust:1.91-slim

# Set environment variables for non-interactive installation
ENV DEBIAN_FRONTEND=noninteractive

# Install required dependencies including those needed by FDB client
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    pkg-config \
    libssl-dev \
    ca-certificates \
    gnupg \
    lsb-release \
    python3 \
    clang \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

# Install FoundationDB client libraries (required for Rust bindings)
# Version should match the FDB server version (7.3.69)
# Install correct architecture (ARM64 or amd64)
# Note: FDB uses _aarch64 naming for ARM64, not _arm64
ARG TARGETARCH
RUN echo "Installing FDB clients for architecture: ${TARGETARCH}" && \
    if [ "$TARGETARCH" = "arm64" ]; then \
        wget -q --show-progress https://github.com/apple/foundationdb/releases/download/7.3.69/foundationdb-clients_7.3.69-1_aarch64.deb -O /tmp/fdb-clients.deb; \
    else \
        wget -q --show-progress https://github.com/apple/foundationdb/releases/download/7.3.69/foundationdb-clients_7.3.69-1_amd64.deb -O /tmp/fdb-clients.deb; \
    fi && \
    dpkg -i /tmp/fdb-clients.deb || (apt-get update && apt-get install -f -y) && \
    rm /tmp/fdb-clients.deb && \
    ldconfig

# Create working directory
WORKDIR /workspace

# Copy the entire project (will be overridden by volume mount in docker-compose)
COPY . .

# Pre-download dependencies (cache layer)
# This speeds up subsequent builds
RUN cargo fetch

# Set FDB cluster file location
ENV FDB_CLUSTER_FILE=/etc/foundationdb/fdb.cluster

# Default command: wait for cluster file and run tests
CMD ["/workspace/docker/fdb-integration-tests/run-tests.sh"]
