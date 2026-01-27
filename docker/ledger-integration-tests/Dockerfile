# Test runner for Control + Ledger integration tests

FROM rust:1.93-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler \
    libprotobuf-dev \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

CMD ["cargo", "test", "--package", "inferadb-control-storage", "--test", "ledger_integration_tests", "--features", "ledger", "--", "--test-threads=1"]
