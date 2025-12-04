# FoundationDB Integration Tests for Management API

This directory contains Docker-based integration tests for the InferaDB Management API with FoundationDB.

## Overview

The integration test suite validates that the management API works correctly with a real FoundationDB cluster, testing:

- Transaction handling and retries
- Conflict resolution
- Key-value operations
- Range queries
- TTL functionality (if applicable)
- Multi-instance coordination (leader election, worker IDs)

## Prerequisites

- Docker and Docker Compose
- At least 4GB of available RAM
- ~5GB of disk space for Docker images

## Quick Start

### Running Tests

```bash
# From the management/ directory
cd docker/fdb-integration-tests

# Build and run tests
docker-compose up --build

# Or run tests manually
docker-compose up -d foundationdb
docker-compose run test-runner /workspace/docker/fdb-integration-tests/run-tests.sh
```

### Running Full Test Suite Against FDB

```bash
# Run all management API tests with FDB backend
docker-compose run -e RUN_FULL_SUITE=true test-runner /workspace/docker/fdb-integration-tests/run-tests.sh
```

### Interactive Testing

```bash
# Start FDB and keep test runner alive
docker-compose up -d

# Enter test runner container
docker exec -it inferadb-mgmt-test-runner bash

# Inside container, run specific tests
cargo test -p inferadb-management-storage --features foundationdb -- --nocapture

# Or run full suite
INFERADB_MGMT__STORAGE__BACKEND=foundationdb \
INFERADB_MGMT__STORAGE__FDB_CLUSTER_FILE=/etc/foundationdb/fdb.cluster \
cargo test --workspace --lib --bins
```

## Architecture

### Components

1. **FoundationDB Container** (`foundationdb`)
   - Single-node FDB 7.3.69 cluster
   - Configured as `single memory` mode for testing
   - Multi-arch support (AMD64 and ARM64/Apple Silicon)
   - Health checks ensure readiness before tests run

2. **Test Runner Container** (`test-runner`)
   - Rust 1.83 with FDB client libraries
   - Pre-fetches dependencies for faster rebuilds
   - Mounts source code for live development
   - Caches cargo registry and build artifacts

### Network

Both containers run on an isolated bridge network (`inferadb-mgmt-fdb-test-net`) to ensure test isolation.

### Volumes

- `fdb-config`: Shared FDB cluster configuration
- `cargo-registry`: Cached Rust crates
- `cargo-git`: Cached git dependencies
- `target-cache`: Build artifacts cache

## Files

- `docker-compose.yml`: Multi-container test environment
- `Dockerfile.fdb`: Custom multi-arch FDB server image
- `Dockerfile`: Test runner with Rust and FDB client
- `fdb-entrypoint.sh`: FDB server startup script
- `run-tests.sh`: Test execution script with FDB readiness checks
- `README.md`: This file

## Environment Variables

### Test Runner

- `FDB_CLUSTER_FILE`: Path to FDB cluster file (default: `/etc/foundationdb/fdb.cluster`)
- `RUST_BACKTRACE`: Enable Rust backtraces (default: `1`)
- `RUST_LOG`: Logging level (default: `debug`)
- `RUN_ALL_TESTS`: Run all storage tests (default: `false`)
- `RUN_FULL_SUITE`: Run full test suite (default: `false`)

### Management API Configuration

When running full suite, configure via environment:

```bash
INFERADB_MGMT__STORAGE__BACKEND=foundationdb
INFERADB_MGMT__STORAGE__FDB_CLUSTER_FILE=/etc/foundationdb/fdb.cluster
```

## Troubleshooting

### Tests Fail to Connect to FDB

**Problem**: Tests timeout waiting for FDB cluster file or connection.

**Solutions**:

1. Check FDB container health: `docker-compose ps`
2. View FDB logs: `docker-compose logs foundationdb`
3. Verify cluster file exists: `docker exec inferadb-mgmt-fdb-test cat /var/fdb/fdb.cluster`
4. Restart FDB: `docker-compose restart foundationdb`

### FDB Cluster Not Initializing

**Problem**: FDB status shows "(Re)initializing" indefinitely.

**Solutions**:

1. Check FDB status: `docker exec inferadb-mgmt-fdb-test fdbcli --exec "status"`
2. Re-initialize: `docker exec inferadb-mgmt-fdb-test fdbcli --exec "configure new single memory"`
3. Clean restart: `docker-compose down -v && docker-compose up`

### Build Fails on ARM64 (Apple Silicon)

**Problem**: FDB client installation fails.

**Solution**: Verify the Dockerfile uses correct architecture detection:

```dockerfile
ARG TARGETARCH
# Should detect as "arm64" on Apple Silicon
```

### Permission Errors

**Problem**: Cannot write to FDB data directory.

**Solution**:

```bash
# Clean up volumes and restart
docker-compose down -v
docker-compose up
```

### Tests Pass Locally But Fail in CI

**Problem**: Race conditions or resource constraints.

**Solutions**:

1. Increase test timeouts in `run-tests.sh`
2. Add `--test-threads=1` to force sequential execution
3. Check CI runner has adequate resources (4GB RAM minimum)

## Cleanup

```bash
# Stop containers and remove volumes
docker-compose down -v

# Remove images
docker-compose down --rmi all -v

# Nuclear option: remove all related Docker resources
docker system prune -a --filter "label=com.docker.compose.project=docker"
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: FDB Integration Tests

on: [push, pull_request]

jobs:
  fdb-integration:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run FDB Integration Tests
        run: |
          cd management/docker/fdb-integration-tests
          docker-compose up --build --abort-on-container-exit --exit-code-from test-runner

      - name: Collect logs on failure
        if: failure()
        run: |
          docker-compose logs foundationdb
          docker-compose logs test-runner
```

## Performance Notes

- **Build Time**: Initial build ~5-10 minutes (downloads FDB binaries, Rust deps)
- **Rebuild Time**: ~30 seconds with cache
- **Test Execution**: ~10-30 seconds depending on test count
- **Resource Usage**: ~1.5GB RAM, 2-4GB disk

## Security Notes

- This setup is for **testing only** - never use in production
- FDB cluster uses default credentials
- No authentication or encryption configured
- Containers run with default (non-root) users where possible

## Further Reading

- [FoundationDB Documentation](https://apple.github.io/foundationdb/)
- [FoundationDB Docker Hub](https://hub.docker.com/r/foundationdb/foundationdb)
- [Rust FoundationDB Bindings](https://github.com/foundationdb-rs/foundationdb-rs)

## Support

For issues or questions:

- Check [TROUBLESHOOTING.md](../../TROUBLESHOOTING.md) in the main project
- Open an issue on GitHub
- Review existing FDB integration test issues
