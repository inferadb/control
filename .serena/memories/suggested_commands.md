# InferaDB Control - Suggested Commands

## One-Time Setup
```bash
make setup                    # Install tools, fetch dependencies
docker-compose up -d          # Start FoundationDB (optional)
export INFERADB_CTRL__AUTH__KEY_ENCRYPTION_SECRET=$(openssl rand -base64 32)
```

## Daily Development
```bash
make dev                      # Dev server with auto-reload (cargo-watch)
make run                      # Run server (debug mode)
cargo build                   # Build debug binary
cargo build --release         # Build release binary
```

## Testing
```bash
make test                     # Run all tests
cargo test                    # Standard test runner
cargo test --package inferadb-control-core  # Test specific crate
cargo test test_name          # Run specific test
cargo test -- --nocapture     # Show test output
make test-integration         # Integration tests only
make test-fdb                 # FoundationDB integration tests (requires Docker)
```

## Code Quality
```bash
make check                    # Format + lint + audit
make format                   # cargo +nightly fmt --all
make lint                     # cargo clippy --workspace --all-targets --all-features -- -D warnings
make audit                    # cargo audit (security)
make deny                     # cargo deny check (dependencies)
make fix                      # Auto-fix clippy warnings
```

## Documentation
```bash
make doc                      # Generate and open rustdoc
cargo doc --no-deps --open    # Same as above
```

## Coverage & Benchmarks
```bash
make coverage                 # Generate coverage report (tarpaulin)
make bench                    # Run benchmarks
```

## Cleanup
```bash
make clean                    # Clean build artifacts
make reset                    # Full reset (clean + remove target + Cargo.lock)
```

## CI
```bash
make ci                       # Run full CI checks (format, lint, test, audit)
```

## Docker
```bash
docker build -t inferadb-control .
docker run -p 9090:9090 inferadb-control
```

## System Commands (macOS/Darwin)
- `git`, `ls`, `cd`, `grep`, `find` - Standard Unix commands (BSD variants)
- `brew` - Homebrew package manager
- `mise` - Tool version manager (replaces asdf)
