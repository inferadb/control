# InferaDB Control - Suggested Commands

## One-Time Setup
```bash
mise trust && mise install    # Install tools via mise
docker-compose up -d          # Start FoundationDB (optional)
export INFERADB_CTRL__AUTH__KEY_ENCRYPTION_SECRET=$(openssl rand -base64 32)
```

## Daily Development
```bash
cargo run --bin inferadb-control              # Run server (debug mode)
cargo watch -x 'run --bin inferadb-control'   # Dev server with auto-reload
cargo build                                   # Build debug binary
cargo build --release                         # Build release binary
```

## Testing
```bash
cargo test --all-targets                      # Run all tests
cargo test --package inferadb-control-core    # Test specific crate
cargo test test_name                          # Run specific test
cargo test -- --nocapture                     # Show test output
cargo test --test '*' --workspace             # Integration tests only
```

## Code Quality
```bash
cargo +nightly fmt --all                                            # Format code
cargo clippy --workspace --all-targets --all-features -- -D warnings # Lint
cargo audit                                                         # Security audit
cargo deny check                                                    # Dependency checks
cargo clippy --fix --allow-dirty --allow-staged                     # Auto-fix warnings
```

## Documentation
```bash
cargo doc --no-deps --open    # Generate and open rustdoc
```

## Coverage & Benchmarks
```bash
cargo tarpaulin --workspace --timeout 300 --out Html --output-dir target/coverage
cargo bench                   # Run benchmarks
```

## Cleanup
```bash
cargo clean                   # Clean build artifacts
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
