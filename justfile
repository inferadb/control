# InferaDB Control Justfile
# Run `just --list` to see available recipes

# Default recipe: run tests
default: test

# Build all workspace crates
build:
    cargo build --workspace

# Run tests
test:
    cargo nextest run --profile ci

# Run clippy linter
lint:
    cargo +1.92 clippy --workspace --all-targets -- -D warnings

# Format code with nightly rustfmt
fmt:
    cargo +nightly fmt --all

# Check formatting without modifying
fmt-check:
    cargo +nightly fmt --all -- --check

# Simulate CI checks locally
ci: fmt-check lint test

# Generate and open documentation
doc:
    cargo doc --workspace --no-deps --open

# Clean build artifacts
clean:
    cargo clean
