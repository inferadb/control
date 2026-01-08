# InferaDB Control - Task Completion Checklist

When completing a task, run through this checklist:

## Before Committing

### 1. Code Quality Checks
```bash
cargo +nightly fmt --all                                             # Format code
cargo clippy --workspace --all-targets --all-features -- -D warnings # Lint
```

### 2. Testing
```bash
cargo test --all-targets      # Run all tests, ensure they pass
```

### 3. Security (if dependencies changed)
```bash
cargo audit                   # Run cargo audit
cargo deny check              # Run cargo deny
```

## Pull Request Checklist
- [ ] Code follows Rust style guidelines (`cargo +nightly fmt --all`)
- [ ] All clippy warnings are addressed (`cargo clippy -- -D warnings`)
- [ ] All tests pass (`cargo test`)
- [ ] New functionality has tests
- [ ] Documentation is updated (if applicable)
- [ ] Commit messages follow Conventional Commits
- [ ] PR description clearly explains the changes

## Full CI Check
```bash
cargo +nightly fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo audit
```

## Notes
- Never commit secrets or credentials
- Use environment variables for sensitive configuration
- Always validate organization/vault access (multi-tenancy)
- Test cross-tenant access attempts when relevant
- Profile performance-critical paths
- Use async/await properly (avoid blocking)
