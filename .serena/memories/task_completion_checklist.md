# InferaDB Control - Task Completion Checklist

When completing a task, run through this checklist:

## Before Committing

### 1. Code Quality Checks
```bash
make format                   # Format code with rustfmt
make lint                     # Run clippy, fix all warnings
```

### 2. Testing
```bash
make test                     # Run all tests, ensure they pass
```

### 3. Security (if dependencies changed)
```bash
make audit                    # Run cargo audit
make deny                     # Run cargo deny
```

## Pull Request Checklist
- [ ] Code follows Rust style guidelines (`cargo fmt`)
- [ ] All clippy warnings are addressed (`cargo clippy -- -D warnings`)
- [ ] All tests pass (`cargo test`)
- [ ] New functionality has tests
- [ ] Documentation is updated (if applicable)
- [ ] Commit messages follow Conventional Commits
- [ ] PR description clearly explains the changes

## Full CI Check
```bash
make ci                       # Runs: format, lint, test, audit
```

## Notes
- Never commit secrets or credentials
- Use environment variables for sensitive configuration
- Always validate organization/vault access (multi-tenancy)
- Test cross-tenant access attempts when relevant
- Profile performance-critical paths
- Use async/await properly (avoid blocking)
