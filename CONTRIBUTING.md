# Contributing to InferaDB Management API

Thank you for your interest in contributing to the InferaDB Management API! This document provides guidelines and best practices for contributing to this project.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:

   ```bash
   git clone https://github.com/YOUR_USERNAME/inferadb.git
   cd inferadb/management
   ```

3. **Set up your development environment** following the [README.md](./README.md)

## Development Process

### 1. Create a Feature Branch

Always create a new branch for your work:

```bash
git checkout -b feature/your-feature-name
```

Branch naming conventions:

- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation changes
- `refactor/` - Code refactoring
- `test/` - Test additions or improvements
- `chore/` - Build process, dependency updates, etc.

### 2. Follow the Implementation Plan

Refer to [PLAN.md](./PLAN.md) for the phased implementation roadmap. Each phase has specific tasks and deliverables.

### 3. Write Quality Code

#### Code Style

- Follow Rust idioms and best practices
- Use `rustfmt` for formatting: `cargo fmt`
- Address all `clippy` warnings: `cargo clippy -- -D warnings`
- Write clear, descriptive variable and function names
- Add documentation comments for public APIs

#### Testing

- Write unit tests for all new functionality
- Add integration tests for API endpoints
- Ensure all tests pass: `cargo test`
- Aim for >80% code coverage

Example test structure:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_name() {
        // Arrange
        let input = ...;

        // Act
        let result = function_to_test(input);

        // Assert
        assert_eq!(result, expected);
    }

    #[tokio::test]
    async fn test_async_function() {
        // ...
    }
}
```

#### Error Handling

- Use the `Result` type for operations that can fail
- Provide meaningful error messages
- Use the error types defined in `inferadb-management-core::error`

#### Documentation

- Add Rustdoc comments for all public APIs:

  ````rust
  /// Brief description of the function
  ///
  /// # Arguments
  ///
  /// * `param1` - Description of param1
  ///
  /// # Returns
  ///
  /// Description of return value
  ///
  /// # Errors
  ///
  /// Description of possible errors
  ///
  /// # Examples
  ///
  /// ```
  /// use crate::module::function;
  /// let result = function(arg);
  /// ```
  pub fn function(param1: Type) -> Result<ReturnType> {
      // ...
  }
  ````

### 4. Commit Your Changes

#### Commit Message Format

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```text
<type>(<scope>): <subject>

<body>

<footer>
```

Types:

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Test additions or improvements
- `chore`: Build process, dependency updates

Examples:

```text
feat(auth): implement password authentication

Add password-based authentication with Argon2id hashing.
Includes rate limiting and session management.

Closes #123
```

```text
fix(storage): handle FoundationDB connection timeout

Add retry logic with exponential backoff for FDB connections.
```

### 5. Push and Create a Pull Request

```bash
git push origin feature/your-feature-name
```

Then create a pull request on GitHub with:

- Clear title describing the change
- Description of what changed and why
- Reference to related issues (e.g., "Closes #123")
- Screenshots or examples if applicable

## Pull Request Checklist

Before submitting a PR, ensure:

- [ ] Code follows Rust style guidelines (`cargo fmt`)
- [ ] All clippy warnings are addressed (`cargo clippy -- -D warnings`)
- [ ] All tests pass (`cargo test`)
- [ ] New functionality has tests
- [ ] Documentation is updated (if applicable)
- [ ] Commit messages follow Conventional Commits
- [ ] PR description clearly explains the changes

## Code Review Process

1. **Automated Checks**: CI will run tests, linters, and formatters
2. **Peer Review**: At least one maintainer will review your code
3. **Feedback**: Address any review comments
4. **Approval**: Once approved, a maintainer will merge your PR

## Development Guidelines

### Security

- Never commit secrets or credentials
- Use environment variables for sensitive configuration
- Follow secure coding practices (input validation, SQL injection prevention, etc.)
- Report security vulnerabilities privately to <security@inferadb.com>

### Performance

- Profile code for performance-critical paths
- Avoid unnecessary allocations
- Use async/await properly to avoid blocking
- Cache expensive operations when appropriate

### Multi-Tenancy

- Always validate organization/vault access
- Ensure data isolation between organizations
- Test cross-tenant access attempts

### API Design

- Follow RESTful conventions
- Use appropriate HTTP status codes
- Provide clear error messages
- Version APIs when making breaking changes

## Testing

### Running Tests

```bash
# All tests
cargo test

# Specific package
cargo test --package inferadb-management-core

# Specific test
cargo test test_name

# With output
cargo test -- --nocapture

# Integration tests only
cargo test --test '*'
```

### Test Coverage

```bash
# Install tarpaulin
cargo install cargo-tarpaulin

# Generate coverage report
cargo tarpaulin --out Html
```

## Documentation

### Generating Documentation

```bash
# Generate and open docs
cargo doc --no-deps --open

# Include private items
cargo doc --no-deps --document-private-items
```

### Updating Architecture Docs

When adding new features or making architectural changes, update:

- [OVERVIEW.md](./OVERVIEW.md) - Entity definitions and behavioral rules
- [AUTHENTICATION.md](./AUTHENTICATION.md) - Authentication flows
- [PLAN.md](./PLAN.md) - Implementation roadmap

## Getting Help

- **GitHub Issues**: For bugs and feature requests
- **Discussions**: For questions and general discussion
- **Documentation**: Check [README.md](./README.md) and [OVERVIEW.md](./OVERVIEW.md)

## License

By contributing to this project, you agree that your contributions will be licensed under the BSL 1.1 License.

## Code of Conduct

Please be respectful and professional in all interactions. We are committed to providing a welcoming and inclusive environment for all contributors.

## Thank You

Your contributions help make InferaDB better for everyone. We appreciate your time and effort!
