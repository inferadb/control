# InferaDB Control - Code Style & Conventions

## Rust Toolchain
- **Channel**: Stable (Rust 1.92+)
- **Components**: clippy, rust-analyzer, rust-src, rustfmt
- **Edition**: 2021

## Formatting (rustfmt)
Configuration (`.rustfmt.toml`):
```toml
comment_width = 100
condense_wildcard_suffixes = true
force_explicit_abi = false
format_macro_matchers = true
group_imports = "StdExternalCrate"      # Group: std, then external, then crate
imports_granularity = "Crate"           # Merge imports by crate
match_block_trailing_comma = true
merge_derives = false
newline_style = "Unix"
normalize_comments = true
style_edition = "2024"
use_small_heuristics = "MAX"
wrap_comments = true
```

**Important**: Use `cargo +nightly fmt` for formatting (nightly required for some options).

## Linting (Clippy)
- Treat all warnings as errors: `-D warnings`
- Run on all targets and features: `--all-targets --all-features`

## Import Ordering
1. Standard library (`std::*`)
2. External crates (alphabetically)
3. Internal crates (`crate::*`)

## Naming Conventions
- **Types/Structs/Enums**: PascalCase (`UserRepository`, `AuthError`)
- **Functions/Methods**: snake_case (`get_user_by_id`, `validate_token`)
- **Constants**: SCREAMING_SNAKE_CASE (`MAX_RETRY_COUNT`)
- **Modules**: snake_case (`auth`, `repository_context`)

## Error Handling
- Use `Result<T, E>` for fallible operations
- Use `thiserror` for defining error types
- Use `anyhow` for application-level errors
- Provide meaningful error messages
- Error types defined in `inferadb-control-core::error`

## Documentation
- Add rustdoc comments (`///`) for all public APIs
- Include: description, arguments, returns, errors, examples
- Use markdown formatting in doc comments

## Testing
- Use `#[cfg(test)]` modules for unit tests
- Use `#[tokio::test]` for async tests
- Follow Arrange-Act-Assert pattern
- Aim for >80% code coverage
- Integration tests go in `tests/` directory

## Commit Messages
Follow [Conventional Commits](https://www.conventionalcommits.org/):
```
<type>(<scope>): <subject>

<body>

<footer>
```
Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

## Branch Naming
- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation
- `refactor/` - Refactoring
- `test/` - Tests
- `chore/` - Build/maintenance
