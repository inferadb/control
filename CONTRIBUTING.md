# Contributing to InferaDB

We welcome contributions! By participating, you agree to uphold the [Code of Conduct](CODE_OF_CONDUCT.md).

## Reporting Issues

- **Bugs**: Search existing issues first. Include version, steps to reproduce, expected vs actual behavior.
- **Features**: Describe the use case and proposed solution.
- **Security**: Email [security@inferadb.com](mailto:security@inferadb.com) — do not open public issues.

## Pull Requests

1. Fork and branch from `main`
2. Run `just ci` to verify tests, linting, and formatting pass
3. Follow [Conventional Commits](https://www.conventionalcommits.org/) for commit messages
4. Update documentation if changing public APIs
5. Submit PR with clear description

## Development

```bash
mise trust && mise install  # Setup tooling
just ci                     # Run all checks before submitting
```

See [README.md](README.md) for full development setup.

## Review Process

1. CI runs automated checks
2. Maintainer reviews code
3. Address feedback
4. Maintainer merges on approval

## License

Contributions are dual-licensed under [MIT](LICENSE-MIT) and [Apache 2.0](LICENSE-APACHE).

## Questions?

- [Discord](https://discord.gg/inferadb)
- [open@inferadb.com](mailto:open@inferadb.com)
