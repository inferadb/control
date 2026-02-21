<div align="center">
    <p><a href="https://inferadb.com"><img src=".github/inferadb.png" width="100" alt="InferaDB Logo" /></a></p>
    <h1>InferaDB Control Plane</h1>
    <p>
        <a href="https://discord.gg/inferadb"><img src="https://img.shields.io/badge/Discord-Join%20us-5865F2?logo=discord&logoColor=white" alt="Discord" /></a>
        <a href="#license"><img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg" alt="License" /></a>
    </p>
    <p><b>Multi-tenant administration APIs for authorization infrastructure.</b></p>
</div>

> [!IMPORTANT]
> Under active development. Not production-ready.

[InferaDB](https://inferadb.com) Control is the administration plane for InferaDB. It manages organizations, users, vaults, clients, and token issuance. Control authenticates operators via password, passkey, or OAuth, enforces RBAC across tenants, and issues vault-scoped JWTs consumed by the [InferaDB Engine](https://github.com/inferadb/engine). Data is persisted to [InferaDB Ledger](https://github.com/inferadb/ledger) for cryptographic auditability.

- [Features](#features)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Contributing](#contributing)
- [Documentation](#documentation)
- [Community](#community)
- [License](#license)

## Features

- **Authentication** — Password, passkey (WebAuthn), OAuth, email verification, PKCE CLI flow
- **Multi-Tenancy** — Organization-based isolation with role hierarchy (Owner > Admin > Member) and team permissions
- **Vault Management** — Policy containers with user and team access grants
- **Client Auth** — Ed25519 certificate lifecycle, RFC 7523 JWT assertions
- **Token Issuance** — Vault-scoped JWTs with refresh token rotation for Engine API

## Quick Start

```bash
git clone https://github.com/inferadb/control && cd control
mise trust && mise install
cargo run --bin inferadb-control -- --dev-mode
```

Dev mode uses in-memory storage and auto-generates an Ed25519 identity. The REST API is available at `http://localhost:9090`.

**Production:**

```bash
inferadb-control \
  --listen 0.0.0.0:9090 \
  --storage ledger \
  --ledger-endpoint http://ledger:50051 \
  --ledger-client-id ctrl-prod-01 \
  --ledger-namespace-id 1 \
  --key-file /data/master.key \
  --log-format json
```

## Configuration

| CLI                     | Purpose                                          | Default                 |
| ----------------------- | ------------------------------------------------ | ----------------------- |
| `--listen`              | HTTP bind address                                | `127.0.0.1:9090`        |
| `--storage`             | Storage backend: `memory` or `ledger`            | `ledger`                |
| `--dev-mode`            | In-memory storage, relaxed security              |                         |
| `--key-file`            | Path to Ed25519 PEM key                          | `./data/master.key`     |
| `--pem`                 | Ed25519 PEM string (alternative to `--key-file`) |                         |
| `--ledger-endpoint`     | Ledger gRPC endpoint                             |                         |
| `--ledger-client-id`    | Ledger client identifier                         |                         |
| `--ledger-namespace-id` | Ledger namespace ID                              |                         |
| `--log-level`           | `trace`, `debug`, `info`, `warn`, `error`        | `info`                  |
| `--log-format`          | `auto`, `json`, `text`                           | `auto`                  |
| `--frontend-url`        | Frontend URL for CORS and email links            | `http://localhost:3000` |

See [Configuration Reference](docs/guides/configuration.md) for environment variables, email/SMTP setup, and all options.

## Contributing

### Prerequisites

- Rust 1.92+
- [mise](https://mise.jdx.dev/) for synchronized development tooling
- [just](https://github.com/casey/just) for convenient development commands

### Build and Test

```bash
mise trust && mise install

just build     # Build workspace
just test      # Run tests
just lint      # Run clippy
just fmt       # Format code
just ci        # All checks
```

## Documentation

- [Getting Started](docs/getting-started.md) — First steps with Control
- [Configuration Reference](docs/guides/configuration.md) — CLI flags, environment variables, email setup
- [Authentication](docs/authentication.md) — Auth flows and session management
- [Architecture](docs/architecture.md) — Crate structure and design decisions
- [Deployment](docs/deployment.md) — Docker, Kubernetes, and Helm
- [API Reference](openapi.yaml) — OpenAPI specification

## Community

Join us on [Discord](https://discord.gg/inferadb) for questions and discussions.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE).
