<div align="center">
    <p><a href="https://inferadb.com"><img src=".github/inferadb.png" width="100" alt="InferaDB Logo" /></a></p>
    <h1>InferaDB Control Plane</h1>
    <p>
        <a href="https://discord.gg/inferadb"><img src="https://img.shields.io/badge/Discord-Join%20us-5865F2?logo=discord&logoColor=white" alt="Discord" /></a>
        <a href="#license"><img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg" alt="License" /></a>
    </p>
    <p>Multi-tenant administration headless APIs, Kubernetes-native deployment, and WebAuthn authentication</p>
</div>

> [!IMPORTANT]
> Under active development. Not production-ready.

## Quick Start

```bash
git clone https://github.com/inferadb/control && cd control
docker-compose up -d
export INFERADB_CTRL__AUTH__KEY_ENCRYPTION_SECRET=$(openssl rand -base64 32)
make setup && make dev
```

Register and login:

```bash
# Register
curl -X POST http://localhost:9090/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "password": "securepass123", "name": "Alice"}'

# Login
curl -X POST http://localhost:9090/v1/auth/login/password \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "password": "securepass123"}'
```

| Endpoint | URL                             |
| -------- | ------------------------------- |
| REST API | `http://localhost:9090`         |
| gRPC API | `http://localhost:9091`         |
| Mesh API | `http://localhost:9092`         |
| Health   | `http://localhost:9090/healthz` |
| Metrics  | `http://localhost:9090/metrics` |

## Features

| Feature              | Description                                  |
| -------------------- | -------------------------------------------- |
| **Authentication**   | Password, passkey, OAuth, email verification |
| **Multi-Tenancy**    | Organization-based isolation with RBAC       |
| **Vault Management** | Policy containers with access grants         |
| **Client Auth**      | Ed25519 certificates, JWT assertions         |
| **Token Issuance**   | Vault-scoped JWTs for Engine API             |

## Key Concepts

| Entity       | Description                                   |
| ------------ | --------------------------------------------- |
| User         | Account with auth methods (password, passkey) |
| Organization | Workspace with members and roles              |
| Vault        | Authorization policy container                |
| Client       | Service identity with Ed25519 certs           |
| Team         | Group-based vault access                      |

**Auth Flow:** User → Session → Vault access → JWT → Engine API

## Architecture

```mermaid
graph TD
    Bin[inferadb-control] --> API[inferadb-control-api]
    Bin --> Config[inferadb-control-config]
    API --> Core[inferadb-control-core]
    Core --> Config
    Core --> Storage[inferadb-control-storage]
    Storage --> FDB[(FoundationDB)]
    Core --> Engine[inferadb-control-engine-client]
```

| Crate                          | Purpose                  |
| ------------------------------ | ------------------------ |
| inferadb-control               | Binary entrypoint        |
| inferadb-control-api           | REST/gRPC handlers       |
| inferadb-control-config        | Configuration loading    |
| inferadb-control-const         | Shared constants         |
| inferadb-control-core          | Business logic, entities |
| inferadb-control-storage       | Memory or FoundationDB   |
| inferadb-control-types         | Shared type definitions  |
| inferadb-control-engine-client | Engine API client        |

## Configuration

```yaml
control:
  listen:
    http: "0.0.0.0:9090"
    grpc: "0.0.0.0:9091"
    mesh: "0.0.0.0:9092"

  webauthn:
    party: "localhost"
    origin: "http://localhost:9090"
```

Environment variables use `INFERADB_CTRL__` prefix (e.g., `INFERADB_CTRL__LISTEN__HTTP`).

See [config.yaml](config.yaml) for all options.

## Development

```bash
make setup                    # One-time setup
make dev                      # Dev server with auto-reload
make test                     # Run tests
make check                    # Format, lint, audit
cargo build --release         # Release build
```

## Deployment

### Docker

```bash
docker run -p 9090:9090 inferadb/control:latest
```

### Kubernetes (Helm)

```bash
helm install inferadb-control ./helm \
  --namespace inferadb \
  --create-namespace \
  --set config.storage=foundationdb \
  --set config.webauthn.party=example.com \
  --set config.webauthn.origin=https://app.example.com
```

See [helm/README.md](helm/README.md) for full configuration options.

## Documentation

| Topic           | Link                                               |
| --------------- | -------------------------------------------------- |
| Getting Started | [docs/getting-started.md](docs/getting-started.md) |
| Authentication  | [docs/authentication.md](docs/authentication.md)   |
| Architecture    | [docs/architecture.md](docs/architecture.md)       |
| API Reference   | [openapi.yaml](openapi.yaml)                       |

## Community

Join us on [Discord](https://discord.gg/inferadb) to discuss InferaDB, get help with your projects, and connect with other developers. Whether you have questions, want to share what you're building, or are interested in contributing, we'd love to have you!

## License

Licensed under either of:

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.
