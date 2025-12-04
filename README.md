# InferaDB Management API

Control plane for InferaDB: user authentication, organization management, and vault access control.

> [!IMPORTANT]
> Under active development. Not production-ready.

## Features

- **Authentication**: Password, passkey, OAuth, email verification
- **Multi-Tenancy**: Organization-based isolation with RBAC (Owner, Admin, Member)
- **Vault Management**: Policy containers with team and user access grants
- **Client Auth**: Backend service identity via Ed25519 certificates and JWT assertions
- **Token Issuance**: Vault-scoped JWTs for Server API authorization

## Quick Start

See [docs/getting-started.md](docs/getting-started.md) for a complete tutorial.

```bash
# Prerequisites: Rust 1.78+, Docker
git clone https://github.com/inferadb/inferadb.git && cd inferadb/management
docker-compose up -d
export INFERADB_MGMT__AUTH__KEY_ENCRYPTION_SECRET=$(openssl rand -base64 32)
cargo run --bin inferadb-management
```

| Endpoint | URL                             |
| -------- | ------------------------------- |
| REST API | `http://localhost:3000`         |
| gRPC API | `http://localhost:3001`         |
| Health   | `http://localhost:3000/health`  |
| Metrics  | `http://localhost:3000/metrics` |
| OpenAPI  | [OpenAPI.yaml](OpenAPI.yaml)    |

## Architecture

```text
inferadb-management              # Binary
├── inferadb-management-api      # REST/gRPC handlers
├── inferadb-management-core     # Business logic, entities, repositories
├── inferadb-management-storage  # Storage backends (memory, FoundationDB)
├── inferadb-management-grpc     # Server API client
├── inferadb-management-types    # Shared type definitions
└── inferadb-management-test-fixtures  # Test utilities
```

**Storage**: Memory (dev/testing) or FoundationDB (production, distributed ACID)

## Configuration

Via `config.yaml` or environment variables (`INFERADB_MGMT__` prefix):

```bash
INFERADB_MGMT__STORAGE__BACKEND=foundationdb
INFERADB_MGMT__STORAGE__FDB_CLUSTER_FILE=/etc/foundationdb/fdb.cluster
INFERADB_MGMT__SERVER__HTTP_PORT=4000
INFERADB_MGMT__OBSERVABILITY__LOG_LEVEL=debug
```

See [config.yaml](config.yaml) for all options.

## Development

```bash
cargo test                                    # All tests
cargo test --package inferadb-management-core   # Specific crate
cargo clippy -- -D warnings                   # Lint
cargo fmt                                     # Format
```

## Key Concepts

| Entity       | Description                                        |
| ------------ | -------------------------------------------------- |
| User         | Account with auth methods (password, passkey)      |
| Organization | Multi-tenant workspace with members and roles      |
| Vault        | Authorization policy container with access grants  |
| Client       | Backend service identity with Ed25519 certificates |
| Team         | Group-based vault access                           |

**IDs**: Snowflake IDs (64-bit, globally unique, time-sortable)

**Auth Flow**: User authenticates → session token → request vault access → vault-scoped JWT → Server API

## API Examples

```bash
# Register
curl -X POST http://localhost:3000/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "securepass123", "name": "Alice"}'

# Login
curl -X POST http://localhost:3000/v1/auth/login/password \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "securepass123"}'

# Create vault (authenticated)
curl -X POST http://localhost:3000/v1/organizations/{org_id}/vaults \
  -H "Cookie: infera_session={session_id}" \
  -d '{"name": "Production Policies"}'

# Generate vault JWT
curl -X POST http://localhost:3000/v1/organizations/{org_id}/vaults/{vault_id}/tokens \
  -H "Cookie: infera_session={session_id}"
```

## Production

```bash
cargo build --release
export INFERADB_MGMT__STORAGE__BACKEND=foundationdb
export INFERADB_MGMT__AUTH__KEY_ENCRYPTION_SECRET=$(openssl rand -base64 32)
./target/release/inferadb-management --config /etc/inferadb/config.yaml
```

For Kubernetes deployment, see [docs/deployment.md](docs/deployment.md).

## Monitoring

- **Metrics**: Prometheus at `/metrics` (latency, status codes, auth attempts)
- **Logs**: Structured JSON (production) or human-readable (dev)
- **Tracing**: Optional OpenTelemetry integration
- **Audit**: See [docs/audit-logs.md](docs/audit-logs.md)

## Load Testing

```bash
brew install k6
k6 run loadtests/auth.js
```

See [loadtests/README.md](loadtests/README.md) and [docs/performance.md](docs/performance.md).

## Documentation

| Topic           | Link                                               |
| --------------- | -------------------------------------------------- |
| Getting Started | [docs/getting-started.md](docs/getting-started.md) |
| Authentication  | [docs/authentication.md](docs/authentication.md)   |
| Architecture    | [docs/architecture.md](docs/architecture.md)       |
| Data Flows      | [docs/flows.md](docs/flows.md)                     |
| Pagination      | [docs/pagination.md](docs/pagination.md)           |
| Audit Logs      | [docs/audit-logs.md](docs/audit-logs.md)           |
| Deployment      | [docs/deployment.md](docs/deployment.md)           |
| Performance     | [docs/performance.md](docs/performance.md)         |
| Troubleshooting | [docs/troubleshooting.md](docs/troubleshooting.md) |
| API Reference   | [OpenAPI.yaml](OpenAPI.yaml)                       |
| Contributing    | [CONTRIBUTING.md](CONTRIBUTING.md)                 |

## License

Business Source License 1.1. See [LICENSE.md](LICENSE.md).

## Support

- Issues: [github.com/inferadb/inferadb/issues](https://github.com/inferadb/inferadb/issues)
- Security: [security@inferadb.com](mailto:security@inferadb.com)
