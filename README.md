# InferaDB Management API

Control Plane API for InferaDB providing self-service user authentication, organization management, and vault access control.

## What It Does

- **User Authentication**: Password, passkey, OAuth, and email verification
- **Multi-Tenancy**: Organization-based isolation with role-based access control (Owner, Admin, Member)
- **Vault Management**: Authorization policy vaults with team and user access grants
- **Client Authentication**: Backend service auth using Ed25519 certificates and JWT assertions
- **Token Issuance**: Generate vault-scoped JWTs for Server API authorization requests

## Quick Start

**New to InferaDB Management API?** See [docs/GettingStarted.md](docs/GettingStarted.md) for a complete step-by-step tutorial.

**Prerequisites**: Rust 1.70+, Docker (for local services)

```bash
# Clone and build
git clone https://github.com/inferadb/inferadb.git
cd inferadb/management
cargo build

# Start supporting services (FoundationDB, MailHog, etc.)
docker-compose up -d

# Generate encryption secret
export INFERADB_MGMT__AUTH__KEY_ENCRYPTION_SECRET=$(openssl rand -base64 32)

# Run the API
cargo run --bin inferadb-management
```

**API Endpoints**:

- REST API: `http://localhost:3000`
- gRPC API: `http://localhost:3001`
- Health: `http://localhost:3000/health`
- Metrics: `http://localhost:3000/metrics`
- OpenAPI Spec: [`OpenAPI.yaml`](OpenAPI.yaml)

## Architecture

Built in Rust with pluggable storage:

```
infera-management        # Main binary
├── infera-management-api      # REST/gRPC handlers
├── infera-management-core     # Business logic, entities, repositories
├── infera-management-storage  # Storage abstraction (memory, FoundationDB)
└── infera-management-grpc     # Server API client
```

**Storage Backends**:

- **Memory**: Default for dev/testing (no persistence)
- **FoundationDB**: Production (distributed, ACID, multi-region)

## Configuration

Via `config.yaml` or environment variables with `INFERADB_MGMT__` prefix:

```bash
# Use FoundationDB
INFERADB_MGMT__STORAGE__BACKEND=foundationdb
INFERADB_MGMT__STORAGE__FDB_CLUSTER_FILE=/etc/foundationdb/fdb.cluster

# Override ports
INFERADB_MGMT__SERVER__HTTP_PORT=4000
INFERADB_MGMT__SERVER__GRPC_PORT=4001

# Observability
INFERADB_MGMT__OBSERVABILITY__LOG_LEVEL=debug
INFERADB_MGMT__OBSERVABILITY__TRACING_ENABLED=true
```

See [`config.yaml`](config.yaml) for all options.

## Development

**Run Tests**:

```bash
cargo test                           # All tests
cargo test --package infera-management-core  # Specific crate
```

**Lint & Format**:

```bash
cargo clippy -- -D warnings
cargo fmt
```

**Generate Docs**:

```bash
cargo doc --no-deps --open
```

## Key Concepts

**Entities**:

- **User**: Individual account with authentication methods (password, passkey)
- **Organization**: Multi-tenant workspace with members and roles
- **Vault**: Authorization policy container with access grants
- **Client**: Backend service identity with Ed25519 certificates
- **Team**: Group-based vault access (future: policy inheritance)

**IDs**: All entities use Twitter Snowflake IDs (64-bit integers, globally unique, time-sortable)

**Authentication Flow**:

1. User authenticates → Management API issues session token
2. User requests vault access → Management API generates vault-scoped JWT
3. Application uses JWT → Server API evaluates authorization policies

See [`docs/Authentication.md`](docs/Authentication.md) for complete flow diagrams.

## Production Deployment

**Single Instance**:

```bash
cargo build --release

export INFERADB_MGMT__STORAGE__BACKEND=foundationdb
export INFERADB_MGMT__STORAGE__FDB_CLUSTER_FILE=/etc/foundationdb/fdb.cluster
export INFERADB_MGMT__AUTH__KEY_ENCRYPTION_SECRET=$(openssl rand -base64 32)

./target/release/inferadb-management --config /etc/inferadb/config.yaml
```

**Multi-Instance** (Kubernetes with leader election): See [`DEPLOYMENT.md`](DEPLOYMENT.md)

## Monitoring

**Metrics**: Prometheus format at `/metrics`

- HTTP request latency, status codes
- Database query performance
- Authentication attempts
- Rate limiting

**Logs**: Structured JSON (production) or human-readable (dev)

**Tracing**: Optional OpenTelemetry integration for distributed tracing

**Audit Logs**: Comprehensive audit trail for security and compliance. See [docs/AuditLogs.md](docs/AuditLogs.md) for:
- Event types and severity levels
- Querying and filtering
- Compliance reporting examples
- Integration with SIEM systems

## Performance & Load Testing

**Performance Benchmarks**: See [PERFORMANCE.md](PERFORMANCE.md) for:

- Latency characteristics (p50/p95/p99) for all operations
- Throughput benchmarks (RPS) under various loads
- Scalability guidelines (horizontal/vertical)
- Optimization recommendations

**Load Testing**: k6-based test suite in [`loadtests/`](loadtests/):

```bash
# Install k6 (macOS)
brew install k6

# Run authentication load test (100 concurrent users)
k6 run loadtests/auth.js

# Run all test scenarios
for test in auth vaults organizations spike; do
  k6 run loadtests/${test}.js
done
```

See [`loadtests/README.md`](loadtests/README.md) for detailed test scenarios and configuration.

## Documentation

- **[Overview](docs/Overview.md)**: Complete entity definitions, data model, and behavioral rules
- **[Authentication](docs/Authentication.md)**: Auth flows, token management, and security model
- **[Deployment](DEPLOYMENT.md)**: Production deployment, scaling, and high availability
- **[Performance](PERFORMANCE.md)**: Performance benchmarks, scalability, and optimization
- **[Contributing](CONTRIBUTING.md)**: Development workflow and contribution guidelines
- **[Plan](PLAN.md)**: Implementation roadmap and phase status

## API Examples

**Register User**:

```bash
curl -X POST http://localhost:3000/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "securepass123", "name": "Alice"}'
```

**Login**:

```bash
curl -X POST http://localhost:3000/v1/auth/login/password \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "securepass123"}'
```

**Create Vault**:

```bash
curl -X POST http://localhost:3000/v1/organizations/{org_id}/vaults \
  -H "Cookie: infera_session={session_id}" \
  -H "Content-Type: application/json" \
  -d '{"name": "Production Policies"}'
```

**Generate Vault JWT**:

```bash
curl -X POST http://localhost:3000/v1/organizations/{org_id}/vaults/{vault_id}/tokens \
  -H "Cookie: infera_session={session_id}"
```

See [OpenAPI.yaml](OpenAPI.yaml) for complete API endpoint specifications.

**Pagination**: All list endpoints support offset-based pagination. See [docs/Pagination.md](docs/Pagination.md) for:
- Query parameter usage (`limit`, `offset`)
- Response format and metadata
- Best practices and code examples
- Performance considerations

## Documentation

### Getting Started
- **[Getting Started Guide](docs/GettingStarted.md)**: Step-by-step tutorial for new users
- **[OpenAPI Specification](OpenAPI.yaml)**: Complete REST API reference
- **[Examples](docs/Examples.md)**: Real-world integration examples

### Core Concepts
- **[Overview](docs/Overview.md)**: Entities, relationships, and data model
- **[Architecture](docs/Architecture.md)**: System architecture and components
- **[Data Flows](docs/Flows.md)**: Detailed data flow diagrams

### Features
- **[Authentication](docs/Authentication.md)**: Auth flows, sessions, and security
- **[Authorization](docs/Authorization.md)**: Policy management and vault integration
- **[Pagination](docs/Pagination.md)**: List endpoints and pagination best practices
- **[Audit Logs](docs/AuditLogs.md)**: Security audit trail and compliance

### Operations
- **[Deployment](DEPLOYMENT.md)**: Production deployment guide
- **[Performance](PERFORMANCE.md)**: Benchmarks and optimization
- **[Troubleshooting](docs/Troubleshooting.md)**: Common issues and solutions
- **[Contributing](CONTRIBUTING.md)**: Development guidelines

## Troubleshooting

See [docs/Troubleshooting.md](docs/Troubleshooting.md) for comprehensive troubleshooting guide covering installation, database, authentication, API errors, performance, and deployment issues.

## License

Business Source License 1.1 (BSL 1.1)

- **Free**: Non-commercial, personal, internal business use
- **Restricted**: Commercial SaaS offerings require separate license
- **Transition**: Automatically converts to Apache 2.0 on January 1, 2031

See [`LICENSE.md`](LICENSE.md) for full terms.

## Support

- **Issues**: [github.com/inferadb/inferadb/issues](https://github.com/inferadb/inferadb/issues)
- **Docs**: [inferadb.com/docs](https://inferadb.com/docs)
- **Security**: [security@inferadb.com](mailto:security@inferadb.com)
