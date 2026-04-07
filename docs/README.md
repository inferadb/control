# InferaDB Control documentation

The Control Plane manages authentication, organizations, teams, vaults, clients, and access control for InferaDB.

## Quickstart

```bash
# Development mode (in-memory storage, no dependencies)
cargo run --bin inferadb-control -- --dev-mode

# Health check
curl http://127.0.0.1:9090/healthz
```

Production deployment requires a Ledger backend:

```bash
inferadb-control \
  --storage ledger \
  --ledger-endpoint https://ledger.inferadb.com \
  --ledger-client-id ctrl-01 \
  --frontend-url https://app.inferadb.com
```

## Documentation

### Architecture and data model

- **[Architecture](architecture.md)** -- System layers, deployment topologies, storage design, request lifecycle
- **[Overview](overview.md)** -- Entity definitions, API reference, behavioral rules, error taxonomy (~4600 lines; use search or the table of contents)

### Authentication

- **[Authentication](authentication.md)** -- Two-token architecture, email code flow, passkey/WebAuthn, TOTP, client assertion (JWT Bearer)

### API reference

- **[Pagination](pagination.md)** -- Cursor-based pagination: query parameters, response shape, page size limits
- **[Audit logs](audit-logs.md)** -- Event types, severity, querying, and retention

### Operations

- **[Deployment](deployment.md)** -- Single-instance and HA setup, Kubernetes config, health probes, graceful shutdown
- **[Data flows](flows.md)** -- Sequence diagrams for registration, login, token generation, organization setup
- **[Troubleshooting](troubleshooting.md)** -- Common issues and fixes for storage, auth, rate limiting, and deployment

### Testing

- **[Load tests](../loadtests/)** -- k6 scenarios for auth, vaults, organizations, and spike testing
- **[Ledger integration tests](../docker/ledger-integration-tests/)** -- Docker-based Ledger test environment

## Health endpoints

| Endpoint        | Purpose                                       |
| --------------- | --------------------------------------------- |
| `GET /livez`    | Liveness probe (process alive?)               |
| `GET /readyz`   | Readiness probe (Ledger reachable?)           |
| `GET /startupz` | Startup probe (initialization complete?)      |
| `GET /healthz`  | Detailed JSON status with version and uptime  |
| `GET /metrics`  | Prometheus metrics (network-policy protected) |

## Links

- [Issues](https://github.com/inferadb/inferadb/issues)
- [Docs](https://inferadb.com/docs)
- [Security reports](mailto:security@inferadb.com)
