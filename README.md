# InferaDB Management API

The Management API serves as the **Control Plane** for InferaDB, providing self-service capabilities for user registration, authentication, organization management, and vault access control.

## Overview

The Management API enables:

- **User Management**: Self-service registration, authentication (password, passkey), and profile management
- **Organization Management**: Multi-tenant organizations with role-based access control
- **Vault Management**: Authorization policy vaults with team and user-based access grants
- **Client Management**: Backend service authentication using Ed25519 certificates and client assertions
- **Token Management**: Vault-scoped JWT generation for accessing the InferaDB Server API

## Architecture

The Management API is built in Rust and consists of the following components:

- **infera-management**: Main binary (`inferadb-management`)
- **infera-management-core**: Core business logic and configuration
- **infera-management-storage**: Storage abstraction layer (in-memory, FoundationDB)
- **infera-management-grpc**: gRPC client for Server API communication
- **infera-management-api**: REST API handlers and routes
- **infera-management-test-fixtures**: Test utilities and fixtures

## Prerequisites

- **Rust**: 1.70 or later
- **FoundationDB**: 7.3.x (for production, optional for development)
- **Docker & Docker Compose**: For local development services

## Development Setup

### 1. Clone the Repository

```bash
git clone https://github.com/inferadb/inferadb.git
cd inferadb/management
```

### 2. Install Dependencies

The project uses standard Rust tooling:

```bash
cargo build
```

### 3. Configure Environment

Copy the example environment file and update with your settings:

```bash
cp .env.example .env
```

Edit `.env` and set:

- `INFERADB_MGMT__AUTH__KEY_ENCRYPTION_SECRET`: Generate with `openssl rand -base64 32`
- Other configuration as needed

### 4. Start Development Services

Start FoundationDB, MailHog, and other services using Docker Compose:

```bash
docker-compose up -d
```

This will start:

- **FoundationDB**: Port 4500 (key-value storage)
- **MailHog**: Port 1025 (SMTP), Port 8025 (Web UI)
- **Jaeger**: Port 4317 (OTLP), Port 16686 (Web UI)
- **Prometheus**: Port 9090
- **Grafana**: Port 3030 (admin/admin)

### 5. Run the Management API

```bash
cargo run --bin inferadb-management
```

The API will start on:

- HTTP: `http://localhost:3000`
- gRPC: `http://localhost:3001`

## Configuration

Configuration is managed via `config.yaml` with environment variable overrides.

### Configuration File

See [`config.yaml`](./config.yaml) for the default configuration.

### Environment Variable Overrides

All configuration values can be overridden using environment variables with the prefix `INFERADB_MGMT__`:

```bash
# Example: Override HTTP port
INFERADB_MGMT__SERVER__HTTP_PORT=4000

# Example: Use FoundationDB
INFERADB_MGMT__STORAGE__BACKEND=foundationdb
INFERADB_MGMT__STORAGE__FDB_CLUSTER_FILE=/etc/foundationdb/fdb.cluster
```

See [`.env.example`](./.env.example) for a complete list of environment variables.

## Building

### Debug Build

```bash
cargo build
```

### Release Build

```bash
cargo build --release
```

The binary will be located at `target/release/inferadb-management`.

## Testing

### Run All Tests

```bash
cargo test
```

### Run Tests with Coverage

```bash
cargo tarpaulin --out Html
```

### Run Specific Test Suite

```bash
cargo test --package infera-management-core
```

## Documentation

### Generate API Documentation

```bash
cargo doc --no-deps --open
```

### Architecture Documentation

See the following documents for detailed information:

- [docs/OVERVIEW.md](./docs/OVERVIEW.md): Complete entity definitions and behavioral rules
- [docs/AUTHENTICATION.md](./docs/AUTHENTICATION.md): Authentication flows and security

## Development Workflow

1. **Create a feature branch**:

   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Run tests and linters**:

   ```bash
   cargo test
   cargo clippy -- -D warnings
   cargo fmt --check
   ```

3. **Commit and push**:

   ```bash
   git add .
   git commit -m "feat: your feature description"
   git push origin feature/your-feature-name
   ```

4. **Create a pull request**

## API Endpoints

### Health Check

```bash
curl http://localhost:3000/health
```

Additional endpoints will be added as implementation progresses. See [PLAN.md](./PLAN.md) for the complete API roadmap.

## Production Deployment

### Single Instance

```bash
# Build release binary
cargo build --release

# Configure via environment variables
export INFERADB_MGMT__STORAGE__BACKEND=foundationdb
export INFERADB_MGMT__STORAGE__FDB_CLUSTER_FILE=/etc/foundationdb/fdb.cluster
export INFERADB_MGMT__AUTH__KEY_ENCRYPTION_SECRET=$(openssl rand -base64 32)

# Run
./target/release/inferadb-management --config /etc/inferadb/config.yaml
```

### Multi-Instance (Kubernetes)

For multi-instance deployments with leader election and distributed coordination, see the Kubernetes deployment guide (to be added in Phase 8).

## Monitoring

### Metrics

Prometheus metrics are exposed at `http://localhost:3000/metrics`.

### Logs

Structured logs are written to stdout in JSON format (production) or human-readable format (development).

Configure log level via:

```bash
INFERADB_MGMT__OBSERVABILITY__LOG_LEVEL=debug
```

### Tracing

Optional OpenTelemetry tracing can be enabled:

```bash
INFERADB_MGMT__OBSERVABILITY__TRACING_ENABLED=true
INFERADB_MGMT__OBSERVABILITY__OTLP_ENDPOINT=http://localhost:4317
```

View traces in Jaeger UI at `http://localhost:16686`.

## Troubleshooting

### FoundationDB Connection Issues

Ensure FoundationDB is running:

```bash
docker-compose ps foundationdb
```

Check cluster file exists:

```bash
cat /etc/foundationdb/fdb.cluster
```

### Email Delivery Issues

Check MailHog is running and view emails in the web UI at `http://localhost:8025`.

### Port Conflicts

If ports 3000 or 3001 are in use, override them:

```bash
INFERADB_MGMT__SERVER__HTTP_PORT=4000
INFERADB_MGMT__SERVER__GRPC_PORT=4001
```

## License

This project is licensed under the BSL 1.1 License. See the [LICENSE](../LICENSE) file for details.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for contribution guidelines.

## Support

For issues and questions:

- GitHub Issues: <https://github.com/inferadb/inferadb/issues>
- Documentation: <https://inferadb.com/docs>
