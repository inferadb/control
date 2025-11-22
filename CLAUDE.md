# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

InferaDB Management API is the control plane for InferaDB, providing user authentication, multi-tenant organization management, vault access control, and token issuance. Built in Rust with a layered architecture supporting pluggable storage backends.

**Storage Backends**:

- **MemoryBackend** (HashMap-based): Currently implemented, suitable for development/testing and single-instance deployments
- **FoundationDB** (Planned): Stub implementation in place, full production implementation planned for future release

**Binary**: `inferadb-management` (REST on port 3000, gRPC on port 3001)

## Common Commands

### Development

```bash
# Build debug
cargo build

# Build release
cargo build --release

# Run the management API server
cargo run --bin inferadb-management

# With custom config
cargo run --bin inferadb-management -- --config config.yaml
```

### Testing

```bash
# Run all tests
cargo test

# Run tests for specific crate
cargo test --package infera-management-core
cargo test --package infera-management-api

# Run specific test by name
cargo test test_create_vault

# Run tests with output
cargo test -- --nocapture

# Run integration tests only (located in crates/*/tests/)
cargo test --test vault_tests

# Run with FoundationDB backend (requires Docker)
cd docker/fdb-integration-tests
docker-compose up --build
```

### Linting & Formatting

```bash
# Format code
cargo fmt

# Check formatting without modifying
cargo fmt -- --check

# Run clippy lints
cargo clippy

# Clippy with warnings as errors
cargo clippy -- -D warnings
```

### Documentation

```bash
# Generate and open docs
cargo doc --no-deps --open

# Generate docs for all workspace crates
cargo doc --workspace --no-deps
```

### Docker & Services

```bash
# Start supporting services (FoundationDB, MailHog)
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down

# Clean restart (removes volumes)
docker-compose down -v
```

### Configuration

The API uses `config.yaml` or environment variables with `INFERADB_MGMT__` prefix:

```bash
# Required: encryption secret for client private keys
export INFERADB_MGMT__AUTH__KEY_ENCRYPTION_SECRET=$(openssl rand -base64 32)

# Use memory backend (default - only fully implemented backend)
export INFERADB_MGMT__STORAGE__BACKEND=memory

# Note: FoundationDB backend is planned but not yet implemented
# export INFERADB_MGMT__STORAGE__BACKEND=foundationdb
# export INFERADB_MGMT__STORAGE__FDB_CLUSTER_FILE=/etc/foundationdb/fdb.cluster

# Change ports
export INFERADB_MGMT__SERVER__HTTP_PORT=4000
export INFERADB_MGMT__SERVER__GRPC_PORT=4001
```

See `config.yaml` and `.env.example` for all options.

## Codebase Architecture

### Workspace Structure

```
crates/
├── infera-management/              # Main binary
├── infera-management-api/          # REST/gRPC handlers, middleware, routes
├── infera-management-core/         # Business logic, entities, repositories
├── infera-management-storage/      # Storage abstraction layer
├── infera-management-grpc/         # Server API gRPC client
└── infera-management-test-fixtures/ # Test utilities and fixtures
```

### Layered Architecture

The codebase follows strict layering:

1. **API Layer** (`infera-management-api/`)

   - Axum HTTP handlers in `handlers/`
   - Tonic gRPC services
   - Middleware: session auth, rate limiting, organization context, permission checks
   - Request/response DTOs and validation
   - Routes defined in `routes.rs`

2. **Core Layer** (`infera-management-core/`)

   - **Entities** (`entities/`): Domain models (User, Organization, Vault, etc.)
   - **Repositories** (`repository/`): Data access trait definitions
   - **Services**: JWT signing, email, cryptography, rate limiting
   - **Business Logic**: Password hashing, ID generation (Snowflake), leader election
   - All IDs are Twitter Snowflake format (64-bit, time-sortable, globally unique)

3. **Storage Layer** (`infera-management-storage/`)

   - **Backend Trait**: Async key-value interface with transactions
   - **Implementations**:
     - `MemoryBackend`: HashMap-based, fully implemented (suitable for development/testing and single-instance deployments)
     - `FdbBackend`: FoundationDB stub, planned for multi-instance production deployments (not yet implemented)
   - Factory pattern in `factory.rs` selects backend from config

4. **Integration Layer** (`infera-management-grpc/`)
   - Client for communicating with InferaDB Server (policy engine)
   - Vault synchronization, schema validation

### Key Design Patterns

**Repository Pattern**: All data access goes through repository traits defined in `infera-management-core/repository/`. Implementations live in `infera-management-storage/` backends. This enables swapping storage without changing business logic.

**RepositoryContext**: Central struct (`repository_context.rs`) that bundles all repositories together. Handlers receive `RepositoryContext` for data access.

**Snowflake IDs**: All entities use 64-bit Snowflake IDs generated via `IdGenerator`. Worker IDs (0-1023) prevent collisions in multi-instance deployments. Call `IdGenerator::init(worker_id)` once at startup.

**Middleware Chain**: Requests flow through middleware layers:

- Rate limiting (per-IP, per-user)
- Session validation (cookie-based)
- Organization context extraction
- Permission checks (RBAC: Owner, Admin, Member)
- Vault context extraction

**Error Handling**: Custom `Error` type in `core/error.rs` with thiserror. Handlers return `Result<Json<T>, Error>` which automatically converts to HTTP responses.

### Entity Relationships

**User → Organization → Vault** hierarchy:

- **User**: Has emails (UserEmail), sessions (UserSession), passkeys (PasskeyCredential)
- **Organization**: Contains members (OrganizationMember) with roles (Owner/Admin/Member)
- **Team**: Groups users within an organization with delegated permissions
- **Vault**: Authorization policy container, grants access to users/teams
- **Client**: Service identity with Ed25519 certificates for backend auth

**Access Control**:

- Organization-level: Role-based (Owner > Admin > Member)
- Vault-level: Grant-based (Admin > Manager > Writer > Reader)
- Team-level: Permission delegation (invite_members, manage_teams, etc.)

### Testing Patterns

**Integration Tests**: Located in `crates/infera-management-api/tests/`. Each file tests a specific domain:

- `vault_tests.rs`: Vault CRUD, grants
- `organization_tests.rs`: Org lifecycle
- `security_*.rs`: Authorization, isolation, input validation

**Test Helpers** (see `vault_tests.rs:1-64`):

- `create_test_state()`: AppState with MemoryBackend
- `create_test_app(state)`: Configured router with middleware
- `register_user(app, name, email, password)`: Returns session cookie
- `extract_session_cookie(headers)`: Parse Set-Cookie header

**Unit Tests**: Use `#[cfg(test)]` modules within source files. Mock external dependencies (email sender, Server API client).

**FoundationDB Tests**: `docker/fdb-integration-tests/` provides Docker-based FDB cluster setup for integration testing when the FDB backend is implemented. Currently uses MemoryBackend for tests.

### Configuration & Secrets

**Hierarchy**: `config.yaml` < environment variables (`INFERADB_MGMT__*`)

**Critical Secrets**:

- `AUTH__KEY_ENCRYPTION_SECRET`: Encrypts client Ed25519 private keys at rest (AES-GCM)
- `EMAIL__SMTP_PASSWORD`: SMTP authentication
- Never commit secrets. Use `.env` (gitignored) or secure secret management.

**Worker ID**: Required for multi-instance deployments to prevent Snowflake ID collisions. In Kubernetes, derive from pod ordinal (StatefulSet).

### Multi-Instance Coordination

**Leader Election**: Only one instance runs background jobs (session cleanup, email queue, expired token deletion). Uses storage backend locking (`leader.rs`). Note: Multi-instance coordination requires FoundationDB backend (not yet implemented), so currently limited to single-instance deployments with MemoryBackend.

**Worker Registry**: Each instance registers its Worker ID in storage backend with heartbeat. Stale registrations (>30s) auto-expire. Prevents ID collision on startup. Note: Requires FoundationDB backend for multi-instance deployments.

**Background Jobs** (`jobs.rs`): Periodic tasks run on leader only:

- Session cleanup (every 30s)
- Token expiration (every 30s)
- Email queue processing (every 10s)

### Storage Keyspace Organization

Planned FoundationDB keyspace structure (see `Architecture.md:298-349` for details):

```
users/{id}
users_by_email/{email}
organizations/{id}
organizations_by_name/{name}
org_members/{org_id}/{user_id}
vaults/{id}
vaults_by_org/{org_id}/{vault_id}
vault_grants_user/{vault_id}/{user_id}
sessions/{id}
workers/active/{worker_id}    # Multi-instance coordination (FDB only)
leader/lock                    # Leader election (FDB only)
jti_replay/{jti}              # JWT replay protection
```

Note: Currently, MemoryBackend uses HashMap-based storage with the same logical structure. When FoundationDB backend is implemented, this keyspace structure will enable efficient lookups and transactions across distributed instances.

### Authentication Flows

**User Auth**: Password (Argon2), Passkey (WebAuthn/FIDO2), or OAuth (future). Creates `UserSession` with secure cookie.

**Client Auth**: Ed25519 certificate → JWT assertion (RFC 7523) → exchange for vault-scoped JWT.

**Vault Access**: Management API generates short-lived JWT (1h) + refresh token (30d). JWT includes vault_id, role, user_id for Server API authorization.

See `docs/Authentication.md` and `docs/Flows.md` for sequence diagrams.

### Common Gotchas

1. **IdGenerator Init**: Must call `IdGenerator::init(worker_id)` before generating any IDs. Tests typically use `IdGenerator::init(1)` in setup.

2. **Transaction Retries**: FoundationDB transactions may retry on conflicts. Repository methods must be idempotent or handle retries gracefully.

3. **Session Cookies**: Use `infera_session` cookie name. Middleware extracts `UserSession` from cookie → loads from storage → validates expiration.

4. **Organization Isolation**: Always filter queries by org_id to prevent cross-tenant data leaks. Middleware sets `RequireOrganization` extension.

5. **Role Checks**: Owner > Admin > Member hierarchy. Owners can delete org, Admins can manage members, Members have read-only access (unless team permissions grant more).

6. **Vault Sync**: After creating/updating vault, Management API calls Server API gRPC to sync policies. VaultSyncStatus tracks success/failure.

### Documentation References

For architectural diagrams, entity definitions, and deployment guides, see:

- `docs/Architecture.md`: Component diagrams, deployment topologies
- `docs/Overview.md`: Complete entity reference and data model
- `docs/Flows.md`: Sequence diagrams for key operations
- `docs/Authentication.md`: Auth flows and security
- `OpenAPI.yaml`: REST API specification

When implementing features, consult the relevant doc first to understand design decisions and constraints.
