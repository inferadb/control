# InferaDB Control

Control plane for InferaDB: user authentication, multi-tenant organization management, vault access control, and token issuance.

**Binary:** `inferadb-control` (REST :3000, gRPC :3001)

## Quick Commands

```bash
# Build & Run
cargo build                                    # Debug build
cargo build --release                          # Release build
cargo run --bin inferadb-control               # Run server
cargo watch -x 'run --bin inferadb-control'    # Dev with auto-reload

# Testing
cargo test                                     # All tests
cargo test --package inferadb-control-core     # Specific crate
cargo test test_create_vault                   # Single test
cargo test -- --nocapture                      # With output

# Quality
cargo fmt                                      # Format
cargo clippy -- -D warnings                    # Lint
make check                                     # All checks
```

## Architecture

### Workspace Structure

| Crate                             | Purpose                                |
| --------------------------------- | -------------------------------------- |
| `inferadb-control`                | Main binary entry point                |
| `inferadb-control-api`            | REST/gRPC handlers, middleware, routes |
| `inferadb-control-core`           | Business logic, entities, repositories |
| `inferadb-control-storage`        | Storage backends (Memory, FDB planned) |
| `inferadb-control-engine-client`  | Engine API gRPC client                 |
| `inferadb-control-test-fixtures`  | Test utilities                         |

### Layered Architecture

```text
API Layer (handlers, middleware, routes)
    ↓
Core Layer (entities, repositories, services)
    ↓
Storage Layer (MemoryBackend, FdbBackend planned)
```

### Storage Backends

| Backend         | Status      | Use Case                     |
| --------------- | ----------- | ---------------------------- |
| `MemoryBackend` | Implemented | Dev/testing, single-instance |
| `FdbBackend`    | Planned     | Multi-instance production    |

## Entity Hierarchy

```text
User → Organization → Vault
  ├── UserEmail          ├── OrganizationMember (Owner/Admin/Member)
  ├── UserSession        ├── Team
  └── PasskeyCredential  └── Client (Ed25519 certs)
```

### Access Control

| Level        | Roles                                                      |
| ------------ | ---------------------------------------------------------- |
| Organization | Owner > Admin > Member                                     |
| Vault        | Admin > Manager > Writer > Reader                          |
| Team         | Delegated permissions (invite_members, manage_teams, etc.) |

## Critical Patterns

### 1. Repository Pattern

All data access through repository traits in `core/repository/`:

```rust
// Handlers receive RepositoryContext for data access
async fn create_vault(
    State(state): State<AppState>,
    Extension(repo): Extension<RepositoryContext>,
) -> Result<Json<Vault>, Error> {
    repo.vault_repository.create(vault).await?
}
```

### 2. Snowflake IDs

All entities use 64-bit Snowflake IDs (time-sortable, globally unique):

```rust
// Must initialize once at startup
IdGenerator::init(worker_id);  // worker_id: 0-1023

// Generate IDs
let id = IdGenerator::next_id();
```

### 3. Middleware Chain

Request flow: Rate Limit → Session → Org Context → Permissions → Vault Context

```rust
// Middleware sets extensions for handlers
Extension(session): Extension<UserSession>,
Extension(org): Extension<RequireOrganization>,
Extension(vault): Extension<VaultContext>,
```

### 4. Organization Isolation

**Always filter by org_id to prevent cross-tenant leaks:**

```rust
// Middleware sets RequireOrganization extension
let org = Extension(RequireOrganization { org_id });

// Repository methods filter by org_id
repo.vault_repository.find_by_org(org_id).await?
```

## Authentication

### User Auth

- Password (Argon2), Passkey (WebAuthn/FIDO2)
- Creates `UserSession` with secure `infera_session` cookie

### Client Auth

- Ed25519 certificate → JWT assertion (RFC 7523) → vault-scoped JWT
- Short-lived JWT (1h) + refresh token (30d)

### JWT Claims

```rust
pub struct VaultToken {
    pub vault_id: String,
    pub user_id: String,
    pub role: VaultRole,
    pub exp: i64,
}
```

## Configuration

**Env prefix:** `INFERADB_CTRL__` (double underscore separator)

```bash
# Required secrets
export INFERADB_CTRL__AUTH__KEY_ENCRYPTION_SECRET=$(openssl rand -base64 32)

# Storage backend (memory is default)
export INFERADB_CTRL__STORAGE__BACKEND=memory

# Ports
export INFERADB_CTRL__SERVER__HTTP_PORT=3000
export INFERADB_CTRL__SERVER__GRPC_PORT=3001
```

**Precedence:** config.yaml < environment variables

### Critical Secrets

| Secret                        | Purpose                                        |
| ----------------------------- | ---------------------------------------------- |
| `AUTH__KEY_ENCRYPTION_SECRET` | Encrypts client Ed25519 private keys (AES-GCM) |
| `EMAIL__SMTP_PASSWORD`        | SMTP authentication                            |

## Testing

### Test Helpers

```rust
// Standard test setup
let state = create_test_state().await;
let app = create_test_app(state);

// Register user, get session cookie
let cookie = register_user(&app, "Test", "test@example.com", "password").await;

// Extract cookie from response
let cookie = extract_session_cookie(response.headers());
```

### Test Organization

- Integration tests: `crates/inferadb-control-api/tests/`
- Unit tests: `#[cfg(test)]` modules in source files
- Fixtures: `crates/inferadb-control-test-fixtures/`

## Multi-Instance (FDB Required)

| Feature         | Description                                      |
| --------------- | ------------------------------------------------ |
| Leader Election | Single instance runs background jobs             |
| Worker Registry | Each instance registers Worker ID with heartbeat |
| Background Jobs | Session cleanup, token expiration, email queue   |

**Note:** Multi-instance requires FoundationDB backend (not yet implemented).

## Error Handling

```rust
// Custom Error type in core/error.rs
#[derive(Debug, Error)]
pub enum Error {
    #[error("Not found")]
    NotFound,
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Storage error")]
    Storage(#[from] StorageError),
}

// Handlers return Result<Json<T>, Error>
// Automatically converts to HTTP responses
```

## Common Gotchas

1. **IdGenerator::init()** - Must call before generating any IDs
2. **Session Cookie** - Use `infera_session` cookie name
3. **Organization Isolation** - Always filter queries by org_id
4. **Role Hierarchy** - Owner > Admin > Member
5. **Vault Sync** - After vault changes, sync to Server API via gRPC

## Code Quality

- **Format:** `cargo fmt`
- **Lint:** `cargo clippy -- -D warnings`
- **Tests:** `cargo test`

All tests must pass. Use `thiserror` for error types.

## Documentation

| Doc                      | Purpose                        |
| ------------------------ | ------------------------------ |
| `docs/architecture.md`   | Component diagrams, deployment |
| `docs/overview.md`       | Entity reference, data model   |
| `docs/flows.md`          | Sequence diagrams              |
| `docs/authentication.md` | Auth flows, security           |
| `openapi.yaml`           | REST API specification         |
