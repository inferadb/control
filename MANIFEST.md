# InferaDB Control Plane — Codebase Manifest

> Comprehensive crate-by-crate, file-by-file analysis of the InferaDB Control Plane.
> Generated 2026-02-05.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Crate: `control` (binary entrypoint)](#crate-control)
- [Crate: `api`](#crate-api)
- [Crate: `core`](#crate-core)
- [Crate: `types`](#crate-types)
- [Crate: `storage`](#crate-storage)
- [Crate: `config`](#crate-config)
- [Crate: `const`](#crate-const)
- [Crate: `test-fixtures`](#crate-test-fixtures)
- [Cross-Crate Observations](#cross-crate-observations)

---

## Architecture Overview

```
inferadb-control (bin) → api → core → storage → inferadb-common-storage → Ledger
                              → config
                              → types (shared across all)
                              → const (shared across all)
```

| Crate           | Purpose                                                       |
| --------------- | ------------------------------------------------------------- |
| `control`       | Binary entrypoint, CLI args, startup orchestration            |
| `api`           | HTTP/gRPC handlers, middleware, routing                       |
| `core`          | Auth, crypto, JWT, repositories, email, jobs, leader election |
| `types`         | Error enum, entities, DTOs, identity                          |
| `storage`       | Storage factory, backend abstraction, caching, coordination   |
| `config`        | Configuration loading and validation                          |
| `const`         | Zero-dependency shared constants                              |
| `test-fixtures` | Shared test utilities                                         |

---

## Crate: `control`

**Path:** `crates/control/` · **Type:** Binary · **Dependencies:** api, config, core, storage, types, anyhow, clap, tokio, tracing

### `src/main.rs`

**Purpose:** Binary entrypoint for the InferaDB Control API server. Handles CLI args, config loading, service initialization, and startup orchestration.

| Symbol   | Kind          | Description                                                                                                                      |
| -------- | ------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `Args`   | Struct (clap) | CLI arguments: `config` path, `json_logs`, `environment`, `dev_mode`                                                             |
| `main()` | Function      | Startup orchestration: crypto provider → args → config → logging → storage → worker ID → ID generator → identity → email → serve |

**`main()` Initialization Sequence:**

1. Install rustls crypto provider (`aws-lc-rs`)
2. Parse CLI args via `clap`
3. Clear terminal in non-production interactive environments
4. Load configuration via `ControlConfig::load()`
5. Apply environment defaults (dev fallback to memory storage)
6. Handle `--dev-mode` flag (force memory storage)
7. Validate configuration
8. Initialize logging
9. Create storage backend
10. Acquire worker ID with collision detection
11. Initialize ID generator (Snowflake)
12. Start worker registry heartbeat
13. Initialize Control identity (load PEM or generate Ed25519 keypair)
14. Initialize email service (optional SMTP)
15. Start API server via `inferadb_control_api::serve()`

**Insights:**

- Clean startup orchestration with explicit dependency ordering
- `anyhow::Result` at the binary boundary is idiomatic — libraries return typed errors, binary aggregates with `anyhow`
- Uses `load()` not `load_or_default()` — malformed config prevents startup (correct for production)
- Worker ID acquisition supports Kubernetes StatefulSet pod ordinals, explicit assignment, and random with collision detection
- Leader election (`Coordinator` trait) exists in the storage crate but is not wired up at startup (`leader: None`), suggesting it's planned
- No custom signal handling — relies on tokio's default via `inferadb_control_api::serve()`

---

## Crate: `api`

**Path:** `crates/api/` · **Type:** Library · **Dependencies:** config, const, core, storage, types, axum, bon, chrono, ed25519-dalek, jsonwebtoken, metrics-exporter-prometheus, serde, tokio, tower, tracing

### `src/lib.rs`

**Purpose:** Crate root with re-exports. Defines `ServicesConfig` and `serve()`.

| Symbol              | Kind     | Description                                                                          |
| ------------------- | -------- | ------------------------------------------------------------------------------------ |
| `ServicesConfig`    | Struct   | Optional `leader`, `email_service`, `control_identity` (all `Option<Arc<...>>`)      |
| `serve()`           | Function | Creates `AppState`, builds router, binds TCP listener, serves with graceful shutdown |
| `shutdown_signal()` | Function | Handles Ctrl+C and SIGTERM for graceful shutdown                                     |

### `src/routes.rs`

**Purpose:** Defines ALL API routes via `create_router_with_state()`.

| Symbol                       | Kind     | Description                                                                                                      |
| ---------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------- |
| `create_router_with_state()` | Function | Three route groups: org-scoped (session + org membership middleware), protected (session only), public (no auth) |

**Route Groups:**

- **Org-scoped:** Organizations CRUD, members, invitations, suspend/resume, clients, certificates, vaults, vault grants, schemas, tokens, audit logs, teams
- **Protected:** Sessions, token revocation, user profile, emails, org create/list, invitation accept, CLI auth, vault GET by ID
- **Public:** Health probes (`/livez`, `/readyz`, `/startupz`, `/healthz`), metrics, auth (register/login/logout/verify-email/password-reset), token refresh, client assertion, CLI token exchange

### `src/audit.rs`

**Purpose:** Fire-and-forget audit logging utilities.

| Symbol                 | Kind     | Description                                                                                           |
| ---------------------- | -------- | ----------------------------------------------------------------------------------------------------- |
| `AuditEventParams`     | Struct   | Fields for org_id, user_id, client_id, resource_type, resource_id, event_data, ip_address, user_agent |
| `log_audit_event()`    | Function | Fire-and-forget: errors logged but don't fail requests                                                |
| `extract_ip_address()` | Function | Checks X-Forwarded-For then X-Real-IP headers                                                         |
| `extract_user_agent()` | Function | Extracts User-Agent header                                                                            |

### `src/pagination.rs`

**Purpose:** Request/response pagination types.

| Symbol             | Kind   | Description                                                                              |
| ------------------ | ------ | ---------------------------------------------------------------------------------------- |
| `PaginationParams` | Struct | `limit` (default 50, max 100), `offset` (default 0); `validate()` clamps limit to 1..100 |
| `PaginationMeta`   | Struct | Response metadata: total, count, offset, limit, has_more                                 |
| `Paginated<T>`     | Struct | Generic wrapper with `data: Vec<T>` and `pagination: PaginationMeta`                     |

---

### Middleware (`src/middleware/`)

#### `middleware/session.rs`

| Symbol              | Kind       | Description                                                                                |
| ------------------- | ---------- | ------------------------------------------------------------------------------------------ |
| `SessionContext`    | Struct     | `session_id: i64`, `user_id: i64`                                                          |
| `require_session()` | Middleware | Extracts session from cookie or Bearer token, validates, updates activity (sliding window) |

#### `middleware/ratelimit.rs`

| Symbol                      | Kind       | Description                                                                                   |
| --------------------------- | ---------- | --------------------------------------------------------------------------------------------- |
| `login_rate_limit()`        | Middleware | 100 requests/hour per IP                                                                      |
| `registration_rate_limit()` | Middleware | 5 requests/day per IP                                                                         |
| `rate_limit_middleware()`   | Middleware | Generic limiter with custom categories/limits; sets `X-RateLimit-*` and `Retry-After` headers |

#### `middleware/organization.rs`

| Symbol                          | Kind       | Description                                                                                                                      |
| ------------------------------- | ---------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `OrganizationContext`           | Struct     | `organization_id`, `member: OrganizationMember`; methods: `has_permission()`, `is_member()`, `is_admin_or_owner()`, `is_owner()` |
| `require_organization_member()` | Middleware | Parses org ID from URI path segment[4], verifies membership, checks org not deleted                                              |

**Insight:** Path segment index coupling (hardcoded index 4) is fragile — would break silently if routes are restructured.

#### `middleware/permission.rs`

| Symbol                              | Kind     | Description                                                                                    |
| ----------------------------------- | -------- | ---------------------------------------------------------------------------------------------- |
| `has_organization_permission()`     | Function | Resolves permissions: Owner=all, Admin=all except owner actions, Member=check team permissions |
| `require_organization_permission()` | Function | Enforces a specific permission                                                                 |
| `get_user_permissions()`            | Function | Returns union of all effective permissions from role + team memberships                        |

#### `middleware/logging.rs`

| Symbol                 | Kind       | Description                                                                            |
| ---------------------- | ---------- | -------------------------------------------------------------------------------------- |
| `logging_middleware()` | Middleware | Logs method, path, status, duration, client_ip, user_agent; records Prometheus metrics |

#### `middleware/vault.rs`

| Symbol                   | Kind       | Description                                                                                                       |
| ------------------------ | ---------- | ----------------------------------------------------------------------------------------------------------------- |
| `VaultContext`           | Struct     | `vault_id`, `organization_id`, `role: VaultRole`; methods: `has_permission()`, `is_reader/writer/manager/admin()` |
| `require_vault_access()` | Middleware | Parses vault ID from path segment[6], verifies vault exists/not deleted/belongs to org, resolves user vault role  |
| `get_user_vault_role()`  | Function   | Checks direct user grant first, then team grants; returns highest role                                            |

---

### Handlers (`src/handlers/`)

#### `handlers/auth.rs`

**Purpose:** Authentication endpoints and core `AppState` definition.

| Symbol                     | Kind             | Description                                                                                                           |
| -------------------------- | ---------------- | --------------------------------------------------------------------------------------------------------------------- |
| `AppState`                 | Struct (Builder) | `storage`, `config`, `worker_id`, `start_time`, `leader`, `email_service`, `control_identity`; `new_test()` for tests |
| `ApiError`                 | Struct           | Wraps `CoreError`; implements `IntoResponse` with status code mapping and JSON error response                         |
| `register()`               | Handler          | POST `/v1/auth/register` — Creates user, email, verification token, session, default org with owner role              |
| `login()`                  | Handler          | POST `/v1/auth/login/password` — Email+password auth, creates session                                                 |
| `logout()`                 | Handler          | POST `/v1/auth/logout` — Revokes session, clears cookie                                                               |
| `verify_email()`           | Handler          | POST `/v1/auth/verify-email` — Validates token, marks email verified                                                  |
| `request_password_reset()` | Handler          | POST `/v1/auth/password-reset/request` — Generates reset token, sends email                                           |
| `confirm_password_reset()` | Handler          | POST `/v1/auth/password-reset/confirm` — Validates token, updates password, revokes ALL sessions                      |

**Insight:** `register()` creates 6+ entities without an explicit transaction boundary. A failure partway through could leave orphaned records.

#### `handlers/health.rs`

| Symbol               | Kind    | Description                                                            |
| -------------------- | ------- | ---------------------------------------------------------------------- |
| `livez_handler()`    | Handler | Always 200 (Kubernetes liveness)                                       |
| `readyz_handler()`   | Handler | Storage health check (Kubernetes readiness)                            |
| `startupz_handler()` | Handler | Delegates to readyz (Kubernetes startup)                               |
| `healthz_handler()`  | Handler | Full JSON response with storage health, leader status, uptime, version |

#### `handlers/tokens.rs`

**Purpose:** Vault-scoped JWT token lifecycle, client assertion auth (RFC 7523).

| Symbol                            | Kind    | Description                                                                                                       |
| --------------------------------- | ------- | ----------------------------------------------------------------------------------------------------------------- |
| `generate_vault_token()`          | Handler | POST — Creates JWT access token + refresh token; validates vault role                                             |
| `refresh_vault_token()`           | Handler | POST `/v1/tokens/refresh` — Validates, marks used (replay protection), rotates tokens                             |
| `ClientAssertionClaims`           | Struct  | JWT claims for RFC 7523: `iss`, `sub`, `_aud`, `exp`, `_iat`, `jti`                                               |
| `client_assertion_authenticate()` | Handler | POST `/v1/token` — OAuth 2.0 JWT Bearer flow: decode header for `kid`, verify Ed25519 signature, check JTI replay |
| `revoke_vault_tokens()`           | Handler | POST `/v1/tokens/revoke/vault/:vault_id` — Vault admin only                                                       |

**Insight:** Refresh token rotation (issue new, invalidate old) is a security best practice. Second use of a rotated token returns 401, indicating potential theft.

#### `handlers/users.rs`

| Symbol             | Kind    | Description                                                                                                 |
| ------------------ | ------- | ----------------------------------------------------------------------------------------------------------- |
| `get_profile()`    | Handler | GET — Returns authenticated user's profile                                                                  |
| `update_profile()` | Handler | PATCH — Updates display name with validation                                                                |
| `delete_user()`    | Handler | DELETE — Validates not last owner of any org; cascades: sessions, memberships, emails, tokens; soft-deletes |

#### `handlers/emails.rs`

| Symbol                  | Kind    | Description                                     |
| ----------------------- | ------- | ----------------------------------------------- |
| `add_email()`           | Handler | POST — Adds email, generates verification token |
| `list_emails()`         | Handler | GET — Lists all user emails                     |
| `update_email()`        | Handler | PATCH — Sets primary (must be verified first)   |
| `verify_email()`        | Handler | POST — Validates verification token             |
| `resend_verification()` | Handler | POST — Generates new verification token         |
| `delete_email()`        | Handler | DELETE — Cannot delete primary email            |

#### `handlers/sessions.rs`

| Symbol                    | Kind    | Description                                                    |
| ------------------------- | ------- | -------------------------------------------------------------- |
| `list_sessions()`         | Handler | GET — Lists active sessions                                    |
| `revoke_session()`        | Handler | DELETE — Revokes specific session (ownership check)            |
| `revoke_other_sessions()` | Handler | POST — Revokes all except current ("sign out everywhere else") |

#### `handlers/organizations.rs`

**Purpose:** Organization lifecycle, member management, invitations. The most complex handler module.

| Symbol                     | Kind    | Description                                                                                 |
| -------------------------- | ------- | ------------------------------------------------------------------------------------------- |
| `create_organization()`    | Handler | POST — Tier limits, verified email required, creator becomes OWNER                          |
| `list_organizations()`     | Handler | GET — Paginated user orgs                                                                   |
| `get_organization()`       | Handler | GET — Requires membership                                                                   |
| `get_organization_by_id()` | Handler | GET `/v1/engine/organizations/:id` — Engine-internal, no membership required                |
| `update_organization()`    | Handler | PATCH — Admin/owner required                                                                |
| `delete_organization()`    | Handler | DELETE — Owner required, fails if active vaults exist; cascades teams, members, invitations |
| `suspend_organization()`   | Handler | POST — Owner only                                                                           |
| `resume_organization()`    | Handler | POST — Owner only                                                                           |
| `list_members()`           | Handler | GET — Lists all members                                                                     |
| `update_member_role()`     | Handler | PATCH — Cannot demote last owner                                                            |
| `remove_member()`          | Handler | DELETE — Cannot remove last owner                                                           |
| `leave_organization()`     | Handler | POST — Cannot leave if last owner                                                           |
| `create_invitation()`      | Handler | POST — Tier member limits, duplicate checks, optional email                                 |
| `list_invitations()`       | Handler | GET — Pending invitations                                                                   |
| `delete_invitation()`      | Handler | DELETE — Cancels invitation                                                                 |
| `accept_invitation()`      | Handler | POST — Validates token, checks email match, creates membership                              |

**Insight:** "Last owner" protection is enforced consistently across role update, member removal, and self-departure — every org must always have at least one owner.

#### `handlers/clients.rs`

**Purpose:** API client management and Ed25519 certificate lifecycle with Ledger integration.

| Symbol                 | Kind    | Description                                                                                                                        |
| ---------------------- | ------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `create_client()`      | Handler | POST — Creates API client for organization                                                                                         |
| `list_clients()`       | Handler | GET — Lists org clients                                                                                                            |
| `get_client()`         | Handler | GET — Single client                                                                                                                |
| `update_client()`      | Handler | PATCH — Name/description                                                                                                           |
| `delete_client()`      | Handler | DELETE — Soft-delete                                                                                                               |
| `create_certificate()` | Handler | POST — Generates Ed25519 keypair, encrypts private key, writes public key to Ledger, creates audit log. Private key returned once. |
| `list_certificates()`  | Handler | GET — Certificate metadata                                                                                                         |
| `get_certificate()`    | Handler | GET — Single certificate                                                                                                           |
| `revoke_certificate()` | Handler | POST — Marks revoked in Control + Ledger, audit log                                                                                |
| `rotate_certificate()` | Handler | POST — Creates new cert with grace period, writes to Ledger with future `valid_from` for zero-downtime rotation                    |

**Insight:** Certificate rotation with grace period (`valid_from` in the future) enables zero-downtime key rotation. The private key is encrypted at rest and returned only once. Dual-write to Control + Ledger creates a consistency concern if the Ledger write fails.

#### `handlers/vaults.rs`

**Purpose:** Vault lifecycle and access grant management (user + team level).

| Symbol                | Kind    | Description                                               |
| --------------------- | ------- | --------------------------------------------------------- |
| `create_vault()`      | Handler | POST — Tier limits, auto-grants creator ADMIN             |
| `list_vaults()`       | Handler | GET — Accessible vaults                                   |
| `get_vault()`         | Handler | GET — Vault details (requires vault access)               |
| `get_vault_by_id()`   | Handler | GET `/v1/engine/vaults/:id` — Engine-internal             |
| `update_vault()`      | Handler | PATCH — Vault admin required                              |
| `delete_vault()`      | Handler | DELETE — Cascades grants; checks no active refresh tokens |
| `create_user_grant()` | Handler | POST — Grant user vault access                            |
| `list_user_grants()`  | Handler | GET                                                       |
| `update_user_grant()` | Handler | PATCH — Change role                                       |
| `delete_user_grant()` | Handler | DELETE — Revoke access                                    |
| `create_team_grant()` | Handler | POST — Grant team vault access                            |
| `list_team_grants()`  | Handler | GET                                                       |
| `update_team_grant()` | Handler | PATCH — Change role                                       |
| `delete_team_grant()` | Handler | DELETE — Revoke access                                    |

**BUG:** `delete_team_grant()` appears to call `vault_user_grant.delete()` instead of `vault_team_grant.delete()`. Copy-paste error — team grant deletion would incorrectly delete a user grant or fail.

#### `handlers/teams.rs`

| Symbol                     | Kind    | Description                            |
| -------------------------- | ------- | -------------------------------------- |
| `create_team()`            | Handler | POST — Tier limits                     |
| `list_teams()`             | Handler | GET                                    |
| `get_team()`               | Handler | GET                                    |
| `update_team()`            | Handler | PATCH — Admin/owner or team manager    |
| `delete_team()`            | Handler | DELETE — Cascades members, permissions |
| `add_team_member()`        | Handler | POST — Verifies org membership first   |
| `list_team_members()`      | Handler | GET                                    |
| `update_team_member()`     | Handler | PATCH — Manager status                 |
| `remove_team_member()`     | Handler | DELETE                                 |
| `grant_team_permission()`  | Handler | POST — Owner only                      |
| `list_team_permissions()`  | Handler | GET — Admin/owner or team members      |
| `revoke_team_permission()` | Handler | DELETE — Owner only                    |

#### `handlers/audit_logs.rs`

| Symbol               | Kind    | Description                                     |
| -------------------- | ------- | ----------------------------------------------- |
| `create_audit_log()` | Handler | POST `/internal/audit` — Internal-only          |
| `list_audit_logs()`  | Handler | GET — Owner-only, with filtering and pagination |

#### `handlers/metrics.rs`

| Symbol              | Kind     | Description                             |
| ------------------- | -------- | --------------------------------------- |
| `METRICS_HANDLE`    | Static   | `OnceLock<PrometheusHandle>` singleton  |
| `init_exporter()`   | Function | Initializes Prometheus recorder (once)  |
| `metrics_handler()` | Handler  | GET `/metrics` — Prometheus text format |

#### `handlers/cli_auth.rs`

**Purpose:** PKCE-based CLI authentication flow.

| Symbol                 | Kind    | Description                                                                       |
| ---------------------- | ------- | --------------------------------------------------------------------------------- |
| `cli_authorize()`      | Handler | POST — Browser-side; generates auth code bound to session and PKCE code_challenge |
| `cli_token_exchange()` | Handler | POST — CLI-side; exchanges code + code_verifier for 7-day CLI session             |

#### `handlers/schemas.rs`

**Purpose:** Schema version management for vaults.

| Symbol                 | Kind    | Description                                                          |
| ---------------------- | ------- | -------------------------------------------------------------------- |
| `deploy_schema()`      | Handler | POST — Auto-increment or explicit version; duplicate rejection       |
| `list_schemas()`       | Handler | GET — Optional status filter, pagination                             |
| `get_schema()`         | Handler | GET — By version number                                              |
| `get_current_schema()` | Handler | GET — Active schema                                                  |
| `activate_schema()`    | Handler | POST — Marks ACTIVE                                                  |
| `rollback_schema()`    | Handler | POST — Reactivates previous version                                  |
| `diff_schemas()`       | Handler | POST — Placeholder (returns empty changes; diff delegated to Engine) |

---

### Test Suite (`tests/`)

| Test File                            | Tests | Coverage                                                                                                                                                              |
| ------------------------------------ | ----- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `schema_tests.rs`                    | 10    | Deploy, auto-version, explicit version, list, get, activate, rollback, diff, duplicate rejection, 404                                                                 |
| `team_tests.rs`                      | 5     | Create, list, add member, grant permission, grant vault access                                                                                                        |
| `security_input_validation_tests.rs` | 11    | XSS, path traversal, null bytes, empty names, long names, Unicode edge cases (ZWJ, directional overrides, Zalgo), SQL injection, control chars, pagination boundaries |
| `organization_tests.rs`              | 7     | Registration default org, CRUD, non-member 403                                                                                                                        |
| `client_tests.rs`                    | 13    | Client CRUD, certificate CRUD, rotation, Ledger integration, audit log                                                                                                |
| `organization_invitation_tests.rs`   | 2     | Create+list, delete                                                                                                                                                   |
| `organization_member_tests.rs`       | 7     | List, update role, cannot demote last owner, remove, cannot remove last owner, leave, last owner cannot leave                                                         |
| `vault_tests.rs`                     | 6     | CRUD, grant access, revoke access                                                                                                                                     |
| `security_isolation_tests.rs`        | 8     | Cross-org vault/client/team access, modify/delete isolation, member list isolation, JWT isolation                                                                     |
| `audit_log_tests.rs`                 | 6     | Creation, list, filtering, pagination, query, retention cleanup                                                                                                       |
| `jwks_verify_test.rs`                | 2     | Ed25519 generate/sign/verify, PEM conversion                                                                                                                          |
| `security_authorization_tests.rs`    | 11    | RBAC enforcement: member/admin escalation prevention, member cannot create/delete/remove/update/team                                                                  |
| `edge_case_tests.rs`                 | 3     | Concurrent vault access, expired token refresh, cert rotation                                                                                                         |
| `token_tests.rs`                     | 4     | Generate, refresh flow, replay protection, revocation                                                                                                                 |

**Total: 95 integration tests**

---

## Crate: `core`

**Path:** `crates/core/` · **Type:** Library · **Dependencies:** types, storage, const, aes-gcm, argon2, ed25519-dalek, jsonwebtoken, idgenerator, lettre, webauthn-rs, tokio, tracing, metrics, bon

### `src/lib.rs`

**Purpose:** Crate root. Re-exports all public types organized by domain concern.

`#![deny(unsafe_code)]` applied crate-wide.

### `src/clock.rs`

**Purpose:** System clock validation against NTP for distributed deployments.

| Symbol                       | Kind   | Description                                                                      |
| ---------------------------- | ------ | -------------------------------------------------------------------------------- |
| `ClockValidator`             | Struct | Checks system time against NTP servers via CLI tools (`chronyc`, `ntpdate`)      |
| `ClockValidator::validate()` | Method | Performs NTP query, returns skew analysis. Soft-fails if no NTP client available |
| `ClockStatus`                | Struct | `system_time`, `ntp_time`, `skew_seconds`, `within_threshold`                    |

**Insight:** NTP parsing is placeholder-level — checks tool output format but returns `Utc::now()` rather than actual NTP time. Comment acknowledges: "In production, use a proper NTP client library."

### `src/crypto.rs`

**Purpose:** Master encryption key (AES-256-GCM) for encrypting Ed25519 private keys at rest, plus keypair generation.

| Symbol                           | Kind     | Description                                                                            |
| -------------------------------- | -------- | -------------------------------------------------------------------------------------- |
| `MasterKey`                      | Struct   | 256-bit key wrapper with secure zeroing on drop                                        |
| `MasterKey::load_or_generate()`  | Method   | Load from file or auto-generate, sets 0600 permissions                                 |
| `PrivateKeyEncryptor`            | Struct   | AES-256-GCM encryption service                                                         |
| `PrivateKeyEncryptor::encrypt()` | Method   | Encrypts 32-byte private key, returns base64 (nonce + ciphertext)                      |
| `PrivateKeyEncryptor::decrypt()` | Method   | Decrypts base64 ciphertext back to 32 bytes                                            |
| `keypair::generate()`            | Function | Generates Ed25519 keypair; returns (URL-safe base64 public key, raw private key bytes) |

**Insights:**

- Random nonces via OsRng, proper AEAD — solid cryptographic implementation
- `Drop` manually zeros the master key, but `[u8; 32]` is `Copy` so compiler copies during moves may leave unzeroed stack copies. `zeroize` crate is a dependency but not used here — `ZeroizeOnDrop` derive would be more robust
- Decrypt returns `Vec<u8>` with no compile-time zeroize enforcement

### `src/id.rs`

**Purpose:** Snowflake ID generation with distributed worker ID coordination.

| Symbol                   | Kind     | Description                                                          |
| ------------------------ | -------- | -------------------------------------------------------------------- |
| `WorkerRegistry<S>`      | Struct   | Worker ID registration/heartbeats in storage for collision detection |
| `IdGenerator`            | Struct   | Zero-sized type exposing static Snowflake ID generation              |
| `IdGenerator::init(u16)` | Method   | One-time global initialization with worker ID (0-1023)               |
| `IdGenerator::next_id()` | Method   | Generates next unique Snowflake ID                                   |
| `acquire_worker_id()`    | Function | Acquire via explicit, K8s ordinal, or random strategy                |

**Insight:** Well-designed multi-strategy: explicit > K8s ordinal > random with collision detection. Custom epoch is 2024-01-01T00:00:00Z.

### `src/jobs.rs`

**Purpose:** Background job scheduler that runs periodic cleanup on the leader instance only.

| Symbol                    | Kind   | Description                                                                                                                              |
| ------------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `BackgroundJobs<S>`       | Struct | Scheduler with shutdown flag and task handles                                                                                            |
| `BackgroundJobs::start()` | Method | Spawns: session cleanup, token cleanup, refresh token cleanup, authz code cleanup, audit log retention (90d), revoked cert cleanup (90d) |
| `BackgroundJobs::stop()`  | Method | Signals shutdown, aborts handles                                                                                                         |

**Insight:** Two of six jobs are no-ops (TTL handles cleanup). Leader-only execution prevents duplicate work in multi-instance deployments.

### `src/jwt.rs`

**Purpose:** JWT signing/verification for vault-scoped access tokens using Ed25519 (EdDSA).

| Symbol                            | Kind   | Description                                                                                |
| --------------------------------- | ------ | ------------------------------------------------------------------------------------------ |
| `VaultTokenClaims`                | Struct | JWT claims: `iss`, `sub`, `aud`, `exp`, `iat`, `org_id`, `vault_id`, `vault_role`, `scope` |
| `JwtSigner`                       | Struct | Signing/verification service wrapping `PrivateKeyEncryptor`                                |
| `JwtSigner::sign_vault_token()`   | Method | Signs claims with certificate's private key, includes `kid` header                         |
| `JwtSigner::verify_vault_token()` | Method | Verifies and decodes JWT using certificate's public key                                    |

**Insights:**

- Ed25519 private key manually wrapped into PKCS#8 DER with hardcoded ASN.1 bytes — correct but fragile
- Audience validation disabled in `verify_vault_token` — potential security risk if callers forget to validate
- Role-to-scope mapping is hardcoded with InferaDB-specific permission names

### `src/leader.rs`

**Purpose:** Leader election using storage as distributed lock with TTL-based lease.

| Symbol                     | Kind   | Description                                                              |
| -------------------------- | ------ | ------------------------------------------------------------------------ |
| `LeaderElection<S>`        | Struct | Coordinator with storage, instance ID, leader status flag, shutdown flag |
| `try_acquire_leadership()` | Method | Attempts to acquire leader lease                                         |
| `is_leader()`              | Method | Cached local check via `RwLock<bool>`                                    |
| `start_lease_renewal()`    | Method | Background renewal (10s interval, 30s TTL)                               |

**Insight:** Not truly atomic (check-then-set TOCTOU race). Acceptable for TTL-based approach since leases expire quickly.

### `src/logging.rs`

**Purpose:** Structured logging with Full/Pretty/Compact/JSON formats and optional OpenTelemetry.

| Symbol                | Kind     | Description                            |
| --------------------- | -------- | -------------------------------------- |
| `LogFormat`           | Enum     | `Full`, `Pretty`, `Compact`, `Json`    |
| `init()`              | Function | Simplified initialization              |
| `init_with_tracing()` | Function | With OpenTelemetry OTLP (10% sampling) |

### `src/metrics.rs`

**Purpose:** Prometheus metrics registration and recording.

| Symbol                  | Kind     | Description                                  |
| ----------------------- | -------- | -------------------------------------------- |
| `init()`                | Function | Register all metrics (idempotent via `Once`) |
| `record_http_request()` | Function | Counter + histogram                          |
| `record_auth_attempt()` | Function | Counter by type/success                      |
| `record_db_query()`     | Function | Histogram for DB latency                     |
| `set_is_leader()`       | Function | Gauge (1.0 or 0.0)                           |

### `src/ratelimit.rs`

**Purpose:** Distributed rate limiter using fixed-window algorithm with storage-backed TTL.

| Symbol                 | Kind   | Description                             |
| ---------------------- | ------ | --------------------------------------- |
| `RateLimit`            | Struct | Config with `max_requests` and `window` |
| `RateLimiter<S>`       | Struct | Storage-backed rate limiter             |
| `RateLimiter::check()` | Method | Check and increment counter             |
| `RateLimitResult`      | Struct | `allowed`, `remaining`, `reset_after`   |

**Insight:** Fixed-window, not atomic (read-then-write). Under high concurrency a few extra requests could sneak through, acceptable for defined limits (100/hr, 5/day).

### `src/repository_context.rs`

**Purpose:** Consolidated repository factory creating all 21 repositories from a single storage backend.

| Symbol                      | Kind   | Description                                              |
| --------------------------- | ------ | -------------------------------------------------------- |
| `RepositoryContext<S>`      | Struct | Public fields for every repository type                  |
| `RepositoryContext::new(S)` | Method | Clones storage 22 times (cheap for Arc-wrapped backends) |

### `src/startup.rs`

**Purpose:** Terminal-aware startup display with ASCII art banner and TRON-aesthetic config tables.

| Symbol                                  | Kind      | Description                                            |
| --------------------------------------- | --------- | ------------------------------------------------------ |
| `ServiceInfo`                           | Struct    | Name, subtext, version, environment                    |
| `StartupDisplay`                        | Builder   | Renders banner + config summary with responsive layout |
| `log_phase/log_initialized/log_ready()` | Functions | Lifecycle phase logging helpers                        |

### `src/auth/password.rs`

**Purpose:** Password hashing with Argon2id (NIST-recommended parameters).

| Symbol                                | Kind   | Description                                         |
| ------------------------------------- | ------ | --------------------------------------------------- |
| `PasswordHasher`                      | Struct | Argon2id with 19 MiB memory, 2 iterations, 1 thread |
| `PasswordHasher::hash()`              | Method | Hash with random salt, returns PHC format           |
| `PasswordHasher::verify()`            | Method | Verify against PHC hash                             |
| `PasswordHasher::validate_password()` | Method | Length validation: 12-128 chars (NIST SP 800-63B)   |

### `src/email/service.rs`

**Purpose:** Email sending abstraction with SMTP implementation and mock.

| Symbol             | Kind   | Description                                              |
| ------------------ | ------ | -------------------------------------------------------- |
| `EmailSender`      | Trait  | `async fn send_email(to, subject, body_html, body_text)` |
| `SmtpEmailService` | Struct | Production SMTP via `lettre`                             |
| `MockEmailSender`  | Struct | Test double (logs, doesn't send)                         |

**Insight:** HTML and text bodies combined with `---` separator in single content-type email rather than proper multipart/alternative MIME.

### `src/email/templates.rs`

**Purpose:** Email template definitions with HTML and plaintext variants.

| Template                                   | Usage                               |
| ------------------------------------------ | ----------------------------------- |
| `VerificationEmailTemplate`                | Email verification with link + code |
| `PasswordResetEmailTemplate`               | Password reset with link + code     |
| `InvitationEmailTemplate`                  | Org invitation with link + token    |
| `InvitationAcceptedEmailTemplate`          | Notification to org owner           |
| `RoleChangeEmailTemplate`                  | Role change notification            |
| `OrganizationDeletionWarningEmailTemplate` | Pending deletion warning            |

**Insight:** XSS risk if `inviter_name` or `organization_name` contain HTML special characters — user input should be HTML-escaped before interpolation.

---

### Repositories (`src/repository/`)

All 16 repositories follow a consistent pattern:

1. `XxxRepository<S: StorageBackend>` with a single `storage: S` field
2. Key schema documented in doc comments (e.g., `"client:{id}"`, `"client:org:{org_id}:{idx}"`)
3. CRUD methods with secondary index management
4. Transactions for multi-key operations
5. JSON serialization via `serde_json`
6. `parse_i64_id()` utility for 8-byte LE index lookups

#### `repository/audit_log.rs`

| Method                   | Description                                           |
| ------------------------ | ----------------------------------------------------- |
| `create()`               | Store audit log entry                                 |
| `get()`                  | By ID                                                 |
| `list_by_organization()` | Paginated with filters (scans all, filters in memory) |
| `delete_older_than()`    | Retention cleanup                                     |

#### `repository/authorization_code.rs`

| Method          | Description              |
| --------------- | ------------------------ |
| `create()`      | With TTL matching expiry |
| `get_by_code()` | Lookup by code string    |
| `mark_used()`   | One-time use             |
| `is_valid()`    | Not expired AND not used |

#### `repository/client.rs`

| Method                          | Description                        |
| ------------------------------- | ---------------------------------- |
| `create()`                      | Org-scoped unique name enforcement |
| `list_by_organization()`        | All clients                        |
| `list_active_by_organization()` | Loads all, filters in memory       |
| `count_by_organization()`       | Loads full list to count           |

#### `repository/client_certificate.rs`

| Method                        | Description                                             |
| ----------------------------- | ------------------------------------------------------- |
| `create()`                    | Globally-unique `kid` enforcement                       |
| `get_by_kid()`                | O(1) lookup — performance-critical for JWT verification |
| `list_all_active()`           | Scans `cert:` prefix, filters by key format             |
| `delete_revoked_older_than()` | 90-day retention cleanup                                |

#### `repository/jti_replay_protection.rs`

| Method                 | Description                               |
| ---------------------- | ----------------------------------------- |
| `check_and_mark_jti()` | TTL matches JWT expiration — auto-expires |
| `is_jti_used()`        | Check if JTI already recorded             |

**Insight:** Elegant TTL usage. Not truly atomic (read-then-write), but window is very small.

#### `repository/organization.rs`

Two repositories: `OrganizationRepository` (CRUD + name lookup + global count) and `OrganizationMemberRepository` (bidirectional user-org indexes).

#### `repository/organization_invitation.rs`

Token-based lookup, email+org duplicate prevention.

#### `repository/passkey_credential.rs`

WebAuthn credential storage with user-credential and credential-ID indexes.

#### `repository/team.rs`

Three repositories: `OrganizationTeamRepository`, `OrganizationTeamMemberRepository`, `OrganizationTeamPermissionRepository`. Team names unique within org.

#### `repository/user.rs`

User CRUD with soft/hard delete. `get()` auto-filters deleted users.

#### `repository/user_email.rs`

Multiple emails per user, verification, primary designation, global email uniqueness.

#### `repository/user_email_verification_token.rs` / `user_password_reset_token.rs`

Token storage with lookups by token string. Significant structural duplication between the two.

#### `repository/user_session.rs`

Concurrent session limits (evicts oldest at `MAX_CONCURRENT_SESSIONS`), sliding window activity, revocation, cleanup.

#### `repository/vault.rs`

Three repositories: `VaultRepository`, `VaultUserGrantRepository`, `VaultTeamGrantRepository`. Vault names unique within org. Bidirectional grant lookups.

#### `repository/vault_refresh_token.rs`

Five index keys per token. Supports session-bound and client-bound tokens. Bulk revocation by session/client/vault.

#### `repository/vault_schema.rs`

Schema versioning with Validating → Deployed → Active → Superseded/RolledBack lifecycle. `activate()` handles previous-active superseding transactionally.

---

## Crate: `types`

**Path:** `crates/types/` · **Type:** Library · **Dependencies:** bon, chrono, serde, snafu, base64, ed25519-dalek, hex, sha2, webauthn-rs, rand, zeroize, jsonwebtoken

`#![deny(unsafe_code)]` at crate root.

### `src/lib.rs`

**Purpose:** Crate root. Re-exports ~100 types from entities and DTOs.

| Type             | Description                                                                                               |
| ---------------- | --------------------------------------------------------------------------------------------------------- |
| `PaginationMeta` | Pagination metadata; `from_total()` (exact) and `from_count()` (heuristic: `count == limit` implies more) |

### `src/id.rs`

| Type          | Description                                                                                                        |
| ------------- | ------------------------------------------------------------------------------------------------------------------ |
| `IdGenerator` | Zero-field struct; `next_id()` delegates to `idgenerator::IdInstance`. Will panic if called before initialization. |

### `src/error.rs`

**Purpose:** Unified error enum with 12 variants.

| Variant           | Status | Code                     | Purpose                  |
| ----------------- | ------ | ------------------------ | ------------------------ |
| `Config`          | 500    | `CONFIGURATION_ERROR`    | Configuration errors     |
| `Storage`         | 500    | `STORAGE_ERROR`          | Storage layer failures   |
| `Auth`            | 401    | `AUTHENTICATION_ERROR`   | Authentication failures  |
| `Authz`           | 403    | `AUTHORIZATION_ERROR`    | Authorization failures   |
| `Validation`      | 400    | `VALIDATION_ERROR`       | Input validation         |
| `NotFound`        | 404    | `NOT_FOUND`              | Resource not found       |
| `AlreadyExists`   | 409    | `ALREADY_EXISTS`         | Duplicate resource       |
| `RateLimit`       | 429    | `RATE_LIMIT_EXCEEDED`    | Rate limiting            |
| `TierLimit`       | 402    | `TIER_LIMIT_EXCEEDED`    | Tier quota exceeded      |
| `TooManyPasskeys` | 400    | `TOO_MANY_PASSKEYS`      | Passkey limit            |
| `External`        | 502    | `EXTERNAL_SERVICE_ERROR` | External service failure |
| `Internal`        | 500    | `INTERNAL_ERROR`         | Internal system error    |

Factory methods: `Error::validation("msg")`, `Error::not_found("msg")`, etc.

### `src/identity.rs`

**Purpose:** Ed25519 keypair identity for control-to-engine JWT authentication, JWKS generation per RFC 7638.

| Symbol                  | Kind       | Description                                                                                                 |
| ----------------------- | ---------- | ----------------------------------------------------------------------------------------------------------- |
| `ControlIdentity`       | Struct     | `control_id`, `kid` (public), `signing_key`, `verifying_key` (private)                                      |
| `generate()`            | Method     | Random Ed25519 keypair, derives control_id from pod name/hostname, computes RFC 7638 JWK Thumbprint for kid |
| `from_pem()`            | Method     | Restores from PKCS#8 PEM (extracts last 32 bytes — simplified)                                              |
| `sign_jwt()`            | Method     | Signs 5-min JWT with admin scope, UUID v4 jti                                                               |
| `to_jwks()`             | Method     | JWKS representation of public key                                                                           |
| `SharedControlIdentity` | Type alias | `Arc<ControlIdentity>`                                                                                      |

**Insight:** Uses `Result<_, String>` rather than the crate's `Error` type — inconsistent with rest of crate.

---

### DTOs (`src/dto/`)

| File               | Types | Purpose                                                                          |
| ------------------ | ----- | -------------------------------------------------------------------------------- |
| `auth.rs`          | 12    | Registration, login, logout, email verification, password reset request/response |
| `tokens.rs`        | 7     | Vault token generation, refresh, client assertion (RFC 7523), revocation         |
| `teams.rs`         | 18+   | Team CRUD, members, permissions request/response                                 |
| `emails.rs`        | 8     | Email management: add, list, verify, set primary                                 |
| `users.rs`         | 4     | User profile CRUD                                                                |
| `sessions.rs`      | 3     | Session listing and revocation                                                   |
| `audit_logs.rs`    | 5     | Audit log creation and querying                                                  |
| `organizations.rs` | 23    | Organization CRUD, members, invitations, ownership, engine-facing                |
| `clients.rs`       | 17    | Client/certificate CRUD with Terraform-compatible deserializer                   |
| `cli_auth.rs`      | 4     | PKCE authorization code flow                                                     |
| `schemas.rs`       | 16    | Schema deploy, activate, rollback, diff                                          |
| `vaults.rs`        | 21    | Vault CRUD, user/team grants                                                     |

**Notable:** `clients.rs` includes `deserialize_optional_string_or_number` for Terraform compatibility (sends numbers as strings).

---

### Entities (`src/entities/`)

| File                               | Types                                                                                                | Key Features                                                                                                           |
| ---------------------------------- | ---------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `user.rs`                          | `User`                                                                                               | Name validation (1-100 chars), passwordless support, ToS acceptance, soft delete                                       |
| `organization.rs`                  | `Organization`, `OrganizationTier`, `OrganizationRole`, `OrganizationMember`                         | Tier limits (Dev/Pro/Max), role hierarchy (Member < Admin < Owner), suspension                                         |
| `team.rs`                          | `OrganizationTeam`, `OrganizationTeamMember`, `OrganizationPermission`, `OrganizationTeamPermission` | 14 permission variants, composite permissions (`OrgPermClientManage` → individual `OrgPermClient*`)                    |
| `vault.rs`                         | `Vault`, `VaultSyncStatus`, `VaultRole`, `VaultUserGrant`, `VaultTeamGrant`                          | Sync lifecycle (Pending/Synced/Failed), role hierarchy via `Ord` derive                                                |
| `client.rs`                        | `Client`, `ClientCertificate`                                                                        | `kid` format: `org-{org_id}-client-{client_id}-cert-{cert_id}`, encrypted private key, revocation tracking             |
| `user_email.rs`                    | `UserEmail`                                                                                          | Multi-email, verification, primary designation, normalization                                                          |
| `user_email_verification_token.rs` | `UserEmailVerificationToken`                                                                         | 24-hour expiry, 64 hex chars, idempotent `mark_used()`                                                                 |
| `user_password_reset_token.rs`     | `UserPasswordResetToken`                                                                             | 1-hour expiry, same structure as verification token                                                                    |
| `vault_refresh_token.rs`           | `VaultRefreshToken`                                                                                  | Session-bound or client-bound, replay detection via `used_at`, validation priority: revoked → used → expired           |
| `user_session.rs`                  | `SessionType`, `UserSession`                                                                         | Type-specific TTLs (Web: 24h, CLI: 7d, SDK: 30d), sliding window expiry                                                |
| `authorization_code.rs`            | `AuthorizationCode`                                                                                  | 10-min TTL, PKCE S256 verification, one-time use                                                                       |
| `organization_invitation.rs`       | `OrganizationInvitation`                                                                             | 7-day expiry, 32-byte hex token, email normalization                                                                   |
| `audit_log.rs`                     | `AuditLog`, `AuditEventType` (37 variants), `AuditResourceType` (12 variants)                        | Auto-generated ID, immutable, security events (RefreshTokenReused, ClockSkewDetected)                                  |
| `passkey_credential.rs`            | `PasskeyCredential`                                                                                  | WebAuthn Level 3, uses `SystemTime` (not `chrono` — inconsistency), backup flags                                       |
| `vault_schema.rs`                  | `VaultSchema`, `SchemaVersion`, `SchemaDeploymentStatus`                                             | SemVer versioning, state machine (Validating → Deployed → Active → Superseded/RolledBack/Failed), 1MB definition limit |

---

## Crate: `storage`

**Path:** `crates/storage/` · **Type:** Library · **Dependencies:** inferadb-common-storage, inferadb-common-storage-ledger, bon, async-trait, parking_lot, serde, tokio, tracing

### `src/lib.rs`

Crate root with barrel re-exports from all modules.

### `src/backend.rs`

Pure re-export of `inferadb_common_storage` types: `StorageBackend`, `Transaction`, `StorageError`, `StorageResult`, `KeyValue`.

### `src/factory.rs`

**Purpose:** Storage backend factory.

| Symbol                     | Kind     | Description                                                                                              |
| -------------------------- | -------- | -------------------------------------------------------------------------------------------------------- |
| `StorageBackendType`       | Enum     | `Memory`, `Ledger`                                                                                       |
| `LedgerConfig`             | Struct   | Required fields (vs config crate's `Option<T>` fields) — type-level validated-vs-unvalidated distinction |
| `Backend`                  | Enum     | Wraps `MemoryBackend` or `LedgerBackend`, implements `StorageBackend` via delegation                     |
| `create_storage_backend()` | Function | Factory creating concrete backend from config                                                            |

**Insight:** Two `LedgerConfig` types (factory: required fields, config: optional fields) encode validation state at the type level.

### `src/memory.rs`

Re-exports `MemoryBackend` from `inferadb_common_storage`. 5 contract tests (basic ops, range, TTL, transaction, health).

### `src/metrics.rs`

Re-exports `Metrics`, `MetricsSnapshot`, `MetricsCollector` from shared storage crate.

### `src/optimization.rs`

**Purpose:** LRU cache + batch write optimization layer.

| Symbol                | Kind   | Description                                                                    |
| --------------------- | ------ | ------------------------------------------------------------------------------ |
| `CacheConfig`         | Struct | `max_entries` (10K), `ttl_secs` (60), `enabled`                                |
| `LruCache`            | Struct | `HashMap` + `VecDeque` with `parking_lot::Mutex`                               |
| `BatchWriter<B>`      | Struct | Wraps `inferadb_common_storage::BatchWriter`, adds cache invalidation on flush |
| `OptimizedBackend<B>` | Struct | Decorator adding caching, batching, metrics to any `StorageBackend`            |

**Insights:**

- LRU `get` is O(n) for access order updates (`VecDeque::iter().position()`) — bottleneck at 10K entries. `LinkedHashMap` or `lru` crate would give O(1)
- `clear_range` clears entire cache (conservative) — could cause churn
- Transactions bypass cache entirely (correct for consistency)
- 18 tests covering hits, invalidation, eviction, metrics, batch ops, stress

### `src/coordination.rs`

**Purpose:** Trait definitions for distributed coordination (interface only, no implementation).

| Symbol         | Kind   | Description                                        |
| -------------- | ------ | -------------------------------------------------- |
| `LeaderStatus` | Enum   | `Leader`, `Follower`, `NoLeader`                   |
| `WorkerInfo`   | Struct | Worker metadata with heartbeat                     |
| `Coordinator`  | Trait  | 7 async methods for leadership + worker management |

### `tests/ledger_integration_tests.rs`

8 integration tests gated behind `RUN_LEDGER_INTEGRATION_TESTS` env var. Covers basic ops, TTL, transactions, concurrent writes, vault isolation, reconnection.

**Insight:** PID-seeded atomic counter for vault ID uniqueness prevents `nextest` parallel collisions. Uses early return pattern instead of `#[ignore]` — tests report as passing when skipped.

---

## Crate: `config`

**Path:** `crates/config/` · **Type:** Library · **Dependencies:** bon, config, num_cpus, serde, tracing, types

### `src/lib.rs`

**Purpose:** Layered configuration loading (defaults → file → env vars) and validation.

| Symbol           | Kind             | Description                                                                                                |
| ---------------- | ---------------- | ---------------------------------------------------------------------------------------------------------- |
| `RootConfig`     | Struct           | Top-level wrapper allowing `control:` and `engine:` sections in same YAML                                  |
| `ControlConfig`  | Struct (Builder) | 12 fields: threads, logging, PEM key, storage, ledger, listen, webauthn, email, limits, webhooks, frontend |
| `ListenConfig`   | Struct           | HTTP (9090) and gRPC (9091) addresses                                                                      |
| `WebAuthnConfig` | Struct           | Relying Party ID and Origin URL                                                                            |
| `EmailConfig`    | Struct           | SMTP config with insecure mode for dev                                                                     |
| `LimitsConfig`   | Struct           | Rate limits: login (100/hr), registration (5/day), email verification (5/hr), password reset (3/hr)        |
| `FrontendConfig` | Struct           | Base URL for email links                                                                                   |
| `WebhookConfig`  | Struct           | Timeout (5000ms), retry count (0)                                                                          |
| `LedgerConfig`   | Struct           | Optional endpoint, client_id, namespace_id, vault_id                                                       |

| Method                         | Description                                                                  |
| ------------------------------ | ---------------------------------------------------------------------------- |
| `ControlConfig::load()`        | Layered: defaults → file → env vars                                          |
| `ControlConfig::validate()`    | Checks addresses, storage backend, ledger completeness, URLs, webhook bounds |
| `apply_environment_defaults()` | Dev auto-fallback from ledger to memory                                      |

**Insights:**

- `test_builder_defaults_match_serde_defaults` is a best practice for dual-default systems
- `EmailConfig::host` has `#[builder(default)]` but no `#[serde(default)]` — latent bug: YAML without `host` key gets `""` not `"localhost"`
- Environment prefix `INFERADB` in code vs `INFERADB_CTRL__` in docs — needs reconciliation

---

## Crate: `const`

**Path:** `crates/const/` · **Type:** Library · **Dependencies:** None (zero-dependency leaf crate)

### `src/auth.rs`

| Constant                 | Value                        | Description       |
| ------------------------ | ---------------------------- | ----------------- |
| `REQUIRED_ISSUER`        | `"https://api.inferadb.com"` | JWT `iss` claim   |
| `REQUIRED_AUDIENCE`      | `"https://api.inferadb.com"` | JWT `aud` claim   |
| `SESSION_COOKIE_NAME`    | `"infera_session"`           | Cookie name       |
| `SESSION_COOKIE_MAX_AGE` | `86400` (24h)                | Cookie expiration |

### `src/duration.rs`

| Constant                                 | Value             | Description             |
| ---------------------------------------- | ----------------- | ----------------------- |
| `AUTHORIZATION_CODE_TTL_SECONDS`         | `600` (10 min)    | OAuth2 auth code        |
| `USER_SESSION_REFRESH_TOKEN_TTL_SECONDS` | `3600` (1 hour)   | Browser session refresh |
| `CLIENT_REFRESH_TOKEN_TTL_SECONDS`       | `604800` (7 days) | Machine client refresh  |
| `INVITATION_EXPIRY_DAYS`                 | `7`               | Org invitation          |
| `EMAIL_VERIFICATION_TOKEN_EXPIRY_HOURS`  | `24`              | Email verification      |
| `PASSWORD_RESET_TOKEN_EXPIRY_HOURS`      | `1`               | Password reset          |

### `src/limits.rs`

| Constant                      | Value     | Description               |
| ----------------------------- | --------- | ------------------------- |
| `MAX_PASSKEYS_PER_USER`       | `20`      | WebAuthn credential limit |
| `MAX_CONCURRENT_SESSIONS`     | `10`      | Per-user session limit    |
| `GLOBAL_ORGANIZATION_LIMIT`   | `100_000` | Safety valve              |
| `PER_USER_ORGANIZATION_LIMIT` | `10`      | Per-user org limit        |
| `MIN_PASSWORD_LENGTH`         | `12`      | NIST SP 800-63B compliant |

### `src/ratelimit.rs`

| Constant             | Value                  | Description          |
| -------------------- | ---------------------- | -------------------- |
| `LOGIN_IP`           | `"login_ip"`           | Rate limit bucket ID |
| `REGISTRATION_IP`    | `"registration_ip"`    | Rate limit bucket ID |
| `EMAIL_VERIFICATION` | `"email_verification"` | Rate limit bucket ID |
| `PASSWORD_RESET`     | `"password_reset"`     | Rate limit bucket ID |

---

## Crate: `test-fixtures`

**Path:** `crates/test-fixtures/` · **Type:** Library · **Dependencies:** api, core, storage, axum, tower

### `src/lib.rs`

**Purpose:** Shared test utilities for integration tests.

| Function                                    | Description                                            |
| ------------------------------------------- | ------------------------------------------------------ |
| `create_test_state()`                       | Creates `AppState` with in-memory `Backend`            |
| `create_test_app(state)`                    | Wraps `create_router_with_state()` for full app router |
| `extract_session_cookie(headers)`           | Parses `Set-Cookie` for `infera_session` value         |
| `register_user(app, name, email, password)` | Full registration flow, returns session cookie         |

**Insights:**

- `#![allow(clippy::unwrap_used, clippy::expect_used)]` at crate level — appropriate for test code
- `extract_session_cookie` only checks first `set-cookie` header — fragile if multiple cookies set
- Excellent documentation with examples, arguments, return values, panic conditions

---

## Cross-Crate Observations

### Strengths

1. **Consistent `#![deny(unsafe_code)]`** across all library crates
2. **Consistent builder pattern** via `bon::Builder` with `#[builder(on(String, into))]` everywhere
3. **Strong error handling** — `Error` enum with factory methods, no `.unwrap()` in production code
4. **Security awareness** — Argon2id passwords, AES-256-GCM key encryption, Ed25519 JWT signing, JTI replay protection, PKCE, rate limiting, audit logging
5. **Distributed systems design** — Worker ID coordination, leader election, clock validation, TTL-based cleanup
6. **Thorough test suite** — 95+ integration tests, security tests (XSS, injection, isolation, authorization), contract tests
7. **Clean architecture** — Clear crate boundaries, trait-based abstractions, repository pattern

### Known Issues

1. **BUG: `delete_team_grant()` in `handlers/vaults.rs`** calls wrong repository method (`vault_user_grant.delete()` instead of `vault_team_grant.delete()`)
2. **Path segment index coupling** — Middleware extracts IDs from hardcoded positions (index 4, 6) in URI path
3. **IP extraction inconsistency** — Rate limiting uses `ConnectInfo<SocketAddr>`, audit logging uses `X-Forwarded-For`/`X-Real-IP`
4. **No transaction boundaries in `register()`** — 6+ entities created without explicit transaction
5. **Dual-write consistency** — Certificate ops write to both Control and Ledger without compensating transactions
6. **Email multipart** — SMTP sender uses `---` separator instead of proper MIME multipart/alternative
7. **XSS risk in email templates** — `inviter_name`/`organization_name` not HTML-escaped
8. **`EmailConfig::host` missing `#[serde(default)]`** — YAML without `host` key gets `""` not `"localhost"`
9. **Environment prefix mismatch** — Code uses `INFERADB`, docs reference `INFERADB_CTRL__`

### Areas for Modernization

1. **LRU cache** — O(n) access order updates via `VecDeque::iter().position()`. Replace with `lru` crate for O(1)
2. **Zeroize enforcement** — `MasterKey` manually zeros but `[u8; 32]` is `Copy`; derive `ZeroizeOnDrop` instead
3. **JWT audience validation** — Disabled in `verify_vault_token`, should be enforced
4. **NTP clock validation** — Placeholder implementation; replace with proper NTP client library
5. **Enum dispatch** — `StorageBackend for Backend` has 8 match arms doing identical delegation; `enum_dispatch` macro would reduce boilerplate
6. **`identity.rs` error types** — Uses `Result<_, String>` instead of crate `Error` type
7. **Structural duplication** — `UserPasswordResetToken` / `UserEmailVerificationToken` nearly identical; `UserGrantInfo`/`UserGrantResponse` structurally identical
8. **Inconsistent DTO typing** — Some DTOs use `VaultRole` enum, others use `String` for roles
9. **Missing root re-exports** — Several DTO types not re-exported from `lib.rs`
10. **PasskeyCredential timestamp type** — Uses `SystemTime` while all other entities use `chrono::DateTime<Utc>`
