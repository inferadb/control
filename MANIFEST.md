# InferaDB Control Plane — Codebase Manifest

> Comprehensive crate-by-crate, file-by-file analysis of the InferaDB Control Plane.
> Generated 2026-02-05. Updated 2026-02-22.

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

**Path:** `crates/control/` · **Type:** Binary · **Dependencies:** api, config, core, storage, types, anyhow, clap, rustls, tokio, tracing, tracing-subscriber

### `src/main.rs`

**Purpose:** Binary entrypoint for the InferaDB Control API server. Handles CLI args, config loading, service initialization, and startup orchestration.

| Symbol   | Kind     | Description                                                                                                                           |
| -------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `main()` | Function | Startup orchestration: crypto provider → CLI parse → config → logging → storage → worker ID → ID generator → identity → email → serve |

**`main()` Initialization Sequence:**

1. Install rustls crypto provider (`aws-lc-rs`)
2. Parse CLI via `Cli::parse()` (clap: CLI args > env vars > defaults)
3. Clear terminal in interactive non-JSON mode
4. Validate configuration (`config.validate()`)
5. Initialize logging (log_level + log_format with Auto TTY detection)
6. Apply dev-mode (forces memory storage via `effective_storage()`)
7. Display startup banner and configuration summary (if not JSON format)
8. Create storage backend
9. Acquire worker ID with collision detection
10. Initialize ID generator (Snowflake)
11. Start worker registry heartbeat
12. Initialize Control identity (load PEM or generate Ed25519 keypair)
13. Initialize email service (optional SMTP)
14. Wrap config in `Arc` for shared ownership
15. Start API server via `inferadb_control_api::serve()`

**Insights:**

- Clean startup orchestration with explicit dependency ordering
- `anyhow::Result` at the binary boundary is idiomatic — libraries return typed errors, binary aggregates with `anyhow`
- Worker ID acquisition supports Kubernetes StatefulSet pod ordinals, explicit assignment, and random with collision detection
- Leader election (`Coordinator` trait) exists in the storage crate but is not wired up at startup (`leader: None`), suggesting it's planned
- No custom signal handling — relies on tokio's default via `inferadb_control_api::serve()`

---

## Crate: `api`

**Path:** `crates/api/` · **Type:** Library · **Dependencies:** config, const, core, storage, types, axum, bon, chrono, ed25519-dalek, jsonwebtoken, metrics-exporter-prometheus, serde, tokio, tower, tracing, proptest (dev), sha2 (dev)

### `src/lib.rs`

**Purpose:** Crate root with re-exports. Defines `ServicesConfig` and `serve()`.

| Symbol              | Kind     | Description                                                                          |
| ------------------- | -------- | ------------------------------------------------------------------------------------ |
| `ServicesConfig`    | Struct   | Optional `leader`, `email_service`, `control_identity` (all `Option<Arc<...>>`)      |
| `serve()`           | Function | Creates `AppState`, builds router, binds TCP listener, serves with graceful shutdown |
| `shutdown_signal()` | Function | Handles Ctrl+C and SIGTERM for graceful shutdown                                     |

### `src/routes.rs`

**Purpose:** Defines ALL API routes via `create_router_with_state()`.

| Symbol                       | Kind     | Description                                                                                                                |
| ---------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------- |
| `create_router_with_state()` | Function | Three route groups: org-scoped (session + org membership via `.route_layer()`), protected (session only), public (no auth) |

**Route Groups:**

- **Org-scoped:** Organizations CRUD, members, invitations, suspend/resume, clients, certificates, vaults, vault grants, schemas, tokens, audit logs, teams
- **Protected:** Sessions, token revocation, user profile, emails, org create/list, invitation accept, CLI auth, vault GET by ID
- **Public:** Health probes (`/livez`, `/readyz`, `/startupz`, `/healthz`), metrics, auth (register/login/logout/verify-email/password-reset), token refresh, client assertion, CLI token exchange

**Note:** Login and registration routes use separate rate-limited sub-routers (via `.route_layer()`) merged into the public group — each route gets independent rate limiting middleware.

### `src/audit.rs`

**Purpose:** Fire-and-forget audit logging utilities.

| Symbol                 | Kind     | Description                                                                                           |
| ---------------------- | -------- | ----------------------------------------------------------------------------------------------------- |
| `AuditEventParams`     | Struct   | Fields for org_id, user_id, client_id, resource_type, resource_id, event_data, ip_address, user_agent |
| `log_audit_event()`    | Function | Fire-and-forget: errors logged but don't fail requests                                                |
| `extract_user_agent()` | Function | Extracts User-Agent header                                                                            |

### `src/extract.rs`

**Purpose:** Unified client IP extraction shared between rate limiting and audit logging.

| Symbol                | Kind     | Description                                                                                     |
| --------------------- | -------- | ----------------------------------------------------------------------------------------------- |
| `extract_client_ip()` | Function | Cascades: `X-Forwarded-For` → `X-Real-IP` → `ConnectInfo<SocketAddr>`; returns `Option<String>` |

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

| Symbol                      | Kind       | Description                                                                                |
| --------------------------- | ---------- | ------------------------------------------------------------------------------------------ |
| `SessionContext`            | Struct     | `session_id: i64`, `user_id: i64`                                                          |
| `require_session()`         | Middleware | Extracts session from cookie or Bearer token, validates, updates activity (sliding window) |
| `extract_session_context()` | Function   | Extracts `SessionContext` from request extensions (public helper)                          |

#### `middleware/ratelimit.rs`

| Symbol                      | Kind       | Description                                                                                                             |
| --------------------------- | ---------- | ----------------------------------------------------------------------------------------------------------------------- |
| `RateLimitConfig`           | Struct     | Configurable rate limits with manual `Default` impl; production defaults: 100/hr login, 5/day registration              |
| `login_rate_limit()`        | Middleware | Per-IP login rate limiting; reads limits from `AppState.rate_limits`                                                    |
| `registration_rate_limit()` | Middleware | Per-IP registration rate limiting; reads limits from `AppState.rate_limits`                                             |
| `rate_limit_middleware()`   | Middleware | Generic limiter with custom categories/limits; sets `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `Retry-After` headers |

#### `middleware/organization.rs`

| Symbol                          | Kind       | Description                                                                                                                      |
| ------------------------------- | ---------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `OrganizationContext`           | Struct     | `organization_id`, `member: OrganizationMember`; methods: `has_permission()`, `is_member()`, `is_admin_or_owner()`, `is_owner()` |
| `require_organization_member()` | Middleware | Extracts org ID via axum `Path<HashMap>` extractor, verifies membership, checks org not deleted/suspended                        |
| `require_member()`              | Function   | Convenience extractor: returns 403 if not a member                                                                               |
| `require_admin_or_owner()`      | Function   | Convenience extractor: returns 403 if not admin or owner                                                                         |
| `require_owner()`               | Function   | Convenience extractor: returns 403 if not owner                                                                                  |

**Note:** Suspension enforcement added — suspended orgs only allow owners to access `/suspend` and `/resume` endpoints; all other requests return 403.

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

| Symbol                   | Kind       | Description                                                                                                                      |
| ------------------------ | ---------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `VaultContext`           | Struct     | `vault_id`, `organization_id`, `role: VaultRole`; methods: `has_permission()`, `is_reader/writer/manager/admin()`                |
| `require_vault_access()` | Middleware | Extracts vault ID via axum `Path<HashMap>` extractor, verifies vault exists/not deleted/belongs to org, resolves user vault role |
| `get_user_vault_role()`  | Function   | Checks direct user grant first, then team grants; returns highest role                                                           |
| `require_reader()`       | Function   | Convenience extractor: returns 403 if vault role < Reader                                                                        |
| `require_writer()`       | Function   | Convenience extractor: returns 403 if vault role < Writer                                                                        |
| `require_manager()`      | Function   | Convenience extractor: returns 403 if vault role < Manager                                                                       |
| `require_admin()`        | Function   | Convenience extractor: returns 403 if vault role < Admin                                                                         |

---

### Handlers (`src/handlers/`)

#### `handlers/auth.rs`

**Purpose:** Authentication endpoints and core `AppState` definition.

| Symbol                     | Kind             | Description                                                                                                                          |
| -------------------------- | ---------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `AppState`                 | Struct (Builder) | `storage`, `config`, `worker_id`, `start_time`, `leader`, `email_service`, `control_identity`, `rate_limits`; `new_test()` for tests |
| `ApiError`                 | Struct           | Wraps `CoreError`; implements `IntoResponse` with status code mapping and JSON error response (includes `code` field)                |
| `ErrorResponse`            | Struct           | JSON error body: `error` (message), `code` (error code string), `details` (optional)                                                 |
| `register()`               | Handler          | POST `/v1/auth/register` — Atomically creates user, email, verification token, session, org via `BufferedBackend`                    |
| `login()`                  | Handler          | POST `/v1/auth/login/password` — Email+password auth, creates session                                                                |
| `logout()`                 | Handler          | POST `/v1/auth/logout` — Revokes session, clears cookie                                                                              |
| `verify_email()`           | Handler          | POST `/v1/auth/verify-email` — Validates token, marks email verified                                                                 |
| `request_password_reset()` | Handler          | POST `/v1/auth/password-reset/request` — Returns consistent 200 OK for all inputs (prevents email enumeration)                       |
| `confirm_password_reset()` | Handler          | POST `/v1/auth/password-reset/confirm` — Validates token, updates password, revokes ALL sessions                                     |

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
| `generate_vault_token()`          | Handler | POST — Creates JWT access token + refresh token; accepts `VaultRole` enum (reader/writer/manager/admin)           |
| `refresh_vault_token()`           | Handler | POST `/v1/tokens/refresh` — Validates, marks used (replay protection), rotates tokens                             |
| `ClientAssertionClaims`           | Struct  | JWT claims for RFC 7523: `iss`, `sub`, `aud`, `exp`, `iat`, `jti` (with `#[serde(rename)]` for underscore fields) |
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

| Symbol                 | Kind    | Description                                                                                                                      |
| ---------------------- | ------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `create_client()`      | Handler | POST — Creates API client for organization                                                                                       |
| `list_clients()`       | Handler | GET — Lists org clients                                                                                                          |
| `get_client()`         | Handler | GET — Single client                                                                                                              |
| `update_client()`      | Handler | PATCH — Name/description                                                                                                         |
| `delete_client()`      | Handler | DELETE — Soft-delete                                                                                                             |
| `create_certificate()` | Handler | POST — Generates Ed25519 keypair, encrypts private key, writes public key to Ledger. Compensating transaction on Ledger failure. |
| `list_certificates()`  | Handler | GET — Certificate metadata                                                                                                       |
| `get_certificate()`    | Handler | GET — Single certificate                                                                                                         |
| `revoke_certificate()` | Handler | POST — Marks revoked in Control + Ledger; compensating rollback restores active state on Ledger failure                          |
| `rotate_certificate()` | Handler | POST — Creates new cert with grace period, writes to Ledger; compensating deletion on Ledger failure                             |

**Note:** All three certificate lifecycle handlers use compensating transactions — on Ledger write failure, Control state is rolled back. A background reconciliation job compares Control and Ledger state hourly.

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

| Test File                            | Tests | Coverage                                                                                                                                     |
| ------------------------------------ | ----- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `audit_log_tests.rs`                 | 6     | Audit log creation, listing, filtering, pagination, owner-only access                                                                        |
| `auth_tests.rs`                      | 21    | Login (valid/invalid/enumeration), logout, verify-email, password-reset (enumeration fix), cookie attributes                                 |
| `cli_auth_tests.rs`                  | 5     | Full PKCE flow, wrong verifier, replay prevention, expired code, unauthenticated                                                             |
| `client_tests.rs`                    | 13    | Client CRUD, certificate CRUD, rotation, Ledger integration, audit log                                                                       |
| `cascade_deletion_tests.rs`          | 9     | User/org/vault deletion cascades: sessions, memberships, emails, teams, grants                                                               |
| `edge_case_tests.rs`                 | 3     | Concurrent vault access, expired token refresh, cert rotation                                                                                |
| `email_tests.rs`                     | 9     | Add, list, set primary, delete, verify (valid/invalid/reused), cross-user isolation                                                          |
| `engine_internal_tests.rs`           | 5     | Vault-by-ID (data, 404, deleted, auth required, cross-org access)                                                                            |
| `health_tests.rs`                    | 5     | `/livez`, `/readyz`, `/startupz`, `/healthz` JSON fields, no-auth required                                                                   |
| `jwks_verify_test.rs`                | 1     | Ed25519 generate/sign/verify with PEM roundtrip                                                                                              |
| `middleware_tests.rs`                | 4     | Org/vault path extraction (standard routes + decoupled non-standard routes)                                                                  |
| `organization_invitation_tests.rs`   | 2     | Create+list, delete                                                                                                                          |
| `organization_member_tests.rs`       | 7     | List, update role, cannot demote last owner, remove, cannot remove last owner, leave, last owner cannot leave                                |
| `organization_suspend_tests.rs`      | 5     | Owner suspend/resume, non-owner 403, blocked resource access, post-resume access                                                             |
| `organization_tests.rs`              | 7     | Registration default org, CRUD, non-member 403                                                                                               |
| `ratelimit_tests.rs`                 | 6     | Login/registration rate limit enforcement, headers, Retry-After, per-IP independence, 429 body                                               |
| `schema_tests.rs`                    | 12    | Deploy, auto-version, explicit version, list, get, activate, current, rollback, diff, duplicate rejection, 404                               |
| `security_authorization_tests.rs`    | 10    | RBAC enforcement: member/admin escalation prevention                                                                                         |
| `security_input_validation_tests.rs` | 14    | XSS, path traversal, null bytes, Unicode edge cases, SQL injection, control characters, pagination boundaries                                |
| `security_isolation_tests.rs`        | 7     | Cross-org vault/client/team access, modify/delete isolation, JWT isolation                                                                   |
| `session_limit_tests.rs`             | 3     | Session eviction at MAX_CONCURRENT_SESSIONS, list respects limit, multiple evictions                                                         |
| `session_tests.rs`                   | 4     | List sessions, revoke specific, revoke others, cross-user revoke blocked                                                                     |
| `team_tests.rs`                      | 13    | Create, list, get, update, delete+cascade, add/update/remove member, grant/revoke permission, auth checks                                    |
| `tier_limit_tests.rs`                | 5     | Vault/team tier limit enforcement (402), soft-delete doesn't count, error response format                                                    |
| `token_tests.rs`                     | 11    | Generate (including manager role), refresh, replay, revocation, client assertion (unknown kid, revoked cert, JTI replay, expired, wrong sig) |
| `vault_tests.rs`                     | 8     | CRUD, user/team grant access, team grant deletion, grant isolation                                                                           |

**Total: 775 tests** (195 integration across 26 test files + unit + property-based across all crates)

---

## Crate: `core`

**Path:** `crates/core/` · **Type:** Library · **Dependencies:** types, storage, const, aes-gcm, argon2, ed25519-dalek, jsonwebtoken, idgenerator, lettre, webauthn-rs, tokio, tracing, metrics, bon, zeroize, rsntp, proptest (dev)

### `src/lib.rs`

**Purpose:** Crate root. Re-exports all public types organized by domain concern, including `SkewSeverity`, `SecureTokenRepository`.

`#![deny(unsafe_code)]` applied crate-wide.

### `src/clock.rs`

**Purpose:** System clock validation against NTP for distributed deployments.

| Symbol                            | Kind     | Description                                                                                          |
| --------------------------------- | -------- | ---------------------------------------------------------------------------------------------------- |
| `ClockValidator`                  | Struct   | Multi-source NTP validation: `rsntp` (async SNTP) → `chronyc tracking` → `ntpdate -q` fallback       |
| `ClockValidator::validate()`      | Method   | Performs NTP query with cascading fallback, returns skew analysis. Soft-fails if no source available |
| `ClockStatus`                     | Struct   | `system_time`, `ntp_time`, `skew_ms` (sub-second precision), `severity: SkewSeverity`                |
| `SkewSeverity`                    | Enum     | `Normal` (< 100ms), `Warning` (100ms–threshold), `Critical` (≥ threshold)                            |
| `ClockValidator::evaluate_skew()` | Method   | Testable skew classification; emits structured tracing + Prometheus gauge                            |
| `classify_skew()`                 | Function | Pure helper: maps `(skew_ms, threshold)` → `SkewSeverity`                                            |
| `parse_chrony_offset()`           | Function | Extracts "System time" offset from `chronyc tracking` output                                         |
| `parse_ntpdate_offset()`          | Function | Extracts signed offset from `ntpdate -q` output                                                      |

### `src/crypto.rs`

**Purpose:** Master encryption key (AES-256-GCM) for encrypting Ed25519 private keys at rest, plus keypair generation.

| Symbol                           | Kind     | Description                                                                                       |
| -------------------------------- | -------- | ------------------------------------------------------------------------------------------------- |
| `MasterKey`                      | Struct   | 256-bit key wrapper; `#[derive(Zeroize, ZeroizeOnDrop)]`, intentionally non-`Clone`               |
| `MasterKey::load_or_generate()`  | Method   | Load from file or auto-generate, sets 0600 permissions                                            |
| `PrivateKeyEncryptor`            | Struct   | AES-256-GCM encryption service                                                                    |
| `PrivateKeyEncryptor::encrypt()` | Method   | Encrypts 32-byte private key, returns base64 (nonce + ciphertext)                                 |
| `PrivateKeyEncryptor::decrypt()` | Method   | Decrypts base64 ciphertext; returns `Zeroizing<Vec<u8>>` for compile-time erasure guarantee       |
| `keypair::generate()`            | Function | Generates Ed25519 keypair; returns (URL-safe base64 public key, `Zeroizing<Vec<u8>>` private key) |

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

| Symbol                     | Kind     | Description                                                                                                                                                                   |
| -------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `BackgroundJobs<S>`        | Struct   | Scheduler with shutdown flag, task handles, optional `signing_key_store`                                                                                                      |
| `BackgroundJobs::start()`  | Method   | Spawns: session cleanup, token cleanup, refresh token cleanup, authz code cleanup, audit log retention (90d), revoked cert cleanup (90d), certificate reconciliation (hourly) |
| `BackgroundJobs::stop()`   | Method   | Signals shutdown, aborts handles                                                                                                                                              |
| `reconcile_certificates()` | Method   | Compares Control and Ledger certificate state, logs divergences with structured fields                                                                                        |
| `org_id_from_kid()`        | Function | Parses org_id from kid format `org-{org_id}-client-{client_id}-cert-{cert_id}`                                                                                                |

### `src/jwt.rs`

**Purpose:** JWT signing/verification for vault-scoped access tokens using Ed25519 (EdDSA).

| Symbol                            | Kind   | Description                                                                                |
| --------------------------------- | ------ | ------------------------------------------------------------------------------------------ |
| `VaultTokenClaims`                | Struct | JWT claims: `iss`, `sub`, `aud`, `exp`, `iat`, `org_id`, `vault_id`, `vault_role`, `scope` |
| `JwtSigner`                       | Struct | Signing/verification service wrapping `PrivateKeyEncryptor`                                |
| `JwtSigner::sign_vault_token()`   | Method | Signs claims via `to_pkcs8_der()` (no hardcoded ASN.1), includes `kid` header              |
| `JwtSigner::verify_vault_token()` | Method | Verifies JWT with audience validation enabled (`REQUIRED_AUDIENCE`)                        |

### `src/leader.rs`

**Purpose:** Leader election using storage as distributed lock with TTL-based lease.

| Symbol                     | Kind   | Description                                                                   |
| -------------------------- | ------ | ----------------------------------------------------------------------------- |
| `LeaderElection<S>`        | Struct | Coordinator with storage, instance ID, leader status flag, shutdown flag      |
| `try_acquire_leadership()` | Method | Atomic acquisition via `compare_and_set(key, None, value)` (insert-if-absent) |
| `renew_lease()`            | Method | CAS with `expected: Some(our_value)` — prevents stale leader from overwriting |
| `release_leadership()`     | Method | CAS-guarded deletion — prevents one leader from deleting another's lease      |
| `is_leader()`              | Method | Cached local check via `RwLock<bool>`                                         |
| `start_lease_renewal()`    | Method | Background renewal (10s interval, 30s TTL)                                    |

### `src/logging.rs`

**Purpose:** Structured logging initialization with optional OpenTelemetry. Uses an internal `LogFormat` enum (`Full`, `Pretty`, `Compact`, `Json`) for renderer selection — distinct from the public `LogFormat` in the config crate (`Auto`, `Json`, `Text`) which maps to these internal formats.

| Symbol                | Kind     | Description                                                                    |
| --------------------- | -------- | ------------------------------------------------------------------------------ |
| `LogFormat`           | Enum     | Internal: `Full`, `Pretty`, `Compact`, `Json` (not exported; used by `init()`) |
| `init()`              | Function | Simplified initialization                                                      |
| `init_with_tracing()` | Function | With OpenTelemetry OTLP (10% sampling)                                         |

### `src/metrics.rs`

**Purpose:** Prometheus metrics registration and recording.

| Symbol                  | Kind     | Description                                   |
| ----------------------- | -------- | --------------------------------------------- |
| `init()`                | Function | Register all metrics (idempotent via `Once`)  |
| `record_http_request()` | Function | Counter + histogram                           |
| `record_auth_attempt()` | Function | Counter by type/success                       |
| `record_db_query()`     | Function | Histogram for DB latency                      |
| `set_is_leader()`       | Function | Gauge (1.0 or 0.0)                            |
| `set_clock_skew()`      | Function | `clock_skew_seconds` gauge for NTP monitoring |

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

**Purpose:** Consolidated repository factory creating all 22 repositories from a single storage backend.

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

| Symbol                                | Kind   | Description                                                                                |
| ------------------------------------- | ------ | ------------------------------------------------------------------------------------------ |
| `PasswordHasher`                      | Struct | Argon2id with 19 MiB memory, 2 iterations, 1 thread                                        |
| `PasswordHasher::hash()`              | Method | Hash with random salt, returns PHC format                                                  |
| `PasswordHasher::verify()`            | Method | Verify against PHC hash; error message matches email-not-found to prevent user enumeration |
| `PasswordHasher::validate_password()` | Method | Length validation: 12-128 chars (NIST SP 800-63B)                                          |

### `src/email/service.rs`

**Purpose:** Email sending abstraction with SMTP implementation and mock.

| Symbol             | Kind   | Description                                                                         |
| ------------------ | ------ | ----------------------------------------------------------------------------------- |
| `EmailSender`      | Trait  | `async fn send_email(to, subject, body_html, body_text)`                            |
| `SmtpEmailService` | Struct | Production SMTP via `lettre`; uses `MultiPart::alternative_plain_html()` (RFC 2046) |
| `MockEmailSender`  | Struct | Test double (logs, doesn't send)                                                    |

### `src/email/mod.rs`

| Symbol          | Kind     | Description                                                                       |
| --------------- | -------- | --------------------------------------------------------------------------------- |
| `html_escape()` | Function | Escapes `&`, `<`, `>`, `"`, `'` to HTML entities; prevents XSS in email templates |

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

**Note:** All user-controlled template variables are HTML-escaped via `html_escape()` in `html_body()` methods.

---

### Repositories (`src/repository/`)

All 22 repositories (across 18 files) follow a consistent pattern:

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

| Method                           | Description                                      |
| -------------------------------- | ------------------------------------------------ |
| `create()`                       | Org-scoped unique name enforcement               |
| `list_by_organization()`         | All clients                                      |
| `list_active_by_organization()`  | Loads all, filters in memory                     |
| `count_by_organization()`        | Range scan key counting (no deserialization)     |
| `count_active_by_organization()` | O(1) counter key read with self-healing fallback |

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

#### `repository/secure_token.rs`

Generic `SecureTokenRepository<S, T: SecureTokenEntity>` with all CRUD methods parameterized via the `SecureTokenEntity` trait. Eliminates structural duplication between token repositories.

#### `repository/user_email_verification_token.rs` / `user_password_reset_token.rs`

Type aliases over `SecureTokenRepository<S, T>` with entity-specific convenience methods (`get_by_email`, `get_by_user`).

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

**Purpose:** Crate root. Re-exports ~100 types from entities and DTOs, including `SecureToken`, `SecureTokenEntity`.

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
| `from_pem()`            | Method     | Restores from PKCS#8 PEM via `SigningKey::from_pkcs8_der()`; returns `Result<Self, Error>`                  |
| `to_pem()`              | Method     | Exports via `to_pkcs8_der()` + `pem` crate wrapping; returns `Result<String, Error>`                        |
| `sign_jwt()`            | Method     | Signs 5-min JWT with admin scope, UUID v4 jti; returns `Result<String, Error>`                              |
| `to_jwks()`             | Method     | JWKS representation of public key                                                                           |
| `SharedControlIdentity` | Type alias | `Arc<ControlIdentity>`                                                                                      |

---

### DTOs (`src/dto/`)

| File               | Types | Purpose                                                                                                      |
| ------------------ | ----- | ------------------------------------------------------------------------------------------------------------ |
| `auth.rs`          | 12    | Registration, login, logout, email verification, password reset request/response                             |
| `tokens.rs`        | 7     | Vault token generation, refresh, client assertion (RFC 7523), revocation; uses `VaultRole` enum (not String) |
| `teams.rs`         | 22    | Team CRUD, members, permissions request/response                                                             |
| `emails.rs`        | 9     | Email management: add, list, verify, set primary                                                             |
| `users.rs`         | 5     | User profile CRUD                                                                                            |
| `sessions.rs`      | 3     | Session listing and revocation                                                                               |
| `audit_logs.rs`    | 5     | Audit log creation and querying                                                                              |
| `organizations.rs` | 26    | Organization CRUD, members, invitations, ownership, engine-facing                                            |
| `clients.rs`       | 19    | Client/certificate CRUD with Terraform-compatible deserializer                                               |
| `cli_auth.rs`      | 4     | PKCE authorization code flow                                                                                 |
| `schemas.rs`       | 16    | Schema deploy, activate, rollback, diff                                                                      |
| `vaults.rs`        | 23    | Vault CRUD, user/team grants (consolidated: `UserGrantInfo`/`TeamGrantInfo` merged into `*Response`)         |

**Notable:** `clients.rs` includes `deserialize_optional_string_or_number` for Terraform compatibility (sends numbers as strings).

---

### Entities (`src/entities/`)

| File                               | Types                                                                                                | Key Features                                                                                                                                                   |
| ---------------------------------- | ---------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `user.rs`                          | `User`                                                                                               | Name validation (1-100 chars), passwordless support, ToS acceptance, soft delete                                                                               |
| `organization.rs`                  | `Organization`, `OrganizationTier`, `OrganizationRole`, `OrganizationMember`                         | Tier limits (Dev/Pro/Max), role hierarchy (Member < Admin < Owner), suspension                                                                                 |
| `team.rs`                          | `OrganizationTeam`, `OrganizationTeamMember`, `OrganizationPermission`, `OrganizationTeamPermission` | 14 permission variants, composite permissions (`OrgPermClientManage` → individual `OrgPermClient*`)                                                            |
| `vault.rs`                         | `Vault`, `VaultSyncStatus`, `VaultRole`, `VaultUserGrant`, `VaultTeamGrant`                          | Sync lifecycle (Pending/Synced/Failed), role hierarchy via `Ord` derive, `VaultRole` serde: `#[serde(rename_all = "lowercase")]` (reader/writer/manager/admin) |
| `client.rs`                        | `Client`, `ClientCertificate`                                                                        | `kid` format: `org-{org_id}-client-{client_id}-cert-{cert_id}`, encrypted private key, revocation tracking                                                     |
| `user_email.rs`                    | `UserEmail`                                                                                          | Multi-email, verification, primary designation, normalization                                                                                                  |
| `secure_token.rs`                  | `SecureToken`, `SecureTokenEntity` trait                                                             | Shared base: id, token, created_at, expires_at, used_at; methods: is_expired, is_used, is_valid, mark_used                                                     |
| `user_email_verification_token.rs` | `UserEmailVerificationToken`                                                                         | Composes `SecureToken` via `#[serde(flatten)]`; 24-hour TTL, links to `user_email_id`                                                                          |
| `user_password_reset_token.rs`     | `UserPasswordResetToken`                                                                             | Composes `SecureToken` via `#[serde(flatten)]`; 1-hour TTL, links to `user_id`                                                                                 |
| `vault_refresh_token.rs`           | `VaultRefreshToken`                                                                                  | Session-bound or client-bound, replay detection via `used_at`, validation priority: revoked → used → expired                                                   |
| `user_session.rs`                  | `SessionType`, `UserSession`                                                                         | Type-specific TTLs (Web: 24h, CLI: 7d, SDK: 30d), sliding window expiry                                                                                        |
| `authorization_code.rs`            | `AuthorizationCode`                                                                                  | 10-min TTL, PKCE S256 verification, one-time use                                                                                                               |
| `organization_invitation.rs`       | `OrganizationInvitation`                                                                             | 7-day expiry, 32-byte hex token, email normalization                                                                                                           |
| `audit_log.rs`                     | `AuditLog`, `AuditEventType` (53 variants), `AuditResourceType` (13 variants)                        | Auto-generated ID, immutable, security events (RefreshTokenReused, ClockSkewDetected)                                                                          |
| `passkey_credential.rs`            | `PasskeyCredential`                                                                                  | WebAuthn Level 3, uses `SystemTime` (not `chrono` — inconsistency), backup flags                                                                               |
| `vault_schema.rs`                  | `VaultSchema`, `SchemaVersion`, `SchemaDeploymentStatus`                                             | SemVer versioning, state machine (Validating → Deployed → Active → Superseded/RolledBack/Failed), 1MB definition limit                                         |

---

## Crate: `storage`

**Path:** `crates/storage/` · **Type:** Library · **Dependencies:** inferadb-common-storage, inferadb-common-storage-ledger, bon, async-trait, moka, serde, tokio, tracing

### `src/lib.rs`

Crate root with barrel re-exports from all modules, including `BufferedBackend`, `MemorySigningKeyStore`, `PublicSigningKey`, `PublicSigningKeyStore`.

### `src/backend.rs`

Pure re-export of `inferadb_common_storage` types: `StorageBackend`, `Transaction`, `StorageError`, `StorageResult`, `KeyValue`.

### `src/factory.rs`

**Purpose:** Storage backend factory.

| Symbol                     | Kind     | Description                                                                                              |
| -------------------------- | -------- | -------------------------------------------------------------------------------------------------------- |
| `StorageBackendType`       | Enum     | `Memory`, `Ledger`                                                                                       |
| `LedgerConfig`             | Struct   | Required fields (vs config crate's `Option<T>` fields) — type-level validated-vs-unvalidated distinction |
| `Backend`                  | Enum     | Wraps `MemoryBackend` or `LedgerBackend`, implements `StorageBackend` via `delegate_storage!` macro      |
| `create_storage_backend()` | Function | Factory creating concrete backend from config                                                            |

**Insight:** Two `LedgerConfig` types (factory: required fields, config: optional fields) encode validation state at the type level.

### `src/memory.rs`

Re-exports `MemoryBackend` from `inferadb_common_storage`. 5 contract tests (basic ops, range, TTL, transaction, health).

### `src/metrics.rs`

Re-exports `Metrics`, `MetricsSnapshot`, `MetricsCollector` from shared storage crate.

### `src/optimization.rs`

**Purpose:** Concurrent cache + batch write optimization layer.

| Symbol                | Kind   | Description                                                                                                        |
| --------------------- | ------ | ------------------------------------------------------------------------------------------------------------------ |
| `CacheConfig`         | Struct | `max_entries` (10K), `ttl_secs` (60), `enabled`                                                                    |
| `MokaCache`           | Type   | `moka::sync::Cache<String, Vec<u8>>` — O(1) ops, TinyLFU eviction, lock-free reads                                 |
| `BatchWriter<B>`      | Struct | Wraps `inferadb_common_storage::BatchWriter`, adds cache invalidation on flush                                     |
| `OptimizedBackend<B>` | Struct | Decorator adding caching, batching, metrics to any `StorageBackend`; uses `Option<MokaCache>` (None when disabled) |

**Note:** Replaced custom `HashMap + VecDeque` LRU (O(n) per access) with `moka::sync::Cache` — production-grade concurrent cache used by crates.io. No external `Arc<Mutex<>>` needed; moka handles concurrency internally. 19 tests covering hits, invalidation, eviction, metrics, batch ops, stress, concurrent access.

### `src/buffered.rs`

**Purpose:** Atomic multi-write wrapper for cross-repository transaction boundaries.

| Symbol                | Kind   | Description                                                                                     |
| --------------------- | ------ | ----------------------------------------------------------------------------------------------- |
| `BufferedBackend<S>`  | Struct | Wraps `StorageBackend`; buffers all writes and commits atomically via a single real transaction |
| `BufferedTransaction` | Struct | Virtual transaction that merges writes into the parent buffer (commit is a no-op to storage)    |

**Note:** Used by `register()` handler to atomically create 6 entities. Reads pass through to inner storage; writes are deferred until `commit()`.

### `src/coordination.rs`

**Purpose:** Trait definitions for distributed coordination (interface only, no implementation).

| Symbol         | Kind   | Description                                        |
| -------------- | ------ | -------------------------------------------------- |
| `LeaderStatus` | Enum   | `Leader`, `Follower`, `NoLeader`                   |
| `WorkerInfo`   | Struct | Worker metadata with heartbeat                     |
| `Coordinator`  | Trait  | 7 async methods for leadership + worker management |

### `tests/ledger_integration_tests.rs`

9 integration tests gated behind `RUN_LEDGER_INTEGRATION_TESTS` env var. Covers basic ops, range ops, TTL, transactions, transaction delete, health check, concurrent writes, vault isolation, reconnection.

**Insight:** PID-seeded atomic counter for vault ID uniqueness prevents `nextest` parallel collisions. Uses early return pattern instead of `#[ignore]` — tests report as passing when skipped.

---

## Crate: `config`

**Path:** `crates/config/` · **Type:** Library · **Dependencies:** bon, clap, serde, strum, tracing, types

### `src/lib.rs`

**Purpose:** CLI-first configuration via `clap::Parser` with environment variable support.

| Symbol           | Kind                    | Description                                                                            |
| ---------------- | ----------------------- | -------------------------------------------------------------------------------------- |
| `Cli`            | Struct (Parser)         | Top-level CLI wrapper with optional subcommands, flattens `Config`                     |
| `CliCommand`     | Enum (Subcommand)       | Placeholder for future subcommands (currently empty)                                   |
| `Config`         | Struct (Parser+Builder) | 19 flat fields: listen, log, PEM, key_file, storage, ledger, email, frontend, dev_mode |
| `StorageBackend` | Enum (ValueEnum)        | `Memory` or `Ledger`; derives `strum::Display` with lowercase serialization            |
| `LogFormat`      | Enum (ValueEnum)        | `Auto`, `Json`, or `Text`                                                              |

| Method                        | Description                                                                |
| ----------------------------- | -------------------------------------------------------------------------- |
| `Config::validate()`          | Cross-field validation: ledger completeness, URL format, dev-mode override |
| `Config::is_email_enabled()`  | Returns `true` when `email_host` is non-empty                              |
| `Config::effective_storage()` | Returns `Memory` if dev_mode, otherwise the storage field                  |
| `Config::is_dev_mode()`       | Returns the dev_mode flag                                                  |

**Note:** Config derives both `clap::Parser` (CLI/env parsing) and `bon::Builder` (test construction). Environment variable prefix: `INFERADB__CONTROL__`. CLI args override env vars override defaults.

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

**Path:** `crates/test-fixtures/` · **Type:** Library · **Dependencies:** api, core, storage, types, axum, tower

### `src/lib.rs`

**Purpose:** Shared test utilities for integration tests. Consolidates common operations to eliminate per-file duplication.

| Function                             | Description                                                          |
| ------------------------------------ | -------------------------------------------------------------------- |
| `create_test_state()`                | Creates `AppState` with in-memory `Backend`                          |
| `create_test_app(state)`             | Wraps `create_router_with_state()` for full app router               |
| `extract_session_cookie(headers)`    | Parses `Set-Cookie` for `infera_session` value                       |
| `register_user(app, ...)`            | Full registration flow, returns session cookie                       |
| `body_json(response)`                | Parse response body as `serde_json::Value`                           |
| `login_user(app, email, password)`   | Login + return session cookie                                        |
| `get_org_id(app, session)`           | Get first org ID from list endpoint                                  |
| `create_organization(app, ...)`      | POST org + return (id, json)                                         |
| `create_vault(app, ...)`             | POST vault + return (id, json)                                       |
| `create_client(app, ...)`            | POST client + return (id, json)                                      |
| `create_client_with_cert(app, ...)`  | Create client + certificate, return (client_id, cert_id, json)       |
| `verify_user_email(state, email)`    | Verify via repository (bypasses email token flow)                    |
| `invite_and_accept_member(app, ...)` | Full invitation flow: create invitation + accept with member session |

---

## Cross-Crate Observations

### Strengths

1. **Consistent `#![deny(unsafe_code)]`** across all library crates
2. **Consistent builder pattern** via `bon::Builder` with `#[builder(on(String, into))]` everywhere
3. **Strong error handling** — `Error` enum with factory methods, no `.unwrap()` in production code; `ErrorResponse` includes machine-readable `code` field
4. **Security hardening** — Argon2id passwords, AES-256-GCM key encryption, Ed25519 JWT signing with audience validation, JTI replay protection, PKCE, rate limiting (wired into routes), audit logging, HTML-escaped email templates, constant-time password reset responses, `Zeroizing<Vec<u8>>` for key material
5. **Distributed systems design** — Worker ID coordination, atomic leader election (CAS-based), NTP clock validation (rsntp), TTL-based cleanup, certificate reconciliation
6. **Comprehensive test suite** — 760 tests: integration (26 test files, 195 tests), unit, property-based (proptest); covers all API endpoints, RBAC, rate limiting, PKCE, tier limits, cascading deletions, concurrent sessions
7. **Clean architecture** — Clear crate boundaries, trait-based abstractions, repository pattern, `BufferedBackend` for cross-repo atomicity
8. **DRY token entities** — `SecureToken` base type eliminates structural duplication between verification and reset tokens
9. **Production-grade caching** — `moka::sync::Cache` (TinyLFU, lock-free reads) replaces custom O(n) LRU; O(1) repository count indexes with self-healing counters

### Remaining Issues

1. **PasskeyCredential timestamp type** — Uses `SystemTime` while all other entities use `chrono::DateTime<Utc>`
2. **Audit event IP addresses** — `extract_client_ip()` exists but audit event callers still use `..Default::default()` for `ip_address` field (always `None`)
3. **`get_organization_by_id()` handler** — Exists but is not routed (dead code); only the vault engine-internal endpoint is active
