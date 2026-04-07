# InferaDB Control Plane — Codebase Manifest

> Comprehensive crate-by-crate, file-by-file analysis of the InferaDB Control Plane.
> Generated 2026-02-05. Updated 2026-04-06.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Crate: `control` (binary entrypoint)](#crate-control)
- [Crate: `api`](#crate-api)
- [Crate: `core`](#crate-core)
- [Crate: `types`](#crate-types)
- [Crate: `config`](#crate-config)
- [Crate: `const`](#crate-const)
- [Crate: `test-fixtures`](#crate-test-fixtures)
- [Crate: `test-integration`](#crate-test-integration)
- [Cross-Crate Observations](#cross-crate-observations)

---

## Architecture Overview

```
inferadb-control (bin) → api → core → inferadb-common-storage
                              → inferadb-ledger-sdk → Ledger
                              → config
                              → types (shared across all)
                              → const (shared across all)
```

| Crate              | Purpose                                                    |
| ------------------ | ---------------------------------------------------------- |
| `control`          | Binary entrypoint, CLI args, startup orchestration         |
| `api`              | HTTP handlers, JWT middleware, routing, rate limiting      |
| `core`             | Crypto, email, ID gen, clock validation, WebAuthn, metrics |
| `types`            | Error enum, ID generator, response DTOs                    |
| `config`           | Configuration loading and validation                       |
| `const`            | Zero-dependency shared constants                           |
| `test-fixtures`    | Lightweight test utilities (state, app, helpers)           |
| `test-integration` | Integration test infrastructure with MockLedgerServer      |

**Key architectural pattern:** The Control Plane is a thin API gateway over the Ledger SDK. Handlers call Ledger directly for entity CRUD, session management, and token operations. No local repository layer or storage abstraction exists in Control — all persistent state is owned by Ledger.

---

## Crate: `control`

**Path:** `crates/control/` · **Type:** Binary · **Dependencies:** api, config, const, core, types, inferadb-ledger-sdk, anyhow, clap, rand, rustls, tokio, tracing, tracing-subscriber

### `src/main.rs`

**Purpose:** Binary entrypoint for the InferaDB Control API server. Handles CLI args, config loading, service initialization, and startup orchestration.

| Symbol   | Kind     | Description                                                                                                                        |
| -------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `main()` | Function | Startup orchestration: crypto provider → CLI → config → logging → display → worker ID → ID gen → email → Ledger → WebAuthn → serve |

**`main()` Initialization Sequence:**

1. Install rustls crypto provider (`aws-lc-rs`)
2. Parse CLI via `Cli::parse()` (clap: CLI args > env vars > defaults)
3. Validate configuration (`config.validate()`)
4. Initialize logging (log_level + log_format with Auto TTY detection)
5. Display startup banner and configuration summary (if not JSON format)
6. Set worker ID (from `--worker-id` config or random 0-1023 with warning)
7. Initialize ID generator (Snowflake) via `IdGenerator::init(worker_id)`
8. Initialize email service (optional SMTP via `lettre`; graceful fallback)
9. Parse email blinding key (hex-encoded HMAC key from config)
10. Connect Ledger SDK client (if storage backend is `ledger`)
11. Initialize rate limiter (`LedgerRateLimiter` if Ledger connected, else `InMemoryRateLimiter`)
12. Configure WebAuthn (`build_webauthn()` with RP ID and origin)
13. Wrap config in `Arc` for shared ownership
14. Start API server via `inferadb_control_api::serve()` with `ServicesConfig`

**Insights:**

- Clean startup orchestration with explicit dependency ordering
- `anyhow::Result` at the binary boundary is idiomatic — libraries return typed errors, binary aggregates with `anyhow`
- Worker ID does **not** support collision detection or K8s ordinal extraction — explicit assignment or random with a warning
- Graceful shutdown via `shutdown_signal()` in `api::lib.rs` — handles Ctrl+C (`SIGINT`) and `SIGTERM`

---

## Crate: `api`

**Path:** `crates/api/` · **Type:** Library · **Dependencies:** config, const, core, types, inferadb-ledger-sdk, inferadb-ledger-types, webauthn-rs, anyhow, axum, axum-extra, base64, bon, chrono, ed25519-dalek, jsonwebtoken, metrics-exporter-prometheus, moka, rand, serde, serde_json, time, tokio, tower, tower-http, tracing, uuid; proptest, sha2, test-fixtures, test-integration, inferadb-common-authn (dev)

### `src/lib.rs`

**Purpose:** Crate root with re-exports. Defines `ServicesConfig` and `serve()`.

| Symbol              | Kind     | Description                                                                                    |
| ------------------- | -------- | ---------------------------------------------------------------------------------------------- |
| `ServicesConfig`    | Struct   | `email_service`, `ledger`, `blinding_key`, `webauthn`, `rate_limiter` (all `Option<Arc<...>>`) |
| `serve()`           | Function | Creates `AppState`, builds router, binds TCP listener, serves with graceful shutdown           |
| `shutdown_signal()` | Function | Handles Ctrl+C and SIGTERM for graceful shutdown                                               |

**Re-exports:** `AppState`, `create_router_with_state`, `RateLimitConfig`, `UserClaims`, `require_jwt`

### `src/routes.rs`

**Purpose:** Defines ALL API routes via `create_router_with_state()`.

| Symbol                       | Kind     | Description                                                                             |
| ---------------------------- | -------- | --------------------------------------------------------------------------------------- |
| `create_router_with_state()` | Function | Two JWT route groups (read/write) plus public routes with rate limiting and body limits |

**Route Groups:**

- **Read routes (local JWT validation):** Organization, team, vault, schema, client, certificate, email, invitation, audit log listing/retrieval — validated locally using cached Ed25519 keys to avoid Ledger round-trips
- **Write routes (Ledger-validated JWT):** All mutation endpoints — organization/team/vault/schema/client CRUD, member management, passkey registration, session revocation
- **Public (no auth):** Health probes (`/livez`, `/readyz`, `/startupz`, `/healthz`), metrics, email auth flow (initiate/verify/complete), MFA verification (TOTP/recovery/passkey), token refresh, client assertion, logout, email verification

**Note:** Auth-related public routes use per-endpoint rate limiting via `.route_layer()`. Registration completion uses a stricter 5/day limit. Default body limit is 256 KiB; schema deploy allows 1 MiB. Concurrency limited to 10,000 requests.

### `src/extract.rs`

**Purpose:** Proxy-aware client IP extraction shared between rate limiting and audit logging.

| Symbol                | Kind     | Description                                                                                                                |
| --------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------- |
| `extract_client_ip()` | Function | If `trusted_proxy_depth` configured: uses rightmost-nth from `X-Forwarded-For`. Otherwise: `ConnectInfo<SocketAddr>` only. |

---

### Middleware (`src/middleware/`)

#### `middleware/jwt.rs`

**Purpose:** Ledger-validated JWT authentication for write routes.

| Symbol                   | Kind       | Description                                                                                  |
| ------------------------ | ---------- | -------------------------------------------------------------------------------------------- |
| `UserClaims`             | Struct     | `user_slug: UserSlug`, `role: String` — extracted from validated JWT                         |
| `require_jwt()`          | Middleware | Validates token via Ledger's `validate_token`, injects `UserClaims`. Returns 401 on failure. |
| `extract_access_token()` | Function   | Extracts from `Authorization: Bearer` header or `inferadb_access` cookie                     |

#### `middleware/jwt_local.rs`

**Purpose:** Local JWT validation for read routes — avoids Ledger round-trip.

| Symbol                | Kind       | Description                                                                                                                             |
| --------------------- | ---------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `JwksCache`           | Struct     | Moka-backed cache (5min TTL, 64 cap) mapping `kid` → `DecodingKey`. Thundering herd prevention via `try_get_with()`.                    |
| `require_jwt_local()` | Middleware | Extracts `kid` from unverified header, fetches key via Ledger on cache miss, validates with EdDSA. Checks audience, issuer, token type. |

#### `middleware/ratelimit.rs`

| Symbol                      | Kind       | Description                                                                                                |
| --------------------------- | ---------- | ---------------------------------------------------------------------------------------------------------- |
| `RateLimitConfig`           | Struct     | Configurable rate limits with manual `Default` impl; production defaults: 100/hr login, 5/day registration |
| `login_rate_limit()`        | Middleware | Per-IP login rate limiting; fail-open on limiter error                                                     |
| `registration_rate_limit()` | Middleware | Per-IP registration rate limiting; fail-open on limiter error                                              |

#### `middleware/logging.rs`

| Symbol                 | Kind       | Description                                                                                                         |
| ---------------------- | ---------- | ------------------------------------------------------------------------------------------------------------------- |
| `logging_middleware()` | Middleware | Logs method, path, matched_path, status, duration_ms, client_ip, user_agent, request_id; records Prometheus metrics |

#### `middleware/request_id.rs`

| Symbol                    | Kind       | Description                                                                                                                  |
| ------------------------- | ---------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `RequestId`               | Struct     | `(pub String)` — unique request identifier                                                                                   |
| `request_id_middleware()` | Middleware | Propagates `X-Request-ID` header or generates UUID v4. Injects into extensions, tracing span, response header. Max 64 chars. |

#### `middleware/security_headers.rs`

| Symbol                          | Kind       | Description                                                                                                                                                      |
| ------------------------------- | ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `security_headers_middleware()` | Middleware | Adds `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store`, HSTS (1yr), `Referrer-Policy: no-referrer`, CSP `default-src 'none'` |

---

### Handlers (`src/handlers/`)

#### `handlers/state.rs`

**Purpose:** Shared application state and error mapping.

| Symbol      | Kind             | Description                                                                                                                                                                                                                |
| ----------- | ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `AppState`  | Struct (Builder) | `config`, `worker_id`, `start_time`, `email_service`, `rate_limits`, `ledger`, `blinding_key`, `webauthn`, `challenge_store`, `rate_limiter`, `jwks_cache`, `health_cache`, `org_membership_cache`; `new_test()` for tests |
| `ApiError`  | Struct           | Wraps `CoreError`; implements `IntoResponse` with status code mapping and JSON error response; scrubs internal details for 5xx                                                                                             |
| `Result<T>` | Type alias       | `std::result::Result<T, ApiError>`                                                                                                                                                                                         |

#### `handlers/common.rs`

**Purpose:** Shared handler utilities, cursor-based pagination, validation.

| Symbol                                | Kind     | Description                                                                            |
| ------------------------------------- | -------- | -------------------------------------------------------------------------------------- |
| `CursorPaginationQuery`               | Struct   | `page_size` (default 50, max 100), `page_token: Option<String>` (opaque base64 cursor) |
| `MessageResponse`                     | Struct   | Generic `{ message: String }` response                                                 |
| `OrgMembershipCache`                  | Struct   | Moka-backed cache (30s TTL, 4096 cap) for `(user_slug, org_slug)` membership checks    |
| `require_ledger()`                    | Function | Returns error if Ledger client unconfigured                                            |
| `encode_page_token()`                 | Function | Base64-encodes cursor bytes                                                            |
| `decode_page_token()`                 | Function | Base64-decodes cursor from query                                                       |
| `verify_org_membership()`             | Function | Checks membership via Ledger with 30s cache                                            |
| `verify_org_membership_from_claims()` | Function | Convenience wrapper extracting org/user from state/claims                              |
| `validate_name()`                     | Function | 1-128 chars, alphanumeric + hyphens/underscores/spaces/periods/apostrophes             |
| `validate_description()`              | Function | Up to 1024 chars, rejects control chars and Unicode bidi overrides                     |
| `validate_email()`                    | Function | RFC 5321 (max 254 chars), requires `local@domain.tld` format                           |
| `safe_id_cast()`                      | Function | Casts i64 → u64 safely, error on negative                                              |

#### `handlers/email_auth.rs`

**Purpose:** Email passwordless authentication — 3-step flow (initiate → verify → complete).

| Symbol       | Kind    | Description                                                                                                      |
| ------------ | ------- | ---------------------------------------------------------------------------------------------------------------- |
| `initiate()` | Handler | POST `/v1/auth/email/initiate` — Generates 6-char code, sends via email (fire-and-forget)                        |
| `verify()`   | Handler | POST `/v1/auth/email/verify` — Verifies code; returns `Authenticated`, `TotpRequired`, or `RegistrationRequired` |
| `complete()` | Handler | POST `/v1/auth/email/complete` — Rate-limited 5/day; creates user + default org, sets cookies                    |

**Response types:** `VerifyResponse` is a tagged enum with three authentication paths. `TotpRequired` includes an encrypted `challenge_nonce` for the MFA step.

#### `handlers/mfa_auth.rs`

**Purpose:** Multi-factor authentication: TOTP, recovery codes, WebAuthn passkeys.

| Symbol                      | Kind    | Description                                                                                                |
| --------------------------- | ------- | ---------------------------------------------------------------------------------------------------------- |
| `verify_totp()`             | Handler | POST `/v1/auth/totp/verify` — Consumes single-use nonce, creates session                                   |
| `consume_recovery()`        | Handler | POST `/v1/auth/recovery` — Single-use recovery code bypass, returns remaining count                        |
| `passkey_begin()`           | Handler | POST `/v1/auth/passkey/begin` — Fetches credentials from Ledger, generates WebAuthn challenge              |
| `passkey_finish()`          | Handler | POST `/v1/auth/passkey/finish` — Validates response, updates sign count; returns session or TOTP challenge |
| `passkey_register_begin()`  | Handler | POST (authenticated) — Generates registration challenge with exclude list                                  |
| `passkey_register_finish()` | Handler | POST (authenticated) — Stores new passkey credential in Ledger                                             |

#### `handlers/auth.rs`

**Purpose:** Session token management — refresh, logout, revoke-all.

| Symbol         | Kind    | Description                                                                  |
| -------------- | ------- | ---------------------------------------------------------------------------- |
| `refresh()`    | Handler | POST `/v1/auth/refresh` — Rotates refresh token via Ledger, sets cookies     |
| `logout()`     | Handler | POST `/v1/auth/logout` — Revokes refresh token (best-effort), clears cookies |
| `revoke_all()` | Handler | POST `/v1/auth/revoke-all` — Requires JWT, revokes all user sessions         |

**Insight:** `set_token_cookies()` sets access (root path) and refresh (`/control/v1/auth` path) as HttpOnly secure cookies with SameSite=Lax. Refresh cookie path-scoped to prevent leakage to non-auth endpoints.

#### `handlers/health.rs`

| Symbol               | Kind    | Description                                             |
| -------------------- | ------- | ------------------------------------------------------- |
| `livez_handler()`    | Handler | Always 200 (Kubernetes liveness)                        |
| `readyz_handler()`   | Handler | Storage health check (Kubernetes readiness)             |
| `startupz_handler()` | Handler | Delegates to readyz (Kubernetes startup)                |
| `healthz_handler()`  | Handler | Full JSON response with storage health, uptime, version |

#### `handlers/tokens.rs`

**Purpose:** Vault-scoped JWT token lifecycle, client assertion auth (RFC 7523).

| Symbol                            | Kind    | Description                                                                                                       |
| --------------------------------- | ------- | ----------------------------------------------------------------------------------------------------------------- |
| `generate_vault_token()`          | Handler | POST — Creates JWT access token + refresh token; accepts `VaultRole` enum                                         |
| `refresh_vault_token()`           | Handler | POST `/v1/tokens/refresh` — Validates, marks used (replay protection), rotates tokens                             |
| `client_assertion_authenticate()` | Handler | POST `/v1/token` — OAuth 2.0 JWT Bearer flow: decode header for `kid`, verify Ed25519 signature, check JTI replay |
| `revoke_vault_tokens()`           | Handler | DELETE — Vault-scoped token revocation                                                                            |

**Insight:** Refresh token rotation (issue new, invalidate old) is a security best practice. Second use of a rotated token returns 401, indicating potential theft.

#### `handlers/users.rs`

| Symbol             | Kind    | Description                                                       |
| ------------------ | ------- | ----------------------------------------------------------------- |
| `get_profile()`    | Handler | GET — Returns authenticated user's profile                        |
| `update_profile()` | Handler | PATCH — Updates display name with validation                      |
| `delete_user()`    | Handler | DELETE — Validates not last owner of any org; cascades via Ledger |

#### `handlers/emails.rs`

| Symbol           | Kind    | Description                                                 |
| ---------------- | ------- | ----------------------------------------------------------- |
| `add_email()`    | Handler | POST — Adds email, generates verification token             |
| `list_emails()`  | Handler | GET — Lists all user emails                                 |
| `delete_email()` | Handler | DELETE — Cannot delete primary email                        |
| `verify_email()` | Handler | POST `/v1/auth/verify-email` — Validates verification token |

#### `handlers/organizations.rs`

**Purpose:** Organization lifecycle, member management, invitations.

| Symbol                        | Kind    | Description                                                        |
| ----------------------------- | ------- | ------------------------------------------------------------------ |
| `create_organization()`       | Handler | POST — Tier limits, verified email required, creator becomes OWNER |
| `list_organizations()`        | Handler | GET — Paginated user orgs                                          |
| `get_organization()`          | Handler | GET — Requires membership                                          |
| `update_organization()`       | Handler | PATCH — Admin/owner required                                       |
| `delete_organization()`       | Handler | DELETE — Owner required                                            |
| `list_members()`              | Handler | GET — Lists all members                                            |
| `update_member_role()`        | Handler | PATCH — Cannot demote last owner                                   |
| `remove_member()`             | Handler | DELETE — Cannot remove last owner                                  |
| `leave_organization()`        | Handler | DELETE — Cannot leave if last owner                                |
| `create_invitation()`         | Handler | POST — Tier member limits, duplicate checks, optional email        |
| `list_invitations()`          | Handler | GET — Pending invitations for an org                               |
| `delete_invitation()`         | Handler | DELETE — Cancels invitation                                        |
| `accept_invitation()`         | Handler | POST — Validates token, checks email match, creates membership     |
| `list_received_invitations()` | Handler | GET — Invitations received by current user                         |
| `decline_invitation()`        | Handler | POST — Declines an invitation                                      |

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
| `revoke_certificate()` | Handler | DELETE — Marks revoked in Control + Ledger; compensating rollback restores active state on Ledger failure                        |
| `rotate_certificate()` | Handler | POST — Creates new cert with grace period, writes to Ledger; compensating deletion on Ledger failure                             |

**Note:** All three certificate lifecycle handlers use compensating transactions — on Ledger write failure, Control state is rolled back.

#### `handlers/vaults.rs`

**Purpose:** Vault lifecycle management. Access grants are managed by Ledger directly.

| Symbol           | Kind    | Description                                              |
| ---------------- | ------- | -------------------------------------------------------- |
| `create_vault()` | Handler | POST — Tier limits, auto-grants creator ADMIN via Ledger |
| `list_vaults()`  | Handler | GET — Accessible vaults                                  |
| `get_vault()`    | Handler | GET — Vault details                                      |
| `update_vault()` | Handler | PATCH — Vault admin required                             |
| `delete_vault()` | Handler | DELETE — Cascades via Ledger                             |

#### `handlers/teams.rs`

| Symbol                 | Kind    | Description                          |
| ---------------------- | ------- | ------------------------------------ |
| `create_team()`        | Handler | POST — Tier limits                   |
| `list_teams()`         | Handler | GET                                  |
| `get_team()`           | Handler | GET                                  |
| `update_team()`        | Handler | PATCH — Admin/owner or team manager  |
| `delete_team()`        | Handler | DELETE — Cascades members            |
| `add_team_member()`    | Handler | POST — Verifies org membership first |
| `list_team_members()`  | Handler | GET                                  |
| `update_team_member()` | Handler | PATCH — Manager status               |
| `remove_team_member()` | Handler | DELETE                               |

#### `handlers/schemas.rs`

**Purpose:** Schema version management for vaults.

| Symbol                 | Kind    | Description                                                         |
| ---------------------- | ------- | ------------------------------------------------------------------- |
| `deploy_schema()`      | Handler | POST — Auto-increment or explicit version; duplicate rejection      |
| `list_schemas()`       | Handler | GET — Optional status filter, pagination                            |
| `get_schema()`         | Handler | GET — By version number                                             |
| `get_current_schema()` | Handler | GET — Active schema                                                 |
| `activate_schema()`    | Handler | POST — Marks ACTIVE                                                 |
| `rollback_schema()`    | Handler | POST — Reactivates previous version                                 |
| `diff_schemas()`       | Handler | GET — Placeholder (returns empty changes; diff delegated to Engine) |

#### `handlers/audit_logs.rs`

| Symbol              | Kind    | Description                                     |
| ------------------- | ------- | ----------------------------------------------- |
| `list_audit_logs()` | Handler | GET — Owner-only, with filtering and pagination |

**Note:** Audit event ingestion is handled by Ledger's event system — no creation handler in Control.

#### `handlers/metrics.rs`

| Symbol              | Kind     | Description                             |
| ------------------- | -------- | --------------------------------------- |
| `METRICS_HANDLE`    | Static   | `OnceLock<PrometheusHandle>` singleton  |
| `init_exporter()`   | Function | Initializes Prometheus recorder (once)  |
| `metrics_handler()` | Handler  | GET `/metrics` — Prometheus text format |

---

### Test Suite (`tests/`)

Tests are consolidated into 3 files with nested module organization:

| Test File              | Coverage                                                                                                                                                   |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `integration_tests.rs` | 118 tests across 13 modules: auth, email_auth, users, organizations, vaults, teams, clients, schemas, tokens, emails, audit_logs, mfa_auth, jwt_middleware |
| `handler_tests.rs`     | 20 handler-level tests                                                                                                                                     |
| `ratelimit_tests.rs`   | 1 rate limit enforcement test                                                                                                                              |

**Module breakdown in `integration_tests.rs`:**

| Module         | Tests |
| -------------- | ----- |
| auth           | 9     |
| email_auth     | 10    |
| users          | 6     |
| organizations  | 23    |
| vaults         | 6     |
| teams          | 10    |
| clients        | 11    |
| schemas        | 7     |
| tokens         | 4     |
| emails         | 4     |
| audit_logs     | 2     |
| mfa_auth       | 21    |
| jwt_middleware | 5     |

Run `cargo nextest run` for current totals.

---

## Crate: `core`

**Path:** `crates/core/` · **Type:** Library · **Dependencies:** types, const, inferadb-common-ratelimit, inferadb-common-storage, inferadb-ledger-sdk, inferadb-ledger-types, tonic, aes-gcm, async-trait, base64, bon, bytes, chrono, ed25519-dalek, idgenerator, lettre, metrics, rand, rsntp, serde, serde_json, terminal_size, tokio, tracing, tracing-subscriber, unicode-width, url, webauthn-rs, zeroize; opentelemetry, opentelemetry-otlp, opentelemetry_sdk, tracing-opentelemetry (optional); proptest, tempfile (dev)

### `src/lib.rs`

**Purpose:** Crate root. Re-exports all public types organized by domain concern.

`#![deny(unsafe_code)]` applied crate-wide.

**Re-exports:** `clock` (ClockStatus, ClockValidator, SkewSeverity), `crypto` (MasterKey, PrivateKeyEncryptor, keypair), `email` (EmailSender, EmailService, all templates, MockEmailSender, SmtpEmailService), `email_hmac` (EmailBlindingKey, compute_email_hmac, normalize_email, parse_blinding_key), `id` (IdGenerator), `ratelimit` (AnyRateLimiter, InMemoryRateLimiter, LedgerRateLimiter, RateLimit, RateLimitResponse, RateLimitResult, RateLimiter, categories, limits), `ratelimit_ledger` (LedgerStorageBackend), `sdk_error` (SdkResultExt, sdk_error_to_control)

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

**Purpose:** Snowflake ID generation with custom epoch (2024-01-01T00:00:00Z).

| Symbol                     | Kind   | Description                                                  |
| -------------------------- | ------ | ------------------------------------------------------------ |
| `IdGenerator`              | Struct | Zero-sized type exposing static Snowflake ID generation      |
| `IdGenerator::init(u16)`   | Method | One-time global initialization with worker ID (0-1023)       |
| `IdGenerator::next_id()`   | Method | Generates next unique Snowflake ID                           |
| `IdGenerator::worker_id()` | Method | Returns the initialized worker ID (0 if not yet initialized) |

### `src/logging.rs`

**Purpose:** Structured logging initialization with optional OpenTelemetry. Uses an internal `LogFormat` enum (`Full`, `Pretty`, `Compact`, `Json`) for renderer selection — distinct from the public `LogFormat` in the config crate (`Auto`, `Json`, `Text`) which maps to these internal formats.

| Symbol                | Kind     | Description                                                                                                       |
| --------------------- | -------- | ----------------------------------------------------------------------------------------------------------------- |
| `LogFormat`           | Enum     | Internal: `Full`, `Pretty`, `Compact`, `Json` (not exported; used by `init()`)                                    |
| `LogConfig`           | Struct   | Configuration: `format`, `include_location`, `include_target`, `include_thread_id`, `log_spans`, `ansi`, `filter` |
| `init_logging()`      | Function | Primary logging initializer; accepts `LogConfig`, used by `main()`                                                |
| `init()`              | Function | Legacy simplified initialization (log_level + json bool)                                                          |
| `init_with_tracing()` | Function | With OpenTelemetry OTLP (10% sampling)                                                                            |

### `src/metrics.rs`

**Purpose:** Prometheus metrics registration and recording.

| Symbol                            | Kind     | Description                                          |
| --------------------------------- | -------- | ---------------------------------------------------- |
| `init()`                          | Function | Register all metrics (idempotent via `Once`)         |
| `record_http_request()`           | Function | Counter + histogram                                  |
| `record_auth_attempt()`           | Function | Counter by type/success                              |
| `record_registration()`           | Function | Registration counter                                 |
| `record_rate_limit_exceeded()`    | Function | Rate limit exceeded counter by category              |
| `record_db_query()`               | Function | Histogram for DB latency                             |
| `record_grpc_request()`           | Function | gRPC request counter + histogram                     |
| `set_active_sessions()`           | Function | `active_sessions` gauge                              |
| `set_organizations_total()`       | Function | `organizations_total` gauge                          |
| `set_vaults_total()`              | Function | `vaults_total` gauge                                 |
| `record_discovery_cache_hit()`    | Function | Discovery cache hit counter                          |
| `record_discovery_cache_miss()`   | Function | Discovery cache miss counter                         |
| `set_discovered_endpoints()`      | Function | `discovered_endpoints` gauge                         |
| `set_clock_skew()`                | Function | `clock_skew_seconds` gauge for NTP monitoring        |
| `record_signing_key_registered()` | Function | Signing key registration counter + histogram per org |
| `record_signing_key_revoked()`    | Function | Signing key revocation counter + histogram per org   |
| `record_signing_key_rotated()`    | Function | Signing key rotation counter + histogram per org     |

### `src/ratelimit.rs`

**Purpose:** Rate limiting with pluggable backends (in-memory or Ledger-backed).

| Symbol                | Kind       | Description                                                            |
| --------------------- | ---------- | ---------------------------------------------------------------------- |
| `RateLimit`           | Type alias | Alias for `RateLimitPolicy` — config with `max_requests` and window    |
| `RateLimiter`         | Type alias | Alias for `AppRateLimiter` — storage-backed rate limiter               |
| `RateLimitResult`     | Type alias | Alias for `RateLimitOutcome` — `allowed`, `remaining`, `reset_after`   |
| `InMemoryRateLimiter` | Type alias | `RateLimiter<MemoryBackend>` — single-node rate limiting               |
| `LedgerRateLimiter`   | Type alias | `RateLimiter<LedgerStorageBackend>` — distributed rate limiting        |
| `AnyRateLimiter`      | Enum       | Dynamic dispatch: `InMemory` or `Ledger` variant with `check()` method |
| `categories`          | Module     | Re-exports rate limit category constants from `inferadb-control-const` |
| `limits`              | Module     | Standard limits: `login_ip()` (100/hr), `registration_ip()` (5/day)    |

### `src/email_hmac.rs`

**Purpose:** Email blinding key utilities for privacy-preserving email lookups.

| Symbol               | Kind      | Description                                              |
| -------------------- | --------- | -------------------------------------------------------- |
| `parse_blinding_key` | Function  | Parses hex-encoded email blinding key from config string |
| `EmailBlindingKey`   | Re-export | Typed blinding key from `inferadb-ledger-types`          |
| `compute_email_hmac` | Re-export | HMAC computation for email blinding                      |
| `normalize_email`    | Re-export | Email normalization (lowercase, trim)                    |

### `src/ratelimit_ledger.rs`

**Purpose:** Ledger-backed storage for distributed rate limiting across multiple Control nodes.

| Symbol                 | Kind   | Description                                                                    |
| ---------------------- | ------ | ------------------------------------------------------------------------------ |
| `LedgerStorageBackend` | Struct | Delegates rate limit state to Ledger's entity store for multi-node consistency |

### `src/sdk_error.rs`

**Purpose:** Mapping Ledger SDK errors to Control API error types.

| Symbol                                     | Kind     | Description                                                               |
| ------------------------------------------ | -------- | ------------------------------------------------------------------------- |
| `sdk_error_to_control()`                   | Function | Converts Ledger SDK errors to Control API errors with gRPC status mapping |
| `SdkResultExt`                             | Trait    | Extension trait on `Result<T, SdkError>` for ergonomic error conversion   |
| `SdkResultExt::map_sdk_err()`              | Method   | Maps SdkError → Control Error                                             |
| `SdkResultExt::map_sdk_err_instrumented()` | Method   | Maps error and records gRPC request metrics (duration, status code)       |

### `src/webauthn.rs`

**Purpose:** WebAuthn passkey challenge orchestration with stateless encrypted challenge store.

| Symbol                         | Kind     | Description                                                                           |
| ------------------------------ | -------- | ------------------------------------------------------------------------------------- |
| `CHALLENGE_TTL`                | Const    | 60 seconds                                                                            |
| `ChallengeState`               | Enum     | Ephemeral state for passkey ceremonies (`Registration`, `Authentication` variants)    |
| `ChallengeStore`               | Struct   | Stateless store backed by AES-256-GCM encrypted tokens — no server-side session state |
| `ChallengeStore::insert()`     | Method   | Encrypts challenge state into opaque base64url token                                  |
| `ChallengeStore::take()`       | Method   | Decrypts and validates token (checks TTL), returns `ChallengeState` or `None`         |
| `build_webauthn()`             | Function | Builds `Webauthn` instance from RP ID and origin config                               |
| `passkey_to_credential_data()` | Function | Converts webauthn-rs `Passkey` to Ledger SDK `CredentialData`                         |
| `credential_info_to_passkey()` | Function | Converts Ledger SDK `PasskeyCredential` back to webauthn-rs `Passkey`                 |

**Insight:** Stateless challenge store is elegant — encrypts the entire challenge state into the token itself (AES-256-GCM), so no server-side state or cache is needed. TTL is embedded in the encrypted payload.

### `src/startup.rs`

**Purpose:** Terminal-aware startup display with ASCII art banner and TRON-aesthetic config tables.

| Symbol                                  | Kind      | Description                                            |
| --------------------------------------- | --------- | ------------------------------------------------------ |
| `ServiceInfo`                           | Struct    | Name, subtext, version, environment                    |
| `StartupDisplay`                        | Builder   | Renders banner + config summary with responsive layout |
| `log_phase/log_initialized/log_ready()` | Functions | Lifecycle phase logging helpers                        |

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

## Crate: `types`

**Path:** `crates/types/` · **Type:** Library · **Dependencies:** inferadb-common-storage, inferadb-ledger-types, bon, serde, serde_json, snafu, idgenerator

`#![deny(unsafe_code)]` at crate root.

**Note:** This crate was significantly slimmed in a March 2026 refactoring. Entity definitions and most DTOs were removed — persistent entities are now owned by Ledger and defined in `inferadb-ledger-types`.

### `src/lib.rs`

**Purpose:** Crate root. Re-exports core shared types.

| Type               | Description                            |
| ------------------ | -------------------------------------- |
| `OrganizationSlug` | Re-export from `inferadb-ledger-types` |
| `VaultSlug`        | Re-export from `inferadb-ledger-types` |
| `IdGenerator`      | Snowflake ID generation                |
| `Error`            | Unified error enum                     |
| `Result`           | `std::result::Result<T, Error>`        |
| `ErrorResponse`    | JSON error response DTO                |

### `src/id.rs`

| Type          | Description                                                                                                        |
| ------------- | ------------------------------------------------------------------------------------------------------------------ |
| `IdGenerator` | Zero-field struct; `next_id()` delegates to `idgenerator::IdInstance`. Will panic if called before initialization. |

### `src/error.rs`

**Purpose:** Unified error enum.

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
| `Unavailable`     | 503    | `SERVICE_UNAVAILABLE`    | Service temporarily down |
| `External`        | 502    | `EXTERNAL_SERVICE_ERROR` | External service failure |
| `Internal`        | 500    | `INTERNAL_ERROR`         | Internal system error    |

Factory methods: `Error::validation("msg")`, `Error::not_found("msg")`, `Error::unavailable("msg")`, etc.

### `src/dto/auth.rs`

| Type            | Description                                                                          |
| --------------- | ------------------------------------------------------------------------------------ |
| `ErrorResponse` | JSON error body: `error` (message), `code` (error code string), `details` (optional) |

---

## Crate: `config`

**Path:** `crates/config/` · **Type:** Library · **Dependencies:** bon, clap, serde, strum, tracing, types

### `src/lib.rs`

**Purpose:** CLI-first configuration via `clap::Parser` with environment variable support.

| Symbol           | Kind                    | Description                                                                         |
| ---------------- | ----------------------- | ----------------------------------------------------------------------------------- |
| `Cli`            | Struct (Parser)         | Top-level CLI wrapper with optional subcommands, flattens `Config`                  |
| `CliCommand`     | Enum (Subcommand)       | Placeholder for future subcommands (currently empty)                                |
| `Config`         | Struct (Parser+Builder) | Flat fields: listen, log, PEM, key_file, storage, ledger, email, frontend, dev_mode |
| `StorageBackend` | Enum (ValueEnum)        | `Memory` or `Ledger`; derives `strum::Display` with lowercase serialization         |
| `LogFormat`      | Enum (ValueEnum)        | `Auto`, `Json`, or `Text`                                                           |

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

| Constant                    | Value                        | Description               |
| --------------------------- | ---------------------------- | ------------------------- |
| `REQUIRED_ISSUER`           | `"https://api.inferadb.com"` | JWT `iss` claim           |
| `REQUIRED_AUDIENCE`         | `"https://api.inferadb.com"` | JWT `aud` claim           |
| `SESSION_COOKIE_NAME`       | `"infera_session"`           | Cookie name               |
| `ACCESS_TOKEN_COOKIE_NAME`  | `"inferadb_access"`          | Access token cookie name  |
| `REFRESH_TOKEN_COOKIE_NAME` | `"inferadb_refresh"`         | Refresh token cookie name |
| `SYSTEM_CALLER_SLUG`        | `0`                          | System caller ID          |
| `SESSION_COOKIE_MAX_AGE`    | `86400` (24h)                | Cookie expiration         |

### `src/duration.rs`

| Constant                                 | Value               | Description             |
| ---------------------------------------- | ------------------- | ----------------------- |
| `AUTHORIZATION_CODE_TTL_SECONDS`         | `600` (10 min)      | OAuth2 auth code        |
| `USER_SESSION_REFRESH_TOKEN_TTL_SECONDS` | `3600` (1 hour)     | Browser session refresh |
| `CLIENT_REFRESH_TOKEN_TTL_SECONDS`       | `604800` (7 days)   | Machine client refresh  |
| `INVITATION_EXPIRY_DAYS`                 | `7`                 | Org invitation          |
| `EMAIL_VERIFICATION_TOKEN_EXPIRY_HOURS`  | `24`                | Email verification      |
| `PASSWORD_RESET_TOKEN_EXPIRY_HOURS`      | `1`                 | Password reset          |
| `ACCESS_COOKIE_MAX_AGE_SECONDS`          | `900` (15 min)      | Access token cookie     |
| `REFRESH_COOKIE_MAX_AGE_SECONDS`         | `2592000` (30 days) | Refresh token cookie    |
| `HEALTH_CACHE_TTL_SECONDS`               | `5`                 | Health check cache      |

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

**Path:** `crates/test-fixtures/` · **Type:** Library · **Dependencies:** api, const, axum, serde_json, tokio, tower

### `src/lib.rs`

**Purpose:** Lightweight test utilities for unit and integration tests. Provides app construction and HTTP helpers.

| Function                          | Description                                                     |
| --------------------------------- | --------------------------------------------------------------- |
| `create_test_state()`             | Creates `AppState` with in-memory backend, no Ledger connection |
| `create_test_app(state)`          | Wraps `create_router_with_state()` for full app router          |
| `extract_access_token(headers)`   | Extracts `inferadb_access` cookie value from response headers   |
| `extract_refresh_token(headers)`  | Extracts `inferadb_refresh` cookie value from response headers  |
| `body_json(response)`             | Parse response body as `serde_json::Value`                      |
| `json_request(method, uri)`       | Builds HTTP request with JSON content-type, no auth             |
| `post_json(app, uri, body)`       | Sends JSON POST request, returns response                       |
| `get(app, uri)`                   | Sends GET request, returns response                             |
| `assert_status(response, status)` | Asserts response status code and returns JSON body              |

**Re-exports:** `AppState`, `create_router_with_state`, `ACCESS_TOKEN_COOKIE_NAME`, `REFRESH_TOKEN_COOKIE_NAME`

---

## Crate: `test-integration`

**Path:** `crates/test-integration/` · **Type:** Library · **Dependencies:** api, config, const, core, types, inferadb-ledger-sdk, inferadb-ledger-types, axum, ed25519-dalek, jsonwebtoken, serde, serde_json, tokio, tower, webauthn-rs

### `src/lib.rs`

**Purpose:** Integration test infrastructure with `MockLedgerServer` for end-to-end handler testing. Provides `TestHarness` with authenticated request helpers, simulating full Ledger interactions without a real Ledger instance.

---

## Cross-Crate Observations

### Strengths

1. **Consistent `#![deny(unsafe_code)]`** across all library crates
2. **Consistent builder pattern** via `bon::Builder` with `#[builder(on(String, into))]` everywhere
3. **Strong error handling** — `Error` enum with 13 factory methods, no `.unwrap()` in production code; `ErrorResponse` includes machine-readable `code` field
4. **Security hardening** — AES-256-GCM key encryption, Ed25519 JWT signing, JTI replay protection, PKCE, rate limiting (per-endpoint), security headers middleware, HTML-escaped email templates, `Zeroizing<Vec<u8>>` for key material, stateless encrypted WebAuthn challenges
5. **Distributed systems design** — Ledger SDK for all persistent state, distributed rate limiting via `LedgerRateLimiter`, NTP clock validation (rsntp), cursor-based pagination
6. **Comprehensive test suite** — 139 tests across integration, handler, and rate limit suites covering all API endpoints, auth flows, MFA, RBAC, and edge cases
7. **Clean architecture** — Thin API gateway pattern, handlers call Ledger SDK directly, no local storage abstraction needed
8. **Dual JWT validation** — Read routes use local Ed25519 key cache (avoids round-trip), write routes validate via Ledger (authoritative)
9. **Stateless auth** — WebAuthn challenges encrypted into tokens (no server-side session state), JWT-based authentication throughout
10. **Caching strategy** — Moka-backed caches with appropriate TTLs: JWKS (5min), org membership (30s), health checks (5s)

### Remaining Issues

1. **SystemTime inconsistency** — `webauthn.rs` challenge store uses `SystemTime` while the rest of the codebase uses `chrono::DateTime<Utc>`
