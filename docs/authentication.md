# Authentication

InferaDB Control authenticates users through passwordless email codes, passkeys, and TOTP, issuing Ed25519-signed JWT access tokens and opaque refresh tokens.

## Why it matters

All Control API operations require authentication. The token architecture separates user identity tokens (for Control operations) from vault-scoped tokens (for Engine operations), preventing privilege escalation across service boundaries.

## Quickstart

Authenticate with email and use the returned tokens:

```bash
# 1. Request a verification code
curl -X POST https://control.example.com/control/v1/auth/email/initiate \
  -H "Content-Type: application/json" \
  -d '{"email": "you@example.com"}'

# 2. Verify the code from your inbox
curl -X POST https://control.example.com/control/v1/auth/email/verify \
  -H "Content-Type: application/json" \
  -d '{"email": "you@example.com", "code": "ABC123"}'
# Returns: {"status": "authenticated", "access_token": "...", "refresh_token": "..."}

# 3. Use the access token for API calls
curl https://control.example.com/control/v1/users/me \
  -H "Authorization: Bearer <access_token>"
```

## Core concepts

### Token types

InferaDB issues three token types:

**JWT access tokens** authenticate requests to Control. They are Ed25519-signed, validated locally for read operations and via Ledger for write operations.

| Property          | Value                                    |
| ----------------- | ---------------------------------------- |
| Algorithm         | EdDSA (Ed25519)                          |
| Issuer            | `https://api.inferadb.com`               |
| Audience          | `https://api.inferadb.com`               |
| Cookie name       | `inferadb_access`                        |
| Cookie path       | `/`                                      |
| Cookie max-age    | 15 minutes (900 seconds)                 |
| Cookie attributes | `HttpOnly`, `Secure`, `SameSite=Lax`     |
| Transmission      | `Authorization: Bearer` header or cookie |

**Opaque refresh tokens** obtain new token pairs. They are stored in Ledger and rotated on every use (the old token is invalidated).

| Property           | Value                                |
| ------------------ | ------------------------------------ |
| Cookie name        | `inferadb_refresh`                   |
| Cookie path        | `/control/v1/auth`                   |
| Cookie max-age     | 30 days (2,592,000 seconds)          |
| Cookie attributes  | `HttpOnly`, `Secure`, `SameSite=Lax` |
| User session TTL   | 1 hour (3,600 seconds)               |
| Client session TTL | 7 days (604,800 seconds)             |
| Transmission       | Request body or cookie               |

**Vault-scoped JWTs** authorize requests to the Engine. They are issued by Control and validated by the Engine using cached JWKS public keys.

| Property     | Value                          |
| ------------ | ------------------------------ |
| Algorithm    | EdDSA (Ed25519)                |
| Issuer       | `https://api.inferadb.com`     |
| Audience     | `https://api.inferadb.com`     |
| Transmission | `Authorization: Bearer` header |

### JWT validation modes

Control uses two validation strategies depending on the operation:

- **Read routes** (GET): Local Ed25519 signature verification using cached public keys (5-minute TTL via moka cache). No Ledger round-trip.
- **Write routes** (POST/PATCH/DELETE): Full Ledger `validate_token` round-trip. Ensures the token has not been revoked.

### Token extraction

The middleware checks for tokens in this order:

1. `Authorization: Bearer <token>` header
2. `inferadb_access` cookie

If neither is present, the request is rejected with 401.

## Authentication methods

### Email code (primary)

Three-step passwordless flow. No passwords exist in the system.

**Step 1 -- Initiate.** Send a 6-character verification code to an email address. The code expires in 10 minutes.

```
POST /control/v1/auth/email/initiate
```

```json
{ "email": "you@example.com", "region": "us-east-va" }
```

The `region` field is optional and defaults to `US_EAST_VA`. It controls data residency for the user's PII.

**Step 2 -- Verify.** Submit the code. The response varies by user state:

```
POST /control/v1/auth/email/verify
```

```json
{ "email": "you@example.com", "code": "ABC123" }
```

Three possible outcomes:

| Status                  | Meaning                     | Response fields                               |
| ----------------------- | --------------------------- | --------------------------------------------- |
| `authenticated`         | Existing user, no TOTP      | `access_token`, `refresh_token`, `token_type` |
| `totp_required`         | Existing user, TOTP enabled | `challenge_nonce` (base64)                    |
| `registration_required` | New user                    | `onboarding_token`                            |

**Step 3 -- Complete** (new users only). Create the user account and default organization.

```
POST /control/v1/auth/email/complete
```

```json
{
  "onboarding_token": "<from step 2>",
  "email": "you@example.com",
  "name": "Alice",
  "organization_name": "Acme Corp",
  "region": "us-east-va"
}
```

Returns:

```json
{
  "registration": {
    "user": 1234567890123456789,
    "organization": 9876543210987654321,
    "access_token": "eyJ...",
    "refresh_token": "opaque-token",
    "token_type": "Bearer"
  }
}
```

**Rate limits:** Initiate and verify share the login rate limit (100 requests/hour per IP). Complete uses the registration rate limit (5 requests/day per IP).

### Passkey authentication (WebAuthn/FIDO2)

Two-step WebAuthn ceremony for users with registered passkeys.

**Begin:**

```
POST /control/v1/auth/passkey/begin
```

```json
{ "user_slug": 1234567890123456789 }
```

Returns `challenge_id` and a WebAuthn `challenge` (RequestChallengeResponse). The challenge expires in 60 seconds. Challenge state is encrypted with AES-256-GCM and encoded into the `challenge_id` itself -- no server-side storage.

**Finish:**

```
POST /control/v1/auth/passkey/finish
```

```json
{
  "challenge_id": "<from begin>",
  "credential": {
    /* WebAuthn PublicKeyCredential */
  }
}
```

Two possible outcomes:

| Status          | Meaning      | Response fields                               |
| --------------- | ------------ | --------------------------------------------- |
| `authenticated` | No TOTP      | `access_token`, `refresh_token`, `token_type` |
| `totp_required` | TOTP enabled | `challenge_nonce` (base64)                    |

### Passkey registration (authenticated)

Requires an existing JWT session. These are write routes validated via Ledger.

**Begin:**

```
POST /control/v1/users/me/credentials/passkeys/begin
```

```json
{ "name": "My MacBook" }
```

The `name` field is optional (defaults to "Passkey"). Returns `challenge_id` and a WebAuthn `challenge` (CreationChallengeResponse). Existing passkeys are used as an exclude list to prevent re-registration.

**Finish:**

```
POST /control/v1/users/me/credentials/passkeys/finish
```

```json
{
  "challenge_id": "<from begin>",
  "name": "My MacBook",
  "credential": {
    /* WebAuthn RegisterPublicKeyCredential */
  }
}
```

Returns `slug` (credential ID) and `name`.

### TOTP verification

When email code or passkey authentication returns `totp_required`, complete the second factor with one of these endpoints.

**TOTP code:**

```
POST /control/v1/auth/totp/verify
```

```json
{
  "user_slug": 1234567890123456789,
  "totp_code": "123456",
  "challenge_nonce": "<base64 from previous step>"
}
```

Returns `access_token`, `refresh_token`, and `token_type`.

**Recovery code** (TOTP bypass):

```
POST /control/v1/auth/recovery
```

```json
{
  "user_slug": 1234567890123456789,
  "code": "ABCD1234",
  "challenge_nonce": "<base64 from previous step>"
}
```

Returns `access_token`, `refresh_token`, `token_type`, and `remaining_codes`. Each recovery code is single-use.

### Client assertion (machine-to-machine)

OAuth 2.0 JWT Bearer (RFC 7523) for backend services. The client signs a short-lived JWT with its Ed25519 private key, and Control verifies the signature against the client's registered public key.

```
POST /control/v1/token
```

```json
{
  "grant_type": "client_credentials",
  "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
  "client_assertion": "<signed-jwt>",
  "organization": 1234567890123456789,
  "vault": "9876543210987654321",
  "scopes": ["vault:read", "vault:write"],
  "requested_role": "write"
}
```

| Field                   | Required | Description                                                        |
| ----------------------- | -------- | ------------------------------------------------------------------ |
| `grant_type`            | Yes      | Must be `"client_credentials"`                                     |
| `client_assertion_type` | Yes      | Must be `"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"` |
| `client_assertion`      | Yes      | Ed25519-signed JWT assertion                                       |
| `organization`          | Yes      | Organization slug (numeric)                                        |
| `vault`                 | Yes      | Vault slug (string)                                                |
| `scopes`                | No       | Scope strings to grant                                             |
| `requested_role`        | No       | Appended to scopes if not already present                          |

Returns `201 Created` with `access_token`, `refresh_token`, `token_type`, and `expires_in`.

## Session management

### Refresh tokens

```
POST /control/v1/auth/refresh
```

Accepts `refresh_token` in the request body or reads from the `inferadb_refresh` cookie. Returns a new token pair. The old refresh token is invalidated (rotate-on-use).

```json
{ "refresh_token": "<opaque-token>" }
```

### Logout

```
POST /control/v1/auth/logout
```

Revokes the current session's refresh token (best-effort) and clears both cookies. Does not require authentication -- the refresh token cookie provides identity.

### Revoke all sessions

```
POST /control/v1/auth/revoke-all
Authorization: Bearer <access_token>
```

Requires JWT authentication (write route, Ledger-validated). Revokes all sessions for the authenticated user. Returns `{"revoked_count": <number>}` and clears cookies.

## Vault tokens

Vault tokens grant access to Engine operations (policy evaluation, relationship queries).

### Generate a vault token

```
POST /control/v1/organizations/{org}/vaults/{vault}/tokens
Authorization: Bearer <access_token>
```

```json
{
  "app": 1234567890123456789,
  "scopes": ["vault:read", "vault:write"]
}
```

The caller must have access to the specified app in the organization. Returns `201 Created`:

```json
{
  "access_token": "<vault-jwt>",
  "refresh_token": "<opaque-token>",
  "token_type": "Bearer",
  "expires_in": 300
}
```

### Refresh a vault token

```
POST /control/v1/tokens/refresh
```

```json
{ "refresh_token": "<opaque-token>" }
```

Public endpoint (the refresh token provides authentication). Returns a new token pair.

### Revoke vault tokens

```
DELETE /control/v1/organizations/{org}/vaults/{vault}/tokens
Authorization: Bearer <access_token>
```

```json
{ "app": 1234567890123456789 }
```

Revokes all tokens for the specified app. Returns `{"revoked_count": <number>}`.

## Vault JWT claims

Vault-scoped JWTs contain these claims:

```json
{
  "iss": "https://api.inferadb.com",
  "sub": "client:1234567890123456789",
  "aud": "https://api.inferadb.com",
  "exp": 1234567890,
  "iat": 1234567800,
  "org_id": "9876543210987654321",
  "vault_id": "1111222233334444555",
  "vault_role": "write",
  "scope": "inferadb.check inferadb.read inferadb.write inferadb.expand inferadb.list inferadb.list-relationships inferadb.list-subjects inferadb.list-resources"
}
```

| Claim        | Description                                             |
| ------------ | ------------------------------------------------------- |
| `iss`        | Issuer (`https://api.inferadb.com`)                     |
| `sub`        | Client identifier (`client:<snowflake_id>`)             |
| `aud`        | Audience (`https://api.inferadb.com`)                   |
| `exp`        | Expiration (Unix timestamp)                             |
| `iat`        | Issued at (Unix timestamp)                              |
| `org_id`     | Organization ID (Snowflake ID as string)                |
| `vault_id`   | Vault ID (Snowflake ID as string)                       |
| `vault_role` | Permission level: `read`, `write`, `manage`, or `admin` |
| `scope`      | Space-separated API permissions based on role           |

## Rate limits

| Endpoint group                                                                    | Limit        | Window        |
| --------------------------------------------------------------------------------- | ------------ | ------------- |
| Login/auth (initiate, verify, TOTP, recovery, passkey, refresh, client assertion) | 100 requests | 1 hour per IP |
| Registration (complete)                                                           | 5 requests   | 1 day per IP  |

When a limit is exceeded, the API returns `429 Too Many Requests` with a `Retry-After` header.

## Security reference

### Token lifetimes

| Token                                   | Lifetime       |
| --------------------------------------- | -------------- |
| Access token cookie                     | 15 minutes     |
| Refresh token cookie                    | 30 days        |
| User session refresh token (Ledger TTL) | 1 hour         |
| Client refresh token (Ledger TTL)       | 7 days         |
| Authorization code                      | 10 minutes     |
| Client assertion                        | 60 seconds max |
| Email verification token                | 24 hours       |
| Organization invitation                 | 7 days         |
| WebAuthn challenge                      | 60 seconds     |

### Revocation

**Session tokens:** Call `POST /control/v1/auth/revoke-all` or `POST /control/v1/auth/logout`. Refresh tokens are rejected on next use. Existing access token JWTs expire naturally (max 15 minutes).

**Vault tokens:** Revoke via `DELETE /control/v1/organizations/{org}/vaults/{vault}/tokens`. Existing vault JWTs expire naturally.

**Client certificates:** Delete via `DELETE /control/v1/organizations/{org}/clients/{client}/certificates/{cert}`. New assertions using this certificate fail. Existing vault JWTs expire naturally. Engine JWKS cache refreshes within 5 minutes.

### Cryptographic details

- JWT algorithm: EdDSA with Ed25519
- JWKS cache: 5-minute TTL, max 64 keys, moka async cache with deduplication
- WebAuthn challenge encryption: AES-256-GCM with 12-byte nonce
- Challenge state: Serialized, timestamped, encrypted, and base64url-encoded (stateless)

## Further reading

- [Data flows](flows.md): Sequence diagrams for each authentication flow
- [Architecture](architecture.md): System architecture and deployment topology
