# Getting Started

Set up InferaDB Control and make your first API calls in under five minutes.

## Why this matters

InferaDB Control is the administration API for the InferaDB platform. You use it to manage accounts, organizations, vaults, clients, and vault tokens. This tutorial takes you from zero to a working vault token you can use with the InferaDB Engine.

## Quickstart

```bash
cargo build --release
./target/release/inferadb-control --dev-mode
```

The server starts on `http://localhost:9090`. Dev mode uses in-memory storage and auto-generates an Ed25519 identity key. No configuration files needed.

## Prerequisites

- **Rust 1.92+** -- install via [rustup](https://rustup.rs/)
- **curl** or any HTTP client
- **jq** (optional, for pretty-printing JSON responses)

## Step 1: Build and start the server

```bash
git clone https://github.com/inferadb/inferadb.git
cd inferadb/control
cargo build --release
./target/release/inferadb-control --dev-mode
```

Expected output:

```text
2026-04-06T10:00:00.000Z INFO  Starting InferaDB Control
2026-04-06T10:00:00.123Z INFO  HTTP server listening on 127.0.0.1:9090
```

Verify the server is running:

```bash
curl http://localhost:9090/healthz
```

## Step 2: Create an account (email auth flow)

InferaDB uses passwordless email authentication. The flow has three steps: initiate, verify, and complete registration.

### Initiate email verification

Send a verification code to your email address:

```bash
curl -s -X POST http://localhost:9090/control/v1/auth/email/initiate \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@northwind.com"
  }'
```

Response:

```json
{
  "message": "verification code sent"
}
```

In dev mode without SMTP configured, the server logs the code but does not send email. Check the server logs for the 6-character code.

### Verify the code

```bash
curl -s -X POST http://localhost:9090/control/v1/auth/email/verify \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@northwind.com",
    "code": "847291"
  }'
```

For a new user, the response indicates registration is required:

```json
{
  "status": "registration_required",
  "onboarding_token": "obt_e8f4a2b1c9d7..."
}
```

For an existing user without TOTP, you receive session tokens directly:

```json
{
  "status": "authenticated",
  "access_token": "eyJhbGciOiJFZERTQSIs...",
  "refresh_token": "rt_7c9d3e2f1a8b...",
  "token_type": "Bearer"
}
```

### Complete registration (new users only)

```bash
curl -s -X POST http://localhost:9090/control/v1/auth/email/complete \
  -H "Content-Type: application/json" \
  -d '{
    "onboarding_token": "obt_e8f4a2b1c9d7...",
    "email": "alice@northwind.com",
    "name": "Alice Chen",
    "organization_name": "Northwind Analytics"
  }'
```

Response:

```json
{
  "registration": {
    "user": 7284619350142976,
    "organization": 7284619350143104,
    "access_token": "eyJhbGciOiJFZERTQSIs...",
    "refresh_token": "rt_7c9d3e2f1a8b...",
    "token_type": "Bearer"
  }
}
```

Save the `access_token` for authenticated requests. The server also sets `inferadb_access` and `inferadb_refresh` cookies.

For the rest of this tutorial, store the token and IDs:

```bash
export TOKEN="eyJhbGciOiJFZERTQSIs..."
export ORG=7284619350143104
```

## Step 3: Create a vault

Vaults are Ledger-managed Raft clusters that store your data. Creating a vault requires no request body:

```bash
curl -s -X POST http://localhost:9090/control/v1/organizations/$ORG/vaults \
  -H "Authorization: Bearer $TOKEN"
```

Response (HTTP 201):

```json
{
  "vault": {
    "organization": 7284619350143104,
    "slug": 7284619350143232,
    "height": 0,
    "status": "active"
  }
}
```

Save the vault slug:

```bash
export VAULT=7284619350143232
```

## Step 4: Create a client

Clients represent applications that access vaults. You need a client before generating vault tokens:

```bash
curl -s -X POST http://localhost:9090/control/v1/organizations/$ORG/clients \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "Northwind API",
    "description": "Production backend service for Northwind Analytics"
  }'
```

Response (HTTP 201):

```json
{
  "client": {
    "slug": 7284619350143360,
    "name": "Northwind API",
    "description": "Production backend service for Northwind Analytics",
    "enabled": true,
    "created_at": "2026-04-06T10:05:00+00:00"
  }
}
```

Save the client slug:

```bash
export CLIENT=7284619350143360
```

## Step 5: Generate a vault token

Vault tokens are JWTs that authorize requests to the InferaDB Engine. They are scoped to a vault and an app (client):

```bash
curl -s -X POST http://localhost:9090/control/v1/organizations/$ORG/vaults/$VAULT/tokens \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "app": '"$CLIENT"',
    "scopes": ["vault:read", "vault:write"]
  }'
```

Response (HTTP 201):

```json
{
  "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "rt_vault_3f8a2c1d9e7b...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

Use this `access_token` to authenticate requests to the InferaDB Engine.

## Core concepts

### Authentication model

InferaDB Control uses a two-token model:

- **Access token**: Short-lived JWT (15 minutes). Send as `Authorization: Bearer <token>` or via the `inferadb_access` cookie.
- **Refresh token**: Long-lived opaque token (30 days for web sessions). Use it to obtain new token pairs via `POST /control/v1/auth/refresh`.

### Resource hierarchy

```
User
  -> Organization (up to 10 per user)
       -> Vault (Raft cluster)
       -> Client (app)
            -> Certificate (for machine-to-machine auth)
       -> Team
            -> Team Member
       -> Invitation
```

### Pagination

All list endpoints use cursor-based pagination with `page_size` (default 50, max 100) and `page_token` query parameters. When more results exist, the response includes a `next_page_token` field.

### Error responses

All errors follow a consistent format:

```json
{
  "error": "VALIDATION_ERROR",
  "message": "name must be between 1 and 128 characters"
}
```

| HTTP Status | Error Code | Meaning |
|---|---|---|
| 400 | `VALIDATION_ERROR` | Invalid request payload |
| 401 | `AUTHENTICATION_ERROR` | Missing or invalid credentials |
| 403 | `AUTHORIZATION_ERROR` | Insufficient permissions |
| 404 | `NOT_FOUND` | Resource does not exist |
| 409 | `ALREADY_EXISTS` | Resource conflict |
| 429 | `RATE_LIMIT_EXCEEDED` | Too many requests |

### Rate limits

- Auth endpoints (login, verify, refresh): 100 requests/hour per IP
- Registration endpoint: 5 requests/day per IP

## Troubleshooting

### Port already in use

```
Address already in use (os error 48)
```

Change the port: `--listen 127.0.0.1:8080` or find the conflicting process: `lsof -i :9090`.

### 401 Unauthorized on every request

Access tokens expire after 15 minutes. Refresh the token:

```bash
curl -s -X POST http://localhost:9090/control/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "rt_7c9d3e2f1a8b..."}'
```

### Verification code not received

In dev mode without SMTP, the code appears in server logs. For production, configure SMTP with `--email-host`, `--email-port`, `--email-username`, and `--email-password`.

## Next steps

- [API Examples](examples.md): Complete request/response examples for every workflow
- [Configuration Guide](guides/configuration.md): CLI flags, environment variables, and deployment profiles
