# API Examples

Complete request/response examples for InferaDB Control, organized by workflow.

## Why this matters

These examples show the full request-response cycle for every major workflow. Each curl command uses correct paths, headers, and JSON payloads matching the actual handler types. Replace slug values with those from your own API responses.

## Quickstart

```bash
# Start the server
./target/release/inferadb-control --dev-mode

# Authenticate (see "Authenticate and get a session" below)
# Then use the access token for all subsequent requests:
export TOKEN="eyJhbGciOiJFZERTQSIs..."
```

## Authenticate and get a session

InferaDB Control uses passwordless email authentication. The flow has three steps: initiate, verify, and (for new users) complete registration.

### Initiate email verification

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

You can optionally specify a data residency region:

```bash
curl -s -X POST http://localhost:9090/control/v1/auth/email/initiate \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@northwind.com",
    "region": "ie-east-dublin"
  }'
```

### Verify the email code

```bash
curl -s -X POST http://localhost:9090/control/v1/auth/email/verify \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@northwind.com",
    "code": "847291"
  }'
```

Response for an existing user (no TOTP):

```json
{
  "status": "authenticated",
  "access_token": "eyJhbGciOiJFZERTQSIs...",
  "refresh_token": "rt_7c9d3e2f1a8b...",
  "token_type": "Bearer"
}
```

Response for an existing user with TOTP enabled:

```json
{
  "status": "totp_required",
  "challenge_nonce": "dGhpcyBpcyBhIGJhc2U2NCBub25jZQ=="
}
```

Response for a new user:

```json
{
  "status": "registration_required",
  "onboarding_token": "obt_e8f4a2b1c9d7..."
}
```

### Complete registration (new users)

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

The `organization` field is `null` if no default organization was created.

### Verify TOTP (when prompted)

```bash
curl -s -X POST http://localhost:9090/control/v1/auth/totp/verify \
  -H "Content-Type: application/json" \
  -d '{
    "challenge_nonce": "dGhpcyBpcyBhIGJhc2U2NCBub25jZQ==",
    "code": "482910"
  }'
```

### Refresh a session token

The refresh token can come from the request body or the `inferadb_refresh` cookie:

```bash
curl -s -X POST http://localhost:9090/control/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "rt_7c9d3e2f1a8b..."
  }'
```

Response:

```json
{
  "access_token": "eyJhbGciOiJFZERTQSIs...",
  "refresh_token": "rt_4a2e8f1b3c9d...",
  "token_type": "Bearer"
}
```

The old refresh token is invalidated (rotate-on-use).

### Log out

```bash
curl -s -X POST http://localhost:9090/control/v1/auth/logout \
  -b cookies.txt
```

Response:

```json
{
  "message": "logged out"
}
```

### Revoke all sessions

Requires JWT authentication. Revokes every active session for the authenticated user:

```bash
curl -s -X POST http://localhost:9090/control/v1/auth/revoke-all \
  -H "Authorization: Bearer $TOKEN"
```

Response:

```json
{
  "revoked_count": 3
}
```

## Manage your profile

### Get your profile

```bash
curl -s http://localhost:9090/control/v1/users/me \
  -H "Authorization: Bearer $TOKEN"
```

Response:

```json
{
  "user": {
    "slug": 7284619350142976,
    "name": "Alice Chen",
    "status": "active",
    "role": "user",
    "created_at": "2026-04-06T10:00:00+00:00"
  }
}
```

### Update your display name

```bash
curl -s -X PATCH http://localhost:9090/control/v1/users/me \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "Alice M. Chen"
  }'
```

### Manage email addresses

List your emails:

```bash
curl -s http://localhost:9090/control/v1/users/emails \
  -H "Authorization: Bearer $TOKEN"
```

Response:

```json
{
  "emails": [
    {
      "slug": 7284619350143008,
      "email": "alice@northwind.com",
      "verified": true,
      "created_at": "2026-04-06T10:00:00+00:00",
      "verified_at": "2026-04-06T10:01:00+00:00"
    }
  ]
}
```

Add an email:

```bash
curl -s -X POST http://localhost:9090/control/v1/users/emails \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "email": "alice.chen@northwind.com"
  }'
```

Response:

```json
{
  "email": {
    "slug": 7284619350143040,
    "email": "alice.chen@northwind.com",
    "verified": false,
    "created_at": "2026-04-06T10:10:00+00:00",
    "verified_at": null
  },
  "message": "Email added. Please check your inbox for a verification link."
}
```

Verify an email with a token (from the verification link):

```bash
curl -s -X POST http://localhost:9090/control/v1/auth/verify-email \
  -H "Content-Type: application/json" \
  -d '{
    "token": "ev_3f8a2c1d9e7b4a6f..."
  }'
```

Response:

```json
{
  "message": "Email verified successfully",
  "verified": true
}
```

Delete an email:

```bash
curl -s -X DELETE http://localhost:9090/control/v1/users/emails/7284619350143040 \
  -H "Authorization: Bearer $TOKEN"
```

## Manage your organization

### Create an organization

Each user can create up to 10 organizations:

```bash
curl -s -X POST http://localhost:9090/control/v1/organizations \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "Northwind Analytics"
  }'
```

Response (HTTP 201):

```json
{
  "organization": {
    "slug": 7284619350143104,
    "name": "Northwind Analytics",
    "region": "us-east-va",
    "status": "active",
    "tier": "free"
  }
}
```

### List organizations

```bash
curl -s http://localhost:9090/control/v1/organizations \
  -H "Authorization: Bearer $TOKEN"
```

Response:

```json
{
  "organizations": [
    {
      "slug": 7284619350143104,
      "name": "Northwind Analytics",
      "region": "us-east-va",
      "status": "active",
      "tier": "free"
    }
  ]
}
```

Paginate with `page_size` and `page_token`:

```bash
curl -s "http://localhost:9090/control/v1/organizations?page_size=10" \
  -H "Authorization: Bearer $TOKEN"
```

### Get organization details

```bash
curl -s http://localhost:9090/control/v1/organizations/7284619350143104 \
  -H "Authorization: Bearer $TOKEN"
```

### Update an organization

```bash
curl -s -X PATCH http://localhost:9090/control/v1/organizations/7284619350143104 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "Northwind Corp"
  }'
```

### Delete an organization

```bash
curl -s -X DELETE http://localhost:9090/control/v1/organizations/7284619350143104 \
  -H "Authorization: Bearer $TOKEN"
```

### Invite a member

Invitations expire after 7 days. The `role` field accepts `"admin"` or `"member"`:

```bash
curl -s -X POST http://localhost:9090/control/v1/organizations/7284619350143104/invitations \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "email": "bob.martinez@northwind.com",
    "role": "admin"
  }'
```

Response (HTTP 201):

```json
{
  "invitation": {
    "slug": 7284619350143136,
    "organization": 7284619350143104,
    "inviter": 7284619350142976,
    "invitee_email": "bob.martinez@northwind.com",
    "role": "admin",
    "status": "pending",
    "created_at": "2026-04-06T10:15:00+00:00",
    "expires_at": "2026-04-13T10:15:00+00:00",
    "token": "inv_8b3f2a1e9c7d..."
  }
}
```

### List invitations (admin view)

```bash
curl -s http://localhost:9090/control/v1/organizations/7284619350143104/invitations \
  -H "Authorization: Bearer $TOKEN"
```

### View your received invitations

```bash
curl -s http://localhost:9090/control/v1/users/me/invitations \
  -H "Authorization: Bearer $TOKEN"
```

Response:

```json
{
  "invitations": [
    {
      "slug": 7284619350143136,
      "organization": 7284619350143104,
      "organization_name": "Northwind Analytics",
      "role": "admin",
      "status": "pending",
      "created_at": "2026-04-06T10:15:00+00:00",
      "expires_at": "2026-04-13T10:15:00+00:00"
    }
  ]
}
```

### Accept or decline an invitation

```bash
# Accept
curl -s -X POST http://localhost:9090/control/v1/users/me/invitations/7284619350143136/accept \
  -H "Authorization: Bearer $TOKEN"

# Decline
curl -s -X POST http://localhost:9090/control/v1/users/me/invitations/7284619350143136/decline \
  -H "Authorization: Bearer $TOKEN"
```

### Manage members

List members:

```bash
curl -s http://localhost:9090/control/v1/organizations/7284619350143104/members \
  -H "Authorization: Bearer $TOKEN"
```

Response:

```json
{
  "members": [
    {
      "user": 7284619350142976,
      "role": "admin",
      "joined_at": "2026-04-06T10:00:00+00:00"
    }
  ]
}
```

Update a member's role:

```bash
curl -s -X PATCH http://localhost:9090/control/v1/organizations/7284619350143104/members/7284619350143168 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "role": "member"
  }'
```

Remove a member:

```bash
curl -s -X DELETE http://localhost:9090/control/v1/organizations/7284619350143104/members/7284619350143168 \
  -H "Authorization: Bearer $TOKEN"
```

Leave an organization:

```bash
curl -s -X DELETE http://localhost:9090/control/v1/organizations/7284619350143104/members/me \
  -H "Authorization: Bearer $TOKEN"
```

## Set up a vault

### Create a vault

```bash
curl -s -X POST http://localhost:9090/control/v1/organizations/7284619350143104/vaults \
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

### List vaults

```bash
curl -s "http://localhost:9090/control/v1/organizations/7284619350143104/vaults?page_size=10" \
  -H "Authorization: Bearer $TOKEN"
```

Response:

```json
{
  "vaults": [
    {
      "organization": 7284619350143104,
      "slug": 7284619350143232,
      "height": 42,
      "status": "active",
      "nodes": ["node-1", "node-2", "node-3"],
      "leader": "node-1"
    }
  ]
}
```

The `nodes` and `leader` fields appear only when the Raft cluster has been initialized.

### Get a vault

```bash
curl -s http://localhost:9090/control/v1/organizations/7284619350143104/vaults/7284619350143232 \
  -H "Authorization: Bearer $TOKEN"
```

### Delete a vault

```bash
curl -s -X DELETE http://localhost:9090/control/v1/organizations/7284619350143104/vaults/7284619350143232 \
  -H "Authorization: Bearer $TOKEN"
```

### Deploy a schema

Schemas define the data model for a vault. The definition is an arbitrary JSON object:

```bash
curl -s -X POST http://localhost:9090/control/v1/organizations/7284619350143104/vaults/7284619350143232/schemas \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "definition": {
      "tables": {
        "users": {
          "columns": {
            "id": {"type": "string", "primary": true},
            "email": {"type": "string", "unique": true},
            "role": {"type": "string"}
          }
        }
      }
    },
    "description": "Initial user schema"
  }'
```

Response (HTTP 201):

```json
{
  "version": 1,
  "status": "deployed"
}
```

### List schema versions

```bash
curl -s http://localhost:9090/control/v1/organizations/7284619350143104/vaults/7284619350143232/schemas \
  -H "Authorization: Bearer $TOKEN"
```

Response:

```json
{
  "schemas": [
    {
      "version": 1,
      "has_definition": true,
      "is_active": true
    }
  ]
}
```

### Get a specific schema version

```bash
curl -s http://localhost:9090/control/v1/organizations/7284619350143104/vaults/7284619350143232/schemas/1 \
  -H "Authorization: Bearer $TOKEN"
```

### Diff two schema versions

```bash
curl -s "http://localhost:9090/control/v1/organizations/7284619350143104/vaults/7284619350143232/schemas/diff?from=1&to=2" \
  -H "Authorization: Bearer $TOKEN"
```

Response:

```json
{
  "from": 1,
  "to": 2,
  "changes": [
    {
      "field": "tables.users.columns.department",
      "change_type": "added"
    }
  ]
}
```

### Activate or rollback a schema

```bash
# Activate a specific version
curl -s -X POST http://localhost:9090/control/v1/organizations/7284619350143104/vaults/7284619350143232/schemas/1/activate \
  -H "Authorization: Bearer $TOKEN"

# Rollback to the previous version
curl -s -X POST http://localhost:9090/control/v1/organizations/7284619350143104/vaults/7284619350143232/schemas/rollback \
  -H "Authorization: Bearer $TOKEN"
```

## Generate and refresh vault tokens

### Generate a vault token (user session)

Vault tokens require an `app` (client) slug to scope the token:

```bash
curl -s -X POST http://localhost:9090/control/v1/organizations/7284619350143104/vaults/7284619350143232/tokens \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "app": 7284619350143360,
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

### Refresh a vault token

This is a public endpoint -- the refresh token authenticates the request:

```bash
curl -s -X POST http://localhost:9090/control/v1/tokens/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "rt_vault_3f8a2c1d9e7b..."
  }'
```

Response:

```json
{
  "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "rt_vault_8d4e2f1a3b7c...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### Revoke vault tokens for a client

```bash
curl -s -X DELETE http://localhost:9090/control/v1/organizations/7284619350143104/vaults/7284619350143232/tokens \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "app": 7284619350143360
  }'
```

Response:

```json
{
  "revoked_count": 2
}
```

## Configure client assertion auth (machine-to-machine)

For backend services that authenticate without a user session, use the OAuth 2.0 JWT Bearer flow (RFC 7523).

### Create a client

```bash
curl -s -X POST http://localhost:9090/control/v1/organizations/7284619350143104/clients \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "Northwind Data Pipeline",
    "description": "Nightly ETL service for analytics data"
  }'
```

Response (HTTP 201):

```json
{
  "client": {
    "slug": 7284619350143360,
    "name": "Northwind Data Pipeline",
    "description": "Nightly ETL service for analytics data",
    "enabled": true,
    "created_at": "2026-04-06T10:20:00+00:00"
  }
}
```

### Create a certificate for the client

```bash
curl -s -X POST http://localhost:9090/control/v1/organizations/7284619350143104/clients/7284619350143360/certificates \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "Production Ed25519 Key",
    "expires_at": "2027-04-06T00:00:00Z"
  }'
```

Response (HTTP 201):

```json
{
  "certificate": {
    "slug": 7284619350143392,
    "name": "Production Ed25519 Key",
    "enabled": true,
    "expires_at": "2027-04-06T00:00:00+00:00",
    "created_at": "2026-04-06T10:21:00+00:00"
  },
  "private_key_pem": "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIE...\n-----END PRIVATE KEY-----\n"
}
```

**Store the `private_key_pem` securely.** It cannot be retrieved again.

### Authenticate with the client assertion

Sign a JWT with the Ed25519 private key, then exchange it for a vault token:

```bash
curl -s -X POST http://localhost:9090/control/v1/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "client_credentials",
    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    "client_assertion": "eyJhbGciOiJFZERTQSIs...",
    "organization": 7284619350143104,
    "vault": "7284619350143232",
    "scopes": ["vault:read", "vault:write"]
  }'
```

Response (HTTP 201):

```json
{
  "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "rt_machine_2c8a1f3d9e7b...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### Manage certificates

List certificates for a client:

```bash
curl -s http://localhost:9090/control/v1/organizations/7284619350143104/clients/7284619350143360/certificates \
  -H "Authorization: Bearer $TOKEN"
```

Get a specific certificate:

```bash
curl -s http://localhost:9090/control/v1/organizations/7284619350143104/clients/7284619350143360/certificates/7284619350143392 \
  -H "Authorization: Bearer $TOKEN"
```

Revoke a certificate:

```bash
curl -s -X DELETE http://localhost:9090/control/v1/organizations/7284619350143104/clients/7284619350143360/certificates/7284619350143392 \
  -H "Authorization: Bearer $TOKEN"
```

Rotate the client secret:

```bash
curl -s -X POST http://localhost:9090/control/v1/organizations/7284619350143104/clients/7284619350143360/secret/rotate \
  -H "Authorization: Bearer $TOKEN"
```

## Manage teams

### Create a team

```bash
curl -s -X POST http://localhost:9090/control/v1/organizations/7284619350143104/teams \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "Platform Engineering"
  }'
```

Response (HTTP 201):

```json
{
  "team": {
    "slug": 7284619350143488,
    "organization": 7284619350143104,
    "name": "Platform Engineering",
    "members": [],
    "created_at": "2026-04-06T10:30:00+00:00"
  }
}
```

### Add a member to the team

The `role` field accepts `"manager"` or `"member"` (default):

```bash
curl -s -X POST http://localhost:9090/control/v1/organizations/7284619350143104/teams/7284619350143488/members \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "user": 7284619350143168,
    "role": "manager"
  }'
```

### Update a team member's role

```bash
curl -s -X PATCH http://localhost:9090/control/v1/organizations/7284619350143104/teams/7284619350143488/members/7284619350143168 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "role": "member"
  }'
```

### Remove a team member

```bash
curl -s -X DELETE http://localhost:9090/control/v1/organizations/7284619350143104/teams/7284619350143488/members/7284619350143168 \
  -H "Authorization: Bearer $TOKEN"
```

### Delete a team

Optionally move members to another team before deletion:

```bash
curl -s -X DELETE http://localhost:9090/control/v1/organizations/7284619350143104/teams/7284619350143488 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "move_members_to": 7284619350143520
  }'
```

## View audit logs

```bash
curl -s http://localhost:9090/control/v1/organizations/7284619350143104/audit-logs \
  -H "Authorization: Bearer $TOKEN"
```

## Health and observability

These endpoints require no authentication:

```bash
# Liveness probe (always returns 200 if the process is running)
curl -s http://localhost:9090/livez

# Readiness probe (returns 200 when the server can accept traffic)
curl -s http://localhost:9090/readyz

# Startup probe
curl -s http://localhost:9090/startupz

# Health check (includes backend connectivity)
curl -s http://localhost:9090/healthz

# Prometheus metrics
curl -s http://localhost:9090/metrics
```

## Handle errors

### Authentication error (401)

```bash
curl -s -w "\nHTTP %{http_code}\n" http://localhost:9090/control/v1/organizations
```

```json
{
  "error": "AUTHENTICATION_ERROR",
  "message": "Authentication error: missing or invalid token"
}
HTTP 401
```

### Validation error (400)

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST http://localhost:9090/control/v1/organizations \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name": ""}'
```

```json
{
  "error": "VALIDATION_ERROR",
  "message": "Validation error: name must be between 1 and 128 characters"
}
HTTP 400
```

### Rate limit error (429)

Auth endpoints are rate-limited at 100 requests/hour per IP. Registration is limited to 5 requests/day per IP.

```json
{
  "error": "RATE_LIMIT_EXCEEDED",
  "message": "Rate limit exceeded: too many requests"
}
HTTP 429
```

### Not found error (404)

```json
{
  "error": "NOT_FOUND",
  "message": "Resource not found: organization 999"
}
HTTP 404
```

## Reference: shell variables

```bash
export CONTROL_URL="http://localhost:9090"
export TOKEN="eyJhbGciOiJFZERTQSIs..."
export ORG="7284619350143104"
export VAULT="7284619350143232"
export CLIENT="7284619350143360"
```
