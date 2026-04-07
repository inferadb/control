# Code Examples

This document provides practical code examples for common workflows using InferaDB Control.

> **Note**: Numeric values like `111222333`, `777888999` are placeholder slugs.
> Replace them with actual values from your API responses.

## Table of Contents

- [Authentication](#authentication)
- [Organization Setup](#organization-setup)
- [Vault Management](#vault-management)
- [Client Management](#client-management)
- [Token Generation](#token-generation)
- [Team Management](#team-management)

## Authentication

InferaDB Control uses a passwordless email verification flow. There are no username/password endpoints.

### Step 1: Initiate Email Verification

```bash
curl -X POST http://localhost:9090/control/v1/auth/email/initiate \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com"
  }'
```

**Response:**

```json
{
  "message": "verification code sent"
}
```

A 6-character verification code is sent to the email address (if SMTP is configured).

### Step 2: Verify Email Code

```bash
curl -X POST http://localhost:9090/control/v1/auth/email/verify \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "code": "123456"
  }'
```

**Response (existing user, no TOTP):**

```json
{
  "status": "authenticated",
  "access_token": "eyJhbGciOiJFZERTQSIs...",
  "refresh_token": "rt_abc123...",
  "token_type": "Bearer"
}
```

Session cookies `inferadb_access` and `inferadb_refresh` are also set automatically.

**Response (new user):**

```json
{
  "status": "registration_required",
  "onboarding_token": "obt_xyz789..."
}
```

**Response (existing user with TOTP):**

```json
{
  "status": "totp_required",
  "challenge_nonce": "base64-encoded-nonce"
}
```

### Step 3: Complete Registration (New Users Only)

```bash
curl -X POST http://localhost:9090/control/v1/auth/email/complete \
  -H "Content-Type: application/json" \
  -d '{
    "onboarding_token": "obt_xyz789...",
    "email": "alice@example.com",
    "name": "Alice Smith",
    "organization_name": "ACME Corporation"
  }'
```

**Response:**

```json
{
  "registration": {
    "user": 123456789,
    "organization": 987654321,
    "access_token": "eyJhbGciOiJFZERTQSIs...",
    "refresh_token": "rt_abc123...",
    "token_type": "Bearer"
  }
}
```

Session cookies `inferadb_access` and `inferadb_refresh` are set automatically.

### Verify Email Address

```bash
curl -X POST http://localhost:9090/control/v1/auth/verify-email \
  -H "Content-Type: application/json" \
  -d '{
    "token": "abc123def456"
  }'
```

### Refresh Session Token

```bash
curl -X POST http://localhost:9090/control/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{
    "refresh_token": "rt_abc123..."
  }'
```

**Response:**

```json
{
  "access_token": "eyJhbGciOiJFZERTQSIs...",
  "refresh_token": "rt_newtoken...",
  "token_type": "Bearer"
}
```

The refresh token can also be provided via the `inferadb_refresh` cookie instead of the request body.

### Logout

```bash
curl -X POST http://localhost:9090/control/v1/auth/logout \
  -b cookies.txt
```

**Response:**

```json
{
  "message": "logged out"
}
```

## Organization Setup

### Create an Organization

```bash
curl -X POST http://localhost:9090/control/v1/organizations \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGciOiJFZERTQSIs..." \
  -d '{
    "name": "ACME Corporation"
  }'
```

**Response:**

```json
{
  "organization": {
    "slug": 111222333,
    "name": "ACME Corporation",
    "region": "us-east-va",
    "status": "active",
    "tier": "free"
  }
}
```

### List Organizations

```bash
curl -X GET http://localhost:9090/control/v1/organizations \
  -H "Authorization: Bearer eyJhbGciOiJFZERTQSIs..."
```

**Response:**

```json
{
  "organizations": [
    {
      "slug": 111222333,
      "name": "ACME Corporation",
      "region": "us-east-va",
      "status": "active",
      "tier": "free"
    }
  ]
}
```

### Invite Member to Organization

```bash
curl -X POST http://localhost:9090/control/v1/organizations/111222333/invitations \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGciOiJFZERTQSIs..." \
  -d '{
    "email": "bob@example.com",
    "role": "admin"
  }'
```

**Response:**

```json
{
  "invitation": {
    "slug": 444555666,
    "organization": 111222333,
    "inviter": 123456789,
    "invitee_email": "bob@example.com",
    "role": "admin",
    "status": "pending",
    "created_at": "2025-01-15T11:00:00Z",
    "expires_at": "2025-01-22T11:00:00Z",
    "token": "inv_xyz789abc"
  }
}
```

### Accept Invitation

```bash
curl -X POST http://localhost:9090/control/v1/users/me/invitations/444555666/accept \
  -H "Authorization: Bearer eyJhbGciOiJFZERTQSIs..."
```

### Decline Invitation

```bash
curl -X POST http://localhost:9090/control/v1/users/me/invitations/444555666/decline \
  -H "Authorization: Bearer eyJhbGciOiJFZERTQSIs..."
```

## Vault Management

### Create a Vault

Vaults are Ledger-managed Raft clusters. Creation takes no request body.

```bash
curl -X POST http://localhost:9090/control/v1/organizations/111222333/vaults \
  -H "Authorization: Bearer eyJhbGciOiJFZERTQSIs..."
```

**Response:**

```json
{
  "vault": {
    "organization": 111222333,
    "slug": 777888999,
    "height": 0,
    "status": "active"
  }
}
```

### List Vaults

```bash
curl -X GET "http://localhost:9090/control/v1/organizations/111222333/vaults?page_size=10" \
  -H "Authorization: Bearer eyJhbGciOiJFZERTQSIs..."
```

**Response:**

```json
{
  "vaults": [
    {
      "organization": 111222333,
      "slug": 777888999,
      "height": 42,
      "status": "active"
    }
  ]
}
```

### Get a Vault

```bash
curl -X GET http://localhost:9090/control/v1/organizations/111222333/vaults/777888999 \
  -H "Authorization: Bearer eyJhbGciOiJFZERTQSIs..."
```

## Client Management

Clients in Control map to "apps" in Ledger.

### Create a Client

```bash
curl -X POST http://localhost:9090/control/v1/organizations/111222333/clients \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGciOiJFZERTQSIs..." \
  -d '{
    "name": "Backend API Service",
    "description": "Production backend service"
  }'
```

**Response:**

```json
{
  "client": {
    "slug": 123123123,
    "name": "Backend API Service",
    "description": "Production backend service",
    "enabled": true,
    "created_at": "2025-01-15T12:00:00Z"
  }
}
```

### Create a Client Certificate

```bash
curl -X POST http://localhost:9090/control/v1/organizations/111222333/clients/123123123/certificates \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGciOiJFZERTQSIs..." \
  -d '{
    "name": "Production Certificate",
    "expires_at": "2026-01-15T00:00:00Z"
  }'
```

**Important:** Save the private key from the response securely. It cannot be retrieved again.

## Token Generation

### Generate a Vault Token (User Session)

Requires an authenticated session and an `app` slug to scope the token.

```bash
curl -X POST http://localhost:9090/control/v1/organizations/111222333/vaults/777888999/tokens \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGciOiJFZERTQSIs..." \
  -d '{
    "app": 123123123,
    "scopes": ["vault:read", "vault:write"]
  }'
```

**Response:**

```json
{
  "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "rt_abc123def456",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### Refresh a Vault Token

```bash
curl -X POST http://localhost:9090/control/v1/tokens/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "rt_abc123def456"
  }'
```

**Response:**

```json
{
  "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "rt_xyz789ghi012",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### Client Assertion Authentication (Machine-to-Machine)

For machine clients using Ed25519 certificate authentication (OAuth 2.0 JWT Bearer, RFC 7523):

```bash
curl -X POST http://localhost:9090/control/v1/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "client_credentials",
    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    "client_assertion": "eyJhbGciOiJFZERTQSIs...",
    "organization": 111222333,
    "vault": "777888999",
    "scopes": ["vault:read", "vault:write"]
  }'
```

**Response:**

```json
{
  "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "rt_machine123...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### Use Token with InferaDB Engine

```bash
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9..." \
  -d '{
    "subject": {
      "type": "user",
      "id": "alice"
    },
    "action": "read",
    "resource": {
      "type": "document",
      "id": "doc_123"
    }
  }'
```

## Team Management

### Create a Team

```bash
curl -X POST http://localhost:9090/control/v1/organizations/111222333/teams \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGciOiJFZERTQSIs..." \
  -d '{
    "name": "Engineering"
  }'
```

### Add Member to Team

```bash
curl -X POST http://localhost:9090/control/v1/organizations/111222333/teams/321321321/members \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGciOiJFZERTQSIs..." \
  -d '{
    "user": 555666777,
    "role": "member"
  }'
```

The `role` field accepts `"manager"` or `"member"` (default).

### Update Team Member Role

```bash
curl -X PATCH http://localhost:9090/control/v1/organizations/111222333/teams/321321321/members/555666777 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGciOiJFZERTQSIs..." \
  -d '{
    "role": "manager"
  }'
```

## Error Handling Examples

### Handling Authentication Errors

```bash
# Attempt to access a protected endpoint without a token
response=$(curl -s -w "\n%{http_code}" -X GET http://localhost:9090/control/v1/organizations)

http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | sed '$d')

if [ "$http_code" -eq 401 ]; then
  echo "Authentication required: $body"
elif [ "$http_code" -eq 200 ]; then
  echo "Success"
  echo "$body" | jq .
fi
```

### Handling Rate Limiting

```bash
# Auth endpoints are rate-limited (100/hour per IP)
response=$(curl -s -w "\n%{http_code}" -X POST http://localhost:9090/control/v1/auth/email/initiate \
  -H "Content-Type: application/json" \
  -d '{"email": "test@test.com"}')

http_code=$(echo "$response" | tail -n1)

if [ "$http_code" -eq 429 ]; then
  echo "Rate limited. Wait before retrying."
fi
```

## Environment Variables for Scripts

```bash
export CONTROL_API_URL="http://localhost:9090"
export ENGINE_API_URL="http://localhost:8080"
export ORG_SLUG="111222333"
export VAULT_SLUG="777888999"
export APP_SLUG="123123123"
```

## Further Reading

- [API Reference](../openapi.yaml): Complete API endpoint specifications
- [Architecture](architecture.md): System architecture and deployment
- [Data Flows](flows.md): Detailed data flow diagrams
