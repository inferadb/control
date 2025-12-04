# Code Examples

This document provides practical code examples for common workflows using the InferaDB Management API.

> **Note**: Values like `{org_id}`, `{vault_id}`, and numeric IDs (e.g., `111222333`, `777888999`)
> are placeholders. Replace them with actual IDs from your API responses.

## Table of Contents

- [User Registration](#user-registration)
- [Organization Setup](#organization-setup)
- [Vault Management](#vault-management)
- [Client Credentials](#client-credentials)
- [Token Generation](#token-generation)
- [Team Management](#team-management)

## User Registration

### Register a New User

```bash
curl -X POST http://localhost:3000/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "password": "SecurePass123!",
    "name": "Alice Smith"
  }'
```

**Response:**

```json
{
  "user": {
    "id": "123456789",
    "name": "Alice Smith",
    "created_at": "2025-01-15T10:30:00Z",
    "tos_accepted_at": null
  },
  "organization": {
    "id": "987654321",
    "name": "Alice Smith's Org",
    "tier": "TIER_DEV_V1",
    "created_at": "2025-01-15T10:30:00Z",
    "role": "owner"
  }
}
```

**Note:** Session cookie `infera_session` is automatically set.

### Login

```bash
curl -X POST http://localhost:3000/v1/auth/login/password \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{
    "email": "alice@example.com",
    "password": "SecurePass123!"
  }'
```

**Response:**

```json
{
  "user": {
    "id": "123456789",
    "name": "Alice Smith",
    "created_at": "2025-01-15T10:30:00Z",
    "tos_accepted_at": "2025-01-15T10:35:00Z"
  },
  "organizations": [
    {
      "id": "987654321",
      "name": "Alice Smith's Org",
      "tier": "TIER_DEV_V1",
      "created_at": "2025-01-15T10:30:00Z",
      "role": "owner"
    }
  ]
}
```

### Verify Email

```bash
curl -X POST http://localhost:3000/v1/auth/verify-email \
  -H "Content-Type: application/json" \
  -d '{
    "token": "abc123def456"
  }'
```

## Organization Setup

### Create Additional Organization

```bash
curl -X POST http://localhost:3000/v1/organizations \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{
    "name": "ACME Corporation",
    "tier": "TIER_PRO_V1"
  }'
```

**Response:**

```json
{
  "organization": {
    "id": "111222333",
    "name": "ACME Corporation",
    "tier": "TIER_PRO_V1",
    "created_at": "2025-01-15T11:00:00Z",
    "role": "owner"
  }
}
```

### Invite Member to Organization

```bash
curl -X POST http://localhost:3000/v1/organizations/111222333/invitations \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{
    "email": "bob@example.com",
    "role": "admin"
  }'
```

**Response:**

```json
{
  "invitation": {
    "id": "444555666",
    "organization_id": "111222333",
    "email": "bob@example.com",
    "role": "admin",
    "token": "inv_xyz789abc",
    "expires_at": "2025-01-22T11:00:00Z",
    "created_at": "2025-01-15T11:00:00Z"
  }
}
```

### Accept Invitation (as Bob)

```bash
# Bob registers/logs in first
curl -X POST http://localhost:3000/v1/auth/register \
  -H "Content-Type: application/json" \
  -c bob_cookies.txt \
  -d '{
    "email": "bob@example.com",
    "password": "BobSecure456!",
    "name": "Bob Jones"
  }'

# Bob accepts invitation
curl -X POST http://localhost:3000/v1/organizations/invitations/accept \
  -H "Content-Type: application/json" \
  -b bob_cookies.txt \
  -d '{
    "token": "inv_xyz789abc"
  }'
```

## Vault Management

### Create a Vault

```bash
curl -X POST http://localhost:3000/v1/organizations/111222333/vaults \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{
    "name": "Production Policies"
  }'
```

**Response:**

```json
{
  "vault": {
    "id": "777888999",
    "organization_id": "111222333",
    "name": "Production Policies",
    "status": "synced",
    "created_at": "2025-01-15T11:30:00Z",
    "updated_at": "2025-01-15T11:30:00Z"
  }
}
```

### Grant User Access to Vault

```bash
curl -X POST http://localhost:3000/v1/organizations/111222333/vaults/777888999/user-grants \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{
    "user_id": "555666777",
    "role": "WRITER"
  }'
```

**Response:**

```json
{
  "grant": {
    "id": "888999000",
    "vault_id": "777888999",
    "user_id": "555666777",
    "role": "WRITER",
    "granted_by": "123456789",
    "created_at": "2025-01-15T11:35:00Z"
  }
}
```

### List Vaults

```bash
curl -X GET "http://localhost:3000/v1/organizations/111222333/vaults?limit=10&offset=0" \
  -H "Content-Type: application/json" \
  -b cookies.txt
```

**Response:**

```json
{
  "vaults": [
    {
      "id": "777888999",
      "organization_id": "111222333",
      "name": "Production Policies",
      "status": "synced",
      "created_at": "2025-01-15T11:30:00Z",
      "updated_at": "2025-01-15T11:30:00Z"
    }
  ],
  "pagination": {
    "total": 1,
    "count": 1,
    "offset": 0,
    "limit": 10
  }
}
```

## Client Credentials

### Create a Client (Backend Service)

```bash
curl -X POST http://localhost:3000/v1/organizations/111222333/clients \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{
    "name": "Backend API Service"
  }'
```

**Response:**

```json
{
  "client": {
    "id": "123123123",
    "organization_id": "111222333",
    "name": "Backend API Service",
    "is_active": true,
    "created_at": "2025-01-15T12:00:00Z"
  }
}
```

### Generate Client Certificate

```bash
curl -X POST http://localhost:3000/v1/organizations/111222333/clients/123123123/certificates \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{
    "name": "Production Certificate"
  }'
```

**Response:**

```json
{
  "certificate": {
    "id": "456456456",
    "client_id": "123123123",
    "organization_id": "111222333",
    "kid": "cert_prod_20250115",
    "public_key": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA...\n-----END PUBLIC KEY-----",
    "name": "Production Certificate",
    "is_active": true,
    "last_used_at": null,
    "created_at": "2025-01-15T12:05:00Z"
  },
  "private_key_pem": "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIE...\n-----END PRIVATE KEY-----"
}
```

**⚠️ IMPORTANT:** Save the `private_key_pem` securely. It cannot be retrieved again.

## Token Generation

### Generate Vault Token (User Session)

```bash
curl -X POST http://localhost:3000/v1/organizations/111222333/vaults/777888999/tokens \
  -H "Content-Type: application/json" \
  -b cookies.txt
```

**Response:**

```json
{
  "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6ImNlcnRfcHJvZF8yMDI1MDExNSJ9...",
  "refresh_token": "rt_abc123def456",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "inferadb.check inferadb.write inferadb.read"
}
```

### Refresh Access Token

```bash
curl -X POST http://localhost:3000/v1/organizations/111222333/vaults/777888999/tokens/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "rt_abc123def456"
  }'
```

**Response:**

```json
{
  "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6ImNlcnRfcHJvZF8yMDI1MDExNSJ9...",
  "refresh_token": "rt_xyz789ghi012",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "inferadb.check inferadb.write inferadb.read"
}
```

### Use Token with InferaDB Server

```bash
curl -X POST http://localhost:4000/v1/evaluate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6ImNlcnRfcHJvZF8yMDI1MDExNSJ9..." \
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
curl -X POST http://localhost:3000/v1/organizations/111222333/teams \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{
    "name": "Engineering"
  }'
```

**Response:**

```json
{
  "team": {
    "id": "321321321",
    "organization_id": "111222333",
    "name": "Engineering",
    "created_at": "2025-01-15T13:00:00Z"
  }
}
```

### Add Member to Team

```bash
curl -X POST http://localhost:3000/v1/organizations/111222333/teams/321321321/members \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{
    "user_id": "555666777",
    "is_manager": false
  }'
```

**Response:**

```json
{
  "member": {
    "id": "654654654",
    "team_id": "321321321",
    "user_id": "555666777",
    "is_manager": false,
    "created_at": "2025-01-15T13:05:00Z"
  }
}
```

### Grant Team Access to Vault

```bash
curl -X POST http://localhost:3000/v1/organizations/111222333/vaults/777888999/team-grants \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{
    "team_id": "321321321",
    "role": "READER"
  }'
```

**Response:**

```json
{
  "grant": {
    "id": "789789789",
    "vault_id": "777888999",
    "team_id": "321321321",
    "role": "READER",
    "granted_by": "123456789",
    "created_at": "2025-01-15T13:10:00Z"
  }
}
```

## Complete Workflow Example

Here's a complete workflow showing user registration through token generation:

### Step 1: Register User

```bash
# Register Alice
curl -X POST http://localhost:3000/v1/auth/register \
  -H "Content-Type: application/json" \
  -c alice_cookies.txt \
  -d '{
    "email": "alice@acme.com",
    "password": "AliceSecure123!",
    "name": "Alice Johnson"
  }' | jq .

# Extract organization ID from response: "987654321"
```

### Step 2: Create Production Vault

```bash
curl -X POST http://localhost:3000/v1/organizations/987654321/vaults \
  -H "Content-Type: application/json" \
  -b alice_cookies.txt \
  -d '{
    "name": "Production Authorization Policies"
  }' | jq .

# Extract vault ID from response: "555555555"
```

### Step 3: Create Backend Client

```bash
curl -X POST http://localhost:3000/v1/organizations/987654321/clients \
  -H "Content-Type: application/json" \
  -b alice_cookies.txt \
  -d '{
    "name": "API Gateway"
  }' | jq .

# Extract client ID from response: "666666666"
```

### Step 4: Generate Client Certificate

```bash
curl -X POST http://localhost:3000/v1/organizations/987654321/clients/666666666/certificates \
  -H "Content-Type: application/json" \
  -b alice_cookies.txt \
  -d '{
    "name": "Production Cert 2025"
  }' | jq .

# IMPORTANT: Save private_key_pem from response to a secure location
# cat > api_gateway_private_key.pem <<EOF
# -----BEGIN PRIVATE KEY-----
# MC4CAQAwBQYDK2VwBCIEIE...
# -----END PRIVATE KEY-----
# EOF
```

### Step 5: Grant Client Access to Vault

The client automatically has access to vaults in its organization. To explicitly grant:

```bash
curl -X POST http://localhost:3000/v1/organizations/987654321/vaults/555555555/team-grants \
  -H "Content-Type: application/json" \
  -b alice_cookies.txt \
  -d '{
    "team_id": "default_team_id",
    "role": "ADMIN"
  }' | jq .
```

### Step 6: Generate Vault Token (as Alice)

```bash
curl -X POST http://localhost:3000/v1/organizations/987654321/vaults/555555555/tokens \
  -H "Content-Type: application/json" \
  -b alice_cookies.txt \
  -o token_response.json

# Extract access_token
cat token_response.json | jq -r '.access_token' > access_token.txt
```

### Step 7: Use Token with InferaDB Server

```bash
curl -X POST http://localhost:4000/v1/evaluate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $(cat access_token.txt)" \
  -d '{
    "subject": {
      "type": "user",
      "id": "user_alice"
    },
    "action": "read",
    "resource": {
      "type": "document",
      "id": "doc_confidential_123"
    }
  }' | jq .
```

## Environment Variables for Scripts

```bash
# Save these in .env file
export MGMT_API_URL="http://localhost:3000"
export SERVER_API_URL="http://localhost:4000"
export ADMIN_EMAIL="alice@acme.com"
export ADMIN_PASSWORD="AliceSecure123!"
export ORG_ID="987654321"
export VAULT_ID="555555555"
```

## Error Handling Examples

### Handling Authentication Errors

```bash
# Attempt login with wrong password
response=$(curl -s -w "\n%{http_code}" -X POST http://localhost:3000/v1/auth/login/password \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@acme.com",
    "password": "WrongPassword"
  }')

http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | sed '$d')

if [ "$http_code" -eq 401 ]; then
  echo "Authentication failed: $body"
elif [ "$http_code" -eq 200 ]; then
  echo "Login successful"
  echo "$body" | jq .
fi
```

### Handling Rate Limiting

```bash
# Check for rate limit response
response=$(curl -s -w "\n%{http_code}" -X POST http://localhost:3000/v1/auth/login/password \
  -H "Content-Type: application/json" \
  -d '{"email": "test@test.com", "password": "test"}')

http_code=$(echo "$response" | tail -n1)

if [ "$http_code" -eq 429 ]; then
  retry_after=$(echo "$response" | grep -i "retry-after" | cut -d: -f2 | tr -d ' \r')
  echo "Rate limited. Retry after $retry_after seconds"
  sleep "$retry_after"
  # Retry request...
fi
```

## Python SDK Example

> **Note**: This is conceptual example code to guide integration. InferaDB does not currently provide
> an official Python SDK. For production use, we recommend using the REST API directly with your
> preferred HTTP client library.

```python
import requests
from typing import Dict, Optional

class InferaManagementClient:
    def __init__(self, base_url: str = "http://localhost:3000"):
        self.base_url = base_url
        self.session = requests.Session()

    def register(self, email: str, password: str, name: str) -> Dict:
        """Register a new user"""
        response = self.session.post(
            f"{self.base_url}/v1/auth/register",
            json={"email": email, "password": password, "name": name}
        )
        response.raise_for_status()
        return response.json()

    def login(self, email: str, password: str) -> Dict:
        """Login and get session cookie"""
        response = self.session.post(
            f"{self.base_url}/v1/auth/login/password",
            json={"email": email, "password": password}
        )
        response.raise_for_status()
        return response.json()

    def create_vault(self, org_id: str, name: str) -> Dict:
        """Create a new vault"""
        response = self.session.post(
            f"{self.base_url}/v1/organizations/{org_id}/vaults",
            json={"name": name}
        )
        response.raise_for_status()
        return response.json()

    def generate_token(self, org_id: str, vault_id: str) -> Dict:
        """Generate vault access token"""
        response = self.session.post(
            f"{self.base_url}/v1/organizations/{org_id}/vaults/{vault_id}/tokens"
        )
        response.raise_for_status()
        return response.json()

# Usage
client = InferaManagementClient()

# Register and login
user_data = client.register(
    email="alice@acme.com",
    password="SecurePass123!",
    name="Alice"
)
org_id = user_data["organization"]["id"]

# Create vault
vault_data = client.create_vault(org_id, "Production Policies")
vault_id = vault_data["vault"]["id"]

# Generate token
token_data = client.generate_token(vault_id)
access_token = token_data["access_token"]

print(f"Access Token: {access_token}")
```

## Further Reading

- [API Reference](../OpenAPI.yaml): Complete API endpoint specifications
- [Architecture](architecture.md): System architecture and deployment
- [Data Flows](flows.md): Detailed data flow diagrams
