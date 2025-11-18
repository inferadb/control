# Authentication Flow

## Overview

The **Management API** acts as the central authentication orchestrator for the entire InferaDB system. This architecture allows the **Server API** to focus exclusively on authorization policy enforcement and decision evaluation, while delegating all identity and authentication concerns to the Management API.

## Two-Token Architecture

InferaDB uses a **two-token system** to maintain clean separation of concerns:

1. **Session Tokens** - Used for Management API operations
   - Identity and account management
   - Organization and vault administration
   - User profile and settings
   - Authentication method management

2. **Vault-Scoped JWTs** - Used for Server API operations
   - Policy evaluation requests
   - Relationship graph queries
   - Authorization decisions
   - Fine-grained access control

This separation ensures that authentication (identity) and authorization (policy) remain distinct concerns handled by their respective services.

## Complete Authentication Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                          CLIENT APPLICATION                         │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  │ 1. Login Request
                                  │    (email/password, passkey, OAuth, etc.)
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         MANAGEMENT API                              │
│                    (Authentication Orchestrator)                    │
├─────────────────────────────────────────────────────────────────────┤
│  2. Validate Credentials                                            │
│  3. Create Session (Twitter Snowflake ID)                           │
│  4. Issue Session Token + Refresh Token                             │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  │ 5. Return Tokens
                                  │    {
                                  │      "session_token": "...",
                                  │      "refresh_token": "..."
                                  │    }
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                          CLIENT APPLICATION                         │
│                    (Stores session credentials)                     │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  │ 6. Request Vault Access
                                  │    Authorization: Bearer <session_token>
                                  │    POST /v1/vaults/{vault_id}/tokens
                                  │    { "role": "VAULT_ROLE_WRITER" }
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         MANAGEMENT API                              │
├─────────────────────────────────────────────────────────────────────┤
│  7. Validate Session Token                                          │
│  8. Check User Permissions for Vault                                │
│  9. Generate Vault-Scoped JWT (signed with Ed25519)                 │
│ 10. Issue Vault Access Token + Vault Refresh Token                  │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  │ 11. Return Vault Token
                                  │     {
                                  │       "access_token": "<jwt>",
                                  │       "refresh_token": "...",
                                  │       "token_type": "Bearer",
                                  │       "expires_in": 3600,
                                  │       "vault_id": "...",
                                  │       "vault_role": "VAULT_ROLE_WRITER"
                                  │     }
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                          CLIENT APPLICATION                         │
│                   (Stores vault access token)                       │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  │ 12. Authorization Request
                                  │     Authorization: Bearer <vault_jwt>
                                  │     POST /check
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                           SERVER API                                │
│                  (Authorization Policy Engine)                      │
├─────────────────────────────────────────────────────────────────────┤
│ 13. Validate JWT Signature (using JWKS from Management API)         │
│ 14. Verify Claims (aud, exp, scope, vault_role)                     │
│ 15. Execute Policy Evaluation                                       │
│ 16. Return Authorization Decision                                   │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  │ 17. Authorization Result
                                  │     { "allowed": true/false }
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                          CLIENT APPLICATION                         │
└─────────────────────────────────────────────────────────────────────┘
```

## JWT Claims Structure

Vault-scoped JWTs issued by the Management API contain the following claims:

```json
{
  "iss": "org:<organization_id>",
  "sub": "org:<organization_id>",
  "aud": "https://server.inferadb.com",
  "exp": 1234567890,
  "iat": 1234567800,
  "jti": "<unique_id>",
  "scope": "vault:<vault_id>",
  "vault_role": "VAULT_ROLE_WRITER"
}
```

### Claim Descriptions

- **iss** (Issuer): The organization that issued the token
- **sub** (Subject): The organization making the request
- **aud** (Audience): Target service (Server API)
- **exp** (Expiration): Unix timestamp when token expires
- **iat** (Issued At): Unix timestamp when token was created
- **jti** (JWT ID): Unique identifier for this token
- **scope**: Vault-specific scope limiting token usage
- **vault_role**: Permission level (READER, WRITER, MANAGER, ADMIN)

## Vault Token Response Format

When a client requests a vault access token, the Management API returns:

```json
{
  "access_token": "<jwt>",
  "refresh_token": "<cryptographic_token>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_expires_in": 86400,
  "vault_id": "<snowflake_id>",
  "vault_role": "VAULT_ROLE_WRITER"
}
```

## Refresh Token Flow

Vault access tokens expire after a short duration (typically 1 hour). Clients can use refresh tokens to obtain new access tokens without re-authenticating:

```
CLIENT                          MANAGEMENT API
  │
  │ POST /v1/vaults/{vault_id}/tokens/refresh
  │ { "refresh_token": "..." }
  ├──────────────────────────────────────────────────>
  │                                                     │
  │                                          Validate Refresh Token
  │                                          Check if Single-Use Token
  │                                          Mark Token as Used
  │                                          Generate New JWT
  │                                          Issue New Refresh Token
  │                                                     │
  │ {                                                   │
  │   "access_token": "<new_jwt>",                      │
  │   "refresh_token": "<new_refresh_token>",           │
  │   "token_type": "Bearer",                           │
  │   "expires_in": 3600                                │
  │ }                                                   │
  <──────────────────────────────────────────────────────┤
  │
```

### Refresh Token Security Properties

1. **Single-Use**: Each refresh token can only be used once
2. **Automatic Rotation**: New refresh token issued with each refresh
3. **Replay Detection**: Reused refresh tokens trigger security alerts
4. **Expiration**: Refresh tokens expire after extended period (e.g., 24 hours)
5. **Token Binding**: Bound to specific authentication context

## Authentication Methods

The Management API supports multiple authentication methods:

### 1. Password Authentication

- Traditional email/password login
- Password hashing with modern algorithms (Argon2, bcrypt)
- Rate limiting and brute-force protection

### 2. Passkey Authentication (WebAuthn/FIDO2)

- Hardware-backed cryptographic authentication
- Phishing-resistant
- Platform authenticators (TouchID, Windows Hello) and roaming authenticators (YubiKey)

### 3. CLI OAuth Flow

- OAuth 2.0 with PKCE (Proof Key for Code Exchange)
- Designed for headless/CLI environments
- Browser-based authorization with device code flow

### 4. Client Assertion (Recommended for Backend Services)

- **OAuth 2.0 JWT Bearer** (RFC 7523) for service-to-service authentication
- Cryptographic proof of identity using public key cryptography
- No shared secrets or long-lived credentials to store
- Self-signed JWT assertions prove client identity
- Each assertion is short-lived and unique
- Key rotation without downtime

#### Client Assertion Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                  ONE-TIME SETUP (Developer Portal)               │
├─────────────────────────────────────────────────────────────────┤
│ 1. Create Client in Management API                              │
│    - Specify name, organization, vault permissions              │
│                                                                  │
│ 2. Management API generates:                                    │
│    - Client ID (e.g., "client_abc123xyz")                       │
│    - Ed25519 key pair                                            │
│                                                                  │
│ 3. Developer downloads private key (PEM/JWK)                    │
│    - Management API stores public key                            │
│    - Private key shown only once                                 │
│                                                                  │
│ 4. Developer configures backend app:                            │
│    - INFERADB_CLIENT_ID=client_abc123xyz                         │
│    - INFERADB_PRIVATE_KEY=<pem_contents>                         │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                  RUNTIME (Every Token Request)                   │
├─────────────────────────────────────────────────────────────────┤
│ BACKEND APP                                                      │
│   1. Create client assertion JWT:                               │
│      {                                                           │
│        "iss": "client_abc123xyz",         // Client ID           │
│        "sub": "client_abc123xyz",         // Client ID           │
│        "aud": "https://management.inferadb.com/v1/token",        │
│        "exp": <now + 60 seconds>,         // Short-lived         │
│        "iat": <now>,                                             │
│        "jti": "<random_unique_id>"        // Prevents replay     │
│      }                                                           │
│                                                                  │
│   2. Sign assertion with private key (Ed25519)                   │
│                                                                  │
│   3. POST /v1/token:                                             │
│      {                                                           │
│        "grant_type": "client_credentials",                       │
│        "client_assertion_type":                                  │
│          "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",│
│        "client_assertion": "<signed_jwt>",                       │
│        "scope": "vault:vault_123:WRITER"  // Requested scope     │
│      }                                                           │
│                                                                  │
│ ──────────────────────────────────────────────────────────────► │
│                                                                  │
│ MANAGEMENT API                                                   │
│   4. Parse client_assertion JWT                                  │
│   5. Lookup Client by iss/sub claim                              │
│   6. Verify signature using stored public key                    │
│   7. Validate claims:                                            │
│      - aud matches token endpoint                                │
│      - exp not expired (< 60 seconds old)                        │
│      - jti not previously used (replay protection)               │
│   8. Check Client has permission for requested vault/role        │
│   9. Generate vault-scoped JWT                                   │
│  10. Return response:                                            │
│      {                                                           │
│        "access_token": "<vault_jwt>",                            │
│        "token_type": "Bearer",                                   │
│        "expires_in": 3600,                                       │
│        "scope": "vault:vault_123:WRITER"                         │
│      }                                                           │
│                                                                  │
│ ◄────────────────────────────────────────────────────────────── │
│                                                                  │
│ BACKEND APP                                                      │
│  11. Cache vault JWT until expiration (~1 hour)                  │
│  12. Use vault JWT for Server API requests                       │
│  13. When expired, repeat steps 1-10                             │
└─────────────────────────────────────────────────────────────────┘
```

#### Client Assertion Benefits

1. **No Credential Storage** - Backend apps only store their own private key (which they control)
2. **Cryptographic Proof** - Signed JWTs prove identity without shared secrets
3. **Short-Lived Assertions** - Each assertion expires in 60 seconds, limiting attack window
4. **Replay Protection** - JTI (JWT ID) prevents assertion reuse
5. **Key Rotation** - Update public key in Management API without app downtime
6. **Audit Trail** - Every token request is signed and traceable
7. **Standards-Based** - OAuth 2.0 RFC 7523 (widely supported)
8. **Better Developer Experience** - No password/API key management

#### Client Assertion Security

- **Private Key Protection**: Store private keys in secure vaults (HashiCorp Vault, AWS Secrets Manager, etc.)
- **Key Algorithm**: Ed25519 for fast signing and small signatures (64 bytes)
- **Assertion Lifetime**: Maximum 60 seconds to limit replay attack window
- **JTI Tracking**: Management API maintains short-term cache of used JTIs
- **Rate Limiting**: Per-client rate limits on token endpoint
- **Key Revocation**: Instantly revoke client by deleting public key

### 5. Single-Page Applications (SPAs)

**Important**: InferaDB is an **authorization service**, not an identity provider. Your application's users authenticate with YOUR auth system (Auth0, Clerk, Firebase, etc.), not with InferaDB.

#### Correct SPA Architecture

```text
END USER (authenticated with your auth)
    │
    │ Your auth JWT
    ▼
SPA (React/Vue/etc.)
    │
    │ API call with user token
    ▼
YOUR BACKEND
    │
    │ Validates user
    │ Uses Client Assertion to get vault token
    │ Checks InferaDB permissions
    ▼
INFERADB (Management + Server APIs)
```

**Flow**:

1. User authenticates with YOUR auth system (Auth0, Clerk, etc.)
2. SPA receives JWT from YOUR auth system
3. SPA calls YOUR backend with user's JWT
4. YOUR backend validates user's JWT
5. YOUR backend uses **Client Assertion** to get InferaDB vault token
6. YOUR backend calls InferaDB Server API to check permissions
7. YOUR backend returns authorization decision to SPA
8. SPA shows/hides features based on permissions

**Key Points**:

- End users NEVER interact with InferaDB directly
- InferaDB is completely invisible to end users
- Your backend maps user identities (email, user ID, etc.) to InferaDB subjects
- Your backend uses Client Assertion (method #4 above) for InferaDB authentication
- Authorization is enforced by your backend based on InferaDB decisions

See [examples/spa-integration/CORRECT_SPA_ARCHITECTURE.md](../examples/spa-integration/CORRECT_SPA_ARCHITECTURE.md) for complete implementation.

**Alternative: JWT Token Exchange** - For truly serverless frontends where even serverless functions aren't desired, see [examples/spa-integration/TRULY_SERVERLESS_OPTIONS.md](../examples/spa-integration/TRULY_SERVERLESS_OPTIONS.md) for JWT token exchange pattern.

## Server API Token Validation

The Server API validates vault-scoped JWTs without making synchronous calls to the Management API:

1. **Fetch JWKS** (JSON Web Key Set) from Management API's `/.well-known/jwks.json` endpoint
2. **Cache JWKS** with appropriate TTL and refresh mechanism
3. **Verify JWT Signature** using Ed25519 public key from JWKS
4. **Validate Claims**:
   - `aud` matches Server API identifier
   - `exp` is in the future (token not expired)
   - `scope` matches requested vault
   - `vault_role` has sufficient permissions
5. **Execute Policy** with authenticated context

This stateless validation allows the Server API to operate independently while still trusting tokens issued by the Management API.

## Security Considerations

### Token Lifetimes

- **Session Tokens**: Long-lived (days to weeks)
- **Vault Access Tokens (JWT)**: Short-lived (minutes to hours)
- **Vault Refresh Tokens**: Medium-lived (hours to days)

### Cryptographic Signing

- Ed25519 signature algorithm for JWTs
- Fast verification performance
- Small signature size (64 bytes)
- Strong security guarantees

### Token Scoping

- Session tokens scope to user + organization
- Vault tokens scope to specific vault + role
- Prevents privilege escalation across vaults
- Role-based access control (RBAC) enforcement

### Revocation

- Session tokens can be revoked, invalidating all derived vault tokens
- Individual vault tokens automatically expire
- Refresh tokens are single-use, preventing replay attacks
- API keys can be revoked independently

## Integration Points

### Management API Responsibilities

- User identity verification
- Session lifecycle management
- Vault permission checks
- JWT issuance and signing
- JWKS publication for Server API
- Refresh token rotation

### Server API Responsibilities

- JWT signature validation
- Claims verification
- Policy evaluation
- Authorization decisions
- Relationship graph queries

This clean separation allows each service to focus on its core competency while maintaining strong security guarantees across the system.
