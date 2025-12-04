# Authentication Flow

## Table of Contents

- [Overview](#overview)
- [Two-Token Architecture](#two-token-architecture)
- [Complete Authentication Flow](#complete-authentication-flow)
- [JWT Claims Structure](#jwt-claims-structure)
  - [Claim Descriptions](#claim-descriptions)
- [Vault Token Response Format](#vault-token-response-format)
- [Refresh Token Flow](#refresh-token-flow)
  - [Refresh Token Security Properties](#refresh-token-security-properties)
- [Authentication Methods](#authentication-methods)
  - [1. Password Authentication](#1-password-authentication)
  - [2. Passkey Authentication (WebAuthn/FIDO2)](#2-passkey-authentication-webauthnfido2)
  - [3. CLI OAuth Flow](#3-cli-oauth-flow)
  - [4. Client Assertion (Recommended for Backend Services)](#4-client-assertion-recommended-for-backend-services)
    - [Client Assertion Flow](#client-assertion-flow)
    - [Client Assertion Benefits](#client-assertion-benefits)
    - [Client Assertion Security](#client-assertion-security)
  - [5. Single-Page Applications (SPAs)](#5-single-page-applications-spas)
    - [Correct SPA Architecture](#correct-spa-architecture)
- [Server API Token Validation](#server-api-token-validation)
- [Security Considerations](#security-considerations)
  - [Token Lifetimes](#token-lifetimes)
  - [Cryptographic Signing](#cryptographic-signing)
  - [Token Scoping](#token-scoping)
  - [Revocation](#revocation)
- [Integration Points](#integration-points)
  - [Management API Responsibilities](#management-api-responsibilities)
  - [Server API Responsibilities](#server-api-responsibilities)

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

### Token Formats

**Session Tokens**:

- Format: Cryptographically secure random string (base64url-encoded)
- Length: 43 characters (256 bits of entropy)
- Example: `sess_7k9mxPqR2vN4wLtY8jFnEaGbUcH5ZdKs3iOoXpW1`
- Storage: Management API database with associated metadata (user_id, org_id, created_at, expires_at)
- Transmission: Bearer token in Authorization header
- Validation: Looked up in database on each use
- Renewal: "Sliding window" - `expires_at` updated on active Management API requests

**Vault-Scoped JWTs**:

- Format: Signed JSON Web Token (JWT) using Ed25519
- Structure: Header + Payload + Signature (see [JWT Claims Structure](#jwt-claims-structure))
- Example: `eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpc3MiOi...`
- Storage: Stateless (no database storage)
- Transmission: Bearer token in Authorization header
- Validation: Cryptographic signature verification using JWKS public keys
- Renewal: Cannot be renewed - must use refresh token to obtain new JWT

**Refresh Tokens**:

- Format: Cryptographically secure random string (base64url-encoded)
- Length: 43 characters (256 bits of entropy)
- Example: `vrt_9aB3cD4eF5gH6iJ7kL8mN0oP1qR2sT3uV4wX5yZ6`
- Storage: Management API database with single-use flag
- Transmission: In request body (not header) for refresh endpoint
- Validation: Looked up in database, marked as used, then invalidated
- Renewal: New refresh token issued with each successful refresh
- **Lifetime**:
  - User session-bound refresh tokens: 1 hour (3,600 seconds)
  - Client-bound refresh tokens: 7 days (604,800 seconds)

## Complete Authentication Flow

```mermaid
sequenceDiagram
    participant Client as Client Application
    participant MgmtAPI as Management API<br/>(Authentication Orchestrator)
    participant ServerAPI as Server API<br/>(Authorization Policy Engine)

    Note over Client: User initiates login
    Client->>MgmtAPI: 1. Login Request<br/>(email/password, passkey, OAuth, etc.)

    Note over MgmtAPI: 2. Validate Credentials<br/>3. Create Session (Snowflake ID)<br/>4. Issue Session + Refresh Tokens

    MgmtAPI-->>Client: 5. Return Tokens<br/>{session_token, refresh_token}

    Note over Client: Store session credentials

    Client->>MgmtAPI: 6. Request Vault Access<br/>POST /v1/organizations/{org_id}/vaults/{vault_id}/tokens<br/>Authorization: Bearer {session_token}<br/>{requested_role: "read"} (optional)

    Note over MgmtAPI: 7. Validate Session Token<br/>8. Check User Vault Permissions<br/>9. Determine Role (requested or default)<br/>10. Generate Vault JWT (Ed25519)<br/>11. Issue Vault Tokens

    MgmtAPI-->>Client: 12. Return Vault Token<br/>{access_token (JWT), refresh_token,<br/>expires_in: 300, vault_role}

    Note over Client: Store vault access token

    Client->>ServerAPI: 13. Authorization Request<br/>POST /check<br/>Authorization: Bearer {vault_jwt}

    Note over ServerAPI: 14. Validate JWT (JWKS)<br/>15. Verify Claims<br/>16. Execute Policy Evaluation

    ServerAPI-->>Client: 17. Authorization Result<br/>{allowed: true/false}
```

## JWT Claims Structure

Vault-scoped JWTs issued by the Management API contain the following claims:

```json
{
  "iss": "https://api.inferadb.com",
  "sub": "client:1234567890123456789",
  "aud": "https://api.inferadb.com/evaluate",
  "exp": 1234567890,
  "iat": 1234567800,
  "org_id": "9876543210987654321",
  "vault_id": "1111222233334444555",
  "vault_role": "write",
  "scope": "inferadb.check inferadb.read inferadb.write inferadb.expand inferadb.list inferadb.list-relationships inferadb.list-subjects inferadb.list-resources"
}
```

### Claim Descriptions

- **iss** (Issuer): Management API URL (`https://api.inferadb.com`)
- **sub** (Subject): Format `client:<client_id>` for service accounts (where client_id is a Snowflake ID)
- **aud** (Audience): Target service (Server API evaluation endpoint: `https://api.inferadb.com/evaluate`)
- **exp** (Expiration): Unix timestamp when token expires (5 minutes from issuance by default)
- **iat** (Issued At): Unix timestamp when token was created
- **org_id**: Organization ID (Snowflake ID as string)
- **vault_id**: The vault ID this token grants access to (Snowflake ID as string)
- **vault_role**: Permission level (lowercase: `read`, `write`, `manage`, `admin`)
- **scope**: Space-separated API permissions based on role:
  - `read`: "inferadb.check inferadb.read inferadb.expand inferadb.list inferadb.list-relationships inferadb.list-subjects inferadb.list-resources"
  - `write`: "inferadb.check inferadb.read inferadb.write inferadb.expand inferadb.list inferadb.list-relationships inferadb.list-subjects inferadb.list-resources"
  - `manage`: "inferadb.check inferadb.read inferadb.write inferadb.expand inferadb.list inferadb.list-relationships inferadb.list-subjects inferadb.list-resources inferadb.vault.manage"
  - `admin`: "inferadb.check inferadb.read inferadb.write inferadb.expand inferadb.list inferadb.list-relationships inferadb.list-subjects inferadb.list-resources inferadb.vault.manage inferadb.admin"

**Note**: This structure follows the Server API specification where:

- `iss` identifies the Management API (not the organization tenant)
- `sub` identifies the client/service account making the request
- `org_id` and `vault_id` are provided as separate claims (Snowflake IDs as strings)
- Custom claims (`org_id`, `vault_id`, `vault_role`) provide authorization context
- The Server API validates these claims against its JWKS cache

## Vault Token Request

When requesting a vault access token, clients can optionally specify the desired permission level:

```http
POST /v1/organizations/{org_id}/vaults/{vault_id}/tokens
Authorization: Bearer {session_token}
Content-Type: application/json

{
  "requested_role": "read"  // Optional: "read", "write", or "admin"
}
```

**Role Selection Logic**:

- If `requested_role` is omitted, defaults to `read` (principle of least privilege)
- If `requested_role` is specified, it must be less than or equal to the user's actual vault permissions
- Users cannot request a role higher than their membership level
- Example: A user with `write` permissions can request `read` or `write`, but not `admin`

**Available Roles** (request values are lowercase):

- **read**: Read-only access to vault data and policy evaluation (JWT: `READER`)
- **write**: Read and write access, can modify vault data (JWT: `WRITER`)
- **manage**: Read, write, and manage grants (JWT: `MANAGER`)
- **admin**: Full administrative access to vault configuration (JWT: `ADMIN`)

### Error Scenarios

The vault token request endpoint returns standard OAuth 2.0 error responses:

#### 1. `access_denied` - No Vault Access

```json
HTTP 403 Forbidden
{
  "error": "access_denied",
  "error_description": "User does not have access to vault <vault_id>"
}
```

**Cause**: User is not a member of the requested vault

**Client Action**: Redirect to vault selection page or show error message

#### 2. `invalid_request` - Role Exceeds Permissions

```json
HTTP 400 Bad Request
{
  "error": "invalid_request",
  "error_description": "Requested role 'admin' exceeds user's permission level 'write'"
}
```

**Cause**: User requested a role higher than their vault membership level

**Client Action**: Retry with a valid role or use default (`read`)

#### 3. `invalid_request` - Invalid Role

```json
HTTP 400 Bad Request
{
  "error": "invalid_request",
  "error_description": "Invalid role 'superadmin'. Must be one of: read, write, manage, admin"
}
```

**Cause**: Invalid role value provided

**Client Action**: Fix request to use valid role

#### 4. `not_found` - Vault Does Not Exist

```json
HTTP 404 Not Found
{
  "error": "not_found",
  "error_description": "Vault <vault_id> not found"
}
```

**Cause**: Vault ID does not exist or has been deleted

**Client Action**: Remove vault from client cache, redirect to vault selection

#### 5. `unauthorized` - Invalid Session Token

```json
HTTP 401 Unauthorized
{
  "error": "unauthorized",
  "error_description": "Invalid or expired session token"
}
```

**Cause**: Session token is invalid, expired, or revoked

**Client Action**: Re-authenticate user (full login flow)

## Vault Token Response Format

When a client requests a vault access token, the Management API returns:

```json
{
  "access_token": "<jwt>",
  "refresh_token": "<cryptographic_token>",
  "token_type": "Bearer",
  "expires_in": 300,
  "refresh_expires_in": 3600,
  "vault_id": "<snowflake_id>",
  "vault_role": "write"
}
```

## Refresh Token Flow

Vault access tokens expire after a short duration (5 minutes). Clients can use refresh tokens to obtain new access tokens without re-authenticating:

```mermaid
sequenceDiagram
    participant Client as Client Application
    participant MgmtAPI as Management API

    Client->>MgmtAPI: POST /v1/tokens/refresh<br/>{refresh_token}

    Note over MgmtAPI: Validate Refresh Token<br/>Check Single-Use Status<br/>Verify Vault Access<br/>Mark Token as Used<br/>Generate New JWT<br/>Issue New Refresh Token

    MgmtAPI-->>Client: New Tokens<br/>{access_token (JWT),<br/>refresh_token (new),<br/>token_type: Bearer,<br/>expires_in: 300}
```

### Refresh Token Security Properties

1. **Single-Use**: Each refresh token can only be used once
2. **Automatic Rotation**: New refresh token issued with each refresh
3. **Replay Detection**: Reused refresh tokens trigger security alerts and immediate revocation
4. **Expiration**: Refresh tokens expire after 1 hour
5. **Token Binding**: Bound to specific authentication context (session + vault)

### Refresh Token Error Handling

Clients **MUST** handle these error scenarios when refreshing tokens:

#### 1. `invalid_grant` - Token Expired, Revoked, or Already Used

```json
{
  "error": "invalid_grant",
  "error_description": "Refresh token is invalid, expired, or already used"
}
```

**Client Action**: Re-authenticate user (full login flow required)

#### 2. `access_denied` - Vault Access Revoked

```json
{
  "error": "access_denied",
  "error_description": "User no longer has access to this vault"
}
```

**Client Action**: Notify user that vault access has been revoked, redirect to vault selection or home page

#### 3. `replay_detected` - Security Alert

```json
{
  "error": "replay_detected",
  "error_description": "Refresh token reuse detected. All tokens for this session have been revoked."
}
```

**Client Action**:

- Immediately discard all stored tokens
- Force user re-authentication
- Log security event

**Security Note**: Refresh token reuse indicates a potential token theft attack. When detected:

1. All tokens associated with the session are immediately revoked
2. User must complete full authentication flow
3. Security event is logged for audit purposes

#### 4. Implementation Guidance

```javascript
async function refreshVaultToken(vaultId, refreshToken) {
  try {
    const response = await fetch(`/v1/vaults/${vaultId}/tokens/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });

    if (!response.ok) {
      const error = await response.json();

      if (error.error === "replay_detected") {
        // Critical security event - purge all tokens
        clearAllTokens();
        redirectToLogin({ reason: "security_alert" });
      } else if (error.error === "access_denied") {
        // Vault access revoked
        redirectToVaultSelection({
          message: "Access to this vault has been revoked",
        });
      } else {
        // Token expired or invalid - normal re-auth
        redirectToLogin({ reason: "session_expired" });
      }
      return null;
    }

    const tokens = await response.json();
    // Store new tokens securely
    storeTokens(tokens);
    return tokens;
  } catch (err) {
    // Network or other error
    console.error("Token refresh failed:", err);
    return null;
  }
}
```

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

##### ONE-TIME SETUP (Developer Portal)

```mermaid
sequenceDiagram
    participant Dev as Developer
    participant Portal as Management API<br/>Dashboard/Portal
    participant MgmtAPI as Management API

    Dev->>Portal: 1. Create Client<br/>(name, organization, vault permissions)

    Portal->>MgmtAPI: Create Client Request

    Note over MgmtAPI: Generate Client ID<br/>Generate Ed25519 Key Pair<br/>Store Public Key

    MgmtAPI-->>Portal: Client Created<br/>{client_id, private_key (PEM)}

    Portal-->>Dev: 2. Download Private Key<br/>⚠️ Shown only once!

    Note over Dev: 3. Configure Backend App:<br/>INFERADB_CLIENT_ID=client_abc123xyz<br/>INFERADB_PRIVATE_KEY={pem_contents}
```

##### RUNTIME (Every Token Request)

```mermaid
sequenceDiagram
    participant Backend as Backend Application
    participant MgmtAPI as Management API

    Note over Backend: 1. Create Client Assertion JWT:<br/>{iss: client_id, sub: client_id,<br/>aud: token_endpoint, exp: now+60s,<br/>iat: now, jti: unique_id}

    Note over Backend: 2. Sign with Private Key (Ed25519)

    Backend->>MgmtAPI: 3. POST /v1/token<br/>{grant_type: client_credentials,<br/>client_assertion_type: jwt-bearer,<br/>client_assertion: {signed_jwt},<br/>vault_id: "<vault_id>",<br/>requested_role: "write"}

    Note over MgmtAPI: 4. Parse Assertion JWT<br/>5. Lookup Client by iss/sub<br/>6. Verify Signature (Public Key)<br/>7. Validate Claims (aud, exp, jti)<br/>8. Check Vault Permissions<br/>9. Generate Vault-Scoped JWT

    MgmtAPI-->>Backend: 10. Vault Token Response<br/>{access_token: {vault_jwt},<br/>token_type: Bearer,<br/>expires_in: 300,<br/>vault_role: "write",<br/>scope: "inferadb.check inferadb.read inferadb.write ..."}

    Note over Backend: 11. Cache JWT (~5 min)<br/>12. Use for Server API Requests<br/>13. Repeat when expired
```

**Token Request Parameters**:

```http
POST /v1/token
Content-Type: application/json

{
  "grant_type": "client_credentials",
  "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
  "client_assertion": "<signed_jwt>",
  "vault_id": "<vault_id>", // Required: Which vault to access
  "requested_role": "write" // Optional: "read", "write", "manage", or "admin" (defaults to "read")
}
```

**Scope Format**: The returned `scope` contains space-separated permissions:

- Format: `{permission1} {permission2} ...`
- Example: `"vault:read vault:write"`
- The vault ID is provided separately in the `vault_id` JWT claim, not in the scope

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

```mermaid
flowchart TB
    User["👤 End User<br/>(authenticated with YOUR auth)"]
    SPA["🌐 SPA<br/>(React/Vue/etc.)"]
    Backend["🔧 YOUR Backend"]
    InferaDB["🔐 InferaDB<br/>(Management + Server APIs)"]

    User -->|"Your Auth JWT"| SPA
    SPA -->|"API call with user token"| Backend
    Backend -->|"1. Validates user<br/>2. Uses Client Assertion<br/>3. Gets vault token<br/>4. Checks permissions"| InferaDB
    InferaDB -->|"Authorization decision"| Backend
    Backend -->|"Response (show/hide features)"| SPA

    style InferaDB fill:#e1f5ff
    style Backend fill:#fff4e1
    style SPA fill:#f0f0f0
    style User fill:#e8f5e9
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

#### Identity Mapping Examples

Your backend must map user identities from YOUR auth system to InferaDB subjects. Here's how:

##### Example 1: Email-Based Mapping

```javascript
// Your backend receives authenticated request
app.get("/api/documents/:id", async (req, res) => {
  // 1. Extract user from YOUR auth token
  const userToken = req.headers.authorization.replace("Bearer ", "");
  const user = await verifyAuth0Token(userToken); // YOUR auth system

  // 2. Map to InferaDB subject (email-based)
  const inferadbSubject = `user:${user.email}`;

  // 3. Get InferaDB vault token (via client assertion)
  const vaultToken = await getInferaDBVaultToken();

  // 4. Check permission in InferaDB
  const decision = await inferadb.check(
    {
      subject: inferadbSubject, // "user:alice@example.com"
      action: "view",
      resource: `document:${req.params.id}`,
      context: {
        ip: req.ip,
        user_agent: req.headers["user-agent"],
      },
    },
    vaultToken
  );

  // 5. Enforce decision
  if (!decision.allowed) {
    return res.status(403).json({ error: "Access denied" });
  }

  // 6. Return data
  const document = await db.documents.findById(req.params.id);
  res.json(document);
});
```

##### Example 2: Stable ID Mapping

```javascript
// Use stable user IDs from your auth provider
const user = await verifyAuth0Token(userToken);

// Map to InferaDB subject using stable ID
const inferadbSubject = `user:auth0|${user.sub}`; // "user:auth0|507f1f77bcf86cd799439011"

// This is better than email because:
// - Emails can change
// - IDs are immutable
// - Works across multiple auth providers
```

##### Example 3: Hybrid Mapping (Recommended)

```javascript
// Store both in your database for flexibility
const userMapping = {
  auth_provider: "auth0",
  auth_user_id: user.sub,
  email: user.email,
  inferadb_subject_id: `user:auth0|${user.sub}`,
  inferadb_subject_email: `user:${user.email}`,
};

// Use ID-based subject for InferaDB checks
const subject = userMapping.inferadb_subject_id;

// But also create email-based relations in InferaDB for human-readable policies
// This allows policies like: "user:alice@example.com can view document:123"
// While still using stable IDs for actual authorization checks
```

##### Example 4: Role-Based Mapping

```javascript
// Map user roles from YOUR system to InferaDB
const user = await verifyClerkToken(userToken);

const subject = `user:${user.id}`;
const roles = user.publicMetadata.roles || []; // ["admin", "editor"]

// Check permissions with context
const decision = await inferadb.check(
  {
    subject: subject,
    action: "delete",
    resource: `document:${docId}`,
    context: {
      roles: roles, // Pass roles as context
      organization: user.orgId,
      session_id: user.sessionId,
    },
  },
  vaultToken
);
```

**Mapping Storage**:

You can store mappings in your database or compute them on-the-fly:

```sql
-- Option 1: Store in your database
CREATE TABLE user_auth_mappings (
  user_id UUID PRIMARY KEY,
  auth_provider VARCHAR(50) NOT NULL,
  auth_user_id VARCHAR(255) NOT NULL,
  email VARCHAR(255) NOT NULL,
  inferadb_subject VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Option 2: Compute on-the-fly (stateless)
-- No storage needed, just compute from auth token
```

**Handling Identity Changes**:

```javascript
// When user changes email
async function handleEmailChange(userId, oldEmail, newEmail) {
  // 1. Update your database
  await db.users.update(userId, { email: newEmail });

  // 2. Update InferaDB relations (if using email-based subjects)
  const vaultToken = await getInferaDBVaultToken();

  // Create new subject
  await inferadb.createSubject(`user:${newEmail}`, vaultToken);

  // Migrate permissions (if needed)
  await inferadb.migrateRelations(
    `user:${oldEmail}`,
    `user:${newEmail}`,
    vaultToken
  );

  // Or keep using stable ID-based subjects (no migration needed!)
  // This is why stable IDs are recommended
}
```

**Best Practices**:

1. **Use Stable IDs**: Prefer `user:provider|id` over `user:email`
2. **Document Format**: Document your subject format in code comments
3. **Validation**: Validate subject format before InferaDB calls
4. **Caching**: Cache InferaDB vault tokens (5 min lifetime)
5. **Error Handling**: Handle InferaDB errors gracefully
6. **Logging**: Log authorization decisions for audit trail

See [examples/spa-integration/CORRECT_SPA_ARCHITECTURE.md](../examples/spa-integration/CORRECT_SPA_ARCHITECTURE.md) for complete implementation.

**Alternative: JWT Token Exchange** - For truly serverless frontends where even serverless functions aren't desired, see [examples/spa-integration/TRULY_SERVERLESS_OPTIONS.md](../examples/spa-integration/TRULY_SERVERLESS_OPTIONS.md) for JWT token exchange pattern.

## Server API Token Validation

The Server API validates vault-scoped JWTs without making synchronous calls to the Management API:

1. **Fetch JWKS** (JSON Web Key Set) from Management API's `/.well-known/jwks.json` endpoint
2. **Cache JWKS** with TTL and background refresh mechanism
3. **Verify JWT Signature** using Ed25519 public key from JWKS
4. **Validate Claims**:
   - `iss` matches expected Management API endpoint
   - `aud` matches Server API identifier
   - `exp` is in the future (token not expired)
   - `vault_id` and `org_id` are valid
   - `vault_role` has sufficient permissions for requested operation
5. **Execute Policy** with authenticated context

This stateless validation allows the Server API to operate independently while still trusting tokens issued by the Management API.

### JWKS Caching Strategy

**Configuration**:

- **Cache TTL**: 5 minutes (300 seconds)
- **Background Refresh**: Refresh JWKS 1 minute before expiration (at 4-minute mark)
- **Capacity**: Support multiple signing keys simultaneously (for rotation)
- **Failure Handling**: Use stale cache for up to 1 hour if Management API is unreachable

**Implementation Flow**:

```mermaid
flowchart TD
    A[JWT Received] --> B{Key ID in Cache?}
    B -->|Yes| C{Cache Expired?}
    B -->|No| D[Fetch JWKS]
    C -->|No| E[Use Cached Key]
    C -->|Yes| F[Background Refresh]
    D --> G{JWKS Fetch Success?}
    G -->|Yes| H[Cache All Keys]
    G -->|No| I{Stale Cache Available?}
    I -->|Yes| J[Use Stale Cache + Log Warning]
    I -->|No| K[Reject Token]
    H --> E
    F --> E
    E --> L[Verify Signature]
    L --> M{Valid?}
    M -->|Yes| N[Validate Claims]
    M -->|No| K
    N --> O{Claims Valid?}
    O -->|Yes| P[Allow Request]
    O -->|No| K
```

**Key Rotation Handling**:

1. **During Rotation**: Management API publishes both old and new keys in JWKS
2. **Grace Period**: Both keys remain valid for overlap period (30 minutes)
3. **Cache Invalidation**: Server API caches all keys from JWKS, automatically picking up new keys
4. **Gradual Migration**: Existing JWTs continue to validate with old key while new JWTs use new key

**Example JWKS Response**:

```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "kid": "org-123-client-456-cert-789",
      "use": "sig",
      "x": "base64url-encoded-public-key"
    },
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "kid": "org-123-client-456-cert-790",
      "use": "sig",
      "x": "base64url-encoded-new-public-key"
    }
  ]
}
```

**Pseudocode Implementation**:

```rust
async fn get_verification_key(kid: &str) -> Result<PublicKey> {
    // Check cache first
    if let Some(key) = cache.get(kid).await {
        if !key.is_expired() {
            return Ok(key);
        }
        // Expired but keep as fallback
    }

    // Cache miss or expired - fetch fresh JWKS
    match fetch_jwks().await {
        Ok(jwks) => {
            // Cache all keys from JWKS
            for key in jwks.keys {
                cache.insert(key.kid, key, Duration::from_secs(300)).await;
            }

            // Return requested key
            cache.get(kid).await.ok_or(Error::KeyNotFound)
        }
        Err(err) => {
            // Network error - use stale cache if available
            if let Some(stale_key) = cache.get_stale(kid, Duration::from_secs(3600)).await {
                log::warn!("Using stale JWKS cache due to fetch error: {}", err);
                Ok(stale_key)
            } else {
                Err(Error::JwksFetchFailed(err))
            }
        }
    }
}

// Background refresh task
async fn jwks_refresh_task() {
    loop {
        sleep(Duration::from_secs(240)).await; // 4 minutes

        match fetch_jwks().await {
            Ok(jwks) => {
                for key in jwks.keys {
                    cache.insert(key.kid, key, Duration::from_secs(300)).await;
                }
                log::info!("JWKS cache refreshed successfully");
            }
            Err(err) => {
                log::error!("Background JWKS refresh failed: {}", err);
                // Continue using cached keys
            }
        }
    }
}
```

**Cache Metrics** (recommended for monitoring):

- `jwks_cache_hits`: Number of successful cache lookups
- `jwks_cache_misses`: Number of cache misses requiring fetch
- `jwks_fetch_errors`: Number of failed JWKS fetch attempts
- `jwks_stale_usage`: Number of times stale cache was used
- `jwks_cache_size`: Current number of keys in cache

## Security Considerations

### Token Lifetimes

InferaDB follows security-first principles with short-lived tokens as the default configuration.

**Recommended Configuration** (Security-First):

- **Session Tokens**: Varies by session type

  - **Web Sessions**: 24 hours (86,400 seconds)
  - **CLI Sessions**: 7 days (604,800 seconds)
  - **SDK Sessions**: 30 days (2,592,000 seconds)
  - Sliding window: Renewed on active Management API use
  - Revocable: Can be invalidated immediately
  - Forces regular re-authentication for enhanced security

- **Vault Access Tokens (JWT)**: 5 minutes (300 seconds)

  - Used for Server API policy evaluation
  - Very short lifetime minimizes impact of token compromise
  - Automatically refreshed by clients before expiration
  - Limits attack window to 5 minutes maximum

- **Vault Refresh Tokens**: Varies by auth method

  - **User Session Refresh Tokens**: 1 hour (3,600 seconds)
    - For interactive user sessions
    - Allows ~12 refreshes before requiring new vault token request
  - **Client Refresh Tokens**: 7 days (604,800 seconds)
    - For service accounts and backend applications
    - Longer lifetime suitable for automated systems
  - Single-use tokens for obtaining new vault access tokens
  - Automatically rotated on each use
  - Bound to specific vault + session/client

- **Client Assertions**: 60 seconds maximum
  - Ephemeral proof of client identity
  - Used only for token endpoint authentication
  - Not stored or cached

**Rationale**:

These conservative lifetimes prioritize security over convenience:

- **Short access tokens** (5 min) limit blast radius of any token compromise
- **Single-use refresh tokens** prevent replay attacks while reducing auth overhead
- **Session type-based lifetimes** balance security with UX for different use cases
- **Automatic rotation** at every layer provides defense in depth
- All tokens are revocable for immediate incident response

**Token Refresh Strategy**:

Clients should refresh tokens proactively:

```javascript
// Refresh when 80% of lifetime has elapsed
const shouldRefresh = (expiresIn) => {
  const timeElapsed = 300 - expiresIn; // 300s = 5 min total lifetime
  return timeElapsed >= 300 * 0.8; // Refresh after 4 minutes
};

// Example: Automatic refresh loop
setInterval(async () => {
  const timeRemaining = getTokenTimeRemaining();
  if (shouldRefresh(timeRemaining)) {
    await refreshVaultToken();
  }
}, 30000); // Check every 30 seconds
```

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

Token revocation provides immediate invalidation of compromised or unwanted access.

#### Session Token Revocation

**How It Works**:

1. Management API marks session as revoked in database
2. Session ID added to Redis revocation cache (TTL: 7 days)
3. All vault tokens derived from this session become invalid
4. Next refresh attempt returns `invalid_grant` error

**API Endpoint**:

```http
DELETE /v1/sessions/{session_id}
Authorization: Bearer {admin_session_token}
```

**Effect**:

- Immediate: Session cannot be used for new vault token requests
- Delayed (max 5 min): Existing vault JWTs expire naturally
- Refresh tokens: Rejected immediately on next use

**Use Cases**:

- User logout
- Suspicious activity detection
- Password change / credential reset
- Account compromise response

#### Vault Token Revocation (JWT)

**Important**: JWTs are stateless and cannot be directly revoked before expiration.

**Revocation Strategies**:

1. **Revoke Parent Session** (Recommended)

   - Revokes the session that issued the vault tokens
   - Prevents new tokens from being issued
   - Existing JWTs expire after 5 minutes maximum

2. **Remove Vault Membership**

   - Remove user from vault member list
   - Future token requests will fail with `access_denied`
   - Existing JWTs continue working until expiration
   - Server API can optionally verify membership in real-time (performance trade-off)

3. **Emergency: Rotate Signing Keys**
   - Generate new Ed25519 key pair for organization
   - Publish new public key to JWKS endpoint
   - Remove old public key after grace period
   - **WARNING**: Invalidates ALL vault tokens for organization
   - Use only in case of key compromise

**Revocation Propagation Delay**:

| Token Type                   | Revocation Method  | Max Delay                  |
| ---------------------------- | ------------------ | -------------------------- |
| Session Token                | Direct revocation  | Immediate                  |
| Vault JWT (via session)      | Session revocation | 5 minutes (JWT expiry)     |
| Vault JWT (via membership)   | Remove from vault  | 5 minutes (JWT expiry)     |
| Vault JWT (via key rotation) | JWKS update        | 5 minutes (JWKS cache TTL) |
| Refresh Token                | Session revocation | Immediate                  |

#### Client Certificate Revocation

**How It Works**:

1. Delete client certificate from Management API database
2. Remove certificate from JWKS endpoint response
3. Server API cache expires (max 5 minutes)
4. New token requests with this certificate fail
5. Existing tokens signed with this certificate expire naturally (5 min)

**API Endpoint**:

```http
DELETE /v1/organizations/{org_id}/clients/{client_id}/certificates/{cert_id}
Authorization: Bearer {admin_session_token}
```

**Effect**:

- Immediate: Cannot issue new client assertions
- Delayed (max 5 min): JWKS cache expires on Server API
- Delayed (max 5 min): Existing vault JWTs expire

**Use Cases**:

- Certificate rotation
- Client decommissioning
- Suspected key compromise
- Certificate expiration

#### Revocation Best Practices

**For Immediate Revocation**:

If you need to revoke access immediately (cannot wait 5 minutes):

1. Implement real-time vault membership checks in Server API
2. Use Redis pub/sub to propagate revocation events
3. Maintain session/client revocation cache

**For Normal Operations**:

The standard 5-minute JWT lifetime provides good balance:

- Most tokens refresh naturally before expiration
- 5-minute window is acceptable risk for normal revocation
- No performance penalty for real-time checks

**Monitoring Revocation**:

Track these metrics:

- `session_revocations_total`: Number of sessions revoked
- `certificate_revocations_total`: Number of certificates revoked
- `refresh_token_rejections_total`: Refresh attempts after revocation
- `revocation_cache_size`: Current size of revocation cache

#### Architecture Diagram

```mermaid
sequenceDiagram
    participant Admin as Administrator
    participant MgmtAPI as Management API
    participant Redis as Redis Cache
    participant ServerAPI as Server API
    participant Client as Client Application

    Admin->>MgmtAPI: DELETE /v1/sessions/{id}
    MgmtAPI->>MgmtAPI: Mark session as revoked in DB
    MgmtAPI->>Redis: Add session_id to revocation set<br/>(TTL: 7 days)
    MgmtAPI-->>Admin: Session revoked

    Note over Client: Attempts to refresh vault token

    Client->>MgmtAPI: POST /v1/tokens/refresh
    MgmtAPI->>Redis: Check if session revoked
    Redis-->>MgmtAPI: Session in revocation set
    MgmtAPI-->>Client: 401 invalid_grant

    Note over Client: Existing JWT still valid (max 5 min)

    Client->>ServerAPI: POST /check<br/>Authorization: Bearer {vault_jwt}
    ServerAPI->>ServerAPI: Validate JWT signature (JWKS)
    ServerAPI->>ServerAPI: Check expiration
    Note over ServerAPI: JWT is valid until expiration<br/>(stateless validation)
    ServerAPI-->>Client: Authorization decision

    Note over Client,ServerAPI: After 5 minutes, JWT expires

    Client->>ServerAPI: POST /check<br/>Authorization: Bearer {expired_jwt}
    ServerAPI-->>Client: 401 Token expired
```

## Server-to-Management Authentication

### Overview

The Server API and Management API implement bidirectional JWT authentication using Ed25519 keypairs:

1. **Management-to-Server**: Management API issues vault tokens for clients (documented above)
2. **Server-to-Management**: Server API authenticates to Management API for verification operations

This bidirectional architecture allows the Server API to verify vault ownership and organization status by making authenticated requests back to the Management API.

### Authentication Flow

```mermaid
sequenceDiagram
    participant Client as Client App
    participant ServerAPI as Server API
    participant MgmtAPI as Management API

    Note over ServerAPI: Server boots with Ed25519 keypair

    ServerAPI->>ServerAPI: Load/generate server identity
    ServerAPI->>ServerAPI: Expose JWKS endpoint

    Note over Client: Client makes request to Server API

    Client->>ServerAPI: POST /check<br/>Authorization: Bearer {vault_jwt}

    Note over ServerAPI: Need to verify vault ownership

    ServerAPI->>ServerAPI: Generate server JWT (5 min TTL)
    ServerAPI->>MgmtAPI: GET /v1/vaults/{vault_id}<br/>Authorization: Bearer {server_jwt}

    MgmtAPI->>ServerAPI: Fetch JWKS from /.well-known/jwks.json
    MgmtAPI->>MgmtAPI: Verify server JWT signature
    MgmtAPI->>MgmtAPI: Validate claims (iss, sub, aud, exp)
    MgmtAPI-->>ServerAPI: Vault details (org_id, name, status)

    ServerAPI->>ServerAPI: Cache vault details (5 min TTL)
    ServerAPI->>MgmtAPI: GET /v1/organizations/{org_id}<br/>Authorization: Bearer {server_jwt}
    MgmtAPI-->>ServerAPI: Organization status

    ServerAPI->>ServerAPI: Cache org status (5 min TTL)
    ServerAPI->>ServerAPI: Evaluate policy
    ServerAPI-->>Client: Authorization decision
```

### Server Identity Configuration

The Server API uses an Ed25519 keypair as its identity:

**Development Mode** (auto-generation):

```yaml
auth:
  management_api_url: "http://localhost:8081"
  # Omit server_identity_private_key to auto-generate
  server_identity_kid: "server-primary-2024"
  server_id: "inferadb-server-dev"
```

On startup without a configured key, the server will:

1. Generate a new Ed25519 keypair
2. Log the PEM-encoded private key (WARNING level)
3. Use this key for the current session
4. Expose the public key via JWKS endpoint

**Production Mode** (configured key):

```yaml
auth:
  management_api_url: "https://management.example.com"
  server_identity_private_key: |
    -----BEGIN PRIVATE KEY-----
    MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF
    -----END PRIVATE KEY-----
  server_identity_kid: "server-primary-2024"
  server_id: "inferadb-server-prod-us-east-1"
```

Key management best practices:

- Store private keys in secure secret management (Vault, AWS Secrets Manager, etc.)
- Use unique `server_id` per deployment/region
- Rotate keys periodically (update `kid` when rotating)
- Never commit private keys to version control

### Server JWT Claims Structure

Server-to-Management JWTs use the following claims:

```json
{
  "iss": "inferadb-server:{server_id}",
  "sub": "server:{server_id}",
  "aud": "http://localhost:8081",
  "iat": 1704123456,
  "exp": 1704123756,
  "jti": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Claim Descriptions**:

- **iss** (issuer): Identifies the server instance (`inferadb-server:{server_id}`)
- **sub** (subject): Server principal (`server:{server_id}`)
- **aud** (audience): Management API base URL (from config)
- **iat** (issued at): Unix timestamp of token creation
- **exp** (expiration): 5 minutes from issuance (short-lived for security)
- **jti** (JWT ID): Unique identifier for replay protection (UUID v4)

**Security Properties**:

- Short expiration (5 minutes) limits exposure if token is compromised
- JTI enables replay attack detection (if implemented)
- EdDSA signature ensures token integrity and authenticity

### JWKS Endpoint

The Server API exposes its public key at `/.well-known/jwks.json`:

```bash
curl http://localhost:8080/.well-known/jwks.json
```

Response:

```json
{
  "keys": [
    {
      "kty": "OKP",
      "alg": "EdDSA",
      "kid": "server-primary-2024",
      "crv": "Ed25519",
      "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
      "use": "sig"
    }
  ]
}
```

**Field Descriptions**:

- **kty**: Key type (always "OKP" for Ed25519)
- **alg**: Algorithm (always "EdDSA" for Ed25519 signatures)
- **kid**: Key identifier (matches server_identity_kid config)
- **crv**: Curve name (always "Ed25519")
- **x**: Base64url-encoded public key (32 bytes)
- **use**: Key usage (always "sig" for signature)

### Dual-Server Architecture

The Management API runs **two separate HTTP servers** for security isolation:

- **Public Server** (port 3000): User-facing API with session authentication and permission checks
- **Internal Server** (port 9091): Server-to-server API with JWT authentication for privileged operations

This architecture ensures that privileged endpoints are only accessible via the internal network and cannot be reached from the public internet.

#### Public Endpoints (Port 3000)

User-facing endpoints with session authentication and permission enforcement:

- `GET /v1/organizations/{org}` - Fetch organization details (requires organization membership)
- `GET /v1/vaults/{vault}` - Fetch vault details (requires vault access)

**User Request Example**:

```bash
# Request to public server (port 3000)
curl -X GET http://localhost:3000/v1/organizations/123456789 \
  -H "Cookie: session_id=987654321"
```

**Authorization**:

- User must be authenticated via session cookie
- User must be a member of the organization
- User must have appropriate permissions (checked via middleware)

#### Internal Endpoints (Port 9091)

Privileged server-to-server endpoints with JWT authentication, **no permission checks**:

- `GET /internal/organizations/{org}` - Fetch organization details (any valid server JWT)
- `GET /internal/vaults/{vault}` - Fetch vault details (any valid server JWT)

**Server Request Example**:

```bash
# Request to internal server (port 9091)
curl -X GET http://localhost:9091/internal/organizations/123456789 \
  -H "Authorization: Bearer eyJhbGc...(server JWT)"
```

**Authorization**:

- Server must provide valid Ed25519-signed JWT
- JWT must be signed by a trusted server (verified via JWKS)
- No organization membership or vault access checks
- Used for server-to-server verification (vault ownership, org status)

#### Key Differences

| Aspect             | Public Server (3000)       | Internal Server (9091)        |
| ------------------ | -------------------------- | ----------------------------- |
| **Authentication** | Session cookies            | Server JWTs (EdDSA)           |
| **Authorization**  | Permission checks required | No permission checks          |
| **Network**        | Public internet            | Internal network only         |
| **Endpoints**      | `/v1/*`                    | `/internal/*`                 |
| **Use Case**       | User requests              | Server-to-server verification |

#### Security Benefits

1. **Network Isolation**: Internal endpoints cannot be reached from public internet
2. **No Permission Bypass**: Public endpoints enforce permissions; internal endpoints are isolated
3. **Separate Attack Surface**: Compromising public server doesn't expose privileged endpoints
4. **Audit Trail**: Different ports allow separate logging and monitoring

### JWKS Caching Strategy

The Management API caches server JWKS to avoid fetching on every request:

```rust
static JWKS_CACHE: once_cell::sync::Lazy<JwksCache> =
    once_cell::sync::Lazy::new(|| JwksCache::new(900)); // 15 minutes TTL
```

**Cache Behavior**:

1. First server JWT validation triggers JWKS fetch
2. JWKS cached for 15 minutes
3. Subsequent validations use cached keys (no network call)
4. After TTL expires, next validation refetches JWKS
5. Thread-safe via `Arc<RwLock<...>>`

**Performance Impact**:

- First validation: ~50-100ms (network roundtrip)
- Cached validations: <1ms (local signature verification)
- Cache hit rate: >99% in steady state

### Use Cases

**Vault Ownership Verification**:

```rust
// Server needs to verify vault belongs to expected organization
let vault = management_client.get_vault(vault_id).await?;
if vault.organization_id != expected_org_id {
    return Err("Vault does not belong to organization");
}
```

**Organization Status Check**:

```rust
// Server needs to verify organization is not suspended
let org = management_client.get_organization(org_id).await?;
if org.status != "active" {
    return Err("Organization suspended");
}
```

**Client Certificate Verification** (from Management-to-Server flow):

```rust
// Server validates client certificate via Management API
let cert = management_client
    .get_certificate(org_id, client_id, cert_id)
    .await?;

if cert.revoked {
    return Err("Certificate revoked");
}
```

### Security Considerations

**Key Rotation**:

- Generate new Ed25519 keypair
- Update configuration with new private key
- Change `server_identity_kid` to new value
- Deploy updated configuration
- Old JWKS entries expire from Management API cache (15 min)

**Threat Model**:

- **Server key compromise**: Attacker can impersonate server to Management API (mitigated by short JWT TTL)
- **JWKS endpoint spoofing**: Attacker cannot spoof without DNS/network access (use HTTPS in production)
- **Replay attacks**: JTI claim enables detection (not currently enforced)

**Best Practices**:

- Use HTTPS for all production traffic
- Store server private keys in secret management systems
- Monitor authentication failures in Management API logs
- Implement JTI-based replay protection for high-security deployments
- Rotate keys on a regular schedule (e.g., quarterly)

## Integration Points

### Management API Responsibilities

- User identity verification
- Session lifecycle management
- Vault permission checks
- JWT issuance and signing (vault tokens for clients)
- JWKS publication for Server API
- Refresh token rotation
- **Server JWT verification** (verifying server-to-management requests)
- **Server JWKS caching** (caching server public keys with 15-min TTL)
- **Dual authentication support** (accepting both session and server JWT)

### Server API Responsibilities

- JWT signature validation (client vault tokens)
- Claims verification
- Policy evaluation
- Authorization decisions
- Relationship graph queries
- **Server JWT issuance** (signing requests to Management API)
- **Server JWKS publication** (exposing public key at `/.well-known/jwks.json`)
- **Management API verification calls** (fetching vault/org data for verification)

This clean separation allows each service to focus on its core competency while maintaining strong security guarantees across the system. The bidirectional authentication architecture enables secure server-to-server communication for verification operations while preserving the stateless nature of policy evaluation.
