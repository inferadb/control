# Control: entity reference and API specification

Complete reference for InferaDB Control's data model, REST API, behavioral rules, configuration, and error taxonomy. This is the authoritative source for building integrations and understanding system behavior.

Control is the administration layer for InferaDB. It manages user authentication, multi-tenant organizations, teams, vaults, client credentials, schema deployment, and audit logging.

---

## Table of contents

### Entities

- [Primary keys](#primary-keys)
- [Users](#users) -- User, UserEmail, UserPasskey, UserSession
- [Organizations](#organizations) -- Organization, OrganizationMember, OrganizationRole, OrganizationInvitation, OrganizationTier
- [Teams](#teams) -- OrganizationTeam, OrganizationTeamMember
- [Clients](#clients) -- Client, ClientCertificate
- [Vaults](#vaults) -- Vault, VaultRole
- [Tokens](#tokens) -- VaultRefreshToken
- [Audit](#audit) -- AuditLog

### API reference

- [REST API conventions](#rest-api-conventions)
- [Authentication endpoints](#authentication-endpoints)
- [User endpoints](#user-endpoints)
- [Email endpoints](#email-endpoints)
- [Passkey endpoints](#passkey-endpoints)
- [Organization endpoints](#organization-endpoints)
- [Organization member endpoints](#organization-member-endpoints)
- [Invitation endpoints](#invitation-endpoints)
- [Team endpoints](#team-endpoints)
- [Team member endpoints](#team-member-endpoints)
- [Client endpoints](#client-endpoints)
- [Certificate endpoints](#certificate-endpoints)
- [Vault endpoints](#vault-endpoints)
- [Vault token endpoints](#vault-token-endpoints)
- [Schema endpoints](#schema-endpoints)
- [Audit log endpoints](#audit-log-endpoints)
- [Health endpoints](#health-endpoints)
- [Metrics endpoint](#metrics-endpoint)

### Behavioral rules

- [Registration flow](#registration-flow)
- [Organization lifecycle](#organization-lifecycle)
- [Team lifecycle](#team-lifecycle)
- [Client and certificate management](#client-and-certificate-management)
- [Vault lifecycle](#vault-lifecycle)
- [Session management](#session-management)
- [Rate limiting](#rate-limiting)
- [Soft delete and cleanup](#soft-delete-and-cleanup)

### System

- [Error response taxonomy](#error-response-taxonomy)
- [Configuration reference](#configuration-reference)

---

## Primary keys

All entities use 64-bit Snowflake IDs: `timestamp (41 bits) | worker_id (10 bits) | sequence (12 bits)`.

- Sortable by creation time
- Globally unique across entity types
- Serialized as strings in JSON (avoids JavaScript 53-bit precision loss)
- Custom epoch: `2024-01-01T00:00:00Z`
- Up to 4096 IDs per millisecond per worker (0--1023)
- Worker ID collision detection via Ledger heartbeat (30s TTL, 10s interval)

---

## Users

### User

An individual user account. API path: `/control/v1/users/me`.

| Field        | Type              | Description                                                                                |
| ------------ | ----------------- | ------------------------------------------------------------------------------------------ |
| `slug`       | u64               | Snowflake ID                                                                               |
| `name`       | string            | Display name (1--128 chars, alphanumeric + hyphens/underscores/spaces/periods/apostrophes) |
| `status`     | string            | Account status (e.g., `"active"`, `"deleted"`)                                             |
| `role`       | string            | Platform role (e.g., `"user"`)                                                             |
| `created_at` | string (RFC 3339) | Account creation timestamp                                                                 |

Users must have at least one verified email for sensitive operations. Users cannot be deleted if they are the sole Owner of any organization.

### UserEmail

An email address belonging to a user. API path: `/control/v1/users/emails`.

| Field         | Type              | Description                                       |
| ------------- | ----------------- | ------------------------------------------------- |
| `slug`        | u64               | Snowflake ID                                      |
| `email`       | string            | Email address (globally unique, case-insensitive) |
| `verified`    | bool              | Whether the email has been verified               |
| `created_at`  | string (RFC 3339) | Creation timestamp                                |
| `verified_at` | string (RFC 3339) | Verification timestamp                            |

### UserPasskey

A WebAuthn/FIDO2 credential. Registration via `/control/v1/users/me/credentials/passkeys/begin` and `/finish`. Maximum 20 passkeys per user.

### UserSession

An authenticated session. Managed through auth endpoints (login, logout, revoke-all). Maximum 10 concurrent sessions per user; oldest session evicted when exceeded.

---

## Organizations

### Organization

A tenant entity. API path: `/control/v1/organizations`.

| Field    | Type   | Description                                  |
| -------- | ------ | -------------------------------------------- |
| `slug`   | u64    | Snowflake ID                                 |
| `name`   | string | Display name (not globally unique)           |
| `region` | string | Data residency region (e.g., `"us-east-va"`) |
| `status` | string | Status (e.g., `"active"`)                    |
| `tier`   | string | Subscription tier (e.g., `"free"`, `"pro"`)  |

Every organization must have at least one Owner. Maximum 10 organizations per user. Global limit: 100,000 organizations.

### OrganizationMember

Associates a user with an organization. API path: `/control/v1/organizations/{org}/members`.

| Field       | Type              | Description                         |
| ----------- | ----------------- | ----------------------------------- |
| `user`      | u64               | User slug                           |
| `role`      | string            | `"member"`, `"admin"`, or `"owner"` |
| `joined_at` | string (RFC 3339) | When the user joined                |

### OrganizationRole

| Role     | Capabilities                                                                                                        |
| -------- | ------------------------------------------------------------------------------------------------------------------- |
| `member` | View org details, view accessible teams and vaults                                                                  |
| `admin`  | All member capabilities + create/manage teams, invite users, create vaults, manage vault access, update org details |
| `owner`  | All admin capabilities + delete org, manage billing/tier, promote/demote to any role                                |

### OrganizationInvitation

An invitation for a user to join an organization. Expires after 7 days.

| Field           | Type              | Description                            |
| --------------- | ----------------- | -------------------------------------- |
| `slug`          | u64               | Snowflake ID                           |
| `organization`  | u64               | Organization slug                      |
| `inviter`       | u64               | Inviter user slug                      |
| `invitee_email` | string            | Email of invitee                       |
| `role`          | string            | Role to assign on acceptance           |
| `status`        | string            | `"pending"`, `"accepted"`, `"revoked"` |
| `created_at`    | string (RFC 3339) | Creation timestamp                     |
| `expires_at`    | string (RFC 3339) | Expiration timestamp                   |

### OrganizationTier

Tiers control resource limits per organization.

| Tier   | Max users | Max teams | Max vaults |
| ------ | --------- | --------- | ---------- |
| `free` | 5         | 3         | 5          |
| `pro`  | 50        | 20        | 50         |
| `max`  | 500       | 100       | 200        |

---

## Teams

### OrganizationTeam

A group of users within an organization. API path: `/control/v1/organizations/{org}/teams`.

| Field          | Type              | Description                               |
| -------------- | ----------------- | ----------------------------------------- |
| `slug`         | u64               | Snowflake ID                              |
| `organization` | u64               | Organization slug                         |
| `name`         | string            | Display name (unique within organization) |
| `members`      | array             | Team members (inline)                     |
| `created_at`   | string (RFC 3339) | Creation timestamp                        |
| `updated_at`   | string (RFC 3339) | Last update timestamp                     |

### OrganizationTeamMember

| Field       | Type              | Description               |
| ----------- | ----------------- | ------------------------- |
| `user`      | u64               | User slug                 |
| `role`      | string            | `"member"` or `"manager"` |
| `joined_at` | string (RFC 3339) | When the user joined      |

Team managers can add/remove members but cannot delete the team.

---

## Clients

### Client

A service identity for backend applications (maps to "app" in Ledger). API path: `/control/v1/organizations/{org}/clients`.

| Field         | Type              | Description                               |
| ------------- | ----------------- | ----------------------------------------- |
| `slug`        | u64               | Snowflake ID                              |
| `name`        | string            | Display name (unique within organization) |
| `description` | string?           | Human-readable description                |
| `enabled`     | bool              | Whether the client is active              |
| `credentials` | object?           | Credential methods (see below)            |
| `created_at`  | string (RFC 3339) | Creation timestamp                        |
| `updated_at`  | string (RFC 3339) | Last update timestamp                     |

Credentials object:

| Field                      | Type | Description                     |
| -------------------------- | ---- | ------------------------------- |
| `client_secret_enabled`    | bool | Client secret auth              |
| `mtls_ca_enabled`          | bool | mTLS with CA certs              |
| `mtls_self_signed_enabled` | bool | mTLS with self-signed certs     |
| `client_assertion_enabled` | bool | JWT client assertion (RFC 7523) |

### ClientCertificate

An Ed25519 key pair for JWT client assertion. API path: `/control/v1/organizations/{org}/clients/{client}/certificates`.

| Field        | Type              | Description                       |
| ------------ | ----------------- | --------------------------------- |
| `slug`       | u64               | Snowflake ID                      |
| `name`       | string            | Friendly name                     |
| `enabled`    | bool              | Whether the certificate is active |
| `expires_at` | string (RFC 3339) | Expiration timestamp              |
| `created_at` | string (RFC 3339) | Creation timestamp                |

The private key PEM is returned only on creation and cannot be retrieved later.

---

## Vaults

### Vault

An authorization policy container. API path: `/control/v1/organizations/{org}/vaults`.

| Field          | Type     | Description                             |
| -------------- | -------- | --------------------------------------- |
| `organization` | u64      | Organization slug                       |
| `slug`         | u64      | Snowflake ID                            |
| `height`       | u64      | Raft log height (block count)           |
| `status`       | string   | Status (e.g., `"active"`, `"deleting"`) |
| `nodes`        | string[] | Raft cluster node IDs                   |
| `leader`       | string?  | Current Raft leader                     |

### VaultRole

| Role      | Capabilities                                                   |
| --------- | -------------------------------------------------------------- |
| `reader`  | Query relationships, authorization checks                      |
| `writer`  | Reader + write/delete relationships                            |
| `manager` | Writer + read/write schema, view access grants                 |
| `admin`   | Manager + clear all relationships, delete vault, manage access |

---

## Tokens

### VaultRefreshToken

Enables refreshing vault-scoped JWTs without re-authenticating. Single-use with automatic rotation.

- User session tokens: 1-hour TTL
- Client tokens: 7-day TTL
- Bound to parent authentication context (session or client)
- Replay detection: reusing a consumed token revokes all tokens for that auth context

---

## Audit

### AuditLog

Immutable security event records. API path: `/control/v1/organizations/{org}/audit-logs`.

| Field        | Type              | Description                                            |
| ------------ | ----------------- | ------------------------------------------------------ |
| `event_id`   | string            | UUID                                                   |
| `event_type` | string            | Hierarchical type (e.g., `"ledger.vault.created"`)     |
| `principal`  | string            | Who performed the action (e.g., `"user:42"`)           |
| `outcome`    | string            | `"success"`, `"failed:<code>"`, or `"denied:<reason>"` |
| `timestamp`  | string (RFC 3339) | When the event occurred                                |
| `source`     | string            | Service that emitted the event                         |
| `action`     | string            | Machine-readable action name                           |
| `details`    | object            | Key-value context                                      |

---

## REST API conventions

**Route prefix**: `/control/v1/`

**Authentication**: JWT access token in `Authorization: Bearer <token>` header or `inferadb_access` cookie.

**JWT validation split**: Read operations (GET) use local JWT validation (cached Ed25519 public keys, no Ledger round-trip). Write operations (POST/PATCH/DELETE) use Ledger-validated JWT.

**Pagination**: Cursor-based. Query parameters: `page_size` (1--100, default 50), `page_token` (opaque base64 cursor). Response includes `next_page_token` when more results exist.

**Body size limits**: 256 KiB default. Schema deployment allows 1 MiB.

**Concurrency limit**: 10,000 concurrent requests.

**Error response format**:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "name must be between 1 and 128 characters"
  }
}
```

---

## Authentication endpoints

All authentication endpoints are public with rate limiting.

### Initiate email verification

```
POST /control/v1/auth/email/initiate
```

Rate limit: 100/hour per IP.

**Request**:

```json
{
  "email": "user@example.com",
  "region": "US_EAST_VA"
}
```

`region` is optional (defaults to `US_EAST_VA`).

**Response** (200):

```json
{
  "message": "verification code sent"
}
```

### Verify email code

```
POST /control/v1/auth/email/verify
```

Rate limit: 100/hour per IP.

**Request**:

```json
{
  "email": "user@example.com",
  "code": "123456",
  "region": "US_EAST_VA"
}
```

**Response** varies by user state:

Existing user (no TOTP):

```json
{
  "status": "authenticated",
  "access_token": "<jwt>",
  "refresh_token": "<token>",
  "token_type": "Bearer"
}
```

Existing user (TOTP enabled):

```json
{
  "status": "totp_required",
  "challenge_nonce": "<base64>"
}
```

New user:

```json
{
  "status": "registration_required",
  "onboarding_token": "<token>"
}
```

### Complete registration

```
POST /control/v1/auth/email/complete
```

Rate limit: 5/day per IP.

**Request**:

```json
{
  "onboarding_token": "<token>",
  "email": "user@example.com",
  "name": "Jane Doe",
  "organization_name": "Acme Corp",
  "region": "US_EAST_VA"
}
```

**Response** (201):

```json
{
  "registration": {
    "user": 12345,
    "organization": 67890,
    "access_token": "<jwt>",
    "refresh_token": "<token>",
    "token_type": "Bearer"
  }
}
```

### Verify TOTP code

```
POST /control/v1/auth/totp/verify
```

Rate limit: 100/hour per IP.

**Request**:

```json
{
  "user_slug": 12345,
  "totp_code": "123456",
  "challenge_nonce": "<base64>"
}
```

**Response** (200):

```json
{
  "access_token": "<jwt>",
  "refresh_token": "<token>",
  "token_type": "Bearer"
}
```

### Consume recovery code

```
POST /control/v1/auth/recovery
```

Rate limit: 100/hour per IP.

**Request**:

```json
{
  "user_slug": 12345,
  "code": "ABC12345",
  "challenge_nonce": "<base64>"
}
```

**Response** (200):

```json
{
  "access_token": "<jwt>",
  "refresh_token": "<token>",
  "token_type": "Bearer",
  "remaining_codes": 4
}
```

### Begin passkey authentication

```
POST /control/v1/auth/passkey/begin
```

Rate limit: 100/hour per IP.

**Request**:

```json
{
  "user_slug": 12345
}
```

**Response** (200):

```json
{
  "challenge_id": "<uuid>",
  "challenge": { ... }
}
```

The `challenge` field is a WebAuthn `RequestChallengeResponse`.

### Finish passkey authentication

```
POST /control/v1/auth/passkey/finish
```

Rate limit: 100/hour per IP.

**Request**:

```json
{
  "challenge_id": "<uuid>",
  "credential": { ... }
}
```

The `credential` field is a WebAuthn `PublicKeyCredential`.

**Response** varies:

Authenticated (no TOTP):

```json
{
  "status": "authenticated",
  "access_token": "<jwt>",
  "refresh_token": "<token>",
  "token_type": "Bearer"
}
```

TOTP required:

```json
{
  "status": "totp_required",
  "challenge_nonce": "<base64>"
}
```

### Client assertion authentication

```
POST /control/v1/token
```

Rate limit: 100/hour per IP. OAuth 2.0 JWT Bearer (RFC 7523).

**Request**:

```json
{
  "grant_type": "client_credentials",
  "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
  "client_assertion": "<signed_jwt>",
  "organization": 12345,
  "vault": "67890",
  "scopes": ["vault:read", "vault:write"],
  "requested_role": "writer"
}
```

**Response** (200):

```json
{
  "access_token": "<jwt>",
  "refresh_token": "<token>",
  "token_type": "Bearer",
  "expires_in": 900
}
```

### Refresh session tokens

```
POST /control/v1/auth/refresh
```

Rate limit: 100/hour per IP.

**Request** (body or `inferadb_refresh` cookie):

```json
{
  "refresh_token": "<token>"
}
```

**Response** (200):

```json
{
  "access_token": "<jwt>",
  "refresh_token": "<new_token>",
  "token_type": "Bearer"
}
```

Sets `inferadb_access` and `inferadb_refresh` cookies.

### Verify email ownership

```
POST /control/v1/auth/verify-email
```

Rate limit: 100/hour per IP.

**Request**:

```json
{
  "token": "<verification_token>"
}
```

**Response** (200):

```json
{
  "message": "email verified",
  "verified": true
}
```

### Logout

```
POST /control/v1/auth/logout
```

No rate limiting. Best-effort revocation of refresh token. Clears cookies.

**Response** (200):

```json
{
  "message": "logged out"
}
```

### Revoke all sessions

```
POST /control/v1/auth/revoke-all
```

Requires JWT. Revokes all sessions for the authenticated user.

**Response** (200):

```json
{
  "revoked_count": 3
}
```

---

## User endpoints

All require JWT authentication.

### Get profile

```
GET /control/v1/users/me
```

Auth: local JWT (read).

**Response** (200):

```json
{
  "user": {
    "slug": 12345,
    "name": "Jane Doe",
    "status": "active",
    "role": "user",
    "created_at": "2025-01-15T10:30:00+00:00"
  }
}
```

### Update profile

```
PATCH /control/v1/users/me
```

Auth: Ledger-validated JWT (write).

**Request**:

```json
{
  "name": "Jane Smith"
}
```

**Response** (200):

```json
{
  "user": { ... }
}
```

### Delete user

```
DELETE /control/v1/users/me
```

Auth: Ledger-validated JWT (write). Fails if the user is the sole Owner of any organization.

**Response** (200):

```json
{
  "message": "user account deleted"
}
```

---

## Email endpoints

### List emails

```
GET /control/v1/users/emails
```

Auth: local JWT (read).

**Response** (200):

```json
{
  "emails": [
    {
      "slug": 100,
      "email": "jane@example.com",
      "verified": true,
      "created_at": "2025-01-15T10:30:00+00:00",
      "verified_at": "2025-01-15T10:35:00+00:00"
    }
  ]
}
```

### Add email

```
POST /control/v1/users/emails
```

Auth: Ledger-validated JWT (write).

**Request**:

```json
{
  "email": "new@example.com"
}
```

**Response** (200):

```json
{
  "email": {
    "slug": 101,
    "email": "new@example.com",
    "verified": false,
    "created_at": "2025-06-01T12:00:00+00:00",
    "verified_at": null
  },
  "message": "verification email sent"
}
```

### Delete email

```
DELETE /control/v1/users/emails/{id}
```

Auth: Ledger-validated JWT (write). Cannot delete the last verified email.

**Response** (200):

```json
{
  "message": "email removed"
}
```

---

## Passkey endpoints

### Begin passkey registration

```
POST /control/v1/users/me/credentials/passkeys/begin
```

Auth: Ledger-validated JWT (write).

**Request**:

```json
{
  "name": "MacBook Pro"
}
```

**Response** (200):

```json
{
  "challenge_id": "<uuid>",
  "challenge": { ... }
}
```

The `challenge` field is a WebAuthn `CreationChallengeResponse`.

### Finish passkey registration

```
POST /control/v1/users/me/credentials/passkeys/finish
```

Auth: Ledger-validated JWT (write).

**Request**:

```json
{
  "challenge_id": "<uuid>",
  "name": "MacBook Pro",
  "credential": { ... }
}
```

The `credential` field is a WebAuthn `RegisterPublicKeyCredential`.

**Response** (200):

```json
{
  "slug": 200,
  "name": "MacBook Pro"
}
```

---

## Organization endpoints

### List organizations

```
GET /control/v1/organizations
```

Auth: local JWT (read). Returns organizations the user belongs to.

**Query parameters**: `page_size`, `page_token`.

**Response** (200):

```json
{
  "organizations": [
    {
      "slug": 1000,
      "name": "Acme Corp",
      "region": "us-east-va",
      "status": "active",
      "tier": "free"
    }
  ],
  "next_page_token": null
}
```

### Create organization

```
POST /control/v1/organizations
```

Auth: Ledger-validated JWT (write).

**Request**:

```json
{
  "name": "Acme Corp"
}
```

**Response** (201):

```json
{
  "organization": {
    "slug": 1001,
    "name": "Acme Corp",
    "region": "us-east-va",
    "status": "active",
    "tier": "free"
  }
}
```

### Get organization

```
GET /control/v1/organizations/{org}
```

Auth: local JWT (read). User must be a member.

**Response** (200):

```json
{
  "organization": { ... }
}
```

### Update organization

```
PATCH /control/v1/organizations/{org}
```

Auth: Ledger-validated JWT (write).

**Request**:

```json
{
  "name": "Acme Inc"
}
```

**Response** (200):

```json
{
  "organization": { ... }
}
```

### Delete organization

```
DELETE /control/v1/organizations/{org}
```

Auth: Ledger-validated JWT (write). Owner only.

**Response** (200):

```json
{
  "message": "organization deleted",
  "retention_days": 90
}
```

---

## Organization member endpoints

### List members

```
GET /control/v1/organizations/{org}/members
```

Auth: local JWT (read). User must be a member.

**Query parameters**: `page_size`, `page_token`.

**Response** (200):

```json
{
  "members": [
    {
      "user": 12345,
      "role": "owner",
      "joined_at": "2025-01-01T00:00:00+00:00"
    }
  ],
  "next_page_token": null
}
```

### Update member role

```
PATCH /control/v1/organizations/{org}/members/{member}
```

Auth: Ledger-validated JWT (write).

**Request**:

```json
{
  "role": "admin"
}
```

Accepted values: `"admin"`, `"member"`. Promotion to Owner is handled separately.

**Response** (200):

```json
{
  "member": {
    "user": 12345,
    "role": "admin",
    "joined_at": "2025-01-01T00:00:00+00:00"
  }
}
```

### Remove member

```
DELETE /control/v1/organizations/{org}/members/{member}
```

Auth: Ledger-validated JWT (write).

**Response** (200):

```json
{
  "message": "member removed"
}
```

### Leave organization

```
DELETE /control/v1/organizations/{org}/members/me
```

Auth: Ledger-validated JWT (write). Fails if the user is the sole Owner.

**Response** (200):

```json
{
  "message": "left organization"
}
```

---

## Invitation endpoints

### List invitations (admin view)

```
GET /control/v1/organizations/{org}/invitations
```

Auth: local JWT (read).

**Query parameters**: `page_size`, `page_token`.

**Response** (200):

```json
{
  "invitations": [
    {
      "slug": 500,
      "organization": 1000,
      "inviter": 12345,
      "invitee_email": "new@example.com",
      "role": "member",
      "status": "pending",
      "created_at": "2025-06-01T00:00:00+00:00",
      "expires_at": "2025-06-08T00:00:00+00:00"
    }
  ],
  "next_page_token": null
}
```

### Create invitation

```
POST /control/v1/organizations/{org}/invitations
```

Auth: Ledger-validated JWT (write).

**Request**:

```json
{
  "email": "new@example.com",
  "role": "member"
}
```

`role` is optional (defaults to `"member"`). Accepted values: `"admin"`, `"member"`.

**Response** (201):

```json
{
  "invitation": { ... }
}
```

### Delete invitation

```
DELETE /control/v1/organizations/{org}/invitations/{invitation}
```

Auth: Ledger-validated JWT (write).

**Response** (200):

```json
{
  "message": "invitation revoked"
}
```

### List received invitations

```
GET /control/v1/users/me/invitations
```

Auth: local JWT (read).

**Response** (200):

```json
{
  "invitations": [
    {
      "slug": 500,
      "organization": 1000,
      "organization_name": "Acme Corp",
      "role": "member",
      "status": "pending",
      "created_at": "2025-06-01T00:00:00+00:00",
      "expires_at": "2025-06-08T00:00:00+00:00"
    }
  ],
  "next_page_token": null
}
```

### Accept invitation

```
POST /control/v1/users/me/invitations/{invitation}/accept
```

Auth: Ledger-validated JWT (write).

**Response** (200):

```json
{
  "message": "invitation accepted"
}
```

### Decline invitation

```
POST /control/v1/users/me/invitations/{invitation}/decline
```

Auth: Ledger-validated JWT (write).

**Response** (200):

```json
{
  "message": "invitation declined"
}
```

---

## Team endpoints

### List teams

```
GET /control/v1/organizations/{org}/teams
```

Auth: local JWT (read).

**Query parameters**: `page_size`, `page_token`.

**Response** (200):

```json
{
  "teams": [
    {
      "slug": 300,
      "organization": 1000,
      "name": "Engineering",
      "members": [
        {
          "user": 12345,
          "role": "manager",
          "joined_at": "2025-01-01T00:00:00+00:00"
        }
      ],
      "created_at": "2025-01-01T00:00:00+00:00",
      "updated_at": "2025-03-15T08:00:00+00:00"
    }
  ],
  "next_page_token": null
}
```

### Create team

```
POST /control/v1/organizations/{org}/teams
```

Auth: Ledger-validated JWT (write).

**Request**:

```json
{
  "name": "Engineering"
}
```

**Response** (201):

```json
{
  "team": { ... }
}
```

### Get team

```
GET /control/v1/organizations/{org}/teams/{team}
```

Auth: local JWT (read).

**Response** (200):

```json
{
  "team": { ... }
}
```

### Update team

```
PATCH /control/v1/organizations/{org}/teams/{team}
```

Auth: Ledger-validated JWT (write).

**Request**:

```json
{
  "name": "Platform Engineering"
}
```

**Response** (200):

```json
{
  "team": { ... }
}
```

### Delete team

```
DELETE /control/v1/organizations/{org}/teams/{team}
```

Auth: Ledger-validated JWT (write).

**Request** (optional body):

```json
{
  "move_members_to": 301
}
```

**Response** (200):

```json
{
  "message": "team deleted"
}
```

---

## Team member endpoints

### List team members

```
GET /control/v1/organizations/{org}/teams/{team}/members
```

Auth: local JWT (read).

**Response** (200):

```json
{
  "members": [
    {
      "user": 12345,
      "role": "manager",
      "joined_at": "2025-01-01T00:00:00+00:00"
    }
  ]
}
```

### Add team member

```
POST /control/v1/organizations/{org}/teams/{team}/members
```

Auth: Ledger-validated JWT (write).

**Request**:

```json
{
  "user": 12345,
  "role": "member"
}
```

`role` defaults to `"member"`. Accepted values: `"manager"`, `"member"`.

**Response** (201):

```json
{
  "message": "member added"
}
```

### Update team member

```
PATCH /control/v1/organizations/{org}/teams/{team}/members/{member}
```

Auth: Ledger-validated JWT (write).

**Request**:

```json
{
  "role": "manager"
}
```

**Response** (200):

```json
{
  "message": "member updated"
}
```

### Remove team member

```
DELETE /control/v1/organizations/{org}/teams/{team}/members/{member}
```

Auth: Ledger-validated JWT (write).

**Response** (200):

```json
{
  "message": "member removed"
}
```

---

## Client endpoints

### List clients

```
GET /control/v1/organizations/{org}/clients
```

Auth: local JWT (read).

**Response** (200):

```json
{
  "clients": [
    {
      "slug": 400,
      "name": "Production Backend",
      "description": "Main API server",
      "enabled": true,
      "credentials": {
        "client_secret_enabled": false,
        "mtls_ca_enabled": false,
        "mtls_self_signed_enabled": false,
        "client_assertion_enabled": true
      },
      "created_at": "2025-01-15T10:00:00+00:00",
      "updated_at": "2025-01-15T10:00:00+00:00"
    }
  ]
}
```

### Create client

```
POST /control/v1/organizations/{org}/clients
```

Auth: Ledger-validated JWT (write).

**Request**:

```json
{
  "name": "CI Pipeline",
  "description": "GitHub Actions deployment"
}
```

`description` is optional (max 1024 chars).

**Response** (201):

```json
{
  "client": { ... }
}
```

### Get client

```
GET /control/v1/organizations/{org}/clients/{client}
```

Auth: local JWT (read).

**Response** (200):

```json
{
  "client": { ... }
}
```

### Update client

```
PATCH /control/v1/organizations/{org}/clients/{client}
```

Auth: Ledger-validated JWT (write).

**Request**:

```json
{
  "name": "Staging Backend",
  "description": "Updated description"
}
```

**Response** (200):

```json
{
  "client": { ... }
}
```

### Delete client

```
DELETE /control/v1/organizations/{org}/clients/{client}
```

Auth: Ledger-validated JWT (write).

**Response** (200):

```json
{
  "message": "client deleted"
}
```

---

## Certificate endpoints

### List certificates

```
GET /control/v1/organizations/{org}/clients/{client}/certificates
```

Auth: local JWT (read).

**Response** (200):

```json
{
  "certificates": [
    {
      "slug": 600,
      "name": "prod-cert-2025",
      "enabled": true,
      "expires_at": "2026-01-15T10:00:00+00:00",
      "created_at": "2025-01-15T10:00:00+00:00"
    }
  ]
}
```

### Get certificate

```
GET /control/v1/organizations/{org}/clients/{client}/certificates/{cert}
```

Auth: local JWT (read).

**Response** (200):

```json
{
  "certificate": { ... }
}
```

### Create certificate

```
POST /control/v1/organizations/{org}/clients/{client}/certificates
```

Auth: Ledger-validated JWT (write).

**Request**:

```json
{
  "name": "prod-cert-2025",
  "expires_at": "2026-01-15T10:00:00Z"
}
```

**Response** (201):

```json
{
  "certificate": {
    "slug": 601,
    "name": "prod-cert-2025",
    "enabled": true,
    "expires_at": "2026-01-15T10:00:00+00:00",
    "created_at": "2025-06-01T12:00:00+00:00"
  },
  "private_key_pem": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
}
```

The `private_key_pem` is returned only in this response. Store it securely.

### Revoke certificate

```
DELETE /control/v1/organizations/{org}/clients/{client}/certificates/{cert}
```

Auth: Ledger-validated JWT (write).

**Response** (200):

```json
{
  "message": "certificate revoked"
}
```

### Rotate client secret

```
POST /control/v1/organizations/{org}/clients/{client}/secret/rotate
```

Auth: Ledger-validated JWT (write).

**Response** (200):

```json
{
  "secret": "<new_client_secret>"
}
```

---

## Vault endpoints

### List vaults

```
GET /control/v1/organizations/{org}/vaults
```

Auth: local JWT (read).

**Query parameters**: `page_size`, `page_token`.

**Response** (200):

```json
{
  "vaults": [
    {
      "organization": 1000,
      "slug": 2000,
      "height": 42,
      "status": "active",
      "nodes": ["node-1", "node-2", "node-3"],
      "leader": "node-1"
    }
  ],
  "next_page_token": null
}
```

### Create vault

```
POST /control/v1/organizations/{org}/vaults
```

Auth: Ledger-validated JWT (write).

**Response** (201):

```json
{
  "vault": { ... }
}
```

### Get vault

```
GET /control/v1/organizations/{org}/vaults/{vault}
```

Auth: local JWT (read).

**Response** (200):

```json
{
  "vault": { ... }
}
```

### Update vault

```
PATCH /control/v1/organizations/{org}/vaults/{vault}
```

Auth: Ledger-validated JWT (write).

**Request**:

```json
{
  "retention_policy": null
}
```

`retention_policy` is not yet supported. Providing a value returns a validation error.

**Response** (200):

```json
{
  "vault": { ... }
}
```

### Delete vault

```
DELETE /control/v1/organizations/{org}/vaults/{vault}
```

Auth: Ledger-validated JWT (write).

**Response** (200):

```json
{
  "message": "vault deleted"
}
```

---

## Vault token endpoints

### Generate vault token

```
POST /control/v1/organizations/{org}/vaults/{vault}/tokens
```

Auth: Ledger-validated JWT (write).

**Request**:

```json
{
  "app": 400,
  "scopes": ["vault:read", "vault:write"]
}
```

**Response** (200):

```json
{
  "access_token": "<jwt>",
  "refresh_token": "<token>",
  "token_type": "Bearer",
  "expires_in": 900
}
```

### Revoke vault tokens

```
DELETE /control/v1/organizations/{org}/vaults/{vault}/tokens
```

Auth: Ledger-validated JWT (write).

**Request**:

```json
{
  "app": 400
}
```

**Response** (200):

```json
{
  "revoked_count": 2
}
```

### Refresh vault token

```
POST /control/v1/tokens/refresh
```

No rate limiting.

**Request**:

```json
{
  "refresh_token": "<token>"
}
```

**Response** (200):

```json
{
  "access_token": "<jwt>",
  "refresh_token": "<new_token>",
  "token_type": "Bearer",
  "expires_in": 900
}
```

---

## Schema endpoints

### List schemas

```
GET /control/v1/organizations/{org}/vaults/{vault}/schemas
```

Auth: local JWT (read).

**Response** (200):

```json
{
  "schemas": [
    { "version": 1, "has_definition": true, "is_active": false },
    { "version": 2, "has_definition": true, "is_active": true }
  ]
}
```

### Get current schema

```
GET /control/v1/organizations/{org}/vaults/{vault}/schemas/current
```

Auth: local JWT (read).

**Response** (200):

```json
{
  "version": 2,
  "definition": { ... },
  "description": "Added user roles"
}
```

### Get schema by version

```
GET /control/v1/organizations/{org}/vaults/{vault}/schemas/{version}
```

Auth: local JWT (read).

**Response** (200):

```json
{
  "version": 1,
  "definition": { ... },
  "description": "Initial schema"
}
```

### Diff schemas

```
GET /control/v1/organizations/{org}/vaults/{vault}/schemas/diff?from=1&to=2
```

Auth: local JWT (read).

**Query parameters**: `from` (version), `to` (version).

**Response** (200):

```json
{
  "from": 1,
  "to": 2,
  "changes": [
    { "field": "users.role", "change_type": "added" },
    { "field": "documents.status", "change_type": "modified" }
  ]
}
```

### Deploy schema

```
POST /control/v1/organizations/{org}/vaults/{vault}/schemas
```

Auth: Ledger-validated JWT (write). Body limit: 1 MiB.

**Request**:

```json
{
  "definition": { ... },
  "version": 3,
  "description": "Added document permissions"
}
```

`version` is optional (auto-increments). `description` is optional.

**Response** (201):

```json
{
  "version": 3,
  "status": "deployed"
}
```

### Rollback schema

```
POST /control/v1/organizations/{org}/vaults/{vault}/schemas/rollback
```

Auth: Ledger-validated JWT (write).

**Response** (200):

```json
{
  "version": 1,
  "status": "active"
}
```

### Activate schema version

```
POST /control/v1/organizations/{org}/vaults/{vault}/schemas/{version}/activate
```

Auth: Ledger-validated JWT (write).

**Response** (200):

```json
{
  "version": 2,
  "status": "active"
}
```

---

## Audit log endpoints

### List audit logs

```
GET /control/v1/organizations/{org}/audit-logs
```

Auth: local JWT (read). User must be an organization member.

**Query parameters**:

| Parameter    | Type   | Description                                               |
| ------------ | ------ | --------------------------------------------------------- |
| `page_size`  | u32    | Items per page (1--100, default 50)                       |
| `page_token` | string | Cursor for next page                                      |
| `event_type` | string | Filter by event type prefix (e.g., `"ledger.vault"`)      |
| `principal`  | string | Filter by principal (e.g., `"user:42"`)                   |
| `outcome`    | string | Filter by outcome: `"success"`, `"failed"`, or `"denied"` |

**Response** (200):

```json
{
  "entries": [
    {
      "event_id": "550e8400-e29b-41d4-a716-446655440000",
      "event_type": "ledger.vault.created",
      "principal": "user:12345",
      "outcome": "success",
      "timestamp": "2025-06-01T12:00:00+00:00",
      "source": "control",
      "action": "vault_created",
      "details": { "vault_slug": "2000" }
    }
  ],
  "next_page_token": null,
  "total_estimate": 1
}
```

---

## Health endpoints

No authentication required.

### Liveness

```
GET /livez
```

Returns 200 if the process is running.

### Readiness

```
GET /readyz
```

Returns 200 if Ledger is reachable. Returns 503 otherwise. Results cached for 5 seconds.

### Startup

```
GET /startupz
```

Same behavior as `/readyz`. Returns 200 after initialization completes.

### Detailed health

```
GET /healthz
```

**Response** (200):

```json
{
  "status": "healthy",
  "service": "inferadb-control",
  "version": "0.1.0",
  "instance_id": 0,
  "uptime_seconds": 3600,
  "ledger_healthy": true
}
```

`status` is `"healthy"` when Ledger is reachable, `"unhealthy"` otherwise.

---

## Metrics endpoint

```
GET /metrics
```

Prometheus-format metrics. Protected by network policy (no application-level auth).

---

## Registration flow

1. `POST /control/v1/auth/email/initiate` -- send verification code
2. `POST /control/v1/auth/email/verify` -- verify code, receive `onboarding_token`
3. `POST /control/v1/auth/email/complete` -- create user, organization, and session

On completion:

- User is created with status `"active"`
- Organization is created with `tier: "free"`, `region` as specified (default `US_EAST_VA`)
- User becomes organization Owner
- Session tokens are returned for immediate use

---

## Organization lifecycle

**Creation**: Any authenticated user with a verified email can create organizations (up to 10 per user).

**Role updates**: Only Owners can promote members to Owner. Admins can promote Members to Admin. The last Owner cannot be demoted or removed.

**Invitations**: Admins and Owners can invite users. Invitations expire after 7 days. Cannot invite existing members.

**Deletion**: Owner-only. Cascades soft-delete to all members, teams, clients, and vaults. 90-day retention.

---

## Team lifecycle

**Creation**: Admins and Owners can create teams. Team names must be unique within the organization.

**Members**: Team managers can add/remove members. The user must already be an organization member.

**Deletion**: Admins and Owners only. Optionally moves members to another team via `move_members_to`.

---

## Client and certificate management

**Creating a client**: Creates a service identity (maps to a Ledger "app"). Returns the client with credential configuration.

**Certificates**: Ed25519 key pairs for JWT client assertion. The private key PEM is returned only at creation time. Multiple certificates can be active simultaneously for zero-downtime rotation.

**Rotation workflow**:

1. Create a new certificate
2. Deploy the new private key alongside the old one
3. Monitor `last_used_at` (not yet exposed in the API) to confirm migration
4. Revoke the old certificate

---

## Vault lifecycle

**Creation**: Returns vault with Raft cluster metadata (nodes, leader, height).

**Tokens**: Generate vault-scoped JWTs via `POST .../tokens`. Access tokens expire in ~15 minutes. Refresh via `POST /control/v1/tokens/refresh`.

**Schemas**: Deploy, rollback, activate, diff, and list schema versions. Schema deployment allows up to 1 MiB bodies.

**Deletion**: Soft-delete with cascading revocation of all associated tokens.

---

## Session management

- Access token cookie: 15-minute max-age, path `/`, HttpOnly, Secure, SameSite=Lax
- Refresh token cookie: 30-day max-age, path `/control/v1/auth`, HttpOnly, Secure, SameSite=Lax
- Maximum 10 concurrent sessions per user (oldest evicted)
- User session refresh token TTL: 1 hour
- Client refresh token TTL: 7 days
- `POST /control/v1/auth/revoke-all` revokes all sessions for the user

---

## Rate limiting

| Endpoint group                                        | Limit        | Window          |
| ----------------------------------------------------- | ------------ | --------------- |
| Auth endpoints (`/auth/*`, `/token`)                  | 100 requests | Per hour per IP |
| Registration (`/auth/email/complete`)                 | 5 requests   | Per day per IP  |
| Session endpoints (`/auth/logout`, `/tokens/refresh`) | No limit     | --              |

Rate-limited responses return HTTP 429 with a `Retry-After` header.

---

## Soft delete and cleanup

- Grace period: 90 days for all soft-deleted entities
- Ledger's TTL garbage collector handles automatic cleanup
- Soft-deleted entities are invisible via the API
- Cascade: deleting a user cascades to emails, sessions, passkeys, and memberships; deleting an organization cascades to teams, members, clients, and vaults

---

## Error response taxonomy

| Error code               | HTTP | Factory method                  | When                           |
| ------------------------ | ---- | ------------------------------- | ------------------------------ |
| `CONFIGURATION_ERROR`    | 500  | `Error::config(msg)`            | Invalid server configuration   |
| `STORAGE_ERROR`          | 500  | `Error::storage(msg)`           | Storage backend failure        |
| `AUTHENTICATION_ERROR`   | 401  | `Error::auth(msg)`              | Invalid or missing credentials |
| `AUTHORIZATION_ERROR`    | 403  | `Error::authz(msg)`             | Insufficient permissions       |
| `VALIDATION_ERROR`       | 400  | `Error::validation(msg)`        | Invalid request payload        |
| `NOT_FOUND`              | 404  | `Error::not_found(msg)`         | Resource does not exist        |
| `ALREADY_EXISTS`         | 409  | `Error::already_exists(msg)`    | Duplicate resource             |
| `RATE_LIMIT_EXCEEDED`    | 429  | `Error::rate_limit(msg)`        | Too many requests              |
| `TIER_LIMIT_EXCEEDED`    | 402  | `Error::tier_limit(msg)`        | Subscription limit reached     |
| `TOO_MANY_PASSKEYS`      | 400  | `Error::too_many_passkeys(max)` | Max passkeys registered        |
| `SERVICE_UNAVAILABLE`    | 503  | `Error::unavailable(msg)`       | Upstream temporarily down      |
| `EXTERNAL_SERVICE_ERROR` | 502  | `Error::external(msg)`          | External dependency error      |
| `INTERNAL_ERROR`         | 500  | `Error::internal(msg)`          | Unexpected failure             |

**StorageError mapping**:

| Storage error                      | Maps to               | HTTP |
| ---------------------------------- | --------------------- | ---- |
| `NotFound`                         | `NOT_FOUND`           | 404  |
| `Conflict` / `CasRetriesExhausted` | `ALREADY_EXISTS`      | 409  |
| `RateLimitExceeded`                | `RATE_LIMIT_EXCEEDED` | 429  |
| `RangeLimitExceeded`               | `VALIDATION_ERROR`    | 400  |
| `CircuitOpen` / `ShuttingDown`     | `SERVICE_UNAVAILABLE` | 503  |
| All others                         | `INTERNAL_ERROR`      | 500  |

---

## Configuration reference

CLI-first configuration with environment variable fallbacks. Precedence: CLI flag > env var > default.

Env var prefix: `INFERADB__CONTROL__`.

### Server

| Flag           | Env var                         | Default          | Description                               |
| -------------- | ------------------------------- | ---------------- | ----------------------------------------- |
| `--listen`     | `INFERADB__CONTROL__LISTEN`     | `127.0.0.1:9090` | HTTP bind address                         |
| `--log-level`  | `INFERADB__CONTROL__LOG_LEVEL`  | `info`           | Tracing filter (`info`, `debug`, `trace`) |
| `--log-format` | `INFERADB__CONTROL__LOG_FORMAT` | `auto`           | `auto` (detect TTY), `json`, `text`       |
| `--dev-mode`   | --                              | `false`          | Forces in-memory storage (CLI-only flag)  |

### Identity and encryption

| Flag         | Env var                       | Default             | Description                                                 |
| ------------ | ----------------------------- | ------------------- | ----------------------------------------------------------- |
| `--pem`      | `INFERADB__CONTROL__PEM`      | --                  | Ed25519 PEM for control identity (auto-generated if absent) |
| `--key-file` | `INFERADB__CONTROL__KEY_FILE` | `./data/master.key` | AES-256-GCM master key path                                 |

### Storage

| Flag                 | Env var                               | Default  | Description                                     |
| -------------------- | ------------------------------------- | -------- | ----------------------------------------------- |
| `--storage`          | `INFERADB__CONTROL__STORAGE`          | `ledger` | `memory` or `ledger`                            |
| `--ledger-endpoint`  | `INFERADB__CONTROL__LEDGER_ENDPOINT`  | --       | Ledger gRPC URL (required for `ledger`)         |
| `--ledger-client-id` | `INFERADB__CONTROL__LEDGER_CLIENT_ID` | --       | Idempotency tracking ID (required for `ledger`) |

### Email blinding

| Flag                   | Env var                                 | Default | Description                                            |
| ---------------------- | --------------------------------------- | ------- | ------------------------------------------------------ |
| `--email-blinding-key` | `INFERADB__CONTROL__EMAIL_BLINDING_KEY` | --      | 64-char hex HMAC-SHA256 key (must match Ledger config) |

### Email (SMTP)

| Flag                   | Env var                                 | Default                | Description                        |
| ---------------------- | --------------------------------------- | ---------------------- | ---------------------------------- |
| `--email-host`         | `INFERADB__CONTROL__EMAIL_HOST`         | `""`                   | SMTP host (empty = email disabled) |
| `--email-port`         | `INFERADB__CONTROL__EMAIL_PORT`         | `587`                  | SMTP port                          |
| `--email-username`     | `INFERADB__CONTROL__EMAIL_USERNAME`     | --                     | SMTP username                      |
| `--email-password`     | `INFERADB__CONTROL__EMAIL_PASSWORD`     | --                     | SMTP password                      |
| `--email-from-address` | `INFERADB__CONTROL__EMAIL_FROM_ADDRESS` | `noreply@inferadb.com` | Sender address                     |
| `--email-from-name`    | `INFERADB__CONTROL__EMAIL_FROM_NAME`    | `InferaDB`             | Sender display name                |
| `--email-insecure`     | `INFERADB__CONTROL__EMAIL_INSECURE`     | `false`                | Skip TLS verification (dev only)   |

### Frontend and WebAuthn

| Flag                | Env var                              | Default                 | Description                                  |
| ------------------- | ------------------------------------ | ----------------------- | -------------------------------------------- |
| `--frontend-url`    | `INFERADB__CONTROL__FRONTEND_URL`    | `http://localhost:3000` | Base URL for email links (no trailing slash) |
| `--webauthn-rp-id`  | `INFERADB__CONTROL__WEBAUTHN_RP_ID`  | `localhost`             | WebAuthn Relying Party domain                |
| `--webauthn-origin` | `INFERADB__CONTROL__WEBAUTHN_ORIGIN` | `http://localhost:3000` | WebAuthn origin URL (must include scheme)    |

### Infrastructure

| Flag                    | Env var                                  | Default | Description                                                |
| ----------------------- | ---------------------------------------- | ------- | ---------------------------------------------------------- |
| `--trusted-proxy-depth` | `INFERADB__CONTROL__TRUSTED_PROXY_DEPTH` | --      | Nth-from-right entry in `X-Forwarded-For`                  |
| `--worker-id`           | `INFERADB__CONTROL__WORKER_ID`           | random  | Snowflake worker ID (0--1023, must be unique per instance) |

### Validation rules

- `--ledger-endpoint` must start with `http://` or `https://`
- `--frontend-url` must start with `http://` or `https://` and must not end with `/`
- `--worker-id` must be in range 0--1023
- When `--storage=ledger`, all three `--ledger-*` required fields must be set

### Development quickstart

```bash
inferadb-control --dev-mode
```

### Production example

```bash
inferadb-control \
  --listen 0.0.0.0:9090 \
  --storage ledger \
  --ledger-endpoint https://ledger.inferadb.com \
  --ledger-client-id ctrl-01 \
  --key-file /run/secrets/master.key \
  --frontend-url https://app.inferadb.com \
  --email-host smtp.sendgrid.net \
  --email-port 587 \
  --email-username apikey \
  --email-password "$SMTP_PASSWORD" \
  --webauthn-rp-id app.inferadb.com \
  --webauthn-origin https://app.inferadb.com \
  --worker-id 0 \
  --log-format json
```
