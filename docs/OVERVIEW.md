# Management (Control Plane) API

This system serves as the Control Plane for our system, allowing users to self-service and manage their own user accounts, organizations, groups, and vaults. It communicates (server-to-server) with our @server/ using gRPC for all data operations, and exposes gRPC and REST APIs for client connections. These client connections will be from a web-based Dashboard, CLI tools, and potentially other client types in the future.

For data storage, we will support both in-memory and FoundationDB. In-memory is the default for development, and FoundationDB for production.

## Primary Keys

All entities use **Twitter Snowflake IDs** for primary keys to remain storage-layer agnostic. Snowflake IDs are:

- 64-bit integers (sortable by creation time)
- Globally unique across all entity types
- Compatible with in-memory, FoundationDB, and future storage backends
- Encoded as strings in JSON APIs to avoid JavaScript integer precision issues

### Snowflake ID Implementation

We use the [idgenerator](https://crates.io/crates/idgenerator) crate for Twitter Snowflake ID generation:

**Format**: `timestamp (41 bits) | worker_id (10 bits) | sequence (12 bits)`

**Configuration**:

- **Worker ID**: Derived from server instance (0-1023)
  - For single-instance deployments: 0
  - For multi-instance deployments: assigned via environment variable `INFERADB_MGMT_WORKER_ID`
  - Worker IDs must be statically assigned and unique across all instances
  - In Kubernetes: Use pod ordinal index from StatefulSet (e.g., `inferadb-management-0` → worker_id=0)
  - In Docker/VM: Assign via environment variable in deployment configuration
  - **Collision Detection**: On startup, register worker_id in storage with heartbeat timestamp:
    - Create ephemeral key: `workers/active/<worker_id>` with TTL (30 seconds)
    - If key already exists with recent heartbeat (< 30s ago), FAIL STARTUP with error: "Worker ID {worker_id} collision detected - another instance is running"
    - Heartbeat updates every 10 seconds during runtime
    - On graceful shutdown, delete worker key immediately
    - Stale worker keys (> 30s old) are automatically cleaned up by TTL
- **Epoch**: Custom epoch starting at `2024-01-01T00:00:00Z` (1704067200 seconds)
- **Thread Safety**: Single global `IdInstance` protected by `Mutex` or use thread-local generators
- **Uniqueness Guarantee**: Up to 4096 IDs per millisecond per worker
- **Clock Synchronization**:
  - All instances MUST use NTP or similar time synchronization (required)
  - Maximum acceptable clock skew: 1 second (configurable via `config.id_generation.max_clock_skew_ms`)
  - On startup, validate system clock against NTP server (fail-fast if skew exceeds threshold)
  - Monitor clock skew via metrics and alert if approaching threshold
  - If clock skew detected at runtime: Log warning and continue (IDs remain unique due to worker_id isolation)

**Usage**:

```rust
use idgenerator::{IdInstance, IdGeneratorOptions};

// Initialize once at startup
let options = IdGeneratorOptions::new()
    .worker_id(0)
    .worker_id_bit_len(10);
let mut id_gen = IdInstance::new(options);

// Generate IDs
let user_id = id_gen.next_id(); // Returns i64
```

**Storage**: IDs are stored as `i64` in FoundationDB and serialized as strings in JSON responses to avoid JavaScript's 53-bit integer precision limit.

## Entity Definitions

### User

Represents an individual user. Lives under the `/v1/users` API path.

**Registration**: Anyone CAN register a new User account.

**Data**:

- **id** (Snowflake ID, required): Unique identifier
- **name** (string, required): User's display name
  - Max length: 100 characters
  - Allowed characters: Unicode letters, spaces, hyphens, apostrophes (regex: `^[\p{L}\p{M}\s'-]+$`)
  - No HTML/script tags allowed
- **created_at** (DateTime UTC, required): When account was created
- **tos_accepted_at** (DateTime UTC, optional): When user last accepted Terms of Service
- **password_hash** (string, optional): Argon2id hash of password
  - When unset, password-based authentication is disabled for this user
  - Format: PHC string format (includes algorithm, parameters, salt, hash)
- **deleted_at** (DateTime UTC, optional): Soft delete timestamp
  - When set, account is considered deleted
  - 90-day grace period before cleanup
  - Users cannot be deleted if they are the only Owner of any Organization

**Constraints**:

- Users MUST have at least one verified email to perform sensitive operations
- Users cannot be deleted if they are the only Owner of any Organization (must transfer ownership or delete organizations first)

**Cascade Delete**: When soft-deleted, all associated UserSession, UserPasskey, UserEmail, and OrganizationMember entries are also soft-deleted. UserPasswordResetToken and UserEmailVerificationToken entries are immediately hard-deleted.

---

### UserEmail

Represents a unique email address for a User account. Lives under the `/v1/users/emails` API path.

**Data**:

- **id** (Snowflake ID, required): Unique identifier
- **user_id** (Snowflake ID, required): User this email belongs to
- **email** (string, required): Email address
  - Max length: 255 characters
  - Case-insensitive (stored lowercase)
  - Validation: RFC 5322 compliant, with common international characters
  - No HTML/script tags allowed
  - **MUST be globally unique** (one email cannot be used for multiple accounts)
- **primary** (boolean, required): Whether this is the user's primary email
  - Default: false
  - Only one email per user can be primary
  - First email added is automatically set as primary
- **verified_at** (DateTime UTC, optional): When email was verified
  - Unverified emails cannot be used for password reset or sensitive operations

**Constraints**:

- Each User can have multiple emails
- Exactly one email per User must be marked as `primary`
- Email addresses are globally unique (enforced at storage layer)

**Cascade Delete**: When User is deleted, all UserEmail entries are soft-deleted.

---

### UserEmailVerificationToken

Represents a token for verifying email ownership. Not exposed via REST API (internal use only).

**Data**:

- **id** (Snowflake ID, required): Unique identifier
- **user_email_id** (Snowflake ID, required): Email being verified
- **token** (string, required): Cryptographically secure random token (32 bytes, hex-encoded)
  - Must be globally unique (enforced at storage layer via index)
- **created_at** (DateTime UTC, required): When token was created
- **expires_at** (DateTime UTC, required): When token expires (24 hours from creation)

**Behavior**:

- Tokens are single-use
- Expired tokens are automatically cleaned up
- When email is successfully verified, token is hard-deleted

---

### UserPasswordResetToken

Represents a token for password reset. Not exposed via REST API (internal use only).

**Data**:

- **id** (Snowflake ID, required): Unique identifier
- **user_id** (Snowflake ID, required): User requesting password reset
- **token** (string, required): Cryptographically secure random token (32 bytes, hex-encoded)
  - Must be globally unique (enforced at storage layer via index)
- **created_at** (DateTime UTC, required): When token was created
- **expires_at** (DateTime UTC, required): When token expires (1 hour from creation)

**Behavior**:

- Tokens are single-use
- Expired tokens are automatically cleaned up
- When password is successfully reset, all UserPasswordResetToken entries for that user are hard-deleted
- All UserSession entries for that user are immediately invalidated (soft-deleted)

---

### UserPasskey

Represents a WebAuthn passkey (FIDO2 credential). Lives under the `/v1/users/passkeys` API path.

**Data**:

- **id** (Snowflake ID, required): Unique identifier
- **user_id** (Snowflake ID, required): User this passkey belongs to
- **name** (string, required): User-defined name for this passkey (e.g., "iPhone 15", "YubiKey 5")
  - Max length: 100 characters
  - Allowed characters: Unicode letters, numbers, spaces, hyphens (regex: `^[\p{L}\p{N}\s-]+$`)
  - No HTML/script tags allowed
- **credential_id** (bytes, required): WebAuthn credential ID (base64url-encoded in JSON)
- **public_key** (bytes, required): COSE-encoded public key
- **sign_count** (u32, required): Signature counter for replay attack prevention
- **aaguid** (bytes, optional): Authenticator attestation GUID
- **transports** (string array, optional): Supported transports (e.g., ["usb", "nfc", "ble", "internal"])
- **created_at** (DateTime UTC, required): When passkey was registered
- **last_used_at** (DateTime UTC, optional): Last successful authentication

**Constraints**:

- `credential_id` must be unique globally (enforced via index)
- Users can have multiple passkeys (recommended for backup)
- If a `credential_id` collision occurs during registration (extremely rare), reject the registration with error "Credential ID collision detected" and instruct the user to retry

**Cascade Delete**: When User is deleted, all UserPasskey entries are soft-deleted.

---

### UserSession

Represents an authenticated user session. Lives under the `/v1/users/sessions` API path (admin/debug only).

**Data**:

- **id** (Snowflake ID, required): Unique identifier (also used as session token)
- **user_id** (Snowflake ID, required): User this session belongs to
- **session_type** (SessionType enum, required): Type of session (WEB, CLI, SDK)
  - Determines default expiry duration
  - Used for auditing and session management
- **created_at** (DateTime UTC, required): When session was created
- **expires_at** (DateTime UTC, required): When session expires
  - Default: 30 days from creation for WEB sessions
  - Default: 90 days for CLI/SDK sessions
  - Configurable per session type
- **last_activity_at** (DateTime UTC, required): Last request using this session
- **ip_address** (string, optional): IP address of session creation
- **user_agent** (string, optional): User agent string
  - Max length: 500 characters
- **deleted_at** (DateTime UTC, optional): Soft delete timestamp
  - Sessions can be explicitly revoked by setting this

**Constraints**:

- Max concurrent sessions per user: 10 (configurable)
- Sessions are automatically expired based on `expires_at`
- Sessions use sliding window: `last_activity_at` updates on each request

**Cascade Delete**: When User is deleted, all UserSession entries are soft-deleted immediately.

---

### SessionType

Enum defining session types (hard-coded).

**Values**:

- **WEB**: Browser-based sessions
  - Default TTL: 30 days
  - Cookie-based authentication
  - Stricter CORS policies
- **CLI**: Command-line interface sessions
  - Default TTL: 90 days
  - Bearer token authentication
  - Longer expiry for developer convenience
- **SDK**: Programmatic SDK sessions
  - Default TTL: 90 days
  - Bearer token authentication
  - Used by client libraries

---

### Organization

Represents a single organization (tenant). Lives under the `/v1/organizations` API path.

**Creation**: Any User can create a new Organization.

**Data**:

- **id** (Snowflake ID, required): Unique identifier (also used as tenant ID in @server)
- **name** (string, required): Organization display name
  - Max length: 100 characters
  - Allowed characters: Unicode letters, numbers, spaces, hyphens (regex: `^[\p{L}\p{N}\s-]+$`)
  - No HTML/script tags allowed
  - **Not globally unique** (multiple organizations can have the same name)
  - **UX Note**: When displaying organization names in user interfaces, always include the organization ID or another distinguishing identifier to help users differentiate between organizations with the same name
- **tier** (OrganizationTier enum, required): Billing/feature tier
- **created_at** (DateTime UTC, required): When organization was created
- **deleted_at** (DateTime UTC, optional): Soft delete timestamp
  - 90-day grace period before cleanup
  - Organizations can only be deleted by Owners
  - All associated entities are cascaded to soft-delete

**Constraints**:

- Every Organization MUST have at least one User with Owner role
- Organizations cannot be deleted unless all Vaults are deleted first (or cascaded)

**Cascade Delete**: When soft-deleted, all associated Vault, OrganizationTeam, OrganizationMember, and OrganizationInvitation entries are also soft-deleted.

---

### OrganizationMember

Associates a User with an Organization. Lives under the `/v1/organizations/:org/members` API path.

**Data**:

- **id** (Snowflake ID, required): Unique identifier
- **organization_id** (Snowflake ID, required): Organization
- **user_id** (Snowflake ID, required): User
- **role** (OrganizationRole enum, required): Member's role (Member, Admin, Owner)
  - Default: Member
- **created_at** (DateTime UTC, required): When member was added

**Constraints**:

- Combination of `(organization_id, user_id)` must be unique
- Users CANNOT delete their own OrganizationMember if they are the only Owner in the Organization
- Users can leave an Organization by deleting their own OrganizationMember (if not the only Owner)
- At least one Owner must exist per Organization at all times

**Cascade Delete**: When Organization is deleted, all OrganizationMember entries are soft-deleted. When User is deleted, all their OrganizationMember entries are soft-deleted.

---

### Client

Represents a registered Client for an Organization using the Client Assertion pattern (OAuth 2.0 JWT Bearer, RFC 7523). A client is a logical service identity (e.g., "Production Backend", "CI/CD Pipeline") that can have multiple certificates for graceful rotation.

Clients are used for backend services, SDKs, CLIs, and any non-interactive authentication scenarios. See [AUTHENTICATION.md](AUTHENTICATION.md#4-client-assertion-recommended-for-backend-services) for complete documentation.

Lives under the `/v1/organizations/:org/clients` API path.

**Data**:

- **id** (Snowflake ID, required): Unique identifier
- **organization_id** (Snowflake ID, required): Organization this client belongs to
- **name** (string, required): User-defined name for this client (e.g., "Production Backend", "CI/CD Pipeline")
  - Max length: 100 characters
  - Allowed characters: Unicode letters, numbers, spaces, hyphens (regex: `^[\p{L}\p{N}\s-]+$`)
  - No HTML/script tags allowed
  - **Must be unique within the Organization**
- **created_at** (DateTime UTC, required): When client was created
- **created_by_user_id** (Snowflake ID, required): User who created this client
- **deleted_at** (DateTime UTC, optional): Soft delete timestamp

**Constraints**:

- Each Organization can have multiple clients (for different services)
- Max clients per organization: 50 (configurable via tier limits)
- Client names must be unique within an Organization
- Only users with `ORG_PERM_CLIENT_CREATE` permission can create clients
- At least one Client with at least one active certificate must exist per Organization at all times

**Cascade Delete**: When Organization is deleted, all Client entries are soft-deleted. When Client is deleted, all ClientCertificate entries are soft-deleted.

**Certificate Management**: Clients can have multiple active certificates simultaneously for graceful rotation. See ClientCertificate entity for details.

---

### ClientCertificate

Represents a cryptographic certificate (Ed25519 key pair) for a Client. Multiple certificates can be active simultaneously to enable zero-downtime credential rotation.

Lives under the `/v1/organizations/:org/clients/:client/certificates` API path.

**Data**:

- **id** (Snowflake ID, required): Unique identifier
- **client_id** (Snowflake ID, required): Client this certificate belongs to
- **public_key** (bytes, required): Ed25519 public key (32 bytes)
  - Exposed via JWKS endpoint for @server to verify JWTs
- **private_key** (bytes, required): Ed25519 private key (64 bytes)
  - **Exposed ONLY during creation** (one-time display for developer to save)
  - After creation, never returned by any API endpoint
  - Stored by the **client application** (backend service, SDK, CLI) to sign client assertions
  - Encrypted at rest in FoundationDB using AES-256-GCM
- **kid** (string, required): Key ID (used in JWT header)
  - Format: `org-<org_id>-client-<client_id>-cert-<cert_id>` (e.g., `org-123-client-456-cert-789`)
  - Globally unique across all organizations
- **name** (string, optional): User-defined name for this certificate (e.g., "Production US-East", "Rollout Phase 1")
  - Max length: 100 characters
  - Helps developers track which certificate is deployed where
- **created_at** (DateTime UTC, required): When certificate was created
- **created_by_user_id** (Snowflake ID, required): User who created this certificate
- **last_used_at** (DateTime UTC, optional): Last time this certificate signed a valid JWT
  - Updated when Management API validates a client assertion signed with this certificate
- **revoked_at** (DateTime UTC, optional): When certificate was revoked
  - Revoked certificates cannot sign new JWTs
  - Existing JWTs signed with revoked certificates are immediately invalid
  - Revoked certificates remain visible for 90 days for audit purposes
- **revoked_by_user_id** (Snowflake ID, optional): User who revoked this certificate
- **deleted_at** (DateTime UTC, optional): Soft delete timestamp (90-day grace period)

**Constraints**:

- Each Client can have multiple certificates
- Max active (non-revoked) certificates per client: 5 (allows graceful rotation with overlap)
- Max total certificates (including revoked) per client: 20 (older revoked certs auto-deleted)
- Only users with `ORG_PERM_CLIENT_CREATE` or `ORG_PERM_CLIENT_MANAGE` can create certificates
- Only users with `ORG_PERM_CLIENT_REVOKE` or `ORG_PERM_CLIENT_MANAGE` can revoke certificates
- At least one active (non-revoked) certificate must exist per Client at all times
- Cannot delete a certificate if it's the last active certificate for the client

**Cascade Delete**: When Client is deleted, all ClientCertificate entries are soft-deleted.

**Cleanup**: Revoked certificates older than 90 days are automatically hard-deleted by background job.

**Security**:

- Private keys are encrypted at rest using AES-256-GCM with a master key derived from `INFERADB_MGMT_KEY_ENCRYPTION_SECRET`
- Private keys should be stored securely by client applications (e.g., HashiCorp Vault, AWS Secrets Manager)
- Client applications use private keys to sign short-lived JWT assertions (max 60 seconds TTL)
- Management API validates client assertions using the certificate's public_key
- Certificate rotation is recommended every 90 days (logged warnings but not enforced)
- JWKS endpoint returns all active (non-revoked) certificates for a client

---

### OrganizationRole

Enum defining Organization membership roles (hard-coded).

**Values**:

- **MEMBER**: Basic member
  - Can view organization details
  - Can view teams they are a member of
  - Can view vaults they have access to
  - Can use vaults they have access to via @server API
- **ADMIN**: Administrator
  - All Member permissions, plus:
  - Can create and manage Teams
  - Can invite users to the Organization
  - Can create Vaults
  - Can manage Vault access for teams and members
  - Can update Organization details (name)
  - Cannot delete Organization or manage billing
- **OWNER**: Owner
  - All Admin permissions, plus:
  - Can delete the Organization
  - Can manage billing and change OrganizationTier
  - Can promote/demote members to/from Admin or Owner roles
  - Can remove other Owners (if not the last Owner)

**Promotion Rules**:

- Members can be promoted to Admin by Owners
- Admins can be promoted to Owner by Owners
- Owners can demote other Owners (if multiple Owners exist)

---

### OrganizationInvitation

Represents an invitation for a User to join an Organization. Lives under the `/v1/organizations/:org/invitations` API path.

**Data**:

- **id** (Snowflake ID, required): Unique identifier
- **organization_id** (Snowflake ID, required): Organization extending the invitation
- **invited_by_user_id** (Snowflake ID, required): User who sent the invitation
- **email** (string, required): Email address being invited
  - Case-insensitive
  - Can invite existing users or users who haven't registered yet
- **role** (OrganizationRole enum, required): Role the invitee will receive
  - Default: Member
  - Can be Member or Admin (not Owner - Owners must be promoted by existing Owners)
- **token** (string, required): Cryptographically secure random token (32 bytes, hex-encoded)
  - Must be globally unique across all invitations (enforced at storage layer)
  - Used as the acceptance link parameter
- **created_at** (DateTime UTC, required): When invitation was sent
- **expires_at** (DateTime UTC, required): When invitation expires (7 days from creation)

**Behavior**:

- Invitations are **single-use**
- When accepted, an OrganizationMember is created and the invitation is hard-deleted
- Invitations can be **revoked** (hard-deleted) by Admins or Owners before acceptance
- Expired invitations are automatically cleaned up
- Invitations can be sent via:
  - **Email**: Automated email with acceptance link
  - **Link**: Share invitation link directly (contains token)

**Constraints**:

- Only Admins and Owners can create invitations
- Cannot invite a user who is already a member
- Max pending invitations per organization: 100 (configurable per tier)

**Cascade Delete**: When Organization is deleted, all OrganizationInvitation entries are hard-deleted immediately.

---

### OrganizationTier

Enum defining Organization billing/feature tiers (hard-coded).

**Values**:

#### TIER_DEV_V1 (Free tier for experimentation)

- **Max users**: 5
- **Max teams**: 3
- **Max vaults**: 5
- **Management API rate limits** (per org, per hour):
  - User operations: 1,000 requests
  - Organization operations: 500 requests
  - Vault operations: 2,000 requests
- **Server API rate limits** (per org, per hour):
  - Relationship writes: 10,000 requests
  - Evaluation checks: 100,000 requests

#### TIER_PRO_V1 (Subscription tier for startups)

- **Max users**: 50
- **Max teams**: 20
- **Max vaults**: 50
- **Management API rate limits** (per org, per hour):
  - User operations: 10,000 requests
  - Organization operations: 5,000 requests
  - Vault operations: 20,000 requests
- **Server API rate limits** (per org, per hour):
  - Relationship writes: 100,000 requests
  - Evaluation checks: 1,000,000 requests
- **Overage billing**: Available for Server API usage beyond base limits

#### TIER_MAX_V1 (Subscription tier for enterprises)

- **Max users**: 500
- **Max teams**: 100
- **Max vaults**: 200
- **Management API rate limits** (per org, per hour):
  - User operations: 50,000 requests
  - Organization operations: 25,000 requests
  - Vault operations: 100,000 requests
- **Server API rate limits** (per org, per hour):
  - Relationship writes: 1,000,000 requests
  - Evaluation checks: 10,000,000 requests
- **Overage billing**: Available with higher baselines before charges begin

**Notes**:

- Rate limits are enforced at the @server data plane API layer
- Limits are measured per organization per hour (rolling window)
- These values are initial estimates and should be easily configurable for future adjustments
- Billing integration hooks will be added in the future

---

### OrganizationTeam

Represents a team (group of users) within an Organization. Lives under the `/v1/organizations/:org/teams` API path.

**Data**:

- **id** (Snowflake ID, required): Unique identifier
- **organization_id** (Snowflake ID, required): Organization this team belongs to
- **name** (string, required): Team display name
  - Max length: 100 characters
  - Allowed characters: Unicode letters, numbers, spaces, hyphens (regex: `^[\p{L}\p{N}\s-]+$`)
  - No HTML/script tags allowed
  - **Must be unique within the Organization**
- **created_at** (DateTime UTC, required): When team was created

**Constraints**:

- Team names must be unique within an Organization (but can be duplicated across different Organizations)
- Teams cannot be nested (flat structure only)
- Only Admins and Owners can create teams

**Cascade Delete**: When Organization is deleted, all OrganizationTeam entries are soft-deleted.

---

### OrganizationTeamMember

Associates a User with a Team. Lives under the `/v1/organizations/:org/teams/:team/members` API path.

**Data**:

- **id** (Snowflake ID, required): Unique identifier
- **team_id** (Snowflake ID, required): Team
- **user_id** (Snowflake ID, required): User (must be an OrganizationMember of the parent Organization)
- **manager** (boolean, required): Whether user is a team manager
  - Default: false
  - Team managers can add/remove team members

**Constraints**:

- Combination of `(team_id, user_id)` must be unique
- User must already be an OrganizationMember of the team's Organization
- Only team managers, Admins, and Owners can modify team membership

**Cascade Delete**: When Team or User is deleted, OrganizationTeamMember entries are soft-deleted.

---

### OrganizationTeamPermission

Grants a Team specific administrative permissions within an Organization. Lives under the `/v1/organizations/:org/teams/:team/permissions` API path.

**Purpose**: Enables delegating administrative capabilities to teams without granting full Admin or Owner roles. This allows organizations to implement least-privilege access control for sensitive operations like Client management.

**Data**:

- **id** (Snowflake ID, required): Unique identifier
- **team_id** (Snowflake ID, required): Team receiving these permissions
- **permission** (OrganizationPermission enum, required): Specific permission granted to this team
- **granted_by_user_id** (Snowflake ID, required): User who granted this permission (must be Owner)
- **granted_at** (DateTime UTC, required): When permission was granted

**Constraints**:

- Combination of `(team_id, permission)` must be unique (each permission can only be granted once per team)
- Team must belong to the same Organization
- Only Owners can grant or revoke organization-level team permissions
- Granting `ORG_PERM_OWNER_ACTIONS` requires special confirmation (high-risk permission)

**Cascade Delete**: When Team is deleted, all OrganizationTeamPermission entries are hard-deleted.

**Permission Precedence**:

- If a User has direct OrganizationMember role of Admin or Owner, they have all permissions regardless of team permissions
- If a User is a Member but belongs to a team with specific permissions, they gain those permissions
- Multiple teams: User gains the union of all permissions from all their teams

---

### OrganizationPermission

Enum defining organization-level permissions that can be delegated to teams (hard-coded).

**Client Management Permissions**:

- **ORG_PERM_CLIENT_READ**: View existing Clients (list, read details, view public keys)
  - **Allows**: `GET /v1/organizations/:org/clients`, `GET /v1/organizations/:org/clients/:client`
  - **Denies**: Cannot view private keys (never returned by API anyway)
  - **Use case**: Security audit, monitoring which clients exist

- **ORG_PERM_CLIENT_CREATE**: Create new Clients
  - **Allows**: `POST /v1/organizations/:org/clients`
  - **Grants**: Private key is shown once on creation (team member must save securely)
  - **Use case**: DevOps teams provisioning new service accounts

- **ORG_PERM_CLIENT_ROTATE**: Rotate Client credentials (create new, revoke old)
  - **Allows**: `POST /v1/organizations/:org/clients/:client/rotate`
  - **Security**: Atomic operation (both create new and revoke old succeed or both fail)
  - **Use case**: Security team enforcing credential rotation policies

- **ORG_PERM_CLIENT_REVOKE**: Revoke existing Clients (non-destructive, can be reversed by creating new client)
  - **Allows**: `POST /v1/organizations/:org/clients/:client/revoke`
  - **Note**: Cannot un-revoke, but can create new client to restore access
  - **Use case**: Security incident response team

- **ORG_PERM_CLIENT_DELETE**: Permanently delete Clients (destructive, cannot be undone)
  - **Allows**: `DELETE /v1/organizations/:org/clients/:client`
  - **Security**: Requires confirmation parameter to prevent accidental deletion
  - **Use case**: Cleanup of deprecated service accounts

- **ORG_PERM_CLIENT_MANAGE**: Full Client management (combination of all above)
  - **Grants**: All Client-related permissions (READ, CREATE, ROTATE, REVOKE, DELETE)
  - **Use case**: Dedicated security/platform team managing all service accounts

**Vault Management Permissions**:

- **ORG_PERM_VAULT_CREATE**: Create new Vaults
  - **Allows**: `POST /v1/vaults` (with organization_id matching the team's org)
  - **Automatically grants**: Creator receives VAULT_ROLE_ADMIN on created vault
  - **Use case**: Engineering teams creating vaults for new projects

- **ORG_PERM_VAULT_DELETE**: Delete Vaults
  - **Allows**: `DELETE /v1/vaults/:vault` (vault must belong to same org)
  - **Requires**: User must also have VAULT_ROLE_ADMIN on the specific vault
  - **Use case**: Engineering leads cleaning up obsolete vaults

**Team Management Permissions**:

- **ORG_PERM_TEAM_CREATE**: Create new Teams
  - **Allows**: `POST /v1/organizations/:org/teams`
  - **Use case**: HR or team leads organizing people

- **ORG_PERM_TEAM_DELETE**: Delete Teams
  - **Allows**: `DELETE /v1/organizations/:org/teams/:team`
  - **Restriction**: Cannot delete team with active VaultTeamGrant entries (must revoke vault access first)
  - **Use case**: Cleanup of dissolved teams

- **ORG_PERM_TEAM_MANAGE_MEMBERS**: Add/remove members from Teams
  - **Allows**: `POST /v1/organizations/:org/teams/:team/members`, `DELETE /v1/organizations/:org/teams/:team/members/:member`
  - **Use case**: Team leads managing their team membership

**Invitation Permissions**:

- **ORG_PERM_INVITE_USERS**: Send invitations to join the Organization
  - **Allows**: `POST /v1/organizations/:org/invitations`
  - **Restriction**: Can only invite as Member role (not Admin or Owner)
  - **Use case**: Team leads onboarding new team members

- **ORG_PERM_REVOKE_INVITATIONS**: Revoke pending invitations
  - **Allows**: `DELETE /v1/organizations/:org/invitations/:invitation`
  - **Use case**: Revoking invitations for candidates who declined

**High-Privilege Permissions** (Require Owner role to grant):

- **ORG_PERM_OWNER_ACTIONS**: Perform Owner-level actions (billing, tier changes, organization deletion)
  - **Allows**: Update OrganizationTier, delete Organization, manage billing settings
  - **Security**: Requires explicit confirmation when granting (displays warning about scope)
  - **Use case**: Finance team managing billing, very rare delegation

**Permission Hierarchy**:

Permissions do NOT inherit - each must be explicitly granted. However, role-based permissions override:

- **Owner**: Has all permissions automatically (cannot be restricted)
- **Admin**: Has all permissions except `ORG_PERM_OWNER_ACTIONS`
- **Member**: Has no permissions by default (must be granted via team)

**Combining Permissions**:

Users can accumulate permissions from multiple sources:

1. Direct OrganizationMember role (Member, Admin, Owner)
2. OrganizationTeamPermission grants from all teams they belong to
3. Final permission set = Union of all sources

---

### Vault

Represents an authorization vault (tenant in @server). Lives under the `/v1/vaults` API path.

**Data**:

- **id** (Snowflake ID, required): Unique identifier (also used as tenant/vault ID in @server)
- **organization_id** (Snowflake ID, required): Organization this vault belongs to
- **name** (string, required): Vault display name
  - Max length: 100 characters
  - Allowed characters: Unicode letters, numbers, spaces, hyphens, underscores (regex: `^[\p{L}\p{N}\s_-]+$`)
  - No HTML/script tags allowed
  - **Must be unique within the Organization**
- **created_at** (DateTime UTC, required): When vault was created
- **updated_at** (DateTime UTC, required): Last time vault metadata was updated
- **sync_status** (VaultSyncStatus enum, required): Synchronization status with @server
  - Values: PENDING, SYNCED, FAILED
- **deleted_at** (DateTime UTC, optional): Soft delete timestamp
  - 90-day grace period before cleanup

**Constraints**:

- Vault names must be unique within an Organization (but can be duplicated across different Organizations)
- Only Admins and Owners can create vaults
- Vaults must be synchronized with @server in real-time upon creation

**Cascade Delete**: When Organization is deleted, all Vault entries are soft-deleted. When Vault is deleted, all VaultTeamGrant and VaultUserGrant entries are soft-deleted.

---

### VaultSyncStatus

Enum for vault synchronization status with @server (hard-coded).

**Values**:

- **PENDING**: Vault created in Management API, awaiting @server sync
- **SYNCED**: Vault successfully created in @server
- **FAILED**: @server sync failed (requires retry or manual intervention)

---

### VaultTeamGrant

Grants a Team access to a Vault. Lives under the `/v1/vaults/:vault/team-grants` API path.

**Data**:

- **id** (Snowflake ID, required): Unique identifier
- **vault_id** (Snowflake ID, required): Vault
- **team_id** (Snowflake ID, required): Team (must belong to same Organization as Vault)
- **role** (VaultRole enum, required): Access role granted to team
- **granted_at** (DateTime UTC, required): When access was granted

**Constraints**:

- Combination of `(vault_id, team_id)` must be unique
- Team must belong to the same Organization as the Vault
- Only Admins and Owners can grant team access

**Cascade Delete**: When Vault or Team is deleted, VaultTeamGrant entries are soft-deleted.

---

### VaultUserGrant

Grants a User direct access to a Vault. Lives under the `/v1/vaults/:vault/user-grants` API path.

**Data**:

- **id** (Snowflake ID, required): Unique identifier
- **vault_id** (Snowflake ID, required): Vault
- **user_id** (Snowflake ID, required): User (must be a member of the Vault's Organization)
- **role** (VaultRole enum, required): Access role granted to user
- **granted_at** (DateTime UTC, required): When access was granted

**Constraints**:

- Combination of `(vault_id, user_id)` must be unique
- User must be a member of the Vault's Organization
- Only Admins and Owners can grant user access

**Permission Precedence**: If a User has both VaultTeamGrant (via team membership) and VaultUserGrant (direct), the **highest permission** is granted.

**Cascade Delete**: When Vault or User is deleted, VaultUserGrant entries are soft-deleted.

---

### VaultRole

Enum defining Vault access roles (hard-coded).

**Values**:

- **VAULT_ROLE_READER**: Read-only access
  - Can query relationships via @server API
  - Can perform authorization checks via @server API
  - Cannot modify anything

- **VAULT_ROLE_WRITER**: Read and write access
  - All Reader permissions, plus:
  - Can write relationships via @server API
  - Can delete relationships via @server API
  - Cannot modify vault schema/policy or manage access

- **VAULT_ROLE_MANAGER**: Policy management access
  - All Writer permissions, plus:
  - Can read and write vault policy/schema
  - Can view vault access grants
  - Cannot perform destructive operations (clear all relationships, delete vault)

- **VAULT_ROLE_ADMIN**: Full administrative access
  - All Manager permissions, plus:
  - Can clear all relationships in vault (destructive)
  - Can delete the vault
  - Can manage vault access for users and teams

---

### VaultRefreshToken

Represents a refresh token for vault-scoped JWTs. Enables long-running operations and background jobs to refresh their Server API access tokens without re-authenticating. Not exposed via REST API (internal use only).

**Data**:

- **id** (Snowflake ID, required): Unique identifier
- **token** (string, required): Cryptographically secure random token (32 bytes, hex-encoded)
  - Must be globally unique (enforced at storage layer via index)
  - Used to refresh expired vault JWTs
- **vault_id** (Snowflake ID, required): Vault this refresh token grants access to
- **organization_id** (Snowflake ID, required): Organization (for efficient queries)
- **vault_role** (VaultRole enum, required): Permission level cached at issuance time
  - Determines permissions in refreshed JWTs
  - Should match user's current vault access at token issuance
- **user_session_id** (Snowflake ID, optional): User session if issued via user authentication
  - Mutually exclusive with `org_api_key_id`
  - Set when refresh token is issued to an authenticated user
- **org_api_key_id** (Snowflake ID, optional): API key if issued via organization API key
  - Mutually exclusive with `user_session_id`
  - Set when refresh token is issued to a CI/CD or automation client
- **created_at** (DateTime UTC, required): When refresh token was created
- **expires_at** (DateTime UTC, required): When refresh token expires
  - 24 hours for user session tokens
  - 7 days for API key tokens (supports periodic background jobs)
- **used_at** (DateTime UTC, optional): When refresh token was used (single-use)
  - Set on first successful refresh
  - Subsequent refresh attempts with same token are rejected
- **revoked_at** (DateTime UTC, optional): When refresh token was revoked
  - Set when parent auth context is invalidated
  - Revoked tokens cannot be used for refresh

**Constraints**:

- Exactly one of `user_session_id` or `org_api_key_id` must be set (not both, not neither)
- Token must be globally unique across all refresh tokens
- Single-use: Once `used_at` is set, token cannot be used again
- Revocation cascades from parent authentication context

**Behavior**:

- **Token Rotation**: Each successful refresh generates a new refresh token and invalidates the old one
- **Binding to Auth Context**: Refresh tokens are bound to their parent authentication:
  - User session tokens: Revoked when UserSession is revoked or expires
  - Client tokens: Revoked when Client is revoked
- **Permission Changes**: Refresh tokens do NOT automatically reflect permission changes
  - If user's vault access is revoked, refresh token remains valid until expiry
  - Clients should handle 403 errors and re-authenticate to get updated permissions
- **Cleanup**: Expired and used refresh tokens are cleaned up by background job after 7 days

**Security Properties**:

- Single-use with automatic rotation prevents replay attacks
- Short expiry (24 hours for users, 7 days for API keys) limits exposure window
- Bound to parent authentication context (cannot outlive parent)
- Cryptographically random token (32 bytes) prevents guessing attacks

**Cascade Delete**:

- When UserSession is deleted: All refresh tokens with matching `user_session_id` are revoked
- When Client is deleted: All refresh tokens with matching `org_api_key_id` are revoked
- When Vault is deleted: All refresh tokens for that vault are revoked
- When VaultUserGrant/VaultTeamGrant is removed: Refresh tokens remain valid (permission changes require re-authentication)

---

### AuditLog

Represents a security audit event for tracking authentication events, permission changes, and sensitive operations. Not directly exposed via REST API (admin/debug access only via `/v1/audit-logs` endpoint).

**Data**:

- **id** (Snowflake ID, required): Unique identifier
- **organization_id** (Snowflake ID, optional): Organization this event belongs to (null for user-level events)
- **user_id** (Snowflake ID, optional): User who performed the action (null for system/automated events)
- **client_id** (Snowflake ID, optional): Client (API key) that performed the action (mutually exclusive with user_id for client-initiated events)
- **event_type** (AuditEventType enum, required): Type of event being logged
- **resource_type** (string, optional): Type of resource affected (e.g., "vault", "organization", "user")
- **resource_id** (Snowflake ID, optional): ID of affected resource
- **event_data** (JSON, optional): Additional event-specific data
  - Flexible JSON field for storing context-specific information
  - Examples: {"old_role": "MEMBER", "new_role": "ADMIN"}, {"ip_address": "203.0.113.1"}
- **ip_address** (string, optional): IP address of request that triggered this event
- **user_agent** (string, optional): User agent string
  - Max length: 500 characters
- **created_at** (DateTime UTC, required): When event occurred

**Constraints**:

- Events are immutable (no updates or deletes after creation)
- Retention: 90 days for free tier, 1 year for paid tiers (configurable)
- At most one of `user_id` or `client_id` should be set (events are either user-initiated or client-initiated)

**Indexes**:

- `organization_id` + `created_at` (for organization audit queries)
- `user_id` + `created_at` (for user activity queries)
- `event_type` + `created_at` (for event filtering)

**Cascade Delete**: When Organization is deleted, all AuditLog entries for that organization are retained (not deleted) for audit trail compliance.

---

### AuditEventType

Enum defining types of audit events (hard-coded).

**Authentication Events**:

- **USER_LOGIN_SUCCESS**: User successfully authenticated
- **USER_LOGIN_FAILED**: User authentication attempt failed
- **USER_LOGOUT**: User explicitly logged out
- **SESSION_EXPIRED**: User session expired
- **SESSION_REVOKED**: User session manually revoked
- **PASSKEY_ADDED**: User registered a new passkey
- **PASSKEY_REMOVED**: User removed a passkey
- **PASSWORD_CHANGED**: User changed their password
- **PASSWORD_RESET_REQUESTED**: User requested password reset
- **PASSWORD_RESET_COMPLETED**: User completed password reset

**Permission Change Events**:

- **VAULT_ACCESS_GRANTED**: User or team granted access to vault (VaultUserGrant/VaultTeamGrant created)
- **VAULT_ACCESS_REVOKED**: User or team access to vault revoked
- **VAULT_ACCESS_ROLE_CHANGED**: User or team vault access role updated
- **ORG_MEMBER_ADDED**: User added to organization
- **ORG_MEMBER_REMOVED**: User removed from organization
- **ORG_MEMBER_ROLE_CHANGED**: Organization member role updated
- **TEAM_MEMBER_ADDED**: User added to team
- **TEAM_MEMBER_REMOVED**: User removed from team
- **TEAM_PERMISSION_GRANTED**: Organization permission granted to team
- **TEAM_PERMISSION_REVOKED**: Organization permission revoked from team

**Resource Management Events**:

- **VAULT_CREATED**: New vault created
- **VAULT_DELETED**: Vault deleted
- **ORGANIZATION_CREATED**: New organization created
- **ORGANIZATION_DELETED**: Organization deleted
- **CLIENT_CREATED**: New client created
- **CLIENT_DELETED**: Client deleted
- **CLIENT_CERTIFICATE_CREATED**: New certificate generated for client
- **CLIENT_CERTIFICATE_REVOKED**: Certificate revoked
- **CLIENT_CERTIFICATE_DELETED**: Certificate deleted

**Security Events**:

- **REFRESH_TOKEN_REUSE_DETECTED**: Attempted reuse of single-use refresh token (possible token theft)
- **INVALID_JWT_SIGNATURE**: JWT with invalid signature rejected
- **EXPIRED_TOKEN_USED**: Attempt to use expired token
- **RATE_LIMIT_EXCEEDED**: Rate limit threshold exceeded
- **SUSPICIOUS_LOGIN_BLOCKED**: Login attempt blocked due to suspicious activity

---

## Behavioral Rules

### When a new User is registered

1. Create the User entity
2. Create UserEmail (unverified, primary=true)
3. Generate UserEmailVerificationToken and send verification email
4. Create a new Organization with:
   - Name: Same as User's name
   - Tier: TIER_DEV_V1
5. Create an OrganizationMember linking User to Organization with role=OWNER
6. Generate first Client for the organization (name="Default Client")
7. Create UserSession and return session_id for immediate use

### When a new Organization is created

1. Create an OrganizationMember for the creating User with role=OWNER
2. Generate first Client for the organization (name="Default Client")
3. User must have at least one verified email (enforced)

### When a new OrganizationTeam is created

1. Must be bound to an Organization (from URL path: `/v1/organizations/:org/teams`)
2. Validate that team name is unique within the Organization
3. Only Admins and Owners can create teams (or Members with `ORG_PERM_TEAM_CREATE` via team grant)

### When OrganizationTeamPermission is granted

1. Validate requesting user is an Owner (only Owners can grant organization-level permissions)
2. Validate team belongs to the same Organization
3. Check if permission already granted (unique constraint on `(team_id, permission)`)
4. **Special handling for ORG_PERM_OWNER_ACTIONS**:
   - Require explicit confirmation parameter (e.g., `confirm_owner_delegation=true`)
   - Display warning in Dashboard: "This grants full Owner privileges including billing and organization deletion"
   - Log AuditEventType::TEAM_PERMISSION_GRANTED with high-severity flag
5. Create OrganizationTeamPermission entry
6. Log audit event for security tracking

### When checking if user has organization permission

**Permission Resolution Algorithm**:

```rust
fn user_has_org_permission(
    user_id: UserId,
    org_id: OrgId,
    permission: OrganizationPermission
) -> Result<bool> {
    // 1. Check direct role (Owner/Admin bypass team permissions)
    let member = get_org_member(user_id, org_id)?;

    if member.role == OrganizationRole::OWNER {
        return Ok(true); // Owners have all permissions
    }

    if member.role == OrganizationRole::ADMIN {
        // Admins have all permissions EXCEPT ORG_PERM_OWNER_ACTIONS
        if permission == OrganizationPermission::ORG_PERM_OWNER_ACTIONS {
            return Ok(false);
        }
        return Ok(true);
    }

    // 2. Member role - check team permissions
    // Get all teams user belongs to in this organization
    let user_teams = get_user_teams_in_org(user_id, org_id)?;

    // Check if any team has the requested permission
    for team in user_teams {
        let team_perms = get_team_permissions(team.id)?;

        // Check exact permission match
        if team_perms.contains(&permission) {
            return Ok(true);
        }

        // Check for composite permissions (e.g., ORG_PERM_CLIENT_MANAGE grants all client perms)
        if permission.is_client_permission() && team_perms.contains(&OrganizationPermission::ORG_PERM_CLIENT_MANAGE) {
            return Ok(true);
        }
    }

    Ok(false) // No permission found
}
```

### When Client operations are requested

**Authorization checks** (before performing operation):

- **List Clients** (`GET /v1/organizations/:org/clients`):
  - Requires: Owner, Admin, OR `ORG_PERM_CLIENT_READ`

- **Get Client details** (`GET /v1/organizations/:org/clients/:client`):
  - Requires: Owner, Admin, OR `ORG_PERM_CLIENT_READ`

- **Create Client** (`POST /v1/organizations/:org/clients`):
  - Requires: Owner, Admin, OR `ORG_PERM_CLIENT_CREATE` OR `ORG_PERM_CLIENT_MANAGE`
  - Log AuditEventType::CLIENT_CREATED with creating user

- **Create certificate** (`POST /v1/organizations/:org/clients/:client/certificates`):
  - Requires: Owner, Admin, OR `ORG_PERM_CLIENT_CREATE` OR `ORG_PERM_CLIENT_MANAGE`
  - Enables graceful zero-downtime rotation

- **Revoke certificate** (`POST /v1/organizations/:org/clients/:client/certificates/:cert/revoke`):
  - Requires: Owner, Admin, OR `ORG_PERM_CLIENT_REVOKE` OR `ORG_PERM_CLIENT_MANAGE`
  - Cannot revoke last active certificate (must generate new one first)

- **Delete Client** (`DELETE /v1/organizations/:org/clients/:client`):
  - Requires: Owner, Admin, OR `ORG_PERM_CLIENT_DELETE` OR `ORG_PERM_CLIENT_MANAGE`
  - Require confirmation parameter: `?confirm_delete=<client_id>`
  - Log AuditEventType::CLIENT_DELETED

### When a new Vault is created

1. Must be bound to an Organization
2. Validate that vault name is unique within the Organization
3. Set `sync_status = PENDING`
4. Initiate real-time gRPC call to @server to create vault there
5. On success: Update `sync_status = SYNCED`
6. On failure: Update `sync_status = FAILED` and return error to client
7. Grant the creating User VAULT_ROLE_ADMIN access automatically via VaultUserGrant
8. Only Admins and Owners can create vaults

### When a new VaultTeamGrant is created

1. Must reference a Vault and Team from the same Organization
2. Validate uniqueness of (vault_id, team_id) pair
3. Only Admins and Owners can grant team access

### When a new VaultUserGrant is created

1. Must reference a Vault and User where User is a member of Vault's Organization
2. Validate uniqueness of (vault_id, user_id) pair
3. Only Admins and Owners can grant user access

### When a Vault is deleted

1. Soft-delete Vault entity (set deleted_at)
2. Initiate real-time gRPC call to @server to delete vault data
3. On success:
   - Mark all relationships and data as deleted in @server
   - Cascade soft-delete all VaultTeamGrant and VaultUserGrant entries
4. On failure:
   - Log error with vault_id and error details
   - Keep Vault in deleted state (manual cleanup required)
   - Set sync_status = FAILED
   - Cascade soft-delete all VaultTeamGrant and VaultUserGrant entries anyway
   - Vault name remains unavailable for reuse until hard-deleted (90-day grace period)
5. Only users with VAULT_ROLE_ADMIN can delete vaults

**Note on name reuse**: Vault names are scoped to (organization_id, name) uniqueness. Soft-deleted vaults in grace period still occupy their name slot. After 90-day hard deletion, the name becomes available for reuse.

**Important**: If an Admin wants to immediately reuse a vault name, they cannot do so while the old vault is in the 90-day grace period. This is intentional to prevent accidental data access confusion during recovery. If immediate name reuse is critical, the Admin must either:

- Wait for the 90-day grace period to expire, OR
- Contact support to manually hard-delete the vault (only after confirming no recovery is needed)

### When an OrganizationInvitation is accepted

1. Validate token is not expired
2. Lookup or create User account if email doesn't exist yet:
   - If User doesn't exist:
     - Create User entity (with password_hash=null if no password provided)
     - Create UserEmail (unverified, primary=true) with the invited email
     - Generate and send UserEmailVerificationToken for email verification
   - If User exists: Validate email matches an existing UserEmail (verified or unverified)
3. Create OrganizationMember with the role specified in invitation
4. Hard-delete the OrganizationInvitation (single-use)
5. Send notification email to user confirming they joined the organization

**Note**: UserEmailVerificationToken is used ONLY for verifying ownership of email addresses for existing users. When accepting an invitation creates a new User, the verification token is sent separately and is not part of the invitation flow itself.

### When OrganizationMember role is updated

1. Only Owners can promote to Owner role
2. Only Owners can demote from Owner role
3. Cannot demote the last Owner (must have at least 1 Owner)
4. Admins can promote Members to Admin
5. Owners can promote Members or Admins to Owner

### When Organization ownership is transferred

**Endpoint**: `POST /v1/organizations/:org/transfer-ownership`

**Behavior**:

1. Validate that the requesting user is an Owner of the organization
2. Validate that the target user (new owner) is already an OrganizationMember of this organization
3. If target user is not already an Owner:
   - Update their OrganizationMember.role to OWNER
4. The requesting user (current owner) has three options (specified in request):
   - **remain_owner**: Keep Owner role (organization will have multiple Owners)
   - **demote_to_admin**: Demote to Admin role
   - **leave_organization**: Remove their OrganizationMember entry (leave the org entirely)
5. If requesting user chooses to leave and they are the last Owner, the transfer will fail (must complete transfer first)
6. No consent required from target user (they're already a member)
7. Log this action in audit trail for security purposes

### When an OrganizationMember is removed

1. User cannot remove themselves if they are the only Owner
2. When a user leaves: Remove all VaultUserGrant for vaults in that organization
3. When a user is removed from a team: Remove all VaultTeamGrant indirectly granted
4. Soft-delete the OrganizationMember entry

### When a User tries to login with email

1. Lookup UserEmail by email address (case-insensitive)
2. If multiple UserEmail entries exist with same email (should be impossible due to uniqueness constraint), return error
3. For password login: Verify User.password_hash exists
4. For passkey login: Return all UserPasskey entries for that user's email

### When VaultUserGrant and VaultTeamGrant conflict

1. Grant the **highest permission level** to the user
2. Example: User has VAULT_ROLE_READER via team, but VAULT_ROLE_WRITER via direct access → User gets VAULT_ROLE_WRITER
3. Permission precedence (highest to lowest): VAULT_ROLE_ADMIN > VAULT_ROLE_MANAGER > VAULT_ROLE_WRITER > VAULT_ROLE_READER

### When soft-deleted entities should become visible

1. Soft-deleted entities are **never visible** via API endpoints (treated as non-existent)
2. Soft-deleted entities are only accessible via admin/debug endpoints (not exposed to users)
3. After 90-day grace period, background cleanup job performs hard deletion

### When a UserEmail is set as primary

1. Unset primary flag on all other UserEmail entries for that user (only one can be primary)
2. User can change primary email at any time
3. Primary email is used for all outgoing notifications and password reset emails

### When a UserEmail is deleted

1. **Cannot delete the last verified email**: If user has only one verified email, deletion is rejected with error: "Cannot delete your only verified email. Add and verify another email first."
2. **Can delete unverified emails** at any time (no minimum required)
3. **If deleting primary email**: Automatically promote another verified email to primary (if available)
   - Selection priority: Most recently verified email becomes primary
   - If no other verified emails exist, user must verify another email before deletion
4. **Account security**: Users with no verified emails have limited functionality (see User Registration Flow)
5. Log email deletion as AuditEventType for security monitoring

### Token generation rate limiting

1. UserEmailVerificationToken: Max 5 tokens per email per hour
2. UserPasswordResetToken: Max 3 tokens per user per hour
3. Prevents abuse of email sending infrastructure

### Login attempt rate limiting

**When a login attempt occurs**:

1. Track login attempts by IP address (rolling 1-hour window)
2. If attempts >= 100 per hour (configurable via `config.rate_limiting.login_attempts_per_ip_per_hour`):
   - Return HTTP 429 Too Many Requests
   - Include `Retry-After` header with seconds until rate limit resets
   - Include error message: "Too many login attempts from this IP address. Please try again later."
3. Rate limit applies to all authentication methods (password, passkey)

### Registration rate limiting

**When a registration attempt occurs**:

1. Track registrations by IP address (rolling 24-hour window)
2. If registrations >= 5 per day (configurable via `config.rate_limiting.registrations_per_ip_per_day`):
   - Return HTTP 429 Too Many Requests
   - Include `Retry-After` header with seconds until rate limit resets
   - Include error message: "Too many registration attempts from this IP address. Please try again later."
3. Successful registrations and failed registrations both count toward limit

### Organization creation limits

1. Users with no verified email: Can only have the default organization created during registration
2. Users with verified email: Can create organizations (subject to per-user and global limits)
3. **Per-user limit**: Maximum 10 organizations per user (configurable via `config.limits.max_orgs_per_user`)
   - Prevents individual user abuse
   - Soft-deleted organizations count toward limit until hard-deleted (90-day grace period)
   - Users can request limit increase via support for legitimate use cases
4. **Global system limit**: Maximum 100,000 total organizations (configurable via `config.limits.max_total_orgs`)
   - Prevents platform resource exhaustion
   - Soft-deleted organizations count toward limit until hard-deleted
   - Monitoring alert when approaching 80% of limit
5. Concurrent organization creation by same user: Serialize requests (no race conditions)

### Passkey-only account recovery

1. Users with no password (passkey-only) who lose all passkeys: Must contact support
2. Recovery requires identity verification (email verification + additional proof)
3. After identity verification, support can add a temporary password to allow account recovery
4. User should add new passkey and remove temporary password

### Team manager permissions

1. Team managers can add/remove OrganizationTeamMember entries for their team
2. Team managers CANNOT delete the team itself (only Admins/Owners can delete teams)
3. Team managers CANNOT grant themselves additional permissions outside the team

### Organization member visibility

1. **Members**: Can view list of all organization members (names, roles, emails)
   - Required for collaboration features (mentioning users, assigning access, etc.)
   - Cannot view members of organizations they don't belong to
2. **Admins**: Same visibility as Members, plus can see pending invitations
3. **Owners**: Full visibility of all members, invitations, and audit logs

### Vault access propagation when teams/users change

1. When a user is added to a team:
   - User immediately gains access to all vaults that team has access to
   - Permission level determined by VaultTeamGrant role
2. When a user is removed from a team:
   - User loses team-based vault access immediately
   - If user has direct VaultUserGrant, they retain that access
3. When VaultTeamGrant is deleted:
   - All team members lose access unless they have direct VaultUserGrant
4. When VaultTeamGrant role is updated:
   - All team members' effective permissions update immediately (if team access is their highest permission)

### Refresh token lifecycle management

**When a UserSession is revoked or deleted**:

1. Find all VaultRefreshToken entries where `user_session_id` matches
2. Set `revoked_at = now()` on all matching refresh tokens
3. These tokens can no longer be used for refresh (validation fails)

**When a Client is revoked or deleted**:

1. Find all VaultRefreshToken entries where `org_api_key_id` matches
2. Set `revoked_at = now()` on all matching refresh tokens
3. These tokens can no longer be used for refresh (validation fails)

**When a Vault is deleted**:

1. Find all VaultRefreshToken entries where `vault_id` matches
2. Set `revoked_at = now()` on all matching refresh tokens
3. Prevents refresh tokens from being used for deleted vaults

**When VaultUserGrant or VaultTeamGrant is removed**:

1. **Do NOT revoke refresh tokens** (permission changes are not reflected in existing refresh tokens)
2. Refresh tokens continue to work with cached `vault_role` until expiry
3. When client uses refreshed JWT to access @server:
   - @server checks current permissions independently
   - @server returns 403 if permissions were revoked
   - Client should handle 403 by re-authenticating to get updated permissions

**Background cleanup job**:

1. Runs every 24 hours
2. Hard-delete VaultRefreshToken entries where:
   - `expires_at < (now - 7 days)` (expired tokens beyond grace period), OR
   - `used_at IS NOT NULL AND used_at < (now - 7 days)` (used tokens beyond grace period)
3. Keeps recent history for debugging and audit purposes

**When a used refresh token is presented again** (replay attack detection):

1. Detect that `used_at IS NOT NULL`
2. This indicates possible token theft
3. Response: Return error `REFRESH_TOKEN_USED`
4. **Security action**: Revoke ALL refresh tokens for that authentication context:
   - If user session: Revoke all refresh tokens with same `user_session_id`
   - If API key: Revoke all refresh tokens with same `org_api_key_id`
   - **Emergency revocation retry**: If revocation fails (storage unavailable, network error):
     - Queue revocation for background retry (up to 3 attempts with exponential backoff)
     - Log critical security alert for immediate operator attention
     - Continue to return `REFRESH_TOKEN_USED` error to client (fail closed)
     - Until revocation succeeds, all refresh attempts for that context will fail with `REFRESH_TOKEN_USED`
5. Force client to re-authenticate with Management API
6. Log security event (AuditEventType::REFRESH_TOKEN_REUSE_DETECTED) for monitoring and incident response

### VaultRole permission hierarchy

Permissions are hierarchical - higher roles include all lower role permissions:

- **VAULT_ROLE_ADMIN** includes VAULT_ROLE_MANAGER + delete/clear operations
- **VAULT_ROLE_MANAGER** includes VAULT_ROLE_WRITER + schema/policy management + view access grants
- **VAULT_ROLE_WRITER** includes VAULT_ROLE_READER + write/delete relationships
- **VAULT_ROLE_READER** base level: read-only access

### Organization tier limit enforcement

**When adding an OrganizationMember**:

1. Count current non-deleted OrganizationMember entries for the organization
2. If count >= tier.max_users, reject with error: "Organization has reached maximum user limit for tier {tier}"
3. Otherwise, proceed with creation

**When creating an OrganizationTeam**:

1. Count current non-deleted OrganizationTeam entries for the organization
2. If count >= tier.max_teams, reject with error: "Organization has reached maximum team limit for tier {tier}"
3. Otherwise, proceed with creation

**When creating a Vault**:

1. Count current non-deleted Vault entries for the organization
2. If count >= tier.max_vaults, reject with error: "Organization has reached maximum vault limit for tier {tier}"
3. Otherwise, proceed with creation

**When downgrading OrganizationTier**:

1. Check if current usage exceeds new tier limits:
   - Count active users, teams, and vaults
   - If any count > new_tier limits, reject downgrade
   - Return error listing which limits are exceeded
2. Example: "Cannot downgrade to TIER_DEV_V1: organization has 8 users (limit: 5), 6 teams (limit: 3)"
3. User must remove excess entities before downgrade is allowed
4. Soft-deleted entities do NOT count toward limits (grace period allows recovery)

### Client certificate management behavioral rules

**When creating a new Client**:

1. Validate requesting user has `ORG_PERM_CLIENT_CREATE` or `ORG_PERM_CLIENT_MANAGE` permission
2. Validate client name is unique within Organization
3. Create Client entity
4. Automatically create first ClientCertificate (name="Default Certificate")
5. Return Client details with private key (one-time display)
6. Log AuditEventType::CLIENT_CREATED with creating user

**When creating a new certificate for existing Client** (`POST /v1/organizations/:org/clients/:client/certificates`):

1. Validate requesting user has `ORG_PERM_CLIENT_CREATE` or `ORG_PERM_CLIENT_MANAGE` permission
2. Validate client has < 5 active (non-revoked) certificates
3. Validate client has < 20 total certificates (including revoked)
4. Generate new Ed25519 key pair
5. Create ClientCertificate entity with optional user-provided name
6. **Return private key ONLY ONCE** (never stored in readable form after this response)
7. Log AuditEventType::CLIENT_CERTIFICATE_CREATED with client_id and certificate_id
8. Display warning in Dashboard: "Save this private key securely - it will not be shown again"

**Developer workflow for graceful certificate rotation**:

```text
Phase 1: Generate new certificate
1. User clicks "Generate New Certificate" in Dashboard
2. User provides optional name: "Rollout 2024-11"
3. System creates new certificate, returns private key
4. User saves private key to secure storage

Phase 2: Deploy new certificate (zero downtime)
5. User updates deployment configuration with new private key
6. User deploys application update (gradual rollout: 10% → 50% → 100%)
7. Both old and new certificates remain active during rollout
8. Applications use whichever certificate they have configured

Phase 3: Verify new certificate usage
9. User monitors `last_used_at` timestamp on both certificates
10. When old certificate `last_used_at` stops updating → all apps migrated

Phase 4: Revoke old certificate (when convenient)
11. User clicks "Revoke" on old certificate
12. System sets `revoked_at = now()` on old certificate
13. Old certificate remains visible for 90 days for audit purposes
14. Background job auto-deletes after 90 days
```

**When revoking a certificate** (`POST /v1/organizations/:org/clients/:client/certificates/:cert/revoke`):

1. Validate requesting user has `ORG_PERM_CLIENT_REVOKE` or `ORG_PERM_CLIENT_MANAGE` permission
2. **Check if last active certificate**: Count non-revoked certificates for this client
3. If this is the last active certificate: Reject with error "Cannot revoke last active certificate. Generate a new certificate first."
4. Set `revoked_at = now()` and `revoked_by_user_id = <current_user>`
5. Revoke all VaultRefreshToken entries that were issued using JWTs signed with this certificate
6. Log AuditEventType::CLIENT_CERTIFICATE_REVOKED
7. Return success with message: "Certificate revoked. It will remain visible for 90 days for audit purposes."

**When listing certificates** (`GET /v1/organizations/:org/clients/:client/certificates`):

Response includes:

```json
{
  "certificates": [
    {
      "id": "cert_active_123",
      "kid": "org-123-client-456-cert-789",
      "name": "Rollout 2024-11",
      "created_at": "2024-11-01T10:00:00Z",
      "created_by_user_id": "user_abc",
      "last_used_at": "2024-11-17T14:30:22Z",
      "revoked_at": null,
      "status": "active",
      "age_days": 16
    },
    {
      "id": "cert_active_456",
      "kid": "org-123-client-456-cert-012",
      "name": "Default Certificate",
      "created_at": "2024-08-15T09:00:00Z",
      "created_by_user_id": "user_xyz",
      "last_used_at": "2024-11-17T14:29:58Z",
      "revoked_at": null,
      "status": "active",
      "age_days": 94,
      "warning": "Certificate is over 90 days old - rotation recommended"
    },
    {
      "id": "cert_revoked_789",
      "kid": "org-123-client-456-cert-345",
      "name": "Legacy Production",
      "created_at": "2024-05-01T10:00:00Z",
      "created_by_user_id": "user_xyz",
      "last_used_at": "2024-10-31T23:59:59Z",
      "revoked_at": "2024-11-01T00:00:00Z",
      "revoked_by_user_id": "user_abc",
      "status": "revoked",
      "days_until_deletion": 74
    }
  ],
  "summary": {
    "active_count": 2,
    "revoked_count": 1,
    "oldest_active_age_days": 94
  }
}
```

**When deleting a certificate** (`DELETE /v1/organizations/:org/clients/:client/certificates/:cert`):

1. Validate requesting user has `ORG_PERM_CLIENT_DELETE` or `ORG_PERM_CLIENT_MANAGE` permission
2. Require confirmation parameter: `?confirm_delete=<cert_id>`
3. **Check if last active certificate**: If not revoked and is last active cert, reject with error
4. Set `deleted_at = now()` (soft delete with 90-day grace period)
5. Log AuditEventType::CLIENT_CERTIFICATE_DELETED

### Email re-verification behavioral rules

**When a UserEmail is modified** (email address changed):

1. **Cannot modify email address**: UserEmail entities are immutable
2. To change email: Delete old UserEmail, create new UserEmail (unverified)
3. New UserEmail automatically generates UserEmailVerificationToken
4. User must verify new email before it can be used for sensitive operations

**When re-verifying an already verified email** (user requests new verification token):

1. Allow re-verification at any time (e.g., user suspects compromise)
2. Generate new UserEmailVerificationToken
3. **Do NOT unset verified_at** (email remains verified during re-verification process)
4. When new token is successfully verified:
   - Update `verified_at = now()` (refresh verification timestamp)
   - Delete all other UserEmailVerificationToken entries for this email
5. If user never completes re-verification, email remains verified with original timestamp

### Session revocation cascading

**When UserSession is explicitly revoked** (user logs out or revokes session):

1. Set UserSession.deleted_at = now()
2. Find all VaultRefreshToken entries with matching user_session_id
3. Set VaultRefreshToken.revoked_at = now() for all matches
4. Log AuditEventType::SESSION_REVOKED
5. If user revokes "all sessions except current":
   - Soft-delete all other UserSession entries for that user
   - Keep current session active
   - Revoke all refresh tokens for deleted sessions

**When Client is revoked**:

1. Set Client.revoked_at = now()
2. Find all VaultRefreshToken entries with matching org_api_key_id
3. Set VaultRefreshToken.revoked_at = now() for all matches
4. Client cannot be un-revoked (permanent action)
5. Log AuditEventType::CLIENT_REVOKED
6. Notify organization Owners via email

### Vault sync failure recovery

**When vault creation fails at @server**:

1. Set Vault.sync_status = FAILED
2. Keep Vault entity in Management API (do not delete)
3. **Manual retry**: Admin can trigger retry via `POST /v1/vaults/:vault/retry-sync`
4. **Automatic retry**: Background job retries failed syncs every 5 minutes (up to 3 attempts)
5. After 3 failed attempts:
   - Send alert to organization Owners
   - Vault remains in FAILED state until manual intervention
6. User can delete failed vault and recreate (vault name becomes available after deletion)

**When vault deletion fails at @server**:

1. Set Vault.sync_status = FAILED
2. Set Vault.deleted_at = now() (vault marked as deleted in Management API)
3. Cascade soft-delete all VaultTeamGrant and VaultUserGrant entries
4. **Orphaned data**: @server vault data remains until cleanup succeeds
5. **Automatic retry**: Background job retries failed deletions every hour (indefinitely until success)
6. Vault name remains reserved (cannot reuse) until deletion succeeds at @server
7. Alert operators after 24 hours of failed deletion attempts

---

## Authentication & Authorization

### User Registration Flow

**Endpoint**: `POST /v1/auth/register`

**Request**:

```json
{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "secret123",
  "tos_accepted": true
}
```

**Response**:

```json
{
  "user_id": "<snowflake_id>",
  "email_verification_required": true,
  "session_id": "<snowflake_id>",
  "expires_at": "2024-12-31T23:59:59Z"
}
```

**Behavior**:

1. Validate email is not already in use (globally unique constraint)
2. Validate password meets minimum requirements:
   - Minimum length: 12 characters (configurable via `config.auth.password_min_length`)
   - No additional complexity requirements (length alone provides sufficient entropy)
   - Rationale: Modern guidance (NIST SP 800-63B) recommends length over complexity rules
3. Create User entity with `tos_accepted_at = now()`
4. Hash password with Argon2id and store in User.password_hash
5. Create UserEmail (unverified, primary=true)
6. Generate UserEmailVerificationToken
7. Send verification email with link
8. Create default Organization with same name as user, tier=TIER_DEV_V1
9. Create OrganizationMember linking user to org with role=OWNER
10. Generate first Client for the organization
11. Create UserSession (30-day expiry for WEB, type determined by User-Agent or explicit parameter)
12. Return session_id for immediate use

**Email Verification Requirements**:

- Users CAN use the platform immediately after registration without email verification
- Unverified emails have the following restrictions:
  - Cannot request password reset (must verify email first)
  - Cannot be used as primary email for sensitive operations
  - Cannot invite other users to organizations (Admins/Owners only, requires verified email)
  - Cannot create additional organizations beyond the default one (requires verified email)
- Users receive periodic reminders to verify their email (background job sends reminders at day 3, 7, 14, 30)
- After 30 days without verification, account functionality becomes limited:
  - Can only access existing resources (read-only mode for organizations, vaults, teams)
  - Cannot create new vaults, teams, or organizations
  - Cannot modify vault access grants or team memberships
  - Can still read data from vaults they have access to (via @server API)
  - Must verify email to restore full functionality
  - UI displays prominent banner: "Please verify your email to restore full access"
- Verification reminders are paused if user has verified at least one email

**Alternative Registration: Passkey-Only Accounts**:

Users can also register with passkey-only (no password):

**Endpoint**: `POST /v1/auth/register/passkey/begin`

**Request**:

```json
{
  "name": "John Doe",
  "email": "john@example.com",
  "tos_accepted": true
}
```

**Response**: WebAuthn registration challenge (same format as passkey login)

**Endpoint**: `POST /v1/auth/register/passkey/finish`

**Request**: WebAuthn credential response

**Behavior**: Same as password registration, but User.password_hash remains unset.

---

### Authentication Flow

Management API supports **three authentication methods**:

#### 1. Password Authentication

**Endpoint**: `POST /v1/auth/login/password`

**Request**:

```json
{
  "email": "user@example.com",
  "password": "secret"
}
```

**Response**:

```json
{
  "session_id": "<snowflake_id>",
  "user_id": "<snowflake_id>",
  "expires_at": "2024-12-31T23:59:59Z"
}
```

**Behavior**:

1. Lookup User by email (via UserEmail)
2. Verify password against Argon2id hash
3. Create UserSession (30-day expiry for web)
4. Return session ID (used as Bearer token in subsequent requests)

---

#### 2. Passkey Authentication (WebAuthn)

**Endpoint**: `POST /v1/auth/login/passkey/begin`

**Request**:

```json
{
  "email": "user@example.com"
}
```

**Response**:

```json
{
  "challenge": "<base64url>",
  "allowCredentials": [
    {
      "id": "<base64url>",
      "type": "public-key",
      "transports": ["usb", "nfc"]
    }
  ],
  "timeout": 60000,
  "rpId": "inferadb.com",
  "userVerification": "required"
}
```

**Endpoint**: `POST /v1/auth/login/passkey/finish`

**Request**:

```json
{
  "credentialId": "<base64url>",
  "authenticatorData": "<base64url>",
  "clientDataJSON": "<base64url>",
  "signature": "<base64url>"
}
```

**Response**:

```json
{
  "session_id": "<snowflake_id>",
  "user_id": "<snowflake_id>",
  "expires_at": "2024-12-31T23:59:59Z"
}
```

**Behavior**:

1. `/begin`: Generate WebAuthn challenge, return user's registered passkeys
2. `/finish`: Verify signature, update sign_count, create UserSession
3. Follow WebAuthn Level 2 specification

---

#### 3. Client Assertion Authentication (for @server access)

Backend applications authenticate to @server using **Client Assertion** (OAuth 2.0 JWT Bearer, RFC 7523). See [AUTHENTICATION.md](AUTHENTICATION.md#4-client-assertion-recommended-for-backend-services) for the complete flow.

**Token Claims**:

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

**Client Key Management**:

- Organizations create Clients via Dashboard or CLI
- Each Client receives an Ed25519 key pair (client stores private key, Management API stores public key)
- Private keys shown only once during creation (developer saves securely)
- Public keys published to JWKS endpoint for @server verification
- Clients can be created, rotated, and revoked by organization Owners

**Client Assertion Flow**:

1. Backend application creates a short-lived JWT assertion (max 60 seconds)
2. Signs assertion with its private key (Ed25519)
3. Sends assertion to Management API `/v1/token` endpoint
4. Management API verifies signature using stored public key
5. Management API issues vault-scoped JWT for @server requests
6. Backend uses vault JWT to call @server API

**Token Scoping**:

- Clients have scopes defining allowed vaults + roles (e.g., `vault:vault_123:WRITER`)
- Management API only issues tokens for vaults the Client has access to
- Tokens scoped to specific vaults based on Client's configured VaultScope entries

---

### Session Management

**Best Practices**:

- Sessions use **secure, httpOnly cookies** for web clients
- Sessions use **Bearer tokens** for CLI/SDK clients
- Session IDs are Snowflake IDs (cryptographically unpredictable)
- **Sliding window expiry**: `last_activity_at` updates on each request
  - Web sessions: 30-day expiry, extends on activity
  - CLI sessions: 90-day expiry, extends on activity
- **Max concurrent sessions**: 10 per user (configurable via `config.auth.max_sessions_per_user`)
  - When exceeded, the least recently active session is revoked (oldest `last_activity_at` timestamp)
  - Expired sessions (where `expires_at < now`) are not counted toward the limit
- **Session revocation**: Users can manually revoke sessions via `/users/sessions/:id` DELETE
- **Password reset invalidates all sessions** for that user

**Security**:

- Session tokens treated as bearer credentials
- Transmitted only over HTTPS in production
- Cookie settings: `Secure; HttpOnly; SameSite=Lax`

---

### Passkey Management

Users can register and manage multiple passkeys for their account.

**Endpoint**: `POST /v1/users/passkeys/register/begin` (Start passkey registration)

**Request**:

```json
{
  "name": "iPhone 15 Pro"
}
```

**Response**:

```json
{
  "challenge": "<base64url>",
  "user": {
    "id": "<base64url>",
    "name": "john@example.com",
    "displayName": "John Doe"
  },
  "rp": {
    "id": "inferadb.com",
    "name": "InferaDB"
  },
  "pubKeyCredParams": [
    {"type": "public-key", "alg": -8},
    {"type": "public-key", "alg": -7}
  ],
  "timeout": 60000,
  "authenticatorSelection": {
    "userVerification": "required",
    "residentKey": "preferred"
  }
}
```

**Endpoint**: `POST /v1/users/passkeys/register/finish` (Complete passkey registration)

**Request**:

```json
{
  "name": "iPhone 15 Pro",
  "credential": {
    "id": "<base64url>",
    "rawId": "<base64url>",
    "type": "public-key",
    "response": {
      "attestationObject": "<base64url>",
      "clientDataJSON": "<base64url>"
    }
  }
}
```

**Response**:

```json
{
  "passkey_id": "<snowflake_id>",
  "name": "iPhone 15 Pro",
  "created_at": "2024-01-15T10:30:00Z"
}
```

**Behavior**:

1. Verify WebAuthn credential is valid
2. Extract public key and credential_id
3. Create UserPasskey entity
4. Return passkey details

**Endpoint**: `GET /v1/users/passkeys` (List user's passkeys)

**Response**:

```json
{
  "passkeys": [
    {
      "id": "<snowflake_id>",
      "name": "iPhone 15 Pro",
      "created_at": "2024-01-15T10:30:00Z",
      "last_used_at": "2024-01-20T14:22:00Z"
    }
  ]
}
```

**Endpoint**: `DELETE /v1/users/passkeys/:id` (Delete a passkey)

**Constraints**:

- Users with passkey-only accounts (no password) must have at least 1 passkey
- Users with password can delete all passkeys
- Cannot delete the last passkey if User.password_hash is null

---

### Client Authentication for @server API

**Flow**:

1. Client authenticates to Management API (password, passkey, or existing session)
2. Client requests a vault-scoped JWT: `POST /v1/tokens/vault/:vault_id`
3. Management API validates:
   - User has active session (or valid API key client assertion)
   - User has access to vault (via VaultUserGrant or VaultTeamGrant)
   - Determines highest VaultRole the user has
4. Management API generates private key JWT signed with Organization's key
5. Management API generates refresh token
6. Client uses JWT as Bearer token for @server gRPC/REST API calls
7. @server validates JWT signature against Organization's JWKS
8. When JWT expires, client can use refresh token to get new JWT without re-authenticating

**Endpoint**: `POST /v1/tokens/vault/:vault_id`

**Request**: (authenticated via session token or API key client assertion)

**Response**:

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

**Behavior**:

1. Validate authentication context (UserSession or Client)
2. Check user/org has access to vault
3. Determine highest VaultRole
4. Generate vault-scoped JWT (1 hour expiry)
5. Generate VaultRefreshToken:
   - Set expiry: 24 hours (user session) or 7 days (client)
   - Bind to authentication context (user_session_id or org_api_key_id)
   - Store vault_role at time of issuance
6. Return both tokens to client

**Note**: Refresh tokens are always included. Clients can choose to use them or ignore them based on their use case.

---

### Refresh Token Flow

**Endpoint**: `POST /v1/tokens/refresh`

**Request**: (authenticated via session token or API key client assertion)

```json
{
  "refresh_token": "<refresh_token>"
}
```

**Response**:

```json
{
  "access_token": "<new_jwt>",
  "refresh_token": "<new_refresh_token>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_expires_in": 86400,
  "vault_id": "<snowflake_id>",
  "vault_role": "VAULT_ROLE_WRITER"
}
```

**Behavior**:

1. Validate authentication context (UserSession or Client)
2. Lookup VaultRefreshToken by token
3. Validate refresh token:
   - Token exists and matches
   - Not expired (`expires_at > now`)
   - Not already used (`used_at IS NULL`)
   - Not revoked (`revoked_at IS NULL`)
   - Bound to current authentication context:
     - If user session: `user_session_id` matches current session
     - If client: `org_api_key_id` matches current client
4. Mark old refresh token as used (`used_at = now`)
5. Generate new vault-scoped JWT (1 hour expiry) with cached `vault_role`
6. Generate new VaultRefreshToken (rotated):
   - New random token
   - Same vault_id, organization_id, vault_role
   - Same authentication context binding
   - New expiry (24 hours or 7 days from now)
7. Return new tokens to client

**Error Cases**:

- `REFRESH_TOKEN_INVALID`: Token doesn't exist or doesn't match authentication context
- `REFRESH_TOKEN_EXPIRED`: Token has expired
- `REFRESH_TOKEN_USED`: Token already used (possible replay attack, revoke immediately)
- `REFRESH_TOKEN_REVOKED`: Token was revoked due to permission changes
- `AUTH_SESSION_EXPIRED`: Parent UserSession has expired
- `AUTH_CLIENT_REVOKED`: Parent Client was revoked

**Security Notes**:

- Refresh tokens are single-use and automatically rotated
- Detecting a used refresh token indicates possible token theft → revoke all refresh tokens for that auth context
- Refresh tokens do NOT check current permissions (uses cached vault_role)
- If permissions change, client will receive 403 from @server and must re-authenticate

---

### Refresh Token Usage Guidelines

**When to Use Refresh Tokens**:

Refresh tokens are always provided by the Management API. Clients should use them when:

✅ **Recommended use cases**:

- Long-running batch operations (data imports, exports, migrations)
- Background workers that run periodically (every few hours)
- Mobile applications that may be backgrounded for extended periods
- CI/CD pipelines with jobs lasting multiple hours
- Scheduled tasks and cron jobs

⚠️ **Optional for**:

- Short-lived web requests (operations completing in under 30 minutes)
- Interactive web UI operations (can rely on 1-hour JWT being sufficient)

Clients can simply ignore the refresh token if they don't need it - there's no overhead to receiving it.

**Client Implementation Pattern**:

```python
class VaultClient:
    def __init__(self, management_url, session_token):
        self.management_url = management_url
        self.session_token = session_token
        self.access_token = None
        self.refresh_token = None
        self.access_token_expires_at = None

    def get_vault_access_token(self, vault_id, use_refresh=False):
        """Get or refresh vault access token"""

        # Check if current token is still valid (with 5-minute buffer)
        if self.access_token and self.access_token_expires_at:
            if time.time() < (self.access_token_expires_at - 300):
                return self.access_token

        # Try refresh if we have a refresh token
        if self.refresh_token and use_refresh:
            try:
                response = requests.post(
                    f"{self.management_url}/tokens/refresh",
                    headers={"Authorization": f"Bearer {self.session_token}"},
                    json={"refresh_token": self.refresh_token}
                )

                if response.status_code == 200:
                    data = response.json()
                    self.access_token = data["access_token"]
                    self.refresh_token = data["refresh_token"]  # Rotated
                    self.access_token_expires_at = time.time() + data["expires_in"]
                    return self.access_token

                # Refresh failed, fall through to request new tokens

            except Exception as e:
                # Log error, fall through to request new tokens
                logger.warning(f"Token refresh failed: {e}")

        # Request new access token (always returns refresh token too)
        response = requests.post(
            f"{self.management_url}/tokens/vault/{vault_id}",
            headers={"Authorization": f"Bearer {self.session_token}"}
        )

        response.raise_for_status()
        data = response.json()

        self.access_token = data["access_token"]
        self.refresh_token = data["refresh_token"]  # Always provided
        self.access_token_expires_at = time.time() + data["expires_in"]

        return self.access_token

    def call_server_api(self, vault_id, operation):
        """Call @server API with automatic token refresh"""

        # Get valid access token
        access_token = self.get_vault_access_token(vault_id, use_refresh=True)

        # Call @server API
        try:
            response = requests.post(
                f"{self.server_url}/check",
                headers={"Authorization": f"Bearer {access_token}"},
                json=operation
            )

            # Handle 401 (expired token) with one retry
            if response.status_code == 401:
                # Force token refresh
                self.access_token = None
                access_token = self.get_vault_access_token(vault_id, use_refresh=True)

                # Retry request
                response = requests.post(
                    f"{self.server_url}/check",
                    headers={"Authorization": f"Bearer {access_token}"},
                    json=operation
                )

            # Handle 403 (permissions revoked)
            if response.status_code == 403:
                # Clear tokens and re-authenticate
                self.access_token = None
                self.refresh_token = None
                raise PermissionDeniedError("Vault access revoked, please re-authenticate")

            response.raise_for_status()
            return response.json()

        except requests.exceptions.HTTPError as e:
            # Handle errors appropriately
            raise
```

**Error Handling Best Practices**:

1. **401 Unauthorized**: Token expired
   - Attempt refresh if refresh token available
   - Otherwise, request new tokens from Management API
   - Retry original request once

2. **403 Forbidden**: Permissions changed
   - Clear all cached tokens (access + refresh)
   - Re-authenticate with Management API to get updated permissions
   - Do NOT retry automatically

3. **`REFRESH_TOKEN_USED`**: Possible token theft
   - All refresh tokens for auth context have been revoked
   - User/API key must re-authenticate completely
   - Log security event

4. **`REFRESH_TOKEN_EXPIRED`**: Refresh token expired
   - Request new tokens from Management API
   - For API keys (7-day expiry), this indicates job ran longer than expected

**Token Expiry Timeline**:

```
Time:     0min        55min        60min        24hr         7d
          |           |            |            |            |
Access:   [========= JWT valid =========][expired]

Refresh:  [============ Valid (user session) ==============][expired]
(user)

Refresh:  [==================== Valid (API key) ====================][expired]
(API key)

Strategy: |<-- Use JWT -->|<- Refresh ->|<-- Use new JWT -->
```

**Recommended Refresh Strategy**:

- **Proactive refresh**: Refresh when JWT has 5 minutes remaining (don't wait for 401)
- **Lazy refresh**: Only refresh on 401 error (simpler, but causes one failed request)
- **Background refresh**: Refresh in background thread before expiry (best for long operations)

---

### CLI & SDK Authentication Methods

The Management API supports multiple authentication methods for command-line tools (CLI) and SDKs to accommodate different deployment scenarios and security requirements.

#### CLI Authentication Methods

##### Method 1: Browser-Based OAuth Flow (Recommended for Interactive CLI)

This method provides the best user experience for interactive CLI usage by leveraging the web-based Dashboard for authentication.

**Flow Overview**:

1. User runs CLI command requiring authentication (e.g., `inferadb login`)
2. CLI starts local HTTP server on `localhost:<random_port>` to receive callback
3. CLI generates PKCE code verifier and challenge
4. CLI opens user's default browser to Dashboard login URL with PKCE challenge
5. User authenticates via Dashboard (password or passkey)
6. Dashboard redirects back to CLI's localhost callback URL with authorization code
7. CLI exchanges authorization code + PKCE verifier for session token
8. CLI stores session token securely for future requests

**Detailed Implementation**:

**Step 1: CLI initiates auth flow**

```bash
inferadb login
```

CLI behavior:

```rust
// Generate PKCE parameters
let code_verifier = generate_random_string(128);  // 128-char random string
let code_challenge = base64url(sha256(code_verifier));  // S256 challenge

// Start local callback server
let callback_port = find_available_port();  // Random port 8000-9000
let callback_url = format!("http://localhost:{}/callback", callback_port);

// Construct authorization URL
let auth_url = format!(
    "https://app.inferadb.com/cli-login?code_challenge={}&code_challenge_method=S256&callback_url={}&state={}",
    code_challenge,
    urlencoded(callback_url),
    random_state
);

// Open browser
println!("Opening browser for authentication...");
println!("If browser doesn't open, visit: {}", auth_url);
open_browser(&auth_url);

// Wait for callback
start_callback_server(callback_port).await;
```

**Step 2: Dashboard authenticates user and redirects**

Dashboard UI (`https://app.inferadb.com/cli-login`):

- Displays "InferaDB CLI Login" page
- Shows login form (password or passkey)
- User authenticates (creates UserSession with type=CLI)
- Dashboard generates authorization code (single-use, 5-minute expiry)
- Redirects to callback URL

**Management API Endpoint**: `POST /v1/auth/cli/authorize` (called by Dashboard)

**Request**:

```json
{
  "session_id": "<user_session_id>",
  "code_challenge": "<pkce_challenge>",
  "code_challenge_method": "S256",
  "callback_url": "http://localhost:8432/callback"
}
```

**Response**:

```json
{
  "authorization_code": "<single_use_code>",
  "expires_in": 300
}
```

**Behavior**:

1. Validate user has active session
2. Generate authorization code (random 32-byte string, base64url-encoded)
3. Store authorization code with associated data:
   - `code_challenge` (for PKCE verification)
   - `session_id` (to link to user session)
   - `expires_at` (5 minutes from now)
4. Return authorization code to Dashboard

**Step 3: Dashboard redirects to CLI callback**

```
HTTP/1.1 302 Found
Location: http://localhost:8432/callback?code=<authorization_code>&state=<state>
```

**Step 4: CLI receives callback and exchanges code for token**

CLI callback handler receives:

```
GET /callback?code=<authorization_code>&state=<state>
```

CLI calls Management API to exchange code for session token:

**Management API Endpoint**: `POST /v1/auth/cli/token`

**Request**:

```json
{
  "authorization_code": "<code_from_callback>",
  "code_verifier": "<original_pkce_verifier>"
}
```

**Response**:

```json
{
  "session_token": "<session_id>",
  "user_id": "<user_id>",
  "expires_at": "2024-04-15T10:30:00Z",
  "expires_in": 7776000
}
```

**Behavior**:

1. Lookup authorization code (validate not expired, not already used)
2. Verify PKCE: `base64url(sha256(code_verifier)) == stored_code_challenge`
3. Mark authorization code as used (single-use)
4. Return the session token associated with the authorization code
5. CLI stores session token in secure storage

**Step 5: CLI uses session token for API requests**

```bash
inferadb vaults list
```

CLI includes session token in requests:

```
GET /v1/organizations
Authorization: Bearer <session_token>
```

**Security Properties**:

- ✅ No credentials stored on CLI (only session token)
- ✅ PKCE prevents authorization code interception
- ✅ Single-use authorization codes (no replay attacks)
- ✅ 5-minute code expiry limits exposure window
- ✅ Localhost-only callback (no external redirect)
- ✅ User authenticates via familiar Dashboard UI

**Storage Location**:

CLI stores session token securely:

- **macOS**: Keychain (`security` command)
- **Linux**: Secret Service API or `~/.config/inferadb/credentials` (chmod 600)
- **Windows**: Credential Manager

---

##### Method 2: Client Assertion (Recommended for CI/CD & Automation)

For non-interactive environments (CI/CD pipelines, automation scripts, backend services), users can create Clients using the Client Assertion pattern. See [AUTHENTICATION.md](AUTHENTICATION.md#4-client-assertion-recommended-for-backend-services) for complete documentation.

**Client Creation Flow**:

1. User logs into Dashboard
2. User navigates to Organization Settings → Clients
3. User creates new Client with a descriptive name (e.g., "GitHub Actions CI")
4. Dashboard displays the **private key** ONCE (user must copy and store securely)
5. User sets environment variable in CI/CD: `INFERADB_CLIENT_ID=<client_id>` and `INFERADB_PRIVATE_KEY=<private_key>`
6. CLI/SDK uses private key to generate and sign client assertion JWTs

**Management API Endpoint**: `POST /v1/organizations/:org/clients`

**Request**:

```json
{
  "name": "GitHub Actions CI"
}
```

**Response**:

```json
{
  "client_id": "client_<snowflake_id>",
  "kid": "org-acme-key-20250116",
  "name": "GitHub Actions CI",
  "public_key": "<Ed25519_public_key_pem>",
  "private_key": "<Ed25519_private_key_pem>",
  "created_at": "2025-01-16T10:00:00Z"
}
```

**⚠️ Security Warning**: The `private_key` is returned ONLY on creation. If lost, user must create a new Client.

**CLI Usage**:

```bash
# Set environment variables
export INFERADB_CLIENT_ID="client_123456789"
export INFERADB_PRIVATE_KEY="<private_key_pem>"

# CLI automatically detects and uses Client Assertion
$ inferadb vaults list
```

**Client Assertion Generation**:

CLI/SDK generates a JWT client assertion signed with the private key:

```rust
use jsonwebtoken::{encode, Algorithm, Header, EncodingKey};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct ClientAssertion {
    iss: String,  // "org:<org_id>"
    sub: String,  // "org:<org_id>"
    aud: String,  // "https://management.inferadb.com"
    exp: i64,     // Current time + 5 minutes
    iat: i64,     // Current time
    jti: String,  // Random UUID
}

fn generate_client_assertion(client_id: &str, private_key_pem: &str) -> Result<String> {
    let claims = ClientAssertion {
        iss: client_id.to_string(),  // e.g., "client_123456789"
        sub: client_id.to_string(),
        aud: "https://management.inferadb.com/v1/token".to_string(),
        exp: Utc::now().timestamp() + 60,  // 60 seconds (short-lived)
        iat: Utc::now().timestamp(),
        jti: Uuid::new_v4().to_string(),
    };

    let header = Header::new(Algorithm::EdDSA);
    let key = EncodingKey::from_ed_pem(private_key_pem.as_bytes())?;

    encode(&header, &claims, &key)
}
```

**Token Exchange Flow**:

CLI/SDK exchanges client assertion for vault-scoped JWT:

```
POST /v1/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&
client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&
client_assertion=<signed_jwt>&
scope=vault:vault_123:WRITER
```

**Management API Token Endpoint**: `/v1/token`

**Validation**:

1. Decode JWT header to extract `kid`
2. Lookup Client by `kid` (via `org_api_key_kid` index)
3. Verify JWT signature using public key from Client
4. Validate claims: `iss`, `sub`, `aud`, `exp`, `iat`
5. Check `jti` not previously used (replay protection)
6. Verify Client has permission for requested scope (vault + role)
7. Issue vault-scoped JWT signed with Management API's key

**Authorization Scope**:

- Client Assertion provides **client-level access** scoped to specific vaults
- Operations are performed on behalf of the Client (not a specific user)
- Audit logs record actions as "via Client: <client_name>"
- Clients can only access vaults configured in their VaultScope list

**Security Properties**:

- ✅ Long-lived credentials for automation
- ✅ No interactive authentication required
- ✅ Scoped to organization (not user)
- ✅ Can be revoked without affecting user accounts
- ✅ Private key never transmitted (only signatures)
- ✅ JWT signatures verify key ownership

---

##### Method 3: Session Token (Programmatic Access)

For programmatic scenarios where browser-based auth is not feasible but API keys are too broad, users can generate short-lived session tokens via the API.

**Use Case**: Temporary access for scripts, testing, or applications that need user-scoped permissions.

**Flow**:

1. User authenticates to Management API via password or passkey
2. User receives session token (30-day or 90-day depending on SessionType)
3. User stores token in environment variable or config file
4. CLI/SDK uses session token for API requests

**CLI Usage**:

```bash
# Login interactively (browser-based flow)
$ inferadb login
Session token saved to keychain.

# Or: Login programmatically (password)
$ inferadb login --email user@example.com --password <password>
Session token saved to keychain.

# Or: Use explicit token
$ export INFERADB_SESSION_TOKEN="<session_token>"
$ inferadb vaults list
```

**Management API Request**:

```
GET /v1/organizations
Authorization: Bearer <session_token>
```

**Validation**:

1. Lookup UserSession by session_id
2. Validate session not expired (`expires_at > now`)
3. Validate session not soft-deleted (`deleted_at IS NULL`)
4. Update `last_activity_at` (sliding window expiry)
5. Attach user authorization context

**Security Properties**:

- ✅ User-scoped permissions (respects VaultUserGrant, OrganizationMember roles)
- ✅ Time-limited (30 or 90 days with sliding window)
- ✅ Can be revoked by user
- ✅ Audit trail links actions to specific user

---

#### SDK Authentication Methods

SDKs (Python, Node.js, Go, Rust) support the same authentication methods as CLI:

1. **Client Assertion (Recommended)**: Use Client for server-side applications
2. **Session Token**: Use user session tokens for user-facing applications

**Python SDK Example**:

```python
from inferadb import InferaDB

# Method 1: Client assertion (API key)
client = InferaDB(
    org_id="org_123",
    api_key=os.environ["INFERADB_API_KEY"]  # Private key PEM
)

# Method 2: Session token
client = InferaDB(
    session_token=os.environ["INFERADB_SESSION_TOKEN"]
)

# SDK automatically handles JWT generation and authentication
vaults = client.vaults.list()
```

**SDK Implementation**:

SDKs automatically:

- Generate client assertion JWTs from API keys (signs with Ed25519)
- Include `Authorization: Bearer <token>` header in all requests
- Handle token refresh if needed
- Provide clear error messages for auth failures

---

#### Authentication Method Comparison

| Method | Use Case | Credential Type | Scope | Lifetime | Revocation |
|--------|----------|----------------|-------|----------|------------|
| **Browser OAuth** | Interactive CLI | Session token | User | 90 days | User can revoke |
| **API Key** | CI/CD, automation | Private key | Organization | Until revoked | Owner can revoke |
| **Session Token** | Scripts, testing | Session token | User | 30-90 days | User can revoke |

**Recommendations**:

- **Interactive CLI**: Browser-based OAuth (best UX)
- **CI/CD Pipelines**: API Key with client assertion
- **Development/Testing**: Session token
- **Production SDKs**: API Key with client assertion
- **User-Facing Apps**: Session token (user-scoped)

---

### JWKS Endpoint (for @server verification)

The Management API exposes organization public keys via JWKS (JSON Web Key Set) for @server to verify JWTs.

**Endpoint**: `GET /.well-known/jwks.json` (Global JWKS for all organizations)

**Response**:

```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "kid": "org-123456789-key-987654321",
      "x": "<base64url-encoded-public-key>",
      "use": "sig",
      "alg": "EdDSA"
    },
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "kid": "org-111111111-key-222222222",
      "x": "<base64url-encoded-public-key>",
      "use": "sig",
      "alg": "EdDSA"
    }
  ]
}
```

**Endpoint**: `GET /v1/organizations/:org/jwks.json` (Organization-specific JWKS)

**Response**:

```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "kid": "org-123456789-key-987654321",
      "x": "<base64url-encoded-public-key>",
      "use": "sig",
      "alg": "EdDSA"
    }
  ]
}
```

**Behavior**:

- Include Client entries where:
  - `revoked_at IS NULL` (active clients), OR
  - `revoked_at > (now - 5 minutes)` (recently revoked clients in grace period)
- Keys are cached by @server with TTL (5 minutes recommended)
- @server uses stale-while-revalidate pattern for JWKS caching (same as tenant JWT verification in @server)
- No authentication required (public endpoint)
- Returns 404 if organization doesn't exist or has no active clients
- Note: After 5 minutes, revoked clients are excluded from JWKS automatically (time-based, no additional field needed)

**Key Rotation**:

When using the `RotateClient` endpoint:

1. Generate new Client (with new keypair)
2. Add new key to JWKS immediately
3. Set `revoked_at` on old client (does NOT delete it yet)
4. Old client remains in JWKS for grace period (5 minutes) to allow in-flight JWTs to validate
5. Return new client details to caller (including private key - one-time only)
6. After 5 minutes, the time-based query `revoked_at > (now - 5 minutes)` automatically excludes the old client from JWKS responses

**Important**: This atomic operation ensures at least one active client exists at all times, satisfying the constraint that "at least one active client must exist per Organization"

When manually revoking a client (without rotation):

1. Validate that this is NOT the last active client (error if it is)
2. Set `revoked_at` on the client
3. Client remains in JWKS for 5-minute grace period (automatically via time-based query)
4. All new JWT signing requests will use a different active client

**Note**: No background job is needed for JWKS cleanup - the time-based query ensures automatic exclusion of clients where `revoked_at <= (now - 5 minutes)`.

---

## Email Flows

### Email Verification

**Endpoint**: `POST /v1/users/emails` (Add new email)

**Request**:

```json
{
  "email": "newemail@example.com"
}
```

**Behavior**:

1. Create UserEmail (unverified)
2. Generate UserEmailVerificationToken
3. Send verification email with link: `https://app.inferadb.com/verify-email?token=<token>`
4. Email contains 6-digit code and clickable link

**Endpoint**: `POST /v1/auth/verify-email` (Confirm verification)

**Request**:

```json
{
  "token": "<token>"
}
```

**Behavior**:

1. Validate token (not expired, exists)
2. Set UserEmail.verified_at = now()
3. Delete UserEmailVerificationToken
4. Return success

---

### Password Reset

**Endpoint**: `POST /v1/auth/password-reset/request`

**Request**:

```json
{
  "email": "user@example.com"
}
```

**Behavior**:

1. Lookup User by email
2. Generate UserPasswordResetToken
3. Send password reset email with link: `https://app.inferadb.com/reset-password?token=<token>`
4. Email contains 6-digit code and clickable link
5. Token expires in 1 hour

**Endpoint**: `POST /v1/auth/password-reset/confirm`

**Request**:

```json
{
  "token": "<token>",
  "new_password": "newsecret"
}
```

**Behavior**:

1. Validate token (not expired, exists)
2. Hash new password with Argon2id
3. Update User.password_hash
4. Delete all UserPasswordResetToken entries for this user
5. Invalidate all UserSession entries for this user (force re-login)
6. Return success

---

## API Design

### REST API

**Base URL**: `https://api.inferadb.com/v1/management`

**Authentication**: Bearer token (UserSession ID) in `Authorization` header

**Common Headers**:

- `Authorization: Bearer <session_id>`
- `Content-Type: application/json`

**Error Response Format**:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Email address is already in use",
    "details": {
      "field": "email"
    }
  }
}
```

**Pagination** (cursor-based):

- Query params: `?cursor=<snowflake_id>&limit=50`
- Response includes: `data`, `next_cursor`, `has_more`

**Filtering**:

- Query params: `?name=<search>` (case-insensitive substring match)
- Example: `GET /organizations?name=acme`

**Sorting**:

- Default: by `id` (creation order, descending)
- Query params: `?sort=name` (ascending), `?sort=-name` (descending)

---

### REST API Endpoints

#### Authentication Endpoints

- `POST /v1/auth/register` - Register new user with password
- `POST /v1/auth/register/passkey/begin` - Begin passkey-only registration
- `POST /v1/auth/register/passkey/finish` - Complete passkey-only registration
- `POST /v1/auth/login/password` - Login with password
- `POST /v1/auth/login/passkey/begin` - Begin passkey login
- `POST /v1/auth/login/passkey/finish` - Complete passkey login
- `POST /v1/auth/logout` - Logout (revoke current session)
- `POST /v1/auth/verify-email` - Verify email with token
- `POST /v1/auth/password-reset/request` - Request password reset
- `POST /v1/auth/password-reset/confirm` - Confirm password reset with token

#### User Endpoints

- `GET /v1/users/me` - Get current user profile
- `PATCH /v1/users/me` - Update current user profile
- `DELETE /v1/users/me` - Delete current user account
- `GET /v1/users/emails` - List user's emails
- `POST /v1/users/emails` - Add new email (triggers verification)
- `PATCH /v1/users/emails/:id` - Update email (e.g., set as primary)
- `DELETE /v1/users/emails/:id` - Remove email
- `GET /v1/users/passkeys` - List user's passkeys
- `POST /v1/users/passkeys/register/begin` - Begin passkey registration
- `POST /v1/users/passkeys/register/finish` - Complete passkey registration
- `DELETE /v1/users/passkeys/:id` - Delete passkey
- `GET /v1/users/sessions` - List user's active sessions
- `DELETE /v1/users/sessions/:id` - Revoke specific session

#### Organization Endpoints

- `GET /v1/organizations` - List user's organizations
- `POST /v1/organizations` - Create new organization
- `GET /v1/organizations/:org` - Get organization details
- `PATCH /v1/organizations/:org` - Update organization
- `DELETE /v1/organizations/:org` - Delete organization
- `GET /v1/organizations/:org/members` - List organization members
- `PATCH /v1/organizations/:org/members/:member` - Update member role
- `DELETE /v1/organizations/:org/members/:member` - Remove member
- `POST /v1/organizations/:org/invitations` - Create invitation
- `GET /v1/organizations/:org/invitations` - List pending invitations
- `DELETE /v1/organizations/:org/invitations/:invitation` - Revoke invitation
- `POST /v1/organizations/:org/invitations/:token/accept` - Accept invitation
- `POST /v1/organizations/:org/transfer-ownership` - Transfer ownership to another user
- `GET /v1/organizations/:org/clients` - List organization clients
- `POST /v1/organizations/:org/clients` - Create new client (automatically creates first certificate)
- `GET /v1/organizations/:org/clients/:client` - Get client details
- `PATCH /v1/organizations/:org/clients/:client` - Update client (name only)
- `DELETE /v1/organizations/:org/clients/:client` - Delete client (soft delete, requires confirmation)
- `GET /v1/organizations/:org/clients/:client/certificates` - List client certificates (active + revoked last 90 days)
- `POST /v1/organizations/:org/clients/:client/certificates` - Create new certificate for client
- `POST /v1/organizations/:org/clients/:client/certificates/:cert/revoke` - Revoke certificate
- `DELETE /v1/organizations/:org/clients/:client/certificates/:cert` - Delete certificate (requires confirmation)
- `GET /v1/organizations/:org/jwks.json` - Get organization's JWKS (all active certificates, public, no auth)

#### Team Endpoints

- `GET /v1/organizations/:org/teams` - List teams in organization
- `POST /v1/organizations/:org/teams` - Create new team
- `GET /v1/organizations/:org/teams/:team` - Get team details
- `PATCH /v1/organizations/:org/teams/:team` - Update team
- `DELETE /v1/organizations/:org/teams/:team` - Delete team
- `GET /v1/organizations/:org/teams/:team/members` - List team members
- `POST /v1/organizations/:org/teams/:team/members` - Add team member
- `PATCH /v1/organizations/:org/teams/:team/members/:member` - Update team member (e.g., set as manager)
- `DELETE /v1/organizations/:org/teams/:team/members/:member` - Remove team member
- `GET /v1/organizations/:org/teams/:team/permissions` - List team's organization permissions
- `POST /v1/organizations/:org/teams/:team/permissions` - Grant organization permission to team
- `DELETE /v1/organizations/:org/teams/:team/permissions/:permission` - Revoke organization permission from team

#### Vault Endpoints

- `GET /v1/vaults` - List vaults (filtered by user's organization memberships)
- `POST /v1/vaults` - Create new vault
- `GET /v1/vaults/:vault` - Get vault details
- `PATCH /v1/vaults/:vault` - Update vault metadata
- `DELETE /v1/vaults/:vault` - Delete vault
- `GET /v1/vaults/:vault/team-grants` - List team access grants
- `POST /v1/vaults/:vault/team-grants` - Grant team access
- `PATCH /v1/vaults/:vault/team-grants/:grant` - Update team access role
- `DELETE /v1/vaults/:vault/team-grants/:grant` - Revoke team access
- `GET /v1/vaults/:vault/user-grants` - List user access grants
- `POST /v1/vaults/:vault/user-grants` - Grant user access
- `PATCH /v1/vaults/:vault/user-grants/:grant` - Update user access role
- `DELETE /v1/vaults/:vault/user-grants/:grant` - Revoke user access

#### Token Endpoints

- `POST /v1/tokens/vault/:vault` - Generate vault-scoped JWT and refresh token for @server
- `POST /v1/tokens/refresh` - Refresh an expired vault JWT using a refresh token

#### Public Endpoints (No Authentication Required)

- `GET /.well-known/jwks.json` - Global JWKS for all organizations
- `GET /v1/health` - Health check endpoint

---

### gRPC API

**Services Exposed by Management API**:

1. **AuthService**: Authentication operations
   - `LoginPassword(LoginPasswordRequest) → Session`
   - `LoginPasskeyBegin(LoginPasskeyBeginRequest) → PasskeyChallenge`
   - `LoginPasskeyFinish(LoginPasskeyFinishRequest) → Session`
   - `Logout(SessionId) → Empty`
   - `RequestPasswordReset(EmailAddress) → Empty`
   - `ConfirmPasswordReset(ResetToken, NewPassword) → Empty`

2. **UserService**: User management
   - `RegisterUser(UserRegistration) → User`
   - `GetUser(UserId) → User`
   - `UpdateUser(UserId, UserUpdate) → User`
   - `DeleteUser(UserId) → Empty`
   - `AddEmail(UserId, Email) → UserEmail`
   - `VerifyEmail(VerificationToken) → UserEmail`

3. **OrganizationService**: Organization management
   - `CreateOrganization(OrganizationCreate) → Organization`
   - `GetOrganization(OrganizationId) → Organization`
   - `ListOrganizations(UserId, Pagination) → OrganizationList`
   - `UpdateOrganization(OrganizationId, OrganizationUpdate) → Organization`
   - `DeleteOrganization(OrganizationId) → Empty`
   - `InviteMember(OrganizationId, Email, Role) → OrganizationInvitation`
   - `AcceptInvitation(InvitationToken) → OrganizationMember`
   - `UpdateMemberRole(MemberId, NewRole) → OrganizationMember`
   - `RemoveMember(MemberId) → Empty`
   - `TransferOwnership(OrganizationId, NewOwnerUserId) → OrganizationMember`
   - `CreateClient(OrganizationId, ClientName) → Client`
   - `ListClients(OrganizationId) → ClientList`
   - `RevokeClient(OrganizationId, ClientId) → Empty`
   - `RotateClient(OrganizationId, OldClientId, NewClientName) → Client`

4. **VaultService**: Vault management
   - `CreateVault(OrganizationId, VaultCreate) → Vault`
   - `GetVault(VaultId) → Vault`
   - `ListVaults(OrganizationId, Pagination) → VaultList`
   - `UpdateVault(VaultId, VaultUpdate) → Vault`
   - `DeleteVault(VaultId) → Empty`
   - `GrantTeamAccess(VaultId, TeamId, Role) → VaultTeamGrant`
   - `GrantUserAccess(VaultId, UserId, Role) → VaultUserGrant`
   - `RevokeTeamAccess(VaultTeamGrantId) → Empty`
   - `RevokeUserAccess(VaultUserGrantId) → Empty`

5. **TokenService**: Vault token generation
   - `GenerateVaultToken(VaultId) → VaultToken` (returns JWT for @server)

**Services Consumed from @server**:

1. **VaultManagementService**:
   - `CreateVault(VaultId, OrganizationId) → VaultStatus`
   - `DeleteVault(VaultId) → Empty`

---

## Management → Server Privileged Authentication

The Management API requires privileged access to the Server API to perform administrative operations on behalf of organizations and users. This section defines how the Management API authenticates with the Server API for these privileged operations.

### Authentication Mechanism: Client Assertion JWT/JWKS

**Approach**: Use **Client Assertion JWT with JWKS** for Management → Server authentication, mirroring the same pattern used for Client authentication.

**Why JWT/JWKS**:

- **Consistent authentication pattern**: Same JWT/JWKS flow as organization clients (reduces implementation complexity)
- **No certificate management overhead**: No CA setup, certificate rotation, or certificate distribution
- **Cryptographically strong**: Ed25519 signatures provide strong authentication
- **Simple key rotation**: Publish new keys to JWKS endpoint, no orchestrated certificate rollout
- **Excellent developer experience**: Works seamlessly in all environments (local, cloud, Kubernetes)
- **Stateless verification**: Server validates JWTs using public keys from JWKS endpoint

### System API Key

The Management API uses a special **System Client** to authenticate with the Server API. This is distinct from organization clients:

**Key Properties**:

- **Type**: `system` (vs. `organization` for org-level clients)
- **Audience**: `inferadb-server`
- **Scope**: Privileged operations only (`vault.create`, `vault.delete`, `vault.configure`)
- **Lifecycle**: Generated once during initial deployment, rotated periodically (recommended: every 90 days)
- **Storage**: Stored securely in Management API configuration (environment variable or secret management system)

**System API Key Record** (stored in Management database):

```rust
pub struct SystemApiKey {
    pub id: i64,
    pub key_id: String,  // UUID, exposed in JWKS as "kid"
    pub public_key: Vec<u8>,  // Ed25519 public key (32 bytes)
    pub private_key_encrypted: Vec<u8>,  // Encrypted Ed25519 private key
    pub created_at: SystemTime,
    pub rotated_at: Option<SystemTime>,
    pub expires_at: SystemTime,  // Recommended: 90 days from creation
    pub revoked_at: Option<SystemTime>,
    pub scope: String,  // "vault.create vault.delete vault.configure"
}
```

### JWT Client Assertion Flow

**Step 1: Management API generates client assertion JWT**

When the Management API needs to call the Server API, it generates a short-lived JWT (client assertion) signed with its System API Key:

```rust
use jsonwebtoken::{encode, Algorithm, Header, EncodingKey};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct ClientAssertion {
    iss: String,  // "inferadb-management"
    sub: String,  // "inferadb-management"
    aud: String,  // "inferadb-server"
    exp: i64,     // Current time + 60 seconds (short-lived)
    iat: i64,     // Current time
    jti: String,  // Unique JWT ID (UUID) to prevent replay attacks
    scope: String,  // "vault.create vault.delete vault.configure"
}

async fn generate_client_assertion(system_key: &SystemApiKey) -> Result<String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;

    let claims = ClientAssertion {
        iss: "inferadb-management".to_string(),
        sub: "inferadb-management".to_string(),
        aud: "inferadb-server".to_string(),
        exp: now + 60,  // Expires in 60 seconds
        iat: now,
        jti: Uuid::new_v4().to_string(),
        scope: "vault.create vault.delete vault.configure".to_string(),
    };

    let private_key = decrypt_private_key(&system_key.private_key_encrypted)?;

    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(system_key.key_id.clone());

    let token = encode(
        &header,
        &claims,
        &EncodingKey::from_ed_der(&private_key),
    )?;

    Ok(token)
}
```

**Step 2: Include JWT in gRPC metadata**

```rust
use tonic::{metadata::MetadataValue, Request};

async fn create_server_client() -> Result<VaultManagementServiceClient<Channel>> {
    let server_endpoint = env::var("INFERADB_SERVER_GRPC_ENDPOINT")?;

    let channel = Channel::from_shared(server_endpoint)?
        .tls_config(ClientTlsConfig::new())?  // TLS for transport encryption
        .connect()
        .await?;

    Ok(VaultManagementServiceClient::with_interceptor(
        channel,
        move |mut req: Request<()>| {
            // Generate fresh client assertion JWT for each request
            let token = generate_client_assertion(&system_key)?;
            let bearer_token = format!("Bearer {}", token);
            req.metadata_mut().insert(
                "authorization",
                MetadataValue::try_from(&bearer_token)?,
            );
            Ok(req)
        },
    ))
}
```

**Step 3: Server validates JWT using JWKS**

The Server API fetches the Management API's JWKS endpoint to retrieve public keys:

```rust
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

pub async fn validate_management_jwt(token: &str) -> Result<ClientAssertion> {
    // Fetch JWKS from Management API
    let jwks_url = env::var("INFERADB_MANAGEMENT_JWKS_URL")?;
    let jwks = fetch_jwks(&jwks_url).await?;

    // Decode header to get "kid"
    let header = jsonwebtoken::decode_header(token)?;
    let kid = header.kid.ok_or(anyhow!("Missing kid in JWT header"))?;

    // Find matching key in JWKS
    let jwk = jwks.keys.iter()
        .find(|k| k.kid.as_ref() == Some(&kid))
        .ok_or(anyhow!("Unknown key ID: {}", kid))?;

    // Validate JWT
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_audience(&["inferadb-server"]);
    validation.set_issuer(&["inferadb-management"]);

    let token_data = decode::<ClientAssertion>(
        token,
        &DecodingKey::from_jwk(jwk)?,
        &validation,
    )?;

    // Additional validation: Check scope
    if !token_data.claims.scope.contains("vault.create") {
        return Err(anyhow!("Insufficient scope"));
    }

    // Check JTI for replay attack prevention (MANDATORY in production, cache recent JTIs in Redis/FoundationDB)
    // In development mode with in-memory storage, JTI checking can be disabled via config flag
    if config.jti_replay_protection_enabled {
        check_jti_not_replayed(&token_data.claims.jti).await?;
    }

    Ok(token_data.claims)
}
```

### JWKS Endpoint (Management API)

The Management API exposes a JWKS endpoint for the Server to fetch system public keys:

**Endpoint**: `GET /.well-known/system-jwks.json`

**Response**:

```json
{
  "keys": [
    {
      "kty": "OKP",
      "use": "sig",
      "kid": "sys_abc123",
      "crv": "Ed25519",
      "x": "base64url-encoded-public-key"
    }
  ]
}
```

**Caching Strategy** (Server-side):

- Cache JWKS for 5 minutes (same as organization API keys)
- Invalidate cache on JWT validation failure with unknown `kid`
- No active cache invalidation needed (keys rotate slowly, 90-day expiry)

### System API Key Rotation

**Rotation Process**:

1. Generate new System API Key (new key pair, new `key_id`)
2. Publish both old and new keys to JWKS endpoint (overlap period: 24 hours)
3. Update Management API configuration to use new key for signing JWTs
4. Wait 24 hours (allow all Server instances to refresh JWKS cache)
5. Revoke old key (remove from JWKS endpoint)

**Automation**:

- Recommended: Rotate every 90 days
- Alert when key is within 30 days of expiry
- Support emergency rotation endpoint: `POST /v1/system/api-keys/rotate`

### Privileged Operations Authorization

Once authenticated, the Server API must authorize Management API requests based on the JWT scope:

**Server gRPC Interceptor**:

```rust
use tonic::{Request, Status};

pub async fn management_auth_interceptor(
    req: Request<()>,
) -> Result<Request<()>, Status> {
    // Extract JWT from Authorization header
    let token = req.metadata()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(Status::unauthenticated("Missing Authorization header"))?;

    // Validate JWT and extract claims
    let claims = validate_management_jwt(token).await
        .map_err(|e| Status::unauthenticated(format!("Invalid token: {}", e)))?;

    // Verify audience
    if claims.aud != "inferadb-server" {
        return Err(Status::unauthenticated("Invalid audience"));
    }

    // Verify issuer
    if claims.iss != "inferadb-management" {
        return Err(Status::unauthenticated("Invalid issuer"));
    }

    // Token is valid, proceed with request
    Ok(req)
}

impl VaultManagementService for VaultService {
    async fn create_vault(
        &self,
        request: Request<CreateVaultRequest>,
    ) -> Result<Response<VaultStatus>, Status> {
        // Auth already validated by interceptor
        let req = request.into_inner();

        // Verify scope for this operation
        let claims = request.extensions().get::<ClientAssertion>()
            .ok_or(Status::internal("Missing claims"))?;

        if !claims.scope.contains("vault.create") {
            return Err(Status::permission_denied("Insufficient scope"));
        }

        // Proceed with vault creation
        let vault_id = req.vault_id;
        let org_id = req.organization_id;

        self.storage.create_vault_namespace(vault_id, org_id).await
            .map_err(|e| Status::internal(format!("Failed to create vault: {}", e)))?;

        Ok(Response::new(VaultStatus { created: true }))
    }
}
```

### Configuration

**Management API Configuration**:

```yaml
system_api_key:
  key_id: "sys_abc123"
  private_key_path: "/var/run/secrets/inferadb/system-key.pem"  # Or from env variable
  scope: "vault.create vault.delete vault.configure"
  jwt_ttl_seconds: 60  # Short-lived tokens

server_api:
  grpc_endpoint: "https://server.inferadb.com:8081"
  tls_enabled: true  # TLS for transport encryption (not mTLS)
```

**Server API Configuration**:

```yaml
management_auth:
  jwks_url: "https://management.inferadb.com/.well-known/system-jwks.json"
  jwks_cache_ttl_seconds: 300  # 5 minutes
  allowed_issuers: ["inferadb-management"]
  required_audience: "inferadb-server"

  # JTI replay attack prevention (MANDATORY in production)
  jti_replay_protection:
    enabled: true  # MUST be true in production deployments
    ttl_seconds: 120  # Must be > max JWT TTL (60s)
    backend: "foundationdb"  # Production: "foundationdb" or "redis", Dev: "memory"
    # Emergency mode: If backend is unavailable, fail closed (reject all JWTs) to prevent replay attacks
```

### Development Mode

For local development, use the same JWT/JWKS flow but with relaxed validation:

**Management API (Development)**:

```yaml
system_api_key:
  key_id: "dev_key"
  private_key_path: "./dev/system-key.pem"  # Local development key
  scope: "vault.create vault.delete vault.configure"

server_api:
  grpc_endpoint: "http://localhost:8081"  # Plain HTTP is acceptable in dev
  tls_enabled: false
```

**Server API (Development)**:

```yaml
management_auth:
  jwks_url: "http://localhost:3000/.well-known/system-jwks.json"
  jwks_cache_ttl_seconds: 60  # Shorter cache for faster development iteration
  jti_replay_protection:
    enabled: false  # Can be disabled in dev for faster iteration (NOT SAFE for production)
```

⚠️ **Note**: Development keys should NEVER be used in production. Generate production keys using secure random generation.

---

## Server API: Role Enforcement & Tenant Isolation

This section defines how the @server API enforces VaultRole-based authorization and tenant isolation when processing requests from client applications (via vault-scoped JWTs issued by the Management API).

### Overview

The Server API receives requests in two categories:

1. **Privileged requests from Management API**: Administrative operations (CreateVault, DeleteVault) authenticated via mTLS
2. **Tenant requests from client applications**: Data plane operations (Check, Write, etc.) authenticated via vault-scoped JWTs

This section focuses on **tenant requests** and how the Server enforces VaultRole permissions and vault isolation.

### Vault-Scoped JWT Authentication

**JWT Issuance**: Management API issues vault-scoped JWTs via the `POST /v1/tokens/vault/:vault` endpoint.

**JWT Claims**:

```json
{
  "iss": "tenant:acme",
  "sub": "tenant:acme",
  "aud": "https://api.inferadb.com/evaluate",
  "exp": 1730000060,
  "iat": 1730000000,
  "vault_id": "vault_a1b2c3d4e5f6",
  "vault_role": "WRITER",
  "scope": "inferadb.check inferadb.write"
}
```

**Key Claims**:

- **vault_id**: Unique identifier for the vault (enforces tenant isolation)
- **vault_role**: Role for this vault (READER, WRITER, MANAGER, ADMIN)
- **scope**: Space-separated list of allowed operations (derived from vault_role)

### VaultRole Hierarchy

VaultRoles define what operations are permitted within a vault:

```
READER < WRITER < MANAGER < ADMIN
```

**Permission Mapping**:

| VaultRole | Scopes | Allowed Operations |
|-----------|--------|-------------------|
| **READER** | `inferadb.check`, `inferadb.expand` | Read-only operations: Check, Expand, ListRelations |
| **WRITER** | `inferadb.check`, `inferadb.expand`, `inferadb.write` | READER + Write, Delete (data mutations) |
| **MANAGER** | `inferadb.check`, `inferadb.expand`, `inferadb.write`, `inferadb.schema` | WRITER + WriteSchema, DeleteSchema (schema changes) |
| **ADMIN** | `inferadb.check`, `inferadb.expand`, `inferadb.write`, `inferadb.schema`, `inferadb.admin` | MANAGER + administrative operations (if any) |

**Inheritance**: Higher roles include all permissions of lower roles (ADMIN has all READER/WRITER/MANAGER permissions).

### Server gRPC Interceptor for JWT Validation

The Server API uses a gRPC interceptor to validate JWTs and extract authorization context.

**Implementation**:

```rust
use tonic::{Request, Status, metadata::MetadataMap};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};

#[derive(Debug, Clone)]
pub struct VaultAuthContext {
    pub vault_id: String,
    pub vault_role: VaultRole,
    pub scopes: Vec<String>,
    pub tenant_id: String,
}

pub async fn vault_auth_interceptor(
    mut req: Request<()>,
    jwks_cache: Arc<JwksCache>,
) -> Result<Request<()>, Status> {
    // Extract Authorization header
    let token = extract_bearer_token(req.metadata())?;

    // Decode JWT header to get 'kid' and 'iss'
    let header = decode_header(&token)
        .map_err(|_| Status::unauthenticated("Invalid JWT format"))?;

    let kid = header.kid.ok_or(Status::unauthenticated("Missing 'kid' in JWT"))?;

    // Decode to get issuer (tenant_id)
    let unverified_claims: Claims = decode_unverified(&token)?;
    let tenant_id = unverified_claims.iss
        .strip_prefix("tenant:")
        .ok_or(Status::unauthenticated("Invalid issuer format"))?;

    // Fetch public key from JWKS cache (via Management API JWKS endpoint)
    let public_key = jwks_cache.get_key(tenant_id, &kid).await
        .map_err(|_| Status::unauthenticated("Unable to fetch JWKS"))?;

    // Verify JWT signature and claims
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_audience(&["https://api.inferadb.com/evaluate"]);
    validation.set_issuer(&[format!("tenant:{}", tenant_id)]);

    let token_data = decode::<Claims>(&token, &DecodingKey::from_ed_pem(&public_key)?, &validation)
        .map_err(|e| Status::unauthenticated(format!("JWT validation failed: {}", e)))?;

    let claims = token_data.claims;

    // Extract authorization context
    let vault_id = claims.vault_id
        .ok_or(Status::unauthenticated("Missing 'vault_id' claim"))?;

    let vault_role = claims.vault_role
        .ok_or(Status::unauthenticated("Missing 'vault_role' claim"))?;

    let scopes: Vec<String> = claims.scope
        .unwrap_or_default()
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();

    // Attach auth context to request extensions
    let auth_ctx = VaultAuthContext {
        vault_id,
        vault_role: VaultRole::from_str(&vault_role)?,
        scopes,
        tenant_id: tenant_id.to_string(),
    };

    req.extensions_mut().insert(auth_ctx);

    Ok(req)
}
```

### Role-Based Authorization in Handlers

Each gRPC handler enforces role requirements using the `VaultAuthContext`:

```rust
impl CheckService for CheckServiceImpl {
    async fn check(&self, request: Request<CheckRequest>)
        -> Result<Response<CheckResponse>, Status> {
        // Extract auth context from request extensions
        let auth_ctx = request.extensions().get::<VaultAuthContext>()
            .ok_or(Status::unauthenticated("Missing auth context"))?;

        // Require 'inferadb.check' scope
        require_scope(&auth_ctx, "inferadb.check")?;

        // Validate vault_id matches the request
        let req = request.into_inner();
        validate_vault_isolation(&auth_ctx.vault_id, &req.vault_id)?;

        // Authorization passed - proceed with check operation
        let result = self.engine.check(
            &auth_ctx.vault_id,  // Use vault_id from JWT (not from request body)
            &req.resource,
            &req.relation,
            &req.subject,
        ).await?;

        Ok(Response::new(CheckResponse { allowed: result }))
    }
}

impl WriteService for WriteServiceImpl {
    async fn write(&self, request: Request<WriteRequest>)
        -> Result<Response<WriteResponse>, Status> {
        let auth_ctx = request.extensions().get::<VaultAuthContext>()
            .ok_or(Status::unauthenticated("Missing auth context"))?;

        // Require 'inferadb.write' scope (WRITER or higher)
        require_scope(&auth_ctx, "inferadb.write")?;

        let req = request.into_inner();
        validate_vault_isolation(&auth_ctx.vault_id, &req.vault_id)?;

        // Proceed with write operation
        self.engine.write(&auth_ctx.vault_id, req.tuples).await?;

        Ok(Response::new(WriteResponse { success: true }))
    }
}

impl SchemaService for SchemaServiceImpl {
    async fn write_schema(&self, request: Request<WriteSchemaRequest>)
        -> Result<Response<WriteSchemaResponse>, Status> {
        let auth_ctx = request.extensions().get::<VaultAuthContext>()
            .ok_or(Status::unauthenticated("Missing auth context"))?;

        // Require 'inferadb.schema' scope (MANAGER or ADMIN only)
        require_scope(&auth_ctx, "inferadb.schema")?;

        let req = request.into_inner();
        validate_vault_isolation(&auth_ctx.vault_id, &req.vault_id)?;

        // Proceed with schema write
        self.engine.write_schema(&auth_ctx.vault_id, &req.schema).await?;

        Ok(Response::new(WriteSchemaResponse { success: true }))
    }
}
```

### Helper Functions

```rust
pub fn require_scope(auth_ctx: &VaultAuthContext, required_scope: &str) -> Result<(), Status> {
    if !auth_ctx.scopes.contains(&required_scope.to_string()) {
        return Err(Status::permission_denied(
            format!("Missing required scope: {}", required_scope)
        ));
    }
    Ok(())
}

pub fn validate_vault_isolation(jwt_vault_id: &str, request_vault_id: &str) -> Result<(), Status> {
    if jwt_vault_id != request_vault_id {
        return Err(Status::permission_denied(
            "Vault ID mismatch: JWT vault_id does not match request vault_id"
        ));
    }
    Ok(())
}
```

### Tenant Isolation at Storage Layer

The Server API enforces tenant isolation by prefixing all storage operations with the `vault_id` from the JWT:

**FoundationDB Keyspace** (Server side):

```
vault_<vault_id>/
  tuples/
    <namespace>/<object>/<relation>/<subject>
  schema/
    <schema_version>
```

**Example**:

```rust
impl StorageEngine {
    pub async fn write_tuple(
        &self,
        vault_id: &str,  // From JWT (trusted)
        tuple: &RelationTuple,
    ) -> Result<()> {
        // Construct key with vault_id prefix for isolation
        let key = format!(
            "vault_{}/tuples/{}/{}#{}/{}#{}",
            vault_id,
            tuple.resource.namespace,
            tuple.resource.object_type,
            tuple.resource.object_id,
            tuple.relation,
            tuple.subject
        );

        self.fdb.set(key.as_bytes(), &serialize(tuple)?).await?;
        Ok(())
    }

    pub async fn check(
        &self,
        vault_id: &str,  // From JWT (trusted)
        resource: &str,
        relation: &str,
        subject: &str,
    ) -> Result<bool> {
        // All queries scoped to vault_id prefix
        let prefix = format!("vault_{}/tuples/", vault_id);

        // Query only within this vault's keyspace
        let results = self.fdb.get_range(prefix.as_bytes()).await?;

        // Process results...
        Ok(true)
    }
}
```

**Security Guarantee**: Since `vault_id` comes from the **JWT (signed by Management API)** and not from the client request body, clients cannot access other vaults' data by tampering with request parameters.

### JWT Validation with JWKS Cache

The Server API caches JWKS from the Management API to avoid fetching public keys on every request:

**JWKS Endpoint** (Management API): `GET /.well-known/jwks.json`

**Response**:

```json
{
  "keys": [
    {
      "kid": "acme-key-2025-01",
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "base64url-encoded-public-key",
      "use": "sig",
      "alg": "EdDSA"
    }
  ]
}
```

**Server JWKS Cache**:

```rust
use moka::future::Cache;
use std::time::Duration;

pub struct JwksCache {
    management_api_url: String,
    cache: Cache<String, Vec<Jwk>>,  // Key: tenant_id, Value: JWKS keys
    ttl: Duration,
}

impl JwksCache {
    pub async fn get_key(&self, tenant_id: &str, kid: &str) -> Result<Vec<u8>> {
        // Check cache first
        if let Some(keys) = self.cache.get(tenant_id).await {
            if let Some(key) = keys.iter().find(|k| k.kid == kid) {
                return Ok(key.to_pem());
            }
        }

        // Cache miss - fetch from Management API
        let url = format!("{}/.well-known/jwks.json", self.management_api_url);
        let keys: JwksResponse = reqwest::get(&url).await?.json().await?;

        // Cache for TTL (5 minutes)
        self.cache.insert(tenant_id.to_string(), keys.keys.clone()).await;

        // Find requested key
        keys.keys.iter()
            .find(|k| k.kid == kid)
            .map(|k| k.to_pem())
            .ok_or_else(|| anyhow!("Key not found: {}", kid))
    }
}
```

**Server Configuration**:

```yaml
auth:
  management_api_url: "https://management.inferadb.com"
  jwks_cache_ttl: 300  # 5 minutes (matches Management API's grace period)
```

### Authorization Flow Summary

1. **Client request**: Includes `Authorization: Bearer <vault-scoped-jwt>` header
2. **Server interceptor**:
   - Extracts JWT and validates signature using JWKS from Management API
   - Extracts `vault_id`, `vault_role`, `scopes` from JWT claims
   - Attaches `VaultAuthContext` to request extensions
3. **Handler authorization**:
   - Checks required scope (e.g., `inferadb.write` for write operations)
   - Validates `vault_id` in JWT matches `vault_id` in request (if present)
   - Uses `vault_id` from JWT for all storage operations (not from request body)
4. **Storage layer**:
   - All operations prefixed with `vault_{vault_id}/`
   - Complete tenant isolation at keyspace level

### Security Properties

✅ **Tenant Isolation**: Enforced at storage layer using `vault_id` prefix from trusted JWT
✅ **Role-Based Access Control**: VaultRole hierarchy enforced via scope validation
✅ **No Cross-Vault Access**: Clients cannot access other vaults' data (vault_id from JWT, not request)
✅ **JWT Integrity**: All JWTs signed by Management API's Client (Ed25519)
✅ **Key Rotation Support**: JWKS cache automatically picks up new keys within TTL window
✅ **Defense in Depth**: Multiple layers of validation (JWT signature, scope, vault isolation)

---

## Configuration

Configuration follows @server patterns using YAML and environment variables.

**Config File**: `config.yaml`

```yaml
server:
  http_port: 8090  # REST API
  grpc_port: 8091  # gRPC API
  host: "0.0.0.0"

storage:
  backend: "memory"  # or "foundationdb"
  foundationdb:
    cluster_file: "/etc/foundationdb/fdb.cluster"
    key_prefix: "mgmt/"  # Namespace isolation

server_api:
  grpc_endpoint: "http://localhost:8081"
  tls_enabled: false  # Enable in production

auth:
  session_ttl_web: 2592000      # 30 days in seconds (SessionType::WEB)
  session_ttl_cli: 7776000      # 90 days in seconds (SessionType::CLI)
  session_ttl_sdk: 7776000      # 90 days in seconds (SessionType::SDK)
  max_sessions_per_user: 10
  password_reset_token_ttl: 3600      # 1 hour (token expiry for password reset)
  email_verification_token_ttl: 86400  # 24 hours (token expiry for email verification)
  password_min_length: 12       # Minimum password length
  client_rotation_warning_days: 90  # Warn when clients are older than 90 days
  key_encryption_secret: "${INFERADB_MGMT_KEY_ENCRYPTION_SECRET}"  # Required for encrypting Client private keys
  webauthn:
    rp_id: "inferadb.com"
    rp_name: "InferaDB"
    rp_origin: "https://app.inferadb.com"

cors:
  enabled: true
  allowed_origins:
    - "http://localhost:3000"  # Dashboard dev
    - "https://app.inferadb.com"  # Dashboard prod
  allowed_methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
  allowed_headers: ["Authorization", "Content-Type"]

email:
  smtp_host: "smtp.sendgrid.net"
  smtp_port: 587
  smtp_user: "apikey"
  smtp_password: "${SMTP_PASSWORD}"
  from_address: "noreply@inferadb.com"
  from_name: "InferaDB"

rate_limiting:
  enabled: true
  # Token generation limits (per user/email per hour)
  email_verification_tokens_per_hour: 5
  password_reset_tokens_per_hour: 3
  # Authentication attempts (per IP per hour)
  login_attempts_per_ip_per_hour: 100
  # Registration limits (per IP per day)
  registrations_per_ip_per_day: 5

observability:
  metrics_port: 9091
  tracing_enabled: false  # Enable in production
  otlp_endpoint: "http://localhost:4317"
```

**Environment Variable Overrides**:

- `INFERADB_MGMT_STORAGE_BACKEND=foundationdb`
- `INFERADB_MGMT_SERVER_API_GRPC_ENDPOINT=https://server.inferadb.com`
- `SMTP_PASSWORD=<secret>`

---

## Multi-Instance Deployment & Distributed Coordination

The Management API is designed to run as multiple instances for high availability and horizontal scalability. This section defines how instances coordinate without requiring external coordination services like etcd or Consul.

### Architecture Overview

**Deployment Models**:

1. **Single-instance** (development, small deployments)
   - Worker ID: 0 (static)
   - No coordination needed
   - Simpler configuration

2. **Multi-instance** (production, high availability)
   - Worker IDs: 0-1023 (statically assigned)
   - Coordination via FoundationDB (no external dependencies)
   - Horizontal scalability

### Worker ID Assignment Strategy

**Static Assignment (Recommended)**:

- Each instance is assigned a unique worker ID via environment variable `INFERADB_MGMT_WORKER_ID`
- Worker IDs are static and must be unique across all running instances
- Configuration examples:
  - Kubernetes StatefulSet: Use pod ordinal index
  - Docker Compose: Assign explicitly in docker-compose.yml
  - VM/bare metal: Configure in systemd unit files or environment

**Kubernetes Example** (StatefulSet):

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: inferadb-management
spec:
  replicas: 3
  serviceName: inferadb-management
  template:
    spec:
      containers:
      - name: management
        image: inferadb/management:latest
        env:
        - name: POD_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: INFERADB_MGMT_WORKER_ID
          value: "$(echo $POD_NAME | grep -oE '[0-9]+$')"  # Extract ordinal
        # For simple numeric extraction, use init container or entrypoint script:
        # inferadb-management-0 → WORKER_ID=0
        # inferadb-management-1 → WORKER_ID=1
```

**Docker Compose Example**:

```yaml
version: '3.8'
services:
  management-0:
    image: inferadb/management:latest
    environment:
      INFERADB_MGMT_WORKER_ID: 0

  management-1:
    image: inferadb/management:latest
    environment:
      INFERADB_MGMT_WORKER_ID: 1

  management-2:
    image: inferadb/management:latest
    environment:
      INFERADB_MGMT_WORKER_ID: 2
```

### Background Job Coordination

Background jobs (cleanup, email retries, token expiration) must run on exactly one instance at a time to avoid duplicate work.

**Leader Election via FoundationDB**:

We use FoundationDB's atomic compare-and-set operations for distributed leader election without external dependencies.

**Implementation**:

```rust
use foundationdb::*;
use std::time::{Duration, SystemTime};

const LEADER_LEASE_TTL: Duration = Duration::from_secs(30);
const LEADER_KEY: &str = "mgmt/leader/background_jobs";

pub struct LeaderElection {
    db: Database,
    worker_id: u16,
    instance_id: String,  // Unique instance identifier (UUID)
}

impl LeaderElection {
    pub async fn try_become_leader(&self) -> Result<bool> {
        let db = &self.db;

        db.run(|tx, _| async move {
            // Read current leader
            let current_leader = tx.get(LEADER_KEY.as_bytes(), false).await?;

            match current_leader {
                Some(leader_data) => {
                    let leader: LeaderRecord = bincode::deserialize(&leader_data)?;
                    let now = SystemTime::now();

                    // Check if lease expired
                    if leader.expires_at < now {
                        // Lease expired, claim leadership
                        let new_leader = LeaderRecord {
                            instance_id: self.instance_id.clone(),
                            worker_id: self.worker_id,
                            acquired_at: now,
                            expires_at: now + LEADER_LEASE_TTL,
                        };
                        tx.set(LEADER_KEY.as_bytes(), &bincode::serialize(&new_leader)?);
                        return Ok(true);  // We are now leader
                    } else if leader.instance_id == self.instance_id {
                        // We are already leader, renew lease
                        let renewed_leader = LeaderRecord {
                            expires_at: now + LEADER_LEASE_TTL,
                            ..leader
                        };
                        tx.set(LEADER_KEY.as_bytes(), &bincode::serialize(&renewed_leader)?);
                        return Ok(true);  // Still leader
                    } else {
                        // Another instance is leader
                        return Ok(false);
                    }
                }
                None => {
                    // No leader exists, claim leadership
                    let now = SystemTime::now();
                    let new_leader = LeaderRecord {
                        instance_id: self.instance_id.clone(),
                        worker_id: self.worker_id,
                        acquired_at: now,
                        expires_at: now + LEADER_LEASE_TTL,
                    };
                    tx.set(LEADER_KEY.as_bytes(), &bincode::serialize(&new_leader)?);
                    return Ok(true);
                }
            }
        }).await
    }

    pub async fn run_with_leadership<F, Fut>(&self, task: F) -> Result<()>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<()>>,
    {
        loop {
            match self.try_become_leader().await {
                Ok(true) => {
                    // We are leader, run the task
                    info!("Instance {} acquired leadership for background jobs", self.instance_id);

                    // Run task until lease expires or we lose leadership
                    let task_result = tokio::time::timeout(
                        LEADER_LEASE_TTL / 2,  // Run for half the lease duration
                        task()
                    ).await;

                    match task_result {
                        Ok(Ok(())) => {
                            // Task completed successfully, renew lease
                            continue;
                        }
                        Ok(Err(e)) => {
                            warn!("Background job error: {}", e);
                            // Continue trying to maintain leadership
                            continue;
                        }
                        Err(_) => {
                            // Timeout reached, renew lease in next iteration
                            continue;
                        }
                    }
                }
                Ok(false) => {
                    // Another instance is leader, wait before retrying
                    tokio::time::sleep(Duration::from_secs(10)).await;
                }
                Err(e) => {
                    error!("Leader election error: {}", e);
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
struct LeaderRecord {
    instance_id: String,
    worker_id: u16,
    acquired_at: SystemTime,
    expires_at: SystemTime,
}
```

**Background Job Runner**:

```rust
pub async fn run_background_jobs(leader_election: Arc<LeaderElection>) {
    leader_election.run_with_leadership(|| async {
        // Run cleanup job
        cleanup_expired_sessions().await?;
        cleanup_expired_tokens().await?;
        cleanup_soft_deleted_entities().await?;
        send_pending_emails().await?;

        Ok(())
    }).await;
}
```

**Properties**:

- ✅ No external coordination service required (uses FoundationDB)
- ✅ Automatic failover if leader crashes (lease expires)
- ✅ Single active leader at any time (prevents duplicate work)
- ✅ Graceful leadership transitions (lease-based)
- ✅ Works with any number of instances

### Rate Limiting in Multi-Instance Deployments

Rate limiting must be enforced globally across all instances, not per-instance.

**Distributed Rate Limiting via FoundationDB**:

Use FoundationDB atomic operations for distributed counters.

**Implementation**:

```rust
use foundationdb::*;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub struct DistributedRateLimiter {
    db: Database,
}

impl DistributedRateLimiter {
    /// Check and increment rate limit counter
    /// Returns Ok(()) if allowed, Err if rate limit exceeded
    pub async fn check_and_increment(
        &self,
        key: &str,           // e.g., "rate_limit:login:192.168.1.100"
        limit: u32,          // e.g., 100 requests per hour
        window_secs: u64,    // e.g., 3600 seconds (1 hour)
    ) -> Result<()> {
        let db = &self.db;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let window_start = now - (now % window_secs);  // Start of current window

        let counter_key = format!("mgmt/rate_limits/{}/{}", key, window_start);

        db.run(|tx, _| async move {
            // Read current count
            let current_count_bytes = tx.get(counter_key.as_bytes(), false).await?;
            let current_count: u32 = match current_count_bytes {
                Some(bytes) => u32::from_be_bytes(bytes.try_into().unwrap_or([0u8; 4])),
                None => 0,
            };

            if current_count >= limit {
                return Err(anyhow!("Rate limit exceeded: {}/{}", current_count, limit));
            }

            // Increment counter
            let new_count = current_count + 1;
            tx.set(counter_key.as_bytes(), &new_count.to_be_bytes());

            // Set TTL for automatic cleanup (window duration + buffer)
            let ttl_key = format!("{}/ttl", counter_key);
            let expires_at = window_start + window_secs + 3600;  // +1 hour buffer
            tx.set(ttl_key.as_bytes(), &expires_at.to_be_bytes());

            Ok(())
        }).await
    }

    /// Get current count for a rate limit key (for monitoring)
    pub async fn get_current_count(&self, key: &str, window_secs: u64) -> Result<u32> {
        let db = &self.db;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let window_start = now - (now % window_secs);

        let counter_key = format!("mgmt/rate_limits/{}/{}", key, window_start);

        let count_bytes = db.run(|tx, _| async move {
            tx.get(counter_key.as_bytes(), false).await
        }).await?;

        Ok(match count_bytes {
            Some(bytes) => u32::from_be_bytes(bytes.try_into().unwrap_or([0u8; 4])),
            None => 0,
        })
    }

    /// Background cleanup of expired rate limit counters
    pub async fn cleanup_expired_counters(&self) -> Result<()> {
        let db = &self.db;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        db.run(|tx, _| async move {
            let prefix = b"mgmt/rate_limits/";
            let range = Range::starts_with(prefix);

            let kvs = tx.get_range(&range, 1000, false).await?;

            for kv in kvs {
                if kv.key().ends_with(b"/ttl") {
                    let expires_at = u64::from_be_bytes(
                        kv.value().try_into().unwrap_or([0u8; 8])
                    );

                    if expires_at < now {
                        // Delete expired counter and its TTL marker
                        let counter_key = &kv.key()[0..kv.key().len()-4];  // Remove "/ttl"
                        tx.clear(counter_key);
                        tx.clear(kv.key());
                    }
                }
            }

            Ok(())
        }).await
    }
}
```

**Usage Example**:

```rust
// In request handler
let rate_limiter = DistributedRateLimiter::new(db.clone());

// Check login rate limit (100 per hour per IP)
let client_ip = request.client_ip();
rate_limiter.check_and_increment(
    &format!("login:{}", client_ip),
    100,   // limit
    3600,  // 1 hour window
).await.map_err(|_| {
    StatusCode::TOO_MANY_REQUESTS
})?;
```

**Properties**:

- ✅ Global rate limiting across all instances
- ✅ Atomic increment operations (no race conditions)
- ✅ Automatic cleanup of expired counters
- ✅ Sliding/fixed window support
- ✅ No external Redis/Memcached required

### Session Limit Enforcement in Multi-Instance

When enforcing max concurrent sessions (10 per user), we must handle race conditions where multiple instances create sessions simultaneously.

**Strategy**: Use FoundationDB transactions to atomically count and enforce limits.

**Implementation**:

```rust
pub async fn create_session_with_limit(
    db: &Database,
    user_id: i64,
    session_type: SessionType,
    max_sessions: u32,
) -> Result<UserSession> {
    db.run(|tx, _| async move {
        // Count active sessions for this user
        let sessions_prefix = format!("mgmt/users/{}/sessions/", user_id);
        let range = Range::starts_with(sessions_prefix.as_bytes());

        let sessions = tx.get_range(&range, 0, false).await?;

        // Filter out expired sessions
        let now = SystemTime::now();
        let active_sessions: Vec<_> = sessions.iter()
            .filter_map(|kv| bincode::deserialize::<UserSession>(kv.value()).ok())
            .filter(|s| s.expires_at > now && s.deleted_at.is_none())
            .collect();

        if active_sessions.len() >= max_sessions as usize {
            // Find oldest session (by last_activity_at)
            let oldest_session = active_sessions.iter()
                .min_by_key(|s| s.last_activity_at)
                .ok_or_else(|| anyhow!("No sessions to revoke"))?;

            // Soft-delete oldest session
            let mut revoked_session = oldest_session.clone();
            revoked_session.deleted_at = Some(now);

            let session_key = format!(
                "mgmt/users/{}/sessions/{}",
                user_id,
                revoked_session.id
            );
            tx.set(session_key.as_bytes(), &bincode::serialize(&revoked_session)?);

            info!("Revoked oldest session {} for user {}", revoked_session.id, user_id);
        }

        // Create new session
        let new_session = UserSession {
            id: generate_snowflake_id(),
            user_id,
            session_type,
            created_at: now,
            expires_at: now + session_type.default_ttl(),
            last_activity_at: now,
            ip_address: None,
            user_agent: None,
            deleted_at: None,
        };

        let session_key = format!("mgmt/users/{}/sessions/{}", user_id, new_session.id);
        tx.set(session_key.as_bytes(), &bincode::serialize(&new_session)?);

        Ok(new_session)
    }).await
}
```

**Properties**:

- ✅ Atomic enforcement across all instances
- ✅ No race conditions (transaction ensures consistency)
- ✅ Automatic eviction of oldest session when limit reached
- ✅ Expired sessions don't count toward limit

### Instance Health Monitoring

Each instance should expose health and readiness endpoints for load balancer integration.

**Health Endpoint** (`GET /v1/health`):

```rust
#[derive(Serialize)]
struct HealthStatus {
    status: String,           // "healthy" | "unhealthy"
    version: String,          // Application version
    instance_id: String,      // Unique instance identifier
    worker_id: u16,           // Snowflake worker ID
    uptime_seconds: u64,      // Time since startup
    storage_healthy: bool,    // FoundationDB connection status
    is_leader: bool,          // Whether this instance is leader for background jobs
}

async fn health_check(state: AppState) -> Json<HealthStatus> {
    let storage_healthy = state.db.check_health().await.is_ok();
    let is_leader = state.leader_election.is_leader().await;

    Json(HealthStatus {
        status: if storage_healthy { "healthy" } else { "unhealthy" },
        version: env!("CARGO_PKG_VERSION").to_string(),
        instance_id: state.instance_id.clone(),
        worker_id: state.worker_id,
        uptime_seconds: state.started_at.elapsed().as_secs(),
        storage_healthy,
        is_leader,
    })
}
```

**Readiness Endpoint** (`GET /v1/ready`):

Returns 200 OK only when the instance is ready to accept traffic (storage initialized and healthy).

### Graceful Shutdown

Instances must gracefully shut down to avoid dropping in-flight requests.

**Implementation**:

```rust
use tokio::signal;
use std::time::Duration;

pub async fn run_with_graceful_shutdown<F>(
    server_future: F,
    shutdown_timeout: Duration,
) where
    F: std::future::Future<Output = Result<()>>,
{
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

    // Spawn shutdown signal handler
    tokio::spawn(async move {
        signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
        info!("Received shutdown signal, starting graceful shutdown...");
        shutdown_tx.send(()).ok();
    });

    // Run server until shutdown signal
    tokio::select! {
        result = server_future => {
            if let Err(e) = result {
                error!("Server error: {}", e);
            }
        }
        _ = shutdown_rx => {
            info!("Shutdown signal received, waiting for in-flight requests...");

            // Wait for in-flight requests to complete (up to timeout)
            tokio::time::sleep(shutdown_timeout).await;

            info!("Graceful shutdown complete");
        }
    }
}
```

**Usage**:

```rust
#[tokio::main]
async fn main() -> Result<()> {
    let app = create_app().await?;
    let listener = TcpListener::bind("0.0.0.0:8090").await?;

    let server = axum::serve(listener, app);

    run_with_graceful_shutdown(
        server.into_future(),
        Duration::from_secs(30),  // 30-second graceful shutdown timeout
    ).await;

    Ok(())
}
```

### Deployment Recommendations

**Minimum Production Configuration**:

- 3 instances for high availability
- Worker IDs: 0, 1, 2 (statically assigned)
- Load balancer: Round-robin or least-connections
- Health checks: `/health` endpoint every 10 seconds
- Graceful shutdown timeout: 30 seconds

**Scaling Guidelines**:

- Up to 10 instances: Assign worker IDs 0-9
- Up to 100 instances: Assign worker IDs 0-99
- Maximum: 1024 instances (worker IDs 0-1023)

**Zero-Downtime Deployment**:

1. Deploy new version to subset of instances (e.g., 1 out of 3)
2. Wait for health check to pass
3. Monitor error rates and latency
4. If healthy, continue rolling out to remaining instances
5. If issues detected, roll back immediately

---

## Multi-Tenancy & Data Isolation

### FoundationDB Keyspace Design

All data is isolated by entity type and organization to ensure security:

```
mgmt/                                    # Namespace prefix
  users/
    <user_id>/                           # User data
      profile                            # User entity
      emails/<email_id>                  # UserEmail entities
      passkeys/<passkey_id>              # UserPasskey entities
      sessions/<session_id>              # UserSession entities

  orgs/
    <org_id>/                            # Organization data
      profile                            # Organization entity
      members/<member_id>                # OrganizationMember entities
      clients/<client_id>/               # Client entities
        profile                          # Client entity
        certificates/<cert_id>           # ClientCertificate entities
      teams/<team_id>/                   # OrganizationTeam entities
        profile                          # Team entity
        members/<team_member_id>         # OrganizationTeamMember entities
        permissions/<permission_id>      # OrganizationTeamPermission entities
      invitations/<invitation_id>        # OrganizationInvitation entities

  vaults/
    <vault_id>/                          # Vault data
      profile                            # Vault entity
      team_grants/<team_id>              # VaultTeamGrant entities
      user_grants/<user_id>              # VaultUserGrant entities

  tokens/
    email_verification/<token>           # UserEmailVerificationToken lookup
    password_reset/<token>               # UserPasswordResetToken lookup
    invitation/<token>                   # OrganizationInvitation lookup (for global uniqueness enforcement)

  indexes/
    email_to_user/<email_lowercase>      # Email uniqueness + lookup (key = lowercase email, value = user_id)
    credential_to_passkey/<cred_id>      # Passkey credential lookup (key = credential_id, value = passkey_id)
    certificate_kid/<kid>                # Certificate lookup by kid (key = kid, value = (org_id, client_id, cert_id))
```

**Key Changes from Initial Design**:

1. **Client**: Added to orgs keyspace
2. **Vaults**: Moved to top-level (vaults are uniquely identified by vault_id, no need to nest under org)
3. **OrganizationInvitation**: Moved under orgs/<org_id> for better isolation
4. **Indexes**: Clarified that email index uses lowercase email directly (no cryptographic hash needed for uniqueness)
5. **Indexes**: Added client_kid index for JWKS endpoint lookups

**Security Guarantees**:

- Organization data strictly isolated by `<org_id>` prefix
- No cross-organization queries possible
- Indexes use cryptographic hashes where needed for privacy
- All queries scoped to authenticated user's organizations

### Multi-Tenancy Isolation Guarantees

The Management API is designed as a **true multi-tenant SaaS platform** supporting thousands of organizations with complete isolation:

**1. Data Isolation (Storage Layer)**:

- **FoundationDB keyspace partitioning**: All organization data prefixed with `orgs/<org_id>/`
- **Vault data isolation**: Each vault has independent keyspace at `vaults/<vault_id>/`
- **@server isolation**: Server API enforces vault-level isolation with `vault_id` prefix on all operations
- **No shared data**: Organizations cannot access or enumerate other organizations' data
- **Index isolation**: Global indexes (email, passkey credentials) use opaque identifiers with no organization leakage

**2. Authentication Isolation**:

- **User sessions**: UserSession scoped to user, no cross-user session access
- **Client assertions**: Client JWTs scoped to specific organization and vault
- **JWT validation**: @server validates vault_id in JWT matches request vault_id
- **JWKS per-tenant**: Each organization's clients use separate key IDs (kid)

**3. Authorization Isolation**:

- **Role-based access**: OrganizationMember roles (Member, Admin, Owner) scoped to single organization
- **Vault permissions**: VaultUserGrant and VaultTeamGrant scoped to vault + organization
- **API endpoints**: All mutation endpoints require organization context (`/v1/organizations/:org/...`)
- **Permission queries**: Cannot check permissions across organization boundaries

**4. Rate Limiting Isolation**:

- **Per-organization limits**: Each organization has independent rate limit buckets
- **Tier-based limits**: Organizations on higher tiers (PRO, MAX) don't affect DEV tier orgs
- **Server API limits**: @server enforces per-organization rate limits for Check/Write operations
- **No noisy neighbor**: One organization's traffic cannot exhaust another's quota

**5. Audit Logging Isolation**:

- **Per-organization logs**: AuditLog entries indexed by organization_id
- **No cross-org visibility**: Organizations cannot view other organizations' audit logs
- **Retention per-tier**: Free tier (90 days), paid tiers (1 year), isolated per organization

**6. Resource Limits (Multi-Tenant Safeguards)**:

- **Per-user limits**: Max 10 organizations per user (prevents individual abuse)
- **Per-organization limits**: Tier-based limits on users, teams, vaults
- **Global system limits**: Max 100,000 total organizations (prevents platform exhaustion)
- **Monitoring**: Alerts when approaching global limits (80% threshold)

**7. Failure Isolation**:

- **Vault sync failures**: Failed vault creation in one org doesn't affect other orgs
- **Background jobs**: Scoped to specific organizations, failures don't cascade
- **Storage transactions**: FoundationDB ACID transactions ensure partial failures rollback cleanly
- **Worker ID collision**: Independent worker IDs prevent cross-instance data corruption

**8. Billing Isolation** (Future):

- **Tier enforcement**: Organizations on different tiers have independent resource pools
- **Usage tracking**: Per-organization metrics for billing (Check count, Write count, storage)
- **Overage billing**: PRO/MAX tiers support overage billing without affecting other orgs
- **Downgrade enforcement**: Organizations cannot downgrade if exceeding new tier limits

**Testing Multi-Tenancy Isolation**:

The test suite includes dedicated multi-tenant scenarios:

- **Cross-organization access attempts**: Verify org A cannot access org B's resources
- **Concurrent operations**: Multiple organizations creating vaults simultaneously
- **Rate limit independence**: Org A hitting rate limit doesn't affect org B
- **Vault isolation**: JWT for vault_123 cannot access vault_456 data
- **Audit log isolation**: Org A cannot query org B's audit events

### In-Memory Storage

- Use Rust `HashMap` with same keyspace structure
- Mutex/RwLock for thread safety
- Not suitable for production (data loss on restart)

---

## Soft Delete & Cleanup

**Grace Period**: 90 days

**Background Cleanup Task**:

Runs daily (cron-like scheduler) and performs the following:

1. **Soft-deleted entity cleanup** (90-day grace period):
   - Identifies entities where `deleted_at < (now - 90 days)`
   - Hard-deletes entities and all descendants
   - Logs all deletions for audit purposes

2. **Expired session cleanup**:
   - Identifies UserSession entries where `expires_at < now`
   - Hard-deletes expired sessions immediately (no grace period needed)
   - Logs cleanup statistics (sessions deleted per run)

3. **Expired token cleanup**:
   - Hard-delete UserEmailVerificationToken entries where `expires_at < now`
   - Hard-delete UserPasswordResetToken entries where `expires_at < now`
   - These are already cleaned up on use, but this catches abandoned tokens

**Cascade Behavior**:

- When User soft-deleted: UserEmail, UserPasskey, UserSession, OrganizationMember cascaded
- When Organization soft-deleted: Vault, OrganizationTeam, OrganizationMember, OrganizationInvitation cascaded
- When Vault soft-deleted: VaultTeamGrant, VaultUserGrant cascaded
- When Team soft-deleted: OrganizationTeamMember, VaultTeamGrant cascaded

**Immediate Hard Deletes** (no soft delete):

- UserEmailVerificationToken (single-use, no recovery needed)
- UserPasswordResetToken (single-use, no recovery needed)
- OrganizationInvitation (after acceptance or revocation)

---

## Testing Strategy

Follow @server patterns:

- **Unit tests**: In `src/` files (`#[cfg(test)] mod tests`)
- **Integration tests**: In `tests/` directory
- **Use cargo-nextest** for test execution
- **Test fixtures**: Shared utilities in `infera-management-test-fixtures` crate
- **Storage tests**: Run against both in-memory and FoundationDB backends

**Key Test Coverage**:

- Authentication flows (password, passkey)
- Authorization rules (who can do what)
- Email verification and password reset flows
- Organization role enforcement
- Vault access permission precedence
- Cascade delete behavior
- Soft delete and cleanup
- Rate limiting enforcement
- Multi-tenancy isolation

---

## Error Response Taxonomy

Comprehensive error codes for consistent client handling and debugging.

**Error Response Format** (as defined earlier):

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "details": {
      "field": "optional field name",
      "additional_context": "..."
    }
  }
}
```

**Error Codes**:

### Authentication Errors (AUTH_*)

- `AUTH_INVALID_CREDENTIALS`: Email or password incorrect
- `AUTH_PASSKEY_VERIFICATION_FAILED`: Passkey signature verification failed
- `AUTH_SESSION_EXPIRED`: User session has expired
- `AUTH_SESSION_REVOKED`: User session was explicitly revoked
- `AUTH_UNVERIFIED_EMAIL`: Operation requires verified email
- `AUTH_PASSWORD_RESET_REQUIRED`: User must reset password
- `AUTH_MFA_REQUIRED`: Multi-factor authentication required (future)

### Validation Errors (VALIDATION_*)

- `VALIDATION_INVALID_EMAIL`: Email format is invalid
- `VALIDATION_EMAIL_ALREADY_EXISTS`: Email address already registered
- `VALIDATION_PASSWORD_TOO_SHORT`: Password doesn't meet minimum length
- `VALIDATION_INVALID_NAME`: Name contains invalid characters
- `VALIDATION_REQUIRED_FIELD`: Required field is missing
- `VALIDATION_INVALID_VAULT_NAME`: Vault name contains invalid characters or already exists
- `VALIDATION_INVALID_TEAM_NAME`: Team name already exists in organization

### Authorization Errors (AUTHZ_*)

- `AUTHZ_INSUFFICIENT_PERMISSIONS`: User lacks required permission
- `AUTHZ_NOT_ORGANIZATION_MEMBER`: User is not a member of the organization
- `AUTHZ_NOT_TEAM_MEMBER`: User is not a member of the team
- `AUTHZ_REQUIRES_OWNER`: Operation requires Owner role
- `AUTHZ_REQUIRES_ADMIN`: Operation requires Admin or Owner role
- `AUTHZ_VAULT_ACCESS_DENIED`: User lacks access to vault
- `AUTHZ_CANNOT_REMOVE_LAST_OWNER`: Cannot remove the last Owner from organization

### Resource Errors (RESOURCE_*)

- `RESOURCE_NOT_FOUND`: Requested resource does not exist
- `RESOURCE_ALREADY_EXISTS`: Resource with same identifier already exists
- `RESOURCE_DELETED`: Resource was soft-deleted (in grace period)
- `RESOURCE_CONFLICT`: Resource state conflict (e.g., vault name already taken)

### Rate Limiting Errors (RATE_LIMIT_*)

- `RATE_LIMIT_EXCEEDED`: Rate limit exceeded, try again later
- `RATE_LIMIT_LOGIN_ATTEMPTS`: Too many login attempts from this IP
- `RATE_LIMIT_REGISTRATIONS`: Too many registration attempts from this IP
- `RATE_LIMIT_EMAIL_TOKENS`: Too many email verification tokens requested
- `RATE_LIMIT_PASSWORD_RESET_TOKENS`: Too many password reset tokens requested

### Tier Limit Errors (TIER_LIMIT_*)

- `TIER_LIMIT_USERS_EXCEEDED`: Organization has reached maximum users for tier
- `TIER_LIMIT_TEAMS_EXCEEDED`: Organization has reached maximum teams for tier
- `TIER_LIMIT_VAULTS_EXCEEDED`: Organization has reached maximum vaults for tier
- `TIER_LIMIT_DOWNGRADE_BLOCKED`: Cannot downgrade tier due to usage exceeding new limits

### External Service Errors (EXTERNAL_*)

- `EXTERNAL_EMAIL_SEND_FAILED`: Failed to send email (SMTP error)
- `EXTERNAL_SERVER_SYNC_FAILED`: Failed to sync with @server (vault creation/deletion)
- `EXTERNAL_JWKS_FETCH_FAILED`: Failed to fetch JWKS from Management API

### System Errors (SYSTEM_*)

- `SYSTEM_INTERNAL_ERROR`: Unexpected server error
- `SYSTEM_STORAGE_ERROR`: Database/storage layer error
- `SYSTEM_UNAVAILABLE`: Service temporarily unavailable

**HTTP Status Code Mapping**:

- 400 Bad Request: VALIDATION_*, some AUTHZ_*, RESOURCE_CONFLICT
- 401 Unauthorized: AUTH_INVALID_CREDENTIALS, AUTH_SESSION_EXPIRED, AUTH_SESSION_REVOKED
- 403 Forbidden: AUTHZ_* (except those mapped to 400), AUTH_UNVERIFIED_EMAIL
- 404 Not Found: RESOURCE_NOT_FOUND
- 409 Conflict: RESOURCE_ALREADY_EXISTS, RESOURCE_CONFLICT
- 429 Too Many Requests: RATE_LIMIT_*
- 500 Internal Server Error: SYSTEM_*, EXTERNAL_* (except retryable errors)
- 503 Service Unavailable: SYSTEM_UNAVAILABLE

---

## Enhanced Security Features

### Client Emergency Revocation

When a Client's private key is compromised, immediate revocation with propagation to @server is critical.

**Endpoint**: `POST /v1/organizations/:org/clients/:client/emergency-revoke`

**Request**:

```json
{
  "reason": "Security incident: private key exposed in public repository"
}
```

**Behavior**:

1. Validate requester is an Owner
2. Set `revoked_at` on Client - immediate revocation
3. **Do NOT wait for 5-minute JWKS grace period**
4. Immediately notify @server instances via webhook or gRPC:
   - Send `InvalidateJWKS` gRPC call to all known @server instances
   - @server instances immediately clear their JWKS cache
   - Next JWT validation will fetch fresh JWKS (without revoked Client key)
5. Log emergency revocation in audit trail with reason
6. Send notification email to all organization Owners
7. Return success with estimated propagation time

**Implementation**:

```rust
pub async fn emergency_revoke_client(
    org_id: i64,
    client_id: i64,
    reason: String,
) -> Result<EmergencyRevocationResponse> {
    // Revoke Client in database
    let revoked_at = SystemTime::now();
    db.revoke_client(org_id, client_id, revoked_at).await?;

    // Notify all @server instances (via gRPC or webhook)
    let server_instances = discover_server_instances().await?;

    for server_url in server_instances {
        tokio::spawn(async move {
            let client = ServerManagementClient::connect(server_url).await?;
            client.invalidate_jwks(InvalidateJwksRequest {
                organization_id: org_id,
                reason: format!("Emergency Client revocation: {}", reason),
            }).await?;

            info!("Notified @server instance {} of emergency Client revocation", server_url);
            Ok::<(), anyhow::Error>(())
        });
    }

    // Log to audit trail
    audit_log(AuditEvent::ClientEmergencyRevocation {
        org_id,
        client_id,
        reason: reason.clone(),
        revoked_at,
    }).await?;

    // Send notification to all Owners
    notify_organization_owners(org_id, EmailTemplate::ClientEmergencyRevoked {
        reason,
        revoked_at,
    }).await?;

    Ok(EmergencyRevocationResponse {
        revoked_at,
        propagation_status: "in_progress",
        estimated_propagation_seconds: 5,  // Optimistic estimate
    })
}
```

**Properties**:

- ✅ Immediate revocation (no grace period for compromised keys)
- ✅ Proactive notification to @server (don't wait for cache expiry)
- ✅ Audit trail for security incidents
- ✅ Owner notifications for transparency

### JWKS Cache Invalidation Strategy

Enhanced JWKS caching with active invalidation support.

**@server JWKS Cache** (updated implementation):

```rust
pub struct JwksCache {
    management_api_url: String,
    cache: Arc<RwLock<HashMap<String, CachedJwks>>>,
    ttl: Duration,
    invalidation_receiver: mpsc::Receiver<JwksInvalidationEvent>,
}

#[derive(Clone)]
struct CachedJwks {
    keys: Vec<Jwk>,
    cached_at: SystemTime,
    expires_at: SystemTime,
}

impl JwksCache {
    pub async fn get_key(&self, org_id: &str, kid: &str) -> Result<Vec<u8>> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.get(org_id) {
                if cached.expires_at > SystemTime::now() {
                    if let Some(key) = cached.keys.iter().find(|k| k.kid == kid) {
                        return Ok(key.to_pem());
                    }
                }
            }
        }

        // Cache miss or expired - fetch from Management API
        self.refresh_jwks(org_id).await?;

        // Retry lookup after refresh
        let cache = self.cache.read().await;
        cache.get(org_id)
            .and_then(|cached| cached.keys.iter().find(|k| k.kid == kid))
            .map(|k| k.to_pem())
            .ok_or_else(|| anyhow!("Key not found after refresh: {}", kid))
    }

    async fn refresh_jwks(&self, org_id: &str) -> Result<()> {
        let url = format!("{}/organizations/{}/jwks.json", self.management_api_url, org_id);
        let keys: JwksResponse = reqwest::get(&url).await?.json().await?;

        let now = SystemTime::now();
        let cached = CachedJwks {
            keys: keys.keys,
            cached_at: now,
            expires_at: now + self.ttl,
        };

        let mut cache = self.cache.write().await;
        cache.insert(org_id.to_string(), cached);

        Ok(())
    }

    /// Handle invalidation events from Management API
    pub async fn run_invalidation_handler(&mut self) {
        while let Some(event) = self.invalidation_receiver.recv().await {
            match event {
                JwksInvalidationEvent::OrganizationRevocation { org_id } => {
                    info!("Received JWKS invalidation for organization {}", org_id);

                    // Immediately remove from cache (force refresh on next request)
                    let mut cache = self.cache.write().await;
                    cache.remove(&org_id);
                }
                JwksInvalidationEvent::GlobalRefresh => {
                    info!("Received global JWKS refresh signal");

                    // Clear entire cache (force refresh for all organizations)
                    let mut cache = self.cache.write().await;
                    cache.clear();
                }
            }
        }
    }
}

#[derive(Debug)]
enum JwksInvalidationEvent {
    OrganizationRevocation { org_id: String },
    GlobalRefresh,
}
```

**Properties**:

- ✅ Stale-while-revalidate pattern (serve cached while refreshing)
- ✅ Active invalidation via gRPC notifications
- ✅ Graceful degradation (use cached keys if Management API unavailable)
- ✅ Per-organization and global invalidation support

### Password Reset Session Invalidation Options

Enhanced password reset flow with user control over session invalidation.

**Updated Endpoint**: `POST /v1/auth/password-reset/confirm`

**Request**:

```json
{
  "token": "<reset_token>",
  "new_password": "newsecret",
  "invalidate_other_sessions": true  // Optional, default: true
}
```

**Behavior**:

1. Validate reset token (not expired, exists)
2. Hash new password with Argon2id
3. Update User.password_hash
4. Delete all UserPasswordResetToken entries for this user
5. **If `invalidate_other_sessions` is true** (default):
   - Soft-delete all UserSession entries for this user **except the current session** (identified by reset token context)
   - Force re-login on all other devices
   - Send notification email: "Your password was reset. All other sessions have been logged out."
6. **If `invalidate_other_sessions` is false**:
   - Keep all existing sessions active
   - Send notification email: "Your password was reset. Your active sessions remain logged in."
7. Return success with session status

**Response**:

```json
{
  "success": true,
  "sessions_invalidated": 5,  // Number of sessions logged out (if invalidate_other_sessions=true)
  "message": "Password reset successfully. Please log in with your new password."
}
```

**UX Improvements**:

- Default behavior (invalidate all) is most secure
- Power users can opt to keep sessions active (convenience)
- Clear messaging about session status
- Notification emails for transparency

### Vault Deletion Failure Recovery

Enhanced vault deletion with automatic retry and admin intervention.

**Vault Deletion States**:

- `ACTIVE`: Vault is active and operational
- `DELETE_PENDING`: Soft-deleted, awaiting @server sync
- `DELETE_FAILED`: @server sync failed, requires intervention
- `DELETED`: Successfully deleted from both Management and @server

**Enhanced Vault Entity**:

```rust
pub struct Vault {
    pub id: i64,
    pub organization_id: i64,
    pub name: String,
    pub created_at: SystemTime,
    pub updated_at: SystemTime,
    pub sync_status: VaultSyncStatus,
    pub deletion_status: Option<VaultDeletionStatus>,  // New field
    pub deleted_at: Option<SystemTime>,
}

#[derive(Serialize, Deserialize, Clone)]
pub enum VaultDeletionStatus {
    DeletePending { retry_count: u32, last_attempt_at: SystemTime },
    DeleteFailed { error: String, retry_count: u32, last_attempt_at: SystemTime },
    Deleted,
}
```

**Enhanced Deletion Flow**:

```rust
pub async fn delete_vault_with_retry(vault_id: i64) -> Result<()> {
    // 1. Soft-delete vault in Management API
    let now = SystemTime::now();
    db.update_vault(vault_id, |vault| {
        vault.deleted_at = Some(now);
        vault.deletion_status = Some(VaultDeletionStatus::DeletePending {
            retry_count: 0,
            last_attempt_at: now,
        });
    }).await?;

    // 2. Cascade soft-delete access grants immediately
    db.soft_delete_vault_access_grants(vault_id).await?;

    // 3. Attempt @server deletion (with retries)
    for attempt in 1..=3 {
        match delete_vault_in_server(vault_id).await {
            Ok(()) => {
                // Success - mark as fully deleted
                db.update_vault(vault_id, |vault| {
                    vault.sync_status = VaultSyncStatus::Synced;
                    vault.deletion_status = Some(VaultDeletionStatus::Deleted);
                }).await?;

                info!("Vault {} successfully deleted from @server", vault_id);
                return Ok(());
            }
            Err(e) if attempt < 3 => {
                // Retry with exponential backoff
                let backoff = Duration::from_secs(2u64.pow(attempt));
                warn!("Vault {} deletion attempt {} failed: {}. Retrying in {:?}",
                      vault_id, attempt, e, backoff);

                db.update_vault(vault_id, |vault| {
                    vault.deletion_status = Some(VaultDeletionStatus::DeletePending {
                        retry_count: attempt,
                        last_attempt_at: SystemTime::now(),
                    });
                }).await?;

                tokio::time::sleep(backoff).await;
            }
            Err(e) => {
                // Final attempt failed - mark as failed
                error!("Vault {} deletion failed after {} attempts: {}", vault_id, attempt, e);

                db.update_vault(vault_id, |vault| {
                    vault.sync_status = VaultSyncStatus::Failed;
                    vault.deletion_status = Some(VaultDeletionStatus::DeleteFailed {
                        error: e.to_string(),
                        retry_count: attempt,
                        last_attempt_at: SystemTime::now(),
                    });
                }).await?;

                // Notify organization owners
                notify_vault_deletion_failed(vault_id, e.to_string()).await?;

                return Err(e);
            }
        }
    }

    unreachable!()
}
```

**Admin Intervention Endpoint**: `POST /vaults/:vault/retry-deletion`

**Behavior**:

- Only accessible to organization Owners
- Manually triggers deletion retry with fresh attempt
- Logs admin intervention in audit trail
- Returns current deletion status

**Background Job** (runs every 15 minutes):

```rust
async fn retry_failed_vault_deletions() -> Result<()> {
    let failed_vaults = db.find_vaults_with_status(
        VaultDeletionStatus::DeleteFailed { .. }
    ).await?;

    for vault in failed_vaults {
        // Only retry if last attempt was > 1 hour ago
        if let Some(VaultDeletionStatus::DeleteFailed { last_attempt_at, retry_count, .. })
            = vault.deletion_status
        {
            if last_attempt_at.elapsed()? > Duration::from_secs(3600) && retry_count < 10 {
                info!("Retrying vault deletion for vault {} (attempt {})", vault.id, retry_count + 1);
                delete_vault_with_retry(vault.id).await.ok();  // Best effort
            }
        }
    }

    Ok(())
}
```

**Properties**:

- ✅ Automatic retry with exponential backoff
- ✅ Manual admin intervention available
- ✅ Background job for stuck deletions
- ✅ Owner notifications for failures
- ✅ Audit trail for all deletion attempts

---

## Observability & Monitoring (Day 1)

Basic observability features included from initial implementation.

### Structured Logging

Use `tracing` crate for structured logging:

```rust
use tracing::{info, warn, error, instrument};

#[instrument(skip(db), fields(user_id, email))]
pub async fn register_user(
    db: &Database,
    name: String,
    email: String,
    password: String,
) -> Result<UserRegistrationResponse> {
    info!(user_name = %name, email = %email, "Starting user registration");

    // Registration logic...

    info!(user_id, "User registered successfully");
    Ok(response)
}
```

**Log Levels**:

- **ERROR**: Unrecoverable errors, system failures
- **WARN**: Recoverable errors, degraded performance, rate limits
- **INFO**: Significant events (logins, registrations, key rotations)
- **DEBUG**: Detailed diagnostic information (development only)
- **TRACE**: Very verbose logging (development only)

### Metrics

Expose Prometheus metrics on `/metrics` endpoint:

**Counter Metrics**:

- `inferadb_mgmt_requests_total{method, path, status}`: Total HTTP requests
- `inferadb_mgmt_auth_attempts_total{method, result}`: Authentication attempts (password/passkey, success/failure)
- `inferadb_mgmt_registrations_total{result}`: User registrations (success/failure)
- `inferadb_mgmt_rate_limits_exceeded_total{limit_type}`: Rate limit violations

**Histogram Metrics**:

- `inferadb_mgmt_request_duration_seconds{method, path}`: Request latency
- `inferadb_mgmt_db_query_duration_seconds{operation}`: Database query latency
- `inferadb_mgmt_grpc_request_duration_seconds{service, method}`: gRPC request latency (to @server)

**Gauge Metrics**:

- `inferadb_mgmt_active_sessions{session_type}`: Current active sessions
- `inferadb_mgmt_organizations_total`: Total organizations
- `inferadb_mgmt_vaults_total{status}`: Total vaults by sync status
- `inferadb_mgmt_is_leader`: Whether this instance is background job leader (0 or 1)

### Health Checks

**Liveness Probe** (`GET /v1/health/live`):

- Returns 200 OK if process is running
- Used by Kubernetes liveness probe
- Never fails (unless process is dead)

**Readiness Probe** (`GET /v1/health/ready`):

```rust
async fn readiness_check(state: AppState) -> Result<StatusCode> {
    // Check FoundationDB connectivity
    if !state.db.is_healthy().await {
        return Ok(StatusCode::SERVICE_UNAVAILABLE);
    }

    // Check leader election health (if applicable)
    if state.config.multi_instance && !state.leader_election.is_responsive().await {
        return Ok(StatusCode::SERVICE_UNAVAILABLE);
    }

    Ok(StatusCode::OK)
}
```

**Startup Probe** (`GET /v1/health/startup`):

- Returns 200 OK only after initialization complete
- Used by Kubernetes startup probe
- Includes:
  - Database connection established
  - JWKS cache initialized
  - Background jobs started

### Tracing (Optional, Production Recommended)

OpenTelemetry integration for distributed tracing:

```yaml
observability:
  tracing_enabled: true  # Enable in production
  otlp_endpoint: "http://otel-collector:4317"
  service_name: "inferadb-management"
  trace_sampling_rate: 0.1  # Sample 10% of requests
```

---

## Future Considerations

Items deferred for later implementation:

1. **Audit Logging**: Comprehensive audit trail of all sensitive operations
2. **Observability**: Metrics, tracing, structured logging (integrate `infera-observe`)
3. **Billing Integration**: Webhooks for tier changes, usage tracking
4. **Advanced Rate Limiting**: Per-user, per-IP, adaptive throttling
5. **Account Recovery**: Additional recovery mechanisms beyond email
6. **Two-Factor Authentication**: TOTP support in addition to passkeys
7. **JWT Token Exchange**: For truly serverless SPAs (see [AUTHENTICATION.md](AUTHENTICATION.md#5-single-page-applications-spas) and [examples/spa-integration/TRULY_SERVERLESS_OPTIONS.md](../examples/spa-integration/TRULY_SERVERLESS_OPTIONS.md))
8. **Webhooks**: Organization-level webhooks for events
9. **SSO Integration**: SAML, OIDC for enterprise authentication
10. **Advanced Search**: Full-text search across entities
