# Data Flows

This document illustrates the data flows for key operations in InferaDB Control.

## User Registration Flow

```mermaid
sequenceDiagram
    participant User
    participant API as Control
    participant DB as Ledger
    participant Email as Email Service

    User->>API: POST /control/v1/auth/register<br/>{email, password, name}

    API->>API: Validate Input<br/>(email format, password strength)

    alt Validation Fails
        API-->>User: 400 Bad Request
    end

    API->>DB: Check Email Exists
    DB-->>API: Email Available

    alt Email Already Registered
        API-->>User: 409 Conflict
    end

    API->>API: Hash Password (Argon2)
    API->>API: Generate User ID (Snowflake)
    API->>API: Generate Session ID (Snowflake)
    API->>API: Generate Org ID (Snowflake)
    API->>API: Generate Member ID (Snowflake)

    API->>DB: BEGIN TRANSACTION
    API->>DB: Create User
    API->>DB: Create User Email
    API->>DB: Create User Session
    API->>DB: Create Default Organization
    API->>DB: Create Organization Member (Owner)
    API->>DB: COMMIT TRANSACTION

    API->>API: Generate Email Verification Token
    API->>DB: Store Verification Token

    API->>Email: Send Verification Email
    Email-->>User: Verification Email

    API-->>User: 201 Created<br/>{session_token, user, organization}
```

## Login Flow

```mermaid
sequenceDiagram
    participant User
    participant API as Control
    participant DB as Ledger

    User->>API: POST /control/v1/auth/login/password<br/>{email, password}

    API->>DB: Get User by Email
    DB-->>API: User + Password Hash

    alt User Not Found
        API-->>User: 401 Unauthorized
    end

    API->>API: Verify Password (Argon2)

    alt Password Invalid
        API-->>User: 401 Unauthorized
    end

    alt Account Deleted
        API-->>User: 401 Unauthorized
    end

    API->>API: Generate Session ID
    API->>DB: Create User Session<br/>(Type: Web, 30 day TTL)

    API->>DB: Get User Organizations
    DB-->>API: Organization List

    API-->>User: 200 OK<br/>{session_token, user, organizations}

    Note over User: Cookie: infera_session={session_id}
```

## Token Generation Flow

```mermaid
sequenceDiagram
    participant App as Application
    participant API as Control
    participant DB as Ledger
    participant Engine as InferaDB Engine

    App->>API: POST /control/v1/organizations/{org}/vaults/{vault}/tokens<br/>Cookie: infera_session={session_id}

    API->>DB: Validate Session
    DB-->>API: Session + User

    alt Session Invalid/Expired
        API-->>App: 401 Unauthorized
    end

    API->>DB: Get Vault
    DB-->>API: Vault Details

    alt Vault Not Found
        API-->>App: 404 Not Found
    end

    API->>DB: Check User Access to Vault<br/>(Direct Grant or Team Grant)
    DB-->>API: Access Level

    alt No Access
        API-->>App: 403 Forbidden
    end

    API->>DB: Get Vault Client Certificates
    DB-->>API: Active Certificates

    API->>API: Select Certificate (Most Recent)
    API->>API: Load Private Key<br/>(Decrypt with Master Secret)

    API->>API: Generate JWT Claims<br/>{vault_id, org_id, scopes, exp}
    API->>API: Sign JWT with Ed25519<br/>(Client Private Key)

    API->>DB: Create Refresh Token<br/>(90 day TTL)

    API-->>App: 200 OK<br/>{access_token, refresh_token, expires_in}

    Note over App: App can now call Engine
    App->>Engine: POST /v1/evaluate<br/>Authorization: Bearer {access_token}
    Engine-->>App: Authorization Decision
```

## Organization Creation Flow

```mermaid
sequenceDiagram
    participant User
    participant API as Control
    participant DB as Ledger

    User->>API: POST /control/v1/organizations<br/>{name, tier}<br/>Cookie: infera_session={session_id}

    API->>DB: Validate Session
    DB-->>API: Session + User

    API->>DB: Count User's Organizations
    DB-->>API: Organization Count

    alt Exceeds Global Limit (100k)
        API-->>User: 400 Bad Request
    end

    API->>API: Validate Organization Name
    API->>API: Generate Org ID
    API->>API: Generate Member ID

    API->>DB: BEGIN TRANSACTION
    API->>DB: Create Organization
    API->>DB: Create Organization Member<br/>(User as Owner)
    API->>DB: COMMIT TRANSACTION

    API-->>User: 201 Created<br/>{organization}
```

## Vault Access Grant Flow

```mermaid
sequenceDiagram
    participant Admin
    participant API as Control
    participant DB as Ledger

    Admin->>API: POST /control/v1/organizations/{org}/vaults/{vault}/user-grants<br/>{user_id, role}<br/>Cookie: infera_session={session_id}

    API->>DB: Validate Session
    DB-->>API: Session + Admin User

    API->>DB: Get Organization Member
    DB-->>API: Admin Membership

    alt Not Admin/Owner
        API-->>Admin: 403 Forbidden
    end

    API->>DB: Get Vault
    DB-->>API: Vault Details

    alt Wrong Organization
        API-->>Admin: 404 Not Found
    end

    API->>DB: Get Target User
    DB-->>API: User Details

    API->>DB: Check User in Organization
    DB-->>API: User Membership

    alt User Not in Org
        API-->>Admin: 400 Bad Request
    end

    API->>API: Generate Grant ID
    API->>DB: Create Vault User Grant<br/>{vault_id, user_id, role}

    API-->>Admin: 201 Created<br/>{grant}

    Note over Admin,DB: User can now generate tokens for this vault
```

## Client Certificate Generation Flow

```mermaid
sequenceDiagram
    participant Admin
    participant API as Control
    participant DB as Ledger

    Admin->>API: POST /control/v1/organizations/{org}/clients/{client}/certificates<br/>{name}<br/>Cookie: infera_session={session_id}

    API->>DB: Validate Session
    DB-->>API: Session + Admin User

    API->>DB: Get Organization Member
    DB-->>API: Admin Membership

    alt Not Admin/Owner
        API-->>Admin: 403 Forbidden
    end

    API->>DB: Get Client
    DB-->>API: Client Details

    alt Wrong Organization
        API-->>Admin: 404 Not Found
    end

    API->>DB: Count Client Certificates
    DB-->>API: Certificate Count

    alt Exceeds Org Tier Limit
        API-->>Admin: 400 Bad Request
    end

    API->>API: Generate Ed25519 Keypair
    API->>API: Encrypt Private Key<br/>(AES-GCM with Master Secret)
    API->>API: Generate Certificate ID
    API->>API: Generate KID (Key ID)

    API->>DB: Create Client Certificate<br/>{public_key, encrypted_private_key, kid}

    API->>API: Decrypt Private Key<br/>(for one-time return)

    API-->>Admin: 201 Created<br/>{certificate, private_key_pem}

    Note over Admin: IMPORTANT: Save private_key_pem securely.<br/>It cannot be retrieved again.
```

## Refresh Token Flow

```mermaid
sequenceDiagram
    participant App as Application
    participant API as Control
    participant DB as Ledger

    App->>API: POST /control/v1/tokens/refresh<br/>{refresh_token}

    API->>DB: Get Refresh Token
    DB-->>API: Token Details

    alt Token Not Found
        API-->>App: 401 Unauthorized
    end

    alt Token Expired
        API->>DB: Mark Token as Used
        API-->>App: 401 Unauthorized
    end

    alt Token Already Used
        API-->>App: 401 Unauthorized
    end

    alt Token Revoked
        API-->>App: 401 Unauthorized
    end

    API->>DB: Mark Token as Used
    API->>DB: Get Vault
    DB-->>API: Vault Details

    API->>DB: Get Client Certificates
    DB-->>API: Active Certificates

    API->>API: Generate New JWT
    API->>API: Sign with Certificate

    API->>DB: Create New Refresh Token

    API-->>App: 200 OK<br/>{access_token, refresh_token, expires_in}
```

## Email Verification Flow

```mermaid
sequenceDiagram
    participant User
    participant API as Control
    participant DB as Ledger

    User->>API: POST /control/v1/auth/verify-email<br/>{token}

    API->>DB: Get Verification Token
    DB-->>API: Token Details

    alt Token Not Found
        API-->>User: 400 Bad Request
    end

    alt Token Expired
        API-->>User: 400 Bad Request
    end

    alt Token Already Used
        API-->>User: 400 Bad Request
    end

    API->>DB: Mark Token as Used
    API->>DB: Get User Email
    DB-->>API: Email Details

    alt Already Verified
        API-->>User: 200 OK<br/>{message: "Already verified"}
    end

    API->>DB: Mark Email as Verified

    API-->>User: 200 OK<br/>{message: "Email verified successfully"}
```

## Password Reset Flow

```mermaid
sequenceDiagram
    participant User
    participant API as Control
    participant DB as Ledger
    participant Email as Email Service

    rect rgb(240, 240, 240)
    Note over User,Email: Step 1: Request Reset
    User->>API: POST /control/v1/auth/password-reset/request<br/>{email}

    API->>DB: Get User by Email
    DB-->>API: User Details

    alt User Not Found
        Note over API: Still return success (security)
        API-->>User: 200 OK
    end

    API->>API: Generate Reset Token
    API->>DB: Store Reset Token<br/>(1 hour expiry)

    API->>Email: Send Reset Email<br/>(token + reset link)
    Email-->>User: Reset Email

    API-->>User: 200 OK
    end

    rect rgb(255, 250, 240)
    Note over User,DB: Step 2: Reset Password
    User->>API: POST /control/v1/auth/password-reset/confirm<br/>{token, new_password}

    API->>DB: Get Reset Token
    DB-->>API: Token Details

    alt Token Invalid/Expired/Used
        API-->>User: 400 Bad Request
    end

    API->>API: Validate New Password<br/>(strength requirements)

    alt Password Too Weak
        API-->>User: 400 Bad Request
    end

    API->>DB: Mark Token as Used
    API->>API: Hash New Password (Argon2)
    API->>DB: Update User Password

    API->>DB: Revoke All User Sessions<br/>(force re-login)

    API-->>User: 200 OK
    end
```

## Multi-Instance Leader Election Flow

```mermaid
sequenceDiagram
    participant I1 as Instance 1
    participant I2 as Instance 2
    participant I3 as Instance 3
    participant Ledger as Ledger

    rect rgb(240, 255, 240)
    Note over I1,Ledger: Startup & Initial Leader Election

    I1->>Ledger: Acquire Leader Lock
    Ledger-->>I1: Lock Acquired → LEADER

    I2->>Ledger: Acquire Leader Lock
    Ledger-->>I2: Lock Held → FOLLOWER

    I3->>Ledger: Acquire Leader Lock
    Ledger-->>I3: Lock Held → FOLLOWER
    end

    rect rgb(255, 255, 240)
    Note over I1,Ledger: Normal Operations

    loop Every 10s - All Instances
        I1->>Ledger: Renew Leader Lock
        I2->>Ledger: Update Heartbeat
        I3->>Ledger: Update Heartbeat
    end

    loop Every 30s - Leader Only
        I1->>Ledger: Cleanup Expired Sessions
        I1->>Ledger: Cleanup Expired Tokens
        I1->>Ledger: Send Email Queue
    end
    end

    rect rgb(255, 240, 240)
    Note over I1,Ledger: Leader Failure Scenario

    I1-xI1: Leader Crashes

    I2->>Ledger: Detect Stale Lock (no renewal)
    I2->>Ledger: Attempt Lock Acquisition
    Ledger-->>I2: Lock Acquired → LEADER

    I3->>Ledger: Attempt Lock Acquisition
    Ledger-->>I3: Lock Held → FOLLOWER

    Note over I2: Instance 2 is now leader

    loop Every 30s - New Leader
        I2->>Ledger: Cleanup Expired Sessions
        I2->>Ledger: Cleanup Expired Tokens
    end
    end
```

## Audit Log Flow

```mermaid
sequenceDiagram
    participant User
    participant API as Control
    participant Handler as Request Handler
    participant DB as Ledger

    User->>API: POST /control/v1/organizations/{org}/vaults<br/>{name}<br/>Cookie: infera_session={session_id}

    API->>API: Extract Session Context<br/>(user_id, org_id, IP, user_agent)

    API->>Handler: Process Request

    Handler->>DB: Create Vault
    DB-->>Handler: Vault Created

    Handler->>Handler: Generate Audit Log Entry<br/>{action: "vault.create", actor: user_id, resource: vault_id}

    Handler->>DB: Store Audit Log

    Handler-->>API: Response

    API-->>User: 201 Created<br/>{vault}

    Note over DB: Audit logs queryable via<br/>GET /control/v1/organizations/{org}/audit-logs
```

## Team-Based Vault Access

```mermaid
graph TB
    subgraph "Organization"
        User1[User: Alice]
        User2[User: Bob]
        User3[User: Charlie]
    end

    subgraph "Teams"
        Team1[Team: Engineering]
        Team2[Team: Security]
    end

    subgraph "Vaults"
        Vault1[Vault: Production Policies]
        Vault2[Vault: Staging Policies]
    end

    User1 -->|Member| Team1
    User2 -->|Member| Team1
    User2 -->|Member| Team2
    User3 -->|Member| Team2

    Team1 -->|Editor| Vault1
    Team1 -->|Viewer| Vault2
    Team2 -->|Admin| Vault1

    style Vault1 fill:#4CAF50
    style Vault2 fill:#2196F3
    style Team1 fill:#FF9800
    style Team2 fill:#9C27B0
```

**Resulting Permissions:**

- **Alice**: Can edit Production (via Engineering), can view Staging (via Engineering)
- **Bob**: Can edit Production (via Engineering), can admin Production (via Security), can view Staging (via Engineering)
- **Charlie**: Can admin Production (via Security)

## Rate Limiting Flow

```mermaid
sequenceDiagram
    participant User
    participant API as Control
    participant RateLimit as Rate Limiter
    participant DB as Ledger

    User->>API: POST /control/v1/auth/login/password<br/>(Request 1)

    API->>RateLimit: Check Rate Limit<br/>(category: auth.login, IP: x.x.x.x)
    RateLimit->>DB: Get Current Window Count
    DB-->>RateLimit: Count: 1/10 (within limit)

    RateLimit->>DB: Increment Counter
    RateLimit-->>API: ALLOWED

    API->>API: Process Login
    API-->>User: 200 OK

    Note over User,DB: ... 9 more requests ...

    User->>API: POST /control/v1/auth/login/password<br/>(Request 11)

    API->>RateLimit: Check Rate Limit
    RateLimit->>DB: Get Current Window Count
    DB-->>RateLimit: Count: 10/10 (at limit)

    RateLimit-->>API: BLOCKED

    API-->>User: 429 Too Many Requests<br/>Retry-After: 60

    Note over User: Wait for window to reset
```

## Session Cleanup (Background Job)

```mermaid
sequenceDiagram
    participant Leader as Leader Instance
    participant DB as Ledger

    loop Every 30 seconds (Leader Only)
        Leader->>DB: Query Expired Sessions<br/>(expired_at < now())

        DB-->>Leader: List of Expired Sessions

        loop For Each Expired Session
            Leader->>DB: Soft Delete Session
        end

        Leader->>DB: Query Expired Tokens<br/>(expires_at < now())

        DB-->>Leader: List of Expired Tokens

        loop For Each Expired Token
            Leader->>DB: Delete Token
        end

        Leader->>DB: Query Expired JTI Entries<br/>(expires_at < now())

        DB-->>Leader: List of Expired JTIs

        loop For Each Expired JTI
            Leader->>DB: Delete JTI Entry
        end
    end
```

## Further Reading

- [Architecture](architecture.md): System architecture diagrams and deployment topology
- [Authentication](authentication.md): Detailed authentication mechanisms
- [Overview](overview.md): Complete entity definitions and data model
