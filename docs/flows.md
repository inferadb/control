# Data Flows

This document illustrates the data flows for key operations in InferaDB Control.

## User Registration Flow

Registration uses the 3-step email code authentication flow. New users are detected at the verify step and must complete registration separately.

```mermaid
sequenceDiagram
    participant User
    participant API as Control
    participant DB as Ledger
    participant Email as Email Service

    User->>API: POST /control/v1/auth/email/initiate<br/>{email, region?}

    API->>API: Validate Email Format

    alt Validation Fails
        API-->>User: 400 Bad Request
    end

    API->>DB: Initiate Email Verification
    DB-->>API: Verification Code

    API->>Email: Send Verification Code<br/>(6-character code, 10 min expiry)
    Email-->>User: Verification Email

    API-->>User: 200 OK<br/>{message: "verification code sent"}

    User->>API: POST /control/v1/auth/email/verify<br/>{email, code, region?}

    API->>DB: Verify Email Code
    DB-->>API: NewUser {onboarding_token}

    API-->>User: 200 OK<br/>{status: "registration_required",<br/>onboarding_token}

    User->>API: POST /control/v1/auth/email/complete<br/>{onboarding_token, email, name,<br/>organization_name, region?}

    API->>API: Validate Email, Name, Org Name

    API->>DB: Complete Registration<br/>(Create User + Default Org)
    DB-->>API: User + Organization + Session

    API-->>User: 200 OK<br/>{registration: {user, organization,<br/>access_token, refresh_token}}

    Note over User: Cookies set:<br/>inferadb_access (15 min)<br/>inferadb_refresh (30 days)
```

## Login Flow

Existing users authenticate via the email code flow. If TOTP is enabled, a second factor is required.

```mermaid
sequenceDiagram
    participant User
    participant API as Control
    participant DB as Ledger
    participant Email as Email Service

    User->>API: POST /control/v1/auth/email/initiate<br/>{email}

    API->>DB: Initiate Email Verification
    DB-->>API: Verification Code

    API->>Email: Send Verification Code
    Email-->>User: Verification Email

    API-->>User: 200 OK<br/>{message: "verification code sent"}

    User->>API: POST /control/v1/auth/email/verify<br/>{email, code}

    API->>DB: Verify Email Code
    DB-->>API: ExistingUser {session}

    API-->>User: 200 OK<br/>{status: "authenticated",<br/>access_token, refresh_token}

    Note over User: Cookies set:<br/>inferadb_access (15 min)<br/>inferadb_refresh (30 days)

    alt TOTP Enabled
        Note over DB: Returns TotpRequired instead
        API-->>User: 200 OK<br/>{status: "totp_required",<br/>challenge_nonce}

        User->>API: POST /control/v1/auth/totp/verify<br/>{user_slug, totp_code, challenge_nonce}
        API->>DB: Verify TOTP
        DB-->>API: Session Tokens

        API-->>User: 200 OK<br/>{access_token, refresh_token}
    end
```

## Token Generation Flow

```mermaid
sequenceDiagram
    participant App as Application
    participant API as Control
    participant DB as Ledger
    participant Engine as InferaDB Engine

    App->>API: POST /control/v1/organizations/{org}/vaults/{vault}/tokens<br/>Authorization: Bearer {access_token}<br/>{app: <app_slug>, scopes: [...]}

    API->>API: Validate JWT Access Token<br/>(Ledger round-trip for write routes)

    alt Token Invalid/Expired
        API-->>App: 401 Unauthorized
    end

    API->>DB: Get App<br/>(Verify caller has access)
    DB-->>API: App Details

    alt App Not Found / No Access
        API-->>App: Error
    end

    API->>DB: Create Vault Token<br/>(org, app, vault, scopes)
    DB-->>API: Token Pair + Expiry

    API-->>App: 201 Created<br/>{access_token, refresh_token,<br/>token_type, expires_in}

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

    User->>API: POST /control/v1/organizations<br/>{name, tier}<br/>Authorization: Bearer {access_token}

    API->>API: Validate JWT Access Token

    API->>DB: Count User's Organizations
    DB-->>API: Organization Count

    alt Exceeds Per-User Limit (10) or Global Limit (100k)
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

## Client Certificate Generation Flow

```mermaid
sequenceDiagram
    participant Admin
    participant API as Control
    participant DB as Ledger

    Admin->>API: POST /control/v1/organizations/{org}/clients/{client}/certificates<br/>{name}<br/>Authorization: Bearer {access_token}

    API->>API: Validate JWT Access Token

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

    API->>DB: Refresh Token<br/>(validates, rotates, issues new pair)
    DB-->>API: New Token Pair

    alt Token Invalid/Expired/Used
        API-->>App: Error
    end

    API-->>App: 200 OK<br/>{access_token, refresh_token,<br/>token_type, expires_in}
```

## Email Verification Flow

```mermaid
sequenceDiagram
    participant User
    participant API as Control
    participant DB as Ledger

    User->>API: POST /control/v1/auth/verify-email<br/>{token}

    API->>DB: Verify User Email (token)

    alt Token Invalid/Expired
        API-->>User: Error
    end

    DB-->>API: Email Verified

    API-->>User: 200 OK<br/>{message: "Email verified successfully",<br/>verified: true}
```

## Audit Log Flow

```mermaid
sequenceDiagram
    participant User
    participant API as Control
    participant Handler as Request Handler
    participant DB as Ledger

    User->>API: POST /control/v1/organizations/{org}/vaults<br/>{name}<br/>Authorization: Bearer {access_token}

    API->>API: Extract Auth Context<br/>(user_id from JWT, org_id, IP, user_agent)

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

    User->>API: POST /control/v1/auth/email/initiate<br/>(Request 1)

    API->>RateLimit: Check Rate Limit<br/>(category: login_ip, IP: x.x.x.x)
    RateLimit->>DB: Get Current Window Count
    DB-->>RateLimit: Count: 1/100 (within limit)

    RateLimit->>DB: Increment Counter
    RateLimit-->>API: ALLOWED

    API->>API: Process Request
    API-->>User: 200 OK

    Note over User,DB: ... 99 more requests ...

    User->>API: POST /control/v1/auth/email/initiate<br/>(Request 101)

    API->>RateLimit: Check Rate Limit
    RateLimit->>DB: Get Current Window Count
    DB-->>RateLimit: Count: 100/100 (at limit)

    RateLimit-->>API: BLOCKED

    API-->>User: 429 Too Many Requests<br/>Retry-After: {seconds}

    Note over User: Wait for window to reset (1 hour window)
```

## Further Reading

- [Architecture](architecture.md): System architecture diagrams and deployment topology
- [Authentication](authentication.md): Detailed authentication mechanisms
- [Overview](overview.md): Complete entity definitions and data model
