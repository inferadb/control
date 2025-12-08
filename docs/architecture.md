# System Architecture

This document provides visual diagrams of the InferaDB Control architecture, deployment topology, and component interactions.

## Component Architecture

Control follows a layered architecture with clear separation of concerns:

```mermaid
graph TB
    subgraph "Client Layer"
        Dashboard[Web Dashboard]
        CLI[CLI Tools]
        Mobile[Mobile Apps]
    end

    subgraph "API Layer"
        REST[Public REST API<br/>Port 9090]
        GRPC[Public gRPC API<br/>Port 9091]
        Internal[Internal REST API<br/>Port 9092]
    end

    subgraph "Application Layer"
        Auth[Authentication<br/>Handlers]
        Org[Organization<br/>Handlers]
        Vault[Vault<br/>Handlers]
        Client[Client<br/>Handlers]
        Token[Token<br/>Generation]
    end

    subgraph "Core Layer"
        Entities[Entity Models]
        Repos[Repositories]
        Crypto[Cryptography]
        JWT[JWT Service]
        Email[Email Service]
    end

    subgraph "Storage Layer"
        Storage[Storage<br/>Abstraction]
        Memory[Memory<br/>Backend<br/>(Implemented)]
        FDB[FoundationDB<br/>Backend<br/>(Planned)]
    end

    subgraph "External Services"
        Server[InferaDB Server<br/>gRPC]
        SMTP[SMTP Server<br/>Email]
        Metrics[Prometheus<br/>Metrics]
        Tracing[Jaeger<br/>Traces]
    end

    Dashboard --> REST
    CLI --> REST
    Mobile --> REST
    Dashboard --> GRPC

    REST --> Auth
    REST --> Org
    REST --> Vault
    REST --> Client
    GRPC --> Auth
    GRPC --> Token

    Auth --> Entities
    Org --> Entities
    Vault --> Entities
    Client --> Entities
    Token --> JWT

    Entities --> Repos
    Repos --> Crypto
    JWT --> Crypto
    Auth --> Email

    Repos --> Storage
    Storage --> Memory
    Storage --> FDB

    Token --> Server
    Email --> SMTP
    REST --> Metrics
    GRPC --> Metrics
    REST --> Tracing
    GRPC --> Tracing

    style REST fill:#4CAF50
    style GRPC fill:#4CAF50
    style Storage fill:#2196F3
    style Server fill:#FF9800
```

## Deployment Topology

### Single Instance Deployment

```mermaid
graph LR
    subgraph "Load Balancer (Optional)"
        LB[Load Balancer<br/>:443<br/>TLS Termination]
    end

    subgraph "Control"
        API[inferadb-control<br/>Public REST: 9090<br/>Public gRPC: 9091<br/>Internal REST: 9092<br/>Storage: In-Memory]
    end

    subgraph "Services"
        SMTP[SMTP Server]
        Prom[Prometheus]
        Jaeger[Jaeger]
    end

    LB --> API
    API --> SMTP
    API --> Prom
    API --> Jaeger

    style API fill:#4CAF50
```

**Important Considerations**:

- All data stored in RAM (no persistence)
- Server restart loses all data
- Ensure adequate RAM allocation (8GB+ recommended)
- Implement regular export/backup procedures

### Multi-Instance Deployment

```mermaid
graph TB
    subgraph "Load Balancer"
        LB[Load Balancer<br/>TLS Termination]
    end

    subgraph "Control Instances"
        API1[Instance 1<br/>Worker ID: 0<br/>Leader]
        API2[Instance 2<br/>Worker ID: 1]
        API3[Instance 3<br/>Worker ID: 2]
    end

    subgraph "FoundationDB Cluster"
        FDB1[(FDB Node 1)]
        FDB2[(FDB Node 2)]
        FDB3[(FDB Node 3)]
    end

    subgraph "Observability"
        Prom[Prometheus]
        Jaeger[Jaeger]
        Grafana[Grafana]
    end

    LB --> API1
    LB --> API2
    LB --> API3

    API1 -.Leader Election.-> FDB1
    API2 -.Heartbeat.-> FDB1
    API3 -.Heartbeat.-> FDB1

    API1 --> FDB1
    API1 --> FDB2
    API1 --> FDB3

    API2 --> FDB1
    API2 --> FDB2
    API2 --> FDB3

    API3 --> FDB1
    API3 --> FDB2
    API3 --> FDB3

    API1 --> Prom
    API2 --> Prom
    API3 --> Prom

    API1 --> Jaeger
    API2 --> Jaeger
    API3 --> Jaeger

    Prom --> Grafana

    style API1 fill:#4CAF50,stroke:#2E7D32,stroke-width:3px
    style API2 fill:#4CAF50
    style API3 fill:#4CAF50
    style FDB1 fill:#2196F3
    style FDB2 fill:#2196F3
    style FDB3 fill:#2196F3
```

## Multi-Instance Coordination

How multiple Control instances coordinate for leader election and distributed ID generation:

```mermaid
sequenceDiagram
    participant API1 as Instance 1
    participant API2 as Instance 2
    participant API3 as Instance 3
    participant FDB as FoundationDB

    Note over API1,FDB: Startup & Leader Election

    API1->>FDB: Register Worker ID 0 + Heartbeat
    API2->>FDB: Register Worker ID 1 + Heartbeat
    API3->>FDB: Register Worker ID 2 + Heartbeat

    API1->>FDB: Try Acquire Leader Lock
    FDB-->>API1: Lock Acquired (Leader)

    API2->>FDB: Try Acquire Leader Lock
    FDB-->>API2: Lock Held (Follower)

    API3->>FDB: Try Acquire Leader Lock
    FDB-->>API3: Lock Held (Follower)

    Note over API1,FDB: Background Jobs (Leader Only)

    loop Every 10 seconds
        API1->>FDB: Update Heartbeat
        API2->>FDB: Update Heartbeat
        API3->>FDB: Update Heartbeat
    end

    loop Every 30 seconds (Leader Only)
        API1->>FDB: Cleanup Expired Sessions
        API1->>FDB: Cleanup Expired Tokens
        API1->>FDB: Send Email Queue
    end

    Note over API1,FDB: Leader Failure & Re-election

    API1-xAPI1: Crash/Shutdown

    loop Every 5 seconds
        API2->>FDB: Check Leader Health
        API2->>FDB: Try Acquire Leader Lock
        FDB-->>API2: Lock Acquired (New Leader)
    end

    Note over API2,FDB: New Leader Takes Over

    loop Every 30 seconds (New Leader)
        API2->>FDB: Cleanup Expired Sessions
        API2->>FDB: Cleanup Expired Tokens
    end
```

## ID Generation Strategy

How Worker IDs prevent Snowflake ID collisions across instances:

```mermaid
graph TB
    subgraph "Instance 1 - Worker ID: 0"
        ID1[Snowflake Generator<br/>Worker: 0]
        IDs1["IDs: xxx...000<br/>xxx...001<br/>xxx...002"]
    end

    subgraph "Instance 2 - Worker ID: 1"
        ID2[Snowflake Generator<br/>Worker: 1]
        IDs2["IDs: xxx...100<br/>xxx...101<br/>xxx...102"]
    end

    subgraph "Instance 3 - Worker ID: 2"
        ID3[Snowflake Generator<br/>Worker: 2]
        IDs3["IDs: xxx...200<br/>xxx...201<br/>xxx...202"]
    end

    subgraph "FoundationDB"
        Worker["Worker Registry<br/>workers/active/0<br/>workers/active/1<br/>workers/active/2"]
    end

    ID1 --> IDs1
    ID2 --> IDs2
    ID3 --> IDs3

    ID1 -.Register & Heartbeat.-> Worker
    ID2 -.Register & Heartbeat.-> Worker
    ID3 -.Register & Heartbeat.-> Worker

    style ID1 fill:#4CAF50
    style ID2 fill:#4CAF50
    style ID3 fill:#4CAF50
    style Worker fill:#2196F3
```

**Key Points**:

- Each instance has a unique Worker ID (0-1023)
- Worker IDs are embedded in the generated Snowflake IDs
- Collision detection: If Worker ID already registered with recent heartbeat, startup fails
- Heartbeat every 10 seconds keeps Worker ID registered
- Stale registrations (>30s) auto-expire via TTL

## Storage Architecture

### In-Memory Storage

Control supports a HashMap-based in-memory storage backend with the following characteristics:

- All data stored in RAM
- No persistence across restarts
- Suitable for development, testing, and single-instance deployments
- Uses the same logical keyspace structure as planned FoundationDB backend

### FoundationDB Storage

When implemented, data will be organized in FoundationDB keyspace:

```mermaid
graph TB
    subgraph "FoundationDB Keyspace"
        subgraph "Users"
            U1["users/{id}"]
            U2["users_by_name/{name}"]
            U3["user_emails/{id}"]
            U4["user_emails_by_email/{email}"]
        end

        subgraph "Organizations"
            O1["organizations/{id}"]
            O2["organizations_by_name/{name}"]
            O3["org_members/{org_id}/{user_id}"]
            O4["org_members_by_user/{user_id}"]
        end

        subgraph "Vaults"
            V1["vaults/{id}"]
            V2["vaults_by_org/{org_id}/{vault_id}"]
            V3["vault_grants_user/{vault_id}/{user_id}"]
            V4["vault_grants_team/{vault_id}/{team_id}"]
        end

        subgraph "Clients"
            C1["clients/{id}"]
            C2["clients_by_org/{org_id}/{client_id}"]
            C3["certificates/{id}"]
            C4["certificates_by_client/{client_id}"]
        end

        subgraph "Sessions & Tokens"
            S1["sessions/{id}"]
            S2["sessions_by_user/{user_id}/{session_id}"]
            S3["refresh_tokens/{id}"]
            S4["refresh_tokens_by_vault/{vault_id}"]
        end

        subgraph "System"
            SYS1["workers/active/{worker_id}"]
            SYS2["leader/lock"]
            SYS3["jti_replay/{jti}"]
        end
    end

    style U1 fill:#E3F2FD
    style O1 fill:#E8F5E9
    style V1 fill:#FFF3E0
    style C1 fill:#F3E5F5
    style S1 fill:#FCE4EC
    style SYS1 fill:#ECEFF1
```

## Security Layers

Defense-in-depth security architecture:

```mermaid
graph TB
    subgraph "Entry Points"
        TLS[TLS 1.3<br/>Encryption]
        RateLimit[Rate Limiting<br/>Per IP/User]
    end

    subgraph "Authentication"
        Session[Session<br/>Validation]
        JWT[JWT<br/>Verification]
        Cert[Client<br/>Certificates]
    end

    subgraph "Authorization"
        RBAC[Role-Based<br/>Access Control]
        OrgIso[Organization<br/>Isolation]
        VaultPerms[Vault<br/>Permissions]
    end

    subgraph "Data Protection"
        Encrypt[Field-Level<br/>Encryption]
        Hashing[Password<br/>Hashing]
        Secrets[Secret<br/>Management]
    end

    subgraph "Audit & Monitoring"
        Logs[Audit Logs]
        Metrics[Security<br/>Metrics]
        Alerts[Anomaly<br/>Detection]
    end

    TLS --> Session
    TLS --> JWT
    TLS --> Cert

    RateLimit --> Session
    RateLimit --> JWT

    Session --> RBAC
    JWT --> VaultPerms
    Cert --> VaultPerms

    RBAC --> OrgIso
    VaultPerms --> OrgIso

    OrgIso --> Encrypt
    OrgIso --> Hashing
    OrgIso --> Secrets

    Encrypt --> Logs
    Hashing --> Logs
    Secrets --> Logs

    Logs --> Metrics
    Metrics --> Alerts

    style TLS fill:#FF5722
    style Session fill:#FF9800
    style RBAC fill:#FFC107
    style Encrypt fill:#4CAF50
    style Logs fill:#2196F3
```

## Request Flow

Complete request lifecycle through the system:

```mermaid
sequenceDiagram
    participant Client
    participant LB as Load Balancer
    participant API as Control
    participant Auth as Auth Middleware
    participant Handler as Request Handler
    participant Repo as Repository
    participant FDB as FoundationDB
    participant Metrics

    Client->>LB: HTTPS Request
    LB->>API: Forward Request

    API->>Metrics: Record Request Start
    API->>Auth: Validate Session/JWT

    alt Invalid Auth
        Auth-->>Client: 401 Unauthorized
    end

    Auth->>Handler: Authorized Request
    Handler->>Repo: Business Logic

    Repo->>FDB: Query/Mutation
    FDB-->>Repo: Result

    Repo-->>Handler: Data
    Handler-->>API: Response

    API->>Metrics: Record Request End
    API-->>LB: HTTP Response
    LB-->>Client: HTTPS Response
```

## Technology Stack

```mermaid
graph LR
    subgraph "Runtime"
        Rust[Rust 1.85+]
        Tokio[Tokio<br/>Async Runtime]
    end

    subgraph "Web Frameworks"
        Axum[Axum<br/>HTTP Server]
        Tonic[Tonic<br/>gRPC Server]
        Tower[Tower<br/>Middleware]
    end

    subgraph "Storage"
        FDB[FoundationDB<br/>7.3.x]
        Memory[In-Memory<br/>HashMap]
    end

    subgraph "Security"
        Argon2[Argon2<br/>Password Hashing]
        Ed25519[Ed25519<br/>Signatures]
        AES[AES-GCM<br/>Encryption]
        JWT[jsonwebtoken<br/>JWT Handling]
    end

    subgraph "Observability"
        Tracing[tracing<br/>Structured Logs]
        Metrics[metrics<br/>Prometheus]
        OTLP[OpenTelemetry<br/>Distributed Tracing]
    end

    Rust --> Tokio
    Tokio --> Axum
    Tokio --> Tonic
    Axum --> Tower
    Tonic --> Tower

    Tower --> FDB
    Tower --> Memory

    Axum --> Argon2
    Axum --> Ed25519
    Axum --> AES
    Tonic --> JWT

    Axum --> Tracing
    Axum --> Metrics
    Axum --> OTLP

    style Rust fill:#FF5722
    style Tokio fill:#FF9800
    style Axum fill:#4CAF50
    style FDB fill:#2196F3
    style Argon2 fill:#9C27B0
    style Tracing fill:#00BCD4
```

## Scalability Strategy

```mermaid
graph TB
    subgraph "Horizontal Scaling"
        H1[Add More<br/>API Instances]
        H2[Worker ID<br/>Assignment]
        H3[Leader Election<br/>Failover]
    end

    subgraph "Vertical Scaling"
        V1[Increase CPU<br/>for Crypto Ops]
        V2[Increase RAM<br/>for Caching]
    end

    subgraph "Database Scaling"
        D1[FoundationDB<br/>Auto-Sharding]
        D2[Multi-Region<br/>Replication]
        D3[Read Replicas]
    end

    subgraph "Caching Strategy"
        C1[Session Cache<br/>In-Memory]
        C2[JWT Verification<br/>Cache]
        C3[Permission Cache]
    end

    H1 --> H2
    H2 --> H3
    V1 --> C1
    V2 --> C2
    D1 --> D2
    D2 --> D3
    C1 --> C3

    style H1 fill:#4CAF50
    style V1 fill:#FF9800
    style D1 fill:#2196F3
    style C1 fill:#9C27B0
```

## Further Reading

- [Overview](overview.md): Complete entity definitions and data model
- [Authentication](authentication.md): Authentication flows and security model
- [Deployment](deployment.md): Production deployment guide
