# InferaDB Control - Codebase Structure

## Workspace Layout
```
control/
├── crates/                          # Rust workspace crates
│   ├── inferadb-control/            # Binary entrypoint (main.rs)
│   ├── inferadb-control-api/        # REST/gRPC handlers (Axum/Tonic)
│   ├── inferadb-control-config/     # Configuration loading (YAML, env vars)
│   ├── inferadb-control-const/      # Shared constants
│   ├── inferadb-control-core/       # Business logic, entities, services
│   ├── inferadb-control-discovery/  # Service discovery
│   ├── inferadb-control-engine-client/ # Engine API client
│   ├── inferadb-control-storage/    # Storage layer (Ledger, in-memory)
│   ├── inferadb-control-test-fixtures/ # Test utilities and fixtures
│   └── inferadb-control-types/      # Shared type definitions
├── docs/                            # Documentation
├── docker/                          # Docker configurations
├── helm/                            # Kubernetes Helm charts
├── k8s/                             # Raw Kubernetes manifests
├── loadtests/                       # Load testing scripts
├── proto/                           # Protocol buffer definitions
├── scripts/                         # Utility scripts
├── Makefile                         # Build shortcuts
├── config.yaml                      # Default configuration
├── openapi.yaml                     # OpenAPI specification
└── docker-compose.yml               # Local development stack
```

## Crate Dependencies (Architecture)
```
inferadb-control (binary)
    └── inferadb-control-api
    └── inferadb-control-config
         └── inferadb-control-core
              └── inferadb-control-config
              └── inferadb-control-storage
                   └── Ledger
              └── inferadb-control-engine-client
```

## Core Crate Modules (inferadb-control-core)
- `auth` - Authentication logic
- `clock` - Time utilities
- `crypto` - Cryptographic operations
- `email` - Email sending
- `id` - ID generation (Snowflake)
- `jobs` - Background jobs
- `jwt` - JWT token handling
- `leader` - Leader election
- `logging` - Structured logging
- `metrics` - Metrics collection
- `ratelimit` - Rate limiting
- `repository` - Data access layer
- `repository_context` - Repository context management
- `startup` - Application startup
