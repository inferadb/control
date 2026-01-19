# InferaDB Control Plane - Project Overview

## Purpose
Multi-tenant administration headless APIs for InferaDB with Kubernetes-native deployment and WebAuthn authentication. This is the control plane service that manages users, organizations, vaults, and client authentication.

## Tech Stack
- **Language**: Rust 1.85+ (stable toolchain)
- **Async Runtime**: Tokio
- **Web Framework**: Axum (REST), Tonic (gRPC)
- **Storage**: Ledger (production) or in-memory (development)
- **Authentication**: Argon2 (password), WebAuthn/FIDO2 (passkeys), OAuth, Email verification
- **Cryptography**: Ed25519 (client certs), JWT (tokens), AES-GCM (encryption)
- **Observability**: OpenTelemetry, Prometheus metrics, tracing

## Key Features
| Feature | Description |
|---------|-------------|
| Authentication | Password, passkey (WebAuthn/FIDO2), OAuth, email verification |
| Multi-Tenancy | Organization-based isolation with RBAC |
| Vault Management | Policy containers with access grants |
| Client Auth | Ed25519 certificates, JWT assertions |
| Token Issuance | Vault-scoped JWTs for Engine API |

## Key Entities
| Entity | Description |
|--------|-------------|
| User | Account with auth methods (password, passkey) |
| Organization | Workspace with members and roles |
| Vault | Authorization policy container |
| Client | Service identity with Ed25519 certs |
| Team | Group-based vault access |

## API Endpoints
| Endpoint | Port | Purpose |
|----------|------|---------|
| REST API | 9090 | HTTP/JSON API |
| gRPC API | 9091 | Protocol buffers API |
| Mesh API | 9092 | Internal mesh communication |
| Health | /healthz | Health check |
| Metrics | /metrics | Prometheus metrics |

## Configuration
- Config files: `config.yaml`, `config.production.yaml`, `config.integration.yaml`
- Environment prefix: `INFERADB_CTRL__` (e.g., `INFERADB_CTRL__LISTEN__HTTP`)
