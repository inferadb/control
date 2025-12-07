# InferaDB Management API Configuration Guide

Complete guide for configuring the InferaDB Management API using configuration files and environment variables.

## Table of Contents

- [Overview](#overview)
- [Configuration Methods](#configuration-methods)
- [Server Configuration](#server-configuration)
- [Storage Configuration](#storage-configuration)
- [Authentication Configuration](#authentication-configuration)
- [Email Configuration](#email-configuration)
- [Rate Limiting Configuration](#rate-limiting-configuration)
- [Observability Configuration](#observability-configuration)
- [ID Generation Configuration](#id-generation-configuration)
- [Policy Service Configuration](#policy-service-configuration)
- [Identity Configuration](#identity-configuration)
- [Cache Invalidation Configuration](#cache-invalidation-configuration)
- [Discovery Configuration](#discovery-configuration)
- [Configuration Profiles](#configuration-profiles)
- [Secrets Management](#secrets-management)
- [Validation](#validation)
- [Best Practices](#best-practices)

## Overview

The Management API supports configuration through multiple sources with the following precedence (highest to lowest):

1. **Environment variables** (highest priority)
2. **Configuration file**
3. **Default values** (lowest priority)

Configuration files use **YAML or JSON** format, and environment variables use the `INFERADB_MGMT__` prefix with double underscores (`__`) as separators.

## Configuration Methods

### Method 1: Configuration File

Create a `config.yaml` or `config.json` file:

**YAML format** (recommended):

```yaml
frontend_base_url: "https://app.inferadb.com"

server:
  host: "127.0.0.1"
  port: 9090
  grpc_host: "127.0.0.1"
  grpc_port: 9091
  internal_host: "0.0.0.0"
  internal_port: 9092
  worker_threads: 4

storage:
  backend: "memory"
  fdb_cluster_file: null

auth:
  session_ttl_web: 2592000
  session_ttl_cli: 7776000
  session_ttl_sdk: 7776000
  password_min_length: 12
  max_sessions_per_user: 10
  webauthn:
    rp_id: "inferadb.com"
    rp_name: "InferaDB"
    origin: "https://app.inferadb.com"

email:
  smtp_host: "smtp.sendgrid.net"
  smtp_port: 587
  from_email: "noreply@inferadb.com"
  from_name: "InferaDB"

rate_limiting:
  login_attempts_per_ip_per_hour: 100
  registrations_per_ip_per_day: 5
  email_verification_tokens_per_hour: 5
  password_reset_tokens_per_hour: 3

observability:
  log_level: "info"
  metrics_enabled: true
  tracing_enabled: false

id_generation:
  worker_id: 0

policy_service:
  service_url: "http://localhost"
  grpc_port: 8081
  internal_port: 8082
  tls_enabled: false

identity:
  service_id: "management-service"
  kid: "management-service"

cache_invalidation:
  timeout_ms: 5000
  retry_attempts: 0

discovery:
  mode:
    type: none
  cache_ttl_seconds: 300
```

**Load configuration file**:

```bash
inferadb-management --config config.yaml
```

### Method 2: Environment Variables

All configuration options can be set via environment variables using the `INFERADB_MGMT__` prefix:

```bash
# Frontend URL
export INFERADB_MGMT__FRONTEND_BASE_URL="https://app.inferadb.com"

# Server configuration
export INFERADB_MGMT__SERVER__HOST="127.0.0.1"
export INFERADB_MGMT__SERVER__PORT=9090
export INFERADB_MGMT__SERVER__GRPC_HOST="127.0.0.1"
export INFERADB_MGMT__SERVER__GRPC_PORT=9091
export INFERADB_MGMT__SERVER__INTERNAL_HOST="0.0.0.0"
export INFERADB_MGMT__SERVER__INTERNAL_PORT=9092
export INFERADB_MGMT__SERVER__WORKER_THREADS=4

# Storage configuration
export INFERADB_MGMT__STORAGE__BACKEND="memory"
export INFERADB_MGMT__STORAGE__FDB_CLUSTER_FILE="/etc/foundationdb/fdb.cluster"

# Authentication
export INFERADB_MGMT__AUTH__SESSION_TTL_WEB=2592000
export INFERADB_MGMT__AUTH__PASSWORD_MIN_LENGTH=12
export INFERADB_MGMT__AUTH__KEY_ENCRYPTION_SECRET="your-32-byte-secret-key-here!!!"

# Email
export INFERADB_MGMT__EMAIL__SMTP_HOST="smtp.sendgrid.net"
export INFERADB_MGMT__EMAIL__SMTP_PORT=587
export INFERADB_MGMT__EMAIL__SMTP_PASSWORD="your-smtp-password"

# Observability
export INFERADB_MGMT__OBSERVABILITY__LOG_LEVEL="info"
export INFERADB_MGMT__OBSERVABILITY__METRICS_ENABLED=true
```

### Method 3: Combined (File + Environment)

Environment variables override file configuration:

```bash
# config.yaml sets port to 9090
# Environment variable overrides to 3000
export INFERADB_MGMT__SERVER__PORT=3000
inferadb-management --config config.yaml
# Server starts on port 3000
```

## Server Configuration

Controls HTTP/gRPC server behavior. The Management API exposes three interfaces:

- **Public REST API** (port 9090): Client-facing HTTP API
- **Public gRPC API** (port 9091): Client-facing gRPC API
- **Internal REST API** (port 9092): Server-to-server communication (JWKS endpoint)

### Options

| Option           | Type    | Default       | Description                             |
| ---------------- | ------- | ------------- | --------------------------------------- |
| `host`           | string  | `"127.0.0.1"` | Public REST API bind address            |
| `port`           | integer | `9090`        | Public REST API port                    |
| `grpc_host`      | string  | `"127.0.0.1"` | Public gRPC API bind address            |
| `grpc_port`      | integer | `9091`        | Public gRPC API port                    |
| `internal_host`  | string  | `"0.0.0.0"`   | Internal REST API bind address          |
| `internal_port`  | integer | `9092`        | Internal REST API port (JWKS, webhooks) |
| `worker_threads` | integer | `4`           | Number of Tokio worker threads          |

### Examples

**Development** (localhost only):

```yaml
server:
  host: "127.0.0.1"
  port: 9090
  grpc_host: "127.0.0.1"
  grpc_port: 9091
  internal_host: "0.0.0.0"
  internal_port: 9092
  worker_threads: 2
```

**Production** (all interfaces):

```yaml
server:
  host: "0.0.0.0"
  port: 9090
  grpc_host: "0.0.0.0"
  grpc_port: 9091
  internal_host: "0.0.0.0"
  internal_port: 9092
  worker_threads: 8
```

### Environment Variables

```bash
export INFERADB_MGMT__SERVER__HOST="0.0.0.0"
export INFERADB_MGMT__SERVER__PORT=9090
export INFERADB_MGMT__SERVER__GRPC_HOST="0.0.0.0"
export INFERADB_MGMT__SERVER__GRPC_PORT=9091
export INFERADB_MGMT__SERVER__INTERNAL_HOST="0.0.0.0"
export INFERADB_MGMT__SERVER__INTERNAL_PORT=9092
export INFERADB_MGMT__SERVER__WORKER_THREADS=8
```

## Storage Configuration

Controls the data storage backend.

### Options

| Option             | Type              | Default    | Description                                     |
| ------------------ | ----------------- | ---------- | ----------------------------------------------- |
| `backend`          | string            | `"memory"` | Storage backend: `"memory"` or `"foundationdb"` |
| `fdb_cluster_file` | string (optional) | `null`     | Path to FoundationDB cluster file               |

### Backend Options

#### Memory Backend (Development)

- **Use case**: Local development, testing
- **Persistence**: None (data lost on restart)
- **Performance**: Fastest
- **Configuration**: No cluster file needed

```yaml
storage:
  backend: "memory"
```

#### FoundationDB Backend (Production)

- **Use case**: Production deployments
- **Persistence**: ACID transactions, replication
- **Performance**: High throughput, low latency
- **Configuration**: Requires FDB cluster file path

```yaml
storage:
  backend: "foundationdb"
  fdb_cluster_file: "/etc/foundationdb/fdb.cluster"
```

### Environment Variables

```bash
export INFERADB_MGMT__STORAGE__BACKEND="foundationdb"
export INFERADB_MGMT__STORAGE__FDB_CLUSTER_FILE="/etc/foundationdb/fdb.cluster"
```

## Authentication Configuration

Controls user authentication, sessions, and security.

### Options

| Option                  | Type              | Default                               | Description                                |
| ----------------------- | ----------------- | ------------------------------------- | ------------------------------------------ |
| `session_ttl_web`       | integer           | `2592000` (30 days)                   | Web session TTL in seconds                 |
| `session_ttl_cli`       | integer           | `7776000` (90 days)                   | CLI session TTL in seconds                 |
| `session_ttl_sdk`       | integer           | `7776000` (90 days)                   | SDK session TTL in seconds                 |
| `password_min_length`   | integer           | `12`                                  | Minimum password length                    |
| `max_sessions_per_user` | integer           | `10`                                  | Maximum concurrent sessions per user       |
| `key_encryption_secret` | string (optional) | `null`                                | Secret for encrypting private keys at rest |
| `jwt_issuer`            | string            | `"https://api.inferadb.com"`          | JWT issuer URL                             |
| `jwt_audience`          | string            | `"https://api.inferadb.com/evaluate"` | JWT audience URL                           |

### WebAuthn Configuration

| Option    | Type   | Default       | Description                |
| --------- | ------ | ------------- | -------------------------- |
| `rp_id`   | string | `"localhost"` | Relying Party ID (domain)  |
| `rp_name` | string | `"InferaDB"`  | Relying Party display name |
| `origin`  | string | (required)    | Origin URL for WebAuthn    |

### Examples

**Development**:

```yaml
auth:
  session_ttl_web: 86400 # 1 day
  session_ttl_cli: 604800 # 7 days
  session_ttl_sdk: 604800 # 7 days
  password_min_length: 8 # Relaxed for testing
  max_sessions_per_user: 5
  webauthn:
    rp_id: "localhost"
    rp_name: "InferaDB Dev"
    origin: "http://localhost:3000"
```

**Production**:

```yaml
auth:
  session_ttl_web: 2592000 # 30 days
  session_ttl_cli: 7776000 # 90 days
  session_ttl_sdk: 7776000 # 90 days
  password_min_length: 12
  max_sessions_per_user: 10
  key_encryption_secret: "${KEY_ENCRYPTION_SECRET}"
  jwt_issuer: "https://api.inferadb.com"
  jwt_audience: "https://api.inferadb.com/evaluate"
  webauthn:
    rp_id: "inferadb.com"
    rp_name: "InferaDB"
    origin: "https://app.inferadb.com"
```

### Environment Variables

```bash
export INFERADB_MGMT__AUTH__SESSION_TTL_WEB=2592000
export INFERADB_MGMT__AUTH__SESSION_TTL_CLI=7776000
export INFERADB_MGMT__AUTH__SESSION_TTL_SDK=7776000
export INFERADB_MGMT__AUTH__PASSWORD_MIN_LENGTH=12
export INFERADB_MGMT__AUTH__MAX_SESSIONS_PER_USER=10
export INFERADB_MGMT__AUTH__KEY_ENCRYPTION_SECRET="your-32-byte-secret-key-here!!!"
export INFERADB_MGMT__AUTH__JWT_ISSUER="https://api.inferadb.com"
export INFERADB_MGMT__AUTH__JWT_AUDIENCE="https://api.inferadb.com/evaluate"
export INFERADB_MGMT__AUTH__WEBAUTHN__RP_ID="inferadb.com"
export INFERADB_MGMT__AUTH__WEBAUTHN__RP_NAME="InferaDB"
export INFERADB_MGMT__AUTH__WEBAUTHN__ORIGIN="https://app.inferadb.com"
```

### Security Notes

- **key_encryption_secret**: Required for encrypting client private keys at rest. Must be at least 32 bytes. If not set, a warning is logged and keys are stored unencrypted.
- **password_min_length**: Recommended minimum of 12 characters for production.

## Email Configuration

Controls email sending for verification and password reset.

### Options

| Option          | Type              | Default         | Description                  |
| --------------- | ----------------- | --------------- | ---------------------------- |
| `smtp_host`     | string            | `"localhost"`   | SMTP server hostname         |
| `smtp_port`     | integer           | `587`           | SMTP server port             |
| `smtp_username` | string (optional) | `null`          | SMTP authentication username |
| `smtp_password` | string (optional) | `null`          | SMTP authentication password |
| `from_email`    | string            | `"noreply@..."` | From email address           |
| `from_name`     | string            | `"InferaDB"`    | From display name            |

### Examples

**Development** (local mailhog):

```yaml
email:
  smtp_host: "localhost"
  smtp_port: 1025
  from_email: "test@inferadb.local"
  from_name: "InferaDB Test"
```

**Production** (SendGrid):

```yaml
email:
  smtp_host: "smtp.sendgrid.net"
  smtp_port: 587
  smtp_username: "apikey"
  smtp_password: "${SENDGRID_API_KEY}"
  from_email: "noreply@inferadb.com"
  from_name: "InferaDB"
```

### Environment Variables

```bash
export INFERADB_MGMT__EMAIL__SMTP_HOST="smtp.sendgrid.net"
export INFERADB_MGMT__EMAIL__SMTP_PORT=587
export INFERADB_MGMT__EMAIL__SMTP_USERNAME="apikey"
export INFERADB_MGMT__EMAIL__SMTP_PASSWORD="your-api-key"
export INFERADB_MGMT__EMAIL__FROM_EMAIL="noreply@inferadb.com"
export INFERADB_MGMT__EMAIL__FROM_NAME="InferaDB"
```

## Rate Limiting Configuration

Controls rate limiting for security-sensitive operations.

### Options

| Option                               | Type    | Default | Description                              |
| ------------------------------------ | ------- | ------- | ---------------------------------------- |
| `login_attempts_per_ip_per_hour`     | integer | `100`   | Max login attempts per IP per hour       |
| `registrations_per_ip_per_day`       | integer | `5`     | Max registrations per IP per day         |
| `email_verification_tokens_per_hour` | integer | `5`     | Max verification emails per address/hour |
| `password_reset_tokens_per_hour`     | integer | `3`     | Max password reset emails per user/hour  |

### Examples

**Development** (relaxed):

```yaml
rate_limiting:
  login_attempts_per_ip_per_hour: 1000
  registrations_per_ip_per_day: 100
  email_verification_tokens_per_hour: 100
  password_reset_tokens_per_hour: 100
```

**Production** (strict):

```yaml
rate_limiting:
  login_attempts_per_ip_per_hour: 50
  registrations_per_ip_per_day: 3
  email_verification_tokens_per_hour: 3
  password_reset_tokens_per_hour: 2
```

### Environment Variables

```bash
export INFERADB_MGMT__RATE_LIMITING__LOGIN_ATTEMPTS_PER_IP_PER_HOUR=50
export INFERADB_MGMT__RATE_LIMITING__REGISTRATIONS_PER_IP_PER_DAY=3
export INFERADB_MGMT__RATE_LIMITING__EMAIL_VERIFICATION_TOKENS_PER_HOUR=3
export INFERADB_MGMT__RATE_LIMITING__PASSWORD_RESET_TOKENS_PER_HOUR=2
```

## Observability Configuration

Controls logging, metrics, and tracing.

### Options

| Option            | Type              | Default  | Description                                                    |
| ----------------- | ----------------- | -------- | -------------------------------------------------------------- |
| `log_level`       | string            | `"info"` | Log level: `"trace"`, `"debug"`, `"info"`, `"warn"`, `"error"` |
| `metrics_enabled` | boolean           | `true`   | Enable Prometheus metrics at `/metrics`                        |
| `tracing_enabled` | boolean           | `false`  | Enable OpenTelemetry distributed tracing                       |
| `otlp_endpoint`   | string (optional) | `null`   | OTLP endpoint for traces                                       |

### Examples

**Development**:

```yaml
observability:
  log_level: "debug"
  metrics_enabled: true
  tracing_enabled: false
```

**Production**:

```yaml
observability:
  log_level: "info"
  metrics_enabled: true
  tracing_enabled: true
  otlp_endpoint: "http://jaeger:4317"
```

### Environment Variables

```bash
export INFERADB_MGMT__OBSERVABILITY__LOG_LEVEL="info"
export INFERADB_MGMT__OBSERVABILITY__METRICS_ENABLED=true
export INFERADB_MGMT__OBSERVABILITY__TRACING_ENABLED=true
export INFERADB_MGMT__OBSERVABILITY__OTLP_ENDPOINT="http://jaeger:4317"
```

## ID Generation Configuration

Controls Snowflake ID generation for distributed deployments.

### Options

| Option      | Type    | Default | Description                          |
| ----------- | ------- | ------- | ------------------------------------ |
| `worker_id` | integer | `0`     | Worker ID for Snowflake IDs (0-1023) |

### Example

```yaml
id_generation:
  worker_id: 0
```

### Environment Variables

```bash
export INFERADB_MGMT__ID_GENERATION__WORKER_ID=0
```

### Notes

- Each Management API instance must have a unique `worker_id` (0-1023)
- In Kubernetes, derive from pod ordinal or use a distributed lock
- Duplicate worker IDs can cause ID collisions

## Policy Service Configuration

Controls connection to the InferaDB Server (policy engine).

### Options

| Option          | Type    | Default              | Description                    |
| --------------- | ------- | -------------------- | ------------------------------ |
| `service_url`   | string  | `"http://localhost"` | Server base URL (without port) |
| `grpc_port`     | integer | `8081`               | Server gRPC port               |
| `internal_port` | integer | `8082`               | Server internal API port       |
| `tls_enabled`   | boolean | `true`               | Enable TLS for gRPC            |

### Examples

**Development**:

```yaml
policy_service:
  service_url: "http://localhost"
  grpc_port: 8081
  internal_port: 8082
  tls_enabled: false
```

**Kubernetes**:

```yaml
policy_service:
  service_url: "http://inferadb-server.inferadb"
  grpc_port: 8081
  internal_port: 8082
  tls_enabled: false
```

### Computed URLs

The Management API computes full URLs from these settings:

- **gRPC URL**: `{service_url}:{grpc_port}` → `http://localhost:8081`
- **Internal URL**: `{service_url}:{internal_port}` → `http://localhost:8082`

### Environment Variables

```bash
export INFERADB_MGMT__POLICY_SERVICE__SERVICE_URL="http://inferadb-server.inferadb"
export INFERADB_MGMT__POLICY_SERVICE__GRPC_PORT=8081
export INFERADB_MGMT__POLICY_SERVICE__INTERNAL_PORT=8082
export INFERADB_MGMT__POLICY_SERVICE__TLS_ENABLED=false
```

## Identity Configuration

Controls Management API identity for service-to-service authentication.

### Options

| Option            | Type              | Default                | Description                       |
| ----------------- | ----------------- | ---------------------- | --------------------------------- |
| `service_id`      | string            | `"management-service"` | Service ID for JWT subject claim  |
| `kid`             | string            | `"management-service"` | Key ID (kid) for JWKS             |
| `private_key_pem` | string (optional) | `null`                 | Ed25519 private key in PEM format |

### Example

```yaml
identity:
  service_id: "management-service"
  kid: "management-2024"
  private_key_pem: "${MANAGEMENT_PRIVATE_KEY}"
```

### Environment Variables

```bash
export INFERADB_MGMT__IDENTITY__SERVICE_ID="management-service"
export INFERADB_MGMT__IDENTITY__KID="management-2024"
export INFERADB_MGMT__IDENTITY__PRIVATE_KEY_PEM="-----BEGIN PRIVATE KEY-----\n..."
```

### Notes

- If `private_key_pem` is not provided, a key is auto-generated on startup
- Auto-generated keys are not recommended for production (not persistent across restarts)
- The public key is exposed at the internal JWKS endpoint for servers to validate

## Cache Invalidation Configuration

Controls webhook-based cache invalidation to server instances.

### Options

| Option           | Type    | Default | Description                         |
| ---------------- | ------- | ------- | ----------------------------------- |
| `timeout_ms`     | integer | `5000`  | Webhook request timeout (ms)        |
| `retry_attempts` | integer | `0`     | Number of retry attempts on failure |

### Example

```yaml
cache_invalidation:
  timeout_ms: 5000
  retry_attempts: 0
```

### Environment Variables

```bash
export INFERADB_MGMT__CACHE_INVALIDATION__TIMEOUT_MS=5000
export INFERADB_MGMT__CACHE_INVALIDATION__RETRY_ATTEMPTS=0
```

### Notes

- Default is fire-and-forget (0 retries) for performance
- Increase `retry_attempts` if cache consistency is critical
- The server's internal port receives these webhooks

## Discovery Configuration

Controls service discovery for multi-node deployments.

### Options

| Option                          | Type    | Default | Description                        |
| ------------------------------- | ------- | ------- | ---------------------------------- |
| `mode`                          | object  | `none`  | Discovery mode configuration       |
| `cache_ttl_seconds`             | integer | `300`   | Cache TTL for discovered endpoints |
| `enable_health_check`           | boolean | `false` | Enable health checking             |
| `health_check_interval_seconds` | integer | `30`    | Health check interval              |

### Discovery Modes

#### None (Default)

Direct connection to a single service URL:

```yaml
discovery:
  mode:
    type: none
```

#### Kubernetes

Discover pod IPs via Kubernetes service:

```yaml
discovery:
  mode:
    type: kubernetes
  cache_ttl_seconds: 30
  enable_health_check: true
  health_check_interval_seconds: 10
```

#### Tailscale

Multi-region discovery via Tailscale mesh:

```yaml
discovery:
  mode:
    type: tailscale
    local_cluster: "us-west-1"
    remote_clusters:
      - name: "eu-west-1"
        tailscale_domain: "eu-west-1.ts.net"
        service_name: "inferadb-management"
        port: 9092
```

### Environment Variables

```bash
export INFERADB_MGMT__DISCOVERY__CACHE_TTL_SECONDS=30
export INFERADB_MGMT__DISCOVERY__ENABLE_HEALTH_CHECK=true
export INFERADB_MGMT__DISCOVERY__HEALTH_CHECK_INTERVAL_SECONDS=10
```

## Frontend Base URL

The `frontend_base_url` is a top-level configuration option that sets the base URL for email links (verification, password reset).

### Options

| Option              | Type   | Default                   | Description                       |
| ------------------- | ------ | ------------------------- | --------------------------------- |
| `frontend_base_url` | string | `"http://localhost:3000"` | Base URL for frontend email links |

### Example

```yaml
frontend_base_url: "https://app.inferadb.com"
```

### Environment Variables

```bash
export INFERADB_MGMT__FRONTEND_BASE_URL="https://app.inferadb.com"
```

### Notes

- Must start with `http://` or `https://`
- Must not end with trailing slash
- A warning is logged if localhost is used in non-development environments

## Configuration Profiles

### Development Profile

Optimized for local development:

```yaml
frontend_base_url: "http://localhost:3000"

server:
  host: "127.0.0.1"
  port: 9090
  grpc_host: "127.0.0.1"
  grpc_port: 9091
  internal_host: "0.0.0.0"
  internal_port: 9092
  worker_threads: 2

storage:
  backend: "memory"

auth:
  session_ttl_web: 86400
  password_min_length: 8
  webauthn:
    rp_id: "localhost"
    rp_name: "InferaDB Dev"
    origin: "http://localhost:3000"

email:
  smtp_host: "localhost"
  smtp_port: 1025
  from_email: "test@inferadb.local"
  from_name: "InferaDB Test"

rate_limiting:
  login_attempts_per_ip_per_hour: 1000
  registrations_per_ip_per_day: 100
  email_verification_tokens_per_hour: 100
  password_reset_tokens_per_hour: 100

observability:
  log_level: "debug"
  metrics_enabled: true
  tracing_enabled: false

id_generation:
  worker_id: 0

policy_service:
  service_url: "http://localhost"
  grpc_port: 8081
  internal_port: 8082
  tls_enabled: false

identity:
  service_id: "management-dev"
  kid: "dev-key"

cache_invalidation:
  timeout_ms: 5000
  retry_attempts: 0

discovery:
  mode:
    type: none
```

### Production Profile

Optimized for production deployment:

```yaml
frontend_base_url: "https://app.inferadb.com"

server:
  host: "0.0.0.0"
  port: 9090
  grpc_host: "0.0.0.0"
  grpc_port: 9091
  internal_host: "0.0.0.0"
  internal_port: 9092
  worker_threads: 8

storage:
  backend: "foundationdb"
  fdb_cluster_file: "/etc/foundationdb/fdb.cluster"

auth:
  session_ttl_web: 2592000
  session_ttl_cli: 7776000
  session_ttl_sdk: 7776000
  password_min_length: 12
  max_sessions_per_user: 10
  key_encryption_secret: "${KEY_ENCRYPTION_SECRET}"
  jwt_issuer: "https://api.inferadb.com"
  jwt_audience: "https://api.inferadb.com/evaluate"
  webauthn:
    rp_id: "inferadb.com"
    rp_name: "InferaDB"
    origin: "https://app.inferadb.com"

email:
  smtp_host: "smtp.sendgrid.net"
  smtp_port: 587
  smtp_username: "apikey"
  smtp_password: "${SENDGRID_API_KEY}"
  from_email: "noreply@inferadb.com"
  from_name: "InferaDB"

rate_limiting:
  login_attempts_per_ip_per_hour: 50
  registrations_per_ip_per_day: 3
  email_verification_tokens_per_hour: 3
  password_reset_tokens_per_hour: 2

observability:
  log_level: "info"
  metrics_enabled: true
  tracing_enabled: true
  otlp_endpoint: "http://jaeger:4317"

id_generation:
  worker_id: 0

policy_service:
  service_url: "http://inferadb-server.inferadb"
  grpc_port: 8081
  internal_port: 8082
  tls_enabled: false

identity:
  service_id: "management-service"
  kid: "management-prod-2024"
  private_key_pem: "${MANAGEMENT_PRIVATE_KEY}"

cache_invalidation:
  timeout_ms: 5000
  retry_attempts: 1

discovery:
  mode:
    type: kubernetes
  cache_ttl_seconds: 30
  enable_health_check: true
```

### Integration Testing Profile

Optimized for E2E testing:

```yaml
frontend_base_url: "http://localhost:9090"

server:
  host: "0.0.0.0"
  port: 9090
  grpc_host: "0.0.0.0"
  grpc_port: 9091
  internal_host: "0.0.0.0"
  internal_port: 9092
  worker_threads: 2

storage:
  backend: "memory"

auth:
  session_ttl_web: 3600
  session_ttl_cli: 7200
  session_ttl_sdk: 7200
  password_min_length: 8
  max_sessions_per_user: 5
  key_encryption_secret: "test-integration-secret-key-32bytes-long!"
  webauthn:
    rp_id: "localhost"
    rp_name: "InferaDB Test"
    origin: "http://localhost:9090"

email:
  smtp_host: "localhost"
  smtp_port: 1025
  from_email: "test@inferadb.local"
  from_name: "InferaDB Test"

rate_limiting:
  login_attempts_per_ip_per_hour: 1000
  registrations_per_ip_per_day: 100
  email_verification_tokens_per_hour: 100
  password_reset_tokens_per_hour: 100

observability:
  log_level: "debug"
  metrics_enabled: true
  tracing_enabled: false

id_generation:
  worker_id: 0

policy_service:
  service_url: "http://inferadb-server.inferadb"
  grpc_port: 8081
  internal_port: 8082
  tls_enabled: false

identity:
  service_id: "management-integration-test"
  kid: "mgmt-test-2024"

cache_invalidation:
  timeout_ms: 5000
  retry_attempts: 0

discovery:
  mode:
    type: kubernetes
  cache_ttl_seconds: 30
```

## Secrets Management

**Never commit secrets to configuration files.**

### Required Secrets

| Secret                  | Purpose                              |
| ----------------------- | ------------------------------------ |
| `key_encryption_secret` | Encrypts client private keys at rest |
| `smtp_password`         | SMTP authentication                  |
| `private_key_pem`       | Service identity for webhooks        |

### Environment Variables (Recommended)

```bash
export INFERADB_MGMT__AUTH__KEY_ENCRYPTION_SECRET="your-32-byte-secret-key-here!!!"
export INFERADB_MGMT__EMAIL__SMTP_PASSWORD="your-smtp-password"
export INFERADB_MGMT__IDENTITY__PRIVATE_KEY_PEM="-----BEGIN PRIVATE KEY-----\n..."
```

### Kubernetes Secrets

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: inferadb-management-secrets
type: Opaque
stringData:
  key-encryption-secret: "your-32-byte-secret-key-here!!!"
  smtp-password: "your-smtp-password"
  private-key: |
    -----BEGIN PRIVATE KEY-----
    ...
    -----END PRIVATE KEY-----
```

```yaml
# In deployment
env:
  - name: INFERADB_MGMT__AUTH__KEY_ENCRYPTION_SECRET
    valueFrom:
      secretKeyRef:
        name: inferadb-management-secrets
        key: key-encryption-secret
  - name: INFERADB_MGMT__EMAIL__SMTP_PASSWORD
    valueFrom:
      secretKeyRef:
        name: inferadb-management-secrets
        key: smtp-password
  - name: INFERADB_MGMT__IDENTITY__PRIVATE_KEY_PEM
    valueFrom:
      secretKeyRef:
        name: inferadb-management-secrets
        key: private-key
```

## Validation

The Management API validates configuration at startup with clear error messages.

### Validation Rules

**Storage**:

- `backend` must be `"memory"` or `"foundationdb"`
- `fdb_cluster_file` required when `backend = "foundationdb"`

**ID Generation**:

- `worker_id` must be between 0 and 1023

**Authentication**:

- `webauthn.rp_id` cannot be empty
- `webauthn.origin` cannot be empty and must start with `http://` or `https://`
- `password_min_length < 8` generates warning

**Frontend**:

- `frontend_base_url` must start with `http://` or `https://`
- `frontend_base_url` must not end with trailing slash

**Policy Service**:

- `service_url` must start with `http://` or `https://`
- `service_url` must not end with trailing slash

**Identity**:

- `service_id` cannot be empty
- `kid` cannot be empty

**Cache Invalidation**:

- `timeout_ms` must be > 0
- `timeout_ms > 60000` generates warning

### Example Validation Errors

```text
Error: Invalid storage backend: postgres. Must be 'memory' or 'foundationdb'
```

```text
Error: Worker ID must be between 0 and 1023, got 2000
```

```text
Error: auth.webauthn.rp_id cannot be empty
```

```text
Error: frontend_base_url must start with http:// or https://
```

## Best Practices

### Security

1. **Always set key_encryption_secret in production**

   ```bash
   export INFERADB_MGMT__AUTH__KEY_ENCRYPTION_SECRET="secure-random-32-byte-string!"
   ```

2. **Use strong password requirements**

   ```yaml
   auth:
     password_min_length: 12
   ```

3. **Configure strict rate limiting**

   ```yaml
   rate_limiting:
     login_attempts_per_ip_per_hour: 50
     registrations_per_ip_per_day: 3
   ```

4. **Never commit secrets**
   - Use environment variables
   - Use Kubernetes secrets
   - Use secret managers

### Operations

1. **Unique worker IDs for each instance**
   - Critical for distributed deployments
   - Prevents Snowflake ID collisions

2. **Configure health checks in Kubernetes**
   - Use `/health` endpoint for liveness
   - Use `/ready` endpoint for readiness

3. **Enable observability**

   ```yaml
   observability:
     metrics_enabled: true
     tracing_enabled: true
   ```

### Performance

1. **Use FoundationDB in production**
   - Memory backend doesn't persist
   - FoundationDB provides ACID + replication

2. **Tune worker threads**
   - Start with 4-8 for most workloads
   - Benchmark and adjust

3. **Use Kubernetes discovery**
   - Enables direct pod-to-pod communication
   - Reduces cache invalidation latency

## Deployment Examples

### Docker Compose

```yaml
version: "3.8"
services:
  inferadb-management:
    image: inferadb/management:latest
    ports:
      - "9090:9090"
      - "9091:9091"
      - "9092:9092"
    environment:
      INFERADB_MGMT__SERVER__HOST: "0.0.0.0"
      INFERADB_MGMT__SERVER__PORT: "9090"
      INFERADB_MGMT__STORAGE__BACKEND: "foundationdb"
      INFERADB_MGMT__STORAGE__FDB_CLUSTER_FILE: "/etc/foundationdb/fdb.cluster"
      INFERADB_MGMT__AUTH__KEY_ENCRYPTION_SECRET: "${KEY_ENCRYPTION_SECRET}"
      INFERADB_MGMT__POLICY_SERVICE__SERVICE_URL: "http://inferadb-server"
      INFERADB_MGMT__FRONTEND_BASE_URL: "https://app.inferadb.com"
    volumes:
      - /etc/foundationdb:/etc/foundationdb:ro
```

### Kubernetes

See the Kubernetes manifests in the `k8s/` directory for complete deployment examples.

## Troubleshooting

### Server Won't Start

**Check configuration**:

```bash
inferadb-management --config config.yaml 2>&1 | grep ERROR
```

### Email Not Sending

1. Check SMTP credentials
2. Verify `smtp_host` and `smtp_port`
3. Check firewall rules
4. Test with local mailhog first

### Cache Invalidation Failing

1. Verify `policy_service.service_url` is correct
2. Check network connectivity to server internal port
3. Increase `timeout_ms` if servers are slow
4. Enable `retry_attempts` for reliability

### Snowflake ID Collisions

1. Ensure unique `worker_id` per instance
2. Check for duplicate pod ordinals
3. Verify ID generation configuration

## See Also

- [Server Configuration](../../server/docs/guides/configuration.md) - Server (policy engine) configuration
- [Authentication Guide](../security/authentication.md) - Detailed authentication setup
- [Deployment Guide](deployment.md) - Production deployment
