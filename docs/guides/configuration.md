# InferaDB Control Configuration Guide

Complete guide for configuring InferaDB Control using configuration files and environment variables.

## Table of Contents

- [Overview](#overview)
- [Configuration Methods](#configuration-methods)
- [Listen Configuration](#listen-configuration)
- [Storage Configuration](#storage-configuration)
- [Authentication Configuration](#authentication-configuration)
- [Email Configuration](#email-configuration)
- [Rate Limits Configuration](#rate-limits-configuration)
- [Mesh Configuration](#mesh-configuration)
- [Webhook Configuration](#webhook-configuration)
- [Discovery Configuration](#discovery-configuration)
- [Frontend Configuration](#frontend-configuration)
- [Identity Configuration](#identity-configuration)
- [Configuration Profiles](#configuration-profiles)
- [Secrets Management](#secrets-management)
- [Validation](#validation)
- [Best Practices](#best-practices)

## Overview

Control supports configuration through multiple sources with the following precedence (highest to lowest):

1. **Environment variables** (highest priority)
2. **Configuration file**
3. **Default values** (lowest priority)

Configuration files use **YAML** format. The configuration supports a unified format where both engine and control can share the same config file, with each service reading its own section.

Environment variables use the `INFERADB__` prefix with double underscores (`__`) as separators. For the control section, use `INFERADB__CONTROL__`.

## Configuration Methods

### Method 1: Configuration File

Create a `config.yaml` file with the `control` section:

**YAML format** (recommended):

```yaml
control:
  threads: 4
  logging: "info"

  # Listen addresses (host:port format)
  listen:
    http: "127.0.0.1:9090" # Client-facing REST API
    grpc: "127.0.0.1:9091" # Client-facing gRPC API
    mesh: "0.0.0.0:9092" # Engine-to-control communication (JWKS, webhooks)

  storage: "memory"

  # Ledger configuration (only used when storage = "ledger")
  ledger:
    endpoint: "http://ledger.inferadb:50051"
    client_id: "control-001"
    namespace_id: 1
    vault_id: 1

  # WebAuthn configuration
  webauthn:
    party: "inferadb.com"
    origin: "https://app.inferadb.com"

  # Email configuration
  email:
    host: "smtp.sendgrid.net"
    port: 587
    username: "apikey"
    password: "${SENDGRID_API_KEY}"
    address: "noreply@inferadb.com"
    name: "InferaDB"

  # Rate limits
  limits:
    login_attempts_per_ip_per_hour: 100
    registrations_per_ip_per_day: 5
    email_verification_tokens_per_hour: 5
    password_reset_tokens_per_hour: 3

  # Engine mesh configuration
  mesh:
    url: "http://localhost"
    grpc: 8081
    port: 8082

  # Webhook configuration for cache invalidation
  webhook:
    timeout: 5000
    retries: 0

  # Service discovery
  discovery:
    mode:
      type: none
    cache_ttl: 300

  # Frontend configuration
  frontend:
    url: "http://localhost:3000"

  # Ed25519 private key in PEM format (optional - auto-generated if not provided)
  # pem: "-----BEGIN PRIVATE KEY-----\n..."

  # Path to master key file for encrypting private keys at rest
  # key_file: "./data/master.key"
```

**Load configuration file**:

```bash
inferadb-control --config config.yaml
```

### Method 2: Environment Variables

All configuration options can be set via environment variables using the `INFERADB__CONTROL__` prefix:

```bash
# Listen configuration
export INFERADB__CONTROL__LISTEN__HTTP="127.0.0.1:9090"
export INFERADB__CONTROL__LISTEN__GRPC="127.0.0.1:9091"
export INFERADB__CONTROL__LISTEN__MESH="0.0.0.0:9092"

# Threads and logging
export INFERADB__CONTROL__THREADS=4
export INFERADB__CONTROL__LOGGING="info"

# Storage configuration
export INFERADB__CONTROL__STORAGE="memory"
export INFERADB__CONTROL__LEDGER__ENDPOINT="http://ledger.inferadb:50051"
export INFERADB__CONTROL__LEDGER__CLIENT_ID="control-001"
export INFERADB__CONTROL__LEDGER__NAMESPACE_ID=1
export INFERADB__CONTROL__LEDGER__VAULT_ID=1

# WebAuthn
export INFERADB__CONTROL__WEBAUTHN__PARTY="inferadb.com"
export INFERADB__CONTROL__WEBAUTHN__ORIGIN="https://app.inferadb.com"

# Email
export INFERADB__CONTROL__EMAIL__HOST="smtp.sendgrid.net"
export INFERADB__CONTROL__EMAIL__PORT=587
export INFERADB__CONTROL__EMAIL__PASSWORD="your-smtp-password"
export INFERADB__CONTROL__EMAIL__ADDRESS="noreply@inferadb.com"
export INFERADB__CONTROL__EMAIL__NAME="InferaDB"

# Mesh (Engine connection)
export INFERADB__CONTROL__MESH__URL="http://localhost"
export INFERADB__CONTROL__MESH__GRPC=8081
export INFERADB__CONTROL__MESH__PORT=8082

# Frontend
export INFERADB__CONTROL__FRONTEND__URL="https://app.inferadb.com"
```

### Method 3: Combined (File + Environment)

Environment variables override file configuration:

```bash
# config.yaml sets listen.http to "127.0.0.1:9090"
# Environment variable overrides to bind to all interfaces
export INFERADB__CONTROL__LISTEN__HTTP="0.0.0.0:9090"
inferadb-control --config config.yaml
# Server binds to 0.0.0.0:9090 instead
```

## Listen Configuration

Controls HTTP/gRPC server listen addresses. Control exposes three interfaces:

- **HTTP** (port 9090): Client-facing REST API
- **gRPC** (port 9091): Client-facing gRPC API
- **Mesh** (port 9092): Engine-to-control communication (JWKS endpoint, webhooks)

### Options

| Option | Type   | Default            | Description                                     |
| ------ | ------ | ------------------ | ----------------------------------------------- |
| `http` | string | `"127.0.0.1:9090"` | Client-facing HTTP/REST API address (host:port) |
| `grpc` | string | `"127.0.0.1:9091"` | Client-facing gRPC API address (host:port)      |
| `mesh` | string | `"0.0.0.0:9092"`   | Engine-to-control mesh address (JWKS, webhooks) |

### Examples

**Development** (localhost only):

```yaml
control:
  listen:
    http: "127.0.0.1:9090"
    grpc: "127.0.0.1:9091"
    mesh: "127.0.0.1:9092"
```

**Production** (all interfaces):

```yaml
control:
  listen:
    http: "0.0.0.0:9090"
    grpc: "0.0.0.0:9091"
    mesh: "0.0.0.0:9092"
```

### Environment Variables

```bash
export INFERADB__CONTROL__LISTEN__HTTP="0.0.0.0:9090"
export INFERADB__CONTROL__LISTEN__GRPC="0.0.0.0:9091"
export INFERADB__CONTROL__LISTEN__MESH="0.0.0.0:9092"
```

## Storage Configuration

Controls the data storage backend.

### Options

| Option                | Type               | Default    | Description                               |
| --------------------- | ------------------ | ---------- | ----------------------------------------- |
| `storage`             | string             | `"memory"` | Storage backend: `"memory"` or `"ledger"` |
| `ledger.endpoint`     | string (optional)  | `null`     | Ledger gRPC endpoint URL                  |
| `ledger.client_id`    | string (optional)  | `null`     | Client ID for idempotency                 |
| `ledger.namespace_id` | integer (optional) | `null`     | Namespace for data scoping                |
| `ledger.vault_id`     | integer (optional) | `null`     | Vault for finer scoping                   |

### Backend Options

#### Memory Backend (Development)

- **Use case**: Local development, testing
- **Persistence**: None (data lost on restart)
- **Performance**: Fastest
- **Configuration**: No additional config needed

```yaml
control:
  storage: "memory"
```

#### Ledger Backend (Production)

- **Use case**: Production deployments
- **Persistence**: ACID transactions, Raft replication, cryptographic verifiability
- **Performance**: High throughput, low latency
- **Configuration**: Requires Ledger endpoint and namespace

```yaml
control:
  storage: "ledger"
  ledger:
    endpoint: "http://ledger.inferadb:50051"
    client_id: "control-001"
    namespace_id: 1
    vault_id: 1
```

### Environment Variables

```bash
export INFERADB__CONTROL__STORAGE="ledger"
export INFERADB__CONTROL__LEDGER__ENDPOINT="http://ledger.inferadb:50051"
export INFERADB__CONTROL__LEDGER__CLIENT_ID="control-001"
export INFERADB__CONTROL__LEDGER__NAMESPACE_ID=1
export INFERADB__CONTROL__LEDGER__VAULT_ID=1
```

## Authentication Configuration

Controls WebAuthn passkey authentication.

### WebAuthn Options

| Option   | Type   | Default                   | Description               |
| -------- | ------ | ------------------------- | ------------------------- |
| `party`  | string | `"localhost"`             | Relying Party ID (domain) |
| `origin` | string | `"http://localhost:3000"` | Origin URL for WebAuthn   |

### Examples

**Development**:

```yaml
control:
  webauthn:
    party: "localhost"
    origin: "http://localhost:3000"
```

**Production**:

```yaml
control:
  webauthn:
    party: "inferadb.com"
    origin: "https://app.inferadb.com"
```

### Environment Variables

```bash
export INFERADB__CONTROL__WEBAUTHN__PARTY="inferadb.com"
export INFERADB__CONTROL__WEBAUTHN__ORIGIN="https://app.inferadb.com"
```

### Security Notes

- **key_file**: Path to master key file for encrypting client private keys at rest. The key file contains 32 bytes of cryptographically secure random data. If the file doesn't exist, it will be generated automatically.
- **pem**: Ed25519 private key in PEM format for Control identity. If not provided, a new keypair is generated on each startup.

## Email Configuration

Controls email sending for verification and password reset.

### Options

| Option     | Type              | Default                  | Description                  |
| ---------- | ----------------- | ------------------------ | ---------------------------- |
| `host`     | string            | `"localhost"`            | SMTP server hostname         |
| `port`     | integer           | `587`                    | SMTP server port             |
| `username` | string (optional) | `null`                   | SMTP authentication username |
| `password` | string (optional) | `null`                   | SMTP authentication password |
| `address`  | string            | `"noreply@inferadb.com"` | From email address           |
| `name`     | string            | `"InferaDB"`             | From display name            |

### Examples

**Development** (local mailhog):

```yaml
control:
  email:
    host: "localhost"
    port: 1025
    address: "test@inferadb.local"
    name: "InferaDB Test"
```

**Production** (SendGrid):

```yaml
control:
  email:
    host: "smtp.sendgrid.net"
    port: 587
    username: "apikey"
    password: "${SENDGRID_API_KEY}"
    address: "noreply@inferadb.com"
    name: "InferaDB"
```

### Environment Variables

```bash
export INFERADB__CONTROL__EMAIL__HOST="smtp.sendgrid.net"
export INFERADB__CONTROL__EMAIL__PORT=587
export INFERADB__CONTROL__EMAIL__USERNAME="apikey"
export INFERADB__CONTROL__EMAIL__PASSWORD="your-api-key"
export INFERADB__CONTROL__EMAIL__ADDRESS="noreply@inferadb.com"
export INFERADB__CONTROL__EMAIL__NAME="InferaDB"
```

## Rate Limits Configuration

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
control:
  limits:
    login_attempts_per_ip_per_hour: 1000
    registrations_per_ip_per_day: 100
    email_verification_tokens_per_hour: 100
    password_reset_tokens_per_hour: 100
```

**Production** (strict):

```yaml
control:
  limits:
    login_attempts_per_ip_per_hour: 50
    registrations_per_ip_per_day: 3
    email_verification_tokens_per_hour: 3
    password_reset_tokens_per_hour: 2
```

### Environment Variables

```bash
export INFERADB__CONTROL__LIMITS__LOGIN_ATTEMPTS_PER_IP_PER_HOUR=50
export INFERADB__CONTROL__LIMITS__REGISTRATIONS_PER_IP_PER_DAY=3
export INFERADB__CONTROL__LIMITS__EMAIL_VERIFICATION_TOKENS_PER_HOUR=3
export INFERADB__CONTROL__LIMITS__PASSWORD_RESET_TOKENS_PER_HOUR=2
```

## Mesh Configuration

Controls connection to the InferaDB Engine.

### Options

| Option | Type    | Default              | Description                                       |
| ------ | ------- | -------------------- | ------------------------------------------------- |
| `url`  | string  | `"http://localhost"` | Engine base URL (without port)                    |
| `grpc` | integer | `8081`               | Engine gRPC port                                  |
| `port` | integer | `8082`               | Engine mesh/internal API port (for webhooks/JWKS) |

### Examples

**Development**:

```yaml
control:
  mesh:
    url: "http://localhost"
    grpc: 8081
    port: 8082
```

**Kubernetes**:

```yaml
control:
  mesh:
    url: "http://inferadb-engine.inferadb"
    grpc: 8081
    port: 8082
```

### Computed URLs

Control computes full URLs from these settings:

- **gRPC URL**: `{url}:{grpc}` → `http://localhost:8081`
- **Mesh URL**: `{url}:{port}` → `http://localhost:8082`

### Environment Variables

```bash
export INFERADB__CONTROL__MESH__URL="http://inferadb-engine.inferadb"
export INFERADB__CONTROL__MESH__GRPC=8081
export INFERADB__CONTROL__MESH__PORT=8082
```

## Webhook Configuration

Controls webhook-based cache invalidation to Engine instances.

### Options

| Option    | Type    | Default | Description                         |
| --------- | ------- | ------- | ----------------------------------- |
| `timeout` | integer | `5000`  | Webhook request timeout (ms)        |
| `retries` | integer | `0`     | Number of retry attempts on failure |

### Example

```yaml
control:
  webhook:
    timeout: 5000
    retries: 0
```

### Environment Variables

```bash
export INFERADB__CONTROL__WEBHOOK__TIMEOUT=5000
export INFERADB__CONTROL__WEBHOOK__RETRIES=0
```

### Notes

- Default is fire-and-forget (0 retries) for performance
- Increase `retries` if cache consistency is critical
- The Engine's mesh port receives these webhooks

## Discovery Configuration

Controls service discovery for multi-node deployments.

### Options

| Option                  | Type    | Default | Description                        |
| ----------------------- | ------- | ------- | ---------------------------------- |
| `mode`                  | object  | `none`  | Discovery mode configuration       |
| `cache_ttl`             | integer | `300`   | Cache TTL for discovered endpoints |
| `health_check_interval` | integer | `30`    | Health check interval (seconds)    |

### Discovery Modes

#### None (Default)

Direct connection to a single service URL:

```yaml
control:
  discovery:
    mode:
      type: none
```

#### Kubernetes

Discover pod IPs via Kubernetes service:

```yaml
control:
  discovery:
    mode:
      type: kubernetes
    cache_ttl: 30
    health_check_interval: 10
```

### Environment Variables

```bash
export INFERADB__CONTROL__DISCOVERY__CACHE_TTL=30
export INFERADB__CONTROL__DISCOVERY__HEALTH_CHECK_INTERVAL=10
```

## Frontend Configuration

Controls the frontend URL for email links (verification, password reset).

### Options

| Option | Type   | Default                   | Description                       |
| ------ | ------ | ------------------------- | --------------------------------- |
| `url`  | string | `"http://localhost:3000"` | Base URL for frontend email links |

### Example

```yaml
control:
  frontend:
    url: "https://app.inferadb.com"
```

### Environment Variables

```bash
export INFERADB__CONTROL__FRONTEND__URL="https://app.inferadb.com"
```

### Notes

- Must start with `http://` or `https://`
- Must not end with trailing slash
- A warning is logged if localhost is used in non-development environments

## Identity Configuration

Controls Control identity for service-to-service authentication with Engine.

### Options

| Option     | Type              | Default               | Description                                                   |
| ---------- | ----------------- | --------------------- | ------------------------------------------------------------- |
| `pem`      | string (optional) | `null`                | Ed25519 private key in PEM format (auto-generated if not set) |
| `key_file` | string (optional) | `"./data/master.key"` | Path to master key file for encrypting client private keys    |

### Example

```yaml
control:
  pem: "${CONTROL_PRIVATE_KEY}"
  key_file: "/secrets/master.key"
```

Or with no configuration (all values auto-generated):

```yaml
control:
  # pem and key_file will be auto-generated
```

### Environment Variables

```bash
export INFERADB__CONTROL__PEM="-----BEGIN PRIVATE KEY-----\n..."
export INFERADB__CONTROL__KEY_FILE="/secrets/master.key"
```

### Recommendations

- In production, always provide `pem` rather than relying on auto-generation
- Use Kubernetes secrets or a secret manager for the private key
- The `kid` is deterministically derived from the public key (RFC 7638), so it remains consistent when using the same private key
- The `management_id` is auto-generated from the hostname (Kubernetes pod name or hostname + random suffix)

## Configuration Profiles

### Development Profile

Optimized for local development:

```yaml
control:
  threads: 2
  logging: "debug"

  listen:
    http: "127.0.0.1:9090"
    grpc: "127.0.0.1:9091"
    mesh: "127.0.0.1:9092"

  storage: "memory"

  webauthn:
    party: "localhost"
    origin: "http://localhost:3000"

  email:
    host: "localhost"
    port: 1025
    address: "test@inferadb.local"
    name: "InferaDB Test"

  limits:
    login_attempts_per_ip_per_hour: 1000
    registrations_per_ip_per_day: 100
    email_verification_tokens_per_hour: 100
    password_reset_tokens_per_hour: 100

  mesh:
    url: "http://localhost"
    grpc: 8081
    port: 8082

  webhook:
    timeout: 5000
    retries: 0

  discovery:
    mode:
      type: none

  frontend:
    url: "http://localhost:3000"
```

### Production Profile

Optimized for production deployment:

```yaml
control:
  threads: 8
  logging: "info"

  listen:
    http: "0.0.0.0:9090"
    grpc: "0.0.0.0:9091"
    mesh: "0.0.0.0:9092"

  storage: "ledger"
  ledger:
    endpoint: "http://ledger.inferadb:50051"
    client_id: "control-001"
    namespace_id: 1
    vault_id: 1

  pem: "${CONTROL_PRIVATE_KEY}"
  key_file: "/secrets/master.key"

  webauthn:
    party: "inferadb.com"
    origin: "https://app.inferadb.com"

  email:
    host: "smtp.sendgrid.net"
    port: 587
    username: "apikey"
    password: "${SENDGRID_API_KEY}"
    address: "noreply@inferadb.com"
    name: "InferaDB"

  limits:
    login_attempts_per_ip_per_hour: 50
    registrations_per_ip_per_day: 3
    email_verification_tokens_per_hour: 3
    password_reset_tokens_per_hour: 2

  mesh:
    url: "http://inferadb-engine.inferadb"
    grpc: 8081
    port: 8082

  webhook:
    timeout: 5000
    retries: 1

  discovery:
    mode:
      type: kubernetes
    cache_ttl: 30
    health_check_interval: 10

  frontend:
    url: "https://app.inferadb.com"
```

### Integration Testing Profile

Optimized for E2E testing:

```yaml
control:
  threads: 2
  logging: "debug"

  listen:
    http: "0.0.0.0:9090"
    grpc: "0.0.0.0:9091"
    mesh: "0.0.0.0:9092"

  storage: "memory"

  webauthn:
    party: "localhost"
    origin: "http://localhost:3000"

  email:
    host: "localhost"
    port: 1025
    address: "test@inferadb.local"
    name: "InferaDB Test"

  limits:
    login_attempts_per_ip_per_hour: 1000
    registrations_per_ip_per_day: 100
    email_verification_tokens_per_hour: 100
    password_reset_tokens_per_hour: 100

  mesh:
    url: "http://inferadb-engine.inferadb"
    grpc: 8081
    port: 8082

  webhook:
    timeout: 5000
    retries: 0

  discovery:
    mode:
      type: kubernetes
    cache_ttl: 30

  frontend:
    url: "http://localhost:3000"
```

## Secrets Management

**Never commit secrets to configuration files.**

### Required Secrets

| Secret           | Purpose                                        |
| ---------------- | ---------------------------------------------- |
| `key_file`       | Path to master key for encrypting private keys |
| `email.password` | SMTP authentication                            |
| `pem`            | Ed25519 private key for Control identity       |

### Environment Variables (Recommended)

```bash
export INFERADB__CONTROL__KEY_FILE="/secrets/master.key"
export INFERADB__CONTROL__EMAIL__PASSWORD="your-smtp-password"
export INFERADB__CONTROL__PEM="-----BEGIN PRIVATE KEY-----\n..."
```

### Kubernetes Secrets

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: inferadb-control-secrets
type: Opaque
stringData:
  smtp-password: "your-smtp-password"
  private-key: |
    -----BEGIN PRIVATE KEY-----
    ...
    -----END PRIVATE KEY-----
data:
  master-key: <base64-encoded-32-byte-key>
```

```yaml
# In deployment
env:
  - name: INFERADB__CONTROL__EMAIL__PASSWORD
    valueFrom:
      secretKeyRef:
        name: inferadb-control-secrets
        key: smtp-password
  - name: INFERADB__CONTROL__PEM
    valueFrom:
      secretKeyRef:
        name: inferadb-control-secrets
        key: private-key
volumeMounts:
  - name: secrets
    mountPath: /secrets
    readOnly: true
volumes:
  - name: secrets
    secret:
      secretName: inferadb-control-secrets
      items:
        - key: master-key
          path: master.key
```

## Validation

Control validates configuration at startup with clear error messages.

### Validation Rules

**Listen Addresses**:

- `listen.http`, `listen.grpc`, `listen.mesh` must be valid socket addresses

**Storage**:

- `storage` must be `"memory"` or `"ledger"`
- `ledger.endpoint` required when `storage = "ledger"`

**WebAuthn**:

- `webauthn.party` cannot be empty
- `webauthn.origin` cannot be empty and must start with `http://` or `https://`

**Frontend**:

- `frontend.url` must start with `http://` or `https://`
- `frontend.url` must not end with trailing slash

**Mesh**:

- `mesh.url` must start with `http://` or `https://`
- `mesh.url` must not end with trailing slash

**Identity**:

- `pem` is optional (auto-generated if not set)

**Webhook**:

- `webhook.timeout` must be > 0
- `webhook.timeout > 60000` generates warning

### Example Validation Errors

```text
Error: Invalid storage: postgres. Must be 'memory' or 'ledger'
```

```text
Error: listen.http '127.0.0.1' is not valid: invalid socket address
```

```text
Error: webauthn.party cannot be empty
```

```text
Error: frontend.url must start with http:// or https://
```

## Best Practices

### Security

1. **Provide persistent identity in production**

   ```bash
   export INFERADB__CONTROL__PEM="-----BEGIN PRIVATE KEY-----\n..."
   export INFERADB__CONTROL__KEY_FILE="/secrets/master.key"
   ```

2. **Configure strict rate limiting**

   ```yaml
   control:
     limits:
       login_attempts_per_ip_per_hour: 50
       registrations_per_ip_per_day: 3
   ```

3. **Never commit secrets**
   - Use environment variables
   - Use Kubernetes secrets
   - Use secret managers

### Operations

1. **Worker IDs are auto-managed**
   - Control automatically acquires unique worker IDs
   - Uses pod ordinal in Kubernetes or collision detection otherwise

2. **Configure health checks in Kubernetes**
   - Use `/healthz` endpoint for liveness
   - Use `/readyz` endpoint for readiness

3. **Enable logging**

   ```yaml
   control:
     logging: "info" # or "debug" for troubleshooting
   ```

### Performance

1. **Use Ledger in production**
   - Memory backend doesn't persist
   - Ledger provides ACID + Raft replication + cryptographic verifiability

2. **Tune threads**
   - Defaults to number of CPU cores
   - Adjust based on workload

3. **Use Kubernetes discovery**
   - Enables direct pod-to-pod communication
   - Reduces cache invalidation latency

## Deployment Examples

### Docker Compose

```yaml
version: "3.8"
services:
  inferadb-control:
    image: inferadb/control:latest
    ports:
      - "9090:9090"
      - "9091:9091"
      - "9092:9092"
    environment:
      INFERADB__CONTROL__LISTEN__HTTP: "0.0.0.0:9090"
      INFERADB__CONTROL__LISTEN__GRPC: "0.0.0.0:9091"
      INFERADB__CONTROL__LISTEN__MESH: "0.0.0.0:9092"
      INFERADB__CONTROL__STORAGE: "ledger"
      INFERADB__CONTROL__LEDGER__ENDPOINT: "http://ledger.inferadb:50051"
      INFERADB__CONTROL__LEDGER__CLIENT_ID: "control-001"
      INFERADB__CONTROL__LEDGER__NAMESPACE_ID: "1"
      INFERADB__CONTROL__MESH__URL: "http://inferadb-engine"
      INFERADB__CONTROL__FRONTEND__URL: "https://app.inferadb.com"
    volumes:
      - ./secrets:/secrets:ro
```

### Kubernetes

See the Kubernetes manifests in the `k8s/` directory for complete deployment examples.

## Troubleshooting

### Server Won't Start

**Check configuration**:

```bash
inferadb-control --config config.yaml 2>&1 | grep ERROR
```

### Email Not Sending

1. Check SMTP credentials
2. Verify `email.host` and `email.port`
3. Check firewall rules
4. Test with local mailhog first

### Cache Invalidation Failing

1. Verify `mesh.url` is correct
2. Check network connectivity to Engine mesh port
3. Increase `webhook.timeout` if Engine instances are slow
4. Enable `webhook.retries` for reliability

### Worker ID Collisions

1. Worker IDs are auto-managed in Control
2. Check logs for collision warnings
3. Verify pod ordinals are unique in Kubernetes

## See Also

- [Engine Configuration](../../engine/docs/guides/configuration.md) - Engine configuration
- [Authentication Guide](../authentication.md) - Authentication details
- [Deployment Guide](../deployment.md) - Production deployment
