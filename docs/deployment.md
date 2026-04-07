# Deployment Guide

This guide covers production deployment of the `inferadb-control` binary.

## Why It Matters

A correct deployment requires matching CLI flags to your infrastructure, configuring health probes, and securing secrets. Mistakes here cause silent data loss (wrong storage backend) or authentication failures (wrong key configuration).

## Quickstart

Development (in-memory, no external dependencies):

```bash
inferadb-control --dev-mode
```

Production (Ledger backend):

```bash
inferadb-control \
  --listen 0.0.0.0:9090 \
  --storage ledger \
  --ledger-endpoint http://ledger:9200 \
  --ledger-client-id control-prod-01 \
  --key-file /etc/inferadb/master.key \
  --frontend-url https://dashboard.example.com \
  --log-level info \
  --log-format json
```

## Configuration

All configuration uses CLI flags or environment variables. There are no config files.

Precedence: CLI flag > environment variable > default value.

### CLI Flags

| Flag                    | Type                   | Default                 | Description                                                     |
| ----------------------- | ---------------------- | ----------------------- | --------------------------------------------------------------- |
| `--listen`              | SocketAddr             | `127.0.0.1:9090`        | HTTP bind address                                               |
| `--storage`             | `memory` or `ledger`   | `ledger`                | Storage backend                                                 |
| `--dev-mode`            | flag                   | off                     | Forces memory storage (CLI-only, no env var)                    |
| `--key-file`            | PathBuf                | `./data/master.key`     | Path to AES-256-GCM master key file (auto-generated if missing) |
| `--pem`                 | String                 | --                      | Ed25519 PEM string for JWT signing (auto-generated if missing)  |
| `--frontend-url`        | String                 | `http://localhost:3000` | Base URL for email links and CORS origin                        |
| `--log-level`           | String                 | `info`                  | Tracing filter: trace, debug, info, warn, error                 |
| `--log-format`          | `auto`, `json`, `text` | `auto`                  | Log output format (auto = JSON when non-TTY, text otherwise)    |
| `--email-host`          | String                 | `""` (disabled)         | SMTP host; empty disables email                                 |
| `--email-port`          | u16                    | `587`                   | SMTP port                                                       |
| `--email-username`      | String                 | --                      | SMTP username                                                   |
| `--email-password`      | String                 | --                      | SMTP password                                                   |
| `--email-from-address`  | String                 | `noreply@inferadb.com`  | Sender email address                                            |
| `--email-from-name`     | String                 | `InferaDB`              | Sender display name                                             |
| `--email-insecure`      | flag                   | off                     | Skip SMTP TLS verification (development only)                   |
| `--email-blinding-key`  | String                 | --                      | HMAC-SHA256 key for email blinding (64-char hex, 32 bytes)      |
| `--ledger-endpoint`     | String                 | --                      | Ledger gRPC endpoint URL (required when `storage=ledger`)       |
| `--ledger-client-id`    | String                 | --                      | Ledger client identifier (required when `storage=ledger`)       |
| `--webauthn-rp-id`      | String                 | `localhost`             | WebAuthn Relying Party ID (domain)                              |
| `--webauthn-origin`     | String                 | `http://localhost:3000` | WebAuthn Relying Party origin URL                               |
| `--trusted-proxy-depth` | NonZeroU8              | --                      | Number of trusted reverse proxies for `X-Forwarded-For`         |
| `--worker-id`           | u16                    | random                  | Snowflake ID worker ID (0-1023, must be unique per instance)    |

### Environment Variables

Every CLI flag maps to an environment variable with the `INFERADB__CONTROL__` prefix. Hyphens in flag names become underscores:

```bash
export INFERADB__CONTROL__LISTEN="0.0.0.0:9090"
export INFERADB__CONTROL__STORAGE="ledger"
export INFERADB__CONTROL__KEY_FILE="/etc/inferadb/master.key"
export INFERADB__CONTROL__LEDGER_ENDPOINT="http://ledger:9200"
export INFERADB__CONTROL__LEDGER_CLIENT_ID="control-prod-01"
export INFERADB__CONTROL__LOG_LEVEL="info"
export INFERADB__CONTROL__LOG_FORMAT="json"
```

Exception: `--dev-mode` has no environment variable. It must be an explicit CLI choice.

Store secrets (`INFERADB__CONTROL__PEM`, `INFERADB__CONTROL__EMAIL_PASSWORD`, `INFERADB__CONTROL__EMAIL_BLINDING_KEY`) in a secrets manager. Do not commit them to version control.

## Authentication Keys

**Ed25519 Identity Key** (JWT signing): Provide via `--pem`. If omitted, a new keypair is generated on each startup, invalidating all existing tokens.

```bash
openssl genpkey -algorithm Ed25519 -out identity.pem
inferadb-control --pem "$(cat identity.pem)"
```

**AES-256-GCM Master Key** (encrypting private keys at rest): The `--key-file` path points to a 32-byte key file. If the file does not exist, a new key is auto-generated with restrictive permissions (0600).

## Health Checks

Control exposes four health endpoints. None require authentication.

| Endpoint    | Purpose                                           | Returns    | Use For                    |
| ----------- | ------------------------------------------------- | ---------- | -------------------------- |
| `/livez`    | Process is running                                | 200 OK     | Kubernetes liveness probe  |
| `/readyz`   | Ledger is reachable (or no Ledger in dev)         | 200 or 503 | Kubernetes readiness probe |
| `/startupz` | Initialization complete (delegates to readyz)     | 200 or 503 | Kubernetes startup probe   |
| `/healthz`  | Detailed JSON with version, uptime, Ledger status | 200 JSON   | Monitoring and debugging   |

`/healthz` response:

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

Health check results are cached for 5 seconds to protect Ledger from probe bursts.

## Graceful Shutdown

Control handles `SIGTERM` and `SIGINT`:

1. Stops accepting new connections.
2. Waits for in-flight requests to complete (up to 30 seconds).
3. Cleans up worker registration.
4. Exits.

Set `terminationGracePeriodSeconds: 60` in Kubernetes to allow sufficient drain time.

## Observability

### Logging

Logs go to stdout. Configure with `--log-level` and `--log-format`.

```bash
# Production
inferadb-control --log-level info --log-format json

# Debugging
inferadb-control --log-level debug --log-format text
```

### Metrics

Prometheus metrics are exposed at `GET /metrics` (no authentication). Key metrics include HTTP request duration/count, storage operation latency, and rate limit hit counts.

## Security

### TLS

Control does not terminate TLS. Place it behind a reverse proxy or load balancer that handles TLS.

### CORS

CORS is configured from `--frontend-url`. Set this to your web dashboard origin:

```bash
inferadb-control --frontend-url https://dashboard.example.com
```

### Rate Limiting

Built-in rate limits are enforced per IP and are not configurable:

- **Login/auth endpoints**: 100 requests/hour per IP
- **Registration**: 5 requests/day per IP

Deploy behind a reverse proxy that sets `X-Forwarded-For`, and use `--trusted-proxy-depth` to specify how many proxy hops to trust.

### Network Security

- Use private networks for Ledger gRPC connections.
- Restrict ingress to the load balancer.
- The metrics endpoint (`/metrics`) has no authentication; protect it with network policy.

## Kubernetes Example

```yaml
apiVersion: v1
kind: Service
metadata:
  name: inferadb-control
spec:
  selector:
    app: inferadb-control
  ports:
    - name: http
      port: 80
      targetPort: 9090

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: inferadb-control
spec:
  template:
    spec:
      terminationGracePeriodSeconds: 60
      containers:
        - name: control
          livenessProbe:
            httpGet:
              path: /livez
              port: 9090
          readinessProbe:
            httpGet:
              path: /readyz
              port: 9090
          startupProbe:
            httpGet:
              path: /startupz
              port: 9090
            failureThreshold: 30
            periodSeconds: 2
```

## Deployment Checklist

- [ ] `--storage ledger` with `--ledger-endpoint` and `--ledger-client-id` configured
- [ ] Ed25519 PEM key persisted (not auto-generated per restart)
- [ ] Master key file path on persistent storage
- [ ] Secrets stored in a secrets manager
- [ ] `--frontend-url` set to the production dashboard URL
- [ ] `--trusted-proxy-depth` matches your proxy chain
- [ ] Unique `--worker-id` per instance (for multi-instance deployments)
- [ ] SMTP credentials configured and tested (if email is needed)
- [ ] TLS termination configured at the load balancer
- [ ] Health check probes configured in the orchestrator
- [ ] `--log-format json` for structured log aggregation
