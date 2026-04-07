# Configuration

Configure InferaDB Control via CLI flags and environment variables. No configuration files.

## Why this matters

InferaDB Control uses CLI-first configuration with environment variable fallbacks. Getting the configuration right determines whether your deployment is secure, observable, and connected to the correct storage backend.

## Quickstart

```bash
# Development -- in-memory storage, auto-generated identity
inferadb-control --dev-mode

# Production -- Ledger backend with all required fields
inferadb-control \
  --listen 0.0.0.0:9090 \
  --storage ledger \
  --ledger-endpoint https://ledger.prod:50051 \
  --ledger-client-id ctrl-prod-01 \
  --pem "$(cat /secrets/identity.pem)" \
  --key-file /data/master.key \
  --frontend-url https://app.inferadb.com \
  --webauthn-rp-id app.inferadb.com \
  --webauthn-origin https://app.inferadb.com \
  --email-host smtp.sendgrid.net \
  --email-port 587 \
  --email-username apikey \
  --email-password "$SENDGRID_API_KEY" \
  --worker-id 0 \
  --log-format json
```

## Precedence

1. **CLI flags** (highest priority)
2. **Environment variables** (prefix: `INFERADB__CONTROL__`)
3. **Default values** (lowest priority)

Run `inferadb-control --help` for the full list of options and defaults.

## Server

| CLI Flag     | Env Var                     | Type         | Default          | Required | Description                                     |
| ------------ | --------------------------- | ------------ | ---------------- | -------- | ----------------------------------------------- |
| `--listen`   | `INFERADB__CONTROL__LISTEN` | `SocketAddr` | `127.0.0.1:9090` | No       | HTTP bind address                               |
| `--dev-mode` | --                          | `bool`       | `false`          | No       | Forces in-memory storage. CLI only, no env var. |

Dev mode overrides `--storage` to `memory` regardless of its value.

## Observability

| CLI Flag       | Env Var                         | Type     | Default | Required | Description                                            |
| -------------- | ------------------------------- | -------- | ------- | -------- | ------------------------------------------------------ |
| `--log-level`  | `INFERADB__CONTROL__LOG_LEVEL`  | `String` | `info`  | No       | Tracing filter string (e.g., `info`, `debug`, `trace`) |
| `--log-format` | `INFERADB__CONTROL__LOG_FORMAT` | `Enum`   | `auto`  | No       | Output format: `auto`, `json`, `text`                  |

The `auto` format uses JSON when stdout is not a TTY, and human-readable text otherwise. Use `json` in production for structured log aggregation.

## Storage

| CLI Flag             | Env Var                               | Type     | Default  | Required              | Description                                                    |
| -------------------- | ------------------------------------- | -------- | -------- | --------------------- | -------------------------------------------------------------- |
| `--storage`          | `INFERADB__CONTROL__STORAGE`          | `Enum`   | `ledger` | No                    | Backend: `memory` or `ledger`                                  |
| `--ledger-endpoint`  | `INFERADB__CONTROL__LEDGER_ENDPOINT`  | `String` | --       | When `storage=ledger` | Ledger gRPC endpoint. Must start with `http://` or `https://`. |
| `--ledger-client-id` | `INFERADB__CONTROL__LEDGER_CLIENT_ID` | `String` | --       | When `storage=ledger` | Client identifier for idempotency tracking                     |

When `storage=ledger`, two fields are required: `ledger-endpoint` and `ledger-client-id`. The server refuses to start if either is missing.

The `memory` backend stores all data in RAM. Data is lost on restart. Use it only for development and testing.

## Identity and encryption

| CLI Flag     | Env Var                       | Type      | Default             | Required | Description                                                                  |
| ------------ | ----------------------------- | --------- | ------------------- | -------- | ---------------------------------------------------------------------------- |
| `--pem`      | `INFERADB__CONTROL__PEM`      | `String`  | --                  | No       | Ed25519 private key in PEM format. Auto-generated on each startup if absent. |
| `--key-file` | `INFERADB__CONTROL__KEY_FILE` | `PathBuf` | `./data/master.key` | No       | Path to AES-256-GCM master key for encrypting private keys at rest           |

In production, provide a stable `--pem` value. If auto-generated, JWTs issued before a restart become invalid because the signing key changes.

## Email (SMTP)

| CLI Flag               | Env Var                                 | Type     | Default                | Required           | Description                                                            |
| ---------------------- | --------------------------------------- | -------- | ---------------------- | ------------------ | ---------------------------------------------------------------------- |
| `--email-host`         | `INFERADB__CONTROL__EMAIL_HOST`         | `String` | `""` (empty)           | No                 | SMTP hostname. Empty string disables email.                            |
| `--email-port`         | `INFERADB__CONTROL__EMAIL_PORT`         | `u16`    | `587`                  | No                 | SMTP port (587 for STARTTLS, 465 for implicit TLS)                     |
| `--email-username`     | `INFERADB__CONTROL__EMAIL_USERNAME`     | `String` | --                     | When email enabled | SMTP authentication username                                           |
| `--email-password`     | `INFERADB__CONTROL__EMAIL_PASSWORD`     | `String` | --                     | When email enabled | SMTP authentication password                                           |
| `--email-from-address` | `INFERADB__CONTROL__EMAIL_FROM_ADDRESS` | `String` | `noreply@inferadb.com` | No                 | Sender email address                                                   |
| `--email-from-name`    | `INFERADB__CONTROL__EMAIL_FROM_NAME`    | `String` | `InferaDB`             | No                 | Sender display name                                                    |
| `--email-insecure`     | `INFERADB__CONTROL__EMAIL_INSECURE`     | `bool`   | `false`                | No                 | Skip TLS certificate verification. For local dev only (e.g., Mailpit). |

Email is disabled by default. Set `--email-host` to a non-empty value to enable it. When disabled, verification codes are generated but not delivered -- check server logs in dev mode.

The server warns at startup if `--email-insecure` is set with a non-localhost host.

## Email blinding

| CLI Flag               | Env Var                                 | Type     | Default | Required             | Description                                             |
| ---------------------- | --------------------------------------- | -------- | ------- | -------------------- | ------------------------------------------------------- |
| `--email-blinding-key` | `INFERADB__CONTROL__EMAIL_BLINDING_KEY` | `String` | --      | For email operations | HMAC-SHA256 key as a 64-character hex string (32 bytes) |

This key must match the key configured on the Ledger cluster. Generate one with:

```bash
openssl rand -hex 32
```

## Authentication (WebAuthn)

| CLI Flag            | Env Var                              | Type     | Default                 | Required | Description                                                         |
| ------------------- | ------------------------------------ | -------- | ----------------------- | -------- | ------------------------------------------------------------------- |
| `--webauthn-rp-id`  | `INFERADB__CONTROL__WEBAUTHN_RP_ID`  | `String` | `localhost`             | No       | Relying Party ID. Must be an effective domain suffix of the origin. |
| `--webauthn-origin` | `INFERADB__CONTROL__WEBAUTHN_ORIGIN` | `String` | `http://localhost:3000` | No       | Relying Party origin URL. Must include the scheme.                  |

The RP ID cannot change after passkey credentials are registered. Set it to your production domain before accepting real credential registrations.

## Frontend

| CLI Flag         | Env Var                           | Type     | Default                 | Required | Description                                                                                        |
| ---------------- | --------------------------------- | -------- | ----------------------- | -------- | -------------------------------------------------------------------------------------------------- |
| `--frontend-url` | `INFERADB__CONTROL__FRONTEND_URL` | `String` | `http://localhost:3000` | No       | Base URL for links in emails (verification, password reset). Also used as the CORS allowed origin. |

Must start with `http://` or `https://`. Must not end with a trailing slash. The server warns if this contains `localhost` or `127.0.0.1`.

## Network

| CLI Flag                | Env Var                                  | Type        | Default | Required | Description                                                                                              |
| ----------------------- | ---------------------------------------- | ----------- | ------- | -------- | -------------------------------------------------------------------------------------------------------- |
| `--trusted-proxy-depth` | `INFERADB__CONTROL__TRUSTED_PROXY_DEPTH` | `NonZeroU8` | --      | No       | Number of trusted reverse proxies. When set, client IP is the Nth-from-right entry in `X-Forwarded-For`. |

Set this when running behind a load balancer (e.g., AWS ALB, nginx). Without it, rate limiting uses the direct connection IP, which is the proxy address.

## Instance identity

| CLI Flag      | Env Var                        | Type  | Default | Required | Description                                                                                              |
| ------------- | ------------------------------ | ----- | ------- | -------- | -------------------------------------------------------------------------------------------------------- |
| `--worker-id` | `INFERADB__CONTROL__WORKER_ID` | `u16` | random  | No       | Snowflake ID worker ID (0--1023). Each instance in a multi-instance deployment must have a unique value. |

If unset, a random value is chosen at startup. In Kubernetes, derive it from the pod ordinal to guarantee uniqueness.

## Validation rules

The server validates configuration at startup and refuses to start if rules are violated:

- **Ledger storage**: `--ledger-endpoint` and `--ledger-client-id` are both required. The endpoint must start with `http://` or `https://`.
- **Frontend URL**: Must start with `http://` or `https://`. Must not end with `/`.
- **Dev mode**: Overrides `--storage` to `memory`.
- **Worker ID**: Must be in the range 0--1023.

## Sensitive fields

Three fields contain secrets and are hidden from `--help` output:

| Field                  | Purpose                                      |
| ---------------------- | -------------------------------------------- |
| `--pem`                | Ed25519 private key (control plane identity) |
| `--email-blinding-key` | HMAC-SHA256 key for email address hashing    |
| `--email-password`     | SMTP authentication credential               |

These fields are also redacted in debug log output.

## Deployment profiles

### Development

```bash
inferadb-control --dev-mode
```

All defaults apply. In-memory storage, auto-generated identity, no email delivery.

### Development with email (Mailpit)

```bash
inferadb-control --dev-mode \
  --email-host localhost \
  --email-port 1025 \
  --email-insecure
```

### Production (CLI flags)

```bash
inferadb-control \
  --listen 0.0.0.0:9090 \
  --storage ledger \
  --ledger-endpoint https://ledger.prod:50051 \
  --ledger-client-id ctrl-prod-01 \
  --pem "$(cat /secrets/identity.pem)" \
  --key-file /data/master.key \
  --email-blinding-key "$EMAIL_BLINDING_KEY" \
  --frontend-url https://app.inferadb.com \
  --webauthn-rp-id app.inferadb.com \
  --webauthn-origin https://app.inferadb.com \
  --email-host smtp.sendgrid.net \
  --email-port 587 \
  --email-username apikey \
  --email-password "$SENDGRID_API_KEY" \
  --email-from-address noreply@inferadb.com \
  --worker-id 0 \
  --log-format json \
  --trusted-proxy-depth 1
```

### Production (environment variables)

```bash
export INFERADB__CONTROL__LISTEN=0.0.0.0:9090
export INFERADB__CONTROL__STORAGE=ledger
export INFERADB__CONTROL__LEDGER_ENDPOINT=https://ledger.prod:50051
export INFERADB__CONTROL__LEDGER_CLIENT_ID=ctrl-prod-01
export INFERADB__CONTROL__PEM="$(cat /secrets/identity.pem)"
export INFERADB__CONTROL__KEY_FILE=/data/master.key
export INFERADB__CONTROL__EMAIL_BLINDING_KEY="$EMAIL_BLINDING_KEY"
export INFERADB__CONTROL__FRONTEND_URL=https://app.inferadb.com
export INFERADB__CONTROL__WEBAUTHN_RP_ID=app.inferadb.com
export INFERADB__CONTROL__WEBAUTHN_ORIGIN=https://app.inferadb.com
export INFERADB__CONTROL__EMAIL_HOST=smtp.sendgrid.net
export INFERADB__CONTROL__EMAIL_PORT=587
export INFERADB__CONTROL__EMAIL_USERNAME=apikey
export INFERADB__CONTROL__EMAIL_PASSWORD="$SENDGRID_API_KEY"
export INFERADB__CONTROL__EMAIL_FROM_ADDRESS=noreply@inferadb.com
export INFERADB__CONTROL__WORKER_ID=0
export INFERADB__CONTROL__LOG_FORMAT=json
export INFERADB__CONTROL__TRUSTED_PROXY_DEPTH=1

inferadb-control
```

### Docker

```bash
docker run -p 9090:9090 inferadb/control:latest --dev-mode
```

### Docker Compose

```yaml
services:
  inferadb-control:
    image: inferadb/control:latest
    ports:
      - "9090:9090"
    environment:
      INFERADB__CONTROL__LISTEN: "0.0.0.0:9090"
      INFERADB__CONTROL__STORAGE: "ledger"
      INFERADB__CONTROL__LEDGER_ENDPOINT: "http://ledger:50051"
      INFERADB__CONTROL__LEDGER_CLIENT_ID: "control-001"
      INFERADB__CONTROL__FRONTEND_URL: "https://app.inferadb.com"
      INFERADB__CONTROL__WEBAUTHN_RP_ID: "app.inferadb.com"
      INFERADB__CONTROL__WEBAUTHN_ORIGIN: "https://app.inferadb.com"
```

### Kubernetes secrets

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: inferadb-control-secrets
type: Opaque
stringData:
  pem: |
    -----BEGIN PRIVATE KEY-----
    MC4CAQAwBQYDK2VwBCIE...
    -----END PRIVATE KEY-----
  emailBlindingKey: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2"
  emailPassword: "SG.your-sendgrid-api-key"
```

Reference the secrets in your deployment:

```yaml
env:
  - name: INFERADB__CONTROL__PEM
    valueFrom:
      secretKeyRef:
        name: inferadb-control-secrets
        key: pem
  - name: INFERADB__CONTROL__EMAIL_BLINDING_KEY
    valueFrom:
      secretKeyRef:
        name: inferadb-control-secrets
        key: emailBlindingKey
  - name: INFERADB__CONTROL__EMAIL_PASSWORD
    valueFrom:
      secretKeyRef:
        name: inferadb-control-secrets
        key: emailPassword
```

## Troubleshooting

### Startup validation fails

Run `inferadb-control --help` to see all options and their types. Common issues:

- Missing `--ledger-endpoint` when `--storage=ledger`
- `--frontend-url` ends with a trailing slash
- `--ledger-endpoint` uses a non-HTTP scheme (e.g., `grpc://`)

### Email not sending

1. Verify `--email-host` is non-empty (empty disables email)
2. Check SMTP credentials and port
3. Test with a local mail server: `--email-host localhost --email-port 1025 --email-insecure`

### Debug logging

```bash
inferadb-control --dev-mode --log-level debug

# Pretty-print JSON logs
inferadb-control --dev-mode --log-format json 2>&1 | jq

# Filter for errors
inferadb-control --dev-mode --log-format json 2>&1 | jq 'select(.level == "ERROR")'
```
