# InferaDB Control Configuration Guide

Configuration via CLI arguments and environment variables.

## Overview

InferaDB Control uses CLI-first configuration with environment variable fallbacks. Precedence (highest to lowest):

1. **CLI arguments** (highest priority)
2. **Environment variables** (`INFERADB__CONTROL__` prefix)
3. **Default values** (lowest priority)

Run `inferadb-control --help` for the full list of options.

## Quick Start

```bash
# Development (in-memory storage, auto-generated identity)
inferadb-control --dev-mode

# Production (all required fields)
inferadb-control \
  --listen 0.0.0.0:9090 \
  --storage ledger \
  --ledger-endpoint https://ledger.inferadb:50051 \
  --ledger-client-id ctrl-prod-01 \
  --ledger-namespace-id 1 \
  --key-file /data/master.key \
  --frontend-url https://app.inferadb.com \
  --log-format json

# Same via environment variables
export INFERADB__CONTROL__LISTEN=0.0.0.0:9090
export INFERADB__CONTROL__STORAGE=ledger
export INFERADB__CONTROL__LEDGER_ENDPOINT=https://ledger.inferadb:50051
export INFERADB__CONTROL__LEDGER_CLIENT_ID=ctrl-prod-01
export INFERADB__CONTROL__LEDGER_NAMESPACE_ID=1
export INFERADB__CONTROL__KEY_FILE=/data/master.key
export INFERADB__CONTROL__FRONTEND_URL=https://app.inferadb.com
export INFERADB__CONTROL__LOG_FORMAT=json
inferadb-control
```

## Configuration Reference

### Server

| CLI Flag       | Env Var                         | Type         | Default          | Description            |
| -------------- | ------------------------------- | ------------ | ---------------- | ---------------------- |
| `--listen`     | `INFERADB__CONTROL__LISTEN`     | `SocketAddr` | `127.0.0.1:9090` | HTTP bind address      |
| `--log-level`  | `INFERADB__CONTROL__LOG_LEVEL`  | `String`     | `info`           | tracing filter string  |
| `--log-format` | `INFERADB__CONTROL__LOG_FORMAT` | `Enum`       | `auto`           | `auto`, `json`, `text` |

### Identity & Encryption

| CLI Flag     | Env Var                       | Type      | Default             | Description                      |
| ------------ | ----------------------------- | --------- | ------------------- | -------------------------------- |
| `--pem`      | `INFERADB__CONTROL__PEM`      | `String?` | —                   | Ed25519 PEM (auto-gen if absent) |
| `--key-file` | `INFERADB__CONTROL__KEY_FILE` | `PathBuf` | `./data/master.key` | AES-256-GCM master key path      |

### Storage

| CLI Flag                | Env Var                                  | Type      | Default  | Description                  |
| ----------------------- | ---------------------------------------- | --------- | -------- | ---------------------------- |
| `--storage`             | `INFERADB__CONTROL__STORAGE`             | `Enum`    | `ledger` | `memory` or `ledger`         |
| `--ledger-endpoint`     | `INFERADB__CONTROL__LEDGER_ENDPOINT`     | `String?` | —        | Required when storage=ledger |
| `--ledger-client-id`    | `INFERADB__CONTROL__LEDGER_CLIENT_ID`    | `String?` | —        | Required when storage=ledger |
| `--ledger-namespace-id` | `INFERADB__CONTROL__LEDGER_NAMESPACE_ID` | `i64?`    | —        | Required when storage=ledger |
| `--ledger-vault-id`     | `INFERADB__CONTROL__LEDGER_VAULT_ID`     | `i64?`    | —        | Optional                     |

### Email (SMTP)

| CLI Flag               | Env Var                                 | Type      | Default                | Description       |
| ---------------------- | --------------------------------------- | --------- | ---------------------- | ----------------- |
| `--email-host`         | `INFERADB__CONTROL__EMAIL_HOST`         | `String`  | `""` (empty)           | Empty = email off |
| `--email-port`         | `INFERADB__CONTROL__EMAIL_PORT`         | `u16`     | `587`                  | SMTP port         |
| `--email-username`     | `INFERADB__CONTROL__EMAIL_USERNAME`     | `String?` | —                      | SMTP username     |
| `--email-password`     | `INFERADB__CONTROL__EMAIL_PASSWORD`     | `String?` | —                      | SMTP password     |
| `--email-from-address` | `INFERADB__CONTROL__EMAIL_FROM_ADDRESS` | `String`  | `noreply@inferadb.com` | From address      |
| `--email-from-name`    | `INFERADB__CONTROL__EMAIL_FROM_NAME`    | `String`  | `InferaDB`             | From display name |
| `--email-insecure`     | `INFERADB__CONTROL__EMAIL_INSECURE`     | `bool`    | `false`                | Skip TLS verify   |

### Frontend

| CLI Flag         | Env Var                           | Type     | Default                 | Description              |
| ---------------- | --------------------------------- | -------- | ----------------------- | ------------------------ |
| `--frontend-url` | `INFERADB__CONTROL__FRONTEND_URL` | `String` | `http://localhost:3000` | Base URL for email links |

### Mode Flags

| CLI Flag     | Type   | Default | Description                                  |
| ------------ | ------ | ------- | -------------------------------------------- |
| `--dev-mode` | `bool` | `false` | Forces storage=memory (no env var, CLI only) |

## Validation Rules

Configuration is validated at startup:

- **Ledger storage**: `ledger_endpoint`, `ledger_client_id`, and `ledger_namespace_id` must all be set; `ledger_endpoint` must start with `http://` or `https://`
- **Frontend URL**: Must start with `http://` or `https://`, must not end with `/`; warns if `localhost` or `127.0.0.1` is used
- **Dev mode**: Overrides storage to `memory` regardless of `--storage` value

## Configuration Profiles

### Development

```bash
inferadb-control --dev-mode
```

### Production

```bash
inferadb-control \
  --listen 0.0.0.0:9090 \
  --storage ledger \
  --ledger-endpoint https://ledger.inferadb:50051 \
  --ledger-client-id ctrl-prod-01 \
  --ledger-namespace-id 1 \
  --key-file /data/master.key \
  --pem "$(cat /secrets/identity.pem)" \
  --frontend-url https://app.inferadb.com \
  --email-host smtp.sendgrid.net \
  --email-port 587 \
  --email-username apikey \
  --email-password "$SENDGRID_API_KEY" \
  --email-from-address noreply@inferadb.com \
  --log-format json

```

## Secrets Management

Never commit secrets. Use environment variables or Kubernetes secrets.

### Sensitive Fields

These are the Kubernetes secret key names used in the examples below:

| Secret Key      | Purpose                                |
| --------------- | -------------------------------------- |
| `pem`           | Ed25519 private key (control identity) |
| `emailPassword` | SMTP authentication                    |

Both use `hide_env_values = true` in clap (hidden from `--help` output).

### Kubernetes Secrets

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: inferadb-control-secrets
type: Opaque
stringData:
  pem: |
    -----BEGIN PRIVATE KEY-----
    ...
    -----END PRIVATE KEY-----
  emailPassword: "your-smtp-password"
```

```yaml
env:
  - name: INFERADB__CONTROL__PEM
    valueFrom:
      secretKeyRef:
        name: inferadb-control-secrets
        key: pem
  - name: INFERADB__CONTROL__EMAIL_PASSWORD
    valueFrom:
      secretKeyRef:
        name: inferadb-control-secrets
        key: emailPassword
```

## Deployment Examples

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
      INFERADB__CONTROL__LEDGER_NAMESPACE_ID: "1"
      INFERADB__CONTROL__FRONTEND_URL: "https://app.inferadb.com"
```

### Kubernetes (Helm)

```bash
helm install inferadb-control ./helm \
  --namespace inferadb \
  --create-namespace \
  --set config.storage=ledger \
  --set config.ledgerEndpoint=http://ledger.inferadb:50051 \
  --set config.ledgerClientId=ctrl-prod-01 \
  --set config.ledgerNamespaceId=1
```

## Troubleshooting

### Validation Errors

Run with `--help` to see all options and their defaults:

```bash
inferadb-control --help
```

### Email Not Sending

1. Verify `--email-host` is non-empty (empty = disabled)
2. Check SMTP credentials
3. Test with local mailhog: `--email-host localhost --email-port 1025`

## See Also

- [Authentication Guide](../authentication.md)
- [Deployment Guide](../deployment.md)
