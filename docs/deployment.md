# InferaDB Control - Deployment Guide

This guide provides instructions for deploying InferaDB Control in production environments.

## Prerequisites

### Infrastructure Requirements

- **Compute Resources** (single instance):
  - CPU: 4+ cores recommended
  - RAM: 8GB+ recommended (data stored in memory)
  - Storage: Minimal (logs only, data in RAM)

- **Network**:
  - HTTP port (default: 127.0.0.1:9090, localhost only) - REST API. Use `0.0.0.0:9090` in production to accept external connections.
  - Outbound access to:
    - SMTP server (for email)
    - InferaDB Ledger (if using ledger storage)

### Software Dependencies

- Rust toolchain (for building from source)
- TLS certificates (for production HTTPS)

## Configuration

InferaDB Control uses CLI flags and environment variables for all configuration. There are no config files.

### CLI Flags

```bash
inferadb-control \
  --listen 0.0.0.0:9090 \
  --storage ledger \
  --key-file /etc/inferadb/master.key \
  --frontend-url https://dashboard.example.com \
  --log-level info \
  --log-format json \
  --email-host smtp.example.com \
  --email-port 587 \
  --email-username "smtp-user" \
  --email-password "smtp-pass" \
  --email-from-address "noreply@example.com" \
  --email-from-name "Your Company" \
  --ledger-endpoint http://ledger:9200 \
  --ledger-client-id your-client-id \
  --ledger-namespace-id your-namespace-id \
  --ledger-vault-id your-vault-id
```

| Flag                    | Type                   | Default                 | Description                                                     |
| ----------------------- | ---------------------- | ----------------------- | --------------------------------------------------------------- |
| `--listen`              | SocketAddr             | `127.0.0.1:9090`        | HTTP listen address (override to `0.0.0.0:9090` for production) |
| `--storage`             | `memory`\|`ledger`     | `ledger`                | Storage backend                                                 |
| `--dev-mode`            | flag                   | off                     | Forces memory storage, relaxes security                         |
| `--key-file`            | PathBuf                | `./data/master.key`     | Path to Ed25519 master key file                                 |
| `--pem`                 | String                 | —                       | Ed25519 PEM string (alternative to `--key-file`)                |
| `--frontend-url`        | String                 | `http://localhost:3000` | Frontend URL for email links                                    |
| `--log-level`           | String                 | `info`                  | Log level: trace, debug, info, warn, error                      |
| `--log-format`          | `auto`\|`json`\|`text` | `auto`                  | Log output format                                               |
| `--email-host`          | String                 | `""` (disabled)         | SMTP host (empty disables email)                                |
| `--email-port`          | u16                    | `587`                   | SMTP port                                                       |
| `--email-username`      | String                 | —                       | SMTP username                                                   |
| `--email-password`      | String                 | —                       | SMTP password                                                   |
| `--email-from-address`  | String                 | `noreply@inferadb.com`  | Sender email address                                            |
| `--email-from-name`     | String                 | `InferaDB`              | Sender display name                                             |
| `--email-insecure`      | flag                   | off                     | Disable SMTP TLS verification                                   |
| `--ledger-endpoint`     | String                 | —                       | Ledger storage endpoint (required when storage=ledger)          |
| `--ledger-client-id`    | String                 | —                       | Ledger client ID (required when storage=ledger)                 |
| `--ledger-namespace-id` | String                 | —                       | Ledger namespace ID (required when storage=ledger)              |
| `--ledger-vault-id`     | String                 | —                       | Ledger vault ID (optional)                                      |

### Environment Variables

Every CLI flag can also be set via environment variable using the `INFERADB__CONTROL__` prefix with double underscores as separators. Hyphens in flag names become underscores:

```bash
# Listen address
export INFERADB__CONTROL__LISTEN="0.0.0.0:9090"

# Storage backend
export INFERADB__CONTROL__STORAGE="ledger"

# Master key
export INFERADB__CONTROL__KEY_FILE="/etc/inferadb/master.key"
# Or provide the PEM string directly
export INFERADB__CONTROL__PEM="-----BEGIN PRIVATE KEY-----..."

# SMTP credentials
export INFERADB__CONTROL__EMAIL_HOST="smtp.example.com"
export INFERADB__CONTROL__EMAIL_PORT="587"
export INFERADB__CONTROL__EMAIL_USERNAME="smtp-user"
export INFERADB__CONTROL__EMAIL_PASSWORD="smtp-pass"
export INFERADB__CONTROL__EMAIL_FROM_ADDRESS="noreply@example.com"
export INFERADB__CONTROL__EMAIL_FROM_NAME="Your Company"

# Ledger storage
export INFERADB__CONTROL__LEDGER_ENDPOINT="http://ledger:9200"
export INFERADB__CONTROL__LEDGER_CLIENT_ID="your-client-id"
export INFERADB__CONTROL__LEDGER_NAMESPACE_ID="your-namespace-id"
export INFERADB__CONTROL__LEDGER_VAULT_ID="your-vault-id"

# Logging
export INFERADB__CONTROL__LOG_LEVEL="info"
export INFERADB__CONTROL__LOG_FORMAT="json"
```

**CRITICAL**: Store secrets (PEM key, SMTP password) securely via a secrets manager or encrypted environment variables. Never commit them to version control.

### Authentication Keys

Generate an Ed25519 key pair for signing JWTs:

```bash
openssl genpkey -algorithm Ed25519 -out master.key
```

Provide the key via `--key-file` (path to the PEM file) or `--pem` (inline PEM string). The `--pem` flag is useful in containerized environments where mounting files is inconvenient.

## Single-Instance Deployment

### Single Instance Configuration

Deploy one instance of Control:

```bash
inferadb-control \
  --listen 0.0.0.0:9090 \
  --storage ledger \
  --key-file /etc/inferadb/master.key \
  --ledger-endpoint http://ledger:9200 \
  --ledger-client-id control-prod-01 \
  --ledger-namespace-id 1
```

### Load Balancer (Optional)

You can still use a load balancer for TLS termination and health checks:

- **Health checks**: `GET /readyz`
- **Session affinity**: Not required
- **TLS termination**: Recommended at load balancer

Example (Kubernetes Service):

```yaml
apiVersion: v1
kind: Service
metadata:
  name: inferadb-control-api
spec:
  selector:
    app: inferadb-control-api
  ports:
    - name: http
      port: 80
      targetPort: 9090
  type: LoadBalancer

---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: inferadb-control-api
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  tls:
    - hosts:
        - api.example.com
      secretName: infera-api-tls
  rules:
    - host: api.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: inferadb-control-api
                port:
                  number: 80
```

### Data Persistence Considerations

**Important**: With the in-memory backend:

- All data (users, sessions, vaults, etc.) is stored in RAM
- Restarting the server loses all data
- For production use, implement regular backups or wait for Ledger backend

**Recommended Approach**:

- Use persistent volumes to store export snapshots
- Implement automated backup scripts
- Plan migration strategy for when Ledger backend is available

## Future: Multi-Instance Deployment

When Ledger backend is implemented, the following features will enable multi-instance HA deployments:

### Leader Election (Future)

Leader election will be automatically handled using Ledger:

- Only the leader instance will run background jobs
- Leadership will automatically transfer on failure
- No manual intervention required

## Health Checks

Control provides multiple health check endpoints:

### Liveness Probe

```bash
GET /livez
```

Returns `200 OK` if the process is running. Use for Kubernetes liveness probes.

### Readiness Probe

```bash
GET /readyz
```

Returns `200 OK` if the service is ready to accept traffic (storage accessible). Use for Kubernetes readiness probes.

### Startup Probe

```bash
GET /startupz
```

Returns `200 OK` after initialization is complete. Use for Kubernetes startup probes.

### Detailed Health Status

```bash
GET /healthz
```

Returns JSON with detailed health information:

```json
{
  "status": "healthy",
  "service": "inferadb-control",
  "version": "0.1.0",
  "instance_id": 0,
  "uptime_seconds": 3600,
  "storage_healthy": true,
  "is_leader": true,
  "details": null
}
```

## Graceful Shutdown

Control handles graceful shutdown on `SIGTERM` and `SIGINT`:

1. Stop accepting new requests
2. Wait for in-flight requests to complete (up to 30 seconds)
3. Release leader lease (if leader)
4. Cleanup worker registration
5. Exit

**Kubernetes**: Set `terminationGracePeriodSeconds: 60` to allow sufficient time for graceful shutdown.

## Observability

### Logging

Logs are written to stdout. Configure via CLI flags:

```bash
inferadb-control --log-level info --log-format json
```

Or via environment variables:

```bash
export INFERADB__CONTROL__LOG_LEVEL="info"    # trace, debug, info, warn, error
export INFERADB__CONTROL__LOG_FORMAT="json"   # auto, json, text
```

### Metrics

Prometheus metrics are exposed at `/metrics`:

Key metrics:

- HTTP request duration/count
- Storage operation latency
- Background job execution status
- Leader election status
- Rate limit hit counts

## Security Best Practices

### 1. TLS/HTTPS

**Always use TLS in production**:

- Terminate TLS at load balancer or reverse proxy
- Use valid certificates (Let's Encrypt, commercial CA)
- Enforce HTTPS redirects

### 2. Secrets Management

**Never commit secrets to version control**:

- Use environment variables for runtime secrets
- Consider secrets management systems:
  - Kubernetes Secrets
  - HashiCorp Vault
  - AWS Secrets Manager
  - Azure Key Vault

### 3. Network Security

- Use private networks for database connections
- Restrict ingress to load balancer only
- Enable mTLS for internal gRPC communication

### 4. Rate Limiting

Rate limits are built-in defaults enforced per IP:

- Login: 100/hour
- Registration: 5/day
- Email verification: 5/hour
- Password reset: 3/hour

These limits are not configurable via CLI flags or environment variables. Deploy behind a reverse proxy that sets `X-Forwarded-For` headers correctly.

### 5. CORS

CORS is configured automatically based on `--frontend-url`. Set this to your web dashboard origin:

```bash
inferadb-control --frontend-url https://dashboard.example.com
```

## Deployment Checklist

- [ ] Ed25519 master key generated and stored securely
- [ ] Secrets stored securely (environment variables/secrets manager)
- [ ] Storage backend selected (`--storage ledger` for production)
- [ ] Ledger endpoint and credentials configured (if using ledger storage)
- [ ] Sufficient RAM allocated (8GB+ recommended)
- [ ] Data backup/export procedures documented
- [ ] Load balancer configured with health checks (if using)
- [ ] TLS certificates provisioned
- [ ] `--frontend-url` set for CORS and email links
- [ ] Email SMTP credentials configured and tested
- [ ] Logging configured (`--log-level`, `--log-format`)
- [ ] Disaster recovery plan established (understand data loss with memory storage)
- [ ] Security review completed
- [ ] Load testing performed
- [ ] Team aware of single-instance limitation

## Troubleshooting

### Data Loss on Restart

**Symptoms**: All users, sessions, and data lost after server restart.

**Explanation**: This is expected behavior with the in-memory backend.

**Solutions**:

1. Implement regular data export/backup procedures
2. Document recovery procedures for team
3. Wait for Ledger backend implementation for persistent storage

### High Rate Limit Rejections

**Symptoms**: Users seeing "429 Too Many Requests" errors.

**Solutions**:

1. Verify load balancer correctly forwards `X-Forwarded-For`
2. Rate limits are hardcoded; contact support if adjustments are needed
3. Implement IP whitelisting for trusted sources

### Session Limit Exceeded

**Symptoms**: Users unable to create new sessions.

**Solutions**:

1. Session limits are hardcoded; review session cleanup job execution in application logs
2. Manually revoke old sessions via API

### Email Delivery Failures

**Symptoms**: Users not receiving verification/reset emails.

**Solutions**:

1. Test SMTP connectivity: `telnet smtp-host 587`
2. Verify SMTP credentials
3. Check email service logs for delivery status
4. Ensure `from_email` is authorized sender

## Maintenance

### Updating Configuration

1. Update CLI flags or environment variables
2. Rolling restart of instances (zero-downtime)
3. Verify health checks pass

### Scaling Up/Down

1. Add/remove instances
2. Ensure unique worker IDs
3. Update load balancer backends
4. Leader election automatically adjusts

## Support

For issues or questions:

- GitHub Issues: <https://github.com/inferadb/inferadb>
- Documentation: <https://inferadb.com/docs>
- Community Discord: <https://discord.gg/inferadb>
