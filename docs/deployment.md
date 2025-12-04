# InferaDB Management API - Deployment Guide

This guide provides instructions for deploying the InferaDB Management API in production environments.

**IMPORTANT**: The Management API currently supports in-memory storage backend only. FoundationDB backend is planned for future multi-instance production deployments but is not yet implemented. This limits deployment to single-instance configurations.

## Prerequisites

### Infrastructure Requirements

- **Compute Resources** (single instance):

  - CPU: 4+ cores recommended
  - RAM: 8GB+ recommended (data stored in memory)
  - Storage: Minimal (logs only, data in RAM)

- **Network**:
  - HTTP port (default: 3000) - Management REST API
  - gRPC port (default: 3001) - Internal gRPC server
  - Outbound access to:
    - InferaDB policy engine (gRPC)
    - SMTP server (for email)
    - Observability endpoints (metrics, tracing)

### Software Dependencies

- Rust toolchain (for building from source)
- TLS certificates (for production HTTPS)

## Configuration

### 1. Copy Production Config Template

```bash
cp config.production.yaml config.yaml
```

### 2. Configure Required Values

Edit `config.yaml` and replace all placeholder values marked with `<...>`:

#### Storage Backend

```yaml
storage:
  backend: "memory" # Only implemented backend currently
```

**Note**: The Management API currently only supports the in-memory storage backend. FoundationDB backend is planned but not yet implemented. This means:

- All data is stored in RAM
- Data is lost on server restart
- Not suitable for high-availability multi-instance deployments
- Ensure adequate RAM allocation (8GB+ recommended)

#### Authentication Security

```yaml
auth:
  key_encryption_secret: "<REPLACE-WITH-32+-BYTE-SECRET>"
```

**Action**: Generate a secure random secret (32+ bytes) for encrypting private keys:

```bash
# Generate a 32-byte hex secret
openssl rand -hex 32
```

**CRITICAL**: Store this secret securely (environment variable or secrets manager). Never commit to version control.

#### WebAuthn Configuration

```yaml
auth:
  webauthn:
    rp_id: "example.com"
    rp_name: "Your Company"
    origin: "https://example.com"
```

**Action**: Set `rp_id` and `origin` to match your production domain. The `origin` must exactly match the browser origin (including protocol and port if non-standard).

#### Email (SMTP)

```yaml
email:
  smtp_host: "<SMTP-HOST>"
  smtp_port: 587
  smtp_username: "<SMTP-USERNAME>" # Optional
  smtp_password: "<SMTP-PASSWORD>" # Optional
  from_email: "noreply@example.com"
  from_name: "Your Company"
```

**Action**: Configure your SMTP provider credentials. For security, use environment variables:

```bash
export SMTP_PASSWORD="your-password"
```

#### Server API Endpoint

```yaml
server_api:
  grpc_endpoint: "https://policy-engine.example.com:8080"
  tls_enabled: true
```

**Action**: Point to your InferaDB policy engine gRPC endpoint. Enable TLS in production.

### 3. Environment-Specific Overrides

Use environment variables to override sensitive configuration:

```bash
# Key encryption secret
export KEY_ENCRYPTION_SECRET="your-32-byte-secret"

# SMTP credentials
export SMTP_USERNAME="smtp-user"
export SMTP_PASSWORD="smtp-pass"

# Worker ID (for multi-instance deployments)
export WORKER_ID="0"
```

## Single-Instance Deployment

**Current Limitation**: Due to the in-memory storage backend, only single-instance deployments are currently supported. Multi-instance high-availability deployments will be possible when the FoundationDB backend is implemented.

### Single Instance Configuration

Deploy one instance of the Management API:

```yaml
id_generation:
  worker_id: 0 # Fixed for single instance
```

### Load Balancer (Optional)

You can still use a load balancer for TLS termination and health checks:

- **Health checks**: `GET /v1/health/ready`
- **Session affinity**: Not required
- **TLS termination**: Recommended at load balancer

Example (Kubernetes Service):

```yaml
apiVersion: v1
kind: Service
metadata:
  name: infera-management-api
spec:
  selector:
    app: infera-management-api
  ports:
    - name: http
      port: 80
      targetPort: 3000
  type: LoadBalancer

---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: infera-management-api
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
                name: infera-management-api
                port:
                  number: 80
```

### Data Persistence Considerations

**Important**: With the in-memory backend:

- All data (users, sessions, vaults, etc.) is stored in RAM
- Restarting the server loses all data
- For production use, implement regular backups or wait for FoundationDB backend

**Recommended Approach**:

- Use persistent volumes to store export snapshots
- Implement automated backup scripts
- Plan migration strategy for when FoundationDB backend is available

## Future: Multi-Instance Deployment

When FoundationDB backend is implemented, the following features will enable multi-instance HA deployments:

### Worker ID Management (Future)

Each instance will require a unique worker ID (0-1023) for Snowflake ID generation:

```yaml
id_generation:
  worker_id: ${WORKER_ID} # Unique per instance
```

### Leader Election (Future)

Leader election will be automatically handled using FoundationDB:

```yaml
leader_election:
  enabled: true
  lease_ttl_seconds: 30
  renewal_interval_seconds: 10
```

- Only the leader instance will run background jobs
- Leadership will automatically transfer on failure
- No manual intervention required

## Health Checks

The management API provides multiple health check endpoints:

### Liveness Probe

```bash
GET /v1/health/live
```

Returns `200 OK` if the process is running. Use for Kubernetes liveness probes.

### Readiness Probe

```bash
GET /v1/health/ready
```

Returns `200 OK` if the service is ready to accept traffic (storage accessible). Use for Kubernetes readiness probes.

### Startup Probe

```bash
GET /v1/health/startup
```

Returns `200 OK` after initialization is complete. Use for Kubernetes startup probes.

### Detailed Health Status

```bash
GET /v1/health
```

Returns JSON with detailed health information:

```json
{
  "status": "healthy",
  "version": "0.1.0",
  "instance_id": 0,
  "uptime": 3600,
  "storage_healthy": true,
  "is_leader": true
}
```

## Graceful Shutdown

The management API handles graceful shutdown on `SIGTERM` and `SIGINT`:

1. Stop accepting new requests
2. Wait for in-flight requests to complete (up to 30 seconds)
3. Release leader lease (if leader)
4. Cleanup worker registration
5. Exit

**Kubernetes**: Set `terminationGracePeriodSeconds: 60` to allow sufficient time for graceful shutdown.

## Observability

### Logging

Logs are written to stdout in JSON format (structured logging).

Configure log level:

```yaml
observability:
  log_level: "info" # trace, debug, info, warn, error
```

### Metrics

Prometheus metrics are exposed at `/metrics` (if enabled):

```yaml
observability:
  metrics_enabled: true
```

Key metrics:

- HTTP request duration/count
- gRPC call duration/count
- Storage operation latency
- Background job execution status
- Leader election status
- Rate limit hit counts

### Distributed Tracing

OpenTelemetry tracing support (optional):

```yaml
observability:
  tracing_enabled: true
  tracing_endpoint: "http://jaeger:4317" # OTLP endpoint
```

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

Rate limits are enforced per IP:

- Login: 100/hour
- Registration: 5/day
- Email verification: 5/hour
- Password reset: 3/hour

Configure behind a reverse proxy that sets `X-Forwarded-For` headers correctly.

### 5. CORS

Configure CORS for your web dashboard:

```yaml
cors:
  allowed_origins:
    - "https://dashboard.example.com"
  allow_credentials: true
```

## Deployment Checklist

- [ ] Production config file created with `backend: "memory"` storage
- [ ] Secrets stored securely (environment variables/secrets manager)
- [ ] Sufficient RAM allocated (8GB+ recommended)
- [ ] Data backup/export procedures documented
- [ ] Load balancer configured with health checks (if using)
- [ ] TLS certificates provisioned
- [ ] CORS configured for web dashboard
- [ ] Email SMTP credentials configured and tested
- [ ] Logging and monitoring configured
- [ ] Disaster recovery plan established (understand data loss on restart)
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
3. Wait for FoundationDB backend implementation for persistent storage

### High Rate Limit Rejections

**Symptoms**: Users seeing "429 Too Many Requests" errors.

**Solutions**:

1. Verify load balancer correctly forwards `X-Forwarded-For`
2. Increase rate limits in config (if legitimate traffic)
3. Implement IP whitelisting for trusted sources

### Session Limit Exceeded

**Symptoms**: Users unable to create new sessions.

**Solutions**:

1. Increase `max_sessions_per_user` in config
2. Review session cleanup job execution (check leader instance logs)
3. Manually revoke old sessions via API

### Email Delivery Failures

**Symptoms**: Users not receiving verification/reset emails.

**Solutions**:

1. Test SMTP connectivity: `telnet smtp-host 587`
2. Verify SMTP credentials
3. Check email service logs for delivery status
4. Ensure `from_email` is authorized sender

## Maintenance

### Updating Configuration

1. Edit `config.yaml`
2. Rolling restart of instances (zero-downtime)
3. Verify health checks pass

### Scaling Up/Down

1. Add/remove instances
2. Ensure unique worker IDs
3. Update load balancer backends
4. Leader election automatically adjusts

### Database Migrations

Currently, the management API uses in-memory storage. Schema evolution is handled in-code.

When FoundationDB backend is implemented, migration procedures will be documented in release notes.

## Support

For issues or questions:

- GitHub Issues: <https://github.com/inferadb/inferadb>
- Documentation: <https://inferadb.com/docs>
- Community Discord: <https://discord.gg/inferadb>
