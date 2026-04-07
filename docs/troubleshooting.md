# Troubleshooting

Common issues and solutions for InferaDB Control.

## Why it matters

Deployment and integration problems have patterns. This guide maps error messages to root causes so you can resolve issues without reading source code.

## Quickstart diagnostics

```bash
# Check if the server is running
curl http://localhost:9090/livez

# Detailed health status
curl http://localhost:9090/healthz

# View configuration (redact secrets)
env | grep INFERADB__CONTROL__ | grep -Evi '(secret|password|token|key|pem|credential|blinding)'

# Enable debug logging
inferadb-control --log-level debug
```

## Build and setup

### Compilation errors

```bash
rustup update
cargo clean
cargo build --release
```

### Storage backend configuration error

`Failed to initialize storage backend` means the storage configuration is incomplete.

For development:

```bash
inferadb-control --dev-mode
```

For production with Ledger:

```bash
inferadb-control --storage ledger \
  --ledger-endpoint http://ledger:50051 \
  --ledger-client-id your-client-id
```

Both Ledger flags (`--ledger-endpoint` and `--ledger-client-id`) are required when `--storage ledger`.

### Port conflict

`Address already in use (os error 48)` or `(os error 98)`:

```bash
# Change port
inferadb-control --listen 127.0.0.1:8080

# Or find and kill the conflicting process
lsof -i :9090
kill <PID>
```

### Master key file not found

`Failed to load master key from file`: Specify a writable path. The file is auto-generated if it does not exist.

```bash
inferadb-control --key-file /etc/inferadb/master.key
```

## Authentication and sessions

### Authentication rejected

`401 Unauthorized: Invalid session`

Tokens are extracted from either the `Authorization: Bearer <token>` header or the `inferadb_access` cookie. The Bearer header takes precedence over cookies when both are present.

```bash
# Correct — Bearer token header (preferred)
curl -H "Authorization: Bearer $TOKEN" http://localhost:9090/control/v1/organizations

# Correct — inferadb_access cookie (browser clients)
curl -H "Cookie: inferadb_access=$TOKEN" http://localhost:9090/control/v1/organizations
```

### Expired tokens

| Token Type                 | Lifetime   |
| -------------------------- | ---------- |
| Access token cookie        | 15 minutes |
| User session refresh token | 1 hour     |
| Client refresh token       | 7 days     |
| Session cookie             | 24 hours   |

Use the refresh endpoint (`POST /control/v1/auth/refresh`) to obtain new access tokens before they expire.

### Session limit exceeded

Each user can have up to 10 concurrent sessions. When the limit is reached, revoke old sessions:

```bash
# Revoke all sessions
curl -X POST http://localhost:9090/control/v1/auth/revoke-all \
  -H "Authorization: Bearer $TOKEN"

# Log out the current session
curl -X POST http://localhost:9090/control/v1/auth/logout \
  -H "Authorization: Bearer $TOKEN"
```

### Rate limit exceeded

`429 Too Many Requests` with a `Retry-After` header.

Rate limits are built-in and not configurable:

- **Auth endpoints**: 100 requests/hour per IP
- **Registration**: 5 requests/day per IP

During development with the in-memory backend, restart the server to clear rate limit state.

For production clients, implement exponential backoff:

```python
import time
import requests

def auth_with_retry(url, payload, max_retries=5):
    for attempt in range(max_retries):
        response = requests.post(url, json=payload)
        if response.status_code == 429:
            wait = 2 ** attempt
            time.sleep(wait)
            continue
        return response
    raise Exception("max retries exceeded")
```

If all users behind a proxy share the same rate limit bucket, verify that the proxy sets `X-Forwarded-For` and that `--trusted-proxy-depth` is configured correctly.

## API errors

### 400 Bad Request

**Invalid JSON**: Ensure request bodies use valid JSON with quoted string values:

```bash
# Wrong
curl -d '{email: user@example.com}'

# Correct
curl -d '{"email": "user@example.com"}' -H "Content-Type: application/json"
```

**Validation failed**: Check the error response for field-specific details:

```json
{
  "error": "name must be between 1 and 128 characters",
  "code": "VALIDATION_ERROR"
}
```

### 403 Forbidden

Check your role in the organization (Owner, Admin, Member). Verify you are using the correct organization ID.

### 404 Not Found

Verify the resource ID is correct and that you have access to the resource:

```bash
curl http://localhost:9090/control/v1/organizations \
  -H "Authorization: Bearer $TOKEN"
```

### 500 Internal Server Error

Enable debug logging and check stdout:

```bash
inferadb-control --log-level debug
```

Include the timestamp, endpoint, and method when reporting issues.

## Performance

### Slow audit log queries

Use filters to narrow the result set:

```bash
# Filtered by event type and outcome
curl "http://localhost:9090/control/v1/organizations/{org}/audit-logs?event_type=ledger.vault&outcome=success&page_size=50" \
  -H "Authorization: Bearer $TOKEN"
```

### High memory usage

- Paginate all list operations with appropriate `page_size` values.
- Monitor memory via `GET /metrics`.
- The Tokio thread count equals CPU core count and is not configurable. Reduce concurrent connections at the load balancer if needed.

## Deployment

### Container fails to start

```bash
# Check logs
docker logs inferadb-control

# Verify environment variables
docker inspect inferadb-control | jq '.[0].Config.Env'

# Check key file mount
docker exec inferadb-control ls -la /data/master.key
```

### Kubernetes pod CrashLoopBackOff

```bash
# Current pod logs
kubectl logs -n infera pod/inferadb-control-xxxxx

# Previous crash logs
kubectl logs -n infera pod/inferadb-control-xxxxx --previous

# Verify config and secrets
kubectl get configmap -n infera infera-config -o yaml
kubectl get secret -n infera infera-secrets -o yaml
```

### Service not accessible from within the cluster

```bash
kubectl get endpoints -n infera inferadb-control

kubectl run -it --rm debug --image=curlimages/curl --restart=Never -- \
  curl http://inferadb-control.infera.svc.cluster.local:9090/healthz
```

## Email delivery

### Verification emails not received

For development with a local mail server (Mailpit, MailHog):

```bash
# Check the web UI
open http://localhost:8025
```

For production, verify SMTP configuration:

```bash
inferadb-control \
  --email-host smtp.example.com \
  --email-port 587 \
  --email-username "smtp-user" \
  --email-password "smtp-pass" \
  --email-from-address "noreply@example.com" \
  --email-from-name "Your Company"
```

Test SMTP connectivity:

```bash
telnet smtp.example.com 587
```

If email is not needed, leave `--email-host` empty (the default). The server runs without email capabilities when the host is empty.

## Getting help

1. Enable trace logging: `inferadb-control --log-level trace`
2. Collect diagnostic info:

   ```bash
   uname -a
   inferadb-control --version
   env | grep INFERADB__CONTROL__ | grep -Evi '(secret|password|token|key|pem|credential|blinding)'
   ```

3. File an issue: [github.com/inferadb/inferadb/issues](https://github.com/inferadb/inferadb/issues)
4. Security issues: Email security@inferadb.com (do not file public issues).
