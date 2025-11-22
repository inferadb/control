# Troubleshooting Guide

This guide covers common issues and their solutions when working with the InferaDB Management API.

## Table of Contents

- [Installation & Setup](#installation--setup)
- [Database & Storage](#database--storage)
- [Authentication & Sessions](#authentication--sessions)
- [API Errors](#api-errors)
- [Performance Issues](#performance-issues)
- [Deployment Issues](#deployment-issues)
- [Development & Testing](#development--testing)

## Installation & Setup

### Rust Build Failures

#### Issue: Compilation errors with missing dependencies

**Error**: `error: failed to compile ...`

**Solution**:

```bash
# Update Rust toolchain
rustup update

# Clean build artifacts
cargo clean

# Rebuild
cargo build --release
```

#### Issue: Storage backend configuration error

**Error**: `Failed to initialize storage backend`

**Solution**:

```bash
# Ensure config.yaml uses memory backend
storage:
  backend: "memory"

# FoundationDB backend is not yet implemented
# If you see FoundationDB-related errors, change to memory backend
```

### Port Conflicts

#### Issue: Address already in use

**Error**: `Address already in use (os error 48)` or `Address already in use (os error 98)`

**Solutions**:

**Option 1**: Change ports in configuration

```yaml
# config.local.yaml
server:
  http_port: 8080 # Changed from 3000
  grpc_port: 8081 # Changed from 3001
```

**Option 2**: Use environment variables

```bash
export INFERADB_MGMT__SERVER__HTTP_PORT=8080
export INFERADB_MGMT__SERVER__GRPC_PORT=8081
./target/release/infera-management-api
```

**Option 3**: Kill conflicting process

```bash
# macOS/Linux: Find process using port
lsof -i :3000

# Kill the process
kill -9 <PID>
```

### Configuration Issues

#### Issue: Configuration file not found

**Error**: `Failed to load configuration file`

**Solution**:

```bash
# Specify config file explicitly
./target/release/infera-management-api --config /path/to/config.yaml

# Or use environment variable
export INFERADB_MGMT_CONFIG_PATH=/path/to/config.yaml
```

#### Issue: Key encryption secret too short

**Error**: `Key encryption secret must be at least 32 bytes`

**Solution**:

```bash
# Generate proper 32-byte secret
openssl rand -base64 32

# Add to config.yaml
auth:
  key_encryption_secret: "generated-secret-here"

# Or use environment variable
export INFERADB_MGMT__AUTH__KEY_ENCRYPTION_SECRET=$(openssl rand -base64 32)
```

## Database & Storage

### Memory Backend Issues

#### Issue: Out of memory errors

**Error**: `Cannot allocate memory` or application crashes

**Solutions**:

1. Check available RAM: `free -h` (Linux) or Activity Monitor (macOS)
2. Increase memory allocation for the process
3. Reduce concurrent users/sessions
4. Consider implementing data cleanup/archival procedures

#### Issue: Data lost after restart

**Symptom**: All users, sessions, vaults disappeared after server restart

**Explanation**: This is expected behavior with in-memory backend

**Solutions**:

1. Implement regular data export procedures
2. Document this limitation for your team
3. Wait for FoundationDB backend implementation (planned)

### Data Migration Issues

#### Issue: Schema version mismatch

**Error**: `Incompatible schema version`

**Solution**:

```bash
# With memory backend, simply restart the server to reset
# All data will be cleared

# For persistent data, wait for FoundationDB backend implementation
```

## Authentication & Sessions

### Login Failures

#### Issue: Invalid credentials

**Error**: `401 Unauthorized: Invalid email or password`

**Solutions**:

1. Verify email is registered: Check with admin or use password reset
2. Check for typos in email/password
3. Ensure password meets minimum requirements (12+ characters by default)
4. Try password reset flow:

```bash
# Request password reset
curl -X POST http://localhost:3000/v1/auth/password-reset/request \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'

# Check email (or MailHog in dev)
```

#### Issue: Email not verified

**Error**: `403 Forbidden: Email verification required`

**Solution**:

```bash
# Resend verification email
curl -X POST http://localhost:3000/v1/auth/email-verification/resend \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'

# For development, disable requirement in config
features:
  require_email_verification: false
```

### Session Issues

#### Issue: Session cookie not working

**Error**: `401 Unauthorized: Invalid session`

**Solutions**:

**Step 1**: Verify cookie format

```bash
# Correct format
curl -H "Cookie: infera_session=sess_abc123..."

# Incorrect (will fail)
curl -H "Authorization: Bearer sess_abc123"  # Wrong header
curl -H "Cookie: session_id=sess_abc123"    # Wrong cookie name
```

**Step 2**: Check session expiration

```bash
# Sessions expire after TTL (default: 30 days for web)
# Login again to get new session
curl -X POST http://localhost:3000/v1/auth/login/password \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "pass"}'
```

**Step 3**: Verify session type matches usage

```yaml
# config.yaml - Check TTL settings
auth:
  session_ttl_web: 2592000 # 30 days
  session_ttl_cli: 7776000 # 90 days
  session_ttl_sdk: 7776000 # 90 days
```

#### Issue: Too many sessions

**Error**: `429 Too Many Requests: Maximum sessions exceeded`

**Solution**:

```bash
# Revoke old sessions
curl -X POST http://localhost:3000/v1/auth/sessions/{session_id}/revoke \
  -H "Cookie: infera_session={current_session_id}"

# Or revoke all sessions
curl -X POST http://localhost:3000/v1/auth/sessions/revoke-all \
  -H "Cookie: infera_session={session_id}"
```

### Rate Limiting

#### Issue: Rate limit exceeded

**Error**: `429 Too Many Requests: Rate limit exceeded`

**Solutions**:

**For development**: Adjust rate limits in config

```yaml
# config.local.yaml
rate_limiting:
  login_attempts_per_ip_per_hour: 1000 # Increase for testing
  registrations_per_ip_per_day: 100
```

**For production**: Implement exponential backoff

```python
import time
import requests

def login_with_retry(email, password, max_retries=5):
    for attempt in range(max_retries):
        response = requests.post(
            "http://localhost:3000/v1/auth/login/password",
            json={"email": email, "password": password}
        )

        if response.status_code == 429:
            # Exponential backoff
            wait_time = 2 ** attempt
            print(f"Rate limited. Waiting {wait_time}s...")
            time.sleep(wait_time)
            continue

        return response

    raise Exception("Max retries exceeded")
```

## API Errors

### 400 Bad Request

#### Issue: Invalid JSON

**Error**: `400 Bad Request: Failed to parse JSON`

**Solution**:

```bash
# Incorrect (missing quotes)
curl -d '{email: user@example.com}'  # ❌

# Correct
curl -d '{"email": "user@example.com"}'  # ✅
```

#### Issue: Validation errors

**Error**: `400 Bad Request: Validation failed`

**Solution**: Check error response for details

```json
{
  "error": "Validation failed",
  "details": {
    "password": "Password must be at least 12 characters"
  }
}
```

### 403 Forbidden

#### Issue: Insufficient permissions

**Error**: `403 Forbidden: Insufficient permissions`

**Solutions**:

1. Check your role in the organization (Owner, Admin, Member)
2. Verify you're using the correct organization ID
3. Request permission upgrade from organization owner

### 404 Not Found

#### Issue: Resource not found

**Error**: `404 Not Found: Organization not found`

**Solutions**:

1. Verify resource ID is correct
2. Check you have access to the resource
3. Confirm resource wasn't deleted

```bash
# List your organizations
curl -X GET http://localhost:3000/v1/organizations \
  -H "Cookie: infera_session={session_id}"
```

### 500 Internal Server Error

#### Issue: Unexpected server error

**Error**: `500 Internal Server Error`

**Solutions**:

**Step 1**: Check server logs

```bash
# View recent logs
tail -f /var/log/infera-management-api.log

# Or if running directly
./target/release/infera-management-api --config config.yaml 2>&1 | tee api.log
```

**Step 2**: Enable debug logging

```yaml
# config.yaml
observability:
  log_level: "debug" # or "trace"
```

**Step 3**: Report the issue with logs

- Include relevant log excerpts
- Note the timestamp of the error
- Provide request details (endpoint, method, payload)

## Performance Issues

### Slow Queries

#### Issue: Audit log queries timing out

**Cause**: Querying large date ranges without filters

**Solution**:

```bash
# Bad: Open-ended query
GET /v1/organizations/{org}/audit-logs

# Good: Time-bounded query
GET /v1/organizations/{org}/audit-logs?start_date=2025-11-01T00:00:00Z&end_date=2025-11-18T23:59:59Z

# Better: Add event type filter
GET /v1/organizations/{org}/audit-logs?event_type=user_login&start_date=2025-11-01T00:00:00Z
```

### High Memory Usage

#### Issue: API consuming excessive memory

**Causes**: Large result sets, memory leaks, or insufficient pagination

**Solutions**:

**Step 1**: Use pagination

```bash
# Fetch in smaller batches
GET /v1/organizations/{org}/vaults?limit=25
```

**Step 2**: Monitor memory usage

```bash
# Check memory usage
ps aux | grep infera-management-api

# Use Prometheus metrics
curl http://localhost:3000/metrics | grep memory
```

**Step 3**: Adjust worker threads

```yaml
# config.yaml
server:
  worker_threads: 4 # Reduce from default
```

## Deployment Issues

### Docker Deployment

#### Issue: Container fails to start

**Error**: `Container exited with code 1`

**Solutions**:

**Step 1**: Check container logs

```bash
docker logs infera-management-api

# Follow logs in real-time
docker logs -f infera-management-api
```

**Step 2**: Verify environment variables

```bash
# List container environment
docker inspect infera-management-api | jq '.[0].Config.Env'
```

**Step 3**: Check volume mounts

```bash
# Verify config file is accessible
docker exec infera-management-api cat /app/config.yaml
```

### Kubernetes Deployment

#### Issue: Pod CrashLoopBackOff

**Error**: Pod repeatedly crashes

**Solutions**:

**Step 1**: Check pod logs

```bash
kubectl logs -n infera pod/infera-management-api-xxxxx

# Check previous crashed pod
kubectl logs -n infera pod/infera-management-api-xxxxx --previous
```

**Step 2**: Verify ConfigMap

```bash
kubectl get configmap -n infera infera-config -o yaml
```

**Step 3**: Check secrets

```bash
kubectl get secret -n infera infera-secrets -o yaml
```

#### Issue: Service not accessible

**Error**: Connection timeout or refused

**Solutions**:

**Step 1**: Verify service

```bash
kubectl get svc -n infera

# Check endpoints
kubectl get endpoints -n infera infera-management-api
```

**Step 2**: Test from within cluster

```bash
kubectl run -it --rm debug --image=curlimages/curl --restart=Never -- \
  curl http://infera-management-api.infera.svc.cluster.local:3000/health
```

## Development & Testing

### Test Failures

#### Issue: Tests failing due to port conflicts

**Error**: `Address already in use` during tests

**Solution**:

```bash
# Use random ports for tests
cargo test -- --test-threads=1

# Or kill conflicting processes
pkill -f infera-management
```

#### Issue: Integration tests failing

**Error**: Storage-related test failures

**Solution**:

```bash
# Tests use in-memory backend by default
cargo test

# Run specific test suites
cargo test --lib  # Unit tests only
cargo test --test '*'  # Integration tests

# Check test output for specific errors
cargo test -- --nocapture
```

### Code Coverage Issues

#### Issue: Tarpaulin timeout

**Error**: `Test timed out after 300 seconds`

**Solution**:

```bash
# Increase timeout
cargo tarpaulin --timeout 600

# Or skip slow tests
cargo tarpaulin --exclude-files 'crates/*/tests/integration/*'
```

### Clippy Warnings

#### Issue: Clippy failing CI

**Error**: `error: this returns a Result<_, ()>  --deny warnings`

**Solution**:

```bash
# Fix all clippy warnings
cargo clippy --fix --allow-dirty --allow-staged

# Check without failing
cargo clippy -- -W clippy::all
```

## Email & Notifications

### Email Not Sending

#### Issue: Verification emails not received

**Solutions**:

**For development**: Check MailHog

```bash
# Open MailHog UI
open http://localhost:8025

# Check MailHog container
docker-compose ps mailhog
docker-compose logs mailhog
```

**For production**: Verify SMTP config

```yaml
# config.production.yaml
email:
  smtp_host: "smtp.gmail.com"
  smtp_port: 587
  smtp_use_tls: true
  smtp_username: "your-email@gmail.com"
  smtp_password: "your-app-password" # Not your real password!
```

**Test SMTP connection**:

```bash
# Test SMTP (Linux)
telnet smtp.gmail.com 587

# Or use curl
curl --url 'smtps://smtp.gmail.com:465' \
  --mail-from 'sender@example.com' \
  --mail-rcpt 'recipient@example.com' \
  --upload-file email.txt
```

## Getting Further Help

If these solutions don't resolve your issue:

1. **Check existing documentation**:

   - [Getting Started](GettingStarted.md)
   - [Deployment Guide](Deployment.md)
   - [API Examples](Examples.md)

2. **Enable debug logging**:

   ```yaml
   observability:
     log_level: "trace"
   ```

3. **Collect diagnostic information**:

   ```bash
   # System info
   uname -a
   rustc --version

   # API version
   ./target/release/inferadb-management --version

   # Configuration (redact secrets!)
   cat config.yaml | grep -v secret

   # Recent logs
   tail -n 100 /var/log/infera-management-api.log
   ```

4. **File an issue**:

   - Include diagnostic information above
   - Provide steps to reproduce
   - Note expected vs actual behavior
   - Link: [GitHub Issues](https://github.com/yourusername/inferadb/issues)

5. **Security issues**: Email <security@inferadb.com> (do not file public issues)
