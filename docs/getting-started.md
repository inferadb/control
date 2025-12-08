# Getting Started

This tutorial walks you through setting up and using the InferaDB Management API from scratch.

## Prerequisites

- **Rust** 1.85+ (install via [rustup](https://rustup.rs/))
- **curl** or similar HTTP client

**Note**: This guide uses the in-memory storage backend for quick setup. FoundationDB backend is planned for future multi-instance production deployments but is not yet implemented.

## Installation

### 1. Build the Management API

```bash
# Clone repository
git clone https://github.com/yourusername/inferadb.git
cd inferadb/management

# Build the project
cargo build --release

# Verify build
./target/release/inferadb-management --version
```

### 2. Configure the API

Create a development configuration file:

```bash
cp config.yaml config.local.yaml
```

Edit `config.local.yaml` to match your environment:

```yaml
server:
  # Combined address strings (host:port)
  public_rest: "127.0.0.1:9090"
  public_grpc: "127.0.0.1:9091"
  private_rest: "0.0.0.0:9092"  # Internal API for server-to-server

storage:
  backend: "memory" # Use in-memory backend for development

auth:
  key_encryption_secret: "dev-secret-key-at-least-32-bytes-long-for-aes256"

observability:
  log_level: "debug"
```

**Security Note**: Never commit `config.local.yaml` to version control. It's already in `.gitignore`.

### 3. Start the API Server

```bash
# Run with local config
./target/release/inferadb-management --config config.local.yaml
```

You should see output like:

```text
2025-11-18T10:00:00.000Z INFO  Starting InferaDB Management API
2025-11-18T10:00:00.123Z INFO  Public REST server listening on 127.0.0.1:9090
2025-11-18T10:00:00.234Z INFO  Public gRPC server listening on 127.0.0.1:9091
2025-11-18T10:00:00.456Z INFO  Internal REST server listening on 0.0.0.0:9092
```

## Quick Start Tutorial

### Step 1: Register a User

Create your first user account:

```bash
curl -X POST http://localhost:9090/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "password": "SecurePass123!",
    "name": "Alice"
  }'
```

Response:

```json
{
  "user": {
    "id": 1234567890123456789,
    "name": "Alice",
    "created_at": "2025-11-18T10:05:00Z"
  },
  "session_id": "sess_abc123...",
  "message": "Registration successful. Please verify your email."
}
```

**Save the session_id** - you'll need it for authenticated requests.

### Step 2: Login

Login with your credentials:

```bash
curl -X POST http://localhost:9090/v1/auth/login/password \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "password": "SecurePass123!"
  }'
```

Response:

```json
{
  "session_id": "sess_xyz789...",
  "user": {
    "id": 1234567890123456789,
    "name": "Alice"
  }
}
```

### Step 3: Create an Organization

Organizations are the top-level container for all resources:

```bash
curl -X POST http://localhost:9090/v1/organizations \
  -H "Cookie: infera_session=sess_xyz789..." \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Acme Corp",
    "display_name": "Acme Corporation"
  }'
```

Response:

```json
{
  "id": 9876543210987654321,
  "name": "acme-corp",
  "display_name": "Acme Corporation",
  "created_at": "2025-11-18T10:10:00Z",
  "role": "owner"
}
```

**Save the organization ID** (`9876543210987654321`) - you'll use it in subsequent requests.

### Step 4: Create a Vault

Vaults store your authorization policies:

```bash
curl -X POST http://localhost:9090/v1/organizations/9876543210987654321/vaults \
  -H "Cookie: infera_session=sess_xyz789..." \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production Policies",
    "description": "Authorization policies for production environment"
  }'
```

Response:

```json
{
  "id": 1111222233334444555,
  "organization_id": 9876543210987654321,
  "name": "Production Policies",
  "description": "Authorization policies for production environment",
  "created_at": "2025-11-18T10:15:00Z"
}
```

**Save the vault ID** (`1111222233334444555`).

### Step 5: Generate a Vault Token

Vault tokens are JWTs used to authorize requests to the InferaDB policy engine:

```bash
curl -X POST http://localhost:9090/v1/organizations/9876543210987654321/vaults/1111222233334444555/tokens \
  -H "Cookie: infera_session=sess_xyz789..."
```

Response:

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "refresh_abc123...",
  "expires_in": 3600,
  "token_type": "Bearer"
}
```

**Save the access_token** - this is what your application will use to make authorization decisions.

### Step 6: Use the Vault Token

Now you can use the vault token to make authorization requests to the InferaDB policy engine:

```bash
# Example: Check if user can read a document
curl -X POST http://localhost:8080/v1/authorize \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "user:alice",
    "action": "read",
    "resource": "document:123"
  }'
```

## Common Workflows

### Creating a Team

Teams help you organize users and manage permissions:

```bash
# 1. Create a team
curl -X POST http://localhost:9090/v1/organizations/9876543210987654321/teams \
  -H "Cookie: infera_session=sess_xyz789..." \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Engineering",
    "description": "Engineering team"
  }'

# Response: {"id": 7777888899990000111, ...}

# 2. Invite a team member
curl -X POST http://localhost:9090/v1/teams/7777888899990000111/members \
  -H "Cookie: infera_session=sess_xyz789..." \
  -H "Content-Type: application/json" \
  -d '{
    "email": "bob@example.com",
    "role": "member"
  }'

# 3. Grant team access to vault
curl -X POST http://localhost:9090/v1/organizations/9876543210987654321/vaults/1111222233334444555/team-grants \
  -H "Cookie: infera_session=sess_xyz789..." \
  -H "Content-Type: application/json" \
  -d '{
    "team_id": 7777888899990000111,
    "access_level": "read_write"
  }'
```

### Creating an OAuth Client

OAuth clients allow applications to obtain vault tokens:

```bash
# 1. Create a client
curl -X POST http://localhost:9090/v1/organizations/9876543210987654321/clients \
  -H "Cookie: infera_session=sess_xyz789..." \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production API",
    "grant_types": ["client_credentials"],
    "vault_ids": [1111222233334444555]
  }'

# Response: {"client_id": "client_abc123", "client_secret": "secret_xyz789", ...}

# 2. Obtain token using client credentials
curl -X POST http://localhost:9090/v1/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'grant_type=client_credentials&client_id=client_abc123&client_secret=secret_xyz789&scope=vault:1111222233334444555'

# Response: {"access_token": "eyJ...", "expires_in": 3600, ...}
```

### Viewing Audit Logs

Review security events:

```bash
# Get recent audit logs
curl -X GET "http://localhost:9090/v1/organizations/9876543210987654321/audit-logs?limit=25" \
  -H "Cookie: infera_session=sess_xyz789..."

# Filter by event type
curl -X GET "http://localhost:9090/v1/organizations/9876543210987654321/audit-logs?event_type=vault_token_generated" \
  -H "Cookie: infera_session=sess_xyz789..."
```

## Development Tips

### Using Environment Variables

Override config values with environment variables (use `INFERADB_MGMT__` prefix with double underscores as separators):

```bash
export INFERADB_MGMT__SERVER__PUBLIC_REST="127.0.0.1:8080"
export INFERADB_MGMT__OBSERVABILITY__LOG_LEVEL=debug
export INFERADB_MGMT__AUTH__KEY_ENCRYPTION_SECRET="your-secret-key"

./target/release/inferadb-management
```

### Running Tests

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_user_registration

# Run with output
cargo test -- --nocapture

# Run with nextest (faster)
cargo nextest run
```

### Generating API Documentation

```bash
# Generate and open Rust docs
cargo doc --open

# View OpenAPI spec
open http://localhost:9090/openapi.yaml
```

### Debugging

Enable debug logging:

```yaml
# config.local.yaml
observability:
  log_level: "debug" # or "trace" for maximum detail
```

View structured logs:

```bash
# Pretty-print JSON logs
./target/release/inferadb-management-api | jq

# Filter for errors
./target/release/inferadb-management-api | jq 'select(.level == "ERROR")'
```

### Resetting the Database

If you need to start fresh with the in-memory backend:

```bash
# Stop the API server (Ctrl+C)

# Restart the API server (in-memory data is automatically cleared on restart)
./target/release/inferadb-management --config config.local.yaml
```

**Note**: The in-memory backend stores all data in RAM. Restarting the server clears all data.

## Next Steps

Now that you have the basics working, explore:

- **[Authentication](authentication.md)**: Deep dive into auth flows and session management
- **[Entities](overview.md)**: Complete data model reference
- **[API Examples](examples.md)**: Real-world integration examples
- **[Deployment](deployment.md)**: Production deployment guide
- **[Audit Logs](audit-logs.md)**: Security audit trail and compliance

## Troubleshooting

### Storage backend issues

**Note**: This guide uses the in-memory backend. FoundationDB backend is not yet implemented.

**Error**: `Failed to initialize storage backend`

**Solutions**:

1. Verify `config.local.yaml` has `backend: "memory"` in the storage section
2. Check that you have sufficient memory available (at least 1GB free)
3. Review error logs for specific issues

### Port already in use

**Error**: `Address already in use (os error 48)`

**Solutions**:

1. Change port in config: `public_rest: "127.0.0.1:8080"`
2. Find and stop conflicting process: `lsof -i :9090`
3. Use environment variable: `export INFERADB_MGMT__SERVER__PUBLIC_REST="127.0.0.1:8080"`

### Key encryption secret too short

**Error**: `Key encryption secret must be at least 32 bytes`

**Solution**: Generate a proper secret:

```bash
# Generate random 32-byte secret
openssl rand -base64 32

# Add to config
key_encryption_secret: "generated-secret-here"
```

### Session cookie not working

**Issue**: Requests return 401 Unauthorized

**Solutions**:

1. Check cookie format: `-H "Cookie: infera_session=sess_xyz789..."`
2. Verify session hasn't expired (default: 30 days)
3. Check for typos in session ID
4. Login again to get fresh session

### Rate limit exceeded

**Error**: `429 Too Many Requests`

**Solutions**:

1. Wait before retrying (exponential backoff recommended)
2. Reduce request frequency
3. Check rate limiting config in `config.local.yaml`
4. For testing, adjust limits in config:

```yaml
rate_limiting:
  login_attempts_per_ip_per_hour: 1000 # Increase for testing
```

## Getting Help

- **Documentation**: [docs/](.)
- **OpenAPI Spec**: [openapi.yaml](../openapi.yaml)
- **Examples**: [examples.md](examples.md)
- **Issues**: [GitHub Issues](https://github.com/yourusername/inferadb/issues)

## Security Checklist

Before deploying to production, review:

- [ ] Changed all default secrets and passwords
- [ ] Using HTTPS (TLS) for all connections
- [ ] Configured firewall rules (only expose necessary ports)
- [ ] Set up monitoring and alerting
- [ ] Configured audit log retention
- [ ] Reviewed rate limiting settings
- [ ] Enabled OpenTelemetry tracing
- [ ] Documented data persistence strategy (in-memory backend loses data on restart)
- [ ] Tested disaster recovery procedures

See [Deployment Guide](deployment.md) for complete production deployment guide.
