# Audit Logs

The InferaDB Control provides comprehensive audit logging for security compliance, incident response, and operational visibility.

## Overview

Audit logs capture all security-relevant events including:

- Authentication and authorization events
- Resource creation, modification, and deletion
- Permission changes and access grants
- Security incidents (token reuse, rate limiting, etc.)

**Key characteristics**:

- **Immutable**: Audit logs cannot be modified or deleted by users
- **Per-organization**: Each organization can only view its own audit logs
- **Indexed**: Optimized for time-range and event-type queries
- **Retention**: 90 days (free tier), 1 year (paid tier)

## Audit Event Types

### Authentication Events

| Event Type             | Description               | Severity |
| ---------------------- | ------------------------- | -------- |
| `user_login`           | Successful user login     | Info     |
| `user_logout`          | User logout               | Info     |
| `user_session_revoked` | Session manually revoked  | Warning  |
| `user_session_expired` | Session expired naturally | Info     |

### Passkey Events

| Event Type        | Description            | Severity |
| ----------------- | ---------------------- | -------- |
| `passkey_added`   | New passkey registered | Info     |
| `passkey_removed` | Passkey deleted        | Warning  |

### Password Events

| Event Type                 | Description               | Severity |
| -------------------------- | ------------------------- | -------- |
| `password_changed`         | Password updated          | Info     |
| `password_reset_requested` | Password reset email sent | Info     |
| `password_reset_completed` | Password reset completed  | Warning  |

### User Management

| Event Type            | Description                    | Severity |
| --------------------- | ------------------------------ | -------- |
| `user_registered`     | New user account created       | Info     |
| `user_deleted`        | User account deleted           | Critical |
| `user_email_added`    | Email address added to account | Info     |
| `user_email_verified` | Email address verified         | Info     |
| `user_email_removed`  | Email address removed          | Warning  |

### Organization Management

| Event Type                           | Description                           | Severity |
| ------------------------------------ | ------------------------------------- | -------- |
| `organization_created`               | New organization created              | Info     |
| `organization_updated`               | Organization settings changed         | Info     |
| `organization_deleted`               | Organization deleted                  | Critical |
| `organization_member_added`          | Member invited to organization        | Info     |
| `organization_member_role_changed`   | Member role updated                   | Warning  |
| `organization_member_removed`        | Member removed from organization      | Warning  |
| `organization_ownership_transferred` | Ownership transferred to another user | Critical |

### Team Management

| Event Type                 | Description                  | Severity |
| -------------------------- | ---------------------------- | -------- |
| `team_created`             | New team created             | Info     |
| `team_updated`             | Team settings changed        | Info     |
| `team_deleted`             | Team deleted                 | Warning  |
| `team_member_added`        | Member added to team         | Info     |
| `team_member_role_changed` | Team member role updated     | Warning  |
| `team_member_removed`      | Member removed from team     | Warning  |
| `team_permission_granted`  | Permission granted to team   | Warning  |
| `team_permission_revoked`  | Permission revoked from team | Warning  |

### Vault Management

| Event Type                  | Description                  | Severity |
| --------------------------- | ---------------------------- | -------- |
| `vault_created`             | New vault created            | Info     |
| `vault_updated`             | Vault settings changed       | Info     |
| `vault_deleted`             | Vault deleted                | Critical |
| `vault_access_granted`      | User granted access to vault | Warning  |
| `vault_access_revoked`      | User access revoked          | Warning  |
| `vault_access_updated`      | User access level changed    | Warning  |
| `vault_team_access_granted` | Team granted access to vault | Warning  |
| `vault_team_access_revoked` | Team access revoked          | Warning  |
| `vault_team_access_updated` | Team access level changed    | Warning  |

### Client Management

| Event Type                   | Description               | Severity |
| ---------------------------- | ------------------------- | -------- |
| `client_created`             | OAuth client created      | Info     |
| `client_updated`             | Client settings changed   | Info     |
| `client_deleted`             | Client deleted            | Warning  |
| `client_certificate_created` | Client certificate issued | Info     |
| `client_certificate_revoked` | Certificate revoked       | Warning  |
| `client_certificate_deleted` | Certificate deleted       | Warning  |

### Token Events

| Event Type              | Description           | Severity |
| ----------------------- | --------------------- | -------- |
| `vault_token_generated` | Vault JWT generated   | Info     |
| `vault_token_refreshed` | Vault JWT refreshed   | Info     |
| `refresh_token_revoked` | Refresh token revoked | Warning  |

### Security Events

| Event Type             | Description                        | Severity |
| ---------------------- | ---------------------------------- | -------- |
| `refresh_token_reused` | **SECURITY**: Token reuse detected | Critical |
| `invalid_jwt`          | Invalid JWT signature detected     | Warning  |
| `rate_limit_exceeded`  | Rate limit exceeded                | Warning  |
| `clock_skew_detected`  | System clock skew detected         | Warning  |
| `worker_id_collision`  | Snowflake ID worker collision      | Critical |

## Audit Log Structure

Each audit log entry contains:

```json
{
  "id": 1234567890123456789,
  "organization_id": 123,
  "user_id": 456,
  "client_id": null,
  "event_type": "vault_access_granted",
  "resource_type": "vault_grant",
  "resource_id": 789,
  "event_data": {
    "vault_id": 100,
    "vault_name": "Production Policies",
    "granted_to_user_id": 999,
    "granted_to_user_email": "alice@example.com",
    "access_level": "read_write"
  },
  "ip_address": "203.0.113.42",
  "user_agent": "Mozilla/5.0 ...",
  "created_at": "2025-11-18T10:30:00Z"
}
```

### Field Descriptions

| Field             | Type      | Description                                       |
| ----------------- | --------- | ------------------------------------------------- |
| `id`              | integer   | Unique Snowflake ID                               |
| `organization_id` | integer?  | Organization context (null for user-level events) |
| `user_id`         | integer?  | User who performed the action                     |
| `client_id`       | integer?  | OAuth client that performed the action            |
| `event_type`      | enum      | Type of event (see tables above)                  |
| `resource_type`   | enum?     | Type of resource affected                         |
| `resource_id`     | integer?  | ID of affected resource                           |
| `event_data`      | object?   | Additional structured event data                  |
| `ip_address`      | string?   | Client IP address                                 |
| `user_agent`      | string?   | HTTP User-Agent header                            |
| `created_at`      | timestamp | When the event occurred (UTC)                     |

## Querying Audit Logs

### List Organization Audit Logs

```bash
GET /v1/organizations/{org}/audit-logs
```

Query parameters:

- `limit` (integer): Page size (default: 50, max: 100)
- `offset` (integer): Offset for pagination (default: 0)
- `event_type` (string): Filter by event type (optional)
- `user_id` (integer): Filter by user (optional)
- `start_date` (ISO 8601): Filter events after this date (optional)
- `end_date` (ISO 8601): Filter events before this date (optional)

### Examples

**Get recent audit logs**:

```bash
curl -X GET "http://localhost:9090/v1/organizations/{org}/audit-logs?limit=50" \
  -H "Cookie: infera_session={session_id}"
```

**Filter by event type**:

```bash
curl -X GET "http://localhost:9090/v1/organizations/{org}/audit-logs?event_type=vault_access_granted" \
  -H "Cookie: infera_session={session_id}"
```

**Filter by user**:

```bash
curl -X GET "http://localhost:9090/v1/organizations/{org}/audit-logs?user_id=456" \
  -H "Cookie: infera_session={session_id}"
```

**Filter by date range**:

```bash
curl -X GET "http://localhost:9090/v1/organizations/{org}/audit-logs?start_date=2025-11-01T00:00:00Z&end_date=2025-11-18T23:59:59Z" \
  -H "Cookie: infera_session={session_id}"
```

**Combine filters**:

```bash
curl -X GET "http://localhost:9090/v1/organizations/{org}/audit-logs?event_type=user_login&start_date=2025-11-01T00:00:00Z&limit=100" \
  -H "Cookie: infera_session={session_id}"
```

## Response Format

Audit log responses use streaming pagination (no total count for performance):

```json
{
  "data": [
    {
      "id": 1234567890123456789,
      "organization_id": 123,
      "user_id": 456,
      "event_type": "vault_access_granted",
      "resource_type": "vault_grant",
      "resource_id": 789,
      "event_data": {
        "vault_name": "Production Policies",
        "granted_to_user_email": "alice@example.com"
      },
      "ip_address": "203.0.113.42",
      "created_at": "2025-11-18T10:30:00Z"
    }
  ],
  "pagination": {
    "count": 50,
    "offset": 0,
    "limit": 50,
    "has_more": true
  }
}
```

**Note**: The `total` field is omitted for audit logs due to the large data volume. Use `has_more` to determine if additional pages exist.

## Common Use Cases

### 1. Security Incident Investigation

Investigate suspicious login activity:

```bash
# Find all failed login attempts in the last 24 hours
curl -X GET "http://localhost:9090/v1/organizations/{org}/audit-logs?event_type=user_login&start_date=$(date -u -v-1d +%Y-%m-%dT%H:%M:%SZ)" \
  -H "Cookie: infera_session={session_id}"
```

### 2. Access Audit

Review vault access grants:

```bash
# List all vault access grants this month
curl -X GET "http://localhost:9090/v1/organizations/{org}/audit-logs?event_type=vault_access_granted&start_date=2025-11-01T00:00:00Z" \
  -H "Cookie: infera_session={session_id}"
```

### 3. User Activity Tracking

Track a specific user's activity:

```bash
# Get all actions by user 456
curl -X GET "http://localhost:9090/v1/organizations/{org}/audit-logs?user_id=456&limit=100" \
  -H "Cookie: infera_session={session_id}"
```

### 4. Compliance Reporting

Export audit logs for compliance:

```python
import requests
from datetime import datetime, timedelta

def export_audit_logs(org_id: str, start_date: datetime, end_date: datetime):
    """Export all audit logs for a date range."""
    logs = []
    offset = 0
    limit = 100

    while True:
        response = requests.get(
            f"http://localhost:9090/v1/organizations/{org_id}/audit-logs",
            params={
                "limit": limit,
                "offset": offset,
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
            },
            cookies={"infera_session": session_id}
        )
        response.raise_for_status()
        data = response.json()

        logs.extend(data["data"])

        if not data["pagination"]["has_more"]:
            break

        offset += limit

    return logs

# Export last month's logs
end_date = datetime.utcnow()
start_date = end_date - timedelta(days=30)
logs = export_audit_logs("org-123", start_date, end_date)

# Save to file
import json
with open("audit_logs.json", "w") as f:
    json.dump(logs, f, indent=2)
```

### 5. Real-Time Monitoring

Monitor for critical security events:

```python
import requests
import time
from datetime import datetime

def monitor_security_events(org_id: str, poll_interval: int = 60):
    """Monitor for critical security events in real-time."""
    critical_events = [
        "refresh_token_reused",
        "worker_id_collision",
        "organization_deleted",
        "vault_deleted",
    ]

    last_check = datetime.utcnow()

    while True:
        for event_type in critical_events:
            response = requests.get(
                f"http://localhost:9090/v1/organizations/{org_id}/audit-logs",
                params={
                    "event_type": event_type,
                    "start_date": last_check.isoformat(),
                    "limit": 100,
                },
                cookies={"infera_session": session_id}
            )

            data = response.json()
            if data["data"]:
                print(f"⚠️  CRITICAL: {len(data['data'])} {event_type} events detected!")
                for log in data["data"]:
                    send_alert(log)

        last_check = datetime.utcnow()
        time.sleep(poll_interval)
```

## Permissions

Audit log access is controlled by organization roles:

| Role       | Access                                     |
| ---------- | ------------------------------------------ |
| **Owner**  | Full access to all organization audit logs |
| **Admin**  | Full access to all organization audit logs |
| **Member** | No access (audit logs are admin-only)      |
| **Viewer** | No access                                  |

**Note**: Users can only view audit logs for organizations where they have Owner or Admin role.

## Data Retention

| Tier           | Retention Period | Notes                                |
| -------------- | ---------------- | ------------------------------------ |
| **Free**       | 90 days          | Automatically deleted after 90 days  |
| **Paid**       | 1 year           | Automatically deleted after 365 days |
| **Enterprise** | Configurable     | Custom retention policies available  |

**Important**: Audit logs are never deleted when organizations or resources are deleted. They are retained for the full retention period for compliance purposes.

## Performance Considerations

### 1. Use Time-Range Filters

Audit logs grow large over time. Always use time-range filters for better performance:

```bash
# Good: Time-bounded query
GET /v1/organizations/{org}/audit-logs?start_date=2025-11-01T00:00:00Z&end_date=2025-11-18T23:59:59Z

# Slower: Open-ended query
GET /v1/organizations/{org}/audit-logs
```

### 2. Combine Filters

Use multiple filters to reduce result sets:

```bash
# Good: Filtered query
GET /v1/organizations/{org}/audit-logs?event_type=vault_access_granted&user_id=456&start_date=2025-11-01T00:00:00Z

# Slower: Broad query
GET /v1/organizations/{org}/audit-logs?start_date=2025-11-01T00:00:00Z
```

### 3. Use Appropriate Page Sizes

```bash
# UI pagination: smaller pages
GET /v1/organizations/{org}/audit-logs?limit=25

# Batch export: larger pages
GET /v1/organizations/{org}/audit-logs?limit=100
```

### 4. Avoid Large Offsets

For very large result sets, avoid deep pagination:

```bash
# Inefficient for large datasets
GET /v1/organizations/{org}/audit-logs?offset=10000&limit=50
```

Instead, use narrower time ranges or export data in batches during off-peak hours.

## Security Best Practices

### 1. Regular Audits

Schedule regular reviews of audit logs:

```bash
# Weekly security review
./scripts/weekly-audit-review.sh

# Monthly compliance export
./scripts/monthly-compliance-export.sh
```

### 2. Alert on Critical Events

Set up monitoring for critical security events:

- `refresh_token_reused`: Possible token theft
- `worker_id_collision`: ID generation issue
- `organization_deleted`: Accidental or malicious deletion
- `rate_limit_exceeded`: Possible abuse

### 3. Export for Long-Term Storage

Export audit logs to external systems for long-term retention:

```python
# Daily export to S3
python scripts/export_audit_logs.py --days 1 --output s3://bucket/audit-logs/
```

### 4. Correlate with Application Logs

Cross-reference audit logs with application logs for complete incident investigation:

```bash
# Find application logs around suspicious event
grep "2025-11-18T10:30" /var/log/inferadb-control-api.log
```

## Integration Examples

### Splunk

```python
import requests
import json

def send_to_splunk(audit_log: dict):
    """Send audit log to Splunk HEC endpoint."""
    event = {
        "sourcetype": "infera:audit_log",
        "event": audit_log,
    }

    response = requests.post(
        "https://splunk.example.com:8088/services/collector/event",
        headers={
            "Authorization": f"Splunk {HEC_TOKEN}",
        },
        json=event,
    )
    response.raise_for_status()
```

### Elasticsearch

```python
from elasticsearch import Elasticsearch

es = Elasticsearch(["http://localhost:9200"])

def index_audit_log(audit_log: dict):
    """Index audit log in Elasticsearch."""
    es.index(
        index="infera-audit-logs",
        id=audit_log["id"],
        body=audit_log,
    )
```

### Datadog

```python
from datadog import api, initialize

initialize(api_key=DD_API_KEY, app_key=DD_APP_KEY)

def send_to_datadog(audit_log: dict):
    """Send audit log to Datadog as custom event."""
    api.Event.create(
        title=f"Audit: {audit_log['event_type']}",
        text=json.dumps(audit_log),
        tags=[
            f"org_id:{audit_log['organization_id']}",
            f"event_type:{audit_log['event_type']}",
        ],
    )
```

## Troubleshooting

### Issue: No audit logs returned

**Cause**: Time filter excludes all events, or user lacks permissions.

**Solution**:

1. Verify you have Owner or Admin role
2. Expand time range: `start_date=2025-01-01T00:00:00Z`
3. Remove event type filter to see all events

### Issue: Query timeout

**Cause**: Querying very large date range without filters.

**Solution**:

1. Add time-range filters (limit to 30-90 days)
2. Add event type or user filters
3. Reduce page size: `limit=25`

### Issue: Missing event_data field

**Cause**: Some events don't have additional structured data.

**Solution**: Check event type documentation. Not all events include `event_data`.

## See Also

- [openapi.yaml](../openapi.yaml): Complete audit log API specifications
- [Architecture](architecture.md): Audit logging architecture
- [Pagination](pagination.md): Pagination best practices
- [Overview](overview.md): Entity relationships and event types
