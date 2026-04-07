# Audit Logs

The audit log API exposes immutable, per-organization event records from Ledger's append-only event system.

## Why It Matters

Audit logs provide the evidence trail for security compliance, incident response, and operational visibility. Every security-relevant action -- resource creation, modification, deletion, and access changes -- produces an immutable event record scoped to the organization where it occurred.

## Quickstart

Fetch the 50 most recent audit events for an organization:

```bash
curl -X GET "http://localhost:9090/control/v1/organizations/{org}/audit-logs" \
  -H "Cookie: infera_session={session_id}"
```

## Endpoint

```
GET /control/v1/organizations/{org}/audit-logs
```

Requires a valid JWT (local validation, no Ledger round-trip). The caller must be a member of the organization.

### Query Parameters

| Parameter    | Type    | Default | Description                                              |
| ------------ | ------- | ------- | -------------------------------------------------------- |
| `page_size`  | integer | 50      | Items per page, clamped to 1-100                         |
| `page_token` | string  | --      | Opaque cursor from a previous response's `next_page_token` |
| `event_type` | string  | --      | Filter by event type prefix (e.g., `ledger.vault`)       |
| `principal`  | string  | --      | Filter by principal (e.g., `user:42`)                    |
| `outcome`    | string  | --      | Filter by outcome: `success`, `failed`, or `denied`      |

When you pass a `page_token`, the server uses the filters encoded in the original query. Do not combine `page_token` with other filter parameters.

### Response

```json
{
  "entries": [
    {
      "event_id": "550e8400-e29b-41d4-a716-446655440000",
      "event_type": "ledger.vault.created",
      "principal": "user:42",
      "outcome": "success",
      "timestamp": "2025-11-18T10:30:00+00:00",
      "source": "control",
      "action": "vault_created",
      "details": {
        "vault": "Production Policies"
      }
    }
  ],
  "next_page_token": "eyJjdXJzb3IiOiAiMTIzNDU2Nzg5MCJ9",
  "total_estimate": 150
}
```

| Field             | Type     | Description                                                   |
| ----------------- | -------- | ------------------------------------------------------------- |
| `entries`         | array    | Audit log entries for the current page                        |
| `next_page_token` | string?  | Opaque token for the next page (absent when no more pages)    |
| `total_estimate`  | integer? | Approximate total matching entries (may be absent)            |

Both `next_page_token` and `total_estimate` are omitted from the JSON when null.

## Audit Log Entry Fields

| Field        | Type              | Description                                            |
| ------------ | ----------------- | ------------------------------------------------------ |
| `event_id`   | string (UUID)     | Unique event identifier                                |
| `event_type` | string            | Hierarchical event type (e.g., `ledger.vault.created`) |
| `principal`  | string            | Who performed the action (e.g., `user:42`)             |
| `outcome`    | string            | Result: `success`, `failed:{code}`, or `denied:{reason}` |
| `timestamp`  | string (RFC 3339) | When the event occurred (UTC)                          |
| `source`     | string            | Service that emitted the event (e.g., `control`)       |
| `action`     | string            | Machine-readable action name (e.g., `vault_created`)   |
| `details`    | object            | Key-value context; varies by event type                |

### Outcome Values

| Outcome           | Meaning                                 |
| ----------------- | --------------------------------------- |
| `success`         | Operation completed                     |
| `failed:{code}`   | Operation failed with the given code    |
| `denied:{reason}` | Operation denied with the given reason  |

## Pagination

Audit logs use cursor-based pagination. See [Pagination](pagination.md) for the full pattern.

1. Send an initial request with `page_size` and optional filters.
2. If `next_page_token` is present in the response, pass it as `page_token` in the next request.
3. When `next_page_token` is absent, you have reached the last page.

## Examples

Filter by event type prefix:

```bash
curl -X GET "http://localhost:9090/control/v1/organizations/{org}/audit-logs?event_type=ledger.vault" \
  -H "Cookie: infera_session={session_id}"
```

Filter by principal:

```bash
curl -X GET "http://localhost:9090/control/v1/organizations/{org}/audit-logs?principal=user:456" \
  -H "Cookie: infera_session={session_id}"
```

Combine filters:

```bash
curl -X GET "http://localhost:9090/control/v1/organizations/{org}/audit-logs?event_type=ledger.vault&outcome=success&page_size=100" \
  -H "Cookie: infera_session={session_id}"
```

Fetch the next page:

```bash
curl -X GET "http://localhost:9090/control/v1/organizations/{org}/audit-logs?page_token={next_page_token}" \
  -H "Cookie: infera_session={session_id}"
```

## Permissions

The handler calls `verify_org_membership_from_claims` before returning results. You must be a member of the organization to access its audit logs.

## Troubleshooting

**No audit logs returned**: Verify you are a member of the organization. Remove filters to confirm events exist. Check that the organization ID is correct.

**Missing `details` field**: The `details` map varies by event type. Some events have no additional context, producing an empty object.
