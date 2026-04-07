# Pagination

All list endpoints in InferaDB Control use cursor-based pagination with opaque page tokens.

## Why it matters

Cursor-based pagination provides stable traversal of large result sets regardless of concurrent modifications. Unlike offset-based pagination, cursors do not skip or duplicate items when data changes between requests.

## Quickstart

```bash
# First page (default: 50 items)
curl "http://localhost:9090/control/v1/organizations/{org}/vaults" \
  -H "Authorization: Bearer $TOKEN"

# Custom page size
curl "http://localhost:9090/control/v1/organizations/{org}/vaults?page_size=25" \
  -H "Authorization: Bearer $TOKEN"

# Next page using token from previous response
curl "http://localhost:9090/control/v1/organizations/{org}/vaults?page_token={next_page_token}" \
  -H "Authorization: Bearer $TOKEN"
```

## Query parameters

Every list endpoint accepts these query parameters:

| Parameter    | Type    | Default | Range | Description                            |
| ------------ | ------- | ------- | ----- | -------------------------------------- |
| `page_size`  | integer | 50      | 1-100 | Number of items per page               |
| `page_token` | string  | --      | --    | Opaque cursor from a previous response |

The server clamps `page_size` to the range 1-100. Values below 1 become 1. Values above 100 become 100. Omitting the parameter defaults to 50.

## Response shape

Every paginated response includes a `next_page_token` field alongside a resource-specific data array. The array key matches the resource type: `organizations`, `vaults`, `members`, `teams`, `invitations`, or `clients`.

| Field             | Type    | Description                                          |
| ----------------- | ------- | ---------------------------------------------------- |
| `next_page_token` | string? | Opaque cursor for the next page (absent = last page) |

The field is omitted from the JSON when null.

Example response (vaults):

```json
{
  "vaults": [{ "vault_id": "...", "name": "..." }],
  "next_page_token": "eyJjdXJzb3IiOiAiMTIzNDU2Nzg5MCJ9"
}
```

Audit log responses use `entries` as the array key and include an additional `total_estimate` field with an approximate total count:

```json
{
  "entries": [{ "event_id": "...", "event_type": "..." }],
  "next_page_token": "eyJjdXJzb3IiOiAiMTIzNDU2Nzg5MCJ9",
  "total_estimate": 150
}
```

## How it works

1. Send an initial request with `page_size` and optional filters.
2. The response includes `next_page_token` if more pages exist.
3. Pass `next_page_token` as `page_token` in the next request.
4. When `next_page_token` is absent, you have reached the last page.

The page token is a base64-encoded opaque cursor. Do not construct or modify tokens manually.

## Endpoints supporting pagination

| Endpoint                                          | Description              |
| ------------------------------------------------- | ------------------------ |
| `GET /control/v1/organizations`                   | User's organizations     |
| `GET /control/v1/organizations/{org}/vaults`      | Organization vaults      |
| `GET /control/v1/organizations/{org}/teams`       | Organization teams       |
| `GET /control/v1/organizations/{org}/members`     | Organization members     |
| `GET /control/v1/organizations/{org}/invitations` | Organization invitations |
| `GET /control/v1/users/me/invitations`            | Received invitations     |
| `GET /control/v1/organizations/{org}/audit-logs`  | Audit logs               |

All endpoints default to 50 items per page.

## Full traversal example

### Python

```python
import requests

def fetch_all_vaults(org_id: str, base_url: str, token: str) -> list:
    """Fetch all vaults for an organization."""
    vaults = []
    params = {"page_size": 100}

    while True:
        response = requests.get(
            f"{base_url}/control/v1/organizations/{org_id}/vaults",
            params=params,
            headers={"Authorization": f"Bearer {token}"},
        )
        response.raise_for_status()
        data = response.json()

        vaults.extend(data["vaults"])

        if not data.get("next_page_token"):
            break

        params = {"page_token": data["next_page_token"]}

    return vaults
```

### TypeScript

```typescript
async function* paginateVaults(
  orgId: string,
  token: string,
  pageSize = 50,
): AsyncGenerator<Vault[]> {
  let pageToken: string | undefined;

  while (true) {
    const params = new URLSearchParams({ page_size: String(pageSize) });
    if (pageToken) {
      params.set("page_token", pageToken);
    }

    const response = await fetch(
      `/control/v1/organizations/${orgId}/vaults?${params}`,
      { headers: { Authorization: `Bearer ${token}` } },
    );
    const page = await response.json();

    yield page.vaults;

    if (!page.next_page_token) break;
    pageToken = page.next_page_token;
  }
}

for await (const batch of paginateVaults("org-123", "your-token")) {
  processBatch(batch);
}
```

## Page size guidance

- **10-25**: UI pagination and incremental loading.
- **50** (default): General-purpose queries.
- **100**: Batch processing and data export.

## Troubleshooting

**Invalid page token**: Page tokens are tied to the query that produced them. Start a new query if a token is rejected.

**Duplicate items across pages**: This can occur if data changes between requests. Cursor-based pagination minimizes this compared to offset-based pagination, but it is not fully eliminated under concurrent writes.
