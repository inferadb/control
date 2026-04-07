# Pagination

All list endpoints in InferaDB Control support cursor-based pagination for efficient data retrieval.

## Overview

Pagination allows clients to retrieve large result sets in manageable chunks, reducing memory usage and network overhead. The API uses **cursor-based pagination** with `page_size` and `page_token` query parameters.

## Query Parameters

All list endpoints accept these optional query parameters:

| Parameter    | Type    | Default | Range | Description                                           |
| ------------ | ------- | ------- | ----- | ----------------------------------------------------- |
| `page_size`  | integer | 50      | 1-100 | Number of items to return per page                    |
| `page_token` | string  | --      | --    | Opaque cursor for the next page (from previous response) |

### Examples

```bash
# Get first page (default: 50 items)
GET /control/v1/organizations/{org}/vaults

# Get 25 items per page
GET /control/v1/organizations/{org}/vaults?page_size=25

# Get next page using token from previous response
GET /control/v1/organizations/{org}/vaults?page_token={next_page_token}
```

## How Cursor-Based Pagination Works

1. Make an initial request with `page_size` (and optional filters)
2. The response includes a `next_page_token` if more pages exist
3. Pass `next_page_token` as `page_token` in the next request
4. When `next_page_token` is absent or null, you have reached the last page

The page token is an opaque base64-encoded cursor. Do not construct or modify page tokens manually.

## Response Format

Response format varies by endpoint. For audit logs, the response uses:

```json
{
  "entries": [
    { "event_id": "...", "event_type": "..." }
  ],
  "next_page_token": "eyJjdXJzb3IiOiAiMTIzNDU2Nzg5MCJ9",
  "total_estimate": 150
}
```

Other endpoints may use different field names for the data array. Check the OpenAPI specification for each endpoint's response schema.

### Pagination Fields

| Field             | Type     | Description                                                  |
| ----------------- | -------- | ------------------------------------------------------------ |
| `next_page_token` | string?  | Opaque cursor for the next page (null/absent = last page)    |
| `total_estimate`  | integer? | Approximate total count (may be omitted for performance)     |

## Best Practices

### 1. Use Appropriate Page Sizes

```bash
# Good: balanced performance
GET /control/v1/organizations/{org}/vaults?page_size=50

# Large batch: fewer requests, higher memory
GET /control/v1/organizations/{org}/vaults?page_size=100
```

**Recommendations**:

- Default (50): Good for most use cases
- Small (10-25): UI pagination, incremental loading
- Large (100): Batch processing, data export

### 2. Implement Robust Pagination Logic

```typescript
async function fetchAllVaults(orgId: string): Promise<Vault[]> {
  const allVaults: Vault[] = [];
  let pageToken: string | undefined;

  while (true) {
    const params = new URLSearchParams({ page_size: "100" });
    if (pageToken) {
      params.set("page_token", pageToken);
    }

    const response = await fetch(
      `/control/v1/organizations/${orgId}/vaults?${params}`,
    );
    const result = await response.json();

    allVaults.push(...result.entries);

    if (!result.next_page_token) {
      break;
    }

    pageToken = result.next_page_token;
  }

  return allVaults;
}
```

### 3. Handle Edge Cases

```typescript
function handlePaginatedResponse(response: any) {
  // Empty result set
  if (response.entries.length === 0) {
    console.log("No results found");
    return;
  }

  // More pages available
  if (response.next_page_token) {
    fetchNextPage(response.next_page_token);
  }
}
```

## Page Size Clamping

The `page_size` parameter is clamped to the range 1-100 by the server:

- Values below 1 are clamped to 1
- Values above 100 are clamped to 100
- If omitted, defaults to 50

## Endpoints Supporting Pagination

All list endpoints support cursor-based pagination:

| Endpoint                                             | Default Page Size | Notes                |
| ---------------------------------------------------- | ----------------- | -------------------- |
| `GET /control/v1/organizations`                      | 50                | User's organizations |
| `GET /control/v1/organizations/{org}/vaults`         | 50                | Organization vaults  |
| `GET /control/v1/organizations/{org}/teams`          | 50                | Organization teams   |
| `GET /control/v1/organizations/{org}/clients`        | 50                | OAuth clients        |
| `GET /control/v1/organizations/{org}/audit-logs`     | 50                | Audit logs           |
| `GET /control/v1/organizations/{org}/teams/{team}/members` | 50          | Team members         |

## Examples

### Python

```python
import requests

def get_all_vaults(org_id: str, api_url: str) -> list:
    """Fetch all vaults for an organization with cursor-based pagination."""
    vaults = []
    page_token = None

    while True:
        params = {"page_size": 100}
        if page_token:
            params["page_token"] = page_token

        response = requests.get(
            f"{api_url}/control/v1/organizations/{org_id}/vaults",
            params=params
        )
        response.raise_for_status()
        data = response.json()

        vaults.extend(data["entries"])

        if not data.get("next_page_token"):
            break

        page_token = data["next_page_token"]

    return vaults
```

### TypeScript

```typescript
async function* fetchVaultsPaginated(
  orgId: string,
  pageSize: number = 50,
): AsyncGenerator<Vault[]> {
  let pageToken: string | undefined;

  while (true) {
    const params = new URLSearchParams({ page_size: String(pageSize) });
    if (pageToken) {
      params.set("page_token", pageToken);
    }

    const response = await fetch(
      `/control/v1/organizations/${orgId}/vaults?${params}`,
    );
    const page = await response.json();

    yield page.entries;

    if (!page.next_page_token) {
      break;
    }

    pageToken = page.next_page_token;
  }
}

// Usage
for await (const vaults of fetchVaultsPaginated("org-123")) {
  console.log(`Processing ${vaults.length} vaults...`);
  processVaults(vaults);
}
```

### Go

```go
type PaginatedResponse[T any] struct {
    Entries       []T     `json:"entries"`
    NextPageToken *string `json:"next_page_token,omitempty"`
    TotalEstimate *int    `json:"total_estimate,omitempty"`
}

func FetchAllVaults(orgID string) ([]Vault, error) {
    var allVaults []Vault
    var pageToken string

    for {
        url := fmt.Sprintf(
            "/control/v1/organizations/%s/vaults?page_size=100",
            orgID,
        )
        if pageToken != "" {
            url += "&page_token=" + pageToken
        }

        resp, err := http.Get(url)
        if err != nil {
            return nil, err
        }
        defer resp.Body.Close()

        var page PaginatedResponse[Vault]
        if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
            return nil, err
        }

        allVaults = append(allVaults, page.Entries...)

        if page.NextPageToken == nil {
            break
        }

        pageToken = *page.NextPageToken
    }

    return allVaults, nil
}
```

## Troubleshooting

### Issue: Invalid page token

**Cause**: The page token is malformed, expired, or from a different query.

**Solution**: Page tokens are opaque and should only be used from the response that generated them. Start a new query from the beginning if a token fails.

### Issue: Duplicate items across pages

**Cause**: Data modified between requests (items added/deleted).

**Solution**: Use filters to maintain consistency. Cursor-based pagination is more resilient to concurrent modifications than offset-based pagination.

## See Also

- [openapi.yaml](../openapi.yaml): Complete API specifications with pagination examples
- [Architecture](architecture.md): Pagination implementation architecture
- [Performance](performance.md): Pagination performance benchmarks
