# Pagination

All list endpoints in the InferaDB Management API support offset-based pagination for efficient data retrieval.

## Overview

Pagination allows clients to retrieve large result sets in manageable chunks, reducing memory usage and network overhead. The API uses **offset-based pagination** with `limit` and `offset` query parameters.

## Query Parameters

All list endpoints accept these optional query parameters:

| Parameter | Type    | Default | Range | Description                                      |
| --------- | ------- | ------- | ----- | ------------------------------------------------ |
| `limit`   | integer | 50      | 1-100 | Number of items to return per page               |
| `offset`  | integer | 0       | 0+    | Number of items to skip before returning results |

### Examples

```bash
# Get first page (default: 50 items)
GET /v1/organizations/{org}/vaults

# Get 25 items per page
GET /v1/organizations/{org}/vaults?limit=25

# Get second page (skip first 50 items)
GET /v1/organizations/{org}/vaults?limit=50&offset=50

# Get third page with 25 items per page
GET /v1/organizations/{org}/vaults?limit=25&offset=50
```

## Response Format

All paginated responses include a `pagination` metadata object:

```json
{
  "data": [
    { "id": 1, "name": "Vault 1" },
    { "id": 2, "name": "Vault 2" }
  ],
  "pagination": {
    "total": 150,
    "count": 2,
    "offset": 0,
    "limit": 50,
    "has_more": true
  }
}
```

### Pagination Metadata Fields

| Field      | Type     | Description                                            |
| ---------- | -------- | ------------------------------------------------------ |
| `total`    | integer? | Total number of items (may be omitted for performance) |
| `count`    | integer  | Number of items in current page                        |
| `offset`   | integer  | Current offset value                                   |
| `limit`    | integer  | Current limit value                                    |
| `has_more` | boolean  | Whether more items are available                       |

## Pagination Modes

The API supports two pagination modes:

### 1. Count-Based Pagination (Default)

When `total` is present in the response, the server knows the exact total count:

```json
{
  "pagination": {
    "total": 150,
    "count": 50,
    "offset": 0,
    "limit": 50,
    "has_more": true
  }
}
```

**Use case**: Small to medium datasets where counting is inexpensive.

### 2. Streaming Pagination

When `total` is omitted, the server doesn't compute the total count for performance:

```json
{
  "pagination": {
    "count": 50,
    "offset": 0,
    "limit": 50,
    "has_more": true
  }
}
```

**Use case**: Large datasets where counting would be expensive (e.g., audit logs).

The `has_more` field indicates whether additional pages exist:

- `true`: More items are available (current page returned exactly `limit` items)
- `false`: This is the last page (current page returned fewer than `limit` items)

## Best Practices

### 1. Use Appropriate Page Sizes

```bash
# Too small: excessive requests
GET /v1/organizations/{org}/vaults?limit=5

# Good: balanced performance
GET /v1/organizations/{org}/vaults?limit=50

# Large batch: fewer requests, higher memory
GET /v1/organizations/{org}/vaults?limit=100
```

**Recommendations**:

- Default (50): Good for most use cases
- Small (10-25): UI pagination, incremental loading
- Large (100): Batch processing, data export

### 2. Implement Robust Pagination Logic

```typescript
async function fetchAllVaults(orgId: string): Promise<Vault[]> {
  const allVaults: Vault[] = [];
  let offset = 0;
  const limit = 100;

  while (true) {
    const response = await fetch(
      `/v1/organizations/${orgId}/vaults?limit=${limit}&offset=${offset}`
    );
    const { data, pagination } = await response.json();

    allVaults.push(...data);

    // Check if there are more pages
    if (!pagination.has_more) {
      break;
    }

    offset += limit;
  }

  return allVaults;
}
```

### 3. Handle Edge Cases

```typescript
function handlePaginatedResponse(response: PaginatedResponse) {
  // Empty result set
  if (response.data.length === 0) {
    console.log("No results found");
    return;
  }

  // Last page (partial results)
  if (response.pagination.count < response.pagination.limit) {
    console.log("Last page");
  }

  // More pages available
  if (response.pagination.has_more) {
    const nextOffset = response.pagination.offset + response.pagination.limit;
    fetchNextPage(nextOffset);
  }
}
```

### 4. Avoid Large Offsets

⚠️ **Performance Warning**: Large offset values can be inefficient in some storage backends.

```bash
# Inefficient for large datasets
GET /v1/audit-logs?limit=50&offset=100000
```

For large datasets, consider:

- Using filters to reduce the result set
- Implementing cursor-based pagination (future enhancement)
- Exporting data in batches during off-peak hours

## Endpoints Supporting Pagination

All list endpoints support pagination:

| Endpoint                                 | Default Limit | Notes                       |
| ---------------------------------------- | ------------- | --------------------------- |
| `GET /v1/organizations`                  | 50            | User's organizations        |
| `GET /v1/organizations/{org}/vaults`     | 50            | Organization vaults         |
| `GET /v1/organizations/{org}/teams`      | 50            | Organization teams          |
| `GET /v1/organizations/{org}/clients`    | 50            | OAuth clients               |
| `GET /v1/organizations/{org}/sessions`   | 50            | User sessions               |
| `GET /v1/organizations/{org}/audit-logs` | 50            | Audit logs (streaming mode) |
| `GET /v1/teams/{team}/members`           | 50            | Team members                |

## Examples

### Python

```python
import requests

def get_all_vaults(org_id: str, api_url: str) -> list:
    """Fetch all vaults for an organization with pagination."""
    vaults = []
    offset = 0
    limit = 100

    while True:
        response = requests.get(
            f"{api_url}/v1/organizations/{org_id}/vaults",
            params={"limit": limit, "offset": offset}
        )
        response.raise_for_status()
        data = response.json()

        vaults.extend(data["data"])

        if not data["pagination"]["has_more"]:
            break

        offset += limit

    return vaults
```

### TypeScript

```typescript
interface PaginatedResponse<T> {
  data: T[];
  pagination: {
    total?: number;
    count: number;
    offset: number;
    limit: number;
    has_more: boolean;
  };
}

async function* fetchVaultsPaginated(
  orgId: string,
  pageSize: number = 50
): AsyncGenerator<Vault[]> {
  let offset = 0;

  while (true) {
    const response = await fetch(
      `/v1/organizations/${orgId}/vaults?limit=${pageSize}&offset=${offset}`
    );
    const page: PaginatedResponse<Vault> = await response.json();

    yield page.data;

    if (!page.pagination.has_more) {
      break;
    }

    offset += pageSize;
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
    Data       []T        `json:"data"`
    Pagination Pagination `json:"pagination"`
}

type Pagination struct {
    Total   *int `json:"total,omitempty"`
    Count   int  `json:"count"`
    Offset  int  `json:"offset"`
    Limit   int  `json:"limit"`
    HasMore bool `json:"has_more"`
}

func FetchAllVaults(orgID string) ([]Vault, error) {
    var allVaults []Vault
    offset := 0
    limit := 100

    for {
        url := fmt.Sprintf(
            "/v1/organizations/%s/vaults?limit=%d&offset=%d",
            orgID, limit, offset,
        )

        resp, err := http.Get(url)
        if err != nil {
            return nil, err
        }
        defer resp.Body.Close()

        var page PaginatedResponse[Vault]
        if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
            return nil, err
        }

        allVaults = append(allVaults, page.Data...)

        if !page.Pagination.HasMore {
            break
        }

        offset += limit
    }

    return allVaults, nil
}
```

## Troubleshooting

### Issue: `has_more` is always `true`

**Cause**: Your offset and limit don't align properly, or you're not checking the correct field.

**Solution**: Always check `pagination.has_more` instead of comparing offsets manually.

### Issue: Duplicate items across pages

**Cause**: Data modified between requests (items added/deleted).

**Solution**: Use filters or sorting to maintain consistency, or consider implementing snapshot isolation for critical operations.

### Issue: Performance degradation with large offsets

**Cause**: Database scans entire offset range on each request.

**Solution**:

- Add filters to reduce result set
- Use smaller page sizes for UI
- Consider cursor-based pagination for very large datasets

## Future Enhancements

Planned improvements to pagination:

- **Cursor-based pagination**: For more efficient large dataset traversal
- **Stable pagination**: Snapshot isolation to prevent duplicates during data modifications
- **Sorting parameters**: `sort_by` and `sort_order` query parameters
- **Field filtering**: Select specific fields to reduce payload size

## See Also

- [OpenAPI.yaml](../OpenAPI.yaml): Complete API specifications with pagination examples
- [Architecture](architecture.md): Pagination implementation architecture
- [Performance](performance.md): Pagination performance benchmarks
