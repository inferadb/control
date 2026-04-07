# Performance Characteristics

InferaDB Control is designed for low-latency multi-tenant administration with built-in rate limiting and horizontal scaling via the Ledger backend.

## Why It Matters

Understanding token lifetimes, rate limits, and resource constraints helps you size deployments, configure clients, and debug unexpected 429 or timeout responses.

## Token and Session Lifetimes

These values are compile-time constants defined in `crates/const/src/duration.rs`:

| Token / Cookie                 | TTL        | Constant                                        |
| ------------------------------ | ---------- | ----------------------------------------------- |
| Access token cookie            | 15 minutes | `ACCESS_COOKIE_MAX_AGE_SECONDS` (900)           |
| User session refresh token     | 1 hour     | `USER_SESSION_REFRESH_TOKEN_TTL_SECONDS` (3600) |
| Client (service) refresh token | 7 days     | `CLIENT_REFRESH_TOKEN_TTL_SECONDS` (604800)     |
| Refresh token cookie           | 30 days    | `REFRESH_COOKIE_MAX_AGE_SECONDS` (2592000)      |
| Session cookie                 | 24 hours   | `SESSION_COOKIE_MAX_AGE` (86400)                |
| Authorization code             | 10 minutes | `AUTHORIZATION_CODE_TTL_SECONDS` (600)          |
| Email verification token       | 24 hours   | `EMAIL_VERIFICATION_TOKEN_EXPIRY_HOURS` (24)    |
| Organization invitation        | 7 days     | `INVITATION_EXPIRY_DAYS` (7)                    |
| Health check cache             | 5 seconds  | `HEALTH_CACHE_TTL_SECONDS` (5)                  |

## Rate Limits

Rate limits are enforced per IP and are not configurable at runtime. Defined in `crates/core/src/ratelimit.rs`:

| Endpoint Category | Limit        | Window | Applies To                                                                |
| ----------------- | ------------ | ------ | ------------------------------------------------------------------------- |
| Login / Auth      | 100 requests | 1 hour | All public auth endpoints (email, passkey, TOTP, token exchange, refresh) |
| Registration      | 5 requests   | 1 day  | `POST /control/v1/auth/email/complete`                                    |

When a rate limit is exceeded, the server returns HTTP 429 with a `Retry-After` header and a JSON body:

```json
{
  "error": "rate limit exceeded",
  "code": "RATE_LIMIT_EXCEEDED"
}
```

Unidentifiable clients (missing `X-Forwarded-For` when behind a proxy) share a single rate limit bucket.

## Resource Limits

Defined in `crates/const/src/limits.rs`:

| Limit                       | Value   | Constant                      |
| --------------------------- | ------- | ----------------------------- |
| Max passkeys per user       | 20      | `MAX_PASSKEYS_PER_USER`       |
| Max concurrent sessions     | 10      | `MAX_CONCURRENT_SESSIONS`     |
| Global organization limit   | 100,000 | `GLOBAL_ORGANIZATION_LIMIT`   |
| Per-user organization limit | 10      | `PER_USER_ORGANIZATION_LIMIT` |

## Scalability

### Single Instance

The in-memory backend is limited to one instance. All data lives in RAM and is lost on restart. Use this for development and testing.

### Horizontal Scaling (Ledger Backend)

With the Ledger backend, Control instances are stateless. Each instance needs a unique `--worker-id` (0-1023) for Snowflake ID generation.

Key properties:

- **Stateless**: No shared in-memory state beyond configuration.
- **Worker IDs**: Each instance must have a unique value. Set via `--worker-id` or `INFERADB__CONTROL__WORKER_ID`.
- **Rate Limits**: With the Ledger-backed rate limiter, limits are shared across instances.
- **Session Affinity**: Not required.

### Request Pipeline

The server uses the Tokio async runtime with a work-stealing scheduler. The concurrency limit is 10,000 simultaneous in-flight requests. A default body size limit of 256 KiB prevents memory exhaustion (schema deployment endpoints allow up to 1 MiB).

## Optimization Guidelines

### Application Level

- **Connection Pooling**: Maintain persistent connections to the Ledger backend.
- **Org Membership Cache**: Successful membership checks are cached for 30 seconds (up to 4,096 entries) to avoid Ledger round-trips on every read request.
- **Health Check Cache**: Ledger health probe results are cached for 5 seconds to absorb Kubernetes probe bursts.

### Infrastructure Level

- **Health Check Endpoint**: Use `GET /readyz` for load balancer health checks.
- **Prometheus Metrics**: Scrape `GET /metrics` for request duration, storage latency, and rate limit counters.
- **Autoscaling Signals**: CPU utilization and request latency from Prometheus are the primary scaling indicators.

## Troubleshooting

**High Latency (p95 > 1s)**: Check Ledger connectivity and transaction conflicts. Review Prometheus histogram data. Scale horizontally if Ledger is healthy but throughput is saturated.

**High 429 Rate**: Verify the load balancer sets `X-Forwarded-For` correctly and `--trusted-proxy-depth` matches your proxy chain. All clients behind a misconfigured proxy share one rate limit bucket.

**High Memory Usage**: Paginate all list operations. The Tokio thread count matches CPU core count and is not configurable. Reduce concurrent connections at the load balancer if memory pressure is high.
