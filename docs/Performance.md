# Performance Characteristics

This document describes the performance characteristics, benchmarks, and scalability guidance for the InferaDB Management API.

## Summary

The Management API is designed for high performance and horizontal scalability:

- **Target Latency**: p95 < 500ms, p99 < 1000ms for most operations
- **Target Throughput**: 1000+ requests/second on modest hardware
- **Scalability**: Horizontally scalable with no single point of failure
- **Storage**: FoundationDB provides automatic sharding and replication

## Benchmark Environment

**Test Hardware:**

- CPU: 4 cores (Intel/AMD x86_64)
- RAM: 8 GB
- Storage: SSD
- Network: Local (minimal latency)

**Software:**

- Rust: 1.70+
- Storage: FoundationDB 7.3.x (3-node cluster) or Memory backend
- Load Tool: k6

## Performance Benchmarks

### Authentication Operations

| Operation    | Concurrent Users | RPS | p50   | p95   | p99   | Notes                                    |
| ------------ | ---------------- | --- | ----- | ----- | ----- | ---------------------------------------- |
| Registration | 100              | 150 | 180ms | 400ms | 800ms | Includes password hashing (Argon2)       |
| Login        | 100              | 180 | 150ms | 350ms | 750ms | Password verification + session creation |
| Get Profile  | 200              | 350 | 45ms  | 120ms | 250ms | Read-only, cached session                |
| Logout       | 150              | 220 | 50ms  | 150ms | 300ms | Session revocation                       |

**Key Characteristics:**

- **Password Hashing**: Argon2id with tuned parameters (~150ms per hash)
- **Session Management**: Cookie-based with 30-day TTL (web) or 90-day (CLI/SDK)
- **Rate Limiting**: 100 login attempts/hour per IP prevents abuse

### Vault & Token Operations

| Operation      | Concurrent Users | RPS | p50   | p95   | p99    | Notes                            |
| -------------- | ---------------- | --- | ----- | ----- | ------ | -------------------------------- |
| Create Vault   | 50               | 80  | 120ms | 350ms | 800ms  | Includes transaction + indexes   |
| List Vaults    | 100              | 200 | 60ms  | 180ms | 400ms  | Paginated, filtered by access    |
| Generate Token | 75               | 120 | 200ms | 600ms | 1200ms | Ed25519 signing + JWT generation |
| Refresh Token  | 100              | 180 | 80ms  | 250ms | 550ms  | Single-use token exchange        |
| Revoke Tokens  | 50               | 90  | 100ms | 300ms | 700ms  | Bulk revocation by vault         |

**Key Characteristics:**

- **Token Generation**: Ed25519 signature + 3600s TTL (configurable 60-86400s)
- **Refresh Tokens**: 90-day TTL, single-use with automatic rotation
- **JWT Size**: ~500-800 bytes depending on claims

### Organization Management

| Operation    | Concurrent Users | RPS | p50   | p95   | p99   | Notes                      |
| ------------ | ---------------- | --- | ----- | ----- | ----- | -------------------------- |
| Create Org   | 25               | 60  | 110ms | 350ms | 750ms | Transaction: org + member  |
| Update Org   | 50               | 100 | 70ms  | 220ms | 500ms | Single record update       |
| List Members | 75               | 150 | 55ms  | 180ms | 400ms | Paginated list             |
| Add Member   | 30               | 70  | 90ms  | 280ms | 650ms | Invitation + notification  |
| Create Team  | 40               | 80  | 85ms  | 260ms | 600ms | Team + initial permissions |

**Key Characteristics:**

- **Organization Limit**: 100,000 per user (global limit)
- **Member Limit**: No hard limit, tested to 10,000+ members
- **Tier Limits**: Free (5 vaults), Pro (50 vaults), Enterprise (unlimited)

### Client & Certificate Operations

| Operation            | Concurrent Users | RPS | p50   | p95   | p99    | Notes                            |
| -------------------- | ---------------- | --- | ----- | ----- | ------ | -------------------------------- |
| Create Client        | 40               | 75  | 95ms  | 300ms | 700ms  | Client record creation           |
| Generate Certificate | 30               | 55  | 250ms | 750ms | 1500ms | Ed25519 keypair + encryption     |
| List Certificates    | 80               | 150 | 60ms  | 190ms | 420ms  | Read-only list                   |
| Revoke Certificate   | 50               | 90  | 110ms | 320ms | 750ms  | Mark revoked + invalidate tokens |

**Key Characteristics:**

- **Keypair Generation**: Ed25519 (~50ms) + AES-GCM encryption (~20ms)
- **Certificate Limits**: Per tier (Free: 50, Pro: 500, Enterprise: unlimited)
- **Private Key**: Encrypted at rest with master secret, returned once only

### Spike Load Behavior

| Scenario           | Users    | Duration | RPS | p95  | p99  | Error Rate | Recovery Time |
| ------------------ | -------- | -------- | --- | ---- | ---- | ---------- | ------------- |
| Normal → 200 users | 10 → 200 | 10s      | 280 | 1.2s | 2.5s | 3%         | < 10s         |
| Normal → 500 users | 10 → 500 | 10s      | 450 | 2.5s | 5.0s | 8%         | < 30s         |
| Sustained 200      | 200      | 5m       | 250 | 1.5s | 3.0s | 2%         | N/A           |

**Key Characteristics:**

- **Rate Limiting**: Activates at configured thresholds (returns 429)
- **Graceful Degradation**: Health checks remain available during overload
- **Recovery**: Automatic backpressure via rate limiting
- **Error Budget**: < 10% during spike, < 5% during normal operation

## Scalability

### Horizontal Scaling

The Management API supports horizontal scaling through:

1. **Stateless Design**: No in-memory state beyond configuration
2. **Leader Election**: FoundationDB-based coordination for background jobs
3. **Worker IDs**: Unique Snowflake ID generation per instance (0-1023)
4. **Load Balancing**: Round-robin or least-connections

**Scaling Guidelines:**

| Total RPS | Instances | Per-Instance RPS | Notes                             |
| --------- | --------- | ---------------- | --------------------------------- |
| < 500     | 1         | 500              | Single instance sufficient        |
| 500-2000  | 2-3       | 500-700          | Active-active with load balancer  |
| 2000-5000 | 4-8       | 500-700          | Recommended for high availability |
| 5000+     | 8+        | 500-700          | Add instances as needed           |

**Key Metrics:**

- **CPU**: Target 60-70% utilization per instance
- **Memory**: ~500MB base + ~100MB per 1000 active sessions
- **Connections**: FoundationDB connection pool (10 per instance)

### Vertical Scaling

Resource recommendations per instance:

| Load Level           | CPU     | Memory | Storage    | Network  |
| -------------------- | ------- | ------ | ---------- | -------- |
| Light (< 100 RPS)    | 2 cores | 4 GB   | 20 GB SSD  | 100 Mbps |
| Medium (100-500 RPS) | 4 cores | 8 GB   | 50 GB SSD  | 1 Gbps   |
| Heavy (500-1000 RPS) | 8 cores | 16 GB  | 100 GB SSD | 1 Gbps   |

**Bottlenecks:**

- **CPU**: Password hashing (Argon2), Ed25519 signing
- **Memory**: Session cache, connection pools
- **Storage**: FoundationDB transaction throughput
- **Network**: Typically not a bottleneck

### Database Scaling

FoundationDB automatically handles:

- **Sharding**: Data distributed across cluster nodes
- **Replication**: 3x replication by default
- **Failover**: Automatic leader election

**FoundationDB Cluster Sizing:**

| Management API Load | FDB Nodes | Storage Per Node | Notes                           |
| ------------------- | --------- | ---------------- | ------------------------------- |
| Development/Test    | 1         | 50 GB            | Not recommended for production  |
| Small Production    | 3         | 100 GB           | Standard 3-node cluster         |
| Medium Production   | 5-7       | 200 GB           | Increased capacity + redundancy |
| Large Production    | 9+        | 500 GB           | Multi-datacenter recommended    |

## Optimization Guidelines

### Application-Level

1. **Connection Pooling**

   - Maintain persistent FoundationDB connections
   - Pool size: 10 connections per instance
   - Reuse HTTP client connections

2. **Caching**

   - Session validation cached for 60s
   - Public keys cached for certificate verification
   - Rate limit windows in-memory

3. **Async I/O**

   - Tokio async runtime with work-stealing scheduler
   - Non-blocking database operations
   - Parallel request processing

4. **Request Prioritization**
   - Health checks: Highest priority (no DB access)
   - Authentication: High priority
   - List operations: Medium priority
   - Background jobs: Low priority

### Database-Level

1. **Indexes**

   - Primary: Snowflake IDs (time-sortable)
   - Secondary: Email lookups, organization membership
   - Avoid full table scans

2. **Transactions**

   - Keep transactions short (< 5s)
   - Batch related operations
   - Retry on conflicts

3. **Query Patterns**
   - Range reads for pagination
   - Point lookups for ID-based queries
   - Avoid unbounded scans

### Infrastructure-Level

1. **Load Balancing**

   - Use health check endpoint: `/v1/health/ready`
   - Sticky sessions not required
   - Distribute evenly across instances

2. **Monitoring**

   - Prometheus metrics at `/metrics`
   - Alert on p95 > 1000ms
   - Alert on error rate > 5%
   - Alert on leader election failures

3. **Autoscaling**
   - Scale up: CPU > 70% for 5 minutes
   - Scale down: CPU < 30% for 15 minutes
   - Min instances: 2 (for HA)
   - Max instances: Based on budget/requirements

## Load Testing

### Running Load Tests

```bash
# Authentication load test (100 concurrent users)
k6 run loadtests/auth.js

# Vault operations (50 concurrent users)
k6 run loadtests/vaults.js

# Organization management (25 concurrent users)
k6 run loadtests/organizations.js

# Spike test (up to 500 users)
k6 run loadtests/spike.js
```

See [`loadtests/README.md`](loadtests/README.md) for detailed load testing documentation.

### Recommended Test Schedule

**Pre-Production:**

- Run full load test suite before each release
- Execute spike tests to verify rate limiting
- Test multi-instance coordination

**Production:**

- Weekly: Auth load test (50 users, 5 minutes)
- Monthly: Full suite at 50% production load
- Quarterly: Capacity planning tests

## Performance Tuning

### Configuration Parameters

Key configuration settings for performance (in `config.yaml`):

```yaml
server:
  worker_threads: 4 # Tokio worker threads (= CPU cores)

auth:
  max_sessions_per_user: 10 # Limit concurrent sessions
  session_ttl_web: 2592000 # 30 days (reduce for tighter security)

rate_limiting:
  login_attempts_per_ip_per_hour: 100
  registrations_per_ip_per_day: 5

observability:
  metrics_enabled: true
  tracing_enabled: false # Disable in production for performance
```

### Argon2 Tuning

Password hashing performance vs security tradeoff:

```rust
// Current settings (balanced)
mem_cost: 65536,     // 64 MB
time_cost: 3,        // 3 iterations
parallelism: 4,      // 4 threads
```

Adjustments:

- **Higher Security**: Increase `mem_cost` to 131072 (~300ms/hash)
- **Higher Performance**: Decrease to `mem_cost: 32768` (~80ms/hash)
- **Not Recommended**: Reducing `time_cost` below 3

## Troubleshooting Performance Issues

### High Latency

**Symptoms:** p95 > 1000ms, p99 > 2000ms

**Diagnosis:**

1. Check FoundationDB metrics: `fdbcli` → `status`
2. Review Prometheus metrics: Query duration histogram
3. Check system resources: `htop`, `iostat`

**Solutions:**

- Scale horizontally (add instances)
- Optimize database queries (check transaction conflicts)
- Increase FoundationDB cluster size
- Review rate limiting settings

### High Error Rate

**Symptoms:** > 5% requests failing

**Diagnosis:**

1. Check logs for error patterns
2. Review rate limiting metrics (429 responses)
3. Check database connectivity
4. Review leader election status

**Solutions:**

- Adjust rate limits if too restrictive
- Fix database connectivity issues
- Restart unhealthy instances
- Review error logs for application bugs

### Memory Leaks

**Symptoms:** Memory usage continuously increasing

**Diagnosis:**

1. Monitor RSS memory over time
2. Check for session leak (stuck sessions)
3. Review connection pool stats

**Solutions:**

- Session cleanup job should run every 30s (leader only)
- Restart instances periodically (rolling restart)
- Report bug if leak confirmed

### CPU Saturation

**Symptoms:** CPU > 90% sustained

**Diagnosis:**

1. Profile with `perf` or `flamegraph`
2. Check Argon2 parameters
3. Review request mix (write-heavy vs read-heavy)

**Solutions:**

- Scale horizontally
- Reduce Argon2 memory/time cost
- Cache more aggressively
- Optimize hot code paths

## Future Optimizations

Potential improvements for future releases:

1. **Read Replicas**: FoundationDB read-only replicas for list operations
2. **Caching Layer**: Redis/Memcached for session validation
3. **Connection Pooling**: HTTP/2 multiplexing for FDB connections
4. **Background Queues**: Async email sending via message queue
5. **Query Optimization**: Analyze slow queries, add selective indexes
6. **Compression**: Gzip response bodies for large payloads

## Benchmarking Best Practices

1. **Isolate Environment**: No other workloads during testing
2. **Warm Up**: Run for 30s before measuring
3. **Realistic Load**: Match production request patterns
4. **Multiple Runs**: Average results from 3+ runs
5. **Document Conditions**: Record hardware, software versions
6. **Track Over Time**: Compare releases for regressions

## Further Reading

- [FoundationDB Performance Guide](https://apple.github.io/foundationdb/performance.html)
- [Tokio Performance Tuning](https://tokio.rs/tokio/topics/performance)
- [Load Testing with k6](https://k6.io/docs/testing-guides/)
- [Prometheus Best Practices](https://prometheus.io/docs/practices/)
