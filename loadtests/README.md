# Load Tests

Performance and load testing suite for InferaDB Control using [k6](https://k6.io/).

## Prerequisites

Install k6:

```bash
# macOS
brew install k6

# Linux (Debian/Ubuntu)
sudo gpg -k
sudo gpg --no-default-keyring --keyring /usr/share/keyrings/k6-archive-keyring.gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" | sudo tee /etc/apt/sources.list.d/k6.list
sudo apt-get update
sudo apt-get install k6

# Docker
docker pull grafana/k6
```

## Test Scenarios

### 1. Authentication Load Test (`auth.js`)

Tests user registration, login, and session management under load.

**What it tests:**

- User registration with concurrent users
- Login flow with password authentication
- Profile retrieval (authenticated requests)
- Session listing
- Logout

**Run:**

```bash
# Default configuration (gradual ramp-up to 100 users)
k6 run loadtests/auth.js

# Custom configuration
k6 run --vus 50 --duration 2m loadtests/auth.js

# With custom base URL
BASE_URL=https://api.example.com k6 run loadtests/auth.js
```

**Expected performance:**

- p95 latency: < 500ms
- p99 latency: < 1000ms
- Error rate: < 5%

### 2. Vault Operations Test (`vaults.js`)

Tests vault creation, token generation, and client management.

**What it tests:**

- Vault creation and management
- Client creation and certificate generation
- Vault token generation (JWT)
- Token refresh flow
- Access control checks

**Run:**

```bash
# Default configuration (gradual ramp-up to 50 users)
k6 run loadtests/vaults.js

# Sustained load
k6 run --vus 30 --duration 5m loadtests/vaults.js
```

**Expected performance:**

- p95 latency: < 1000ms
- p99 latency: < 2000ms
- Error rate: < 5%

### 3. Organization Management Test (`organizations.js`)

Tests organization and team management operations.

**What it tests:**

- Organization creation
- Organization updates
- Member management
- Team creation and management
- Multi-organization scenarios

**Run:**

```bash
# Default configuration
k6 run loadtests/organizations.js

# Heavy load
k6 run --vus 40 --duration 3m loadtests/organizations.js
```

**Expected performance:**

- p95 latency: < 800ms
- p99 latency: < 1500ms
- Error rate: < 5%

### 4. Spike Test (`spike.js`)

Tests system behavior under sudden traffic spikes.

**What it tests:**

- Sudden traffic increases (10 → 200 → 500 users)
- Rate limiting behavior
- System recovery after spike
- Health check availability during load

**Run:**

```bash
# Run spike test
k6 run loadtests/spike.js
```

**Expected behavior:**

- Rate limiting activates appropriately (429 responses)
- Health checks remain available
- System recovers gracefully
- Error rate: < 10% (higher tolerance during spike)

## Running All Tests

```bash
# Run all test scenarios sequentially
for test in auth vaults organizations spike; do
  echo "Running ${test} test..."
  k6 run loadtests/${test}.js
  echo "Waiting 30s before next test..."
  sleep 30
done
```

## Test Environment

### Local Development

1. Start Control:

   ```bash
   cargo run --bin inferadb-control
   ```

2. Run tests against localhost:

   ```bash
   k6 run loadtests/auth.js
   ```

### Custom Environment

Set the `BASE_URL` environment variable:

```bash
# Staging
BASE_URL=https://staging-api.inferadb.com k6 run loadtests/auth.js

# Production (use with caution)
BASE_URL=https://api.inferadb.com k6 run --vus 10 --duration 30s loadtests/auth.js
```

## Understanding Results

### Key Metrics

k6 automatically tracks:

- **http_req_duration**: Request latency (p50, p95, p99)
- **http_req_failed**: Error rate percentage
- **http_reqs**: Total requests per second
- **vus**: Virtual users (concurrent users)
- **iterations**: Total test iterations

### Custom Metrics

Each test defines custom metrics:

- `register_errors`, `login_errors`, etc.: Error rates for specific operations
- `register_latency`, `token_gen_latency`, etc.: Operation-specific latency trends

### Example Output

```text
running (4m30.0s), 000/100 VUs, 12500 complete and 0 interrupted iterations
default ✓ [======================================] 100 VUs  4m30s

     ✓ register: status is 201
     ✓ login: status is 200
     ✓ profile: status is 200

     checks.........................: 100.00% ✓ 37500      ✗ 0
     data_received..................: 125 MB  464 kB/s
     data_sent......................: 45 MB   167 kB/s
     http_req_duration..............: avg=245ms  min=45ms  med=189ms  max=1.2s   p(95)=456ms  p(99)=789ms
     http_req_failed................: 0.00%   ✓ 0          ✗ 37500
     http_reqs......................: 37500   139/s
     iterations.....................: 12500   46/s
     vus............................: 100     min=0        max=100
```

## Thresholds

Tests fail if thresholds are not met:

```javascript
thresholds: {
  'http_req_duration': ['p(95)<500', 'p(99)<1000'], // 95% requests < 500ms
  'http_req_failed': ['rate<0.05'],                  // Error rate < 5%
}
```

Override thresholds for specific scenarios:

```bash
# More lenient thresholds for spike tests
k6 run --no-thresholds loadtests/spike.js
```

## Performance Benchmarks

Based on typical hardware (4 CPU, 8GB RAM):

| Scenario          | Concurrent Users | RPS | p95 Latency | p99 Latency |
| ----------------- | ---------------- | --- | ----------- | ----------- |
| Authentication    | 100              | 150 | 400ms       | 800ms       |
| Vault Operations  | 50               | 80  | 900ms       | 1800ms      |
| Organizations     | 25               | 60  | 700ms       | 1400ms      |
| Spike (200 users) | 200              | 250 | 1500ms      | 3000ms      |

## CI/CD Integration

### GitHub Actions Example

```yaml
- name: Run Load Tests
  run: |
    k6 run --vus 50 --duration 1m loadtests/auth.js
    k6 run --vus 30 --duration 1m loadtests/vaults.js
```

### Docker

```bash
docker run --rm -i grafana/k6 run - <loadtests/auth.js
```

## Troubleshooting

### Connection Refused

Ensure Control is running:

```bash
curl http://localhost:3000/v1/health
```

### Rate Limiting

If you see many 429 responses:

- Reduce concurrent users (`--vus`)
- Increase ramp-up time in test stages
- Adjust rate limits in `config.yaml`

### High Latency

- Check database performance (Ledger metrics)
- Monitor system resources (CPU, memory)
- Review logs for errors
- Consider horizontal scaling

### Test Data Cleanup

Load tests create test users/organizations. To clean up:

```bash
# For memory backend (development)
# Restart the service

# For Ledger (production)
# Implement cleanup script or use soft-delete TTL
```

## Advanced Usage

### Custom Scenarios

Modify test stages for specific scenarios:

```javascript
export const options = {
  stages: [
    { duration: "2m", target: 100 }, // Ramp up
    { duration: "5m", target: 100 }, // Stay at load
    { duration: "2m", target: 200 }, // Increase
    { duration: "5m", target: 200 }, // Sustain
    { duration: "2m", target: 0 }, // Ramp down
  ],
};
```

### CSV Output

Save results to CSV:

```bash
k6 run --out csv=results.csv loadtests/auth.js
```

### JSON Summary

Output JSON summary:

```bash
k6 run --summary-export=summary.json loadtests/auth.js
```

### Distributed Testing

For very high load, use k6 Cloud or multiple k6 instances:

```bash
# Instance 1
k6 run --vus 250 loadtests/auth.js

# Instance 2 (different machine)
k6 run --vus 250 loadtests/auth.js
```

## Further Reading

- [k6 Documentation](https://k6.io/docs/)
- [Performance Testing Best Practices](https://k6.io/docs/testing-guides/test-types/)
- [k6 Cloud](https://k6.io/cloud/) - Managed load testing service
