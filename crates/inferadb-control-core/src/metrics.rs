use std::sync::Once;

use metrics::{counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram};

static METRICS_INIT: Once = Once::new();

/// Initialize Prometheus metrics descriptions
///
/// This should be called once during application startup.
/// It registers all metric names and descriptions with the metrics registry.
pub fn init() {
    METRICS_INIT.call_once(|| {
        // Counter metrics
        describe_counter!("http_requests_total", "Total number of HTTP requests received");
        describe_counter!("auth_attempts_total", "Total number of authentication attempts");
        describe_counter!("registrations_total", "Total number of user registrations");
        describe_counter!(
            "rate_limits_exceeded_total",
            "Total number of rate limit exceeded responses"
        );
        describe_counter!("discovery_cache_hits_total", "Total cache hits for endpoint discovery");
        describe_counter!(
            "discovery_cache_misses_total",
            "Total cache misses for endpoint discovery"
        );

        // Histogram metrics
        describe_histogram!("http_request_duration_seconds", "HTTP request duration in seconds");
        describe_histogram!("db_query_duration_seconds", "Database query duration in seconds");
        describe_histogram!("grpc_request_duration_seconds", "gRPC request duration in seconds");

        // Gauge metrics
        describe_gauge!("active_sessions", "Number of currently active sessions");
        describe_gauge!("organizations_total", "Total number of organizations");
        describe_gauge!("vaults_total", "Total number of vaults");
        describe_gauge!("is_leader", "Whether this instance is the leader (1) or not (0)");
        describe_gauge!("discovered_endpoints", "Number of currently discovered server endpoints");
    });
}

/// Record an HTTP request completion
///
/// # Arguments
///
/// * `method` - HTTP method (GET, POST, etc.)
/// * `path` - Request path pattern
/// * `status` - HTTP status code
/// * `duration_secs` - Request duration in seconds
pub fn record_http_request(method: &str, path: &str, status: u16, duration_secs: f64) {
    counter!("http_requests_total", "method" => method.to_string(), "path" => path.to_string(), "status" => status.to_string())
        .increment(1);
    histogram!("http_request_duration_seconds", "method" => method.to_string(), "path" => path.to_string())
        .record(duration_secs);
}

/// Record an authentication attempt
///
/// # Arguments
///
/// * `auth_type` - Type of authentication (password, passkey, client_cert, etc.)
/// * `success` - Whether the attempt was successful
pub fn record_auth_attempt(auth_type: &str, success: bool) {
    counter!("auth_attempts_total", "type" => auth_type.to_string(), "success" => success.to_string())
        .increment(1);
}

/// Record a user registration
pub fn record_registration() {
    counter!("registrations_total").increment(1);
}

/// Record a rate limit exceeded event
///
/// # Arguments
///
/// * `category` - Rate limit category (login_ip, registration_ip, etc.)
pub fn record_rate_limit_exceeded(category: &str) {
    counter!("rate_limits_exceeded_total", "category" => category.to_string()).increment(1);
}

/// Record a database query completion
///
/// # Arguments
///
/// * `operation` - Type of operation (get, set, delete, transaction, etc.)
/// * `duration_secs` - Query duration in seconds
pub fn record_db_query(operation: &str, duration_secs: f64) {
    histogram!("db_query_duration_seconds", "operation" => operation.to_string())
        .record(duration_secs);
}

/// Record a gRPC request completion
///
/// # Arguments
///
/// * `service` - gRPC service name
/// * `method` - gRPC method name
/// * `status` - gRPC status code
/// * `duration_secs` - Request duration in seconds
pub fn record_grpc_request(service: &str, method: &str, status: &str, duration_secs: f64) {
    histogram!("grpc_request_duration_seconds", "service" => service.to_string(), "method" => method.to_string(), "status" => status.to_string())
        .record(duration_secs);
}

/// Set the number of active sessions
pub fn set_active_sessions(count: i64) {
    gauge!("active_sessions").set(count as f64);
}

/// Set the total number of organizations
pub fn set_organizations_total(count: i64) {
    gauge!("organizations_total").set(count as f64);
}

/// Set the total number of vaults
pub fn set_vaults_total(count: i64) {
    gauge!("vaults_total").set(count as f64);
}

/// Set whether this instance is the leader
pub fn set_is_leader(is_leader: bool) {
    gauge!("is_leader").set(if is_leader { 1.0 } else { 0.0 });
}

/// Record a discovery cache hit
pub fn record_discovery_cache_hit() {
    counter!("discovery_cache_hits_total").increment(1);
}

/// Record a discovery cache miss
pub fn record_discovery_cache_miss() {
    counter!("discovery_cache_misses_total").increment(1);
}

/// Set the number of discovered endpoints
pub fn set_discovered_endpoints(count: i64) {
    gauge!("discovered_endpoints").set(count as f64);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_metrics() {
        // Should not panic when called multiple times
        init();
        init();
    }

    #[test]
    fn test_record_http_request() {
        init();
        record_http_request("GET", "/v1/health", 200, 0.001);
        record_http_request("POST", "/v1/auth/login", 200, 0.125);
        record_http_request("POST", "/v1/auth/login", 401, 0.050);
    }

    #[test]
    fn test_record_auth_attempt() {
        init();
        record_auth_attempt("password", true);
        record_auth_attempt("password", false);
        record_auth_attempt("passkey", true);
    }

    #[test]
    fn test_record_registration() {
        init();
        record_registration();
    }

    #[test]
    fn test_record_rate_limit_exceeded() {
        init();
        record_rate_limit_exceeded("login_ip");
        record_rate_limit_exceeded("registration_ip");
    }

    #[test]
    fn test_record_db_query() {
        init();
        record_db_query("get", 0.001);
        record_db_query("set", 0.002);
        record_db_query("transaction", 0.050);
    }

    #[test]
    fn test_record_grpc_request() {
        init();
        record_grpc_request("ManagementService", "CreateVault", "OK", 0.015);
        record_grpc_request("ManagementService", "DeleteVault", "NotFound", 0.005);
    }

    #[test]
    fn test_set_gauges() {
        init();
        set_active_sessions(150);
        set_organizations_total(42);
        set_vaults_total(105);
        set_is_leader(true);
        set_is_leader(false);
    }

    #[test]
    fn test_record_discovery_metrics() {
        init();
        record_discovery_cache_hit();
        record_discovery_cache_miss();
        set_discovered_endpoints(5);
    }
}
