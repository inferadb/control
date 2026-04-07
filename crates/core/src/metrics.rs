//! Prometheus metrics for the control plane.
//!
//! Registers and records counters, histograms, and gauges for HTTP requests,
//! authentication attempts, database queries, gRPC calls, signing key operations,
//! and system health indicators.

use std::sync::Once;

use inferadb_control_types::OrganizationSlug;
use metrics::{counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram};

static METRICS_INIT: Once = Once::new();

/// Registers all Prometheus metric descriptions with the metrics registry.
///
/// Call once during application startup. Safe to call multiple times
/// (subsequent calls are no-ops).
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

        // Signing key metrics
        describe_counter!(
            "inferadb_control_signing_keys_registered_total",
            "Total number of signing keys registered in Ledger"
        );
        describe_counter!(
            "inferadb_control_signing_keys_revoked_total",
            "Total number of signing keys revoked in Ledger"
        );
        describe_counter!(
            "inferadb_control_signing_keys_rotated_total",
            "Total number of signing key rotations"
        );
        describe_histogram!(
            "inferadb_control_ledger_key_write_duration_seconds",
            "Duration of Ledger key write operations in seconds"
        );

        // Histogram metrics
        describe_histogram!("http_request_duration_seconds", "HTTP request duration in seconds");
        describe_histogram!("db_query_duration_seconds", "Database query duration in seconds");
        describe_histogram!("grpc_request_duration_seconds", "gRPC request duration in seconds");

        // Gauge metrics
        describe_gauge!("active_sessions", "Number of currently active sessions");
        describe_gauge!("organizations_total", "Total number of organizations");
        describe_gauge!("vaults_total", "Total number of vaults");
        describe_gauge!("discovered_endpoints", "Number of currently discovered server endpoints");
        describe_gauge!("clock_skew_seconds", "Measured clock skew against NTP in seconds");
    });
}

/// Records an HTTP request completion.
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

/// Records an authentication attempt.
///
/// # Arguments
///
/// * `auth_type` - Type of authentication (password, passkey, client_cert, etc.)
/// * `success` - Whether the attempt was successful
pub fn record_auth_attempt(auth_type: &str, success: bool) {
    counter!("auth_attempts_total", "type" => auth_type.to_string(), "success" => success.to_string())
        .increment(1);
}

/// Increments the `registrations_total` counter.
pub fn record_registration() {
    counter!("registrations_total").increment(1);
}

/// Records a rate limit exceeded event.
///
/// # Arguments
///
/// * `category` - Rate limit category (login_ip, registration_ip, etc.)
pub fn record_rate_limit_exceeded(category: &str) {
    counter!("rate_limits_exceeded_total", "category" => category.to_string()).increment(1);
}

/// Records a database query completion.
///
/// # Arguments
///
/// * `operation` - Type of operation (get, set, delete, transaction, etc.)
/// * `duration_secs` - Query duration in seconds
pub fn record_db_query(operation: &str, duration_secs: f64) {
    histogram!("db_query_duration_seconds", "operation" => operation.to_string())
        .record(duration_secs);
}

/// Records a gRPC request completion.
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

/// Updates the `active_sessions` gauge.
pub fn set_active_sessions(count: u64) {
    gauge!("active_sessions").set(count as f64);
}

/// Updates the `organizations_total` gauge.
pub fn set_organizations_total(count: u64) {
    gauge!("organizations_total").set(count as f64);
}

/// Updates the `vaults_total` gauge.
pub fn set_vaults_total(count: u64) {
    gauge!("vaults_total").set(count as f64);
}

/// Increments the `discovery_cache_hits_total` counter.
pub fn record_discovery_cache_hit() {
    counter!("discovery_cache_hits_total").increment(1);
}

/// Increments the `discovery_cache_misses_total` counter.
pub fn record_discovery_cache_miss() {
    counter!("discovery_cache_misses_total").increment(1);
}

/// Updates the `discovered_endpoints` gauge.
pub fn set_discovered_endpoints(count: u64) {
    gauge!("discovered_endpoints").set(count as f64);
}

/// Updates the `clock_skew_seconds` gauge with the measured NTP skew.
pub fn set_clock_skew(skew_seconds: f64) {
    gauge!("clock_skew_seconds").set(skew_seconds);
}

/// Records a signing key registration in Ledger.
///
/// # Arguments
///
/// * `organization` - Organization that owns the key
/// * `duration_secs` - Duration of the Ledger write operation in seconds
pub fn record_signing_key_registered(organization: OrganizationSlug, duration_secs: f64) {
    counter!("inferadb_control_signing_keys_registered_total", "organization" => organization.to_string())
        .increment(1);
    histogram!("inferadb_control_ledger_key_write_duration_seconds", "operation" => "create")
        .record(duration_secs);
}

/// Records a signing key revocation in Ledger.
///
/// # Arguments
///
/// * `organization` - Organization that owns the key
/// * `reason` - Reason for revocation (e.g., "user_requested", "emergency", "rotation")
/// * `duration_secs` - Duration of the Ledger write operation in seconds
pub fn record_signing_key_revoked(
    organization: OrganizationSlug,
    reason: &str,
    duration_secs: f64,
) {
    counter!("inferadb_control_signing_keys_revoked_total", "organization" => organization.to_string(), "reason" => reason.to_string())
        .increment(1);
    histogram!("inferadb_control_ledger_key_write_duration_seconds", "operation" => "revoke")
        .record(duration_secs);
}

/// Records a signing key rotation.
///
/// # Arguments
///
/// * `organization` - Organization that owns the key
/// * `duration_secs` - Duration of the Ledger write operation in seconds
pub fn record_signing_key_rotated(organization: OrganizationSlug, duration_secs: f64) {
    counter!("inferadb_control_signing_keys_rotated_total", "organization" => organization.to_string())
        .increment(1);
    histogram!("inferadb_control_ledger_key_write_duration_seconds", "operation" => "rotate")
        .record(duration_secs);
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_init_idempotent_across_multiple_calls() {
        init();
        init();
    }

    #[test]
    fn test_record_http_request_various_methods_and_statuses() {
        init();

        record_http_request("GET", "/v1/health", 200, 0.001);
        record_http_request("POST", "/v1/auth/login", 200, 0.125);
        record_http_request("POST", "/v1/auth/login", 401, 0.050);
    }

    #[test]
    fn test_record_auth_attempt_success_and_failure() {
        init();

        record_auth_attempt("password", true);
        record_auth_attempt("password", false);
        record_auth_attempt("passkey", true);
    }

    #[test]
    fn test_counter_functions_accept_various_labels() {
        init();

        record_registration();
        record_rate_limit_exceeded("login_ip");
        record_rate_limit_exceeded("registration_ip");
        record_discovery_cache_hit();
        record_discovery_cache_miss();
    }

    #[test]
    fn test_histogram_functions_record_durations() {
        init();

        record_db_query("get", 0.001);
        record_db_query("set", 0.002);
        record_db_query("transaction", 0.050);
        record_grpc_request("ControlService", "CreateVault", "OK", 0.015);
        record_grpc_request("ControlService", "DeleteVault", "NotFound", 0.005);
    }

    #[test]
    fn test_gauge_functions_set_values() {
        init();

        set_active_sessions(150);
        set_organizations_total(42);
        set_vaults_total(105);
        set_discovered_endpoints(5);
        set_clock_skew(0.042);
    }

    #[test]
    fn test_signing_key_metrics_all_operations() {
        init();

        record_signing_key_registered(OrganizationSlug::from(123), 0.015);
        record_signing_key_revoked(OrganizationSlug::from(123), "user_requested", 0.010);
        record_signing_key_revoked(OrganizationSlug::from(456), "emergency", 0.005);
        record_signing_key_rotated(OrganizationSlug::from(123), 0.020);
    }
}
