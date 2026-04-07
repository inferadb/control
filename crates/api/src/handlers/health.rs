//! Health check endpoints for Kubernetes probes.
//!
//! Provides standard Kubernetes health endpoints:
//! - `/livez` — Liveness probe (is the process alive?)
//! - `/readyz` — Readiness probe (can it accept traffic?)
//! - `/startupz` — Startup probe (has initialization completed?)
//! - `/healthz` — Detailed health status for debugging/monitoring
//!
//! Health checks probe the Ledger SDK client when configured, falling back
//! to a simple "alive" check when running without a Ledger connection.
//! Results are cached for 5 seconds to protect Ledger from probe bursts.

use std::{
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::SystemTime,
};

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use inferadb_control_const::duration::HEALTH_CACHE_TTL_SECONDS;
use serde::{Deserialize, Serialize};

use crate::handlers::AppState;

/// Health check status indicator.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// All subsystems are operational.
    Healthy,
    /// Some subsystems are impaired but the service is functional.
    Degraded,
    /// Critical subsystems are unreachable.
    Unhealthy,
}

/// Detailed health status response for the `/healthz` endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct HealthResponse {
    /// Overall health status.
    pub status: HealthStatus,
    /// Service name (e.g., `"inferadb-control"`).
    pub service: &'static str,
    /// Crate version from `Cargo.toml`.
    pub version: &'static str,
    /// Worker/instance identifier.
    pub instance_id: u16,
    /// Seconds since server startup.
    pub uptime_seconds: u64,
    /// Whether the Ledger SDK client is reachable.
    pub ledger_healthy: bool,
    /// Optional human-readable diagnostic details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Cached health check state preventing probe bursts from cascading to Ledger.
///
/// Stored in [`AppState`] for test isolation. Uses lock-free atomics so
/// concurrent probes do not block each other. The cache is best-effort:
/// concurrent callers may occasionally duplicate a health check, which is
/// acceptable for probes.
pub struct HealthCache {
    /// Unix epoch seconds of the last health check.
    last_check_epoch_secs: AtomicU64,
    /// Whether the last health check succeeded.
    last_result: AtomicBool,
}

impl Default for HealthCache {
    fn default() -> Self {
        Self { last_check_epoch_secs: AtomicU64::new(0), last_result: AtomicBool::new(false) }
    }
}

impl std::fmt::Debug for HealthCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HealthCache")
            .field("last_check_epoch_secs", &self.last_check_epoch_secs.load(Ordering::Relaxed))
            .field("last_result", &self.last_result.load(Ordering::Relaxed))
            .finish()
    }
}

/// Probes Ledger SDK health, caching the result for 5 seconds.
async fn check_ledger_health(state: &AppState) -> bool {
    let Some(ref ledger) = state.ledger else {
        // No Ledger configured (dev-mode) — consider healthy
        return true;
    };

    let now =
        SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_secs();

    let last_check = state.health_cache.last_check_epoch_secs.load(Ordering::Acquire);
    if now.saturating_sub(last_check) < HEALTH_CACHE_TTL_SECONDS {
        return state.health_cache.last_result.load(Ordering::Acquire);
    }

    let result = ledger.health_check().await.unwrap_or(false);
    // Store result before epoch so readers that see the new epoch also see the new result.
    state.health_cache.last_result.store(result, Ordering::Release);
    state.health_cache.last_check_epoch_secs.store(now, Ordering::Release);
    result
}

/// GET /livez
///
/// Returns 200 OK if the server process is running.
pub async fn livez_handler() -> impl IntoResponse {
    StatusCode::OK
}

/// GET /readyz
///
/// Returns 200 OK when the Ledger SDK client is reachable, 503 otherwise.
pub async fn readyz_handler(State(state): State<AppState>) -> impl IntoResponse {
    if check_ledger_health(&state).await { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE }
}

/// GET /startupz
///
/// Delegates to the readiness probe. Ledger must be accessible.
pub async fn startupz_handler(State(state): State<AppState>) -> impl IntoResponse {
    readyz_handler(State(state)).await
}

/// GET /healthz
///
/// Returns JSON with service health, version, uptime, and Ledger status.
pub async fn healthz_handler(State(state): State<AppState>) -> impl IntoResponse {
    let ledger_healthy = check_ledger_health(&state).await;
    let uptime_seconds =
        SystemTime::now().duration_since(state.start_time).unwrap_or_default().as_secs();

    let status = if ledger_healthy { HealthStatus::Healthy } else { HealthStatus::Unhealthy };

    Json(HealthResponse {
        status,
        service: "inferadb-control",
        version: env!("CARGO_PKG_VERSION"),
        instance_id: state.worker_id,
        uptime_seconds,
        ledger_healthy,
        details: None,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;

    // ── livez_handler ──────────────────────────────────────────────

    #[tokio::test]
    async fn test_livez_handler_returns_200() {
        let response = livez_handler().await.into_response();

        assert_eq!(response.status(), StatusCode::OK);
    }

    // ── readyz_handler ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_readyz_handler_no_ledger_returns_200() {
        let state = crate::handlers::AppState::new_test();

        let response = readyz_handler(State(state)).await.into_response();

        assert_eq!(response.status(), StatusCode::OK);
    }

    // ── startupz_handler ───────────────────────────────────────────

    #[tokio::test]
    async fn test_startupz_handler_no_ledger_returns_200() {
        let state = crate::handlers::AppState::new_test();

        let response = startupz_handler(State(state)).await.into_response();

        assert_eq!(response.status(), StatusCode::OK);
    }

    // ── healthz_handler ────────────────────────────────────────────

    #[tokio::test]
    async fn test_healthz_handler_no_ledger_returns_healthy_json() {
        let state = crate::handlers::AppState::new_test();

        let response = healthz_handler(State(state)).await.into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "healthy");
        assert_eq!(json["service"], "inferadb-control");
        assert!(json["ledger_healthy"].as_bool().unwrap());
    }

    // ── HealthCache ──────────────────────────────────────────────

    #[test]
    fn test_health_cache_default_initializes_to_unchecked_state() {
        let cache = HealthCache::default();

        assert_eq!(cache.last_check_epoch_secs.load(Ordering::Relaxed), 0);
        assert!(!cache.last_result.load(Ordering::Relaxed));
    }

    #[test]
    fn test_health_cache_debug_contains_field_names() {
        let cache = HealthCache::default();

        let debug = format!("{cache:?}");

        assert!(debug.contains("HealthCache"));
        assert!(debug.contains("last_check_epoch_secs"));
        assert!(debug.contains("last_result"));
    }

    // ── check_ledger_health ────────────────────────────────────────

    #[tokio::test]
    async fn test_check_ledger_health_no_ledger_returns_true() {
        let state = crate::handlers::AppState::new_test();

        let result = check_ledger_health(&state).await;

        assert!(result);
    }

    #[tokio::test]
    async fn test_check_ledger_health_no_ledger_skips_cache() {
        let state = crate::handlers::AppState::new_test();

        check_ledger_health(&state).await;

        let cached_epoch = state.health_cache.last_check_epoch_secs.load(Ordering::Acquire);
        assert_eq!(cached_epoch, 0);
    }

    #[tokio::test]
    async fn test_check_ledger_health_no_ledger_stable_across_calls() {
        let state = crate::handlers::AppState::new_test();

        let result1 = check_ledger_health(&state).await;
        let result2 = check_ledger_health(&state).await;

        assert_eq!(result1, result2);
    }

    // ── HealthStatus serialization ───────────────────────────────

    #[test]
    fn test_health_status_serializes_to_lowercase() {
        let cases = [
            (HealthStatus::Healthy, "healthy"),
            (HealthStatus::Degraded, "degraded"),
            (HealthStatus::Unhealthy, "unhealthy"),
        ];

        for (variant, expected) in cases {
            let json = serde_json::to_value(&variant).unwrap();
            assert_eq!(json, expected, "serialize {expected}");
        }
    }

    #[test]
    fn test_health_status_deserializes_from_lowercase() {
        let cases = [
            (r#""healthy""#, "Healthy"),
            (r#""degraded""#, "Degraded"),
            (r#""unhealthy""#, "Unhealthy"),
        ];

        for (json_str, label) in cases {
            let status: HealthStatus = serde_json::from_str(json_str).unwrap();
            // Verify round-trip: serialize back and compare
            let reserialized = serde_json::to_value(&status).unwrap();
            assert_eq!(reserialized, json_str.trim_matches('"'), "deserialize {label}");
        }
    }

    // ── HealthResponse serialization ─────────────────────────────

    #[test]
    fn test_health_response_none_details_omitted() {
        let resp = HealthResponse {
            status: HealthStatus::Healthy,
            service: "test",
            version: "0.1.0",
            instance_id: 0,
            uptime_seconds: 100,
            ledger_healthy: true,
            details: None,
        };

        let json = serde_json::to_value(&resp).unwrap();

        assert!(json.get("details").is_none());
    }

    #[test]
    fn test_health_response_present_details_included() {
        let resp = HealthResponse {
            status: HealthStatus::Unhealthy,
            service: "test",
            version: "0.1.0",
            instance_id: 1,
            uptime_seconds: 0,
            ledger_healthy: false,
            details: Some("connection refused".to_string()),
        };

        let json = serde_json::to_value(&resp).unwrap();

        assert_eq!(json["details"], "connection refused");
    }

    #[test]
    fn test_health_response_serializes_all_fields() {
        let resp = HealthResponse {
            status: HealthStatus::Healthy,
            service: "inferadb-control",
            version: "1.2.3",
            instance_id: 5,
            uptime_seconds: 3600,
            ledger_healthy: true,
            details: None,
        };

        let json = serde_json::to_value(&resp).unwrap();

        assert_eq!(json["status"], "healthy");
        assert_eq!(json["service"], "inferadb-control");
        assert_eq!(json["version"], "1.2.3");
        assert_eq!(json["instance_id"], 5);
        assert_eq!(json["uptime_seconds"], 3600);
        assert_eq!(json["ledger_healthy"], true);
    }
}
