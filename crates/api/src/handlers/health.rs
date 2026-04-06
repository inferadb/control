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
    pub service: String,
    /// Crate version from `Cargo.toml`.
    pub version: String,
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
    last_check_epoch_secs: AtomicU64,
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

/// Checks Ledger SDK health, caching the result for 5 seconds.
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

/// Liveness probe handler (`/livez`).
///
/// Always returns 200 OK if the server is running.
pub async fn livez_handler() -> impl IntoResponse {
    StatusCode::OK
}

/// Readiness probe handler (`/readyz`).
///
/// Checks whether the Ledger SDK client is reachable.
pub async fn readyz_handler(State(state): State<AppState>) -> impl IntoResponse {
    if check_ledger_health(&state).await { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE }
}

/// Startup probe handler (`/startupz`).
///
/// Delegates to the readiness probe; Ledger must be accessible.
pub async fn startupz_handler(State(state): State<AppState>) -> impl IntoResponse {
    readyz_handler(State(state)).await
}

/// Detailed health check handler (`/healthz`).
///
/// Returns JSON with service health, version, uptime, and Ledger status.
pub async fn healthz_handler(State(state): State<AppState>) -> impl IntoResponse {
    let ledger_healthy = check_ledger_health(&state).await;
    let uptime_seconds =
        SystemTime::now().duration_since(state.start_time).unwrap_or_default().as_secs();

    let status = if ledger_healthy { HealthStatus::Healthy } else { HealthStatus::Unhealthy };

    Json(HealthResponse {
        status,
        service: "inferadb-control".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
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

    #[tokio::test]
    async fn test_livez() {
        let response = livez_handler().await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_readyz_no_ledger() {
        let state = crate::handlers::AppState::new_test();
        let response = readyz_handler(State(state)).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_healthz_no_ledger() {
        let state = crate::handlers::AppState::new_test();
        let response = healthz_handler(State(state)).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_startupz_delegates_to_readyz() {
        let state = crate::handlers::AppState::new_test();
        let response = startupz_handler(State(state)).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    // ── HealthCache ──────────────────────────────────────────────

    #[test]
    fn health_cache_default_is_expired() {
        let cache = HealthCache::default();
        assert_eq!(cache.last_check_epoch_secs.load(Ordering::Relaxed), 0);
        assert!(!cache.last_result.load(Ordering::Relaxed));
    }

    #[test]
    fn health_cache_debug_format() {
        let cache = HealthCache::default();
        let debug = format!("{cache:?}");
        assert!(debug.contains("HealthCache"));
        assert!(debug.contains("last_check_epoch_secs"));
        assert!(debug.contains("last_result"));
    }

    #[tokio::test]
    async fn check_ledger_health_no_ledger_returns_true() {
        let state = crate::handlers::AppState::new_test();
        // No ledger configured (dev-mode) => returns true without caching
        let result = check_ledger_health(&state).await;
        assert!(result);
        // Cache epoch stays at 0 because the early return skips the cache
        let cached_epoch = state.health_cache.last_check_epoch_secs.load(Ordering::Acquire);
        assert_eq!(cached_epoch, 0);
    }

    #[tokio::test]
    async fn check_ledger_health_no_ledger_stable_across_calls() {
        let state = crate::handlers::AppState::new_test();
        let result1 = check_ledger_health(&state).await;
        let result2 = check_ledger_health(&state).await;
        assert!(result1);
        assert_eq!(result1, result2);
    }

    // ── HealthStatus serialization ───────────────────────────────

    #[test]
    fn health_status_serializes_lowercase() {
        let healthy = serde_json::to_value(HealthStatus::Healthy).unwrap();
        assert_eq!(healthy, "healthy");
        let degraded = serde_json::to_value(HealthStatus::Degraded).unwrap();
        assert_eq!(degraded, "degraded");
        let unhealthy = serde_json::to_value(HealthStatus::Unhealthy).unwrap();
        assert_eq!(unhealthy, "unhealthy");
    }

    #[test]
    fn health_status_deserializes() {
        let status: HealthStatus = serde_json::from_str(r#""healthy""#).unwrap();
        assert!(matches!(status, HealthStatus::Healthy));
        let status: HealthStatus = serde_json::from_str(r#""degraded""#).unwrap();
        assert!(matches!(status, HealthStatus::Degraded));
    }

    #[test]
    fn health_response_omits_none_details() {
        let resp = HealthResponse {
            status: HealthStatus::Healthy,
            service: "test".to_string(),
            version: "0.1.0".to_string(),
            instance_id: 0,
            uptime_seconds: 100,
            ledger_healthy: true,
            details: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("details").is_none());
    }

    #[test]
    fn health_response_includes_details_when_present() {
        let resp = HealthResponse {
            status: HealthStatus::Unhealthy,
            service: "test".to_string(),
            version: "0.1.0".to_string(),
            instance_id: 1,
            uptime_seconds: 0,
            ledger_healthy: false,
            details: Some("connection refused".to_string()),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["details"], "connection refused");
    }
}
