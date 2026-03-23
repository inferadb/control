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

/// Health check status.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Detailed health status response.
#[derive(Debug, Clone, Serialize)]
pub struct HealthResponse {
    pub status: HealthStatus,
    pub service: String,
    pub version: String,
    pub instance_id: u16,
    pub uptime_seconds: u64,
    pub ledger_healthy: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Cached health check state. Prevents probe bursts from cascading to Ledger.
///
/// Stored in `AppState` for test isolation. Uses lock-free atomics so concurrent
/// probes don't block each other. The cache is best-effort: concurrent callers
/// may occasionally duplicate a health check, which is acceptable for probes.
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

/// Checks Ledger SDK health with 5-second caching.
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
/// Same as readiness — Ledger must be accessible.
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
    use super::*;

    #[tokio::test]
    async fn test_livez() {
        let response = livez_handler().await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_readyz_no_ledger() {
        let state = crate::handlers::AppState::new_test();
        // new_test() has no Ledger configured — should be healthy (dev-mode fallback)
        let response = readyz_handler(State(state)).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_healthz_no_ledger() {
        let state = crate::handlers::AppState::new_test();
        let response = healthz_handler(State(state)).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
