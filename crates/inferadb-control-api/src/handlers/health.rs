//! Health check endpoints for Kubernetes probes
//!
//! Provides standard Kubernetes health endpoints following the API server conventions:
//! - `/livez` - Liveness probe (is the process alive?)
//! - `/readyz` - Readiness probe (can it accept traffic?)
//! - `/startupz` - Startup probe (has initialization completed?)
//! - `/healthz` - Detailed health status for debugging/monitoring

use std::time::SystemTime;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use inferadb_control_storage::StorageBackend;
use serde::{Deserialize, Serialize};

use crate::handlers::AppState;

/// Health check status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Detailed health status response
#[derive(Debug, Clone, Serialize)]
pub struct HealthResponse {
    /// Overall health status
    pub status: HealthStatus,

    /// Service name
    pub service: String,

    /// Service version
    pub version: String,

    /// Instance identifier (worker ID)
    pub instance_id: u16,

    /// Uptime in seconds
    pub uptime_seconds: u64,

    /// Whether storage backend is healthy
    pub storage_healthy: bool,

    /// Whether this instance is the leader
    pub is_leader: bool,

    /// Additional details (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Liveness probe handler (`/livez`)
///
/// Indicates whether the service is running. If this fails, Kubernetes will restart the pod.
/// Always returns 200 OK if the server is running.
///
/// Returns:
/// - 200 OK if the service is alive
/// - 503 Service Unavailable if the service is dead (unreachable in practice)
pub async fn livez_handler() -> impl IntoResponse {
    StatusCode::OK
}

/// Readiness probe handler (`/readyz`)
///
/// Indicates whether the service is ready to accept traffic.
/// If this fails, Kubernetes will remove the pod from the load balancer.
///
/// Checks:
/// - Storage backend is accessible
///
/// Returns:
/// - 200 OK if the service is ready
/// - 503 Service Unavailable if the service is not ready
pub async fn readyz_handler(State(state): State<AppState>) -> impl IntoResponse {
    // Check storage health by doing a simple operation
    let storage_healthy = state.storage.get(b"health_check".as_ref()).await.is_ok();

    if storage_healthy { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE }
}

/// Startup probe handler (`/startupz`)
///
/// Indicates whether the service has completed initialization.
/// Kubernetes will not send traffic until this succeeds.
///
/// Returns:
/// - 200 OK if startup is complete
/// - 503 Service Unavailable if still initializing
pub async fn startupz_handler(State(state): State<AppState>) -> impl IntoResponse {
    // For now, same as readiness (storage must be accessible)
    readyz_handler(State(state)).await
}

/// Detailed health check handler (`/healthz`)
///
/// Returns comprehensive health information including component status.
/// Useful for debugging and monitoring dashboards.
///
/// Returns JSON with detailed health status including:
/// - Overall status (healthy/degraded/unhealthy)
/// - Service name and version
/// - Uptime in seconds
/// - Storage and leader election status
pub async fn healthz_handler(State(state): State<AppState>) -> impl IntoResponse {
    // Check storage health
    let storage_healthy = state.storage.get(b"health_check".as_ref()).await.is_ok();

    // Get instance details from state
    let instance_id = state.worker_id;
    let start_time = state.start_time;
    let is_leader = state
        .leader
        .as_ref()
        .map(|l| {
            let leader_check = l.clone();
            // Use tokio::task::block_in_place to avoid blocking the runtime
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(leader_check.is_leader())
            })
        })
        .unwrap_or(false);

    // Calculate uptime
    let uptime_seconds = SystemTime::now().duration_since(start_time).unwrap_or_default().as_secs();

    // Determine overall status
    let status = if storage_healthy { HealthStatus::Healthy } else { HealthStatus::Unhealthy };

    let response = HealthResponse {
        status,
        service: "inferadb-control".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        instance_id,
        uptime_seconds,
        storage_healthy,
        is_leader,
        details: None,
    };

    Json(response)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use inferadb_control_storage::Backend;

    use super::*;

    #[tokio::test]
    async fn test_livez() {
        let response = livez_handler().await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_readyz_with_healthy_storage() {
        let storage = Arc::new(Backend::memory());
        let state = crate::handlers::AppState::new_test(storage);

        let response = readyz_handler(State(state)).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_healthz() {
        let storage = Arc::new(Backend::memory());
        let state = crate::handlers::AppState::new_test(storage);

        let response = healthz_handler(State(state)).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
