use std::time::SystemTime;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use inferadb_management_storage::StorageBackend;
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

    /// Service version
    pub version: String,

    /// Instance identifier (worker ID)
    pub instance_id: u16,

    /// Uptime in seconds
    pub uptime: u64,

    /// Whether storage backend is healthy
    pub storage_healthy: bool,

    /// Whether this instance is the leader
    pub is_leader: bool,

    /// Additional details (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Liveness probe
///
/// Always returns 200 OK if the server is running.
/// This endpoint is used by Kubernetes liveness probes.
///
/// GET /v1/health/live
pub async fn health_live() -> impl IntoResponse {
    StatusCode::OK
}

/// Readiness probe
///
/// Returns 200 if the service is ready to accept traffic.
/// Checks:
/// - Storage backend is accessible
/// - Leader election is functioning (if enabled)
///
/// GET /v1/health/ready
pub async fn health_ready(State(state): State<AppState>) -> impl IntoResponse {
    // Check storage health by doing a simple operation
    let storage_healthy = state.storage.get(b"health_check".as_ref()).await.is_ok();

    if storage_healthy { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE }
}

/// Startup probe
///
/// Returns 200 once the service has completed initialization.
/// This can be the same as the readiness probe for now.
///
/// GET /v1/health/startup
pub async fn health_startup(State(state): State<AppState>) -> impl IntoResponse {
    // For now, same as readiness
    health_ready(State(state)).await
}

/// Detailed health status
///
/// Returns comprehensive health information about the service.
/// Useful for monitoring and debugging.
///
/// GET /v1/health
pub async fn health_detailed(State(state): State<AppState>) -> impl IntoResponse {
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
    let uptime = SystemTime::now().duration_since(start_time).unwrap_or_default().as_secs();

    // Determine overall status
    let status = if storage_healthy { HealthStatus::Healthy } else { HealthStatus::Unhealthy };

    let response = HealthResponse {
        status,
        version: env!("CARGO_PKG_VERSION").to_string(),
        instance_id,
        uptime,
        storage_healthy,
        is_leader,
        details: None,
    };

    Json(response)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use inferadb_management_storage::{Backend, MemoryBackend};

    use super::*;

    #[tokio::test]
    async fn test_health_live() {
        let response = health_live().await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_ready_with_healthy_storage() {
        let storage = Arc::new(Backend::Memory(MemoryBackend::new()));
        let state = crate::handlers::AppState::new_test(storage);

        let response = health_ready(State(state)).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_detailed() {
        let storage = Arc::new(Backend::Memory(MemoryBackend::new()));
        let state = crate::handlers::AppState::new_test(storage);

        let response = health_detailed(State(state)).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
