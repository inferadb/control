use std::sync::OnceLock;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

static METRICS_HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

/// Initialize Prometheus metrics exporter
///
/// This should be called once during application startup.
/// It sets up the Prometheus exporter that will collect and expose metrics.
pub fn init_exporter() {
    METRICS_HANDLE.get_or_init(|| {
        // Metrics recorder installation failure is unrecoverable at startup
        #[allow(clippy::expect_used)]
        let handle = PrometheusBuilder::new()
            .install_recorder()
            .expect("Failed to install Prometheus recorder");

        // Initialize metric descriptions
        inferadb_control_core::metrics::init();

        handle
    });
}

/// Prometheus metrics endpoint
///
/// Returns metrics in Prometheus text exposition format.
///
/// GET /metrics
pub async fn metrics_handler() -> Response {
    // Get the Prometheus handle to render metrics
    match METRICS_HANDLE.get() {
        Some(handle) => {
            let metrics = handle.render();
            (StatusCode::OK, metrics).into_response()
        },
        None => {
            // If exporter wasn't initialized, return error
            (StatusCode::INTERNAL_SERVER_ERROR, "Metrics exporter not initialized").into_response()
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_metrics_handler() {
        init_exporter();
        let response = metrics_handler().await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_init_exporter() {
        // Should not panic when called multiple times
        init_exporter();
        init_exporter();
    }
}
