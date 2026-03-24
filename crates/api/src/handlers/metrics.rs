//! Prometheus metrics exporter and handler.
//!
//! Initializes the Prometheus metrics recorder at startup and serves
//! collected metrics in text exposition format on `GET /metrics`.

use std::sync::OnceLock;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

static METRICS_HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

/// Initializes the Prometheus metrics exporter.
///
/// Must be called once during application startup. Sets up the recorder
/// that collects and exposes metrics via the `/metrics` endpoint.
pub fn init_exporter() {
    METRICS_HANDLE.get_or_init(|| {
        // Metrics recorder installation failure is unrecoverable at startup
        #[allow(clippy::expect_used)]
        let handle = PrometheusBuilder::new()
            .install_recorder()
            .expect("Failed to install Prometheus recorder");

        inferadb_control_core::metrics::init();

        handle
    });
}

/// Handles the Prometheus metrics endpoint (`GET /metrics`).
///
/// Returns metrics in Prometheus text exposition format.
pub async fn metrics_handler() -> Response {
    match METRICS_HANDLE.get() {
        Some(handle) => {
            let metrics = handle.render();
            (StatusCode::OK, metrics).into_response()
        },
        None => {
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
