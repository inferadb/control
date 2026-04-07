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

/// Global Prometheus metrics handle, initialized once at startup.
static METRICS_HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

/// Installs the Prometheus metrics recorder.
///
/// Call once during application startup. Subsequent calls are no-ops.
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

/// GET /metrics
///
/// Returns collected metrics in Prometheus text exposition format.
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
    async fn test_metrics_handler_after_init_returns_200() {
        init_exporter();
        let response = metrics_handler().await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_init_exporter_multiple_calls_no_panic() {
        init_exporter();
        init_exporter();
    }
}
