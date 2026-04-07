//! HTTP request logging and metrics middleware.
//!
//! Records structured log entries and Prometheus metrics (request count,
//! duration histogram) for every HTTP request.

use std::{net::SocketAddr, time::Instant};

use axum::{
    extract::{ConnectInfo, MatchedPath, Request},
    middleware::Next,
    response::Response,
};
use inferadb_control_core::metrics;

use super::request_id::RequestId;

/// Logs each HTTP request and records Prometheus metrics.
///
/// Captures method, path, route pattern, status, duration, client IP, user
/// agent, and request ID. Records `http_requests_total` and
/// `http_request_duration_seconds` with method/path/status labels.
pub async fn logging_middleware(req: Request, next: Next) -> Response {
    let start = Instant::now();
    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = uri.path().to_string();

    let matched_path = req.extensions().get::<MatchedPath>().map(|mp| mp.as_str().to_string());

    let client_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip().to_string());

    let user_agent =
        req.headers().get("user-agent").and_then(|v| v.to_str().ok()).map(|s| s.to_string());

    let request_id = req.extensions().get::<RequestId>().map(|r| r.0.clone());

    let response = next.run(req).await;
    let duration = start.elapsed();
    let status = response.status().as_u16();

    tracing::info!(
        request_id = request_id.as_deref(),
        method = %method,
        path = %path,
        matched_path = matched_path.as_deref(),
        status = status,
        duration_ms = duration.as_millis() as u64,
        client_ip = client_ip.as_deref(),
        user_agent = user_agent.as_deref(),
        "HTTP request completed"
    );

    let metrics_path = matched_path.as_deref().unwrap_or(&path);
    metrics::record_http_request(method.as_str(), metrics_path, status, duration.as_secs_f64());

    response
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        middleware,
        response::IntoResponse,
        routing::get,
    };
    use tower::ServiceExt;

    use super::*;

    async fn ok_handler() -> impl IntoResponse {
        StatusCode::OK
    }

    async fn error_handler() -> impl IntoResponse {
        StatusCode::INTERNAL_SERVER_ERROR
    }

    fn app_with_logging(path: &str, handler: axum::routing::MethodRouter) -> Router {
        Router::new()
            .route(path, handler)
            .layer(middleware::from_fn(logging_middleware))
    }

    #[tokio::test]
    async fn test_logging_middleware_passes_through_ok_response() {
        let app = app_with_logging("/test", get(ok_handler));
        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_logging_middleware_passes_through_error_response() {
        let app = app_with_logging("/fail", get(error_handler));
        let request = Request::builder().uri("/fail").body(Body::empty()).unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_logging_middleware_preserves_response_body() {
        let app = app_with_logging(
            "/body",
            get(|| async { (StatusCode::OK, "hello") }),
        );
        let request = Request::builder().uri("/body").body(Body::empty()).unwrap();

        let response = app.oneshot(request).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), 1024).await.unwrap();
        assert_eq!(&body[..], b"hello");
    }
}
