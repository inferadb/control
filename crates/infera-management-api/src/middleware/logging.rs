use axum::{
    extract::{ConnectInfo, MatchedPath, Request},
    middleware::Next,
    response::Response,
};
use infera_management_core::metrics;
use std::net::SocketAddr;
use std::time::Instant;

/// Logging and metrics middleware for HTTP requests
///
/// Logs all incoming HTTP requests with structured fields and records Prometheus metrics:
/// - method: HTTP method
/// - path: Request path
/// - matched_path: Route pattern that matched
/// - status: Response status code
/// - duration_ms: Request duration in milliseconds
/// - client_ip: Client IP address
/// - user_agent: User agent string
///
/// Metrics recorded:
/// - http_requests_total: Counter with method, path, and status labels
/// - http_request_duration_seconds: Histogram with method and path labels
///
/// Example log output (JSON):
/// ```json
/// {
///   "timestamp": "2024-01-15T10:30:45Z",
///   "level": "INFO",
///   "target": "infera_management_api::middleware::logging",
///   "fields": {
///     "method": "POST",
///     "path": "/v1/auth/login",
///     "matched_path": "/v1/auth/login",
///     "status": 200,
///     "duration_ms": 42,
///     "client_ip": "192.168.1.1",
///     "user_agent": "Mozilla/5.0..."
///   },
///   "message": "HTTP request completed"
/// }
/// ```
pub async fn logging_middleware(req: Request, next: Next) -> Response {
    let start = Instant::now();
    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = uri.path().to_string();

    // Extract matched path (route pattern)
    let matched_path = req
        .extensions()
        .get::<MatchedPath>()
        .map(|mp| mp.as_str().to_string());

    // Extract client IP
    let client_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip().to_string());

    // Extract user agent
    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Process request
    let response = next.run(req).await;

    // Calculate duration
    let duration = start.elapsed();
    let status = response.status().as_u16();

    // Log the request with structured fields
    tracing::info!(
        method = %method,
        path = %path,
        matched_path = matched_path.as_deref(),
        status = status,
        duration_ms = duration.as_millis() as u64,
        client_ip = client_ip.as_deref(),
        user_agent = user_agent.as_deref(),
        "HTTP request completed"
    );

    // Record metrics
    let metrics_path = matched_path.as_deref().unwrap_or(&path);
    metrics::record_http_request(
        method.as_str(),
        metrics_path,
        status,
        duration.as_secs_f64(),
    );

    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        middleware,
        response::IntoResponse,
        routing::get,
        Router,
    };
    use tower::ServiceExt;

    async fn test_handler() -> impl IntoResponse {
        StatusCode::OK
    }

    #[tokio::test]
    async fn test_logging_middleware() {
        let app = Router::new()
            .route("/test", get(test_handler))
            .layer(middleware::from_fn(logging_middleware));

        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
