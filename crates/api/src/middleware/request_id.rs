//! Request ID middleware.
//!
//! Generates or propagates a unique request ID for every HTTP request.
//! The ID is added to request extensions, the tracing span, and the
//! `X-Request-ID` response header for end-to-end correlation.

use axum::{
    extract::Request,
    http::{HeaderValue, header::HeaderName},
    middleware::Next,
    response::Response,
};
use uuid::Uuid;

/// Header name for the request correlation ID.
static X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

/// Unique identifier for an HTTP request, stored in request extensions.
///
/// Handlers and middleware access this via `req.extensions().get::<RequestId>()`.
#[derive(Debug, Clone)]
pub struct RequestId(pub String);

/// Assigns a request ID to every request.
///
/// Propagates an incoming `X-Request-ID` header for end-to-end correlation,
/// or generates a UUID v4. The ID is inserted into request extensions, a
/// tracing span, and the `X-Request-ID` response header.
pub async fn request_id_middleware(mut req: Request, next: Next) -> Response {
    let id = req
        .headers()
        .get(&X_REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .filter(|s| {
            s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
        .map(|s| s.to_string())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    req.extensions_mut().insert(RequestId(id.clone()));

    let span = tracing::info_span!("request", request_id = %id);
    let _guard = span.enter();

    let mut response = {
        // Drop the span guard before awaiting so the span covers
        // the full request lifecycle via the instrumented future.
        drop(_guard);
        let fut = next.run(req);
        tracing::Instrument::instrument(fut, span).await
    };

    if let Ok(value) = HeaderValue::from_str(&id) {
        response.headers_mut().insert(X_REQUEST_ID.clone(), value);
    }

    response
}
