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

static X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

/// A unique identifier for the current request.
#[derive(Debug, Clone)]
pub struct RequestId(pub String);

/// Middleware that assigns a request ID to every request.
///
/// If the caller sends an `X-Request-ID` header, that value is used
/// (enabling end-to-end correlation across services). Otherwise a
/// new UUID v4 is generated.
///
/// The ID is inserted into:
/// - Request extensions (accessible by downstream handlers/middleware)
/// - A tracing span field
/// - The `X-Request-ID` response header
pub async fn request_id_middleware(mut req: Request, next: Next) -> Response {
    let id = req
        .headers()
        .get(&X_REQUEST_ID)
        .and_then(|v| v.to_str().ok())
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
