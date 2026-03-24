//! Security response headers middleware.
//!
//! Sets defense-in-depth headers on all responses:
//! - `X-Content-Type-Options: nosniff` — prevents MIME-type sniffing
//! - `X-Frame-Options: DENY` — prevents clickjacking via iframes
//! - `Cache-Control: no-store` — prevents caching of sensitive API responses
//! - `Strict-Transport-Security` — enforces HTTPS (browsers ignore this over plain HTTP per RFC
//!   6797)
//! - `Referrer-Policy: no-referrer` — prevents leaking URLs in referer headers
//! - `Content-Security-Policy: default-src 'none'` — disallows all resource loading (JSON API)

use axum::{extract::Request, http::HeaderValue, middleware::Next, response::Response};

/// Adds security headers to all responses.
///
/// HSTS is set unconditionally. Per RFC 6797 section 8.1, user agents ignore
/// `Strict-Transport-Security` over insecure transport, so this is harmless
/// on localhost and avoids relying on the `Host` header for a security decision.
pub async fn security_headers_middleware(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    headers.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert("cache-control", HeaderValue::from_static("no-store"));
    headers.insert(
        "strict-transport-security",
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert("content-security-policy", HeaderValue::from_static("default-src 'none'"));

    response
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        middleware,
        routing::get,
    };
    use tower::ServiceExt;

    use super::*;

    async fn ok_handler() -> &'static str {
        "ok"
    }

    fn test_router() -> Router {
        Router::new()
            .route("/test", get(ok_handler))
            .layer(middleware::from_fn(security_headers_middleware))
    }

    #[tokio::test]
    async fn sets_security_headers() {
        let app = test_router();
        let req = Request::builder()
            .uri("/test")
            .header("host", "api.inferadb.com")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get("x-content-type-options").unwrap(), "nosniff");
        assert_eq!(response.headers().get("x-frame-options").unwrap(), "DENY");
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
        assert!(response.headers().get("strict-transport-security").is_some());
        assert_eq!(response.headers().get("referrer-policy").unwrap(), "no-referrer");
        assert_eq!(
            response.headers().get("content-security-policy").unwrap(),
            "default-src 'none'"
        );
    }

    #[tokio::test]
    async fn sets_hsts_for_localhost() {
        let app = test_router();
        let req = Request::builder()
            .uri("/test")
            .header("host", "localhost:9090")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get("x-content-type-options").unwrap(), "nosniff");
        // HSTS is always set — browsers ignore it over plain HTTP per RFC 6797 §8.1
        assert!(response.headers().get("strict-transport-security").is_some());
    }
}
