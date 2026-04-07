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

    async fn get_response() -> Response {
        let app = test_router();
        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        app.oneshot(req).await.unwrap()
    }

    #[tokio::test]
    async fn test_security_headers_all_values() {
        let response = get_response().await;
        assert_eq!(response.status(), StatusCode::OK);

        let expected: &[(&str, &str)] = &[
            ("x-content-type-options", "nosniff"),
            ("x-frame-options", "DENY"),
            ("cache-control", "no-store"),
            ("strict-transport-security", "max-age=31536000; includeSubDomains"),
            ("referrer-policy", "no-referrer"),
            ("content-security-policy", "default-src 'none'"),
        ];

        for (header, value) in expected {
            let actual = response
                .headers()
                .get(*header)
                .unwrap_or_else(|| panic!("missing header: {header}"));
            assert_eq!(
                actual.to_str().unwrap(),
                *value,
                "header {header} mismatch"
            );
        }
    }

    #[tokio::test]
    async fn test_security_headers_hsts_set_unconditionally() {
        // HSTS is set regardless of Host header (RFC 6797 section 8.1:
        // browsers ignore it over plain HTTP, so it's harmless on localhost).
        let app = test_router();
        let req = Request::builder()
            .uri("/test")
            .header("host", "localhost:9090")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(
            response.headers().get("strict-transport-security").unwrap().to_str().unwrap(),
            "max-age=31536000; includeSubDomains",
        );
    }

    #[tokio::test]
    async fn test_security_headers_do_not_override_status() {
        // Middleware should not alter the inner handler's status code.
        let app = Router::new()
            .route(
                "/err",
                get(|| async { (StatusCode::NOT_FOUND, "nope") }),
            )
            .layer(middleware::from_fn(security_headers_middleware));

        let req = Request::builder().uri("/err").body(Body::empty()).unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        // Headers still applied even on error responses
        assert_eq!(response.headers().get("x-frame-options").unwrap(), "DENY");
    }
}
