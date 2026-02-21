use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Request};

/// Extract the client IP address from a request.
///
/// Checks proxy headers first, then falls back to the TCP peer address:
/// 1. `X-Forwarded-For` — first IP in the comma-separated list
/// 2. `X-Real-IP` — single IP set by the reverse proxy
/// 3. `ConnectInfo<SocketAddr>` — TCP peer address (direct connection)
pub fn extract_client_ip(req: &Request) -> Option<String> {
    let headers = req.headers();

    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .or_else(|| {
            req.extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ConnectInfo(addr)| addr.ip().to_string())
        })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use axum::{body::Body, http::Request};

    use super::*;

    fn request_with_headers(headers: &[(&str, &str)]) -> Request<Body> {
        let mut builder = Request::builder().uri("/test");
        for (key, value) in headers {
            builder = builder.header(*key, *value);
        }
        builder.body(Body::empty()).unwrap()
    }

    fn request_with_connect_info(addr: SocketAddr) -> Request<Body> {
        let mut req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        req.extensions_mut().insert(ConnectInfo(addr));
        req
    }

    #[test]
    fn returns_x_forwarded_for_first_ip() {
        let req = request_with_headers(&[(
            "x-forwarded-for",
            "203.0.113.50, 70.41.3.18, 150.172.238.178",
        )]);
        assert_eq!(extract_client_ip(&req).as_deref(), Some("203.0.113.50"));
    }

    #[test]
    fn returns_x_forwarded_for_single_ip() {
        let req = request_with_headers(&[("x-forwarded-for", "203.0.113.50")]);
        assert_eq!(extract_client_ip(&req).as_deref(), Some("203.0.113.50"));
    }

    #[test]
    fn returns_x_real_ip_when_no_forwarded_for() {
        let req = request_with_headers(&[("x-real-ip", "198.51.100.42")]);
        assert_eq!(extract_client_ip(&req).as_deref(), Some("198.51.100.42"));
    }

    #[test]
    fn prefers_x_forwarded_for_over_x_real_ip() {
        let req = request_with_headers(&[
            ("x-forwarded-for", "203.0.113.50"),
            ("x-real-ip", "198.51.100.42"),
        ]);
        assert_eq!(extract_client_ip(&req).as_deref(), Some("203.0.113.50"));
    }

    #[test]
    fn falls_back_to_connect_info() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
        let req = request_with_connect_info(addr);
        assert_eq!(extract_client_ip(&req).as_deref(), Some("127.0.0.1"));
    }

    #[test]
    fn returns_none_without_any_source() {
        let req = request_with_headers(&[]);
        assert_eq!(extract_client_ip(&req), None);
    }

    #[test]
    fn skips_empty_forwarded_for() {
        let req = request_with_headers(&[("x-forwarded-for", "")]);
        assert_eq!(extract_client_ip(&req), None);
    }

    #[test]
    fn skips_empty_real_ip() {
        let req = request_with_headers(&[("x-real-ip", "  ")]);
        assert_eq!(extract_client_ip(&req), None);
    }

    #[test]
    fn trims_whitespace_from_forwarded_for() {
        let req = request_with_headers(&[("x-forwarded-for", "  203.0.113.50  , 70.41.3.18")]);
        assert_eq!(extract_client_ip(&req).as_deref(), Some("203.0.113.50"));
    }

    #[test]
    fn trims_whitespace_from_real_ip() {
        let req = request_with_headers(&[("x-real-ip", "  198.51.100.42  ")]);
        assert_eq!(extract_client_ip(&req).as_deref(), Some("198.51.100.42"));
    }

    #[test]
    fn prefers_headers_over_connect_info() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 12345);
        let mut req = request_with_headers(&[("x-forwarded-for", "203.0.113.50")]);
        req.extensions_mut().insert(ConnectInfo(addr));
        assert_eq!(extract_client_ip(&req).as_deref(), Some("203.0.113.50"));
    }
}
