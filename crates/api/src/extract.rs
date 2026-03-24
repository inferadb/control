//! Client IP extraction utilities.
//!
//! Provides proxy-aware and direct-connection IP extraction from HTTP
//! requests, used by rate limiting and audit logging.

use std::{net::SocketAddr, num::NonZeroU8};

use axum::extract::{ConnectInfo, Request};

/// Extracts the client IP address from a request.
///
/// Behavior depends on `trusted_proxy_depth`:
///
/// - `Some(n)`: Takes the client IP from `X-Forwarded-For` by skipping the `n` rightmost entries
///   (which were appended by trusted proxy infrastructure). Returns `None` if the header has fewer
///   entries than required. Falls back to `ConnectInfo` only when the header is absent.
///
/// - `None` (direct connection mode): Uses only `ConnectInfo` (TCP peer address). This is the safe
///   default when not behind a reverse proxy.
pub fn extract_client_ip(req: &Request, trusted_proxy_depth: Option<NonZeroU8>) -> Option<String> {
    match trusted_proxy_depth {
        Some(depth) => extract_with_proxy_depth(req, depth),
        None => extract_direct(req),
    }
}

/// Extracts IP using rightmost-nth selection from `X-Forwarded-For`.
///
/// With `depth=1` (one trusted proxy), the proxy appended the rightmost entry,
/// so the client IP is at position `len - 2` (just before the proxy entry).
/// With `depth=2` (two proxies), it's at `len - 3`, etc.
fn extract_with_proxy_depth(req: &Request, depth: NonZeroU8) -> Option<String> {
    let headers = req.headers();

    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        let ips: Vec<&str> = xff.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();

        // The real client IP is at position len - depth - 1 (just before proxy entries).
        let index = ips.len().checked_sub(depth.get() as usize + 1)?;
        let ip = ips.get(index)?;
        return Some((*ip).to_string());
    }

    // Fall back to ConnectInfo if X-Forwarded-For is absent
    req.extensions().get::<ConnectInfo<SocketAddr>>().map(|ConnectInfo(addr)| addr.ip().to_string())
}

/// Extracts IP in direct connection mode (no trusted proxies).
///
/// Uses only `ConnectInfo` (TCP peer address). Proxy headers are ignored
/// because without trusted proxy configuration they are freely spoofable.
fn extract_direct(req: &Request) -> Option<String> {
    req.extensions().get::<ConnectInfo<SocketAddr>>().map(|ConnectInfo(addr)| addr.ip().to_string())
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

    // ── Direct mode (trusted_proxy_depth = None) ──────────────────

    #[test]
    fn direct_mode_prefers_connect_info() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 12345);
        let mut req = request_with_headers(&[("x-forwarded-for", "203.0.113.50")]);
        req.extensions_mut().insert(ConnectInfo(addr));
        assert_eq!(extract_client_ip(&req, None).as_deref(), Some("10.0.0.1"));
    }

    #[test]
    fn direct_mode_ignores_proxy_headers() {
        let req = request_with_headers(&[
            ("x-forwarded-for", "203.0.113.50"),
            ("x-real-ip", "198.51.100.42"),
        ]);
        // Without ConnectInfo, direct mode returns None — proxy headers are untrusted
        assert_eq!(extract_client_ip(&req, None), None);
    }

    #[test]
    fn direct_mode_returns_none_without_any_source() {
        let req = request_with_headers(&[]);
        assert_eq!(extract_client_ip(&req, None), None);
    }

    // ── Proxy mode (trusted_proxy_depth = Some(n)) ────────────────

    fn depth(n: u8) -> Option<NonZeroU8> {
        Some(NonZeroU8::new(n).unwrap())
    }

    #[test]
    fn proxy_depth_1_takes_client_ip() {
        let req =
            request_with_headers(&[("x-forwarded-for", "spoofed.ip, 203.0.113.50, 10.0.0.1")]);
        // depth=1: one trusted proxy appended 10.0.0.1, client is 203.0.113.50
        assert_eq!(extract_client_ip(&req, depth(1)).as_deref(), Some("203.0.113.50"));
    }

    #[test]
    fn proxy_depth_2_takes_second_from_right() {
        let req = request_with_headers(&[(
            "x-forwarded-for",
            "spoofed.ip, 203.0.113.50, 10.0.0.1, 10.0.0.2",
        )]);
        // depth=2: two proxies appended 10.0.0.1 and 10.0.0.2
        assert_eq!(extract_client_ip(&req, depth(2)).as_deref(), Some("203.0.113.50"));
    }

    #[test]
    fn proxy_depth_with_single_ip_falls_back() {
        let req = request_with_headers(&[("x-forwarded-for", "203.0.113.50")]);
        // depth=1 with single IP: the proxy appended this IP, so there's no client
        // IP before it. Falls back to None (no ConnectInfo set).
        assert_eq!(extract_client_ip(&req, depth(1)), None);
    }

    #[test]
    fn proxy_depth_with_two_ips() {
        let req = request_with_headers(&[("x-forwarded-for", "203.0.113.50, 10.0.0.1")]);
        // depth=1: proxy added 10.0.0.1, client is 203.0.113.50
        assert_eq!(extract_client_ip(&req, depth(1)).as_deref(), Some("203.0.113.50"));
    }

    #[test]
    fn proxy_depth_exceeds_ip_count_returns_none() {
        let req = request_with_headers(&[("x-forwarded-for", "203.0.113.50")]);
        // depth=3 but only 1 IP — can't extract
        assert_eq!(extract_client_ip(&req, depth(3)), None);
    }

    #[test]
    fn proxy_mode_falls_back_to_connect_info_without_xff() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
        let req = request_with_connect_info(addr);
        assert_eq!(extract_client_ip(&req, depth(1)).as_deref(), Some("127.0.0.1"));
    }

    #[test]
    fn proxy_mode_trims_whitespace() {
        let req = request_with_headers(&[("x-forwarded-for", "  203.0.113.50  ,  10.0.0.1  ")]);
        assert_eq!(extract_client_ip(&req, depth(1)).as_deref(), Some("203.0.113.50"));
    }

    #[test]
    fn proxy_mode_skips_empty_xff() {
        let req = request_with_headers(&[("x-forwarded-for", "")]);
        assert_eq!(extract_client_ip(&req, depth(1)), None);
    }
}
