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
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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

    fn depth(n: u8) -> Option<NonZeroU8> {
        Some(NonZeroU8::new(n).unwrap())
    }

    // ── Direct mode (trusted_proxy_depth = None) ──────────────────

    #[test]
    fn test_extract_ip_direct_mode_uses_connect_info() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 12345);
        let mut req = request_with_headers(&[("x-forwarded-for", "203.0.113.50")]);
        req.extensions_mut().insert(ConnectInfo(addr));
        // Direct mode ignores XFF, uses TCP peer address
        assert_eq!(extract_client_ip(&req, None).as_deref(), Some("10.0.0.1"));
    }

    #[test]
    fn test_extract_ip_direct_mode_ignores_all_proxy_headers() {
        let req = request_with_headers(&[
            ("x-forwarded-for", "203.0.113.50"),
            ("x-real-ip", "198.51.100.42"),
        ]);
        assert_eq!(extract_client_ip(&req, None), None);
    }

    #[test]
    fn test_extract_ip_direct_mode_no_source_returns_none() {
        let req = request_with_headers(&[]);
        assert_eq!(extract_client_ip(&req, None), None);
    }

    #[test]
    fn test_extract_ip_direct_mode_ipv6_connect_info() {
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080);
        let req = request_with_connect_info(addr);
        assert_eq!(extract_client_ip(&req, None).as_deref(), Some("::1"));
    }

    // ── Proxy mode (trusted_proxy_depth = Some(n)) ────────────────

    #[test]
    fn test_extract_ip_proxy_depth1_returns_client_ip() {
        let req =
            request_with_headers(&[("x-forwarded-for", "spoofed.ip, 203.0.113.50, 10.0.0.1")]);
        assert_eq!(extract_client_ip(&req, depth(1)).as_deref(), Some("203.0.113.50"));
    }

    #[test]
    fn test_extract_ip_proxy_depth2_skips_two_proxies() {
        let req = request_with_headers(&[(
            "x-forwarded-for",
            "spoofed.ip, 203.0.113.50, 10.0.0.1, 10.0.0.2",
        )]);
        assert_eq!(extract_client_ip(&req, depth(2)).as_deref(), Some("203.0.113.50"));
    }

    #[test]
    fn test_extract_ip_proxy_single_ip_insufficient_depth_returns_none() {
        let req = request_with_headers(&[("x-forwarded-for", "203.0.113.50")]);
        // depth=1 with single IP: only the proxy entry exists, no client before it
        assert_eq!(extract_client_ip(&req, depth(1)), None);
    }

    #[test]
    fn test_extract_ip_proxy_two_ips_depth1_returns_first() {
        let req = request_with_headers(&[("x-forwarded-for", "203.0.113.50, 10.0.0.1")]);
        assert_eq!(extract_client_ip(&req, depth(1)).as_deref(), Some("203.0.113.50"));
    }

    #[test]
    fn test_extract_ip_proxy_depth_exceeds_count_returns_none() {
        let req = request_with_headers(&[("x-forwarded-for", "203.0.113.50")]);
        assert_eq!(extract_client_ip(&req, depth(3)), None);
    }

    #[test]
    fn test_extract_ip_proxy_fallback_to_connect_info_without_xff() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
        let req = request_with_connect_info(addr);
        assert_eq!(extract_client_ip(&req, depth(1)).as_deref(), Some("127.0.0.1"));
    }

    #[test]
    fn test_extract_ip_proxy_trims_whitespace_in_xff() {
        let req = request_with_headers(&[("x-forwarded-for", "  203.0.113.50  ,  10.0.0.1  ")]);
        assert_eq!(extract_client_ip(&req, depth(1)).as_deref(), Some("203.0.113.50"));
    }

    #[test]
    fn test_extract_ip_proxy_empty_xff_returns_none() {
        let req = request_with_headers(&[("x-forwarded-for", "")]);
        assert_eq!(extract_client_ip(&req, depth(1)), None);
    }

    #[test]
    fn test_extract_ip_proxy_ipv6_in_xff() {
        let req = request_with_headers(&[("x-forwarded-for", "2001:db8::1, 10.0.0.1")]);
        assert_eq!(extract_client_ip(&req, depth(1)).as_deref(), Some("2001:db8::1"));
    }

    #[test]
    fn test_extract_ip_proxy_xff_only_commas_returns_none() {
        let req = request_with_headers(&[("x-forwarded-for", ", ,")]);
        // Empty entries after trim+filter, so no IPs extracted
        assert_eq!(extract_client_ip(&req, depth(1)), None);
    }
}
