//! Static discovery implementation (no-op discovery)
//!
//! Used when service discovery is disabled and the service URL
//! should be used directly.

use async_trait::async_trait;
use tracing::debug;

use crate::{Endpoint, EndpointDiscovery, Result};

/// Static discovery that returns the service URL directly
#[derive(Debug, Default)]
pub struct StaticDiscovery;

impl StaticDiscovery {
    /// Create a new static discovery instance
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl EndpointDiscovery for StaticDiscovery {
    async fn discover(&self, service_url: &str) -> Result<Vec<Endpoint>> {
        debug!(service_url = %service_url, "Using static endpoint (no discovery)");

        // Parse URL to validate and normalize
        let url = url::Url::parse(service_url)?;

        // Build the endpoint URL
        let scheme = url.scheme();
        let host = url.host_str().unwrap_or("localhost");
        let endpoint_url = if let Some(port) = url.port() {
            format!("{scheme}://{host}:{port}")
        } else {
            format!("{scheme}://{host}")
        };

        Ok(vec![Endpoint::healthy(endpoint_url)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_static_discovery() {
        let discovery = StaticDiscovery::new();
        let endpoints = discovery.discover("http://localhost:8080").await.unwrap();

        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].url, "http://localhost:8080");
    }

    #[tokio::test]
    async fn test_static_discovery_without_port() {
        let discovery = StaticDiscovery::new();
        let endpoints = discovery.discover("http://localhost").await.unwrap();

        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].url, "http://localhost");
    }

    #[tokio::test]
    async fn test_static_discovery_with_path() {
        let discovery = StaticDiscovery::new();
        let endpoints = discovery.discover("http://localhost:8080/api").await.unwrap();

        assert_eq!(endpoints.len(), 1);
        // Path is stripped - we only care about host:port
        assert_eq!(endpoints[0].url, "http://localhost:8080");
    }
}
