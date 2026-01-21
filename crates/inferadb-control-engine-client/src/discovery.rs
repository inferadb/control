//! Service discovery for policy service (engine) endpoints
//!
//! This module provides endpoint discovery for the engine client's load balancer.
//! Currently supports static endpoint configuration. Kubernetes service discovery
//! can be added when needed.

use inferadb_control_types::DiscoveryMode;
use tracing::info;

/// Service discovery for policy service endpoints
///
/// This provides endpoint URLs for the engine client's load balancer.
/// Currently uses static endpoints; Kubernetes discovery can be added later.
#[derive(Debug)]
pub struct ServiceDiscovery {
    /// Service URL (used for building discovery query)
    service_url: String,
    /// Service port
    port: u16,
    /// Discovery mode (kept for reference)
    mode: DiscoveryMode,
}

impl ServiceDiscovery {
    /// Create a new service discovery instance
    pub fn new(service_url: String, port: u16, mode: DiscoveryMode) -> Self {
        Self { service_url, port, mode }
    }

    /// Discover endpoints based on the configured mode
    ///
    /// Returns a list of endpoint URLs (e.g., "http://10.0.0.1:8080")
    pub async fn discover(&self) -> Vec<String> {
        let full_url = format!("{}:{}", self.service_url.trim_end_matches('/'), self.port);

        match &self.mode {
            DiscoveryMode::None => {
                info!(url = %full_url, "Using static endpoint");
                vec![full_url]
            },
            DiscoveryMode::Kubernetes => {
                // Kubernetes discovery not yet implemented in new architecture.
                // Fall back to static endpoint for now.
                info!(
                    url = %full_url,
                    "Kubernetes discovery not implemented, using static fallback"
                );
                vec![full_url]
            },
        }
    }

    /// Get the discovery mode
    pub fn mode(&self) -> &DiscoveryMode {
        &self.mode
    }

    /// Get the service URL
    pub fn service_url(&self) -> &str {
        &self.service_url
    }

    /// Get the port
    pub fn port(&self) -> u16 {
        self.port
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discovery_mode_default() {
        let mode = DiscoveryMode::default();
        assert_eq!(mode, DiscoveryMode::None);
    }

    #[tokio::test]
    async fn test_static_discovery() {
        let discovery =
            ServiceDiscovery::new("http://localhost".to_string(), 8080, DiscoveryMode::None);
        let endpoints = discovery.discover().await;
        assert_eq!(endpoints, vec!["http://localhost:8080".to_string()]);
    }

    #[tokio::test]
    async fn test_static_discovery_with_trailing_slash() {
        let discovery =
            ServiceDiscovery::new("http://localhost/".to_string(), 8080, DiscoveryMode::None);
        let endpoints = discovery.discover().await;
        assert_eq!(endpoints, vec!["http://localhost:8080".to_string()]);
    }

    #[test]
    fn test_service_discovery_accessors() {
        let discovery = ServiceDiscovery::new(
            "http://test-server".to_string(),
            9090,
            DiscoveryMode::Kubernetes,
        );

        assert_eq!(discovery.service_url(), "http://test-server");
        assert_eq!(discovery.port(), 9090);
        assert!(matches!(discovery.mode(), DiscoveryMode::Kubernetes));
    }
}
