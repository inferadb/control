//! Service discovery for distributed deployments
//!
//! Provides abstractions for discovering service endpoints in Kubernetes environments,
//! enabling direct pod-to-pod communication and bypassing service proxies for improved
//! performance and latency.
//!
//! # Discovery Modes
//!
//! - **Static**: Use service URL directly (no discovery)
//! - **Kubernetes**: Discover pod IPs from Kubernetes Endpoints API

#![deny(unsafe_code)]

use std::fmt;

use async_trait::async_trait;

pub mod config;
pub mod endpoint;
pub mod error;
pub mod kubernetes;
pub mod lb_client;
pub mod metrics;
pub mod refresh;
pub mod static_discovery;

pub use config::{DiscoveryConfig, DiscoveryMode};
pub use endpoint::{Endpoint, EndpointHealth};
pub use error::{DiscoveryError, Result};
pub use kubernetes::KubernetesServiceDiscovery;
pub use lb_client::LoadBalancingClient;
pub use refresh::DiscoveryRefresher;
pub use static_discovery::StaticDiscovery;

/// Trait for service discovery implementations
#[async_trait]
pub trait EndpointDiscovery: Send + Sync + fmt::Debug {
    /// Discover endpoints for a service
    ///
    /// # Arguments
    ///
    /// * `service_url` - The service URL to discover endpoints for
    ///   (e.g., "http://service-name:8080" or "http://service-name.namespace.svc.cluster.local:8080")
    ///
    /// # Returns
    ///
    /// A list of discovered endpoints (pod IPs in Kubernetes)
    ///
    /// # Errors
    ///
    /// Returns `DiscoveryError` if discovery fails
    async fn discover(&self, service_url: &str) -> Result<Vec<Endpoint>>;

    /// Refresh endpoint health status
    ///
    /// This is optional and may be a no-op for some implementations
    async fn refresh_health(&self, _endpoints: &mut [Endpoint]) -> Result<()> {
        Ok(())
    }
}

/// Create a discovery service based on the configured mode
pub fn create_discovery(mode: &DiscoveryMode) -> Box<dyn EndpointDiscovery> {
    match mode {
        DiscoveryMode::None => Box::new(StaticDiscovery::new()),
        DiscoveryMode::Kubernetes => Box::new(KubernetesServiceDiscovery::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_discovery_static() {
        let mode = DiscoveryMode::None;
        let discovery = create_discovery(&mode);
        assert!(format!("{discovery:?}").contains("StaticDiscovery"));
    }

    #[test]
    fn test_create_discovery_kubernetes() {
        let mode = DiscoveryMode::Kubernetes;
        let discovery = create_discovery(&mode);
        assert!(format!("{discovery:?}").contains("KubernetesServiceDiscovery"));
    }
}
