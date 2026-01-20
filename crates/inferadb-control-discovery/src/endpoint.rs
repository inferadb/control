//! Endpoint types for service discovery

use std::{collections::HashMap, fmt};

use serde::{Deserialize, Serialize};

/// Represents a discovered service endpoint
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    /// Full URL of the endpoint (e.g., "http://10.0.1.2:8080")
    pub url: String,

    /// Health status of the endpoint
    pub health: EndpointHealth,

    /// Optional pod name (for Kubernetes)
    pub pod_name: Option<String>,

    /// Optional metadata (e.g., zone, region, cluster)
    pub metadata: HashMap<String, String>,
}

impl Endpoint {
    /// Create a new endpoint with the given URL
    pub fn new(url: String) -> Self {
        Self { url, health: EndpointHealth::Unknown, pod_name: None, metadata: HashMap::new() }
    }

    /// Create a new healthy endpoint
    pub fn healthy(url: String) -> Self {
        Self { url, health: EndpointHealth::Healthy, pod_name: None, metadata: HashMap::new() }
    }

    /// Set the pod name
    pub fn with_pod_name(mut self, name: String) -> Self {
        self.pod_name = Some(name);
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Mark endpoint as healthy
    pub fn mark_healthy(&mut self) {
        self.health = EndpointHealth::Healthy;
    }

    /// Mark endpoint as unhealthy
    pub fn mark_unhealthy(&mut self) {
        self.health = EndpointHealth::Unhealthy;
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({:?})", self.url, self.health)
    }
}

/// Health status of a discovered endpoint
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum EndpointHealth {
    /// Endpoint is healthy and ready to receive traffic
    Healthy,

    /// Endpoint is unhealthy and should not receive traffic
    Unhealthy,

    /// Health status is unknown
    #[default]
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endpoint_new() {
        let endpoint = Endpoint::new("http://10.0.1.2:8080".to_string());
        assert_eq!(endpoint.url, "http://10.0.1.2:8080");
        assert_eq!(endpoint.health, EndpointHealth::Unknown);
        assert!(endpoint.pod_name.is_none());
        assert!(endpoint.metadata.is_empty());
    }

    #[test]
    fn test_endpoint_healthy() {
        let endpoint = Endpoint::healthy("http://10.0.1.2:8080".to_string());
        assert_eq!(endpoint.health, EndpointHealth::Healthy);
    }

    #[test]
    fn test_endpoint_with_pod_name() {
        let endpoint =
            Endpoint::new("http://10.0.1.2:8080".to_string()).with_pod_name("my-pod-0".to_string());
        assert_eq!(endpoint.pod_name, Some("my-pod-0".to_string()));
    }

    #[test]
    fn test_endpoint_with_metadata() {
        let endpoint = Endpoint::new("http://10.0.1.2:8080".to_string())
            .with_metadata("zone".to_string(), "us-west-1a".to_string());
        assert_eq!(endpoint.metadata.get("zone"), Some(&"us-west-1a".to_string()));
    }

    #[test]
    fn test_endpoint_display() {
        let endpoint = Endpoint::healthy("http://10.0.1.2:8080".to_string());
        assert_eq!(format!("{endpoint}"), "http://10.0.1.2:8080 (Healthy)");
    }

    #[test]
    fn test_mark_healthy_unhealthy() {
        let mut endpoint = Endpoint::new("http://10.0.1.2:8080".to_string());
        assert_eq!(endpoint.health, EndpointHealth::Unknown);

        endpoint.mark_healthy();
        assert_eq!(endpoint.health, EndpointHealth::Healthy);

        endpoint.mark_unhealthy();
        assert_eq!(endpoint.health, EndpointHealth::Unhealthy);
    }
}
