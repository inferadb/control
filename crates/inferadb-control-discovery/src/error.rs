//! Error types for service discovery

use std::fmt;

/// Result type for discovery operations
pub type Result<T> = std::result::Result<T, DiscoveryError>;

/// Errors that can occur during service discovery
#[derive(Debug)]
pub enum DiscoveryError {
    /// Error communicating with Kubernetes API
    KubernetesApi(String),

    /// Invalid service URL format
    InvalidUrl(String),

    /// Service not found
    ServiceNotFound(String),

    /// No healthy endpoints available
    NoEndpoints(String),

    /// Configuration error
    Config(String),

    /// DNS resolution error
    DnsResolution(String),

    /// Other errors
    Other(String),
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DiscoveryError::KubernetesApi(msg) => write!(f, "Kubernetes API error: {msg}"),
            DiscoveryError::InvalidUrl(msg) => write!(f, "Invalid URL: {msg}"),
            DiscoveryError::ServiceNotFound(msg) => write!(f, "Service not found: {msg}"),
            DiscoveryError::NoEndpoints(msg) => write!(f, "No endpoints available: {msg}"),
            DiscoveryError::Config(msg) => write!(f, "Configuration error: {msg}"),
            DiscoveryError::DnsResolution(msg) => write!(f, "DNS resolution error: {msg}"),
            DiscoveryError::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for DiscoveryError {}

impl From<url::ParseError> for DiscoveryError {
    fn from(e: url::ParseError) -> Self {
        DiscoveryError::InvalidUrl(e.to_string())
    }
}

impl From<kube::Error> for DiscoveryError {
    fn from(e: kube::Error) -> Self {
        DiscoveryError::KubernetesApi(e.to_string())
    }
}

impl From<std::io::Error> for DiscoveryError {
    fn from(e: std::io::Error) -> Self {
        DiscoveryError::DnsResolution(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = DiscoveryError::KubernetesApi("connection refused".to_string());
        assert!(err.to_string().contains("Kubernetes API error"));

        let err = DiscoveryError::InvalidUrl("missing scheme".to_string());
        assert!(err.to_string().contains("Invalid URL"));

        let err = DiscoveryError::ServiceNotFound("my-service".to_string());
        assert!(err.to_string().contains("Service not found"));

        let err = DiscoveryError::NoEndpoints("all unhealthy".to_string());
        assert!(err.to_string().contains("No endpoints available"));

        let err = DiscoveryError::Config("missing field".to_string());
        assert!(err.to_string().contains("Configuration error"));

        let err = DiscoveryError::DnsResolution("timeout".to_string());
        assert!(err.to_string().contains("DNS resolution error"));

        let err = DiscoveryError::Other("unknown error".to_string());
        assert!(err.to_string().contains("unknown error"));
    }
}
