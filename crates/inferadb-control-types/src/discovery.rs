//! Service discovery configuration types
//!
//! These types configure how Control discovers Engine service endpoints.
//! With the Ledger-based architecture, discovery is simplified as Engine
//! instances can operate independently without Control connectivity.

use serde::{Deserialize, Serialize};

/// Service discovery mode for finding Engine endpoints
///
/// Controls how Control locates Engine service instances for policy evaluation.
/// The default is `None`, which uses a statically configured endpoint.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiscoveryMode {
    /// No discovery - use static endpoint URL
    ///
    /// In this mode, the `mesh.url` configuration value is used directly.
    /// This is the default and simplest mode, suitable for development
    /// and single-node deployments.
    #[default]
    None,

    /// Kubernetes service discovery
    ///
    /// Discovers Engine pod IPs via Kubernetes Endpoints API.
    /// Requires appropriate RBAC permissions to read endpoints.
    Kubernetes,
}

/// Configuration for service discovery
///
/// Controls how Control discovers and caches Engine service endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    /// Discovery mode (none, kubernetes)
    #[serde(default)]
    pub mode: DiscoveryMode,

    /// Cache TTL in seconds for discovered endpoints
    ///
    /// How long to cache discovered endpoint information before
    /// refreshing from the discovery source.
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl: u64,
}

fn default_cache_ttl() -> u64 {
    300
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self { mode: DiscoveryMode::default(), cache_ttl: default_cache_ttl() }
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

    #[test]
    fn test_discovery_mode_serialization() {
        let mode = DiscoveryMode::None;
        let json = serde_json::to_string(&mode).expect("serialize");
        assert_eq!(json, "\"none\"");

        let mode = DiscoveryMode::Kubernetes;
        let json = serde_json::to_string(&mode).expect("serialize");
        assert_eq!(json, "\"kubernetes\"");
    }

    #[test]
    fn test_discovery_mode_deserialization() {
        let mode: DiscoveryMode = serde_json::from_str("\"none\"").expect("deserialize");
        assert_eq!(mode, DiscoveryMode::None);

        let mode: DiscoveryMode = serde_json::from_str("\"kubernetes\"").expect("deserialize");
        assert_eq!(mode, DiscoveryMode::Kubernetes);
    }

    #[test]
    fn test_discovery_config_default() {
        let config = DiscoveryConfig::default();
        assert_eq!(config.mode, DiscoveryMode::None);
        assert_eq!(config.cache_ttl, 300);
    }

    #[test]
    fn test_discovery_config_serialization() {
        let config = DiscoveryConfig { mode: DiscoveryMode::Kubernetes, cache_ttl: 600 };

        let json = serde_json::to_string(&config).expect("serialize");
        assert!(json.contains("\"mode\":\"kubernetes\""));
        assert!(json.contains("\"cache_ttl\":600"));
    }

    #[test]
    fn test_discovery_config_deserialization() {
        let json = r#"{"mode": "kubernetes", "cache_ttl": 120}"#;
        let config: DiscoveryConfig = serde_json::from_str(json).expect("deserialize");

        assert_eq!(config.mode, DiscoveryMode::Kubernetes);
        assert_eq!(config.cache_ttl, 120);
    }

    #[test]
    fn test_discovery_config_deserialization_defaults() {
        let json = "{}";
        let config: DiscoveryConfig = serde_json::from_str(json).expect("deserialize");

        assert_eq!(config.mode, DiscoveryMode::None);
        assert_eq!(config.cache_ttl, 300);
    }
}
