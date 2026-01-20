//! Kubernetes service discovery implementation
//!
//! Discovers pod IPs from the Kubernetes Endpoints API, enabling
//! direct pod-to-pod communication.

use async_trait::async_trait;
use k8s_openapi::api::core::v1::Endpoints as K8sEndpoints;
use kube::{Api, Client};
use tracing::{debug, info, warn};

use crate::{DiscoveryError, Endpoint, EndpointDiscovery, Result};

/// Kubernetes service discovery
///
/// Queries the Kubernetes Endpoints API to discover pod IPs for a service.
#[derive(Debug)]
pub struct KubernetesServiceDiscovery {
    /// Default namespace when not specified in URL
    default_namespace: String,
}

impl Default for KubernetesServiceDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

impl KubernetesServiceDiscovery {
    /// Create a new Kubernetes service discovery instance
    pub fn new() -> Self {
        let default_namespace =
            std::env::var("KUBERNETES_NAMESPACE").unwrap_or_else(|_| "default".to_string());
        Self { default_namespace }
    }

    /// Create with a specific default namespace
    pub fn with_namespace(namespace: String) -> Self {
        Self { default_namespace: namespace }
    }

    /// Parse service URL to extract service name and namespace
    ///
    /// Supported formats:
    /// - "http://service-name:8080" -> (service-name, default namespace)
    /// - "http://service-name.namespace:8080" -> (service-name, namespace)
    /// - "http://service-name.namespace.svc.cluster.local:8080" -> (service-name, namespace)
    fn parse_service_url(&self, service_url: &str) -> Result<(String, String, u16)> {
        let url = url::Url::parse(service_url)?;

        let host = url
            .host_str()
            .ok_or_else(|| DiscoveryError::InvalidUrl("No host in URL".to_string()))?;

        let port = url
            .port_or_known_default()
            .ok_or_else(|| DiscoveryError::InvalidUrl("No port in URL".to_string()))?;

        // Parse hostname to extract service name and namespace
        let parts: Vec<&str> = host.split('.').collect();
        let (service_name, namespace) = if parts.len() >= 2 {
            (parts[0].to_string(), parts[1].to_string())
        } else {
            (parts[0].to_string(), self.default_namespace.clone())
        };

        Ok((service_name, namespace, port))
    }
}

#[async_trait]
impl EndpointDiscovery for KubernetesServiceDiscovery {
    async fn discover(&self, service_url: &str) -> Result<Vec<Endpoint>> {
        let (service_name, namespace, port) = self.parse_service_url(service_url)?;

        debug!(
            service_name = %service_name,
            namespace = %namespace,
            port = port,
            "Discovering Kubernetes service endpoints"
        );

        // Create Kubernetes client
        let client = Client::try_default().await?;

        // Get the Endpoints resource for this service
        let endpoints_api: Api<K8sEndpoints> = Api::namespaced(client, &namespace);

        let endpoints = endpoints_api.get(&service_name).await.map_err(|e| {
            if e.to_string().contains("404") {
                DiscoveryError::ServiceNotFound(format!("{service_name}.{namespace}"))
            } else {
                DiscoveryError::KubernetesApi(format!(
                    "Failed to get endpoints for {service_name}.{namespace}: {e}"
                ))
            }
        })?;

        // Extract pod IPs from the Endpoints resource
        let mut pod_endpoints = Vec::new();

        if let Some(subsets) = endpoints.subsets {
            for subset in subsets {
                // Only use ready addresses (healthy pods)
                if let Some(addresses) = subset.addresses {
                    for address in addresses {
                        let pod_ip = &address.ip;
                        let endpoint_url = format!("http://{pod_ip}:{port}");

                        let mut endpoint = Endpoint::healthy(endpoint_url);

                        // Add pod name if available
                        if let Some(ref target_ref) = address.target_ref
                            && let Some(ref name) = target_ref.name
                        {
                            endpoint = endpoint.with_pod_name(name.clone());
                        }

                        // Add metadata
                        endpoint = endpoint
                            .with_metadata("namespace".to_string(), namespace.clone())
                            .with_metadata("service".to_string(), service_name.clone());

                        pod_endpoints.push(endpoint);
                    }
                }
            }
        }

        if pod_endpoints.is_empty() {
            warn!(
                service_name = %service_name,
                namespace = %namespace,
                "No ready endpoints found for service"
            );
            return Err(DiscoveryError::NoEndpoints(format!(
                "No ready endpoints for {service_name}.{namespace}"
            )));
        }

        info!(
            service_name = %service_name,
            namespace = %namespace,
            endpoint_count = pod_endpoints.len(),
            "Discovered Kubernetes service endpoints"
        );

        Ok(pod_endpoints)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_service_url() {
        let discovery = KubernetesServiceDiscovery::with_namespace("test-ns".to_string());
        let (name, ns, port) = discovery.parse_service_url("http://my-service:8080").unwrap();

        assert_eq!(name, "my-service");
        assert_eq!(ns, "test-ns"); // Uses default namespace
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_parse_service_url_with_namespace() {
        let discovery = KubernetesServiceDiscovery::new();
        let (name, ns, port) =
            discovery.parse_service_url("http://my-service.production:8080").unwrap();

        assert_eq!(name, "my-service");
        assert_eq!(ns, "production");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_parse_service_url_full_fqdn() {
        let discovery = KubernetesServiceDiscovery::new();
        let (name, ns, port) = discovery
            .parse_service_url("http://my-service.production.svc.cluster.local:8080")
            .unwrap();

        assert_eq!(name, "my-service");
        assert_eq!(ns, "production");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_parse_service_url_invalid() {
        let discovery = KubernetesServiceDiscovery::new();
        let result = discovery.parse_service_url("not-a-url");

        assert!(result.is_err());
    }
}
