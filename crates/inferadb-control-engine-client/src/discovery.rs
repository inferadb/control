//! Service discovery for policy service (server) endpoints
//!
//! Supports multiple discovery modes:
//! - Static: Use service URL directly
//! - Kubernetes: Discover pod IPs from Kubernetes Endpoints API
//! - Tailscale: Discover endpoints via MagicDNS

use tracing::{debug, error, info, warn};

/// Service discovery mode
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum DiscoveryMode {
    /// No service discovery - use service URL directly
    #[default]
    None,
    /// Kubernetes service discovery - resolve to pod IPs
    Kubernetes,
    /// Tailscale mesh networking for multi-region discovery
    Tailscale {
        /// Local cluster name (e.g., "us-west-1")
        local_cluster: String,
        /// Remote clusters to discover across
        remote_clusters: Vec<RemoteCluster>,
    },
}

/// Remote cluster configuration for Tailscale mesh networking
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteCluster {
    /// Cluster name (e.g., "eu-west-1", "ap-southeast-1")
    pub name: String,
    /// Tailscale domain for this cluster (e.g., "eu-west-1.ts.net")
    pub tailscale_domain: String,
    /// Service name within the cluster (e.g., "inferadb-engine")
    pub service_name: String,
    /// Service port
    pub port: u16,
}

/// Service discovery for policy service endpoints
#[derive(Debug)]
pub struct ServiceDiscovery {
    service_url: String,
    port: u16,
    mode: DiscoveryMode,
}

impl ServiceDiscovery {
    /// Create a new service discovery instance
    pub fn new(service_url: String, port: u16, mode: DiscoveryMode) -> Self {
        Self { service_url, port, mode }
    }

    /// Discover endpoints based on the configured mode
    pub async fn discover(&self) -> Vec<String> {
        match &self.mode {
            DiscoveryMode::None => {
                let endpoint = format!("{}:{}", self.service_url.trim_end_matches('/'), self.port);
                debug!(endpoint = %endpoint, "Using static endpoint");
                vec![endpoint]
            },
            DiscoveryMode::Kubernetes => match self.discover_kubernetes().await {
                Ok(endpoints) => {
                    info!(count = endpoints.len(), "Discovered Kubernetes endpoints");
                    endpoints
                },
                Err(e) => {
                    error!(error = %e, "Kubernetes discovery failed, using static fallback");
                    let endpoint =
                        format!("{}:{}", self.service_url.trim_end_matches('/'), self.port);
                    vec![endpoint]
                },
            },
            DiscoveryMode::Tailscale { local_cluster, remote_clusters } => {
                match self.discover_tailscale(local_cluster, remote_clusters).await {
                    Ok(endpoints) => {
                        info!(count = endpoints.len(), "Discovered Tailscale endpoints");
                        endpoints
                    },
                    Err(e) => {
                        error!(error = %e, "Tailscale discovery failed, returning empty list");
                        vec![]
                    },
                }
            },
        }
    }

    /// Discover Kubernetes service endpoints
    async fn discover_kubernetes(&self) -> Result<Vec<String>, String> {
        use k8s_openapi::api::core::v1::Endpoints as K8sEndpoints;
        use kube::{Api, Client};

        // Parse the service URL to extract service name and namespace
        let url = url::Url::parse(&self.service_url)
            .map_err(|e| format!("Invalid service URL: {}", e))?;

        let service_host = url.host_str().ok_or_else(|| "No host in service URL".to_string())?;

        // Extract service name and namespace from hostname
        // Formats supported:
        // - "service-name" -> (service-name, default namespace from env)
        // - "service-name.namespace" -> (service-name, namespace)
        // - "service-name.namespace.svc.cluster.local" -> (service-name, namespace)
        let parts: Vec<&str> = service_host.split('.').collect();
        let default_namespace =
            std::env::var("KUBERNETES_NAMESPACE").unwrap_or_else(|_| "default".to_string());
        let (service_name, namespace) = if parts.len() >= 2 {
            (parts[0], parts[1].to_string())
        } else {
            (parts[0], default_namespace)
        };

        debug!(
            service_name = %service_name,
            namespace = %namespace,
            port = self.port,
            "Discovering Kubernetes service endpoints"
        );

        // Create Kubernetes client
        let client = Client::try_default()
            .await
            .map_err(|e| format!("Failed to create Kubernetes client: {}", e))?;

        // Get the Endpoints resource for this service
        let endpoints_api: Api<K8sEndpoints> = Api::namespaced(client, &namespace);

        let endpoints = endpoints_api.get(service_name).await.map_err(|e| {
            if e.to_string().contains("404") {
                format!("Service {}.{} not found", service_name, namespace)
            } else {
                format!("Failed to get endpoints for {}.{}: {}", service_name, namespace, e)
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
                        let endpoint_url = format!("http://{}:{}", pod_ip, self.port);
                        pod_endpoints.push(endpoint_url);
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
            return Ok(vec![]);
        }

        info!(
            service_name = %service_name,
            namespace = %namespace,
            endpoint_count = pod_endpoints.len(),
            "Discovered Kubernetes service endpoints"
        );

        Ok(pod_endpoints)
    }

    /// Discover Tailscale service endpoints across multiple clusters
    async fn discover_tailscale(
        &self,
        _local_cluster: &str,
        remote_clusters: &[RemoteCluster],
    ) -> Result<Vec<String>, String> {
        use tokio::net::lookup_host;

        debug!(
            remote_cluster_count = remote_clusters.len(),
            "Discovering Tailscale endpoints across clusters"
        );

        let mut all_endpoints = Vec::new();

        // Discover endpoints for each remote cluster in parallel
        let mut tasks = Vec::new();

        for cluster in remote_clusters {
            let cluster_clone = cluster.clone();

            let task = tokio::spawn(async move {
                let tailscale_hostname =
                    format!("{}.{}", cluster_clone.service_name, cluster_clone.tailscale_domain);

                debug!(
                    cluster = %cluster_clone.name,
                    hostname = %tailscale_hostname,
                    "Resolving Tailscale MagicDNS name"
                );

                // Perform DNS lookup for the Tailscale hostname
                let addrs: Vec<std::net::SocketAddr> =
                    match lookup_host(format!("{}:{}", tailscale_hostname, cluster_clone.port))
                        .await
                    {
                        Ok(iter) => iter.collect(),
                        Err(e) => {
                            warn!(
                                cluster = %cluster_clone.name,
                                hostname = %tailscale_hostname,
                                error = %e,
                                "Failed to resolve Tailscale hostname"
                            );
                            return vec![];
                        },
                    };

                // Build endpoint URLs from resolved IPs
                let mut endpoints = Vec::new();
                for addr in addrs {
                    let endpoint_url = format!("http://{}:{}", addr.ip(), cluster_clone.port);
                    endpoints.push(endpoint_url);
                }

                info!(
                    cluster = %cluster_clone.name,
                    endpoint_count = endpoints.len(),
                    "Discovered Tailscale endpoints for cluster"
                );

                endpoints
            });

            tasks.push(task);
        }

        // Collect results from all tasks
        for task in tasks {
            match task.await {
                Ok(endpoints) => {
                    all_endpoints.extend(endpoints);
                },
                Err(e) => {
                    error!(error = %e, "Tailscale discovery task failed");
                },
            }
        }

        if all_endpoints.is_empty() {
            return Err("No Tailscale endpoints discovered across any cluster".to_string());
        }

        info!(total_endpoints = all_endpoints.len(), "Completed Tailscale multi-cluster discovery");

        Ok(all_endpoints)
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
}
