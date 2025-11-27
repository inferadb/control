//! Webhook client for invalidating server-side caches
//!
//! This module provides a client for sending cache invalidation webhooks to InferaDB server
//! instances when vaults or organizations are updated in the Management API.

use infera_management_types::ManagementIdentity;
use parking_lot::RwLock;
use reqwest::Client as HttpClient;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

use crate::config::{DiscoveryMode, RemoteCluster};

/// Discovery mode for server endpoints
#[derive(Debug, Clone)]
enum InternalDiscoveryMode {
    /// Static endpoints (no discovery)
    Static(Vec<String>),
    /// Kubernetes service discovery
    Kubernetes {
        service_name: String,
        namespace: String,
        port: u16,
    },
    /// Tailscale multi-region mesh discovery
    Tailscale {
        local_cluster: String,
        remote_clusters: Vec<RemoteCluster>,
    },
}

/// Cached endpoints with TTL validation
#[derive(Debug, Clone)]
struct CachedEndpoints {
    endpoints: Vec<String>,
    cached_at: Instant,
    ttl: Duration,
}

impl CachedEndpoints {
    fn is_valid(&self) -> bool {
        self.cached_at.elapsed() < self.ttl
    }
}

/// Webhook client for sending cache invalidation requests to server instances
pub struct WebhookClient {
    /// HTTP client for making requests
    http_client: HttpClient,
    /// Discovery mode for endpoints
    discovery_mode: InternalDiscoveryMode,
    /// Management identity for signing webhook JWTs
    management_identity: Arc<ManagementIdentity>,
    /// Cached discovered endpoints
    endpoint_cache: Arc<RwLock<Option<CachedEndpoints>>>,
    /// Cache TTL in seconds
    cache_ttl_seconds: u64,
}

impl std::fmt::Debug for WebhookClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookClient")
            .field("discovery_mode", &self.discovery_mode)
            .field("cache_ttl_seconds", &self.cache_ttl_seconds)
            .finish()
    }
}

impl WebhookClient {
    /// Create a new webhook client with discovery support
    ///
    /// # Arguments
    ///
    /// * `server_endpoints` - List of server URLs to send webhooks to
    /// * `management_identity` - Management identity for signing webhook JWTs
    /// * `timeout_ms` - Request timeout in milliseconds (default: 5000)
    /// * `discovery_mode` - Service discovery mode (None or Kubernetes)
    /// * `cache_ttl_seconds` - Cache TTL for discovered endpoints (default: 300)
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use std::sync::Arc;
    /// use infera_management_core::{WebhookClient, ManagementIdentity};
    /// use infera_management_core::config::DiscoveryMode;
    ///
    /// let identity = Arc::new(ManagementIdentity::generate("mgmt-1".to_string(), "key-1".to_string()));
    /// let endpoints = vec!["http://server1:8080".to_string(), "http://server2:8080".to_string()];
    /// let client = WebhookClient::new_with_discovery(
    ///     endpoints,
    ///     identity,
    ///     5000,
    ///     DiscoveryMode::None,
    ///     300
    /// ).unwrap();
    /// ```
    pub fn new_with_discovery(
        server_endpoints: Vec<String>,
        management_identity: Arc<ManagementIdentity>,
        timeout_ms: u64,
        discovery_mode: DiscoveryMode,
        cache_ttl_seconds: u64,
    ) -> Result<Self, String> {
        let http_client = HttpClient::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .pool_max_idle_per_host(10)
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

        let internal_discovery_mode = match discovery_mode {
            DiscoveryMode::None => InternalDiscoveryMode::Static(server_endpoints),
            DiscoveryMode::Kubernetes => {
                // Parse the first endpoint as Kubernetes service
                if server_endpoints.is_empty() {
                    return Err(
                        "Kubernetes discovery requires at least one service URL".to_string()
                    );
                }

                let service_endpoint = &server_endpoints[0];
                let url = url::Url::parse(service_endpoint)
                    .map_err(|e| format!("Invalid service URL: {}", e))?;

                let service_host = url
                    .host_str()
                    .ok_or_else(|| "No host in service URL".to_string())?;
                let service_port = url
                    .port_or_known_default()
                    .ok_or_else(|| "No port in service URL".to_string())?;

                // Extract service name and namespace from hostname
                let parts: Vec<&str> = service_host.split('.').collect();
                let default_namespace =
                    std::env::var("KUBERNETES_NAMESPACE").unwrap_or_else(|_| "default".to_string());
                let (service_name, namespace) = if parts.len() >= 2 {
                    (parts[0].to_string(), parts[1].to_string())
                } else {
                    (parts[0].to_string(), default_namespace)
                };

                info!(
                    service_name = %service_name,
                    namespace = %namespace,
                    port = service_port,
                    "Configured Kubernetes service discovery"
                );

                InternalDiscoveryMode::Kubernetes {
                    service_name,
                    namespace,
                    port: service_port,
                }
            }
            DiscoveryMode::Tailscale {
                local_cluster,
                remote_clusters,
            } => {
                info!(
                    local_cluster = %local_cluster,
                    remote_cluster_count = remote_clusters.len(),
                    "Configured Tailscale multi-region discovery"
                );

                InternalDiscoveryMode::Tailscale {
                    local_cluster,
                    remote_clusters,
                }
            }
        };

        Ok(Self {
            http_client,
            discovery_mode: internal_discovery_mode,
            management_identity,
            endpoint_cache: Arc::new(RwLock::new(None)),
            cache_ttl_seconds,
        })
    }

    /// Create a new webhook client (legacy, for backward compatibility)
    ///
    /// # Arguments
    ///
    /// * `server_endpoints` - List of server URLs to send webhooks to
    /// * `management_identity` - Management identity for signing webhook JWTs
    /// * `timeout_ms` - Request timeout in milliseconds (default: 5000)
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use std::sync::Arc;
    /// use infera_management_core::{WebhookClient, ManagementIdentity};
    ///
    /// let identity = Arc::new(ManagementIdentity::generate("mgmt-1".to_string(), "key-1".to_string()));
    /// let endpoints = vec!["http://server1:8080".to_string(), "http://server2:8080".to_string()];
    /// let client = WebhookClient::new(endpoints, identity, 5000).unwrap();
    /// ```
    pub fn new(
        server_endpoints: Vec<String>,
        management_identity: Arc<ManagementIdentity>,
        timeout_ms: u64,
    ) -> Result<Self, String> {
        Self::new_with_discovery(
            server_endpoints,
            management_identity,
            timeout_ms,
            DiscoveryMode::None,
            300,
        )
    }

    /// Get endpoints (with discovery and caching)
    async fn get_endpoints(&self) -> Vec<String> {
        // Check cache first
        {
            let cache = self.endpoint_cache.read();
            if let Some(cached) = cache.as_ref() {
                if cached.is_valid() {
                    debug!(count = cached.endpoints.len(), "Using cached endpoints");
                    crate::metrics::record_discovery_cache_hit();
                    return cached.endpoints.clone();
                }
            }
        }

        // Cache miss or expired
        crate::metrics::record_discovery_cache_miss();
        debug!("Cache miss or expired, discovering endpoints");

        // Discover endpoints based on mode
        let endpoints = match &self.discovery_mode {
            InternalDiscoveryMode::Static(endpoints) => {
                debug!(count = endpoints.len(), "Using static endpoints");
                endpoints.clone()
            }
            InternalDiscoveryMode::Kubernetes {
                service_name,
                namespace,
                port,
            } => {
                let service_url = format!("http://{}:{}", service_name, port);
                match Self::discover_k8s_endpoints(service_name, namespace, *port).await {
                    Ok(discovered) => {
                        info!(
                            count = discovered.len(),
                            service_name = %service_name,
                            namespace = %namespace,
                            "Discovered Kubernetes endpoints"
                        );
                        discovered
                    }
                    Err(e) => {
                        error!(
                            error = %e,
                            service_name = %service_name,
                            namespace = %namespace,
                            "Discovery failed, using service URL fallback"
                        );
                        vec![service_url]
                    }
                }
            }
            InternalDiscoveryMode::Tailscale {
                local_cluster,
                remote_clusters,
            } => match Self::discover_tailscale_endpoints(local_cluster, remote_clusters).await {
                Ok(discovered) => {
                    info!(
                        count = discovered.len(),
                        local_cluster = %local_cluster,
                        remote_cluster_count = remote_clusters.len(),
                        "Discovered Tailscale endpoints across clusters"
                    );
                    discovered
                }
                Err(e) => {
                    error!(
                        error = %e,
                        local_cluster = %local_cluster,
                        "Tailscale discovery failed, returning empty list"
                    );
                    vec![]
                }
            },
        };

        // Update cache
        {
            let mut cache = self.endpoint_cache.write();
            *cache = Some(CachedEndpoints {
                endpoints: endpoints.clone(),
                cached_at: Instant::now(),
                ttl: Duration::from_secs(self.cache_ttl_seconds),
            });
        }

        // Update metrics
        crate::metrics::set_discovered_endpoints(endpoints.len() as i64);

        endpoints
    }

    /// Get the number of configured server endpoints (from cache or discovery)
    pub async fn endpoint_count(&self) -> usize {
        self.get_endpoints().await.len()
    }

    /// Discover Tailscale service endpoints across multiple clusters
    async fn discover_tailscale_endpoints(
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
                let tailscale_hostname = format!(
                    "{}.{}",
                    cluster_clone.service_name, cluster_clone.tailscale_domain
                );

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
                        }
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
                }
                Err(e) => {
                    error!(error = %e, "Tailscale discovery task failed");
                }
            }
        }

        if all_endpoints.is_empty() {
            return Err("No Tailscale endpoints discovered across any cluster".to_string());
        }

        info!(
            total_endpoints = all_endpoints.len(),
            "Completed Tailscale multi-cluster discovery"
        );

        Ok(all_endpoints)
    }

    /// Discover Kubernetes service endpoints
    async fn discover_k8s_endpoints(
        service_name: &str,
        namespace: &str,
        port: u16,
    ) -> Result<Vec<String>, String> {
        use k8s_openapi::api::core::v1::Endpoints as K8sEndpoints;
        use kube::{Api, Client};

        debug!(
            service_name = %service_name,
            namespace = %namespace,
            port = port,
            "Discovering Kubernetes service endpoints"
        );

        // Create Kubernetes client
        let client = Client::try_default()
            .await
            .map_err(|e| format!("Failed to create Kubernetes client: {}", e))?;

        // Get the Endpoints resource for this service
        let endpoints_api: Api<K8sEndpoints> = Api::namespaced(client, namespace);

        let endpoints = endpoints_api.get(service_name).await.map_err(|e| {
            if e.to_string().contains("404") {
                format!("Service {}.{} not found", service_name, namespace)
            } else {
                format!(
                    "Failed to get endpoints for {}.{}: {}",
                    service_name, namespace, e
                )
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
                        let endpoint_url = format!("http://{}:{}", pod_ip, port);
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

    /// Invalidate vault cache on all server instances
    ///
    /// Sends cache invalidation webhooks to all configured server endpoints in parallel.
    /// This is a fire-and-forget operation - errors are logged but don't fail the operation.
    ///
    /// # Arguments
    ///
    /// * `vault_id` - The vault ID to invalidate
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// client.invalidate_vault(12345).await;
    /// ```
    pub async fn invalidate_vault(&self, vault_id: i64) {
        let endpoints = self.get_endpoints().await;

        if endpoints.is_empty() {
            warn!(vault_id = %vault_id, "No server endpoints configured, skipping cache invalidation");
            return;
        }

        info!(
            vault_id = %vault_id,
            endpoints_count = endpoints.len(),
            "Invalidating vault cache across all servers"
        );

        // Send requests to all endpoints in parallel
        let mut tasks = Vec::new();

        for endpoint in &endpoints {
            let http_client = self.http_client.clone();
            let url = format!("{}/internal/cache/invalidate/vault/{}", endpoint, vault_id);
            let endpoint_clone = endpoint.clone();
            let management_identity = Arc::clone(&self.management_identity);

            let task = tokio::spawn(async move {
                debug!(
                    vault_id = %vault_id,
                    endpoint = %endpoint_clone,
                    "Sending vault invalidation webhook"
                );

                // Sign JWT for server authentication
                let jwt = match management_identity.sign_jwt(&endpoint_clone) {
                    Ok(token) => token,
                    Err(e) => {
                        error!(
                            vault_id = %vault_id,
                            endpoint = %endpoint_clone,
                            error = %e,
                            "Failed to sign JWT for vault invalidation webhook"
                        );
                        return;
                    }
                };

                let request = http_client
                    .post(&url)
                    .header("Authorization", format!("Bearer {}", jwt));

                match request.send().await {
                    Ok(response) => {
                        if response.status().is_success() {
                            debug!(
                                vault_id = %vault_id,
                                endpoint = %endpoint_clone,
                                "Vault invalidation webhook succeeded"
                            );
                        } else {
                            warn!(
                                vault_id = %vault_id,
                                endpoint = %endpoint_clone,
                                status = %response.status(),
                                "Vault invalidation webhook returned non-success status"
                            );
                        }
                    }
                    Err(e) => {
                        error!(
                            vault_id = %vault_id,
                            endpoint = %endpoint_clone,
                            error = %e,
                            "Failed to send vault invalidation webhook"
                        );
                    }
                }
            });

            tasks.push(task);
        }

        // Wait for all tasks to complete (fire-and-forget)
        for task in tasks {
            let _ = task.await;
        }

        info!(
            vault_id = %vault_id,
            endpoints_count = endpoints.len(),
            "Completed vault invalidation webhooks"
        );
    }

    /// Invalidate organization cache on all server instances
    ///
    /// Sends cache invalidation webhooks to all configured server endpoints in parallel.
    /// This is a fire-and-forget operation - errors are logged but don't fail the operation.
    ///
    /// # Arguments
    ///
    /// * `org_id` - The organization ID to invalidate
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// client.invalidate_organization(67890).await;
    /// ```
    pub async fn invalidate_organization(&self, org_id: i64) {
        let endpoints = self.get_endpoints().await;

        if endpoints.is_empty() {
            warn!(org_id = %org_id, "No server endpoints configured, skipping cache invalidation");
            return;
        }

        info!(
            org_id = %org_id,
            endpoints_count = endpoints.len(),
            "Invalidating organization cache across all servers"
        );

        // Send requests to all endpoints in parallel
        let mut tasks = Vec::new();

        for endpoint in &endpoints {
            let http_client = self.http_client.clone();
            let url = format!(
                "{}/internal/cache/invalidate/organization/{}",
                endpoint, org_id
            );
            let endpoint_clone = endpoint.clone();
            let management_identity = Arc::clone(&self.management_identity);

            let task = tokio::spawn(async move {
                debug!(
                    org_id = %org_id,
                    endpoint = %endpoint_clone,
                    "Sending organization invalidation webhook"
                );

                // Sign JWT for server authentication
                let jwt = match management_identity.sign_jwt(&endpoint_clone) {
                    Ok(token) => token,
                    Err(e) => {
                        error!(
                            org_id = %org_id,
                            endpoint = %endpoint_clone,
                            error = %e,
                            "Failed to sign JWT for organization invalidation webhook"
                        );
                        return;
                    }
                };

                let request = http_client
                    .post(&url)
                    .header("Authorization", format!("Bearer {}", jwt));

                match request.send().await {
                    Ok(response) => {
                        if response.status().is_success() {
                            debug!(
                                org_id = %org_id,
                                endpoint = %endpoint_clone,
                                "Organization invalidation webhook succeeded"
                            );
                        } else {
                            warn!(
                                org_id = %org_id,
                                endpoint = %endpoint_clone,
                                status = %response.status(),
                                "Organization invalidation webhook returned non-success status"
                            );
                        }
                    }
                    Err(e) => {
                        error!(
                            org_id = %org_id,
                            endpoint = %endpoint_clone,
                            error = %e,
                            "Failed to send organization invalidation webhook"
                        );
                    }
                }
            });

            tasks.push(task);
        }

        // Wait for all tasks to complete (fire-and-forget)
        for task in tasks {
            let _ = task.await;
        }

        info!(
            org_id = %org_id,
            endpoints_count = endpoints.len(),
            "Completed organization invalidation webhooks"
        );
    }

    /// Discover server endpoints, with support for Kubernetes service discovery
    ///
    /// If the endpoint is a Kubernetes service format (e.g., "http://service-name:port")
    /// and running in Kubernetes (KUBERNETES_SERVICE_HOST env var is set), this will
    /// use the Kubernetes API to discover all pod endpoints behind the service.
    ///
    /// Otherwise, it returns the static endpoints as-is.
    ///
    /// # Arguments
    ///
    /// * `endpoints` - List of static endpoints or Kubernetes service names
    ///
    /// # Returns
    ///
    /// Discovered endpoints (either from k8s or static)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use infera_management_core::WebhookClient;
    ///
    /// let endpoints = vec!["http://inferadb-server:8080".to_string()];
    /// let discovered = WebhookClient::discover_endpoints(endpoints).await;
    /// ```
    pub async fn discover_endpoints(endpoints: Vec<String>) -> Vec<String> {
        // Check if running in Kubernetes
        let in_kubernetes = std::env::var("KUBERNETES_SERVICE_HOST").is_ok();

        if !in_kubernetes {
            debug!(
                "Not running in Kubernetes - using static endpoints: {:?}",
                endpoints
            );
            return endpoints;
        }

        debug!("Running in Kubernetes - attempting service discovery");

        let mut discovered_endpoints = Vec::new();

        for endpoint in &endpoints {
            // Check if this looks like a Kubernetes service (no dots in hostname, simple format)
            if is_kubernetes_service(endpoint) {
                match discover_k8s_service_endpoints(endpoint).await {
                    Ok(pod_endpoints) => {
                        info!(
                            service = %endpoint,
                            pod_count = pod_endpoints.len(),
                            "Discovered Kubernetes service endpoints"
                        );
                        discovered_endpoints.extend(pod_endpoints);
                    }
                    Err(e) => {
                        warn!(
                            service = %endpoint,
                            error = %e,
                            "Failed to discover Kubernetes endpoints, falling back to service URL"
                        );
                        discovered_endpoints.push(endpoint.clone());
                    }
                }
            } else {
                // Not a k8s service, use as-is
                discovered_endpoints.push(endpoint.clone());
            }
        }

        discovered_endpoints
    }
}

/// Check if an endpoint looks like a Kubernetes service
///
/// Kubernetes services typically have simple hostnames without dots:
/// - http://service-name:8080
/// - http://service-name.namespace:8080
/// - http://service-name.namespace.svc.cluster.local:8080
fn is_kubernetes_service(endpoint: &str) -> bool {
    // Parse the URL to extract hostname
    if let Ok(url) = url::Url::parse(endpoint) {
        if let Some(host) = url.host_str() {
            // Check if it's an IP address (not a k8s service)
            if host.chars().all(|c| c.is_ascii_digit() || c == '.') {
                return false;
            }

            // Kubernetes services have specific patterns:
            // 1. No dots (simple service name): "service-name"
            // 2. Ends with .svc.cluster.local: "service.namespace.svc.cluster.local"
            // 3. Contains .svc.: "service.namespace.svc.something"
            // 4. Has exactly one dot (service.namespace format): "service.namespace"
            let dot_count = host.chars().filter(|&c| c == '.').count();

            return !host.contains('.')
                || host.ends_with(".svc.cluster.local")
                || host.contains(".svc.")
                || (dot_count == 1
                    && !host.contains(".com")
                    && !host.contains(".io")
                    && !host.contains(".net"));
        }
    }
    false
}

/// Discover Kubernetes service endpoints using the Kubernetes API
///
/// This queries the Kubernetes API to find all pod IPs behind a service.
///
/// # Arguments
///
/// * `service_endpoint` - The Kubernetes service URL (e.g., "http://service-name:8080")
///
/// # Returns
///
/// List of pod endpoints (e.g., ["http://10.0.1.2:8080", "http://10.0.1.3:8080"])
async fn discover_k8s_service_endpoints(service_endpoint: &str) -> Result<Vec<String>, String> {
    use k8s_openapi::api::core::v1::Endpoints as K8sEndpoints;
    use kube::{Api, Client};

    // Parse the service URL
    let url =
        url::Url::parse(service_endpoint).map_err(|e| format!("Invalid service URL: {}", e))?;

    let service_host = url
        .host_str()
        .ok_or_else(|| "No host in service URL".to_string())?;
    let service_port = url
        .port_or_known_default()
        .ok_or_else(|| "No port in service URL".to_string())?;
    let scheme = url.scheme();

    // Extract service name and namespace from hostname
    // Formats supported:
    // - "service-name" -> (service-name, default namespace from env)
    // - "service-name.namespace" -> (service-name, namespace)
    // - "service-name.namespace.svc.cluster.local" -> (service-name, namespace)
    let parts: Vec<&str> = service_host.split('.').collect();
    let default_namespace =
        std::env::var("KUBERNETES_NAMESPACE").unwrap_or_else(|_| "default".to_string());
    let (service_name, namespace) = if parts.len() >= 2 {
        (parts[0], parts[1])
    } else {
        (parts[0], default_namespace.as_str())
    };

    debug!(
        service_name = %service_name,
        namespace = %namespace,
        port = service_port,
        "Discovering Kubernetes service endpoints"
    );

    // Create Kubernetes client
    let client = Client::try_default()
        .await
        .map_err(|e| format!("Failed to create Kubernetes client: {}", e))?;

    // Get the Endpoints resource for this service
    let endpoints_api: Api<K8sEndpoints> = Api::namespaced(client, namespace);

    let endpoints = endpoints_api.get(service_name).await.map_err(|e| {
        if e.to_string().contains("404") {
            format!("Service {}.{} not found", service_name, namespace)
        } else {
            format!(
                "Failed to get endpoints for {}.{}: {}",
                service_name, namespace, e
            )
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
                    let endpoint_url = format!("{}://{}:{}", scheme, pod_ip, service_port);
                    pod_endpoints.push(endpoint_url);
                }
            }
        }
    }

    if pod_endpoints.is_empty() {
        warn!(
            service_name = %service_name,
            namespace = %namespace,
            "No ready endpoints found for service - falling back to service URL"
        );
        return Ok(vec![service_endpoint.to_string()]);
    }

    info!(
        service_name = %service_name,
        namespace = %namespace,
        endpoint_count = pod_endpoints.len(),
        "Discovered Kubernetes service endpoints"
    );

    Ok(pod_endpoints)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DiscoveryMode;

    #[test]
    fn test_is_kubernetes_service() {
        // Kubernetes services
        assert!(is_kubernetes_service("http://inferadb-server:8080"));
        assert!(is_kubernetes_service("http://inferadb-server.default:8080"));
        assert!(is_kubernetes_service(
            "http://inferadb-server.default.svc.cluster.local:8080"
        ));

        // Not Kubernetes services
        assert!(!is_kubernetes_service("http://192.168.1.1:8080"));
        assert!(!is_kubernetes_service("http://example.com:8080"));
        assert!(!is_kubernetes_service("https://api.inferadb.io:443"));
    }

    #[tokio::test]
    async fn test_webhook_client_creation() {
        let identity = Arc::new(ManagementIdentity::generate(
            "test-mgmt".to_string(),
            "test-key".to_string(),
        ));
        let endpoints = vec!["http://localhost:8080".to_string()];
        let client = WebhookClient::new(endpoints, identity, 5000);
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn test_webhook_client_creation_with_discovery() {
        let identity = Arc::new(ManagementIdentity::generate(
            "test-mgmt".to_string(),
            "test-key".to_string(),
        ));
        let endpoints = vec!["http://localhost:8080".to_string()];

        // Test with DiscoveryMode::None
        let client = WebhookClient::new_with_discovery(
            endpoints.clone(),
            identity.clone(),
            5000,
            DiscoveryMode::None,
            300,
        );
        assert!(client.is_ok());

        // Test with DiscoveryMode::Kubernetes
        let client = WebhookClient::new_with_discovery(
            vec!["http://inferadb-server:8080".to_string()],
            identity,
            5000,
            DiscoveryMode::Kubernetes,
            300,
        );
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn test_discover_endpoints_static() {
        let endpoints = vec![
            "http://server1:8080".to_string(),
            "http://server2:8080".to_string(),
        ];

        // When not in Kubernetes, should return static endpoints as-is
        std::env::remove_var("KUBERNETES_SERVICE_HOST");
        let discovered = WebhookClient::discover_endpoints(endpoints.clone()).await;
        assert_eq!(discovered, endpoints);
    }

    #[tokio::test]
    async fn test_cached_endpoints_is_valid() {
        let cached = CachedEndpoints {
            endpoints: vec!["http://test:8080".to_string()],
            cached_at: Instant::now(),
            ttl: Duration::from_secs(30),
        };
        assert!(cached.is_valid());

        // Test expired cache
        let expired = CachedEndpoints {
            endpoints: vec!["http://test:8080".to_string()],
            cached_at: Instant::now() - Duration::from_secs(31),
            ttl: Duration::from_secs(30),
        };
        assert!(!expired.is_valid());
    }

    #[tokio::test]
    async fn test_get_endpoints_caching() {
        let identity = Arc::new(ManagementIdentity::generate(
            "test-mgmt".to_string(),
            "test-key".to_string(),
        ));
        let endpoints = vec![
            "http://server1:8080".to_string(),
            "http://server2:8080".to_string(),
        ];

        let client = WebhookClient::new_with_discovery(
            endpoints.clone(),
            identity,
            5000,
            DiscoveryMode::None,
            30,
        )
        .unwrap();

        // First call should cache
        let result1 = client.get_endpoints().await;
        assert_eq!(result1, endpoints);

        // Second call should use cache (same result)
        let result2 = client.get_endpoints().await;
        assert_eq!(result2, endpoints);
    }

    #[tokio::test]
    async fn test_endpoint_count() {
        let identity = Arc::new(ManagementIdentity::generate(
            "test-mgmt".to_string(),
            "test-key".to_string(),
        ));
        let endpoints = vec![
            "http://server1:8080".to_string(),
            "http://server2:8080".to_string(),
            "http://server3:8080".to_string(),
        ];

        let client = WebhookClient::new_with_discovery(
            endpoints.clone(),
            identity,
            5000,
            DiscoveryMode::None,
            300,
        )
        .unwrap();

        assert_eq!(client.endpoint_count().await, 3);
    }

    #[tokio::test]
    async fn test_kubernetes_discovery_mode_parsing() {
        let identity = Arc::new(ManagementIdentity::generate(
            "test-mgmt".to_string(),
            "test-key".to_string(),
        ));

        // Simple service name
        let client = WebhookClient::new_with_discovery(
            vec!["http://inferadb-server:8080".to_string()],
            identity.clone(),
            5000,
            DiscoveryMode::Kubernetes,
            300,
        );
        assert!(client.is_ok());

        // Service with namespace
        let client = WebhookClient::new_with_discovery(
            vec!["http://inferadb-server.default:8080".to_string()],
            identity.clone(),
            5000,
            DiscoveryMode::Kubernetes,
            300,
        );
        assert!(client.is_ok());

        // Full FQDN
        let client = WebhookClient::new_with_discovery(
            vec!["http://inferadb-server.default.svc.cluster.local:8080".to_string()],
            identity,
            5000,
            DiscoveryMode::Kubernetes,
            300,
        );
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn test_kubernetes_discovery_mode_empty_endpoints() {
        let identity = Arc::new(ManagementIdentity::generate(
            "test-mgmt".to_string(),
            "test-key".to_string(),
        ));

        let client = WebhookClient::new_with_discovery(
            vec![],
            identity,
            5000,
            DiscoveryMode::Kubernetes,
            300,
        );

        assert!(client.is_err());
        assert!(client
            .unwrap_err()
            .contains("requires at least one service URL"));
    }
}
