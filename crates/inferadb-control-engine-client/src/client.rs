//! HTTP client for communicating with the Engine's REST API
//!
//! This module provides a client for vault lifecycle operations with load balancing,
//! circuit breaker, and service discovery support.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use inferadb_control_discovery::DiscoveryMode;
use inferadb_control_types::{ControlIdentity, Result};
use parking_lot::RwLock;
use reqwest::Client as HttpClient;
use serde::Serialize;
use tracing::{debug, info, warn};

use crate::discovery::ServiceDiscovery;

/// Circuit breaker thresholds (matching engine's implementation)
const FAILURE_THRESHOLD: u32 = 5;
const CIRCUIT_RECOVERY_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RETRY_ATTEMPTS: u32 = 3;

/// Circuit breaker state for an endpoint
#[derive(Debug, Clone)]
enum CircuitState {
    Closed,
    Open { since: Instant },
}

/// State for a single endpoint
#[derive(Debug)]
struct EndpointState {
    url: String,
    failures: u32,
    last_failure: Option<Instant>,
    circuit: CircuitState,
}

impl EndpointState {
    fn new(url: String) -> Self {
        Self { url, failures: 0, last_failure: None, circuit: CircuitState::Closed }
    }

    fn is_healthy(&self) -> bool {
        match &self.circuit {
            CircuitState::Closed => true,
            CircuitState::Open { since } => since.elapsed() >= CIRCUIT_RECOVERY_TIMEOUT,
        }
    }

    fn mark_success(&mut self) {
        self.failures = 0;
        self.last_failure = None;
        self.circuit = CircuitState::Closed;
    }

    fn mark_failure(&mut self) {
        self.failures += 1;
        self.last_failure = Some(Instant::now());
        if self.failures >= FAILURE_THRESHOLD {
            self.circuit = CircuitState::Open { since: Instant::now() };
            warn!(
                endpoint = %self.url,
                failures = self.failures,
                "Circuit breaker opened for endpoint"
            );
        }
    }
}

/// Load balancer state
#[derive(Debug)]
struct LoadBalancerState {
    endpoints: Vec<EndpointState>,
    current_index: usize,
}

impl LoadBalancerState {
    fn new(endpoints: Vec<String>) -> Self {
        Self {
            endpoints: endpoints.into_iter().map(EndpointState::new).collect(),
            current_index: 0,
        }
    }

    fn get_next_healthy_endpoint(&mut self) -> Option<String> {
        if self.endpoints.is_empty() {
            return None;
        }

        let len = self.endpoints.len();
        for _ in 0..len {
            let endpoint = &self.endpoints[self.current_index];
            self.current_index = (self.current_index + 1) % len;

            if endpoint.is_healthy() {
                return Some(endpoint.url.clone());
            }
        }

        // If all endpoints are unhealthy, return the first one (allow circuit to recover)
        Some(self.endpoints[0].url.clone())
    }

    fn mark_success(&mut self, endpoint_url: &str) {
        if let Some(state) = self.endpoints.iter_mut().find(|e| e.url == endpoint_url) {
            state.mark_success();
        }
    }

    fn mark_failure(&mut self, endpoint_url: &str) {
        if let Some(state) = self.endpoints.iter_mut().find(|e| e.url == endpoint_url) {
            state.mark_failure();
        }
    }

    fn update_endpoints(&mut self, endpoints: Vec<String>) {
        self.endpoints = endpoints.into_iter().map(EndpointState::new).collect();
        self.current_index = 0;
    }
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

/// Request body for creating a vault
#[derive(Debug, Serialize)]
struct CreateVaultRequest {
    name: String,
}

/// HTTP client for communicating with the Engine's REST API
///
/// Features:
/// - Service discovery (Static, Kubernetes)
/// - Load balancing with round-robin selection
/// - Circuit breaker pattern (opens after 5 failures, recovers after 30s)
/// - Automatic retry with failover (up to 3 attempts)
/// - JWT authentication for control→engine communication
pub struct EngineClient {
    http_client: HttpClient,
    discovery: ServiceDiscovery,
    control_identity: Option<Arc<ControlIdentity>>,
    endpoint_cache: Arc<RwLock<Option<CachedEndpoints>>>,
    lb_state: Arc<RwLock<LoadBalancerState>>,
    cache_ttl: Duration,
    port: u16,
}

impl std::fmt::Debug for EngineClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineClient")
            .field("discovery", &self.discovery)
            .field("port", &self.port)
            .field("cache_ttl", &self.cache_ttl)
            .finish()
    }
}

impl EngineClient {
    /// Create a new engine client (legacy constructor for backward compatibility)
    ///
    /// # Arguments
    ///
    /// * `service_url` - Base service URL without port (e.g., "http://localhost")
    /// * `grpc_port` - Port for engine communication (uses REST API on this port)
    pub fn new(service_url: String, grpc_port: u16) -> Result<Self> {
        Self::with_config(service_url, grpc_port, None, DiscoveryMode::None, 300, 5000)
    }

    /// Create a new engine client with full configuration
    ///
    /// # Arguments
    ///
    /// * `service_url` - Base service URL without port (e.g., "http://localhost")
    /// * `port` - Engine's public REST API port (e.g., 8080)
    /// * `control_identity` - Control identity for JWT authentication
    /// * `discovery_mode` - Service discovery mode
    /// * `cache_ttl` - Cache TTL for discovered endpoints in seconds
    /// * `timeout_ms` - Request timeout in milliseconds
    pub fn with_config(
        service_url: String,
        port: u16,
        control_identity: Option<Arc<ControlIdentity>>,
        discovery_mode: DiscoveryMode,
        cache_ttl: u64,
        timeout_ms: u64,
    ) -> Result<Self> {
        let http_client = HttpClient::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .pool_max_idle_per_host(10)
            .build()
            .map_err(|e| {
                inferadb_control_types::Error::External(format!(
                    "Failed to create HTTP client: {}",
                    e
                ))
            })?;

        let discovery = ServiceDiscovery::new(service_url.clone(), port, discovery_mode);

        // Initialize with static endpoint
        let initial_endpoint = format!("{}:{}", service_url.trim_end_matches('/'), port);

        Ok(Self {
            http_client,
            discovery,
            control_identity,
            endpoint_cache: Arc::new(RwLock::new(None)),
            lb_state: Arc::new(RwLock::new(LoadBalancerState::new(vec![initial_endpoint]))),
            cache_ttl: Duration::from_secs(cache_ttl),
            port,
        })
    }

    /// Get discovered endpoints with caching
    async fn get_endpoints(&self) -> Vec<String> {
        // Check cache first
        {
            let cache = self.endpoint_cache.read();
            if let Some(cached) = cache.as_ref() {
                if cached.is_valid() {
                    debug!(count = cached.endpoints.len(), "Using cached engine endpoints");
                    return cached.endpoints.clone();
                }
            }
        }

        // Cache miss or expired - discover endpoints
        debug!("Discovering engine endpoints");
        let endpoints = self.discovery.discover().await;

        // Update cache
        {
            let mut cache = self.endpoint_cache.write();
            *cache = Some(CachedEndpoints {
                endpoints: endpoints.clone(),
                cached_at: Instant::now(),
                ttl: self.cache_ttl,
            });
        }

        // Update load balancer state
        {
            let mut lb = self.lb_state.write();
            lb.update_endpoints(endpoints.clone());
        }

        endpoints
    }

    /// Get next healthy endpoint for load balancing
    async fn get_next_endpoint(&self) -> Option<String> {
        // Ensure endpoints are discovered
        let _ = self.get_endpoints().await;

        let mut lb = self.lb_state.write();
        lb.get_next_healthy_endpoint()
    }

    /// Execute a request with retry and failover
    async fn execute_with_failover<F, Fut, T>(
        &self,
        operation: &str,
        mut request_fn: F,
    ) -> Result<T>
    where
        F: FnMut(String) -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let mut last_error = None;

        for attempt in 0..MAX_RETRY_ATTEMPTS {
            let endpoint = match self.get_next_endpoint().await {
                Some(e) => e,
                None => {
                    return Err(inferadb_control_types::Error::External(
                        "No engine endpoints available".to_string(),
                    ));
                },
            };

            debug!(
                attempt = attempt + 1,
                endpoint = %endpoint,
                operation = %operation,
                "Attempting request"
            );

            match request_fn(endpoint.clone()).await {
                Ok(result) => {
                    let mut lb = self.lb_state.write();
                    lb.mark_success(&endpoint);
                    return Ok(result);
                },
                Err(e) => {
                    warn!(
                        attempt = attempt + 1,
                        endpoint = %endpoint,
                        error = %e,
                        operation = %operation,
                        "Request failed"
                    );
                    {
                        let mut lb = self.lb_state.write();
                        lb.mark_failure(&endpoint);
                    }
                    last_error = Some(e);
                },
            }
        }

        Err(last_error.unwrap_or_else(|| {
            inferadb_control_types::Error::External(format!(
                "{} failed after {} attempts",
                operation, MAX_RETRY_ATTEMPTS
            ))
        }))
    }

    /// Create a vault on the engine
    ///
    /// Sends a POST request to create a vault, with automatic retry and failover
    /// across discovered engine endpoints.
    ///
    /// # Arguments
    ///
    /// * `vault_id` - The vault ID (used for logging)
    /// * `organization_id` - The organization ID
    ///
    /// # Returns
    ///
    /// Ok(()) on success, or an error if all retry attempts fail
    pub async fn create_vault(&self, vault_id: i64, organization_id: i64) -> Result<()> {
        info!(vault_id = vault_id, organization_id = organization_id, "Creating vault on engine");

        self.execute_with_failover("create_vault", |endpoint| {
            let http_client = self.http_client.clone();
            let vault_name = format!("vault-{}", vault_id);

            async move {
                let url =
                    format!("{}/access/v1/organizations/{}/vaults", endpoint, organization_id);

                // Sign JWT for authentication
                let jwt = match &self.control_identity {
                    Some(identity) => identity.sign_jwt(&endpoint).map_err(|e| {
                        inferadb_control_types::Error::External(format!(
                            "Failed to sign JWT: {}",
                            e
                        ))
                    })?,
                    None => String::new(),
                };

                let mut request =
                    http_client.post(&url).json(&CreateVaultRequest { name: vault_name });

                if !jwt.is_empty() {
                    request = request.header("Authorization", format!("Bearer {}", jwt));
                }

                let response = request.send().await.map_err(|e| {
                    inferadb_control_types::Error::External(format!("HTTP request failed: {}", e))
                })?;

                if response.status().is_success() {
                    debug!(vault_id = vault_id, "Vault created successfully");
                    Ok(())
                } else {
                    let status = response.status();
                    let body = response.text().await.unwrap_or_default();
                    Err(inferadb_control_types::Error::External(format!(
                        "Engine returned {}: {}",
                        status, body
                    )))
                }
            }
        })
        .await
    }

    /// Delete a vault on the engine
    ///
    /// Sends a DELETE request to remove a vault, with automatic retry and failover
    /// across discovered engine endpoints.
    ///
    /// # Arguments
    ///
    /// * `vault_id` - The vault ID to delete
    ///
    /// # Returns
    ///
    /// Ok(()) on success, or an error if all retry attempts fail
    pub async fn delete_vault(&self, vault_id: i64) -> Result<()> {
        info!(vault_id = vault_id, "Deleting vault on engine");

        self.execute_with_failover("delete_vault", |endpoint| {
            let http_client = self.http_client.clone();

            async move {
                let url = format!("{}/access/v1/vaults/{}", endpoint, vault_id);

                // Sign JWT for authentication
                let jwt = match &self.control_identity {
                    Some(identity) => identity.sign_jwt(&endpoint).map_err(|e| {
                        inferadb_control_types::Error::External(format!(
                            "Failed to sign JWT: {}",
                            e
                        ))
                    })?,
                    None => String::new(),
                };

                let mut request = http_client.delete(&url);

                if !jwt.is_empty() {
                    request = request.header("Authorization", format!("Bearer {}", jwt));
                }

                let response = request.send().await.map_err(|e| {
                    inferadb_control_types::Error::External(format!("HTTP request failed: {}", e))
                })?;

                if response.status().is_success() || response.status().as_u16() == 404 {
                    // 404 is acceptable - vault may already be deleted
                    debug!(vault_id = vault_id, "Vault deleted successfully");
                    Ok(())
                } else {
                    let status = response.status();
                    let body = response.text().await.unwrap_or_default();
                    Err(inferadb_control_types::Error::External(format!(
                        "Engine returned {}: {}",
                        status, body
                    )))
                }
            }
        })
        .await
    }

    /// Update endpoints from discovery (called by background refresh task)
    pub fn update_endpoints(&self, endpoints: Vec<String>) {
        let mut lb = self.lb_state.write();
        lb.update_endpoints(endpoints.clone());

        let mut cache = self.endpoint_cache.write();
        *cache =
            Some(CachedEndpoints { endpoints, cached_at: Instant::now(), ttl: self.cache_ttl });
    }

    /// Get the current endpoint count (for monitoring)
    pub async fn endpoint_count(&self) -> usize {
        self.get_endpoints().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endpoint_state_healthy() {
        let state = EndpointState::new("http://test:8080".to_string());
        assert!(state.is_healthy());
    }

    #[test]
    fn test_endpoint_state_circuit_breaker() {
        let mut state = EndpointState::new("http://test:8080".to_string());

        // Mark failures until circuit opens
        for _ in 0..FAILURE_THRESHOLD {
            state.mark_failure();
        }

        assert!(!state.is_healthy());
        assert!(matches!(state.circuit, CircuitState::Open { .. }));
    }

    #[test]
    fn test_endpoint_state_recovery() {
        let mut state = EndpointState::new("http://test:8080".to_string());
        state.mark_failure();
        state.mark_failure();
        state.mark_success();

        assert_eq!(state.failures, 0);
        assert!(state.is_healthy());
    }

    #[test]
    fn test_load_balancer_round_robin() {
        let mut lb = LoadBalancerState::new(vec![
            "http://server1:8080".to_string(),
            "http://server2:8080".to_string(),
            "http://server3:8080".to_string(),
        ]);

        let e1 = lb.get_next_healthy_endpoint();
        let e2 = lb.get_next_healthy_endpoint();
        let e3 = lb.get_next_healthy_endpoint();
        let e4 = lb.get_next_healthy_endpoint();

        assert_eq!(e1, Some("http://server1:8080".to_string()));
        assert_eq!(e2, Some("http://server2:8080".to_string()));
        assert_eq!(e3, Some("http://server3:8080".to_string()));
        assert_eq!(e4, Some("http://server1:8080".to_string())); // Wraps around
    }

    #[test]
    fn test_load_balancer_skips_unhealthy() {
        let mut lb = LoadBalancerState::new(vec![
            "http://server1:8080".to_string(),
            "http://server2:8080".to_string(),
        ]);

        // Make server1 unhealthy
        for _ in 0..FAILURE_THRESHOLD {
            lb.mark_failure("http://server1:8080");
        }

        let e1 = lb.get_next_healthy_endpoint();
        let e2 = lb.get_next_healthy_endpoint();

        // Should skip server1 and return server2
        assert_eq!(e1, Some("http://server2:8080".to_string()));
        assert_eq!(e2, Some("http://server2:8080".to_string()));
    }

    #[test]
    fn test_cached_endpoints_validity() {
        let cached = CachedEndpoints {
            endpoints: vec!["http://test:8080".to_string()],
            cached_at: Instant::now(),
            ttl: Duration::from_secs(30),
        };
        assert!(cached.is_valid());

        let expired = CachedEndpoints {
            endpoints: vec!["http://test:8080".to_string()],
            cached_at: Instant::now() - Duration::from_secs(31),
            ttl: Duration::from_secs(30),
        };
        assert!(!expired.is_valid());
    }

    #[tokio::test]
    async fn test_engine_client_creation() {
        let client = EngineClient::new("http://localhost".to_string(), 8080);
        assert!(client.is_ok());
    }
}
