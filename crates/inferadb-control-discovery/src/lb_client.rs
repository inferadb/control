//! Load balancing client with circuit breaker pattern
//!
//! Provides client-side load balancing across discovered endpoints
//! with health tracking and automatic failover.

use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};

use parking_lot::RwLock;
use tracing::{debug, info, warn};

use crate::Endpoint;

/// Circuit breaker configuration
const CIRCUIT_BREAKER_FAILURE_THRESHOLD: usize = 5;
const CIRCUIT_BREAKER_RECOVERY_TIMEOUT: Duration = Duration::from_secs(30);

/// State of an endpoint for load balancing
#[derive(Debug)]
struct EndpointState {
    /// The endpoint
    endpoint: Endpoint,
    /// Consecutive failure count
    failure_count: usize,
    /// Last failure time
    last_failure: Option<Instant>,
    /// Whether the circuit is open (endpoint is unavailable)
    circuit_open: bool,
}

impl EndpointState {
    fn new(endpoint: Endpoint) -> Self {
        Self { endpoint, failure_count: 0, last_failure: None, circuit_open: false }
    }

    /// Check if this endpoint is available for requests
    fn is_available(&self) -> bool {
        if !self.circuit_open {
            return true;
        }

        // Check if we should try again (half-open state)
        if let Some(last_failure) = self.last_failure
            && last_failure.elapsed() >= CIRCUIT_BREAKER_RECOVERY_TIMEOUT
        {
            return true;
        }

        false
    }

    /// Record a successful request
    fn record_success(&mut self) {
        self.failure_count = 0;
        self.circuit_open = false;
        self.endpoint.mark_healthy();
    }

    /// Record a failed request
    fn record_failure(&mut self) -> bool {
        self.failure_count += 1;
        self.last_failure = Some(Instant::now());
        self.endpoint.mark_unhealthy();

        if self.failure_count >= CIRCUIT_BREAKER_FAILURE_THRESHOLD {
            self.circuit_open = true;
            return true; // Circuit opened
        }

        false
    }
}

/// Load balancing client with circuit breaker
///
/// Distributes requests across multiple endpoints using round-robin
/// selection with health tracking and automatic failover.
#[derive(Debug)]
pub struct LoadBalancingClient {
    /// Endpoint states
    endpoints: RwLock<Vec<EndpointState>>,
    /// Current index for round-robin
    current_index: AtomicUsize,
}

impl LoadBalancingClient {
    /// Create a new load balancing client
    pub fn new(endpoints: Vec<Endpoint>) -> Self {
        let states: Vec<EndpointState> = endpoints.into_iter().map(EndpointState::new).collect();
        Self { endpoints: RwLock::new(states), current_index: AtomicUsize::new(0) }
    }

    /// Get the next endpoint using round-robin selection
    ///
    /// Returns the endpoint URL and its index, or None if no endpoints are available.
    pub fn next_endpoint(&self) -> Option<(String, usize)> {
        let endpoints = self.endpoints.read();

        if endpoints.is_empty() {
            return None;
        }

        let start_index = self.current_index.fetch_add(1, Ordering::Relaxed) % endpoints.len();

        // Try to find an available endpoint starting from current index
        for i in 0..endpoints.len() {
            let index = (start_index + i) % endpoints.len();
            let state = &endpoints[index];

            if state.is_available() {
                return Some((state.endpoint.url.clone(), index));
            }
        }

        // If all endpoints have open circuits, try the first one anyway
        // (allows recovery attempts)
        warn!("All endpoints have open circuits, attempting recovery");
        Some((endpoints[start_index].endpoint.url.clone(), start_index))
    }

    /// Record a successful request to an endpoint
    pub fn record_success(&self, index: usize) {
        let mut endpoints = self.endpoints.write();
        if let Some(state) = endpoints.get_mut(index) {
            state.record_success();
            debug!(
                endpoint = %state.endpoint.url,
                "Request succeeded, endpoint healthy"
            );
        }
    }

    /// Record a failed request to an endpoint
    ///
    /// Returns true if the circuit was opened.
    pub fn record_failure(&self, index: usize) -> bool {
        let mut endpoints = self.endpoints.write();
        if let Some(state) = endpoints.get_mut(index) {
            let circuit_opened = state.record_failure();
            if circuit_opened {
                warn!(
                    endpoint = %state.endpoint.url,
                    failure_count = state.failure_count,
                    "Circuit breaker opened for endpoint"
                );
            } else {
                debug!(
                    endpoint = %state.endpoint.url,
                    failure_count = state.failure_count,
                    "Request failed"
                );
            }
            return circuit_opened;
        }
        false
    }

    /// Update the endpoints list
    pub fn update_endpoints(&self, new_endpoints: Vec<Endpoint>) {
        let mut endpoints = self.endpoints.write();

        // Create new states, preserving health info for existing endpoints
        let mut new_states: Vec<EndpointState> = Vec::with_capacity(new_endpoints.len());

        for new_endpoint in new_endpoints {
            // Check if this endpoint already exists
            let existing = endpoints.iter().find(|s| s.endpoint.url == new_endpoint.url);

            if let Some(existing_state) = existing {
                // Preserve the existing state
                new_states.push(EndpointState {
                    endpoint: new_endpoint,
                    failure_count: existing_state.failure_count,
                    last_failure: existing_state.last_failure,
                    circuit_open: existing_state.circuit_open,
                });
            } else {
                // New endpoint
                new_states.push(EndpointState::new(new_endpoint));
            }
        }

        info!(
            old_count = endpoints.len(),
            new_count = new_states.len(),
            "Updated load balancer endpoints"
        );

        *endpoints = new_states;
    }

    /// Get the current endpoint count
    pub fn endpoint_count(&self) -> usize {
        self.endpoints.read().len()
    }

    /// Get the count of healthy (available) endpoints
    pub fn healthy_endpoint_count(&self) -> usize {
        self.endpoints.read().iter().filter(|s| s.is_available()).count()
    }

    /// Get all endpoint URLs
    pub fn endpoint_urls(&self) -> Vec<String> {
        self.endpoints.read().iter().map(|s| s.endpoint.url.clone()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_endpoints(count: usize) -> Vec<Endpoint> {
        (0..count).map(|i| Endpoint::healthy(format!("http://endpoint-{i}:8080"))).collect()
    }

    #[test]
    fn test_round_robin_selection() {
        let endpoints = create_test_endpoints(3);
        let client = LoadBalancingClient::new(endpoints);

        let (url1, _) = client.next_endpoint().unwrap();
        let (url2, _) = client.next_endpoint().unwrap();
        let (url3, _) = client.next_endpoint().unwrap();
        let (url4, _) = client.next_endpoint().unwrap();

        // Should cycle through endpoints
        assert_eq!(url1, "http://endpoint-0:8080");
        assert_eq!(url2, "http://endpoint-1:8080");
        assert_eq!(url3, "http://endpoint-2:8080");
        assert_eq!(url4, "http://endpoint-0:8080");
    }

    #[test]
    fn test_circuit_breaker() {
        let endpoints = create_test_endpoints(2);
        let client = LoadBalancingClient::new(endpoints);

        // Get first endpoint
        let (_, index) = client.next_endpoint().unwrap();

        // Fail it multiple times
        for _ in 0..CIRCUIT_BREAKER_FAILURE_THRESHOLD {
            client.record_failure(index);
        }

        // Now the circuit should be open
        // Next requests should skip this endpoint
        let healthy = client.healthy_endpoint_count();
        assert_eq!(healthy, 1);
    }

    #[test]
    fn test_update_endpoints() {
        let endpoints = create_test_endpoints(2);
        let client = LoadBalancingClient::new(endpoints);

        assert_eq!(client.endpoint_count(), 2);

        // Update with 3 endpoints
        let new_endpoints = create_test_endpoints(3);
        client.update_endpoints(new_endpoints);

        assert_eq!(client.endpoint_count(), 3);
    }

    #[test]
    fn test_record_success_resets_failures() {
        let endpoints = create_test_endpoints(1);
        let client = LoadBalancingClient::new(endpoints);

        let (_, index) = client.next_endpoint().unwrap();

        // Fail a few times (but not enough to open circuit)
        for _ in 0..3 {
            client.record_failure(index);
        }

        // Now succeed
        client.record_success(index);

        // Should be fully healthy again
        assert_eq!(client.healthy_endpoint_count(), 1);
    }

    #[test]
    fn test_empty_endpoints() {
        let client = LoadBalancingClient::new(vec![]);

        assert!(client.next_endpoint().is_none());
        assert_eq!(client.endpoint_count(), 0);
    }
}
