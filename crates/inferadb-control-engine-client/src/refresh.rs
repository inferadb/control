//! Background discovery refresh task
//!
//! Provides periodic endpoint refresh by querying the discovery service
//! and updating the engine client with newly discovered endpoints.

use std::sync::Arc;

use tokio::time::{Duration, interval};
use tracing::{debug, error, info};

use crate::{EngineClient, ServiceDiscovery};

/// Background task for refreshing discovered endpoints
pub struct DiscoveryRefresher {
    /// Discovery service implementation
    discovery: Arc<ServiceDiscovery>,
    /// Engine client to update
    engine_client: Arc<EngineClient>,
    /// How often to refresh endpoints
    refresh_interval: Duration,
    /// Service URL being discovered (for logging)
    service_url: String,
}

impl DiscoveryRefresher {
    /// Create a new discovery refresher
    ///
    /// # Arguments
    ///
    /// * `discovery` - The discovery service implementation
    /// * `engine_client` - The engine client to update
    /// * `refresh_interval_secs` - How often to refresh endpoints (in seconds)
    /// * `service_url` - The service URL being discovered (for logging)
    pub fn new(
        discovery: Arc<ServiceDiscovery>,
        engine_client: Arc<EngineClient>,
        refresh_interval_secs: u64,
        service_url: String,
    ) -> Self {
        Self {
            discovery,
            engine_client,
            refresh_interval: Duration::from_secs(refresh_interval_secs),
            service_url,
        }
    }

    /// Spawn the background refresh task
    ///
    /// This creates a tokio task that periodically queries the discovery service
    /// and updates the engine client with new endpoints.
    ///
    /// The task runs indefinitely until the program exits or the task is cancelled.
    ///
    /// Returns a handle that can be used to abort the task if needed.
    pub fn spawn(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        info!(
            service_url = %self.service_url,
            refresh_interval_secs = self.refresh_interval.as_secs(),
            "Spawning engine discovery refresh task"
        );

        tokio::spawn(async move {
            let mut timer = interval(self.refresh_interval);

            // Skip the first immediate tick
            timer.tick().await;

            loop {
                timer.tick().await;

                debug!(
                    service_url = %self.service_url,
                    "Refreshing engine endpoints"
                );

                let endpoints = self.discovery.discover().await;

                if endpoints.is_empty() {
                    error!(
                        service_url = %self.service_url,
                        "Discovery returned no endpoints, keeping existing endpoints"
                    );
                    continue;
                }

                info!(
                    service_url = %self.service_url,
                    count = endpoints.len(),
                    "Successfully refreshed engine endpoints"
                );

                // Update engine client with new endpoints
                self.engine_client.update_endpoints(endpoints);
            }
        })
    }

    /// Perform an immediate refresh (useful for testing or on-demand updates)
    ///
    /// This does not spawn a background task, but performs a single refresh operation.
    pub async fn refresh_once(&self) -> usize {
        debug!(
            service_url = %self.service_url,
            "Performing one-time engine endpoint refresh"
        );

        let endpoints = self.discovery.discover().await;

        if endpoints.is_empty() {
            error!(
                service_url = %self.service_url,
                "One-time refresh returned no endpoints"
            );
            return 0;
        }

        info!(
            service_url = %self.service_url,
            count = endpoints.len(),
            "One-time engine refresh completed"
        );

        let count = endpoints.len();
        self.engine_client.update_endpoints(endpoints);

        count
    }

    /// Get the refresh interval
    pub fn refresh_interval(&self) -> Duration {
        self.refresh_interval
    }
}

#[cfg(test)]
mod tests {
    use inferadb_control_types::DiscoveryMode;

    use super::*;

    #[tokio::test]
    async fn test_refresh_once() {
        // Create discovery with static endpoint
        let discovery = Arc::new(ServiceDiscovery::new(
            "http://test-server".to_string(),
            8080,
            DiscoveryMode::None,
        ));

        let engine_client =
            Arc::new(EngineClient::new("http://localhost".to_string(), 8080).unwrap());

        let refresher = DiscoveryRefresher::new(
            discovery,
            engine_client.clone(),
            30,
            "http://test-server:8080".to_string(),
        );

        let count = refresher.refresh_once().await;

        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_spawn_task() {
        let discovery = Arc::new(ServiceDiscovery::new(
            "http://test-server".to_string(),
            8080,
            DiscoveryMode::None,
        ));

        let engine_client =
            Arc::new(EngineClient::new("http://localhost".to_string(), 8080).unwrap());

        let refresher = Arc::new(DiscoveryRefresher::new(
            discovery,
            engine_client.clone(),
            1, // 1 second for fast test
            "http://test-server:8080".to_string(),
        ));

        // Spawn the task
        let handle = refresher.spawn();

        // Wait for at least one refresh
        tokio::time::sleep(Duration::from_millis(1500)).await;

        // Abort the task
        handle.abort();

        // Verify we got endpoints
        let count = engine_client.endpoint_count().await;
        assert!(count >= 1);
    }

    #[test]
    fn test_refresh_interval() {
        let discovery = Arc::new(ServiceDiscovery::new(
            "http://test-server".to_string(),
            8080,
            DiscoveryMode::None,
        ));

        let engine_client =
            Arc::new(EngineClient::new("http://localhost".to_string(), 8080).unwrap());

        let refresher = DiscoveryRefresher::new(
            discovery,
            engine_client,
            60,
            "http://test-server:8080".to_string(),
        );

        assert_eq!(refresher.refresh_interval(), Duration::from_secs(60));
    }
}
