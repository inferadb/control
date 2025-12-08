//! Server API client for policy service (server) communication
//!
//! This crate provides HTTP-based communication with the InferaDB server's REST API
//! for vault lifecycle operations, with support for:
//!
//! - Service discovery (Static, Kubernetes, Tailscale)
//! - Load balancing with round-robin selection
//! - Circuit breaker pattern for fault tolerance
//! - Automatic retry with failover
//! - Background endpoint discovery refresh

pub mod client;
pub mod discovery;
pub mod refresh;

pub use client::ServerApiClient;
pub use discovery::{DiscoveryMode, RemoteCluster, ServiceDiscovery};
pub use refresh::DiscoveryRefresher;
