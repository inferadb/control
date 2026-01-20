//! Engine client for policy service communication
//!
//! This crate provides HTTP-based communication with the InferaDB server's REST API
//! for vault lifecycle operations, with support for:
//!
//! - Service discovery (Static, Kubernetes)
//! - Load balancing with round-robin selection
//! - Circuit breaker pattern for fault tolerance
//! - Automatic retry with failover
//! - Background endpoint discovery refresh

#![deny(unsafe_code)]

pub mod client;
pub mod discovery;
pub mod refresh;

pub use client::EngineClient;
pub use discovery::ServiceDiscovery;
pub use refresh::DiscoveryRefresher;
