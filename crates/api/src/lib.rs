//! # InferaDB Control API
//!
//! Stateless REST API gateway for the InferaDB Control Plane.
//! All domain operations delegate to Ledger via the SDK.
//!
//! ## AppState Builder
//!
//! The [`AppState`] struct uses a builder for server initialization:
//!
//! ```ignore
//! use std::sync::Arc;
//! use inferadb_control_api::AppState;
//!
//! async fn example(config: Arc<Config>) {
//!     let state = AppState::builder()
//!         .config(config)
//!         .worker_id(1)
//!         .maybe_email_service(None)
//!         .maybe_ledger(None)
//!         .maybe_blinding_key(None)
//!         .build();
//! }
//! ```

#![deny(unsafe_code)]

use std::sync::Arc;

use inferadb_control_config::Config;
use inferadb_control_core::startup;
use tracing::info;

pub mod extract;
pub mod handlers;
pub mod middleware;
pub mod routes;

pub use handlers::AppState;
pub use middleware::{RateLimitConfig, UserClaims, require_jwt};
pub use routes::create_router_with_state;

/// Graceful shutdown signal handler
async fn shutdown_signal() {
    use tokio::signal;

    let ctrl_c = async {
        // Signal handler installation failure is unrecoverable at runtime
        #[allow(clippy::expect_used)]
        signal::ctrl_c().await.expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        // Signal handler installation failure is unrecoverable at runtime
        #[allow(clippy::expect_used)]
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C signal, initiating shutdown");
        }
        _ = terminate => {
            info!("Received SIGTERM signal, initiating shutdown");
        }
    }
}

/// Configuration for optional services in the Control API
pub struct ServicesConfig {
    pub email_service: Option<Arc<inferadb_control_core::EmailService>>,
    pub ledger: Option<Arc<inferadb_ledger_sdk::LedgerClient>>,
    pub blinding_key: Option<Arc<inferadb_ledger_types::EmailBlindingKey>>,
    pub webauthn: Option<Arc<webauthn_rs::Webauthn>>,
    /// Rate limiter backend. Defaults to in-memory when `None`.
    pub rate_limiter: Option<Arc<inferadb_control_core::AnyRateLimiter>>,
}

/// Start the Control API HTTP server
pub async fn serve(
    config: Arc<Config>,
    worker_id: u16,
    services: ServicesConfig,
) -> anyhow::Result<()> {
    // Create AppState with services using the builder pattern
    let state = AppState::builder()
        .config(config.clone())
        .worker_id(worker_id)
        .maybe_email_service(services.email_service)
        .maybe_ledger(services.ledger)
        .maybe_blinding_key(services.blinding_key)
        .maybe_webauthn(services.webauthn)
        .maybe_rate_limiter(services.rate_limiter)
        .build();

    // Create router
    let router = routes::create_router_with_state(state.clone());

    // Bind listener (address is already validated in config)
    let listener = tokio::net::TcpListener::bind(config.listen).await?;

    // Log ready status
    startup::log_ready("Control");

    // Serve with graceful shutdown.
    // `into_make_service_with_connect_info` injects `ConnectInfo<SocketAddr>` into
    // every request, required for IP-based rate limiting in direct-connection mode.
    let service = router.into_make_service_with_connect_info::<std::net::SocketAddr>();
    axum::serve(listener, service)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| anyhow::anyhow!("Server error: {e}"))?;

    Ok(())
}
