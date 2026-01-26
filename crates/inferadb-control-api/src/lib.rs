//! # InferaDB Control API
//!
//! REST API handlers and routes for the InferaDB Control Plane.
//!
//! ## Request/Response Builders
//!
//! API request and response types use [`bon::Builder`] for ergonomic construction,
//! particularly useful in tests:
//!
//! ```no_run
//! use inferadb_control_types::dto::{RegisterRequest, LoginRequest, CreateVaultRequest};
//!
//! // Registration request with all required fields
//! let register = RegisterRequest::builder()
//!     .email("user@example.com")
//!     .password("secure_password")
//!     .name("Alice")
//!     .build();
//!
//! // Login request
//! let login = LoginRequest::builder()
//!     .email("user@example.com")
//!     .password("secure_password")
//!     .build();
//!
//! // Vault creation with optional description
//! let vault = CreateVaultRequest::builder()
//!     .name("my-vault")
//!     .maybe_description(Some("Production policies".to_string()))
//!     .build();
//! ```
//!
//! ## AppState Builder
//!
//! The [`AppState`] struct uses a builder for server initialization:
//!
//! ```no_run
//! use std::sync::Arc;
//! use inferadb_control_api::AppState;
//!
//! # async fn example(storage: Arc<inferadb_control_storage::Backend>, config: Arc<inferadb_control_config::ControlConfig>) {
//! let state = AppState::builder()
//!     .storage(storage)
//!     .config(config)
//!     .worker_id(1)
//!     .maybe_leader(None)           // Optional leader election
//!     .maybe_email_service(None)    // Optional email service
//!     .maybe_control_identity(None) // Optional control identity
//!     .build();
//! # }
//! ```

#![deny(unsafe_code)]

use std::sync::Arc;

use inferadb_control_core::{ControlConfig, startup};
use inferadb_control_storage::Backend;
use tracing::info;

pub mod audit;
pub mod handlers;
pub mod middleware;
pub mod pagination;
pub mod routes;

pub use handlers::AppState;
pub use inferadb_control_types::{
    dto::ErrorResponse,
    identity::{ControlIdentity, SharedControlIdentity},
};
pub use middleware::{
    OrganizationContext, SessionContext, VaultContext, extract_session_context,
    get_user_vault_role, require_admin, require_admin_or_owner, require_manager, require_member,
    require_organization_member, require_owner, require_reader, require_session,
    require_vault_access, require_writer,
};
pub use pagination::{Paginated, PaginationMeta, PaginationParams, PaginationQuery};
pub use routes::create_router_with_state;

/// Graceful shutdown signal handler
async fn shutdown_signal() {
    use tokio::signal;

    let ctrl_c = async {
        signal::ctrl_c().await.expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
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
    pub leader: Option<Arc<inferadb_control_core::LeaderElection<Backend>>>,
    pub email_service: Option<Arc<inferadb_control_core::EmailService>>,
    pub control_identity: Option<Arc<ControlIdentity>>,
}

/// Start the Control API HTTP server
pub async fn serve(
    storage: Arc<Backend>,
    config: Arc<ControlConfig>,
    worker_id: u16,
    services: ServicesConfig,
) -> anyhow::Result<()> {
    // Create AppState with services using the builder pattern
    let state = AppState::builder()
        .storage(storage.clone())
        .config(config.clone())
        .worker_id(worker_id)
        .maybe_leader(services.leader)
        .maybe_email_service(services.email_service)
        .maybe_control_identity(services.control_identity)
        .build();

    // Create router
    let router = routes::create_router_with_state(state.clone());

    // Bind listener (address is already validated in config)
    let listener = tokio::net::TcpListener::bind(&config.listen.http).await?;

    // Log ready status
    startup::log_ready("Control");

    // Serve with graceful shutdown
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| anyhow::anyhow!("Server error: {e}"))?;

    Ok(())
}
