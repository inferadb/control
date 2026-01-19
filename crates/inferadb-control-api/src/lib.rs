// REST API handlers and routes

use std::sync::Arc;

use inferadb_control_core::{ControlConfig, startup};
use inferadb_control_engine_client::EngineClient;
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

/// Start the Control API HTTP server (dual-server or single-server mode)
pub async fn serve(
    storage: Arc<Backend>,
    config: Arc<ControlConfig>,
    engine_client: Arc<EngineClient>,
    worker_id: u16,
    services: ServicesConfig,
) -> anyhow::Result<()> {
    // Create AppState with services using the builder pattern
    let mut builder =
        AppState::builder(storage.clone(), config.clone(), engine_client.clone(), worker_id);

    if let Some(leader) = services.leader {
        builder = builder.leader(leader);
    }
    if let Some(email_service) = services.email_service {
        builder = builder.email_service(email_service);
    }
    if let Some(control_identity) = services.control_identity {
        builder = builder.control_identity(control_identity);
    }

    let state = builder.build();

    // Create routers for both servers
    let public_router = routes::public_routes(state.clone());
    let internal_router = routes::internal_routes(state.clone());

    // Bind listeners (addresses are already validated in config)
    let public_listener = tokio::net::TcpListener::bind(&config.listen.http).await?;
    let internal_listener = tokio::net::TcpListener::bind(&config.listen.mesh).await?;

    // Log ready status
    startup::log_ready("Control");

    // Setup graceful shutdown
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::broadcast::channel::<()>(2);
    let mut shutdown_rx_internal = shutdown_tx.subscribe();

    // Spawn task to handle shutdown signals
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(());
    });
    tokio::try_join!(
        async {
            axum::serve(public_listener, public_router)
                .with_graceful_shutdown(async move {
                    shutdown_rx.recv().await.ok();
                })
                .await
                .map_err(|e| anyhow::anyhow!("Public server error: {}", e))
        },
        async {
            axum::serve(internal_listener, internal_router)
                .with_graceful_shutdown(async move {
                    shutdown_rx_internal.recv().await.ok();
                })
                .await
                .map_err(|e| anyhow::anyhow!("Internal server error: {}", e))
        }
    )?;

    Ok(())
}
