// REST API handlers and routes

use infera_management_core::ManagementConfig;
use infera_management_grpc::ServerApiClient;
use infera_management_storage::Backend;
use std::sync::Arc;
use tracing::info;

pub mod audit;
pub mod handlers;
pub mod middleware;
pub mod pagination;
pub mod routes;

pub use handlers::{AppState, ErrorResponse};
pub use middleware::{
    extract_session_context, get_user_vault_role, require_admin, require_admin_or_owner,
    require_manager, require_member, require_organization_member, require_owner, require_reader,
    require_session, require_vault_access, require_writer, OrganizationContext, SessionContext,
    VaultContext,
};
pub use pagination::{Paginated, PaginationMeta, PaginationParams, PaginationQuery};
pub use routes::create_router_with_state;

/// Graceful shutdown signal handler
async fn shutdown_signal() {
    use tokio::signal;

    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
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

/// Start the Management API HTTP server
pub async fn serve(
    storage: Arc<Backend>,
    config: Arc<ManagementConfig>,
    server_client: Arc<ServerApiClient>,
    worker_id: u16,
    leader: Option<Arc<infera_management_core::LeaderElection<Backend>>>,
    email_service: Option<Arc<infera_management_core::EmailService>>,
) -> anyhow::Result<()> {
    // Create AppState with services
    let state = AppState::new(
        storage,
        config.clone(),
        server_client,
        worker_id,
        leader,
        email_service,
    );

    let app = create_router_with_state(state);

    let addr = format!("{}:{}", config.server.http_host, config.server.http_port);
    info!("Starting Management API HTTP server on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;

    // Setup graceful shutdown
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    // Spawn task to handle shutdown signals
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(());
    });

    // Serve with graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            shutdown_rx.await.ok();
        })
        .await?;

    Ok(())
}
