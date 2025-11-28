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

pub use handlers::AppState;
pub use infera_management_types::dto::ErrorResponse;
pub use infera_management_types::identity::{ManagementIdentity, SharedManagementIdentity};
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

/// Configuration for optional services in the Management API
pub struct ServicesConfig {
    pub leader: Option<Arc<infera_management_core::LeaderElection<Backend>>>,
    pub email_service: Option<Arc<infera_management_core::EmailService>>,
    pub webhook_client: Option<Arc<infera_management_core::WebhookClient>>,
    pub management_identity: Option<Arc<ManagementIdentity>>,
}

/// Start the Management API HTTP server (dual-server or single-server mode)
pub async fn serve(
    storage: Arc<Backend>,
    config: Arc<ManagementConfig>,
    server_client: Arc<ServerApiClient>,
    worker_id: u16,
    services: ServicesConfig,
) -> anyhow::Result<()> {
    // Create AppState with services using the builder pattern
    let mut builder = AppState::builder(
        storage.clone(),
        config.clone(),
        server_client.clone(),
        worker_id,
    );

    if let Some(leader) = services.leader {
        builder = builder.leader(leader);
    }
    if let Some(email_service) = services.email_service {
        builder = builder.email_service(email_service);
    }
    if let Some(webhook_client) = services.webhook_client {
        builder = builder.webhook_client(webhook_client);
    }
    if let Some(management_identity) = services.management_identity {
        builder = builder.management_identity(management_identity);
    }

    let state = builder.build();

    info!(
        "Starting dual-server mode - Public: {}:{}, Internal: {}:{}",
        config.server.http_host,
        config.server.http_port,
        config.server.internal_host,
        config.server.internal_port
    );

    // Create routers for both servers
    let public_router = routes::public_routes(state.clone());
    let internal_router = routes::internal_routes(state.clone());

    // Bind listeners
    let public_addr = format!("{}:{}", config.server.http_host, config.server.http_port);
    let internal_addr = format!(
        "{}:{}",
        config.server.internal_host, config.server.internal_port
    );

    info!("Binding public server to {}", public_addr);
    let public_listener = tokio::net::TcpListener::bind(&public_addr).await?;

    info!("Binding internal server to {}", internal_addr);
    let internal_listener = tokio::net::TcpListener::bind(&internal_addr).await?;

    // Setup graceful shutdown
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::broadcast::channel::<()>(2);
    let mut shutdown_rx_internal = shutdown_tx.subscribe();

    // Spawn task to handle shutdown signals
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(());
    });

    // Start both servers concurrently
    info!("Starting public and internal servers concurrently");
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
