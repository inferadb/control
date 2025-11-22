use anyhow::Result;
use clap::Parser;
use infera_management_core::{logging, ManagementConfig};
use infera_management_grpc::ServerApiClient;
use infera_management_storage::factory::{create_storage_backend, StorageConfig};
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(name = "inferadb-management")]
#[command(about = "InferaDB Management API - Control Plane for InferaDB", long_about = None)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "config.yaml")]
    config: String,

    /// Use JSON structured logging (default: auto-detect based on TTY)
    #[arg(long)]
    json_logs: bool,

    /// Environment (development, staging, production)
    #[arg(short, long, env = "ENVIRONMENT", default_value = "development")]
    environment: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Load configuration
    let config = ManagementConfig::load(&args.config)?;
    config.validate()?;

    // Determine if we should use JSON logging
    // Use JSON in production or when explicitly requested
    let use_json = args.json_logs || args.environment == "production";

    // Initialize structured logging
    logging::init(&config.observability, use_json);

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        environment = %args.environment,
        config_file = %args.config,
        worker_id = config.id_generation.worker_id,
        "Starting InferaDB Management API"
    );

    // Initialize storage backend
    tracing::info!(backend = %config.storage.backend, "Initializing storage backend");
    let storage_config = match config.storage.backend.as_str() {
        "memory" => StorageConfig::memory(),
        "foundationdb" => StorageConfig::foundationdb(config.storage.fdb_cluster_file.clone()),
        _ => anyhow::bail!("Invalid storage backend: {}", config.storage.backend),
    };
    let storage = Arc::new(create_storage_backend(&storage_config).await?);
    tracing::info!("Storage backend initialized successfully");

    // Initialize server API client (for gRPC communication with @server)
    tracing::info!(endpoint = %config.server_api.grpc_endpoint, "Initializing server API client");
    let server_client = Arc::new(ServerApiClient::new(
        config.server_api.grpc_endpoint.clone(),
    )?);
    tracing::info!("Server API client initialized successfully");

    // Wrap config in Arc for sharing across services
    let config = Arc::new(config);

    // Start HTTP server
    // Note: Leader election and email service are optional for now
    // They can be initialized and passed when needed for multi-node deployments
    tracing::info!("Starting HTTP server");
    infera_management_api::serve(
        storage.clone(),
        config.clone(),
        server_client.clone(),
        config.id_generation.worker_id,
        None, // leader election (optional, for multi-node)
        None, // email service (optional, can be initialized later)
    )
    .await?;

    tracing::info!("Shutting down gracefully");
    Ok(())
}
