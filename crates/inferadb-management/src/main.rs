use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use inferadb_management_api::ManagementIdentity;
use inferadb_management_core::{ManagementConfig, WebhookClient, logging};
use inferadb_management_grpc::ServerApiClient;
use inferadb_management_storage::factory::{StorageConfig, create_storage_backend};

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
    // Install the rustls crypto provider early, before any TLS operations.
    // This is required for crates like `kube` that use rustls internally.
    // Using aws-lc-rs as the provider for consistency with jsonwebtoken.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

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
    let server_client = Arc::new(ServerApiClient::new(config.server_api.grpc_endpoint.clone())?);
    tracing::info!("Server API client initialized successfully");

    // Initialize Management API identity for webhook authentication
    tracing::info!(
        management_id = %config.management_identity.management_id,
        kid = %config.management_identity.kid,
        "Initializing Management API identity"
    );
    let management_identity = if let Some(ref pem) = config.management_identity.private_key_pem {
        tracing::info!("Loading Management identity from configured private key");
        ManagementIdentity::from_pem(
            config.management_identity.management_id.clone(),
            config.management_identity.kid.clone(),
            pem,
        )
        .map_err(|e| anyhow::anyhow!("Failed to load Management identity from PEM: {}", e))?
    } else {
        tracing::info!("Generating new Management identity (no private key configured)");
        let identity = ManagementIdentity::generate(
            config.management_identity.management_id.clone(),
            config.management_identity.kid.clone(),
        );

        // Log the generated PEM for persistence (in production, save this to config)
        let pem = identity.to_pem();
        tracing::warn!(
            "Generated new Ed25519 keypair for Management identity. \
             To persist this identity across restarts, add this to your config:\n\
             management_identity:\n  private_key_pem: |\n{}",
            pem.lines().map(|l| format!("    {}", l)).collect::<Vec<_>>().join("\n")
        );

        identity
    };
    let management_identity = Arc::new(management_identity);
    tracing::info!("Management API identity initialized successfully");

    // Initialize webhook client for cache invalidation (if endpoints configured)
    let webhook_client = if !config.cache_invalidation.http_endpoints.is_empty() {
        tracing::info!(
            endpoints = ?config.cache_invalidation.http_endpoints,
            timeout_ms = config.cache_invalidation.timeout_ms,
            retry_attempts = config.cache_invalidation.retry_attempts,
            discovery_mode = ?config.cache_invalidation.discovery.mode,
            cache_ttl_seconds = config.cache_invalidation.discovery.cache_ttl_seconds,
            "Initializing webhook client for cache invalidation"
        );

        let client = WebhookClient::new_with_discovery(
            config.cache_invalidation.http_endpoints.clone(),
            Arc::clone(&management_identity),
            config.cache_invalidation.timeout_ms,
            config.cache_invalidation.discovery.mode.clone(),
            config.cache_invalidation.discovery.cache_ttl_seconds,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create webhook client: {}", e))?;

        tracing::info!("Webhook client initialized successfully");
        Some(Arc::new(client))
    } else {
        tracing::info!("Webhook client disabled (no http_endpoints configured)");
        None
    };

    // Wrap config in Arc for sharing across services
    let config = Arc::new(config);

    // Start HTTP server
    // Note: Leader election and email service are optional for now
    // They can be initialized and passed when needed for multi-node deployments
    tracing::info!("Starting HTTP server");
    inferadb_management_api::serve(
        storage.clone(),
        config.clone(),
        server_client.clone(),
        config.id_generation.worker_id,
        inferadb_management_api::ServicesConfig {
            leader: None,        // leader election (optional, for multi-node)
            email_service: None, // email service (optional, can be initialized later)
            webhook_client,      // cache invalidation webhooks
            management_identity: Some(management_identity), // management identity for JWKS endpoint
        },
    )
    .await?;

    tracing::info!("Shutting down gracefully");
    Ok(())
}
