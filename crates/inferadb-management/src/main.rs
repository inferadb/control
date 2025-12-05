use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use inferadb_management_api::ManagementIdentity;
use inferadb_management_core::{ManagementConfig, WebhookClient, logging, startup};
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

    // Initialize structured logging with environment-appropriate format
    // Use Full format (matching server) in development, JSON in production
    let log_config = logging::LogConfig {
        format: if args.json_logs || args.environment == "production" {
            logging::LogFormat::Json
        } else {
            logging::LogFormat::Full // Match server's default output style
        },
        filter: Some(config.observability.log_level.clone()),
        ..Default::default()
    };

    if let Err(e) = logging::init_logging(log_config) {
        eprintln!("Failed to initialize logging: {}", e);
        std::process::exit(1);
    }

    // Display startup banner and configuration summary
    let use_json = args.json_logs || args.environment == "production";
    if !use_json {
        startup::StartupDisplay::new(startup::ServiceInfo {
            name: "InferaDB",
            subtext: "Management API Server",
            version: env!("CARGO_PKG_VERSION"),
            environment: args.environment.clone(),
        })
        .entries(vec![
            startup::ConfigEntry::new("General", "environment", &args.environment),
            startup::ConfigEntry::new("General", "config_file", &args.config),
            startup::ConfigEntry::new("General", "worker_id", config.id_generation.worker_id),
            startup::ConfigEntry::new("Storage", "backend", &config.storage.backend),
            startup::ConfigEntry::new(
                "Server API",
                "grpc_endpoint",
                &config.server_api.grpc_endpoint,
            ),
            startup::ConfigEntry::new(
                "Identity",
                "management_id",
                &config.management_identity.management_id,
            ),
            startup::ConfigEntry::new("Identity", "kid", &config.management_identity.kid),
            startup::ConfigEntry::new(
                "Observability",
                "log_level",
                &config.observability.log_level,
            ),
            startup::ConfigEntry::new(
                "Observability",
                "metrics_enabled",
                config.observability.metrics_enabled,
            ),
        ])
        .display();
    } else {
        tracing::info!(
            version = env!("CARGO_PKG_VERSION"),
            environment = %args.environment,
            config_file = %args.config,
            worker_id = config.id_generation.worker_id,
            "Starting InferaDB Management API"
        );
    }

    // ━━━ Initialize Components ━━━
    startup::log_phase("Initializing Components");

    // Storage backend
    let storage_config = match config.storage.backend.as_str() {
        "memory" => StorageConfig::memory(),
        "foundationdb" => StorageConfig::foundationdb(config.storage.fdb_cluster_file.clone()),
        _ => anyhow::bail!("Invalid storage backend: {}", config.storage.backend),
    };
    let storage = Arc::new(create_storage_backend(&storage_config).await?);
    startup::log_initialized(&format!("Storage ({})", config.storage.backend));

    // Server API client (for gRPC communication with @server)
    let server_client = Arc::new(ServerApiClient::new(config.server_api.grpc_endpoint.clone())?);
    startup::log_initialized("Server API client");

    // Management API identity for webhook authentication
    let management_identity = if let Some(ref pem) = config.management_identity.private_key_pem {
        ManagementIdentity::from_pem(
            config.management_identity.management_id.clone(),
            config.management_identity.kid.clone(),
            pem,
        )
        .map_err(|e| anyhow::anyhow!("Failed to load Management identity from PEM: {}", e))?
    } else {
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
    startup::log_initialized("Management identity");

    // Webhook client for cache invalidation (if endpoints configured)
    let webhook_client = if !config.cache_invalidation.http_endpoints.is_empty() {
        let client = WebhookClient::new_with_discovery(
            config.cache_invalidation.http_endpoints.clone(),
            Arc::clone(&management_identity),
            config.cache_invalidation.timeout_ms,
            config.cache_invalidation.discovery.mode.clone(),
            config.cache_invalidation.discovery.cache_ttl_seconds,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create webhook client: {}", e))?;

        startup::log_initialized("Webhook client");
        Some(Arc::new(client))
    } else {
        startup::log_skipped("Webhook client", "no http_endpoints configured");
        None
    };

    // Wrap config in Arc for sharing across services
    let config = Arc::new(config);

    // ━━━ Start Server ━━━
    startup::log_phase("Starting Server");
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
