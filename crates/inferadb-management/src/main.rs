use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use inferadb_management_api::ManagementIdentity;
use inferadb_management_core::{
    ManagementConfig, WebhookClient, config::DiscoveryMode, logging, startup,
};
use inferadb_management_grpc::ServerApiClient;
use inferadb_management_storage::factory::{StorageConfig, create_storage_backend};

#[derive(Parser, Debug)]
#[command(name = "inferadb-management")]
#[command(about = "InferaDB Management Service", long_about = None)]
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

    // Clear terminal in development mode when running interactively
    if args.environment != "production" && std::io::IsTerminal::is_terminal(&std::io::stdout()) {
        print!("\x1B[2J\x1B[1;1H");
    }

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

    // Get full path of configuration file
    let config_path = std::fs::canonicalize(&args.config)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| args.config.clone());

    // Display startup banner and configuration summary
    let use_json = args.json_logs || args.environment == "production";
    if !use_json {
        // Create the private key entry based on whether it's configured
        let private_key_entry = if let Some(ref pem) = config.identity.private_key_pem {
            startup::ConfigEntry::new("Identity", "Private Key", startup::private_key_hint(pem))
        } else {
            startup::ConfigEntry::warning("Identity", "Private Key", "○ Unassigned")
        };

        // Create policy service entry with discovery context
        let policy_url = config.effective_internal_url();
        let policy_entry = match &config.discovery.mode {
            DiscoveryMode::None => startup::ConfigEntry::new(
                "Network",
                "Policy Service",
                format!("{} (local)", policy_url),
            ),
            DiscoveryMode::Kubernetes => startup::ConfigEntry::new(
                "Network",
                "Policy Service",
                format!("{} (kubernetes)", policy_url),
            ),
            DiscoveryMode::Tailscale { local_cluster, .. } => startup::ConfigEntry::new(
                "Network",
                "Policy Service",
                format!("{} (tailscale:{})", policy_url, local_cluster),
            ),
        };

        // Create discovery mode entry
        let discovery_entry = match config.discovery.mode {
            DiscoveryMode::None => {
                startup::ConfigEntry::warning("Network", "Service Discovery", "○ Disabled")
            },
            DiscoveryMode::Kubernetes | DiscoveryMode::Tailscale { .. } => {
                startup::ConfigEntry::new("Network", "Service Discovery", "✓ Enabled")
            },
        };

        startup::StartupDisplay::new(startup::ServiceInfo {
            name: "InferaDB",
            subtext: "Management Service",
            version: env!("CARGO_PKG_VERSION"),
            environment: args.environment.clone(),
        })
        .entries(vec![
            // General
            startup::ConfigEntry::new("General", "Environment", &args.environment),
            startup::ConfigEntry::new("General", "Worker ID", config.id_generation.worker_id),
            startup::ConfigEntry::new("General", "Configuration File", &config_path),
            // Storage
            startup::ConfigEntry::new("Storage", "Backend", &config.storage.backend),
            // Network
            startup::ConfigEntry::new("Network", "Public API (REST)", &config.server.public_rest),
            startup::ConfigEntry::new("Network", "Public API (gRPC)", &config.server.public_grpc),
            startup::ConfigEntry::new("Network", "Private API (REST)", &config.server.private_rest),
            startup::ConfigEntry::separator("Network"),
            policy_entry,
            discovery_entry,
            private_key_entry,
        ])
        .display();
    } else {
        tracing::info!(
            version = env!("CARGO_PKG_VERSION"),
            environment = %args.environment,
            config_file = %args.config,
            worker_id = config.id_generation.worker_id,
            "Starting InferaDB Management Service"
        );
    }

    // Storage backend
    let storage_config = match config.storage.backend.as_str() {
        "memory" => StorageConfig::memory(),
        "foundationdb" => StorageConfig::foundationdb(config.storage.fdb_cluster_file.clone()),
        _ => anyhow::bail!("Invalid storage backend: {}", config.storage.backend),
    };
    let storage = Arc::new(create_storage_backend(&storage_config).await?);
    startup::log_initialized(&format!("Storage ({})", config.storage.backend));

    // Server API client (for gRPC communication with policy service)
    let server_client = Arc::new(ServerApiClient::new(
        config.policy_service.service_url.clone(),
        config.policy_service.grpc_port,
    )?);
    startup::log_initialized("Policy Service client");

    // Management API identity for webhook authentication
    let management_identity = if let Some(ref pem) = config.identity.private_key_pem {
        ManagementIdentity::from_pem(pem)
            .map_err(|e| anyhow::anyhow!("Failed to load Management identity from PEM: {}", e))?
    } else {
        // Generate new identity and display in formatted box
        let identity = ManagementIdentity::generate();
        let pem = identity.to_pem();
        startup::print_generated_keypair(&pem, "identity.private_key_pem");
        identity
    };

    tracing::info!(
        management_id = %management_identity.management_id,
        kid = %management_identity.kid,
        "Management identity initialized"
    );

    let management_identity = Arc::new(management_identity);
    startup::log_initialized("Identity");

    // Webhook client for cache invalidation
    // Always enabled - uses discovery mode to find policy service (server) instances automatically
    let webhook_client = WebhookClient::new(
        config.policy_service.service_url.clone(),
        config.policy_service.internal_port,
        Arc::clone(&management_identity),
        config.cache_invalidation.timeout_ms,
        config.discovery.mode.clone(),
        config.discovery.cache_ttl,
    )
    .map_err(|e| anyhow::anyhow!("Failed to create webhook client: {}", e))?;
    startup::log_initialized("Webhook client");
    let webhook_client = Some(Arc::new(webhook_client));

    // Wrap config in Arc for sharing across services
    let config = Arc::new(config);

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
