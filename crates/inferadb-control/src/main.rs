use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use inferadb_control_api::ControlIdentity;
use inferadb_control_core::{
    ControlConfig, EmailService, IdGenerator, SmtpConfig, SmtpEmailService, WorkerRegistry,
    acquire_worker_id, logging, startup,
};
use inferadb_control_engine_client::EngineClient;
use inferadb_control_storage::{
    LedgerConfig as StorageLedgerConfig,
    factory::{StorageConfig, create_storage_backend},
};
use inferadb_control_types::DiscoveryMode;

#[derive(Parser, Debug)]
#[command(name = "inferadb-control")]
#[command(about = "InferaDB Control", long_about = None)]
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

    /// Force development mode with in-memory storage.
    /// Use this flag for local development and testing without Ledger.
    /// In production, Ledger storage is the default and required.
    #[arg(long)]
    dev_mode: bool,
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
    let mut config = ControlConfig::load(&args.config)?;

    // Apply environment-aware defaults (in development, auto-fallback to memory if no Ledger
    // config)
    config.apply_environment_defaults(&args.environment);

    // Handle --dev-mode flag: force memory storage for development/testing
    if args.dev_mode {
        tracing::info!("Development mode enabled via --dev-mode flag: using memory storage");
        config.storage = "memory".to_string();
    }

    config.validate()?;

    // Initialize structured logging with environment-appropriate format
    // Use Full format (matching server) in development, JSON in production
    let log_config = logging::LogConfig {
        format: if args.json_logs || args.environment == "production" {
            logging::LogFormat::Json
        } else {
            logging::LogFormat::Full // Match server's default output style
        },
        filter: Some(config.logging.clone()),
        ..Default::default()
    };

    if let Err(e) = logging::init_logging(log_config) {
        eprintln!("Failed to initialize logging: {e}");
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
        let private_key_entry = if let Some(ref pem) = config.pem {
            startup::ConfigEntry::new("Identity", "Private Key", startup::private_key_hint(pem))
        } else {
            startup::ConfigEntry::warning("Identity", "Private Key", "○ Unassigned")
        };

        // Create policy service entry with discovery context
        let policy_url = config.effective_mesh_url();
        let policy_entry = match &config.discovery.mode {
            DiscoveryMode::None => startup::ConfigEntry::new(
                "Network",
                "Engine Endpoint",
                format!("{policy_url} (local)"),
            ),
            DiscoveryMode::Kubernetes => startup::ConfigEntry::new(
                "Network",
                "Engine Endpoint",
                format!("{policy_url} (kubernetes)"),
            ),
        };

        // Create discovery mode entry
        let discovery_entry = match config.discovery.mode {
            DiscoveryMode::None => {
                startup::ConfigEntry::warning("Network", "Service Discovery", "○ Disabled")
            },
            DiscoveryMode::Kubernetes => {
                startup::ConfigEntry::new("Network", "Service Discovery", "✓ Enabled")
            },
        };

        startup::StartupDisplay::new(startup::ServiceInfo {
            name: "InferaDB",
            subtext: "Control",
            version: env!("CARGO_PKG_VERSION"),
            environment: args.environment.clone(),
        })
        .entries(vec![
            // General
            startup::ConfigEntry::new("General", "Environment", &args.environment),
            startup::ConfigEntry::new("General", "Configuration File", &config_path),
            // Storage
            startup::ConfigEntry::new("Storage", "Backend", &config.storage),
            // Listen
            startup::ConfigEntry::new("Listen", "HTTP", &config.listen.http),
            startup::ConfigEntry::new("Listen", "gRPC", &config.listen.grpc),
            startup::ConfigEntry::new("Listen", "Mesh", &config.listen.mesh),
            startup::ConfigEntry::separator("Listen"),
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
            "Starting InferaDB Control"
        );
    }

    // Storage backend
    let storage_config = match config.storage.as_str() {
        "memory" => StorageConfig::memory(),
        "ledger" => {
            let ledger_config = StorageLedgerConfig {
                endpoint: config.ledger.endpoint.clone().expect("validated"),
                client_id: config.ledger.client_id.clone().expect("validated"),
                namespace_id: config.ledger.namespace_id.expect("validated"),
                vault_id: config.ledger.vault_id,
            };
            StorageConfig::ledger(ledger_config)
        },
        _ => anyhow::bail!(
            "Invalid storage backend: '{}'. Supported: 'memory', 'ledger'",
            config.storage
        ),
    };
    let storage = Arc::new(create_storage_backend(&storage_config).await?);
    startup::log_initialized(&format!("Storage ({})", config.storage));

    // Acquire worker ID automatically (uses pod ordinal or random with collision detection)
    let worker_id = acquire_worker_id(storage.as_ref(), None)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to acquire worker ID: {e}"))?;

    // Initialize the ID generator with the acquired worker ID
    IdGenerator::init(worker_id)
        .map_err(|e| anyhow::anyhow!("Failed to initialize ID generator: {e}"))?;

    // Start worker registry heartbeat to maintain registration
    // Note: acquire_worker_id already registers the ID with TTL, so we only need to start the
    // heartbeat
    let worker_registry = Arc::new(WorkerRegistry::new(storage.as_ref().clone(), worker_id));
    worker_registry.clone().start_heartbeat();
    startup::log_initialized(&format!("Worker ID ({worker_id})"));

    // Identity for engine authentication (needs to be created before engine_client)
    let control_identity = if let Some(ref pem) = config.pem {
        ControlIdentity::from_pem(pem)
            .map_err(|e| anyhow::anyhow!("Failed to load Control identity from PEM: {e}"))?
    } else {
        // Generate new identity and display in formatted box
        let identity = ControlIdentity::generate();
        let pem = identity.to_pem();
        startup::print_generated_keypair(&pem, "pem");
        identity
    };

    tracing::info!(
        control_id = %control_identity.control_id,
        kid = %control_identity.kid,
        "Control identity initialized"
    );

    let control_identity = Arc::new(control_identity);
    startup::log_initialized("Identity");

    // Engine client (for communication with engine)
    // Uses control identity for JWT authentication and discovery for load balancing
    let engine_client = Arc::new(EngineClient::with_config(
        config.mesh.url.clone(),
        config.mesh.grpc,
        Some(Arc::clone(&control_identity)),
        config.discovery.mode.clone(),
        config.discovery.cache_ttl,
        config.webhook.timeout,
    )?);
    startup::log_initialized("Engine client");

    // Initialize email service (if configured)
    let email_service = if !config.email.host.is_empty() {
        let smtp_config = SmtpConfig {
            host: config.email.host.clone(),
            port: config.email.port,
            username: config.email.username.clone().unwrap_or_default(),
            password: config.email.password.clone().unwrap_or_default(),
            address: config.email.address.clone(),
            name: config.email.name.clone(),
            insecure: config.email.insecure,
        };

        match SmtpEmailService::new(smtp_config) {
            Ok(smtp_service) => {
                startup::log_initialized(&format!(
                    "Email service ({}:{}{})",
                    config.email.host,
                    config.email.port,
                    if config.email.insecure { " [insecure]" } else { "" }
                ));
                Some(Arc::new(EmailService::new(Box::new(smtp_service))))
            },
            Err(e) => {
                tracing::warn!(error = %e, "Failed to initialize email service - emails will be disabled");
                None
            },
        }
    } else {
        tracing::info!("Email service not configured - verification emails disabled");
        None
    };

    // Wrap config in Arc for sharing across services
    let config = Arc::new(config);

    inferadb_control_api::serve(
        storage.clone(),
        config.clone(),
        engine_client.clone(),
        worker_id,
        inferadb_control_api::ServicesConfig {
            leader: None,
            email_service,
            control_identity: Some(control_identity),
        },
    )
    .await?;

    tracing::info!("Shutting down gracefully");
    Ok(())
}
