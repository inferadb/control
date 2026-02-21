use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use inferadb_control_config::{Cli, LogFormat, StorageBackend};
use inferadb_control_core::{
    EmailService, IdGenerator, SmtpEmailService, WorkerRegistry, acquire_worker_id, logging,
    startup,
};
use inferadb_control_storage::{
    LedgerConfig as StorageLedgerConfig,
    factory::{StorageConfig, create_storage_backend},
};
use inferadb_control_types::ControlIdentity;

#[tokio::main]
async fn main() -> Result<()> {
    // Install the rustls crypto provider early, before any TLS operations.
    // SAFETY: Crypto provider installation failure is unrecoverable at startup
    #[allow(clippy::expect_used)]
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let cli = Cli::parse();
    let config = cli.config;

    // Clear terminal when running interactively with non-JSON output
    if config.log_format != LogFormat::Json && std::io::IsTerminal::is_terminal(&std::io::stdout())
    {
        print!("\x1B[2J\x1B[1;1H");
    }

    config.validate()?;

    // Initialize structured logging
    let log_config = logging::LogConfig {
        format: match config.log_format {
            LogFormat::Json => logging::LogFormat::Json,
            LogFormat::Text => logging::LogFormat::Full,
            LogFormat::Auto => {
                if std::io::IsTerminal::is_terminal(&std::io::stdout()) {
                    logging::LogFormat::Full
                } else {
                    logging::LogFormat::Json
                }
            },
        },
        filter: Some(config.log_level.clone()),
        ..Default::default()
    };

    if let Err(e) = logging::init_logging(log_config) {
        eprintln!("Failed to initialize logging: {e}");
        std::process::exit(1);
    }

    if config.is_dev_mode() {
        tracing::info!("Development mode enabled via --dev-mode flag: using memory storage");
    }

    let effective_storage = config.effective_storage();

    // Display startup banner and configuration summary
    if config.log_format != LogFormat::Json {
        let private_key_entry = if let Some(ref pem) = config.pem {
            startup::ConfigEntry::new("Identity", "Private Key", startup::private_key_hint(pem))
        } else {
            startup::ConfigEntry::warning("Identity", "Private Key", "○ Unassigned")
        };

        startup::StartupDisplay::new(startup::ServiceInfo {
            name: "InferaDB",
            subtext: "Control",
            version: env!("CARGO_PKG_VERSION"),
            environment: if config.is_dev_mode() {
                "development".to_string()
            } else {
                "production".to_string()
            },
        })
        .entries(vec![
            startup::ConfigEntry::new("Storage", "Backend", effective_storage.to_string()),
            startup::ConfigEntry::new("Listen", "HTTP", config.listen.to_string()),
            startup::ConfigEntry::separator("Listen"),
            private_key_entry,
        ])
        .display();
    } else {
        tracing::info!(version = env!("CARGO_PKG_VERSION"), "Starting InferaDB Control");
    }

    // Storage backend
    let storage_config = match effective_storage {
        StorageBackend::Memory => StorageConfig::memory(),
        StorageBackend::Ledger => {
            // config.validate() ensures these fields are present when storage == ledger
            #[allow(clippy::expect_used)]
            let ledger_config = StorageLedgerConfig {
                endpoint: config.ledger_endpoint.clone().expect("validated"),
                client_id: config.ledger_client_id.clone().expect("validated"),
                namespace_id: config.ledger_namespace_id.expect("validated"),
                vault_id: config.ledger_vault_id,
            };
            StorageConfig::ledger(ledger_config)
        },
    };
    let storage = Arc::new(create_storage_backend(&storage_config).await?);
    startup::log_initialized(&format!("Storage ({effective_storage})"));

    // Acquire worker ID automatically (uses pod ordinal or random with collision detection)
    let worker_id = acquire_worker_id(storage.as_ref(), None)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to acquire worker ID: {e}"))?;

    // Initialize the ID generator with the acquired worker ID
    IdGenerator::init(worker_id)
        .map_err(|e| anyhow::anyhow!("Failed to initialize ID generator: {e}"))?;

    // Start worker registry heartbeat to maintain registration
    let worker_registry = Arc::new(WorkerRegistry::new(storage.as_ref().clone(), worker_id));
    worker_registry.clone().start_heartbeat();
    startup::log_initialized(&format!("Worker ID ({worker_id})"));

    // Identity for engine authentication
    let control_identity = if let Some(ref pem) = config.pem {
        ControlIdentity::from_pem(pem)?
    } else {
        let identity = ControlIdentity::generate();
        let pem = identity.to_pem()?;
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

    // Initialize email service (if configured)
    let email_service = if config.is_email_enabled() {
        match SmtpEmailService::new(
            &config.email_host,
            config.email_port,
            config.email_username.as_deref().unwrap_or_default(),
            config.email_password.as_deref().unwrap_or_default(),
            config.email_from_address.clone(),
            config.email_from_name.clone(),
            config.email_insecure,
        ) {
            Ok(smtp_service) => {
                startup::log_initialized(&format!(
                    "Email service ({}:{}{})",
                    config.email_host,
                    config.email_port,
                    if config.email_insecure { " [insecure]" } else { "" }
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
