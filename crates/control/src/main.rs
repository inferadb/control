//! InferaDB control plane binary entrypoint.

use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use inferadb_control_config::{Cli, LogFormat, StorageBackend};
use inferadb_control_core::{
    AnyRateLimiter, EmailService, IdGenerator, SmtpEmailService, ledger_rate_limiter, logging,
    parse_blinding_key, startup,
};
#[tokio::main]
async fn main() -> Result<()> {
    #[allow(clippy::expect_used)]
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let cli = Cli::parse();
    let config = cli.config;

    if config.log_format != LogFormat::Json && std::io::IsTerminal::is_terminal(&std::io::stdout())
    {
        print!("\x1B[2J\x1B[1;1H");
    }

    config.validate()?;

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

    if config.log_format != LogFormat::Json {
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
        ])
        .display();
    } else {
        tracing::info!(version = env!("CARGO_PKG_VERSION"), "Starting InferaDB Control");
    }

    let worker_id: u16 = config.worker_id.unwrap_or_else(|| {
        let id = rand::random::<u16>() % 1024;
        tracing::warn!(
            worker_id = id,
            "No --worker-id or INFERADB__CONTROL__WORKER_ID set; using random value. \
             In multi-instance deployments, set a unique worker ID per instance to \
             guarantee Snowflake ID uniqueness."
        );
        id
    });

    IdGenerator::init(worker_id)
        .map_err(|e| anyhow::anyhow!("Failed to initialize ID generator: {e}"))?;

    startup::log_initialized(&format!("Worker ID ({worker_id})"));

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

    let blinding_key = parse_blinding_key(config.email_blinding_key.as_deref())?.map(Arc::new);
    if blinding_key.is_some() {
        startup::log_initialized("Email blinding key");
    }

    let ledger = if effective_storage == StorageBackend::Ledger {
        // config.validate() ensures these fields are present when storage == ledger
        #[allow(clippy::expect_used)]
        let endpoint = config.ledger_endpoint.as_ref().expect("validated");
        #[allow(clippy::expect_used)]
        let client_id = config.ledger_client_id.as_ref().expect("validated");

        let ledger_client = inferadb_ledger_sdk::LedgerClient::connect(endpoint, client_id)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to connect to Ledger: {e}"))?;
        startup::log_initialized("Ledger SDK client");
        Some(Arc::new(ledger_client))
    } else {
        None
    };

    // Initialize rate limiter — Ledger-backed when a Ledger client is available,
    // in-memory otherwise (dev-mode / memory storage).
    let rate_limiter = if let Some(ref ledger_client) = ledger {
        #[allow(clippy::expect_used)]
        let org_id = config.ledger_organization.expect("validated");
        let caller =
            inferadb_ledger_sdk::UserSlug::new(inferadb_control_const::auth::SYSTEM_CALLER_SLUG);
        let organization = inferadb_ledger_sdk::OrganizationSlug::new(org_id);
        let limiter = ledger_rate_limiter(Arc::clone(ledger_client), caller, organization);
        startup::log_initialized("Rate limiter (Ledger-backed)");
        Arc::new(AnyRateLimiter::Ledger(limiter))
    } else {
        startup::log_initialized("Rate limiter (in-memory)");
        Arc::new(AnyRateLimiter::InMemory(inferadb_control_core::in_memory_rate_limiter()))
    };

    let webauthn = inferadb_control_core::webauthn::build_webauthn(
        &config.webauthn_rp_id,
        &config.webauthn_origin,
    )?;
    startup::log_initialized(&format!(
        "WebAuthn (rp_id={}, origin={})",
        config.webauthn_rp_id, config.webauthn_origin
    ));
    let webauthn = Arc::new(webauthn);

    let config = Arc::new(config);

    inferadb_control_api::serve(
        config.clone(),
        worker_id,
        inferadb_control_api::ServicesConfig {
            email_service,
            ledger,
            blinding_key,
            webauthn: Some(webauthn),
            rate_limiter: Some(rate_limiter),
        },
    )
    .await?;

    tracing::info!("Shutting down gracefully");
    Ok(())
}
