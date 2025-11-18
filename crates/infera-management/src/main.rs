use anyhow::Result;
use clap::Parser;
use infera_management_core::{logging, ManagementConfig};

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

    // TODO: Initialize storage
    // TODO: Start HTTP server
    // TODO: Start gRPC server

    tracing::info!("Management API started successfully");

    // Keep running until interrupted
    tokio::signal::ctrl_c().await?;
    tracing::info!("Shutting down gracefully");

    Ok(())
}
