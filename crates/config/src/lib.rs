//! # InferaDB Control Configuration
//!
//! CLI-first configuration for the Control API. Uses `clap::Parser` for
//! argument parsing with environment variable fallbacks, and `bon::Builder`
//! for ergonomic test construction without CLI/env interference.
//!
//! ```no_run
//! use inferadb_control_config::{Cli, Config};
//! use clap::Parser;
//!
//! let cli = Cli::parse();
//! let config = cli.config;
//! config.validate().expect("invalid configuration");
//! ```
//!
//! ```no_run
//! use std::path::PathBuf;
//! use inferadb_control_config::{Config, StorageBackend};
//!
//! let config = Config::builder()
//!     .storage(StorageBackend::Memory)
//!     .frontend_url("http://localhost:3000")
//!     .build();
//! ```

#![deny(unsafe_code)]

use std::{net::SocketAddr, path::PathBuf};

use bon::Builder;
use clap::Parser;
use inferadb_control_types::error::{Error, Result};

/// Default HTTP listen address.
const DEFAULT_LISTEN: &str = "127.0.0.1:9090";

/// Default master key file path.
const DEFAULT_KEY_FILE: &str = "./data/master.key";

/// Default frontend URL for email links.
const DEFAULT_FRONTEND_URL: &str = "http://localhost:3000";

/// Default log level filter string.
const DEFAULT_LOG_LEVEL: &str = "info";

/// Default email from address.
const DEFAULT_EMAIL_FROM_ADDRESS: &str = "noreply@inferadb.com";

/// Default email from display name.
const DEFAULT_EMAIL_FROM_NAME: &str = "InferaDB";

/// Default SMTP port.
const DEFAULT_EMAIL_PORT: u16 = 587;

/// Storage backend selection.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum, strum::Display)]
#[strum(serialize_all = "lowercase")]
pub enum StorageBackend {
    /// In-memory storage (data lost on restart).
    Memory,
    /// Persistent storage via InferaDB Ledger.
    #[default]
    Ledger,
}

/// Log output format.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum, strum::Display)]
#[strum(serialize_all = "lowercase")]
pub enum LogFormat {
    /// Automatically detect: JSON for non-TTY stdout, text otherwise.
    #[default]
    Auto,
    /// JSON structured logging (recommended for production).
    Json,
    /// Human-readable text format.
    Text,
}

/// Command-line interface for the InferaDB Control Plane.
#[derive(Debug, Parser)]
#[command(name = "inferadb-control")]
#[command(version)]
pub struct Cli {
    /// Subcommand to run. If omitted, starts the server.
    #[command(subcommand)]
    pub command: Option<CliCommand>,

    /// Server configuration (flattened so flags appear at top level).
    #[command(flatten)]
    pub config: Config,
}

/// CLI subcommands.
#[derive(Debug, clap::Subcommand)]
pub enum CliCommand {}

/// Configuration for the InferaDB Control Plane.
///
/// All fields are configurable via CLI flags or environment variables.
/// Precedence: CLI arg > env var > default value.
///
/// Sensitive fields (`pem`, `email_password`) use `hide_env_values` to
/// prevent leaking secrets in `--help` output.
#[derive(Debug, Clone, Builder, Parser)]
#[command(name = "inferadb-control")]
#[command(version)]
#[builder(on(String, into))]
pub struct Config {
    // ── Server ───────────────────────────────────────────────────────
    /// HTTP bind address.
    #[arg(long = "listen", env = "INFERADB__CONTROL__LISTEN", default_value = DEFAULT_LISTEN)]
    #[builder(default = default_listen())]
    pub listen: SocketAddr,

    /// Tracing-subscriber filter string (e.g., info, debug, trace).
    #[arg(long = "log-level", env = "INFERADB__CONTROL__LOG_LEVEL", default_value = DEFAULT_LOG_LEVEL)]
    #[builder(default = DEFAULT_LOG_LEVEL.to_string())]
    pub log_level: String,

    /// Log output format: auto, json, or text.
    #[arg(
        long = "log-format",
        env = "INFERADB__CONTROL__LOG_FORMAT",
        value_enum,
        default_value = "auto"
    )]
    #[builder(default)]
    pub log_format: LogFormat,

    // ── Identity & Encryption ────────────────────────────────────────
    /// Ed25519 private key in PEM format for control identity.
    /// If not provided, a new keypair is generated on each startup.
    #[arg(long = "pem", env = "INFERADB__CONTROL__PEM", hide_env_values = true)]
    pub pem: Option<String>,

    /// Path to the AES-256-GCM master key file for encrypting private keys at rest.
    #[arg(long = "key-file", env = "INFERADB__CONTROL__KEY_FILE", default_value = DEFAULT_KEY_FILE)]
    #[builder(default = PathBuf::from(DEFAULT_KEY_FILE))]
    pub key_file: PathBuf,

    // ── Storage ──────────────────────────────────────────────────────
    /// Storage backend: memory or ledger.
    #[arg(
        long = "storage",
        env = "INFERADB__CONTROL__STORAGE",
        value_enum,
        default_value = "ledger"
    )]
    #[builder(default)]
    pub storage: StorageBackend,

    /// Ledger gRPC endpoint URL. Required when storage=ledger.
    #[arg(long = "ledger-endpoint", env = "INFERADB__CONTROL__LEDGER_ENDPOINT")]
    pub ledger_endpoint: Option<String>,

    /// Ledger client identifier for idempotency tracking. Required when storage=ledger.
    #[arg(long = "ledger-client-id", env = "INFERADB__CONTROL__LEDGER_CLIENT_ID")]
    pub ledger_client_id: Option<String>,

    /// Ledger namespace ID for data scoping. Required when storage=ledger.
    #[arg(long = "ledger-namespace-id", env = "INFERADB__CONTROL__LEDGER_NAMESPACE_ID")]
    pub ledger_namespace_id: Option<i64>,

    /// Optional ledger vault ID for finer-grained key scoping.
    #[arg(long = "ledger-vault-id", env = "INFERADB__CONTROL__LEDGER_VAULT_ID")]
    pub ledger_vault_id: Option<i64>,

    // ── Email (SMTP) ─────────────────────────────────────────────────
    /// SMTP host. Empty string disables email.
    #[arg(long = "email-host", env = "INFERADB__CONTROL__EMAIL_HOST", default_value = "")]
    #[builder(default)]
    pub email_host: String,

    /// SMTP port.
    #[arg(long = "email-port", env = "INFERADB__CONTROL__EMAIL_PORT", default_value_t = DEFAULT_EMAIL_PORT)]
    #[builder(default = DEFAULT_EMAIL_PORT)]
    pub email_port: u16,

    /// SMTP username.
    #[arg(long = "email-username", env = "INFERADB__CONTROL__EMAIL_USERNAME")]
    pub email_username: Option<String>,

    /// SMTP password.
    #[arg(
        long = "email-password",
        env = "INFERADB__CONTROL__EMAIL_PASSWORD",
        hide_env_values = true
    )]
    pub email_password: Option<String>,

    /// From email address for outgoing messages.
    #[arg(long = "email-from-address", env = "INFERADB__CONTROL__EMAIL_FROM_ADDRESS", default_value = DEFAULT_EMAIL_FROM_ADDRESS)]
    #[builder(default = DEFAULT_EMAIL_FROM_ADDRESS.to_string())]
    pub email_from_address: String,

    /// From display name for outgoing messages.
    #[arg(long = "email-from-name", env = "INFERADB__CONTROL__EMAIL_FROM_NAME", default_value = DEFAULT_EMAIL_FROM_NAME)]
    #[builder(default = DEFAULT_EMAIL_FROM_NAME.to_string())]
    pub email_from_name: String,

    /// Allow insecure (unencrypted) SMTP connections.
    /// Only for local development with tools like Mailpit.
    #[arg(long = "email-insecure", env = "INFERADB__CONTROL__EMAIL_INSECURE")]
    #[builder(default)]
    pub email_insecure: bool,

    // ── Frontend ─────────────────────────────────────────────────────
    /// Base URL for email links (verification, password reset).
    #[arg(long = "frontend-url", env = "INFERADB__CONTROL__FRONTEND_URL", default_value = DEFAULT_FRONTEND_URL)]
    #[builder(default = DEFAULT_FRONTEND_URL.to_string())]
    pub frontend_url: String,

    // ── Mode Flags ───────────────────────────────────────────────────
    /// Force development mode: uses in-memory storage regardless of --storage.
    /// No environment variable — this must be an explicit CLI choice.
    #[arg(long = "dev-mode")]
    #[builder(default)]
    pub dev_mode: bool,
}

fn default_listen() -> SocketAddr {
    #[allow(clippy::expect_used)]
    DEFAULT_LISTEN.parse().expect("valid default listen address")
}

impl Config {
    /// Validate cross-field business rules.
    ///
    /// Must be called after parsing and before using the config. Checks
    /// ledger storage requirements, frontend URL format, and applies
    /// dev-mode overrides.
    pub fn validate(&self) -> Result<()> {
        // Validate ledger storage requirements
        if self.effective_storage() == StorageBackend::Ledger {
            let Some(endpoint) = self.ledger_endpoint.as_ref() else {
                return Err(Error::config("--ledger-endpoint is required when storage=ledger"));
            };
            if self.ledger_client_id.is_none() {
                return Err(Error::config("--ledger-client-id is required when storage=ledger"));
            }
            if self.ledger_namespace_id.is_none() {
                return Err(Error::config("--ledger-namespace-id is required when storage=ledger"));
            }
            if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
                return Err(Error::config(format!(
                    "--ledger-endpoint must start with http:// or https://, got: {endpoint}"
                )));
            }
        }

        // Validate frontend URL format
        if !self.frontend_url.starts_with("http://") && !self.frontend_url.starts_with("https://") {
            return Err(Error::config("--frontend-url must start with http:// or https://"));
        }

        if self.frontend_url.ends_with('/') {
            return Err(Error::config("--frontend-url must not end with a trailing slash"));
        }

        if self.frontend_url.contains("localhost") || self.frontend_url.contains("127.0.0.1") {
            tracing::warn!(
                "--frontend-url contains localhost — this should only be used in development"
            );
        }

        Ok(())
    }

    /// Returns whether email sending is enabled.
    ///
    /// Email is disabled when `email_host` is empty (the default).
    pub fn is_email_enabled(&self) -> bool {
        !self.email_host.is_empty()
    }

    /// Returns the effective storage backend, accounting for dev-mode override.
    ///
    /// When `dev_mode` is true, always returns `Memory` regardless of the
    /// `storage` field value.
    pub fn effective_storage(&self) -> StorageBackend {
        if self.dev_mode { StorageBackend::Memory } else { self.storage }
    }

    /// Returns whether dev-mode is enabled.
    pub fn is_dev_mode(&self) -> bool {
        self.dev_mode
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // ── Default Values ───────────────────────────────────────────────

    #[test]
    fn defaults_match_expected_values() {
        let config = Config::builder().build();

        assert_eq!(config.listen, "127.0.0.1:9090".parse::<SocketAddr>().unwrap());
        assert_eq!(config.log_level, "info");
        assert_eq!(config.log_format, LogFormat::Auto);
        assert!(config.pem.is_none());
        assert_eq!(config.key_file, PathBuf::from("./data/master.key"));
        assert_eq!(config.storage, StorageBackend::Ledger);
        assert!(config.ledger_endpoint.is_none());
        assert!(config.ledger_client_id.is_none());
        assert!(config.ledger_namespace_id.is_none());
        assert!(config.ledger_vault_id.is_none());
        assert_eq!(config.email_host, "");
        assert_eq!(config.email_port, 587);
        assert!(config.email_username.is_none());
        assert!(config.email_password.is_none());
        assert_eq!(config.email_from_address, "noreply@inferadb.com");
        assert_eq!(config.email_from_name, "InferaDB");
        assert!(!config.email_insecure);
        assert_eq!(config.frontend_url, "http://localhost:3000");
        assert!(!config.dev_mode);
    }

    // ── Validation: Ledger Storage ───────────────────────────────────

    #[test]
    fn validate_rejects_ledger_without_endpoint() {
        let config = Config::builder().storage(StorageBackend::Ledger).build();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("--ledger-endpoint is required"));
    }

    #[test]
    fn validate_rejects_ledger_without_client_id() {
        let config = Config::builder()
            .storage(StorageBackend::Ledger)
            .ledger_endpoint("http://localhost:50051")
            .build();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("--ledger-client-id is required"));
    }

    #[test]
    fn validate_rejects_ledger_without_namespace_id() {
        let config = Config::builder()
            .storage(StorageBackend::Ledger)
            .ledger_endpoint("http://localhost:50051")
            .ledger_client_id("control-test")
            .build();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("--ledger-namespace-id is required"));
    }

    #[test]
    fn validate_rejects_invalid_ledger_endpoint_scheme() {
        let config = Config::builder()
            .storage(StorageBackend::Ledger)
            .ledger_endpoint("grpc://localhost:50051")
            .ledger_client_id("control-test")
            .maybe_ledger_namespace_id(Some(1))
            .build();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("http://"));
    }

    #[test]
    fn validate_passes_complete_ledger_config() {
        let config = Config::builder()
            .storage(StorageBackend::Ledger)
            .ledger_endpoint("http://localhost:50051")
            .ledger_client_id("control-test")
            .maybe_ledger_namespace_id(Some(1))
            .build();
        assert!(config.validate().is_ok());
    }

    // ── Validation: Frontend URL ─────────────────────────────────────

    #[test]
    fn validate_rejects_frontend_url_without_scheme() {
        let config = Config::builder()
            .storage(StorageBackend::Memory)
            .frontend_url("ftp://example.com")
            .build();
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_frontend_url_with_trailing_slash() {
        let config = Config::builder()
            .storage(StorageBackend::Memory)
            .frontend_url("https://example.com/")
            .build();
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_passes_valid_https_frontend_url() {
        let config = Config::builder()
            .storage(StorageBackend::Memory)
            .frontend_url("https://app.inferadb.com")
            .build();
        assert!(config.validate().is_ok());
    }

    // ── Validation: Memory Storage ───────────────────────────────────

    #[test]
    fn validate_passes_minimal_memory_config() {
        let config = Config::builder().storage(StorageBackend::Memory).build();
        assert!(config.validate().is_ok());
    }

    // ── Helper Methods ───────────────────────────────────────────────

    #[test]
    fn is_email_enabled_returns_false_when_host_empty() {
        let config = Config::builder().storage(StorageBackend::Memory).build();
        assert!(!config.is_email_enabled());
    }

    #[test]
    fn is_email_enabled_returns_true_when_host_set() {
        let config = Config::builder()
            .storage(StorageBackend::Memory)
            .email_host("smtp.example.com")
            .build();
        assert!(config.is_email_enabled());
    }

    #[test]
    fn effective_storage_returns_memory_in_dev_mode() {
        let config = Config::builder().storage(StorageBackend::Ledger).dev_mode(true).build();
        assert_eq!(config.effective_storage(), StorageBackend::Memory);
    }

    #[test]
    fn effective_storage_returns_field_when_not_dev_mode() {
        let config = Config::builder().storage(StorageBackend::Ledger).build();
        assert_eq!(config.effective_storage(), StorageBackend::Ledger);

        let config = Config::builder().storage(StorageBackend::Memory).build();
        assert_eq!(config.effective_storage(), StorageBackend::Memory);
    }

    #[test]
    fn dev_mode_skips_ledger_validation() {
        let config = Config::builder().dev_mode(true).build();
        // dev_mode forces Memory, so ledger fields aren't required
        assert!(config.validate().is_ok());
    }

    // ── CLI Parsing ──────────────────────────────────────────────────

    #[test]
    fn cli_parse_dev_mode() {
        let cli = Cli::try_parse_from(["test", "--dev-mode"]).unwrap();
        assert!(cli.config.dev_mode);
    }

    #[test]
    fn cli_parse_storage_memory() {
        let cli = Cli::try_parse_from(["test", "--storage", "memory"]).unwrap();
        assert_eq!(cli.config.storage, StorageBackend::Memory);
    }

    #[test]
    fn cli_parse_listen_address() {
        let cli = Cli::try_parse_from(["test", "--listen", "0.0.0.0:8080"]).unwrap();
        assert_eq!(cli.config.listen, "0.0.0.0:8080".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn cli_parse_log_format_json() {
        let cli = Cli::try_parse_from(["test", "--log-format", "json"]).unwrap();
        assert_eq!(cli.config.log_format, LogFormat::Json);
    }

    #[test]
    fn cli_parse_log_format_text() {
        let cli = Cli::try_parse_from(["test", "--log-format", "text"]).unwrap();
        assert_eq!(cli.config.log_format, LogFormat::Text);
    }

    #[test]
    fn cli_rejects_invalid_storage_value() {
        let result = Cli::try_parse_from(["test", "--storage", "postgres"]);
        assert!(result.is_err());
    }

    #[test]
    fn cli_rejects_unknown_flags() {
        let result = Cli::try_parse_from(["test", "--config", "foo.yaml"]);
        assert!(result.is_err());
    }

    #[test]
    fn cli_parse_all_ledger_fields() {
        let cli = Cli::try_parse_from([
            "test",
            "--storage",
            "ledger",
            "--ledger-endpoint",
            "http://ledger:50051",
            "--ledger-client-id",
            "ctrl-01",
            "--ledger-namespace-id",
            "42",
            "--ledger-vault-id",
            "7",
        ])
        .unwrap();

        assert_eq!(cli.config.storage, StorageBackend::Ledger);
        assert_eq!(cli.config.ledger_endpoint.as_deref(), Some("http://ledger:50051"));
        assert_eq!(cli.config.ledger_client_id.as_deref(), Some("ctrl-01"));
        assert_eq!(cli.config.ledger_namespace_id, Some(42));
        assert_eq!(cli.config.ledger_vault_id, Some(7));
    }

    #[test]
    fn cli_parse_email_fields() {
        let cli = Cli::try_parse_from([
            "test",
            "--storage",
            "memory",
            "--email-host",
            "smtp.example.com",
            "--email-port",
            "465",
            "--email-username",
            "user",
            "--email-password",
            "secret",
            "--email-from-address",
            "noreply@example.com",
            "--email-from-name",
            "MyApp",
            "--email-insecure",
        ])
        .unwrap();

        assert_eq!(cli.config.email_host, "smtp.example.com");
        assert_eq!(cli.config.email_port, 465);
        assert_eq!(cli.config.email_username.as_deref(), Some("user"));
        assert_eq!(cli.config.email_password.as_deref(), Some("secret"));
        assert_eq!(cli.config.email_from_address, "noreply@example.com");
        assert_eq!(cli.config.email_from_name, "MyApp");
        assert!(cli.config.email_insecure);
    }

    #[test]
    fn cli_parse_key_file() {
        let cli = Cli::try_parse_from(["test", "--key-file", "/data/master.key"]).unwrap();
        assert_eq!(cli.config.key_file, PathBuf::from("/data/master.key"));
    }

    // ── Enum Display ─────────────────────────────────────────────────

    #[test]
    fn storage_backend_display() {
        assert_eq!(StorageBackend::Memory.to_string(), "memory");
        assert_eq!(StorageBackend::Ledger.to_string(), "ledger");
    }

    #[test]
    fn log_format_display() {
        assert_eq!(LogFormat::Auto.to_string(), "auto");
        assert_eq!(LogFormat::Json.to_string(), "json");
        assert_eq!(LogFormat::Text.to_string(), "text");
    }
}
