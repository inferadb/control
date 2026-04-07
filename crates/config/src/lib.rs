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

use std::{net::SocketAddr, num::NonZeroU8, path::PathBuf};

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
    /// Auto-detect based on stdout: JSON when non-TTY, text otherwise.
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

    /// Server configuration.
    #[command(flatten)]
    pub config: Config,
}

/// CLI subcommands. The server starts when no subcommand is given.
#[derive(Debug, clap::Subcommand)]
pub enum CliCommand {}

/// Configuration for the InferaDB Control Plane.
///
/// All fields are configurable via CLI flags or environment variables.
/// Precedence: CLI arg > env var > default value.
///
/// Sensitive fields (`pem`, `email_password`) use `hide_env_values` to prevent
/// leaking secrets in `--help` output.
#[derive(Clone, Builder, Parser)]
#[command(name = "inferadb-control")]
#[command(version)]
#[builder(on(String, into))]
pub struct Config {
    // ── Server ───────────────────────────────────────────────────────
    /// HTTP bind address. Defaults to `127.0.0.1:9090`.
    #[arg(long = "listen", env = "INFERADB__CONTROL__LISTEN", default_value = DEFAULT_LISTEN)]
    #[builder(default = default_listen())]
    pub listen: SocketAddr,

    /// Tracing-subscriber filter string (e.g., `info`, `debug`, `trace`). Defaults to `info`.
    #[arg(long = "log-level", env = "INFERADB__CONTROL__LOG_LEVEL", default_value = DEFAULT_LOG_LEVEL)]
    #[builder(default = DEFAULT_LOG_LEVEL.to_string())]
    pub log_level: String,

    /// Log output format: `auto`, `json`, or `text`. Defaults to `auto`.
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
    ///
    /// If not provided, a new keypair is generated on each startup.
    #[arg(long = "pem", env = "INFERADB__CONTROL__PEM", hide_env_values = true)]
    pub pem: Option<String>,

    /// Path to the AES-256-GCM master key file for encrypting private keys at rest.
    /// Defaults to `./data/master.key`.
    #[arg(long = "key-file", env = "INFERADB__CONTROL__KEY_FILE", default_value = DEFAULT_KEY_FILE)]
    #[builder(default = PathBuf::from(DEFAULT_KEY_FILE))]
    pub key_file: PathBuf,

    // ── Storage ──────────────────────────────────────────────────────
    /// Storage backend: `memory` or `ledger`. Defaults to `ledger`.
    #[arg(
        long = "storage",
        env = "INFERADB__CONTROL__STORAGE",
        value_enum,
        default_value = "ledger"
    )]
    #[builder(default)]
    pub storage: StorageBackend,

    /// Ledger gRPC endpoint URL. Required when `storage=ledger`.
    #[arg(long = "ledger-endpoint", env = "INFERADB__CONTROL__LEDGER_ENDPOINT")]
    pub ledger_endpoint: Option<String>,

    /// Ledger client identifier for idempotency tracking. Required when `storage=ledger`.
    #[arg(long = "ledger-client-id", env = "INFERADB__CONTROL__LEDGER_CLIENT_ID")]
    pub ledger_client_id: Option<String>,

    // ── Email Blinding ────────────────────────────────────────────────
    /// Email blinding key for HMAC-SHA256 computation (64-char hex string, 32 bytes).
    ///
    /// Must match the key configured on the Ledger cluster.
    /// Generate with: `openssl rand -hex 32`
    #[arg(
        long = "email-blinding-key",
        env = "INFERADB__CONTROL__EMAIL_BLINDING_KEY",
        hide_env_values = true
    )]
    pub email_blinding_key: Option<String>,

    // ── Email (SMTP) ─────────────────────────────────────────────────
    /// SMTP host for outgoing email. Defaults to empty string (email disabled).
    #[arg(long = "email-host", env = "INFERADB__CONTROL__EMAIL_HOST", default_value = "")]
    #[builder(default)]
    pub email_host: String,

    /// SMTP port for outgoing email. Defaults to `587` (STARTTLS).
    #[arg(long = "email-port", env = "INFERADB__CONTROL__EMAIL_PORT", default_value_t = DEFAULT_EMAIL_PORT)]
    #[builder(default = DEFAULT_EMAIL_PORT)]
    pub email_port: u16,

    /// SMTP authentication username. Required when email is enabled.
    #[arg(long = "email-username", env = "INFERADB__CONTROL__EMAIL_USERNAME")]
    pub email_username: Option<String>,

    /// SMTP authentication password. Required when email is enabled.
    #[arg(
        long = "email-password",
        env = "INFERADB__CONTROL__EMAIL_PASSWORD",
        hide_env_values = true
    )]
    pub email_password: Option<String>,

    /// Sender address for outgoing email. Defaults to `noreply@inferadb.com`.
    #[arg(long = "email-from-address", env = "INFERADB__CONTROL__EMAIL_FROM_ADDRESS", default_value = DEFAULT_EMAIL_FROM_ADDRESS)]
    #[builder(default = DEFAULT_EMAIL_FROM_ADDRESS.to_string())]
    pub email_from_address: String,

    /// Sender display name for outgoing email. Defaults to `InferaDB`.
    #[arg(long = "email-from-name", env = "INFERADB__CONTROL__EMAIL_FROM_NAME", default_value = DEFAULT_EMAIL_FROM_NAME)]
    #[builder(default = DEFAULT_EMAIL_FROM_NAME.to_string())]
    pub email_from_name: String,

    /// Skip TLS verification for SMTP connections. Defaults to `false`.
    ///
    /// Only for local development with tools like Mailpit.
    #[arg(long = "email-insecure", env = "INFERADB__CONTROL__EMAIL_INSECURE")]
    #[builder(default)]
    pub email_insecure: bool,

    // ── Frontend ─────────────────────────────────────────────────────
    /// Base URL for email links (verification, password reset). Defaults to `http://localhost:3000`.
    #[arg(long = "frontend-url", env = "INFERADB__CONTROL__FRONTEND_URL", default_value = DEFAULT_FRONTEND_URL)]
    #[builder(default = DEFAULT_FRONTEND_URL.to_string())]
    pub frontend_url: String,

    // ── WebAuthn ─────────────────────────────────────────────────────
    /// WebAuthn Relying Party ID (domain). Defaults to `localhost`.
    ///
    /// Must be an effective domain suffix of the origin. Cannot be changed after
    /// credentials are registered.
    #[arg(
        long = "webauthn-rp-id",
        env = "INFERADB__CONTROL__WEBAUTHN_RP_ID",
        default_value = "localhost"
    )]
    #[builder(default = "localhost".to_string())]
    pub webauthn_rp_id: String,

    /// WebAuthn Relying Party origin URL (e.g., `https://app.inferadb.com`).
    /// Defaults to `http://localhost:3000`.
    ///
    /// Must include scheme. The RP ID must be a suffix of this origin's domain.
    #[arg(
        long = "webauthn-origin",
        env = "INFERADB__CONTROL__WEBAUTHN_ORIGIN",
        default_value = "http://localhost:3000"
    )]
    #[builder(default = "http://localhost:3000".to_string())]
    pub webauthn_origin: String,

    // ── Proxy ─────────────────────────────────────────────────────────
    /// Number of trusted reverse proxies between the client and this server.
    ///
    /// When set, the client IP is extracted as the Nth-from-right entry in
    /// `X-Forwarded-For` (rightmost entries are added by trusted infrastructure).
    #[arg(long = "trusted-proxy-depth", env = "INFERADB__CONTROL__TRUSTED_PROXY_DEPTH")]
    pub trusted_proxy_depth: Option<NonZeroU8>,

    // ── Instance Identity ────────────────────────────────────────────
    /// Unique worker ID for Snowflake ID generation (0-1023).
    ///
    /// In multi-instance deployments, each instance MUST have a unique worker ID
    /// to guarantee ID uniqueness. Set via the Kubernetes pod ordinal or a
    /// deterministic assignment mechanism. Defaults to a random value if unset.
    #[arg(
        long = "worker-id",
        env = "INFERADB__CONTROL__WORKER_ID",
        value_parser = clap::value_parser!(u16).range(0..=1023)
    )]
    pub worker_id: Option<u16>,

    // ── Mode Flags ───────────────────────────────────────────────────
    /// Forces development mode: uses in-memory storage regardless of `--storage`. Defaults to
    /// `false`.
    ///
    /// No environment variable; this must be an explicit CLI choice.
    #[arg(long = "dev-mode")]
    #[builder(default)]
    pub dev_mode: bool,
}

/// Redacts sensitive fields (`pem`, `email_blinding_key`, `email_password`).
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("listen", &self.listen)
            .field("log_level", &self.log_level)
            .field("log_format", &self.log_format)
            .field("pem", &self.pem.as_ref().map(|_| "[REDACTED]"))
            .field("key_file", &self.key_file)
            .field("storage", &self.storage)
            .field("ledger_endpoint", &self.ledger_endpoint)
            .field("ledger_client_id", &self.ledger_client_id)
            .field("email_blinding_key", &self.email_blinding_key.as_ref().map(|_| "[REDACTED]"))
            .field("email_host", &self.email_host)
            .field("email_port", &self.email_port)
            .field("email_username", &self.email_username)
            .field("email_password", &self.email_password.as_ref().map(|_| "[REDACTED]"))
            .field("email_from_address", &self.email_from_address)
            .field("email_from_name", &self.email_from_name)
            .field("email_insecure", &self.email_insecure)
            .field("frontend_url", &self.frontend_url)
            .field("webauthn_rp_id", &self.webauthn_rp_id)
            .field("webauthn_origin", &self.webauthn_origin)
            .field("trusted_proxy_depth", &self.trusted_proxy_depth)
            .field("worker_id", &self.worker_id)
            .field("dev_mode", &self.dev_mode)
            .finish()
    }
}

fn default_listen() -> SocketAddr {
    #[allow(clippy::expect_used)]
    DEFAULT_LISTEN.parse().expect("valid default listen address")
}

impl Config {
    /// Validates cross-field business rules.
    ///
    /// Checks Ledger storage requirements and frontend URL format. Uses
    /// [`effective_storage`](Self::effective_storage) to account for dev-mode.
    ///
    /// # Errors
    ///
    /// Returns `Error::config` if required Ledger fields are missing when
    /// storage is `Ledger`, or if `frontend_url` has an invalid format.
    pub fn validate(&self) -> Result<()> {
        // Validate ledger storage requirements
        if self.effective_storage() == StorageBackend::Ledger {
            let Some(endpoint) = self.ledger_endpoint.as_ref() else {
                return Err(Error::config("--ledger-endpoint is required when storage=ledger"));
            };
            if self.ledger_client_id.is_none() {
                return Err(Error::config("--ledger-client-id is required when storage=ledger"));
            }
            if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
                return Err(Error::config(format!(
                    "--ledger-endpoint must start with http:// or https://, got: {endpoint}"
                )));
            }
        }

        // Warn about insecure email with non-localhost host
        if self.email_insecure
            && !self.email_host.is_empty()
            && self.email_host != "localhost"
            && self.email_host != "127.0.0.1"
            && self.email_host != "::1"
        {
            tracing::warn!(
                "email_insecure=true with non-localhost host '{}'; TLS verification disabled",
                self.email_host
            );
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
    fn test_builder_defaults_match_expected_values() {
        let config = Config::builder().build();

        assert_eq!(config.listen, "127.0.0.1:9090".parse::<SocketAddr>().unwrap());
        assert_eq!(config.log_level, "info");
        assert_eq!(config.log_format, LogFormat::Auto);
        assert!(config.pem.is_none());
        assert_eq!(config.key_file, PathBuf::from("./data/master.key"));
        assert_eq!(config.storage, StorageBackend::Ledger);
        assert!(config.ledger_endpoint.is_none());
        assert!(config.ledger_client_id.is_none());
        assert!(config.email_blinding_key.is_none());
        assert_eq!(config.email_host, "");
        assert_eq!(config.email_port, 587);
        assert!(config.email_username.is_none());
        assert!(config.email_password.is_none());
        assert_eq!(config.email_from_address, "noreply@inferadb.com");
        assert_eq!(config.email_from_name, "InferaDB");
        assert!(!config.email_insecure);
        assert_eq!(config.frontend_url, "http://localhost:3000");
        assert_eq!(config.webauthn_rp_id, "localhost");
        assert_eq!(config.webauthn_origin, "http://localhost:3000");
        assert!(config.trusted_proxy_depth.is_none());
        assert!(config.worker_id.is_none());
        assert!(!config.dev_mode);
    }

    // ── Enum defaults ───────────────────────────────────────────────

    #[test]
    fn test_storage_backend_default_is_ledger() {
        assert_eq!(StorageBackend::default(), StorageBackend::Ledger);
    }

    #[test]
    fn test_log_format_default_is_auto() {
        assert_eq!(LogFormat::default(), LogFormat::Auto);
    }

    // ── Validation: Ledger Storage ───────────────────────────────────

    #[test]
    fn test_validate_ledger_missing_fields_rejected() {
        struct Case {
            name: &'static str,
            config: Config,
            expected_msg: &'static str,
        }
        let cases = vec![
            Case {
                name: "missing_endpoint",
                config: Config::builder().storage(StorageBackend::Ledger).build(),
                expected_msg: "--ledger-endpoint is required",
            },
            Case {
                name: "missing_client_id",
                config: Config::builder()
                    .storage(StorageBackend::Ledger)
                    .ledger_endpoint("http://localhost:50051")
                    .build(),
                expected_msg: "--ledger-client-id is required",
            },
            Case {
                name: "invalid_endpoint_scheme",
                config: Config::builder()
                    .storage(StorageBackend::Ledger)
                    .ledger_endpoint("grpc://localhost:50051")
                    .ledger_client_id("control-test")
                    .build(),
                expected_msg: "must start with http:// or https://",
            },
        ];

        for case in cases {
            let err = case.config.validate().unwrap_err();
            assert!(
                err.to_string().contains(case.expected_msg),
                "{}: expected '{}' in '{}'",
                case.name,
                case.expected_msg,
                err
            );
        }
    }

    #[test]
    fn test_validate_ledger_complete_config_passes() {
        let config = Config::builder()
            .storage(StorageBackend::Ledger)
            .ledger_endpoint("http://localhost:50051")
            .ledger_client_id("control-test")
            .build();

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_ledger_https_endpoint_passes() {
        let config = Config::builder()
            .storage(StorageBackend::Ledger)
            .ledger_endpoint("https://ledger.prod:50051")
            .ledger_client_id("control-prod")
            .build();

        assert!(config.validate().is_ok());
    }

    // ── Validation: Frontend URL ─────────────────────────────────────

    #[test]
    fn test_validate_frontend_url_invalid_rejected() {
        struct Case {
            name: &'static str,
            url: &'static str,
            expected_msg: &'static str,
        }
        let cases = vec![
            Case {
                name: "ftp_scheme",
                url: "ftp://example.com",
                expected_msg: "must start with http:// or https://",
            },
            Case {
                name: "no_scheme",
                url: "example.com",
                expected_msg: "must start with http:// or https://",
            },
            Case {
                name: "trailing_slash",
                url: "https://example.com/",
                expected_msg: "must not end with a trailing slash",
            },
        ];

        for case in cases {
            let config =
                Config::builder().storage(StorageBackend::Memory).frontend_url(case.url).build();

            let err = config.validate().unwrap_err();
            assert!(
                err.to_string().contains(case.expected_msg),
                "{}: expected '{}' in '{}'",
                case.name,
                case.expected_msg,
                err
            );
        }
    }

    #[test]
    fn test_validate_frontend_url_valid_passes() {
        let cases =
            vec![("https", "https://app.inferadb.com"), ("http", "http://staging.inferadb.com")];

        for (name, url) in cases {
            let config =
                Config::builder().storage(StorageBackend::Memory).frontend_url(url).build();
            assert!(config.validate().is_ok(), "{name}: expected Ok for {url}");
        }
    }

    // ── Validation: Memory Storage ───────────────────────────────────

    #[test]
    fn test_validate_memory_minimal_config_passes() {
        let config = Config::builder().storage(StorageBackend::Memory).build();

        assert!(config.validate().is_ok());
    }

    // ── Helper Methods ───────────────────────────────────────────────

    #[test]
    fn test_is_email_enabled_empty_host_returns_false() {
        let config = Config::builder().storage(StorageBackend::Memory).build();

        assert!(!config.is_email_enabled());
    }

    #[test]
    fn test_is_email_enabled_nonempty_host_returns_true() {
        let config = Config::builder()
            .storage(StorageBackend::Memory)
            .email_host("smtp.example.com")
            .build();

        assert!(config.is_email_enabled());
    }

    #[test]
    fn test_effective_storage_dev_mode_returns_memory() {
        let config = Config::builder().storage(StorageBackend::Ledger).dev_mode(true).build();

        assert_eq!(config.effective_storage(), StorageBackend::Memory);
    }

    #[test]
    fn test_effective_storage_no_dev_mode_returns_configured() {
        let cases = vec![
            ("ledger", StorageBackend::Ledger, StorageBackend::Ledger),
            ("memory", StorageBackend::Memory, StorageBackend::Memory),
        ];

        for (name, input, expected) in cases {
            let config = Config::builder().storage(input).build();
            assert_eq!(config.effective_storage(), expected, "mismatch for {name}");
        }
    }

    #[test]
    fn test_is_dev_mode_returns_field_value() {
        let config_off = Config::builder().build();
        let config_on = Config::builder().dev_mode(true).build();

        assert!(!config_off.is_dev_mode());
        assert!(config_on.is_dev_mode());
    }

    #[test]
    fn test_validate_dev_mode_skips_ledger_validation() {
        let config = Config::builder().dev_mode(true).build();

        assert!(config.validate().is_ok());
    }

    // ── CLI Parsing ──────────────────────────────────────────────────

    #[test]
    fn test_cli_parse_dev_mode_flag() {
        let cli = Cli::try_parse_from(["test", "--dev-mode"]).unwrap();

        assert!(cli.config.dev_mode);
    }

    #[test]
    fn test_cli_parse_storage_memory() {
        let cli = Cli::try_parse_from(["test", "--storage", "memory"]).unwrap();

        assert_eq!(cli.config.storage, StorageBackend::Memory);
    }

    #[test]
    fn test_cli_parse_listen_address() {
        let cli = Cli::try_parse_from(["test", "--listen", "0.0.0.0:8080"]).unwrap();

        assert_eq!(cli.config.listen, "0.0.0.0:8080".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn test_cli_parse_log_format_values() {
        let cases =
            vec![("json", LogFormat::Json), ("text", LogFormat::Text), ("auto", LogFormat::Auto)];

        for (input, expected) in cases {
            let cli = Cli::try_parse_from(["test", "--log-format", input]).unwrap();
            assert_eq!(cli.config.log_format, expected, "mismatch for --log-format {input}");
        }
    }

    #[test]
    fn test_cli_rejects_invalid_storage_value() {
        let result = Cli::try_parse_from(["test", "--storage", "postgres"]);

        assert!(result.is_err());
    }

    #[test]
    fn test_cli_rejects_unknown_flags() {
        let result = Cli::try_parse_from(["test", "--config", "foo.yaml"]);

        assert!(result.is_err());
    }

    #[test]
    fn test_cli_parse_all_ledger_fields() {
        let cli = Cli::try_parse_from([
            "test",
            "--storage",
            "ledger",
            "--ledger-endpoint",
            "http://ledger:50051",
            "--ledger-client-id",
            "ctrl-01",
        ])
        .unwrap();

        assert_eq!(cli.config.storage, StorageBackend::Ledger);
        assert_eq!(cli.config.ledger_endpoint.as_deref(), Some("http://ledger:50051"));
        assert_eq!(cli.config.ledger_client_id.as_deref(), Some("ctrl-01"));
    }

    #[test]
    fn test_cli_parse_email_fields() {
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
    fn test_cli_parse_key_file() {
        let cli = Cli::try_parse_from(["test", "--key-file", "/data/master.key"]).unwrap();

        assert_eq!(cli.config.key_file, PathBuf::from("/data/master.key"));
    }

    #[test]
    fn test_cli_parse_webauthn_fields() {
        let cli = Cli::try_parse_from([
            "test",
            "--storage",
            "memory",
            "--webauthn-rp-id",
            "example.com",
            "--webauthn-origin",
            "https://example.com",
        ])
        .unwrap();

        assert_eq!(cli.config.webauthn_rp_id, "example.com");
        assert_eq!(cli.config.webauthn_origin, "https://example.com");
    }

    #[test]
    fn test_cli_parse_worker_id() {
        let cli = Cli::try_parse_from(["test", "--worker-id", "512"]).unwrap();

        assert_eq!(cli.config.worker_id, Some(512));
    }

    #[test]
    fn test_cli_rejects_worker_id_above_1023() {
        let result = Cli::try_parse_from(["test", "--worker-id", "1024"]);

        assert!(result.is_err());
    }

    #[test]
    fn test_cli_parse_trusted_proxy_depth() {
        let cli = Cli::try_parse_from(["test", "--trusted-proxy-depth", "2"]).unwrap();

        assert_eq!(cli.config.trusted_proxy_depth.map(|v| v.get()), Some(2));
    }

    // ── Validation: Email Insecure ────────────────────────────────────

    #[test]
    fn test_validate_email_insecure_non_localhost_passes() {
        let config = Config::builder()
            .storage(StorageBackend::Memory)
            .email_host("smtp.example.com")
            .email_insecure(true)
            .build();

        assert!(config.validate().is_ok());
    }

    // ── Debug redaction ──────────────────────────────────────────────

    #[test]
    fn test_debug_redacts_sensitive_fields() {
        let config = Config::builder()
            .storage(StorageBackend::Memory)
            .pem("SECRET_PEM_DATA")
            .email_blinding_key("deadbeef".repeat(4))
            .email_password("hunter2")
            .build();

        let debug = format!("{config:?}");

        assert!(debug.contains("[REDACTED]"), "should redact sensitive fields");
        assert!(!debug.contains("SECRET_PEM_DATA"), "pem should be redacted");
        assert!(!debug.contains("hunter2"), "email_password should be redacted");
        assert!(!debug.contains(&"deadbeef".repeat(4)), "email_blinding_key should be redacted");
    }

    // ── Enum Display ─────────────────────────────────────────────────

    #[test]
    fn test_storage_backend_display() {
        assert_eq!(StorageBackend::Memory.to_string(), "memory");
        assert_eq!(StorageBackend::Ledger.to_string(), "ledger");
    }

    #[test]
    fn test_log_format_display() {
        assert_eq!(LogFormat::Auto.to_string(), "auto");
        assert_eq!(LogFormat::Json.to_string(), "json");
        assert_eq!(LogFormat::Text.to_string(), "text");
    }
}
