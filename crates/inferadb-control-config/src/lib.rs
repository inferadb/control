//! # InferaDB Control Configuration
//!
//! Handles configuration loading from files, environment variables, and CLI args.
//!
//! ## Unified Configuration Format
//!
//! This crate supports a unified configuration format that allows both engine and control
//! services to share the same configuration file:
//!
//! ```yaml
//! engine:
//!   threads: 4
//!   logging: "info"
//!   listen:
//!     http: "127.0.0.1:8080"
//!   # ... other engine config (ignored by control)
//!
//! control:
//!   threads: 4
//!   logging: "info"
//!   listen:
//!     http: "127.0.0.1:9090"
//!   # ... control config
//! ```
//!
//! The control service reads its configuration from the `control:` section. Any `engine:` section
//! is ignored by control (and vice versa when engine reads the same file).

#![deny(unsafe_code)]

pub mod refresh;

use std::path::Path;

use inferadb_control_types::error::{Error, Result};
pub use refresh::ConfigRefresher;
use serde::{Deserialize, Serialize};

/// Root configuration wrapper for unified config file support.
///
/// This allows both engine and control to read from the same YAML file,
/// with each service reading its own section:
///
/// ```yaml
/// engine:
///   listen:
///     http: "127.0.0.1:8080"
///   # ... other engine config (ignored by control)
///
/// control:
///   listen:
///     http: "127.0.0.1:9090"
///   # ... control config
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RootConfig {
    /// Control-specific configuration
    #[serde(default)]
    pub control: ControlConfig,
    // Note: `engine` section may exist in the file but is ignored by control
}

/// Configuration for the Control API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlConfig {
    /// Number of worker threads for the async runtime
    #[serde(default = "default_threads")]
    pub threads: usize,

    /// Log level (trace, debug, info, warn, error)
    #[serde(default = "default_logging")]
    pub logging: String,

    /// Ed25519 private key in PEM format (optional - will auto-generate if not provided for
    /// control API. If provided, the key is persisted across restarts.
    /// If not provided, a new keypair is generated on each startup.
    pub pem: Option<String>,

    /// Path to the master key file for encrypting private keys at rest.
    ///
    /// The key file contains 32 bytes of cryptographically secure random data
    /// used as the AES-256-GCM encryption key for client certificate private keys.
    ///
    /// Behavior:
    /// - If set and file exists: load the key from file
    /// - If set but file missing: generate a new key and save to file
    /// - If not set: generate a new key in the default location (./data/master.key)
    ///
    /// SECURITY:
    /// - The key file is created with restrictive permissions (0600)
    /// - Back up this file securely - losing it means losing access to encrypted keys
    /// - In production, mount from a Kubernetes secret or secrets manager
    #[serde(default = "default_key_file")]
    pub key_file: Option<String>,

    #[serde(default = "default_storage")]
    pub storage: String,
    /// Ledger backend configuration (required when storage = "ledger")
    #[serde(default)]
    pub ledger: LedgerConfig,
    #[serde(default)]
    pub listen: ListenConfig,
    #[serde(default)]
    pub webauthn: WebAuthnConfig,
    #[serde(default)]
    pub email: EmailConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub webhook: WebhookConfig,
    #[serde(default)]
    pub frontend: FrontendConfig,
}

/// Listen address configuration for API servers
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ListenConfig {
    /// Client-facing HTTP/REST API server address
    /// Format: "host:port" (e.g., "127.0.0.1:9090")
    #[serde(default = "default_http")]
    pub http: String,

    /// Client-facing gRPC API server address
    /// Format: "host:port" (e.g., "127.0.0.1:9091")
    #[serde(default = "default_grpc")]
    pub grpc: String,
}

/// WebAuthn configuration for passkey authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnConfig {
    /// Relying Party ID (domain)
    /// e.g., "inferadb.com" for production or "localhost" for development
    #[serde(default = "default_webauthn_party")]
    pub party: String,

    /// Origin URL for WebAuthn
    /// e.g., "https://app.inferadb.com" or "http://localhost:3000"
    #[serde(default = "default_webauthn_origin")]
    pub origin: String,
}

impl Default for WebAuthnConfig {
    fn default() -> Self {
        Self { party: default_webauthn_party(), origin: default_webauthn_origin() }
    }
}

fn default_webauthn_party() -> String {
    "localhost".to_string()
}

fn default_webauthn_origin() -> String {
    "http://localhost:3000".to_string()
}

/// Email configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EmailConfig {
    /// SMTP host
    pub host: String,

    /// SMTP port
    #[serde(default = "default_email_port")]
    pub port: u16,

    /// SMTP username
    pub username: Option<String>,

    /// SMTP password (should be set via environment variable)
    pub password: Option<String>,

    /// From email address
    pub address: String,

    /// From display name
    #[serde(default = "default_email_name")]
    pub name: String,

    /// Allow insecure (unencrypted) SMTP connections.
    ///
    /// **WARNING**: Only enable this for local development/testing with tools like Mailpit.
    /// Never enable in production as it transmits credentials in plain text.
    #[serde(default)]
    pub insecure: bool,
}

/// Rate limits configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LimitsConfig {
    /// Login attempts per IP per hour
    #[serde(default = "default_login_attempts_per_ip_per_hour")]
    pub login_attempts_per_ip_per_hour: u32,

    /// Registrations per IP per day
    #[serde(default = "default_registrations_per_ip_per_day")]
    pub registrations_per_ip_per_day: u32,

    /// Email verification tokens per email per hour
    #[serde(default = "default_email_verification_tokens_per_hour")]
    pub email_verification_tokens_per_hour: u32,

    /// Password reset tokens per user per hour
    #[serde(default = "default_password_reset_tokens_per_hour")]
    pub password_reset_tokens_per_hour: u32,
}

/// Frontend configuration for web UI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrontendConfig {
    /// Base URL for email links (verification, password reset)
    /// Example: "https://app.inferadb.com" or "http://localhost:3000"
    #[serde(default = "default_frontend_url")]
    pub url: String,
}

impl Default for FrontendConfig {
    fn default() -> Self {
        Self { url: default_frontend_url() }
    }
}

/// Webhook configuration for cache invalidation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Webhook request timeout in milliseconds
    #[serde(default = "default_webhook_timeout")]
    pub timeout: u64,

    /// Number of retry attempts on webhook failure
    #[serde(default = "default_webhook_retries")]
    pub retries: u8,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self { timeout: default_webhook_timeout(), retries: default_webhook_retries() }
    }
}

/// Ledger storage backend configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LedgerConfig {
    /// Ledger server endpoint URL
    /// e.g., "http://localhost:50051" or "https://ledger.inferadb.com:50051"
    pub endpoint: Option<String>,

    /// Client ID for idempotency tracking
    /// Should be unique per control instance to ensure correct duplicate detection
    /// e.g., "control-prod-us-west-1a-001"
    pub client_id: Option<String>,

    /// Namespace ID for data scoping
    /// All keys will be stored within this namespace
    pub namespace_id: Option<i64>,

    /// Optional vault ID for finer-grained key scoping
    /// If set, keys are scoped to this specific vault within the namespace
    pub vault_id: Option<i64>,
}

// Default value functions
fn default_http() -> String {
    "127.0.0.1:9090".to_string()
}

fn default_grpc() -> String {
    "127.0.0.1:9091".to_string()
}

fn default_threads() -> usize {
    num_cpus::get()
}

fn default_logging() -> String {
    "info".to_string()
}

fn default_storage() -> String {
    "ledger".to_string()
}

fn default_email_port() -> u16 {
    587
}

fn default_email_name() -> String {
    "InferaDB".to_string()
}

fn default_login_attempts_per_ip_per_hour() -> u32 {
    100
}

fn default_registrations_per_ip_per_day() -> u32 {
    5
}

fn default_email_verification_tokens_per_hour() -> u32 {
    5
}

fn default_password_reset_tokens_per_hour() -> u32 {
    3
}

fn default_frontend_url() -> String {
    "http://localhost:3000".to_string()
}

fn default_webhook_timeout() -> u64 {
    5000 // 5 seconds (in milliseconds)
}

fn default_webhook_retries() -> u8 {
    0 // Fire-and-forget
}

fn default_key_file() -> Option<String> {
    Some("./data/master.key".to_string())
}

impl Default for ControlConfig {
    fn default() -> Self {
        Self {
            threads: default_threads(),
            logging: default_logging(),
            storage: default_storage(),
            ledger: LedgerConfig::default(),
            listen: ListenConfig { http: default_http(), grpc: default_grpc() },
            webauthn: WebAuthnConfig::default(),
            key_file: default_key_file(),
            email: EmailConfig {
                host: "localhost".to_string(),
                port: default_email_port(),
                username: None,
                password: None,
                address: "noreply@inferadb.com".to_string(),
                name: default_email_name(),
                insecure: false,
            },
            limits: LimitsConfig {
                login_attempts_per_ip_per_hour: default_login_attempts_per_ip_per_hour(),
                registrations_per_ip_per_day: default_registrations_per_ip_per_day(),
                email_verification_tokens_per_hour: default_email_verification_tokens_per_hour(),
                password_reset_tokens_per_hour: default_password_reset_tokens_per_hour(),
            },
            pem: None,
            webhook: WebhookConfig::default(),
            frontend: FrontendConfig::default(),
        }
    }
}

impl ControlConfig {
    /// Load configuration with layered precedence: defaults → file → env vars
    ///
    /// This function implements a proper configuration hierarchy:
    /// 1. Start with hardcoded defaults (via `#[serde(default)]` annotations)
    /// 2. Override with values from config file (if file exists and properties are set)
    /// 3. Override with environment variables (if env vars are set)
    ///
    /// Each layer only overrides properties that are explicitly set, preserving
    /// defaults for unspecified values.
    ///
    /// ## Unified Configuration Format
    ///
    /// This function supports the unified configuration format that allows both
    /// engine and control to share the same config file:
    ///
    /// ```yaml
    /// control:
    ///   threads: 4
    ///   logging: "info"
    ///   network:
    ///     public_rest: "127.0.0.1:9090"
    ///   # ... control config
    ///
    /// engine:
    ///   # ... engine config (ignored by control)
    /// ```
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        // The config crate will use serde's #[serde(default)] annotations for defaults
        // Layer 1 (defaults) is handled by serde deserialization
        // Layer 2: Add file source (optional - only overrides if file exists)
        let builder =
            config::Config::builder().add_source(config::File::from(path.as_ref()).required(false));

        // Layer 3: Add environment variables (highest precedence)
        // Use INFERADB__ prefix for the nested format (INFERADB__CONTROL__...)
        let builder = builder.add_source(
            config::Environment::with_prefix("INFERADB").separator("__").try_parsing(true),
        );

        let config =
            builder.build().map_err(|e| Error::Config(format!("Failed to build config: {e}")))?;

        // Deserialize as RootConfig and extract the control section
        let root: RootConfig = config
            .try_deserialize()
            .map_err(|e| Error::Config(format!("Failed to deserialize config: {e}")))?;

        Ok(root.control)
    }

    /// Load configuration with defaults, never panicking
    ///
    /// Convenience wrapper around `load()` that logs warnings but never fails.
    /// Always returns a valid configuration, falling back to defaults if needed.
    pub fn load_or_default<P: AsRef<Path>>(path: P) -> Self {
        match Self::load(path.as_ref()) {
            Ok(config) => {
                tracing::info!("Configuration loaded successfully from {:?}", path.as_ref());
                config
            },
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Failed to load config from {:?}. Using defaults with environment overrides.",
                    path.as_ref()
                );

                // Even if file loading fails, apply env vars to defaults
                Self::default()
            },
        }
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        // Validate listen addresses are parseable
        self.listen.http.parse::<std::net::SocketAddr>().map_err(|e| {
            Error::Config(format!("listen.http '{}' is not valid: {}", self.listen.http, e))
        })?;
        self.listen.grpc.parse::<std::net::SocketAddr>().map_err(|e| {
            Error::Config(format!("listen.grpc '{}' is not valid: {}", self.listen.grpc, e))
        })?;

        // Validate storage backend
        match self.storage.as_str() {
            "memory" => {},
            "ledger" => {
                // Validate required ledger fields
                if self.ledger.endpoint.is_none() {
                    return Err(Error::Config(
                        "ledger.endpoint is required when using Ledger backend".to_string(),
                    ));
                }
                if self.ledger.client_id.is_none() {
                    return Err(Error::Config(
                        "ledger.client_id is required when using Ledger backend".to_string(),
                    ));
                }
                if self.ledger.namespace_id.is_none() {
                    return Err(Error::Config(
                        "ledger.namespace_id is required when using Ledger backend".to_string(),
                    ));
                }
                // Validate endpoint format
                let endpoint = self.ledger.endpoint.as_ref().unwrap();
                if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
                    return Err(Error::Config(format!(
                        "ledger.endpoint must start with http:// or https://, got: {endpoint}"
                    )));
                }
            },
            _ => {
                return Err(Error::Config(format!(
                    "Invalid storage backend: '{}'. Supported: 'memory', 'ledger'",
                    self.storage
                )));
            },
        }

        // Note: key_file validation is handled at runtime when loading the key
        // The MasterKey::load_or_generate() function will create the key file if needed

        // Validate frontend.url format
        if !self.frontend.url.starts_with("http://") && !self.frontend.url.starts_with("https://") {
            return Err(Error::Config(
                "frontend.url must start with http:// or https://".to_string(),
            ));
        }

        if self.frontend.url.ends_with('/') {
            return Err(Error::Config("frontend.url must not end with trailing slash".to_string()));
        }

        // Warn about localhost in production-like environments
        if self.frontend.url.contains("localhost") || self.frontend.url.contains("127.0.0.1") {
            tracing::warn!(
                "frontend.url contains localhost - this should only be used in development. \
                 Production deployments should use a public domain."
            );
        }

        // Validate webhook.timeout is reasonable
        if self.webhook.timeout == 0 {
            return Err(Error::Config("webhook.timeout must be greater than 0".to_string()));
        }
        if self.webhook.timeout > 60000 {
            tracing::warn!(
                timeout = self.webhook.timeout,
                "webhook.timeout is very high (>60s). Consider using a lower timeout."
            );
        }

        // Validate WebAuthn configuration
        if self.webauthn.party.is_empty() {
            return Err(Error::Config("webauthn.party cannot be empty".to_string()));
        }
        if self.webauthn.origin.is_empty() {
            return Err(Error::Config("webauthn.origin cannot be empty".to_string()));
        }
        if !self.webauthn.origin.starts_with("http://")
            && !self.webauthn.origin.starts_with("https://")
        {
            return Err(Error::Config(
                "webauthn.origin must start with http:// or https://".to_string(),
            ));
        }

        Ok(())
    }

    /// Apply environment-aware defaults for storage backend.
    ///
    /// In development environment, if Ledger is the default but no Ledger configuration
    /// is provided, automatically fall back to memory storage for convenience.
    /// This allows `cargo run` to "just work" without requiring Ledger setup.
    ///
    /// In production or when Ledger configuration is explicitly provided,
    /// no changes are made and validation will enforce proper configuration.
    ///
    /// # Arguments
    ///
    /// * `environment` - The environment name (e.g., "development", "staging", "production")
    pub fn apply_environment_defaults(&mut self, environment: &str) {
        // Only apply in development environment
        if environment != "development" {
            return;
        }

        // If storage is ledger (the default) and no ledger config is provided,
        // fall back to memory for developer convenience
        if self.storage == "ledger"
            && self.ledger.endpoint.is_none()
            && self.ledger.client_id.is_none()
            && self.ledger.namespace_id.is_none()
        {
            tracing::info!(
                "Development mode: No Ledger configuration provided, using memory storage. \
                 Set storage='memory' explicitly or provide ledger config to suppress this message."
            );
            self.storage = "memory".to_string();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        assert_eq!(default_http(), "127.0.0.1:9090");
        assert_eq!(default_grpc(), "127.0.0.1:9091");
        assert_eq!(default_storage(), "ledger"); // Ledger is now the default
        assert_eq!(default_webauthn_party(), "localhost");
        assert_eq!(default_webauthn_origin(), "http://localhost:3000");
    }

    #[test]
    fn test_storage_validation() {
        let mut config = ControlConfig::default();
        config.webauthn.party = "localhost".to_string();
        config.webauthn.origin = "http://localhost:3000".to_string();
        config.storage = "invalid".to_string();

        // Invalid storage
        assert!(config.validate().is_err());

        // Valid storage backends
        config.storage = "memory".to_string();
        assert!(config.validate().is_ok());

        // Ledger requires configuration
        config.storage = "ledger".to_string();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("ledger.endpoint is required"));

        // Ledger with valid config
        config.ledger.endpoint = Some("http://localhost:50051".to_string());
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("ledger.client_id is required"));

        config.ledger.client_id = Some("control-test".to_string());
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("ledger.namespace_id is required"));

        config.ledger.namespace_id = Some(1);
        assert!(config.validate().is_ok());
    }
}
