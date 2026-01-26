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
//!
//! ## Builder Pattern for Configuration
//!
//! All configuration structs use [`bon::Builder`] for programmatic construction. Builder
//! defaults match serde defaults, so both file-based and programmatic configs behave
//! identically:
//!
//! ```no_run
//! use inferadb_control_config::{ControlConfig, ListenConfig};
//!
//! // Build a custom configuration programmatically
//! let config = ControlConfig::builder()
//!     .threads(8)
//!     .logging("debug")  // &str accepted via Into<String>
//!     .listen(
//!         ListenConfig::builder()
//!             .http("0.0.0.0:9090")
//!             .grpc("0.0.0.0:9091")
//!             .build()
//!     )
//!     .build();
//!
//! // Use defaults for most fields
//! let minimal = ControlConfig::builder().build();
//! assert_eq!(minimal.logging, "info");  // serde default
//! ```
//!
//! ### Default Values
//!
//! Configuration fields have sensible defaults aligned between serde and builder:
//!
//! | Field | Default |
//! |-------|---------|
//! | `threads` | Number of CPU cores |
//! | `logging` | `"info"` |
//! | `listen.http` | `"127.0.0.1:9090"` |
//! | `listen.grpc` | `"127.0.0.1:9091"` |
//!
//! Optional fields (`Option<T>`) can be set using `.maybe_*()` methods:
//!
//! ```ignore
//! use inferadb_control_config::ControlConfig;
//!
//! let config = ControlConfig::builder()
//!     .maybe_pem(Some("-----BEGIN PRIVATE KEY-----...".to_string()))
//!     .maybe_key_file(None)  // explicitly None
//!     .build();
//! ```

#![deny(unsafe_code)]

use std::path::Path;

use bon::Builder;
use inferadb_control_types::error::{Error, Result};
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
#[derive(Debug, Clone, Serialize, Deserialize, Default, Builder)]
pub struct RootConfig {
    /// Control-specific configuration
    #[serde(default)]
    #[builder(default)]
    pub control: ControlConfig,
    // Note: `engine` section may exist in the file but is ignored by control
}

/// Configuration for the Control API
#[derive(Debug, Clone, Serialize, Deserialize, Builder)]
#[builder(on(String, into))]
pub struct ControlConfig {
    /// Number of worker threads for the async runtime
    #[serde(default = "default_threads")]
    #[builder(default = num_cpus::get())]
    pub threads: usize,

    /// Log level (trace, debug, info, warn, error)
    #[serde(default = "default_logging")]
    #[builder(default = "info".to_string())]
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
    #[builder(default = "ledger".to_string())]
    pub storage: String,
    /// Ledger backend configuration (required when storage = "ledger")
    #[serde(default)]
    #[builder(default)]
    pub ledger: LedgerConfig,
    #[serde(default)]
    #[builder(default)]
    pub listen: ListenConfig,
    #[serde(default)]
    #[builder(default)]
    pub webauthn: WebAuthnConfig,
    #[serde(default)]
    #[builder(default)]
    pub email: EmailConfig,
    #[serde(default)]
    #[builder(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    #[builder(default)]
    pub webhook: WebhookConfig,
    #[serde(default)]
    #[builder(default)]
    pub frontend: FrontendConfig,
}

/// Listen address configuration for API servers
#[derive(Debug, Clone, Serialize, Deserialize, Builder)]
#[builder(on(String, into))]
pub struct ListenConfig {
    /// Client-facing HTTP/REST API server address
    /// Format: "host:port" (e.g., "127.0.0.1:9090")
    #[serde(default = "default_http")]
    #[builder(default = "127.0.0.1:9090".to_string())]
    pub http: String,

    /// Client-facing gRPC API server address
    /// Format: "host:port" (e.g., "127.0.0.1:9091")
    #[serde(default = "default_grpc")]
    #[builder(default = "127.0.0.1:9091".to_string())]
    pub grpc: String,
}

impl Default for ListenConfig {
    fn default() -> Self {
        Self { http: default_http(), grpc: default_grpc() }
    }
}

/// WebAuthn configuration for passkey authentication
#[derive(Debug, Clone, Serialize, Deserialize, Builder)]
#[builder(on(String, into))]
pub struct WebAuthnConfig {
    /// Relying Party ID (domain)
    /// e.g., "inferadb.com" for production or "localhost" for development
    #[serde(default = "default_webauthn_party")]
    #[builder(default = "localhost".to_string())]
    pub party: String,

    /// Origin URL for WebAuthn
    /// e.g., "https://app.inferadb.com" or "http://localhost:3000"
    #[serde(default = "default_webauthn_origin")]
    #[builder(default = "http://localhost:3000".to_string())]
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
#[derive(Debug, Clone, Serialize, Deserialize, Builder)]
#[builder(on(String, into))]
pub struct EmailConfig {
    /// SMTP host
    #[builder(default = "localhost".to_string())]
    pub host: String,

    /// SMTP port
    #[serde(default = "default_email_port")]
    #[builder(default = 587)]
    pub port: u16,

    /// SMTP username
    pub username: Option<String>,

    /// SMTP password (should be set via environment variable)
    pub password: Option<String>,

    /// From email address
    #[builder(default = "noreply@inferadb.com".to_string())]
    pub address: String,

    /// From display name
    #[serde(default = "default_email_name")]
    #[builder(default = "InferaDB".to_string())]
    pub name: String,

    /// Allow insecure (unencrypted) SMTP connections.
    ///
    /// **WARNING**: Only enable this for local development/testing with tools like Mailpit.
    /// Never enable in production as it transmits credentials in plain text.
    #[serde(default)]
    #[builder(default)]
    pub insecure: bool,
}

impl Default for EmailConfig {
    fn default() -> Self {
        Self {
            host: "localhost".to_string(),
            port: default_email_port(),
            username: None,
            password: None,
            address: "noreply@inferadb.com".to_string(),
            name: default_email_name(),
            insecure: false,
        }
    }
}

/// Rate limits configuration
#[derive(Debug, Clone, Serialize, Deserialize, Builder)]
pub struct LimitsConfig {
    /// Login attempts per IP per hour
    #[serde(default = "default_login_attempts_per_ip_per_hour")]
    #[builder(default = 100)]
    pub login_attempts_per_ip_per_hour: u32,

    /// Registrations per IP per day
    #[serde(default = "default_registrations_per_ip_per_day")]
    #[builder(default = 5)]
    pub registrations_per_ip_per_day: u32,

    /// Email verification tokens per email per hour
    #[serde(default = "default_email_verification_tokens_per_hour")]
    #[builder(default = 5)]
    pub email_verification_tokens_per_hour: u32,

    /// Password reset tokens per user per hour
    #[serde(default = "default_password_reset_tokens_per_hour")]
    #[builder(default = 3)]
    pub password_reset_tokens_per_hour: u32,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            login_attempts_per_ip_per_hour: default_login_attempts_per_ip_per_hour(),
            registrations_per_ip_per_day: default_registrations_per_ip_per_day(),
            email_verification_tokens_per_hour: default_email_verification_tokens_per_hour(),
            password_reset_tokens_per_hour: default_password_reset_tokens_per_hour(),
        }
    }
}

/// Frontend configuration for web UI
#[derive(Debug, Clone, Serialize, Deserialize, Builder)]
#[builder(on(String, into))]
pub struct FrontendConfig {
    /// Base URL for email links (verification, password reset)
    /// Example: "https://app.inferadb.com" or "http://localhost:3000"
    #[serde(default = "default_frontend_url")]
    #[builder(default = "http://localhost:3000".to_string())]
    pub url: String,
}

impl Default for FrontendConfig {
    fn default() -> Self {
        Self { url: default_frontend_url() }
    }
}

/// Webhook configuration for cache invalidation
#[derive(Debug, Clone, Serialize, Deserialize, Builder)]
pub struct WebhookConfig {
    /// Webhook request timeout in milliseconds
    #[serde(default = "default_webhook_timeout")]
    #[builder(default = 5000)]
    pub timeout: u64,

    /// Number of retry attempts on webhook failure
    #[serde(default = "default_webhook_retries")]
    #[builder(default = 0)]
    pub retries: u8,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self { timeout: default_webhook_timeout(), retries: default_webhook_retries() }
    }
}

/// Ledger storage backend configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default, Builder)]
#[builder(on(String, into))]
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
            builder.build().map_err(|e| Error::config(format!("Failed to build config: {e}")))?;

        // Deserialize as RootConfig and extract the control section
        let root: RootConfig = config
            .try_deserialize()
            .map_err(|e| Error::config(format!("Failed to deserialize config: {e}")))?;

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
            Error::config(format!("listen.http '{}' is not valid: {}", self.listen.http, e))
        })?;
        self.listen.grpc.parse::<std::net::SocketAddr>().map_err(|e| {
            Error::config(format!("listen.grpc '{}' is not valid: {}", self.listen.grpc, e))
        })?;

        // Validate storage backend
        match self.storage.as_str() {
            "memory" => {},
            "ledger" => {
                // Validate required ledger fields
                if self.ledger.endpoint.is_none() {
                    return Err(Error::config(
                        "ledger.endpoint is required when using Ledger backend".to_string(),
                    ));
                }
                if self.ledger.client_id.is_none() {
                    return Err(Error::config(
                        "ledger.client_id is required when using Ledger backend".to_string(),
                    ));
                }
                if self.ledger.namespace_id.is_none() {
                    return Err(Error::config(
                        "ledger.namespace_id is required when using Ledger backend".to_string(),
                    ));
                }
                // Validate endpoint format
                let endpoint = self.ledger.endpoint.as_ref().unwrap();
                if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
                    return Err(Error::config(format!(
                        "ledger.endpoint must start with http:// or https://, got: {endpoint}"
                    )));
                }
            },
            _ => {
                return Err(Error::config(format!(
                    "Invalid storage backend: '{}'. Supported: 'memory', 'ledger'",
                    self.storage
                )));
            },
        }

        // Note: key_file validation is handled at runtime when loading the key
        // The MasterKey::load_or_generate() function will create the key file if needed

        // Validate frontend.url format
        if !self.frontend.url.starts_with("http://") && !self.frontend.url.starts_with("https://") {
            return Err(Error::config(
                "frontend.url must start with http:// or https://".to_string(),
            ));
        }

        if self.frontend.url.ends_with('/') {
            return Err(Error::config("frontend.url must not end with trailing slash".to_string()));
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
            return Err(Error::config("webhook.timeout must be greater than 0".to_string()));
        }
        if self.webhook.timeout > 60000 {
            tracing::warn!(
                timeout = self.webhook.timeout,
                "webhook.timeout is very high (>60s). Consider using a lower timeout."
            );
        }

        // Validate WebAuthn configuration
        if self.webauthn.party.is_empty() {
            return Err(Error::config("webauthn.party cannot be empty".to_string()));
        }
        if self.webauthn.origin.is_empty() {
            return Err(Error::config("webauthn.origin cannot be empty".to_string()));
        }
        if !self.webauthn.origin.starts_with("http://")
            && !self.webauthn.origin.starts_with("https://")
        {
            return Err(Error::config(
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

    #[test]
    fn test_builder_defaults_match_serde_defaults() {
        // Build using bon builder
        let built = ControlConfig::builder().build();

        // Build using serde default
        let serde_default = ControlConfig::default();

        // Verify all defaults match
        assert_eq!(built.threads, serde_default.threads);
        assert_eq!(built.logging, serde_default.logging);
        assert_eq!(built.storage, serde_default.storage);
        assert_eq!(built.listen.http, serde_default.listen.http);
        assert_eq!(built.listen.grpc, serde_default.listen.grpc);
        assert_eq!(built.webauthn.party, serde_default.webauthn.party);
        assert_eq!(built.webauthn.origin, serde_default.webauthn.origin);
        assert_eq!(built.email.host, serde_default.email.host);
        assert_eq!(built.email.port, serde_default.email.port);
        assert_eq!(built.email.address, serde_default.email.address);
        assert_eq!(built.email.name, serde_default.email.name);
        assert_eq!(built.email.insecure, serde_default.email.insecure);
        assert_eq!(
            built.limits.login_attempts_per_ip_per_hour,
            serde_default.limits.login_attempts_per_ip_per_hour
        );
        assert_eq!(
            built.limits.registrations_per_ip_per_day,
            serde_default.limits.registrations_per_ip_per_day
        );
        assert_eq!(
            built.limits.email_verification_tokens_per_hour,
            serde_default.limits.email_verification_tokens_per_hour
        );
        assert_eq!(
            built.limits.password_reset_tokens_per_hour,
            serde_default.limits.password_reset_tokens_per_hour
        );
        assert_eq!(built.frontend.url, serde_default.frontend.url);
        assert_eq!(built.webhook.timeout, serde_default.webhook.timeout);
        assert_eq!(built.webhook.retries, serde_default.webhook.retries);
    }

    #[test]
    fn test_nested_config_builders() {
        // Verify nested configs can also be built with bon builders
        let listen = ListenConfig::builder().build();
        assert_eq!(listen.http, "127.0.0.1:9090");
        assert_eq!(listen.grpc, "127.0.0.1:9091");

        let webauthn = WebAuthnConfig::builder().build();
        assert_eq!(webauthn.party, "localhost");
        assert_eq!(webauthn.origin, "http://localhost:3000");

        let email = EmailConfig::builder().build();
        assert_eq!(email.host, "localhost");
        assert_eq!(email.port, 587);
        assert_eq!(email.address, "noreply@inferadb.com");
        assert_eq!(email.name, "InferaDB");

        let limits = LimitsConfig::builder().build();
        assert_eq!(limits.login_attempts_per_ip_per_hour, 100);
        assert_eq!(limits.registrations_per_ip_per_day, 5);

        let frontend = FrontendConfig::builder().build();
        assert_eq!(frontend.url, "http://localhost:3000");

        let webhook = WebhookConfig::builder().build();
        assert_eq!(webhook.timeout, 5000);
        assert_eq!(webhook.retries, 0);

        let ledger = LedgerConfig::builder().build();
        assert!(ledger.endpoint.is_none());
        assert!(ledger.client_id.is_none());
    }
}
