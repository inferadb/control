use std::path::Path;

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
///     public_rest: "127.0.0.1:8080"
///   # ... other engine config (ignored by control)
///
/// control:
///   listen:
///     public_rest: "127.0.0.1:9090"
///   # ... control config
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RootConfig {
    /// Control-specific configuration
    #[serde(default)]
    pub control: ManagementConfig,
    // Note: `engine` section may exist in the file but is ignored by control
}

/// Configuration for the Control API (formerly Management API)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagementConfig {
    /// Number of worker threads for the async runtime
    #[serde(default = "default_threads")]
    pub threads: usize,

    /// Log level (trace, debug, info, warn, error)
    #[serde(default = "default_logging")]
    pub logging: String,

    /// Listen address configuration for API servers
    #[serde(default)]
    pub listen: ListenConfig,

    /// Storage configuration
    #[serde(default)]
    pub storage: StorageConfig,

    /// Authentication configuration
    #[serde(default)]
    pub auth: AuthConfig,

    /// Email configuration
    #[serde(default)]
    pub email: EmailConfig,

    /// Rate limits configuration
    #[serde(default)]
    pub limits: LimitsConfig,

    /// Engine service configuration (for policy engine communication)
    #[serde(default)]
    pub engine: EngineConfig,

    /// Ed25519 private key in PEM format (optional - will auto-generate if not provided)
    /// If provided, the key is persisted across restarts.
    /// If not provided, a new keypair is generated on each startup.
    pub pem: Option<String>,

    /// Cache invalidation webhook configuration
    #[serde(default)]
    pub cache_invalidation: CacheInvalidationConfig,

    /// Service discovery configuration
    #[serde(default)]
    pub discovery: DiscoveryConfig,

    /// Frontend configuration for web UI links
    #[serde(default)]
    pub frontend: FrontendConfig,
}

/// Listen address configuration for API servers
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ListenConfig {
    /// Public REST API server address (client-facing)
    /// Format: "host:port" (e.g., "127.0.0.1:9090")
    #[serde(default = "default_public_rest")]
    pub public_rest: String,

    /// Public gRPC API server address
    /// Format: "host:port" (e.g., "127.0.0.1:9091")
    #[serde(default = "default_public_grpc")]
    pub public_grpc: String,

    /// Internal/Private REST API server address (server-to-server, JWKS endpoint)
    /// Format: "host:port" (e.g., "0.0.0.0:9092")
    #[serde(default = "default_private_rest")]
    pub private_rest: String,
}

/// Storage backend configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StorageConfig {
    /// Storage backend type: "memory" or "foundationdb"
    #[serde(default = "default_storage_backend")]
    pub backend: String,

    /// FoundationDB cluster file path (only used when backend = "foundationdb")
    pub fdb_cluster_file: Option<String>,
}

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthConfig {
    /// Session TTL for WEB sessions (seconds)
    #[serde(default = "default_session_ttl_web")]
    pub session_ttl_web: u64,

    /// Session TTL for CLI sessions (seconds)
    #[serde(default = "default_session_ttl_cli")]
    pub session_ttl_cli: u64,

    /// Session TTL for SDK sessions (seconds)
    #[serde(default = "default_session_ttl_sdk")]
    pub session_ttl_sdk: u64,

    /// Minimum password length
    #[serde(default = "default_password_min_length")]
    pub password_min_length: usize,

    /// Maximum concurrent sessions per user
    #[serde(default = "default_max_sessions_per_user")]
    pub max_sessions_per_user: usize,

    /// WebAuthn configuration
    pub webauthn: WebAuthnConfig,

    /// Key encryption secret for encrypting private keys at rest
    /// Should be set via environment variable INFERADB_CTRL_KEY_ENCRYPTION_SECRET
    pub key_encryption_secret: Option<String>,
    // Note: JWT issuer and audience are now hardcoded in jwt.rs as REQUIRED_ISSUER
    // and REQUIRED_AUDIENCE to ensure consistency with the Server API and follow
    // RFC 8725 best practices.
}

/// WebAuthn configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WebAuthnConfig {
    /// Relying Party ID (domain)
    pub rp_id: String,

    /// Relying Party name
    #[serde(default = "default_rp_name")]
    pub rp_name: String,

    /// Origin URL for WebAuthn
    pub origin: String,
}

/// Email configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EmailConfig {
    /// SMTP host
    pub smtp_host: String,

    /// SMTP port
    #[serde(default = "default_smtp_port")]
    pub smtp_port: u16,

    /// SMTP username
    pub smtp_username: Option<String>,

    /// SMTP password (should be set via environment variable)
    pub smtp_password: Option<String>,

    /// From email address
    pub from_email: String,

    /// From name
    #[serde(default = "default_from_name")]
    pub from_name: String,
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

/// Engine service configuration
///
/// This configuration controls how control discovers and connects to
/// engine (policy service) instances. Both gRPC and HTTP internal endpoints are
/// derived from the same base URL with different ports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineConfig {
    /// gRPC port for engine communication
    /// Default: 8081
    #[serde(default = "default_engine_grpc_port")]
    pub grpc_port: u16,

    /// Internal HTTP port for webhooks/JWKS
    /// Default: 8082
    #[serde(default = "default_engine_internal_port")]
    pub internal_port: u16,

    /// Service URL (base URL without port, used for discovery or direct connection)
    /// e.g., "http://inferadb-engine.inferadb" for K8s or "http://localhost" for dev
    #[serde(default = "default_engine_service_url")]
    pub service_url: String,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            grpc_port: default_engine_grpc_port(),
            internal_port: default_engine_internal_port(),
            service_url: default_engine_service_url(),
        }
    }
}

/// Cache invalidation webhook configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheInvalidationConfig {
    /// Webhook request timeout in milliseconds
    #[serde(default = "default_webhook_timeout_ms")]
    pub timeout_ms: u64,

    /// Number of retry attempts on webhook failure
    #[serde(default = "default_webhook_retry_attempts")]
    pub retry_attempts: u8,
}

impl Default for CacheInvalidationConfig {
    fn default() -> Self {
        Self {
            timeout_ms: default_webhook_timeout_ms(),
            retry_attempts: default_webhook_retry_attempts(),
        }
    }
}

/// Service discovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    /// Discovery mode (none or kubernetes)
    #[serde(default)]
    pub mode: DiscoveryMode,

    /// Cache TTL for discovered endpoints (in seconds)
    #[serde(default = "default_discovery_cache_ttl")]
    pub cache_ttl: u64,

    /// Health check interval (in seconds)
    #[serde(default = "default_discovery_health_check_interval")]
    pub health_check_interval: u64,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            mode: DiscoveryMode::None,
            cache_ttl: default_discovery_cache_ttl(),
            health_check_interval: default_discovery_health_check_interval(),
        }
    }
}

/// Service discovery mode
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase", tag = "type")]
pub enum DiscoveryMode {
    /// No service discovery - use service URL directly
    #[default]
    None,
    /// Kubernetes service discovery - resolve to pod IPs
    Kubernetes,
    /// Tailscale mesh networking for multi-region discovery
    Tailscale {
        /// Local cluster name (e.g., "us-west-1")
        local_cluster: String,
        /// Remote clusters to discover across
        #[serde(default)]
        remote_clusters: Vec<RemoteCluster>,
    },
}

/// Remote cluster configuration for Tailscale mesh networking
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteCluster {
    /// Cluster name (e.g., "eu-west-1", "ap-southeast-1")
    pub name: String,

    /// Tailscale domain for this cluster (e.g., "eu-west-1.ts.net")
    pub tailscale_domain: String,

    /// Service name within the cluster (e.g., "inferadb-control")
    pub service_name: String,

    /// Service port
    pub port: u16,
}

// Default value functions
fn default_public_rest() -> String {
    "127.0.0.1:9090".to_string()
}

fn default_public_grpc() -> String {
    "127.0.0.1:9091".to_string()
}

fn default_private_rest() -> String {
    "0.0.0.0:9092".to_string() // Management internal/private server port
}

fn default_threads() -> usize {
    num_cpus::get()
}

fn default_logging() -> String {
    "info".to_string()
}

fn default_storage_backend() -> String {
    "memory".to_string()
}

fn default_session_ttl_web() -> u64 {
    30 * 24 * 60 * 60 // 30 days
}

fn default_session_ttl_cli() -> u64 {
    90 * 24 * 60 * 60 // 90 days
}

fn default_session_ttl_sdk() -> u64 {
    90 * 24 * 60 * 60 // 90 days
}

fn default_password_min_length() -> usize {
    12
}

fn default_max_sessions_per_user() -> usize {
    10
}

fn default_rp_name() -> String {
    "InferaDB".to_string()
}

fn default_smtp_port() -> u16 {
    587
}

fn default_from_name() -> String {
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


fn default_engine_grpc_port() -> u16 {
    8081 // Engine's public gRPC port
}

fn default_engine_internal_port() -> u16 {
    8082 // Engine's internal/private API port
}

fn default_engine_service_url() -> String {
    "http://localhost".to_string() // Default for development
}

fn default_frontend_url() -> String {
    "http://localhost:3000".to_string()
}

fn default_webhook_timeout_ms() -> u64 {
    5000 // 5 seconds
}

fn default_webhook_retry_attempts() -> u8 {
    0 // Fire-and-forget
}

fn default_discovery_cache_ttl() -> u64 {
    300 // 5 minutes
}

fn default_discovery_health_check_interval() -> u64 {
    30 // 30 seconds
}

impl Default for ManagementConfig {
    fn default() -> Self {
        Self {
            threads: default_threads(),
            logging: default_logging(),
            listen: ListenConfig {
                public_rest: default_public_rest(),
                public_grpc: default_public_grpc(),
                private_rest: default_private_rest(),
            },
            storage: StorageConfig { backend: default_storage_backend(), fdb_cluster_file: None },
            auth: AuthConfig {
                session_ttl_web: default_session_ttl_web(),
                session_ttl_cli: default_session_ttl_cli(),
                session_ttl_sdk: default_session_ttl_sdk(),
                password_min_length: default_password_min_length(),
                max_sessions_per_user: default_max_sessions_per_user(),
                webauthn: WebAuthnConfig {
                    rp_id: "localhost".to_string(),
                    rp_name: default_rp_name(),
                    origin: "http://localhost:3000".to_string(),
                },
                key_encryption_secret: None,
            },
            email: EmailConfig {
                smtp_host: "localhost".to_string(),
                smtp_port: default_smtp_port(),
                smtp_username: None,
                smtp_password: None,
                from_email: "noreply@inferadb.com".to_string(),
                from_name: default_from_name(),
            },
            limits: LimitsConfig {
                login_attempts_per_ip_per_hour: default_login_attempts_per_ip_per_hour(),
                registrations_per_ip_per_day: default_registrations_per_ip_per_day(),
                email_verification_tokens_per_hour: default_email_verification_tokens_per_hour(),
                password_reset_tokens_per_hour: default_password_reset_tokens_per_hour(),
            },
            engine: EngineConfig::default(),
            pem: None,
            cache_invalidation: CacheInvalidationConfig::default(),
            discovery: DiscoveryConfig::default(),
            frontend: FrontendConfig::default(),
        }
    }
}

impl ManagementConfig {
    /// Get the effective gRPC URL for the engine service
    ///
    /// Combines `engine.service_url` with `engine.grpc_port`
    /// to produce the full gRPC endpoint URL.
    ///
    /// Example: "http://localhost" + 8081 → "http://localhost:8081"
    pub fn effective_grpc_url(&self) -> String {
        format!("{}:{}", self.engine.service_url, self.engine.grpc_port)
    }

    /// Get the effective internal HTTP URL for the engine service
    ///
    /// Combines `engine.service_url` with `engine.internal_port`
    /// to produce the full internal API endpoint URL.
    ///
    /// Example: "http://localhost" + 8082 → "http://localhost:8082"
    pub fn effective_internal_url(&self) -> String {
        format!("{}:{}", self.engine.service_url, self.engine.internal_port)
    }

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
            builder.build().map_err(|e| Error::Config(format!("Failed to build config: {}", e)))?;

        // Deserialize as RootConfig and extract the control section
        let root: RootConfig = config
            .try_deserialize()
            .map_err(|e| Error::Config(format!("Failed to deserialize config: {}", e)))?;

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
        // Validate storage backend
        if self.storage.backend != "memory" && self.storage.backend != "foundationdb" {
            return Err(Error::Config(format!(
                "Invalid storage backend: {}. Must be 'memory' or 'foundationdb'",
                self.storage.backend
            )));
        }

        // Validate FoundationDB config
        if self.storage.backend == "foundationdb" && self.storage.fdb_cluster_file.is_none() {
            return Err(Error::Config(
                "fdb_cluster_file is required when using FoundationDB backend".to_string(),
            ));
        }

        // Validate key encryption secret is set
        if self.auth.key_encryption_secret.is_none() {
            tracing::warn!(
                "KEY_ENCRYPTION_SECRET not set - private keys will not be encrypted at rest!"
            );
        }

        // Validate frontend.url format
        if !self.frontend.url.starts_with("http://") && !self.frontend.url.starts_with("https://") {
            return Err(Error::Config(
                "frontend.url must start with http:// or https://".to_string(),
            ));
        }

        if self.frontend.url.ends_with('/') {
            return Err(Error::Config(
                "frontend.url must not end with trailing slash".to_string(),
            ));
        }

        // Warn about localhost in production-like environments
        if self.frontend.url.contains("localhost") || self.frontend.url.contains("127.0.0.1") {
            tracing::warn!(
                "frontend.url contains localhost - this should only be used in development. \
                 Production deployments should use a public domain."
            );
        }

        // Validate cache_invalidation.timeout_ms is reasonable
        if self.cache_invalidation.timeout_ms == 0 {
            return Err(Error::Config(
                "cache_invalidation.timeout_ms must be greater than 0".to_string(),
            ));
        }
        if self.cache_invalidation.timeout_ms > 60000 {
            tracing::warn!(
                timeout_ms = self.cache_invalidation.timeout_ms,
                "cache_invalidation.timeout_ms is very high (>60s). Consider using a lower timeout."
            );
        }

        // Validate WebAuthn configuration
        if self.auth.webauthn.rp_id.is_empty() {
            return Err(Error::Config("auth.webauthn.rp_id cannot be empty".to_string()));
        }
        if self.auth.webauthn.origin.is_empty() {
            return Err(Error::Config("auth.webauthn.origin cannot be empty".to_string()));
        }
        if !self.auth.webauthn.origin.starts_with("http://")
            && !self.auth.webauthn.origin.starts_with("https://")
        {
            return Err(Error::Config(
                "auth.webauthn.origin must start with http:// or https://".to_string(),
            ));
        }

        // Validate engine.service_url format
        if !self.engine.service_url.starts_with("http://")
            && !self.engine.service_url.starts_with("https://")
        {
            return Err(Error::Config(
                "engine.service_url must start with http:// or https://".to_string(),
            ));
        }
        if self.engine.service_url.ends_with('/') {
            return Err(Error::Config(
                "engine.service_url must not end with trailing slash".to_string(),
            ));
        }

        // Validate password minimum length is reasonable
        if self.auth.password_min_length < 8 {
            tracing::warn!(
                min_length = self.auth.password_min_length,
                "auth.password_min_length is less than 8. Consider using at least 8 characters for security."
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        assert_eq!(default_public_rest(), "127.0.0.1:9090");
        assert_eq!(default_public_grpc(), "127.0.0.1:9091");
        assert_eq!(default_private_rest(), "0.0.0.0:9092");
        assert_eq!(default_storage_backend(), "memory");
        assert_eq!(default_password_min_length(), 12);
        assert_eq!(default_max_sessions_per_user(), 10);
    }

    #[test]
    fn test_storage_backend_validation() {
        let mut config = ManagementConfig::default();
        config.auth.webauthn.rp_id = "localhost".to_string();
        config.auth.webauthn.origin = "http://localhost:3000".to_string();
        config.auth.key_encryption_secret = Some("test-secret".to_string());
        config.storage.backend = "invalid".to_string();

        // Invalid storage backend
        assert!(config.validate().is_err());

        // Valid backends
        config.storage.backend = "memory".to_string();
        assert!(config.validate().is_ok());

        config.storage.backend = "foundationdb".to_string();
        config.storage.fdb_cluster_file = Some("/path/to/fdb.cluster".to_string());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_effective_urls() {
        let config = ManagementConfig::default();
        assert_eq!(config.effective_grpc_url(), "http://localhost:8081");
        assert_eq!(config.effective_internal_url(), "http://localhost:8082");

        let mut config = ManagementConfig::default();
        config.engine.service_url = "http://inferadb-engine.inferadb".to_string();
        config.engine.grpc_port = 9000;
        config.engine.internal_port = 9191;
        assert_eq!(config.effective_grpc_url(), "http://inferadb-engine.inferadb:9000");
        assert_eq!(config.effective_internal_url(), "http://inferadb-engine.inferadb:9191");
    }
}
