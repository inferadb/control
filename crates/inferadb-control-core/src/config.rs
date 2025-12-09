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

    /// Ed25519 private key in PEM format (optional - will auto-generate if not provided for control API.
    /// If provided, the key is persisted across restarts.
    /// If not provided, a new keypair is generated on each startup.
    pub pem: Option<String>,

    /// Master secret for encrypting private keys at rest.
    /// Should be set via environment variable INFERADB__CONTROL__SECRET
    ///
    /// SECURITY: This secret should be:
    /// - At least 32 bytes (256 bits) of random data
    /// - Stored securely (e.g., in a secrets manager)
    /// - Rotated periodically with proper key re-encryption
    pub secret: Option<String>,

    #[serde(default = "default_storage")]
    pub storage: String,
    #[serde(default)]
    pub listen: ListenConfig,
    #[serde(default)]
    pub foundationdb: FoundationDbConfig,
    #[serde(default)]
    pub webauthn: WebAuthnConfig,
    #[serde(default)]
    pub email: EmailConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub mesh: MeshConfig,
    #[serde(default)]
    pub webhook: WebhookConfig,
    #[serde(default)]
    pub discovery: DiscoveryConfig,
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

    /// Service mesh / inter-service communication address (server-to-server, JWKS endpoint)
    /// Format: "host:port" (e.g., "0.0.0.0:9092")
    #[serde(default = "default_mesh")]
    pub mesh: String,
}

/// FoundationDB configuration (only used when storage = "foundationdb")
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FoundationDbConfig {
    /// FoundationDB cluster file path
    /// e.g., "/etc/foundationdb/fdb.cluster"
    pub cluster_file: Option<String>,
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

/// Service mesh configuration for engine communication
///
/// This configuration controls how control discovers and connects to
/// engine (policy service) instances. Both gRPC and HTTP internal endpoints are
/// derived from the same base URL with different ports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshConfig {
    /// gRPC port for engine communication
    /// Default: 8081
    #[serde(default = "default_mesh_grpc")]
    pub grpc: u16,

    /// Mesh port for internal communication (webhooks/JWKS)
    /// Default: 8082
    #[serde(default = "default_mesh_port")]
    pub port: u16,

    /// Base URL (without port, used for discovery or direct connection)
    /// e.g., "http://inferadb-engine.inferadb" for K8s or "http://localhost" for dev
    #[serde(default = "default_mesh_url")]
    pub url: String,
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            grpc: default_mesh_grpc(),
            port: default_mesh_port(),
            url: default_mesh_url(),
        }
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
        Self {
            timeout: default_webhook_timeout(),
            retries: default_webhook_retries(),
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
fn default_http() -> String {
    "127.0.0.1:9090".to_string()
}

fn default_grpc() -> String {
    "127.0.0.1:9091".to_string()
}

fn default_mesh() -> String {
    "0.0.0.0:9092".to_string() // Management internal/mesh server port
}

fn default_threads() -> usize {
    num_cpus::get()
}

fn default_logging() -> String {
    "info".to_string()
}

fn default_storage() -> String {
    "memory".to_string()
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


fn default_mesh_grpc() -> u16 {
    8081 // Engine's public gRPC port
}

fn default_mesh_port() -> u16 {
    8082 // Engine's mesh/internal API port
}

fn default_mesh_url() -> String {
    "http://localhost".to_string() // Default for development
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
            storage: default_storage(),
            listen: ListenConfig {
                http: default_http(),
                grpc: default_grpc(),
                mesh: default_mesh(),
            },
            foundationdb: FoundationDbConfig::default(),
            webauthn: WebAuthnConfig::default(),
            secret: None,
            email: EmailConfig {
                host: "localhost".to_string(),
                port: default_email_port(),
                username: None,
                password: None,
                address: "noreply@inferadb.com".to_string(),
                name: default_email_name(),
            },
            limits: LimitsConfig {
                login_attempts_per_ip_per_hour: default_login_attempts_per_ip_per_hour(),
                registrations_per_ip_per_day: default_registrations_per_ip_per_day(),
                email_verification_tokens_per_hour: default_email_verification_tokens_per_hour(),
                password_reset_tokens_per_hour: default_password_reset_tokens_per_hour(),
            },
            mesh: MeshConfig::default(),
            pem: None,
            webhook: WebhookConfig::default(),
            discovery: DiscoveryConfig::default(),
            frontend: FrontendConfig::default(),
        }
    }
}

impl ManagementConfig {
    /// Get the effective gRPC URL for the engine service
    ///
    /// Combines `mesh.url` with `mesh.grpc`
    /// to produce the full gRPC endpoint URL.
    ///
    /// Example: "http://localhost" + 8081 → "http://localhost:8081"
    pub fn effective_grpc_url(&self) -> String {
        format!("{}:{}", self.mesh.url, self.mesh.grpc)
    }

    /// Get the effective mesh URL for the engine service
    ///
    /// Combines `mesh.url` with `mesh.port`
    /// to produce the full mesh/internal API endpoint URL.
    ///
    /// Example: "http://localhost" + 8082 → "http://localhost:8082"
    pub fn effective_mesh_url(&self) -> String {
        format!("{}:{}", self.mesh.url, self.mesh.port)
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
        // Validate listen addresses are parseable
        self.listen
            .http
            .parse::<std::net::SocketAddr>()
            .map_err(|e| Error::Config(format!("listen.http '{}' is not valid: {}", self.listen.http, e)))?;
        self.listen
            .grpc
            .parse::<std::net::SocketAddr>()
            .map_err(|e| Error::Config(format!("listen.grpc '{}' is not valid: {}", self.listen.grpc, e)))?;
        self.listen
            .mesh
            .parse::<std::net::SocketAddr>()
            .map_err(|e| Error::Config(format!("listen.mesh '{}' is not valid: {}", self.listen.mesh, e)))?;

        // Validate storage backend
        if self.storage != "memory" && self.storage != "foundationdb" {
            return Err(Error::Config(format!(
                "Invalid storage: {}. Must be 'memory' or 'foundationdb'",
                self.storage
            )));
        }

        // Validate FoundationDB config
        if self.storage == "foundationdb" && self.foundationdb.cluster_file.is_none() {
            return Err(Error::Config(
                "foundationdb.cluster_file is required when storage = 'foundationdb'".to_string(),
            ));
        }

        // Validate secret is set
        if self.secret.is_none() {
            tracing::warn!(
                "secret not set - private keys will not be encrypted at rest!"
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

        // Validate webhook.timeout is reasonable
        if self.webhook.timeout == 0 {
            return Err(Error::Config(
                "webhook.timeout must be greater than 0".to_string(),
            ));
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

        // Validate mesh.url format
        if !self.mesh.url.starts_with("http://")
            && !self.mesh.url.starts_with("https://")
        {
            return Err(Error::Config(
                "mesh.url must start with http:// or https://".to_string(),
            ));
        }
        if self.mesh.url.ends_with('/') {
            return Err(Error::Config(
                "mesh.url must not end with trailing slash".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        assert_eq!(default_http(), "127.0.0.1:9090");
        assert_eq!(default_grpc(), "127.0.0.1:9091");
        assert_eq!(default_mesh(), "0.0.0.0:9092");
        assert_eq!(default_storage(), "memory");
        assert_eq!(default_webauthn_party(), "localhost");
        assert_eq!(default_webauthn_origin(), "http://localhost:3000");
    }

    #[test]
    fn test_storage_validation() {
        let mut config = ManagementConfig::default();
        config.webauthn.party = "localhost".to_string();
        config.webauthn.origin = "http://localhost:3000".to_string();
        config.secret = Some("test-secret".to_string());
        config.storage = "invalid".to_string();

        // Invalid storage
        assert!(config.validate().is_err());

        // Valid storage backends
        config.storage = "memory".to_string();
        assert!(config.validate().is_ok());

        config.storage = "foundationdb".to_string();
        config.foundationdb.cluster_file = Some("/path/to/fdb.cluster".to_string());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_effective_urls() {
        let config = ManagementConfig::default();
        assert_eq!(config.effective_grpc_url(), "http://localhost:8081");
        assert_eq!(config.effective_mesh_url(), "http://localhost:8082");

        let mut config = ManagementConfig::default();
        config.mesh.url = "http://inferadb-engine.inferadb".to_string();
        config.mesh.grpc = 9000;
        config.mesh.port = 9191;
        assert_eq!(config.effective_grpc_url(), "http://inferadb-engine.inferadb:9000");
        assert_eq!(config.effective_mesh_url(), "http://inferadb-engine.inferadb:9191");
    }
}
