use serde::{Deserialize, Serialize};
use std::path::Path;

use infera_management_types::error::{Error, Result};

/// Root configuration for the Management API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagementConfig {
    /// Server configuration
    #[serde(default)]
    pub server: ServerConfig,

    /// Storage configuration
    #[serde(default)]
    pub storage: StorageConfig,

    /// Authentication configuration
    #[serde(default)]
    pub auth: AuthConfig,

    /// Email configuration
    #[serde(default)]
    pub email: EmailConfig,

    /// Rate limiting configuration
    #[serde(default)]
    pub rate_limiting: RateLimitingConfig,

    /// Observability configuration
    #[serde(default)]
    pub observability: ObservabilityConfig,

    /// ID generation configuration
    #[serde(default)]
    pub id_generation: IdGenerationConfig,

    /// Server API configuration (for gRPC communication with @server)
    #[serde(default)]
    pub server_api: ServerApiConfig,

    /// Management identity configuration (for webhook authentication)
    #[serde(default = "default_management_identity")]
    pub management_identity: ManagementIdentityConfig,

    /// Cache invalidation webhook configuration
    #[serde(default = "default_cache_invalidation")]
    pub cache_invalidation: CacheInvalidationConfig,

    /// Frontend base URL for email links (verification, password reset)
    /// Example: "https://app.inferadb.com" or "http://localhost:3000"
    /// Environment variable: INFERADB_MGMT__FRONTEND_BASE_URL
    #[serde(default = "default_frontend_base_url")]
    pub frontend_base_url: String,
}

/// Server/HTTP configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServerConfig {
    /// HTTP server host
    #[serde(default = "default_http_host")]
    pub http_host: String,

    /// HTTP server port
    #[serde(default = "default_http_port")]
    pub http_port: u16,

    /// gRPC server host
    #[serde(default = "default_grpc_host")]
    pub grpc_host: String,

    /// gRPC server port
    #[serde(default = "default_grpc_port")]
    pub grpc_port: u16,

    /// Worker threads for async runtime
    #[serde(default = "default_worker_threads")]
    pub worker_threads: usize,
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
    /// Should be set via environment variable INFERADB_MGMT_KEY_ENCRYPTION_SECRET
    pub key_encryption_secret: Option<String>,

    /// JWT issuer URL (this Management API instance)
    /// Used in vault-scoped JWTs issued to clients
    /// Example: "https://api.inferadb.com" or "http://localhost:8081"
    /// Environment variable: INFERA_MANAGEMENT__AUTH__JWT_ISSUER
    #[serde(default = "default_jwt_issuer")]
    pub jwt_issuer: String,

    /// JWT audience URL (the Server API)
    /// Used in vault-scoped JWTs issued to clients
    /// Example: "https://api.inferadb.com/evaluate" or "http://localhost:8080/evaluate"
    /// Environment variable: INFERA_MANAGEMENT__AUTH__JWT_AUDIENCE
    #[serde(default = "default_jwt_audience")]
    pub jwt_audience: String,
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

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RateLimitingConfig {
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

/// Observability configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ObservabilityConfig {
    /// Log level
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Enable Prometheus metrics
    #[serde(default = "default_metrics_enabled")]
    pub metrics_enabled: bool,

    /// Enable OpenTelemetry tracing
    #[serde(default = "default_tracing_enabled")]
    pub tracing_enabled: bool,

    /// OTLP endpoint for traces (if tracing enabled)
    pub otlp_endpoint: Option<String>,
}

/// ID generation configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IdGenerationConfig {
    /// Worker ID for Snowflake ID generation (0-1023)
    #[serde(default = "default_worker_id")]
    pub worker_id: u16,

    /// Maximum acceptable clock skew in milliseconds
    #[serde(default = "default_max_clock_skew_ms")]
    pub max_clock_skew_ms: u64,
}

/// Server API configuration (for gRPC communication with @server)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServerApiConfig {
    /// gRPC endpoint for @server
    pub grpc_endpoint: String,

    /// Enable TLS for gRPC communication
    #[serde(default = "default_grpc_tls_enabled")]
    pub tls_enabled: bool,
}

/// Management identity configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagementIdentityConfig {
    /// Management instance ID (unique identifier for this management instance)
    #[serde(default = "default_management_id")]
    pub management_id: String,

    /// Key ID for JWKS
    #[serde(default = "default_kid")]
    pub kid: String,

    /// Ed25519 private key in PEM format (optional - will auto-generate if not provided)
    pub private_key_pem: Option<String>,
}

/// Cache invalidation webhook configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheInvalidationConfig {
    /// HTTP endpoints for Server API instances (for webhook calls)
    /// Example: ["http://localhost:8080", "http://server-2:8080"]
    #[serde(default = "default_http_endpoints")]
    pub http_endpoints: Vec<String>,

    /// Webhook request timeout in milliseconds
    #[serde(default = "default_webhook_timeout_ms")]
    pub timeout_ms: u64,

    /// Number of retry attempts on webhook failure
    #[serde(default = "default_webhook_retry_attempts")]
    pub retry_attempts: u8,

    /// Service discovery configuration
    #[serde(default)]
    pub discovery: DiscoveryConfig,
}

/// Service discovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    /// Discovery mode (none or kubernetes)
    #[serde(default)]
    pub mode: DiscoveryMode,

    /// Cache TTL for discovered endpoints (in seconds)
    #[serde(default = "default_discovery_cache_ttl")]
    pub cache_ttl_seconds: u64,

    /// Whether to enable health checking of endpoints
    #[serde(default = "default_discovery_health_check")]
    pub enable_health_check: bool,

    /// Health check interval (in seconds)
    #[serde(default = "default_discovery_health_check_interval")]
    pub health_check_interval_seconds: u64,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            mode: DiscoveryMode::None,
            cache_ttl_seconds: default_discovery_cache_ttl(),
            enable_health_check: default_discovery_health_check(),
            health_check_interval_seconds: default_discovery_health_check_interval(),
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

    /// Service name within the cluster (e.g., "inferadb-management-api")
    pub service_name: String,

    /// Service port
    pub port: u16,
}

// Default value functions
fn default_http_host() -> String {
    "127.0.0.1".to_string()
}

fn default_http_port() -> u16 {
    3000
}

fn default_grpc_host() -> String {
    "127.0.0.1".to_string()
}

fn default_grpc_port() -> u16 {
    3001
}

fn default_worker_threads() -> usize {
    4
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

fn default_log_level() -> String {
    "info".to_string()
}

fn default_metrics_enabled() -> bool {
    true
}

fn default_tracing_enabled() -> bool {
    false
}

fn default_worker_id() -> u16 {
    0
}

fn default_max_clock_skew_ms() -> u64 {
    1000 // 1 second
}

fn default_grpc_tls_enabled() -> bool {
    true
}

fn default_frontend_base_url() -> String {
    "http://localhost:3000".to_string()
}

fn default_jwt_issuer() -> String {
    "https://api.inferadb.com".to_string()
}

fn default_jwt_audience() -> String {
    "https://api.inferadb.com/evaluate".to_string()
}

fn default_management_identity() -> ManagementIdentityConfig {
    ManagementIdentityConfig {
        management_id: "management-primary".to_string(),
        kid: "mgmt-2024-01".to_string(),
        private_key_pem: None, // Auto-generate on startup
    }
}

fn default_cache_invalidation() -> CacheInvalidationConfig {
    CacheInvalidationConfig {
        http_endpoints: vec![], // No webhooks by default
        timeout_ms: 5000,       // 5 seconds
        retry_attempts: 0,      // Fire-and-forget (no retries)
        discovery: DiscoveryConfig::default(),
    }
}

fn default_management_id() -> String {
    "management-primary".to_string()
}

fn default_kid() -> String {
    "mgmt-2024-01".to_string()
}

fn default_http_endpoints() -> Vec<String> {
    vec![] // Empty by default - webhooks disabled
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

fn default_discovery_health_check() -> bool {
    false
}

fn default_discovery_health_check_interval() -> u64 {
    30 // 30 seconds
}

impl Default for ManagementConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                http_host: default_http_host(),
                http_port: default_http_port(),
                grpc_host: default_grpc_host(),
                grpc_port: default_grpc_port(),
                worker_threads: default_worker_threads(),
            },
            storage: StorageConfig {
                backend: default_storage_backend(),
                fdb_cluster_file: None,
            },
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
                jwt_issuer: default_jwt_issuer(),
                jwt_audience: default_jwt_audience(),
            },
            email: EmailConfig {
                smtp_host: "localhost".to_string(),
                smtp_port: default_smtp_port(),
                smtp_username: None,
                smtp_password: None,
                from_email: "noreply@inferadb.com".to_string(),
                from_name: default_from_name(),
            },
            rate_limiting: RateLimitingConfig {
                login_attempts_per_ip_per_hour: default_login_attempts_per_ip_per_hour(),
                registrations_per_ip_per_day: default_registrations_per_ip_per_day(),
                email_verification_tokens_per_hour: default_email_verification_tokens_per_hour(),
                password_reset_tokens_per_hour: default_password_reset_tokens_per_hour(),
            },
            observability: ObservabilityConfig {
                log_level: default_log_level(),
                metrics_enabled: default_metrics_enabled(),
                tracing_enabled: default_tracing_enabled(),
                otlp_endpoint: None,
            },
            id_generation: IdGenerationConfig {
                worker_id: default_worker_id(),
                max_clock_skew_ms: default_max_clock_skew_ms(),
            },
            server_api: ServerApiConfig {
                grpc_endpoint: "http://localhost:8080".to_string(),
                tls_enabled: default_grpc_tls_enabled(),
            },
            management_identity: default_management_identity(),
            cache_invalidation: default_cache_invalidation(),
            frontend_base_url: default_frontend_base_url(),
        }
    }
}

impl ManagementConfig {
    /// Load configuration with layered precedence: defaults → file → env vars
    ///
    /// This function implements a proper configuration hierarchy:
    /// 1. Start with hardcoded defaults (via `#[serde(default)]` annotations)
    /// 2. Override with values from config file (if file exists and properties are set)
    /// 3. Override with environment variables (if env vars are set)
    ///
    /// Each layer only overrides properties that are explicitly set, preserving
    /// defaults for unspecified values.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        // The config crate will use serde's #[serde(default)] annotations for defaults
        // Layer 1 (defaults) is handled by serde deserialization
        // Layer 2: Add file source (optional - only overrides if file exists)
        let builder =
            config::Config::builder().add_source(config::File::from(path.as_ref()).required(false));

        // Layer 3: Add environment variables (highest precedence)
        let builder = builder.add_source(
            config::Environment::with_prefix("INFERADB_MGMT")
                .separator("__")
                .try_parsing(true),
        );

        let config = builder
            .build()
            .map_err(|e| Error::Config(format!("Failed to build config: {}", e)))?;

        config
            .try_deserialize()
            .map_err(|e| Error::Config(format!("Failed to deserialize config: {}", e)))
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
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Failed to load config from {:?}. Using defaults with environment overrides.",
                    path.as_ref()
                );

                // Even if file loading fails, apply env vars to defaults
                Self::default()
            }
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

        // Validate worker ID range
        if self.id_generation.worker_id > 1023 {
            return Err(Error::Config(format!(
                "Worker ID must be between 0 and 1023, got {}",
                self.id_generation.worker_id
            )));
        }

        // Validate key encryption secret is set
        if self.auth.key_encryption_secret.is_none() {
            tracing::warn!(
                "KEY_ENCRYPTION_SECRET not set - private keys will not be encrypted at rest!"
            );
        }

        // Validate frontend_base_url format
        if !self.frontend_base_url.starts_with("http://")
            && !self.frontend_base_url.starts_with("https://")
        {
            return Err(Error::Config(
                "frontend_base_url must start with http:// or https://".to_string(),
            ));
        }

        if self.frontend_base_url.ends_with('/') {
            return Err(Error::Config(
                "frontend_base_url must not end with trailing slash".to_string(),
            ));
        }

        // Warn about localhost in production-like environments
        if self.frontend_base_url.contains("localhost")
            || self.frontend_base_url.contains("127.0.0.1")
        {
            tracing::warn!(
                "frontend_base_url contains localhost - this should only be used in development. \
                 Production deployments should use a public domain."
            );
        }

        // Validate cache_invalidation.http_endpoints format
        for (idx, endpoint) in self.cache_invalidation.http_endpoints.iter().enumerate() {
            if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
                return Err(Error::Config(format!(
                    "cache_invalidation.http_endpoints[{}] must start with http:// or https://, got: {}",
                    idx, endpoint
                )));
            }
            if endpoint.ends_with('/') {
                return Err(Error::Config(format!(
                    "cache_invalidation.http_endpoints[{}] must not end with trailing slash: {}",
                    idx, endpoint
                )));
            }
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
            return Err(Error::Config(
                "auth.webauthn.rp_id cannot be empty".to_string(),
            ));
        }
        if self.auth.webauthn.origin.is_empty() {
            return Err(Error::Config(
                "auth.webauthn.origin cannot be empty".to_string(),
            ));
        }
        if !self.auth.webauthn.origin.starts_with("http://")
            && !self.auth.webauthn.origin.starts_with("https://")
        {
            return Err(Error::Config(
                "auth.webauthn.origin must start with http:// or https://".to_string(),
            ));
        }

        // Validate server_api.grpc_endpoint format
        if !self.server_api.grpc_endpoint.starts_with("http://")
            && !self.server_api.grpc_endpoint.starts_with("https://")
        {
            return Err(Error::Config(
                "server_api.grpc_endpoint must start with http:// or https://".to_string(),
            ));
        }

        // Validate password minimum length is reasonable
        if self.auth.password_min_length < 8 {
            tracing::warn!(
                min_length = self.auth.password_min_length,
                "auth.password_min_length is less than 8. Consider using at least 8 characters for security."
            );
        }

        // Validate management_identity configuration
        if self.management_identity.management_id.is_empty() {
            return Err(Error::Config(
                "management_identity.management_id cannot be empty".to_string(),
            ));
        }
        if self.management_identity.kid.is_empty() {
            return Err(Error::Config(
                "management_identity.kid cannot be empty".to_string(),
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
        assert_eq!(default_http_host(), "127.0.0.1");
        assert_eq!(default_http_port(), 3000);
        assert_eq!(default_grpc_port(), 3001);
        assert_eq!(default_storage_backend(), "memory");
        assert_eq!(default_password_min_length(), 12);
        assert_eq!(default_max_sessions_per_user(), 10);
    }

    #[test]
    fn test_worker_id_validation() {
        let mut config = ManagementConfig {
            server: ServerConfig {
                http_host: default_http_host(),
                http_port: default_http_port(),
                grpc_host: default_grpc_host(),
                grpc_port: default_grpc_port(),
                worker_threads: default_worker_threads(),
            },
            storage: StorageConfig {
                backend: "memory".to_string(),
                fdb_cluster_file: None,
            },
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
                key_encryption_secret: Some("test-secret".to_string()),
                jwt_issuer: default_jwt_issuer(),
                jwt_audience: default_jwt_audience(),
            },
            email: EmailConfig {
                smtp_host: "localhost".to_string(),
                smtp_port: default_smtp_port(),
                smtp_username: None,
                smtp_password: None,
                from_email: "noreply@inferadb.com".to_string(),
                from_name: default_from_name(),
            },
            rate_limiting: RateLimitingConfig {
                login_attempts_per_ip_per_hour: default_login_attempts_per_ip_per_hour(),
                registrations_per_ip_per_day: default_registrations_per_ip_per_day(),
                email_verification_tokens_per_hour: default_email_verification_tokens_per_hour(),
                password_reset_tokens_per_hour: default_password_reset_tokens_per_hour(),
            },
            observability: ObservabilityConfig {
                log_level: default_log_level(),
                metrics_enabled: default_metrics_enabled(),
                tracing_enabled: default_tracing_enabled(),
                otlp_endpoint: None,
            },
            id_generation: IdGenerationConfig {
                worker_id: 0,
                max_clock_skew_ms: default_max_clock_skew_ms(),
            },
            server_api: ServerApiConfig {
                grpc_endpoint: "http://localhost:8080".to_string(),
                tls_enabled: false,
            },
            management_identity: default_management_identity(),
            cache_invalidation: default_cache_invalidation(),
            frontend_base_url: default_frontend_base_url(),
        };

        // Valid worker ID
        assert!(config.validate().is_ok());

        // Invalid worker ID
        config.id_generation.worker_id = 1024;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_storage_backend_validation() {
        let mut config = ManagementConfig {
            server: ServerConfig {
                http_host: default_http_host(),
                http_port: default_http_port(),
                grpc_host: default_grpc_host(),
                grpc_port: default_grpc_port(),
                worker_threads: default_worker_threads(),
            },
            storage: StorageConfig {
                backend: "invalid".to_string(),
                fdb_cluster_file: None,
            },
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
                key_encryption_secret: Some("test-secret".to_string()),
                jwt_issuer: default_jwt_issuer(),
                jwt_audience: default_jwt_audience(),
            },
            email: EmailConfig {
                smtp_host: "localhost".to_string(),
                smtp_port: default_smtp_port(),
                smtp_username: None,
                smtp_password: None,
                from_email: "noreply@inferadb.com".to_string(),
                from_name: default_from_name(),
            },
            rate_limiting: RateLimitingConfig {
                login_attempts_per_ip_per_hour: default_login_attempts_per_ip_per_hour(),
                registrations_per_ip_per_day: default_registrations_per_ip_per_day(),
                email_verification_tokens_per_hour: default_email_verification_tokens_per_hour(),
                password_reset_tokens_per_hour: default_password_reset_tokens_per_hour(),
            },
            observability: ObservabilityConfig {
                log_level: default_log_level(),
                metrics_enabled: default_metrics_enabled(),
                tracing_enabled: default_tracing_enabled(),
                otlp_endpoint: None,
            },
            id_generation: IdGenerationConfig {
                worker_id: 0,
                max_clock_skew_ms: default_max_clock_skew_ms(),
            },
            server_api: ServerApiConfig {
                grpc_endpoint: "http://localhost:8080".to_string(),
                tls_enabled: false,
            },
            management_identity: default_management_identity(),
            cache_invalidation: default_cache_invalidation(),
            frontend_base_url: default_frontend_base_url(),
        };

        // Invalid storage backend
        assert!(config.validate().is_err());

        // Valid backends
        config.storage.backend = "memory".to_string();
        assert!(config.validate().is_ok());

        config.storage.backend = "foundationdb".to_string();
        config.storage.fdb_cluster_file = Some("/path/to/fdb.cluster".to_string());
        assert!(config.validate().is_ok());
    }
}
