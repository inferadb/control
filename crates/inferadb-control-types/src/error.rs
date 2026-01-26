use thiserror::Error;

/// Result type alias for management operations
pub type Result<T> = std::result::Result<T, Error>;

/// Error types for the Control API
///
/// Use the constructor methods (e.g., `Error::validation("message")`) to create errors.
#[derive(Debug, Error)]
pub enum Error {
    /// Configuration errors
    #[error("Configuration error: {0}")]
    Config(String),

    /// Storage errors
    #[error("Storage error: {0}")]
    Storage(String),

    /// Authentication errors
    #[error("Authentication error: {0}")]
    Auth(String),

    /// Authorization errors
    #[error("Authorization error: {0}")]
    Authz(String),

    /// Validation errors
    #[error("Validation error: {0}")]
    Validation(String),

    /// Resource not found
    #[error("Resource not found: {0}")]
    NotFound(String),

    /// Resource already exists
    #[error("Resource already exists: {0}")]
    AlreadyExists(String),

    /// Rate limit exceeded
    #[error("Rate limit exceeded: {0}")]
    RateLimit(String),

    /// Tier limit exceeded
    #[error("Tier limit exceeded: {0}")]
    TierLimit(String),

    /// Too many passkeys
    #[error("Too many passkeys registered (max: {0})")]
    TooManyPasskeys(usize),

    /// External service errors
    #[error("External service error: {0}")]
    External(String),

    /// Internal system errors
    #[error("Internal error: {0}")]
    Internal(String),
}

impl Error {
    // =========================================================================
    // Constructors - maintain API compatibility
    // =========================================================================

    /// Create a configuration error
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    /// Create a storage error
    pub fn storage(message: impl Into<String>) -> Self {
        Self::Storage(message.into())
    }

    /// Create an authentication error
    pub fn auth(message: impl Into<String>) -> Self {
        Self::Auth(message.into())
    }

    /// Create an authorization error
    pub fn authz(message: impl Into<String>) -> Self {
        Self::Authz(message.into())
    }

    /// Create a validation error
    pub fn validation(message: impl Into<String>) -> Self {
        Self::Validation(message.into())
    }

    /// Create a not found error
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::NotFound(message.into())
    }

    /// Create an already exists error
    pub fn already_exists(message: impl Into<String>) -> Self {
        Self::AlreadyExists(message.into())
    }

    /// Create a rate limit error
    pub fn rate_limit(message: impl Into<String>) -> Self {
        Self::RateLimit(message.into())
    }

    /// Create a tier limit error
    pub fn tier_limit(message: impl Into<String>) -> Self {
        Self::TierLimit(message.into())
    }

    /// Create a too many passkeys error
    pub fn too_many_passkeys(max: usize) -> Self {
        Self::TooManyPasskeys(max)
    }

    /// Create an external service error
    pub fn external(message: impl Into<String>) -> Self {
        Self::External(message.into())
    }

    /// Create an internal error
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal(message.into())
    }

    // =========================================================================
    // Metadata accessors
    // =========================================================================

    /// Get HTTP status code for this error
    pub fn status_code(&self) -> u16 {
        match self {
            Error::Config(_) => 500,
            Error::Storage(_) => 500,
            Error::Auth(_) => 401,
            Error::Authz(_) => 403,
            Error::Validation(_) => 400,
            Error::NotFound(_) => 404,
            Error::AlreadyExists(_) => 409,
            Error::RateLimit(_) => 429,
            Error::TierLimit(_) => 402,
            Error::TooManyPasskeys(_) => 400,
            Error::External(_) => 502,
            Error::Internal(_) => 500,
        }
    }

    /// Get error code for client consumption
    pub fn error_code(&self) -> &str {
        match self {
            Error::Config(_) => "CONFIGURATION_ERROR",
            Error::Storage(_) => "STORAGE_ERROR",
            Error::Auth(_) => "AUTHENTICATION_ERROR",
            Error::Authz(_) => "AUTHORIZATION_ERROR",
            Error::Validation(_) => "VALIDATION_ERROR",
            Error::NotFound(_) => "NOT_FOUND",
            Error::AlreadyExists(_) => "ALREADY_EXISTS",
            Error::RateLimit(_) => "RATE_LIMIT_EXCEEDED",
            Error::TierLimit(_) => "TIER_LIMIT_EXCEEDED",
            Error::TooManyPasskeys(_) => "TOO_MANY_PASSKEYS",
            Error::External(_) => "EXTERNAL_SERVICE_ERROR",
            Error::Internal(_) => "INTERNAL_ERROR",
        }
    }
}
