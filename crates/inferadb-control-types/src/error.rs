use thiserror::Error;

/// Result type alias for management operations
pub type Result<T> = std::result::Result<T, Error>;

/// Error types for the Management API
#[derive(Error, Debug)]
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
    #[error("Too many passkeys registered (max: {max})")]
    TooManyPasskeys { max: usize },

    /// External service errors
    #[error("External service error: {0}")]
    External(String),

    /// Internal system errors
    #[error("Internal error: {0}")]
    Internal(String),

    /// Generic errors
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl Error {
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
            Error::TooManyPasskeys { .. } => 400,
            Error::External(_) => 502,
            Error::Internal(_) => 500,
            Error::Other(_) => 500,
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
            Error::TooManyPasskeys { .. } => "TOO_MANY_PASSKEYS",
            Error::External(_) => "EXTERNAL_SERVICE_ERROR",
            Error::Internal(_) => "INTERNAL_ERROR",
            Error::Other(_) => "INTERNAL_ERROR",
        }
    }
}
