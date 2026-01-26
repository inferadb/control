use std::backtrace::Backtrace;

use snafu::Snafu;

/// Result type alias for management operations
pub type Result<T> = std::result::Result<T, Error>;

/// Error types for the Control API
///
/// All variants include backtraces for debugging. Use the constructor methods
/// (e.g., `Error::validation("message")`) to create errors.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum Error {
    /// Configuration errors
    #[snafu(display("Configuration error: {message}"))]
    Config { message: String, backtrace: Backtrace },

    /// Storage errors
    #[snafu(display("Storage error: {message}"))]
    Storage { message: String, backtrace: Backtrace },

    /// Authentication errors
    #[snafu(display("Authentication error: {message}"))]
    Auth { message: String, backtrace: Backtrace },

    /// Authorization errors
    #[snafu(display("Authorization error: {message}"))]
    Authz { message: String, backtrace: Backtrace },

    /// Validation errors
    #[snafu(display("Validation error: {message}"))]
    Validation { message: String, backtrace: Backtrace },

    /// Resource not found
    #[snafu(display("Resource not found: {message}"))]
    NotFound { message: String, backtrace: Backtrace },

    /// Resource already exists
    #[snafu(display("Resource already exists: {message}"))]
    AlreadyExists { message: String, backtrace: Backtrace },

    /// Rate limit exceeded
    #[snafu(display("Rate limit exceeded: {message}"))]
    RateLimit { message: String, backtrace: Backtrace },

    /// Tier limit exceeded
    #[snafu(display("Tier limit exceeded: {message}"))]
    TierLimit { message: String, backtrace: Backtrace },

    /// Too many passkeys
    #[snafu(display("Too many passkeys registered (max: {max})"))]
    TooManyPasskeys { max: usize, backtrace: Backtrace },

    /// External service errors
    #[snafu(display("External service error: {message}"))]
    External { message: String, backtrace: Backtrace },

    /// Internal system errors
    #[snafu(display("Internal error: {message}"))]
    Internal { message: String, backtrace: Backtrace },
}

impl Error {
    // =========================================================================
    // Constructors - maintain API compatibility while capturing backtraces
    // =========================================================================

    /// Create a configuration error
    pub fn config(message: impl Into<String>) -> Self {
        ConfigSnafu { message: message.into() }.build()
    }

    /// Create a storage error
    pub fn storage(message: impl Into<String>) -> Self {
        StorageSnafu { message: message.into() }.build()
    }

    /// Create an authentication error
    pub fn auth(message: impl Into<String>) -> Self {
        AuthSnafu { message: message.into() }.build()
    }

    /// Create an authorization error
    pub fn authz(message: impl Into<String>) -> Self {
        AuthzSnafu { message: message.into() }.build()
    }

    /// Create a validation error
    pub fn validation(message: impl Into<String>) -> Self {
        ValidationSnafu { message: message.into() }.build()
    }

    /// Create a not found error
    pub fn not_found(message: impl Into<String>) -> Self {
        NotFoundSnafu { message: message.into() }.build()
    }

    /// Create an already exists error
    pub fn already_exists(message: impl Into<String>) -> Self {
        AlreadyExistsSnafu { message: message.into() }.build()
    }

    /// Create a rate limit error
    pub fn rate_limit(message: impl Into<String>) -> Self {
        RateLimitSnafu { message: message.into() }.build()
    }

    /// Create a tier limit error
    pub fn tier_limit(message: impl Into<String>) -> Self {
        TierLimitSnafu { message: message.into() }.build()
    }

    /// Create a too many passkeys error
    pub fn too_many_passkeys(max: usize) -> Self {
        TooManyPasskeysSnafu { max }.build()
    }

    /// Create an external service error
    pub fn external(message: impl Into<String>) -> Self {
        ExternalSnafu { message: message.into() }.build()
    }

    /// Create an internal error
    pub fn internal(message: impl Into<String>) -> Self {
        InternalSnafu { message: message.into() }.build()
    }

    // =========================================================================
    // Metadata accessors
    // =========================================================================

    /// Get HTTP status code for this error
    pub fn status_code(&self) -> u16 {
        match self {
            Error::Config { .. } => 500,
            Error::Storage { .. } => 500,
            Error::Auth { .. } => 401,
            Error::Authz { .. } => 403,
            Error::Validation { .. } => 400,
            Error::NotFound { .. } => 404,
            Error::AlreadyExists { .. } => 409,
            Error::RateLimit { .. } => 429,
            Error::TierLimit { .. } => 402,
            Error::TooManyPasskeys { .. } => 400,
            Error::External { .. } => 502,
            Error::Internal { .. } => 500,
        }
    }

    /// Get error code for client consumption
    pub fn error_code(&self) -> &str {
        match self {
            Error::Config { .. } => "CONFIGURATION_ERROR",
            Error::Storage { .. } => "STORAGE_ERROR",
            Error::Auth { .. } => "AUTHENTICATION_ERROR",
            Error::Authz { .. } => "AUTHORIZATION_ERROR",
            Error::Validation { .. } => "VALIDATION_ERROR",
            Error::NotFound { .. } => "NOT_FOUND",
            Error::AlreadyExists { .. } => "ALREADY_EXISTS",
            Error::RateLimit { .. } => "RATE_LIMIT_EXCEEDED",
            Error::TierLimit { .. } => "TIER_LIMIT_EXCEEDED",
            Error::TooManyPasskeys { .. } => "TOO_MANY_PASSKEYS",
            Error::External { .. } => "EXTERNAL_SERVICE_ERROR",
            Error::Internal { .. } => "INTERNAL_ERROR",
        }
    }
}
