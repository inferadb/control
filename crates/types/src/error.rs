//! Error types and [`Result`] alias for the Control API.

use inferadb_common_storage::StorageError;
use snafu::{Backtrace, Snafu};

/// Alias for `std::result::Result<T, Error>` used throughout the Control plane crates.
pub type Result<T> = std::result::Result<T, Error>;

/// Unified error enum for all Control API operations.
///
/// Each variant maps to a specific HTTP status code and machine-readable error code.
/// Use the factory methods (e.g., [`Error::validation`]) to create errors;
/// they automatically capture backtraces when `RUST_BACKTRACE` or `RUST_LIB_BACKTRACE` is set.
///
/// # Examples
///
/// ```no_run
/// use inferadb_control_types::error::Error;
///
/// // Create errors using factory methods
/// let validation_err = Error::validation("Invalid email format");
/// let not_found_err = Error::not_found("User with ID 123");
/// let auth_err = Error::auth("Invalid credentials");
///
/// // Access error metadata
/// assert_eq!(validation_err.status_code(), 400);
/// assert_eq!(validation_err.error_code(), "VALIDATION_ERROR");
/// ```
#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum Error {
    /// Invalid or missing configuration. Status: 500.
    #[snafu(display("Configuration error: {message}"))]
    Config { message: String, backtrace: Backtrace },

    /// Storage backend failure. Status: 500.
    #[snafu(display("Storage error: {message}"))]
    Storage { message: String, backtrace: Backtrace },

    /// Caller identity could not be verified. Status: 401.
    #[snafu(display("Authentication error: {message}"))]
    Auth { message: String, backtrace: Backtrace },

    /// Caller lacks permission for the requested action. Status: 403.
    #[snafu(display("Authorization error: {message}"))]
    Authz { message: String, backtrace: Backtrace },

    /// Request payload failed validation. Status: 400.
    #[snafu(display("Validation error: {message}"))]
    Validation { message: String, backtrace: Backtrace },

    /// Requested resource does not exist. Status: 404.
    #[snafu(display("Resource not found: {message}"))]
    NotFound { message: String, backtrace: Backtrace },

    /// Resource conflicts with an existing one. Status: 409.
    #[snafu(display("Resource already exists: {message}"))]
    AlreadyExists { message: String, backtrace: Backtrace },

    /// Request rate exceeded the allowed limit. Status: 429.
    #[snafu(display("Rate limit exceeded: {message}"))]
    RateLimit { message: String, backtrace: Backtrace },

    /// Subscription tier limit reached. Status: 402.
    #[snafu(display("Tier limit exceeded: {message}"))]
    TierLimit { message: String, backtrace: Backtrace },

    /// User has registered the maximum number of passkeys. Status: 400.
    #[snafu(display("Too many passkeys registered (max: {max})"))]
    TooManyPasskeys { max: usize, backtrace: Backtrace },

    /// Upstream service is temporarily unavailable. Status: 503.
    #[snafu(display("Service unavailable: {message}"))]
    Unavailable { message: String, backtrace: Backtrace },

    /// External dependency returned an error. Status: 502.
    #[snafu(display("External service error: {message}"))]
    External { message: String, backtrace: Backtrace },

    /// Unexpected internal failure. Status: 500.
    #[snafu(display("Internal error: {message}"))]
    Internal { message: String, backtrace: Backtrace },
}

impl Error {
    /// Creates a [`Config`](Error::Config) error.
    pub fn config(message: impl Into<String>) -> Self {
        ConfigSnafu { message: message.into() }.build()
    }

    /// Creates a [`Storage`](Error::Storage) error.
    pub fn storage(message: impl Into<String>) -> Self {
        StorageSnafu { message: message.into() }.build()
    }

    /// Creates an [`Auth`](Error::Auth) error.
    pub fn auth(message: impl Into<String>) -> Self {
        AuthSnafu { message: message.into() }.build()
    }

    /// Creates an [`Authz`](Error::Authz) error.
    pub fn authz(message: impl Into<String>) -> Self {
        AuthzSnafu { message: message.into() }.build()
    }

    /// Creates a [`Validation`](Error::Validation) error.
    pub fn validation(message: impl Into<String>) -> Self {
        ValidationSnafu { message: message.into() }.build()
    }

    /// Creates a [`NotFound`](Error::NotFound) error.
    pub fn not_found(message: impl Into<String>) -> Self {
        NotFoundSnafu { message: message.into() }.build()
    }

    /// Creates an [`AlreadyExists`](Error::AlreadyExists) error.
    pub fn already_exists(message: impl Into<String>) -> Self {
        AlreadyExistsSnafu { message: message.into() }.build()
    }

    /// Creates a [`RateLimit`](Error::RateLimit) error.
    pub fn rate_limit(message: impl Into<String>) -> Self {
        RateLimitSnafu { message: message.into() }.build()
    }

    /// Creates a [`TierLimit`](Error::TierLimit) error.
    pub fn tier_limit(message: impl Into<String>) -> Self {
        TierLimitSnafu { message: message.into() }.build()
    }

    /// Creates a [`TooManyPasskeys`](Error::TooManyPasskeys) error.
    pub fn too_many_passkeys(max: usize) -> Self {
        TooManyPasskeysSnafu { max }.build()
    }

    /// Creates an [`Unavailable`](Error::Unavailable) error.
    pub fn unavailable(message: impl Into<String>) -> Self {
        UnavailableSnafu { message: message.into() }.build()
    }

    /// Creates an [`External`](Error::External) error.
    pub fn external(message: impl Into<String>) -> Self {
        ExternalSnafu { message: message.into() }.build()
    }

    /// Creates an [`Internal`](Error::Internal) error.
    pub fn internal(message: impl Into<String>) -> Self {
        InternalSnafu { message: message.into() }.build()
    }

    /// Returns the HTTP status code for this error variant.
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
            Error::Unavailable { .. } => 503,
            Error::External { .. } => 502,
            Error::Internal { .. } => 500,
        }
    }

    /// Returns the machine-readable error code string for API responses.
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
            Error::Unavailable { .. } => "SERVICE_UNAVAILABLE",
            Error::External { .. } => "EXTERNAL_SERVICE_ERROR",
            Error::Internal { .. } => "INTERNAL_ERROR",
        }
    }
}

impl From<StorageError> for Error {
    fn from(e: StorageError) -> Self {
        match &e {
            StorageError::NotFound { .. } => Error::not_found(e.to_string()),
            StorageError::Conflict { .. } | StorageError::CasRetriesExhausted { .. } => {
                Error::already_exists(e.to_string())
            },
            StorageError::RateLimitExceeded { .. } => Error::rate_limit(e.to_string()),
            StorageError::RangeLimitExceeded { .. } => Error::validation(e.to_string()),
            StorageError::CircuitOpen { .. } | StorageError::ShuttingDown { .. } => {
                Error::unavailable("storage service temporarily unavailable")
            },
            _ => Error::internal(e.to_string()),
        }
    }
}
