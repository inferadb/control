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

#[cfg(test)]
mod tests {
    use super::*;

    // ── Factory methods ──────────────────────────────────────────────

    #[test]
    fn factory_config_creates_config_variant() {
        let err = Error::config("bad config");
        assert!(matches!(err, Error::Config { ref message, .. } if message == "bad config"));
    }

    #[test]
    fn factory_storage_creates_storage_variant() {
        let err = Error::storage("disk full");
        assert!(matches!(err, Error::Storage { ref message, .. } if message == "disk full"));
    }

    #[test]
    fn factory_auth_creates_auth_variant() {
        let err = Error::auth("invalid token");
        assert!(matches!(err, Error::Auth { ref message, .. } if message == "invalid token"));
    }

    #[test]
    fn factory_authz_creates_authz_variant() {
        let err = Error::authz("forbidden");
        assert!(matches!(err, Error::Authz { ref message, .. } if message == "forbidden"));
    }

    #[test]
    fn factory_validation_creates_validation_variant() {
        let err = Error::validation("invalid email");
        assert!(matches!(err, Error::Validation { ref message, .. } if message == "invalid email"));
    }

    #[test]
    fn factory_not_found_creates_not_found_variant() {
        let err = Error::not_found("user 42");
        assert!(matches!(err, Error::NotFound { ref message, .. } if message == "user 42"));
    }

    #[test]
    fn factory_already_exists_creates_already_exists_variant() {
        let err = Error::already_exists("duplicate key");
        assert!(
            matches!(err, Error::AlreadyExists { ref message, .. } if message == "duplicate key")
        );
    }

    #[test]
    fn factory_rate_limit_creates_rate_limit_variant() {
        let err = Error::rate_limit("too fast");
        assert!(matches!(err, Error::RateLimit { ref message, .. } if message == "too fast"));
    }

    #[test]
    fn factory_tier_limit_creates_tier_limit_variant() {
        let err = Error::tier_limit("plan exceeded");
        assert!(matches!(err, Error::TierLimit { ref message, .. } if message == "plan exceeded"));
    }

    #[test]
    fn factory_too_many_passkeys_creates_too_many_passkeys_variant() {
        let err = Error::too_many_passkeys(10);
        assert!(matches!(err, Error::TooManyPasskeys { max: 10, .. }));
    }

    #[test]
    fn factory_unavailable_creates_unavailable_variant() {
        let err = Error::unavailable("maintenance");
        assert!(matches!(err, Error::Unavailable { ref message, .. } if message == "maintenance"));
    }

    #[test]
    fn factory_external_creates_external_variant() {
        let err = Error::external("upstream failed");
        assert!(matches!(err, Error::External { ref message, .. } if message == "upstream failed"));
    }

    #[test]
    fn factory_internal_creates_internal_variant() {
        let err = Error::internal("unexpected");
        assert!(matches!(err, Error::Internal { ref message, .. } if message == "unexpected"));
    }

    // ── Factory methods accept &str via Into<String> ─────────────────

    #[test]
    fn factory_accepts_str_ref() {
        let msg: &str = "a message";
        let err = Error::validation(msg);
        assert!(matches!(err, Error::Validation { .. }));
    }

    #[test]
    fn factory_accepts_owned_string() {
        let msg = String::from("a message");
        let err = Error::validation(msg);
        assert!(matches!(err, Error::Validation { .. }));
    }

    // ── status_code ──────────────────────────────────────────────────

    #[test]
    fn status_code_config_is_500() {
        assert_eq!(Error::config("x").status_code(), 500);
    }

    #[test]
    fn status_code_storage_is_500() {
        assert_eq!(Error::storage("x").status_code(), 500);
    }

    #[test]
    fn status_code_auth_is_401() {
        assert_eq!(Error::auth("x").status_code(), 401);
    }

    #[test]
    fn status_code_authz_is_403() {
        assert_eq!(Error::authz("x").status_code(), 403);
    }

    #[test]
    fn status_code_validation_is_400() {
        assert_eq!(Error::validation("x").status_code(), 400);
    }

    #[test]
    fn status_code_not_found_is_404() {
        assert_eq!(Error::not_found("x").status_code(), 404);
    }

    #[test]
    fn status_code_already_exists_is_409() {
        assert_eq!(Error::already_exists("x").status_code(), 409);
    }

    #[test]
    fn status_code_rate_limit_is_429() {
        assert_eq!(Error::rate_limit("x").status_code(), 429);
    }

    #[test]
    fn status_code_tier_limit_is_402() {
        assert_eq!(Error::tier_limit("x").status_code(), 402);
    }

    #[test]
    fn status_code_too_many_passkeys_is_400() {
        assert_eq!(Error::too_many_passkeys(5).status_code(), 400);
    }

    #[test]
    fn status_code_unavailable_is_503() {
        assert_eq!(Error::unavailable("x").status_code(), 503);
    }

    #[test]
    fn status_code_external_is_502() {
        assert_eq!(Error::external("x").status_code(), 502);
    }

    #[test]
    fn status_code_internal_is_500() {
        assert_eq!(Error::internal("x").status_code(), 500);
    }

    // ── error_code ───────────────────────────────────────────────────

    #[test]
    fn error_code_config() {
        assert_eq!(Error::config("x").error_code(), "CONFIGURATION_ERROR");
    }

    #[test]
    fn error_code_storage() {
        assert_eq!(Error::storage("x").error_code(), "STORAGE_ERROR");
    }

    #[test]
    fn error_code_auth() {
        assert_eq!(Error::auth("x").error_code(), "AUTHENTICATION_ERROR");
    }

    #[test]
    fn error_code_authz() {
        assert_eq!(Error::authz("x").error_code(), "AUTHORIZATION_ERROR");
    }

    #[test]
    fn error_code_validation() {
        assert_eq!(Error::validation("x").error_code(), "VALIDATION_ERROR");
    }

    #[test]
    fn error_code_not_found() {
        assert_eq!(Error::not_found("x").error_code(), "NOT_FOUND");
    }

    #[test]
    fn error_code_already_exists() {
        assert_eq!(Error::already_exists("x").error_code(), "ALREADY_EXISTS");
    }

    #[test]
    fn error_code_rate_limit() {
        assert_eq!(Error::rate_limit("x").error_code(), "RATE_LIMIT_EXCEEDED");
    }

    #[test]
    fn error_code_tier_limit() {
        assert_eq!(Error::tier_limit("x").error_code(), "TIER_LIMIT_EXCEEDED");
    }

    #[test]
    fn error_code_too_many_passkeys() {
        assert_eq!(Error::too_many_passkeys(1).error_code(), "TOO_MANY_PASSKEYS");
    }

    #[test]
    fn error_code_unavailable() {
        assert_eq!(Error::unavailable("x").error_code(), "SERVICE_UNAVAILABLE");
    }

    #[test]
    fn error_code_external() {
        assert_eq!(Error::external("x").error_code(), "EXTERNAL_SERVICE_ERROR");
    }

    #[test]
    fn error_code_internal() {
        assert_eq!(Error::internal("x").error_code(), "INTERNAL_ERROR");
    }

    // ── Display impl ─────────────────────────────────────────────────

    #[test]
    fn display_config_includes_message() {
        let err = Error::config("missing key");
        let display = err.to_string();
        assert!(display.contains("missing key"), "got: {display}");
        assert!(display.contains("Configuration error"), "got: {display}");
    }

    #[test]
    fn display_storage_includes_message() {
        let err = Error::storage("io failure");
        let display = err.to_string();
        assert!(display.contains("io failure"), "got: {display}");
        assert!(display.contains("Storage error"), "got: {display}");
    }

    #[test]
    fn display_auth_includes_message() {
        let err = Error::auth("bad token");
        let display = err.to_string();
        assert!(display.contains("bad token"), "got: {display}");
        assert!(display.contains("Authentication error"), "got: {display}");
    }

    #[test]
    fn display_authz_includes_message() {
        let err = Error::authz("no access");
        let display = err.to_string();
        assert!(display.contains("no access"), "got: {display}");
        assert!(display.contains("Authorization error"), "got: {display}");
    }

    #[test]
    fn display_validation_includes_message() {
        let err = Error::validation("bad input");
        let display = err.to_string();
        assert!(display.contains("bad input"), "got: {display}");
        assert!(display.contains("Validation error"), "got: {display}");
    }

    #[test]
    fn display_not_found_includes_message() {
        let err = Error::not_found("item xyz");
        let display = err.to_string();
        assert!(display.contains("item xyz"), "got: {display}");
        assert!(display.contains("not found"), "got: {display}");
    }

    #[test]
    fn display_already_exists_includes_message() {
        let err = Error::already_exists("duplicate");
        let display = err.to_string();
        assert!(display.contains("duplicate"), "got: {display}");
        assert!(display.contains("already exists"), "got: {display}");
    }

    #[test]
    fn display_rate_limit_includes_message() {
        let err = Error::rate_limit("slow down");
        let display = err.to_string();
        assert!(display.contains("slow down"), "got: {display}");
        assert!(display.contains("Rate limit"), "got: {display}");
    }

    #[test]
    fn display_tier_limit_includes_message() {
        let err = Error::tier_limit("upgrade required");
        let display = err.to_string();
        assert!(display.contains("upgrade required"), "got: {display}");
        assert!(display.contains("Tier limit"), "got: {display}");
    }

    #[test]
    fn display_too_many_passkeys_includes_max() {
        let err = Error::too_many_passkeys(10);
        let display = err.to_string();
        assert!(display.contains("10"), "got: {display}");
        assert!(display.contains("passkeys"), "got: {display}");
    }

    #[test]
    fn display_unavailable_includes_message() {
        let err = Error::unavailable("down for maintenance");
        let display = err.to_string();
        assert!(display.contains("down for maintenance"), "got: {display}");
        assert!(display.contains("unavailable"), "got: {display}");
    }

    #[test]
    fn display_external_includes_message() {
        let err = Error::external("api timeout");
        let display = err.to_string();
        assert!(display.contains("api timeout"), "got: {display}");
        assert!(display.contains("External"), "got: {display}");
    }

    #[test]
    fn display_internal_includes_message() {
        let err = Error::internal("oops");
        let display = err.to_string();
        assert!(display.contains("oops"), "got: {display}");
        assert!(display.contains("Internal error"), "got: {display}");
    }

    // ── From<StorageError> conversion ────────────────────────────────

    #[test]
    fn from_storage_not_found_maps_to_not_found() {
        let se = StorageError::not_found("test_key");
        let err = Error::from(se);
        assert!(matches!(err, Error::NotFound { .. }));
        assert_eq!(err.status_code(), 404);
    }

    #[test]
    fn from_storage_conflict_maps_to_already_exists() {
        let se = StorageError::conflict();
        let err = Error::from(se);
        assert!(matches!(err, Error::AlreadyExists { .. }));
        assert_eq!(err.status_code(), 409);
    }

    #[test]
    fn from_storage_cas_retries_exhausted_maps_to_already_exists() {
        let se = StorageError::cas_retries_exhausted(5);
        let err = Error::from(se);
        assert!(matches!(err, Error::AlreadyExists { .. }));
        assert_eq!(err.status_code(), 409);
    }

    #[test]
    fn from_storage_rate_limit_exceeded_maps_to_rate_limit() {
        let se = StorageError::rate_limit_exceeded(std::time::Duration::from_secs(1));
        let err = Error::from(se);
        assert!(matches!(err, Error::RateLimit { .. }));
        assert_eq!(err.status_code(), 429);
    }

    #[test]
    fn from_storage_range_limit_exceeded_maps_to_validation() {
        let se = StorageError::range_limit_exceeded(1000, 500);
        let err = Error::from(se);
        assert!(matches!(err, Error::Validation { .. }));
        assert_eq!(err.status_code(), 400);
    }

    #[test]
    fn from_storage_circuit_open_maps_to_unavailable() {
        let se = StorageError::circuit_open();
        let err = Error::from(se);
        assert!(matches!(err, Error::Unavailable { .. }));
        assert_eq!(err.status_code(), 503);
    }

    #[test]
    fn from_storage_shutting_down_maps_to_unavailable() {
        let se = StorageError::shutting_down();
        let err = Error::from(se);
        assert!(matches!(err, Error::Unavailable { .. }));
        assert_eq!(err.status_code(), 503);
    }

    #[test]
    fn from_storage_internal_maps_to_internal() {
        let se = StorageError::Internal {
            message: "backend crashed".to_string(),
            source: None,
            span_id: None,
        };
        let err = Error::from(se);
        assert!(matches!(err, Error::Internal { .. }));
        assert_eq!(err.status_code(), 500);
    }

    #[test]
    fn from_storage_connection_maps_to_internal() {
        let se = StorageError::Connection {
            message: "refused".to_string(),
            source: None,
            span_id: None,
        };
        let err = Error::from(se);
        assert!(matches!(err, Error::Internal { .. }));
        assert_eq!(err.status_code(), 500);
    }

    #[test]
    fn from_storage_serialization_maps_to_internal() {
        let se = StorageError::Serialization {
            message: "bad data".to_string(),
            source: None,
            span_id: None,
        };
        let err = Error::from(se);
        assert!(matches!(err, Error::Internal { .. }));
        assert_eq!(err.status_code(), 500);
    }

    #[test]
    fn from_storage_timeout_maps_to_internal() {
        let se = StorageError::Timeout { context: None, span_id: None };
        let err = Error::from(se);
        assert!(matches!(err, Error::Internal { .. }));
        assert_eq!(err.status_code(), 500);
    }
}
