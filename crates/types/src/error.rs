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

/// Converts [`StorageError`] variants into the appropriate [`Error`] variant
/// based on HTTP semantics: not-found maps to 404, conflicts to 409,
/// rate limits to 429, and most others to 500.
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
#[allow(clippy::needless_pass_by_value)]
mod tests {
    use super::*;

    // ── Factory methods (table-driven) ──────────────────────────────

    /// Helper enum to describe the expected variant for assertion.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Variant {
        Config,
        Storage,
        Auth,
        Authz,
        Validation,
        NotFound,
        AlreadyExists,
        RateLimit,
        TierLimit,
        TooManyPasskeys,
        Unavailable,
        External,
        Internal,
    }

    fn classify(err: &Error) -> Variant {
        match err {
            Error::Config { .. } => Variant::Config,
            Error::Storage { .. } => Variant::Storage,
            Error::Auth { .. } => Variant::Auth,
            Error::Authz { .. } => Variant::Authz,
            Error::Validation { .. } => Variant::Validation,
            Error::NotFound { .. } => Variant::NotFound,
            Error::AlreadyExists { .. } => Variant::AlreadyExists,
            Error::RateLimit { .. } => Variant::RateLimit,
            Error::TierLimit { .. } => Variant::TierLimit,
            Error::TooManyPasskeys { .. } => Variant::TooManyPasskeys,
            Error::Unavailable { .. } => Variant::Unavailable,
            Error::External { .. } => Variant::External,
            Error::Internal { .. } => Variant::Internal,
        }
    }

    fn message_of(err: &Error) -> Option<&str> {
        match err {
            Error::Config { message, .. }
            | Error::Storage { message, .. }
            | Error::Auth { message, .. }
            | Error::Authz { message, .. }
            | Error::Validation { message, .. }
            | Error::NotFound { message, .. }
            | Error::AlreadyExists { message, .. }
            | Error::RateLimit { message, .. }
            | Error::TierLimit { message, .. }
            | Error::Unavailable { message, .. }
            | Error::External { message, .. }
            | Error::Internal { message, .. } => Some(message),
            Error::TooManyPasskeys { .. } => None,
        }
    }

    #[test]
    fn test_factory_variant_correct_and_message_preserved() {
        let cases = vec![
            ("config", Error::config("bad config"), Variant::Config, Some("bad config")),
            ("storage", Error::storage("disk full"), Variant::Storage, Some("disk full")),
            ("auth", Error::auth("invalid token"), Variant::Auth, Some("invalid token")),
            ("authz", Error::authz("forbidden"), Variant::Authz, Some("forbidden")),
            (
                "validation",
                Error::validation("invalid email"),
                Variant::Validation,
                Some("invalid email"),
            ),
            ("not_found", Error::not_found("user 42"), Variant::NotFound, Some("user 42")),
            (
                "already_exists",
                Error::already_exists("duplicate key"),
                Variant::AlreadyExists,
                Some("duplicate key"),
            ),
            ("rate_limit", Error::rate_limit("too fast"), Variant::RateLimit, Some("too fast")),
            (
                "tier_limit",
                Error::tier_limit("plan exceeded"),
                Variant::TierLimit,
                Some("plan exceeded"),
            ),
            ("too_many_passkeys", Error::too_many_passkeys(10), Variant::TooManyPasskeys, None),
            (
                "unavailable",
                Error::unavailable("maintenance"),
                Variant::Unavailable,
                Some("maintenance"),
            ),
            (
                "external",
                Error::external("upstream failed"),
                Variant::External,
                Some("upstream failed"),
            ),
            ("internal", Error::internal("unexpected"), Variant::Internal, Some("unexpected")),
        ];

        for (name, err, expected_variant, expected_msg) in cases {
            assert_eq!(classify(&err), expected_variant, "variant mismatch for {name}");
            assert_eq!(message_of(&err), expected_msg, "message mismatch for {name}");
        }
    }

    #[test]
    fn test_factory_too_many_passkeys_stores_max_value() {
        let err = Error::too_many_passkeys(10);

        assert!(matches!(err, Error::TooManyPasskeys { max: 10, .. }));
    }

    // ── Factory: Into<String> acceptance (table-driven) ─────────────

    #[test]
    fn test_factory_accepts_str_ref_and_owned_and_empty() {
        struct Case {
            name: &'static str,
            err: Error,
            expected: &'static str,
        }
        let cases = vec![
            Case { name: "str_ref", err: Error::validation("a message"), expected: "a message" },
            Case {
                name: "owned_string",
                err: Error::validation(String::from("a message")),
                expected: "a message",
            },
            Case { name: "empty_string", err: Error::validation(""), expected: "" },
        ];

        for case in cases {
            assert_eq!(message_of(&case.err), Some(case.expected), "mismatch for {}", case.name);
        }
    }

    // ── status_code (table-driven) ──────────────────────────────────

    #[test]
    fn test_status_code_maps_variant_to_http_code() {
        let cases = vec![
            ("config", Error::config("x"), 500u16),
            ("storage", Error::storage("x"), 500),
            ("auth", Error::auth("x"), 401),
            ("authz", Error::authz("x"), 403),
            ("validation", Error::validation("x"), 400),
            ("not_found", Error::not_found("x"), 404),
            ("already_exists", Error::already_exists("x"), 409),
            ("rate_limit", Error::rate_limit("x"), 429),
            ("tier_limit", Error::tier_limit("x"), 402),
            ("too_many_passkeys", Error::too_many_passkeys(5), 400),
            ("unavailable", Error::unavailable("x"), 503),
            ("external", Error::external("x"), 502),
            ("internal", Error::internal("x"), 500),
        ];

        for (name, err, expected_code) in cases {
            assert_eq!(err.status_code(), expected_code, "status_code mismatch for {name}");
        }
    }

    // ── error_code (table-driven) ───────────────────────────────────

    #[test]
    fn test_error_code_maps_variant_to_machine_string() {
        let cases = vec![
            ("config", Error::config("x"), "CONFIGURATION_ERROR"),
            ("storage", Error::storage("x"), "STORAGE_ERROR"),
            ("auth", Error::auth("x"), "AUTHENTICATION_ERROR"),
            ("authz", Error::authz("x"), "AUTHORIZATION_ERROR"),
            ("validation", Error::validation("x"), "VALIDATION_ERROR"),
            ("not_found", Error::not_found("x"), "NOT_FOUND"),
            ("already_exists", Error::already_exists("x"), "ALREADY_EXISTS"),
            ("rate_limit", Error::rate_limit("x"), "RATE_LIMIT_EXCEEDED"),
            ("tier_limit", Error::tier_limit("x"), "TIER_LIMIT_EXCEEDED"),
            ("too_many_passkeys", Error::too_many_passkeys(1), "TOO_MANY_PASSKEYS"),
            ("unavailable", Error::unavailable("x"), "SERVICE_UNAVAILABLE"),
            ("external", Error::external("x"), "EXTERNAL_SERVICE_ERROR"),
            ("internal", Error::internal("x"), "INTERNAL_ERROR"),
        ];

        for (name, err, expected_code) in cases {
            assert_eq!(err.error_code(), expected_code, "error_code mismatch for {name}");
        }
    }

    // ── Display impl (table-driven) ─────────────────────────────────

    #[test]
    fn test_display_format_matches_expected_string() {
        let cases = vec![
            ("config", Error::config("missing key"), "Configuration error: missing key"),
            ("storage", Error::storage("io failure"), "Storage error: io failure"),
            ("auth", Error::auth("bad token"), "Authentication error: bad token"),
            ("authz", Error::authz("no access"), "Authorization error: no access"),
            ("validation", Error::validation("bad input"), "Validation error: bad input"),
            ("not_found", Error::not_found("item xyz"), "Resource not found: item xyz"),
            (
                "already_exists",
                Error::already_exists("duplicate"),
                "Resource already exists: duplicate",
            ),
            ("rate_limit", Error::rate_limit("slow down"), "Rate limit exceeded: slow down"),
            (
                "tier_limit",
                Error::tier_limit("upgrade required"),
                "Tier limit exceeded: upgrade required",
            ),
            (
                "unavailable",
                Error::unavailable("down for maintenance"),
                "Service unavailable: down for maintenance",
            ),
            ("external", Error::external("api timeout"), "External service error: api timeout"),
            ("internal", Error::internal("oops"), "Internal error: oops"),
        ];

        for (name, err, expected_display) in cases {
            let display = err.to_string();
            assert_eq!(display, expected_display, "display mismatch for {name}");
        }
    }

    #[test]
    fn test_display_too_many_passkeys_includes_max() {
        let err = Error::too_many_passkeys(10);

        let display = err.to_string();

        assert_eq!(display, "Too many passkeys registered (max: 10)");
    }

    // ── std::error::Error impl ──────────────────────────────────────

    #[test]
    fn test_error_implements_std_error_trait() {
        let err = Error::validation("test");

        let std_err: &dyn std::error::Error = &err;

        assert!(std_err.to_string().contains("test"));
    }

    #[test]
    fn test_error_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}

        assert_send_sync::<Error>();
    }

    // ── From<StorageError> conversion (table-driven) ────────────────

    #[test]
    fn test_from_storage_error_maps_variant_and_status() {
        let cases: Vec<(&str, StorageError, Variant, u16)> = vec![
            ("not_found", StorageError::not_found("test_key"), Variant::NotFound, 404),
            ("conflict", StorageError::conflict(), Variant::AlreadyExists, 409),
            (
                "cas_retries_exhausted",
                StorageError::cas_retries_exhausted(5),
                Variant::AlreadyExists,
                409,
            ),
            (
                "rate_limit_exceeded",
                StorageError::rate_limit_exceeded(std::time::Duration::from_secs(1)),
                Variant::RateLimit,
                429,
            ),
            (
                "range_limit_exceeded",
                StorageError::range_limit_exceeded(1000, 500),
                Variant::Validation,
                400,
            ),
            ("circuit_open", StorageError::circuit_open(), Variant::Unavailable, 503),
            ("shutting_down", StorageError::shutting_down(), Variant::Unavailable, 503),
            (
                "internal",
                StorageError::Internal {
                    message: "backend crashed".to_string(),
                    source: None,
                    span_id: None,
                },
                Variant::Internal,
                500,
            ),
            (
                "connection",
                StorageError::Connection {
                    message: "refused".to_string(),
                    source: None,
                    span_id: None,
                },
                Variant::Internal,
                500,
            ),
            (
                "serialization",
                StorageError::Serialization {
                    message: "bad data".to_string(),
                    source: None,
                    span_id: None,
                },
                Variant::Internal,
                500,
            ),
            (
                "timeout",
                StorageError::Timeout { context: None, span_id: None },
                Variant::Internal,
                500,
            ),
            (
                "size_limit_exceeded",
                StorageError::size_limit_exceeded("value", 2048, 1024),
                Variant::Internal,
                500,
            ),
        ];

        for (name, storage_err, expected_variant, expected_status) in cases {
            let err = Error::from(storage_err);
            assert_eq!(classify(&err), expected_variant, "{name}: variant mismatch");
            assert_eq!(err.status_code(), expected_status, "{name}: status_code mismatch");
        }
    }

    #[test]
    fn test_from_storage_error_preserves_original_message() {
        let se = StorageError::not_found("my_key");
        let original_display = se.to_string();

        let err = Error::from(se);

        let err_display = err.to_string();
        assert!(
            err_display.contains(&original_display),
            "converted error should contain original storage error message: got '{err_display}', expected to contain '{original_display}'"
        );
    }

    #[test]
    fn test_from_storage_error_circuit_open_uses_fixed_message() {
        let se = StorageError::circuit_open();

        let err = Error::from(se);

        let display = err.to_string();
        assert!(
            display.contains("storage service temporarily unavailable"),
            "unavailable mapping should use fixed message, got: {display}"
        );
    }

    #[test]
    fn test_from_storage_error_shutting_down_uses_fixed_message() {
        let se = StorageError::shutting_down();

        let err = Error::from(se);

        let display = err.to_string();
        assert!(
            display.contains("storage service temporarily unavailable"),
            "unavailable mapping should use fixed message, got: {display}"
        );
    }
}
