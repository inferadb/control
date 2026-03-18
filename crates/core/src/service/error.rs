//! Maps Ledger SDK errors to Control API errors.
//!
//! The Ledger SDK returns [`SdkError`] with gRPC status codes and structured
//! error details. This module converts those into [`Error`] variants that the
//! API layer maps to HTTP status codes.
//!
//! Uses a free function rather than `From` impl to avoid orphan rule violations
//! (neither `SdkError` nor `Error` is defined in this crate).

use inferadb_control_types::error::Error;
use inferadb_ledger_sdk::SdkError;
use tonic::Code;

/// Converts a Ledger SDK error into a Control API error.
///
/// Mapping strategy:
/// - gRPC status codes map to the semantically closest Control error variant
/// - Transient errors (connection, timeout, unavailable) become storage errors
/// - The original SDK error message is preserved for debugging
pub fn sdk_error_to_control(err: SdkError) -> Error {
    match &err {
        SdkError::Rpc { code, message, .. } => rpc_code_to_error(*code, message),

        SdkError::RateLimited { message, .. } => Error::rate_limit(message.clone()),

        SdkError::Validation { message } => Error::validation(message.clone()),

        SdkError::Connection { message } => {
            Error::storage(format!("ledger connection error: {message}"))
        },

        SdkError::Transport { source } => {
            Error::storage(format!("ledger transport error: {source}"))
        },

        SdkError::Timeout { duration_ms } => {
            Error::storage(format!("ledger operation timed out after {duration_ms}ms"))
        },

        SdkError::Unavailable { message } => {
            Error::storage(format!("ledger unavailable: {message}"))
        },

        SdkError::RetryExhausted {
            attempts,
            last_error,
            ..
        } => Error::storage(format!(
            "ledger retry exhausted after {attempts} attempts: {last_error}"
        )),

        SdkError::CircuitOpen { endpoint, .. } => {
            Error::storage(format!("ledger circuit open for {endpoint}"))
        },

        SdkError::OrganizationMigrating { .. } => {
            Error::storage("organization is migrating, try again later")
        },

        SdkError::UserMigrating { .. } => {
            Error::storage("user is migrating between regions, try again later")
        },

        SdkError::Config { message } => Error::internal(format!("SDK config error: {message}")),

        SdkError::Shutdown => Error::internal("ledger client is shutting down"),

        SdkError::Cancelled => Error::internal("request cancelled"),

        SdkError::Idempotency { message, .. } => {
            Error::internal(format!("idempotency error: {message}"))
        },

        SdkError::AlreadyCommitted { .. } => {
            // Not an error — the original write succeeded. Treat as success in
            // the caller; if we reach here, it's unexpected.
            Error::internal("operation already committed")
        },

        SdkError::StreamDisconnected { message } => {
            Error::storage(format!("ledger stream disconnected: {message}"))
        },

        SdkError::InvalidUrl { url, message } => {
            Error::internal(format!("invalid ledger URL '{url}': {message}"))
        },

        SdkError::ProofVerification { reason } => {
            Error::internal(format!("proof verification failed: {reason}"))
        },
    }
}

/// Maps a gRPC status code + message to the appropriate Control error variant.
fn rpc_code_to_error(code: Code, message: &str) -> Error {
    match code {
        Code::NotFound => Error::not_found(message),
        Code::AlreadyExists => Error::already_exists(message),
        Code::InvalidArgument => Error::validation(message),
        Code::FailedPrecondition => Error::validation(message),
        Code::PermissionDenied => Error::authz(message),
        Code::Unauthenticated => Error::auth(message),
        Code::ResourceExhausted => Error::tier_limit(message),
        Code::Unavailable => Error::storage(format!("ledger unavailable: {message}")),
        Code::DeadlineExceeded => Error::storage(format!("ledger deadline exceeded: {message}")),
        Code::Aborted => Error::storage(format!("ledger aborted: {message}")),
        Code::Internal => Error::internal(format!("ledger internal error: {message}")),
        Code::Unimplemented => Error::internal(format!("ledger unimplemented: {message}")),
        Code::DataLoss => Error::internal(format!("ledger data loss: {message}")),
        _ => Error::internal(format!("ledger error ({code:?}): {message}")),
    }
}

/// Extension trait for converting `Result<T, SdkError>` to `Result<T, Error>`.
///
/// Provides a `.map_sdk_err()` method for ergonomic error conversion in service
/// wrappers without needing to import the conversion function at every call site.
pub trait SdkResultExt<T> {
    /// Maps the error variant from [`SdkError`] to [`Error`].
    fn map_sdk_err(self) -> inferadb_control_types::error::Result<T>;
}

impl<T> SdkResultExt<T> for std::result::Result<T, SdkError> {
    fn map_sdk_err(self) -> inferadb_control_types::error::Result<T> {
        self.map_err(sdk_error_to_control)
    }
}
