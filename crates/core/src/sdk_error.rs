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
            tracing::error!(error = %message, "Ledger connection error");
            Error::unavailable("upstream service temporarily unavailable")
        },

        SdkError::Transport { source } => {
            tracing::error!(error = %source, "Ledger transport error");
            Error::unavailable("upstream service temporarily unavailable")
        },

        SdkError::Timeout { duration_ms } => {
            tracing::error!(duration_ms = duration_ms, "Ledger operation timed out");
            Error::unavailable("upstream service temporarily unavailable")
        },

        SdkError::Unavailable { message } => {
            tracing::error!(error = %message, "Ledger unavailable");
            Error::unavailable("upstream service temporarily unavailable")
        },

        SdkError::RetryExhausted { attempts, last_error, .. } => {
            tracing::error!(attempts = attempts, error = %last_error, "Ledger retry exhausted");
            Error::unavailable("upstream service temporarily unavailable")
        },

        SdkError::CircuitOpen { endpoint, .. } => {
            tracing::error!(endpoint = %endpoint, "Ledger circuit breaker open");
            Error::unavailable("upstream service temporarily unavailable")
        },

        SdkError::OrganizationMigrating { .. } => {
            Error::unavailable("organization is temporarily unavailable, please retry")
        },

        SdkError::UserMigrating { .. } => {
            Error::unavailable("account is temporarily unavailable, please retry")
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
            tracing::error!(error = %message, "Ledger stream disconnected");
            Error::unavailable("upstream service temporarily unavailable")
        },

        SdkError::InvalidUrl { url, message } => {
            tracing::error!(url = %url, error = %message, "Invalid Ledger URL");
            Error::internal("upstream service configuration error")
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
        Code::Unavailable => {
            tracing::error!(error = %message, "Ledger RPC unavailable");
            Error::unavailable("upstream service temporarily unavailable")
        },
        Code::DeadlineExceeded => {
            tracing::error!(error = %message, "Ledger RPC deadline exceeded");
            Error::unavailable("upstream service temporarily unavailable")
        },
        Code::Aborted => {
            tracing::error!(error = %message, "Ledger RPC aborted");
            Error::unavailable("operation could not be completed, please retry")
        },
        Code::Internal => {
            tracing::error!(error = %message, "Ledger internal error");
            Error::internal("upstream service internal error")
        },
        Code::Unimplemented => Error::internal("requested operation is not supported"),
        Code::DataLoss => {
            tracing::error!(error = %message, "Ledger data loss");
            Error::internal("upstream service data integrity error")
        },
        _ => {
            tracing::error!(code = ?code, error = %message, "Unexpected Ledger RPC error");
            Error::internal("unexpected upstream service error")
        },
    }
}

/// Extension trait for converting `Result<T, SdkError>` to `Result<T, Error>`.
///
/// Provides `.map_sdk_err()` for basic error conversion, and
/// `.map_sdk_err_instrumented()` which additionally records gRPC metrics
/// and logs failures with the method name.
pub trait SdkResultExt<T> {
    /// Maps the error variant from [`SdkError`] to [`Error`].
    fn map_sdk_err(self) -> inferadb_control_types::error::Result<T>;

    /// Maps the error and records gRPC request metrics (duration + status).
    ///
    /// Call this instead of `map_sdk_err()` in service functions to get
    /// automatic `grpc_request_duration_seconds` and error logging with
    /// the Ledger method name.
    fn map_sdk_err_instrumented(
        self,
        method: &str,
        start: std::time::Instant,
    ) -> inferadb_control_types::error::Result<T>;
}

impl<T> SdkResultExt<T> for std::result::Result<T, SdkError> {
    fn map_sdk_err(self) -> inferadb_control_types::error::Result<T> {
        self.map_err(sdk_error_to_control)
    }

    fn map_sdk_err_instrumented(
        self,
        method: &str,
        start: std::time::Instant,
    ) -> inferadb_control_types::error::Result<T> {
        let duration = start.elapsed().as_secs_f64();
        match self {
            Ok(val) => {
                crate::metrics::record_grpc_request("Ledger", method, "OK", duration);
                Ok(val)
            },
            Err(e) => {
                let status = sdk_error_status_label(&e);
                crate::metrics::record_grpc_request("Ledger", method, status, duration);
                tracing::warn!(method = method, error = %e, "Ledger SDK call failed");
                Err(sdk_error_to_control(e))
            },
        }
    }
}

/// Returns a short status label for metrics from an SDK error.
fn sdk_error_status_label(err: &SdkError) -> &'static str {
    match err {
        SdkError::Rpc { code, .. } => match code {
            Code::NotFound => "NOT_FOUND",
            Code::AlreadyExists => "ALREADY_EXISTS",
            Code::InvalidArgument => "INVALID_ARGUMENT",
            Code::FailedPrecondition => "FAILED_PRECONDITION",
            Code::PermissionDenied => "PERMISSION_DENIED",
            Code::Unauthenticated => "UNAUTHENTICATED",
            Code::ResourceExhausted => "RESOURCE_EXHAUSTED",
            Code::Unavailable => "UNAVAILABLE",
            Code::DeadlineExceeded => "DEADLINE_EXCEEDED",
            Code::Internal => "INTERNAL",
            _ => "UNKNOWN",
        },
        SdkError::Connection { .. } => "CONNECTION_ERROR",
        SdkError::Transport { .. } => "TRANSPORT_ERROR",
        SdkError::Timeout { .. } => "TIMEOUT",
        SdkError::Unavailable { .. } => "UNAVAILABLE",
        SdkError::RetryExhausted { .. } => "RETRY_EXHAUSTED",
        SdkError::CircuitOpen { .. } => "CIRCUIT_OPEN",
        SdkError::RateLimited { .. } => "RATE_LIMITED",
        SdkError::Validation { .. } => "VALIDATION",
        _ => "OTHER",
    }
}
