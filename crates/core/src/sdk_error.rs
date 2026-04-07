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
/// - Transient errors (connection, timeout, unavailable) become unavailable errors
/// - The original SDK error context is preserved for debugging
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
/// Provides [`map_sdk_err`](Self::map_sdk_err) for error conversion, and
/// [`map_sdk_err_instrumented`](Self::map_sdk_err_instrumented) which additionally
/// records gRPC request metrics (duration and status code) and logs results.
pub trait SdkResultExt<T> {
    /// Maps the error variant from [`SdkError`] to [`Error`].
    ///
    /// # Errors
    ///
    /// Returns the converted [`Error`] if the original result was `Err`.
    fn map_sdk_err(self) -> inferadb_control_types::error::Result<T>;

    /// Maps the error and records gRPC request metrics (duration and status).
    ///
    /// Records `grpc_request_duration_seconds` and logs failures with the
    /// Ledger method name. Prefer this over [`map_sdk_err`](Self::map_sdk_err)
    /// in handler functions.
    ///
    /// # Errors
    ///
    /// Returns the converted [`Error`] if the original result was `Err`.
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use inferadb_ledger_types::Region;

    use super::*;

    fn rpc(code: Code) -> SdkError {
        SdkError::Rpc {
            code,
            message: "test".into(),
            request_id: None,
            trace_id: None,
            error_details: None,
        }
    }

    // ── sdk_error_to_control: RPC code mapping ────────────────────────

    #[test]
    fn test_sdk_error_to_control_rpc_codes_map_to_expected_http_status() {
        let cases: Vec<(Code, u16, &str)> = vec![
            (Code::NotFound, 404, "NotFound"),
            (Code::AlreadyExists, 409, "AlreadyExists"),
            (Code::InvalidArgument, 400, "InvalidArgument"),
            (Code::FailedPrecondition, 400, "FailedPrecondition"),
            (Code::PermissionDenied, 403, "PermissionDenied"),
            (Code::Unauthenticated, 401, "Unauthenticated"),
            (Code::ResourceExhausted, 402, "ResourceExhausted"),
            (Code::Unavailable, 503, "Unavailable"),
            (Code::DeadlineExceeded, 503, "DeadlineExceeded"),
            (Code::Internal, 500, "Internal"),
            (Code::Aborted, 503, "Aborted"),
            (Code::Unimplemented, 500, "Unimplemented"),
            (Code::DataLoss, 500, "DataLoss"),
            (Code::OutOfRange, 500, "OutOfRange (fallback)"),
        ];

        for (code, expected_status, label) in cases {
            let err = sdk_error_to_control(rpc(code));

            assert_eq!(
                err.status_code(),
                expected_status,
                "RPC code {label} should map to HTTP {expected_status}"
            );
        }
    }

    // ── sdk_error_to_control: non-RPC variant mapping ─────────────────

    #[test]
    fn test_sdk_error_to_control_non_rpc_variants_map_to_expected_http_status() {
        let cases: Vec<(SdkError, u16, &str)> = vec![
            (
                SdkError::RateLimited {
                    message: "slow down".into(),
                    retry_after: std::time::Duration::from_secs(1),
                    request_id: None,
                    trace_id: None,
                    error_details: None,
                },
                429,
                "RateLimited",
            ),
            (SdkError::Validation { message: "bad input".into() }, 400, "Validation"),
            (SdkError::Connection { message: "refused".into() }, 503, "Connection"),
            (SdkError::Timeout { duration_ms: 5000 }, 503, "Timeout"),
            (SdkError::Unavailable { message: "down".into() }, 503, "Unavailable"),
            (
                SdkError::RetryExhausted {
                    attempts: 3,
                    last_error: "failed".into(),
                    attempt_history: vec![(1, "err1".into()), (2, "err2".into())],
                },
                503,
                "RetryExhausted",
            ),
            (
                SdkError::CircuitOpen {
                    endpoint: "localhost:50051".into(),
                    retry_after: std::time::Duration::from_secs(30),
                },
                503,
                "CircuitOpen",
            ),
            (
                SdkError::OrganizationMigrating {
                    source_region: Region::US_EAST_VA,
                    target_region: Region::US_WEST_OR,
                    retry_after: std::time::Duration::from_secs(60),
                },
                503,
                "OrganizationMigrating",
            ),
            (
                SdkError::UserMigrating {
                    source_region: Region::US_EAST_VA,
                    target_region: Region::US_WEST_OR,
                    retry_after: std::time::Duration::from_secs(60),
                },
                503,
                "UserMigrating",
            ),
            (SdkError::Config { message: "bad config".into() }, 500, "Config"),
            (SdkError::Shutdown, 500, "Shutdown"),
            (SdkError::Cancelled, 500, "Cancelled"),
            (
                SdkError::Idempotency {
                    message: "conflict".into(),
                    conflict_key: None,
                    original_tx_id: None,
                },
                500,
                "Idempotency",
            ),
            (
                SdkError::AlreadyCommitted { tx_id: "tx-1".into(), block_height: 42 },
                500,
                "AlreadyCommitted",
            ),
            (SdkError::StreamDisconnected { message: "gone".into() }, 503, "StreamDisconnected"),
            (
                SdkError::InvalidUrl { url: "not-a-url".into(), message: "bad scheme".into() },
                500,
                "InvalidUrl",
            ),
            (SdkError::ProofVerification { reason: "hash mismatch" }, 500, "ProofVerification"),
        ];

        for (sdk_err, expected_status, label) in cases {
            let err = sdk_error_to_control(sdk_err);

            assert_eq!(
                err.status_code(),
                expected_status,
                "{label} should map to HTTP {expected_status}"
            );
        }
    }

    #[test]
    fn test_sdk_error_to_control_transport_error_maps_to_503() {
        let Err(transport_err) = tonic::transport::Endpoint::from_shared(vec![0xFF]) else {
            panic!("expected Endpoint::from_shared to fail on invalid UTF-8");
        };

        let err = sdk_error_to_control(SdkError::Transport { source: transport_err });

        assert_eq!(err.status_code(), 503);
    }

    // ── SdkResultExt ──────────────────────────────────────────────────

    #[test]
    fn test_map_sdk_err_ok_value_passes_through() {
        let result: Result<i32, SdkError> = Ok(42);

        let mapped = result.map_sdk_err();

        assert_eq!(mapped.unwrap(), 42);
    }

    #[test]
    fn test_map_sdk_err_error_converts_to_control_error() {
        let result: Result<i32, SdkError> = Err(SdkError::Validation { message: "bad".into() });

        let mapped = result.map_sdk_err();

        assert_eq!(mapped.unwrap_err().status_code(), 400);
    }

    // ── sdk_error_status_label: RPC codes ─────────────────────────────

    #[test]
    fn test_status_label_rpc_codes_return_expected_labels() {
        let cases: Vec<(Code, &str)> = vec![
            (Code::NotFound, "NOT_FOUND"),
            (Code::AlreadyExists, "ALREADY_EXISTS"),
            (Code::InvalidArgument, "INVALID_ARGUMENT"),
            (Code::FailedPrecondition, "FAILED_PRECONDITION"),
            (Code::PermissionDenied, "PERMISSION_DENIED"),
            (Code::Unauthenticated, "UNAUTHENTICATED"),
            (Code::ResourceExhausted, "RESOURCE_EXHAUSTED"),
            (Code::Unavailable, "UNAVAILABLE"),
            (Code::DeadlineExceeded, "DEADLINE_EXCEEDED"),
            (Code::Internal, "INTERNAL"),
            (Code::OutOfRange, "UNKNOWN"),
        ];

        for (code, expected_label) in cases {
            assert_eq!(
                sdk_error_status_label(&rpc(code)),
                expected_label,
                "RPC code {code:?} should produce label {expected_label}"
            );
        }
    }

    // ── sdk_error_status_label: non-RPC variants ──────────────────────

    #[test]
    fn test_status_label_non_rpc_variants_return_expected_labels() {
        let cases: Vec<(SdkError, &str)> = vec![
            (SdkError::Connection { message: "err".into() }, "CONNECTION_ERROR"),
            (SdkError::Timeout { duration_ms: 1000 }, "TIMEOUT"),
            (SdkError::Unavailable { message: "down".into() }, "UNAVAILABLE"),
            (
                SdkError::RetryExhausted {
                    attempts: 3,
                    last_error: "fail".into(),
                    attempt_history: vec![],
                },
                "RETRY_EXHAUSTED",
            ),
            (
                SdkError::CircuitOpen {
                    endpoint: "host".into(),
                    retry_after: std::time::Duration::from_secs(5),
                },
                "CIRCUIT_OPEN",
            ),
            (
                SdkError::RateLimited {
                    message: "slow".into(),
                    retry_after: std::time::Duration::from_secs(1),
                    request_id: None,
                    trace_id: None,
                    error_details: None,
                },
                "RATE_LIMITED",
            ),
            (SdkError::Validation { message: "bad".into() }, "VALIDATION"),
            (SdkError::Shutdown, "OTHER"),
            (SdkError::Cancelled, "OTHER"),
            (SdkError::Config { message: "x".into() }, "OTHER"),
        ];

        for (sdk_err, expected_label) in cases {
            assert_eq!(
                sdk_error_status_label(&sdk_err),
                expected_label,
                "{sdk_err:?} should produce label {expected_label}"
            );
        }
    }
}
