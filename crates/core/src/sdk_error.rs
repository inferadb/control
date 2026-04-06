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
    fn map_sdk_err(self) -> inferadb_control_types::error::Result<T>;

    /// Maps the error and records gRPC request metrics (duration and status).
    ///
    /// Records `grpc_request_duration_seconds` and logs failures with the
    /// Ledger method name. Prefer this over [`map_sdk_err`](Self::map_sdk_err)
    /// in handler functions.
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

    #[test]
    fn rpc_not_found_maps_to_404() {
        let err = sdk_error_to_control(rpc(Code::NotFound));
        assert_eq!(err.status_code(), 404);
    }

    #[test]
    fn rpc_already_exists_maps_to_409() {
        let err = sdk_error_to_control(rpc(Code::AlreadyExists));
        assert_eq!(err.status_code(), 409);
    }

    #[test]
    fn rpc_invalid_argument_maps_to_400() {
        let err = sdk_error_to_control(rpc(Code::InvalidArgument));
        assert_eq!(err.status_code(), 400);
    }

    #[test]
    fn rpc_failed_precondition_maps_to_400() {
        let err = sdk_error_to_control(rpc(Code::FailedPrecondition));
        assert_eq!(err.status_code(), 400);
    }

    #[test]
    fn rpc_permission_denied_maps_to_403() {
        let err = sdk_error_to_control(rpc(Code::PermissionDenied));
        assert_eq!(err.status_code(), 403);
    }

    #[test]
    fn rpc_unauthenticated_maps_to_401() {
        let err = sdk_error_to_control(rpc(Code::Unauthenticated));
        assert_eq!(err.status_code(), 401);
    }

    #[test]
    fn rpc_resource_exhausted_maps_to_402() {
        let err = sdk_error_to_control(rpc(Code::ResourceExhausted));
        assert_eq!(err.status_code(), 402);
    }

    #[test]
    fn rpc_unavailable_maps_to_503() {
        let err = sdk_error_to_control(rpc(Code::Unavailable));
        assert_eq!(err.status_code(), 503);
    }

    #[test]
    fn rpc_deadline_exceeded_maps_to_503() {
        let err = sdk_error_to_control(rpc(Code::DeadlineExceeded));
        assert_eq!(err.status_code(), 503);
    }

    #[test]
    fn rpc_internal_maps_to_500() {
        let err = sdk_error_to_control(rpc(Code::Internal));
        assert_eq!(err.status_code(), 500);
    }

    #[test]
    fn rpc_aborted_maps_to_503() {
        let err = sdk_error_to_control(rpc(Code::Aborted));
        assert_eq!(err.status_code(), 503);
    }

    #[test]
    fn rpc_unimplemented_maps_to_500() {
        let err = sdk_error_to_control(rpc(Code::Unimplemented));
        assert_eq!(err.status_code(), 500);
    }

    #[test]
    fn rpc_data_loss_maps_to_500() {
        let err = sdk_error_to_control(rpc(Code::DataLoss));
        assert_eq!(err.status_code(), 500);
    }

    #[test]
    fn rate_limited_maps_to_429() {
        let err = sdk_error_to_control(SdkError::RateLimited {
            message: "slow down".into(),
            retry_after: std::time::Duration::from_secs(1),
            request_id: None,
            trace_id: None,
            error_details: None,
        });
        assert_eq!(err.status_code(), 429);
    }

    #[test]
    fn validation_maps_to_400() {
        let err = sdk_error_to_control(SdkError::Validation { message: "bad input".into() });
        assert_eq!(err.status_code(), 400);
    }

    #[test]
    fn connection_maps_to_503() {
        let err = sdk_error_to_control(SdkError::Connection { message: "refused".into() });
        assert_eq!(err.status_code(), 503);
    }

    #[test]
    fn transport_maps_to_503() {
        let Err(transport_err) = tonic::transport::Endpoint::from_shared(vec![0xFF]) else {
            panic!("expected Endpoint::from_shared to fail on invalid UTF-8");
        };
        let err = sdk_error_to_control(SdkError::Transport { source: transport_err });
        assert_eq!(err.status_code(), 503);
    }

    #[test]
    fn timeout_maps_to_503() {
        let err = sdk_error_to_control(SdkError::Timeout { duration_ms: 5000 });
        assert_eq!(err.status_code(), 503);
    }

    #[test]
    fn unavailable_maps_to_503() {
        let err = sdk_error_to_control(SdkError::Unavailable { message: "down".into() });
        assert_eq!(err.status_code(), 503);
    }

    #[test]
    fn retry_exhausted_maps_to_503() {
        let err = sdk_error_to_control(SdkError::RetryExhausted {
            attempts: 3,
            last_error: "failed".into(),
            attempt_history: vec![(1, "err1".into()), (2, "err2".into())],
        });
        assert_eq!(err.status_code(), 503);
    }

    #[test]
    fn circuit_open_maps_to_503() {
        let err = sdk_error_to_control(SdkError::CircuitOpen {
            endpoint: "localhost:50051".into(),
            retry_after: std::time::Duration::from_secs(30),
        });
        assert_eq!(err.status_code(), 503);
    }

    #[test]
    fn organization_migrating_maps_to_503() {
        let err = sdk_error_to_control(SdkError::OrganizationMigrating {
            source_region: Region::US_EAST_VA,
            target_region: Region::US_WEST_OR,
            retry_after: std::time::Duration::from_secs(60),
        });
        assert_eq!(err.status_code(), 503);
    }

    #[test]
    fn user_migrating_maps_to_503() {
        let err = sdk_error_to_control(SdkError::UserMigrating {
            source_region: Region::US_EAST_VA,
            target_region: Region::US_WEST_OR,
            retry_after: std::time::Duration::from_secs(60),
        });
        assert_eq!(err.status_code(), 503);
    }

    #[test]
    fn config_maps_to_500() {
        let err = sdk_error_to_control(SdkError::Config { message: "bad config".into() });
        assert_eq!(err.status_code(), 500);
    }

    #[test]
    fn shutdown_maps_to_500() {
        let err = sdk_error_to_control(SdkError::Shutdown);
        assert_eq!(err.status_code(), 500);
    }

    #[test]
    fn cancelled_maps_to_500() {
        let err = sdk_error_to_control(SdkError::Cancelled);
        assert_eq!(err.status_code(), 500);
    }

    #[test]
    fn idempotency_maps_to_500() {
        let err = sdk_error_to_control(SdkError::Idempotency {
            message: "conflict".into(),
            conflict_key: None,
            original_tx_id: None,
        });
        assert_eq!(err.status_code(), 500);
    }

    #[test]
    fn already_committed_maps_to_500() {
        let err = sdk_error_to_control(SdkError::AlreadyCommitted {
            tx_id: "tx-1".into(),
            block_height: 42,
        });
        assert_eq!(err.status_code(), 500);
    }

    #[test]
    fn stream_disconnected_maps_to_503() {
        let err = sdk_error_to_control(SdkError::StreamDisconnected { message: "gone".into() });
        assert_eq!(err.status_code(), 503);
    }

    #[test]
    fn invalid_url_maps_to_500() {
        let err = sdk_error_to_control(SdkError::InvalidUrl {
            url: "not-a-url".into(),
            message: "bad scheme".into(),
        });
        assert_eq!(err.status_code(), 500);
    }

    #[test]
    fn proof_verification_maps_to_500() {
        let err = sdk_error_to_control(SdkError::ProofVerification { reason: "hash mismatch" });
        assert_eq!(err.status_code(), 500);
    }

    #[test]
    fn map_sdk_err_preserves_ok() {
        let result: Result<i32, SdkError> = Ok(42);
        let mapped = result.map_sdk_err();
        assert!(matches!(mapped, Ok(42)));
    }

    #[test]
    fn map_sdk_err_converts_err() {
        let result: Result<i32, SdkError> = Err(SdkError::Validation { message: "bad".into() });
        let mapped = result.map_sdk_err();
        let Err(err) = mapped else {
            panic!("expected Err variant");
        };
        assert_eq!(err.status_code(), 400);
    }

    #[test]
    fn status_label_rpc_not_found() {
        assert_eq!(sdk_error_status_label(&rpc(Code::NotFound)), "NOT_FOUND");
    }

    #[test]
    fn status_label_rpc_already_exists() {
        assert_eq!(sdk_error_status_label(&rpc(Code::AlreadyExists)), "ALREADY_EXISTS");
    }

    #[test]
    fn status_label_rpc_invalid_argument() {
        assert_eq!(sdk_error_status_label(&rpc(Code::InvalidArgument)), "INVALID_ARGUMENT");
    }

    #[test]
    fn status_label_rpc_unavailable() {
        assert_eq!(sdk_error_status_label(&rpc(Code::Unavailable)), "UNAVAILABLE");
    }

    #[test]
    fn status_label_rpc_deadline_exceeded() {
        assert_eq!(sdk_error_status_label(&rpc(Code::DeadlineExceeded)), "DEADLINE_EXCEEDED");
    }

    #[test]
    fn status_label_rpc_internal() {
        assert_eq!(sdk_error_status_label(&rpc(Code::Internal)), "INTERNAL");
    }

    #[test]
    fn status_label_rpc_unknown_code() {
        assert_eq!(sdk_error_status_label(&rpc(Code::OutOfRange)), "UNKNOWN");
    }

    #[test]
    fn status_label_connection() {
        let err = SdkError::Connection { message: "err".into() };
        assert_eq!(sdk_error_status_label(&err), "CONNECTION_ERROR");
    }

    #[test]
    fn status_label_timeout() {
        let err = SdkError::Timeout { duration_ms: 1000 };
        assert_eq!(sdk_error_status_label(&err), "TIMEOUT");
    }

    #[test]
    fn status_label_unavailable() {
        let err = SdkError::Unavailable { message: "down".into() };
        assert_eq!(sdk_error_status_label(&err), "UNAVAILABLE");
    }

    #[test]
    fn status_label_retry_exhausted() {
        let err = SdkError::RetryExhausted {
            attempts: 3,
            last_error: "fail".into(),
            attempt_history: vec![],
        };
        assert_eq!(sdk_error_status_label(&err), "RETRY_EXHAUSTED");
    }

    #[test]
    fn status_label_circuit_open() {
        let err = SdkError::CircuitOpen {
            endpoint: "host".into(),
            retry_after: std::time::Duration::from_secs(5),
        };
        assert_eq!(sdk_error_status_label(&err), "CIRCUIT_OPEN");
    }

    #[test]
    fn status_label_rate_limited() {
        let err = SdkError::RateLimited {
            message: "slow".into(),
            retry_after: std::time::Duration::from_secs(1),
            request_id: None,
            trace_id: None,
            error_details: None,
        };
        assert_eq!(sdk_error_status_label(&err), "RATE_LIMITED");
    }

    #[test]
    fn status_label_validation() {
        let err = SdkError::Validation { message: "bad".into() };
        assert_eq!(sdk_error_status_label(&err), "VALIDATION");
    }

    #[test]
    fn status_label_other_variants() {
        assert_eq!(sdk_error_status_label(&SdkError::Shutdown), "OTHER");
        assert_eq!(sdk_error_status_label(&SdkError::Cancelled), "OTHER");
        assert_eq!(sdk_error_status_label(&SdkError::Config { message: "x".into() }), "OTHER");
    }
}
