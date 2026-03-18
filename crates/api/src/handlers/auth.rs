//! Application state, API error handling, and shared auth infrastructure.
//!
//! Auth handlers have been moved to:
//! - `auth_v2.rs` — token refresh, logout, revoke-all
//! - `email_auth.rs` — email code auth flow (initiate, verify, complete)
//! - `mfa_auth.rs` — TOTP verify, recovery code, passkey auth

use std::sync::Arc;

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use bon::Builder;
use inferadb_control_types::{Error as CoreError, dto::ErrorResponse};

/// Application state shared across handlers
#[derive(Clone, Builder)]
#[builder(on(Arc<_>, into))]
pub struct AppState {
    pub config: Arc<inferadb_control_config::Config>,
    pub worker_id: u16,
    #[builder(default = std::time::SystemTime::now())]
    pub start_time: std::time::SystemTime,
    pub email_service: Option<Arc<inferadb_control_core::EmailService>>,
    pub control_identity: Option<Arc<inferadb_control_types::ControlIdentity>>,
    #[builder(default)]
    pub rate_limits: crate::middleware::RateLimitConfig,
    /// Ledger SDK client for direct service calls.
    pub ledger: Option<Arc<inferadb_ledger_sdk::LedgerClient>>,
    /// Email blinding key for HMAC computation.
    pub blinding_key: Option<Arc<inferadb_ledger_types::EmailBlindingKey>>,
}

impl AppState {
    /// Create AppState for testing with default configuration.
    pub fn new_test() -> Self {
        use inferadb_control_config::{Config, StorageBackend};

        let config = Config::builder()
            .storage(StorageBackend::Memory)
            .key_file(std::path::PathBuf::from("/tmp/test-master.key"))
            .build();

        let email_sender = Box::new(inferadb_control_core::MockEmailSender::new());
        let email_service = inferadb_control_core::EmailService::new(email_sender);

        Self::builder()
            .config(Arc::new(config))
            .worker_id(0)
            .email_service(Arc::new(email_service))
            .build()
    }
}

/// API error type that wraps core errors
#[derive(Debug)]
pub struct ApiError(pub CoreError);

impl From<CoreError> for ApiError {
    fn from(error: CoreError) -> Self {
        ApiError(error)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status =
            StatusCode::from_u16(self.0.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let error_message = self.0.to_string();

        if status.is_server_error() {
            tracing::error!(status = %status, error = %error_message, "API error");
        } else if status.is_client_error() && status != StatusCode::NOT_FOUND {
            tracing::warn!(status = %status, error = %error_message, "Client error");
        }

        let error_code = self.0.error_code().to_string();

        (status, Json(ErrorResponse { error: error_message, code: error_code, details: None }))
            .into_response()
    }
}

pub type Result<T> = std::result::Result<T, ApiError>;
