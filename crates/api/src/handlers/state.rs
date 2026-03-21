//! Application state and API error handling.
//!
//! [`AppState`] holds shared services (Ledger client, email, WebAuthn, rate
//! limiter) and is cloned into every axum handler via `State<AppState>`.
//! [`ApiError`] maps core domain errors to HTTP status codes and JSON responses.

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
    #[builder(default)]
    pub rate_limits: crate::middleware::RateLimitConfig,
    /// Ledger SDK client for direct service calls.
    pub ledger: Option<Arc<inferadb_ledger_sdk::LedgerClient>>,
    /// Email blinding key for HMAC computation.
    pub blinding_key: Option<Arc<inferadb_ledger_types::EmailBlindingKey>>,
    /// WebAuthn instance for passkey ceremony validation.
    pub webauthn: Option<Arc<webauthn_rs::Webauthn>>,
    /// Stateless challenge store for WebAuthn begin/finish ceremonies.
    #[builder(default)]
    pub challenge_store: inferadb_control_core::webauthn::ChallengeStore,
    /// Application-level rate limiter for auth endpoints.
    #[builder(default = Arc::new(inferadb_control_core::in_memory_rate_limiter()))]
    pub rate_limiter: Arc<inferadb_control_core::InMemoryRateLimiter>,
    /// JWKS cache for local JWT validation on read routes.
    #[builder(default)]
    pub jwks_cache: crate::middleware::JwksCache,
    /// Cached health check state (5-second TTL, lock-free).
    #[builder(default)]
    pub health_cache: Arc<super::health::HealthCache>,
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
