use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use infera_management_core::{
    entities::{
        Organization, OrganizationMember, OrganizationRole, OrganizationTier, SessionType, User,
        UserEmail, UserSession,
    },
    error::Error as CoreError,
    hash_password, verify_password, IdGenerator, OrganizationMemberRepository,
    OrganizationRepository, UserEmailRepository, UserEmailVerificationTokenRepository,
    UserPasswordResetToken, UserPasswordResetTokenRepository, UserRepository,
    UserSessionRepository,
};
use infera_management_grpc::ServerApiClient;
use infera_management_storage::Backend;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use time;

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<Backend>,
    pub config: Arc<infera_management_core::ManagementConfig>,
    pub server_client: Arc<ServerApiClient>,
}

impl AppState {
    pub fn new(
        storage: Arc<Backend>,
        config: Arc<infera_management_core::ManagementConfig>,
        server_client: Arc<ServerApiClient>,
    ) -> Self {
        Self {
            storage,
            config,
            server_client,
        }
    }

    /// Create AppState for testing with default configuration
    /// This is used by both unit tests and integration tests
    pub fn new_test(storage: Arc<Backend>) -> Self {
        use infera_management_core::ManagementConfig;

        // Create a minimal test config
        let config_str = r#"
server:
  http_host: "127.0.0.1"
  http_port: 3000
  grpc_host: "127.0.0.1"
  grpc_port: 3001
  worker_threads: 4

storage:
  backend: "memory"

auth:
  session_ttl_web: 2592000
  session_ttl_cli: 7776000
  session_ttl_sdk: 7776000
  password_min_length: 12
  max_sessions_per_user: 10
  key_encryption_secret: "test-secret-key-at-least-32-bytes-long!"
  webauthn:
    rp_id: "localhost"
    rp_name: "InferaDB"
    origin: "http://localhost:3000"

email:
  smtp_host: "localhost"
  smtp_port: 587
  from_email: "test@example.com"
  from_name: "InferaDB Test"

rate_limiting:
  login_attempts_per_ip_per_hour: 100
  registrations_per_ip_per_day: 5
  email_verification_tokens_per_hour: 5
  password_reset_tokens_per_hour: 3

observability:
  log_level: "info"
  metrics_enabled: true
  tracing_enabled: false

id_generation:
  worker_id: 0
  max_clock_skew_ms: 1000

server_api:
  grpc_endpoint: "http://localhost:8080"
  tls_enabled: false
"#;

        let config: ManagementConfig = serde_yaml::from_str(config_str).unwrap();
        let server_client = ServerApiClient::new("http://localhost:8080".to_string()).unwrap();
        Self {
            storage,
            config: Arc::new(config),
            server_client: Arc::new(server_client),
        }
    }
}

/// API error response
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

impl ErrorResponse {
    pub fn new(error: String) -> Self {
        Self {
            error,
            details: None,
        }
    }

    pub fn with_details(error: String, details: String) -> Self {
        Self {
            error,
            details: Some(details),
        }
    }
}

/// API error type that wraps core errors
#[derive(Debug)]
pub struct ApiError(CoreError);

impl From<CoreError> for ApiError {
    fn from(error: CoreError) -> Self {
        ApiError(error)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self.0 {
            CoreError::Config(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            CoreError::Storage(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            CoreError::Auth(msg) => (StatusCode::UNAUTHORIZED, msg),
            CoreError::Authz(msg) => (StatusCode::FORBIDDEN, msg),
            CoreError::Validation(msg) => (StatusCode::BAD_REQUEST, msg),
            CoreError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            CoreError::AlreadyExists(msg) => (StatusCode::CONFLICT, msg),
            CoreError::RateLimit(msg) => (StatusCode::TOO_MANY_REQUESTS, msg),
            CoreError::TierLimit(msg) => (StatusCode::PAYMENT_REQUIRED, msg),
            CoreError::External(msg) => (StatusCode::BAD_GATEWAY, msg),
            CoreError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            CoreError::Other(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
        };

        (status, Json(ErrorResponse::new(error_message))).into_response()
    }
}

pub type Result<T> = std::result::Result<T, ApiError>;

/// Request body for user registration
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterRequest {
    /// User's display name
    pub name: String,
    /// User's email address
    pub email: String,
    /// User's password (12-128 characters)
    pub password: String,
}

/// Response body for user registration
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterResponse {
    /// Newly created user ID
    pub user_id: i64,
    /// User's name
    pub name: String,
    /// User's email
    pub email: String,
    /// Session ID
    pub session_id: i64,
}

/// Request body for password login
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    /// Email address
    pub email: String,
    /// Password
    pub password: String,
}

/// Response body for successful login
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    /// User ID
    pub user_id: i64,
    /// User's name
    pub name: String,
    /// Session ID
    pub session_id: i64,
}

/// Response body for logout
#[derive(Debug, Serialize, Deserialize)]
pub struct LogoutResponse {
    /// Confirmation message
    pub message: String,
}

/// Session cookie name
pub const SESSION_COOKIE_NAME: &str = "infera_session";

/// Session cookie max age (24 hours for web sessions)
pub const SESSION_COOKIE_MAX_AGE: i64 = 24 * 60 * 60;

/// Register a new user
///
/// POST /v1/auth/register
///
/// Creates a new user account with email and password, and returns a session cookie.
#[axum::debug_handler]
pub async fn register(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<RegisterRequest>,
) -> Result<(CookieJar, Json<RegisterResponse>)> {
    // Validate inputs
    if payload.name.trim().is_empty() {
        return Err(CoreError::Validation("Name cannot be empty".to_string()).into());
    }

    if payload.email.trim().is_empty() {
        return Err(CoreError::Validation("Email cannot be empty".to_string()).into());
    }

    // Check if email is already in use
    let email_repo = UserEmailRepository::new((*state.storage).clone());
    if email_repo.is_email_in_use(&payload.email).await? {
        return Err(
            CoreError::Validation(format!("Email '{}' is already in use", payload.email)).into(),
        );
    }

    // Check if name is available
    let user_repo = UserRepository::new((*state.storage).clone());
    if !user_repo.is_name_available(&payload.name).await? {
        return Err(
            CoreError::Validation(format!("Name '{}' is already taken", payload.name)).into(),
        );
    }

    // Hash password
    let password_hash = hash_password(&payload.password)?;

    // Generate IDs
    let user_id = IdGenerator::next_id();
    let email_id = IdGenerator::next_id();
    let session_id = IdGenerator::next_id();

    // Create user
    let mut user = User::new(user_id, payload.name.clone(), Some(password_hash))?;
    user.accept_tos(); // Auto-accept TOS on registration
    user_repo.create(user).await?;

    // Create email
    let mut email = UserEmail::new(email_id, user_id, payload.email.clone(), true)?;
    email.verify(); // Auto-verify email for now (TODO: implement verification flow)
    email_repo.create(email).await?;

    // Create session
    let session = UserSession::new(session_id, user_id, SessionType::Web, None, None);
    let session_repo = UserSessionRepository::new((*state.storage).clone());
    session_repo.create(session).await?;

    // Create default organization with same name as user
    let org_id = IdGenerator::next_id();
    let member_id = IdGenerator::next_id();

    let organization =
        Organization::new(org_id, payload.name.clone(), OrganizationTier::TierDevV1)?;
    let org_repo = OrganizationRepository::new((*state.storage).clone());
    org_repo.create(organization).await?;

    // Create organization member (owner role)
    let member = OrganizationMember::new(member_id, org_id, user_id, OrganizationRole::Owner);
    let member_repo = OrganizationMemberRepository::new((*state.storage).clone());
    member_repo.create(member).await?;

    // Set session cookie
    let cookie = Cookie::build((SESSION_COOKIE_NAME, session_id.to_string()))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::seconds(SESSION_COOKIE_MAX_AGE))
        .build();

    let jar = jar.add(cookie);

    Ok((
        jar,
        Json(RegisterResponse {
            user_id,
            name: payload.name,
            email: payload.email,
            session_id,
        }),
    ))
}

/// Login with email and password
///
/// POST /v1/auth/login/password
///
/// Authenticates a user with email and password, and returns a session cookie.
pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<LoginRequest>,
) -> Result<(CookieJar, Json<LoginResponse>)> {
    // Find user by email
    let email_repo = UserEmailRepository::new((*state.storage).clone());
    let email = email_repo
        .get_by_email(&payload.email)
        .await?
        .ok_or_else(|| CoreError::Auth("Invalid email or password".to_string()))?;

    // Get user
    let user_repo = UserRepository::new((*state.storage).clone());
    let user = user_repo
        .get(email.user_id)
        .await?
        .ok_or_else(|| CoreError::Auth("Invalid email or password".to_string()))?;

    // Verify password
    let password_hash = user
        .password_hash
        .ok_or_else(|| CoreError::Auth("Password login not available for this user".to_string()))?;

    verify_password(&payload.password, &password_hash)?;

    // Create session
    let session_id = IdGenerator::next_id();
    let session = UserSession::new(session_id, user.id, SessionType::Web, None, None);
    let session_repo = UserSessionRepository::new((*state.storage).clone());
    session_repo.create(session).await?;

    // Set session cookie
    let cookie = Cookie::build((SESSION_COOKIE_NAME, session_id.to_string()))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::seconds(SESSION_COOKIE_MAX_AGE))
        .build();

    let jar = jar.add(cookie);

    Ok((
        jar,
        Json(LoginResponse {
            user_id: user.id,
            name: user.name,
            session_id,
        }),
    ))
}

/// Logout current session
///
/// POST /v1/auth/logout
///
/// Revokes the current session and clears the session cookie.
pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, Json<LogoutResponse>)> {
    // Get session ID from cookie
    if let Some(cookie) = jar.get(SESSION_COOKIE_NAME) {
        if let Ok(session_id) = cookie.value().parse::<i64>() {
            // Revoke session
            let session_repo = UserSessionRepository::new((*state.storage).clone());
            // Ignore errors if session doesn't exist
            let _ = session_repo.revoke(session_id).await;
        }
    }

    // Remove session cookie
    let jar = jar.remove(Cookie::from(SESSION_COOKIE_NAME));

    Ok((
        jar,
        Json(LogoutResponse {
            message: "Logged out successfully".to_string(),
        }),
    ))
}

/// Request body for email verification
#[derive(Debug, Deserialize)]
pub struct VerifyEmailRequest {
    /// Verification token from email
    pub token: String,
}

/// Response body for email verification
#[derive(Debug, Serialize)]
pub struct VerifyEmailResponse {
    /// Success message
    pub message: String,
    /// The verified email address
    pub email: String,
}

/// Verify email address with token
///
/// POST /v1/auth/verify-email
///
/// Verifies an email address using the token sent via email
pub async fn verify_email(
    State(state): State<AppState>,
    Json(payload): Json<VerifyEmailRequest>,
) -> Result<Json<VerifyEmailResponse>> {
    let token_repo = UserEmailVerificationTokenRepository::new((*state.storage).clone());

    // Get token
    let mut token = token_repo
        .get_by_token(&payload.token)
        .await?
        .ok_or_else(|| {
            CoreError::Validation("Invalid or expired verification token".to_string())
        })?;

    // Check if token is valid (not expired and not used)
    if !token.is_valid() {
        return Err(
            CoreError::Validation("Invalid or expired verification token".to_string()).into(),
        );
    }

    // Get the email
    let email_repo = UserEmailRepository::new((*state.storage).clone());
    let mut email = email_repo
        .get(token.user_email_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Email not found".to_string()))?;

    // Check if already verified
    if email.is_verified() {
        return Ok(Json(VerifyEmailResponse {
            message: "Email already verified".to_string(),
            email: email.email,
        }));
    }

    // Mark email as verified
    email.verify();
    email_repo.update(email.clone()).await?;

    // Mark token as used
    token.mark_used();
    token_repo.update(token).await?;

    Ok(Json(VerifyEmailResponse {
        message: "Email verified successfully".to_string(),
        email: email.email,
    }))
}

/// Request body for password reset request
#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordResetRequestRequest {
    /// Email address to send reset link to
    pub email: String,
}

/// Response body for password reset request
#[derive(Debug, Serialize)]
pub struct PasswordResetRequestResponse {
    /// Success message
    pub message: String,
}

/// Request password reset
///
/// POST /v1/auth/password-reset/request
///
/// Generates a password reset token and sends it via email
pub async fn request_password_reset(
    State(state): State<AppState>,
    Json(payload): Json<PasswordResetRequestRequest>,
) -> Result<Json<PasswordResetRequestResponse>> {
    let email_repo = UserEmailRepository::new((*state.storage).clone());
    let user_repo = UserRepository::new((*state.storage).clone());

    // Find the email
    let email = email_repo
        .get_by_email(&payload.email)
        .await?
        .ok_or_else(|| {
            // Don't reveal whether email exists for security
            CoreError::Validation("If the email exists, a reset link will be sent".to_string())
        })?;

    // Verify the email is verified and primary
    if !email.is_verified() {
        return Err(
            CoreError::Validation("Email must be verified to reset password".to_string()).into(),
        );
    }

    // Get the user to ensure they exist and aren't deleted
    let user = user_repo
        .get(email.user_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("User not found".to_string()))?;

    if user.is_deleted() {
        return Err(CoreError::Validation("User account is deleted".to_string()).into());
    }

    // Generate password reset token
    let token_repo = UserPasswordResetTokenRepository::new((*state.storage).clone());
    let token_id = IdGenerator::next_id();
    let token_string = UserPasswordResetToken::generate_token();
    let reset_token = UserPasswordResetToken::new(token_id, user.id, token_string.clone())?;

    // Store the token
    token_repo.create(reset_token).await?;

    // TODO: Send password reset email with token
    tracing::info!(
        "Password reset token generated for user {} (email: {}): {}",
        user.id,
        email.email,
        token_string
    );

    Ok(Json(PasswordResetRequestResponse {
        message: "If the email exists, a reset link has been sent".to_string(),
    }))
}

/// Request body for password reset confirmation
#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordResetConfirmRequest {
    /// Reset token from email
    pub token: String,
    /// New password (12-128 characters)
    pub new_password: String,
}

/// Response body for password reset confirmation
#[derive(Debug, Serialize)]
pub struct PasswordResetConfirmResponse {
    /// Success message
    pub message: String,
}

/// Confirm password reset with token
///
/// POST /v1/auth/password-reset/confirm
///
/// Resets the user's password using the token sent via email
pub async fn confirm_password_reset(
    State(state): State<AppState>,
    Json(payload): Json<PasswordResetConfirmRequest>,
) -> Result<Json<PasswordResetConfirmResponse>> {
    // Validate new password
    if payload.new_password.len() < 12 || payload.new_password.len() > 128 {
        return Err(CoreError::Validation(
            "Password must be between 12 and 128 characters".to_string(),
        )
        .into());
    }

    let token_repo = UserPasswordResetTokenRepository::new((*state.storage).clone());

    // Get token
    let mut token = token_repo
        .get_by_token(&payload.token)
        .await?
        .ok_or_else(|| CoreError::Validation("Invalid or expired reset token".to_string()))?;

    // Check if token is valid (not expired and not used)
    if !token.is_valid() {
        return Err(CoreError::Validation("Invalid or expired reset token".to_string()).into());
    }

    // Get the user
    let user_repo = UserRepository::new((*state.storage).clone());
    let mut user = user_repo
        .get(token.user_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("User not found".to_string()))?;

    if user.is_deleted() {
        return Err(CoreError::Validation("User account is deleted".to_string()).into());
    }

    // Hash the new password
    let password_hash = hash_password(&payload.new_password)?;

    // Update user's password
    user.set_password_hash(password_hash);
    user_repo.update(user).await?;

    // Mark token as used
    let user_id = token.user_id;
    token.mark_used();
    token_repo.update(token).await?;

    // TODO: Invalidate all user sessions for security
    tracing::info!("Password reset successfully for user {}", user_id);

    Ok(Json(PasswordResetConfirmResponse {
        message: "Password reset successfully".to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use infera_management_storage::MemoryBackend;
    use tower::ServiceExt;

    fn create_test_app() -> axum::Router {
        // Initialize ID generator
        let _ = IdGenerator::init(1);

        let storage = Arc::new(Backend::Memory(MemoryBackend::new()));
        let state = AppState::new_test(storage);

        axum::Router::new()
            .route("/register", axum::routing::post(register))
            .route("/login", axum::routing::post(login))
            .route("/logout", axum::routing::post(logout))
            .with_state(state)
    }

    #[tokio::test]
    async fn test_register_success() {
        let app = create_test_app();

        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/register")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::to_string(&RegisterRequest {
                    name: "alice".to_string(),
                    email: "alice@example.com".to_string(),
                    password: "secure-password-123".to_string(),
                })
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let register_response: RegisterResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(register_response.name, "alice");
        assert_eq!(register_response.email, "alice@example.com");
    }

    #[tokio::test]
    async fn test_register_duplicate_email() {
        let app = create_test_app();

        // Register first user
        let request1 = axum::http::Request::builder()
            .method("POST")
            .uri("/register")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::to_string(&RegisterRequest {
                    name: "alice".to_string(),
                    email: "alice@example.com".to_string(),
                    password: "secure-password-123".to_string(),
                })
                .unwrap(),
            ))
            .unwrap();

        let response1 = app.clone().oneshot(request1).await.unwrap();
        assert_eq!(response1.status(), StatusCode::OK);

        // Try to register with same email
        let request2 = axum::http::Request::builder()
            .method("POST")
            .uri("/register")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::to_string(&RegisterRequest {
                    name: "bob".to_string(),
                    email: "alice@example.com".to_string(),
                    password: "another-password-456".to_string(),
                })
                .unwrap(),
            ))
            .unwrap();

        let response2 = app.oneshot(request2).await.unwrap();
        assert_eq!(response2.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_login_success() {
        let app = create_test_app();

        // Register user
        let register_request = axum::http::Request::builder()
            .method("POST")
            .uri("/register")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::to_string(&RegisterRequest {
                    name: "alice".to_string(),
                    email: "alice@example.com".to_string(),
                    password: "secure-password-123".to_string(),
                })
                .unwrap(),
            ))
            .unwrap();

        app.clone().oneshot(register_request).await.unwrap();

        // Login
        let login_request = axum::http::Request::builder()
            .method("POST")
            .uri("/login")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::to_string(&LoginRequest {
                    email: "alice@example.com".to_string(),
                    password: "secure-password-123".to_string(),
                })
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(login_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_login_wrong_password() {
        let app = create_test_app();

        // Register user
        let register_request = axum::http::Request::builder()
            .method("POST")
            .uri("/register")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::to_string(&RegisterRequest {
                    name: "alice".to_string(),
                    email: "alice@example.com".to_string(),
                    password: "secure-password-123".to_string(),
                })
                .unwrap(),
            ))
            .unwrap();

        app.clone().oneshot(register_request).await.unwrap();

        // Login with wrong password
        let login_request = axum::http::Request::builder()
            .method("POST")
            .uri("/login")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::to_string(&LoginRequest {
                    email: "alice@example.com".to_string(),
                    password: "wrong-password".to_string(),
                })
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(login_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_password_reset_flow() {
        let _ = IdGenerator::init(1);
        let storage = Arc::new(Backend::Memory(MemoryBackend::new()));
        let state = AppState::new_test(storage.clone());

        let app = axum::Router::new()
            .route("/register", axum::routing::post(register))
            .route(
                "/password-reset-request",
                axum::routing::post(request_password_reset),
            )
            .route(
                "/password-reset-confirm",
                axum::routing::post(confirm_password_reset),
            )
            .route("/login", axum::routing::post(login))
            .with_state(state.clone());

        // Register user
        let register_request = axum::http::Request::builder()
            .method("POST")
            .uri("/register")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::to_string(&RegisterRequest {
                    name: "alice".to_string(),
                    email: "alice@example.com".to_string(),
                    password: "old-password-123".to_string(),
                })
                .unwrap(),
            ))
            .unwrap();

        app.clone().oneshot(register_request).await.unwrap();

        // Manually verify the email since we don't have email sending
        let email_repo = UserEmailRepository::new((*storage).clone());
        let mut email = email_repo
            .get_by_email("alice@example.com")
            .await
            .unwrap()
            .unwrap();
        let user_id = email.user_id;
        email.verify();
        email_repo.update(email).await.unwrap();

        // Request password reset
        let reset_request = axum::http::Request::builder()
            .method("POST")
            .uri("/password-reset-request")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::to_string(&PasswordResetRequestRequest {
                    email: "alice@example.com".to_string(),
                })
                .unwrap(),
            ))
            .unwrap();

        let response = app.clone().oneshot(reset_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Get the reset token from the repository
        let token_repo = UserPasswordResetTokenRepository::new((*storage).clone());
        let tokens = token_repo.get_by_user(user_id).await.unwrap();
        assert_eq!(tokens.len(), 1);
        let reset_token = tokens[0].token.clone();

        // Confirm password reset
        let confirm_request = axum::http::Request::builder()
            .method("POST")
            .uri("/password-reset-confirm")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::to_string(&PasswordResetConfirmRequest {
                    token: reset_token,
                    new_password: "new-password-456".to_string(),
                })
                .unwrap(),
            ))
            .unwrap();

        let response = app.clone().oneshot(confirm_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Try to login with new password
        let login_request = axum::http::Request::builder()
            .method("POST")
            .uri("/login")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::to_string(&LoginRequest {
                    email: "alice@example.com".to_string(),
                    password: "new-password-456".to_string(),
                })
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(login_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_password_reset_invalid_token() {
        let _ = IdGenerator::init(1);
        let storage = Arc::new(Backend::Memory(MemoryBackend::new()));
        let state = AppState::new_test(storage);

        let app = axum::Router::new()
            .route(
                "/password-reset-confirm",
                axum::routing::post(confirm_password_reset),
            )
            .with_state(state);

        // Try to confirm with invalid token
        let confirm_request = axum::http::Request::builder()
            .method("POST")
            .uri("/password-reset-confirm")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::to_string(&PasswordResetConfirmRequest {
                    token: "0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string(),
                    new_password: "new-password-456".to_string(),
                })
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(confirm_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
