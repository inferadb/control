use std::sync::Arc;

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use inferadb_control_const::auth::{SESSION_COOKIE_MAX_AGE, SESSION_COOKIE_NAME};
use inferadb_control_core::{
    IdGenerator, RepositoryContext, UserPasswordResetToken, error::Error as CoreError,
    hash_password, verify_password,
};
use inferadb_control_engine_client::EngineClient;
use inferadb_control_storage::Backend;
use inferadb_control_types::{
    dto::{
        AuthVerifyEmailRequest, AuthVerifyEmailResponse, ErrorResponse, LoginRequest,
        LoginResponse, LogoutResponse, PasswordResetConfirmRequest, PasswordResetConfirmResponse,
        PasswordResetRequestRequest, PasswordResetRequestResponse, RegisterRequest,
        RegisterResponse,
    },
    entities::{
        Organization, OrganizationMember, OrganizationRole, OrganizationTier, SessionType, User,
        UserEmail, UserEmailVerificationToken, UserSession,
    },
};
use time;

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<Backend>,
    pub config: Arc<inferadb_control_core::ControlConfig>,
    pub engine_client: Arc<EngineClient>,
    pub worker_id: u16,
    pub start_time: std::time::SystemTime,
    pub leader: Option<Arc<inferadb_control_core::LeaderElection<Backend>>>,
    pub email_service: Option<Arc<inferadb_control_core::EmailService>>,
    pub control_identity: Option<Arc<inferadb_control_types::ControlIdentity>>,
}

/// Builder for AppState to avoid too many function parameters
pub struct AppStateBuilder {
    storage: Arc<Backend>,
    config: Arc<inferadb_control_core::ControlConfig>,
    engine_client: Arc<EngineClient>,
    worker_id: u16,
    leader: Option<Arc<inferadb_control_core::LeaderElection<Backend>>>,
    email_service: Option<Arc<inferadb_control_core::EmailService>>,
    control_identity: Option<Arc<inferadb_control_types::ControlIdentity>>,
}

impl AppStateBuilder {
    /// Create a new AppStateBuilder with required parameters
    pub fn new(
        storage: Arc<Backend>,
        config: Arc<inferadb_control_core::ControlConfig>,
        engine_client: Arc<EngineClient>,
        worker_id: u16,
    ) -> Self {
        Self {
            storage,
            config,
            engine_client,
            worker_id,
            leader: None,
            email_service: None,
            control_identity: None,
        }
    }

    /// Set leader election component (optional)
    pub fn leader(mut self, leader: Arc<inferadb_control_core::LeaderElection<Backend>>) -> Self {
        self.leader = Some(leader);
        self
    }

    /// Set email service (optional)
    pub fn email_service(
        mut self,
        email_service: Arc<inferadb_control_core::EmailService>,
    ) -> Self {
        self.email_service = Some(email_service);
        self
    }

    /// Set control identity (optional)
    pub fn control_identity(
        mut self,
        control_identity: Arc<inferadb_control_types::ControlIdentity>,
    ) -> Self {
        self.control_identity = Some(control_identity);
        self
    }

    /// Build the AppState
    pub fn build(self) -> AppState {
        AppState {
            storage: self.storage,
            config: self.config,
            engine_client: self.engine_client,
            worker_id: self.worker_id,
            start_time: std::time::SystemTime::now(),
            leader: self.leader,
            email_service: self.email_service,
            control_identity: self.control_identity,
        }
    }
}

impl AppState {
    /// Create AppState using the builder pattern
    ///
    /// # Example
    ///
    /// ```ignore
    /// let state = AppState::builder(storage, config, engine_client, worker_id)
    ///     .email_service(email_service)
    ///     .build();
    /// ```
    pub fn builder(
        storage: Arc<Backend>,
        config: Arc<inferadb_control_core::ControlConfig>,
        engine_client: Arc<EngineClient>,
        worker_id: u16,
    ) -> AppStateBuilder {
        AppStateBuilder::new(storage, config, engine_client, worker_id)
    }

    /// Create AppState for testing with default configuration
    /// This is used by both unit tests and integration tests
    #[allow(clippy::field_reassign_with_default)]
    pub fn new_test(storage: Arc<Backend>) -> Self {
        use inferadb_control_core::ControlConfig;

        // Create a minimal test config using default and overriding necessary fields
        let mut config = ControlConfig::default();
        // Use a temporary key file for tests - MasterKey will auto-generate it
        config.key_file = Some("/tmp/test-master.key".to_string());
        config.webauthn.party = "localhost".to_string();
        config.webauthn.origin = "http://localhost:3000".to_string();
        let engine_client = EngineClient::new("http://localhost".to_string(), 8080).unwrap();

        // Create mock email service for testing
        let email_sender = Box::new(inferadb_control_core::MockEmailSender::new());
        let email_service = inferadb_control_core::EmailService::new(email_sender);

        Self {
            storage,
            config: Arc::new(config),
            engine_client: Arc::new(engine_client),
            worker_id: 0,
            start_time: std::time::SystemTime::now(),
            leader: None,
            email_service: Some(Arc::new(email_service)),
            control_identity: None,
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
            CoreError::TooManyPasskeys { max } => {
                (StatusCode::BAD_REQUEST, format!("Too many passkeys registered (maximum: {max})"))
            },
            CoreError::External(msg) => (StatusCode::BAD_GATEWAY, msg),
            CoreError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            CoreError::Other(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
        };

        // Log errors at appropriate levels
        if status.is_server_error() {
            tracing::error!(status = %status, error = %error_message, "API error");
        } else if status.is_client_error() && status != StatusCode::NOT_FOUND {
            tracing::warn!(status = %status, error = %error_message, "Client error");
        }

        (status, Json(ErrorResponse { error: error_message, details: None })).into_response()
    }
}

pub type Result<T> = std::result::Result<T, ApiError>;

/// Register a new user
///
/// POST /v1/auth/register
///
/// Creates a new user account with email and password, and returns a session cookie.
#[axum::debug_handler]
#[tracing::instrument(skip(state, jar, payload), fields(email = %payload.email, name = %payload.name))]
pub async fn register(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<RegisterRequest>,
) -> Result<(CookieJar, Json<RegisterResponse>)> {
    // Initialize repository context
    let repos = RepositoryContext::new((*state.storage).clone());

    // Validate inputs
    if payload.name.trim().is_empty() {
        return Err(CoreError::Validation("Name cannot be empty".to_string()).into());
    }

    if payload.email.trim().is_empty() {
        return Err(CoreError::Validation("Email cannot be empty".to_string()).into());
    }

    // Check if email is already in use
    if repos.user_email.is_email_in_use(&payload.email).await? {
        return Err(
            CoreError::Validation(format!("Email '{}' is already in use", payload.email)).into()
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
    repos.user.create(user).await?;

    // Create email (unverified)
    let email = UserEmail::new(email_id, user_id, payload.email.clone(), true)?;
    repos.user_email.create(email.clone()).await?;

    // Create email verification token
    let token_id = IdGenerator::next_id();
    let token_string = UserEmailVerificationToken::generate_token();
    let verification_token = UserEmailVerificationToken::new(token_id, email_id, token_string)?;
    repos.user_email_verification_token.create(verification_token.clone()).await?;

    // Send verification email (fire-and-forget - don't block registration)
    if let Some(email_service) = &state.email_service {
        let email_addr = email.email.clone();
        let user_name = payload.name.clone();
        let token_str = verification_token.token.clone();
        let email_service = Arc::clone(email_service);
        let frontend_url = state.config.frontend.url.clone();

        // Spawn async task to send email
        tokio::spawn(async move {
            use inferadb_control_core::{EmailTemplate, VerificationEmailTemplate};

            let verification_link = format!("{frontend_url}/verify-email?token={token_str}");

            let template = VerificationEmailTemplate {
                user_name,
                verification_link,
                verification_code: token_str,
            };

            if let Err(e) = email_service
                .send_email(
                    &email_addr,
                    &template.subject(),
                    &template.html_body(),
                    &template.text_body(),
                )
                .await
            {
                tracing::error!(
                    error = %e,
                    email = %email_addr,
                    "Failed to send verification email"
                );
            }
        });
    }

    // Create session
    let session = UserSession::new(session_id, user_id, SessionType::Web, None, None);
    repos.user_session.create(session).await?;

    // Create default organization with same name as user
    let org_id = IdGenerator::next_id();
    let member_id = IdGenerator::next_id();

    let organization =
        Organization::new(org_id, payload.name.clone(), OrganizationTier::TierDevV1)?;
    repos.org.create(organization).await?;

    // Create organization member (owner role)
    let member = OrganizationMember::new(member_id, org_id, user_id, OrganizationRole::Owner);
    repos.org_member.create(member).await?;

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
            default_organization_id: org_id,
        }),
    ))
}

/// Login with email and password
///
/// POST /v1/auth/login/password
///
/// Authenticates a user with email and password, and returns a session cookie.
#[tracing::instrument(skip(state, jar, payload), fields(email = %payload.email))]
pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<LoginRequest>,
) -> Result<(CookieJar, Json<LoginResponse>)> {
    let repos = RepositoryContext::new((*state.storage).clone());

    // Find user by email
    let email = repos
        .user_email
        .get_by_email(&payload.email)
        .await?
        .ok_or_else(|| CoreError::Auth("Invalid email or password".to_string()))?;

    // Get user
    let user = repos
        .user
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
    repos.user_session.create(session).await?;

    // Set session cookie
    let cookie = Cookie::build((SESSION_COOKIE_NAME, session_id.to_string()))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::seconds(SESSION_COOKIE_MAX_AGE))
        .build();

    let jar = jar.add(cookie);

    Ok((jar, Json(LoginResponse { user_id: user.id, name: user.name, session_id })))
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
    if let Some(cookie) = jar.get(SESSION_COOKIE_NAME)
        && let Ok(session_id) = cookie.value().parse::<i64>()
    {
        let repos = RepositoryContext::new((*state.storage).clone());
        // Revoke session
        // Ignore errors if session doesn't exist
        let _ = repos.user_session.revoke(session_id).await;
    }

    // Remove session cookie
    let jar = jar.remove(Cookie::from(SESSION_COOKIE_NAME));

    Ok((jar, Json(LogoutResponse { message: "Logged out successfully".to_string() })))
}

/// Verify email address with token
///
/// POST /v1/auth/verify-email
///
/// Verifies an email address using the token sent via email
pub async fn verify_email(
    State(state): State<AppState>,
    Json(payload): Json<AuthVerifyEmailRequest>,
) -> Result<Json<AuthVerifyEmailResponse>> {
    let repos = RepositoryContext::new((*state.storage).clone());

    // Get token
    let mut token =
        repos.user_email_verification_token.get_by_token(&payload.token).await?.ok_or_else(
            || CoreError::Validation("Invalid or expired verification token".to_string()),
        )?;

    // Check if token is valid (not expired and not used)
    if !token.is_valid() {
        return Err(
            CoreError::Validation("Invalid or expired verification token".to_string()).into()
        );
    }

    // Get the email
    let mut email = repos
        .user_email
        .get(token.user_email_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Email not found".to_string()))?;

    // Check if already verified
    if email.is_verified() {
        return Ok(Json(AuthVerifyEmailResponse {
            message: "Email already verified".to_string(),
            email: email.email,
        }));
    }

    // Mark email as verified
    email.verify();
    repos.user_email.update(email.clone()).await?;

    // Mark token as used
    token.mark_used();
    repos.user_email_verification_token.update(token).await?;

    Ok(Json(AuthVerifyEmailResponse {
        message: "Email verified successfully".to_string(),
        email: email.email,
    }))
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
    let repos = RepositoryContext::new((*state.storage).clone());

    // Find the email
    let email = repos.user_email.get_by_email(&payload.email).await?.ok_or_else(|| {
        // Don't reveal whether email exists for security
        CoreError::Validation("If the email exists, a reset link will be sent".to_string())
    })?;

    // Verify the email is verified and primary
    if !email.is_verified() {
        return Err(
            CoreError::Validation("Email must be verified to reset password".to_string()).into()
        );
    }

    // Get the user to ensure they exist and aren't deleted
    let user = repos
        .user
        .get(email.user_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("User not found".to_string()))?;

    if user.is_deleted() {
        return Err(CoreError::Validation("User account is deleted".to_string()).into());
    }

    // Generate password reset token
    let token_id = IdGenerator::next_id();
    let token_string = UserPasswordResetToken::generate_token();
    let reset_token = UserPasswordResetToken::new(token_id, user.id, token_string.clone())?;

    // Store the token
    repos.user_password_reset_token.create(reset_token).await?;

    // Send password reset email (fire-and-forget - don't block request)
    if let Some(email_service) = &state.email_service {
        let email_addr = email.email.clone();
        let user_name = user.name.clone();
        let token_for_email = token_string.clone();
        let email_service = Arc::clone(email_service);
        let frontend_url = state.config.frontend.url.clone();

        // Spawn async task to send email
        tokio::spawn(async move {
            use inferadb_control_core::{EmailTemplate, PasswordResetEmailTemplate};

            let reset_link = format!("{frontend_url}/reset-password?token={token_for_email}");

            let template =
                PasswordResetEmailTemplate { user_name, reset_link, reset_code: token_for_email };

            if let Err(e) = email_service
                .send_email(
                    &email_addr,
                    &template.subject(),
                    &template.html_body(),
                    &template.text_body(),
                )
                .await
            {
                tracing::error!(
                    error = %e,
                    email = %email_addr,
                    "Failed to send password reset email"
                );
            }
        });
    }

    Ok(Json(PasswordResetRequestResponse {
        message: "If the email exists, a reset link has been sent".to_string(),
    }))
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

    let repos = RepositoryContext::new((*state.storage).clone());

    // Get token
    let mut token = repos
        .user_password_reset_token
        .get_by_token(&payload.token)
        .await?
        .ok_or_else(|| CoreError::Validation("Invalid or expired reset token".to_string()))?;

    // Check if token is valid (not expired and not used)
    if !token.is_valid() {
        return Err(CoreError::Validation("Invalid or expired reset token".to_string()).into());
    }

    // Get the user
    let mut user = repos
        .user
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
    repos.user.update(user).await?;

    // Mark token as used
    let user_id = token.user_id;
    token.mark_used();
    repos.user_password_reset_token.update(token).await?;

    // Invalidate all user sessions for security
    repos.user_session.revoke_user_sessions(user_id).await?;
    tracing::info!("Password reset successfully for user {} - all sessions revoked", user_id);

    Ok(Json(PasswordResetConfirmResponse { message: "Password reset successfully".to_string() }))
}

#[cfg(test)]
mod tests {
    use tower::ServiceExt;

    use super::*;

    fn create_test_app() -> axum::Router {
        // Initialize ID generator
        let _ = IdGenerator::init(1);

        let storage = Arc::new(Backend::memory());
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

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
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
        let storage = Arc::new(Backend::memory());
        let state = AppState::new_test(storage.clone());

        let app = axum::Router::new()
            .route("/register", axum::routing::post(register))
            .route("/password-reset-request", axum::routing::post(request_password_reset))
            .route("/password-reset-confirm", axum::routing::post(confirm_password_reset))
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
        let repos = RepositoryContext::new((*storage).clone());
        let mut email = repos.user_email.get_by_email("alice@example.com").await.unwrap().unwrap();
        let user_id = email.user_id;
        email.verify();
        repos.user_email.update(email).await.unwrap();

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
        let tokens = repos.user_password_reset_token.get_by_user(user_id).await.unwrap();
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
        let storage = Arc::new(Backend::memory());
        let state = AppState::new_test(storage);

        let app = axum::Router::new()
            .route("/password-reset-confirm", axum::routing::post(confirm_password_reset))
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

    #[tokio::test]
    async fn test_password_reset_revokes_all_sessions() {
        let _ = IdGenerator::init(1);
        let storage = Arc::new(Backend::memory());
        let state = AppState::new_test(storage.clone());

        let app = axum::Router::new()
            .route("/register", axum::routing::post(register))
            .route("/password-reset-request", axum::routing::post(request_password_reset))
            .route("/password-reset-confirm", axum::routing::post(confirm_password_reset))
            .with_state(state.clone());

        // Register user (creates first session)
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

        // Manually verify the email
        let repos = RepositoryContext::new((*storage).clone());
        let mut email = repos.user_email.get_by_email("alice@example.com").await.unwrap().unwrap();
        let user_id = email.user_id;
        email.verify();
        repos.user_email.update(email).await.unwrap();

        // Create additional sessions to verify they all get revoked
        let session2 =
            UserSession::new(IdGenerator::next_id(), user_id, SessionType::Cli, None, None);
        let session3 =
            UserSession::new(IdGenerator::next_id(), user_id, SessionType::Sdk, None, None);
        repos.user_session.create(session2.clone()).await.unwrap();
        repos.user_session.create(session3.clone()).await.unwrap();

        // Verify we have 3 active sessions (1 from registration + 2 created)
        let sessions_before = repos.user_session.get_user_sessions(user_id).await.unwrap();
        let active_before: Vec<_> = sessions_before.iter().filter(|s| s.is_active()).collect();
        assert_eq!(active_before.len(), 3, "Should have 3 active sessions before password reset");

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

        app.clone().oneshot(reset_request).await.unwrap();

        // Get the reset token
        let tokens = repos.user_password_reset_token.get_by_user(user_id).await.unwrap();
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

        let response = app.oneshot(confirm_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Verify ALL sessions are now revoked
        let sessions_after = repos.user_session.get_user_sessions(user_id).await.unwrap();
        let active_after: Vec<_> = sessions_after.iter().filter(|s| s.is_active()).collect();
        assert_eq!(active_after.len(), 0, "All sessions should be revoked after password reset");

        // Verify all sessions have deleted_at set
        for session in sessions_after {
            assert!(
                session.deleted_at.is_some(),
                "Session {} should have deleted_at set",
                session.id
            );
        }
    }
}
