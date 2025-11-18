use axum::{
    extract::{Path, State},
    Extension, Json,
};
use infera_management_core::{
    entities::UserEmailVerificationToken, error::Error as CoreError, IdGenerator, UserEmail,
    UserEmailRepository, UserEmailVerificationTokenRepository,
};
use serde::{Deserialize, Serialize};

use crate::handlers::auth::{AppState, Result};
use crate::middleware::SessionContext;

/// Request body for adding a new email
#[derive(Debug, Serialize, Deserialize)]
pub struct AddEmailRequest {
    /// Email address to add
    pub email: String,
}

/// Response body for adding a new email
#[derive(Debug, Serialize, Deserialize)]
pub struct AddEmailResponse {
    /// The created email
    pub email: UserEmailInfo,
    /// Message indicating verification email was sent
    pub message: String,
}

/// Email information
#[derive(Debug, Serialize, Deserialize)]
pub struct UserEmailInfo {
    /// Email ID
    pub id: i64,
    /// Email address
    pub email: String,
    /// Whether this is the primary email
    pub is_primary: bool,
    /// Whether this email is verified
    pub is_verified: bool,
    /// When the email was created
    pub created_at: String,
}

/// Response body for listing emails
#[derive(Debug, Serialize, Deserialize)]
pub struct ListEmailsResponse {
    /// List of user's emails
    pub emails: Vec<UserEmailInfo>,
}

/// Request body for setting primary email
#[derive(Debug, Serialize, Deserialize)]
pub struct SetPrimaryEmailRequest {
    /// Whether to set as primary
    pub is_primary: bool,
}

/// Response body for email operations
#[derive(Debug, Serialize, Deserialize)]
pub struct EmailOperationResponse {
    /// Success message
    pub message: String,
}

impl From<UserEmail> for UserEmailInfo {
    fn from(email: UserEmail) -> Self {
        Self {
            id: email.id,
            email: email.email,
            is_primary: email.primary,
            is_verified: email.verified_at.is_some(),
            created_at: email.created_at.to_rfc3339(),
        }
    }
}

/// Add a new email address
///
/// POST /v1/users/emails
///
/// Adds a new email address for the authenticated user and sends a verification email
pub async fn add_email(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
    Json(payload): Json<AddEmailRequest>,
) -> Result<Json<AddEmailResponse>> {
    // Create email record
    let email_repo = UserEmailRepository::new((*state.storage).clone());

    // Check if email already exists
    if email_repo.get_by_email(&payload.email).await?.is_some() {
        return Err(CoreError::Validation("Email address already in use".to_string()).into());
    }

    let email_id = IdGenerator::next_id();
    let user_email = UserEmail::new(email_id, ctx.user_id, payload.email.clone(), false)?;

    email_repo.create(user_email.clone()).await?;

    // Generate verification token
    let token_id = IdGenerator::next_id();
    let token_string = UserEmailVerificationToken::generate_token();
    let verification_token =
        UserEmailVerificationToken::new(token_id, email_id, token_string.clone())?;

    let token_repo = UserEmailVerificationTokenRepository::new((*state.storage).clone());
    token_repo.create(verification_token).await?;

    // TODO: Send verification email via email service
    // For now, we'll just log the token
    tracing::info!(
        "Verification token for email {}: {}",
        payload.email,
        token_string
    );

    Ok(Json(AddEmailResponse {
        email: user_email.into(),
        message: "Email added. Please check your inbox for a verification link.".to_string(),
    }))
}

/// List all emails for the authenticated user
///
/// GET /v1/users/emails
///
/// Returns all email addresses associated with the user's account
pub async fn list_emails(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
) -> Result<Json<ListEmailsResponse>> {
    let email_repo = UserEmailRepository::new((*state.storage).clone());
    let emails = email_repo.get_user_emails(ctx.user_id).await?;

    Ok(Json(ListEmailsResponse {
        emails: emails.into_iter().map(|e| e.into()).collect(),
    }))
}

/// Set an email as primary
///
/// PATCH /v1/users/emails/:id
///
/// Sets the specified email as the user's primary email (must be verified)
pub async fn update_email(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
    Path(email_id): Path<i64>,
    Json(payload): Json<SetPrimaryEmailRequest>,
) -> Result<Json<EmailOperationResponse>> {
    let email_repo = UserEmailRepository::new((*state.storage).clone());

    // Get the email
    let email = email_repo
        .get(email_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Email not found".to_string()))?;

    // Verify ownership
    if email.user_id != ctx.user_id {
        return Err(CoreError::Auth("Not authorized to modify this email".to_string()).into());
    }

    if payload.is_primary {
        // Only allow setting verified emails as primary
        if !email.is_verified() {
            return Err(CoreError::Validation(
                "Cannot set unverified email as primary".to_string(),
            )
            .into());
        }

        // Update the email to be primary
        let mut updated_email = email.clone();
        updated_email.set_primary(true);
        email_repo.update(updated_email).await?;

        Ok(Json(EmailOperationResponse {
            message: "Email set as primary".to_string(),
        }))
    } else {
        Err(CoreError::Validation("Can only set emails as primary".to_string()).into())
    }
}

/// Delete an email address
///
/// DELETE /v1/users/emails/:id
///
/// Removes an email address from the user's account (cannot delete primary email)
pub async fn delete_email(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
    Path(email_id): Path<i64>,
) -> Result<Json<EmailOperationResponse>> {
    let email_repo = UserEmailRepository::new((*state.storage).clone());

    // Get the email
    let email = email_repo
        .get(email_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Email not found".to_string()))?;

    // Verify ownership
    if email.user_id != ctx.user_id {
        return Err(CoreError::Auth("Not authorized to delete this email".to_string()).into());
    }

    // Cannot delete primary email
    if email.primary {
        return Err(CoreError::Validation(
            "Cannot delete primary email. Set another email as primary first.".to_string(),
        )
        .into());
    }

    email_repo.delete(email_id).await?;

    Ok(Json(EmailOperationResponse {
        message: "Email deleted successfully".to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use axum::middleware;
    use axum::routing::{delete, get, patch, post};
    use infera_management_core::{
        entities::{SessionType, User, UserSession},
        UserRepository, UserSessionRepository,
    };
    use infera_management_storage::{Backend, MemoryBackend};
    use std::sync::Arc;
    use tower::ServiceExt;

    use crate::handlers::auth::SESSION_COOKIE_NAME;
    use crate::middleware::require_session;

    fn create_test_app(storage: Arc<Backend>) -> axum::Router {
        let _ = IdGenerator::init(1);

        let state = AppState::new_test(storage);

        axum::Router::new()
            .route("/users/emails", post(add_email))
            .route("/users/emails", get(list_emails))
            .route("/users/emails/{id}", patch(update_email))
            .route("/users/emails/{id}", delete(delete_email))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                require_session,
            ))
            .with_state(state)
    }

    async fn create_test_user_and_session(
        storage: Arc<Backend>,
        user_id: i64,
        session_id: i64,
    ) -> (User, UserSession) {
        let user = User::new(user_id, "testuser".to_string(), None).unwrap();
        let user_repo = UserRepository::new((*storage).clone());
        user_repo.create(user.clone()).await.unwrap();

        let session = UserSession::new(session_id, user_id, SessionType::Web, None, None);
        let session_repo = UserSessionRepository::new((*storage).clone());
        session_repo.create(session.clone()).await.unwrap();

        (user, session)
    }

    #[tokio::test]
    async fn test_add_email() {
        let storage = Arc::new(Backend::Memory(MemoryBackend::new()));
        let (_user, session) = create_test_user_and_session(storage.clone(), 100, 1).await;

        let app = create_test_app(storage.clone());

        let request = HttpRequest::builder()
            .method("POST")
            .uri("/users/emails")
            .header("cookie", format!("{}={}", SESSION_COOKIE_NAME, session.id))
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_string(&AddEmailRequest {
                    email: "newemail@example.com".to_string(),
                })
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let add_response: AddEmailResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(add_response.email.email, "newemail@example.com");
        assert!(!add_response.email.is_verified);
    }

    #[tokio::test]
    async fn test_list_emails() {
        let storage = Arc::new(Backend::Memory(MemoryBackend::new()));
        let (_user, session) = create_test_user_and_session(storage.clone(), 100, 1).await;

        // Add an email first
        let email_repo = UserEmailRepository::new((*storage).clone());
        let email = UserEmail::new(200, 100, "test@example.com".to_string(), true).unwrap();
        email_repo.create(email).await.unwrap();

        let app = create_test_app(storage.clone());

        let request = HttpRequest::builder()
            .method("GET")
            .uri("/users/emails")
            .header("cookie", format!("{}={}", SESSION_COOKIE_NAME, session.id))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let list_response: ListEmailsResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(list_response.emails.len(), 1);
        assert_eq!(list_response.emails[0].email, "test@example.com");
    }

    #[tokio::test]
    async fn test_delete_email() {
        let storage = Arc::new(Backend::Memory(MemoryBackend::new()));
        let (_user, session) = create_test_user_and_session(storage.clone(), 100, 1).await;

        // Add a non-primary email
        let email_repo = UserEmailRepository::new((*storage).clone());
        let email = UserEmail::new(200, 100, "delete@example.com".to_string(), false).unwrap();
        email_repo.create(email).await.unwrap();

        let app = create_test_app(storage.clone());

        let request = HttpRequest::builder()
            .method("DELETE")
            .uri("/users/emails/200")
            .header("cookie", format!("{}={}", SESSION_COOKIE_NAME, session.id))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        // Verify email was deleted
        let deleted = email_repo.get(200).await.unwrap();
        assert!(deleted.is_none());
    }

    #[tokio::test]
    async fn test_cannot_delete_primary_email() {
        let storage = Arc::new(Backend::Memory(MemoryBackend::new()));
        let (_user, session) = create_test_user_and_session(storage.clone(), 100, 1).await;

        // Add a primary email
        let email_repo = UserEmailRepository::new((*storage).clone());
        let email = UserEmail::new(200, 100, "primary@example.com".to_string(), true).unwrap();
        email_repo.create(email).await.unwrap();

        let app = create_test_app(storage.clone());

        let request = HttpRequest::builder()
            .method("DELETE")
            .uri("/users/emails/200")
            .header("cookie", format!("{}={}", SESSION_COOKIE_NAME, session.id))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }
}
