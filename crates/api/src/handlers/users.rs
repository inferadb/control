use axum::{Extension, Json, extract::State};
use inferadb_control_core::RepositoryContext;
use inferadb_control_types::{
    Error as CoreError,
    dto::{
        DeleteUserResponse, GetUserProfileResponse, UpdateProfileRequest, UpdateProfileResponse,
        UserProfile,
    },
};

use crate::{
    handlers::auth::{AppState, Result},
    middleware::SessionContext,
};

/// Get current user's profile
///
/// GET /v1/users/me
///
/// Returns the authenticated user's profile information
pub async fn get_profile(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
) -> Result<Json<GetUserProfileResponse>> {
    let repos = RepositoryContext::new((*state.storage).clone());

    // Get user from repository
    let user = repos
        .user
        .get(ctx.user_id)
        .await?
        .ok_or_else(|| CoreError::not_found("User not found".to_string()))?;

    Ok(Json(GetUserProfileResponse {
        user: UserProfile {
            id: user.id,
            name: user.name,
            created_at: user.created_at.to_rfc3339(),
            tos_accepted_at: user.tos_accepted_at.map(|dt| dt.to_rfc3339()),
        },
    }))
}

/// Update current user's profile
///
/// PATCH /v1/users/me
///
/// Updates the authenticated user's profile (name, TOS acceptance)
pub async fn update_profile(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
    Json(payload): Json<UpdateProfileRequest>,
) -> Result<Json<UpdateProfileResponse>> {
    let repos = RepositoryContext::new((*state.storage).clone());

    // Get user from repository
    let mut user = repos
        .user
        .get(ctx.user_id)
        .await?
        .ok_or_else(|| CoreError::not_found("User not found".to_string()))?;

    // Update name if provided
    if let Some(name) = payload.name {
        user.set_name(name)?;
    }

    // Accept TOS if requested
    if let Some(true) = payload.accept_tos {
        user.accept_tos();
    }

    // Save updated user
    repos.user.update(user.clone()).await?;

    Ok(Json(UpdateProfileResponse {
        profile: UserProfile {
            id: user.id,
            name: user.name,
            created_at: user.created_at.to_rfc3339(),
            tos_accepted_at: user.tos_accepted_at.map(|dt| dt.to_rfc3339()),
        },
    }))
}

/// Delete current user account
///
/// DELETE /v1/users/me
///
/// Soft-deletes the authenticated user's account and all related data.
/// Note: Users who are the only owner of an organization cannot delete their account.
pub async fn delete_user(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
) -> Result<Json<DeleteUserResponse>> {
    let repos = RepositoryContext::new((*state.storage).clone());

    // VALIDATION: Check if user is the only owner of any organizations
    let memberships = repos.org_member.get_by_user(ctx.user_id).await?;

    for membership in &memberships {
        if membership.role == inferadb_control_types::entities::OrganizationRole::Owner {
            // Check if this user is the only owner
            let owner_count = repos.org_member.count_owners(membership.organization_id).await?;
            if owner_count <= 1
                && let Some(org) = repos.org.get(membership.organization_id).await?
            {
                return Err(CoreError::validation(format!(
                    "Cannot delete account while being the only owner of organization '{}'. Please transfer ownership or delete the organization first.",
                    org.name
                ))
                .into());
            }
        }
    }

    // Get user from repository
    let mut user = repos
        .user
        .get(ctx.user_id)
        .await?
        .ok_or_else(|| CoreError::not_found("User not found".to_string()))?;

    // CASCADE DELETE: Revoke all user sessions
    let sessions = repos.user_session.get_user_sessions(ctx.user_id).await?;
    for session in sessions {
        repos.user_session.delete(session.id).await?;
    }

    // CASCADE DELETE: Remove organization memberships (only if not owner)
    for membership in memberships {
        if membership.role != inferadb_control_types::entities::OrganizationRole::Owner {
            repos.org_member.delete(membership.id).await?;
        }
    }

    // CASCADE DELETE: Delete all email verification tokens first, then email addresses
    let emails = repos.user_email.get_user_emails(ctx.user_id).await?;

    for email in &emails {
        let tokens = repos.user_email_verification_token.get_by_email(email.id).await?;
        for token in tokens {
            repos.user_email_verification_token.delete(token.id).await?;
        }
    }

    // Now delete all email addresses
    for email in emails {
        repos.user_email.delete(email.id).await?;
    }

    // CASCADE DELETE: Delete all password reset tokens
    let reset_tokens = repos.user_password_reset_token.get_by_user(ctx.user_id).await?;
    for token in reset_tokens {
        repos.user_password_reset_token.delete(token.id).await?;
    }

    // Soft-delete the user
    user.soft_delete();
    repos.user.update(user).await?;

    Ok(Json(DeleteUserResponse { message: "User account deleted successfully".to_string() }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::Arc;

    use axum::{
        body::Body,
        http::Request as HttpRequest,
        middleware,
        routing::{delete, get, patch},
    };
    use inferadb_control_const::auth::SESSION_COOKIE_NAME;
    use inferadb_control_core::{IdGenerator, RepositoryContext};
    use inferadb_control_storage::Backend;
    use inferadb_control_types::entities::{SessionType, User, UserSession};
    use tower::ServiceExt;

    use super::*;
    use crate::middleware::require_session;

    fn create_test_app(storage: Arc<Backend>) -> axum::Router {
        // Initialize ID generator
        let _ = IdGenerator::init(1);

        let state = AppState::new_test(storage);

        axum::Router::new()
            .route("/users/me", get(get_profile))
            .route("/users/me", patch(update_profile))
            .route("/users/me", delete(delete_user))
            .layer(middleware::from_fn_with_state(state.clone(), require_session))
            .with_state(state)
    }

    async fn create_test_user_and_session(
        storage: Arc<Backend>,
        user_id: i64,
        session_id: i64,
    ) -> (User, UserSession) {
        let repos = RepositoryContext::new((*storage).clone());
        let user = User::builder().id(user_id).name("testuser").create().unwrap();
        repos.user.create(user.clone()).await.unwrap();

        let session = UserSession::builder()
            .id(session_id)
            .user_id(user_id)
            .session_type(SessionType::Web)
            .create();
        repos.user_session.create(session.clone()).await.unwrap();

        (user, session)
    }

    #[tokio::test]
    async fn test_get_profile() {
        let storage = Arc::new(Backend::memory());
        let (user, session) = create_test_user_and_session(storage.clone(), 100, 1).await;

        let app = create_test_app(storage.clone());

        let request = HttpRequest::builder()
            .method("GET")
            .uri("/users/me")
            .header("cookie", format!("{}={}", SESSION_COOKIE_NAME, session.id))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let response_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let profile: UserProfile = serde_json::from_value(response_json["user"].clone()).unwrap();

        assert_eq!(profile.id, user.id);
        assert_eq!(profile.name, user.name);
    }

    #[tokio::test]
    async fn test_update_profile_name() {
        let storage = Arc::new(Backend::memory());
        let (_user, session) = create_test_user_and_session(storage.clone(), 100, 1).await;

        let app = create_test_app(storage.clone());

        let request = HttpRequest::builder()
            .method("PATCH")
            .uri("/users/me")
            .header("cookie", format!("{}={}", SESSION_COOKIE_NAME, session.id))
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_string(&UpdateProfileRequest {
                    name: Some("newname".to_string()),
                    accept_tos: None,
                })
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let update_response: UpdateProfileResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(update_response.profile.name, "newname");
    }

    #[tokio::test]
    async fn test_update_profile_accept_tos() {
        let storage = Arc::new(Backend::memory());
        let (_user, session) = create_test_user_and_session(storage.clone(), 100, 1).await;

        let app = create_test_app(storage.clone());

        let request = HttpRequest::builder()
            .method("PATCH")
            .uri("/users/me")
            .header("cookie", format!("{}={}", SESSION_COOKIE_NAME, session.id))
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_string(&UpdateProfileRequest { name: None, accept_tos: Some(true) })
                    .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let update_response: UpdateProfileResponse = serde_json::from_slice(&body).unwrap();

        assert!(update_response.profile.tos_accepted_at.is_some());
    }

    #[tokio::test]
    async fn test_delete_user() {
        let storage = Arc::new(Backend::memory());
        let (user, session) = create_test_user_and_session(storage.clone(), 100, 1).await;

        let app = create_test_app(storage.clone());

        let request = HttpRequest::builder()
            .method("DELETE")
            .uri("/users/me")
            .header("cookie", format!("{}={}", SESSION_COOKIE_NAME, session.id))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        // Verify user is soft-deleted
        let repos = RepositoryContext::new((*storage).clone());
        let deleted_user = repos.user.get(user.id).await.unwrap();
        assert!(deleted_user.is_none()); // Soft-deleted users are filtered out by get()
    }
}
