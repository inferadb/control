use axum::{Extension, Json};
use infera_management_core::{error::Error as CoreError, UserRepository};
use serde::{Deserialize, Serialize};

use crate::handlers::auth::{AppState, Result};
use crate::middleware::SessionContext;
use axum::extract::State;

/// Get user profile response (wrapped)
#[derive(Debug, Serialize, Deserialize)]
pub struct GetUserProfileResponse {
    pub user: UserProfile,
}

/// User profile response
#[derive(Debug, Serialize, Deserialize)]
pub struct UserProfile {
    /// User ID
    pub id: i64,
    /// User's name
    pub name: String,
    /// When the user was created
    pub created_at: String,
    /// When TOS was accepted (if applicable)
    pub tos_accepted_at: Option<String>,
}

/// Request body for updating user profile
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateProfileRequest {
    /// Updated name (optional)
    pub name: Option<String>,
    /// Accept terms of service (optional)
    pub accept_tos: Option<bool>,
}

/// Response body for profile updates
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateProfileResponse {
    /// Updated user profile
    pub profile: UserProfile,
}

/// Response body for user deletion
#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteUserResponse {
    /// Confirmation message
    pub message: String,
}

/// Get current user's profile
///
/// GET /v1/users/me
///
/// Returns the authenticated user's profile information
pub async fn get_profile(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
) -> Result<Json<GetUserProfileResponse>> {
    // Get user from repository
    let user_repo = UserRepository::new((*state.storage).clone());
    let user = user_repo
        .get(ctx.user_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("User not found".to_string()))?;

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
    // Get user from repository
    let user_repo = UserRepository::new((*state.storage).clone());
    let mut user = user_repo
        .get(ctx.user_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("User not found".to_string()))?;

    // Update name if provided
    if let Some(name) = payload.name {
        user.set_name(name)?;
    }

    // Accept TOS if requested
    if let Some(true) = payload.accept_tos {
        user.accept_tos();
    }

    // Save updated user
    user_repo.update(user.clone()).await?;

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
    // TODO: Check if user is the only owner of any organizations
    // This will be implemented in Phase 3 when organizations are added

    // Get user from repository
    let user_repo = UserRepository::new((*state.storage).clone());
    let mut user = user_repo
        .get(ctx.user_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("User not found".to_string()))?;

    // Soft-delete the user
    user.soft_delete();
    user_repo.update(user).await?;

    // TODO: Cascade delete related entities (Phase 3+):
    // - Revoke all user sessions
    // - Remove from organization memberships
    // - Clean up email addresses
    // - Revoke vault access grants

    Ok(Json(DeleteUserResponse {
        message: "User account deleted successfully".to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use axum::middleware;
    use axum::routing::{delete, get, patch};
    use infera_management_core::{
        entities::{SessionType, User, UserSession},
        IdGenerator, UserSessionRepository,
    };
    use infera_management_storage::{Backend, MemoryBackend};
    use std::sync::Arc;
    use tower::ServiceExt;

    use crate::handlers::auth::SESSION_COOKIE_NAME;
    use crate::middleware::require_session;

    fn create_test_app(storage: Arc<Backend>) -> axum::Router {
        // Initialize ID generator
        let _ = IdGenerator::init(1);

        let state = AppState::new_test(storage);

        axum::Router::new()
            .route("/users/me", get(get_profile))
            .route("/users/me", patch(update_profile))
            .route("/users/me", delete(delete_user))
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
    async fn test_get_profile() {
        let storage = Arc::new(Backend::Memory(MemoryBackend::new()));
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

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let response_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let profile: UserProfile = serde_json::from_value(response_json["user"].clone()).unwrap();

        assert_eq!(profile.id, user.id);
        assert_eq!(profile.name, user.name);
    }

    #[tokio::test]
    async fn test_update_profile_name() {
        let storage = Arc::new(Backend::Memory(MemoryBackend::new()));
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

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let update_response: UpdateProfileResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(update_response.profile.name, "newname");
    }

    #[tokio::test]
    async fn test_update_profile_accept_tos() {
        let storage = Arc::new(Backend::Memory(MemoryBackend::new()));
        let (_user, session) = create_test_user_and_session(storage.clone(), 100, 1).await;

        let app = create_test_app(storage.clone());

        let request = HttpRequest::builder()
            .method("PATCH")
            .uri("/users/me")
            .header("cookie", format!("{}={}", SESSION_COOKIE_NAME, session.id))
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_string(&UpdateProfileRequest {
                    name: None,
                    accept_tos: Some(true),
                })
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let update_response: UpdateProfileResponse = serde_json::from_slice(&body).unwrap();

        assert!(update_response.profile.tos_accepted_at.is_some());
    }

    #[tokio::test]
    async fn test_delete_user() {
        let storage = Arc::new(Backend::Memory(MemoryBackend::new()));
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
        let user_repo = UserRepository::new((*storage).clone());
        let deleted_user = user_repo.get(user.id).await.unwrap();
        assert!(deleted_user.is_none()); // Soft-deleted users are filtered out by get()
    }
}
