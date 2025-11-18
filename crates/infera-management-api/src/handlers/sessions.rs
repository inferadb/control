use axum::{
    extract::{Path, Request, State},
    Json,
};
use infera_management_core::{error::Error as CoreError, UserSessionRepository};
use serde::{Deserialize, Serialize};

use crate::handlers::auth::{AppState, Result};
use crate::middleware::extract_session_context;

/// Session information response
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionInfo {
    /// Session ID
    pub session_id: i64,
    /// Session type (WEB, CLI, SDK)
    pub session_type: String,
    /// When the session was created
    pub created_at: String,
    /// When the session expires
    pub expires_at: String,
    /// Last activity timestamp
    pub last_activity_at: String,
    /// IP address (if available)
    pub ip_address: Option<String>,
    /// User agent (if available)
    pub user_agent: Option<String>,
}

/// Response body for session listing
#[derive(Debug, Serialize, Deserialize)]
pub struct ListSessionsResponse {
    /// List of active sessions
    pub sessions: Vec<SessionInfo>,
    /// Total count of active sessions
    pub count: usize,
}

/// Response body for session revocation
#[derive(Debug, Serialize, Deserialize)]
pub struct RevokeSessionResponse {
    /// Confirmation message
    pub message: String,
}

/// List all active sessions for the current user
///
/// GET /v1/users/sessions
///
/// Returns all active sessions for the authenticated user
pub async fn list_sessions(
    State(state): State<AppState>,
    request: Request,
) -> Result<Json<ListSessionsResponse>> {
    // Extract session context from middleware
    let ctx = extract_session_context(&request)?;

    // Get all user sessions
    let session_repo = UserSessionRepository::new((*state.storage).clone());
    let sessions = session_repo.get_user_sessions(ctx.user_id).await?;

    // Convert to response format
    let sessions: Vec<SessionInfo> = sessions
        .into_iter()
        .map(|s| SessionInfo {
            session_id: s.id,
            session_type: format!("{:?}", s.session_type).to_uppercase(),
            created_at: s.created_at.to_rfc3339(),
            expires_at: s.expires_at.to_rfc3339(),
            last_activity_at: s.last_activity_at.to_rfc3339(),
            ip_address: s.ip_address,
            user_agent: s.user_agent,
        })
        .collect();

    let count = sessions.len();

    Ok(Json(ListSessionsResponse { sessions, count }))
}

/// Revoke a specific session
///
/// DELETE /v1/users/sessions/:id
///
/// Revokes a session by ID. Users can revoke their own sessions.
pub async fn revoke_session(
    State(state): State<AppState>,
    Path(session_id): Path<i64>,
    request: Request,
) -> Result<Json<RevokeSessionResponse>> {
    // Extract session context from middleware
    let ctx = extract_session_context(&request)?;

    // Get the session to revoke
    let session_repo = UserSessionRepository::new((*state.storage).clone());
    let session = session_repo
        .get(session_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Session not found".to_string()))?;

    // Verify the session belongs to the current user
    if session.user_id != ctx.user_id {
        return Err(CoreError::Authz("Cannot revoke another user's session".to_string()).into());
    }

    // Revoke the session
    session_repo.revoke(session_id).await?;

    Ok(Json(RevokeSessionResponse {
        message: "Session revoked successfully".to_string(),
    }))
}

/// Revoke all other sessions (keep current session)
///
/// POST /v1/users/sessions/revoke-others
///
/// Revokes all sessions except the current one
pub async fn revoke_other_sessions(
    State(state): State<AppState>,
    request: Request,
) -> Result<Json<RevokeSessionResponse>> {
    // Extract session context from middleware
    let ctx = extract_session_context(&request)?;

    // Get all user sessions
    let session_repo = UserSessionRepository::new((*state.storage).clone());
    let sessions = session_repo.get_user_sessions(ctx.user_id).await?;

    // Revoke all sessions except the current one
    let mut revoked_count = 0;
    for session in sessions {
        if session.id != ctx.session_id {
            session_repo.revoke(session.id).await?;
            revoked_count += 1;
        }
    }

    Ok(Json(RevokeSessionResponse {
        message: format!("Revoked {} other session(s)", revoked_count),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use axum::middleware;
    use axum::routing::{delete, get, post};
    use infera_management_core::{entities::SessionType, entities::UserSession, IdGenerator};
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
            .route("/sessions", get(list_sessions))
            .route("/sessions/{id}", delete(revoke_session))
            .route("/sessions/revoke-others", post(revoke_other_sessions))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                require_session,
            ))
            .with_state(state)
    }

    async fn create_test_session_in_storage(
        storage: Arc<Backend>,
        session_id: i64,
        user_id: i64,
    ) -> UserSession {
        let session = UserSession::new(session_id, user_id, SessionType::Web, None, None);
        let repo = UserSessionRepository::new((*storage).clone());
        repo.create(session.clone()).await.unwrap();
        session
    }

    #[tokio::test]
    async fn test_list_sessions() {
        let storage = Arc::new(Backend::Memory(MemoryBackend::new()));

        // Create test sessions
        let session1 = create_test_session_in_storage(storage.clone(), 1, 100).await;
        let _session2 = create_test_session_in_storage(storage.clone(), 2, 100).await;

        let app = create_test_app(storage.clone());

        let request = HttpRequest::builder()
            .method("GET")
            .uri("/sessions")
            .header("cookie", format!("{}={}", SESSION_COOKIE_NAME, session1.id))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let list_response: ListSessionsResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(list_response.count, 2);
        assert_eq!(list_response.sessions.len(), 2);
    }

    #[tokio::test]
    async fn test_revoke_session() {
        let storage = Arc::new(Backend::Memory(MemoryBackend::new()));

        // Create test sessions
        let session1 = create_test_session_in_storage(storage.clone(), 1, 100).await;
        let session2 = create_test_session_in_storage(storage.clone(), 2, 100).await;

        let app = create_test_app(storage.clone());

        let request = HttpRequest::builder()
            .method("DELETE")
            .uri(format!("/sessions/{}", session2.id))
            .header("cookie", format!("{}={}", SESSION_COOKIE_NAME, session1.id))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        // Verify session2 is revoked
        let repo = UserSessionRepository::new((*storage).clone());
        assert!(!repo.is_active(session2.id).await.unwrap());
        assert!(repo.is_active(session1.id).await.unwrap());
    }

    #[tokio::test]
    async fn test_revoke_other_sessions() {
        let storage = Arc::new(Backend::Memory(MemoryBackend::new()));

        // Create test sessions
        let session1 = create_test_session_in_storage(storage.clone(), 1, 100).await;
        let _session2 = create_test_session_in_storage(storage.clone(), 2, 100).await;
        let _session3 = create_test_session_in_storage(storage.clone(), 3, 100).await;

        let app = create_test_app(storage.clone());

        let request = HttpRequest::builder()
            .method("POST")
            .uri("/sessions/revoke-others")
            .header("cookie", format!("{}={}", SESSION_COOKIE_NAME, session1.id))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let revoke_response: RevokeSessionResponse = serde_json::from_slice(&body).unwrap();
        assert!(revoke_response.message.contains("2 other session"));

        // Verify only session1 is still active
        let repo = UserSessionRepository::new((*storage).clone());
        assert!(repo.is_active(1).await.unwrap());
        assert!(!repo.is_active(2).await.unwrap());
        assert!(!repo.is_active(3).await.unwrap());
    }

    #[tokio::test]
    async fn test_cannot_revoke_other_users_session() {
        let storage = Arc::new(Backend::Memory(MemoryBackend::new()));

        // Create sessions for different users
        let session1 = create_test_session_in_storage(storage.clone(), 1, 100).await;
        let session2 = create_test_session_in_storage(storage.clone(), 2, 200).await;

        let app = create_test_app(storage.clone());

        let request = HttpRequest::builder()
            .method("DELETE")
            .uri(format!("/sessions/{}", session2.id))
            .header("cookie", format!("{}={}", SESSION_COOKIE_NAME, session1.id))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }
}
