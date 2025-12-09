use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use axum_extra::extract::cookie::CookieJar;
use inferadb_control_const::auth::SESSION_COOKIE_NAME;
use inferadb_control_core::{UserSessionRepository, error::Error as CoreError};

use crate::handlers::auth::{ApiError, AppState};

/// Context for authenticated requests
#[derive(Debug, Clone)]
pub struct SessionContext {
    pub session_id: i64,
    pub user_id: i64,
}

/// Session validation middleware
///
/// Extracts session token from Authorization header or cookie, validates the session,
/// updates last_activity_at (sliding window), and attaches user context to the request.
pub async fn require_session(
    State(state): State<AppState>,
    jar: CookieJar,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    // Try to extract session ID from cookie first, then from Authorization header
    let session_id = if let Some(cookie) = jar.get(SESSION_COOKIE_NAME) {
        cookie
            .value()
            .parse::<i64>()
            .map_err(|_| CoreError::Auth("Invalid session cookie".to_string()))?
    } else if let Some(auth_header) = request.headers().get("authorization") {
        let auth_str = auth_header
            .to_str()
            .map_err(|_| CoreError::Auth("Invalid authorization header".to_string()))?;

        // Support "Bearer <session_id>" format
        if let Some(token) = auth_str.strip_prefix("Bearer ") {
            token
                .parse::<i64>()
                .map_err(|_| CoreError::Auth("Invalid session token".to_string()))?
        } else {
            return Err(
                CoreError::Auth("Missing or invalid authorization header".to_string()).into()
            );
        }
    } else {
        return Err(CoreError::Auth("No session token provided".to_string()).into());
    };

    // Get session from repository
    let session_repo = UserSessionRepository::new((*state.storage).clone());
    let session = session_repo
        .get(session_id)
        .await?
        .ok_or_else(|| CoreError::Auth("Session not found or expired".to_string()))?;

    // Update activity (sliding window expiry)
    session_repo.update_activity(session_id).await?;

    // Attach session context to request extensions
    request
        .extensions_mut()
        .insert(SessionContext { session_id: session.id, user_id: session.user_id });

    Ok(next.run(request).await)
}

/// Extract session context from request extensions
///
/// This should only be called from handlers that are wrapped with require_session middleware
pub fn extract_session_context(request: &Request) -> Result<SessionContext, ApiError> {
    request.extensions().get::<SessionContext>().cloned().ok_or_else(|| {
        CoreError::Internal("Session context not found in request extensions".to_string()).into()
    })
}

/// Unauthorized response for missing or invalid sessions
impl IntoResponse for SessionContext {
    fn into_response(self) -> Response {
        (StatusCode::UNAUTHORIZED, "Unauthorized").into_response()
    }
}
