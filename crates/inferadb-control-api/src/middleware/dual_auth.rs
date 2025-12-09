use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use axum_extra::extract::cookie::CookieJar;
use inferadb_control_const::auth::SESSION_COOKIE_NAME;
use inferadb_control_core::error::Error as CoreError;

use super::{EngineContext, SessionContext, require_engine_jwt, require_session};
use crate::handlers::auth::{ApiError, AppState};

/// Dual authentication middleware
///
/// Accepts EITHER session authentication OR engine JWT authentication.
/// This allows both user requests (via session cookies/tokens) and
/// engine-to-control requests (via JWT) to access the same endpoints.
///
/// Attaches either SessionContext or EngineContext to the request extensions.
pub async fn require_session_or_engine_jwt(
    State(state): State<AppState>,
    jar: CookieJar,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    // Check if this looks like a JWT request (Bearer token in Authorization header)
    let has_bearer_token = request
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.starts_with("Bearer "))
        .unwrap_or(false);

    // Check if this looks like a session request (session cookie or numeric Bearer token)
    let has_session = jar.get(SESSION_COOKIE_NAME).is_some()
        || request
            .headers()
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .and_then(|token| token.parse::<i64>().ok())
            .is_some();

    // If we have a Bearer token and it's NOT a session (numeric), check if it's an engine JWT
    if has_bearer_token && !has_session {
        // Peek at the JWT to determine if it's an engine JWT or client JWT
        // We need to decode just the header to check the kid format without consuming the request
        let is_engine_jwt = request
            .headers()
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .and_then(|token| {
                use jsonwebtoken::decode_header;
                decode_header(token).ok()
            })
            .and_then(|header| header.kid)
            .map(|kid| !kid.contains("-client-")) // Engine JWTs don't have "-client-" in kid
            .unwrap_or(false);

        if is_engine_jwt {
            // This is an engine JWT, use engine JWT auth
            return require_engine_jwt(State(state), request, next).await;
        }
        // Fall through to try session auth for client JWTs
    }

    // Try session auth (handles cookies, numeric tokens, and client JWTs)
    if has_session || has_bearer_token {
        return require_session(State(state), jar, request, next).await;
    }

    // No recognizable auth present
    Err(CoreError::Auth(
        "Authentication required: provide either a session token or engine JWT".to_string(),
    )
    .into())
}

/// Extract either session context or engine context from request
///
/// Returns SessionContext if session auth was used, or converts EngineContext to a
/// compatible format if engine JWT was used.
pub fn extract_dual_auth_context(request: &Request) -> Result<AuthContextType, ApiError> {
    // Try to extract session context first
    if let Some(session_ctx) = request.extensions().get::<SessionContext>() {
        return Ok(AuthContextType::Session(session_ctx.clone()));
    }

    // Try to extract engine context
    if let Some(engine_ctx) = request.extensions().get::<EngineContext>() {
        return Ok(AuthContextType::Engine(engine_ctx.clone()));
    }

    Err(CoreError::Auth("No authentication context found in request".to_string()).into())
}

/// Enum representing the type of authentication used
#[derive(Debug, Clone)]
pub enum AuthContextType {
    /// Session-based authentication (user request)
    Session(SessionContext),
    /// Engine JWT authentication (engine-to-control)
    Engine(EngineContext),
}

impl AuthContextType {
    /// Get user ID if this is a session context, None otherwise
    pub fn user_id(&self) -> Option<i64> {
        match self {
            AuthContextType::Session(ctx) => Some(ctx.user_id),
            AuthContextType::Engine(_) => None,
        }
    }

    /// Get engine ID if this is an engine context, None otherwise
    pub fn engine_id(&self) -> Option<&str> {
        match self {
            AuthContextType::Session(_) => None,
            AuthContextType::Engine(ctx) => Some(&ctx.engine_id),
        }
    }

    /// Check if this is an engine authentication
    pub fn is_engine_auth(&self) -> bool {
        matches!(self, AuthContextType::Engine(_))
    }

    /// Check if this is a session authentication
    pub fn is_session_auth(&self) -> bool {
        matches!(self, AuthContextType::Session(_))
    }
}
