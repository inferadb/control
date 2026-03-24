//! JWT-based authentication middleware.
//!
//! Validates access tokens via the Ledger SDK's `validate_token` endpoint.
//!
//! Access tokens are extracted from:
//! 1. `Authorization: Bearer <token>` header (API clients, CLI)
//! 2. `inferadb_access` HttpOnly cookie (web clients)

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use axum_extra::extract::cookie::CookieJar;
use inferadb_control_const::auth::ACCESS_TOKEN_COOKIE_NAME;
use inferadb_control_core::SdkResultExt;
use inferadb_control_types::Error as CoreError;
use inferadb_ledger_types::UserSlug;

use crate::handlers::state::{ApiError, AppState};

/// Claims extracted from a validated JWT access token.
///
/// Injected into request extensions by [`require_jwt`]. Handlers access
/// this via `Extension<UserClaims>`.
#[derive(Debug, Clone)]
pub struct UserClaims {
    /// The authenticated user's slug identifier (Snowflake ID).
    pub user_slug: UserSlug,
    /// The user's role ("user" or "admin").
    pub role: String,
}

/// Ledger-validated JWT authentication middleware.
///
/// Extracts and validates a JWT access token via Ledger's `validate_token`
/// endpoint, then injects [`UserClaims`] into request extensions.
///
/// Returns 401 if no token is found, the Ledger client is unavailable,
/// validation fails, or the token is not a user session token.
pub async fn require_jwt(
    State(state): State<AppState>,
    jar: CookieJar,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let ledger =
        state.ledger.as_ref().ok_or_else(|| CoreError::internal("Ledger client not configured"))?;

    let token = extract_access_token(&jar, &request)?;

    let validated = ledger
        .validate_token(&token, inferadb_control_const::auth::REQUIRED_AUDIENCE)
        .await
        .map_sdk_err()?;

    let claims = match validated {
        inferadb_ledger_sdk::token::ValidatedToken::UserSession { user, role } => {
            UserClaims { user_slug: user, role }
        },
        inferadb_ledger_sdk::token::ValidatedToken::VaultAccess { .. } => {
            return Err(CoreError::auth(
                "vault access tokens cannot be used for user authentication",
            )
            .into());
        },
    };

    request.extensions_mut().insert(claims);
    Ok(next.run(request).await)
}

/// Extracts the access token from the Authorization header or cookie.
///
/// Checks the `Authorization: Bearer <token>` header first, then falls back
/// to the `inferadb_access` cookie.
pub(crate) fn extract_access_token(jar: &CookieJar, request: &Request) -> Result<String, ApiError> {
    if let Some(auth_header) = request.headers().get("authorization") {
        let auth_str = auth_header
            .to_str()
            .map_err(|_| CoreError::auth("invalid authorization header encoding"))?;

        if let Some(token) = auth_str.strip_prefix("Bearer ") {
            let token = token.trim();
            if token.is_empty() {
                return Err(CoreError::auth("empty bearer token").into());
            }
            return Ok(token.to_string());
        }
        return Err(CoreError::auth("authorization header must use Bearer scheme").into());
    }

    if let Some(cookie) = jar.get(ACCESS_TOKEN_COOKIE_NAME) {
        let value = cookie.value().trim();
        if value.is_empty() {
            return Err(CoreError::auth("empty access token cookie").into());
        }
        return Ok(value.to_string());
    }

    Err(CoreError::auth("no access token provided").into())
}
