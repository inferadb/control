use axum::{
    Extension, Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use base64::Engine;
use chrono::Utc;
use inferadb_control_core::{IdGenerator, RepositoryContext};
use inferadb_control_types::{
    dto::{CliAuthorizeRequest, CliAuthorizeResponse, CliTokenRequest, CliTokenResponse},
    entities::{AuthorizationCode, SessionType, UserSession},
};

use crate::{handlers::AppState, middleware::session::SessionContext};

/// Authorize CLI access (browser-based OAuth flow)
///
/// This endpoint is called from a browser where the user has an active web session.
/// It generates an authorization code that the CLI can exchange for a session token.
///
/// # Flow
/// 1. CLI generates code_verifier and code_challenge
/// 2. CLI opens browser to this endpoint with code_challenge
/// 3. User logs in (if not already) via web session
/// 4. This endpoint generates authorization code bound to:
///    - User's session
///    - PKCE code_challenge
/// 5. Browser redirects back to CLI with code
/// 6. CLI calls token exchange endpoint with code and code_verifier
pub async fn cli_authorize(
    State(state): State<AppState>,
    Extension(session_ctx): Extension<SessionContext>,
    Json(req): Json<CliAuthorizeRequest>,
) -> Result<Json<CliAuthorizeResponse>, Response> {
    // Validate code_challenge_method
    if req.code_challenge_method != "S256" {
        return Err((StatusCode::BAD_REQUEST, "code_challenge_method must be 'S256'".to_string())
            .into_response());
    }

    // Generate a cryptographically secure authorization code
    let code_bytes = generate_secure_code(32);
    let code = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&code_bytes);

    // Generate ID for the authorization code
    let code_id = IdGenerator::next_id();

    // Create authorization code entity
    let auth_code = AuthorizationCode::new(
        code_id,
        code.clone(),
        session_ctx.session_id,
        req.code_challenge,
        req.code_challenge_method,
    );

    // Store the authorization code
    let repos = RepositoryContext::new((*state.storage).clone());
    repos.authorization_code.create(auth_code.clone()).await.map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create authorization code: {e}"))
            .into_response()
    })?;

    Ok(Json(CliAuthorizeResponse { code, expires_in: AuthorizationCode::TTL_SECONDS }))
}

/// Exchange authorization code for CLI session token
///
/// This endpoint is called by the CLI to exchange the authorization code
/// for a long-lived session token (7 days).
///
/// # Flow
/// 1. Verify authorization code exists and is valid
/// 2. Verify PKCE code_verifier matches stored code_challenge
/// 3. Get the user session associated with the code
/// 4. Create a new CLI session for the user
/// 5. Mark the authorization code as used (single-use)
/// 6. Return the CLI session token
pub async fn cli_token_exchange(
    State(state): State<AppState>,
    Json(req): Json<CliTokenRequest>,
) -> Result<Json<CliTokenResponse>, Response> {
    // Get authorization code
    let repos = RepositoryContext::new((*state.storage).clone());
    let mut auth_code = repos
        .authorization_code
        .get_by_code(&req.code)
        .await
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get authorization code: {e}"))
                .into_response()
        })?
        .ok_or_else(|| {
            (StatusCode::UNAUTHORIZED, "Invalid or expired authorization code".to_string())
                .into_response()
        })?;

    // Verify PKCE code_verifier
    if !auth_code.verify_code_verifier(&req.code_verifier) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Invalid code_verifier (PKCE verification failed)".to_string(),
        )
            .into_response());
    }

    // Get the original session to extract user_id
    let original_session = repos
        .user_session
        .get(auth_code.session_id)
        .await
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get session: {e}"))
                .into_response()
        })?
        .ok_or_else(|| {
            (StatusCode::UNAUTHORIZED, "Original session expired or not found".to_string())
                .into_response()
        })?;

    // Generate new CLI session ID
    let cli_session_id = IdGenerator::next_id();

    // Create CLI session
    let cli_session = UserSession::builder()
        .id(cli_session_id)
        .user_id(original_session.user_id)
        .session_type(SessionType::Cli)
        .user_agent("InferaDB CLI")
        .create();

    // Store CLI session
    repos.user_session.create(cli_session.clone()).await.map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create CLI session: {e}"))
            .into_response()
    })?;

    // Mark authorization code as used (prevent replay)
    auth_code.mark_used();
    repos.authorization_code.update(auth_code).await.map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to mark code as used: {e}"))
            .into_response()
    })?;

    // Calculate expires_in
    let expires_in = (cli_session.expires_at - Utc::now()).num_seconds();

    Ok(Json(CliTokenResponse { session_token: cli_session_id.to_string(), expires_in }))
}

/// Generate a cryptographically secure random code
fn generate_secure_code(length: usize) -> Vec<u8> {
    use rand::RngExt;
    let mut rng = rand::rng();
    (0..length).map(|_| rng.random()).collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::Arc;

    use inferadb_control_storage::Backend;

    use super::*;

    #[test]
    fn test_generate_secure_code() {
        let code1 = generate_secure_code(32);
        let code2 = generate_secure_code(32);

        assert_eq!(code1.len(), 32);
        assert_eq!(code2.len(), 32);
        assert_ne!(code1, code2); // Should be different
    }

    #[tokio::test]
    async fn test_cli_authorize_invalid_method() {
        let storage = Arc::new(Backend::memory());
        let state = crate::handlers::AppState::new_test(storage);

        let session_ctx = SessionContext { session_id: 1, user_id: 100 };

        let req = CliAuthorizeRequest {
            code_challenge: "test-challenge".to_string(),
            code_challenge_method: "plain".to_string(), // Invalid
        };

        let result = cli_authorize(State(state), Extension(session_ctx), Json(req)).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_cli_token_exchange_invalid_code() {
        let storage = Arc::new(Backend::memory());
        let state = crate::handlers::AppState::new_test(storage);

        let req = CliTokenRequest {
            code: "nonexistent-code".to_string(),
            code_verifier: "test-verifier".to_string(),
        };

        let result = cli_token_exchange(State(state), Json(req)).await;
        assert!(result.is_err());
    }
}
