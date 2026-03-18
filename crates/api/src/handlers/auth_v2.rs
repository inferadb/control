//! Ledger-backed authentication handlers (v2).
//!
//! Token refresh, logout, and revoke-all endpoints that delegate to
//! Ledger's token service. These coexist with the old auth handlers
//! during migration.

use axum::{Json, extract::State};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use inferadb_control_const::auth::{
    ACCESS_TOKEN_COOKIE_NAME, REFRESH_TOKEN_COOKIE_NAME,
};
use inferadb_control_core::service;
use inferadb_control_types::Error as CoreError;
use serde::{Deserialize, Serialize};
use time;

use super::auth::{ApiError, AppState};
use crate::middleware::UserClaims;

// ── Request/Response Types ──────────────────────────────────────────────

/// Request body for token refresh (API clients).
/// Web clients send the refresh token via cookie instead.
#[derive(Debug, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: Option<String>,
}

/// Response containing a new token pair.
#[derive(Debug, Serialize)]
pub struct TokenPairResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: &'static str,
}

/// Response for logout.
#[derive(Debug, Serialize)]
pub struct LogoutResponse {
    pub message: &'static str,
}

/// Response for revoke-all.
#[derive(Debug, Serialize)]
pub struct RevokeAllResponse {
    pub revoked_count: u64,
}

// ── Cookie Helpers ──────────────────────────────────────────────────────

/// Maximum age for access token cookie (15 minutes).
const ACCESS_COOKIE_MAX_AGE_SECS: i64 = 15 * 60;

/// Maximum age for refresh token cookie (30 days).
const REFRESH_COOKIE_MAX_AGE_SECS: i64 = 30 * 24 * 60 * 60;

/// Sets access and refresh token cookies on the response.
pub fn set_token_cookies(
    jar: CookieJar,
    token_pair: &inferadb_ledger_sdk::token::TokenPair,
) -> CookieJar {
    let access_cookie = Cookie::build((ACCESS_TOKEN_COOKIE_NAME, token_pair.access_token.clone()))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::seconds(ACCESS_COOKIE_MAX_AGE_SECS))
        .build();

    let refresh_cookie =
        Cookie::build((REFRESH_TOKEN_COOKIE_NAME, token_pair.refresh_token.clone()))
            .path("/control/v1/auth")
            .http_only(true)
            .secure(true)
            .same_site(SameSite::Lax)
            .max_age(time::Duration::seconds(REFRESH_COOKIE_MAX_AGE_SECS))
            .build();

    jar.add(access_cookie).add(refresh_cookie)
}

/// Clears access and refresh token cookies.
pub fn clear_token_cookies(jar: CookieJar) -> CookieJar {
    jar.remove(Cookie::build(ACCESS_TOKEN_COOKIE_NAME).path("/").build())
        .remove(Cookie::build(REFRESH_TOKEN_COOKIE_NAME).path("/control/v1/auth").build())
}

// ── Handlers ────────────────────────────────────────────────────────────

/// POST /v1/auth/refresh
///
/// Refreshes a token pair using a refresh token from the cookie or request body.
/// Returns a new token pair (rotate-on-use: old refresh token is invalidated).
pub async fn refresh(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<RefreshTokenRequest>,
) -> Result<(CookieJar, Json<TokenPairResponse>), ApiError> {
    let ledger = state
        .ledger
        .as_ref()
        .ok_or_else(|| CoreError::internal("Ledger client not configured"))?;

    // Extract refresh token from body or cookie
    let refresh_token = body
        .refresh_token
        .or_else(|| jar.get(REFRESH_TOKEN_COOKIE_NAME).map(|c| c.value().to_string()))
        .ok_or_else(|| CoreError::auth("no refresh token provided"))?;

    let token_pair = service::session::refresh_token(ledger, &refresh_token).await?;

    let response = TokenPairResponse {
        access_token: token_pair.access_token.clone(),
        refresh_token: token_pair.refresh_token.clone(),
        token_type: "Bearer",
    };

    let jar = set_token_cookies(jar, &token_pair);
    Ok((jar, Json(response)))
}

/// POST /v1/auth/logout
///
/// Revokes the current session's refresh token and clears cookies.
pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, Json<LogoutResponse>), ApiError> {
    let ledger = state
        .ledger
        .as_ref()
        .ok_or_else(|| CoreError::internal("Ledger client not configured"))?;

    // Try to revoke the refresh token if present
    if let Some(cookie) = jar.get(REFRESH_TOKEN_COOKIE_NAME) {
        let refresh_token = cookie.value();
        if !refresh_token.is_empty() {
            // Best-effort revocation — don't fail the logout if revocation fails
            if let Err(e) = service::session::revoke_token(ledger, refresh_token).await {
                tracing::warn!(error = %e, "Failed to revoke refresh token during logout");
            }
        }
    }

    let jar = clear_token_cookies(jar);
    Ok((jar, Json(LogoutResponse { message: "logged out" })))
}

/// POST /v1/auth/revoke-all
///
/// Revokes all sessions for the authenticated user. Requires JWT auth.
pub async fn revoke_all(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<UserClaims>,
    jar: CookieJar,
) -> Result<(CookieJar, Json<RevokeAllResponse>), ApiError> {
    let ledger = state
        .ledger
        .as_ref()
        .ok_or_else(|| CoreError::internal("Ledger client not configured"))?;

    let revoked_count =
        service::session::revoke_all_user_sessions(ledger, claims.user_slug).await?;

    let jar = clear_token_cookies(jar);
    Ok((jar, Json(RevokeAllResponse { revoked_count })))
}
