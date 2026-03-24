//! Authentication session handlers.
//!
//! Token refresh, logout, and revoke-all endpoints that delegate to
//! Ledger's token service.

use std::time::Instant;

use axum::{Json, extract::State};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use inferadb_control_const::{
    auth::{ACCESS_TOKEN_COOKIE_NAME, REFRESH_TOKEN_COOKIE_NAME},
    duration::{ACCESS_COOKIE_MAX_AGE_SECONDS, REFRESH_COOKIE_MAX_AGE_SECONDS},
};
use inferadb_control_core::SdkResultExt;
use inferadb_control_types::Error as CoreError;
use serde::{Deserialize, Serialize};
use time;

use super::{
    common::require_ledger,
    state::{ApiError, AppState},
};
use crate::middleware::UserClaims;

// ── Request/Response Types ──────────────────────────────────────────────

/// Request body for token refresh.
///
/// API clients send the refresh token in the body; web clients use cookies.
#[derive(Debug, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: Option<String>,
}

/// Response containing a session token pair (access + refresh).
#[derive(Debug, Serialize)]
pub struct SessionTokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: &'static str,
}

/// Response confirming logout.
#[derive(Debug, Serialize)]
pub struct LogoutResponse {
    pub message: &'static str,
}

/// Response for the revoke-all-sessions operation.
#[derive(Debug, Serialize)]
pub struct RevokeAllResponse {
    pub revoked_count: u64,
}

// ── Cookie Helpers ──────────────────────────────────────────────────────

/// Sets access and refresh token cookies on the response.
pub fn set_token_cookies(
    jar: CookieJar,
    token_pair: &inferadb_ledger_sdk::token::TokenPair,
) -> CookieJar {
    // Derive access cookie max-age from token expiry when available,
    // falling back to the default constant.
    let access_max_age_secs = token_pair
        .access_expires_at
        .and_then(|expires_at| {
            expires_at.duration_since(std::time::SystemTime::now()).ok().map(|d| d.as_secs() as i64)
        })
        .unwrap_or(ACCESS_COOKIE_MAX_AGE_SECONDS);

    let access_cookie = Cookie::build((ACCESS_TOKEN_COOKIE_NAME, token_pair.access_token.clone()))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::seconds(access_max_age_secs))
        .build();

    let refresh_cookie =
        Cookie::build((REFRESH_TOKEN_COOKIE_NAME, token_pair.refresh_token.clone()))
            .path("/control/v1/auth")
            .http_only(true)
            .secure(true)
            .same_site(SameSite::Lax)
            .max_age(time::Duration::seconds(REFRESH_COOKIE_MAX_AGE_SECONDS))
            .build();

    jar.add(access_cookie).add(refresh_cookie)
}

/// Clears access and refresh token cookies.
pub fn clear_token_cookies(jar: CookieJar) -> CookieJar {
    jar.remove(Cookie::build(ACCESS_TOKEN_COOKIE_NAME).path("/").build())
        .remove(Cookie::build(REFRESH_TOKEN_COOKIE_NAME).path("/control/v1/auth").build())
}

// ── Handlers ────────────────────────────────────────────────────────────

/// POST /control/v1/auth/refresh
///
/// Refreshes a token pair using a refresh token from the cookie or request body.
/// Returns a new token pair (rotate-on-use: old refresh token is invalidated).
pub async fn refresh(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<RefreshTokenRequest>,
) -> Result<(CookieJar, Json<SessionTokenResponse>), ApiError> {
    let ledger = require_ledger(&state)?;

    let refresh_token = body
        .refresh_token
        .or_else(|| jar.get(REFRESH_TOKEN_COOKIE_NAME).map(|c| c.value().to_string()))
        .ok_or_else(|| CoreError::auth("no refresh token provided"))?;

    let start = Instant::now();
    let token_pair = ledger
        .refresh_token(&refresh_token)
        .await
        .map_sdk_err_instrumented("refresh_token", start)?;

    let response = SessionTokenResponse {
        access_token: token_pair.access_token.clone(),
        refresh_token: token_pair.refresh_token.clone(),
        token_type: "Bearer",
    };

    let jar = set_token_cookies(jar, &token_pair);
    Ok((jar, Json(response)))
}

/// POST /control/v1/auth/logout
///
/// Revokes the current session's refresh token and clears cookies.
pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, Json<LogoutResponse>), ApiError> {
    let ledger = require_ledger(&state)?;

    if let Some(cookie) = jar.get(REFRESH_TOKEN_COOKIE_NAME) {
        let refresh_token = cookie.value();
        if !refresh_token.is_empty() {
            // Best-effort revocation — don't fail the logout if revocation fails
            let start = Instant::now();
            if let Err(e) = ledger
                .revoke_token(refresh_token)
                .await
                .map_sdk_err_instrumented("revoke_token", start)
            {
                tracing::warn!(error = %e, "Failed to revoke refresh token during logout");
            }
        }
    }

    let jar = clear_token_cookies(jar);
    Ok((jar, Json(LogoutResponse { message: "logged out" })))
}

/// POST /control/v1/auth/revoke-all
///
/// Revokes all sessions for the authenticated user. Requires JWT auth.
pub async fn revoke_all(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<UserClaims>,
    jar: CookieJar,
) -> Result<(CookieJar, Json<RevokeAllResponse>), ApiError> {
    let ledger = require_ledger(&state)?;

    let start = Instant::now();
    let revoked_count = ledger
        .revoke_all_user_sessions(claims.user_slug)
        .await
        .map_sdk_err_instrumented("revoke_all_user_sessions", start)?;

    let jar = clear_token_cookies(jar);
    Ok((jar, Json(RevokeAllResponse { revoked_count })))
}
