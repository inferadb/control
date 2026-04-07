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
    /// JWT access token.
    pub access_token: String,
    /// Opaque refresh token for obtaining new access tokens.
    pub refresh_token: String,
    /// Token type (always `"Bearer"`).
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use inferadb_ledger_sdk::token::TokenPair;

    use super::*;

    fn make_token_pair() -> TokenPair {
        TokenPair {
            access_token: "test-access-token".to_string(),
            refresh_token: "test-refresh-token".to_string(),
            access_expires_at: None,
            refresh_expires_at: None,
        }
    }

    // ── set_token_cookies ─────────────────────────────────────────────

    #[test]
    fn test_set_token_cookies_values_match_token_pair() {
        let jar = set_token_cookies(CookieJar::new(), &make_token_pair());

        let access = jar.get(ACCESS_TOKEN_COOKIE_NAME).expect("access cookie missing");
        assert_eq!(access.value(), "test-access-token");

        let refresh = jar.get(REFRESH_TOKEN_COOKIE_NAME).expect("refresh cookie missing");
        assert_eq!(refresh.value(), "test-refresh-token");
    }

    #[test]
    fn test_set_token_cookies_access_path_is_root() {
        let jar = set_token_cookies(CookieJar::new(), &make_token_pair());
        let cookie = jar.get(ACCESS_TOKEN_COOKIE_NAME).unwrap();
        assert_eq!(cookie.path().unwrap(), "/");
    }

    #[test]
    fn test_set_token_cookies_refresh_path_is_auth_scope() {
        let jar = set_token_cookies(CookieJar::new(), &make_token_pair());
        let cookie = jar.get(REFRESH_TOKEN_COOKIE_NAME).unwrap();
        assert_eq!(cookie.path().unwrap(), "/control/v1/auth");
    }

    #[test]
    fn test_set_token_cookies_security_attributes() {
        let jar = set_token_cookies(CookieJar::new(), &make_token_pair());
        let access = jar.get(ACCESS_TOKEN_COOKIE_NAME).unwrap();
        let refresh = jar.get(REFRESH_TOKEN_COOKIE_NAME).unwrap();

        for (label, cookie) in [("access", &access), ("refresh", &refresh)] {
            assert!(cookie.http_only().unwrap_or(false), "{label} cookie should be httpOnly");
            assert!(cookie.secure().unwrap_or(false), "{label} cookie should be secure");
            assert_eq!(cookie.same_site(), Some(SameSite::Lax), "{label} cookie should be Lax");
        }
    }

    #[test]
    fn test_set_token_cookies_no_expiry_uses_default_max_age() {
        let jar = set_token_cookies(CookieJar::new(), &make_token_pair());
        let access = jar.get(ACCESS_TOKEN_COOKIE_NAME).unwrap();
        assert_eq!(access.max_age(), Some(time::Duration::seconds(ACCESS_COOKIE_MAX_AGE_SECONDS)));
    }

    #[test]
    fn test_set_token_cookies_with_expiry_derives_max_age() {
        let pair = TokenPair {
            access_token: "at".to_string(),
            refresh_token: "rt".to_string(),
            access_expires_at: Some(
                std::time::SystemTime::now() + std::time::Duration::from_secs(300),
            ),
            refresh_expires_at: None,
        };
        let jar = set_token_cookies(CookieJar::new(), &pair);
        let max_age_secs = jar.get(ACCESS_TOKEN_COOKIE_NAME).unwrap().max_age().unwrap().whole_seconds();
        assert!((295..=305).contains(&max_age_secs), "max_age should be ~300s, got {max_age_secs}");
    }

    #[test]
    fn test_set_token_cookies_refresh_has_expected_max_age() {
        let jar = set_token_cookies(CookieJar::new(), &make_token_pair());
        let refresh = jar.get(REFRESH_TOKEN_COOKIE_NAME).unwrap();
        assert_eq!(
            refresh.max_age(),
            Some(time::Duration::seconds(REFRESH_COOKIE_MAX_AGE_SECONDS))
        );
    }

    // ── clear_token_cookies ───────────────────────────────────────────

    #[test]
    fn test_clear_token_cookies_removes_both_cookies() {
        let jar = set_token_cookies(CookieJar::new(), &make_token_pair());
        assert!(jar.get(ACCESS_TOKEN_COOKIE_NAME).is_some());
        assert!(jar.get(REFRESH_TOKEN_COOKIE_NAME).is_some());

        let jar = clear_token_cookies(jar);

        let is_removed = |c: Option<&Cookie>| c.is_none() || c.is_some_and(|c| c.value().is_empty());
        assert!(is_removed(jar.get(ACCESS_TOKEN_COOKIE_NAME)), "access cookie should be cleared");
        assert!(is_removed(jar.get(REFRESH_TOKEN_COOKIE_NAME)), "refresh cookie should be cleared");
    }

    #[test]
    fn test_clear_token_cookies_empty_jar_does_not_panic() {
        let jar = clear_token_cookies(CookieJar::new());
        let is_removed = |c: Option<&Cookie>| c.is_none() || c.is_some_and(|c| c.value().is_empty());
        assert!(is_removed(jar.get(ACCESS_TOKEN_COOKIE_NAME)));
    }

    // ── SessionTokenResponse serialization ────────────────────────────

    #[test]
    fn test_session_token_response_serializes_all_fields() {
        let resp = SessionTokenResponse {
            access_token: "at".to_string(),
            refresh_token: "rt".to_string(),
            token_type: "Bearer",
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["access_token"], "at");
        assert_eq!(json["refresh_token"], "rt");
        assert_eq!(json["token_type"], "Bearer");
    }

    #[test]
    fn test_logout_response_serializes() {
        let json = serde_json::to_value(&LogoutResponse { message: "logged out" }).unwrap();
        assert_eq!(json["message"], "logged out");
    }

    #[test]
    fn test_revoke_all_response_serializes_count() {
        let json = serde_json::to_value(&RevokeAllResponse { revoked_count: 5 }).unwrap();
        assert_eq!(json["revoked_count"], 5);
    }

    #[test]
    fn test_revoke_all_response_serializes_zero_count() {
        let json = serde_json::to_value(&RevokeAllResponse { revoked_count: 0 }).unwrap();
        assert_eq!(json["revoked_count"], 0);
    }

    // ── RefreshTokenRequest deserialization ───────────────────────────

    #[test]
    fn test_refresh_token_request_with_token() {
        let req: RefreshTokenRequest = serde_json::from_str(r#"{"refresh_token": "tok"}"#).unwrap();
        assert_eq!(req.refresh_token.as_deref(), Some("tok"));
    }

    #[test]
    fn test_refresh_token_request_without_token() {
        let req: RefreshTokenRequest = serde_json::from_str(r#"{}"#).unwrap();
        assert!(req.refresh_token.is_none());
    }

    #[test]
    fn test_refresh_token_request_with_null_token() {
        let req: RefreshTokenRequest =
            serde_json::from_str(r#"{"refresh_token": null}"#).unwrap();
        assert!(req.refresh_token.is_none());
    }
}
