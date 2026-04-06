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
    fn set_token_cookies_adds_access_cookie() {
        let jar = CookieJar::new();
        let pair = make_token_pair();
        let jar = set_token_cookies(jar, &pair);
        let cookie = jar.get(ACCESS_TOKEN_COOKIE_NAME).expect("access cookie should be set");
        assert_eq!(cookie.value(), "test-access-token");
    }

    #[test]
    fn set_token_cookies_adds_refresh_cookie() {
        let jar = CookieJar::new();
        let pair = make_token_pair();
        let jar = set_token_cookies(jar, &pair);
        let cookie = jar.get(REFRESH_TOKEN_COOKIE_NAME).expect("refresh cookie should be set");
        assert_eq!(cookie.value(), "test-refresh-token");
    }

    #[test]
    fn set_token_cookies_access_has_root_path() {
        let jar = CookieJar::new();
        let pair = make_token_pair();
        let jar = set_token_cookies(jar, &pair);
        let cookie = jar.get(ACCESS_TOKEN_COOKIE_NAME).unwrap();
        assert_eq!(cookie.path().unwrap(), "/");
    }

    #[test]
    fn set_token_cookies_refresh_has_auth_path() {
        let jar = CookieJar::new();
        let pair = make_token_pair();
        let jar = set_token_cookies(jar, &pair);
        let cookie = jar.get(REFRESH_TOKEN_COOKIE_NAME).unwrap();
        assert_eq!(cookie.path().unwrap(), "/control/v1/auth");
    }

    #[test]
    fn set_token_cookies_are_http_only() {
        let jar = CookieJar::new();
        let pair = make_token_pair();
        let jar = set_token_cookies(jar, &pair);
        let access = jar.get(ACCESS_TOKEN_COOKIE_NAME).unwrap();
        let refresh = jar.get(REFRESH_TOKEN_COOKIE_NAME).unwrap();
        assert!(access.http_only().unwrap_or(false), "access cookie should be httpOnly");
        assert!(refresh.http_only().unwrap_or(false), "refresh cookie should be httpOnly");
    }

    #[test]
    fn set_token_cookies_are_secure() {
        let jar = CookieJar::new();
        let pair = make_token_pair();
        let jar = set_token_cookies(jar, &pair);
        let access = jar.get(ACCESS_TOKEN_COOKIE_NAME).unwrap();
        let refresh = jar.get(REFRESH_TOKEN_COOKIE_NAME).unwrap();
        assert!(access.secure().unwrap_or(false), "access cookie should be secure");
        assert!(refresh.secure().unwrap_or(false), "refresh cookie should be secure");
    }

    #[test]
    fn set_token_cookies_are_same_site_lax() {
        let jar = CookieJar::new();
        let pair = make_token_pair();
        let jar = set_token_cookies(jar, &pair);
        let access = jar.get(ACCESS_TOKEN_COOKIE_NAME).unwrap();
        let refresh = jar.get(REFRESH_TOKEN_COOKIE_NAME).unwrap();
        assert_eq!(access.same_site(), Some(SameSite::Lax));
        assert_eq!(refresh.same_site(), Some(SameSite::Lax));
    }

    #[test]
    fn set_token_cookies_uses_default_max_age_without_expiry() {
        let jar = CookieJar::new();
        let pair = make_token_pair();
        let jar = set_token_cookies(jar, &pair);
        let access = jar.get(ACCESS_TOKEN_COOKIE_NAME).unwrap();
        let expected = time::Duration::seconds(ACCESS_COOKIE_MAX_AGE_SECONDS);
        assert_eq!(access.max_age(), Some(expected));
    }

    #[test]
    fn set_token_cookies_uses_expiry_based_max_age() {
        let pair = TokenPair {
            access_token: "at".to_string(),
            refresh_token: "rt".to_string(),
            access_expires_at: Some(
                std::time::SystemTime::now() + std::time::Duration::from_secs(300),
            ),
            refresh_expires_at: None,
        };
        let jar = set_token_cookies(CookieJar::new(), &pair);
        let access = jar.get(ACCESS_TOKEN_COOKIE_NAME).unwrap();
        let max_age_secs = access.max_age().unwrap().whole_seconds();
        // Should be approximately 300 seconds (allow some slack for test execution)
        assert!((295..=305).contains(&max_age_secs), "max_age should be ~300s, got {max_age_secs}");
    }

    // ── clear_token_cookies ───────────────────────────────────────────

    #[test]
    fn clear_token_cookies_removes_access_cookie() {
        let jar = CookieJar::new();
        let pair = make_token_pair();
        let jar = set_token_cookies(jar, &pair);
        assert!(jar.get(ACCESS_TOKEN_COOKIE_NAME).is_some());
        let jar = clear_token_cookies(jar);
        // After clearing, the cookie should be a removal cookie (empty value)
        let cookie = jar.get(ACCESS_TOKEN_COOKIE_NAME);
        assert!(
            cookie.is_none() || cookie.is_some_and(|c| c.value().is_empty()),
            "access cookie should be removed or empty after clearing"
        );
    }

    #[test]
    fn clear_token_cookies_removes_refresh_cookie() {
        let jar = CookieJar::new();
        let pair = make_token_pair();
        let jar = set_token_cookies(jar, &pair);
        assert!(jar.get(REFRESH_TOKEN_COOKIE_NAME).is_some());
        let jar = clear_token_cookies(jar);
        let cookie = jar.get(REFRESH_TOKEN_COOKIE_NAME);
        assert!(
            cookie.is_none() || cookie.is_some_and(|c| c.value().is_empty()),
            "refresh cookie should be removed or empty after clearing"
        );
    }

    #[test]
    fn clear_token_cookies_on_empty_jar_is_noop() {
        let jar = CookieJar::new();
        let jar = clear_token_cookies(jar);
        // Should not panic and jar should have no meaningful cookies
        assert!(
            jar.get(ACCESS_TOKEN_COOKIE_NAME).is_none()
                || jar.get(ACCESS_TOKEN_COOKIE_NAME).is_some_and(|c| c.value().is_empty())
        );
    }

    // ── Response type serialization ───────────────────────────────────

    #[test]
    fn session_token_response_serializes() {
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
    fn logout_response_serializes() {
        let resp = LogoutResponse { message: "logged out" };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["message"], "logged out");
    }

    #[test]
    fn revoke_all_response_serializes() {
        let resp = RevokeAllResponse { revoked_count: 5 };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["revoked_count"], 5);
    }

    #[test]
    fn refresh_token_request_deserializes_with_token() {
        let json = r#"{"refresh_token": "tok"}"#;
        let req: RefreshTokenRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.refresh_token.as_deref(), Some("tok"));
    }

    #[test]
    fn refresh_token_request_deserializes_without_token() {
        let json = r#"{}"#;
        let req: RefreshTokenRequest = serde_json::from_str(json).unwrap();
        assert!(req.refresh_token.is_none());
    }
}
