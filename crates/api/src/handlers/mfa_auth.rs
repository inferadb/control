//! Multi-factor authentication handlers (TOTP, recovery codes, passkey).
//!
//! These endpoints complete the second-factor step of authentication
//! after primary auth (email code or passkey) returns a TOTP challenge.

use axum::{Json, extract::State};
use axum_extra::extract::cookie::CookieJar;
use base64::Engine;
use inferadb_control_core::service;
use inferadb_ledger_types::UserSlug;
use inferadb_control_types::Error as CoreError;
use serde::{Deserialize, Serialize};

use super::auth::ApiError;
use super::auth_v2::set_token_cookies;
use crate::handlers::AppState;

// ── Request Types ───────────────────────────────────────────────────────

/// TOTP verification request.
#[derive(Debug, Deserialize)]
pub struct VerifyTotpRequest {
    /// User slug (from the initial auth step).
    pub user_slug: u64,
    /// 6 or 8-digit TOTP code from authenticator app.
    pub totp_code: String,
    /// Base64-encoded challenge nonce from the initial auth step.
    pub challenge_nonce: String,
}

/// Recovery code request (TOTP bypass).
#[derive(Debug, Deserialize)]
pub struct RecoveryCodeRequest {
    /// User slug (from the initial auth step).
    pub user_slug: u64,
    /// 8-character alphanumeric recovery code.
    pub code: String,
    /// Base64-encoded challenge nonce from the initial auth step.
    pub challenge_nonce: String,
}

/// Passkey authentication begin request.
#[derive(Debug, Deserialize)]
pub struct PasskeyBeginRequest {
    /// Email address to identify the user (for credential lookup).
    pub email: String,
}

// ── Response Types ──────────────────────────────────────────────────────

/// Response for successful TOTP or recovery code verification.
#[derive(Debug, Serialize)]
pub struct MfaAuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: &'static str,
}

/// Response for recovery code consumption (includes remaining count).
#[derive(Debug, Serialize)]
pub struct RecoveryCodeResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: &'static str,
    pub remaining_codes: u32,
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Decodes a base64-encoded challenge nonce.
fn decode_challenge_nonce(nonce_b64: &str) -> Result<Vec<u8>, ApiError> {
    base64::engine::general_purpose::STANDARD
        .decode(nonce_b64)
        .map_err(|_| CoreError::validation("invalid base64 challenge nonce").into())
}

// ── Handlers ────────────────────────────────────────────────────────────

/// POST /v1/auth/totp/verify
///
/// Verifies a TOTP code against a pending challenge. On success, creates
/// a session and returns a token pair. The challenge nonce is consumed
/// atomically (single-use).
pub async fn verify_totp(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<VerifyTotpRequest>,
) -> Result<(CookieJar, Json<MfaAuthResponse>), ApiError> {
    let ledger = state
        .ledger
        .as_ref()
        .ok_or_else(|| CoreError::internal("Ledger client not configured"))?;

    let nonce = decode_challenge_nonce(&body.challenge_nonce)?;
    let user = UserSlug::new(body.user_slug);

    let token_pair =
        service::credential::verify_totp(ledger, user, &body.totp_code, nonce).await?;

    let jar = set_token_cookies(jar, &token_pair);
    Ok((
        jar,
        Json(MfaAuthResponse {
            access_token: token_pair.access_token,
            refresh_token: token_pair.refresh_token,
            token_type: "Bearer",
        }),
    ))
}

/// POST /v1/auth/recovery
///
/// Consumes a recovery code to bypass TOTP verification. On success,
/// creates a session. Returns the token pair and remaining unused code count.
/// The recovery code is atomically consumed (single-use).
pub async fn consume_recovery(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<RecoveryCodeRequest>,
) -> Result<(CookieJar, Json<RecoveryCodeResponse>), ApiError> {
    let ledger = state
        .ledger
        .as_ref()
        .ok_or_else(|| CoreError::internal("Ledger client not configured"))?;

    let nonce = decode_challenge_nonce(&body.challenge_nonce)?;
    let user = UserSlug::new(body.user_slug);

    let result =
        service::credential::consume_recovery_code(ledger, user, &body.code, nonce).await?;

    let jar = set_token_cookies(jar, &result.tokens);
    Ok((
        jar,
        Json(RecoveryCodeResponse {
            access_token: result.tokens.access_token,
            refresh_token: result.tokens.refresh_token,
            token_type: "Bearer",
            remaining_codes: result.remaining_codes,
        }),
    ))
}

/// POST /v1/auth/passkey/begin
///
/// Begins a passkey authentication ceremony. Fetches the user's passkey
/// credentials from Ledger and generates a WebAuthn challenge.
///
/// NOTE: This is a placeholder — full WebAuthn ceremony integration
/// requires the `webauthn-rs` library and in-memory challenge state
/// management. The implementation will be completed when passkey
/// credential management is migrated in Task 10.
pub async fn passkey_begin(
    State(state): State<AppState>,
    Json(_body): Json<PasskeyBeginRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let _ledger = state
        .ledger
        .as_ref()
        .ok_or_else(|| CoreError::internal("Ledger client not configured"))?;

    // WebAuthn ceremony implementation:
    // 1. Look up user by email (or accept user_slug directly)
    // 2. Fetch passkey credentials from Ledger: list_user_credentials(user, Some(Passkey))
    // 3. Convert Ledger PasskeyCredentialInfo to webauthn-rs Passkey types
    // 4. Generate authentication challenge via webauthn-rs
    // 5. Store challenge in memory (60s TTL)
    // 6. Return challenge JSON to client

    Err(CoreError::internal("passkey auth not yet implemented").into())
}

/// POST /v1/auth/passkey/finish
///
/// Completes the passkey authentication ceremony. Validates the WebAuthn
/// response, updates the sign count, and creates a session (or initiates
/// TOTP challenge if enabled).
///
/// NOTE: Placeholder — see `passkey_begin` for implementation plan.
pub async fn passkey_finish(
    State(state): State<AppState>,
    _jar: CookieJar,
    Json(_body): Json<serde_json::Value>,
) -> Result<(CookieJar, Json<serde_json::Value>), ApiError> {
    let _ledger = state
        .ledger
        .as_ref()
        .ok_or_else(|| CoreError::internal("Ledger client not configured"))?;

    // WebAuthn ceremony implementation:
    // 1. Extract challenge from memory store
    // 2. Validate WebAuthn response via webauthn-rs
    // 3. Update sign_count via update_user_credential()
    // 4. Check if user has TOTP enabled (list_user_credentials with Totp filter)
    // 5a. If TOTP: create_totp_challenge(user, "passkey"), return nonce
    // 5b. If no TOTP: create_user_session(user), return token pair

    Err(CoreError::internal("passkey auth not yet implemented").into())
}
