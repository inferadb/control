//! Multi-factor authentication handlers (TOTP, recovery codes, passkey).
//!
//! These endpoints complete the second-factor step of authentication
//! after primary auth (email code or passkey) returns a TOTP challenge.
//! Passkey handlers implement the full WebAuthn ceremony for both
//! authentication and registration flows.

use std::time::Instant;

use axum::{Extension, Json, extract::State};
use axum_extra::extract::cookie::CookieJar;
use base64::Engine;
use inferadb_control_core::{
    SdkResultExt,
    webauthn::{ChallengeState, credential_info_to_passkey},
};
use inferadb_control_types::Error as CoreError;
use inferadb_ledger_sdk::{CredentialData, CredentialType, PasskeyCredentialInfo};
use inferadb_ledger_types::UserSlug;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::*;

use super::{auth_v2::set_token_cookies, common::require_ledger, state::ApiError};
use crate::{handlers::AppState, middleware::UserClaims};

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
    /// User slug to identify the user for credential lookup.
    pub user_slug: u64,
}

/// Passkey authentication finish request.
#[derive(Debug, Deserialize)]
pub struct PasskeyFinishRequest {
    /// Challenge ID returned from the begin endpoint.
    pub challenge_id: String,
    /// WebAuthn PublicKeyCredential response from the authenticator.
    pub credential: PublicKeyCredential,
}

/// Passkey registration begin request.
#[derive(Debug, Deserialize)]
pub struct PasskeyRegisterBeginRequest {
    /// Optional friendly name for the passkey (e.g., "My MacBook").
    pub name: Option<String>,
}

/// Passkey registration finish request.
#[derive(Debug, Deserialize)]
pub struct PasskeyRegisterFinishRequest {
    /// Challenge ID returned from the begin endpoint.
    pub challenge_id: String,
    /// Friendly name for the passkey.
    pub name: String,
    /// WebAuthn RegisterPublicKeyCredential response from the authenticator.
    pub credential: RegisterPublicKeyCredential,
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

/// Response from passkey authentication begin.
#[derive(Debug, Serialize)]
pub struct PasskeyBeginResponse {
    pub challenge_id: String,
    pub challenge: RequestChallengeResponse,
}

/// Response from passkey authentication finish — either a session or TOTP challenge.
#[derive(Debug, Serialize)]
#[serde(tag = "status")]
pub enum PasskeyFinishResponse {
    /// Session created — no TOTP required.
    #[serde(rename = "authenticated")]
    Authenticated { access_token: String, refresh_token: String, token_type: &'static str },
    /// TOTP is required — complete via `/auth/totp/verify`.
    #[serde(rename = "totp_required")]
    TotpRequired { challenge_nonce: String },
}

/// Response from passkey registration begin.
#[derive(Debug, Serialize)]
pub struct PasskeyRegisterBeginResponse {
    pub challenge_id: String,
    pub challenge: CreationChallengeResponse,
}

/// Response from passkey registration finish.
#[derive(Debug, Serialize)]
pub struct PasskeyRegisterFinishResponse {
    pub slug: u64,
    pub name: String,
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Decodes a base64-encoded challenge nonce.
fn decode_challenge_nonce(nonce_b64: &str) -> Result<Vec<u8>, ApiError> {
    base64::engine::general_purpose::STANDARD
        .decode(nonce_b64)
        .map_err(|_| CoreError::validation("invalid base64 challenge nonce").into())
}

/// Extracts the required WebAuthn instance from app state.
fn require_webauthn(state: &AppState) -> Result<&webauthn_rs::Webauthn, ApiError> {
    state.webauthn.as_deref().ok_or_else(|| CoreError::internal("WebAuthn not configured").into())
}

/// Extracts `PasskeyCredentialInfo` from a `CredentialData::Passkey` variant.
fn extract_passkey_info(data: &CredentialData) -> Option<&PasskeyCredentialInfo> {
    match data {
        CredentialData::Passkey(info) => Some(info),
        _ => None,
    }
}

// ── Handlers ────────────────────────────────────────────────────────────

/// POST /v1/auth/totp/verify
///
/// Verifies a TOTP code against a pending challenge. On success, creates
/// a session and returns a token pair. The challenge nonce is consumed
/// atomically (single-use).
///
/// # Trust assumption
///
/// The `user_slug` is provided by the client (pre-auth endpoint). Ledger's
/// `verify_totp` validates that the challenge nonce was issued for the given
/// user — a mismatched user/nonce pair is rejected server-side.
pub async fn verify_totp(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<VerifyTotpRequest>,
) -> Result<(CookieJar, Json<MfaAuthResponse>), ApiError> {
    let ledger = require_ledger(&state)?;

    let nonce = decode_challenge_nonce(&body.challenge_nonce)?;
    let user = UserSlug::new(body.user_slug);

    let start = Instant::now();
    let token_pair = ledger
        .verify_totp(user, &body.totp_code, nonce)
        .await
        .map_sdk_err_instrumented("verify_totp", start)?;

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
///
/// # Trust assumption
///
/// The `user_slug` is provided by the client (pre-auth endpoint). Ledger's
/// `consume_recovery_code` validates that the challenge nonce was issued for
/// the given user — a mismatched user/nonce pair is rejected server-side.
pub async fn consume_recovery(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<RecoveryCodeRequest>,
) -> Result<(CookieJar, Json<RecoveryCodeResponse>), ApiError> {
    let ledger = require_ledger(&state)?;

    let nonce = decode_challenge_nonce(&body.challenge_nonce)?;
    let user = UserSlug::new(body.user_slug);

    let start = Instant::now();
    let result = ledger
        .consume_recovery_code(user, &body.code, nonce)
        .await
        .map_sdk_err_instrumented("consume_recovery_code", start)?;

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
/// credentials from Ledger, converts them to webauthn-rs `Passkey` types,
/// and generates a WebAuthn authentication challenge.
pub async fn passkey_begin(
    State(state): State<AppState>,
    Json(body): Json<PasskeyBeginRequest>,
) -> Result<Json<PasskeyBeginResponse>, ApiError> {
    let ledger = require_ledger(&state)?;
    let webauthn = require_webauthn(&state)?;
    let user = UserSlug::new(body.user_slug);

    // Fetch the user's passkey credentials from Ledger.
    let start = Instant::now();
    let credentials = ledger
        .list_user_credentials(user, Some(CredentialType::Passkey))
        .await
        .map_sdk_err_instrumented("list_user_credentials", start)?;

    // Convert each credential to a webauthn-rs Passkey.
    let passkeys: Vec<Passkey> = credentials
        .iter()
        .filter_map(|cred| {
            cred.data.as_ref().and_then(extract_passkey_info).map(|info| {
                // Convert SDK PasskeyCredentialInfo to ledger-types PasskeyCredential
                // for the credential_info_to_passkey function.
                let aaguid: Option<[u8; 16]> =
                    info.aaguid.as_ref().and_then(|v| <[u8; 16]>::try_from(v.as_slice()).ok());
                let ledger_passkey = inferadb_ledger_types::PasskeyCredential {
                    credential_id: info.credential_id.clone(),
                    public_key: info.public_key.clone(),
                    sign_count: info.sign_count,
                    transports: info.transports.clone(),
                    backup_eligible: info.backup_eligible,
                    backup_state: info.backup_state,
                    attestation_format: info.attestation_format.clone(),
                    aaguid,
                };
                credential_info_to_passkey(&ledger_passkey)
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    if passkeys.is_empty() {
        return Err(CoreError::validation("no passkey credentials registered for this user").into());
    }

    // Generate the WebAuthn authentication challenge.
    let (challenge, auth_state) = webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|e| CoreError::internal(format!("WebAuthn authentication error: {e}")))?;

    // Store the challenge state for the finish step.
    let challenge_id = state
        .challenge_store
        .insert(ChallengeState::Authentication { user_slug: body.user_slug, state: auth_state })?;

    Ok(Json(PasskeyBeginResponse { challenge_id, challenge }))
}

/// POST /v1/auth/passkey/finish
///
/// Completes the passkey authentication ceremony. Validates the WebAuthn
/// response, updates the sign count in Ledger, and either creates a session
/// or initiates a TOTP challenge if the user has TOTP enabled.
pub async fn passkey_finish(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<PasskeyFinishRequest>,
) -> Result<(CookieJar, Json<PasskeyFinishResponse>), ApiError> {
    let ledger = require_ledger(&state)?;
    let webauthn = require_webauthn(&state)?;

    // Retrieve and consume the challenge state (single-use).
    let challenge_state = state
        .challenge_store
        .take(&body.challenge_id)
        .ok_or_else(|| CoreError::validation("invalid or expired challenge_id"))?;

    let (user_slug_raw, auth_state) = match challenge_state {
        ChallengeState::Authentication { user_slug, state } => (user_slug, state),
        ChallengeState::Registration { .. } => {
            return Err(CoreError::validation(
                "challenge_id refers to a registration, not authentication",
            )
            .into());
        },
    };

    let user = UserSlug::new(user_slug_raw);

    // Validate the WebAuthn response.
    let auth_result = webauthn
        .finish_passkey_authentication(&body.credential, &auth_state)
        .map_err(|e| CoreError::auth(format!("passkey authentication failed: {e}")))?;

    // Update the sign count for the credential that was used.
    // Find the matching credential by comparing credential IDs.
    let used_cred_id: &[u8] = auth_result.cred_id().as_ref();
    let start = Instant::now();
    let credentials = ledger
        .list_user_credentials(user, Some(CredentialType::Passkey))
        .await
        .map_sdk_err_instrumented("list_user_credentials", start)?;

    for cred in &credentials {
        if let Some(passkey_info) = cred.data.as_ref().and_then(extract_passkey_info)
            && passkey_info.credential_id == used_cred_id
        {
            // Build updated passkey data with the new sign count.
            let updated_info = PasskeyCredentialInfo {
                credential_id: passkey_info.credential_id.clone(),
                public_key: passkey_info.public_key.clone(),
                sign_count: auth_result.counter(),
                transports: passkey_info.transports.clone(),
                backup_eligible: auth_result.backup_eligible(),
                backup_state: auth_result.backup_state(),
                attestation_format: passkey_info.attestation_format.clone(),
                aaguid: passkey_info.aaguid.clone(),
            };
            let start = Instant::now();
            let _ = ledger
                .update_user_credential(user, cred.id, None, None, Some(updated_info))
                .await
                .map_sdk_err_instrumented("update_user_credential", start)?;
            break;
        }
    }

    // Check if the user has TOTP enabled.
    let start = Instant::now();
    let totp_credentials = ledger
        .list_user_credentials(user, Some(CredentialType::Totp))
        .await
        .map_sdk_err_instrumented("list_user_credentials", start)?;

    if totp_credentials.is_empty() {
        // No TOTP — create a session directly.
        let start = Instant::now();
        let token_pair = ledger
            .create_user_session(user)
            .await
            .map_sdk_err_instrumented("create_user_session", start)?;
        let jar = set_token_cookies(jar, &token_pair);
        Ok((
            jar,
            Json(PasskeyFinishResponse::Authenticated {
                access_token: token_pair.access_token,
                refresh_token: token_pair.refresh_token,
                token_type: "Bearer",
            }),
        ))
    } else {
        // TOTP is enabled — create a TOTP challenge.
        let start = Instant::now();
        let nonce = ledger
            .create_totp_challenge(user, "passkey")
            .await
            .map_sdk_err_instrumented("create_totp_challenge", start)?;
        let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(&nonce);
        Ok((jar, Json(PasskeyFinishResponse::TotpRequired { challenge_nonce: nonce_b64 })))
    }
}

/// POST /v1/users/me/credentials/passkeys/begin
///
/// Begins a passkey registration ceremony for the authenticated user.
/// Fetches existing passkey credentials to use as exclude list (prevents
/// re-registration of the same authenticator).
pub async fn passkey_register_begin(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Json(body): Json<PasskeyRegisterBeginRequest>,
) -> Result<Json<PasskeyRegisterBeginResponse>, ApiError> {
    let ledger = require_ledger(&state)?;
    let webauthn = require_webauthn(&state)?;
    let user = claims.user_slug;

    let name = body.name.unwrap_or_else(|| "Passkey".to_string());

    // Fetch existing passkey credentials to use as exclude list.
    let start = Instant::now();
    let existing = ledger
        .list_user_credentials(user, Some(CredentialType::Passkey))
        .await
        .map_sdk_err_instrumented("list_user_credentials", start)?;

    let exclude_creds: Vec<CredentialID> = existing
        .iter()
        .filter_map(|cred| {
            cred.data
                .as_ref()
                .and_then(extract_passkey_info)
                .map(|info| CredentialID::from(info.credential_id.clone()))
        })
        .collect();

    let exclude = if exclude_creds.is_empty() { None } else { Some(exclude_creds) };

    // Generate a deterministic UUID from the user slug for WebAuthn user_unique_id.
    let user_uuid = Uuid::from_u64_pair(0, user.value());

    let user_name = format!("user-{}", user.value());

    // Start the registration ceremony.
    let (challenge, reg_state) = webauthn
        .start_passkey_registration(user_uuid, &user_name, &name, exclude)
        .map_err(|e| CoreError::internal(format!("WebAuthn registration error: {e}")))?;

    // Store the challenge state for the finish step.
    let challenge_id = state
        .challenge_store
        .insert(ChallengeState::Registration { user_slug: user.value(), state: reg_state })?;

    Ok(Json(PasskeyRegisterBeginResponse { challenge_id, challenge }))
}

/// POST /v1/users/me/credentials/passkeys/finish
///
/// Completes the passkey registration ceremony. Validates the WebAuthn
/// response and stores the new passkey credential in Ledger.
pub async fn passkey_register_finish(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Json(body): Json<PasskeyRegisterFinishRequest>,
) -> Result<Json<PasskeyRegisterFinishResponse>, ApiError> {
    let ledger = require_ledger(&state)?;
    let webauthn = require_webauthn(&state)?;
    let user = claims.user_slug;

    // Retrieve and consume the challenge state (single-use).
    let challenge_state = state
        .challenge_store
        .take(&body.challenge_id)
        .ok_or_else(|| CoreError::validation("invalid or expired challenge_id"))?;

    let (stored_user_slug, reg_state) = match challenge_state {
        ChallengeState::Registration { user_slug, state } => (user_slug, state),
        ChallengeState::Authentication { .. } => {
            return Err(CoreError::validation(
                "challenge_id refers to an authentication, not registration",
            )
            .into());
        },
    };

    // Verify the challenge belongs to the authenticated user.
    if stored_user_slug != user.value() {
        return Err(CoreError::auth("challenge does not belong to authenticated user").into());
    }

    // Validate the WebAuthn response and get the passkey.
    let passkey = webauthn
        .finish_passkey_registration(&body.credential, &reg_state)
        .map_err(|e| CoreError::validation(format!("passkey registration failed: {e}")))?;

    // Convert webauthn-rs Passkey to SDK CredentialData for Ledger storage.
    // Serialize the entire Passkey as JSON into public_key for lossless round-tripping.
    let cred: Credential = passkey.clone().into();
    let passkey_json = serde_json::to_vec(&passkey)
        .map_err(|e| CoreError::internal(format!("failed to serialize passkey: {e}")))?;

    let transports: Vec<String> = cred
        .transports
        .as_ref()
        .map(|ts| ts.iter().map(|t| format!("{t:?}").to_lowercase()).collect::<Vec<_>>())
        .unwrap_or_default();

    let attestation_format = match cred.attestation_format {
        AttestationFormat::None => None,
        other => Some(format!("{other:?}")),
    };

    let cred_data = CredentialData::Passkey(PasskeyCredentialInfo {
        credential_id: cred.cred_id.as_ref().to_vec(),
        public_key: passkey_json,
        sign_count: cred.counter,
        transports,
        backup_eligible: cred.backup_eligible,
        backup_state: cred.backup_state,
        attestation_format,
        aaguid: None,
    });

    // Store the credential in Ledger.
    let start = Instant::now();
    let created = ledger
        .create_user_credential(user, &body.name, cred_data)
        .await
        .map_sdk_err_instrumented("create_user_credential", start)?;

    let slug = super::common::safe_id_cast(created.id.value())?;

    Ok(Json(PasskeyRegisterFinishResponse { slug, name: created.name }))
}
