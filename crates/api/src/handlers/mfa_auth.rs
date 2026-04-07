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

use super::{auth::set_token_cookies, common::require_ledger, state::ApiError};
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

/// Response containing session tokens after TOTP verification.
#[derive(Debug, Serialize)]
pub struct MfaAuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: &'static str,
}

/// Response containing session tokens and the remaining recovery code count.
#[derive(Debug, Serialize)]
pub struct RecoveryCodeResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: &'static str,
    pub remaining_codes: u32,
}

/// Response from the passkey authentication begin step.
#[derive(Debug, Serialize)]
pub struct PasskeyBeginResponse {
    pub challenge_id: String,
    pub challenge: RequestChallengeResponse,
}

/// Response from passkey authentication completion.
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

/// Response from the passkey registration begin step.
#[derive(Debug, Serialize)]
pub struct PasskeyRegisterBeginResponse {
    pub challenge_id: String,
    pub challenge: CreationChallengeResponse,
}

/// Response from the passkey registration finish step.
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

/// Extracts [`PasskeyCredentialInfo`] from a [`CredentialData::Passkey`] variant.
fn extract_passkey_info(data: &CredentialData) -> Option<&PasskeyCredentialInfo> {
    match data {
        CredentialData::Passkey(info) => Some(info),
        _ => None,
    }
}

// ── Challenge State Helpers ────────────────────────────────────────────

/// Retrieves and validates an authentication challenge from the store.
///
/// Consumes the challenge (single-use). Returns an error if the challenge
/// does not exist or is a registration challenge (type mismatch).
fn take_auth_challenge(
    store: &inferadb_control_core::webauthn::ChallengeStore,
    challenge_id: &str,
) -> Result<(u64, PasskeyAuthentication), ApiError> {
    let challenge_state = store
        .take(challenge_id)
        .ok_or_else(|| CoreError::validation("invalid or expired challenge_id"))?;

    match challenge_state {
        ChallengeState::Authentication { user_slug, state } => Ok((user_slug, state)),
        ChallengeState::Registration { .. } => {
            Err(CoreError::validation("challenge_id refers to a registration, not authentication")
                .into())
        },
    }
}

/// Retrieves and validates a registration challenge from the store.
///
/// Consumes the challenge (single-use). Returns an error if the challenge
/// does not exist, is an authentication challenge (type mismatch), or
/// belongs to a different user than `expected_user`.
fn take_registration_challenge(
    store: &inferadb_control_core::webauthn::ChallengeStore,
    challenge_id: &str,
    expected_user: u64,
) -> Result<PasskeyRegistration, ApiError> {
    let challenge_state = store
        .take(challenge_id)
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

    if stored_user_slug != expected_user {
        return Err(CoreError::auth("challenge does not belong to authenticated user").into());
    }

    Ok(reg_state)
}

// ── Credential Conversion ─────────────────────────────────────────────

/// Builds an updated [`PasskeyCredentialInfo`] with a new sign count and backup state.
///
/// Used after successful passkey authentication to persist the authenticator's
/// updated counter and backup flags.
fn build_updated_passkey_info(
    existing: &PasskeyCredentialInfo,
    new_sign_count: u32,
    backup_eligible: bool,
    backup_state: bool,
) -> PasskeyCredentialInfo {
    PasskeyCredentialInfo {
        credential_id: existing.credential_id.clone(),
        public_key: existing.public_key.clone(),
        sign_count: new_sign_count,
        transports: existing.transports.clone(),
        backup_eligible,
        backup_state,
        attestation_format: existing.attestation_format.clone(),
        aaguid: existing.aaguid.clone(),
    }
}

/// Converts a webauthn-rs [`Credential`] into SDK [`CredentialData`] for Ledger storage.
///
/// Serializes the full passkey as JSON (for the `public_key` field), formats
/// transport names as lowercase strings, and maps `AttestationFormat::None` to `None`.
fn credential_to_sdk_data(
    cred: &Credential,
    passkey: &Passkey,
) -> Result<CredentialData, ApiError> {
    let passkey_json = serde_json::to_vec(passkey)
        .map_err(|e| CoreError::internal(format!("failed to serialize passkey: {e}")))?;

    let transports: Vec<String> = cred
        .transports
        .as_ref()
        .map(|ts| ts.iter().map(|t| format!("{t:?}").to_lowercase()).collect::<Vec<_>>())
        .unwrap_or_default();

    let attestation_format = match cred.attestation_format {
        AttestationFormat::None => None,
        ref other => Some(format!("{other:?}")),
    };

    Ok(CredentialData::Passkey(PasskeyCredentialInfo {
        credential_id: cred.cred_id.as_ref().to_vec(),
        public_key: passkey_json,
        sign_count: cred.counter,
        transports,
        backup_eligible: cred.backup_eligible,
        backup_state: cred.backup_state,
        attestation_format,
        aaguid: None,
    }))
}

// ── Handlers ────────────────────────────────────────────────────────────

/// POST /control/v1/auth/totp/verify
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
        .verify_totp(user, user, &body.totp_code, nonce)
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

/// POST /control/v1/auth/recovery
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
        .consume_recovery_code(user, user, &body.code, nonce)
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

/// POST /control/v1/auth/passkey/begin
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
        .list_user_credentials(user, user, Some(CredentialType::Passkey))
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

/// POST /control/v1/auth/passkey/finish
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

    let (user_slug_raw, auth_state) =
        take_auth_challenge(&state.challenge_store, &body.challenge_id)?;
    let user = UserSlug::new(user_slug_raw);

    // Validate the WebAuthn response.
    let auth_result = webauthn
        .finish_passkey_authentication(&body.credential, &auth_state)
        .map_err(|e| CoreError::auth(format!("passkey authentication failed: {e}")))?;

    // Fetch passkey and TOTP credentials concurrently — these are independent reads.
    let used_cred_id: &[u8] = auth_result.cred_id().as_ref();
    let start_creds = Instant::now();
    let (passkey_result, totp_result) = tokio::join!(
        ledger.list_user_credentials(user, user, Some(CredentialType::Passkey)),
        ledger.list_user_credentials(user, user, Some(CredentialType::Totp)),
    );
    let credentials =
        passkey_result.map_sdk_err_instrumented("list_user_credentials", start_creds)?;
    let totp_credentials =
        totp_result.map_sdk_err_instrumented("list_user_credentials", start_creds)?;

    // Update the sign count for the credential that was used.
    for cred in &credentials {
        if let Some(passkey_info) = cred.data.as_ref().and_then(extract_passkey_info)
            && passkey_info.credential_id == used_cred_id
        {
            let updated_info = build_updated_passkey_info(
                passkey_info,
                auth_result.counter(),
                auth_result.backup_eligible(),
                auth_result.backup_state(),
            );
            let start = Instant::now();
            let _ = ledger
                .update_user_credential(user, user, cred.id, None, None, Some(updated_info))
                .await
                .map_sdk_err_instrumented("update_user_credential", start)?;
            break;
        }
    }

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
            .create_totp_challenge(user, user, "passkey")
            .await
            .map_sdk_err_instrumented("create_totp_challenge", start)?;
        let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(&nonce);
        Ok((jar, Json(PasskeyFinishResponse::TotpRequired { challenge_nonce: nonce_b64 })))
    }
}

/// POST /control/v1/users/me/credentials/passkeys/begin
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
    super::common::validate_name(&name)?;

    // Fetch existing passkey credentials to use as exclude list.
    let start = Instant::now();
    let existing = ledger
        .list_user_credentials(user, user, Some(CredentialType::Passkey))
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

/// POST /control/v1/users/me/credentials/passkeys/finish
///
/// Completes the passkey registration ceremony. Validates the WebAuthn
/// response and stores the new passkey credential in Ledger.
pub async fn passkey_register_finish(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Json(body): Json<PasskeyRegisterFinishRequest>,
) -> Result<Json<PasskeyRegisterFinishResponse>, ApiError> {
    super::common::validate_name(&body.name)?;
    let ledger = require_ledger(&state)?;
    let webauthn = require_webauthn(&state)?;
    let user = claims.user_slug;

    let reg_state =
        take_registration_challenge(&state.challenge_store, &body.challenge_id, user.value())?;

    // Validate the WebAuthn response and get the passkey.
    let passkey = webauthn
        .finish_passkey_registration(&body.credential, &reg_state)
        .map_err(|e| CoreError::validation(format!("passkey registration failed: {e}")))?;

    let cred: Credential = passkey.clone().into();
    let cred_data = credential_to_sdk_data(&cred, &passkey)?;

    // Store the credential in Ledger.
    let start = Instant::now();
    let created = ledger
        .create_user_credential(user, user, &body.name, cred_data)
        .await
        .map_sdk_err_instrumented("create_user_credential", start)?;

    let slug = super::common::safe_id_cast(created.id.value())?;

    Ok(Json(PasskeyRegisterFinishResponse { slug, name: created.name }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // ── decode_challenge_nonce ───────────────────────────────────────────

    #[test]
    fn test_decode_challenge_nonce_valid_base64_returns_bytes() {
        let encoded = base64::engine::general_purpose::STANDARD.encode(b"hello");

        let result = decode_challenge_nonce(&encoded).unwrap();

        assert_eq!(result, b"hello");
    }

    #[test]
    fn test_decode_challenge_nonce_empty_input_returns_empty_vec() {
        let encoded = base64::engine::general_purpose::STANDARD.encode(b"");

        let result = decode_challenge_nonce(&encoded).unwrap();

        assert!(result.is_empty());
    }

    #[test]
    fn test_decode_challenge_nonce_invalid_base64_returns_error() {
        let result = decode_challenge_nonce("not-valid-base64!!!");

        assert!(result.is_err());
    }

    #[test]
    fn test_decode_challenge_nonce_binary_payload_round_trips() {
        let payload: Vec<u8> = (0..=255).collect();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&payload);

        let result = decode_challenge_nonce(&encoded).unwrap();

        assert_eq!(result, payload);
    }

    // ── extract_passkey_info ────────────────────────────────────────────

    #[test]
    fn test_extract_passkey_info_passkey_variant_returns_inner() {
        let info = PasskeyCredentialInfo {
            credential_id: vec![1, 2, 3],
            public_key: vec![4, 5, 6],
            sign_count: 42,
            transports: vec!["usb".to_string()],
            backup_eligible: true,
            backup_state: false,
            attestation_format: None,
            aaguid: None,
        };
        let data = CredentialData::Passkey(info);

        let result = extract_passkey_info(&data);

        let extracted = result.expect("should return Some for Passkey variant");
        assert_eq!(extracted.credential_id, vec![1, 2, 3]);
        assert_eq!(extracted.sign_count, 42);
    }

    #[test]
    fn test_extract_passkey_info_non_passkey_variants_return_none() {
        let cases: Vec<(&str, CredentialData)> = vec![
            (
                "Totp",
                CredentialData::Totp(inferadb_ledger_sdk::TotpCredentialInfo {
                    secret: vec![],
                    algorithm: inferadb_ledger_sdk::TotpAlgorithm::Sha1,
                    digits: 6,
                    period: 30,
                }),
            ),
            (
                "RecoveryCode",
                CredentialData::RecoveryCode(inferadb_ledger_sdk::RecoveryCodeCredentialInfo {
                    code_hashes: vec![],
                    total_generated: 10,
                }),
            ),
        ];

        for (label, data) in cases {
            assert!(extract_passkey_info(&data).is_none(), "{label} variant should return None");
        }
    }

    // ── Request type deserialization ────────────────────────────────────

    #[test]
    fn test_verify_totp_request_deserializes_all_fields() {
        let json = r#"{"user_slug": 42, "totp_code": "123456", "challenge_nonce": "dGVzdA=="}"#;

        let req: VerifyTotpRequest = serde_json::from_str(json).unwrap();

        assert_eq!(req.user_slug, 42);
        assert_eq!(req.totp_code, "123456");
        assert_eq!(req.challenge_nonce, "dGVzdA==");
    }

    #[test]
    fn test_recovery_code_request_deserializes_all_fields() {
        let json = r#"{"user_slug": 7, "code": "ABCD1234", "challenge_nonce": "bm9uY2U="}"#;

        let req: RecoveryCodeRequest = serde_json::from_str(json).unwrap();

        assert_eq!(req.user_slug, 7);
        assert_eq!(req.code, "ABCD1234");
        assert_eq!(req.challenge_nonce, "bm9uY2U=");
    }

    #[test]
    fn test_passkey_begin_request_deserializes_user_slug() {
        let json = r#"{"user_slug": 100}"#;

        let req: PasskeyBeginRequest = serde_json::from_str(json).unwrap();

        assert_eq!(req.user_slug, 100);
    }

    #[test]
    fn test_passkey_register_begin_request_with_name() {
        let json = r#"{"name": "My MacBook"}"#;

        let req: PasskeyRegisterBeginRequest = serde_json::from_str(json).unwrap();

        assert_eq!(req.name.as_deref(), Some("My MacBook"));
    }

    #[test]
    fn test_passkey_register_begin_request_without_name() {
        let req: PasskeyRegisterBeginRequest = serde_json::from_str(r#"{}"#).unwrap();

        assert!(req.name.is_none());
    }

    // ── Response type serialization ────────────────────────────────────

    #[test]
    fn test_mfa_auth_response_serializes_all_fields() {
        let resp = MfaAuthResponse {
            access_token: "acc".to_string(),
            refresh_token: "ref".to_string(),
            token_type: "Bearer",
        };

        let json = serde_json::to_value(&resp).unwrap();

        assert_eq!(json["access_token"], "acc");
        assert_eq!(json["refresh_token"], "ref");
        assert_eq!(json["token_type"], "Bearer");
    }

    #[test]
    fn test_recovery_code_response_serializes_all_fields() {
        let resp = RecoveryCodeResponse {
            access_token: "a".to_string(),
            refresh_token: "r".to_string(),
            token_type: "Bearer",
            remaining_codes: 5,
        };

        let json = serde_json::to_value(&resp).unwrap();

        assert_eq!(json["access_token"], "a");
        assert_eq!(json["refresh_token"], "r");
        assert_eq!(json["remaining_codes"], 5);
        assert_eq!(json["token_type"], "Bearer");
    }

    #[test]
    fn test_passkey_finish_response_authenticated_includes_tag_and_tokens() {
        let resp = PasskeyFinishResponse::Authenticated {
            access_token: "at".to_string(),
            refresh_token: "rt".to_string(),
            token_type: "Bearer",
        };

        let json = serde_json::to_value(&resp).unwrap();

        assert_eq!(json["status"], "authenticated");
        assert_eq!(json["access_token"], "at");
        assert_eq!(json["refresh_token"], "rt");
        assert!(json.get("challenge_nonce").is_none());
    }

    #[test]
    fn test_passkey_finish_response_totp_required_includes_tag_without_tokens() {
        let resp = PasskeyFinishResponse::TotpRequired { challenge_nonce: "abc123".to_string() };

        let json = serde_json::to_value(&resp).unwrap();

        assert_eq!(json["status"], "totp_required");
        assert_eq!(json["challenge_nonce"], "abc123");
        assert!(json.get("access_token").is_none());
        assert!(json.get("refresh_token").is_none());
    }

    #[test]
    fn test_passkey_register_finish_response_serializes_all_fields() {
        let resp = PasskeyRegisterFinishResponse { slug: 42, name: "My Key".to_string() };

        let json = serde_json::to_value(&resp).unwrap();

        assert_eq!(json["slug"], 42);
        assert_eq!(json["name"], "My Key");
    }

    // ── require_webauthn ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_require_webauthn_unconfigured_returns_error() {
        let state = AppState::new_test();

        let result = require_webauthn(&state);

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_require_webauthn_configured_returns_ok() {
        use std::sync::Arc;

        let mut state = AppState::new_test();
        let webauthn =
            inferadb_control_core::webauthn::build_webauthn("localhost", "http://localhost")
                .unwrap();
        state.webauthn = Some(Arc::new(webauthn));

        let result = require_webauthn(&state);

        assert!(result.is_ok());
    }

    // ── validate_name for passkey registration ────────────────────────

    #[test]
    fn test_validate_name_accepts_valid_passkey_names() {
        let valid_names =
            ["My MacBook", "Touch ID", "YubiKey 5", "Work Laptop's Key", "key-1", "key_2", "v1.0"];

        for name in valid_names {
            assert!(super::super::common::validate_name(name).is_ok(), "expected valid: {name:?}");
        }
    }

    #[test]
    fn test_validate_name_rejects_invalid_passkey_names() {
        let invalid_names = [
            ("", "empty"),
            ("   ", "whitespace only"),
            ("<script>alert(1)</script>", "script injection"),
            ("key@home", "at sign"),
            ("key#1", "hash"),
            ("key&co", "ampersand"),
            ("key;drop", "semicolon"),
            (&"a".repeat(129), "exceeds max length"),
        ];

        for (name, label) in invalid_names {
            assert!(
                super::super::common::validate_name(name).is_err(),
                "expected invalid ({label}): {name:?}"
            );
        }
    }

    #[test]
    fn test_validate_name_accepts_max_length() {
        let exact = "a".repeat(128);

        assert!(super::super::common::validate_name(&exact).is_ok());
    }

    // ── Challenge store helpers ────────────────────────────────────────

    fn test_challenge_store() -> inferadb_control_core::webauthn::ChallengeStore {
        inferadb_control_core::webauthn::ChallengeStore::default()
    }

    fn test_webauthn() -> webauthn_rs::Webauthn {
        inferadb_control_core::webauthn::build_webauthn("localhost", "http://localhost:3000")
            .unwrap()
    }

    #[test]
    fn test_take_auth_challenge_missing_id_returns_error() {
        let store = test_challenge_store();

        let result = take_auth_challenge(&store, "nonexistent");

        assert!(result.is_err());
    }

    #[test]
    fn test_take_auth_challenge_registration_state_returns_type_mismatch_error() {
        let store = test_challenge_store();
        let webauthn = test_webauthn();
        let user_uuid = uuid::Uuid::from_u64_pair(0, 42);
        let (_, reg_state) =
            webauthn.start_passkey_registration(user_uuid, "test-user", "Test Key", None).unwrap();
        let state = ChallengeState::Registration { user_slug: 42, state: reg_state };
        let token = store.insert(state).unwrap();

        let result = take_auth_challenge(&store, &token);

        assert!(result.is_err());
    }

    #[test]
    fn test_take_auth_challenge_consumes_token_single_use() {
        let store = test_challenge_store();
        let webauthn = test_webauthn();
        let user_uuid = uuid::Uuid::from_u64_pair(0, 42);
        let (_, reg_state) =
            webauthn.start_passkey_registration(user_uuid, "test-user", "Key", None).unwrap();
        let state = ChallengeState::Registration { user_slug: 42, state: reg_state };
        let token = store.insert(state).unwrap();

        // First take consumes it (returns error because type mismatch, but still consumed)
        let _ = take_auth_challenge(&store, &token);
        // Second take should fail because token is consumed
        let result = take_auth_challenge(&store, &token);

        assert!(result.is_err());
    }

    #[test]
    fn test_take_registration_challenge_missing_id_returns_error() {
        let store = test_challenge_store();

        let result = take_registration_challenge(&store, "nonexistent", 42);

        assert!(result.is_err());
    }

    #[test]
    fn test_take_registration_challenge_wrong_user_returns_error() {
        let store = test_challenge_store();
        let webauthn = test_webauthn();
        let user_uuid = uuid::Uuid::from_u64_pair(0, 42);
        let (_, reg_state) =
            webauthn.start_passkey_registration(user_uuid, "test-user", "Test Key", None).unwrap();
        let state = ChallengeState::Registration { user_slug: 42, state: reg_state };
        let token = store.insert(state).unwrap();

        let result = take_registration_challenge(&store, &token, 99);

        assert!(result.is_err());
    }

    #[test]
    fn test_take_registration_challenge_correct_user_returns_state() {
        let store = test_challenge_store();
        let webauthn = test_webauthn();
        let user_uuid = uuid::Uuid::from_u64_pair(0, 42);
        let (_, reg_state) =
            webauthn.start_passkey_registration(user_uuid, "test-user", "Test Key", None).unwrap();
        let state = ChallengeState::Registration { user_slug: 42, state: reg_state };
        let token = store.insert(state).unwrap();

        let result = take_registration_challenge(&store, &token, 42);

        assert!(result.is_ok());
    }

    // ── build_updated_passkey_info ────────────────────────────────────

    #[test]
    fn test_build_updated_passkey_info_updates_mutable_fields_preserves_immutable() {
        let existing = PasskeyCredentialInfo {
            credential_id: vec![1, 2, 3],
            public_key: vec![4, 5, 6],
            sign_count: 10,
            transports: vec!["usb".to_string()],
            backup_eligible: false,
            backup_state: false,
            attestation_format: Some("packed".to_string()),
            aaguid: Some(vec![0u8; 16]),
        };

        let updated = build_updated_passkey_info(&existing, 42, true, true);

        // Preserved fields
        assert_eq!(updated.credential_id, vec![1, 2, 3]);
        assert_eq!(updated.public_key, vec![4, 5, 6]);
        assert_eq!(updated.transports, vec!["usb".to_string()]);
        assert_eq!(updated.attestation_format, Some("packed".to_string()));
        assert_eq!(updated.aaguid, Some(vec![0u8; 16]));
        // Updated fields
        assert_eq!(updated.sign_count, 42);
        assert!(updated.backup_eligible);
        assert!(updated.backup_state);
    }

    #[test]
    fn test_build_updated_passkey_info_preserves_none_optional_fields() {
        let existing = PasskeyCredentialInfo {
            credential_id: vec![],
            public_key: vec![],
            sign_count: 0,
            transports: vec![],
            backup_eligible: false,
            backup_state: false,
            attestation_format: None,
            aaguid: None,
        };

        let updated = build_updated_passkey_info(&existing, 1, false, false);

        assert!(updated.attestation_format.is_none());
        assert!(updated.aaguid.is_none());
        assert_eq!(updated.sign_count, 1);
    }
}
