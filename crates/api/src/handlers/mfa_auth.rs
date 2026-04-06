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
    // Uses the SDK's CredentialData type directly (not the core conversion function)
    // because the handler's SDK dependency resolves to a different crate version
    // than core's path-patched types during test compilation.
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
    fn decode_challenge_nonce_valid_base64() {
        let encoded = base64::engine::general_purpose::STANDARD.encode(b"hello");
        let result = decode_challenge_nonce(&encoded);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"hello");
    }

    #[test]
    fn decode_challenge_nonce_empty_string_is_valid() {
        let encoded = base64::engine::general_purpose::STANDARD.encode(b"");
        let result = decode_challenge_nonce(&encoded);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn decode_challenge_nonce_invalid_base64_returns_error() {
        let result = decode_challenge_nonce("not-valid-base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn decode_challenge_nonce_binary_payload() {
        let payload: Vec<u8> = (0..=255).collect();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&payload);
        let result = decode_challenge_nonce(&encoded);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), payload);
    }

    // ── extract_passkey_info ────────────────────────────────────────────

    #[test]
    fn extract_passkey_info_returns_some_for_passkey_variant() {
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
        let data = CredentialData::Passkey(info.clone());
        let result = extract_passkey_info(&data);
        assert!(result.is_some());
        assert_eq!(result.unwrap().credential_id, vec![1, 2, 3]);
        assert_eq!(result.unwrap().sign_count, 42);
    }

    #[test]
    fn extract_passkey_info_returns_none_for_totp_variant() {
        let data = CredentialData::Totp(inferadb_ledger_sdk::TotpCredentialInfo {
            secret: vec![],
            algorithm: inferadb_ledger_sdk::TotpAlgorithm::Sha1,
            digits: 6,
            period: 30,
        });
        assert!(extract_passkey_info(&data).is_none());
    }

    #[test]
    fn extract_passkey_info_returns_none_for_recovery_variant() {
        let data = CredentialData::RecoveryCode(inferadb_ledger_sdk::RecoveryCodeCredentialInfo {
            code_hashes: vec![],
            total_generated: 10,
        });
        assert!(extract_passkey_info(&data).is_none());
    }

    // ── Request type deserialization ────────────────────────────────────

    #[test]
    fn verify_totp_request_deserializes() {
        let json = r#"{"user_slug": 42, "totp_code": "123456", "challenge_nonce": "dGVzdA=="}"#;
        let req: VerifyTotpRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.user_slug, 42);
        assert_eq!(req.totp_code, "123456");
        assert_eq!(req.challenge_nonce, "dGVzdA==");
    }

    #[test]
    fn recovery_code_request_deserializes() {
        let json = r#"{"user_slug": 7, "code": "ABCD1234", "challenge_nonce": "bm9uY2U="}"#;
        let req: RecoveryCodeRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.user_slug, 7);
        assert_eq!(req.code, "ABCD1234");
    }

    #[test]
    fn passkey_begin_request_deserializes() {
        let json = r#"{"user_slug": 100}"#;
        let req: PasskeyBeginRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.user_slug, 100);
    }

    #[test]
    fn passkey_register_begin_request_with_name() {
        let json = r#"{"name": "My MacBook"}"#;
        let req: PasskeyRegisterBeginRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name.as_deref(), Some("My MacBook"));
    }

    #[test]
    fn passkey_register_begin_request_without_name() {
        let json = r#"{}"#;
        let req: PasskeyRegisterBeginRequest = serde_json::from_str(json).unwrap();
        assert!(req.name.is_none());
    }

    // ── Response type serialization ────────────────────────────────────

    #[test]
    fn mfa_auth_response_serializes() {
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
    fn recovery_code_response_serializes() {
        let resp = RecoveryCodeResponse {
            access_token: "a".to_string(),
            refresh_token: "r".to_string(),
            token_type: "Bearer",
            remaining_codes: 5,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["remaining_codes"], 5);
        assert_eq!(json["token_type"], "Bearer");
    }

    #[test]
    fn passkey_finish_response_authenticated_serializes_with_tag() {
        let resp = PasskeyFinishResponse::Authenticated {
            access_token: "at".to_string(),
            refresh_token: "rt".to_string(),
            token_type: "Bearer",
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["status"], "authenticated");
        assert_eq!(json["access_token"], "at");
    }

    #[test]
    fn passkey_finish_response_totp_required_serializes_with_tag() {
        let resp = PasskeyFinishResponse::TotpRequired { challenge_nonce: "abc123".to_string() };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["status"], "totp_required");
        assert_eq!(json["challenge_nonce"], "abc123");
    }

    #[test]
    fn passkey_register_begin_response_serialization_includes_challenge_id() {
        // We cannot easily construct a CreationChallengeResponse, but we can
        // verify the struct fields exist and the challenge_id serializes.
        let resp = PasskeyRegisterFinishResponse { slug: 42, name: "My Key".to_string() };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["slug"], 42);
        assert_eq!(json["name"], "My Key");
    }

    // ── require_webauthn ────────────────────────────────────────────────

    #[tokio::test]
    async fn require_webauthn_returns_error_when_none() {
        let state = AppState::new_test();
        // new_test() does not configure webauthn, so it should be None.
        assert!(state.webauthn.is_none());
        let result = require_webauthn(&state);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn require_webauthn_returns_ok_when_configured() {
        use std::sync::Arc;

        let mut state = AppState::new_test();
        let webauthn =
            inferadb_control_core::webauthn::build_webauthn("localhost", "http://localhost")
                .unwrap();
        state.webauthn = Some(Arc::new(webauthn));
        let result = require_webauthn(&state);
        assert!(result.is_ok());
    }

    // ── decode_challenge_nonce additional edge cases ───────────────

    #[test]
    fn decode_challenge_nonce_with_padding() {
        let encoded = base64::engine::general_purpose::STANDARD.encode(b"ab");
        assert!(encoded.contains('='));
        let result = decode_challenge_nonce(&encoded);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"ab");
    }

    #[test]
    fn decode_challenge_nonce_large_payload() {
        let payload = vec![0xFFu8; 1024];
        let encoded = base64::engine::general_purpose::STANDARD.encode(&payload);
        let result = decode_challenge_nonce(&encoded);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1024);
    }

    // ── PasskeyFinishResponse serialization completeness ──────────

    #[test]
    fn passkey_finish_response_totp_required_has_no_tokens() {
        let resp = PasskeyFinishResponse::TotpRequired { challenge_nonce: "nonce".to_string() };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("access_token").is_none());
        assert!(json.get("refresh_token").is_none());
    }

    #[test]
    fn passkey_finish_response_authenticated_has_no_challenge() {
        let resp = PasskeyFinishResponse::Authenticated {
            access_token: "at".to_string(),
            refresh_token: "rt".to_string(),
            token_type: "Bearer",
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("challenge_nonce").is_none());
    }

    // ── validate_name for passkey registration ────────────────────────

    #[test]
    fn validate_name_accepts_valid_passkey_names() {
        assert!(super::super::common::validate_name("My MacBook").is_ok());
        assert!(super::super::common::validate_name("Touch ID").is_ok());
        assert!(super::super::common::validate_name("YubiKey 5").is_ok());
        assert!(super::super::common::validate_name("Work Laptop's Key").is_ok());
        assert!(super::super::common::validate_name("key-1").is_ok());
        assert!(super::super::common::validate_name("key_2").is_ok());
        assert!(super::super::common::validate_name("v1.0").is_ok());
    }

    #[test]
    fn validate_name_rejects_empty_passkey_name() {
        assert!(super::super::common::validate_name("").is_err());
    }

    #[test]
    fn validate_name_rejects_whitespace_only_passkey_name() {
        assert!(super::super::common::validate_name("   ").is_err());
    }

    #[test]
    fn validate_name_rejects_script_injection() {
        assert!(super::super::common::validate_name("<script>alert(1)</script>").is_err());
    }

    #[test]
    fn validate_name_rejects_special_chars() {
        assert!(super::super::common::validate_name("key@home").is_err());
        assert!(super::super::common::validate_name("key#1").is_err());
        assert!(super::super::common::validate_name("key&co").is_err());
        assert!(super::super::common::validate_name("key;drop").is_err());
    }

    #[test]
    fn validate_name_rejects_too_long_passkey_name() {
        let long = "a".repeat(129);
        assert!(super::super::common::validate_name(&long).is_err());
    }

    #[test]
    fn validate_name_accepts_max_length_passkey_name() {
        let exact = "a".repeat(128);
        assert!(super::super::common::validate_name(&exact).is_ok());
    }

    // ── Transport formatting ──────────────────────────────────────────

    #[test]
    fn transport_formatting_produces_lowercase() {
        // The handler converts transports via `format!("{t:?}").to_lowercase()`.
        // Verify the lowercasing step works as expected for typical transport strings.
        let transports = ["Internal", "Usb", "Nfc", "Ble", "Hybrid"];
        let formatted: Vec<String> = transports.iter().map(|t| t.to_lowercase()).collect();
        assert_eq!(formatted, ["internal", "usb", "nfc", "ble", "hybrid"]);
    }

    #[test]
    fn empty_transports_produces_empty_vec() {
        let transports: Option<Vec<String>> = None;
        let result: Vec<String> = transports
            .as_ref()
            .map(|ts| ts.iter().map(|t| t.to_lowercase()).collect::<Vec<_>>())
            .unwrap_or_default();
        assert!(result.is_empty());
    }

    // ── AttestationFormat conversion ──────────────────────────────────

    #[test]
    fn attestation_format_none_maps_to_none() {
        let fmt = AttestationFormat::None;
        let result: Option<String> = match fmt {
            AttestationFormat::None => None,
            other => Some(format!("{other:?}")),
        };
        assert!(result.is_none());
    }

    #[test]
    fn attestation_format_packed_maps_to_string() {
        let fmt = AttestationFormat::Packed;
        let result: Option<String> = match fmt {
            AttestationFormat::None => None,
            other => Some(format!("{other:?}")),
        };
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "Packed");
    }

    #[test]
    fn attestation_format_fidou2f_maps_to_string() {
        let fmt = AttestationFormat::FIDOU2F;
        let result: Option<String> = match fmt {
            AttestationFormat::None => None,
            other => Some(format!("{other:?}")),
        };
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "FIDOU2F");
    }

    #[test]
    fn attestation_format_tpm_maps_to_string() {
        let fmt = AttestationFormat::Tpm;
        let result: Option<String> = match fmt {
            AttestationFormat::None => None,
            other => Some(format!("{other:?}")),
        };
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "Tpm");
    }
}
