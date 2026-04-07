//! Email management handlers.
//!
//! All operations delegate to Ledger SDK via the service layer.
//! Email state (verification, primary flag) is owned by Ledger.

use std::time::Instant;

use axum::{
    Extension, Json,
    extract::{Path, State},
};
use inferadb_control_core::SdkResultExt;
use inferadb_control_types::Error as CoreError;
use inferadb_ledger_sdk::UserEmailInfo;
use inferadb_ledger_types::UserEmailId;
use serde::{Deserialize, Serialize};

use super::common::{require_ledger, safe_id_cast, system_time_to_rfc3339};
use crate::{
    handlers::state::{AppState, Result},
    middleware::UserClaims,
};

// ── Request/Response Types ─────────────────────────────────────────────

/// Request body for adding an email address.
#[derive(Debug, Deserialize)]
pub struct AddEmailRequest {
    pub email: String,
}

/// Email information mapped from Ledger SDK [`UserEmailInfo`].
#[derive(Debug, Serialize)]
pub struct EmailInfoResponse {
    /// Email address slug identifier.
    pub slug: u64,
    /// The email address.
    pub email: String,
    /// Whether the email has been verified.
    pub verified: bool,
    /// RFC 3339 creation timestamp.
    pub created_at: Option<String>,
    /// RFC 3339 timestamp of when the email was verified.
    pub verified_at: Option<String>,
}

/// Response for a newly added email address.
#[derive(Debug, Serialize)]
pub struct AddEmailResponse {
    pub email: EmailInfoResponse,
    pub message: String,
}

/// Response containing the user's email addresses.
#[derive(Debug, Serialize)]
pub struct ListEmailsResponse {
    pub emails: Vec<EmailInfoResponse>,
}

/// Response for email mutation operations.
#[derive(Debug, Serialize)]
pub struct EmailOperationResponse {
    pub message: String,
}

/// Request body for verifying an email address with a token.
#[derive(Debug, Deserialize)]
pub struct VerifyEmailRequest {
    pub token: String,
}

/// Response for email verification.
#[derive(Debug, Serialize)]
pub struct VerifyEmailResponse {
    pub message: String,
    pub verified: bool,
}

// ── Helpers ────────────────────────────────────────────────────────────

/// Converts a Ledger [`UserEmailInfo`] to an API response.
fn map_email_info(
    info: &UserEmailInfo,
) -> std::result::Result<EmailInfoResponse, inferadb_control_types::Error> {
    Ok(EmailInfoResponse {
        slug: safe_id_cast(info.id.value())?,
        email: info.email.clone(),
        verified: info.verified,
        created_at: system_time_to_rfc3339(&info.created_at),
        verified_at: system_time_to_rfc3339(&info.verified_at),
    })
}

/// Extracts the required email blinding key from app state.
fn require_blinding_key(
    state: &AppState,
) -> std::result::Result<&inferadb_ledger_types::EmailBlindingKey, CoreError> {
    state
        .blinding_key
        .as_deref()
        .ok_or_else(|| CoreError::internal("Email blinding key not configured"))
}

// ── Handlers ───────────────────────────────────────────────────────────

/// POST /control/v1/users/emails
///
/// Adds an email address to the authenticated user's account.
/// Creates the email via Ledger SDK, which generates a verification token.
pub async fn add_email(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Json(payload): Json<AddEmailRequest>,
) -> Result<Json<AddEmailResponse>> {
    let ledger = require_ledger(&state)?;
    let blinding_key = require_blinding_key(&state)?;

    let normalized = inferadb_control_core::normalize_email(&payload.email);
    let hmac = inferadb_control_core::compute_email_hmac(blinding_key, &normalized);

    let start = Instant::now();
    let info = ledger
        .create_user_email(claims.user_slug, &normalized, &hmac)
        .await
        .map_sdk_err_instrumented("create_user_email", start)?;

    Ok(Json(AddEmailResponse {
        email: map_email_info(&info)?,
        message: "Email added. Please check your inbox for a verification link.".to_string(),
    }))
}

/// GET /control/v1/users/emails
///
/// Lists all emails for the authenticated user.
pub async fn list_emails(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
) -> Result<Json<ListEmailsResponse>> {
    let ledger = require_ledger(&state)?;

    let start = Instant::now();
    let emails = ledger
        .search_user_email(claims.user_slug, Some(claims.user_slug), None)
        .await
        .map_sdk_err_instrumented("list_user_emails", start)?;

    Ok(Json(ListEmailsResponse {
        emails: emails.iter().map(map_email_info).collect::<std::result::Result<Vec<_>, _>>()?,
    }))
}

/// DELETE /control/v1/users/emails/{id}
///
/// Deletes an email address.
pub async fn delete_email(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path(email_id): Path<u64>,
) -> Result<Json<EmailOperationResponse>> {
    let ledger = require_ledger(&state)?;

    let id = i64::try_from(email_id)
        .map_err(|_| CoreError::validation("invalid email address identifier"))?;
    let start = Instant::now();
    ledger
        .delete_user_email(claims.user_slug, UserEmailId::new(id))
        .await
        .map_sdk_err_instrumented("delete_user_email", start)?;

    Ok(Json(EmailOperationResponse { message: "Email deleted successfully".to_string() }))
}

/// POST /control/v1/auth/verify-email
///
/// Verifies an email address using a verification token.
pub async fn verify_email(
    State(state): State<AppState>,
    Json(payload): Json<VerifyEmailRequest>,
) -> Result<Json<VerifyEmailResponse>> {
    let ledger = require_ledger(&state)?;

    let start = Instant::now();
    ledger
        .verify_user_email(&payload.token)
        .await
        .map_sdk_err_instrumented("verify_user_email", start)?;

    Ok(Json(VerifyEmailResponse {
        message: "Email verified successfully".to_string(),
        verified: true,
    }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::Arc;

    use inferadb_ledger_types::{EmailBlindingKey, UserEmailId};

    use super::*;

    // ── map_email_info ────────────────────────────────────────────

    #[test]
    fn test_map_email_info_valid_info_maps_all_fields() {
        let info = UserEmailInfo {
            id: UserEmailId::new(42),
            email: "test@example.com".to_string(),
            verified: true,
            created_at: Some(std::time::SystemTime::UNIX_EPOCH),
            verified_at: Some(std::time::SystemTime::UNIX_EPOCH),
        };

        let result = map_email_info(&info).unwrap();

        assert_eq!(result.slug, 42);
        assert_eq!(result.email, "test@example.com");
        assert!(result.verified);
        assert!(result.created_at.is_some());
        assert!(result.verified_at.is_some());
    }

    #[test]
    fn test_map_email_info_no_timestamps_returns_none_fields() {
        let info = UserEmailInfo {
            id: UserEmailId::new(1),
            email: "user@domain.com".to_string(),
            verified: false,
            created_at: None,
            verified_at: None,
        };

        let result = map_email_info(&info).unwrap();

        assert_eq!(result.slug, 1);
        assert!(!result.verified);
        assert!(result.created_at.is_none());
        assert!(result.verified_at.is_none());
    }

    #[test]
    fn test_map_email_info_negative_id_returns_error() {
        let info = UserEmailInfo {
            id: UserEmailId::new(-1),
            email: "bad@id.com".to_string(),
            verified: false,
            created_at: None,
            verified_at: None,
        };

        assert!(map_email_info(&info).is_err());
    }

    // ── require_blinding_key ──────────────────────────────────────

    #[tokio::test]
    async fn test_require_blinding_key_none_returns_error() {
        let state = AppState::new_test();

        let result = require_blinding_key(&state);

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_require_blinding_key_present_returns_key() {
        let mut state = AppState::new_test();
        let key = EmailBlindingKey::new([0u8; 32], 1);
        state.blinding_key = Some(Arc::new(key));

        let result = require_blinding_key(&state);

        assert!(result.is_ok());
        assert_eq!(result.unwrap().version(), 1);
    }

    // ── Request/Response serialization ────────────────────────────

    #[test]
    fn test_add_email_request_deserializes() {
        let json = r#"{"email": "test@example.com"}"#;

        let req: AddEmailRequest = serde_json::from_str(json).unwrap();

        assert_eq!(req.email, "test@example.com");
    }

    #[test]
    fn test_email_info_response_serializes_with_null_optional() {
        let resp = EmailInfoResponse {
            slug: 1,
            email: "a@b.com".to_string(),
            verified: true,
            created_at: Some("2026-01-01T00:00:00Z".to_string()),
            verified_at: None,
        };

        let json = serde_json::to_value(&resp).unwrap();

        assert_eq!(json["slug"], 1);
        assert_eq!(json["verified"], true);
        assert!(json["verified_at"].is_null());
    }

    #[test]
    fn test_add_email_response_serializes_nested_email() {
        let resp = AddEmailResponse {
            email: EmailInfoResponse {
                slug: 1,
                email: "a@b.com".to_string(),
                verified: false,
                created_at: None,
                verified_at: None,
            },
            message: "Email added.".to_string(),
        };

        let json = serde_json::to_value(&resp).unwrap();

        assert_eq!(json["message"], "Email added.");
        assert_eq!(json["email"]["slug"], 1);
    }

    #[test]
    fn test_list_emails_response_serializes_empty() {
        let resp = ListEmailsResponse { emails: vec![] };

        let json = serde_json::to_value(&resp).unwrap();

        assert!(json["emails"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_email_operation_response_serializes() {
        let resp = EmailOperationResponse { message: "done".to_string() };

        let json = serde_json::to_value(&resp).unwrap();

        assert_eq!(json["message"], "done");
    }

    #[test]
    fn test_verify_email_request_deserializes() {
        let json = r#"{"token": "abc123"}"#;

        let req: VerifyEmailRequest = serde_json::from_str(json).unwrap();

        assert_eq!(req.token, "abc123");
    }

    #[test]
    fn test_verify_email_response_serializes() {
        let resp = VerifyEmailResponse { message: "ok".to_string(), verified: true };

        let json = serde_json::to_value(&resp).unwrap();

        assert_eq!(json["verified"], true);
    }
}
