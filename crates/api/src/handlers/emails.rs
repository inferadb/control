//! Email management handlers.
//!
//! All operations delegate to Ledger SDK via the service layer.
//! Email state (verification, primary flag) is owned by Ledger.

use std::time::Instant;

use axum::{
    Extension, Json,
    extract::{Path, State},
};
use chrono::{DateTime, Utc};
use inferadb_control_core::SdkResultExt;
use inferadb_control_types::Error as CoreError;
use inferadb_ledger_sdk::UserEmailInfo;
use inferadb_ledger_types::UserEmailId;
use serde::{Deserialize, Serialize};

use super::common::{require_ledger, safe_id_cast};
use crate::{
    handlers::state::{AppState, Result},
    middleware::UserClaims,
};

// ── Request/Response Types ─────────────────────────────────────────────

/// Add email request.
#[derive(Debug, Deserialize)]
pub struct AddEmailRequest {
    pub email: String,
}

/// Email info response (mapped from Ledger SDK UserEmailInfo).
#[derive(Debug, Serialize)]
pub struct EmailInfoResponse {
    pub slug: u64,
    pub email: String,
    pub verified: bool,
    pub created_at: Option<String>,
    pub verified_at: Option<String>,
}

/// Add email response.
#[derive(Debug, Serialize)]
pub struct AddEmailResponse {
    pub email: EmailInfoResponse,
    pub message: String,
}

/// List emails response.
#[derive(Debug, Serialize)]
pub struct ListEmailsResponse {
    pub emails: Vec<EmailInfoResponse>,
}

/// Email operation response.
#[derive(Debug, Serialize)]
pub struct EmailOperationResponse {
    pub message: String,
}

/// Verify email request.
#[derive(Debug, Deserialize)]
pub struct VerifyEmailRequest {
    pub token: String,
}

/// Verify email response.
#[derive(Debug, Serialize)]
pub struct VerifyEmailResponse {
    pub message: String,
    pub verified: bool,
}

// ── Helpers ────────────────────────────────────────────────────────────

fn map_email_info(
    info: &UserEmailInfo,
) -> std::result::Result<EmailInfoResponse, inferadb_control_types::Error> {
    Ok(EmailInfoResponse {
        slug: safe_id_cast(info.id.value())?,
        email: info.email.clone(),
        verified: info.verified,
        created_at: info.created_at.map(|t| DateTime::<Utc>::from(t).to_rfc3339()),
        verified_at: info.verified_at.map(|t| DateTime::<Utc>::from(t).to_rfc3339()),
    })
}

fn require_blinding_key(
    state: &AppState,
) -> std::result::Result<&inferadb_ledger_types::EmailBlindingKey, CoreError> {
    state
        .blinding_key
        .as_deref()
        .ok_or_else(|| CoreError::internal("Email blinding key not configured"))
}

// ── Handlers ───────────────────────────────────────────────────────────

/// Add a new email address.
///
/// POST /control/v1/users/emails
///
/// Creates a new email address via Ledger SDK. The Ledger generates
/// a verification token which should be sent via SMTP.
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

/// List all emails for the authenticated user.
///
/// GET /control/v1/users/emails
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

/// Delete an email address.
///
/// DELETE /control/v1/users/emails/{id}
pub async fn delete_email(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path(email_id): Path<i64>,
) -> Result<Json<EmailOperationResponse>> {
    let ledger = require_ledger(&state)?;

    let start = Instant::now();
    ledger
        .delete_user_email(claims.user_slug, UserEmailId::new(email_id))
        .await
        .map_sdk_err_instrumented("delete_user_email", start)?;

    Ok(Json(EmailOperationResponse { message: "Email deleted successfully".to_string() }))
}

/// Verify an email address using a verification token.
///
/// POST /control/v1/auth/verify-email
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
