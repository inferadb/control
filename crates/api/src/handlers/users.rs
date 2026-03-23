//! User profile management handlers.
//!
//! All operations delegate to Ledger SDK via the service layer.
//! User state (profile, emails, credentials) is owned by Ledger.

use std::time::Instant;

use axum::{Extension, Json, extract::State};
use inferadb_control_core::SdkResultExt;
use inferadb_control_types::Error as CoreError;
use serde::{Deserialize, Serialize};

use super::common::{require_ledger, system_time_to_rfc3339, validate_name};
use crate::{
    handlers::state::{AppState, Result},
    middleware::UserClaims,
};

// ── Response Types ──────────────────────────────────────────────────────

/// User profile response (mapped from Ledger SDK UserInfo).
#[derive(Debug, Serialize)]
pub struct UserProfileData {
    pub slug: u64,
    pub name: String,
    pub status: String,
    pub role: String,
    pub created_at: Option<String>,
}

/// Wrapped user profile response.
#[derive(Debug, Serialize)]
pub struct UserProfileResponse {
    pub user: UserProfileData,
}

/// Update profile request.
#[derive(Debug, Deserialize)]
pub struct UpdateProfileRequest {
    pub name: Option<String>,
}

/// Delete user response.
#[derive(Debug, Serialize)]
pub struct DeleteUserResponse {
    pub message: String,
}

// ── Handlers ────────────────────────────────────────────────────────────

/// GET /v1/users/me
///
/// Returns the authenticated user's profile from Ledger.
pub async fn get_profile(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
) -> Result<Json<UserProfileResponse>> {
    let ledger = require_ledger(&state)?;

    let start = Instant::now();
    let user =
        ledger.get_user(claims.user_slug).await.map_sdk_err_instrumented("get_user", start)?;

    Ok(Json(UserProfileResponse {
        user: UserProfileData {
            slug: user.slug.value(),
            name: user.name,
            status: user.status.to_string(),
            role: user.role.to_string(),
            created_at: system_time_to_rfc3339(&user.created_at),
        },
    }))
}

/// PATCH /v1/users/me
///
/// Updates the authenticated user's display name.
pub async fn update_profile(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Json(payload): Json<UpdateProfileRequest>,
) -> Result<Json<UserProfileResponse>> {
    let ledger = require_ledger(&state)?;

    let name =
        payload.name.ok_or_else(|| CoreError::validation("at least one field must be provided"))?;
    validate_name(&name)?;

    let start = Instant::now();
    let user = ledger
        .update_user(claims.user_slug, Some(name), None, None)
        .await
        .map_sdk_err_instrumented("update_user_name", start)?;

    Ok(Json(UserProfileResponse {
        user: UserProfileData {
            slug: user.slug.value(),
            name: user.name,
            status: user.status.to_string(),
            role: user.role.to_string(),
            created_at: system_time_to_rfc3339(&user.created_at),
        },
    }))
}

/// DELETE /v1/users/me
///
/// Soft-deletes the authenticated user's account. Ledger handles all cascade
/// deletion (sessions, memberships, emails, credentials, etc.).
pub async fn delete_user(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
) -> Result<Json<DeleteUserResponse>> {
    let ledger = require_ledger(&state)?;

    let start = Instant::now();
    ledger
        .delete_user(claims.user_slug, claims.user_slug)
        .await
        .map_sdk_err_instrumented("delete_user", start)?;

    Ok(Json(DeleteUserResponse { message: "User account deleted successfully".to_string() }))
}
