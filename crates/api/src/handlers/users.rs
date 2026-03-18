//! User profile management handlers.
//!
//! All operations delegate to Ledger SDK via the service layer.
//! User state (profile, emails, credentials) is owned by Ledger.

use axum::{Extension, Json, extract::State};
use chrono::{DateTime, Utc};
use inferadb_control_core::service;
use inferadb_control_types::Error as CoreError;
use serde::{Deserialize, Serialize};

use crate::{
    handlers::auth::{AppState, Result},
    middleware::UserClaims,
};

// ── Response Types ──────────────────────────────────────────────────────

/// User profile response (mapped from Ledger SDK UserInfo).
#[derive(Debug, Serialize)]
pub struct UserProfileResponse {
    pub slug: u64,
    pub name: String,
    pub status: String,
    pub role: String,
    pub created_at: Option<String>,
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
    let ledger = state
        .ledger
        .as_ref()
        .ok_or_else(|| CoreError::internal("Ledger client not configured"))?;

    let user = service::user::get_user(ledger, claims.user_slug).await?;

    Ok(Json(UserProfileResponse {
        slug: user.slug.value(),
        name: user.name,
        status: format!("{:?}", user.status),
        role: format!("{:?}", user.role),
        created_at: user.created_at.map(|t| {
            DateTime::<Utc>::from(t).to_rfc3339()
        }),
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
    let ledger = state
        .ledger
        .as_ref()
        .ok_or_else(|| CoreError::internal("Ledger client not configured"))?;

    let name = payload
        .name
        .ok_or_else(|| CoreError::validation("at least one field must be provided"))?;

    let user = service::user::update_user_name(ledger, claims.user_slug, name).await?;

    Ok(Json(UserProfileResponse {
        slug: user.slug.value(),
        name: user.name,
        status: format!("{:?}", user.status),
        role: format!("{:?}", user.role),
        created_at: user.created_at.map(|t| {
            DateTime::<Utc>::from(t).to_rfc3339()
        }),
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
    let ledger = state
        .ledger
        .as_ref()
        .ok_or_else(|| CoreError::internal("Ledger client not configured"))?;

    let slug_str = claims.user_slug.value().to_string();
    service::user::delete_user(ledger, claims.user_slug, &slug_str).await?;

    Ok(Json(DeleteUserResponse { message: "User account deleted successfully".to_string() }))
}
