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

/// User profile data mapped from Ledger SDK [`UserInfo`](inferadb_ledger_sdk::UserInfo).
#[derive(Debug, Serialize)]
pub struct UserProfileData {
    /// User slug identifier (Snowflake ID).
    pub slug: u64,
    /// Display name.
    pub name: String,
    /// Account status (e.g., `"active"`, `"deleted"`).
    pub status: &'static str,
    /// Platform role (e.g., `"user"`, `"admin"`).
    pub role: &'static str,
    /// RFC 3339 account creation timestamp.
    pub created_at: Option<String>,
}

/// Envelope response wrapping [`UserProfileData`].
#[derive(Debug, Serialize)]
pub struct UserProfileResponse {
    pub user: UserProfileData,
}

/// Request body for updating the user profile.
#[derive(Debug, Deserialize)]
pub struct UpdateProfileRequest {
    pub name: Option<String>,
}

/// Response confirming account deletion.
#[derive(Debug, Serialize)]
pub struct DeleteUserResponse {
    pub message: &'static str,
}

// ── Handlers ────────────────────────────────────────────────────────────

/// GET /control/v1/users/me
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
            status: user.status.as_str(),
            role: user.role.as_str(),
            created_at: system_time_to_rfc3339(&user.created_at),
        },
    }))
}

/// PATCH /control/v1/users/me
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
            status: user.status.as_str(),
            role: user.role.as_str(),
            created_at: system_time_to_rfc3339(&user.created_at),
        },
    }))
}

/// DELETE /control/v1/users/me
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

    Ok(Json(DeleteUserResponse { message: "User account deleted successfully" }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // ── UserProfileData serialization ─────────────────────────────────

    #[test]
    fn test_user_profile_data_serializes_all_fields() {
        let json = serde_json::to_value(&UserProfileData {
            slug: 42,
            name: "Alice".to_string(),
            status: "active",
            role: "admin",
            created_at: Some("2026-01-01T00:00:00Z".to_string()),
        })
        .unwrap();
        assert_eq!(json["slug"], 42);
        assert_eq!(json["name"], "Alice");
        assert_eq!(json["status"], "active");
        assert_eq!(json["role"], "admin");
        assert_eq!(json["created_at"], "2026-01-01T00:00:00Z");
    }

    #[test]
    fn test_user_profile_data_created_at_none_is_null() {
        let json = serde_json::to_value(&UserProfileData {
            slug: 1,
            name: "Bob".to_string(),
            status: "active",
            role: "member",
            created_at: None,
        })
        .unwrap();
        assert!(json["created_at"].is_null());
    }

    // ── UserProfileResponse serialization ─────────────────────────────

    #[test]
    fn test_user_profile_response_wraps_in_user_key() {
        let json = serde_json::to_value(&UserProfileResponse {
            user: UserProfileData {
                slug: 1,
                name: "Bob".to_string(),
                status: "active",
                role: "member",
                created_at: None,
            },
        })
        .unwrap();
        assert_eq!(json["user"]["slug"], 1);
        assert_eq!(json["user"]["name"], "Bob");
    }

    // ── UpdateProfileRequest deserialization ───────────────────────────

    #[test]
    fn test_update_profile_request_with_name() {
        let req: UpdateProfileRequest = serde_json::from_str(r#"{"name": "New Name"}"#).unwrap();
        assert_eq!(req.name.as_deref(), Some("New Name"));
    }

    #[test]
    fn test_update_profile_request_empty_body_has_no_name() {
        let req: UpdateProfileRequest = serde_json::from_str(r#"{}"#).unwrap();
        assert!(req.name.is_none());
    }

    #[test]
    fn test_update_profile_request_explicit_null_name() {
        let req: UpdateProfileRequest = serde_json::from_str(r#"{"name": null}"#).unwrap();
        assert!(req.name.is_none());
    }

    // ── DeleteUserResponse serialization ──────────────────────────────

    #[test]
    fn test_delete_user_response_serializes_message() {
        let json =
            serde_json::to_value(&DeleteUserResponse { message: "deleted" }).unwrap();
        assert_eq!(json["message"], "deleted");
    }
}
