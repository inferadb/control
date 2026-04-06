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
    pub slug: u64,
    pub name: String,
    pub status: String,
    pub role: String,
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
    pub message: String,
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
            status: user.status.to_string(),
            role: user.role.to_string(),
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
            status: user.status.to_string(),
            role: user.role.to_string(),
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

    Ok(Json(DeleteUserResponse { message: "User account deleted successfully".to_string() }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn user_profile_data_serializes() {
        let data = UserProfileData {
            slug: 42,
            name: "Alice".to_string(),
            status: "active".to_string(),
            role: "admin".to_string(),
            created_at: Some("2026-01-01T00:00:00Z".to_string()),
        };
        let json = serde_json::to_value(&data).unwrap();
        assert_eq!(json["slug"], 42);
        assert_eq!(json["name"], "Alice");
        assert_eq!(json["status"], "active");
        assert_eq!(json["role"], "admin");
        assert!(json["created_at"].is_string());
    }

    #[test]
    fn user_profile_response_serializes() {
        let resp = UserProfileResponse {
            user: UserProfileData {
                slug: 1,
                name: "Bob".to_string(),
                status: "active".to_string(),
                role: "member".to_string(),
                created_at: None,
            },
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["user"]["slug"], 1);
        assert!(json["user"]["created_at"].is_null());
    }

    #[test]
    fn update_profile_request_deserializes_with_name() {
        let json = r#"{"name": "New Name"}"#;
        let req: UpdateProfileRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name.as_deref(), Some("New Name"));
    }

    #[test]
    fn update_profile_request_deserializes_without_name() {
        let json = r#"{}"#;
        let req: UpdateProfileRequest = serde_json::from_str(json).unwrap();
        assert!(req.name.is_none());
    }

    #[test]
    fn delete_user_response_serializes() {
        let resp = DeleteUserResponse { message: "deleted".to_string() };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["message"], "deleted");
    }
}
