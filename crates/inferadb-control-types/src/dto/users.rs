use serde::{Deserialize, Serialize};

/// Get user profile response (wrapped)
#[derive(Debug, Serialize, Deserialize)]
pub struct GetUserProfileResponse {
    pub user: UserProfile,
}

/// User profile response
#[derive(Debug, Serialize, Deserialize)]
pub struct UserProfile {
    /// User ID
    pub id: i64,
    /// User's name
    pub name: String,
    /// When the user was created
    pub created_at: String,
    /// When TOS was accepted (if applicable)
    pub tos_accepted_at: Option<String>,
}

/// Request body for updating user profile
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateProfileRequest {
    /// Updated name (optional)
    pub name: Option<String>,
    /// Accept terms of service (optional)
    pub accept_tos: Option<bool>,
}

/// Response body for profile updates
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateProfileResponse {
    /// Updated user profile
    pub profile: UserProfile,
}

/// Response body for user deletion
#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteUserResponse {
    /// Confirmation message
    pub message: String,
}
