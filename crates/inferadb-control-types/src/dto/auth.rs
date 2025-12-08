use serde::{Deserialize, Serialize};

/// API error response
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Request body for user registration
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterRequest {
    /// User's display name
    pub name: String,
    /// User's email address
    pub email: String,
    /// User's password (12-128 characters)
    pub password: String,
}

/// Response body for user registration
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterResponse {
    /// Newly created user ID
    pub user_id: i64,
    /// User's name
    pub name: String,
    /// User's email
    pub email: String,
    /// Session ID
    pub session_id: i64,
    /// Default organization ID created for the user
    pub default_organization_id: i64,
}

/// Request body for password login
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    /// Email address
    pub email: String,
    /// Password
    pub password: String,
}

/// Response body for successful login
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    /// User ID
    pub user_id: i64,
    /// User's name
    pub name: String,
    /// Session ID
    pub session_id: i64,
}

/// Response body for logout
#[derive(Debug, Serialize, Deserialize)]
pub struct LogoutResponse {
    /// Confirmation message
    pub message: String,
}

/// Request body for email verification
#[derive(Debug, Deserialize)]
pub struct VerifyEmailRequest {
    /// Verification token from email
    pub token: String,
}

/// Response body for email verification
#[derive(Debug, Serialize)]
pub struct VerifyEmailResponse {
    /// Success message
    pub message: String,
    /// The verified email address
    pub email: String,
}

/// Request body for password reset request
#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordResetRequestRequest {
    /// Email address to send reset link to
    pub email: String,
}

/// Response body for password reset request
#[derive(Debug, Serialize)]
pub struct PasswordResetRequestResponse {
    /// Success message
    pub message: String,
}

/// Request body for password reset confirmation
#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordResetConfirmRequest {
    /// Reset token from email
    pub token: String,
    /// New password (12-128 characters)
    pub new_password: String,
}

/// Response body for password reset confirmation
#[derive(Debug, Serialize)]
pub struct PasswordResetConfirmResponse {
    /// Success message
    pub message: String,
}
