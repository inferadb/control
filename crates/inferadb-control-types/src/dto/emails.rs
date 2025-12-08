use serde::{Deserialize, Serialize};

/// Request body for adding a new email
#[derive(Debug, Serialize, Deserialize)]
pub struct AddEmailRequest {
    /// Email address to add
    pub email: String,
}

/// Response body for adding a new email
#[derive(Debug, Serialize, Deserialize)]
pub struct AddEmailResponse {
    /// The created email
    pub email: UserEmailInfo,
    /// Message indicating verification email was sent
    pub message: String,
}

/// Email information
#[derive(Debug, Serialize, Deserialize)]
pub struct UserEmailInfo {
    /// Email ID
    pub id: i64,
    /// Email address
    pub email: String,
    /// Whether this is the primary email
    pub is_primary: bool,
    /// Whether this email is verified
    pub is_verified: bool,
    /// When the email was created
    pub created_at: String,
}

/// Response body for listing emails
#[derive(Debug, Serialize, Deserialize)]
pub struct ListEmailsResponse {
    /// List of user's emails
    pub emails: Vec<UserEmailInfo>,
}

/// Request body for setting primary email
#[derive(Debug, Serialize, Deserialize)]
pub struct SetPrimaryEmailRequest {
    /// Whether to set as primary
    pub is_primary: bool,
}

/// Response body for email operations
#[derive(Debug, Serialize, Deserialize)]
pub struct EmailOperationResponse {
    /// Success message
    pub message: String,
}

/// Request body for email verification
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyEmailRequest {
    /// Verification token from email
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyEmailResponse {
    /// Success message
    pub message: String,
    /// Whether the email was verified
    pub verified: bool,
}

/// Response body for resending verification
#[derive(Debug, Serialize, Deserialize)]
pub struct ResendVerificationResponse {
    /// Success message
    pub message: String,
}
