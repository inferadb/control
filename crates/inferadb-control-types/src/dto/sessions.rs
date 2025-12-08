use serde::{Deserialize, Serialize};

/// Session information response
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionInfo {
    /// Session ID
    pub session_id: i64,
    /// Session type (WEB, CLI, SDK)
    pub session_type: String,
    /// When the session was created
    pub created_at: String,
    /// When the session expires
    pub expires_at: String,
    /// Last activity timestamp
    pub last_activity_at: String,
    /// IP address (if available)
    pub ip_address: Option<String>,
    /// User agent (if available)
    pub user_agent: Option<String>,
}

/// Response body for session listing
#[derive(Debug, Serialize, Deserialize)]
pub struct ListSessionsResponse {
    /// List of active sessions
    pub sessions: Vec<SessionInfo>,
    /// Total count of active sessions
    pub count: usize,
}

/// Response body for session revocation
#[derive(Debug, Serialize, Deserialize)]
pub struct RevokeSessionResponse {
    /// Confirmation message
    pub message: String,
}
