use serde::{Deserialize, Serialize};

/// Request to authorize CLI access
///
/// This is called by the CLI after redirecting the user to the browser.
/// The user must be logged in with a valid session (web session).
#[derive(Debug, Deserialize)]
pub struct CliAuthorizeRequest {
    /// PKCE code challenge (base64url encoded SHA256 of code_verifier)
    pub code_challenge: String,

    /// PKCE code challenge method (must be "S256")
    pub code_challenge_method: String,
}

/// Response containing authorization code
#[derive(Debug, Serialize)]
pub struct CliAuthorizeResponse {
    /// The authorization code to exchange for a session token
    pub code: String,

    /// When the code expires (seconds from now)
    pub expires_in: i64,
}

/// Request to exchange authorization code for session token
#[derive(Debug, Deserialize)]
pub struct CliTokenRequest {
    /// The authorization code
    pub code: String,

    /// PKCE code verifier
    pub code_verifier: String,
}

/// Response containing session token
#[derive(Debug, Serialize)]
pub struct CliTokenResponse {
    /// Session token (session ID as string)
    pub session_token: String,

    /// Session expiry time (seconds from now)
    pub expires_in: i64,
}
