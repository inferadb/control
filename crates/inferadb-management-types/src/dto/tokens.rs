use serde::{Deserialize, Serialize};

// ============================================================================
// Request/Response Types - Token Generation
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct GenerateVaultTokenRequest {
    /// Client ID to use for signing (optional, defaults to first active client cert)
    pub client_id: Option<i64>,
    /// TTL for access token in seconds (default: 300 = 5 minutes)
    pub access_token_ttl: Option<i64>,
    /// TTL for refresh token in seconds (default: 3600 = 1 hour for sessions)
    pub refresh_token_ttl: Option<i64>,
    /// Requested role (optional: "read", "write", "admin", defaults to "read")
    pub requested_role: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct GenerateVaultTokenResponse {
    /// Short-lived JWT access token
    pub access_token: String,
    /// Type of token (always "Bearer")
    pub token_type: String,
    /// Access token TTL in seconds (OAuth 2.0 standard)
    pub expires_in: i64,
    /// Refresh token expiration time in seconds (OAuth 2.0 standard)
    pub refresh_expires_in: i64,
    /// Vault ID this token is scoped to
    pub vault_id: String,
    /// Vault role granted by this token
    pub vault_role: String,
    /// Long-lived refresh token (hex-encoded)
    pub refresh_token: String,
}

// ============================================================================
// Request/Response Types - Token Refresh
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct RefreshTokenRequest {
    /// Refresh token (hex-encoded)
    pub refresh_token: String,
    /// TTL for new access token in seconds (default: 300 = 5 minutes)
    pub access_token_ttl: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct RefreshTokenResponse {
    /// New short-lived JWT access token
    pub access_token: String,
    /// Type of token (always "Bearer")
    pub token_type: String,
    /// Access token TTL in seconds (OAuth 2.0 standard)
    pub expires_in: i64,
    /// Refresh token TTL in seconds (OAuth 2.0 standard)
    pub refresh_expires_in: i64,
    /// New refresh token (rotation)
    pub refresh_token: String,
}

// ============================================================================
// Request/Response Types - Client Assertion
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct ClientAssertionRequest {
    /// Must be "client_credentials"
    pub grant_type: String,
    /// Must be "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    pub client_assertion_type: String,
    /// Signed JWT containing client assertion
    pub client_assertion: String,
    /// Vault ID to access (required)
    pub vault_id: String,
    /// Requested role: "read", "write", or "admin" (optional, defaults to "read")
    pub requested_role: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ClientAssertionResponse {
    /// Short-lived JWT access token
    pub access_token: String,
    /// Type of token (always "Bearer")
    pub token_type: String,
    /// Access token expiration time in seconds
    pub expires_in: i64,
    /// Space-separated scope permissions (e.g., "vault:read vault:write")
    pub scope: String,
    /// Vault role granted ("read", "write", or "admin")
    pub vault_role: String,
    /// Refresh token for obtaining new access tokens
    pub refresh_token: String,
}

// ============================================================================
// Token Revocation Endpoint
// ============================================================================

#[derive(Debug, Serialize)]
pub struct RevokeTokensResponse {
    /// Number of tokens revoked
    pub revoked_count: usize,
}
