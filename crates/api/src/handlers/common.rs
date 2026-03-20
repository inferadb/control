//! Shared types and helpers used across handler modules.

use chrono::{DateTime, Utc};
use inferadb_control_types::Error as CoreError;
use serde::{Deserialize, Serialize};

use super::auth::AppState;

// ── Shared Request Types ────────────────────────────────────────────

/// Cursor-based pagination query parameters.
///
/// Used by all list endpoints for consistent pagination behavior.
#[derive(Debug, Deserialize)]
pub struct CursorPaginationQuery {
    /// Number of items per page (default 50, max 100).
    #[serde(default = "default_page_size")]
    pub page_size: u32,
    /// Opaque cursor for the next page (base64-encoded).
    pub page_token: Option<String>,
}

fn default_page_size() -> u32 {
    50
}

impl CursorPaginationQuery {
    pub fn validated_page_size(&self) -> u32 {
        self.page_size.clamp(1, 100)
    }

    pub fn decoded_page_token(&self) -> Option<Vec<u8>> {
        use base64::Engine;
        self.page_token
            .as_deref()
            .and_then(|t| base64::engine::general_purpose::STANDARD.decode(t).ok())
    }
}

// ── Shared Response Types ───────────────────────────────────────────

/// Simple message response used by multiple handlers.
#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub message: String,
}

// ── Shared Helpers ──────────────────────────────────────────────────

/// Extracts a reference to the Ledger client from app state.
///
/// Returns `Error::internal` if the Ledger client is not configured
/// (e.g., running in a mode where Ledger is unavailable).
pub fn require_ledger(
    state: &AppState,
) -> std::result::Result<&inferadb_ledger_sdk::LedgerClient, CoreError> {
    state.ledger.as_deref().ok_or_else(|| CoreError::internal("Ledger client not configured"))
}

/// Encodes a page token (raw bytes) to a base64 string for API responses.
pub fn encode_page_token(token: &Option<Vec<u8>>) -> Option<String> {
    use base64::Engine;
    token.as_ref().map(|t| base64::engine::general_purpose::STANDARD.encode(t))
}

/// Converts an optional `SystemTime` to an RFC 3339 string.
pub fn system_time_to_rfc3339(t: &Option<std::time::SystemTime>) -> Option<String> {
    t.map(|st| DateTime::<Utc>::from(st).to_rfc3339())
}
