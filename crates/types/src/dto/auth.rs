//! Error response DTO returned to clients on failed requests.

use serde::Serialize;

/// JSON body returned to clients when a request fails.
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    /// Human-readable error message.
    pub error: String,
    /// Machine-readable error code (e.g., `VALIDATION_ERROR`).
    pub code: String,
    /// Optional additional context about the error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}
