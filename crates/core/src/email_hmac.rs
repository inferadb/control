//! Email blinding key and HMAC computation.
//!
//! Re-exports from `inferadb-ledger-types` to ensure Control and Ledger
//! use the exact same HMAC algorithm, normalization rules, and key format.
//! See [`inferadb_ledger_types::email_hash`] for implementation details.

pub use inferadb_ledger_types::{
    EmailBlindingKey, EmailBlindingKeyParseError, compute_email_hmac, normalize_email,
};

use inferadb_control_types::error::{Error, Result};

/// Parses a hex-encoded blinding key from config, returning a typed key.
///
/// The key must be a 64-character hex string (32 bytes). Returns `None` if
/// no key is configured; returns an error if the key is present but malformed.
pub fn parse_blinding_key(hex: Option<&str>) -> Result<Option<EmailBlindingKey>> {
    let Some(hex) = hex else {
        return Ok(None);
    };
    let key: EmailBlindingKey =
        hex.parse().map_err(|e: EmailBlindingKeyParseError| Error::config(e.to_string()))?;
    Ok(Some(key))
}
