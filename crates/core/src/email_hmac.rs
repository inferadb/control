//! Email blinding key and HMAC computation.
//!
//! Re-exports from `inferadb-ledger-types` to ensure Control and Ledger
//! use the exact same HMAC algorithm, normalization rules, and key format.
//! See `inferadb_ledger_types::email_hash` for implementation details.

use inferadb_control_types::error::{Error, Result};
pub use inferadb_ledger_types::{
    EmailBlindingKey, EmailBlindingKeyParseError, compute_email_hmac, normalize_email,
};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_blinding_key_none_returns_ok_none() {
        let result = parse_blinding_key(None);
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn parse_blinding_key_valid_hex_returns_ok_some() {
        let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let result = parse_blinding_key(Some(hex));
        assert!(matches!(result, Ok(Some(_))));
    }

    #[test]
    fn parse_blinding_key_too_short_returns_err() {
        let result = parse_blinding_key(Some("abcdef"));
        assert!(matches!(result, Err(Error::Config { .. })));
    }

    #[test]
    fn parse_blinding_key_invalid_hex_returns_err() {
        let hex = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        let result = parse_blinding_key(Some(hex));
        assert!(matches!(result, Err(Error::Config { .. })));
    }
}
