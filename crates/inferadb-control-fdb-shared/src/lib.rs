//! Shared FDB types for cross-service communication between Engine and Control.
//!
//! This crate defines the FDB keyspace layout and data types used for:
//! - JWKS storage (Control publishes, Engine reads)
//! - Cache invalidation events (Control publishes, Engine watches)
//!
//! The same types are duplicated in `inferadb-engine-fdb-shared` to maintain
//! submodule independence between engine/ and control/.

use serde::{Deserialize, Serialize};

// ============================================================================
// FDB Key Prefixes
// ============================================================================

/// Prefix for Control JWKS storage: `inferadb/control-jwks/{control_id}`
pub const CONTROL_JWKS_PREFIX: &[u8] = b"inferadb/control-jwks/";

/// Key for invalidation version counter: `inferadb/invalidation/version`
pub const INVALIDATION_VERSION_KEY: &[u8] = b"inferadb/invalidation/version";

/// Prefix for invalidation event log: `inferadb/invalidation-log/{timestamp}:{event_id}`
pub const INVALIDATION_LOG_PREFIX: &[u8] = b"inferadb/invalidation-log/";

// ============================================================================
// JWKS Types
// ============================================================================

/// JWKS stored in FDB by Control instances.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredJwks {
    /// Control instance ID (e.g., "ctrl-inferadb-control-0")
    pub control_id: String,
    /// Public keys in JWK format
    pub keys: Vec<StoredJwk>,
    /// Unix timestamp when this JWKS was last updated
    pub updated_at: i64,
}

/// Individual JWK (JSON Web Key) for Ed25519 public keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredJwk {
    /// Key type (always "OKP" for Ed25519)
    pub kty: String,
    /// Algorithm (always "EdDSA")
    pub alg: String,
    /// Key ID (RFC 7638 thumbprint)
    pub kid: String,
    /// Curve (always "Ed25519")
    pub crv: String,
    /// Base64url-encoded public key
    pub x: String,
    /// Key use (always "sig" for signature)
    #[serde(rename = "use")]
    pub key_use: String,
}

// ============================================================================
// Cache Invalidation Types
// ============================================================================

/// Cache invalidation event types.
///
/// When Control modifies data that Engine caches, it writes an invalidation
/// event to FDB. Engine watches for these events and invalidates its caches.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InvalidationEvent {
    /// Invalidate all caches for a specific vault
    Vault { vault_id: i64 },
    /// Invalidate all caches for an organization
    Organization { org_id: i64 },
    /// Invalidate a specific certificate
    Certificate { org_id: i64, client_id: i64, cert_id: i64 },
    /// Invalidate all caches (nuclear option)
    All,
}

/// Invalidation log entry stored in FDB.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvalidationLogEntry {
    /// Unique event ID (UUID)
    pub event_id: String,
    /// Unix timestamp (milliseconds) when the event was created
    pub timestamp_ms: i64,
    /// The invalidation event
    pub event: InvalidationEvent,
    /// Control instance that triggered this event
    pub source_control_id: String,
}

// ============================================================================
// Key Construction Helpers
// ============================================================================

/// Build the FDB key for a Control instance's JWKS.
pub fn jwks_key(control_id: &str) -> Vec<u8> {
    let mut key = CONTROL_JWKS_PREFIX.to_vec();
    key.extend_from_slice(control_id.as_bytes());
    key
}

/// Build the FDB key for an invalidation log entry.
///
/// Format: `{prefix}{timestamp_ms}:{event_id}`
/// This ensures entries are ordered by time for efficient range reads.
pub fn invalidation_log_key(timestamp_ms: i64, event_id: &str) -> Vec<u8> {
    let mut key = INVALIDATION_LOG_PREFIX.to_vec();
    // Zero-pad timestamp to ensure proper lexicographic ordering
    key.extend_from_slice(format!("{:020}:", timestamp_ms).as_bytes());
    key.extend_from_slice(event_id.as_bytes());
    key
}

/// Parse timestamp from an invalidation log key.
pub fn parse_invalidation_log_key(key: &[u8]) -> Option<i64> {
    if !key.starts_with(INVALIDATION_LOG_PREFIX) {
        return None;
    }
    let suffix = &key[INVALIDATION_LOG_PREFIX.len()..];
    let colon_pos = suffix.iter().position(|&b| b == b':')?;
    let timestamp_str = std::str::from_utf8(&suffix[..colon_pos]).ok()?;
    timestamp_str.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwks_key() {
        let key = jwks_key("ctrl-inferadb-control-0");
        assert_eq!(key, b"inferadb/control-jwks/ctrl-inferadb-control-0".to_vec());
    }

    #[test]
    fn test_invalidation_log_key() {
        let key = invalidation_log_key(1699999999000, "abc-123");
        // 20-digit zero-padded timestamp for proper lexicographic ordering
        let expected = b"inferadb/invalidation-log/00000001699999999000:abc-123";
        assert_eq!(key, expected.to_vec());
    }

    #[test]
    fn test_parse_invalidation_log_key() {
        let key = invalidation_log_key(1699999999000, "abc-123");
        let parsed = parse_invalidation_log_key(&key);
        assert_eq!(parsed, Some(1699999999000));
    }

    #[test]
    fn test_invalidation_event_serde() {
        let event = InvalidationEvent::Vault { vault_id: 42 };
        let json = serde_json::to_string(&event).unwrap();
        assert_eq!(json, r#"{"type":"vault","vault_id":42}"#);

        let parsed: InvalidationEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn test_stored_jwks_serde() {
        let jwks = StoredJwks {
            control_id: "ctrl-test".to_string(),
            keys: vec![StoredJwk {
                kty: "OKP".to_string(),
                alg: "EdDSA".to_string(),
                kid: "test-kid".to_string(),
                crv: "Ed25519".to_string(),
                x: "base64url-encoded-key".to_string(),
                key_use: "sig".to_string(),
            }],
            updated_at: 1699999999,
        };

        let json = serde_json::to_string(&jwks).unwrap();
        let parsed: StoredJwks = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.control_id, "ctrl-test");
        assert_eq!(parsed.keys.len(), 1);
        assert_eq!(parsed.keys[0].kid, "test-kid");
    }
}
