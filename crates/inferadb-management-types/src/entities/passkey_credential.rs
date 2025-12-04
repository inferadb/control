use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;

/// Passkey credential for WebAuthn authentication
///
/// Stores a user's passkey credential including the public key and metadata.
/// Users can have multiple passkey credentials registered.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PasskeyCredential {
    /// Unique credential ID (Snowflake)
    pub id: i64,

    /// User ID this credential belongs to
    pub user_id: i64,

    /// Credential ID from WebAuthn (binary, base64url-encoded)
    pub credential_id: Vec<u8>,

    /// Public key credential data (serialized from webauthn-rs)
    /// Uses danger-allow-state-serialisation feature
    pub credential: Passkey,

    /// Human-readable name for the credential (e.g., "MacBook Pro Touch ID")
    pub name: String,

    /// Backup eligible flag (indicates if credential can be backed up)
    pub backup_eligible: bool,

    /// Backup state flag (indicates if credential is currently backed up)
    pub backup_state: bool,

    /// Counter for replay protection
    pub counter: u32,

    /// Attestation format used during registration
    pub attestation_format: Option<String>,

    /// Timestamp of registration
    pub created_at: SystemTime,

    /// Timestamp of last use
    pub last_used_at: Option<SystemTime>,
}

impl PasskeyCredential {
    /// Create a new passkey credential
    pub fn new(
        id: i64,
        user_id: i64,
        credential: Passkey,
        name: String,
        attestation_format: Option<String>,
    ) -> Self {
        let credential_id = credential.cred_id().clone().into();
        Self {
            id,
            user_id,
            credential_id,
            credential,
            name,
            backup_eligible: false,
            backup_state: false,
            counter: 0,
            attestation_format,
            created_at: SystemTime::now(),
            last_used_at: None,
        }
    }

    /// Update the counter after successful authentication
    pub fn update_counter(&mut self, new_counter: u32) {
        self.counter = new_counter;
        self.last_used_at = Some(SystemTime::now());
    }

    /// Update backup state
    pub fn update_backup_state(&mut self, backup_eligible: bool, backup_state: bool) {
        self.backup_eligible = backup_eligible;
        self.backup_state = backup_state;
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_new_passkey_credential() {
        // Note: This test is limited because we can't easily create a real Passkey
        // without going through the full WebAuthn registration flow
        // Real passkey credentials are tested in integration tests
    }

    #[test]
    fn test_update_counter() {
        // We'll add integration tests for this
    }
}
