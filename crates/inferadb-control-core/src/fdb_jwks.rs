//! FDB-based JWKS writer for Control-to-Engine communication
//!
//! This module writes Control's JWKS to FDB, where Engine instances can read it
//! for verifying Control-signed JWTs. This replaces HTTP-based JWKS discovery.

use std::sync::Arc;

use chrono::Utc;
use foundationdb::Database;
use inferadb_control_fdb_shared::{StoredJwk, StoredJwks, jwks_key};
use inferadb_control_types::ControlIdentity;
use tracing::{debug, info};

/// FDB-based JWKS writer
///
/// Writes Control's JWKS to FDB on startup and removes it on shutdown.
/// Engine instances read from the same FDB keyspace to verify Control JWTs.
#[derive(Clone)]
pub struct FdbJwksWriter {
    db: Arc<Database>,
    control_identity: Arc<ControlIdentity>,
}

impl FdbJwksWriter {
    /// Create a new FDB JWKS writer
    pub fn new(db: Arc<Database>, control_identity: Arc<ControlIdentity>) -> Self {
        Self { db, control_identity }
    }

    /// Write the Control JWKS to FDB
    ///
    /// Should be called at startup after the Control identity is generated.
    pub async fn write_jwks(&self) -> Result<(), String> {
        let jwks = self.control_identity.to_jwks();
        let control_id = &self.control_identity.control_id;

        let stored_jwks = StoredJwks {
            control_id: control_id.clone(),
            keys: jwks
                .keys
                .into_iter()
                .map(|k| StoredJwk {
                    kty: k.kty,
                    alg: k.alg,
                    kid: k.kid,
                    crv: k.crv,
                    x: k.x,
                    key_use: k.key_use,
                })
                .collect(),
            updated_at: Utc::now().timestamp(),
        };

        let key = jwks_key(control_id);
        let value = serde_json::to_vec(&stored_jwks)
            .map_err(|e| format!("Failed to serialize JWKS: {e}"))?;

        let db = Arc::clone(&self.db);
        db.run({
            let key = key.clone();
            let value = value.clone();
            move |trx, _maybe_committed| {
                let key = key.clone();
                let value = value.clone();
                async move {
                    trx.set(&key, &value);
                    Ok(())
                }
            }
        })
        .await
        .map_err(|e| format!("Failed to write JWKS to FDB: {e}"))?;

        info!(
            control_id = %control_id,
            kid = %self.control_identity.kid,
            "Wrote Control JWKS to FDB"
        );

        Ok(())
    }

    /// Remove the Control JWKS from FDB
    ///
    /// Should be called during graceful shutdown.
    pub async fn remove_jwks(&self) -> Result<(), String> {
        let control_id = &self.control_identity.control_id;
        let key = jwks_key(control_id);

        let db = Arc::clone(&self.db);
        db.run({
            let key = key.clone();
            move |trx, _maybe_committed| {
                let key = key.clone();
                async move {
                    trx.clear(&key);
                    Ok(())
                }
            }
        })
        .await
        .map_err(|e| format!("Failed to remove JWKS from FDB: {e}"))?;

        debug!(
            control_id = %control_id,
            "Removed Control JWKS from FDB"
        );

        Ok(())
    }

    /// Start the JWKS writer background task
    ///
    /// This writes the JWKS immediately and sets up cleanup on shutdown.
    pub async fn start(&self) -> Result<(), String> {
        self.write_jwks().await
    }
}

impl Drop for FdbJwksWriter {
    fn drop(&mut self) {
        // Note: This won't run async code, but we log the intent
        // Actual cleanup should be done via remove_jwks() before drop
        debug!(
            control_id = %self.control_identity.control_id,
            "FdbJwksWriter dropped"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stored_jwks_serialization() {
        let stored = StoredJwks {
            control_id: "ctrl-test".to_string(),
            keys: vec![StoredJwk {
                kty: "OKP".to_string(),
                alg: "EdDSA".to_string(),
                kid: "test-kid".to_string(),
                crv: "Ed25519".to_string(),
                x: "test-x".to_string(),
                key_use: "sig".to_string(),
            }],
            updated_at: 1234567890,
        };

        let json = serde_json::to_string(&stored).unwrap();
        let parsed: StoredJwks = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.control_id, "ctrl-test");
        assert_eq!(parsed.keys.len(), 1);
    }
}
