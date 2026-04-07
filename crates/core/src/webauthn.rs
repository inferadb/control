//! WebAuthn ceremony orchestration.
//!
//! Manages the stateful challenge/response flow for passkey registration
//! and authentication. Challenges are serialized, encrypted with AES-256-GCM,
//! and returned as opaque tokens — eliminating in-memory state for horizontal
//! scaling.
//!
//! Credential storage is delegated to Ledger.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes_gcm::{AeadCore, AeadInPlace, Aes256Gcm, KeyInit, aead::OsRng};
use base64::engine::{Engine, general_purpose::URL_SAFE_NO_PAD};
use inferadb_control_types::error::{Error, Result};
use inferadb_ledger_types::{CredentialData, PasskeyCredential};
use serde::{Deserialize, Serialize};
use url::Url;
use webauthn_rs::prelude::*;

/// Challenge TTL — challenges expire after 60 seconds.
const CHALLENGE_TTL: Duration = Duration::from_secs(60);

/// AES-256-GCM nonce length in bytes.
const NONCE_LEN: usize = 12;

/// Timestamp length in bytes (u64 seconds since epoch).
const TIMESTAMP_LEN: usize = 8;

/// Ephemeral state stored between begin/finish calls.
///
/// Serialized and encrypted into an opaque challenge token that the client
/// passes back during the finish step.
#[derive(Clone, Serialize, Deserialize)]
pub enum ChallengeState {
    /// Begin-registration state awaiting the authenticator's attestation response.
    Registration {
        /// Ledger user slug that initiated registration.
        user_slug: u64,
        /// Webauthn-rs registration ceremony state.
        state: PasskeyRegistration,
    },
    /// Begin-authentication state awaiting the authenticator's assertion response.
    Authentication {
        /// Ledger user slug attempting authentication.
        user_slug: u64,
        /// Webauthn-rs authentication ceremony state.
        state: PasskeyAuthentication,
    },
}

/// Stateless challenge store backed by AES-256-GCM encrypted tokens.
///
/// Each challenge is serialized to JSON, prepended with a creation timestamp,
/// encrypted with a random nonce, and base64url-encoded. The resulting string
/// serves as both the challenge ID and the challenge state — no server-side
/// storage is required.
///
/// On `take()`, the token is decoded, decrypted, the timestamp is validated
/// against the TTL, and the `ChallengeState` is deserialized.
///
/// # Replay Prevention
///
/// The stateless design means tokens can be replayed within the 60-second TTL
/// window. This is an accepted trade-off for horizontal scalability:
///
/// - **Authentication:** webauthn-rs validates the authenticator's cryptographic challenge
///   response, preventing replay of the actual credential assertion.
/// - **Registration:** Ledger handles idempotency for credential creation.
/// - The TTL is deliberately short (60 seconds) to minimize the replay window.
#[derive(Clone)]
pub struct ChallengeStore {
    cipher: Aes256Gcm,
}

impl ChallengeStore {
    /// Creates a new stateless challenge store with the given 32-byte AES key.
    ///
    /// In production, derive this key from the master key. For dev/test mode,
    /// use [`Default`](Self::default) which generates a random key.
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher = Aes256Gcm::new(key.into());
        Self { cipher }
    }

    /// Stores a challenge state by encrypting it into an opaque token.
    ///
    /// Returns a base64url-encoded string containing `nonce || ciphertext || tag`.
    /// The plaintext is `timestamp_bytes || json_bytes`.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization or encryption fails, or if the system
    /// clock cannot be read.
    pub fn insert(&self, state: ChallengeState) -> Result<String> {
        let json = serde_json::to_vec(&state)
            .map_err(|e| Error::internal(format!("failed to serialize challenge state: {e}")))?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Error::internal(format!("system clock error: {e}")))?;
        let timestamp_bytes = now.as_secs().to_be_bytes();

        // Plaintext: timestamp || json
        let mut plaintext = Vec::with_capacity(TIMESTAMP_LEN + json.len());
        plaintext.extend_from_slice(&timestamp_bytes);
        plaintext.extend_from_slice(&json);

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        self.cipher
            .encrypt_in_place(&nonce, b"", &mut plaintext)
            .map_err(|e| Error::internal(format!("challenge encryption failed: {e}")))?;

        // Output: nonce || ciphertext+tag
        let mut output = Vec::with_capacity(NONCE_LEN + plaintext.len());
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&plaintext);

        Ok(URL_SAFE_NO_PAD.encode(&output))
    }

    /// Retrieves a challenge state by decrypting and validating the token.
    ///
    /// Returns `None` if the token is invalid, expired, or tampered with.
    pub fn take(&self, token: &str) -> Option<ChallengeState> {
        self.take_inner(token).ok()
    }

    fn take_inner(&self, token: &str) -> Result<ChallengeState> {
        let raw = URL_SAFE_NO_PAD
            .decode(token)
            .map_err(|e| Error::validation(format!("invalid challenge token encoding: {e}")))?;

        if raw.len() < NONCE_LEN + TIMESTAMP_LEN {
            return Err(Error::validation("challenge token too short"));
        }

        let (nonce_bytes, ciphertext) = raw.split_at(NONCE_LEN);
        let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);

        let mut buffer = ciphertext.to_vec();
        self.cipher
            .decrypt_in_place(nonce, b"", &mut buffer)
            .map_err(|_| Error::validation("challenge token decryption failed"))?;

        if buffer.len() < TIMESTAMP_LEN {
            return Err(Error::validation("challenge token plaintext too short"));
        }

        let (ts_bytes, json_bytes) = buffer.split_at(TIMESTAMP_LEN);
        let created_secs = u64::from_be_bytes(
            ts_bytes.try_into().map_err(|_| Error::internal("timestamp conversion error"))?,
        );

        // Validate TTL
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Error::internal(format!("system clock error: {e}")))?
            .as_secs();

        let age = now_secs.saturating_sub(created_secs);
        if age > CHALLENGE_TTL.as_secs() {
            return Err(Error::validation("challenge token expired"));
        }

        serde_json::from_slice(json_bytes)
            .map_err(|e| Error::internal(format!("failed to deserialize challenge state: {e}")))
    }
}

impl Default for ChallengeStore {
    fn default() -> Self {
        use rand::RngExt;
        let key: [u8; 32] = rand::rng().random();
        Self::new(&key)
    }
}

/// Builds a `Webauthn` instance from configuration.
///
/// The RP ID and origin are immutable after deployment — changing them
/// invalidates all registered credentials.
///
/// # Errors
///
/// Returns an error if the origin URL is invalid or the WebAuthn builder
/// rejects the configuration.
pub fn build_webauthn(rp_id: &str, origin: &str) -> Result<webauthn_rs::Webauthn> {
    let rp_origin =
        Url::parse(origin).map_err(|e| Error::config(format!("invalid WebAuthn origin: {e}")))?;

    let builder = WebauthnBuilder::new(rp_id, &rp_origin)
        .map_err(|e| Error::config(format!("WebAuthn builder error: {e}")))?;

    builder
        .rp_name("InferaDB")
        .build()
        .map_err(|e| Error::config(format!("WebAuthn build error: {e}")))
}

// ── Type Conversions ────────────────────────────────────────────────────

/// Converts a webauthn-rs [`Passkey`] into Ledger SDK [`CredentialData::Passkey`].
///
/// Serializes the entire [`Passkey`] as JSON into the `public_key` field,
/// avoiding dependency on webauthn-rs internal struct layouts and guaranteeing
/// lossless round-tripping via [`credential_info_to_passkey`].
///
/// # Errors
///
/// Returns an error if the passkey cannot be serialized to JSON.
pub fn passkey_to_credential_data(passkey: &Passkey) -> Result<CredentialData> {
    let cred: Credential = passkey.clone().into();

    let credential_id: Vec<u8> = cred.cred_id.as_ref().to_vec();

    let transports = cred
        .transports
        .as_ref()
        .map(|ts| ts.iter().map(|t| format!("{t:?}").to_lowercase()).collect())
        .unwrap_or_default();

    let passkey_json = serde_json::to_vec(passkey)
        .map_err(|e| Error::internal(format!("failed to serialize passkey: {e}")))?;

    Ok(CredentialData::Passkey(PasskeyCredential {
        credential_id,
        public_key: passkey_json,
        sign_count: cred.counter,
        transports,
        backup_eligible: cred.backup_eligible,
        backup_state: cred.backup_state,
        attestation_format: match cred.attestation_format {
            AttestationFormat::None => None,
            other => Some(format!("{other:?}")),
        },
        aaguid: None,
    }))
}

/// Converts Ledger SDK [`PasskeyCredential`] back to a webauthn-rs [`Passkey`].
///
/// Deserializes the [`Passkey`] from the JSON stored in `public_key`.
/// Inverse of [`passkey_to_credential_data`].
///
/// # Errors
///
/// Returns an error if the stored JSON cannot be deserialized into a [`Passkey`].
pub fn credential_info_to_passkey(info: &PasskeyCredential) -> Result<Passkey> {
    serde_json::from_slice(&info.public_key)
        .map_err(|e| Error::internal(format!("failed to deserialize passkey: {e}")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Helper: produce a real `ChallengeState::Registration` via webauthn-rs.
    fn registration_state(user_slug: u64) -> ChallengeState {
        let webauthn = build_webauthn("localhost", "http://localhost:3000").unwrap();
        let user_id = Uuid::new_v4();
        let (_, reg_state) =
            webauthn.start_passkey_registration(user_id, "test-user", "Test User", None).unwrap();
        ChallengeState::Registration { user_slug, state: reg_state }
    }

    /// Helper: craft a token with a specific timestamp using raw crypto ops.
    fn craft_token_with_timestamp(
        store: &ChallengeStore,
        json: &[u8],
        timestamp_secs: u64,
    ) -> String {
        let mut plaintext = Vec::with_capacity(TIMESTAMP_LEN + json.len());
        plaintext.extend_from_slice(&timestamp_secs.to_be_bytes());
        plaintext.extend_from_slice(json);

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        store.cipher.encrypt_in_place(&nonce, b"", &mut plaintext).unwrap();

        let mut output = Vec::with_capacity(NONCE_LEN + plaintext.len());
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&plaintext);

        URL_SAFE_NO_PAD.encode(&output)
    }

    // ── ChallengeStore ─────────────────────────────────────────────────

    #[test]
    fn test_challenge_store_insert_take_roundtrip_preserves_registration_state() {
        let store = ChallengeStore::default();
        let state = registration_state(42);

        let token = store.insert(state).unwrap();
        let recovered = store.take(&token).unwrap();
        match recovered {
            ChallengeState::Registration { user_slug, .. } => assert_eq!(user_slug, 42),
            _ => panic!("expected Registration variant"),
        }
    }

    #[test]
    fn test_challenge_store_insert_produces_nonempty_token() {
        let store = ChallengeStore::default();
        let state = registration_state(1);

        let token = store.insert(state).unwrap();

        assert!(!token.is_empty());
    }

    #[test]
    fn test_challenge_store_stateless_token_reusable_within_ttl() {
        let store = ChallengeStore::default();
        let state = registration_state(1);
        let token = store.insert(state).unwrap();

        // Stateless design: token decrypts on every call within TTL
        assert!(store.take(&token).is_some());
        assert!(store.take(&token).is_some());
    }

    #[test]
    fn test_challenge_store_take_garbage_string_returns_none() {
        let store = ChallengeStore::default();

        assert!(store.take("nonexistent-token").is_none());
    }

    #[test]
    fn test_challenge_store_take_empty_string_returns_none() {
        let store = ChallengeStore::default();

        assert!(store.take("").is_none());
    }

    #[test]
    fn test_challenge_store_take_expired_token_returns_none() {
        let key = [0u8; 32];
        let store = ChallengeStore::new(&key);
        let two_minutes_ago =
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs().saturating_sub(120);

        let token = craft_token_with_timestamp(&store, b"{}", two_minutes_ago);

        assert!(store.take(&token).is_none());
    }

    #[test]
    fn test_challenge_store_take_tampered_ciphertext_returns_none() {
        let store = ChallengeStore::default();
        let token = URL_SAFE_NO_PAD.encode([42u8; 64]);

        assert!(store.take(&token).is_none());
    }

    #[test]
    fn test_challenge_store_take_shorter_than_nonce_returns_none() {
        let store = ChallengeStore::default();
        let token = URL_SAFE_NO_PAD.encode([1u8; 4]);

        assert!(store.take(&token).is_none());
    }

    #[test]
    fn test_challenge_store_take_missing_timestamp_returns_none() {
        let store = ChallengeStore::default();
        let token = URL_SAFE_NO_PAD.encode([0u8; NONCE_LEN]);

        assert!(store.take(&token).is_none());
    }

    #[test]
    fn test_challenge_store_take_partial_timestamp_returns_none() {
        let store = ChallengeStore::default();
        let token = URL_SAFE_NO_PAD.encode([0u8; NONCE_LEN + TIMESTAMP_LEN - 1]);

        assert!(store.take(&token).is_none());
    }

    #[test]
    fn test_challenge_store_take_corrupted_payload_returns_none() {
        let store = ChallengeStore::default();
        let data = [0xAB_u8; NONCE_LEN + TIMESTAMP_LEN + 32];
        let token = URL_SAFE_NO_PAD.encode(data);

        assert!(store.take(&token).is_none());
    }

    #[test]
    fn test_challenge_store_different_keys_cannot_decrypt_each_others_tokens() {
        let store_a = ChallengeStore::new(&[1u8; 32]);
        let store_b = ChallengeStore::new(&[2u8; 32]);
        let state = registration_state(1);

        let token = store_a.insert(state).unwrap();

        assert!(store_b.take(&token).is_none());
    }

    #[test]
    fn test_challenge_store_default_creates_functional_store() {
        let store = ChallengeStore::default();
        let state = registration_state(99);

        let token = store.insert(state).unwrap();
        let recovered = store.take(&token);

        assert!(recovered.is_some());
    }

    #[test]
    fn test_challenge_store_new_explicit_key_insert_take_roundtrips() {
        let store = ChallengeStore::new(&[7u8; 32]);
        let state = registration_state(55);

        let token = store.insert(state).unwrap();
        let recovered = store.take(&token).unwrap();

        match recovered {
            ChallengeState::Registration { user_slug, .. } => assert_eq!(user_slug, 55),
            ChallengeState::Authentication { .. } => panic!("expected Registration variant"),
        }
    }

    // ── build_webauthn ─────────────────────────────────────────────────

    #[test]
    fn test_build_webauthn_localhost_http_succeeds() {
        assert!(build_webauthn("localhost", "http://localhost:3000").is_ok());
    }

    #[test]
    fn test_build_webauthn_https_origin_succeeds() {
        assert!(build_webauthn("example.com", "https://example.com").is_ok());
    }

    #[test]
    fn test_build_webauthn_invalid_origin_returns_error() {
        assert!(build_webauthn("localhost", "not-a-url").is_err());
    }

    // ── Credential conversions ─────────────────────────────────────────

    #[test]
    fn test_credential_info_to_passkey_invalid_json_returns_error() {
        let info = PasskeyCredential {
            credential_id: vec![1, 2, 3],
            public_key: b"not-valid-json".to_vec(),
            sign_count: 0,
            transports: vec![],
            backup_eligible: false,
            backup_state: false,
            attestation_format: None,
            aaguid: None,
        };

        assert!(credential_info_to_passkey(&info).is_err());
    }
}
