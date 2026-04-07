//! Cryptographic primitives for the control plane.
//!
//! Provides [`MasterKey`] for at-rest encryption key management,
//! [`PrivateKeyEncryptor`] for AES-256-GCM encryption of Ed25519 private keys,
//! and [`keypair`] for Ed25519 key pair generation.

use std::{fs, path::Path};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD},
};
use inferadb_control_types::error::{Error, Result};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Master encryption key (256-bit / 32 bytes).
///
/// Encrypts client certificate private keys at rest.
/// Loaded from a file or auto-generated on first startup.
///
/// Uses [`ZeroizeOnDrop`] to guarantee key material is securely erased from memory
/// when dropped, preventing dead-store elimination by the optimizer.
///
/// Intentionally does not implement [`Clone`] to prevent accidental copies of
/// cryptographic key material in memory.
///
/// ```compile_fail
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<inferadb_control_core::MasterKey>();
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; 32]);

impl MasterKey {
    /// Loads the master key from a file, or generates a new one if the file does not exist.
    ///
    /// If the file exists, loads and validates the 32-byte key. Otherwise, generates
    /// a new key, creates parent directories as needed, saves the key, and sets file
    /// permissions to 0600 (owner read/write only) on Unix.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read/written, parent directories
    /// cannot be created, or the existing file has an invalid key length.
    pub fn load_or_generate(key_file: &Path) -> Result<Self> {
        if key_file.exists() {
            Self::load_from_file(key_file)
        } else {
            tracing::info!(path = %key_file.display(), "Master key file not found, generating new key");
            let key = Self::generate()?;
            key.save_to_file(key_file)?;
            Ok(key)
        }
    }

    /// Generates a new random 256-bit master key.
    fn generate() -> Result<Self> {
        use rand::RngExt;
        let mut rng = rand::rng();
        let key: [u8; 32] = rng.random();
        Ok(Self(key))
    }

    /// Loads the master key from a file.
    fn load_from_file(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).map_err(|e| {
            Error::config(format!("Failed to read master key file '{}': {}", path.display(), e))
        })?;

        if bytes.len() != 32 {
            return Err(Error::config(format!(
                "Master key file '{}' has invalid length: {} bytes (expected 32)",
                path.display(),
                bytes.len()
            )));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);

        tracing::info!(path = %path.display(), "Loaded master key from file");
        Ok(Self(key))
    }

    /// Saves the master key to a file.
    fn save_to_file(&self, path: &Path) -> Result<()> {
        // Create parent directories if needed
        if let Some(parent) = path.parent()
            && !parent.exists()
        {
            fs::create_dir_all(parent).map_err(|e| {
                Error::config(format!("Failed to create directory '{}': {}", parent.display(), e))
            })?;
        }

        fs::write(path, self.0).map_err(|e| {
            Error::config(format!("Failed to write master key file '{}': {}", path.display(), e))
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o600);
            fs::set_permissions(path, perms).map_err(|e| {
                Error::config(format!("Failed to set permissions on '{}': {}", path.display(), e))
            })?;
        }

        tracing::info!(path = %path.display(), "Generated and saved new master key");
        Ok(())
    }

    /// Returns the key bytes for use with [`PrivateKeyEncryptor`].
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Private key encryption using AES-256-GCM.
///
/// Encrypts Ed25519 private keys for secure at-rest storage.
/// Uses a 256-bit master key directly (no key derivation needed).
pub struct PrivateKeyEncryptor {
    cipher: Aes256Gcm,
}

impl PrivateKeyEncryptor {
    /// Creates a new encryptor from a master key.
    ///
    /// The master key must be exactly 32 bytes (256 bits) of cryptographically
    /// secure random data, typically loaded via [`MasterKey::load_or_generate`].
    ///
    /// # Errors
    ///
    /// Returns an error if the AES-256-GCM cipher fails to initialize.
    pub fn new(master_key: &[u8; 32]) -> Result<Self> {
        let cipher = Aes256Gcm::new_from_slice(master_key)
            .map_err(|e| Error::internal(format!("Failed to initialize cipher: {e}")))?;

        Ok(Self { cipher })
    }

    /// Creates a new encryptor from a [`MasterKey`].
    ///
    /// # Errors
    ///
    /// Returns an error if the AES-256-GCM cipher fails to initialize.
    pub fn from_master_key(master_key: &MasterKey) -> Result<Self> {
        Self::new(master_key.as_bytes())
    }

    /// Encrypts a private key (32 bytes for Ed25519).
    ///
    /// Returns base64-encoded ciphertext with nonce prepended (12 bytes nonce + ciphertext).
    ///
    /// # Errors
    ///
    /// Returns an error if `private_key` is not exactly 32 bytes or encryption fails.
    pub fn encrypt(&self, private_key: &[u8]) -> Result<String> {
        if private_key.len() != 32 {
            return Err(Error::validation("Private key must be 32 bytes (Ed25519)".to_string()));
        }

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let ciphertext = self
            .cipher
            .encrypt(&nonce, private_key)
            .map_err(|e| Error::internal(format!("Failed to encrypt private key: {e}")))?;

        let mut combined = nonce.to_vec();
        combined.extend_from_slice(&ciphertext);

        Ok(BASE64_STANDARD.encode(&combined))
    }

    /// Decrypts a private key.
    ///
    /// Takes a base64-encoded string with the nonce prepended and returns the 32-byte
    /// private key wrapped in [`Zeroizing`] for secure erasure on drop.
    ///
    /// # Errors
    ///
    /// Returns an error if the base64 is invalid, the ciphertext is too short,
    /// decryption fails (wrong key or tampered data), or the plaintext length
    /// is not 32 bytes.
    pub fn decrypt(&self, encrypted_base64: &str) -> Result<Zeroizing<Vec<u8>>> {
        let combined = BASE64_STANDARD
            .decode(encrypted_base64)
            .map_err(|e| Error::internal(format!("Failed to decode encrypted key: {e}")))?;

        // Split nonce and ciphertext (first 12 bytes are nonce)
        if combined.len() < 12 {
            return Err(Error::internal("Encrypted data too short (missing nonce)".to_string()));
        }

        let (nonce_bytes, ciphertext) = combined.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| Error::internal(format!("Failed to decrypt private key: {e}")))?;

        // Verify it's 32 bytes (Ed25519 private key)
        if plaintext.len() != 32 {
            return Err(Error::internal(format!(
                "Decrypted key has invalid length: {} bytes (expected 32)",
                plaintext.len()
            )));
        }

        Ok(Zeroizing::new(plaintext))
    }
}

/// Ed25519 key pair generation for client certificate signing.
pub mod keypair {
    use ed25519_dalek::{SigningKey, VerifyingKey};

    use super::*;

    /// Generates a new Ed25519 key pair.
    ///
    /// Returns `(public_key_base64, private_key_bytes)`. The private key bytes are
    /// wrapped in [`Zeroizing`] and should be encrypted before storage.
    pub fn generate() -> (String, Zeroizing<Vec<u8>>) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key: VerifyingKey = signing_key.verifying_key();

        // JWK standard (RFC 7517) uses URL-safe base64 without padding for key material
        let public_key_base64 = URL_SAFE_NO_PAD.encode(verifying_key.as_bytes());
        let private_key_bytes = Zeroizing::new(signing_key.to_bytes().to_vec());

        (public_key_base64, private_key_bytes)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    fn fixed_master_key_bytes() -> [u8; 32] {
        [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ]
    }

    fn test_encryptor() -> PrivateKeyEncryptor {
        PrivateKeyEncryptor::new(&fixed_master_key_bytes()).unwrap()
    }

    // ── MasterKey ──────────────────────────────────────────────────────

    #[test]
    fn test_master_key_load_or_generate_creates_file_when_absent() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.key");

        let _key = MasterKey::load_or_generate(&path).unwrap();

        assert!(path.exists());
    }

    #[test]
    fn test_master_key_load_or_generate_returns_same_key_on_reload() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.key");

        let key1 = MasterKey::load_or_generate(&path).unwrap();
        let key2 = MasterKey::load_or_generate(&path).unwrap();

        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_master_key_load_or_generate_invalid_length_returns_error() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("invalid.key");
        fs::write(&path, b"too_short").unwrap();

        let result = MasterKey::load_or_generate(&path);

        assert!(result.is_err());
    }

    #[test]
    fn test_master_key_load_or_generate_creates_parent_directories() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nested").join("dir").join("test.key");
        assert!(!path.parent().unwrap().exists());

        let _key = MasterKey::load_or_generate(&path).unwrap();

        assert!(path.exists());
    }

    #[test]
    fn test_master_key_as_bytes_returns_32_bytes() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.key");

        let key = MasterKey::load_or_generate(&path).unwrap();

        assert_eq!(key.as_bytes().len(), 32);
    }

    #[cfg(unix)]
    #[test]
    fn test_master_key_save_sets_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.key");

        let _key = MasterKey::load_or_generate(&path).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    // ── PrivateKeyEncryptor ────────────────────────────────────────────

    #[test]
    fn test_encryptor_new_valid_key_succeeds() {
        let key = fixed_master_key_bytes();
        assert!(PrivateKeyEncryptor::new(&key).is_ok());
    }

    #[test]
    fn test_encryptor_from_master_key_encrypt_decrypt_roundtrips() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.key");
        let master_key = MasterKey::load_or_generate(&path).unwrap();

        let encryptor = PrivateKeyEncryptor::from_master_key(&master_key).unwrap();

        let plaintext = [42u8; 32];
        let encrypted = encryptor.encrypt(&plaintext).unwrap();
        let decrypted = encryptor.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted.as_slice(), &plaintext);
    }

    #[test]
    fn test_encryptor_encrypt_decrypt_roundtrip_preserves_data() {
        let encryptor = test_encryptor();
        let plaintext = [42u8; 32];

        let encrypted = encryptor.encrypt(&plaintext).unwrap();
        let decrypted = encryptor.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted.as_slice(), &plaintext);
    }

    #[test]
    fn test_encryptor_encrypt_non_32_byte_key_returns_validation_error() {
        let encryptor = test_encryptor();

        let result = encryptor.encrypt(&[42u8; 16]);

        assert!(result.is_err());
    }

    #[test]
    fn test_encryptor_encrypt_empty_key_returns_validation_error() {
        let encryptor = test_encryptor();

        let result = encryptor.encrypt(&[]);

        assert!(result.is_err());
    }

    #[test]
    fn test_encryptor_decrypt_invalid_base64_returns_error() {
        let encryptor = test_encryptor();

        let result = encryptor.decrypt("not-valid-base64!!!");

        assert!(result.is_err());
    }

    #[test]
    fn test_encryptor_decrypt_too_short_ciphertext_returns_error() {
        let encryptor = test_encryptor();
        let short_data = BASE64_STANDARD.encode(b"short");

        let result = encryptor.decrypt(&short_data);

        assert!(result.is_err());
    }

    #[test]
    fn test_encryptor_decrypt_corrupted_ciphertext_returns_error() {
        let encryptor = test_encryptor();
        let encrypted = encryptor.encrypt(&[42u8; 32]).unwrap();

        let mut bytes = BASE64_STANDARD.decode(&encrypted).unwrap();
        bytes[20] ^= 0xFF;
        let corrupted = BASE64_STANDARD.encode(&bytes);

        assert!(encryptor.decrypt(&corrupted).is_err());
    }

    #[test]
    fn test_encryptor_decrypt_wrong_key_returns_error() {
        let encryptor_a = PrivateKeyEncryptor::new(&[0xAA; 32]).unwrap();
        let encryptor_b = PrivateKeyEncryptor::new(&[0xBB; 32]).unwrap();

        let encrypted = encryptor_a.encrypt(&[42u8; 32]).unwrap();

        assert!(encryptor_b.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_encryptor_encrypt_produces_unique_ciphertexts_per_call() {
        let encryptor = test_encryptor();
        let plaintext = [42u8; 32];

        let ct1 = encryptor.encrypt(&plaintext).unwrap();
        let ct2 = encryptor.encrypt(&plaintext).unwrap();

        assert_ne!(ct1, ct2, "random nonces must produce different ciphertexts");

        let pt1 = encryptor.decrypt(&ct1).unwrap();
        let pt2 = encryptor.decrypt(&ct2).unwrap();
        assert_eq!(pt1.as_slice(), pt2.as_slice());
    }

    // ── keypair ────────────────────────────────────────────────────────

    #[test]
    fn test_keypair_generate_returns_32_byte_public_and_private_keys() {
        let (public_b64, private_bytes) = keypair::generate();

        let public_decoded = URL_SAFE_NO_PAD.decode(&public_b64).unwrap();
        assert_eq!(public_decoded.len(), 32);
        assert_eq!(private_bytes.len(), 32);
    }

    #[test]
    fn test_keypair_generate_public_key_is_valid_ed25519() {
        let (public_b64, _) = keypair::generate();

        let decoded = URL_SAFE_NO_PAD.decode(&public_b64).unwrap();
        let key_bytes: [u8; 32] = decoded.try_into().unwrap();
        assert!(ed25519_dalek::VerifyingKey::from_bytes(&key_bytes).is_ok());
    }

    #[test]
    fn test_keypair_generate_unique_keys_per_call() {
        let (pub1, priv1) = keypair::generate();
        let (pub2, priv2) = keypair::generate();

        assert_ne!(pub1, pub2);
        assert_ne!(priv1.as_slice(), priv2.as_slice());
    }

    #[test]
    fn test_keypair_encrypt_decrypt_integration() {
        let encryptor = test_encryptor();
        let (_public_key, private_key_bytes) = keypair::generate();

        let encrypted = encryptor.encrypt(&private_key_bytes).unwrap();
        let decrypted = encryptor.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted.as_slice(), private_key_bytes.as_slice());
    }

    #[test]
    fn test_keypair_base64_roundtrip_consistency() {
        for _ in 0..256 {
            let (public_b64, _) = keypair::generate();

            let decoded = URL_SAFE_NO_PAD
                .decode(&public_b64)
                .expect("URL_SAFE_NO_PAD decode should succeed for every generated key");
            assert_eq!(decoded.len(), 32, "Ed25519 public key must be 32 bytes");

            let re_encoded = URL_SAFE_NO_PAD.encode(&decoded);
            assert_eq!(re_encoded, public_b64, "base64 roundtrip must be lossless");

            ed25519_dalek::VerifyingKey::from_bytes(&decoded.try_into().unwrap())
                .expect("decoded bytes must form a valid Ed25519 public key");
        }
    }

    mod proptest_crypto {
        use proptest::prelude::*;

        use super::*;

        fn proptest_encryptor() -> PrivateKeyEncryptor {
            PrivateKeyEncryptor::new(&[0x42; 32]).unwrap()
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            #[test]
            fn encrypt_decrypt_roundtrip(key in proptest::collection::vec(any::<u8>(), 32)) {
                let encryptor = proptest_encryptor();
                let key_arr: [u8; 32] = key.try_into().unwrap();

                let encrypted = encryptor.encrypt(&key_arr).unwrap();
                let decrypted = encryptor.decrypt(&encrypted).unwrap();
                prop_assert_eq!(&*decrypted, &key_arr);
            }

            #[test]
            fn encrypt_produces_unique_ciphertexts(key in proptest::collection::vec(any::<u8>(), 32)) {
                let encryptor = proptest_encryptor();
                let key_arr: [u8; 32] = key.try_into().unwrap();

                let ct1 = encryptor.encrypt(&key_arr).unwrap();
                let ct2 = encryptor.encrypt(&key_arr).unwrap();
                prop_assert_ne!(&ct1, &ct2);

                let pt1 = encryptor.decrypt(&ct1).unwrap();
                let pt2 = encryptor.decrypt(&ct2).unwrap();
                prop_assert_eq!(&*pt1, &*pt2);
            }

            #[test]
            fn encrypt_rejects_non_32_byte_keys(len in (0usize..100).prop_filter("not 32", |l| *l != 32)) {
                let encryptor = proptest_encryptor();
                let key = vec![0u8; len];
                prop_assert!(encryptor.encrypt(&key).is_err());
            }
        }
    }
}
