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

/// Master encryption key (256-bit / 32 bytes)
///
/// This key is used to encrypt client certificate private keys at rest.
/// It is loaded from a file or auto-generated on first startup.
#[derive(Clone)]
pub struct MasterKey([u8; 32]);

impl MasterKey {
    /// Load the master key from a file, or generate a new one if it doesn't exist.
    ///
    /// # Arguments
    /// * `key_file` - Optional path to the key file. If None, uses default path.
    ///
    /// # Behavior
    /// - If file exists: load and validate the 32-byte key
    /// - If file doesn't exist: generate a new key and save it
    /// - Creates parent directories if needed
    /// - Sets file permissions to 0600 (owner read/write only) on Unix
    pub fn load_or_generate(key_file: Option<&str>) -> Result<Self> {
        let default_path = "./data/master.key".to_string();
        let path_str = key_file.unwrap_or(&default_path);
        let path = Path::new(path_str);

        if path.exists() {
            Self::load_from_file(path)
        } else {
            tracing::info!(path = %path.display(), "Master key file not found, generating new key");
            let key = Self::generate()?;
            key.save_to_file(path)?;
            Ok(key)
        }
    }

    /// Generate a new random 256-bit master key
    fn generate() -> Result<Self> {
        use rand::Rng;
        let mut rng = rand::rng();
        let key: [u8; 32] = rng.random();
        Ok(Self(key))
    }

    /// Load the master key from a file
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

    /// Save the master key to a file
    fn save_to_file(&self, path: &Path) -> Result<()> {
        // Create parent directories if needed
        if let Some(parent) = path.parent()
            && !parent.exists()
        {
            fs::create_dir_all(parent).map_err(|e| {
                Error::config(format!("Failed to create directory '{}': {}", parent.display(), e))
            })?;
        }

        // Write the key file
        fs::write(path, self.0).map_err(|e| {
            Error::config(format!("Failed to write master key file '{}': {}", path.display(), e))
        })?;

        // Set restrictive permissions on Unix
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

    /// Get the key bytes for use with PrivateKeyEncryptor
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        // Zero out the key when dropped for security
        self.0.fill(0);
    }
}

/// Private key encryption service using AES-256-GCM
///
/// This service encrypts Ed25519 private keys for secure storage in the database.
/// Uses a 256-bit master key directly (no key derivation needed).
pub struct PrivateKeyEncryptor {
    cipher: Aes256Gcm,
}

impl PrivateKeyEncryptor {
    /// Create a new encryptor from a master key
    ///
    /// The master key should be exactly 32 bytes (256 bits) of cryptographically
    /// secure random data, typically loaded via `MasterKey::load_or_generate()`.
    pub fn new(master_key: &[u8; 32]) -> Result<Self> {
        let cipher = Aes256Gcm::new_from_slice(master_key)
            .map_err(|e| Error::internal(format!("Failed to initialize cipher: {e}")))?;

        Ok(Self { cipher })
    }

    /// Create a new encryptor from a MasterKey
    pub fn from_master_key(master_key: &MasterKey) -> Result<Self> {
        Self::new(master_key.as_bytes())
    }

    /// Encrypt a private key (32 bytes for Ed25519)
    ///
    /// Returns base64-encoded ciphertext with nonce prepended (12 bytes nonce + ciphertext)
    pub fn encrypt(&self, private_key: &[u8]) -> Result<String> {
        if private_key.len() != 32 {
            return Err(Error::validation("Private key must be 32 bytes (Ed25519)".to_string()));
        }

        // Generate a random 96-bit nonce (12 bytes)
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        // Encrypt the private key
        let ciphertext = self
            .cipher
            .encrypt(&nonce, private_key)
            .map_err(|e| Error::internal(format!("Failed to encrypt private key: {e}")))?;

        // Combine nonce + ciphertext for storage
        let mut combined = nonce.to_vec();
        combined.extend_from_slice(&ciphertext);

        // Encode to base64
        Ok(BASE64_STANDARD.encode(&combined))
    }

    /// Decrypt a private key
    ///
    /// Takes base64-encoded string with nonce prepended, returns the 32-byte private key
    ///
    /// IMPORTANT: The returned Vec contains sensitive key material and should be zeroized when no
    /// longer needed.
    pub fn decrypt(&self, encrypted_base64: &str) -> Result<Vec<u8>> {
        // Decode from base64
        let combined = BASE64_STANDARD
            .decode(encrypted_base64)
            .map_err(|e| Error::internal(format!("Failed to decode encrypted key: {e}")))?;

        // Split nonce and ciphertext (first 12 bytes are nonce)
        if combined.len() < 12 {
            return Err(Error::internal("Encrypted data too short (missing nonce)".to_string()));
        }

        let (nonce_bytes, ciphertext) = combined.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Decrypt the private key
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

        Ok(plaintext)
    }
}

/// Generate a new Ed25519 key pair
pub mod keypair {
    use ed25519_dalek::{SigningKey, VerifyingKey};

    use super::*;

    /// Generate a new Ed25519 key pair
    ///
    /// Returns (public_key_base64, private_key_bytes)
    /// The private key bytes should be encrypted before storage
    pub fn generate() -> (String, Vec<u8>) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key: VerifyingKey = signing_key.verifying_key();

        // JWK standard (RFC 7517) uses URL-safe base64 without padding for key material
        let public_key_base64 = URL_SAFE_NO_PAD.encode(verifying_key.as_bytes());
        let private_key_bytes = signing_key.to_bytes().to_vec();

        (public_key_base64, private_key_bytes)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    fn create_test_key() -> [u8; 32] {
        // Fixed test key for reproducible tests
        [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ]
    }

    fn create_test_encryptor() -> PrivateKeyEncryptor {
        let key = create_test_key();
        PrivateKeyEncryptor::new(&key).unwrap()
    }

    #[test]
    fn test_encryptor_creation() {
        let key = create_test_key();
        assert!(PrivateKeyEncryptor::new(&key).is_ok());
    }

    #[test]
    fn test_master_key_generate_and_load() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("test.key");
        let key_path_str = key_path.to_str().unwrap();

        // First call should generate a new key
        let key1 = MasterKey::load_or_generate(Some(key_path_str)).unwrap();

        // File should exist now
        assert!(key_path.exists());

        // Second call should load the same key
        let key2 = MasterKey::load_or_generate(Some(key_path_str)).unwrap();

        // Keys should be identical
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_master_key_invalid_length() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("invalid.key");

        // Write a file with wrong length
        fs::write(&key_path, b"too_short").unwrap();

        // Loading should fail
        let result = MasterKey::load_or_generate(Some(key_path.to_str().unwrap()));
        assert!(result.is_err());
    }

    #[test]
    fn test_master_key_creates_parent_dirs() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("nested").join("dir").join("test.key");
        let key_path_str = key_path.to_str().unwrap();

        // Parent directories don't exist yet
        assert!(!key_path.parent().unwrap().exists());

        // Should create parent dirs and generate key
        let _key = MasterKey::load_or_generate(Some(key_path_str)).unwrap();

        // File and parents should exist now
        assert!(key_path.exists());
    }

    #[test]
    fn test_encryptor_from_master_key() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("test.key");
        let key_path_str = key_path.to_str().unwrap();

        let master_key = MasterKey::load_or_generate(Some(key_path_str)).unwrap();
        let encryptor = PrivateKeyEncryptor::from_master_key(&master_key).unwrap();

        // Should work for encryption/decryption
        let private_key = [42u8; 32];
        let encrypted = encryptor.encrypt(&private_key).unwrap();
        let decrypted = encryptor.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted.as_slice(), &private_key);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let encryptor = create_test_encryptor();

        // Generate a test private key (32 bytes)
        let private_key = [42u8; 32];

        // Encrypt
        let encrypted = encryptor.encrypt(&private_key).unwrap();
        assert!(!encrypted.is_empty());

        // Decrypt
        let decrypted = encryptor.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted.as_slice(), &private_key);
    }

    #[test]
    fn test_encrypt_invalid_key_length() {
        let encryptor = create_test_encryptor();

        let wrong_size = [42u8; 16]; // Wrong size (not 32 bytes)
        assert!(encryptor.encrypt(&wrong_size).is_err());
    }

    #[test]
    fn test_decrypt_invalid_base64() {
        let encryptor = create_test_encryptor();
        assert!(encryptor.decrypt("not-valid-base64!!!").is_err());
    }

    #[test]
    fn test_decrypt_too_short() {
        let encryptor = create_test_encryptor();
        let short_data = BASE64_STANDARD.encode(b"short");
        assert!(encryptor.decrypt(&short_data).is_err());
    }

    #[test]
    fn test_decrypt_corrupted_ciphertext() {
        let encryptor = create_test_encryptor();
        let private_key = [42u8; 32];
        let encrypted = encryptor.encrypt(&private_key).unwrap();

        // Corrupt the ciphertext
        let mut corrupted_bytes = BASE64_STANDARD.decode(&encrypted).unwrap();
        corrupted_bytes[20] ^= 0xFF; // Flip bits in ciphertext
        let corrupted = BASE64_STANDARD.encode(&corrupted_bytes);

        assert!(encryptor.decrypt(&corrupted).is_err());
    }

    #[test]
    fn test_encryption_is_nondeterministic() {
        let encryptor = create_test_encryptor();
        let private_key = [42u8; 32];

        let encrypted1 = encryptor.encrypt(&private_key).unwrap();
        let encrypted2 = encryptor.encrypt(&private_key).unwrap();

        // Same plaintext should produce different ciphertexts (due to random nonces)
        assert_ne!(encrypted1, encrypted2);

        // But both should decrypt to the same plaintext
        let decrypted1 = encryptor.decrypt(&encrypted1).unwrap();
        let decrypted2 = encryptor.decrypt(&encrypted2).unwrap();
        assert_eq!(decrypted1.as_slice(), decrypted2.as_slice());
    }

    #[test]
    fn test_keypair_generation() {
        let (public_key_base64, private_key_bytes) = keypair::generate();

        // Public key should be URL-safe base64 encoded 32 bytes (Ed25519, JWK standard)
        let public_key_decoded = URL_SAFE_NO_PAD.decode(&public_key_base64).unwrap();
        assert_eq!(public_key_decoded.len(), 32);

        // Private key should be 32 bytes
        assert_eq!(private_key_bytes.len(), 32);
    }

    #[test]
    fn test_keypair_encryption_integration() {
        let encryptor = create_test_encryptor();

        // Generate a real Ed25519 key pair
        let (_public_key, private_key_bytes) = keypair::generate();

        // Encrypt the private key
        let encrypted = encryptor.encrypt(&private_key_bytes).unwrap();

        // Decrypt and verify
        let decrypted = encryptor.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted.as_slice(), &private_key_bytes);
    }

    #[test]
    fn test_keypair_base64_roundtrip_consistency() {
        // Generate multiple keypairs and verify the public key survives a
        // URL_SAFE_NO_PAD encode → decode roundtrip, confirming no encoding
        // mismatch between generation and consumption.
        for _ in 0..256 {
            let (public_key_base64, _private_key_bytes) = keypair::generate();

            // Decode the URL-safe base64 back to raw bytes
            let decoded = URL_SAFE_NO_PAD
                .decode(&public_key_base64)
                .expect("URL_SAFE_NO_PAD decode should succeed for every generated key");

            assert_eq!(decoded.len(), 32, "Ed25519 public key must be 32 bytes");

            // Re-encode and verify roundtrip
            let re_encoded = URL_SAFE_NO_PAD.encode(&decoded);
            assert_eq!(re_encoded, public_key_base64, "base64 roundtrip must be lossless");

            // Verify that the key reconstructs a valid Ed25519 VerifyingKey
            ed25519_dalek::VerifyingKey::from_bytes(&decoded.try_into().unwrap())
                .expect("decoded bytes must form a valid Ed25519 public key");
        }
    }
}
