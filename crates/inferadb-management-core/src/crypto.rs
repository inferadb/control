use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use inferadb_management_types::error::{Error, Result};
use sha2::{Digest, Sha256};

/// Private key encryption service using AES-256-GCM
///
/// This service encrypts Ed25519 private keys for secure storage in the database.
/// The encryption key is derived from a master secret using SHA-256.
pub struct PrivateKeyEncryptor {
    cipher: Aes256Gcm,
}

impl PrivateKeyEncryptor {
    /// Create a new encryptor from a master secret
    ///
    /// The master secret should be at least 32 bytes and come from the
    /// INFERADB_MGMT_KEY_ENCRYPTION_SECRET environment variable.
    pub fn new(master_secret: &[u8]) -> Result<Self> {
        if master_secret.len() < 32 {
            return Err(Error::Validation("Master secret must be at least 32 bytes".to_string()));
        }

        // Derive a 256-bit key from the master secret using SHA-256
        let mut hasher = Sha256::new();
        hasher.update(master_secret);
        let key_bytes = hasher.finalize();

        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .map_err(|e| Error::Internal(format!("Failed to initialize cipher: {}", e)))?;

        Ok(Self { cipher })
    }

    /// Encrypt a private key (32 bytes for Ed25519)
    ///
    /// Returns base64-encoded ciphertext with nonce prepended (12 bytes nonce + ciphertext)
    pub fn encrypt(&self, private_key: &[u8]) -> Result<String> {
        if private_key.len() != 32 {
            return Err(Error::Validation("Private key must be 32 bytes (Ed25519)".to_string()));
        }

        // Generate a random 96-bit nonce (12 bytes)
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        // Encrypt the private key
        let ciphertext = self
            .cipher
            .encrypt(&nonce, private_key)
            .map_err(|e| Error::Internal(format!("Failed to encrypt private key: {}", e)))?;

        // Combine nonce + ciphertext for storage
        let mut combined = nonce.to_vec();
        combined.extend_from_slice(&ciphertext);

        // Encode to base64
        Ok(BASE64.encode(&combined))
    }

    /// Decrypt a private key
    ///
    /// Takes base64-encoded string with nonce prepended, returns the 32-byte private key
    ///
    /// IMPORTANT: The returned Vec contains sensitive key material and should be zeroized when no
    /// longer needed.
    pub fn decrypt(&self, encrypted_base64: &str) -> Result<Vec<u8>> {
        // Decode from base64
        let combined = BASE64
            .decode(encrypted_base64)
            .map_err(|e| Error::Internal(format!("Failed to decode encrypted key: {}", e)))?;

        // Split nonce and ciphertext (first 12 bytes are nonce)
        if combined.len() < 12 {
            return Err(Error::Internal("Encrypted data too short (missing nonce)".to_string()));
        }

        let (nonce_bytes, ciphertext) = combined.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Decrypt the private key
        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| Error::Internal(format!("Failed to decrypt private key: {}", e)))?;

        // Verify it's 32 bytes (Ed25519 private key)
        if plaintext.len() != 32 {
            return Err(Error::Internal(format!(
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

        let public_key_base64 = BASE64.encode(verifying_key.as_bytes());
        let private_key_bytes = signing_key.to_bytes().to_vec();

        (public_key_base64, private_key_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_encryptor() -> PrivateKeyEncryptor {
        let master_secret = b"test_master_secret_at_least_32_bytes_long!";
        PrivateKeyEncryptor::new(master_secret).unwrap()
    }

    #[test]
    fn test_encryptor_creation() {
        let master_secret = b"test_master_secret_at_least_32_bytes_long!";
        assert!(PrivateKeyEncryptor::new(master_secret).is_ok());

        let short_secret = b"too_short";
        assert!(PrivateKeyEncryptor::new(short_secret).is_err());
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
        let short_data = BASE64.encode(b"short");
        assert!(encryptor.decrypt(&short_data).is_err());
    }

    #[test]
    fn test_decrypt_corrupted_ciphertext() {
        let encryptor = create_test_encryptor();
        let private_key = [42u8; 32];
        let encrypted = encryptor.encrypt(&private_key).unwrap();

        // Corrupt the ciphertext
        let mut corrupted_bytes = BASE64.decode(&encrypted).unwrap();
        corrupted_bytes[20] ^= 0xFF; // Flip bits in ciphertext
        let corrupted = BASE64.encode(&corrupted_bytes);

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

        // Public key should be base64 encoded 32 bytes (Ed25519)
        let public_key_decoded = BASE64.decode(&public_key_base64).unwrap();
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
}
