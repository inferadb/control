use argon2::{
    Argon2,
    password_hash::{
        PasswordHash, PasswordHasher as _, PasswordVerifier, SaltString, rand_core::OsRng,
    },
};
use inferadb_control_const::limits::MIN_PASSWORD_LENGTH;
use inferadb_control_types::error::{Error, Result};

/// Password hasher with Argon2id configuration
///
/// Uses NIST-recommended parameters:
/// - Memory cost: 19 MiB (19456 KiB)
/// - Time cost: 2 iterations
/// - Parallelism: 1 thread
/// - Output length: 32 bytes
pub struct PasswordHasher {
    argon2: Argon2<'static>,
}

impl PasswordHasher {
    /// Create a new password hasher with default parameters
    pub fn new() -> Self {
        Self { argon2: Argon2::default() }
    }

    /// Hash a password
    ///
    /// # Arguments
    ///
    /// * `password` - Plain text password
    ///
    /// # Returns
    ///
    /// PHC string format hash
    ///
    /// # Errors
    ///
    /// Returns an error if hashing fails
    pub fn hash(&self, password: &str) -> Result<String> {
        Self::validate_password(password)?;

        let salt = SaltString::generate(&mut OsRng);

        let password_hash = self
            .argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| Error::Internal(format!("Failed to hash password: {e}")))?;

        Ok(password_hash.to_string())
    }

    /// Verify a password against a hash
    ///
    /// # Arguments
    ///
    /// * `password` - Plain text password
    /// * `hash` - PHC string format hash
    ///
    /// # Returns
    ///
    /// Ok(()) if password matches, Err otherwise
    pub fn verify(&self, password: &str, hash: &str) -> Result<()> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| Error::Auth(format!("Invalid password hash: {e}")))?;

        self.argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .map_err(|_| Error::Auth("Invalid password".to_string()))?;

        Ok(())
    }

    /// Validate password requirements
    ///
    /// Rules (per NIST guidelines):
    /// - Minimum length: 12 characters (configurable via MIN_PASSWORD_LENGTH)
    /// - No maximum length (up to reasonable limits)
    /// - No complexity requirements (letters, numbers, symbols not required)
    pub fn validate_password(password: &str) -> Result<()> {
        if password.len() < MIN_PASSWORD_LENGTH {
            return Err(Error::Validation(format!(
                "Password must be at least {MIN_PASSWORD_LENGTH} characters long"
            )));
        }

        if password.len() > 128 {
            return Err(Error::Validation("Password must be 128 characters or less".to_string()));
        }

        Ok(())
    }
}

impl Default for PasswordHasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience function to hash a password
pub fn hash_password(password: &str) -> Result<String> {
    PasswordHasher::new().hash(password)
}

/// Convenience function to verify a password
pub fn verify_password(password: &str, hash: &str) -> Result<()> {
    PasswordHasher::new().verify(password, hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_password() {
        let hasher = PasswordHasher::new();
        let password = "my-secure-password-123";
        let hash = hasher.hash(password).unwrap();

        // Hash should be non-empty
        assert!(!hash.is_empty());

        // Hash should be PHC format (starts with $argon2)
        assert!(hash.starts_with("$argon2"));
    }

    #[test]
    fn test_verify_password_success() {
        let hasher = PasswordHasher::new();
        let password = "my-secure-password-123";
        let hash = hasher.hash(password).unwrap();

        // Verification should succeed
        assert!(hasher.verify(password, &hash).is_ok());
    }

    #[test]
    fn test_verify_password_failure() {
        let hasher = PasswordHasher::new();
        let password = "my-secure-password-123";
        let hash = hasher.hash(password).unwrap();

        // Wrong password should fail
        assert!(hasher.verify("wrong-password", &hash).is_err());
    }

    #[test]
    fn test_hash_uniqueness() {
        let hasher = PasswordHasher::new();
        let password = "my-secure-password-123";

        let hash1 = hasher.hash(password).unwrap();
        let hash2 = hasher.hash(password).unwrap();

        // Hashes should be different (due to random salt)
        assert_ne!(hash1, hash2);

        // But both should verify correctly
        assert!(hasher.verify(password, &hash1).is_ok());
        assert!(hasher.verify(password, &hash2).is_ok());
    }

    #[test]
    fn test_validate_password_too_short() {
        assert!(PasswordHasher::validate_password("short").is_err());
        assert!(PasswordHasher::validate_password("11chars-pwd").is_err());
    }

    #[test]
    fn test_validate_password_too_long() {
        let long_password = "a".repeat(129);
        assert!(PasswordHasher::validate_password(&long_password).is_err());
    }

    #[test]
    fn test_validate_password_valid() {
        assert!(PasswordHasher::validate_password("12chars-pass").is_ok());
        assert!(PasswordHasher::validate_password("a-longer-valid-password").is_ok());
        assert!(PasswordHasher::validate_password(&"a".repeat(128)).is_ok());
    }

    #[test]
    fn test_convenience_functions() {
        let password = "my-secure-password-123";
        let hash = hash_password(password).unwrap();
        assert!(verify_password(password, &hash).is_ok());
        assert!(verify_password("wrong", &hash).is_err());
    }
}
