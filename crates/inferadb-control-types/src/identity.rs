//! Management API identity for authenticating with Server APIs
//!
//! This module handles the Management API's Ed25519 keypair used to sign JWTs when
//! making authenticated requests to Server APIs for cache invalidation webhooks.

use std::sync::Arc;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{SigningKey, VerifyingKey};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Management API identity containing Ed25519 keypair for signing JWTs
#[derive(Clone)]
pub struct ManagementIdentity {
    /// Management API ID (used in JWT sub claim as "management:{management_id}")
    /// Auto-generated from environment (pod name or hostname)
    pub management_id: String,
    /// Key ID for JWKS (RFC 7638 JWK Thumbprint)
    /// Auto-generated as SHA-256 hash of the canonical JWK representation
    pub kid: String,
    /// Ed25519 signing key (private key)
    signing_key: SigningKey,
    /// Ed25519 verifying key (public key)
    verifying_key: VerifyingKey,
}

/// JWT claims for management-to-server authentication
#[derive(Debug, Serialize, Deserialize)]
struct ManagementJwtClaims {
    /// Issuer - the management API instance
    iss: String,
    /// Subject - "management:{management_id}"
    sub: String,
    /// Audience - the server URL
    aud: String,
    /// Issued at (Unix timestamp)
    iat: i64,
    /// Expiration (Unix timestamp) - short lived, 5 minutes
    exp: i64,
    /// JWT ID for replay protection
    jti: String,
}

/// JWKS (JSON Web Key Set) response
#[derive(Debug, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// JWK (JSON Web Key)
#[derive(Debug, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type (always "OKP" for Ed25519)
    pub kty: String,
    /// Algorithm (always "EdDSA")
    pub alg: String,
    /// Key ID
    pub kid: String,
    /// Curve (always "Ed25519")
    pub crv: String,
    /// Public key (base64url encoded)
    pub x: String,
    /// Key use (always "sig" for signature)
    #[serde(rename = "use")]
    pub key_use: String,
}

impl ManagementIdentity {
    /// Generate a new management identity with a random Ed25519 keypair.
    pub fn generate() -> Self {
        use rand::RngCore;

        let mut rng = rand::rng();
        let mut secret_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_bytes);

        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();

        let management_id = Self::generate_management_id();
        let kid = Self::generate_kid(&verifying_key);

        Self { management_id, kid, signing_key, verifying_key }
    }

    /// Create management identity from an existing Ed25519 private key (PEM format).
    pub fn from_pem(pem: &str) -> Result<Self, String> {
        // Parse PEM to extract the private key bytes
        let pem = pem::parse(pem).map_err(|e| format!("Failed to parse PEM: {}", e))?;

        if pem.tag() != "PRIVATE KEY" {
            return Err(format!("Invalid PEM tag: expected 'PRIVATE KEY', got '{}'", pem.tag()));
        }

        // Ed25519 private keys are 32 bytes
        let key_bytes = pem.contents();
        if key_bytes.len() < 32 {
            return Err("Invalid Ed25519 private key length".to_string());
        }

        // Extract the last 32 bytes (Ed25519 private key)
        let private_key_bytes: [u8; 32] = key_bytes[key_bytes.len() - 32..]
            .try_into()
            .map_err(|_| "Failed to extract 32-byte private key")?;

        let signing_key = SigningKey::from_bytes(&private_key_bytes);
        let verifying_key = signing_key.verifying_key();

        let management_id = Self::generate_management_id();
        let kid = Self::generate_kid(&verifying_key);

        Ok(Self { management_id, kid, signing_key, verifying_key })
    }

    /// Generate the management_id from the environment.
    ///
    /// In Kubernetes, uses the pod name from HOSTNAME.
    /// Otherwise, uses hostname + random suffix.
    fn generate_management_id() -> String {
        // Try Kubernetes pod name first (HOSTNAME env var)
        if let Ok(pod_name) = std::env::var("HOSTNAME") {
            // In Kubernetes, HOSTNAME is typically the pod name (e.g., "inferadb-control-0")
            return format!("mgmt-{}", pod_name);
        }

        // Fallback to hostname + random suffix for non-Kubernetes environments
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        let random_suffix = &uuid::Uuid::new_v4().to_string()[..8];
        format!("mgmt-{}-{}", hostname, random_suffix)
    }

    /// Generate the kid as an RFC 7638 JWK Thumbprint.
    ///
    /// For Ed25519 (OKP) keys, the canonical JWK representation is:
    /// `{"crv":"Ed25519","kty":"OKP","x":"<base64url-encoded-public-key>"}`
    ///
    /// The thumbprint is the base64url-encoded SHA-256 hash of this representation.
    fn generate_kid(verifying_key: &VerifyingKey) -> String {
        let public_key_bytes = verifying_key.as_bytes();
        let x = URL_SAFE_NO_PAD.encode(public_key_bytes);

        // RFC 7638: Canonical JWK representation (alphabetically ordered, no whitespace)
        let canonical_jwk = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#, x);

        // SHA-256 hash of the canonical representation
        let mut hasher = Sha256::new();
        hasher.update(canonical_jwk.as_bytes());
        let hash = hasher.finalize();

        // Base64url-encode the hash
        URL_SAFE_NO_PAD.encode(hash)
    }

    /// Export the private key as PEM format (for saving to config)
    pub fn to_pem(&self) -> String {
        let key_bytes = self.signing_key.to_bytes();

        // PKCS#8 format for Ed25519 private key
        // This is a simplified version - in production you might want to use a proper PKCS#8
        // encoder
        let mut pkcs8_bytes = vec![
            0x30, 0x2e, // SEQUENCE, length 46
            0x02, 0x01, 0x00, // INTEGER 0 (version)
            0x30, 0x05, // SEQUENCE, length 5
            0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
            0x04, 0x22, // OCTET STRING, length 34
            0x04, 0x20, // OCTET STRING, length 32
        ];
        pkcs8_bytes.extend_from_slice(&key_bytes);

        let pem = pem::Pem::new("PRIVATE KEY", pkcs8_bytes);
        pem::encode(&pem)
    }

    /// Sign a JWT for management-to-server authentication
    ///
    /// # Arguments
    ///
    /// * `server_url` - The audience (server URL) for the JWT
    ///
    /// # Returns
    ///
    /// A signed JWT valid for 5 minutes
    pub fn sign_jwt(&self, server_url: &str) -> Result<String, String> {
        let now = chrono::Utc::now();
        let exp = now + chrono::Duration::minutes(5);

        let claims = ManagementJwtClaims {
            iss: format!("inferadb-control:{}", self.management_id),
            sub: format!("management:{}", self.management_id),
            aud: server_url.to_string(),
            iat: now.timestamp(),
            exp: exp.timestamp(),
            jti: uuid::Uuid::new_v4().to_string(),
        };

        let mut header = Header::new(jsonwebtoken::Algorithm::EdDSA);
        header.kid = Some(self.kid.clone());

        // Convert Ed25519 signing key to PEM for jsonwebtoken
        let pem = self.to_pem();
        let encoding_key = EncodingKey::from_ed_pem(pem.as_bytes())
            .map_err(|e| format!("Failed to create encoding key: {}", e))?;

        encode(&header, &claims, &encoding_key).map_err(|e| format!("Failed to sign JWT: {}", e))
    }

    /// Get the JWKS representation of the public key
    pub fn to_jwks(&self) -> Jwks {
        let public_key_bytes = self.verifying_key.as_bytes();
        let x = URL_SAFE_NO_PAD.encode(public_key_bytes);

        Jwks {
            keys: vec![Jwk {
                kty: "OKP".to_string(),
                alg: "EdDSA".to_string(),
                kid: self.kid.clone(),
                crv: "Ed25519".to_string(),
                x,
                key_use: "sig".to_string(),
            }],
        }
    }
}

/// Thread-safe management identity
pub type SharedManagementIdentity = Arc<ManagementIdentity>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_management_identity() {
        let identity = ManagementIdentity::generate();
        // management_id should start with "mgmt-"
        assert!(identity.management_id.starts_with("mgmt-"));
        // kid should be a base64url-encoded SHA-256 hash (43 characters for 256 bits)
        assert_eq!(identity.kid.len(), 43);
    }

    #[test]
    fn test_pem_round_trip() {
        let identity = ManagementIdentity::generate();
        let pem = identity.to_pem();

        let restored = ManagementIdentity::from_pem(&pem);
        assert!(restored.is_ok());
        let restored = restored.unwrap();
        // The kid should be the same since it's derived from the key
        assert_eq!(identity.kid, restored.kid);
    }

    #[test]
    fn test_kid_is_deterministic() {
        // Same key should always produce the same kid
        let identity = ManagementIdentity::generate();
        let pem = identity.to_pem();

        let restored1 = ManagementIdentity::from_pem(&pem).unwrap();
        let restored2 = ManagementIdentity::from_pem(&pem).unwrap();

        assert_eq!(restored1.kid, restored2.kid);
        assert_eq!(identity.kid, restored1.kid);
    }

    #[test]
    fn test_different_keys_have_different_kids() {
        let identity1 = ManagementIdentity::generate();
        let identity2 = ManagementIdentity::generate();

        // Different keys should have different kids
        assert_ne!(identity1.kid, identity2.kid);
    }

    #[test]
    fn test_sign_jwt() {
        let identity = ManagementIdentity::generate();
        let jwt = identity.sign_jwt("http://localhost:8080");
        assert!(jwt.is_ok());

        let token = jwt.unwrap();
        assert!(!token.is_empty());
        assert_eq!(token.matches('.').count(), 2); // JWT has 3 parts separated by 2 dots
    }

    #[test]
    fn test_to_jwks() {
        let identity = ManagementIdentity::generate();
        let jwks = identity.to_jwks();

        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].kty, "OKP");
        assert_eq!(jwks.keys[0].alg, "EdDSA");
        assert_eq!(jwks.keys[0].kid, identity.kid); // kid should match
        assert_eq!(jwks.keys[0].crv, "Ed25519");
        assert_eq!(jwks.keys[0].key_use, "sig");
        assert!(!jwks.keys[0].x.is_empty());
    }

    #[test]
    fn test_rfc7638_thumbprint_format() {
        // Verify the kid is a valid base64url-encoded SHA-256 hash
        let identity = ManagementIdentity::generate();

        // SHA-256 produces 32 bytes, base64url encodes to 43 characters (no padding)
        assert_eq!(identity.kid.len(), 43);

        // Should be valid base64url (no + or /, no padding)
        assert!(!identity.kid.contains('+'));
        assert!(!identity.kid.contains('/'));
        assert!(!identity.kid.contains('='));
    }
}
