use crate::crypto::PrivateKeyEncryptor;
use crate::entities::{ClientCertificate, VaultRole};
use crate::error::{Error, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};

/// JWT claims for vault-scoped access tokens
///
/// These tokens allow a client to access a specific vault with a specific role.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultTokenClaims {
    /// Issuer: "tenant:<org_id>"
    pub iss: String,
    /// Subject: "tenant:<org_id>"
    pub sub: String,
    /// Audience: `https://api.inferadb.com/evaluate`
    pub aud: String,
    /// Expiration time (Unix timestamp)
    pub exp: i64,
    /// Issued at (Unix timestamp)
    pub iat: i64,
    /// Vault ID
    pub vault_id: i64,
    /// Vault role granted to this token
    pub vault_role: VaultRole,
    /// Scope string (e.g., "vault:read", "vault:write")
    pub scope: String,
}

impl VaultTokenClaims {
    /// Create new vault token claims
    ///
    /// # Arguments
    /// * `organization_id` - Organization ID
    /// * `vault_id` - Vault ID
    /// * `vault_role` - Role granted to this token
    /// * `ttl_seconds` - Time to live in seconds (default: 3600 = 1 hour)
    pub fn new(
        organization_id: i64,
        vault_id: i64,
        vault_role: VaultRole,
        ttl_seconds: i64,
    ) -> Self {
        let now = Utc::now();
        let exp = now + Duration::seconds(ttl_seconds);

        let scope = match vault_role {
            VaultRole::Reader => "vault:read",
            VaultRole::Writer => "vault:read vault:write",
            VaultRole::Manager => "vault:read vault:write vault:manage",
            VaultRole::Admin => "vault:read vault:write vault:manage vault:admin",
        };

        Self {
            iss: format!("tenant:{}", organization_id),
            sub: format!("tenant:{}", organization_id),
            aud: "https://api.inferadb.com/evaluate".to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            vault_id,
            vault_role,
            scope: scope.to_string(),
        }
    }

    /// Check if token has expired
    pub fn is_expired(&self) -> bool {
        let now = Utc::now().timestamp();
        self.exp <= now
    }

    /// Get expiration time as DateTime
    pub fn expires_at(&self) -> DateTime<Utc> {
        DateTime::from_timestamp(self.exp, 0).unwrap_or_else(Utc::now)
    }

    /// Get issued at time as DateTime
    pub fn issued_at(&self) -> DateTime<Utc> {
        DateTime::from_timestamp(self.iat, 0).unwrap_or_else(Utc::now)
    }
}

/// JWT signing service using client certificates
pub struct JwtSigner {
    encryptor: PrivateKeyEncryptor,
}

impl JwtSigner {
    /// Create a new JWT signer
    pub fn new(encryptor: PrivateKeyEncryptor) -> Self {
        Self { encryptor }
    }

    /// Convert Ed25519 private key (32 bytes) to PKCS#8 PEM format
    fn ed25519_to_pem(&self, private_key: &[u8; 32]) -> Result<Vec<u8>> {
        // PKCS#8 v1 structure for Ed25519:
        // SEQUENCE {
        //   INTEGER 0 (version)
        //   SEQUENCE {
        //     OBJECT IDENTIFIER 1.3.101.112 (Ed25519)
        //   }
        //   OCTET STRING {
        //     OCTET STRING <32 bytes private key>
        //   }
        // }

        // Ed25519 OID: 1.3.101.112
        let mut pkcs8_der = vec![
            0x30, 0x2e, // SEQUENCE (46 bytes)
            0x02, 0x01, 0x00, // INTEGER 0 (version)
            0x30, 0x05, // SEQUENCE (algorithm)
            0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112
            0x04, 0x22, // OCTET STRING (34 bytes)
            0x04, 0x20, // OCTET STRING (32 bytes)
        ];
        pkcs8_der.extend_from_slice(private_key);

        // Convert to PEM
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            BASE64.encode(&pkcs8_der)
        );

        Ok(pem.into_bytes())
    }

    /// Convert Ed25519 public key (32 bytes) to SPKI PEM format
    fn ed25519_public_to_pem(&self, public_key: &[u8]) -> Result<Vec<u8>> {
        if public_key.len() != 32 {
            return Err(Error::Internal("Public key must be 32 bytes".to_string()));
        }

        // SubjectPublicKeyInfo structure for Ed25519:
        // SEQUENCE {
        //   SEQUENCE {
        //     OBJECT IDENTIFIER 1.3.101.112 (Ed25519)
        //   }
        //   BIT STRING <32 bytes public key>
        // }

        let mut spki_der = vec![
            0x30, 0x2a, // SEQUENCE (42 bytes)
            0x30, 0x05, // SEQUENCE (algorithm)
            0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112
            0x03, 0x21, 0x00, // BIT STRING (33 bytes, 0 unused bits)
        ];
        spki_der.extend_from_slice(public_key);

        // Convert to PEM
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            BASE64.encode(&spki_der)
        );

        Ok(pem.into_bytes())
    }

    /// Sign JWT claims using a client certificate
    ///
    /// The JWT will be signed with the Ed25519 private key from the certificate.
    pub fn sign_vault_token(
        &self,
        claims: &VaultTokenClaims,
        certificate: &ClientCertificate,
    ) -> Result<String> {
        // Decrypt the private key
        let private_key_bytes = self.encryptor.decrypt(&certificate.private_key_encrypted)?;

        // Create Ed25519 signing key
        let signing_key_array: [u8; 32] = private_key_bytes
            .try_into()
            .map_err(|_| Error::Internal("Invalid private key length".to_string()))?;

        // Create encoding key for jsonwebtoken using raw Ed25519 key bytes
        // jsonwebtoken expects the seed (32 bytes) for EdDSA
        let encoding_key = EncodingKey::from_ed_pem(&self.ed25519_to_pem(&signing_key_array)?)
            .map_err(|e| Error::Internal(format!("Failed to create encoding key: {}", e)))?;

        // Create header with kid (key ID)
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(certificate.kid.clone());

        // Encode the JWT
        let token = encode(&header, claims, &encoding_key)
            .map_err(|e| Error::Internal(format!("Failed to sign JWT: {}", e)))?;

        Ok(token)
    }

    /// Verify a JWT and extract claims (for testing and token refresh validation)
    ///
    /// This verifies the signature using the certificate's public key.
    pub fn verify_vault_token(
        &self,
        token: &str,
        certificate: &ClientCertificate,
    ) -> Result<VaultTokenClaims> {
        use jsonwebtoken::{decode, DecodingKey, Validation};

        // Decode the public key
        let public_key_bytes = BASE64
            .decode(&certificate.public_key)
            .map_err(|e| Error::Internal(format!("Failed to decode public key: {}", e)))?;

        if public_key_bytes.len() != 32 {
            return Err(Error::Internal(
                "Invalid public key length (expected 32 bytes)".to_string(),
            ));
        }

        // Create decoding key from PEM
        let public_key_pem = self.ed25519_public_to_pem(&public_key_bytes)?;
        let decoding_key = DecodingKey::from_ed_pem(&public_key_pem)
            .map_err(|e| Error::Internal(format!("Failed to create decoding key: {}", e)))?;

        // Set up validation
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_audience(&["https://api.inferadb.com/evaluate"]);

        // Decode and verify
        let token_data = decode::<VaultTokenClaims>(token, &decoding_key, &validation)
            .map_err(|e| Error::Internal(format!("Failed to verify JWT: {}", e)))?;

        Ok(token_data.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keypair;

    fn create_test_encryptor() -> PrivateKeyEncryptor {
        let master_secret = b"test_master_secret_at_least_32_bytes_long!";
        PrivateKeyEncryptor::new(master_secret).unwrap()
    }

    fn create_test_certificate(encryptor: &PrivateKeyEncryptor) -> ClientCertificate {
        let (public_key, private_key_bytes) = keypair::generate();
        let private_key_encrypted = encryptor.encrypt(&private_key_bytes).unwrap();

        ClientCertificate::new(
            1,
            100,
            200,
            public_key,
            private_key_encrypted,
            "Test Certificate".to_string(),
            999,
        )
        .unwrap()
    }

    #[test]
    fn test_vault_token_claims_creation() {
        let claims = VaultTokenClaims::new(123, 456, VaultRole::Reader, 3600);

        assert_eq!(claims.iss, "tenant:123");
        assert_eq!(claims.sub, "tenant:123");
        assert_eq!(claims.aud, "https://api.inferadb.com/evaluate");
        assert_eq!(claims.vault_id, 456);
        assert_eq!(claims.vault_role, VaultRole::Reader);
        assert_eq!(claims.scope, "vault:read");
        assert!(!claims.is_expired());
    }

    #[test]
    fn test_vault_token_scopes() {
        let reader = VaultTokenClaims::new(1, 1, VaultRole::Reader, 3600);
        assert_eq!(reader.scope, "vault:read");

        let writer = VaultTokenClaims::new(1, 1, VaultRole::Writer, 3600);
        assert_eq!(writer.scope, "vault:read vault:write");

        let manager = VaultTokenClaims::new(1, 1, VaultRole::Manager, 3600);
        assert_eq!(manager.scope, "vault:read vault:write vault:manage");

        let admin = VaultTokenClaims::new(1, 1, VaultRole::Admin, 3600);
        assert_eq!(
            admin.scope,
            "vault:read vault:write vault:manage vault:admin"
        );
    }

    #[test]
    fn test_vault_token_expiration() {
        // Create an expired token (TTL = -1 second)
        let expired = VaultTokenClaims::new(1, 1, VaultRole::Reader, -1);
        assert!(expired.is_expired());

        // Create a valid token
        let valid = VaultTokenClaims::new(1, 1, VaultRole::Reader, 3600);
        assert!(!valid.is_expired());
    }

    #[test]
    fn test_jwt_sign_and_verify() {
        let encryptor = create_test_encryptor();
        let certificate = create_test_certificate(&encryptor);
        let signer = JwtSigner::new(encryptor);

        let claims = VaultTokenClaims::new(123, 456, VaultRole::Writer, 3600);

        // Sign the token
        let token = signer.sign_vault_token(&claims, &certificate).unwrap();
        assert!(!token.is_empty());

        // Verify the token
        let verified_claims = signer.verify_vault_token(&token, &certificate).unwrap();
        assert_eq!(verified_claims.iss, claims.iss);
        assert_eq!(verified_claims.sub, claims.sub);
        assert_eq!(verified_claims.aud, claims.aud);
        assert_eq!(verified_claims.vault_id, claims.vault_id);
        assert_eq!(verified_claims.vault_role, claims.vault_role);
    }

    #[test]
    fn test_jwt_kid_in_header() {
        let encryptor = create_test_encryptor();
        let certificate = create_test_certificate(&encryptor);
        let signer = JwtSigner::new(encryptor);

        let claims = VaultTokenClaims::new(123, 456, VaultRole::Reader, 3600);
        let token = signer.sign_vault_token(&claims, &certificate).unwrap();

        // Decode header to check kid
        use jsonwebtoken::decode_header;
        let header = decode_header(&token).unwrap();
        assert_eq!(header.kid, Some(certificate.kid.clone()));
        assert_eq!(header.alg, Algorithm::EdDSA);
    }

    #[test]
    fn test_jwt_verification_fails_with_wrong_certificate() {
        let encryptor = create_test_encryptor();
        let cert1 = create_test_certificate(&encryptor);
        let cert2 = create_test_certificate(&encryptor); // Different certificate
        let signer = JwtSigner::new(encryptor);

        let claims = VaultTokenClaims::new(123, 456, VaultRole::Reader, 3600);
        let token = signer.sign_vault_token(&claims, &cert1).unwrap();

        // Verification with wrong certificate should fail
        let result = signer.verify_vault_token(&token, &cert2);
        assert!(result.is_err());
    }

    #[test]
    fn test_vault_token_datetime_conversion() {
        let claims = VaultTokenClaims::new(123, 456, VaultRole::Reader, 3600);

        let issued_at = claims.issued_at();
        let expires_at = claims.expires_at();

        // Issued at should be approximately now
        let now = Utc::now();
        assert!((issued_at - now).num_seconds().abs() < 2);

        // Expires at should be approximately 1 hour from now
        let expected_exp = now + Duration::seconds(3600);
        assert!((expires_at - expected_exp).num_seconds().abs() < 2);
    }
}
