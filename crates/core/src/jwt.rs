use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bon::bon;
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::pkcs8::{EncodePrivateKey, spki::EncodePublicKey};
use inferadb_control_const::auth::{REQUIRED_AUDIENCE, REQUIRED_ISSUER};
use inferadb_control_types::{
    entities::{ClientCertificate, VaultRole},
    error::{Error, Result},
};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::crypto::PrivateKeyEncryptor;

/// JWT claims for vault-scoped access tokens
///
/// These tokens allow a client to access a specific vault with a specific role.
/// Format matches the Engine specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultTokenClaims {
    /// Issuer: Management API URL (<https://api.inferadb.com>)
    pub iss: String,
    /// Subject: Format "client:<client_id>" for service accounts
    pub sub: String,
    /// Audience: InferaDB Engine (hardcoded to REQUIRED_AUDIENCE)
    pub aud: String,
    /// Expiration time (Unix timestamp)
    pub exp: i64,
    /// Issued at (Unix timestamp)
    pub iat: i64,
    /// Organization ID (Snowflake ID as string)
    pub org_id: String,
    /// Vault ID (Snowflake ID as string)
    pub vault_id: String,
    /// Vault role granted to this token (lowercase: read/write/manage/admin)
    pub vault_role: String,
    /// Scope string (e.g., "vault:read vault:write")
    pub scope: String,
}

#[bon]
impl VaultTokenClaims {
    /// Create new vault token claims
    ///
    /// # Arguments
    /// * `organization_id` - Organization ID (Snowflake ID)
    /// * `client_id` - Client ID (Snowflake ID) for service accounts
    /// * `vault_id` - Vault ID (Snowflake ID)
    /// * `vault_role` - Role granted to this token
    /// * `ttl_seconds` - Time to live in seconds (default: 300 = 5 minutes)
    ///
    /// Note: issuer and audience are hardcoded to REQUIRED_ISSUER and REQUIRED_AUDIENCE
    /// since we own the entire experience end-to-end.
    #[builder]
    pub fn new(
        organization_id: i64,
        client_id: i64,
        vault_id: i64,
        vault_role: VaultRole,
        ttl_seconds: i64,
    ) -> Self {
        let now = Utc::now();
        let exp = now + Duration::seconds(ttl_seconds);

        let (vault_role_str, scope) = match vault_role {
            VaultRole::Reader => (
                "read",
                "inferadb.check inferadb.read inferadb.expand inferadb.list inferadb.list-relationships inferadb.list-subjects inferadb.list-resources",
            ),
            VaultRole::Writer => (
                "write",
                "inferadb.check inferadb.read inferadb.write inferadb.expand inferadb.list inferadb.list-relationships inferadb.list-subjects inferadb.list-resources",
            ),
            VaultRole::Manager => (
                "manage",
                "inferadb.check inferadb.read inferadb.write inferadb.expand inferadb.list inferadb.list-relationships inferadb.list-subjects inferadb.list-resources inferadb.vault.manage",
            ),
            VaultRole::Admin => (
                "admin",
                "inferadb.check inferadb.read inferadb.write inferadb.expand inferadb.list inferadb.list-relationships inferadb.list-subjects inferadb.list-resources inferadb.vault.manage inferadb.admin",
            ),
        };

        Self {
            iss: REQUIRED_ISSUER.to_string(),
            sub: format!("client:{client_id}"),
            aud: REQUIRED_AUDIENCE.to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            org_id: organization_id.to_string(),
            vault_id: vault_id.to_string(),
            vault_role: vault_role_str.to_string(),
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

    /// Sign JWT claims using a client certificate
    ///
    /// The JWT will be signed with the Ed25519 private key from the certificate.
    pub fn sign_vault_token(
        &self,
        claims: &VaultTokenClaims,
        certificate: &ClientCertificate,
    ) -> Result<String> {
        // Decrypt the private key (returned as Zeroizing<Vec<u8>> for secure erasure)
        let private_key_bytes = self.encryptor.decrypt(&certificate.private_key_encrypted)?;

        // Create Ed25519 signing key
        let mut signing_key_array: [u8; 32] = private_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::internal("Invalid private key length".to_string()))?;

        // Encode private key as PKCS#8 DER using the pkcs8 crate
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_key_array);
        signing_key_array.zeroize();
        let pkcs8_der = signing_key
            .to_pkcs8_der()
            .map_err(|e| Error::internal(format!("Failed to encode PKCS#8 DER: {e}")))?;
        let encoding_key = EncodingKey::from_ed_der(pkcs8_der.as_bytes());

        // Create header with kid (key ID)
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(certificate.kid.clone());

        // Encode the JWT
        let token = encode(&header, claims, &encoding_key)
            .map_err(|e| Error::internal(format!("Failed to sign JWT: {e}")))?;

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
        use jsonwebtoken::{DecodingKey, Validation, decode};

        // Decode the public key (JWK uses URL-safe base64)
        let public_key_bytes = URL_SAFE_NO_PAD
            .decode(&certificate.public_key)
            .map_err(|e| Error::internal(format!("Failed to decode public key: {e}")))?;

        let public_key_array: [u8; 32] = public_key_bytes.as_slice().try_into().map_err(|_| {
            Error::internal("Invalid public key length (expected 32 bytes)".to_string())
        })?;

        // Encode public key as SPKI DER using the pkcs8/spki crate
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key_array)
            .map_err(|e| Error::internal(format!("Invalid public key: {e}")))?;
        let spki_der = verifying_key
            .to_public_key_der()
            .map_err(|e| Error::internal(format!("Failed to encode SPKI DER: {e}")))?;
        let decoding_key = DecodingKey::from_ed_der(spki_der.as_ref());

        // Set up validation
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_audience(&[REQUIRED_AUDIENCE]);

        // Decode and verify
        let token_data = decode::<VaultTokenClaims>(token, &decoding_key, &validation)
            .map_err(|e| Error::internal(format!("Failed to verify JWT: {e}")))?;

        Ok(token_data.claims)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::crypto::keypair;

    fn create_test_encryptor() -> PrivateKeyEncryptor {
        let master_key: [u8; 32] = [0x42; 32]; // Test key with fixed bytes
        PrivateKeyEncryptor::new(&master_key).unwrap()
    }

    fn create_test_certificate(encryptor: &PrivateKeyEncryptor) -> ClientCertificate {
        let (public_key, private_key_bytes) = keypair::generate();
        let private_key_encrypted = encryptor.encrypt(&private_key_bytes).unwrap();

        ClientCertificate::builder()
            .id(1)
            .client_id(100)
            .organization_id(200)
            .public_key(public_key)
            .private_key_encrypted(private_key_encrypted)
            .name("Test Certificate".to_string())
            .created_by_user_id(999)
            .create()
            .unwrap()
    }

    #[test]
    fn test_vault_token_claims_creation() {
        let claims = VaultTokenClaims::builder()
            .organization_id(123)
            .client_id(789)
            .vault_id(456)
            .vault_role(VaultRole::Reader)
            .ttl_seconds(3600)
            .build();

        assert_eq!(claims.iss, REQUIRED_ISSUER);
        assert_eq!(claims.sub, "client:789");
        assert_eq!(claims.aud, REQUIRED_AUDIENCE);
        assert_eq!(claims.org_id, "123");
        assert_eq!(claims.vault_id, "456");
        assert_eq!(claims.vault_role, "read");
        assert_eq!(
            claims.scope,
            "inferadb.check inferadb.read inferadb.expand inferadb.list inferadb.list-relationships inferadb.list-subjects inferadb.list-resources"
        );
        assert!(!claims.is_expired());
    }

    #[test]
    fn test_vault_token_scopes() {
        let reader = VaultTokenClaims::builder()
            .organization_id(1)
            .client_id(2)
            .vault_id(3)
            .vault_role(VaultRole::Reader)
            .ttl_seconds(3600)
            .build();
        assert_eq!(
            reader.scope,
            "inferadb.check inferadb.read inferadb.expand inferadb.list inferadb.list-relationships inferadb.list-subjects inferadb.list-resources"
        );
        assert_eq!(reader.vault_role, "read");

        let writer = VaultTokenClaims::builder()
            .organization_id(1)
            .client_id(2)
            .vault_id(3)
            .vault_role(VaultRole::Writer)
            .ttl_seconds(3600)
            .build();
        assert_eq!(
            writer.scope,
            "inferadb.check inferadb.read inferadb.write inferadb.expand inferadb.list inferadb.list-relationships inferadb.list-subjects inferadb.list-resources"
        );
        assert_eq!(writer.vault_role, "write");

        let manager = VaultTokenClaims::builder()
            .organization_id(1)
            .client_id(2)
            .vault_id(3)
            .vault_role(VaultRole::Manager)
            .ttl_seconds(3600)
            .build();
        assert_eq!(
            manager.scope,
            "inferadb.check inferadb.read inferadb.write inferadb.expand inferadb.list inferadb.list-relationships inferadb.list-subjects inferadb.list-resources inferadb.vault.manage"
        );
        assert_eq!(manager.vault_role, "manage");

        let admin = VaultTokenClaims::builder()
            .organization_id(1)
            .client_id(2)
            .vault_id(3)
            .vault_role(VaultRole::Admin)
            .ttl_seconds(3600)
            .build();
        assert_eq!(
            admin.scope,
            "inferadb.check inferadb.read inferadb.write inferadb.expand inferadb.list inferadb.list-relationships inferadb.list-subjects inferadb.list-resources inferadb.vault.manage inferadb.admin"
        );
        assert_eq!(admin.vault_role, "admin");
    }

    #[test]
    fn test_vault_token_expiration() {
        // Create an expired token (TTL = -1 second)
        let expired = VaultTokenClaims::builder()
            .organization_id(1)
            .client_id(2)
            .vault_id(3)
            .vault_role(VaultRole::Reader)
            .ttl_seconds(-1)
            .build();
        assert!(expired.is_expired());

        // Create a valid token
        let valid = VaultTokenClaims::builder()
            .organization_id(1)
            .client_id(2)
            .vault_id(3)
            .vault_role(VaultRole::Reader)
            .ttl_seconds(3600)
            .build();
        assert!(!valid.is_expired());
    }

    #[test]
    fn test_jwt_sign_and_verify() {
        let encryptor = create_test_encryptor();
        let certificate = create_test_certificate(&encryptor);
        let signer = JwtSigner::new(encryptor);

        let claims = VaultTokenClaims::builder()
            .organization_id(123)
            .client_id(789)
            .vault_id(456)
            .vault_role(VaultRole::Writer)
            .ttl_seconds(3600)
            .build();

        // Sign the token
        let token = signer.sign_vault_token(&claims, &certificate).unwrap();
        assert!(!token.is_empty());

        // Verify the token
        let verified_claims = signer.verify_vault_token(&token, &certificate).unwrap();
        assert_eq!(verified_claims.iss, claims.iss);
        assert_eq!(verified_claims.sub, claims.sub);
        assert_eq!(verified_claims.aud, claims.aud);
        assert_eq!(verified_claims.org_id, claims.org_id);
        assert_eq!(verified_claims.vault_id, claims.vault_id);
        assert_eq!(verified_claims.vault_role, claims.vault_role);
    }

    #[test]
    fn test_jwt_kid_in_header() {
        let encryptor = create_test_encryptor();
        let certificate = create_test_certificate(&encryptor);
        let signer = JwtSigner::new(encryptor);

        let claims = VaultTokenClaims::builder()
            .organization_id(123)
            .client_id(789)
            .vault_id(456)
            .vault_role(VaultRole::Reader)
            .ttl_seconds(3600)
            .build();
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

        let claims = VaultTokenClaims::builder()
            .organization_id(123)
            .client_id(789)
            .vault_id(456)
            .vault_role(VaultRole::Reader)
            .ttl_seconds(3600)
            .build();
        let token = signer.sign_vault_token(&claims, &cert1).unwrap();

        // Verification with wrong certificate should fail
        let result = signer.verify_vault_token(&token, &cert2);
        assert!(result.is_err());
    }

    #[test]
    fn test_vault_token_datetime_conversion() {
        let claims = VaultTokenClaims::builder()
            .organization_id(123)
            .client_id(789)
            .vault_id(456)
            .vault_role(VaultRole::Reader)
            .ttl_seconds(3600)
            .build();

        let issued_at = claims.issued_at();
        let expires_at = claims.expires_at();

        // Issued at should be approximately now
        let now = Utc::now();
        assert!((issued_at - now).num_seconds().abs() < 2);

        // Expires at should be approximately 1 hour from now
        let expected_exp = now + Duration::seconds(3600);
        assert!((expires_at - expected_exp).num_seconds().abs() < 2);
    }

    #[test]
    fn test_verify_vault_token_rejects_wrong_audience() {
        let encryptor = create_test_encryptor();
        let certificate = create_test_certificate(&encryptor);
        let signer = JwtSigner::new(encryptor);

        // Manually construct claims with wrong audience
        let now = Utc::now();
        let exp = now + Duration::seconds(3600);
        let wrong_aud_claims = VaultTokenClaims {
            iss: REQUIRED_ISSUER.to_string(),
            sub: "client:100".to_string(),
            aud: "https://wrong.example.com".to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            org_id: "123".to_string(),
            vault_id: "456".to_string(),
            vault_role: "read".to_string(),
            scope: "inferadb.check inferadb.read".to_string(),
        };

        let token = signer.sign_vault_token(&wrong_aud_claims, &certificate).unwrap();

        let result = signer.verify_vault_token(&token, &certificate);
        assert!(result.is_err(), "Token with wrong audience should be rejected");
    }

    #[test]
    fn test_verify_vault_token_accepts_correct_audience() {
        let encryptor = create_test_encryptor();
        let certificate = create_test_certificate(&encryptor);
        let signer = JwtSigner::new(encryptor);

        let claims = VaultTokenClaims::builder()
            .organization_id(123)
            .client_id(789)
            .vault_id(456)
            .vault_role(VaultRole::Writer)
            .ttl_seconds(3600)
            .build();

        let token = signer.sign_vault_token(&claims, &certificate).unwrap();
        let verified = signer.verify_vault_token(&token, &certificate).unwrap();
        assert_eq!(verified.aud, REQUIRED_AUDIENCE);
    }

    #[test]
    fn test_pkcs8_der_roundtrip_sign_verify() {
        // Verify that pkcs8 DER encoding produces keys compatible with sign/verify
        // Test with multiple random keypairs to catch encoding edge cases
        for _ in 0..10 {
            let encryptor = create_test_encryptor();
            let certificate = create_test_certificate(&encryptor);
            let signer = JwtSigner::new(encryptor);

            let claims = VaultTokenClaims::builder()
                .organization_id(1)
                .client_id(1)
                .vault_id(1)
                .vault_role(VaultRole::Reader)
                .ttl_seconds(300)
                .build();

            let token = signer.sign_vault_token(&claims, &certificate).unwrap();
            let verified = signer.verify_vault_token(&token, &certificate).unwrap();
            assert_eq!(verified.sub, claims.sub);
            assert_eq!(verified.vault_id, claims.vault_id);
        }
    }

    mod proptest_jwt {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            #[test]
            fn sign_verify_roundtrip(
                org_id in 1i64..10000,
                client_id in 1i64..10000,
                vault_id in 1i64..10000,
                vault_role in prop_oneof![
                    Just(VaultRole::Reader),
                    Just(VaultRole::Writer),
                    Just(VaultRole::Manager),
                    Just(VaultRole::Admin),
                ],
                ttl in 60i64..86400,
            ) {
                let encryptor = create_test_encryptor();
                let certificate = create_test_certificate(&encryptor);
                let signer = JwtSigner::new(encryptor);

                let claims = VaultTokenClaims::builder()
                    .organization_id(org_id)
                    .client_id(client_id)
                    .vault_id(vault_id)
                    .vault_role(vault_role)
                    .ttl_seconds(ttl)
                    .build();

                let token = signer.sign_vault_token(&claims, &certificate).unwrap();
                let verified = signer.verify_vault_token(&token, &certificate).unwrap();

                prop_assert_eq!(verified.org_id, org_id.to_string());
                prop_assert_eq!(verified.vault_id, vault_id.to_string());

                // JWT stores vault_role as "read"/"write"/"manage"/"admin"
                // (not "reader"/"writer"/"manager"/"admin" from Display)
                let expected_role = match vault_role {
                    VaultRole::Reader => "read",
                    VaultRole::Writer => "write",
                    VaultRole::Manager => "manage",
                    VaultRole::Admin => "admin",
                };
                prop_assert_eq!(verified.vault_role, expected_role);
            }

            #[test]
            fn different_keys_cannot_verify(
                org_id in 1i64..10000,
                vault_id in 1i64..10000,
            ) {
                let encryptor1 = create_test_encryptor();
                let cert1 = create_test_certificate(&encryptor1);
                let signer1 = JwtSigner::new(encryptor1);

                let encryptor2 = create_test_encryptor();
                let cert2 = create_test_certificate(&encryptor2);
                let signer2 = JwtSigner::new(encryptor2);

                let claims = VaultTokenClaims::builder()
                    .organization_id(org_id)
                    .client_id(1)
                    .vault_id(vault_id)
                    .vault_role(VaultRole::Reader)
                    .ttl_seconds(300)
                    .build();

                let token = signer1.sign_vault_token(&claims, &cert1).unwrap();
                // Verification with a different certificate should fail
                prop_assert!(signer2.verify_vault_token(&token, &cert2).is_err());
            }
        }
    }
}
