/// Minimal test to verify JWKS public key can verify JWTs signed with the corresponding private key
/// This test simulates the E2E flow: Management API generates keypair → returns private key →
/// client signs JWT → server fetches JWKS → server verifies JWT

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use infera_management_core::keypair;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct TestClaims {
    sub: String,
    exp: u64,
}

#[test]
fn test_keypair_generate_sign_verify() {
    // 1. Simulate Management API: Generate keypair
    let (public_key_base64, private_key_bytes) = keypair::generate();

    println!("Generated keypair:");
    println!("  Public key (base64): {}", public_key_base64);
    println!("  Private key length: {} bytes", private_key_bytes.len());

    // 2. Simulate client: Receive private key, sign JWT
    assert_eq!(private_key_bytes.len(), 32, "Private key should be 32 bytes");

    // Convert to PEM (same as E2E test)
    let private_key_array: [u8; 32] = private_key_bytes.as_slice().try_into().expect("Invalid private key length");
    let pem = ed25519_to_pem(&private_key_array);
    let encoding_key = EncodingKey::from_ed_pem(&pem).expect("Failed to create encoding key");

    let claims = TestClaims {
        sub: "test-subject".to_string(),
        exp: (chrono::Utc::now() + chrono::Duration::minutes(5)).timestamp() as u64,
    };

    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some("test-kid-001".to_string());

    let jwt = encode(&header, &claims, &encoding_key).expect("Failed to encode JWT");
    println!("  JWT: {}...", &jwt[..50]);

    // 3. Simulate JWKS: Convert public key to base64url (what JWKS handler does)
    let public_key_bytes = BASE64.decode(&public_key_base64).expect("Failed to decode public key");
    assert_eq!(public_key_bytes.len(), 32, "Public key should be 32 bytes");

    let public_key_base64url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&public_key_bytes);
    println!("  Public key (base64url): {}", public_key_base64url);

    // 4. Simulate server: Use JWKS public key to create DecodingKey
    let decoding_key = DecodingKey::from_ed_components(&public_key_base64url)
        .expect("Failed to create decoding key");

    // 5. Verify JWT
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.validate_exp = false; // Don't validate expiry for this test
    validation.required_spec_claims.clear(); // Don't require standard claims

    let result = decode::<TestClaims>(&jwt, &decoding_key, &validation);

    match result {
        Ok(token_data) => {
            println!("✓ JWT verification SUCCEEDED");
            println!("  Claims: {:?}", token_data.claims);
            assert_eq!(token_data.claims.sub, "test-subject");
        }
        Err(e) => {
            panic!("✗ JWT verification FAILED: {:?}", e);
        }
    }
}

/// Convert Ed25519 private key to PEM format (same as E2E test)
fn ed25519_to_pem(private_key: &[u8; 32]) -> Vec<u8> {
    let mut pkcs8_der = vec![
        0x30, 0x2e, // SEQUENCE (46 bytes)
        0x02, 0x01, 0x00, // INTEGER 0 (version)
        0x30, 0x05, // SEQUENCE (algorithm)
        0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112
        0x04, 0x22, // OCTET STRING (34 bytes)
        0x04, 0x20, // OCTET STRING (32 bytes)
    ];
    pkcs8_der.extend_from_slice(private_key);

    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
        BASE64.encode(&pkcs8_der)
    );

    pem.into_bytes()
}
