#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
/// Minimal test to verify JWKS public key can verify JWTs signed with the corresponding
/// private key This test simulates the E2E flow: Control API generates keypair → returns
/// private key → client signs JWT → server fetches JWKS → server verifies JWT
use ed25519_dalek::pkcs8::EncodePrivateKey;
use inferadb_control_core::keypair;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct TestClaims {
    sub: String,
    exp: u64,
}

#[test]
fn test_keypair_generate_sign_verify() {
    // 1. Simulate Control API: Generate keypair
    let (public_key_base64, private_key_bytes) = keypair::generate();

    println!("Generated keypair:");
    println!("  Public key (base64): {public_key_base64}");
    println!("  Private key length: {} bytes", private_key_bytes.len());

    // 2. Simulate client: Receive private key, sign JWT
    assert_eq!(private_key_bytes.len(), 32, "Private key should be 32 bytes");

    // Convert to PKCS#8 DER using the pkcs8 crate
    let private_key_array: [u8; 32] =
        private_key_bytes.as_slice().try_into().expect("Invalid private key length");
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&private_key_array);
    let pkcs8_der = signing_key.to_pkcs8_der().expect("Failed to encode PKCS#8 DER");
    let encoding_key = EncodingKey::from_ed_der(pkcs8_der.as_bytes());

    let claims = TestClaims {
        sub: "test-subject".to_string(),
        exp: (chrono::Utc::now() + chrono::Duration::minutes(5)).timestamp() as u64,
    };

    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some("test-kid-001".to_string());

    let jwt = encode(&header, &claims, &encoding_key).expect("Failed to encode JWT");
    println!("  JWT: {}...", &jwt[..50]);

    // 3. The public key from keypair::generate() is already URL-safe base64 encoded
    // (JWK standard), so we can use it directly for the decoding key
    println!("  Public key (base64url): {public_key_base64}");

    // 4. Simulate server: Use JWKS public key to create DecodingKey
    let decoding_key =
        DecodingKey::from_ed_components(&public_key_base64).expect("Failed to create decoding key");

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
        },
        Err(e) => {
            panic!("✗ JWT verification FAILED: {e:?}");
        },
    }
}
