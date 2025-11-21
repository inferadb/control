use crate::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use base64::{
    engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD},
    Engine,
};
use infera_management_core::RepositoryContext;
use serde::{Deserialize, Serialize};

/// JSON Web Key Set (JWKS) response format
/// This follows the RFC 7517 specification for JWK Set
#[derive(Debug, Serialize, Deserialize)]
pub struct JwksResponse {
    pub keys: Vec<Jwk>,
}

/// JSON Web Key (JWK) format for Ed25519 keys
/// This follows RFC 8037 for EdDSA keys
#[derive(Debug, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type - always "OKP" for Ed25519
    pub kty: String,
    /// Curve - always "Ed25519"
    pub crv: String,
    /// Key ID
    pub kid: String,
    /// Public key (base64url encoded)
    pub x: String,
    /// Key use - "sig" for signing
    #[serde(rename = "use")]
    pub key_use: String,
    /// Algorithm - "EdDSA"
    pub alg: String,
}

impl Jwk {
    /// Create a JWK from a certificate's public key
    fn from_certificate_public_key(kid: String, public_key_base64: &str) -> Result<Self, String> {
        // Decode the base64 public key
        let public_key_bytes = BASE64
            .decode(public_key_base64)
            .map_err(|e| format!("Failed to decode public key: {}", e))?;

        if public_key_bytes.len() != 32 {
            return Err(format!(
                "Invalid Ed25519 public key length: {} (expected 32)",
                public_key_bytes.len()
            ));
        }

        // Re-encode as base64url (RFC 4648 Section 5)
        let x = base64_url_encode(&public_key_bytes);

        Ok(Jwk {
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            kid,
            x,
            key_use: "sig".to_string(),
            alg: "EdDSA".to_string(),
        })
    }
}

/// Encode bytes as base64url (no padding) per RFC 4648 Section 5
fn base64_url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Get global JWKS (all active certificates across all organizations)
///
/// GET /.well-known/jwks.json
/// Public endpoint - no authentication required
pub async fn get_global_jwks(
    State(state): State<AppState>,
) -> Result<Json<JwksResponse>, (StatusCode, String)> {
    let repos = RepositoryContext::new((*state.storage).clone());

    // Get all active certificates
    let certs = repos
        .client_certificate
        .list_all_active()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Convert to JWKs
    let mut keys = Vec::new();
    for cert in certs {
        match Jwk::from_certificate_public_key(cert.kid.clone(), &cert.public_key) {
            Ok(jwk) => keys.push(jwk),
            Err(e) => {
                tracing::warn!("Skipping invalid certificate {}: {}", cert.kid, e);
                continue;
            }
        }
    }

    Ok(Json(JwksResponse { keys }))
}

/// Get organization-specific JWKS (active certificates for an organization)
///
/// GET /v1/organizations/:org/jwks.json
/// Public endpoint - no authentication required
pub async fn get_org_jwks(
    State(state): State<AppState>,
    Path(org_id): Path<i64>,
) -> Result<Json<JwksResponse>, (StatusCode, String)> {
    // Verify organization exists
    let repos = RepositoryContext::new((*state.storage).clone());
    repos
        .org
        .get(org_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Organization not found".to_string()))?;

    // Get all active certificates (we'll filter by org)
    let all_certs = repos
        .client_certificate
        .list_all_active()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    tracing::debug!(
        org_id = %org_id,
        total_certs = all_certs.len(),
        cert_kids = ?all_certs.iter().map(|c| &c.kid).collect::<Vec<_>>(),
        "JWKS: Retrieved all active certificates"
    );

    // Filter by organization (kid format: org-<org_id>-client-<client_id>-cert-<cert_id>)
    let org_prefix = format!("org-{}-", org_id);
    let org_certs: Vec<_> = all_certs
        .into_iter()
        .filter(|cert| cert.kid.starts_with(&org_prefix))
        .collect();

    tracing::debug!(
        org_id = %org_id,
        org_prefix = %org_prefix,
        filtered_count = org_certs.len(),
        filtered_kids = ?org_certs.iter().map(|c| &c.kid).collect::<Vec<_>>(),
        "JWKS: Filtered certificates by organization"
    );

    // Convert to JWKs
    let mut keys = Vec::new();
    for cert in org_certs {
        match Jwk::from_certificate_public_key(cert.kid.clone(), &cert.public_key) {
            Ok(jwk) => keys.push(jwk),
            Err(e) => {
                tracing::warn!("Skipping invalid certificate {}: {}", cert.kid, e);
                continue;
            }
        }
    }

    Ok(Json(JwksResponse { keys }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_url_encode() {
        let bytes = b"hello world";
        let encoded = base64_url_encode(bytes);
        // Standard base64 would be "aGVsbG8gd29ybGQ="
        // Base64url should be "aGVsbG8gd29ybGQ" (no padding)
        assert_eq!(encoded, "aGVsbG8gd29ybGQ");
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        assert!(!encoded.contains('='));
    }

    #[test]
    fn test_jwk_from_certificate() {
        // Valid Ed25519 public key (32 bytes of zeros for testing)
        let public_key_bytes = vec![0u8; 32];
        let public_key_base64 = BASE64.encode(&public_key_bytes);

        let jwk =
            Jwk::from_certificate_public_key("test-kid".to_string(), &public_key_base64).unwrap();

        assert_eq!(jwk.kty, "OKP");
        assert_eq!(jwk.crv, "Ed25519");
        assert_eq!(jwk.kid, "test-kid");
        assert_eq!(jwk.key_use, "sig");
        assert_eq!(jwk.alg, "EdDSA");
        assert!(!jwk.x.is_empty());
    }

    #[test]
    fn test_jwk_invalid_public_key_length() {
        // Invalid length (not 32 bytes)
        let public_key_bytes = vec![0u8; 16];
        let public_key_base64 = BASE64.encode(&public_key_bytes);

        let result = Jwk::from_certificate_public_key("test-kid".to_string(), &public_key_base64);
        assert!(result.is_err());
    }
}
