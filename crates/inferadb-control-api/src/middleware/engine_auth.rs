use std::sync::{Arc, LazyLock};

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use inferadb_control_core::error::Error as CoreError;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::handlers::auth::{ApiError, AppState};

/// Context for engine-authenticated requests
#[derive(Debug, Clone)]
pub struct EngineContext {
    /// Engine ID from JWT subject claim
    pub engine_id: String,
}

/// JWT claims for engine-to-control authentication
#[derive(Debug, Serialize, Deserialize)]
struct EngineJwtClaims {
    /// Issuer - the engine instance
    iss: String,
    /// Subject - "server:{server_id}" (format from engine)
    sub: String,
    /// Audience - the control API
    aud: String,
    /// Issued at (Unix timestamp)
    iat: i64,
    /// Expiration (Unix timestamp)
    exp: i64,
    /// JWT ID for replay protection
    jti: String,
}

/// JWKS (JSON Web Key Set) response from engine
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// JWK (JSON Web Key)
#[derive(Debug, Serialize, Deserialize, Clone)]
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

/// Cache for engine JWKS with TTL
#[derive(Clone)]
struct JwksCache {
    jwks: Arc<RwLock<Option<(Jwks, std::time::Instant)>>>,
    ttl: std::time::Duration,
}

impl JwksCache {
    fn new(ttl_seconds: u64) -> Self {
        Self { jwks: Arc::new(RwLock::new(None)), ttl: std::time::Duration::from_secs(ttl_seconds) }
    }

    async fn get_or_fetch(&self, jwks_url: &str) -> Result<Jwks, CoreError> {
        // Check cache first
        {
            let cache = self.jwks.read().await;
            if let Some((jwks, cached_at)) = cache.as_ref() {
                if cached_at.elapsed() < self.ttl {
                    return Ok(jwks.clone());
                }
            }
        }

        // Fetch fresh JWKS
        let client = reqwest::Client::new();
        let jwks: Jwks = client
            .get(jwks_url)
            .send()
            .await
            .map_err(|e| CoreError::Internal(format!("Failed to fetch engine JWKS: {}", e)))?
            .json()
            .await
            .map_err(|e| CoreError::Internal(format!("Failed to parse engine JWKS: {}", e)))?;

        // Update cache
        {
            let mut cache = self.jwks.write().await;
            *cache = Some((jwks.clone(), std::time::Instant::now()));
        }

        Ok(jwks)
    }
}

/// Global JWKS cache (lazy initialized with default TTL)
/// The actual TTL is configured per-request from AppState config
static JWKS_CACHE: LazyLock<JwksCache> = LazyLock::new(|| JwksCache::new(300)); // 5 minutes

/// Engine JWT authentication middleware
///
/// Extracts JWT from Authorization header, verifies it against the engine's JWKS,
/// and attaches engine context to the request.
pub async fn require_engine_jwt(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    // Extract JWT from Authorization header
    let auth_header = request
        .headers()
        .get("authorization")
        .ok_or_else(|| CoreError::Auth("Missing authorization header".to_string()))?;

    let auth_str = auth_header
        .to_str()
        .map_err(|_| CoreError::Auth("Invalid authorization header".to_string()))?;

    // Extract token from "Bearer <token>" format
    let token = auth_str.strip_prefix("Bearer ").ok_or_else(|| {
        CoreError::Auth("Authorization header must use Bearer scheme".to_string())
    })?;

    // Decode header to get kid
    let header = decode_header(token)
        .map_err(|e| CoreError::Auth(format!("Failed to decode JWT header: {}", e)))?;

    let kid = header.kid.ok_or_else(|| CoreError::Auth("JWT missing kid claim".to_string()))?;

    // Derive engine JWKS URL from policy_service config
    // The JWKS endpoint is at /.well-known/jwks.json on the engine's mesh port
    let engine_jwks_url = format!("{}/.well-known/jwks.json", state.config.effective_mesh_url());

    // Fetch JWKS and find the key
    let jwks = JWKS_CACHE.get_or_fetch(&engine_jwks_url).await?;

    let jwk = jwks
        .keys
        .iter()
        .find(|k| k.kid == kid)
        .ok_or_else(|| CoreError::Auth(format!("Key ID {} not found in engine JWKS", kid)))?;

    // Verify algorithm
    if jwk.alg != "EdDSA" || jwk.kty != "OKP" || jwk.crv != "Ed25519" {
        return Err(CoreError::Auth(format!(
            "Unsupported key algorithm: {} {} {}",
            jwk.alg, jwk.kty, jwk.crv
        ))
        .into());
    }

    // Construct PEM from JWK for EdDSA verification
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let public_key_bytes = URL_SAFE_NO_PAD
        .decode(&jwk.x)
        .map_err(|e| CoreError::Auth(format!("Failed to decode public key: {}", e)))?;

    if public_key_bytes.len() != 32 {
        return Err(CoreError::Auth("Invalid Ed25519 public key length".to_string()).into());
    }

    // Create PEM format for jsonwebtoken
    let pem = create_ed25519_public_key_pem(&public_key_bytes);

    let decoding_key = DecodingKey::from_ed_pem(pem.as_bytes())
        .map_err(|e| CoreError::Auth(format!("Failed to create decoding key: {}", e)))?;

    // Set up validation
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.validate_exp = true;
    validation.validate_nbf = false;

    // Get expected audience (control API URL) from environment or default
    let control_url = std::env::var("CONTROL_API_AUDIENCE")
        .unwrap_or_else(|_| "http://localhost:8081".to_string());
    validation.set_audience(&[control_url.as_str()]);
    validation.set_required_spec_claims(&["exp", "iss", "sub", "aud"]);

    // Verify JWT
    let token_data = decode::<EngineJwtClaims>(token, &decoding_key, &validation)
        .map_err(|e| CoreError::Auth(format!("JWT validation failed: {}", e)))?;

    // Extract engine ID from subject claim (format: "server:{server_id}" from engine)
    let engine_id = token_data
        .claims
        .sub
        .strip_prefix("server:")
        .ok_or_else(|| CoreError::Auth("Invalid engine subject format".to_string()))?
        .to_string();

    // Attach engine context to request extensions
    request.extensions_mut().insert(EngineContext { engine_id });

    Ok(next.run(request).await)
}

/// Create Ed25519 public key PEM from raw bytes
fn create_ed25519_public_key_pem(public_key_bytes: &[u8]) -> String {
    // SPKI format for Ed25519 public key
    let mut spki_bytes = vec![
        0x30, 0x2a, // SEQUENCE, length 42
        0x30, 0x05, // SEQUENCE, length 5
        0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
        0x03, 0x21, // BIT STRING, length 33
        0x00, // no unused bits
    ];
    spki_bytes.extend_from_slice(public_key_bytes);

    let pem = pem::Pem::new("PUBLIC KEY", spki_bytes);
    pem::encode(&pem)
}

/// Extract engine context from request extensions
///
/// This should only be called from handlers that are wrapped with require_engine_jwt middleware
pub fn extract_engine_context(request: &Request) -> Result<EngineContext, ApiError> {
    request
        .extensions()
        .get::<EngineContext>()
        .cloned()
        .ok_or_else(|| CoreError::Auth("Engine context not found in request".to_string()).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_ed25519_public_key_pem() {
        let public_key_bytes = [0u8; 32]; // Dummy key for testing
        let pem = create_ed25519_public_key_pem(&public_key_bytes);

        assert!(pem.contains("-----BEGIN PUBLIC KEY-----"));
        assert!(pem.contains("-----END PUBLIC KEY-----"));
    }
}
