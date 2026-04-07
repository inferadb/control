//! Local JWT validation middleware using cached JWKS public keys.
//!
//! Validates access tokens locally using Ed25519 public keys fetched from
//! the Ledger SDK. Keys are cached with a 5-minute TTL via [`moka`].
//! This avoids a network round-trip to Ledger for read-only operations.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use axum_extra::extract::cookie::CookieJar;
use inferadb_control_const::auth::REQUIRED_AUDIENCE;
use inferadb_control_types::Error as CoreError;
use inferadb_ledger_sdk::LedgerClient;
use inferadb_ledger_types::UserSlug;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};

use super::jwt::{UserClaims, extract_access_token};
use crate::handlers::state::{ApiError, AppState};

/// JWKS key cache keyed by `kid` with a 5-minute TTL.
///
/// Wraps a [`moka::future::Cache`] mapping key IDs to [`DecodingKey`]s.
/// Keys are refreshed from the Ledger SDK on cache miss using `try_get_with()`
/// for built-in deduplication (one concurrent caller fetches from Ledger).
#[derive(Clone)]
pub struct JwksCache {
    inner: moka::future::Cache<String, Arc<DecodingKey>>,
}

impl Default for JwksCache {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for JwksCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwksCache").field("entry_count", &self.inner.entry_count()).finish()
    }
}

impl JwksCache {
    /// Creates a new JWKS cache with a 5-minute TTL.
    ///
    /// Key rotation is infrequent (monthly/quarterly), so a 5-minute TTL
    /// balances freshness with reduced Ledger round-trips.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: moka::future::Cache::builder()
                .time_to_live(std::time::Duration::from_secs(300))
                .max_capacity(64)
                .build(),
        }
    }

    /// Pre-populates the cache with a decoding key.
    ///
    /// Test infrastructure calls this to inject test signing keys, bypassing
    /// the Ledger key fetch.
    pub async fn insert_key(&self, kid: String, key: Arc<DecodingKey>) {
        self.inner.insert(kid, key).await;
    }

    /// Looks up a decoding key by kid, fetching from Ledger on cache miss.
    ///
    /// Uses `try_get_with()` for built-in deduplication: when multiple requests
    /// hit a cache miss for the same `kid`, only one fetches from Ledger while
    /// the others await the result. This prevents thundering herd on key rotation.
    async fn get_or_fetch(
        &self,
        kid: &str,
        ledger: &LedgerClient,
    ) -> Result<Arc<DecodingKey>, CoreError> {
        let ledger_clone = ledger.clone();
        let kid_owned = kid.to_string();

        self.inner
            .try_get_with(
                kid_owned.clone(),
                async move { fetch_key(&ledger_clone, &kid_owned).await },
            )
            .await
            .map_err(|e| CoreError::auth(format!("failed to fetch signing key: {e}")))
    }
}

/// Fetches a specific key by kid from Ledger's public key set.
async fn fetch_key(ledger: &LedgerClient, target_kid: &str) -> Result<Arc<DecodingKey>, CoreError> {
    let system_caller = UserSlug::new(inferadb_control_const::auth::SYSTEM_CALLER_SLUG);
    let keys = ledger.get_public_keys(system_caller, None).await.map_err(|e| {
        CoreError::internal(format!("failed to fetch public keys from Ledger: {e}"))
    })?;

    for key_info in keys {
        if key_info.status == "active" && key_info.kid == target_kid {
            return Ok(Arc::new(DecodingKey::from_ed_der(&key_info.public_key)));
        }
    }

    Err(CoreError::auth("signing key not found"))
}

/// JWT claims matching Ledger's `UserSessionClaims`.
///
/// Carries the subset of fields needed to construct [`UserClaims`]
/// during local JWT decoding; `jsonwebtoken` validates the rest.
#[derive(Debug, serde::Deserialize)]
struct LocalJwtClaims {
    /// Token type discriminator (must be "user_session").
    #[serde(rename = "type")]
    token_type: String,
    /// User slug (Snowflake ID).
    user: u64,
    /// User role ("user" or "admin").
    role: String,
}

/// Extracts the `kid` from a JWT header without cryptographic verification.
///
/// Rejects tokens with an `alg` other than `"EdDSA"` or a missing `kid`.
fn extract_kid_from_header(token: &str) -> Result<String, CoreError> {
    use base64::Engine;

    let header_part = token.split('.').next().ok_or_else(|| CoreError::auth("malformed JWT"))?;

    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header_part)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(header_part))
        .map_err(|_| CoreError::auth("invalid JWT header encoding"))?;

    let header: serde_json::Value =
        serde_json::from_slice(&header_bytes).map_err(|_| CoreError::auth("invalid JWT header"))?;

    let alg = header
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CoreError::auth("missing algorithm in JWT header"))?;

    if alg != "EdDSA" {
        return Err(CoreError::auth("unsupported JWT algorithm"));
    }

    let kid = header
        .get("kid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CoreError::auth("missing kid in JWT header"))?;

    Ok(kid.to_string())
}

/// Validates a JWT locally using cached Ed25519 public keys.
async fn validate_jwt_locally(
    token: &str,
    cache: &JwksCache,
    ledger: &LedgerClient,
) -> Result<UserClaims, CoreError> {
    let kid = extract_kid_from_header(token)?;

    let decoding_key = cache.get_or_fetch(&kid, ledger).await?;

    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_audience(&[REQUIRED_AUDIENCE]);
    validation.set_issuer(&[inferadb_control_const::auth::REQUIRED_ISSUER]);
    validation.validate_nbf = true;
    validation.leeway = 30;

    let token_data = jsonwebtoken::decode::<LocalJwtClaims>(token, &decoding_key, &validation)
        .map_err(|e| CoreError::auth(format!("JWT validation failed: {e}")))?;

    let claims = token_data.claims;
    if claims.token_type != "user_session" {
        return Err(CoreError::auth("vault access tokens cannot be used for user authentication"));
    }

    Ok(UserClaims { user_slug: UserSlug::new(claims.user), role: claims.role })
}

/// Local JWT validation middleware for read-only routes.
///
/// Validates the JWT locally using cached Ed25519 public keys from Ledger,
/// avoiding a network round-trip for read operations. On validation success,
/// injects [`UserClaims`] into request extensions.
pub async fn require_jwt_local(
    State(state): State<AppState>,
    jar: CookieJar,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let ledger =
        state.ledger.as_ref().ok_or_else(|| CoreError::internal("Ledger client not configured"))?;

    let token = extract_access_token(&jar, &request)?;

    let claims = validate_jwt_locally(&token, &state.jwks_cache, ledger).await?;

    request.extensions_mut().insert(claims);
    Ok(next.run(request).await)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use base64::Engine;

    use super::*;

    /// Encodes a JSON value as a URL-safe base64 JWT header segment.
    fn encode_header(header: &serde_json::Value) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(header).unwrap())
    }

    /// Builds a fake JWT string from a pre-encoded header.
    fn fake_token(encoded_header: &str) -> String {
        format!("{encoded_header}.payload.signature")
    }

    // ── extract_kid_from_header: malformed input ─────────────────

    #[test]
    fn test_extract_kid_no_dots_returns_malformed_error() {
        let err = extract_kid_from_header("nodots").unwrap_err();
        assert!(err.to_string().contains("malformed JWT"), "expected 'malformed JWT', got: {err}");
    }

    #[test]
    fn test_extract_kid_invalid_base64_returns_encoding_error() {
        let err = extract_kid_from_header(&fake_token("!!!not-base64!!!")).unwrap_err();
        assert!(
            err.to_string().contains("invalid JWT header encoding"),
            "expected encoding error, got: {err}"
        );
    }

    #[test]
    fn test_extract_kid_invalid_json_returns_header_error() {
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"not-json");
        let err = extract_kid_from_header(&fake_token(&encoded)).unwrap_err();
        assert!(
            err.to_string().contains("invalid JWT header"),
            "expected 'invalid JWT header', got: {err}"
        );
    }

    // ── extract_kid_from_header: algorithm validation ────────────

    #[test]
    fn test_extract_kid_missing_alg_returns_error() {
        let header = serde_json::json!({"typ": "JWT", "kid": "k1"});
        let err = extract_kid_from_header(&fake_token(&encode_header(&header))).unwrap_err();
        assert!(
            err.to_string().contains("missing algorithm"),
            "expected 'missing algorithm', got: {err}"
        );
    }

    #[test]
    fn test_extract_kid_unsupported_algorithm_returns_error() {
        let cases = [("RS256", "RSA"), ("HS256", "HMAC"), ("ES256", "ECDSA")];
        for (alg, label) in cases {
            let header = serde_json::json!({"alg": alg, "typ": "JWT", "kid": "k1"});
            let err = extract_kid_from_header(&fake_token(&encode_header(&header))).unwrap_err();
            assert!(
                err.to_string().contains("unsupported JWT algorithm"),
                "{label} alg={alg} should be rejected, got: {err}"
            );
        }
    }

    // ── extract_kid_from_header: kid extraction ──────────────────

    #[test]
    fn test_extract_kid_missing_kid_returns_error() {
        let header = serde_json::json!({"alg": "EdDSA", "typ": "JWT"});
        let err = extract_kid_from_header(&fake_token(&encode_header(&header))).unwrap_err();
        assert!(err.to_string().contains("missing kid"), "expected 'missing kid', got: {err}");
    }

    #[test]
    fn test_extract_kid_valid_header_returns_kid() {
        let header = serde_json::json!({"alg": "EdDSA", "typ": "JWT", "kid": "key-abc-123"});
        let kid = extract_kid_from_header(&fake_token(&encode_header(&header))).unwrap();
        assert_eq!(kid, "key-abc-123");
    }

    #[test]
    fn test_extract_kid_accepts_padded_base64() {
        let header = serde_json::json!({"alg": "EdDSA", "typ": "JWT", "kid": "padded-key"});
        let encoded = base64::engine::general_purpose::URL_SAFE.encode(
            serde_json::to_vec(&header).unwrap(),
        );
        let kid = extract_kid_from_header(&fake_token(&encoded)).unwrap();
        assert_eq!(kid, "padded-key");
    }

    // ── JwksCache ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_jwks_cache_insert_and_retrieve() {
        let cache = JwksCache::new();
        let key = Arc::new(DecodingKey::from_ed_der(&[0u8; 32]));
        cache.insert_key("kid-1".to_string(), key.clone()).await;
        assert_eq!(cache.inner.entry_count(), 1);
    }

    #[test]
    fn test_jwks_cache_debug_format() {
        let cache = JwksCache::new();
        let debug = format!("{cache:?}");
        assert!(debug.contains("JwksCache"), "debug output should contain struct name");
        assert!(debug.contains("entry_count"), "debug output should contain entry_count");
    }

    #[test]
    fn test_jwks_cache_default_creates_empty_cache() {
        let cache = JwksCache::default();
        assert_eq!(cache.inner.entry_count(), 0);
    }
}
