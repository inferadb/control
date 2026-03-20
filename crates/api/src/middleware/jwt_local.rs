//! Local JWT validation middleware using cached JWKS public keys.
//!
//! Validates access tokens locally using Ed25519 public keys fetched from
//! the Ledger SDK. Keys are cached with a 60-second TTL via [`moka`].
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
use crate::handlers::auth::{ApiError, AppState};

/// Cached JWKS keys keyed by `kid`, with a 60-second TTL.
///
/// Wraps a [`moka::future::Cache`] that maps key IDs to [`DecodingKey`]s.
/// Keys are refreshed from the Ledger SDK on cache miss.
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
    /// Creates a new JWKS cache with a 60-second TTL.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: moka::future::Cache::builder()
                .time_to_live(std::time::Duration::from_secs(60))
                .max_capacity(64)
                .build(),
        }
    }

    /// Looks up a decoding key by kid.
    async fn get(&self, kid: &str) -> Option<Arc<DecodingKey>> {
        self.inner.get(kid).await
    }

    /// Inserts a decoding key for a given kid.
    async fn insert(&self, kid: String, key: Arc<DecodingKey>) {
        self.inner.insert(kid, key).await;
    }
}

/// Fetches active public keys from Ledger and populates the cache.
async fn refresh_keys(ledger: &LedgerClient, cache: &JwksCache) -> Result<(), CoreError> {
    let keys = ledger.get_public_keys(None).await.map_err(|e| {
        CoreError::internal(format!("failed to fetch public keys from Ledger: {e}"))
    })?;

    for key_info in keys {
        if key_info.status != "active" {
            continue;
        }
        let decoding_key = DecodingKey::from_ed_der(&key_info.public_key);
        cache.insert(key_info.kid, Arc::new(decoding_key)).await;
    }

    Ok(())
}

/// JWT claims structure matching the Ledger's `UserSessionClaims`.
///
/// Used for local JWT decoding. Only the fields needed for constructing
/// [`UserClaims`] are extracted; the rest are validated by `jsonwebtoken`.
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
/// Performs defense-in-depth checks:
/// 1. Rejects any `alg` value that is not exactly `"EdDSA"`.
/// 2. Validates `kid` is present.
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

/// Validates a JWT locally using cached public keys.
///
/// On cache miss for the given `kid`, refreshes the cache from Ledger
/// and retries the lookup once.
async fn validate_jwt_locally(
    token: &str,
    cache: &JwksCache,
    ledger: &LedgerClient,
) -> Result<UserClaims, CoreError> {
    let kid = extract_kid_from_header(token)?;

    // First try: look up key in cache.
    let decoding_key = match cache.get(&kid).await {
        Some(key) => key,
        None => {
            // Cache miss: refresh keys from Ledger and retry.
            refresh_keys(ledger, cache).await?;
            cache.get(&kid).await.ok_or_else(|| CoreError::auth("signing key not found"))?
        },
    };

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
