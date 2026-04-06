//! Integration test infrastructure with MockLedgerServer.
//!
//! Provides test helpers that spin up a [`MockLedgerServer`] on an ephemeral
//! port, connect a real [`LedgerClient`], and build a fully-configured
//! [`AppState`] with Ledger support. This enables end-to-end handler testing
//! without a running Ledger cluster.
//!
//! # Architecture
//!
//! ```text
//! Test ──► Axum Router ──► Handler ──► LedgerClient ──► MockLedgerServer
//!                                         (real gRPC)     (ephemeral port)
//! ```
//!
//! # Usage
//!
//! ```no_run
//! use inferadb_control_test_integration::TestHarness;
//!
//! #[tokio::test]
//! async fn test_create_organization() {
//!     let harness = TestHarness::start().await;
//!     let response = harness.authenticated_post(
//!         "/control/v1/organizations",
//!         serde_json::json!({"name": "Test Org"}),
//!     ).await;
//!     assert_eq!(response.status(), axum::http::StatusCode::OK);
//! }
//! ```

// Test fixtures use unwrap/expect for clear failure messages in assertions.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![deny(unsafe_code)]

use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use ed25519_dalek::SigningKey;
use inferadb_control_api::{AppState, create_router_with_state};
use inferadb_control_config::{Config, StorageBackend};
pub use inferadb_control_const::auth::{ACCESS_TOKEN_COOKIE_NAME, REFRESH_TOKEN_COOKIE_NAME};
use inferadb_ledger_sdk::{ClientConfig, LedgerClient, ServerSource, mock::MockLedgerServer};
use inferadb_ledger_types::OrganizationSlug;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
pub use serde_json::Value;
use tower::ServiceExt;

/// Default mock access token returned by [`MockLedgerServer`].
///
/// The mock's `validate_token` always accepts this token and returns
/// user_slug=42, role="user".
pub const MOCK_ACCESS_TOKEN: &str = "mock-access-token";

/// Default mock refresh token returned by [`MockLedgerServer`].
pub const MOCK_REFRESH_TOKEN: &str = "mock-refresh-token";

/// Default test user slug returned by the mock token validator.
pub const MOCK_USER_SLUG: u64 = 42;

/// Default test organization slug for seeded test data.
pub const TEST_ORG_SLUG: u64 = 1;

/// Key ID used in test JWTs.
const TEST_KID: &str = "test-kid-001";

/// JWT claims matching the `LocalJwtClaims` structure expected by `require_jwt_local`.
#[derive(serde::Serialize)]
struct TestJwtClaims {
    /// Token type discriminator.
    #[serde(rename = "type")]
    token_type: String,
    /// User slug (Snowflake ID).
    user: u64,
    /// User role.
    role: String,
    /// Issued at (Unix timestamp).
    iat: u64,
    /// Expiration (Unix timestamp).
    exp: u64,
    /// Not before (Unix timestamp).
    nbf: u64,
    /// Audience.
    aud: String,
    /// Issuer.
    iss: String,
}

/// Generates a test Ed25519 keypair and a signed JWT for local validation.
fn generate_test_jwt(user_slug: u64, role: &str) -> (String, jsonwebtoken::DecodingKey) {
    // Use a deterministic seed for reproducible tests.
    let seed: [u8; 32] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time should be after epoch")
        .as_secs();

    let claims = TestJwtClaims {
        token_type: "user_session".to_string(),
        user: user_slug,
        role: role.to_string(),
        iat: now,
        exp: now + 3600,
        nbf: now - 30,
        aud: inferadb_control_const::auth::REQUIRED_AUDIENCE.to_string(),
        iss: inferadb_control_const::auth::REQUIRED_ISSUER.to_string(),
    };

    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(TEST_KID.to_string());

    // The jsonwebtoken crate's from_ed_der expects PKCS#8 DER format, not raw bytes.
    // Construct the PKCS#8 DER wrapper around the raw Ed25519 key.
    let pkcs8_prefix: &[u8] = &[
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    let mut pkcs8_der = Vec::with_capacity(pkcs8_prefix.len() + 32);
    pkcs8_der.extend_from_slice(pkcs8_prefix);
    pkcs8_der.extend_from_slice(signing_key.as_bytes());

    let encoding_key = EncodingKey::from_ed_der(&pkcs8_der);
    let token =
        jsonwebtoken::encode(&header, &claims, &encoding_key).expect("JWT encoding should succeed");

    // For the decoding key, use the SubjectPublicKeyInfo DER format.
    let spki_prefix: &[u8] =
        &[0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
    let mut spki_der = Vec::with_capacity(spki_prefix.len() + 32);
    spki_der.extend_from_slice(spki_prefix);
    spki_der.extend_from_slice(verifying_key.as_bytes());

    let decoding_key = jsonwebtoken::DecodingKey::from_ed_der(&spki_der);

    (token, decoding_key)
}

/// Fully-configured test environment with a mock Ledger backend.
///
/// Owns the [`MockLedgerServer`] (which shuts down on drop), the connected
/// [`LedgerClient`], and the Axum [`Router`] wired with all middleware.
pub struct TestHarness {
    /// The mock gRPC server. Kept alive for the duration of the test.
    pub server: MockLedgerServer,
    /// A real Ledger client connected to the mock server.
    pub client: LedgerClient,
    /// Fully-configured Axum router with Ledger-backed AppState.
    pub app: Router,
    /// The AppState used to build the router.
    pub state: AppState,
    /// A valid JWT signed with a test Ed25519 key.
    ///
    /// This token passes both `require_jwt` (Ledger-validated, mock accepts any
    /// non-empty token) and `require_jwt_local` (locally validated with cached
    /// Ed25519 key). Use this for read route tests.
    pub jwt_token: String,
}

impl TestHarness {
    /// Starts a new test harness with a mock Ledger server.
    ///
    /// Creates a [`MockLedgerServer`] on an ephemeral port, connects a
    /// [`LedgerClient`], builds an [`AppState`] with the client, and
    /// constructs the full router with all middleware.
    pub async fn start() -> Self {
        let server = MockLedgerServer::start().await.expect("mock server should start");

        let config = ClientConfig::builder()
            .servers(ServerSource::from_static([server.endpoint().to_string()]))
            .client_id("test-control")
            .build()
            .expect("client config should be valid");

        let client = LedgerClient::new(config).await.expect("client should connect");

        let app_config = Config::builder()
            .storage(StorageBackend::Memory)
            .key_file(std::path::PathBuf::from("/tmp/test-master.key"))
            .build();

        let email_sender = Box::new(inferadb_control_core::MockEmailSender::new());
        let email_service = inferadb_control_core::EmailService::new(email_sender);

        // Generate a test JWT signed with a deterministic Ed25519 key.
        let (jwt_token, decoding_key) = generate_test_jwt(MOCK_USER_SLUG, "user");

        let state = AppState::builder()
            .config(Arc::new(app_config))
            .worker_id(0)
            .email_service(Arc::new(email_service))
            .ledger(Arc::new(client.clone()))
            .build();

        // Pre-populate the JWKS cache so `require_jwt_local` can validate our test JWT
        // without fetching keys from the mock Ledger (which returns invalid keys).
        state.jwks_cache.insert_key(TEST_KID.to_string(), Arc::new(decoding_key)).await;

        let app = create_router_with_state(state.clone());

        Self { server, client, app, state, jwt_token }
    }

    /// Starts a harness with WebAuthn configured.
    ///
    /// Identical to [`start`] but also configures a [`webauthn_rs::Webauthn`]
    /// instance in [`AppState`], enabling passkey ceremony handlers.
    pub async fn start_with_webauthn() -> Self {
        let server = MockLedgerServer::start().await.expect("mock server should start");

        let config = ClientConfig::builder()
            .servers(ServerSource::from_static([server.endpoint().to_string()]))
            .client_id("test-control")
            .build()
            .expect("client config should be valid");

        let client = LedgerClient::new(config).await.expect("client should connect");

        let app_config = Config::builder()
            .storage(StorageBackend::Memory)
            .key_file(std::path::PathBuf::from("/tmp/test-master.key"))
            .build();

        let email_sender = Box::new(inferadb_control_core::MockEmailSender::new());
        let email_service = inferadb_control_core::EmailService::new(email_sender);

        let (jwt_token, decoding_key) = generate_test_jwt(MOCK_USER_SLUG, "user");

        let webauthn =
            inferadb_control_core::webauthn::build_webauthn("localhost", "http://localhost:3000")
                .expect("WebAuthn should build");

        let state = AppState::builder()
            .config(Arc::new(app_config))
            .worker_id(0)
            .email_service(Arc::new(email_service))
            .ledger(Arc::new(client.clone()))
            .webauthn(Arc::new(webauthn))
            .build();

        state.jwks_cache.insert_key(TEST_KID.to_string(), Arc::new(decoding_key)).await;

        let app = create_router_with_state(state.clone());

        Self { server, client, app, state, jwt_token }
    }

    /// Starts a harness with a pre-seeded organization.
    ///
    /// Adds an organization (slug=1, name="Test Org") with the mock user
    /// (slug=42) as an admin member, matching the mock token validator's
    /// default user.
    pub async fn start_with_org() -> Self {
        let harness = Self::start().await;
        harness.seed_org(OrganizationSlug::new(TEST_ORG_SLUG), "Test Org");
        harness
    }

    /// Seeds an organization with the default test user as admin.
    pub fn seed_org(&self, org: OrganizationSlug, name: &str) {
        self.server.add_organization(org, name, inferadb_ledger_types::Region::US_EAST_VA);
    }

    // ── Request Helpers ────────────────────────────────────────────

    /// Sends an authenticated GET request with a valid JWT.
    ///
    /// Uses the test JWT (signed with a real Ed25519 key) which is accepted
    /// by both `require_jwt` (Ledger-validated) and `require_jwt_local`
    /// (locally validated via pre-populated JWKS cache).
    pub async fn authenticated_get(&self, uri: &str) -> axum::http::Response<Body> {
        self.app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .header("authorization", format!("Bearer {}", self.jwt_token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    /// Sends an authenticated POST request with JSON body.
    pub async fn authenticated_post(&self, uri: &str, body: Value) -> axum::http::Response<Body> {
        self.app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("authorization", format!("Bearer {MOCK_ACCESS_TOKEN}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    /// Sends an authenticated PATCH request with JSON body.
    pub async fn authenticated_patch(&self, uri: &str, body: Value) -> axum::http::Response<Body> {
        self.app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(uri)
                    .header("authorization", format!("Bearer {MOCK_ACCESS_TOKEN}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    /// Sends an authenticated DELETE request.
    pub async fn authenticated_delete(&self, uri: &str) -> axum::http::Response<Body> {
        self.app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(uri)
                    .header("authorization", format!("Bearer {MOCK_ACCESS_TOKEN}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    /// Sends an unauthenticated POST request with JSON body.
    pub async fn post(&self, uri: &str, body: Value) -> axum::http::Response<Body> {
        self.app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    /// Sends an unauthenticated GET request.
    pub async fn get(&self, uri: &str) -> axum::http::Response<Body> {
        self.app
            .clone()
            .oneshot(Request::builder().method("GET").uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    /// Sends an unauthenticated POST with a cookie header.
    pub async fn post_with_cookie(
        &self,
        uri: &str,
        body: Value,
        cookie: &str,
    ) -> axum::http::Response<Body> {
        self.app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("content-type", "application/json")
                    .header("cookie", cookie)
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    // ── Response Helpers ───────────────────────────────────────────

    /// Parses an HTTP response body as JSON.
    ///
    /// Returns [`Value::Null`] for empty response bodies instead of panicking.
    pub async fn body_json(response: axum::http::Response<Body>) -> Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        if bytes.is_empty() {
            return Value::Null;
        }
        serde_json::from_slice(&bytes).unwrap()
    }

    /// Asserts the response has the expected status code and returns the JSON body.
    pub async fn assert_status(
        response: axum::http::Response<Body>,
        expected: StatusCode,
    ) -> Value {
        let actual = response.status();
        let json = Self::body_json(response).await;
        assert_eq!(actual, expected, "expected status {expected}, got {actual}; body: {json}");
        json
    }

    /// Extracts a named cookie value from response Set-Cookie headers.
    pub fn extract_cookie(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
        let prefix = format!("{name}=");
        headers.get_all("set-cookie").iter().filter_map(|v| v.to_str().ok()).find_map(|s| {
            s.split(';')
                .next()
                .and_then(|cookie| cookie.strip_prefix(&prefix))
                .map(|v| v.to_string())
        })
    }
}
