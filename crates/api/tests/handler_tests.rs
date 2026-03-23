//! Handler-level integration tests.
//!
//! These tests verify Control's own logic — input validation, error responses,
//! security headers, and health endpoints — without a Ledger backend.
//! Endpoints that require Ledger return 500 "an internal error occurred"
//! when `AppState.ledger` is `None`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use inferadb_control_core::IdGenerator;
use inferadb_control_test_fixtures::{create_test_app, create_test_state};
use serde_json::{Value, json};
use tower::ServiceExt;

async fn body_json(response: axum::http::Response<Body>) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn json_post(uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn json_get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

fn test_app() -> axum::Router {
    let _ = IdGenerator::init(900);
    create_test_app(create_test_state())
}

// ── Health Endpoints ─────────────────────────────────────────────────

#[tokio::test]
async fn healthz_returns_ok() {
    let app = test_app();
    let resp = app.oneshot(json_get("/healthz")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["status"], "healthy");
}

#[tokio::test]
async fn livez_returns_ok() {
    let app = test_app();
    let resp = app.oneshot(json_get("/livez")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn readyz_returns_200_without_ledger() {
    let app = test_app();
    let resp = app.oneshot(json_get("/readyz")).await.unwrap();
    // Without Ledger, readyz returns OK (dev mode = healthy)
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn healthz_returns_service_name() {
    let app = test_app();
    let resp = app.oneshot(json_get("/healthz")).await.unwrap();
    let json = body_json(resp).await;
    assert_eq!(json["service"], "inferadb-control");
}

// ── Security Headers ─────────────────────────────────────────────────

#[tokio::test]
async fn responses_include_security_headers() {
    let app = test_app();
    let resp = app.oneshot(json_get("/healthz")).await.unwrap();
    let h = resp.headers();

    assert_eq!(h.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(h.get("x-frame-options").unwrap(), "DENY");
    assert_eq!(h.get("cache-control").unwrap(), "no-store");
    assert!(h.get("strict-transport-security").is_some());
    assert_eq!(h.get("referrer-policy").unwrap(), "no-referrer");
    assert_eq!(h.get("content-security-policy").unwrap(), "default-src 'none'");
}

#[tokio::test]
async fn responses_include_request_id() {
    let app = test_app();
    let resp = app.oneshot(json_get("/healthz")).await.unwrap();
    assert!(resp.headers().get("x-request-id").is_some());
}

#[tokio::test]
async fn client_request_id_is_propagated() {
    let app = test_app();
    let req = Request::builder()
        .uri("/healthz")
        .header("x-request-id", "test-correlation-123")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.headers().get("x-request-id").unwrap(), "test-correlation-123");
}

#[tokio::test]
async fn invalid_request_id_is_replaced() {
    let app = test_app();
    let req = Request::builder()
        .uri("/healthz")
        .header("x-request-id", "has spaces and $pecial chars!")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // Invalid request ID should be replaced with a UUID
    let id = resp.headers().get("x-request-id").unwrap().to_str().unwrap();
    assert_ne!(id, "has spaces and $pecial chars!");
    assert!(id.contains('-')); // UUID format
}

// ── Input Validation (email auth) ────────────────────────────────────

#[tokio::test]
async fn email_initiate_rejects_invalid_email() {
    let app = test_app();
    let resp = app
        .oneshot(json_post("/control/v1/auth/email/initiate", json!({"email": "not-an-email"})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = body_json(resp).await;
    assert_eq!(json["code"], "VALIDATION_ERROR");
}

#[tokio::test]
async fn email_initiate_rejects_control_characters() {
    let app = test_app();
    let resp = app
        .oneshot(json_post(
            "/control/v1/auth/email/initiate",
            json!({"email": "test@exam\nple.com"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn email_initiate_rejects_oversized_email() {
    let app = test_app();
    let long_local = "a".repeat(300);
    let resp = app
        .oneshot(json_post(
            "/control/v1/auth/email/initiate",
            json!({"email": format!("{long_local}@example.com")}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn complete_registration_rejects_invalid_name() {
    let app = test_app();
    let resp = app
        .oneshot(json_post(
            "/control/v1/auth/email/complete",
            json!({
                "onboarding_token": "fake",
                "email": "test@example.com",
                "name": "<script>alert('xss')</script>",
                "organization_name": "Valid Org"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = body_json(resp).await;
    assert_eq!(json["code"], "VALIDATION_ERROR");
}

#[tokio::test]
async fn complete_registration_rejects_empty_org_name() {
    let app = test_app();
    let resp = app
        .oneshot(json_post(
            "/control/v1/auth/email/complete",
            json!({
                "onboarding_token": "fake",
                "email": "test@example.com",
                "name": "Test User",
                "organization_name": "   "
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── Error Response Format ────────────────────────────────────────────

#[tokio::test]
async fn error_responses_have_structured_format() {
    let app = test_app();
    let resp = app
        .oneshot(json_post("/control/v1/auth/email/initiate", json!({"email": "bad"})))
        .await
        .unwrap();
    let json = body_json(resp).await;
    // All error responses must have `error` and `code` fields
    assert!(json["error"].is_string(), "error field must be a string");
    assert!(json["code"].is_string(), "code field must be a string");
}

#[tokio::test]
async fn server_errors_are_scrubbed() {
    let app = test_app();
    // Without Ledger configured, email verify should hit the "Ledger not configured"
    // internal error — but the client should see a generic message
    let resp = app
        .oneshot(json_post(
            "/control/v1/auth/email/verify",
            json!({"email": "test@example.com", "code": "123456"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let json = body_json(resp).await;
    assert_eq!(json["error"], "an internal error occurred");
    assert_eq!(json["code"], "INTERNAL_ERROR");
    // Must NOT contain "Ledger" or internal details
    let error_str = json["error"].as_str().unwrap();
    assert!(!error_str.contains("Ledger"), "internal details must not leak to client");
}

// ── 404 for Unknown Routes ───────────────────────────────────────────

#[tokio::test]
async fn unknown_route_returns_404() {
    let app = test_app();
    let resp = app.oneshot(json_get("/control/v1/nonexistent")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ── Metrics Endpoint ─────────────────────────────────────────────────

#[tokio::test]
async fn metrics_endpoint_is_accessible_without_auth() {
    let app = test_app();
    let resp = app.oneshot(json_get("/metrics")).await.unwrap();
    // Metrics should be accessible without JWT (infrastructure endpoint).
    let status = resp.status();
    assert!(
        status != StatusCode::UNAUTHORIZED && status != StatusCode::FORBIDDEN,
        "metrics endpoint should not require authentication (got {status})"
    );
}

// ── CORS ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn cors_preflight_returns_allowed_origin() {
    let app = test_app();
    let req = Request::builder()
        .method("OPTIONS")
        .uri("/control/v1/auth/email/initiate")
        .header("origin", "http://localhost:3000")
        .header("access-control-request-method", "POST")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert!(
        resp.headers().get("access-control-allow-origin").is_some(),
        "CORS preflight should include allow-origin"
    );
}

// ── JSON Body Handling ───────────────────────────────────────────────

#[tokio::test]
async fn malformed_json_returns_400() {
    let app = test_app();
    let req = Request::builder()
        .method("POST")
        .uri("/control/v1/auth/email/initiate")
        .header("content-type", "application/json")
        .body(Body::from("not valid json"))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn missing_required_field_is_rejected() {
    let app = test_app();
    // email field is required for initiate — axum returns 422 for deserialization errors
    let resp = app.oneshot(json_post("/control/v1/auth/email/initiate", json!({}))).await.unwrap();
    let status = resp.status();
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY,
        "missing required field should be rejected (got {status})"
    );
}
