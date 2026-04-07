//! Handler-level integration tests.
//!
//! These tests verify Control's own logic -- input validation, error responses,
//! security headers, and health endpoints -- without a Ledger backend.
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

// -- Health Endpoints ---------------------------------------------------------

#[tokio::test]
async fn test_healthz_ok_returns_healthy_status() {
    let app = test_app();

    let resp = app.oneshot(json_get("/healthz")).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["status"], "healthy");
}

#[tokio::test]
async fn test_healthz_ok_returns_service_name() {
    let app = test_app();

    let resp = app.oneshot(json_get("/healthz")).await.unwrap();

    let json = body_json(resp).await;
    assert_eq!(json["service"], "inferadb-control");
}

/// Health probe endpoints all return 200 with no special setup.
#[tokio::test]
async fn test_health_probes_return_200() {
    for endpoint in ["/livez", "/readyz", "/startupz"] {
        let app = test_app();

        let resp = app.oneshot(json_get(endpoint)).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK, "{endpoint} should return 200");
    }
}

/// The /healthz response contains all expected JSON structure fields.
#[tokio::test]
async fn test_healthz_response_contains_all_structure_fields() {
    let app = test_app();

    let resp = app.oneshot(json_get("/healthz")).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert!(json["version"].is_string(), "version field must be present");
    assert!(json["instance_id"].is_number(), "instance_id field must be present");
    assert!(json["uptime_seconds"].is_number(), "uptime_seconds field must be present");
    assert!(json["ledger_healthy"].is_boolean(), "ledger_healthy field must be present");
}

// -- Security Headers ---------------------------------------------------------

#[tokio::test]
async fn test_response_headers_include_security_headers() {
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
async fn test_response_headers_include_request_id() {
    let app = test_app();

    let resp = app.oneshot(json_get("/healthz")).await.unwrap();

    assert!(resp.headers().get("x-request-id").is_some());
}

#[tokio::test]
async fn test_request_id_valid_value_is_propagated() {
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
async fn test_request_id_invalid_value_is_replaced() {
    let app = test_app();
    let req = Request::builder()
        .uri("/healthz")
        .header("x-request-id", "has spaces and $pecial chars!")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();

    let id = resp.headers().get("x-request-id").unwrap().to_str().unwrap();
    assert_ne!(id, "has spaces and $pecial chars!");
    assert!(id.contains('-')); // UUID format
}

/// Error responses also include the x-request-id header.
#[tokio::test]
async fn test_request_id_present_on_error_responses() {
    let app = test_app();

    let resp = app.oneshot(json_get("/control/v1/nonexistent")).await.unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert!(
        resp.headers().get("x-request-id").is_some(),
        "error responses must include x-request-id"
    );
}

// -- Input Validation (email auth) --------------------------------------------

/// Invalid email formats are rejected with 400.
#[tokio::test]
async fn test_email_initiate_invalid_email_formats_return_400() {
    let cases: &[(&str, &str)] = &[
        ("not-an-email", "missing @ and domain"),
        ("test@exam\nple.com", "control characters"),
        (&format!("{}@example.com", "a".repeat(300)), "oversized local part"),
    ];

    for (email, label) in cases {
        let app = test_app();

        let resp = app
            .oneshot(json_post("/control/v1/auth/email/initiate", json!({"email": email})))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "case: {label}");
    }
}

#[tokio::test]
async fn test_email_initiate_invalid_email_returns_validation_error_code() {
    let app = test_app();

    let resp = app
        .oneshot(json_post("/control/v1/auth/email/initiate", json!({"email": "not-an-email"})))
        .await
        .unwrap();

    let json = body_json(resp).await;
    assert_eq!(json["code"], "VALIDATION_ERROR");
}

#[tokio::test]
async fn test_email_complete_invalid_name_returns_400() {
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
async fn test_email_complete_empty_org_name_returns_400() {
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

// -- Error Response Format ----------------------------------------------------

#[tokio::test]
async fn test_error_response_format_has_error_and_code_fields() {
    let app = test_app();

    let resp = app
        .oneshot(json_post("/control/v1/auth/email/initiate", json!({"email": "bad"})))
        .await
        .unwrap();

    let json = body_json(resp).await;
    assert!(json["error"].is_string(), "error field must be a string");
    assert!(json["code"].is_string(), "code field must be a string");
}

#[tokio::test]
async fn test_error_response_internal_details_are_scrubbed() {
    let app = test_app();

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
    let error_str = json["error"].as_str().unwrap();
    assert!(!error_str.contains("Ledger"), "internal details must not leak to client");
}

// -- 404 for Unknown Routes ---------------------------------------------------

#[tokio::test]
async fn test_router_unknown_route_returns_404() {
    let app = test_app();

    let resp = app.oneshot(json_get("/control/v1/nonexistent")).await.unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// -- Metrics Endpoint ---------------------------------------------------------

/// Metrics endpoint is accessible without authentication credentials.
/// Without the exporter initialized, it returns 500 (not 401/403).
#[tokio::test]
async fn test_metrics_endpoint_does_not_require_auth() {
    let app = test_app();

    let resp = app.oneshot(json_get("/metrics")).await.unwrap();

    let status = resp.status();
    assert_ne!(status, StatusCode::UNAUTHORIZED, "metrics should not require authentication");
    assert_ne!(status, StatusCode::FORBIDDEN, "metrics should not require authorization");
}

/// Metrics endpoint returns Prometheus text exposition format when exporter is initialized.
#[tokio::test]
async fn test_metrics_endpoint_returns_prometheus_content_type() {
    inferadb_control_api::handlers::init_exporter();
    let app = test_app();

    let resp = app.oneshot(json_get("/metrics")).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let content_type = resp
        .headers()
        .get("content-type")
        .expect("metrics response must have content-type header")
        .to_str()
        .unwrap();
    assert!(
        content_type.contains("text/plain"),
        "metrics content-type should be text/plain for Prometheus format, got: {content_type}"
    );
}

// -- CORS ---------------------------------------------------------------------

#[tokio::test]
async fn test_cors_preflight_returns_allowed_origin() {
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

// -- JSON Body Handling -------------------------------------------------------

/// Malformed or incomplete JSON bodies return 4xx errors.
#[tokio::test]
async fn test_json_body_malformed_returns_400() {
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

/// Missing required fields are rejected as client errors (400 or 422).
#[tokio::test]
async fn test_json_body_missing_required_fields_return_client_error() {
    let cases: &[(&str, &str)] = &[
        ("/control/v1/auth/email/initiate", "initiate without email"),
        ("/control/v1/auth/email/complete", "complete without any fields"),
    ];

    for (uri, label) in cases {
        let app = test_app();

        let resp = app.oneshot(json_post(uri, json!({}))).await.unwrap();

        let status = resp.status();
        assert!(
            status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY,
            "case '{label}': missing required field should be rejected (got {status})"
        );
    }
}
