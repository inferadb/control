#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Integration tests for health check endpoints.
//!
//! Tests `/livez`, `/readyz`, `/startupz`, and `/healthz` through the full
//! HTTP router without authentication (public endpoints).

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use inferadb_control_test_fixtures::{body_json, create_test_app, create_test_state};
use tower::ServiceExt;

#[tokio::test]
async fn test_livez_returns_200() {
    let state = create_test_state();
    let app = create_test_app(state);

    let response = app
        .clone()
        .oneshot(Request::builder().method("GET").uri("/livez").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK, "Livez should always return 200");
}

#[tokio::test]
async fn test_readyz_returns_200_with_healthy_storage() {
    let state = create_test_state();
    let app = create_test_app(state);

    let response = app
        .clone()
        .oneshot(Request::builder().method("GET").uri("/readyz").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Readyz should return 200 with in-memory storage"
    );
}

#[tokio::test]
async fn test_startupz_returns_200() {
    let state = create_test_state();
    let app = create_test_app(state);

    let response = app
        .clone()
        .oneshot(Request::builder().method("GET").uri("/startupz").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Startupz should return 200 (delegates to readyz)"
    );
}

#[tokio::test]
async fn test_healthz_returns_json_with_expected_fields() {
    let state = create_test_state();
    let app = create_test_app(state);

    let response = app
        .clone()
        .oneshot(Request::builder().method("GET").uri("/healthz").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let json = body_json(response).await;

    // Validate all required fields exist and have correct types
    assert_eq!(json["status"].as_str().unwrap(), "healthy");
    assert_eq!(json["service"].as_str().unwrap(), "inferadb-control");
    assert!(json["version"].as_str().is_some(), "Should have a version string");
    assert!(json["instance_id"].as_u64().is_some(), "Should have instance_id");
    assert!(json["uptime_seconds"].as_u64().is_some(), "Should have uptime_seconds");
    assert!(
        json["storage_healthy"].as_bool().unwrap(),
        "Storage should be healthy with in-memory backend"
    );
    // is_leader is false in tests (no leader election configured)
    assert!(json["is_leader"].is_boolean(), "is_leader should be a boolean");
}

#[tokio::test]
async fn test_healthz_does_not_require_authentication() {
    let state = create_test_state();
    let app = create_test_app(state);

    // No cookie header — should still succeed
    let response = app
        .clone()
        .oneshot(Request::builder().method("GET").uri("/healthz").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Health endpoints should not require authentication"
    );
}
