#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::{
    Extension, Router,
    body::Body,
    extract::Path,
    http::{Request, StatusCode},
    middleware,
    response::IntoResponse,
    routing::get,
};
use inferadb_control_api::middleware::{
    OrganizationContext, require_organization_member, require_session,
};
use inferadb_control_core::IdGenerator;
use inferadb_control_test_fixtures::{
    create_test_app, create_test_state, get_org_id, register_user,
};
use serde_json::json;
use tower::ServiceExt;

/// Helper: register user, get session and org_id
async fn setup_user_and_org(app: &Router, seed: i32) -> (String, i64) {
    let session = register_user(
        app,
        &format!("mwuser{seed}"),
        &format!("mw{seed}@example.com"),
        "securepassword123",
    )
    .await;

    let org_id = get_org_id(app, &session).await;

    (session, org_id)
}

/// Verify organization middleware correctly extracts {org} from standard route structure.
///
/// This tests that after switching from hardcoded segment[4] indexing to axum's
/// Path parameter extraction, the middleware still works with the production routes.
#[tokio::test]
async fn test_org_middleware_extracts_id_from_standard_routes() {
    let _ = IdGenerator::init(40);
    let state = create_test_state();
    let app = create_test_app(state);

    let (session, org_id) = setup_user_and_org(&app, 1).await;

    // GET /control/v1/organizations/{org} — standard org-scoped route
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/control/v1/organizations/{org_id}"))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["organization"]["id"], org_id);
}

/// Verify vault middleware correctly extracts {vault} from nested route structure.
///
/// Routes like /control/v1/organizations/{org}/vaults/{vault}/user-grants test that
/// the vault middleware extracts the vault ID from the {vault} path param, not from
/// a hardcoded segment index.
#[tokio::test]
async fn test_vault_middleware_extracts_id_from_nested_routes() {
    let _ = IdGenerator::init(41);
    let state = create_test_state();
    let app = create_test_app(state);

    let (session, org_id) = setup_user_and_org(&app, 2).await;

    // Create a vault
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/vaults"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "mw-test-vault",
                        "description": "Middleware test vault"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let create_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let vault_id = create_json["vault"]["id"].as_i64().expect("Should have vault ID");

    // GET /control/v1/organizations/{org}/vaults/{vault} — both middleware layers extract IDs
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/control/v1/organizations/{org_id}/vaults/{vault_id}"))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["id"], vault_id);
    assert_eq!(json["name"], "mw-test-vault");
}

/// Verify organization middleware works when routes are nested under a different prefix.
///
/// This is the critical decoupling test: instead of `/control/v1/organizations/{org}`,
/// we mount a custom route at `/api/v2/orgs/{org}/info` and verify the middleware
/// still extracts the org ID correctly from the `{org}` path parameter.
#[tokio::test]
async fn test_org_middleware_works_with_different_route_prefix() {
    let _ = IdGenerator::init(42);
    let state = create_test_state();

    // Register a user and org through the standard app
    let standard_app = create_test_app(state.clone());
    let (session, org_id) = setup_user_and_org(&standard_app, 3).await;

    // Build a custom router with a completely different prefix structure.
    // The old hardcoded approach (segments[4]) would fail here because
    // /api/v2/orgs/{org}/info has {org} at segment[3], not segment[4].
    async fn org_info_handler(
        Extension(org_ctx): Extension<OrganizationContext>,
    ) -> impl IntoResponse {
        axum::Json(json!({
            "org_id": org_ctx.organization_id,
            "role": format!("{:?}", org_ctx.member.role),
        }))
    }

    let custom_app = Router::new()
        .route("/api/v2/orgs/{org}/info", get(org_info_handler))
        .with_state(state.clone())
        .route_layer(middleware::from_fn_with_state(state.clone(), require_organization_member))
        .route_layer(middleware::from_fn_with_state(state, require_session));

    let response = custom_app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v2/orgs/{org_id}/info"))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["org_id"], org_id);
}

/// Verify vault middleware works when routes use a different path structure.
///
/// Mount a custom route at `/v3/{org}/v/{vault}/check` — both parameters are at
/// different segment positions than the standard routes.
#[tokio::test]
async fn test_vault_middleware_works_with_different_route_structure() {
    let _ = IdGenerator::init(43);
    let state = create_test_state();

    let standard_app = create_test_app(state.clone());
    let (session, org_id) = setup_user_and_org(&standard_app, 4).await;

    // Create a vault through the standard app
    let response = standard_app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/vaults"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "custom-vault",
                        "description": "Test"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let create_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let vault_id = create_json["vault"]["id"].as_i64().expect("Should have vault ID");

    // Custom route with completely different structure
    async fn vault_check_handler(
        Extension(org_ctx): Extension<OrganizationContext>,
        Path((_org, vault_id)): Path<(i64, i64)>,
    ) -> impl IntoResponse {
        axum::Json(json!({
            "org_id": org_ctx.organization_id,
            "vault_id": vault_id,
        }))
    }

    let custom_app = Router::new()
        .route("/v3/{org}/v/{vault}/check", get(vault_check_handler))
        .with_state(state.clone())
        .route_layer(middleware::from_fn_with_state(state.clone(), require_organization_member))
        .route_layer(middleware::from_fn_with_state(state, require_session));

    let response = custom_app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v3/{org_id}/v/{vault_id}/check"))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["org_id"], org_id);
    assert_eq!(json["vault_id"], vault_id);
}
