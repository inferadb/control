use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use inferadb_control_core::{
    IdGenerator,
    entities::{AuditEventType, AuditLog, AuditResourceType},
    repository::AuditLogRepository,
};
use inferadb_control_test_fixtures::{create_test_app, create_test_state, register_user};
use tower::ServiceExt;

#[tokio::test]
async fn test_audit_log_creation() {
    let _ = IdGenerator::init(300);
    let state = create_test_state();

    // Create an audit log directly
    let repo = AuditLogRepository::new((*state.storage).clone());
    let log = AuditLog::new(AuditEventType::UserLogin, Some(1), Some(100))
        .with_resource(AuditResourceType::User, 100)
        .with_ip_address("127.0.0.1")
        .with_user_agent("test-agent");

    // Create the log
    repo.create(log.clone()).await.unwrap();

    // Retrieve and verify
    let retrieved = repo.get(log.id).await.unwrap();
    assert!(retrieved.is_some());
    let retrieved = retrieved.unwrap();

    assert_eq!(retrieved.id, log.id);
    assert_eq!(retrieved.organization_id, Some(1));
    assert_eq!(retrieved.user_id, Some(100));
    assert_eq!(retrieved.event_type, AuditEventType::UserLogin);
    assert_eq!(retrieved.resource_type, Some(AuditResourceType::User));
    assert_eq!(retrieved.resource_id, Some(100));
    assert_eq!(retrieved.ip_address, Some("127.0.0.1".to_string()));
    assert_eq!(retrieved.user_agent, Some("test-agent".to_string()));
}

#[tokio::test]
async fn test_audit_log_list_by_organization() {
    let _ = IdGenerator::init(301);
    let state = create_test_state();
    let repo = AuditLogRepository::new((*state.storage).clone());

    // Create multiple audit logs for different organizations
    for i in 0..10 {
        let log = AuditLog::new(
            AuditEventType::UserLogin,
            Some(1), // All for org 1
            Some(100 + i),
        )
        .with_resource(AuditResourceType::User, 100 + i);
        repo.create(log).await.unwrap();
    }

    // Create logs for another organization
    for i in 0..5 {
        let log = AuditLog::new(
            AuditEventType::UserLogin,
            Some(2), // Org 2
            Some(200 + i),
        )
        .with_resource(AuditResourceType::User, 200 + i);
        repo.create(log).await.unwrap();
    }

    // List logs for organization 1
    let filters = inferadb_control_core::AuditLogFilters::default();
    let (logs, total) = repo.list_by_organization(1, filters, 50, 0).await.unwrap();

    assert_eq!(total, 10);
    assert_eq!(logs.len(), 10);

    // Verify all logs are for org 1
    for log in &logs {
        assert_eq!(log.organization_id, Some(1));
    }
}

#[tokio::test]
async fn test_audit_log_filtering() {
    let _ = IdGenerator::init(302);
    let state = create_test_state();
    let repo = AuditLogRepository::new((*state.storage).clone());

    // Create logs with different event types
    let log1 = AuditLog::new(AuditEventType::UserLogin, Some(1), Some(100))
        .with_resource(AuditResourceType::User, 100);
    repo.create(log1).await.unwrap();

    let log2 = AuditLog::new(AuditEventType::UserLogout, Some(1), Some(100))
        .with_resource(AuditResourceType::User, 100);
    repo.create(log2).await.unwrap();

    let log3 = AuditLog::new(AuditEventType::VaultCreated, Some(1), Some(100))
        .with_resource(AuditResourceType::Vault, 200);
    repo.create(log3).await.unwrap();

    // Filter by event type
    let filters = inferadb_control_core::AuditLogFilters {
        action: Some(AuditEventType::UserLogin),
        ..Default::default()
    };
    let (logs, total) = repo.list_by_organization(1, filters, 50, 0).await.unwrap();

    assert_eq!(total, 1);
    assert_eq!(logs[0].event_type, AuditEventType::UserLogin);

    // Filter by resource type
    let filters = inferadb_control_core::AuditLogFilters {
        resource_type: Some(AuditResourceType::Vault),
        ..Default::default()
    };
    let (logs, total) = repo.list_by_organization(1, filters, 50, 0).await.unwrap();

    assert_eq!(total, 1);
    assert_eq!(logs[0].resource_type, Some(AuditResourceType::Vault));
}

#[tokio::test]
async fn test_audit_log_pagination() {
    let _ = IdGenerator::init(303);
    let state = create_test_state();
    let repo = AuditLogRepository::new((*state.storage).clone());

    // Create 25 audit logs
    for i in 0..25 {
        let log = AuditLog::new(AuditEventType::UserLogin, Some(1), Some(100 + i))
            .with_resource(AuditResourceType::User, 100 + i);
        repo.create(log).await.unwrap();
    }

    // Get first page (10 items)
    let filters = inferadb_control_core::AuditLogFilters::default();
    let (logs, total) = repo.list_by_organization(1, filters.clone(), 10, 0).await.unwrap();

    assert_eq!(total, 25);
    assert_eq!(logs.len(), 10);

    // Get second page
    let (logs, total) = repo.list_by_organization(1, filters.clone(), 10, 10).await.unwrap();

    assert_eq!(total, 25);
    assert_eq!(logs.len(), 10);

    // Get third page
    let (logs, total) = repo.list_by_organization(1, filters, 10, 20).await.unwrap();

    assert_eq!(total, 25);
    assert_eq!(logs.len(), 5);
}

#[tokio::test]
async fn test_audit_log_query_endpoint() {
    let _ = IdGenerator::init(304);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    // Register user and get session
    let session = register_user(&app, "owner", "owner@example.com", "securepassword123").await;

    // Get organization ID
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/organizations")
                .header("cookie", format!("infera_session={}", session))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let org_id = json["organizations"][0]["id"].as_i64().unwrap();

    // Create some audit logs for this organization
    let repo = AuditLogRepository::new((*state.storage).clone());
    for i in 0..5 {
        let log = AuditLog::new(AuditEventType::UserLogin, Some(org_id), Some(100 + i))
            .with_resource(AuditResourceType::User, 100 + i);
        repo.create(log).await.unwrap();
    }

    // Query audit logs via API
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/organizations/{}/audit-logs", org_id))
                .header("cookie", format!("infera_session={}", session))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Verify response structure
    assert!(json["audit_logs"].is_array());
    assert!(json["total"].as_i64().unwrap() >= 5);
    assert!(json["limit"].is_i64());
    assert!(json["offset"].is_i64());
}

#[tokio::test]
async fn test_audit_log_retention_cleanup() {
    use chrono::Duration;

    let _ = IdGenerator::init(305);
    let state = create_test_state();
    let repo = AuditLogRepository::new((*state.storage).clone());

    // Create old audit logs (older than 90 days)
    let old_date = chrono::Utc::now() - Duration::days(100);
    for i in 0..5 {
        let mut log = AuditLog::new(AuditEventType::UserLogin, Some(1), Some(100 + i))
            .with_resource(AuditResourceType::User, 100 + i);
        // Manually set the created_at to old date
        log.created_at = old_date;
        repo.create(log).await.unwrap();
    }

    // Create recent audit logs (within 90 days)
    for i in 0..5 {
        let log = AuditLog::new(AuditEventType::UserLogout, Some(1), Some(200 + i))
            .with_resource(AuditResourceType::User, 200 + i);
        repo.create(log).await.unwrap();
    }

    // Verify we have 10 logs total
    let filters = inferadb_control_core::AuditLogFilters::default();
    let (_logs, total) = repo.list_by_organization(1, filters.clone(), 50, 0).await.unwrap();
    assert_eq!(total, 10);

    // Run retention cleanup (90-day cutoff)
    let cutoff_date = chrono::Utc::now() - Duration::days(90);
    let deleted = repo.delete_older_than(cutoff_date).await.unwrap();

    // Should have deleted 5 old logs
    assert_eq!(deleted, 5);

    // Verify only 5 logs remain
    let (logs, total) = repo.list_by_organization(1, filters, 50, 0).await.unwrap();
    assert_eq!(total, 5);

    // Verify remaining logs are all recent (UserLogout events)
    for log in logs {
        assert_eq!(log.event_type, AuditEventType::UserLogout);
    }
}
