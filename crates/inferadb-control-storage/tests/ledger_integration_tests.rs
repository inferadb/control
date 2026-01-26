//! Integration tests for Ledger storage backend in Control
//!
//! These tests require a running Ledger server. They are skipped unless the
//! `RUN_LEDGER_INTEGRATION_TESTS` environment variable is set.
//!
//! Run with: cargo test --test ledger_integration_tests
//!
//! Or using Docker Compose:
//! ```bash
//! cd docker/ledger-integration-tests && ./run-tests.sh
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    env,
    ops::Bound,
    sync::atomic::{AtomicI64, Ordering},
    time::Duration,
};

use bytes::Bytes;
use inferadb_control_storage::backend::StorageBackend;
use inferadb_storage_ledger::{LedgerBackend, LedgerBackendConfig};
use tokio::time::sleep;

// ============================================================================
// Test Configuration
// ============================================================================

static VAULT_COUNTER: AtomicI64 = AtomicI64::new(30000);

fn should_run() -> bool {
    env::var("RUN_LEDGER_INTEGRATION_TESTS").is_ok()
}

fn ledger_endpoint() -> String {
    env::var("LEDGER_ENDPOINT").unwrap_or_else(|_| "http://localhost:50051".to_string())
}

fn ledger_namespace_id() -> i64 {
    env::var("LEDGER_NAMESPACE_ID").ok().and_then(|s| s.parse().ok()).unwrap_or(1)
}

fn unique_vault_id() -> i64 {
    VAULT_COUNTER.fetch_add(1, Ordering::SeqCst)
}

async fn create_ledger_backend() -> LedgerBackend {
    let vault_id = unique_vault_id();
    let config = LedgerBackendConfig::builder()
        .endpoints(vec![ledger_endpoint()])
        .client_id(format!("control-test-{vault_id}"))
        .namespace_id(ledger_namespace_id())
        .vault_id(vault_id)
        .build()
        .expect("valid config");

    LedgerBackend::new(config).await.expect("backend creation should succeed")
}

// ============================================================================
// Basic Operations Tests
// ============================================================================

#[tokio::test]
async fn test_ledger_basic_operations() {
    if !should_run() {
        eprintln!("Skipping Ledger integration test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let backend = create_ledger_backend().await;

    // Test set and get
    backend
        .set(b"control_test_key".to_vec(), b"test_value".to_vec())
        .await
        .expect("Failed to set value");

    let value = backend.get(b"control_test_key").await.expect("Failed to get value");

    assert_eq!(value, Some(Bytes::from("test_value")));

    // Test delete
    backend.delete(b"control_test_key").await.expect("Failed to delete");

    let value = backend.get(b"control_test_key").await.expect("Failed to get after delete");

    assert_eq!(value, None);
}

#[tokio::test]
async fn test_ledger_range_operations() {
    if !should_run() {
        eprintln!("Skipping Ledger integration test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let backend = create_ledger_backend().await;

    // Insert test data
    for i in 0..10 {
        let key = format!("ctrl_range_test_{i:02}");
        let value = format!("value_{i}");
        backend
            .set(key.as_bytes().to_vec(), value.as_bytes().to_vec())
            .await
            .expect("Failed to set value");
    }

    // Test range query
    let start = b"ctrl_range_test_00".to_vec();
    let end = b"ctrl_range_test_05".to_vec();
    let range = (Bound::Included(start.clone()), Bound::Excluded(end));

    let results = backend.get_range(range).await.expect("Failed to get range");

    assert_eq!(results.len(), 5, "Expected 5 results in range");

    // Verify results are in order
    for (i, kv) in results.iter().enumerate() {
        let expected_key = format!("ctrl_range_test_{i:02}");
        let expected_value = format!("value_{i}");
        assert_eq!(kv.key.as_ref(), expected_key.as_bytes());
        assert_eq!(kv.value.as_ref(), expected_value.as_bytes());
    }

    // Clean up
    let start = b"ctrl_range_test_00".to_vec();
    let end = b"ctrl_range_test_~~".to_vec();
    let range = (Bound::Included(start), Bound::Excluded(end));
    backend.clear_range(range).await.expect("Failed to clear range");
}

#[tokio::test]
async fn test_ledger_ttl_expiration() {
    if !should_run() {
        eprintln!("Skipping Ledger integration test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let backend = create_ledger_backend().await;

    // Set a key with 2 second TTL
    backend
        .set_with_ttl(b"ctrl_ttl_test".to_vec(), b"expiring_value".to_vec(), 2)
        .await
        .expect("Failed to set with TTL");

    // Verify key exists
    let value = backend.get(b"ctrl_ttl_test").await.expect("Failed to get TTL value");

    assert_eq!(value, Some(Bytes::from("expiring_value")));

    // Wait for expiration
    sleep(Duration::from_secs(3)).await;

    // Verify key is gone
    let value = backend.get(b"ctrl_ttl_test").await.expect("Failed to get expired value");

    assert_eq!(value, None);
}

#[tokio::test]
async fn test_ledger_transaction() {
    if !should_run() {
        eprintln!("Skipping Ledger integration test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let backend = create_ledger_backend().await;

    // Start a transaction
    let mut txn = backend.transaction().await.expect("Failed to create transaction");

    // Buffer some writes
    txn.set(b"ctrl_txn_key1".to_vec(), b"value1".to_vec());
    txn.set(b"ctrl_txn_key2".to_vec(), b"value2".to_vec());

    // Read-your-writes
    let val = txn.get(b"ctrl_txn_key1").await.expect("Failed to get from txn");
    assert_eq!(val, Some(Bytes::from("value1")));

    // Commit
    txn.commit().await.expect("Failed to commit");

    // Verify after commit
    assert_eq!(backend.get(b"ctrl_txn_key1").await.unwrap(), Some(Bytes::from("value1")));
    assert_eq!(backend.get(b"ctrl_txn_key2").await.unwrap(), Some(Bytes::from("value2")));
}

#[tokio::test]
async fn test_ledger_transaction_delete() {
    if !should_run() {
        eprintln!("Skipping Ledger integration test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let backend = create_ledger_backend().await;

    // Pre-populate
    backend.set(b"ctrl_txn_del".to_vec(), b"to_delete".to_vec()).await.unwrap();

    // Delete in transaction
    let mut txn = backend.transaction().await.unwrap();
    txn.delete(b"ctrl_txn_del".to_vec());

    // Read-your-writes: should see None
    assert_eq!(txn.get(b"ctrl_txn_del").await.unwrap(), None);

    txn.commit().await.unwrap();

    // Verify deleted
    assert_eq!(backend.get(b"ctrl_txn_del").await.unwrap(), None);
}

#[tokio::test]
async fn test_ledger_health_check() {
    if !should_run() {
        eprintln!("Skipping Ledger integration test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let backend = create_ledger_backend().await;

    let result = backend.health_check().await;
    assert!(result.is_ok(), "Health check should succeed");
}

// ============================================================================
// Concurrent Operations Tests
// ============================================================================

#[tokio::test]
async fn test_ledger_concurrent_writes() {
    if !should_run() {
        eprintln!("Skipping Ledger integration test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    // Spawn concurrent writers (each gets its own backend with unique vault)
    let mut handles = Vec::new();
    for i in 0..10 {
        let vault_id = unique_vault_id();
        let config = LedgerBackendConfig::builder()
            .endpoints(vec![ledger_endpoint()])
            .client_id(format!("concurrent-test-{vault_id}"))
            .namespace_id(ledger_namespace_id())
            .vault_id(vault_id)
            .build()
            .expect("valid config");

        handles.push(tokio::spawn(async move {
            let backend = LedgerBackend::new(config).await.expect("backend");
            let key = format!("ctrl_concurrent_{i}");
            let value = format!("value_{i}");
            backend.set(key.into_bytes(), value.into_bytes()).await
        }));
    }

    // Wait for all to complete
    for handle in handles {
        handle.await.expect("task should succeed").expect("write should succeed");
    }
}

// ============================================================================
// Vault Isolation Tests
// ============================================================================

#[tokio::test]
async fn test_ledger_vault_isolation() {
    if !should_run() {
        eprintln!("Skipping Ledger integration test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let vault_a = unique_vault_id();
    let vault_b = unique_vault_id();

    let config_a = LedgerBackendConfig::builder()
        .endpoints(vec![ledger_endpoint()])
        .client_id(format!("vault-a-{vault_a}"))
        .namespace_id(ledger_namespace_id())
        .vault_id(vault_a)
        .build()
        .unwrap();

    let config_b = LedgerBackendConfig::builder()
        .endpoints(vec![ledger_endpoint()])
        .client_id(format!("vault-b-{vault_b}"))
        .namespace_id(ledger_namespace_id())
        .vault_id(vault_b)
        .build()
        .unwrap();

    let backend_a = LedgerBackend::new(config_a).await.unwrap();
    let backend_b = LedgerBackend::new(config_b).await.unwrap();

    // Write to vault A
    backend_a.set(b"ctrl_shared_key".to_vec(), b"vault_a_value".to_vec()).await.unwrap();

    // Should NOT be visible in vault B
    assert_eq!(backend_b.get(b"ctrl_shared_key").await.unwrap(), None);

    // Write to vault B
    backend_b.set(b"ctrl_shared_key".to_vec(), b"vault_b_value".to_vec()).await.unwrap();

    // Each vault sees its own value
    assert_eq!(
        backend_a.get(b"ctrl_shared_key").await.unwrap(),
        Some(Bytes::from("vault_a_value"))
    );
    assert_eq!(
        backend_b.get(b"ctrl_shared_key").await.unwrap(),
        Some(Bytes::from("vault_b_value"))
    );
}

// ============================================================================
// Reconnection Tests
// ============================================================================

#[tokio::test]
async fn test_ledger_reconnection_after_idle() {
    if !should_run() {
        eprintln!("Skipping Ledger integration test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let backend = create_ledger_backend().await;

    // First operation
    backend
        .set(b"ctrl_reconnect_key".to_vec(), b"value1".to_vec())
        .await
        .expect("first set should succeed");

    // Simulate idle period
    sleep(Duration::from_secs(5)).await;

    // Should reconnect automatically
    let result = backend.get(b"ctrl_reconnect_key").await.expect("get after idle should succeed");

    assert_eq!(result, Some(Bytes::from("value1")));
}
