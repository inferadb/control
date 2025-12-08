//! Integration tests for FoundationDB backend
//!
//! These tests require a running FoundationDB cluster.
//! Run with: cargo test --test fdb_integration_tests --features fdb

#![cfg(feature = "fdb")]

use std::{env, ops::Bound, time::Duration};

use bytes::Bytes;
use inferadb_control_storage::{FdbBackend, backend::StorageBackend};
use tokio::time::sleep;

/// Helper to create an FDB backend from environment variables
async fn create_fdb_backend() -> FdbBackend {
    let cluster_file = env::var("FDB_CLUSTER_FILE").ok();
    FdbBackend::with_cluster_file(cluster_file).await.expect("Failed to create FDB backend")
}

#[tokio::test]
async fn test_fdb_basic_operations() {
    let backend = create_fdb_backend().await;

    // Test set and get
    backend.set(b"test_key".to_vec(), b"test_value".to_vec()).await.expect("Failed to set value");

    let value = backend.get(b"test_key").await.expect("Failed to get value");

    assert_eq!(value, Some(Bytes::from("test_value")));

    // Test delete
    backend.delete(b"test_key").await.expect("Failed to delete");

    let value = backend.get(b"test_key").await.expect("Failed to get after delete");

    assert_eq!(value, None);
}

#[tokio::test]
async fn test_fdb_range_operations() {
    let backend = create_fdb_backend().await;

    // Insert test data
    for i in 0..10 {
        let key = format!("range_test_{:02}", i);
        let value = format!("value_{}", i);
        backend
            .set(key.as_bytes().to_vec(), value.as_bytes().to_vec())
            .await
            .expect("Failed to set value");
    }

    // Test range query
    let start = b"range_test_00".to_vec();
    let end = b"range_test_05".to_vec();
    let range = (Bound::Included(start), Bound::Excluded(end));

    let results = backend.get_range(range).await.expect("Failed to get range");

    assert_eq!(results.len(), 5);

    // Verify results are in order
    for (i, kv) in results.iter().enumerate() {
        let expected_key = format!("range_test_{:02}", i);
        let expected_value = format!("value_{}", i);
        assert_eq!(kv.key.as_ref(), expected_key.as_bytes());
        assert_eq!(kv.value.as_ref(), expected_value.as_bytes());
    }

    // Clean up
    let start = b"range_test_00".to_vec();
    let end = b"range_test_10".to_vec();
    let range = (Bound::Included(start), Bound::Excluded(end));
    backend.clear_range(range).await.expect("Failed to clear range");
}

#[tokio::test]
async fn test_fdb_ttl_expiration() {
    let backend = create_fdb_backend().await;

    // Set a key with 2 second TTL
    backend
        .set_with_ttl(b"ttl_test".to_vec(), b"expiring_value".to_vec(), 2)
        .await
        .expect("Failed to set with TTL");

    // Verify key exists
    let value = backend.get(b"ttl_test").await.expect("Failed to get TTL value");

    assert_eq!(value, Some(Bytes::from("expiring_value")));

    // Wait for expiration (2s TTL + 1s cleanup interval + 1s buffer)
    sleep(Duration::from_secs(4)).await;

    // Verify key is gone
    let value = backend.get(b"ttl_test").await.expect("Failed to get expired value");

    assert_eq!(value, None);
}

#[tokio::test]
async fn test_fdb_transaction_commit() {
    let backend = create_fdb_backend().await;

    // Create a transaction
    let mut txn = backend.transaction().await.expect("Failed to create transaction");

    // Perform writes
    txn.set(b"txn_key1".to_vec(), b"txn_value1".to_vec());
    txn.set(b"txn_key2".to_vec(), b"txn_value2".to_vec());
    txn.set(b"txn_key3".to_vec(), b"txn_value3".to_vec());

    // Verify reads within transaction see pending writes
    let value = txn.get(b"txn_key1").await.expect("Failed to get within transaction");

    assert_eq!(value, Some(Bytes::from("txn_value1")));

    // Commit transaction
    txn.commit().await.expect("Failed to commit transaction");

    // Verify values are persisted
    let value = backend.get(b"txn_key1").await.expect("Failed to get committed value");

    assert_eq!(value, Some(Bytes::from("txn_value1")));

    let value = backend.get(b"txn_key2").await.expect("Failed to get committed value");

    assert_eq!(value, Some(Bytes::from("txn_value2")));

    // Clean up
    backend.delete(b"txn_key1").await.unwrap();
    backend.delete(b"txn_key2").await.unwrap();
    backend.delete(b"txn_key3").await.unwrap();
}

#[tokio::test]
async fn test_fdb_transaction_rollback() {
    let backend = create_fdb_backend().await;

    // Set initial value
    backend
        .set(b"rollback_key".to_vec(), b"initial_value".to_vec())
        .await
        .expect("Failed to set initial value");

    // Create a transaction
    let mut txn = backend.transaction().await.expect("Failed to create transaction");

    // Modify value in transaction
    txn.set(b"rollback_key".to_vec(), b"modified_value".to_vec());

    // Verify transaction sees modified value
    let value = txn.get(b"rollback_key").await.expect("Failed to get within transaction");

    assert_eq!(value, Some(Bytes::from("modified_value")));

    // Drop transaction without commit (implicit rollback)
    drop(txn);

    // Verify original value is unchanged
    let value = backend.get(b"rollback_key").await.expect("Failed to get after rollback");

    assert_eq!(value, Some(Bytes::from("initial_value")));

    // Clean up
    backend.delete(b"rollback_key").await.unwrap();
}

#[tokio::test]
async fn test_fdb_transaction_delete() {
    let backend = create_fdb_backend().await;

    // Set initial values
    backend.set(b"delete_key1".to_vec(), b"value1".to_vec()).await.expect("Failed to set value");

    backend.set(b"delete_key2".to_vec(), b"value2".to_vec()).await.expect("Failed to set value");

    // Create a transaction and delete a key
    let mut txn = backend.transaction().await.expect("Failed to create transaction");

    txn.delete(b"delete_key1".to_vec());

    // Verify deletion within transaction
    let value = txn.get(b"delete_key1").await.expect("Failed to get within transaction");

    assert_eq!(value, None);

    // Commit transaction
    txn.commit().await.expect("Failed to commit transaction");

    // Verify deletion is persisted
    let value = backend.get(b"delete_key1").await.expect("Failed to get after delete");

    assert_eq!(value, None);

    // Verify other key is unaffected
    let value = backend.get(b"delete_key2").await.expect("Failed to get unaffected key");

    assert_eq!(value, Some(Bytes::from("value2")));

    // Clean up
    backend.delete(b"delete_key2").await.unwrap();
}

#[tokio::test]
async fn test_fdb_concurrent_transactions() {
    let backend = create_fdb_backend().await;

    // Set initial counter
    backend.set(b"counter".to_vec(), b"0".to_vec()).await.expect("Failed to set counter");

    // Spawn multiple tasks to increment counter
    let mut handles = vec![];
    for i in 0..10 {
        let backend_clone = backend.clone();
        let handle = tokio::spawn(async move {
            let mut txn = backend_clone.transaction().await.expect("Failed to create transaction");

            // Read current value
            let current = txn.get(b"counter").await.expect("Failed to get counter");

            let current_val: i32 =
                String::from_utf8_lossy(current.as_ref().unwrap()).parse().unwrap();

            // Increment
            let new_val = current_val + 1;
            txn.set(b"counter".to_vec(), new_val.to_string().as_bytes().to_vec());

            // Commit
            txn.commit().await.expect("Failed to commit");

            i
        });
        handles.push(handle);
    }

    // Wait for all tasks
    for handle in handles {
        handle.await.unwrap();
    }

    // Verify final counter value
    let final_value = backend.get(b"counter").await.expect("Failed to get final counter");

    let final_val: i32 = String::from_utf8_lossy(final_value.as_ref().unwrap()).parse().unwrap();

    // All increments should have been applied
    assert_eq!(final_val, 10);

    // Clean up
    backend.delete(b"counter").await.unwrap();
}

#[tokio::test]
async fn test_fdb_health_check() {
    let backend = create_fdb_backend().await;

    // Health check should succeed
    backend.health_check().await.expect("Health check should succeed");
}

#[tokio::test]
async fn test_fdb_large_value() {
    let backend = create_fdb_backend().await;

    // Create a large value (10KB)
    let large_value: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();

    backend
        .set(b"large_key".to_vec(), large_value.clone())
        .await
        .expect("Failed to set large value");

    let retrieved = backend.get(b"large_key").await.expect("Failed to get large value");

    assert_eq!(retrieved, Some(Bytes::from(large_value)));

    // Clean up
    backend.delete(b"large_key").await.unwrap();
}

#[tokio::test]
async fn test_fdb_empty_value() {
    let backend = create_fdb_backend().await;

    // Set empty value
    backend.set(b"empty_key".to_vec(), vec![]).await.expect("Failed to set empty value");

    let value = backend.get(b"empty_key").await.expect("Failed to get empty value");

    assert_eq!(value, Some(Bytes::from(vec![])));

    // Clean up
    backend.delete(b"empty_key").await.unwrap();
}

#[tokio::test]
async fn test_fdb_binary_keys_and_values() {
    let backend = create_fdb_backend().await;

    // Test with binary data containing null bytes
    let binary_key: Vec<u8> = vec![0xFF, 0x00, 0xAB, 0xCD, 0x00, 0x12];
    let binary_value: Vec<u8> = vec![0x00, 0x11, 0x22, 0x33, 0x00, 0xFF];

    backend.set(binary_key.clone(), binary_value.clone()).await.expect("Failed to set binary data");

    let value = backend.get(&binary_key).await.expect("Failed to get binary data");

    assert_eq!(value, Some(Bytes::from(binary_value)));

    // Clean up
    backend.delete(&binary_key).await.unwrap();
}
