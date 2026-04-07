//! Snowflake ID generation.
//!
//! Provides a globally initialized [`IdGenerator`] that produces unique,
//! time-ordered 64-bit IDs using a custom epoch (2024-01-01) and configurable
//! worker ID for multi-instance deployments.

use std::sync::OnceLock;

use idgenerator::IdGeneratorOptions;
use inferadb_control_types::error::{Error, Result};

/// Custom epoch for Snowflake IDs: 2024-01-01T00:00:00Z (in milliseconds).
const CUSTOM_EPOCH: i64 = 1704067200000;

static WORKER_ID: OnceLock<u16> = OnceLock::new();

/// Snowflake ID generator with custom epoch and worker ID management.
pub struct IdGenerator;

impl IdGenerator {
    /// Initializes the global ID generator with the specified worker ID.
    ///
    /// This must be called once at application startup before generating any IDs.
    ///
    /// # Arguments
    ///
    /// * `worker_id` - Worker ID (0-1023) for this instance
    ///
    /// # Errors
    ///
    /// Returns an error if `worker_id` is out of range or initialization fails.
    pub fn init(worker_id: u16) -> Result<()> {
        if worker_id > 1023 {
            return Err(Error::config(format!(
                "Worker ID must be between 0 and 1023, got {worker_id}"
            )));
        }

        WORKER_ID.get_or_init(|| {
            let options = IdGeneratorOptions::new()
                .worker_id(worker_id.into())
                .worker_id_bit_len(10)
                .base_time(CUSTOM_EPOCH);

            // Initialization failure at startup is unrecoverable - panic is appropriate
            #[allow(clippy::expect_used)]
            idgenerator::IdInstance::init(options).expect("Failed to initialize ID generator");
            worker_id
        });

        Ok(())
    }

    /// Generates a new unique 64-bit Snowflake ID.
    ///
    /// # Panics
    ///
    /// Panics if `init()` has not been called first.
    pub fn next_id() -> u64 {
        idgenerator::IdInstance::next_id() as u64
    }

    /// Returns the worker ID for this generator.
    ///
    /// Returns 0 if the generator has not been initialized.
    pub fn worker_id() -> u16 {
        WORKER_ID.get().copied().unwrap_or(0)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    // Note: IdGenerator uses OnceLock, so init() only takes effect once per process.
    // All tests share the same global state. We call init() defensively but cannot
    // test re-initialization or worker_id changes.

    #[test]
    fn test_init_valid_worker_id_succeeds() {
        let result = IdGenerator::init(0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_init_worker_id_above_1023_returns_error() {
        let err = IdGenerator::init(1024).unwrap_err();
        assert!(err.to_string().contains("1024"));
        assert!(err.to_string().contains("0 and 1023"));
    }

    #[test]
    fn test_init_worker_id_at_max_boundary_succeeds() {
        // 1023 is the maximum valid worker ID (10-bit)
        let result = IdGenerator::init(1023);
        assert!(result.is_ok());
    }

    #[test]
    fn test_next_id_returns_positive_value() {
        let _ = IdGenerator::init(0);

        let id = IdGenerator::next_id();

        assert!(id > 0);
    }

    #[test]
    fn test_next_id_sequential_calls_produce_unique_ids() {
        let _ = IdGenerator::init(0);

        let id1 = IdGenerator::next_id();
        let id2 = IdGenerator::next_id();

        assert_ne!(id1, id2);
    }

    #[test]
    fn test_next_id_sequential_calls_are_strictly_increasing() {
        let _ = IdGenerator::init(0);

        let id1 = IdGenerator::next_id();
        let id2 = IdGenerator::next_id();
        let id3 = IdGenerator::next_id();

        assert!(id2 > id1);
        assert!(id3 > id2);
    }

    #[test]
    fn test_next_id_bulk_generation_produces_no_duplicates() {
        let _ = IdGenerator::init(1);
        let mut ids = HashSet::new();

        for _ in 0..1000 {
            let id = IdGenerator::next_id();
            assert!(ids.insert(id), "Duplicate ID generated: {id}");
        }
    }

    #[test]
    fn test_worker_id_returns_initialized_value() {
        let _ = IdGenerator::init(0);

        // Due to OnceLock, worker_id returns whichever value was set first
        let wid = IdGenerator::worker_id();
        assert!(wid <= 1023);
    }

    mod proptest_id {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            #[test]
            fn ids_are_strictly_increasing(n in 2usize..100) {
                let _ = IdGenerator::init(999);
                let ids: Vec<u64> = (0..n).map(|_| IdGenerator::next_id()).collect();
                for window in ids.windows(2) {
                    prop_assert!(window[1] > window[0], "IDs must be strictly increasing: {} > {}", window[1], window[0]);
                }
            }

            #[test]
            fn ids_are_unique(n in 2usize..100) {
                let _ = IdGenerator::init(998);
                let ids: Vec<u64> = (0..n).map(|_| IdGenerator::next_id()).collect();
                let unique: HashSet<u64> = ids.iter().copied().collect();
                prop_assert_eq!(ids.len(), unique.len(), "All generated IDs must be unique");
            }

            #[test]
            fn ids_are_positive(_seed in 0u16..1000) {
                let _ = IdGenerator::init(997);
                let id = IdGenerator::next_id();
                prop_assert!(id > 0, "Generated IDs must be positive: {}", id);
            }
        }
    }
}
