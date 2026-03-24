//! Snowflake-style unique ID generation.

/// Generates unique snowflake-style IDs using the `idgenerator` crate.
///
/// The underlying generator must be initialized by the core crate
/// before calling [`IdGenerator::next_id`].
pub struct IdGenerator;

impl IdGenerator {
    /// Generates a new unique snowflake ID.
    ///
    /// # Panics
    ///
    /// Panics if the ID generator has not been initialized.
    pub fn next_id() -> u64 {
        idgenerator::IdInstance::next_id() as u64
    }
}
