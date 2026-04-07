//! Snowflake-style unique ID generation.

/// Snowflake-style unique ID generator backed by the `idgenerator` crate.
///
/// The core crate must initialize the underlying generator
/// before any call to [`IdGenerator::next_id`].
pub struct IdGenerator;

impl IdGenerator {
    /// Returns a new unique snowflake ID.
    ///
    /// # Panics
    ///
    /// Panics if the generator has not been initialized.
    pub fn next_id() -> u64 {
        idgenerator::IdInstance::next_id() as u64
    }
}
