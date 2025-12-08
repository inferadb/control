/// Simple wrapper around the ID generator for type-level usage
///
/// Note: This is just a re-export of the idgenerator functionality.
/// The actual initialization and worker ID management happens in
/// infera-management-core::id module.
pub struct IdGenerator;

impl IdGenerator {
    /// Generate a new unique ID
    ///
    /// This assumes the ID generator has been initialized by the core crate.
    pub fn next_id() -> i64 {
        idgenerator::IdInstance::next_id()
    }
}
