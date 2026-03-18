//! Organization middleware (removed).
//!
//! Organization membership checks are now performed inline in handlers
//! via Ledger SDK calls. The old middleware that extracted `OrganizationContext`
//! from session state has been removed.
