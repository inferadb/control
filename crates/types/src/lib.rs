//! Shared type definitions for the InferaDB Control plane.
//!
//! Provides the [`Error`] enum, [`Result`] alias, [`IdGenerator`], and
//! shared DTOs used across Control crates to prevent circular dependencies.

#![deny(unsafe_code)]

pub use inferadb_ledger_types::{OrganizationSlug, VaultSlug};

pub mod id;

pub use id::IdGenerator;

pub mod error;

pub use error::{Error, Result};

pub mod dto;

pub use dto::ErrorResponse;
