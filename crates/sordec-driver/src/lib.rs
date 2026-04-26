//! Pipeline orchestration for sordec.
//!
//! Owns the [`Driver`] type that wires the frontend → lifted pipeline →
//! lowering → high pipeline → backend together.
//!
//! `sordec-driver` deliberately does not re-export types from
//! [`sordec_ir`] or [`sordec_passes`]: keeping each crate's API surface
//! its own preserves the freedom to refactor crate boundaries later
//! without churning every downstream `use` statement.

pub mod driver;

pub use driver::{DecompileOutput, Driver, DriverError, DriverReport};
