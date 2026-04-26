//! Shared types used across the sordec pipeline.
//!
//! This crate defines the primitives that every other crate depends on:
//! typed identifiers ([`FuncId`], [`BlockId`], [`ValueId`], [`TypeId`]),
//! the storage container that uses them ([`Arena`]), the structured
//! audit-trail tracking refinements through the pipeline ([`Provenance`]),
//! and the explicit reasons why information is missing
//! ([`UnknownReason`]).
//!
//! `sordec-common` has no dependencies on other sordec crates. Every other
//! crate depends on it, so changes here recompile the entire workspace.
//! Keep the surface area minimal and stable.
//!
//! ## Feature flags
//!
//! - `serde` — enables `Serialize`/`Deserialize` derives on every public
//!   type. Off by default; pass `--features serde` when serialising IR for
//!   inspection or test goldens.

pub mod arena;
pub mod ids;
pub mod provenance;
pub mod unknown;

pub use arena::Arena;
pub use ids::{BlockId, FuncId, IrId, TypeId, ValueId};
pub use provenance::{Provenance, ProvenanceSource};
pub use unknown::UnknownReason;
