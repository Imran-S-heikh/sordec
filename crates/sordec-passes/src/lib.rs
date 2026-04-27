//! Pass-based middle-end for the sordec pipeline.
//!
//! This crate defines:
//!
//! - The [`Pass`] trait every analysis or transformation pass implements.
//! - [`Pipeline`] — a manifest-ordered list of passes with optional
//!   fixpoint groups.
//! - [`LoweringStep`] — the trait used at phase boundaries between IR
//!   layers (e.g. [`sordec_ir::LiftedIr`] → [`sordec_ir::HighIr`]).
//!
//! Concrete passes (lifting, type inference, semantic recovery,
//! structuring, etc.) land in this crate over Phase 1.3 and Phase 2 as
//! separate modules.

pub mod error;
pub mod lift;
pub mod lowering;
pub mod pass;
pub mod pipeline;

pub use error::{LiftError, LiftResult};
pub use lift::{lift_with_waffle, LiftOutput};
pub use lowering::{LoweringError, LoweringStep};
pub use pass::{Pass, PassMetrics, PassResult};
pub use pipeline::{Pipeline, PipelineReport};
