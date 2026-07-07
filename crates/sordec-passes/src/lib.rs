//! Pass-based middle-end for the sordec pipeline.
//!
//! This crate defines:
//!
//! - The [`Pass`] trait every analysis or transformation pass implements.
//! - [`Pipeline`] — a manifest-ordered list of passes with optional
//!   fixpoint groups.
//! - [`LoweringStep`] — the trait used at phase boundaries between IR
//!   layers (e.g. [`sordec_ir::LiftedIr`] → [`sordec_ir::HighIr`]).
//! - [`lift_with_waffle`] — the WASM-to-`LiftedIr` boundary, wrapping
//!   `waffle` and surfacing `LiftOutput` (lifted IR + diagnostics).
//! - [`host_calls`] — vendored Soroban host-function catalog and
//!   `(module, name) → friendly_name` resolver. Used by the CLI's
//!   `dump-ir` for human-readable host-call rendering and (in Phase 2)
//!   by pattern recovery passes that need to recognise specific host
//!   calls before tracing their arguments.
//! - [`dataflow`] — analysis primitives (backward constant tracing,
//!   etc.) that Phase 2 pattern-recovery passes consume.
//!
//! Concrete pattern-recovery passes (Val encoding, storage tier,
//! auth chain, cross-contract clients) land in this crate during
//! Phase 2 as separate modules.

pub mod dataflow;
pub mod error;
pub mod host_calls;
pub mod lift;
pub mod lowering;
pub mod pass;
pub mod pipeline;

pub use dataflow::{
    trace_const, trace_const_with_limit, DefUseIndex, TraceStop, UseSite, DEFAULT_MAX_DEPTH,
};
pub use error::{LiftError, LiftResult};
pub use host_calls::{catalog_size, resolve as resolve_host_call, HostCall, CATALOG_VERSION};
pub use lift::{lift_with_waffle, LiftOutput};
pub use lowering::{LiftToHigh, LoweringError, LoweringStep};
pub use pass::{Pass, PassMetrics, PassResult};
pub use pipeline::{Pipeline, PipelineReport};
pub use sordec_common::LiftDiagnostics;
