//! Data-flow analysis primitives for `LiftedIr`.
//!
//! Every Phase 2 pattern recognizer needs to answer questions like:
//!
//! - "Given this `ValueId`, what constant produced it?" — used to resolve
//!   the durability arg of a storage call, the callee address of a
//!   cross-contract call, the error code of `fail_with_error`, and so on.
//! - "Which values use this def?" — needed for auth patterns
//!   (`instance.get(Admin) → require_auth`) and for peephole rewrites.
//!
//! Rather than each recognizer re-implementing SSA traversal, this module
//! provides the shared primitives. Utilities here are:
//!
//! - Pure (no I/O, no mutation).
//! - Scoped to a single [`sordec_ir::LiftedFunction`] (no inter-procedural
//!   analysis in Phase 2).
//! - Return-value-based failure reporting (no diagnostic emission — the
//!   recognizer decides whether a failure becomes a `LiftDiagnostic`).
//!
//! ## Public surface
//!
//! - [`trace_const()`] / [`trace_const_with_limit()`] — backward-fold a
//!   `ValueId` to a concrete [`sordec_ir::Literal`] by chasing
//!   `Alias`/`PickOutput` links until a `*Const` operator is found.
//! - [`TraceStop`] — the closed set of stop reasons for a failed trace.
//! - [`DefUseIndex`] — the forward direction: per-function reverse-use
//!   map answering "who consumes this value?", with the `sole_use`
//!   check pattern collapses hinge on.
//! - [`UseSite`] — where a use occurs (a value's definition or a block
//!   terminator).
//! - [`CfgFacts`] / [`LoopForest`] — control-flow-graph facts (deduped
//!   adjacency, reverse postorder, immediate dominators, reducibility)
//!   and the natural-loop nesting derived from them; the substrate the
//!   Phase-3 structurer and cleanup passes stand on.
//! - [`for_each_target`] — raw terminator-target enumeration with
//!   multiplicity, in the order [`CfgFacts`]'s RPO is defined by.
//! - [`CfgEdge`] — one directed CFG edge (back edges, irreducibility
//!   witnesses).
//!
//! Additional analyses (fixpoint driver, expression visitor) land here
//! as Phase 2 recognizers require them.

pub mod cfg;
pub mod const_prop;
pub mod def_use;
pub mod frame_facts;
pub mod high;
pub mod high_uses;
pub mod inline_plan;
pub mod trace_bytes;
pub mod trace_const;

pub use cfg::{for_each_target, CfgEdge, CfgFacts, LoopForest, LoopId, NaturalLoop};
pub use const_prop::{CallIndex, CallSite, Resolver, DEFAULT_RESOLVE_DEPTH};
pub use def_use::{DefUseIndex, UseSite};
pub use frame_facts::{
    block_containing, canon_addr, facts_at_end, facts_before, may_write_memory, FrameFacts,
    SlotFact,
};
pub use high::{resolve_use, trace_int, trace_literal, DEFAULT_USE_DEPTH};
pub use high_uses::{HighUseIndex, HighUseSite};
pub use inline_plan::{InlineClass, InlinePlan, InlineSite, InlineStats};
pub use trace_bytes::{trace_bytes, trace_u32val};
pub use trace_const::{trace_const, trace_const_with_limit, TraceStop, DEFAULT_MAX_DEPTH};
