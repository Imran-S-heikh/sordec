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
//! - [`val_abi`] — vendored Soroban `Val` encoding ABI (tag table, bit
//!   layout, conversion-function mapping) consumed by the Val-encoding
//!   recognizer.
//! - [`metrics_catalog`] — the canonical public names of the
//!   `PassMetrics` counter keys that `sordec coverage` surfaces (F1–F8
//!   + the enum-key / TTL / dispatcher ratios).
//!
//! Concrete pattern-recovery passes (Val encoding, storage tier,
//! auth chain, cross-contract clients) land in this crate during
//! Phase 2 as separate modules.

pub mod dataflow;
pub mod declutter;
pub mod effects;
pub mod error;
pub mod host_calls;
pub mod interfaces;
pub mod ledger;
pub mod lift;
pub mod lowering;
pub mod marshalling;
pub mod memory;
pub mod metrics_catalog;
pub mod pass;
pub mod pipeline;
pub mod recognizers;
pub mod refine;
pub mod structuring;
#[cfg(test)]
mod test_util;
pub mod treeify;
pub mod type_infer;
pub mod val_abi;

pub use dataflow::{
    for_each_target, resolve_use, trace_bytes, trace_const, trace_const_with_limit, trace_literal,
    trace_u32val, CallIndex, CallSite, CfgEdge, CfgFacts, DefUseIndex, HighUseIndex, HighUseSite,
    InlineClass, InlinePlan, InlineSite, InlineStats, LoopForest, LoopId, NaturalLoop, Resolver,
    TraceStop, UseSite, DEFAULT_MAX_DEPTH, DEFAULT_RESOLVE_DEPTH, DEFAULT_USE_DEPTH,
};
pub use declutter::{
    MergeBlockChainsPass, PruneTrivialPhisPass, ResolveAliasesPass, SweepDeadPass,
    ThreadTrivialJumpsPass,
};
pub use error::{LiftError, LiftResult};
pub use host_calls::{catalog_size, resolve as resolve_host_call, HostCall, CATALOG_VERSION};
pub use lift::{lift_with_waffle, LiftOutput};
pub use lowering::{LiftToHigh, LoweringError, LoweringStep};
pub use memory::{SlotPromotionPass, SretReturnPass};
pub use marshalling::{
    ArgGuardElisionPass, FrameElisionPass, ValDecodeCollapsePass, ValEncodeCollapsePass,
    WideReturnPass,
};
pub use pass::{Pass, PassMetrics, PassResult};
pub use pipeline::{Pipeline, PipelineReport};
pub use recognizers::{
    AbiSweepPass, AuthFlowPass, AuthPass, ClientCallPass, CollectionsPass, ConstPropPass,
    ContextPass, CrossContractPass, DispatcherPass, EnumKeyPass, ErrorConstPass, LinearMemoryPass,
    StoragePass, TtlPass, UnrecognizedScanPass, ValEncodingPass,
};
pub use refine::{
    AndMergePass, DispatchLinkPass, GuardClausePass, LoopClassifyPass, PanicRecoverPass,
    PolarityPass, SwitchDedupPass, TrapInlinePass,
};
pub use sordec_common::LiftDiagnostics;
pub use structuring::{structure, StructureError, StructuringCensusPass, StructuringStatsPass};
pub use treeify::TreeifyStatsPass;
pub use type_infer::TypeInferPass;

use sordec_ir::{HighIr, LiftedIr};

/// Build the default lifted-IR de-cluttering pipeline.
///
/// Runs between [`lift_with_waffle`] and the [`LiftToHigh`] lowering.
/// [`ResolveAliasesPass`] runs once up front — no later pass creates a
/// *used* alias (trivial-phi tombstones are born use-free). The
/// remaining de-cluttering passes form a fixpoint group because they
/// enable each other: threading removes predecessors, which makes more
/// phis trivial; pruning empties parameter lists, which unlocks chain
/// merges; the dead sweep removes orphaned blocks' edges, which
/// un-blocks both. See the [`declutter`] module docs for the
/// termination measure. `--raw` CLI paths skip this pipeline entirely,
/// preserving the pristine post-waffle view.
#[must_use]
#[allow(clippy::single_range_in_vec_init)] // fixpoint group, not a range literal
pub fn default_lifted_pipeline() -> Pipeline<LiftedIr> {
    Pipeline::new(
        vec![
            Box::new(ResolveAliasesPass),
            Box::new(PruneTrivialPhisPass),
            Box::new(ThreadTrivialJumpsPass),
            Box::new(MergeBlockChainsPass),
            Box::new(SweepDeadPass),
            // `memory::SretReturnPass` and `memory::SlotPromotionPass`
            // belong here, in this order, inside the fixpoint group — it is
            // LLVM's documented SROA-then-mem2reg loop. Registering them
            // also means widening the group to `0..7`: promotion creates
            // *used* aliases, which is exactly what the note above says
            // nobody does. `tests/memory_staged.rs` runs that pipeline and
            // locks it valid corpus-wide.
            //
            // Not registered yet, and not because of a defect in either
            // pass: `sret` rewrites the Val-decode helper into a
            // multi-value return, which is the shape `marshalling`'s
            // elision matches on, so wiring them today costs hello-add its
            // clean emission. See the `memory::promote` module docs.
        ],
        vec![1..5],
    )
}

/// Build the default high-IR pattern-recovery pipeline.
///
/// The manifest of `Pass<HighIr>` recognizers that run after the
/// `LiftedIr → HighIr` lowering. Recognizers are registered here in the
/// order the kickoff plan sequences them; as more land they join a
/// fixpoint group so patterns that feed each other converge.
///
/// [`LinearMemoryPass`] runs after [`ValEncodingPass`] because it consumes
/// C1's output: the `(position, length)` operands of the
/// `*_new_from_linear_memory` constructors arrive as `U32Val`s that C1 has
/// already collapsed into `ValEncodeSmall`, which the linear-memory tracer
/// peels. [`EnumKeyPass`] runs after [`ConstPropPass`] — not a hard
/// dependency (its evidence is local constants + rodata + frame facts),
/// but it keeps the refiners-before-consumers reading of the manifest.
/// [`AbiSweepPass`] runs after [`StoragePass`] and [`CollectionsPass`]
/// so every prior `l`/`m`/`v`/`b` claim happens first — its `l`-deploy
/// pickup is then unambiguous. [`DispatcherPass`] runs immediately after
/// [`CollectionsPass`], which produces the
/// `SymbolIndexInLinearMemory` `BufOp` it refines; it needs only that op
/// plus `memory` + `soroban_facts`, so it is independent of the
/// const-prop / enum-key refiners. [`ClientCallPass`] consumes
/// `ConstPropPass`'s `resolved_callee`. [`TtlPass`] runs after
/// [`ConstPropPass`] so a `StorageExtendTtl`'s tier is already resolved
/// on the binding — it fills the independent TTL ledger-amount slots
/// without contending with the tier rewrite. [`UnrecognizedScanPass`] is
/// the terminal step: after every recogniser has run, it emits a
/// diagnostic for each host call still left as `SemanticOp::Unknown`
/// (diagnostics-only, never rewrites). [`AuthFlowPass`] runs last of the
/// rewriting passes,
/// consuming `EnumKeyPass`'s resolved keys (hard dependencies both).
/// The two terminal passes are metrics-only, after every rewrite has
/// settled: [`TreeifyStatsPass`] reports how much of the final IR the B6
/// inlinability analysis classifies foldable / effect-pinned / residue,
/// and [`StructuringCensusPass`] emits the A6 structuring coverage
/// counters (per-function structured ratio, loop-kind breakdown,
/// recovered switches, labeled-exit tax) over the settled region trees.
/// Both must stay outside the fixpoint group so their census counters
/// are not multiplied by the iteration count.
///
/// The **region-refinement group** sits between the structuring report
/// and the recognizers: the D-category passes rewrite the region tree
/// toward source shape (guard clauses, inlined traps, canonical
/// polarity) and iterate to a fixpoint because each transform exposes
/// work for the others. Recognizers read bindings, not regions, so the
/// ordering between the group and the recognizer chain is by clarity,
/// not dependency. The recognizer chain itself needs no fixpoint: its
/// dependencies are a straight line and every pass is idempotent.
#[must_use]
pub fn default_high_pipeline() -> Pipeline<HighIr> {
    Pipeline::new(
        vec![
            Box::new(StructuringStatsPass),
            // Region-refinement fixpoint group (D-category, wave 1).
            Box::new(PolarityPass),
            Box::new(GuardClausePass),
            Box::new(TrapInlinePass),
            Box::new(SwitchDedupPass),
            Box::new(AndMergePass),
            // Loop classification: a single tag-only pass once the
            // group above has settled the body shapes it reads.
            Box::new(LoopClassifyPass),
            // Recognizer chain (order rationale above).
            Box::new(ValEncodingPass),
            Box::new(StoragePass),
            Box::new(AuthPass),
            Box::new(ContextPass),
            Box::new(LinearMemoryPass),
            Box::new(CollectionsPass),
            Box::new(DispatcherPass),
            Box::new(AbiSweepPass),
            Box::new(CrossContractPass),
            Box::new(ConstPropPass),
            Box::new(TtlPass),
            Box::new(EnumKeyPass),
            // Decode constant contract-error Vals to named variants — needs
            // const-folding done (ConstPropPass) + the declared error enums,
            // and must precede TypeInferPass so the Error type is planted.
            Box::new(ErrorConstPass),
            Box::new(ClientCallPass),
            Box::new(AuthFlowPass),
            // Region-refinement wave 2: region rewrites that consume
            // recognizer output, so they cannot join the pre-recognizer
            // group above. Straight-line, no fixpoint.
            Box::new(DispatchLinkPass),
            Box::new(PanicRecoverPass),
            // Marshalling elision — deletes the ABI glue the source never
            // wrote, now that every recognizer has named it. A fixpoint
            // group because the three feed each other in one direction:
            // collapsing a decode makes its failure guard constant,
            // removing that guard makes the frame pointer dead, and a dead
            // frame pointer is what lets the bracket go.
            Box::new(ValDecodeCollapsePass),
            Box::new(ValEncodeCollapsePass),
            // `WideReturnPass` belongs here, strictly after the decode
            // collapse. It is not registered yet: it needs a dominance
            // gate first, and switching it on without one measured +14
            // `cargo check` errors across the corpus. See its module docs.
            Box::new(ArgGuardElisionPass),
            Box::new(FrameElisionPass),
            Box::new(UnrecognizedScanPass),
            // General type propagation — runs once the recognizers have
            // planted their host-call/val result types, flowing them
            // through params, arithmetic, phis, and returns. Deliberately
            // *after* elision: the marshalling gates read `signature`
            // (the authoritative ABI) rather than inferred types, and
            // propagating over the cleaned IR means no type has to be
            // threaded through glue that is about to disappear.
            Box::new(TypeInferPass),
            Box::new(TreeifyStatsPass),
            Box::new(StructuringCensusPass),
        ],
        // Two fixpoint groups: wave-1 region refinement, and marshalling
        // elision. Both converge because every member strictly reduces a
        // measure — nesting depth for the first, live marshalling bindings
        // for the second. `marshalling_group_covers_exactly_the_elision_passes`
        // pins the second range by pass name, so inserting a pass above it
        // fails a test instead of silently shifting the window.
        vec![1..6, 24..28],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixpoint group is a pair of raw indices into the manifest, so
    /// adding a pass anywhere above one silently moves the window over the
    /// wrong passes. This pins the marshalling group by name.
    #[test]
    fn marshalling_group_covers_exactly_the_elision_passes() {
        let pipeline = default_high_pipeline();
        let names: Vec<&str> = pipeline.pass_names();
        let group = pipeline
            .fixpoint_groups()
            .iter()
            .find(|r| names[r.start] == marshalling::decode::PASS_NAME)
            .expect("the marshalling group starts at the decode pass");
        assert_eq!(
            &names[group.clone()],
            &[
                marshalling::decode::PASS_NAME,
                marshalling::encode::PASS_NAME,
                marshalling::guard::PASS_NAME,
                marshalling::frame::PASS_NAME,
            ],
        );
    }
}
