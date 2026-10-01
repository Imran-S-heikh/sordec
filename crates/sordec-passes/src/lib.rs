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

// This crate's module docs are the design record for the pass pipeline, and
// they are written for the people maintaining it. They routinely link to the
// private helpers a pass is built from — `sret`, `pin_target_block`,
// `MAX_ROUNDS` and friends — because naming the actual item is what makes the
// prose checkable against the code.
//
// `rustdoc::private_intra_doc_links` fires on all 22 of those. Suppressed
// deliberately and crate-wide rather than by rewriting each link into a plain
// code span, which would cost the reader the one thing the link is for. On
// docs.rs such a link renders as ordinary text, so nothing breaks for a public
// reader either.
//
// The lints that catch real mistakes stay hard errors under the gate's
// `RUSTDOCFLAGS="-D warnings"`: a link to an item that does not exist is a
// broken link, not a private one, and still fails the build.
#![allow(rustdoc::private_intra_doc_links)]

pub mod arith;
pub mod attribution;
pub mod dataflow;
pub mod declutter;
pub mod effects;
pub mod error;
pub mod host_calls;
pub mod interfaces;
pub mod interproc;
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
    MergeBlockChainsPass, PruneDeadParamsPass, PruneTrivialPhisPass, ResolveAliasesPass,
    SweepDeadPass, ThreadTrivialJumpsPass,
};
pub use error::{LiftError, LiftResult};
pub use host_calls::{catalog_size, resolve as resolve_host_call, HostCall, CATALOG_VERSION};
pub use arith::{I128BuiltinPass, WideFoldPass};
pub use attribution::SdkAttributionPass;
pub use recognizers::symbol_encoder::SymbolEncoderPass;
pub use interproc::{
    ConstReturnPass, SpecializePass, StructArgPass, WideParamPass, WideReturnPromotePass,
    WrapperInlinePass,
};
pub use lift::{lift_with_waffle, LiftOutput};
pub use lowering::{LiftToHigh, LoweringError, LoweringStep};
pub use memory::{
    ArgPromotionPass, SlotPromotionPass, SretReturnPass, StoreForwardPass, UnrollFillLoopsPass,
};
pub use marshalling::{
    ArgGuardElisionPass, DeadFrameStorePass, FoldedEncodePass, FrameElisionPass, FrameForwardPass, KeyConstructionElisionPass,
    BoolCodecPass, ClientArgVecPass, VecElementsPass, EnumDiscriminantPass, EnumEncodePass, FieldTypePass, OptionDefaultPass, UdtEncodePass, OptionProbePass, OptionSretPass, OptionUnwrapPass, ScalarDecodePass, SpecFromGuardsPass, TypedReadPass, UdtDecodePass, ValDecodeCollapsePass, ValEncodeCollapsePass,
    WideCodecPass, WideReturnPass,
};
pub use pass::{Pass, PassMetrics, PassResult};
pub use pipeline::{Pipeline, PipelineReport};
pub use recognizers::{
    AbiSweepPass, AuthFlowPass, AuthPass, ClientCallPass, CollectionsPass, ConstPropPass,
    ContextPass, CrossContractPass, DispatcherPass, EnumKeyPass, ErrorConstPass, LinearMemoryPass,
    StoragePass, TtlPass, UnrecognizedScanPass, ValEncodingPass, ValPackedComparePass,
};
pub use refine::{
    AndMergePass, ConstBranchFoldPass, DispatchLinkPass, GuardClausePass, LoopClassifyPass, PanicRecoverPass,
    OverflowGuardElisionPass, PolarityPass, ScopeFallthroughPass, ScopeIfElsePass, SelectReturnPass,
    SwitchDedupPass,
    TrapCallInlinePass, TrapInlinePass, TrivialPhiPass, WideArithPass, WideComparePass, WidePhiPass, WideSelectPass, WideZeroPass, WidthFoldPass,
};
pub use sordec_common::LiftDiagnostics;
pub use structuring::{structure, StructureError, StructuringCensusPass, StructuringStatsPass};
pub use treeify::TreeifyStatsPass;
pub use type_infer::TypeInferPass;

use sordec_ir::{HighIr, LiftedIr};

/// Build the default lifted-IR de-cluttering pipeline.
///
/// Runs between [`lift_with_waffle`] and the [`LiftToHigh`] lowering.
///
/// Every pass is inside one fixpoint group, because they enable each
/// other: threading removes predecessors, which makes more phis trivial;
/// pruning empties parameter lists, which unlocks chain merges; the dead
/// sweep removes orphaned blocks' edges, which un-blocks both; removing an
/// unread parameter drops the arguments feeding it, which can make the
/// values behind them dead in turn; and stopping the frame escaping into a
/// callee is what lets its slots promote. That last one is why the group
/// matters most here: a helper that forwards its pointer to another helper
/// only stops escaping once the *inner* one is promoted, so the outer
/// candidate appears on a later iteration and not the first.
///
/// Two orderings inside the group are load-bearing rather than
/// stylistic:
///
/// - [`PruneDeadParamsPass`] follows [`PruneTrivialPhisPass`]. They remove
///   disjoint kinds — the same parameter for different reasons — and the
///   cheaper, far more common case going first leaves less for the
///   fixpoint. Promotion depends on the pair *jointly*: it inserts a
///   parameter in every reachable block and neither cleanup alone removes
///   the surplus.
/// - [`ArgPromotionPass`] and [`SretReturnPass`] both precede
///   [`SlotPromotionPass`] — LLVM's SROA-then-mem2reg order. Escape is
///   mem2reg's precondition, so the ABI changes have to happen before the
///   forwarding. The two handle opposite directions of the same escape (a
///   pointer the callee reads through, and one it writes through) and
///   `argpromote` goes first only so that a function which is somehow both
///   is claimed by the pass that needs no placeholder value.
/// - [`StoreForwardPass`] sits between them and [`SlotPromotionPass`]
///   because it consumes what they produce: both relocate memory traffic,
///   and it is the pass that removes the *reads* of that traffic on the
///   frames `promote` declines whole. Running it before them would find
///   nothing; running it after `promote` would find only what `promote`
///   had already retired.
///
/// [`ResolveAliasesPass`] is **in** the group rather than once up front,
/// which its own docs' rationale would otherwise allow: promotion retires
/// each forwarded load into an alias tombstone whose readers still name
/// it, and only a chased re-resolution fixes those. Leaving it outside
/// produced a used-but-unscheduled value that surfaced two stages later as
/// a region-validator `UseBeforeDef`. `tests/memory_staged.rs` locks both
/// halves of that.
///
/// See the [`declutter`] module docs for the termination measure, which the
/// two `memory` passes extend. `--raw` CLI paths skip this pipeline
/// entirely, preserving the pristine post-waffle view.
#[must_use]
#[allow(clippy::single_range_in_vec_init)] // fixpoint group, not a range literal
pub fn default_lifted_pipeline() -> Pipeline<LiftedIr> {
    Pipeline::new(
        vec![
            Box::new(ResolveAliasesPass),
            Box::new(PruneTrivialPhisPass),
            Box::new(PruneDeadParamsPass),
            Box::new(ThreadTrivialJumpsPass),
            Box::new(MergeBlockChainsPass),
            Box::new(SweepDeadPass),
            // The `[Val::VOID; N]` fill and copy loops, unrolled before the
            // memory passes: a loop-carried slot address is what makes the
            // whole frame decline promotion, and the dead body it leaves is
            // the sweep's to collect on the next round.
            Box::new(UnrollFillLoopsPass),
            Box::new(ArgPromotionPass),
            Box::new(SretReturnPass),
            Box::new(StoreForwardPass),
            Box::new(SlotPromotionPass),
        ],
        vec![0..11],
    )
}

/// [`ConstPropPass`] re-run after the inliner; see [`default_high_pipeline`].
pub const CONST_PROP_AFTER_INLINE: &str = "const-prop-after-inline";
/// [`TtlPass`] re-run after the inliner; see [`default_high_pipeline`].
pub const TTL_AFTER_INLINE: &str = "ttl-after-inline";
/// [`EnumKeyPass`] re-run after the inliner; see [`default_high_pipeline`].
pub const ENUM_KEY_AFTER_INLINE: &str = "enum-key-after-inline";
/// Name of the panic-recovery re-run inside the elision group.
pub const PANIC_RECOVER_AFTER_RECOVERY: &str = "panic-recover-after-recovery";
/// Name of the polarity re-run inside the elision group.
pub const POLARITY_AFTER_ELISION: &str = "polarity-after-elision";
/// Name of the declared-type recovery re-run after the elision group.
pub const SPEC_FROM_GUARDS_AFTER_ELISION: &str = "spec-from-guards-after-elision";
/// [`DeadFrameStorePass`] re-run after the `Vec` elements are recovered.
/// [`OptionProbePass`] re-run once every wrapper has been inlined.
pub const OPTION_PROBE_AFTER_ELISION: &str = "option-probe-after-elision";
/// [`OptionUnwrapPass`] re-run on the probes that re-run found.
pub const OPTION_UNWRAP_AFTER_ELISION: &str = "option-unwrap-after-elision";
/// [`OptionDefaultPass`] re-run on the probes that re-run found.
pub const OPTION_DEFAULT_AFTER_ELISION: &str = "option-default-after-elision";
/// What that re-run reports: its fold count and its whole decline census.
///
/// A site refused by both the first run and this one is counted twice.
/// These counters are a worklist of refusal *events*, not a set of sites —
/// the catalog says so for the `sret` family too — and under-reporting a
/// contract as having no candidates at all is the worse failure.
const OPTION_DEFAULT_COUNTERS: &[&str] = &[
    metrics_catalog::MARSHALLING_OPTION_DEFAULTS_RECOVERED,
    metrics_catalog::MARSHALLING_OPTION_DEFAULT_DECLINED_ARM_ALWAYS_TRAPS,
    metrics_catalog::MARSHALLING_OPTION_DEFAULT_DECLINED_SOME_ARM_BRANCHES,
    metrics_catalog::MARSHALLING_OPTION_DEFAULT_DECLINED_NONE_ARM_BRANCHES,
    metrics_catalog::MARSHALLING_OPTION_DEFAULT_DECLINED_ARM_HAS_EFFECTS,
    metrics_catalog::MARSHALLING_OPTION_DEFAULT_DECLINED_PROBE_SHARED,
    metrics_catalog::MARSHALLING_OPTION_DEFAULT_DECLINED_NOT_ONE_READ,
    metrics_catalog::MARSHALLING_OPTION_DEFAULT_DECLINED_MERGE_SHAPE,
    metrics_catalog::MARSHALLING_OPTION_DEFAULT_DECLINED_NOTHING_MERGED,
    metrics_catalog::MARSHALLING_OPTION_DEFAULT_DECLINED_STRUCT_WITH_CHECKS,
    metrics_catalog::MARSHALLING_OPTION_DEFAULT_DECLINED_NO_COMMON_DEFAULT,
    metrics_catalog::MARSHALLING_OPTION_DEFAULT_DECLINED_CHECK_WOULD_FIRE,
];
/// [`DeadFrameStorePass`] re-run after the `Vec` elements are recovered.
pub const DEAD_FRAME_STORE_AFTER_VEC: &str = "dead-frame-store-after-vec";
/// [`FrameElisionPass`] re-run after the `Vec` elements are recovered.
pub const FRAME_ELISION_AFTER_VEC: &str = "frame-elision-after-vec";
/// Name of the declared-type recovery re-run inside the elision group,
/// where a struct recovered from its key table first has fields to type.
pub const SPEC_FROM_GUARDS_ON_FIELDS: &str = "spec-from-guards-on-fields";

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
/// [`SpecializePass`] runs *ahead of every recognizer that reads a
/// constant*, which puts it between [`ValEncodingPass`] and
/// [`StoragePass`]. It splits the helpers rustc merged, so the
/// recognizers below see one fact per body instead of a meet over
/// disagreeing callers — a hard dependency in one direction and none in
/// the other, since it rewrites no operand a recognizer would claim. It
/// follows `ValEncodingPass` only so the `U32Val` wrappers are already
/// collapsed when it traces call-site arguments to literals.
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
///
/// Three refiners run a second time inside the marshalling group, after
/// the inliner, under the names below: a pasted helper body carries the
/// unresolved slots its helper had, and only the copy sees the caller's
/// constants.
#[must_use]
pub fn default_high_pipeline() -> Pipeline<HighIr> {
    Pipeline::new(
        vec![
            Box::new(StructuringStatsPass),
            // Region-refinement fixpoint group (D-category, wave 1).
            Box::new(PolarityPass),
            Box::new(GuardClausePass),
            Box::new(TrapInlinePass),
            Box::new(TrapCallInlinePass),
            Box::new(SwitchDedupPass),
            Box::new(AndMergePass),
            // Loop classification: a single tag-only pass once the
            // group above has settled the body shapes it reads.
            Box::new(LoopClassifyPass),
            // Recognizer chain (order rationale above).
            //
            // `SdkAttributionPass` leads it. It reads only `ir.facts` — the
            // fingerprints the frontend computed from the original bytes —
            // so it depends on no pass and no pass can invalidate it, and
            // running first means every recognizer below can consult what a
            // body *is* rather than infer it from shape. Diagnostics-only
            // today; the passes that act on its answers come later.
            Box::new(SdkAttributionPass),
            // The `compiler_builtins` 128-bit runtime, recovered as
            // arithmetic over wide joins. Reads only body shape, so it
            // depends on nothing; it goes first so every pass below sees
            // `a * b` where the wasm had a helper call and two limb
            // projections, and so the overflow flag it plants is a
            // condition the panic classifier can name.
            Box::new(I128BuiltinPass),
            Box::new(ValEncodingPass),
            Box::new(SpecializePass),
            Box::new(StoragePass),
            Box::new(AuthPass),
            Box::new(ContextPass),
            Box::new(LinearMemoryPass),
            // Folds the SDK's *inlined* small-symbol encoder, which
            // `LinearMemoryPass` cannot see: that pass classifies the
            // `symbol_new_from_linear_memory` **host call**, and this
            // encoder's fast path makes no host call at all. It sits
            // directly after so the two symbol paths — host-built and
            // inlined — are resolved together, and before `CollectionsPass`
            // and `DispatcherPass`, which read symbols the encoder produces.
            Box::new(SymbolEncoderPass),
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
            // Needs both halves of the `Option` shape named: the tier
            // from `StoragePass` and the key from `EnumKeyPass`, since
            // the pairing is proved on key identity at a proven tier.
            Box::new(OptionProbePass),
            Box::new(ClientCallPass),
            Box::new(AuthFlowPass),
            // Last in the recognizer chain: reconciles the two readings of
            // a `U32Val`-returning host call — the ABI type names its
            // payload, the surrounding code was compiled against its bits.
            // Needs the host-call families named (`CollectionsPass`,
            // `ContextPass`) and the constants folded (`ConstPropPass`);
            // the marshalling elision below reads its output, which is why
            // it sits above that group rather than inside it.
            Box::new(ValPackedComparePass),
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
            // Before the elision group, and outside it: what it recovers
            // is a *declaration*, which every gate below reads and none
            // produces. Only fires where the module carries no spec.
            Box::new(SpecFromGuardsPass),
            Box::new(ValDecodeCollapsePass),
            Box::new(ValEncodeCollapsePass),
            // The 128-bit codecs the two passes above decline on purpose:
            // a four-slot decode collapses to limb extractors of the
            // parameter, and an `(status, Val)` encode to a join. Before
            // the guard elision so the constant discriminant it plants is
            // what that pass then folds.
            Box::new(WideCodecPass),
            // Forwards the frame stores the collapses above leave behind
            // to the loads that read them back, so a constant discriminant
            // reaches its guard and a stored join reaches its consumer.
            Box::new(FrameForwardPass),
            // A forwarded discriminant leaves its guard testing `0 != 1`;
            // the fold replaces the branch with the arm it always took.
            Box::new(ConstBranchFoldPass),
            // The fold keeps one arm; a merge that arm alone now reaches is
            // a rename of the one value it carries, and takes its type.
            Box::new(TrivialPhiPass),
            // A narrowing of a value the passes above typed as 32 bits —
            // a typed read, a decoded argument — is that value.
            Box::new(WidthFoldPass),
            // rustc's arithmetic overflow guard, in the group rather than
            // after it: a helper is only straight-line — and so only
            // inlinable — once its `if a < b { panic }` borrow check is
            // gone. It removes guards and rewrites no binding, so the
            // group's measure still strictly decreases.
            // Again, now that the group has recovered the 128-bit
            // divisions: a guard is only recognizable as a division's own
            // once there is a division to attribute it to.
            Box::new(pass::Rerun::new(
                PanicRecoverPass,
                PANIC_RECOVER_AFTER_RECOVERY,
                refine::panic_recover::RESOLUTION_COUNTERS,
            )),
            Box::new(OverflowGuardElisionPass),
            // `WideReturnPass` belongs here, strictly after the decode
            // collapse. It is not registered yet: it needs a dominance
            // gate first, and switching it on without one measured +14
            // `cargo check` errors across the corpus. See its module docs.
            Box::new(ArgGuardElisionPass),
            // Straight-line SDK wrappers pasted into their callers, with
            // every recognized fact attached. Before the key-construction
            // elision because a wrapped `Storage::has` is the call that
            // pass cannot see through; inside the group because inlining
            // a wrapper exposes its frame and guards to the passes above.
            // A derived conversion's `Result` discriminant is a constant
            // the caller cannot see. Naming it at the call site lets the
            // constant-branch fold at the top of the group delete the
            // unwrap it guards. Beside the inliner: both are what let a
            // caller see through a helper it does not inline.
            Box::new(ConstReturnPass),
            // An `i128` comes back in two registers. Until the halves have
            // a whole to belong to, every comparison and sum the caller
            // makes on them stays split and unreadable.
            Box::new(WideReturnPromotePass),
            // And the same in the other direction: a helper handed the
            // two halves of an `i128` by every caller takes the value.
            Box::new(WideParamPass),
            // With the halves owned, the OR tree that tests a 128-bit
            // value against zero can be read as that test.
            // The sum or difference rustc wrote out limb by limb, before
            // the promotions that need a whole value to hand over.
            Box::new(WideArithPass),
            // And the halves a branch merged separately.
            Box::new(WidePhiPass),
            Box::new(WideZeroPass),
            // And the lexicographic comparison of two values' halves,
            // which is where the borrow check on a 128-bit subtraction
            // hides. Before the panic re-classification below, which is
            // what reads it.
            Box::new(WideComparePass),
            // A choice between two wide values, which wasm spells as one
            // `select` per limb. After the comparison, because the
            // condition is often one of those it has just recovered.
            Box::new(WideSelectPass),
            Box::new(WrapperInlinePass),
            // A pasted body carries the facts its helper had, and a helper
            // called with different durabilities or keys had none: the
            // tier slot is `Unknown`, the key unnamed, the TTL unresolved.
            // Each copy now sees its caller's constants, so the three
            // refiners that fill those slots run again here. All are
            // idempotent by contract (a filled slot no longer matches).
            Box::new(pass::Rerun::new(
                ConstPropPass,
                CONST_PROP_AFTER_INLINE,
                recognizers::const_prop::RESOLUTION_COUNTERS,
            )),
            Box::new(pass::Rerun::new(
                TtlPass,
                TTL_AFTER_INLINE,
                recognizers::ttl::RESOLUTION_COUNTERS,
            )),
            Box::new(pass::Rerun::new(
                EnumKeyPass,
                ENUM_KEY_AFTER_INLINE,
                recognizers::enum_key::RESOLUTION_COUNTERS,
            )),
            // `get(&k).unwrap()` of a value wider than a register: the SDK
            // writes the `Option` into the caller's frame from a branching
            // helper. Each call becomes the read and the stores its `Some`
            // path makes; the frame forwarder at the top of the group then
            // carries them to the loads, and the constant-branch fold drops
            // the flag test. After the re-run refiners, which resolve the
            // key and tier the helper's read needs.
            // A storage read followed by the SDK's payload conversion — a
            // tag check that traps and an unpack — is a typed read. Before
            // the Option passes, whose gates then see the payload rather
            // than a `Val` and its checks.
            // `bool` has no body: its conversion is a dispatch on the tag
            // one way and a pair of selects the other. Before the typed
            // read, whose gates then see a `bool` rather than a `Val`.
            Box::new(BoolCodecPass),
            Box::new(TypedReadPass),
            // Its sibling: the types with two encodings, whose decode
            // tests both and so is a branch rather than one check.
            Box::new(ScalarDecodePass),
            // A typed read's `count + 1` arrives folded into the U32Val
            // encode of the result; recover the addition, label its
            // overflow check for the elision above, and name the stored
            // value by its `u32`.
            Box::new(FoldedEncodePass),
            Box::new(OptionSretPass),
            // `get(&k).unwrap_or(d)`: the probe's branch whose other arm
            // only merges constants. The read takes the default and the
            // probe becomes `true`, which the constant-branch fold at the
            // top of the group then drops.
            Box::new(OptionDefaultPass),
            // The derived `#[contracttype]` struct decode: once the unpack
            // wrapper is inlined, the key table names the struct and the
            // slot loads become its fields. After the inliner for that
            // reason; before the wide codec's next iteration, whose
            // evidence rule accepts a field of a recovered struct.
            Box::new(UdtDecodePass),
            // The same derive in the other direction: the slot stores and
            // key table a struct literal is built from. After the decode,
            // whose recovered fields it may be spelled from.
            Box::new(UdtEncodePass),
            // A recovered struct's fields, at the types it declares: the
            // decode each one arrives through is the derive's. After both
            // UDT passes, which are what name the struct.
            // A struct recovered from a key table starts with `Val`
            // fields; the derived conversion's own checks say what they
            // are, and the pass below is what needs to know.
            Box::new(pass::Rerun::new(
                SpecFromGuardsPass,
                SPEC_FROM_GUARDS_ON_FIELDS,
                &[],
            )),
            Box::new(FieldTypePass),
            // A struct too big for a register is passed by reference, and
            // the callee's own key table says which slot is which field.
            // After the UDT passes, which is what reads that table.
            Box::new(StructArgPass),
            // A unit enum, once typed, is masked and compared as a
            // number. Name the variant instead — there is no `&` between
            // an enum and an integer. After the field typing that gives
            // the value its enum type.
            Box::new(EnumDiscriminantPass),
            // And the branch that re-encodes the variant it just tested:
            // the compiler decodes an enum on the way in and builds it
            // again on the way out, which the source never asked for.
            Box::new(EnumEncodePass),
            // `get(&k).unwrap()`: the proven Option probe, its trapping
            // None branch and the read, collapsed to an unwrap of the
            // read. After the inliner, which is what brings the wrapped
            // probe next to its read; before the key-construction elision,
            // which then sees one consumer fewer of the key.
            Box::new(OptionUnwrapPass),
            // The derived `#[contracttype]` enum-to-`Val` converter behind
            // a storage key the recognizers already resolved. Inside this
            // group because eliding the converter can leave its frame slot
            // dead, which is what `FrameElisionPass` below then collects.
            Box::new(KeyConstructionElisionPass),
            // The same, one host call along: a cross-contract call's
            // argument vector, once every element of it is recovered.
            // The slab it was built from goes with it, because the
            // stores are then unread and `DeadFrameStorePass` is next.
            Box::new(ClientArgVecPass),
            // A store into a private frame that nothing loads back is the
            // last reader of a frame pointer the bracket elision below
            // needs unread.
            Box::new(DeadFrameStorePass),
            Box::new(FrameElisionPass),
            // Cancels a wide join against its own limbs. In the group
            // because the decode collapse is what plants the limb
            // extractors it cancels, and each cancellation may expose the
            // next; it strictly reduces the count of wide nodes.
            Box::new(WideFoldPass),
            // Dropping the overflow guard (above, in the group) can leave
            // its merge scope with a single tail `Break`, which is then a
            // fallthrough rather than a jump — the pair below undoes that.
            // Wasm's forward-branch spelling of `if`/`else`, undone in two
            // steps that feed each other: the first deletes the breaks that
            // jump where control was already going, the second turns a
            // guarded break into the `else` arm it skips past — which
            // exposes fresh tail exits for the first. Hence a fixpoint pair.
            //
            // They sit here, far from `GuardClausePass`, on purpose. That
            // pass performs the second one's exact inverse, and in one group
            // they would oscillate. `ScopeIfElsePass` also removes the
            // trailing `Break` that made the arm terminate, so the shape it
            // emits is one `GuardClausePass` cannot match — belt and braces,
            // and its own test pins the belt.
            //
            // They close the elision group rather than following it: the
            // `Option` helper collapse above recognizes a branch on the
            // probe, which only exists as an `if` once this pair has run,
            // and the elisions after it need the next iteration to see the
            // result.
            // Again, now that the elisions have emptied arms. A guard
            // whose trap moved into derived code leaves `if c {} else {E}`,
            // which is the one-armed branch the source wrote with the
            // opposite polarity — and the pair below reads the result.
            Box::new(pass::Rerun::new(PolarityPass, POLARITY_AFTER_ELISION, &[])),
            Box::new(ScopeFallthroughPass),
            Box::new(ScopeIfElsePass),
            // After the group, on settled IR. A `Vec`'s elements are stores
            // into a scratch buffer above its constructor, and reading them
            // back is what lets `vec![..]` be spelled at all.
            //
            // Outside the fixpoint group on purpose, not merely last in it.
            // Filling the elements in changes which values are live, and
            // several gates inside the group are liveness-sensitive: run in
            // the group — anywhere in it — the `Option` collapse stops
            // matching on auth, custom_types and events, each falling
            // 1.0000 -> 0.7059 on a branch the source never wrote. Out
            // here the group has already converged, so nothing it decided
            // can be disturbed. The cost is that the buffer stores are not
            // collected afterwards, since the elisions that would do it
            // have run.
            // The SDK's `Option` probe, once more now that every wrapper
            // has been pasted.
            //
            // The pairing gate needs a `has` and a `get` on one key at one
            // tier, and its first run sees neither: the SDK puts them in
            // *separate* wrappers that each build the same constant key
            // themselves, so the caller passes nothing and there is no
            // shared value to pair on. After inlining they are siblings
            // with two equal constants, which `same_key` matches.
            //
            // Out here rather than in the elision group, and the collapse
            // runs immediately after the marking. An earlier attempt put
            // the re-run inside that group and cost 0.09 on the corpus —
            // marking a probe takes the pair out of the group's reach
            // while its members are still iterating, and a marked-but-
            // uncollapsed probe is strictly worse than an unmarked one.
            Box::new(pass::Rerun::new(
                OptionProbePass,
                OPTION_PROBE_AFTER_ELISION,
                &[],
            )),
            Box::new(pass::Rerun::new(
                OptionUnwrapPass,
                OPTION_UNWRAP_AFTER_ELISION,
                &[],
            )),
            // Unlike the re-runs above, this one reports. Two reasons, and
            // both turn on it sitting *outside* the elision group rather
            // than in it: it runs exactly once, so a miss counter cannot be
            // counted per iteration, and its rewrite counter is the only
            // record of a fold that the first run could not see.
            //
            // On phoenix-vesting the probes do not exist until the wrappers
            // are inlined, so every one of its `unwrap_or` candidates is
            // decided here. With an empty list the contract reported a
            // clean zero in all fifteen counters while the pass was
            // refusing two sites.
            Box::new(pass::Rerun::new(
                OptionDefaultPass,
                OPTION_DEFAULT_AFTER_ELISION,
                OPTION_DEFAULT_COUNTERS,
            )),
            Box::new(VecElementsPass),
            // Collecting the buffer the elements came out of, in a group of
            // its own.
            //
            // The main elision group has already converged, and this pass
            // must not rejoin it — see the note above. But recovering the
            // elements makes the buffer's stores unread for the first time,
            // and the two passes that collect an unread frame have run. So
            // they run again here, as their own fixpoint: the store
            // retirement makes the frame pointer unread, the bracket
            // elision then takes the bracket, and neither reads the
            // liveness-sensitive shapes the big group gates on. Worth 78
            // more holes than leaving the buffer behind.
            Box::new(pass::Rerun::new(
                DeadFrameStorePass,
                DEAD_FRAME_STORE_AFTER_VEC,
                &[],
            )),
            Box::new(pass::Rerun::new(
                FrameElisionPass,
                FRAME_ELISION_AFTER_VEC,
                &[],
            )),
            // After the group, on settled IR: a returned `select` becomes
            // the `if`/`else` it compiled from, so each arm can be the
            // `Ok`/`Err` it is.
            Box::new(SelectReturnPass),
            // Again, on settled IR. A return whose encode has collapsed
            // now *is* the value, so its type names the return type; the
            // first run saw only the helper call. Parameters were already
            // recovered up there, where the gates could still use them.
            Box::new(pass::Rerun::new(
                SpecFromGuardsPass,
                SPEC_FROM_GUARDS_AFTER_ELISION,
                &[],
            )),
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
        // elision with the scope-exit pair at its tail. Both converge
        // because every member strictly reduces a measure — nesting depth
        // for the first; live marshalling bindings and labeled exits for
        // the second. `marshalling_group_covers_exactly_the_elision_passes`
        // and `scope_exit_pair_shares_the_elision_group` pin those ranges
        // by pass name, so inserting a pass above one fails a test instead
        // of silently shifting the window.
        vec![1..7, 32..76],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixpoint group is a pair of raw indices into the manifest, so
    /// adding a pass anywhere above one silently moves the window over the
    /// wrong passes. This pins where the scope-exit pair lives by name. It
    /// matters more than most: its group must stay clear of
    /// `GuardClausePass`, whose transform is the inverse of
    /// `ScopeIfElsePass`.
    #[test]
    fn scope_exit_pair_shares_the_elision_group() {
        let pipeline = default_high_pipeline();
        let names: Vec<&str> = pipeline.pass_names();
        let group = pipeline
            .fixpoint_groups()
            .iter()
            .find(|r| names[(*r).clone()].contains(&refine::SCOPE_FALLTHROUGH_PASS_NAME))
            .expect("the scope-exit pair is in a fixpoint group");
        let members = &names[group.clone()];
        assert_eq!(
            &members[members.len() - 2..],
            &[refine::SCOPE_FALLTHROUGH_PASS_NAME, refine::SCOPE_IF_ELSE_PASS_NAME],
            "the pair closes its group"
        );
        // The inverse transform must not share the group.
        assert!(
            !members.contains(&refine::GUARD_CLAUSE_PASS_NAME),
            "guard-clause hoisting is ScopeIfElsePass's inverse and would oscillate"
        );
    }

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
                marshalling::wide_codec::PASS_NAME,
                marshalling::forward::PASS_NAME,
                refine::CONST_BRANCH_PASS_NAME,
                refine::TRIVIAL_PHI_PASS_NAME,
                refine::WIDTH_FOLD_PASS_NAME,
                PANIC_RECOVER_AFTER_RECOVERY,
                refine::OVERFLOW_GUARD_PASS_NAME,
                marshalling::guard::PASS_NAME,
                interproc::const_return::PASS_NAME,
                interproc::wide_promote::PASS_NAME,
                interproc::wide_param::PASS_NAME,
                refine::WIDE_ARITH_PASS_NAME,
                refine::WIDE_PHI_PASS_NAME,
                refine::WIDE_ZERO_PASS_NAME,
                refine::WIDE_COMPARE_PASS_NAME,
                refine::WIDE_SELECT_PASS_NAME,
                interproc::inline::PASS_NAME,
                CONST_PROP_AFTER_INLINE,
                TTL_AFTER_INLINE,
                ENUM_KEY_AFTER_INLINE,
                marshalling::bool_codec::PASS_NAME,
                marshalling::typed_read::PASS_NAME,
                marshalling::scalar_decode::PASS_NAME,
                marshalling::folded_encode::PASS_NAME,
                marshalling::option_sret::PASS_NAME,
                marshalling::option_default::PASS_NAME,
                marshalling::udt_decode::PASS_NAME,
                marshalling::udt_encode::PASS_NAME,
                SPEC_FROM_GUARDS_ON_FIELDS,
                marshalling::field_type::PASS_NAME,
                interproc::struct_arg::PASS_NAME,
                marshalling::enum_discriminant::PASS_NAME,
                marshalling::enum_encode::PASS_NAME,
                marshalling::option_unwrap::PASS_NAME,
                marshalling::key_construction::PASS_NAME,
                marshalling::client_args::PASS_NAME,
                marshalling::dead_store::PASS_NAME,
                marshalling::frame::PASS_NAME,
                arith::wide_fold::PASS_NAME,
                POLARITY_AFTER_ELISION,
                refine::SCOPE_FALLTHROUGH_PASS_NAME,
                refine::SCOPE_IF_ELSE_PASS_NAME,
            ],
        );
    }
}
