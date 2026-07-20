//! Coverage metrics for `sordec coverage <wasm>`.
//!
//! Computes a [`CoverageReport`] from a parsed + lifted contract,
//! describing how much of the contract our pipeline currently
//! understands. Three primary axes:
//!
//! 1. **Host-call recognition** — fraction of imported-function (host)
//!    calls our vendored 26.1.2 catalog names. Direct measure of
//!    catalog freshness; degrades only when a contract uses calls
//!    introduced after the vendored protocol version.
//! 2. **Lift completeness** — fraction of functions waffle lifted
//!    without lift-stage diagnostics. (The recogniser-pipeline misses
//!    that W6 wired into [`sordec_common::LiftDiagnosticCode`] surface
//!    separately, in the diagnostics section below.)
//! 3. **Parse + metadata health** — boolean checks (did the WASM parse,
//!    was Soroban metadata present and decoded). Always-yes for real
//!    contracts; tracked for completeness.
//!
//! Plus the **structuring** section (A6/W8): control-flow structuring
//! coverage — per-function structured ratio, the loop-kind breakdown,
//! recovered `match` count, the labeled-exit readability tax, and the
//! region-refinement / declutter / treeify counters — also drawn from
//! the pipeline's [`PassMetrics`](sordec_passes::PassMetrics).
//!
//! Plus the **recognition** section (W7): per-pattern recovery counts
//! and ratios (storage tiers, enum keys, TTL, client calls, dispatcher,
//! auth, events, collections, panics, Val boilerplate) drawn from the
//! pipeline's [`PassMetrics`](sordec_passes::PassMetrics), and a
//! two-number **semantic recovery** headline. Plus context counters
//! (total operators broken down by call kind).
//!
//! ## Output formats
//!
//! Two renderers consume the same [`CoverageReport`]:
//!
//! - [`render_text`] — human-readable layout for terminals.
//! - [`render_json`] — machine-readable, schema-stable. The schema is
//!   *append-only* across releases: future Phase 4 dashboards may add
//!   fields, but no field already in the schema is removed or renamed.
//!
//! ## Why this lives in `sordec-cli`, not in `sordec-passes`
//!
//! Coverage is a read-only inspection, not a transformation. There is no
//! `Pass<LiftedIr>` here, no IR mutation. The CLI is the only consumer
//! today; if Phase 4's regression dashboard wants the metric in a
//! library context, the module migrates wholesale to `sordec-driver`
//! with no API changes — `compute_coverage` is already a pure function
//! over `&LiftedIr` + diagnostic slices.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::Path;

use serde::Serialize;
use sordec_common::{Diagnostic, DiagnosticCode, Location};
use sordec_ir::{ImportKind, LiftedIr, LiftedValueDef};
use sordec_passes::{host_calls, metrics_catalog as mc};
use waffle::entity::EntityRef as _;

// ---------------------------------------------------------------------
// Public report types
// ---------------------------------------------------------------------

/// Top-level coverage report for a single contract.
///
/// Field ordering matches the rendered text output (top-to-bottom)
/// rather than alphabetical. JSON serialisation respects the same
/// order.
#[derive(Debug, Clone, Serialize)]
pub struct CoverageReport {
    /// Path of the inspected WASM file, as supplied on the command line.
    pub wasm: String,
    /// Identifier of the host-call catalog used to compute recognition.
    /// Mirrors [`sordec_passes::CATALOG_VERSION`].
    pub catalog: &'static str,
    /// Parse-stage health.
    pub parse: ParseHealth,
    /// Metadata-stage health.
    pub metadata: MetadataHealth,
    /// Lift-stage coverage.
    pub lift: LiftCoverage,
    /// Host-call recognition counts and unrecognised breakdown.
    pub host_calls: HostCallCoverage,
    /// Operator counts by kind. Closed total: the four numbered buckets
    /// sum to `total`.
    pub operators: OperatorBreakdown,
    /// Control-flow structuring coverage (A6): per-function structured
    /// ratio, loop-kind breakdown, recovered switches, labeled-exit tax,
    /// and the region-refinement / declutter / treeify counters.
    pub structuring: StructuringCoverage,
    /// Per-pattern recognition counts and ratios (F1–F8 + beyond-kickoff).
    pub recognition: RecognitionCoverage,
    /// The two-number semantic-recovery headline (W7).
    pub headline: HeadlineCoverage,
    /// Per-code counts of recogniser-pipeline diagnostics (E3/F9).
    pub diagnostics: DiagnosticCoverage,
}

/// Parse-stage health.
///
/// `ok` is `true` iff no parse-level diagnostics were surfaced. In v0
/// [`DiagnosticCode::Parse`] exists as an explicit artifact slot but is
/// uninhabited, so `ok` is effectively always `true`; the field is
/// reserved for symmetry with [`MetadataHealth`] and for the Phase 4
/// dashboard.
#[derive(Debug, Clone, Serialize)]
pub struct ParseHealth {
    /// `true` when `diagnostics == 0`.
    pub ok: bool,
    /// Number of parse-level diagnostics.
    pub diagnostics: usize,
}

/// Metadata-stage health.
#[derive(Debug, Clone, Serialize)]
pub struct MetadataHealth {
    /// `true` iff `SorobanFacts` was successfully decoded from the
    /// WASM. `false` for stripped contracts and for non-Soroban WASM.
    pub present: bool,
    /// Number of metadata-level diagnostics surfaced during decoding
    /// (e.g. `UnresolvedTypeReference`, `DuplicateTypeName`).
    pub diagnostics: usize,
}

/// Lift-stage coverage.
///
/// `completeness` is `null` when `functions_total == 0` (a degenerate
/// case for non-Soroban WASM with zero local functions); never `NaN`.
#[derive(Debug, Clone, Serialize)]
pub struct LiftCoverage {
    /// Total number of local functions in the lifted IR.
    pub functions_total: usize,
    /// Number of functions with at least one [`Diagnostic`] attached
    /// via [`Location::Function`] / [`Location::Block`] / [`Location::Value`].
    pub functions_with_diagnostics: usize,
    /// Fraction `(functions_total - functions_with_diagnostics) / functions_total`.
    /// `None` when `functions_total == 0`.
    pub completeness: Option<f64>,
}

/// Host-call recognition counts.
///
/// `ratio` is `null` when `total == 0` (degenerate inputs such as
/// non-Soroban WASM with no imported host calls); never `NaN`.
#[derive(Debug, Clone, Serialize)]
pub struct HostCallCoverage {
    /// Total number of `Operator::Call` instructions targeting an
    /// imported (host) function.
    pub total: usize,
    /// Subset of `total` for which the host-call catalog returned a
    /// friendly name.
    pub recognized: usize,
    /// `recognized / total`; `None` when `total == 0`.
    pub ratio: Option<f64>,
    /// Per-`(module, name)` counts of unrecognised host calls. Empty
    /// when every host call resolved cleanly. Sorted by descending
    /// count, then by `(module, name)` ascending for tie-break.
    pub unrecognized: Vec<UnrecognizedCall>,
}

/// One unrecognised `(module, name)` pair with its observed frequency.
#[derive(Debug, Clone, Serialize)]
pub struct UnrecognizedCall {
    /// WASM `import.module` (e.g. `"l"`).
    pub module: String,
    /// WASM `import.name` (e.g. `"9"`).
    pub name: String,
    /// Number of times this `(module, name)` pair was called across
    /// the whole module.
    pub count: usize,
}

/// Operator counts broken down by kind. Total is the sum of the four
/// numbered buckets, so the breakdown is closed-totaled and useful as
/// a sanity check.
#[derive(Debug, Clone, Serialize)]
pub struct OperatorBreakdown {
    /// Sum of the four buckets below.
    pub total: usize,
    /// `Operator::Call` targeting an imported (host) function.
    pub call_to_import: usize,
    /// `Operator::Call` targeting a local function.
    pub call_to_local: usize,
    /// `Operator::CallIndirect` (table dispatch) or `Operator::CallRef`
    /// (typed funcref dispatch). Both are "indirect" — neither
    /// resolves statically to a single function id without
    /// devirtualisation, which is post-Phase-1.
    pub call_indirect: usize,
    /// Every other operator (arithmetic, memory, control flow, etc.).
    pub other: usize,
}

/// Control-flow structuring coverage (A6/W8).
///
/// Drawn from the pipeline's structuring counters
/// ([`sordec_passes::metrics_catalog`]): the terminal
/// `StructuringCensusPass` supplies the census fields (functions, loops,
/// switches, labeled exits) over the *settled* region trees, while the
/// refinement / declutter / treeify passes supply the rewrite-event
/// counters. Grouped by A6 deliverable so each subsection maps to a
/// milestone bullet; every counter appears exactly once.
#[derive(Debug, Clone, Serialize)]
pub struct StructuringCoverage {
    /// Per-function structured ratio (`%functions_structured`).
    pub functions: StructuredFunctions,
    /// Per-`LoopKind` breakdown + loop→shape classification ratio.
    pub loops: LoopClassification,
    /// Recovered `match` count + the switch-refinement counters.
    pub switches: SwitchRecovery,
    /// Trap-leaf refinement counts (inline / duplicate / panic typing).
    pub traps: TrapRefinement,
    /// Labeled break / continue census — the readability-tax meter.
    pub labeled_exits: LabeledExits,
    /// The remaining region-refinement counters (guards, polarity, &&).
    pub refinements: RefinementCounts,
    /// Lifted-IR de-cluttering counters (W3), the structuring precursor.
    pub declutter: DeclutterCounts,
    /// Treeification (inlinability) analysis counters (B6).
    pub treeify: TreeifyCounts,
}

/// Per-function structuring outcome (`%functions_structured`).
#[derive(Debug, Clone, Serialize)]
pub struct StructuredFunctions {
    /// Local functions in the high IR (the ratio denominator).
    pub total: i64,
    /// Functions with zero `Region::Unstructured` nodes (the numerator).
    pub structured: i64,
    /// `structured / total`; `None` when `total == 0`. Corpus-locked to
    /// 1.0 (K3).
    pub ratio: Option<f64>,
    /// `Region::Unstructured` *nodes* across all functions (the
    /// `structuring_fallback` counter). Node-level, so it may exceed
    /// `total - structured` when one function has several fragments.
    pub fallback_regions: i64,
}

/// Per-`LoopKind` census + classification ratio.
///
/// `total` is the closed sum of the five kinds; a new `LoopKind` variant
/// is a compile error in the census pass, so the breakdown stays
/// exhaustive.
#[derive(Debug, Clone, Serialize)]
pub struct LoopClassification {
    /// All `Region::Loop` nodes (sum of the five kinds below).
    pub total: i64,
    /// Loops rendered as `while cond { .. }`.
    pub while_top: i64,
    /// Rotated do-while loops (exit test at the latch).
    pub do_while_bottom: i64,
    /// Guarded rotated do-while loops re-derivable as `while` / `for`.
    pub guarded_do_while: i64,
    /// Loops with no conditional exit (`loop { .. }`).
    pub infinite: i64,
    /// Loops the classifier soundly left unproven (never guessed).
    pub unclassified: i64,
    /// `(total - unclassified) / total`; `None` when there are no loops.
    pub classified_ratio: Option<f64>,
}

/// Recovered-`match` count and the switch-refinement counters.
#[derive(Debug, Clone, Serialize)]
pub struct SwitchRecovery {
    /// `Region::Switch` nodes — recovered `match` constructs.
    pub recovered: i64,
    /// Switches linked to a recovered `SymbolDispatch` enum (D6) — arms
    /// render by variant name.
    pub dispatch_linked: i64,
    /// Arms folded into the wildcard because they equal the default (D5).
    pub arms_deduped: i64,
}

/// Trap-leaf refinement counts (D2 / D8).
#[derive(Debug, Clone, Serialize)]
pub struct TrapRefinement {
    /// Break sites rewritten into an inline copy of a shared bare
    /// terminator (LLVM tail-merge undone).
    pub inlined: i64,
    /// Break sites rewritten into a fresh-id duplicate of a
    /// binding-carrying shared trap block (D2-ext).
    pub duplicated: i64,
    /// Shared out-blocks left labeled because their bindings failed the
    /// duplication gates — the remaining-work signal.
    pub shared_with_bindings: i64,
    /// Trap leaves typed as bare `panic!()` sites (D8).
    pub bare_panics: i64,
    /// Trap leaves typed as unwrap-shaped, tag-checked panics (D8).
    pub unwraps: i64,
}

/// Labeled break / continue census — the readability-tax meter.
#[derive(Debug, Clone, Serialize)]
pub struct LabeledExits {
    /// `Region::Break` nodes (all render label-carrying).
    pub breaks: i64,
    /// `Region::Continue` nodes. Upper bound on *rendered* labeled
    /// continues: a `WhileTop` loop's back-edge continue is elided by
    /// `render_while` but still counted here.
    pub continues: i64,
}

/// The remaining region-refinement counters not grouped above.
#[derive(Debug, Clone, Serialize)]
pub struct RefinementCounts {
    /// Guard conditions inverted into canonical exit-in-`then` form (D4).
    pub polarity_flipped: i64,
    /// `else` bodies hoisted out from under a terminating `then` (D1).
    pub guards_hoisted: i64,
    /// Shared-else diamonds merged into one `&&` guard (D7).
    pub and_merged: i64,
    /// Diamonds matching the D7 shape but blocked by a gate — the
    /// widening signal.
    pub and_merge_blocked: i64,
    /// Loops proven to a source shape and `LoopKind`-tagged (D3). Should
    /// equal `loops.total - loops.unclassified`.
    pub loops_classified: i64,
    /// Client-call element lists recovered by the copy-loop trace (D9).
    pub client_args_via_copy_loop: i64,
}

/// Lifted-IR de-cluttering counters (W3).
#[derive(Debug, Clone, Serialize)]
pub struct DeclutterCounts {
    /// Alias uses rewritten to their terminal definition.
    pub aliases_resolved: i64,
    /// Trivial block parameters removed (Braun-style pruning).
    pub phis_pruned: i64,
    /// Edges retargeted past empty forwarding blocks.
    pub jumps_threaded: i64,
    /// Branches to empty return blocks turned into `Return`.
    pub returns_inlined: i64,
    /// Branches to empty `Unreachable` blocks inlined.
    pub traps_inlined: i64,
    /// Single-predecessor block pairs spliced.
    pub chains_merged: i64,
    /// Unreachable blocks cleared to tombstones.
    pub dead_blocks_cleared: i64,
    /// Pure-total zero-use instructions removed from the schedule.
    pub dead_values_unscheduled: i64,
}

/// Treeification (inlinability) analysis counters (B6).
#[derive(Debug, Clone, Serialize)]
pub struct TreeifyCounts {
    /// Bindings classified `Inline` (pure-total, single live use).
    pub inline: i64,
    /// Single-live-use bindings pinned only by their effects — the K4
    /// readability tax.
    pub pinned_single_use: i64,
    /// De-clutter residue bindings hidden as `Dead`.
    pub dead_residue: i64,
}

/// Per-pattern recognition counts and ratios (spec F1–F8, plus the
/// enum-key / TTL / dispatcher ratios W7 added beyond the kickoff list).
///
/// Drawn from the recogniser pipeline's
/// [`PassMetrics`](sordec_passes::PassMetrics) counters, keyed on
/// [`sordec_passes::metrics_catalog`]. **Ratios render only where a
/// pass emits a real miss counter** (storage tier, enum key, TTL,
/// client typing, dispatcher); every other group is a count plus a note
/// saying where its misses would surface — deriving a denominator any
/// other way would mean inventing the fact the pipeline failed to
/// recover (the no-guessing principle). Ratios are `None` on a zero
/// denominator, never `NaN`.
#[derive(Debug, Clone, Serialize)]
pub struct RecognitionCoverage {
    /// F1 — storage durability-tier resolution + CRUD/TTL op counts.
    pub storage: StorageRecognition,
    /// Enum storage-key naming ratio (beyond-kickoff).
    pub enum_keys: EnumKeyRecognition,
    /// TTL ledger-amount resolution ratio (D3; beyond-kickoff).
    pub ttl: TtlRecognition,
    /// F5 — cross-contract client-call typing.
    pub client_calls: ClientCallRecognition,
    /// Symbol-dispatcher case-table resolution ratio (C25; beyond-kickoff).
    pub dispatcher: DispatcherRecognition,
    /// F2 — auth pattern counts (misses surface as unrecognised host calls).
    pub auth: AuthRecognition,
    /// F3 — event-emission count (flavor split is Phase-3 emit).
    pub events: EventRecognition,
    /// F4 — collection constructor/op counts (element expansion is W9).
    pub collections: CollectionRecognition,
    /// F6 — typed-panic count (bare panic!/unwrap detection is Phase-3).
    pub panics: PanicRecognition,
    /// F7 — wide-arithmetic fusion (deferred; C19).
    pub wide_arithmetic: WideArithRecognition,
    /// F8 — collapsed Val-boilerplate site counts.
    pub val_boilerplate: ValBoilerplateRecognition,
}

/// F1 — storage tier resolution ratio + per-op CRUD/TTL counts.
#[derive(Debug, Clone, Serialize)]
pub struct StorageRecognition {
    /// Storage ops whose durability tier resolved to a concrete tier.
    pub tiers_resolved: i64,
    /// Storage ops whose durability arg stayed a typed `Unknown`.
    pub tiers_unknown: i64,
    /// `tiers_resolved / (tiers_resolved + tiers_unknown)`; `None` when zero.
    pub tier_ratio: Option<f64>,
    /// `get` / `set` / `has` / `remove` / `extend_ttl` op counts.
    pub ops: StorageOps,
}

/// Per-op storage CRUD/TTL counts.
#[derive(Debug, Clone, Serialize)]
pub struct StorageOps {
    pub get: i64,
    pub set: i64,
    pub has: i64,
    pub remove: i64,
    pub extend_ttl: i64,
}

/// Enum storage-key naming ratio.
#[derive(Debug, Clone, Serialize)]
pub struct EnumKeyRecognition {
    /// Keys named against the `#[contracttype]` spec.
    pub named: i64,
    /// Keys the recognizer soundly declined to name.
    pub unresolved: i64,
    /// Constructor sites matched (payload-carrying variants).
    pub ctor_matched: i64,
    /// `named / (named + unresolved)`; `None` when zero.
    pub ratio: Option<f64>,
}

/// TTL ledger-amount resolution ratio (D3).
#[derive(Debug, Clone, Serialize)]
pub struct TtlRecognition {
    pub resolved: i64,
    pub unresolved: i64,
    /// `resolved / (resolved + unresolved)`; `None` when zero.
    pub ratio: Option<f64>,
}

/// F5 — cross-contract client-call typing.
#[derive(Debug, Clone, Serialize)]
pub struct ClientCallRecognition {
    /// Total invoke sites (`invoke_contract` + `try_invoke_contract`).
    pub sites: i64,
    /// Sites whose argument arity was recovered (the "typed" numerator).
    pub arity_resolved: i64,
    /// Sites whose full argument element list was recovered.
    pub args_resolved: i64,
    /// Sites matched to a known interface table (SEP-41 today).
    pub iface_matched: i64,
    /// Sites the recognizer soundly declined.
    pub unresolved: i64,
    /// `arity_resolved / sites`; `None` when zero. Numerator is arity
    /// (structural typing), not iface: a non-SEP-41 callee can never
    /// match the interface table, so using iface would penalise
    /// contracts for calling interfaces we lack tables for.
    pub typed_ratio: Option<f64>,
}

/// Symbol-dispatcher case-table resolution ratio (C25).
#[derive(Debug, Clone, Serialize)]
pub struct DispatcherRecognition {
    pub cases_resolved: i64,
    pub enum_named: i64,
    pub unresolved: i64,
    /// `cases_resolved / (cases_resolved + unresolved)`; `None` when zero.
    pub ratio: Option<f64>,
}

/// F2 — auth pattern counts. No ratio: an unrecognised auth call would
/// survive as a `SemanticOp::Unknown` and surface in the diagnostics
/// section as `lift::unrecognised_host_call`, not as a typed miss here.
#[derive(Debug, Clone, Serialize)]
pub struct AuthRecognition {
    pub require_auth: i64,
    pub require_auth_for_args: i64,
    pub authorize_as_curr_contract: i64,
    pub address_conversion: i64,
    /// Admin-from-instance-storage gates recognised (W1 auth-flow).
    pub admin_gates: i64,
}

/// F3 — event emission count. The raw / `TokenUtils` / `#[contractevent]`
/// flavor split is a Phase-3 emit-side distinction (all three compile to
/// one host call; C14), so it is not a Phase-2 recognition ratio.
#[derive(Debug, Clone, Serialize)]
pub struct EventRecognition {
    pub published: i64,
    /// Marker that the flavor split is deferred to the Phase-3 emitter.
    pub flavor_split: &'static str,
}

/// F4 — collection constructor / op counts. No ratio: literal element
/// expansion (`vec![&env, a, b]` contents) is W9-deferred structuring
/// (C9), not a Phase-2 recognition miss.
#[derive(Debug, Clone, Serialize)]
pub struct CollectionRecognition {
    pub vec_new: i64,
    pub vec_op: i64,
    pub map_new: i64,
    pub map_op: i64,
    pub buf_op: i64,
}

/// F6 — typed-panic count. Bare `panic!` / `unwrap` detection is
/// control-flow shaped (C16/C17) and lands with Phase-3 structuring, so
/// there is no Phase-2 denominator.
#[derive(Debug, Clone, Serialize)]
pub struct PanicRecognition {
    /// `panic_with_error` / `fail_with_error` sites recognised.
    pub typed: i64,
    /// Marker that bare-panic/unwrap detection is deferred.
    pub untyped_detection: &'static str,
}

/// F7 — wide-arithmetic fusion. Deferred (C19): multi-block carry chains
/// need structuring; the corpus's i128 flows go through host objects and
/// are already recognised as such. Reports zero with a deferral pointer.
#[derive(Debug, Clone, Serialize)]
pub struct WideArithRecognition {
    pub fused: i64,
    /// Deferral pointer (the closeout item that tracks it).
    pub deferred: &'static str,
}

/// F8 — collapsed Val-boilerplate site counts. No ratio by construction:
/// a *missed* pure-bit-op pattern is indistinguishable from ordinary
/// arithmetic, so there is no honest denominator; the `dump-hir` e2e
/// locks are the real guard that these collapse.
#[derive(Debug, Clone, Serialize)]
pub struct ValBoilerplateRecognition {
    pub object: i64,
    pub tag_check: i64,
    pub encode_small: i64,
    pub encode_u32: i64,
    pub decode_small: i64,
    pub compare: i64,
}

/// The two-number semantic-recovery headline (W7).
///
/// Deliberately **not** blended into one scalar: the two axes measure
/// different things and a single number would either bury the recognition
/// win or overstate resolution.
///
/// - **host interactions** — did the pipeline turn each host-boundary
///   call into a named semantic operation? (Phase-2's recognition claim.)
/// - **deep facts** — of the sub-facts the recognisers *attempted* to
///   resolve (storage tier, enum key, TTL amount, client arity, dispatch
///   cases), how many resolved? Every miss is a sound decline carrying a
///   located diagnostic (see the diagnostics section), not a crash or a
///   guess.
///
/// Neither is the RFP's contractual accuracy number: structural accuracy
/// vs source is a Phase-4 scoring artifact over Phase-3 emitter output.
/// [`note`](Self::note) states that inline.
#[derive(Debug, Clone, Serialize)]
pub struct HeadlineCoverage {
    /// Host-boundary calls the pipeline recognised into semantic ops.
    pub host_interactions: HostInteractions,
    /// Deep sub-facts resolved out of those attempted.
    pub deep_facts: DeepFacts,
    /// Plain-language pointer to the Phase-3/4 accuracy metric.
    pub note: &'static str,
}

/// Host-boundary call recognition — the pipeline's verdict.
#[derive(Debug, Clone, Serialize)]
pub struct HostInteractions {
    /// Host-call sites turned into a named semantic op
    /// (`total` − surviving `Unknown`s).
    pub recognized: i64,
    /// Total host-boundary call sites.
    pub total: i64,
    /// `recognized / total`; `None` when the contract has no host calls.
    pub ratio: Option<f64>,
}

/// Deep-fact resolution — summed over the five
/// [`metrics_catalog::DEEP_FACT_PAIRS`](sordec_passes::metrics_catalog::DEEP_FACT_PAIRS).
#[derive(Debug, Clone, Serialize)]
pub struct DeepFacts {
    /// Sub-facts resolved to a concrete value.
    pub resolved: i64,
    /// Sub-facts the recognisers attempted (resolved + soundly declined).
    pub attempted: i64,
    /// `resolved / attempted`; `None` when nothing was attempted.
    pub ratio: Option<f64>,
}

/// Per-code counts of the diagnostics the recogniser pipeline surfaced
/// (spec E3/F9) — every recogniser-miss and every unrecognised host call,
/// bucketed by their stable `LiftDiagnosticCode`.
///
/// `total == 0` for a fully-recovered contract. Distinct from the
/// lift-stage [`LiftCoverage`] diagnostics, which are emitted before
/// recognition; this section reflects the post-recognition pipeline.
#[derive(Debug, Clone, Serialize)]
pub struct DiagnosticCoverage {
    /// Sum of all per-code counts.
    pub total: usize,
    /// One entry per diagnostic code that fired, sorted by descending
    /// count then code (empty when the contract is fully recovered).
    pub by_code: Vec<DiagnosticCodeCount>,
}

/// One diagnostic code and how many times the pipeline emitted it.
#[derive(Debug, Clone, Serialize)]
pub struct DiagnosticCodeCount {
    /// Stable `<layer>::snake_case` code identifier
    /// ([`sordec_common::DiagnosticCode::key`]).
    pub code: String,
    /// Number of diagnostics with this code.
    pub count: usize,
}

// ---------------------------------------------------------------------
// Compute
// ---------------------------------------------------------------------

/// Compute a [`CoverageReport`] from a successfully parsed + lifted
/// contract.
///
/// `front_diagnostics` is borrowed from
/// `sordec_frontend::ParseOutput.diagnostics` — it is partitioned
/// internally into parse vs metadata buckets by [`DiagnosticCode`]
/// variant.
///
/// `lift_diagnostics` is borrowed from
/// `sordec_passes::LiftOutput.diagnostics` — lift-stage conditions,
/// distinct from the recogniser-pipeline diagnostics aggregated in
/// `recognizer_diagnostics`.
///
/// `metric_totals` is borrowed from
/// [`sordec_passes::PipelineReport::metric_totals`] — the per-pass
/// counter sums that back the W7 recognition + headline sections.
///
/// This function is pure (no I/O) and total — it does not panic on
/// any well-formed input, including contracts with zero functions or
/// zero host calls.
#[must_use]
pub fn compute_coverage(
    wasm_path: &Path,
    front_diagnostics: &[Diagnostic],
    metadata_present: bool,
    lifted: &LiftedIr,
    lift_diagnostics: &[Diagnostic],
    recognizer_diagnostics: &BTreeMap<&'static str, usize>,
    metric_totals: &BTreeMap<&'static str, i64>,
) -> CoverageReport {
    let metadata_diag_count = front_diagnostics
        .iter()
        .filter(|d| matches!(&d.code, DiagnosticCode::Metadata(_)))
        .count();
    let parse_diag_count = front_diagnostics.len() - metadata_diag_count;

    let imported_func_count: usize = lifted
        .facts
        .imports
        .iter()
        .filter(|imp| matches!(imp.kind, ImportKind::Func(_)))
        .count();

    // Walk every value across every local function. Operator counts
    // accumulate into the breakdown; for `Call` to imports we also
    // tally recognised-vs-unrecognised host calls.
    let mut total_ops = 0usize;
    let mut call_to_import = 0usize;
    let mut call_to_local = 0usize;
    let mut call_indirect = 0usize;
    let mut other_ops = 0usize;
    let mut recognized = 0usize;
    let mut unrecognized_counts: BTreeMap<(String, String), usize> = BTreeMap::new();

    for func in &lifted.functions {
        for (_value_id, value) in func.values.iter() {
            if let LiftedValueDef::Operator { op, .. } = &value.def {
                total_ops += 1;
                match op.0 {
                    waffle::Operator::Call { function_index } => {
                        let idx = function_index.index();
                        if idx < imported_func_count {
                            call_to_import += 1;
                            if let Some(import) = lifted.facts.imports.get(idx) {
                                if host_calls::resolve(&import.module, &import.name).is_some() {
                                    recognized += 1;
                                } else {
                                    *unrecognized_counts
                                        .entry((import.module.clone(), import.name.clone()))
                                        .or_insert(0) += 1;
                                }
                            }
                        } else {
                            call_to_local += 1;
                        }
                    }
                    waffle::Operator::CallIndirect { .. } | waffle::Operator::CallRef { .. } => {
                        call_indirect += 1;
                    }
                    _ => {
                        other_ops += 1;
                    }
                }
            }
        }
    }

    // Lift completeness — count functions with any diagnostic attached
    // via Location::{Function, Block, Value}. Today the input is
    // always empty (LiftDiagnosticCode is uninhabited), so this is
    // structurally 100%; the metric is wired so Phase 2's first
    // diagnostic surfaces immediately as a coverage drop.
    let functions_total = lifted.functions.len();
    let functions_with_diagnostics = count_functions_with_diagnostics(lift_diagnostics);
    let completeness = if functions_total == 0 {
        None
    } else {
        let clean = functions_total.saturating_sub(functions_with_diagnostics);
        Some(clean as f64 / functions_total as f64)
    };

    let host_calls_ratio = if call_to_import == 0 {
        None
    } else {
        Some(recognized as f64 / call_to_import as f64)
    };

    let unrecognized = sort_unrecognized(unrecognized_counts);

    CoverageReport {
        wasm: wasm_path.display().to_string(),
        catalog: sordec_passes::CATALOG_VERSION,
        parse: ParseHealth {
            ok: parse_diag_count == 0,
            diagnostics: parse_diag_count,
        },
        metadata: MetadataHealth {
            present: metadata_present,
            diagnostics: metadata_diag_count,
        },
        lift: LiftCoverage {
            functions_total,
            functions_with_diagnostics,
            completeness,
        },
        host_calls: HostCallCoverage {
            total: call_to_import,
            recognized,
            ratio: host_calls_ratio,
            unrecognized,
        },
        operators: OperatorBreakdown {
            total: total_ops,
            call_to_import,
            call_to_local,
            call_indirect,
            other: other_ops,
        },
        structuring: build_structuring(metric_totals),
        recognition: build_recognition(metric_totals),
        headline: build_headline(metric_totals, call_to_import),
        diagnostics: build_diagnostic_coverage(recognizer_diagnostics),
    }
}

/// Build the two-number semantic-recovery headline.
///
/// `host_call_sites` is the operator-walk count of `Call`-to-import
/// instructions (the total host-boundary interactions). The recognised
/// count subtracts the terminal scan's surviving `Unknown`s — the
/// pipeline's own recognition verdict, stricter than catalog naming.
fn build_headline(t: &BTreeMap<&'static str, i64>, host_call_sites: usize) -> HeadlineCoverage {
    let total = host_call_sites as i64;
    let unrecognised = metric(t, mc::UNRECOGNISED_HOST_CALL);
    // Saturating: the scan can never blame more sites than exist, but a
    // never-negative numerator keeps the ratio honest under any drift.
    let recognized = total.saturating_sub(unrecognised).max(0);

    // Deep facts: sum resolved / attempted over the five locked pairs.
    let mut resolved = 0i64;
    let mut attempted = 0i64;
    for &(ok, miss) in mc::DEEP_FACT_PAIRS {
        let r = metric(t, ok);
        let u = metric(t, miss);
        resolved += r;
        attempted += r + u;
    }

    HeadlineCoverage {
        host_interactions: HostInteractions {
            recognized,
            total,
            ratio: ratio(recognized, total),
        },
        deep_facts: DeepFacts {
            resolved,
            attempted,
            ratio: ratio(resolved, attempted),
        },
        note: "structural accuracy vs source (>=90% AST node-count, D4.1) \
               is a Phase-4 metric built on the Phase-3 Rust emitter — \
               not yet computable",
    }
}

/// Read a metric counter, defaulting to 0 when the pipeline never
/// emitted it (a pattern absent from this contract).
fn metric(totals: &BTreeMap<&'static str, i64>, key: &'static str) -> i64 {
    totals.get(key).copied().unwrap_or(0)
}

/// `numerator / denominator` as a fraction, or `None` when the
/// denominator is zero — the report's uniform never-`NaN` ratio policy.
fn ratio(numerator: i64, denominator: i64) -> Option<f64> {
    if denominator == 0 {
        None
    } else {
        Some(numerator as f64 / denominator as f64)
    }
}

/// Build the recognition section from the pipeline's per-pass counter
/// totals. Every counter is looked up by a `metrics_catalog` const —
/// no raw key strings here (see [`RecognitionCoverage`]).
fn build_recognition(t: &BTreeMap<&'static str, i64>) -> RecognitionCoverage {
    let tiers_resolved = metric(t, mc::STORAGE_TIER_RESOLVED);
    let tiers_unknown = metric(t, mc::STORAGE_TIER_UNKNOWN);

    let enum_named = metric(t, mc::ENUM_KEY_NAMED);
    let enum_unresolved = metric(t, mc::ENUM_KEY_UNRESOLVED);

    let ttl_resolved = metric(t, mc::TTL_RESOLVED);
    let ttl_unresolved = metric(t, mc::TTL_UNRESOLVED);

    let sites = metric(t, mc::INVOKE_CONTRACT) + metric(t, mc::TRY_INVOKE_CONTRACT);
    let arity_resolved = metric(t, mc::CLIENT_ARITY_RESOLVED);

    let cases_resolved = metric(t, mc::DISPATCHER_CASES_RESOLVED);
    let dispatcher_unresolved = metric(t, mc::DISPATCHER_UNRESOLVED);

    RecognitionCoverage {
        storage: StorageRecognition {
            tiers_resolved,
            tiers_unknown,
            tier_ratio: ratio(tiers_resolved, tiers_resolved + tiers_unknown),
            ops: StorageOps {
                get: metric(t, mc::STORAGE_GET),
                set: metric(t, mc::STORAGE_SET),
                has: metric(t, mc::STORAGE_HAS),
                remove: metric(t, mc::STORAGE_REMOVE),
                extend_ttl: metric(t, mc::STORAGE_EXTEND_TTL),
            },
        },
        enum_keys: EnumKeyRecognition {
            named: enum_named,
            unresolved: enum_unresolved,
            ctor_matched: metric(t, mc::ENUM_KEY_CTOR_MATCHED),
            ratio: ratio(enum_named, enum_named + enum_unresolved),
        },
        ttl: TtlRecognition {
            resolved: ttl_resolved,
            unresolved: ttl_unresolved,
            ratio: ratio(ttl_resolved, ttl_resolved + ttl_unresolved),
        },
        client_calls: ClientCallRecognition {
            sites,
            arity_resolved,
            args_resolved: metric(t, mc::CLIENT_ARGS_RESOLVED),
            iface_matched: metric(t, mc::CLIENT_IFACE_MATCHED),
            unresolved: metric(t, mc::CLIENT_UNRESOLVED),
            typed_ratio: ratio(arity_resolved, sites),
        },
        dispatcher: DispatcherRecognition {
            cases_resolved,
            enum_named: metric(t, mc::DISPATCHER_ENUM_NAMED),
            unresolved: dispatcher_unresolved,
            ratio: ratio(cases_resolved, cases_resolved + dispatcher_unresolved),
        },
        auth: AuthRecognition {
            require_auth: metric(t, mc::REQUIRE_AUTH),
            require_auth_for_args: metric(t, mc::REQUIRE_AUTH_FOR_ARGS),
            authorize_as_curr_contract: metric(t, mc::AUTHORIZE_AS_CURR_CONTRACT),
            address_conversion: metric(t, mc::ADDRESS_CONVERSION),
            admin_gates: metric(t, mc::AUTH_ADMIN_GATE),
        },
        events: EventRecognition {
            published: metric(t, mc::PUBLISH_EVENT),
            flavor_split: "phase-3-emit",
        },
        collections: CollectionRecognition {
            vec_new: metric(t, mc::VEC_NEW),
            vec_op: metric(t, mc::VEC_OP),
            map_new: metric(t, mc::MAP_NEW),
            map_op: metric(t, mc::MAP_OP),
            buf_op: metric(t, mc::BUF_OP),
        },
        panics: PanicRecognition {
            typed: metric(t, mc::PANIC_WITH_ERROR),
            untyped_detection: "phase-3-structuring",
        },
        wide_arithmetic: WideArithRecognition {
            fused: 0,
            deferred: "C19",
        },
        val_boilerplate: ValBoilerplateRecognition {
            object: metric(t, mc::VAL_OBJECT),
            tag_check: metric(t, mc::VAL_TAG_CHECK),
            encode_small: metric(t, mc::VAL_ENCODE_SMALL),
            encode_u32: metric(t, mc::VAL_ENCODE_U32),
            decode_small: metric(t, mc::VAL_DECODE_SMALL),
            compare: metric(t, mc::VAL_COMPARE),
        },
    }
}

/// Build the structuring section (A6) from the pipeline's per-pass
/// counter totals. Every counter is looked up by a `metrics_catalog`
/// const — no raw key strings (same discipline as [`build_recognition`]).
///
/// The census counters (`structuring_*`) come from the terminal
/// `StructuringCensusPass` and are true census values; the `refine_*` /
/// `declutter_*` / `treeify_*` counters are rewrite-event totals summed
/// across pipeline invocations. The classification ratio is derived from
/// the census, not the `refine_loops_classified` event count, so it
/// stays correct regardless of fixpoint iteration counts.
fn build_structuring(t: &BTreeMap<&'static str, i64>) -> StructuringCoverage {
    let functions_total = metric(t, mc::STRUCTURING_FUNCTIONS_TOTAL);
    let functions_structured = metric(t, mc::STRUCTURING_FUNCTIONS_STRUCTURED);

    let while_top = metric(t, mc::STRUCTURING_LOOPS_WHILE_TOP);
    let do_while_bottom = metric(t, mc::STRUCTURING_LOOPS_DO_WHILE_BOTTOM);
    let guarded_do_while = metric(t, mc::STRUCTURING_LOOPS_GUARDED_DO_WHILE);
    let infinite = metric(t, mc::STRUCTURING_LOOPS_INFINITE);
    let unclassified = metric(t, mc::STRUCTURING_LOOPS_UNCLASSIFIED);
    let loops_total = while_top + do_while_bottom + guarded_do_while + infinite + unclassified;

    StructuringCoverage {
        functions: StructuredFunctions {
            total: functions_total,
            structured: functions_structured,
            ratio: ratio(functions_structured, functions_total),
            fallback_regions: metric(t, mc::STRUCTURING_FALLBACK),
        },
        loops: LoopClassification {
            total: loops_total,
            while_top,
            do_while_bottom,
            guarded_do_while,
            infinite,
            unclassified,
            classified_ratio: ratio(loops_total - unclassified, loops_total),
        },
        switches: SwitchRecovery {
            recovered: metric(t, mc::STRUCTURING_SWITCHES),
            dispatch_linked: metric(t, mc::REFINE_DISPATCH_LINKED),
            arms_deduped: metric(t, mc::REFINE_SWITCH_ARMS_DEDUPED),
        },
        traps: TrapRefinement {
            inlined: metric(t, mc::REFINE_TRAPS_INLINED),
            duplicated: metric(t, mc::REFINE_TRAPS_DUPLICATED),
            shared_with_bindings: metric(t, mc::REFINE_SHARED_TRAP_WITH_BINDINGS),
            bare_panics: metric(t, mc::REFINE_BARE_PANICS),
            unwraps: metric(t, mc::REFINE_UNWRAPS),
        },
        labeled_exits: LabeledExits {
            breaks: metric(t, mc::STRUCTURING_LABELED_BREAKS),
            continues: metric(t, mc::STRUCTURING_LABELED_CONTINUES),
        },
        refinements: RefinementCounts {
            polarity_flipped: metric(t, mc::REFINE_POLARITY_FLIPPED),
            guards_hoisted: metric(t, mc::REFINE_GUARDS_HOISTED),
            and_merged: metric(t, mc::REFINE_AND_MERGED),
            and_merge_blocked: metric(t, mc::REFINE_AND_MERGE_BLOCKED),
            loops_classified: metric(t, mc::REFINE_LOOPS_CLASSIFIED),
            client_args_via_copy_loop: metric(t, mc::CLIENT_ARGS_VIA_COPY_LOOP),
        },
        declutter: DeclutterCounts {
            aliases_resolved: metric(t, mc::DECLUTTER_ALIASES_RESOLVED),
            phis_pruned: metric(t, mc::DECLUTTER_PHIS_PRUNED),
            jumps_threaded: metric(t, mc::DECLUTTER_JUMPS_THREADED),
            returns_inlined: metric(t, mc::DECLUTTER_RETURNS_INLINED),
            traps_inlined: metric(t, mc::DECLUTTER_TRAPS_INLINED),
            chains_merged: metric(t, mc::DECLUTTER_CHAINS_MERGED),
            dead_blocks_cleared: metric(t, mc::DECLUTTER_DEAD_BLOCKS_CLEARED),
            dead_values_unscheduled: metric(t, mc::DECLUTTER_DEAD_VALUES_UNSCHEDULED),
        },
        treeify: TreeifyCounts {
            inline: metric(t, mc::TREEIFY_INLINE),
            pinned_single_use: metric(t, mc::TREEIFY_PINNED_SINGLE_USE),
            dead_residue: metric(t, mc::TREEIFY_DEAD_RESIDUE),
        },
    }
}

/// Turn the pipeline's per-code diagnostic counts into the report
/// section: total plus a list sorted by descending count, then code.
fn build_diagnostic_coverage(counts: &BTreeMap<&'static str, usize>) -> DiagnosticCoverage {
    let total = counts.values().sum();
    let mut by_code: Vec<DiagnosticCodeCount> = counts
        .iter()
        .map(|(&code, &count)| DiagnosticCodeCount {
            code: code.to_string(),
            count,
        })
        .collect();
    by_code.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.code.cmp(&b.code)));
    DiagnosticCoverage { total, by_code }
}

/// Count distinct functions that any diagnostic blames via a
/// function-scoped [`Location`].
///
/// A diagnostic without a `Location` (or with `Location::CustomSection`)
/// is module-level and does not contribute to per-function coverage.
fn count_functions_with_diagnostics(diagnostics: &[Diagnostic]) -> usize {
    let mut blamed = std::collections::BTreeSet::new();
    for d in diagnostics {
        match &d.location {
            Some(Location::Function(func)) => {
                blamed.insert(*func);
            }
            Some(Location::Block { func, .. }) => {
                blamed.insert(*func);
            }
            Some(Location::Value { func, .. }) => {
                blamed.insert(*func);
            }
            // Module-level (CustomSection) or unspecified — does not
            // contribute to per-function coverage.
            _ => {}
        }
    }
    blamed.len()
}

/// Sort unrecognised entries by descending count, with `(module, name)`
/// ascending as the tie-break. Stable across runs — important for the
/// e2e tests and for any diff-based tooling layered on the JSON.
fn sort_unrecognized(counts: BTreeMap<(String, String), usize>) -> Vec<UnrecognizedCall> {
    let mut entries: Vec<UnrecognizedCall> = counts
        .into_iter()
        .map(|((module, name), count)| UnrecognizedCall {
            module,
            name,
            count,
        })
        .collect();
    entries.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then_with(|| a.module.cmp(&b.module))
            .then_with(|| a.name.cmp(&b.name))
    });
    entries
}

// ---------------------------------------------------------------------
// Render: text
// ---------------------------------------------------------------------

/// Render a [`CoverageReport`] in human-readable text form.
///
/// # Errors
///
/// Returns the underlying [`io::Error`] when writing to `out` fails.
pub fn render_text(out: &mut impl Write, r: &CoverageReport) -> io::Result<()> {
    let display_name = Path::new(&r.wasm)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(&r.wasm);

    writeln!(out, "coverage report — {display_name}")?;
    writeln!(out, "  catalog:         {}", r.catalog)?;

    writeln!(
        out,
        "  parse:           {} ({} {})",
        if r.parse.ok { "ok" } else { "had diagnostics" },
        r.parse.diagnostics,
        plural(r.parse.diagnostics, "diagnostic"),
    )?;

    writeln!(
        out,
        "  metadata:        {} ({} {})",
        if r.metadata.present {
            "present"
        } else {
            "absent"
        },
        r.metadata.diagnostics,
        plural(r.metadata.diagnostics, "diagnostic"),
    )?;

    let lift_pct = match r.lift.completeness {
        Some(c) => format!("{:.1}%", c * 100.0),
        None => "n/a".to_string(),
    };
    writeln!(
        out,
        "  lift:            {} {}, {} with diagnostics  ({})",
        r.lift.functions_total,
        plural(r.lift.functions_total, "function"),
        r.lift.functions_with_diagnostics,
        lift_pct,
    )?;

    if r.host_calls.total == 0 {
        writeln!(out, "  host calls:      no host calls in this contract")?;
    } else {
        let pct = match r.host_calls.ratio {
            Some(rt) => format!("{:.1}%", rt * 100.0),
            None => "n/a".to_string(),
        };
        writeln!(
            out,
            "  host calls:      {} / {} recognized               ({})",
            r.host_calls.recognized, r.host_calls.total, pct,
        )?;
        if !r.host_calls.unrecognized.is_empty() {
            writeln!(out, "                   unrecognized:")?;
            for u in &r.host_calls.unrecognized {
                writeln!(
                    out,
                    "                     host:{}:{} (\u{00d7}{})",
                    u.module, u.name, u.count
                )?;
            }
        }
    }

    writeln!(out, "  operators:       {} total", r.operators.total)?;
    writeln!(
        out,
        "                     call (import):  {:>5}",
        r.operators.call_to_import
    )?;
    writeln!(
        out,
        "                     call (local):   {:>5}",
        r.operators.call_to_local
    )?;
    writeln!(
        out,
        "                     call indirect:  {:>5}",
        r.operators.call_indirect
    )?;
    writeln!(
        out,
        "                     other:          {:>5}",
        r.operators.other
    )?;

    render_structuring(out, &r.structuring)?;
    render_recognition(out, &r.recognition)?;
    render_headline(out, &r.headline)?;

    writeln!(
        out,
        "  diagnostics:     {} total (recogniser misses)",
        r.diagnostics.total,
    )?;
    for c in &r.diagnostics.by_code {
        writeln!(out, "                     {} (\u{00d7}{})", c.code, c.count)?;
    }

    Ok(())
}

fn plural(n: usize, singular: &str) -> String {
    if n == 1 {
        singular.to_string()
    } else {
        format!("{singular}s")
    }
}

/// Format an optional ratio as a percentage, or `n/a` on a zero
/// denominator. Never emits `NaN`/`inf` (the ratio is already `None`
/// in that case).
fn fmt_pct(ratio: Option<f64>) -> String {
    match ratio {
        Some(r) => format!("{:.1}%", r * 100.0),
        None => "n/a".to_string(),
    }
}

/// Render the A6 structuring section — per-function structured ratio,
/// loop-kind breakdown, recovered switches, labeled-exit tax, and the
/// refinement / declutter / treeify counters. Fixed shape: every row
/// renders even at zero (the `loops` row degrades to `no loops`), so the
/// report stays a stable artifact.
fn render_structuring(out: &mut impl Write, s: &StructuringCoverage) -> io::Result<()> {
    writeln!(out, "  structuring:")?;

    let f = &s.functions;
    writeln!(
        out,
        "    functions:      {} / {} structured        ({})   fallback regions ×{}",
        f.structured,
        f.total,
        fmt_pct(f.ratio),
        f.fallback_regions,
    )?;

    let l = &s.loops;
    if l.total == 0 {
        writeln!(out, "    loops:          no loops in this contract")?;
    } else {
        writeln!(
            out,
            "    loops:          {} / {} classified          ({})",
            l.total - l.unclassified,
            l.total,
            fmt_pct(l.classified_ratio),
        )?;
        writeln!(
            out,
            "                    while ×{}, do_while ×{}, guarded ×{}, infinite ×{}, unclassified ×{}",
            l.while_top, l.do_while_bottom, l.guarded_do_while, l.infinite, l.unclassified,
        )?;
    }

    let sw = &s.switches;
    if sw.recovered == 0 {
        writeln!(out, "    switches:       no match sites")?;
    } else {
        writeln!(
            out,
            "    switches:       {} match recovered   (dispatch-linked ×{}, arms deduped ×{})",
            sw.recovered, sw.dispatch_linked, sw.arms_deduped,
        )?;
    }

    let tr = &s.traps;
    writeln!(
        out,
        "    traps:          inlined ×{}, duplicated ×{}, shared+bindings ×{}, panic! ×{}, unwrap ×{}",
        tr.inlined, tr.duplicated, tr.shared_with_bindings, tr.bare_panics, tr.unwraps,
    )?;

    let le = &s.labeled_exits;
    writeln!(
        out,
        "    labeled exits:  break ×{}, continue ×{}   (readability tax; while back edges not counted)",
        le.breaks, le.continues,
    )?;

    let re = &s.refinements;
    writeln!(
        out,
        "    refinements:    guards ×{}, polarity ×{}, &&-merge ×{} (blocked ×{}), loop tags ×{}, copy-loop args ×{}",
        re.guards_hoisted,
        re.polarity_flipped,
        re.and_merged,
        re.and_merge_blocked,
        re.loops_classified,
        re.client_args_via_copy_loop,
    )?;

    let dc = &s.declutter;
    writeln!(
        out,
        "    declutter:      aliases ×{}, phis ×{}, jumps ×{}, returns ×{}, traps ×{}, chains ×{}, dead blocks ×{}, dead vals ×{}",
        dc.aliases_resolved,
        dc.phis_pruned,
        dc.jumps_threaded,
        dc.returns_inlined,
        dc.traps_inlined,
        dc.chains_merged,
        dc.dead_blocks_cleared,
        dc.dead_values_unscheduled,
    )?;

    let tf = &s.treeify;
    writeln!(
        out,
        "    treeify:        inline ×{}, effect-pinned ×{}, residue ×{}",
        tf.inline, tf.pinned_single_use, tf.dead_residue,
    )?;

    Ok(())
}

/// Render the W7 recognition section — per-pattern counts and ratios.
/// Fixed shape: every row renders even at zero, so the report is a
/// stable artifact rather than a highlights reel.
fn render_recognition(out: &mut impl Write, r: &RecognitionCoverage) -> io::Result<()> {
    writeln!(out, "  recognition:")?;

    let s = &r.storage;
    writeln!(
        out,
        "    storage:        tiers {} / {} resolved     ({})",
        s.tiers_resolved,
        s.tiers_resolved + s.tiers_unknown,
        fmt_pct(s.tier_ratio),
    )?;
    writeln!(
        out,
        "                    get ×{}, set ×{}, has ×{}, remove ×{}, extend_ttl ×{}",
        s.ops.get, s.ops.set, s.ops.has, s.ops.remove, s.ops.extend_ttl,
    )?;

    let e = &r.enum_keys;
    writeln!(
        out,
        "    enum keys:      {} / {} named             ({})   ctor ×{}",
        e.named,
        e.named + e.unresolved,
        fmt_pct(e.ratio),
        e.ctor_matched,
    )?;

    let ttl = &r.ttl;
    writeln!(
        out,
        "    ttl amounts:    {} / {} resolved          ({})",
        ttl.resolved,
        ttl.resolved + ttl.unresolved,
        fmt_pct(ttl.ratio),
    )?;

    let c = &r.client_calls;
    if c.sites == 0 {
        writeln!(out, "    client calls:   no invoke sites")?;
    } else {
        writeln!(
            out,
            "    client calls:   {} / {} typed             ({})   iface ×{}, args ×{}",
            c.arity_resolved,
            c.sites,
            fmt_pct(c.typed_ratio),
            c.iface_matched,
            c.args_resolved,
        )?;
    }

    let d = &r.dispatcher;
    if d.cases_resolved + d.unresolved == 0 {
        writeln!(out, "    dispatcher:     no dispatch sites")?;
    } else {
        writeln!(
            out,
            "    dispatcher:     {} / {} cases resolved    ({})   enum ×{}",
            d.cases_resolved,
            d.cases_resolved + d.unresolved,
            fmt_pct(d.ratio),
            d.enum_named,
        )?;
    }

    let a = &r.auth;
    writeln!(
        out,
        "    auth:           require_auth ×{}, for_args ×{}, as_curr ×{}, addr_conv ×{}, admin_gate ×{}",
        a.require_auth,
        a.require_auth_for_args,
        a.authorize_as_curr_contract,
        a.address_conversion,
        a.admin_gates,
    )?;

    writeln!(
        out,
        "    events:         {} published   (flavor split: Phase-3 emit)",
        r.events.published,
    )?;

    let col = &r.collections;
    writeln!(
        out,
        "    collections:    vec ×{}, vec_op ×{}, map ×{}, map_op ×{}, buf_op ×{}",
        col.vec_new, col.vec_op, col.map_new, col.map_op, col.buf_op,
    )?;

    writeln!(
        out,
        "    panics:         {} typed   (bare panic!/unwrap: Phase-3)",
        r.panics.typed,
    )?;

    writeln!(
        out,
        "    wide arithmetic: {} fused   (deferred: {})",
        r.wide_arithmetic.fused, r.wide_arithmetic.deferred,
    )?;

    let v = &r.val_boilerplate;
    let val_total =
        v.object + v.tag_check + v.encode_small + v.encode_u32 + v.decode_small + v.compare;
    writeln!(
        out,
        "    val boilerplate: {val_total} sites collapsed   (object ×{}, tag ×{}, enc_small ×{}, enc_u32 ×{}, dec_small ×{}, cmp ×{})",
        v.object, v.tag_check, v.encode_small, v.encode_u32, v.decode_small, v.compare,
    )?;

    Ok(())
}

/// Render the two-number semantic-recovery headline.
fn render_headline(out: &mut impl Write, h: &HeadlineCoverage) -> io::Result<()> {
    writeln!(out, "  semantic recovery:")?;
    writeln!(
        out,
        "    host interactions:  {} / {} recognized       ({})",
        h.host_interactions.recognized,
        h.host_interactions.total,
        fmt_pct(h.host_interactions.ratio),
    )?;
    writeln!(
        out,
        "    deep facts:         {} / {} resolved         ({})",
        h.deep_facts.resolved,
        h.deep_facts.attempted,
        fmt_pct(h.deep_facts.ratio),
    )?;
    writeln!(out, "    note: {}", h.note)?;
    Ok(())
}

// ---------------------------------------------------------------------
// Render: JSON
// ---------------------------------------------------------------------

/// Render a [`CoverageReport`] as pretty-printed JSON.
///
/// # Errors
///
/// Returns [`serde_json::Error`] on serialisation failure (impossible
/// for the report types — every field is `Serialize`-derived from
/// trivially serialisable primitives — but propagated for caller
/// completeness).
pub fn render_json(out: &mut impl Write, r: &CoverageReport) -> serde_json::Result<()> {
    serde_json::to_writer_pretty(out, r)
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{Arena, BlockId, FuncId, IrId, ValueId};
    use sordec_ir::{
        Import, ImportKind, LiftedBlock, LiftedFunction, LiftedTerminator, LiftedType, LiftedValue,
        MemoryImage, WasmFacts, WasmOp,
    };

    /// Build a minimal `LiftedIr` with the supplied imports and no
    /// functions. Useful for shape tests that don't exercise op
    /// counting.
    fn empty_lifted_ir(imports: Vec<Import>) -> LiftedIr {
        LiftedIr {
            facts: WasmFacts {
                imports,
                exports: vec![],
                function_type_indices: vec![],
                custom_sections: vec![],
            },
            soroban_facts: None,
            functions: vec![],
            memory: MemoryImage::empty(),
        }
    }

    /// Build a one-function `LiftedIr` whose entry block contains the
    /// supplied `LiftedValueDef`s as instructions, in order.
    ///
    /// Each value is given an `I64` result type — irrelevant for these
    /// tests, but `LiftedValue` requires a `types` vector.
    fn lifted_ir_with_one_function(
        imports: Vec<Import>,
        defs: Vec<LiftedValueDef>,
    ) -> LiftedIr {
        let mut values: Arena<ValueId, LiftedValue> = Arena::new();
        let mut instructions: Vec<ValueId> = Vec::new();
        for def in defs {
            let id = values.push(LiftedValue {
                def,
                types: vec![LiftedType::I64],
            });
            instructions.push(id);
        }

        let mut blocks: Arena<BlockId, LiftedBlock> = Arena::new();
        let entry_id = blocks.push(LiftedBlock {
            id: BlockId::from_index(0),
            params: vec![],
            instructions,
            terminator: LiftedTerminator::Unreachable,
        });

        LiftedIr {
            facts: WasmFacts {
                imports,
                exports: vec![],
                function_type_indices: vec![0],
                custom_sections: vec![],
            },
            soroban_facts: None,
            functions: vec![LiftedFunction {
                id: FuncId::from_index(0),
                entry: entry_id,
                blocks,
                values,
            }],
            memory: MemoryImage::empty(),
        }
    }

    fn import(module: &str, name: &str) -> Import {
        Import {
            index: 0,
            module: module.to_string(),
            name: name.to_string(),
            kind: ImportKind::Func(0),
        }
    }

    fn op_call(idx: u32) -> LiftedValueDef {
        LiftedValueDef::Operator {
            op: WasmOp(waffle::Operator::Call {
                function_index: waffle::Func::new(idx as usize),
            }),
            args: vec![],
        }
    }

    #[test]
    fn compute_coverage_on_empty_ir_returns_zeros_without_panic() {
        let ir = empty_lifted_ir(vec![]);
        let r = compute_coverage(Path::new("empty.wasm"), &[], false, &ir, &[], &BTreeMap::new(), &BTreeMap::new());

        assert_eq!(r.parse.diagnostics, 0);
        assert!(r.parse.ok);
        assert!(!r.metadata.present);
        assert_eq!(r.lift.functions_total, 0);
        assert!(r.lift.completeness.is_none(), "denominator-zero → null");
        assert_eq!(r.host_calls.total, 0);
        assert!(r.host_calls.ratio.is_none(), "denominator-zero → null");
        assert!(r.host_calls.unrecognized.is_empty());
        assert_eq!(r.operators.total, 0);
        // No recogniser diagnostics → clean section.
        assert_eq!(r.diagnostics.total, 0);
        assert!(r.diagnostics.by_code.is_empty());
    }

    #[test]
    fn diagnostic_coverage_totals_and_sorts_by_count() {
        let ir = empty_lifted_ir(vec![]);
        let counts = BTreeMap::from([
            ("lift::non_constant_durability_arg", 3),
            ("lift::unresolved_symbol_dispatch", 1),
            ("lift::non_constant_ttl_amount", 3),
        ]);
        let r = compute_coverage(Path::new("t.wasm"), &[], true, &ir, &[], &counts, &BTreeMap::new());

        assert_eq!(r.diagnostics.total, 7);
        // Sorted by descending count, then code ascending for ties.
        let order: Vec<&str> = r.diagnostics.by_code.iter().map(|c| c.code.as_str()).collect();
        assert_eq!(
            order,
            [
                "lift::non_constant_durability_arg",
                "lift::non_constant_ttl_amount",
                "lift::unresolved_symbol_dispatch",
            ]
        );
        assert_eq!(r.diagnostics.by_code[0].count, 3);

        // The text render surfaces the section.
        let mut buf = Vec::new();
        render_text(&mut buf, &r).unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("diagnostics:     7 total (recogniser misses)"));
        assert!(text.contains("lift::non_constant_ttl_amount (\u{00d7}3)"));
    }

    #[test]
    fn compute_coverage_recognizes_known_host_call() {
        // Function index 0 is an import to `("l", "_")` which the
        // catalog resolves to `put_contract_data`. One Call to it
        // should produce recognized=1, total=1, ratio=1.0.
        let ir = lifted_ir_with_one_function(vec![import("l", "_")], vec![op_call(0)]);
        let r = compute_coverage(Path::new("t.wasm"), &[], true, &ir, &[], &BTreeMap::new(), &BTreeMap::new());

        assert_eq!(r.host_calls.total, 1);
        assert_eq!(r.host_calls.recognized, 1);
        assert_eq!(r.host_calls.ratio, Some(1.0));
        assert!(r.host_calls.unrecognized.is_empty());
        assert_eq!(r.operators.call_to_import, 1);
        assert_eq!(r.operators.call_to_local, 0);
    }

    #[test]
    fn compute_coverage_records_unrecognized_with_count() {
        // Three calls to an unknown (module, name) pair should
        // collapse into a single UnrecognizedCall with count=3.
        let ir = lifted_ir_with_one_function(
            vec![import("zz", "?")],
            vec![op_call(0), op_call(0), op_call(0)],
        );
        let r = compute_coverage(Path::new("t.wasm"), &[], true, &ir, &[], &BTreeMap::new(), &BTreeMap::new());

        assert_eq!(r.host_calls.total, 3);
        assert_eq!(r.host_calls.recognized, 0);
        assert_eq!(r.host_calls.ratio, Some(0.0));
        assert_eq!(r.host_calls.unrecognized.len(), 1);
        let u = &r.host_calls.unrecognized[0];
        assert_eq!(u.module, "zz");
        assert_eq!(u.name, "?");
        assert_eq!(u.count, 3);
    }

    #[test]
    fn compute_coverage_distinguishes_local_from_import_calls() {
        // One import (idx 0) and one call to a local function
        // (waffle idx 1, past imported_func_count of 1).
        let ir = lifted_ir_with_one_function(vec![import("l", "_")], vec![op_call(1)]);
        let r = compute_coverage(Path::new("t.wasm"), &[], true, &ir, &[], &BTreeMap::new(), &BTreeMap::new());

        assert_eq!(r.operators.call_to_import, 0);
        assert_eq!(r.operators.call_to_local, 1);
        assert_eq!(r.host_calls.total, 0);
        assert!(r.host_calls.ratio.is_none());
    }

    #[test]
    fn compute_coverage_separates_metadata_from_parse_diagnostics() {
        use sordec_common::{Diagnostic, MetadataDiagnosticCode};

        // Two metadata diagnostics, no parse-level diagnostics.
        let diags = vec![
            Diagnostic::warning(
                MetadataDiagnosticCode::DuplicateTypeName {
                    name: "Foo".into(),
                },
                "",
            ),
            Diagnostic::warning(
                MetadataDiagnosticCode::DuplicateFunctionName {
                    name: "bar".into(),
                },
                "",
            ),
        ];
        let ir = empty_lifted_ir(vec![]);
        let r = compute_coverage(Path::new("t.wasm"), &diags, true, &ir, &[], &BTreeMap::new(), &BTreeMap::new());

        assert_eq!(r.parse.diagnostics, 0);
        assert!(r.parse.ok);
        assert_eq!(r.metadata.diagnostics, 2);
    }

    #[test]
    fn render_text_handles_zero_host_calls_without_nan() {
        let ir = empty_lifted_ir(vec![]);
        let r = compute_coverage(Path::new("hello.wasm"), &[], true, &ir, &[], &BTreeMap::new(), &BTreeMap::new());
        let mut buf = Vec::new();
        render_text(&mut buf, &r).expect("write succeeds");
        let s = String::from_utf8(buf).expect("utf-8");

        assert!(
            s.contains("no host calls in this contract"),
            "expected zero-host-call text, got:\n{s}"
        );
        assert!(!s.contains("NaN"), "must never render NaN, got:\n{s}");
        assert!(!s.contains("inf"), "must never render inf, got:\n{s}");
    }

    #[test]
    fn render_json_round_trips_through_serde_json() {
        let ir = lifted_ir_with_one_function(vec![import("l", "_")], vec![op_call(0)]);
        let r = compute_coverage(Path::new("t.wasm"), &[], true, &ir, &[], &BTreeMap::new(), &BTreeMap::new());

        let mut buf = Vec::new();
        render_json(&mut buf, &r).expect("serialize");
        let v: serde_json::Value = serde_json::from_slice(&buf).expect("parse");

        // Spot-check the schema's top-level keys match D7 of the plan,
        // plus the W7 additions. Schema is append-only: none removed.
        for key in [
            "wasm",
            "catalog",
            "parse",
            "metadata",
            "lift",
            "host_calls",
            "operators",
            "structuring",
            "recognition",
            "headline",
        ] {
            assert!(v.get(key).is_some(), "missing top-level key {key:?}");
        }
        assert_eq!(v["host_calls"]["total"], 1);
        assert_eq!(v["host_calls"]["recognized"], 1);
    }

    #[test]
    fn unrecognized_entries_are_sorted_by_descending_count_then_name() {
        // Three distinct unrecognized pairs with counts 1, 2, 3 —
        // expect output ordered 3, 2, 1. Module names use the
        // multi-byte `zz0..2` form so they cannot coincidentally hit
        // a real single-byte Soroban host module like `c` (crypto).
        let ir = lifted_ir_with_one_function(
            vec![
                import("zz0", "?"), // idx 0
                import("zz1", "?"), // idx 1
                import("zz2", "?"), // idx 2
            ],
            vec![
                op_call(0),
                op_call(1),
                op_call(1),
                op_call(2),
                op_call(2),
                op_call(2),
            ],
        );
        let r = compute_coverage(Path::new("t.wasm"), &[], true, &ir, &[], &BTreeMap::new(), &BTreeMap::new());

        let names: Vec<_> = r
            .host_calls
            .unrecognized
            .iter()
            .map(|u| (u.module.clone(), u.name.clone(), u.count))
            .collect();
        assert_eq!(
            names,
            vec![
                ("zz2".into(), "?".into(), 3),
                ("zz1".into(), "?".into(), 2),
                ("zz0".into(), "?".into(), 1),
            ]
        );
    }

    #[test]
    fn operator_breakdown_total_equals_sum_of_buckets() {
        // Mix of import call (idx 0), local call (idx 1), and a
        // non-call operator (I32Const). Verify the closed-total
        // invariant.
        let ir = lifted_ir_with_one_function(
            vec![import("l", "_")],
            vec![
                op_call(0), // import
                op_call(1), // local
                LiftedValueDef::Operator {
                    op: WasmOp(waffle::Operator::I32Const { value: 0 }),
                    args: vec![],
                },
            ],
        );
        let r = compute_coverage(Path::new("t.wasm"), &[], true, &ir, &[], &BTreeMap::new(), &BTreeMap::new());

        let sum = r.operators.call_to_import
            + r.operators.call_to_local
            + r.operators.call_indirect
            + r.operators.other;
        assert_eq!(sum, r.operators.total, "operator buckets must sum to total");
        assert_eq!(r.operators.total, 3);
    }

    #[test]
    fn recognition_ratios_computed_from_metric_totals() {
        use sordec_passes::metrics_catalog as mc;
        // A synthetic counter map mirroring token-v23's shape, so the
        // ratio math is checked without booting the whole pipeline.
        let totals = BTreeMap::from([
            (mc::STORAGE_TIER_RESOLVED, 8i64),
            (mc::STORAGE_TIER_UNKNOWN, 2),
            (mc::STORAGE_GET, 4),
            (mc::ENUM_KEY_NAMED, 6),
            (mc::ENUM_KEY_UNRESOLVED, 2),
            (mc::TTL_RESOLVED, 1),
            (mc::TTL_UNRESOLVED, 1),
            (mc::INVOKE_CONTRACT, 2),
            (mc::CLIENT_ARITY_RESOLVED, 2),
            (mc::CLIENT_IFACE_MATCHED, 2),
        ]);
        let ir = empty_lifted_ir(vec![]);
        let r = compute_coverage(Path::new("t.wasm"), &[], true, &ir, &[], &BTreeMap::new(), &totals);

        let rec = &r.recognition;
        assert_eq!(rec.storage.tier_ratio, Some(0.8), "8/10");
        assert_eq!(rec.storage.ops.get, 4);
        assert_eq!(rec.enum_keys.ratio, Some(0.75), "6/8");
        assert_eq!(rec.ttl.ratio, Some(0.5), "1/2");
        assert_eq!(rec.client_calls.sites, 2, "invoke + try_invoke");
        assert_eq!(rec.client_calls.typed_ratio, Some(1.0), "arity 2/2");
    }

    #[test]
    fn recognition_ratios_are_none_on_zero_denominator() {
        // No counters at all — every ratio null, never NaN.
        let ir = empty_lifted_ir(vec![]);
        let r = compute_coverage(Path::new("t.wasm"), &[], true, &ir, &[], &BTreeMap::new(), &BTreeMap::new());
        assert!(r.recognition.storage.tier_ratio.is_none());
        assert!(r.recognition.enum_keys.ratio.is_none());
        assert!(r.recognition.ttl.ratio.is_none());
        assert!(r.recognition.client_calls.typed_ratio.is_none());
        assert!(r.recognition.dispatcher.ratio.is_none());
        assert!(r.headline.deep_facts.ratio.is_none());
    }

    #[test]
    fn structuring_section_computed_from_metric_totals() {
        use sordec_passes::metrics_catalog as mc;
        // Synthetic counters exercising the derived fields: a closed loop
        // total across two kinds, the classification ratio, the
        // function-structured ratio, and passthrough of a declutter and a
        // treeify counter.
        let totals = BTreeMap::from([
            (mc::STRUCTURING_FUNCTIONS_TOTAL, 10i64),
            (mc::STRUCTURING_FUNCTIONS_STRUCTURED, 9),
            (mc::STRUCTURING_FALLBACK, 1),
            (mc::STRUCTURING_LOOPS_WHILE_TOP, 3),
            (mc::STRUCTURING_LOOPS_UNCLASSIFIED, 1),
            (mc::STRUCTURING_SWITCHES, 2),
            (mc::STRUCTURING_LABELED_BREAKS, 5),
            (mc::STRUCTURING_LABELED_CONTINUES, 2),
            (mc::REFINE_DISPATCH_LINKED, 1),
            (mc::DECLUTTER_PHIS_PRUNED, 42),
            (mc::TREEIFY_INLINE, 100),
        ]);
        let ir = empty_lifted_ir(vec![]);
        let r =
            compute_coverage(Path::new("t.wasm"), &[], true, &ir, &[], &BTreeMap::new(), &totals);

        let st = &r.structuring;
        assert_eq!(st.functions.ratio, Some(0.9), "9/10 structured");
        assert_eq!(st.functions.fallback_regions, 1);
        assert_eq!(st.loops.total, 4, "closed sum of the five kinds");
        assert_eq!(st.loops.classified_ratio, Some(0.75), "3/4 classified");
        assert_eq!(st.switches.recovered, 2);
        assert_eq!(st.switches.dispatch_linked, 1);
        assert_eq!(st.labeled_exits.breaks, 5);
        assert_eq!(st.labeled_exits.continues, 2);
        assert_eq!(st.declutter.phis_pruned, 42);
        assert_eq!(st.treeify.inline, 100);
    }

    #[test]
    fn structuring_ratios_are_none_on_zero_denominator() {
        // No counters at all — both structuring ratios null, never NaN,
        // and the text render must contain no NaN/inf.
        let ir = empty_lifted_ir(vec![]);
        let r = compute_coverage(
            Path::new("t.wasm"),
            &[],
            true,
            &ir,
            &[],
            &BTreeMap::new(),
            &BTreeMap::new(),
        );
        assert!(r.structuring.functions.ratio.is_none());
        assert!(r.structuring.loops.classified_ratio.is_none());
        assert_eq!(r.structuring.loops.total, 0);

        let mut buf = Vec::new();
        render_text(&mut buf, &r).expect("render");
        let text = String::from_utf8(buf).expect("utf8");
        assert!(!text.contains("NaN"), "no NaN in render");
        assert!(!text.contains("inf"), "no inf in render");
        assert!(text.contains("no loops in this contract"));
        assert!(text.contains("no match sites"));
    }

    #[test]
    fn headline_deep_facts_sum_the_five_pairs() {
        use sordec_passes::metrics_catalog as mc;
        // resolved = 8+6+1+2+0 = 17; attempted = 10+8+2+2+0 = 22.
        let totals = BTreeMap::from([
            (mc::STORAGE_TIER_RESOLVED, 8i64),
            (mc::STORAGE_TIER_UNKNOWN, 2),
            (mc::ENUM_KEY_NAMED, 6),
            (mc::ENUM_KEY_UNRESOLVED, 2),
            (mc::TTL_RESOLVED, 1),
            (mc::TTL_UNRESOLVED, 1),
            (mc::CLIENT_ARITY_RESOLVED, 2),
        ]);
        let ir = empty_lifted_ir(vec![]);
        let r = compute_coverage(Path::new("t.wasm"), &[], true, &ir, &[], &BTreeMap::new(), &totals);
        assert_eq!(r.headline.deep_facts.resolved, 17);
        assert_eq!(r.headline.deep_facts.attempted, 22);
    }

    #[test]
    fn headline_host_interactions_subtract_surviving_unknowns() {
        use sordec_passes::metrics_catalog as mc;
        // Three import-call sites; one survived unrecognised → 2/3.
        let ir = lifted_ir_with_one_function(
            vec![import("l", "_")],
            vec![op_call(0), op_call(0), op_call(0)],
        );
        let totals = BTreeMap::from([(mc::UNRECOGNISED_HOST_CALL, 1i64)]);
        let r = compute_coverage(Path::new("t.wasm"), &[], true, &ir, &[], &BTreeMap::new(), &totals);
        assert_eq!(r.headline.host_interactions.total, 3);
        assert_eq!(r.headline.host_interactions.recognized, 2);
        assert_eq!(r.headline.host_interactions.ratio, Some(2.0 / 3.0));
    }
}
