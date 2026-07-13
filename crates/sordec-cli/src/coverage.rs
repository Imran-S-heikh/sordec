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
    /// Per-pattern recognition counts and ratios (F1–F8 + beyond-kickoff).
    pub recognition: RecognitionCoverage,
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
        recognition: build_recognition(metric_totals),
        diagnostics: build_diagnostic_coverage(recognizer_diagnostics),
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

    render_recognition(out, &r.recognition)?;

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

        // Spot-check the schema's top-level keys match D7 of the plan.
        for key in [
            "wasm",
            "catalog",
            "parse",
            "metadata",
            "lift",
            "host_calls",
            "operators",
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
}
