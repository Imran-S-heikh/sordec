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
//!    without diagnostics. Today this is trivially 100% because
//!    [`sordec_common::LiftDiagnosticCode`] has no variants; reporting
//!    it now puts the metric in place for Phase 2 when pattern-recovery
//!    passes start emitting recoverable conditions.
//! 3. **Parse + metadata health** — boolean checks (did the WASM parse,
//!    was Soroban metadata present and decoded). Always-yes for real
//!    contracts; tracked for completeness.
//!
//! Plus context counters (total operators broken down by call kind).
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
use sordec_passes::host_calls;
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
/// `sordec_passes::LiftOutput.diagnostics` (always empty in v0; see
/// the module-level note).
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
    }
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

    Ok(())
}

fn plural(n: usize, singular: &str) -> String {
    if n == 1 {
        singular.to_string()
    } else {
        format!("{singular}s")
    }
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
        let r = compute_coverage(Path::new("empty.wasm"), &[], false, &ir, &[]);

        assert_eq!(r.parse.diagnostics, 0);
        assert!(r.parse.ok);
        assert!(!r.metadata.present);
        assert_eq!(r.lift.functions_total, 0);
        assert!(r.lift.completeness.is_none(), "denominator-zero → null");
        assert_eq!(r.host_calls.total, 0);
        assert!(r.host_calls.ratio.is_none(), "denominator-zero → null");
        assert!(r.host_calls.unrecognized.is_empty());
        assert_eq!(r.operators.total, 0);
    }

    #[test]
    fn compute_coverage_recognizes_known_host_call() {
        // Function index 0 is an import to `("l", "_")` which the
        // catalog resolves to `put_contract_data`. One Call to it
        // should produce recognized=1, total=1, ratio=1.0.
        let ir = lifted_ir_with_one_function(vec![import("l", "_")], vec![op_call(0)]);
        let r = compute_coverage(Path::new("t.wasm"), &[], true, &ir, &[]);

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
        let r = compute_coverage(Path::new("t.wasm"), &[], true, &ir, &[]);

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
        let r = compute_coverage(Path::new("t.wasm"), &[], true, &ir, &[]);

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
        let r = compute_coverage(Path::new("t.wasm"), &diags, true, &ir, &[]);

        assert_eq!(r.parse.diagnostics, 0);
        assert!(r.parse.ok);
        assert_eq!(r.metadata.diagnostics, 2);
    }

    #[test]
    fn render_text_handles_zero_host_calls_without_nan() {
        let ir = empty_lifted_ir(vec![]);
        let r = compute_coverage(Path::new("hello.wasm"), &[], true, &ir, &[]);
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
        let r = compute_coverage(Path::new("t.wasm"), &[], true, &ir, &[]);

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
        let r = compute_coverage(Path::new("t.wasm"), &[], true, &ir, &[]);

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
        let r = compute_coverage(Path::new("t.wasm"), &[], true, &ir, &[]);

        let sum = r.operators.call_to_import
            + r.operators.call_to_local
            + r.operators.call_indirect
            + r.operators.other;
        assert_eq!(sum, r.operators.total, "operator buckets must sum to total");
        assert_eq!(r.operators.total, 3);
    }
}
