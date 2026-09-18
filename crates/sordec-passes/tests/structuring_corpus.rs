//! Corpus locks for the control-flow structurer (Phase 3, C3/K3).
//!
//! Every committed fixture must structure completely: WASM can only
//! express reducible control flow, and on reducible input a correct
//! Beyond Relooper implementation never fails — so any
//! `Region::Unstructured` on the corpus is a structurer bug, not an
//! input problem (kickoff K3). The locks:
//!
//! 1. zero `Region::Unstructured` in any function's region tree;
//! 2. every CFG-reachable block appears **exactly once** as a
//!    `Region::Basic` leaf — the two structurer bug classes are dropped
//!    subtrees and duplicated subtrees, and this catches both;
//! 3. zero `StructuringFallback` diagnostics from the high pipeline —
//!    the diagnostic-side statement of the same invariant.
//!
//! Alongside the locks lives the **skeleton cross-check** (C4): one
//! `wasmparser` scan of the *original* binary — an oracle independent
//! of both waffle's frontend and our lift — asserting per-function
//! parity between original `loop`/`br_table` opcode counts and derived
//! `Region::Loop`/`Region::Switch` node counts. Block and `return`
//! counts are deliberately NOT compared (chain merging and
//! return-funnel inlining legitimately change them), and the corpus has
//! zero `if` opcodes (census R3). Structuring depth metrics are the
//! A6/W8 coverage surface, not asserted here.

mod common;

use std::collections::HashMap;

use common::FIXTURES;
use sordec_common::{BlockId, DiagnosticCode, LiftDiagnosticCode};
use sordec_ir::{validate_high, validate_lifted, HighIr, LiftedIr, Region};
use sordec_passes::{
    default_high_pipeline, default_lifted_pipeline, lift_with_waffle, CfgFacts, LiftToHigh,
    LoweringStep, PipelineReport,
};

/// The front half of the real pipeline: parse, lift, declutter, lower
/// (which structures at the boundary), recognize. Returns the
/// decluttered lifted IR (CFG ground truth), the high IR **as the
/// structurer emitted it**, the high IR after the full pass pipeline, and
/// the pipeline report.
///
/// The two high-IR snapshots are not interchangeable, and which one a lock
/// belongs on is a question about what the lock protects. "Every reachable
/// block appears exactly once" is a statement about the *structurer*: it
/// must not silently drop or duplicate work while turning a CFG into a
/// tree. It is **not** true after the pipeline, and increasingly so — the
/// marshalling and overflow elisions delete regions on purpose, each
/// recording a diagnostic for the block it removed. Asserting it on the
/// post-pipeline tree would make every future elision look like a
/// structuring bug.
fn structure_fixture(wasm: &[u8]) -> (LiftedIr, HighIr, HighIr, PipelineReport) {
    let parsed = sordec_frontend::parse(wasm).expect("frontend parses fixture");
    let mut lifted = lift_with_waffle(wasm, &parsed.wasm_facts, parsed.soroban_facts.as_ref())
        .expect("lifter accepts fixture")
        .lifted;
    default_lifted_pipeline().run(&mut lifted);
    common::assert_invariants_hold(&lifted);
    let mut high = LiftToHigh
        .lower(lifted.clone())
        .expect("boundary lowering succeeds");
    let structured = high.clone();
    let report = default_high_pipeline().run(&mut high);
    (lifted, structured, high, report)
}

#[test]
fn refinement_recovers_the_measured_guard_shape() {
    // Coarse magnitude lock against silent no-op regressions in the
    // W6/W7 refinement passes, mirroring the declutter floors.
    // Measured 2026-07-19 on the pinned corpus (post-W7):
    //   guards_hoisted 468 · polarity_flipped 4 · traps_inlined 164 ·
    //   traps_duplicated 60 (D2-ext: 20 of the 38 binding-carrying
    //   patterns qualified) · shared_trap_with_bindings 18 (the
    //   intra-block-reference remainder) · dispatch_linked 1 ·
    //   bare_panics 242 · unwraps 85 · switch_arms_deduped 4 ·
    //   loops_classified 26.
    // (The 4 flips disproved the planning guess that exit-in-else
    // never occurs in rustc output.) Floors sit below measured values
    // to tolerate benign fixture drift, not to excuse regressions.
    let mut totals: std::collections::BTreeMap<&'static str, i64> =
        std::collections::BTreeMap::new();
    for (_, wasm) in FIXTURES {
        let (_, _, _, report) = structure_fixture(wasm);
        for (key, value) in report.metric_totals() {
            *totals.entry(key).or_insert(0) += value;
        }
    }
    let floors: &[(&str, i64)] = &[
        ("refine_guards_hoisted", 400),
        ("refine_polarity_flipped", 1),
        ("refine_traps_inlined", 120),
        // W7 D6: timelock's symbol dispatcher is the corpus's one
        // linkable switch — the floor equals the measured value.
        ("refine_dispatch_linked", 1),
        // W7 D8, measured 2026-07-19: bare_panics 192 · unwraps 85
        // (corpus-wide 277 typed traps, 2 honest `unreachable`
        // switch-default exhaustiveness traps left).
        ("refine_bare_panics", 150),
        ("refine_unwraps", 60),
        // W7 D5, measured 2026-07-19: 4 default-equal arms folded
        // (token-v22/v23/v23-stripped + dex).
        ("refine_switch_arms_deduped", 3),
        // W7 D3, measured 2026-07-19: 26 of 32 loops proven WhileTop
        // (the SDK tuple->vec copy loops in every fixture family); the
        // 6 with per-iteration effectful headers honestly stay
        // Unclassified. Re-measured 2026-09-18: those 24 fill/copy loops
        // are unrolled at the lifted layer now, so the classifier sees
        // only dex's Newton bisection and string parse.
        ("refine_loops_classified", 2),
        // W7 D2-ext, measured 2026-07-19: 60 break sites duplicated
        // out of the binding-carrying shared trap blocks.
        ("refine_traps_duplicated", 40),
        // W7 D9, measured 2026-07-20: both multi-arg transfer sites
        // (dex + timelock) recover elements through the copy loop.
        // Since 2026-09-18 the copy loop is unrolled before the
        // recognizer runs, so both sites take the in-block tier and this
        // tier is honestly unexercised by the corpus.
        ("client_args_via_copy_loop", 0),
        // W8 A6, measured 2026-07-20: the census counts 26 WhileTop
        // loops corpus-wide; 2026-09-18: 2, for the reason above.
        ("structuring_loops_while_top", 2),
    ];
    for (key, floor) in floors {
        let got = totals.get(key).copied().unwrap_or(0);
        assert!(
            got >= *floor,
            "corpus-wide `{key}` = {got}, expected at least {floor}",
        );
    }

    // W8 A6 invariant (not a floor): every corpus function structures
    // fully — the metric-side statement of the K3 zero-Unstructured lock
    // (see `corpus_structures_with_zero_unstructured_regions`). Measured
    // 2026-07-20: 221 functions, all structured; the two counters must
    // stay equal even as fixtures change.
    let functions_total = totals.get("structuring_functions_total").copied().unwrap_or(0);
    let functions_structured = totals
        .get("structuring_functions_structured")
        .copied()
        .unwrap_or(0);
    assert!(functions_total > 0, "corpus has functions");
    assert_eq!(
        functions_structured, functions_total,
        "every corpus function must structure fully (K3)",
    );
    // The labeled-exit census is a readability *meter*, not a recovery
    // claim, so it carries no floor/ceiling (a bound would either be
    // meaningless or break on benign fixture drift). Measured 2026-07-20
    // for the record: 258 labeled breaks, 32 labeled continues.
}

#[test]
fn corpus_satisfies_ir_validators() {
    // The A5 validators run green over the whole corpus — the region
    // structure (label enclosure, transfer integrity, no duplicate
    // leaves) and region-order dominance the W6/W7 refinement passes
    // will lean on.
    for (name, wasm) in FIXTURES {
        let (lifted, structured, high, _) = structure_fixture(wasm);
        validate_lifted(&lifted)
            .unwrap_or_else(|e| panic!("[{name}] lifted validator: {e:?}"));
        // Both snapshots: the structurer must hand refinement a valid tree,
        // and refinement must hand the emitter one back.
        validate_high(&structured)
            .unwrap_or_else(|e| panic!("[{name}] high validator (structured): {e:?}"));
        validate_high(&high).unwrap_or_else(|e| panic!("[{name}] high validator: {e:?}"));
    }
}

#[test]
fn corpus_structures_with_zero_unstructured_regions() {
    for (name, wasm) in FIXTURES {
        let (lifted, structured, high, report) = structure_fixture(wasm);

        for (lifted_func, high_func) in lifted.functions.iter().zip(&high.functions) {
            // Lock 1 (K3): zero Unstructured.
            high_func.region.for_each_node(|region| {
                assert!(
                    !matches!(region, Region::Unstructured { .. }),
                    "[{name}] {} contains an Unstructured region",
                    high_func.id,
                );
            });

            // Lock 2: every bindings-carrying reachable block exactly
            // once as a Basic leaf; zero-binding blocks at most once —
            // trap inlining (D2) legitimately dissolves a shared bare
            // terminator's block, and only such blocks. Unreachable
            // blocks (declutter tombstones) never appear.
            //
            // Asserted on the **structurer's** tree, not the pipeline's.
            // This lock catches the two structurer bug classes — dropped
            // and duplicated subtrees — and both are properties of turning
            // a CFG into a tree. Elision passes then delete regions on
            // purpose (`marshalling::guard`, `refine::overflow_guard`),
            // including blocks that carry bindings: the panic glue an
            // overflow check calls is real content that is genuinely not
            // part of the source. Holding the post-pipeline tree to
            // "exactly once" would report every such removal as a
            // structuring bug. What the elisions must preserve — reference
            // integrity, label enclosure, transfer validity — is checked by
            // `debug_validate` after each pass and by
            // `corpus_satisfies_ir_validators` on both snapshots.
            let structured_func = structured
                .functions
                .iter()
                .find(|f| f.id == high_func.id)
                .expect("the pipeline neither adds nor removes functions");
            let cfg = CfgFacts::build(lifted_func);
            let mut basic_counts: HashMap<BlockId, u32> = HashMap::new();
            structured_func.region.for_each_node(|region| {
                if let Region::Basic(b) = region {
                    *basic_counts.entry(*b).or_insert(0) += 1;
                }
            });
            for (block_id, lifted_block) in lifted_func.blocks.iter() {
                let count = basic_counts.get(&block_id).copied().unwrap_or(0);
                if !cfg.is_reachable(block_id) {
                    assert_eq!(
                        count, 0,
                        "[{name}] {} unreachable block {} leaked into the region tree",
                        high_func.id, block_id,
                    );
                } else if lifted_block.instructions.is_empty() {
                    assert!(
                        count <= 1,
                        "[{name}] {} zero-binding block {} appears {count} times",
                        high_func.id, block_id,
                    );
                } else {
                    assert_eq!(
                        count, 1,
                        "[{name}] {} reachable block {} appears {count} times in the region tree",
                        high_func.id, block_id,
                    );
                }
            }
        }

        // Lock 3: no StructuringFallback diagnostics.
        let fallbacks: Vec<_> = report
            .diagnostics()
            .filter(|d| {
                matches!(
                    d.code,
                    DiagnosticCode::Lift(LiftDiagnosticCode::StructuringFallback)
                )
            })
            .collect();
        assert!(
            fallbacks.is_empty(),
            "[{name}] StructuringFallback on corpus input: {fallbacks:?}",
        );
    }
}

/// Original-binary control-flow skeleton of one defined function.
struct OpcodeCensus {
    /// `loop` opcodes in the function body.
    loops: u32,
    /// `br_table` opcodes in the function body.
    br_tables: u32,
}

/// Count `loop`/`br_table` opcodes per defined function by scanning the
/// code section directly — no waffle, no lift.
fn scan_code_section(wasm: &[u8]) -> Vec<OpcodeCensus> {
    let mut census = Vec::new();
    for payload in wasmparser::Parser::new(0).parse_all(wasm) {
        let wasmparser::Payload::CodeSectionEntry(body) = payload.expect("fixture parses") else {
            continue;
        };
        let mut counts = OpcodeCensus {
            loops: 0,
            br_tables: 0,
        };
        let mut ops = body
            .get_operators_reader()
            .expect("code entry has operators");
        while !ops.eof() {
            match ops.read().expect("operator decodes") {
                wasmparser::Operator::Loop { .. } => counts.loops += 1,
                wasmparser::Operator::BrTable { .. } => counts.br_tables += 1,
                _ => {}
            }
        }
        census.push(counts);
    }
    census
}

#[test]
fn skeleton_matches_original_wasm_nesting() {
    for (name, wasm) in FIXTURES {
        let (_, _, high, _) = structure_fixture(wasm);
        let originals = scan_code_section(wasm);
        // Defined-function order is the correlation key: code-section
        // entry i is lifted function i by construction of the lift.
        //
        // `SpecializePass` appends copies of the helpers rustc merged, so
        // the lift can hold *more* functions than the binary has bodies.
        // The correlation still holds over the prefix — appending never
        // renumbers — and a copy is verbatim, so its nesting is its
        // source's and re-checking it would prove nothing new. What must
        // never happen is a body going missing, which is what the
        // inequality pins.
        assert!(
            high.functions.len() >= originals.len(),
            "[{name}] every code-section entry must have a lifted function \
             ({} lifted, {} in the binary)",
            high.functions.len(),
            originals.len(),
        );

        for (high_func, original) in high.functions.iter().zip(&originals) {
            let mut loops = 0u32;
            let mut switches = 0u32;
            high_func.region.for_each_node(|region| match region {
                Region::Loop { .. } => loops += 1,
                Region::Switch { .. } => switches += 1,
                _ => {}
            });
            // At most: the lifted unroller turns the SDK's fixed-count
            // `[Val::VOID; N]` fill and copy loops into straight-line
            // stores before structuring, so a function may derive fewer
            // loops than its binary has `loop` opcodes — never more.
            assert!(
                loops <= original.loops,
                "[{name}] {}: derived Loop regions ({loops}) vs original `loop` opcodes ({})",
                high_func.id,
                original.loops,
            );
            assert_eq!(
                switches, original.br_tables,
                "[{name}] {}: derived Switch regions vs original `br_table` opcodes",
                high_func.id,
            );
        }
    }
}
