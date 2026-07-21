//! Corpus-driven soundness checks for the WAT anchoring layer (E2).
//!
//! These exercise the `pub(crate)` anchor internals against the real
//! fixtures — which an integration test (public-API only) cannot reach —
//! so they live inside the crate behind `cfg(test)`. They use the
//! frontend (to recover `WasmFacts` with E1 body ranges) and a
//! `wasmparser` rescan of the original code section as an independent
//! oracle.

use sordec_ir::{HighIr, WasmFacts};
use sordec_passes::LoweringStep;

use crate::emit_annotated_wat;
use crate::extract_annotated_facts;
use crate::wat::anchor;
use crate::wat::facts::recovered_facts;
use crate::wat::print;

/// Every committed fixture, as `(name, bytes)`.
fn fixtures() -> Vec<(&'static str, &'static [u8])> {
    macro_rules! fixture {
        ($name:literal) => {
            (
                $name,
                include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../samples/contracts/",
                    $name,
                    "/",
                    $name,
                    ".wasm"
                )) as &[u8],
            )
        };
    }
    vec![
        fixture!("hello-add"),
        fixture!("token-v22"),
        fixture!("token-v23"),
        fixture!("token-v23-stripped"),
        fixture!("timelock"),
        fixture!("attestation"),
        fixture!("dex-liquidity-pool"),
    ]
}

fn parse_facts(wasm: &[u8]) -> WasmFacts {
    sordec_frontend::parse(wasm)
        .expect("fixture parses")
        .wasm_facts
}

/// Run the full front-to-high pipeline, mirroring the CLI's `dump-hir` path.
fn build_high(wasm: &[u8]) -> HighIr {
    let parsed = sordec_frontend::parse(wasm).expect("fixture parses");
    let mut lift = sordec_passes::lift_with_waffle(
        wasm,
        &parsed.wasm_facts,
        parsed.soroban_facts.as_ref(),
    )
    .expect("lift succeeds");
    sordec_passes::default_lifted_pipeline().run(&mut lift.lifted);
    let mut high = sordec_passes::LiftToHigh
        .lower(lift.lifted)
        .expect("lowering succeeds");
    sordec_passes::default_high_pipeline().run(&mut high);
    high
}

/// The ordered host-call callee indices of each local function, read
/// directly from the original binary — the independent oracle the
/// printed-WAT anchoring must reproduce.
fn binary_host_calls(wasm: &[u8], func_import_count: u32) -> Vec<Vec<u32>> {
    let mut per_function = Vec::new();
    for payload in wasmparser::Parser::new(0).parse_all(wasm) {
        if let wasmparser::Payload::CodeSectionEntry(body) = payload.expect("valid payload") {
            let mut calls = Vec::new();
            for op in body.get_operators_reader().expect("operators") {
                if let wasmparser::Operator::Call { function_index } = op.expect("operator")
                    && function_index < func_import_count
                {
                    calls.push(function_index);
                }
            }
            per_function.push(calls);
        }
    }
    per_function
}

#[test]
fn every_local_function_is_anchored_exactly_once() {
    for (name, wasm) in fixtures() {
        let facts = parse_facts(wasm);
        let lines = print::print_flat(wasm).expect("prints");
        let anchors = anchor::anchor_functions(&lines, &facts);

        assert_eq!(
            anchors.len(),
            facts.function_bodies.len(),
            "{name}: every local function must anchor (all body lines offset-tagged)"
        );
        // Local indices are dense and in order.
        for (i, anchor) in anchors.iter().enumerate() {
            assert_eq!(anchor.local_index, i, "{name}: anchors in code order");
            assert!(
                anchor.header_line <= anchor.body_lines.start,
                "{name}: header precedes body"
            );
        }
    }
}

#[test]
fn printed_host_call_order_matches_the_binary() {
    for (name, wasm) in fixtures() {
        let facts = parse_facts(wasm);
        let lines = print::print_flat(wasm).expect("prints");
        let anchors = anchor::anchor_functions(&lines, &facts);
        let import_count = anchor::func_import_count(&facts);

        let printed: Vec<Vec<u32>> = anchors
            .iter()
            .map(|a| {
                anchor::host_call_sites(&lines, a, import_count)
                    .iter()
                    .map(|s| s.func_index)
                    .collect()
            })
            .collect();
        let binary = binary_host_calls(wasm, import_count);

        assert_eq!(
            printed, binary,
            "{name}: anchored host-call sequence must equal the binary's, per function"
        );
    }
}

#[test]
fn extractor_round_trips_recovered_facts_losslessly() {
    for (name, wasm) in fixtures() {
        let high = build_high(wasm);
        let wat = emit_annotated_wat(&high, wasm).expect("emits");

        // Ground truth the emitter serialized, through the same `;)`/newline
        // sanitizer the header lines went through.
        let expected: Vec<(String, Vec<String>)> = recovered_facts(&high)
            .into_iter()
            .map(|f| {
                (
                    print::sanitize(&f.title),
                    f.facts.iter().map(|s| print::sanitize(s)).collect(),
                )
            })
            .collect();
        let extracted: Vec<(String, Vec<String>)> = extract_annotated_facts(&wat)
            .into_iter()
            .map(|f| (f.title, f.facts))
            .collect();

        assert_eq!(
            extracted, expected,
            "{name}: extracted annotations must reproduce every recovered fact, in order"
        );
    }
}

#[test]
fn emission_is_deterministic_across_the_corpus() {
    for (name, wasm) in fixtures() {
        let high = build_high(wasm);
        let first = emit_annotated_wat(&high, wasm).expect("emits");
        let second = emit_annotated_wat(&high, wasm).expect("emits");
        assert_eq!(first, second, "{name}: emission must be deterministic");
    }
}
