//! Corpus-driven soundness checks for the WAT anchoring layer (E2).
//!
//! These exercise the `pub(crate)` anchor internals against the real
//! fixtures — which an integration test (public-API only) cannot reach —
//! so they live inside the crate behind `cfg(test)`. They use the
//! frontend (to recover `WasmFacts` with E1 body ranges) and a
//! `wasmparser` rescan of the original code section as an independent
//! oracle.

use sordec_ir::WasmFacts;

use crate::wat::anchor;
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
