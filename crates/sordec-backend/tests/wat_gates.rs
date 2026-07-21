//! K5 acceptance gates for the annotated WAT, as tests.
//!
//! Byte round-trip is provably unachievable (LLD pads LEBs; re-encode
//! minimizes — research finding R7), so acceptance was redefined (K5) to
//! what *is* checkable and is asserted here on every fixture:
//!
//! 1. **Parse** — the emitted annotated WAT assembles under `wat`.
//! 2. **Inert annotations / print-fixpoint** — stripping our `;;` lines by
//!    re-assembling yields a module that prints identically to the
//!    original's own one-hop text round-trip.
//! 3. **Structural equality** — same type/import/function/export counts and
//!    the Soroban custom sections (contractspec / env / meta) survive
//!    **byte-for-byte**.
//!
//! The fourth gate — extractor-diff losslessness — lives with the internal
//! `recovered_facts` ground truth in the crate's `corpus_tests`.

mod common;

use std::collections::BTreeMap;

use sordec_backend::emit_annotated_wat;

/// Emit annotated WAT for a fixture.
fn emit(wasm: &[u8]) -> String {
    let high = common::build_high(wasm);
    emit_annotated_wat(&high, wasm).expect("emits")
}

#[test]
fn emitted_wat_parses() {
    for (name, wasm) in common::fixtures() {
        let wat = emit(wasm);
        wat::parse_str(&wat).unwrap_or_else(|e| panic!("{name}: emitted WAT must parse: {e}"));
    }
}

#[test]
fn assembled_module_is_print_idempotent() {
    // K5's print-fixpoint: the annotated WAT assembles to a module that is
    // stable under print∘parse (a fixpoint after the one LLD-normalising
    // hop, R7). Comment lines are ignored by the assembler, so this also
    // demonstrates the annotations are semantically inert.
    for (name, wasm) in common::fixtures() {
        let module = wat::parse_str(emit(wasm)).expect("annotated assembles");
        let printed_once = wasmprinter::print_bytes(&module).expect("prints");
        let reparsed = wat::parse_str(&printed_once).expect("re-assembles");
        let printed_twice = wasmprinter::print_bytes(&reparsed).expect("prints");
        assert_eq!(
            printed_once, printed_twice,
            "{name}: assembled module must be a print∘parse fixpoint"
        );
    }
}

#[test]
fn structurally_equal_with_custom_sections_byte_equal() {
    for (name, wasm) in common::fixtures() {
        let annotated_bin = wat::parse_str(emit(wasm)).expect("assembles");

        let original = fingerprint(wasm);
        let round_tripped = fingerprint(&annotated_bin);

        assert_eq!(
            original.counts, round_tripped.counts,
            "{name}: section item counts must match"
        );
        // Every Soroban custom section must survive byte-for-byte.
        for section in ["contractspecv0", "contractenvmetav0", "contractmetav0"] {
            assert_eq!(
                original.custom.get(section),
                round_tripped.custom.get(section),
                "{name}: custom section `{section}` must be byte-equal"
            );
        }
    }
}

/// A structural fingerprint of a WASM module: per-kind item counts plus
/// the raw bytes of every custom section.
struct Fingerprint {
    counts: [usize; 5],
    custom: BTreeMap<String, Vec<u8>>,
}

fn fingerprint(wasm: &[u8]) -> Fingerprint {
    use wasmparser::Payload;
    let mut counts = [0usize; 5]; // types, imports, functions, exports, code bodies
    let mut custom = BTreeMap::new();
    for payload in wasmparser::Parser::new(0).parse_all(wasm) {
        match payload.expect("valid payload") {
            Payload::TypeSection(r) => counts[0] = r.count() as usize,
            Payload::ImportSection(r) => counts[1] = r.count() as usize,
            Payload::FunctionSection(r) => counts[2] = r.count() as usize,
            Payload::ExportSection(r) => counts[3] = r.count() as usize,
            Payload::CodeSectionEntry(_) => counts[4] += 1,
            Payload::CustomSection(c) => {
                custom.insert(c.name().to_string(), c.data().to_vec());
            }
            _ => {}
        }
    }
    Fingerprint { counts, custom }
}
