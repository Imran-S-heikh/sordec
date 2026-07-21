//! Reproducible corpus opcode census (research finding R3).
//!
//! The R3 census — taken by hand during Phase-3 planning — drove real
//! architectural decisions: **zero `if` opcodes** (rustc/LLVM lowers all
//! branching to `br_if`, so the structurer never sees a WASM `if`), zero
//! function-typed blocks, `br_if`-dominated control flow, rare loops, and
//! small `br_table`s. This test makes it reproducible: it re-walks every
//! committed fixture's raw bytes with `wasmparser`, **asserts the
//! load-bearing invariants**, and **prints the descriptive profile** so a
//! new fixture surfaces its opcode shape automatically (run with
//! `--nocapture`).
//!
//! Reducibility — the other structural precondition — is locked
//! separately in `cfg_oracle.rs`; it is not re-checked here.

// The census table is intentional stdout output for `--nocapture`; it is
// the point of the descriptive half of this test.
#![allow(clippy::print_stdout)]

mod common;

use common::FIXTURES;
use wasmparser::{BlockType, Operator, Parser, Payload};

/// Raw-opcode profile of one module.
#[derive(Debug, Default)]
struct Census {
    functions: usize,
    if_count: usize,
    block_count: usize,
    loop_count: usize,
    br_if: usize,
    br_table: usize,
    select: usize,
    /// Blocks / loops / ifs declared with a function type (multi-value
    /// signature). R3: zero corpus-wide.
    func_type_blocks: usize,
    /// Deepest nesting of control structures in any function.
    max_nesting: usize,
    /// Most operators in any single function body.
    max_body_ops: usize,
}

fn census(wasm: &[u8]) -> Census {
    let mut c = Census::default();
    for payload in Parser::new(0).parse_all(wasm) {
        let Payload::CodeSectionEntry(body) = payload.expect("valid payload") else {
            continue;
        };
        c.functions += 1;
        let mut depth = 0usize;
        let mut ops = 0usize;
        for op in body.get_operators_reader().expect("operators") {
            ops += 1;
            match op.expect("operator") {
                Operator::If { blockty } => {
                    c.if_count += 1;
                    enter(&mut c, &mut depth, blockty);
                }
                Operator::Block { blockty } => {
                    c.block_count += 1;
                    enter(&mut c, &mut depth, blockty);
                }
                Operator::Loop { blockty } => {
                    c.loop_count += 1;
                    enter(&mut c, &mut depth, blockty);
                }
                // `End` closes a control frame (or the function itself —
                // saturating avoids underflow on the trailing one).
                Operator::End => depth = depth.saturating_sub(1),
                Operator::BrIf { .. } => c.br_if += 1,
                Operator::BrTable { .. } => c.br_table += 1,
                Operator::Select | Operator::TypedSelect { .. } => c.select += 1,
                _ => {}
            }
        }
        c.max_body_ops = c.max_body_ops.max(ops);
    }
    c
}

fn enter(c: &mut Census, depth: &mut usize, blockty: BlockType) {
    *depth += 1;
    c.max_nesting = c.max_nesting.max(*depth);
    if matches!(blockty, BlockType::FuncType(_)) {
        c.func_type_blocks += 1;
    }
}

#[test]
fn opcode_census_locks_corpus_shape_and_prints_profile() {
    println!(
        "\n{:<22} {:>5} {:>4} {:>6} {:>5} {:>6} {:>8} {:>7} {:>8}",
        "fixture", "funcs", "if", "br_if", "loop", "select", "br_table", "nesting", "max_body"
    );
    for (name, wasm) in FIXTURES {
        let c = census(wasm);
        println!(
            "{name:<22} {:>5} {:>4} {:>6} {:>5} {:>6} {:>8} {:>7} {:>8}",
            c.functions,
            c.if_count,
            c.br_if,
            c.loop_count,
            c.select,
            c.br_table,
            c.max_nesting,
            c.max_body_ops,
        );

        // The load-bearing invariants the structuring architecture rests
        // on (R3). Descriptive counts above are printed, not pinned.
        assert_eq!(
            c.if_count, 0,
            "{name}: rustc lowers all branching to br_if — a WASM `if` \
             opcode would mean the structurer sees a shape it never planned for"
        );
        assert_eq!(
            c.func_type_blocks, 0,
            "{name}: no function-typed (multi-value) blocks expected in the corpus"
        );
    }
}
