//! Corpus guard for the type-inference pass (Tranche-2 reviewer fix).
//!
//! A raw arithmetic or bitwise operation on a logical Soroban value
//! (`address & 0xFF`) yields an integer tag, not the logical type. This test
//! locks that in across the committed WASM corpus: no binding whose expression
//! is a raw arithmetic/bitwise op may carry a nonnumeric `KnownType`. It is the
//! regression the reviewer asked for.

mod common;

use common::FIXTURES;
use sordec_ir::{BinaryOp, Expr, HighIr, IrType, UnaryOp};
use sordec_passes::{
    default_high_pipeline, default_lifted_pipeline, lift_with_waffle, LiftToHigh, LoweringStep,
};

/// The front half of the real pipeline, through type inference: parse, lift,
/// declutter, lower (structures at the boundary), recognize + infer types.
fn high_ir(wasm: &[u8]) -> HighIr {
    let parsed = sordec_frontend::parse(wasm).expect("frontend parses fixture");
    let mut lifted = lift_with_waffle(wasm, &parsed.wasm_facts, parsed.soroban_facts.as_ref())
        .expect("lifter accepts fixture")
        .lifted;
    default_lifted_pipeline().run(&mut lifted);
    let mut high = LiftToHigh.lower(lifted).expect("boundary lowering succeeds");
    default_high_pipeline().run(&mut high);
    high
}

/// Arithmetic or bitwise (not comparison) — the ops whose result is an
/// integer, so a logical operand type must never survive onto the result.
fn is_raw_arithmetic(op: BinaryOp) -> bool {
    use BinaryOp as B;
    matches!(
        op,
        B::Add
            | B::Sub
            | B::Mul
            | B::Div
            | B::Rem
            | B::BitAnd
            | B::BitOr
            | B::BitXor
            | B::Shl
            | B::Shr
            | B::Rotl
            | B::Rotr
    )
}

/// Sign/bit flips that preserve a numeric type — but must not preserve a
/// logical one.
fn is_type_preserving_unary(op: UnaryOp) -> bool {
    matches!(
        op,
        UnaryOp::Neg | UnaryOp::Not | UnaryOp::BitNot | UnaryOp::Abs
    )
}

#[test]
fn no_logical_type_on_a_raw_arithmetic_result() {
    for (name, wasm) in FIXTURES {
        let high = high_ir(wasm);
        for func in &high.functions {
            for (id, binding) in func.bindings.iter() {
                let is_raw = match &binding.expr {
                    Expr::Binary { op, .. } => is_raw_arithmetic(*op),
                    Expr::Unary { op, .. } => is_type_preserving_unary(*op),
                    _ => false,
                };
                if !is_raw {
                    continue;
                }
                if let IrType::Known(k) | IrType::Inferred(k) = &binding.ty {
                    assert!(
                        k.is_numeric(),
                        "{name}: {id:?} is a raw arithmetic/bitwise result but is typed as \
                         the nonnumeric {k:?} — a logical Soroban type must not survive onto \
                         a mask/shift/arithmetic result"
                    );
                }
            }
        }
    }
}
