//! Read an `i128` zero test back off its halves.
//!
//! Nothing in WASM compares 128 bits, so `reserve == 0` compiles to an OR
//! of the two halves tested against zero, and `a | b == 0` to an OR of
//! four:
//!
//! ```text
//! eqz(or(lo(r), hi(r)))                      →  eqz(r)
//! eqz(or(or(lo(a), lo(b)), or(hi(a), hi(b)))) →  eqz(a | b)
//! ```
//!
//! Once [`crate::WideReturnPromotePass`] has given the halves a whole to
//! belong to, the tree says plainly which values it is testing, and the
//! test can be spelled on them. Until then the same code reads as
//! arithmetic on unrelated registers, and the branch it guards looks like
//! something the source wrote.
//!
//! # Why it is exact
//!
//! A bitwise OR is zero exactly when every bit of every operand is zero.
//! The halves of a value partition its bits, so an OR over both halves of
//! each of several values is zero exactly when the OR of those values is —
//! at any width. The rewrite replaces the tree with that OR and leaves the
//! comparison alone.
//!
//! Every half must be accounted for: both halves of each value, each
//! exactly once, and nothing else in the tree. A tree missing a half tests
//! something narrower than the value, and one with a stray operand tests
//! something else entirely.

use std::collections::BTreeMap;

use sordec_common::{IrId, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{BinaryOp, Binding, Expr, HighFunction, HighIr, IrType, KnownType, UnaryOp};

use crate::dataflow::resolve_use;
use crate::metrics_catalog::REFINE_WIDE_ZERO_TESTS as M_TESTS;
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "refine-wide-zero";

/// Rewrites an OR over both halves of wide values as an OR of the values.
#[derive(Debug, Default, Clone, Copy)]
pub struct WideZeroPass;

impl Pass<HighIr> for WideZeroPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            let trees: Vec<(ValueId, Vec<ValueId>)> =
                func.bindings.iter().filter_map(|(id, _)| whole_values(func, id).map(|w| (id, w))).collect();
            for (root, values) in trees {
                rewrite(func, root, &values);
                result.metrics.increment(M_TESTS, 1);
                result.changed = true;
            }
        }
        result
    }
}

/// The wide values an OR tree covers both halves of, in a stable order.
fn whole_values(func: &HighFunction, root: ValueId) -> Option<Vec<ValueId>> {
    // The root has to be the OR itself; a bare half is not a tree.
    if !matches!(func.bindings.get(root)?.expr, Expr::Binary { op: BinaryOp::BitOr, .. }) {
        return None;
    }
    let mut found = Vec::new();
    if !leaves(func, root, &mut found, 0) {
        return None;
    }
    let mut halves: BTreeMap<ValueId, (bool, bool)> = BTreeMap::new();
    for (op, value) in found {
        let seen = halves.entry(value).or_default();
        let slot = match op {
            UnaryOp::WideLo => &mut seen.0,
            _ => &mut seen.1,
        };
        // A half twice over is not a partition of anything.
        if std::mem::replace(slot, true) {
            return None;
        }
    }
    halves
        .values()
        .all(|(lo, hi)| *lo && *hi)
        .then(|| halves.keys().copied().collect::<Vec<_>>())
        .filter(|v: &Vec<ValueId>| !v.is_empty())
}

/// Walk the OR tree, collecting its leaves. False if any leaf is not a
/// half of something.
fn leaves(func: &HighFunction, value: ValueId, out: &mut Vec<(UnaryOp, ValueId)>, depth: u32) -> bool {
    const MAX_DEPTH: u32 = 8;
    let Some(binding) = func.bindings.get(resolve_use(func, value)) else {
        return false;
    };
    match &binding.expr {
        Expr::Binary { op: BinaryOp::BitOr, lhs, rhs } if depth < MAX_DEPTH => {
            leaves(func, *lhs, out, depth + 1) && leaves(func, *rhs, out, depth + 1)
        }
        Expr::Unary { op: op @ (UnaryOp::WideLo | UnaryOp::WideHi), value } => {
            out.push((*op, resolve_use(func, *value)));
            true
        }
        _ => false,
    }
}

/// Replace the tree with the OR of the values it covers.
fn rewrite(func: &mut HighFunction, root: ValueId, values: &[ValueId]) {
    let note = Provenance::new(
        PASS_NAME,
        ProvenanceSource::DataFlow,
        "an OR over both halves of each value is the OR of the values",
    );
    let wide = IrType::Inferred(KnownType::I128);
    // Fold left, binding each partial OR before the root reads it.
    let mut fresh = Vec::new();
    let mut acc = values[0];
    for next in &values[1..] {
        let id = ValueId::from_index(func.bindings.len() as u32);
        func.bindings.push(Binding::new(
            id,
            wide.clone(),
            Expr::Binary { op: BinaryOp::BitOr, lhs: acc, rhs: *next },
            note.clone(),
        ));
        fresh.push(id);
        acc = id;
    }
    for (_, block) in func.blocks.iter_mut() {
        if let Some(pos) = block.bindings.iter().position(|v| *v == root) {
            for (i, id) in fresh.iter().enumerate() {
                block.bindings.insert(pos + i, *id);
            }
            break;
        }
    }
    if let Some(b) = func.bindings.get_mut(root) {
        b.expr = Expr::Use(acc);
        b.ty = wide;
        b.add_provenance(note);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};

    /// `or(or(lo(a), lo(b)), or(hi(a), hi(b)))`; `whole` false drops one
    /// half so the tree covers only part of `b`.
    fn shape(whole: bool) -> HighIr {
        let last = if whole { 5 } else { 4 };
        module(vec![func_with(
            vec![
                Expr::Phi { incoming: vec![] },                                  // v0 a
                Expr::Phi { incoming: vec![] },                                  // v1 b
                Expr::Unary { op: UnaryOp::WideLo, value: v(0) },                 // v2
                Expr::Unary { op: UnaryOp::WideLo, value: v(1) },                 // v3
                Expr::Unary { op: UnaryOp::WideHi, value: v(0) },                 // v4
                Expr::Unary { op: UnaryOp::WideHi, value: v(1) },                 // v5
                Expr::Binary { op: BinaryOp::BitOr, lhs: v(2), rhs: v(3) },        // v6
                Expr::Binary { op: BinaryOp::BitOr, lhs: v(4), rhs: v(last) },     // v7
                Expr::Binary { op: BinaryOp::BitOr, lhs: v(6), rhs: v(7) },        // v8
            ],
            vec![v(0), v(1)],
            vec![2, 3, 4, 5, 6, 7, 8],
        )])
    }

    #[test]
    fn a_tree_over_both_halves_of_each_value_is_the_or_of_the_values() {
        let mut m = shape(true);
        assert!(WideZeroPass.run(&mut m).changed);
        let f = &m.functions[0];
        let Expr::Use(folded) = f.bindings.get(v(8)).unwrap().expr else {
            panic!("the root names the folded OR");
        };
        assert!(matches!(
            f.bindings.get(folded).unwrap().expr,
            Expr::Binary { op: BinaryOp::BitOr, lhs, rhs } if lhs == v(0) && rhs == v(1)
        ));
        assert_eq!(f.bindings.get(v(8)).unwrap().ty, IrType::Inferred(KnownType::I128));
    }

    /// Half of `b` missing: the tree tests something narrower than `b`.
    #[test]
    fn a_tree_missing_a_half_is_left_alone() {
        let mut m = shape(false);
        assert!(!WideZeroPass.run(&mut m).changed);
    }

    #[test]
    fn the_pass_is_idempotent() {
        let mut m = shape(true);
        assert!(WideZeroPass.run(&mut m).changed);
        assert!(!WideZeroPass.run(&mut m).changed);
    }
}
