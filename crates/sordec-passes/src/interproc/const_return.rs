//! Read a helper's constant return at its call sites.
//!
//! The conversions `#[contracttype]` derives return a `Result`, and rustc
//! passes it back in two registers: a discriminant and a payload. Most of
//! those conversions cannot fail — building a one-element `Vec` from a
//! symbol the compiler chose is not a fallible operation — so the
//! discriminant is the same constant on every path out of the helper:
//!
//! ```text
//! fn func_6(sym) {              at the call site:
//!     …                         (err, val) = func_6(s)
//!     return 0, vec![sym]   →   if err { panic!() }      ← err is 0
//! }
//! ```
//!
//! The caller cannot see that, so it keeps the branch that tests the
//! discriminant, and the trap it guards, and every merge downstream of
//! them. Naming the constant at the call site lets the constant-branch
//! fold delete the lot.
//!
//! # Why it is exact
//!
//! A [`Expr::Project`] names one component of a value the call already
//! produced; it computes nothing and cannot trap. Replacing it with a
//! literal leaves the call itself untouched — the helper still runs, in
//! the same place, with the same effects — and the literal is what every
//! `return` in that helper puts in that position. A helper with no
//! `return` at all (it only traps) states nothing about any position and
//! is skipped.

use std::collections::HashMap;

use sordec_common::{FuncId, Provenance, ProvenanceSource};
use sordec_ir::{Expr, HighFunction, HighIr, IrType, Literal, Region};

use crate::dataflow::resolve_use;
use crate::metrics_catalog::INTERPROC_CONST_RETURNS as M_RETURNS;
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "interproc-const-return";

/// Replaces a projection of a call with the constant the callee returns.
#[derive(Debug, Default, Clone, Copy)]
pub struct ConstReturnPass;

impl Pass<HighIr> for ConstReturnPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let known: HashMap<(FuncId, u32), (Literal, IrType)> =
            ir.functions.iter().flat_map(constant_returns).collect();
        if known.is_empty() {
            return result;
        }
        for func in &mut ir.functions {
            // A projection of a call to a helper whose return in that
            // position is always the same literal.
            let folds: Vec<_> = func
                .bindings
                .iter()
                .filter_map(|(id, b)| {
                    let Expr::Project { value, index } = &b.expr else {
                        return None;
                    };
                    let Expr::Call { target, .. } = &func.bindings.get(resolve_use(func, *value))?.expr
                    else {
                        return None;
                    };
                    let (lit, ty) = known.get(&(*target, *index))?;
                    Some((id, lit.clone(), ty.clone()))
                })
                .collect();
            for (id, lit, ty) in folds {
                if let Some(b) = func.bindings.get_mut(id) {
                    b.expr = Expr::Literal(lit);
                    b.ty = ty;
                    b.add_provenance(Provenance::new(
                        PASS_NAME,
                        ProvenanceSource::DataFlow,
                        "the constant this helper returns in this position on every path",
                    ));
                    result.metrics.increment(M_RETURNS, 1);
                    result.changed = true;
                }
            }
        }
        result
    }
}

/// Each return position of `func` that is the same literal on every path
/// out of it.
fn constant_returns(func: &HighFunction) -> Vec<((FuncId, u32), (Literal, IrType))> {
    let mut rows: Vec<Vec<Option<(Literal, IrType)>>> = Vec::new();
    func.region.for_each_node(|node| {
        if let Region::Return { values } = node {
            rows.push(values.iter().map(|v| literal_of(func, *v)).collect());
        }
    });
    // A helper that only traps states nothing. Mismatched arities mean the
    // region is not what this pass thinks it is; say nothing rather than
    // line up positions that are not the same position.
    let Some(arity) = rows.first().map(Vec::len) else {
        return Vec::new();
    };
    if rows.iter().any(|row| row.len() != arity) {
        return Vec::new();
    }
    (0..arity)
        .filter_map(|k| {
            let first = rows[0][k].clone()?;
            let index = u32::try_from(k).ok()?;
            rows.iter()
                .all(|row| row[k].as_ref().is_some_and(|(lit, _)| *lit == first.0))
                .then_some(((func.id, index), first))
        })
        .collect()
}

/// The integer literal a returned value is, with the type it carries.
fn literal_of(func: &HighFunction, value: sordec_common::ValueId) -> Option<(Literal, IrType)> {
    let b = func.bindings.get(resolve_use(func, value))?;
    match &b.expr {
        Expr::Literal(
            lit @ (Literal::I32(_) | Literal::I64(_) | Literal::U32(_) | Literal::U64(_)),
        ) => Some((lit.clone(), b.ty.clone())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};
    use sordec_common::{BlockId, IrId};

    /// A helper returning `(0, x)` on both paths, and a caller that
    /// projects both components.
    fn shape(second_return: i64) -> HighIr {
        let mut helper = func_with(
            vec![
                Expr::Phi { incoming: vec![] },              // v0 arg
                Expr::Literal(Literal::I64(0)),              // v1
                Expr::Literal(Literal::I64(second_return)),  // v2
                Expr::Literal(Literal::I64(7)),              // v3 payload
            ],
            vec![v(0)],
            vec![1, 2, 3],
        );
        helper.region = Region::Sequence(vec![
            Region::Basic(BlockId::from_index(0)),
            Region::If {
                cond: v(0),
                then_region: Box::new(Region::Return { values: vec![v(1), v(3)] }),
                else_region: Some(Box::new(Region::Return { values: vec![v(2), v(3)] })),
            },
        ]);
        let mut caller = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                                        // v0
                Expr::Call { target: FuncId::from_index(0), args: vec![v(0)] },         // v1
                Expr::Project { value: v(1), index: 0 },                                // v2
                Expr::Project { value: v(1), index: 1 },                                // v3
            ],
            vec![v(0)],
            vec![1, 2, 3],
        );
        caller.id = FuncId::from_index(1);
        let mut m = module(vec![helper, caller]);
        m.functions[0].id = FuncId::from_index(0);
        m
    }

    #[test]
    fn a_position_that_is_the_same_literal_everywhere_is_read_at_the_call() {
        let mut m = shape(0);
        assert!(ConstReturnPass.run(&mut m).changed);
        let caller = &m.functions[1];
        assert!(matches!(caller.bindings.get(v(2)).unwrap().expr, Expr::Literal(Literal::I64(0))));
        // The payload differs per path in general; this helper's does not
        // vary either, so it folds too — the point is that the call stays.
        assert!(matches!(caller.bindings.get(v(1)).unwrap().expr, Expr::Call { .. }));
    }

    /// A discriminant that differs between paths is a real `Result`.
    #[test]
    fn a_position_that_varies_is_left_alone() {
        let mut m = shape(1);
        ConstReturnPass.run(&mut m);
        assert!(matches!(
            m.functions[1].bindings.get(v(2)).unwrap().expr,
            Expr::Project { index: 0, .. }
        ));
    }

    #[test]
    fn the_pass_is_idempotent() {
        let mut m = shape(0);
        assert!(ConstReturnPass.run(&mut m).changed);
        assert!(!ConstReturnPass.run(&mut m).changed);
    }
}
