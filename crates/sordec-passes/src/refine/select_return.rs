//! Turn a returned `select` back into the branch the source wrote, and an
//! object comparison against zero back into `==`.
//!
//! # A returned `select`
//!
//! ```ignore
//! if actual == claimed { Ok(()) } else { Err(Error::DigestMismatch) }
//! ```
//!
//! has two cheap arms, so LLVM computes both and picks one with wasm's
//! `select`. What reaches us is one returned value, `select(ok, err, cond)`,
//! and no branch — which the emitter cannot even type, because each arm is
//! a different half of the `Result`. When the select's only reader is the
//! `return`, the return becomes
//!
//! ```text
//! if cond { return ok } else { return err }
//! ```
//!
//! Exact: both operands are values computed before the select, so choosing
//! between them after the branch instead of before it changes nothing but
//! where the choice is spelled.
//!
//! # An object comparison
//!
//! `actual == claimed` on two `BytesN` compiles to the host's `obj_cmp`,
//! an ordering, compared against zero. `eqz(val_compare(a, b))` is
//! `a == b` and `val_compare(a, b) != 0` is `a != b` — Rust's `PartialEq`
//! on SDK objects is that same host comparison.

use std::collections::HashMap;

use sordec_common::{Provenance, ProvenanceSource, ValueId};
use sordec_ir::{
    BinaryOp, Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Region, SemanticOp, UnaryOp,
    WasmOpcodeKind,
};

use crate::dataflow::{resolve_use, trace_int};
use crate::metrics_catalog::REFINE_SELECTS_BRANCHED as M_BRANCHED;
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "refine-select-return";

/// Branches returned selects and names object equality.
#[derive(Debug, Default, Clone, Copy)]
pub struct SelectReturnPass;

impl Pass<HighIr> for SelectReturnPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            for (id, expr) in object_equalities(func) {
                if let Some(b) = func.bindings.get_mut(id) {
                    b.expr = expr;
                    b.ty = IrType::Inferred(KnownType::Bool);
                    b.add_provenance(Provenance::new(
                        PASS_NAME,
                        ProvenanceSource::SdkPattern,
                        "object equality: the host comparison against zero",
                    ));
                    result.changed = true;
                }
            }
            // Decided on the intact region: the reader count includes it.
            let selects = returned_selects(func);
            let mut branched = 0;
            let region = std::mem::replace(&mut func.region, Region::Unreachable);
            func.region = branch_returns(func, region, &selects, &mut branched);
            if branched > 0 {
                result.metrics.increment(M_BRANCHED, branched);
                result.changed = true;
            }
        }
        result
    }
}

/// `eqz(val_compare(a, b))` and `val_compare(a, b) {==,!=} 0`.
fn object_equalities(func: &HighFunction) -> Vec<(ValueId, Expr)> {
    let compare = |v: ValueId| match func.bindings.get(resolve_use(func, v)).map(|b| &b.expr) {
        Some(Expr::Semantic(SemanticOp::Known(KnownOp::ValCompare { a, b }))) => Some((*a, *b)),
        _ => None,
    };
    func.bindings
        .iter()
        .filter_map(|(id, b)| match &b.expr {
            Expr::Unary { op: UnaryOp::Eqz, value } => {
                let (a, b) = compare(*value)?;
                Some((id, Expr::Binary { op: BinaryOp::Eq, lhs: a, rhs: b }))
            }
            Expr::Binary { op: op @ (BinaryOp::Eq | BinaryOp::Ne), lhs, rhs } => {
                let (cmp, zero) = if compare(*lhs).is_some() { (*lhs, *rhs) } else { (*rhs, *lhs) };
                let (a, b) = compare(cmp)?;
                (trace_int(func, zero) == Some(0)).then_some((id, Expr::Binary { op: *op, lhs: a, rhs: b }))
            }
            _ => None,
        })
        .collect()
}

/// Every select read by exactly one thing, mapped to its
/// `(on_true, on_false, cond)`. Whether that one reader is a return is
/// decided where the return is found.
fn returned_selects(func: &HighFunction) -> HashMap<ValueId, (ValueId, ValueId, ValueId)> {
    let mut readers: HashMap<ValueId, usize> = HashMap::new();
    for (_, b) in func.bindings.iter() {
        b.expr.for_each_value_use(|u| *readers.entry(resolve_use(func, u)).or_default() += 1);
    }
    func.region.for_each_value_use(|u| *readers.entry(resolve_use(func, u)).or_default() += 1);
    func.bindings
        .iter()
        .filter_map(|(id, b)| {
            let Expr::Unknown { op_kind: WasmOpcodeKind::Select, args, .. } = &b.expr else {
                return None;
            };
            let [on_true, on_false, cond] = args.as_slice() else {
                return None;
            };
            (readers.get(&id) == Some(&1)).then_some((id, (*on_true, *on_false, *cond)))
        })
        .collect()
}

fn branch_returns(
    func: &HighFunction,
    region: Region,
    selects: &HashMap<ValueId, (ValueId, ValueId, ValueId)>,
    branched: &mut i64,
) -> Region {
    let mut recurse = |r: Region| branch_returns(func, r, selects, branched);
    match region {
        Region::Return { values } if values.len() == 1 => match selects.get(&resolve_use(func, values[0])).copied() {
            Some((on_true, on_false, cond)) => {
                *branched += 1;
                Region::If {
                    cond,
                    then_region: Box::new(Region::Return { values: vec![on_true] }),
                    else_region: Some(Box::new(Region::Return { values: vec![on_false] })),
                }
            }
            None => Region::Return { values },
        },
        Region::Sequence(items) => Region::Sequence(items.into_iter().map(&mut recurse).collect()),
        Region::Scope { out, body } => Region::Scope { out, body: Box::new(recurse(*body)) },
        Region::Loop { header, body, kind } => Region::Loop { header, body: Box::new(recurse(*body)), kind },
        Region::If { cond, then_region, else_region } => Region::If {
            cond,
            then_region: Box::new(recurse(*then_region)),
            else_region: else_region.map(|e| Box::new(recurse(*e))),
        },
        Region::Switch { index, arms, default, dispatch } => Region::Switch {
            index,
            arms: arms
                .into_iter()
                .map(|mut arm| {
                    arm.body = recurse(arm.body);
                    arm
                })
                .collect(),
            default: Box::new(recurse(*default)),
            dispatch,
        },
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};
    use sordec_common::{BlockId, IrId, UnknownReason};
    use sordec_ir::Literal;

    /// `v2 = val_compare(v0, v1); v3 = eqz(v2); v6 = select(v4, v5, v3);
    /// return v6`.
    fn shape(extra_reader: bool) -> HighIr {
        let mut exprs = vec![
            Expr::Phi { incoming: vec![] },                                             // v0
            Expr::Phi { incoming: vec![] },                                             // v1
            Expr::Semantic(SemanticOp::Known(KnownOp::ValCompare { a: v(0), b: v(1) })), // v2
            Expr::Unary { op: UnaryOp::Eqz, value: v(2) },                              // v3
            Expr::Literal(Literal::I64(2)),                                            // v4
            Expr::Literal(Literal::I64(3)),                                            // v5
            Expr::Unknown {
                op_kind: WasmOpcodeKind::Select,
                args: vec![v(4), v(5), v(3)],
                reason: UnknownReason::UnsupportedPattern,
            }, // v6
        ];
        let mut sched = vec![2, 3, 4, 5, 6];
        if extra_reader {
            exprs.push(Expr::Use(v(6))); // v7
            sched.push(7);
        }
        let mut f = func_with(exprs, vec![v(0), v(1)], sched);
        f.region = Region::Sequence(vec![
            Region::Basic(BlockId::from_index(0)),
            Region::Return { values: vec![v(6)] },
        ]);
        module(vec![f])
    }

    #[test]
    fn a_returned_select_becomes_a_branch_and_the_comparison_equality() {
        let mut m = shape(false);
        assert!(SelectReturnPass.run(&mut m).changed);
        let f = &m.functions[0];
        assert!(matches!(f.bindings.get(v(3)).unwrap().expr, Expr::Binary { op: BinaryOp::Eq, lhs, rhs } if lhs == v(0) && rhs == v(1)));
        let mut branch = false;
        f.region.for_each_node(|n| {
            if let Region::If { cond, else_region: Some(_), .. } = n {
                branch |= *cond == v(3);
            }
        });
        assert!(branch, "the return is now if/else on the select's condition");
    }

    /// A select someone else also reads stays a value.
    #[test]
    fn a_select_with_another_reader_stays() {
        let mut m = shape(true);
        SelectReturnPass.run(&mut m);
        let mut ifs = 0;
        m.functions[0].region.for_each_node(|n| ifs += usize::from(matches!(n, Region::If { .. })));
        assert_eq!(ifs, 0);
    }
}
