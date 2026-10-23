//! A `bool` returned from an entrypoint is returned as its tag.
//!
//! # The shape
//!
//! A `bool` *is* its `Val` tag — `False` is 0, `True` is 1 — so an
//! entrypoint returning one hands back the flag widened to the word, and a
//! constant `false` as the literal `0`:
//!
//! ```text
//! r = phi [early → 0, done → extend_u32(a & b)]     r = phi [early → false,
//! return r                                     →                done → a & b]
//! ```
//!
//! [`super::bool_codec`] folds the select chain the SDK's encoder uses on a
//! value it does not know is a `bool`. This is the case where it does —
//! `import_ark_bn254`'s `mock_verify` — and the widening is all there is:
//! printed as it was, the `bool` function returned an `i64` through a phi
//! the emitter declared `Val`.
//!
//! # Why it is exact
//!
//! `extend_u32(f)` of a flag is `0` or `1`, which is `f`'s encoding; and
//! `0`/`1` are `false`/`true`'s. The contract's own spec says the function
//! returns a `bool`, so the host reads the word back as exactly that.
//!
//! # Gates
//!
//! - **The spec returns `bool`.** No other return type is touched.
//! - **Every arm is one of the two shapes.** A phi with any other arm is
//!   left alone, and so is a literal something else in the body still reads.

use std::collections::HashSet;

use sordec_common::{Provenance, ProvenanceSource, ValueId};
use sordec_ir::{BinaryOp, Expr, HighFunction, HighIr, IrType, KnownType, Literal, Region, UnaryOp};

use crate::dataflow::resolve_use;
use crate::metrics_catalog::MARSHALLING_BOOL_RETURNS as M_BOOL;
use crate::pass::{Pass, PassResult};
use crate::type_infer::known_of_type_ref;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-bool-return";

/// Folds a returned `bool`'s widening to its tag back into the `bool`.
#[derive(Debug, Default, Clone, Copy)]
pub struct BoolReturnPass;

impl Pass<HighIr> for BoolReturnPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            let Some(plan) = plan(func) else { continue };
            let count = plan.len();
            for (id, expr) in plan {
                if let Some(b) = func.bindings.get_mut(id) {
                    if let Some(expr) = expr {
                        b.expr = expr;
                    }
                    b.ty = IrType::Known(KnownType::Bool);
                    b.add_provenance(Provenance::new(
                        PASS_NAME,
                        ProvenanceSource::SdkPattern,
                        "a `bool` returned as its tag: the `bool`",
                    ));
                }
            }
            result.metrics.increment(M_BOOL, count as i64);
            result.changed = true;
        }
        result
    }
}

/// The rewrites for one function, or `None` when it has nothing to fold.
/// `None` in a pair keeps the binding's expression and retypes it.
fn plan(func: &HighFunction) -> Option<Vec<(ValueId, Option<Expr>)>> {
    let sig = func.signature.as_ref()?;
    let [out] = sig.outputs.as_slice() else { return None };
    if known_of_type_ref(out)? != KnownType::Bool {
        return None;
    }
    let mut plan = Vec::new();
    let mut seen = HashSet::new();
    for r in returned_values(func) {
        if !seen.insert(r) {
            continue;
        }
        match arm(func, r) {
            Some(Some(fold)) => {
                plan.push((r, Some(fold)));
                continue;
            }
            Some(None) => continue, // already a `bool`
            None => {}
        }
        let Some(Expr::Phi { incoming }) = func.bindings.get(r).map(|b| &b.expr) else {
            continue;
        };
        let arms: Option<Vec<_>> = incoming
            .iter()
            .map(|(_, v)| resolve_use(func, *v))
            .collect::<HashSet<_>>()
            .into_iter()
            .map(|v| arm(func, v).map(|fold| (v, fold)))
            .collect();
        let Some(arms) = arms else { continue };
        if arms.iter().all(|(_, fold)| fold.is_none()) {
            continue; // already all `bool`s: nothing was widened
        }
        plan.extend(arms.into_iter().filter(|(_, fold)| fold.is_some()));
        plan.push((r, None));
    }
    (!plan.is_empty()).then_some(plan)
}

/// One returned value's fold: `Some(Some(e))` rewrites it to `e`,
/// `Some(None)` means it is already a `bool`, `None` that it is neither.
fn arm(func: &HighFunction, v: ValueId) -> Option<Option<Expr>> {
    let b = func.bindings.get(v)?;
    if matches!(b.ty, IrType::Known(KnownType::Bool) | IrType::Inferred(KnownType::Bool)) {
        return Some(None);
    }
    match &b.expr {
        Expr::Unary { op: UnaryOp::ExtendU32, value } if is_bool(func, resolve_use(func, *value)) => {
            Some(Some(Expr::Use(resolve_use(func, *value))))
        }
        Expr::Literal(Literal::I64(n @ (0 | 1))) if only_returned(func, v) => {
            Some(Some(Expr::Literal(Literal::Bool(*n == 1))))
        }
        Expr::Literal(Literal::I32(n @ (0 | 1))) if only_returned(func, v) => {
            Some(Some(Expr::Literal(Literal::Bool(*n == 1))))
        }
        _ => None,
    }
}

/// A `bool` by type or by construction: a comparison, a negation, or a
/// bitwise combination of `bool`s.
fn is_bool(func: &HighFunction, v: ValueId) -> bool {
    bool_like(func, v, 0)
}

fn bool_like(func: &HighFunction, v: ValueId, depth: u32) -> bool {
    let Some(b) = func.bindings.get(v) else { return false };
    if matches!(b.ty, IrType::Known(KnownType::Bool) | IrType::Inferred(KnownType::Bool)) {
        return true;
    }
    if depth > 4 {
        return false;
    }
    match &b.expr {
        Expr::Binary { op, lhs, rhs } => match op {
            BinaryOp::Eq | BinaryOp::Ne | BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => true,
            BinaryOp::BitAnd | BinaryOp::BitOr | BinaryOp::BitXor => {
                bool_like(func, resolve_use(func, *lhs), depth + 1)
                    && bool_like(func, resolve_use(func, *rhs), depth + 1)
            }
            _ => false,
        },
        Expr::Unary { op: UnaryOp::Eqz | UnaryOp::Not, .. } | Expr::IsSome { .. } => true,
        Expr::Use(inner) => bool_like(func, resolve_use(func, *inner), depth + 1),
        _ => false,
    }
}

/// Nothing the body still executes reads `v` except as a phi arm or a
/// return: the literal is the returned `false`, not a number used elsewhere.
fn only_returned(func: &HighFunction, v: ValueId) -> bool {
    let scheduled: HashSet<ValueId> =
        func.blocks.iter().flat_map(|(_, b)| b.bindings.iter().copied()).collect();
    !func.bindings.iter().any(|(id, b)| {
        if matches!(b.expr, Expr::Phi { .. }) || !scheduled.contains(&id) {
            return false;
        }
        let mut reads = false;
        b.expr.for_each_value_use(|u| reads |= resolve_use(func, u) == v);
        reads
    })
}

/// Every value a `return` in the structured body hands back.
fn returned_values(func: &HighFunction) -> Vec<ValueId> {
    let mut values = Vec::new();
    func.region.for_each_node(|node| {
        if let Region::Return { values: returned } = node {
            values.extend(returned.iter().map(|v| resolve_use(func, *v)));
        }
    });
    values
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};
    use sordec_common::{BlockId, IrId};
    use sordec_ir::{FunctionSignature, PrimitiveType, TypeRef};

    /// `r = phi [0, extend_u32(flag)]; return r` from a function the spec
    /// says returns `ty`.
    fn shape(ty: PrimitiveType) -> HighIr {
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                                // v0: flag
                Expr::Literal(Literal::I64(0)),                                // v1
                Expr::Unary { op: UnaryOp::ExtendU32, value: v(0) },           // v2
                Expr::Phi { incoming: vec![(BlockId::from_index(0), v(1)), (BlockId::from_index(1), v(2))] }, // v3
            ],
            vec![v(0)],
            vec![1, 2],
        );
        f.bindings.get_mut(v(0)).unwrap().ty = IrType::Inferred(KnownType::Bool);
        f.signature = Some(FunctionSignature {
            name: "verify".into(),
            inputs: vec![],
            outputs: vec![TypeRef::Primitive(ty)],
        });
        f.region = Region::Return { values: vec![v(3)] };
        module(vec![f])
    }

    #[test]
    fn a_returned_tag_is_the_bool() {
        let mut ir = shape(PrimitiveType::Bool);
        assert!(BoolReturnPass.run(&mut ir).changed);
        let f = &ir.functions[0];
        assert!(matches!(f.bindings.get(v(1)).unwrap().expr, Expr::Literal(Literal::Bool(false))));
        assert!(matches!(f.bindings.get(v(2)).unwrap().expr, Expr::Use(x) if x == v(0)));
        assert_eq!(f.bindings.get(v(3)).unwrap().ty, IrType::Known(KnownType::Bool));
    }

    #[test]
    fn another_return_type_is_left_alone() {
        let mut ir = shape(PrimitiveType::U64);
        assert!(!BoolReturnPass.run(&mut ir).changed);
    }

    #[test]
    fn the_pass_is_idempotent() {
        let mut ir = shape(PrimitiveType::Bool);
        assert!(BoolReturnPass.run(&mut ir).changed);
        assert!(!BoolReturnPass.run(&mut ir).changed);
    }
}
