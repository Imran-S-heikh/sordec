//! An `Option` parameter tested against `Void` is tested for `None`.
//!
//! # The shape
//!
//! `pub fn option(e: Env, option: Option<u32>) -> Option<u32> { option }`
//! decodes its argument and encodes it again. An `Option` travels as its
//! payload's `Val`, or as `Void` (tag 2, body 0 — the whole `Val` is `2`)
//! for `None`, so both directions test and produce that constant:
//!
//! ```text
//! if option == 2 { return 2 }        if !option.is_some() { return None }
//! …payload tag check…           →    …
//! return option                      return option
//! ```
//!
//! The decode collapse ([`super::decode`]) has already named the parameter
//! and typed it `Option<u32>`, so left alone the test compares an `Option`
//! with an `i64` and the early return hands back an `i64` for one.
//!
//! # Why it is exact
//!
//! `Void` is the encoding of `None` and of nothing else an `Option<T>` can
//! hold — no `T` encodes to it — so equality with it is `is_none()`. And a
//! function declared to return an `Option` returning `Void` returns `None`.
//!
//! # Gates
//!
//! - **The parameter's type is the spec's.** An entrypoint parameter
//!   declared `Option<T>`.
//! - **A returned `2` only where the spec returns an `Option`**, and only
//!   when every use of that constant is a return.

use sordec_common::{Provenance, ProvenanceSource, ValueId};
use sordec_ir::{BinaryOp, Expr, HighFunction, HighIr, IrType, KnownType, Literal, Region, UnaryOp};

use crate::dataflow::resolve_use;
use crate::metrics_catalog::MARSHALLING_OPTION_PARAMS as M_OPTION;
use crate::pass::{Pass, PassResult};
use crate::type_infer::known_of_type_ref;
use crate::val_abi::TAG_VOID;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-option-param";

/// Folds `Void` tests of an `Option` parameter, and `Void` returned as one.
#[derive(Debug, Default, Clone, Copy)]
pub struct OptionParamPass;

impl Pass<HighIr> for OptionParamPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            let tests = tests(func);
            let nones = returned_nones(func);
            let count = tests.len() + nones.len();
            for (id, expr) in tests {
                rewrite(func, id, expr, IrType::Inferred(KnownType::Bool), "an `Option` compared with `Void` is tested for `None`");
            }
            for (id, ty) in nones {
                rewrite(func, id, Expr::Optional { payload: None }, ty, "`Void` returned as an `Option` is `None`");
            }
            if count > 0 {
                result.metrics.increment(M_OPTION, count as i64);
                result.changed = true;
            }
        }
        result
    }
}

fn rewrite(func: &mut HighFunction, id: ValueId, expr: Expr, ty: IrType, note: &'static str) {
    if let Some(b) = func.bindings.get_mut(id) {
        b.expr = expr;
        b.ty = ty;
        b.add_provenance(Provenance::new(PASS_NAME, ProvenanceSource::SdkPattern, note));
    }
}

/// `p == Void` and `p != Void` for an `Option` parameter `p`, as the
/// bindings to rewrite. `!=` is `p.is_some()` in place. `==` needs the
/// `is_some()` as an operand of its `!`, and takes the `Void` literal's
/// binding for it — only when the comparison is that literal's one reader.
fn tests(func: &HighFunction) -> Vec<(ValueId, Expr)> {
    let returned = returned_values(func);
    let mut out = Vec::new();
    for (id, b) in func.bindings.iter() {
        let Expr::Binary { op: op @ (BinaryOp::Eq | BinaryOp::Ne), lhs, rhs } = &b.expr else {
            continue;
        };
        let (l, r) = (resolve_use(func, *lhs), resolve_use(func, *rhs));
        let (value, void) = if is_void(func, r) && is_option_param(func, l) {
            (l, r)
        } else if is_void(func, l) && is_option_param(func, r) {
            (r, l)
        } else {
            continue;
        };
        if *op == BinaryOp::Ne {
            out.push((id, Expr::IsSome { value }));
        } else if readers(func, void) == 1 && !returned.contains(&void) {
            out.push((void, Expr::IsSome { value }));
            out.push((id, Expr::Unary { op: UnaryOp::Not, value: void }));
        }
    }
    out
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

/// How many bindings the body still executes read `v`. Pruning residue
/// left unscheduled in the arena is not a reader.
fn readers(func: &HighFunction, v: ValueId) -> usize {
    let scheduled: std::collections::HashSet<ValueId> =
        func.blocks.iter().flat_map(|(_, b)| b.bindings.iter().copied()).collect();
    func.bindings
        .iter()
        .filter(|(id, b)| {
            if !scheduled.contains(id) {
                return false;
            }
            let mut reads = false;
            b.expr.for_each_value_use(|u| reads |= resolve_use(func, u) == v);
            reads
        })
        .count()
}

/// Literal `Void` bindings used only by return sites of a function whose
/// spec returns an `Option`, with that `Option`'s type.
fn returned_nones(func: &HighFunction) -> Vec<(ValueId, IrType)> {
    let Some(sig) = &func.signature else {
        return Vec::new();
    };
    let [out] = sig.outputs.as_slice() else {
        return Vec::new();
    };
    let Some(ty @ KnownType::Option(_)) = known_of_type_ref(out) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for v in returned_values(func) {
        if out.iter().any(|(o, _)| *o == v) || !is_void(func, v) {
            continue;
        }
        // Read anywhere but a return, it is the number, not the `None`.
        if readers(func, v) == 0 {
            out.push((v, IrType::Known(ty.clone())));
        }
    }
    out
}

fn is_void(func: &HighFunction, v: ValueId) -> bool {
    matches!(
        func.bindings.get(v).map(|b| &b.expr),
        Some(Expr::Literal(Literal::I64(n))) if *n == i64::from(TAG_VOID)
    )
}

/// An entrypoint parameter the spec declares `Option<T>`.
fn is_option_param(func: &HighFunction, v: ValueId) -> bool {
    let Some(sig) = &func.signature else {
        return false;
    };
    func.params
        .iter()
        .position(|p| *p == v)
        .and_then(|i| sig.inputs.get(i))
        .and_then(|input| known_of_type_ref(&input.ty))
        .is_some_and(|t| matches!(t, KnownType::Option(_)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};
    use sordec_ir::{CompositeType, FunctionParam, FunctionSignature, PrimitiveType, TypeRef};

    /// `option == 2` over a parameter declared `Option<u32>`, then a
    /// separate `2` returned from a function declared to return one.
    fn shape(op: BinaryOp) -> HighIr {
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                     // v0: option
                Expr::Literal(Literal::I64(2)),                     // v1
                Expr::Binary { op, lhs: v(0), rhs: v(1) },          // v2
                Expr::Literal(Literal::I64(2)),                     // v3: returned
            ],
            vec![v(0)],
            vec![1, 2, 3],
        );
        let opt = TypeRef::Composite(CompositeType::Option(Box::new(TypeRef::Primitive(PrimitiveType::U32))));
        f.signature = Some(FunctionSignature {
            name: "option".into(),
            inputs: vec![FunctionParam { name: "option".into(), ty: opt.clone() }],
            outputs: vec![opt],
        });
        f.region = Region::Sequence(vec![
            Region::Return { values: vec![v(3)] },
            Region::Return { values: vec![v(0)] },
        ]);
        module(vec![f])
    }

    #[test]
    fn a_void_test_of_an_option_parameter_is_a_none_test() {
        let mut ir = shape(BinaryOp::Eq);
        assert!(OptionParamPass.run(&mut ir).changed);
        let f = &ir.functions[0];
        assert!(matches!(f.bindings.get(v(1)).unwrap().expr, Expr::IsSome { value } if value == v(0)));
        assert!(matches!(f.bindings.get(v(2)).unwrap().expr, Expr::Unary { op: UnaryOp::Not, value } if value == v(1)));
        assert!(matches!(f.bindings.get(v(3)).unwrap().expr, Expr::Optional { payload: None }));
    }

    #[test]
    fn a_not_void_test_is_is_some() {
        let mut ir = shape(BinaryOp::Ne);
        assert!(OptionParamPass.run(&mut ir).changed);
        let f = &ir.functions[0];
        assert!(matches!(f.bindings.get(v(2)).unwrap().expr, Expr::IsSome { value } if value == v(0)));
        assert!(matches!(f.bindings.get(v(1)).unwrap().expr, Expr::Literal(_)), "the literal is left alone");
    }

    #[test]
    fn a_parameter_declared_otherwise_is_left_alone() {
        let mut ir = shape(BinaryOp::Eq);
        let sig = ir.functions[0].signature.as_mut().unwrap();
        sig.inputs[0].ty = TypeRef::Primitive(PrimitiveType::U32);
        sig.outputs[0] = TypeRef::Primitive(PrimitiveType::U32);
        assert!(!OptionParamPass.run(&mut ir).changed);
    }
}
