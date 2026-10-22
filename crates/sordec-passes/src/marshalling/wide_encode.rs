//! The SDK's 128-bit `IntoVal`, inlined, is the value it encodes.
//!
//! # The shape
//!
//! [`super::wide_codec`] folds the encode when rustc outlines it into a
//! helper. When it is inlined instead — `token::Client::transfer(&from,
//! &to, &amount)` inside a helper that took `amount` in two registers —
//! the two encodings are two arms in the body itself:
//!
//! ```text
//! if fits_small(lo, hi) {
//!     v = val_encode<i128>(lo)                v = amount
//! } else {                               →
//!     v = obj_from_i128_pieces(hi, lo)        v = amount
//! }
//! transfer(.., v)
//! ```
//!
//! Left alone, both arms are holes, the `Val` they merge into is handed
//! where the client wants an `&i128`, and the limb arithmetic of the range
//! test (`lo ^ lo`, `hi ^ (lo >> 63)`) mixes an `i128` with an `i64`.
//!
//! # Why it is exact
//!
//! Each arm is one of the two encodings of the same value, chosen by
//! whether it fits — so each arm's result is the `Val` of `wide(lo, hi)`,
//! and the typed value in its place is encoded to that same `Val` by
//! whatever consumes it. The branch is then two arms doing the same work.
//!
//! # Gates
//!
//! - **Both forms, over the same limbs.** The small encode of `lo` and the
//!   object built from `(hi, lo)` in the same function. One alone is not
//!   the conversion: a small encode of a bare `i64` is something else.
//! - **The pair agrees on signedness.** `i128` small with the `i128`
//!   constructor, `u128` with `u128`.
//! - **Not the outlined encoder.** A function returning the encoded value
//!   is the helper [`super::wide_codec`] recognizes by these arms.

use std::collections::HashMap;

use sordec_common::{Provenance, ProvenanceSource, ValueId};
use sordec_ir::{
    Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, SemanticOp, UnaryOp, ValObjectKind,
};

use crate::dataflow::resolve_use;
use crate::metrics_catalog::MARSHALLING_WIDE_ENCODES_INLINE as M_INLINE;
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-wide-encode";

/// Folds an inlined 128-bit encode into the value.
#[derive(Debug, Default, Clone, Copy)]
pub struct WideEncodePass;

impl Pass<HighIr> for WideEncodePass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            let folds = folds(func);
            let merges = merges(func, &folds);
            if outlined(func, &folds, &merges) {
                continue;
            }
            let count = folds.len();
            for (id, expr, ty) in folds {
                if let Some(b) = func.bindings.get_mut(id) {
                    b.expr = expr;
                    b.ty = IrType::Inferred(ty);
                    b.add_provenance(Provenance::new(
                        PASS_NAME,
                        ProvenanceSource::SdkPattern,
                        "one encoding of a 128-bit value: the value",
                    ));
                }
            }
            for (id, ty) in merges {
                if let Some(b) = func.bindings.get_mut(id) {
                    b.ty = IrType::Inferred(ty);
                    b.add_provenance(Provenance::new(
                        PASS_NAME,
                        ProvenanceSource::SdkPattern,
                        "the merge of a 128-bit encode's arms: the value's type",
                    ));
                }
            }
            if count > 0 {
                result.metrics.increment(M_INLINE, count as i64);
                result.changed = true;
            }
        }
        result
    }
}

/// Each arm of an inlined 128-bit encode, with the value and its type.
fn folds(func: &HighFunction) -> Vec<(ValueId, Expr, KnownType)> {
    // The object arms first: they name both limbs. Keyed by `lo` and
    // whether the type is signed.
    let mut objects: HashMap<(ValueId, bool), Vec<(ValueId, ValueId)>> = HashMap::new();
    for (id, b) in func.bindings.iter() {
        if let Expr::Semantic(SemanticOp::Known(KnownOp::ValObject { kind, args })) = &b.expr
            && let [hi, lo] = args.as_slice()
            && let Some(ty) = constructed(*kind)
        {
            let lo = resolve_use(func, *lo);
            objects.entry((lo, ty == KnownType::I128)).or_default().push((id, resolve_use(func, *hi)));
        }
    }
    let mut out = Vec::new();
    for (id, b) in func.bindings.iter() {
        let Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty, value })) = &b.expr else {
            continue;
        };
        if !matches!(ty, KnownType::I128 | KnownType::U128) {
            continue;
        }
        let lo = resolve_use(func, *value);
        let Some(arms) = objects.get(&(lo, *ty == KnownType::I128)) else {
            continue;
        };
        // Every object arm over this `lo` must name the same `hi`.
        let hi = arms[0].1;
        if arms.iter().any(|(_, h)| *h != hi) {
            continue;
        }
        let whole = whole_of(func, lo, hi);
        out.push((id, whole.clone(), ty.clone()));
        out.extend(arms.iter().map(|(obj, _)| (*obj, whole.clone(), ty.clone())));
    }
    out
}

/// Whether this function hands the encoded value back: the outlined
/// encoder [`super::wide_codec`] recognizes by these very arms, and folds
/// at its call sites.
fn outlined(func: &HighFunction, folds: &[(ValueId, Expr, KnownType)], merges: &[(ValueId, KnownType)]) -> bool {
    func.returns.iter().flatten().any(|v| {
        let v = resolve_use(func, *v);
        folds.iter().any(|(f, ..)| *f == v) || merges.iter().any(|(m, _)| *m == v)
    })
}

/// Phis every incoming value of which is a folded arm: the variable the
/// two arms assign. Typed as the value, since it was typed as the `Val`
/// they used to produce.
fn merges(func: &HighFunction, folds: &[(ValueId, Expr, KnownType)]) -> Vec<(ValueId, KnownType)> {
    func.bindings
        .iter()
        .filter_map(|(id, b)| {
            let Expr::Phi { incoming } = &b.expr else {
                return None;
            };
            let ty = |v: ValueId| folds.iter().find(|(f, ..)| *f == resolve_use(func, v)).map(|(.., t)| t);
            let first = ty(incoming.first()?.1)?;
            incoming.iter().all(|(_, v)| ty(*v) == Some(first)).then(|| (id, first.clone()))
        })
        .collect()
}

/// The 128-bit type an object constructor builds from its two pieces.
fn constructed(kind: ValObjectKind) -> Option<KnownType> {
    match kind {
        ValObjectKind::ObjFromI128Pieces => Some(KnownType::I128),
        ValObjectKind::ObjFromU128Pieces => Some(KnownType::U128),
        _ => None,
    }
}

/// The value `lo` and `hi` are the halves of: the one they were taken
/// from, when both name it, else the join of the two.
fn whole_of(func: &HighFunction, lo: ValueId, hi: ValueId) -> Expr {
    let limb = |v: ValueId, want: UnaryOp| match func.bindings.get(v).map(|b| &b.expr) {
        Some(Expr::Unary { op, value }) if *op == want => Some(resolve_use(func, *value)),
        _ => None,
    };
    match (limb(lo, UnaryOp::WideLo), limb(hi, UnaryOp::WideHi)) {
        (Some(a), Some(b)) if a == b => Expr::Use(a),
        _ => Expr::WideJoin { lo, hi },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};

    /// `w`; its limbs; the small encode of `lo`; the object from `(hi, lo)`.
    fn shape(small: KnownType, object: ValObjectKind) -> HighIr {
        module(vec![func_with(
            vec![
                Expr::Phi { incoming: vec![] },                         // v0: w
                Expr::Unary { op: UnaryOp::WideLo, value: v(0) },       // v1
                Expr::Unary { op: UnaryOp::WideHi, value: v(0) },       // v2
                Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty: small, value: v(1) })), // v3
                Expr::Semantic(SemanticOp::Known(KnownOp::ValObject { kind: object, args: vec![v(2), v(1)] })), // v4
            ],
            vec![v(0)],
            vec![1, 2, 3, 4],
        )])
    }

    #[test]
    fn both_arms_of_an_inlined_encode_are_the_value() {
        let mut ir = shape(KnownType::I128, ValObjectKind::ObjFromI128Pieces);
        assert!(WideEncodePass.run(&mut ir).changed);
        for id in [v(3), v(4)] {
            let b = ir.functions[0].bindings.get(id).unwrap();
            assert!(matches!(b.expr, Expr::Use(w) if w == v(0)));
            assert_eq!(b.ty, IrType::Inferred(KnownType::I128));
        }
    }

    /// An `i128` small encode beside a `u128` object is not one conversion.
    #[test]
    fn mismatched_signedness_is_left_alone() {
        let mut ir = shape(KnownType::I128, ValObjectKind::ObjFromU128Pieces);
        assert!(!WideEncodePass.run(&mut ir).changed);
    }

    #[test]
    fn the_pass_is_idempotent() {
        let mut ir = shape(KnownType::U128, ValObjectKind::ObjFromU128Pieces);
        assert!(WideEncodePass.run(&mut ir).changed);
        assert!(!WideEncodePass.run(&mut ir).changed);
    }
}
