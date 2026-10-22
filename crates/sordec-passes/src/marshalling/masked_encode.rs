//! A 32-bit value re-encoded with one mask is the value.
//!
//! # The shape
//!
//! `pub fn i32_(e: Env, i32_: i32) -> i32 { i32_ }` decodes its argument
//! and encodes it again to return it. The argument arrives as the `I32Val`
//! — the `i32` in the high word over tag 5 — and the decode collapse
//! ([`super::decode`]) has already named it `i32_`. What is left is the
//! re-encode, which LLVM folds into a single mask because the tag is known:
//!
//! ```text
//! r = i32_ & 0xFFFF_FFFF_0000_0005      →   r = i32_
//! return r
//! ```
//!
//! `u32` the same, over tag 4. `other_custom_types` has five of them, each
//! printing as a `u32 & i64` that does not compile.
//!
//! # Why it is exact
//!
//! On a well-formed encoding the low word is exactly the tag, so the mask
//! changes nothing: the result is the `Val` the value already was, and the
//! returned or stored `p` is encoded to that same `Val` by its `IntoVal`.
//! The all-ones high word is what makes this the encoded form: a value
//! already decoded to a number has a zero high word, and LLVM would have
//! folded the mask to its tag bit.
//!
//! # Gates
//!
//! - **The mask is the type's own.** Tag 4 for a `u32`, tag 5 for an `i32`,
//!   over an all-ones high word. Nothing else.
//! - **The type is the spec's or a recovered one.** An entrypoint
//!   parameter's declared type first, since type inference runs later.

use sordec_common::{Provenance, ProvenanceSource, ValueId};
use sordec_ir::{BinaryOp, Expr, HighFunction, HighIr, IrType, KnownType, Literal};

use crate::dataflow::resolve_use;
use crate::metrics_catalog::MARSHALLING_MASKED_ENCODES as M_MASKED;
use crate::pass::{Pass, PassResult};
use crate::type_infer::known_of_type_ref;
use crate::val_abi::{TAG_I32_VAL, TAG_U32_VAL};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-masked-encode";

/// Folds a 32-bit value's single-mask re-encode into the value.
#[derive(Debug, Default, Clone, Copy)]
pub struct MaskedEncodePass;

impl Pass<HighIr> for MaskedEncodePass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            let folds = folds(func);
            let count = folds.len();
            for (id, value, ty) in folds {
                if let Some(b) = func.bindings.get_mut(id) {
                    b.expr = Expr::Use(value);
                    b.ty = ty;
                    b.add_provenance(Provenance::new(
                        PASS_NAME,
                        ProvenanceSource::SdkPattern,
                        "a 32-bit value masked with its own encoding is the value",
                    ));
                }
            }
            if count > 0 {
                result.metrics.increment(M_MASKED, count as i64);
                result.changed = true;
            }
        }
        result
    }
}

/// Each `p & (0xFFFF_FFFF_0000_0000 | tag)` with `p` of the type `tag` encodes.
fn folds(func: &HighFunction) -> Vec<(ValueId, ValueId, IrType)> {
    func.bindings
        .iter()
        .filter_map(|(id, b)| {
            let Expr::Binary { op: BinaryOp::BitAnd, lhs, rhs } = &b.expr else {
                return None;
            };
            let (l, r) = (resolve_use(func, *lhs), resolve_use(func, *rhs));
            let (value, mask) = match (literal(func, l), literal(func, r)) {
                (None, Some(m)) => (l, m),
                (Some(m), None) => (r, m),
                _ => return None,
            };
            let ty = declared(func, value).or_else(|| func.bindings.get(value).map(|b| b.ty.clone()))?;
            let tag = match &ty {
                IrType::Known(KnownType::U32) | IrType::Inferred(KnownType::U32) => TAG_U32_VAL,
                IrType::Known(KnownType::I32) | IrType::Inferred(KnownType::I32) => TAG_I32_VAL,
                _ => return None,
            };
            (mask == encoding_mask(tag)).then_some((id, value, ty))
        })
        .collect()
}

/// An entrypoint parameter's type as the spec declares it. Type inference
/// runs after this pass, so the binding may not carry it yet.
fn declared(func: &HighFunction, value: ValueId) -> Option<IrType> {
    let sig = func.signature.as_ref()?;
    let i = func.params.iter().position(|p| *p == value)?;
    known_of_type_ref(&sig.inputs.get(i)?.ty).map(IrType::Known)
}

/// The all-ones high word over `tag`, as the signed constant wasm carries.
fn encoding_mask(tag: u8) -> i64 {
    (0xFFFF_FFFF_0000_0000_u64 | u64::from(tag)).cast_signed()
}

fn literal(func: &HighFunction, v: ValueId) -> Option<i64> {
    match func.bindings.get(v).map(|b| &b.expr) {
        Some(Expr::Literal(Literal::I64(n))) => Some(*n),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};

    fn masked(ty: KnownType, mask: i64) -> HighIr {
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                              // v0
                Expr::Literal(Literal::I64(mask)),                           // v1
                Expr::Binary { op: BinaryOp::BitAnd, lhs: v(0), rhs: v(1) }, // v2
            ],
            vec![v(0)],
            vec![1, 2],
        );
        f.bindings.get_mut(v(0)).unwrap().ty = IrType::Known(ty);
        module(vec![f])
    }

    #[test]
    fn the_type_s_own_mask_is_the_value() {
        for (ty, mask) in [(KnownType::I32, -4_294_967_291), (KnownType::U32, -4_294_967_292)] {
            let mut ir = masked(ty.clone(), mask);
            assert!(MaskedEncodePass.run(&mut ir).changed);
            let b = ir.functions[0].bindings.get(v(2)).unwrap();
            assert!(matches!(b.expr, Expr::Use(p) if p == v(0)));
            assert_eq!(b.ty, IrType::Known(ty));
        }
    }

    #[test]
    fn another_type_s_mask_is_left_alone() {
        // A `u32` masked with the `I32Val` tag is not its encoding.
        let mut ir = masked(KnownType::U32, -4_294_967_291);
        assert!(!MaskedEncodePass.run(&mut ir).changed);
    }
}
