//! A host length is already the `u32` the SDK hands back.
//!
//! # The shape
//!
//! `vec_len` and `map_len` return a `U32Val`, and the SDK's `len()` decodes
//! it to the `u32` the source sees.
//! The collections recognizer names the call `v.len()` and types it `u32`,
//! so that decode has already happened in the name — but its instructions
//! are still there, and so is the re-encode when the length goes back to
//! the host:
//!
//! ```text
//! n = vec_len(v)        : u32         n = v.len()
//! c = val_decode(n)                →  c = n
//! s = (n & !0xFFFF_FFFF) | 4          s = n
//! ```
//!
//! Left alone the first is a hole and the second masks a `u32` with an
//! `i64` (`account`'s `__constructor`, which stores `signers.len()`).
//!
//! # Why it is exact
//!
//! A `U32Val` is the `u32` in the high word over tag 4. Decoding it is the
//! `u32`, and masking off the low word and setting the tag again rebuilds
//! the same `Val` — which is what the store's `IntoVal` makes of `&n`. The
//! host guarantees the tag, so there is no check to keep.
//!
//! # Gates
//!
//! - **Only a collection length.** The result type is the host ABI's, not
//!   an inference. `bytes_len` is left to [`super::bytesn_convert`], whose
//!   `BytesN<N>` conversion is recognized by that same decode.
//! - **Only the exact re-encode.** `and` with the high-word mask, then `or`
//!   with the `U32Val` tag; any other constant is not this.

use sordec_common::{Provenance, ProvenanceSource, ValueId};
use sordec_ir::{
    BinaryOp, Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Literal,
    MapOpKind, SemanticOp, VecOpKind,
};

use crate::dataflow::resolve_use;
use crate::metrics_catalog::MARSHALLING_HOST_LEN_CODECS as M_LEN;
use crate::pass::{Pass, PassResult};
use crate::val_abi::TAG_U32_VAL;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-host-len";

/// Folds the decode and re-encode of a host length into the length.
#[derive(Debug, Default, Clone, Copy)]
pub struct HostLenPass;

impl Pass<HighIr> for HostLenPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            let folds = folds(func);
            for &(id, len, note) in &folds {
                if let Some(b) = func.bindings.get_mut(id) {
                    b.expr = Expr::Use(len);
                    b.ty = IrType::Known(KnownType::U32);
                    b.add_provenance(Provenance::new(PASS_NAME, ProvenanceSource::SdkPattern, note));
                }
            }
            if !folds.is_empty() {
                result.metrics.increment(M_LEN, folds.len() as i64);
                result.changed = true;
            }
        }
        result
    }
}

/// Each decode or re-encode of a length, with the length it is.
fn folds(func: &HighFunction) -> Vec<(ValueId, ValueId, &'static str)> {
    func.bindings
        .iter()
        .filter_map(|(id, b)| match &b.expr {
            Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { value })) => {
                let len = resolve_use(func, *value);
                is_len(func, len).then_some((id, len, "decoding a host length is the `u32` `len()` returned"))
            }
            Expr::Binary { op: BinaryOp::BitOr, lhs, rhs } if literal(func, *rhs) == Some(i64::from(TAG_U32_VAL)) => {
                let Some(Expr::Binary { op: BinaryOp::BitAnd, lhs: n, rhs: mask }) =
                    func.bindings.get(resolve_use(func, *lhs)).map(|b| &b.expr)
                else {
                    return None;
                };
                let len = resolve_use(func, *n);
                (literal(func, *mask) == Some(-0x1_0000_0000) && is_len(func, len))
                    .then_some((id, len, "re-encoding a host length is the length"))
            }
            _ => None,
        })
        .collect()
}

/// A collection length, which the host returns as a `U32Val`.
fn is_len(func: &HighFunction, v: ValueId) -> bool {
    matches!(
        func.bindings.get(v).map(|b| &b.expr),
        Some(Expr::Semantic(SemanticOp::Known(
            KnownOp::VecOp { kind: VecOpKind::Len, .. }
                | KnownOp::MapOp { kind: MapOpKind::Len, .. }
        )))
    )
}

fn literal(func: &HighFunction, v: ValueId) -> Option<i64> {
    match func.bindings.get(resolve_use(func, v)).map(|b| &b.expr) {
        Some(Expr::Literal(Literal::I64(n))) => Some(*n),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};

    /// `n = vec_len(v0); c = val_decode(n); s = (n & !0xFFFF_FFFF) | 4`.
    fn shape(mask: i64) -> HighIr {
        module(vec![func_with(
            vec![
                Expr::Phi { incoming: vec![] },                                                      // v0
                Expr::Semantic(SemanticOp::Known(KnownOp::VecOp { kind: VecOpKind::Len, args: vec![v(0)] })), // v1
                Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { value: v(1) })),          // v2
                Expr::Literal(Literal::I64(mask)),                                                   // v3
                Expr::Binary { op: BinaryOp::BitAnd, lhs: v(1), rhs: v(3) },                         // v4
                Expr::Literal(Literal::I64(4)),                                                      // v5
                Expr::Binary { op: BinaryOp::BitOr, lhs: v(4), rhs: v(5) },                          // v6
            ],
            vec![v(0)],
            vec![1, 2, 3, 4, 5, 6],
        )])
    }

    #[test]
    fn a_length_s_decode_and_re_encode_are_the_length() {
        let mut ir = shape(-0x1_0000_0000);
        assert!(HostLenPass.run(&mut ir).changed);
        let f = &ir.functions[0];
        for id in [v(2), v(6)] {
            assert!(matches!(f.bindings.get(id).unwrap().expr, Expr::Use(n) if n == v(1)));
            assert_eq!(f.bindings.get(id).unwrap().ty, IrType::Known(KnownType::U32));
        }
    }

    #[test]
    fn another_mask_is_not_the_re_encode() {
        let mut ir = shape(-0x100);
        HostLenPass.run(&mut ir);
        let f = &ir.functions[0];
        assert!(matches!(f.bindings.get(v(6)).unwrap().expr, Expr::Binary { .. }));
        assert!(matches!(f.bindings.get(v(2)).unwrap().expr, Expr::Use(_)), "the decode still folds");
    }
}
