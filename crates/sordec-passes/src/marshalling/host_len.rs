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
//!
//! # And a bound checked on the raw `Val`
//!
//! The SDK's `Vec::get(i)` checks `i` against the length without decoding
//! it: `account`'s `args.get(2)` is `raw_len <= 0x2_FFFF_FFFF`, the raw form
//! of `len < 3`. With the length named `len()` that read `v.len() <= 12884901887`,
//! a `u32` against an `i64`. The raw value is `len · 2³² + 4`, so
//!
//! ```text
//! raw <= C  ⟺  len <= ⌊(C − 4) / 2³²⌋        raw == C  ⟺  len == C >> 32
//! ```
//!
//! (with `<` as `<= C − 1`, and `>`, `>=`, `!=` their negations), and the
//! comparison is rewritten on the length. The lowering has erased the
//! comparison's signedness, which is safe here: signed and unsigned order
//! agree on every raw value with `len < 2³¹`, and no Soroban collection
//! approaches that. A bound outside the `u32` range, or an equality with a
//! constant that is no `U32Val`, is left alone.
//!
//! # And two lengths compared through their raw words
//!
//! `tot_signers == signatures.len()` compiles to the two raw `U32Val`s
//! xored and tested `< 2³²` unsigned: the tags cancel, leaving
//! `(a ^ b) << 32`, which is below 2³² exactly when the payloads are equal.
//! Rewritten as the `==` it is (`>=` as `!=`) when both sides are raw
//! `U32Val` words — a host length, or a storage read checked as one — and the
//! comparison was lowered from an unsigned opcode. Under a signed one a
//! payload xor with its top bit set also passes, so that is not equality and
//! is left alone.

use sordec_common::{IrId, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{
    BinaryOp, Binding, Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Literal,
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
            let equalities = equalities(func);
            for &(cmp, op, a, b) in &equalities {
                if let Some(binding) = func.bindings.get_mut(cmp) {
                    binding.expr = Expr::Binary { op, lhs: a, rhs: b };
                    binding.add_provenance(Provenance::new(
                        PASS_NAME,
                        ProvenanceSource::SdkPattern,
                        "two raw `U32Val`s xored and tested below 2^32: their payloads compared",
                    ));
                }
            }
            if !equalities.is_empty() {
                result.metrics.increment(M_LEN, equalities.len() as i64);
                result.changed = true;
            }
            let bounds = bounds(func);
            for &(cmp, op, len, bound) in &bounds {
                let lit = push_literal(func, bound);
                schedule_before(func, cmp, lit);
                if let Some(b) = func.bindings.get_mut(cmp) {
                    b.expr = Expr::Binary { op, lhs: len, rhs: lit };
                    b.add_provenance(Provenance::new(
                        PASS_NAME,
                        ProvenanceSource::SdkPattern,
                        "a bound on a raw host length is the bound on the length",
                    ));
                }
            }
            if !bounds.is_empty() {
                result.metrics.increment(M_LEN, bounds.len() as i64);
                result.changed = true;
            }
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

/// Each comparison of a raw host length with a constant, as the same
/// comparison on the length: `(comparison, op, length, bound)`, length on
/// the left.
fn bounds(func: &HighFunction) -> Vec<(ValueId, BinaryOp, ValueId, u32)> {
    func.bindings
        .iter()
        .filter_map(|(id, b)| {
            let Expr::Binary { op, lhs, rhs } = &b.expr else {
                return None;
            };
            let (lhs, rhs) = (resolve_use(func, *lhs), resolve_use(func, *rhs));
            // Length on the left; a constant on the left flips the order.
            let (op, len, c) = if is_len(func, lhs) {
                (*op, lhs, literal(func, rhs)?)
            } else if is_len(func, rhs) {
                (flipped(*op)?, rhs, literal(func, lhs)?)
            } else {
                return None;
            };
            let (op, bound) = on_length(op, i128::from(c))?;
            Some((id, op, len, u32::try_from(bound).ok()?))
        })
        .collect()
}

/// Each `(a ^ b) <u 2³²` over two raw `U32Val` words, as
/// `(comparison, Eq or Ne, a, b)`.
fn equalities(func: &HighFunction) -> Vec<(ValueId, BinaryOp, ValueId, ValueId)> {
    func.bindings
        .iter()
        .filter_map(|(id, b)| {
            let Expr::Binary { op, lhs, rhs } = &b.expr else {
                return None;
            };
            let op = match op {
                BinaryOp::Lt => BinaryOp::Eq,
                BinaryOp::Ge => BinaryOp::Ne,
                _ => return None,
            };
            if literal(func, *rhs) != Some(1 << 32) || !crate::lowering::lift_to_high::lowered_unsigned(b) {
                return None;
            }
            let Some(Expr::Binary { op: BinaryOp::BitXor, lhs: x, rhs: y }) =
                func.bindings.get(resolve_use(func, *lhs)).map(|b| &b.expr)
            else {
                return None;
            };
            let (x, y) = (resolve_use(func, *x), resolve_use(func, *y));
            (u32_val_word(func, x) && u32_val_word(func, y)).then_some((id, op, x, y))
        })
        .collect()
}

/// A `u32` the IR holds as the raw `U32Val` the host handed over, so that
/// what it renders as is the payload: a collection length, or a storage
/// read the program checks is a `U32Val` (whose typed read is the payload,
/// and traps where that check does).
///
/// Only the payload matters to the xor, whose low word the comparison
/// ignores — the tags need not match for the rewrite to be exact.
fn u32_val_word(func: &HighFunction, v: ValueId) -> bool {
    let read = matches!(
        func.bindings.get(v).map(|b| &b.expr),
        Some(Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet { .. })))
    );
    let checked_u32 = || {
        func.bindings.iter().any(|(_, b)| {
            matches!(
                &b.expr,
                Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck { value, tag, .. }))
                    if *tag == TAG_U32_VAL && resolve_use(func, *value) == v
            )
        })
    };
    is_len(func, v) || (read && checked_u32())
}

/// `raw op c` as `len op' bound`, where `raw = len · 2³² + 4`.
fn on_length(op: BinaryOp, c: i128) -> Option<(BinaryOp, i128)> {
    const WORD: i128 = 1 << 32;
    let tag = i128::from(TAG_U32_VAL);
    // `raw <= c ⟺ len <= ⌊(c − 4) / 2³²⌋`, defined while `c ≥ 4`.
    let le = |c: i128| (c >= tag).then(|| (c - tag).div_euclid(WORD));
    Some(match op {
        BinaryOp::Le => (BinaryOp::Le, le(c)?),
        BinaryOp::Lt => (BinaryOp::Le, le(c - 1)?),
        BinaryOp::Gt => (BinaryOp::Gt, le(c)?),
        BinaryOp::Ge => (BinaryOp::Gt, le(c - 1)?),
        BinaryOp::Eq | BinaryOp::Ne if c.rem_euclid(WORD) == tag => (op, c.div_euclid(WORD)),
        _ => return None,
    })
}

/// The comparison with its operands swapped.
fn flipped(op: BinaryOp) -> Option<BinaryOp> {
    Some(match op {
        BinaryOp::Lt => BinaryOp::Gt,
        BinaryOp::Le => BinaryOp::Ge,
        BinaryOp::Gt => BinaryOp::Lt,
        BinaryOp::Ge => BinaryOp::Le,
        BinaryOp::Eq | BinaryOp::Ne => op,
        _ => return None,
    })
}

/// Append a `u32` literal binding; the caller schedules it.
fn push_literal(func: &mut HighFunction, n: u32) -> ValueId {
    let id = ValueId::from_index(func.bindings.len() as u32);
    func.bindings.push(Binding::new(
        id,
        IrType::Known(KnownType::U32),
        Expr::Literal(Literal::U32(n)),
        Provenance::new(PASS_NAME, ProvenanceSource::SdkPattern, "a raw length bound, decoded"),
    ));
    id
}

/// Schedule `fresh` immediately before `anchor` in whichever block holds it.
fn schedule_before(func: &mut HighFunction, anchor: ValueId, fresh: ValueId) {
    for (_, block) in func.blocks.iter_mut() {
        if let Some(pos) = block.bindings.iter().position(|v| *v == anchor) {
            block.bindings.insert(pos, fresh);
            return;
        }
    }
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

    /// `vec_len(v0) op c`, the constant on the right or the left.
    fn bound(op: BinaryOp, c: i64, constant_first: bool) -> HighIr {
        let (lhs, rhs) = if constant_first { (v(2), v(1)) } else { (v(1), v(2)) };
        module(vec![func_with(
            vec![
                Expr::Phi { incoming: vec![] },                                                      // v0
                Expr::Semantic(SemanticOp::Known(KnownOp::VecOp { kind: VecOpKind::Len, args: vec![v(0)] })), // v1
                Expr::Literal(Literal::I64(c)),                                                      // v2
                Expr::Binary { op, lhs, rhs },                                                       // v3
            ],
            vec![v(0)],
            vec![1, 2, 3],
        )])
    }

    fn rewritten(ir: &HighIr) -> Option<(BinaryOp, u32)> {
        let f = &ir.functions[0];
        let Expr::Binary { op, lhs, rhs } = f.bindings.get(v(3))?.expr else {
            return None;
        };
        assert_eq!(lhs, v(1), "the length on the left");
        match f.bindings.get(rhs)?.expr {
            Expr::Literal(Literal::U32(n)) => Some((op, n)),
            _ => None,
        }
    }

    #[test]
    fn a_raw_length_bound_is_a_bound_on_the_length() {
        // `args.get(2)`: `raw <= 0x2_FFFF_FFFF` is `len <= 2`.
        let mut ir = bound(BinaryOp::Le, 0x2_FFFF_FFFF, false);
        assert!(HostLenPass.run(&mut ir).changed);
        assert_eq!(rewritten(&ir), Some((BinaryOp::Le, 2)));
        // `raw < (3 << 32) | 4` is `len < 3`, i.e. `len <= 2`.
        let mut ir = bound(BinaryOp::Lt, (3 << 32) | 4, false);
        HostLenPass.run(&mut ir);
        assert_eq!(rewritten(&ir), Some((BinaryOp::Le, 2)));
        // `0x2_FFFF_FFFF < raw`, constant first, is `len > 2`.
        let mut ir = bound(BinaryOp::Lt, 0x2_FFFF_FFFF, true);
        HostLenPass.run(&mut ir);
        assert_eq!(rewritten(&ir), Some((BinaryOp::Gt, 2)));
        // An equality with a `U32Val` is one on its payload.
        let mut ir = bound(BinaryOp::Eq, (5 << 32) | 4, false);
        HostLenPass.run(&mut ir);
        assert_eq!(rewritten(&ir), Some((BinaryOp::Eq, 5)));
    }

    #[test]
    fn a_constant_that_is_no_length_bound_is_left_alone() {
        // No `U32Val` equals this, and below the tag nothing is `<=`.
        for (op, c) in [(BinaryOp::Eq, 0x2_FFFF_FFFF), (BinaryOp::Le, 3)] {
            let mut ir = bound(op, c, false);
            HostLenPass.run(&mut ir);
            assert_eq!(rewritten(&ir), None, "{op:?} {c}");
        }
    }

    /// `vec_len(v0) ^ vec_len(v1) < 2^32`, with the comparison lowered from
    /// `i64.lt_u` when `unsigned`.
    fn xored(unsigned: bool) -> HighIr {
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                                                      // v0
                Expr::Phi { incoming: vec![] },                                                      // v1
                Expr::Semantic(SemanticOp::Known(KnownOp::VecOp { kind: VecOpKind::Len, args: vec![v(0)] })), // v2
                Expr::Semantic(SemanticOp::Known(KnownOp::VecOp { kind: VecOpKind::Len, args: vec![v(1)] })), // v3
                Expr::Binary { op: BinaryOp::BitXor, lhs: v(2), rhs: v(3) },                        // v4
                Expr::Literal(Literal::I64(1 << 32)),                                                // v5
                Expr::Binary { op: BinaryOp::Lt, lhs: v(4), rhs: v(5) },                             // v6
            ],
            vec![v(0), v(1)],
            vec![2, 3, 4, 5, 6],
        );
        let cmp = f.bindings.get_mut(v(6)).unwrap();
        *cmp = Binding::new(
            v(6),
            IrType::Unknown(sordec_common::UnknownReason::InsufficientEvidence),
            cmp.expr.clone(),
            crate::lowering::lift_to_high::compare_provenance(unsigned),
        );
        module(vec![f])
    }

    #[test]
    fn two_raw_lengths_xored_below_2_32_are_equal() {
        // `tot_signers == signatures.len()`, as `account` compiles it.
        let mut ir = xored(true);
        assert!(HostLenPass.run(&mut ir).changed);
        let cmp = &ir.functions[0].bindings.get(v(6)).unwrap().expr;
        assert!(
            matches!(cmp, Expr::Binary { op: BinaryOp::Eq, lhs, rhs } if *lhs == v(2) && *rhs == v(3)),
            "{cmp:?}"
        );
    }

    #[test]
    fn a_signed_xor_test_is_not_equality() {
        // A payload xor with its top bit set is negative, and passes `< 2^32`
        // signed: that comparison is not `==`.
        let mut ir = xored(false);
        HostLenPass.run(&mut ir);
        assert!(matches!(
            ir.functions[0].bindings.get(v(6)).unwrap().expr,
            Expr::Binary { op: BinaryOp::Lt, .. }
        ));
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
