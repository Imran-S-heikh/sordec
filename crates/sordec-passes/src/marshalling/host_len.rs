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
//! # And the decode spelled out
//!
//! Where no decode was recognized, the same decode arrives as its two
//! instructions: `wrap32(shr_u(n, 32))`. Named `len()`, that printed as
//! `v.len() >> 32` — a `u32` shifted by its own width, which is not the
//! length (it panics, or is the length unshifted, depending on the build).
//! It folds to `n` like the decode.
//!
//! Why it is exact: the raw word is `len · 2³² + 4`; shifted right by 32,
//! unsigned, it is `len`, and `len < 2³²`, so keeping the low 32 bits keeps
//! all of it. Gates: a collection length (as above) or a `bytes_len`,
//! whose `U32Val` is the same; an unsigned shift by exactly 32; and the
//! 32-bit wrap of that shift.
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
//! comparison is rewritten on the length, as the unsigned comparison it is.
//! Only an unsigned ordering qualifies: a raw `Val` is a `u64`, and that is
//! how the SDK's bound check compares it; under a signed one a raw value
//! with `len ≥ 2³¹` is negative and the identity above fails. A bound
//! outside the `u32` range, or an equality with a constant that is no
//! `U32Val`, is left alone — and so is a comparison on the length a decode
//! already produced, which is on the payload.
//!
//! # And two lengths compared through their raw words
//!
//! `tot_signers == signatures.len()` compiles to the two raw `U32Val`s
//! xored and tested `< 2³²` unsigned: the tags cancel, leaving
//! `(a ^ b) << 32`, which is below 2³² exactly when the payloads are equal.
//! Rewritten as the `==` it is (`>=` as `!=`) when both sides are raw
//! `U32Val` words — a host length, or a storage read checked as one — and the
//! comparison is the unsigned one. Under a signed one a
//! payload xor with its top bit set also passes, so that is not equality and
//! is left alone.

use sordec_common::{IrId, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{
    BinaryOp, Binding, Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Literal,
    MapOpKind, SemanticOp, UnaryOp, VecOpKind,
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
                raw_len(func, *value).map(|len| (id, len, "decoding a host length is the `u32` `len()` returned"))
            }
            // The same decode spelled out: the high word shifted down and
            // the low 32 bits kept ("And the decode spelled out").
            Expr::Unary { op: UnaryOp::Wrap32, value } => {
                let Some(Expr::Binary { op: BinaryOp::ShrU, lhs: n, rhs: by }) =
                    func.bindings.get(resolve_use(func, *value)).map(|b| &b.expr)
                else {
                    return None;
                };
                let len = raw_len(func, *n).or_else(|| raw_bytes_len(func, *n))?;
                (literal(func, *by) == Some(32))
                    .then_some((id, len, "the high word of a host length's `U32Val` is the `u32` `len()` returned"))
            }
            Expr::Binary { op: BinaryOp::BitOr, lhs, rhs } if literal(func, *rhs) == Some(i64::from(TAG_U32_VAL)) => {
                let Some(Expr::Binary { op: BinaryOp::BitAnd, lhs: n, rhs: mask }) =
                    func.bindings.get(resolve_use(func, *lhs)).map(|b| &b.expr)
                else {
                    return None;
                };
                let len = raw_len(func, *n)?;
                (literal(func, *mask) == Some(-0x1_0000_0000))
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
            // Length on the left; a constant on the left flips the order.
            let (op, len, c) = if let Some(len) = raw_len(func, *lhs) {
                (*op, len, literal(func, *rhs)?)
            } else {
                (op.flipped()?, raw_len(func, *rhs)?, literal(func, *lhs)?)
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
                BinaryOp::LtU => BinaryOp::Eq,
                BinaryOp::GeU => BinaryOp::Ne,
                _ => return None,
            };
            if literal(func, *rhs) != Some(1 << 32) {
                return None;
            }
            let Some(Expr::Binary { op: BinaryOp::BitXor, lhs: x, rhs: y }) =
                func.bindings.get(resolve_use(func, *lhs)).map(|b| &b.expr)
            else {
                return None;
            };
            Some((id, op, u32_val_word(func, *x)?, u32_val_word(func, *y)?))
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
fn u32_val_word(func: &HighFunction, v: ValueId) -> Option<ValueId> {
    if let Some(len) = raw_len(func, v) {
        return Some(len);
    }
    let v = resolve_use(func, v);
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
    (read && checked_u32()).then_some(v)
}

/// `raw op c` as `len op' bound`, where `raw = len · 2³² + 4`.
fn on_length(op: BinaryOp, c: i128) -> Option<(BinaryOp, i128)> {
    const WORD: i128 = 1 << 32;
    let tag = i128::from(TAG_U32_VAL);
    // `raw <= c ⟺ len <= ⌊(c − 4) / 2³²⌋`, defined while `c ≥ 4`.
    let le = |c: i128| (c >= tag).then(|| (c - tag).div_euclid(WORD));
    Some(match op {
        BinaryOp::LeU => (BinaryOp::LeU, le(c)?),
        BinaryOp::LtU => (BinaryOp::LeU, le(c - 1)?),
        BinaryOp::GtU => (BinaryOp::GtU, le(c)?),
        BinaryOp::GeU => (BinaryOp::GtU, le(c - 1)?),
        BinaryOp::Eq | BinaryOp::Ne if c.rem_euclid(WORD) == tag => (op, c.div_euclid(WORD)),
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

/// The raw host length `v` is, through renames — but not through this
/// pass's own folds. A decode folded to the length is the payload: a bound
/// or a re-encode read through it would convert the length a second time
/// (a decoded `len <= 5` rewritten as the raw `len <= 0`).
fn raw_len(func: &HighFunction, v: ValueId) -> Option<ValueId> {
    let mut current = v;
    for _ in 0..16 {
        let b = func.bindings.get(current)?;
        match &b.expr {
            Expr::Use(_) if b.provenance().iter().any(|p| p.pass == PASS_NAME) => return None,
            Expr::Use(next) => current = *next,
            _ => return is_len(func, current).then_some(current),
        }
    }
    None
}

/// A `bytes_len`, through renames: a `U32Val` like a collection length.
/// Only its spelled-out decode is folded here ("And the decode spelled
/// out"); its bounds and recognized decode are [`super::bytesn_convert`]'s.
fn raw_bytes_len(func: &HighFunction, v: ValueId) -> Option<ValueId> {
    let v = resolve_use(func, v);
    matches!(
        func.bindings.get(v).map(|b| &b.expr),
        Some(Expr::Semantic(SemanticOp::Known(KnownOp::BufOp { kind: sordec_ir::BufOpKind::BytesLen, .. })))
    )
    .then_some(v)
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

    /// `n = vec_len(v0); w = wrap32(n >>u by)`.
    fn spelled(op: BinaryOp, by: i64) -> HighIr {
        module(vec![func_with(
            vec![
                Expr::Phi { incoming: vec![] },                                                      // v0
                Expr::Semantic(SemanticOp::Known(KnownOp::VecOp { kind: VecOpKind::Len, args: vec![v(0)] })), // v1
                Expr::Literal(Literal::I64(by)),                                                     // v2
                Expr::Binary { op, lhs: v(1), rhs: v(2) },                                           // v3
                Expr::Unary { op: UnaryOp::Wrap32, value: v(3) },                                    // v4
            ],
            vec![v(0)],
            vec![1, 2, 3, 4],
        )])
    }

    #[test]
    fn a_length_s_high_word_is_the_length() {
        let mut ir = spelled(BinaryOp::ShrU, 32);
        assert!(HostLenPass.run(&mut ir).changed);
        let f = &ir.functions[0];
        assert!(matches!(f.bindings.get(v(4)).unwrap().expr, Expr::Use(n) if n == v(1)));
        // Another amount, or a signed shift, is not the decode.
        assert!(!HostLenPass.run(&mut spelled(BinaryOp::ShrU, 31)).changed);
        assert!(!HostLenPass.run(&mut spelled(BinaryOp::Shr, 32)).changed);
        // A `bytes_len`'s is the same.
        let mut ir = spelled(BinaryOp::ShrU, 32);
        ir.functions[0].bindings.get_mut(v(1)).unwrap().expr =
            Expr::Semantic(SemanticOp::Known(KnownOp::BufOp { kind: sordec_ir::BufOpKind::BytesLen, args: vec![v(0)] }));
        assert!(HostLenPass.run(&mut ir).changed);
        assert!(matches!(ir.functions[0].bindings.get(v(4)).unwrap().expr, Expr::Use(n) if n == v(1)));
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
        let mut ir = bound(BinaryOp::LeU, 0x2_FFFF_FFFF, false);
        assert!(HostLenPass.run(&mut ir).changed);
        assert_eq!(rewritten(&ir), Some((BinaryOp::LeU, 2)));
        // `raw < (3 << 32) | 4` is `len < 3`, i.e. `len <= 2`.
        let mut ir = bound(BinaryOp::LtU, (3 << 32) | 4, false);
        HostLenPass.run(&mut ir);
        assert_eq!(rewritten(&ir), Some((BinaryOp::LeU, 2)));
        // `0x2_FFFF_FFFF < raw`, constant first, is `len > 2`.
        let mut ir = bound(BinaryOp::LtU, 0x2_FFFF_FFFF, true);
        HostLenPass.run(&mut ir);
        assert_eq!(rewritten(&ir), Some((BinaryOp::GtU, 2)));
        // An equality with a `U32Val` is one on its payload.
        let mut ir = bound(BinaryOp::Eq, (5 << 32) | 4, false);
        HostLenPass.run(&mut ir);
        assert_eq!(rewritten(&ir), Some((BinaryOp::Eq, 5)));
    }

    #[test]
    fn a_constant_that_is_no_length_bound_is_left_alone() {
        // No `U32Val` equals this, and below the tag nothing is `<=`.
        for (op, c) in [(BinaryOp::Eq, 0x2_FFFF_FFFF), (BinaryOp::LeU, 3)] {
            let mut ir = bound(op, c, false);
            HostLenPass.run(&mut ir);
            assert_eq!(rewritten(&ir), None, "{op:?} {c}");
        }
    }

    #[test]
    fn a_signed_bound_on_the_raw_word_is_not_a_length_bound() {
        // Under a signed order a raw value with `len >= 2^31` is negative,
        // and the identity with `len <= bound` fails; only the unsigned
        // comparison, the one the SDK's bound check compiles to, qualifies.
        let mut ir = bound(BinaryOp::Le, 0x2_FFFF_FFFF, false);
        HostLenPass.run(&mut ir);
        assert_eq!(rewritten(&ir), None);
    }

    #[test]
    fn a_decoded_length_s_bound_is_not_converted_again() {
        // `c = val_decode(vec_len(v0)); c <= 5` is already on the length.
        // The first run folds the decode to the length; the second must not
        // read `5` as a raw bound through that fold (it is not `len <= 0`).
        let mut ir = module(vec![func_with(
            vec![
                Expr::Phi { incoming: vec![] },                                                      // v0
                Expr::Semantic(SemanticOp::Known(KnownOp::VecOp { kind: VecOpKind::Len, args: vec![v(0)] })), // v1
                Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { value: v(1) })),          // v2
                Expr::Literal(Literal::I64(5)),                                                      // v3
                Expr::Binary { op: BinaryOp::LeU, lhs: v(2), rhs: v(3) },                            // v4
            ],
            vec![v(0)],
            vec![1, 2, 3, 4],
        )]);
        assert!(HostLenPass.run(&mut ir).changed);
        assert!(!HostLenPass.run(&mut ir).changed);
        let cmp = &ir.functions[0].bindings.get(v(4)).unwrap().expr;
        assert!(
            matches!(cmp, Expr::Binary { op: BinaryOp::LeU, lhs, rhs } if *lhs == v(2) && *rhs == v(3)),
            "{cmp:?}"
        );
    }

    /// `vec_len(v0) ^ vec_len(v1) < 2^32`, the comparison `op`.
    fn xored(op: BinaryOp) -> HighIr {
        let f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                                                      // v0
                Expr::Phi { incoming: vec![] },                                                      // v1
                Expr::Semantic(SemanticOp::Known(KnownOp::VecOp { kind: VecOpKind::Len, args: vec![v(0)] })), // v2
                Expr::Semantic(SemanticOp::Known(KnownOp::VecOp { kind: VecOpKind::Len, args: vec![v(1)] })), // v3
                Expr::Binary { op: BinaryOp::BitXor, lhs: v(2), rhs: v(3) },                        // v4
                Expr::Literal(Literal::I64(1 << 32)),                                                // v5
                Expr::Binary { op, lhs: v(4), rhs: v(5) },                                           // v6
            ],
            vec![v(0), v(1)],
            vec![2, 3, 4, 5, 6],
        );
        module(vec![f])
    }

    #[test]
    fn two_raw_lengths_xored_below_2_32_are_equal() {
        // `tot_signers == signatures.len()`, as `account` compiles it.
        let mut ir = xored(BinaryOp::LtU);
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
        let mut ir = xored(BinaryOp::Lt);
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
