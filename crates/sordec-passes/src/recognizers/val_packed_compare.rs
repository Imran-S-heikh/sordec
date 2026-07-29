//! Comparisons rustc compiled against a `U32Val`'s *bits* rather than its
//! *payload*.
//!
//! ## The contradiction this resolves
//!
//! A host call returning a `U32Val` gets its recovered type from the ABI
//! table — `bytes_len` is [`KnownType::U32`]
//! ([`crate::val_abi::buf_kind_result_type`]) — and that type names the
//! **payload**. But the guest code around it was compiled against the
//! **encoding**: a `U32Val` is `(payload << 32) | 4`, and rustc compares
//! the packed word directly rather than shifting the payload down first.
//! So the IR ends up holding
//!
//! ```text
//! v8: u32 = bytes_len(v1)
//! if (lt v8, 4294967296i64)          ← a u32 against 1 << 32
//! ```
//!
//! which is not a typo in the dump: both halves are right, and nothing
//! reconciles them. The emitter cannot annotate the resulting hole,
//! because the recovered type does not coincide with the wasm value type,
//! so `todo!()`'s `!` falls back to `()` and the arithmetic fails to
//! compile (`no implementation for () & i64`).
//!
//! This pass rewrites the comparison to the one the source wrote —
//! `message.len() == 0` — leaving the mask and the packed constant dead
//! for the existing sweep to remove.
//!
//! ## What counts as a `U32Val` producer
//!
//! Only an ABI-proven one: a `Semantic(Known(_))` whose host function
//! *returns* a `U32Val` by `env.json` — the `b`/`v`/`m` object modules'
//! length and index accessors, plus the two `u32`-valued ledger
//! accessors. See `u32val_producer`.
//!
//! The exclusion that matters is the `i`-module ([`KnownOp::ValObject`]).
//! Its `obj_to_*` extractors are also typed `U32`/`U64`, but they return a
//! **raw machine word**, not a tagged Val — masking one is ordinary
//! arithmetic, and reading it as a Val payload would be wrong. Typing
//! alone therefore cannot decide this; the op family has to.
//!
//! ## The three shapes, and what each rests on
//!
//! | shape | pattern | payload predicate | premise |
//! |---|---|---|---|
//! | A | `(p & MAJOR_MASK) {==,!=} k << 32` | `payload {==,!=} k` | none |
//! | B-eq | `p {==,!=} ((k << 32) \| 4)` | `payload {==,!=} k` | none |
//! | B-lt | `p < k << 32` | `payload < k` | unsigned |
//!
//! **A** is exact. `bits & MAJOR_MASK` is `payload << 32` for any
//! well-formed `U32Val`, and `<< 32` is injective on 32-bit values, so
//! the masked equality *is* payload equality. No signedness enters —
//! `Eq`/`Ne` do not have a signed and an unsigned reading.
//!
//! **B-eq** is exact for the same reason, one step shorter: two
//! well-formed `U32Val`s are bit-equal exactly when their payloads are.
//!
//! **B-lt carries a premise, and it is recorded rather than hidden.**
//! `payload << 32 | 4 <ᵘ k << 32` iff `payload < k`, but
//! [`crate::lowering::lift_to_high`] folds `i64.lt_s` and `i64.lt_u` onto
//! the same [`BinaryOp::Lt`] — sign is deliberately erased there, on the
//! grounds that the operand types carry it, which for a raw Val they do
//! not. Signed and unsigned agree here iff the payload is below 2³¹. Every
//! witnessed producer is a host-side length or index, and the wasm this
//! was derived from is `i64.lt_u`, so the reading is the right one; it is
//! an inference from the SDK's compiled shape, not a proof, and the
//! binding's provenance says so. `sordec-diffexec` is what settles it.
//!
//! `Le`/`Gt`/`Ge` are deliberately **not** recognized. Each maps to a
//! payload predicate with a *different* operator (`p <=ᵘ k << 32` is
//! `payload < k`, because `payload << 32 | 4` can never equal `k << 32`),
//! and no corpus fixture witnesses one. They join when something needs
//! them, with their own derivation and test.
//!
//! ## Why the rewrite is in-place and use-count-gated
//!
//! Rewriting the mask binding to an alias of its producer is only sound
//! for a reader that goes on to compare against a `k << 32` constant; a
//! reader wanting the actual masked bits would be broken by it. The same
//! goes for re-typing a shared literal. So both bindings must have exactly
//! one use, checked against [`HighUseIndex`], and a site that fails the
//! check is declined rather than approximated.
//!
//! Nothing is deleted here: the mask becomes an alias and the packed
//! constant becomes unread, which is what the backend's dead-`let` pass
//! already knows how to remove.

use sordec_common::{IrId, ProvenanceSource, ValueId};
use sordec_ir::{
    BinaryOp, Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Literal, SemanticOp,
};

use crate::dataflow::{resolve_use, HighUseIndex};
use crate::pass::{Pass, PassMetrics, PassResult};
use crate::val_abi;

use super::{apply_rewrites, Rewrite};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "val-packed-compare";

// Metric counter keys, split by which shape matched, because the two
// carry different evidence and a reviewer wants to see the ratio.
const M_MASKED: &str = "val_packed_compare_masked";
const M_ORDERED: &str = "val_packed_compare_ordered";

/// Rewrites bit-packed `U32Val` comparisons into payload comparisons.
#[derive(Debug, Default, Clone, Copy)]
pub struct ValPackedComparePass;

impl Pass<HighIr> for ValPackedComparePass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            let (changed, metrics) = recognize_function(func);
            result.changed |= changed;
            for (key, value) in metrics.iter() {
                result.metrics.increment(key, value);
            }
        }
        result
    }
}

/// One recognized site: the edits that turn it into a payload comparison.
struct Site {
    /// Edits to apply, in arena-independent order.
    rewrites: Vec<Rewrite>,
    /// Which shape matched.
    metric: &'static str,
}

/// Recognize every packed comparison in one function.
fn recognize_function(func: &mut HighFunction) -> (bool, PassMetrics) {
    let mut metrics = PassMetrics::new();
    let uses = HighUseIndex::build(func);
    let mut rewrites: Vec<Rewrite> = Vec::new();

    for (id, binding) in func.bindings.iter() {
        let Expr::Binary { op, lhs, rhs } = &binding.expr else {
            continue;
        };
        if let Some(site) = try_site(func, &uses, id, *op, *lhs, *rhs) {
            metrics.increment(site.metric, 1);
            rewrites.extend(site.rewrites);
        }
    }

    let changed = !rewrites.is_empty();
    apply_rewrites(func, PASS_NAME, rewrites);
    (changed, metrics)
}

/// Match one comparison binding against the three shapes.
///
/// `cmp` is the comparison binding itself; it is rewritten only for the
/// `< 1 << 32` normalization, where the payload predicate is spelled
/// `== 0` instead.
fn try_site(
    func: &HighFunction,
    uses: &HighUseIndex,
    cmp: ValueId,
    op: BinaryOp,
    lhs: ValueId,
    rhs: ValueId,
) -> Option<Site> {
    // The packed constant may sit on either side. Both readings are tried
    // rather than assumed, and the operator is never mirrored: operands
    // are rewritten in place, so their order — and hence the operator's
    // meaning — is preserved.
    try_oriented(func, uses, cmp, op, lhs, rhs, ConstSide::Rhs)
        .or_else(|| try_oriented(func, uses, cmp, op, rhs, lhs, ConstSide::Lhs))
}

/// Which operand of the comparison holds the packed constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConstSide {
    Lhs,
    Rhs,
}

/// Match with `value` as the compared expression and `konst` as the
/// packed constant.
fn try_oriented(
    func: &HighFunction,
    uses: &HighUseIndex,
    cmp: ValueId,
    op: BinaryOp,
    value: ValueId,
    konst: ValueId,
    side: ConstSide,
) -> Option<Site> {
    let (const_id, bits) = direct_int_literal(func, konst)?;
    // Re-typing a literal is only sound for the reader that proved the
    // encoding; a shared one may be read as raw bits elsewhere.
    if uses.use_count(const_id) != 1 {
        return None;
    }

    match op {
        BinaryOp::Eq | BinaryOp::Ne => {
            try_masked(func, uses, value, const_id, bits)
                .or_else(|| try_packed_eq(func, value, const_id, bits))
        }
        // Only `<`, and only with the constant on the right: the other
        // ordered operators map onto a *different* payload operator (see
        // the module docs) and nothing witnesses them.
        BinaryOp::Lt if side == ConstSide::Rhs => try_ordered(func, cmp, value, const_id, bits),
        _ => None,
    }
}

/// Shape A — `(p & MAJOR_MASK) {==,!=} k << 32`.
///
/// Exact: the mask leaves `payload << 32`, and `<< 32` is injective on a
/// 32-bit payload, so this is payload equality spelled without a shift.
fn try_masked(
    func: &HighFunction,
    uses: &HighUseIndex,
    value: ValueId,
    const_id: ValueId,
    bits: u64,
) -> Option<Site> {
    // The compared-against constant must be a bare `k << 32`: a
    // well-formed Val would have a tag in the low byte, and this side of
    // the comparison has had its tag masked away.
    if bits & !val_abi::MAJOR_MASK != 0 {
        return None;
    }
    let k = u32::try_from(bits >> val_abi::MAJOR_SHIFT).ok()?;

    let mask_id = resolve_use(func, value);
    let Expr::Binary {
        op: BinaryOp::BitAnd,
        lhs,
        rhs,
    } = &binding_expr(func, mask_id)?
    else {
        return None;
    };
    // Either operand may be the mask; the other must be the producer.
    let (producer, payload_ty) = mask_and_producer(func, *lhs, *rhs)?;

    // Aliasing the mask away is sound only for a reader that compares
    // against `k << 32`. Any second reader wants the masked bits.
    if uses.use_count(mask_id) != 1 {
        return None;
    }

    Some(Site {
        metric: M_MASKED,
        rewrites: vec![
            Rewrite {
                id: mask_id,
                expr: Expr::Use(producer),
                ty: Some(IrType::Known(payload_ty)),
                source: ProvenanceSource::SdkPattern,
                note: format!(
                    "val-packed-compare: `& {:#x}` selects a {} payload whole, so the mask is \
                     the identity on it",
                    val_abi::MAJOR_MASK,
                    val_abi::tag_name(val_abi::TAG_U32_VAL).unwrap_or("U32Val")
                ),
                metric: M_MASKED,
            },
            Rewrite {
                id: const_id,
                expr: Expr::Literal(Literal::U32(k)),
                ty: Some(IrType::Known(KnownType::U32)),
                source: ProvenanceSource::SdkPattern,
                note: format!("val-packed-compare: {bits} is {k} << {}", val_abi::MAJOR_SHIFT),
                metric: M_MASKED,
            },
        ],
    })
}

/// Shape B-eq — `p {==,!=} ((k << 32) | 4)`.
///
/// Exact: two well-formed `U32Val`s are bit-equal exactly when their
/// payloads are, so only the constant needs unpacking.
fn try_packed_eq(
    func: &HighFunction,
    value: ValueId,
    const_id: ValueId,
    bits: u64,
) -> Option<Site> {
    let k = val_abi::decode_u32val(bits)?;
    u32val_producer(func, value)?;
    Some(Site {
        metric: M_MASKED,
        rewrites: vec![Rewrite {
            id: const_id,
            expr: Expr::Literal(Literal::U32(k)),
            ty: Some(IrType::Known(KnownType::U32)),
            source: ProvenanceSource::SdkPattern,
            note: format!(
                "val-packed-compare: {bits} is the {} {k}",
                val_abi::tag_name(val_abi::TAG_U32_VAL).unwrap_or("U32Val")
            ),
            metric: M_MASKED,
        }],
    })
}

/// Shape B-lt — `p < k << 32`, i.e. `payload < k`.
///
/// The one shape with a premise: `BinaryOp::Lt` has lost whether the wasm
/// said `lt_s` or `lt_u`, and the two agree only for a payload below 2³¹.
/// See the module docs.
fn try_ordered(
    func: &HighFunction,
    cmp: ValueId,
    value: ValueId,
    const_id: ValueId,
    bits: u64,
) -> Option<Site> {
    // A bare boundary, not a Val: a tagged constant on this side would be
    // an ordering against an encoding, which means nothing at the payload
    // level.
    if bits & !val_abi::MAJOR_MASK != 0 {
        return None;
    }
    let k = u32::try_from(bits >> val_abi::MAJOR_SHIFT).ok()?;
    // `k == 0` would be `payload < 0` — unsatisfiable, so the shape is
    // not what we think it is.
    if k == 0 {
        return None;
    }
    // Reject a constant whose bit pattern is negative as an i64: there the
    // signed and unsigned readings differ for *every* payload, not just
    // large ones, and the premise below would not hold at all.
    if (bits as i64) < 0 {
        return None;
    }
    u32val_producer(func, value)?;

    let mut rewrites = vec![Rewrite {
        id: const_id,
        expr: Expr::Literal(Literal::U32(if k == 1 { 0 } else { k })),
        ty: Some(IrType::Known(KnownType::U32)),
        source: ProvenanceSource::SdkPattern,
        note: format!(
            "val-packed-compare: `< {k} << {shift}` on a packed U32Val is `< {k}` on its \
             payload (reads the wasm comparison as unsigned, which holds for every payload \
             below 2^31)",
            shift = val_abi::MAJOR_SHIFT
        ),
        metric: M_ORDERED,
    }];

    // `payload < 1` and `payload == 0` are the same predicate on a u32,
    // and `== 0` is what a person writes. Normalizing between provably
    // equal spellings is not a guess, and it is what makes the recovered
    // line read as `message.len() == 0`.
    if k == 1 {
        let Expr::Binary { lhs, rhs, .. } = binding_expr(func, cmp)? else {
            return None;
        };
        rewrites.push(Rewrite {
            id: cmp,
            expr: Expr::Binary {
                op: BinaryOp::Eq,
                lhs,
                rhs,
            },
            ty: Some(IrType::Known(KnownType::Bool)),
            source: ProvenanceSource::SdkPattern,
            note: "val-packed-compare: `< 1` normalized to `== 0` (identical on a u32)"
                .to_string(),
            metric: M_ORDERED,
        });
    }

    Some(Site {
        metric: M_ORDERED,
        rewrites,
    })
}

/// Split a `BitAnd`'s operands into (producer, payload type), requiring
/// one of them to be the major-field mask and the other an ABI-proven
/// `U32Val` producer.
fn mask_and_producer(
    func: &HighFunction,
    lhs: ValueId,
    rhs: ValueId,
) -> Option<(ValueId, KnownType)> {
    for (mask_side, value_side) in [(lhs, rhs), (rhs, lhs)] {
        let Some((_, bits)) = direct_int_literal(func, mask_side) else {
            continue;
        };
        if bits != val_abi::MAJOR_MASK {
            continue;
        }
        if let Some(ty) = u32val_producer(func, value_side) {
            return Some((value_side, ty));
        }
    }
    None
}

/// The payload type of a binding that returns a tagged `U32Val` /
/// `I32Val` from the host, or `None`.
///
/// Membership is by **op family**, not by recovered type. The `i`-module
/// ([`KnownOp::ValObject`]) is the reason: its `obj_to_u32`-style
/// extractors carry the same `U32` type but hand back a raw machine word,
/// so bit-masking one means something else entirely. Every family listed
/// here returns a tagged Val per `env.json`.
fn u32val_producer(func: &HighFunction, value: ValueId) -> Option<KnownType> {
    let id = resolve_use(func, value);
    let Expr::Semantic(SemanticOp::Known(op)) = binding_expr(func, id)? else {
        return None;
    };
    let ty = match op {
        KnownOp::BufOp { kind, .. } => val_abi::buf_kind_result_type(kind),
        KnownOp::VecOp { kind, .. } => val_abi::vec_kind_result_type(kind),
        KnownOp::MapOp { kind, .. } => val_abi::map_kind_result_type(kind),
        // `env.ledger().sequence()` / `.protocol_version()` — both
        // `U32Val` by `env.json`, and both unit variants carrying no kind.
        KnownOp::GetLedgerSequence | KnownOp::GetLedgerProtocolVersion => KnownType::U32,
        _ => return None,
    };
    matches!(ty, KnownType::U32 | KnownType::I32).then_some(ty)
}

/// `value`'s expression, bounds-checked.
///
/// `Arena::get` debug-asserts on an out-of-range id and `resolve_use`
/// returns dangling ids unchanged, so the check has to come first.
fn binding_expr(func: &HighFunction, value: ValueId) -> Option<Expr> {
    if (value.index() as usize) >= func.bindings.len() {
        return None;
    }
    Some(func.bindings.get(value)?.expr.clone())
}

/// `value` when it is *directly* a 64-bit integer literal binding, with
/// its raw bits.
///
/// Deliberately not [`crate::dataflow::trace_int`]: this pass rewrites the
/// literal binding it finds, so it must be the binding the operand names,
/// not one reached through an alias or a conversion. An alias hop means
/// the pass declines — narrower than tracing, and it cannot rewrite the
/// wrong binding.
fn direct_int_literal(func: &HighFunction, value: ValueId) -> Option<(ValueId, u64)> {
    match binding_expr(func, value)? {
        Expr::Literal(Literal::I64(bits)) => Some((value, bits as u64)),
        Expr::Literal(Literal::U64(bits)) => Some((value, bits)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::v;
    use sordec_ir::BufOpKind;

    /// A function whose single block holds `exprs` in arena order, all of
    /// them scheduled so the region walk — and hence [`HighUseIndex`] —
    /// sees every one.
    fn func_with(exprs: Vec<Expr>) -> HighFunction {
        let scheduled = (0..exprs.len() as u32).collect();
        crate::marshalling::test_support::func_with(exprs, vec![], scheduled)
    }

    fn bytes_len(arg: ValueId) -> Expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::BufOp {
            kind: BufOpKind::BytesLen,
            args: vec![arg],
        }))
    }

    fn run(func: &mut HighFunction) -> PassMetrics {
        let (_, metrics) = recognize_function(func);
        metrics
    }

    #[test]
    fn masked_inequality_becomes_a_payload_comparison() {
        // attest's `BytesN<64>` length check:
        //   v2 = bytes_len(v0); v3 = MAJOR_MASK; v4 = v2 & v3;
        //   v5 = 64 << 32;      v6 = v4 != v5
        let mut func = func_with(vec![
            Expr::Phi { incoming: vec![] },
            Expr::Phi { incoming: vec![] },
            bytes_len(v(0)),
            Expr::Literal(Literal::I64(val_abi::MAJOR_MASK as i64)),
            Expr::Binary { op: BinaryOp::BitAnd, lhs: v(2), rhs: v(3) },
            Expr::Literal(Literal::I64(64 << val_abi::MAJOR_SHIFT)),
            Expr::Binary { op: BinaryOp::Ne, lhs: v(4), rhs: v(5) },
        ]);
        assert_eq!(run(&mut func).get(M_MASKED), Some(1));
        // The mask is now an alias of the producer …
        assert!(matches!(func.bindings.get(v(4)).unwrap().expr, Expr::Use(p) if p == v(2)));
        // … and the packed constant is the bare payload.
        assert!(matches!(
            func.bindings.get(v(5)).unwrap().expr,
            Expr::Literal(Literal::U32(64))
        ));
        // The comparison itself is untouched: its operands changed, not it.
        assert!(matches!(
            func.bindings.get(v(6)).unwrap().expr,
            Expr::Binary { op: BinaryOp::Ne, .. }
        ));
    }

    #[test]
    fn a_less_than_one_shifted_becomes_equals_zero() {
        // digest_keccak's real logic: `if message.len() == 0`.
        let mut func = func_with(vec![
            Expr::Phi { incoming: vec![] },
            bytes_len(v(0)),
            Expr::Literal(Literal::I64(1 << val_abi::MAJOR_SHIFT)),
            Expr::Binary { op: BinaryOp::Lt, lhs: v(1), rhs: v(2) },
        ]);
        assert_eq!(run(&mut func).get(M_ORDERED), Some(1));
        assert!(matches!(
            func.bindings.get(v(2)).unwrap().expr,
            Expr::Literal(Literal::U32(0))
        ));
        assert!(matches!(
            func.bindings.get(v(3)).unwrap().expr,
            Expr::Binary { op: BinaryOp::Eq, .. }
        ));
    }

    #[test]
    fn a_larger_ordered_bound_keeps_its_operator() {
        // `< 4 << 32` is `< 4`; only the k == 1 case is normalized.
        let mut func = func_with(vec![
            Expr::Phi { incoming: vec![] },
            bytes_len(v(0)),
            Expr::Literal(Literal::I64(4 << val_abi::MAJOR_SHIFT)),
            Expr::Binary { op: BinaryOp::Lt, lhs: v(1), rhs: v(2) },
        ]);
        assert_eq!(run(&mut func).get(M_ORDERED), Some(1));
        assert!(matches!(
            func.bindings.get(v(2)).unwrap().expr,
            Expr::Literal(Literal::U32(4))
        ));
        assert!(matches!(
            func.bindings.get(v(3)).unwrap().expr,
            Expr::Binary { op: BinaryOp::Lt, .. }
        ));
    }

    #[test]
    fn a_packed_u32val_equality_unpacks_only_the_constant() {
        // `p == U32Val(7)` — no mask, tag intact.
        let packed = (7u64 << val_abi::MAJOR_SHIFT) | u64::from(val_abi::TAG_U32_VAL);
        let mut func = func_with(vec![
            Expr::Phi { incoming: vec![] },
            bytes_len(v(0)),
            Expr::Literal(Literal::I64(packed as i64)),
            Expr::Binary { op: BinaryOp::Eq, lhs: v(1), rhs: v(2) },
        ]);
        assert_eq!(run(&mut func).get(M_MASKED), Some(1));
        assert!(matches!(
            func.bindings.get(v(2)).unwrap().expr,
            Expr::Literal(Literal::U32(7))
        ));
    }

    #[test]
    fn a_shared_mask_result_is_declined() {
        // A second reader wants the masked bits; aliasing them away would
        // silently change what it reads.
        let mut func = func_with(vec![
            Expr::Phi { incoming: vec![] },
            bytes_len(v(0)),
            Expr::Literal(Literal::I64(val_abi::MAJOR_MASK as i64)),
            Expr::Binary { op: BinaryOp::BitAnd, lhs: v(1), rhs: v(2) },
            Expr::Literal(Literal::I64(64 << val_abi::MAJOR_SHIFT)),
            Expr::Binary { op: BinaryOp::Ne, lhs: v(3), rhs: v(4) },
            // the second reader
            Expr::Unary { op: sordec_ir::UnaryOp::BitNot, value: v(3) },
        ]);
        assert_eq!(run(&mut func).get(M_MASKED), None);
        assert!(matches!(
            func.bindings.get(v(3)).unwrap().expr,
            Expr::Binary { op: BinaryOp::BitAnd, .. }
        ));
    }

    #[test]
    fn a_shared_constant_is_declined() {
        let mut func = func_with(vec![
            Expr::Phi { incoming: vec![] },
            bytes_len(v(0)),
            Expr::Literal(Literal::I64(1 << val_abi::MAJOR_SHIFT)),
            Expr::Binary { op: BinaryOp::Lt, lhs: v(1), rhs: v(2) },
            // a second reader of the same literal
            Expr::Binary { op: BinaryOp::Add, lhs: v(2), rhs: v(2) },
        ]);
        assert_eq!(run(&mut func).get(M_ORDERED), None);
    }

    #[test]
    fn a_raw_word_extractor_is_not_a_val_producer() {
        // `obj_to_u64` is typed U64 and returns a *raw* word, so masking
        // it is ordinary arithmetic. Must not match.
        let mut func = func_with(vec![
            Expr::Phi { incoming: vec![] },
            Expr::Semantic(SemanticOp::Known(KnownOp::ValObject {
                kind: sordec_ir::ValObjectKind::ObjToU64,
                args: vec![v(0)],
            })),
            Expr::Literal(Literal::I64(val_abi::MAJOR_MASK as i64)),
            Expr::Binary { op: BinaryOp::BitAnd, lhs: v(1), rhs: v(2) },
            Expr::Literal(Literal::I64(64 << val_abi::MAJOR_SHIFT)),
            Expr::Binary { op: BinaryOp::Ne, lhs: v(3), rhs: v(4) },
        ]);
        assert_eq!(run(&mut func).get(M_MASKED), None);
    }

    #[test]
    fn an_unrecognized_producer_is_declined() {
        // Plain arithmetic typed U32 is not evidence of a Val encoding.
        let mut func = func_with(vec![
            Expr::Phi { incoming: vec![] },
            Expr::Binary { op: BinaryOp::Add, lhs: v(0), rhs: v(0) },
            Expr::Literal(Literal::I64(val_abi::MAJOR_MASK as i64)),
            Expr::Binary { op: BinaryOp::BitAnd, lhs: v(1), rhs: v(2) },
            Expr::Literal(Literal::I64(64 << val_abi::MAJOR_SHIFT)),
            Expr::Binary { op: BinaryOp::Ne, lhs: v(3), rhs: v(4) },
        ]);
        assert_eq!(run(&mut func).get(M_MASKED), None);
    }

    #[test]
    fn the_unwitnessed_ordered_operators_are_declined() {
        for op in [BinaryOp::Le, BinaryOp::Gt, BinaryOp::Ge] {
            let mut func = func_with(vec![
                Expr::Phi { incoming: vec![] },
                bytes_len(v(0)),
                Expr::Literal(Literal::I64(1 << val_abi::MAJOR_SHIFT)),
                Expr::Binary { op, lhs: v(1), rhs: v(2) },
            ]);
            assert_eq!(run(&mut func).get(M_ORDERED), None, "{op:?} must not match");
        }
    }

    #[test]
    fn a_negative_boundary_is_declined() {
        // `k << 32` with the sign bit set: signed and unsigned readings
        // differ for every payload, so the premise fails outright.
        let bits = (1u64 << 31) << val_abi::MAJOR_SHIFT;
        let mut func = func_with(vec![
            Expr::Phi { incoming: vec![] },
            bytes_len(v(0)),
            Expr::Literal(Literal::I64(bits as i64)),
            Expr::Binary { op: BinaryOp::Lt, lhs: v(1), rhs: v(2) },
        ]);
        assert_eq!(run(&mut func).get(M_ORDERED), None);
    }

    #[test]
    fn a_second_run_changes_nothing() {
        let mut func = func_with(vec![
            Expr::Phi { incoming: vec![] },
            bytes_len(v(0)),
            Expr::Literal(Literal::I64(1 << val_abi::MAJOR_SHIFT)),
            Expr::Binary { op: BinaryOp::Lt, lhs: v(1), rhs: v(2) },
        ]);
        let (first, _) = recognize_function(&mut func);
        assert!(first);
        let (second, metrics) = recognize_function(&mut func);
        assert!(!second, "the rewrite must not re-match its own output");
        assert!(metrics.is_empty());
    }
}
