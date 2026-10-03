//! Comparisons rustc compiled against a Val's *bits* rather than its
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
//! ## The four shapes, and what each rests on
//!
//! | shape | pattern | payload predicate | premise |
//! |---|---|---|---|
//! | A | `(p & MAJOR_MASK) {==,!=} k << 32` | `payload {==,!=} k` | none |
//! | B-eq | `p {==,!=} ((k << 32) \| 4)` | `payload {==,!=} k` | none |
//! | B-lt | `p < k << 32` | `payload < k` | unsigned |
//! | C | `b {==,!=} {0,1}` | `b` / `!b` | none |
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
//! **C is the degenerate case, and it is exact by the encoding's own
//! definition.** A `Bool` Val carries no body: `Tag::False` is `0` and
//! `Tag::True` is `1` ([`crate::val_abi::TAG_FALSE`] /
//! [`TAG_TRUE`](crate::val_abi::TAG_TRUE)), so the whole 64-bit word *is*
//! `0` or `1`. `bits == 1` is therefore the value itself and `bits == 0`
//! its negation — no shift, no mask, and nothing to be unsigned about.
//! rustc spells the test that way because at the machine level it only
//! ever had an `i64`.
//!
//! This is the shape behind `env.storage().<tier>().has(&k)`, whose result
//! the SDK immediately narrows with `== 1`. It matters more than its
//! triviality suggests: [`KnownType::Bool`] does not coincide with the
//! wasm value type, so the emitter cannot annotate a hole standing where
//! the `has` was, and `todo!()`'s `!` falls back to `()` — the failure is
//! `can't compare `()` with `i64``, the exact symptom the U32Val half of
//! this pass was written for.
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
/// Shape E: a mask read at the payload level rather than on the bits.
const M_MASKED_VALUE: &str = "val_packed_compare_masked_value";
/// Shape C — a `Bool` Val narrowed to a machine bool by `== 1`.
const M_BOOL: &str = "val_packed_compare_bool";

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

/// Match one comparison binding against the four shapes.
///
/// `cmp` is the comparison binding itself; it is rewritten for the
/// `< 1 << 32` normalization, where the payload predicate is spelled
/// `== 0` instead, and for shape C, which replaces the comparison
/// outright.
fn try_site(
    func: &HighFunction,
    uses: &HighUseIndex,
    cmp: ValueId,
    op: BinaryOp,
    lhs: ValueId,
    rhs: ValueId,
) -> Option<Site> {
    // Shape C first, and outside `try_oriented`: it neither re-types a
    // literal nor aliases a mask, so the use-count gate those rewrites
    // need does not apply to it and would only decline sites sharing a
    // `1i64`.
    if let Some(site) = try_bool_val(func, cmp, op, lhs, rhs) {
        return Some(site);
    }
    // The packed constant may sit on either side. Both readings are tried
    // rather than assumed, and the operator is never mirrored: operands
    // are rewritten in place, so their order — and hence the operator's
    // meaning — is preserved.
    try_oriented(func, uses, cmp, op, lhs, rhs, ConstSide::Rhs)
        .or_else(|| try_oriented(func, uses, cmp, op, rhs, lhs, ConstSide::Lhs))
}

/// Shape C — `b {==,!=} {0,1}` where `b` is an ABI-proven `Bool` Val.
///
/// Replaces the comparison with the Val itself (or its negation), because
/// a `Bool` Val's bits *are* its value. Unlike the packed shapes this
/// rewrites the comparison binding rather than its operands: there is no
/// payload to extract, so there is nothing left for the comparison to do.
fn try_bool_val(
    func: &HighFunction,
    cmp: ValueId,
    op: BinaryOp,
    lhs: ValueId,
    rhs: ValueId,
) -> Option<Site> {
    // Either orientation; the constant identifies itself.
    let (value, konst) = [(lhs, rhs), (rhs, lhs)]
        .into_iter()
        .find(|(v, _)| bool_val_producer(func, *v))?;
    let (_, bits) = direct_int_literal(func, konst)?;

    // `Bool`'s two encodings, as bit patterns. Named rather than spelled
    // `0`/`1` so the derivation stays visible: these are tag bytes, and a
    // `Bool` Val has no body for them to share the word with.
    const TRUE_BITS: u64 = val_abi::TAG_TRUE as u64;
    const FALSE_BITS: u64 = val_abi::TAG_FALSE as u64;

    let negated = match (op, bits) {
        (BinaryOp::Eq, TRUE_BITS) | (BinaryOp::Ne, FALSE_BITS) => false,
        (BinaryOp::Eq, FALSE_BITS) | (BinaryOp::Ne, TRUE_BITS) => true,
        // Any other constant is not a well-formed `Bool` Val, so this is
        // not the shape — decline rather than reinterpret it.
        _ => return None,
    };

    let (expr, note) = if negated {
        (
            Expr::Unary {
                op: sordec_ir::UnaryOp::Not,
                value,
            },
            "Bool Val compared against Tag::False — the SDK's negated narrowing",
        )
    } else {
        (
            Expr::Use(value),
            "Bool Val compared against Tag::True — the SDK's narrowing to a machine bool",
        )
    };
    Some(Site {
        rewrites: vec![Rewrite {
            id: cmp,
            expr,
            ty: Some(IrType::Known(KnownType::Bool)),
            source: ProvenanceSource::SdkPattern,
            note: note.to_string(),
            metric: M_BOOL,
        }],
        metric: M_BOOL,
    })
}

/// Whether `value` is an ABI-proven `Bool`-valued host call.
///
/// Membership is by **op family**, exactly as [`u32val_producer`] does and
/// for the same reason: a `bool`-typed binding is not evidence, since
/// every comparison in the IR is typed `bool` and comparing one of *those*
/// against `1` is ordinary logic, not marshalling.
fn bool_val_producer(func: &HighFunction, value: ValueId) -> bool {
    let id = resolve_use(func, value);
    let Some(Expr::Semantic(SemanticOp::Known(op))) = binding_expr(func, id) else {
        return false;
    };
    let ty = match op {
        // `l.0` — the only storage op returning a Bool.
        KnownOp::StorageHas { .. } => KnownType::Bool,
        KnownOp::MapOp { kind, .. } => val_abi::map_kind_result_type(kind),
        KnownOp::VecOp { kind, .. } => val_abi::vec_kind_result_type(kind),
        KnownOp::BufOp { kind, .. } => val_abi::buf_kind_result_type(kind),
        KnownOp::CryptoOp { kind, .. } => val_abi::crypto_kind_result_type(kind),
        _ => return false,
    };
    matches!(ty, KnownType::Bool)
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
        // `>=` against a bare boundary is `<`'s mirror and rests on the
        // same unsigned reading: `p >= k << 32` iff `payload >= k`. It
        // reached here once an entrypoint's own `u32` parameter counted as
        // a producer — `if decimal > 18` compiles to `ge param, 19 << 32`.
        BinaryOp::Lt | BinaryOp::Ge if side == ConstSide::Rhs => {
            try_ordered(func, cmp, value, const_id, bits)
        }
        BinaryOp::Gt if side == ConstSide::Rhs => try_ordered_gt(func, value, const_id, bits),
        BinaryOp::BitAnd => try_masked_value(func, cmp, value, const_id, bits),
        _ => None,
    }
}

/// Shape E — `p & ((m << 32) | tag)` as a *value*, which is
/// `payload & m`.
///
/// The other shapes end in a comparison; this one does not. rustc emits it
/// when it has proven a payload's range and masks to the bits that range
/// can occupy: token-v22's `TokenMetadata { decimal, … }` arrives as
/// `decimal & 0x1F_00000004`, because the `decimal > 18` check above it
/// bounds the payload at 18 and `0x1F` covers `0..=31`.
///
/// **Exact, with no premise.** A bitwise AND distributes over the Val's
/// fields independently: `(payload << 32 | tag) & (m << 32 | tag)` is
/// `((payload & m) << 32) | tag`. So the result is a well-formed Val of the
/// same tag whose payload is `payload & m`, and reading it at the payload
/// level is that mask and nothing else. The redundancy rustc was exploiting
/// is not needed to recover the expression — only to simplify it further,
/// which would take range reasoning this pipeline does not do.
///
/// The constant's whole minor field must be exactly the tag. `p & 0xFF` is
/// the tag *extraction* the SDK's own checks use, and reading that as a
/// payload mask would be nonsense.
fn try_masked_value(
    func: &HighFunction,
    and: ValueId,
    value: ValueId,
    const_id: ValueId,
    bits: u64,
) -> Option<Site> {
    let ty = u32val_producer(func, value)?;
    let tag = match ty {
        KnownType::U32 => u64::from(val_abi::TAG_U32_VAL),
        _ => return None,
    };
    if bits & !val_abi::MAJOR_MASK != tag {
        return None;
    }
    let m = u32::try_from(bits >> val_abi::MAJOR_SHIFT).ok()?;
    // An all-ones mask is the identity on the payload, so the expression
    // *is* the value. Declining left `expiration_ledger & -4294967292i64`
    // standing — the same `0xFFFFFFFF_00000004` written as a negative
    // `i64` — on the assumption some sweep would take it; none does, and
    // a rename says it outright.
    if m == u32::MAX {
        return Some(Site {
            rewrites: vec![Rewrite {
                id: and,
                expr: Expr::Use(value),
                ty: Some(IrType::Known(KnownType::U32)),
                source: ProvenanceSource::SdkPattern,
                note: "val-packed-compare: `& (u32::MAX << 32 | tag)` keeps every payload                        bit, so the masked value is the value"
                    .to_string(),
                metric: M_MASKED_VALUE,
            }],
            metric: M_MASKED_VALUE,
        });
    }
    Some(Site {
        rewrites: vec![
            Rewrite {
                id: const_id,
                expr: Expr::Literal(Literal::U32(m)),
                ty: Some(IrType::Known(KnownType::U32)),
                source: ProvenanceSource::SdkPattern,
                note: format!(
                    "val-packed-compare: `& ({m} << {shift} | tag)` on a packed U32Val is                      `& {m}` on its payload — the AND distributes over the Val's fields, so                      this is exact",
                    shift = val_abi::MAJOR_SHIFT
                ),
                metric: M_MASKED_VALUE,
            },
            Rewrite {
                id: and,
                expr: Expr::Binary {
                    op: BinaryOp::BitAnd,
                    lhs: value,
                    rhs: const_id,
                },
                ty: Some(IrType::Known(KnownType::U32)),
                source: ProvenanceSource::SdkPattern,
                note: "val-packed-compare: the masked value is its payload".to_string(),
                metric: M_MASKED_VALUE,
            },
        ],
        metric: M_MASKED_VALUE,
    })
}

/// Shape D — `p > (k << 32) - 1`, which is `payload > k - 1`.
///
/// rustc writes a `>` bound this way rather than as `>= k << 32`, because
/// wasm has no unsigned `>=` against an immediate it would rather spell.
/// `x > (k << 32) - 1` is `x >= k << 32` on unsigned, and `>= k` on the
/// payload is `> k - 1`, so the operator is kept and only the bound moves.
///
/// `dex`'s `if claimants.len() > 10` is the witness: `vec_len` returns a
/// packed `U32Val` and the bound is `(11 << 32) - 1`.
///
/// Same unsigned reading as [`try_ordered`], and the same guard against a
/// constant whose bit pattern is negative as an `i64`.
fn try_ordered_gt(
    func: &HighFunction,
    value: ValueId,
    const_id: ValueId,
    bits: u64,
) -> Option<Site> {
    // Every low bit set, so that incrementing leaves a clean major field.
    if bits == u64::MAX || (bits + 1) & !val_abi::MAJOR_MASK != 0 {
        return None;
    }
    let k = u32::try_from((bits + 1) >> val_abi::MAJOR_SHIFT).ok()?;
    // `k == 0` cannot happen once the increment is clean, and `payload > 0`
    // would be spelled `!= 0`; either way there is nothing to rewrite.
    if k == 0 {
        return None;
    }
    if (bits as i64) < 0 {
        return None;
    }
    u32val_producer(func, value)?;
    Some(Site {
        metric: M_ORDERED,
        rewrites: vec![Rewrite {
            id: const_id,
            expr: Expr::Literal(Literal::U32(k - 1)),
            ty: Some(IrType::Known(KnownType::U32)),
            source: ProvenanceSource::SdkPattern,
            note: format!(
                "val-packed-compare: `> ({k} << {shift}) - 1` on a packed U32Val is `> {}` on                  its payload (reads the wasm comparison as unsigned, which holds for every                  payload below 2^31)",
                k - 1,
                shift = val_abi::MAJOR_SHIFT
            ),
            metric: M_ORDERED,
        }],
    })
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
    // An entrypoint parameter the contract's own spec declares `u32` is a
    // `U32Val` on the wire, by the same ABI that types a host call's
    // result — and declared by the contract rather than looked up, so if
    // anything it is the firmer of the two. The guest code around it is
    // compiled against the encoding exactly as it is around a `bytes_len`:
    // token-v22's `if decimal > 18` reaches us as
    // `ge param, 19 << 32`.
    if let Some(ty) = spec_u32_param(func, id) {
        return Some(ty);
    }
    let Expr::Semantic(SemanticOp::Known(op)) = binding_expr(func, id)? else {
        return None;
    };
    // A storage read the SDK's own conversion checks against `U32Val`: the
    // check traps on anything else, and the typed read that replaces it
    // traps at the read itself — so from the read on, it is one. The
    // `errors` example's `count <= MAX` arrives as the raw read compared
    // with `MAX + 1 << 32`.
    if matches!(op, KnownOp::StorageGet { .. }) && tag_checked_u32(func, id) {
        return Some(KnownType::U32);
    }
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

/// The declared `u32`/`i32` type of `value` when it is this function's own
/// entrypoint parameter, by position against `contractspecv0`.
///
/// Positional because that is what the ABI is: one Val per declared
/// argument, in order. A function without a spec signature has no declared
/// types to read, and a parameter declared anything else is not a
/// `U32Val`.
fn spec_u32_param(func: &HighFunction, value: ValueId) -> Option<KnownType> {
    let index = func.params.iter().position(|p| *p == value)?;
    let declared = func
        .signature
        .as_ref()
        .and_then(|sig| sig.inputs.get(index))
        .and_then(|input| match &input.ty {
            sordec_ir::TypeRef::Primitive(sordec_ir::PrimitiveType::U32) => Some(KnownType::U32),
            sordec_ir::TypeRef::Primitive(sordec_ir::PrimitiveType::I32) => Some(KnownType::I32),
            _ => None,
        });
    declared.or_else(|| tag_checked_u32(func, value).then_some(KnownType::U32))
}

/// Whether the function's own body checks `value`'s tag against
/// `U32Val`.
///
/// The proof a `strip = true` module still carries. With no spec to declare
/// the parameter `u32`, the SDK's argument decode is still there, and its
/// first act is to test the tag byte: a value checked against `U32Val` *is*
/// one, by that check. The pipeline does recover the `u32` type later, but
/// `type_infer` runs long after this pass, so the recovered type is not
/// there yet to read — the tag check is.
fn tag_checked_u32(func: &HighFunction, value: ValueId) -> bool {
    func.bindings.iter().any(|(_, b)| {
        matches!(
            &b.expr,
            Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck { value: checked, tag, .. }))
                if *tag == val_abi::TAG_U32_VAL && resolve_use(func, *checked) == value
        )
    })
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

    /// `env.storage().<tier>().has(&k)` — a `Bool`-valued host call.
    fn storage_has(key: ValueId) -> Expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::StorageHas {
            tier: sordec_ir::StorageTier::Known(sordec_ir::KnownTier::Instance),
            durability: key,
            key,
            resolved_key: None,
            probe: false,
        }))
    }

    // --- shape C: a Bool Val narrowed by `== 1` ---

    #[test]
    fn a_bool_val_compared_against_true_is_the_val_itself() {
        // The SDK's `has` wrapper: `v1 = has(v0); v2 = 1; v3 = v1 == v2`.
        let mut func = func_with(vec![
            Expr::Phi { incoming: vec![] },
            storage_has(v(0)),
            Expr::Literal(Literal::I64(1)),
            Expr::Binary { op: BinaryOp::Eq, lhs: v(1), rhs: v(2) },
        ]);
        assert_eq!(run(&mut func).get(M_BOOL), Some(1));
        // The comparison *is* the Val — a Bool Val's bits are its value.
        assert!(matches!(func.bindings.get(v(3)).unwrap().expr, Expr::Use(p) if p == v(1)));
        assert_eq!(
            func.bindings.get(v(3)).unwrap().ty,
            IrType::Known(KnownType::Bool)
        );
    }

    #[test]
    fn a_bool_val_compared_against_false_is_its_negation() {
        let mut func = func_with(vec![
            Expr::Phi { incoming: vec![] },
            storage_has(v(0)),
            Expr::Literal(Literal::I64(0)),
            Expr::Binary { op: BinaryOp::Eq, lhs: v(1), rhs: v(2) },
        ]);
        assert_eq!(run(&mut func).get(M_BOOL), Some(1));
        assert!(matches!(
            func.bindings.get(v(3)).unwrap().expr,
            Expr::Unary { op: sordec_ir::UnaryOp::Not, value } if value == v(1)
        ));
    }

    #[test]
    fn the_constant_is_recognized_on_either_side() {
        let mut func = func_with(vec![
            Expr::Phi { incoming: vec![] },
            storage_has(v(0)),
            Expr::Literal(Literal::I64(1)),
            Expr::Binary { op: BinaryOp::Eq, lhs: v(2), rhs: v(1) },
        ]);
        assert_eq!(run(&mut func).get(M_BOOL), Some(1));
        assert!(matches!(func.bindings.get(v(3)).unwrap().expr, Expr::Use(p) if p == v(1)));
    }

    #[test]
    fn a_shared_constant_still_matches() {
        // Shape C re-types nothing, so the use-count gate the packed
        // shapes need must not apply to it: both comparisons match.
        let mut func = func_with(vec![
            Expr::Phi { incoming: vec![] },
            storage_has(v(0)),
            storage_has(v(0)),
            Expr::Literal(Literal::I64(1)),
            Expr::Binary { op: BinaryOp::Eq, lhs: v(1), rhs: v(3) },
            Expr::Binary { op: BinaryOp::Eq, lhs: v(2), rhs: v(3) },
        ]);
        assert_eq!(run(&mut func).get(M_BOOL), Some(2));
    }

    #[test]
    fn an_ordinary_bool_compared_against_one_is_left_alone() {
        // Every comparison in the IR is typed `bool`. Comparing one of
        // those against 1 is logic, not marshalling — which is why
        // membership is by op family, never by recovered type.
        let mut func = func_with(vec![
            Expr::Phi { incoming: vec![] },
            Expr::Phi { incoming: vec![] },
            Expr::Binary { op: BinaryOp::Lt, lhs: v(0), rhs: v(1) },
            Expr::Literal(Literal::I64(1)),
            Expr::Binary { op: BinaryOp::Eq, lhs: v(2), rhs: v(3) },
        ]);
        assert_eq!(run(&mut func).get(M_BOOL), None);
    }

    #[test]
    fn a_non_bool_host_call_is_not_this_shape() {
        // `bytes_len` is a U32Val; `== 1` on it is the packed shapes'
        // business, not this one.
        let mut func = func_with(vec![
            Expr::Phi { incoming: vec![] },
            bytes_len(v(0)),
            Expr::Literal(Literal::I64(1)),
            Expr::Binary { op: BinaryOp::Eq, lhs: v(1), rhs: v(2) },
        ]);
        assert_eq!(run(&mut func).get(M_BOOL), None);
    }

    #[test]
    fn a_constant_that_is_not_a_bool_encoding_is_declined() {
        // 2 is not a well-formed `Bool` Val, so the shape does not hold
        // and nothing is reinterpreted.
        let mut func = func_with(vec![
            Expr::Phi { incoming: vec![] },
            storage_has(v(0)),
            Expr::Literal(Literal::I64(2)),
            Expr::Binary { op: BinaryOp::Eq, lhs: v(1), rhs: v(2) },
        ]);
        assert_eq!(run(&mut func).get(M_BOOL), None);
    }

    #[test]
    fn bool_shape_is_idempotent() {
        let mut func = func_with(vec![
            Expr::Phi { incoming: vec![] },
            storage_has(v(0)),
            Expr::Literal(Literal::I64(1)),
            Expr::Binary { op: BinaryOp::Eq, lhs: v(1), rhs: v(2) },
        ]);
        assert_eq!(run(&mut func).get(M_BOOL), Some(1));
        assert_eq!(run(&mut func).get(M_BOOL), None, "no comparison left to match");
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

    /// `Le` stays unwitnessed: no fixture has produced one, so there is
    /// nothing to check a reading against. `Gt` declines *this* constant
    /// because [`try_ordered_gt`] needs every low bit set; it has its own
    /// test.
    #[test]
    fn the_unwitnessed_ordered_operators_are_declined() {
        for op in [BinaryOp::Le, BinaryOp::Gt] {
            let mut func = func_with(vec![
                Expr::Phi { incoming: vec![] },
                bytes_len(v(0)),
                Expr::Literal(Literal::I64(1 << val_abi::MAJOR_SHIFT)),
                Expr::Binary { op, lhs: v(1), rhs: v(2) },
            ]);
            assert_eq!(run(&mut func).get(M_ORDERED), None, "{op:?} must not match");
        }
    }

    /// A mask used as a *value* reads at the payload level, exactly: the
    /// AND distributes over the Val's fields, so `p & (31 << 32 | 4)` is
    /// `payload & 31`. token-v22's `TokenMetadata { decimal, … }` is the
    /// witness — rustc masked to the bits the `decimal > 18` check above
    /// proves the payload can occupy.
    #[test]
    fn a_mask_used_as_a_value_reads_as_its_payload() {
        let mut func = func_with(vec![
            Expr::Phi { incoming: vec![] },
            bytes_len(v(0)),
            Expr::Literal(Literal::I64(
                (31 << val_abi::MAJOR_SHIFT) | i64::from(val_abi::TAG_U32_VAL),
            )),
            Expr::Binary { op: BinaryOp::BitAnd, lhs: v(1), rhs: v(2) },
        ]);
        assert_eq!(run(&mut func).get(M_MASKED_VALUE), Some(1), "one site");
        assert!(
            matches!(
                func.bindings.get(v(2)).expect("the mask").expr,
                Expr::Literal(Literal::U32(31))
            ),
            "the mask reads as its payload"
        );
    }

    /// An all-ones payload mask keeps every bit, so the expression is the
    /// value. token-v22 writes it as the negative `i64`
    /// `-4294967292` — the same `0xFFFFFFFF_00000004`.
    #[test]
    fn an_all_ones_mask_is_a_rename() {
        let mut func = func_with(vec![
            Expr::Phi { incoming: vec![] },
            bytes_len(v(0)),
            Expr::Literal(Literal::I64(-4_294_967_292)),
            Expr::Binary { op: BinaryOp::BitAnd, lhs: v(1), rhs: v(2) },
        ]);
        assert_eq!(run(&mut func).get(M_MASKED_VALUE), Some(1));
        assert!(
            matches!(
                func.bindings.get(v(3)).expect("the mask").expr,
                Expr::Use(u) if u == v(1)
            ),
            "the masked value is the value, got {:?}",
            func.bindings.get(v(3)).map(|b| &b.expr)
        );
    }

    /// The half that matters. `p & 0xFF` is the SDK's own *tag*
    /// extraction, not a payload mask — its minor field is not the tag, so
    /// reading it at the payload level would be nonsense.
    #[test]
    fn a_tag_extraction_is_not_a_payload_mask() {
        let mut func = func_with(vec![
            Expr::Phi { incoming: vec![] },
            bytes_len(v(0)),
            Expr::Literal(Literal::I64(255)),
            Expr::Binary { op: BinaryOp::BitAnd, lhs: v(1), rhs: v(2) },
        ]);
        assert_eq!(run(&mut func).get(M_MASKED_VALUE), None, "left alone");
    }

    /// A stripped module has no spec to declare a parameter `u32`, but the
    /// SDK's decode still tag-checks it — and a value checked against
    /// `U32Val` is one. token-v23-stripped's `__constructor` is the witness.
    #[test]
    fn a_tag_checked_parameter_is_a_u32val_without_a_spec() {
        let mut func = crate::marshalling::test_support::func_with(
            vec![
                Expr::Phi { incoming: vec![] }, // v0, the parameter
                Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck {
                    value: v(0),
                    tag: val_abi::TAG_U32_VAL,
                    negated: true,
                })), // v1
                Expr::Literal(Literal::I64(19 << val_abi::MAJOR_SHIFT)), // v2
                Expr::Binary { op: BinaryOp::Ge, lhs: v(0), rhs: v(2) }, // v3
            ],
            vec![v(0)],
            vec![1, 2, 3],
        );
        assert_eq!(run(&mut func).get(M_ORDERED), Some(1), "the tag check is the proof");
    }

    /// The half that matters: an untested parameter is a raw word, and a
    /// comparison on it is ordinary arithmetic.
    #[test]
    fn an_unchecked_parameter_without_a_spec_is_left_alone() {
        let mut func = crate::marshalling::test_support::func_with(
            vec![
                Expr::Phi { incoming: vec![] },
                Expr::Literal(Literal::I64(19 << val_abi::MAJOR_SHIFT)),
                Expr::Binary { op: BinaryOp::Ge, lhs: v(0), rhs: v(1) },
            ],
            vec![v(0)],
            vec![1, 2],
        );
        assert_eq!(run(&mut func).get(M_ORDERED), None, "nothing proves it is a Val");
    }

    /// `>=` is `<`'s mirror under the same unsigned reading, and
    /// token-v22's `if decimal > 18` is what witnessed it.
    #[test]
    fn a_ge_against_a_bare_boundary_reads_as_the_payload() {
        let mut func = func_with(vec![
            Expr::Phi { incoming: vec![] },
            bytes_len(v(0)),
            Expr::Literal(Literal::I64(19 << val_abi::MAJOR_SHIFT)),
            Expr::Binary { op: BinaryOp::Ge, lhs: v(1), rhs: v(2) },
        ]);
        assert_eq!(run(&mut func).get(M_ORDERED), Some(1), "Ge is witnessed");
        assert!(
            matches!(
                func.bindings.get(v(2)).expect("the boundary").expr,
                Expr::Literal(Literal::U32(19))
            ),
            "the boundary reads as its payload"
        );
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
