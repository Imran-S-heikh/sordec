//! Fold the SDK's `bool` ↔ `Val` conversion back to the `bool`.
//!
//! A `bool` has no small-integer body: it *is* its tag, `Tag::False` (0) or
//! `Tag::True` (1). So the conversion rustc inlines is not the tag check and
//! unpack [`super::typed_read`] folds, but a dispatch on the tag byte in one
//! direction and a pair of selects in the other.
//!
//! # Decoding
//!
//! `e.storage().instance().get(&PAUSED)` at type `bool` arrives as
//!
//! ```text
//! match (g & 0xFF) {        →   return g          : bool
//!     0 => return 0,
//!     1 => return 1,
//!     _ => panic!(),
//! }
//! ```
//!
//! The arms are the re-encoding the generated entrypoint wrapper does, so
//! case 0 must yield the `Val` for `false` and case 1 the `Val` for `true`.
//! Read that way the whole dispatch is `Val → bool → Val` on the same value,
//! and what it returns is the value it was given.
//!
//! # Encoding
//!
//! `set(&PAUSED, &paused)` arrives as the reverse, spelled with selects
//! because both arms are constants:
//!
//! ```text
//! t = has_tag(v, True)                  →   v        : bool
//! e = select(1, select(2, 0, v & 0xFF), t)
//! if e != 2 { … } else { panic!() }     →   (always taken)
//! ```
//!
//! `2` is `Tag::Void` — the SDK's "this was not a bool" marker, which the
//! branch after it tests for. When `v` is a value a pass has already typed
//! `bool`, the marker is unreachable: the encoding of a `bool` is 0 or 1.
//! So the select chain is the value and every comparison of it against a
//! constant outside `{0, 1}` folds to the answer it always gives.
//!
//! # Why it is exact
//!
//! Both rewrites need `v` to be a `bool`, and both keep the trap. Decoding,
//! the conversion is re-emitted by the typed `get` the reconstruction
//! prints, which runs the same `bool::try_from_val`; the tag test deleted
//! here is the one it makes. Encoding, the value is already typed `bool` —
//! by the entrypoint's own signature, in the case this was written for — so
//! the check that it is one cannot fail, and folding it away removes a
//! branch the source never had rather than one it relied on.

use sordec_common::{Provenance, ProvenanceSource, ValueId};
use sordec_ir::{
    BinaryOp, Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Literal, Region, SemanticOp,
    UnaryOp, WasmOpcodeKind,
};

use crate::dataflow::{block_containing, resolve_use};
use crate::effects::expr_effects;
use crate::metrics_catalog::MARSHALLING_BOOL_CODECS as M_BOOLS;
use crate::pass::{Pass, PassResult};
use crate::type_infer::known_of_type_ref;
use crate::val_abi::{TAG_FALSE, TAG_TRUE, TAG_VOID};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-bool-codec";

/// Folds `bool` ↔ `Val` conversion into the `bool`.
#[derive(Debug, Default, Clone, Copy)]
pub struct BoolCodecPass;

impl Pass<HighIr> for BoolCodecPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            // Both reads are taken before either rewrite: once an encoding
            // is a rename, `resolve_use` walks straight past it and its
            // marker test no longer names it.
            let folded = encodings(func);
            let tests = marker_tests(func, &folded);
            let widened = widenings(func, &folded);
            let masked = masks(func, &folded);
            for (id, value) in &folded {
                retype(func, *id, Expr::Use(*value), "the `bool` this encoding was made from");
            }
            for (id, value) in masked {
                retype(func, id, Expr::Use(value), "the low bit of a `bool` encoding is the `bool`");
            }
            for (id, value) in widened {
                retype(func, id, Expr::Use(value), "the widening of a `bool` to its `Val` is the `bool`");
            }
            for (id, answer) in tests {
                retype(func, id, Expr::Literal(Literal::Bool(answer)), "a `bool` encoding is never the void marker");
            }
            if !folded.is_empty() {
                result.metrics.increment(M_BOOLS, folded.len() as i64);
                result.changed = true;
            }
            let mut decoded = Vec::new();
            let region = std::mem::replace(&mut func.region, Region::Unreachable);
            func.region = fold_decodes(func, region, &mut decoded);
            if !decoded.is_empty() {
                result.metrics.increment(M_BOOLS, decoded.len() as i64);
                result.changed = true;
            }
            // The dispatch proved the value is a `bool`, so the read it came
            // from is one — as long as the dispatch was its only reader.
            // A value someone else still reads as a `Val` keeps its type,
            // the same gate [`super::typed_read`] makes.
            for (value, chain) in decoded {
                let only_reader = !func.bindings.iter().any(|(id, b)| {
                    let mut reads = false;
                    b.expr.for_each_value_use(|u| reads |= resolve_use(func, u) == value);
                    reads && !chain.contains(&id)
                });
                if only_reader && let Some(b) = func.bindings.get_mut(value) {
                    b.ty = IrType::Inferred(KnownType::Bool);
                    b.add_provenance(Provenance::new(
                        PASS_NAME,
                        ProvenanceSource::SdkPattern,
                        "read as a `bool` by the dispatch that decoded it",
                    ));
                }
            }
        }
        result
    }
}

fn retype(func: &mut HighFunction, id: ValueId, expr: Expr, note: &'static str) {
    if let Some(b) = func.bindings.get_mut(id) {
        b.expr = expr;
        b.ty = IrType::Inferred(KnownType::Bool);
        b.add_provenance(Provenance::new(PASS_NAME, ProvenanceSource::SdkPattern, note));
    }
}

/// `select(1, select(2, 0, tag_byte(v)), has_tag(v, True))` over a value
/// already typed `bool`, mapped to that value.
fn encodings(func: &HighFunction) -> Vec<(ValueId, ValueId)> {
    func.bindings
        .iter()
        .filter_map(|(id, b)| {
            let [on_true, on_false, cond] = select_args(&b.expr)?;
            // The `true` arm is the encoding of `true`, and the condition
            // the test that the value is it.
            (int_literal(func, on_true)? == i128::from(TAG_TRUE)).then_some(())?;
            let value = match &func.bindings.get(resolve_use(func, cond))?.expr {
                Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck { value, tag, negated: false }))
                    if *tag == TAG_TRUE =>
                {
                    resolve_use(func, *value)
                }
                _ => return None,
            };
            if !is_bool(func, value) {
                return None;
            }
            // The `false` arm decides between the encoding of `false` and
            // the void marker, and rustc spells it two ways.
            other_arm(func, on_false, value).then_some((id, value))
        })
        .collect()
}

/// The arm taken when the value is not `Tag::True`: it yields the
/// encoding of `false` when the value is `Tag::False`, and the void
/// marker when it is neither.
///
/// ```text
/// select(Void, False, tag_byte(v))     the tag byte decides
/// (!has_tag(v, False)) << 1            0 when it is False, 2 when not
/// ```
///
/// The shift is the same statement arithmetically: `Tag::Void` is 2 and
/// `Tag::False` is 0, so doubling the "is not false" flag gives one or
/// the other.
fn other_arm(func: &HighFunction, arm: ValueId, value: ValueId) -> bool {
    let Some(expr) = func.bindings.get(resolve_use(func, arm)).map(|b| &b.expr) else {
        return false;
    };
    if let Some([marker, on_zero, byte]) = select_args(expr) {
        return int_literal(func, marker) == Some(i128::from(TAG_VOID))
            && int_literal(func, on_zero) == Some(i128::from(TAG_FALSE))
            && tag_byte_of(func, byte) == Some(value);
    }
    let Expr::Binary { op: BinaryOp::Shl, lhs, rhs } = expr else {
        return false;
    };
    // One doubling, of the "not false" test on the same value.
    if int_literal(func, resolve_use(func, *rhs)) != Some(1) {
        return false;
    }
    matches!(
        func.bindings.get(resolve_use(func, *lhs)).map(|b| &b.expr),
        Some(Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck { value: v, tag, negated: true })))
            if *tag == TAG_FALSE && resolve_use(func, *v) == value
    )
}

/// The widening of a folded encoding to a full `Val`. A `bool` is its tag,
/// so the wide form carries nothing the narrow one did not.
fn widenings(func: &HighFunction, folded: &[(ValueId, ValueId)]) -> Vec<(ValueId, ValueId)> {
    func.bindings
        .iter()
        .filter_map(|(id, b)| {
            let Expr::Unary { op: UnaryOp::ExtendU32 | UnaryOp::ExtendS32, value } = &b.expr else {
                return None;
            };
            let target = resolve_use(func, *value);
            folded.iter().find(|(f, _)| *f == target).map(|(_, v)| (id, *v))
        })
        .collect()
}

/// `encoding & 1`, which reads the flag back out. A `bool` encoding is 0
/// or 1, so masking its low bit gives it back.
fn masks(func: &HighFunction, folded: &[(ValueId, ValueId)]) -> Vec<(ValueId, ValueId)> {
    func.bindings
        .iter()
        .filter_map(|(id, b)| {
            let Expr::Binary { op: BinaryOp::BitAnd, lhs, rhs } = &b.expr else {
                return None;
            };
            [(*lhs, *rhs), (*rhs, *lhs)].into_iter().find_map(|(value, mask)| {
                (int_literal(func, resolve_use(func, mask))? == 1).then_some(())?;
                let target = resolve_use(func, value);
                folded.iter().find(|(f, _)| *f == target).map(|(_, v)| (id, *v))
            })
        })
        .collect()
}

/// Comparisons of a folded encoding against a constant it can never equal:
/// the branch the SDK writes to catch a value that was not a `bool`.
fn marker_tests(func: &HighFunction, folded: &[(ValueId, ValueId)]) -> Vec<(ValueId, bool)> {
    func.bindings
        .iter()
        .filter_map(|(id, b)| {
            let Expr::Binary { op: op @ (BinaryOp::Eq | BinaryOp::Ne), lhs, rhs } = &b.expr else {
                return None;
            };
            let encoding = |v: ValueId| folded.iter().any(|(f, _)| *f == resolve_use(func, v));
            let other = if encoding(*lhs) {
                *rhs
            } else if encoding(*rhs) {
                *lhs
            } else {
                return None;
            };
            let n = int_literal(func, resolve_use(func, other))?;
            // 0 and 1 are the encodings themselves; anything else is a
            // value the comparison can only ever answer one way.
            (n != 0 && n != 1).then_some((id, *op == BinaryOp::Ne))
        })
        .collect()
}

/// Rewrites every `match tag_byte(v) { False => false, True => true }`
/// whose arms return the re-encoded answer to a return of `v` itself.
fn fold_decodes(func: &HighFunction, region: Region, decoded: &mut Vec<(ValueId, Vec<ValueId>)>) -> Region {
    let mut recurse = |r: Region| fold_decodes(func, r, decoded);
    match region {
        Region::Switch { index, arms, default, dispatch } => {
            if let Some((value, chain)) = decoded_bool(func, index, &arms, &default) {
                decoded.push((value, chain));
                return Region::Return { values: vec![value] };
            }
            Region::Switch {
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
            }
        }
        Region::Sequence(items) => Region::Sequence(items.into_iter().map(&mut recurse).collect()),
        Region::Scope { out, body } => Region::Scope { out, body: Box::new(recurse(*body)) },
        Region::Loop { header, body, kind } => Region::Loop { header, body: Box::new(recurse(*body)), kind },
        Region::If { cond, then_region, else_region } => Region::If {
            cond,
            then_region: Box::new(recurse(*then_region)),
            else_region: else_region.map(|e| Box::new(recurse(*e))),
        },
        other => other,
    }
}

/// The value a decoding dispatch converts, if that is what this is.
fn decoded_bool(
    func: &HighFunction,
    index: ValueId,
    arms: &[sordec_ir::SwitchArm],
    default: &Region,
) -> Option<(ValueId, Vec<ValueId>)> {
    if !traps(default) {
        return None;
    }
    let mut chain = Vec::new();
    let value = tag_byte_chain(func, index, &mut chain)?;
    let [a, b] = arms else {
        return None;
    };
    let returned = |arm: &sordec_ir::SwitchArm, case: u32, tag: u8| -> bool {
        arm.cases == vec![case]
            && arm_return(func, &arm.body)
                .and_then(|v| int_literal(func, resolve_use(func, v)))
                == Some(i128::from(tag))
    };
    (returned(a, u32::from(TAG_FALSE), TAG_FALSE) && returned(b, u32::from(TAG_TRUE), TAG_TRUE))
        .then_some((value, chain))
}

/// An arm that only traps: the conversion error on a tag that is neither.
fn traps(region: &Region) -> bool {
    let mut panics = false;
    let mut ok = true;
    region.for_each_node(|node| match node {
        Region::Panic { .. } => panics = true,
        Region::Basic(_) | Region::Sequence(_) => {}
        _ => ok = false,
    });
    panics && ok
}

/// The one value an arm returns, when returning it is all the arm does.
/// Its blocks may compute the constant it returns, and nothing with an
/// effect: the arm is about to stop existing.
fn arm_return(func: &HighFunction, region: &Region) -> Option<ValueId> {
    let mut returned = None;
    let mut blocks = Vec::new();
    let mut ok = true;
    region.for_each_node(|node| match node {
        Region::Return { values } if values.len() == 1 => {
            if returned.replace(values[0]).is_some() {
                ok = false;
            }
        }
        Region::Basic(block) => blocks.push(*block),
        Region::Sequence(_) => {}
        _ => ok = false,
    });
    if !ok {
        return None;
    }
    for (id, binding) in func.bindings.iter() {
        if block_containing(func, id).is_some_and(|b| blocks.contains(&b))
            && !expr_effects(&binding.expr).is_pure_total()
        {
            return None;
        }
    }
    returned
}

/// The value whose tag byte this is: `x & 0xFF` on `x` or its narrowing.
fn tag_byte_of(func: &HighFunction, value: ValueId) -> Option<ValueId> {
    tag_byte_chain(func, value, &mut Vec::new())
}

/// As [`tag_byte_of`], also collecting the bindings the mask is spelled
/// with, so a caller can tell them from a reader that wanted the `Val`.
fn tag_byte_chain(func: &HighFunction, value: ValueId, chain: &mut Vec<ValueId>) -> Option<ValueId> {
    let masked_id = resolve_use(func, value);
    chain.push(masked_id);
    let Expr::Binary { op: BinaryOp::BitAnd, lhs, rhs } = &func.bindings.get(masked_id)?.expr else {
        return None;
    };
    let masked = if int_literal(func, resolve_use(func, *rhs)) == Some(0xFF) {
        *lhs
    } else if int_literal(func, resolve_use(func, *lhs)) == Some(0xFF) {
        *rhs
    } else {
        return None;
    };
    let masked = resolve_use(func, masked);
    chain.push(masked);
    match &func.bindings.get(masked)?.expr {
        Expr::Unary { op: UnaryOp::Wrap32, value } => Some(resolve_use(func, *value)),
        _ => Some(masked),
    }
}

fn select_args(expr: &Expr) -> Option<[ValueId; 3]> {
    let Expr::Unknown { op_kind: WasmOpcodeKind::Select, args, .. } = expr else {
        return None;
    };
    let [a, b, c] = args.as_slice() else {
        return None;
    };
    Some([*a, *b, *c])
}

/// Whether this value is known to be a `bool` — by the entrypoint's
/// declared signature, which is the authoritative ABI, or by a type a pass
/// has already committed to. Type inference runs after this group, so the
/// signature is what is available here.
fn is_bool(func: &HighFunction, value: ValueId) -> bool {
    let declared = func
        .signature
        .as_ref()
        .zip(func.params.iter().position(|p| *p == value))
        .and_then(|(sig, i)| known_of_type_ref(&sig.inputs.get(i)?.ty));
    declared == Some(KnownType::Bool)
        || matches!(
            func.bindings.get(value).map(|b| &b.ty),
            Some(IrType::Known(KnownType::Bool) | IrType::Inferred(KnownType::Bool))
        )
}

fn int_literal(func: &HighFunction, value: ValueId) -> Option<i128> {
    match &func.bindings.get(value)?.expr {
        Expr::Literal(Literal::I32(n)) => Some(i128::from(*n)),
        Expr::Literal(Literal::I64(n)) => Some(i128::from(*n)),
        Expr::Literal(Literal::U32(n)) => Some(i128::from(*n)),
        Expr::Literal(Literal::U64(n)) => Some(i128::from(*n)),
        Expr::Literal(Literal::Bool(b)) => Some(i128::from(*b)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};
    use sordec_common::UnknownReason;
    use sordec_ir::{PanicKind, SwitchArm};

    fn select(on_true: ValueId, on_false: ValueId, cond: ValueId) -> Expr {
        Expr::Unknown {
            op_kind: WasmOpcodeKind::Select,
            args: vec![on_true, on_false, cond],
            reason: UnknownReason::UnsupportedPattern,
        }
    }

    /// `v0: bool` encoded and tested against the void marker.
    fn encode_shape(ty: IrType) -> HighIr {
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                                    // v0
                Expr::Literal(Literal::I32(1)),                                    // v1 true
                Expr::Literal(Literal::I32(0)),                                    // v2 false
                Expr::Literal(Literal::I32(2)),                                    // v3 void
                Expr::Literal(Literal::I32(0xFF)),                                 // v4
                Expr::Unary { op: UnaryOp::Wrap32, value: v(0) },                   // v5
                Expr::Binary { op: BinaryOp::BitAnd, lhs: v(5), rhs: v(4) },           // v6
                Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck {
                    value: v(0),
                    tag: TAG_TRUE,
                    negated: false,
                })), // v7
                select(v(3), v(2), v(6)),                                          // v8
                select(v(1), v(8), v(7)),                                          // v9
                Expr::Binary { op: BinaryOp::Ne, lhs: v(9), rhs: v(3) },            // v10
                Expr::Unary { op: UnaryOp::ExtendU32, value: v(9) },                // v11
            ],
            vec![v(0)],
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
        );
        f.bindings.get_mut(v(0)).unwrap().ty = ty;
        module(vec![f])
    }

    #[test]
    fn an_encoding_of_a_bool_is_the_bool_and_its_marker_test_is_settled() {
        let mut m = encode_shape(IrType::Known(KnownType::Bool));
        assert!(BoolCodecPass.run(&mut m).changed);
        let f = &m.functions[0];
        assert!(matches!(f.bindings.get(v(9)).unwrap().expr, Expr::Use(x) if x == v(0)));
        assert!(matches!(f.bindings.get(v(10)).unwrap().expr, Expr::Literal(Literal::Bool(true))));
        assert!(matches!(f.bindings.get(v(11)).unwrap().expr, Expr::Use(x) if x == v(0)), "the widening too");
    }

    /// The other spelling of the `false` arm: `(!has_tag(v, False)) << 1`
    /// is 0 when the value is false and the void marker when it is not a
    /// bool at all. The mask that reads the flag back out goes with it.
    #[test]
    fn the_shift_spelling_of_the_false_arm_is_recognized_too() {
        let mut m = module(vec![{
            let mut f = func_with(
                vec![
                    Expr::Phi { incoming: vec![] },                      // v0
                    Expr::Literal(Literal::I32(1)),                      // v1
                    Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck {
                        value: v(0),
                        tag: TAG_FALSE,
                        negated: true,
                    })), // v2
                    Expr::Binary { op: BinaryOp::Shl, lhs: v(2), rhs: v(1) }, // v3
                    Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck {
                        value: v(0),
                        tag: TAG_TRUE,
                        negated: false,
                    })), // v4
                    select(v(1), v(3), v(4)),                            // v5
                    Expr::Binary { op: BinaryOp::BitAnd, lhs: v(5), rhs: v(1) }, // v6
                ],
                vec![v(0)],
                vec![1, 2, 3, 4, 5, 6],
            );
            f.bindings.get_mut(v(0)).unwrap().ty = IrType::Known(KnownType::Bool);
            f
        }]);
        assert!(BoolCodecPass.run(&mut m).changed);
        let f = &m.functions[0];
        assert!(matches!(f.bindings.get(v(5)).unwrap().expr, Expr::Use(x) if x == v(0)));
        assert!(
            matches!(f.bindings.get(v(6)).unwrap().expr, Expr::Use(x) if x == v(0)),
            "the low bit of the encoding is the bool"
        );
    }

    /// The same shape on an untyped value is a real conversion.
    #[test]
    fn an_encoding_of_an_untyped_value_stays() {
        let mut m = encode_shape(IrType::Known(KnownType::I64));
        assert!(!BoolCodecPass.run(&mut m).changed);
    }

    /// `match g & 0xFF { 0 => return 0, 1 => return 1, _ => panic }`.
    fn decode_shape(true_arm: i64) -> HighIr {
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                          // v0 the read
                Expr::Literal(Literal::I32(0xFF)),                       // v1
                Expr::Unary { op: UnaryOp::Wrap32, value: v(0) },         // v2
                Expr::Binary { op: BinaryOp::BitAnd, lhs: v(2), rhs: v(1) }, // v3
                Expr::Literal(Literal::I64(0)),                          // v4
                Expr::Literal(Literal::I64(true_arm)),                   // v5
            ],
            vec![],
            vec![1, 2, 3, 4, 5],
        );
        f.region = Region::Switch {
            index: v(3),
            arms: vec![
                SwitchArm { cases: vec![0], body: Region::Return { values: vec![v(4)] } },
                SwitchArm { cases: vec![1], body: Region::Return { values: vec![v(5)] } },
            ],
            default: Box::new(Region::Panic { kind: PanicKind::Bare }),
            dispatch: None,
        };
        module(vec![f])
    }

    #[test]
    fn a_decoding_dispatch_returns_the_value_it_decoded() {
        let mut m = decode_shape(1);
        assert!(BoolCodecPass.run(&mut m).changed);
        assert!(matches!(&m.functions[0].region, Region::Return { values } if values == &vec![v(0)]));
    }

    /// An arm that yields something other than the re-encoding is a real
    /// dispatch on a tag, not a round trip.
    #[test]
    fn a_dispatch_that_is_not_a_round_trip_stays() {
        let mut m = decode_shape(7);
        assert!(!BoolCodecPass.run(&mut m).changed);
    }
}
