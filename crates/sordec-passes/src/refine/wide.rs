//! The 128-bit operands hiding in pairs of 64-bit registers.
//!
//! Wasm has no 128-bit type. Every `i128` in a Soroban contract reaches
//! us as two registers, and the passes that read an operation back off
//! its limbs ([`super::wide_arith`], [`super::wide_compare`]) all face
//! the same question first: *which value is this pair the halves of?*
//!
//! There are two answers. Sometimes the function already names the
//! value and each limb is an explicit half of it — a helper's promoted
//! parameter, an earlier recovery. Sometimes the limbs are all there is:
//! two registers loaded out of storage, two parameters, two results of a
//! host call, with nothing tying them together. The second case is the
//! common one, and refusing it is why a recognizer that knows the
//! pattern exactly still declines the contract in front of it.
//!
//! A pair is only an operand when the pattern says so. That evidence is
//! the caller's to supply — a borrow naming its low limbs, a
//! lexicographic tie-break naming its high ones — and this module only
//! holds what to do once it has been supplied: check the two limbs agree
//! about which kind of pair they are, and build the join when they are
//! loose.

use sordec_common::{IrId, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{Binding, Expr, HighFunction, IrType, KnownType, UnaryOp};

use crate::dataflow::resolve_use;

/// One 128-bit operand, before it necessarily exists as a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Side {
    /// Both limbs are already halves of a value the function names.
    Whole(ValueId),
    /// Two loose registers; the operand is their join.
    Loose { lo: ValueId, hi: ValueId },
}

impl Side {
    /// Whether `value` is this operand's low limb.
    pub(crate) fn has_lo(&self, func: &HighFunction, value: ValueId) -> bool {
        match self {
            Side::Whole(w) => half_of(func, value, UnaryOp::WideLo) == Some(*w),
            Side::Loose { lo, .. } => resolve_use(func, value) == *lo,
        }
    }

    /// The values that must already be in hand to build this operand.
    pub(crate) fn needs(&self) -> [Option<ValueId>; 2] {
        match self {
            Side::Whole(w) => [Some(*w), None],
            Side::Loose { lo, hi } => [Some(*lo), Some(*hi)],
        }
    }
}

/// The operand a low and a high limb are the two halves of.
///
/// Either the function already names it and both limbs are its halves,
/// or neither limb is anyone's half and the operand is their join. A
/// limb belonging to one value beside a limb belonging to another — or
/// to nothing — is not a pair, and joining across it would invent an
/// operand out of two unrelated registers.
pub(crate) fn paired(func: &HighFunction, lo: ValueId, hi: ValueId) -> Option<Side> {
    match (
        half_of(func, lo, UnaryOp::WideLo),
        half_of(func, hi, UnaryOp::WideHi),
    ) {
        (Some(from_lo), Some(from_hi)) if from_lo == from_hi => Some(Side::Whole(from_lo)),
        (None, None) => Some(Side::Loose { lo, hi }),
        _ => None,
    }
}

/// Whether every operand can be named at `before`'s place in the
/// schedule.
///
/// An operand computed *between* the two limbs of an operation cannot be
/// named ahead of the first of them, and naming it there anyway is a use
/// before its definition. Values the schedule does not mention are
/// parameters and block parameters, which are always in hand.
pub(crate) fn available_before(
    order: &[ValueId],
    sides: &[Side],
    before: usize,
) -> bool {
    !sides
        .iter()
        .flat_map(Side::needs)
        .flatten()
        .any(|v| order.iter().position(|o| *o == v).is_some_and(|p| p >= before))
}

/// The value this operand is, building the join when it is loose.
///
/// The new binding is pushed but not scheduled — the caller knows where
/// the operation it belongs to goes, and puts it there.
pub(crate) fn materialize(func: &mut HighFunction, side: Side, pass: &'static str) -> ValueId {
    match side {
        Side::Whole(v) => v,
        Side::Loose { lo, hi } => {
            let joined = ValueId::from_index(func.bindings.len() as u32);
            func.bindings.push(Binding::new(
                joined,
                IrType::Inferred(KnownType::I128),
                Expr::WideJoin { lo, hi },
                Provenance::new(
                    pass,
                    ProvenanceSource::DataFlow,
                    "the operand these two limbs are the halves of",
                ),
            ));
            joined
        }
    }
}

/// The value this is the named half of.
pub(crate) fn half_of(func: &HighFunction, value: ValueId, want: UnaryOp) -> Option<ValueId> {
    match &func.bindings.get(resolve_use(func, value))?.expr {
        Expr::Unary { op, value } if *op == want => Some(resolve_use(func, *value)),
        _ => None,
    }
}
