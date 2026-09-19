//! Read a 128-bit addition or subtraction back off its limbs.
//!
//! The multiply and divide arrive as calls to compiler-rt helpers and are
//! already recovered from those. Addition and subtraction are cheap
//! enough that rustc writes them out, one limb at a time, threading a
//! carry between:
//!
//! ```text
//! lo = lo(a) - lo(b)                             r  = a - b
//! hi = (hi(a) - hi(b)) - (lo(a) <u lo(b))   →    lo = wide_lo(r)
//!                                                hi = wide_hi(r)
//! ```
//!
//! Left in limbs it is the last thing holding several recognizers apart.
//! A helper handed `lo` and `hi` cannot be given the whole value, because
//! there is no whole value to give; the comparison the callee makes on it
//! stays a `select` over two unrelated registers; and the guard that
//! comparison feeds keeps the polarity wasm gave it.
//!
//! # Why it is exact
//!
//! This is the definition of the operation at twice the width: the low
//! limb wraps and the carry it produces is exactly the `<u` test rustc
//! writes, so the pair `(hi, lo)` is the two halves of `a ± b`. The
//! rewrite names that value and leaves each limb naming its own half of
//! it, so every reader sees what it saw.
//!
//! # Gates
//!
//! - **Both limbs of both operands**, and the same two values throughout.
//! - **The carry is the one this addition produces**: `lo <u lo(b)` for a
//!   sum, `lo(a) <u lo(b)` for a difference. A carry from somewhere else
//!   makes this some other arithmetic.
//! - **The carry is zero-extended.** That is how a 1-bit flag becomes a
//!   limb, and anything else in that position is a value, not a carry.

use sordec_common::{IrId, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{BinaryOp, Binding, Expr, HighFunction, HighIr, IrType, KnownType, UnaryOp};

use crate::dataflow::resolve_use;
use crate::metrics_catalog::REFINE_WIDE_ARITH as M_ARITH;
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "refine-wide-arith";

/// Names the 128-bit sum or difference a limb pair computes.
#[derive(Debug, Default, Clone, Copy)]
pub struct WideArithPass;

/// One recovered operation.
struct Found {
    lo: ValueId,
    hi: ValueId,
    op: BinaryOp,
    a: ValueId,
    b: ValueId,
}

impl Pass<HighIr> for WideArithPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            let found: Vec<Found> =
                func.bindings.iter().filter_map(|(id, b)| limbs(func, id, &b.expr)).collect();
            for f in found {
                let note = Provenance::new(
                    PASS_NAME,
                    ProvenanceSource::DataFlow,
                    "the 128-bit value these two limbs compute",
                );
                let whole = ValueId::from_index(func.bindings.len() as u32);
                func.bindings.push(Binding::new(
                    whole,
                    IrType::Inferred(KnownType::I128),
                    Expr::Binary { op: f.op, lhs: f.a, rhs: f.b },
                    note.clone(),
                ));
                // Before whichever limb the schedule reaches first: the
                // other one reads this value too, and rustc is free to
                // compute the high limb before the low.
                let order = crate::marshalling::sret::emission_order(func);
                let first = [f.lo, f.hi]
                    .into_iter()
                    .filter_map(|v| order.iter().position(|o| *o == v).map(|p| (p, v)))
                    .min()
                    .map(|(_, v)| v);
                if let Some(first) = first {
                    for (_, block) in func.blocks.iter_mut() {
                        if let Some(pos) = block.bindings.iter().position(|v| *v == first) {
                            block.bindings.insert(pos, whole);
                            break;
                        }
                    }
                }
                for (id, op) in [(f.lo, UnaryOp::WideLo), (f.hi, UnaryOp::WideHi)] {
                    if let Some(b) = func.bindings.get_mut(id) {
                        b.expr = Expr::Unary { op, value: whole };
                        b.add_provenance(note.clone());
                    }
                }
                result.metrics.increment(M_ARITH, 1);
                result.changed = true;
            }
        }
        result
    }
}

/// The operation a high limb completes, given the whole function.
///
/// Keyed on the *high* limb because that is where the carry appears, and
/// the carry is what says which low limb belongs to it.
fn limbs(func: &HighFunction, hi: ValueId, expr: &Expr) -> Option<Found> {
    // `(hi_a ± hi_b) ± carry`
    let Expr::Binary { op, lhs, rhs } = expr else {
        return None;
    };
    if !matches!(op, BinaryOp::Add | BinaryOp::Sub) {
        return None;
    }
    let carry = zero_extended(func, *rhs)?;
    let Expr::Binary { op: inner, lhs: hi_a, rhs: hi_b } =
        &func.bindings.get(resolve_use(func, *lhs))?.expr
    else {
        return None;
    };
    if inner != op {
        return None;
    }
    let (a, b) = (
        half_of(func, *hi_a, UnaryOp::WideHi)?,
        half_of(func, *hi_b, UnaryOp::WideHi)?,
    );
    // The carry: the low limbs' unsigned comparison.
    let Expr::Binary { op: BinaryOp::Lt, lhs: c_l, rhs: c_r } =
        &func.bindings.get(resolve_use(func, carry))?.expr
    else {
        return None;
    };
    // And the low limb itself, computed from the same two values.
    let lo = func.bindings.iter().find_map(|(id, bind)| {
        let Expr::Binary { op: low_op, lhs, rhs } = &bind.expr else {
            return None;
        };
        (low_op == op
            && half_of(func, *lhs, UnaryOp::WideLo) == Some(a)
            && half_of(func, *rhs, UnaryOp::WideLo) == Some(b))
        .then_some(id)
    })?;
    // For a difference the carry compares the operands' low limbs; for a
    // sum it compares the result against one of them.
    let borrow_ok = match op {
        BinaryOp::Sub => {
            half_of(func, *c_l, UnaryOp::WideLo) == Some(a)
                && half_of(func, *c_r, UnaryOp::WideLo) == Some(b)
        }
        _ => {
            resolve_use(func, *c_l) == lo
                && [a, b].contains(&half_of(func, *c_r, UnaryOp::WideLo).unwrap_or(*c_r))
        }
    };
    borrow_ok.then_some(Found { lo, hi, op: *op, a, b })
}

/// The flag behind a zero-extension, which is how a carry becomes a limb.
fn zero_extended(func: &HighFunction, value: ValueId) -> Option<ValueId> {
    match &func.bindings.get(resolve_use(func, value))?.expr {
        Expr::Unary { op: UnaryOp::ExtendU32, value } => Some(resolve_use(func, *value)),
        _ => None,
    }
}

/// The value this is the named half of.
fn half_of(func: &HighFunction, value: ValueId, want: UnaryOp) -> Option<ValueId> {
    match &func.bindings.get(resolve_use(func, value))?.expr {
        Expr::Unary { op, value } if *op == want => Some(resolve_use(func, *value)),
        _ => None,
    }
}
