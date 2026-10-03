//! Fold the SDK's `TryFromVal` on a storage read into a typed read.
//!
//! # The shape
//!
//! `let count: u32 = e.storage().instance().get(&COUNTER).unwrap_or(0);`
//! reads a `Val` from the host and converts it to the payload type the source
//! asked for. rustc inlines the conversion where the value arrives:
//!
//! ```text
//! g = storage_get(k)                    g = storage_get(k)   : u32
//! if !has_tag(g, U32Val) { panic!() }   →
//! n = val_decode(g)                     n = g
//! ```
//!
//! The same collapse [`super::decode`] makes for an entrypoint argument, one
//! hop later: the source wrote a typed read, not a check and an unpack.
//!
//! # Why removing the check is exact
//!
//! The trap moves; it does not go away. The reconstruction re-emits
//! `get(&k)` at the payload type, and `Storage::get::<K, u32>` runs
//! `u32::try_from_val` on the host's `Val` and traps on a mismatch — the check
//! deleted here. The same relocation argument as the argument guard, with the
//! SDK's generic `get` in place of the generated entrypoint wrapper.
//!
//! # Gates
//!
//! - **One tag, and one that is the whole encoding.** `U32Val` and `I32Val`
//!   only. A `u64` has a small and an object form and its decode tests both;
//!   a single check on one of them is not the conversion.
//! - **The read is used only by the conversion.** Every reader is the tag
//!   check or a decode. The `errors` example compares the raw `Val` against
//!   an encoded bound directly; retyping the read there would change what
//!   that comparison means, so such a read is left alone.
//! - **The check traps on a mismatch and does nothing else.** An else-less
//!   branch whose arm is a bare trap.

use std::collections::HashMap;

use sordec_common::{Provenance, ProvenanceSource, ValueId};
use sordec_ir::{Expr, HighFunction, HighIr, IrType, KnownOp, Literal, Region, SemanticOp};

use super::sret::emission_order;
use crate::dataflow::resolve_use;
use crate::metrics_catalog::MARSHALLING_TYPED_READS as M_TYPED;
use crate::pass::{Pass, PassResult};
use crate::val_abi::{small_tag_payload_type, TAG_I32_VAL, TAG_U32_VAL};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-typed-read";

/// Folds the payload conversion after a storage read into the read's type.
#[derive(Debug, Default, Clone, Copy)]
pub struct TypedReadPass;

impl Pass<HighIr> for TypedReadPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            let plans = plans(func);
            if plans.is_empty() {
                continue;
            }
            let guards: HashMap<ValueId, String> = plans
                .iter()
                .map(|p| (p.guard, "the SDK's payload type check on a storage read".to_string()))
                .collect();
            let empty = super::guard::empty_blocks(func);
            let region = std::mem::replace(&mut func.region, Region::Unreachable);
            let mut stripped = 0_i64;
            func.region = super::guard::strip(region, &guards, &empty, &mut stripped);
            for plan in plans {
                apply(func, &plan);
                result.metrics.increment(M_TYPED, 1);
                result.changed = true;
            }
        }
        result
    }
}

struct Plan {
    read: ValueId,
    /// The tag check, which is also the guard's condition.
    guard: ValueId,
    decodes: Vec<ValueId>,
    ty: sordec_ir::KnownType,
}

fn plans(func: &HighFunction) -> Vec<Plan> {
    let order = emission_order(func);
    let mut plans = Vec::new();
    for &read in &order {
        let is_read = matches!(
            func.bindings.get(read).map(|b| &b.expr),
            Some(Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet { .. })))
        );
        // A read already given its payload type has been folded.
        if !is_read || !is_val(func, read) {
            continue;
        }
        if let Some(plan) = plan(func, &order, read) {
            plans.push(plan);
        }
    }
    plans
}

/// Whether the read is still typed as a raw `Val` (or not typed at all).
fn is_val(func: &HighFunction, read: ValueId) -> bool {
    matches!(
        func.bindings.get(read).map(|b| &b.ty),
        Some(IrType::Known(sordec_ir::KnownType::Val) | IrType::Inferred(sordec_ir::KnownType::Val) | IrType::Unknown(_))
    )
}

fn plan(func: &HighFunction, order: &[ValueId], read: ValueId) -> Option<Plan> {
    let mut guard = None;
    let mut decodes = Vec::new();
    for &id in order {
        let binding = func.bindings.get(id)?;
        let mut reads_it = false;
        binding.expr.for_each_value_use(|u| reads_it |= resolve_use(func, u) == read);
        if !reads_it {
            continue;
        }
        match &binding.expr {
            Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck { tag, negated: true, .. }))
                if (*tag == TAG_U32_VAL || *tag == TAG_I32_VAL) =>
            {
                if guard.replace((id, *tag)).is_some() {
                    return None;
                }
            }
            Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { .. })) => decodes.push(id),
            // The tag byte the check was recognized from, left behind unread.
            Expr::Binary { op: sordec_ir::BinaryOp::BitAnd, .. } if uses(func, order, id) == 0 => {}
            // A comparison the packed-compare recogniser already read on the
            // payload: its other side is a decoded `u32`, so once the read is
            // typed the two agree.
            Expr::Binary { op, lhs, rhs }
                if matches!(
                    op,
                    sordec_ir::BinaryOp::Lt
                        | sordec_ir::BinaryOp::Le
                        | sordec_ir::BinaryOp::Gt
                        | sordec_ir::BinaryOp::Ge
                        | sordec_ir::BinaryOp::Eq
                        | sordec_ir::BinaryOp::Ne
                ) && [*lhs, *rhs].iter().any(|v| {
                    matches!(
                        func.bindings.get(resolve_use(func, *v)).map(|b| &b.expr),
                        Some(Expr::Literal(Literal::U32(_)))
                    )
                }) => {}
            // A rename is not a reader: an inlined wrapper hands the read back
            // through one, and what reads *it* is found here already, through
            // `resolve_use`.
            Expr::Use(_) => {}
            _ => return None,
        }
    }
    let mut region_reads = 0;
    func.region.for_each_value_use(|u| region_reads += usize::from(resolve_use(func, u) == read));
    if region_reads != 0 || decodes.is_empty() {
        return None;
    }
    let (guard, tag) = guard?;
    // The check is read by exactly one branch, and that branch is the trap.
    if uses(func, order, guard) != 1 || !traps_on(func, &func.region, guard) {
        return None;
    }
    Some(Plan { read, guard, decodes, ty: small_tag_payload_type(tag)? })
}

/// Reads of `value` by scheduled bindings and the region tree.
fn uses(func: &HighFunction, order: &[ValueId], value: ValueId) -> usize {
    let mut n = 0;
    for id in order {
        if let Some(b) = func.bindings.get(*id) {
            b.expr.for_each_value_use(|u| n += usize::from(u == value));
        }
    }
    func.region.for_each_value_use(|u| n += usize::from(u == value));
    n
}

/// Whether `region` holds `if cond { <bare trap> }` with no else.
fn traps_on(func: &HighFunction, region: &Region, cond: ValueId) -> bool {
    let empty = super::guard::empty_blocks(func);
    let mut found = false;
    region.for_each_node(|node| {
        if let Region::If { cond: c, then_region, else_region: None } = node
            && *c == cond
            && super::guard::is_trap(then_region, &empty)
        {
            found = true;
        }
    });
    found
}

fn apply(func: &mut HighFunction, plan: &Plan) {
    for &d in &plan.decodes {
        if let Some(b) = func.bindings.get_mut(d) {
            b.expr = Expr::Use(plan.read);
            b.ty = IrType::Known(plan.ty.clone());
            b.add_provenance(Provenance::new(
                PASS_NAME,
                ProvenanceSource::SdkPattern,
                "payload decode of a typed storage read: the read's own value",
            ));
        }
    }
    if let Some(b) = func.bindings.get_mut(plan.guard) {
        b.expr = Expr::Literal(Literal::Unit);
        b.ty = IrType::Known(sordec_ir::KnownType::Unit);
        b.add_provenance(Provenance::new(
            PASS_NAME,
            ProvenanceSource::SdkPattern,
            "payload type check of a storage read, regenerated by the typed `get`",
        ));
    }
    if let Some(b) = func.bindings.get_mut(plan.read) {
        b.ty = IrType::Known(plan.ty.clone());
        b.add_provenance(Provenance::new(
            PASS_NAME,
            ProvenanceSource::SdkPattern,
            "typed storage read: the SDK's TryFromVal on the payload folded in",
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};
    use sordec_common::{BlockId, IrId};
    use sordec_ir::{KnownTier, KnownType, Missing, PanicKind, StorageTier};

    /// `g = get(k); t = !has_tag(g, U32Val); if t { panic }; n = decode(g)`
    /// plus, when `raw_use`, a comparison against the raw `Val`.
    fn shape(raw_use: bool) -> HighFunction {
        let mut exprs = vec![
            Expr::Phi { incoming: vec![] }, // v0 key
            Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet {
                tier: StorageTier::Known(KnownTier::Instance),
                durability: v(0),
                key: v(0),
                resolved_key: None,
                missing: Missing::Option,
            })), // v1
            Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck { value: v(1), tag: TAG_U32_VAL, negated: true })), // v2
            Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { value: v(1) })), // v3
        ];
        let mut sched = vec![1, 2, 3];
        if raw_use {
            exprs.push(Expr::Literal(Literal::I64(5 << 32))); // v4
            exprs.push(Expr::Binary { op: sordec_ir::BinaryOp::Ge, lhs: v(1), rhs: v(4) }); // v5
            sched.push(5);
        }
        let mut f = func_with(exprs, vec![v(0)], sched);
        f.region = Region::Sequence(vec![
            Region::Basic(BlockId::from_index(0)),
            Region::If {
                cond: v(2),
                then_region: Box::new(Region::Panic { kind: PanicKind::Bare }),
                else_region: None,
            },
            Region::Return { values: vec![v(3)] },
        ]);
        f
    }

    #[test]
    fn a_checked_decode_of_a_read_becomes_a_typed_read() {
        let mut m = module(vec![shape(false)]);
        let r = TypedReadPass.run(&mut m);
        assert!(r.changed);
        let f = &m.functions[0];
        assert!(matches!(f.bindings.get(v(3)).unwrap().expr, Expr::Use(r) if r == v(1)));
        assert_eq!(f.bindings.get(v(1)).unwrap().ty, IrType::Known(KnownType::U32));
        let mut ifs = 0;
        f.region.for_each_node(|n| ifs += usize::from(matches!(n, Region::If { .. })));
        assert_eq!(ifs, 0, "the check is gone");
    }

    /// A read also compared as a raw `Val` keeps its `Val` type.
    #[test]
    fn a_read_used_as_a_raw_val_is_left_alone() {
        let mut m = module(vec![shape(true)]);
        assert!(!TypedReadPass.run(&mut m).changed);
    }

    #[test]
    fn the_pass_is_idempotent() {
        let mut m = module(vec![shape(false)]);
        assert!(TypedReadPass.run(&mut m).changed);
        assert!(!TypedReadPass.run(&mut m).changed);
    }
}
