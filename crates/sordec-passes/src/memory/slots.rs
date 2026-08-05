//! Pointer-base aliasing analysis — the SROA half, shared.
//!
//! Both shadow-stack passes ask the same three questions about a pointer
//! before they will touch anything it addresses:
//!
//! 1. Which values *are* this pointer? (the base, its aliases, and any
//!    `add` of one with a constant)
//! 2. Does anything consume one of them that we have not accounted for?
//! 3. What does this memory operator do — load or store, how wide, at what
//!    offset?
//!
//! [`super::promote`] asks them about a **frame base**; [`super::argpromote`]
//! asks them about a **parameter**. Nothing in the analysis cares which,
//! because "an address we cannot follow may alias anything reachable from
//! it" is a property of the pointer, not of where it came from. Keeping one
//! copy is what stops the two passes disagreeing about what an escape is —
//! and they must not, because between them they decide which memory traffic
//! is safe to delete.
//!
//! ## The rule that is easy to get wrong
//!
//! Every scan here works over the **scheduled** value set, never the whole
//! arena. See [`scheduled`] for what happens otherwise; it is not a
//! micro-optimisation but the difference between 4 and 29 analysable frames
//! on one fixture.

use std::collections::HashSet;

use sordec_common::ValueId;
use sordec_ir::{LiftedFunction, LiftedTerminator, LiftedType, LiftedValueDef, WasmOp};

use super::frame::canon_addr;
use crate::dataflow::{for_each_target, CfgFacts};

/// Every value id that some reachable block actually schedules, plus the
/// block parameters.
///
/// **Every scan here works over this set, never over the whole
/// arena.** De-cluttering leaves unscheduled residue behind — alias
/// tombstones and dead phis that still name an address — and the
/// arenas are push-only, so that residue is permanent. Counting it as a use
/// made 25 of token-v23's 29 frames look like they escaped. The same
/// mistake, in its `HighIr` form, previously made every out-parameter in
/// the corpus look un-analysable.
pub(super) fn scheduled(func: &LiftedFunction, cfg: &CfgFacts) -> HashSet<ValueId> {
    let mut live: HashSet<ValueId> = HashSet::new();
    for (block_id, block) in func.blocks.iter() {
        if !cfg.is_reachable(block_id) {
            continue;
        }
        live.extend(block.instructions.iter().copied());
        live.extend(block.params.iter().copied());
    }
    live
}

/// Every value that *is* an address derived from `base`: the base
/// itself, its aliases, and any `add` of one of those with a constant.
pub(super) fn address_closure(
    func: &LiftedFunction,
    base: ValueId,
    live: &HashSet<ValueId>,
) -> HashSet<ValueId> {
    let mut closure: HashSet<ValueId> = HashSet::new();
    closure.insert(base);
    for (id, value) in func.values.iter() {
        if !live.contains(&id) {
            continue;
        }
        let derived = match &value.def {
            LiftedValueDef::Alias(from) => closure.contains(from),
            LiftedValueDef::Operator { .. } => canon_addr(func, id).0 == base,
            _ => false,
        };
        if derived {
            closure.insert(id);
        }
    }
    closure
}

/// Whether every consumer of an address derived from `base` is an access
/// we accounted for, further address arithmetic, or a frame bracket's own
/// `global.set`.
///
/// This is the aliasing gate. It is written as "what is allowed" rather
/// than "what is forbidden" so that an operator nobody thought about
/// declines instead of slipping through.
pub(super) fn addresses_only_flow_to(
    func: &LiftedFunction,
    addresses: &HashSet<ValueId>,
    accessors: &HashSet<ValueId>,
    live: &HashSet<ValueId>,
) -> bool {
    for (id, value) in func.values.iter() {
        if !live.contains(&id) || accessors.contains(&id) || addresses.contains(&id) {
            continue;
        }
        let consumes = match &value.def {
            LiftedValueDef::Operator { op, args } => {
                let mentions = args.iter().any(|a| addresses.contains(a));
                // The bracket publishes the pointer back to its global; that
                // is the frame's own bookkeeping, not an escape into code
                // that could alias a slot.
                mentions && !is_global_set(op)
            }
            LiftedValueDef::Alias(from) | LiftedValueDef::PickOutput { from, .. } => {
                addresses.contains(from)
            }
            LiftedValueDef::BlockParam { .. } => false,
        };
        if consumes {
            return false;
        }
    }
    // A frame address that leaves through a terminator escapes the function.
    !func.blocks.iter().any(|(_, block)| {
        let mut escapes = false;
        for_each_target(&block.terminator, |t| {
            escapes |= t.args.iter().any(|a| addresses.contains(a));
        });
        if let LiftedTerminator::Return { values } = &block.terminator {
            escapes |= values.iter().any(|v| addresses.contains(v));
        }
        escapes
    })
}

fn is_global_set(op: &WasmOp) -> bool {
    matches!(op.0, waffle::Operator::GlobalSet { .. })
}

/// What one memory access does.
pub(super) struct AccessShape {
    pub(super) is_store: bool,
    pub(super) width: u32,
    pub(super) memarg_offset: u32,
    pub(super) ty: LiftedType,
}

/// Classify a memory operator, or `None` for anything that is not one.
///
/// Sub-word accesses are deliberately absent. An `i64.load8_u` reads one
/// byte of a slot and sign/zero-extends it; promoting that would need the
/// slot modelled as bytes rather than as a scalar, and the corpus does not
/// contain one on a frame.
pub(super) fn access_shape(op: &WasmOp) -> Option<AccessShape> {
    let (is_store, width, ty, memarg) = match &op.0 {
        waffle::Operator::I32Load { memory } => (false, 4, LiftedType::I32, memory),
        waffle::Operator::I64Load { memory } => (false, 8, LiftedType::I64, memory),
        waffle::Operator::F32Load { memory } => (false, 4, LiftedType::F32, memory),
        waffle::Operator::F64Load { memory } => (false, 8, LiftedType::F64, memory),
        waffle::Operator::I32Store { memory } => (true, 4, LiftedType::I32, memory),
        waffle::Operator::I64Store { memory } => (true, 8, LiftedType::I64, memory),
        waffle::Operator::F32Store { memory } => (true, 4, LiftedType::F32, memory),
        waffle::Operator::F64Store { memory } => (true, 8, LiftedType::F64, memory),
        _ => return None,
    };
    Some(AccessShape {
        is_store,
        width,
        memarg_offset: memarg.offset,
        ty,
    })
}