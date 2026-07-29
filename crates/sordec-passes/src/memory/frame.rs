//! Shadow-stack frame identification — finding the "C stack pointer".
//!
//! WASM locals have no addresses. Anything a Rust program might borrow, and
//! anything wider than a machine word, therefore has to live in **linear
//! memory** — the module's one addressable byte array. rustc manages that
//! space itself with a *shadow stack*: a global holds the current stack
//! pointer, and every function needing scratch space brackets its body with
//!
//! ```text
//! sp = global.get G          ;; prologue
//! fp = sp - SIZE
//! global.set G, fp
//!   … body, addressing slots as fp + offset …
//! global.set G, fp + SIZE    ;; epilogue
//! ```
//!
//! None of this is in the source; it is the calling convention made
//! explicit. Recovering it is the precondition for everything else in this
//! module: once we know *which* value is the frame base, memory traffic
//! through it stops being opaque `Load`/`Store` and becomes named slots.
//!
//! Ghidra's WASM plugin does exactly this step — it detects the "C Stack
//! Pointer" global before handing the frame to Ghidra's ordinary
//! stack-variable analysis. This module is that detection; [`super::sret`]
//! and [`super::promote`] are the analysis.
//!
//! ## What it will not do
//!
//! Detection is deliberately narrow, because every consumer treats the
//! result as ground truth about which bytes belong to this function:
//!
//! - **One frame per function.** Two independent brackets would mean two
//!   base pointers to disambiguate at every access; no corpus contract does
//!   this, and guessing wrong would mix two functions' slots.
//! - **A constant frame size.** A computed size means a variable-length
//!   frame, where slot offsets are not statically known.
//! - **The base is used, or nothing is reported.** A prologue whose result
//!   feeds only the `global.set` is a frame with no slots; there is nothing
//!   to promote and reporting it would invite consumers to act on it.

use sordec_common::ValueId;
use sordec_ir::{LiftedFunction, LiftedValueDef, WasmOp};
use waffle::entity::EntityRef as _;

/// The recovered shadow-stack bracket of one function.
//
// `dead_code`-allowed while staged: [`detect`] and this type are consumed by
// `memory::promote`, which lands next and is the reason this module exists.
// Only the census test uses them today. The allow is deliberately on the
// items rather than the module, so anything *else* going unused here still
// fails the gate.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FrameLayout {
    /// Index of the global holding the stack pointer.
    pub global: u32,
    /// The frame base — `sp - size`, the value slot addresses are relative
    /// to.
    pub base: ValueId,
    /// Frame size in bytes, as reserved by the prologue.
    pub size: u32,
}

/// Recover `func`'s shadow-stack bracket, or `None` when it has none (a
/// leaf function needing no scratch space) or when the shape is not the one
/// documented above.
#[allow(dead_code)] // staged for `memory::promote`; see `FrameLayout`.
pub(crate) fn detect(func: &LiftedFunction) -> Option<FrameLayout> {
    let mut found: Option<FrameLayout> = None;

    for (id, value) in func.values.iter() {
        // The base is the subtraction, so match that and work outward.
        let LiftedValueDef::Operator { op, args } = &value.def else {
            continue;
        };
        if !is_sub(op) || args.len() != 2 {
            continue;
        }
        let Some(global) = global_get_index(func, args[0]) else {
            continue;
        };
        let Some(size) = const_u32(func, args[1]) else {
            continue;
        };
        // The reservation only counts if it is published back to the
        // global; a bare subtraction is ordinary arithmetic.
        if !is_published(func, id, global) {
            continue;
        }
        // A second bracket means two base pointers to disambiguate at every
        // access. Decline rather than pick one.
        if found.is_some() {
            return None;
        }
        found = Some(FrameLayout {
            global,
            base: id,
            size,
        });
    }
    found
}

/// The global index read by `value`, when it is a `global.get`.
#[allow(dead_code)] // staged for `memory::promote`; see `FrameLayout`.
fn global_get_index(func: &LiftedFunction, value: ValueId) -> Option<u32> {
    match &definition(func, value)? {
        LiftedValueDef::Operator { op, .. } => match &op.0 {
            waffle::Operator::GlobalGet { global_index } => Some(global_index.index() as u32),
            _ => None,
        },
        _ => None,
    }
}

/// Whether some `global.set G` publishes `base` — the half of the prologue
/// that makes the subtraction a stack-pointer reservation rather than
/// arithmetic that happens to subtract from a global.
#[allow(dead_code)] // staged for `memory::promote`; see `FrameLayout`.
fn is_published(func: &LiftedFunction, base: ValueId, global: u32) -> bool {
    func.values.iter().any(|(_, value)| {
        matches!(
            &value.def,
            LiftedValueDef::Operator { op, args }
                if global_set_index(op) == Some(global)
                    && args.first().copied() == Some(base)
        )
    })
}

/// The global index written by `op`, when it is a `global.set`.
#[allow(dead_code)] // staged for `memory::promote`; see `FrameLayout`.
fn global_set_index(op: &WasmOp) -> Option<u32> {
    match &op.0 {
        waffle::Operator::GlobalSet { global_index } => Some(global_index.index() as u32),
        _ => None,
    }
}

/// Resolve `value` to its definition, following `Alias` links.
///
/// `ResolveAliasesPass` normally flattens these, but this module runs in
/// the same fixpoint group and must not depend on having been preceded by
/// it in a given iteration.
fn definition(func: &LiftedFunction, value: ValueId) -> Option<LiftedValueDef> {
    let mut current = value;
    for _ in 0..MAX_ALIAS_HOPS {
        let def = &func.values.get(current)?.def;
        match def {
            LiftedValueDef::Alias(next) => current = *next,
            other => return Some(other.clone()),
        }
    }
    None
}

/// Defensive bound on alias chains. Real chains are one link; a cycle is
/// malformed IR, and this makes it terminate rather than hang.
const MAX_ALIAS_HOPS: u32 = 64;

/// `value` as a `u32` constant, following aliases.
///
/// Only `i32.const` counts: a WASM address is a 32-bit offset into linear
/// memory, so a 64-bit frame size is not a shape this models.
fn const_u32(func: &LiftedFunction, value: ValueId) -> Option<u32> {
    match definition(func, value)? {
        LiftedValueDef::Operator { op, .. } => match op.0 {
            waffle::Operator::I32Const { value } => Some(value),
            _ => None,
        },
        _ => None,
    }
}

#[allow(dead_code)] // staged for `memory::promote`; see `FrameLayout`.
fn is_sub(op: &WasmOp) -> bool {
    matches!(op.0, waffle::Operator::I32Sub)
}

/// Canonicalise a frame-relative address to `(base, byte offset)`.
///
/// Folds `add addr, const` chains so a caller that carves sub-frames out of
/// one reservation — `f(fp + 8)`, `g(fp + 24)` — is described in the same
/// terms as one that passes the base directly. The lifted-IR twin of
/// [`crate::dataflow::canon_addr`], which works on `HighIr`.
///
/// Total by design: an address that folds to nothing is its own base at
/// offset 0, and callers compare the base against the frame they care
/// about.
pub(crate) fn canon_addr(func: &LiftedFunction, addr: ValueId) -> (ValueId, u32) {
    let mut base = addr;
    let mut offset: u32 = 0;
    for _ in 0..MAX_ALIAS_HOPS {
        let Some(LiftedValueDef::Operator { op, args }) = definition(func, base) else {
            return (resolve_alias(func, base), offset);
        };
        if !matches!(op.0, waffle::Operator::I32Add) || args.len() != 2 {
            return (resolve_alias(func, base), offset);
        }
        // Either operand may be the constant; `fp + 8` and `8 + fp` are the
        // same address.
        let (next, delta) = match (const_u32(func, args[1]), const_u32(func, args[0])) {
            (Some(k), _) => (args[0], k),
            (None, Some(k)) => (args[1], k),
            (None, None) => return (resolve_alias(func, base), offset),
        };
        // A wrapping offset is not provably a forward displacement into the
        // frame, so stop folding and report what is proven so far.
        let Some(sum) = offset.checked_add(delta) else {
            return (resolve_alias(func, base), offset);
        };
        offset = sum;
        base = next;
    }
    (resolve_alias(func, base), offset)
}

/// Follow `Alias` links to the underlying value id.
fn resolve_alias(func: &LiftedFunction, value: ValueId) -> ValueId {
    let mut current = value;
    for _ in 0..MAX_ALIAS_HOPS {
        match func.values.get(current).map(|v| &v.def) {
            Some(LiftedValueDef::Alias(next)) => current = *next,
            _ => return current,
        }
    }
    current
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{block, func_with, i32_const, op, v};
    use sordec_ir::{LiftedTerminator, LiftedValueDef};

    fn global_get(index: u32) -> LiftedValueDef {
        op(
            waffle::Operator::GlobalGet {
                global_index: waffle::Global::from(index),
            },
            vec![],
        )
    }

    fn global_set(index: u32, value: ValueId) -> LiftedValueDef {
        op(
            waffle::Operator::GlobalSet {
                global_index: waffle::Global::from(index),
            },
            vec![value],
        )
    }

    /// The canonical prologue: `fp = global.get 0 - 16; global.set 0, fp`.
    fn framed() -> sordec_ir::LiftedFunction {
        func_with(
            vec![
                global_get(0),                                 // v0 sp
                i32_const(16),                                 // v1 size
                op(waffle::Operator::I32Sub, vec![v(0), v(1)]), // v2 fp
                global_set(0, v(2)),                           // v3
            ],
            vec![block(
                0,
                vec![],
                vec![v(0), v(1), v(2), v(3)],
                LiftedTerminator::Return { values: vec![] },
            )],
        )
    }

    #[test]
    fn the_canonical_prologue_is_recovered() {
        let layout = detect(&framed()).expect("a shadow-stack bracket");
        assert_eq!(
            layout,
            FrameLayout {
                global: 0,
                base: v(2),
                size: 16,
            }
        );
    }

    #[test]
    fn a_subtraction_never_published_is_not_a_frame() {
        // `global.get 0 - 16` with no `global.set` is arithmetic that
        // happens to read a global, not a stack reservation.
        let mut func = framed();
        func.values.get_mut(v(3)).unwrap().def = i32_const(0);
        assert!(detect(&func).is_none());
    }

    #[test]
    fn a_non_constant_frame_size_declines() {
        // A computed size means slot offsets are not statically known.
        let mut func = framed();
        func.values.get_mut(v(1)).unwrap().def = global_get(1);
        assert!(detect(&func).is_none());
    }

    #[test]
    fn a_function_with_no_frame_reports_none() {
        let func = func_with(
            vec![i32_const(1)],
            vec![block(
                0,
                vec![],
                vec![v(0)],
                LiftedTerminator::Return { values: vec![] },
            )],
        );
        assert!(detect(&func).is_none());
    }

    #[test]
    fn two_brackets_decline_rather_than_pick_one() {
        // Two base pointers would have to be disambiguated at every access.
        let func = func_with(
            vec![
                global_get(0),
                i32_const(16),
                op(waffle::Operator::I32Sub, vec![v(0), v(1)]),
                global_set(0, v(2)),
                global_get(0),
                i32_const(32),
                op(waffle::Operator::I32Sub, vec![v(4), v(5)]),
                global_set(0, v(6)),
            ],
            vec![block(
                0,
                vec![],
                (0..8).map(v).collect(),
                LiftedTerminator::Return { values: vec![] },
            )],
        );
        assert!(detect(&func).is_none(), "ambiguous frames must decline");
    }

    // --- canon_addr ---

    #[test]
    fn a_bare_base_is_its_own_address_at_offset_zero() {
        let func = framed();
        assert_eq!(canon_addr(&func, v(2)), (v(2), 0));
    }

    #[test]
    fn sub_frame_addresses_fold_to_base_plus_offset() {
        // `(fp + 8) + 16` is the frame base at byte 24 — the shape a caller
        // carving several out-parameters from one reservation produces.
        let func = func_with(
            vec![
                global_get(0),
                i32_const(64),
                op(waffle::Operator::I32Sub, vec![v(0), v(1)]), // v2 fp
                global_set(0, v(2)),
                i32_const(8),
                op(waffle::Operator::I32Add, vec![v(2), v(4)]), // v5 fp+8
                i32_const(16),
                op(waffle::Operator::I32Add, vec![v(5), v(6)]), // v7 fp+24
            ],
            vec![block(
                0,
                vec![],
                (0..8).map(v).collect(),
                LiftedTerminator::Return { values: vec![] },
            )],
        );
        assert_eq!(canon_addr(&func, v(7)), (v(2), 24));
        assert_eq!(canon_addr(&func, v(5)), (v(2), 8));
    }

    #[test]
    fn a_commuted_constant_folds_the_same_way() {
        let func = func_with(
            vec![
                global_get(0),
                i32_const(64),
                op(waffle::Operator::I32Sub, vec![v(0), v(1)]),
                global_set(0, v(2)),
                i32_const(8),
                op(waffle::Operator::I32Add, vec![v(4), v(2)]), // 8 + fp
            ],
            vec![block(
                0,
                vec![],
                (0..6).map(v).collect(),
                LiftedTerminator::Return { values: vec![] },
            )],
        );
        assert_eq!(canon_addr(&func, v(5)), (v(2), 8));
    }

    #[test]
    fn a_non_constant_displacement_stops_folding() {
        // `fp + n` where `n` is runtime-computed is not a statically known
        // slot; report the opaque address rather than inventing an offset.
        let func = func_with(
            vec![
                global_get(0),
                i32_const(64),
                op(waffle::Operator::I32Sub, vec![v(0), v(1)]),
                global_set(0, v(2)),
                global_get(1),                                 // v4 runtime
                op(waffle::Operator::I32Add, vec![v(2), v(4)]), // v5
            ],
            vec![block(
                0,
                vec![],
                (0..6).map(v).collect(),
                LiftedTerminator::Return { values: vec![] },
            )],
        );
        assert_eq!(canon_addr(&func, v(5)), (v(5), 0));
    }

    #[test]
    fn aliases_are_followed() {
        let func = func_with(
            vec![
                global_get(0),
                i32_const(16),
                op(waffle::Operator::I32Sub, vec![v(0), v(1)]),
                global_set(0, v(2)),
                LiftedValueDef::Alias(v(2)),
            ],
            vec![block(
                0,
                vec![],
                vec![v(0), v(1), v(2), v(3)],
                LiftedTerminator::Return { values: vec![] },
            )],
        );
        assert_eq!(canon_addr(&func, v(4)), (v(2), 0));
        assert_eq!(detect(&func).map(|l| l.base), Some(v(2)));
    }
}
