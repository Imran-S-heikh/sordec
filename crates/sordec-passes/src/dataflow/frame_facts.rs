//! Block-local memory-slot tracking over `HighIr`.
//!
//! rustc routinely threads constants recognizers need through the
//! *shadow stack*: a caller stores an enum discriminant (and payload)
//! into its frame, then passes a pointer to a shared helper — the
//! [`Resolver`](super::Resolver)'s register-level channels never see
//! it. This module is the missing memory channel, deliberately scoped
//! to what is provable **without a CFG** (HighIr carries no block
//! terminators until Phase 3 structuring): facts hold within a single
//! basic block, whose binding list is documented execution order.
//!
//! ## Soundness rules (each guards a concrete wrong-answer hole)
//!
//! - **Address canonicalization** ([`canon_addr`]): a pointer is
//!   `(base, constant offset)` where only `Add`-with-constant folds;
//!   every other terminal (including `Sub` — the frame-pointer
//!   computation itself) is an opaque base. Two addresses are proven
//!   non-aliasing only when they share the same SSA base with disjoint
//!   ranges.
//! - **Kill discipline** ([`facts_before`]): a store to a *different*
//!   base may alias ours → kill everything. Any direct or indirect
//!   call may write through an escaped pointer → kill. An unrecognized
//!   host call → kill. A recognized host op kills iff it is one of the
//!   linear-memory writers (`*_copy_to_linear_memory`,
//!   `*_unpack_to_linear_memory`). Raw WASM operators kill by
//!   [`WasmOpcodeKind`] class, matched exhaustively so a new class
//!   forces an explicit decision here; unclassified (`Other`) kills.
//! - **Width discipline**: a fact records the store's exact byte range
//!   ([`MemWidth`] from S1); queries must match offset *and* width
//!   exactly. Overlapping stores clear whatever they touch.
//! - **Position discipline**: facts are computed strictly *before* the
//!   query binding. If the query binding is not in the given block the
//!   result is empty — never facts from the wrong position.

use std::collections::BTreeMap;

use sordec_common::{BlockId, IrId, ValueId};
use sordec_ir::{BinaryOp, Expr, HighBlock, HighFunction, MemWidth};

use super::high::{resolve_use, trace_int};

/// Recursion bound for [`canon_addr`]'s `Add`-chain folding. Real
/// pointer arithmetic chains are one or two links deep.
const CANON_DEPTH: u32 = 32;

/// One tracked memory slot: the SSA value a store put there, plus the
/// store's exact byte width. Consumers resolve the value through the
/// existing tracers ([`trace_int`], the [`Resolver`](super::Resolver))
/// — the fact layer records *which value*, not *which constant*, so
/// payload slots (runtime addresses) are as queryable as discriminants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotFact {
    /// Byte width of the store that produced this fact.
    pub width: MemWidth,
    /// The stored SSA value (as written — callers `resolve_use` it).
    pub value: ValueId,
}

/// Facts about one pointer base at one program point, keyed by byte
/// offset from the base.
#[derive(Debug, Clone, Default)]
pub struct FrameFacts {
    slots: BTreeMap<u32, SlotFact>,
}

impl FrameFacts {
    /// The value stored at exactly `[offset, offset + width)`, or
    /// `None` when no fact covers that precise range (width mismatch is
    /// a miss, never a reinterpretation).
    #[must_use]
    pub fn value_at(&self, offset: u32, width: MemWidth) -> Option<ValueId> {
        match self.slots.get(&offset) {
            Some(fact) if fact.width == width => Some(fact.value),
            _ => None,
        }
    }

    /// Like [`value_at`](Self::value_at), but additionally accepts a
    /// **wider** store at the same offset — a little-endian truncating
    /// read (WASM memory is little-endian, so the low bytes of a wider
    /// store sit exactly where a narrower load at the same offset
    /// reads). CAVEAT: the returned value is the *full* stored value;
    /// the runtime reads its truncation. Callers must range-check the
    /// resolved constant so that any value truncation would change
    /// fails their gate instead of being misread.
    #[must_use]
    pub fn value_at_trunc(&self, offset: u32, width: MemWidth) -> Option<ValueId> {
        match self.slots.get(&offset) {
            Some(fact) if fact.width.bytes() >= width.bytes() => Some(fact.value),
            _ => None,
        }
    }

    /// All facts in ascending offset order.
    pub fn iter(&self) -> impl Iterator<Item = (u32, SlotFact)> + '_ {
        self.slots.iter().map(|(off, fact)| (*off, *fact))
    }

    /// Whether any fact exists at `offset` or beyond (the enum-key
    /// pass's payload-footprint probe).
    #[must_use]
    pub fn any_at_or_after(&self, offset: u32) -> bool {
        self.slots.range(offset..).next().is_some()
    }

    /// Record a store at `[offset, offset + width)`, clearing every
    /// fact whose byte range overlaps the new one.
    fn record(&mut self, offset: u32, width: MemWidth, value: ValueId) {
        let new_end = u64::from(offset) + u64::from(width.bytes());
        self.slots.retain(|other_off, other| {
            let other_end = u64::from(*other_off) + u64::from(other.width.bytes());
            u64::from(*other_off) >= new_end || other_end <= u64::from(offset)
        });
        self.slots.insert(offset, SlotFact { width, value });
    }

    fn kill_all(&mut self) {
        self.slots.clear();
    }
}

/// Canonicalize an address operand to `(base, constant byte offset)`.
///
/// Folds `Add`-with-constant chains through `Use` links; every other
/// terminal — `Sub`, `Phi`, parameters, loads, overflowing chains — is
/// its own opaque base at offset 0. Total by design: an address that
/// resolves to "some opaque SSA value" is still a valid base identity,
/// and the kill discipline handles bases that don't match. Negative or
/// non-`u32` "constants" do not fold (the operand is then not provably
/// a forward offset).
#[must_use]
pub fn canon_addr(func: &HighFunction, addr: ValueId) -> (ValueId, u32) {
    let mut current = addr;
    let mut offset: u32 = 0;
    for _ in 0..CANON_DEPTH {
        let terminal = resolve_use(func, current);
        if (terminal.index() as usize) >= func.bindings.len() {
            return (terminal, offset);
        }
        let Some(binding) = func.bindings.get(terminal) else {
            return (terminal, offset);
        };
        let Expr::Binary {
            op: BinaryOp::Add,
            lhs,
            rhs,
        } = &binding.expr
        else {
            return (terminal, offset);
        };
        // Fold whichever operand is a provable u32 constant; an Add
        // with no constant operand is an opaque base.
        let folded = [(lhs, rhs), (rhs, lhs)].into_iter().find_map(|(k, rest)| {
            let konst = u32::try_from(trace_int(func, *k)?).ok()?;
            let total = offset.checked_add(konst)?;
            Some((*rest, total))
        });
        match folded {
            Some((rest, total)) => {
                offset = total;
                current = rest;
            }
            None => return (terminal, offset),
        }
    }
    // Chain deeper than any real pointer arithmetic: opaque base,
    // dropping the partial offset would conflate distinct addresses, so
    // keep what was folded and stop.
    (resolve_use(func, current), offset)
}

/// The block whose scheduled binding list contains `value`, if any.
/// (Unscheduled bindings — block params, aliases — belong to no block.)
#[must_use]
pub fn block_containing(func: &HighFunction, value: ValueId) -> Option<BlockId> {
    func.blocks
        .iter()
        .find(|(_, block)| block.bindings.contains(&value))
        .map(|(id, _)| id)
}

/// Compute the facts about `base` visible immediately before `at`
/// within `block`, by a forward scan of the block's binding list
/// applying the module-level kill discipline. Empty if `at` is not
/// scheduled in `block`.
#[must_use]
pub fn facts_before(
    func: &HighFunction,
    block: &HighBlock,
    at: ValueId,
    base: ValueId,
) -> FrameFacts {
    let mut facts = FrameFacts::default();
    for &id in &block.bindings {
        if id == at {
            return facts;
        }
        let Some(binding) = func.bindings.get(id) else {
            // Malformed schedule entry: fail closed.
            facts.kill_all();
            continue;
        };
        if let Expr::Store {
            addr,
            value,
            offset,
            width,
        } = &binding.expr
        {
            let (store_base, addr_off) = canon_addr(func, *addr);
            match u32::checked_add(addr_off, *offset) {
                Some(total) if store_base == base => facts.record(total, *width, *value),
                // Different base (may alias) or offset overflow:
                // fail closed.
                _ => facts.kill_all(),
            }
        } else if may_write_memory(&binding.expr) {
            facts.kill_all();
        }
    }
    // `at` was never reached: the query position is not in this block,
    // so no computed fact is positionally valid.
    FrameFacts::default()
}

/// Whether an expression may write linear memory — the module's shared
/// kill predicate (stores are handled separately by [`facts_before`],
/// which needs their address; this classifies everything else).
/// Fail-closed: unrecognized host calls, any call, and uncategorised
/// raw operators all count as writers.
///
/// Delegates to the [`crate::effects`] classification table (which
/// absorbed this module's original per-`KnownOp` and per-opcode-kind
/// write predicates — the INVARIANT that a new `KnownOp` variant must
/// declare its guest-memory behaviour now lives on
/// [`crate::effects::known_op_effects`]'s exhaustive match). Notably a
/// `GlobalSet` still does NOT kill: it writes a *global*, not linear
/// memory — the axes are separate — which is what lets the
/// shadow-stack-pointer adjust precede a tracked store without
/// poisoning the scan.
#[must_use]
pub fn may_write_memory(expr: &Expr) -> bool {
    crate::effects::expr_effects(expr).writes_memory
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{Arena, FuncId, Provenance, ProvenanceSource, UnknownReason};
    use sordec_ir::{
        Binding, BufOpKind, IrType, KnownOp, Literal, Region, SemanticOp, WasmOpcodeKind,
    };

    /// Build a one-block function whose bindings are `exprs` at ids
    /// 0..N, **all scheduled in bb0 in order** (unlike the tracer-test
    /// builders, position matters here).
    fn func_with_block(exprs: Vec<Expr>) -> HighFunction {
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        let mut scheduled = Vec::new();
        for expr in exprs {
            let id = ValueId::from_index(bindings.len() as u32);
            bindings.push(Binding::new(
                id,
                IrType::Unknown(UnknownReason::InsufficientEvidence),
                expr,
                Provenance::new("test", ProvenanceSource::DataFlow, "seed"),
            ));
            scheduled.push(id);
        }
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        blocks.push(HighBlock {
            id: BlockId::from_index(0),
            bindings: scheduled,
        });
        HighFunction {
            id: FuncId::from_index(0),
            name: None,
            signature: None,
            blocks,
            bindings,
            region: Region::Unreachable,
            params: vec![],
            returns: vec![],
        }
    }

    fn v(i: u32) -> ValueId {
        ValueId::from_index(i)
    }

    fn i64c(n: i64) -> Expr {
        Expr::Literal(Literal::I64(n))
    }

    fn i32c(n: i32) -> Expr {
        Expr::Literal(Literal::I32(n))
    }

    fn store(addr: u32, value: u32, offset: u32, width: MemWidth) -> Expr {
        Expr::Store {
            addr: v(addr),
            value: v(value),
            offset,
            width,
        }
    }

    fn add(lhs: u32, rhs: u32) -> Expr {
        Expr::Binary {
            op: BinaryOp::Add,
            lhs: v(lhs),
            rhs: v(rhs),
        }
    }

    fn call(target: u32, args: Vec<ValueId>) -> Expr {
        Expr::Call {
            target: FuncId::from_index(target),
            args,
        }
    }

    fn facts(func: &HighFunction, at: u32, base: u32) -> FrameFacts {
        let block_id = block_containing(func, v(at)).expect("query binding scheduled");
        facts_before(func, func.blocks.get(block_id).unwrap(), v(at), v(base))
    }

    // --- the corpus shape ---

    #[test]
    fn discriminant_store_visible_at_call() {
        // v0 = base (opaque); v1 = 3i64; v2 = store v0 <- v1 offset=8;
        // v3 = add v0, 8; v4 = call f9(v3)
        let func = func_with_block(vec![
            Expr::Phi { incoming: vec![] },
            i64c(3),
            store(0, 1, 8, MemWidth::W8),
            i32c(8),
            add(0, 3),
            call(9, vec![v(4)]),
        ]);
        let f = facts(&func, 5, 0);
        assert_eq!(f.value_at(8, MemWidth::W8), Some(v(1)));
        // The pointer arg canonicalizes to the same base at offset 8.
        assert_eq!(canon_addr(&func, v(4)), (v(0), 8));
    }

    #[test]
    fn store_through_folded_pointer_lands_at_folded_offset() {
        // v2 = add v0, 8; v3 = store v2 <- v1 offset=4  → fact at 12.
        let func = func_with_block(vec![
            Expr::Phi { incoming: vec![] },
            i64c(7),
            i32c(8),
            add(0, 2),
            store(3, 1, 4, MemWidth::W8),
            call(9, vec![]),
        ]);
        // Query before the call (which kills) is position 5; the call
        // itself is the killer, so query AT the call: facts stop there.
        let f = facts(&func, 5, 0);
        assert_eq!(f.value_at(12, MemWidth::W8), Some(v(1)));
    }

    // --- record/overwrite/overlap ---

    #[test]
    fn later_store_overwrites_same_slot() {
        let func = func_with_block(vec![
            Expr::Phi { incoming: vec![] },
            i64c(1),
            i64c(2),
            store(0, 1, 0, MemWidth::W8),
            store(0, 2, 0, MemWidth::W8),
            call(9, vec![]),
        ]);
        assert_eq!(facts(&func, 5, 0).value_at(0, MemWidth::W8), Some(v(2)));
    }

    #[test]
    fn overlapping_store_clears_previous_fact() {
        // W8 at 8, then W4 at 12 (overlaps [8,16)): the W8 fact must go.
        let func = func_with_block(vec![
            Expr::Phi { incoming: vec![] },
            i64c(1),
            i32c(2),
            store(0, 1, 8, MemWidth::W8),
            store(0, 2, 12, MemWidth::W4),
            call(9, vec![]),
        ]);
        let f = facts(&func, 5, 0);
        assert_eq!(f.value_at(8, MemWidth::W8), None);
        assert_eq!(f.value_at(12, MemWidth::W4), Some(v(2)));
    }

    #[test]
    fn width_mismatch_is_a_miss() {
        let func = func_with_block(vec![
            Expr::Phi { incoming: vec![] },
            i64c(1),
            store(0, 1, 0, MemWidth::W8),
            call(9, vec![]),
        ]);
        assert_eq!(facts(&func, 3, 0).value_at(0, MemWidth::W4), None);
    }

    #[test]
    fn disjoint_same_base_stores_coexist() {
        let func = func_with_block(vec![
            Expr::Phi { incoming: vec![] },
            i64c(1),
            i64c(2),
            store(0, 1, 0, MemWidth::W8),
            store(0, 2, 8, MemWidth::W8),
            call(9, vec![]),
        ]);
        let f = facts(&func, 5, 0);
        assert_eq!(f.value_at(0, MemWidth::W8), Some(v(1)));
        assert_eq!(f.value_at(8, MemWidth::W8), Some(v(2)));
        assert!(f.any_at_or_after(8));
        assert!(!f.any_at_or_after(16));
    }

    // --- kill discipline ---

    #[test]
    fn store_to_different_base_kills_all() {
        let func = func_with_block(vec![
            Expr::Phi { incoming: vec![] }, // v0: tracked base
            Expr::Phi { incoming: vec![] }, // v1: some other pointer
            i64c(3),
            store(0, 2, 0, MemWidth::W8),
            store(1, 2, 64, MemWidth::W8), // may alias v0's frame
            call(9, vec![]),
        ]);
        assert_eq!(facts(&func, 5, 0).value_at(0, MemWidth::W8), None);
    }

    #[test]
    fn intervening_call_kills_all() {
        let func = func_with_block(vec![
            Expr::Phi { incoming: vec![] },
            i64c(3),
            store(0, 1, 0, MemWidth::W8),
            call(7, vec![]), // may write through any escaped pointer
            call(9, vec![]),
        ]);
        assert_eq!(facts(&func, 4, 0).value_at(0, MemWidth::W8), None);
    }

    #[test]
    fn facts_stop_at_query_position() {
        // A store AFTER the query binding must not be visible.
        let func = func_with_block(vec![
            Expr::Phi { incoming: vec![] },
            i64c(3),
            call(9, vec![]),
            store(0, 1, 0, MemWidth::W8),
        ]);
        assert_eq!(facts(&func, 2, 0).value_at(0, MemWidth::W8), None);
    }

    #[test]
    fn unscheduled_query_yields_no_facts() {
        let func = func_with_block(vec![
            Expr::Phi { incoming: vec![] },
            i64c(3),
            store(0, 1, 0, MemWidth::W8),
        ]);
        // v99 is in no block.
        let block = func.blocks.get(BlockId::from_index(0)).unwrap();
        let f = facts_before(&func, block, v(99), v(0));
        assert_eq!(f.value_at(0, MemWidth::W8), None);
    }

    #[test]
    fn unknown_host_call_kills_but_known_nonwriter_keeps() {
        let keep = Expr::Semantic(SemanticOp::Known(KnownOp::GetLedgerSequence));
        let kill = Expr::Semantic(SemanticOp::Unknown {
            host_module: "l".into(),
            host_fn: "_".into(),
            args: vec![],
            reason: UnknownReason::UnrecognizedHostCall {
                module: "l".into(),
                name: "_".into(),
            },
        });
        let func = func_with_block(vec![
            Expr::Phi { incoming: vec![] },
            i64c(3),
            store(0, 1, 0, MemWidth::W8),
            keep,
            call(9, vec![]),
        ]);
        assert_eq!(facts(&func, 4, 0).value_at(0, MemWidth::W8), Some(v(1)));

        let func = func_with_block(vec![
            Expr::Phi { incoming: vec![] },
            i64c(3),
            store(0, 1, 0, MemWidth::W8),
            kill,
            call(9, vec![]),
        ]);
        assert_eq!(facts(&func, 4, 0).value_at(0, MemWidth::W8), None);
    }

    #[test]
    fn linear_memory_writer_host_op_kills() {
        let writer = Expr::Semantic(SemanticOp::Known(KnownOp::BufOp {
            kind: BufOpKind::BytesCopyToLinearMemory,
            args: vec![],
        }));
        let func = func_with_block(vec![
            Expr::Phi { incoming: vec![] },
            i64c(3),
            store(0, 1, 0, MemWidth::W8),
            writer,
            call(9, vec![]),
        ]);
        assert_eq!(facts(&func, 4, 0).value_at(0, MemWidth::W8), None);
    }

    #[test]
    fn global_set_keeps_but_uncategorised_kills() {
        let global_set = Expr::Unknown {
            op_kind: WasmOpcodeKind::GlobalSet,
            args: vec![],
            reason: UnknownReason::UnsupportedPattern,
        };
        let other = Expr::Unknown {
            op_kind: WasmOpcodeKind::Other,
            args: vec![],
            reason: UnknownReason::UnsupportedPattern,
        };
        let func = func_with_block(vec![
            Expr::Phi { incoming: vec![] },
            i64c(3),
            global_set,
            store(0, 1, 0, MemWidth::W8),
            other,
            call(9, vec![]),
        ]);
        // GlobalSet before the store: harmless. `Other` after: kills.
        assert_eq!(facts(&func, 5, 0).value_at(0, MemWidth::W8), None);

        let func = func_with_block(vec![
            Expr::Phi { incoming: vec![] },
            i64c(3),
            Expr::Unknown {
                op_kind: WasmOpcodeKind::GlobalSet,
                args: vec![],
                reason: UnknownReason::UnsupportedPattern,
            },
            store(0, 1, 0, MemWidth::W8),
            call(9, vec![]),
        ]);
        assert_eq!(facts(&func, 4, 0).value_at(0, MemWidth::W8), Some(v(1)));
    }

    // --- canon_addr ---

    #[test]
    fn canon_addr_folds_nested_adds_through_uses() {
        // v3 = add v0, 8; v4 = Use(v3); v6 = add v4, 4 → (v0, 12)
        let func = func_with_block(vec![
            Expr::Phi { incoming: vec![] },
            i32c(8),
            i32c(4),
            add(0, 1),
            Expr::Use(v(3)),
            i64c(0),
            add(4, 2),
        ]);
        assert_eq!(canon_addr(&func, v(6)), (v(0), 12));
    }

    #[test]
    fn canon_addr_add_without_const_is_opaque_base() {
        // v2 = add v0, v1 (both non-const) → the Add itself is the base.
        let func = func_with_block(vec![
            Expr::Phi { incoming: vec![] },
            Expr::Phi { incoming: vec![] },
            add(0, 1),
        ]);
        assert_eq!(canon_addr(&func, v(2)), (v(2), 0));
    }

    #[test]
    fn canon_addr_sub_is_opaque_base() {
        // The frame-pointer computation `sub sp, N` must stay a base —
        // folding it would need negative offsets.
        let func = func_with_block(vec![
            Expr::Phi { incoming: vec![] },
            i32c(80),
            Expr::Binary {
                op: BinaryOp::Sub,
                lhs: v(0),
                rhs: v(1),
            },
        ]);
        assert_eq!(canon_addr(&func, v(2)), (v(2), 0));
    }

    #[test]
    fn canon_addr_negative_const_is_opaque() {
        let func = func_with_block(vec![
            Expr::Phi { incoming: vec![] },
            i32c(-8),
            add(0, 1),
        ]);
        assert_eq!(canon_addr(&func, v(2)), (v(2), 0));
    }

    #[test]
    fn block_containing_finds_scheduled_and_rejects_unscheduled() {
        let func = func_with_block(vec![i64c(1)]);
        assert_eq!(block_containing(&func, v(0)), Some(BlockId::from_index(0)));
        assert_eq!(block_containing(&func, v(9)), None);
    }
}
