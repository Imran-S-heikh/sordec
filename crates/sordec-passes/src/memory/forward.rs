//! Store-to-load forwarding, within one block.
//!
//! A load of an address a store just wrote is a read of a value already in
//! hand. Binding it to that value is textbook local redundant-load
//! elimination — LLVM does it in GVN, Ghidra in its heritage pass — and
//! here it discharges the mechanism [`super::argpromote`] depends on:
//!
//! ```text
//! store fp+0 <- k                store fp+0 <- k
//! store fp+8 <- v                store fp+8 <- v
//! a = load fp+0            →     call f(y, k, v)
//! b = load fp+8
//! call f(y, a, b)
//! ```
//!
//! ## Why this is not [`super::promote`]'s job
//!
//! `promote` answers a strictly harder question — "what is in this slot at
//! every point in the function" — and to do it soundly it must first prove
//! the frame never escapes. It declines a frame **whole**, so a single
//! surviving escape costs every slot in it. Measured on the corpus, that
//! left 24 of token-v23's 29 frames unpromotable, and every load in them
//! rendered as a hole.
//!
//! This pass asks a much smaller question that needs no escape analysis at
//! all: *between this store and this load, could anything have written
//! these bytes?* Inside one block that is answerable by inspection, so the
//! forwarding happens on frames `promote` will never touch. The two are
//! complements, not alternatives — `promote` removes the traffic, this
//! removes the *reads* whether or not the traffic can go.
//!
//! ## The aliasing rule, and where it is deliberately blunt
//!
//! Availability is keyed by `(base, offset)` where `base` is
//! [`canon_addr`]'s canonical pointer value. Two entries are known
//! disjoint only when they share a base and their byte ranges do not
//! overlap — same pointer, comparable offsets, no reasoning required.
//!
//! Everything else invalidates:
//!
//! - **A store under a different base kills every entry.** Two distinct
//!   `ValueId`s may well hold the same pointer, and nothing here proves
//!   they do not. Treating "different base" as "might alias" is the safe
//!   direction of that ignorance; treating it as "disjoint" would be a
//!   guess about memory layout.
//! - **A call, an indirect call, or a bulk-memory operator kills
//!   everything.** A callee may hold a pointer into this frame — indeed
//!   the whole reason `promote` declines these frames is that one does.
//! - **A store whose address is not a plain offset from its base kills
//!   everything**, for the same reason as the first case.
//!
//! The result is that a forward only ever happens when the intervening
//! instructions provably cannot have touched the bytes, which is why this
//! needs none of the gates its neighbours do.
//!
//! ## What it leaves behind, and who removes it
//!
//! The store. `SweepDeadPass` keeps every store by design — "every call,
//! store, or global write is observable" — so a store whose only reader
//! this pass just retired would linger as a hole. That is why
//! [`super::promote`] now also removes stores to a slot nothing loads,
//! which it can do soundly for the one case that matters: a frame it has
//! already proved does not escape cannot have those bytes observed by
//! anyone. Without that companion change this pass would trade a load hole
//! for a store hole on exactly the frames `promote` does handle.

use std::collections::HashMap;

use sordec_common::ValueId;
use sordec_ir::{LiftedFunction, LiftedIr, LiftedType, LiftedValueDef, WasmOp};

use super::frame::canon_addr;
use super::slots::access_shape;
use crate::dataflow::CfgFacts;
use crate::metrics_catalog::MEMORY_LOADS_FORWARDED_LOCALLY;
use crate::pass::{Pass, PassResult};

/// Unique pipeline name of this pass.
pub const PASS_NAME: &str = "memory-store-to-load-forward";

/// What is known to be at one address.
#[derive(Debug, Clone, Copy)]
struct Available {
    /// The value the store wrote.
    value: ValueId,
    /// Access width in bytes, so a narrower or wider read declines.
    width: u32,
    /// Value type, so a reinterpreting read declines.
    ty: LiftedType,
}

/// Binds a load to the value a preceding store in the same block wrote.
#[derive(Debug, Default, Clone, Copy)]
pub struct StoreForwardPass;

impl Pass<LiftedIr> for StoreForwardPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut LiftedIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            let forwarded = forward_in_function(func);
            if forwarded > 0 {
                result.changed = true;
                result
                    .metrics
                    .increment(MEMORY_LOADS_FORWARDED_LOCALLY, forwarded);
            }
        }
        result
    }
}

/// Forward within every reachable block, returning how many loads were
/// bound.
fn forward_in_function(func: &mut LiftedFunction) -> i64 {
    let cfg = CfgFacts::build(func);
    let blocks: Vec<_> = func
        .blocks
        .iter()
        .map(|(id, _)| id)
        .filter(|id| cfg.is_reachable(*id))
        .collect();

    let mut forwarded = 0i64;
    for block_id in blocks {
        let Some(block) = func.blocks.get(block_id) else {
            continue;
        };
        let instructions = block.instructions.clone();
        // `(base, offset) → what is there`. Availability is per block: a
        // predecessor's stores are not tracked, because proving they reach
        // is the dataflow problem `promote` solves and this pass avoids.
        let mut available: HashMap<(ValueId, u32), Available> = HashMap::new();
        let mut rewrites: Vec<(ValueId, ValueId)> = Vec::new();

        for id in instructions {
            let Some(value) = func.values.get(id) else {
                continue;
            };
            let LiftedValueDef::Operator { op, args } = &value.def else {
                continue;
            };
            let Some(shape) = access_shape(op) else {
                // Not a memory access. Anything that could write memory
                // some other way invalidates everything we know.
                if clobbers_memory(op) {
                    available.clear();
                }
                continue;
            };
            let Some(&addr) = args.first() else {
                available.clear();
                continue;
            };
            let (base, delta) = canon_addr(func, addr);
            let Some(offset) = delta.checked_add(shape.memarg_offset) else {
                available.clear();
                continue;
            };

            if shape.is_store {
                let Some(&stored) = args.get(1) else {
                    available.clear();
                    continue;
                };
                invalidate(&mut available, base, offset, shape.width);
                available.insert(
                    (base, offset),
                    Available {
                        value: stored,
                        width: shape.width,
                        ty: shape.ty,
                    },
                );
            } else if let Some(entry) = available.get(&(base, offset))
                && entry.width == shape.width
                && entry.ty == shape.ty
            {
                // The load reads exactly the bytes the store wrote, and
                // nothing since could have changed them.
                rewrites.push((id, entry.value));
            }
        }

        // The arena is push-only, so a retired load becomes an `Alias`
        // tombstone its readers still name — the established shape, which
        // is why this pass belongs inside `ResolveAliasesPass`'s group.
        for (load, value) in &rewrites {
            if let Some(target) = func.values.get_mut(*load) {
                target.def = LiftedValueDef::Alias(*value);
            }
        }
        if !rewrites.is_empty() {
            let retired: Vec<ValueId> = rewrites.iter().map(|(load, _)| *load).collect();
            if let Some(block) = func.blocks.get_mut(block_id) {
                block.instructions.retain(|id| !retired.contains(id));
            }
            forwarded += rewrites.len() as i64;
        }
    }
    forwarded
}

/// Drop every entry a store of `width` bytes at `(base, offset)` could have
/// changed.
///
/// Under the same base, overlap is decidable: the offsets are displacements
/// from one pointer. Under any other base it is not, so those entries go
/// unconditionally.
fn invalidate(
    available: &mut HashMap<(ValueId, u32), Available>,
    base: ValueId,
    offset: u32,
    width: u32,
) {
    let start = u64::from(offset);
    let end = start + u64::from(width);
    available.retain(|(entry_base, entry_offset), entry| {
        if *entry_base != base {
            return false;
        }
        let entry_start = u64::from(*entry_offset);
        let entry_end = entry_start + u64::from(entry.width);
        // Keep only what the store provably did not touch.
        entry_end <= start || entry_start >= end
    });
}

/// Whether an operator may write linear memory by some route this pass does
/// not model.
///
/// Written as "what is known safe" so an operator nobody considered
/// invalidates rather than slipping through.
fn clobbers_memory(op: &WasmOp) -> bool {
    use waffle::Operator as O;
    !matches!(
        op.0,
        O::I32Const { .. }
            | O::I64Const { .. }
            | O::F32Const { .. }
            | O::F64Const { .. }
            | O::I32Add
            | O::I32Sub
            | O::I32Mul
            | O::I32And
            | O::I32Or
            | O::I32Xor
            | O::I32Shl
            | O::I32ShrU
            | O::I32ShrS
            | O::I64Add
            | O::I64Sub
            | O::I64Mul
            | O::I64And
            | O::I64Or
            | O::I64Xor
            | O::I64Shl
            | O::I64ShrU
            | O::I64ShrS
            | O::I32Eq
            | O::I32Ne
            | O::I32LtS
            | O::I32LtU
            | O::I32GtS
            | O::I32GtU
            | O::I32LeS
            | O::I32LeU
            | O::I32GeS
            | O::I32GeU
            | O::I64Eq
            | O::I64Ne
            | O::I64LtS
            | O::I64LtU
            | O::I64GtS
            | O::I64GtU
            | O::I64LeS
            | O::I64LeU
            | O::I64GeS
            | O::I64GeU
            | O::I32Eqz
            | O::I64Eqz
            | O::I32WrapI64
            | O::I64ExtendI32S
            | O::I64ExtendI32U
            | O::GlobalGet { .. }
            | O::GlobalSet { .. }
            | O::Select
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{block, func_with, i32_const, op, v};
    use sordec_ir::LiftedTerminator;

    fn mem() -> waffle::Memory {
        waffle::Memory::from(0)
    }

    fn memarg(offset: u32) -> waffle::MemoryArg {
        waffle::MemoryArg {
            align: 3,
            offset,
            memory: mem(),
        }
    }

    fn store(offset: u32, addr: ValueId, value: ValueId) -> LiftedValueDef {
        op(
            waffle::Operator::I64Store {
                memory: memarg(offset),
            },
            vec![addr, value],
        )
    }

    fn load(offset: u32, addr: ValueId) -> LiftedValueDef {
        op(
            waffle::Operator::I64Load {
                memory: memarg(offset),
            },
            vec![addr],
        )
    }

    fn param(index: u32) -> LiftedValueDef {
        LiftedValueDef::BlockParam {
            block: crate::test_util::bb(0),
            index,
        }
    }

    fn call(args: Vec<ValueId>) -> LiftedValueDef {
        op(
            waffle::Operator::Call {
                function_index: waffle::Func::from(0),
            },
            args,
        )
    }

    /// Build a single-block function from defs, scheduling all of them.
    fn single_block(defs: Vec<LiftedValueDef>, params: Vec<ValueId>) -> LiftedFunction {
        let scheduled: Vec<ValueId> = (params.len() as u32..defs.len() as u32).map(v).collect();
        func_with(
            defs,
            vec![block(
                0,
                params,
                scheduled,
                LiftedTerminator::Return { values: vec![] },
            )],
        )
    }

    fn alias_of(func: &LiftedFunction, id: ValueId) -> Option<ValueId> {
        match func.values.get(id)?.def {
            LiftedValueDef::Alias(to) => Some(to),
            _ => None,
        }
    }

    #[test]
    fn a_load_of_what_was_just_stored_is_that_value() {
        let mut func = single_block(
            vec![param(0), param(1), store(0, v(0), v(1)), load(0, v(0))],
            vec![v(0), v(1)],
        );
        assert_eq!(forward_in_function(&mut func), 1);
        assert_eq!(alias_of(&func, v(3)), Some(v(1)));
        assert!(
            !func.blocks.get(func.entry).unwrap().instructions.contains(&v(3)),
            "the load is retired"
        );
    }

    #[test]
    fn a_disjoint_store_under_the_same_base_does_not_block_it() {
        // The shape `argpromote` creates: two stores, then two loads.
        let mut func = single_block(
            vec![
                param(0),               // v0 frame
                param(1),               // v1 k
                param(2),               // v2 val
                store(0, v(0), v(1)),   // v3
                store(8, v(0), v(2)),   // v4 — disjoint from +0
                load(0, v(0)),          // v5
                load(8, v(0)),          // v6
            ],
            vec![v(0), v(1), v(2)],
        );
        assert_eq!(forward_in_function(&mut func), 2);
        assert_eq!(alias_of(&func, v(5)), Some(v(1)));
        assert_eq!(alias_of(&func, v(6)), Some(v(2)));
    }

    #[test]
    fn an_overlapping_store_invalidates() {
        // `+4` as 8 bytes covers half of `+0`'s eight.
        let mut func = single_block(
            vec![
                param(0),
                param(1),
                param(2),
                store(0, v(0), v(1)),
                store(4, v(0), v(2)),
                load(0, v(0)),
            ],
            vec![v(0), v(1), v(2)],
        );
        assert_eq!(forward_in_function(&mut func), 0);
    }

    #[test]
    fn a_store_under_another_base_invalidates_everything() {
        // Two `ValueId`s may hold the same pointer; nothing here proves
        // otherwise, so the unknown resolves against forwarding.
        let mut func = single_block(
            vec![
                param(0),
                param(1),
                param(2),
                store(0, v(0), v(1)),
                store(0, v(2), v(1)),
                load(0, v(0)),
            ],
            vec![v(0), v(1), v(2)],
        );
        assert_eq!(forward_in_function(&mut func), 0);
    }

    #[test]
    fn a_call_between_them_invalidates() {
        // A callee may hold a pointer into this frame — which is exactly
        // why `promote` declined the frame in the first place.
        let mut func = single_block(
            vec![
                param(0),
                param(1),
                store(0, v(0), v(1)),
                call(vec![v(0)]),
                load(0, v(0)),
            ],
            vec![v(0), v(1)],
        );
        assert_eq!(forward_in_function(&mut func), 0);
    }

    #[test]
    fn a_narrower_read_is_not_a_read_of_that_value() {
        let mut func = single_block(
            vec![
                param(0),
                param(1),
                store(0, v(0), v(1)),
                op(
                    waffle::Operator::I32Load {
                        memory: waffle::MemoryArg {
                            align: 2,
                            offset: 0,
                            memory: mem(),
                        },
                    },
                    vec![v(0)],
                ),
            ],
            vec![v(0), v(1)],
        );
        assert_eq!(forward_in_function(&mut func), 0);
    }

    #[test]
    fn address_arithmetic_resolves_to_the_same_slot() {
        // `store fp+8` then `load (fp+8)+0` is one slot, not two.
        let mut func = single_block(
            vec![
                param(0),                                   // v0
                param(1),                                   // v1
                store(8, v(0), v(1)),                       // v2
                i32_const(8),                               // v3
                op(waffle::Operator::I32Add, vec![v(0), v(3)]), // v4
                load(0, v(4)),                              // v5
            ],
            vec![v(0), v(1)],
        );
        assert_eq!(forward_in_function(&mut func), 1);
        assert_eq!(alias_of(&func, v(5)), Some(v(1)));
    }

    #[test]
    fn availability_does_not_cross_a_block_boundary() {
        // Proving a predecessor's store reaches is the dataflow problem
        // `promote` solves; this pass declines rather than approximating it.
        let mut func = func_with(
            vec![
                param(0),             // v0
                param(1),             // v1
                store(0, v(0), v(1)), // v2
                load(0, v(0)),        // v3 — in the next block
            ],
            vec![
                block(
                    0,
                    vec![v(0), v(1)],
                    vec![v(2)],
                    LiftedTerminator::Branch(crate::test_util::target(1, vec![])),
                ),
                block(
                    1,
                    vec![],
                    vec![v(3)],
                    LiftedTerminator::Return { values: vec![] },
                ),
            ],
        );
        assert_eq!(forward_in_function(&mut func), 0);
    }

    #[test]
    fn second_run_reports_no_work() {
        let mut ir = LiftedIr {
            facts: sordec_ir::WasmFacts {
                imports: vec![],
                exports: vec![],
                function_type_indices: vec![],
                function_bodies: vec![],
                function_fingerprints: vec![],
                table_functions: None,
                custom_sections: vec![],
            },
            soroban_facts: None,
            functions: vec![single_block(
                vec![param(0), param(1), store(0, v(0), v(1)), load(0, v(0))],
                vec![v(0), v(1)],
            )],
            memory: sordec_ir::MemoryImage::empty(),
        };
        assert!(StoreForwardPass.run(&mut ir).changed);
        assert!(
            !StoreForwardPass.run(&mut ir).changed,
            "idempotent: the load is gone"
        );
    }
}
