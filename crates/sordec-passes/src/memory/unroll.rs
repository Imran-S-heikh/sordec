//! Unroll the fixed-count slot loops rustc leaves in a frame.
//!
//! `vec![&env, a, b]` is `Vec::from_array`, which the SDK writes as
//!
//! ```text
//! let mut tmp: [Val; N] = [Val::VOID.to_val(); N];   // fill
//! for (dst, src) in tmp.iter_mut().zip(items) { … }  // copy
//! env.vec_new_from_slice(&tmp)
//! ```
//!
//! and rustc keeps both loops rolled for `N ≥ 2`. Each arrives here as a
//! header block with one induction parameter, a body that stores through
//! `frame + base + i` and steps `i` by the slot width, and a compare
//! against the byte count:
//!
//! ```text
//! bb2(i):  if i != 16 → bb4 else bb5
//! bb4:     store (fp + 16) + i <- 2i64;  branch bb2(i + 8)
//! ```
//!
//! Two costs, one cause. The loop is three control-flow constructs the
//! source never wrote. Worse, its address is `fp + 16 + i` with a
//! loop-carried `i`, and the slot promotion that follows in this pipeline
//! canonicalises only `base + constant`: one un-foldable address makes
//! the escape analysis decline the *whole* frame, so every other store
//! in the function stays a `todo!("memory store")` too. That is why this
//! runs here, on the lifted CFG, and not as a recognizer downstream: it
//! is what makes the frame promotable at all.
//!
//! # The transform
//!
//! With the trip count known (`(bound - init) / step`, small), the body is
//! pasted `N` times into the header with the induction variable replaced
//! by its constant on each iteration, and the header falls through to the
//! exit. The body block keeps its edge into the header and becomes
//! unreachable; the dead-block sweep in the same fixpoint group collects
//! it.
//!
//! # Gates
//!
//! - One induction parameter, initialised by every entry edge to the same
//!   constant, stepped by a positive constant, compared against a constant
//!   with `i32.ne`/`i32.eq`; the count divides exactly and is at most
//!   sixteen — a frame, not a buffer.
//! - The body is straight-line memory traffic and integer arithmetic:
//!   constants, adds, loads and stores. No call, no branch, no other
//!   side effect, because a copied call would run `N` times where the
//!   loop's own semantics also ran it `N` times — true, but the
//!   recognizers that read it expect one.
//! - The header holds nothing but the compare and its constant.
//! - The body's only predecessor is the header, the header's only
//!   predecessors are the entry edge(s) and the body, and the exit edge
//!   passes no argument that depends on the induction variable.

use std::collections::HashMap;

use sordec_common::{BlockId, ValueId};
use sordec_ir::{
    BlockTarget, LiftedFunction, LiftedIr, LiftedTerminator, LiftedType, LiftedValue,
    LiftedValueDef, WasmOp, WasmOpcodeKind,
};

use crate::metrics_catalog::MEMORY_FILL_LOOPS_UNROLLED as M_UNROLLED;
use crate::pass::{Pass, PassResult};

/// Pass name.
pub const PASS_NAME: &str = "memory-unroll-fill-loops";

/// Longest loop this will unroll: a frame of sixteen 8-byte slots.
const MAX_TRIPS: i64 = 16;

/// Unrolls fixed-count frame-slot loops into straight-line stores.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnrollFillLoopsPass;

impl Pass<LiftedIr> for UnrollFillLoopsPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut LiftedIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            let loops: Vec<FillLoop> = func.blocks.ids().filter_map(|h| classify(func, h)).collect();
            for l in loops {
                unroll(func, &l);
                result.metrics.increment(M_UNROLLED, 1);
                result.changed = true;
            }
        }
        result
    }
}

/// One loop this pass will unroll.
struct FillLoop {
    header: BlockId,
    body: BlockId,
    exit: BlockTarget,
    induction: ValueId,
    init: i64,
    step: i64,
    trips: i64,
}

/// Resolve `Alias` links to the defining value.
fn resolve(func: &LiftedFunction, mut v: ValueId) -> ValueId {
    for _ in 0..32 {
        match func.values.get(v).map(|x| &x.def) {
            Some(LiftedValueDef::Alias(inner)) => v = *inner,
            _ => return v,
        }
    }
    v
}

fn const_i32(func: &LiftedFunction, v: ValueId) -> Option<i64> {
    match &func.values.get(resolve(func, v))?.def {
        LiftedValueDef::Operator { op: WasmOp(waffle::Operator::I32Const { value }), .. } => {
            Some(i64::from(*value as i32))
        }
        _ => None,
    }
}

/// Every `(predecessor, args)` edge into each block.
fn predecessors(func: &LiftedFunction) -> HashMap<BlockId, Vec<(BlockId, Vec<ValueId>)>> {
    let mut preds: HashMap<BlockId, Vec<(BlockId, Vec<ValueId>)>> = HashMap::new();
    for (id, block) in func.blocks.iter() {
        let mut targets: Vec<&BlockTarget> = Vec::new();
        match &block.terminator {
            LiftedTerminator::Branch(t) => targets.push(t),
            LiftedTerminator::BranchIf { if_true, if_false, .. } => {
                targets.push(if_true);
                targets.push(if_false);
            }
            LiftedTerminator::Switch { targets: ts, default, .. } => {
                targets.extend(ts.iter());
                targets.push(default);
            }
            LiftedTerminator::Return { .. } | LiftedTerminator::Unreachable => {}
        }
        for t in targets {
            preds.entry(t.block).or_default().push((id, t.args.clone()));
        }
    }
    preds
}

fn classify(func: &LiftedFunction, header: BlockId) -> Option<FillLoop> {
    let h = func.blocks.get(header)?;
    let [induction] = h.params[..] else { return None };
    let LiftedTerminator::BranchIf { cond, if_true, if_false } = &h.terminator else {
        return None;
    };

    // The compare: `induction ?= bound`, with `ne` continuing on true and
    // `eq` continuing on false.
    let LiftedValueDef::Operator { op, args } = &func.values.get(resolve(func, *cond))?.def else {
        return None;
    };
    let (continue_on_true, [a, b]) = match (&op.0, args.as_slice()) {
        (waffle::Operator::I32Ne, [a, b]) => (true, [*a, *b]),
        (waffle::Operator::I32Eq, [a, b]) => (false, [*a, *b]),
        _ => return None,
    };
    let bound = if resolve(func, a) == induction {
        const_i32(func, b)?
    } else if resolve(func, b) == induction {
        const_i32(func, a)?
    } else {
        return None;
    };
    let (body_t, exit_t) = if continue_on_true { (if_true, if_false) } else { (if_false, if_true) };
    if !body_t.args.is_empty() || body_t.block == header {
        return None;
    }
    // The header holds only the compare and its constant.
    for &v in &h.instructions {
        let LiftedValueDef::Operator { op, .. } = &func.values.get(v)?.def else { return None };
        if !matches!(op.0, waffle::Operator::I32Const { .. } | waffle::Operator::I32Ne | waffle::Operator::I32Eq) {
            return None;
        }
    }

    // The body: straight-line memory traffic, then back to the header
    // with the stepped induction variable.
    let body = body_t.block;
    let bb = func.blocks.get(body)?;
    if !bb.params.is_empty() {
        return None;
    }
    let LiftedTerminator::Branch(back) = &bb.terminator else { return None };
    if back.block != header || back.args.len() != 1 {
        return None;
    }
    let LiftedValueDef::Operator { op, args } = &func.values.get(resolve(func, back.args[0]))?.def else {
        return None;
    };
    let step = match (&op.0, args.as_slice()) {
        (waffle::Operator::I32Add, [x, y]) if resolve(func, *x) == induction => const_i32(func, *y)?,
        (waffle::Operator::I32Add, [x, y]) if resolve(func, *y) == induction => const_i32(func, *x)?,
        _ => return None,
    };
    if step <= 0 {
        return None;
    }
    for &v in &bb.instructions {
        let LiftedValueDef::Operator { op, .. } = &func.values.get(v)?.def else { return None };
        let simple = matches!(
            op.0,
            waffle::Operator::I32Const { .. }
                | waffle::Operator::I64Const { .. }
                | waffle::Operator::I32Add
                | waffle::Operator::I32Sub
                | waffle::Operator::I64Add
        ) || matches!(op.kind(), WasmOpcodeKind::Load | WasmOpcodeKind::Store);
        if !simple {
            return None;
        }
    }

    // Edges: the body is entered only from the header; the header from
    // the body and from entry edges that all pass one constant.
    let preds = predecessors(func);
    let body_preds = preds.get(&body)?;
    if body_preds.len() != 1 || body_preds[0].0 != header {
        return None;
    }
    let mut init: Option<i64> = None;
    for (from, args) in preds.get(&header)? {
        if *from == body {
            continue;
        }
        let [arg] = args[..] else { return None };
        let c = const_i32(func, arg)?;
        if init.replace(c).is_some_and(|prev| prev != c) {
            return None;
        }
    }
    let init = init?;
    if (bound - init) % step != 0 {
        return None;
    }
    let trips = (bound - init) / step;
    if !(1..=MAX_TRIPS).contains(&trips) {
        return None;
    }
    // The exit must not carry the induction variable onward.
    if exit_t.args.iter().any(|a| resolve(func, *a) == induction) {
        return None;
    }
    Some(FillLoop {
        header,
        body,
        exit: exit_t.clone(),
        induction,
        init,
        step,
        trips,
    })
}

fn unroll(func: &mut LiftedFunction, l: &FillLoop) {
    let body_instrs: Vec<ValueId> = func.blocks.get(l.body).map(|b| b.instructions.clone()).unwrap_or_default();
    let mut pasted: Vec<ValueId> = Vec::new();
    for k in 0..l.trips {
        let current = l.init + k * l.step;
        let c = func.values.push(LiftedValue {
            def: LiftedValueDef::Operator {
                op: WasmOp(waffle::Operator::I32Const { value: current as u32 }),
                args: vec![],
            },
            types: vec![LiftedType::I32],
        });
        pasted.push(c);
        let mut map: HashMap<ValueId, ValueId> = HashMap::from([(l.induction, c)]);
        for &v in &body_instrs {
            let Some(orig) = func.values.get(v).cloned() else { continue };
            let def = match orig.def {
                LiftedValueDef::Operator { op, args } => LiftedValueDef::Operator {
                    op,
                    args: args.iter().map(|a| *map.get(&resolve(func, *a)).unwrap_or(a)).collect(),
                },
                other => other,
            };
            let id = func.values.push(LiftedValue { def, types: orig.types });
            map.insert(v, id);
            pasted.push(id);
        }
    }
    if let Some(h) = func.blocks.get_mut(l.header) {
        h.instructions.extend(pasted);
        h.terminator = LiftedTerminator::Branch(l.exit.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{bb, block, func_with, i32_const, op, param, target, v};
    use sordec_ir::LiftedBlock;

    fn store(addr: ValueId, value: ValueId) -> LiftedValueDef {
        op(
            waffle::Operator::I64Store {
                memory: waffle::MemoryArg { align: 3, offset: 0, memory: waffle::Memory::from(0) },
            },
            vec![addr, value],
        )
    }

    /// token-v23's `func31` fill loop over a 16-byte region at `fp + 16`:
    /// `bb0: fp; branch bb1(0)` / `bb1(i): if i != 16 → bb2 else bb3` /
    /// `bb2: store (fp+16)+i <- 2; branch bb1(i+8)` / `bb3: return`.
    fn fill_loop() -> LiftedFunction {
        func_with(
            vec![
                i32_const(1000),                                        // v0 fp
                i32_const(0),                                           // v1 init
                param(1, 0),                                            // v2 i
                i32_const(16),                                          // v3 bound
                op(waffle::Operator::I32Ne, vec![v(2), v(3)]),           // v4
                i32_const(16),                                          // v5
                op(waffle::Operator::I32Add, vec![v(0), v(5)]),          // v6 fp+16
                op(waffle::Operator::I32Add, vec![v(6), v(2)]),          // v7 +i
                op(waffle::Operator::I64Const { value: 2 }, vec![]),    // v8
                store(v(7), v(8)),                                      // v9
                i32_const(8),                                           // v10
                op(waffle::Operator::I32Add, vec![v(2), v(10)]),         // v11 i+8
            ],
            vec![
                block(0, vec![], vec![v(0), v(1)], LiftedTerminator::Branch(target(1, vec![v(1)]))),
                block(
                    1,
                    vec![v(2)],
                    vec![v(3), v(4)],
                    LiftedTerminator::BranchIf { cond: v(4), if_true: target(2, vec![]), if_false: target(3, vec![]) },
                ),
                block(2, vec![], vec![v(5), v(6), v(7), v(8), v(9), v(10), v(11)], LiftedTerminator::Branch(target(1, vec![v(11)]))),
                block(3, vec![], vec![], LiftedTerminator::Return { values: vec![] }),
            ],
        )
    }

    fn stores_in(func: &LiftedFunction, b: u32) -> Vec<(i64, i64)> {
        let blk: &LiftedBlock = func.blocks.get(bb(b)).unwrap();
        blk.instructions
            .iter()
            .filter_map(|&id| match &func.values.get(id)?.def {
                LiftedValueDef::Operator { op, args } if matches!(op.kind(), WasmOpcodeKind::Store) => {
                    // address = (fp + 16) + k: read `k` back off the add.
                    let LiftedValueDef::Operator { args: a, .. } = &func.values.get(args[0])?.def else { return None };
                    Some((const_i32(func, a[1])?, 0))
                }
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_two_slot_fill_loop_becomes_two_stores() {
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
            functions: vec![fill_loop()],
            memory: sordec_ir::MemoryImage::empty(),
        };
        let r = UnrollFillLoopsPass.run(&mut ir);
        assert!(r.changed);
        assert_eq!(r.metrics.get(M_UNROLLED), Some(1));
        let f = &ir.functions[0];
        // The header now falls through to the exit …
        assert!(matches!(&f.blocks.get(bb(1)).unwrap().terminator, LiftedTerminator::Branch(t) if t.block == bb(3)));
        // … after two pasted stores at constant offsets 0 and 8.
        let offsets: Vec<i64> = stores_in(f, 1).into_iter().map(|(k, _)| k).collect();
        assert_eq!(offsets, vec![0, 8]);
    }

    #[test]
    fn a_loop_with_a_call_in_its_body_is_left_alone() {
        let mut f = fill_loop();
        // Replace the store with a call.
        f.values.get_mut(v(9)).unwrap().def = op(
            waffle::Operator::Call { function_index: waffle::Func::from(0) },
            vec![v(7)],
        );
        assert!(classify(&f, bb(1)).is_none());
    }

    #[test]
    fn a_count_that_does_not_divide_is_left_alone() {
        let mut f = fill_loop();
        f.values.get_mut(v(3)).unwrap().def = i32_const(20);
        assert!(classify(&f, bb(1)).is_none());
    }

    #[test]
    fn the_pass_is_idempotent() {
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
            functions: vec![fill_loop()],
            memory: sordec_ir::MemoryImage::empty(),
        };
        assert!(UnrollFillLoopsPass.run(&mut ir).changed);
        assert!(!UnrollFillLoopsPass.run(&mut ir).changed);
    }
}
