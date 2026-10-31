//! Stores into a frame that is not private, which every path overwrites or
//! leaves before anything can read them.
//!
//! # The shape
//!
//! [`super::dead_store`] retires the stores of a *private* frame that no
//! load reads back. A frame the function hands to a helper is not private,
//! so none of its stores qualify there, however plainly dead some are. The
//! `vec!` buffers of `groth16`'s `verify_proof` are the witness: once
//! [`super::from_array`] has run `Vec::from_array`'s loops and
//! [`super::vec_elements`] has read the elements back, what is left of each
//! vector is its scratch stores,
//!
//! ```text
//! store fp+112 <- a; … store fp+136 <- d       // the items array
//! store fp+56 <- VOID; … store fp+80 <- VOID   // the fill
//! store fp+144 <- …; … store fp+164 <- 4       // the zip, as its out-pointer left it
//! store fp+56 <- a; … store fp+80 <- d         // the copy
//! v = Vec::from_array(e, [a, b, c, d])         // reads none of them
//! ```
//!
//! and the second vector writes the same slots again, then the function
//! returns. Every one of those stores prints as a hole, eighteen a vector,
//! though nothing can read any of them: the frame escaped to helpers
//! called *earlier*, never between the stores and the point where they
//! are overwritten or the function leaves.
//!
//! # The rewrite
//!
//! Such a store becomes `()`, with a provenance entry; the value it wrote
//! is untouched.
//!
//! # Why it is exact
//!
//! A store matters only to a later read of its bytes. Walking forward from
//! the store along every path the region tree allows, each binding is one
//! of: a store to the frame, which overwrites whichever of the bytes it
//! covers; a read that cannot reach them; or anything else, which stops
//! the walk and keeps the store. A path that has overwritten every byte,
//! returns, or traps before such a read leaves the store unobservable:
//!
//! - **Overwritten**: the next read of those bytes sees the later store.
//! - **Returned**: the frame is the shadow-stack space carved below the
//!   pointer the function was entered with, and released on return; no
//!   address the callers hold reaches it (the reading [`super::from_array`]
//!   makes of a helper's frame), and the function hands none of its own
//!   out — that is a gate.
//! - **Trapped**: a trap ends the invocation, and its memory with it.
//!
//! The reads that cannot reach the bytes are: a load from the frame at a
//! constant offset that misses every byte still unwritten; a load whose
//! address is a parameter plus a constant, since a parameter is an address
//! the caller held before this frame existed; and a `Vec` constructor whose
//! elements were recovered, which the reconstruction builds from those
//! values and not from memory. A load from any other address, any call,
//! any host operation that touches linear memory (read or write: the
//! effect table records `map_unpack_to_linear_memory` by its write alone,
//! though it reads its keys from memory too), and every other operation
//! that may read memory stops the walk.
//!
//! # Gates
//!
//! - **The frame pointer**: `global.get - size`, as [`super::dead_store`]
//!   finds it; the store's address is it plus a constant.
//! - **No frame address leaves**: none is returned or stored outside the
//!   frame. (Handed to a call is fine — the call itself stops any walk
//!   that reaches it.)
//! - **The walk**: entering a loop, going round one, an unstructured
//!   region, or more than [`MAX_STEPS`] steps keeps the store. Both arms of
//!   a branch, and every arm of a switch, must clear it.

use std::collections::HashMap;

use sordec_common::{BlockId, ValueId};
use sordec_ir::{Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Literal, Region, SemanticOp};

use super::{apply_elisions, metrics, Elision};
use crate::dataflow::{canon_addr, resolve_use};
use crate::effects::expr_effects;
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field for every elision.
pub const PASS_NAME: &str = "marshalling-overwritten-frame-store";

/// Steps — regions entered plus bindings read — one store's walk may take.
const MAX_STEPS: usize = 20_000;

/// Retires frame stores that every path overwrites or leaves unread.
#[derive(Debug, Default, Clone, Copy)]
pub struct OverwrittenFrameStorePass;

impl Pass<HighIr> for OverwrittenFrameStorePass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            let elisions = plan(func);
            if elisions.is_empty() {
                continue;
            }
            result.changed = true;
            result.metrics.increment(metrics::OVERWRITTEN_FRAME_STORES, elisions.len() as i64);
            apply_elisions(func, PASS_NAME, elisions);
        }
        result
    }
}

/// What still has to run after a point: the innermost frame last.
#[derive(Debug, Clone, Copy)]
enum Frame<'r> {
    /// The sibling regions still to come in a sequence.
    Rest(&'r [Region]),
    /// The end of the scope a `break` to this label resumes after.
    Scope(BlockId),
    /// The end of a loop body: falling off it goes round again.
    Loop,
}

fn plan(func: &HighFunction) -> Vec<Elision> {
    let Some(fp) = super::dead_store::frame_pointer(func) else {
        return Vec::new();
    };
    if frame_address_leaves(func, fp) {
        return Vec::new();
    }
    let mut after: HashMap<BlockId, Vec<Frame<'_>>> = HashMap::new();
    index(&func.region, Vec::new(), &mut after);

    let mut elisions = Vec::new();
    for (block_id, k) in &after {
        let Some(block) = func.blocks.get(*block_id) else { continue };
        for (i, &id) in block.bindings.iter().enumerate() {
            let Some(Expr::Store { addr, offset, width, .. }) = func.bindings.get(id).map(|b| &b.expr) else {
                continue;
            };
            let (base, off) = canon_addr(func, *addr);
            let Some(start) = off.checked_add(*offset) else { continue };
            if base != fp || width.bytes() > 8 {
                continue;
            }
            let mut walk = Walk { func, fp, start, mask: full_mask(width.bytes()), steps: 0 };
            let dead = match walk.scan(&block.bindings[i + 1..]) {
                Some(dead) => dead,
                None => walk.rest(k.clone()),
            };
            if dead {
                elisions.push(Elision {
                    id,
                    expr: Expr::Literal(Literal::Unit),
                    ty: Some(IrType::Known(KnownType::Unit)),
                    note: format!(
                        "store to frame slot +{start} that every path overwrites, returns or traps before anything can read it"
                    ),
                    metric: metrics::OVERWRITTEN_FRAME_STORES,
                });
            }
        }
    }
    elisions
}

/// Record, for every block, what runs after its last binding.
fn index<'r>(region: &'r Region, k: Vec<Frame<'r>>, after: &mut HashMap<BlockId, Vec<Frame<'r>>>) {
    match region {
        Region::Basic(b) => {
            after.insert(*b, k);
        }
        Region::Sequence(items) => {
            for (i, item) in items.iter().enumerate() {
                let mut next = k.clone();
                next.push(Frame::Rest(&items[i + 1..]));
                index(item, next, after);
            }
        }
        Region::Scope { out, body } => {
            let mut next = k;
            next.push(Frame::Scope(*out));
            index(body, next, after);
        }
        Region::If { then_region, else_region, .. } => {
            index(then_region, k.clone(), after);
            if let Some(e) = else_region {
                index(e, k, after);
            }
        }
        Region::Switch { arms, default, .. } => {
            for arm in arms {
                index(&arm.body, k.clone(), after);
            }
            index(default, k, after);
        }
        Region::Loop { body, .. } => {
            let mut next = k;
            next.push(Frame::Loop);
            index(body, next, after);
        }
        _ => {}
    }
}

/// Whether a frame address is returned or stored anywhere but the frame.
fn frame_address_leaves(func: &HighFunction, fp: ValueId) -> bool {
    let in_frame = |v: ValueId| canon_addr(func, v).0 == fp || resolve_use(func, v) == fp;
    let mut leaves = false;
    func.region.for_each_node(|node| {
        if let Region::Return { values } = node {
            leaves |= values.iter().any(|v| in_frame(*v));
        }
    });
    for (_, binding) in func.bindings.iter() {
        if let Expr::Store { addr, value, .. } = &binding.expr
            && in_frame(*value)
            && canon_addr(func, *addr).0 != fp
        {
            leaves = true;
        }
    }
    leaves
}

/// The low `width` bits set: one per byte of a store.
fn full_mask(width: u32) -> u8 {
    if width >= 8 { u8::MAX } else { (1u8 << width) - 1 }
}

/// The bits of `[start, start + 8)` that `[at, at + width)` covers.
fn covered(start: u32, at: u32, width: u32) -> u8 {
    let mut mask = 0u8;
    for byte in 0..8u32 {
        let addr = u64::from(start) + u64::from(byte);
        if addr >= u64::from(at) && addr < u64::from(at) + u64::from(width) {
            mask |= 1 << byte;
        }
    }
    mask
}

/// One store's walk.
struct Walk<'a> {
    func: &'a HighFunction,
    fp: ValueId,
    /// The store's first byte, from the frame pointer.
    start: u32,
    /// Its bytes not yet overwritten.
    mask: u8,
    steps: usize,
}

impl<'a> Walk<'a> {
    /// Run `bindings` in order: `Some(true)` once every byte is
    /// overwritten, `Some(false)` at a read that may reach one, `None` when
    /// the bindings run out first.
    fn scan(&mut self, bindings: &[ValueId]) -> Option<bool> {
        for &id in bindings {
            self.steps += 1;
            if self.steps > MAX_STEPS {
                return Some(false);
            }
            let Some(binding) = self.func.bindings.get(id) else { continue };
            match &binding.expr {
                Expr::Store { addr, offset, width, .. } => {
                    let (base, off) = canon_addr(self.func, *addr);
                    if base == self.fp
                        && let Some(at) = off.checked_add(*offset)
                    {
                        self.mask &= !covered(self.start, at, width.bytes());
                        if self.mask == 0 {
                            return Some(true);
                        }
                    }
                }
                Expr::Load { addr, offset, width, .. } => {
                    let (base, off) = canon_addr(self.func, *addr);
                    if base == self.fp {
                        match off.checked_add(*offset) {
                            Some(at) if self.mask & covered(self.start, at, width.bytes()) == 0 => {}
                            _ => return Some(false),
                        }
                    } else if !self.func.params.contains(&base) {
                        return Some(false);
                    }
                }
                Expr::Semantic(SemanticOp::Known(KnownOp::VecNew { elements: Some(_), .. })) => {}
                // A host operation that touches linear memory at all is
                // taken as reading it: the effect table records some by
                // their write alone (`map_unpack_to_linear_memory` also
                // reads its keys from memory).
                Expr::Semantic(_) => {
                    let effects = expr_effects(&binding.expr);
                    if effects.reads_memory || effects.writes_memory {
                        return Some(false);
                    }
                }
                other => {
                    if expr_effects(other).reads_memory {
                        return Some(false);
                    }
                }
            }
        }
        None
    }

    /// Whether the store is dead on every path through the continuation
    /// `k`.
    fn rest<'r>(&mut self, mut k: Vec<Frame<'r>>) -> bool {
        loop {
            self.steps += 1;
            if self.steps > MAX_STEPS {
                return false;
            }
            let Some(top) = k.pop() else {
                // Fell off the function's body: it returns.
                return true;
            };
            let items = match top {
                Frame::Scope(_) => continue,
                Frame::Loop => return false,
                Frame::Rest(items) => items,
            };
            let Some((first, rest)) = items.split_first() else { continue };
            k.push(Frame::Rest(rest));
            match first {
                Region::Basic(b) => {
                    let Some(block) = self.func.blocks.get(*b) else { return false };
                    if let Some(dead) = self.scan(&block.bindings) {
                        return dead;
                    }
                }
                Region::Sequence(xs) => k.push(Frame::Rest(xs)),
                Region::Scope { out, body } => {
                    k.push(Frame::Scope(*out));
                    k.push(Frame::Rest(std::slice::from_ref(body.as_ref())));
                }
                Region::If { then_region, else_region, .. } => {
                    let mut then_k = k.clone();
                    then_k.push(Frame::Rest(std::slice::from_ref(then_region.as_ref())));
                    let saved = self.mask;
                    if !self.rest(then_k) {
                        return false;
                    }
                    self.mask = saved;
                    if let Some(e) = else_region {
                        k.push(Frame::Rest(std::slice::from_ref(e.as_ref())));
                    }
                }
                Region::Switch { arms, default, .. } => {
                    let saved = self.mask;
                    for arm in arms {
                        let mut arm_k = k.clone();
                        arm_k.push(Frame::Rest(std::slice::from_ref(&arm.body)));
                        if !self.rest(arm_k) {
                            return false;
                        }
                        self.mask = saved;
                    }
                    k.push(Frame::Rest(std::slice::from_ref(default.as_ref())));
                }
                Region::Break { target, .. } => loop {
                    match k.pop() {
                        None => return false,
                        Some(Frame::Scope(label)) if label == *target => break,
                        Some(_) => {}
                    }
                },
                Region::Transfer { .. } => {}
                Region::Return { .. } | Region::Panic { .. } | Region::Unreachable => return true,
                Region::Loop { .. } | Region::Continue { .. } | Region::Unstructured { .. } => return false,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, load, module, store, v};
    use sordec_common::{FuncId, IrId, UnknownReason};
    use sordec_ir::{BinaryOp, HighBlock, WasmOpcodeKind};

    fn global_set(value: ValueId) -> Expr {
        Expr::Unknown { op_kind: WasmOpcodeKind::GlobalSet, args: vec![value], reason: UnknownReason::UnsupportedPattern }
    }

    fn call(arg: ValueId) -> Expr {
        Expr::Call { target: FuncId::from_index(9), args: vec![arg] }
    }

    /// v0 param, v1 sp, v2 32, v3 fp, v4 set sp, v5 a value, v6 fp+8,
    /// v7 call(fp) — the frame escapes before anything below — then
    /// `rest` from v8 on. Bindings are scheduled in `blocks`, each a
    /// `Basic` in `region`'s tree (built by the caller from the ids).
    fn framed(rest: Vec<Expr>) -> Vec<Expr> {
        let mut exprs = vec![
            Expr::Phi { incoming: vec![] },                                // v0 param (a pointer)
            Expr::GlobalGet { index: 0 },                                  // v1 sp
            Expr::Literal(Literal::I32(32)),                               // v2
            Expr::Binary { op: BinaryOp::Sub, lhs: v(1), rhs: v(2) },      // v3 fp
            global_set(v(3)),                                              // v4
            Expr::Literal(Literal::I64(7)),                                // v5
            Expr::Literal(Literal::I32(8)),                                // v6
            call(v(3)),                                                    // v7 escape
        ];
        exprs.extend(rest);
        exprs
    }

    fn one_block(exprs: Vec<Expr>) -> HighFunction {
        let n = exprs.len() as u32;
        func_with(exprs, vec![v(0)], (1..n).collect())
    }

    fn elided(func: &HighFunction, id: u32) -> bool {
        matches!(func.bindings.get(v(id)).unwrap().expr, Expr::Literal(Literal::Unit))
    }

    fn run(func: HighFunction) -> HighFunction {
        let mut m = module(vec![func]);
        OverwrittenFrameStorePass.run(&mut m);
        m.functions.remove(0)
    }

    /// A store overwritten before anything reads it, and the overwrite
    /// itself unread before the function falls off its end.
    #[test]
    fn a_store_overwritten_unread_goes_and_so_does_the_last_one() {
        let f = run(one_block(framed(vec![
            store(v(3), v(5), 8), // v8
            load(v(0), 0),        // v9: through the parameter
            store(v(3), v(5), 8), // v10
        ])));
        assert!(elided(&f, 8) && elided(&f, 10));
    }

    /// A load of the bytes, a call, or a load through an address that is
    /// neither the frame nor a parameter may read them: the store stays.
    #[test]
    fn a_store_a_read_may_reach_stays() {
        for reader in [load(v(3), 8), load(v(3), 12), call(v(0)), load(v(5), 0)] {
            let f = run(one_block(framed(vec![store(v(3), v(5), 8), reader, store(v(3), v(5), 8)])));
            assert!(!elided(&f, 8), "{:?}", f.bindings.get(v(9)).unwrap().expr);
        }
    }

    /// A host operation recorded as only writing memory may still read it.
    #[test]
    fn a_host_op_touching_memory_keeps_the_store() {
        let unpack = Expr::Semantic(SemanticOp::Known(KnownOp::MapOp {
            kind: sordec_ir::MapOpKind::UnpackToLinearMemory,
            args: vec![v(5), v(3), v(6), v(5)],
        }));
        let f = run(one_block(framed(vec![store(v(3), v(5), 8), unpack, store(v(3), v(5), 8)])));
        assert!(!elided(&f, 8));
    }

    /// A load of other bytes of the frame does not keep it.
    #[test]
    fn a_load_of_other_bytes_does_not_keep_it() {
        let f = run(one_block(framed(vec![store(v(3), v(5), 8), load(v(3), 16), store(v(3), v(5), 8)])));
        assert!(elided(&f, 8));
    }

    /// The function returning a frame address hands the frame out.
    #[test]
    fn a_frame_address_returned_keeps_every_store() {
        let mut func = one_block(framed(vec![store(v(3), v(5), 8)]));
        func.region = Region::Sequence(vec![Region::Basic(BlockId::from_index(0)), Region::Return { values: vec![v(3)] }]);
        assert!(!elided(&run(func), 8));
    }

    /// Blocks: b0 = v1..=v8 (the store), b1 = `then`, b2 = after.
    fn branching(then: Vec<Expr>, after: Vec<Expr>, then_breaks: bool) -> HighFunction {
        let mut exprs = framed(vec![store(v(3), v(5), 8)]); // v8
        let then_ids: Vec<u32> = (exprs.len() as u32..).take(then.len()).collect();
        exprs.extend(then);
        let after_ids: Vec<u32> = (exprs.len() as u32..).take(after.len()).collect();
        exprs.extend(after);
        let mut func = one_block(exprs);
        func.blocks = sordec_common::Arena::new();
        let ids = |xs: Vec<u32>| xs.into_iter().map(v).collect();
        func.blocks.push(HighBlock { id: BlockId::from_index(0), bindings: ids((1..=8).collect()) });
        func.blocks.push(HighBlock { id: BlockId::from_index(1), bindings: ids(then_ids) });
        func.blocks.push(HighBlock { id: BlockId::from_index(2), bindings: ids(after_ids) });
        let out = BlockId::from_index(3);
        let then_region = if then_breaks {
            Region::Sequence(vec![
                Region::Basic(BlockId::from_index(1)),
                Region::Break { target: out, transfer: vec![] },
            ])
        } else {
            Region::Basic(BlockId::from_index(1))
        };
        func.region = Region::Sequence(vec![
            Region::Scope {
                out,
                body: Box::new(Region::Sequence(vec![
                    Region::Basic(BlockId::from_index(0)),
                    Region::If { cond: v(5), then_region: Box::new(then_region), else_region: None },
                    Region::Basic(BlockId::from_index(2)),
                ])),
            },
            Region::Return { values: vec![] },
        ]);
        func
    }

    /// Both ways out of a branch must clear the store: the arm that breaks
    /// past the overwrite returns unread, the other overwrites it.
    #[test]
    fn every_path_must_overwrite_or_leave() {
        let f = run(branching(vec![], vec![store(v(3), v(5), 8)], true));
        assert!(elided(&f, 8));
        // The same, with the arm reading the slot before it leaves.
        let f = run(branching(vec![load(v(3), 8)], vec![store(v(3), v(5), 8)], true));
        assert!(!elided(&f, 8));
        // An arm that falls through to the overwrite clears it as well.
        let f = run(branching(vec![load(v(0), 0)], vec![store(v(3), v(5), 8)], false));
        assert!(elided(&f, 8));
    }

    /// A loop is not entered: the store before it stays.
    #[test]
    fn a_loop_ahead_keeps_the_store() {
        let mut func = one_block(framed(vec![store(v(3), v(5), 8)]));
        func.region = Region::Sequence(vec![
            Region::Basic(BlockId::from_index(0)),
            Region::Loop {
                header: BlockId::from_index(5),
                body: Box::new(Region::Return { values: vec![] }),
                kind: sordec_ir::LoopKind::Infinite,
            },
        ]);
        assert!(!elided(&run(func), 8));
    }
}
