//! Remove stores into a private frame that nothing reads back.
//!
//! [`super::frame`] can only take a shadow-stack bracket away once the
//! frame pointer has no readers. After the elisions above it, the last
//! readers are usually stores: the `Result` discriminant a wrapper wrote
//! to scratch space and then read back through a load that has since
//! become a literal. The slot is written, never read, and the write keeps
//! the whole frame alive.
//!
//! ```text
//! fp = sp - 16
//! store fp <- 0 offset=0        ← nobody loads fp+0 any more
//! …                             → (store gone; frame elision then takes
//! global.set 0, fp + 16            the bracket)
//! ```
//!
//! ## Why a private frame's dead store is really dead
//!
//! The frame is this function's own scratch space, carved out of the
//! shadow stack by the bracket and released on exit. It is private when
//! the pointer never leaves the function: every use of `fp` (and of any
//! `fp + k` derived from it) is the bracket itself, a store address or a
//! load address. Under that condition no callee, no host operation and no
//! other frame can observe the slot, so a store whose bytes no load in the
//! function overlaps has no reader anywhere. If the pointer is passed to a
//! call, stored somewhere, returned, or folded into arithmetic this pass
//! cannot follow, the frame is not private and nothing is touched.
//!
//! Loads are matched by byte range, not exact slot: a wider load covering
//! part of the store keeps it.

use std::collections::{HashMap, HashSet};

use sordec_common::ValueId;
use sordec_ir::{BinaryOp, Expr, HighFunction, HighIr, IrType, KnownType, Literal};

use super::{apply_elisions, metrics, Elision};
use crate::dataflow::{canon_addr, resolve_use, trace_int};
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field for every elision.
pub const PASS_NAME: &str = "marshalling-dead-frame-store";

/// Elides stores into a private frame that no load reads back.
#[derive(Debug, Default, Clone, Copy)]
pub struct DeadFrameStorePass;

impl Pass<HighIr> for DeadFrameStorePass {
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
            result.metrics.increment(metrics::DEAD_FRAME_STORES, elisions.len() as i64);
            apply_elisions(func, PASS_NAME, elisions);
        }
        result
    }
}

fn plan(func: &HighFunction) -> Vec<Elision> {
    let Some(fp) = frame_pointer(func) else {
        return Vec::new();
    };
    let order = super::sret::emission_order(func);

    // Every emitted use of the frame pointer and its derived addresses
    // must be a store address, a load address, or the bracket.
    let mut derived: HashSet<ValueId> = HashSet::from([fp]);
    for &id in &order {
        if let Some(Expr::Binary { op: BinaryOp::Add, lhs, rhs }) = func.bindings.get(id).map(|b| &b.expr)
            && derived.contains(&resolve_use(func, *lhs))
            && trace_int(func, *rhs).is_some()
        {
            derived.insert(id);
        }
    }
    let mut loads: Vec<(u32, u32)> = Vec::new();
    let mut stores: Vec<(ValueId, u32, u32)> = Vec::new();
    for &id in &order {
        let Some(binding) = func.bindings.get(id) else {
            continue;
        };
        match &binding.expr {
            Expr::Store { addr, value, offset, width } => {
                if derived.contains(&resolve_use(func, *value)) {
                    return Vec::new();
                }
                let (base, off) = canon_addr(func, *addr);
                if base == fp
                    && let Some(start) = off.checked_add(*offset)
                {
                    stores.push((id, start, width.bytes()));
                }
            }
            Expr::Load { addr, offset, width, .. } => {
                let (base, off) = canon_addr(func, *addr);
                if base == fp
                    && let Some(start) = off.checked_add(*offset)
                {
                    loads.push((start, width.bytes()));
                }
            }
            // The bracket's own reads of the pointer: the epilogue
            // restore (`fp + size`) is a derived add with no further use,
            // and the `global.set`s consume `fp` and that add.
            Expr::Unknown { op_kind: sordec_ir::WasmOpcodeKind::GlobalSet, .. } => {}
            Expr::Binary { op: BinaryOp::Add, .. } if derived.contains(&id) => {}
            other => {
                let mut escapes = false;
                other.for_each_value_use(|u| {
                    if derived.contains(&resolve_use(func, u)) {
                        escapes = true;
                    }
                });
                if escapes {
                    return Vec::new();
                }
            }
        }
    }
    let mut region_reads = false;
    func.region.for_each_value_use(|u| {
        if derived.contains(&resolve_use(func, u)) {
            region_reads = true;
        }
    });
    if region_reads {
        return Vec::new();
    }

    stores
        .into_iter()
        .filter(|(_, start, width)| {
            !loads
                .iter()
                .any(|(ls, lw)| ls < &(start + width) && start < &(ls + lw))
        })
        .map(|(id, start, _)| Elision {
            id,
            expr: Expr::Literal(Literal::Unit),
            ty: Some(IrType::Known(KnownType::Unit)),
            note: format!("store to private frame slot +{start} that nothing reads back"),
            metric: metrics::DEAD_FRAME_STORES,
        })
        .collect()
}

/// The frame pointer `fp = global.get G - size`, when the function has one.
fn frame_pointer(func: &HighFunction) -> Option<ValueId> {
    let counts: HashMap<ValueId, usize> = HashMap::new();
    let _ = counts;
    func.bindings.iter().find_map(|(id, binding)| {
        let Expr::Binary { op: BinaryOp::Sub, lhs, rhs } = &binding.expr else {
            return None;
        };
        let sp = resolve_use(func, *lhs);
        let is_global = matches!(func.bindings.get(sp)?.expr, Expr::GlobalGet { .. });
        (is_global && trace_int(func, *rhs).is_some()).then_some(id)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, load, module, store, v};
    use sordec_common::{FuncId, IrId, UnknownReason};
    use sordec_ir::WasmOpcodeKind;

    fn global_set(value: ValueId) -> Expr {
        Expr::Unknown {
            op_kind: WasmOpcodeKind::GlobalSet,
            args: vec![value],
            reason: UnknownReason::UnsupportedPattern,
        }
    }

    /// A 16-byte frame with one store and, optionally, a load of it.
    fn framed(read_back: bool, escape: bool) -> HighFunction {
        let mut exprs = vec![
            Expr::GlobalGet { index: 0 },                                  // v0 sp
            Expr::Literal(Literal::I32(16)),                               // v1
            Expr::Binary { op: BinaryOp::Sub, lhs: v(0), rhs: v(1) },      // v2 fp
            global_set(v(2)),                                              // v3
            Expr::Literal(Literal::I64(0)),                                // v4
            store(v(2), v(4), 0),                                          // v5
            Expr::Binary { op: BinaryOp::Add, lhs: v(2), rhs: v(1) },      // v6 fp+16
            global_set(v(6)),                                              // v7
        ];
        let mut sched = vec![0, 1, 2, 3, 4, 5, 6, 7];
        if read_back {
            exprs.push(load(v(2), 0)); // v8
            sched.push(8);
        }
        if escape {
            exprs.push(Expr::Call { target: FuncId::from_index(9), args: vec![v(2)] });
            sched.push(exprs.len() as u32 - 1);
        }
        func_with(exprs, vec![], sched)
    }

    #[test]
    fn an_unread_store_into_a_private_frame_is_elided() {
        let mut m = module(vec![framed(false, false)]);
        let r = DeadFrameStorePass.run(&mut m);
        assert!(r.changed);
        assert!(matches!(m.functions[0].bindings.get(v(5)).unwrap().expr, Expr::Literal(Literal::Unit)));
    }

    #[test]
    fn a_store_with_a_reader_stays() {
        let mut m = module(vec![framed(true, false)]);
        assert!(!DeadFrameStorePass.run(&mut m).changed);
    }

    /// A frame pointer handed to a callee is not private: the callee may
    /// read the slot.
    #[test]
    fn an_escaping_frame_is_left_alone() {
        let mut m = module(vec![framed(false, true)]);
        assert!(!DeadFrameStorePass.run(&mut m).changed);
    }

    #[test]
    fn the_pass_is_idempotent() {
        let mut m = module(vec![framed(false, false)]);
        assert!(DeadFrameStorePass.run(&mut m).changed);
        assert!(!DeadFrameStorePass.run(&mut m).changed);
    }
}
