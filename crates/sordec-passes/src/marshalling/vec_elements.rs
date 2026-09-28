//! Recover a `Vec`'s elements from the buffer the SDK built it out of.
//!
//! `vec![&e, a, b, c]` has no wasm instruction of its own. The SDK writes
//! the elements into a scratch buffer on the caller's frame and hands the
//! host a pointer and a count:
//!
//! ```text
//! store fp+32 <- a          ← the elements, one Val per 8 bytes
//! store fp+40 <- b
//! store fp+48 <- c
//! p = fp + 32
//! v = vec_new_from_linear_memory(p, 3)
//! ```
//!
//! [`linear_memory`](crate::recognizers::linear_memory) recognises the
//! constructor and stops there, because the elements are "runtime, not
//! rodata" — true, and beside the point. They are not *literals*, but they
//! are perfectly good SSA values sitting in stores a few lines up. Left
//! unrecovered they cost three ways at once: the stores render as
//! `todo!("memory store")`, the constructor renders as
//! `todo!("vec_new(len=…)")`, and the buffer keeps the whole frame alive so
//! its bracket cannot be elided either.
//!
//! This pass reads them back and fills [`KnownOp::VecNew::elements`]. It
//! deletes nothing: the stores become unread, and
//! [`super::dead_store`] is what collects them.
//!
//! ## The evidence gate
//!
//! - **The count is a constant.** A runtime length has no fixed set of
//!   slots to read.
//! - **The pointer is a constant offset from a base** that
//!   [`canon_addr`] can name.
//! - **Every element slot has a reaching store of exactly 8 bytes.** A
//!   `Val` is 8 bytes; a slot written at another width is not one element,
//!   and a slot with no reaching store is one this pass cannot supply.
//!   [`facts_before`] is what makes "reaching" precise — it walks the region
//!   tree, so a store on one arm of a branch does not count for a
//!   constructor after the join, and anything that may write memory in
//!   between kills the fact.
//!
//! All or nothing per constructor: a `Vec` with three of its four elements
//! recovered is not a `Vec` anybody can read, and half-filling the slot
//! would let the emitter print a shorter vector than the contract builds.

use sordec_common::{Provenance, ProvenanceSource};
use sordec_ir::{Expr, HighIr, KnownOp, MemWidth, SemanticOp};

use crate::dataflow::frame_facts::facts_before;
use crate::dataflow::{block_containing, canon_addr, trace_u32val};
use crate::recognizers::client_call::peel_encode;
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-vec-elements";

/// Bytes per `Val` in a linear-memory element array.
const VAL_BYTES: u32 = 8;

/// Sanity bound on a recovered element count, mirroring the one the
/// client-call recognizer applies to a call's arity.
const MAX_ELEMENTS: u32 = 64;

/// Constructors whose elements were read back out of the frame.
const M_RECOVERED: &str = "vec_elements_recovered";
/// Constructors left alone because the gate did not pass.
const M_UNRESOLVED: &str = "vec_elements_unresolved";

/// Fills in `VecNew`'s elements from the stores that built its buffer.
#[derive(Debug, Default, Clone, Copy)]
pub struct VecElementsPass;

impl Pass<HighIr> for VecElementsPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        // Which functions are somebody else's, decided over an immutable
        // view before any rewriting.
        let converters: std::collections::HashSet<sordec_common::FuncId> = ir
            .functions
            .iter()
            .map(|f| f.id)
            .filter(|&id| crate::recognizers::enum_key::is_key_constructor(ir, id))
            .collect();

        for func in &mut ir.functions {
            // A key with a payload is spelled as a `Vec`, and the converter
            // that builds it belongs to `enum_key` +
            // `super::key_construction`, which rewrite the whole shape
            // between them. Recovering its elements leaves that half-done
            // and the `Option` collapse downstream stops matching — auth,
            // custom_types and events each fell 1.0000 -> 0.7059 before
            // this gate existed.
            if converters.contains(&func.id) {
                continue;
            }
            // Two phases: the recovery reads the whole function's frame
            // facts, which cannot be done while a binding is borrowed
            // mutably for the write.
            let mut found: Vec<(sordec_common::ValueId, Vec<sordec_common::ValueId>)> = Vec::new();
            for (id, binding) in func.bindings.iter() {
                let Expr::Semantic(SemanticOp::Known(KnownOp::VecNew {
                    vals_pos,
                    len,
                    elements: None,
                })) = &binding.expr
                else {
                    continue;
                };
                match recover(func, id, *vals_pos, *len) {
                    Some(values) => found.push((id, values)),
                    None => result.metrics.increment(M_UNRESOLVED, 1),
                }
            }
            for (id, values) in found {
                let Some(binding) = func.bindings.get_mut(id) else {
                    continue;
                };
                let Expr::Semantic(SemanticOp::Known(KnownOp::VecNew { elements, .. })) =
                    &mut binding.expr
                else {
                    continue;
                };
                let n = values.len();
                *elements = Some(values);
                binding.add_provenance(Provenance::new(
                    PASS_NAME,
                    ProvenanceSource::DataFlow,
                    format!("vec elements read back from {n} frame slots"),
                ));
                result.metrics.increment(M_RECOVERED, 1);
                result.changed = true;
            }
        }
        result
    }
}

/// The element values behind one constructor, or `None` when the gate
/// declines.
fn recover(
    func: &sordec_ir::HighFunction,
    at: sordec_common::ValueId,
    vals_pos: sordec_common::ValueId,
    len: sordec_common::ValueId,
) -> Option<Vec<sordec_common::ValueId>> {
    // Both operands arrive Val-encoded when the constructor was inlined
    // from the SDK's wrapper, which is the usual case.
    let count = trace_u32val(func, len)?;
    if count == 0 || count > MAX_ELEMENTS {
        return None;
    }
    let (base, start) = canon_addr(func, peel_encode(func, vals_pos));
    let block_id = block_containing(func, at)?;
    let block = func.blocks.get(block_id)?;
    let facts = facts_before(func, block, at, base);
    (0..count)
        .map(|index| facts.value_at(start.checked_add(index.checked_mul(VAL_BYTES)?)?, MemWidth::W8))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, store, v};
    use crate::pass::Pass;
    use sordec_ir::Literal;

    /// Two elements stored into a buffer, then the constructor: the
    /// elements come back in offset order, which is the vector's order.
    #[test]
    fn elements_come_back_in_offset_order() {
        let mut ir = module(vec![func_with(
            vec![
                Expr::Literal(Literal::I32(0)),                    // v0 base
                Expr::Literal(Literal::I64(11)),                   // v1 first
                Expr::Literal(Literal::I64(22)),                   // v2 second
                store(v(0), v(1), 0),                              // v3
                store(v(0), v(2), 8),                              // v4
                Expr::Literal(Literal::I32(2)),                    // v5 count
                Expr::Semantic(SemanticOp::Known(KnownOp::VecNew {
                    vals_pos: v(0),
                    len: v(5),
                    elements: None,
                })),                                               // v6
            ],
            vec![],
            (0..7).collect(),
        )]);

        assert!(VecElementsPass.run(&mut ir).changed, "the gate passes");
        let func = ir.functions.first().expect("one function");
        let Expr::Semantic(SemanticOp::Known(KnownOp::VecNew { elements, .. })) =
            &func.bindings.get(v(6)).expect("the constructor").expr
        else {
            panic!("still a VecNew");
        };
        assert_eq!(
            elements.as_deref(),
            Some(&[v(1), v(2)][..]),
            "offset 0 then offset 8"
        );
    }

    /// All or nothing: a buffer with a gap in it yields no elements at all,
    /// because a vector printed shorter than the contract builds is a wrong
    /// fact rather than a partial one.
    #[test]
    fn a_missing_slot_declines_the_whole_constructor() {
        let mut ir = module(vec![func_with(
            vec![
                Expr::Literal(Literal::I32(0)),
                Expr::Literal(Literal::I64(11)),
                store(v(0), v(1), 0), // only slot 0 is written
                Expr::Literal(Literal::I32(2)),
                Expr::Semantic(SemanticOp::Known(KnownOp::VecNew {
                    vals_pos: v(0),
                    len: v(3),
                    elements: None,
                })),
            ],
            vec![],
            (0..5).collect(),
        )]);

        assert!(!VecElementsPass.run(&mut ir).changed, "slot 8 is unwritten");
        let func = ir.functions.first().expect("one function");
        let Expr::Semantic(SemanticOp::Known(KnownOp::VecNew { elements, .. })) =
            &func.bindings.get(v(4)).expect("the constructor").expr
        else {
            panic!("still a VecNew");
        };
        assert!(elements.is_none(), "no half-filled vector");
    }
}
