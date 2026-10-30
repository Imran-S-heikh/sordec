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
//!
//! ## An element stored as a constant word
//!
//! `(1, 2).into_val(&e)` builds its vec from two constants the compiler
//! has already encoded, so what sits in each slot is the word
//! `1 << 32 | I32Val`, not the number one. Named as the literal it was
//! loaded as, it would print as `4294967301i64` — a vec of `i64`s, whose
//! elements encode to different words than the ones the contract stored.
//!
//! Such an element is read back through its decode instead: a fresh
//! binding holding the value the word encodes, typed by its tag, scheduled
//! just before the constructor and standing in the element's place. The
//! store it came from is untouched; it is the dead-store collection's.
//!
//! ### Why it is exact
//!
//! Every slot the host reads is a `Val`: that is what
//! `vec_new_from_linear_memory` takes. A constant word in one is therefore
//! a `Val`'s bits, and the value it decodes to encodes back to exactly
//! those bits — a `u32` or `i32` sits in the high half over its tag, a
//! `bool` is its own tag, a short symbol is its characters packed over its
//! tag. So the vec holds the same words either way.
//!
//! ### Gates
//!
//! - **A raw 64-bit constant**, typed as nothing narrower than the word it
//!   was loaded as ([`super::encode::encoded_constant`]'s reading).
//! - **A tag that names one of those types**, with the bits that type
//!   leaves zero zero, and a symbol that is a strict short-symbol packing.
//!   Any other word is left as it is.

use sordec_common::{IrId as _, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Literal, MemWidth, SemanticOp};

use super::encode::encoded_constant;

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
                let values = decode_words(func, id, values);
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

/// The elements with each constant word replaced by the value it encodes,
/// as a fresh binding scheduled just before the constructor `at`. See the
/// module doc.
fn decode_words(func: &mut HighFunction, at: ValueId, values: Vec<ValueId>) -> Vec<ValueId> {
    values
        .into_iter()
        .map(|element| match decoded_word(func, element) {
            Some((lit, ty)) => schedule_before(func, at, lit, ty).unwrap_or(element),
            None => element,
        })
        .collect()
}

/// The value a constant word in a `Val` slot encodes, and its type, when
/// its tag names a `u32`, an `i32`, a `bool` or a short symbol.
fn decoded_word(func: &HighFunction, element: ValueId) -> Option<(Literal, KnownType)> {
    let b = func.bindings.get(crate::dataflow::resolve_use(func, element))?;
    let raw = matches!(b.expr, Expr::Literal(Literal::I64(_) | Literal::U64(_)))
        && matches!(
            &b.ty,
            IrType::Unknown(_)
                | IrType::Known(KnownType::I64 | KnownType::U64)
                | IrType::Inferred(KnownType::I64 | KnownType::U64)
        );
    if !raw {
        return None;
    }
    // The tag picks at most one of these.
    [KnownType::U32, KnownType::I32, KnownType::Bool, KnownType::Symbol]
        .into_iter()
        .find_map(|ty| encoded_constant(func, element, &ty).map(|lit| (lit, ty)))
}

/// A fresh binding of `lit`, scheduled just before `at` in its block.
fn schedule_before(func: &mut HighFunction, at: ValueId, lit: Literal, ty: KnownType) -> Option<ValueId> {
    let block = block_containing(func, at)?;
    let fresh = ValueId::from_index(func.bindings.len() as u32);
    func.bindings.push(sordec_ir::Binding::new(
        fresh,
        IrType::Known(ty),
        Expr::Literal(lit),
        Provenance::new(
            PASS_NAME,
            ProvenanceSource::SdkPattern,
            "a vec element stored as its encoded constant, decoded",
        ),
    ));
    let bindings = &mut func.blocks.get_mut(block)?.bindings;
    let pos = bindings.iter().position(|v| *v == at)?;
    bindings.insert(pos, fresh);
    Some(fresh)
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

    /// `(1, 2).into_val(&e)`: two constant `I32Val` words and one that is
    /// no small value of a decodable type (an `I64Small`).
    fn constant_words() -> HighIr {
        module(vec![func_with(
            vec![
                Expr::Literal(Literal::I32(0)),               // v0 base
                Expr::Literal(Literal::I64((1 << 32) | 5)),   // v1 I32Val(1)
                Expr::Literal(Literal::I64((2 << 32) | 5)),   // v2 I32Val(2)
                Expr::Literal(Literal::I64((9 << 8) | 7)),    // v3 I64Small(9)
                store(v(0), v(1), 0),                         // v4
                store(v(0), v(2), 8),                         // v5
                store(v(0), v(3), 16),                        // v6
                Expr::Literal(Literal::I32(3)),               // v7 count
                Expr::Semantic(SemanticOp::Known(KnownOp::VecNew {
                    vals_pos: v(0),
                    len: v(7),
                    elements: None,
                })),                                          // v8
            ],
            vec![],
            (0..9).collect(),
        )])
    }

    /// A constant word in a slot is read through its decode: the value it
    /// encodes, typed by its tag, scheduled before the constructor. A word
    /// of another tag stays the word.
    #[test]
    fn a_constant_word_element_is_the_value_it_encodes() {
        let mut ir = constant_words();
        assert!(VecElementsPass.run(&mut ir).changed);
        let func = ir.functions.first().expect("one function");
        let Expr::Semantic(SemanticOp::Known(KnownOp::VecNew { elements: Some(elements), .. })) =
            &func.bindings.get(v(8)).expect("the constructor").expr
        else {
            panic!("elements recovered");
        };
        assert_eq!(elements.len(), 3);
        for (element, want) in elements.iter().zip([1, 2]) {
            let b = func.bindings.get(*element).expect("fresh binding");
            assert!(matches!(b.expr, Expr::Literal(Literal::I32(n)) if n == want), "{:?}", b.expr);
            assert_eq!(b.ty, IrType::Known(KnownType::I32));
            let block = func.blocks.iter().next().expect("one block").1;
            let at = |x: ValueId| block.bindings.iter().position(|y| *y == x);
            assert!(at(*element) < at(v(8)), "scheduled before the constructor");
        }
        assert_eq!(elements[2], v(3), "an I64Small word is left as it is");
    }

    /// A short symbol packed in a slot is the symbol.
    #[test]
    fn a_short_symbol_word_element_is_the_symbol() {
        let mut ir = constant_words();
        // "hello" over the SymbolSmall tag.
        ir.functions[0].bindings.get_mut(v(1)).unwrap().expr = Expr::Literal(Literal::I64(196_144_296_974));
        VecElementsPass.run(&mut ir);
        let func = ir.functions.first().expect("one function");
        let Expr::Semantic(SemanticOp::Known(KnownOp::VecNew { elements: Some(elements), .. })) =
            &func.bindings.get(v(8)).expect("the constructor").expr
        else {
            panic!("elements recovered");
        };
        let first = func.bindings.get(elements[0]).expect("fresh binding");
        assert!(matches!(&first.expr, Expr::Literal(Literal::Symbol(s)) if s == "hello"));
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
