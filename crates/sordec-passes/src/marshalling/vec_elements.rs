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
//!   [`facts_at`] is what makes "reaching" precise — it walks the region
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
use crate::dataflow::{block_containing, canon_addr, resolve_use, trace_u32val};
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

/// The counters recording work newly done, for a re-run to report.
pub(crate) const RESOLUTION_COUNTERS: &[&str] = &[M_RECOVERED];

/// Fills in `VecNew`'s elements from the stores that built its buffer.
#[derive(Debug, Default, Clone, Copy)]
pub struct VecElementsPass;

impl Pass<HighIr> for VecElementsPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            let claimed = claimed_vectors(func);
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
                if claimed.contains(&id) {
                    continue;
                }
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

/// Vectors another pass already owns, which this one must not touch.
///
/// A `Vec` is not only `vec![..]`. The SDK also spells an enum key with a
/// payload as one (`DataKey::Counter(user)` is a two-element vector) and a
/// cross-contract call's argument list as one, and each has an owner that
/// rewrites the whole shape:
/// [`super::key_construction`] and [`super::client_args`].
///
/// Recovering the elements of one of those leaves its shape half-rewritten
/// — the constructor names values while its owner still expects the buffer
/// — and the `Option` collapse reading the result stops matching.
/// Measured: `auth`, `custom_types` and `events` each fell from 1.0000 to
/// 0.7059, gaining a branch the source never wrote. Ordering alone cannot
/// prevent it, because these passes share a fixpoint group and this one
/// would still win a round.
fn claimed_vectors(
    func: &sordec_ir::HighFunction,
) -> std::collections::HashSet<sordec_common::ValueId> {
    let mut claimed = std::collections::HashSet::new();
    let mut claim = |v: sordec_common::ValueId| {
        claimed.insert(resolve_use(func, v));
    };
    for (_, binding) in func.bindings.iter() {
        let Expr::Semantic(SemanticOp::Known(op)) = &binding.expr else {
            continue;
        };
        match op {
            KnownOp::StorageGet { key, .. }
            | KnownOp::StorageSet { key, .. }
            | KnownOp::StorageHas { key, .. }
            | KnownOp::StorageRemove { key, .. }
            | KnownOp::StorageExtendTtl { key, .. }
            | KnownOp::StorageExtendTtlV2 { key, .. } => claim(*key),
            KnownOp::InvokeContract { args, .. } | KnownOp::TryInvokeContract { args, .. } => {
                for a in args {
                    claim(*a);
                }
            }
            _ => {}
        }
    }
    claimed
}
