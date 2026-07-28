//! Out-parameter (sret) slot-layout analysis.
//!
//! WASM has no multi-value return in the shape rustc needs, so a function
//! returning anything wider than one machine word is compiled to take a
//! *pointer to caller-allocated space* as its leading argument and write
//! its result through it:
//!
//! ```text
//! fn callee(out: *mut T, x: Val)      caller:
//!   …                                   fp = <frame>
//!   store out+0 <- discriminant         call callee(fp, x)
//!   store out+8 <- payload              load fp+0   ← discriminant
//!   return                              load fp+8   ← payload
//! ```
//!
//! This module recovers the **slot layout** — which offsets the callee
//! writes and which SSA value lands in each. It deliberately answers only
//! that question, because the same shape carries two opposite meanings and
//! the layout is the part they share:
//!
//! - the SDK's `TryFromVal` decode glue, which is marshalling and should
//!   be elided ([`super::decode`]);
//! - a genuine wide-returning contract function (`read_balance -> i128`),
//!   whose out-parameter is a real return value in disguise.
//!
//! Telling those apart is the *caller's* job here; see
//! [`super::decode::classify`] for the effect gate that does it. Nothing
//! in this module rewrites anything.

use std::collections::BTreeMap;

use sordec_common::ValueId;
use sordec_ir::{Expr, HighFunction, Region};

use crate::dataflow::resolve_use;

/// The recovered out-parameter layout of one function.
#[derive(Debug, Clone)]
pub(crate) struct SretShape {
    /// Position of the out-pointer in the parameter list.
    ///
    /// Always `0` in the corpus, and stored rather than assumed because
    /// the caller matches it positionally against a `Call`'s arguments —
    /// an assumption made in two places is an assumption that can drift.
    pub out_index: usize,
    /// `offset → value stored there`, ascending. One entry per slot.
    pub slots: BTreeMap<u32, ValueId>,
    /// The binding ids of the stores themselves, so a consumer that
    /// rewrites the function can neutralise exactly those and nothing
    /// else.
    pub store_bindings: Vec<ValueId>,
}

impl SretShape {
    /// The single value stored at `offset`, if a slot covers it.
    pub fn slot(&self, offset: u32) -> Option<ValueId> {
        self.slots.get(&offset).copied()
    }
}

/// Recover `func`'s out-parameter layout, or `None` when it does not have
/// one.
///
/// Gates, each guarding a concrete wrong-answer:
///
/// - **Helpers only** (`signature.is_none()`). A `contractspecv0`
///   entrypoint's parameters are ABI values by definition — never a
///   caller-allocated pointer — so a spec'd function can never be an sret
///   shape no matter what its first parameter is used for.
/// - **The pointer must be used *only* as a store address.** Any other
///   read (passed on, loaded from, returned, arithmetic) means it escapes
///   or aliases and the slot picture is incomplete, so we decline rather
///   than guess.
/// - **One store per offset.** Two stores to the same offset would make
///   "the value in that slot" position-dependent; the analysis reports a
///   single value per slot and must not be handed an ambiguous one.
pub(crate) fn analyze(func: &HighFunction) -> Option<SretShape> {
    if func.signature.is_some() {
        return None;
    }
    const OUT_INDEX: usize = 0;
    let out_param = *func.params.get(OUT_INDEX)?;

    let mut slots: BTreeMap<u32, ValueId> = BTreeMap::new();
    let mut store_bindings: Vec<ValueId> = Vec::new();

    // Scan the *emitted* bindings only. De-cluttering leaves unscheduled
    // residue behind — alias tombstones (`v21 = v0`) and dead phis that
    // still name the pointer — and counting those as escapes would decline
    // every real out-parameter in the corpus. They are not in any block the
    // region walks, so no generated code can observe them; this mirrors how
    // the backend's dead-`let` pass defines "used".
    for id in emission_order(func) {
        let Some(binding) = func.bindings.get(id) else {
            continue;
        };
        match &binding.expr {
            Expr::Store {
                addr,
                value,
                offset,
                width: _,
            } if resolve_use(func, *addr) == out_param => {
                if slots.insert(*offset, *value).is_some() {
                    // Two stores to one offset — ambiguous, decline.
                    return None;
                }
                store_bindings.push(id);
            }
            // Every other mention of the pointer disqualifies the shape.
            other => {
                let mut escapes = false;
                other.for_each_value_use(|u| {
                    if resolve_use(func, u) == out_param {
                        escapes = true;
                    }
                });
                if escapes {
                    return None;
                }
            }
        }
    }

    // The region itself must not read the pointer (a returned or
    // branched-on frame pointer is not a plain out-parameter).
    let mut region_reads = false;
    func.region.for_each_value_use(|u| {
        if resolve_use(func, u) == out_param {
            region_reads = true;
        }
    });
    if region_reads || slots.is_empty() {
        return None;
    }

    Some(SretShape {
        out_index: OUT_INDEX,
        slots,
        store_bindings,
    })
}

/// Every binding id in `func`, in the order the backend emits them.
///
/// The body walk emits `Region::Basic` blocks in the region tree's
/// depth-first pre-order, so that walk *is* emission order — which is what
/// a position-sensitive consumer needs when the same frame pointer feeds
/// several calls in sequence (hello-add decodes two arguments through one
/// 16-byte frame, and the loads after the second call must not be matched
/// against the first).
pub(crate) fn emission_order(func: &HighFunction) -> Vec<ValueId> {
    let mut ordered = Vec::new();
    func.region.for_each_node(|node| {
        if let Region::Basic(b) = node
            && let Some(block) = func.blocks.get(*b)
        {
            ordered.extend(block.bindings.iter().copied());
        }
    });
    ordered
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, store, v};
    use sordec_ir::{BinaryOp, Expr, Literal};

    #[test]
    fn two_slot_out_param_is_recovered() {
        // params [v0 = out, v1 = val]; stores at 0 and 8.
        let func = func_with(
            vec![
                Expr::Phi { incoming: vec![] },  // v0 out-param
                Expr::Phi { incoming: vec![] },  // v1
                Expr::Literal(Literal::I64(7)),  // v2
                store(v(0), v(2), 0),            // v3
                store(v(0), v(1), 8),            // v4
            ],
            vec![v(0), v(1)],
            vec![2, 3, 4],
        );
        let shape = analyze(&func).expect("two-slot sret shape");
        assert_eq!(shape.out_index, 0);
        assert_eq!(shape.slot(0), Some(v(2)));
        assert_eq!(shape.slot(8), Some(v(1)));
        assert_eq!(shape.store_bindings, vec![v(3), v(4)]);
    }

    #[test]
    fn a_pointer_that_escapes_is_not_an_out_param() {
        // v3 reads the pointer arithmetically → it may alias, so decline.
        let func = func_with(
            vec![
                Expr::Phi { incoming: vec![] },
                Expr::Literal(Literal::I32(8)),
                store(v(0), v(1), 0),
                Expr::Binary { op: BinaryOp::Add, lhs: v(0), rhs: v(1) },
            ],
            vec![v(0)],
            vec![1, 2, 3],
        );
        assert!(analyze(&func).is_none(), "an escaping pointer must decline");
    }

    #[test]
    fn two_stores_to_one_offset_decline() {
        let func = func_with(
            vec![
                Expr::Phi { incoming: vec![] },
                Expr::Literal(Literal::I64(1)),
                store(v(0), v(1), 0),
                store(v(0), v(1), 0),
            ],
            vec![v(0)],
            vec![1, 2, 3],
        );
        assert!(analyze(&func).is_none(), "an ambiguous slot must decline");
    }

    #[test]
    fn a_spec_entrypoint_is_never_an_sret_shape() {
        let mut func = func_with(
            vec![
                Expr::Phi { incoming: vec![] },
                Expr::Literal(Literal::I64(1)),
                store(v(0), v(1), 0),
            ],
            vec![v(0)],
            vec![1, 2],
        );
        func.signature = Some(sordec_ir::FunctionSignature {
            name: "add".to_string(),
            inputs: vec![],
            outputs: vec![],
        });
        assert!(
            analyze(&func).is_none(),
            "an ABI parameter is never a caller-allocated pointer"
        );
    }
}
