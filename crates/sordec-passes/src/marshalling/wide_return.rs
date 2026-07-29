//! Reconstruct a wide return value from its out-parameter.
//!
//! WASM returns one machine word. A Rust function returning anything
//! wider — an `i128`, a `Result<T, E>`, a struct — is compiled to take a
//! pointer to caller-allocated space as its leading argument and write the
//! pieces through it. Reconstructed literally, `read_balance(addr) -> i128`
//! comes back as a void function plus a pile of memory traffic:
//!
//! ```text
//! call read_balance(fp, addr)      →   let t = read_balance(addr);
//! load fp+0                        →   t.0
//! load fp+8                        →   t.1
//! ```
//!
//! ## Relationship to [`super::decode`]
//!
//! Same silhouette, opposite meaning, and the two are not interchangeable.
//! An SDK `TryFromVal` helper computes its result from its own `Val`
//! argument and is *deleted*: the source never wrote it. `read_balance`
//! reads storage and is *kept*: the source wrote it, and only the shape it
//! was compiled into is wrong. `decode` runs first and takes what it can
//! prove is marshalling; this pass takes the rest.
//!
//! That ordering is the safety property. If this pass ran first it would
//! happily give the SDK's decode glue a real signature, and the result
//! would compile, run correctly, and leave the reconstruction full of
//! machinery the contract's author never wrote.
//!
//! ## Why this needs no ABI
//!
//! Unlike everything else in this module, the transform rests on nothing
//! but the slot layout — no `contractspecv0`, no declared types, no
//! entrypoint. So it reaches helpers, and it reaches a stripped contract
//! that has no spec at all. That is why it is worth more than its
//! fixture count suggests: 18 functions across the corpus, 13 of them in
//! `dex-liquidity-pool`, which is the fixture furthest from compiling.
//!
//! ## SUPERSEDED — use `memory::sret` + `memory::promote`
//!
//! [`crate::SretReturnPass`] and [`crate::SlotPromotionPass`] are now
//! registered in [`crate::default_lifted_pipeline`] and do this job at the
//! lifted layer, where the soundness bug described below does not arise:
//! `sret` changes only the ABI and leaves the caller's stores where the
//! call was, and `promote` forwards them away with mem2reg, which *inserts
//! a phi* at a merge rather than declining. This pass is retained for its
//! tests and its account of the problem, not as a staged alternative —
//! wiring it now would double-convert what the lifted pair already did.
//!
//! ## The dominance gate this pass is missing
//!
//! This pass is complete and tested but deliberately absent from
//! [`crate::default_high_pipeline`], because switching it on measured
//! **worse**: token-v23 125 -> 140 `cargo check` errors, timelock 53 ->
//! 59, against dex 314 -> 309 and attestation 8 -> 6. Net +14.
//!
//! The cause is a soundness bug, not a tuning problem. A caller may make
//! the call inside a branch and read the slots after the join:
//!
//! ```text
//! 'bb4: { t = read_balance(fp, x); break 'bb4 }
//! load fp+0        <- reached on paths where that call never ran
//! ```
//!
//! [`rewrite_call_sites`] binds that load to the call regardless, and the
//! call does not dominate it. The value reaches the join through a phi, so
//! the emitted projection lands on the phi — which is declared `Val`,
//! because [`IrType`] has no product type — and `v.0` becomes a field
//! access on a scalar.
//!
//! Two things are needed before this can be switched on, in this order:
//!
//! 1. **A dominance gate.** Bind a load to a call only when the call
//!    dominates it. `CfgFacts` already computes dominance; the pass walks
//!    regions and currently has no access to it.
//! 2. **A product type in [`IrType`]**, so a tuple that reaches a phi has
//!    something to be declared as. Until then the honest behaviour is to
//!    decline — [`unrepresentable_callees`] is the beginning of that, and
//!    it is insufficient: it inspects the *call's* readers, but the tuple
//!    reaches the phi through the projections instead.
//!
//! Everything else here is exercised by the unit tests below and by
//! `sret_candidate_census`, which sizes the work at 18 functions.
//!
//! ## Sub-frames
//!
//! A caller with several wide results carves them out of one frame and
//! passes `fp + k` to each callee, so a slot's address is
//! `base + k + offset` rather than `base + offset`. Addresses are
//! canonicalised to `(base, byte offset)` with
//! [`crate::dataflow::canon_addr`], and a load is matched by absolute
//! position, so the sub-frame case needs no special handling.

use std::collections::HashMap;

use sordec_common::{FuncId, ValueId};
use sordec_ir::{Expr, HighFunction, HighIr, IrType, KnownType, Literal, Region};

use super::sret;
use super::{apply_elisions, metrics, Elision};
use crate::dataflow::{canon_addr, resolve_use};
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-wide-return";

/// How one function's out-parameter maps onto returned components.
#[derive(Debug, Clone)]
struct WidePlan {
    /// Position of the out-pointer in the parameter list.
    out_index: usize,
    /// Slot offsets, ascending. Component `i` lives at `offsets[i]`.
    offsets: Vec<u32>,
    /// The value stored in each slot, parallel to `offsets`.
    values: Vec<ValueId>,
    /// The store bindings to neutralise once the values are returned.
    stores: Vec<ValueId>,
}

/// Turns out-parameter writes back into return values.
#[derive(Debug, Default, Clone, Copy)]
pub struct WideReturnPass;

impl Pass<HighIr> for WideReturnPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();

        let mut plans: HashMap<FuncId, WidePlan> = ir
            .functions
            .iter()
            .filter_map(|f| convertible(f).map(|plan| (f.id, plan)))
            .collect();
        // A signature change is all-or-nothing across the module: convert a
        // callee whose result one caller cannot consume as a tuple and that
        // caller is left passing a frame to a function that no longer takes
        // one. So every call site gets a veto before anything moves.
        let vetoed: Vec<FuncId> = ir
            .functions
            .iter()
            .flat_map(|f| unrepresentable_callees(f, &plans))
            .collect();
        for id in &vetoed {
            plans.remove(id);
        }
        if plans.is_empty() {
            return result;
        }

        // Call sites first. Rewriting the callee's signature before its
        // callers have been re-pointed would leave the module briefly
        // inconsistent, and a debug validator between the two would be
        // right to complain.
        for func in &mut ir.functions {
            let elisions = rewrite_call_sites(func, &plans);
            if !elisions.is_empty() {
                result.changed = true;
                result
                    .metrics
                    .increment(metrics::WIDE_LOADS_REBOUND, elisions.len() as i64);
                apply_elisions(func, PASS_NAME, elisions);
            }
        }

        // Then the callees.
        for func in &mut ir.functions {
            let Some(plan) = plans.get(&func.id) else {
                continue;
            };
            convert(func, plan);
            result.changed = true;
            result.metrics.increment(metrics::WIDE_RETURNS_RECOVERED, 1);
        }

        crate::refine::debug_validate(ir, PASS_NAME);
        result
    }
}

/// Can `func`'s out-parameter become a return value?
fn convertible(func: &HighFunction) -> Option<WidePlan> {
    // `decode` owns the marshalling case and deletes it outright. Giving
    // the SDK's own glue a tidy signature would produce a reconstruction
    // that is correct and still full of code nobody wrote.
    if super::decode::classify(func).is_some() {
        return None;
    }
    let shape = sret::analyze(func)?;

    // A function that already returns something is a shape this does not
    // model: the wasm return and the out-parameter would both have to
    // become components, and their order is not recorded anywhere.
    if func.returns.iter().any(|site| !site.is_empty()) {
        return None;
    }

    let offsets: Vec<u32> = shape.slots.keys().copied().collect();
    let values: Vec<ValueId> = shape.slots.values().copied().collect();
    Some(WidePlan {
        out_index: shape.out_index,
        offsets,
        values,
        stores: shape.store_bindings,
    })
}

// ---------------------------------------------------------------------
// Caller side
// ---------------------------------------------------------------------

/// Callees whose result `func` consumes in a way the IR cannot type.
///
/// A converted call produces several values at once. [`Expr::Project`]
/// names one of them, and that is the *only* consumer the emitter can
/// render, because [`IrType`] has no product type: a tuple that has to be
/// declared — a phi's `let mut v: T`, a value returned onward, a value
/// passed to another function — has no `T` to write, and the emitter falls
/// back to `Val`, producing a field access on a scalar.
///
/// Rather than invent a tuple type here, the pass declines. The
/// alternative — converting anyway and emitting something that does not
/// compile — would trade a recovered signature for a broken crate, which
/// is the wrong side of this project's bargain.
///
/// Widening `IrType` with a product type is the real fix and is worth
/// doing; it is a change to the IR's vocabulary, not to this pass.
fn unrepresentable_callees(
    func: &HighFunction,
    plans: &HashMap<FuncId, WidePlan>,
) -> Vec<FuncId> {
    // What the region reads directly: phi transfer sources, returned
    // values, branch conditions. None of those can carry a tuple.
    let mut structural: Vec<ValueId> = Vec::new();
    func.region.for_each_value_use(|u| structural.push(u));

    let mut vetoed = Vec::new();
    for (id, binding) in func.bindings.iter() {
        let Expr::Call { target, args } = &binding.expr else {
            continue;
        };
        let Some(plan) = plans.get(target) else {
            continue;
        };
        if args.get(plan.out_index).is_none() {
            vetoed.push(*target);
            continue;
        }
        if structural.iter().any(|u| resolve_use(func, *u) == id) {
            vetoed.push(*target);
            continue;
        }
        // Any binding that reads the call other than through a slot load
        // would also need the tuple as a value.
        for (_, other) in func.bindings.iter() {
            let mut reads = false;
            other.expr.for_each_value_use(|u| {
                if resolve_use(func, u) == id {
                    reads = true;
                }
            });
            if reads && !matches!(other.expr, Expr::Load { .. }) {
                vetoed.push(*target);
                break;
            }
        }
    }
    vetoed
}

/// A call whose components are still being read at this point of the walk.
struct Active {
    /// The call binding, which now produces the whole tuple.
    call: ValueId,
    /// Absolute byte position of the frame the callee wrote into.
    base_offset: u32,
    plan: WidePlan,
}

/// Rebind every load of a converted callee's slots to a projection.
fn rewrite_call_sites(
    func: &HighFunction,
    plans: &HashMap<FuncId, WidePlan>,
) -> Vec<Elision> {
    let mut elisions = Vec::new();
    // Pointer base → the calls that have written through it, most recent
    // last. Several sub-frames share one base, so this cannot be keyed on
    // the base alone.
    let mut active: HashMap<ValueId, Vec<Active>> = HashMap::new();

    for id in sret::emission_order(func) {
        let Some(binding) = func.bindings.get(id) else {
            continue;
        };
        match &binding.expr {
            Expr::Call { target, args } => {
                let Some(plan) = plans.get(target) else {
                    continue;
                };
                let Some(frame_arg) = args.get(plan.out_index) else {
                    continue;
                };
                let (base, base_offset) = canon_addr(func, *frame_arg);
                active.entry(base).or_default().push(Active {
                    call: id,
                    base_offset,
                    plan: plan.clone(),
                });
                // Drop the frame argument; the value comes back instead.
                let mut rest = args.clone();
                rest.remove(plan.out_index);
                elisions.push(Elision {
                    id,
                    expr: Expr::Call {
                        target: *target,
                        args: rest,
                    },
                    ty: None,
                    note: "out-parameter dropped: the callee returns its value".to_string(),
                    metric: metrics::WIDE_LOADS_REBOUND,
                });
            }
            Expr::Load { addr, offset, .. } => {
                let (base, addr_offset) = canon_addr(func, *addr);
                let position = addr_offset.saturating_add(*offset);
                // Most recent writer of this slot wins — a frame is reused.
                let Some(found) = active.get(&base).and_then(|calls| {
                    calls.iter().rev().find_map(|act| {
                        let slot = position.checked_sub(act.base_offset)?;
                        let index = act.plan.offsets.iter().position(|o| *o == slot)?;
                        Some((act.call, index))
                    })
                }) else {
                    continue;
                };
                let (call, index) = found;
                elisions.push(Elision {
                    id,
                    expr: Expr::Project {
                        value: call,
                        index: index as u32,
                    },
                    ty: None,
                    note: format!(
                        "slot read rebound to return component {index} of the call \
                         that produced it"
                    ),
                    metric: metrics::WIDE_LOADS_REBOUND,
                });
            }
            // Anything else writing through a tracked base invalidates it:
            // the slot picture we are matching against is no longer the
            // most recent writer.
            Expr::Store { addr, .. } => {
                let (base, _) = canon_addr(func, *addr);
                active.remove(&base);
            }
            _ => {}
        }
    }
    elisions
}

// ---------------------------------------------------------------------
// Callee side
// ---------------------------------------------------------------------

/// Give `func` a real return: drop the out-parameter, neutralise the
/// stores, and return their values instead.
fn convert(func: &mut HighFunction, plan: &WidePlan) {
    if plan.out_index < func.params.len() {
        func.params.remove(plan.out_index);
    }

    // Every return site now carries the components. `returns` is the
    // record inter-procedural analyses read; the region is what the
    // backend emits. Both have to move, or the emitted `return` and the
    // declared signature disagree.
    for site in &mut func.returns {
        site.clone_from(&plan.values);
    }
    let region = std::mem::replace(&mut func.region, Region::Unreachable);
    func.region = fill_returns(region, &plan.values);

    let elisions = plan
        .stores
        .iter()
        .map(|id| Elision {
            id: *id,
            expr: Expr::Literal(Literal::Unit),
            ty: Some(IrType::Known(KnownType::Unit)),
            note: "out-parameter store: the value is returned instead".to_string(),
            metric: metrics::WIDE_RETURNS_RECOVERED,
        })
        .collect();
    apply_elisions(func, PASS_NAME, elisions);
}

/// Rewrite every value-less `Return` to carry `values`.
fn fill_returns(region: Region, values: &[ValueId]) -> Region {
    match region {
        Region::Return { values: existing } if existing.is_empty() => Region::Return {
            values: values.to_vec(),
        },
        Region::Sequence(items) => Region::Sequence(
            items
                .into_iter()
                .map(|item| fill_returns(item, values))
                .collect(),
        ),
        Region::Scope { out, body } => Region::Scope {
            out,
            body: Box::new(fill_returns(*body, values)),
        },
        Region::Loop { header, body, kind } => Region::Loop {
            header,
            body: Box::new(fill_returns(*body, values)),
            kind,
        },
        Region::Switch {
            index,
            arms,
            default,
            dispatch,
        } => Region::Switch {
            index,
            arms: arms
                .into_iter()
                .map(|mut arm| {
                    arm.body = fill_returns(arm.body, values);
                    arm
                })
                .collect(),
            default: Box::new(fill_returns(*default, values)),
            dispatch,
        },
        Region::If {
            cond,
            then_region,
            else_region,
        } => Region::If {
            cond,
            then_region: Box::new(fill_returns(*then_region, values)),
            else_region: else_region.map(|e| Box::new(fill_returns(*e, values))),
        },
        leaf @ (Region::Basic(_)
        | Region::Break { .. }
        | Region::Continue { .. }
        | Region::Transfer { .. }
        | Region::Return { .. }
        | Region::Unreachable
        | Region::Panic { .. }
        | Region::Unstructured { .. }) => leaf,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, load, module, store, v};
    use sordec_common::{BlockId, FuncId as _FuncId, IrId as _};
    use sordec_ir::BinaryOp;

    /// `read_balance`-shaped: `(out, arg)`, two slots, no ABI needed.
    fn wide_callee() -> HighFunction {
        let mut func = func_with(
            vec![
                Expr::Phi { incoming: vec![] }, // v0 out-pointer
                Expr::Phi { incoming: vec![] }, // v1 argument
                Expr::Literal(Literal::I64(7)), // v2 hi
                Expr::Literal(Literal::I64(9)), // v3 lo
                store(v(0), v(2), 0),           // v4
                store(v(0), v(3), 8),           // v5
            ],
            vec![v(0), v(1)],
            vec![2, 3, 4, 5],
        );
        func.returns = vec![vec![]];
        func.region = Region::Sequence(vec![
            Region::Basic(BlockId::from_index(0)),
            Region::Return { values: vec![] },
        ]);
        func
    }

    #[test]
    fn an_out_parameter_becomes_a_return_value() {
        let mut func = wide_callee();
        let plan = convertible(&func).expect("a wide return");
        assert_eq!(plan.offsets, vec![0, 8]);
        convert(&mut func, &plan);

        assert_eq!(func.params, vec![v(1)], "the out-pointer is gone");
        assert_eq!(func.returns, vec![vec![v(2), v(3)]]);
        // The emitted return has to agree with the declared signature.
        let mut returned = None;
        func.region.for_each_node(|node| {
            if let Region::Return { values } = node {
                returned = Some(values.clone());
            }
        });
        assert_eq!(returned, Some(vec![v(2), v(3)]));
        // And the stores no longer write anything.
        assert!(matches!(
            func.bindings.get(v(4)).unwrap().expr,
            Expr::Literal(Literal::Unit)
        ));
    }

    #[test]
    fn a_decode_helper_is_left_to_the_decode_pass() {
        // Giving the SDK's own glue a tidy signature produces a
        // reconstruction that is correct and full of code nobody wrote.
        let helper = super::super::decode::tests::u64_decode_helper();
        assert!(
            convertible(&helper).is_none(),
            "marshalling is deleted, not re-signed"
        );
    }

    #[test]
    fn a_function_that_already_returns_something_is_declined() {
        let mut func = wide_callee();
        func.returns = vec![vec![v(2)]];
        assert!(convertible(&func).is_none());
    }

    fn caller_with(frame_expr: Vec<Expr>, load_base: ValueId, offsets: (u32, u32)) -> HighFunction {
        let mut exprs = vec![Expr::Phi { incoming: vec![] }]; // v0 the frame base
        exprs.extend(frame_expr);
        let call_id = exprs.len() as u32;
        exprs.push(Expr::Call {
            target: _FuncId::from_index(0),
            args: vec![v(call_id - 1), v(0)],
        });
        exprs.push(load(load_base, offsets.0));
        exprs.push(load(load_base, offsets.1));
        let scheduled = (1..exprs.len() as u32).collect();
        let mut func = func_with(exprs, vec![v(0)], scheduled);
        func.id = _FuncId::from_index(1);
        func
    }

    fn plans_for(callee: &HighFunction) -> HashMap<FuncId, WidePlan> {
        let mut m = HashMap::new();
        m.insert(_FuncId::from_index(0), convertible(callee).unwrap());
        m
    }

    #[test]
    fn slot_loads_become_projections_of_the_call() {
        // `call f(fp, x); load fp+0; load fp+8`
        let func = caller_with(vec![Expr::Use(v(0))], v(0), (0, 8));
        let elisions = rewrite_call_sites(&func, &plans_for(&wide_callee()));
        let projections: Vec<_> = elisions
            .iter()
            .filter_map(|e| match e.expr {
                Expr::Project { value, index } => Some((value, index)),
                _ => None,
            })
            .collect();
        assert_eq!(projections.len(), 2, "both slots rebind");
        assert_eq!(projections[0].1, 0);
        assert_eq!(projections[1].1, 1);
        assert_eq!(
            projections[0].0, projections[1].0,
            "both name the same producing call"
        );
        // And the frame argument is dropped from the call itself.
        assert!(elisions.iter().any(|e| matches!(
            &e.expr,
            Expr::Call { args, .. } if args.len() == 1
        )));
    }

    #[test]
    fn a_sub_frame_call_matches_by_absolute_position() {
        // `call f(fp + 8, x)` writes slots at fp+8 and fp+16, so the
        // loads sit at those absolute positions rather than at 0 and 8.
        // This is the shape a caller with several wide results produces.
        let func = caller_with(
            vec![
                Expr::Literal(Literal::I32(8)),
                Expr::Binary { op: BinaryOp::Add, lhs: v(0), rhs: v(1) },
            ],
            v(0),
            (8, 16),
        );
        let elisions = rewrite_call_sites(&func, &plans_for(&wide_callee()));
        let indices: Vec<u32> = elisions
            .iter()
            .filter_map(|e| match e.expr {
                Expr::Project { index, .. } => Some(index),
                _ => None,
            })
            .collect();
        assert_eq!(indices, vec![0, 1], "sub-frame slots still map to 0 and 1");
    }

    #[test]
    fn a_load_outside_the_slot_layout_is_left_alone() {
        // Offset 4 is not a slot; rebinding it would invent a component.
        let func = caller_with(vec![Expr::Use(v(0))], v(0), (4, 8));
        let elisions = rewrite_call_sites(&func, &plans_for(&wide_callee()));
        let indices: Vec<u32> = elisions
            .iter()
            .filter_map(|e| match e.expr {
                Expr::Project { index, .. } => Some(index),
                _ => None,
            })
            .collect();
        assert_eq!(indices, vec![1], "only the real slot rebinds");
    }

    #[test]
    fn second_run_reports_no_work() {
        let mut ir = module(vec![wide_callee()]);
        assert!(WideReturnPass.run(&mut ir).changed);
        assert!(
            !WideReturnPass.run(&mut ir).changed,
            "idempotent: the out-parameter is gone, so the shape no longer matches"
        );
    }
}
