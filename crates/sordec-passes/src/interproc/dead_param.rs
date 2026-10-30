//! Drop the parameters a helper never reads, and their arguments.
//!
//! The commonest by far is the `&Env` every SDK method takes. `Env` has no
//! bytes on the wasm side, so rustc passes a pointer to a one-byte slot of
//! the caller's frame — `fp + 15` in a 16-byte frame — that nothing ever
//! dereferences:
//!
//! ```text
//! fn func4(e) -> u32 {                     fn func6(e, arg0: u32, arg1: i32) -> u32 {
//!     let v1 = global.get 0                    ..                // arg1 never read
//!     let v3 = v1 - 16
//!     global.set v3
//!     let v8 = func6(e, v5, v3 + 15)
//!     global.set v3 + 16
//!     v8
//! }
//! ```
//!
//! The address still counts as the frame escaping into a call, so `func4`
//! keeps its whole shadow-stack bracket — a `global.get 0` and two
//! `global.set`s the source never wrote — only to hand a helper an address
//! it ignores. This pass removes such a parameter and the matching
//! argument at every call site (LLVM's dead-argument elimination); the
//! frame passes re-run after it then take the unused bracket away.
//!
//! It runs late, after the recognizers: many of them match a helper by the
//! shape of its parameter list, `&Env` pointer included, and dropping it
//! earlier moved their output. Measured with this pass on the lifted IR,
//! two recognized encodes stopped matching and seven `cargo check` errors
//! appeared. Here the recognizers have all run and only the frame passes
//! and the final probe spelling follow.
//!
//! # Why it is exact
//!
//! A parameter no code reads cannot influence anything the helper
//! computes, writes or returns, so the helper behaves the same whatever
//! value it is passed. At a call site the argument is a value that has
//! already been computed; dropping the argument removes a read of it, not
//! the binding that computed it, so every effect the caller had still
//! happens in the same order.
//!
//! "No code reads it" is the accounting the emitter's own liveness uses,
//! the same one [`crate::marshalling::frame`] decides a frame is unused
//! by: no scheduled binding reads it (scheduled residue nothing live reads
//! is dropped by the emitter, so its reads do not count), no merge reads
//! it, the region does not, and no return does. A read through a `Use`
//! alias is a read. An unscheduled binding — a store some elision retired
//! — is never emitted, so it reads nothing.
//!
//! # Gates
//!
//! - **A helper**: no ABI signature and no export name. An entrypoint's
//!   parameters are the contract's.
//! - **Every caller is a direct call this pass can see**
//!   ([`CallIndex::caller_set_complete`], the rule every signature change
//!   follows), there is at least one, and each passes one argument per
//!   parameter. A call whose arity disagrees vetoes the helper rather than
//!   guessing which argument is which.
//! - **To a fixpoint.** A helper that only forwards a parameter to another
//!   helper's unread one reads it until that one goes; the pass repeats
//!   until nothing more can.

use std::collections::{HashMap, HashSet};

use sordec_common::{FuncId, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{Expr, HighFunction, HighIr};

use crate::dataflow::{dead_residue, resolve_use, CallIndex};
use crate::marshalling::sret::emission_order;
use crate::metrics_catalog::INTERPROC_DEAD_PARAMS as M_DROPPED;
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "interproc-dead-param";

/// Drops parameters nothing reads, with their arguments.
#[derive(Debug, Default, Clone, Copy)]
pub struct DeadParamPass;

impl Pass<HighIr> for DeadParamPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        // Each round can only shrink a parameter list, so this terminates;
        // the bound is a backstop against a bug, not a budget.
        for _ in 0..64 {
            let dropped = one_round(ir);
            if dropped == 0 {
                break;
            }
            result.changed = true;
            result.metrics.increment(M_DROPPED, dropped as i64);
        }
        result
    }
}

/// Plan and apply one round. Returns how many parameters went.
fn one_round(ir: &mut HighIr) -> usize {
    let calls = CallIndex::build(ir);
    let mut plans: HashMap<FuncId, Vec<bool>> = ir
        .functions
        .iter()
        .filter(|f| f.signature.is_none() && f.name.is_none())
        .filter(|f| calls.caller_set_complete(f.id))
        .filter(|f| !calls.callers_of(f.id).is_empty())
        .filter_map(|f| unread_params(f).map(|mask| (f.id, mask)))
        .collect();
    plans.retain(|&target, mask| {
        calls.callers_of(target).iter().all(|site| {
            ir.function(site.caller)
                .and_then(|caller| caller.bindings.get(site.call))
                .is_some_and(|b| matches!(&b.expr, Expr::Call { args, .. } if args.len() == mask.len()))
        })
    });
    if plans.is_empty() {
        return 0;
    }

    let note = || {
        Provenance::new(
            PASS_NAME,
            ProvenanceSource::DataFlow,
            "an argument the callee never reads, dropped with its parameter",
        )
    };
    let mut dropped = 0;
    for func in &mut ir.functions {
        let sites: Vec<ValueId> = func
            .bindings
            .iter()
            .filter(|(_, b)| matches!(&b.expr, Expr::Call { target, args } if plans.get(target).is_some_and(|m| m.len() == args.len())))
            .map(|(id, _)| id)
            .collect();
        for id in sites {
            let Some(binding) = func.bindings.get_mut(id) else { continue };
            if let Expr::Call { target, args } = &mut binding.expr {
                let mask = &plans[target];
                let mut position = 0;
                args.retain(|_| {
                    let keep = mask[position];
                    position += 1;
                    keep
                });
            }
            binding.add_provenance(note());
        }
        if let Some(mask) = plans.get(&func.id) {
            let gone: Vec<ValueId> = func
                .params
                .iter()
                .zip(mask)
                .filter(|(_, keep)| !**keep)
                .map(|(p, _)| *p)
                .collect();
            for p in &gone {
                if let Some(binding) = func.bindings.get_mut(*p) {
                    binding.add_provenance(note());
                }
            }
            dropped += gone.len();
            let mut position = 0;
            func.params.retain(|_| {
                let keep = mask[position];
                position += 1;
                keep
            });
        }
    }
    dropped
}

/// The keep-mask over `func`'s parameters, or `None` when every one is
/// read.
fn unread_params(func: &HighFunction) -> Option<Vec<bool>> {
    if func.params.is_empty() {
        return None;
    }
    let read = reads(func);
    let mask: Vec<bool> = func.params.iter().map(|p| read.contains(p)).collect();
    mask.iter().any(|keep| !keep).then_some(mask)
}

/// Every value some code reads, aliases included.
fn reads(func: &HighFunction) -> HashSet<ValueId> {
    let order = emission_order(func);
    let dead = dead_residue(func, &order);
    let mut read: HashSet<ValueId> = HashSet::new();
    let mut mark = |u: ValueId| {
        read.insert(u);
        read.insert(resolve_use(func, u));
    };
    for &id in &order {
        if dead.contains(&id) {
            continue;
        }
        if let Some(binding) = func.bindings.get(id) {
            binding.expr.for_each_value_use(&mut mark);
        }
    }
    // A merge is not scheduled and still reads what flows into it.
    for (_, binding) in func.bindings.iter() {
        if matches!(binding.expr, Expr::Phi { .. }) {
            binding.expr.for_each_value_use(&mut mark);
        }
    }
    func.region.for_each_value_use(&mut mark);
    for site in &func.returns {
        site.iter().for_each(|&v| mark(v));
    }
    read
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{check_indirect_gate, func_with, load, module, v};
    use sordec_common::{FuncId, IrId as _};
    use sordec_ir::{BinaryOp, Literal, Region};

    /// End `f`'s one block with `return value`, in the region as the
    /// lowering puts it and in `returns`.
    fn returning(f: &mut HighFunction, value: ValueId) {
        f.returns = vec![vec![value]];
        f.region = Region::Sequence(vec![f.region.clone(), Region::Return { values: vec![value] }]);
    }

    /// `func_0(p, x) -> x`: `p` is never read.
    fn ignores_first() -> HighFunction {
        let mut f = func_with(
            vec![Expr::Phi { incoming: vec![] }, Expr::Phi { incoming: vec![] }],
            vec![v(0), v(1)],
            vec![],
        );
        returning(&mut f, v(1));
        f
    }

    /// `func_1`: `r = func_0(15, 7)`, `r` returned.
    fn caller() -> HighFunction {
        let mut f = func_with(
            vec![
                Expr::Literal(Literal::I32(15)),
                Expr::Literal(Literal::I32(7)),
                Expr::Call { target: FuncId::from_index(0), args: vec![v(0), v(1)] },
            ],
            vec![],
            vec![0, 1, 2],
        );
        f.id = FuncId::from_index(1);
        returning(&mut f, v(2));
        f
    }

    fn call_args(func: &HighFunction, id: ValueId) -> Vec<ValueId> {
        match &func.bindings.get(id).unwrap().expr {
            Expr::Call { args, .. } => args.clone(),
            other => panic!("not a call: {other:?}"),
        }
    }

    #[test]
    fn an_unread_parameter_and_its_argument_go() {
        let mut ir = module(vec![ignores_first(), caller()]);
        assert!(DeadParamPass.run(&mut ir).changed);
        assert_eq!(ir.functions[0].params, vec![v(1)]);
        assert_eq!(call_args(&ir.functions[1], v(2)), vec![v(1)]);
        assert!(
            ir.functions[1].bindings.get(v(2)).unwrap().provenance().iter().any(|p| p.pass == PASS_NAME),
            "the rewritten call says why"
        );
        assert!(!DeadParamPass.run(&mut ir).changed, "idempotent");
    }

    #[test]
    fn a_parameter_read_by_a_live_binding_stays() {
        // `func_0(p, x) { y = p + x; return y }`.
        let mut callee = func_with(
            vec![
                Expr::Phi { incoming: vec![] },
                Expr::Phi { incoming: vec![] },
                Expr::Binary { op: BinaryOp::Add, lhs: v(0), rhs: v(1) },
            ],
            vec![v(0), v(1)],
            vec![2],
        );
        returning(&mut callee, v(2));
        let mut ir = module(vec![callee, caller()]);
        assert!(!DeadParamPass.run(&mut ir).changed);
    }

    #[test]
    fn residue_does_not_hold_a_parameter_but_a_load_does() {
        // `y = load p` is scheduled and nothing reads `y`, but a load may
        // trap, so it is not residue: it reads `p`, and `p` stays.
        let mut callee = func_with(
            vec![Expr::Phi { incoming: vec![] }, Expr::Phi { incoming: vec![] }, load(v(0), 0)],
            vec![v(0), v(1)],
            vec![2],
        );
        returning(&mut callee, v(1));
        let mut ir = module(vec![callee, caller()]);
        DeadParamPass.run(&mut ir);
        assert_eq!(ir.functions[0].params, vec![v(0), v(1)], "a load is a read");

        // Pure arithmetic nothing reads is residue: it does not hold `p`.
        let mut callee = func_with(
            vec![
                Expr::Phi { incoming: vec![] },
                Expr::Phi { incoming: vec![] },
                Expr::Literal(Literal::I32(15)),
                Expr::Binary { op: BinaryOp::Add, lhs: v(0), rhs: v(2) },
            ],
            vec![v(0), v(1)],
            vec![2, 3],
        );
        returning(&mut callee, v(1));
        let mut ir = module(vec![callee, caller()]);
        assert!(DeadParamPass.run(&mut ir).changed);
        assert_eq!(ir.functions[0].params, vec![v(1)]);
    }

    #[test]
    fn an_unscheduled_binding_does_not_hold_a_parameter_but_a_merge_does() {
        // A retired load through `p` that no block schedules.
        let mut callee = func_with(
            vec![Expr::Phi { incoming: vec![] }, Expr::Phi { incoming: vec![] }, load(v(0), 0)],
            vec![v(0), v(1)],
            vec![],
        );
        returning(&mut callee, v(1));
        let mut ir = module(vec![callee, caller()]);
        assert!(DeadParamPass.run(&mut ir).changed);
        assert_eq!(ir.functions[0].params, vec![v(1)]);

        // A merge taking `p` on one edge reads it.
        let mut callee = func_with(
            vec![
                Expr::Phi { incoming: vec![] },
                Expr::Phi { incoming: vec![] },
                Expr::Phi { incoming: vec![(sordec_common::BlockId::from_index(0), v(0))] },
            ],
            vec![v(0), v(1)],
            vec![],
        );
        returning(&mut callee, v(1));
        let mut ir = module(vec![callee, caller()]);
        assert!(!DeadParamPass.run(&mut ir).changed);
    }

    #[test]
    fn an_entrypoint_keeps_its_parameters() {
        let mut ir = module(vec![ignores_first(), caller()]);
        ir.functions[0].name = Some("transfer".into());
        assert!(!DeadParamPass.run(&mut ir).changed);
    }

    #[test]
    fn a_call_of_the_wrong_arity_vetoes_the_helper() {
        let mut odd = caller();
        odd.bindings.get_mut(v(2)).unwrap().expr =
            Expr::Call { target: FuncId::from_index(0), args: vec![v(0)] };
        let mut ir = module(vec![ignores_first(), odd]);
        assert!(!DeadParamPass.run(&mut ir).changed);
    }

    #[test]
    fn a_forwarded_parameter_goes_once_its_reader_does() {
        // func_2(q) { func_0(q, 1) } — `q` is read only as func_0's unread
        // first argument; func_3 calls func_2(15).
        let mut forwarder = func_with(
            vec![
                Expr::Phi { incoming: vec![] },
                Expr::Literal(Literal::I32(1)),
                Expr::Call { target: FuncId::from_index(0), args: vec![v(0), v(1)] },
            ],
            vec![v(0)],
            vec![1, 2],
        );
        forwarder.id = FuncId::from_index(2);
        let mut outer = func_with(
            vec![
                Expr::Literal(Literal::I32(15)),
                Expr::Call { target: FuncId::from_index(2), args: vec![v(0)] },
            ],
            vec![],
            vec![0, 1],
        );
        outer.id = FuncId::from_index(3);
        let mut ir = module(vec![ignores_first(), caller(), forwarder, outer]);
        assert!(DeadParamPass.run(&mut ir).changed);
        assert!(ir.functions[2].params.is_empty());
        assert!(call_args(&ir.functions[3], v(1)).is_empty());
    }

    #[test]
    fn a_helper_an_indirect_call_may_reach_keeps_its_parameters() {
        check_indirect_gate(
            || module(vec![ignores_first(), caller()]),
            0,
            |ir| {
                DeadParamPass.run(ir);
                ir.functions[0].params.len() == 1
            },
        );
    }
}
