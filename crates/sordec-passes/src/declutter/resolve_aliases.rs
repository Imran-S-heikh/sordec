//! Alias resolution: rewrite every use of an `Alias` def to its
//! terminal definition.
//!
//! waffle's frontend emits [`LiftedValueDef::Alias`] as transparent
//! indirection (~2,500 defs across the corpus). Recognizers already
//! chase them via `resolve_use`; this pass rewires the graph once so
//! nothing downstream — structurer, refinement, emitter — ever sees
//! one. Pure rewiring: no computation moves, so no effect gating
//! (kickoff K4 table).
//!
//! After the rewrite, alias defs have zero uses and their inner target
//! is flattened to the terminal id — honest residue that the sweep
//! pass and renderers treat as dead. [`crate::PruneTrivialPhisPass`]
//! later *creates* aliases as tombstones for pruned params, but those
//! are born use-free: nothing ever needs re-resolution, which is why
//! this pass runs once outside the declutter fixpoint group.

use sordec_common::{IrId, ValueId};
use sordec_ir::{LiftedFunction, LiftedIr, LiftedValueDef};

use crate::declutter::rewrite_uses;
use crate::pass::{Pass, PassResult};

/// Unique pipeline name of this pass.
pub const PASS_NAME: &str = "resolve-aliases";

/// Alias uses rewritten to their terminal definition.
const M_ALIASES_RESOLVED: &str = "declutter_aliases_resolved";

/// Defensive bound on alias-chain length. Well-formed waffle output has
/// chains a handful of links deep; the cap turns a malformed cycle into
/// an unresolved (and therefore untouched) alias instead of a hang.
const MAX_CHAIN: u32 = 128;

/// The alias-resolution pass. Stateless; see the module docs.
#[derive(Debug, Default, Clone, Copy)]
pub struct ResolveAliasesPass;

impl Pass<LiftedIr> for ResolveAliasesPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut LiftedIr) -> PassResult {
        let mut result = PassResult::default();
        let mut rewritten: u64 = 0;
        let mut flattened: u64 = 0;

        for func in &mut ir.functions {
            let (r, f) = resolve_function(func);
            rewritten += r;
            flattened += f;
        }

        if rewritten > 0 {
            result.metrics.increment(M_ALIASES_RESOLVED, rewritten as i64);
        }
        result.changed = rewritten > 0 || flattened > 0;
        result
    }
}

/// Resolve one function's aliases. Returns `(uses rewritten, alias defs
/// flattened)`.
fn resolve_function(func: &mut LiftedFunction) -> (u64, u64) {
    let terminal = terminal_map(func);
    if terminal
        .iter()
        .enumerate()
        .all(|(i, v)| v.index() as usize == i)
    {
        return (0, 0); // alias-free: skip the rewrite sweep
    }

    let rewritten = rewrite_uses(func, |v| resolve(&terminal, v));

    // Flatten the alias defs themselves so residue chains read as one
    // hop. Cosmetic (uses are already rewired), but it keeps the
    // tombstone story honest.
    let mut flattened: u64 = 0;
    for (id, value) in func.values.iter_mut() {
        if let LiftedValueDef::Alias(target) = &mut value.def {
            let new = resolve(&terminal, id);
            if new != *target && new != id {
                *target = new;
                flattened += 1;
            }
        }
    }

    debug_assert!(
        crate::lift::validate_lifted_function(func).is_ok(),
        "resolve-aliases broke invariants in {:?}",
        func.id
    );

    (rewritten, flattened)
}

/// Per-value terminal ids: `map[i]` is where `ValueId(i)`'s alias chain
/// ends (itself for non-aliases; for a chain still aliased after
/// [`MAX_CHAIN`] hops — a malformed cycle — wherever the capped chase
/// stopped).
fn terminal_map(func: &LiftedFunction) -> Vec<ValueId> {
    func.values
        .ids()
        .map(|id| {
            let mut current = id;
            let mut hops = 0;
            while let Some(value) = func.values.get(current) {
                match value.def {
                    LiftedValueDef::Alias(target) if hops < MAX_CHAIN => {
                        current = target;
                        hops += 1;
                    }
                    _ => break,
                }
            }
            current
        })
        .collect()
}

/// Look `v` up in the terminal map (identity for out-of-range ids —
/// malformed IR is the validator's concern).
fn resolve(map: &[ValueId], v: ValueId) -> ValueId {
    map.get(v.index() as usize).copied().unwrap_or(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{bb, block, func_with, i32_const, op, target, v};
    use sordec_ir::LiftedTerminator;

    #[test]
    fn operand_uses_rewritten_to_terminal() {
        // v0 const; v1 = Alias(v0); v2 = Add(v1, v1).
        let mut func = func_with(
            vec![
                i32_const(7),
                LiftedValueDef::Alias(v(0)),
                op(waffle::Operator::I32Add, vec![v(1), v(1)]),
            ],
            vec![block(
                0,
                vec![],
                vec![v(0), v(2)],
                LiftedTerminator::Return { values: vec![] },
            )],
        );
        let (rewritten, _) = resolve_function(&mut func);
        assert_eq!(rewritten, 2);
        let LiftedValueDef::Operator { args, .. } = &func.values.get(v(2)).unwrap().def else {
            panic!("v2 stays an operator");
        };
        assert_eq!(args, &[v(0), v(0)]);
    }

    #[test]
    fn terminator_cond_target_args_and_returns_rewritten() {
        // v1 aliases v0 and is used as a branch cond, a target arg, and
        // a return value.
        let mut func = func_with(
            vec![i32_const(1), LiftedValueDef::Alias(v(0))],
            vec![
                block(
                    0,
                    vec![],
                    vec![v(0)],
                    LiftedTerminator::BranchIf {
                        cond: v(1),
                        if_true: target(1, vec![v(1)]),
                        if_false: target(2, vec![]),
                    },
                ),
                block(1, vec![], vec![], LiftedTerminator::Return { values: vec![v(1)] }),
                block(2, vec![], vec![], LiftedTerminator::Unreachable),
            ],
        );
        let (rewritten, _) = resolve_function(&mut func);
        assert_eq!(rewritten, 3);
        let LiftedTerminator::BranchIf { cond, if_true, .. } =
            &func.blocks.get(bb(0)).unwrap().terminator
        else {
            panic!("bb0 stays a branch_if");
        };
        assert_eq!(*cond, v(0));
        assert_eq!(if_true.args, vec![v(0)]);
        let LiftedTerminator::Return { values } = &func.blocks.get(bb(1)).unwrap().terminator
        else {
            panic!("bb1 stays a return");
        };
        assert_eq!(values, &[v(0)]);
    }

    #[test]
    fn alias_chains_flatten_to_terminal() {
        // v2 -> v1 -> v0; a use of v2 must land on v0, and v2's own def
        // must flatten to Alias(v0).
        let mut func = func_with(
            vec![
                i32_const(1),
                LiftedValueDef::Alias(v(0)),
                LiftedValueDef::Alias(v(1)),
                op(waffle::Operator::I32Eqz, vec![v(2)]),
            ],
            vec![block(
                0,
                vec![],
                vec![v(0), v(3)],
                LiftedTerminator::Return { values: vec![] },
            )],
        );
        resolve_function(&mut func);
        let LiftedValueDef::Operator { args, .. } = &func.values.get(v(3)).unwrap().def else {
            panic!("v3 stays an operator");
        };
        assert_eq!(args, &[v(0)]);
        assert_eq!(
            func.values.get(v(2)).unwrap().def,
            LiftedValueDef::Alias(v(0)),
            "chain flattened"
        );
    }

    #[test]
    fn second_run_reports_unchanged() {
        let mut func = func_with(
            vec![
                i32_const(7),
                LiftedValueDef::Alias(v(0)),
                op(waffle::Operator::I32Eqz, vec![v(1)]),
            ],
            vec![block(
                0,
                vec![],
                vec![v(0), v(2)],
                LiftedTerminator::Return { values: vec![] },
            )],
        );
        let (rewritten, _) = resolve_function(&mut func);
        assert_eq!(rewritten, 1);
        assert_eq!(resolve_function(&mut func), (0, 0), "idempotent");
    }

    #[test]
    fn alias_free_function_untouched() {
        let mut func = func_with(
            vec![i32_const(7)],
            vec![block(
                0,
                vec![],
                vec![v(0)],
                LiftedTerminator::Return { values: vec![] },
            )],
        );
        assert_eq!(resolve_function(&mut func), (0, 0));
    }

    #[test]
    fn alias_cycle_terminates_without_hanging() {
        // v0 <-> v1 alias cycle (malformed IR): the chase cap must turn
        // this into a bounded walk, not a hang. Where inside the cycle
        // the use ends up is unspecified.
        let mut func = func_with(
            vec![
                LiftedValueDef::Alias(v(1)),
                LiftedValueDef::Alias(v(0)),
                op(waffle::Operator::I32Eqz, vec![v(1)]),
            ],
            vec![block(
                0,
                vec![],
                vec![v(2)],
                LiftedTerminator::Return { values: vec![] },
            )],
        );
        resolve_function(&mut func);
        let LiftedValueDef::Operator { args, .. } = &func.values.get(v(2)).unwrap().def else {
            panic!("v2 stays an operator");
        };
        assert!(args[0] == v(0) || args[0] == v(1));
    }
}
