//! Work done on the way to a trap that no one can see.
//!
//! A panic in a contract compiles to a call into the formatting machinery
//! — `core::result::unwrap_failed`, `core::panicking::panic_fmt` — with
//! its arguments laid out in the caller's frame, and then `unreachable`:
//!
//! ```text
//! store fp+8  <- msg_ptr
//! store fp+12 <- msg_len
//! call unwrap_failed(msg_ptr, msg_len, fp+15, vtable, location)
//! unreachable
//! ```
//!
//! On Soroban the message goes nowhere: the invocation traps, and a trap
//! throws away its linear memory and its globals and rolls back every
//! change the host made for it. Yet the call hands the helper a pointer
//! into the frame, and that one escape keeps the whole frame — and its
//! stack-pointer bookkeeping — in the reconstruction, together with every
//! formatting helper behind it, none of which the source wrote.
//!
//! This pass removes, from the end of a block that ends in `unreachable`,
//! the calls and memory writes that cannot be observed before the trap.
//! The block still ends in the same trap; the backend still spells it
//! `panic!()`.
//!
//! ## Why it is exact
//!
//! Everything removed runs after the last thing in the block that can
//! affect the world outside the invocation, and before a trap that ends
//! the invocation. What it can still touch is this invocation's own
//! linear memory and globals, which the trap discards; whatever host state
//! the invocation changed is rolled back by the trap either way. So no
//! later code, no host function and no other contract can observe a
//! difference — and the invocation fails with the same trap.
//!
//! The removed calls are to *quiet* functions: ones that, on every path
//! and through every function they can call, never call the host. That is
//! what makes "how the invocation fails" the same too: a quiet callee can
//! return (and the `unreachable` traps), trap itself, or run out of budget
//! — it cannot fail with a contract error, which is the one failure a
//! calling contract can tell apart from a trap. Running out of budget is
//! the one premise left standing: a reconstruction does not preserve the
//! instruction count anywhere, so that is not a property this pass alone
//! could keep.
//!
//! ## Beside `refine::trap_call`
//!
//! [`crate::refine::TrapCallInlinePass`] replaces a call to a helper that
//! is *nothing but* a trap with `panic!()`, and declines a helper that
//! stores before dying, on the grounds that a store is an effect. Before a
//! trap it is not one anybody can see: the store lands in memory the trap
//! discards. That pass's rule stays as it is — it runs on the high IR,
//! where a call it declines is still a call — and this one takes the
//! formatting helpers it declines, one layer down, by the argument above.
//!
//! ## Gates
//!
//! - **The block ends in `unreachable`.** Only then is everything after the
//!   removed instructions a trap.
//! - **A call handed only constants stays.** It cannot be what keeps a
//!   frame alive, and it is evidence: `option::unwrap_failed` and its kin are
//!   what tell the recognizers that a guard is the source's `.unwrap()`
//!   and not the SDK's own type check, and `refine::trap_call` already
//!   spells such a call `panic!()`. Removing them measured as guards
//!   reappearing in the corpus (`if !has(k) { panic!() }` before a
//!   `get(k).unwrap()`, an overflow check before an `i128` subtraction).
//!   The walk steps over such a call and goes on.
//! - **Removed, walking back from the end:** a call to a quiet local
//!   function, and an operator whose only effects are writing linear
//!   memory or trapping (a store, `memory.fill`, `memory.copy`). Reads and
//!   arithmetic are stepped over and left for the dead sweep. The walk
//!   **stops** at anything else — a host call, a call to a function that
//!   is not quiet, an indirect call, a write to a global — so nothing
//!   before such an instruction is touched.
//! - **Quiet** is a greatest fixpoint over the module: a function is quiet
//!   unless code that can run in it calls the host, calls a function that
//!   is not quiet, or makes an indirect call that can reach one. An
//!   indirect call can reach any function an element segment declares;
//!   when the segments could not be read, it can reach anything and the
//!   caller is not quiet.
//! - A value the removed instructions produced is read by nothing that
//!   stays: a step-over instruction reading one is removed with it (it is
//!   pure, and after the stop point).

use std::collections::{HashMap, HashSet};

use sordec_common::{FuncId, ValueId};
use sordec_ir::{LiftedFunction, LiftedIr, LiftedTerminator, LiftedValueDef};

use super::calls::CallIndex;
use crate::dataflow::CfgFacts;
use crate::effects::wasm_operator_effects;
use crate::metrics_catalog::MEMORY_TRAP_TAIL_REMOVED;
use crate::pass::{Pass, PassResult};

/// Unique pipeline name of this pass.
pub const PASS_NAME: &str = "memory-trap-tail";

/// Removes unobservable calls and memory writes just before a trap.
#[derive(Debug, Default, Clone, Copy)]
pub struct TrapTailPass;

impl Pass<LiftedIr> for TrapTailPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut LiftedIr) -> PassResult {
        let mut result = PassResult::default();
        let calls = CallIndex::build(ir);
        let quiet = quiet_functions(ir, &calls);
        let mut removed = 0i64;
        for func in &mut ir.functions {
            removed += trim_trap_tails(func, &calls, &quiet) as i64;
        }
        if removed > 0 {
            result.changed = true;
            result.metrics.increment(MEMORY_TRAP_TAIL_REMOVED, removed);
        }
        result
    }
}

/// What one scheduled instruction can do, as far as quietness goes.
enum Reach {
    /// No call at all.
    Local,
    /// A direct call to a local function.
    Calls(FuncId),
    /// An indirect call.
    Indirect,
    /// A call to the host.
    Host,
}

fn reach(func: &LiftedFunction, id: ValueId, calls: &CallIndex) -> Reach {
    let Some(LiftedValueDef::Operator { op, .. }) = func.values.get(id).map(|v| &v.def) else {
        return Reach::Local;
    };
    match &op.0 {
        waffle::Operator::Call { .. } => calls.target(op).map_or(Reach::Host, Reach::Calls),
        waffle::Operator::CallIndirect { .. } => Reach::Indirect,
        _ => Reach::Local,
    }
}

/// Every instruction that can run in `func`.
fn scheduled_ids(func: &LiftedFunction) -> Vec<ValueId> {
    let cfg = CfgFacts::build(func);
    func.blocks
        .iter()
        .filter(|(id, _)| cfg.is_reachable(*id))
        .flat_map(|(_, b)| b.instructions.iter().copied())
        .collect()
}

/// The functions that never call the host, however they run.
fn quiet_functions(ir: &LiftedIr, calls: &CallIndex) -> HashSet<FuncId> {
    // What each function's runnable code calls, gathered once.
    let mut callees: HashMap<FuncId, Vec<Reach>> = HashMap::new();
    for func in &ir.functions {
        let reaches = scheduled_ids(func)
            .into_iter()
            .map(|id| reach(func, id, calls))
            .filter(|r| !matches!(r, Reach::Local))
            .collect();
        callees.insert(func.id, reaches);
    }
    let mut quiet: HashSet<FuncId> = ir.functions.iter().map(|f| f.id).collect();
    loop {
        let before = quiet.len();
        let snapshot = quiet.clone();
        let table_quiet = calls
            .table_functions()
            .is_some_and(|t| t.iter().all(|f| snapshot.contains(f)));
        quiet.retain(|f| {
            callees[f].iter().all(|r| match r {
                Reach::Local => true,
                Reach::Calls(g) => snapshot.contains(g),
                Reach::Indirect => table_quiet,
                Reach::Host => false,
            })
        });
        if quiet.len() == before {
            return quiet;
        }
    }
}

/// Trim every trap tail in `func`. Returns how many instructions went.
fn trim_trap_tails(func: &mut LiftedFunction, calls: &CallIndex, quiet: &HashSet<FuncId>) -> usize {
    let cfg = CfgFacts::build(func);
    let blocks: Vec<_> = func
        .blocks
        .iter()
        .filter(|(id, b)| cfg.is_reachable(*id) && matches!(b.terminator, LiftedTerminator::Unreachable))
        .map(|(id, _)| id)
        .collect();
    let mut total = 0;
    for block_id in blocks {
        let Some(block) = func.blocks.get(block_id) else {
            continue;
        };
        let doomed = doomed_tail(func, &block.instructions, calls, quiet);
        if doomed.is_empty() {
            continue;
        }
        total += doomed.len();
        if let Some(block) = func.blocks.get_mut(block_id) {
            block.instructions.retain(|id| !doomed.contains(id));
        }
    }
    total
}

/// The instructions at the end of a trapping block that can go.
fn doomed_tail(
    func: &LiftedFunction,
    instructions: &[ValueId],
    calls: &CallIndex,
    quiet: &HashSet<FuncId>,
) -> HashSet<ValueId> {
    // Walk back to the stop point, noting what goes and what is stepped
    // over.
    let mut doomed: HashSet<ValueId> = HashSet::new();
    let mut stepped: Vec<ValueId> = Vec::new();
    for &id in instructions.iter().rev() {
        match classify(func, id, calls, quiet) {
            Step::Remove => {
                doomed.insert(id);
            }
            Step::Over => stepped.push(id),
            Step::Stop => break,
        }
    }
    if doomed.is_empty() {
        return doomed;
    }
    // A stepped-over instruction reading something that goes, goes too.
    // `stepped` is in reverse order, so walk it forwards in program order
    // to carry the closure along a chain.
    for &id in stepped.iter().rev() {
        let reads_doomed = match func.values.get(id).map(|v| &v.def) {
            Some(LiftedValueDef::Operator { args, .. }) => args.iter().any(|a| doomed.contains(a)),
            Some(LiftedValueDef::Alias(from) | LiftedValueDef::PickOutput { from, .. }) => doomed.contains(from),
            _ => false,
        };
        if reads_doomed {
            doomed.insert(id);
        }
    }
    doomed
}

/// Whether `value` is an integer constant — a literal, or the address of
/// static data, never anything the caller computed.
fn is_constant(func: &LiftedFunction, value: ValueId) -> bool {
    matches!(
        func.values.get(value).map(|v| &v.def),
        Some(LiftedValueDef::Operator { op, .. })
            if matches!(op.0, waffle::Operator::I32Const { .. } | waffle::Operator::I64Const { .. })
    )
}

enum Step {
    Remove,
    Over,
    Stop,
}

fn classify(func: &LiftedFunction, id: ValueId, calls: &CallIndex, quiet: &HashSet<FuncId>) -> Step {
    let Some(value) = func.values.get(id) else {
        return Step::Stop;
    };
    let (op, args) = match &value.def {
        LiftedValueDef::Operator { op, args } => (op, args),
        LiftedValueDef::Alias(_) | LiftedValueDef::PickOutput { .. } => return Step::Over,
        LiftedValueDef::BlockParam { .. } => return Step::Stop,
    };
    match &op.0 {
        waffle::Operator::Call { .. } => {
            return match calls.target(op) {
                // Handed nothing but constants, it holds nothing of the
                // caller's: it stays, as the evidence of which panic this is.
                Some(g) if quiet.contains(&g) && args.iter().all(|a| is_constant(func, *a)) => Step::Over,
                Some(g) if quiet.contains(&g) => Step::Remove,
                _ => Step::Stop,
            };
        }
        waffle::Operator::CallIndirect { .. } => return Step::Stop,
        _ => {}
    }
    let effects = wasm_operator_effects(&op.0);
    if effects.writes_globals || effects.reads_host || effects.writes_host {
        return Step::Stop;
    }
    if effects.writes_memory {
        Step::Remove
    } else {
        Step::Over
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{block, func_with, i32_const, op, v};
    use sordec_ir::ImportKind;

    fn call(index: u32, args: Vec<ValueId>) -> LiftedValueDef {
        op(
            waffle::Operator::Call {
                function_index: waffle::Func::from(index),
            },
            args,
        )
    }

    fn store(addr: ValueId, value: ValueId) -> LiftedValueDef {
        op(
            waffle::Operator::I32Store {
                memory: waffle::MemoryArg { align: 2, offset: 8, memory: waffle::Memory::from(0) },
            },
            vec![addr, value],
        )
    }

    fn module(functions: Vec<LiftedFunction>, host_imports: usize) -> LiftedIr {
        LiftedIr {
            facts: sordec_ir::WasmFacts {
                imports: (0..host_imports)
                    .map(|i| sordec_ir::Import {
                        index: i as u32,
                        module: "x".into(),
                        name: format!("{i}"),
                        kind: ImportKind::Func(0),
                    })
                    .collect(),
                exports: vec![],
                function_type_indices: vec![],
                function_bodies: vec![],
                function_fingerprints: vec![],
                table_functions: None,
                custom_sections: vec![],
            },
            soroban_facts: None,
            functions,
            memory: sordec_ir::MemoryImage::empty(),
        }
    }

    /// Local function 0 (wasm index `imports`): `{ unreachable }`.
    fn panics() -> LiftedFunction {
        func_with(vec![], vec![block(0, vec![], vec![], LiftedTerminator::Unreachable)])
    }

    /// Local function 1: stores a message word through `k`, calls `callee`
    /// with it, and traps.
    fn panicking_caller(callee: u32) -> LiftedFunction {
        let mut f = func_with(
            vec![
                i32_const(1024),               // v0 address
                i32_const(7),                  // v1
                store(v(0), v(1)),             // v2
                call(callee, vec![v(4)]),      // v3, handed the computed v4
                op(waffle::Operator::I32Add, vec![v(0), v(1)]), // v4
            ],
            vec![block(0, vec![], vec![v(0), v(1), v(4), v(2), v(3)], LiftedTerminator::Unreachable)],
        );
        f.id = FuncId::new(1);
        f
    }

    fn instructions(func: &LiftedFunction) -> Vec<ValueId> {
        func.blocks.get(func.entry).unwrap().instructions.clone()
    }

    #[test]
    fn a_quiet_call_and_the_stores_before_a_trap_go() {
        // No imports: wasm index 0 is local function 0.
        let mut ir = module(vec![panics(), panicking_caller(0)], 0);
        assert!(TrapTailPass.run(&mut ir).changed);
        assert_eq!(instructions(&ir.functions[1]), vec![v(0), v(1), v(4)], "pure values left for the sweep");
        assert!(matches!(
            ir.functions[1].blocks.get(ir.functions[1].entry).unwrap().terminator,
            LiftedTerminator::Unreachable
        ));
        assert!(!TrapTailPass.run(&mut ir).changed, "idempotent");
    }

    #[test]
    fn a_host_call_stops_the_walk() {
        // One import: wasm index 0 is the host, index 1 local function 0.
        let mut ir = module(vec![panics(), panicking_caller(0)], 1);
        assert!(!TrapTailPass.run(&mut ir).changed, "a host call is not removed, and nothing before it is");
    }

    #[test]
    fn a_callee_that_reaches_the_host_is_not_quiet() {
        // Local 0 calls the host (wasm 0) and traps; local 1 calls local 0.
        let mut noisy = func_with(
            vec![call(0, vec![])],
            vec![block(0, vec![], vec![v(0)], LiftedTerminator::Unreachable)],
        );
        noisy.id = FuncId::new(0);
        let mut ir = module(vec![noisy, panicking_caller(1)], 1);
        let calls = CallIndex::build(&ir);
        assert!(quiet_functions(&ir, &calls).is_empty());
        assert!(!TrapTailPass.run(&mut ir).changed);
    }

    #[test]
    fn a_block_that_returns_is_untouched() {
        let mut f = panicking_caller(0);
        f.blocks.get_mut(f.entry).unwrap().terminator = LiftedTerminator::Return { values: vec![] };
        let mut ir = module(vec![panics(), f], 0);
        assert!(!TrapTailPass.run(&mut ir).changed);
    }

    #[test]
    fn a_global_write_stops_the_walk_and_protects_what_precedes_it() {
        let mut f = func_with(
            vec![
                i32_const(1024),
                i32_const(7),
                store(v(0), v(1)),
                op(waffle::Operator::GlobalSet { global_index: waffle::Global::from(0) }, vec![v(0)]),
                call(0, vec![v(5)]),
                op(waffle::Operator::I32Add, vec![v(0), v(1)]),
            ],
            vec![block(0, vec![], vec![v(0), v(1), v(2), v(3), v(5), v(4)], LiftedTerminator::Unreachable)],
        );
        f.id = FuncId::new(1);
        let mut ir = module(vec![panics(), f], 0);
        assert!(TrapTailPass.run(&mut ir).changed);
        assert_eq!(instructions(&ir.functions[1]), vec![v(0), v(1), v(2), v(3), v(5)], "only the call after the global write goes");
    }

    #[test]
    fn an_indirect_call_is_quiet_only_when_every_table_function_is() {
        let mut indirect = func_with(
            vec![op(
                waffle::Operator::CallIndirect {
                    sig_index: waffle::Signature::from(0),
                    table_index: waffle::Table::from(0),
                },
                vec![],
            )],
            vec![block(0, vec![], vec![v(0)], LiftedTerminator::Unreachable)],
        );
        indirect.id = FuncId::new(0);
        let mut ir = module(vec![indirect, panicking_caller(0), panics()], 0);
        ir.functions[2].id = FuncId::new(2);
        // Segments unknown: the indirect call can reach anything.
        assert!(!quiet_functions(&ir, &CallIndex::build(&ir)).contains(&FuncId::new(0)));
        // Segments declare only the quiet function 2.
        ir.facts.table_functions = Some(vec![2]);
        assert!(quiet_functions(&ir, &CallIndex::build(&ir)).contains(&FuncId::new(0)));
    }

    #[test]
    fn a_call_handed_only_constants_stays_and_the_walk_goes_past_it() {
        // store; call func_0(1024); unreachable — the store goes, the call
        // (a constant argument) stays.
        let mut f = func_with(
            vec![i32_const(1024), i32_const(7), store(v(0), v(1)), call(0, vec![v(0)])],
            vec![block(0, vec![], vec![v(0), v(1), v(2), v(3)], LiftedTerminator::Unreachable)],
        );
        f.id = FuncId::new(1);
        let mut ir = module(vec![panics(), f], 0);
        assert!(TrapTailPass.run(&mut ir).changed);
        assert_eq!(instructions(&ir.functions[1]), vec![v(0), v(1), v(3)]);
    }

    #[test]
    fn a_pure_reader_of_a_removed_call_goes_with_it() {
        let mut f = func_with(
            vec![
                i32_const(1024),
                call(0, vec![v(3)]),
                op(waffle::Operator::I32Eqz, vec![v(1)]),
                op(waffle::Operator::I32Eqz, vec![v(0)]),
            ],
            vec![block(0, vec![], vec![v(0), v(3), v(1), v(2)], LiftedTerminator::Unreachable)],
        );
        f.id = FuncId::new(1);
        let mut ir = module(vec![panics(), f], 0);
        assert!(TrapTailPass.run(&mut ir).changed);
        assert_eq!(instructions(&ir.functions[1]), vec![v(0), v(3)]);
    }
}
