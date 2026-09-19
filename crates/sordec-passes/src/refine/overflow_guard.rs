//! Elide rustc's arithmetic overflow check.
//!
//! Under `overflow-checks = true`, rustc compiles `a + b` into a wrapping
//! add, a carry test, and a branch to the panic glue. The source wrote an
//! expression; the binary carries a branch. `super::panic_recover` proves
//! which traps are that check ([`PanicKind::ArithOverflow`]) and this pass
//! removes the guard they sit in.
//!
//! ```text
//! s = a + b                       s = a + b
//! if s <u a { panic }      →
//! ```
//!
//! ## Why removing it preserves behaviour
//!
//! **Relocation, not unreachability.** The trap is entirely reachable —
//! `add(u64::MAX, 1)` takes it. It is safe to delete here because our own
//! re-emission puts it back:
//!
//! - we emit the arithmetic as `a + b`;
//! - `sordec-backend`'s emitted `Cargo.toml` pins
//!   `[profile.release] overflow-checks = true`, and that flag exists for
//!   exactly this reason — its docstring says "without it, arithmetic wraps
//!   where the original trapped — a behavioural difference we introduced
//!   ourselves";
//! - `sordec-diffexec` recompiles with `--release`, so the flag applies
//!   where behaviour is measured.
//!
//! rustc therefore regenerates the identical check from the identical
//! source construct. Keeping ours as well would emit the guard twice.
//!
//! This is the same argument class as `crate::marshalling::guard`, which
//! relocates an SDK argument check into the `#[contractimpl]` wrapper — and
//! it is checked the same way, by a test rather than by reasoning alone.
//! `sordec-diffexec`'s argument tables deliberately include `u64::MAX` and
//! offset each parameter's index so the sweep hits `(MAX, 1)` — its comment
//! says "which is what actually overflows". If this elision were wrong, the
//! reconstruction would wrap where the original traps and `hello-add`'s
//! behaviour score would fall off 1.0000.
//!
//! ## What it will not touch
//!
//! Only an else-less guard whose taken arm does nothing but reach the panic
//! glue. In particular a guard whose arm carries recovered work, or whose
//! trap is a `panic_with_error!`, is contract logic and stays — those never
//! reach `ArithOverflow` in the first place, because the classification
//! keys on the arithmetic derivation of the *condition* rather than on the
//! comparison's shape.
//!
//! Corpus reach is small and deliberately so: 6 sites, one per fixture
//! except `attestation`. The check is ubiquitous in the wasm but rustc
//! outlines most of them into shared helpers, and those helper bodies are
//! the `sub`-borrow shape.

use std::collections::HashSet;

use sordec_common::{BlockId, Diagnostic, LiftDiagnosticCode};
use sordec_ir::{HighFunction, HighIr, PanicKind, Region};

use super::debug_validate;
use crate::metrics_catalog::REFINE_OVERFLOW_GUARDS_ELIDED as M_ELIDED;
use crate::pass::{Pass, PassResult};
use crate::structuring::seq;

/// Unique pipeline name of this pass.
pub const PASS_NAME: &str = "refine-overflow-guard";

/// Removes the compiler-inserted arithmetic overflow guard. Stateless.
#[derive(Debug, Default, Clone, Copy)]
pub struct OverflowGuardElisionPass;

impl Pass<HighIr> for OverflowGuardElisionPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let mut elided: i64 = 0;
        for func in &mut ir.functions {
            let before = elided;
            let inert = inert_blocks(func);
            let region = std::mem::replace(&mut func.region, Region::Unreachable);
            func.region = strip(region, &mut elided, &inert);
            // One diagnostic per removal. Deleting a reachable trap is a
            // behavioural claim; it should be reviewable without diffing
            // two decompilations.
            for _ in 0..(elided - before) {
                result.diagnostics.push(Diagnostic::info(
                    LiftDiagnosticCode::MarshallingGuardElided,
                    format!(
                        "{}arithmetic overflow check removed: the source wrote the \
                         arithmetic, and `overflow-checks = true` regenerates the guard \
                         from it",
                        func_prefix(func)
                    ),
                ));
            }
        }
        if elided > 0 {
            result.metrics.increment(M_ELIDED, elided);
            result.changed = true;
        }
        debug_validate(ir, PASS_NAME);
        result
    }
}

/// `"fn <name>: "` when the function has a recovered name, so a diagnostic
/// points at a place rather than floating free.
fn func_prefix(func: &HighFunction) -> String {
    match func.signature.as_ref().map(|s| &s.name).or(func.name.as_ref()) {
        Some(name) => format!("fn {name}: "),
        None => format!("func{}: ", sordec_common::IrId::index(func.id)),
    }
}

/// Bottom-up rewrite dropping every overflow guard.
fn strip(region: Region, elided: &mut i64, inert: &HashSet<BlockId>) -> Region {
    match region {
        Region::Sequence(items) => {
            seq(items.into_iter().map(|item| strip(item, elided, inert)).collect())
        }
        Region::Scope { out, body } => Region::Scope {
            out,
            body: Box::new(strip(*body, elided, inert)),
        },
        Region::Loop { header, body, kind } => Region::Loop {
            header,
            body: Box::new(strip(*body, elided, inert)),
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
                    arm.body = strip(arm.body, elided, inert);
                    arm
                })
                .collect(),
            default: Box::new(strip(*default, elided, inert)),
            dispatch,
        },
        Region::If {
            cond,
            then_region,
            else_region,
        } => {
            if else_region.is_none() && is_overflow_trap(&then_region) {
                *elided += 1;
                return seq(vec![]);
            }
            let then_region = strip(*then_region, elided, inert);
            let else_region = else_region.map(|e| strip(*e, elided, inert));
            // Both arms now empty: the division guards come in a pair, and
            // the `d == -1` test that selects between them carries no trap
            // of its own. Once the trap inside it goes, the branch decides
            // between doing nothing and doing nothing.
            if empty(&then_region, inert) && else_region.as_ref().is_none_or(|e| empty(e, inert)) {
                return seq(vec![]);
            }
            Region::If {
                cond,
                then_region: Box::new(then_region),
                else_region: else_region.map(Box::new),
            }
        }
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

/// Blocks that compute nothing anyone reads: no bindings at all, or only
/// pure ones the rest of the function has stopped reading. Dropping the
/// branch that reaches such a block drops nothing.
fn inert_blocks(func: &mut HighFunction) -> HashSet<BlockId> {
    let order = crate::marshalling::sret::emission_order(func);
    let dead = crate::dataflow::dead_residue(func, &order);
    let candidates: HashSet<BlockId> = func
        .blocks
        .iter()
        .filter(|(_, block)| block.bindings.iter().all(|v| dead.contains(v)))
        .map(|(id, _)| id)
        .collect();
    // Everything those blocks define is about to lose its definition, so
    // a dead binding still *naming* one has to let go first: the IR
    // validator does not know which reads are dead, and a dangling name
    // is a broken invariant however unreachable the reader.
    let doomed: HashSet<sordec_common::ValueId> = func
        .blocks
        .iter()
        .filter(|(id, _)| candidates.contains(id))
        .flat_map(|(_, block)| block.bindings.iter().copied())
        .collect();
    let dangling: Vec<sordec_common::ValueId> = func
        .bindings
        .iter()
        .filter(|(id, _)| dead.contains(id) && !doomed.contains(id))
        .filter(|(_, b)| {
            let mut names = false;
            b.expr.for_each_value_use(|u| names |= doomed.contains(&u));
            names
        })
        .map(|(id, _)| id)
        .collect();
    for id in dangling {
        if let Some(b) = func.bindings.get_mut(id) {
            b.expr = sordec_ir::Expr::Literal(sordec_ir::Literal::Unit);
            b.add_provenance(sordec_common::Provenance::new(
                PASS_NAME,
                sordec_common::ProvenanceSource::DataFlow,
                "named a value in a block the guard removal is about to drop",
            ));
        }
    }
    // Named from outside the candidates. Bindings *inside* them name each
    // other freely — that is what a block is — and they leave together.
    let mut named: HashSet<sordec_common::ValueId> = HashSet::new();
    for (id, b) in func.bindings.iter() {
        if doomed.contains(&id) {
            continue;
        }
        b.expr.for_each_value_use(|u| {
            named.insert(u);
        });
    }
    func.region.for_each_value_use(|u| {
        named.insert(u);
    });
    candidates
        .into_iter()
        .filter(|id| {
            func.blocks.get(*id).is_some_and(|b| b.bindings.iter().all(|v| !named.contains(v)))
        })
        .collect()
}

/// A region that does nothing at all.
fn empty(region: &Region, inert: &HashSet<BlockId>) -> bool {
    match region {
        Region::Sequence(items) => items.iter().all(|item| empty(item, inert)),
        Region::Basic(b) => inert.contains(b),
        // A fall-through to the join. It assigns the join's block
        // parameters; with nothing to assign it is the arm doing nothing
        // and then arriving, which is what both arms do anyway.
        Region::Transfer { transfer, .. } => transfer.is_empty(),
        _ => false,
    }
}

/// A guard arm that does nothing but reach the overflow panic.
///
/// The panic glue arrives as `Seq([Basic(call core::panicking), Panic])`,
/// so a `Basic` prefix is expected — but only *ahead of* the classified
/// trap, and only when the arm contains nothing else. Any other region in
/// the arm means it does work, and work is not something to delete.
fn is_overflow_trap(region: &Region) -> bool {
    match region {
        Region::Panic {
            kind: PanicKind::ArithOverflow | PanicKind::DivisionGuard,
        } => true,
        Region::Sequence(items) => {
            items.last().is_some_and(is_overflow_trap)
                && items[..items.len() - 1]
                    .iter()
                    .all(|item| matches!(item, Region::Basic(_)))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{BlockId, IrId, ValueId};

    fn bb(i: u32) -> BlockId {
        BlockId::from_index(i)
    }

    fn v(i: u32) -> ValueId {
        ValueId::from_index(i)
    }

    fn panic_of(kind: PanicKind) -> Region {
        Region::Panic { kind }
    }

    /// hello-add's shape: the guard's arm calls the panic glue, then traps.
    fn guard(kind: PanicKind) -> Region {
        Region::If {
            cond: v(22),
            then_region: Box::new(Region::Sequence(vec![
                Region::Basic(bb(2)),
                panic_of(kind),
            ])),
            else_region: None,
        }
    }

    /// No block is inert unless a test says so: these shapes are about
    /// the trap, not about what the arms compute.
    fn run(region: Region) -> (Region, i64) {
        run_with(region, &HashSet::new())
    }

    fn run_with(region: Region, inert: &HashSet<BlockId>) -> (Region, i64) {
        let mut n = 0;
        let out = strip(region, &mut n, inert);
        (out, n)
    }

    /// The `MIN / -1` pair: the inner guard holds the trap, the outer
    /// branch only chooses whether to reach it. Both go.
    #[test]
    fn a_branch_left_with_nothing_in_either_arm_goes_too() {
        let inner = guard(PanicKind::DivisionGuard);
        let region = Region::If {
            cond: ValueId::from_index(9),
            then_region: Box::new(Region::Basic(bb(7))),
            else_region: Some(Box::new(inner)),
        };
        let inert: HashSet<BlockId> = [bb(7)].into_iter().collect();
        let (out, n) = run_with(region, &inert);
        assert_eq!(n, 1);
        assert!(matches!(out, Region::Sequence(ref s) if s.is_empty()));
    }

    /// The fall-through arms carry an empty block-parameter transfer,
    /// which assigns nothing.
    #[test]
    fn a_branch_whose_arms_only_fall_through_goes() {
        let region = Region::If {
            cond: ValueId::from_index(9),
            then_region: Box::new(Region::Transfer { target: bb(7), transfer: vec![] }),
            else_region: Some(Box::new(Region::Sequence(vec![
                guard(PanicKind::DivisionGuard),
                Region::Transfer { target: bb(7), transfer: vec![] },
            ]))),
        };
        let (out, n) = run_with(region, &HashSet::new());
        assert_eq!(n, 1);
        assert!(matches!(out, Region::Sequence(ref s) if s.is_empty()));
    }

    /// A transfer that assigns something is work.
    #[test]
    fn a_branch_whose_arm_assigns_a_parameter_stays() {
        let region = Region::If {
            cond: ValueId::from_index(9),
            then_region: Box::new(Region::Transfer {
                target: bb(7),
                transfer: vec![(ValueId::from_index(1), ValueId::from_index(2))],
            }),
            else_region: Some(Box::new(guard(PanicKind::DivisionGuard))),
        };
        let (out, n) = run_with(region, &HashSet::new());
        assert_eq!(n, 1);
        assert!(matches!(out, Region::If { .. }));
    }

    /// An arm that still computes something keeps its branch.
    #[test]
    fn a_branch_whose_other_arm_works_stays() {
        let region = Region::If {
            cond: ValueId::from_index(9),
            then_region: Box::new(Region::Basic(bb(7))),
            else_region: Some(Box::new(guard(PanicKind::DivisionGuard))),
        };
        let (out, n) = run_with(region, &HashSet::new());
        assert_eq!(n, 1, "the guard itself still goes");
        assert!(matches!(out, Region::If { .. }), "the branch stays");
    }

    #[test]
    fn an_overflow_guard_is_removed() {
        let (out, n) = run(guard(PanicKind::ArithOverflow));
        assert_eq!(n, 1);
        assert!(matches!(out, Region::Sequence(ref s) if s.is_empty()));
    }

    #[test]
    fn a_bare_trap_guard_of_the_same_shape_stays() {
        // Identical structurally — only the classification differs, which
        // is the whole point of recognizing before eliding.
        let (out, n) = run(guard(PanicKind::Bare));
        assert_eq!(n, 0);
        assert!(matches!(out, Region::If { .. }));
    }

    #[test]
    fn an_unwrap_guard_stays() {
        assert_eq!(run(guard(PanicKind::Unwrap)).1, 0);
    }

    #[test]
    fn a_two_armed_guard_stays() {
        // An `else` means the condition selects between two behaviours; the
        // overflow check never has one.
        let region = Region::If {
            cond: v(22),
            then_region: Box::new(panic_of(PanicKind::ArithOverflow)),
            else_region: Some(Box::new(Region::Basic(bb(3)))),
        };
        assert_eq!(run(region).1, 0);
    }

    #[test]
    fn an_arm_that_does_more_than_trap_stays() {
        // A `Return` alongside the trap means the arm has a second exit;
        // deleting it would delete that too.
        let region = Region::If {
            cond: v(22),
            then_region: Box::new(Region::Sequence(vec![
                Region::Return { values: vec![] },
                panic_of(PanicKind::ArithOverflow),
            ])),
            else_region: None,
        };
        assert_eq!(run(region).1, 0);
    }

    #[test]
    fn a_bare_classified_trap_with_no_prefix_is_removed() {
        // Not every overflow guard goes through the glue helper; rustc
        // inlines the trap when the function is small enough.
        let region = Region::If {
            cond: v(22),
            then_region: Box::new(panic_of(PanicKind::ArithOverflow)),
            else_region: None,
        };
        assert_eq!(run(region).1, 1);
    }

    #[test]
    fn guards_nested_in_every_region_kind_are_reached() {
        for wrap in [
            |g| Region::Scope {
                out: bb(9),
                body: Box::new(g),
            },
            |g| Region::Loop {
                header: bb(9),
                body: Box::new(g),
                kind: sordec_ir::LoopKind::Unclassified,
            },
            |g: Region| Region::If {
                cond: v(1),
                then_region: Box::new(g),
                else_region: None,
            },
        ] {
            assert_eq!(run(wrap(guard(PanicKind::ArithOverflow))).1, 1);
        }
    }

    #[test]
    fn a_second_run_changes_nothing() {
        let (once, first) = run(guard(PanicKind::ArithOverflow));
        assert_eq!(first, 1);
        assert_eq!(run(once).1, 0);
    }
}
