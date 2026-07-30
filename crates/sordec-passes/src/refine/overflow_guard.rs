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

use sordec_common::{Diagnostic, LiftDiagnosticCode};
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
            let region = std::mem::replace(&mut func.region, Region::Unreachable);
            func.region = strip(region, &mut elided);
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
fn strip(region: Region, elided: &mut i64) -> Region {
    match region {
        Region::Sequence(items) => {
            seq(items.into_iter().map(|item| strip(item, elided)).collect())
        }
        Region::Scope { out, body } => Region::Scope {
            out,
            body: Box::new(strip(*body, elided)),
        },
        Region::Loop { header, body, kind } => Region::Loop {
            header,
            body: Box::new(strip(*body, elided)),
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
                    arm.body = strip(arm.body, elided);
                    arm
                })
                .collect(),
            default: Box::new(strip(*default, elided)),
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
            Region::If {
                cond,
                then_region: Box::new(strip(*then_region, elided)),
                else_region: else_region.map(|e| Box::new(strip(*e, elided))),
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

/// A guard arm that does nothing but reach the overflow panic.
///
/// The panic glue arrives as `Seq([Basic(call core::panicking), Panic])`,
/// so a `Basic` prefix is expected — but only *ahead of* the classified
/// trap, and only when the arm contains nothing else. Any other region in
/// the arm means it does work, and work is not something to delete.
fn is_overflow_trap(region: &Region) -> bool {
    match region {
        Region::Panic {
            kind: PanicKind::ArithOverflow,
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

    fn run(region: Region) -> (Region, i64) {
        let mut n = 0;
        let out = strip(region, &mut n);
        (out, n)
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
