//! Region-refinement passes (Phase-3 D-category).
//!
//! The structurer emits a *faithful* region tree — every guard is a
//! `Break` to a labeled scope inside a fully else-nested `If` cascade,
//! because that is literally what the compiler's CFG says. These passes
//! undo the specific compiler transforms standing between that tree and
//! the source shape: guard-clause recovery (early exits stop nesting),
//! trap inlining (the shared `unreachable` block LLVM tail-merged goes
//! back to its guards), condition-polarity normalization (the exit arm
//! reads without negation).
//!
//! ## Discipline
//!
//! - **Undo, never invent** (research R2, SAILR): every rewrite here
//!   reverses a known rustc/LLVM transform. No boolean synthesis, no
//!   condition invention — a shape we cannot faithfully un-transform
//!   stays as the structurer emitted it.
//! - **Effects gate motion** (kickoff K4): nothing is moved or
//!   duplicated past the effect table's word. Wave 1 needs no
//!   exception: the only duplicated content is zero-binding
//!   terminators.
//! - **Monotone toward canonical form**: each pass strictly reduces a
//!   measure (nesting depth, `{Scope, Break}` node count) or moves
//!   one-way (polarity toward exit-in-`then`), so the fixpoint group
//!   converges.
//! - **Self-guarded**: every pass re-validates the IR after rewriting
//!   (debug builds), so a bad splice fails at the pass that made it,
//!   not three passes later.

mod guard_clause;
mod polarity;

pub use guard_clause::GuardClausePass;
pub use polarity::PolarityPass;

use sordec_ir::{HighIr, Region, Validate as _};

/// Is `region` a *bare exit* — one node that leaves the enclosing
/// context carrying no values: an empty-transfer `Break`/`Continue`, a
/// `Return`, or a trap?
///
/// This is the guard-arm shape. Value-carrying breaks (phi transfers)
/// are merge arms, not guards, and never classify as bare.
pub(crate) fn is_bare_exit(region: &Region) -> bool {
    match region {
        Region::Break { transfer, .. } | Region::Continue { transfer, .. } => transfer.is_empty(),
        Region::Return { .. } | Region::Unreachable => true,
        _ => false,
    }
}

/// Does control never fall out of `region` onto its successor in the
/// parent sequence?
///
/// The guard-clause rewrite hoists an `else` body after its `if`, which
/// is sound only when the `then` provably leaves the context. The
/// analysis is conservative: `Scope` reports `false` (a `Break` to its
/// own `out` resumes exactly at the successor), and so does anything
/// unknown.
pub(crate) fn is_terminating(region: &Region) -> bool {
    match region {
        Region::Break { .. }
        | Region::Continue { .. }
        | Region::Return { .. }
        | Region::Unreachable => true,
        Region::Sequence(items) => items.last().is_some_and(is_terminating),
        Region::If {
            then_region,
            else_region,
            ..
        } => else_region
            .as_ref()
            .is_some_and(|e| is_terminating(then_region) && is_terminating(e)),
        Region::Switch { arms, default, .. } => {
            arms.iter().all(|arm| is_terminating(&arm.body)) && is_terminating(default)
        }
        // A well-formed loop body always ends in its back edge or an
        // exit through an enclosing label — control never falls to the
        // loop's successor. A body that would fall through (ill-formed)
        // reports false, which only suppresses the rewrite.
        Region::Loop { body, .. } => is_terminating(body),
        // Breaks to this scope's own `out` resume at the successor.
        Region::Scope { .. } => false,
        Region::Basic(_) | Region::Transfer { .. } | Region::Unstructured { .. } => false,
    }
}

/// Debug-build guardrail run by every refinement pass after rewriting:
/// a region splice that breaks an invariant (label enclosure, transfer
/// integrity, emission-order dominance — the A5 set) fails *here*, at
/// the pass that made it. Release builds skip the walk.
pub(crate) fn debug_validate(ir: &HighIr, pass: &'static str) {
    #[cfg(debug_assertions)]
    if let Err(e) = ir.validate() {
        panic!("refinement pass `{pass}` broke an IR invariant: {e:?}");
    }
    #[cfg(not(debug_assertions))]
    let _ = (ir, pass);
}
