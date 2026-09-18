//! Use-counting and the effect classification behind dead-`let` cleanup.
//!
//! The body walk binds every scheduled value as `let vN = <expr>;`. Many of
//! those values are never read — a unit-returning idiom
//! (`storage().set(...)`, `require_auth()`, `events().publish(...)`), an
//! unused helper call, an ABI-marshalling temporary. Binding them adds
//! noise (and a `let () = …` clippy smell). [`Liveness`] counts every read
//! so the emitter can drop the dead binding *name*.
//!
//! Dropping a name must never drop an **effect**. [`survives_unused`]
//! splits the unused bindings: an effectful expression is re-emitted as a
//! bare statement (`storage().set(...);` still runs), while a pure one is
//! elided entirely. Potentially-trapping arithmetic (`/`, `%`) counts as
//! effectful so a divide-by-zero panic is preserved — conservative and
//! semantics-preserving, matching the project's "preserve everything" rule.
//!
//! ## Why a hole is judged by a different rule
//!
//! That split assumes re-emitting *preserves* the effect, and for a
//! rendered expression it does: `message.len();` still traps exactly when
//! the original did. A **hole** does not. `todo!()` diverges
//! *unconditionally*, so re-emitting an unread hole does not conserve a
//! conditional trap — it fabricates a certain one where the original had
//! at most a possible one. Keeping it "to be safe" is therefore not the
//! conservative choice; it is the choice that guarantees the divergence it
//! was meant to guard against, on a path the contract actually runs.
//!
//! So a hole is kept only where dropping it would silently lose a **state
//! change** — a host write, a memory write, a global write. There the loud
//! `todo!()` is honest: we could not reproduce that write, and saying so
//! beats pretending it did not happen. A hole that is pure, or that merely
//! *might* trap, is dropped, because dropping is strictly closer to the
//! original than an unconditional panic.
//!
//! Nothing is concealed by this. An unrecovered op is still counted and
//! reported by the coverage layer (`UnrecognizedScanPass`), which is where
//! "we did not recover this" belongs.
//!
//! Measured on `attestation`: the dead holes left behind by guard elision
//! and by lowering `symbol_new` were the whole gap between `behavior`
//! 0.4000 and 1.0000 — the reconstruction compiled and then panicked on
//! its first statement.
//!
//! Effects come from [`sordec_passes::effects::expr_effects`], the same
//! analysis the passes use, so the emitter cannot drift from the
//! pipeline's view of what an op does.

use std::collections::{HashMap, HashSet};

use sordec_ir::{BinaryOp, Expr, HighFunction, Region, SemanticOp};
use sordec_passes::effects::expr_effects;

use sordec_common::ValueId;

use crate::rust::fold::Fold;
use crate::rust::idiom;

/// Per-function read counts for every value the body emits.
pub(crate) struct Liveness {
    /// `uses[v]` = the number of times `v` is read. Absent ⇒ zero reads.
    uses: HashMap<ValueId, u32>,
}

impl Liveness {
    /// Count reads across exactly the code the body emits: the operands of
    /// every scheduled binding, plus the region's structural reads
    /// (if-conditions, switch selectors, phi-transfer *sources*, returns).
    ///
    /// This mirrors the emission set precisely — it walks the same
    /// `Region::Basic` blocks the body walk emits, so "unused" means "unused
    /// by emitted code", not merely absent from the arena. There is no
    /// double count: [`Region::for_each_value_use`] deliberately skips
    /// `Basic` blocks (their operands are indexed here) and does not count a
    /// phi transfer's *destination* as a read — a phi written but never read
    /// is correctly dead.
    pub(crate) fn build(func: &HighFunction) -> Self {
        Self::build_excluding(func, &HashSet::new(), &Fold::build(func))
    }

    /// [`Liveness::build`], but treating every binding in `dropped` as
    /// already gone: its operand reads do not count.
    ///
    /// This is what makes dead-binding cleanup transitive. Dropping a
    /// binding can be what makes *its* operands dead, and one pass cannot
    /// see that — `attestation`'s `domain` needs two rounds, because the
    /// `Symbol::new` lowering discards a pointer whose producer is itself
    /// only read by the thing that discarded it.
    ///
    /// Reads are counted against the value they print as ([`Fold::reads`]):
    /// a rename's reads are its target's, and a literal printed in place is
    /// read by nobody.
    pub(crate) fn build_excluding(func: &HighFunction, dropped: &HashSet<ValueId>, fold: &Fold) -> Self {
        let mut uses: HashMap<ValueId, u32> = HashMap::new();
        let mut count = |u: ValueId| {
            if let Some(v) = fold.reads(u) {
                *uses.entry(v).or_default() += 1;
            }
        };

        // Operand reads inside every scheduled binding that survives.
        func.region.for_each_node(|node| {
            if let Region::Basic(b) = node
                && let Some(block) = func.blocks.get(*b)
            {
                for &vid in &block.bindings {
                    if dropped.contains(&vid) {
                        continue;
                    }
                    let Some(binding) = func.bindings.get(vid) else {
                        continue;
                    };
                    rendered_reads(func, binding, &mut count);
                }
            }
        });

        // Structural reads the region carries directly.
        func.region.for_each_value_use(&mut count);

        Self { uses }
    }

    /// Whether a value is never read.
    pub(crate) fn is_unused(&self, vid: ValueId) -> bool {
        !self.uses.contains_key(&vid)
    }
}

/// Whether an unread binding must still be emitted, as a bare statement,
/// rather than elided entirely.
///
/// `rendered_as_hole` says whether the emitter managed to render `expr` as
/// real Rust or fell back to a `todo!(…)`, and it changes the question
/// being asked — see the module docs.
///
/// A **rendered** expression keeps [`is_effectful`]'s classification
/// unchanged. That rule is deliberately generous about recognized ops: an
/// unread `e.ledger().sequence();` is a runtime no-op, so keeping it
/// cannot break behaviour, and it is a *true* statement about a host call
/// the contract really makes — dropping it would cost semantic recall for
/// nothing.
///
/// A **hole** is kept only when it writes state, because that generosity
/// stops being free the moment the statement is `todo!()`.
pub(crate) fn survives_unused(expr: &Expr, rendered_as_hole: bool) -> bool {
    if !rendered_as_hole {
        return is_effectful(expr);
    }
    let effects = expr_effects(expr);
    // Reads are not kept either: an unread load or global-get changes
    // nothing observable, so standing in for one with an unconditional
    // panic is strictly worse than dropping it.
    effects.writes_host || effects.writes_memory || effects.writes_globals
}

/// The operands a binding reads *as the renderer prints it*.
///
/// A lowering that renders none of its operands reads none of them,
/// however many the IR records; one that renders some reads exactly
/// those. Every analysis that asks "who reads this value?" on behalf of
/// the emitter has to agree on the answer — liveness and the escape test
/// disagreeing means a value hoisted to the body top and then never
/// assigned.
pub(crate) fn rendered_reads(
    func: &HighFunction,
    binding: &sordec_ir::Binding,
    mut f: impl FnMut(ValueId),
) {
    if let Expr::Semantic(SemanticOp::Known(op)) = &binding.expr {
        if idiom::ignores_operands(op) {
            return;
        }
        if let Some(reads) = idiom::rendered_operands(func, op) {
            for u in reads {
                f(u);
            }
            return;
        }
    }
    binding.expr.for_each_value_use(f);
}

/// Whether an expression carries an observable effect that must survive
/// even when its result is unused.
///
/// Exhaustive on [`Expr`] on purpose: a new variant must be classified
/// here (compile error otherwise) before the emitter can silently drop it.
fn is_effectful(expr: &Expr) -> bool {
    match expr {
        // Calls and host operations may mutate ledger/auth/event state.
        Expr::Call { .. }
        | Expr::IndirectCall { .. }
        | Expr::Semantic(_)
        | Expr::Load { .. }
        | Expr::Store { .. }
        | Expr::GlobalGet { .. }
        | Expr::Unknown { .. } => true,
        // Division/remainder can trap (divide-by-zero); keep the trap.
        Expr::Binary { op: BinaryOp::Div | BinaryOp::Rem, .. } => true,
        // Pure value production — safe to elide when unused. A projection
        // only names a component of an already-produced value; dropping an
        // unread one cannot drop the producer, which is bound separately.
        Expr::Literal(_)
        | Expr::Use(_)
        | Expr::Unary { .. }
        | Expr::Binary { .. }
        | Expr::Phi { .. }
        | Expr::Project { .. }
        | Expr::WideJoin { .. }
        | Expr::Field { .. }
        | Expr::Struct { .. } => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{FuncId, UnknownReason};
    use sordec_ir::{
        BinaryOp, KnownOp, Literal, MemWidth, SemanticOp, UnaryOp, WasmOpcodeKind,
    };

    fn v(i: u32) -> ValueId {
        ValueId::new(i)
    }

    /// A rendered (non-hole) expression.
    fn rendered(expr: &Expr) -> bool {
        survives_unused(expr, false)
    }

    /// The same expression, but the emitter could only produce `todo!(…)`.
    fn hole(expr: &Expr) -> bool {
        survives_unused(expr, true)
    }

    fn unknown(op_kind: WasmOpcodeKind) -> Expr {
        Expr::Unknown {
            op_kind,
            args: vec![],
            reason: UnknownReason::InsufficientEvidence,
        }
    }

    #[test]
    fn effectful_rendered_ops_are_kept() {
        assert!(rendered(&Expr::Call { target: FuncId::new(0), args: vec![] }));
        assert!(rendered(&Expr::GlobalGet { index: 0 }));
        assert!(rendered(&Expr::Semantic(SemanticOp::Known(KnownOp::GetLedgerSequence))));
        // Trapping arithmetic stays: the emitted statement really does trap.
        assert!(rendered(&Expr::Binary { op: BinaryOp::Div, lhs: v(0), rhs: v(1) }));
        assert!(rendered(&Expr::Binary { op: BinaryOp::Rem, lhs: v(0), rhs: v(1) }));
    }

    #[test]
    fn pure_ops_are_droppable() {
        for expr in [
            Expr::Literal(Literal::I32(7)),
            Expr::Use(v(0)),
            Expr::Unary { op: UnaryOp::Neg, value: v(0) },
            Expr::Binary { op: BinaryOp::Add, lhs: v(0), rhs: v(1) },
        ] {
            assert!(!rendered(&expr), "{expr:?} is pure");
            assert!(!hole(&expr), "{expr:?} is pure");
        }
    }

    #[test]
    fn a_pure_recovered_op_is_kept_when_rendered_and_dropped_when_a_hole() {
        // `ValTagCheck` is pure bit arithmetic. Rendered, keeping it costs
        // nothing at runtime and may still carry a fact; as a hole it is
        // the guard-elision residue that made `attestation` panic.
        let tag_check = Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck {
            value: v(0),
            tag: 72,
            negated: true,
        }));
        assert!(rendered(&tag_check));
        assert!(!hole(&tag_check));
    }

    #[test]
    fn a_hole_that_writes_state_is_kept() {
        // Dropping these would silently lose a write, and the loud
        // `todo!()` is the honest report that we could not reproduce it.
        assert!(hole(&Expr::Store {
            addr: v(0),
            value: v(1),
            offset: 0,
            width: MemWidth::W8,
        }));
        assert!(hole(&unknown(WasmOpcodeKind::GlobalSet)));
        // An unrecognized host call fails closed to WORST, which writes.
        assert!(hole(&Expr::Semantic(SemanticOp::Unknown {
            host_module: "l".to_string(),
            host_fn: "_".to_string(),
            args: vec![],
            reason: UnknownReason::InsufficientEvidence,
        })));
    }

    #[test]
    fn a_hole_that_only_reads_or_traps_is_dropped() {
        // The case that cost `attestation` its behaviour score: an unread
        // `i64.extend_i32_u` buckets as `Conversion`, which is may_trap
        // only. Standing in for it with `todo!()` turns a never-taken trap
        // into a certain panic on the entrypoint's first statement.
        assert!(!hole(&unknown(WasmOpcodeKind::Conversion)));
        assert!(!hole(&Expr::GlobalGet { index: 0 }));
        assert!(!hole(&Expr::Load {
            addr: v(0),
            offset: 0,
            width: MemWidth::W8,
            signed: None,
            ty: sordec_ir::IrType::Unknown(UnknownReason::InsufficientEvidence),
        }));
        // …but the same expressions, once the emitter can render them, are
        // kept: a real statement reproduces the trap faithfully.
        assert!(rendered(&unknown(WasmOpcodeKind::Conversion)));
        assert!(rendered(&Expr::GlobalGet { index: 0 }));
    }
}
