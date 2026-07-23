//! Use-counting and the effect classification behind dead-`let` cleanup.
//!
//! The body walk binds every scheduled value as `let vN = <expr>;`. Many of
//! those values are never read — a unit-returning idiom
//! (`storage().set(...)`, `require_auth()`, `events().publish(...)`), an
//! unused helper call, an ABI-marshalling temporary. Binding them adds
//! noise (and a `let () = …` clippy smell). [`Liveness`] counts every read
//! so the emitter can drop the dead binding *name*.
//!
//! Dropping a name must never drop an **effect**. [`is_effectful`] splits
//! the unused bindings: an effectful expression is re-emitted as a bare
//! statement (`storage().set(...);` still runs), while a pure one is elided
//! entirely. Potentially-trapping arithmetic (`/`, `%`) counts as effectful
//! so a divide-by-zero panic is preserved — conservative and
//! semantics-preserving, matching the project's "preserve everything" rule.

use std::collections::HashMap;

use sordec_ir::{BinaryOp, Expr, HighFunction, Region};

use sordec_common::ValueId;

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
        let mut uses: HashMap<ValueId, u32> = HashMap::new();

        // Operand reads inside every scheduled binding.
        func.region.for_each_node(|node| {
            if let Region::Basic(b) = node
                && let Some(block) = func.blocks.get(*b)
            {
                for &vid in &block.bindings {
                    if let Some(binding) = func.bindings.get(vid) {
                        binding.expr.for_each_value_use(|u| *uses.entry(u).or_default() += 1);
                    }
                }
            }
        });

        // Structural reads the region carries directly.
        func.region
            .for_each_value_use(|u| *uses.entry(u).or_default() += 1);

        Self { uses }
    }

    /// Whether a value is never read.
    pub(crate) fn is_unused(&self, vid: ValueId) -> bool {
        !self.uses.contains_key(&vid)
    }
}

/// Whether an expression carries an observable effect that must survive even
/// when its result is unused — so an unused binding of it is re-emitted as a
/// statement rather than elided.
///
/// Exhaustive on [`Expr`] on purpose: a new variant must be classified here
/// (compile error otherwise) before the emitter can silently drop it.
pub(crate) fn is_effectful(expr: &Expr) -> bool {
    match expr {
        // Calls and host operations may mutate ledger/auth/event state.
        Expr::Call { .. }
        | Expr::IndirectCall { .. }
        | Expr::Semantic(_)
        | Expr::Load { .. }
        | Expr::Store { .. }
        | Expr::GlobalGet { .. }
        // A hole diverges (`todo!`) and must stay surfaced.
        | Expr::Unknown { .. } => true,
        // Division/remainder can trap (divide-by-zero); keep the trap.
        Expr::Binary { op: BinaryOp::Div | BinaryOp::Rem, .. } => true,
        // Pure value production — safe to elide when unused.
        Expr::Literal(_)
        | Expr::Use(_)
        | Expr::Unary { .. }
        | Expr::Binary { .. }
        | Expr::Phi { .. } => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::FuncId;
    use sordec_ir::{KnownOp, Literal, SemanticOp, UnaryOp};

    fn v(i: u32) -> ValueId {
        ValueId::new(i)
    }

    #[test]
    fn effectful_ops_are_kept() {
        // Calls / host ops (the struct arm covers Load/Store/GlobalGet too).
        assert!(is_effectful(&Expr::Call { target: FuncId::new(0), args: vec![] }));
        assert!(is_effectful(&Expr::GlobalGet { index: 0 }));
        assert!(is_effectful(&Expr::Semantic(SemanticOp::Known(KnownOp::GetLedgerSequence))));
        // Trapping arithmetic is treated as effectful so the trap is kept.
        assert!(is_effectful(&Expr::Binary { op: BinaryOp::Div, lhs: v(0), rhs: v(1) }));
        assert!(is_effectful(&Expr::Binary { op: BinaryOp::Rem, lhs: v(0), rhs: v(1) }));
    }

    #[test]
    fn pure_ops_are_droppable() {
        assert!(!is_effectful(&Expr::Literal(Literal::I32(7))));
        assert!(!is_effectful(&Expr::Use(v(0))));
        assert!(!is_effectful(&Expr::Unary { op: UnaryOp::Neg, value: v(0) }));
        assert!(!is_effectful(&Expr::Binary { op: BinaryOp::Add, lhs: v(0), rhs: v(1) }));
    }
}
