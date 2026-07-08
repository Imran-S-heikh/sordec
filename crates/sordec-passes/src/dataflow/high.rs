//! Constant tracing over `HighIr`.
//!
//! The `LiftedFunction` tracer ([`crate::dataflow::trace_const()`]) walks
//! `LiftedValueDef`s. Recognizers, though, run as `Pass<HighIr>` and see
//! the `Expr` tree instead. This module is the HighIr-level counterpart.
//!
//! Tracing over HighIr is simpler than over LiftedIr: the lowering step
//! already folded WASM `*Const` operators into [`Expr::Literal`], and
//! `Alias` indirection lowered to [`Expr::Use`]. (`PickOutput` lowers
//! to `Expr::Unknown` — a multi-result projection is not transparent,
//! so hitting one honestly terminates a trace rather than chasing
//! through it.) The tracer therefore only chases `Use` chains to their
//! terminal binding.

use sordec_common::{IrId, ValueId};
use sordec_ir::{Expr, HighFunction, Literal};

/// Default chase depth for [`trace_literal`] / [`resolve_use`].
///
/// A defensive bound against malformed `Use` cycles (which well-formed
/// HighIr never contains). Real use-chains are a handful of links deep.
pub const DEFAULT_USE_DEPTH: u32 = 128;

/// Follow `Expr::Use` links from `value` and, if the terminal binding is
/// an `Expr::Literal`, return that literal.
///
/// Returns `None` when the terminal binding is anything other than a
/// literal (an operator, a semantic op, a phi, ...), when `value` is not
/// in the function's binding arena, or when the chase exceeds
/// [`DEFAULT_USE_DEPTH`].
///
/// This is the recognizer's operand resolver: a pattern like
/// `(x << 8) | 6` needs the `6` operand resolved to `Literal::I64(6)`
/// even when it arrives through an intervening `Use`.
#[must_use]
pub fn trace_literal(func: &HighFunction, value: ValueId) -> Option<Literal> {
    let terminal = resolve_use(func, value);
    // Bounds-check before Arena::get (which debug_asserts on
    // out-of-range ids). `resolve_use` returns its input unchanged for
    // a dangling id, so `terminal` may be out of range here.
    if (terminal.index() as usize) >= func.bindings.len() {
        return None;
    }
    match &func.bindings.get(terminal)?.expr {
        Expr::Literal(lit) => Some(lit.clone()),
        _ => None,
    }
}

/// Resolve `value` to an integer literal, across all four integer
/// literal widths (`I32`/`I64`/`U32`/`U64` — a constant arrives as
/// whichever width the WASM emitted).
///
/// The common recognizer helper for resolving tag bytes, shift
/// amounts, and enum discriminants (e.g. the storage durability
/// constant). Returns `None` when the value doesn't trace to an
/// integer literal.
#[must_use]
pub fn trace_int(func: &HighFunction, value: ValueId) -> Option<i128> {
    match trace_literal(func, value)? {
        Literal::I32(n) => Some(i128::from(n)),
        Literal::I64(n) => Some(i128::from(n)),
        Literal::U32(n) => Some(i128::from(n)),
        Literal::U64(n) => Some(i128::from(n)),
        _ => None,
    }
}

/// Follow `Expr::Use` links from `value` to the first non-`Use` binding
/// and return that binding's id.
///
/// Returns `value` unchanged if its binding is already non-`Use`, if it
/// is not in the arena, or if the chase hits the depth cap (returning
/// the last id reached). Pattern matchers use this to reach the "real"
/// definition behind an alias before inspecting its `Expr`.
#[must_use]
pub fn resolve_use(func: &HighFunction, value: ValueId) -> ValueId {
    let mut current = value;
    let mut depth: u32 = 0;
    while depth < DEFAULT_USE_DEPTH {
        depth += 1;
        // Bounds-check before Arena::get (which debug_asserts on
        // out-of-range ids); an unresolvable id resolves to itself.
        if (current.index() as usize) >= func.bindings.len() {
            return current;
        }
        match func.bindings.get(current) {
            Some(binding) => match &binding.expr {
                Expr::Use(next) => current = *next,
                _ => return current,
            },
            None => return current,
        }
    }
    current
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{Arena, BlockId, FuncId, Provenance, ProvenanceSource};
    use sordec_ir::{Binding, HighBlock, IrType, Region};

    /// Build a one-block `HighFunction` whose bindings are the supplied
    /// `Expr`s at ids 0..N (each `IrType::Unknown`, with a throwaway
    /// provenance entry).
    fn func_with_exprs(exprs: Vec<Expr>) -> HighFunction {
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        for expr in exprs {
            let id = ValueId::from_index(bindings.len() as u32);
            bindings.push(Binding::new(
                id,
                IrType::Unknown(sordec_common::UnknownReason::InsufficientEvidence),
                expr,
                Provenance::new("test", ProvenanceSource::DataFlow, "seed"),
            ));
        }
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        blocks.push(HighBlock {
            id: BlockId::from_index(0),
            bindings: vec![],
        });
        HighFunction {
            id: FuncId::from_index(0),
            name: None,
            signature: None,
            blocks,
            bindings,
            region: Region::Unreachable,
        }
    }

    fn v(idx: u32) -> ValueId {
        ValueId::from_index(idx)
    }

    #[test]
    fn direct_literal_resolves() {
        let func = func_with_exprs(vec![Expr::Literal(Literal::I64(42))]);
        assert_eq!(trace_literal(&func, v(0)), Some(Literal::I64(42)));
    }

    #[test]
    fn literal_through_use_chain_resolves() {
        // v0 = Literal(6); v1 = Use(v0); v2 = Use(v1)
        let func = func_with_exprs(vec![
            Expr::Literal(Literal::I64(6)),
            Expr::Use(v(0)),
            Expr::Use(v(1)),
        ]);
        assert_eq!(trace_literal(&func, v(2)), Some(Literal::I64(6)));
        assert_eq!(resolve_use(&func, v(2)), v(0));
    }

    #[test]
    fn non_literal_terminal_returns_none() {
        // v0 = Binary(...); v1 = Use(v0) — resolves to v0, which is not
        // a literal.
        let func = func_with_exprs(vec![
            Expr::Binary {
                op: sordec_ir::BinaryOp::Add,
                lhs: v(0),
                rhs: v(0),
            },
            Expr::Use(v(0)),
        ]);
        assert_eq!(trace_literal(&func, v(1)), None);
        assert_eq!(resolve_use(&func, v(1)), v(0));
    }

    #[test]
    fn dangling_value_resolves_to_itself_without_panic() {
        let func = func_with_exprs(vec![Expr::Literal(Literal::Unit)]);
        assert_eq!(resolve_use(&func, v(99)), v(99));
        assert_eq!(trace_literal(&func, v(99)), None);
    }

    #[test]
    fn use_cycle_is_bounded() {
        // v0 = Use(v1); v1 = Use(v0) — a malformed cycle. Must not hang.
        let func = func_with_exprs(vec![Expr::Use(v(1)), Expr::Use(v(0))]);
        // resolve_use returns some id without looping forever; the key
        // property is termination, not which id.
        let _ = resolve_use(&func, v(0));
        assert_eq!(trace_literal(&func, v(0)), None);
    }
}
