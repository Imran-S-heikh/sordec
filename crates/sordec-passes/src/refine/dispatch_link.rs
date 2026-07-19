//! Dispatcher-cascade linking (D6) — the region half of symbol dispatch.
//!
//! The `dispatcher` recognizer decodes the rodata variant table behind a
//! `symbol_index_in_linear_memory` call into [`KnownOp::SymbolDispatch`]
//! (data side); the structurer independently recovers the `br_table`
//! driven by that index into a [`Region::Switch`] (control side). This
//! pass ties the two: when a switch's selector provably carries the
//! dispatch result, `Switch::dispatch` is pointed at the
//! `SymbolDispatch` binding, and the renderer/emitter can name the arms
//! by enum variant (`TimeBoundKind::Before`) instead of raw integers.
//!
//! ## Selector tracing
//!
//! The SDK never feeds the host result to `br_table` directly — the
//! `U32Val` payload is decoded and narrowed first. On the corpus
//! (timelock) the chain is
//! `Conversion(val_decode(symbol_dispatch(..)))`. Tracing peels exactly
//! those payload-preserving wrappers — [`KnownOp::ValDecodeSmall`] and
//! single-operand `Conversion`s — and accepts nothing else, so a plain
//! integer switch (a `#[contracttype]` struct-enum discriminant load)
//! never links. Wrong-link risk is asymmetric: a miss keeps honest
//! integer arms, a false link would print wrong variant names.
//!
//! Linking never restructures: the region tree and the switch's arms are
//! byte-identical after the pass; only the `dispatch` slot (validated
//! against the binding by `validate_high`) is written.

use sordec_common::{Arena, ValueId};
use sordec_ir::{Binding, Expr, HighIr, KnownOp, Region, SemanticOp};

use super::debug_validate;
use crate::pass::{Pass, PassResult};

/// Unique pipeline name of this pass.
pub const PASS_NAME: &str = "refine-dispatch-link";

/// Metric counter key: switches linked to a recovered dispatch table.
const M_LINKED: &str = "refine_dispatch_linked";

/// Wrapper-peeling depth bound. The corpus chain is two hops
/// (`Conversion` over `ValDecodeSmall`); the bound only stops a
/// pathological self-referential chain from looping.
const MAX_TRACE_DEPTH: u32 = 8;

/// The dispatch-linking pass. Stateless; see the module docs.
#[derive(Debug, Default, Clone, Copy)]
pub struct DispatchLinkPass;

impl Pass<HighIr> for DispatchLinkPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let mut linked = 0i64;
        for func in &mut ir.functions {
            // Disjoint field borrows: the walk mutates the region tree
            // while the tracer reads the binding arena.
            let (region, bindings) = (&mut func.region, &func.bindings);
            link_switches(region, bindings, &mut linked);
        }
        if linked > 0 {
            result.metrics.increment(M_LINKED, linked);
            result.changed = true;
        }
        debug_validate(ir, PASS_NAME);
        result
    }
}

/// Recurse the region tree, linking every unlinked switch whose selector
/// traces to a `SymbolDispatch` binding. Exhaustive on purpose — a new
/// `Region` variant must decide its children here.
fn link_switches(region: &mut Region, bindings: &Arena<ValueId, Binding>, linked: &mut i64) {
    match region {
        Region::Sequence(items) => {
            for item in items {
                link_switches(item, bindings, linked);
            }
        }
        Region::Scope { body, .. } | Region::Loop { body, .. } => {
            link_switches(body, bindings, linked);
        }
        Region::If {
            then_region,
            else_region,
            ..
        } => {
            link_switches(then_region, bindings, linked);
            if let Some(else_region) = else_region {
                link_switches(else_region, bindings, linked);
            }
        }
        Region::Switch {
            index,
            arms,
            default,
            dispatch,
        } => {
            if dispatch.is_none()
                && let Some(source) = trace_to_dispatch(bindings, *index, MAX_TRACE_DEPTH)
            {
                *dispatch = Some(source);
                *linked += 1;
            }
            for arm in arms {
                link_switches(&mut arm.body, bindings, linked);
            }
            link_switches(default, bindings, linked);
        }
        Region::Basic(_)
        | Region::Break { .. }
        | Region::Continue { .. }
        | Region::Transfer { .. }
        | Region::Return { .. }
        | Region::Unreachable
        | Region::Panic { .. }
        | Region::Unstructured { .. } => {}
    }
}

/// Peel payload-preserving wrappers from `value` until a
/// [`KnownOp::SymbolDispatch`] binding is found. Anything outside the
/// two known SDK decode wrappers stops the trace (see module docs).
fn trace_to_dispatch(
    bindings: &Arena<ValueId, Binding>,
    value: ValueId,
    depth: u32,
) -> Option<ValueId> {
    if depth == 0 {
        return None;
    }
    let binding = bindings.get(value)?;
    match &binding.expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::SymbolDispatch { .. })) => Some(value),
        Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { value: inner })) => {
            trace_to_dispatch(bindings, *inner, depth - 1)
        }
        Expr::Unknown { args, .. } if args.len() == 1 => {
            // The i64→i32 narrowing between decode and `br_table` lowers
            // as an unrecovered single-operand Conversion. Any other
            // one-arg Unknown is opaque — refusing to peel it can only
            // cost a link, never mint a wrong one, and Unknowns carry no
            // op identity worth branching on here.
            trace_to_dispatch(bindings, args[0], depth - 1)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{
        BlockId, FuncId, IrId, Provenance, ProvenanceSource, UnknownReason, ValueId,
    };
    use sordec_ir::{
        DispatchTable, HighBlock, HighFunction, IrType, KnownType, Literal, MemoryImage,
        SwitchArm, WasmFacts, WasmOpcodeKind,
    };

    fn v(i: u32) -> ValueId {
        ValueId::from_index(i)
    }
    fn bb(i: u32) -> BlockId {
        BlockId::from_index(i)
    }

    fn symbol_dispatch() -> Expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::SymbolDispatch {
            sym: v(0),
            table_pos: v(0),
            len: v(0),
            table: DispatchTable {
                cases: vec!["Before".into(), "After".into()],
                enum_name: Some("TimeBoundKind".into()),
            },
        }))
    }

    fn val_decode(inner: u32) -> Expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall {
            value: v(inner),
        }))
    }

    fn conversion(inner: u32) -> Expr {
        Expr::Unknown {
            op_kind: WasmOpcodeKind::Conversion,
            args: vec![v(inner)],
            reason: UnknownReason::UnsupportedPattern,
        }
    }

    /// One function, one block scheduling every binding, region = a
    /// switch on `selector` with two trivial return arms. Binding `v0`
    /// is always a literal operand donor (so `symbol_dispatch()`'s
    /// operand reads satisfy emission-order dominance); caller exprs
    /// start at `v1`.
    fn func_with_switch(exprs: Vec<Expr>, selector: u32) -> HighFunction {
        let mut bindings: sordec_common::Arena<ValueId, Binding> = sordec_common::Arena::new();
        let mut scheduled = Vec::new();
        let exprs: Vec<Expr> = std::iter::once(Expr::Literal(Literal::I64(0)))
            .chain(exprs)
            .collect();
        for expr in exprs {
            let id = ValueId::from_index(bindings.len() as u32);
            scheduled.push(id);
            bindings.push(Binding::new(
                id,
                IrType::Known(KnownType::U32),
                expr,
                Provenance::new("test", ProvenanceSource::DataFlow, ""),
            ));
        }
        let mut blocks: sordec_common::Arena<BlockId, HighBlock> = sordec_common::Arena::new();
        blocks.push(HighBlock {
            id: bb(0),
            bindings: scheduled,
        });
        HighFunction {
            id: FuncId::from_index(0),
            name: None,
            signature: None,
            blocks,
            bindings,
            region: Region::Sequence(vec![
                Region::Basic(bb(0)),
                Region::Switch {
                    index: v(selector),
                    arms: vec![
                        SwitchArm {
                            cases: vec![0],
                            body: Region::Return { values: vec![] },
                        },
                        SwitchArm {
                            cases: vec![1],
                            body: Region::Return { values: vec![] },
                        },
                    ],
                    default: Box::new(Region::Unreachable),
                    dispatch: None,
                },
            ]),
            params: vec![],
            returns: vec![],
        }
    }

    fn run_pass(func: HighFunction) -> (HighFunction, PassResult) {
        let mut ir = HighIr {
            facts: WasmFacts {
                imports: vec![],
                exports: vec![],
                function_type_indices: vec![],
                custom_sections: vec![],
            },
            soroban_facts: None,
            functions: vec![func],
            memory: MemoryImage::empty(),
        };
        let result = DispatchLinkPass.run(&mut ir);
        (ir.functions.pop().expect("one function"), result)
    }

    fn dispatch_of(func: &HighFunction) -> Option<ValueId> {
        let Region::Sequence(items) = &func.region else {
            panic!("root is a sequence");
        };
        let Region::Switch { dispatch, .. } = &items[1] else {
            panic!("second item is the switch");
        };
        *dispatch
    }

    #[test]
    fn direct_selector_links() {
        let (func, result) = run_pass(func_with_switch(vec![symbol_dispatch()], 1));
        assert!(result.changed);
        assert_eq!(result.metrics.get(M_LINKED), Some(1));
        assert_eq!(dispatch_of(&func), Some(v(1)));
    }

    #[test]
    fn corpus_decode_chain_links() {
        // The timelock shape: match on Conversion(val_decode(dispatch)).
        let (func, result) = run_pass(func_with_switch(
            vec![symbol_dispatch(), val_decode(1), conversion(2)],
            3,
        ));
        assert!(result.changed);
        assert_eq!(dispatch_of(&func), Some(v(1)));
    }

    #[test]
    fn plain_integer_switch_stays_unlinked() {
        // A discriminant load (the token/dex DataKey switch): no link.
        let (func, result) = run_pass(func_with_switch(
            vec![Expr::Literal(Literal::U32(2))],
            1,
        ));
        assert!(!result.changed);
        assert_eq!(result.metrics.get(M_LINKED), None);
        assert_eq!(dispatch_of(&func), None);
    }

    #[test]
    fn multi_operand_unknown_stops_the_trace() {
        // A two-arg Unknown between decode and switch is not a wrapper.
        let two_arg = Expr::Unknown {
            op_kind: WasmOpcodeKind::Arithmetic,
            args: vec![v(1), v(1)],
            reason: UnknownReason::UnsupportedPattern,
        };
        let (func, result) = run_pass(func_with_switch(vec![symbol_dispatch(), two_arg], 2));
        assert!(!result.changed);
        assert_eq!(dispatch_of(&func), None);
    }

    #[test]
    fn second_run_is_idempotent() {
        let (func, first) = run_pass(func_with_switch(vec![symbol_dispatch()], 1));
        assert!(first.changed);
        let (func, second) = run_pass(func);
        assert!(!second.changed, "already linked, nothing to do");
        assert_eq!(dispatch_of(&func), Some(v(1)));
    }
}
