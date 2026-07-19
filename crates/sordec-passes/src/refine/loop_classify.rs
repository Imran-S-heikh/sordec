//! Loop classification (D3) — `LoopKind` tagging.
//!
//! The structurer emits every loop as `LoopKind::Unclassified`; this
//! pass proves source-level shapes and tags them. Tags are the whole
//! output — the region tree is byte-identical afterwards, per the
//! `LoopKind` contract ("consumers must treat every kind as the same
//! canonical `Loop`"). The renderer/emitter derive `while` forms from
//! the tag, falling back to plain `loop` whenever the shape stops
//! matching.
//!
//! ## What is proven (corpus-grounded)
//!
//! Post-wave-1, rustc's `while` loops appear in two dual forms, both
//! `[Basic(header), If { c, then, else: None }, rest…]`:
//!
//! - **Continue-in-then** (dex's copy loops): `then` ends in the back
//!   edge, `rest` is the exit path (no back edge). Source:
//!   `while c { body }` — the condition reads without negation.
//! - **Exit-in-then** (guard-recovered): `then` terminates without the
//!   back edge, `rest` ends in it. Source: `while ¬c { body }` — the
//!   renderer inverts the comparator (arithmetically, never with a
//!   synthesized `!`).
//!
//! Both are tagged [`LoopKind::WhileTop`] only when every binding
//! scheduled in the header block is **pure-total**: a header holding
//! per-iteration effectful work (dex's Newton-iteration `call`) is a
//! mid-test loop, not a source `while`, and honestly stays
//! `Unclassified`. The remaining kinds (`Infinite`, `DoWhileBottom`,
//! `GuardedDoWhile`) have no corpus witness — the classifier does not
//! guess at unobserved shapes; they gain proofs when a fixture shows
//! them.

use sordec_common::BlockId;
use sordec_ir::{HighIr, LoopKind, Region};

use super::debug_validate;
use crate::effects::expr_effects;
use crate::pass::{Pass, PassResult};

/// Unique pipeline name of this pass.
pub const PASS_NAME: &str = "refine-loop-classify";

/// Metric counter key: loops proven and tagged (any kind).
const M_CLASSIFIED: &str = "refine_loops_classified";

/// The loop-classification pass. Stateless; see the module docs.
#[derive(Debug, Default, Clone, Copy)]
pub struct LoopClassifyPass;

impl Pass<HighIr> for LoopClassifyPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let mut tagged = 0i64;
        for func in &mut ir.functions {
            let (region, blocks, bindings) = (&mut func.region, &func.blocks, &func.bindings);
            // Split borrows: the walk mutates only `kind` slots while
            // the prover reads blocks/bindings.
            classify(region, &ProveCtx { blocks, bindings }, &mut tagged);
        }
        if tagged > 0 {
            result.metrics.increment(M_CLASSIFIED, tagged);
            result.changed = true;
        }
        debug_validate(ir, PASS_NAME);
        result
    }
}

/// The read-only halves of a [`sordec_ir::HighFunction`] the prover
/// consults.
struct ProveCtx<'a> {
    blocks: &'a sordec_common::Arena<BlockId, sordec_ir::HighBlock>,
    bindings: &'a sordec_common::Arena<sordec_common::ValueId, sordec_ir::Binding>,
}

/// Recurse the region tree tagging every provable loop. Exhaustive on
/// purpose — a new `Region` variant must decide its children here.
fn classify(region: &mut Region, ctx: &ProveCtx<'_>, tagged: &mut i64) {
    match region {
        Region::Sequence(items) => {
            for item in items {
                classify(item, ctx, tagged);
            }
        }
        Region::Scope { body, .. } => classify(body, ctx, tagged),
        Region::If {
            then_region,
            else_region,
            ..
        } => {
            classify(then_region, ctx, tagged);
            if let Some(else_region) = else_region {
                classify(else_region, ctx, tagged);
            }
        }
        Region::Switch {
            arms, default, ..
        } => {
            for arm in arms {
                classify(&mut arm.body, ctx, tagged);
            }
            classify(default, ctx, tagged);
        }
        Region::Loop { header, body, kind } => {
            classify(body, ctx, tagged);
            if *kind == LoopKind::Unclassified
                && let Some(proven) = prove(*header, body, ctx)
            {
                *kind = proven;
                *tagged += 1;
            }
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

/// Prove a loop's source shape, or `None` to stay `Unclassified`.
fn prove(header: BlockId, body: &Region, ctx: &ProveCtx<'_>) -> Option<LoopKind> {
    let Region::Sequence(items) = body else {
        return None;
    };
    let [Region::Basic(b), Region::If {
        then_region,
        else_region: None,
        ..
    }, rest @ ..] = items.as_slice()
    else {
        return None;
    };
    if *b != header || rest.is_empty() || !header_is_pure(*b, ctx) {
        return None;
    }

    let continue_in_then = ends_in_continue(then_region, header);
    let rest_has_back_edge = rest.iter().any(|r| contains_continue(r, header));
    if continue_in_then && !rest_has_back_edge {
        // Continue-in-then: `while c { then }`, exit path follows.
        return Some(LoopKind::WhileTop);
    }
    let rest_ends_in_back_edge = rest.last().is_some_and(|r| ends_in_continue(r, header));
    if !continue_in_then
        && !contains_continue(then_region, header)
        && super::is_terminating(then_region)
        && rest_ends_in_back_edge
    {
        // Exit-in-then: `while ¬c { rest }`, exit arm follows.
        return Some(LoopKind::WhileTop);
    }
    None
}

/// Every binding scheduled in the header block is pure-total — the
/// block is condition-chain material, not per-iteration work.
fn header_is_pure(block: BlockId, ctx: &ProveCtx<'_>) -> bool {
    ctx.blocks.get(block).is_some_and(|b| {
        b.bindings.iter().all(|&v| {
            ctx.bindings
                .get(v)
                .is_some_and(|binding| expr_effects(&binding.expr).is_pure_total())
        })
    })
}

/// Does this region's final position (through nested sequences) hit the
/// loop's back edge?
pub(crate) fn ends_in_continue(region: &Region, header: BlockId) -> bool {
    match region {
        Region::Continue { target, .. } => *target == header,
        Region::Sequence(items) => items
            .last()
            .is_some_and(|last| ends_in_continue(last, header)),
        _ => false,
    }
}

/// Does the subtree contain the loop's back edge anywhere?
pub(crate) fn contains_continue(region: &Region, header: BlockId) -> bool {
    let mut found = false;
    region.for_each_node(|node| {
        if let Region::Continue { target, .. } = node
            && *target == header
        {
            found = true;
        }
    });
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{Arena, FuncId, IrId, Provenance, ProvenanceSource, UnknownReason,
        ValueId};
    use sordec_ir::{
        BinaryOp, Binding, Expr, HighBlock, HighFunction, IrType, Literal, MemoryImage,
        WasmFacts, WasmOpcodeKind,
    };

    fn v(i: u32) -> ValueId {
        ValueId::from_index(i)
    }
    fn bb(i: u32) -> BlockId {
        BlockId::from_index(i)
    }
    fn binding(id: u32, expr: Expr) -> Binding {
        Binding::new(
            v(id),
            IrType::Unknown(UnknownReason::UpstreamUnknown),
            expr,
            Provenance::new("test", ProvenanceSource::DataFlow, ""),
        )
    }
    fn cont(header: u32) -> Region {
        Region::Continue {
            target: bb(header),
            transfer: vec![],
        }
    }

    /// A function with a comparison `v2` scheduled in the loop header
    /// `bb1`, and a loop with the given body.
    fn func_with_loop(header_bindings: Vec<Binding>, body: Region) -> HighFunction {
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        bindings.push(binding(0, Expr::Literal(Literal::I32(0))));
        let scheduled: Vec<ValueId> = header_bindings.iter().map(|b| b.id).collect();
        for b in header_bindings {
            bindings.push(b);
        }
        let mut blocks: Arena<sordec_common::BlockId, HighBlock> = Arena::new();
        blocks.push(HighBlock {
            id: bb(0),
            bindings: vec![v(0)],
        });
        blocks.push(HighBlock {
            id: bb(1),
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
                Region::Loop {
                    header: bb(1),
                    body: Box::new(body),
                    kind: LoopKind::Unclassified,
                },
            ]),
            params: vec![],
            returns: vec![],
        }
    }

    fn cmp_v1() -> Vec<Binding> {
        vec![binding(
            1,
            Expr::Binary {
                op: BinaryOp::Ne,
                lhs: v(0),
                rhs: v(0),
            },
        )]
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
        let result = LoopClassifyPass.run(&mut ir);
        (ir.functions.pop().expect("one function"), result)
    }

    fn kind_of(func: &HighFunction) -> LoopKind {
        let Region::Sequence(items) = &func.region else {
            panic!("root is a sequence");
        };
        let Region::Loop { kind, .. } = &items[1] else {
            panic!("second item is the loop");
        };
        *kind
    }

    /// dex bb3: `if c { body…; continue }` + exit tail.
    fn continue_in_then_body() -> Region {
        Region::Sequence(vec![
            Region::Basic(bb(1)),
            Region::If {
                cond: v(1),
                then_region: Box::new(cont(1)),
                else_region: None,
            },
            Region::Return { values: vec![] },
        ])
    }

    /// dex bb8: `if c { …return }` + body + trailing continue.
    fn exit_in_then_body() -> Region {
        Region::Sequence(vec![
            Region::Basic(bb(1)),
            Region::If {
                cond: v(1),
                then_region: Box::new(Region::Return { values: vec![] }),
                else_region: None,
            },
            cont(1),
        ])
    }

    #[test]
    fn continue_in_then_proves_while_top() {
        let (func, result) = run_pass(func_with_loop(cmp_v1(), continue_in_then_body()));
        assert!(result.changed);
        assert_eq!(result.metrics.get(M_CLASSIFIED), Some(1));
        assert_eq!(kind_of(&func), LoopKind::WhileTop);
    }

    #[test]
    fn exit_in_then_proves_while_top() {
        let (func, result) = run_pass(func_with_loop(cmp_v1(), exit_in_then_body()));
        assert!(result.changed);
        assert_eq!(kind_of(&func), LoopKind::WhileTop);
    }

    #[test]
    fn effectful_header_stays_unclassified() {
        // The Newton-iteration shape: a per-iteration call in the
        // header is not a source `while`.
        let call = binding(
            1,
            Expr::Unknown {
                op_kind: WasmOpcodeKind::Call,
                args: vec![],
                reason: UnknownReason::UpstreamUnknown,
            },
        );
        let (func, result) = run_pass(func_with_loop(vec![call], continue_in_then_body()));
        assert!(!result.changed);
        assert_eq!(kind_of(&func), LoopKind::Unclassified);
    }

    #[test]
    fn back_edge_on_both_sides_stays_unclassified() {
        // Continue in the then AND in the rest — neither dual form.
        let body = Region::Sequence(vec![
            Region::Basic(bb(1)),
            Region::If {
                cond: v(1),
                then_region: Box::new(cont(1)),
                else_region: None,
            },
            cont(1),
        ]);
        let (func, result) = run_pass(func_with_loop(cmp_v1(), body));
        assert!(!result.changed);
        assert_eq!(kind_of(&func), LoopKind::Unclassified);
    }

    #[test]
    fn second_run_is_idempotent() {
        let (func, first) = run_pass(func_with_loop(cmp_v1(), continue_in_then_body()));
        assert!(first.changed);
        let (_, second) = run_pass(func);
        assert!(!second.changed, "tags write once");
    }
}
