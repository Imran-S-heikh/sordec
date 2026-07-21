//! Trivial short-circuit merge (D7) — the shared-else diamond only.
//!
//! rustc lowers `if a && b { X } else { Y }` into a nested diamond with
//! the else duplicated as a branch target:
//!
//! ```text
//! if a {                      if a && b {
//!   ;; bbM (computes b)         X
//!   if b { X } else { Y }  →  } else {
//! } else {                      Y
//!   Y                         }
//! }
//! ```
//!
//! This pass undoes exactly that shape: an outer `If` whose `then` is
//! `[Basic(M), If b { X } else { Y }]` and whose own else `Y′` is
//! structurally equal to `Y`. The rewrite mints one fresh binding
//! `t = a & b` (scheduled at the end of `M`, typed `Bool`), re-points
//! the merged `If` at it, and drops the duplicate `Y′`.
//!
//! ## Gates (all must hold)
//!
//! - **K4 / effects**: every binding scheduled in `M` becomes
//!   unconditionally evaluated (it ran only under `a` before), so all
//!   of `M` must be pure-total per [`expr_effects`]. Bitwise `&` over
//!   pure-total operands is observationally equal to the source's
//!   short-circuit `&&` — rustc itself makes the same transform in the
//!   other direction.
//! - **Boolean operands**: both `a` and `b` must be boolean-producing
//!   (an integer comparison or a `Val` tag check) — the kickoff's
//!   "recovered as `a && b` when both sides are boolean-typed" rule.
//!   No DREAM-style condition synthesis beyond the one conjunction
//!   (research R2; J9 rejected).
//! - **Shared else**: `Y ≡ Y′` via `Region` equality. Equal bodies are
//!   provably `Basic`-free (a block appears in the tree exactly once),
//!   so dropping `Y′` never orphans a block.
//!
//! Diamonds that match the shape but fail a gate are counted by the
//! `refine_and_merge_blocked` metric — the measured signal for whether
//! a wider variant is worth building (the D2 pattern).

use sordec_common::{IrId, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{
    BinaryOp, Binding, Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Region, SemanticOp,
};

use super::debug_validate;
use crate::effects::expr_effects;
use crate::pass::{Pass, PassResult};
use crate::structuring::seq;

/// Unique pipeline name of this pass.
pub const PASS_NAME: &str = "refine-and-merge";

// Metric counter keys.
/// Shared-else diamonds merged into one `&&` guard.
const M_MERGED: &str = "refine_and_merged";
/// Diamonds matching the shape but blocked by a gate (effects or
/// non-boolean operands) — the widening signal.
const M_BLOCKED: &str = "refine_and_merge_blocked";

/// The short-circuit-merge pass. Stateless; see the module docs.
#[derive(Debug, Default, Clone, Copy)]
pub struct AndMergePass;

impl Pass<HighIr> for AndMergePass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let mut stats = Stats::default();
        for func in &mut ir.functions {
            let region = std::mem::replace(&mut func.region, Region::Unreachable);
            func.region = merge(region, func, &mut stats);
        }
        if stats.merged > 0 {
            result.metrics.increment(M_MERGED, stats.merged);
            result.changed = true;
        }
        if stats.blocked > 0 {
            result.metrics.increment(M_BLOCKED, stats.blocked);
        }
        debug_validate(ir, PASS_NAME);
        result
    }
}

#[derive(Default)]
struct Stats {
    merged: i64,
    blocked: i64,
}

/// Bottom-up rewrite: children first, so nested diamonds cascade
/// through the fixpoint group.
fn merge(region: Region, func: &mut HighFunction, stats: &mut Stats) -> Region {
    match region {
        Region::Sequence(items) => seq(items
            .into_iter()
            .map(|item| merge(item, func, stats))
            .collect()),
        Region::Scope { out, body } => Region::Scope {
            out,
            body: Box::new(merge(*body, func, stats)),
        },
        Region::Loop { header, body, kind } => Region::Loop {
            header,
            body: Box::new(merge(*body, func, stats)),
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
                    arm.body = merge(arm.body, func, stats);
                    arm
                })
                .collect(),
            default: Box::new(merge(*default, func, stats)),
            dispatch,
        },
        Region::If {
            cond,
            then_region,
            else_region,
        } => {
            let then_region = merge(*then_region, func, stats);
            let else_region = else_region.map(|e| merge(*e, func, stats));
            try_merge_diamond(cond, then_region, else_region, func, stats)
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

/// Fire the diamond pattern on one (already child-rewritten) `If`, or
/// reassemble it unchanged.
fn try_merge_diamond(
    cond: ValueId,
    then_region: Region,
    else_region: Option<Region>,
    func: &mut HighFunction,
    stats: &mut Stats,
) -> Region {
    // Shape: else present, then = [Basic(M), If b { X } else { Y }],
    // outer else ≡ inner else.
    let fires = 'shape: {
        let Some(outer_else) = &else_region else {
            break 'shape false;
        };
        let Region::Sequence(items) = &then_region else {
            break 'shape false;
        };
        let [Region::Basic(m), Region::If {
            cond: inner_cond,
            else_region: Some(inner_else),
            ..
        }] = items.as_slice()
        else {
            break 'shape false;
        };
        if **inner_else != *outer_else {
            break 'shape false;
        }
        // Gates: pure-total M, boolean a and b.
        let pure_m = func.blocks.get(*m).is_some_and(|block| {
            block.bindings.iter().all(|&v| {
                func.bindings
                    .get(v)
                    .is_some_and(|b| expr_effects(&b.expr).is_pure_total())
            })
        });
        if !(pure_m && is_boolean(func, cond) && is_boolean(func, *inner_cond)) {
            stats.blocked += 1;
            break 'shape false;
        }
        true
    };
    if !fires {
        return Region::If {
            cond,
            then_region: Box::new(then_region),
            else_region: else_region.map(Box::new),
        };
    }

    let Region::Sequence(mut items) = then_region else {
        unreachable!("matched above");
    };
    let Some(Region::If {
        cond: inner_cond,
        then_region: inner_then,
        ..
    }) = items.pop()
    else {
        unreachable!("matched above");
    };
    let Some(Region::Basic(m)) = items.pop() else {
        unreachable!("matched above");
    };

    // Mint `t = a & b` at the end of `M` — both operands are defined by
    // then (`a` before the outer `if`, `b` inside `M`), and the single
    // fresh provenance entry lets the renderer fold `t` into the merged
    // condition as `a && b`.
    let id = ValueId::from_index(func.bindings.len() as u32);
    func.bindings.push(Binding::new(
        id,
        IrType::Known(KnownType::Bool),
        Expr::Binary {
            op: BinaryOp::BitAnd,
            lhs: cond,
            rhs: inner_cond,
        },
        Provenance::new(
            PASS_NAME,
            ProvenanceSource::UpstreamRefinement,
            "shared-else diamond merged to `&&`",
        ),
    ));
    func.blocks
        .get_mut(m)
        .expect("gate resolved this block")
        .bindings
        .push(id);
    stats.merged += 1;

    seq(vec![
        Region::Basic(m),
        Region::If {
            cond: id,
            then_region: inner_then,
            else_region: else_region.map(Box::new),
        },
    ])
}

/// Is `value` a boolean-producing binding — an integer comparison or a
/// `Val` tag check?
fn is_boolean(func: &HighFunction, value: ValueId) -> bool {
    func.bindings.get(value).is_some_and(|b| {
        matches!(
            &b.expr,
            Expr::Binary {
                op: BinaryOp::Eq
                    | BinaryOp::Ne
                    | BinaryOp::Lt
                    | BinaryOp::Le
                    | BinaryOp::Gt
                    | BinaryOp::Ge,
                ..
            } | Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck { .. }))
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{Arena, BlockId, FuncId, IrId, UnknownReason};
    use sordec_ir::{HighBlock, Literal, MemoryImage, WasmFacts};

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
    fn cmp(id: u32, lhs: u32, rhs: u32) -> Binding {
        binding(
            id,
            Expr::Binary {
                op: BinaryOp::Lt,
                lhs: v(lhs),
                rhs: v(rhs),
            },
        )
    }
    fn brk(target: u32) -> Region {
        Region::Break {
            target: bb(target),
            transfer: vec![],
        }
    }

    /// The diamond: block 0 computes `a` (v2), block 1 computes `b`
    /// (v3); region = Scope{out: bb2} around
    /// `if v2 { [Basic(1), if v3 { return } else { break 'bb2 }] }
    ///  else { break 'bb2 }`.
    fn diamond(b_expr: Expr) -> HighFunction {
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        bindings.push(binding(0, Expr::Literal(Literal::I32(1))));
        bindings.push(binding(1, Expr::Literal(Literal::I32(2))));
        bindings.push(cmp(2, 0, 1));
        bindings.push(Binding::new(
            v(3),
            IrType::Unknown(UnknownReason::UpstreamUnknown),
            b_expr,
            Provenance::new("test", ProvenanceSource::DataFlow, ""),
        ));
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        blocks.push(HighBlock {
            id: bb(0),
            bindings: vec![v(0), v(1), v(2)],
        });
        blocks.push(HighBlock {
            id: bb(1),
            bindings: vec![v(3)],
        });
        blocks.push(HighBlock {
            id: bb(2),
            bindings: vec![],
        });
        HighFunction {
            id: FuncId::from_index(0),
            name: None,
            signature: None,
            blocks,
            bindings,
            region: Region::Sequence(vec![
                Region::Scope {
                    out: bb(2),
                    body: Box::new(Region::Sequence(vec![
                        Region::Basic(bb(0)),
                        Region::If {
                            cond: v(2),
                            then_region: Box::new(Region::Sequence(vec![
                                Region::Basic(bb(1)),
                                Region::If {
                                    cond: v(3),
                                    then_region: Box::new(Region::Return { values: vec![] }),
                                    else_region: Some(Box::new(brk(2))),
                                },
                            ])),
                            else_region: Some(Box::new(brk(2))),
                        },
                    ])),
                },
                Region::Basic(bb(2)),
                Region::Return { values: vec![] },
            ]),
            params: vec![],
            returns: vec![],
        }
    }

    fn comparison_b() -> Expr {
        Expr::Binary {
            op: BinaryOp::Eq,
            lhs: v(0),
            rhs: v(1),
        }
    }

    fn run_pass(func: HighFunction) -> (HighFunction, PassResult) {
        let mut ir = HighIr {
            facts: WasmFacts {
                imports: vec![],
                exports: vec![],
                function_type_indices: vec![],
                function_bodies: vec![],
                custom_sections: vec![],
            },
            soroban_facts: None,
            functions: vec![func],
            memory: MemoryImage::empty(),
        };
        let result = AndMergePass.run(&mut ir);
        (ir.functions.pop().expect("one function"), result)
    }

    #[test]
    fn shared_else_diamond_merges_to_one_guard() {
        let (func, result) = run_pass(diamond(comparison_b()));
        assert!(result.changed);
        assert_eq!(result.metrics.get(M_MERGED), Some(1));

        // The merged binding: `v4 = v2 & v3`, Bool, scheduled in bb1.
        let merged = func.bindings.get(v(4)).expect("minted binding");
        assert!(
            matches!(
                merged.expr,
                Expr::Binary {
                    op: BinaryOp::BitAnd,
                    lhs,
                    rhs,
                } if lhs == v(2) && rhs == v(3)
            ),
            "got {:?}",
            merged.expr
        );
        assert_eq!(merged.ty, IrType::Known(KnownType::Bool));
        assert_eq!(
            func.blocks.get(bb(1)).unwrap().bindings,
            vec![v(3), v(4)]
        );

        // The tree: one flat `if v4 { return } else { break 'bb2 }`.
        let Region::Sequence(items) = &func.region else {
            panic!("root stays a sequence");
        };
        let Region::Scope { body, .. } = &items[0] else {
            panic!("scope survives");
        };
        assert_eq!(
            **body,
            Region::Sequence(vec![
                Region::Basic(bb(0)),
                Region::Basic(bb(1)),
                Region::If {
                    cond: v(4),
                    then_region: Box::new(Region::Return { values: vec![] }),
                    else_region: Some(Box::new(brk(2))),
                },
            ])
        );
    }

    #[test]
    fn effectful_inner_block_blocks_the_merge() {
        // `b`'s block carries a load — not pure-total, K4 refuses.
        let (func, result) = run_pass(diamond(Expr::Unknown {
            op_kind: sordec_ir::WasmOpcodeKind::Load,
            args: vec![v(0)],
            reason: UnknownReason::UpstreamUnknown,
        }));
        assert!(!result.changed);
        assert_eq!(result.metrics.get(M_MERGED), None);
        assert_eq!(result.metrics.get(M_BLOCKED), Some(1));
        let Region::Sequence(items) = &func.region else {
            panic!("root stays a sequence");
        };
        let Region::Scope { body, .. } = &items[0] else {
            panic!("scope survives");
        };
        let Region::Sequence(body_items) = &**body else {
            panic!("body stays a sequence");
        };
        assert!(
            matches!(&body_items[1], Region::If { else_region: Some(_), .. }),
            "diamond left nested"
        );
    }

    #[test]
    fn distinct_elses_do_not_merge() {
        let mut func = diamond(comparison_b());
        // Outer else becomes a Return — no longer equal to inner.
        let Region::Sequence(items) = &mut func.region else {
            unreachable!()
        };
        let Region::Scope { body, .. } = &mut items[0] else {
            unreachable!()
        };
        let Region::Sequence(body_items) = &mut **body else {
            unreachable!()
        };
        let Region::If { else_region, .. } = &mut body_items[1] else {
            unreachable!()
        };
        *else_region = Some(Box::new(Region::Return { values: vec![] }));

        let (_, result) = run_pass(func);
        assert!(!result.changed);
        assert_eq!(result.metrics.get(M_BLOCKED), None, "shape miss, not a gate block");
    }

    #[test]
    fn second_run_is_idempotent() {
        let (func, first) = run_pass(diamond(comparison_b()));
        assert!(first.changed);
        let (_, second) = run_pass(func);
        assert!(!second.changed, "no diamond left");
    }
}
