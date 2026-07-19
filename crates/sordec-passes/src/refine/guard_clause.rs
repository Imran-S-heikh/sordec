//! Guard-clause recovery (D1) — the highest-value refinement on the
//! corpus (census R3: the fixtures are guard-shaped).
//!
//! The structurer's `If`s are fully else-nested because both CFG
//! successors always terminate; source code almost never looks like
//! that — rustc/LLVM *created* the nesting when they lowered early
//! returns and panic guards. This pass reverses it: when an `If`'s
//! `then` arm provably leaves the enclosing context, the `else` body is
//! hoisted out to sit after the `if`, removing one nesting level:
//!
//! ```text
//! if cond { break 'trap } else { REST }   →   if cond { break 'trap }
//!                                             REST
//! ```
//!
//! Sound in any sequence position: the `then` never falls through, so
//! the hoisted body still executes exactly on the `!cond` path.
//!
//! One asymmetry is deliberately *not* hoisted: a bare exit in the
//! `else` under a content-carrying `then` (`if c { BIG } else { break }`).
//! Hoisting would strand the exit after a large block — the opposite of
//! a guard clause. That shape is polarity's (D4) to flip when the
//! condition inverts; when it cannot, the nested form reads better and
//! stays.

use sordec_ir::{HighIr, Region};

use super::{debug_validate, is_bare_exit, is_terminating};
use crate::pass::{Pass, PassResult};
use crate::structuring::seq;

/// Unique pipeline name of this pass.
pub const PASS_NAME: &str = "refine-guard-clause";

// Metric counter key.
/// `else` bodies hoisted out from under a terminating `then`.
const M_HOISTED: &str = "refine_guards_hoisted";

/// The guard-clause recovery pass. Stateless; see the module docs.
#[derive(Debug, Default, Clone, Copy)]
pub struct GuardClausePass;

impl Pass<HighIr> for GuardClausePass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let mut hoisted: i64 = 0;
        for func in &mut ir.functions {
            let region = std::mem::replace(&mut func.region, Region::Unreachable);
            func.region = hoist(region, &mut hoisted);
        }
        if hoisted > 0 {
            result.metrics.increment(M_HOISTED, hoisted);
            result.changed = true;
        }
        debug_validate(ir, PASS_NAME);
        result
    }
}

/// Bottom-up structural rewrite. A fired guard returns a `Sequence`
/// (the else-less `if` followed by the hoisted body), which
/// [`seq`] flattening splices into the parent — the tree stays in the
/// canonical no-nested-`Sequence` form the structurer established.
fn hoist(region: Region, hoisted: &mut i64) -> Region {
    match region {
        Region::Sequence(items) => seq(items
            .into_iter()
            .map(|item| hoist(item, hoisted))
            .collect()),
        Region::Scope { out, body } => Region::Scope {
            out,
            body: Box::new(hoist(*body, hoisted)),
        },
        Region::Loop { header, body, kind } => Region::Loop {
            header,
            body: Box::new(hoist(*body, hoisted)),
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
                    arm.body = hoist(arm.body, hoisted);
                    arm
                })
                .collect(),
            default: Box::new(hoist(*default, hoisted)),
            dispatch,
        },
        Region::If {
            cond,
            then_region,
            else_region,
        } => {
            let then_region = hoist(*then_region, hoisted);
            let else_region = else_region.map(|e| hoist(*e, hoisted));
            match else_region {
                Some(else_body)
                    if is_terminating(&then_region)
                        // The D4 asymmetry: never strand a bare exit
                        // after a content-carrying then.
                        && !(is_bare_exit(&else_body) && !is_bare_exit(&then_region)) =>
                {
                    *hoisted += 1;
                    seq(vec![
                        Region::If {
                            cond,
                            then_region: Box::new(then_region),
                            else_region: None,
                        },
                        else_body,
                    ])
                }
                other => Region::If {
                    cond,
                    then_region: Box::new(then_region),
                    else_region: other.map(Box::new),
                },
            }
        }
        leaf @ (Region::Basic(_)
        | Region::Break { .. }
        | Region::Continue { .. }
        | Region::Transfer { .. }
        | Region::Return { .. }
        | Region::Unreachable
        | Region::Unstructured { .. }) => leaf,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{Arena, BlockId, FuncId, Provenance, ProvenanceSource, UnknownReason,
        ValueId};
    use sordec_ir::{BinaryOp, Binding, Expr, HighBlock, HighFunction, IrType, Literal};

    fn v(i: u32) -> ValueId {
        ValueId::new(i)
    }
    fn bb(i: u32) -> BlockId {
        BlockId::new(i)
    }
    fn binding(id: u32, expr: Expr) -> Binding {
        Binding::new(
            v(id),
            IrType::Unknown(UnknownReason::UpstreamUnknown),
            expr,
            Provenance::new("test", ProvenanceSource::DataFlow, ""),
        )
    }
    fn cmp(id: u32, op: BinaryOp) -> Binding {
        binding(
            id,
            Expr::Binary {
                op,
                lhs: v(0),
                rhs: v(0),
            },
        )
    }
    fn block(id: u32, bindings: Vec<u32>) -> HighBlock {
        HighBlock {
            id: bb(id),
            bindings: bindings.into_iter().map(v).collect(),
        }
    }
    fn func(bindings: Vec<Binding>, blocks: Vec<HighBlock>, region: Region) -> HighFunction {
        let mut b: Arena<ValueId, Binding> = Arena::new();
        for x in bindings {
            b.push(x);
        }
        let mut blk: Arena<BlockId, HighBlock> = Arena::new();
        for x in blocks {
            blk.push(x);
        }
        HighFunction {
            id: FuncId::new(0),
            name: None,
            signature: None,
            blocks: blk,
            bindings: b,
            region,
            params: vec![],
            returns: vec![],
        }
    }
    fn run_pass(func: HighFunction) -> (HighFunction, PassResult) {
        let mut ir = sordec_ir::HighIr {
            facts: sordec_ir::WasmFacts {
                imports: vec![],
                exports: vec![],
                function_type_indices: vec![],
                custom_sections: vec![],
            },
            soroban_facts: None,
            functions: vec![func],
            memory: sordec_ir::MemoryImage::empty(),
        };
        let result = GuardClausePass.run(&mut ir);
        (ir.functions.pop().expect("one function"), result)
    }
    fn brk(target: u32) -> Region {
        Region::Break {
            target: bb(target),
            transfer: vec![],
        }
    }

    /// The canonical structurer guard: bare exit in `then`, everything
    /// else nested in `else`.
    fn guard_shape() -> HighFunction {
        func(
            vec![binding(0, Expr::Literal(Literal::I64(5))), cmp(1, BinaryOp::Ne)],
            vec![block(0, vec![0, 1]), block(1, vec![]), block(2, vec![])],
            Region::Sequence(vec![
                Region::Scope {
                    out: bb(2),
                    body: Box::new(Region::Sequence(vec![
                        Region::Basic(bb(0)),
                        Region::If {
                            cond: v(1),
                            then_region: Box::new(brk(2)),
                            else_region: Some(Box::new(Region::Sequence(vec![
                                Region::Basic(bb(1)),
                                Region::Return { values: vec![] },
                            ]))),
                        },
                    ])),
                },
                Region::Basic(bb(2)),
                Region::Unreachable,
            ]),
        )
    }

    #[test]
    fn guard_else_is_hoisted_flat() {
        let (f, result) = run_pass(guard_shape());
        assert!(result.changed);
        assert_eq!(result.metrics.get(M_HOISTED), Some(1));
        assert_eq!(
            f.region,
            Region::Sequence(vec![
                Region::Scope {
                    out: bb(2),
                    body: Box::new(Region::Sequence(vec![
                        Region::Basic(bb(0)),
                        Region::If {
                            cond: v(1),
                            then_region: Box::new(brk(2)),
                            else_region: None,
                        },
                        Region::Basic(bb(1)),
                        Region::Return { values: vec![] },
                    ])),
                },
                Region::Basic(bb(2)),
                Region::Unreachable,
            ])
        );
    }

    #[test]
    fn guard_cascade_flattens_in_one_run() {
        // Two nested guards to the same trap scope: both hoist in a
        // single bottom-up pass, leaving a flat clause sequence.
        let f = func(
            vec![
                binding(0, Expr::Literal(Literal::I64(5))),
                cmp(1, BinaryOp::Ne),
                cmp(2, BinaryOp::Eq),
            ],
            vec![
                block(0, vec![0, 1, 2]),
                block(1, vec![]),
                block(2, vec![]),
                block(3, vec![]),
            ],
            Region::Sequence(vec![
                Region::Scope {
                    out: bb(3),
                    body: Box::new(Region::Sequence(vec![
                        Region::Basic(bb(0)),
                        Region::If {
                            cond: v(1),
                            then_region: Box::new(brk(3)),
                            else_region: Some(Box::new(Region::Sequence(vec![
                                Region::Basic(bb(1)),
                                Region::If {
                                    cond: v(2),
                                    then_region: Box::new(brk(3)),
                                    else_region: Some(Box::new(Region::Sequence(vec![
                                        Region::Basic(bb(2)),
                                        Region::Return { values: vec![] },
                                    ]))),
                                },
                            ]))),
                        },
                    ])),
                },
                Region::Basic(bb(3)),
                Region::Unreachable,
            ]),
        );
        let (f, result) = run_pass(f);
        assert_eq!(result.metrics.get(M_HOISTED), Some(2));
        let Region::Sequence(items) = &f.region else {
            panic!("root stays a sequence");
        };
        let Region::Scope { body, .. } = &items[0] else {
            panic!("scope survives");
        };
        assert_eq!(
            **body,
            Region::Sequence(vec![
                Region::Basic(bb(0)),
                Region::If {
                    cond: v(1),
                    then_region: Box::new(brk(3)),
                    else_region: None,
                },
                Region::Basic(bb(1)),
                Region::If {
                    cond: v(2),
                    then_region: Box::new(brk(3)),
                    else_region: None,
                },
                Region::Basic(bb(2)),
                Region::Return { values: vec![] },
            ])
        );
    }

    #[test]
    fn bare_exit_in_else_is_left_for_polarity() {
        // if c { BIG } else { break }: hoisting would strand the exit
        // after the content arm — D4's flip handles this shape, not D1.
        let mut f = guard_shape();
        if let Region::Sequence(items) = &mut f.region
            && let Region::Scope { body, .. } = &mut items[0]
            && let Region::Sequence(body_items) = &mut **body
            && let Region::If {
                then_region,
                else_region: Some(else_region),
                ..
            } = &mut body_items[1]
        {
            std::mem::swap(&mut **then_region, &mut **else_region);
        }
        let before = f.region.clone();
        let (f, result) = run_pass(f);
        assert!(!result.changed);
        assert_eq!(f.region, before);
    }

    #[test]
    fn both_content_arms_still_flatten() {
        // if c { BIG1-terminating } else { BIG2 }: hoisting BIG2 removes
        // a nesting level without stranding anything.
        let f = func(
            vec![binding(0, Expr::Literal(Literal::I64(5))), cmp(1, BinaryOp::Ne)],
            vec![block(0, vec![0, 1]), block(1, vec![]), block(2, vec![])],
            Region::Sequence(vec![
                Region::Basic(bb(0)),
                Region::If {
                    cond: v(1),
                    then_region: Box::new(Region::Sequence(vec![
                        Region::Basic(bb(1)),
                        Region::Return { values: vec![] },
                    ])),
                    else_region: Some(Box::new(Region::Sequence(vec![
                        Region::Basic(bb(2)),
                        Region::Return { values: vec![] },
                    ]))),
                },
            ]),
        );
        let (f, result) = run_pass(f);
        assert_eq!(result.metrics.get(M_HOISTED), Some(1));
        assert_eq!(
            f.region,
            Region::Sequence(vec![
                Region::Basic(bb(0)),
                Region::If {
                    cond: v(1),
                    then_region: Box::new(Region::Sequence(vec![
                        Region::Basic(bb(1)),
                        Region::Return { values: vec![] },
                    ])),
                    else_region: None,
                },
                Region::Basic(bb(2)),
                Region::Return { values: vec![] },
            ])
        );
    }

    #[test]
    fn non_terminating_then_is_untouched() {
        // The then falls through (no exit): hoisting the else would run
        // it on both paths — must not fire.
        let f = func(
            vec![binding(0, Expr::Literal(Literal::I64(5))), cmp(1, BinaryOp::Ne)],
            vec![block(0, vec![0, 1]), block(1, vec![]), block(2, vec![])],
            Region::Sequence(vec![
                Region::Basic(bb(0)),
                Region::If {
                    cond: v(1),
                    then_region: Box::new(Region::Basic(bb(1))),
                    else_region: Some(Box::new(Region::Sequence(vec![
                        Region::Basic(bb(2)),
                        Region::Return { values: vec![] },
                    ]))),
                },
                Region::Return { values: vec![] },
            ]),
        );
        let before = f.region.clone();
        let (f, result) = run_pass(f);
        assert!(!result.changed);
        assert_eq!(f.region, before);
    }

    #[test]
    fn second_run_reports_no_work() {
        let (f, first) = run_pass(guard_shape());
        assert!(first.changed);
        let (_, second) = run_pass(f);
        assert!(!second.changed, "idempotent after flattening");
    }
}
