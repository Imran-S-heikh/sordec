//! Condition-polarity normalization (D4).
//!
//! Canonical guard form puts the bare exit in the `then` arm:
//! `if cond { break/trap } …`. When the structurer emitted the exit in
//! the `else` — the CFG had the polarity the compiler chose, not the
//! source's — and the condition is an invertible comparison, this pass
//! swaps the arms and inverts the comparator, so guard-clause recovery
//! (D1) sees the canonical shape and the rendered condition reads
//! without negation (kickoff rule: prefer non-negated conditions; a
//! `!`-wrapper is never introduced).
//!
//! ## Safety gates
//!
//! The inversion rewrites the *condition binding's* expression, which
//! would corrupt any other reader, so it fires only when this `If` is
//! the condition's sole live use — exactly the
//! [`InlineClass::Inline`]`(`[`InlineSite::RegionUse`]`)` class the
//! treeification analysis already computes. Only the six total integer
//! comparators invert (`Eq↔Ne`, `Lt↔Ge`, `Le↔Gt`; sound for either
//! signedness, which [`BinaryOp`] erases — floats, the one unsound
//! case, cannot reach deployed Soroban code). Every flip appends a
//! provenance entry, so the audit trail records that the rendered
//! polarity is refined, not raw.

use sordec_common::{Arena, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{BinaryOp, Binding, Expr, HighIr, Region};

use super::{debug_validate, is_bare_exit};
use crate::dataflow::{InlineClass, InlinePlan, InlineSite};
use crate::pass::{Pass, PassResult};

/// Unique pipeline name of this pass.
pub const PASS_NAME: &str = "refine-polarity";

// Metric counter key.
/// Guard conditions inverted into the canonical exit-in-`then` form.
const M_FLIPPED: &str = "refine_polarity_flipped";

/// The condition-polarity normalization pass. Stateless; see the
/// module docs.
#[derive(Debug, Default, Clone, Copy)]
pub struct PolarityPass;

impl Pass<HighIr> for PolarityPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let mut flipped: i64 = 0;
        for func in &mut ir.functions {
            // Use facts computed before rewriting; a flip preserves the
            // use count (same reader, same operands), so the plan stays
            // accurate across the walk.
            let plan = InlinePlan::build(func);
            let mut region = std::mem::replace(&mut func.region, Region::Unreachable);
            flipped += normalize(&mut region, &mut func.bindings, &plan);
            func.region = region;
        }
        if flipped > 0 {
            result.metrics.increment(M_FLIPPED, flipped);
            result.changed = true;
        }
        debug_validate(ir, PASS_NAME);
        result
    }
}

/// Bottom-up walk flipping every non-canonical guard. Returns the
/// number of flips. Exhaustive over [`Region`] so a new variant must
/// declare how the walk treats it.
fn normalize(
    region: &mut Region,
    bindings: &mut Arena<ValueId, Binding>,
    plan: &InlinePlan,
) -> i64 {
    match region {
        Region::Sequence(items) => items
            .iter_mut()
            .map(|item| normalize(item, bindings, plan))
            .sum(),
        Region::Scope { out: _, body } | Region::Loop { body, .. } => {
            normalize(body, bindings, plan)
        }
        Region::If {
            cond,
            then_region,
            else_region,
        } => {
            let mut flips = normalize(then_region, bindings, plan);
            let Some(else_region) = else_region else {
                return flips;
            };
            flips += normalize(else_region, bindings, plan);

            // Non-canonical guard: bare exit in the else, content in
            // the then. Flip when the condition is ours alone to
            // rewrite and its comparator inverts.
            if is_bare_exit(else_region)
                && !is_bare_exit(then_region)
                && matches!(
                    plan.class(*cond),
                    InlineClass::Inline(InlineSite::RegionUse)
                )
                && invert_comparator(bindings, *cond)
            {
                std::mem::swap(&mut **then_region, &mut **else_region);
                flips += 1;
            }
            flips
        }
        Region::Switch { arms, default, .. } => {
            arms.iter_mut()
                .map(|arm| normalize(&mut arm.body, bindings, plan))
                .sum::<i64>()
                + normalize(default, bindings, plan)
        }
        Region::Basic(_)
        | Region::Break { .. }
        | Region::Continue { .. }
        | Region::Transfer { .. }
        | Region::Return { .. }
        | Region::Unreachable
        | Region::Panic { .. }
        | Region::Unstructured { .. } => 0,
    }
}

/// Invert `cond`'s comparator in place when it is one of the six total
/// integer comparisons; records the flip in the binding's provenance.
/// Returns whether the inversion happened.
fn invert_comparator(bindings: &mut Arena<ValueId, Binding>, cond: ValueId) -> bool {
    let Some(binding) = bindings.get_mut(cond) else {
        return false;
    };
    let Expr::Binary { op, .. } = &mut binding.expr else {
        return false;
    };
    let inverted = match op {
        BinaryOp::Eq => BinaryOp::Ne,
        BinaryOp::Ne => BinaryOp::Eq,
        BinaryOp::Lt => BinaryOp::Ge,
        BinaryOp::Ge => BinaryOp::Lt,
        BinaryOp::Le => BinaryOp::Gt,
        BinaryOp::Gt => BinaryOp::Le,
        _ => return false,
    };
    *op = inverted;
    binding.add_provenance(Provenance::new(
        PASS_NAME,
        ProvenanceSource::UpstreamRefinement,
        "comparison inverted: guard exit canonicalized into the then arm",
    ));
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::Pipeline;
    use sordec_common::{BlockId, FuncId, UnknownReason};
    use sordec_ir::{HighBlock, HighFunction, IrType, Literal};

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
    fn block(id: u32, bindings: Vec<u32>) -> HighBlock {
        HighBlock {
            id: bb(id),
            bindings: bindings.into_iter().map(v).collect(),
        }
    }

    /// Single-function `HighIr` wrapper is overkill for these tests; the
    /// pass iterates functions, so exercise `normalize` + the flip
    /// through a hand-built function.
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

    /// The non-canonical guard: content-then, bare-exit else, single-use
    /// invertible condition.
    ///
    /// ```text
    /// 'bb2: {           // Scope{out: bb2}
    ///   bb0: v0 = 5; v1 = ne v0, v0
    ///   if v1 { bb1; return } else { break 'bb2 }
    /// }
    /// bb2: unreachable
    /// ```
    fn exit_in_else() -> HighFunction {
        func(
            vec![
                binding(0, Expr::Literal(Literal::I64(5))),
                binding(
                    1,
                    Expr::Binary {
                        op: BinaryOp::Ne,
                        lhs: v(0),
                        rhs: v(0),
                    },
                ),
            ],
            vec![block(0, vec![0, 1]), block(1, vec![]), block(2, vec![])],
            Region::Sequence(vec![
                Region::Scope {
                    out: bb(2),
                    body: Box::new(Region::Sequence(vec![
                        Region::Basic(bb(0)),
                        Region::If {
                            cond: v(1),
                            then_region: Box::new(Region::Sequence(vec![
                                Region::Basic(bb(1)),
                                Region::Return { values: vec![] },
                            ])),
                            else_region: Some(Box::new(Region::Break {
                                target: bb(2),
                                transfer: vec![],
                            })),
                        },
                    ])),
                },
                Region::Basic(bb(2)),
                Region::Unreachable,
            ]),
        )
    }

    fn high_ir(func: HighFunction) -> sordec_ir::HighIr {
        sordec_ir::HighIr {
            facts: sordec_ir::WasmFacts {
                imports: vec![],
                exports: vec![],
                function_type_indices: vec![],
                custom_sections: vec![],
            },
            soroban_facts: None,
            functions: vec![func],
            memory: sordec_ir::MemoryImage::empty(),
        }
    }

    fn run_pass(func: HighFunction) -> (HighFunction, PassResult) {
        let mut ir = high_ir(func);
        let result = PolarityPass.run(&mut ir);
        (ir.functions.pop().expect("one function"), result)
    }

    #[test]
    fn exit_in_else_flips_comparator_and_swaps_arms() {
        let (f, result) = run_pass(exit_in_else());
        assert!(result.changed);
        assert_eq!(result.metrics.get(M_FLIPPED), Some(1));

        // Comparator inverted with a provenance record.
        let cond = f.bindings.get(v(1)).expect("cond binding");
        assert!(matches!(cond.expr, Expr::Binary { op: BinaryOp::Eq, .. }));
        assert_eq!(cond.provenance().len(), 2);

        // Arms swapped: bare exit now in the then.
        let Region::Sequence(items) = &f.region else {
            panic!("root stays a sequence");
        };
        let Region::Scope { body, .. } = &items[0] else {
            panic!("scope survives");
        };
        let Region::Sequence(body_items) = &**body else {
            panic!("scope body stays a sequence");
        };
        let Region::If {
            then_region,
            else_region,
            ..
        } = &body_items[1]
        else {
            panic!("if survives");
        };
        assert!(matches!(&**then_region, Region::Break { .. }));
        assert!(matches!(
            else_region.as_deref(),
            Some(Region::Sequence(_))
        ));
    }

    #[test]
    fn canonical_guard_is_untouched() {
        // Same shape but the exit is already in the then.
        let mut f = exit_in_else();
        // Swap arms by hand to make it canonical up front.
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
        assert!(matches!(
            f.bindings.get(v(1)).expect("cond").expr,
            Expr::Binary { op: BinaryOp::Ne, .. }
        ));
    }

    #[test]
    fn multi_use_condition_is_never_rewritten() {
        // v1 is also read by a live binding (returned), so the flip
        // would corrupt the second reader — the single-use gate must
        // hold it back.
        let mut f = exit_in_else();
        f.bindings.push(binding(
            2,
            Expr::Unary {
                op: sordec_ir::UnaryOp::Not,
                value: v(1),
            },
        ));
        if let Some(b0) = f.blocks.get(bb(0)) {
            let mut sched = b0.bindings.clone();
            sched.push(v(2));
            f.blocks.get_mut(bb(0)).expect("bb0").bindings = sched;
        }
        // Make the then arm return the second reader so it is live.
        if let Region::Sequence(items) = &mut f.region
            && let Region::Scope { body, .. } = &mut items[0]
            && let Region::Sequence(body_items) = &mut **body
            && let Region::If { then_region, .. } = &mut body_items[1]
        {
            **then_region = Region::Sequence(vec![
                Region::Basic(bb(1)),
                Region::Return { values: vec![v(2)] },
            ]);
        }
        let before = f.region.clone();
        let (f, result) = run_pass(f);
        assert!(!result.changed);
        assert_eq!(f.region, before);
        assert!(matches!(
            f.bindings.get(v(1)).expect("cond").expr,
            Expr::Binary { op: BinaryOp::Ne, .. }
        ));
    }

    #[test]
    fn non_invertible_condition_is_untouched() {
        // Condition is a literal (no comparator to invert): no flip,
        // and — critically — no arm swap without the inversion.
        let mut f = exit_in_else();
        f.bindings.get_mut(v(1)).expect("cond").expr = Expr::Literal(Literal::I64(1));
        let before = f.region.clone();
        let (f, result) = run_pass(f);
        assert!(!result.changed);
        assert_eq!(f.region, before);
    }

    #[test]
    fn second_run_reports_no_work() {
        let (f, first) = run_pass(exit_in_else());
        assert!(first.changed);
        let (_, second) = run_pass(f);
        assert!(!second.changed, "idempotent after canonicalization");
    }

    #[test]
    #[allow(clippy::single_range_in_vec_init)] // fixpoint group, not a range literal
    fn registered_in_a_fixpoint_group_converges() {
        // Sanity: a single-pass fixpoint group around this pass
        // terminates (monotone flips only).
        let mut ir = high_ir(exit_in_else());
        let pipeline: Pipeline<sordec_ir::HighIr> =
            Pipeline::new(vec![Box::new(PolarityPass)], vec![0..1]);
        let report = pipeline.run(&mut ir);
        assert_eq!(report.fixpoint_iterations, vec![2], "flip, then quiesce");
    }
}
