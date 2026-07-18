//! Treeification core (Phase-3 B6): which bindings may fold into their
//! consumer's expression?
//!
//! An **analysis, not a transform** — the IR stays in ANF (the T2
//! deliverable text mandates ANF bindings). Consumers fold at their own
//! layer: `pretty_hir` renders `Inline` operands nested in place today;
//! the W6+ refinement passes and the Phase-4 Rust emitter consult the
//! same plan (the emit-side *presentation* policy — nesting depth,
//! method chaining — is kickoff J3 and layers on top).
//!
//! ## Classification
//!
//! Per binding, [`InlineClass`]:
//!
//! - [`Inline`](InlineClass::Inline): pure-total per the B4 effect
//!   table ([`crate::effects::expr_effects`]), **live**, and read
//!   exactly once by a live consumer. Evaluation may then materialize
//!   at the use site — for a pure-total expression any interleaving is
//!   unobservable, and SSA dominance of its operands over the use site
//!   is transitive. Phis never inline (they are merge points, not
//!   expressions).
//! - [`Dead`](InlineClass::Dead): safe to hide entirely. **While the
//!   region is [`Region::Unstructured`], only zero-use [`Expr::Use`]
//!   bindings qualify** — the de-clutterer's rewiring residue (pruned
//!   params, resolved aliases), which provably has no consumer
//!   anywhere including the invisible lifted terminators. A zero-use
//!   phi or literal may be an invisible branch condition at this stage
//!   and stays [`Pinned`](InlineClass::Pinned). Once the structurer
//!   populates the region tree, conditions become visible uses and the
//!   rule relaxes to "not live + pure-total" with no call-site change.
//! - [`Pinned`](InlineClass::Pinned): everything else — renders/emits
//!   as its own statement. This is K4's default: effectful, trapping,
//!   or unknown-effect bindings never move.
//!
//! ## Liveness
//!
//! Roots are the emission surface: every *scheduled* binding
//! (`HighBlock::bindings`), every return-site value, every region-tree
//! read. Liveness closes transitively over expression reads (a live
//! phi keeps its incoming values live). Uses arriving from non-live
//! bindings (dead residue still referencing its source) do not count
//! toward the single-use test — otherwise every pruned-param tombstone
//! would pin its replacement forever.

use sordec_common::{IrId, ValueId};
use sordec_ir::{Expr, HighFunction, Region};

use crate::dataflow::high_uses::{HighUseIndex, HighUseSite};
use crate::effects::expr_effects;

/// Where an [`InlineClass::Inline`] binding's single live use lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InlineSite {
    /// Operand of another (live) binding's expression.
    ExprOperand {
        /// The consuming binding.
        user: ValueId,
    },
    /// Read by the region tree (a condition, switch index, transfer
    /// source, or region return).
    RegionUse,
}

/// Fold classification for one binding. See the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InlineClass {
    /// Must render/emit as its own statement.
    Pinned,
    /// Pure-total with exactly one live use: may materialize inline.
    Inline(InlineSite),
    /// Unreferenced residue: safe to hide.
    Dead,
}

/// Aggregate counts for metrics (`treeify_*` keys).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InlineStats {
    /// Bindings classified [`InlineClass::Inline`].
    pub inline: u64,
    /// Single-live-use bindings pinned only by their effects — the
    /// readability tax the K4 discipline pays.
    pub pinned_single_use: u64,
    /// Bindings classified [`InlineClass::Dead`].
    pub dead_residue: u64,
}

/// Per-function fold plan. Build with [`InlinePlan::build`]; snapshot
/// semantics (rebuild after mutating the function).
#[derive(Debug, Clone)]
pub struct InlinePlan {
    classes: Vec<InlineClass>,
    stats: InlineStats,
}

impl InlinePlan {
    /// Classify every binding of `func`. Cost: two linear scans plus a
    /// worklist closure.
    #[must_use]
    pub fn build(func: &HighFunction) -> Self {
        let index = HighUseIndex::build(func);
        let structured = !matches!(func.region, Region::Unstructured { .. });
        let live = liveness(func);

        let mut classes = vec![InlineClass::Pinned; func.bindings.len()];
        let mut stats = InlineStats::default();

        for (id, binding) in func.bindings.iter() {
            let slot = id.index() as usize;
            if !live[slot] {
                let is_residue = if structured {
                    expr_effects(&binding.expr).is_pure_total()
                } else {
                    matches!(binding.expr, Expr::Use(_))
                };
                if is_residue {
                    classes[slot] = InlineClass::Dead;
                    stats.dead_residue += 1;
                }
                continue;
            }

            // Live: count uses from live consumers only.
            let mut live_uses = index.uses_of(id).iter().filter(|site| match site {
                HighUseSite::Binding { user } => {
                    live.get(user.index() as usize).copied().unwrap_or(false)
                }
                HighUseSite::Return | HighUseSite::Region => true,
            });
            let (first, second) = (live_uses.next(), live_uses.next());
            let single_use = first.is_some() && second.is_none();
            if !single_use {
                continue;
            }

            // Phis are merge points, never expressions to materialize.
            if matches!(binding.expr, Expr::Phi { .. }) {
                continue;
            }
            if !expr_effects(&binding.expr).is_pure_total() {
                stats.pinned_single_use += 1;
                continue;
            }
            match first.expect("single_use implies a first site") {
                HighUseSite::Binding { user } => {
                    // A self-referencing expression is malformed IR
                    // (the validator's finding); inlining it would
                    // recurse forever at render time.
                    if *user == id {
                        continue;
                    }
                    // Phi incomings are per-edge transfer assignments
                    // (A1 DD2), not expression slots — renderers show
                    // them as raw ids, so folding into one would drop
                    // the binding from display.
                    if func
                        .bindings
                        .get(*user)
                        .is_some_and(|b| matches!(b.expr, Expr::Phi { .. }))
                    {
                        continue;
                    }
                    classes[slot] = InlineClass::Inline(InlineSite::ExprOperand { user: *user });
                    stats.inline += 1;
                }
                HighUseSite::Region => {
                    classes[slot] = InlineClass::Inline(InlineSite::RegionUse);
                    stats.inline += 1;
                }
                // A return-site read has no expression to fold into at
                // this layer; the structurer's Region::Return makes it
                // a RegionUse later.
                HighUseSite::Return => {}
            }
        }

        Self { classes, stats }
    }

    /// Classification of `value` ([`InlineClass::Pinned`] for ids
    /// outside the arena).
    #[must_use]
    pub fn class(&self, value: ValueId) -> InlineClass {
        self.classes
            .get(value.index() as usize)
            .copied()
            .unwrap_or(InlineClass::Pinned)
    }

    /// Aggregate counts for metrics.
    #[must_use]
    pub fn stats(&self) -> InlineStats {
        self.stats
    }
}

/// Liveness over bindings: reachable from the emission surface
/// (schedule ∪ returns ∪ region reads) through expression reads.
fn liveness(func: &HighFunction) -> Vec<bool> {
    let mut live = vec![false; func.bindings.len()];
    let mut worklist: Vec<ValueId> = Vec::new();
    let push = |value: ValueId, live: &mut Vec<bool>, worklist: &mut Vec<ValueId>| {
        if let Some(slot) = live.get_mut(value.index() as usize)
            && !*slot
        {
            *slot = true;
            worklist.push(value);
        }
    };

    for (_block_id, block) in func.blocks.iter() {
        for &value in &block.bindings {
            push(value, &mut live, &mut worklist);
        }
    }
    for site_values in &func.returns {
        for &value in site_values {
            push(value, &mut live, &mut worklist);
        }
    }
    func.region
        .for_each_value_use(|value| push(value, &mut live, &mut worklist));

    while let Some(value) = worklist.pop() {
        if let Some(binding) = func.bindings.get(value) {
            binding
                .expr
                .for_each_value_use(|read| push(read, &mut live, &mut worklist));
        }
    }
    live
}

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{Arena, BlockId, FuncId, Provenance, ProvenanceSource, UnknownReason};
    use sordec_ir::{BinaryOp, Binding, HighBlock, IrType, Literal};

    fn v(idx: u32) -> ValueId {
        ValueId::from_index(idx)
    }

    fn unstructured() -> Region {
        Region::Unstructured {
            entry: BlockId::from_index(0),
            reason: UnknownReason::UpstreamUnknown,
        }
    }

    /// Function whose block schedules exactly `scheduled`; every expr
    /// gets a binding in id order.
    fn func_with(
        exprs: Vec<Expr>,
        scheduled: Vec<ValueId>,
        returns: Vec<Vec<ValueId>>,
        region: Region,
    ) -> HighFunction {
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        for (i, expr) in exprs.into_iter().enumerate() {
            bindings.push(Binding::new(
                v(i as u32),
                IrType::Unknown(UnknownReason::UpstreamUnknown),
                expr,
                Provenance {
                    pass: "test",
                    source: ProvenanceSource::DataFlow,
                    note: String::new(),
                },
            ));
        }
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        blocks.push(HighBlock {
            id: BlockId::from_index(0),
            bindings: scheduled,
        });
        HighFunction {
            id: FuncId::from_index(0),
            name: None,
            signature: None,
            blocks,
            bindings,
            region,
            params: vec![],
            returns,
        }
    }

    fn add(lhs: ValueId, rhs: ValueId) -> Expr {
        Expr::Binary {
            op: BinaryOp::Add,
            lhs,
            rhs,
        }
    }

    #[test]
    fn pure_single_use_scheduled_binding_inlines() {
        // v0 literal used once by scheduled v1.
        let func = func_with(
            vec![Expr::Literal(Literal::I32(7)), add(v(0), v(0))],
            vec![v(0), v(1)],
            vec![vec![v(1)]],
            unstructured(),
        );
        // v0 has TWO occurrences in v1 (lhs+rhs) — not single-use.
        let plan = InlinePlan::build(&func);
        assert_eq!(plan.class(v(0)), InlineClass::Pinned);

        // With one occurrence it inlines.
        let func = func_with(
            vec![
                Expr::Literal(Literal::I32(7)),
                Expr::Literal(Literal::I32(1)),
                add(v(0), v(1)),
            ],
            vec![v(0), v(1), v(2)],
            vec![vec![v(2)]],
            unstructured(),
        );
        let plan = InlinePlan::build(&func);
        assert_eq!(
            plan.class(v(0)),
            InlineClass::Inline(InlineSite::ExprOperand { user: v(2) })
        );
        assert_eq!(plan.stats().inline, 2, "both literal operands fold");
    }

    #[test]
    fn impure_single_use_is_pinned_and_counted() {
        // v0 = div (may trap) used once: pinned by effects.
        let func = func_with(
            vec![
                Expr::Literal(Literal::I32(6)),
                Expr::Literal(Literal::I32(3)),
                Expr::Binary {
                    op: BinaryOp::Div,
                    lhs: v(0),
                    rhs: v(1),
                },
                add(v(2), v(2)),
            ],
            vec![v(0), v(1), v(2), v(3)],
            vec![vec![v(3)]],
            unstructured(),
        );
        let plan = InlinePlan::build(&func);
        // v2 is used twice (lhs+rhs) — build a single-use variant.
        assert_eq!(plan.class(v(2)), InlineClass::Pinned);

        let func = func_with(
            vec![
                Expr::Literal(Literal::I32(6)),
                Expr::Literal(Literal::I32(3)),
                Expr::Binary {
                    op: BinaryOp::Div,
                    lhs: v(0),
                    rhs: v(1),
                },
                Expr::Use(v(2)),
            ],
            vec![v(0), v(1), v(2), v(3)],
            vec![vec![v(3)]],
            unstructured(),
        );
        let plan = InlinePlan::build(&func);
        assert_eq!(plan.class(v(2)), InlineClass::Pinned);
        assert_eq!(plan.stats().pinned_single_use, 1);
    }

    #[test]
    fn zero_use_use_expr_is_dead_residue_pre_structuring() {
        // v1 = Use(v0) with no consumers: declutter tombstone.
        let func = func_with(
            vec![Expr::Literal(Literal::I32(7)), Expr::Use(v(0))],
            vec![v(0)],
            vec![vec![v(0)]],
            unstructured(),
        );
        let plan = InlinePlan::build(&func);
        assert_eq!(plan.class(v(1)), InlineClass::Dead);
        assert_eq!(plan.stats().dead_residue, 1);
    }

    #[test]
    fn zero_use_literal_and_phi_stay_pinned_pre_structuring() {
        // Unscheduled zero-use literal/phi may be an invisible branch
        // condition while the region is unstructured — never Dead.
        let func = func_with(
            vec![
                Expr::Literal(Literal::I32(7)),
                Expr::Phi { incoming: vec![] },
            ],
            vec![],
            vec![],
            unstructured(),
        );
        let plan = InlinePlan::build(&func);
        assert_eq!(plan.class(v(0)), InlineClass::Pinned);
        assert_eq!(plan.class(v(1)), InlineClass::Pinned);
        assert_eq!(plan.stats().dead_residue, 0);
    }

    #[test]
    fn structured_region_relaxes_deadness_and_counts_cond_uses() {
        // With a structured region: a zero-use pure literal is Dead,
        // and a cond-only comparison is single-use via RegionUse.
        let region = Region::If {
            cond: v(2),
            then_region: Box::new(Region::Return { values: vec![] }),
            else_region: None,
        };
        let func = func_with(
            vec![
                Expr::Literal(Literal::I32(7)), // v0: zero-use -> Dead
                Expr::Literal(Literal::I32(0)), // v1: operand of v2
                Expr::Binary {
                    op: BinaryOp::Lt,
                    lhs: v(1),
                    rhs: v(1),
                }, // v2: cond-only
            ],
            vec![v(1), v(2)],
            vec![],
            region,
        );
        let plan = InlinePlan::build(&func);
        assert_eq!(plan.class(v(0)), InlineClass::Dead);
        assert_eq!(plan.class(v(2)), InlineClass::Inline(InlineSite::RegionUse));
    }

    #[test]
    fn uses_from_dead_residue_do_not_pin_the_source() {
        // v0 is read by live v2 once AND by dead tombstone v1 — the
        // tombstone must not count: v0 inlines.
        let func = func_with(
            vec![
                Expr::Literal(Literal::I32(7)),
                Expr::Use(v(0)), // unscheduled, unreferenced residue
                Expr::Unary {
                    op: sordec_ir::UnaryOp::Not,
                    value: v(0),
                },
            ],
            vec![v(0), v(2)],
            vec![vec![v(2)]],
            unstructured(),
        );
        let plan = InlinePlan::build(&func);
        assert_eq!(plan.class(v(1)), InlineClass::Dead);
        assert_eq!(
            plan.class(v(0)),
            InlineClass::Inline(InlineSite::ExprOperand { user: v(2) })
        );
    }

    #[test]
    fn phi_consumed_value_stays_pinned() {
        // v0's single use is a live phi's incoming — an edge transfer,
        // not an expression slot: must not inline.
        let func = func_with(
            vec![
                Expr::Literal(Literal::I32(7)),
                Expr::Phi {
                    incoming: vec![(BlockId::from_index(0), v(0))],
                },
                Expr::Use(v(1)),
            ],
            vec![v(0), v(2)],
            vec![vec![v(2)]],
            unstructured(),
        );
        let plan = InlinePlan::build(&func);
        assert_eq!(plan.class(v(0)), InlineClass::Pinned);
    }

    #[test]
    fn return_only_use_stays_pinned() {
        let func = func_with(
            vec![Expr::Literal(Literal::I32(7))],
            vec![v(0)],
            vec![vec![v(0)]],
            unstructured(),
        );
        let plan = InlinePlan::build(&func);
        assert_eq!(plan.class(v(0)), InlineClass::Pinned);
    }
}
