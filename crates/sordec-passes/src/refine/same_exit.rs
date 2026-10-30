//! Drop a branch whose two ways end the same.
//!
//! # The shape
//!
//! The SDK's conversion of an argument tests one encoding, then the
//! other, and traps on neither. `Symbol::try_from_val`, inlined into an
//! entrypoint that hands its argument straight back, reaches us as
//!
//! ```text
//! if has_tag(v, SymbolSmall) { return v }
//! if !has_tag(v, SymbolObject) { panic!() }
//! return v
//! ```
//!
//! [`crate::marshalling::guard`] moves the second test's trap into the
//! regenerated wrapper, where `#[contractimpl]` re-runs the conversion.
//! The first test is left choosing between two ways that do the same
//! thing:
//!
//! ```text
//! if has_tag(v, SymbolSmall) { return v }        →        return v
//! return v
//! ```
//!
//! and since a `Val`'s tag is not a Rust-level fact, the reconstruction
//! cannot even spell the test: it prints as a gap. The same residue is
//! left by every two-form scalar once its unpacks are named
//! ([`crate::marshalling::ScalarDecodePass`]) — both arms then compute the
//! parameter, and the re-encode's own small-or-object test returns it
//! either way.
//!
//! # The rewrite
//!
//! A branch is dropped when both of its ways reach the same place doing
//! nothing on the way that anyone can see:
//!
//! - both arms fall through, holding only such bindings — the branch is
//!   removed;
//! - one arm returns some values, and the other arm (or, without one, the
//!   code after the branch) falls through to a return of the same values —
//!   the branch is removed and the code after it returns them;
//! - both arms return the same values — the branch becomes that return.
//!
//! "The same values" is read through renames ([`resolve_use`]). The arms'
//! bindings are unscheduled, as a folded arm's are
//! ([`super::const_branch`]); the condition's own binding stays where it
//! is scheduled, and records the drop in its provenance.
//!
//! # Why it is exact
//!
//! Every binding either way executes is pure and total
//! ([`crate::effects`]): it writes nothing, reads no mutable state and
//! cannot trap. Executing it or not is invisible, so the two ways differ
//! in nothing but the branch itself, and the program without the branch
//! does what both did. The returned values are the same values, defined
//! before the branch, so they are available whichever way is gone.
//!
//! # Gates
//!
//! - Each way is a run of `Basic` blocks of pure, total bindings (nested
//!   sequences of them included) ending in a `return` or falling through.
//!   A transfer counts as falling through only when it assigns no merge
//!   and goes to the block that follows the branch anyway. Any other
//!   transfer, a `break`, `continue`, trap, loop, switch, labelled scope
//!   or nested branch on the way leaves the branch alone: where those go
//!   is not followed.
//! - The code after the branch is read only through the sequences that
//!   hold it and the arms of enclosing branches; inside a scope or a loop
//!   nothing after the body is assumed.
//! - Nothing outside a dropped arm reads a binding scheduled in it, and a
//!   return that replaces the branch returns values defined outside both
//!   arms.

use std::collections::{HashMap, HashSet};

use sordec_common::{BlockId, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{HighFunction, HighIr, Region};

use super::debug_validate;
use crate::dataflow::resolve_use;
use crate::effects::expr_effects;
use crate::metrics_catalog::REFINE_SAME_EXIT_BRANCHES as M_DROPPED;
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field on every dropped branch's
/// condition.
pub const PASS_NAME: &str = "refine-same-exit";

/// Drops branches whose two ways end the same.
#[derive(Debug, Default, Clone, Copy)]
pub struct SameExitPass;

impl Pass<HighIr> for SameExitPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            let mut ctx = Ctx::of(func);
            let region = std::mem::replace(&mut func.region, Region::Unreachable);
            let region = simplify(&mut ctx, func, region, None, None);
            func.region = region;
            if ctx.dropped.is_empty() {
                continue;
            }
            result.changed = true;
            result.metrics.increment(M_DROPPED, ctx.dropped.len() as i64);
            for cond in ctx.dropped {
                if let Some(binding) = func.bindings.get_mut(cond) {
                    binding.add_provenance(Provenance::new(
                        PASS_NAME,
                        ProvenanceSource::DataFlow,
                        "the branch on this condition was dropped: both ways reach the same exit \
                         through pure, total bindings",
                    ));
                }
            }
        }
        debug_validate(ir, PASS_NAME);
        result
    }
}

/// Where a way ends, when it ends somewhere this pass can name.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Exit {
    /// It reaches the end of the region and carries on after it.
    Falls,
    /// It returns these values, each resolved through renames.
    Returns(Vec<ValueId>),
}

/// What the walk needs of the function, computed before the region is
/// taken apart and kept current as branches go.
struct Ctx {
    /// Blocks every binding of which is pure and total.
    pure: HashSet<BlockId>,
    /// How many times each value is read anywhere live: by a scheduled
    /// binding, or by the region — whose transfers are the reads that feed
    /// a merge. A merge's own list of incoming values is not counted: it
    /// outlives the edges, and a merge the trivial-merge pass retired
    /// still lists what it once merged.
    uses: HashMap<ValueId, usize>,
    /// The conditions of the branches dropped so far.
    dropped: Vec<ValueId>,
}

impl Ctx {
    fn of(func: &HighFunction) -> Self {
        let pure = func
            .blocks
            .iter()
            .filter(|(_, block)| {
                block.bindings.iter().all(|id| {
                    func.bindings.get(*id).is_some_and(|b| expr_effects(&b.expr).is_pure_total())
                })
            })
            .map(|(id, _)| id)
            .collect();
        let mut uses: HashMap<ValueId, usize> = HashMap::new();
        let mut count = |v: ValueId| *uses.entry(v).or_default() += 1;
        // Only blocks the region still holds: an arm an earlier fold
        // dropped leaves its block in the arena, and nothing in it runs.
        reads_of(func, &func.region, &mut count);
        Self {
            pure,
            uses,
            dropped: Vec::new(),
        }
    }
}

/// The first block control reaches entering `items`, when it is a block.
fn first_block(items: &[Region]) -> Option<BlockId> {
    match items.first()? {
        Region::Basic(b) => Some(*b),
        Region::Sequence(inner) => first_block(inner),
        _ => None,
    }
}

/// Rebuild `region`, dropping every branch whose ways end the same.
/// `after` is where control goes when `region` falls through, when known,
/// and `join` the block it falls through to.
fn simplify(
    ctx: &mut Ctx,
    func: &HighFunction,
    region: Region,
    after: Option<&Exit>,
    join: Option<BlockId>,
) -> Region {
    match region {
        Region::Sequence(items) => {
            // Back to front, so each item sees the already simplified code
            // after it.
            let mut rest: Vec<Region> = Vec::with_capacity(items.len());
            for item in items.into_iter().rev() {
                let next = if rest.is_empty() { join } else { first_block(&rest) };
                let cont = way(ctx, func, &rest, after, join);
                match simplify(ctx, func, item, cont.as_ref(), next) {
                    Region::Sequence(inner) => {
                        rest.splice(0..0, inner);
                    }
                    other => rest.insert(0, other),
                }
            }
            Region::Sequence(rest)
        }
        Region::If {
            cond,
            then_region,
            else_region,
        } => {
            let then_region = simplify(ctx, func, *then_region, after, join);
            let else_region = else_region.map(|e| simplify(ctx, func, *e, after, join));
            match decide(ctx, func, &then_region, else_region.as_ref(), after, join) {
                Some(replacement) => {
                    // Keep the use counts current: what the branch and its
                    // arms read is no longer read, and a return standing in
                    // for it reads its values.
                    let mut forget = |v: ValueId| {
                        if let Some(n) = ctx.uses.get_mut(&v) {
                            *n = n.saturating_sub(1);
                        }
                    };
                    forget(cond);
                    for arm in std::iter::once(&then_region).chain(else_region.as_ref()) {
                        reads_of(func, arm, &mut forget);
                    }
                    replacement.for_each_value_use(|v| *ctx.uses.entry(v).or_default() += 1);
                    ctx.dropped.push(cond);
                    replacement
                }
                None => Region::If {
                    cond,
                    then_region: Box::new(then_region),
                    else_region: else_region.map(Box::new),
                },
            }
        }
        // What follows a scope or a loop body is not followed: a `break`
        // or a `continue` can leave it from anywhere.
        Region::Scope { out, body } => Region::Scope {
            out,
            body: Box::new(simplify(ctx, func, *body, None, None)),
        },
        Region::Loop { header, body, kind } => Region::Loop {
            header,
            body: Box::new(simplify(ctx, func, *body, None, None)),
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
                    arm.body = simplify(ctx, func, arm.body, None, None);
                    arm
                })
                .collect(),
            default: Box::new(simplify(ctx, func, *default, None, None)),
            dispatch,
        },
        other => other,
    }
}

/// Every value `region` reads: through the region itself, and through the
/// bindings scheduled in its blocks.
fn reads_of(func: &HighFunction, region: &Region, f: &mut impl FnMut(ValueId)) {
    region.for_each_node(|node| {
        if let Region::Basic(b) = node
            && let Some(block) = func.blocks.get(*b)
        {
            for id in &block.bindings {
                if let Some(binding) = func.bindings.get(*id) {
                    binding.expr.for_each_value_use(&mut *f);
                }
            }
        }
    });
    region.for_each_value_use(&mut *f);
}

/// What replaces a branch whose two ways end the same, or `None` to keep
/// it.
fn decide(
    ctx: &Ctx,
    func: &HighFunction,
    then_region: &Region,
    else_region: Option<&Region>,
    after: Option<&Exit>,
    join: Option<BlockId>,
) -> Option<Region> {
    let falls = Exit::Falls;
    let t = way(ctx, func, std::slice::from_ref(then_region), Some(&falls), join)?;
    let f = match else_region {
        Some(e) => way(ctx, func, std::slice::from_ref(e), Some(&falls), join)?,
        None => Exit::Falls,
    };
    let replacement = match (&t, &f) {
        (Exit::Falls, Exit::Falls) => Region::Sequence(vec![]),
        (Exit::Returns(a), Exit::Returns(b)) if a == b => Region::Return { values: a.clone() },
        (Exit::Returns(values), Exit::Falls) | (Exit::Falls, Exit::Returns(values))
            if after.is_some_and(|a| *a == Exit::Returns(values.clone())) =>
        {
            Region::Sequence(vec![])
        }
        _ => return None,
    };
    // The arms' bindings are about to be unscheduled: nothing outside
    // them may read one, and a return that stands in for the branch must
    // not name one.
    let mut inside: HashSet<ValueId> = HashSet::new();
    let mut inner_uses: HashMap<ValueId, usize> = HashMap::new();
    for arm in std::iter::once(then_region).chain(else_region) {
        arm.for_each_node(|node| {
            if let Region::Basic(b) = node
                && let Some(block) = func.blocks.get(*b)
            {
                inside.extend(block.bindings.iter().copied());
            }
        });
        reads_of(func, arm, &mut |v| *inner_uses.entry(v).or_default() += 1);
    }
    let read_outside = inside
        .iter()
        .any(|id| ctx.uses.get(id).copied().unwrap_or(0) > inner_uses.get(id).copied().unwrap_or(0));
    if read_outside {
        return None;
    }
    if let Region::Return { values } = &replacement
        && values.iter().any(|v| inside.contains(v))
    {
        return None;
    }
    Some(replacement)
}

/// Where control entering `items` ends, when every step on the way is a
/// block of pure, total bindings: the `return` it reaches, or `after` when
/// it runs off the end — or leaves by a transfer that assigns nothing to
/// `join`, the block it would fall through to anyway. `None` at the first
/// step that is anything else.
fn way(ctx: &Ctx, func: &HighFunction, items: &[Region], after: Option<&Exit>, join: Option<BlockId>) -> Option<Exit> {
    for item in items {
        match item {
            Region::Basic(b) if ctx.pure.contains(b) => {}
            Region::Sequence(inner) => match way(ctx, func, inner, Some(&Exit::Falls), join)? {
                Exit::Falls => {}
                end => return Some(end),
            },
            Region::Return { values } => {
                return Some(Exit::Returns(values.iter().map(|v| resolve_use(func, *v)).collect()));
            }
            Region::Transfer { target, transfer } if transfer.is_empty() && Some(*target) == join => {
                return after.cloned();
            }
            _ => return None,
        }
    }
    after.cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};
    use sordec_common::{BlockId, IrId};
    use sordec_ir::{Expr, HighBlock, KnownOp, Literal, SemanticOp};

    fn b(i: u32) -> BlockId {
        BlockId::from_index(i)
    }

    /// `v0` is the subject, `v1 = has_tag(v0, SymbolSmall)`, `v2 = v0`
    /// (a rename), `v3` a call (not pure). Block 0 holds `v1`; the
    /// region is built by each test.
    fn shape(region: Region, extra_blocks: Vec<Vec<u32>>) -> HighIr {
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] }, // v0
                Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck {
                    value: v(0),
                    tag: 14,
                    negated: false,
                })), // v1
                Expr::Use(v(0)), // v2
                Expr::Call {
                    target: sordec_common::FuncId::from_index(0),
                    args: vec![v(0)],
                }, // v3
                Expr::Literal(Literal::I64(7)), // v4
                Expr::Literal(Literal::I64(7)), // v5
                Expr::Phi { incoming: vec![(b(1), v(4))] }, // v6 — a retired merge of v4
            ],
            vec![v(0)],
            vec![1],
        );
        for (i, ids) in extra_blocks.into_iter().enumerate() {
            f.blocks.push(HighBlock {
                id: b(i as u32 + 1),
                bindings: ids.into_iter().map(v).collect(),
            });
        }
        f.region = region;
        module(vec![f])
    }

    fn ret(i: u32) -> Region {
        Region::Return { values: vec![v(i)] }
    }

    fn branch(then_region: Region, else_region: Option<Region>) -> Region {
        Region::If {
            cond: v(1),
            then_region: Box::new(then_region),
            else_region: else_region.map(Box::new),
        }
    }

    fn has_if(m: &HighIr) -> bool {
        let mut found = false;
        m.functions[0].region.for_each_node(|n| found |= matches!(n, Region::If { .. }));
        found
    }

    /// `if has_tag(v, SymbolSmall) { return v }  return v` — the
    /// conversion residue: the branch goes, the return stays.
    #[test]
    fn a_return_of_what_follows_drops_the_branch() {
        let mut m = shape(
            Region::Sequence(vec![Region::Basic(b(0)), branch(ret(0), None), Region::Basic(b(1)), ret(2)]),
            vec![vec![2]],
        );
        assert!(SameExitPass.run(&mut m).changed);
        assert!(!has_if(&m));
        assert!(matches!(
            &m.functions[0].region,
            Region::Sequence(items) if matches!(items.last(), Some(Region::Return { .. }))
        ));
    }

    /// `if c { return 7 }  return 7`, each `7` its own binding: values are
    /// compared through renames only, so two constants stay two returns.
    #[test]
    fn two_bindings_of_one_constant_are_left_alone() {
        let mut m = shape(
            Region::Sequence(vec![
                Region::Basic(b(0)),
                branch(Region::Sequence(vec![Region::Basic(b(1)), ret(4)]), None),
                Region::Basic(b(2)),
                ret(5),
            ]),
            vec![vec![4], vec![5]],
        );
        assert!(!SameExitPass.run(&mut m).changed);
    }

    /// Both arms return the same value: the branch is that return.
    #[test]
    fn two_equal_returns_become_one() {
        let mut m = shape(
            Region::Sequence(vec![
                Region::Basic(b(0)),
                branch(ret(0), Some(Region::Sequence(vec![Region::Basic(b(1)), ret(2)]))),
            ]),
            vec![vec![4, 2]],
        );
        assert!(SameExitPass.run(&mut m).changed);
        assert!(!has_if(&m));
    }

    /// Two arms that only compute pure values and fall through choose
    /// nothing.
    #[test]
    fn pure_arms_that_fall_through_are_no_branch() {
        let mut m = shape(
            Region::Sequence(vec![
                Region::Basic(b(0)),
                branch(Region::Basic(b(1)), Some(Region::Basic(b(2)))),
                Region::Return { values: vec![] },
            ]),
            vec![vec![4], vec![2]],
        );
        assert!(SameExitPass.run(&mut m).changed);
        assert!(!has_if(&m));
    }

    /// The code after the branch returns something else: the two ways
    /// differ.
    #[test]
    fn a_different_return_keeps_the_branch() {
        let mut m = shape(
            Region::Sequence(vec![Region::Basic(b(0)), branch(ret(0), None), Region::Basic(b(1)), ret(4)]),
            vec![vec![4]],
        );
        assert!(!SameExitPass.run(&mut m).changed);
        assert!(has_if(&m));
    }

    /// A call on the way may do anything: the branch is real.
    #[test]
    fn an_effect_on_the_way_keeps_the_branch() {
        let mut m = shape(
            Region::Sequence(vec![Region::Basic(b(0)), branch(ret(0), None), Region::Basic(b(1)), ret(0)]),
            vec![vec![3]],
        );
        assert!(!SameExitPass.run(&mut m).changed);
    }

    /// A trap on one way is not the other way's return.
    #[test]
    fn a_trap_keeps_the_branch() {
        let mut m = shape(
            Region::Sequence(vec![
                Region::Basic(b(0)),
                branch(Region::Panic { kind: sordec_ir::PanicKind::Bare }, None),
                ret(0),
            ]),
            vec![],
        );
        assert!(!SameExitPass.run(&mut m).changed);
    }

    /// A value computed in the arm and read after it keeps the arm.
    #[test]
    fn a_value_read_outside_the_arm_keeps_it() {
        let mut m = shape(
            Region::Sequence(vec![
                Region::Basic(b(0)),
                branch(Region::Basic(b(1)), None),
                Region::Return { values: vec![v(4)] },
            ]),
            vec![vec![4]],
        );
        assert!(!SameExitPass.run(&mut m).changed);
    }

    /// An arm ending in a transfer that assigns nothing, to the block after
    /// the branch, falls through — the structurer's spelling of the join.
    #[test]
    fn an_empty_transfer_to_the_next_block_falls_through() {
        let transfer_to = |t: u32| Region::Transfer { target: b(t), transfer: vec![] };
        let mut m = shape(
            Region::Sequence(vec![
                Region::Basic(b(0)),
                branch(Region::Sequence(vec![Region::Basic(b(1)), transfer_to(2)]), None),
                Region::Basic(b(2)),
                Region::Return { values: vec![] },
            ]),
            vec![vec![4], vec![]],
        );
        assert!(SameExitPass.run(&mut m).changed);
        assert!(!has_if(&m));
    }

    /// A transfer to some other block is not where the code after the
    /// branch goes.
    #[test]
    fn a_transfer_elsewhere_keeps_the_branch() {
        let mut m = shape(
            Region::Sequence(vec![
                Region::Basic(b(0)),
                branch(
                    Region::Sequence(vec![
                        Region::Basic(b(1)),
                        Region::Transfer { target: b(3), transfer: vec![] },
                    ]),
                    None,
                ),
                Region::Basic(b(2)),
                Region::Return { values: vec![] },
            ]),
            vec![vec![4], vec![], vec![]],
        );
        assert!(!SameExitPass.run(&mut m).changed);
    }

    /// Nothing is assumed about what follows a scope: a `break` can leave
    /// it from anywhere.
    #[test]
    fn a_return_after_a_scope_is_not_followed() {
        let mut m = shape(
            Region::Sequence(vec![
                Region::Scope {
                    out: b(2),
                    body: Box::new(Region::Sequence(vec![Region::Basic(b(0)), branch(ret(0), None)])),
                },
                ret(0),
            ]),
            vec![vec![], vec![]],
        );
        assert!(!SameExitPass.run(&mut m).changed);
    }

    #[test]
    fn the_pass_is_idempotent() {
        let mut m = shape(
            Region::Sequence(vec![Region::Basic(b(0)), branch(ret(0), None), Region::Basic(b(1)), ret(2)]),
            vec![vec![2]],
        );
        assert!(SameExitPass.run(&mut m).changed);
        assert!(!SameExitPass.run(&mut m).changed);
    }
}
