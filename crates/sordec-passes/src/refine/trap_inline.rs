//! Bounded trap inlining (D2).
//!
//! LLVM tail-merges the `unreachable` every panic guard jumps to into
//! one shared block, which the structurer faithfully renders as a
//! labeled scope with `break`s from every guard:
//!
//! ```text
//! 'bb4: {                          if cond_a { unreachable }
//!   if cond_a { break 'bb4 }       …
//!   …                        →     if cond_b { unreachable }
//!   if cond_b { break 'bb4 }       …
//!   …
//! }
//! unreachable                      (scope + trailing trap gone)
//! ```
//!
//! Undoing the merge restores the source's `if cond { panic!() }` shape
//! (SAILR's "compiler-induced goto"). The approved W6 bound: only
//! **zero-binding terminating out-blocks** whose breaks all carry empty
//! transfers are inlined — nothing is duplicated but a bare
//! `Unreachable`/`Return` node, so the K4 effect discipline holds by
//! construction, and `Return` operands are dominance-safe at every
//! break site (SSA: a value read by the shared block dominates each of
//! its predecessors).
//!
//! Shared out-blocks that *carry* bindings (the panic-glue helper
//! `call func_N; unreachable` reached by several guards) are
//! **duplicated** under fresh value/block ids (W7 D2-ext) when the
//! block is small and *externally closed* — no binding reads a value
//! defined inside the block, so each clone keeps the original operand
//! ids (SSA: externals dominate every break site) and no expression
//! rewriting is needed. The W6 corpus measured every such block as
//! exactly one zero-argument glue call; the closure/size gates bound
//! the general case. Duplication is K4-path-equivalent — the block
//! already executed after each break; only its region position moves.
//! Blocks failing a gate stay labeled and counted. Single-predecessor
//! trap blocks never reach this pass at all — the structurer inlines
//! non-merge blocks at their branch site.

use std::collections::{HashMap, VecDeque};

use sordec_common::{BlockId, IrId, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{Binding, HighBlock, HighFunction, HighIr, Region};

use super::debug_validate;
use crate::pass::{Pass, PassResult};
use crate::structuring::seq;

/// Unique pipeline name of this pass.
pub const PASS_NAME: &str = "refine-trap-inline";

// Metric counter keys.
/// Break sites rewritten into an inline copy of the shared terminator.
const M_INLINED: &str = "refine_traps_inlined";
/// Shared terminating out-blocks left labeled because they carry
/// bindings that fail the duplication gates (intra-block references or
/// over the size cap).
const M_SHARED_WITH_BINDINGS: &str = "refine_shared_trap_with_bindings";
/// Break sites rewritten into a fresh-id duplicate of a
/// binding-carrying shared trap block (D2-ext).
const M_DUPLICATED: &str = "refine_traps_duplicated";

/// Readability cap on duplicated blocks: every corpus witness carries
/// exactly one glue-call binding; the cap only bounds pathological
/// helpers.
const MAX_DUPLICATED_BINDINGS: usize = 4;

/// The bounded trap-inlining pass. Stateless; see the module docs.
#[derive(Debug, Default, Clone, Copy)]
pub struct TrapInlinePass;

impl Pass<HighIr> for TrapInlinePass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let mut stats = Stats::default();
        for func in &mut ir.functions {
            let region = std::mem::replace(&mut func.region, Region::Unreachable);
            func.region = inline_traps(region, func, &mut stats);
        }
        if stats.inlined > 0 {
            result.metrics.increment(M_INLINED, stats.inlined);
            result.changed = true;
        }
        if stats.duplicated > 0 {
            result.metrics.increment(M_DUPLICATED, stats.duplicated);
            result.changed = true;
        }
        if stats.shared_with_bindings > 0 {
            result
                .metrics
                .increment(M_SHARED_WITH_BINDINGS, stats.shared_with_bindings);
        }
        debug_validate(ir, PASS_NAME);
        result
    }
}

#[derive(Default)]
struct Stats {
    inlined: i64,
    duplicated: i64,
    shared_with_bindings: i64,
}

/// Bottom-up rewrite. The trap pattern lives at a sequence tail:
/// `[…, Scope { out: T }, Basic(T), terminator]` — one scan per visit;
/// cascades exposed by a splice converge through the fixpoint group.
fn inline_traps(region: Region, func: &mut HighFunction, stats: &mut Stats) -> Region {
    match region {
        Region::Sequence(items) => {
            let items: Vec<Region> = items
                .into_iter()
                .map(|item| inline_traps(item, func, stats))
                .collect();
            rewrite_tail(items, func, stats)
        }
        Region::Scope { out, body } => Region::Scope {
            out,
            body: Box::new(inline_traps(*body, func, stats)),
        },
        Region::Loop { header, body, kind } => Region::Loop {
            header,
            body: Box::new(inline_traps(*body, func, stats)),
            kind,
        },
        Region::If {
            cond,
            then_region,
            else_region,
        } => Region::If {
            cond,
            then_region: Box::new(inline_traps(*then_region, func, stats)),
            else_region: else_region.map(|e| Box::new(inline_traps(*e, func, stats))),
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
                    arm.body = inline_traps(arm.body, func, stats);
                    arm
                })
                .collect(),
            default: Box::new(inline_traps(*default, func, stats)),
            dispatch,
        },
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

/// How one matched tail pattern fires.
enum Fire {
    /// No match, or the gates refused.
    No,
    /// Zero-binding block: every break site gets the bare terminator.
    Inline,
    /// Binding-carrying externally-closed block: every break site gets
    /// a fresh-id duplicate (D2-ext).
    Duplicate,
}

/// Fire the tail pattern on one (already child-rewritten) sequence.
fn rewrite_tail(mut items: Vec<Region>, func: &mut HighFunction, stats: &mut Stats) -> Region {
    // `[…, Scope{out: T}, Basic(T), <Unreachable | Panic | Return>]`
    // with the terminator as the final item.
    let fire = if items.len() < 3 {
        Fire::No
    } else {
        let n = items.len();
        // `Panic` joins the terminator set: the D8 pass may have typed
        // the shared trap on a previous pipeline pass, and a typed trap
        // inlines exactly like a bare one.
        let terminator_ok = matches!(
            items[n - 1],
            Region::Unreachable | Region::Panic { .. } | Region::Return { .. }
        );
        let scope_and_basic = match (&items[n - 3], &items[n - 2]) {
            (Region::Scope { out, .. }, Region::Basic(b)) if out == b => Some(*out),
            _ => None,
        };
        match (terminator_ok, scope_and_basic) {
            (true, Some(out)) => {
                let zero_bindings = func
                    .blocks
                    .get(out)
                    .is_some_and(|block| block.bindings.is_empty());
                let all_breaks_bare = {
                    let Region::Scope { body, .. } = &items[items.len() - 3] else {
                        unreachable!("matched above");
                    };
                    breaks_are_bare(body, out)
                };
                if !all_breaks_bare {
                    Fire::No
                } else if zero_bindings {
                    Fire::Inline
                } else if duplication_gates_hold(func, out) {
                    Fire::Duplicate
                } else {
                    // Intra-block references or over the cap: left
                    // labeled, the remaining-work signal.
                    stats.shared_with_bindings += 1;
                    Fire::No
                }
            }
            _ => Fire::No,
        }
    };
    if matches!(fire, Fire::No) {
        return seq(items);
    }

    let terminator = items.pop().expect("matched tail");
    let basic = items.pop().expect("matched basic");
    let scope = items.pop().expect("matched scope");
    let Region::Basic(_) = basic else {
        unreachable!("matched above");
    };
    let Region::Scope { out, body } = scope else {
        unreachable!("matched above");
    };
    // Pre-mint one replacement per break site (traversal order), then
    // splice them in: the scope dissolves either way.
    let sites = count_bare_breaks(&body, out);
    let mut replacements: VecDeque<Region> = match fire {
        Fire::Inline => {
            stats.inlined += sites as i64;
            (0..sites).map(|_| terminator.clone()).collect()
        }
        Fire::Duplicate => {
            stats.duplicated += sites as i64;
            // The first site reuses the original block — every
            // reachable block keeps exactly one `Basic` in the tree
            // (the corpus completeness lock) — and only the remaining
            // sites mint fresh-id clones.
            (0..sites)
                .map(|site| {
                    if site == 0 {
                        seq(vec![Region::Basic(out), terminator.clone()])
                    } else {
                        duplicate_trap_block(func, out, &terminator)
                    }
                })
                .collect()
        }
        Fire::No => unreachable!("early-returned above"),
    };
    items.push(substitute_breaks(*body, out, &mut replacements));
    debug_assert!(replacements.is_empty(), "one replacement per site");
    seq(items)
}

/// D2-ext gates: the block is small and *externally closed* — no
/// binding reads a value defined inside the block, so clones can keep
/// original operand ids (externals dominate every break site by SSA).
fn duplication_gates_hold(func: &HighFunction, block: BlockId) -> bool {
    let Some(blk) = func.blocks.get(block) else {
        return false;
    };
    if blk.bindings.is_empty() || blk.bindings.len() > MAX_DUPLICATED_BINDINGS {
        return false;
    }
    let internal: std::collections::HashSet<ValueId> = blk.bindings.iter().copied().collect();
    blk.bindings.iter().all(|&v| {
        let Some(binding) = func.bindings.get(v) else {
            return false;
        };
        let mut closed = true;
        binding.expr.for_each_value_use(|u| {
            if internal.contains(&u) {
                closed = false;
            }
        });
        closed
    })
}

/// Mint one fresh-id duplicate of the shared trap block: a new
/// `HighBlock` scheduling clones of the original bindings (identical
/// expressions — the closure gate guarantees no intra-block operand
/// needs rewriting), each stamped with duplication provenance, followed
/// by the terminator with any `Return` operands remapped onto the
/// clones.
fn duplicate_trap_block(func: &mut HighFunction, block: BlockId, terminator: &Region) -> Region {
    let template = func
        .blocks
        .get(block)
        .expect("gate resolved this block")
        .bindings
        .clone();
    let mut map: HashMap<ValueId, ValueId> = HashMap::new();
    let mut fresh_schedule = Vec::with_capacity(template.len());
    for old in template {
        let original = func.bindings.get(old).expect("gate resolved bindings");
        let mut clone = Binding::new(
            ValueId::from_index(func.bindings.len() as u32),
            original.ty.clone(),
            original.expr.clone(),
            original.latest_provenance().clone(),
        );
        clone.add_provenance(Provenance::new(
            PASS_NAME,
            ProvenanceSource::UpstreamRefinement,
            format!("duplicated from the shared trap block bb{}", block.index()),
        ));
        let fresh = clone.id;
        map.insert(old, fresh);
        fresh_schedule.push(fresh);
        func.bindings.push(clone);
    }
    let fresh_block = BlockId::from_index(func.blocks.len() as u32);
    func.blocks.push(HighBlock {
        id: fresh_block,
        bindings: fresh_schedule,
    });
    let terminator = match terminator {
        Region::Return { values } => Region::Return {
            values: values
                .iter()
                .map(|v| map.get(v).copied().unwrap_or(*v))
                .collect(),
        },
        other => other.clone(),
    };
    seq(vec![Region::Basic(fresh_block), terminator])
}

/// Count the bare `Break { target }` sites a substitution will rewrite.
fn count_bare_breaks(region: &Region, target: BlockId) -> usize {
    let mut count = 0;
    region.for_each_node(|node| {
        if let Region::Break { target: t, .. } = node
            && *t == target
        {
            count += 1;
        }
    });
    count
}

/// Every `Break { target }` inside `region` carries an empty transfer.
/// (Label enclosure guarantees all such breaks live inside the scope's
/// body, and out-labels are unique per function — no shadowing.)
fn breaks_are_bare(region: &Region, target: BlockId) -> bool {
    let mut bare = true;
    region.for_each_node(|node| {
        if let Region::Break {
            target: t,
            transfer,
        } = node
            && *t == target
            && !transfer.is_empty()
        {
            bare = false;
        }
    });
    bare
}

/// Replace every `Break { target }` with the next pre-minted
/// replacement, in the same pre-order [`Region::for_each_node`] walks
/// (which [`count_bare_breaks`] used to size the queue).
fn substitute_breaks(
    region: Region,
    target: BlockId,
    replacements: &mut VecDeque<Region>,
) -> Region {
    match region {
        Region::Break {
            target: t,
            transfer,
        } => {
            if t == target {
                debug_assert!(transfer.is_empty(), "gated by breaks_are_bare");
                replacements.pop_front().expect("one replacement per site")
            } else {
                Region::Break {
                    target: t,
                    transfer,
                }
            }
        }
        Region::Sequence(items) => seq(items
            .into_iter()
            .map(|item| substitute_breaks(item, target, replacements))
            .collect()),
        Region::Scope { out, body } => Region::Scope {
            out,
            body: Box::new(substitute_breaks(*body, target, replacements)),
        },
        Region::Loop { header, body, kind } => Region::Loop {
            header,
            body: Box::new(substitute_breaks(*body, target, replacements)),
            kind,
        },
        Region::If {
            cond,
            then_region,
            else_region,
        } => Region::If {
            cond,
            then_region: Box::new(substitute_breaks(*then_region, target, replacements)),
            else_region: else_region
                .map(|e| Box::new(substitute_breaks(*e, target, replacements))),
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
                    arm.body = substitute_breaks(arm.body, target, replacements);
                    arm
                })
                .collect(),
            default: Box::new(substitute_breaks(*default, target, replacements)),
            dispatch,
        },
        leaf @ (Region::Basic(_)
        | Region::Continue { .. }
        | Region::Transfer { .. }
        | Region::Return { .. }
        | Region::Unreachable
        | Region::Panic { .. }
        | Region::Unstructured { .. }) => leaf,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{Arena, BlockId, FuncId, Provenance, ProvenanceSource, UnknownReason,
        ValueId};
    use sordec_ir::{BinaryOp, Binding, Expr, HighBlock, IrType, Literal};

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
    fn cmp(id: u32) -> Binding {
        binding(
            id,
            Expr::Binary {
                op: BinaryOp::Ne,
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
                function_bodies: vec![],
                custom_sections: vec![],
            },
            soroban_facts: None,
            functions: vec![func],
            memory: sordec_ir::MemoryImage::empty(),
        };
        let result = TrapInlinePass.run(&mut ir);
        (ir.functions.pop().expect("one function"), result)
    }
    fn guard(cond: u32, then: Region) -> Region {
        Region::If {
            cond: v(cond),
            then_region: Box::new(then),
            else_region: None,
        }
    }
    fn brk(target: u32) -> Region {
        Region::Break {
            target: bb(target),
            transfer: vec![],
        }
    }

    /// Two flat guards (post-D1 shape) breaking to a shared bare trap.
    fn shared_trap() -> HighFunction {
        func(
            vec![
                binding(0, Expr::Literal(Literal::I64(5))),
                cmp(1),
                cmp(2),
            ],
            vec![
                block(0, vec![0, 1, 2]),
                block(1, vec![]),
                block(2, vec![]),
            ],
            Region::Sequence(vec![
                Region::Scope {
                    out: bb(2),
                    body: Box::new(Region::Sequence(vec![
                        Region::Basic(bb(0)),
                        guard(1, brk(2)),
                        Region::Basic(bb(1)),
                        guard(2, brk(2)),
                        Region::Return { values: vec![] },
                    ])),
                },
                Region::Basic(bb(2)),
                Region::Unreachable,
            ]),
        )
    }

    #[test]
    fn shared_bare_trap_inlines_into_every_guard() {
        let (f, result) = run_pass(shared_trap());
        assert!(result.changed);
        assert_eq!(result.metrics.get(M_INLINED), Some(2));
        assert_eq!(
            f.region,
            Region::Sequence(vec![
                Region::Basic(bb(0)),
                guard(1, Region::Unreachable),
                Region::Basic(bb(1)),
                guard(2, Region::Unreachable),
                Region::Return { values: vec![] },
            ])
        );
    }

    #[test]
    fn shared_return_trap_inlines_too() {
        // The shared terminator may be a Return of a dominating value —
        // SSA guarantees it dominates every break site.
        let mut f = shared_trap();
        if let Region::Sequence(items) = &mut f.region {
            *items.last_mut().expect("terminator") = Region::Return { values: vec![v(0)] };
        }
        let (f, result) = run_pass(f);
        assert_eq!(result.metrics.get(M_INLINED), Some(2));
        let Region::Sequence(items) = &f.region else {
            panic!("root stays a sequence");
        };
        assert_eq!(
            items[1],
            guard(1, Region::Return { values: vec![v(0)] })
        );
    }

    /// `shared_trap` with the out-block carrying one externally-closed
    /// binding (the corpus's panic-glue-call shape).
    fn shared_trap_with_binding() -> HighFunction {
        let mut f = shared_trap();
        f.blocks.get_mut(bb(2)).expect("bb2").bindings = vec![v(0)];
        // Keep IR valid: v0 must now be scheduled in bb2, not bb0.
        f.blocks.get_mut(bb(0)).expect("bb0").bindings = vec![v(1), v(2)];
        // …and the comparisons can't read v0 before it exists, so make
        // them self-contained literals.
        f.bindings.get_mut(v(1)).expect("v1").expr = Expr::Literal(Literal::I64(1));
        f.bindings.get_mut(v(2)).expect("v2").expr = Expr::Literal(Literal::I64(2));
        f
    }

    #[test]
    fn out_block_with_bindings_duplicates_under_fresh_ids() {
        // The D2-ext path: the first guard reuses the original block
        // (every reachable block keeps exactly one `Basic`), the
        // second gets a fresh-id clone; the shared scope dissolves.
        let (f, result) = run_pass(shared_trap_with_binding());
        assert!(result.changed);
        assert_eq!(result.metrics.get(M_DUPLICATED), Some(2));
        assert_eq!(result.metrics.get(M_SHARED_WITH_BINDINGS), None);

        // One fresh block (bb3) scheduling one fresh clone of v0
        // stamped with duplication provenance.
        assert_eq!(f.blocks.len(), 4);
        let clone_a = f.blocks.get(bb(3)).expect("minted duplicate").bindings[0];
        let cloned = f.bindings.get(clone_a).expect("fresh binding");
        assert!(matches!(cloned.expr, Expr::Literal(Literal::I64(5))));
        assert_eq!(cloned.latest_provenance().pass, PASS_NAME);
        assert_eq!(
            f.region,
            Region::Sequence(vec![
                Region::Basic(bb(0)),
                guard(
                    1,
                    Region::Sequence(vec![Region::Basic(bb(2)), Region::Unreachable]),
                ),
                Region::Basic(bb(1)),
                guard(
                    2,
                    Region::Sequence(vec![Region::Basic(bb(3)), Region::Unreachable]),
                ),
                Region::Return { values: vec![] },
            ])
        );
    }

    #[test]
    fn intra_block_references_stay_labeled_and_counted() {
        // `v0 = literal; v3 = use-of-v0` inside the trap block: the
        // closure gate refuses (a clone would need operand rewriting)
        // and the remaining-work metric records it.
        let mut f = shared_trap_with_binding();
        f.bindings.push(binding(
            3,
            Expr::Binary {
                op: BinaryOp::Ne,
                lhs: v(0),
                rhs: v(0),
            },
        ));
        f.blocks.get_mut(bb(2)).expect("bb2").bindings = vec![v(0), v(3)];
        let before = f.region.clone();
        let (f, result) = run_pass(f);
        assert!(!result.changed);
        assert_eq!(result.metrics.get(M_SHARED_WITH_BINDINGS), Some(1));
        assert_eq!(f.region, before);
    }

    #[test]
    fn value_carrying_breaks_disqualify_the_scope() {
        // A transfer into the out-block means it is a value merge, not
        // a trap — never inlined.
        let mut f = shared_trap();
        // Give bb2 a phi and route one break's value through it.
        f.bindings.push(binding(3, Expr::Phi { incoming: vec![] }));
        if let Region::Sequence(items) = &mut f.region
            && let Region::Scope { body, .. } = &mut items[0]
            && let Region::Sequence(body_items) = &mut **body
            && let Region::If { then_region, .. } = &mut body_items[1]
        {
            **then_region = Region::Break {
                target: bb(2),
                transfer: vec![(v(3), v(0))],
            };
        }
        let before = f.region.clone();
        let (f, result) = run_pass(f);
        assert!(!result.changed);
        assert_eq!(f.region, before);
    }

    #[test]
    fn second_run_reports_no_work() {
        let (f, first) = run_pass(shared_trap());
        assert!(first.changed);
        let (_, second) = run_pass(f);
        assert!(!second.changed, "idempotent after inlining");
    }
}
