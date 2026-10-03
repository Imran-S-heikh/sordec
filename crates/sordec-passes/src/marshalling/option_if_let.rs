//! Recover the `if let Some(v) = get(&k)` the source wrote around a
//! storage read.
//!
//! # The shape
//!
//! ```rust,ignore
//! if let Some(balance) = e.storage().persistent().get::<DataKey, i128>(&key) {
//!     e.storage().persistent().extend_ttl(&key, LOW, HIGH);
//!     balance
//! } else {
//!     0
//! }
//! ```
//!
//! reaches us as the SDK's probe, a branch on it, and the read on the arm
//! where the probe said present:
//!
//! ```text
//! h = has(k)                         ← proven SDK probe
//! if !h { m = 0 }
//! else  { g = get(k); extend_ttl(k); m = g }
//! ```
//!
//! [`super::option_default`] folds this when the arm is only the read: then
//! it is `get(k).unwrap_or(0)`. Here the arm does more — the TTL bump runs
//! only on `Some` — so there is no `unwrap_or` to fold to, and the branch
//! is the author's. Left alone it prints a hole for the probe and an
//! `Option` that the arm then does arithmetic on, which is a compile error
//! as well as a wrong reading.
//!
//! # The rewrite
//!
//! The read takes [`Missing::Present`], naming the probe, and the branch is
//! normalised so its condition *is* the probe with the present arm first.
//! Nothing moves and nothing is deleted: the emitter spells that branch as
//! the `if let`, binding the read's name in the pattern.
//!
//! # Why it is exact
//!
//! `get(&k)` is, in the SDK, `if has(k) { Some(get(k)) } else { None }`.
//! Spelling the branch as `if let Some(v) = get(&k)` performs the same
//! `has`, then — on the present arm only — the same `get`, before anything
//! else on that arm runs. So the gates are about the read being *first*:
//!
//! - it runs on entry to the present arm, before any branch there, and
//!   nothing before it on the arm has an effect;
//! - what it reads (the key) is available before the branch, so it can
//!   be spelled in the condition;
//! - nothing outside the arm reads it, since the pattern binds it only
//!   inside;
//! - the probe decides this branch and nothing else.

use std::collections::HashSet;

use sordec_common::{BlockId, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{
    Expr, HighFunction, HighIr, KnownOp, KnownTier, Missing, Region, SemanticOp, UnaryOp,
};

use super::option_probe::{proven_tier, same_key};
use super::sret::emission_order;
use crate::dataflow::{block_containing, resolve_use};
use crate::effects::expr_effects;
use crate::pass::{Pass, PassResult};
use crate::recognizers::wrappers::chase_value;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-option-if-let";

/// Branches recovered as `if let Some(..) = get(..)`.
const M_RECOVERED: &str = "marshalling_option_if_let_recovered";
/// The branch tests the probe the other way round and has no `else`: the
/// read is on the fall-through, which is a `let … else`, not an `if let`.
const M_FALL_THROUGH: &str = "marshalling_option_if_let_declined_fall_through";
/// Something besides the branch reads the probe.
const M_PROBE_USED: &str = "marshalling_option_if_let_declined_probe_used_elsewhere";
/// No read of the probed entry on the present arm, or more than one.
const M_NOT_ONE_READ: &str = "marshalling_option_if_let_declined_not_one_read";
/// The read is not the first thing the present arm does.
const M_NOT_FIRST: &str = "marshalling_option_if_let_declined_read_not_first";
/// The read's key is computed on the arm, so the condition cannot name it.
const M_KEY_ON_ARM: &str = "marshalling_option_if_let_declined_key_on_arm";
/// Something outside the present arm reads the value.
const M_READ_OUTSIDE: &str = "marshalling_option_if_let_declined_read_outside_arm";

/// Recovers a probe-guarded read whose arm does more than return it as
/// `if let Some(v) = get(&k)`.
#[derive(Debug, Default, Clone, Copy)]
pub struct OptionIfLetPass;

impl Pass<HighIr> for OptionIfLetPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            let (plans, declines) = plans(func);
            for why in declines {
                result.metrics.increment(why, 1);
            }
            for plan in plans {
                apply(func, &plan);
                result.metrics.increment(M_RECOVERED, 1);
                result.changed = true;
            }
        }
        result
    }
}

/// One branch to rewrite.
struct Plan {
    /// The branch's condition as found — its identity in the region tree.
    cond: ValueId,
    /// The probe the branch tests.
    probe: ValueId,
    /// The read on the present arm.
    get: ValueId,
    /// Whether the present arm is the `else`, so the arms swap when the
    /// condition becomes the probe itself.
    swap: bool,
}

fn plans(func: &HighFunction) -> (Vec<Plan>, Vec<&'static str>) {
    let order = emission_order(func);
    let probes: Vec<(ValueId, ValueId, KnownTier)> = order
        .iter()
        .filter_map(|&id| match &func.bindings.get(id)?.expr {
            Expr::Semantic(SemanticOp::Known(KnownOp::StorageHas { probe: true, key, tier, .. })) => {
                Some((id, chase_value(func, *key), proven_tier(tier)?))
            }
            _ => None,
        })
        .collect();
    let mut plans = Vec::new();
    let mut declines = Vec::new();
    if probes.is_empty() {
        return (plans, declines);
    }
    func.region.for_each_node(|node| {
        let Region::If { cond, then_region, else_region } = node else {
            return;
        };
        for &(probe, key, tier) in &probes {
            let Some(on_probe) = polarity(func, *cond, probe, 0) else {
                continue;
            };
            let arm = if on_probe {
                &**then_region
            } else {
                match else_region.as_deref() {
                    Some(e) => e,
                    None => {
                        declines.push(M_FALL_THROUGH);
                        continue;
                    }
                }
            };
            match plan(func, &order, *cond, key, tier, arm) {
                Ok(get) => plans.push(Plan { cond: *cond, probe, get, swap: !on_probe }),
                Err(why) => declines.push(why),
            }
        }
    });
    (plans, declines)
}

fn plan(
    func: &HighFunction,
    order: &[ValueId],
    cond: ValueId,
    key: ValueId,
    tier: KnownTier,
    arm: &Region,
) -> Result<ValueId, &'static str> {
    // The probe decides this branch and nothing else: every reader of it,
    // or of the renames and negations between it and the condition, is
    // on that chain.
    let chain = cond_chain(func, cond);
    for &id in order {
        if chain.contains(&id) {
            continue;
        }
        let Some(b) = func.bindings.get(id) else { continue };
        // A rename nothing reads is not a reader: an inlined wrapper leaves
        // its own copy of the probe behind.
        if matches!(b.expr, Expr::Use(_)) && unread(func, order, id) {
            continue;
        }
        let mut reads = false;
        b.expr.for_each_value_use(|u| reads |= chain.contains(&u));
        if reads {
            return Err(M_PROBE_USED);
        }
    }
    let mut region_reads = 0;
    func.region.for_each_value_use(|u| region_reads += usize::from(chain.contains(&u)));
    if region_reads != 1 {
        return Err(M_PROBE_USED);
    }

    // Exactly one read of the probed entry on the arm.
    let blocks = arm_blocks(arm);
    let mut get = None;
    for &id in order {
        let Some(block) = block_containing(func, id) else { continue };
        if !blocks.contains(&block) {
            continue;
        }
        if let Some(Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet {
            key: k,
            tier: t,
            missing: Missing::Option,
            ..
        }))) = func.bindings.get(id).map(|b| &b.expr)
            && same_key(func, chase_value(func, *k), key)
            && proven_tier(t) == Some(tier)
            && get.replace(id).is_some()
        {
            return Err(M_NOT_ONE_READ);
        }
    }
    let get = get.ok_or(M_NOT_ONE_READ)?;

    // First on the arm: on its entry path, with nothing effectful before it.
    let mut first = false;
    'entry: for block in entry_blocks(arm) {
        let Some(b) = func.blocks.get(block) else { break };
        for &id in &b.bindings {
            if id == get {
                first = true;
                break 'entry;
            }
            let pure = func.bindings.get(id).is_some_and(|b| expr_effects(&b.expr).is_pure_total());
            if !pure {
                break 'entry;
            }
        }
    }
    if !first {
        return Err(M_NOT_FIRST);
    }

    // What the read reads is there before the branch.
    let mut on_arm = false;
    if let Some(Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet { key, resolved_key, .. }))) =
        func.bindings.get(get).map(|b| &b.expr)
    {
        let mut operands = vec![*key];
        if let Some(k) = resolved_key {
            // A resolved key prints from its payload, not the raw key.
            operands = k.payload.clone();
        }
        on_arm = operands.iter().any(|&v| defined_on(func, v, &blocks));
    }
    if on_arm {
        return Err(M_KEY_ON_ARM);
    }

    // Nothing outside the arm reads the value.
    if read_outside(func, order, get, arm, &blocks) {
        return Err(M_READ_OUTSIDE);
    }
    Ok(get)
}

/// Whether nothing live reads `value`.
fn unread(func: &HighFunction, order: &[ValueId], value: ValueId) -> bool {
    let mut n = 0;
    for id in order {
        if let Some(b) = func.bindings.get(*id) {
            b.expr.for_each_value_use(|u| n += usize::from(u == value));
        }
    }
    func.region.for_each_value_use(|u| n += usize::from(u == value));
    n == 0
}

/// The condition, and every rename or negation between it and the probe.
fn cond_chain(func: &HighFunction, cond: ValueId) -> HashSet<ValueId> {
    let mut chain = HashSet::new();
    let mut current = cond;
    for _ in 0..8 {
        if !chain.insert(current) {
            break;
        }
        match func.bindings.get(current).map(|b| &b.expr) {
            Some(Expr::Use(next)) | Some(Expr::Unary { op: UnaryOp::Not | UnaryOp::Eqz, value: next }) => {
                current = *next;
            }
            _ => break,
        }
    }
    chain
}

/// Whether `cond` is true exactly when `probe` is (`Some(true)`) or exactly
/// when it is not (`Some(false)`).
fn polarity(func: &HighFunction, cond: ValueId, probe: ValueId, depth: u32) -> Option<bool> {
    let c = resolve_use(func, cond);
    if c == probe {
        return Some(true);
    }
    if depth >= 4 {
        return None;
    }
    match &func.bindings.get(c)?.expr {
        Expr::Unary { op: UnaryOp::Not | UnaryOp::Eqz, value } => {
            polarity(func, *value, probe, depth + 1).map(|p| !p)
        }
        _ => None,
    }
}

/// Every block the arm schedules.
fn arm_blocks(arm: &Region) -> HashSet<BlockId> {
    let mut out = HashSet::new();
    arm.for_each_node(|node| {
        if let Region::Basic(b) = node {
            out.insert(*b);
        }
    });
    out
}

/// The blocks that run on entry to the arm, in order, before anything in
/// it branches.
fn entry_blocks(arm: &Region) -> Vec<BlockId> {
    fn walk(region: &Region, out: &mut Vec<BlockId>) -> bool {
        match region {
            Region::Basic(b) => {
                out.push(*b);
                true
            }
            Region::Sequence(items) => items.iter().all(|item| walk(item, out)),
            // A scope's body starts running at once; what follows it may
            // be reached by a break from anywhere inside, so stop there.
            Region::Scope { body, .. } => {
                walk(body, out);
                false
            }
            _ => false,
        }
    }
    let mut out = Vec::new();
    walk(arm, &mut out);
    out
}

/// Whether `value` is computed on the arm: scheduled in one of its blocks,
/// or a merge one of its blocks feeds.
fn defined_on(func: &HighFunction, value: ValueId, blocks: &HashSet<BlockId>) -> bool {
    if let Some(block) = block_containing(func, value) {
        return blocks.contains(&block);
    }
    matches!(
        func.bindings.get(value).map(|b| &b.expr),
        Some(Expr::Phi { incoming }) if incoming.iter().any(|(b, _)| blocks.contains(b))
    )
}

/// Whether anything outside the arm reads `get`.
///
/// A merge reading it along an edge out of the arm is inside: the
/// transfer that assigns it is emitted on the arm.
fn read_outside(
    func: &HighFunction,
    order: &[ValueId],
    get: ValueId,
    arm: &Region,
    blocks: &HashSet<BlockId>,
) -> bool {
    let scheduled: HashSet<ValueId> = order.iter().copied().collect();
    for (id, b) in func.bindings.iter() {
        if let Expr::Phi { incoming } = &b.expr {
            if incoming.iter().any(|(from, v)| *v == get && !blocks.contains(from)) {
                return true;
            }
            continue;
        }
        // Residue a rewrite left unscheduled is never emitted, so it reads
        // nothing. Counting it declined `errors`' read over a rename the
        // typed-read fold had already orphaned.
        if !scheduled.contains(&id) {
            continue;
        }
        let mut reads = false;
        b.expr.for_each_value_use(|u| reads |= u == get);
        if !reads {
            continue;
        }
        if !block_containing(func, id).is_some_and(|blk| blocks.contains(&blk)) {
            return true;
        }
    }
    if func.returns.iter().any(|site| site.contains(&get)) {
        return true;
    }
    let mut total = 0;
    func.region.for_each_value_use(|u| total += usize::from(u == get));
    let mut within = 0;
    arm.for_each_value_use(|u| within += usize::from(u == get));
    total != within
}

fn apply(func: &mut HighFunction, plan: &Plan) {
    if let Some(b) = func.bindings.get_mut(plan.get) {
        if let Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet { missing, .. })) = &mut b.expr {
            *missing = Missing::Present(plan.probe);
        }
        b.add_provenance(Provenance::new(
            PASS_NAME,
            ProvenanceSource::SdkPattern,
            "`if let Some(..)`: the read on the arm where the SDK's has-probe said present",
        ));
    }
    normalise(&mut func.region, plan);
}

/// Point the planned branch's condition at the probe itself, present arm
/// first. The renames and negations that fed it are left unread, for the
/// sweeps to collect.
fn normalise(region: &mut Region, plan: &Plan) -> bool {
    match region {
        Region::If { cond, then_region, else_region } if *cond == plan.cond => {
            *cond = plan.probe;
            if plan.swap
                && let Some(present) = else_region.take()
            {
                let absent = std::mem::replace(then_region, present);
                *else_region = (!matches!(&*absent, Region::Sequence(items) if items.is_empty()))
                    .then_some(absent);
            }
            true
        }
        Region::Sequence(items) => items.iter_mut().any(|item| normalise(item, plan)),
        Region::Scope { body, .. } | Region::Loop { body, .. } => normalise(body, plan),
        Region::If { then_region, else_region, .. } => {
            normalise(then_region, plan) || else_region.as_deref_mut().is_some_and(|e| normalise(e, plan))
        }
        Region::Switch { arms, default, .. } => {
            arms.iter_mut().any(|arm| normalise(&mut arm.body, plan)) || normalise(default, plan)
        }
        Region::Basic(_)
        | Region::Break { .. }
        | Region::Continue { .. }
        | Region::Transfer { .. }
        | Region::Return { .. }
        | Region::Unreachable
        | Region::Panic { .. }
        | Region::Unstructured { .. } => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{module, v};
    use sordec_common::{Arena, FuncId, IrId, UnknownReason};
    use sordec_ir::{Binding, HighBlock, IrType, Literal, StorageTier};

    fn bb(i: u32) -> BlockId {
        BlockId::from_index(i)
    }

    /// `if !has(k) { m = 0 } else { g = get(k); bump(); m = g }`: the
    /// present arm does something besides hand the read back, so there is
    /// no `unwrap_or` to fold to. `key_on_arm` computes the read's key on
    /// the arm instead of before the branch.
    fn shape(key_on_arm: bool) -> HighFunction {
        let tier = || StorageTier::Known(KnownTier::Persistent);
        let exprs = vec![
            Expr::Phi { incoming: vec![] }, // v0 key
            Expr::Literal(Literal::I64(1)), // v1 durability
            Expr::Semantic(SemanticOp::Known(KnownOp::StorageHas {
                tier: tier(),
                durability: v(1),
                key: v(0),
                resolved_key: None,
                probe: true,
            })), // v2
            Expr::Unary { op: UnaryOp::Eqz, value: v(2) }, // v3
            Expr::Literal(Literal::I64(0)),                // v4
            Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet {
                tier: tier(),
                durability: v(1),
                key: if key_on_arm { v(8) } else { v(0) },
                resolved_key: None,
                missing: Missing::Option,
            })), // v5
            Expr::Call { target: FuncId::from_index(1), args: vec![] }, // v6 the bump
            Expr::Phi { incoming: vec![(bb(0), v(4)), (bb(1), v(5))] }, // v7
            Expr::Use(v(0)),                                           // v8 key, re-read
        ];
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        for expr in exprs {
            let id = ValueId::from_index(bindings.len() as u32);
            bindings.push(Binding::new(
                id,
                IrType::Unknown(UnknownReason::InsufficientEvidence),
                expr,
                Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
            ));
        }
        let arm = if key_on_arm { vec![v(8), v(5), v(6)] } else { vec![v(5), v(6)] };
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        blocks.push(HighBlock { id: bb(0), bindings: vec![v(2), v(3)] });
        blocks.push(HighBlock { id: bb(1), bindings: arm });
        HighFunction {
            id: FuncId::from_index(0),
            name: None,
            signature: None,
            aliases: Vec::new(),
            blocks,
            bindings,
            region: Region::Sequence(vec![
                Region::Basic(bb(0)),
                Region::If {
                    cond: v(3),
                    then_region: Box::new(Region::Transfer { target: bb(2), transfer: vec![(v(7), v(4))] }),
                    else_region: Some(Box::new(Region::Sequence(vec![
                        Region::Basic(bb(1)),
                        Region::Transfer { target: bb(2), transfer: vec![(v(7), v(5))] },
                    ]))),
                },
                Region::Return { values: vec![v(7)] },
            ]),
            params: vec![v(0)],
            returns: vec![],
        }
    }

    fn branch(func: &HighFunction) -> (ValueId, &Region, Option<&Region>) {
        let Region::Sequence(items) = &func.region else { panic!("a sequence") };
        let Region::If { cond, then_region, else_region } = &items[1] else { panic!("the branch") };
        (*cond, then_region, else_region.as_deref())
    }

    /// The whole point: the branch tests the probe, present arm first, and
    /// the read says which probe made it present.
    #[test]
    fn a_read_with_more_on_its_arm_becomes_an_if_let() {
        let mut ir = module(vec![shape(false)]);
        assert!(OptionIfLetPass.run(&mut ir).changed);
        let f = &ir.functions[0];
        let (cond, then_region, else_region) = branch(f);
        assert_eq!(cond, v(2), "the condition is the probe itself");
        assert!(matches!(then_region, Region::Sequence(_)), "present arm first");
        assert!(matches!(else_region, Some(Region::Transfer { .. })), "absent arm second");
        assert!(matches!(
            f.bindings.get(v(5)).map(|b| &b.expr),
            Some(Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet { missing: Missing::Present(p), .. }))) if *p == v(2)
        ));
    }

    /// A key computed on the arm cannot be named in the condition, which
    /// runs before the arm does.
    #[test]
    fn a_key_computed_on_the_arm_is_declined() {
        let mut ir = module(vec![shape(true)]);
        let result = OptionIfLetPass.run(&mut ir);
        assert!(!result.changed);
        assert_eq!(result.metrics.get(M_KEY_ON_ARM), Some(1));
    }

    /// The pattern binds the value only inside the arm; a reader after the
    /// branch would lose it.
    #[test]
    fn a_read_used_after_the_branch_is_declined() {
        let mut f = shape(false);
        if let Region::Sequence(items) = &mut f.region {
            items[2] = Region::Return { values: vec![v(5)] };
        }
        let mut ir = module(vec![f]);
        let result = OptionIfLetPass.run(&mut ir);
        assert!(!result.changed);
        assert_eq!(result.metrics.get(M_READ_OUTSIDE), Some(1));
    }

    /// Something with an effect ahead of the read on the arm would run
    /// after it once the read moves into the condition.
    #[test]
    fn an_effect_before_the_read_is_declined() {
        let mut f = shape(false);
        if let Some(block) = f.blocks.get_mut(bb(1)) {
            block.bindings = vec![v(6), v(5)];
        }
        let mut ir = module(vec![f]);
        let result = OptionIfLetPass.run(&mut ir);
        assert!(!result.changed);
        assert_eq!(result.metrics.get(M_NOT_FIRST), Some(1));
    }

    /// A second run finds nothing: the read is no longer `Option`.
    #[test]
    fn the_pass_is_idempotent() {
        let mut ir = module(vec![shape(false)]);
        assert!(OptionIfLetPass.run(&mut ir).changed);
        assert!(!OptionIfLetPass.run(&mut ir).changed);
    }
}
