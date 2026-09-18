//! Fold the SDK's `Option` branch around a storage read back into the
//! `.unwrap_or(default)` the source wrote.
//!
//! # The shape
//!
//! `e.storage().persistent().get(&DataKey::Shares(user)).unwrap_or(0)`
//! reaches us as the SDK's probe, a branch, and a merge:
//!
//! ```text
//! h = has(k)                        ← proven SDK probe
//! if !h {                           v = get(k).unwrap_or(0)
//!     lo = 0; hi = 0          →     lo = wide_lo(v)
//! } else {                          hi = wide_hi(v)
//!     g = get(k)
//!     lo = wide_lo(g); hi = wide_hi(g)
//! }
//! ```
//!
//! # The rewrite
//!
//! The read takes the default — [`Missing::Or`] — and the probe becomes the
//! constant `true`, so the constant-branch fold keeps the read's arm and
//! drops the other. Every value merged out of the branch then comes from
//! the read's arm alone.
//!
//! # Why it is exact
//!
//! On `Some` nothing changes. On `None` the new read yields the default,
//! and the read's arm computes each merged value from it; the gate is that
//! this gives exactly what the other arm merged. For every merge the read's
//! arm must contribute the read itself or one of its limbs, the other arm a
//! constant, and one default must reproduce all of those constants at
//! once. The read's arm may compute nothing else with an effect, since it
//! now runs on `None` too; the other arm may compute nothing at all.
//!
//! The read's arm may hold trap checks — the compiler hoists the overflow
//! check of `count += 1` into it, since on `None` the count is a constant
//! that cannot overflow. Each is evaluated with the read standing for the
//! default and must come out not taken: then on `None` the check runs and
//! passes, as the original's `None` arm never ran it at all.
//!
//! A branch whose `None` side traps is `.unwrap()`, and
//! [`super::option_unwrap`] and [`super::option_sret`] own it.

use sordec_common::{BlockId, IrId, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{
    Binding, Expr, HighFunction, HighIr, IrType, KnownOp, KnownTier, KnownType, Literal, Missing,
    Region, SemanticOp, UnaryOp,
};

use super::option_probe::proven_tier;
use super::sret::emission_order;
use crate::dataflow::{block_containing, resolve_use};
use crate::effects::expr_effects;
use crate::metrics_catalog::MARSHALLING_OPTION_DEFAULTS_RECOVERED as M_DEFAULTS;
use crate::pass::{Pass, PassResult};
use crate::recognizers::wrappers::chase_value;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-option-default";

/// Folds a probe-guarded read with a constant `None` arm into
/// `get(..).unwrap_or(default)`.
#[derive(Debug, Default, Clone, Copy)]
pub struct OptionDefaultPass;

impl Pass<HighIr> for OptionDefaultPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            for plan in plans(func) {
                apply(func, &plan);
                result.metrics.increment(M_DEFAULTS, 1);
                result.changed = true;
            }
        }
        result
    }
}

/// One read to give a default.
struct Plan {
    probe: ValueId,
    get: ValueId,
    default: i128,
    ty: IrType,
}

/// How a merged value is computed from the read on its arm.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Part {
    Whole,
    Lo,
    Hi,
}

fn plans(func: &HighFunction) -> Vec<Plan> {
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
    if probes.is_empty() {
        return plans;
    }
    func.region.for_each_node(|node| {
        let Region::If { cond, then_region, else_region } = node else {
            return;
        };
        for (probe, key, tier) in &probes {
            let Some(on_probe) = polarity(func, *cond, *probe, 0) else {
                continue;
            };
            let (some_arm, none_arm) = if on_probe {
                (&**then_region, else_region.as_deref())
            } else {
                match else_region.as_deref() {
                    Some(e) => (e, Some(&**then_region)),
                    None => continue,
                }
            };
            if let Some(plan) = plan(func, &order, *probe, *key, *tier, some_arm, none_arm) {
                plans.push(plan);
            }
        }
    });
    plans
}

#[allow(clippy::too_many_arguments)]
fn plan(
    func: &HighFunction,
    order: &[ValueId],
    probe: ValueId,
    key: ValueId,
    tier: KnownTier,
    some_arm: &Region,
    none_arm: Option<&Region>,
) -> Option<Plan> {
    let mut checks = Vec::new();
    if !arm_fits(func, some_arm, &mut checks) || none_arm.is_some_and(|n| !straight(n)) {
        return None;
    }
    // The probe decides this branch and nothing else.
    if uses(func, order, probe) != 1 {
        return None;
    }
    // Exactly one read of the probed entry, on the read's arm; nothing else
    // there with an effect, nothing at all with one on the other arm.
    let mut get = None;
    for &id in order {
        let Some(block) = block_containing(func, id) else {
            continue;
        };
        let in_some = contains_block(some_arm, block);
        let in_none = none_arm.is_some_and(|n| contains_block(n, block));
        if !in_some && !in_none {
            continue;
        }
        let expr = &func.bindings.get(id)?.expr;
        if in_some
            && let Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet { key: k, tier: t, missing: Missing::Option, .. })) = expr
            && chase_value(func, *k) == key
            && proven_tier(t) == Some(tier)
        {
            if get.replace(id).is_some() {
                return None;
            }
            continue;
        }
        if !expr_effects(expr).is_pure_total() {
            return None;
        }
    }
    let get = get?;

    // Every merge fed from the read's arm, as (read's arm, other arm).
    let mut pairs = Vec::new();
    for &id in order.iter().chain(unscheduled(func).iter()) {
        let Some(Expr::Phi { incoming }) = func.bindings.get(id).map(|b| &b.expr) else {
            continue;
        };
        if !incoming.iter().any(|(b, _)| contains_block(some_arm, *b)) {
            continue;
        }
        let [(a_block, a), (b_block, b)] = incoming.as_slice() else {
            return None;
        };
        let (some, none) = match (contains_block(some_arm, *a_block), contains_block(some_arm, *b_block)) {
            (true, false) => (*a, *b),
            (false, true) => (*b, *a),
            _ => return None,
        };
        pairs.push((resolve_use(func, some), resolve_use(func, none)));
    }
    if pairs.is_empty() {
        return None;
    }
    let default = literal_default(func, &pairs, get).or_else(|| zero_default(func, &pairs, get, some_arm))?;
    // The default is spelled as a literal of the read's type; it has to fit
    // the literal the IR carries.
    i64::try_from(default).ok()?;
    // Every check on the read's arm passes when the read is the default.
    for check in checks {
        if eval(func, check, get, default, 0)? != 0 {
            return None;
        }
    }
    let ty = func.bindings.get(get)?.ty.clone();
    Some(Plan { probe, get, default, ty })
}

/// The default the merges name when each is a part of the read against a
/// constant: the read itself, or both of its limbs.
fn literal_default(func: &HighFunction, pairs: &[(ValueId, ValueId)], get: ValueId) -> Option<i128> {
    let mut whole = None;
    let (mut lo, mut hi) = (None, None);
    for &(some, none) in pairs {
        let constant = int_literal(func, none)?;
        let slot = match part_of(func, some, get)? {
            Part::Whole => &mut whole,
            Part::Lo => &mut lo,
            Part::Hi => &mut hi,
        };
        if slot.replace(constant).is_some_and(|prev| prev != constant) {
            return None;
        }
    }
    match (whole, lo, hi) {
        (Some(w), None, None) => Some(w),
        (None, Some(l), Some(h)) => Some((h << 64) | i128::from(l as u64)),
        (Some(w), Some(l), Some(h)) if w == (h << 64) | i128::from(l as u64) => Some(w),
        _ => None,
    }
}

/// `0`, when the compiler folded the source's arithmetic into both arms:
/// `unwrap_or_default() + value` becomes `value` on the `None` arm and
/// `read + value` on the other. Each merge's read-arm expression, with the
/// read standing for `0`, must reduce to exactly what the other arm merges.
fn zero_default(func: &HighFunction, pairs: &[(ValueId, ValueId)], get: ValueId, some_arm: &Region) -> Option<i128> {
    for &(some, none) in pairs {
        let reduced = reduce(func, some, get, 0, some_arm, 0)?;
        let expected = match int_literal(func, none) {
            Some(c) => Sym::Const(c),
            None => Sym::Value(none),
        };
        if reduced != expected {
            return None;
        }
    }
    Some(0)
}

/// A value computed on the read's arm, with the read replaced by a default:
/// a constant, or a value from outside the arm.
#[derive(PartialEq, Eq)]
enum Sym {
    Const(i128),
    Value(ValueId),
}

/// Reduce `value` with the read `get` standing for `default`, by identities
/// only: `x + 0`, `x - 0`, `x | 0`, `x ^ 0`, and constant arithmetic whose
/// result does not depend on width. `None` for anything else.
fn reduce(func: &HighFunction, value: ValueId, get: ValueId, default: i128, arm: &Region, depth: u32) -> Option<Sym> {
    let value = resolve_use(func, value);
    if value == get {
        return Some(Sym::Const(default));
    }
    if depth > 8 {
        return None;
    }
    // A value from outside the arm is what it is on either path.
    let inside = block_containing(func, value).is_some_and(|b| contains_block(arm, b));
    if !inside && !matches!(func.bindings.get(value)?.expr, Expr::Literal(_)) {
        return Some(Sym::Value(value));
    }
    let next = |v: ValueId| reduce(func, v, get, default, arm, depth + 1);
    match &func.bindings.get(value)?.expr {
        Expr::Literal(_) => int_literal(func, value).map(Sym::Const),
        Expr::Binary { op, lhs, rhs } => {
            let (a, b) = (next(*lhs)?, next(*rhs)?);
            use sordec_ir::BinaryOp as B;
            match (op, a, b) {
                (B::Add | B::BitOr | B::BitXor, Sym::Const(0), x)
                | (B::Add | B::Sub | B::BitOr | B::BitXor, x, Sym::Const(0)) => Some(x),
                (B::Add, Sym::Const(x), Sym::Const(y)) if x >= 0 && y >= 0 => Some(Sym::Const(x + y)),
                _ => None,
            }
        }
        Expr::Unary { op: UnaryOp::Wrap32 | UnaryOp::ExtendU32, value } => match next(*value)? {
            Sym::Const(c) if (0..=i128::from(i32::MAX)).contains(&c) => Some(Sym::Const(c)),
            _ => None,
        },
        _ => None,
    }
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
        Expr::Unary { op: UnaryOp::Not | UnaryOp::Eqz, value } => polarity(func, *value, probe, depth + 1).map(|p| !p),
        _ => None,
    }
}

fn part_of(func: &HighFunction, value: ValueId, get: ValueId) -> Option<Part> {
    if value == get {
        return Some(Part::Whole);
    }
    match &func.bindings.get(value)?.expr {
        Expr::Unary { op: UnaryOp::WideLo, value } if resolve_use(func, *value) == get => Some(Part::Lo),
        Expr::Unary { op: UnaryOp::WideHi, value } if resolve_use(func, *value) == get => Some(Part::Hi),
        _ => None,
    }
}

fn int_literal(func: &HighFunction, value: ValueId) -> Option<i128> {
    match &func.bindings.get(value)?.expr {
        Expr::Literal(Literal::I32(n)) => Some(i128::from(*n)),
        Expr::Literal(Literal::I64(n)) => Some(i128::from(*n)),
        Expr::Literal(Literal::U32(n)) => Some(i128::from(*n)),
        Expr::Literal(Literal::U64(n)) => Some(i128::from(*n)),
        _ => None,
    }
}

/// The read's arm: blocks, sequences, renames, and else-less branches to a
/// bare trap, whose conditions are collected into `checks`.
fn arm_fits(func: &HighFunction, region: &Region, checks: &mut Vec<ValueId>) -> bool {
    match region {
        Region::Basic(_) | Region::Transfer { .. } => true,
        Region::Sequence(items) => items.iter().all(|i| arm_fits(func, i, checks)),
        Region::If { cond, then_region, else_region: None }
            if super::guard::is_trap(then_region, &super::guard::empty_blocks(func)) =>
        {
            checks.push(*cond);
            true
        }
        _ => false,
    }
}

/// The integer `value` computes when the read `get` yields `default`, for
/// the comparisons and bit operations a check is made of. Width is not
/// modelled, so only operations whose result does not depend on it are
/// evaluated: comparisons and bit operations on non-negative operands,
/// equality on any.
fn eval(func: &HighFunction, value: ValueId, get: ValueId, default: i128, depth: u32) -> Option<i128> {
    let value = resolve_use(func, value);
    if value == get {
        return Some(default);
    }
    if depth > 8 {
        return None;
    }
    let next = |v: ValueId| eval(func, v, get, default, depth + 1);
    match &func.bindings.get(value)?.expr {
        Expr::Literal(Literal::Bool(b)) => Some(i128::from(*b)),
        Expr::Literal(_) => int_literal(func, value),
        Expr::Unary { op: UnaryOp::Eqz | UnaryOp::Not, value } => next(*value).map(|n| i128::from(n == 0)),
        Expr::Binary { op, lhs, rhs } => {
            let (a, b) = (next(*lhs)?, next(*rhs)?);
            let non_negative = a >= 0 && b >= 0;
            Some(match op {
                sordec_ir::BinaryOp::Eq => i128::from(a == b),
                sordec_ir::BinaryOp::Ne => i128::from(a != b),
                sordec_ir::BinaryOp::Lt if non_negative => i128::from(a < b),
                sordec_ir::BinaryOp::Le if non_negative => i128::from(a <= b),
                sordec_ir::BinaryOp::Gt if non_negative => i128::from(a > b),
                sordec_ir::BinaryOp::Ge if non_negative => i128::from(a >= b),
                sordec_ir::BinaryOp::BitAnd if non_negative => a & b,
                sordec_ir::BinaryOp::BitOr if non_negative => a | b,
                _ => return None,
            })
        }
        _ => None,
    }
}

/// Blocks, sequences and renames only.
fn straight(region: &Region) -> bool {
    let mut ok = true;
    region.for_each_node(|node| {
        if !matches!(node, Region::Basic(_) | Region::Sequence(_) | Region::Transfer { .. }) {
            ok = false;
        }
    });
    ok
}

fn contains_block(region: &Region, target: BlockId) -> bool {
    let mut found = false;
    region.for_each_node(|node| {
        if matches!(node, Region::Basic(b) if *b == target) {
            found = true;
        }
    });
    found
}

/// Bindings no block schedules — block parameters, where the merges live.
fn unscheduled(func: &HighFunction) -> Vec<ValueId> {
    let scheduled: std::collections::HashSet<ValueId> =
        func.blocks.iter().flat_map(|(_, b)| b.bindings.iter().copied()).collect();
    func.bindings.iter().map(|(id, _)| id).filter(|id| !scheduled.contains(id)).collect()
}

/// How often `value` is read by a scheduled binding or the region tree.
fn uses(func: &HighFunction, order: &[ValueId], value: ValueId) -> usize {
    let mut n = 0;
    for id in order {
        if let Some(b) = func.bindings.get(*id) {
            b.expr.for_each_value_use(|u| n += usize::from(u == value));
        }
    }
    func.region.for_each_value_use(|u| n += usize::from(u == value));
    n
}

fn apply(func: &mut HighFunction, plan: &Plan) {
    let default = ValueId::from_index(func.bindings.len() as u32);
    func.bindings.push(Binding::new(
        default,
        plan.ty.clone(),
        Expr::Literal(Literal::I64(plan.default as i64)),
        Provenance::new(PASS_NAME, ProvenanceSource::SdkPattern, "the default the source's `unwrap_or` names"),
    ));
    for (_, block) in func.blocks.iter_mut() {
        if let Some(pos) = block.bindings.iter().position(|v| *v == plan.get) {
            block.bindings.insert(pos, default);
            break;
        }
    }
    if let Some(b) = func.bindings.get_mut(plan.get) {
        if let Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet { missing, .. })) = &mut b.expr {
            *missing = Missing::Or(default);
        }
        b.add_provenance(Provenance::new(
            PASS_NAME,
            ProvenanceSource::SdkPattern,
            "`.unwrap_or(..)`: the SDK's has-probe and its constant None arm, folded into the read",
        ));
    }
    if let Some(b) = func.bindings.get_mut(plan.probe) {
        b.expr = Expr::Literal(Literal::Bool(true));
        b.ty = IrType::Known(KnownType::Bool);
        b.add_provenance(Provenance::new(
            PASS_NAME,
            ProvenanceSource::SdkPattern,
            "SDK Option probe, regenerated by `get(..).unwrap_or(..)`: its branch keeps the read",
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{module, v};
    use sordec_common::{Arena, FuncId, IrId, UnknownReason};
    use sordec_ir::{HighBlock, StorageTier};

    fn bb(i: u32) -> BlockId {
        BlockId::from_index(i)
    }

    /// `if !has(k) { m = 0 } else { g = get(k); m = wide_lo(g) }` plus the
    /// high limb, merged into `m_lo`/`m_hi`. `none_hi` is the constant the
    /// `None` arm merges for the high limb.
    fn shape(none_hi: i64) -> HighFunction {
        let tier = || StorageTier::Known(KnownTier::Persistent);
        let exprs = vec![
            Expr::Phi { incoming: vec![] },  // v0 key
            Expr::Literal(Literal::I64(1)),  // v1 durability
            Expr::Semantic(SemanticOp::Known(KnownOp::StorageHas {
                tier: tier(),
                durability: v(1),
                key: v(0),
                resolved_key: None,
                probe: true,
            })), // v2
            Expr::Unary { op: UnaryOp::Eqz, value: v(2) }, // v3
            Expr::Literal(Literal::I64(0)),                // v4
            Expr::Literal(Literal::I64(none_hi)),          // v5
            Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet {
                tier: tier(),
                durability: v(1),
                key: v(0),
                resolved_key: None,
                missing: Missing::Option,
            })), // v6
            Expr::Unary { op: UnaryOp::WideLo, value: v(6) }, // v7
            Expr::Unary { op: UnaryOp::WideHi, value: v(6) }, // v8
            Expr::Phi { incoming: vec![(bb(0), v(4)), (bb(1), v(7))] }, // v9
            Expr::Phi { incoming: vec![(bb(0), v(5)), (bb(1), v(8))] }, // v10
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
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        blocks.push(HighBlock { id: bb(0), bindings: vec![v(2), v(3)] });
        blocks.push(HighBlock { id: bb(1), bindings: vec![v(6), v(7), v(8)] });
        HighFunction {
            id: FuncId::from_index(0),
            name: None,
            signature: None,
            blocks,
            bindings,
            region: Region::Sequence(vec![
                Region::Basic(bb(0)),
                Region::If {
                    cond: v(3),
                    then_region: Box::new(Region::Transfer { target: bb(2), transfer: vec![(v(9), v(4)), (v(10), v(5))] }),
                    else_region: Some(Box::new(Region::Sequence(vec![
                        Region::Basic(bb(1)),
                        Region::Transfer { target: bb(2), transfer: vec![(v(9), v(7)), (v(10), v(8))] },
                    ]))),
                },
                Region::Return { values: vec![v(9), v(10)] },
            ]),
            params: vec![v(0)],
            returns: vec![],
        }
    }

    #[test]
    fn a_constant_none_arm_becomes_the_reads_default() {
        let mut m = module(vec![shape(0)]);
        let r = OptionDefaultPass.run(&mut m);
        assert!(r.changed);
        let f = &m.functions[0];
        let Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet { missing: Missing::Or(d), .. })) =
            &f.bindings.get(v(6)).unwrap().expr
        else {
            panic!("the read takes a default");
        };
        assert!(matches!(f.bindings.get(*d).unwrap().expr, Expr::Literal(Literal::I64(0))));
        // The probe is now the constant that keeps the read's arm.
        assert!(matches!(f.bindings.get(v(2)).unwrap().expr, Expr::Literal(Literal::Bool(true))));
    }

    /// A `None` arm merging `(lo, hi) = (0, 7)` names the default `7 << 64`,
    /// which the literal the IR carries cannot hold: declined rather than
    /// truncated.
    #[test]
    fn a_default_the_literal_cannot_carry_is_declined() {
        let mut m = module(vec![shape(7)]);
        assert!(!OptionDefaultPass.run(&mut m).changed);
    }

    #[test]
    fn the_pass_is_idempotent() {
        let mut m = module(vec![shape(0)]);
        assert!(OptionDefaultPass.run(&mut m).changed);
        assert!(!OptionDefaultPass.run(&mut m).changed);
    }
}
