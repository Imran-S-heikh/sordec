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
    Region, SemanticOp, StructDef, UnaryOp,
};

use super::metrics;
use super::option_probe::proven_tier;
use super::sret::emission_order;
use crate::dataflow::{block_containing, resolve_use};
use crate::effects::expr_effects;
use crate::metrics_catalog::MARSHALLING_OPTION_DEFAULTS_RECOVERED as M_DEFAULTS;
use crate::pass::{Pass, PassResult};
use crate::type_infer::known_of_type_ref;
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
        let structs: Vec<StructDef> =
            ir.soroban_facts.as_ref().map(|f| f.types.structs.clone()).unwrap_or_default();
        for func in &mut ir.functions {
            let planned = plans(func, &structs);
            for why in &planned.declines {
                result.metrics.increment(why.metric(), 1);
            }
            for plan in planned.plans {
                apply(func, &plan);
                result.metrics.increment(M_DEFAULTS, 1);
                result.changed = true;
            }
        }
        result
    }
}

/// Why a probe that looked like an `unwrap_or` was not folded.
///
/// The gate is specific and the reasons are not interchangeable: one of
/// these says the author wrote something this pass must not touch, another
/// says the shape is right and a *different* recogniser has not finished
/// yet. Counting them apart is the difference between "this contract has no
/// `unwrap_or`" and "it has three and we are one decode away".
///
/// Measured need: ten probes across the held-out set mark as SDK probes and
/// then fail to collapse, which leaves the output strictly worse than an
/// unmarked probe — a hole *and* the branch it guards. Diagnosing that twice
/// came to nothing because this pass could only say no.
#[derive(Debug, Clone, Copy)]
enum Decline {
    /// The branch tests the probe the other way round and has no `else`,
    /// so the read is on the fall-through rather than on an arm.
    ///
    /// The early-return sweep below owns this shape, and only when both
    /// sides leave by returning one value. Anything else falls between the
    /// two sweeps, which is why it is counted here: 5 of phoenix-vesting's
    /// 7 proven probes are this, and before this counter existed they were
    /// dropped without a word — the pass reported neither a fold nor a
    /// refusal for any of them.
    ReadOnFallThrough,
    /// The read's arm always traps, so the branch asserts rather than
    /// merges and there is no value for a default to stand in for.
    ///
    /// Measured on the held-out 25, all 10 are the else-less
    /// `if has(k) { panic!() }` — the "already initialized" guard — which
    /// the emitter already spells correctly. [`super::option_unwrap`]
    /// takes the opposite polarity, `if !has(k) { panic!() }`, so neither
    /// pass is missing work here. The counter exists so that is visible
    /// instead of being filed under control flow this pass could not
    /// carry.
    ArmAlwaysTraps,
    /// The read's arm carries control flow this pass cannot move onto a
    /// single expression — a nested branch, a loop, anything that is not a
    /// trap guard.
    SomeArmBranches,
    /// The `None` arm carries control flow, so there is no one value for
    /// `unwrap_or` to take.
    NoneArmBranches,
    /// An effectful binding on one of the arms besides the read itself.
    /// Folding would make that effect run on `None` too.
    ArmHasEffects,
    /// The probe decides something besides this branch.
    ProbeUsedElsewhere,
    /// No read of the probed entry on the arm, or more than one.
    NotOneRead,
    /// A merge this pass cannot address positionally — a phi with other than
    /// two incoming edges, or both edges from the same arm.
    MergeShape,
    /// The branch merges nothing, so there is no value to give a default.
    NothingMerged,
    /// A struct default with a hoisted check on the arm: the default names
    /// no single integer to evaluate the check against.
    StructWithChecks,
    /// No single default reproduces every constant the other arm merged.
    NoCommonDefault,
    /// A hoisted check on the read's arm would fire with the read standing
    /// for the default, so folding would trap where the original did not.
    CheckWouldFire,
}

impl Decline {
    fn metric(self) -> &'static str {
        match self {
            Self::ReadOnFallThrough => metrics::OPTION_DEFAULT_READ_ON_FALL_THROUGH,
            Self::ArmAlwaysTraps => metrics::OPTION_DEFAULT_ARM_ALWAYS_TRAPS,
            Self::SomeArmBranches => metrics::OPTION_DEFAULT_SOME_ARM_BRANCHES,
            Self::NoneArmBranches => metrics::OPTION_DEFAULT_NONE_ARM_BRANCHES,
            Self::ArmHasEffects => metrics::OPTION_DEFAULT_ARM_HAS_EFFECTS,
            Self::ProbeUsedElsewhere => metrics::OPTION_DEFAULT_PROBE_SHARED,
            Self::NotOneRead => metrics::OPTION_DEFAULT_NOT_ONE_READ,
            Self::MergeShape => metrics::OPTION_DEFAULT_MERGE_SHAPE,
            Self::NothingMerged => metrics::OPTION_DEFAULT_NOTHING_MERGED,
            Self::StructWithChecks => metrics::OPTION_DEFAULT_STRUCT_WITH_CHECKS,
            Self::NoCommonDefault => metrics::OPTION_DEFAULT_NO_COMMON_DEFAULT,
            Self::CheckWouldFire => metrics::OPTION_DEFAULT_CHECK_WOULD_FIRE,
        }
    }
}

/// One read to give a default.
struct Plan {
    probe: ValueId,
    get: ValueId,
    default: Default,
    ty: IrType,
}

/// The value the source's `unwrap_or` names.
enum Default {
    /// One integer — the read itself, or both of its limbs.
    Int(i128),
    /// A `#[contracttype]` struct, field by field: the merges name the
    /// fields of the read separately, so the default does too.
    Struct(Vec<(String, i128, KnownType)>),
}

/// How a merged value is computed from the read on its arm.
#[derive(Clone, PartialEq, Eq)]
enum Part {
    Whole,
    Lo,
    Hi,
    /// A field of the read, once the struct decode has named it.
    Field(String),
}

/// The folds for one function, and why each candidate that looked like this
/// pass's shape was refused.
struct Planned {
    plans: Vec<Plan>,
    declines: Vec<Decline>,
}

fn plans(func: &HighFunction, structs: &[StructDef]) -> Planned {
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
    let mut declines: Vec<Decline> = Vec::new();
    if probes.is_empty() {
        // Not a decline: no probe means no candidate, and counting
        // every function without one would swamp the census.
        return Planned { plans, declines };
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
                    // The read is whatever follows the branch, which this
                    // sweep does not model. Counted, not skipped.
                    None => {
                        declines.push(Decline::ReadOnFallThrough);
                        continue;
                    }
                }
            };
            match plan(func, &order, structs, *probe, *key, *tier, some_arm, none_arm, None) {
                Err(why) => declines.push(why),
                Ok(plan) => plans.push(plan),
            }
        }
    });
    // The same branch spelled as an early return: the `None` arm leaves the
    // function and the read is what follows, so the merge is the two
    // `return`s rather than a block parameter.
    func.region.for_each_node(|node| {
        let Region::Sequence(items) = node else {
            return;
        };
        for (i, item) in items.iter().enumerate() {
            let Region::If { cond, then_region, else_region: None } = item else {
                continue;
            };
            let (Some((taken, taken_rest)), Some((fallen, fallen_rest))) =
                (exit_return(then_region), exit_return(&Region::Sequence(items[i + 1..].to_vec())))
            else {
                continue;
            };
            for (probe, key, tier) in &probes {
                let Some(on_probe) = polarity(func, *cond, *probe, 0) else {
                    continue;
                };
                let (some, none, pair) = if on_probe {
                    (&taken_rest, &fallen_rest, (taken, fallen))
                } else {
                    (&fallen_rest, &taken_rest, (fallen, taken))
                };
                match plan(func, &order, structs, *probe, *key, *tier, some, Some(none), Some(pair)) {
                    Err(why) => declines.push(why),
                    Ok(plan) => plans.push(plan),
                }
            }
        }
    });
    Planned { plans, declines }
}

/// An arm that ends by returning one value: that value, and everything the
/// arm does before returning it.
fn exit_return(region: &Region) -> Option<(ValueId, Region)> {
    match region {
        Region::Return { values } if values.len() == 1 => Some((values[0], Region::Sequence(Vec::new()))),
        Region::Sequence(items) => match items.split_last() {
            Some((Region::Return { values }, rest)) if values.len() == 1 => {
                Some((values[0], Region::Sequence(rest.to_vec())))
            }
            _ => None,
        },
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn plan(
    func: &HighFunction,
    order: &[ValueId],
    structs: &[StructDef],
    probe: ValueId,
    key: ValueId,
    tier: KnownTier,
    some_arm: &Region,
    none_arm: Option<&Region>,
    returned: Option<(ValueId, ValueId)>,
) -> Result<Plan, Decline> {
    // **First**, because every gate below asks how to fold the arm and
    // this one asks whether the arm is a value at all. A trapping arm
    // asserts; it merges nothing. Reporting one as "the arm branches" is
    // what made 10 of the 14 held-out refusals read as control flow this
    // pass could not carry when not one of the 10 was a default in the
    // first place — the same misattribution the `sret` census had to
    // correct.
    if always_traps(some_arm) {
        return Err(Decline::ArmAlwaysTraps);
    }
    let mut checks = Vec::new();
    // Two gates, not one: an arm that branches and an arm that has an
    // effect need different work to unblock, and a single counter over
    // both says only "something". The first census ran them together and
    // reported 51 of 51 on the corpus, which named nothing.
    if !arm_fits(func, some_arm, &mut checks) {
        return Err(Decline::SomeArmBranches);
    }
    if none_arm.is_some_and(|n| !straight(n)) {
        return Err(Decline::NoneArmBranches);
    }
    // The probe decides this branch and nothing else.
    if uses(func, order, probe) != 1 {
        return Err(Decline::ProbeUsedElsewhere);
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
        let Some(binding) = func.bindings.get(id) else {
            continue;
        };
        let expr = &binding.expr;
        if in_some
            && let Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet { key: k, tier: t, missing: Missing::Option, .. })) = expr
            && super::option_probe::same_key(func, chase_value(func, *k), key)
            && proven_tier(t) == Some(tier)
        {
            if get.replace(id).is_some() {
                return Err(Decline::NotOneRead);
            }
            continue;
        }
        if !expr_effects(expr).is_pure_total() {
            return Err(Decline::ArmHasEffects);
        }
    }
    let Some(get) = get else {
        return Err(Decline::NotOneRead);
    };

    // Every merge fed from the read's arm, as (read's arm, other arm).
    let mut pairs = Vec::new();
    if let Some((some, none)) = returned {
        pairs.push((resolve_use(func, some), resolve_use(func, none)));
    }
    for &id in order.iter().chain(unscheduled(func).iter()) {
        let Some(Expr::Phi { incoming }) = func.bindings.get(id).map(|b| &b.expr) else {
            continue;
        };
        if !incoming.iter().any(|(b, _)| contains_block(some_arm, *b)) {
            continue;
        }
        let [(a_block, a), (b_block, b)] = incoming.as_slice() else {
            return Err(Decline::MergeShape);
        };
        let (some, none) = match (contains_block(some_arm, *a_block), contains_block(some_arm, *b_block)) {
            (true, false) => (*a, *b),
            (false, true) => (*b, *a),
            _ => return Err(Decline::MergeShape),
        };
        pairs.push((resolve_use(func, some), resolve_use(func, none)));
    }
    if pairs.is_empty() {
        return Err(Decline::NothingMerged);
    }
    let ty = func.bindings.get(get).ok_or(Decline::NotOneRead)?.ty.clone();
    if let Some(fields) = struct_default(func, &pairs, get, structs, &ty) {
        // A struct default names no single integer, so there is nothing to
        // evaluate a hoisted check against.
        if !checks.is_empty() {
            return Err(Decline::StructWithChecks);
        }
        return Ok(Plan { probe, get, default: Default::Struct(fields), ty });
    }
    let default = literal_default(func, &pairs, get)
        .or_else(|| zero_default(func, &pairs, get, some_arm))
        .ok_or(Decline::NoCommonDefault)?;
    // The default is spelled as a literal of the read's type; it has to fit
    // the literal the IR carries.
    i64::try_from(default).map_err(|_| Decline::NoCommonDefault)?;
    // Every check on the read's arm passes when the read is the default.
    for check in checks {
        if eval(func, check, get, default, 0).ok_or(Decline::CheckWouldFire)? != 0 {
            return Err(Decline::CheckWouldFire);
        }
    }
    Ok(Plan { probe, get, default: Default::Int(default), ty })
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
            // A field is the struct default's business, not this one's.
            Part::Field(_) => return None,
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
    let mut current = value;
    // A field arrives through the conversion its declared type asks for.
    for _ in 0..4 {
        if current == get {
            return Some(Part::Whole);
        }
        match &func.bindings.get(current)?.expr {
            Expr::Unary { op: UnaryOp::WideLo, value } if resolve_use(func, *value) == get => {
                return Some(Part::Lo)
            }
            Expr::Unary { op: UnaryOp::WideHi, value } if resolve_use(func, *value) == get => {
                return Some(Part::Hi)
            }
            Expr::Field { base, field } if resolve_use(func, *base) == get => {
                return Some(Part::Field(field.clone()))
            }
            Expr::Unary {
                op: UnaryOp::Wrap32 | UnaryOp::ExtendU32 | UnaryOp::ExtendS32,
                value,
            }
            | Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { value })) => {
                current = resolve_use(func, *value);
            }
            _ => return None,
        }
    }
    None
}

/// The default when the merges name the read's fields: a struct literal,
/// one constant per field.
///
/// Every field of the declared struct must be covered. A field the `Some`
/// arm never reads has no constant on the other arm either — rustc deleted
/// it with the read — and inventing one would be a guess about what the
/// source wrote.
fn struct_default(
    func: &HighFunction,
    pairs: &[(ValueId, ValueId)],
    get: ValueId,
    structs: &[StructDef],
    ty: &IrType,
) -> Option<Vec<(String, i128, KnownType)>> {
    let (IrType::Known(KnownType::UserDefined(id)) | IrType::Inferred(KnownType::UserDefined(id))) = ty
    else {
        return None;
    };
    let def = structs.iter().find(|s| s.id == *id)?;
    let mut by_field: Vec<(String, i128)> = Vec::new();
    for &(some, none) in pairs {
        let Part::Field(name) = part_of(func, some, get)? else {
            return None;
        };
        let constant = int_literal(func, none)?;
        match by_field.iter().find(|(f, _)| *f == name) {
            Some((_, prev)) if *prev != constant => return None,
            Some(_) => {}
            None => by_field.push((name, constant)),
        }
    }
    def.fields
        .iter()
        .map(|f| {
            let (_, constant) = by_field.iter().find(|(name, _)| *name == f.name)?;
            Some((f.name.clone(), *constant, known_of_type_ref(&f.ty)?))
        })
        .collect()
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
/// Whether an arm leaves the function by trapping on every path through
/// it, so it merges no value.
fn always_traps(region: &Region) -> bool {
    match region {
        Region::Panic { .. } | Region::Unreachable => true,
        // A sequence traps if any item does: nothing after it runs.
        Region::Sequence(items) => items.iter().any(always_traps),
        Region::If { then_region, else_region: Some(else_region), .. } => {
            always_traps(then_region) && always_traps(else_region)
        }
        _ => false,
    }
}

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
    let note =
        Provenance::new(PASS_NAME, ProvenanceSource::SdkPattern, "the default the source's `unwrap_or` names");
    let mut fresh = Vec::new();
    let mut push = |func: &mut HighFunction, ty: IrType, expr: Expr| {
        let id = ValueId::from_index(func.bindings.len() as u32);
        func.bindings.push(Binding::new(id, ty, expr, note.clone()));
        fresh.push(id);
        id
    };
    let default = match &plan.default {
        Default::Int(n) => {
            let expr = match plan.ty {
                IrType::Known(KnownType::Bool) | IrType::Inferred(KnownType::Bool) => {
                    Expr::Literal(Literal::Bool(*n != 0))
                }
                _ => Expr::Literal(Literal::I64(*n as i64)),
            };
            push(func, plan.ty.clone(), expr)
        }
        Default::Struct(fields) => {
            let values: Vec<(String, ValueId)> = fields
                .iter()
                .map(|(name, n, ty)| {
                    let expr = match ty {
                        KnownType::U32 => Expr::Literal(Literal::U32(*n as u32)),
                        KnownType::Bool => Expr::Literal(Literal::Bool(*n != 0)),
                        _ => Expr::Literal(Literal::I64(*n as i64)),
                    };
                    (name.clone(), push(func, IrType::Known(ty.clone()), expr))
                })
                .collect();
            push(func, plan.ty.clone(), Expr::Struct { fields: values })
        }
    };
    for (_, block) in func.blocks.iter_mut() {
        if let Some(pos) = block.bindings.iter().position(|v| *v == plan.get) {
            for (i, id) in fresh.iter().enumerate() {
                block.bindings.insert(pos + i, *id);
            }
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
    use sordec_ir::{HighBlock, PanicKind, StorageTier};

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

    /// The same read spelled as an early return:
    /// `if !has(k) { return false } … return get(k)`.
    fn exit_shape() -> HighFunction {
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
            Expr::Literal(Literal::I64(0)),                // v4 the default
            Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet {
                tier: tier(),
                durability: v(1),
                key: v(0),
                resolved_key: None,
                missing: Missing::Option,
            })), // v5
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
        blocks.push(HighBlock { id: bb(1), bindings: vec![v(4)] });
        blocks.push(HighBlock { id: bb(2), bindings: vec![v(5)] });
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
                    then_region: Box::new(Region::Sequence(vec![
                        Region::Basic(bb(1)),
                        Region::Return { values: vec![v(4)] },
                    ])),
                    else_region: None,
                },
                Region::Basic(bb(2)),
                Region::Return { values: vec![v(5)] },
            ]),
            params: vec![v(0)],
            returns: vec![],
        }
    }

    #[test]
    fn an_early_return_none_arm_becomes_the_reads_default() {
        let mut m = module(vec![exit_shape()]);
        assert!(OptionDefaultPass.run(&mut m).changed);
        let f = &m.functions[0];
        let Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet { missing: Missing::Or(d), .. })) =
            &f.bindings.get(v(5)).unwrap().expr
        else {
            panic!("the read takes a default");
        };
        assert!(matches!(f.bindings.get(*d).unwrap().expr, Expr::Literal(Literal::I64(0))));
        assert!(matches!(f.bindings.get(v(2)).unwrap().expr, Expr::Literal(Literal::Bool(true))));
    }

    #[test]
    fn the_pass_is_idempotent() {
        let mut m = module(vec![shape(0)]);
        assert!(OptionDefaultPass.run(&mut m).changed);
        assert!(!OptionDefaultPass.run(&mut m).changed);
    }

    /// The two sweeps overlap, and the census must not pretend otherwise:
    /// the first sweep sees an else-less branch, counts that the read is on
    /// the fall-through and moves on, and the second sweep folds it anyway.
    /// So a refusal here is a note about sweep one, never a verdict on the
    /// candidate — which is why it is counted beside a recovery rather than
    /// instead of one.
    #[test]
    fn a_fall_through_read_is_counted_without_blocking_the_fold() {
        let mut m = module(vec![exit_shape()]);
        let result = OptionDefaultPass.run(&mut m);
        assert!(result.changed, "sweep two still folds it");
        assert_eq!(
            result.metrics.get(metrics::OPTION_DEFAULT_READ_ON_FALL_THROUGH),
            Some(1),
            "and sweep one says it looked"
        );
        assert_eq!(
            result.metrics.get(M_DEFAULTS),
            Some(1),
            "both, not one or the other"
        );
    }

    /// An arm that leaves by trapping merges no value, so the branch
    /// asserts and is not this pass's. The census says so rather than
    /// filing it under control flow this pass could not carry.
    #[test]
    fn a_trapping_arm_is_not_this_passs_candidate() {
        let panic = || Region::Panic { kind: PanicKind::Bare };
        assert!(always_traps(&panic()), "a bare trap");
        assert!(
            always_traps(&Region::Sequence(vec![Region::Basic(bb(0)), panic()])),
            "nothing after a trap runs"
        );
        assert!(
            always_traps(&Region::If {
                cond: v(0),
                then_region: Box::new(panic()),
                else_region: Some(Box::new(panic())),
            }),
            "both arms trap"
        );
    }

    /// The half that matters: an arm that only *may* trap still merges a
    /// value on the other path, so the gate must not swallow it.
    #[test]
    fn an_arm_that_only_may_trap_still_merges() {
        let panic = Region::Panic { kind: PanicKind::Bare };
        assert!(!always_traps(&Region::Basic(bb(0))), "straight-line work");
        assert!(
            !always_traps(&Region::If {
                cond: v(0),
                then_region: Box::new(panic),
                else_region: Some(Box::new(Region::Basic(bb(1)))),
            }),
            "the else arm returns normally"
        );
        assert!(
            !always_traps(&Region::If {
                cond: v(0),
                then_region: Box::new(Region::Panic { kind: PanicKind::Bare }),
                else_region: None,
            }),
            "a hoisted trap check is exactly what `arm_fits` accepts"
        );
    }
}
