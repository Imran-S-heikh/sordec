//! `Option<T>` returned in two registers — the shape
//! [`super::optional_out`] takes through memory, handed back as a wasm
//! multi-value instead.
//!
//! # The shape
//!
//! A helper returning a one-word `Option` leaves with the discriminant and
//! the value side by side, and its caller picks between the value and a
//! fallback on the discriminant:
//!
//! ```text
//! fn func_0(k) {                            caller:
//!     if has(k) { return 1, get(k) }            r = func_0(k)
//!     return 0, <anything>                      n = select(r.1, 0, r.0 & 1)
//! }
//! ```
//!
//! That is `get(&k).unwrap_or(0)` with the `get` outlined — the SDK's
//! `Storage::get`, left a function of its own by a build that does not
//! inline it. The value on the absent path is whatever register was at
//! hand (the key pointer, a zero), and no caller reads it.
//!
//! # The rewrite
//!
//! The helper returns `Some(v)` or `None` where it returned `(tag, v)`.
//! A choice between the value and a fallback, made on the tag, becomes
//! `r.unwrap_or(fallback)`; a choice between the value's `Val` encoding
//! and the fallback's becomes the encoding of `r.unwrap_or(fallback)`,
//! which the return-encode collapse downstream then takes. An `if` on the
//! tag asks `r.is_some()`.
//!
//! # What makes a helper
//!
//! - Not exported (no spec signature).
//! - Every return hands back two values, the first a constant, and the
//!   returns carry exactly two different constants.
//!
//! # What makes a call site
//!
//! Every live read of the call is one of its two components. Every read
//! of the tag, followed through the arithmetic that tests it, ends as a
//! condition whose outcome the tag alone decides. Every read of the value,
//! directly or through a `Val` encode, is the arm of a `select` on such a
//! condition that the select takes when the tag says present — the other
//! arm reading nothing of the call. Which tag means present is what those
//! selects say, and every site must agree.
//!
//! A signature changes, so it is every call site or none, and nothing
//! when the module has an indirect call.

use std::collections::{HashMap, HashSet};

use sordec_common::{BlockId, FuncId, IrId, Provenance, ProvenanceSource, UnknownReason, ValueId};
use sordec_ir::{
    Binding, Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Literal, Region, SemanticOp, UnaryOp,
    WasmOpcodeKind,
};

use super::encode::encoded_constant;
use super::sret::emission_order;
use crate::dataflow::{block_containing, dead_residue, resolve_use, trace_int};
use crate::metrics_catalog::{
    MARSHALLING_OPTIONAL_PAIR_HELPERS as M_HELPERS, MARSHALLING_OPTIONAL_PAIR_REWRITTEN as M_REWRITTEN,
    MARSHALLING_OPTIONAL_PAIR_SITES as M_SITES, MARSHALLING_OPTIONAL_PAIR_SITES_REFUSED as M_SITES_REFUSED,
};
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-optional-pair";

/// How deep a tag test may be evaluated (`t & 1`, `== 0`, a rename, …).
const EVAL_DEPTH: usize = 6;

/// Rewrites helpers returning `(tag, value)` to return `Option<T>`.
#[derive(Debug, Default, Clone, Copy)]
pub struct OptionalPairPass;

impl Pass<HighIr> for OptionalPairPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let helpers: HashMap<FuncId, [i128; 2]> = ir
            .functions
            .iter()
            .filter_map(|f| match classify(f) {
                Ok(tags) => {
                    trace(f, "classified");
                    Some((f.id, tags))
                }
                Err(why) => {
                    if why != NOT_A_CANDIDATE {
                        trace(f, why);
                    }
                    None
                }
            })
            .collect();
        result.metrics.increment(M_HELPERS, helpers.len() as i64);
        if helpers.is_empty() {
            return result;
        }

        let mut plans: HashMap<FuncId, Vec<(usize, SitePlan)>> = HashMap::new();
        let mut refused: HashSet<FuncId> = HashSet::new();
        for (index, caller) in ir.functions.iter().enumerate() {
            let live = Live::build(caller);
            for &id in &emission_order(caller) {
                let Some(Expr::Call { target, .. }) = caller.bindings.get(id).map(|b| &b.expr) else {
                    continue;
                };
                let Some(tags) = helpers.get(target) else {
                    continue;
                };
                let planned = if *target == caller.id {
                    Err("the helper calls itself")
                } else {
                    site(caller, &live, id, *tags)
                };
                match planned {
                    Ok(plan) => {
                        trace(caller, &format!("site v{} -> func_{} ok", id.index(), target.index()));
                        result.metrics.increment(M_SITES, 1);
                        plans.entry(*target).or_default().push((index, plan));
                    }
                    Err(why) => {
                        trace(caller, &format!("site v{} -> func_{}: {why}", id.index(), target.index()));
                        result.metrics.increment(M_SITES_REFUSED, 1);
                        refused.insert(*target);
                    }
                }
            }
        }

        // The rewrite changes a signature, so it is every site or none. An
        // indirect call anywhere means callers this pass cannot see.
        let indirect = ir
            .functions
            .iter()
            .any(|f| f.bindings.iter().any(|(_, b)| matches!(b.expr, Expr::IndirectCall { .. })));
        if indirect {
            return result;
        }
        let mut targets: Vec<FuncId> = plans.keys().copied().filter(|t| !refused.contains(t)).collect();
        targets.sort_unstable();
        for target in targets {
            let sites = &plans[&target];
            // Which tag is `Some`: what the sites' choices say, all alike.
            let Some(present) = single(sites.iter().filter_map(|(_, p)| p.present)) else {
                trace_id(target, "the sites do not agree on which tag holds the value");
                continue;
            };
            let Some(at) = ir.functions.iter().position(|f| f.id == target) else {
                continue;
            };
            if rewrite_helper(&mut ir.functions[at], present).is_err() {
                continue;
            }
            for (index, plan) in sites {
                if let Some(caller) = ir.functions.get_mut(*index) {
                    rewrite_site(caller, plan, present);
                }
            }
            result.metrics.increment(M_REWRITTEN, 1);
            result.changed = true;
        }
        result
    }
}

/// Print a classification line when `SORDEC_OPTION_TRACE` is set — the
/// switch the other `Option` passes read.
#[allow(clippy::print_stderr)]
fn trace(func: &HighFunction, what: &str) {
    trace_id(func.id, what);
}

#[allow(clippy::print_stderr)]
fn trace_id(func: FuncId, what: &str) {
    if std::env::var_os("SORDEC_OPTION_TRACE").is_some() {
        eprintln!("optional-pair: func_{}: {what}", func.index());
    }
}

/// The one value an iterator yields, if it yields exactly one (repeats
/// allowed).
fn single(mut values: impl Iterator<Item = i128>) -> Option<i128> {
    let first = values.next()?;
    values.all(|v| v == first).then_some(first)
}

// ---------------------------------------------------------------------
// The helper
// ---------------------------------------------------------------------

/// Not a two-register return at all: an ordinary function, not worth a
/// line.
const NOT_A_CANDIDATE: &str = "no tagged pair returned";

/// The two tag constants, when `func` returns `(tag, value)` on every path.
fn classify(func: &HighFunction) -> Result<[i128; 2], &'static str> {
    if func.signature.is_some() {
        return Err(NOT_A_CANDIDATE);
    }
    let returns = returns(func);
    if returns.is_empty() || returns.iter().any(|(_, values)| values.len() != 2) {
        return Err(NOT_A_CANDIDATE);
    }
    let mut tags: Vec<i128> = Vec::new();
    for (_, values) in &returns {
        let tag = trace_int(func, values[0]).ok_or(NOT_A_CANDIDATE)?;
        if !tags.contains(&tag) {
            tags.push(tag);
        }
    }
    // One tag on every path is an infallible `Result`, which the
    // constant-return fold already names at its call sites.
    let [a, b] = tags.as_slice() else {
        return Err(NOT_A_CANDIDATE);
    };
    if returns.iter().any(|(block, _)| block.is_none()) {
        return Err("a return with no block of its own to build the `Option` in");
    }
    Ok([*a, *b])
}

/// Every `return` in the region tree, in pre-order, with the block that
/// runs straight before it on its path — where its `Option` is built.
fn returns(func: &HighFunction) -> Vec<(Option<BlockId>, Vec<ValueId>)> {
    fn go(region: &Region, last: &mut Option<BlockId>, out: &mut Vec<(Option<BlockId>, Vec<ValueId>)>) {
        match region {
            Region::Basic(b) => *last = Some(*b),
            Region::Sequence(items) => {
                for item in items {
                    go(item, last, out);
                }
            }
            Region::Scope { body, .. } | Region::Loop { body, .. } => {
                *last = None;
                go(body, last, out);
                *last = None;
            }
            Region::If { then_region, else_region, .. } => {
                *last = None;
                go(then_region, last, out);
                *last = None;
                if let Some(e) = else_region {
                    go(e, last, out);
                }
                *last = None;
            }
            Region::Switch { arms, default, .. } => {
                for arm in arms {
                    *last = None;
                    go(&arm.body, last, out);
                }
                *last = None;
                go(default, last, out);
                *last = None;
            }
            Region::Return { values } => out.push((*last, values.clone())),
            _ => {}
        }
    }
    let mut out = Vec::new();
    go(&func.region, &mut None, &mut out);
    out
}

/// Each `return (tag, v)` becomes `return Some(v)` or `return None`.
fn rewrite_helper(func: &mut HighFunction, present: i128) -> Result<(), ()> {
    let sites = returns(func);
    let mut built: Vec<ValueId> = Vec::with_capacity(sites.len());
    for (block, values) in &sites {
        let (Some(block), [tag, value]) = (block, values.as_slice()) else {
            return Err(());
        };
        let (payload, note) = if trace_int(func, *tag) == Some(present) {
            (Some(vec![*value]), "the value this path returned beside its tag, as `Some`")
        } else {
            (None, "this path's tag says it has no value: `None`")
        };
        let id = push(func, Expr::Optional { payload }, untyped(), note);
        func.blocks.get_mut(*block).ok_or(())?.bindings.push(id);
        built.push(id);
    }
    let mut next = built.into_iter();
    give_back(&mut func.region, &mut next);
    if fold_get(func) {
        trace(func, "the `Option` is the storage read it was built from");
    }
    func.returns = returns(func).into_iter().map(|(_, values)| values).collect();
    Ok(())
}

/// `if has(k) { ..; return Some(get(k)) } ..; return None` is `get(k)`
/// itself — the SDK's `Storage::get`, which the helper is. The read
/// becomes the `Option` and is returned; the probe and its branch go.
///
/// Only when nothing but pure bindings runs on the arm beside the read
/// (they now run whether or not the entry exists) and nothing but pure
/// bindings runs between the branch and `return None` (they are dropped).
fn fold_get(func: &mut HighFunction) -> bool {
    let Region::Sequence(items) = &func.region else {
        return false;
    };
    let [body @ .., Region::Return { values: none }] = items.as_slice() else {
        return false;
    };
    let Some(at) = body.iter().position(|r| matches!(r, Region::If { .. })) else {
        return false;
    };
    let (pre, post) = (&body[..at], &body[at + 1..]);
    let Region::If { cond, then_region, else_region: None } = &body[at] else {
        return false;
    };
    let basic_only = |rs: &[Region]| rs.iter().all(|r| matches!(r, Region::Basic(_)));
    let Region::Sequence(arm) = then_region.as_ref() else {
        return false;
    };
    let [arm_blocks @ .., Region::Return { values: some }] = arm.as_slice() else {
        return false;
    };
    if !basic_only(pre) || !basic_only(post) || !basic_only(arm_blocks) {
        return false;
    }
    let ([none], [some]) = (none.as_slice(), some.as_slice()) else {
        return false;
    };
    let expr = |v: ValueId| func.bindings.get(v).map(|b| &b.expr);
    if !matches!(expr(*none), Some(Expr::Optional { payload: None })) {
        return false;
    }
    let Some(Expr::Optional { payload: Some(payload) }) = expr(*some) else {
        return false;
    };
    let [value] = payload.as_slice() else {
        return false;
    };
    let read = resolve_use(func, *value);
    let probe = resolve_use(func, *cond);
    let (
        Some(Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet { tier, key, missing, .. }))),
        Some(Expr::Semantic(SemanticOp::Known(KnownOp::StorageHas { tier: has_tier, key: has_key, .. }))),
    ) = (expr(read), expr(probe))
    else {
        return false;
    };
    let same_tier = super::option_probe::proven_tier(tier).is_some()
        && super::option_probe::proven_tier(tier) == super::option_probe::proven_tier(has_tier);
    if !same_tier
        || !super::option_probe::same_key(func, *key, *has_key)
        || !matches!(missing, sordec_ir::Missing::Option | sordec_ir::Missing::Present(_))
    {
        return false;
    }
    // What runs on the arm now runs unconditionally, and what ran after the
    // branch is dropped: both must be free of effects.
    let block_ids = |rs: &[Region]| -> Vec<BlockId> {
        rs.iter()
            .filter_map(|r| if let Region::Basic(b) = r { Some(*b) } else { None })
            .collect()
    };
    let pure_except = |blocks: &[BlockId], allowed: &[ValueId]| {
        blocks.iter().all(|b| {
            func.blocks.get(*b).is_some_and(|block| {
                block.bindings.iter().all(|id| {
                    allowed.contains(id)
                        || func
                            .bindings
                            .get(*id)
                            .is_some_and(|b| crate::effects::expr_effects(&b.expr).is_pure_total())
                })
            })
        })
    };
    if !pure_except(&block_ids(arm_blocks), &[read]) || !pure_except(&block_ids(post), &[]) {
        return false;
    }

    let mut folded: Vec<Region> = pre.to_vec();
    folded.extend(arm_blocks.iter().cloned());
    folded.push(Region::Return { values: vec![read] });
    let (some, none) = (*some, *none);
    let original = std::mem::replace(&mut func.region, Region::Sequence(folded));
    // The probe goes with its branch; anything else still reading it keeps
    // both.
    let live = Live::build(func);
    if !live.users(probe).is_empty() || live.region_uses(probe) > 0 {
        func.region = original;
        return false;
    }
    if let Some(binding) = func.bindings.get_mut(read) {
        if let Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet { missing, .. })) = &mut binding.expr {
            *missing = sordec_ir::Missing::Option;
        }
        binding.ty = match &binding.ty {
            IrType::Unknown(_) => untyped(),
            payload => IrType::Inferred(KnownType::Option(Box::new(payload.clone()))),
        };
        binding.add_provenance(Provenance::new(
            PASS_NAME,
            ProvenanceSource::SdkPattern,
            "`get(&key)` itself: its `Some` and `None` arms were the SDK's own",
        ));
    }
    rewrite(func, probe, Expr::Literal(Literal::Bool(true)), IrType::Known(KnownType::Bool), "the probe of a read returned as the `Option` it is");
    for id in [some, none] {
        rewrite(func, id, Expr::Literal(Literal::Unit), IrType::Known(KnownType::Unit), "the `Option` the read already is");
    }
    true
}

/// Hand each `return`, in pre-order, its `Option`.
fn give_back(region: &mut Region, next: &mut impl Iterator<Item = ValueId>) {
    match region {
        Region::Return { values } => {
            if let Some(option) = next.next() {
                *values = vec![option];
            }
        }
        Region::Sequence(items) => items.iter_mut().for_each(|r| give_back(r, next)),
        Region::Scope { body, .. } | Region::Loop { body, .. } => give_back(body, next),
        Region::If { then_region, else_region, .. } => {
            give_back(then_region, next);
            if let Some(e) = else_region {
                give_back(e, next);
            }
        }
        Region::Switch { arms, default, .. } => {
            arms.iter_mut().for_each(|a| give_back(&mut a.body, next));
            give_back(default, next);
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------
// A call site
// ---------------------------------------------------------------------

/// Who reads what, counting only what the function still does: scheduled
/// bindings that are not dead residue, their operands, and the region.
struct Live {
    users: HashMap<ValueId, Vec<ValueId>>,
    region_uses: HashMap<ValueId, usize>,
    if_conds: HashMap<ValueId, usize>,
}

impl Live {
    fn build(func: &HighFunction) -> Self {
        let order = emission_order(func);
        let dead = dead_residue(func, &order);
        let mut live: HashSet<ValueId> = HashSet::new();
        let mut stack: Vec<ValueId> = order.iter().copied().filter(|id| !dead.contains(id)).collect();
        func.region.for_each_value_use(|u| stack.push(u));
        while let Some(id) = stack.pop() {
            if (id.index() as usize) >= func.bindings.len() || !live.insert(id) {
                continue;
            }
            if let Some(b) = func.bindings.get(id) {
                b.expr.for_each_value_use(|u| stack.push(u));
            }
        }
        let mut users: HashMap<ValueId, Vec<ValueId>> = HashMap::new();
        for &id in &live {
            if let Some(b) = func.bindings.get(id) {
                b.expr.for_each_value_use(|u| {
                    let list = users.entry(u).or_default();
                    if !list.contains(&id) {
                        list.push(id);
                    }
                });
            }
        }
        let mut region_uses: HashMap<ValueId, usize> = HashMap::new();
        func.region.for_each_value_use(|u| *region_uses.entry(u).or_default() += 1);
        let mut if_conds: HashMap<ValueId, usize> = HashMap::new();
        func.region.for_each_node(|node| {
            if let Region::If { cond, .. } = node {
                *if_conds.entry(*cond).or_default() += 1;
            }
        });
        Self { users, region_uses, if_conds }
    }

    fn users(&self, value: ValueId) -> &[ValueId] {
        self.users.get(&value).map_or(&[], Vec::as_slice)
    }

    fn region_uses(&self, value: ValueId) -> usize {
        self.region_uses.get(&value).copied().unwrap_or(0)
    }

    fn if_conds(&self, value: ValueId) -> usize {
        self.if_conds.get(&value).copied().unwrap_or(0)
    }
}

/// A choice between the value and a fallback, made on the tag.
struct Pick {
    select: ValueId,
    /// The fallback.
    default: Fallback,
    /// `Some(ty)` when the arms are the `Val` encodings of the value and
    /// the fallback, as `ty`.
    encode: Option<KnownType>,
}

enum Fallback {
    Value(ValueId),
    Literal(Literal, KnownType),
}

/// One call site, planned.
struct SitePlan {
    call: ValueId,
    /// The tag the site's choices take the value under, when it has any.
    present: Option<i128>,
    picks: Vec<Pick>,
    /// Conditions on the tag that an `if` reads: the value and whether it
    /// holds for `tags[0]`.
    tests: Vec<(ValueId, bool)>,
    tags: [i128; 2],
    /// Everything else derived from the call, read by nothing once the
    /// picks and tests are rewritten.
    retired: Vec<ValueId>,
}

/// The arms and condition of a `select`, recovered or not.
fn select_parts(func: &HighFunction, id: ValueId) -> Option<(ValueId, ValueId, ValueId)> {
    match &func.bindings.get(id)?.expr {
        Expr::Unknown { op_kind: WasmOpcodeKind::Select, args, .. } if args.len() == 3 => Some((args[0], args[1], args[2])),
        Expr::Select { cond, if_true, if_false } => Some((*if_true, *if_false, *cond)),
        _ => None,
    }
}

/// The payload a small `Val` encode wraps, and as which type.
fn encode_of(func: &HighFunction, id: ValueId) -> Option<(KnownType, ValueId)> {
    match &func.bindings.get(resolve_use(func, id))?.expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty, value })) => Some((ty.clone(), *value)),
        _ => None,
    }
}

fn site(func: &HighFunction, live: &Live, call: ValueId, tags: [i128; 2]) -> Result<SitePlan, &'static str> {
    if live.region_uses(call) > 0 {
        return Err("the call's result is read by control flow");
    }
    let mut tag_projs: Vec<ValueId> = Vec::new();
    let mut val_projs: Vec<ValueId> = Vec::new();
    for &user in live.users(call) {
        match func.bindings.get(user).map(|b| &b.expr) {
            Some(Expr::Project { index: 0, .. }) => tag_projs.push(user),
            Some(Expr::Project { index: 1, .. }) => val_projs.push(user),
            _ => return Err("the call's result is read other than by its two components"),
        }
    }
    let derived_from = |set: &[ValueId], v: ValueId| set.contains(&v) || set.contains(&resolve_use(func, v));

    // The tag, followed through the arithmetic that tests it.
    let test = |v: ValueId| -> Option<bool> {
        let a = eval(func, v, &tag_projs, tags[0], 0)? != 0;
        let b = eval(func, v, &tag_projs, tags[1], 0)? != 0;
        (a != b).then_some(a)
    };
    let mut tag_side: Vec<ValueId> = tag_projs.clone();
    let mut select_conds: Vec<ValueId> = Vec::new();
    let mut tests: Vec<(ValueId, bool)> = Vec::new();
    let mut i = 0;
    while let Some(&m) = tag_side.get(i) {
        i += 1;
        let conds = live.if_conds(m);
        if live.region_uses(m) != conds {
            return Err("the tag is read by control flow other than an `if`");
        }
        if conds > 0 {
            tests.push((m, test(m).ok_or("an `if` on the tag the tag does not decide")?));
        }
        for &user in live.users(m) {
            if tag_side.contains(&user) {
                continue;
            }
            if let Some((t, f, c)) = select_parts(func, user)
                && c == m
                && t != m
                && f != m
            {
                test(m).ok_or("a choice on the tag the tag does not decide")?;
                select_conds.push(user);
                continue;
            }
            let arithmetic = matches!(
                func.bindings.get(user).map(|b| &b.expr),
                Some(
                    Expr::Use(_)
                        | Expr::Unary { .. }
                        | Expr::Binary { .. }
                        | Expr::Unknown { op_kind: WasmOpcodeKind::Conversion, .. }
                )
            );
            if !arithmetic
                || eval(func, user, &tag_projs, tags[0], 0).is_none()
                || eval(func, user, &tag_projs, tags[1], 0).is_none()
            {
                return Err("the tag is read other than by a test");
            }
            tag_side.push(user);
        }
    }

    // The value, followed through renames and its `Val` encode.
    let mut val_side: Vec<ValueId> = val_projs.clone();
    let mut picks: Vec<Pick> = Vec::new();
    let mut present: Option<i128> = None;
    let mut i = 0;
    while let Some(&m) = val_side.get(i) {
        i += 1;
        if live.region_uses(m) > 0 {
            return Err("the value is read by control flow");
        }
        for &user in live.users(m) {
            if val_side.contains(&user) || picks.iter().any(|p| p.select == user) {
                continue;
            }
            match func.bindings.get(user).map(|b| &b.expr) {
                Some(Expr::Use(_)) => {
                    val_side.push(user);
                    continue;
                }
                Some(Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { .. }))) => {
                    val_side.push(user);
                    continue;
                }
                _ => {}
            }
            let Some((t, f, c)) = select_parts(func, user) else {
                return Err("the value is read other than by a choice on the tag");
            };
            if c == m || (t == m) == (f == m) {
                return Err("the value is a choice's condition, or both its arms");
            }
            if !derived_from(&tag_side, c) {
                return Err("a choice of the value not made on the tag");
            }
            let holds_for_first = test(c).ok_or("a choice on the tag the tag does not decide")?;
            let value_if_true = t == m;
            let (arm, other) = if value_if_true { (t, f) } else { (f, t) };
            if derived_from(&val_side, other) || derived_from(&tag_side, other) || other == call {
                return Err("both arms of the choice read the call");
            }
            // The value is taken when the test says present: under the tag
            // that makes the condition pick the value's arm.
            let takes = if holds_for_first == value_if_true { tags[0] } else { tags[1] };
            if present.replace(takes).is_some_and(|p| p != takes) {
                return Err("two choices disagree on which tag holds the value");
            }
            let pick = if val_projs.contains(&resolve_use(func, arm)) {
                Pick { select: user, default: Fallback::Value(other), encode: None }
            } else if let Some((ty, inner)) = encode_of(func, arm)
                && val_projs.contains(&resolve_use(func, inner))
            {
                let default = if let Some(lit) = encoded_constant(func, other, &ty) {
                    Fallback::Literal(lit, ty.clone())
                } else if let Some((other_ty, d)) = encode_of(func, other)
                    && other_ty == ty
                {
                    Fallback::Value(d)
                } else {
                    return Err("an encoded value chosen against a fallback of another encoding");
                };
                Pick { select: user, default, encode: Some(ty) }
            } else {
                return Err("a choice of something computed from the value");
            };
            picks.push(pick);
        }
    }
    if select_conds.iter().any(|s| !picks.iter().any(|p| p.select == *s)) {
        return Err("a choice on the tag between values that are not the call's");
    }

    let rewritten: HashSet<ValueId> = tests.iter().map(|(v, _)| *v).collect();
    let retired = tag_side
        .iter()
        .chain(&val_side)
        .copied()
        .filter(|v| !rewritten.contains(v))
        .collect();
    Ok(SitePlan { call, present, picks, tests, tags, retired })
}

/// `value` evaluated with every tag projection reading `tag`, when it is a
/// short enough chain of integer operators over them and constants.
fn eval(func: &HighFunction, value: ValueId, tag_projs: &[ValueId], tag: i128, depth: usize) -> Option<i128> {
    let value = resolve_use(func, value);
    if tag_projs.contains(&value) {
        return Some(tag);
    }
    if depth >= EVAL_DEPTH {
        return None;
    }
    let sub = |v: ValueId| eval(func, v, tag_projs, tag, depth + 1);
    match &func.bindings.get(value)?.expr {
        Expr::Literal(Literal::Bool(b)) => Some(i128::from(*b)),
        Expr::Literal(_) => trace_int(func, value),
        Expr::Unary { op: UnaryOp::Eqz | UnaryOp::Not, value } => Some(i128::from(sub(*value)? == 0)),
        Expr::Unary { op: UnaryOp::Wrap32 | UnaryOp::ExtendU32 | UnaryOp::ExtendS32, value } => sub(*value),
        Expr::Unknown { op_kind: WasmOpcodeKind::Conversion, args, .. } if args.len() == 1 => sub(args[0]),
        Expr::Binary { op, lhs, rhs } => {
            let (l, r) = (sub(*lhs)?, sub(*rhs)?);
            use sordec_ir::BinaryOp;
            Some(match op {
                BinaryOp::BitAnd => l & r,
                BinaryOp::BitOr => l | r,
                BinaryOp::BitXor => l ^ r,
                BinaryOp::Eq => i128::from(l == r),
                BinaryOp::Ne => i128::from(l != r),
                _ => return None,
            })
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------
// The rewrite
// ---------------------------------------------------------------------

fn untyped() -> IrType {
    IrType::Unknown(UnknownReason::InsufficientEvidence)
}

/// A new binding in `func`, unscheduled; the caller places it.
fn push(func: &mut HighFunction, expr: Expr, ty: IrType, note: &str) -> ValueId {
    let id = ValueId::from_index(func.bindings.len() as u32);
    func.bindings.push(Binding::new(
        id,
        ty,
        expr,
        Provenance::new(PASS_NAME, ProvenanceSource::SdkPattern, note.to_string()),
    ));
    id
}

/// Schedule `new` straight before `anchor`, in `anchor`'s block.
fn place_before(func: &mut HighFunction, anchor: ValueId, new: ValueId) {
    let Some(block) = block_containing(func, anchor).and_then(|b| func.blocks.get_mut(b)) else {
        return;
    };
    if let Some(at) = block.bindings.iter().position(|b| *b == anchor) {
        block.bindings.insert(at, new);
    }
}

/// Replace `id`'s expression and type.
fn rewrite(func: &mut HighFunction, id: ValueId, expr: Expr, ty: IrType, note: &str) {
    if let Some(binding) = func.bindings.get_mut(id) {
        binding.expr = expr;
        binding.ty = ty;
        binding.add_provenance(Provenance::new(PASS_NAME, ProvenanceSource::SdkPattern, note.to_string()));
    }
}

/// The call yields the `Option`; the choices on its tag ask it.
fn rewrite_site(func: &mut HighFunction, plan: &SitePlan, present: i128) {
    rewrite_ty(func, plan.call);
    let mut is_some: Option<ValueId> = None;
    for &(test, holds_for_first) in &plan.tests {
        let asks = *is_some.get_or_insert_with(|| {
            let id = push(func, Expr::IsSome { value: plan.call }, IrType::Known(KnownType::Bool), "whether the call returned a value");
            place_after_call(func, plan.call, id);
            id
        });
        // The test holds when the tag is `present`, or when it is not.
        let holds_when_present = holds_for_first == (plan.tags[0] == present);
        let (expr, note) = if holds_when_present {
            (Expr::Use(asks), "the tag, tested: whether the call returned a value")
        } else {
            (Expr::Unary { op: UnaryOp::Not, value: asks }, "the tag, tested: whether the call returned nothing")
        };
        rewrite(func, test, expr, IrType::Known(KnownType::Bool), note);
    }
    for pick in &plan.picks {
        let default = match &pick.default {
            Fallback::Value(v) => *v,
            Fallback::Literal(lit, ty) => {
                let id = push(func, Expr::Literal(lit.clone()), IrType::Known(ty.clone()), "the fallback, decoded from its `Val`");
                place_before(func, pick.select, id);
                id
            }
        };
        let unwrap_or = Expr::UnwrapOr { value: plan.call, default };
        match &pick.encode {
            None => rewrite(func, pick.select, unwrap_or, untyped(), "the value, or the fallback when the call returned none"),
            Some(ty) => {
                let id = push(func, unwrap_or, IrType::Inferred(ty.clone()), "the value, or the fallback when the call returned none");
                place_before(func, pick.select, id);
                rewrite(
                    func,
                    pick.select,
                    Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty: ty.clone(), value: id })),
                    IrType::Known(KnownType::Val),
                    "the choice between two encodings is the encoding of the choice",
                );
            }
        }
    }
    for &id in &plan.retired {
        rewrite(
            func,
            id,
            Expr::Literal(Literal::Unit),
            IrType::Known(KnownType::Unit),
            "a component of the returned pair, read now through the `Option`",
        );
    }
}

fn place_after_call(func: &mut HighFunction, call: ValueId, new: ValueId) {
    let Some(block) = block_containing(func, call).and_then(|b| func.blocks.get_mut(b)) else {
        return;
    };
    if let Some(at) = block.bindings.iter().position(|b| *b == call) {
        block.bindings.insert(at + 1, new);
    }
}

fn rewrite_ty(func: &mut HighFunction, id: ValueId) {
    if let Some(binding) = func.bindings.get_mut(id) {
        binding.ty = untyped();
        binding.add_provenance(Provenance::new(
            PASS_NAME,
            ProvenanceSource::SdkPattern,
            "the call yields the `Option` its two results encoded",
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{module, v};
    use sordec_common::Arena;
    use sordec_ir::{BinaryOp, HighBlock};

    fn bb(i: u32) -> BlockId {
        BlockId::from_index(i)
    }

    fn func(id: u32, exprs: Vec<Expr>, params: Vec<u32>, layout: Vec<Vec<u32>>, region: Region) -> HighFunction {
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        for expr in exprs {
            let vid = ValueId::from_index(bindings.len() as u32);
            bindings.push(Binding::new(
                vid,
                untyped(),
                expr,
                Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
            ));
        }
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        for (i, ids) in layout.into_iter().enumerate() {
            blocks.push(HighBlock { id: bb(i as u32), bindings: ids.into_iter().map(v).collect() });
        }
        HighFunction {
            id: FuncId::from_index(id),
            name: None,
            signature: None,
            aliases: Vec::new(),
            blocks,
            bindings,
            region,
            params: params.into_iter().map(v).collect(),
            returns: vec![],
        }
    }

    /// func_1: `if p { return 1, x } return 0, k` — the outlined `get`.
    fn helper() -> HighFunction {
        let exprs = vec![
            Expr::Phi { incoming: vec![] },   // v0 key
            Expr::Phi { incoming: vec![] },   // v1 present?
            Expr::Phi { incoming: vec![] },   // v2 the value
            Expr::Literal(Literal::I32(1)),   // v3
            Expr::Literal(Literal::I32(0)),   // v4
        ];
        func(
            1,
            exprs,
            vec![0, 1, 2],
            vec![vec![], vec![3], vec![4]],
            Region::Sequence(vec![
                Region::Basic(bb(0)),
                Region::If {
                    cond: v(1),
                    then_region: Box::new(Region::Sequence(vec![
                        Region::Basic(bb(1)),
                        Region::Return { values: vec![v(3), v(2)] },
                    ])),
                    else_region: None,
                },
                Region::Basic(bb(2)),
                Region::Return { values: vec![v(4), v(0)] },
            ]),
        )
    }

    fn select(t: u32, f: u32, c: u32) -> Expr {
        Expr::Unknown { op_kind: WasmOpcodeKind::Select, args: vec![v(t), v(f), v(c)], reason: UnknownReason::InsufficientEvidence }
    }

    /// func_0: `r = func_1(k, p, x); n = select(r.1, 0, r.0 & 1); return n`.
    /// `encoded` returns `select(enc(r.1), 4, ..)` instead.
    fn caller(encoded: bool) -> HighFunction {
        let mut exprs = vec![
            Expr::Phi { incoming: vec![] },                                                  // v0 k
            Expr::Call { target: FuncId::from_index(1), args: vec![v(0), v(0), v(0)] }, // v1
            Expr::Project { value: v(1), index: 0 },                                         // v2
            Expr::Project { value: v(1), index: 1 },                                         // v3
            Expr::Literal(Literal::I32(1)),                                                  // v4
            Expr::Binary { op: BinaryOp::BitAnd, lhs: v(2), rhs: v(4) },                    // v5
            Expr::Literal(Literal::I32(0)),                                                  // v6
        ];
        let ret = if encoded {
            exprs.push(Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty: KnownType::U32, value: v(3) }))); // v7
            exprs.push(Expr::Literal(Literal::I64(4))); // v8: U32Val(0)
            exprs.push(select(7, 8, 5)); // v9
            9
        } else {
            exprs.push(select(3, 6, 5)); // v7
            7
        };
        let scheduled: Vec<u32> = (1..=ret).collect();
        func(
            0,
            exprs,
            vec![0],
            vec![scheduled],
            Region::Sequence(vec![Region::Basic(bb(0)), Region::Return { values: vec![v(ret)] }]),
        )
    }

    #[test]
    fn a_pick_on_the_tag_is_unwrap_or() {
        let mut ir = module(vec![caller(false), helper()]);
        assert!(OptionalPairPass.run(&mut ir).changed);
        let (c, h) = (&ir.functions[0], &ir.functions[1]);
        assert!(
            matches!(c.bindings.get(v(7)).unwrap().expr, Expr::UnwrapOr { value, default } if value == v(1) && default == v(6))
        );
        assert!(matches!(c.bindings.get(v(5)).unwrap().expr, Expr::Literal(Literal::Unit)), "the tag test retires");
        let built: Vec<bool> = h
            .returns
            .iter()
            .map(|r| matches!(h.bindings.get(r[0]).unwrap().expr, Expr::Optional { payload: Some(_) }))
            .collect();
        assert_eq!(built, vec![true, false], "tag 1 is Some, tag 0 is None");
        assert!(h.returns.iter().all(|r| r.len() == 1));
    }

    #[test]
    fn an_encoded_pick_is_the_encoding_of_unwrap_or() {
        let mut ir = module(vec![caller(true), helper()]);
        assert!(OptionalPairPass.run(&mut ir).changed);
        let c = &ir.functions[0];
        let Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty: KnownType::U32, value })) =
            &c.bindings.get(v(9)).unwrap().expr
        else {
            panic!("the select is an encode");
        };
        let Expr::UnwrapOr { default, .. } = &c.bindings.get(*value).unwrap().expr else {
            panic!("of an unwrap_or");
        };
        assert!(matches!(c.bindings.get(*default).unwrap().expr, Expr::Literal(Literal::U32(0))));
    }

    #[test]
    fn a_value_read_without_a_test_refuses_the_helper() {
        let mut c = caller(false);
        // The value also flows into arithmetic nothing guards.
        c.bindings.push(Binding::new(
            v(8),
            untyped(),
            Expr::Binary { op: BinaryOp::Add, lhs: v(3), rhs: v(4) },
            Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
        ));
        c.blocks.get_mut(bb(0)).unwrap().bindings.push(v(8));
        c.region = Region::Sequence(vec![Region::Basic(bb(0)), Region::Return { values: vec![v(8)] }]);
        let mut ir = module(vec![c, helper()]);
        assert!(!OptionalPairPass.run(&mut ir).changed);
        assert!(returns(&ir.functions[1]).iter().all(|(_, r)| r.len() == 2), "the helper is untouched");
    }

    #[test]
    fn one_tag_on_every_path_is_not_a_candidate() {
        let mut h = helper();
        if let Some(b) = h.bindings.get_mut(v(4)) {
            b.expr = Expr::Literal(Literal::I32(1));
        }
        assert_eq!(classify(&h), Err(NOT_A_CANDIDATE));
    }
}
