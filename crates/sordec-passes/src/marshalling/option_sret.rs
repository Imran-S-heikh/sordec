//! Collapse the SDK's `Option` out-parameter reads at their call sites.
//!
//! # The shape
//!
//! `e.storage().instance().get(&DataKey::ReserveA).unwrap()` returns an
//! `Option<i128>`, and an `Option` of anything wider than a register comes
//! back through memory. rustc outlines the read into a helper that writes
//! the `Option` into its caller's frame:
//!
//! ```text
//! fn func51(out) {                         fn func20() -> i128 {
//!     if has(k) {                              func51(fp);
//!         g = get(k)                           if load(fp+0) & 1 {
//!         store out+16 <- lo(g)                    return join(load(fp+16),
//!         store out+24 <- hi(g)                               load(fp+24))
//!         d = 1                                }
//!     } else { d = 0 }                         unwrap_failed()   // None
//!     store out+0 <- d                     }
//! }
//! ```
//!
//! The caller's branch is the source's `.unwrap()`. Neither function is
//! straight-line, so the wrapper inliner leaves both alone, and every
//! entrypoint that reads storage this way carries two branches the source
//! never wrote.
//!
//! # The rewrite
//!
//! At each call site, the call becomes the read itself and the stores the
//! helper would have made on its `Some` path:
//!
//! ```text
//! g = get(k).unwrap()
//! store fp+0  <- 1
//! store fp+16 <- lo(g)
//! store fp+24 <- hi(g)
//! ```
//!
//! Nothing else changes here. The frame forwarder then carries the stored
//! values to the loads, the constant-branch fold drops the now-constant
//! flag test, and the dead-store and frame elisions collect the frame.
//!
//! # Why it is exact
//!
//! On `Some`, the new code writes the same slots with the same values the
//! helper wrote. On `None`, the helper wrote the `None` flag and the
//! caller trapped on it; now the read traps — `.unwrap()` on `None` is the
//! same bare panic. That second half is the gate: the rewrite is made only
//! when **every** load of the flag slot in the caller feeds a branch whose
//! `None` side is nothing but a trap, and the first of them follows the
//! call with nothing in between that could observe the difference. A
//! caller that does something else with `None` (`unwrap_or`, `if let`)
//! keeps its helper.
//!
//! A decode guard inside the helper — `if !is_address(g) { panic }` — is
//! the SDK's `TryFromVal` on the payload. It is not copied: the read is
//! typed with the tag's type instead, and a typed `get` regenerates it.
//!
//! # What makes a helper
//!
//! Not exported. One proven `has` probe and one `get` on the same key at
//! the same proven tier. One branch on the probe; straight-line code
//! around it. Every store goes to one parameter at a constant offset: the
//! payload (the read, or a limb of it) on the `Some` arm, and after the
//! merge a flag that is one literal from the `Some` arm and a different
//! one from the other. Nothing else with an effect. The key is a
//! parameter, or a resolved `#[contracttype]` key whose payload is made of
//! parameters.

use std::collections::{HashMap, HashSet};

use sordec_common::{FuncId, IrId, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{
    BinaryOp, Binding, EnumKey, Expr, HighFunction, HighIr, IrType, KnownOp, KnownTier, KnownType,
    Literal, MemWidth, Region, SemanticOp, StorageTier, UnaryOp,
};

use super::option_probe::proven_tier;
use super::sret::emission_order;
use crate::dataflow::{block_containing, canon_addr, resolve_use, trace_int};
use crate::effects::expr_effects;
use crate::metrics_catalog::MARSHALLING_OPTION_HELPERS_COLLAPSED as M_COLLAPSED;
use crate::pass::{Pass, PassResult};
use crate::recognizers::wrappers::chase_value;
use crate::refine::pure_traps;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-option-sret";

/// How many operators may sit between the flag load and the branch on it
/// (`d & 1`, `(d & 1) != 0`, a rename).
const FLAG_CHAIN_DEPTH: usize = 4;

/// Collapses calls to `Option` out-parameter storage helpers.
#[derive(Debug, Default, Clone, Copy)]
pub struct OptionSretPass;

impl Pass<HighIr> for OptionSretPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let helpers: HashMap<FuncId, Helper> = ir
            .functions
            .iter()
            .filter_map(|f| classify(f).map(|h| (f.id, h)))
            .collect();
        if helpers.is_empty() {
            return result;
        }
        let traps = pure_traps(ir);
        let plans: Vec<(usize, Vec<Site>)> = ir
            .functions
            .iter()
            .enumerate()
            .filter_map(|(i, f)| {
                let sites = sites(f, &helpers, &traps);
                (!sites.is_empty()).then_some((i, sites))
            })
            .collect();
        for (index, sites) in plans {
            let Some(func) = ir.functions.get_mut(index) else {
                continue;
            };
            for site in sites {
                if let Some(helper) = helpers.get(&site.helper) {
                    rewrite(func, helper, &site);
                    result.metrics.increment(M_COLLAPSED, 1);
                    result.changed = true;
                }
            }
        }
        result
    }
}

// ---------------------------------------------------------------------
// The helper
// ---------------------------------------------------------------------

/// A helper proven to be an `Option` out-parameter storage read.
struct Helper {
    /// Which parameter is the out-pointer.
    out: usize,
    tier: KnownTier,
    key: KeySource,
    /// The resolved `#[contracttype]` key, its payload as parameter
    /// indices.
    resolved: Option<(String, String, Vec<usize>)>,
    /// The type the read carries at the call site.
    ty: IrType,
    /// Every slot the helper writes, in its own store order.
    slots: Vec<(u32, MemWidth, Slot)>,
}

/// Where the key comes from at a call site.
enum KeySource {
    /// The helper's parameter at this index.
    Param(usize),
    /// A resolved key whose converter was elided: the name is the key.
    Resolved,
    /// The helper builds the key by calling a constructor on its own
    /// parameters and constants — dex's shared `get_token_a`/`get_token_b`
    /// body, which only one caller's argument tells apart. The call is
    /// rebuilt at each site with that site's arguments, where the key
    /// recognizer can name it.
    Call { target: FuncId, args: Vec<Arg>, ty: IrType },
}

/// One argument of a rebuilt key constructor call.
enum Arg {
    Param(usize),
    Lit(Literal),
}

/// What one slot of the out-parameter holds.
#[derive(Clone)]
enum Slot {
    /// The `Option` discriminant.
    Flag { some: Literal, none: Literal },
    /// The value read, or one limb of it.
    Payload(Part),
    /// A constant written on every path.
    Const(Literal),
}

#[derive(Clone, Copy)]
enum Part {
    Whole,
    Lo,
    Hi,
}

fn classify(func: &HighFunction) -> Option<Helper> {
    if func.signature.is_some() {
        return None;
    }
    let order = emission_order(func);
    let (mut has, mut get) = (None, None);
    for &id in &order {
        let slot = match &func.bindings.get(id)?.expr {
            Expr::Semantic(SemanticOp::Known(KnownOp::StorageHas { probe: true, .. })) => &mut has,
            Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet { .. })) => &mut get,
            _ => continue,
        };
        if slot.replace(id).is_some() {
            return None;
        }
    }
    let (Some(has), Some(get)) = (has, get) else {
        return None;
    };
    trace(func, "has a probe and a read");
    let Expr::Semantic(SemanticOp::Known(KnownOp::StorageHas { key: has_key, tier: has_tier, .. })) =
        &func.bindings.get(has)?.expr
    else {
        return None;
    };
    let get_binding = func.bindings.get(get)?;
    let Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet {
        key: get_key,
        tier: get_tier,
        resolved_key,
        missing: sordec_ir::Missing::Option,
        ..
    })) = &get_binding.expr
    else {
        return None;
    };
    let tier = proven_tier(get_tier)?;
    if proven_tier(has_tier)? != tier || chase_value(func, *has_key) != chase_value(func, *get_key) {
        return decline(func, "probe and read disagree on key or tier");
    }

    // One branch on the probe, straight-line code around it, and at most
    // a bare `return` at the end.
    let items: &[Region] = match &func.region {
        Region::Sequence(items) => items,
        other => std::slice::from_ref(other),
    };
    let (at, some_arm, none_arm) = items.iter().enumerate().find_map(|(i, item)| {
        let Region::If { cond, then_region, else_region } = item else {
            return None;
        };
        let on_some = polarity(func, *cond, has, 0)?;
        let other = else_region.as_deref();
        Some(if on_some {
            (i, Some(&**then_region), other)
        } else {
            (i, other, Some(&**then_region))
        })
    })
    .or_else(|| decline(func, "no top-level branch on the probe"))?;
    let some_arm = some_arm?;
    for (i, item) in items.iter().enumerate() {
        let fits = match item {
            _ if i == at => true,
            Region::Return { values } => i + 1 == items.len() && values.is_empty(),
            other => straight(other),
        };
        if !fits {
            return decline(func, "code around the branch is not straight-line");
        }
    }
    if none_arm.is_some_and(|n| !straight(n)) {
        return decline(func, "None arm is not straight-line");
    }
    let mut decode = None;
    if !some_arm_fits(func, some_arm, get, &mut decode) {
        return decline(func, "Some arm has more than a decode guard");
    }

    // The key constructor call, if the key is built here: the one
    // binding with an effect the helper may have besides its stores.
    let key_value = chase_value(func, *get_key);
    let key_call = match &func.bindings.get(key_value)?.expr {
        Expr::Call { target, args } if *target != func.id => {
            let args = args
                .iter()
                .map(|a| {
                    let a = chase_value(func, *a);
                    match func.params.iter().position(|p| *p == a) {
                        Some(i) => Some(Arg::Param(i)),
                        None => literal(func, a).map(Arg::Lit),
                    }
                })
                .collect::<Option<Vec<_>>>()
                .or_else(|| decline(func, "key constructor takes more than parameters and constants"))?;
            Some((key_value, *target, args))
        }
        _ => None,
    };

    // The stores, and nothing else with an effect.
    let mut out: Option<usize> = None;
    let mut slots = Vec::new();
    let mut flags = 0;
    for &id in &order {
        if id == has || id == get || key_call.as_ref().is_some_and(|(k, _, _)| *k == id) {
            continue;
        }
        let binding = func.bindings.get(id)?;
        let Expr::Store { addr, value, offset, width } = &binding.expr else {
            if !expr_effects(&binding.expr).is_pure_total() {
                return decline(func, "a binding with an effect besides the stores");
            }
            continue;
        };
        let (base, off) = canon_addr(func, *addr);
        let param = func
            .params
            .iter()
            .position(|p| *p == base)
            .or_else(|| decline(func, "a store not through a parameter"))?;
        if *out.get_or_insert(param) != param {
            return None;
        }
        let at_off = off.checked_add(*offset)?;
        let block = block_containing(func, id)?;
        let value = resolve_use(func, *value);
        let slot = if contains_block(some_arm, block) {
            Slot::Payload(part_of(func, value, get).or_else(|| decline(func, "a Some-arm store that is not the read"))?)
        } else if none_arm.is_some_and(|n| contains_block(n, block)) {
            return decline(func, "a store on the None arm");
        } else if let Some(lit) = literal(func, value) {
            Slot::Const(lit)
        } else {
            flags += 1;
            flag_values(func, value, some_arm).or_else(|| decline(func, "a merged store that is not a flag"))?
        };
        slots.push((at_off, *width, slot));
    }
    let payloads = slots.iter().filter(|(_, _, s)| matches!(s, Slot::Payload(_))).count();
    if flags != 1 || payloads == 0 {
        return decline(func, "not exactly one flag and a payload");
    }

    let key = key_value;
    let key = if let Some(i) = func.params.iter().position(|p| *p == key) {
        KeySource::Param(i)
    } else if let Some((_, target, args)) = key_call {
        if args.iter().any(|a| matches!(a, Arg::Param(i) if Some(*i) == out)) {
            return decline(func, "key constructor reads the out-pointer");
        }
        KeySource::Call { target, args, ty: func.bindings.get(key)?.ty.clone() }
    } else if resolved_key.is_some()
        && matches!(func.bindings.get(key).map(|b| &b.expr), Some(Expr::Literal(Literal::Unit)))
    {
        KeySource::Resolved
    } else {
        return decline(func, "key is neither a parameter nor a resolved name");
    };
    let resolved = match resolved_key {
        Some(ek) => {
            let payload = ek
                .payload
                .iter()
                .map(|p| {
                    let p = chase_value(func, *p);
                    func.params.iter().position(|q| *q == p)
                })
                .collect::<Option<Vec<_>>>()?;
            Some((ek.enum_name.clone(), ek.variant.clone(), payload))
        }
        None => None,
    };
    let ty = match decode.and_then(crate::val_abi::tag_payload_type) {
        Some(t) => IrType::Known(t),
        None => get_binding.ty.clone(),
    };
    trace(func, "classified as an Option out-parameter helper");
    Some(Helper { out: out?, tier, key, resolved, ty, slots })
}

/// Print why a candidate was declined, when `SORDEC_OPTION_TRACE` is set.
#[allow(clippy::print_stderr)]
fn trace(func: &HighFunction, what: &str) {
    if std::env::var_os("SORDEC_OPTION_TRACE").is_some() {
        eprintln!("option-sret: func_{}: {what}", IrId::index(func.id));
    }
}

fn decline<T>(func: &HighFunction, why: &str) -> Option<T> {
    trace(func, why);
    None
}

/// Whether `cond` is true exactly when the probe `has` is (`Some(true)`)
/// or exactly when it is not (`Some(false)`).
fn polarity(func: &HighFunction, cond: ValueId, has: ValueId, depth: usize) -> Option<bool> {
    let c = resolve_use(func, cond);
    if c == has {
        return Some(true);
    }
    if depth >= FLAG_CHAIN_DEPTH {
        return None;
    }
    match &func.bindings.get(c)?.expr {
        Expr::Unary { op: UnaryOp::Not | UnaryOp::Eqz, value } => {
            polarity(func, *value, has, depth + 1).map(|p| !p)
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

/// The `Some` arm: straight-line, plus at most one decode guard on the
/// read — `if !has_tag(g, T) { panic }` — whose tag is recorded.
fn some_arm_fits(func: &HighFunction, region: &Region, get: ValueId, decode: &mut Option<u8>) -> bool {
    match region {
        Region::Basic(_) | Region::Transfer { .. } => true,
        Region::Sequence(items) => items.iter().all(|i| some_arm_fits(func, i, get, decode)),
        Region::If { cond, then_region, else_region: None } if bare_trap(func, then_region) => {
            match func.bindings.get(resolve_use(func, *cond)).map(|b| &b.expr) {
                Some(Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck { value, tag, negated: true })))
                    if resolve_use(func, *value) == get =>
                {
                    decode.replace(*tag).is_none()
                }
                _ => false,
            }
        }
        _ => false,
    }
}

/// A trap with nothing before it: `panic!()`, or empty blocks then one.
fn bare_trap(func: &HighFunction, region: &Region) -> bool {
    match region {
        Region::Panic { .. } | Region::Unreachable => true,
        Region::Sequence(items) => items.split_last().is_some_and(|(last, rest)| {
            bare_trap(func, last)
                && rest.iter().all(|item| match item {
                    Region::Basic(b) => func.blocks.get(*b).is_some_and(|block| block.bindings.is_empty()),
                    _ => false,
                })
        }),
        _ => false,
    }
}

/// The part of the read a payload store writes.
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

fn literal(func: &HighFunction, value: ValueId) -> Option<Literal> {
    match &func.bindings.get(value)?.expr {
        Expr::Literal(lit @ (Literal::I32(_) | Literal::I64(_) | Literal::U32(_) | Literal::U64(_))) => {
            Some(lit.clone())
        }
        _ => None,
    }
}

/// The discriminant: a merge of two different literals, one arriving
/// from the `Some` arm.
fn flag_values(func: &HighFunction, value: ValueId, some_arm: &Region) -> Option<Slot> {
    let Expr::Phi { incoming } = &func.bindings.get(value)?.expr else {
        return None;
    };
    let [(a_block, a), (b_block, b)] = incoming.as_slice() else {
        return None;
    };
    let (a_some, b_some) = (contains_block(some_arm, *a_block), contains_block(some_arm, *b_block));
    let (some, none) = match (a_some, b_some) {
        (true, false) => (*a, *b),
        (false, true) => (*b, *a),
        _ => return None,
    };
    let (some, none) = (literal(func, resolve_use(func, some))?, literal(func, resolve_use(func, none))?);
    (int(&some)? != int(&none)?).then_some(Slot::Flag { some, none })
}

fn int(lit: &Literal) -> Option<i128> {
    match lit {
        Literal::I32(n) => Some(i128::from(*n)),
        Literal::I64(n) => Some(i128::from(*n)),
        Literal::U32(n) => Some(i128::from(*n)),
        Literal::U64(n) => Some(i128::from(*n)),
        Literal::Bool(b) => Some(i128::from(*b)),
        _ => None,
    }
}

fn contains_block(region: &Region, target: sordec_common::BlockId) -> bool {
    let mut found = false;
    region.for_each_node(|node| {
        if matches!(node, Region::Basic(b) if *b == target) {
            found = true;
        }
    });
    found
}

// ---------------------------------------------------------------------
// The call sites
// ---------------------------------------------------------------------

struct Site {
    call: ValueId,
    helper: FuncId,
    args: Vec<ValueId>,
}

fn sites(func: &HighFunction, helpers: &HashMap<FuncId, Helper>, traps: &HashSet<FuncId>) -> Vec<Site> {
    let order = emission_order(func);
    let mut out = Vec::new();
    for &id in &order {
        let Some(Expr::Call { target, args }) = func.bindings.get(id).map(|b| &b.expr) else {
            continue;
        };
        if *target == func.id {
            continue;
        }
        let Some(helper) = helpers.get(target) else {
            continue;
        };
        if gate(func, &order, id, args, helper, helpers, traps) {
            out.push(Site { call: id, helper: *target, args: args.clone() });
        }
    }
    out
}

/// Whether the call at `call` may become the read: its result is unused,
/// the frame it writes does not escape, and every read of the flag it
/// writes traps on `None`.
fn gate(
    func: &HighFunction,
    order: &[ValueId],
    call: ValueId,
    args: &[ValueId],
    helper: &Helper,
    helpers: &HashMap<FuncId, Helper>,
    traps: &HashSet<FuncId>,
) -> bool {
    let Some(&ptr) = args.get(helper.out) else {
        return false;
    };
    if use_count(func, order, call) != 0 {
        trace(func, "call result is used");
        return false;
    }
    let (base, k) = canon_addr(func, ptr);
    if escapes(func, order, base, helpers) {
        trace(func, "frame escapes");
        return false;
    }
    let Some((flag_off, flag_width, some, none)) = helper.slots.iter().find_map(|(off, w, s)| match s {
        Slot::Flag { some, none } => Some((*off, *w, int(some)?, int(none)?)),
        _ => None,
    }) else {
        return false;
    };
    let Some(flag_at) = k.checked_add(flag_off) else {
        return false;
    };
    let flag_end = u64::from(flag_at) + u64::from(flag_width.bytes());

    // Every load touching the flag reads exactly it, and traps on `None`.
    let mut flag_loads = Vec::new();
    for &id in order {
        let Some(Expr::Load { addr, offset, width, .. }) = func.bindings.get(id).map(|b| &b.expr) else {
            continue;
        };
        let (b, o) = canon_addr(func, *addr);
        let Some(start) = o.checked_add(*offset) else {
            return false;
        };
        let end = u64::from(start) + u64::from(width.bytes());
        if b != base || end <= u64::from(flag_at) || u64::from(start) >= flag_end {
            continue;
        }
        if start != flag_at || !traps_on_none(func, order, id, some, none, traps) {
            trace(func, "a flag read does not trap on None");
            return false;
        }
        flag_loads.push(id);
    }

    // The first one follows the call in its block, with nothing between
    // that could see the trap move to the read.
    let Some(block) = block_containing(func, call).and_then(|b| func.blocks.get(b)) else {
        return false;
    };
    let Some(from) = block.bindings.iter().position(|v| *v == call) else {
        return false;
    };
    for &id in &block.bindings[from + 1..] {
        if flag_loads.contains(&id) {
            return true;
        }
        let Some(binding) = func.bindings.get(id) else {
            return false;
        };
        let quiet = match &binding.expr {
            Expr::Load { addr, .. } => canon_addr(func, *addr).0 == base,
            other => expr_effects(other).is_pure_total(),
        };
        if !quiet {
            trace(func, "something observable between the call and the flag read");
            return false;
        }
    }
    trace(func, "no flag read after the call in its block");
    false
}

/// How often `value` is read by a scheduled binding or the region tree.
fn use_count(func: &HighFunction, order: &[ValueId], value: ValueId) -> usize {
    binding_users(func, order, value).len() + region_uses(func, value)
}

fn binding_users(func: &HighFunction, order: &[ValueId], value: ValueId) -> Vec<ValueId> {
    order
        .iter()
        .copied()
        .filter(|id| {
            let mut reads = false;
            if let Some(b) = func.bindings.get(*id) {
                b.expr.for_each_value_use(|u| reads |= u == value);
            }
            reads
        })
        .collect()
}

fn region_uses(func: &HighFunction, value: ValueId) -> usize {
    let mut n = 0;
    func.region.for_each_value_use(|u| n += usize::from(u == value));
    n
}

/// Whether the frame at `base` is reachable from anything but loads and
/// stores through it, the shadow-stack bracket, and the out-pointer
/// argument of an `Option` helper.
fn escapes(func: &HighFunction, order: &[ValueId], base: ValueId, helpers: &HashMap<FuncId, Helper>) -> bool {
    let mut derived: HashSet<ValueId> = HashSet::from([base]);
    for &id in order {
        if let Some(Expr::Binary { op: BinaryOp::Add, lhs, rhs }) = func.bindings.get(id).map(|b| &b.expr)
            && derived.contains(&resolve_use(func, *lhs))
            && trace_int(func, *rhs).is_some()
        {
            derived.insert(id);
        }
    }
    let is_derived = |v: ValueId| derived.contains(&resolve_use(func, v));
    for &id in order {
        let Some(binding) = func.bindings.get(id) else {
            return true;
        };
        let fine = match &binding.expr {
            Expr::Store { value, .. } => !is_derived(*value),
            Expr::Load { .. } | Expr::Unknown { op_kind: sordec_ir::WasmOpcodeKind::GlobalSet, .. } => true,
            Expr::Binary { op: BinaryOp::Add, .. } if derived.contains(&id) => true,
            Expr::Call { target, args } => match helpers.get(target) {
                Some(h) => args.iter().enumerate().all(|(i, a)| i == h.out || !is_derived(*a)),
                None => !args.iter().any(|a| is_derived(*a)),
            },
            other => {
                let mut reads = false;
                other.for_each_value_use(|u| reads |= is_derived(u));
                !reads
            }
        };
        if !fine {
            return true;
        }
    }
    let mut region_reads = false;
    func.region.for_each_value_use(|u| region_reads |= is_derived(u));
    region_reads
}

/// Whether the flag loaded at `load` is only ever tested by a branch whose
/// `None` side is a bare trap. The test may pass through a short chain of
/// operators; each is evaluated on both flag values, and the branch must
/// tell them apart.
fn traps_on_none(
    func: &HighFunction,
    order: &[ValueId],
    load: ValueId,
    some: i128,
    none: i128,
    traps: &HashSet<FuncId>,
) -> bool {
    let (mut value, mut on_some, mut on_none) = (load, some, none);
    for _ in 0..=FLAG_CHAIN_DEPTH {
        let users = binding_users(func, order, value);
        match (users.as_slice(), region_uses(func, value)) {
            ([user], 0) => {
                let Some((s, n)) = step(func, *user, value, on_some, on_none) else {
                    return false;
                };
                (value, on_some, on_none) = (*user, s, n);
            }
            ([], 1) => {
                let (t_some, t_none) = (on_some != 0, on_none != 0);
                return t_some != t_none
                    && guard_traps(func, &func.region, value, t_none, &[], traps) == Some(true);
            }
            _ => return false,
        }
    }
    false
}

/// Evaluate `user`, which reads `value`, on both flag values.
fn step(func: &HighFunction, user: ValueId, value: ValueId, some: i128, none: i128) -> Option<(i128, i128)> {
    let other = |lhs: ValueId, rhs: ValueId| -> Option<i128> {
        match (resolve_use(func, lhs) == value, resolve_use(func, rhs) == value) {
            (true, false) => trace_int(func, rhs),
            (false, true) => trace_int(func, lhs),
            _ => None,
        }
    };
    match &func.bindings.get(user)?.expr {
        Expr::Use(_) => Some((some, none)),
        Expr::Unary { op: UnaryOp::Eqz | UnaryOp::Not, .. } => {
            Some((i128::from(some == 0), i128::from(none == 0)))
        }
        // A width conversion of a small non-negative flag keeps it.
        Expr::Unknown { op_kind: sordec_ir::WasmOpcodeKind::Conversion, args, .. }
            if args.len() == 1 && (0..=i128::from(i32::MAX)).contains(&some) && (0..=i128::from(i32::MAX)).contains(&none) =>
        {
            Some((some, none))
        }
        Expr::Binary { op, lhs, rhs } => {
            let c = other(*lhs, *rhs)?;
            match op {
                BinaryOp::BitAnd if c >= 0 && some >= 0 && none >= 0 => Some((some & c, none & c)),
                BinaryOp::Ne => Some((i128::from(some != c), i128::from(none != c))),
                BinaryOp::Eq => Some((i128::from(some == c), i128::from(none == c))),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Find the branch on `cond` and report whether its `None` side is a
/// bare trap. `none_takes_then` says which arm `None` selects; `rest` is
/// what follows the branch in its enclosing sequence, which is where an
/// else-less `None` side falls through to.
fn guard_traps(
    func: &HighFunction,
    region: &Region,
    cond: ValueId,
    none_takes_then: bool,
    rest: &[Region],
    traps: &HashSet<FuncId>,
) -> Option<bool> {
    match region {
        Region::If { cond: c, then_region, else_region } if *c == cond => Some(if none_takes_then {
            none_path_traps(func, then_region, traps)
        } else {
            match else_region {
                Some(e) => none_path_traps(func, e, traps),
                None => leaves(then_region) && none_path_traps(func, &Region::Sequence(rest.to_vec()), traps),
            }
        }),
        Region::Sequence(items) => items
            .iter()
            .enumerate()
            .find_map(|(i, item)| guard_traps(func, item, cond, none_takes_then, &items[i + 1..], traps)),
        Region::Scope { body, .. } | Region::Loop { body, .. } => {
            guard_traps(func, body, cond, none_takes_then, &[], traps)
        }
        Region::If { then_region, else_region, .. } => {
            guard_traps(func, then_region, cond, none_takes_then, &[], traps).or_else(|| {
                else_region
                    .as_ref()
                    .and_then(|e| guard_traps(func, e, cond, none_takes_then, &[], traps))
            })
        }
        Region::Switch { arms, default, .. } => arms
            .iter()
            .find_map(|arm| guard_traps(func, &arm.body, cond, none_takes_then, &[], traps))
            .or_else(|| guard_traps(func, default, cond, none_takes_then, &[], traps)),
        _ => None,
    }
}

/// Whether control never falls out of the bottom of `region`.
fn leaves(region: &Region) -> bool {
    match region {
        Region::Return { .. }
        | Region::Break { .. }
        | Region::Continue { .. }
        | Region::Panic { .. }
        | Region::Unreachable => true,
        Region::Sequence(items) => items.last().is_some_and(leaves),
        Region::If { then_region, else_region: Some(e), .. } => leaves(then_region) && leaves(e),
        _ => false,
    }
}

/// Whether `region` dies with a bare panic and does nothing observable on
/// the way: its blocks hold only pure bindings and calls to functions
/// whose whole body is a trap.
fn none_path_traps(func: &HighFunction, region: &Region, traps: &HashSet<FuncId>) -> bool {
    match region {
        Region::Panic { kind } => matches!(kind, sordec_ir::PanicKind::Bare | sordec_ir::PanicKind::Unwrap),
        Region::Unreachable => true,
        Region::Basic(b) => {
            let Some(block) = func.blocks.get(*b) else {
                return false;
            };
            let calls_trap = block.bindings.iter().any(|id| {
                matches!(func.bindings.get(*id).map(|b| &b.expr), Some(Expr::Call { target, .. }) if traps.contains(target))
            });
            calls_trap && block_is_quiet(func, block, traps)
        }
        Region::Sequence(items) => {
            for item in items {
                if none_path_traps(func, item, traps) {
                    return true;
                }
                let quiet = match item {
                    Region::Basic(b) => func.blocks.get(*b).is_some_and(|block| block_is_quiet(func, block, traps)),
                    Region::Transfer { .. } => true,
                    _ => false,
                };
                if !quiet {
                    return false;
                }
            }
            false
        }
        _ => false,
    }
}

fn block_is_quiet(func: &HighFunction, block: &sordec_ir::HighBlock, traps: &HashSet<FuncId>) -> bool {
    block.bindings.iter().all(|id| match func.bindings.get(*id).map(|b| &b.expr) {
        Some(Expr::Call { target, .. }) => traps.contains(target),
        Some(other) => expr_effects(other).is_pure_total(),
        None => false,
    })
}

// ---------------------------------------------------------------------
// The rewrite
// ---------------------------------------------------------------------

fn rewrite(func: &mut HighFunction, helper: &Helper, site: &Site) {
    let Some(&ptr) = site.args.get(helper.out) else {
        return;
    };
    let mut fresh: Vec<ValueId> = Vec::new();
    let mut push = |func: &mut HighFunction, ty: IrType, expr: Expr, note: &str| -> ValueId {
        let id = ValueId::from_index(func.bindings.len() as u32);
        func.bindings.push(Binding::new(
            id,
            ty,
            expr,
            Provenance::new(PASS_NAME, ProvenanceSource::SdkPattern, note.to_string()),
        ));
        fresh.push(id);
        id
    };

    let durability = push(
        func,
        IrType::Known(KnownType::I64),
        Expr::Literal(Literal::I64(match helper.tier {
            KnownTier::Temporary => 0,
            KnownTier::Persistent => 1,
            KnownTier::Instance => 2,
        })),
        "storage durability of the collapsed read",
    );
    let key = match &helper.key {
        KeySource::Param(i) => site.args.get(*i).copied(),
        KeySource::Resolved => Some(push(
            func,
            IrType::Known(KnownType::Unit),
            Expr::Literal(Literal::Unit),
            "resolved storage key: spelled by its name",
        )),
        KeySource::Call { target, args, ty } => {
            let mut mapped = Vec::with_capacity(args.len());
            for arg in args {
                mapped.push(match arg {
                    Arg::Param(i) => match site.args.get(*i) {
                        Some(a) => *a,
                        None => return,
                    },
                    Arg::Lit(lit) => push(func, lit_type(lit), Expr::Literal(lit.clone()), "key constructor argument"),
                });
            }
            Some(push(
                func,
                ty.clone(),
                Expr::Call { target: *target, args: mapped },
                "the helper's key constructor, rebuilt with this call site's arguments",
            ))
        }
    };
    let Some(key) = key else {
        return;
    };
    let resolved_key = match &helper.resolved {
        Some((enum_name, variant, payload)) => {
            let Some(payload) = payload.iter().map(|i| site.args.get(*i).copied()).collect::<Option<Vec<_>>>() else {
                return;
            };
            Some(EnumKey { enum_name: enum_name.clone(), variant: variant.clone(), payload })
        }
        None => None,
    };
    let read = push(
        func,
        helper.ty.clone(),
        Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet {
            tier: StorageTier::Known(helper.tier),
            durability,
            key,
            resolved_key,
            missing: sordec_ir::Missing::Unwrap,
        })),
        "`get(..).unwrap()`: the SDK's Option out-parameter read, collapsed at its call site",
    );
    for (off, width, slot) in &helper.slots {
        let value = match slot {
            Slot::Flag { some, .. } => push(func, lit_type(some), Expr::Literal(some.clone()), "Option discriminant: Some"),
            Slot::Const(lit) => push(func, lit_type(lit), Expr::Literal(lit.clone()), "constant slot of the Option"),
            Slot::Payload(Part::Whole) => read,
            Slot::Payload(Part::Lo) => push(
                func,
                IrType::Inferred(KnownType::I64),
                Expr::Unary { op: UnaryOp::WideLo, value: read },
                "low limb of the read",
            ),
            Slot::Payload(Part::Hi) => push(
                func,
                IrType::Inferred(KnownType::I64),
                Expr::Unary { op: UnaryOp::WideHi, value: read },
                "high limb of the read",
            ),
        };
        push(
            func,
            IrType::Known(KnownType::Unit),
            Expr::Store { addr: ptr, value, offset: *off, width: *width },
            "the store the helper made on its Some path",
        );
    }

    for (_, block) in func.blocks.iter_mut() {
        if let Some(pos) = block.bindings.iter().position(|v| *v == site.call) {
            for (i, id) in fresh.iter().enumerate() {
                block.bindings.insert(pos + i, *id);
            }
            break;
        }
    }
    if let Some(b) = func.bindings.get_mut(site.call) {
        b.expr = Expr::Literal(Literal::Unit);
        b.ty = IrType::Known(KnownType::Unit);
        b.add_provenance(Provenance::new(
            PASS_NAME,
            ProvenanceSource::SdkPattern,
            format!("call to Option storage helper func_{} replaced by the read it makes", site.helper.index()),
        ));
    }
}

fn lit_type(lit: &Literal) -> IrType {
    IrType::Known(match lit {
        Literal::I32(_) => KnownType::I32,
        Literal::U32(_) => KnownType::U32,
        Literal::U64(_) => KnownType::U64,
        _ => KnownType::I64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{module, v};
    use sordec_common::{Arena, BlockId, UnknownReason};
    use sordec_ir::{HighBlock, PanicKind};

    fn bb(i: u32) -> BlockId {
        BlockId::from_index(i)
    }

    /// A function over `exprs` (ids `0..N`) with blocks laid out by
    /// `layout` and the given region; `params` are binding ids.
    fn func(id: u32, exprs: Vec<Expr>, params: Vec<u32>, layout: Vec<Vec<u32>>, region: Region) -> HighFunction {
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        for expr in exprs {
            let vid = ValueId::from_index(bindings.len() as u32);
            bindings.push(Binding::new(
                vid,
                IrType::Unknown(UnknownReason::InsufficientEvidence),
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
            blocks,
            bindings,
            region,
            params: params.into_iter().map(v).collect(),
            returns: vec![],
        }
    }

    fn admin() -> Option<EnumKey> {
        Some(EnumKey { enum_name: "DataKey".into(), variant: "Admin".into(), payload: vec![] })
    }

    /// func_1: `if has(Admin) { store out+8 <- get(Admin); d = 1 } else
    /// { d = 0 }; store out+0 <- d`. `none_store` adds a store on the
    /// `None` side, which disqualifies it.
    fn helper(none_store: bool) -> HighFunction {
        let tier = || StorageTier::Known(KnownTier::Instance);
        let mut exprs = vec![
            Expr::Phi { incoming: vec![] }, // v0 out
            Expr::Literal(Literal::Unit),   // v1 key
            Expr::Literal(Literal::I64(2)), // v2 durability
            Expr::Semantic(SemanticOp::Known(KnownOp::StorageHas {
                tier: tier(),
                durability: v(2),
                key: v(1),
                resolved_key: admin(),
                probe: true,
            })), // v3
            Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet {
                tier: tier(),
                durability: v(2),
                key: v(1),
                resolved_key: admin(),
                missing: sordec_ir::Missing::Option,
            })), // v4
            Expr::Literal(Literal::I64(1)), // v5
            Expr::Literal(Literal::I64(0)), // v6
            Expr::Store { addr: v(0), value: v(4), offset: 8, width: MemWidth::W8 }, // v7
            Expr::Phi { incoming: vec![(bb(1), v(5)), (bb(3), v(6))] },               // v8
            Expr::Store { addr: v(0), value: v(8), offset: 0, width: MemWidth::W8 }, // v9
            Expr::Store { addr: v(0), value: v(6), offset: 16, width: MemWidth::W8 }, // v10
        ];
        exprs.truncate(11);
        let none_block = if none_store { vec![10] } else { vec![] };
        func(
            1,
            exprs,
            vec![0],
            vec![vec![3], vec![4, 7], vec![9], none_block],
            Region::Sequence(vec![
                Region::Basic(bb(0)),
                Region::If {
                    cond: v(3),
                    then_region: Box::new(Region::Basic(bb(1))),
                    else_region: Some(Box::new(Region::Basic(bb(3)))),
                },
                Region::Basic(bb(2)),
                Region::Return { values: vec![] },
            ]),
        )
    }

    /// func_2: the panic helper, a bare trap.
    fn trap() -> HighFunction {
        func(2, vec![], vec![], vec![vec![]], Region::Panic { kind: PanicKind::Bare })
    }

    /// func_0: `func_1(fp); if load(fp+0) { return load(fp+8) } <none>`,
    /// where `<none>` is `func_2(); panic!()` or, when `default`, a
    /// return of a constant.
    fn caller(default: bool) -> HighFunction {
        let exprs = vec![
            Expr::Phi { incoming: vec![] }, // v0 frame
            Expr::Call { target: FuncId::from_index(1), args: vec![v(0)] }, // v1
            Expr::Load {
                addr: v(0),
                offset: 0,
                width: MemWidth::W8,
                signed: None,
                ty: IrType::Unknown(UnknownReason::InsufficientEvidence),
            }, // v2 flag
            Expr::Load {
                addr: v(0),
                offset: 8,
                width: MemWidth::W8,
                signed: None,
                ty: IrType::Unknown(UnknownReason::InsufficientEvidence),
            }, // v3 payload
            Expr::Call { target: FuncId::from_index(2), args: vec![] }, // v4
            Expr::Literal(Literal::I64(7)), // v5
        ];
        let none = if default {
            Region::Return { values: vec![v(5)] }
        } else {
            Region::Sequence(vec![Region::Basic(bb(2)), Region::Panic { kind: PanicKind::Bare }])
        };
        func(
            0,
            exprs,
            vec![],
            vec![vec![1, 2], vec![3], if default { vec![] } else { vec![4] }],
            Region::Sequence(vec![
                Region::Basic(bb(0)),
                Region::If {
                    cond: v(2),
                    then_region: Box::new(Region::Sequence(vec![
                        Region::Basic(bb(1)),
                        Region::Return { values: vec![v(3)] },
                    ])),
                    else_region: None,
                },
                none,
            ]),
        )
    }

    /// Every read in `f`: whether it unwraps, and the variant it names.
    fn reads(f: &HighFunction) -> Vec<(bool, Option<String>)> {
        f.bindings
            .iter()
            .filter_map(|(_, b)| match &b.expr {
                Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet { missing, resolved_key, .. })) => {
                    Some((*missing == sordec_ir::Missing::Unwrap, resolved_key.as_ref().map(|k| k.variant.clone())))
                }
                _ => None,
            })
            .collect()
    }

    #[test]
    fn the_helper_is_classified_with_its_flag_and_payload() {
        let h = classify(&helper(false)).expect("an Option helper");
        assert_eq!(h.out, 0);
        assert!(matches!(h.key, KeySource::Resolved));
        assert!(h.slots.iter().any(|(off, _, s)| *off == 0 && matches!(s, Slot::Flag { .. })));
        assert!(h.slots.iter().any(|(off, _, s)| *off == 8 && matches!(s, Slot::Payload(Part::Whole))));
    }

    #[test]
    fn a_store_on_the_none_arm_is_not_a_helper() {
        assert!(classify(&helper(true)).is_none());
    }

    #[test]
    fn a_call_whose_none_side_traps_becomes_the_unwrapped_read() {
        let mut m = module(vec![caller(false), helper(false), trap()]);
        let r = OptionSretPass.run(&mut m);
        assert!(r.changed);
        assert_eq!(r.metrics.get(M_COLLAPSED), Some(1));
        let f = &m.functions[0];
        assert!(matches!(f.bindings.get(v(1)).unwrap().expr, Expr::Literal(Literal::Unit)));
        assert_eq!(reads(f), vec![(true, Some("Admin".to_string()))]);
        // The Some-path stores are scheduled where the call was, ahead of
        // the flag load.
        let block = &f.blocks.get(bb(0)).unwrap().bindings;
        let flag_load = block.iter().position(|x| *x == v(2)).unwrap();
        let stores: Vec<u32> = block[..flag_load]
            .iter()
            .filter_map(|id| match &f.bindings.get(*id).unwrap().expr {
                Expr::Store { offset, .. } => Some(*offset),
                _ => None,
            })
            .collect();
        assert_eq!(stores, vec![8, 0]);
    }

    /// `unwrap_or`: the caller's `None` side returns a default rather than
    /// trapping, so the read must stay an `Option`.
    #[test]
    fn a_call_whose_none_side_does_not_trap_is_left_alone() {
        let mut m = module(vec![caller(true), helper(false), trap()]);
        assert!(!OptionSretPass.run(&mut m).changed);
        assert!(matches!(m.functions[0].bindings.get(v(1)).unwrap().expr, Expr::Call { .. }));
    }

    #[test]
    fn the_pass_is_idempotent() {
        let mut m = module(vec![caller(false), helper(false), trap()]);
        assert!(OptionSretPass.run(&mut m).changed);
        assert!(!OptionSretPass.run(&mut m).changed);
    }
}
