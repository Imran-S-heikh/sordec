//! Function specialization — splitting the helpers rustc merged.
//!
//! LLVM's identical-code folding rewrites a family of source functions
//! that differ only in a constant into **one** body, with the constant
//! demoted to a parameter. dex's `get_total_shares`, `get_reserve_a` and
//! `get_reserve_b` become a single helper called with `2`, `3`, `4`;
//! timelock's two `env.storage().instance().set(…)` calls become one
//! helper called with two different keys.
//!
//! Every downstream recognizer then declines, *correctly*.
//! [`Resolver`](crate::dataflow::Resolver) meets over all callers and
//! returns `None` on disagreement; [`EnumKeyPass`](crate::recognizers::EnumKeyPass)
//! meets a key parameter the same way. But the disagreement is not
//! ambiguity — it is several distinct facts sharing one body. This pass
//! gives each fact its body back, which is the exact inverse of the
//! transform that destroyed it.
//!
//! ## The two halves, and why both are needed
//!
//! - **De-share.** Clone the helper once per call site and retarget each
//!   site to its own copy. Every meet-over-callers then meets over
//!   exactly one caller, so the existing recognizers resolve with no
//!   change to them. This is what recovers timelock's `set` helper,
//!   where the distinguishing argument is a *constructed key* — never a
//!   constant, so no amount of constant folding would have reached it.
//! - **Pin.** Inside each copy, a parameter whose call-site argument is
//!   a literal is deleted and its binding rewritten to that literal.
//!   This is what recovers dex's discriminants and durability tiers,
//!   which [`trace_int`] reads
//!   intra-procedurally and so could never see through a parameter.
//!
//! ## Why pinning must *remove* the parameter
//!
//! [`Resolver::walk_terminal`](crate::dataflow::Resolver) tests
//! `func.params.contains(..)` **before** it looks at the expression, and
//! returns an honest `None` for any parameter binding that is not the
//! empty `Phi` the lowering guarantees. Pinning a constant into a
//! binding that is still listed in `params` would therefore make
//! resolution strictly *worse* than leaving it alone. The parameter has
//! to actually go — which means the call site loses that argument too.
//!
//! The consequence is a scheduling obligation. `check_region_dominance`
//! seeds its defined-set from `params` and from every `Phi`; a former
//! parameter that is now an `Expr::Literal` is neither, so it must be
//! scheduled into the first block the dominance walk reaches or the
//! validator reports `UseBeforeDef`. [`pin_target_block`] finds that
//! block by mirroring the validator's own traversal, and declines when
//! the walk reads a value before reaching any block.
//!
//! ## What it will not do (each guards a wrong-answer hole)
//!
//! - **Exported functions are never specialized**, and never treated as
//!   a caller worth splitting. They are host-invocable, so their
//!   internal call sites are not the complete caller set — the same rule
//!   [`crate::dataflow::Resolver`] states.
//! - **Any indirect call in the module disables the pass**, module-wide.
//!   Table-called functions have invisible callers, so no caller set can
//!   be trusted. Again [`crate::dataflow::Resolver`]'s rule, reused rather
//!   than restated.
//! - **Self-recursive functions are skipped.** Cloning one is sound but
//!   pointless (the copy still calls the original), and skipping keeps
//!   the round structure below easy to reason about.
//! - **Demand-driven only.** Cloning every multi-caller helper would
//!   take dex from 50 functions to ~180. A function is a candidate only
//!   when a storage key or durability operand inside it dead-ends at one
//!   of its own parameters, or when it forwards a parameter into a
//!   position already known to be blocked. Measured cost of that rule on
//!   the corpus: +8 functions on dex's 50, +2 on timelock's 18.
//!
//! ## Rounds, and why one pass is not enough
//!
//! Nested candidates cannot be split in one sweep: dex's `func11`
//! forwards `func4`'s discriminant, and cloning both at once would wire
//! `func4`'s copies to the *original* `func11`'s call sites — which the
//! same sweep has just made unreachable. So each round splits only the
//! outermost layer (candidates none of whose callers are themselves
//! candidates) and then rebuilds the call graph. Two rounds settle the
//! corpus; [`MAX_ROUNDS`] backstops.
//!
//! A declined candidate is a recoverable fact left on the table, so it
//! reports by name through [`LiftDiagnosticCode::SpecializationDeclined`]
//! rather than only as a counter.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use sordec_common::{
    BlockId, Diagnostic, FuncId, IrId, LiftDiagnosticCode, Location, Provenance, ProvenanceSource,
    ValueId,
};
use sordec_ir::{Expr, HighFunction, HighIr, KnownOp, Literal, Region, SemanticOp};

use crate::dataflow::{trace_int, CallIndex, CallSite};
use crate::pass::{Pass, PassResult};
use crate::recognizers::storage::storage_operands;
use crate::recognizers::wrappers::chase_value;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "specialize";

// Metric counter keys.
/// Copies of merged helpers created, one per de-shared call site.
const M_CLONED: &str = "specialize_cloned";
/// Call sites retargeted onto a copy or re-aritied by pinning.
const M_RETARGETED: &str = "specialize_retargeted";
/// Parameters deleted and replaced by the constant their caller passes.
const M_PINNED: &str = "specialize_params_pinned";
/// Candidates left merged (cycle, budget, or an unpinnable region shape).
const M_DECLINED: &str = "specialize_declined";
/// Why each declined candidate was left merged. The total alone cannot say
/// whether a contract is near the fan-out line or nowhere near it.
const M_FANOUT: &str = crate::metrics_catalog::SPECIALIZE_DECLINED_FANOUT;
/// See [`M_FANOUT`].
const M_GROUPING: &str = crate::metrics_catalog::SPECIALIZE_DECLINED_GROUPING;
/// See [`M_FANOUT`].
const M_BUDGET: &str = crate::metrics_catalog::SPECIALIZE_DECLINED_BUDGET;
/// See [`M_FANOUT`].
const M_UNPINNABLE: &str = crate::metrics_catalog::SPECIALIZE_DECLINED_UNPINNABLE;
/// See [`M_FANOUT`].
const M_INDIRECT: &str = crate::metrics_catalog::SPECIALIZE_DISABLED_INDIRECT;

/// How deep to look through constructor helpers when asking which of a
/// function's parameters a storage operand depends on. A `#[contracttype]`
/// key reaches its storage call through one or two tiny helpers.
const OPERAND_DEPTH: u32 = 3;

/// Skip a helper with more call sites than this. De-sharing is linear in
/// the fan-out, and a helper called from everywhere is shared
/// infrastructure rather than a folded source family.
const MAX_CALLSITE_FANOUT: usize = 8;

/// Largest body (emitted bindings, literals included) a helper may have
/// for a guard on its own parameters to make it a candidate. The SDK's
/// slice constructors are around twenty — three `U32Val` encodes and the
/// constructor call; a real function that happens to compare two
/// parameters is not what this rule is for.
const GUARD_HELPER_MAX_BODY: usize = 40;

/// Outermost-layer rounds before giving up. The corpus settles in two.
const MAX_ROUNDS: u32 = 8;

/// The function specializer. Stateless between runs.
#[derive(Debug, Default, Clone, Copy)]
pub struct SpecializePass;

impl Pass<HighIr> for SpecializePass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        // Growth budget: at most one extra function per original. Held
        // across rounds so a deep nest cannot spend it a layer at a time.
        let mut budget = ir.functions.len();
        let mut declined: BTreeSet<FuncId> = BTreeSet::new();
        let mut why: BTreeMap<FuncId, &'static str> = BTreeMap::new();

        for _ in 0..MAX_ROUNDS {
            let calls = CallIndex::build(ir);
            // Indirect calls anywhere mean no caller set is complete.
            if calls.has_indirect_calls() {
                result.metrics.increment(M_INDIRECT, 1);
                break;
            }
            let blocked = blocked_params(ir, &calls);
            let candidates = candidates(ir, &calls, &blocked);
            if candidates.is_empty() {
                break;
            }
            let plans = plan_round(
                ir,
                &calls,
                &blocked,
                &candidates,
                &mut budget,
                &mut declined,
                &mut why,
            );
            if plans.is_empty() {
                break;
            }
            apply(ir, plans, &mut result);
        }

        for func in declined {
            result.metrics.increment(M_DECLINED, 1);
            if let Some(reason) = why.get(&func) {
                result.metrics.increment(reason, 1);
            }
            result.diagnostics.push(
                Diagnostic::warning(LiftDiagnosticCode::SpecializationDeclined, "")
                    .at(Location::Function(func)),
            );
        }
        crate::refine::debug_validate(ir, PASS_NAME);
        result
    }
}

// ---------------------------------------------------------------------
// Phase A — which parameters block storage evidence
// ---------------------------------------------------------------------

/// The key and durability operands of a storage call, whether it is
/// still a raw `l`-module host call (this pass's registered position,
/// ahead of [`StoragePass`](crate::recognizers::StoragePass)) or already
/// a named op. Reading both keeps the pass position-independent.
fn storage_operand_values(expr: &Expr) -> Option<(ValueId, ValueId)> {
    match expr {
        Expr::Semantic(SemanticOp::Unknown {
            host_module,
            host_fn,
            args,
            ..
        }) if host_module == "l" => {
            let ops = storage_operands(host_fn, args.len())?;
            Some((args[ops.key], args[ops.durability]))
        }
        Expr::Semantic(SemanticOp::Known(
            KnownOp::StorageGet { key, durability, .. }
            | KnownOp::StorageSet { key, durability, .. }
            | KnownOp::StorageHas { key, durability, .. }
            | KnownOp::StorageRemove { key, durability, .. }
            | KnownOp::StorageExtendTtl { key, durability, .. }
            | KnownOp::StorageExtendTtlV2 { key, durability, .. },
        )) => Some((*key, *durability)),
        _ => None,
    }
}

/// The key-table position and element count of a map unpack (`m.a`), in
/// either the raw or the recognised form.
///
/// Blocked for the same reason a storage key is. `#[contracttype]`'s
/// derived `TryFromVal` unpacks every struct through one shared SDK
/// wrapper whose key table and length arrive as parameters. De-sharing
/// already happens here for other reasons, so the *clone* exists — but
/// pinning only replaces parameters this demand rule named, so the key
/// table stayed a parameter and `marshalling::udt_decode` kept declining
/// for want of a table it could not read.
///
/// Measured on `other_custom_types`: three of its five unpacks resolve
/// their length (3 and 8, per clone) and none resolve their key table.
fn unpack_operand_values(expr: &Expr) -> Option<(ValueId, ValueId)> {
    match expr {
        Expr::Semantic(SemanticOp::Unknown {
            host_module,
            host_fn,
            args,
            ..
        }) if host_module == "m" && host_fn == "a" && args.len() == 4 => {
            Some((args[1], args[3]))
        }
        Expr::Semantic(SemanticOp::Known(KnownOp::MapOp {
            kind: sordec_ir::MapOpKind::UnpackToLinearMemory,
            args,
        })) if args.len() == 4 => Some((args[1], args[3])),
        _ => None,
    }
}

/// Which of `func`'s parameters `value` depends on for its *identity* —
/// the parameters that, left merged, cost a recognizer its answer.
///
/// Chases through `Use`/rename links to the terminal producer; if that
/// is a call to an internal helper (the `#[contracttype]` key
/// constructor idiom), the dependence continues through its arguments.
///
/// A constructor call that already carries a discriminant constant is
/// **not** blocked, even when its other arguments are parameters. That
/// mirrors [`EnumKeyPass`](crate::recognizers::EnumKeyPass)'s by-value
/// channel, which reads exactly that constant and treats the rest as
/// payload. Without the test, dex's `get_token_a` — whose discriminant
/// is a literal and whose *payload* is a parameter — reads as blocked
/// and gets split into copies that each re-report the one storage fact
/// it already recovered.
fn param_positions(
    ir: &HighIr,
    func: &HighFunction,
    value: ValueId,
    depth: u32,
    out: &mut BTreeSet<usize>,
) {
    let terminal = chase_value(func, value);
    if let Some(idx) = func.params.iter().position(|p| *p == terminal) {
        out.insert(idx);
        return;
    }
    if depth == 0 {
        return;
    }
    let Some(binding) = func.bindings.get(terminal) else {
        return;
    };
    if let Expr::Call { target, args } = &binding.expr {
        // Only internal helpers; an exported callee is not a constructor.
        if ir.function(*target).is_none_or(|f| f.name.is_some()) {
            return;
        }
        if args.iter().any(|arg| trace_int(func, *arg).is_some()) {
            return;
        }
        for arg in args {
            param_positions(ir, func, *arg, depth - 1, out);
        }
    }
}

/// Per-function parameter positions that some storage operand needs
/// resolved — seeded from the storage calls themselves, then propagated
/// up the call graph through every parameter a caller forwards into an
/// already-blocked position.
///
/// Monotone over a finite `(function, parameter)` domain, so the
/// worklist terminates regardless of call-graph cycles.
fn blocked_params(ir: &HighIr, calls: &CallIndex) -> HashMap<FuncId, BTreeSet<usize>> {
    let mut blocked: HashMap<FuncId, BTreeSet<usize>> = HashMap::new();
    let mut work: Vec<(FuncId, usize)> = Vec::new();

    for func in &ir.functions {
        for (_, binding) in func.bindings.iter() {
            let Some((first, second)) = storage_operand_values(&binding.expr)
                .or_else(|| unpack_operand_values(&binding.expr))
            else {
                continue;
            };
            // A linear-memory operand reaches the host as a `U32Val`, so
            // the parameter it really is sits one `ValEncodeSmall` down.
            // `param_positions` chases renames and helper calls but not
            // that wrapper, which is why an unpack's key table looked like
            // no parameter at all.
            let first = crate::recognizers::client_call::peel_encode(func, first);
            let second = crate::recognizers::client_call::peel_encode(func, second);
            let mut positions = BTreeSet::new();
            param_positions(ir, func, first, OPERAND_DEPTH, &mut positions);
            param_positions(ir, func, second, OPERAND_DEPTH, &mut positions);
            for idx in positions {
                if blocked.entry(func.id).or_default().insert(idx) {
                    work.push((func.id, idx));
                }
            }
        }
    }

    // The inlined symbol encoder folds only a call site whose `(pointer,
    // length)` are literals. token-v22 wraps it: `Symbol::try_from_val`
    // is a helper that forwards its own parameters into the encoder, and
    // the literals sit one caller up. Those parameters are blocked in the
    // same sense as a storage key — the fact is there, one frame away —
    // so de-sharing and pinning the wrapper is what lets the fold fire.
    let encoders: HashSet<FuncId> = ir
        .functions
        .iter()
        .filter(|f| crate::recognizers::symbol_encoder::is_symbol_encoder(f))
        .map(|f| f.id)
        .collect();
    if !encoders.is_empty() {
        for func in &ir.functions {
            for (_, binding) in func.bindings.iter() {
                let Expr::Call { target, args } = &binding.expr else {
                    continue;
                };
                if !encoders.contains(target) || args.len() != 2 {
                    continue;
                }
                let mut positions = BTreeSet::new();
                param_positions(ir, func, args[0], OPERAND_DEPTH, &mut positions);
                param_positions(ir, func, args[1], OPERAND_DEPTH, &mut positions);
                for idx in positions {
                    if blocked.entry(func.id).or_default().insert(idx) {
                        work.push((func.id, idx));
                    }
                }
            }
        }
    }

    // A small helper that branches on nothing but its own parameters —
    // `map_new_from_slices` asserting `keys.len() == vals.len()` — has a
    // guard every caller decides at compile time. Pinning the parameters
    // makes the condition a constant, the fold takes the branch, and a
    // straight-line body is what the wrapper inliner can paste. Kept to
    // small bodies so this stays demand-driven rather than a general
    // cloning policy.
    for func in &ir.functions {
        if func.name.is_some() || crate::marshalling::sret::emission_order(func).len() > GUARD_HELPER_MAX_BODY {
            continue;
        }
        let mut conds: Vec<ValueId> = Vec::new();
        func.region.for_each_node(|node| {
            if let sordec_ir::Region::If { cond, .. } = node {
                conds.push(*cond);
            }
        });
        for cond in conds {
            let id = crate::dataflow::resolve_use(func, cond);
            let Some(Expr::Binary { lhs, rhs, .. }) = func.bindings.get(id).map(|b| &b.expr) else {
                continue;
            };
            let mut positions = BTreeSet::new();
            param_positions(ir, func, *lhs, 0, &mut positions);
            param_positions(ir, func, *rhs, 0, &mut positions);
            // Only a guard that reads parameters alone: one side may be a
            // literal, but a side that is neither is runtime state.
            let literal = |v: ValueId| trace_int(func, v).is_some();
            let param_or_lit = |v: ValueId| {
                literal(v) || {
                    let mut p = BTreeSet::new();
                    param_positions(ir, func, v, 0, &mut p);
                    !p.is_empty()
                }
            };
            if positions.is_empty() || !param_or_lit(*lhs) || !param_or_lit(*rhs) {
                continue;
            }
            for idx in positions {
                if blocked.entry(func.id).or_default().insert(idx) {
                    work.push((func.id, idx));
                }
            }
        }
    }

    while let Some((callee, idx)) = work.pop() {
        for site in calls.callers_of(callee) {
            let Some(caller) = ir.function(site.caller) else {
                continue;
            };
            // An exported caller cannot be specialized, so propagating
            // into it would only manufacture candidates we must decline.
            if caller.name.is_some() {
                continue;
            }
            let Some(Expr::Call { args, .. }) = caller.bindings.get(site.call).map(|b| &b.expr)
            else {
                continue;
            };
            let Some(arg) = args.get(idx) else {
                continue;
            };
            let mut positions = BTreeSet::new();
            param_positions(ir, caller, *arg, OPERAND_DEPTH, &mut positions);
            for pos in positions {
                if blocked.entry(site.caller).or_default().insert(pos) {
                    work.push((site.caller, pos));
                }
            }
        }
    }

    blocked
}

/// Functions worth splitting: internal, actually called, not
/// self-recursive, and holding at least one blocked parameter.
fn candidates(
    ir: &HighIr,
    calls: &CallIndex,
    blocked: &HashMap<FuncId, BTreeSet<usize>>,
) -> HashSet<FuncId> {
    blocked
        .iter()
        .filter(|(id, params)| {
            !params.is_empty()
                && ir.function(**id).is_some_and(|f| f.name.is_none())
                && !calls.callers_of(**id).is_empty()
                && !calls.callers_of(**id).iter().any(|s| s.caller == **id)
        })
        .map(|(id, _)| *id)
        .collect()
}

// ---------------------------------------------------------------------
// Phase A — the round plan
// ---------------------------------------------------------------------

/// What a call site carries in one blocked parameter position — the
/// evidence that says *which* of the folded source functions this was.
#[derive(Debug, Clone, PartialEq)]
enum ArgSig {
    /// A literal, which the copy can be specialized on outright.
    Const(Literal),
    /// A value built by an internal helper from arguments that
    /// themselves carry evidence — the `#[contracttype]` key
    /// constructor idiom, where the discriminant never appears as a
    /// literal at the call site but the constructor call still names
    /// the variant.
    Built(FuncId, Vec<ArgSig>),
    /// No evidence. Two call sites carrying `Opaque` are not *known* to
    /// differ, so they stay in one group: splitting on no evidence
    /// would be a guess, and this pass does not guess.
    Opaque,
}

/// A parameter deleted in favour of the constant its callers pass.
#[derive(Debug, Clone)]
struct Pin {
    /// Position in the *original* parameter list.
    param: usize,
    /// The literal every call site in this group passes there.
    value: Literal,
}

/// One planned split: the call sites that agree on a signature get one
/// copy of `source` between them, with `pins` folded in.
///
/// Grouping rather than cloning per call site is what keeps the output
/// the shape of the *source*: `get_reserve_a` was one function called
/// three times, so its three call sites share one copy. Cloning per
/// site would report the same storage fact three times and cost
/// precision exactly as much as it gained recall.
#[derive(Debug, Clone)]
struct Plan {
    source: FuncId,
    sites: Vec<CallSite>,
    pins: Vec<Pin>,
    clone: bool,
}

/// Plan the outermost layer of candidates.
///
/// Only candidates none of whose callers are themselves candidates are
/// touched: splitting an inner one first would wire its copies to call
/// sites this same round is about to orphan.
fn plan_round(
    ir: &HighIr,
    calls: &CallIndex,
    blocked: &HashMap<FuncId, BTreeSet<usize>>,
    candidates: &HashSet<FuncId>,
    budget: &mut usize,
    declined: &mut BTreeSet<FuncId>,
    why: &mut BTreeMap<FuncId, &'static str>,
) -> Vec<Plan> {
    let mut plans = Vec::new();
    // Deterministic order: FuncId, so budget exhaustion is reproducible.
    let mut ordered: Vec<FuncId> = candidates.iter().copied().collect();
    ordered.sort_by_key(|id| id.index());

    for id in ordered {
        let sites = calls.callers_of(id);
        if sites.iter().any(|s| candidates.contains(&s.caller)) {
            continue; // inner layer — a later round
        }
        if sites.len() > MAX_CALLSITE_FANOUT {
            declined.insert(id);
            why.insert(id, M_FANOUT);
            continue;
        }
        let Some(func) = ir.function(id) else {
            continue;
        };
        // Ascending, so a signature vector indexes the same parameter
        // for every call site.
        let params: Vec<usize> = blocked.get(&id).cloned().unwrap_or_default().into_iter().collect();
        let Some(groups) = group_sites(ir, func, sites, &params) else {
            declined.insert(id);
            why.insert(id, M_GROUPING);
            continue;
        };
        let clone = groups.len() > 1;
        // One copy per group; the original then goes dead.
        if clone && groups.len() > *budget {
            declined.insert(id);
            why.insert(id, M_BUDGET);
            continue;
        }
        // A constant is only pinnable if it has somewhere to be
        // scheduled that dominates its readers.
        let pinnable = pin_target_block(&func.region).is_some();

        let round: Vec<Plan> = groups
            .into_iter()
            .map(|group| Plan {
                source: id,
                pins: if pinnable { pins_of(&group.sig, &params) } else { Vec::new() },
                sites: group.sites,
                clone,
            })
            // Nothing to gain: one group with nothing to pin is already
            // as resolvable as it will ever be.
            .filter(|plan| plan.clone || !plan.pins.is_empty())
            .collect();

        if round.is_empty() {
            // Blocked, and neither de-sharing nor pinning reaches it.
            if !pinnable {
                declined.insert(id);
                why.insert(id, M_UNPINNABLE);
            }
            continue;
        }
        if clone {
            *budget -= round.len();
        }
        plans.extend(round);
    }
    plans
}

/// Call sites sharing one signature over the blocked parameters.
struct Group {
    sig: Vec<ArgSig>,
    sites: Vec<CallSite>,
}

/// Partition `sites` by what they carry in the blocked positions.
///
/// `None` when any call site's arity disagrees with the callee — that is
/// malformed IR, not something to specialize through.
fn group_sites(
    ir: &HighIr,
    callee: &HighFunction,
    sites: &[CallSite],
    params: &[usize],
) -> Option<Vec<Group>> {
    let mut groups: Vec<Group> = Vec::new();
    for site in sites {
        let caller = ir.function(site.caller)?;
        let Expr::Call { args, .. } = &caller.bindings.get(site.call)?.expr else {
            return None;
        };
        if args.len() != callee.params.len() {
            return None;
        }
        let sig: Vec<ArgSig> = params
            .iter()
            .map(|&p| match args.get(p) {
                Some(arg) => arg_sig(ir, caller, *arg, OPERAND_DEPTH),
                None => ArgSig::Opaque,
            })
            .collect();
        match groups.iter_mut().find(|g| g.sig == sig) {
            Some(group) => group.sites.push(*site),
            None => groups.push(Group {
                sig,
                sites: vec![*site],
            }),
        }
    }
    Some(groups)
}

/// The evidence one argument carries about which source function this
/// call site came from.
fn arg_sig(ir: &HighIr, func: &HighFunction, value: ValueId, depth: u32) -> ArgSig {
    let terminal = chase_value(func, value);
    let Some(binding) = func.bindings.get(terminal) else {
        return ArgSig::Opaque;
    };
    match &binding.expr {
        Expr::Literal(lit) => ArgSig::Const(lit.clone()),
        Expr::Call { target, args }
            if depth > 0 && ir.function(*target).is_some_and(|f| f.name.is_none()) =>
        {
            let inner: Vec<ArgSig> = args
                .iter()
                .map(|arg| arg_sig(ir, func, *arg, depth - 1))
                .collect();
            // A constructor whose own arguments say nothing distinguishes
            // nothing.
            if inner.iter().all(|s| matches!(s, ArgSig::Opaque)) {
                ArgSig::Opaque
            } else {
                ArgSig::Built(*target, inner)
            }
        }
        _ => ArgSig::Opaque,
    }
}

/// The positions of a signature that are outright constants — the only
/// ones a copy can fold in.
fn pins_of(sig: &[ArgSig], params: &[usize]) -> Vec<Pin> {
    sig.iter()
        .zip(params)
        .filter_map(|(s, &param)| match s {
            ArgSig::Const(value) => Some(Pin {
                param,
                value: value.clone(),
            }),
            ArgSig::Built(..) | ArgSig::Opaque => None,
        })
        .collect()
}

// ---------------------------------------------------------------------
// Phase B — apply
// ---------------------------------------------------------------------

fn apply(ir: &mut HighIr, plans: Vec<Plan>, result: &mut PassResult) {
    for plan in plans {
        let target = if plan.clone {
            let Some(mut copy) = ir.function(plan.source).cloned() else {
                continue;
            };
            let id = FuncId::from_index(
                u32::try_from(ir.functions.len()).expect("function count fits in u32"),
            );
            copy.id = id;
            pin_into(&mut copy, &plan.pins, plan.source);
            ir.functions.push(copy);
            result.metrics.increment(M_CLONED, 1);
            id
        } else {
            let Some(func) = ir.function_mut(plan.source) else {
                continue;
            };
            pin_into(func, &plan.pins, plan.source);
            plan.source
        };

        let pinned = i64::try_from(plan.pins.len()).unwrap_or(i64::MAX);
        if pinned > 0 {
            result.metrics.increment(M_PINNED, pinned);
        }
        for site in &plan.sites {
            if retarget(ir, &plan, *site, target) {
                result.metrics.increment(M_RETARGETED, 1);
                result.changed = true;
            }
        }
    }
}

/// Fold `pins` into `func`: delete each parameter and rewrite its
/// binding to the constant, scheduled where the dominance walk will see
/// it first.
fn pin_into(func: &mut HighFunction, pins: &[Pin], source: FuncId) {
    let Some(block_id) = pin_target_block(&func.region) else {
        debug_assert!(pins.is_empty(), "pins planned without a schedulable block");
        return;
    };
    // Descending, so each removal leaves the lower positions valid.
    let mut ordered: Vec<&Pin> = pins.iter().collect();
    ordered.sort_by_key(|pin| std::cmp::Reverse(pin.param));

    for pin in ordered {
        if pin.param >= func.params.len() {
            continue;
        }
        let value = func.params.remove(pin.param);
        let note = format!(
            "specialized from #{} — parameter {} is always {:?} at this call site",
            source.index(),
            pin.param,
            pin.value
        );
        if let Some(binding) = func.bindings.get_mut(value) {
            binding.expr = Expr::Literal(pin.value.clone());
            binding.add_provenance(Provenance::new(PASS_NAME, ProvenanceSource::DataFlow, note));
        }
        // A former parameter is neither a param nor a phi, so the
        // dominance walk no longer gets it for free.
        if let Some(block) = func.blocks.get_mut(block_id)
            && !block.bindings.contains(&value)
        {
            block.bindings.insert(0, value);
        }
    }
}

/// Point one call site at `target` and drop the arguments its pinned
/// parameters no longer take.
fn retarget(ir: &mut HighIr, plan: &Plan, site: CallSite, target: FuncId) -> bool {
    let Some(caller) = ir.function_mut(site.caller) else {
        return false;
    };
    let Some(binding) = caller.bindings.get_mut(site.call) else {
        return false;
    };
    let Expr::Call { target: slot, args } = &mut binding.expr else {
        return false;
    };
    let mut dropped: Vec<usize> = plan.pins.iter().map(|p| p.param).collect();
    dropped.sort_unstable_by(|a, b| b.cmp(a));
    for param in dropped {
        if param < args.len() {
            args.remove(param);
        }
    }
    let retargeted = *slot != target;
    *slot = target;
    let note = if plan.clone {
        format!(
            "de-shared onto a copy of #{} shared by {} agreeing call site(s), {} parameter(s) pinned",
            plan.source.index(),
            plan.sites.len(),
            plan.pins.len()
        )
    } else {
        format!(
            "every call site of #{} agrees: {} parameter(s) pinned in place",
            plan.source.index(),
            plan.pins.len()
        )
    };
    binding.add_provenance(Provenance::new(PASS_NAME, ProvenanceSource::DataFlow, note));
    retargeted || !plan.pins.is_empty()
}

// ---------------------------------------------------------------------
// Scheduling
// ---------------------------------------------------------------------

/// What the dominance walk meets first.
enum Reach {
    /// A basic block — a constant scheduled at its head dominates
    /// everything the walk reaches later.
    Block(BlockId),
    /// A value read, with no block yet. Nothing can be scheduled early
    /// enough to dominate it.
    Value,
    /// Nothing that constrains scheduling.
    Nothing,
}

/// The block a pinned constant can be scheduled into, or `None` when
/// the region reads a value before reaching any block.
///
/// Mirrors `check_region_dominance`'s traversal exactly — the point is
/// not to guess an entry block but to answer the validator's own
/// question in the validator's own order.
fn pin_target_block(region: &Region) -> Option<BlockId> {
    match first_reach(region) {
        Reach::Block(b) => Some(b),
        Reach::Value | Reach::Nothing => None,
    }
}

fn first_reach(region: &Region) -> Reach {
    match region {
        Region::Basic(b) => Reach::Block(*b),
        Region::Sequence(items) => {
            for item in items {
                match first_reach(item) {
                    Reach::Nothing => {}
                    found => return found,
                }
            }
            Reach::Nothing
        }
        Region::Scope { body, .. } | Region::Loop { body, .. } => first_reach(body),
        // Both read their selector before descending.
        Region::If { .. } | Region::Switch { .. } => Reach::Value,
        Region::Break { transfer, .. }
        | Region::Continue { transfer, .. }
        | Region::Transfer { transfer, .. } => {
            if transfer.is_empty() {
                Reach::Nothing
            } else {
                Reach::Value
            }
        }
        Region::Return { values } => {
            if values.is_empty() {
                Reach::Nothing
            } else {
                Reach::Value
            }
        }
        Region::Unreachable | Region::Panic { .. } | Region::Unstructured { .. } => Reach::Nothing,
    }
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{Arena, BlockId, Provenance, UnknownReason};
    use sordec_ir::{
        Binding, DataSegment, HighBlock, IrType, MemoryImage, SorobanFacts, Validate, WasmFacts,
    };

    /// A function with `n_params` leading parameters (empty-incoming
    /// phis, as the lowering guarantees) then `exprs`, scheduled into one
    /// basic block which is also the region root.
    fn func(id: u32, name: Option<&str>, n_params: usize, exprs: Vec<Expr>) -> HighFunction {
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        let mut params = Vec::new();
        let mut scheduled = Vec::new();
        for _ in 0..n_params {
            let vid = ValueId::from_index(bindings.len() as u32);
            bindings.push(Binding::new(
                vid,
                IrType::Unknown(UnknownReason::InsufficientEvidence),
                Expr::Phi { incoming: vec![] },
                Provenance::new("test", ProvenanceSource::DataFlow, "param"),
            ));
            params.push(vid);
        }
        for expr in exprs {
            let vid = ValueId::from_index(bindings.len() as u32);
            bindings.push(Binding::new(
                vid,
                IrType::Unknown(UnknownReason::InsufficientEvidence),
                expr,
                Provenance::new("test", ProvenanceSource::DataFlow, "seed"),
            ));
            scheduled.push(vid);
        }
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        let bid = blocks.push(HighBlock {
            id: BlockId::from_index(0),
            bindings: scheduled,
        });
        HighFunction {
            id: FuncId::from_index(id),
            name: name.map(str::to_string),
            signature: None,
            blocks,
            bindings,
            region: Region::Basic(bid),
            params,
            returns: vec![],
        }
    }

    fn module(functions: Vec<HighFunction>) -> HighIr {
        // One body per local function, as every real module has: the WAT
        // side reads this length to know which functions are anchorable.
        let bodies = (0..functions.len())
            .map(|i| sordec_ir::ByteRange {
                start: i as u64,
                end: i as u64 + 1,
            })
            .collect();
        HighIr {
            facts: WasmFacts {
                imports: vec![],
                exports: vec![],
                function_type_indices: vec![],
                function_bodies: bodies,
                function_fingerprints: vec![],
                custom_sections: vec![],
            },
            soroban_facts: Some(SorobanFacts::default()),
            functions,
            memory: MemoryImage::from_segments(vec![DataSegment {
                offset: 1000,
                bytes: b"key".to_vec(),
            }]),
        }
    }

    fn v(i: u32) -> ValueId {
        ValueId::from_index(i)
    }

    fn i64c(n: i64) -> Expr {
        Expr::Literal(Literal::I64(n))
    }

    fn call(target: u32, args: Vec<ValueId>) -> Expr {
        Expr::Call {
            target: FuncId::from_index(target),
            args,
        }
    }

    /// `l."1"` — storage get(key, durability).
    fn storage_get(key: ValueId, durability: ValueId) -> Expr {
        Expr::Semantic(SemanticOp::Unknown {
            host_module: "l".to_string(),
            host_fn: "1".to_string(),
            args: vec![key, durability],
            reason: UnknownReason::UnsupportedPattern,
        })
    }

    fn run(ir: &mut HighIr) -> PassResult {
        SpecializePass.run(ir)
    }

    /// The storage helper `f1(key, durability)`, non-exported.
    fn helper(id: u32) -> HighFunction {
        func(id, None, 2, vec![storage_get(v(0), v(1))])
    }

    fn params_of(ir: &HighIr, id: u32) -> Vec<ValueId> {
        ir.functions[id as usize].params.clone()
    }

    fn call_at(ir: &HighIr, func: u32, value: ValueId) -> (FuncId, Vec<ValueId>) {
        match &ir.functions[func as usize].bindings.get(value).unwrap().expr {
            Expr::Call { target, args } => (*target, args.clone()),
            other => panic!("expected a call, got {other:?}"),
        }
    }

    // --- pinning (single group: every caller agrees) ---

    #[test]
    fn sole_agreeing_caller_pins_in_place_without_cloning() {
        // main: v0 = key, v1 = 2 (instance), v2 = f1(v0, v1)
        let main = func(
            0,
            Some("main"),
            0,
            vec![i64c(100), i64c(2), call(1, vec![v(0), v(1)])],
        );
        let mut ir = module(vec![main, helper(1)]);
        let result = run(&mut ir);

        assert!(result.changed);
        assert_eq!(ir.functions.len(), 2, "single group needs no copy");
        assert_eq!(result.metrics.get(M_CLONED), None);
        assert_eq!(result.metrics.get(M_PINNED), Some(2));

        // Both parameters are gone, and their bindings are the constants.
        assert!(params_of(&ir, 1).is_empty());
        let helper = &ir.functions[1];
        assert!(matches!(
            helper.bindings.get(v(1)).unwrap().expr,
            Expr::Literal(Literal::I64(2))
        ));
        // A former parameter is neither a param nor a phi, so it has to
        // be scheduled or the region validator rejects the function.
        let entry = helper.blocks.get(BlockId::from_index(0)).unwrap();
        assert!(entry.bindings.contains(&v(0)) && entry.bindings.contains(&v(1)));

        // The call site dropped both arguments to match.
        let (target, args) = call_at(&ir, 0, v(2));
        assert_eq!(target, FuncId::from_index(1));
        assert!(args.is_empty());
        assert!(ir.validate().is_ok(), "specialized IR stays valid");
    }

    #[test]
    fn pinned_parameter_records_why_it_is_a_constant() {
        let main = func(
            0,
            Some("main"),
            0,
            vec![i64c(100), i64c(2), call(1, vec![v(0), v(1)])],
        );
        let mut ir = module(vec![main, helper(1)]);
        run(&mut ir);
        let note = &ir.functions[1]
            .bindings
            .get(v(1))
            .unwrap()
            .latest_provenance()
            .note;
        assert!(note.contains("always"), "{note}");
        assert!(note.contains("specialized from #1"), "{note}");
    }

    // --- de-sharing (the compiler-merged family) ---

    #[test]
    fn disagreeing_callers_each_get_their_own_copy() {
        // Two callers passing different durability constants: the exact
        // shape identical-code folding produces.
        let a = func(
            0,
            Some("a"),
            0,
            vec![i64c(100), i64c(1), call(2, vec![v(0), v(1)])],
        );
        let b = func(
            1,
            Some("b"),
            0,
            vec![i64c(100), i64c(2), call(2, vec![v(0), v(1)])],
        );
        let mut ir = module(vec![a, b, helper(2)]);
        let result = run(&mut ir);

        assert!(result.changed);
        assert_eq!(result.metrics.get(M_CLONED), Some(2));
        assert_eq!(ir.functions.len(), 5, "two copies appended");

        // Each caller now targets its own copy, and the copies differ.
        let (target_a, _) = call_at(&ir, 0, v(2));
        let (target_b, _) = call_at(&ir, 1, v(2));
        assert_ne!(target_a, target_b);
        // Appending never renumbers an existing function.
        assert!(target_a.index() >= 3 && target_b.index() >= 3);

        // Each copy holds the constant its caller passes.
        let dur = |f: FuncId| match &ir.functions[f.index() as usize]
            .bindings
            .get(v(1))
            .unwrap()
            .expr
        {
            Expr::Literal(Literal::I64(n)) => *n,
            other => panic!("expected the pinned constant, got {other:?}"),
        };
        assert_eq!(dur(target_a), 1);
        assert_eq!(dur(target_b), 2);
        assert!(ir.validate().is_ok());
    }

    #[test]
    fn call_sites_carrying_the_same_fact_share_one_copy() {
        // Three call sites, two distinct constants. The source had two
        // functions, not three — cloning per call site would report the
        // same storage fact twice and cost exactly the precision it
        // bought in recall.
        let a = func(
            0,
            Some("a"),
            0,
            vec![i64c(100), i64c(1), call(3, vec![v(0), v(1)])],
        );
        let b = func(
            1,
            Some("b"),
            0,
            vec![i64c(100), i64c(1), call(3, vec![v(0), v(1)])],
        );
        let c = func(
            2,
            Some("c"),
            0,
            vec![i64c(100), i64c(2), call(3, vec![v(0), v(1)])],
        );
        let mut ir = module(vec![a, b, c, helper(3)]);
        let result = run(&mut ir);

        assert_eq!(result.metrics.get(M_CLONED), Some(2), "two facts, two copies");
        let (ta, _) = call_at(&ir, 0, v(2));
        let (tb, _) = call_at(&ir, 1, v(2));
        let (tc, _) = call_at(&ir, 2, v(2));
        assert_eq!(ta, tb, "agreeing call sites share a copy");
        assert_ne!(ta, tc);
    }

    #[test]
    fn constructed_keys_split_even_though_no_constant_reaches_the_call() {
        // timelock's shape: the distinguishing argument is a *built* key,
        // never a literal at the call site. Constant folding cannot reach
        // it; de-sharing can.
        let ctor = func(3, None, 1, vec![storage_get(v(0), v(0))]);
        let a = func(
            0,
            Some("a"),
            0,
            vec![i64c(0), call(3, vec![v(0)]), i64c(2), call(4, vec![v(1), v(2)])],
        );
        let b = func(
            1,
            Some("b"),
            0,
            vec![i64c(1), call(3, vec![v(0)]), i64c(2), call(4, vec![v(1), v(2)])],
        );
        // f2 is unused filler so ids line up with the call targets above.
        let filler = func(2, Some("filler"), 0, vec![i64c(0)]);
        let mut ir = module(vec![a, b, filler, ctor, helper(4)]);
        let result = run(&mut ir);

        assert!(result.changed);
        let (ta, _) = call_at(&ir, 0, v(3));
        let (tb, _) = call_at(&ir, 1, v(3));
        assert_ne!(ta, tb, "different constructed keys must not share a body");
    }

    // --- gates (each guards a wrong-answer hole) ---

    #[test]
    fn exported_callee_is_never_specialized() {
        // An exported function is host-invocable, so its internal call
        // sites are not the complete caller set.
        let a = func(
            0,
            Some("a"),
            0,
            vec![i64c(100), i64c(1), call(2, vec![v(0), v(1)])],
        );
        let b = func(
            1,
            Some("b"),
            0,
            vec![i64c(100), i64c(2), call(2, vec![v(0), v(1)])],
        );
        let mut exported = helper(2);
        exported.name = Some("entrypoint".to_string());
        let mut ir = module(vec![a, b, exported]);

        let result = run(&mut ir);
        assert!(!result.changed);
        assert_eq!(ir.functions.len(), 3);
    }

    #[test]
    fn any_indirect_call_disables_the_pass_module_wide() {
        // A table-called function has invisible callers, so no caller set
        // can be trusted anywhere in the module.
        let mut a = func(
            0,
            Some("a"),
            0,
            vec![i64c(100), i64c(1), call(2, vec![v(0), v(1)])],
        );
        let vid = ValueId::from_index(a.bindings.len() as u32);
        a.bindings.push(Binding::new(
            vid,
            IrType::Unknown(UnknownReason::InsufficientEvidence),
            Expr::IndirectCall {
                table: 0,
                sig: 0,
                callee: v(0),
                args: vec![],
            },
            Provenance::new("test", ProvenanceSource::DataFlow, "seed"),
        ));
        let b = func(
            1,
            Some("b"),
            0,
            vec![i64c(100), i64c(2), call(2, vec![v(0), v(1)])],
        );
        let mut ir = module(vec![a, b, helper(2)]);

        let result = run(&mut ir);
        assert!(!result.changed);
        assert_eq!(ir.functions.len(), 3);
    }

    #[test]
    fn self_recursive_helper_is_left_alone() {
        // f1 calls itself, so one of its "call sites" is its own body.
        let main = func(
            0,
            Some("main"),
            0,
            vec![i64c(100), i64c(2), call(1, vec![v(0), v(1)])],
        );
        let mut recursive = helper(1);
        let vid = ValueId::from_index(recursive.bindings.len() as u32);
        recursive.bindings.push(Binding::new(
            vid,
            IrType::Unknown(UnknownReason::InsufficientEvidence),
            call(1, vec![v(0), v(1)]),
            Provenance::new("test", ProvenanceSource::DataFlow, "seed"),
        ));
        recursive.blocks.get_mut(BlockId::from_index(0)).unwrap().bindings.push(vid);
        let mut ir = module(vec![main, recursive]);

        let result = run(&mut ir);
        assert!(!result.changed);
        assert!(!params_of(&ir, 1).is_empty(), "parameters stay");
    }

    #[test]
    fn a_storage_free_helper_is_not_a_candidate() {
        // Demand-driven: no storage operand dead-ends at a parameter, so
        // there is nothing to unblock and no reason to grow the module.
        let plain = func(1, None, 2, vec![i64c(7)]);
        let a = func(
            0,
            Some("a"),
            0,
            vec![i64c(100), i64c(1), call(1, vec![v(0), v(1)])],
        );
        let mut ir = module(vec![a, plain]);
        let result = run(&mut ir);
        assert!(!result.changed);
        assert_eq!(ir.functions.len(), 2);
    }

    // --- idempotency ---

    #[test]
    fn second_run_reports_no_change() {
        let a = func(
            0,
            Some("a"),
            0,
            vec![i64c(100), i64c(1), call(2, vec![v(0), v(1)])],
        );
        let b = func(
            1,
            Some("b"),
            0,
            vec![i64c(100), i64c(2), call(2, vec![v(0), v(1)])],
        );
        let mut ir = module(vec![a, b, helper(2)]);
        assert!(run(&mut ir).changed);
        let count = ir.functions.len();
        let second = run(&mut ir);
        assert!(!second.changed, "idempotent on rerun");
        assert_eq!(ir.functions.len(), count, "no further growth");
    }

    // --- scheduling ---

    #[test]
    fn a_region_that_reads_before_any_block_declines_to_pin() {
        // `check_region_dominance` requires an `If`'s condition before it
        // walks into any block, so no scheduled binding can dominate it.
        let main = func(
            0,
            Some("main"),
            0,
            vec![i64c(100), i64c(2), call(1, vec![v(0), v(1)])],
        );
        let mut odd = helper(1);
        odd.region = Region::If {
            cond: v(0),
            then_region: Box::new(Region::Basic(BlockId::from_index(0))),
            else_region: None,
        };
        let mut ir = module(vec![main, odd]);
        let result = run(&mut ir);
        assert!(!result.changed, "no schedulable slot, so no pin");
        assert_eq!(params_of(&ir, 1).len(), 2);
    }
}
