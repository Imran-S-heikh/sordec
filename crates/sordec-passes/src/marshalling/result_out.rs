//! `Result<T, E>` returned through an out-parameter, and the helper that
//! turns it into the entrypoint's `Val`.
//!
//! # The shape
//!
//! A `Result<bool, Groth16Error>` is wider than a register, so a helper
//! returning one writes it into its caller's frame: a **tag** byte, then
//! the payload of the variant the path built. Each path writes its own
//! tag, right before it leaves:
//!
//! ```text
//! fn func4(out, vk, proof, inputs) {           fn func5(env, p) -> Val {
//!     if len(inputs) + 1 != len(vk.ic) {           if load8(p+0) != 0 {
//!         store8 out+0 <- 1                            r = <Error Val of code 0>
//!         store  out+4 <- 0     // the code        } else {
//!     } else {                                         r = func34(env, p+1).1
//!         ...                                      }
//!         store8 out+0 <- 0                        return r
//!         store8 out+1 <- pairing_check(..)    }
//!     }
//! }                                            fn func34(env, q) -> (i64, Val) {
//!                                                  return (0, load8(q+0))
//! fn func1(..) -> Val {                        }
//!     func4(fp+64, ..)
//!     return func5(fp+143, fp+64)
//! }
//! ```
//!
//! `func5` is the SDK's `IntoVal` for that `Result`: the tag picks the
//! side, an `Err` becomes its `Error` value (folded to one constant here,
//! since the enum has one variant), an `Ok(b)` becomes the `bool`'s `Val`
//! — `func34`, whose word is the byte itself, because `false` and `true`
//! encode as `0` and `1`. `func1` is the exported wrapper's body, and the
//! entrypoint returns what it returns.
//!
//! Left as it is, `func5`'s merge holds an `Error` on one side and a `Val`
//! on the other, and the entrypoint declared `-> Result<bool,
//! Groth16Error>` returns a `Val`.
//!
//! # The rewrite
//!
//! The writer returns the `Result` it wrote: each path builds its `Ok(..)`
//! or `Err(..)` where it used to write the tag, a merge carries it to the
//! one `return`, and the out-parameter goes. At the call site the writer's
//! call yields the `Result`, and the converter's call becomes that value:
//!
//! ```text
//! fn func4(vk, proof, inputs) -> Result<bool, Groth16Error> {
//!     if .. { r = Err(Groth16Error::MalformedVerifyingKey) }
//!     else  { ..; r = Ok(pairing_check(..)) }
//!     return r
//! }
//! fn func1(..) -> Result<bool, Groth16Error> { let r = func4(..); return r }
//! ```
//!
//! The converter and its `bool` helper lose their last caller and are no
//! longer emitted.
//!
//! # Why it is exact
//!
//! Composition, path by path. The writer's last act on every path that
//! returns is one block of stores — a tag, then a payload — with nothing
//! after it but the merge and the stack epilogue. The converter reads the
//! tag, and its test on the tag, evaluated at the constant each path
//! wrote, picks a side:
//!
//! - **The `Err` side** returns the `Error` value of one variant. The path
//!   wrote exactly one payload, that variant's code — so the path built
//!   `Err(variant)`, and the converter returned its encoding.
//! - **The `Ok` side** returns the word of the byte at the `Ok` slot. The
//!   path wrote exactly one payload there, a `bool` — `0` or `1`, which is
//!   that `bool`'s `Val` — so the path built `Ok(b)`, and the converter
//!   returned `b`'s encoding.
//!
//! So the converter's result is the encoding of the `Result` the writer
//! built, on every path. That value reaches nothing but returns, up a
//! chain of calls, to an entrypoint the spec declares `-> Result<T, E>` —
//! the very `T` and `E` above — and the SDK's wrapper returns
//! `result.into_val(..)` for such an entrypoint. Returning the `Result`
//! itself is that same word.
//!
//! Nothing else is lost. The converter and its helper only read the
//! result's bytes; the writer's other effects all happen before its final
//! stores and are kept; and between the two calls, and after the second,
//! the caller does nothing that touches memory before it returns, so the
//! bytes no longer written are bytes no one reads. The frame is the
//! caller's own shadow-stack frame, which is gone once it returns.
//!
//! # Gates
//!
//! - **The writer**: a helper (no spec, not exported); one parameter used
//!   only as a store address, every store through it in a block that ends
//!   with an explicit edge into one merge; on every path, such a block is
//!   the last thing before the merge, and the merge is followed only by the
//!   stack epilogue and a bare `return`. No path returns, or reaches the
//!   merge, without having written the result; no store through the
//!   parameter sits in a loop that goes round again.
//! - **The converter**: a helper whose body is one `if` on a byte read
//!   from its pointer parameter, each side handing the merge it returns
//!   one value: a resolved contract-error constant, or component `1` of a
//!   call to a straight-line helper that returns `(0, byte read from its
//!   pointer)` and does nothing else. Every other binding pure; the
//!   parameters read by nothing but those two reads.
//! - **The pair at the call site**: the converter's call follows the
//!   writer's in the same block with only pure bindings between, on the
//!   same address in the caller's shadow-stack frame; after it, only pure
//!   bindings and the epilogue, then the `return`.
//! - **Each path the writer takes**: one tag store at the converter's tag
//!   slot, a small constant; an `Err`-side path writes exactly one other
//!   store, the error's code; an `Ok`-side path writes exactly one, a
//!   value typed `bool`, at the slot the converter reads.
//! - **The chain**: the converter's result is read only by returns, every
//!   return of that function returns it, and so on up the callers to an
//!   entrypoint whose spec declares `Result<bool, E>` with `E` the
//!   `#[contracterror]` enum naming the error constant.
//! - **Every call site** of the writer qualifies (its signature changes),
//!   and the module has no indirect call.

use std::collections::{HashMap, HashSet};

use sordec_common::{BlockId, FuncId, IrId, Provenance, ProvenanceSource, TypeId, ValueId};
use sordec_ir::{
    BinaryOp, Binding, Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Literal, MemWidth, Region,
    SemanticOp, TypeRegistry, WasmOpcodeKind,
};

use super::optional_out::{escapes, eval, give_back};
use super::sret::emission_order;
use crate::dataflow::{block_containing, canon_addr, resolve_use, trace_int};
use crate::effects::expr_effects;
use crate::metrics_catalog::{
    MARSHALLING_RESULT_OUT_REWRITTEN as M_REWRITTEN, MARSHALLING_RESULT_OUT_SITES as M_SITES,
    MARSHALLING_RESULT_OUT_SITES_REFUSED as M_SITES_REFUSED,
};
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-result-out";

/// How many helper calls a returned value may climb to reach an entrypoint.
const CHAIN_DEPTH: usize = 4;

/// Rewrites `Result` out-parameter writers to return the `Result`, and the
/// conversion of that `Result` to a `Val` to the `Result` itself.
#[derive(Debug, Default, Clone, Copy)]
pub struct ResultOutParamPass;

impl Pass<HighIr> for ResultOutParamPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let Some(reg) = ir.soroban_facts.as_ref().map(|f| f.types.clone()) else {
            return result;
        };
        if reg.errors.is_empty() {
            return result;
        }
        let indirect = ir
            .functions
            .iter()
            .any(|f| f.bindings.iter().any(|(_, b)| matches!(b.expr, Expr::IndirectCall { .. })));
        if indirect {
            return result;
        }
        let writers: HashMap<FuncId, Writer> = ir
            .functions
            .iter()
            .filter_map(|f| match classify_writer(f) {
                Ok(w) => Some((f.id, w)),
                Err(why) => {
                    if why != NOT_A_CANDIDATE {
                        trace(f, why);
                    }
                    None
                }
            })
            .collect();
        if writers.is_empty() {
            return result;
        }
        let converters: HashMap<FuncId, Converter> = ir
            .functions
            .iter()
            .filter_map(|f| classify_converter(ir, f).map(|c| (f.id, c)))
            .collect();

        // Every scheduled call of every writer, planned or refused.
        let mut plans: HashMap<FuncId, Vec<(FuncId, SitePlan)>> = HashMap::new();
        let mut refused: HashSet<FuncId> = HashSet::new();
        for caller in &ir.functions {
            for id in emission_order(caller) {
                let Some(Expr::Call { target, .. }) = caller.bindings.get(id).map(|b| &b.expr) else {
                    continue;
                };
                let Some(writer) = writers.get(target) else {
                    continue;
                };
                match plan_site(ir, &reg, caller, id, *target, writer, &converters) {
                    Ok(plan) => {
                        trace(caller, &format!("site v{} -> func_{} ok", id.index(), target.index()));
                        result.metrics.increment(M_SITES, 1);
                        plans.entry(*target).or_default().push((caller.id, plan));
                    }
                    Err(why) => {
                        trace(caller, &format!("site v{} -> func_{}: {why}", id.index(), target.index()));
                        result.metrics.increment(M_SITES_REFUSED, 1);
                        refused.insert(*target);
                    }
                }
            }
        }

        let mut targets: Vec<FuncId> = plans.keys().copied().filter(|t| !refused.contains(t)).collect();
        targets.sort_unstable();
        for target in targets {
            let sites = &plans[&target];
            // Every site must read the writer's paths the same way.
            let Some((_, first)) = sites.first() else {
                continue;
            };
            if sites.iter().any(|(_, p)| p.arms != first.arms || p.ty != first.ty) {
                trace_id(target, "call sites disagree on the result");
                continue;
            }
            let writer = &writers[&target];
            let Some(arity) = ir.function(target).map(|f| f.params.len()) else {
                continue;
            };
            for (caller, plan) in sites {
                if let Some(func) = ir.function_mut(*caller) {
                    rewrite_site(func, plan, writer.out);
                }
            }
            // A call no block schedules still names the old signature.
            for func in &mut ir.functions {
                for (_, binding) in func.bindings.iter_mut() {
                    if let Expr::Call { target: t, args } = &mut binding.expr
                        && *t == target
                        && args.len() == arity
                    {
                        args.remove(writer.out);
                    }
                }
            }
            if let Some(func) = ir.function_mut(target) {
                rewrite_writer(func, writer, &first.arms, &first.ty);
            }
            result.metrics.increment(M_REWRITTEN, 1);
            result.changed = true;
        }
        result
    }
}

/// Print a classification line when `SORDEC_OPTION_TRACE` is set — the
/// switch the `Option` passes already read.
#[allow(clippy::print_stderr)]
fn trace(func: &HighFunction, what: &str) {
    trace_id(func.id, what);
}

#[allow(clippy::print_stderr)]
fn trace_id(func: FuncId, what: &str) {
    if std::env::var_os("SORDEC_OPTION_TRACE").is_some() {
        eprintln!("result-out: func_{}: {what}", func.index());
    }
}

/// One slot of a result in memory: a byte offset and a width in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Slot {
    offset: u32,
    bytes: u32,
}

// ---------------------------------------------------------------------
// The writer
// ---------------------------------------------------------------------

/// No store through a parameter at all: an ordinary function.
const NOT_A_CANDIDATE: &str = "no store through a parameter";

/// A helper whose every returning path ends by writing a result through
/// its out-parameter.
struct Writer {
    /// Which parameter is the out-pointer.
    out: usize,
    /// Each block that writes the result: the stores, in order.
    arms: Vec<WriterArm>,
    /// Every store through the out-pointer and every address computed
    /// from it, retired by the rewrite.
    retired: Vec<ValueId>,
}

struct WriterArm {
    block: BlockId,
    /// `(slot, value stored)`, the value resolved through renames.
    stores: Vec<(Slot, ValueId)>,
}

fn classify_writer(func: &HighFunction) -> Result<Writer, &'static str> {
    if func.signature.is_some() || func.name.is_some() {
        return Err(NOT_A_CANDIDATE);
    }
    let order = emission_order(func);
    // The out-pointer: the one parameter stored through.
    let mut out: Option<(usize, ValueId)> = None;
    for &id in &order {
        let Some(Expr::Store { addr, .. }) = func.bindings.get(id).map(|b| &b.expr) else {
            continue;
        };
        let (base, _) = canon_addr(func, *addr);
        if let Some(i) = func.params.iter().position(|p| *p == base) {
            if out.is_some_and(|(j, _)| j != i) {
                return Err("stores through two parameters");
            }
            out = Some((i, base));
        }
    }
    let (out, out_param) = out.ok_or(NOT_A_CANDIDATE)?;
    if escapes(func, &order, out_param) {
        return Err("the out-pointer is used other than as a store address");
    }
    if func.returns.iter().any(|r| !r.is_empty()) {
        return Err("the writer also returns a value");
    }

    // The blocks that write the result, each store with its slot.
    let mut stores: HashMap<BlockId, Vec<(Slot, ValueId)>> = HashMap::new();
    for &id in &order {
        let Some(Expr::Store { addr, value, offset, width }) = func.bindings.get(id).map(|b| &b.expr) else {
            continue;
        };
        let (base, off) = canon_addr(func, *addr);
        if base != out_param {
            continue;
        }
        let block = block_containing(func, id).ok_or("an unscheduled store")?;
        let slot = Slot { offset: off.checked_add(*offset).ok_or("an offset overflows")?, bytes: width.bytes() };
        stores.entry(block).or_default().push((slot, resolve_use(func, *value)));
    }
    // Within a writing block, nothing but more stores and pure bindings
    // once the first store is made: the stores are the block's last act.
    for block in stores.keys() {
        let bindings = &func.blocks.get(*block).ok_or("a missing block")?.bindings;
        let first = bindings
            .iter()
            .position(|id| is_out_store(func, *id, out_param))
            .ok_or("a writing block without its store")?;
        for &id in &bindings[first..] {
            let expr = &func.bindings.get(id).ok_or("a missing binding")?.expr;
            if !is_out_store(func, id, out_param) && !expr_effects(expr).is_pure_total() {
                return Err("the block that writes the result does more after it");
            }
        }
        let mut seen: Vec<Slot> = Vec::new();
        for (slot, _) in &stores[block] {
            if seen.iter().any(|s| overlaps(*s, *slot)) {
                return Err("a block writes one slot twice");
            }
            seen.push(*slot);
        }
    }

    let mut walk = Walk { func, writing: &stores, join: None, arms: Vec::new(), pending: HashMap::new() };
    let tail = walk.region(&func.region, States::CLEAN)?;
    if !tail.is_empty() {
        return Err("control falls off the end of the function");
    }
    let mut arm_blocks: Vec<BlockId> = walk.arms.clone();
    arm_blocks.sort_unstable();
    let mut writing: Vec<BlockId> = stores.keys().copied().collect();
    writing.sort_unstable();
    if arm_blocks != writing {
        return Err("a write of the result not followed by an edge into the merge");
    }
    let arms = walk
        .arms
        .iter()
        .map(|b| WriterArm { block: *b, stores: stores[b].clone() })
        .collect();

    let retired = order
        .iter()
        .copied()
        .filter(|id| match func.bindings.get(*id).map(|b| &b.expr) {
            Some(Expr::Store { addr, .. }) => canon_addr(func, *addr).0 == out_param,
            Some(Expr::Binary { op: BinaryOp::Add, .. }) => *id != out_param && canon_addr(func, *id).0 == out_param,
            _ => false,
        })
        .collect();
    Ok(Writer { out, arms, retired })
}

fn is_out_store(func: &HighFunction, id: ValueId, out_param: ValueId) -> bool {
    matches!(func.bindings.get(id).map(|b| &b.expr),
        Some(Expr::Store { addr, .. }) if canon_addr(func, *addr).0 == out_param)
}

fn overlaps(a: Slot, b: Slot) -> bool {
    a.offset < b.offset + b.bytes && b.offset < a.offset + a.bytes
}

/// What a path may have done when it reaches a point: nothing to the
/// result yet (`clean`), or just written it (`armed`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct States {
    clean: bool,
    armed: bool,
}

impl States {
    const NONE: States = States { clean: false, armed: false };
    const CLEAN: States = States { clean: true, armed: false };
    const ARMED: States = States { clean: false, armed: true };

    fn is_empty(self) -> bool {
        !self.clean && !self.armed
    }

    fn union(self, other: States) -> States {
        States { clean: self.clean || other.clean, armed: self.armed || other.armed }
    }
}

/// Walks the writer's region tree, proving that every path to the return
/// writes the result once, as its last act before the merge.
struct Walk<'f> {
    func: &'f HighFunction,
    /// The blocks that write the result.
    writing: &'f HashMap<BlockId, Vec<(Slot, ValueId)>>,
    /// The merge every writing block's edge goes to.
    join: Option<BlockId>,
    /// The writing blocks met, each followed by its edge into the merge.
    arms: Vec<BlockId>,
    /// States breaking to each scope label.
    pending: HashMap<BlockId, States>,
}

impl Walk<'_> {
    fn region(&mut self, region: &Region, s: States) -> Result<States, &'static str> {
        if s.is_empty() {
            return Ok(States::NONE);
        }
        match region {
            Region::Basic(b) => {
                if self.writing.contains_key(b) {
                    // Arms are recorded where their edge is checked.
                    if !self.arms.contains(b) {
                        return Err("a write of the result not followed by an edge into the merge");
                    }
                    if s.armed {
                        return Err("a path writes the result twice");
                    }
                    return Ok(States::ARMED);
                }
                if Some(*b) == self.join {
                    if s.clean {
                        return Err("a path reaches the merge without writing the result");
                    }
                    self.tail(*b)?;
                    return Ok(s);
                }
                if s.armed && !self.inert(*b) {
                    return Err("code between the result's writes and the merge");
                }
                Ok(s)
            }
            Region::Sequence(items) => {
                let mut flow = s;
                for (i, item) in items.iter().enumerate() {
                    if flow.is_empty() {
                        break;
                    }
                    if let Region::Basic(b) = item
                        && self.writing.contains_key(b)
                    {
                        let target = match items.get(i + 1) {
                            Some(Region::Break { target, .. } | Region::Transfer { target, .. }) => *target,
                            _ => return Err("a write of the result not followed by an edge into the merge"),
                        };
                        if self.join.is_some_and(|j| j != target) {
                            return Err("the result's writes lead to two merges");
                        }
                        self.join = Some(target);
                        if self.arms.contains(b) {
                            return Err("a writing block met twice");
                        }
                        self.arms.push(*b);
                    }
                    flow = self.region(item, flow)?;
                }
                Ok(flow)
            }
            Region::Scope { out, body } => {
                let flow = self.region(body, s)?;
                Ok(flow.union(self.pending.remove(out).unwrap_or(States::NONE)))
            }
            Region::If { then_region, else_region, .. } => {
                let t = self.region(then_region, s)?;
                let e = match else_region {
                    Some(e) => self.region(e, s)?,
                    None => s,
                };
                Ok(t.union(e))
            }
            Region::Switch { arms, default, .. } => {
                let mut flow = self.region(default, s)?;
                for arm in arms {
                    flow = flow.union(self.region(&arm.body, s)?);
                }
                Ok(flow)
            }
            Region::Loop { body, .. } => {
                if s.armed {
                    return Err("a loop after the result is written");
                }
                // Falling off the body goes round again: it must not
                // carry a written result back to the top.
                let back = self.region(body, s)?;
                if back.armed {
                    return Err("a written result goes round a loop");
                }
                Ok(States::NONE)
            }
            Region::Break { target, .. } => {
                self.edge(*target, s)?;
                let p = self.pending.entry(*target).or_insert(States::NONE);
                *p = p.union(s);
                Ok(States::NONE)
            }
            Region::Transfer { target, .. } => {
                self.edge(*target, s)?;
                Ok(s)
            }
            Region::Continue { .. } => {
                if s.armed {
                    return Err("a written result goes round a loop");
                }
                Ok(States::NONE)
            }
            Region::Return { values } => {
                if !values.is_empty() {
                    return Err("a return with a value");
                }
                if s.clean {
                    return Err("a return before the result is written");
                }
                Ok(States::NONE)
            }
            Region::Panic { .. } | Region::Unreachable => Ok(States::NONE),
            Region::Unstructured { .. } => Err("unstructured control flow"),
        }
    }

    /// An edge to `target` carrying states `s`.
    fn edge(&self, target: BlockId, s: States) -> Result<(), &'static str> {
        if s.armed && self.join != Some(target) {
            return Err("a written result goes somewhere other than the merge");
        }
        if s.clean && self.join == Some(target) {
            return Err("a path reaches the merge without writing the result");
        }
        Ok(())
    }

    /// Whether block `b` does nothing at all — no binding with an effect.
    fn inert(&self, b: BlockId) -> bool {
        self.func.blocks.get(b).is_some_and(|block| {
            block.bindings.iter().all(|id| {
                self.func.bindings.get(*id).is_some_and(|binding| expr_effects(&binding.expr).is_pure_total())
            })
        })
    }

    /// The merge block: pure bindings and the shadow-stack epilogue only.
    fn tail(&self, b: BlockId) -> Result<(), &'static str> {
        let block = self.func.blocks.get(b).ok_or("a missing block")?;
        for id in &block.bindings {
            let expr = &self.func.bindings.get(*id).ok_or("a missing binding")?.expr;
            let epilogue = matches!(expr, Expr::Unknown { op_kind: WasmOpcodeKind::GlobalSet, .. });
            if !epilogue && !expr_effects(expr).is_pure_total() {
                return Err("the merge does more than return");
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------
// The converter
// ---------------------------------------------------------------------

/// A helper that reads a `Result` through a pointer and returns its `Val`.
#[derive(Debug, Clone)]
struct Converter {
    /// Which parameter points at the `Result`.
    ptr: usize,
    /// The tag's slot, relative to that pointer.
    tag: Slot,
    tag_load: ValueId,
    /// The test on the tag, and what each side returns.
    cond: ValueId,
    then_side: Side,
    else_side: Side,
}

#[derive(Debug, Clone, PartialEq)]
enum Side {
    /// The `Error` value of one contract-error variant.
    Err { code: u32, enum_name: String, variant: String },
    /// The `Val` of the `bool` byte in this slot.
    OkBool(Slot),
}

fn classify_converter(ir: &HighIr, func: &HighFunction) -> Option<Converter> {
    if func.signature.is_some() || func.name.is_some() {
        return None;
    }
    // `[Basic*, If, Basic*, Return [m]]`.
    let items: &[Region] = match &func.region {
        Region::Sequence(items) => items,
        _ => return None,
    };
    let (Region::Return { values }, body) = items.split_last()? else {
        return None;
    };
    let [merged] = values.as_slice() else {
        return None;
    };
    let mut branch = None;
    for item in body {
        match item {
            Region::Basic(_) => {}
            Region::If { cond, then_region, else_region: Some(else_region) } if branch.is_none() => {
                branch = Some((*cond, &**then_region, &**else_region));
            }
            _ => return None,
        }
    }
    let (cond, then_region, else_region) = branch?;
    if func.returns.iter().any(|r| r.as_slice() != [*merged]) {
        return None;
    }
    let then_value = branch_value(then_region, *merged)?;
    let else_value = branch_value(else_region, *merged)?;

    // Every binding pure, but the one tag read and the `bool` helper's call.
    let order = emission_order(func);
    let mut tag: Option<(ValueId, usize, Slot)> = None;
    let mut calls: Vec<ValueId> = Vec::new();
    for &id in &order {
        let expr = &func.bindings.get(id)?.expr;
        match expr {
            Expr::Load { addr, offset, width, .. } => {
                let (base, off) = canon_addr(func, *addr);
                let ptr = func.params.iter().position(|p| *p == base)?;
                let slot = Slot { offset: off.checked_add(*offset)?, bytes: width.bytes() };
                if tag.replace((id, ptr, slot)).is_some() {
                    return None;
                }
            }
            Expr::Call { .. } => calls.push(id),
            other if expr_effects(other).is_pure_total() => {}
            _ => return None,
        }
    }
    let (tag_load, ptr, tag_slot) = tag?;
    if tag_slot.bytes != MemWidth::W1.bytes() {
        return None;
    }
    let ptr_param = func.params[ptr];

    let side = |value: ValueId| -> Option<Side> {
        match &func.bindings.get(resolve_use(func, value))?.expr {
            Expr::Semantic(SemanticOp::Known(KnownOp::MakeError { code, resolved: Some(ev) })) => Some(Side::Err {
                code: *code,
                enum_name: ev.enum_name.clone(),
                variant: ev.variant.clone(),
            }),
            Expr::Project { value: call, index: 1 } => {
                let call = resolve_use(func, *call);
                if !calls.contains(&call) {
                    return None;
                }
                let Expr::Call { target, args } = &func.bindings.get(call)?.expr else {
                    return None;
                };
                let helper = ir.function(*target)?;
                let (q, at) = bool_byte_helper(helper)?;
                let (base, off) = canon_addr(func, *args.get(q)?);
                if base != ptr_param {
                    return None;
                }
                Some(Side::OkBool(Slot { offset: off.checked_add(at)?, bytes: 1 }))
            }
            _ => None,
        }
    };
    let then_side = side(then_value)?;
    let else_side = side(else_value)?;
    if matches!(then_side, Side::Err { .. }) == matches!(else_side, Side::Err { .. }) {
        return None;
    }

    // The parameters: read only by the tag load and as the helper's
    // arguments, in positions the helper reads only as its pointer or not
    // at all.
    let mut derived: HashSet<ValueId> = func.params.iter().copied().collect();
    for &id in &order {
        if let Some(Expr::Binary { op: BinaryOp::Add, lhs, rhs }) = func.bindings.get(id).map(|b| &b.expr)
            && derived.contains(&resolve_use(func, *lhs))
            && trace_int(func, *rhs).is_some()
        {
            derived.insert(id);
        }
    }
    let is_derived = |v: ValueId| derived.contains(&resolve_use(func, v));
    for &id in &order {
        let expr = &func.bindings.get(id)?.expr;
        let fine = match expr {
            Expr::Load { .. } => id == tag_load,
            Expr::Binary { op: BinaryOp::Add, .. } if derived.contains(&id) => true,
            Expr::Use(v) if is_derived(*v) => false,
            Expr::Call { target, args } => {
                let helper = ir.function(*target)?;
                let (q, _) = bool_byte_helper(helper)?;
                args.iter().enumerate().all(|(j, a)| {
                    if !is_derived(*a) {
                        return true;
                    }
                    if j == q {
                        return canon_addr(func, *a).0 == ptr_param;
                    }
                    helper.params.get(j).is_some_and(|p| !read_in(helper, *p))
                })
            }
            other => {
                let mut reads = false;
                other.for_each_value_use(|u| reads |= is_derived(u));
                !reads
            }
        };
        if !fine {
            return None;
        }
    }
    let mut region_reads = false;
    func.region.for_each_value_use(|u| region_reads |= is_derived(u));
    if region_reads {
        return None;
    }
    Some(Converter { ptr, tag: tag_slot, tag_load, cond, then_side, else_side })
}

/// The value one side of the converter's `if` hands its merge: the side is
/// at most one block, then the edge.
pub(super) fn branch_value(region: &Region, merged: ValueId) -> Option<ValueId> {
    let edge = |r: &Region| match r {
        Region::Transfer { transfer, .. } | Region::Break { transfer, .. } => match transfer.as_slice() {
            [(phi, value)] if *phi == merged => Some(*value),
            _ => None,
        },
        _ => None,
    };
    match region {
        Region::Sequence(items) => {
            let (last, rest) = items.split_last()?;
            rest.iter().all(|r| matches!(r, Region::Basic(_))).then_some(())?;
            edge(last)
        }
        other => edge(other),
    }
}

/// A helper returning `(0, byte read from its pointer)` and doing nothing
/// else: the SDK's `bool` → `Val`, whose word is the byte — `false` and
/// `true` encode as `0` and `1`. Returns the pointer's parameter index and
/// the byte's offset from it.
fn bool_byte_helper(func: &HighFunction) -> Option<(usize, u32)> {
    if func.signature.is_some() || func.name.is_some() {
        return None;
    }
    let order = emission_order(func);
    let mut load: Option<(ValueId, usize, u32)> = None;
    for &id in &order {
        let expr = &func.bindings.get(id)?.expr;
        match expr {
            Expr::Load { addr, offset, width: MemWidth::W1, signed: Some(false) | None, .. } => {
                let (base, off) = canon_addr(func, *addr);
                let q = func.params.iter().position(|p| *p == base)?;
                if load.replace((id, q, off.checked_add(*offset)?)).is_some() {
                    return None;
                }
            }
            other if expr_effects(other).is_pure_total() => {}
            _ => return None,
        }
    }
    let (load, q, at) = load?;
    let [only] = func.returns.as_slice() else {
        return None;
    };
    let [tag, word] = only.as_slice() else {
        return None;
    };
    if trace_int(func, *tag) != Some(0) || resolve_use(func, *word) != load {
        return None;
    }
    // Straight-line: no branch that could trap or take another path.
    let mut ok = true;
    func.region.for_each_node(|node| match node {
        Region::Return { values } => ok &= values == only,
        Region::Basic(_) | Region::Sequence(_) => {}
        _ => ok = false,
    });
    // The pointer is read by the load alone; every other parameter by
    // nothing.
    let pointer = func.params[q];
    for (j, p) in func.params.iter().enumerate() {
        if j == q {
            let mut other = false;
            for &id in &order {
                if id == load {
                    continue;
                }
                if let Some(b) = func.bindings.get(id) {
                    match &b.expr {
                        Expr::Binary { op: BinaryOp::Add, .. } if canon_addr(func, id).0 == pointer => {}
                        e => e.for_each_value_use(|u| other |= resolve_use(func, u) == pointer),
                    }
                }
            }
            ok &= !other;
        } else {
            ok &= !read_in(func, *p);
        }
    }
    ok.then_some((q, at))
}

/// Whether anything `func` runs reads `value`.
fn read_in(func: &HighFunction, value: ValueId) -> bool {
    let mut reads = false;
    for id in emission_order(func) {
        if let Some(b) = func.bindings.get(id) {
            b.expr.for_each_value_use(|u| reads |= resolve_use(func, u) == value);
        }
    }
    func.region.for_each_value_use(|u| reads |= resolve_use(func, u) == value);
    reads
}

// ---------------------------------------------------------------------
// The call site
// ---------------------------------------------------------------------

/// What one arm of the writer built.
#[derive(Debug, Clone, PartialEq)]
enum ArmKind {
    /// `Ok(value)`.
    Ok(ValueId),
    /// `Err(variant)`.
    Err(String),
}

struct SitePlan {
    /// The writer's call.
    call: ValueId,
    /// The converter's call, which becomes the writer's `Result`.
    convert: ValueId,
    /// What each of the writer's arms built, in its arm order.
    arms: Vec<ArmKind>,
    /// The `Result` type.
    ty: KnownType,
}

fn plan_site(
    ir: &HighIr,
    reg: &TypeRegistry,
    caller: &HighFunction,
    call: ValueId,
    target: FuncId,
    writer: &Writer,
    converters: &HashMap<FuncId, Converter>,
) -> Result<SitePlan, &'static str> {
    if caller.id == target {
        return Err("the writer calls itself");
    }
    let Some(Expr::Call { args, .. }) = caller.bindings.get(call).map(|b| &b.expr) else {
        return Err("not a call");
    };
    let (base, at) = canon_addr(caller, *args.get(writer.out).ok_or("no out-pointer argument")?);
    if !is_frame(caller, base) {
        return Err("the result is not in the caller's own frame");
    }
    let block = block_containing(caller, call).ok_or("an unscheduled call")?;
    let bindings = &caller.blocks.get(block).ok_or("a missing block")?.bindings;
    let pos = bindings.iter().position(|b| *b == call).ok_or("an unscheduled call")?;
    let mut read = false;
    caller.region.for_each_value_use(|u| read |= u == call);
    for (_, b) in caller.bindings.iter() {
        b.expr.for_each_value_use(|u| read |= u == call);
    }
    if read {
        return Err("the writer's own result is read");
    }

    // The converter: the next binding with an effect, on the same address.
    let mut rest = bindings[pos + 1..].iter();
    let convert = loop {
        let id = *rest.next().ok_or("no converter after the call")?;
        let expr = &caller.bindings.get(id).ok_or("a missing binding")?.expr;
        if expr_effects(expr).is_pure_total() {
            continue;
        }
        break id;
    };
    let Some(Expr::Call { target: conv_id, args: conv_args }) = caller.bindings.get(convert).map(|b| &b.expr) else {
        return Err("the next effect is not a call");
    };
    let conv = converters.get(conv_id).ok_or("the next call is not a converter")?;
    let conv_func = ir.function(*conv_id).ok_or("a missing converter")?;
    if canon_addr(caller, *conv_args.get(conv.ptr).ok_or("no pointer argument")?) != (base, at) {
        return Err("the converter reads another address");
    }
    // After it: pure bindings and the epilogue, then the return.
    for id in rest {
        let expr = &caller.bindings.get(*id).ok_or("a missing binding")?.expr;
        let epilogue = matches!(expr, Expr::Unknown { op_kind: WasmOpcodeKind::GlobalSet, .. });
        if !epilogue && !expr_effects(expr).is_pure_total() {
            return Err("the caller does more after the conversion");
        }
    }
    if !followed_by_return(&caller.region, block) {
        return Err("the conversion's block is not followed by the return");
    }

    // The chain up to the declared `Result`.
    if !only_returned(caller, convert) {
        return Err("the converted value is used other than returned");
    }
    let ty = declared_result(ir, caller.id, CHAIN_DEPTH).ok_or("no entrypoint declares the result")?;
    let KnownType::Result(ok, err) = &ty else {
        return Err("no entrypoint declares the result");
    };
    if !matches!(&**ok, IrType::Known(KnownType::Bool) | IrType::Inferred(KnownType::Bool)) {
        return Err("the declared result's `Ok` is not a bool");
    }
    let err_id: TypeId = match &**err {
        IrType::Known(KnownType::UserDefined(id)) | IrType::Inferred(KnownType::UserDefined(id)) => *id,
        _ => return Err("the declared result's `Err` is not a contract error enum"),
    };
    let err_enum = reg.errors.iter().find(|e| e.id == err_id).ok_or("the declared `Err` is not an error enum")?;

    // Each arm of the writer, read through the converter.
    let mut arms = Vec::new();
    for arm in &writer.arms {
        let tag_store = arm.stores.iter().filter(|(s, _)| *s == conv.tag).collect::<Vec<_>>();
        let [(_, tag_value)] = tag_store.as_slice() else {
            return Err("an arm without one tag store at the converter's tag");
        };
        let tag = trace_int(caller_of(ir, target)?, *tag_value).ok_or("a tag that is not a constant")?;
        if !(0..128).contains(&tag) {
            return Err("a tag outside the byte both readings agree on");
        }
        let taken = eval(conv_func, conv.cond, &[conv.tag_load], tag, 0).ok_or("the tag test cannot be evaluated")?;
        let side = if taken != 0 { &conv.then_side } else { &conv.else_side };
        let payload: Vec<&(Slot, ValueId)> = arm.stores.iter().filter(|(s, _)| *s != conv.tag).collect();
        let [(slot, value)] = payload.as_slice() else {
            return Err("an arm without exactly one payload store");
        };
        let writer_func = caller_of(ir, target)?;
        match side {
            Side::Err { code, enum_name, variant } => {
                if *enum_name != err_enum.name {
                    return Err("the error constant names another enum");
                }
                if !err_enum.cases.iter().any(|c| c.value == *code && c.name == *variant) {
                    return Err("the error constant is not a variant of the declared enum");
                }
                if trace_int(writer_func, *value) != Some(i128::from(*code)) {
                    return Err("the error arm writes another code");
                }
                if slot.bytes != MemWidth::W4.bytes() {
                    return Err("the error code is not a 32-bit word");
                }
                arms.push(ArmKind::Err(variant.clone()));
            }
            Side::OkBool(ok_slot) => {
                if slot != ok_slot {
                    return Err("the `Ok` arm writes where the converter does not read");
                }
                let typed_bool = |v: ValueId| {
                    matches!(
                        writer_func.bindings.get(v).map(|b| &b.ty),
                        Some(IrType::Known(KnownType::Bool) | IrType::Inferred(KnownType::Bool))
                    )
                };
                if !typed_bool(*value) {
                    return Err("the `Ok` arm writes a value not proven a bool");
                }
                arms.push(ArmKind::Ok(*value));
            }
        }
    }
    Ok(SitePlan { call, convert, arms, ty })
}

fn caller_of(ir: &HighIr, id: FuncId) -> Result<&HighFunction, &'static str> {
    ir.function(id).ok_or("a missing function")
}

/// Whether `base` is the function's own shadow-stack frame:
/// `global.get - size`.
fn is_frame(func: &HighFunction, base: ValueId) -> bool {
    let Some(Expr::Binary { op: BinaryOp::Sub, lhs, rhs }) = func.bindings.get(base).map(|b| &b.expr) else {
        return false;
    };
    matches!(func.bindings.get(resolve_use(func, *lhs)).map(|b| &b.expr), Some(Expr::GlobalGet { .. }))
        && trace_int(func, *rhs).is_some()
}

/// Whether, in the sequence holding `block`, the next item is the return.
fn followed_by_return(region: &Region, block: BlockId) -> bool {
    let mut found = false;
    region.for_each_node(|node| {
        if let Region::Sequence(items) = node {
            for pair in items.windows(2) {
                if matches!(pair[0], Region::Basic(b) if b == block) && matches!(pair[1], Region::Return { .. }) {
                    found = true;
                }
            }
        }
    });
    found
}

/// Whether `value` is read by nothing but returns (through renames), and
/// every return of the function returns it.
fn only_returned(func: &HighFunction, value: ValueId) -> bool {
    let order = emission_order(func);
    let mut aliases: HashSet<ValueId> = HashSet::from([value]);
    let mut grew = true;
    while grew {
        grew = false;
        for &id in &order {
            if let Some(Expr::Use(v)) = func.bindings.get(id).map(|b| &b.expr)
                && aliases.contains(v)
            {
                grew |= aliases.insert(id);
            }
        }
    }
    for &id in &order {
        let Some(b) = func.bindings.get(id) else {
            return false;
        };
        if aliases.contains(&id) {
            continue;
        }
        let mut reads = false;
        b.expr.for_each_value_use(|u| reads |= aliases.contains(&u));
        if reads {
            return false;
        }
    }
    let mut returns = 0usize;
    let mut fine = true;
    func.region.for_each_node(|node| match node {
        Region::Return { values } => {
            returns += 1;
            fine &= matches!(values.as_slice(), [v] if aliases.contains(v));
        }
        Region::If { cond, .. } => fine &= !aliases.contains(cond),
        Region::Switch { index, .. } => fine &= !aliases.contains(index),
        Region::Break { transfer, .. } | Region::Continue { transfer, .. } | Region::Transfer { transfer, .. } => {
            fine &= transfer.iter().all(|(_, src)| !aliases.contains(src));
        }
        _ => {}
    });
    fine && returns > 0 && func.returns.iter().all(|r| matches!(r.as_slice(), [v] if aliases.contains(v)))
}

/// The `Result` an entrypoint's spec declares for what `func` returns:
/// its own, or — for a helper — the one every caller returns its result
/// as, up to `depth` calls.
fn declared_result(ir: &HighIr, func: FuncId, depth: usize) -> Option<KnownType> {
    let f = ir.function(func)?;
    if let Some(sig) = &f.signature {
        let [out] = sig.outputs.as_slice() else {
            return None;
        };
        let ty = crate::type_infer::known_of_type_ref(out)?;
        return matches!(ty, KnownType::Result(..)).then_some(ty);
    }
    if depth == 0 || f.name.is_some() {
        return None;
    }
    let mut found: Option<KnownType> = None;
    for g in &ir.functions {
        for id in emission_order(g) {
            let Some(Expr::Call { target, .. }) = g.bindings.get(id).map(|b| &b.expr) else {
                continue;
            };
            if *target != func {
                continue;
            }
            if g.id == func || !only_returned(g, id) {
                return None;
            }
            let ty = declared_result(ir, g.id, depth - 1)?;
            if found.as_ref().is_some_and(|t| *t != ty) {
                return None;
            }
            found = Some(ty);
        }
    }
    found
}

// ---------------------------------------------------------------------
// The rewrite
// ---------------------------------------------------------------------

fn prov(note: &str) -> Provenance {
    Provenance::new(PASS_NAME, ProvenanceSource::SdkPattern, note.to_string())
}

/// A new binding in `func`, unscheduled; the caller places it.
fn push(func: &mut HighFunction, expr: Expr, ty: IrType, note: &str) -> ValueId {
    let id = ValueId::from_index(func.bindings.len() as u32);
    func.bindings.push(Binding::new(id, ty, expr, prov(note)));
    id
}

fn rewrite(func: &mut HighFunction, id: ValueId, expr: Option<Expr>, ty: IrType, note: &str) {
    if let Some(binding) = func.bindings.get_mut(id) {
        if let Some(expr) = expr {
            binding.expr = expr;
        }
        binding.ty = ty;
        binding.add_provenance(prov(note));
    }
}

/// The writer returns its `Result` instead of writing it.
fn rewrite_writer(func: &mut HighFunction, writer: &Writer, kinds: &[ArmKind], ty: &KnownType) {
    let result_ty = IrType::Inferred(ty.clone());
    let err_ty = match ty {
        KnownType::Result(_, err) => (**err).clone(),
        _ => return,
    };
    let err_ty = match err_ty {
        IrType::Known(k) | IrType::Inferred(k) => IrType::Inferred(k),
        other => other,
    };
    let mut built: Vec<(BlockId, ValueId)> = Vec::new();
    for (arm, kind) in writer.arms.iter().zip(kinds) {
        let mut new = Vec::new();
        let value = match kind {
            ArmKind::Ok(value) => push(
                func,
                Expr::Variant { name: "Ok".to_string(), payload: vec![*value] },
                result_ty.clone(),
                "this path wrote the `Ok` tag and its value through the out-pointer: `Ok(value)`",
            ),
            ArmKind::Err(variant) => {
                let e = push(
                    func,
                    Expr::Variant { name: variant.clone(), payload: Vec::new() },
                    err_ty.clone(),
                    "the error code this path wrote, as its variant",
                );
                new.push(e);
                push(
                    func,
                    Expr::Variant { name: "Err".to_string(), payload: vec![e] },
                    result_ty.clone(),
                    "this path wrote the `Err` tag and an error code through the out-pointer: `Err(variant)`",
                )
            }
        };
        new.push(value);
        if let Some(block) = func.blocks.get_mut(arm.block) {
            block.bindings.extend(new);
        }
        built.push((arm.block, value));
    }
    let merged = push(
        func,
        Expr::Phi { incoming: built.clone() },
        result_ty,
        "the `Result` each path built, merged where the paths meet",
    );
    let by_block: HashMap<BlockId, ValueId> = built.into_iter().collect();
    carry(&mut func.region, &by_block, merged);

    for &id in &writer.retired {
        rewrite(
            func,
            id,
            Some(Expr::Literal(Literal::Unit)),
            IrType::Known(KnownType::Unit),
            "out-parameter write, now the returned `Result`",
        );
    }
    give_back(&mut func.region, merged);
    func.returns = vec![vec![merged]];
    if writer.out < func.params.len() {
        func.params.remove(writer.out);
    }
}

/// Add `(merged, built)` to the edge right after each writing block.
pub(super) fn carry(region: &mut Region, by_block: &HashMap<BlockId, ValueId>, merged: ValueId) {
    match region {
        Region::Sequence(items) => {
            for i in 0..items.len() {
                let built = match &items[i] {
                    Region::Basic(b) => by_block.get(b).copied(),
                    _ => None,
                };
                if let Some(built) = built
                    && let Some(Region::Break { transfer, .. } | Region::Transfer { transfer, .. }) = items.get_mut(i + 1)
                {
                    transfer.push((merged, built));
                }
            }
            for item in items.iter_mut() {
                carry(item, by_block, merged);
            }
        }
        Region::Scope { body, .. } | Region::Loop { body, .. } => carry(body, by_block, merged),
        Region::If { then_region, else_region, .. } => {
            carry(then_region, by_block, merged);
            if let Some(e) = else_region {
                carry(e, by_block, merged);
            }
        }
        Region::Switch { arms, default, .. } => {
            for arm in arms {
                carry(&mut arm.body, by_block, merged);
            }
            carry(default, by_block, merged);
        }
        _ => {}
    }
}

/// The writer's call yields the `Result`; the converter's call is it.
fn rewrite_site(func: &mut HighFunction, plan: &SitePlan, out: usize) {
    let ty = IrType::Inferred(plan.ty.clone());
    if let Some(binding) = func.bindings.get_mut(plan.call)
        && let Expr::Call { args, .. } = &mut binding.expr
        && out < args.len()
    {
        args.remove(out);
    }
    rewrite(func, plan.call, None, ty.clone(), "the call returns the `Result` its frame used to receive");
    rewrite(
        func,
        plan.convert,
        Some(Expr::Use(plan.call)),
        ty,
        "the `Result`'s conversion to the entrypoint's `Val`, which the declared `Result` return performs",
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{module, v};
    use sordec_common::{Arena, UnknownReason};
    use sordec_ir::{
        CompositeType, EnumCase, EnumDef, ErrorVariant, FunctionSignature, HighBlock, PrimitiveType, SorobanFacts,
        TypeRef,
    };

    fn bb(i: u32) -> BlockId {
        BlockId::from_index(i)
    }

    fn untyped() -> IrType {
        IrType::Unknown(UnknownReason::InsufficientEvidence)
    }

    /// A function over `exprs` (ids `0..N`), blocks `blocks[i]` scheduling
    /// those ids, and `region`.
    fn func(id: u32, exprs: Vec<(Expr, IrType)>, blocks: Vec<Vec<u32>>, region: Region, params: Vec<u32>) -> HighFunction {
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        for (expr, ty) in exprs {
            let vid = ValueId::from_index(bindings.len() as u32);
            bindings.push(Binding::new(vid, ty, expr, Provenance::new("seed", ProvenanceSource::DataFlow, "seed")));
        }
        let mut arena: Arena<BlockId, HighBlock> = Arena::new();
        for (i, ids) in blocks.into_iter().enumerate() {
            arena.push(HighBlock { id: bb(i as u32), bindings: ids.into_iter().map(v).collect() });
        }
        let mut returns = Vec::new();
        region.for_each_node(|node| {
            if let Region::Return { values } = node {
                returns.push(values.clone());
            }
        });
        HighFunction {
            id: FuncId::from_index(id),
            name: None,
            signature: None,
            aliases: Vec::new(),
            blocks: arena,
            bindings,
            region,
            params: params.into_iter().map(v).collect(),
            returns,
        }
    }

    fn lit(n: i32) -> (Expr, IrType) {
        (Expr::Literal(Literal::I32(n)), IrType::Known(KnownType::I32))
    }

    fn param() -> (Expr, IrType) {
        (Expr::Phi { incoming: vec![] }, untyped())
    }

    fn store(addr: u32, value: u32, offset: u32, width: MemWidth) -> (Expr, IrType) {
        (Expr::Store { addr: v(addr), value: v(value), offset, width }, untyped())
    }

    fn load8(addr: u32, offset: u32) -> (Expr, IrType) {
        (Expr::Load { addr: v(addr), offset, width: MemWidth::W1, signed: Some(false), ty: untyped() }, untyped())
    }

    /// Writes `Err(code 0)` when `v1` holds, else `Ok(v7)` with the bool at
    /// `ok_at`. `ok_writes` false leaves the `Ok` path writing nothing.
    fn writer(ok_at: u32, ok_writes: bool) -> HighFunction {
        let exprs = vec![
            param(),                                  // v0 out
            (Expr::Phi { incoming: vec![] }, IrType::Known(KnownType::Bool)), // v1 flag
            lit(1),                                   // v2
            store(0, 2, 0, MemWidth::W1),             // v3 tag 1
            lit(0),                                   // v4
            store(0, 4, 4, MemWidth::W4),             // v5 code 0
            (Expr::Unary { op: sordec_ir::UnaryOp::Not, value: v(1) }, IrType::Known(KnownType::Bool)), // v6
            lit(0),                                   // v7
            store(0, 7, 0, MemWidth::W1),             // v8 tag 0
            store(0, 6, ok_at, MemWidth::W1),         // v9 the bool
        ];
        let ok_block = if ok_writes { vec![6, 7, 8, 9] } else { vec![6, 7] };
        let region = Region::Sequence(vec![
            Region::Basic(bb(0)),
            Region::Scope {
                out: bb(3),
                body: Box::new(Region::If {
                    cond: v(1),
                    then_region: Box::new(Region::Sequence(vec![
                        Region::Basic(bb(1)),
                        Region::Transfer { target: bb(3), transfer: vec![] },
                    ])),
                    else_region: Some(Box::new(Region::Sequence(vec![
                        Region::Basic(bb(2)),
                        Region::Break { target: bb(3), transfer: vec![] },
                    ]))),
                }),
            },
            Region::Basic(bb(3)),
            Region::Return { values: vec![] },
        ]);
        func(0, exprs, vec![vec![], vec![2, 3, 4, 5], ok_block, vec![]], region, vec![0, 1])
    }

    /// `(0, load8(q))`.
    fn bool_helper() -> HighFunction {
        let exprs = vec![
            param(),                                                      // v0 env
            param(),                                                      // v1 q
            (Expr::Literal(Literal::I64(0)), IrType::Known(KnownType::I64)), // v2
            load8(1, 0),                                                  // v3
        ];
        let region = Region::Sequence(vec![Region::Basic(bb(0)), Region::Return { values: vec![v(2), v(3)] }]);
        func(1, exprs, vec![vec![2, 3]], region, vec![0, 1])
    }

    /// `if load8(p) { r = Error(code 0) } else { r = func1(env, p+1).1 }`.
    fn converter() -> HighFunction {
        let error = Expr::Semantic(SemanticOp::Known(KnownOp::MakeError {
            code: 0,
            resolved: Some(ErrorVariant { enum_name: "MyError".into(), variant: "Bad".into() }),
        }));
        let exprs = vec![
            param(),                                                                  // v0 env
            param(),                                                                  // v1 p
            (error, IrType::Known(KnownType::Error)),                                 // v2
            load8(1, 0),                                                              // v3 tag
            lit(1),                                                                   // v4
            (Expr::Binary { op: BinaryOp::Add, lhs: v(1), rhs: v(4) }, untyped()),    // v5 p+1
            (Expr::Call { target: FuncId::from_index(1), args: vec![v(0), v(5)] }, untyped()), // v6
            (Expr::Project { value: v(6), index: 1 }, untyped()),                     // v7
            (Expr::Phi { incoming: vec![(bb(0), v(2)), (bb(1), v(7))] }, untyped()),  // v8
        ];
        let region = Region::Sequence(vec![
            Region::Basic(bb(0)),
            Region::If {
                cond: v(3),
                then_region: Box::new(Region::Transfer { target: bb(2), transfer: vec![(v(8), v(2))] }),
                else_region: Some(Box::new(Region::Sequence(vec![
                    Region::Basic(bb(1)),
                    Region::Transfer { target: bb(2), transfer: vec![(v(8), v(7))] },
                ]))),
            },
            Region::Basic(bb(2)),
            Region::Return { values: vec![v(8)] },
        ]);
        func(2, exprs, vec![vec![2, 3], vec![4, 5, 6, 7], vec![]], region, vec![0, 1])
    }

    /// `func0(fp+8, a); return func2(fp+15, fp+8)`, `between` scheduled
    /// between the two calls.
    fn caller(between: Option<(Expr, IrType)>) -> HighFunction {
        let mut exprs = vec![
            param(),                                                               // v0 a
            (Expr::GlobalGet { index: 0 }, IrType::Known(KnownType::I32)),         // v1
            lit(16),                                                               // v2
            (Expr::Binary { op: BinaryOp::Sub, lhs: v(1), rhs: v(2) }, untyped()), // v3 fp
            lit(8),                                                                // v4
            (Expr::Binary { op: BinaryOp::Add, lhs: v(3), rhs: v(4) }, untyped()), // v5 fp+8
            (Expr::Call { target: FuncId::from_index(0), args: vec![v(5), v(0)] }, untyped()), // v6
            lit(15),                                                               // v7
            (Expr::Binary { op: BinaryOp::Add, lhs: v(3), rhs: v(7) }, untyped()), // v8
            (Expr::Binary { op: BinaryOp::Add, lhs: v(3), rhs: v(4) }, untyped()), // v9 fp+8
            (Expr::Call { target: FuncId::from_index(2), args: vec![v(8), v(9)] }, untyped()), // v10
        ];
        let mut block = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        if let Some(extra) = between {
            exprs.push(extra); // v11
            block.push(11);
        }
        block.push(10);
        let region = Region::Sequence(vec![Region::Basic(bb(0)), Region::Return { values: vec![v(10)] }]);
        func(3, exprs, vec![block], region, vec![0])
    }

    /// The entrypoint: `return func3(x)`, declared `-> Result<ok, MyError>`.
    fn entry(ok: PrimitiveType) -> HighFunction {
        let exprs = vec![
            (Expr::Phi { incoming: vec![] }, IrType::Known(KnownType::Bool)),
            (Expr::Call { target: FuncId::from_index(3), args: vec![v(0)] }, untyped()),
        ];
        let region = Region::Sequence(vec![Region::Basic(bb(0)), Region::Return { values: vec![v(1)] }]);
        let mut f = func(4, exprs, vec![vec![1]], region, vec![0]);
        f.name = Some("verify".into());
        f.signature = Some(FunctionSignature {
            name: "verify".into(),
            inputs: vec![],
            outputs: vec![TypeRef::Composite(CompositeType::Result(
                Box::new(TypeRef::Primitive(ok)),
                Box::new(TypeRef::UserDefined(TypeId::from_index(1))),
            ))],
        });
        f
    }

    fn ir(functions: Vec<HighFunction>) -> HighIr {
        let mut ir = module(functions);
        let mut types = TypeRegistry::default();
        types.errors.push(EnumDef {
            id: TypeId::from_index(1),
            name: "MyError".into(),
            cases: vec![EnumCase { name: "Bad".into(), value: 0 }],
        });
        ir.soroban_facts = Some(SorobanFacts {
            functions: Default::default(),
            types,
            contract_meta: Default::default(),
            env_meta: Default::default(),
        });
        ir
    }

    fn standard() -> HighIr {
        ir(vec![writer(1, true), bool_helper(), converter(), caller(None), entry(PrimitiveType::Bool)])
    }

    #[test]
    fn the_writer_returns_the_result_and_the_conversion_is_it() {
        let mut ir = standard();
        let r = ResultOutParamPass.run(&mut ir);
        assert!(r.changed);

        let w = ir.function(FuncId::from_index(0)).unwrap();
        assert_eq!(w.params, vec![v(1)], "the out-pointer is gone");
        let [site] = w.returns.as_slice() else { panic!("{:?}", w.returns) };
        let [merged] = site.as_slice() else { panic!("{site:?}") };
        let Expr::Phi { incoming } = &w.bindings.get(*merged).unwrap().expr else { panic!() };
        assert_eq!(incoming.len(), 2);
        let names: Vec<&str> = incoming
            .iter()
            .map(|(_, val)| match &w.bindings.get(*val).unwrap().expr {
                Expr::Variant { name, .. } => name.as_str(),
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(names, vec!["Err", "Ok"]);
        // `Ok` carries the stored bool; `Err` the variant the code names.
        let ok = incoming[1].1;
        assert!(matches!(&w.bindings.get(ok).unwrap().expr, Expr::Variant { payload, .. } if payload == &vec![v(6)]));
        let Expr::Variant { payload, .. } = &w.bindings.get(incoming[0].1).unwrap().expr else { panic!() };
        assert!(matches!(&w.bindings.get(payload[0]).unwrap().expr, Expr::Variant { name, .. } if name == "Bad"));
        for s in [3, 5, 8, 9] {
            assert!(matches!(w.bindings.get(v(s)).unwrap().expr, Expr::Literal(Literal::Unit)), "v{s} retired");
        }
        // Each edge into the merge carries its arm's `Result`.
        let mut carried = Vec::new();
        w.region.for_each_node(|node| {
            if let Region::Break { transfer, .. } | Region::Transfer { transfer, .. } = node {
                carried.extend(transfer.iter().copied());
            }
        });
        assert_eq!(carried.len(), 2);
        assert!(carried.iter().all(|(phi, _)| phi == merged));
        assert!(matches!(&w.bindings.get(*merged).unwrap().ty, IrType::Inferred(KnownType::Result(..))));

        let c = ir.function(FuncId::from_index(3)).unwrap();
        assert!(matches!(&c.bindings.get(v(6)).unwrap().expr, Expr::Call { args, .. } if args == &vec![v(0)]));
        assert!(matches!(c.bindings.get(v(10)).unwrap().expr, Expr::Use(x) if x == v(6)));
        assert!(matches!(&c.bindings.get(v(10)).unwrap().ty, IrType::Inferred(KnownType::Result(..))));
    }

    fn unchanged(mut ir: HighIr) {
        let before = ir.function(FuncId::from_index(0)).unwrap().params.len();
        let r = ResultOutParamPass.run(&mut ir);
        assert!(!r.changed);
        assert_eq!(ir.function(FuncId::from_index(0)).unwrap().params.len(), before);
        let c = ir.function(FuncId::from_index(3)).unwrap();
        assert!(matches!(c.bindings.get(v(10)).unwrap().expr, Expr::Call { .. }));
    }

    #[test]
    fn an_ok_written_where_the_converter_does_not_read_is_left() {
        unchanged(ir(vec![writer(2, true), bool_helper(), converter(), caller(None), entry(PrimitiveType::Bool)]));
    }

    #[test]
    fn a_path_that_writes_nothing_is_left() {
        unchanged(ir(vec![writer(1, false), bool_helper(), converter(), caller(None), entry(PrimitiveType::Bool)]));
    }

    #[test]
    fn a_result_the_entrypoint_does_not_declare_is_left() {
        unchanged(ir(vec![writer(1, true), bool_helper(), converter(), caller(None), entry(PrimitiveType::U32)]));
    }

    #[test]
    fn a_write_between_the_calls_is_left() {
        let between = store(3, 4, 8, MemWidth::W1);
        unchanged(ir(vec![
            writer(1, true),
            bool_helper(),
            converter(),
            caller(Some(between)),
            entry(PrimitiveType::Bool),
        ]));
    }

    #[test]
    fn a_bool_helper_that_can_trap_is_left() {
        let mut h = bool_helper();
        h.region = Region::Sequence(vec![
            Region::Basic(bb(0)),
            Region::If { cond: v(3), then_region: Box::new(Region::Unreachable), else_region: None },
            Region::Return { values: vec![v(2), v(3)] },
        ]);
        unchanged(ir(vec![writer(1, true), h, converter(), caller(None), entry(PrimitiveType::Bool)]));
    }

    #[test]
    fn a_converted_value_used_other_than_returned_is_left() {
        let mut c = caller(None);
        // `return value == value` reads the conversion before the return.
        c.bindings.push(Binding::new(
            v(11),
            untyped(),
            Expr::Binary { op: BinaryOp::Eq, lhs: v(10), rhs: v(10) },
            Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
        ));
        c.blocks.get_mut(bb(0)).unwrap().bindings.push(v(11));
        c.region = Region::Sequence(vec![Region::Basic(bb(0)), Region::Return { values: vec![v(11)] }]);
        c.returns = vec![vec![v(11)]];
        unchanged(ir(vec![writer(1, true), bool_helper(), converter(), c, entry(PrimitiveType::Bool)]));
    }
}
