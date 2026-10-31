//! `Result<u32, E>` handed back in two registers, `(tag, payload)`, and
//! turned into the entrypoint's `Val` by a wrapper that puts the pair in
//! its own frame for the converter — the register form of
//! [`super::result_out`].
//!
//! # The shape
//!
//! ```text
//! fn func20(..) -> (i32, i32) {            fn func21(t, p, x) -> Val {
//!     if full {                                store4 fp+8  <- t
//!         (t, p) = (1, 5)                      store4 fp+12 <- p
//!     } else {                                 return func56(x, fp+8)
//!         ..                               }
//!         (t, p) = (0, count - 1)
//!     }                                    fn func56(x, q) -> Val {
//!     return t, p                              if load4(q+0) != 0 {
//! }                                                c = load4(q+4)
//!                                                  r = (((c - 1) as u32 as u64) << 32)
//! fn func19(..) -> Val {                               + <Error Val of code 1>
//!     s = func20(..)                           } else {
//!     return func21(s.0, s.1, fp+47)               r = func110(q+4, x).1
//! }                                            }
//!                                              return r
//!                                          }
//! fn func110(q, x) { return (0, func160(x, q).1) }
//! fn func160(x, q) { return (0, U32Val(load4_u(q))) }
//! ```
//!
//! `func20` is a helper returning `Result<u32, E>`: the tag says which
//! side, the payload is the `u32` or the error's code. `func21` and
//! `func56` are the SDK's `IntoVal` for that `Result`: the wrapper puts the
//! pair in its frame, and the converter reads it back — on the error side
//! building the contract error of the code it reads, a value it only knows
//! at run time since one converter serves every path; on the other side
//! the `u32`'s `U32Val`, through two outlined helpers. `func19` is the
//! exported wrapper's body, and the entrypoint returns what it returns.
//!
//! Left as it is, the converter adds an `Error` to an integer, the
//! helper's payload merges an error code with a count, and the entrypoint
//! declared `-> Result<u32, E>` returns a `Val`.
//!
//! # The rewrite
//!
//! The helper returns the `Result`: each edge into its merge builds the
//! `Ok(payload)` or `Err(error)` its pair stood for, a merge carries it to
//! the one `return`, and the pair goes. At the call site the wrapper's
//! call becomes the helper's result:
//!
//! ```text
//! fn func20(..) -> Result<u32, Error> {
//!     if full { r = Err(Error::from_contract_error(5)) }
//!     else    { ..; r = Ok(count - 1) }
//!     return r
//! }
//! fn func19(..) -> Result<u32, Error> { let s = func20(..); return s }
//! ```
//!
//! The wrapper, the converter and its helpers lose their last caller and
//! are no longer emitted.
//!
//! # Why it is exact
//!
//! Composition, edge by edge, as in [`super::result_out`]. The helper's
//! one `return` hands back two merges, and each edge into the block
//! before it hands those merges one pair: so the pairs on the edges are
//! every pair the helper can return.
//!
//! The wrapper stores its tag and payload parameters, as 32-bit words,
//! into its own frame, and its only other act is the converter's call on
//! that address, whose value it returns; its other argument reaches only
//! parameters nothing reads. So the wrapper's result is the converter's,
//! reading back exactly the pair. The converter reads the tag word, and
//! its test on it, evaluated at the constant each edge hands over, picks a
//! side:
//!
//! - **The `Err` side** reads the payload word `c` and returns
//!   `((c + k0) mod 2^32) << 32`, wrapping-added to the `Error` `Val` of
//!   contract code `k`, with `k0 + k ≡ 0 (mod 2^32)`. That `Error` `Val` is
//!   `(k << 32) | 3` — tag `3`, error type `Contract` (zero) in the minor
//!   field, the code in the top 32 bits — so the sum is
//!   `(((c + k0 + k) mod 2^32) << 32) | 3`: the low 32 bits of the shifted
//!   term are zero, so the add never reaches the tag, and the top 32 bits
//!   wrap. That is `(c << 32) | 3`, the `Error` of contract code `c`, for
//!   every `c`. The edge handed over a constant code `c`, so it built the
//!   error of that code. When `E` is the SDK's own `Error`, that is
//!   `Error::from_contract_error(c)` — the same bits, whatever `c` is.
//!   When `E` is a declared `#[contracterror]` enum, it is the variant
//!   whose discriminant is `c`: the SDK converts such a value into exactly
//!   `Error::from_contract_error(discriminant)`. A code that names no
//!   variant has no `E` with that encoding, and is refused.
//! - **The `Ok` side** returns component `1` of a straight-line helper
//!   chain returning `(0, U32Val(word))`, the word the payload slot holds:
//!   the edge's payload, read unsigned. So the edge built `Ok(payload)`,
//!   the payload as a `u32`. The payload is a 32-bit word: the merge it
//!   reaches has one wasm type, and another edge hands that merge an `i32`
//!   constant. It is typed `i32` only because that is the opcode's word —
//!   wasm has no other — and the converter's unsigned read is the evidence
//!   it is a `u32`; the rewrite gives it that type when nothing else reads
//!   it.
//!
//! So the converter's result is the encoding of the `Result` the edge
//! built, on every edge. That value reaches nothing but returns, up a
//! chain of calls, to an entrypoint the spec declares `-> Result<u32, E>`
//! — the very `E` above — and the SDK's wrapper returns
//! `result.into_val(..)` for such an entrypoint. Returning the `Result`
//! itself is that same word.
//!
//! Nothing else is lost. The wrapper writes only its own shadow-stack
//! frame, which is gone once it returns, and restores the stack pointer it
//! lowered; the converter and its helpers only read that frame. The pair's
//! two components are read by nothing that runs but the wrapper's call.
//!
//! # Gates
//!
//! - **The helper**: no spec, not exported; one `return`, of two merges
//!   made at the block right before it, which does nothing but pure
//!   bindings and the stack epilogue; every edge into that block hands
//!   over exactly those two merges, and each merge has one incoming value
//!   per edge, so no path reaches it another way.
//! - **The wrapper**: no spec, not exported, straight-line; its frame is
//!   `global.get - size`, set as the stack pointer first and restored to
//!   `frame + size` last; exactly two stores, both into that frame, both
//!   4-byte words, of two different parameters; one call, to a converter,
//!   whose pointer is an address in that frame; it returns the call.
//!   Everything else pure.
//! - **The converter**: no spec, not exported; one `if` on a 4-byte tag
//!   read through its pointer, each side handing the one `return` a value:
//!   the error-of-code form above on one side, component `1` of a call to
//!   a `(0, U32Val(word))` helper on the other, both reading the same
//!   4-byte payload slot. Every other binding pure; every parameter but
//!   the pointer read by nothing, but as an argument a helper reads by
//!   nothing.
//! - **The slots**: the wrapper stores the tag where the converter reads
//!   the tag and the payload where it reads the payload.
//! - **The call site**: the wrapper's tag and payload arguments are
//!   components `0` and `1` of one call of the helper, whose result is read
//!   by nothing else that runs; the wrapper's result is read only by
//!   returns, up the callers to an entrypoint whose spec declares
//!   `Result<u32, E>`, `E` the SDK's `Error` or a `#[contracterror]` enum.
//! - **Each edge**: a tag constant in `0..128`; on the `Err` side a
//!   constant code in `0..=u32::MAX` (naming a variant of a declared `E`);
//!   on the `Ok` side a payload typed `u32`, or typed only as the 32-bit
//!   word and read by nothing else. Some edge hands the payload merge an
//!   `i32` constant, which makes the merge a 32-bit word.
//! - **Every call site** of the helper qualifies, and all agree on what
//!   each edge built; and those direct calls are all of its callers
//!   ([`CallIndex::caller_set_complete`]): the helper comes to return the
//!   `Result`, so an indirect call a table may route to it would still pass
//!   the old pair. The same holds for every helper the declared `Result` is
//!   climbed through.
//!
//! # A converter handed the pair in registers
//!
//! The converter need not read the pair from memory. When rustc keeps the
//! `Result<u32, E>` in two registers all the way, the converter takes the
//! tag and the payload as two parameters:
//!
//! ```text
//! fn func29(t, p) -> Val {
//!     if t & 1 { return (((p - 1) as u32 as u64) << 32) + <Error Val of code 1> }
//!     return U32Val(p)
//! }
//! ```
//!
//! It is read like a wrapper and its converter in one: the tag test is
//! evaluated on the tag parameter itself, the `Err` side builds the error
//! of the code the payload parameter carries, and the `Ok` side is the
//! payload's `U32Val`. Every binding is pure, so the result is exactly the
//! side the test picks — the same composition as above, one step shorter.
//!
//! Its caller may hand it a writer's two components, as above, or two
//! merges of its own: the entrypoint built the pair itself, path by path,
//! and calls the converter once where the paths meet (`propose`'s
//! `func29(tag, code)` after its `?`s and checks). Then each edge into
//! the call's block builds the `Ok` or `Err` its pair stood for, a new
//! merge there carries it, and the call becomes that merge — the writer's
//! rewrite, in the caller.
//!
//! Why it is exact: the same argument, edge by edge. The two merges are
//! read by nothing but the call, and every edge into its block hands both
//! over, so the pairs on the edges are every pair the converter can see.
//!
//! Gates, beyond the ones above: the converter has no spec and is not
//! exported; one `if` on a test of one parameter — the tag, whose test
//! comes out differently at `0` and `1` — returning each side's value
//! from the branch or through one merge; every binding pure. For the
//! caller's merges: both merges, distinct, read by nothing but the call;
//! every edge into the call's block hands over both, and nothing else
//! hands them anything. An `Ok` payload typed other than the 32-bit word
//! (or `u32`) is refused; one read by nothing but the merge is retyped
//! `u32`, one other things read keeps its word for the typing to settle.
//!
//! # A code read from memory, and the spec's `Error`
//!
//! An edge's code need not be a constant. A helper's own `Result`, passed
//! on by `?`, hands over the code word it wrote into the frame: a 4-byte
//! read. As in [`super::error_code`], that word is the discriminant of the
//! `E` written there — a `#[contracterror]` enum is `#[repr(u32)]` — so
//! the edge built `Err` of it, and the read is typed `E`: in place when
//! the merge is all that reads it, or read again right after itself when
//! something else does too. Only for a declared enum: the SDK's own
//! `Error` is not a `u32` discriminant.
//!
//! And the spec erases a `#[contracterror]` enum to `Error`, which the
//! reconstruction names back when the contract declares exactly one (the
//! emitter's `result_error`). So `E` is then that enum, and a constant
//! code is its variant, as in [`super::error_code`]; spelled as the SDK's
//! `Error` it would not be the type the function returns.

use std::collections::{HashMap, HashSet};

use sordec_common::{BlockId, FuncId, IrId, Provenance, ProvenanceSource, TypeId, ValueId};
use sordec_ir::{
    BinaryOp, Binding, Expr, HighBlock, HighFunction, HighIr, IrType, KnownOp, KnownType, Literal, MemWidth, Region,
    SemanticOp, TypeRegistry, UnaryOp, WasmOpcodeKind,
};

use super::optional_out::eval;
use super::result_out::{branch_value, declared_result, is_frame, only_returned};
use super::sret::emission_order;
use crate::dataflow::{canon_addr, resolve_use, trace_int, trace_literal, CallIndex};
use crate::effects::expr_effects;
use crate::metrics_catalog::{
    MARSHALLING_RESULT_PAIR_REWRITTEN as M_REWRITTEN, MARSHALLING_RESULT_PAIR_SITES as M_SITES,
    MARSHALLING_RESULT_PAIR_SITES_REFUSED as M_SITES_REFUSED,
};
use crate::pass::{Pass, PassResult};
use crate::val_abi;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-result-pair";

/// How many helper calls a returned value may climb to reach an entrypoint.
const CHAIN_DEPTH: usize = 4;

/// How many outlined helpers the converter's `U32Val` may sit behind.
const HELPER_DEPTH: usize = 3;

/// Rewrites helpers returning a `Result` as a `(tag, payload)` pair to
/// return the `Result`, and its conversion to a `Val` to the `Result`.
#[derive(Debug, Default, Clone, Copy)]
pub struct ResultPairPass;

impl Pass<HighIr> for ResultPairPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let Some(reg) = ir.soroban_facts.as_ref().map(|f| f.types.clone()) else {
            return result;
        };
        // Raw and recovered indirect calls alike: a helper a table may reach
        // keeps its signature (the rule the other signature-changing passes
        // share).
        let calls = CallIndex::build(ir);
        let converters: HashMap<FuncId, Converter> = ir
            .functions
            .iter()
            .filter_map(|f| classify_converter(ir, f).map(|c| (f.id, c)))
            .collect();
        let registers: HashMap<FuncId, RegisterConverter> =
            ir.functions.iter().filter_map(|f| classify_register_converter(f).map(|c| (f.id, c))).collect();
        let wrappers: HashMap<FuncId, Wrapper> = ir
            .functions
            .iter()
            .filter_map(|f| classify_wrapper(f, &converters).map(|w| (f.id, w)))
            .collect();
        if wrappers.is_empty() && registers.is_empty() {
            return result;
        }
        let readers = Readers { wrappers: &wrappers, converters: &converters, registers: &registers };
        let writers: HashMap<FuncId, Writer> = ir
            .functions
            .iter()
            .filter(|f| calls.caller_set_complete(f.id))
            .filter_map(|f| match classify_writer(f) {
                Ok(w) => Some((f.id, w)),
                Err(why) => {
                    if why != NOT_A_CANDIDATE {
                        trace(f.id, why);
                    }
                    None
                }
            })
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
                match plan_site(ir, &reg, &calls, caller, id, *target, writer, &readers) {
                    Ok(plan) => {
                        trace(caller.id, &format!("site v{} -> func_{} ok", id.index(), target.index()));
                        result.metrics.increment(M_SITES, 1);
                        plans.entry(*target).or_default().push((caller.id, plan));
                    }
                    Err(why) => {
                        trace(caller.id, &format!("site v{} -> func_{}: {why}", id.index(), target.index()));
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
            let Some((_, first)) = sites.first() else {
                continue;
            };
            if sites.iter().any(|(_, p)| p.arms != first.arms || p.ty != first.ty) {
                trace(target, "call sites disagree on the result");
                continue;
            }
            let writer = &writers[&target];
            let Some(func) = ir.function(target) else {
                continue;
            };
            if let Err(why) = retypable(func, writer, &first.arms) {
                trace(target, why);
                continue;
            }
            let (arms, ty) = (first.arms.clone(), first.ty.clone());
            for (caller, plan) in sites {
                if let Some(func) = ir.function_mut(*caller) {
                    rewrite_site(func, plan);
                }
            }
            if let Some(func) = ir.function_mut(target) {
                rewrite_writer(func, writer, &arms, &ty);
            }
            result.metrics.increment(M_REWRITTEN, 1);
            result.changed = true;
        }

        // A register converter handed two merges of its own caller.
        if registers.is_empty() {
            return result;
        }
        let mut inline: Vec<(FuncId, InlinePlan)> = Vec::new();
        for caller in &ir.functions {
            for id in emission_order(caller) {
                let Some(Expr::Call { target, .. }) = caller.bindings.get(id).map(|b| &b.expr) else {
                    continue;
                };
                let Some(rc) = registers.get(target) else {
                    continue;
                };
                let Some(conv) = ir.function(*target) else {
                    continue;
                };
                match plan_inline(ir, &reg, &calls, caller, id, conv, rc) {
                    Ok(plan) => {
                        trace(caller.id, &format!("inline site v{} -> func_{} ok", id.index(), target.index()));
                        result.metrics.increment(M_SITES, 1);
                        inline.push((caller.id, plan));
                    }
                    Err(why) => {
                        trace(caller.id, &format!("inline site v{} -> func_{}: {why}", id.index(), target.index()));
                    }
                }
            }
        }
        for (caller, plan) in inline {
            if let Some(func) = ir.function_mut(caller) {
                rewrite_inline(func, &plan);
                result.metrics.increment(M_REWRITTEN, 1);
                result.changed = true;
            }
        }
        result
    }
}

/// Print a classification line when `SORDEC_OPTION_TRACE` is set — the
/// switch the `Option` passes already read.
#[allow(clippy::print_stderr)]
fn trace(func: FuncId, what: &str) {
    if std::env::var_os("SORDEC_OPTION_TRACE").is_some() {
        eprintln!("result-pair: func_{}: {what}", func.index());
    }
}

/// One slot of the pair in memory: a byte offset and a width in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Slot {
    offset: u32,
    bytes: u32,
}

const WORD: u32 = 4;

fn expr_of(func: &HighFunction, id: ValueId) -> Option<&Expr> {
    func.bindings.get(resolve_use(func, id)).map(|b| &b.expr)
}

/// A 4-byte load through `ptr` (plus constant offsets): its slot.
fn word_load(func: &HighFunction, load: ValueId, ptr: ValueId) -> Option<Slot> {
    let Expr::Load { addr, offset, width: MemWidth::W4, .. } = expr_of(func, load)? else {
        return None;
    };
    let (base, off) = canon_addr(func, *addr);
    (base == ptr).then_some(Slot { offset: off.checked_add(*offset)?, bytes: WORD })
}

// ---------------------------------------------------------------------
// The `U32Val` helpers
// ---------------------------------------------------------------------

/// A straight-line helper returning `(0, U32Val(word))`, the word read
/// from its pointer — directly, or as component `1` of a call to another
/// such helper. Every parameter but the pointer is read by nothing, but
/// as an argument the inner helper reads by nothing. Returns the
/// pointer's parameter index and the word's offset from it.
fn u32_word_helper(ir: &HighIr, func: &HighFunction, depth: usize) -> Option<(usize, u32)> {
    if func.signature.is_some() || func.name.is_some() {
        return None;
    }
    let [only] = func.returns.as_slice() else {
        return None;
    };
    let [zero, word] = only.as_slice() else {
        return None;
    };
    if trace_int(func, *zero) != Some(0) {
        return None;
    }
    let mut straight = true;
    func.region.for_each_node(|node| match node {
        Region::Return { values } => straight &= values == only,
        Region::Basic(_) | Region::Sequence(_) => {}
        _ => straight = false,
    });
    if !straight {
        return None;
    }
    // The word: a `U32Val` encode of a 4-byte load, or the inner helper's;
    // and the pointer, the base of that load's address or of the argument
    // in the inner helper's pointer position.
    let (reader, q, ptr_value, at) = match expr_of(func, *word)? {
        Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty: KnownType::U32, value })) => {
            let load = resolve_use(func, *value);
            let Expr::Load { addr, offset, width: MemWidth::W4, .. } = &func.bindings.get(load)?.expr else {
                return None;
            };
            let (base, off) = canon_addr(func, *addr);
            (load, None, base, off.checked_add(*offset)?)
        }
        Expr::Project { value: call, index: 1 } => {
            let call = resolve_use(func, *call);
            let Expr::Call { target, args } = &func.bindings.get(call)?.expr else {
                return None;
            };
            if depth == 0 || *target == func.id {
                return None;
            }
            let (q, inner_at) = u32_word_helper(ir, ir.function(*target)?, depth - 1)?;
            let (base, off) = canon_addr(func, *args.get(q)?);
            (call, Some(q), base, off.checked_add(inner_at)?)
        }
        _ => return None,
    };
    let ptr = func.params.iter().position(|p| *p == ptr_value)?;
    let order = emission_order(func);
    // The one read (or call) has an effect; everything else is pure.
    for &id in &order {
        let expr = &func.bindings.get(id)?.expr;
        if id != reader && !expr_effects(expr).is_pure_total() {
            return None;
        }
    }
    params_read_only_through(func, &order, ptr_value, reader, q).then_some((ptr, at))
}

/// Whether, in `func`, the pointer `ptr` is read only by address
/// arithmetic feeding `reader` — a load's address, or the argument in
/// the callee's pointer position `q` — and every other parameter is read
/// by nothing but `reader`'s call, in positions the callee reads by
/// nothing (any position but `q`, for the helpers above).
fn params_read_only_through(
    func: &HighFunction,
    order: &[ValueId],
    ptr: ValueId,
    reader: ValueId,
    q: Option<usize>,
) -> bool {
    let derived = derived_from(func, order, ptr);
    let others: HashSet<ValueId> = func.params.iter().copied().filter(|p| *p != ptr).collect();
    let watched = |v: ValueId| {
        let v = resolve_use(func, v);
        derived.contains(&v) || others.contains(&v)
    };
    for &id in order {
        let Some(binding) = func.bindings.get(id) else {
            return false;
        };
        let fine = match &binding.expr {
            Expr::Binary { op: BinaryOp::Add, .. } if derived.contains(&id) => true,
            Expr::Use(v) if watched(*v) => false,
            Expr::Load { addr, .. } if id == reader && q.is_none() => canon_addr(func, *addr).0 == ptr,
            Expr::Call { args, .. } if id == reader => q.is_some_and(|q| pointer_only_at(func, args, &derived, ptr, q)),
            other => {
                let mut reads = false;
                other.for_each_value_use(|u| reads |= watched(u));
                !reads
            }
        };
        if !fine {
            return false;
        }
    }
    let mut region_reads = false;
    func.region.for_each_value_use(|u| region_reads |= watched(u));
    !region_reads
}

/// `ptr` and every address computed from it by adding a constant.
fn derived_from(func: &HighFunction, order: &[ValueId], ptr: ValueId) -> HashSet<ValueId> {
    let mut derived: HashSet<ValueId> = HashSet::from([ptr]);
    for &id in order {
        if let Some(Expr::Binary { op: BinaryOp::Add, lhs, rhs }) = func.bindings.get(id).map(|b| &b.expr)
            && derived.contains(&resolve_use(func, *lhs))
            && trace_int(func, *rhs).is_some()
        {
            derived.insert(id);
        }
    }
    derived
}

/// A call's arguments: an address through `ptr` in position `q`, and no
/// address through it anywhere else. Every other argument lands in a
/// position the callee reads by nothing (the helpers' gate), so what it
/// is does not matter.
fn pointer_only_at(func: &HighFunction, args: &[ValueId], derived: &HashSet<ValueId>, ptr: ValueId, q: usize) -> bool {
    args.iter().enumerate().all(|(j, a)| {
        let a = resolve_use(func, *a);
        if j == q { canon_addr(func, a).0 == ptr } else { !derived.contains(&a) }
    })
}

// ---------------------------------------------------------------------
// The converter
// ---------------------------------------------------------------------

/// A helper that reads a `(tag, payload)` pair through a pointer and
/// returns the `Result`'s `Val`.
#[derive(Debug, Clone)]
struct Converter {
    /// Which parameter points at the pair.
    ptr: usize,
    tag: Slot,
    payload: Slot,
    tag_load: ValueId,
    /// The test on the tag; `err_when` is the outcome that picks `Err`.
    cond: ValueId,
    err_when: bool,
}

fn classify_converter(ir: &HighIr, func: &HighFunction) -> Option<Converter> {
    if func.signature.is_some() || func.name.is_some() {
        return None;
    }
    // `[Basic*, If, Basic*, Return [m]]`.
    let Region::Sequence(items) = &func.region else {
        return None;
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

    let ptr = *func.params.iter().find(|p| {
        // The pointer: the base every load goes through.
        emission_order(func).iter().any(|id| {
            matches!(func.bindings.get(*id).map(|b| &b.expr), Some(Expr::Load { addr, .. })
                if canon_addr(func, *addr).0 == **p)
        })
    })?;
    let err = |v: ValueId| error_of_code(func, v, ptr);
    let ok = |v: ValueId| u32_of_word(ir, func, v, ptr);
    let (err_when, err_load, err_slot, ok_call, ok_slot) = match (err(then_value), ok(else_value)) {
        (Some((l, s)), Some((c, o))) => (true, l, s, c, o),
        _ => {
            let (l, s) = err(else_value)?;
            let (c, o) = ok(then_value)?;
            (false, l, s, c, o)
        }
    };
    if err_slot != ok_slot {
        return None;
    }

    // Exactly two loads, the tag's and the error side's payload; the one
    // helper call; everything else pure.
    let order = emission_order(func);
    let mut loads = Vec::new();
    for &id in &order {
        let expr = &func.bindings.get(id)?.expr;
        match expr {
            Expr::Load { .. } => loads.push(id),
            Expr::Call { .. } if id == ok_call => {}
            other if expr_effects(other).is_pure_total() => {}
            _ => return None,
        }
    }
    let [a, b] = loads.as_slice() else {
        return None;
    };
    let tag_load = if *a == err_load { *b } else if *b == err_load { *a } else { return None };
    let tag = word_load(func, tag_load, ptr)?;
    if tag == err_slot {
        return None;
    }
    // The pointer read only through those reads and the helper's pointer
    // argument; every other parameter only where the helper reads nothing.
    if !converter_params_ok(ir, func, &order, ptr, &[tag_load, err_load], ok_call) {
        return None;
    }
    Some(Converter {
        ptr: func.params.iter().position(|p| *p == ptr)?,
        tag,
        payload: err_slot,
        tag_load,
        cond,
        err_when,
    })
}

/// `((c + k0) as u32 as u64) << 32` wrapping-added to the `Error` `Val` of
/// contract code `k`, with `k0 + k ≡ 0 (mod 2^32)` and `c` a 4-byte load
/// through `ptr`: the `Error` of contract code `c`. Returns the load and
/// its slot.
fn error_of_code(func: &HighFunction, value: ValueId, ptr: ValueId) -> Option<(ValueId, Slot)> {
    let Expr::Binary { op: BinaryOp::Add, lhs, rhs } = expr_of(func, value)? else {
        return None;
    };
    [(*lhs, *rhs), (*rhs, *lhs)].into_iter().find_map(|(shifted, constant)| {
        let k = contract_error_code(func, constant)?;
        let Expr::Binary { op: BinaryOp::Shl, lhs: widened, rhs: by } = expr_of(func, shifted)? else {
            return None;
        };
        if trace_int(func, *by) != Some(32) {
            return None;
        }
        let Expr::Unary { op: UnaryOp::ExtendU32, value: word } = expr_of(func, *widened)? else {
            return None;
        };
        let word = resolve_use(func, *word);
        let (load, k0) = match &func.bindings.get(word)?.expr {
            Expr::Load { .. } => (word, 0i128),
            Expr::Binary { op: BinaryOp::Add, lhs, rhs } => [(*lhs, *rhs), (*rhs, *lhs)]
                .into_iter()
                .find_map(|(l, c)| {
                    let l = resolve_use(func, l);
                    matches!(func.bindings.get(l)?.expr, Expr::Load { .. }).then_some(())?;
                    Some((l, trace_int(func, c)?))
                })?,
            _ => return None,
        };
        if (k0 + i128::from(k)).rem_euclid(1 << 32) != 0 {
            return None;
        }
        Some((load, word_load(func, load, ptr)?))
    })
}

/// The contract code of a constant `Error` `Val`: a recognised one, or a
/// literal whose bits decode as a `Contract`-type error.
fn contract_error_code(func: &HighFunction, value: ValueId) -> Option<u32> {
    match expr_of(func, value)? {
        Expr::Semantic(SemanticOp::Known(KnownOp::MakeError { code, .. })) => Some(*code),
        Expr::Literal(Literal::I64(n)) => val_abi::decode_contract_error(*n as u64),
        Expr::Literal(Literal::U64(n)) => val_abi::decode_contract_error(*n),
        _ => None,
    }
}

/// Component `1` of a call to a `(0, U32Val(word))` helper whose pointer
/// argument is an address through `ptr`: the call and the word's slot.
fn u32_of_word(ir: &HighIr, func: &HighFunction, value: ValueId, ptr: ValueId) -> Option<(ValueId, Slot)> {
    let Expr::Project { value: call, index: 1 } = expr_of(func, value)? else {
        return None;
    };
    let call = resolve_use(func, *call);
    let Expr::Call { target, args } = &func.bindings.get(call)?.expr else {
        return None;
    };
    if *target == func.id {
        return None;
    }
    let (q, at) = u32_word_helper(ir, ir.function(*target)?, HELPER_DEPTH)?;
    let (base, off) = canon_addr(func, *args.get(q)?);
    (base == ptr).then_some((call, Slot { offset: off.checked_add(at)?, bytes: WORD }))
}

/// The converter's parameters: the pointer read only by `loads` and the
/// helper's pointer argument (through address arithmetic), every other
/// parameter read by nothing but the helper's call, in a position the
/// helper reads by nothing.
fn converter_params_ok(
    ir: &HighIr,
    func: &HighFunction,
    order: &[ValueId],
    ptr: ValueId,
    loads: &[ValueId],
    call: ValueId,
) -> bool {
    let Some(Expr::Call { target, .. }) = func.bindings.get(call).map(|b| &b.expr) else {
        return false;
    };
    let Some((q, _)) = ir.function(*target).and_then(|h| u32_word_helper(ir, h, HELPER_DEPTH)) else {
        return false;
    };
    let derived = derived_from(func, order, ptr);
    let others: HashSet<ValueId> = func.params.iter().copied().filter(|p| *p != ptr).collect();
    let watched = |v: ValueId| {
        let v = resolve_use(func, v);
        derived.contains(&v) || others.contains(&v)
    };
    for &id in order {
        let Some(binding) = func.bindings.get(id) else {
            return false;
        };
        let fine = match &binding.expr {
            Expr::Binary { op: BinaryOp::Add, .. } if derived.contains(&id) => true,
            Expr::Use(v) if watched(*v) => false,
            Expr::Load { addr, .. } if loads.contains(&id) => canon_addr(func, *addr).0 == ptr,
            Expr::Call { args, .. } if id == call => pointer_only_at(func, args, &derived, ptr, q),
            other => {
                let mut reads = false;
                other.for_each_value_use(|u| reads |= watched(u));
                !reads
            }
        };
        if !fine {
            return false;
        }
    }
    let mut region_reads = false;
    func.region.for_each_value_use(|u| region_reads |= watched(u));
    !region_reads
}

// ---------------------------------------------------------------------
// The wrapper
// ---------------------------------------------------------------------

/// A helper that stores a `(tag, payload)` pair into its own frame and
/// returns the converter's result on it.
#[derive(Debug, Clone)]
struct Wrapper {
    /// Which parameter is the tag, which the payload.
    tag: usize,
    payload: usize,
    /// The converter it calls.
    converter: FuncId,
}

fn classify_wrapper(func: &HighFunction, converters: &HashMap<FuncId, Converter>) -> Option<Wrapper> {
    if func.signature.is_some() || func.name.is_some() {
        return None;
    }
    let [only] = func.returns.as_slice() else {
        return None;
    };
    let [returned] = only.as_slice() else {
        return None;
    };
    let mut straight = true;
    func.region.for_each_node(|node| match node {
        Region::Return { values } => straight &= values == only,
        Region::Basic(_) | Region::Sequence(_) => {}
        _ => straight = false,
    });
    if !straight {
        return None;
    }
    let call = resolve_use(func, *returned);
    let Expr::Call { target, args } = &func.bindings.get(call)?.expr else {
        return None;
    };
    let conv = converters.get(target)?;
    let (frame, at) = canon_addr(func, *args.get(conv.ptr)?);
    if !is_frame(func, frame) {
        return None;
    }
    let Expr::Binary { op: BinaryOp::Sub, lhs: sp, rhs: size } = &func.bindings.get(frame)?.expr else {
        return None;
    };
    let sp = resolve_use(func, *sp);
    let size = u32::try_from(trace_int(func, *size)?).ok()?;

    // The bindings: the stack pointer read once, set to the frame first
    // and back to `frame + size` last, two word stores into the frame, the
    // one call, everything else pure.
    let order = emission_order(func);
    let mut sets = Vec::new();
    let mut stores = Vec::new();
    for &id in &order {
        let expr = &func.bindings.get(id)?.expr;
        match expr {
            Expr::GlobalGet { .. } if id == sp => {}
            Expr::Unknown { op_kind: WasmOpcodeKind::GlobalSet, args, .. } => {
                let [value] = args.as_slice() else {
                    return None;
                };
                sets.push(canon_addr(func, *value));
            }
            Expr::Store { addr, value, offset, width: MemWidth::W4 } => {
                let (base, off) = canon_addr(func, *addr);
                if base != frame {
                    return None;
                }
                stores.push((off.checked_add(*offset)?, resolve_use(func, *value)));
            }
            Expr::Call { .. } if id == call => {}
            other if expr_effects(other).is_pure_total() => {}
            _ => return None,
        }
    }
    if sets != [(frame, 0), (frame, size)] {
        return None;
    }
    let stored = |slot: Slot| -> Option<usize> {
        let at = at.checked_add(slot.offset)?;
        if at.checked_add(slot.bytes)? > size {
            return None;
        }
        let [(_, value)] = stores.iter().filter(|(o, _)| *o == at).copied().collect::<Vec<_>>()[..] else {
            return None;
        };
        func.params.iter().position(|p| *p == value)
    };
    let tag = stored(conv.tag)?;
    let payload = stored(conv.payload)?;
    if stores.len() != 2 || tag == payload {
        return None;
    }
    // The frame reaches nothing but the stores, the stack pointer's
    // restore and the converter's pointer.
    let mut leaks = false;
    for &id in &order {
        match &func.bindings.get(id)?.expr {
            Expr::Store { value, .. } => leaks |= canon_addr(func, *value).0 == frame,
            Expr::Call { args, .. } => {
                for (j, a) in args.iter().enumerate() {
                    leaks |= j != conv.ptr && canon_addr(func, *a).0 == frame;
                }
            }
            _ => {}
        }
    }
    (!leaks).then_some(Wrapper { tag, payload, converter: *target })
}

// ---------------------------------------------------------------------
// The register converter
// ---------------------------------------------------------------------

/// A helper that takes a `Result<u32, E>`'s `(tag, payload)` in two of its
/// parameters, not through memory, and returns the `Result`'s `Val`: the
/// same converter as [`Converter`], with no wrapper storing the pair first.
#[derive(Debug, Clone)]
struct RegisterConverter {
    /// Which parameter is the tag, which the payload.
    tag: usize,
    payload: usize,
    /// The test on the tag; `err_when` is the outcome that picks `Err`.
    cond: ValueId,
    err_when: bool,
}

/// `func` as a register converter: one `if` on a test of the tag parameter,
/// each side returning one value — the error-of-code form of the payload
/// parameter on one, its `U32Val` on the other — either from inside the
/// branch (`if t { return err } return ok`) or through a merge; every
/// binding pure.
fn classify_register_converter(func: &HighFunction) -> Option<RegisterConverter> {
    if func.signature.is_some() || func.name.is_some() {
        return None;
    }
    let Region::Sequence(items) = &func.region else {
        return None;
    };
    let (Region::Return { values }, body) = items.split_last()? else {
        return None;
    };
    let [last] = values.as_slice() else {
        return None;
    };
    let mut branch = None;
    for item in body {
        match item {
            Region::Basic(_) => {}
            Region::If { cond, then_region, else_region } if branch.is_none() => {
                branch = Some((*cond, &**then_region, else_region.as_deref()));
            }
            _ => return None,
        }
    }
    let (cond, then_region, else_region) = branch?;
    let early_return = |r: &Region| -> Option<ValueId> {
        let Region::Sequence(items) = r else {
            return None;
        };
        let (Region::Return { values }, rest) = items.split_last()? else {
            return None;
        };
        rest.iter().all(|r| matches!(r, Region::Basic(_))).then_some(())?;
        match values.as_slice() {
            [one] => Some(*one),
            _ => None,
        }
    };
    let (then_value, else_value) = match else_region {
        None => (early_return(then_region)?, *last),
        Some(e) => (branch_value(then_region, *last)?, branch_value(e, *last)?),
    };
    if func.returns.iter().any(|r| r.len() != 1) {
        return None;
    }
    // Everything pure: the result is then exactly the side the test picks.
    for id in emission_order(func) {
        if !expr_effects(&func.bindings.get(id)?.expr).is_pure_total() {
            return None;
        }
    }
    let param_at = |v: ValueId| func.params.iter().position(|p| *p == resolve_use(func, v));
    let ok_of = |v: ValueId| -> Option<usize> {
        match expr_of(func, v)? {
            Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty: KnownType::U32, value })) => param_at(*value),
            _ => None,
        }
    };
    let err_of = |v: ValueId| error_of_param(func, v).and_then(param_at);
    let (err_when, payload) = match (err_of(then_value), ok_of(else_value)) {
        (Some(e), Some(o)) if e == o => (true, e),
        _ => match (err_of(else_value), ok_of(then_value)) {
            (Some(e), Some(o)) if e == o => (false, e),
            _ => return None,
        },
    };
    // The tag: the one other parameter the test reads, at either value.
    let tag = (0..func.params.len()).find(|&t| {
        let at = |x: i128| eval(func, cond, &[func.params[t]], x, 0);
        t != payload && matches!((at(0), at(1)), (Some(a), Some(b)) if a != b)
    })?;
    Some(RegisterConverter { tag, payload, cond, err_when })
}

/// `((p + k0) as u32 as u64) << 32` wrapping-added to the `Error` `Val` of
/// contract code `k`, `k0 + k ≡ 0 (mod 2^32)`: the `Error` of contract code
/// `p` ([`error_of_code`], the code handed over rather than read). Returns
/// `p`.
fn error_of_param(func: &HighFunction, value: ValueId) -> Option<ValueId> {
    let Expr::Binary { op: BinaryOp::Add, lhs, rhs } = expr_of(func, value)? else {
        return None;
    };
    [(*lhs, *rhs), (*rhs, *lhs)].into_iter().find_map(|(shifted, constant)| {
        let k = contract_error_code(func, constant)?;
        let Expr::Binary { op: BinaryOp::Shl, lhs: widened, rhs: by } = expr_of(func, shifted)? else {
            return None;
        };
        if trace_int(func, *by) != Some(32) {
            return None;
        }
        let Expr::Unary { op: UnaryOp::ExtendU32, value: word } = expr_of(func, *widened)? else {
            return None;
        };
        let word = resolve_use(func, *word);
        let (code, k0) = match &func.bindings.get(word)?.expr {
            Expr::Binary { op: BinaryOp::Add, lhs, rhs } => [(*lhs, *rhs), (*rhs, *lhs)]
                .into_iter()
                .find_map(|(c, n)| Some((resolve_use(func, c), trace_int(func, n)?)))?,
            _ => (word, 0i128),
        };
        if !func.params.contains(&code) || (k0 + i128::from(k)).rem_euclid(1 << 32) != 0 {
            return None;
        }
        Some(code)
    })
}

/// The two converters a `(tag, payload)` pair can be handed to.
struct Readers<'a> {
    wrappers: &'a HashMap<FuncId, Wrapper>,
    converters: &'a HashMap<FuncId, Converter>,
    registers: &'a HashMap<FuncId, RegisterConverter>,
}

/// How a call reads the pair it is handed: the argument positions of the
/// tag and the payload, and the test that picks the side, in the function
/// that runs it, with `tag_input` standing for the tag.
struct Reading<'a> {
    tag: usize,
    payload: usize,
    func: &'a HighFunction,
    cond: ValueId,
    tag_input: ValueId,
    err_when: bool,
}

impl Readers<'_> {
    fn reading<'f>(&self, ir: &'f HighIr, target: FuncId) -> Option<Reading<'f>> {
        if let Some(w) = self.wrappers.get(&target) {
            let conv = self.converters.get(&w.converter)?;
            return Some(Reading {
                tag: w.tag,
                payload: w.payload,
                func: ir.function(w.converter)?,
                cond: conv.cond,
                tag_input: conv.tag_load,
                err_when: conv.err_when,
            });
        }
        let rc = self.registers.get(&target)?;
        let func = ir.function(target)?;
        Some(Reading {
            tag: rc.tag,
            payload: rc.payload,
            func,
            cond: rc.cond,
            tag_input: *func.params.get(rc.tag)?,
            err_when: rc.err_when,
        })
    }
}

// ---------------------------------------------------------------------
// The writer
// ---------------------------------------------------------------------

/// Not a two-value return at all: an ordinary function.
const NOT_A_CANDIDATE: &str = "no two-value return";

/// A helper whose one `return` hands back two merges.
struct Writer {
    /// The two merges, in return order.
    merges: [ValueId; 2],
    /// The block they are made at, right before the `return`.
    join: BlockId,
    /// Every edge into it: the two values it hands the merges.
    edges: Vec<[ValueId; 2]>,
}

fn classify_writer(func: &HighFunction) -> Result<Writer, &'static str> {
    if func.signature.is_some() || func.name.is_some() {
        return Err(NOT_A_CANDIDATE);
    }
    let [only] = func.returns.as_slice() else {
        return Err(NOT_A_CANDIDATE);
    };
    let [a, b] = only.as_slice() else {
        return Err(NOT_A_CANDIDATE);
    };
    let merges = [*a, *b];
    let Region::Sequence(items) = &func.region else {
        return Err("not a sequence ending in the return");
    };
    let [.., Region::Basic(join), Region::Return { values }] = items.as_slice() else {
        return Err("the return does not follow the merge block");
    };
    if values != only {
        return Err("the return does not follow the merge block");
    }
    let mut returns = 0;
    func.region.for_each_node(|node| returns += usize::from(matches!(node, Region::Return { .. })));
    if returns != 1 {
        return Err("more than one return");
    }
    for m in merges {
        if !matches!(func.bindings.get(m).map(|b| &b.expr), Some(Expr::Phi { .. })) {
            return Err("a returned value is not a merge");
        }
    }
    if merges[0] == merges[1] {
        return Err("one merge returned twice");
    }
    // The merge block: pure bindings and the stack epilogue only.
    let block = func.blocks.get(*join).ok_or("a missing block")?;
    for id in &block.bindings {
        let expr = &func.bindings.get(*id).ok_or("a missing binding")?.expr;
        let epilogue = matches!(expr, Expr::Unknown { op_kind: WasmOpcodeKind::GlobalSet, .. });
        if !epilogue && !expr_effects(expr).is_pure_total() {
            return Err("the merge does more than return");
        }
    }
    // Every edge into the merge block hands over exactly the two merges.
    let mut edges = Vec::new();
    let mut bad = false;
    func.region.for_each_node(|node| match node {
        Region::Break { target, transfer } | Region::Transfer { target, transfer } if target == join => {
            let get = |m: ValueId| transfer.iter().find(|(phi, _)| *phi == m).map(|(_, v)| *v);
            match (get(merges[0]), get(merges[1])) {
                (Some(x), Some(y)) if transfer.len() == 2 => edges.push([x, y]),
                _ => bad = true,
            }
        }
        Region::Continue { target, .. } if target == join => bad = true,
        _ => {}
    });
    if bad || edges.is_empty() {
        return Err("an edge into the merge does not hand over the pair");
    }
    for m in merges {
        let Some(Expr::Phi { incoming }) = func.bindings.get(m).map(|b| &b.expr) else {
            return Err("a returned value is not a merge");
        };
        if incoming.len() != edges.len() {
            return Err("a merge reached other than by the edges");
        }
    }
    Ok(Writer { merges, join: *join, edges })
}

// ---------------------------------------------------------------------
// The call site
// ---------------------------------------------------------------------

/// How an edge's `Err` is spelled.
#[derive(Debug, Clone, PartialEq)]
enum ErrSpelling {
    /// The SDK's `Error` of this contract code.
    Code(u32),
    /// This variant of the declared enum (this one).
    Variant(String, TypeId),
    /// The declared enum (this one) whose discriminant this 4-byte read
    /// holds.
    Read(ValueId, TypeId),
}

/// What one edge of the writer built.
#[derive(Debug, Clone, PartialEq)]
enum ArmKind {
    /// `Ok(payload)`.
    Ok(ValueId),
    /// `Err(..)`.
    Err(ErrSpelling),
}

struct SitePlan {
    /// The writer's call.
    call: ValueId,
    /// The wrapper's call, which becomes the writer's `Result`.
    wrap: ValueId,
    /// The components of the writer's result the wrapper took.
    projects: Vec<ValueId>,
    /// What each edge built, by the pair it hands over.
    arms: Vec<([ValueId; 2], ArmKind)>,
    /// The `Result` type.
    ty: KnownType,
}

#[allow(clippy::too_many_arguments)]
fn plan_site(
    ir: &HighIr,
    reg: &TypeRegistry,
    calls: &CallIndex,
    caller: &HighFunction,
    call: ValueId,
    target: FuncId,
    writer: &Writer,
    readers: &Readers<'_>,
) -> Result<SitePlan, &'static str> {
    if caller.id == target {
        return Err("the writer calls itself");
    }
    let order = emission_order(caller);
    // Everything that runs and reads the call: its two components, and
    // what reads those: one wrapper call, nothing else.
    let mut projects: Vec<(ValueId, u32)> = Vec::new();
    for &id in &order {
        let Some(b) = caller.bindings.get(id) else {
            return Err("a missing binding");
        };
        let mut reads = false;
        b.expr.for_each_value_use(|u| reads |= resolve_use(caller, u) == call);
        if !reads {
            continue;
        }
        match &b.expr {
            Expr::Project { value, index } if resolve_use(caller, *value) == call && *index < 2 => {
                projects.push((id, *index));
            }
            _ => return Err("the writer's result is read other than by its components"),
        }
    }
    let mut region_reads = false;
    caller.region.for_each_value_use(|u| {
        let u = resolve_use(caller, u);
        region_reads |= u == call || projects.iter().any(|(p, _)| *p == u);
    });
    if region_reads {
        return Err("the writer's result is read by the control flow");
    }
    let component = |v: ValueId| projects.iter().find(|(p, _)| *p == resolve_use(caller, v)).map(|(_, i)| *i);
    let mut wraps = Vec::new();
    for &id in &order {
        let Some(b) = caller.bindings.get(id) else {
            return Err("a missing binding");
        };
        if projects.iter().any(|(p, _)| *p == id) {
            continue;
        }
        let mut reads = false;
        b.expr.for_each_value_use(|u| reads |= component(u).is_some());
        if reads {
            wraps.push(id);
        }
    }
    let [wrap] = wraps.as_slice() else {
        return Err("the components are not read by one wrapper call");
    };
    let Some(Expr::Call { target: wrap_target, args }) = caller.bindings.get(*wrap).map(|b| &b.expr) else {
        return Err("the components are read other than by a call");
    };
    let reading = readers.reading(ir, *wrap_target).ok_or("the components go to something other than a wrapper")?;
    let tag_index = args.get(reading.tag).and_then(|a| component(*a)).ok_or("the tag is not a component")?;
    let payload_index = args.get(reading.payload).and_then(|a| component(*a)).ok_or("the payload is not a component")?;
    if tag_index == payload_index {
        return Err("the tag and the payload are one component");
    }
    for (j, a) in args.iter().enumerate() {
        if j != reading.tag && j != reading.payload && component(*a).is_some() {
            return Err("a component passed in another position");
        }
    }

    // The chain up to the declared `Result`.
    if !only_returned(caller, *wrap) {
        return Err("the converted value is used other than returned");
    }
    let (ty, err_enum) = declared_u32_result(ir, reg, calls, caller.id)?;

    // Each edge, read through the converter.
    let writer_func = ir.function(target).ok_or("a missing function")?;
    let (tag_at, payload_at) = (tag_index as usize, payload_index as usize);
    let pairs: Vec<(ValueId, ValueId)> = writer.edges.iter().map(|p| (p[tag_at], p[payload_at])).collect();
    let kinds = edge_arms(writer_func, &pairs, &reading, err_enum)?;
    let arms = writer.edges.iter().copied().zip(kinds).collect();
    Ok(SitePlan { call, wrap: *wrap, projects: projects.iter().map(|(p, _)| *p).collect(), arms, ty })
}

/// The `Result<u32, E>` an entrypoint declares for what `func` returns, and
/// `E`'s declaration when it is a `#[contracterror]` enum (`None` for the
/// SDK's own `Error`).
fn declared_u32_result<'r>(
    ir: &HighIr,
    reg: &'r TypeRegistry,
    calls: &CallIndex,
    func: FuncId,
) -> Result<(KnownType, Option<&'r sordec_ir::EnumDef>), &'static str> {
    let ty = declared_result(ir, calls, func, CHAIN_DEPTH).ok_or("no entrypoint declares the result")?;
    let KnownType::Result(ok, err) = &ty else {
        return Err("no entrypoint declares the result");
    };
    if !matches!(&**ok, IrType::Known(KnownType::U32) | IrType::Inferred(KnownType::U32)) {
        return Err("the declared result's `Ok` is not a u32");
    }
    let err_enum = match &**err {
        // The spec erases a `#[contracterror]` enum to `Error`, and the
        // reconstruction names it back when the contract declares exactly
        // one (the emitter's `result_error`): then `E` is that enum, and an
        // edge's code is its variant.
        IrType::Known(KnownType::Error) | IrType::Inferred(KnownType::Error) => sole_error_enum(reg),
        IrType::Known(KnownType::UserDefined(id)) | IrType::Inferred(KnownType::UserDefined(id)) => {
            let id: TypeId = *id;
            Some(reg.errors.iter().find(|e| e.id == id).ok_or("the declared `Err` is not an error enum")?)
        }
        _ => return Err("the declared result's `Err` is not an error"),
    };
    Ok((ty, err_enum))
}

/// What each `(tag, payload)` pair `func` hands over builds, read through
/// the converter: its tag test, evaluated at the pair's constant tag,
/// picks the side.
fn edge_arms(
    func: &HighFunction,
    pairs: &[(ValueId, ValueId)],
    reading: &Reading<'_>,
    err_enum: Option<&sordec_ir::EnumDef>,
) -> Result<Vec<ArmKind>, &'static str> {
    let mut arms = Vec::new();
    for &(tag, payload) in pairs {
        let tag = trace_int(func, tag).ok_or("a tag that is not a constant")?;
        if !(0..128).contains(&tag) {
            return Err("a tag outside the small constants");
        }
        let taken =
            eval(reading.func, reading.cond, &[reading.tag_input], tag, 0).ok_or("the tag test cannot be evaluated")?;
        let kind = if (taken != 0) == reading.err_when {
            match trace_int(func, payload) {
                Some(code) => {
                    let code = u32::try_from(code).map_err(|_| "an error code outside u32")?;
                    match err_enum {
                        None => ArmKind::Err(ErrSpelling::Code(code)),
                        Some(e) => {
                            let case = e.cases.iter().find(|c| c.value == code).ok_or("an error code no variant names")?;
                            ArmKind::Err(ErrSpelling::Variant(case.name.clone(), e.id))
                        }
                    }
                }
                // A code read from memory is the discriminant of the `E`
                // written there ([`super::error_code`]): the read, as `E`.
                None if is_word_load(func, payload) => {
                    let e = err_enum.ok_or("a code read from memory with no declared error enum")?;
                    ArmKind::Err(ErrSpelling::Read(resolve_use(func, payload), e.id))
                }
                None => return Err("an error code that is not a constant"),
            }
        } else {
            ArmKind::Ok(payload)
        };
        arms.push(kind);
    }
    // The payload merge is a 32-bit word: a wasm merge has one type, and
    // some edge hands it an `i32` constant or a 4-byte read.
    let word = pairs.iter().any(|(_, p)| {
        matches!(trace_literal(func, *p), Some(Literal::I32(_) | Literal::U32(_))) || is_word_load(func, *p)
    });
    if !word {
        return Err("no edge shows the payload is a 32-bit word");
    }
    Ok(arms)
}

/// The contract's one `#[contracterror]` enum, which the reconstruction
/// names a spec's `Error` back to.
fn sole_error_enum(reg: &TypeRegistry) -> Option<&sordec_ir::EnumDef> {
    let name = reg.sole_error_enum()?;
    reg.errors.iter().find(|e| e.name == name)
}

/// A 4-byte read of memory.
fn is_word_load(func: &HighFunction, value: ValueId) -> bool {
    matches!(expr_of(func, value), Some(Expr::Load { width: MemWidth::W4, .. }))
}

/// Whether every `Ok` payload can be the `u32` the converter read: typed
/// `u32` already, or typed only as the 32-bit word and read by nothing but
/// the edges into the merge.
fn retypable(func: &HighFunction, writer: &Writer, arms: &[([ValueId; 2], ArmKind)]) -> Result<(), &'static str> {
    for (_, kind) in arms {
        let ArmKind::Ok(payload) = kind else {
            continue;
        };
        match func.bindings.get(*payload).map(|b| &b.ty) {
            Some(IrType::Known(KnownType::U32) | IrType::Inferred(KnownType::U32)) => continue,
            Some(IrType::Inferred(KnownType::I32) | IrType::Unknown(_)) => {}
            _ => return Err("an `Ok` payload typed other than the 32-bit word"),
        }
        if func.params.contains(payload) {
            return Err("an `Ok` payload that is a parameter");
        }
        let mut reads = 0usize;
        for id in emission_order(func) {
            if let Some(b) = func.bindings.get(id) {
                b.expr.for_each_value_use(|u| reads += usize::from(u == *payload));
            }
        }
        let mut region_reads = 0usize;
        func.region.for_each_value_use(|u| region_reads += usize::from(u == *payload));
        let on_edges = writer.edges.iter().filter(|e| e.contains(payload)).count();
        if reads != 0 || region_reads != on_edges {
            return Err("an `Ok` payload read by something other than the merge");
        }
    }
    Ok(())
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

/// The writer returns its `Result` instead of the pair.
fn rewrite_writer(func: &mut HighFunction, writer: &Writer, arms: &[([ValueId; 2], ArmKind)], ty: &KnownType) {
    let result_ty = IrType::Inferred(ty.clone());
    let KnownType::Result(_, err) = ty else {
        return;
    };
    let err_ty = match (**err).clone() {
        IrType::Known(k) | IrType::Inferred(k) => IrType::Inferred(k),
        other => other,
    };
    for (_, kind) in arms {
        if let ArmKind::Ok(payload) = kind
            && !matches!(
                func.bindings.get(*payload).map(|b| &b.ty),
                Some(IrType::Known(KnownType::U32) | IrType::Inferred(KnownType::U32))
            )
        {
            rewrite(
                func,
                *payload,
                None,
                IrType::Inferred(KnownType::U32),
                "the `Ok` payload the converter read back unsigned and encoded as a `U32Val`",
            );
        }
    }
    let merged = push(
        func,
        Expr::Phi { incoming: Vec::new() },
        result_ty.clone(),
        "the `Result` each edge built, merged where the edges meet",
    );
    let reads = read_codes(func, writer, arms);
    let region = std::mem::replace(&mut func.region, Region::Unreachable);
    let mut ctx =
        Place { func, writer, arms, merged, result_ty: &result_ty, err_ty: &err_ty, reads: &reads, incoming: Vec::new() };
    let region = ctx.region(region);
    let incoming = std::mem::take(&mut ctx.incoming);
    func.region = region;
    if let Some(b) = func.bindings.get_mut(merged) {
        b.expr = Expr::Phi { incoming };
    }
    for m in writer.merges {
        rewrite(
            func,
            m,
            Some(Expr::Literal(Literal::Unit)),
            IrType::Known(KnownType::Unit),
            "one half of the returned pair, now the returned `Result`",
        );
    }
    replace_return(&mut func.region, &writer.merges, merged);
    func.returns = vec![vec![merged]];
}

/// Puts each edge's `Result` on the edge.
struct Place<'a> {
    func: &'a mut HighFunction,
    writer: &'a Writer,
    arms: &'a [([ValueId; 2], ArmKind)],
    merged: ValueId,
    result_ty: &'a IrType,
    err_ty: &'a IrType,
    /// Each code read from memory, and the read of it as the error.
    reads: &'a HashMap<ValueId, ValueId>,
    incoming: Vec<(BlockId, ValueId)>,
}

impl Place<'_> {
    fn is_edge(&self, region: &Region) -> bool {
        matches!(region, Region::Break { target, .. } | Region::Transfer { target, .. } if *target == self.writer.join)
    }

    /// The edge's `Result`, built into `block`; the edge then hands it over.
    fn build(&mut self, block: BlockId, edge: &mut Region) {
        let (Region::Break { transfer, .. } | Region::Transfer { transfer, .. }) = edge else {
            return;
        };
        let get = |m: ValueId| transfer.iter().find(|(phi, _)| *phi == m).map(|(_, v)| *v);
        let (Some(a), Some(b)) = (get(self.writer.merges[0]), get(self.writer.merges[1])) else {
            return;
        };
        let Some((_, kind)) = self.arms.iter().find(|(p, _)| *p == [a, b]) else {
            return;
        };
        let mut new = Vec::new();
        let value = match kind.clone() {
            ArmKind::Ok(payload) => push(
                self.func,
                Expr::Variant { name: "Ok".to_string(), payload: vec![payload] },
                self.result_ty.clone(),
                "this edge handed over the `Ok` tag and a u32: `Ok(value)`",
            ),
            ArmKind::Err(spelling) => {
                let mut ty = self.err_ty.clone();
                let (expr, note) = match spelling {
                    ErrSpelling::Read(load, _) => {
                        let Some(e) = self.reads.get(&load).copied() else {
                            return;
                        };
                        let value = push(
                            self.func,
                            Expr::Variant { name: "Err".to_string(), payload: vec![e] },
                            self.result_ty.clone(),
                            "this edge handed over the `Err` tag and a code read from memory: `Err(error)`",
                        );
                        if let Some(b) = self.func.blocks.get_mut(block) {
                            b.bindings.push(value);
                        }
                        transfer.retain(|(phi, _)| !self.writer.merges.contains(phi));
                        transfer.push((self.merged, value));
                        self.incoming.push((block, value));
                        return;
                    }
                    ErrSpelling::Code(code) => (
                        Expr::Semantic(SemanticOp::Known(KnownOp::MakeError { code, resolved: None })),
                        "the error code this edge handed over, as the SDK's `Error` of that contract code",
                    ),
                    ErrSpelling::Variant(name, id) => {
                        ty = IrType::Inferred(KnownType::UserDefined(id));
                        (
                            Expr::Variant { name, payload: Vec::new() },
                            "the error code this edge handed over, as the declared variant with that discriminant",
                        )
                    }
                };
                let e = push(self.func, expr, ty, note);
                new.push(e);
                push(
                    self.func,
                    Expr::Variant { name: "Err".to_string(), payload: vec![e] },
                    self.result_ty.clone(),
                    "this edge handed over the `Err` tag and an error code: `Err(error)`",
                )
            }
        };
        new.push(value);
        if let Some(b) = self.func.blocks.get_mut(block) {
            b.bindings.extend(new);
        }
        transfer.retain(|(phi, _)| !self.writer.merges.contains(phi));
        transfer.push((self.merged, value));
        self.incoming.push((block, value));
    }

    /// A fresh block, for an edge that has none of its own before it.
    fn fresh_block(&mut self) -> BlockId {
        let id = BlockId::from_index(self.func.blocks.len() as u32);
        self.func.blocks.push(HighBlock { id, bindings: Vec::new() });
        id
    }

    /// `[Basic(fresh), edge]` with the edge's `Result` built in `fresh`.
    fn wrapped(&mut self, mut edge: Region) -> Region {
        let block = self.fresh_block();
        self.build(block, &mut edge);
        Region::Sequence(vec![Region::Basic(block), edge])
    }

    fn boxed(&mut self, region: Region) -> Box<Region> {
        Box::new(self.region(region))
    }

    fn region(&mut self, region: Region) -> Region {
        if self.is_edge(&region) {
            return self.wrapped(region);
        }
        match region {
            Region::Sequence(items) => {
                let mut out: Vec<Region> = Vec::with_capacity(items.len());
                for item in items {
                    if self.is_edge(&item) {
                        let mut edge = item;
                        if let Some(Region::Basic(block)) = out.last() {
                            let block = *block;
                            self.build(block, &mut edge);
                            out.push(edge);
                        } else {
                            out.push(self.wrapped(edge));
                        }
                    } else {
                        out.push(self.region(item));
                    }
                }
                Region::Sequence(out)
            }
            Region::Scope { out, body } => Region::Scope { out, body: self.boxed(*body) },
            Region::Loop { header, body, kind } => Region::Loop { header, body: self.boxed(*body), kind },
            Region::If { cond, then_region, else_region } => Region::If {
                cond,
                then_region: self.boxed(*then_region),
                else_region: else_region.map(|e| self.boxed(*e)),
            },
            Region::Switch { index, arms, default, dispatch } => Region::Switch {
                index,
                arms: arms
                    .into_iter()
                    .map(|mut arm| {
                        arm.body = self.region(arm.body);
                        arm
                    })
                    .collect(),
                default: self.boxed(*default),
                dispatch,
            },
            other => other,
        }
    }
}

/// The `return` of the pair returns the `Result`.
fn replace_return(region: &mut Region, merges: &[ValueId; 2], merged: ValueId) {
    match region {
        Region::Return { values } if values.as_slice() == merges => *values = vec![merged],
        Region::Sequence(items) => items.iter_mut().for_each(|r| replace_return(r, merges, merged)),
        Region::Scope { body, .. } | Region::Loop { body, .. } => replace_return(body, merges, merged),
        Region::If { then_region, else_region, .. } => {
            replace_return(then_region, merges, merged);
            if let Some(e) = else_region {
                replace_return(e, merges, merged);
            }
        }
        Region::Switch { arms, default, .. } => {
            arms.iter_mut().for_each(|a| replace_return(&mut a.body, merges, merged));
            replace_return(default, merges, merged);
        }
        _ => {}
    }
}

/// The writer's call yields the `Result`; the wrapper's call is it.
fn rewrite_site(func: &mut HighFunction, plan: &SitePlan) {
    let ty = IrType::Inferred(plan.ty.clone());
    rewrite(func, plan.call, None, ty.clone(), "the call returns the `Result` its two registers stood for");
    for p in &plan.projects {
        rewrite(
            func,
            *p,
            Some(Expr::Literal(Literal::Unit)),
            IrType::Known(KnownType::Unit),
            "one half of the pair, now part of the returned `Result`",
        );
    }
    rewrite(
        func,
        plan.wrap,
        Some(Expr::Use(plan.call)),
        ty,
        "the `Result`'s conversion to the entrypoint's `Val`, which the declared `Result` return performs",
    );
}

/// Each code an edge reads from memory, as the declared error: the read
/// itself, retyped, when the merge edges are all that read it (they go);
/// otherwise a second read of the same address right after it, nothing
/// between, typed as the error, while every other reader keeps the first.
fn read_codes(func: &mut HighFunction, writer: &Writer, arms: &[([ValueId; 2], ArmKind)]) -> HashMap<ValueId, ValueId> {
    let mut out = HashMap::new();
    for (_, kind) in arms {
        let ArmKind::Err(ErrSpelling::Read(load, e)) = kind else {
            continue;
        };
        let err_ty = &IrType::Inferred(KnownType::UserDefined(*e));
        if out.contains_key(load) {
            continue;
        }
        // The pair's own merges go with the rewrite, so they do not count.
        let mut reads = 0usize;
        for (id, b) in func.bindings.iter() {
            if !writer.merges.contains(&id) {
                b.expr.for_each_value_use(|u| reads += usize::from(u == *load));
            }
        }
        let mut region_reads = 0usize;
        func.region.for_each_value_use(|u| region_reads += usize::from(u == *load));
        let on_edges = writer.edges.iter().map(|e| e.iter().filter(|x| *x == load).count()).sum::<usize>();
        if reads == 0 && region_reads == on_edges {
            rewrite(func, *load, None, err_ty.clone(), "the code read back, as the declared error it is the discriminant of");
            out.insert(*load, *load);
            continue;
        }
        let Some(expr) = func.bindings.get(*load).map(|b| b.expr.clone()) else {
            continue;
        };
        let Some(block) = crate::dataflow::block_containing(func, *load) else {
            continue;
        };
        let again = push(func, expr, err_ty.clone(), "the code read again, as the declared error it is the discriminant of");
        if let Some(b) = func.blocks.get_mut(block)
            && let Some(at) = b.bindings.iter().position(|x| x == load)
        {
            b.bindings.insert(at + 1, again);
        }
        out.insert(*load, again);
    }
    out
}

// ---------------------------------------------------------------------
// The pair as two merges of the converter's own caller
// ---------------------------------------------------------------------

/// A register converter called on two merges of its caller.
struct InlinePlan {
    call: ValueId,
    /// The two merges, as a writer's: at the call's block, every edge
    /// into it handing both over.
    writer: Writer,
    arms: Vec<([ValueId; 2], ArmKind)>,
    ty: KnownType,
    /// The `Ok` payloads the merge is the only reader of.
    sole: HashSet<ValueId>,
}

/// The plan for `call`, a call of the register converter `conv` in
/// `caller` on two merges at the call's own block.
fn plan_inline(
    ir: &HighIr,
    reg: &TypeRegistry,
    calls: &CallIndex,
    caller: &HighFunction,
    call: ValueId,
    conv: &HighFunction,
    rc: &RegisterConverter,
) -> Result<InlinePlan, &'static str> {
    let Some(Expr::Call { args, .. }) = caller.bindings.get(call).map(|b| &b.expr) else {
        return Err("not a call");
    };
    let merge_at = |i: usize| -> Option<ValueId> {
        let m = resolve_use(caller, *args.get(i)?);
        matches!(caller.bindings.get(m).map(|b| &b.expr), Some(Expr::Phi { incoming }) if !incoming.is_empty())
            .then_some(m)
    };
    let (Some(tag), Some(payload)) = (merge_at(rc.tag), merge_at(rc.payload)) else {
        return Err("the pair is not two merges");
    };
    if tag == payload {
        return Err("one merge handed over twice");
    }
    let join = crate::dataflow::block_containing(caller, call).ok_or("the call is not scheduled")?;
    let merges = [tag, payload];
    // The merges are read by nothing but the call.
    for id in emission_order(caller) {
        let Some(b) = caller.bindings.get(id) else {
            return Err("a missing binding");
        };
        let mut reads = false;
        b.expr.for_each_value_use(|u| reads |= merges.contains(&resolve_use(caller, u)));
        if reads && id != call {
            return Err("a merge of the pair read by something else");
        }
    }
    let mut region_reads = false;
    caller.region.for_each_value_use(|u| region_reads |= merges.contains(&u));
    if region_reads {
        return Err("a merge of the pair read by the control flow");
    }
    // Every edge into the call's block hands over both merges, and only
    // those edges hand them anything.
    let mut edges = Vec::new();
    let mut bad = false;
    caller.region.for_each_node(|node| match node {
        Region::Break { target, transfer } | Region::Transfer { target, transfer } => {
            let get = |m: ValueId| transfer.iter().find(|(phi, _)| *phi == m).map(|(_, v)| *v);
            match (get(tag), get(payload)) {
                (Some(x), Some(y)) if *target == join => edges.push([x, y]),
                (None, None) => {}
                _ => bad = true,
            }
        }
        Region::Continue { transfer, .. } => bad |= transfer.iter().any(|(phi, _)| merges.contains(phi)),
        _ => {}
    });
    if bad || edges.is_empty() {
        return Err("an edge does not hand over the pair");
    }
    for m in merges {
        let Some(Expr::Phi { incoming }) = caller.bindings.get(m).map(|b| &b.expr) else {
            return Err("a missing merge");
        };
        if incoming.len() != edges.len() {
            return Err("a merge reached other than by the edges");
        }
    }
    if !only_returned(caller, call) {
        return Err("the converted value is used other than returned");
    }
    let (ty, err_enum) = declared_u32_result(ir, reg, calls, caller.id)?;
    let reading = Reading {
        tag: rc.tag,
        payload: rc.payload,
        func: conv,
        cond: rc.cond,
        tag_input: *conv.params.get(rc.tag).ok_or("a missing parameter")?,
        err_when: rc.err_when,
    };
    let pairs: Vec<(ValueId, ValueId)> = edges.iter().map(|e| (e[0], e[1])).collect();
    let kinds = edge_arms(caller, &pairs, &reading, err_enum)?;
    let writer = Writer { merges, join, edges };
    let arms: Vec<([ValueId; 2], ArmKind)> = writer.edges.iter().copied().zip(kinds).collect();
    // An `Ok` payload is the `u32` the converter encodes: typed so, or the
    // 32-bit word. One read by nothing but the merge is retyped here; one
    // other things read keeps its word for the typing to settle, which
    // reads the `Ok` it is now in.
    for (_, kind) in &arms {
        if let ArmKind::Ok(p) = kind
            && !matches!(
                caller.bindings.get(*p).map(|b| &b.ty),
                Some(
                    IrType::Known(KnownType::U32)
                        | IrType::Inferred(KnownType::U32 | KnownType::I32)
                        | IrType::Unknown(_)
                )
            )
        {
            return Err("an `Ok` payload typed other than the 32-bit word");
        }
    }
    let sole: HashSet<ValueId> = arms
        .iter()
        .filter_map(|(_, k)| match k {
            ArmKind::Ok(p) => Some(*p),
            ArmKind::Err(_) => None,
        })
        .filter(|p| retypable(caller, &writer, &[([*p, *p], ArmKind::Ok(*p))]).is_ok())
        .collect();
    Ok(InlinePlan { call, writer, arms, ty, sole })
}

/// Each edge builds its `Result`, a merge at the call's block carries it,
/// and the converter's call is that merge.
fn rewrite_inline(func: &mut HighFunction, plan: &InlinePlan) {
    let result_ty = IrType::Inferred(plan.ty.clone());
    let KnownType::Result(_, err) = &plan.ty else {
        return;
    };
    let err_ty = match (**err).clone() {
        IrType::Known(k) | IrType::Inferred(k) => IrType::Inferred(k),
        other => other,
    };
    for payload in &plan.sole {
        if !matches!(
            func.bindings.get(*payload).map(|b| &b.ty),
            Some(IrType::Known(KnownType::U32) | IrType::Inferred(KnownType::U32))
        ) {
            rewrite(
                func,
                *payload,
                None,
                IrType::Inferred(KnownType::U32),
                "the `Ok` payload the converter encoded as a `U32Val`",
            );
        }
    }
    let merged = push(
        func,
        Expr::Phi { incoming: Vec::new() },
        result_ty.clone(),
        "the `Result` each edge built, merged where the edges meet",
    );
    let reads = read_codes(func, &plan.writer, &plan.arms);
    let region = std::mem::replace(&mut func.region, Region::Unreachable);
    let mut ctx = Place {
        func,
        writer: &plan.writer,
        arms: &plan.arms,
        merged,
        result_ty: &result_ty,
        err_ty: &err_ty,
        reads: &reads,
        incoming: Vec::new(),
    };
    let region = ctx.region(region);
    let incoming = std::mem::take(&mut ctx.incoming);
    func.region = region;
    if let Some(b) = func.bindings.get_mut(merged) {
        b.expr = Expr::Phi { incoming };
    }
    for m in plan.writer.merges {
        rewrite(
            func,
            m,
            Some(Expr::Literal(Literal::Unit)),
            IrType::Known(KnownType::Unit),
            "one half of the pair handed to the converter, now part of the `Result`",
        );
    }
    rewrite(
        func,
        plan.call,
        Some(Expr::Use(merged)),
        result_ty,
        "the `Result`'s conversion to the entrypoint's `Val`, which the declared `Result` return performs",
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{module, v};
    use sordec_common::{Arena, UnknownReason};
    use sordec_ir::{
        CompositeType, EnumCase, EnumDef, ErrorVariant, FunctionSignature, PrimitiveType, SorobanFacts, TypeRef,
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

    fn lit64(n: i64) -> (Expr, IrType) {
        (Expr::Literal(Literal::I64(n)), IrType::Known(KnownType::I64))
    }

    fn param() -> (Expr, IrType) {
        (Expr::Phi { incoming: vec![] }, untyped())
    }

    fn bin(op: BinaryOp, lhs: u32, rhs: u32) -> (Expr, IrType) {
        (Expr::Binary { op, lhs: v(lhs), rhs: v(rhs) }, untyped())
    }

    fn load4(addr: u32) -> (Expr, IrType) {
        (Expr::Load { addr: v(addr), offset: 0, width: MemWidth::W4, signed: None, ty: untyped() }, untyped())
    }

    fn call(target: u32, args: &[u32]) -> (Expr, IrType) {
        (Expr::Call { target: FuncId::from_index(target), args: args.iter().map(|a| v(*a)).collect() }, untyped())
    }

    fn project(value: u32, index: u32) -> (Expr, IrType) {
        (Expr::Project { value: v(value), index }, untyped())
    }

    fn global_set(value: u32) -> (Expr, IrType) {
        let expr =
            Expr::Unknown { op_kind: WasmOpcodeKind::GlobalSet, args: vec![v(value)], reason: UnknownReason::UnsupportedPattern };
        (expr, untyped())
    }

    /// `if flag { (1, code) } else { (0, a + 7) }`, `code` the binding the
    /// `Err` edge hands over.
    fn writer(code: (Expr, IrType)) -> HighFunction {
        let exprs = vec![
            param(),                                                                 // v0 a
            (Expr::Phi { incoming: vec![] }, IrType::Known(KnownType::Bool)),        // v1 flag
            lit(1),                                                                  // v2 tag Err
            code,                                                                    // v3 code
            lit(0),                                                                  // v4 tag Ok
            lit(7),                                                                  // v5
            bin(BinaryOp::Add, 0, 5),                                                // v6 payload
            (Expr::Phi { incoming: vec![(bb(0), v(2)), (bb(1), v(4))] }, untyped()), // v7 tag merge
            (Expr::Phi { incoming: vec![(bb(0), v(3)), (bb(1), v(6))] }, untyped()), // v8 payload merge
        ];
        let region = Region::Sequence(vec![
            Region::Basic(bb(0)),
            Region::If {
                cond: v(1),
                then_region: Box::new(Region::Transfer { target: bb(2), transfer: vec![(v(7), v(2)), (v(8), v(3))] }),
                else_region: Some(Box::new(Region::Sequence(vec![
                    Region::Basic(bb(1)),
                    Region::Transfer { target: bb(2), transfer: vec![(v(7), v(4)), (v(8), v(6))] },
                ]))),
            },
            Region::Basic(bb(2)),
            Region::Return { values: vec![v(7), v(8)] },
        ]);
        func(0, exprs, vec![vec![2, 3, 4], vec![5, 6], vec![]], region, vec![0, 1])
    }

    /// `(0, U32Val(load4(q)))`, `x` unread.
    fn word_helper() -> HighFunction {
        let encode = Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty: KnownType::U32, value: v(3) }));
        let exprs = vec![
            param(),           // v0 x
            param(),           // v1 q
            lit64(0),          // v2
            load4(1),          // v3
            (encode, untyped()), // v4
        ];
        let region = Region::Sequence(vec![Region::Basic(bb(0)), Region::Return { values: vec![v(2), v(4)] }]);
        func(1, exprs, vec![vec![2, 3, 4]], region, vec![0, 1])
    }

    /// `(0, func1(x, q).1)`.
    fn outer_helper() -> HighFunction {
        let exprs = vec![
            param(),          // v0 q
            param(),          // v1 x
            call(1, &[1, 0]), // v2
            lit64(0),         // v3
            project(2, 1),    // v4
        ];
        let region = Region::Sequence(vec![Region::Basic(bb(0)), Region::Return { values: vec![v(3), v(4)] }]);
        func(2, exprs, vec![vec![2, 3, 4]], region, vec![0, 1])
    }

    /// `if load4(p) { (((load4(p+4) + k0) as u64) << 32) + Error(code 1) }
    /// else { func2(p+4, x).1 }`.
    fn converter(k0: i32) -> HighFunction {
        let error = Expr::Semantic(SemanticOp::Known(KnownOp::MakeError {
            code: 1,
            resolved: Some(ErrorVariant { enum_name: "MyError".into(), variant: "First".into() }),
        }));
        let exprs = vec![
            param(),                                                                   // v0 x
            param(),                                                                   // v1 p
            lit(4),                                                                    // v2
            bin(BinaryOp::Add, 1, 2),                                                  // v3 p+4
            load4(1),                                                                  // v4 tag
            load4(3),                                                                  // v5 code
            lit(k0),                                                                   // v6
            bin(BinaryOp::Add, 5, 6),                                                  // v7
            (Expr::Unary { op: UnaryOp::ExtendU32, value: v(7) }, untyped()),          // v8
            lit64(32),                                                                 // v9
            bin(BinaryOp::Shl, 8, 9),                                                  // v10
            (error, IrType::Known(KnownType::Error)),                                  // v11
            bin(BinaryOp::Add, 10, 11),                                                // v12
            call(2, &[3, 0]),                                                          // v13
            project(13, 1),                                                            // v14
            (Expr::Phi { incoming: vec![(bb(1), v(12)), (bb(2), v(14))] }, untyped()), // v15
        ];
        let region = Region::Sequence(vec![
            Region::Basic(bb(0)),
            Region::If {
                cond: v(4),
                then_region: Box::new(Region::Sequence(vec![
                    Region::Basic(bb(1)),
                    Region::Transfer { target: bb(3), transfer: vec![(v(15), v(12))] },
                ])),
                else_region: Some(Box::new(Region::Sequence(vec![
                    Region::Basic(bb(2)),
                    Region::Transfer { target: bb(3), transfer: vec![(v(15), v(14))] },
                ]))),
            },
            Region::Basic(bb(3)),
            Region::Return { values: vec![v(15)] },
        ]);
        func(3, exprs, vec![vec![2, 3, 4], vec![5, 6, 7, 8, 9, 10, 11, 12], vec![13, 14], vec![]], region, vec![0, 1])
    }

    /// `store4 fp+tag_at <- t; store4 fp+12 <- p; return func3(x, fp+8)`.
    fn wrapper(tag_at: u32) -> HighFunction {
        let store = |value: u32, offset: u32| {
            (Expr::Store { addr: v(5), value: v(value), offset, width: MemWidth::W4 }, untyped())
        };
        let exprs = vec![
            param(),                                                       // v0 t
            param(),                                                       // v1 p
            param(),                                                       // v2 x
            (Expr::GlobalGet { index: 0 }, IrType::Known(KnownType::I32)), // v3
            lit(16),                                                       // v4
            bin(BinaryOp::Sub, 3, 4),                                      // v5 fp
            global_set(5),                                                 // v6
            store(1, 12),                                                  // v7
            store(0, tag_at),                                              // v8
            lit(8),                                                        // v9
            bin(BinaryOp::Add, 5, 9),                                      // v10 fp+8
            call(3, &[2, 10]),                                             // v11
            lit(16),                                                       // v12
            bin(BinaryOp::Add, 5, 12),                                     // v13
            global_set(13),                                                // v14
        ];
        let region = Region::Sequence(vec![Region::Basic(bb(0)), Region::Return { values: vec![v(11)] }]);
        func(4, exprs, vec![(3..=14).collect()], region, vec![0, 1, 2])
    }

    /// `s = func0(a, 1); return func4(s.0, s.1, a)`, `extra` scheduled
    /// after the components.
    fn caller(extra: Option<(Expr, IrType)>) -> HighFunction {
        let mut exprs = vec![
            param(),             // v0 a
            lit(1),              // v1
            call(0, &[0, 1]),    // v2
            project(2, 0),       // v3
            project(2, 1),       // v4
            call(4, &[3, 4, 0]), // v5
        ];
        let mut block = vec![1, 2, 3, 4];
        if let Some(extra) = extra {
            exprs.push(extra); // v6
            block.push(6);
        }
        block.push(5);
        let region = Region::Sequence(vec![Region::Basic(bb(0)), Region::Return { values: vec![v(5)] }]);
        func(5, exprs, vec![block], region, vec![0])
    }

    /// The entrypoint: `return func5(x)`, declared `-> Result<ok, err>`.
    fn entry(ok: PrimitiveType, err: TypeRef) -> HighFunction {
        let exprs = vec![param(), call(5, &[0])];
        let region = Region::Sequence(vec![Region::Basic(bb(0)), Region::Return { values: vec![v(1)] }]);
        let mut f = func(6, exprs, vec![vec![1]], region, vec![0]);
        f.name = Some("deposit".into());
        f.signature = Some(FunctionSignature {
            name: "deposit".into(),
            inputs: vec![],
            outputs: vec![TypeRef::Composite(CompositeType::Result(Box::new(TypeRef::Primitive(ok)), Box::new(err)))],
        });
        f
    }

    fn sdk_error() -> TypeRef {
        TypeRef::Primitive(PrimitiveType::Error)
    }

    fn my_error() -> TypeRef {
        TypeRef::UserDefined(TypeId::from_index(1))
    }

    /// The module, its error enum declaring codes `1` and `full`.
    fn ir(functions: Vec<HighFunction>, full: u32) -> HighIr {
        let mut ir = module(functions);
        let mut types = TypeRegistry::default();
        types.errors.push(EnumDef {
            id: TypeId::from_index(1),
            name: "MyError".into(),
            cases: vec![EnumCase { name: "First".into(), value: 1 }, EnumCase { name: "Full".into(), value: full }],
        });
        ir.soroban_facts = Some(SorobanFacts {
            functions: Default::default(),
            types,
            contract_meta: Default::default(),
            env_meta: Default::default(),
        });
        ir
    }

    fn parts(code: (Expr, IrType), k0: i32, tag_at: u32, err: TypeRef) -> Vec<HighFunction> {
        vec![
            writer(code),
            word_helper(),
            outer_helper(),
            converter(k0),
            wrapper(tag_at),
            caller(None),
            entry(PrimitiveType::U32, err),
        ]
    }

    fn standard(err: TypeRef) -> HighIr {
        ir(parts(lit(5), -1, 8, err), 5)
    }

    /// The `Result` each edge into the writer's merge now hands over.
    fn built(w: &HighFunction) -> Vec<&Expr> {
        let [site] = w.returns.as_slice() else { panic!("{:?}", w.returns) };
        let [merged] = site.as_slice() else { panic!("{site:?}") };
        assert!(matches!(&w.bindings.get(*merged).unwrap().ty, IrType::Inferred(KnownType::Result(..))));
        let Expr::Phi { incoming } = &w.bindings.get(*merged).unwrap().expr else { panic!() };
        let mut carried = Vec::new();
        w.region.for_each_node(|node| {
            if let Region::Break { transfer, .. } | Region::Transfer { transfer, .. } = node {
                carried.extend(transfer.iter().copied());
            }
        });
        assert_eq!(carried.len(), 2, "each edge carries the `Result` alone");
        assert!(carried.iter().all(|(phi, _)| phi == merged));
        // Every incoming value is scheduled in the block it names.
        for (block, value) in incoming {
            assert!(w.blocks.get(*block).unwrap().bindings.contains(value), "{block:?} schedules {value:?}");
        }
        incoming.iter().map(|(_, val)| &w.bindings.get(*val).unwrap().expr).collect()
    }

    #[test]
    fn the_writer_returns_the_result_and_the_wrapper_call_is_it() {
        let mut ir = standard(sdk_error());
        assert!(ResultPairPass.run(&mut ir).changed);

        let w = ir.function(FuncId::from_index(0)).unwrap();
        let arms = built(w);
        let [Expr::Variant { name: err, payload: e }, Expr::Variant { name: ok, payload: o }] = arms.as_slice() else {
            panic!("{arms:?}")
        };
        assert_eq!((err.as_str(), ok.as_str()), ("Err", "Ok"));
        assert_eq!(o, &vec![v(6)]);
        // The spec's `Error` is the contract's one error enum, named back.
        let error = w.bindings.get(e[0]).unwrap();
        assert!(matches!(&error.expr, Expr::Variant { name, .. } if name == "Full"), "{:?}", error.expr);
        assert_eq!(error.ty, IrType::Inferred(KnownType::UserDefined(TypeId::from_index(1))));
        // The `Ok` payload is the u32 the converter encoded.
        assert_eq!(w.bindings.get(v(6)).unwrap().ty, IrType::Inferred(KnownType::U32));
        // The old merges are retired; the return hands back the `Result`.
        for m in [7, 8] {
            assert!(matches!(w.bindings.get(v(m)).unwrap().expr, Expr::Literal(Literal::Unit)), "v{m} retired");
        }
        // The then-edge had no block of its own: one was made for it.
        assert_eq!(w.blocks.len(), 4);

        let c = ir.function(FuncId::from_index(5)).unwrap();
        assert!(matches!(c.bindings.get(v(5)).unwrap().expr, Expr::Use(x) if x == v(2)));
        assert!(matches!(&c.bindings.get(v(2)).unwrap().ty, IrType::Inferred(KnownType::Result(..))));
        for p in [3, 4] {
            assert!(matches!(c.bindings.get(v(p)).unwrap().expr, Expr::Literal(Literal::Unit)), "v{p} retired");
        }
    }

    /// The writer comes to return the `Result`: beside a raw indirect call,
    /// only when no table can hold it.
    #[test]
    fn a_writer_a_raw_indirect_call_may_reach_keeps_its_pair() {
        crate::marshalling::test_support::check_indirect_gate(
            || standard(sdk_error()),
            0,
            |ir| ResultPairPass.run(ir).changed,
        );
    }

    #[test]
    fn a_declared_error_enum_names_the_variant() {
        let mut ir = standard(my_error());
        assert!(ResultPairPass.run(&mut ir).changed);
        let w = ir.function(FuncId::from_index(0)).unwrap();
        let arms = built(w);
        let Expr::Variant { payload: e, .. } = arms[0] else { panic!() };
        let error = w.bindings.get(e[0]).unwrap();
        assert!(matches!(&error.expr, Expr::Variant { name, .. } if name == "Full"));
        assert_eq!(error.ty, IrType::Inferred(KnownType::UserDefined(TypeId::from_index(1))));
    }

    fn unchanged(mut ir: HighIr) {
        let r = ResultPairPass.run(&mut ir);
        assert!(!r.changed);
        let w = ir.function(FuncId::from_index(0)).unwrap();
        assert_eq!(w.returns, vec![vec![v(7), v(8)]]);
        let c = ir.function(FuncId::from_index(5)).unwrap();
        assert!(matches!(c.bindings.get(v(5)).unwrap().expr, Expr::Call { .. }));
    }

    #[test]
    fn a_code_the_declared_enum_does_not_name_is_left() {
        // The enum declares 1 and 6; the edge hands over 5.
        unchanged(ir(parts(lit(5), -1, 8, my_error()), 6));
    }

    #[test]
    fn an_error_that_is_not_of_the_code_read_is_left() {
        // `(c - 2) << 32` plus the error of code 1 is the error of `c - 1`.
        unchanged(ir(parts(lit(5), -2, 8, sdk_error()), 5));
    }

    #[test]
    fn a_code_only_known_at_run_time_is_left() {
        unchanged(ir(parts(param(), -1, 8, sdk_error()), 5));
    }

    #[test]
    fn a_tag_stored_where_the_converter_does_not_read_is_left() {
        unchanged(ir(parts(lit(5), -1, 4, sdk_error()), 5));
    }

    #[test]
    fn a_result_the_entrypoint_does_not_declare_as_u32_is_left() {
        let mut fs = parts(lit(5), -1, 8, sdk_error());
        fs[6] = entry(PrimitiveType::I32, sdk_error());
        unchanged(ir(fs, 5));
    }

    #[test]
    fn a_component_read_by_something_else_is_left() {
        let mut fs = parts(lit(5), -1, 8, sdk_error());
        fs[5] = caller(Some(bin(BinaryOp::Eq, 3, 1)));
        unchanged(ir(fs, 5));
    }

    #[test]
    fn the_sdk_error_with_no_error_enum_is_the_code() {
        let mut ir = standard(sdk_error());
        if let Some(f) = ir.soroban_facts.as_mut() {
            f.types.errors.clear();
        }
        assert!(ResultPairPass.run(&mut ir).changed);
        let w = ir.function(FuncId::from_index(0)).unwrap();
        let arms = built(w);
        let Expr::Variant { payload: e, .. } = arms[0] else { panic!() };
        assert!(matches!(
            w.bindings.get(e[0]).unwrap().expr,
            Expr::Semantic(SemanticOp::Known(KnownOp::MakeError { code: 5, resolved: None }))
        ));
    }

    /// `fn func0(t, p) { if t & 1 { return ((p - 1) as u32 as u64 << 32) +
    /// Error(1) } return U32Val(p) }`: the pair in two registers.
    fn register_converter() -> HighFunction {
        let error = Expr::Semantic(SemanticOp::Known(KnownOp::MakeError {
            code: 1,
            resolved: Some(ErrorVariant { enum_name: "MyError".into(), variant: "First".into() }),
        }));
        let encode = Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty: KnownType::U32, value: v(1) }));
        let exprs = vec![
            param(),                                                          // v0 t
            param(),                                                          // v1 p
            lit(1),                                                           // v2
            bin(BinaryOp::BitAnd, 0, 2),                                      // v3 cond
            lit(-1),                                                          // v4
            bin(BinaryOp::Add, 1, 4),                                         // v5
            (Expr::Unary { op: UnaryOp::ExtendU32, value: v(5) }, untyped()), // v6
            lit64(32),                                                        // v7
            bin(BinaryOp::Shl, 6, 7),                                         // v8
            (error, IrType::Known(KnownType::Error)),                         // v9
            bin(BinaryOp::Add, 8, 9),                                         // v10
            (encode, untyped()),                                              // v11
        ];
        let region = Region::Sequence(vec![
            Region::Basic(bb(0)),
            Region::If {
                cond: v(3),
                then_region: Box::new(Region::Sequence(vec![
                    Region::Basic(bb(1)),
                    Region::Return { values: vec![v(10)] },
                ])),
                else_region: None,
            },
            Region::Basic(bb(2)),
            Region::Return { values: vec![v(11)] },
        ]);
        func(0, exprs, vec![vec![2, 3], vec![4, 5, 6, 7, 8, 9, 10], vec![11]], region, vec![0, 1])
    }

    /// The entrypoint `-> Result<u32, err>`: `if flag { (t, p) = (1, code) }
    /// else { (t, p) = (0, a + 7) }; return func0(t, p)`, `extra` scheduled
    /// before the call.
    fn inline_entry(code: (Expr, IrType), err: TypeRef, extra: Option<(Expr, IrType)>) -> HighFunction {
        let mut exprs = vec![
            param(),                                                                 // v0 a
            (Expr::Phi { incoming: vec![] }, IrType::Known(KnownType::Bool)),        // v1 flag
            lit(1),                                                                  // v2 tag Err
            code,                                                                    // v3 code
            lit(0),                                                                  // v4 tag Ok
            lit(7),                                                                  // v5
            bin(BinaryOp::Add, 0, 5),                                                // v6 payload
            (Expr::Phi { incoming: vec![(bb(0), v(2)), (bb(1), v(4))] }, untyped()), // v7 tag merge
            (Expr::Phi { incoming: vec![(bb(0), v(3)), (bb(1), v(6))] }, untyped()), // v8 payload merge
            call(0, &[7, 8]),                                                        // v9
        ];
        let mut join = vec![9];
        if let Some(extra) = extra {
            exprs.push(extra); // v10
            join.insert(0, 10);
        }
        let region = Region::Sequence(vec![
            Region::Basic(bb(0)),
            Region::If {
                cond: v(1),
                then_region: Box::new(Region::Transfer { target: bb(2), transfer: vec![(v(7), v(2)), (v(8), v(3))] }),
                else_region: Some(Box::new(Region::Sequence(vec![
                    Region::Basic(bb(1)),
                    Region::Transfer { target: bb(2), transfer: vec![(v(7), v(4)), (v(8), v(6))] },
                ]))),
            },
            Region::Basic(bb(2)),
            Region::Return { values: vec![v(9)] },
        ]);
        let mut f = func(1, exprs, vec![vec![2, 3, 4], vec![5, 6], join], region, vec![0, 1]);
        f.name = Some("propose".into());
        f.signature = Some(FunctionSignature {
            name: "propose".into(),
            inputs: vec![],
            outputs: vec![TypeRef::Composite(CompositeType::Result(
                Box::new(TypeRef::Primitive(PrimitiveType::U32)),
                Box::new(err),
            ))],
        });
        f
    }

    /// The `Result`s the edges into the entrypoint's join now hand over.
    fn inline_built(ir: &HighIr) -> Vec<Expr> {
        let f = ir.function(FuncId::from_index(1)).unwrap();
        let Expr::Use(merged) = f.bindings.get(v(9)).unwrap().expr else { panic!("{:?}", f.bindings.get(v(9))) };
        let Expr::Phi { incoming } = &f.bindings.get(merged).unwrap().expr else { panic!() };
        for m in [7, 8] {
            assert!(matches!(f.bindings.get(v(m)).unwrap().expr, Expr::Literal(Literal::Unit)), "v{m} retired");
        }
        incoming.iter().map(|(_, val)| f.bindings.get(*val).unwrap().expr.clone()).collect()
    }

    #[test]
    fn a_register_converter_on_its_callers_merges_is_the_result() {
        let mut ir = ir(vec![register_converter(), inline_entry(lit(5), sdk_error(), None)], 5);
        assert!(ResultPairPass.run(&mut ir).changed);
        let arms = inline_built(&ir);
        let [Expr::Variant { name: err, payload: e }, Expr::Variant { name: ok, payload: o }] = arms.as_slice() else {
            panic!("{arms:?}")
        };
        assert_eq!((err.as_str(), ok.as_str()), ("Err", "Ok"));
        assert_eq!(o, &vec![v(6)]);
        let f = ir.function(FuncId::from_index(1)).unwrap();
        assert!(matches!(&f.bindings.get(e[0]).unwrap().expr, Expr::Variant { name, .. } if name == "Full"));
    }

    #[test]
    fn a_code_read_from_memory_is_the_declared_error() {
        let mut ir = ir(vec![register_converter(), inline_entry(load4(0), sdk_error(), None)], 5);
        assert!(ResultPairPass.run(&mut ir).changed);
        let arms = inline_built(&ir);
        let Expr::Variant { payload: e, .. } = &arms[0] else { panic!("{arms:?}") };
        assert_eq!(e, &vec![v(3)], "the read itself, read by nothing else");
        let f = ir.function(FuncId::from_index(1)).unwrap();
        assert_eq!(f.bindings.get(v(3)).unwrap().ty, IrType::Inferred(KnownType::UserDefined(TypeId::from_index(1))));
    }

    #[test]
    fn a_merge_of_the_pair_read_by_something_else_is_left() {
        let extra = bin(BinaryOp::Eq, 8, 2);
        let mut ir = ir(vec![register_converter(), inline_entry(lit(5), sdk_error(), Some(extra))], 5);
        assert!(!ResultPairPass.run(&mut ir).changed);
        let f = ir.function(FuncId::from_index(1)).unwrap();
        assert!(matches!(f.bindings.get(v(9)).unwrap().expr, Expr::Call { .. }));
    }

    #[test]
    fn a_tag_that_is_not_a_constant_is_left() {
        let mut entry = inline_entry(lit(5), sdk_error(), None);
        if let Some(b) = entry.bindings.get_mut(v(2)) {
            b.expr = Expr::Binary { op: BinaryOp::Add, lhs: v(0), rhs: v(4) };
        }
        let mut ir = ir(vec![register_converter(), entry], 5);
        assert!(!ResultPairPass.run(&mut ir).changed);
    }

    #[test]
    fn a_converter_whose_ok_side_is_not_the_payload_is_not_one() {
        let mut conv = register_converter();
        if let Some(b) = conv.bindings.get_mut(v(11)) {
            b.expr = Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty: KnownType::U32, value: v(0) }));
        }
        assert!(classify_register_converter(&conv).is_none());
        assert!(classify_register_converter(&register_converter()).is_some());
    }

    #[test]
    fn a_word_helper_that_reads_another_parameter_is_left() {
        let mut fs = parts(lit(5), -1, 8, sdk_error());
        let mut h = word_helper();
        // `U32Val(load4(q) + x)`: the converter's other argument now matters.
        h.bindings.push(Binding::new(
            v(5),
            untyped(),
            Expr::Binary { op: BinaryOp::Add, lhs: v(3), rhs: v(0) },
            Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
        ));
        h.blocks.get_mut(bb(0)).unwrap().bindings.insert(2, v(5));
        if let Some(b) = h.bindings.get_mut(v(4)) {
            b.expr = Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty: KnownType::U32, value: v(5) }));
        }
        fs[1] = h;
        unchanged(ir(fs, 5));
    }
}
