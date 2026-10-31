//! A fixed-size byte array the host fills, read back as the array it is.
//!
//! # The shape
//!
//! `BytesN::to_array` and `Bytes::copy_into_slice` are one host call into a
//! buffer in the caller's frame, `bytes_copy_to_linear_memory(b, 0, &mut a,
//! N)`. What the source then does with `a` the wasm does with the frame
//! bytes: loads them back at constant offsets (`u32::from_be_bytes(a)` is a
//! 4-byte load and a byte swap), copies them word by word into another
//! buffer, hands them to `Bytes::from_array` (`bytes_new_from_linear_memory`
//! over the same bytes):
//!
//! ```text
//! store fp+8 <- 0 (width 4)                       let a: [u8; 4] = { let mut array = [0u8; 4];
//! bytes_copy_to_linear_memory(b, 0, fp+8, 4)          b.copy_into_slice(&mut array); array };
//! x = load fp+8 (width 4)                   →     let x = i32::from_le_bytes(a[0..4].try_into().unwrap());
//! ```
//!
//! # The rewrite
//!
//! The host call becomes the array value ([`KnownOp::BytesToArray`], typed
//! `[u8; N]`); each load of its bytes becomes [`Expr::ArrayRead`] of that
//! value; a `bytes_new_from_linear_memory` over exactly its bytes becomes
//! `Bytes::from_array(&e, &a)` ([`KnownOp::BytesNew`] with `array`). The
//! zero fill before it and the frame slots are then unread, and the
//! dead-store and frame elisions take them.
//!
//! A second rule reads a buffer the array was copied into: a
//! `bytes_new_from_linear_memory(fp+k, N)` whose `N` bytes are, by the
//! frame facts at that call, stores of the array's own bytes in order — the
//! `let b = a;` move rustc compiles to word copies — is
//! `Bytes::from_array(&e, &a)` too.
//!
//! A third rule follows the array out of a helper. rustc returns a
//! `[u8; N]` through an out-pointer: `fn take<const N>(..) -> [u8; N]` fills
//! its own buffer, then `memcpy(out, buffer, N)` before its one `return`.
//! Such a helper returns the array instead — the copy and the parameter go,
//! the `return` carries the value — and each call site's call *is* the
//! array: the reads of the bytes it wrote in the caller's frame become reads
//! of the call's value, as for a host copy (`Bytes::from_array(&e,
//! &take::<96>(..))`).
//!
//! ## Why it is exact
//!
//! The spelled call is the same host call. `b.to_array()` is
//! `bytes_copy_to_linear_memory(b, 0, &mut array, N)` and nothing else; the
//! `Bytes` form of `copy_into_slice` adds one check, `b.len() != N` panics,
//! which the code has already made on every path to the copy (see *Gates*),
//! so it never fires. Either way the host is handed the same object, start
//! and length, traps where the original trapped (a source shorter than `N`)
//! and copies the same `N` bytes.
//!
//! A load becomes a read of the array only when the host copy is the last
//! write of every byte it takes: it sits in the copy's own block, after it,
//! with nothing in between that may write memory or store over those bytes.
//! It then reads the array's bytes `[offset, offset + width)`, little-endian
//! as wasm memory is, extended as the load extended them — what
//! [`Expr::ArrayRead`] computes. A constructor over exactly the copy's bytes
//! under the same condition reads all `N` of them, which is what
//! `Bytes::from_array` hands the host.
//!
//! The copy then stops writing the frame, which is exact only if nothing
//! else read what it wrote. That is the backward liveness of the frame's
//! bytes [`super::dead_store`] proves its dead stores with: every reader of
//! the frame — its loads, the calls handed its addresses (through what their
//! callees read), the host constructors reading a buffer — is counted, every
//! store and host copy kills what it writes, and the copy is rewritten only
//! when none of its bytes is live after it once the reads it is about to
//! replace are left out. A byte nobody reads before it is written again, or
//! before the frame is released, is a byte whose value does not matter.
//!
//! The copy rule rests on [`crate::dataflow::facts_at`]: each slot it reads
//! holds the value a store put there along every path, unclobbered, and
//! that value is a read of the array's bytes at the same distance from the
//! buffer's start, at the store's own width. The `N` bytes of the buffer are
//! then the array's `N` bytes.
//!
//! The out-parameter rule moves where the array's bytes live, not what they
//! are. In the helper, the copy reads the buffer while it still holds the
//! array (the copy's own block, nothing writing it in between), so it writes
//! exactly the array's `N` bytes through the pointer; it runs on every path
//! to the one `return` (the block falls straight into it), and every other
//! path traps, so a caller that resumes has always had them written. The
//! out-parameter is read by nothing but the copy, and the helper's value was
//! nothing, so the caller saw these `N` bytes and nothing else of the call's
//! work through that pointer. In each caller, the bytes the call wrote are
//! read only by the reads rewritten — the same frame liveness as for a host
//! copy, with the call a definite write of them (it writes them on every
//! return) — so not writing them is unobservable, and each rewritten read
//! sees the array's bytes at its offset, which is what the returned value
//! holds.
//!
//! ## Gates
//!
//! - The copy's start in the source is the constant `U32Val` `0`, its length
//!   a constant `N` (at most [`MAX_LEN`]), its destination the frame pointer
//!   plus a constant.
//! - The source: a `BytesN<N>` whose type is proven (`Known`) spells
//!   `to_array()`. A `Bytes` (or `BytesN<N>`, or a value not typed yet)
//!   spells `copy_into_slice` only when `b.len() == N` holds on every path
//!   to the copy — the host's `bytes_len` on it, so it is a bytes object
//!   whatever its type says so far: the copy is inside
//!   the arm of an `if` that tests it, or after a guard `if b.len() != N {
//!   <never falls through> }` in the same sequence. A `Bytes` whose length
//!   nothing checked is left: `copy_into_slice` would add a check the binary
//!   does not make.
//! - Every use of a frame address is a load or store address (never a
//!   stored value), the shadow-stack bracket, a call whose reach into the
//!   frame is known, or the `U32Val` position operand of a host copy or
//!   constructor whose extent is a constant; anything else leaves the
//!   function untouched.
//! - The read is wholly inside the array, and its binding is untyped or a
//!   machine word of the load's own width.
//! - The flow is structured, and each loop's liveness settles.
//! - Out-parameter: the helper is not exported, returns nothing, has one
//!   `return`, and its only use of the parameter is the destination of a
//!   `memcpy`/`memmove` (whose value goes unread) of exactly a host copy's
//!   buffer, in that copy's block and the block before the `return`, with
//!   the copy itself passing every gate above. Every call is direct
//!   (no indirect call can reach it) and every call site passes: the
//!   out-pointer is the caller's own frame plus a constant, nothing else the
//!   call is handed reaches those bytes, and the caller's frame liveness
//!   shows no other reader. One refused site keeps the helper as it is.

use std::collections::{BTreeSet, HashMap, HashSet};

use sordec_common::{BlockId, FuncId, IrId, ValueId};
use sordec_sigs::MemRoutine;
use sordec_ir::{
    ArrayFill, BinaryOp, BufOpKind, Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Literal, MemWidth,
    Region, SemanticOp,
};

use super::dead_store::{frame_addresses, frame_pointer, Liveness};
use super::optional_out::{give_back, leaves, Frames, Slot};
use super::sret::emission_order;
use super::{apply_elisions, Elision};
use crate::dataflow::{block_containing, canon_addr, facts_at, resolve_use, trace_int, CallIndex};
use crate::effects::expr_effects;
use crate::metrics_catalog::{MARSHALLING_BYTE_ARRAYS_FILLED, MARSHALLING_BYTE_ARRAY_READS};
use crate::pass::{Pass, PassResult};
use crate::recognizers::mem_builtins::routine;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-byte-array";

/// Longest array taken. The liveness walk tracks the frame byte by byte;
/// the SDK's arrays are curve points and hashes, 4 to 192 bytes.
pub const MAX_LEN: u32 = 1024;

/// Rounds of one-copy-per-function planning in a single run. Each round
/// rewrites at least one copy, and a function holds few.
const MAX_ROUNDS: usize = 16;

/// Reads a host-filled frame buffer as the `[u8; N]` array it is.
#[derive(Debug, Default, Clone, Copy)]
pub struct ByteArrayPass;

impl Pass<HighIr> for ByteArrayPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for _ in 0..MAX_ROUNDS {
            // Planned over the whole module first: what a call reads through
            // a pointer is read off its callee.
            let plans: Vec<(usize, FillPlan)> = {
                let frames = Frames::new(ir);
                ir.functions
                    .iter()
                    .enumerate()
                    .filter_map(|(i, func)| plan(&frames, ir, func).map(|p| (i, p)))
                    .collect()
            };
            if plans.is_empty() {
                break;
            }
            for (index, fill) in plans {
                let Some(func) = ir.functions.get_mut(index) else { continue };
                result.changed = true;
                result.metrics.increment(MARSHALLING_BYTE_ARRAYS_FILLED, 1);
                result.metrics.increment(MARSHALLING_BYTE_ARRAY_READS, fill.reads.len() as i64);
                apply(func, fill);
            }
        }
        for _ in 0..MAX_ROUNDS {
            if !returned_arrays(ir, &mut result) {
                break;
            }
        }
        for func in &mut ir.functions {
            let copies = plan_copies(func);
            if copies.is_empty() {
                continue;
            }
            result.changed = true;
            result.metrics.increment(MARSHALLING_BYTE_ARRAY_READS, copies.len() as i64);
            apply_elisions(func, PASS_NAME, copies);
        }
        result
    }
}

/// A host buffer operation on the frame, with the slot it touches.
#[derive(Debug, Clone, Copy)]
enum HostBuf {
    /// `bytes_copy_to_linear_memory(bytes, pos, fp + slot.offset, slot.bytes)`.
    /// `from_start` when `pos` is the constant `0`.
    Fill { slot: Slot, bytes: ValueId, from_start: bool },
    /// `bytes_new_from_linear_memory(fp + slot.offset, slot.bytes)`, contents
    /// not yet known.
    New { slot: Slot },
}

/// One host copy to rewrite, and the reads that go with it.
struct FillPlan {
    fill: ValueId,
    bytes: ValueId,
    slot: Slot,
    form: ArrayFill,
    /// `(load, offset into the array, width, extension, binding type)`.
    reads: Vec<(ValueId, u32, MemWidth, Option<bool>, IrType)>,
    /// Constructors over exactly the copy's bytes.
    news: Vec<ValueId>,
    /// The `memset` that zeroed the buffer first, when nothing reads what it
    /// wrote: `[0u8; N]`, which the spelled call makes itself.
    retired: Vec<ValueId>,
}

/// A function's frame, as the walks here see it.
struct View {
    fp: ValueId,
    order: Vec<ValueId>,
    ops: HashMap<ValueId, HostBuf>,
    /// Calls that write a known slot whenever they return: `memcpy`,
    /// `memmove`, `memset` of a constant length, and a call handing an
    /// array helper its out-parameter.
    writes: HashMap<ValueId, Slot>,
    /// The `memset`s among them.
    fills: Vec<ValueId>,
}

/// `func`'s frame, its host buffer operations and its definite writes, when
/// every use of a frame address is accounted for. `helpers` names the
/// functions whose out-parameter is known to be written whole.
fn view(frames: &Frames<'_>, ir: &HighIr, func: &HighFunction, helpers: &HashMap<FuncId, OutHelper>) -> Option<View> {
    let fp = frame_pointer(func)?;
    let order = emission_order(func);
    let ops = host_buffers(func, fp, &order);
    if !accounted(frames, func, fp, &order, &ops) {
        return None;
    }
    let mut writes = HashMap::new();
    let mut fills = Vec::new();
    for &id in &order {
        let Some(Expr::Call { target, args }) = func.bindings.get(id).map(|b| &b.expr) else { continue };
        if let Some(helper) = helpers.get(target) {
            let (base, offset) = canon_addr(func, *args.get(helper.out)?);
            if base == fp {
                writes.insert(id, Slot { offset, bytes: helper.len });
            }
            continue;
        }
        let Some(routine @ (MemRoutine::Memcpy | MemRoutine::Memmove | MemRoutine::Memset)) = routine(ir, *target)
        else {
            continue;
        };
        let [dst, _, len] = args[..] else { continue };
        let (base, offset) = canon_addr(func, dst);
        let Some(bytes) = trace_int(func, len).and_then(|n| u32::try_from(n).ok()) else { continue };
        if base != fp || bytes == 0 || offset.checked_add(bytes).is_none() {
            continue;
        }
        writes.insert(id, Slot { offset, bytes });
        if routine == MemRoutine::Memset {
            fills.push(id);
        }
    }
    Some(View { fp, order, ops, writes, fills })
}

/// Why a copy was left, printed when `SORDEC_BYTE_ARRAY_TRACE` is set.
#[allow(clippy::print_stderr)]
fn trace(func: &HighFunction, at: ValueId, why: &str) {
    if std::env::var_os("SORDEC_BYTE_ARRAY_TRACE").is_some() {
        eprintln!("byte-array: func_{} v{}: {why}", func.id.index(), at.index());
    }
}

/// The first host copy in `func` that can be read as an array, if any.
fn plan(frames: &Frames<'_>, ir: &HighIr, func: &HighFunction) -> Option<FillPlan> {
    let fp = frame_pointer(func)?;
    let order = emission_order(func);
    if !host_buffers(func, fp, &order).values().any(|op| matches!(op, HostBuf::Fill { from_start: true, .. })) {
        return None;
    }
    let view = view(frames, ir, func, &HashMap::new())?;
    view.order.iter().find_map(|&id| match view.ops.get(&id) {
        Some(&HostBuf::Fill { slot, bytes, from_start: true }) => {
            plan_fill(frames, &view, func, id, slot, bytes, &[]).map(|(p, _)| p)
        }
        _ => None,
    })
}

/// The `u32` a `U32Val` operand encodes, when it is a constant: the
/// `ValEncodeSmall` of a constant, or the encoded word itself as a literal.
fn u32_val_const(func: &HighFunction, value: ValueId) -> Option<u32> {
    match &func.bindings.get(resolve_use(func, value))?.expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty: KnownType::U32, value })) => {
            u32::try_from(trace_int(func, *value)?).ok()
        }
        Expr::Literal(Literal::I64(bits)) if bits & 0xff == 4 => u32::try_from((*bits as u64) >> 32).ok(),
        Expr::Literal(Literal::U64(bits)) if bits & 0xff == 4 => u32::try_from(bits >> 32).ok(),
        _ => None,
    }
}

/// The frame offset a `U32Val` position operand encodes, when it is the
/// `ValEncodeSmall` of an address in the frame.
fn u32_val_frame(func: &HighFunction, value: ValueId, fp: ValueId) -> Option<u32> {
    match &func.bindings.get(resolve_use(func, value))?.expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty: KnownType::U32, value })) => {
            let (base, off) = canon_addr(func, *value);
            (base == fp).then_some(off)
        }
        _ => None,
    }
}

/// Every host copy into, and constructor from, a frame buffer of constant
/// extent, by binding.
fn host_buffers(func: &HighFunction, fp: ValueId, order: &[ValueId]) -> HashMap<ValueId, HostBuf> {
    let mut out = HashMap::new();
    for &id in order {
        let Some(binding) = func.bindings.get(id) else { continue };
        match &binding.expr {
            Expr::Semantic(SemanticOp::Known(KnownOp::BufOp { kind: BufOpKind::BytesCopyToLinearMemory, args })) => {
                let [bytes, pos, lm, len] = args[..] else { continue };
                let (Some(offset), Some(n)) = (u32_val_frame(func, lm, fp), u32_val_const(func, len)) else {
                    continue;
                };
                if n == 0 || offset.checked_add(n).is_none() {
                    continue;
                }
                out.insert(
                    id,
                    HostBuf::Fill {
                        slot: Slot { offset, bytes: n },
                        bytes: resolve_use(func, bytes),
                        from_start: u32_val_const(func, pos) == Some(0),
                    },
                );
            }
            Expr::Semantic(SemanticOp::Known(KnownOp::BytesNew { lm_pos, len, resolved: None, array: None })) => {
                let (Some(offset), Some(n)) = (u32_val_frame(func, *lm_pos, fp), u32_val_const(func, *len)) else {
                    continue;
                };
                if n == 0 || offset.checked_add(n).is_none() {
                    continue;
                }
                out.insert(id, HostBuf::New { slot: Slot { offset, bytes: n } });
            }
            _ => {}
        }
    }
    out
}

/// Whether every use of an address in the frame is one the liveness walk
/// counts ("Gates").
fn accounted(
    frames: &Frames<'_>,
    func: &HighFunction,
    fp: ValueId,
    order: &[ValueId],
    ops: &HashMap<ValueId, HostBuf>,
) -> bool {
    let derived = frame_addresses(func, fp, order);
    let dead = crate::dataflow::dead_residue(func, order);
    let is_address = |v: ValueId| derived.contains(&resolve_use(func, v));
    // Who reads each `U32Val` position operand: it must be only the host
    // operations counted in `ops`, as their position.
    let mut position_readers: HashMap<ValueId, Vec<ValueId>> = HashMap::new();
    for (id, binding) in func.bindings.iter() {
        if dead.contains(&id) {
            continue;
        }
        binding.expr.for_each_value_use(|u| position_readers.entry(resolve_use(func, u)).or_default().push(id));
    }
    let mut region_reads = false;
    func.region.for_each_value_use(|u| {
        region_reads |= is_address(u);
        position_readers.entry(resolve_use(func, u)).or_default().push(fp);
    });
    if region_reads {
        trace(func, fp, "an address read by the control flow");
        return false;
    }
    for &id in order {
        let Some(binding) = func.bindings.get(id) else { return false };
        match &binding.expr {
            Expr::Store { value, .. } => {
                if is_address(*value) {
                    trace(func, id, "an address stored to memory");
                    return false;
                }
            }
            Expr::Load { .. } => {}
            Expr::Unknown { op_kind: sordec_ir::WasmOpcodeKind::GlobalSet, .. } => {}
            Expr::Binary { op: BinaryOp::Add, .. } if derived.contains(&id) => {}
            Expr::Use(_) if derived.contains(&resolve_use(func, id)) => {}
            other if dead.contains(&id) && expr_effects(other).is_pure_total() => {}
            Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty: KnownType::U32, value }))
                if is_address(*value) =>
            {
                let readers = position_readers.get(&id).map(Vec::as_slice).unwrap_or_default();
                if readers.iter().any(|r| !position_of(func, ops, *r, id)) {
                    trace(func, id, "a position operand read by something other than a counted host op");
                    return false;
                }
            }
            other => {
                let mut uses = false;
                other.for_each_value_use(|u| uses |= is_address(u));
                if !uses {
                    continue;
                }
                let call = matches!(
                    other,
                    Expr::Call { .. } | Expr::Unknown { op_kind: sordec_ir::WasmOpcodeKind::MemoryOp, .. }
                );
                if !call || frames.touches(func, id, fp).is_none() {
                    trace(func, id, "an address handed to something whose reach is unknown");
                    return false;
                }
            }
        }
    }
    true
}

/// Whether `reader` is a host buffer operation in `ops` reading `operand`
/// only as its linear-memory position.
fn position_of(func: &HighFunction, ops: &HashMap<ValueId, HostBuf>, reader: ValueId, operand: ValueId) -> bool {
    if !ops.contains_key(&reader) {
        return false;
    }
    let same = |v: ValueId| resolve_use(func, v) == operand;
    match func.bindings.get(reader).map(|b| &b.expr) {
        Some(Expr::Semantic(SemanticOp::Known(KnownOp::BufOp { args, .. }))) => {
            let [bytes, pos, lm, len] = args[..] else { return false };
            same(lm) && !same(bytes) && !same(pos) && !same(len)
        }
        Some(Expr::Semantic(SemanticOp::Known(KnownOp::BytesNew { lm_pos, len, .. }))) => same(*lm_pos) && !same(*len),
        _ => false,
    }
}

/// The copy `fill` as an array, with its reads, when every gate holds.
///
/// `out_copy` is the copy into a helper's out-parameter that the caller
/// rewrites with it: it reads the buffer and stops doing so. Returns, with
/// the plan, whether that copy reads the copy's bytes unclobbered.
fn plan_fill(
    frames: &Frames<'_>,
    view: &View,
    func: &HighFunction,
    fill: ValueId,
    slot: Slot,
    bytes: ValueId,
    out_copy: &[ValueId],
) -> Option<(FillPlan, bool)> {
    let (fp, ops) = (view.fp, &view.ops);
    if slot.bytes > MAX_LEN {
        return None;
    }
    let Some(form) = fill_form(func, fill, bytes, slot.bytes) else {
        if std::env::var_os("SORDEC_BYTE_ARRAY_TRACE").is_some() {
            let mut proven = Vec::new();
            let found = block_containing(func, fill)
                .is_some_and(|block| proven_lengths(func, &func.region, block, &mut proven));
            let ty = func.bindings.get(bytes).map(|b| format!("{:?}", b.ty));
            trace(func, fill, &format!("the source's length is not proven: v{} {ty:?} found={found} {proven:?}", bytes.index()));
        }
        return None;
    };
    let (reads, news, copied) = reads_after(func, fp, ops, fill, slot, out_copy.first().copied())?;
    let mut walk = Liveness::new(frames, func, fp);
    walk.writes.extend(view.writes.iter().map(|(k, v)| (*k, *v)));
    walk.skip.extend(out_copy.iter().copied());
    for (&id, op) in ops {
        match *op {
            HostBuf::Fill { slot, .. } => {
                walk.writes.insert(id, slot);
            }
            HostBuf::New { slot } => {
                walk.reads.insert(id, slot);
            }
        }
    }
    walk.skip.extend(reads.iter().map(|r| r.0));
    walk.skip.extend(news.iter().copied());
    if walk.region(&func.region, &BTreeSet::new()).is_none() {
        trace(func, fill, "the flow or a call's reach could not be followed");
        return None;
    }
    let live = walk.after.get(&fill)?;
    if let Some(byte) = live.range(slot.offset..slot.offset + slot.bytes).next() {
        trace(func, fill, &format!("frame byte +{byte} it writes may be read after it"));
        return None;
    }
    // The zero fill `[0u8; N]` compiles to, when nothing reads its bytes:
    // the copy overwrote them all, and nothing between read them.
    let readers = live_readers(func, &view.order);
    let retired = view
        .fills
        .iter()
        .copied()
        .filter(|m| view.writes.get(m) == Some(&slot))
        .filter(|m| readers.get(m).is_none_or(Vec::is_empty))
        .filter(|m| walk.after.get(m).is_some_and(|l| l.range(slot.offset..slot.offset + slot.bytes).next().is_none()))
        .collect();
    Some((FillPlan { fill, bytes, slot, form, reads, news, retired }, copied))
}

/// Who reads each value, among the bindings that run — scheduled and not
/// dead residue, or a merge — and the region.
fn live_readers(func: &HighFunction, order: &[ValueId]) -> HashMap<ValueId, Vec<ValueId>> {
    let dead = crate::dataflow::dead_residue(func, order);
    let scheduled: HashSet<ValueId> = order.iter().copied().collect();
    let mut readers: HashMap<ValueId, Vec<ValueId>> = HashMap::new();
    for (id, binding) in func.bindings.iter() {
        let runs = (scheduled.contains(&id) && !dead.contains(&id)) || matches!(binding.expr, Expr::Phi { .. });
        if runs {
            binding.expr.for_each_value_use(|u| readers.entry(resolve_use(func, u)).or_default().push(id));
        }
    }
    let marker = ValueId::from_index(u32::MAX);
    func.region.for_each_value_use(|u| readers.entry(resolve_use(func, u)).or_default().push(marker));
    readers
}

/// How the source spelled the copy of `bytes` into an `n`-byte array at
/// `fill`, when its type or a proven length says ("Gates").
fn fill_form(func: &HighFunction, fill: ValueId, bytes: ValueId, n: u32) -> Option<ArrayFill> {
    let ty = &func.bindings.get(bytes)?.ty;
    let checked = || {
        let block = block_containing(func, fill)?;
        let mut proven = Vec::new();
        proven_lengths(func, &func.region, block, &mut proven).then_some(())?;
        proven.contains(&(bytes, n)).then_some(())
    };
    match ty {
        // Untyped yet: the length test that proves `N` is the host's
        // `bytes_len`, which takes nothing but a bytes object, so the value
        // is one — and type inference reads it so from that same call.
        IrType::Known(KnownType::Bytes) | IrType::Inferred(KnownType::Bytes) | IrType::Unknown(_) => {
            checked().map(|()| ArrayFill::CopyIntoSlice)
        }
        IrType::Known(KnownType::BytesN(m)) | IrType::Inferred(KnownType::BytesN(m)) if *m == n => {
            match checked() {
                Some(()) => Some(ArrayFill::CopyIntoSlice),
                None if matches!(ty, IrType::Known(_)) => Some(ArrayFill::ToArray),
                None => None,
            }
        }
        _ => None,
    }
}

/// Collect into `proven` the `(bytes, n)` for which `bytes.len() == n` holds
/// on entry to `target`, walking `region` down to it: the arm of an `if`
/// that tests it, and the guards before it in a sequence that leave when
/// it fails. Returns whether `target` was found.
///
/// A length is a fact about an immutable host object, so one proven on the
/// way down holds wherever the path goes next, loops included.
fn proven_lengths(func: &HighFunction, region: &Region, target: BlockId, proven: &mut Vec<(ValueId, u32)>) -> bool {
    match region {
        Region::Basic(b) => *b == target,
        Region::Sequence(items) => {
            for item in items {
                if contains_block(item, target) {
                    return proven_lengths(func, item, target, proven);
                }
                if let Region::If { cond, then_region, else_region: None } = item
                    && leaves(then_region)
                    && let Some(fact) = length_fact(func, *cond, false)
                {
                    proven.push(fact);
                }
            }
            false
        }
        Region::Scope { body, .. } | Region::Loop { body, .. } => proven_lengths(func, body, target, proven),
        Region::If { cond, then_region, else_region } => {
            if contains_block(then_region, target) {
                proven.extend(length_fact(func, *cond, true));
                return proven_lengths(func, then_region, target, proven);
            }
            match else_region {
                Some(other) if contains_block(other, target) => {
                    proven.extend(length_fact(func, *cond, false));
                    proven_lengths(func, other, target, proven)
                }
                _ => false,
            }
        }
        Region::Switch { arms, default, .. } => match arms.iter().find(|a| contains_block(&a.body, target)) {
            Some(arm) => proven_lengths(func, &arm.body, target, proven),
            None => proven_lengths(func, default, target, proven),
        },
        _ => false,
    }
}

/// `(bytes, n)` when `cond` having the truth value `holds` proves
/// `bytes.len() == n`: `len == n` holding, or `len != n` failing.
fn length_fact(func: &HighFunction, cond: ValueId, holds: bool) -> Option<(ValueId, u32)> {
    let Expr::Binary { op, lhs, rhs } = &func.bindings.get(resolve_use(func, cond))?.expr else {
        return None;
    };
    let equal = match op {
        BinaryOp::Eq => holds,
        BinaryOp::Ne => !holds,
        _ => return None,
    };
    if !equal {
        return None;
    }
    let len_of = |v: ValueId| -> Option<ValueId> {
        let binding = func.bindings.get(resolve_use(func, v))?;
        match &binding.expr {
            Expr::Semantic(SemanticOp::Known(KnownOp::BufOp { kind: BufOpKind::BytesLen, args }))
                if matches!(binding.ty, IrType::Known(KnownType::U32)) =>
            {
                Some(resolve_use(func, *args.first()?))
            }
            _ => None,
        }
    };
    let constant = |v: ValueId| u32::try_from(trace_int(func, v)?).ok();
    match (len_of(*lhs), len_of(*rhs)) {
        (Some(b), None) => Some((b, constant(*rhs)?)),
        (None, Some(b)) => Some((b, constant(*lhs)?)),
        _ => None,
    }
}

/// Whether `region` holds `target` anywhere in its tree.
fn contains_block(region: &Region, target: BlockId) -> bool {
    let mut found = false;
    region.for_each_node(|node| found |= matches!(node, Region::Basic(b) if *b == target));
    found
}

type Reads = Vec<(ValueId, u32, MemWidth, Option<bool>, IrType)>;

/// The loads and constructors after `fill` in its own block that read only
/// bytes it wrote, before anything may write memory or writes those bytes.
///
/// With `copy`, also whether that binding — a copy of exactly the buffer —
/// is reached the same way.
fn reads_after(
    func: &HighFunction,
    fp: ValueId,
    ops: &HashMap<ValueId, HostBuf>,
    fill: ValueId,
    slot: Slot,
    copy: Option<ValueId>,
) -> Option<(Reads, Vec<ValueId>, bool)> {
    let block = block_containing(func, fill)?;
    let bindings = &func.blocks.get(block)?.bindings;
    let start = bindings.iter().position(|b| *b == fill)?;
    let mut clobbered: HashSet<u32> = HashSet::new();
    let mut reads = Vec::new();
    let mut news = Vec::new();
    let mut copied = false;
    for &id in &bindings[start + 1..] {
        let Some(binding) = func.bindings.get(id) else { break };
        if Some(id) == copy {
            copied = !(slot.offset..slot.offset + slot.bytes).any(|b| clobbered.contains(&b));
            break;
        }
        match &binding.expr {
            Expr::Load { addr, offset, width, signed, ty: word } => {
                let (base, off) = canon_addr(func, *addr);
                if base != fp {
                    continue;
                }
                let Some(at) = off.checked_add(*offset) else { continue };
                let read = Slot { offset: at, bytes: width.bytes() };
                let inside = at >= slot.offset && at + read.bytes <= slot.offset + slot.bytes;
                if !inside || (at..at + read.bytes).any(|b| clobbered.contains(&b)) {
                    continue;
                }
                let Some(ty) = read_type(&binding.ty, word, *width) else { continue };
                reads.push((id, at - slot.offset, *width, *signed, ty));
            }
            Expr::Store { addr, offset, width, .. } => {
                let (base, off) = canon_addr(func, *addr);
                // Through a pointer the function was handed: that memory was
                // there before this frame was carved out below it, so it is
                // none of the frame's bytes.
                if base != fp && func.params.contains(&base) {
                    continue;
                }
                if base != fp {
                    break;
                }
                let at = off.checked_add(*offset)?;
                clobbered.extend(at..at.checked_add(width.bytes())?);
            }
            _ => match ops.get(&id) {
                Some(HostBuf::Fill { slot: written, .. }) => {
                    clobbered.extend(written.offset..written.offset + written.bytes);
                }
                Some(HostBuf::New { slot: read }) => {
                    if *read == slot && !(read.offset..read.offset + read.bytes).any(|b| clobbered.contains(&b)) {
                        news.push(id);
                    }
                }
                None if expr_effects(&binding.expr).writes_memory => break,
                None => {}
            },
        }
    }
    Some((reads, news, copied))
}

/// The type an array read takes: the binding's own, when it is a machine
/// word of the load's width; the load's word, inferred, when the binding is
/// untyped. `None` for anything else — a word typed as an object is no
/// array read.
fn read_type(current: &IrType, word: &IrType, width: MemWidth) -> Option<IrType> {
    let word_bytes = match word {
        IrType::Known(KnownType::I32) => 4,
        IrType::Known(KnownType::I64) => 8,
        _ => return None,
    };
    if width.bytes() > word_bytes {
        return None;
    }
    match current {
        IrType::Unknown(_) => Some(match word_bytes {
            4 => IrType::Inferred(KnownType::I32),
            _ => IrType::Inferred(KnownType::I64),
        }),
        IrType::Known(k) | IrType::Inferred(k) => {
            let bytes = match k {
                KnownType::I32 | KnownType::U32 => 4,
                KnownType::I64 | KnownType::U64 => 8,
                _ => return None,
            };
            (bytes == word_bytes).then(|| current.clone())
        }
    }
}

fn apply(func: &mut HighFunction, plan: FillPlan) {
    let n = plan.slot.bytes;
    let mut rewrites = vec![Elision {
        id: plan.fill,
        expr: Expr::Semantic(SemanticOp::Known(KnownOp::BytesToArray { bytes: plan.bytes, len: n, form: plan.form })),
        ty: Some(IrType::Known(KnownType::ByteArray(n))),
        note: format!(
            "host copy of {n} bytes into frame +{} read as the [u8; {n}] it fills ({:?}); every read of those \
             bytes is now a read of the array",
            plan.slot.offset, plan.form
        ),
        metric: MARSHALLING_BYTE_ARRAYS_FILLED,
    }];
    for &id in &plan.retired {
        rewrites.push(Elision {
            id,
            expr: Expr::Literal(Literal::Unit),
            ty: Some(IrType::Known(KnownType::Unit)),
            note: format!(
                "memset of the {n} bytes the host copy then fills, nothing reading them between: the `[0u8; {n}]` \
                 the spelled copy starts from"
            ),
            metric: MARSHALLING_BYTE_ARRAYS_FILLED,
        });
    }
    apply_elisions(func, PASS_NAME, rewrites);
    apply_reads(func, plan.fill, &plan.reads, &plan.news);
}

/// The loads and constructors found after `array`'s writer, as reads of it.
fn apply_reads(func: &mut HighFunction, array: ValueId, reads: &Reads, news: &[ValueId]) {
    let mut rewrites = Vec::new();
    for &(id, offset, width, signed, ref ty) in reads {
        rewrites.push(Elision {
            id,
            expr: Expr::ArrayRead { array, offset, width, signed },
            ty: Some(ty.clone()),
            note: format!(
                "load of bytes {offset}..{} of the array written just before it, with nothing writing them in \
                 between",
                offset + width.bytes()
            ),
            metric: MARSHALLING_BYTE_ARRAY_READS,
        });
    }
    for &id in news {
        let Some(Expr::Semantic(SemanticOp::Known(KnownOp::BytesNew { lm_pos, len, resolved, .. }))) =
            func.bindings.get(id).map(|b| b.expr.clone())
        else {
            continue;
        };
        rewrites.push(Elision {
            id,
            expr: Expr::Semantic(SemanticOp::Known(KnownOp::BytesNew {
                lm_pos,
                len,
                resolved,
                array: Some(array),
            })),
            ty: None,
            note: "bytes_new over exactly the bytes of the array written just before it: Bytes::from_array".to_string(),
            metric: MARSHALLING_BYTE_ARRAY_READS,
        });
    }
    apply_elisions(func, PASS_NAME, rewrites);
}

// ---------------------------------------------------------------------
// An array handed back through an out-parameter
// ---------------------------------------------------------------------

/// A helper that returns a `[u8; N]` the only way rustc can: by copying the
/// array it filled into the caller's frame through an out-pointer
/// (`fn take<const N>(..) -> [u8; N]`, rustc's `sret`).
struct OutHelper {
    /// The out-parameter's position.
    out: usize,
    /// The array's length, the bytes the copy writes through it.
    len: u32,
    /// The `memcpy(out, buffer, N)`, which the return replaces.
    copy: ValueId,
    /// The array itself, inside the helper.
    fill: FillPlan,
}

/// One call to an array helper, with the reads of the bytes it wrote.
struct SitePlan {
    call: ValueId,
    reads: Reads,
    news: Vec<ValueId>,
}

/// `func` as an array helper, when it is one ("Gates" of the out-parameter
/// rule in the module docs).
fn classify_out(frames: &Frames<'_>, ir: &HighIr, func: &HighFunction) -> Option<OutHelper> {
    if func.signature.is_some() || func.returns.iter().any(|r| !r.is_empty()) {
        return None;
    }
    let mut returns = 0usize;
    func.region.for_each_node(|node| returns += usize::from(matches!(node, Region::Return { .. })));
    if returns != 1 {
        return None;
    }
    let fp = frame_pointer(func)?;
    if !host_buffers(func, fp, &emission_order(func)).values().any(|op| matches!(op, HostBuf::Fill { from_start: true, .. }))
    {
        return None;
    }
    let Some(view) = view(frames, ir, func, &HashMap::new()) else {
        trace(func, fp, "array helper candidate: the frame is not accounted for");
        return None;
    };
    let readers = live_readers(func, &view.order);
    for &copy in &view.order {
        let Some(Expr::Call { target, args }) = func.bindings.get(copy).map(|b| &b.expr) else { continue };
        if !matches!(routine(ir, *target), Some(MemRoutine::Memcpy | MemRoutine::Memmove)) {
            continue;
        }
        let [dst, src, len] = args[..] else { continue };
        let dst = resolve_use(func, dst);
        let Some(out) = func.params.iter().position(|p| *p == dst) else { continue };
        trace(func, copy, &format!("a copy into parameter {out}; its readers {:?}, the copy's {:?}", readers.get(&dst), readers.get(&copy)));
        // The out-parameter is read by the copy alone, as its destination,
        // and nothing reads the copy's value (the destination again).
        if readers.get(&dst).map(Vec::as_slice) != Some(&[copy][..])
            || resolve_use(func, src) == dst
            || resolve_use(func, len) == dst
            || readers.get(&copy).is_some_and(|r| !r.is_empty())
        {
            continue;
        }
        let (base, offset) = canon_addr(func, src);
        let Some(n) = trace_int(func, len).and_then(|n| u32::try_from(n).ok()) else { continue };
        if base != fp {
            continue;
        }
        let slot = Slot { offset, bytes: n };
        let Some((fill, bytes)) = view.ops.iter().find_map(|(id, op)| match *op {
            HostBuf::Fill { slot: s, bytes, from_start: true } if s == slot => Some((*id, bytes)),
            _ => None,
        }) else {
            continue;
        };
        if !falls_into_return(&func.region, block_containing(func, copy)?) {
            trace(func, copy, "the out-parameter copy is not right before the one return");
            continue;
        }
        let (plan, copied) = plan_fill(frames, &view, func, fill, slot, bytes, &[copy])?;
        if !copied {
            trace(func, copy, "the out-parameter copy does not read the array unclobbered");
            continue;
        }
        return Some(OutHelper { out, len: n, copy, fill: plan });
    }
    None
}

/// Whether `block` is followed, in its sequence, by a `return`: every path
/// to that return runs the whole block.
fn falls_into_return(region: &Region, block: BlockId) -> bool {
    let mut found = false;
    region.for_each_node(|node| {
        if let Region::Sequence(items) = node {
            found |= items
                .windows(2)
                .any(|w| matches!(w, [Region::Basic(b), Region::Return { .. }] if *b == block));
        }
    });
    found
}

/// The call `call` to `helper` as the array it returns, when the caller
/// reads the bytes it wrote only where that array can stand.
fn plan_site(
    frames: &Frames<'_>,
    ir: &HighIr,
    caller: &HighFunction,
    call: ValueId,
    helpers: &HashMap<FuncId, OutHelper>,
) -> Option<SitePlan> {
    let view = view(frames, ir, caller, helpers)?;
    // The out-pointer is into this caller's own frame: what reads it after
    // the call is then all here to count.
    let slot = *view.writes.get(&call)?;
    for (touch, write_only) in frames.touches(caller, call, view.fp)? {
        if touch == slot && write_only {
            continue;
        }
        if touch.overlaps(slot) {
            trace(caller, call, "the call reaches the result's bytes through another pointer");
            return None;
        }
    }
    let (reads, news, _) = reads_after(caller, view.fp, &view.ops, call, slot, None)?;
    let mut walk = Liveness::new(frames, caller, view.fp);
    walk.writes.extend(view.writes.iter().map(|(k, v)| (*k, *v)));
    for (&id, op) in &view.ops {
        match *op {
            HostBuf::Fill { slot, .. } => {
                walk.writes.insert(id, slot);
            }
            HostBuf::New { slot } => {
                walk.reads.insert(id, slot);
            }
        }
    }
    walk.skip.extend(reads.iter().map(|r| r.0));
    walk.skip.extend(news.iter().copied());
    walk.region(&caller.region, &BTreeSet::new())?;
    if let Some(byte) = walk.after.get(&call)?.range(slot.offset..slot.offset + slot.bytes).next() {
        trace(caller, call, &format!("frame byte +{byte} the call writes may be read after it"));
        return None;
    }
    Some(SitePlan { call, reads, news })
}

/// Every array helper whose every call site can take the array as a value,
/// rewritten to return it. Whether anything changed.
fn returned_arrays(ir: &mut HighIr, result: &mut PassResult) -> bool {
    let calls = CallIndex::build(ir);
    let (helpers, sites) = {
        let frames = Frames::new(ir);
        let mut helpers: HashMap<FuncId, OutHelper> = ir
            .functions
            .iter()
            .filter(|f| calls.caller_set_complete(f.id))
            .filter_map(|f| classify_out(&frames, ir, f).map(|h| (f.id, h)))
            .collect();
        if helpers.is_empty() {
            return false;
        }
        let mut sites: HashMap<FuncId, Vec<(usize, SitePlan)>> = HashMap::new();
        let mut refused: HashSet<FuncId> = HashSet::new();
        for (index, caller) in ir.functions.iter().enumerate() {
            for id in emission_order(caller) {
                let Some(Expr::Call { target, .. }) = caller.bindings.get(id).map(|b| &b.expr) else { continue };
                if !helpers.contains_key(target) {
                    continue;
                }
                match (*target != caller.id).then(|| plan_site(&frames, ir, caller, id, &helpers)).flatten() {
                    Some(plan) => sites.entry(*target).or_default().push((index, plan)),
                    None => {
                        refused.insert(*target);
                    }
                }
            }
        }
        helpers.retain(|id, _| !refused.contains(id) && sites.contains_key(id));
        (helpers, sites)
    };
    if helpers.is_empty() {
        return false;
    }
    for (target, helper) in helpers {
        let n = helper.len;
        for (index, site) in sites.get(&target).into_iter().flatten() {
            let Some(caller) = ir.functions.get_mut(*index) else { continue };
            rewrite_site(caller, site, helper.out, n);
            result.metrics.increment(MARSHALLING_BYTE_ARRAY_READS, (site.reads.len() + site.news.len()) as i64);
        }
        // A call no block schedules still names the old signature.
        let Some(at) = ir.functions.iter().position(|f| f.id == target) else { continue };
        let arity = ir.functions[at].params.len();
        for func in &mut ir.functions {
            for (_, binding) in func.bindings.iter_mut() {
                if let Expr::Call { target: t, args } = &mut binding.expr
                    && *t == target
                    && args.len() == arity
                {
                    args.remove(helper.out);
                }
            }
        }
        let func = &mut ir.functions[at];
        let array = helper.fill.fill;
        apply(func, helper.fill);
        apply_elisions(
            func,
            PASS_NAME,
            vec![Elision {
                id: helper.copy,
                expr: Expr::Literal(Literal::Unit),
                ty: Some(IrType::Known(KnownType::Unit)),
                note: format!("the copy of the [u8; {n}] into the out-parameter, now the returned array"),
                metric: MARSHALLING_BYTE_ARRAYS_FILLED,
            }],
        );
        give_back(&mut func.region, array);
        for site in &mut func.returns {
            *site = vec![array];
        }
        if helper.out < func.params.len() {
            func.params.remove(helper.out);
        }
        result.metrics.increment(MARSHALLING_BYTE_ARRAYS_FILLED, 1);
        result.changed = true;
    }
    true
}

/// The call yields the array; the reads of what it wrote read the array.
fn rewrite_site(caller: &mut HighFunction, site: &SitePlan, out: usize, n: u32) {
    if let Some(binding) = caller.bindings.get_mut(site.call)
        && let Expr::Call { args, .. } = &mut binding.expr
        && out < args.len()
    {
        args.remove(out);
        binding.ty = IrType::Known(KnownType::ByteArray(n));
        binding.add_provenance(sordec_common::Provenance::new(
            PASS_NAME,
            sordec_common::ProvenanceSource::SdkPattern,
            format!("the helper's out-parameter held a [u8; {n}] it copied there whole; the call returns it"),
        ));
    }
    apply_reads(caller, site.call, &site.reads, &site.news);
}

/// The copy rule: each constructor whose buffer holds, slot by slot, the
/// bytes of one array in order ("The rewrite").
fn plan_copies(func: &HighFunction) -> Vec<Elision> {
    let Some(fp) = frame_pointer(func) else { return Vec::new() };
    let order = emission_order(func);
    let mut out = Vec::new();
    for (id, op) in host_buffers(func, fp, &order) {
        let HostBuf::New { slot } = op else { continue };
        let Some(array) = copied_array(func, fp, id, slot) else { continue };
        let Some(Expr::Semantic(SemanticOp::Known(KnownOp::BytesNew { lm_pos, len, resolved, .. }))) =
            func.bindings.get(id).map(|b| b.expr.clone())
        else {
            continue;
        };
        out.push(Elision {
            id,
            expr: Expr::Semantic(SemanticOp::Known(KnownOp::BytesNew { lm_pos, len, resolved, array: Some(array) })),
            ty: None,
            note: format!(
                "bytes_new over frame +{}: its {} bytes are stores of the array's bytes in order, unclobbered \
                 (frame facts): Bytes::from_array",
                slot.offset, slot.bytes
            ),
            metric: MARSHALLING_BYTE_ARRAY_READS,
        });
    }
    out
}

/// The array whose bytes fill `slot` at `at`, one store per piece, each the
/// array's bytes at the same distance from the start.
fn copied_array(func: &HighFunction, fp: ValueId, at: ValueId, slot: Slot) -> Option<ValueId> {
    let facts = facts_at(func, at, fp);
    let by_offset: HashMap<u32, _> = facts.iter().collect();
    let mut array: Option<ValueId> = None;
    let mut cursor = slot.offset;
    while cursor < slot.offset + slot.bytes {
        let fact = by_offset.get(&cursor)?;
        let Expr::ArrayRead { array: a, offset, width, .. } = &func.bindings.get(resolve_use(func, fact.value))?.expr
        else {
            return None;
        };
        if *width != fact.width || *offset != cursor - slot.offset || array.is_some_and(|x| x != *a) {
            return None;
        }
        array = Some(*a);
        cursor = cursor.checked_add(width.bytes())?;
    }
    let array = array?;
    let filled = matches!(
        &func.bindings.get(array)?.expr,
        Expr::Semantic(SemanticOp::Known(KnownOp::BytesToArray { len, .. })) if *len == slot.bytes
    );
    (filled && cursor == slot.offset + slot.bytes).then_some(array)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{module, v};
    use sordec_common::{Arena, FuncId, Provenance, ProvenanceSource, UnknownReason};
    use sordec_ir::{Binding, HighBlock, PanicKind, WasmOpcodeKind};

    fn global_set(value: ValueId) -> Expr {
        Expr::Unknown { op_kind: WasmOpcodeKind::GlobalSet, args: vec![value], reason: UnknownReason::UnsupportedPattern }
    }

    fn known(op: KnownOp) -> Expr {
        Expr::Semantic(SemanticOp::Known(op))
    }

    fn encode(value: ValueId) -> Expr {
        known(KnownOp::ValEncodeSmall { ty: KnownType::U32, value })
    }

    fn load(addr: ValueId, offset: u32, width: MemWidth, word: KnownType) -> Expr {
        Expr::Load { addr, offset, width, signed: None, ty: IrType::Known(word) }
    }

    /// The shape of `take::<4>`: a 16-byte frame, a length guard on the
    /// source, the host copy of 4 bytes into `fp+8`, and a 4-byte load of
    /// them returned.
    ///
    /// `guard` is the length the guard tests (`None` for no guard), `source`
    /// the source's type, and `extra` bindings scheduled between the copy
    /// and the load, numbered from 22.
    struct Shape {
        guard: Option<i32>,
        source: IrType,
        extra: Vec<Expr>,
        load_offset: u32,
    }

    impl Default for Shape {
        fn default() -> Self {
            Shape {
                guard: Some(4),
                source: IrType::Unknown(UnknownReason::InsufficientEvidence),
                extra: Vec::new(),
                load_offset: 8,
            }
        }
    }

    fn build(shape: Shape) -> HighFunction {
        let mut exprs: Vec<(Expr, IrType)> = Vec::new();
        let untyped = || IrType::Unknown(UnknownReason::InsufficientEvidence);
        let mut push = |e: Expr, t: IrType| exprs.push((e, t));
        push(Expr::GlobalGet { index: 0 }, untyped()); // v0
        push(Expr::Literal(Literal::I32(16)), untyped()); // v1
        push(Expr::Binary { op: BinaryOp::Sub, lhs: v(0), rhs: v(1) }, untyped()); // v2 fp
        push(global_set(v(2)), untyped()); // v3
        push(Expr::Phi { incoming: vec![] }, shape.source.clone()); // v4 bytes
        push(
            known(KnownOp::BufOp { kind: BufOpKind::BytesLen, args: vec![v(4)] }),
            IrType::Known(KnownType::U32),
        ); // v5
        push(Expr::Literal(Literal::I32(shape.guard.unwrap_or(4))), untyped()); // v6
        push(Expr::Binary { op: BinaryOp::Ne, lhs: v(5), rhs: v(6) }, untyped()); // v7
        push(Expr::Literal(Literal::I32(8)), untyped()); // v8
        push(Expr::Binary { op: BinaryOp::Add, lhs: v(2), rhs: v(8) }, untyped()); // v9 fp+8
        push(encode(v(9)), untyped()); // v10
        push(Expr::Literal(Literal::I64(4)), untyped()); // v11 U32Val 0
        push(Expr::Literal(Literal::I32(4)), untyped()); // v12
        push(encode(v(12)), untyped()); // v13
        push(
            known(KnownOp::BufOp { kind: BufOpKind::BytesCopyToLinearMemory, args: vec![v(4), v(11), v(10), v(13)] }),
            IrType::Known(KnownType::Unit),
        ); // v14
        push(load(v(2), shape.load_offset, MemWidth::W4, KnownType::I32), untyped()); // v15
        push(Expr::Binary { op: BinaryOp::Add, lhs: v(2), rhs: v(1) }, untyped()); // v16
        push(global_set(v(16)), untyped()); // v17
        // v18..v21: spare values for the extra bindings.
        push(Expr::Literal(Literal::I32(0)), untyped()); // v18
        push(Expr::Literal(Literal::I32(9)), untyped()); // v19
        push(Expr::Binary { op: BinaryOp::Add, lhs: v(2), rhs: v(19) }, untyped()); // v20 fp+9
        push(Expr::Literal(Literal::Unit), untyped()); // v21
        let extra_ids: Vec<u32> = (0..shape.extra.len() as u32).map(|i| 22 + i).collect();
        for e in shape.extra {
            push(e, untyped());
        }

        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        for (expr, ty) in exprs {
            let id = ValueId::from_index(bindings.len() as u32);
            bindings.push(Binding::new(id, ty, expr, Provenance::new("seed", ProvenanceSource::DataFlow, "seed")));
        }
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        let bb0 = BlockId::from_index(0);
        let bb1 = BlockId::from_index(1);
        let bb2 = BlockId::from_index(2);
        blocks.push(HighBlock { id: bb0, bindings: [0, 1, 2, 3, 5, 6, 7].into_iter().map(v).collect() });
        blocks.push(HighBlock { id: bb1, bindings: vec![] });
        let mut tail: Vec<u32> = vec![8, 9, 10, 11, 12, 13, 14];
        tail.extend(extra_ids);
        tail.extend([15, 16, 17]);
        blocks.push(HighBlock { id: bb2, bindings: tail.into_iter().map(v).collect() });
        let mut items = vec![Region::Basic(bb0)];
        if shape.guard.is_some() {
            items.push(Region::If {
                cond: v(7),
                then_region: Box::new(Region::Sequence(vec![Region::Basic(bb1), Region::Panic { kind: PanicKind::Bare }])),
                else_region: None,
            });
        }
        items.push(Region::Basic(bb2));
        items.push(Region::Return { values: vec![v(15)] });
        HighFunction {
            id: FuncId::from_index(0),
            name: None,
            signature: None,
            aliases: Vec::new(),
            blocks,
            bindings,
            region: Region::Sequence(items),
            params: vec![v(4)],
            returns: vec![vec![v(15)]],
        }
    }

    fn run(func: HighFunction) -> HighFunction {
        let mut ir = module(vec![func]);
        ByteArrayPass.run(&mut ir);
        ir.functions.remove(0)
    }

    fn filled(func: &HighFunction) -> Option<(ValueId, u32, ArrayFill)> {
        match &func.bindings.get(v(14))?.expr {
            Expr::Semantic(SemanticOp::Known(KnownOp::BytesToArray { bytes, len, form })) => Some((*bytes, *len, *form)),
            _ => None,
        }
    }

    #[test]
    fn a_guarded_copy_is_copy_into_slice_and_its_load_reads_the_array() {
        let out = run(build(Shape::default()));
        assert_eq!(filled(&out), Some((v(4), 4, ArrayFill::CopyIntoSlice)));
        assert_eq!(out.bindings.get(v(14)).map(|b| b.ty.clone()), Some(IrType::Known(KnownType::ByteArray(4))));
        assert!(matches!(
            out.bindings.get(v(15)).map(|b| &b.expr),
            Some(Expr::ArrayRead { array, offset: 0, width: MemWidth::W4, signed: None }) if *array == v(14)
        ));
        assert_eq!(out.bindings.get(v(15)).map(|b| b.ty.clone()), Some(IrType::Inferred(KnownType::I32)));
    }

    #[test]
    fn an_unguarded_bytes_source_is_left() {
        let out = run(build(Shape { guard: None, ..Shape::default() }));
        assert_eq!(filled(&out), None);
        assert!(matches!(out.bindings.get(v(15)).map(|b| &b.expr), Some(Expr::Load { .. })));
    }

    #[test]
    fn a_guard_on_another_length_proves_nothing() {
        let out = run(build(Shape { guard: Some(8), ..Shape::default() }));
        assert_eq!(filled(&out), None);
    }

    #[test]
    fn a_proven_bytes_n_needs_no_guard_and_spells_to_array() {
        let out = run(build(Shape { guard: None, source: IrType::Known(KnownType::BytesN(4)), ..Shape::default() }));
        assert_eq!(filled(&out), Some((v(4), 4, ArrayFill::ToArray)));
    }

    #[test]
    fn an_inferred_bytes_n_without_a_guard_is_left() {
        let out = run(build(Shape { guard: None, source: IrType::Inferred(KnownType::BytesN(4)), ..Shape::default() }));
        assert_eq!(filled(&out), None);
    }

    #[test]
    fn a_read_past_the_array_keeps_the_copy() {
        // Bytes 10..14: two of the copy's, two beyond it.
        let out = run(build(Shape { load_offset: 10, ..Shape::default() }));
        assert_eq!(filled(&out), None);
        assert!(matches!(out.bindings.get(v(15)).map(|b| &b.expr), Some(Expr::Load { .. })));
    }

    #[test]
    fn a_partial_overwrite_before_the_read_keeps_the_copy() {
        // `store8 fp+9 <- 0`: the load then sees one byte that is not the
        // array's and three that are.
        let store = Expr::Store { addr: v(20), value: v(18), offset: 0, width: MemWidth::W1 };
        let out = run(build(Shape { extra: vec![store], ..Shape::default() }));
        assert_eq!(filled(&out), None);
    }

    #[test]
    fn a_call_handed_the_buffer_keeps_the_copy() {
        // `func_7(fp+8)`: no function 7 in the module, so its reach is unknown.
        let call = Expr::Call { target: FuncId::from_index(7), args: vec![v(9)] };
        let out = run(build(Shape { extra: vec![call], ..Shape::default() }));
        assert_eq!(filled(&out), None);
    }

    #[test]
    fn a_constructor_over_the_buffer_is_from_array() {
        // `bytes_new(fp+8, 4)` right after the copy.
        let new = known(KnownOp::BytesNew { lm_pos: v(10), len: v(13), resolved: None, array: None });
        let out = run(build(Shape { extra: vec![new], ..Shape::default() }));
        assert_eq!(filled(&out).map(|f| f.2), Some(ArrayFill::CopyIntoSlice));
        assert!(matches!(
            out.bindings.get(v(22)).map(|b| &b.expr),
            Some(Expr::Semantic(SemanticOp::Known(KnownOp::BytesNew { array: Some(a), .. }))) if *a == v(14)
        ));
    }

    #[test]
    fn a_word_copy_of_the_array_is_from_array() {
        // `fp+12 <- load fp+8 (4)`, then `bytes_new(fp+12, 4)`: the buffer the
        // array was moved into.
        let extra = vec![
            Expr::Literal(Literal::I32(12)),                                           // v22
            Expr::Binary { op: BinaryOp::Add, lhs: v(2), rhs: v(22) },                 // v23 fp+12
            Expr::Store { addr: v(23), value: v(15), offset: 0, width: MemWidth::W4 }, // v24
            encode(v(23)),                                                             // v25
            known(KnownOp::BytesNew { lm_pos: v(25), len: v(13), resolved: None, array: None }), // v26
        ];
        let mut func = build(Shape { extra, ..Shape::default() });
        // The copy's load goes first: it is what the store reads.
        let block = func.blocks.get_mut(BlockId::from_index(2)).expect("bb2");
        block.bindings.retain(|b| *b != v(15));
        let at = block.bindings.iter().position(|b| *b == v(22)).expect("v22");
        block.bindings.insert(at, v(15));
        let out = run(func);
        assert!(matches!(out.bindings.get(v(15)).map(|b| &b.expr), Some(Expr::ArrayRead { .. })));
        assert!(matches!(
            out.bindings.get(v(26)).map(|b| &b.expr),
            Some(Expr::Semantic(SemanticOp::Known(KnownOp::BytesNew { array: Some(a), .. }))) if *a == v(14)
        ));
    }

    /// A function over `exprs` (ids `0..N`, all untyped but those in
    /// `typed`), its blocks' schedules, and its region.
    fn function(
        id: u32,
        exprs: Vec<Expr>,
        typed: &[(u32, IrType)],
        params: Vec<u32>,
        blocks: Vec<Vec<u32>>,
        region: Region,
        returns: Vec<Vec<u32>>,
    ) -> HighFunction {
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        for (i, expr) in exprs.into_iter().enumerate() {
            let ty = typed
                .iter()
                .find(|(t, _)| *t as usize == i)
                .map_or(IrType::Unknown(UnknownReason::InsufficientEvidence), |(_, ty)| ty.clone());
            let vid = ValueId::from_index(i as u32);
            bindings.push(Binding::new(vid, ty, expr, Provenance::new("seed", ProvenanceSource::DataFlow, "seed")));
        }
        let mut arena: Arena<BlockId, HighBlock> = Arena::new();
        for (i, schedule) in blocks.into_iter().enumerate() {
            arena.push(HighBlock { id: BlockId::from_index(i as u32), bindings: schedule.into_iter().map(v).collect() });
        }
        HighFunction {
            id: FuncId::from_index(id),
            name: None,
            signature: None,
            aliases: Vec::new(),
            blocks: arena,
            bindings,
            region,
            params: params.into_iter().map(v).collect(),
            returns: returns.into_iter().map(|r| r.into_iter().map(v).collect()).collect(),
        }
    }

    /// `func_0(out, bytes)`: `take::<4>` — the length guard, the host copy
    /// into `fp+8`, and `memcpy(out, fp+8, 4)` before the one return.
    fn take_helper() -> HighFunction {
        let exprs = vec![
            Expr::Phi { incoming: vec![] },                                             // v0 out
            Expr::Phi { incoming: vec![] },                                             // v1 bytes
            Expr::GlobalGet { index: 0 },                                               // v2
            Expr::Literal(Literal::I32(16)),                                            // v3
            Expr::Binary { op: BinaryOp::Sub, lhs: v(2), rhs: v(3) },                   // v4 fp
            global_set(v(4)),                                                           // v5
            known(KnownOp::BufOp { kind: BufOpKind::BytesLen, args: vec![v(1)] }),      // v6
            Expr::Literal(Literal::I32(4)),                                             // v7
            Expr::Binary { op: BinaryOp::Ne, lhs: v(6), rhs: v(7) },                    // v8
            Expr::Literal(Literal::I32(8)),                                             // v9
            Expr::Binary { op: BinaryOp::Add, lhs: v(4), rhs: v(9) },                   // v10 fp+8
            encode(v(10)),                                                              // v11
            Expr::Literal(Literal::I64(4)),                                             // v12
            Expr::Literal(Literal::I32(4)),                                             // v13
            encode(v(13)),                                                              // v14
            known(KnownOp::BufOp {
                kind: BufOpKind::BytesCopyToLinearMemory,
                args: vec![v(1), v(12), v(11), v(14)],
            }),                                                                         // v15
            Expr::Call { target: FuncId::from_index(2), args: vec![v(0), v(10), v(13)] }, // v16
            Expr::Binary { op: BinaryOp::Add, lhs: v(4), rhs: v(3) },                   // v17
            global_set(v(17)),                                                          // v18
        ];
        let region = Region::Sequence(vec![
            Region::Basic(BlockId::from_index(0)),
            Region::If {
                cond: v(8),
                then_region: Box::new(Region::Sequence(vec![
                    Region::Basic(BlockId::from_index(1)),
                    Region::Panic { kind: PanicKind::Bare },
                ])),
                else_region: None,
            },
            Region::Basic(BlockId::from_index(2)),
            Region::Return { values: vec![] },
        ]);
        function(
            0,
            exprs,
            &[(6, IrType::Known(KnownType::U32))],
            vec![0, 1],
            vec![vec![2, 3, 4, 5, 6, 7, 8], vec![], (9..=18).collect()],
            region,
            vec![vec![]],
        )
    }

    /// `func_1(bytes)`: `Bytes::from_array(&take::<4>(bytes))` — the helper
    /// handed `fp+8`, then `bytes_new(fp+8, 4)`; `extra` scheduled after.
    fn take_caller(extra: Vec<Expr>) -> HighFunction {
        let mut exprs = vec![
            Expr::Phi { incoming: vec![] },                                             // v0 bytes
            Expr::GlobalGet { index: 0 },                                               // v1
            Expr::Literal(Literal::I32(16)),                                            // v2
            Expr::Binary { op: BinaryOp::Sub, lhs: v(1), rhs: v(2) },                   // v3 fp
            global_set(v(3)),                                                           // v4
            Expr::Literal(Literal::I32(8)),                                             // v5
            Expr::Binary { op: BinaryOp::Add, lhs: v(3), rhs: v(5) },                   // v6 fp+8
            Expr::Call { target: FuncId::from_index(0), args: vec![v(6), v(0)] },        // v7
            encode(v(6)),                                                               // v8
            Expr::Literal(Literal::I32(4)),                                             // v9
            encode(v(9)),                                                               // v10
            known(KnownOp::BytesNew { lm_pos: v(8), len: v(10), resolved: None, array: None }), // v11
            Expr::Binary { op: BinaryOp::Add, lhs: v(3), rhs: v(2) },                   // v12
            global_set(v(12)),                                                          // v13
        ];
        let mut schedule: Vec<u32> = (1..=11).collect();
        for (i, e) in extra.into_iter().enumerate() {
            exprs.push(e);
            schedule.push(14 + i as u32);
        }
        schedule.extend([12, 13]);
        let region = Region::Sequence(vec![Region::Basic(BlockId::from_index(0)), Region::Return { values: vec![v(11)] }]);
        function(1, exprs, &[], vec![0], vec![schedule], region, vec![vec![11]])
    }

    /// `func_2`: the `memcpy` the fingerprint table names.
    fn memcpy_fn() -> HighFunction {
        let exprs = vec![
            Expr::Phi { incoming: vec![] },
            Expr::Phi { incoming: vec![] },
            Expr::Phi { incoming: vec![] },
            Expr::Store { addr: v(0), value: v(1), offset: 0, width: MemWidth::W1 },
        ];
        function(2, exprs, &[], vec![0, 1, 2], vec![vec![3]], Region::Basic(BlockId::from_index(0)), vec![vec![0]])
    }

    fn run_module(functions: Vec<HighFunction>) -> HighIr {
        let mut ir = module(functions);
        let memcpy = sordec_sigs::builtins::MEM_ROUTINES
            .iter()
            .find(|e| e.routine == MemRoutine::Memcpy)
            .map(|e| e.fingerprint.to_u128());
        ir.facts.function_fingerprints = vec![None, None, memcpy];
        ByteArrayPass.run(&mut ir);
        ir
    }

    #[test]
    fn a_helper_copying_its_array_to_an_out_parameter_returns_it() {
        let ir = run_module(vec![take_helper(), take_caller(Vec::new()), memcpy_fn()]);
        let helper = &ir.functions[0];
        assert_eq!(helper.params, vec![v(1)], "the out-parameter is gone");
        assert_eq!(helper.returns, vec![vec![v(15)]]);
        assert!(matches!(
            helper.bindings.get(v(15)).map(|b| &b.expr),
            Some(Expr::Semantic(SemanticOp::Known(KnownOp::BytesToArray { len: 4, form: ArrayFill::CopyIntoSlice, .. })))
        ));
        assert!(matches!(helper.bindings.get(v(16)).map(|b| &b.expr), Some(Expr::Literal(Literal::Unit))));
        let caller = &ir.functions[1];
        assert!(matches!(
            caller.bindings.get(v(7)).map(|b| (&b.expr, &b.ty)),
            Some((Expr::Call { args, .. }, IrType::Known(KnownType::ByteArray(4)))) if *args == vec![v(0)]
        ));
        assert!(matches!(
            caller.bindings.get(v(11)).map(|b| &b.expr),
            Some(Expr::Semantic(SemanticOp::Known(KnownOp::BytesNew { array: Some(a), .. }))) if *a == v(7)
        ));
    }

    #[test]
    fn a_caller_handing_the_result_on_keeps_the_helper() {
        // `func_9(fp+8)` after the constructor: a call nothing here can see
        // into may read the helper's bytes.
        let extra = vec![Expr::Call { target: FuncId::from_index(9), args: vec![v(6)] }];
        let ir = run_module(vec![take_helper(), take_caller(extra), memcpy_fn()]);
        assert_eq!(ir.functions[0].params, vec![v(0), v(1)]);
        assert!(matches!(ir.functions[0].bindings.get(v(16)).map(|b| &b.expr), Some(Expr::Call { .. })));
        assert!(matches!(ir.functions[1].bindings.get(v(7)).map(|b| &b.expr), Some(Expr::Call { args, .. }) if args.len() == 2));
    }
}
