//! `Option<T>` returned through an out-parameter — the shape
//! [`crate::memory::sret`] and [`super::option_sret`] both refuse.
//!
//! # The shape
//!
//! A helper returning "a value, or nothing" hands it back through a
//! pointer to its caller's frame: a **tag** written on every path, the
//! **value** written only on the paths that have one. `account`'s
//! `BytesN<32>::try_from_val`:
//!
//! ```text
//! fn func2(out, v) {                       caller:
//!     if !is_bytes(v)       { t = 1 }          func2(fp, v)
//!     else if len(v) != 32  { t = 1 }          if load(fp+0) & 1 == 0 {
//!     else { store out+8 <- v; t = 0 }             use load(fp+8)
//!     store out+0 <- t                         }
//! }
//! ```
//!
//! `memory::sret` refuses it because the absent paths have no value to
//! return, and `option_sret` takes only storage reads whose caller
//! `unwrap()`s. `plan/NOTES.md` ("W4", 2026-08-06) records why a
//! placeholder for the missing value is not an answer: a `todo!()` traps on
//! a live path, and a zero is a claim about every caller. The answer is the
//! sum type the source wrote.
//!
//! # The rewrite
//!
//! The helper returns `Option<T>`: each path builds its `Some(..)` or
//! `None` where it leaves, the merged tag carries it to the one `return`,
//! and the writes through the out-pointer retire with the parameter. Each
//! caller stops passing its frame: a read of the tag becomes the tag read
//! back from `is_some()` (or the test itself, when it is only branched on),
//! and a read of the value becomes `unwrap()` — placed only where a test on
//! the tag proves it present, so it never traps.
//!
//! A signature changes, so it is every call site or none, and none for a
//! helper an indirect call could reach (see *Gates*). It runs after the
//! elision group, so
//! [`super::option_sret`]'s `get(..).unwrap()` keeps every helper it can
//! take.
//!
//! # What makes a helper
//!
//! - Not exported (no spec signature).
//! - One parameter used only as a store address: the out-pointer.
//! - The tag written in one of two ways:
//!   - **Once, after the merge**: one store of a phi whose inputs are all
//!     constants. Each arm that assigns the phi is a path to the result.
//!   - **Once per arm**: no such store, and every path into the block
//!     where the paths meet stores its own constant to one slot, exactly
//!     once — the one slot every path stores a constant to. A path that
//!     meets the others without writing it, or writes it twice, refuses
//!     the helper. The rewrite builds the merge the first form already
//!     has: each arm's `Option`, carried on its edge into that block.
//!
//!   Either way, the other stores through the out-pointer on a path are its
//!   payload. Arms with a payload are *present*, arms without *absent*; one
//!   tag constant each, and different.
//! - Every present arm writes the same slots, and none of the values is a
//!   raw memory read: inside an `Option` its type would be pinned to a
//!   storage width the caller did not use. Nor a merge with such a read,
//!   or with an unrecognised host call's result, among its arms: its type
//!   would be pinned to whatever word its other arms happen to carry.
//! - After the merge, nothing but the tag store, constant stores and the
//!   shadow-stack epilogue.
//!
//! ## Why the tag written per arm is exact
//!
//! The argument is the same one, path by path. A path's stores through the
//! out-pointer are all it leaves in the result — the merge block after it
//! writes only constants, and nothing reads the out-pointer — so its one
//! tag store and its payload stores *are* the result on that path, and its
//! `Some(payload)` or `None` says the same. The new merge takes each
//! path's `Option` on the edge that path enters by, which is what the tag
//! phi of the first form does with its constants; every edge into the
//! block is such a path, so no path reaches the return without one.
//!
//! # What makes a call site
//!
//! Every read of the result's slots after the call is one of them exactly,
//! is reached by this call and no other write, and — for a value read — sits
//! where a test on the tag proves it present. Any other use of the frame by
//! another call refuses the site: the rewrite stops writing that memory,
//! and a callee reading it would see something else.
//!
//! A value read need not sit under its test in two shapes the compiler
//! makes of `get(&k).unwrap_or(0)`:
//!
//! - **A choice on the tag.** `n = select(load(fp+8), 0, load(fp+0))`
//!   picks the value when the tag says present and a fallback otherwise:
//!   that is `r.unwrap_or(0)`, and the read goes with it.
//! - **A read hoisted above its test.** `n = load(fp+8); if tag != 1 {
//!   .. } else { loop while i != n { .. } }` reads the value early and
//!   uses it only on the arm the test proves it present on. The read
//!   becomes `r.unwrap()` and moves to the start of that arm.
//!
//! ## Why it is exact
//!
//! The choice yields the value exactly when the tag is the present one,
//! and the fallback otherwise; `unwrap_or` yields the same, and the
//! fallback reads nothing of the call. The moved read is a pure function
//! of the call's result, so moving it changes no value; at its new place
//! the test has proved the value present, so it never traps; and every use
//! of it is in that arm, after the place it moves to.
//!
//! ## Its gates
//!
//! - The payload is one value, not the parts of a struct.
//! - A choice: every use of the read is a `select` whose condition the
//!   tag decides — one way for the present tag, the other for the absent
//!   one — taking the read on the present side; the other arm reads
//!   neither the call nor its slots.
//! - A hoisted read: no merge reads it, and every use, in a block or in
//!   the region, is inside the present arm of an `if` on the tag that
//!   follows the read in a sequence holding both (with nothing but scopes
//!   between); the arm starts with a block.
//!
//! # Gates
//!
//! The refusals that keep the two facts the rewrite rests on true.
//!
//! **Every caller is a direct call.** The helper stops taking its
//! out-pointer, so a caller this pass cannot see would still hand it one.
//!
//! - An indirect call can reach any function the module's element segments
//!   declare. When the module has one — recovered, or a raw `call_indirect`
//!   the pipeline left as it found it — a helper they declare keeps its
//!   signature, and so does every helper when the declared set could not
//!   be read. This is [`CallIndex::caller_set_complete`], the rule
//!   `memory::calls` gives `sret` one layer down; a helper outside the set
//!   has only the direct callers the census saw.
//! - A raw `call_indirect` handed a pointer into the frame is a call whose
//!   extent is unknown, like a recovered one: the site is refused.
//!
//! **The result is in the caller's own frame.** The out-pointer must point
//! into the caller's shadow-stack frame (`global.get 0` less a constant).
//! The census below counts what can read the result *inside* the caller;
//! memory reached through the caller's own out-pointer, or any pointer it
//! was handed or read, is also read by the caller's caller once it
//! returns, which no census here sees. `privacy_pools`' `BytesN<32>`
//! decoder hands its own out-pointer straight on to the length check, and
//! that one site would have let the length check stop writing a result
//! the decoder's callers read.
//!
//! **Nothing else sees the result's bytes.** Bulk memory operations
//! (`memory.copy`, `memory.fill`, here an `Unknown` of kind `MemoryOp`
//! taking `[destination, source or byte, length]`) count as the reads and
//! writes they are:
//!
//! - One with its source or destination in the frame and a length that is
//!   not a constant may touch any of it: the site is refused.
//! - A copy whose source overlaps the result reads it: refused, as for a
//!   call that may read it. A fill's second operand is a byte, not an
//!   address; reading it as one can only refuse more.
//! - A copy or fill whose destination overlaps the result writes it: a
//!   write a later read can see, like a store.
//! - Inside a callee handed the frame, a bulk operation on that pointer
//!   counts the same way, relative to the pointer: its destination is
//!   written and its second operand read, for its constant length. One
//!   whose length is not a constant, or whose operand derived from the
//!   pointer does not resolve to it plus a constant, makes what the callee
//!   touches unknown, and the site is refused. This is the premise the
//!   callee's loads and stores are counted under: only addresses built
//!   from the pointer reach the frame.
//! - A call to a `compiler_builtins` `memcpy`, `memmove` or `memset`, as
//!   [`crate::recognizers::mem_builtins::routine`] names it from the body's
//!   fingerprint, is counted as the bulk operation it is, from the call's
//!   own arguments `[destination, source or byte, length]` — at the call
//!   site, or inside a callee handed the frame. The routine's whole effect
//!   on memory is its contract: the destination's bytes for the length
//!   written, a copy's source read for as long. The scratch word its
//!   unaligned path uses lies below the stack pointer at the call, so in
//!   no frame of the caller's. Every other call keeps the reach its body
//!   shows.
//!
//! **A read sees all of one write.** A read's nearest write before it,
//! when that is a store or a bulk operation, must write every byte the
//! read takes. One that writes only some leaves the rest to an earlier
//! write — maybe the call's, which the rewrite removes — and refuses the
//! site. When the nearest write is another call (the next call to a
//! helper, reusing the slot), the read is taken to see that call's bytes:
//! what a call writes is known only as a range it may write, so this one
//! premise is not checked byte for byte.
//!
//! # What can read the result
//!
//! Only code that can run after the call, while the result's bytes are
//! still the helper's, can see them: the census of other calls and bulk
//! memory operations handed the frame (see *Gates*) is limited to that.
//!
//! - **What runs after** is read off the region tree: the rest of the
//!   call's block, the later items of each enclosing sequence control can
//!   still fall into, and the whole body of each enclosing loop it can go
//!   round ([`runs_after`]). More than can run, never less.
//! - **Written over on the straight line.** Once stores that every path
//!   falling on from the call runs have covered all of the result, nothing
//!   after them sees the helper's bytes. Counted only until paths merge at
//!   a scope's end or go round a loop, where the call may run again.
//! - **Written over before a reader.** A call that reads the result's
//!   range is allowed when its last write before it, on every path, is a
//!   store or a bulk copy covering the whole result: it reads that write.
//!
//! Why it is exact: memory a read cannot reach, or bytes written over
//! before it, are bytes whose content it never sees, so the rewrite no
//! longer writing them changes nothing it computes.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

use sordec_common::{BlockId, FuncId, IrId, Provenance, ProvenanceSource, UnknownReason, ValueId};
use sordec_ir::{
    BinaryOp, Binding, Expr, HighFunction, HighIr, IrType, KnownType, Literal, Region, UnaryOp,
    WasmOpcodeKind,
};

use super::result_out::is_frame;
use super::sret::emission_order;
use crate::dataflow::{block_containing, canon_addr, resolve_use, trace_int, CallIndex};
use crate::effects::expr_effects;
use crate::metrics_catalog::{
    MARSHALLING_OPTIONAL_OUT_HELPERS as M_HELPERS, MARSHALLING_OPTIONAL_OUT_REWRITTEN as M_REWRITTEN,
    MARSHALLING_OPTIONAL_OUT_SITES as M_SITES, MARSHALLING_OPTIONAL_OUT_SITES_REFUSED as M_SITES_REFUSED,
};
use crate::pass::{Pass, PassResult};
use crate::recognizers::mem_builtins::routine;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-optional-out";

/// How deep a tag test may be evaluated (`t & 1`, `== 0`, a rename, …).
const EVAL_DEPTH: usize = 6;

/// Rewrites `Option` out-parameter helpers to return `Option<T>`.
#[derive(Debug, Default, Clone, Copy)]
pub struct OptionalOutParamPass;

impl Pass<HighIr> for OptionalOutParamPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let mut helpers: HashMap<FuncId, Helper> = ir
            .functions
            .iter()
            .filter_map(|f| match classify(f) {
                Ok(h) => {
                    trace(f, "classified");
                    Some((f.id, h))
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
        let structs = ir.soroban_facts.as_ref().map(|f| f.types.structs.clone()).unwrap_or_default();
        for (id, helper) in &mut helpers {
            let (Some(parts), Some(func)) = (&helper.whole, ir.functions.iter().find(|f| f.id == *id)) else {
                continue;
            };
            let def = helper.arms.iter().find_map(|a| whole_of(func, a)).and_then(|base| {
                match &func.bindings.get(base)?.ty {
                    IrType::Known(KnownType::UserDefined(t)) | IrType::Inferred(KnownType::UserDefined(t)) => {
                        structs.iter().find(|s| s.id == *t)
                    }
                    _ => None,
                }
            });
            helper.part_types = parts
                .iter()
                .map(|(field, _)| {
                    let f = def?.fields.iter().find(|f| f.name == *field)?;
                    crate::type_infer::known_of_type_ref(&f.ty)
                })
                .collect();
        }

        // Census: every call site of every helper, planned or refused.
        let mut plans: HashMap<FuncId, Vec<(usize, SitePlan)>> = HashMap::new();
        let mut refused: HashSet<FuncId> = HashSet::new();
        {
            let frames = Frames { ir, helpers: &helpers, extents: RefCell::new(HashMap::new()) };
            for (index, caller) in ir.functions.iter().enumerate() {
                let order = emission_order(caller);
                for &id in &order {
                    let Some(Expr::Call { target, args }) = caller.bindings.get(id).map(|b| &b.expr) else {
                        continue;
                    };
                    let Some(helper) = helpers.get(target) else {
                        continue;
                    };
                    let planned = if *target == caller.id {
                        Err("the helper calls itself")
                    } else {
                        site(&frames, caller, &order, id, args, helper)
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
        }

        // The rewrite changes a signature, so it is every site or none — and
        // none for a helper an indirect call, recovered or raw, could reach:
        // its callers are more than the census saw.
        let calls = CallIndex::build(ir);
        let mut targets: Vec<FuncId> = plans.keys().copied().filter(|t| !refused.contains(t)).collect();
        targets.retain(|t| {
            let complete = calls.caller_set_complete(*t);
            if !complete && let Some(f) = ir.functions.iter().find(|f| f.id == *t) {
                trace(f, "kept: an indirect call may reach it");
            }
            complete
        });
        targets.sort_unstable();
        for target in targets {
            let helper = &helpers[&target];
            let Some(at) = ir.functions.iter().position(|f| f.id == target) else {
                continue;
            };
            let arity = ir.functions[at].params.len();
            for (index, plan) in &plans[&target] {
                if let Some(caller) = ir.functions.get_mut(*index) {
                    rewrite_site(caller, plan, helper);
                }
            }
            // A call no block schedules still names the old signature, and
            // the type pass reads every binding: drop its frame too.
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
            rewrite_helper(&mut ir.functions[at], helper);
            result.metrics.increment(M_REWRITTEN, 1);
            result.changed = true;
        }
        result
    }
}

/// Print a classification line when `SORDEC_OPTION_TRACE` is set — the
/// switch [`super::option_sret`] already reads.
#[allow(clippy::print_stderr)]
fn trace(func: &HighFunction, what: &str) {
    if std::env::var_os("SORDEC_OPTION_TRACE").is_some() {
        eprintln!("optional-out: func_{}: {what}", func.id.index());
    }
}

// ---------------------------------------------------------------------
// The helper
// ---------------------------------------------------------------------

/// No tag-shaped store at all: an ordinary function, not worth a line.
const NOT_A_CANDIDATE: &str = "no tag store";

/// One slot of the out-parameter, as an offset and a width in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct Slot {
    offset: u32,
    bytes: u32,
}

impl Slot {
    fn overlaps(self, other: Slot) -> bool {
        self.offset < other.offset + other.bytes && other.offset < self.offset + self.bytes
    }

    fn shifted(self, by: u32) -> Option<Slot> {
        Some(Slot { offset: self.offset.checked_add(by)?, bytes: self.bytes })
    }
}

/// A store through the out-pointer: the binding, its slot, the value.
type Store = (ValueId, Slot, ValueId);

/// One path to the result: the tag it sets, the stores on its way, and the
/// block it leaves from — where the rewrite builds its `Option`.
struct Arm {
    tag: i128,
    stores: Vec<Store>,
    pred: BlockId,
}

/// A helper proven to return `Option<T>` through an out-parameter.
struct Helper {
    /// Which parameter is the out-pointer.
    out: usize,
    tag: Slot,
    present: i128,
    absent: i128,
    /// The value's slots, ascending, each with the type stored there.
    payload: Vec<(Slot, IrType)>,
    /// Slots written with the same constant whatever the path.
    consts: Vec<(Slot, Literal)>,
    arms: Vec<Arm>,
    /// Where the paths' tags meet, which becomes the returned `Option`.
    merge: Merge,
    /// Everything that writes through the out-pointer or computes an
    /// address into it, retired by the rewrite.
    retired: Vec<ValueId>,
    /// When every present arm writes nothing but fields of one struct
    /// value — a decoded `MinterConfig` copied out field by field, an
    /// `i128` field as its two halves — that struct is the payload, and
    /// each slot is a part of it: `(field, half)`, by payload component.
    whole: Option<Vec<(String, Option<UnaryOp>)>>,
    /// The declared type of each of those fields, filled from the spec.
    part_types: Vec<Option<KnownType>>,
}

/// How a helper's paths hand their tag to the one return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Merge {
    /// A phi of the arms' tag constants, stored once after they meet.
    Phi(ValueId),
    /// Each arm stores its own tag constant before the paths meet at this
    /// block; the rewrite builds the merge.
    PerArm(BlockId),
}

impl Helper {
    fn slots(&self) -> impl Iterator<Item = Slot> + '_ {
        std::iter::once(self.tag)
            .chain(self.payload.iter().map(|(s, _)| *s))
            .chain(self.consts.iter().map(|(s, _)| *s))
    }
}

fn classify(func: &HighFunction) -> Result<Helper, &'static str> {
    if func.signature.is_some() {
        return Err(NOT_A_CANDIDATE);
    }
    let order = emission_order(func);

    // The tag store: through a parameter, of a phi of constants.
    let mut tag = None;
    for &id in &order {
        let Some(Expr::Store { addr, value, offset, width }) = func.bindings.get(id).map(|b| &b.expr) else {
            continue;
        };
        let (base, off) = canon_addr(func, *addr);
        let Some(out) = func.params.iter().position(|p| *p == base) else {
            continue;
        };
        let phi = resolve_use(func, *value);
        let Some(Expr::Phi { incoming }) = func.bindings.get(phi).map(|b| &b.expr) else {
            continue;
        };
        if incoming.is_empty() || !incoming.iter().all(|(_, v)| trace_int(func, *v).is_some()) {
            continue;
        }
        let slot = Slot { offset: off.checked_add(*offset).ok_or(NOT_A_CANDIDATE)?, bytes: width.bytes() };
        if tag.replace((id, out, base, phi, slot)).is_some() {
            return Err("two tag-shaped stores");
        }
    }
    // Without one, each arm may store its own constant tag: the out-pointer
    // is then the one parameter anything is stored through, and the tag
    // the one slot every arm stores a constant to (settled after the walk).
    let (merged, out, out_param) = match tag {
        Some((store, out, base, phi, slot)) => (Some((store, phi, slot)), out, base),
        None => {
            let mut through: Option<(usize, ValueId)> = None;
            for &id in &order {
                let Some(Expr::Store { addr, .. }) = func.bindings.get(id).map(|b| &b.expr) else {
                    continue;
                };
                let base = canon_addr(func, *addr).0;
                if let Some(i) = func.params.iter().position(|p| *p == base)
                    && through.replace((i, base)).is_some_and(|(prev, _)| prev != i)
                {
                    return Err("stores through two parameters");
                }
            }
            let (out, base) = through.ok_or(NOT_A_CANDIDATE)?;
            (None, out, base)
        }
    };
    if escapes(func, &order, out_param) {
        return Err("the out-pointer is used other than as a store address");
    }

    let mut walk = Walk {
        func,
        out_param,
        tag_store: merged.map(|(store, _, _)| store),
        tag_phi: merged.map(|(_, phi, _)| phi),
        join: None,
        arms: Vec::new(),
        pending: HashMap::new(),
        tail: None,
        last: None,
    };
    walk.region(&func.region, Flow::Falls(Vec::new()))?;
    let tail = walk.tail.take().ok_or("no merge after the arms")?;
    let join = walk.join.ok_or("no merge after the arms")?;
    let mut arms = std::mem::take(&mut walk.arms);
    let (merge, tag_slot) = match merged {
        Some((_, tag_phi, tag_slot)) => {
            let Some(Expr::Phi { incoming }) = func.bindings.get(tag_phi).map(|b| &b.expr) else {
                return Err("the tag is not a phi");
            };
            let mut preds: Vec<BlockId> = arms.iter().map(|a| a.pred).collect();
            let mut inputs: Vec<BlockId> = incoming.iter().map(|(b, _)| *b).collect();
            preds.sort_unstable();
            inputs.sort_unstable();
            if preds != inputs || preds.windows(2).any(|w| w[0] == w[1]) {
                return Err("the merge's inputs do not match its arms");
            }
            (Merge::Phi(tag_phi), tag_slot)
        }
        None => (Merge::PerArm(join), per_arm_tags(func, join, &mut arms)?),
    };

    let (present, absent): (Vec<&Arm>, Vec<&Arm>) = arms.iter().partition(|a| !a.stores.is_empty());
    let present_tag = single(present.iter().map(|a| a.tag)).ok_or("present arms disagree on the tag")?;
    let absent_tag = single(absent.iter().map(|a| a.tag)).ok_or("absent arms disagree on the tag")?;
    if present_tag == absent_tag {
        return Err("present and absent share a tag");
    }

    // Every present arm writes the same slots, once each, of known types.
    let mut payload: Vec<(Slot, IrType)> = Vec::new();
    for (i, arm) in present.iter().enumerate() {
        let mut slots: Vec<(Slot, IrType)> = Vec::new();
        for &(_, slot, value) in &arm.stores {
            if slots.iter().any(|(s, _)| s.overlaps(slot)) {
                return Err("an arm writes one slot twice");
            }
            if slot.overlaps(tag_slot) {
                return Err("a payload store overlaps the tag");
            }
            // Types are not a gate here: this runs before `type_infer`, so
            // most values are still untyped. The rewrite settles the
            // payload type after inference.
            let ty = func.bindings.get(value).map(|b| b.ty.clone()).ok_or("a stored value has no binding")?;
            slots.push((slot, ty));
        }
        slots.sort_by_key(|(s, _)| *s);
        if i == 0 {
            payload = slots;
        } else if slots.iter().map(|(s, _)| *s).ne(payload.iter().map(|(s, _)| *s)) {
            return Err("present arms write different slots");
        } else if slots
            .iter()
            .zip(&payload)
            .any(|((_, a), (_, b))| matches!((known(a), known(b)), (Some(x), Some(y)) if x != y))
        {
            return Err("present arms store different types in one slot");
        }
    }
    // A value read raw out of memory has no type of its own. As a hole it
    // takes whatever its use needs; inside an `Option` it is pinned to a
    // storage width (`i32` where the field is a `u32`, `Val` where it is a
    // limb), and the caller stops compiling. Left as it is until the
    // memory it comes from is recovered. So is a merge with such a value
    // among its arms, or with an unrecognised host call's result: the
    // merge then has only its other arms' words to be typed by. `bls`'s
    // field reduction merges its `U256` parameter, typed `i64` by its tag
    // tests, with an unrecognised `u256_rem_euclid`, and became an
    // `Option<i64>` returned where the spec says `U256`.
    if present.iter().flat_map(|a| &a.stores).any(|(_, _, v)| untyped_payload(func, *v, MERGE_DEPTH)) {
        return Err("a value read raw out of memory");
    }
    if tail.iter().any(|(s, _)| payload.iter().any(|(p, _)| p.overlaps(*s)) || s.overlaps(tag_slot)) {
        return Err("a constant store overlaps the result");
    }

    let whole = struct_parts(func, &present);
    let retired = order
        .iter()
        .copied()
        .filter(|id| match func.bindings.get(*id).map(|b| &b.expr) {
            Some(Expr::Store { addr, .. }) => canon_addr(func, *addr).0 == out_param,
            Some(Expr::Binary { op: BinaryOp::Add, .. }) => *id != out_param && canon_addr(func, *id).0 == out_param,
            _ => false,
        })
        .collect();
    Ok(Helper {
        out,
        tag: tag_slot,
        present: present_tag,
        absent: absent_tag,
        payload,
        consts: tail,
        arms,
        merge,
        retired,
        whole,
        part_types: Vec::new(),
    })
}

/// The tag slot of a helper whose arms each store their own tag, and each
/// arm's tag, taken out of its stores: the one slot every arm stores a
/// constant to, exactly once. Every edge into the merge must be an arm —
/// a path that meets the others without writing the tag has no `Option`
/// to hand back.
fn per_arm_tags(func: &HighFunction, join: BlockId, arms: &mut [Arm]) -> Result<Slot, &'static str> {
    let mut edges = 0usize;
    func.region.for_each_node(|node| {
        if let Region::Break { target, .. } | Region::Transfer { target, .. } = node {
            edges += usize::from(*target == join);
        }
    });
    if edges != arms.len() {
        return Err("a path reaches the merge without setting the tag");
    }
    let constant = |store: &Store| trace_int(func, store.2).is_some();
    let mut candidates: Option<Vec<Slot>> = None;
    for arm in arms.iter() {
        let mine: Vec<Slot> = arm.stores.iter().filter(|s| constant(s)).map(|s| s.1).collect();
        candidates = Some(match candidates {
            None => mine,
            Some(prev) => prev.into_iter().filter(|s| mine.contains(s)).collect(),
        });
    }
    let mut candidates = candidates.unwrap_or_default();
    candidates.sort_unstable();
    candidates.dedup();
    let [slot] = candidates[..] else {
        return Err(if candidates.is_empty() { "a path writes no tag" } else { "more than one slot could be the tag" });
    };
    for arm in arms.iter_mut() {
        let at: Vec<usize> = (0..arm.stores.len()).filter(|&i| arm.stores[i].1 == slot).collect();
        let [i] = at[..] else {
            return Err("a path writes the tag twice");
        };
        let (_, _, value) = arm.stores.remove(i);
        arm.tag = trace_int(func, value).ok_or("the tag is not a constant")?;
    }
    Ok(slot)
}

/// How many merges deep [`untyped_payload`] looks.
const MERGE_DEPTH: u32 = 3;

/// Whether `value` has no type of its own to hand a caller: a raw read of
/// memory, an unrecovered operation, or, inside a merge `depth` merges
/// deep, an unrecognised host call's result.
fn untyped_payload(func: &HighFunction, value: ValueId, depth: u32) -> bool {
    match func.bindings.get(resolve_use(func, value)).map(|b| &b.expr) {
        Some(Expr::Load { .. } | Expr::Unknown { .. }) => true,
        Some(Expr::Phi { incoming }) if depth > 0 => incoming.iter().any(|(_, v)| {
            matches!(
                func.bindings.get(resolve_use(func, *v)).map(|b| &b.expr),
                Some(Expr::Semantic(sordec_ir::SemanticOp::Unknown { .. }))
            ) || untyped_payload(func, *v, depth - 1)
        }),
        _ => false,
    }
}

/// A field of a struct value, or one half of a wide one: `(value, field,
/// half)`.
fn part_of(func: &HighFunction, value: ValueId) -> Option<(ValueId, String, Option<UnaryOp>)> {
    let field = |v: ValueId| match &func.bindings.get(resolve_use(func, v))?.expr {
        Expr::Field { base, field } => Some((resolve_use(func, *base), field.clone())),
        _ => None,
    };
    match &func.bindings.get(resolve_use(func, value))?.expr {
        Expr::Unary { op: op @ (UnaryOp::WideLo | UnaryOp::WideHi), value } => {
            field(*value).map(|(base, f)| (base, f, Some(*op)))
        }
        _ => field(value).map(|(base, f)| (base, f, None)),
    }
}

/// The parts of one struct value every present arm writes, in payload
/// order, when each arm writes nothing else — see [`Helper::whole`].
fn struct_parts(func: &HighFunction, present: &[&Arm]) -> Option<Vec<(String, Option<UnaryOp>)>> {
    let mut agreed: Option<Vec<(String, Option<UnaryOp>)>> = None;
    for arm in present {
        let mut stores = arm.stores.clone();
        stores.sort_by_key(|(_, slot, _)| *slot);
        let mut base: Option<ValueId> = None;
        let mut parts = Vec::new();
        for (_, _, value) in &stores {
            let (b, field, half) = part_of(func, *value)?;
            if base.replace(b).is_some_and(|prev| prev != b) {
                return None;
            }
            parts.push((field, half));
        }
        if agreed.replace(parts.clone()).is_some_and(|prev| prev != parts) {
            return None;
        }
    }
    agreed.filter(|p| !p.is_empty())
}

/// The struct value an arm's stores are parts of.
fn whole_of(func: &HighFunction, arm: &Arm) -> Option<ValueId> {
    arm.stores.first().and_then(|(_, _, v)| part_of(func, *v)).map(|(base, _, _)| base)
}

/// The one value an iterator yields, if it yields exactly one (repeats
/// allowed).
fn single(mut values: impl Iterator<Item = i128>) -> Option<i128> {
    let first = values.next()?;
    values.all(|v| v == first).then_some(first)
}

fn known(ty: &IrType) -> Option<&sordec_ir::KnownType> {
    match ty {
        IrType::Known(t) | IrType::Inferred(t) => Some(t),
        _ => None,
    }
}

/// Whether `param` is read by anything but the address of a store — or
/// address arithmetic feeding one.
pub(super) fn escapes(func: &HighFunction, order: &[ValueId], param: ValueId) -> bool {
    let mut derived: HashSet<ValueId> = HashSet::from([param]);
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
            Expr::Binary { op: BinaryOp::Add, .. } if derived.contains(&id) => true,
            Expr::Use(v) if is_derived(*v) => {
                // A rename of an address is itself an address.
                true
            }
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

/// Where control can be at the end of a region, for the walk below.
#[derive(Debug, Clone, PartialEq)]
enum Flow {
    /// Falls through, having stored these through the out-pointer.
    Falls(Vec<Store>),
    /// Every path reached the merge, each recorded as an arm.
    Joined,
    /// No path continues (return, trap, a break recorded elsewhere).
    Leaves,
}

/// Join two flows that meet after a branch.
fn merge(a: Flow, b: Flow) -> Result<Flow, &'static str> {
    Ok(match (a, b) {
        (Flow::Leaves, x) | (x, Flow::Leaves) => x,
        (Flow::Joined, Flow::Joined) => Flow::Joined,
        (Flow::Joined, f @ Flow::Falls(_)) | (f @ Flow::Falls(_), Flow::Joined) => f,
        (Flow::Falls(a), Flow::Falls(b)) if a == b => Flow::Falls(a),
        (Flow::Falls(_), Flow::Falls(_)) => {
            return Err("a store through the out-pointer on one side of a branch that rejoins");
        }
    })
}

/// Walks the helper's region tree, recording each path to the merge.
struct Walk<'f> {
    func: &'f HighFunction,
    out_param: ValueId,
    /// The one tag store after the merge, and the phi it stores; `None`
    /// when each arm stores its own tag.
    tag_store: Option<ValueId>,
    tag_phi: Option<ValueId>,
    /// The block the tag phi belongs to, once an edge into it is seen.
    join: Option<BlockId>,
    arms: Vec<Arm>,
    /// Paths breaking to a scope that is not the merge, by its label.
    pending: HashMap<BlockId, Vec<Vec<Store>>>,
    /// The constant stores after the merge, once the merge is walked.
    tail: Option<Vec<(Slot, Literal)>>,
    /// The last block on the current path: the source of an edge met next.
    last: Option<BlockId>,
}

impl Walk<'_> {
    fn region(&mut self, region: &Region, flow: Flow) -> Result<Flow, &'static str> {
        let path = match flow {
            Flow::Falls(path) => path,
            // Only the merge's own block may follow the arms.
            Flow::Joined => {
                return match region {
                    Region::Basic(b) if Some(*b) == self.join => self.tail(*b),
                    Region::Return { values } if values.is_empty() && self.tail.is_some() => Ok(Flow::Leaves),
                    Region::Sequence(items) => {
                        let mut flow = Flow::Joined;
                        for item in items {
                            if flow == Flow::Leaves {
                                break;
                            }
                            flow = self.region(item, flow)?;
                        }
                        Ok(flow)
                    }
                    _ => Err("code between the arms and the merge"),
                };
            }
            Flow::Leaves => return Ok(Flow::Leaves),
        };
        match region {
            Region::Basic(b) => {
                if Some(*b) == self.join {
                    return Err("a path reaches the merge without setting the tag");
                }
                let mut path = path;
                self.last = Some(*b);
                for &id in &self.func.blocks.get(*b).ok_or("a missing block")?.bindings {
                    if let Some(store) = self.store(id)? {
                        path.push(store);
                    }
                }
                Ok(Flow::Falls(path))
            }
            Region::Sequence(items) => {
                let mut flow = Flow::Falls(path);
                for item in items {
                    if flow == Flow::Leaves {
                        break;
                    }
                    flow = self.region(item, flow)?;
                }
                Ok(flow)
            }
            Region::Scope { out, body } => {
                let body = self.region(body, Flow::Falls(path))?;
                let mut flow = body;
                for p in self.pending.remove(out).unwrap_or_default() {
                    flow = merge(flow, Flow::Falls(p))?;
                }
                self.last = None;
                Ok(flow)
            }
            Region::If { then_region, else_region, .. } => {
                let entry = self.last;
                let t = self.region(then_region, Flow::Falls(path.clone()))?;
                self.last = entry;
                let e = match else_region {
                    Some(e) => self.region(e, Flow::Falls(path))?,
                    None => Flow::Falls(path),
                };
                self.last = None;
                merge(t, e)
            }
            Region::Switch { arms, default, .. } => {
                let entry = self.last;
                let mut flow = self.region(default, Flow::Falls(path.clone()))?;
                for arm in arms {
                    self.last = entry;
                    let f = self.region(&arm.body, Flow::Falls(path.clone()))?;
                    flow = merge(flow, f)?;
                }
                self.last = None;
                Ok(flow)
            }
            Region::Break { target, transfer } | Region::Transfer { target, transfer } => {
                // An arm's edge: one carrying the tag phi, or — when each
                // arm stores its own tag — one leaving a path that wrote
                // through the out-pointer. Its tag is settled after the walk.
                let arm = match self.tag_phi {
                    Some(phi) => transfer.iter().find(|(p, _)| *p == phi).map(|&(_, v)| Some(v)),
                    None => (!path.is_empty()).then_some(None),
                };
                if let Some(carried) = arm {
                    if self.join.is_some_and(|j| j != *target) {
                        return Err("the tag merges in two places");
                    }
                    self.join = Some(*target);
                    if transfer.len() != usize::from(carried.is_some()) {
                        return Err("the merge carries more than the tag");
                    }
                    let tag = match carried {
                        Some(v) => trace_int(self.func, v).ok_or("the tag is not a constant")?,
                        None => 0,
                    };
                    let pred = self.last.ok_or("an edge into the merge from an unknown block")?;
                    self.arms.push(Arm { tag, stores: path, pred });
                    return Ok(Flow::Joined);
                }
                if Some(*target) == self.join {
                    return Err("an edge into the merge that does not set the tag");
                }
                if matches!(region, Region::Transfer { .. }) {
                    Ok(Flow::Falls(path))
                } else {
                    self.pending.entry(*target).or_default().push(path);
                    Ok(Flow::Leaves)
                }
            }
            Region::Loop { body, .. } => {
                if self.writes_inside(body) {
                    return Err("the out-pointer is written inside a loop");
                }
                self.last = None;
                Ok(Flow::Falls(path))
            }
            Region::Continue { .. } | Region::Panic { .. } | Region::Unreachable => Ok(Flow::Leaves),
            Region::Return { .. } => Err("a return before the tag is set"),
            Region::Unstructured { .. } => Err("unstructured control flow"),
        }
    }

    /// The merge block: the tag store, constant stores, and the epilogue.
    fn tail(&mut self, block: BlockId) -> Result<Flow, &'static str> {
        let mut consts = Vec::new();
        let mut tag_seen = false;
        for &id in &self.func.blocks.get(block).ok_or("a missing block")?.bindings {
            if Some(id) == self.tag_store {
                tag_seen = true;
                continue;
            }
            if let Some((_, slot, value)) = self.store(id)? {
                let lit = literal(self.func, value).ok_or("a store after the merge that is not a constant")?;
                consts.push((slot, lit));
                continue;
            }
            let expr = &self.func.bindings.get(id).ok_or("a missing binding")?.expr;
            let epilogue = matches!(expr, Expr::Unknown { op_kind: sordec_ir::WasmOpcodeKind::GlobalSet, .. });
            if !epilogue && !expr_effects(expr).is_pure_total() {
                return Err("the merge does more than finish the result");
            }
        }
        if self.tag_store.is_some() && !tag_seen {
            return Err("the tag is stored outside the merge");
        }
        self.tail = Some(consts);
        Ok(Flow::Joined)
    }

    /// The store through the out-pointer at `id`, if it is one.
    fn store(&self, id: ValueId) -> Result<Option<Store>, &'static str> {
        let Some(Expr::Store { addr, value, offset, width }) = self.func.bindings.get(id).map(|b| &b.expr) else {
            return Ok(None);
        };
        let (base, off) = canon_addr(self.func, *addr);
        if base != self.out_param {
            return Ok(None);
        }
        if Some(id) == self.tag_store {
            return Err("the tag is stored before the merge");
        }
        let offset = off.checked_add(*offset).ok_or("an offset overflows")?;
        Ok(Some((id, Slot { offset, bytes: width.bytes() }, resolve_use(self.func, *value))))
    }

    fn writes_inside(&self, region: &Region) -> bool {
        let mut writes = false;
        region.for_each_node(|node| {
            if let Region::Basic(b) = node
                && let Some(block) = self.func.blocks.get(*b)
            {
                writes |= block.bindings.iter().any(|id| matches!(self.store(*id), Ok(Some(_)) | Err(_)));
            }
        });
        writes
    }
}

fn literal(func: &HighFunction, value: ValueId) -> Option<Literal> {
    match &func.bindings.get(resolve_use(func, value))?.expr {
        Expr::Literal(lit) => Some(lit.clone()),
        _ => None,
    }
}

// ---------------------------------------------------------------------
// The rewrite
// ---------------------------------------------------------------------

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

/// Schedule `new` next to `anchor` in `anchor`'s block, before or after it.
fn place(func: &mut HighFunction, anchor: ValueId, new: ValueId, after: bool) {
    let Some(block) = block_containing(func, anchor).and_then(|b| func.blocks.get_mut(b)) else {
        return;
    };
    if let Some(at) = block.bindings.iter().position(|b| *b == anchor) {
        block.bindings.insert(at + usize::from(after), new);
    }
}

/// Replace `id`'s expression, resetting its type for `type_infer` to settle.
fn rewrite(func: &mut HighFunction, id: ValueId, expr: Expr, ty: Option<IrType>, note: &str) {
    if let Some(binding) = func.bindings.get_mut(id) {
        binding.expr = expr;
        if let Some(ty) = ty {
            binding.ty = ty;
        }
        binding.add_provenance(Provenance::new(PASS_NAME, ProvenanceSource::SdkPattern, note.to_string()));
    }
}

fn untyped() -> IrType {
    IrType::Unknown(UnknownReason::InsufficientEvidence)
}

/// The helper returns its `Option` instead of writing it.
fn rewrite_helper(func: &mut HighFunction, helper: &Helper) {
    // One `Option` per arm, built where the arm leaves.
    let mut by_pred: HashMap<BlockId, ValueId> = HashMap::new();
    for arm in &helper.arms {
        let payload = (!arm.stores.is_empty()).then(|| match (&helper.whole, whole_of(func, arm)) {
            (Some(_), Some(value)) => vec![value],
            _ => {
                let mut stores = arm.stores.clone();
                stores.sort_by_key(|(_, slot, _)| *slot);
                stores.into_iter().map(|(_, _, value)| value).collect()
            }
        });
        let note = if payload.is_some() {
            "the value this path wrote through the out-pointer, returned as `Some`"
        } else {
            "this path wrote no value through the out-pointer: `None`"
        };
        let id = push(func, Expr::Optional { payload }, untyped(), note);
        if let Some(block) = func.blocks.get_mut(arm.pred) {
            block.bindings.push(id);
        }
        by_pred.insert(arm.pred, id);
    }

    let merged = match helper.merge {
        // The merged tag becomes the merged `Option`.
        Merge::Phi(tag_phi) => {
            if let Some(binding) = func.bindings.get_mut(tag_phi)
                && let Expr::Phi { incoming } = &mut binding.expr
            {
                for (pred, value) in incoming.iter_mut() {
                    if let Some(option) = by_pred.get(pred) {
                        *value = *option;
                    }
                }
                binding.ty = untyped();
                binding.add_provenance(Provenance::new(
                    PASS_NAME,
                    ProvenanceSource::SdkPattern,
                    "the out-parameter's tag, merged as the `Option` it encoded",
                ));
            }
            retarget(&mut func.region, &mut None, tag_phi, &by_pred);
            tag_phi
        }
        // Each arm wrote its own tag: the `Option`s meet in a new merge,
        // carried on each arm's edge into the block where the paths meet.
        Merge::PerArm(join) => {
            let mut incoming: Vec<(BlockId, ValueId)> = by_pred.iter().map(|(b, o)| (*b, *o)).collect();
            incoming.sort_unstable();
            let phi = push(
                func,
                Expr::Phi { incoming },
                untyped(),
                "the `Option` each path wrote through the out-parameter, merged where the paths meet",
            );
            attach(&mut func.region, &mut None, join, phi, &by_pred);
            phi
        }
    };

    for &id in &helper.retired {
        rewrite(
            func,
            id,
            Expr::Literal(Literal::Unit),
            Some(IrType::Known(KnownType::Unit)),
            "out-parameter write, now the returned `Option`",
        );
    }
    give_back(&mut func.region, merged);
    for site in &mut func.returns {
        *site = vec![merged];
    }
    if helper.out < func.params.len() {
        func.params.remove(helper.out);
    }
}

/// Point every edge into the merge at its arm's `Option` instead of a tag.
fn retarget(region: &mut Region, last: &mut Option<BlockId>, tag_phi: ValueId, by_pred: &HashMap<BlockId, ValueId>) {
    match region {
        Region::Basic(b) => *last = Some(*b),
        Region::Sequence(items) => {
            for item in items {
                retarget(item, last, tag_phi, by_pred);
            }
        }
        Region::Scope { body, .. } | Region::Loop { body, .. } => {
            retarget(body, last, tag_phi, by_pred);
            *last = None;
        }
        Region::If { then_region, else_region, .. } => {
            let entry = *last;
            retarget(then_region, last, tag_phi, by_pred);
            *last = entry;
            if let Some(e) = else_region {
                retarget(e, last, tag_phi, by_pred);
            }
            *last = None;
        }
        Region::Switch { arms, default, .. } => {
            let entry = *last;
            retarget(default, last, tag_phi, by_pred);
            for arm in arms {
                *last = entry;
                retarget(&mut arm.body, last, tag_phi, by_pred);
            }
            *last = None;
        }
        Region::Break { transfer, .. } | Region::Transfer { transfer, .. } => {
            for (phi, value) in transfer.iter_mut() {
                if *phi == tag_phi
                    && let Some(option) = last.and_then(|b| by_pred.get(&b))
                {
                    *value = *option;
                }
            }
        }
        _ => {}
    }
}

/// Carry each arm's `Option` into `phi` on the arm's edge into `join`.
fn attach(region: &mut Region, last: &mut Option<BlockId>, join: BlockId, phi: ValueId, by_pred: &HashMap<BlockId, ValueId>) {
    match region {
        Region::Basic(b) => *last = Some(*b),
        Region::Sequence(items) => {
            for item in items {
                attach(item, last, join, phi, by_pred);
            }
        }
        Region::Scope { body, .. } | Region::Loop { body, .. } => {
            attach(body, last, join, phi, by_pred);
            *last = None;
        }
        Region::If { then_region, else_region, .. } => {
            let entry = *last;
            attach(then_region, last, join, phi, by_pred);
            *last = entry;
            if let Some(e) = else_region {
                attach(e, last, join, phi, by_pred);
            }
            *last = None;
        }
        Region::Switch { arms, default, .. } => {
            let entry = *last;
            attach(default, last, join, phi, by_pred);
            for arm in arms {
                *last = entry;
                attach(&mut arm.body, last, join, phi, by_pred);
            }
            *last = None;
        }
        Region::Break { target, transfer } | Region::Transfer { target, transfer } => {
            if *target == join
                && let Some(option) = last.and_then(|b| by_pred.get(&b))
            {
                transfer.push((phi, *option));
            }
        }
        _ => {}
    }
}

/// Every bare `return` hands the `Option` back.
pub(super) fn give_back(region: &mut Region, value: ValueId) {
    match region {
        Region::Return { values } if values.is_empty() => values.push(value),
        Region::Sequence(items) => items.iter_mut().for_each(|r| give_back(r, value)),
        Region::Scope { body, .. } | Region::Loop { body, .. } => give_back(body, value),
        Region::If { then_region, else_region, .. } => {
            give_back(then_region, value);
            if let Some(e) = else_region {
                give_back(e, value);
            }
        }
        Region::Switch { arms, default, .. } => {
            arms.iter_mut().for_each(|a| give_back(&mut a.body, value));
            give_back(default, value);
        }
        _ => {}
    }
}

/// The call yields the `Option`; its reads become questions about it.
fn rewrite_site(func: &mut HighFunction, plan: &SitePlan, helper: &Helper) {
    if let Some(binding) = func.bindings.get_mut(plan.call)
        && let Expr::Call { args, .. } = &mut binding.expr
        && helper.out < args.len()
    {
        args.remove(helper.out);
    }
    rewrite_ty(func, plan.call, "the call yields the `Option` its frame used to receive");

    let is_some = push(func, Expr::IsSome { value: plan.call }, IrType::Known(KnownType::Bool), "whether the call returned a value");
    place(func, plan.call, is_some, true);

    // The tag, read back exactly: the present tag when it holds a value.
    // A tag only ever branched on is that question itself, as a `bool` —
    // a wasm `br_if` on an integer is a test for non-zero.
    for &tag in &plan.tags {
        if cond_only(func, tag) {
            let (expr, note) = match (helper.present != 0, helper.absent != 0) {
                (true, false) => (Expr::Use(is_some), "the tag, tested: whether the call returned a value"),
                (false, true) => (
                    Expr::Unary { op: UnaryOp::Not, value: is_some },
                    "the tag, tested: whether the call returned nothing",
                ),
                _ => (Expr::Literal(Literal::Bool(helper.present != 0)), "the tag, tested, is the same either way"),
            };
            rewrite(func, tag, expr, Some(IrType::Known(KnownType::Bool)), note);
            continue;
        }
        let wide = matches!(func.bindings.get(tag).map(|b| &b.expr), Some(Expr::Load { width: sordec_ir::MemWidth::W8, .. }));
        let lit = |n: i128| {
            if wide {
                (Literal::I64(n as i64), IrType::Known(KnownType::I64))
            } else {
                (Literal::I32(n as i32), IrType::Known(KnownType::I32))
            }
        };
        let (p, pt) = lit(helper.present);
        let (a, at) = lit(helper.absent);
        let present = push(func, Expr::Literal(p), pt, "the tag the helper wrote when it had a value");
        let absent = push(func, Expr::Literal(a), at, "the tag the helper wrote when it had none");
        place(func, tag, present, false);
        place(func, tag, absent, false);
        rewrite(
            func,
            tag,
            Expr::Select { cond: is_some, if_true: present, if_false: absent },
            None,
            "the out-parameter's tag, read from the returned `Option`",
        );
    }
    let arity = helper.payload.len() as u32;
    for &(load, index) in &plan.values {
        if let Some((field, half)) = helper.whole.as_ref().and_then(|w| w.get(index)) {
            let whole = push(
                func,
                Expr::Unwrap { value: plan.call, index: 0, arity: 1 },
                untyped(),
                "the struct the helper returned, where the `Option` is proven present",
            );
            place(func, load, whole, false);
            let declared = helper.part_types.get(index).cloned().flatten();
            let part = push(
                func,
                Expr::Field { base: whole, field: field.clone() },
                declared.map_or_else(untyped, IrType::Known),
                "the field of the returned struct this slot held",
            );
            place(func, load, part, false);
            let (expr, ty) = match half {
                Some(op) => (Expr::Unary { op: *op, value: part }, Some(IrType::Inferred(KnownType::I64))),
                None => (Expr::Use(part), Some(untyped())),
            };
            rewrite(func, load, expr, ty, "the out-parameter's slot, read from the returned struct");
            continue;
        }
        rewrite(
            func,
            load,
            Expr::Unwrap { value: plan.call, index: index as u32, arity },
            Some(untyped()),
            "the out-parameter's value, read from the returned `Option` where it is proven present",
        );
    }
    for (load, lit) in &plan.consts {
        rewrite(func, *load, Expr::Literal(lit.clone()), None, "a slot the helper always wrote this constant to");
    }
    // A choice between the value and a fallback, made on the tag, is the
    // value or the fallback: `unwrap_or`. The read it chose goes with it.
    for &(select, load, fallback) in &plan.picks {
        rewrite(
            func,
            select,
            Expr::UnwrapOr { value: plan.call, default: fallback },
            Some(untyped()),
            "the value, or the fallback where the call returned none",
        );
        rewrite(
            func,
            load,
            Expr::Literal(Literal::Unit),
            Some(IrType::Known(KnownType::Unit)),
            "the out-parameter's value, now read through `unwrap_or`",
        );
    }
    // A value read above its test moves to the start of the arm that test
    // proves it present on, where all its uses are.
    for &(load, block) in &plan.sinks {
        if let Some(from) = block_containing(func, load).and_then(|b| func.blocks.get_mut(b)) {
            from.bindings.retain(|b| *b != load);
        }
        if let Some(to) = func.blocks.get_mut(block) {
            to.bindings.insert(0, load);
        }
        if let Some(binding) = func.bindings.get_mut(load) {
            binding.add_provenance(Provenance::new(
                PASS_NAME,
                ProvenanceSource::SdkPattern,
                "moved from above the test to the arm where the value is proven present",
            ));
        }
    }
}

/// Whether `value` is read only as the condition of an `if`.
fn cond_only(func: &HighFunction, value: ValueId) -> bool {
    let mut bound = false;
    for id in emission_order(func) {
        if let Some(b) = func.bindings.get(id) {
            b.expr.for_each_value_use(|u| bound |= u == value);
        }
    }
    let mut all = 0usize;
    func.region.for_each_value_use(|u| all += usize::from(u == value));
    let mut conds = 0usize;
    func.region.for_each_node(|node| {
        if let Region::If { cond, .. } = node {
            conds += usize::from(*cond == value);
        }
    });
    !bound && conds > 0 && conds == all
}

fn rewrite_ty(func: &mut HighFunction, id: ValueId, note: &str) {
    if let Some(binding) = func.bindings.get_mut(id) {
        binding.ty = untyped();
        binding.add_provenance(Provenance::new(PASS_NAME, ProvenanceSource::SdkPattern, note.to_string()));
    }
}

// ---------------------------------------------------------------------
// What a call can touch through a pointer
// ---------------------------------------------------------------------

/// Module-wide context for the call-site gates: the classified helpers,
/// and a memo of what each function can touch through each parameter.
struct Frames<'ir> {
    ir: &'ir HighIr,
    helpers: &'ir HashMap<FuncId, Helper>,
    /// `(function, parameter) -> bytes read and bytes written through it`,
    /// relative to the parameter; `None` when unknown. An in-progress entry
    /// is `None`, which is what makes recursion answer "unknown" rather than
    /// loop.
    extents: RefCell<HashMap<(FuncId, usize), Option<Extent>>>,
}

/// One access range a call has into a frame, and whether it only writes.
type Touch = (Slot, bool);

/// What a function does through one pointer parameter: the bytes it reads
/// and the bytes it writes, each `None` when it does neither.
#[derive(Debug, Clone, Copy, Default)]
struct Extent {
    reads: Option<Slot>,
    writes: Option<Slot>,
}

/// The smallest slot covering both.
fn cover(a: Option<Slot>, b: Slot) -> Slot {
    match a {
        None => b,
        Some(a) => {
            let lo = a.offset.min(b.offset);
            let hi = (a.offset + a.bytes).max(b.offset + b.bytes);
            Slot { offset: lo, bytes: hi - lo }
        }
    }
}

/// Whether `outer` holds every byte of `inner`.
fn holds(outer: Slot, inner: Slot) -> bool {
    outer.offset <= inner.offset && outer.offset + outer.bytes >= inner.offset + inner.bytes
}

/// What a bulk memory operation does to the frame at `base`, as touches
/// relative to it. `memory.copy` and `memory.fill` take `[destination,
/// source or byte, length]`: the destination is written for the length,
/// and the second operand, when it is an address in the frame, is read for
/// as long — a fill's byte never is, so reading it as one only refuses
/// more. `None` when an operand is in the frame and the length is not a
/// constant (or is in the frame itself); empty when nothing it is handed is
/// in the frame, which is also `memory.size` and `memory.grow` unless their
/// operand is.
fn bulk_touches(func: &HighFunction, args: &[ValueId], base: ValueId) -> Option<Vec<Touch>> {
    let at = |v: ValueId| {
        let (b, o) = canon_addr(func, v);
        (b == base).then_some(o)
    };
    let [dst, src, len] = args else {
        return args.iter().all(|a| at(*a).is_none()).then(Vec::new);
    };
    if at(*len).is_some() {
        return None;
    }
    let (d, s) = (at(*dst), at(*src));
    if d.is_none() && s.is_none() {
        return Some(Vec::new());
    }
    let bytes = u32::try_from(trace_int(func, *len)?).ok()?;
    let mut out = Vec::new();
    for (offset, write) in [(d, true), (s, false)] {
        if let Some(offset) = offset
            && bytes > 0
        {
            offset.checked_add(bytes)?;
            out.push((Slot { offset, bytes }, write));
        }
    }
    Some(out)
}

/// The bytes `id` writes at `base` whenever it runs: a store's slot, or a
/// bulk operation's destination for its constant length. `None` when it
/// writes nothing there, or what it writes is not known.
fn definite_write(func: &HighFunction, id: ValueId, base: ValueId) -> Option<Slot> {
    match &func.bindings.get(id)?.expr {
        Expr::Store { addr, offset, width, .. } => {
            let (b, o) = canon_addr(func, *addr);
            let offset = o.checked_add(*offset)?;
            offset.checked_add(width.bytes())?;
            (b == base).then_some(Slot { offset, bytes: width.bytes() })
        }
        Expr::Unknown { op_kind: WasmOpcodeKind::MemoryOp, args, .. } => bulk_touches(func, args, base)?
            .into_iter()
            .find_map(|(slot, write)| write.then_some(slot)),
        _ => None,
    }
}

impl Frames<'_> {
    /// What the call at `binding` can touch in the frame at `base`, or
    /// `None` when it is handed a pointer into it and the extent is not
    /// known. Empty for a call handed nothing of the frame.
    fn touches(&self, func: &HighFunction, binding: ValueId, base: ValueId) -> Option<Vec<Touch>> {
        let (target, args) = match func.bindings.get(binding).map(|b| &b.expr) {
            Some(Expr::Call { target, args }) => (Some(*target), args),
            Some(
                Expr::IndirectCall { args, .. }
                | Expr::Unknown { op_kind: WasmOpcodeKind::CallIndirect, args, .. },
            ) => (None, args),
            Some(Expr::Unknown { op_kind: WasmOpcodeKind::MemoryOp, args, .. }) => {
                return bulk_touches(func, args, base);
            }
            _ => return Some(Vec::new()),
        };
        // A call to a memory routine is the bulk operation it performs.
        if let Some(target) = target
            && routine(self.ir, target).is_some()
        {
            return bulk_touches(func, args, base);
        }
        let mut out = Vec::new();
        for (i, arg) in args.iter().enumerate() {
            let (b, at) = canon_addr(func, *arg);
            if b != base {
                continue;
            }
            let target = target?;
            if let Some(h) = self.helpers.get(&target)
                && h.out == i
            {
                for slot in h.slots() {
                    out.push((slot.shifted(at)?, true));
                }
                continue;
            }
            let extent = self.param_extent(target, i)?;
            if let Some(read) = extent.reads {
                out.push((read.shifted(at)?, false));
            }
            if let Some(written) = extent.writes {
                out.push((written.shifted(at)?, true));
            }
        }
        Some(out)
    }

    /// What `target` does through parameter `index`, relative to it, or
    /// `None` when that cannot be told.
    fn param_extent(&self, target: FuncId, index: usize) -> Option<Extent> {
        if let Some(known) = self.extents.borrow().get(&(target, index)) {
            return *known;
        }
        self.extents.borrow_mut().insert((target, index), None);
        let found = self.compute_extent(target, index);
        self.extents.borrow_mut().insert((target, index), found);
        found
    }

    fn compute_extent(&self, target: FuncId, index: usize) -> Option<Extent> {
        let func = self.ir.functions.iter().find(|f| f.id == target)?;
        if func.signature.is_some() {
            return None;
        }
        let param = *func.params.get(index)?;
        let order = emission_order(func);
        let mut addresses: HashSet<ValueId> = HashSet::from([param]);
        for &id in &order {
            match func.bindings.get(id).map(|b| &b.expr) {
                Some(Expr::Binary { op: BinaryOp::Add, lhs, rhs })
                    if addresses.contains(&resolve_use(func, *lhs)) && trace_int(func, *rhs).is_some() =>
                {
                    addresses.insert(id);
                }
                Some(Expr::Use(v)) if addresses.contains(&resolve_use(func, *v)) => {
                    addresses.insert(id);
                }
                _ => {}
            }
        }
        let is_address = |v: ValueId| addresses.contains(&resolve_use(func, v));
        let mut extent = Extent::default();
        for &id in &order {
            if addresses.contains(&id) {
                continue;
            }
            let expr = &func.bindings.get(id)?.expr;
            match expr {
                Expr::Load { addr, offset, width, .. } if is_address(*addr) => {
                    let (_, o) = canon_addr(func, *addr);
                    extent.reads = Some(cover(extent.reads, Slot { offset: o.checked_add(*offset)?, bytes: width.bytes() }));
                }
                Expr::Store { addr, value, offset, width } if is_address(*addr) => {
                    if is_address(*value) {
                        return None;
                    }
                    let (_, o) = canon_addr(func, *addr);
                    extent.writes = Some(cover(extent.writes, Slot { offset: o.checked_add(*offset)?, bytes: width.bytes() }));
                }
                // A bulk copy or fill on the pointer — the instruction, or a
                // call to a memory routine — counted as for the caller; an
                // address operand that does not resolve to the pointer plus
                // a constant is not located, so nothing is told.
                Expr::Unknown { op_kind: WasmOpcodeKind::MemoryOp, args, .. }
                | Expr::Call { args, .. }
                    if args.iter().any(|a| is_address(*a))
                        && match expr {
                            Expr::Call { target, .. } => routine(self.ir, *target).is_some(),
                            _ => true,
                        } =>
                {
                    if args.iter().any(|a| is_address(*a) && canon_addr(func, *a).0 != param) {
                        return None;
                    }
                    for (slot, write) in bulk_touches(func, args, param)? {
                        if write {
                            extent.writes = Some(cover(extent.writes, slot));
                        } else {
                            extent.reads = Some(cover(extent.reads, slot));
                        }
                    }
                }
                Expr::Call { target, args } => {
                    for (j, arg) in args.iter().enumerate() {
                        if !is_address(*arg) {
                            continue;
                        }
                        let (_, o) = canon_addr(func, *arg);
                        let inner = self.param_extent(*target, j)?;
                        if let Some(r) = inner.reads {
                            extent.reads = Some(cover(extent.reads, r.shifted(o)?));
                        }
                        if let Some(w) = inner.writes {
                            extent.writes = Some(cover(extent.writes, w.shifted(o)?));
                        }
                    }
                }
                other => {
                    let mut reads = false;
                    other.for_each_value_use(|u| reads |= is_address(u));
                    if reads {
                        return None;
                    }
                }
            }
        }
        let mut region_reads = false;
        func.region.for_each_value_use(|u| region_reads |= is_address(u));
        if region_reads {
            return None;
        }
        Some(extent)
    }
}

// ---------------------------------------------------------------------
// The call site
// ---------------------------------------------------------------------

fn site(
    frames: &Frames<'_>,
    func: &HighFunction,
    order: &[ValueId],
    call: ValueId,
    args: &[ValueId],
    helper: &Helper,
) -> Result<SitePlan, &'static str> {
    let ptr = *args.get(helper.out).ok_or("the call has no out-pointer argument")?;
    let (base, at) = canon_addr(func, ptr);
    // Only the caller's own frame is memory nothing reads once the caller
    // returns. Through its own out-pointer, or any pointer it was handed,
    // the helper writes memory the caller's caller reads afterwards, and
    // the rewrite would stop writing it.
    if !is_frame(func, base) {
        return Err("the out-pointer is not into the caller's own frame");
    }
    let tag = helper.tag.shifted(at).ok_or("an offset overflows")?;
    let payload: Vec<Slot> = helper.payload.iter().map(|(s, _)| s.shifted(at)).collect::<Option<_>>().ok_or("an offset overflows")?;
    let all: Vec<Slot> = helper.slots().map(|s| s.shifted(at)).collect::<Option<_>>().ok_or("an offset overflows")?;
    let lo = all.iter().map(|s| s.offset).min().ok_or("no slots")?;
    let hi = all.iter().map(|s| s.offset + s.bytes).max().ok_or("no slots")?;
    let range = Slot { offset: lo, bytes: hi - lo };

    // Another call handed this frame may read the result, which the
    // rewrite stops writing. Allowed only where what it can touch is known
    // and misses the result — a key passed by reference sits beside it —
    // or where all it is handed is another helper's out-pointer, which it
    // only stores through.
    // The call's own other arguments too: an in-out pointer overlapping the
    // result would read what the rewrite no longer writes.
    for (i, arg) in args.iter().enumerate() {
        let (b, o) = canon_addr(func, *arg);
        if i == helper.out || b != base {
            continue;
        }
        let Some(target) = (match func.bindings.get(call).map(|b| &b.expr) {
            Some(Expr::Call { target, .. }) => Some(*target),
            _ => None,
        }) else {
            return Err("the call is not direct");
        };
        let extent = frames.param_extent(target, i).ok_or("the call takes the frame twice, extent unknown")?;
        for slot in extent.reads.into_iter().chain(extent.writes) {
            if slot.shifted(o).is_none_or(|s| s.overlaps(range)) {
                return Err("the call reads or writes the result through another argument");
            }
        }
    }
    // Only what can run after the call, before the result's bytes are all
    // written over, can read what it wrote. A call that cannot — in an
    // earlier loop the call's own loop never returns to, or past the
    // stores that overwrite the result — sees other bytes.
    let after = runs_after(func, call, base, range);
    for &id in order {
        if id == call || after.as_ref().is_some_and(|a| !a.contains(&id)) {
            continue;
        }
        // A bulk copy or fill is counted like a call: what it reads and
        // what it writes, by its operands.
        let bulk = matches!(
            func.bindings.get(id).map(|b| &b.expr),
            Some(Expr::Unknown { op_kind: WasmOpcodeKind::MemoryOp, .. })
        );
        let Some(touched) = frames.touches(func, id, base) else {
            trace(func, &format!("  call v{} into the frame, extent unknown", id.index()));
            return Err(if bulk {
                "a bulk copy or fill of unknown length on the frame"
            } else {
                "the frame is handed to a call that may read anything"
            });
        };
        // A reader whose last write before it, on every path, covered
        // the whole result reads that write's bytes instead.
        if touched.iter().any(|(slot, write_only)| !write_only && slot.overlaps(range))
            && !matches!(nearest_writer(frames, func, id, base, range), Ok(Some(w))
                if w != call && definite_write(func, w, base).is_some_and(|s| holds(s, range)))
        {
            trace(func, &format!("  call v{} may read the result", id.index()));
            return Err(if bulk { "a bulk copy may read the result" } else { "another call may read the result" });
        }
    }

    let mut tag_loads = Vec::new();
    let mut payload_loads = Vec::new();
    let mut const_loads = Vec::new();
    for &id in order {
        let Some(Expr::Load { addr, offset, width, .. }) = func.bindings.get(id).map(|b| &b.expr) else {
            continue;
        };
        let (b, o) = canon_addr(func, *addr);
        if b != base {
            continue;
        }
        let slot = Slot { offset: o.checked_add(*offset).ok_or("an offset overflows")?, bytes: width.bytes() };
        if !slot.overlaps(range) {
            continue;
        }
        // A read another write reaches belongs to that write — the next
        // call to the same helper, reusing the slot — and the rewrite leaves
        // it alone. Only a read whose writer depends on the path is a
        // problem.
        if nearest_writer(frames, func, id, base, slot)? != Some(call) {
            continue;
        }
        // The low bytes of a small tag are the tag: wasm is little-endian,
        // and a caller reads an 8-byte discriminant as an `i32`.
        let low_bits = |t: i128| slot.bytes >= 16 || (0..(1i128 << (8 * slot.bytes))).contains(&t);
        let tag_prefix = slot.offset == tag.offset
            && slot.bytes < tag.bytes
            && low_bits(helper.present)
            && low_bits(helper.absent);
        if slot == tag || tag_prefix {
            tag_loads.push(id);
        } else if let Some(index) = payload.iter().position(|s| *s == slot) {
            payload_loads.push((id, index));
        } else if let Some((_, lit)) = helper.consts.iter().find(|(s, _)| s.shifted(at) == Some(slot)) {
            const_loads.push((id, lit.clone()));
        } else {
            trace(func, &format!("  read v{} at {:?}; slots {:?}", id.index(), slot, all));
            return Err("a read that is not one of the result's slots");
        }
    }
    let mut values = Vec::new();
    let mut picks = Vec::new();
    let mut sinks = Vec::new();
    for &(load, index) in &payload_loads {
        if guarded(func, load, &tag_loads, helper) {
            values.push((load, index));
            continue;
        }
        // The rest need the value as one component, not parts of a struct.
        let single = helper.payload.len() == 1 && helper.whole.is_none();
        if single && let Some(found) = choices(func, load, call, &tag_loads, &payload_loads, helper) {
            picks.extend(found);
            continue;
        }
        if single && let Some(block) = sink_target(func, load, &tag_loads, helper) {
            values.push((load, index));
            sinks.push((load, block));
            continue;
        }
        return Err("a value read not proven present");
    }
    Ok(SitePlan { call, tags: tag_loads, values, consts: const_loads, picks, sinks })
}

/// What a qualifying call site reads of the result, for the rewrite.
struct SitePlan {
    call: ValueId,
    /// Reads of the tag (or its low bytes).
    tags: Vec<ValueId>,
    /// Reads of the value, each with its payload component.
    values: Vec<(ValueId, usize)>,
    /// Reads of a slot the helper always writes the same constant to.
    consts: Vec<(ValueId, Literal)>,
    /// Choices between the value and a fallback made on the tag, each with
    /// the value read it chose and the fallback: `unwrap_or`.
    picks: Vec<(ValueId, ValueId, ValueId)>,
    /// Value reads placed above their test, each with the block that
    /// starts the arm the test proves the value present on: the read moves
    /// there.
    sinks: Vec<(ValueId, BlockId)>,
}

/// The arms and condition of a `select`, recovered or not:
/// `(if_true, if_false, cond)`.
fn select_parts(func: &HighFunction, id: ValueId) -> Option<(ValueId, ValueId, ValueId)> {
    match &func.bindings.get(id)?.expr {
        Expr::Unknown { op_kind: WasmOpcodeKind::Select, args, .. } if args.len() == 3 => Some((args[0], args[1], args[2])),
        Expr::Select { cond, if_true, if_false } => Some((*if_true, *if_false, *cond)),
        _ => None,
    }
}

/// Every binding the region tree schedules, by block, and how many times the
/// region itself reads each value.
fn uses_of(func: &HighFunction, value: ValueId) -> (Vec<(BlockId, ValueId)>, usize) {
    let mut users = Vec::new();
    func.region.for_each_node(|node| {
        if let Region::Basic(b) = node
            && let Some(block) = func.blocks.get(*b)
        {
            for &id in &block.bindings {
                let mut reads = false;
                if let Some(binding) = func.bindings.get(id) {
                    binding.expr.for_each_value_use(|u| reads |= u == value);
                }
                if reads {
                    users.push((*b, id));
                }
            }
        }
    });
    let mut region = 0usize;
    func.region.for_each_value_use(|u| region += usize::from(u == value));
    (users, region)
}

/// Whether a merge (a phi, which no block schedules) reads `value`.
fn merged(func: &HighFunction, value: ValueId) -> bool {
    func.bindings.iter().any(|(_, b)| {
        let mut reads = false;
        if let Expr::Phi { incoming } = &b.expr {
            reads = incoming.iter().any(|(_, v)| *v == value);
        }
        reads
    })
}

/// When every use of the value read `load` is a choice between it and a
/// fallback, made on the tag and taking the value exactly when the tag says
/// present: each choice as `(select, load, fallback)`. The fallback reads
/// nothing of the call.
fn choices(
    func: &HighFunction,
    load: ValueId,
    call: ValueId,
    tag_loads: &[ValueId],
    payload_loads: &[(ValueId, usize)],
    helper: &Helper,
) -> Option<Vec<(ValueId, ValueId, ValueId)>> {
    let (users, region) = uses_of(func, load);
    if region > 0 || users.is_empty() || merged(func, load) {
        return None;
    }
    let of_call = |v: ValueId| {
        let v = resolve_use(func, v);
        v == call || tag_loads.contains(&v) || payload_loads.iter().any(|(l, _)| *l == v)
    };
    let mut out = Vec::new();
    for (_, select) in users {
        let (t, f, c) = select_parts(func, select)?;
        let (t, f) = (resolve_use(func, t), resolve_use(func, f));
        if resolve_use(func, c) == load || (t == load) == (f == load) {
            return None;
        }
        let present = eval(func, c, tag_loads, helper.present, 0)? != 0;
        let absent = eval(func, c, tag_loads, helper.absent, 0)? != 0;
        // The value's arm must be the one the present tag selects, and the
        // absent tag the other.
        if present == absent || present != (t == load) {
            return None;
        }
        let fallback = if t == load { f } else { t };
        if of_call(fallback) {
            return None;
        }
        out.push((select, load, fallback));
    }
    Some(out)
}

/// The first block a region runs, when it starts with one.
fn first_block(region: &Region) -> Option<BlockId> {
    match region {
        Region::Basic(b) => Some(*b),
        Region::Sequence(items) => first_block(items.first()?),
        _ => None,
    }
}

/// Where the value read `load`, placed above its test, can move: the block
/// that starts the arm of a later `if` whose test on the tag sends the
/// present tag there, when every use of the read is inside that arm. The
/// `if` must follow the read in a sequence that holds both, with nothing
/// but scopes between, so the arm runs after the read on every path.
fn sink_target(func: &HighFunction, load: ValueId, tag_loads: &[ValueId], helper: &Helper) -> Option<BlockId> {
    let block = block_containing(func, load)?;
    let path = path_to(&func.region, block)?;
    let (users, region_uses) = uses_of(func, load);
    if merged(func, load) {
        return None;
    }
    let polarity = |cond: ValueId| -> Option<bool> {
        let p = eval(func, cond, tag_loads, helper.present, 0)?;
        let a = eval(func, cond, tag_loads, helper.absent, 0)?;
        ((p != 0) != (a != 0)).then_some(p != 0)
    };
    for (region, child) in path.iter().rev() {
        match region {
            Region::Sequence(items) => {
                for item in &items[child + 1..] {
                    let Region::If { cond, then_region, else_region } = item else {
                        continue;
                    };
                    let Some(present_takes_then) = polarity(*cond) else {
                        continue;
                    };
                    let arm: &Region = if present_takes_then {
                        then_region
                    } else {
                        let Some(e) = else_region else {
                            continue;
                        };
                        e
                    };
                    let mut inside: HashSet<BlockId> = HashSet::new();
                    arm.for_each_node(|n| {
                        if let Region::Basic(b) = n {
                            inside.insert(*b);
                        }
                    });
                    let mut arm_uses = 0usize;
                    arm.for_each_value_use(|u| arm_uses += usize::from(u == load));
                    if arm_uses == region_uses && users.iter().all(|(b, _)| inside.contains(b)) {
                        return first_block(arm);
                    }
                }
            }
            Region::Scope { .. } => {}
            _ => return None,
        }
    }
    None
}

/// How control can leave a region: by falling out of its end, or by a
/// branch to a label outside it. A return or a trap is no way on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Exit {
    Falls,
    Break(BlockId),
    Continue(BlockId),
}

/// Every way control can leave `region`; `None` for unstructured flow.
fn exits(region: &Region) -> Option<HashSet<Exit>> {
    Some(match region {
        Region::Basic(_) | Region::Transfer { .. } => HashSet::from([Exit::Falls]),
        Region::Sequence(items) => {
            let mut out = HashSet::new();
            for item in items {
                let e = exits(item)?;
                let falls = e.contains(&Exit::Falls);
                out.extend(e.into_iter().filter(|x| *x != Exit::Falls));
                if !falls {
                    return Some(out);
                }
            }
            out.insert(Exit::Falls);
            out
        }
        Region::Scope { out, body } => {
            let mut e = exits(body)?;
            if e.remove(&Exit::Break(*out)) {
                e.insert(Exit::Falls);
            }
            e
        }
        Region::If { then_region, else_region, .. } => {
            let mut e = exits(then_region)?;
            match else_region {
                Some(r) => e.extend(exits(r)?),
                None => {
                    e.insert(Exit::Falls);
                }
            }
            e
        }
        Region::Switch { arms, default, .. } => {
            let mut e = exits(default)?;
            for arm in arms {
                e.extend(exits(&arm.body)?);
            }
            e
        }
        // Going round stays inside. Falling off the body's end goes round
        // too, and is kept as a way out as well: more ways out only ever
        // mean more code counted as running after.
        Region::Loop { header, body, .. } => {
            let mut e = exits(body)?;
            e.remove(&Exit::Continue(*header));
            e
        }
        Region::Break { target, .. } => HashSet::from([Exit::Break(*target)]),
        Region::Continue { target, .. } => HashSet::from([Exit::Continue(*target)]),
        Region::Return { .. } | Region::Unreachable | Region::Panic { .. } => HashSet::new(),
        Region::Unstructured { .. } => return None,
    })
}

/// Whether `written` covers every byte of `range`.
fn covers(written: &[Slot], range: Slot) -> bool {
    let mut slots = written.to_vec();
    slots.sort();
    let mut reached = range.offset;
    for s in slots {
        if s.offset <= reached {
            reached = reached.max(s.offset + s.bytes);
        }
    }
    reached >= range.offset + range.bytes
}

/// The bindings that may run after `call` in one run of the function, as the
/// region tree tells it, before `range` at `base` is all written over: what
/// follows the call in its block, then, climbing out, each later item of a
/// sequence control can still fall into, and the whole body of a loop it can
/// go round. More than can run, never less; `None` when the tree cannot
/// tell.
///
/// The writing-over only counts on the straight line from the call — blocks
/// every path that falls on from the call runs, in order. Once paths merge
/// at a scope's end, or go round a loop (where the call itself may run
/// again), it stops counting.
fn runs_after(func: &HighFunction, call: ValueId, base: ValueId, range: Slot) -> Option<HashSet<ValueId>> {
    let block = block_containing(func, call)?;
    let path = path_to(&func.region, block)?;
    let bindings = &func.blocks.get(block)?.bindings;
    let at = bindings.iter().position(|b| *b == call)?;
    let mut after: HashSet<ValueId> = HashSet::new();
    let mut written: Vec<Slot> = Vec::new();
    // Walk one straight-line block, stopping once the range is written over.
    let mut walk = |ids: &[ValueId], after: &mut HashSet<ValueId>| -> bool {
        for &id in ids {
            after.insert(id);
            if let Some(slot) = definite_write(func, id, base) {
                written.push(slot);
                if covers(&written, range) {
                    return true;
                }
            }
        }
        false
    };
    let add = |region: &Region, after: &mut HashSet<ValueId>| {
        region.for_each_node(|n| {
            if let Region::Basic(b) = n
                && let Some(block) = func.blocks.get(*b)
            {
                after.extend(block.bindings.iter().copied());
            }
        });
    };
    let mut straight = true;
    let mut pending: HashSet<Exit> = HashSet::new();
    if !walk(&bindings[at + 1..], &mut after) {
        pending.insert(Exit::Falls);
    }
    for (region, child) in path.iter().rev() {
        match region {
            Region::Sequence(items) if pending.remove(&Exit::Falls) => {
                let mut falls = true;
                for item in &items[child + 1..] {
                    if straight
                        && let Region::Basic(b) = item
                        && let Some(block) = func.blocks.get(*b)
                    {
                        if walk(&block.bindings, &mut after) {
                            falls = false;
                            break;
                        }
                        continue;
                    }
                    add(item, &mut after);
                    let e = exits(item)?;
                    falls = e.contains(&Exit::Falls);
                    pending.extend(e.into_iter().filter(|x| *x != Exit::Falls));
                    if !falls {
                        break;
                    }
                }
                if falls {
                    pending.insert(Exit::Falls);
                }
            }
            Region::Scope { out, .. } => {
                if pending.remove(&Exit::Break(*out)) {
                    pending.insert(Exit::Falls);
                    straight = false;
                }
            }
            Region::Loop { header, body, .. } => {
                let continued = pending.remove(&Exit::Continue(*header));
                if continued || pending.contains(&Exit::Falls) {
                    add(body, &mut after);
                    let mut e = exits(body)?;
                    e.remove(&Exit::Continue(*header));
                    pending.extend(e);
                    straight = false;
                }
            }
            Region::Unstructured { .. } => return None,
            _ => {}
        }
    }
    Some(after)
}

/// Whether `binding` writes memory at `base` that may overlap `range`: a
/// store there, a bulk copy or fill into it, or a call handed a pointer
/// into the frame.
fn writes(frames: &Frames<'_>, func: &HighFunction, binding: ValueId, base: ValueId, range: Slot) -> bool {
    match func.bindings.get(binding).map(|b| &b.expr) {
        Some(Expr::Store { addr, offset, width, .. }) => {
            let (b, o) = canon_addr(func, *addr);
            b == base && o.checked_add(*offset).is_none_or(|start| Slot { offset: start, bytes: width.bytes() }.overlaps(range))
        }
        // Its destination; its source it only reads.
        Some(Expr::Unknown { op_kind: WasmOpcodeKind::MemoryOp, args, .. }) => bulk_touches(func, args, base)
            .is_none_or(|touched| touched.iter().any(|(slot, write)| *write && slot.overlaps(range))),
        Some(
            Expr::Call { .. }
            | Expr::IndirectCall { .. }
            | Expr::Unknown { op_kind: WasmOpcodeKind::CallIndirect, .. },
        ) => frames
            .touches(func, binding, base)
            .is_none_or(|touched| touched.iter().any(|(slot, _)| slot.overlaps(range))),
        _ => false,
    }
}

/// `writer`, the nearest write before a read of `range`, as the write the
/// read sees. A store or bulk operation must write every byte of it: one
/// that writes only some leaves the rest to an earlier write.
fn seen(func: &HighFunction, writer: ValueId, base: ValueId, range: Slot) -> Result<Option<ValueId>, &'static str> {
    let direct = matches!(
        func.bindings.get(writer).map(|b| &b.expr),
        Some(Expr::Store { .. } | Expr::Unknown { op_kind: WasmOpcodeKind::MemoryOp, .. })
    );
    if direct && !definite_write(func, writer, base).is_some_and(|w| holds(w, range)) {
        return Err("a read whose nearest write covers only part of it");
    }
    Ok(Some(writer))
}

/// The write that `load` reads: the last write on every path to it, when
/// that is one binding. `Err` when it depends on the path.
fn nearest_writer(
    frames: &Frames<'_>,
    func: &HighFunction,
    load: ValueId,
    base: ValueId,
    range: Slot,
) -> Result<Option<ValueId>, &'static str> {
    let block = block_containing(func, load).ok_or("an unscheduled read")?;
    let bindings = &func.blocks.get(block).ok_or("a missing block")?.bindings;
    let at = bindings.iter().position(|b| *b == load).ok_or("an unscheduled read")?;
    if let Some(w) = bindings[..at].iter().rev().find(|b| writes(frames, func, **b, base, range)) {
        return seen(func, *w, base, range);
    }
    let path = path_to(&func.region, block).ok_or("a read outside the region tree")?;
    let writes_in = |region: &Region| -> Vec<ValueId> {
        let mut found = Vec::new();
        region.for_each_node(|node| {
            if let Region::Basic(b) = node
                && let Some(block) = func.blocks.get(*b)
            {
                found.extend(block.bindings.iter().copied().filter(|v| writes(frames, func, *v, base, range)));
            }
        });
        found
    };
    for (region, child) in path.iter().rev() {
        match region {
            Region::Sequence(items) => {
                for item in items[..*child].iter().rev() {
                    let found = writes_in(item);
                    match (item, found.last()) {
                        (_, None) => {}
                        (Region::Basic(_), Some(w)) => return seen(func, *w, base, range),
                        _ => return Err("a write inside an earlier branch"),
                    }
                }
            }
            Region::Loop { .. } if !writes_in(region).is_empty() => {
                return Err("a write inside the enclosing loop");
            }
            _ => {}
        }
    }
    Ok(None)
}

/// The chain of regions from `root` down to the `Basic` region of
/// `block`, each with the index of the child taken (0 for single-child
/// regions; for an `If`, 0 is `then` and 1 is `else`).
fn path_to(root: &Region, block: BlockId) -> Option<Vec<(&Region, usize)>> {
    fn go<'r>(region: &'r Region, block: BlockId, path: &mut Vec<(&'r Region, usize)>) -> bool {
        let children: Vec<&Region> = match region {
            Region::Basic(b) => return *b == block,
            Region::Sequence(items) => items.iter().collect(),
            Region::Scope { body, .. } | Region::Loop { body, .. } => vec![&**body],
            Region::If { then_region, else_region, .. } => {
                std::iter::once(&**then_region).chain(else_region.as_deref()).collect()
            }
            Region::Switch { arms, default, .. } => {
                arms.iter().map(|a| &a.body).chain(std::iter::once(&**default)).collect()
            }
            _ => return false,
        };
        for (i, child) in children.into_iter().enumerate() {
            path.push((region, i));
            if go(child, block, path) {
                return true;
            }
            path.pop();
        }
        false
    }
    let mut path = Vec::new();
    go(root, block, &mut path).then_some(path)
}

/// Whether `load` sits where a test on one of `tag_loads` proves the value
/// present: inside the arm the test sends `present` to, or after an `if`
/// whose `absent` arm leaves.
fn guarded(func: &HighFunction, load: ValueId, tag_loads: &[ValueId], helper: &Helper) -> bool {
    let Some(block) = block_containing(func, load) else {
        return false;
    };
    let Some(path) = path_to(&func.region, block) else {
        return false;
    };
    let polarity = |cond: ValueId| -> Option<bool> {
        let p = eval(func, cond, tag_loads, helper.present, 0)?;
        let a = eval(func, cond, tag_loads, helper.absent, 0)?;
        ((p != 0) != (a != 0)).then_some(p != 0)
    };
    for (region, child) in &path {
        match region {
            Region::If { cond, .. } => {
                if let Some(present_takes_then) = polarity(*cond)
                    && present_takes_then == (*child == 0)
                {
                    return true;
                }
            }
            Region::Sequence(items) => {
                for item in &items[..*child] {
                    if let Region::If { cond, then_region, else_region: None } = item
                        && polarity(*cond) == Some(false)
                        && leaves(then_region)
                    {
                        return true;
                    }
                }
            }
            _ => {}
        }
    }
    false
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
        Region::Scope { body, .. } => leaves(body),
        Region::If { then_region, else_region: Some(e), .. } => leaves(then_region) && leaves(e),
        _ => false,
    }
}

/// `value` evaluated with every tag load reading `tag`, when it is a short
/// enough chain of integer operators over them and constants.
pub(super) fn eval(func: &HighFunction, value: ValueId, tag_loads: &[ValueId], tag: i128, depth: usize) -> Option<i128> {
    let value = resolve_use(func, value);
    if tag_loads.contains(&value) {
        return Some(tag);
    }
    if depth >= EVAL_DEPTH {
        return None;
    }
    let sub = |v: ValueId| eval(func, v, tag_loads, tag, depth + 1);
    match &func.bindings.get(value)?.expr {
        Expr::Literal(Literal::Bool(b)) => Some(i128::from(*b)),
        Expr::Literal(_) => trace_int(func, value),
        Expr::Unary { op: UnaryOp::Eqz | UnaryOp::Not, value } => Some(i128::from(sub(*value)? == 0)),
        Expr::Unary { op: UnaryOp::Wrap32 | UnaryOp::ExtendU32 | UnaryOp::ExtendS32, value } => sub(*value),
        Expr::Unknown { op_kind: sordec_ir::WasmOpcodeKind::Conversion, args, .. } if args.len() == 1 => sub(args[0]),
        Expr::Binary { op, lhs, rhs } => {
            let (l, r) = (sub(*lhs)?, sub(*rhs)?);
            Some(match op {
                BinaryOp::BitAnd => l & r,
                BinaryOp::BitOr => l | r,
                BinaryOp::BitXor => l ^ r,
                BinaryOp::Eq => i128::from(l == r),
                BinaryOp::Ne => i128::from(l != r),
                BinaryOp::Add => l.checked_add(r)?,
                BinaryOp::Sub => l.checked_sub(r)?,
                _ => return None,
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{module, v};
    use sordec_common::{Arena, Provenance, ProvenanceSource, UnknownReason};
    use sordec_ir::{Binding, HighBlock, MemWidth, PanicKind};

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
        let mut blocks: Arena<BlockId, sordec_ir::HighBlock> = Arena::new();
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

    fn store(addr: u32, value: u32, offset: u32) -> Expr {
        Expr::Store { addr: v(addr), value: v(value), offset, width: MemWidth::W8 }
    }

    fn load(addr: u32, offset: u32, width: MemWidth) -> Expr {
        Expr::Load {
            addr: v(addr),
            offset,
            width,
            signed: None,
            ty: IrType::Unknown(UnknownReason::InsufficientEvidence),
        }
    }

    /// func_1, `BytesN::try_from_val`'s shape: tag 1 and nothing else on
    /// the failing arm, tag 0 and the value at `+8` on the other.
    /// `absent_writes` makes the failing arm write `+8` too.
    fn helper(absent_writes: bool) -> HighFunction {
        let exprs = vec![
            Expr::Phi { incoming: vec![] },          // v0 out-pointer
            Expr::Phi { incoming: vec![] },          // v1 the value
            Expr::Literal(Literal::I64(1)),          // v2 absent tag
            Expr::Literal(Literal::Bool(true)),      // v3 the test
            Expr::Literal(Literal::I64(0)),          // v4 present tag
            store(0, 1, 8),                          // v5 the payload
            Expr::Phi { incoming: vec![(bb(1), v(2)), (bb(2), v(4))] }, // v6
            store(0, 6, 0),                          // v7 the tag
            store(0, 2, 8),                          // v8 a write on the failing arm
        ];
        let absent = if absent_writes { vec![8] } else { vec![] };
        let arm = |block: u32, tag: u32| {
            Region::Sequence(vec![
                Region::Basic(bb(block)),
                Region::Transfer { target: bb(3), transfer: vec![(v(6), v(tag))] },
            ])
        };
        func(
            1,
            exprs,
            vec![0, 1],
            vec![vec![2, 3, 4], absent, vec![5], vec![7]],
            Region::Sequence(vec![
                Region::Basic(bb(0)),
                Region::If {
                    cond: v(3),
                    then_region: Box::new(arm(1, 2)),
                    else_region: Some(Box::new(arm(2, 4))),
                },
                Region::Basic(bb(3)),
                Region::Return { values: vec![] },
            ]),
        )
    }

    /// func_0: `func_1(fp, x); if eqz(load32(fp+0)) { return load(fp+8) }
    /// panic!()`. `early` reads the value before the test instead.
    fn caller(early: bool) -> HighFunction {
        let exprs = vec![
            Expr::Phi { incoming: vec![] },                                         // v0 frame
            Expr::Phi { incoming: vec![] },                                         // v1 x
            Expr::Call { target: FuncId::from_index(1), args: vec![v(0), v(1)] }, // v2
            load(0, 0, MemWidth::W4),                                               // v3 tag, low half
            Expr::Unary { op: UnaryOp::Eqz, value: v(3) },                          // v4 present?
            load(0, 8, MemWidth::W8),                                               // v5 the value
        ];
        let (entry, present) = if early { (vec![2, 3, 4, 5], vec![]) } else { (vec![2, 3, 4], vec![5]) };
        func(
            0,
            exprs,
            vec![1],
            vec![entry, present],
            Region::Sequence(vec![
                Region::Basic(bb(0)),
                Region::If {
                    cond: v(4),
                    then_region: Box::new(Region::Sequence(vec![
                        Region::Basic(bb(1)),
                        Region::Return { values: vec![v(5)] },
                    ])),
                    else_region: None,
                },
                Region::Panic { kind: PanicKind::Bare },
            ]),
        )
    }

    /// `f` with its `v0` the shadow-stack frame rustc builds,
    /// `global.get 0 - 32`. The two bindings it needs go at the end, so
    /// every id a test names stays where it was.
    fn framed(mut f: HighFunction) -> HighFunction {
        let at = f.bindings.len() as u32;
        for expr in [Expr::GlobalGet { index: 0 }, i32c(32)] {
            let id = ValueId::from_index(f.bindings.len() as u32);
            f.bindings.push(Binding::new(
                id,
                IrType::Unknown(UnknownReason::InsufficientEvidence),
                expr,
                Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
            ));
        }
        f.bindings.get_mut(v(0)).expect("the frame").expr =
            Expr::Binary { op: BinaryOp::Sub, lhs: v(at), rhs: v(at + 1) };
        f
    }

    /// func_1 with each arm storing its own tag, and no merge of tags:
    /// `if t { store out <- 1 } else { store out+8 <- v; store out <- 0 }`.
    /// `absent_tags` is how many tag stores the failing arm makes (0, 1 or
    /// 2).
    fn per_arm_helper(absent_tags: usize) -> HighFunction {
        let exprs = vec![
            Expr::Phi { incoming: vec![] },     // v0 out-pointer
            Expr::Phi { incoming: vec![] },     // v1 the value
            Expr::Literal(Literal::I64(1)),     // v2 absent tag
            Expr::Literal(Literal::Bool(true)), // v3 the test
            Expr::Literal(Literal::I64(0)),     // v4 present tag
            store(0, 1, 8),                     // v5 the payload
            store(0, 2, 0),                     // v6 the failing arm's tag
            store(0, 4, 0),                     // v7 the other arm's tag
            store(0, 2, 0),                     // v8 the failing arm's tag, again
        ];
        let absent = [vec![], vec![6], vec![6, 8]][absent_tags].clone();
        let arm = |block: u32| {
            Region::Sequence(vec![Region::Basic(bb(block)), Region::Transfer { target: bb(3), transfer: vec![] }])
        };
        func(
            1,
            exprs,
            vec![0, 1],
            vec![vec![2, 3, 4], absent, vec![5, 7], vec![]],
            Region::Sequence(vec![
                Region::Basic(bb(0)),
                Region::If { cond: v(3), then_region: Box::new(arm(1)), else_region: Some(Box::new(arm(2))) },
                Region::Basic(bb(3)),
                Region::Return { values: vec![] },
            ]),
        )
    }

    #[test]
    fn a_tag_stored_in_each_arm_is_classified() {
        let h = classify(&per_arm_helper(1)).expect("each path writes one tag and its value");
        assert_eq!(h.out, 0);
        assert_eq!((h.present, h.absent), (0, 1));
        assert_eq!(h.tag, Slot { offset: 0, bytes: 8 });
        assert_eq!(h.payload.iter().map(|(s, _)| *s).collect::<Vec<_>>(), [Slot { offset: 8, bytes: 8 }]);
        assert_eq!(h.merge, Merge::PerArm(bb(3)));
    }

    #[test]
    fn a_path_writing_no_tag_or_two_is_refused() {
        assert_eq!(classify(&per_arm_helper(0)).err(), Some("a path reaches the merge without setting the tag"));
        assert_eq!(classify(&per_arm_helper(2)).err(), Some("a path writes the tag twice"));
    }

    #[test]
    fn a_tag_stored_in_each_arm_is_returned_as_one_merged_option() {
        let mut ir = module(vec![framed(caller(false)), per_arm_helper(1)]);
        assert!(OptionalOutParamPass.run(&mut ir).changed);
        let h = &ir.functions[1];
        assert_eq!(h.params, vec![v(1)], "the out-pointer is no longer a parameter");
        let Region::Sequence(items) = &h.region else { panic!("a sequence") };
        let Some(Region::Return { values }) = items.last() else { panic!("a return") };
        let merged = values[0];
        let Some(Expr::Phi { incoming }) = h.bindings.get(merged).map(|b| &b.expr) else {
            panic!("the arms' `Option`s meet in a merge");
        };
        assert_eq!(incoming.iter().map(|(b, _)| *b).collect::<Vec<_>>(), [bb(1), bb(2)]);
        let arms: Vec<&Expr> = incoming.iter().map(|(_, o)| &h.bindings.get(*o).unwrap().expr).collect();
        assert!(
            matches!(arms.as_slice(), [Expr::Optional { payload: None }, Expr::Optional { payload: Some(p) }] if p == &vec![v(1)]),
            "the failing arm is None, the other Some(value)"
        );
        // Each arm's edge into the merge carries its `Option`.
        let mut carried = Vec::new();
        h.region.for_each_node(|n| {
            if let Region::Transfer { transfer, .. } = n {
                carried.extend(transfer.iter().copied());
            }
        });
        assert_eq!(carried, incoming.iter().map(|(_, o)| (merged, *o)).collect::<Vec<_>>());
        for store in [v(5), v(6), v(7)] {
            assert!(matches!(h.bindings.get(store).unwrap().expr, Expr::Literal(Literal::Unit)), "the writes retire");
        }
        let c = &ir.functions[0];
        assert!(matches!(c.bindings.get(v(5)).unwrap().expr, Expr::Unwrap { value, .. } if value == v(2)));
    }

    #[test]
    fn a_result_written_through_the_callers_own_pointer_is_refused() {
        // The caller hands on its own out-pointer, a parameter: its caller
        // reads what the helper writes there after it returns.
        let mut own = caller(false);
        own.params = vec![v(0), v(1)];
        let ir = module(vec![own, helper(false)]);
        let helpers: HashMap<FuncId, Helper> =
            ir.functions.iter().filter_map(|f| classify(f).ok().map(|h| (f.id, h))).collect();
        let frames = Frames { ir: &ir, helpers: &helpers, extents: RefCell::new(HashMap::new()) };
        let f = &ir.functions[0];
        let Some(Expr::Call { args, .. }) = f.bindings.get(v(2)).map(|b| &b.expr) else { panic!("the call") };
        let planned = site(&frames, f, &emission_order(f), v(2), args, &helpers[&FuncId::from_index(1)]);
        assert_eq!(planned.err(), Some("the out-pointer is not into the caller's own frame"));
    }

    fn site_of(caller: HighFunction) -> Result<(), &'static str> {
        plan_in(vec![caller, helper(false)]).map(|_| ())
    }

    /// The site at `functions[0]`'s `v2`, calling the helper func_1, as
    /// how many tag reads and value reads it rewrites.
    fn plan_in(functions: Vec<HighFunction>) -> Result<(usize, usize), &'static str> {
        plan_with_prints(functions, vec![])
    }

    /// [`plan_in`] over a module whose bodies carry `prints`, the parse-time
    /// fingerprints the memory routines are named by.
    fn plan_with_prints(mut functions: Vec<HighFunction>, prints: Vec<Option<u128>>) -> Result<(usize, usize), &'static str> {
        let first = framed(functions.remove(0));
        functions.insert(0, first);
        let mut ir = module(functions);
        ir.facts.function_fingerprints = prints;
        let helpers: HashMap<FuncId, Helper> = ir
            .functions
            .iter()
            .filter_map(|f| classify(f).ok().map(|h| (f.id, h)))
            .collect();
        let frames = Frames { ir: &ir, helpers: &helpers, extents: RefCell::new(HashMap::new()) };
        let f = &ir.functions[0];
        let order = emission_order(f);
        let Some(Expr::Call { args, .. }) = f.bindings.get(v(2)).map(|b| &b.expr) else {
            panic!("v2 is the call");
        };
        site(&frames, f, &order, v(2), args, &helpers[&FuncId::from_index(1)]).map(|p| (p.tags.len(), p.values.len()))
    }

    /// `caller(false)` with `extra` bindings (ids from 6) run right after
    /// the call.
    fn caller_then(extra: Vec<Expr>) -> HighFunction {
        let mut f = caller(false);
        let mut ids = Vec::new();
        for expr in extra {
            let id = ValueId::from_index(f.bindings.len() as u32);
            f.bindings.push(Binding::new(
                id,
                IrType::Unknown(UnknownReason::InsufficientEvidence),
                expr,
                Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
            ));
            ids.push(id);
        }
        let entry = &mut f.blocks.get_mut(bb(0)).expect("the entry block").bindings;
        let at = entry.iter().position(|b| *b == v(2)).expect("the call") + 1;
        entry.splice(at..at, ids);
        f
    }

    /// A `memory.copy` or `memory.fill`, as the pipeline leaves it.
    fn bulk(dst: u32, src: u32, len: u32) -> Expr {
        Expr::Unknown {
            op_kind: WasmOpcodeKind::MemoryOp,
            args: vec![v(dst), v(src), v(len)],
            reason: UnknownReason::UnsupportedPattern,
        }
    }

    fn i32c(n: i32) -> Expr {
        Expr::Literal(Literal::I32(n))
    }

    fn opaque() -> Expr {
        Expr::Phi { incoming: vec![] }
    }

    #[test]
    fn a_try_from_val_shaped_helper_is_classified() {
        let h = classify(&helper(false)).expect("an Option out-parameter helper");
        assert_eq!(h.out, 0);
        assert_eq!((h.present, h.absent), (0, 1));
        assert_eq!(h.tag, Slot { offset: 0, bytes: 8 });
        assert_eq!(h.payload.iter().map(|(s, _)| *s).collect::<Vec<_>>(), [Slot { offset: 8, bytes: 8 }]);
    }

    #[test]
    fn a_payload_merging_an_unrecognised_host_result_is_not_a_helper() {
        // The present arm stores `phi [host:i:u256_rem_euclid(x), x]`: the
        // merge has only `x`'s word to be typed by.
        let with_payload = |arms: [u32; 2]| {
            let mut f = helper(false);
            for expr in [
                Expr::Semantic(sordec_ir::SemanticOp::Unknown {
                    host_module: "i".to_string(),
                    host_fn: "u256_rem_euclid".to_string(),
                    args: vec![v(1)],
                    reason: UnknownReason::UnsupportedPattern,
                }), // v9
                Expr::Phi { incoming: vec![(bb(0), v(arms[0])), (bb(0), v(arms[1]))] }, // v10
            ] {
                let id = ValueId::from_index(f.bindings.len() as u32);
                f.bindings.push(Binding::new(
                    id,
                    IrType::Unknown(UnknownReason::InsufficientEvidence),
                    expr,
                    Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
                ));
            }
            f.bindings.get_mut(v(5)).unwrap().expr = store(0, 10, 8);
            f
        };
        assert_eq!(classify(&with_payload([9, 1])).err(), Some("a value read raw out of memory"));
        assert!(classify(&with_payload([1, 1])).is_ok(), "a merge of the value with itself still is one");
    }

    #[test]
    fn an_absent_arm_that_writes_is_not_a_helper() {
        // Both arms write, so both read as present, with different tags:
        // that is a `Result` with two payloads, not this shape.
        assert_eq!(classify(&helper(true)).err(), Some("present arms disagree on the tag"));
    }

    #[test]
    fn a_value_read_on_the_present_arm_qualifies() {
        // The tag is read as an `i32`, its low half: still the tag.
        assert_eq!(site_of(caller(false)), Ok(()));
    }

    #[test]
    fn a_value_read_before_the_test_moves_under_it() {
        // Read in the entry block, used only on the arm the test proves it
        // present on: it can move there.
        assert_eq!(site_of(caller(true)), Ok(()));
        let mut ir = module(vec![framed(caller(true)), helper(false)]);
        assert!(OptionalOutParamPass.run(&mut ir).changed);
        let c = &ir.functions[0];
        assert!(matches!(c.bindings.get(v(5)).unwrap().expr, Expr::Unwrap { value, .. } if value == v(2)));
        assert_eq!(block_containing(c, v(5)), Some(bb(1)), "the unwrap sits under the test");
    }

    /// `caller(true)`, but the early read is also returned after the
    /// branch, where nothing proves it present.
    fn caller_escaping() -> HighFunction {
        let mut f = caller(true);
        f.region = Region::Sequence(vec![
            Region::Basic(bb(0)),
            Region::If {
                cond: v(4),
                then_region: Box::new(Region::Sequence(vec![
                    Region::Basic(bb(1)),
                    Region::Return { values: vec![v(5)] },
                ])),
                else_region: None,
            },
            Region::Return { values: vec![v(5)] },
        ]);
        f
    }

    #[test]
    fn a_value_read_used_outside_the_present_arm_is_refused() {
        assert_eq!(site_of(caller_escaping()), Err("a value read not proven present"));
    }

    /// func_0: `return select(fallback, load(fp+8), load(fp+0))` — the
    /// value when the tag is `0` (present), the fallback otherwise.
    /// `swapped` puts the value on the absent side instead.
    fn caller_choice(swapped: bool) -> HighFunction {
        let (t, f) = if swapped { (4, 5) } else { (5, 4) };
        let exprs = vec![
            Expr::Phi { incoming: vec![] },                                         // v0 frame
            Expr::Phi { incoming: vec![] },                                         // v1 x
            Expr::Call { target: FuncId::from_index(1), args: vec![v(0), v(1)] }, // v2
            load(0, 0, MemWidth::W8),                                               // v3 tag
            load(0, 8, MemWidth::W8),                                               // v4 the value
            Expr::Literal(Literal::I64(7)),                                         // v5 fallback
            Expr::Unknown {
                op_kind: WasmOpcodeKind::Select,
                args: vec![v(t), v(f), v(3)],
                reason: UnknownReason::InsufficientEvidence,
            }, // v6
        ];
        func(
            0,
            exprs,
            vec![1],
            vec![vec![2, 3, 4, 5, 6]],
            Region::Sequence(vec![Region::Basic(bb(0)), Region::Return { values: vec![v(6)] }]),
        )
    }

    #[test]
    fn a_choice_between_the_value_and_a_fallback_on_the_tag_is_unwrap_or() {
        let mut ir = module(vec![framed(caller_choice(false)), helper(false)]);
        assert!(OptionalOutParamPass.run(&mut ir).changed);
        let c = &ir.functions[0];
        assert!(
            matches!(c.bindings.get(v(6)).unwrap().expr, Expr::UnwrapOr { value, default } if value == v(2) && default == v(5)),
            "the select is `unwrap_or(fallback)`"
        );
        assert!(matches!(c.bindings.get(v(4)).unwrap().expr, Expr::Literal(Literal::Unit)), "the read goes with it");
    }

    #[test]
    fn a_choice_taking_the_value_when_the_tag_says_absent_is_refused() {
        assert_eq!(site_of(caller_choice(true)), Err("a value read not proven present"));
    }

    #[test]
    fn what_runs_after_a_call_leaves_out_an_earlier_loop() {
        // Loop A (v0) runs and is left; v1; then loop B holds the call v2
        // and v4 after it, and is left only by returning.
        let exprs = vec![
            Expr::Literal(Literal::I32(0)),     // v0 in loop A
            Expr::Literal(Literal::I32(1)),     // v1 between
            Expr::Literal(Literal::I32(2)),     // v2 the call
            Expr::Literal(Literal::Bool(true)), // v3 a condition
            Expr::Literal(Literal::I32(4)),     // v4 after the call
        ];
        let f = func(
            0,
            exprs,
            vec![],
            vec![vec![0], vec![1], vec![2, 4]],
            Region::Sequence(vec![
                Region::Scope {
                    out: bb(1),
                    body: Box::new(Region::Loop {
                        header: bb(0),
                        body: Box::new(Region::Sequence(vec![
                            Region::Basic(bb(0)),
                            Region::If {
                                cond: v(3),
                                then_region: Box::new(Region::Break { target: bb(1), transfer: vec![] }),
                                else_region: None,
                            },
                            Region::Continue { target: bb(0), transfer: vec![] },
                        ])),
                        kind: sordec_ir::LoopKind::Unclassified,
                    }),
                },
                Region::Basic(bb(1)),
                Region::Loop {
                    header: bb(2),
                    body: Box::new(Region::Sequence(vec![
                        Region::Basic(bb(2)),
                        Region::If {
                            cond: v(3),
                            then_region: Box::new(Region::Return { values: vec![] }),
                            else_region: None,
                        },
                        Region::Continue { target: bb(2), transfer: vec![] },
                    ])),
                    kind: sordec_ir::LoopKind::Unclassified,
                },
            ]),
        );
        let after = runs_after(&f, v(2), v(3), Slot { offset: 0, bytes: 8 }).expect("structured");
        assert_eq!(after, HashSet::from([v(2), v(4)]), "its own loop goes round; the earlier one never runs again");
    }

    #[test]
    fn nothing_after_the_result_is_written_over_can_read_it() {
        let exprs = vec![
            Expr::Phi { incoming: vec![] },  // v0 frame
            Expr::Literal(Literal::I32(1)),  // v1 the call
            store(0, 5, 0),                  // v2 writes all 8 bytes
            Expr::Literal(Literal::I32(3)),  // v3 after that
            Expr::Literal(Literal::I32(4)),  // v4 a later block
            Expr::Literal(Literal::I64(0)),  // v5
        ];
        let f = func(
            0,
            exprs,
            vec![0],
            vec![vec![1, 2, 3], vec![4]],
            Region::Sequence(vec![Region::Basic(bb(0)), Region::Basic(bb(1))]),
        );
        assert_eq!(runs_after(&f, v(1), v(0), Slot { offset: 0, bytes: 8 }), Some(HashSet::from([v(2)])));
        // A wider result is not covered by the one store: everything runs.
        assert_eq!(
            runs_after(&f, v(1), v(0), Slot { offset: 0, bytes: 16 }),
            Some(HashSet::from([v(2), v(3), v(4)]))
        );
    }

    #[test]
    fn a_bulk_copy_touches_its_destination_and_its_source() {
        let exprs = vec![
            Expr::Phi { incoming: vec![] },                                              // v0 frame
            Expr::Binary { op: BinaryOp::Add, lhs: v(0), rhs: v(2) },                    // v1 fp+16
            Expr::Literal(Literal::I32(16)),                                             // v2
            Expr::Literal(Literal::I32(32)),                                             // v3 length
            Expr::Phi { incoming: vec![] },                                              // v4 a length not known
        ];
        let f = func(0, exprs, vec![0], vec![vec![1]], Region::Basic(bb(0)));
        assert_eq!(
            bulk_touches(&f, &[v(1), v(0), v(3)], v(0)),
            Some(vec![(Slot { offset: 16, bytes: 32 }, true), (Slot { offset: 0, bytes: 32 }, false)])
        );
        assert_eq!(bulk_touches(&f, &[v(1), v(0), v(4)], v(0)), None, "a length not known touches anything");
    }

    #[test]
    fn the_helper_returns_an_option_and_its_caller_asks_it() {
        let mut ir = module(vec![framed(caller(false)), helper(false)]);
        let result = OptionalOutParamPass.run(&mut ir);
        assert!(result.changed, "every site qualifies, so the helper is rewritten");

        // The helper: no out-pointer, one returned `Option`, built per arm.
        let h = &ir.functions[1];
        assert_eq!(h.params, vec![v(1)], "the out-pointer is no longer a parameter");
        let Region::Sequence(items) = &h.region else { panic!("a sequence") };
        assert_eq!(items.last(), Some(&Region::Return { values: vec![v(6)] }), "the merge is returned");
        let Some(Expr::Phi { incoming }) = h.bindings.get(v(6)).map(|b| &b.expr) else {
            panic!("the tag phi stays a phi");
        };
        let arms: Vec<&Expr> = incoming.iter().map(|(_, o)| &h.bindings.get(*o).unwrap().expr).collect();
        assert!(
            matches!(arms.as_slice(), [Expr::Optional { payload: None }, Expr::Optional { payload: Some(p) }] if p == &vec![v(1)]),
            "the failing arm is None, the other Some(value)"
        );
        for store in [v(5), v(7)] {
            assert!(
                matches!(h.bindings.get(store).unwrap().expr, Expr::Literal(Literal::Unit)),
                "out-pointer writes retire"
            );
        }

        // The caller: the call drops its frame, the reads ask the `Option`.
        let c = &ir.functions[0];
        let Some(Expr::Call { args, .. }) = c.bindings.get(v(2)).map(|b| &b.expr) else { panic!("v2 is the call") };
        assert_eq!(args, &vec![v(1)]);
        assert!(matches!(c.bindings.get(v(3)).unwrap().expr, Expr::Select { .. }), "the tag read is exact");
        assert!(
            matches!(c.bindings.get(v(5)).unwrap().expr, Expr::Unwrap { value, index: 0, arity: 1 } if value == v(2)),
            "the value read unwraps where it is proven present"
        );

        // Idempotent: nothing left to classify.
        assert!(!OptionalOutParamPass.run(&mut ir).changed);
    }

    #[test]
    fn one_refused_site_keeps_the_helper_as_it_is() {
        // The same helper, called once properly and once with the value
        // read where nothing proves it present: the signature cannot change
        // for one caller.
        let mut early = caller_escaping();
        early.id = FuncId::from_index(2);
        let mut ir = module(vec![framed(caller(false)), helper(false), framed(early)]);
        assert!(!OptionalOutParamPass.run(&mut ir).changed);
        assert_eq!(ir.functions[1].params.len(), 2, "the helper keeps its out-pointer");
    }

    #[test]
    fn a_bulk_copy_out_of_the_result_reads_it() {
        // memory.copy(elsewhere, fp, 16): the result's 16 bytes, read
        // through a copy the rewrite would leave reading stale memory.
        let copy = caller_then(vec![i32c(16), opaque(), bulk(7, 0, 6)]);
        assert_eq!(plan_in(vec![copy, helper(false)]), Err("a bulk copy may read the result"));
        // memory.copy(elsewhere, fp + 64, 16) reads beside it.
        let beside = caller_then(vec![
            i32c(16),
            opaque(),
            i32c(64),
            Expr::Binary { op: BinaryOp::Add, lhs: v(0), rhs: v(8) },
            bulk(7, 9, 6),
        ]);
        assert_eq!(plan_in(vec![beside, helper(false)]), Ok((1, 1)));
    }

    #[test]
    fn a_bulk_operation_of_unknown_length_on_the_frame_is_refused() {
        let fill = caller_then(vec![opaque(), i32c(0), bulk(0, 7, 6)]);
        assert_eq!(plan_in(vec![fill, helper(false)]), Err("a bulk copy or fill of unknown length on the frame"));
    }

    #[test]
    fn a_bulk_fill_over_the_result_is_the_write_its_reads_see() {
        // memory.fill(fp, 0, 16) right after the call: both reads see the
        // fill's zeros, not the helper's bytes, and are left as they are.
        let fill = || caller_then(vec![i32c(16), i32c(0), bulk(0, 7, 6)]);
        assert_eq!(plan_in(vec![fill(), helper(false)]), Ok((0, 0)));
        let mut ir = module(vec![framed(fill()), helper(false)]);
        assert!(OptionalOutParamPass.run(&mut ir).changed);
        let c = &ir.functions[0];
        for read in [v(3), v(5)] {
            assert!(matches!(c.bindings.get(read).unwrap().expr, Expr::Load { .. }), "the read still reads the fill");
        }
    }

    #[test]
    fn a_write_over_part_of_a_read_refuses_the_site() {
        // memory.fill(fp, 0, 2) leaves the tag read's upper two bytes to
        // the helper.
        let fill = caller_then(vec![i32c(2), i32c(0), bulk(0, 7, 6)]);
        assert_eq!(plan_in(vec![fill, helper(false)]), Err("a read whose nearest write covers only part of it"));
        // So does a one-byte store.
        let store = caller_then(vec![
            i32c(0),
            Expr::Store { addr: v(0), value: v(6), offset: 0, width: MemWidth::W1 },
        ]);
        assert_eq!(plan_in(vec![store, helper(false)]), Err("a read whose nearest write covers only part of it"));
    }

    #[test]
    fn a_callee_that_bulk_copies_through_the_frame_refuses_the_site() {
        // func_2(p) { memory.copy(dst, src, 16) }, handed the frame.
        let callee = |src: u32| {
            func(2, vec![opaque(), opaque(), i32c(16), bulk(1, src, 2)], vec![0], vec![vec![2, 3]], Region::Basic(bb(0)))
        };
        let call = || caller_then(vec![Expr::Call { target: FuncId::from_index(2), args: vec![v(0)] }]);
        assert_eq!(
            plan_in(vec![call(), helper(false), callee(0)]),
            Err("another call may read the result"),
            "copying from its parameter, it reads the result"
        );
        assert_eq!(plan_in(vec![call(), helper(false), callee(1)]), Ok((1, 1)), "copying elsewhere, it touches nothing");
        // func_2(p) { memory.copy(p + 64, src, 16) }: it writes beside the
        // result and reads nothing of the frame.
        let beside = func(
            2,
            vec![opaque(), opaque(), i32c(16), i32c(64), Expr::Binary { op: BinaryOp::Add, lhs: v(0), rhs: v(3) }, bulk(4, 1, 2)],
            vec![0],
            vec![vec![2, 3, 4, 5]],
            Region::Basic(bb(0)),
        );
        assert_eq!(plan_in(vec![call(), helper(false), beside]), Ok((1, 1)));
        // func_2(p) { memory.copy(p, src, n) } with `n` not known: anything.
        let unknown = func(2, vec![opaque(), opaque(), opaque(), bulk(0, 1, 2)], vec![0], vec![vec![3]], Region::Basic(bb(0)));
        assert_eq!(
            plan_in(vec![call(), helper(false), unknown]),
            Err("the frame is handed to a call that may read anything")
        );
    }

    /// func_2, three parameters whose body stores through `dst + n` — an
    /// address no constant locates, so what it reaches is unknown — standing
    /// in for a memory routine's loops. With `memcpy`'s fingerprint on it,
    /// a call is counted by its arguments instead.
    fn copy_routine() -> HighFunction {
        func(
            2,
            vec![
                opaque(),                                                    // v0 dst
                opaque(),                                                    // v1 src
                opaque(),                                                    // v2 n
                Expr::Binary { op: BinaryOp::Add, lhs: v(0), rhs: v(2) },    // v3
                Expr::Store { addr: v(3), value: v(1), offset: 0, width: MemWidth::W1 },
            ],
            vec![0, 1, 2],
            vec![vec![3, 4]],
            Region::Basic(bb(0)),
        )
    }

    fn memcpy_print() -> Option<u128> {
        sordec_sigs::builtins::MEM_ROUTINES
            .iter()
            .find(|e| e.routine == sordec_sigs::MemRoutine::Memcpy)
            .map(|e| e.fingerprint.to_u128())
    }

    #[test]
    fn a_call_to_a_memory_routine_with_a_constant_length_touches_its_bytes() {
        // func_2(fp + 64, x, 16) beside the result, func_2(x, fp, 16) reading
        // it, and func_2(fp + 64, x, x) of a length not known.
        let call = |dst: u32, src: u32, len: u32| {
            caller_then(vec![
                i32c(64),
                Expr::Binary { op: BinaryOp::Add, lhs: v(0), rhs: v(6) },
                i32c(16),
                Expr::Call { target: FuncId::from_index(2), args: vec![v(dst), v(src), v(len)] },
            ])
        };
        let named = vec![None, None, memcpy_print()];
        assert_eq!(plan_with_prints(vec![call(7, 1, 8), helper(false), copy_routine()], named.clone()), Ok((1, 1)));
        assert_eq!(
            plan_with_prints(vec![call(1, 0, 8), helper(false), copy_routine()], named.clone()),
            Err("another call may read the result")
        );
        assert_eq!(
            plan_with_prints(vec![call(7, 1, 1), helper(false), copy_routine()], named),
            Err("the frame is handed to a call that may read anything")
        );
        // The same body without the fingerprint is a call it cannot see into.
        assert_eq!(
            plan_in(vec![call(7, 1, 8), helper(false), copy_routine()]),
            Err("the frame is handed to a call that may read anything")
        );
    }

    #[test]
    fn a_callee_that_calls_a_memory_routine_on_its_pointer_touches_its_bytes() {
        // func_3(p) { func_2(p + 64, src, 16) }, handed the frame.
        let callee = func(
            3,
            vec![
                opaque(),
                opaque(),
                i32c(64),
                Expr::Binary { op: BinaryOp::Add, lhs: v(0), rhs: v(2) },
                i32c(16),
                Expr::Call { target: FuncId::from_index(2), args: vec![v(3), v(1), v(4)] },
            ],
            vec![0],
            vec![vec![2, 3, 4, 5]],
            Region::Basic(bb(0)),
        );
        let call = || caller_then(vec![Expr::Call { target: FuncId::from_index(3), args: vec![v(0)] }]);
        assert_eq!(
            plan_with_prints(
                vec![call(), helper(false), copy_routine(), callee.clone()],
                vec![None, None, memcpy_print(), None]
            ),
            Ok((1, 1))
        );
        assert_eq!(
            plan_in(vec![call(), helper(false), copy_routine(), callee]),
            Err("the frame is handed to a call that may read anything")
        );
    }

    fn raw_call_indirect(args: Vec<ValueId>) -> Expr {
        Expr::Unknown { op_kind: WasmOpcodeKind::CallIndirect, args, reason: UnknownReason::UnsupportedPattern }
    }

    #[test]
    fn a_raw_call_indirect_handed_the_frame_may_read_anything() {
        let call = caller_then(vec![i32c(3), raw_call_indirect(vec![v(0), v(6)])]);
        assert_eq!(plan_in(vec![call, helper(false)]), Err("the frame is handed to a call that may read anything"));
    }

    #[test]
    fn an_unrecovered_indirect_call_keeps_a_helper_a_table_may_hold() {
        // func_2 makes a raw `call_indirect`; the helper is func_1.
        let indirect = || {
            let mut f = crate::marshalling::test_support::func_with(
                vec![i32c(0), raw_call_indirect(vec![v(0)])],
                vec![],
                vec![0, 1],
            );
            f.id = FuncId::from_index(2);
            f
        };
        let import = sordec_ir::Import {
            index: 0,
            module: "x".to_string(),
            name: "_".to_string(),
            kind: sordec_ir::ImportKind::Func(0),
        };
        // (function imports, element-declared global indices, rewritten)
        let cases = [
            (0, None, false),          // the declared set is not known
            (0, Some(vec![1]), false), // the table holds the helper
            (0, Some(vec![2]), true),  // only the indirect caller is declared
            (1, Some(vec![2]), false), // global 2 is local 1, the helper
            (1, Some(vec![1]), true),  // global 1 is local 0, the caller
        ];
        for (imports, table, rewritten) in cases {
            let mut ir = module(vec![framed(caller(false)), helper(false), indirect()]);
            ir.facts.imports = vec![import.clone(); imports];
            ir.facts.table_functions = table.clone();
            assert_eq!(OptionalOutParamPass.run(&mut ir).changed, rewritten, "imports {imports}, table {table:?}");
            assert_eq!(ir.functions[1].params.len(), if rewritten { 1 } else { 2 });
        }
    }
}
