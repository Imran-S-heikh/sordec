//! Take apart a `#[contracttype]` enum decoded inline through the SDK's
//! vector iterator: the decode and the switch on its variant become a
//! `match` on the value that binds each variant's payload.
//!
//! # The shape
//!
//! ```rust,ignore
//! pub fn get_data(env: Env, key: DataKey) -> Option<i64> {
//!     match key {
//!         DataKey::Persistent(_) => env.storage().persistent().get(&key),
//!         DataKey::Temp(_) => ..,
//!     }
//! }
//! ```
//!
//! A `#[contracttype]` enum travels as a vector: the variant's name as a
//! symbol, then its payload. When rustc inlines the derived `TryFromVal`
//! into the entrypoint it walks that vector with the SDK's iterator, whose
//! state (the vector, the next index, the length) sits in the frame and
//! whose `next` is a small helper writing `Option<Val>` into memory the
//! caller provides:
//!
//! ```text
//! len = vec_len(key)
//! store fp+0 <- key ; store fp+8 <- 0 ; store fp+12 <- len
//! next(fp+16, fp) ; if load fp+16 != 0 { trap }      ; element 0
//! s = load fp+24 ; <s is a symbol, else trap>
//! i = symbol_index(s, ["Persistent", "Temp", ...]) ; if i > 2 { trap }
//! match i {
//!     1 => { if len - idx > 1 { trap }                ; one payload element
//!            next(fp+16, fp) ; if load fp+16 != 0 { trap }
//!            x = load fp+24 ; <x is a u32, else trap> ; p = decode(x) ; .. }
//!     ..
//! }
//! ```
//!
//! # The rewrite
//!
//! The switch selects on `key` itself (`index` and `dispatch` both `key`,
//! see `Region::Switch::dispatch`); an arm whose variant has a payload opens
//! with it (`Expr::VariantPayload`), and the element's reads become the
//! payload — `decode(x)` of a `u32` (or a unit enum's code) its value
//! widened, any other use the payload itself. The iterator, its state, the
//! symbol, the lookup and every check made on them go:
//!
//! ```text
//! match key { DataKey::Temp(p) => { .. p .. }, .. }
//! ```
//!
//! # Why it is exact
//!
//! The value is proven to be the enum: an entrypoint parameter the spec
//! declares with it, a value an earlier decode typed (`udt_of`), or an
//! element `vec_get` reads from a vector of the enum — a parameter the spec
//! declares `Vec<E>`, a vector an earlier pass proved one, or
//! `__check_auth`'s `Vec<Context>`, which the custom account interface
//! fixes — or a value `map_get` reads from a map an earlier pass typed
//! `Map<K, E>` from a declaration (a recovered struct's field). Its `Val`
//! is then a vector holding the variant's name and its payload's `Val`s,
//! one each — and the code that reads it is the derived decode, which the
//! re-emitted `#[contracttype]` regenerates where the value enters: in the
//! entrypoint wrapper, or, for an element, in the typed collection's own
//! read (`get_unchecked`, `iter`, `Map::get`), as every marshalling
//! elision relocates its decode. The element is then typed as the enum.
//!
//! `Context` is the SDK's (`soroban_sdk::auth`, `export = false`), so no
//! spec declares it; its declaration is the auth table's
//! (`auth_entries`), as the SDK version the contract was built with has it,
//! registered as imported from the SDK only when a match names it.
//!
//! Each step the rewrite takes away is that decode's:
//!
//! - **The iterator is the SDK's.** `next` reads the state it is handed
//!   (vector at +0, index at +8, length at +12), and on the paths that
//!   leave a tag other than `2` (`None`) it writes `vec_get(vector, index)`
//!   to +8 of its out-pointer and `index + 1` back; its tags are `0` and
//!   `2` only. The state is set from the value (`v`, `0`, `vec_len(v)`)
//!   and nothing but these calls and loads of the index and length touches
//!   those 16 bytes while the decode uses them, so the state is the
//!   iterator's own. rustc gives the bytes to other locals once the decode
//!   is done with them (an event's topics, built in the frame): a forward
//!   walk (`ordered`) proves no decode access may follow another write to
//!   them on any path, and that no other read may see what the decode left
//!   there — which only taking the decode away would change, so such a
//!   read keeps the decode (as proven, see below) rather than refusing it.
//!   What a helper handed a frame pointer touches is its summary; one that
//!   computes with the pointer (`p + 8`) is summarised by the bytes its
//!   loads and stores reach through it (`udt_decode::widened`).
//! - **Two decodes may take the same 16 bytes in turn.** rustc gives the
//!   iterator state of a decode nested in another's arm (a payload's own
//!   field decoded as the enum again) the frame slot the outer decode is
//!   done with. Each setting of the state is the three stores of one
//!   vector, its `0` and its length, in one block with no call or load of
//!   the state between them. A forward walk of the region tree
//!   (`reach::walk`) records, for every `next` call and load of the index
//!   or length, which settings last ran on some path to it. One that
//!   follows this decode's setting on every path, and no other, reads this
//!   decode's state: no other setting lies on any path between them, so
//!   the bytes are this vector's. One that follows only another's setting
//!   is that decode's and is left alone; one that may follow either
//!   refuses the site. What this decode removes is only its own.
//! - **The k-th call reads element k.** The state's three stores sit in
//!   one block with no call between them, so after the first a call sees
//!   all three. A forward walk of the region tree counts, on every path,
//!   the calls made since the state was last set, round loops included
//!   (`udt_decode::reach::walk`): a call reads element `k` when that count
//!   is `k` on every path reaching it, and is refused otherwise — a call
//!   the state's setting does not precede, or one two paths reach with two
//!   counts. Inside a loop each iteration sets the state afresh from that
//!   iteration's value before its calls, so the count restarts. The first
//!   call is the one whose element the lookup reads, with count `0`; every
//!   other call sits in exactly one arm of the switch, at most one per arm,
//!   with count `1`. A variant has at most one payload
//!   component (larger ones are refused), so every call reads an index
//!   below the vector's length and returns `Some`: its element slot holds
//!   that element. A read of the slot is that element where the reach
//!   check (`udt_decode::reach`) proves it reads the call's write whole on
//!   every path. A helper writing a `Result` the caller then tests (the
//!   payload's own decoder) writes its fields where the reach check is told
//!   so: on the side of the test where its tag is not the failing one
//!   (`gated_summary`, as `enum_match` uses it).
//! - **The switch is on the variant.** Element 0 is the variant's name;
//!   the lookup's table is the enum's variant names in declared order, so
//!   it returns the variant's position, and the switch on it takes the arm
//!   for that position. The rewritten switch selects on the value's
//!   variant, which is that position.
//! - **Element 1 is the payload.** On the arm of a variant with one
//!   component, element 1 is that component's `Val`. `decode(x)` of a
//!   `u32`'s `Val` is its body, the `u32` zero-extended; a unit enum's is
//!   its code, the same. Any other use takes the `Val`, which for a type
//!   carried as its own `Val` (a contract type, a handle) is the value.
//!   rustc folds a unit enum's check into `select(chain, k, is_u32(x))`,
//!   the chain sending each declared discriminant of `x`'s code to itself
//!   and anything else to a code no case has, `k` no case's code either:
//!   on the payload `x` is a `U32Val` holding a declared code, so the
//!   select is that code, the payload's discriminant (`p as i32`).
//! - **The checks go.** Every value computed only from the decode's own
//!   data — the iterator state, the `next` tags, the elements' tags, the
//!   symbol, the lookup — is invisible to the source, which sees only the
//!   variant and the payload; a trap such a value guards is the derived
//!   decode's failure path, never taken on a proven value. So `if c { trap }`
//!   goes, `if c { x } else { trap }` becomes `x`, and a branch both of whose
//!   ways are then empty goes. The lookup's position is the one such value
//!   the source does see (it is the variant): a test of it goes only when it
//!   is `position > k` with `k` at least the last position, false for every
//!   variant.
//! - **Removing the decode loses no read.** Every read of the state and of
//!   each call's slot is one of the above (the reach check refuses a call
//!   otherwise), and every use of the values derived from them is removed
//!   or rewritten, all or nothing.
//!
//! When the variant whose code follows the switch (its default arm, falling
//! through into the rest of the sequence because no other arm does) has a
//! payload, the rest moves into the default arm — it runs exactly when
//! control falls out of the switch, which only the default does — and that
//! arm names the variant: no other position is left for it to take.
//!
//! The same when the default arm is a bare `break` out of a scope around
//! the switch, the scope's body never falls out of it, and that `break` is
//! the only one to the scope: the code after the scope in its sequence is
//! then reached only through the default, and moves into it in place of
//! the `break`. Breaks and continues in it still name constructs around
//! it. If it can fall off the end of its sequence, that sequence must be a
//! scope's body, and a `break` to that scope ends the moved code — where
//! falling off went.
//!
//! The value's own check that it is a vector (the first step of its
//! derived conversion, `Vec<Val>::try_from_val`) is a check of the decode
//! like the others, and goes with it.
//!
//! # Gates
//!
//! - `next`: no spec, `(out, state)`; `out` only stored at +0 (8 bytes,
//!   every path) and +8 (8 bytes); `state` only read at +0/8, +8/4,
//!   +12/4 and written at +8/4; the tag a merge of `0` and `2`, the element
//!   and index stores together on the paths whose tag is not `2`; the
//!   element `vec_get(load +0, U32Val(load +8))`, the index that load
//!   plus one.
//! - The value proven to be a declared enum (a parameter, a typed value, an
//!   element of a typed vector, a value of a typed map) every variant of
//!   which has at most one payload component (`Context` declared by the auth table, for
//!   an SDK major it covers, and only when the contract declares no type
//!   of its name).
//! - The state: three stores of the value, `0` and its `vec_len`, in one
//!   block with no call between them; nothing else touches its 16 bytes
//!   but `next` calls handed it and loads of the index and length, except
//!   after every decode access on every path, with a reach that can be told
//!   (a load, a store, a summarised helper, a host collection built from
//!   memory); a pointer into the frame stored or handed on unsummarised
//!   refuses. When
//!   several vectors set it, each setting is such a group, the walk over
//!   the whole region completes, and every call and state load this
//!   decode takes follows its setting alone on every path.
//! - One lookup over the enum's variant names, on an element of the first
//!   call; one switch on its position; every other call in a single-case
//!   arm (or the default, or the code its bare `break` alone reaches) of
//!   that switch whose variant has a payload, one per arm.
//! - Every call's count from the state's setting the same on every path:
//!   `0` for the first, `1` for an arm's; the whole region walked.
//! - Each call: the reach check accepts its slot; its element read whole.
//! - A payload's uses: in its arm; `decode` only for a `u32` or unit enum;
//!   a unit enum's checked code only as the select chain above, its codes
//!   exactly the declared ones; other non-check uses only for a type
//!   carried as its own `Val`.
//!
//! - Every removed value's uses removed with it; each condition is a trap
//!   guard, an inverted trap guard, or a branch left empty.
//!
//! Not taken yet: a variant of several components (`X(a, b)`), a payload
//! of a numeric type other than `u32` (`i64`, `i128`: their two-form
//! decodes), a tuple payload, and a payload carried out of its arm by a
//! merge (but see below).
//!
//! # A decode kept: the variant tested again
//!
//! ```rust,ignore
//! pub fn propose(env: Env, action: Action) -> Result<u32, Error> {
//!     check_action(&action)?;      // match action { Pay(p) if p.amount <= 0 => Err(..), .. }
//!     let d = action.clone().to_xdr(&env);
//!     ..
//! }
//! ```
//!
//! rustc decodes `action` once and carries each variant's payload out of
//! its arm in registers — merges that take the payload's value on its own
//! variant and whatever the register held on the others (the vector's
//! length, a tag word, `0`). Each later `match` on the variant is a switch
//! on the same position reading those merges. Such a decode is not taken
//! apart (the merges and the other switches read it), but everything up to
//! the payloads is proven as above (`Proof`), and two things follow:
//!
//! - **A struct payload's element is typed as the struct.** On the arm of
//!   `X(S)`, element 1 is `S`'s `Val`, and a struct is carried as its own
//!   `Val`; the payload's derived decoder helper the arm hands it to is then
//!   that struct's decode (`udt_decode`), and its slot reads become the
//!   fields.
//! - **A later switch on the position becomes a `match` on the value.**
//!   It selects on the same position, so it takes the arm of the value's
//!   variant. Each merge its arm of variant `k` reads is, there, the value
//!   the decode's arm `k` gave it: every path to the later switch went
//!   through the decode's switch, in arm `k`. Where that value was computed
//!   from the payload alone, the arm binds the payload and recomputes it
//!   (`Step`): the element becomes the payload for a type carried as its own
//!   `Val`, `decode(x)` of a `u32` the payload widened, and every pure step
//!   between (a field, a limb, a narrowing) is cloned. Where it was computed
//!   before the decode's switch, it is read as it is.
//!
//! ## Why it is exact
//!
//! - The position is the variant's (proven as for the decode above), and
//!   the later switch reads the same SSA value, so the arm it takes is the
//!   arm of `value`'s variant: selecting on `value` takes the same one.
//! - A merge every input of which comes out of an arm of the decode's
//!   switch holds, after it, the input of the arm that ran; the later switch
//!   lies after the decode's switch in its sequence, so every path to it
//!   ran exactly that arm last, the one of the same position. On arm `k`
//!   the merge is therefore arm `k`'s input — one value, or the switch is
//!   left alone.
//! - The recomputation reads only the payload and constants, through pure
//!   operations, and the payload the later arm binds is the one the decode
//!   read: the same value's same variant.
//! - A default that stands for one variant and reads its payload becomes
//!   that variant's arm; the rest of the sequence after the switch, which
//!   only the default reaches (no arm falls out), moves into it, as for the
//!   decode's own default above.
//!
//! ## Gates
//!
//! - The decode proven up to its payloads; the later switch a switch on its
//!   position, after its switch in the same sequence, every case a variant.
//! - Each merge read: every input out of the decode's switch; on the arm's
//!   variant one value; that value computed before the switch (read as is)
//!   or from the arm's payload element alone through pure steps, the leaves
//!   the element of a type carried as its own `Val` or `decode` of a `u32`.
//! - An arm needing the payload stands for one variant; a default that
//!   moves the rest falls into it.
//!
//! The merges stay, read by whatever else reads them (the raw stores of a
//! struct the value is written into). Where only such holes read one, the
//! backend leaves out the inputs its declared type cannot hold: nothing
//! that runs reads it (`hole_read_merges`). That hides the merge's mixed
//! type; it does not recover it.

use std::collections::{BTreeSet, HashMap, HashSet};

use sordec_common::{BlockId, FuncId, Provenance, ProvenanceSource, TypeId, ValueId};
use sordec_ir::{
    BinaryOp, BufOpKind, CompositeType, Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Literal, MapOpKind, MemWidth,
    Region, SdkType, SemanticOp, StructDef, SwitchArm, TypeRef, TypeRegistry, UnaryOp, UnionDef, VecOpKind,
};

use super::auth_entries::SdkTypes;
use super::enum_match::{blocks_in, expr_of, falls_through, gated_summary, open_arm, scheduled};
use super::udt_decode::reach::{self, Gated};
use super::udt_decode::{param_accesses, raw_address, read_keys, udt_of, Candidate, CertainWrite, ParamAccess, Role, Slot};
use super::{apply_elisions, Elision};
use crate::dataflow::{canon_addr, resolve_use, trace_int, trace_u32val, HighUseIndex, HighUseSite};
use crate::metrics_catalog as mc;
use crate::pass::{Pass, PassResult};
use crate::type_infer::known_of_type_ref;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-enum-iter";

/// Takes inline enum decodes apart into a `match`; see the module docs.
#[derive(Debug, Default, Clone, Copy)]
pub struct EnumIterPass;

impl Pass<HighIr> for EnumIterPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let Some(facts) = ir.soroban_facts.as_ref() else {
            return result;
        };
        let mut types = facts.types.clone();
        // `__check_auth`'s contexts are the SDK's `Context`, which no spec
        // declares: its declaration comes from the auth table, as the SDK
        // version the contract was built with has it.
        let sdk = if ir.functions.iter().any(takes_auth_contexts) {
            super::auth_entries::sdk_major(facts)
                .and_then(|major| SdkTypes::register(&types, major, super::auth_entries::CONTEXT))
        } else {
            None
        };
        let context = sdk.as_ref().and_then(|s| s.id(super::auth_entries::CONTEXT));
        if let Some(s) = sdk {
            types = s.types;
        }
        if types.unions.is_empty() {
            return result;
        }
        let access: HashMap<FuncId, Vec<Option<ParamAccess>>> =
            ir.functions.iter().map(|f| (f.id, param_accesses(f))).collect();
        let nexts: HashSet<FuncId> =
            ir.functions.iter().filter(|f| is_next(ir, f, access.get(&f.id))).map(|f| f.id).collect();
        if nexts.is_empty() {
            return result;
        }
        // Every helper whose writes a tag word gates: `next`, and the
        // decoders of a payload that write a `Result` into the frame.
        let gated: HashMap<FuncId, Vec<Option<Gated>>> =
            ir.functions.iter().map(|f| (f.id, gated_summary(ir, f, access.get(&f.id)))).collect();
        // What a call can touch through a pointer it is handed, for the
        // decode's checks: a helper that computes with its pointer (`p + 8`)
        // has no exact summary, but the bytes its loads and stores reach
        // through it are known (`Frames::param_touches`).
        let access = super::udt_decode::widened(ir, access);
        let memory = ir.memory.clone();
        let mut sdk_used = false;
        for func in &mut ir.functions {
            let mut tried: HashSet<ValueId> = HashSet::new();
            // A site rewrites the region, so the next is planned afresh.
            for _ in 0..16 {
                let (site, refused) = plan(func, &memory, &types, context, &nexts, &access, &gated, &mut tried, &mut Vec::new());
                result.metrics.increment(mc::MARSHALLING_ENUM_ITER_REFUSED, refused);
                let Some(site) = site else { break };
                sdk_used |= types.sdk_module(site.union).is_some();
                let payloads = apply(func, site);
                result.metrics.increment(mc::MARSHALLING_ENUM_ITER_SITES, 1);
                result.metrics.increment(mc::MARSHALLING_ENUM_ITER_PAYLOADS, payloads);
                result.changed = true;
            }
            // Decodes proven but kept: a struct payload's element is typed
            // as the struct, and a later switch on the variant becomes a
            // match on the value (see `rematch`). Planned afresh after each
            // re-match, which rewrites the region.
            for _ in 0..8 {
                let mut kept: Vec<Proof> = Vec::new();
                let _ = plan(func, &memory, &types, context, &nexts, &access, &gated, &mut HashSet::new(), &mut kept);
                let mut again = false;
                for proof in &kept {
                    let typed = type_struct_payloads(func, proof, &types);
                    if typed > 0 {
                        result.metrics.increment(mc::MARSHALLING_ENUM_ITER_PAYLOADS, typed);
                        result.changed = true;
                    }
                    if rematch(func, proof, &types) {
                        result.metrics.increment(mc::MARSHALLING_ENUM_ITER_SITES, 1);
                        result.changed = true;
                        again = true;
                        break;
                    }
                }
                if !again {
                    break;
                }
            }
        }
        // The SDK's types join the registry only when a match names them.
        if sdk_used && let Some(facts) = ir.soroban_facts.as_mut() {
            facts.types = types;
        }
        result
    }
}

/// Whether `f` is handed `Vec<Context>`: the custom account interface's
/// `__check_auth`, whose contexts the protocol fixes.
fn takes_auth_contexts(f: &HighFunction) -> bool {
    f.signature.as_ref().is_some_and(|s| {
        s.inputs.iter().any(|p| {
            matches!(&p.ty, TypeRef::Composite(CompositeType::Vec(e)) if matches!(**e, TypeRef::Sdk(SdkType::AuthContext)))
        })
    })
}

/// The declared enum the elements of `vec` are: a `Vec` of it by the spec
/// (an entrypoint parameter, or `__check_auth`'s `Vec<Context>`, which the
/// protocol fixes) or by a type an earlier pass proved.
fn element_union(func: &HighFunction, vec: ValueId, context: Option<TypeId>) -> Option<TypeId> {
    let vec = resolve_use(func, vec);
    if let Some(index) = func.params.iter().position(|p| *p == vec)
        && let Some(sig) = func.signature.as_ref()
        && let TypeRef::Composite(CompositeType::Vec(e)) = &sig.inputs.get(index)?.ty
    {
        return match &**e {
            TypeRef::UserDefined(id) => Some(*id),
            TypeRef::Sdk(SdkType::AuthContext) => context,
            _ => None,
        };
    }
    match &func.bindings.get(vec)?.ty {
        IrType::Known(KnownType::Vec(e)) => match &**e {
            IrType::Known(KnownType::UserDefined(id)) => Some(*id),
            _ => None,
        },
        _ => None,
    }
}

/// The enum `value` is proven to be, and whether that proof is the vector
/// it was read from (the value is then typed with the match): a value
/// already typed (`udt_of`), or an element `vec_get` reads from a vector of
/// the enum.
fn proven_union(func: &HighFunction, value: ValueId, context: Option<TypeId>) -> Option<(TypeId, bool)> {
    if let Some(id) = udt_of(func, value) {
        return Some((id, false));
    }
    match func.bindings.get(value).map(|b| &b.expr)? {
        Expr::Semantic(SemanticOp::Known(KnownOp::VecOp { kind: VecOpKind::Get, args })) if args.len() == 2 => {
            element_union(func, args[0], context).map(|id| (id, true))
        }
        Expr::Semantic(SemanticOp::Known(KnownOp::MapOp { kind: MapOpKind::Get, args })) if args.len() == 2 => {
            map_value_union(func, args[0]).map(|id| (id, true))
        }
        _ => None,
    }
}

/// The declared enum the values of `map` are: a map an earlier pass typed
/// `Map<K, E>` from a declaration (a recovered struct's field, say). A value
/// `map_get` reads from it is then an `E`, decoded where `Map::get` reads it.
fn map_value_union(func: &HighFunction, map: ValueId) -> Option<TypeId> {
    match &func.bindings.get(resolve_use(func, map))?.ty {
        IrType::Known(KnownType::Map(_, v)) => match &**v {
            IrType::Known(KnownType::UserDefined(id)) => Some(*id),
            _ => None,
        },
        _ => None,
    }
}

#[allow(clippy::print_stderr)]
fn trace(func: &HighFunction, why: &str) {
    if std::env::var_os("SORDEC_ENUM_TRACE").is_some() {
        eprintln!("enum-iter: func_{}: {why}", sordec_common::IrId::index(func.id));
    }
}

// ---------------------------------------------------------------------
// The iterator's `next`
// ---------------------------------------------------------------------

/// Whether `f` is the SDK vector iterator's `next` (see *Gates*).
fn is_next(ir: &HighIr, f: &HighFunction, access: Option<&Vec<Option<ParamAccess>>>) -> bool {
    if f.signature.is_some() || f.params.len() != 2 {
        return false;
    }
    let Some(acc) = access else { return false };
    let (Some(Some(out)), Some(Some(it))) = (acc.first(), acc.get(1)) else { return false };
    let set = |v: &[(u32, u32)]| v.iter().copied().collect::<BTreeSet<_>>();
    if !out.reads.is_empty() || set(&out.writes) != BTreeSet::from([(0, 8), (8, 8)]) {
        return false;
    }
    if set(&it.reads) != BTreeSet::from([(0, 8), (8, 4), (12, 4)]) || set(&it.writes) != BTreeSet::from([(8, 4)]) {
        return false;
    }
    let gated = gated_summary(ir, f, Some(acc));
    let Some(Some(g)) = gated.first() else { return false };
    if g.width != 8 || g.none != 2 || g.writes != [(8, 8)] {
        return false;
    }
    let (out_p, it_p) = (f.params[0], f.params[1]);
    let mut elem: Option<(BlockId, ValueId)> = None;
    let mut next_idx: Option<(BlockId, ValueId)> = None;
    let mut tag: Option<ValueId> = None;
    for (b, v) in scheduled(f) {
        let Some(Expr::Store { addr, value, offset, width }) = f.bindings.get(v).map(|b| &b.expr) else { continue };
        let a = resolve_use(f, *addr);
        match (a == out_p, a == it_p, *offset, *width) {
            (true, _, 0, MemWidth::W8) => tag = Some(*value),
            (true, _, 8, MemWidth::W8) if elem.is_none() => elem = Some((b, *value)),
            (_, true, 8, MemWidth::W4) if next_idx.is_none() => next_idx = Some((b, *value)),
            _ => return false,
        }
    }
    let (Some((eb, elem)), Some((ib, next_idx)), Some(tag)) = (elem, next_idx, tag) else { return false };
    if eb != ib {
        return false;
    }
    // The tags: `0` and `2`, nothing else.
    let Some(Expr::Phi { incoming }) = expr_of(f, tag) else { return false };
    if incoming.is_empty() || !incoming.iter().all(|(_, x)| matches!(trace_int(f, *x), Some(0 | 2))) {
        return false;
    }
    let load_of = |v: ValueId, off: u32, w: MemWidth| -> Option<ValueId> {
        let v = resolve_use(f, v);
        match &f.bindings.get(v)?.expr {
            Expr::Load { addr, offset, width, .. } if resolve_use(f, *addr) == it_p && *offset == off && *width == w => {
                Some(v)
            }
            _ => None,
        }
    };
    let Some(Expr::Semantic(SemanticOp::Known(KnownOp::VecOp { kind: VecOpKind::Get, args }))) = expr_of(f, elem)
    else {
        return false;
    };
    let [vec, at] = args.as_slice() else { return false };
    if load_of(*vec, 0, MemWidth::W8).is_none() {
        return false;
    }
    let Some(Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { value: index, .. }))) = expr_of(f, *at) else {
        return false;
    };
    let Some(index) = load_of(*index, 8, MemWidth::W4) else { return false };
    let Some(Expr::Binary { op: BinaryOp::Add, lhs, rhs }) = expr_of(f, next_idx) else { return false };
    [(*lhs, *rhs), (*rhs, *lhs)].iter().any(|(a, k)| resolve_use(f, *a) == index && trace_int(f, *k) == Some(1))
}

// ---------------------------------------------------------------------
// A site
// ---------------------------------------------------------------------

/// One inline decode taken apart.
#[derive(Debug)]
struct Site {
    value: ValueId,
    /// The enum the value is.
    union: TypeId,
    /// The value is an element read from a vector of the enum, typed with
    /// the match.
    element: bool,
    /// The default arm is `break` to an enclosing scope, the code after
    /// which runs only through it: that code moves into the arm.
    hoist: Option<Hoist>,
    /// The bindings that go, with every use.
    removed: HashSet<ValueId>,
    /// `decode(x)` of a payload element: `(binding, arm key)`.
    decodes: Vec<(ValueId, ArmKey)>,
    /// A unit enum payload's checked code: `(binding, arm key)`.
    codes: Vec<(ValueId, ArmKey)>,
    /// Conditions of `if c { trap }` (no else), `if c { trap } else { x }`,
    /// `if c { x } else { trap }` and `if c { .. } else { .. }` left empty.
    strip: HashSet<ValueId>,
    keep_else: HashSet<ValueId>,
    keep_then: HashSet<ValueId>,
    dissolve: HashSet<ValueId>,
    /// The dispatch switch's selector binding.
    selector: ValueId,
    /// Per arm with a payload: the variant, its position, the component's
    /// declared type, and the element loads it reads.
    payloads: Vec<ArmPayload>,
    /// The default arm becomes an explicit arm for this position; with
    /// `true`, the rest of the sequence after the switch moves into it.
    explicit_default: Option<(u32, bool)>,
}

/// What a decode's analysis proved before deciding whether it can be taken
/// away: the value is the enum, `decoded` is its variant's position, the
/// switch on it takes the arm of that position, and an arm's payload
/// element is that variant's payload's `Val`.
#[derive(Debug, Clone)]
struct Proof {
    value: ValueId,
    union: TypeId,
    /// The variant's position, decoded from the lookup.
    decoded: ValueId,
    /// The decode's switch's arms that stand for one variant: its
    /// position, the arm, and the blocks only that arm reaches.
    arms: Vec<(u32, ArmKey, HashSet<BlockId>)>,
    /// Every block of the decode's switch.
    switch_blocks: HashSet<BlockId>,
    /// The blocks after the switch in the sequence holding it, which run
    /// only once it is done.
    after: HashSet<BlockId>,
    /// Per variant read: its position, its name, its payload's type, and
    /// the loads of the payload's `Val`.
    payloads: Vec<(u32, String, KnownType, Vec<ValueId>)>,
}

/// The default arm's continuation: the default is `break 'inner`, and the
/// items after scope `'inner` in its sequence are reached only through it.
/// They end in a `break 'outer` when they fall off the end of the sequence,
/// which is `'outer`'s body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Hoist {
    inner: BlockId,
    outer: Option<BlockId>,
}

/// An explicit arm by its index among the switch's arms, or the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ArmKey {
    Arm(usize),
    Default,
}

#[derive(Debug)]
struct ArmPayload {
    arm: ArmKey,
    variant: String,
    ty: KnownType,
    loads: Vec<ValueId>,
}

/// Where the iterator stands on a path: how many `next` calls ran since its
/// state was last set, or no one count (never set, or two paths that
/// disagree).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pos {
    Unset,
    At(u32),
    Mixed,
}

/// The forward walk counting `next` calls from the state's last setting, on
/// every path, round loops included: what each call saw on every visit,
/// met.
struct Counting<'a> {
    resets: &'a HashSet<ValueId>,
    calls: &'a HashSet<ValueId>,
    seen: HashMap<ValueId, Pos>,
}

impl reach::Flow for Counting<'_> {
    type State = Pos;

    fn join(into: &mut Pos, other: &Pos) {
        if into != other {
            *into = Pos::Mixed;
        }
    }

    fn step(&mut self, id: ValueId, state: &mut Pos) {
        if self.resets.contains(&id) {
            *state = Pos::At(0);
        } else if self.calls.contains(&id) {
            let at = self.seen.entry(id).or_insert(*state);
            if *at != *state {
                *at = Pos::Mixed;
            }
            *state = match *state {
                Pos::At(k) => Pos::At(k + 1),
                _ => Pos::Mixed,
            };
        }
    }
}

/// How many calls ran since the state was set, for each call, on every
/// path that reaches it — `None` when the walk could not see the whole
/// function.
fn call_positions(func: &HighFunction, resets: &HashSet<ValueId>, calls: &HashSet<ValueId>) -> Option<HashMap<ValueId, Pos>> {
    let mut flow = Counting { resets, calls, seen: HashMap::new() };
    let walked = reach::walk(func, &mut flow, Pos::Unset);
    walked.complete.then_some(flow.seen)
}

/// The scope labelled `out` in `region`, with the sequence holding it, its
/// place there, and the scope whose body that sequence is (if one is).
fn scope_in(region: &Region, out: BlockId, parent: Option<BlockId>) -> Option<(&[Region], usize, Option<BlockId>)> {
    match region {
        Region::Sequence(items) => {
            for (i, item) in items.iter().enumerate() {
                if matches!(item, Region::Scope { out: o, .. } if *o == out) {
                    return Some((items.as_slice(), i, parent));
                }
                // Only the sequence itself is the scope's body.
                if let Some(found) = scope_in(item, out, None) {
                    return Some(found);
                }
            }
            None
        }
        Region::Scope { out: o, body } => scope_in(body, out, Some(*o)),
        Region::Loop { body, .. } => scope_in(body, out, None),
        Region::If { then_region, else_region, .. } => {
            scope_in(then_region, out, None).or_else(|| else_region.as_deref().and_then(|e| scope_in(e, out, None)))
        }
        Region::Switch { arms, default, .. } => {
            arms.iter().find_map(|a| scope_in(&a.body, out, None)).or_else(|| scope_in(default, out, None))
        }
        _ => None,
    }
}

/// The `break`s to `out` in `region`.
fn breaks_to(region: &Region, out: BlockId) -> usize {
    let mut n = 0;
    region.for_each_node(|node| n += usize::from(matches!(node, Region::Break { target, .. } if *target == out)));
    n
}

/// The scope a default arm leaves by a bare `break`: the arm is that break
/// and nothing else that does work.
fn default_break(func: &HighFunction, default: &Region) -> Option<BlockId> {
    let empty = |r: &Region| match r {
        Region::Basic(b) => func.blocks.get(*b).is_some_and(|blk| blk.bindings.is_empty()),
        Region::Sequence(items) => items.is_empty(),
        _ => false,
    };
    let last = match default {
        Region::Sequence(items) => {
            let (last, before) = items.split_last()?;
            if !before.iter().all(empty) {
                return None;
            }
            last
        }
        other => other,
    };
    match last {
        Region::Break { target, transfer } if transfer.is_empty() => Some(*target),
        _ => None,
    }
}

/// The default arm's continuation, when its arm is a bare `break 'inner`
/// out of a scope enclosing the switch (see [`Hoist`]): the scope's body
/// never falls out of it and breaks to it only from that arm, so the code
/// after it runs exactly when the default is taken. It must not fall out
/// of its own sequence either, unless that sequence is a scope's body,
/// which falling out of leaves. Its blocks, with the hoist.
fn continuation(func: &HighFunction, switch: &Region, default: &Region) -> Option<(Hoist, HashSet<BlockId>)> {
    let inner = default_break(func, default)?;
    let (items, at, parent) = scope_in(&func.region, inner, None)?;
    let Region::Scope { body, .. } = &items[at] else { return None };
    if falls_through(body) || breaks_to(body, inner) != 1 || !blocks_in(body).is_superset(&blocks_in(switch)) {
        return None;
    }
    let rest = &items[at + 1..];
    let falls = rest.iter().all(falls_through);
    let outer = if falls { Some(parent?) } else { None };
    Some((Hoist { inner, outer }, rest.iter().flat_map(blocks_in).collect()))
}

/// A switch found, with the sequence holding it and its position there.
type Found<'r> = (&'r Region, Option<(&'r [Region], usize)>);

/// The switch whose selector is `decoded` (directly or its low 32 bits),
/// with the region sequence holding it and its position there (`None`
/// when it is not an item of a sequence).
fn find_switch<'r>(func: &HighFunction, region: &'r Region, decoded: ValueId, out: &mut Vec<Found<'r>>) {
    let selects = |index: ValueId| {
        let mut sel = resolve_use(func, index);
        if let Some(Expr::Unary { op: UnaryOp::Wrap32, value }) = func.bindings.get(sel).map(|b| &b.expr) {
            sel = resolve_use(func, *value);
        }
        sel == decoded
    };
    match region {
        Region::Sequence(items) => {
            for (i, item) in items.iter().enumerate() {
                if let Region::Switch { index, .. } = item
                    && selects(*index)
                {
                    out.push((item, Some((items.as_slice(), i))));
                    if let Region::Switch { arms, default, .. } = item {
                        arms.iter().for_each(|a| find_switch(func, &a.body, decoded, out));
                        find_switch(func, default, decoded, out);
                    }
                } else {
                    find_switch(func, item, decoded, out);
                }
            }
        }
        Region::Switch { index, arms, default, .. } => {
            if selects(*index) {
                out.push((region, None));
            }
            arms.iter().for_each(|a| find_switch(func, &a.body, decoded, out));
            find_switch(func, default, decoded, out);
        }
        Region::Scope { body, .. } | Region::Loop { body, .. } => find_switch(func, body, decoded, out),
        Region::If { then_region, else_region, .. } => {
            find_switch(func, then_region, decoded, out);
            if let Some(e) = else_region {
                find_switch(func, e, decoded, out);
            }
        }
        _ => {}
    }
}

/// Where `v` points, as `(base, offset)` through a `U32Val` wrapping.
fn addr(func: &HighFunction, v: ValueId) -> (ValueId, u32) {
    canon_addr(func, raw_address(func, v))
}

/// One setting of an iterator's state: the stores of a vector, of the
/// index `0` and of the vector's length into the same 16 bytes, all in one
/// block with nothing on the state between them.
struct InitGroup {
    /// The vector, the index, the length.
    stores: [ValueId; 3],
    /// The vector the state iterates.
    value: ValueId,
    /// The first of the three in the block: where the state becomes this
    /// vector's.
    first: ValueId,
}

/// The decodes sharing one iterator state, and which of them each `next`
/// call and state load follows.
struct Split {
    groups: Vec<InitGroup>,
    /// Per call and state load, the vectors whose setting of the state
    /// last ran on some path to it (`None`: a path on which none ran).
    seen: HashMap<ValueId, BTreeSet<Option<ValueId>>>,
}

/// The forward walk behind [`owners`]: the settings of the state that
/// last ran on some path, and what each call or state load saw.
struct Owner<'a> {
    starts: HashMap<ValueId, ValueId>,
    touches: &'a dyn Fn(ValueId) -> bool,
    seen: HashMap<ValueId, BTreeSet<Option<ValueId>>>,
}

impl reach::Flow for Owner<'_> {
    type State = BTreeSet<Option<ValueId>>;

    fn join(into: &mut Self::State, other: &Self::State) {
        into.extend(other.iter().copied());
    }

    fn step(&mut self, id: ValueId, state: &mut Self::State) {
        if let Some(y) = self.starts.get(&id) {
            *state = BTreeSet::from([Some(*y)]);
        } else if (self.touches)(id) {
            self.seen.entry(id).or_default().extend(state.iter().copied());
        }
    }
}

/// The ordered split of one iterator state several decodes reuse: every
/// setting of it ([`InitGroup`]), and, by a forward walk of the region
/// tree, which setting each `next` call and load of the index or length
/// follows on every path. A call that follows exactly one setting on every
/// path reads that vector's state: no other setting lies on any path from
/// it to the call, and the stores of one setting run together.
fn owners(
    func: &HighFunction,
    order: &[(BlockId, ValueId)],
    nexts: &HashSet<FuncId>,
    base: ValueId,
    at: u32,
) -> Result<Split, String> {
    let position: HashMap<ValueId, usize> = func
        .blocks
        .iter()
        .flat_map(|(_, blk)| blk.bindings.iter().enumerate().map(|(i, v)| (*v, i)))
        .collect();
    let store_at = |v: ValueId| match func.bindings.get(v).map(|b| &b.expr) {
        Some(Expr::Store { addr: a, value: x, offset, width }) => {
            let (b, k) = canon_addr(func, *a);
            (b == base).then_some(())?;
            Some((k.checked_add(*offset)?, *width, resolve_use(func, *x)))
        }
        _ => None,
    };
    let touches = |v: ValueId| match func.bindings.get(v).map(|b| &b.expr) {
        Some(Expr::Call { target, args }) => {
            nexts.contains(target) && args.len() == 2 && addr(func, args[1]) == (base, at)
        }
        Some(Expr::Load { addr: a, offset, width: MemWidth::W4, .. }) => {
            let (lb, k) = canon_addr(func, *a);
            lb == base && matches!(k.checked_add(*offset), Some(o) if o == at + 8 || o == at + 12)
        }
        _ => false,
    };
    let mut groups = Vec::new();
    for (b, v) in order {
        let Some((o, MemWidth::W8, y)) = store_at(*v) else { continue };
        if o != at {
            continue;
        }
        let in_block: Vec<ValueId> = func.blocks.get(*b).map(|blk| blk.bindings.clone()).unwrap_or_default();
        let idx: Vec<ValueId> = in_block
            .iter()
            .copied()
            .filter(|s| matches!(store_at(*s), Some((k, MemWidth::W4, x)) if k == at + 8 && trace_int(func, x) == Some(0)))
            .collect();
        let lens: Vec<ValueId> = in_block
            .iter()
            .copied()
            .filter(|s| {
                matches!(store_at(*s), Some((k, MemWidth::W4, x)) if k == at + 12
                    && matches!(expr_of(func, x), Some(Expr::Semantic(SemanticOp::Known(KnownOp::VecOp { kind: VecOpKind::Len, args })))
                        if args.len() == 1 && resolve_use(func, args[0]) == y))
            })
            .collect();
        let ([i], [l]) = (idx.as_slice(), lens.as_slice()) else {
            return Err(format!("{v:?} sets the state without one index and one length store beside it"));
        };
        let stores = [*v, *i, *l];
        let ps: Vec<usize> = stores.iter().filter_map(|s| position.get(s).copied()).collect();
        let (Some(lo), Some(hi)) = (ps.iter().min().copied(), ps.iter().max().copied()) else {
            return Err("a state store is not scheduled".into());
        };
        if ps.len() != 3 || in_block[lo..=hi].iter().any(|x| touches(*x)) {
            return Err(format!("the state is read between the stores that set it at {v:?}"));
        }
        groups.push(InitGroup { stores, value: y, first: in_block[lo] });
    }
    let mut flow = Owner {
        starts: groups.iter().map(|g| (g.first, g.value)).collect(),
        touches: &touches,
        seen: HashMap::new(),
    };
    let walked = reach::walk(func, &mut flow, BTreeSet::from([None]));
    if !walked.complete {
        return Err("the walk of the state's owners did not settle".into());
    }
    Ok(Split { groups, seen: flow.seen })
}

/// Whether `v` is computed from `base` (arithmetic, conversions, merges).
fn derived_from(func: &HighFunction, v: ValueId, base: ValueId) -> bool {
    let mut seen = HashSet::new();
    let mut stack = vec![v];
    while let Some(x) = stack.pop() {
        let x = resolve_use(func, x);
        if x == base {
            return true;
        }
        if !seen.insert(x) {
            continue;
        }
        if seen.len() > 64 {
            return true;
        }
        match func.bindings.get(x).map(|b| &b.expr) {
            Some(Expr::Binary { lhs, rhs, .. }) => stack.extend([*lhs, *rhs]),
            Some(Expr::Unary { value, .. }) => stack.push(*value),
            Some(Expr::Select { if_true, if_false, .. }) => stack.extend([*if_true, *if_false]),
            Some(Expr::Phi { incoming }) => stack.extend(incoming.iter().map(|(_, v)| *v)),
            Some(Expr::Unknown { args, .. }) => stack.extend(args.iter().copied()),
            Some(Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { value, .. }))) => stack.push(*value),
            _ => {}
        }
    }
    false
}

/// What one operation does to the 16 state bytes, as masks of those bytes
/// (bit `i` is byte `at + i`): the bytes it may read, may write, and
/// writes on every path through it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct StateTouch {
    reads: u16,
    writes: u16,
    must: u16,
}

/// The bits of the 16 state bytes at `at` that `[s, s + w)` covers.
fn state_mask(at: u32, s: u64, w: u64) -> u16 {
    let (lo, hi) = (u64::from(at), u64::from(at) + 16);
    let (a, b) = (s.max(lo), (s + w).min(hi));
    (a..b).fold(0u16, |m, byte| m | (1 << (byte - lo)))
}

/// What everything but `allowed` does to the 16 state bytes at
/// `base + at`: a load, a store, or an operation handed a pointer into
/// the frame, with exactly the bytes it reaches — or the first operation
/// whose reach cannot be told (a pointer stored or handed on in a way no
/// summary describes).
fn foreign_touches(
    func: &HighFunction,
    base: ValueId,
    at: u32,
    allowed: &HashSet<ValueId>,
    access: &HashMap<FuncId, Vec<Option<ParamAccess>>>,
) -> Result<HashMap<ValueId, StateTouch>, ValueId> {
    let mask = |s: u64, w: u64| state_mask(at, s, w);
    let mut out: HashMap<ValueId, StateTouch> = HashMap::new();
    for (_, id) in scheduled(func) {
        if allowed.contains(&id) {
            continue;
        }
        let Some(expr) = func.bindings.get(id).map(|b| &b.expr) else { continue };
        let effects = crate::effects::expr_effects(expr);
        if !effects.reads_memory && !effects.writes_memory {
            continue;
        }
        let mut t = StateTouch::default();
        match expr {
            Expr::Load { addr: a, offset, width, .. } => {
                let (b, k) = canon_addr(func, *a);
                if b == base {
                    t.reads = mask(u64::from(k) + u64::from(*offset), u64::from(width.bytes()));
                } else if derived_from(func, *a, base) {
                    return Err(id);
                }
            }
            Expr::Store { addr: a, value, offset, width } => {
                if derived_from(func, *value, base) {
                    return Err(id);
                }
                let (b, k) = canon_addr(func, *a);
                if b == base {
                    let m = mask(u64::from(k) + u64::from(*offset), u64::from(width.bytes()));
                    t.writes = m;
                    t.must = m;
                } else if derived_from(func, *a, base) {
                    return Err(id);
                }
            }
            Expr::Call { target, args } => {
                for (k, a) in args.iter().enumerate() {
                    if !derived_from(func, *a, base) {
                        continue;
                    }
                    let (b, off) = addr(func, *a);
                    if b != base {
                        return Err(id);
                    }
                    let off = u64::from(off);
                    // Another iterator's `next`, or any summarised helper:
                    // exactly the bytes it touches through this parameter.
                    if let Some(acc) = access.get(target).and_then(|s| s.get(k)).and_then(Option::as_ref) {
                        for (o, w) in &acc.reads {
                            t.reads |= mask(off + u64::from(*o), u64::from(*w));
                        }
                        for (o, w) in &acc.writes {
                            t.writes |= mask(off + u64::from(*o), u64::from(*w));
                        }
                        for (o, w) in &acc.must_writes {
                            t.must |= mask(off + u64::from(*o), u64::from(*w));
                        }
                        continue;
                    }
                    return Err(id);
                }
            }
            // The host reading `len` `Val`s from linear memory to build a
            // collection: exactly those bytes.
            Expr::Semantic(SemanticOp::Known(op @ (KnownOp::VecNew { elements: None, .. } | KnownOp::MapNew { entries: None, .. }))) => {
                let (positions, len) = match op {
                    KnownOp::VecNew { vals_pos, len, .. } => (vec![*vals_pos], *len),
                    KnownOp::MapNew { keys_pos, vals_pos, len, .. } => (vec![*keys_pos, *vals_pos], *len),
                    _ => unreachable!(),
                };
                let mut unknown = false;
                expr.for_each_value_use(|u| unknown |= !positions.contains(&u) && derived_from(func, u, base));
                if unknown {
                    return Err(id);
                }
                for pos in positions {
                    let p = raw_address(func, pos);
                    if !derived_from(func, p, base) {
                        continue;
                    }
                    let (b, off) = canon_addr(func, p);
                    let n = trace_u32val(func, len).ok_or(id)?;
                    if b != base {
                        return Err(id);
                    }
                    t.reads |= mask(u64::from(off), u64::from(n) * 8);
                }
            }
            other => {
                let mut unknown = false;
                other.for_each_value_use(|u| {
                    if unknown || !derived_from(func, u, base) {
                        return;
                    }
                    let (b, off) = addr(func, u);
                    unknown = b != base || u64::from(off) < u64::from(at) + 16;
                });
                if unknown {
                    return Err(id);
                }
            }
        }
        if t != StateTouch::default() {
            out.insert(id, t);
        }
    }
    Ok(out)
}

/// The forward walk behind [`ordered`]: on each path, the state bytes whose
/// content may be the decode's, and whether anything else may have written
/// the state since.
struct Order<'a> {
    decode: &'a HashMap<ValueId, u16>,
    foreign: &'a HashMap<ValueId, StateTouch>,
    /// A decode access some foreign write may precede.
    late: Option<ValueId>,
    /// A foreign read that may see bytes the decode wrote.
    sees: Option<ValueId>,
}

impl reach::Flow for Order<'_> {
    type State = (u16, bool);

    fn join(into: &mut Self::State, other: &Self::State) {
        into.0 |= other.0;
        into.1 |= other.1;
    }

    fn step(&mut self, id: ValueId, state: &mut Self::State) {
        if let Some(writes) = self.decode.get(&id) {
            if state.1 {
                self.late.get_or_insert(id);
            }
            state.0 |= *writes;
        } else if let Some(t) = self.foreign.get(&id) {
            if t.reads & state.0 != 0 {
                self.sees.get_or_insert(id);
            }
            state.0 &= !t.must;
            state.1 |= t.writes != 0;
        }
    }
}

/// Whether the foreign touches leave the decode alone, by a forward walk of
/// the region tree: `Err` when a decode access (a setting store, a `next`
/// call, a load of the index or length) may run after something else wrote
/// the state — its bytes are then not the decode's own, and nothing about
/// it is proven. `Ok(Some(..))` when only a foreign read may see bytes the
/// decode wrote — the decode is what it is, but taking it away would change
/// what that read sees. `decode` holds each decode access with the state
/// bytes it may write.
fn ordered(
    func: &HighFunction,
    decode: &HashMap<ValueId, u16>,
    foreign: &HashMap<ValueId, StateTouch>,
) -> Result<Option<String>, String> {
    if foreign.is_empty() {
        return Ok(None);
    }
    let mut flow = Order { decode, foreign, late: None, sees: None };
    let walked = reach::walk(func, &mut flow, (0, false));
    if !walked.complete {
        return Err("the walk over the state's other users did not settle".into());
    }
    if let Some(id) = flow.late {
        return Err(format!("{id:?} may run after something else wrote the iterator state"));
    }
    Ok(flow.sees.map(|id| format!("{id:?} may read what the decode left in the iterator state")))
}

/// The enum's variant names, if `lookup` is the derived decode's symbol
/// lookup on `sym` and its table is exactly them in declared order.
fn lookup_on(func: &HighFunction, memory: &sordec_ir::MemoryImage, lookup: ValueId, union: &UnionDef) -> Option<ValueId> {
    let names: Vec<String> = union.cases.iter().map(|c| c.name.clone()).collect();
    match func.bindings.get(lookup).map(|b| &b.expr)? {
        Expr::Semantic(SemanticOp::Known(KnownOp::SymbolDispatch { sym, table, .. })) => {
            (table.cases == names).then_some(resolve_use(func, *sym))
        }
        Expr::Semantic(SemanticOp::Known(KnownOp::BufOp { kind: BufOpKind::SymbolIndexInLinearMemory, args }))
            if args.len() == 3 =>
        {
            let pos = trace_u32val(func, args[1])?;
            let len = trace_u32val(func, args[2])?;
            (read_keys(memory, pos, len)? == names).then_some(resolve_use(func, args[0]))
        }
        _ => None,
    }
}

/// Whether `expr` computes a value and nothing else.
fn pure(expr: &Expr) -> bool {
    if matches!(expr, Expr::Phi { .. } | Expr::Literal(_)) {
        return false;
    }
    let e = crate::effects::expr_effects(expr);
    !(e.may_trap || e.reads_memory || e.writes_memory || e.reads_globals || e.writes_globals || e.reads_host || e.writes_host)
}

/// A payload component's type when its `Val` is the value itself.
fn val_is_value(ty: &KnownType) -> bool {
    matches!(
        ty,
        KnownType::UserDefined(_)
            | KnownType::Address
            | KnownType::Bytes
            | KnownType::String
            | KnownType::Vec(_)
            | KnownType::Map(..)
            | KnownType::BytesN(_)
            | KnownType::Symbol
    )
}

/// Whether `decode(x)` of the component's `Val` is the value zero-extended.
fn decodes_as_u32(ty: &KnownType, types: &TypeRegistry) -> bool {
    match ty {
        KnownType::U32 => true,
        KnownType::UserDefined(id) => types.enums.iter().any(|e| e.id == *id),
        _ => false,
    }
}

/// A region that does nothing once the site's checks are gone: blocks
/// holding only removed bindings and constants, and conditions the site
/// removes.
fn empty_after(func: &HighFunction, r: &Region, removed: &HashSet<ValueId>, empty: &HashSet<BlockId>) -> bool {
    match r {
        Region::Basic(b) => func.blocks.get(*b).is_some_and(|blk| {
            blk.bindings
                .iter()
                .all(|v| removed.contains(v) || matches!(func.bindings.get(*v).map(|b| &b.expr), Some(Expr::Literal(_))))
        }),
        Region::Sequence(items) => items.iter().all(|i| empty_after(func, i, removed, empty)),
        Region::Transfer { transfer, .. } => transfer.is_empty(),
        Region::If { cond, then_region, else_region } if removed.contains(cond) => {
            let then_trap = super::guard::is_trap(then_region, empty);
            match else_region {
                None => then_trap || empty_after(func, then_region, removed, empty),
                Some(e) => {
                    let else_trap = super::guard::is_trap(e, empty);
                    (then_trap || empty_after(func, then_region, removed, empty))
                        && (else_trap || empty_after(func, e, removed, empty))
                        && !(then_trap && else_trap)
                }
            }
        }
        _ => false,
    }
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn plan(
    func: &HighFunction,
    memory: &sordec_ir::MemoryImage,
    types: &TypeRegistry,
    context: Option<TypeId>,
    nexts: &HashSet<FuncId>,
    access: &HashMap<FuncId, Vec<Option<ParamAccess>>>,
    gated: &HashMap<FuncId, Vec<Option<Gated>>>,
    tried: &mut HashSet<ValueId>,
    kept: &mut Vec<Proof>,
) -> (Option<Site>, i64) {
    let order = scheduled(func);
    let mut refused = 0;
    for (_, len) in &order {
        let Some(Expr::Semantic(SemanticOp::Known(KnownOp::VecOp { kind: VecOpKind::Len, args }))) =
            func.bindings.get(*len).map(|b| &b.expr)
        else {
            continue;
        };
        let [arg] = args.as_slice() else { continue };
        let value = resolve_use(func, *arg);
        let Some((uid, element)) = proven_union(func, value, context) else { continue };
        let Some(union) = types.unions.iter().find(|u| u.id == uid) else { continue };
        if !tried.insert(*len) {
            continue;
        }
        let mut proof = None;
        match site(func, memory, types, nexts, access, gated, &order, *len, value, union, &mut proof) {
            Ok(mut s) => {
                s.element = element;
                return (Some(s), refused);
            }
            Err(why) => {
                refused += 1;
                trace(func, &format!("decode of {value:?} refused: {why}"));
                if let Some(p) = proof {
                    kept.push(p);
                }
            }
        }
    }
    (None, refused)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines, clippy::cognitive_complexity)]
fn site(
    func: &HighFunction,
    memory: &sordec_ir::MemoryImage,
    types: &TypeRegistry,
    nexts: &HashSet<FuncId>,
    access: &HashMap<FuncId, Vec<Option<ParamAccess>>>,
    gated: &HashMap<FuncId, Vec<Option<Gated>>>,
    order: &[(BlockId, ValueId)],
    len: ValueId,
    value: ValueId,
    union: &UnionDef,
    proven: &mut Option<Proof>,
) -> Result<Site, String> {
    if union.cases.iter().any(|c| c.fields.len() > 1) {
        return Err("a variant with several payload components".into());
    }
    let block_of: HashMap<ValueId, BlockId> = order.iter().map(|(b, v)| (*v, *b)).collect();
    let store = |v: ValueId| match func.bindings.get(v).map(|b| &b.expr) {
        Some(Expr::Store { addr: a, value: x, offset, width }) => {
            let (b, k) = canon_addr(func, *a);
            Some((b, k.checked_add(*offset)?, *width, resolve_use(func, *x)))
        }
        _ => None,
    };

    // The state: the value, 0 and its length, at +0, +8, +12.
    let vec_stores: Vec<(ValueId, ValueId, u32)> = order
        .iter()
        .filter_map(|(_, v)| match store(*v)? {
            (b, at, MemWidth::W8, x) if x == value => Some((*v, b, at)),
            _ => None,
        })
        .collect();
    let [(s_vec, base, at)] = vec_stores.as_slice() else {
        return Err(format!("{} stores of the value into memory", vec_stores.len()));
    };
    let (base, at) = (*base, *at);
    let find = |off: u32, ok: &dyn Fn(ValueId) -> bool| -> Option<ValueId> {
        let hits: Vec<ValueId> = order
            .iter()
            .filter(|(_, v)| matches!(store(*v), Some((b, k, MemWidth::W4, x)) if b == base && k == off && ok(x)))
            .map(|(_, v)| *v)
            .collect();
        match hits.as_slice() {
            [one] => Some(*one),
            _ => None,
        }
    };
    // One decode's state, or several decodes taking the same 16 bytes in
    // turn: then each `next` call and state load is the decode's whose
    // setting of the state it follows on every path (see `owners`).
    let zero_stores = order
        .iter()
        .filter(|(_, v)| {
            matches!(store(*v), Some((b, k, MemWidth::W4, x)) if b == base && k == at + 8 && trace_int(func, x) == Some(0))
        })
        .count();
    let split = if zero_stores > 1 { Some(owners(func, order, nexts, base, at)?) } else { None };
    let (s_idx, s_len) = match &split {
        None => (
            find(at + 8, &|x| trace_int(func, x) == Some(0)).ok_or("no single zero index store")?,
            find(at + 12, &|x| x == len).ok_or("no single length store")?,
        ),
        Some(split) => {
            let g = split.groups.iter().find(|g| g.stores[0] == *s_vec).ok_or("the state is not set in one block")?;
            if g.value != value || !matches!(store(g.stores[2]), Some((_, _, _, x)) if x == len) {
                return Err("the length stored is not the value's".into());
            }
            (g.stores[1], g.stores[2])
        }
    };
    // Whether a call or load on the state is this decode's: always, with
    // one decode; with several, where this decode set it on every path.
    let mine = |v: ValueId| -> Result<bool, String> {
        let Some(split) = &split else { return Ok(true) };
        let owner = split.seen.get(&v).ok_or_else(|| format!("{v:?} is not reached by the walk"))?;
        if owner.len() == 1 && owner.contains(&Some(value)) {
            Ok(true)
        } else if owner.contains(&Some(value)) {
            Err(format!("{v:?} may follow another decode's setting of the state"))
        } else {
            Ok(false)
        }
    };
    // The state is set at once: its three stores in one block.
    let state_block = block_of.get(s_vec).ok_or("the state is not scheduled")?;
    if [s_idx, s_len].iter().any(|s| block_of.get(s) != Some(state_block)) {
        return Err("the state's stores are in different blocks".into());
    }

    // The `next` calls on it, and the loads of its index and length.
    let mut calls: Vec<(ValueId, u32)> = Vec::new();
    let mut state_loads: Vec<ValueId> = Vec::new();
    // Another decode's: its own setting of the state, calls and loads.
    let mut others: HashSet<ValueId> = HashSet::new();
    if let Some(split) = &split {
        for g in split.groups.iter().filter(|g| g.stores[0] != *s_vec) {
            others.extend(g.stores);
        }
    }
    for (_, v) in order {
        match func.bindings.get(*v).map(|b| &b.expr) {
            Some(Expr::Call { target, args }) if nexts.contains(target) && args.len() == 2 => {
                if addr(func, args[1]) != (base, at) {
                    continue;
                }
                if !mine(*v)? {
                    others.insert(*v);
                    continue;
                }
                let (ob, r) = addr(func, args[0]);
                if ob != base || (r < at + 16 && at < r + 16) {
                    return Err("a next call's out-pointer is not a frame slot of its own".into());
                }
                calls.push((*v, r));
            }
            Some(Expr::Load { addr: a, offset, width: MemWidth::W4, .. }) => {
                let (lb, k) = canon_addr(func, *a);
                if lb == base && matches!(k.checked_add(*offset), Some(o) if o == at + 8 || o == at + 12) {
                    if mine(*v)? {
                        state_loads.push(*v);
                    } else {
                        others.insert(*v);
                    }
                }
            }
            _ => {}
        }
    }
    if calls.is_empty() {
        return Err("no next call on the state".into());
    }
    // No call between the state's stores: once the first is made, the next
    // call sees all three.
    let in_block: Vec<ValueId> = func.blocks.get(*state_block).map(|blk| blk.bindings.clone()).unwrap_or_default();
    let place = |v: ValueId| in_block.iter().position(|x| *x == v);
    let placed: Vec<usize> = [*s_vec, s_idx, s_len].iter().filter_map(|s| place(*s)).collect();
    let (lo, hi) = (placed.iter().min().copied().unwrap_or(0), placed.iter().max().copied().unwrap_or(0));
    if calls.iter().any(|(c, _)| place(*c).is_some_and(|p| lo < p && p < hi)) {
        return Err("a next call between the state's stores".into());
    }
    // What each call reads: the count of calls since the state was set, the
    // same on every path to it — loops included, where each iteration sets
    // the state afresh before its calls.
    let resets: HashSet<ValueId> = [*s_vec, s_idx, s_len].into_iter().collect();
    let call_ids: HashSet<ValueId> = calls.iter().map(|(c, _)| *c).collect();
    let positions = call_positions(func, &resets, &call_ids).ok_or("the region could not be walked")?;
    let position = |c: ValueId| match positions.get(&c) {
        Some(Pos::At(k)) => Some(*k),
        _ => None,
    };
    let mut allowed: HashSet<ValueId> = [*s_vec, s_idx, s_len].into_iter().collect();
    allowed.extend(calls.iter().map(|(c, _)| *c));
    allowed.extend(state_loads.iter().copied());
    allowed.extend(others.iter().copied());
    // Everything else that touches the state's bytes must run after the
    // decode is done with them; a read of what the decode left there keeps
    // the decode, which taking it away would change (`blocked`).
    let foreign = foreign_touches(func, base, at, &allowed, access)
        .map_err(|other| format!("{other:?} may touch the iterator state"))?;
    let mut decode_writes: HashMap<ValueId, u16> = HashMap::from([(*s_vec, 0x00ff), (s_idx, 0x0f00), (s_len, 0xf000)]);
    decode_writes.extend(calls.iter().map(|(c, _)| (*c, 0x0f00)));
    decode_writes.extend(state_loads.iter().map(|l| (*l, 0)));
    let mut blocked: Option<String> = ordered(func, &decode_writes, &foreign)?;

    // Each call's slot: its tag and element reads.
    let dummy = StructDef { id: TypeId::new(0), name: String::new(), fields: Vec::new() };
    let cands: Vec<Candidate<'_>> = calls
        .iter()
        .map(|(c, r)| Candidate {
            base,
            start: *r,
            producer: *c,
            map: *c,
            def: &dummy,
            slots: vec![
                Slot { rel: 0, width: 8, role: Role::Disc },
                Slot { rel: 8, width: 8, role: Role::Disc },
            ],
            vals: false,
            payload: false,
        })
        .collect();
    let certain: Vec<CertainWrite> = cands.iter().map(|c| (c.producer, c.base, c.certain_writes())).collect();
    let mut tags: Vec<ValueId> = Vec::new();
    let mut elements: HashMap<ValueId, Vec<ValueId>> = HashMap::new();
    for cand in &cands {
        let reads = reach::check_gated(func, cand, &certain, access, gated)?;
        if !reads.tags.is_empty() {
            return Err("a tag-byte read of a next slot".into());
        }
        for (load, slot) in reads.fields {
            if slot == 0 {
                tags.push(load);
            } else {
                let whole = matches!(func.bindings.get(load).map(|b| &b.expr),
                    Some(Expr::Load { width: MemWidth::W8, .. }));
                if !whole {
                    return Err(format!("{load:?} reads part of an element"));
                }
                elements.entry(cand.producer).or_default().push(load);
            }
        }
    }

    // The lookup on element 0, its position, the switch on it.
    let element_of: HashMap<ValueId, ValueId> =
        elements.iter().flat_map(|(c, ls)| ls.iter().map(move |l| (*l, *c))).collect();
    let lookups: Vec<(ValueId, ValueId)> = order
        .iter()
        .filter_map(|(_, v)| {
            let sym = lookup_on(func, memory, *v, union)?;
            let call = element_of.get(&sym)?;
            Some((*v, *call))
        })
        .collect();
    let [(lookup, first)] = lookups.as_slice() else {
        return Err(format!("{} lookups of the variant name on an element", lookups.len()));
    };
    let (lookup, first) = (*lookup, *first);
    let decodeds: Vec<ValueId> = order
        .iter()
        .filter(|(_, v)| {
            matches!(expr_of(func, *v), Some(Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { value })))
                if resolve_use(func, *value) == lookup)
        })
        .map(|(_, v)| *v)
        .collect();
    let [decoded] = decodeds.as_slice() else { return Err("the position is not decoded once".into()) };
    let decoded = *decoded;
    let mut found = Vec::new();
    find_switch(func, &func.region, decoded, &mut found);
    // Several switches on the position: the decode's is the one whose arms
    // hold every payload call; the others test the variant again later
    // (see `rematch`), which keeps the decode.
    if found.len() > 1 {
        let payload_blocks: HashSet<BlockId> =
            calls.iter().filter(|(c, _)| *c != first).filter_map(|(c, _)| block_of.get(c).copied()).collect();
        found.retain(|(sw, _)| !payload_blocks.is_empty() && blocks_in(sw).is_superset(&payload_blocks));
        // The decode's switch holds the payload calls; one nested in its arm
        // would hold them too, so the outermost is the first found.
        found.truncate(1);
        blocked.get_or_insert_with(|| "the position is switched on again".into());
    }
    let [(switch, holder)] = found.as_slice() else {
        return Err(format!("{} switches on the position", found.len()));
    };
    let Region::Switch { index: selector, arms, default, dispatch } = switch else { unreachable!() };
    let selector = *selector;
    // The dispatcher's link to the lookup it names the arms by.
    let linked = dispatch.filter(|d| resolve_use(func, *d) == lookup);
    let n = union.cases.len() as u32;
    if arms.iter().flat_map(|a| &a.cases).any(|c| *c >= n) {
        return Err("a switch case that is no variant".into());
    }
    let named: HashSet<u32> = arms.iter().flat_map(|a| a.cases.iter().copied()).collect();
    let missing: Vec<u32> = (0..n).filter(|c| !named.contains(c)).collect();

    // The blocks only each arm reaches; the default's take the rest of
    // the sequence when no other arm falls out of the switch.
    let mut arm_blocks: Vec<(ArmKey, HashSet<BlockId>)> =
        arms.iter().enumerate().map(|(i, a)| (ArmKey::Arm(i), blocks_in(&a.body))).collect();
    let mut default_blocks = blocks_in(default);
    let rest_blocks: HashSet<BlockId> = match holder {
        Some((items, i)) if !arms.iter().any(|a| falls_through(&a.body)) => {
            items[i + 1..].iter().flat_map(blocks_in).collect()
        }
        _ => HashSet::new(),
    };
    default_blocks.extend(rest_blocks.iter().copied());
    // A default that leaves by `break` to a scope whose continuation only it
    // reaches: that continuation is the default's.
    let hoist = match rest_blocks.is_empty() {
        true => continuation(func, switch, default),
        false => None,
    };
    if let Some((_, blocks)) = &hoist {
        default_blocks.extend(blocks.iter().copied());
    }
    let hoist = hoist.map(|(h, _)| h);
    arm_blocks.push((ArmKey::Default, default_blocks));
    let first_block = *block_of.get(&first).ok_or("the first call is not scheduled")?;
    if arm_blocks.iter().any(|(_, bs)| bs.contains(&first_block)) || blocks_in(switch).contains(&first_block) {
        return Err("the first call is inside the switch".into());
    }
    if position(first) != Some(0) {
        return Err("the first call does not read element 0 on every path".into());
    }

    // Every other call: in one arm of a variant with a payload, one each.
    let mut by_arm: HashMap<ArmKey, ValueId> = HashMap::new();
    for (c, _) in &calls {
        if *c == first {
            continue;
        }
        let b = block_of.get(c).ok_or("a call is not scheduled")?;
        let Some((key, _)) = arm_blocks.iter().find(|(_, bs)| bs.contains(b)) else {
            return Err(format!("{c:?} is in no arm of the switch"));
        };
        if by_arm.insert(*key, *c).is_some() {
            return Err("two next calls in one arm".into());
        }
        if position(*c) != Some(1) {
            return Err(format!("{c:?} does not read element 1 on every path"));
        }
    }
    let case_of = |key: ArmKey| -> Option<u32> {
        match key {
            ArmKey::Arm(i) => match arms[i].cases.as_slice() {
                [c] => Some(*c),
                _ => None,
            },
            ArmKey::Default => match missing.as_slice() {
                [c] => Some(*c),
                _ => None,
            },
        }
    };
    let mut payloads: Vec<ArmPayload> = Vec::new();
    let mut kept: HashSet<ValueId> = HashSet::new();
    let mut decodes: Vec<(ValueId, ArmKey)> = Vec::new();
    // In arm order, so the payloads are numbered the same on every run.
    let mut in_order: Vec<(&ArmKey, &ValueId)> = by_arm.iter().collect();
    in_order.sort_by_key(|(k, _)| match k {
        ArmKey::Arm(i) => *i,
        ArmKey::Default => usize::MAX,
    });
    for (key, call) in in_order {
        let case = case_of(*key).ok_or("a next call in an arm of several variants")?;
        let variant = &union.cases[case as usize];
        let [field] = variant.fields.as_slice() else {
            return Err(format!("a next call in the arm of `{}`, which has no payload", variant.name));
        };
        let ty = known_of_type_ref(field).ok_or("a payload type with no known form")?;
        let loads = elements.get(call).cloned().unwrap_or_default();
        payloads.push(ArmPayload { arm: *key, variant: variant.name.clone(), ty, loads });
    }
    // A variant with a payload whose arm makes no call has not read it.
    for (key, _) in &arm_blocks {
        let Some(case) = case_of(*key) else { continue };
        if !union.cases[case as usize].fields.is_empty() && !by_arm.contains_key(key) {
            return Err(format!("the arm of `{}` reads no payload", union.cases[case as usize].name));
        }
    }
    // Every payload read sits in its arm.
    for p in &payloads {
        let bs = &arm_blocks.iter().find(|(k, _)| *k == p.arm).expect("an arm").1;
        for load in &p.loads {
            if !block_of.get(load).is_some_and(|b| bs.contains(b)) {
                return Err(format!("{load:?} reads a payload outside its arm"));
            }
        }
    }
    // The decode is proven here: the value, its variant's position, the
    // switch on it and each arm's payload element. What follows decides
    // only whether it can be taken away.
    *proven = Some(Proof {
        value,
        union: union.id,
        decoded,
        arms: arm_blocks
            .iter()
            .filter_map(|(key, blocks)| Some((case_of(*key)?, *key, blocks.clone())))
            .collect(),
        switch_blocks: blocks_in(switch),
        after: match holder {
            Some((items, i)) => items[i + 1..].iter().flat_map(blocks_in).collect(),
            None => HashSet::new(),
        },
        payloads: payloads
            .iter()
            .filter_map(|p| Some((case_of(p.arm)?, p.variant.clone(), p.ty.clone(), p.loads.clone())))
            .collect(),
    });
    if let Some(why) = blocked.take() {
        return Err(why);
    }

    // What goes: the length, the state, the calls, their tags, element 0,
    // the lookup and its position, the payload elements — and every pure
    // value computed only from them.
    let uses = HighUseIndex::build(func);
    // A binding counts as a reader when it runs: scheduled, or a merge.
    let live = |v: ValueId| {
        block_of.contains_key(&v) || matches!(func.bindings.get(v).map(|b| &b.expr), Some(Expr::Phi { .. }))
    };
    let mut removed: HashSet<ValueId> = HashSet::new();
    removed.insert(len);
    removed.extend([*s_vec, s_idx, s_len]);
    removed.extend(calls.iter().map(|(c, _)| *c));
    removed.extend(tags.iter().copied());
    removed.extend(state_loads.iter().copied());
    removed.extend(elements.values().flatten().copied());
    removed.insert(lookup);
    // The decode's first step, the value's conversion to the vector it is
    // carried as: a test of its tag against the vector's.
    for (_, v) in order {
        if let Some(Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck { value: x, tag, .. }))) =
            func.bindings.get(*v).map(|b| &b.expr)
            && *tag == crate::val_abi::TAG_VEC_OBJECT
            && resolve_use(func, *x) == value
        {
            removed.insert(*v);
        }
    }
    // A `Use` alias of the length (the decoded `u32`) goes with it.
    for (_, v) in order {
        if resolve_use(func, *v) == len {
            removed.insert(*v);
        }
    }
    // The payload elements' uses: a `u32` decode is the value; a value
    // carried as its own `Val` is the payload; pure work joins `removed`.
    for p in &payloads {
        for load in &p.loads {
            for site in uses.uses_of(*load) {
                let HighUseSite::Binding { user } = site else {
                    return Err(format!("{load:?}, a payload element, is used by the region"));
                };
                if !live(*user) {
                    continue;
                }
                let Some(expr) = func.bindings.get(*user).map(|b| &b.expr) else { continue };
                let user_block = block_of.get(user).copied();
                let in_arm = user_block.is_some_and(|b| {
                    arm_blocks.iter().find(|(k, _)| *k == p.arm).is_some_and(|(_, bs)| bs.contains(&b))
                });
                match expr {
                    Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { .. })) if decodes_as_u32(&p.ty, types) => {
                        if !in_arm {
                            return Err(format!("{user:?} decodes a payload outside its arm"));
                        }
                        kept.insert(*user);
                        decodes.push((*user, p.arm));
                    }
                    e if pure(e) => {}
                    Expr::Use(_) => {}
                    _ if val_is_value(&p.ty) => {
                        if !in_arm {
                            return Err(format!("{user:?} uses a payload outside its arm"));
                        }
                        kept.insert(*user);
                    }
                    _ => return Err(format!("{user:?} uses a payload element of a type not carried as its own Val")),
                }
            }
        }
    }
    // A unit enum's code, checked as rustc folds it: `select(chain, k,
    // is_u32(x))` where the chain sends each declared discriminant of the
    // decoded code to itself and anything else to a code no case has, and
    // `k` is no case's code either. On the payload `x` is a `U32Val` and its
    // code a declared one, so the select is that code: the payload's
    // discriminant.
    let mut codes: Vec<(ValueId, ArmKey)> = Vec::new();
    for p in &payloads {
        let KnownType::UserDefined(id) = &p.ty else { continue };
        let Some(def) = types.enums.iter().find(|e| e.id == *id) else { continue };
        let declared: HashSet<i128> = def.cases.iter().map(|c| i128::from(c.value)).collect();
        let of_payload = |v: ValueId| p.loads.contains(&resolve_use(func, v));
        for (b, sel) in order {
            let (if_true, if_false, cond) = match func.bindings.get(*sel).map(|b| &b.expr) {
                Some(Expr::Select { cond, if_true, if_false }) => (*if_true, *if_false, *cond),
                Some(Expr::Unknown { op_kind: sordec_ir::WasmOpcodeKind::Select, args, .. }) if args.len() == 3 => {
                    (args[0], args[1], args[2])
                }
                _ => continue,
            };
            let tested = matches!(expr_of(func, cond),
                Some(Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck { value, tag, negated: false })))
                    if of_payload(*value) && *tag == crate::val_abi::TAG_U32_VAL);
            if !tested || trace_int(func, if_false).is_none_or(|k| declared.contains(&k)) {
                continue;
            }
            let Some((found, parts)) = super::enum_match::code_chain_parts(func, if_true) else { continue };
            let word_ok = parts.last().is_some_and(|w| {
                matches!(func.bindings.get(*w).map(|b| &b.expr), Some(Expr::Unary { op: UnaryOp::Wrap32, value })
                    if matches!(expr_of(func, *value),
                        Some(Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { value: x }))) if of_payload(*x)))
            });
            if found != declared || !word_ok {
                continue;
            }
            let here = arm_blocks.iter().find(|(k, _)| *k == p.arm).is_some_and(|(_, bs)| bs.contains(b));
            if !here {
                return Err(format!("{sel:?} reads a payload's code outside its arm"));
            }
            kept.insert(*sel);
            codes.push((*sel, p.arm));
            removed.extend(parts.iter().copied());
            removed.insert(resolve_use(func, cond));
        }
    }
    // The position: only the switch and a bound test no variant passes.
    let aliases: Vec<ValueId> =
        func.bindings.iter().map(|(id, _)| id).filter(|id| resolve_use(func, *id) == decoded).collect();
    let mut bound_tests: HashSet<ValueId> = HashSet::new();
    for d in &aliases {
        removed.insert(*d);
        for site in uses.uses_of(*d) {
            let HighUseSite::Binding { user } = site else {
                if resolve_use(func, selector) == decoded {
                    continue;
                }
                return Err("the position is used by the region other than as the switch".into());
            };
            if !live(*user) || aliases.contains(user) {
                continue;
            }
            match func.bindings.get(*user).map(|b| &b.expr) {
                Some(Expr::Unary { op: UnaryOp::Wrap32, .. }) if resolve_use(func, selector) == *user => {
                    removed.insert(*user);
                }
                Some(Expr::Binary { op: BinaryOp::GtU, lhs, rhs })
                    if resolve_use(func, *lhs) == decoded
                        && trace_int(func, *rhs).is_some_and(|k| k >= i128::from(n) - 1) =>
                {
                    removed.insert(*user);
                    bound_tests.insert(*user);
                }
                _ => return Err(format!("{user:?} reads the position other than as the switch or a bound test")),
            }
        }
    }
    removed.insert(resolve_use(func, selector));
    // Pure work on what goes, forward and back, to a fixpoint. The
    // position's own uses are settled above.
    // Nothing joins through the position: the source sees the variant, so
    // a test of it is the source's unless it is the bound test above.
    let mut protected: HashSet<ValueId> = aliases.iter().copied().collect();
    protected.insert(resolve_use(func, selector));
    protected.extend(bound_tests.iter().copied());
    loop {
        let mut grew = false;
        for (_, v) in order {
            if removed.contains(v) || kept.contains(v) || resolve_use(func, *v) == value {
                continue;
            }
            let Some(expr) = func.bindings.get(*v).map(|b| &b.expr) else { continue };
            if !pure(expr) && !matches!(expr, Expr::Use(_)) {
                continue;
            }
            let mut operands = Vec::new();
            expr.for_each_value_use(|u| operands.push(u));
            let from_removed = operands.iter().any(|u| removed.contains(u))
                && operands
                    .iter()
                    .all(|u| removed.contains(u) || matches!(expr_of(func, *u), Some(Expr::Literal(_))));
            if from_removed && !operands.iter().any(|u| protected.contains(u)) {
                removed.insert(*v);
                grew = true;
                continue;
            }
            // Built from constants and feeding only what goes: the
            // lookup's table operands.
            let sites: Vec<&HighUseSite> =
                uses.uses_of(*v).iter().filter(|s| !matches!(s, HighUseSite::Binding { user } if !live(*user))).collect();
            let feeds = !sites.is_empty()
                && sites.iter().all(|s| matches!(s, HighUseSite::Binding { user } if removed.contains(user)));
            let constant = operands
                .iter()
                .all(|u| removed.contains(u) || matches!(expr_of(func, *u), Some(Expr::Literal(_))));
            if feeds && constant && !operands.is_empty() {
                removed.insert(*v);
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }

    // Every use of what goes goes too: by a removed binding, a decode or
    // a payload use rewritten above, or a condition the region drops.
    let mut conds: HashSet<ValueId> = HashSet::new();
    for r in &removed {
        for s in uses.uses_of(*r) {
            match s {
                HighUseSite::Binding { user } if removed.contains(user) || kept.contains(user) || !live(*user) => {}
                HighUseSite::Binding { user } => {
                    return Err(format!("{user:?} uses {r:?}, which the decode removes"));
                }
                HighUseSite::Return => return Err(format!("{r:?} is returned")),
                HighUseSite::Region => {
                    conds.insert(*r);
                }
            }
        }
    }
    let empty = super::guard::empty_blocks(func);
    let mut strip = HashSet::new();
    let mut keep_else = HashSet::new();
    let mut keep_then = HashSet::new();
    let mut dissolve = HashSet::new();
    let mut bad: Option<String> = None;
    let mut index_seen = false;
    func.region.for_each_node(|node| match node {
        Region::If { cond, then_region, else_region } if conds.contains(cond) => {
            let then_trap = super::guard::is_trap(then_region, &empty);
            let else_trap = else_region.as_ref().is_some_and(|e| super::guard::is_trap(e, &empty));
            // A test of the position goes only as a trap guard.
            if bound_tests.contains(cond) && !(then_trap && else_region.is_none()) {
                bad = Some(format!("the bound test {cond:?} is not a trap guard"));
                return;
            }
            match (then_trap, else_region.is_some(), else_trap) {
                (true, false, _) => {
                    strip.insert(*cond);
                }
                (true, true, false) => {
                    keep_else.insert(*cond);
                }
                (false, true, true) => {
                    keep_then.insert(*cond);
                }
                _ if empty_after(func, node, &removed, &empty) => {
                    dissolve.insert(*cond);
                }
                _ => bad = Some(format!("{cond:?} branches to work the decode does not explain")),
            }
        }
        Region::Switch { index, .. } if conds.contains(index) || *index == selector => {
            if *index == selector {
                index_seen = true;
            } else {
                bad = Some("another switch on a removed value".into());
            }
        }
        _ => {}
    });
    if let Some(why) = bad {
        return Err(why);
    }
    let mut region_uses: Vec<ValueId> = Vec::new();
    func.region.for_each_value_use(|u| {
        if conds.contains(&u) {
            region_uses.push(u);
        }
    });
    for u in region_uses {
        let handled = strip.contains(&u)
            || keep_else.contains(&u)
            || keep_then.contains(&u)
            || dissolve.contains(&u)
            || (u == selector && index_seen)
            || Some(u) == linked;
        if !handled {
            return Err(format!("{u:?} is read by the region other than as a condition it drops"));
        }
    }
    // Conditions are tested once each: two `if`s on one could disagree on
    // what the rewrite keeps.
    let mut counted: HashMap<ValueId, usize> = HashMap::new();
    func.region.for_each_node(|node| {
        if let Region::If { cond, .. } = node
            && conds.contains(cond)
        {
            *counted.entry(*cond).or_default() += 1;
        }
    });
    if counted.values().any(|n| *n > 1) {
        return Err("one removed condition guards two branches".into());
    }

    // The default arm names its variant when it reads a payload.
    let explicit_default = match by_arm.get(&ArmKey::Default) {
        Some(c) => {
            let case = case_of(ArmKey::Default).ok_or("the default arm stands for several variants")?;
            let b = block_of.get(c).ok_or("a call is not scheduled")?;
            let moves = rest_blocks.contains(b);
            if moves && !falls_through(default) {
                return Err("the default arm does not fall into the rest".into());
            }
            Some((case, moves))
        }
        None => None,
    };
    // The continuation moves only for the payload it reads.
    let in_default = blocks_in(default);
    let hoist = hoist.filter(|_| {
        by_arm.get(&ArmKey::Default).and_then(|c| block_of.get(c)).is_some_and(|b| !in_default.contains(b))
    });
    trace(
        func,
        &format!(
            "decode of {value:?} as {}: {} calls, {} payload arms, {} removed",
            union.name,
            calls.len(),
            payloads.len(),
            removed.len()
        ),
    );
    Ok(Site {
        value,
        union: union.id,
        element: false,
        hoist,
        removed,
        decodes,
        codes,
        strip,
        keep_else,
        keep_then,
        dissolve,
        selector,
        payloads,
        explicit_default,
    })
}

// ---------------------------------------------------------------------
// The rewrite
// ---------------------------------------------------------------------

fn apply(func: &mut HighFunction, site: Site) -> i64 {
    let prov = |note: String| Provenance::new(PASS_NAME, ProvenanceSource::SdkPattern, note);
    // An element read from a vector of the enum is the enum: the decode
    // just taken apart is its derived conversion, which reading it from the
    // typed vector regenerates.
    if site.element
        && let Some(b) = func.bindings.get_mut(site.value)
    {
        b.ty = IrType::Known(KnownType::UserDefined(site.union));
        b.add_provenance(prov(
            "an element of a vector the declaration types, decoded inline as that enum: the element".into(),
        ));
    }
    // The default's continuation moves into it, in place of its `break`.
    if let Some(h) = site.hoist {
        let region = std::mem::replace(&mut func.region, Region::Unreachable);
        func.region = hoist(region, h, site.selector);
    }
    // The payloads, one per arm that reads one.
    let mut opening: HashMap<ArmKey, (ValueId, HashMap<ValueId, ValueId>)> = HashMap::new();
    for p in &site.payloads {
        let id = ValueId::new(func.bindings.len() as u32);
        func.bindings.push(sordec_ir::Binding::new(
            id,
            IrType::Known(p.ty.clone()),
            Expr::VariantPayload { value: site.value, variant: p.variant.clone(), index: 0 },
            prov(format!("the payload of `{}`, bound by its arm of the match on the decoded enum", p.variant)),
        ));
        let map: HashMap<ValueId, ValueId> = p.loads.iter().map(|l| (*l, id)).collect();
        opening.insert(p.arm, (id, map));
    }
    // Decodes of a payload's `Val`: the value, widened.
    let mut elisions = Vec::new();
    for (d, arm) in &site.decodes {
        let Some((p, _)) = opening.get(arm) else { continue };
        elisions.push(Elision {
            id: *d,
            expr: Expr::Unary { op: UnaryOp::ExtendU32, value: *p },
            ty: Some(IrType::Inferred(KnownType::I64)),
            note: "the payload's `Val` decoded is its value: the body of a `U32Val`".into(),
            metric: mc::MARSHALLING_ENUM_ITER_PAYLOADS,
        });
    }
    for (c, arm) in &site.codes {
        let Some((p, _)) = opening.get(arm) else { continue };
        elisions.push(Elision {
            id: *c,
            expr: Expr::Unary { op: UnaryOp::Wrap32, value: *p },
            ty: Some(IrType::Inferred(KnownType::I32)),
            note: "the payload's checked code is its discriminant: its `Val` is a `U32Val` of a declared case".into(),
            metric: mc::MARSHALLING_ENUM_ITER_PAYLOADS,
        });
    }
    for v in &site.removed {
        elisions.push(Elision {
            id: *v,
            expr: Expr::Literal(Literal::Unit),
            ty: Some(IrType::Known(KnownType::Unit)),
            note: "the enum's derived decode through the vector iterator, elided: the match names the variant and \
                   binds the payload"
                .into(),
            metric: mc::MARSHALLING_ENUM_ITER_SITES,
        });
    }
    apply_elisions(func, PASS_NAME, elisions);
    // The region: checks drop, the switch selects on the value, its arms
    // open with their payloads.
    let empty = super::guard::empty_blocks(func);
    let region = std::mem::replace(&mut func.region, Region::Unreachable);
    let region = drop_checks(region, &site, &empty);
    func.region = rewrite_switch(func, region, &site, &opening);
    site.payloads.len() as i64
}

/// `region` with the items after scope `h.inner` moved into the default
/// arm of the switch on `selector`, in place of its `break 'inner`, ending
/// in `break 'outer` when they fell out of `'outer`'s body.
fn hoist(region: Region, h: Hoist, selector: ValueId) -> Region {
    fn take(region: Region, h: Hoist, moved: &mut Option<Vec<Region>>) -> Region {
        match region {
            Region::Sequence(items) => {
                let mut out = Vec::with_capacity(items.len());
                let mut it = items.into_iter();
                while let Some(item) = it.next() {
                    let ours = matches!(&item, Region::Scope { out, .. } if *out == h.inner);
                    out.push(take(item, h, moved));
                    if ours && moved.is_none() {
                        let mut rest: Vec<Region> = it.by_ref().collect();
                        if let Some(outer) = h.outer {
                            rest.push(Region::Break { target: outer, transfer: Vec::new() });
                        }
                        *moved = Some(rest);
                    }
                }
                Region::Sequence(out)
            }
            Region::Scope { out, body } => Region::Scope { out, body: Box::new(take(*body, h, moved)) },
            Region::Loop { header, body, kind } => Region::Loop { header, body: Box::new(take(*body, h, moved)), kind },
            Region::If { cond, then_region, else_region } => Region::If {
                cond,
                then_region: Box::new(take(*then_region, h, moved)),
                else_region: else_region.map(|e| Box::new(take(*e, h, moved))),
            },
            Region::Switch { index, arms, default, dispatch } => Region::Switch {
                index,
                arms: arms.into_iter().map(|a| SwitchArm { cases: a.cases, body: take(a.body, h, moved) }).collect(),
                default: Box::new(take(*default, h, moved)),
                dispatch,
            },
            leaf => leaf,
        }
    }
    fn place(region: Region, selector: ValueId, moved: &mut Option<Vec<Region>>) -> Region {
        match region {
            Region::Sequence(items) => Region::Sequence(items.into_iter().map(|r| place(r, selector, moved)).collect()),
            Region::Scope { out, body } => Region::Scope { out, body: Box::new(place(*body, selector, moved)) },
            Region::Loop { header, body, kind } => {
                Region::Loop { header, body: Box::new(place(*body, selector, moved)), kind }
            }
            Region::If { cond, then_region, else_region } => Region::If {
                cond,
                then_region: Box::new(place(*then_region, selector, moved)),
                else_region: else_region.map(|e| Box::new(place(*e, selector, moved))),
            },
            Region::Switch { index, arms, default, dispatch } => {
                let arms = arms.into_iter().map(|a| SwitchArm { cases: a.cases, body: place(a.body, selector, moved) });
                let arms: Vec<SwitchArm> = arms.collect();
                let default = if index == selector && let Some(rest) = moved.take() {
                    // The arm's `break` gives way to where it went.
                    let kept: Vec<Region> = match *default {
                        Region::Sequence(items) => {
                            items.into_iter().filter(|r| !matches!(r, Region::Break { .. })).collect()
                        }
                        Region::Break { .. } => Vec::new(),
                        other => vec![other],
                    };
                    Region::Sequence(kept.into_iter().chain(rest).collect())
                } else {
                    place(*default, selector, moved)
                };
                Region::Switch { index, arms, default: Box::new(default), dispatch }
            }
            leaf => leaf,
        }
    }
    let mut moved = None;
    let region = take(region, h, &mut moved);
    place(region, selector, &mut moved)
}

/// The site's conditions, dropped: a trap guard goes, an inverted one
/// keeps its other side, a branch left empty keeps only its blocks.
fn drop_checks(region: Region, site: &Site, empty: &HashSet<BlockId>) -> Region {
    let rec = |r: Region| drop_checks(r, site, empty);
    match region {
        Region::Sequence(items) => Region::Sequence(items.into_iter().map(rec).collect()),
        Region::Scope { out, body } => Region::Scope { out, body: Box::new(rec(*body)) },
        Region::Loop { header, body, kind } => Region::Loop { header, body: Box::new(rec(*body)), kind },
        Region::Switch { index, arms, default, dispatch } => Region::Switch {
            index,
            arms: arms
                .into_iter()
                .map(|a| SwitchArm { cases: a.cases, body: rec(a.body) })
                .collect(),
            default: Box::new(rec(*default)),
            dispatch,
        },
        Region::If { cond, then_region, else_region } => {
            if site.strip.contains(&cond) {
                return Region::Sequence(Vec::new());
            }
            if site.keep_else.contains(&cond)
                && let Some(e) = else_region
            {
                return rec(*e);
            }
            if site.keep_then.contains(&cond) {
                return rec(*then_region);
            }
            if site.dissolve.contains(&cond) {
                let mut blocks: Vec<Region> = Vec::new();
                let whole = Region::If { cond, then_region, else_region };
                whole.for_each_node(|n| {
                    if let Region::Basic(b) = n
                        && !empty.contains(b)
                    {
                        blocks.push(Region::Basic(*b));
                    }
                });
                return Region::Sequence(blocks);
            }
            Region::If { cond, then_region: Box::new(rec(*then_region)), else_region: else_region.map(|e| Box::new(rec(*e))) }
        }
        leaf => leaf,
    }
}

/// The dispatch switch, on the value; the default made the payload
/// variant's arm when it reads one; arms opened with their payloads.
fn rewrite_switch(
    func: &mut HighFunction,
    region: Region,
    site: &Site,
    opening: &HashMap<ArmKey, (ValueId, HashMap<ValueId, ValueId>)>,
) -> Region {
    match region {
        Region::Sequence(items) => {
            let mut out: Vec<Region> = Vec::new();
            let mut it = items.into_iter();
            while let Some(item) = it.next() {
                let ours = matches!(&item, Region::Switch { index, .. } if *index == site.selector);
                if ours && matches!(site.explicit_default, Some((_, true))) {
                    // The rest runs only when control falls out of the
                    // switch, which only the default does.
                    let rest: Vec<Region> = it.by_ref().collect();
                    let Region::Switch { index, arms, default, dispatch } = item else { unreachable!() };
                    let default = Region::Sequence(std::iter::once(*default).chain(rest).collect());
                    let moved = Region::Switch { index, arms, default: Box::new(default), dispatch };
                    out.push(rewrite_switch(func, moved, site, opening));
                    break;
                }
                out.push(rewrite_switch(func, item, site, opening));
            }
            Region::Sequence(out)
        }
        Region::Scope { out, body } => Region::Scope { out, body: Box::new(rewrite_switch(func, *body, site, opening)) },
        Region::Loop { header, body, kind } => {
            Region::Loop { header, body: Box::new(rewrite_switch(func, *body, site, opening)), kind }
        }
        Region::If { cond, then_region, else_region } => Region::If {
            cond,
            then_region: Box::new(rewrite_switch(func, *then_region, site, opening)),
            else_region: else_region.map(|e| Box::new(rewrite_switch(func, *e, site, opening))),
        },
        Region::Switch { index, arms, default, dispatch } => {
            let ours = index == site.selector;
            let mut new_arms: Vec<SwitchArm> = Vec::new();
            for (i, arm) in arms.into_iter().enumerate() {
                let body = rewrite_switch(func, arm.body, site, opening);
                let body = match opening.get(&ArmKey::Arm(i)) {
                    Some((p, map)) if ours => open_arm(func, body, &[*p], map),
                    _ => body,
                };
                new_arms.push(SwitchArm { cases: arm.cases, body });
            }
            let default = rewrite_switch(func, *default, site, opening);
            if !ours {
                return Region::Switch { index, arms: new_arms, default: Box::new(default), dispatch };
            }
            let default = match (site.explicit_default, opening.get(&ArmKey::Default)) {
                (Some((case, _)), Some((p, map))) => {
                    let body = open_arm(func, default, &[*p], map);
                    new_arms.push(SwitchArm { cases: vec![case], body });
                    new_arms.sort_by_key(|a| a.cases.first().copied());
                    Region::Unreachable
                }
                _ => default,
            };
            Region::Switch { index: site.value, arms: new_arms, default: Box::new(default), dispatch: Some(site.value) }
        }
        leaf => leaf,
    }
}

// ---------------------------------------------------------------------
// A decode kept: its struct payloads typed, its variant re-matched
// ---------------------------------------------------------------------

/// The `Val` of a struct payload, typed as the struct the declaration
/// gives it: the payload element of the variant's arm is that variant's
/// payload, and a struct is carried as its own `Val`. A decoder helper
/// the arm hands it to is then that struct's decode at the call
/// (`udt_decode`). The count typed.
fn type_struct_payloads(func: &mut HighFunction, proof: &Proof, types: &TypeRegistry) -> i64 {
    let mut n = 0;
    for (_, variant, ty, loads) in &proof.payloads {
        let KnownType::UserDefined(id) = ty else { continue };
        let Some(def) = types.structs.iter().find(|s| s.id == *id) else { continue };
        let want = IrType::Known(ty.clone());
        for load in loads {
            let Some(b) = func.bindings.get_mut(*load) else { continue };
            if b.ty == want {
                continue;
            }
            b.ty = want.clone();
            b.add_provenance(Provenance::new(
                PASS_NAME,
                ProvenanceSource::SdkPattern,
                format!("the payload of `{variant}` read by the enum's derived decode: a `{}` as declared", def.name),
            ));
            n += 1;
        }
    }
    n
}

/// Per arm a re-match opens: the bindings it opens with (the payload, then
/// what is recomputed from it) and each merge it reads, renamed.
type Openings = HashMap<ArmKey, (Vec<ValueId>, HashMap<ValueId, ValueId>)>;

/// One step of a payload value's re-derivation: a binding cloned with its
/// operands renamed, or the payload itself standing for its element.
#[derive(Debug, Clone, Copy)]
enum Step {
    /// The element is the payload (a type carried as its own `Val`).
    Payload(ValueId),
    /// `decode(element)` of a `u32` payload: the payload widened.
    Decode(ValueId),
    /// A pure binding computed from earlier steps and constants.
    Clone(ValueId),
}

/// How `v` is computed from the payload element `loads` alone, as the
/// steps that recompute it in order; `None` when it reads anything else
/// the decode's switch computed.
fn derivation(
    func: &HighFunction,
    v: ValueId,
    loads: &[ValueId],
    ty: &KnownType,
    types: &TypeRegistry,
    out: &mut Vec<Step>,
    seen: &mut HashSet<ValueId>,
) -> Option<()> {
    if !seen.insert(v) {
        return Some(());
    }
    if seen.len() > 64 {
        return None;
    }
    if loads.contains(&v) {
        val_is_value(ty).then_some(())?;
        out.push(Step::Payload(v));
        return Some(());
    }
    let expr = &func.bindings.get(v)?.expr;
    match expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { value })) => {
            (loads.contains(&resolve_use(func, *value)) && decodes_as_u32(ty, types)).then_some(())?;
            out.push(Step::Decode(v));
            return Some(());
        }
        Expr::Literal(_) => {}
        Expr::Use(_)
        | Expr::Unary { .. }
        | Expr::Binary { .. }
        | Expr::Field { .. }
        | Expr::WideJoin { .. }
        | Expr::Select { .. } => {
            if !matches!(expr, Expr::Use(_)) && !pure(expr) {
                return None;
            }
            let mut operands = Vec::new();
            expr.for_each_value_use(|u| operands.push(u));
            for u in operands {
                derivation(func, u, loads, ty, types, out, seen)?;
            }
        }
        _ => return None,
    }
    out.push(Step::Clone(v));
    Some(())
}

/// An arm a re-match opens with the payload: the arm, its variant's
/// position, and each merge it reads with that merge's value there.
type ArmOpen = (ArmKey, u32, Vec<(ValueId, ValueId)>);

/// A later switch on a kept decode's position, planned: which arms open
/// with the payload, and the merges each reads re-derived from it.
#[derive(Debug)]
struct Rematch {
    /// The switch's blocks, which name it.
    blocks: HashSet<BlockId>,
    /// Per arm reading a merge the decode's arm of its variant computed:
    /// the arm, its variant's position, and each merge with its value on
    /// that variant.
    opens: Vec<ArmOpen>,
    /// The default stands for one variant and reads its payload: it becomes
    /// that variant's arm, and with `true` the rest of the sequence after
    /// the switch, which only it reaches, moves into it.
    explicit_default: Option<(u32, bool)>,
}

/// The values a region reads: every scheduled binding's operands in its
/// blocks, and its own (conditions, selectors, transfer sources).
fn reads_in(func: &HighFunction, region: &Region, out: &mut BTreeSet<ValueId>) {
    for b in blocks_in(region) {
        let Some(block) = func.blocks.get(b) else { continue };
        for id in &block.bindings {
            if let Some(binding) = func.bindings.get(*id) {
                binding.expr.for_each_value_use(|u| {
                    out.insert(u);
                });
            }
        }
    }
    region.for_each_value_use(|u| {
        out.insert(u);
    });
}

/// The next later switch on `proof`'s position worth re-matching on the
/// value, planned; `None` when none is.
#[allow(clippy::too_many_lines)]
fn plan_rematch(func: &HighFunction, proof: &Proof, types: &TypeRegistry) -> Option<Rematch> {
    let union = types.unions.iter().find(|u| u.id == proof.union)?;
    let n = union.cases.len() as u32;
    let case_of_block: HashMap<BlockId, u32> =
        proof.arms.iter().flat_map(|(c, _, bs)| bs.iter().map(move |b| (*b, *c))).collect();
    let def_block: HashMap<ValueId, BlockId> = scheduled(func).into_iter().map(|(b, v)| (v, b)).collect();
    let mut found = Vec::new();
    find_switch(func, &func.region, proof.decoded, &mut found);
    'switches: for (sw, holder) in &found {
        let sw_blocks = blocks_in(sw);
        // After the decode's switch: every path to it went through that
        // switch, in the arm of the same position.
        if sw_blocks.is_empty() || !sw_blocks.is_subset(&proof.after) {
            continue;
        }
        let Region::Switch { arms, default, .. } = sw else { continue };
        if arms.iter().flat_map(|a| &a.cases).any(|c| *c >= n) {
            trace(func, "rematch: a case that is no variant");
            continue;
        }
        let named: HashSet<u32> = arms.iter().flat_map(|a| a.cases.iter().copied()).collect();
        let missing: Vec<u32> = (0..n).filter(|c| !named.contains(c)).collect();
        // The rest of the sequence, when no arm falls out of the switch:
        // only the default reaches it.
        let rest: &[Region] = match holder {
            Some((items, i)) if !arms.iter().any(|a| falls_through(&a.body)) => &items[i + 1..],
            _ => &[],
        };
        let mut keyed: Vec<(ArmKey, Option<u32>, BTreeSet<ValueId>)> = Vec::new();
        for (i, arm) in arms.iter().enumerate() {
            let mut reads = BTreeSet::new();
            reads_in(func, &arm.body, &mut reads);
            let case = match arm.cases.as_slice() {
                [c] => Some(*c),
                _ => None,
            };
            keyed.push((ArmKey::Arm(i), case, reads));
        }
        let mut reads = BTreeSet::new();
        reads_in(func, default, &mut reads);
        for r in rest {
            reads_in(func, r, &mut reads);
        }
        let default_case = match missing.as_slice() {
            [c] => Some(*c),
            _ => None,
        };
        keyed.push((ArmKey::Default, default_case, reads));

        let mut opens: Vec<ArmOpen> = Vec::new();
        for (key, case, reads) in keyed {
            let mut merges: Vec<(ValueId, ValueId)> = Vec::new();
            for p in reads {
                // A merge of the decode's switch: every value it takes comes
                // out of one of its arms.
                let Some(Expr::Phi { incoming }) = func.bindings.get(p).map(|b| &b.expr) else { continue };
                if incoming.is_empty() || !incoming.iter().all(|(b, _)| proof.switch_blocks.contains(b)) {
                    continue;
                }
                let inside = |v: ValueId| def_block.get(&v).is_some_and(|b| proof.switch_blocks.contains(b));
                let Some(k) = case else {
                    // Several variants: the merge is read as it is, which is
                    // its value whatever arm set it.
                    continue;
                };
                let values: BTreeSet<ValueId> = incoming
                    .iter()
                    .filter(|(b, _)| case_of_block.get(b) == Some(&k))
                    .map(|(_, v)| resolve_use(func, *v))
                    .collect();
                let [e] = values.iter().copied().collect::<Vec<_>>()[..] else {
                    trace(func, &format!("rematch: {p:?} takes {} values on variant {k}", values.len()));
                    continue 'switches;
                };
                // Computed before the switch: in scope, and read as it is.
                if !inside(e) {
                    continue;
                }
                let Some((_, _, ty, loads)) = proof.payloads.iter().find(|(c, ..)| *c == k) else {
                    trace(func, &format!("rematch: {p:?} is computed on variant {k}, which reads no payload"));
                    continue 'switches;
                };
                let mut steps = Vec::new();
                if derivation(func, e, loads, ty, types, &mut steps, &mut HashSet::new()).is_none() {
                    trace(func, &format!("rematch: {p:?} is not computed from the payload alone on variant {k}"));
                    continue 'switches;
                }
                merges.push((p, e));
            }
            if merges.is_empty() {
                continue;
            }
            let Some(k) = case else { continue 'switches };
            opens.push((key, k, merges));
        }
        if opens.is_empty() {
            continue;
        }
        let explicit_default =
            opens.iter().find(|(key, ..)| *key == ArmKey::Default).map(|(_, k, _)| (*k, !rest.is_empty()));
        if explicit_default.is_some_and(|(_, moves)| moves) && !falls_through(default) {
            trace(func, "rematch: the default does not fall into the rest");
            continue;
        }
        return Some(Rematch { blocks: sw_blocks, opens, explicit_default });
    }
    None
}

/// Re-match one later switch on a kept decode's position as a `match` on
/// the value; the merges its arms read become their values recomputed from
/// the payload the arm binds. Whether one was.
fn rematch(func: &mut HighFunction, proof: &Proof, types: &TypeRegistry) -> bool {
    let Some(plan) = plan_rematch(func, proof, types) else { return false };
    let prov = |note: String| Provenance::new(PASS_NAME, ProvenanceSource::SdkPattern, note);
    let mut opening: Openings = HashMap::new();
    for (key, k, merges) in &plan.opens {
        let Some((_, variant, ty, loads)) = proof.payloads.iter().find(|(c, ..)| c == k) else { return false };
        let p = ValueId::new(func.bindings.len() as u32);
        func.bindings.push(sordec_ir::Binding::new(
            p,
            IrType::Known(ty.clone()),
            Expr::VariantPayload { value: proof.value, variant: variant.clone(), index: 0 },
            prov(format!("the payload of `{variant}`, bound again where the variant is tested again")),
        ));
        let mut bindings = vec![p];
        let mut renamed: HashMap<ValueId, ValueId> = HashMap::new();
        let mut map: HashMap<ValueId, ValueId> = HashMap::new();
        for (merge, value) in merges {
            let mut steps = Vec::new();
            if derivation(func, *value, loads, ty, types, &mut steps, &mut HashSet::new()).is_none() {
                return false;
            }
            for step in steps {
                match step {
                    Step::Payload(v) => {
                        renamed.insert(v, p);
                    }
                    Step::Decode(v) => {
                        if renamed.contains_key(&v) {
                            continue;
                        }
                        let id = ValueId::new(func.bindings.len() as u32);
                        func.bindings.push(sordec_ir::Binding::new(
                            id,
                            IrType::Inferred(KnownType::I64),
                            Expr::Unary { op: UnaryOp::ExtendU32, value: p },
                            prov("the payload's `Val` decoded is its value: the body of a `U32Val`".into()),
                        ));
                        bindings.push(id);
                        renamed.insert(v, id);
                    }
                    Step::Clone(v) => {
                        if renamed.contains_key(&v) {
                            continue;
                        }
                        let Some(orig) = func.bindings.get(v) else { return false };
                        let mut expr = orig.expr.clone();
                        let ty = orig.ty.clone();
                        expr.for_each_value_use_mut(|u| {
                            if let Some(to) = renamed.get(u) {
                                *u = *to;
                            }
                        });
                        let id = ValueId::new(func.bindings.len() as u32);
                        func.bindings.push(sordec_ir::Binding::new(
                            id,
                            ty,
                            expr,
                            prov(format!(
                                "{v:?} recomputed from the payload of `{variant}`, which the decode computed it from"
                            )),
                        ));
                        bindings.push(id);
                        renamed.insert(v, id);
                    }
                }
            }
            let Some(to) = renamed.get(value).copied() else { return false };
            map.insert(*merge, to);
        }
        opening.insert(*key, (bindings, map));
    }
    let region = std::mem::replace(&mut func.region, Region::Unreachable);
    func.region = rewrite_rematch(func, region, &plan, proof, &mut opening);
    trace(func, &format!("rematch: a later switch on the variant of {:?}, {} arms opened", proof.value, plan.opens.len()));
    true
}

/// `region` with the planned switch selecting on the value: its planned
/// arms open with the payload and their re-derived merges, the default made
/// its variant's arm (with the rest moved in) when planned.
fn rewrite_rematch(
    func: &mut HighFunction,
    region: Region,
    plan: &Rematch,
    proof: &Proof,
    opening: &mut Openings,
) -> Region {
    let is_ours = |r: &Region| matches!(r, Region::Switch { .. }) && blocks_in(r) == plan.blocks;
    match region {
        Region::Sequence(items) => {
            let mut out: Vec<Region> = Vec::new();
            let mut it = items.into_iter();
            while let Some(item) = it.next() {
                if is_ours(&item) && matches!(plan.explicit_default, Some((_, true))) {
                    let rest: Vec<Region> = it.by_ref().collect();
                    let Region::Switch { index, arms, default, dispatch } = item else { unreachable!() };
                    let default = Region::Sequence(std::iter::once(*default).chain(rest).collect());
                    let whole = Region::Switch { index, arms, default: Box::new(default), dispatch };
                    out.push(rewrite_rematch_switch(func, whole, plan, proof, opening));
                    break;
                }
                out.push(rewrite_rematch(func, item, plan, proof, opening));
            }
            Region::Sequence(out)
        }
        r @ Region::Switch { .. } if is_ours(&r) => rewrite_rematch_switch(func, r, plan, proof, opening),
        Region::Scope { out, body } => {
            Region::Scope { out, body: Box::new(rewrite_rematch(func, *body, plan, proof, opening)) }
        }
        Region::Loop { header, body, kind } => {
            Region::Loop { header, body: Box::new(rewrite_rematch(func, *body, plan, proof, opening)), kind }
        }
        Region::If { cond, then_region, else_region } => Region::If {
            cond,
            then_region: Box::new(rewrite_rematch(func, *then_region, plan, proof, opening)),
            else_region: else_region.map(|e| Box::new(rewrite_rematch(func, *e, plan, proof, opening))),
        },
        Region::Switch { index, arms, default, dispatch } => Region::Switch {
            index,
            arms: arms
                .into_iter()
                .map(|a| SwitchArm { cases: a.cases, body: rewrite_rematch(func, a.body, plan, proof, opening) })
                .collect(),
            default: Box::new(rewrite_rematch(func, *default, plan, proof, opening)),
            dispatch,
        },
        leaf => leaf,
    }
}

/// The planned switch itself, rewritten (see [`rewrite_rematch`]).
fn rewrite_rematch_switch(
    func: &mut HighFunction,
    switch: Region,
    plan: &Rematch,
    proof: &Proof,
    opening: &mut Openings,
) -> Region {
    let Region::Switch { arms, default, .. } = switch else { return switch };
    let mut new_arms: Vec<SwitchArm> = Vec::new();
    for (i, arm) in arms.into_iter().enumerate() {
        let body = match opening.remove(&ArmKey::Arm(i)) {
            Some((bindings, map)) => open_arm(func, arm.body, &bindings, &map),
            None => arm.body,
        };
        new_arms.push(SwitchArm { cases: arm.cases, body });
    }
    let default = match (plan.explicit_default, opening.remove(&ArmKey::Default)) {
        (Some((case, _)), Some((bindings, map))) => {
            let body = open_arm(func, *default, &bindings, &map);
            new_arms.push(SwitchArm { cases: vec![case], body });
            new_arms.sort_by_key(|a| a.cases.first().copied());
            Region::Unreachable
        }
        _ => *default,
    };
    Region::Switch { index: proof.value, arms: new_arms, default: Box::new(default), dispatch: Some(proof.value) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{Arena, IrId, UnknownReason};
    use sordec_ir::{Binding, DispatchTable, HighBlock, MemoryImage, PanicKind, PrimitiveType, TypeRef, UnionCase};

    use crate::marshalling::test_support::v;

    const NEXT: u32 = 1;

    fn bb(i: u32) -> BlockId {
        BlockId::new(i)
    }

    fn untyped() -> IrType {
        IrType::Unknown(UnknownReason::InsufficientEvidence)
    }

    fn trap() -> Box<Region> {
        Box::new(Region::Panic { kind: PanicKind::Bare })
    }

    fn guard(cond: u32) -> Region {
        Region::If { cond: v(cond), then_region: trap(), else_region: None }
    }

    /// `enum E { A, B(<payload>) }`.
    fn types(payload: PrimitiveType) -> TypeRegistry {
        let mut reg = TypeRegistry::default();
        reg.unions.push(UnionDef {
            id: TypeId::new(0),
            name: "E".into(),
            cases: vec![
                UnionCase { name: "A".into(), fields: vec![] },
                UnionCase { name: "B".into(), fields: vec![TypeRef::Primitive(payload)] },
            ],
            exported: true,
        });
        reg
    }

    /// What `next` does through each parameter, and its gated element.
    type Summaries = (HashMap<FuncId, Vec<Option<ParamAccess>>>, HashMap<FuncId, Vec<Option<Gated>>>);

    fn summaries() -> Summaries {
        let out = ParamAccess { reads: vec![], writes: vec![(0, 8), (8, 8)], must_writes: vec![(0, 8)] };
        let state = ParamAccess { reads: vec![(0, 8), (8, 4), (12, 4)], writes: vec![(8, 4)], must_writes: vec![(8, 4)] };
        let id = FuncId::from_index(NEXT);
        let gated = Gated { width: 8, none: 2, writes: vec![(8, 8)] };
        (HashMap::from([(id, vec![Some(out), Some(state)])]), HashMap::from([(id, vec![Some(gated), None])]))
    }

    /// Departures from the plain shape, each a reason to refuse.
    struct Shape {
        /// Two `next` calls in the payload arm.
        twice: bool,
        /// The default arm also tests the position (`position == 0`).
        reads_position: bool,
        /// Something else stores into the iterator's index before the
        /// payload's `next` call.
        foreign_store: bool,
        /// Something else reads the iterator's state after the decode (its
        /// vector word, in `A`'s arm), seeing what the decode left there.
        reads_index_after: bool,
        /// The payload's code checked by a select chain whose fallback is
        /// this constant (`B(U)` with `enum U { X = 1, Y = 2 }`).
        code: Option<i32>,
        /// The decode is the body of a loop, which goes round after the
        /// match.
        looped: bool,
        /// The first call is made before the state is set.
        stale_first: bool,
        /// The value is an element `vec_get` reads from a `Vec<E>`.
        element: bool,
        /// The value is one `map_get` reads from a `Map<u32, E>`.
        map_value: bool,
        /// `B`'s arm is the default, `break 'scope`, and its work follows
        /// the scope; with `true` twice, a second break to that scope.
        hoisted: Option<bool>,
    }

    const PLAIN: Shape = Shape {
        twice: false,
        reads_position: false,
        foreign_store: false,
        reads_index_after: false,
        code: None,
        looped: false,
        stale_first: false,
        element: false,
        map_value: false,
        hoisted: None,
    };

    struct Builder {
        b: Arena<ValueId, Binding>,
    }

    impl Builder {
        fn seed(&mut self, ty: IrType, expr: Expr) -> u32 {
            let id = self.b.len() as u32;
            self.b.push(Binding::new(v(id), ty, expr, Provenance::new("seed", ProvenanceSource::DataFlow, "seed")));
            id
        }

        fn untyped(&mut self, expr: Expr) -> u32 {
            self.seed(untyped(), expr)
        }

        fn lit32(&mut self, n: i32) -> u32 {
            self.seed(IrType::Known(KnownType::I32), Expr::Literal(Literal::I32(n)))
        }

        fn lit64(&mut self, n: i64) -> u32 {
            self.seed(IrType::Known(KnownType::I64), Expr::Literal(Literal::I64(n)))
        }

        fn load(&mut self, base: u32, offset: u32, width: MemWidth) -> u32 {
            self.untyped(Expr::Load { addr: v(base), offset, width, signed: None, ty: untyped() })
        }

        fn store(&mut self, base: u32, value: u32, offset: u32, width: MemWidth) -> u32 {
            self.untyped(Expr::Store { addr: v(base), value: v(value), offset, width })
        }

        fn bin(&mut self, op: BinaryOp, lhs: u32, rhs: u32) -> u32 {
            self.untyped(Expr::Binary { op, lhs: v(lhs), rhs: v(rhs) })
        }

        fn known(&mut self, op: KnownOp) -> u32 {
            self.untyped(Expr::Semantic(SemanticOp::Known(op)))
        }

        fn func(self, id: u32, blocks: Vec<Vec<u32>>, region: Region) -> HighFunction {
            let mut arena: Arena<BlockId, HighBlock> = Arena::new();
            for (i, ids) in blocks.into_iter().enumerate() {
                arena.push(HighBlock { id: bb(i as u32), bindings: ids.into_iter().map(v).collect() });
            }
            HighFunction {
                id: FuncId::from_index(id),
                name: None,
                signature: None,
                aliases: Vec::new(),
                blocks: arena,
                bindings: self.b,
                region,
                params: vec![v(0), v(1)],
                returns: vec![],
            }
        }
    }

    /// The entrypoint: `e: E` (v0), the frame (v1); the inline decode, then
    /// `match position { 1 => { remaining check; next; x + x }, _ => {} }`.
    fn entry(shape: &Shape) -> HighFunction {
        let mut f = Builder { b: Arena::new() };
        let enum_ty = IrType::Known(KnownType::UserDefined(TypeId::new(0)));
        let param_ty = if shape.map_value {
            IrType::Known(KnownType::Map(Box::new(IrType::Known(KnownType::U32)), Box::new(enum_ty)))
        } else if shape.element {
            IrType::Known(KnownType::Vec(Box::new(enum_ty)))
        } else {
            enum_ty
        };
        let param = f.seed(param_ty, Expr::Phi { incoming: vec![] });
        let fp = f.seed(IrType::Known(KnownType::I32), Expr::Phi { incoming: vec![] });
        let mut prologue = Vec::new();
        let e = if shape.element || shape.map_value {
            let at = f.lit64(4);
            let got = if shape.map_value {
                f.known(KnownOp::MapOp { kind: MapOpKind::Get, args: vec![v(param), v(at)] })
            } else {
                f.known(KnownOp::VecOp { kind: VecOpKind::Get, args: vec![v(param), v(at)] })
            };
            let not_vec = f.known(KnownOp::ValTagCheck { value: v(got), tag: crate::val_abi::TAG_VEC_OBJECT, negated: true });
            prologue.extend([at, got, not_vec]);
            got
        } else {
            param
        };
        let len = f.known(KnownOp::VecOp { kind: VecOpKind::Len, args: vec![v(e)] });
        let zero = f.lit32(0);
        let s0 = f.store(fp, e, 0, MemWidth::W8);
        let s1 = f.store(fp, zero, 8, MemWidth::W4);
        let s2 = f.store(fp, len, 12, MemWidth::W4);
        let sixteen = f.lit32(16);
        let out = f.bin(BinaryOp::Add, fp, sixteen);
        let next = Expr::Call { target: FuncId::from_index(NEXT), args: vec![v(out), v(fp)] };
        let c0 = f.untyped(next.clone());
        let t0 = f.load(fp, 16, MemWidth::W8);
        let z64 = f.lit64(0);
        let t0_bad = f.bin(BinaryOp::Ne, t0, z64);
        let sym = f.load(fp, 24, MemWidth::W8);
        let pos = f.lit32(0);
        let n = f.lit32(2);
        let lookup = f.known(KnownOp::SymbolDispatch {
            sym: v(sym),
            table_pos: v(pos),
            len: v(n),
            table: DispatchTable { cases: vec!["A".into(), "B".into()], enum_name: Some("E".into()) },
        });
        let decoded = f.known(KnownOp::ValDecodeSmall { value: v(lookup) });
        let one64 = f.lit64(1);
        let bound = f.bin(BinaryOp::GtU, decoded, one64);
        let sel = f.untyped(Expr::Unary { op: UnaryOp::Wrap32, value: v(decoded) });
        // Arm `B`: one element left, then the payload.
        let idx = f.load(fp, 8, MemWidth::W4);
        let end = f.load(fp, 12, MemWidth::W4);
        let left = f.bin(BinaryOp::Sub, end, idx);
        let one32 = f.lit32(1);
        let too_many = f.bin(BinaryOp::GtU, left, one32);
        let c1 = f.untyped(next.clone());
        let t1 = f.load(fp, 16, MemWidth::W8);
        let t1_bad = f.bin(BinaryOp::Ne, t1, z64);
        let x = f.load(fp, 24, MemWidth::W8);
        let not_u32 = f.known(KnownOp::ValTagCheck { value: v(x), tag: 4, negated: true });
        let body = f.known(KnownOp::ValDecodeSmall { value: v(x) });
        let user = f.bin(BinaryOp::Add, body, body);
        let mut arm_tail = vec![body, user];
        if let Some(fallback) = shape.code {
            let word = f.untyped(Expr::Unary { op: UnaryOp::Wrap32, value: v(body) });
            let (one, two, none, k) = (f.lit32(1), f.lit32(2), f.lit32(0), f.lit32(fallback));
            let is2 = f.bin(BinaryOp::Eq, word, two);
            let s2 = f.untyped(Expr::Select { cond: v(is2), if_true: v(two), if_false: v(none) });
            let is1 = f.bin(BinaryOp::Eq, word, one);
            let s1 = f.untyped(Expr::Select { cond: v(is1), if_true: v(one), if_false: v(s2) });
            let tagged = f.known(KnownOp::ValTagCheck { value: v(x), tag: 4, negated: false });
            let code = f.untyped(Expr::Select { cond: v(tagged), if_true: v(s1), if_false: v(k) });
            let used = f.bin(BinaryOp::Add, code, code);
            arm_tail.extend([word, one, two, none, k, is2, s2, is1, s1, tagged, code, used]);
        }
        if shape.twice {
            arm_tail.push(f.untyped(next));
        }
        let mut default_block = Vec::new();
        if shape.reads_position {
            let z = f.lit64(0);
            default_block.extend([z, f.bin(BinaryOp::Eq, decoded, z)]);
        }
        if shape.reads_index_after {
            default_block.push(f.load(fp, 0, MemWidth::W8));
        }
        // Before the switch, so the payload arm's `next` call follows it.
        let mut lookup_block = vec![sym, pos, n, lookup, decoded, one64, bound, sel];
        if shape.foreign_store {
            let k = f.lit32(7);
            lookup_block.extend([k, f.store(fp, k, 8, MemWidth::W4)]);
        }
        let first_block = if shape.stale_first {
            vec![len, zero, sixteen, out, c0, s0, s1, s2, t0, z64, t0_bad]
        } else {
            vec![len, zero, s0, s1, s2, sixteen, out, c0, t0, z64, t0_bad]
        };
        let blocks = vec![
            prologue,
            first_block,
            lookup_block,
            vec![idx, end, left, one32, too_many],
            vec![c1, t1, t1_bad],
            vec![x, not_u32],
            arm_tail,
            default_block,
        ];
        let arm_items = vec![
            Region::Basic(bb(3)),
            guard(too_many),
            Region::Basic(bb(4)),
            guard(t1_bad),
            Region::Basic(bb(5)),
            guard(not_u32),
            Region::Basic(bb(6)),
            Region::Return { values: vec![v(user)] },
        ];
        let mut items = vec![Region::Basic(bb(0))];
        if shape.element || shape.map_value {
            // The element's check that it is a vector, a trap guard.
            let check = blocks[0][2];
            items.push(guard(check));
        }
        items.extend([Region::Basic(bb(1)), guard(t0_bad), Region::Basic(bb(2)), guard(bound)]);
        let after = if shape.looped {
            Region::Continue { target: bb(0), transfer: vec![] }
        } else {
            Region::Return { values: vec![] }
        };
        match shape.hoisted {
            None => {
                items.push(Region::Switch {
                    index: v(sel),
                    arms: vec![SwitchArm { cases: vec![1], body: Region::Sequence(arm_items) }],
                    default: Box::new(Region::Basic(bb(7))),
                    dispatch: Some(v(lookup)),
                });
                items.push(after);
            }
            Some(twice) => {
                // `A` (case 0) falls out to the rest; the default (`B`)
                // leaves the scope and its work follows it.
                let scope = bb(9);
                let mut body = vec![Region::Switch {
                    index: v(sel),
                    arms: vec![SwitchArm { cases: vec![0], body: Region::Basic(bb(7)) }],
                    default: Box::new(Region::Break { target: scope, transfer: vec![] }),
                    dispatch: Some(v(lookup)),
                }];
                if twice {
                    body.push(Region::If {
                        cond: v(fp),
                        then_region: Box::new(Region::Break { target: scope, transfer: vec![] }),
                        else_region: None,
                    });
                }
                body.push(after);
                items.push(Region::Scope { out: scope, body: Box::new(Region::Sequence(body)) });
                items.extend(arm_items);
            }
        }
        let region = if shape.looped {
            Region::Sequence(vec![
                Region::Loop { header: bb(0), body: Box::new(Region::Sequence(items)), kind: sordec_ir::LoopKind::Infinite },
            ])
        } else {
            Region::Sequence(items)
        };
        f.func(0, blocks, region)
    }

    fn run(func: &mut HighFunction, payload: PrimitiveType) -> Result<i64, ()> {
        run_with(func, &types(payload))
    }

    fn run_with(func: &mut HighFunction, types: &TypeRegistry) -> Result<i64, ()> {
        let (access, gated) = summaries();
        let nexts = HashSet::from([FuncId::from_index(NEXT)]);
        let mut tried = HashSet::new();
        let (site, _) = plan(func, &MemoryImage::empty(), types, None, &nexts, &access, &gated, &mut tried, &mut Vec::new());
        site.map(|s| apply(func, s)).ok_or(())
    }

    /// `enum E { A, B(U) }`, `enum U { X = 1, Y = 2 }`.
    fn unit_payload() -> TypeRegistry {
        let mut reg = types(PrimitiveType::U32);
        reg.unions[0].cases[1].fields = vec![TypeRef::UserDefined(TypeId::new(1))];
        reg.enums.push(sordec_ir::EnumDef {
            id: TypeId::new(1),
            name: "U".into(),
            cases: vec![
                sordec_ir::EnumCase { name: "X".into(), value: 1 },
                sordec_ir::EnumCase { name: "Y".into(), value: 2 },
            ],
        });
        reg
    }

    #[test]
    fn a_unit_enum_payloads_checked_code_is_its_discriminant() {
        let mut func = entry(&Shape { code: Some(0), ..PLAIN });
        assert_eq!(run_with(&mut func, &unit_payload()), Ok(1));
        let code = func.bindings.iter().find(|(_, b)| matches!(b.expr, Expr::Unary { op: UnaryOp::Wrap32, value }
            if matches!(func.bindings.get(value).map(|p| &p.expr), Some(Expr::VariantPayload { .. }))));
        assert!(code.is_some(), "the checked code is the payload as its discriminant");
    }

    #[test]
    fn a_code_chain_falling_back_to_a_declared_code_keeps_the_decode() {
        let mut func = entry(&Shape { code: Some(2), ..PLAIN });
        assert_eq!(run_with(&mut func, &unit_payload()), Err(()));
    }

    fn expr(func: &HighFunction, id: ValueId) -> &Expr {
        &func.bindings.get(id).expect("binding").expr
    }

    #[test]
    fn an_inline_decode_becomes_a_match_binding_the_payload() {
        let mut func = entry(&PLAIN);
        assert_eq!(run(&mut func, PrimitiveType::U32), Ok(1));
        let Region::Sequence(items) = &func.region else { panic!("sequence") };
        let switch = items.iter().find(|r| matches!(r, Region::Switch { .. })).expect("the switch");
        let Region::Switch { index, dispatch, arms, .. } = switch else { unreachable!() };
        assert_eq!((*index, *dispatch), (v(0), Some(v(0))));
        // The arm opens with `B`'s payload, and the decode of its `Val` is it.
        let Region::Sequence(arm) = &arms[0].body else { panic!("arm sequence") };
        let Region::Basic(first) = &arm[0] else { panic!("arm block") };
        let p = func.blocks.get(*first).expect("block").bindings[0];
        assert!(matches!(expr(&func, p), Expr::VariantPayload { variant, index: 0, .. } if variant == "B"));
        let widened = func.bindings.iter().any(|(_, b)| matches!(b.expr, Expr::Unary { op: UnaryOp::ExtendU32, value } if value == p));
        assert!(widened, "the payload's decode is the payload widened");
        // The iterator, its checks and the lookup are gone.
        let mut ifs = 0;
        func.region.for_each_node(|n| ifs += usize::from(matches!(n, Region::If { .. })));
        assert_eq!(ifs, 0, "every check of the decode is dropped");
        for id in [2, 4, 5, 6] {
            assert!(matches!(expr(&func, v(id)), Expr::Literal(Literal::Unit)), "v{id} is the decode's");
        }
    }

    #[test]
    fn a_payload_whose_val_decode_is_not_its_value_keeps_the_decode() {
        let mut func = entry(&PLAIN);
        assert_eq!(run(&mut func, PrimitiveType::I64), Err(()));
    }

    #[test]
    fn a_test_of_the_variant_outside_the_switch_keeps_the_decode() {
        let mut func = entry(&Shape { reads_position: true, ..PLAIN });
        assert_eq!(run(&mut func, PrimitiveType::U32), Err(()));
    }

    #[test]
    fn a_second_next_call_in_an_arm_keeps_the_decode() {
        let mut func = entry(&Shape { twice: true, ..PLAIN });
        assert_eq!(run(&mut func, PrimitiveType::U32), Err(()));
    }

    #[test]
    fn another_write_to_the_iterator_state_keeps_the_decode() {
        let mut func = entry(&Shape { foreign_store: true, ..PLAIN });
        assert_eq!(run(&mut func, PrimitiveType::U32), Err(()));
    }

    /// The switch the rewrite left, wherever it sits.
    fn the_switch(func: &HighFunction) -> (ValueId, Vec<SwitchArm>, Region) {
        let mut found = None;
        func.region.for_each_node(|n| {
            if let Region::Switch { index, arms, default, .. } = n {
                found = Some((*index, arms.clone(), (**default).clone()));
            }
        });
        found.expect("a switch")
    }

    /// The payload a match arm opens with.
    fn opens_with_payload(func: &HighFunction, body: &Region, variant: &str) -> bool {
        let first = match body {
            Region::Basic(b) => Some(*b),
            Region::Sequence(items) => match items.first() {
                Some(Region::Basic(b)) => Some(*b),
                _ => None,
            },
            _ => None,
        };
        first.and_then(|b| func.blocks.get(b)).and_then(|blk| blk.bindings.first()).is_some_and(
            |p| matches!(expr(func, *p), Expr::VariantPayload { variant: name, .. } if name == variant),
        )
    }

    /// Each iteration sets the state afresh before its calls, so its first
    /// call reads element 0 and the arm's element 1, round after round.
    #[test]
    fn a_decode_in_a_loop_body_is_taken_per_iteration() {
        let mut func = entry(&Shape { looped: true, ..PLAIN });
        assert_eq!(run(&mut func, PrimitiveType::U32), Ok(1));
        let (index, arms, _) = the_switch(&func);
        assert_eq!(index, v(0));
        assert!(opens_with_payload(&func, &arms[0].body, "B"));
    }

    /// A call made before the state is set reads what the last iteration
    /// left — or nothing at all, the first time round.
    #[test]
    fn a_call_before_the_state_is_set_keeps_the_decode() {
        for looped in [false, true] {
            let mut func = entry(&Shape { stale_first: true, looped, ..PLAIN });
            assert_eq!(run(&mut func, PrimitiveType::U32), Err(()), "looped: {looped}");
        }
    }

    /// An element read from a vector of the enum is decoded as it: typed
    /// with the match, and its own check that it is a vector goes with the
    /// decode.
    #[test]
    fn an_element_of_a_vector_of_the_enum_is_the_enum() {
        let mut func = entry(&Shape { element: true, looped: true, ..PLAIN });
        assert_eq!(run(&mut func, PrimitiveType::U32), Ok(1));
        let (index, _, _) = the_switch(&func);
        let got = func.bindings.get(index).expect("the element");
        assert!(matches!(got.expr, Expr::Semantic(SemanticOp::Known(KnownOp::VecOp { kind: VecOpKind::Get, .. }))));
        assert_eq!(got.ty, IrType::Known(KnownType::UserDefined(TypeId::new(0))));
        let mut ifs = 0;
        func.region.for_each_node(|n| ifs += usize::from(matches!(n, Region::If { .. })));
        assert_eq!(ifs, 0, "the vector check goes with the decode");
    }

    /// A vector of something else says nothing about its elements.
    #[test]
    fn an_element_of_a_vector_of_another_type_keeps_the_decode() {
        let mut func = entry(&Shape { element: true, ..PLAIN });
        func.bindings.get_mut(v(0)).unwrap().ty = IrType::Known(KnownType::Vec(Box::new(IrType::Known(KnownType::Val))));
        assert_eq!(run(&mut func, PrimitiveType::U32), Err(()));
    }

    /// The default arm leaves a scope whose rest only it reaches: that rest
    /// is the default's variant's arm, and moves into it.
    #[test]
    fn a_default_arm_that_breaks_to_its_continuation_takes_it() {
        let mut func = entry(&Shape { hoisted: Some(false), ..PLAIN });
        assert_eq!(run(&mut func, PrimitiveType::U32), Ok(1));
        let (_, arms, default) = the_switch(&func);
        let b = arms.iter().find(|a| a.cases == [1]).expect("`B` named");
        assert!(opens_with_payload(&func, &b.body, "B"));
        let mut returns = 0;
        b.body.for_each_node(|n| returns += usize::from(matches!(n, Region::Return { values } if values.len() == 1)));
        assert_eq!(returns, 1, "the continuation moved into the arm");
        assert!(matches!(default, Region::Unreachable));
    }

    /// A second way into the continuation: it is not the default's alone.
    #[test]
    fn a_continuation_reached_another_way_keeps_the_decode() {
        let mut func = entry(&Shape { hoisted: Some(true), ..PLAIN });
        assert_eq!(run(&mut func, PrimitiveType::U32), Err(()));
    }

    /// A value read from a map the declaration types `Map<u32, E>` is an
    /// `E`, decoded where `Map::get` reads it.
    #[test]
    fn a_value_of_a_map_of_the_enum_is_the_enum() {
        let mut func = entry(&Shape { map_value: true, ..PLAIN });
        assert_eq!(run(&mut func, PrimitiveType::U32), Ok(1));
        let (index, _, _) = the_switch(&func);
        let got = func.bindings.get(index).expect("the value");
        assert!(matches!(got.expr, Expr::Semantic(SemanticOp::Known(KnownOp::MapOp { kind: MapOpKind::Get, .. }))));
        assert_eq!(got.ty, IrType::Known(KnownType::UserDefined(TypeId::new(0))));
    }

    /// A map of `Val`s says nothing about what it holds.
    #[test]
    fn a_value_of_a_map_of_another_type_keeps_the_decode() {
        let mut func = entry(&Shape { map_value: true, ..PLAIN });
        let vals = KnownType::Map(Box::new(IrType::Known(KnownType::U32)), Box::new(IrType::Known(KnownType::Val)));
        func.bindings.get_mut(v(0)).unwrap().ty = IrType::Known(vals);
        assert_eq!(run(&mut func, PrimitiveType::U32), Err(()));
    }

    /// One plain decode of `e` through the state at `fp`, its payload arm
    /// falling through: its blocks (numbered from `at`) and region items.
    /// The state's setting has a block of its own, `at`.
    fn decode_of(f: &mut Builder, e: u32, fp: u32, at: u32) -> (Vec<Vec<u32>>, Vec<Region>) {
        let len = f.known(KnownOp::VecOp { kind: VecOpKind::Len, args: vec![v(e)] });
        let zero = f.lit32(0);
        let s0 = f.store(fp, e, 0, MemWidth::W8);
        let s1 = f.store(fp, zero, 8, MemWidth::W4);
        let s2 = f.store(fp, len, 12, MemWidth::W4);
        let sixteen = f.lit32(16);
        let out = f.bin(BinaryOp::Add, fp, sixteen);
        let next = Expr::Call { target: FuncId::from_index(NEXT), args: vec![v(out), v(fp)] };
        let c0 = f.untyped(next.clone());
        let t0 = f.load(fp, 16, MemWidth::W8);
        let z64 = f.lit64(0);
        let t0_bad = f.bin(BinaryOp::Ne, t0, z64);
        let sym = f.load(fp, 24, MemWidth::W8);
        let (pos, n) = (f.lit32(0), f.lit32(2));
        let lookup = f.known(KnownOp::SymbolDispatch {
            sym: v(sym),
            table_pos: v(pos),
            len: v(n),
            table: DispatchTable { cases: vec!["A".into(), "B".into()], enum_name: Some("E".into()) },
        });
        let decoded = f.known(KnownOp::ValDecodeSmall { value: v(lookup) });
        let one64 = f.lit64(1);
        let bound = f.bin(BinaryOp::GtU, decoded, one64);
        let sel = f.untyped(Expr::Unary { op: UnaryOp::Wrap32, value: v(decoded) });
        let idx = f.load(fp, 8, MemWidth::W4);
        let end = f.load(fp, 12, MemWidth::W4);
        let left = f.bin(BinaryOp::Sub, end, idx);
        let one32 = f.lit32(1);
        let too_many = f.bin(BinaryOp::GtU, left, one32);
        let c1 = f.untyped(next);
        let t1 = f.load(fp, 16, MemWidth::W8);
        let t1_bad = f.bin(BinaryOp::Ne, t1, z64);
        let x = f.load(fp, 24, MemWidth::W8);
        let not_u32 = f.known(KnownOp::ValTagCheck { value: v(x), tag: 4, negated: true });
        let body = f.known(KnownOp::ValDecodeSmall { value: v(x) });
        let user = f.bin(BinaryOp::Add, body, body);
        let blocks = vec![
            vec![len, zero, s0, s1, s2],
            vec![sixteen, out, c0, t0, z64, t0_bad],
            vec![sym, pos, n, lookup, decoded, one64, bound, sel],
            vec![idx, end, left, one32, too_many],
            vec![c1, t1, t1_bad],
            vec![x, not_u32],
            vec![body, user],
            vec![],
        ];
        let arm = Region::Sequence(vec![
            Region::Basic(bb(at + 3)),
            guard(too_many),
            Region::Basic(bb(at + 4)),
            guard(t1_bad),
            Region::Basic(bb(at + 5)),
            guard(not_u32),
            Region::Basic(bb(at + 6)),
        ]);
        let items = vec![
            Region::Basic(bb(at)),
            Region::Basic(bb(at + 1)),
            guard(t0_bad),
            Region::Basic(bb(at + 2)),
            guard(bound),
            Region::Switch {
                index: v(sel),
                arms: vec![SwitchArm { cases: vec![1], body: arm }],
                default: Box::new(Region::Basic(bb(at + 7))),
                dispatch: Some(v(lookup)),
            },
        ];
        (blocks, items)
    }

    /// Two enum values decoded one after the other through the same frame
    /// slot; with `maybe`, the second's setting of the state happens on one
    /// path only, so its first call may read the first's state.
    fn two_decodes(maybe: bool) -> HighFunction {
        let mut f = Builder { b: Arena::new() };
        let enum_ty = IrType::Known(KnownType::UserDefined(TypeId::new(0)));
        let first = f.seed(enum_ty.clone(), Expr::Phi { incoming: vec![] });
        let fp = f.seed(IrType::Known(KnownType::I32), Expr::Phi { incoming: vec![] });
        let second = f.seed(enum_ty, Expr::Phi { incoming: vec![] });
        let flag = f.seed(IrType::Known(KnownType::Bool), Expr::Phi { incoming: vec![] });
        let (mut blocks, mut items) = decode_of(&mut f, first, fp, 0);
        let (more, mut rest) = decode_of(&mut f, second, fp, 8);
        blocks.extend(more);
        if maybe {
            let setting = rest.remove(0);
            rest.insert(0, Region::If { cond: v(flag), then_region: Box::new(setting), else_region: None });
        }
        items.extend(rest);
        items.push(Region::Return { values: vec![] });
        f.func(0, blocks, Region::Sequence(items))
    }

    /// Every site `plan` finds, applied in turn.
    fn run_all(func: &mut HighFunction) -> usize {
        let (access, gated) = summaries();
        let nexts = HashSet::from([FuncId::from_index(NEXT)]);
        let types = types(PrimitiveType::U32);
        let mut tried = HashSet::new();
        let mut sites = 0;
        while let (Some(site), _) = plan(func, &MemoryImage::empty(), &types, None, &nexts, &access, &gated, &mut tried, &mut Vec::new()) {
            apply(func, site);
            sites += 1;
        }
        sites
    }

    /// The second decode takes the slot once the first is done with it:
    /// each call follows its own decode's setting on every path, and both
    /// become matches.
    #[test]
    fn two_decodes_taking_one_state_in_turn_are_both_taken() {
        let mut func = two_decodes(false);
        assert_eq!(run_all(&mut func), 2);
        let mut on: Vec<ValueId> = Vec::new();
        func.region.for_each_node(|n| {
            if let Region::Switch { index, .. } = n {
                on.push(*index);
            }
        });
        assert_eq!(on, vec![v(0), v(2)]);
    }

    /// The second's first call may follow either setting: neither decode
    /// can say whose element it reads.
    #[test]
    fn a_call_that_may_follow_either_setting_keeps_both_decodes() {
        let mut func = two_decodes(true);
        assert_eq!(run_all(&mut func), 0);
    }

    /// `next(out, state)` as rustc emits it; `bump` is what it adds to the
    /// index.
    fn next_helper(bump: i32) -> HighFunction {
        let mut f = Builder { b: Arena::new() };
        let out = f.seed(IrType::Known(KnownType::I32), Expr::Phi { incoming: vec![] });
        let st = f.seed(IrType::Known(KnownType::I32), Expr::Phi { incoming: vec![] });
        let none = f.lit64(2);
        let idx = f.load(st, 8, MemWidth::W4);
        let end = f.load(st, 12, MemWidth::W4);
        let done = f.bin(BinaryOp::GeU, idx, end);
        let vec = f.load(st, 0, MemWidth::W8);
        let at = f.known(KnownOp::ValEncodeSmall { ty: KnownType::U32, value: v(idx) });
        let get = f.known(KnownOp::VecOp { kind: VecOpKind::Get, args: vec![v(vec), v(at)] });
        let put = f.store(out, get, 8, MemWidth::W8);
        let k = f.lit32(bump);
        let bumped = f.bin(BinaryOp::Add, idx, k);
        let save = f.store(st, bumped, 8, MemWidth::W4);
        let some = f.lit64(0);
        let tag = f.untyped(Expr::Phi { incoming: vec![(bb(0), v(none)), (bb(1), v(some))] });
        let write = f.store(out, tag, 0, MemWidth::W8);
        let blocks = vec![vec![none, idx, end, done], vec![vec, at, get, put, k, bumped, save, some], vec![write]];
        let region = Region::Sequence(vec![
            Region::Scope {
                out: bb(2),
                body: Box::new(Region::Sequence(vec![
                    Region::Basic(bb(0)),
                    Region::If {
                        cond: v(done),
                        then_region: Box::new(Region::Break { target: bb(2), transfer: vec![(v(tag), v(none))] }),
                        else_region: Some(Box::new(Region::Sequence(vec![
                            Region::Basic(bb(1)),
                            Region::Break { target: bb(2), transfer: vec![(v(tag), v(some))] },
                        ]))),
                    },
                ])),
            },
            Region::Basic(bb(2)),
            Region::Return { values: vec![] },
        ]);
        f.func(NEXT, blocks, region)
    }

    fn classified(f: &HighFunction) -> bool {
        let ir = crate::marshalling::test_support::module(vec![f.clone()]);
        let access = param_accesses(f);
        is_next(&ir, f, Some(&access))
    }

    #[test]
    fn the_sdk_iterators_next_is_recognised() {
        assert!(classified(&next_helper(1)));
    }

    #[test]
    fn a_next_that_skips_an_element_is_not_the_iterator() {
        assert!(!classified(&next_helper(2)));
    }

    /// Departures from the plain re-match shape below.
    #[derive(Default)]
    struct Rem {
        /// `B`'s merge input is the `next` tag word, not the payload's.
        not_payload: bool,
        /// A store into the iterator's index between the two switches.
        store_between: bool,
        /// That store before the switch, so `B`'s `next` call follows it.
        store_before: bool,
        /// The merge takes a second value from another block of `B`'s arm.
        two_values: bool,
        /// The second switch's arm is for case 5, no variant of `E`.
        bad_case: bool,
        /// The second switch sits in the decode's switch's default arm, not
        /// after the switch.
        nested: bool,
    }

    /// `enum E { A, B(u32) }` decoded inline; the switch's arms merge a value
    /// into `m` (`B`: computed from the payload's element; `A`: a constant),
    /// then a second switch on the position reads `m` in `B`'s arm.
    fn rematched(shape: &Rem) -> (HighFunction, u32, u32) {
        let mut f = Builder { b: Arena::new() };
        let param = f.seed(IrType::Known(KnownType::UserDefined(TypeId::new(0))), Expr::Phi { incoming: vec![] });
        let fp = f.seed(IrType::Known(KnownType::I32), Expr::Phi { incoming: vec![] });
        let len = f.known(KnownOp::VecOp { kind: VecOpKind::Len, args: vec![v(param)] });
        let zero = f.lit32(0);
        let s0 = f.store(fp, param, 0, MemWidth::W8);
        let s1 = f.store(fp, zero, 8, MemWidth::W4);
        let s2 = f.store(fp, len, 12, MemWidth::W4);
        let sixteen = f.lit32(16);
        let out = f.bin(BinaryOp::Add, fp, sixteen);
        let next = Expr::Call { target: FuncId::from_index(NEXT), args: vec![v(out), v(fp)] };
        let c0 = f.untyped(next.clone());
        let t0 = f.load(fp, 16, MemWidth::W8);
        let z64 = f.lit64(0);
        let t0_bad = f.bin(BinaryOp::Ne, t0, z64);
        let sym = f.load(fp, 24, MemWidth::W8);
        let pos = f.lit32(0);
        let n = f.lit32(2);
        let lookup = f.known(KnownOp::SymbolDispatch {
            sym: v(sym),
            table_pos: v(pos),
            len: v(n),
            table: DispatchTable { cases: vec!["A".into(), "B".into()], enum_name: Some("E".into()) },
        });
        let decoded = f.known(KnownOp::ValDecodeSmall { value: v(lookup) });
        let one64 = f.lit64(1);
        let bound = f.bin(BinaryOp::GtU, decoded, one64);
        let sel = f.untyped(Expr::Unary { op: UnaryOp::Wrap32, value: v(decoded) });
        let idx = f.load(fp, 8, MemWidth::W4);
        let end = f.load(fp, 12, MemWidth::W4);
        let left = f.bin(BinaryOp::Sub, end, idx);
        let one32 = f.lit32(1);
        let too_many = f.bin(BinaryOp::GtU, left, one32);
        let c1 = f.untyped(next);
        let t1 = f.load(fp, 16, MemWidth::W8);
        let t1_bad = f.bin(BinaryOp::Ne, t1, z64);
        let x = f.load(fp, 24, MemWidth::W8);
        let not_u32 = f.known(KnownOp::ValTagCheck { value: v(x), tag: 4, negated: true });
        let body = f.known(KnownOp::ValDecodeSmall { value: v(x) });
        let word = f.untyped(Expr::Unary { op: UnaryOp::Wrap32, value: v(body) });
        let junk = f.lit32(0);
        let carried = if shape.not_payload { t1 } else { word };
        let mut incoming = vec![(bb(5), v(carried)), (bb(6), v(junk))];
        if shape.two_values {
            incoming.push((bb(4), v(x)));
        }
        let merge = f.untyped(Expr::Phi { incoming });
        let seven = f.lit32(7);
        let clobber = f.store(fp, seven, 8, MemWidth::W4);
        let read = f.bin(BinaryOp::Add, merge, merge);
        let between = if shape.store_between { vec![seven, clobber] } else { vec![seven] };
        let mut lookup_block = vec![sym, pos, n, lookup, decoded, one64, bound, sel];
        if shape.store_before {
            lookup_block.extend([seven, clobber]);
        }
        let blocks = vec![
            vec![len, zero, s0, s1, s2, sixteen, out, c0, t0, z64, t0_bad],
            lookup_block,
            vec![idx, end, left, one32, too_many],
            vec![c1, t1, t1_bad],
            vec![x, not_u32],
            vec![body, word],
            vec![junk],
            between,
            vec![read],
        ];
        let decode_switch = Region::Switch {
            index: v(sel),
            arms: vec![SwitchArm {
                cases: vec![1],
                body: Region::Sequence(vec![
                    Region::Basic(bb(2)),
                    guard(too_many),
                    Region::Basic(bb(3)),
                    guard(t1_bad),
                    Region::Basic(bb(4)),
                    guard(not_u32),
                    Region::Basic(bb(5)),
                    Region::Transfer { target: bb(7), transfer: vec![(v(merge), v(carried))] },
                ]),
            }],
            default: Box::new(Region::Sequence(vec![
                Region::Basic(bb(6)),
                Region::Transfer { target: bb(7), transfer: vec![(v(merge), v(junk))] },
            ])),
            dispatch: Some(v(lookup)),
        };
        let again = Region::Switch {
            index: v(sel),
            arms: vec![SwitchArm {
                cases: vec![if shape.bad_case { 5 } else { 1 }],
                body: Region::Sequence(vec![Region::Basic(bb(8)), Region::Return { values: vec![v(read)] }]),
            }],
            default: Box::new(Region::Return { values: vec![] }),
            dispatch: None,
        };
        let decode_switch = match (shape.nested, decode_switch) {
            (true, Region::Switch { index, arms, dispatch, .. }) => Region::Switch {
                index,
                arms,
                default: Box::new(Region::Sequence(vec![Region::Basic(bb(6)), again.clone()])),
                dispatch,
            },
            (_, sw) => sw,
        };
        let mut items =
            vec![Region::Basic(bb(0)), guard(t0_bad), Region::Basic(bb(1)), guard(bound), decode_switch, Region::Basic(bb(7))];
        if !shape.nested {
            items.push(again);
        }
        (f.func(0, blocks, Region::Sequence(items)), merge, read)
    }

    /// The decode kept, and its later switches re-matched: whether one was.
    fn rematch_kept(func: &mut HighFunction, types: &TypeRegistry) -> bool {
        let (access, gated) = summaries();
        let nexts = HashSet::from([FuncId::from_index(NEXT)]);
        let mut kept = Vec::new();
        let (site, _) =
            plan(func, &MemoryImage::empty(), types, None, &nexts, &access, &gated, &mut HashSet::new(), &mut kept);
        assert!(site.is_none(), "a variant tested again keeps the decode");
        kept.iter().any(|p| rematch(func, p, types))
    }

    /// The second switch, found by the block its `B` arm reads in.
    fn second_switch(func: &HighFunction) -> (ValueId, Option<ValueId>, Region) {
        let mut found = None;
        func.region.for_each_node(|node| {
            if let Region::Switch { index, arms, dispatch, .. } = node
                && arms.iter().any(|a| blocks_in(&a.body).contains(&bb(8)))
            {
                found = Some((*index, *dispatch, node.clone()));
            }
        });
        found.expect("the second switch")
    }

    #[test]
    fn a_later_switch_on_the_variant_reads_the_payload_it_binds() {
        let (mut func, merge, read) = rematched(&Rem::default());
        assert!(rematch_kept(&mut func, &types(PrimitiveType::U32)));
        let (index, dispatch, sw) = second_switch(&func);
        assert_eq!((index, dispatch), (v(0), Some(v(0))), "the second switch selects on the value");
        assert!(opens_with_payload(&func, &match sw {
            Region::Switch { arms, .. } => arms[0].body.clone(),
            _ => unreachable!(),
        }, "B"));
        // The merge's read becomes the payload's value recomputed in the arm.
        let Expr::Binary { lhs, rhs, .. } = expr(&func, v(read)).clone() else { panic!("the read stays an add") };
        assert_eq!(lhs, rhs);
        assert_ne!(lhs, v(merge), "the merge is no longer read in the arm");
        assert!(matches!(expr(&func, lhs), Expr::Unary { op: UnaryOp::Wrap32, .. }));
    }

    #[test]
    fn a_merge_not_computed_from_the_payload_keeps_the_later_switch() {
        let (mut func, merge, read) = rematched(&Rem { not_payload: true, ..Rem::default() });
        assert!(!rematch_kept(&mut func, &types(PrimitiveType::U32)));
        let (index, _, _) = second_switch(&func);
        assert_ne!(index, v(0));
        assert!(matches!(expr(&func, v(read)), Expr::Binary { lhs, .. } if *lhs == v(merge)));
    }

    #[test]
    fn a_store_into_the_state_after_the_decode_does_not_keep_it_unproven() {
        // The store into the iterator's index runs after every access the
        // decode makes: the decode is proven, and re-matched.
        let (mut func, _, _) = rematched(&Rem { store_between: true, ..Rem::default() });
        assert!(rematch_kept(&mut func, &types(PrimitiveType::U32)));
    }

    /// Not re-matched, and the second switch still selects on the position.
    fn not_rematched(shape: &Rem) {
        let (mut func, _, _) = rematched(shape);
        assert!(!rematch_kept(&mut func, &types(PrimitiveType::U32)));
        let (index, _, _) = second_switch(&func);
        assert_ne!(index, v(0));
    }

    #[test]
    fn a_store_into_the_state_before_a_next_call_leaves_the_decode_unproven() {
        not_rematched(&Rem { store_before: true, ..Rem::default() });
    }

    #[test]
    fn a_merge_two_values_on_one_variant_keeps_the_later_switch() {
        not_rematched(&Rem { two_values: true, ..Rem::default() });
    }

    #[test]
    fn a_later_switch_on_a_case_that_is_no_variant_is_kept() {
        not_rematched(&Rem { bad_case: true, ..Rem::default() });
    }

    #[test]
    fn a_switch_on_the_position_not_after_the_decodes_is_kept() {
        not_rematched(&Rem { nested: true, ..Rem::default() });
    }

    #[test]
    fn a_read_of_what_the_decode_left_in_the_state_keeps_the_decode() {
        let mut func = entry(&Shape { reads_index_after: true, ..PLAIN });
        assert!(run(&mut func, PrimitiveType::U32).is_err());
        assert!(run(&mut entry(&PLAIN), PrimitiveType::U32).is_ok());
    }
}
