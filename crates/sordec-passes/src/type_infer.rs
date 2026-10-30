//! General type propagation over the high IR.
//!
//! The boundary lowering starts every binding [`IrType::Unknown`]; the
//! recognizers type only the bindings they rewrite (host-call results via
//! [`crate::val_abi`], val-encoded scalars). That leaves the connective
//! tissue — parameters, arithmetic, comparisons, phis, `Use` aliases,
//! returns — untyped. This pass is the missing propagation: it seeds types
//! from proven sources and flows them through the value graph to a
//! fixpoint, so the recovered program is *typed*, not just typeable.
//!
//! ## Certainty discipline
//!
//! - **`Known`** — proven: a `contractspecv0` parameter type, an integer
//!   literal.
//! - **`Inferred`** — derived by propagation (an arithmetic result, a phi
//!   join, a value flowing to a typed return). Evidence, not proof.
//! - **`Unknown`** — genuinely undetermined, or a phi whose arms disagree.
//!   Never a default guess.
//!
//! The lattice is **monotonic** (`Unknown < Inferred < Known`): a binding's
//! type only ever rises in certainty, and an equal-rank candidate of the
//! *same* base never displaces the incumbent. The one exception is a genuine
//! conflict — an equal-rank candidate of a *different* base — which reverts
//! the binding to `Unknown` and freezes it there, so the fixpoint still
//! terminates and stays order-deterministic. A binding the recognizers
//! already proved (`Known`) is never overwritten.
//!
//! ## Inter-procedural propagation
//!
//! Value flow does not stop at a call. Without crossing it, a `Call`
//! result is untyped no matter how well-typed the callee is, and a helper's
//! parameters are untyped no matter what its callers pass — measured on the
//! corpus, **97% of `Call` results and 96% of `Project`s were `Unknown`**,
//! which is what made almost every emitted helper
//! `fn funcN(arg0: Val, arg1: Val) -> Val` while its callers passed
//! integers. `Unknown` renders as the ABI-universal `Val`, so that is also
//! the single largest source of type errors in the emitted Rust.
//!
//! So the per-function fixpoint is wrapped in a **module-level** one over a
//! [`SigTable`]: each function's parameter and return types, joined from
//! every witness (its call sites, its return sites). A round infers inside
//! every function, then recomputes the table; the pass stops when neither
//! moves.
//!
//! Two properties make that sound:
//!
//! - **Slots use their own three-point lattice** ([`Slot`]): no evidence,
//!   one agreed type, or conflicting evidence. Both ends render as
//!   `IrType::Unknown` — "nothing known" and "no sound single type" are
//!   different reasons for the same honest answer, matching what
//!   [`phi_join`] already does when a phi's arms disagree.
//! - **Slots are recomputed from scratch each round**, as a join over all
//!   witnesses — never raised incrementally. Raising incrementally would
//!   let the first call site win and leave a later, disagreeing one unable
//!   to correct it, silently pinning a wrong type onto a signature.
//!
//! Monotonicity survives: witnesses' own types only rise, and the join is
//! monotone in each argument, so table entries ascend a finite-height
//! lattice. Recursion and mutual recursion therefore need no special
//! handling — no SCC condensation, just the fixpoint.
//!
//! A function with a `contractspecv0` signature is **not** subject to
//! call-site evidence: the ABI is proven and authoritative, the same stance
//! [`crate::marshalling`] takes when its gates read `signature` rather than
//! inferred types.
//!
//! Measured on the pinned corpus, crossing calls took typedness from
//! **60.4% to 80.9%** (`Unknown` 5,425 → 2,618) and `cargo check` errors
//! from 653 to 345. `Known` did not move: every type this adds is
//! `Inferred`, and nothing proven is overwritten.
//!
//! ## What the host catalog fixes
//!
//! A crypto or bytes call's object operand is the object the catalog
//! names: a `BytesObject` operand is a `Bytes`, a `VecObject` one a `Vec`
//! (`Known`, by the ABI). Exact because an object crosses into the host as
//! its handle, so the operand is that object whatever computed it — the
//! same reasoning that types an unnamed host call's object *result*. The
//! value whose length a `bytes_len` reads is a bytes object, whether it
//! was loaded from a slot nothing else reads or handed in as a helper's
//! parameter. Two limits
//! keep it from saying more than the catalog does. It names only an
//! operand nothing has named, or named only `Val`: a `BytesObject` may be a
//! `BytesN` the source converted on the way in, and the catalog says
//! nothing of length, so a `BytesN<32>` is never widened by it. And a small
//! scalar operand (`U32Val`) is left alone: what the host receives there is
//! the encoding, not the number.
//!
//! "Nothing has named" must mean nothing *will*, so the catalog speaks
//! last: the module fixpoint settles once without it and then again with
//! it. Within one fixpoint a `Known(Bytes)` planted in the first round
//! would outrank a `BytesN<32>` the next round derives — an `unwrap` of an
//! `Option<BytesN<32>>` typed only once its producer is — and the message
//! handed to `ed25519_verify` would lose the width it carries.
//!
//! ## A vec op's result, and a merge of vecs
//!
//! A vec op that hands back its receiver changed — `push_back`, `del`,
//! `insert`, `slice`, … — hands back the receiver's type (`Inferred`).
//! Exact because the SDK writes each as a method on one `Vec<T>` that
//! stores the host's result back into it (`slice` returns `Self`), so the
//! result and the receiver are one Rust type. The host's `Vec<?>` on the
//! result is what it says of every vec, not a second type.
//!
//! And `Vec<?>` merges with `Vec<T>` as `Vec<T>`, as `Option<?>` already
//! did ([`merge_partial`]): an unknown element type is less said about the
//! same type, not a different one. Two named element types that differ
//! still conflict. The merge's arms are the values of one variable, so an
//! arm known only as `Vec<?>` is the merge's `Vec<T>` too — the empty vec a
//! loop starts from is the vec it pushes onto — and so is the `Vec<?>` a
//! copy typed `Vec<T>` copies. Without that the merge is typed and its arm
//! still printed `Vec<Val>`, and the assignment moved the type error rather
//! than removing it. Callers are the exception: separate callers pass
//! separate vecs, so their `Vec<?>` and `Vec<T>` still conflict.
//!
//! ## A struct literal's fields
//!
//! A value placed in a `#[contracttype]` struct literal's field is the
//! field's declared type (`Inferred`): the contract's own declaration says
//! what the field holds. Only for a value nothing has named, or named only
//! `Val` — a slot read back, a helper's `Val` result. A value with a type
//! of its own keeps it: a `BytesN<32>` in a `Bytes` field is a widening the
//! source wrote, not a mistyping.
//!
//! ## An integer enum's decoded discriminant
//!
//! A `#[contracttype]` enum with integer discriminants crosses the ABI as
//! the `U32Val` of its discriminant, so a small decode of a value typed as
//! one is that discriminant: a `u32` (`Inferred`). The decode is often
//! still a hole — the guest range-checks and unpacks the word before
//! matching on it — and without a type the hole's `let` falls back to `()`,
//! which no cast or mask accepts. Only an enum the contract declares with
//! integer discriminants: a payload union or a struct is no small `Val`.
//!
//! ## An encoded number is not the number
//!
//! `Val` is the top of the lattice, and a named type refines it
//! ([`refines_val`]): an `Address` *is* its `Val`, so a host read used as
//! an `Address` is one. That is true of an object handle and false of an
//! encoded small scalar. The bits of `val_encode<u64>(x)` are
//! `x << 8 | U64Small`, not `x`; an `obj_from_u64(x)` is a handle, not
//! `x`. Refined anyway, the helper rustc outlines the `u64` encode into
//! was declared to return the `u64` it was given while both its arms are
//! `Val`s, and every caller handing that "number" on mismatched.
//!
//! So for a helper recognised as only encoding its argument
//! ([`EncoderTable`]):
//!
//! - what it returns in an encoded component — the merge of the encode's
//!   two forms, and the forms themselves — and that component wherever
//!   the helper is called are `Val`s, and no evidence makes them the
//!   number ([`encoded_values`]);
//! - that component is a `Val` in the signature table, whatever its
//!   callers do with it;
//! - the parameter it encodes is the number (`Known`), as an inline
//!   encode's operand is ([`semantic_arg_types`]): the helper hands it
//!   unchanged to the encode, whose ABI says what it is. A caller holding
//!   the raw 64-bit word passes it with the sign cast the emitter already
//!   writes for a word of the other sign.
//!
//! Why it is exact: the first two only decline evidence — they never name
//! a type the value does not have, and every value they cover is an encode
//! of the argument on every path, which the recogniser's gates prove. The
//! parameter pin is the encode's own operand type, carried through a
//! helper that does nothing else.
//!
//! Gates: only a recognised encoder's encoded components; an object handle
//! is never one and stays refinable. The parameter pin only for the
//! scalars whose small form packs the value itself (`u64`, `i64`, `u32`,
//! `i32`).
//!
//! Not every encode: an inline `val_encode` that a helper returns of a
//! value it loaded is the same fact, but covering it was measured to add
//! an error to five reconstructions. Each is a helper chain the encode
//! collapse does not see through, whose callers use the encode as the
//! number — typed as the number, the hole that stands for the encode
//! happens to compile. That gap is the collapse's, and is left to it.
//!
//! ## A returned merge is the declared number
//!
//! `let mut sum = 0; for v in input { sum += v } Ok(sum)` returns a loop
//! merge. The return encode collapses onto it ([`crate::marshalling`]),
//! leaving a copy typed `u64` by the spec (`Known`). Left to the rounds,
//! the merge's constant arm — `0i64`, the opcode's word — votes before the
//! back edge says anything, the merge comes out `i64`, and the sum and the
//! decoded element it adds follow it: `u64 + i64` in the reconstruction.
//!
//! So before the rounds, a merge such a copy reads is that number
//! (`Known`). Why it is exact: the copy is the merge, the same value, and
//! the spec says the value returned is that number; a merge has no
//! operation of its own whose type this could contradict. Its arms keep
//! theirs — the emitter fits a constant to the merge and casts an arm of
//! the other sign on its edge, as it does for any merge.
//!
//! Gates: an entrypoint (a spec signature); the copy is `Known` as one of
//! the scalars whose encode packs the value itself (`u64`, `i64`, `u32`,
//! `i32`), so no widening a collapse folded is read back as the merge's
//! type; the source is a merge with arms (not a parameter) that nothing
//! has typed yet.

use std::collections::{HashMap, HashSet};

use sordec_common::{FuncId, Provenance, ProvenanceSource, TypeId, ValueId};
use sordec_ir::{
    BinaryOp, CompositeType, CryptoOpKind, Expr, FunctionSignature, HighFunction, HighIr, IrType, KnownOp,
    KnownType, Literal, PrimitiveType, Region, SemanticOp, StructDef, TypeRef, UnaryOp, ValObjectKind,
    WasmOpcodeKind,
};

use crate::dataflow::{resolve_use, HighUseIndex};
use crate::effects::expr_effects;
use crate::marshalling::encode_helper::EncoderTable;
use crate::metrics_catalog as mc;
use crate::pass::{Pass, PassResult};

/// Unique pipeline name of this pass.
pub const PASS_NAME: &str = "type-infer";

/// Safety bound on propagation rounds. The lattice is monotonic so this is
/// never the reason a run stops in practice; it caps a pathological input.
const MAX_ROUNDS: usize = 64;

/// Safety bound on module-level rounds. Each one can only raise slots up a
/// three-point lattice, so the count needed is bounded by call-graph depth;
/// as with [`MAX_ROUNDS`] this caps a pathological input rather than
/// stopping a normal run.
const MAX_MODULE_ROUNDS: usize = 16;

/// The general type-propagation pass. Stateless; see the module docs.
#[derive(Debug, Default, Clone, Copy)]
pub struct TypeInferPass;

impl Pass<HighIr> for TypeInferPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let mut changed = false;

        // Module-level fixpoint: infer inside every function against the
        // current signature table, then rebuild the table from what that
        // produced. Both ascend, so this settles; see the module docs.
        let seed = seed_signatures(ir);
        let mut sigs = seed.clone();
        // Which helpers only encode their argument. Read from the shape of
        // each body, which inference does not change, so built once.
        let encoders = EncoderTable::build(ir);
        let mut disagreements: u64 = 0;
        let structs: Vec<StructDef> =
            ir.soroban_facts.as_ref().map(|f| f.types.structs.clone()).unwrap_or_default();
        let int_enums: HashSet<TypeId> = ir
            .soroban_facts
            .as_ref()
            .map(|f| f.types.enums.iter().map(|e| e.id).collect())
            .unwrap_or_default();
        // Settled twice: first on everything but the host catalog's object
        // kinds, then with them, so that weakest of named statements only
        // speaks where nothing else has (see "What the host catalog fixes").
        for catalog in [false, true] {
            for round_index in 0..MAX_MODULE_ROUNDS {
                // Until one round has run, no helper's parameter has been
                // read from its callers ([`phi_join_with_constants`]).
                let awaiting_callers = !catalog && round_index == 0;
                let mut round = false;
                // Counted fresh each round, not accumulated: the loop exits on
                // a round that changed nothing, so that round's count is the
                // settled one rather than a running total over rounds.
                disagreements = 0;
                for func in &mut ir.functions {
                    let (func_changed, func_disagreements) =
                        infer_function(func, &sigs, catalog, &structs, &int_enums, awaiting_callers, &encoders);
                    round |= func_changed;
                    disagreements += func_disagreements;
                }
                let next = recompute_signatures(ir, &seed, &encoders);
                if next != sigs {
                    sigs = next;
                    round = true;
                }
                changed |= round;
                if !round {
                    break;
                }
            }
        }
        if disagreements > 0 {
            result
                .metrics
                .increment(mc::TYPES_EVIDENCE_DISAGREEMENTS, disagreements as i64);
        }
        // Census the settled types (feeds the `coverage` typedness metric).
        for func in &ir.functions {
            for (_, binding) in func.bindings.iter() {
                match binding.ty {
                    IrType::Known(_) => result.metrics.increment(mc::TYPES_KNOWN, 1),
                    IrType::Inferred(_) => result.metrics.increment(mc::TYPES_INFERRED, 1),
                    IrType::Unknown(_) => result.metrics.increment(mc::TYPES_UNKNOWN, 1),
                }
            }
        }
        result.changed = changed;
        result
    }
}

/// Infer types for one function to a fixpoint against the module's
/// signature table. Returns whether any binding's type improved, and how
/// many times inter-procedural evidence disagreed with an equal-rank
/// incumbent. Works on a `ValueId -> IrType` snapshot and writes the
/// improvements back with `TypePropagation` provenance. `catalog` lets the
/// host catalog's operand kinds speak ([`catalog_object_args`]); `structs`
/// are the contract's declared structs, whose literals type their fields;
/// `int_enums` its enums with integer discriminants; `encoders` the
/// helpers that only encode their argument.
fn infer_function(
    func: &mut HighFunction,
    sigs: &SigTable,
    catalog: bool,
    structs: &[StructDef],
    int_enums: &HashSet<TypeId>,
    awaiting_callers: bool,
    encoders: &EncoderTable,
) -> (bool, u64) {
    let mut types: HashMap<ValueId, IrType> =
        func.bindings.iter().map(|(id, b)| (id, b.ty.clone())).collect();
    // Structure does not change during inference, so this is built once.
    let uses = HighUseIndex::build(func);
    // An encoder helper's encoded components stay `Val` whatever later
    // evidence says ("An encoded number is not the number").
    let mut ev = Evidence { encoded: encoded_values(func, encoders), ..Evidence::default() };

    seed_abi(func, &mut types, &mut ev);
    seed_returned_merges(func, &mut types, &mut ev);
    seed_params(func, sigs, &mut types, &mut ev);
    seed_encoder_params(func, encoders, &mut types, &mut ev);
    seed_tests(func, &mut types, &mut ev);

    for _ in 0..MAX_ROUNDS {
        let mut round_changed = false;
        // Forward: each binding's type from its own expression.
        for (id, binding) in func.bindings.iter() {
            let cand = match &binding.expr {
                Expr::Phi { incoming } => counter_bounded_by_u32(func, id, incoming, &types)
                    .or_else(|| phi_join_with_constants(func, incoming, &types, awaiting_callers))
                    .filter(|c| !ok_arms_of(types.get(&id), c)),
                Expr::Binary { op, lhs, rhs } => {
                    offset_of_known(func, *op, *lhs, *rhs, &types).or_else(|| infer_expr(&binding.expr, &types))
                }
                Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { value })) => {
                    discriminant_of(*value, &types, int_enums).or_else(|| infer_expr(&binding.expr, &types))
                }
                other => infer_expr(other, &types),
            };
            if let Some(cand) = cand {
                round_changed |= improve(&mut types, &mut ev, id, cand);
            }
            // Across a call: the callee's return components.
            if let Some(cand) = infer_call_result(func, &binding.expr, sigs) {
                round_changed |= improve_tracked(&mut types, &mut ev, id, cand);
            }
        }
        // Backward: uses constrain their operands / returned values.
        round_changed |= backward(func, &uses, &mut types, &mut ev, catalog, structs);
        round_changed |= backward_calls(func, sigs, &mut types, &mut ev);
        round_changed |= backward_returns(func, sigs, &mut types, &mut ev);
        if !round_changed {
            break;
        }
    }

    // Write improvements back, recording provenance.
    let mut changed = false;
    let ids: Vec<ValueId> = func.bindings.iter().map(|(id, _)| id).collect();
    for id in ids {
        let Some(cand) = types.get(&id).cloned() else {
            continue;
        };
        // A higher certainty wins, and so does naming an element type the
        // binding left `Unknown` — that is more information at the same
        // certainty, and refusing it is what kept a `vec_new` typed
        // `Vec<?>` after its elements were recovered.
        let Some(binding) = func.bindings.get_mut(id) else {
            continue;
        };
        let write = if rank(&cand) > rank(&binding.ty) || refines_val(&binding.ty, &cand) {
            Some(cand)
        } else {
            refine_element(&binding.ty, &cand)
        };
        if let Some(cand) = write {
            let note = format!("type-propagation: {}", describe(&cand));
            binding.ty = cand;
            binding.add_provenance(Provenance::new(
                PASS_NAME,
                ProvenanceSource::TypePropagation,
                note,
            ));
            changed = true;
        }
    }
    (changed, ev.disagreements)
}

/// The bindings that hold what a recognised encoding helper
/// ([`EncoderTable`]) returns the encode of its argument in: the call's
/// component where the helper is called, a copy of it, and, inside the
/// helper, each value returned in that component with the merges and
/// encodes it is made of — which the helper's recognition proved are
/// encodes of the argument and nothing else.
fn encoded_values(func: &HighFunction, encoders: &EncoderTable) -> HashSet<ValueId> {
    let mut out: HashSet<ValueId> =
        func.bindings.iter().map(|(id, _)| id).filter(|id| encoders.encoded_by_call(func, *id).is_some()).collect();
    let Some(slots) = encoders.slots(func.id) else {
        return out;
    };
    let mut work: Vec<ValueId> = Vec::new();
    func.region.for_each_node(|node| {
        if let Region::Return { values } = node {
            for (value, slot) in values.iter().zip(slots) {
                if slot.is_some() {
                    work.push(*value);
                }
            }
        }
    });
    while let Some(v) = work.pop() {
        if !out.insert(v) {
            continue;
        }
        match func.bindings.get(v).map(|b| &b.expr) {
            Some(Expr::Phi { incoming }) => work.extend(incoming.iter().map(|(_, a)| *a)),
            Some(Expr::Use(source)) => work.push(*source),
            _ => {}
        }
    }
    out
}

/// An encoding helper's parameter is the number it encodes (`Known`), as
/// the operand of an inline encode is ([`semantic_arg_types`]): the helper
/// hands it unchanged to that encode on every path, so the encode's ABI
/// says what it is. Only the scalars whose small form packs the value
/// itself; a wide number's small form packs only a limb, and a timepoint's
/// two forms disagree about what their operand is called.
fn seed_encoder_params(
    func: &HighFunction,
    encoders: &EncoderTable,
    types: &mut HashMap<ValueId, IrType>,
    ev: &mut Evidence,
) {
    let Some(slots) = encoders.slots(func.id) else {
        return;
    };
    for (index, ty) in slots.iter().flatten() {
        if !matches!(ty, KnownType::U64 | KnownType::I64 | KnownType::U32 | KnownType::I32) {
            continue;
        }
        if let Some(param) = func.params.get(*index) {
            improve(types, ev, *param, IrType::Known(ty.clone()));
        }
    }
}

/// Seed the entry parameters and returned values from the `contractspecv0`
/// signature — the proven ABI boundary (`Known`).
fn seed_abi(func: &HighFunction, types: &mut HashMap<ValueId, IrType>, ev: &mut Evidence) {
    let Some(sig) = &func.signature else {
        return;
    };
    // Parameters: positional against the entry block params (1 Val per
    // logical arg in the Soroban ABI).
    for (param, input) in func.params.iter().zip(&sig.inputs) {
        if let Some(ty) = type_ref_to_ir(&input.ty, Certainty::Known) {
            improve(types, ev, *param, ty);
        }
    }
    seed_returns(func, sig, types, ev);
}

/// Type every test a `bool` before the first round.
///
/// A comparison (or `eqz`) is a `bool` by its opcode alone, so the forward
/// rule would say so in the first round anyway — but only once the walk
/// reaches it. A merge listed earlier is joined first, sees the test still
/// untyped and settles on its constant arm's word: the `exhausted` flag of
/// an inclusive range loop is `phi [0i32, i >= n]`, typed `i32` in the
/// first round and conflicted to nothing in the second, when the test
/// arrives as a `bool`. Typed up front, the merge sees both arms at once
/// and the constant `0` joins as `false` ([`fits_constant`]).
///
/// Exact: it is the forward rule's own answer, moved ahead of the walk;
/// nothing else is typed by it.
fn seed_tests(func: &HighFunction, types: &mut HashMap<ValueId, IrType>, ev: &mut Evidence) {
    for (id, binding) in func.bindings.iter() {
        let test = match &binding.expr {
            Expr::Binary { op, .. } => is_comparison(*op),
            Expr::Unary { op: UnaryOp::Eqz, .. } => true,
            _ => false,
        };
        if test {
            improve(types, ev, id, IrType::Inferred(KnownType::Bool));
        }
    }
}

/// Seed this function's own parameters from the inter-procedural table —
/// what its callers were measured to pass.
///
/// Complements [`seed_abi`], which only fires for a function carrying a
/// `contractspecv0` signature. A helper has no ABI to read, and its call
/// sites are the only evidence its parameters ever get.
fn seed_params(
    func: &HighFunction,
    sigs: &SigTable,
    types: &mut HashMap<ValueId, IrType>,
    ev: &mut Evidence,
) {
    let Some(sig) = sigs.get(&func.id) else {
        return;
    };
    for (param, slot) in func.params.iter().zip(&sig.params) {
        if let Some(ty) = slot.to_ir(Certainty::Inferred) {
            improve_tracked(types, ev, *param, ty);
        }
    }
}

/// A `Call`'s or `Project`'s type, taken from the callee's return
/// components.
///
/// A single-component return types the `Call` binding itself. A multi-value
/// return has no single `KnownType` to give it, so the call stays untyped
/// and the components are typed through the `Project`s that read them —
/// which is the shape [`crate::SretReturnPass`] produces.
fn infer_call_result(func: &HighFunction, expr: &Expr, sigs: &SigTable) -> Option<IrType> {
    match expr {
        Expr::Call { target, .. } => {
            let sig = sigs.get(target)?;
            match sig.returns.as_slice() {
                [only] => sig.declared.clone().or_else(|| only.to_ir(Certainty::Inferred)),
                _ => None,
            }
        }
        Expr::Project { value, index } => {
            let call = resolve_use(func, *value);
            let Expr::Call { target, .. } = &func.bindings.get(call)?.expr else {
                return None;
            };
            sigs.get(target)?
                .returns
                .get(*index as usize)?
                .to_ir(Certainty::Inferred)
        }
        _ => None,
    }
}

/// Back-type call arguments from the callee's parameter types.
///
/// Positional, which the corpus verifies is exact: every `Call`'s argument
/// list matches its callee's `params` one-for-one (`Env` is not an IR
/// parameter — the emitter prepends it).
fn backward_calls(
    func: &HighFunction,
    sigs: &SigTable,
    types: &mut HashMap<ValueId, IrType>,
    ev: &mut Evidence,
) -> bool {
    let mut changed = false;
    for (_, binding) in func.bindings.iter() {
        let Expr::Call { target, args } = &binding.expr else {
            continue;
        };
        let Some(sig) = sigs.get(target) else {
            continue;
        };
        for (arg, slot) in args.iter().zip(&sig.params) {
            if let Some(ty) = slot.to_ir(Certainty::Inferred) {
                // A fixed-width value handed to a `Bytes` parameter keeps
                // its width: the call is where it widens.
                if base_of(Some(&ty)) == Some(KnownType::Bytes)
                    && matches!(base_of(types.get(arg)), Some(KnownType::BytesN(_)))
                {
                    continue;
                }
                changed |= improve_tracked(types, ev, *arg, ty);
            }
        }
    }
    changed
}

/// Back-type **every** return site's components from the settled return
/// type.
///
/// Not only the sites that already agree: the emitter's `helper_return`
/// takes its signature from the *first* value-carrying site, so leaving
/// sites disagreeing would emit a return type that some `return` statements
/// contradict.
fn backward_returns(
    func: &HighFunction,
    sigs: &SigTable,
    types: &mut HashMap<ValueId, IrType>,
    ev: &mut Evidence,
) -> bool {
    let Some(sig) = sigs.get(&func.id) else {
        return false;
    };
    let mut changed = false;
    for site in func.returns.iter().filter(|s| s.len() == sig.returns.len()) {
        for (value, slot) in site.iter().zip(&sig.returns) {
            if let Some(ty) = slot.to_ir(Certainty::Inferred) {
                changed |= improve_tracked(types, ev, *value, ty);
            }
        }
    }
    changed
}

/// Back-type each returned value from the signature's return type. The
/// value that flows out of a function *is* its return type by ABI, so this
/// is `Inferred` on the (possibly computed) value.
/// A merge a return encode collapsed onto is the number the spec declares
/// (`Known`), before any arm votes ("A returned merge is the declared
/// number").
fn seed_returned_merges(func: &HighFunction, types: &mut HashMap<ValueId, IrType>, ev: &mut Evidence) {
    if func.signature.is_none() {
        return;
    }
    for (_, b) in func.bindings.iter() {
        let Expr::Use(source) = &b.expr else { continue };
        let IrType::Known(k @ (KnownType::U32 | KnownType::I32 | KnownType::U64 | KnownType::I64)) = &b.ty else {
            continue;
        };
        let merge = matches!(
            func.bindings.get(*source).map(|s| &s.expr),
            Some(Expr::Phi { incoming }) if !incoming.is_empty()
        );
        let untyped = matches!(types.get(source), None | Some(IrType::Unknown(_)));
        if merge && untyped {
            improve(types, ev, *source, IrType::Known(k.clone()));
        }
    }
}

fn seed_returns(
    func: &HighFunction,
    sig: &FunctionSignature,
    types: &mut HashMap<ValueId, IrType>,
    ev: &mut Evidence,
) {
    for site in &func.returns {
        for (value, out) in site.iter().zip(&sig.outputs) {
            if let Some(ty) = type_ref_to_ir(out, Certainty::Inferred) {
                improve(types, ev, *value, ty);
            }
        }
    }
}

/// Backward rules: propagate from a use back to its operands. Returns
/// whether anything improved this round.
///
/// Bindings nothing reads are skipped when they are also pure — they are
/// residue, and residue must not dictate types. A recognizer that rewrites a
/// tag check into [`KnownOp::ValTagCheck`] leaves the raw `and v1, 255`
/// behind unread, and taking that as evidence types `v1` as the machine
/// `i64` it is at the bit level, contradicting the `BytesN<32>` the ABI
/// proves and the recognized op agrees with. The dead binding then wins,
/// because `improve` will not displace an equal rank.
///
/// The same discipline [`crate::marshalling::sret`] and
/// [`crate::SlotPromotionPass`] both document: scan what the program
/// actually does, never the leftovers. The check is one level deep, not
/// transitive — a binding read only by another dead binding still counts as
/// read, which errs toward keeping evidence.
fn backward(
    func: &HighFunction,
    uses: &HighUseIndex,
    types: &mut HashMap<ValueId, IrType>,
    ev: &mut Evidence,
    catalog: bool,
    structs: &[StructDef],
) -> bool {
    let mut changed = false;
    for (id, binding) in func.bindings.iter() {
        if uses.is_unused(id) && expr_effects(&binding.expr).is_pure_total() {
            continue;
        }
        match &binding.expr {
            // Numeric arithmetic: both operands share the numeric type. A
            // bitwise op that involves a logical type (`address & 255`) is a
            // tag extraction, not shared-type arithmetic — so only a
            // *numeric* base propagates; a logical base is never forced onto
            // an operand.
            //
            // Nor is a number forced onto a `bool` operand. Wasm has no
            // `bool`: a test yields the `i32` `0` or `1`, and whatever
            // computes with it computes with that word — `flag & 1`,
            // `i + (i < n)`. The arithmetic says what the word is, not that
            // the value is an integer; read as evidence it conflicts the
            // `bool` and the flag loses its type.
            Expr::Binary { op, lhs, rhs } if is_arithmetic(*op) => {
                if let Some(base) = numeric_base(types.get(lhs), types.get(rhs)) {
                    for operand in [lhs, rhs] {
                        if base_of(types.get(operand)) == Some(KnownType::Bool) {
                            continue;
                        }
                        changed |= improve(types, ev, *operand, IrType::Inferred(base.clone()));
                    }
                }
            }
            // A join's limbs are the two 64-bit halves of one value —
            // that is what the construct means, so it types them
            // whatever produced them. Without it a limb the pipeline
            // never recovered is emitted as an untyped `todo!()`, which
            // Rust reads as `()`, and the cast the join renders does not
            // compile.
            Expr::WideJoin { lo, hi } => {
                changed |= improve(types, ev, *lo, IrType::Inferred(KnownType::I64));
                changed |= improve(types, ev, *hi, IrType::Inferred(KnownType::I64));
            }
            // Comparison: the two operands share one type (the result is
            // `bool`, handled forward). Logical types compare
            // (`addr == addr`), so this is not gated on `is_numeric`.
            Expr::Binary { op, lhs, rhs } if is_comparison(*op) => {
                if let Some(base) = base_of(types.get(lhs)).or_else(|| base_of(types.get(rhs))) {
                    changed |= improve(types, ev, *lhs, IrType::Inferred(base.clone()));
                    changed |= improve(types, ev, *rhs, IrType::Inferred(base));
                }
            }
            // A vec whose recovered elements disagree is a `Vec<Val>` —
            // that is the only element type they all satisfy — so each of
            // them is a `Val`. Only the ones nothing has typed take it:
            // `refines_val` keeps `Val` from displacing a named type, so a
            // `Symbol, Address, Address` vec types nothing and a
            // `?, Address, Address` one types the `?`.
            //
            // Without this the untyped element stays untyped, is *emitted*
            // as a `Val` because that is what the hole policy names it,
            // and a helper declaring it that way is handed a `Symbol` by
            // its caller. The conversion belongs after this, not instead
            // of it.
            Expr::Semantic(SemanticOp::Known(KnownOp::VecNew {
                elements: Some(values),
                ..
            })) if disagree(values, types) => {
                for v in values {
                    changed |= improve(types, ev, *v, IrType::Inferred(KnownType::Val));
                }
            }
            // Host-call arguments and conversions: the recovered op's ABI
            // *pins* these operand types authoritatively — `val_encode<u32>`'s
            // argument IS a `u32`, `require_auth`'s receiver IS an `Address`.
            // They are `Known`, so they win over the weak arithmetic
            // operand-share guess (a `u32` that is also bit-shifted to build a
            // `Val` stays a `u32`, it does not become a conflict → `Unknown`).
            Expr::Semantic(SemanticOp::Known(op)) => {
                let pinned = semantic_arg_types(op);
                for (arg, ty) in pinned.iter().cloned() {
                    // A shadow-stack address handed to the host as a
                    // `U32Val` (the SDK's buffer pointers) is `ptr as u32`
                    // there; the address itself stays the wasm word every
                    // other use of it computes in.
                    if matches!(op, KnownOp::ValEncodeSmall { .. }) && is_frame_address(func, arg) {
                        continue;
                    }
                    changed |= improve(types, ev, arg, IrType::Known(ty));
                }
                // The object kind the host's catalog fixes for the rest —
                // only where nothing better is said ([`catalog_object_args`]).
                // A bytes op's operand already named `Val` is the value the
                // SDK's fixed-width decode checks the tag and length of, and
                // keeps that name ([`catalog_object_args`]).
                let refines_val = !matches!(op, KnownOp::BufOp { .. });
                for (arg, ty) in catalog_object_args(op) {
                    if !catalog
                        || pinned.iter().any(|(p, _)| *p == arg)
                        || base_of(types.get(&arg)).is_some_and(|have| have != KnownType::Val || !refines_val)
                    {
                        continue;
                    }
                    changed |= improve(types, ev, arg, IrType::Known(ty));
                }
            }
            // A copy is its source: a return encode collapsed onto a `Use`
            // is typed by the ABI, a receiver by `require_auth`, and the
            // value either copies is that type. Three cases only:
            //
            // - a number naming an untyped source, or settling the 32-bit
            //   word's sign;
            // - anything naming a source typed only `Val` — the host's
            //   settled weakest statement, which a named type refines
            //   ([`refines_val`]): a storage read used as an `Address`.
            //
            // A source with a type of its own keeps it: a collapse can fold
            // a widening — a `u64` returned where `u128` is declared — and
            // there the copy's type is the conversion's. And a non-number
            // does not name an untyped source: untyped *this round* is not
            // untyped, and a source typed later from its own producer then
            // conflicts with the guess and loses its type altogether.
            Expr::Use(source) => {
                if let Some(base) = base_of(types.get(&id)).filter(|b| *b != KnownType::Val) {
                    let fits = match base_of(types.get(source)) {
                        None => base.is_numeric(),
                        Some(KnownType::Val) => true,
                        // A `Vec<?>` the copy names `Vec<T>`: one value, the
                        // element type less said about it, not a conversion.
                        Some(have @ KnownType::Vec(_)) => {
                            have != base && merge_partial(&have, &base).as_ref() == Some(&base)
                        }
                        Some(have) => unsigned_word(&have, &base).is_some(),
                    };
                    if fits {
                        changed |= improve(types, ev, *source, IrType::Inferred(base));
                    }
                }
            }
            // A merge's arm known only as `Vec<?>` is the merge's `Vec<T>`:
            // the arms are the values of one variable, and an unknown
            // element type is less said about it, not a different type
            // ([`merge_partial`]). Only that arm: a named element is left
            // to stand or conflict on its own evidence.
            Expr::Phi { incoming } => {
                if let Some(merged @ KnownType::Vec(_)) = base_of(types.get(&id)) {
                    for (_, arm) in incoming {
                        let Some(have @ KnownType::Vec(_)) = base_of(types.get(arm)) else {
                            continue;
                        };
                        if have != merged && merge_partial(&have, &merged).as_ref() == Some(&merged) {
                            changed |= improve(types, ev, *arm, IrType::Inferred(merged.clone()));
                        }
                    }
                }
                // An untyped arm read from memory in fewer than 64 bits is a
                // number — no `Val` fits in it — and the merge's number: the
                // arms are the values of one variable. Only such a read,
                // which nothing else will ever type: its own opcode names
                // only the 32-bit word ([`infer_expr`]).
                if let Some(merged) = base_of(types.get(&id)).filter(is_machine_word) {
                    for (_, arm) in incoming {
                        if base_of(types.get(arm)).is_none() && is_narrow_load(func, *arm) {
                            changed |= improve(types, ev, *arm, IrType::Inferred(merged.clone()));
                        }
                    }
                }
            }
            // A struct literal's field holds the field's declared type: the
            // contract's own declaration says so, and the literal puts the
            // value there. Only a value nothing has named, or named only
            // `Val` — a field read back from a frame slot or a helper's
            // `Val` result. A value with a type of its own keeps it, and a
            // disagreement stays visible rather than being overwritten.
            Expr::Struct { fields } => {
                let Some(KnownType::UserDefined(ty)) = base_of(types.get(&id)) else {
                    continue;
                };
                let Some(def) = structs.iter().find(|s| s.id == ty) else {
                    continue;
                };
                for (name, value) in fields {
                    let Some(declared) = def
                        .fields
                        .iter()
                        .find(|f| f.name == *name)
                        .and_then(|f| known_of_type_ref(&f.ty))
                    else {
                        continue;
                    };
                    if declared == KnownType::Val
                        || base_of(types.get(value)).is_some_and(|have| have != KnownType::Val)
                    {
                        continue;
                    }
                    changed |= improve(types, ev, *value, IrType::Inferred(declared));
                }
            }
            // Each component is the tuple's declared slot.
            Expr::Tuple { items } => {
                if let Some(KnownType::Tuple(slots)) = base_of(types.get(&id))
                    && slots.len() == items.len()
                {
                    for (item, slot) in items.iter().zip(slots) {
                        if let Some(base) = base_of(Some(&slot)) {
                            changed |= improve(types, ev, *item, IrType::Inferred(base));
                        }
                    }
                }
            }
            // The fallback stands in for the payload, so it is one.
            Expr::UnwrapOr { value, default } => {
                if let Some(KnownType::Option(payload)) = base_of(types.get(value))
                    && let Some(base) = base_of(Some(payload.as_ref()))
                {
                    changed |= improve(types, ev, *default, IrType::Inferred(base));
                }
            }
            _ => {}
        }
    }
    changed
}

/// One of the four integer words a wasm value is.
fn is_machine_word(k: &KnownType) -> bool {
    matches!(k, KnownType::I32 | KnownType::U32 | KnownType::I64 | KnownType::U64)
}

/// A memory read narrower than 64 bits, widened to the 64-bit word.
fn is_narrow_load(func: &HighFunction, value: ValueId) -> bool {
    matches!(
        func.bindings.get(value).map(|b| &b.expr),
        Some(Expr::Load { width, ty: IrType::Known(KnownType::I64), .. }) if width.bytes() < 8
    )
}

/// Whether `value` is an address in the shadow-stack frame: an offset from
/// `global.get 0` minus the frame size.
fn is_frame_address(func: &HighFunction, value: ValueId) -> bool {
    let (base, _) = crate::dataflow::canon_addr(func, value);
    let global = |v: ValueId| {
        matches!(func.bindings.get(resolve_use(func, v)).map(|b| &b.expr), Some(Expr::GlobalGet { index: 0 }))
    };
    match func.bindings.get(base).map(|b| &b.expr) {
        Some(Expr::GlobalGet { index: 0 }) => true,
        Some(Expr::Binary { op: BinaryOp::Sub, lhs, .. }) => global(*lhs),
        _ => false,
    }
}

/// `x + 1`, `x - 1`, `x * 2` on an `x` whose numeric type is proven: that
/// type, proven too. A bare literal takes its type from the other operand
/// in Rust, so the sum is the operand's type whatever word the wasm
/// computed it in — and only a proven candidate displaces the word the
/// lowering seeded (`count + 1` stayed the `i32` it was added in).
///
/// Only the three operators that offset a number. A mask or a shift is
/// where the wasm word is the type the source meant.
fn offset_of_known(
    func: &HighFunction,
    op: BinaryOp,
    lhs: ValueId,
    rhs: ValueId,
    types: &HashMap<ValueId, IrType>,
) -> Option<IrType> {
    if !matches!(op, BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul) {
        return None;
    }
    let literal = |v: ValueId| matches!(func.bindings.get(resolve_use(func, v)).map(|b| &b.expr), Some(Expr::Literal(_)));
    let proven = |v: ValueId| match types.get(&v) {
        Some(IrType::Known(k)) if k.is_numeric() => Some(IrType::Known(k.clone())),
        _ => None,
    };
    match (literal(lhs), literal(rhs)) {
        (false, true) => proven(lhs),
        (true, false) => proven(rhs),
        _ => None,
    }
}

/// The `u32` a small decode of an integer enum yields: its discriminant.
/// See "An integer enum's decoded discriminant" in the module doc.
fn discriminant_of(value: ValueId, types: &HashMap<ValueId, IrType>, int_enums: &HashSet<TypeId>) -> Option<IrType> {
    match base_of(types.get(&value))? {
        KnownType::UserDefined(id) if int_enums.contains(&id) => Some(IrType::Inferred(KnownType::U32)),
        _ => None,
    }
}

/// A candidate type for a binding derived from its own expression, or
/// `None` to leave it to seeding / backward rules.
fn infer_expr(expr: &Expr, types: &HashMap<ValueId, IrType>) -> Option<IrType> {
    match expr {
        // Proven.
        Expr::Literal(lit) => literal_type(lit).map(IrType::Known),
        // Identity alias: preserve the operand's type and certainty.
        Expr::Use(v) => types.get(v).cloned().filter(|t| !matches!(t, IrType::Unknown(_))),
        Expr::Unary { op, value } => unary_result(*op, types.get(value)),
        Expr::Binary { op, lhs, rhs } => binary_result(*op, types.get(lhs), types.get(rhs)),
        Expr::Phi { incoming } => phi_join(incoming, types),
        // A host call no recogniser named still has the catalog's return
        // type. Only an object: an object's handle *is* its `Val`, while a
        // small scalar result arrives encoded and is decoded after.
        Expr::Semantic(SemanticOp::Unknown { host_module, host_fn, .. }) => {
            let call = crate::host_calls::resolve(host_module, host_fn)?;
            Some(IrType::Known(match call.return_type {
                "AddressObject" => KnownType::Address,
                "VecObject" => KnownType::Vec(Box::new(IrType::Unknown(sordec_common::UnknownReason::InsufficientEvidence))),
                "MapObject" => KnownType::Map(
                    Box::new(IrType::Unknown(sordec_common::UnknownReason::InsufficientEvidence)),
                    Box::new(IrType::Unknown(sordec_common::UnknownReason::InsufficientEvidence)),
                ),
                "BytesObject" => KnownType::Bytes,
                "StringObject" => KnownType::String,
                _ => return None,
            }))
        }
        // A `select` is a value, whatever the lowering could not name it
        // as: it yields one of its two arms, so when they agree on a type
        // it has that type. Without this the binding is untyped, the
        // emitter cannot annotate the hole it renders, and the `let` falls
        // back to `()` — which nothing can be compared with.
        Expr::Unknown { op_kind: WasmOpcodeKind::Select, args, .. } if args.len() == 3 => {
            let (a, b) = (base_of(types.get(&args[0]))?, base_of(types.get(&args[1]))?);
            (a == b).then_some(IrType::Inferred(a))
        }
        // `Some(x)` is an `Option` of whatever `x` is; several components
        // make a tuple payload. `None` says nothing of its payload, so it
        // takes its type from the merge it flows into (`phi_join` skips an
        // untyped arm) rather than voting `Option<?>` against `Some`.
        // An `Option` even before its payload is typed: what it holds can
        // be `Unknown` and named later (`merge_partial`), but whether it is
        // an `Option` is not in doubt, and a call or merge typed as anything
        // else does not have `is_some`.
        Expr::Optional { payload: Some(values) } => {
            let items: Vec<IrType> = values
                .iter()
                .map(|v| {
                    base_of(types.get(v))
                        .map_or(IrType::Unknown(sordec_common::UnknownReason::InsufficientEvidence), IrType::Inferred)
                })
                .collect();
            let payload = match items.as_slice() {
                [one] => one.clone(),
                _ => IrType::Inferred(KnownType::Tuple(items)),
            };
            Some(IrType::Inferred(KnownType::Option(Box::new(payload))))
        }
        Expr::Optional { payload: None } => None,
        Expr::Tuple { items } => Some(IrType::Inferred(KnownType::Tuple(
            items
                .iter()
                .map(|v| {
                    base_of(types.get(v))
                        .map_or(IrType::Unknown(sordec_common::UnknownReason::InsufficientEvidence), IrType::Inferred)
                })
                .collect(),
        ))),
        Expr::IsSome { .. } => Some(IrType::Known(KnownType::Bool)),
        Expr::Unwrap { value, index, arity } => {
            let KnownType::Option(payload) = base_of(types.get(value))? else {
                return None;
            };
            if *arity == 1 {
                return base_of(Some(payload.as_ref())).map(IrType::Inferred);
            }
            let KnownType::Tuple(items) = base_of(Some(payload.as_ref()))? else {
                return None;
            };
            base_of(items.get(*index as usize)).map(IrType::Inferred)
        }
        // At the payload's own certainty: the value *is* the payload, so a
        // payload the ABI proved is not outvoted by the word of the literal
        // it is then added to.
        Expr::UnwrapOr { value, .. } => {
            let KnownType::Option(payload) = base_of(types.get(value))? else {
                return None;
            };
            (!matches!(payload.as_ref(), IrType::Unknown(_))).then(|| payload.as_ref().clone())
        }
        // Two limbs read as one integer. `i128` is the guess only because
        // it is what Soroban contracts overwhelmingly use; a recognizer
        // that knows the value is a `u128` plants `Known` and wins.
        Expr::WideJoin { .. } => Some(IrType::Inferred(KnownType::I128)),
        // A vec whose elements are recovered knows its element type: the
        // elements have one. The recognizer types a `vec_new` as
        // `Vec<Unknown>` because at recognition the buffer is still a
        // buffer, and `Unknown` renders as `Val` — so the *type* said
        // `Vec<Val>` while the emitted `vec![e, sym]` was a `Vec<Symbol>`,
        // and a helper returning it did not compile. Only when every
        // element agrees: a mixed vec really is a `Vec<Val>`.
        Expr::Semantic(SemanticOp::Known(KnownOp::VecNew {
            elements: Some(values),
            ..
        })) if !values.is_empty() => {
            let first = base_of(types.get(values.first()?))?;
            values
                .iter()
                .all(|v| base_of(types.get(v)) == Some(first.clone()))
                .then(|| IrType::Inferred(KnownType::Vec(Box::new(IrType::Inferred(first)))))
        }
        // A vec op that hands back the vec it was given — `push_back`,
        // `del`, `slice`, … — hands back that vec's type: the SDK's
        // `v.push_back(x)` is `v = vec_push_back(v, x)`, one variable before
        // and after. The host types the result only `Vec<?>`, which left a
        // loop that pushes onto a `Vec<u32>` merging it with a `Vec<?>`.
        Expr::Semantic(SemanticOp::Known(KnownOp::VecOp { kind, args })) if returns_receiver(*kind) => {
            let ty @ KnownType::Vec(_) = base_of(types.get(args.first()?))? else {
                return None;
            };
            Some(IrType::Inferred(ty))
        }
        // A 32-bit load is the word its opcode produced, and no `Val` (always
        // 64 bits) fits in it — the same fact a 32-bit parameter carries.
        // `Inferred`, so `u32` evidence settles its sign as for any word.
        Expr::Load { ty: IrType::Known(KnownType::I32), .. } => Some(IrType::Inferred(KnownType::I32)),
        // Semantic ops are typed by the recognizers (host ABI); leave them.
        // Store/GlobalGet/IndirectCall/Unknown, and 64-bit loads (which may
        // hold a `Val`), stay for later waves.
        _ => None,
    }
}

/// Whether a vec op's result is a vec of its first operand's type: the
/// edits the SDK writes as `&mut self` methods, which store the result back
/// into the receiver, and `slice`, which returns `Self`. `append`'s second
/// operand is another vec of that type, but the receiver is the first.
fn returns_receiver(kind: sordec_ir::VecOpKind) -> bool {
    use sordec_ir::VecOpKind as K;
    matches!(
        kind,
        K::Put | K::Del | K::PushFront | K::PopFront | K::PushBack | K::PopBack | K::Insert | K::Append | K::Slice
    )
}

/// Whether two of these values carry *different* recovered bases.
///
/// An untyped value is not a disagreement — it has said nothing. Two named
/// and different ones are, and that is what makes the vec a `Vec<Val>`.
fn disagree(values: &[ValueId], types: &HashMap<ValueId, IrType>) -> bool {
    let named: Vec<KnownType> = values.iter().filter_map(|v| base_of(types.get(v))).collect();
    named.windows(2).any(|w| w[0] != w[1])
}

/// Join the incoming edges of a phi: `Inferred(T)` when every *resolved*
/// edge agrees on base `T`, else `None` (arms disagree — honestly
/// `Unknown`).
///
/// An unresolved edge is **skipped, not fatal**. Bailing on the first
/// `Unknown` is the wrong lattice join: it lets one unrecovered arm
/// discard what every other arm proved, and a phi is exactly where arms
/// are unequally recovered. Measured on `phoenix-vesting`, 24 phis had a
/// `Known` incoming type and still came out `Unknown` for this reason —
/// nine of them `Known:I64`, ten `Known:I32`.
///
/// Leaving them `Unknown` is not the neutral choice it looks like,
/// because a slot must still be *declared* something: the Rust backend's
/// [`HolePolicy::unknown_type`] stands in `soroban_sdk::Val`, so the
/// binding is emitted as `let mut v160: Val;` and every
/// `v160 = 0i64;` assigning into it fails to compile. The choice is not
/// between guessing and not guessing — it is between the backend guessing
/// `Val` with no evidence and this join naming the type the resolved arms
/// actually carry.
///
/// The result stays `Inferred`, never `Known`: it is propagated from the
/// arms, and a recognizer that proves the type still outranks it.
fn phi_join(
    incoming: &[(sordec_common::BlockId, ValueId)],
    types: &HashMap<ValueId, IrType>,
) -> Option<IrType> {
    let mut agreed: Option<KnownType> = None;
    for (_, value) in incoming {
        let Some(base) = base_of(types.get(value)) else {
            continue; // unrecovered arm: no evidence, not counter-evidence
        };
        match &agreed {
            None => agreed = Some(base),
            Some(prev) if *prev == base => {}
            Some(prev) => agreed = Some(merge_partial(prev, &base)?), // or conflict
        }
    }
    agreed.map(IrType::Inferred)
}

/// [`phi_join`], with a constant arm taking the type the other arms agree
/// on when it fits.
///
/// A literal is typed by the wasm word it was loaded as, which is the
/// machine's choice and not a claim about the value: `unwrap_or(0) + 1`
/// folds its `None` arm to `1i64` while the `Some` arm is a `u32`. Read as
/// a vote, that constant conflicts the merge and it comes out untyped —
/// declared `Val`, assigned a `u32`. So the arms that are not constants
/// decide, and a constant agrees with them when its value fits.
///
/// When the other arms say nothing yet the constants are all there is — but
/// not while one of them is a helper's parameter in the first round
/// (`awaiting_callers`). A parameter is typed by what its callers pass, and
/// that is read only after a round; deciding before it is deciding on the
/// constant alone, and a type once written is never lowered. `2` beside a
/// `Symbol` parameter is the `Void` a buffer of `Val`s starts as, not an
/// `i64`: the merge must see the `Symbol` to see it holds neither type.
fn phi_join_with_constants(
    func: &HighFunction,
    incoming: &[(sordec_common::BlockId, ValueId)],
    types: &HashMap<ValueId, IrType>,
    awaiting_callers: bool,
) -> Option<IrType> {
    let constant = |v: ValueId| match func.bindings.get(v).map(|b| &b.expr) {
        Some(Expr::Literal(Literal::I32(n))) => Some(i128::from(*n)),
        Some(Expr::Literal(Literal::I64(n))) => Some(i128::from(*n)),
        Some(Expr::Literal(Literal::U32(n))) => Some(i128::from(*n)),
        Some(Expr::Literal(Literal::U64(n))) => Some(i128::from(*n)),
        _ => None,
    };
    let (constants, others): (Vec<_>, Vec<_>) =
        incoming.iter().copied().partition(|(_, v)| constant(*v).is_some());
    if constants.is_empty() || others.is_empty() {
        return phi_join(incoming, types);
    }
    // The other arms saying nothing yet — a loop counter's back edge, typed
    // only once its own merge is — leaves the constants as all there is.
    let Some(decided) = phi_join(&others, types) else {
        let parameter = |v: ValueId| func.signature.is_none() && func.params.contains(&resolve_use(func, v));
        if awaiting_callers && others.iter().any(|(_, v)| parameter(*v)) {
            return None;
        }
        return phi_join(incoming, types);
    };
    let Some(k) = base_of(Some(&decided)) else {
        return phi_join(incoming, types);
    };
    let word = |v: ValueId| Slot::witness(types.get(&v));
    if constants.iter().all(|(_, v)| constant(*v).is_some_and(|n| fits_constant(&k, n, &word(*v)))) {
        Some(decided)
    } else {
        phi_join(incoming, types)
    }
}

/// Whether a merge's arms, joined as `cand`, are the `Ok` payloads of the
/// `Result<T, E>` the merge already is.
///
/// A returned merge is typed by the spec's `Result<T, E>`, and the arms that
/// carry a `T` are its `Ok` values — the host reads a returned `T`'s
/// encoding as `Ok(t)`, and the emitter wraps such an arm as `Ok(..)`. So
/// the arms agreeing on `T` say less of the merge, not something else; read
/// as a conflict they took the merge's type away, and it was declared `Val`
/// while every arm assigned it a `T` or an error.
fn ok_arms_of(merge: Option<&IrType>, cand: &IrType) -> bool {
    match (base_of(merge), base_of(Some(cand))) {
        (Some(KnownType::Result(ok, _)), Some(arms)) => base_of(Some(ok.as_ref())) == Some(arms),
        _ => false,
    }
}

/// A loop counter whose bound is a `u32` is a `u32`.
///
/// `for i in 0..v.len()` keeps `i` in whatever word the wasm compares it
/// in, and a length decoded by an `i64.shr_u` makes that an `i64`: the
/// counter's start and step are `i64` literals and nothing else about it
/// says `u32` but the bound. Read as votes, those literals conflict with
/// the bound's comparison and the counter comes out untyped — `account`'s
/// signature loop declared `i: Val`, stepped with `+ 1i64`.
///
/// The shape is the induction variable: a phi whose constant arms are
/// non-negative, whose other arms are this phi plus a positive constant,
/// and which is compared `==` / `!=` with a `u32`. It runs from its start
/// up to that bound and stops there, so every value it takes is a `u32`.
fn counter_bounded_by_u32(
    func: &HighFunction,
    phi: ValueId,
    incoming: &[(sordec_common::BlockId, ValueId)],
    types: &HashMap<ValueId, IrType>,
) -> Option<IrType> {
    let literal = |v: ValueId| match func.bindings.get(resolve_use(func, v)).map(|b| &b.expr) {
        Some(Expr::Literal(Literal::I32(n))) => Some(i128::from(*n)),
        Some(Expr::Literal(Literal::I64(n))) => Some(i128::from(*n)),
        Some(Expr::Literal(Literal::U32(n))) => Some(i128::from(*n)),
        Some(Expr::Literal(Literal::U64(n))) => Some(i128::from(*n)),
        _ => None,
    };
    let step = |v: ValueId| match func.bindings.get(resolve_use(func, v)).map(|b| &b.expr) {
        Some(Expr::Binary { op: BinaryOp::Add, lhs, rhs }) => {
            let (lhs, rhs) = (resolve_use(func, *lhs), resolve_use(func, *rhs));
            (lhs == phi && literal(rhs).is_some_and(|n| n > 0))
                || (rhs == phi && literal(lhs).is_some_and(|n| n > 0))
        }
        _ => false,
    };
    let mut started = false;
    for &(_, v) in incoming {
        match literal(v) {
            Some(n) if n >= 0 => started = true,
            Some(_) => return None,
            None if step(v) => {}
            None => return None,
        }
    }
    if !started {
        return None;
    }
    let is_u32 = |v: ValueId| base_of(types.get(&resolve_use(func, v))) == Some(KnownType::U32);
    let bounded = func.bindings.iter().any(|(_, b)| match &b.expr {
        Expr::Binary { op: BinaryOp::Eq | BinaryOp::Ne, lhs, rhs } => {
            let (lhs, rhs) = (resolve_use(func, *lhs), resolve_use(func, *rhs));
            (lhs == phi && is_u32(rhs)) || (rhs == phi && is_u32(lhs))
        }
        _ => false,
    });
    bounded.then_some(IrType::Inferred(KnownType::U32))
}

fn unary_result(op: UnaryOp, operand: Option<&IrType>) -> Option<IrType> {
    match op {
        // Sign/bit flips preserve the operand's numeric type — but only a
        // numeric one. A bit-flip of a logical type is a raw-integer op, not
        // the logical type.
        UnaryOp::Neg | UnaryOp::Not | UnaryOp::BitNot | UnaryOp::Abs => {
            base_of(operand)
                .filter(KnownType::is_numeric)
                .map(IrType::Inferred)
        }
        // A bit count is the operand's own width in wasm — `i64.clz` is an
        // `i64` — and `u32` only in Rust's spelling of it. The IR carries
        // the wasm meaning and the emitter casts, the same division of
        // labour as `WideLo`/`WideHi` below. Typing it `u32` here instead
        // put the Rust return type on a value the next instruction
        // subtracts from an `i64`, and the cast had nowhere to come from.
        UnaryOp::Clz | UnaryOp::Ctz | UnaryOp::Popcnt => Some(IrType::Inferred(
            base_of(operand).filter(KnownType::is_numeric).unwrap_or(KnownType::U32),
        )),
        // `eqz` is a comparison wearing a unary opcode: whatever the
        // operand's width, the answer is a boolean. Typing it so is what
        // lets a nested `eqz(eqz(x))` render its outer half as `!…` rather
        // than a second `== 0` against a bool.
        UnaryOp::Eqz => Some(IrType::Inferred(KnownType::Bool)),
        // Float ops don't occur in Soroban; leave untyped.
        UnaryOp::Sqrt | UnaryOp::Floor | UnaryOp::Ceil | UnaryOp::Trunc => None,
        // A limb of a 128-bit value is the raw 64-bit word the wasm
        // carried; its signedness is not the wide value's.
        UnaryOp::WideLo | UnaryOp::WideHi => Some(IrType::Inferred(KnownType::I64)),
        // A width move keeps the operand's signedness where it has one: the
        // low half of a `u64` is a `u32`, a zero-extended `u32` a `u64`.
        UnaryOp::Wrap32 => Some(IrType::Inferred(match base_of(operand) {
            Some(KnownType::U32 | KnownType::U64) => KnownType::U32,
            _ => KnownType::I32,
        })),
        UnaryOp::ExtendU32 => Some(IrType::Inferred(match base_of(operand) {
            Some(KnownType::U32) => KnownType::U64,
            _ => KnownType::I64,
        })),
        UnaryOp::ExtendS32 => Some(IrType::Inferred(KnownType::I64)),
    }
}

fn binary_result(op: BinaryOp, lhs: Option<&IrType>, rhs: Option<&IrType>) -> Option<IrType> {
    if is_comparison(op) {
        return Some(IrType::Inferred(KnownType::Bool));
    }
    // Arithmetic / bitwise: the result is the *numeric* type of a numeric
    // operand. A bitwise op on a logical type (`address & 255`) extracts a
    // tag/integer, not the logical type, so a logical base never becomes the
    // result — it is left `Unknown` (or takes the numeric operand's type).
    numeric_base(lhs, rhs).map(IrType::Inferred)
}

/// ABI-pinned types of a recovered op's operands: the "host-call
/// arguments" and "conversions" Mo named. Only the unambiguous ones — an
/// address that must be an `Address`, a callee symbol, a scalar being
/// wrapped into a Val object. Ops whose operand types the ABI does not fix
/// return nothing (left to flow propagation, honestly).
fn semantic_arg_types(op: &KnownOp) -> Vec<(ValueId, KnownType)> {
    use KnownOp as K;
    match op {
        // Val encode: the packed value IS the tag's payload type — except
        // a wide one, whose small form packs only the low limb: the
        // `val_encode<i128>(lo)` beside `obj_from_i128_pieces(hi, lo)` is
        // handed an `i64`, and typing it `i128` mixed the limbs' arithmetic.
        K::ValEncodeSmall { ty, value } => {
            let limb = match ty {
                KnownType::I128 | KnownType::I256 => KnownType::I64,
                KnownType::U128 | KnownType::U256 => KnownType::U64,
                other => other.clone(),
            };
            vec![(*value, limb)]
        }
        // Auth: the receiver is an Address.
        K::RequireAuth { address } => vec![(*address, KnownType::Address)],
        K::RequireAuthForArgs { address, .. } => vec![(*address, KnownType::Address)],
        // Cross-contract: callee address + function symbol.
        K::InvokeContract { contract, function, .. }
        | K::TryInvokeContract { contract, function, .. } => {
            vec![(*contract, KnownType::Address), (*function, KnownType::Symbol)]
        }
        // Object conversions: the scalar side of a 1-arg `obj_from_*`.
        K::ValObject { kind, args } => obj_from_scalar_type(*kind)
            .and_then(|ty| args.first().map(|a| (*a, ty)))
            .into_iter()
            .collect(),
        // `ed25519_verify(&BytesN<32>, &Bytes, &BytesN<64>)`: the key and
        // the signature are fixed-width in the SDK's own signature. The
        // message is left alone — a `Bytes` there is as often a `BytesN`
        // the source converted, and typing it would contradict that.
        K::CryptoOp { kind: CryptoOpKind::VerifySigEd25519, args } => match args.as_slice() {
            [key, _message, signature] => {
                vec![(*key, KnownType::BytesN(32)), (*signature, KnownType::BytesN(64))]
            }
            _ => vec![],
        },
        _ => vec![],
    }
}

/// The object type the host catalog declares for each operand of a crypto
/// or bytes call: a `BytesObject` operand is a `Bytes`, a `VecObject` one a
/// `Vec`.
///
/// Objects only. An object's handle *is* the `Val` the host receives, so
/// the operand is that object whatever produced it — the same reason
/// [`infer_expr`] types an unnamed host call's object result. A small
/// scalar (`U32Val`, `U256Val`) arrives encoded, and the operand is the
/// encoding, not the number. The caller applies these only to an operand
/// nothing has named, or named only `Val`: the catalog says the object's
/// kind, not its length, so a `BytesN<32>` handed to `sha256` stays one.
///
/// A bytes op's operand named `Val` keeps that name. `bytes_len` is how the
/// SDK's `BytesN<N>` decode checks a `Val`'s length before the source holds
/// it as the fixed-width type: the helper takes the `Val` its callers hand
/// it, and returns it as `Some(BytesN<N>)` once the length agrees. Naming
/// that parameter `Bytes` contradicts both its callers and the width its
/// other use carries, which the catalog cannot see.
fn catalog_object_args(op: &KnownOp) -> Vec<(ValueId, KnownType)> {
    let (module, name, args) = match op {
        KnownOp::CryptoOp { kind, args } => ("c", crate::val_abi::crypto_kind_name(*kind), args),
        KnownOp::BufOp { kind, args } => ("b", crate::val_abi::buf_kind_name(*kind), args),
        _ => return vec![],
    };
    let Some(call) = crate::host_calls::all().iter().find(|c| c.module == module && c.friendly_name == name) else {
        return vec![];
    };
    if call.arg_types.len() != args.len() {
        return vec![];
    }
    args.iter()
        .zip(call.arg_types)
        .filter_map(|(arg, ty)| {
            let ty = match *ty {
                "BytesObject" => KnownType::Bytes,
                "VecObject" => KnownType::Vec(Box::new(IrType::Unknown(
                    sordec_common::UnknownReason::InsufficientEvidence,
                ))),
                _ => return None,
            };
            Some((*arg, ty))
        })
        .collect()
}

/// The scalar operand type of a single-argument `obj_from_*` conversion, or
/// `None` for the multi-piece / `obj_to_*` forms (whose operand is itself a
/// Val handle, not an informative scalar).
fn obj_from_scalar_type(kind: ValObjectKind) -> Option<KnownType> {
    use ValObjectKind as K;
    Some(match kind {
        K::ObjFromU64 | K::TimepointObjFromU64 | K::DurationObjFromU64 => KnownType::U64,
        K::ObjFromI64 => KnownType::I64,
        _ => return None,
    })
}

fn is_arithmetic(op: BinaryOp) -> bool {
    use BinaryOp as B;
    matches!(
        op,
        B::Add
            | B::Sub
            | B::Mul
            | B::Div
            | B::DivU
            | B::Rem
            | B::RemU
            | B::BitAnd
            | B::BitOr
            | B::BitXor
            | B::Shl
            | B::Shr
            | B::ShrU
            | B::Rotl
            | B::Rotr
    )
}

fn is_comparison(op: BinaryOp) -> bool {
    op.is_comparison() || op == BinaryOp::MulOverflows
}

/// The concrete Soroban type of an integer/bool/unit literal, or `None` for
/// floats (absent in Soroban).
fn literal_type(lit: &Literal) -> Option<KnownType> {
    Some(match lit {
        Literal::I32(_) => KnownType::I32,
        Literal::I64(_) => KnownType::I64,
        Literal::U32(_) => KnownType::U32,
        Literal::U64(_) => KnownType::U64,
        Literal::Bool(_) => KnownType::Bool,
        Literal::Unit => KnownType::Unit,
        Literal::Symbol(_) => KnownType::Symbol,
        Literal::String(_) => KnownType::String,
        Literal::Bytes(_) => KnownType::Bytes,
        Literal::F32(_) | Literal::F64(_) => return None,
    })
}

// ---------------------------------------------------------------------
// Inter-procedural signature table
// ---------------------------------------------------------------------

/// Accumulated evidence for one signature slot — a parameter position or a
/// return component.
///
/// A three-point lattice, joined rather than raised. `Bottom` and
/// `Conflict` both mean "no type to apply", but they are different facts
/// and keeping them apart is what lets the join be monotone: once a slot is
/// `Conflict` no further witness can talk it back into a concrete type.
#[derive(Clone, PartialEq, Debug)]
enum Slot {
    /// No witness has said anything yet.
    Bottom,
    /// Every witness so far agrees on this type.
    Agreed(KnownType),
    /// Witnesses disagree; there is no sound single type.
    Conflict,
}

impl Slot {
    /// Least upper bound. `Bottom` is the identity, `Conflict` absorbing,
    /// and two different agreed types conflict.
    fn join(self, other: Slot) -> Slot {
        self.join_with(other, false)
    }

    /// [`join`](Self::join), for witnesses that are values of one variable
    /// — a function's return sites, a merge's arms — or, with `callers`,
    /// the arguments separate callers pass one parameter. Two things differ
    /// between them.
    ///
    /// `Vec<?>` and `Vec<T>` are one type only for one variable
    /// ([`merge_partial_with`]). Each caller builds its own vec, and a
    /// `Vec<?>` there is often the `Vec<Val>` a client call's arguments
    /// are, which merging into another caller's `Vec<Address>` would
    /// declare the parameter as, and leave that caller passing a
    /// `Vec<Val>` to it.
    ///
    /// And a `BytesN<N>` beside a `Bytes` is a `Bytes` parameter only
    /// across callers: a call is where the SDK's `From<BytesN<N>> for
    /// Bytes` widens one, and the emitter writes that conversion there.
    /// Nothing widens a merge's arm or a returned value.
    fn join_with(self, other: Slot, callers: bool) -> Slot {
        match (self, other) {
            (Slot::Agreed(KnownType::Bytes), Slot::Agreed(KnownType::BytesN(_)))
            | (Slot::Agreed(KnownType::BytesN(_)), Slot::Agreed(KnownType::Bytes))
                if callers =>
            {
                Slot::Agreed(KnownType::Bytes)
            }
            (Slot::Conflict, _) | (_, Slot::Conflict) => Slot::Conflict,
            (Slot::Bottom, s) | (s, Slot::Bottom) => s,
            // `Val` is the lattice's top, not a leaf. Every host object and
            // every small value *is* a `Val`, so a witness saying `Val`
            // says nothing against one that names a type — and the host ABI
            // says `Val` about everything it hands back. Treating that as a
            // disagreement conflicts the slot, and a conflicted slot
            // witnesses nothing, so neither side ever learns from the
            // other.
            (Slot::Agreed(KnownType::Val), s @ Slot::Agreed(_))
            | (s @ Slot::Agreed(_), Slot::Agreed(KnownType::Val)) => s,
            (Slot::Agreed(a), Slot::Agreed(b)) => match merge_partial_with(&a, &b, !callers) {
                Some(merged) => Slot::Agreed(merged),
                None => Slot::Conflict,
            },
        }
    }

    /// One witness's contribution. An `Unknown` witness is *no evidence*
    /// (`Bottom`), never a conflict — it has not spoken.
    fn witness(ty: Option<&IrType>) -> Slot {
        match base_of(ty) {
            Some(k) => Slot::Agreed(k),
            None => Slot::Bottom,
        }
    }

    /// The type to apply to a binding, or `None` for both "nothing known"
    /// and "conflicting" — the honest answer is `Unknown` either way.
    fn to_ir(&self, certainty: Certainty) -> Option<IrType> {
        match self {
            Slot::Agreed(k) => Some(match certainty {
                Certainty::Known => IrType::Known(k.clone()),
                Certainty::Inferred => IrType::Inferred(k.clone()),
            }),
            Slot::Bottom | Slot::Conflict => None,
        }
    }
}

/// One function's inter-procedural signature: types by parameter position
/// and by return component.
#[derive(Clone, Default, PartialEq, Debug)]
struct FnSig {
    params: Vec<Slot>,
    returns: Vec<Slot>,
    /// A helper's one return value as the emitter declares it — the type of
    /// the value at its first computed return site — when that type is
    /// proven. A call to it is then exactly that, whatever the slots say:
    /// it is what the reconstruction's own signature hands back.
    declared: Option<IrType>,
}

/// Signature evidence for every function in the module.
type SigTable = HashMap<FuncId, FnSig>;

/// The common arity of `func`'s value-carrying return sites, or `None` when
/// there are none or they disagree.
///
/// Disagreement means components cannot be addressed positionally, so the
/// honest answer is to contribute no return information at all rather than
/// index into rows of different widths. `HighFunction::returns` records
/// sites faithfully, including 0-value ones, which is why the empty sites
/// are skipped rather than counted.
fn return_arity(func: &HighFunction) -> Option<usize> {
    let mut arity: Option<usize> = None;
    for site in func.returns.iter().filter(|s| !s.is_empty()) {
        match arity {
            None => arity = Some(site.len()),
            Some(n) if n == site.len() => {}
            Some(_) => return None,
        }
    }
    arity
}

/// The proven type of a helper's one returned value, read from the site
/// the emitter declares its return type from: the first that returns
/// something other than a constant. A helper returning only constants has
/// none — a literal's type is the wasm word it was loaded as, not a proof.
fn declared_return(func: &HighFunction) -> Option<IrType> {
    let constant = |v: &ValueId| matches!(func.bindings.get(*v).map(|b| &b.expr), Some(Expr::Literal(_)));
    let site = func.returns.iter().find(|vals| !vals.is_empty() && !vals.iter().all(constant))?;
    let [one] = site.as_slice() else {
        return None;
    };
    match &func.bindings.get(*one)?.ty {
        known @ IrType::Known(_) => Some(known.clone()),
        _ => None,
    }
}

/// The table's starting point: `contractspecv0` types where a function has
/// a signature, `Bottom` everywhere else.
///
/// Re-cloned at the head of every recomputation, which is what keeps ABI
/// slots authoritative and non-ABI slots recomputed from scratch.
fn seed_signatures(ir: &HighIr) -> SigTable {
    let mut table = SigTable::new();
    for func in &ir.functions {
        let mut sig = FnSig {
            params: vec![Slot::Bottom; func.params.len()],
            returns: vec![Slot::Bottom; return_arity(func).unwrap_or(0)],
            declared: None,
        };
        if let Some(spec) = &func.signature {
            for (slot, input) in sig.params.iter_mut().zip(&spec.inputs) {
                if let Some(k) = type_ref_base(&input.ty) {
                    *slot = Slot::Agreed(k);
                }
            }
            for (slot, out) in sig.returns.iter_mut().zip(&spec.outputs) {
                if let Some(k) = type_ref_base(out) {
                    *slot = Slot::Agreed(k);
                }
            }
        }
        table.insert(func.id, sig);
    }
    table
}

/// Whether `v` is the result of a call.
fn is_call(func: &HighFunction, v: ValueId) -> bool {
    matches!(func.bindings.get(resolve_use(func, v)).map(|b| &b.expr), Some(Expr::Call { .. }))
}

/// Recompute every non-ABI slot as a join over its witnesses.
///
/// Returns are witnessed by the function's own return sites; parameters by
/// every call site in the module that names it. Functions carrying a
/// `contractspecv0` signature keep the seeded ABI types untouched.
fn recompute_signatures(ir: &HighIr, seed: &SigTable, encoders: &EncoderTable) -> SigTable {
    let mut table = seed.clone();
    let used_as = result_uses(ir, &table);

    for func in &ir.functions {
        if func.signature.is_some() {
            continue; // ABI is proven; call sites do not get a vote.
        }
        let Some(entry) = table.get_mut(&func.id) else {
            continue;
        };
        let arity = entry.returns.len();
        if arity == 0 {
            continue;
        }
        let mut slots = vec![Slot::Bottom; arity];
        // Constants vote last here too: `return 0i32` beside `return found`
        // is a `bool` function whose constant was loaded as a wasm word.
        let mut held: Vec<Vec<(i128, Slot)>> = vec![Vec::new(); arity];
        // A call not typed yet has not spoken, but it will: its result is
        // typed from the callee once the callee's own sites settle, a
        // round or more later. Until then the constants do not decide
        // alone — `return 0i32` beside `return check(x)` would
        // fix the slot as the word before `check` is known to return a
        // `bool`, and the two then conflict for good.
        let mut pending = vec![false; arity];
        for site in func.returns.iter().filter(|s| s.len() == arity) {
            for (index, (slot, value)) in slots.iter_mut().zip(site).enumerate() {
                let witness = Slot::witness(func.bindings.get(*value).map(|b| &b.ty));
                if let Some(n) = int_constant(func, *value) {
                    held[index].push((n, witness));
                    continue;
                }
                if witness == Slot::Bottom && is_call(func, *value) {
                    pending[index] = true;
                }
                *slot = std::mem::replace(slot, Slot::Bottom).join(witness);
            }
        }
        for ((slot, consts), pending) in slots.iter_mut().zip(held).zip(pending) {
            let agrees = matches!(&*slot, Slot::Agreed(k) if consts.iter().all(|(n, w)| fits_constant(k, *n, w)));
            if !agrees && !(pending && *slot == Slot::Bottom) {
                for (_, witness) in consts {
                    *slot = std::mem::replace(slot, Slot::Bottom).join(witness);
                }
            }
        }
        // ...and by what the callers do with the result. Without this the
        // return side is witnessed in one direction only: a helper whose
        // body yields a `Val` keeps declaring `Val` however many call sites
        // treat it as an `Address`, and settling the *parameter* side alone
        // only moves the mismatch one line up the caller.
        if let Some(used) = used_as.get(&func.id) {
            for (slot, witness) in slots.iter_mut().zip(used) {
                *slot = std::mem::replace(slot, Slot::Bottom).join(witness.clone());
            }
        }
        // A component a helper returns the encode of its argument in, on
        // every path, is that encode: a `Val`, whatever a caller does with
        // it. A caller treating it as the number is the mistake, not
        // evidence ("An encoded number is not the number").
        if let Some(encoded) = encoders.slots(func.id) {
            for (slot, encode) in slots.iter_mut().zip(encoded) {
                if encode.is_some() {
                    *slot = Slot::Agreed(KnownType::Val);
                }
            }
        }
        entry.returns = slots;
        entry.declared = declared_return(func);
    }

    // Parameters: one pass over every call in the module.
    let mut evidence: HashMap<FuncId, Vec<Slot>> = ir
        .functions
        .iter()
        .filter(|f| f.signature.is_none())
        .map(|f| {
            // Seeded from what the callee's own body proved, not `Bottom`.
            // A helper that calls `require_auth` on its first parameter has
            // proven it an `Address`, and no caller can supply that — they
            // hold the `Val` the host gave them.
            let own: Vec<Slot> = f
                .params
                .iter()
                .map(|p| Slot::witness(f.bindings.get(*p).map(|b| &b.ty)))
                .collect();
            (f.id, own)
        })
        .collect();
    // Positions some caller hands a value that can only cross a call as a
    // `Val` — see the conflict rule below.
    let mut val_only: HashSet<(FuncId, usize)> = HashSet::new();
    // Constant arguments, held back until the other callers have spoken.
    let mut constants: HashMap<(FuncId, usize), Vec<(i128, Slot)>> = HashMap::new();
    for caller in &ir.functions {
        for (_, binding) in caller.bindings.iter() {
            let Expr::Call { target, args } = &binding.expr else {
                continue;
            };
            let Some(slots) = evidence.get_mut(target) else {
                continue;
            };
            for (index, (slot, arg)) in slots.iter_mut().zip(args).enumerate() {
                let ty = caller.bindings.get(*arg).map(|b| &b.ty);
                if base_of(ty).is_some_and(|k| crosses_only_as_val(&k)) {
                    val_only.insert((*target, index));
                }
                // A constant votes last: its type is the wasm word it was
                // loaded as, not a claim about the parameter.
                if let Some(n) = int_constant(caller, *arg) {
                    constants.entry((*target, index)).or_default().push((n, Slot::witness(ty)));
                    continue;
                }
                let witness = Slot::witness(ty);
                *slot = std::mem::replace(slot, Slot::Bottom).join_with(witness, true);
            }
        }
    }
    // A constant agrees with the type the other callers settled on when it
    // fits it — bls_signature's helper is called with `0i32` and a `u32`
    // count. With nothing else said, the constants are the evidence.
    for ((id, index), consts) in constants {
        let Some(slot) = evidence.get_mut(&id).and_then(|s| s.get_mut(index)) else { continue };
        let fits_all = match &*slot {
            Slot::Agreed(k) => consts.iter().all(|(n, w)| fits_constant(k, *n, w)),
            _ => false,
        };
        if !fits_all {
            for (_, witness) in consts {
                *slot = std::mem::replace(slot, Slot::Bottom).join(witness);
            }
        }
    }
    for (id, mut slots) in evidence {
        // Callers disagreeing is usually the end of the story: no single
        // type is sound, so the slot says nothing. Not when one of them
        // passes an object. An `Address` or a `Map` reaches a wasm function
        // only as a `Val`, so the parameter *is* a `Val`, and every caller
        // is handing one over — some of them as the thing it was before
        // encoding. The SDK's two-element vec builder is the witness:
        // LLVM merged it across a key's `(Symbol, payload)` and an event's
        // `(amount, ledger)`, and with the slot left `Unknown` the
        // `amount` call site is a type error.
        for (index, slot) in slots.iter_mut().enumerate() {
            if *slot == Slot::Conflict && val_only.contains(&(id, index)) {
                *slot = Slot::Agreed(KnownType::Val);
            }
        }
        if let Some(entry) = table.get_mut(&id) {
            entry.params = slots;
        }
    }
    table
}

/// `value` when it is an integer constant.
fn int_constant(func: &HighFunction, value: ValueId) -> Option<i128> {
    match &func.bindings.get(value)?.expr {
        Expr::Literal(Literal::I32(n)) => Some(i128::from(*n)),
        Expr::Literal(Literal::I64(n)) => Some(i128::from(*n)),
        Expr::Literal(Literal::U32(n)) => Some(i128::from(*n)),
        Expr::Literal(Literal::U64(n)) => Some(i128::from(*n)),
        _ => None,
    }
}

/// [`fits`], for a constant whose own type is `word`: a `bool` is a 32-bit
/// value in the wasm, so only a 32-bit `0` or `1` can be one.
fn fits_constant(k: &KnownType, n: i128, word: &Slot) -> bool {
    if *k == KnownType::Bool {
        return matches!(word, Slot::Agreed(KnownType::I32 | KnownType::U32) | Slot::Bottom) && fits(k, n);
    }
    fits(k, n)
}

/// Whether the integer `n` is a value of type `k`.
fn fits(k: &KnownType, n: i128) -> bool {
    match k {
        KnownType::U32 => u32::try_from(n).is_ok(),
        KnownType::I32 => i32::try_from(n).is_ok(),
        KnownType::U64 => u64::try_from(n).is_ok(),
        KnownType::I64 | KnownType::I128 => true,
        KnownType::U128 => n >= 0,
        KnownType::Bool => n == 0 || n == 1,
        _ => false,
    }
}

/// Whether a value of this type can only be passed between wasm functions
/// as a `Val`: a host object, or a number too wide for one machine word.
fn crosses_only_as_val(k: &KnownType) -> bool {
    matches!(
        k,
        KnownType::Address
            | KnownType::MuxedAddress
            | KnownType::Symbol
            | KnownType::String
            | KnownType::Bytes
            | KnownType::BytesN(_)
            | KnownType::Vec(_)
            | KnownType::Map(_, _)
            | KnownType::UserDefined(_)
            | KnownType::I128
            | KnownType::U128
            | KnownType::I256
            | KnownType::U256
    )
}

/// What each helper's returned components are *used as*, joined over every
/// call site in the module.
///
/// The mirror of the parameter pass: a call's own binding (arity 1) or the
/// [`Expr::Project`]s that read it (arity > 1) carry whatever the caller's
/// body proved about the value, and that is evidence about the callee's
/// return type which the callee cannot see.
///
/// Two callers may use one result differently. That join is a `Conflict`,
/// and a conflict is the honest answer — it says the two disagree, not
/// that one of them is right.
fn result_uses(ir: &HighIr, table: &SigTable) -> HashMap<FuncId, Vec<Slot>> {
    let mut uses: HashMap<FuncId, Vec<Slot>> = ir
        .functions
        .iter()
        .filter(|f| f.signature.is_none())
        .filter_map(|f| {
            let arity = table.get(&f.id)?.returns.len();
            (arity > 0).then(|| (f.id, vec![Slot::Bottom; arity]))
        })
        .collect();

    for caller in &ir.functions {
        for (call_id, binding) in caller.bindings.iter() {
            let Expr::Call { target, .. } = &binding.expr else {
                continue;
            };
            let Some(slots) = uses.get_mut(target) else {
                continue;
            };
            if slots.len() == 1 {
                let witness = Slot::witness(Some(&binding.ty));
                slots[0] = std::mem::replace(&mut slots[0], Slot::Bottom).join(witness);
                continue;
            }
            // A multi-value call is a tuple; the components are read by the
            // projections off it, and the call binding itself has no type
            // worth witnessing.
            for (_, other) in caller.bindings.iter() {
                let Expr::Project { value, index } = &other.expr else {
                    continue;
                };
                if *value != call_id {
                    continue;
                }
                let Some(slot) = slots.get_mut(*index as usize) else {
                    continue;
                };
                let witness = Slot::witness(Some(&other.ty));
                *slot = std::mem::replace(slot, Slot::Bottom).join(witness);
            }
        }
    }
    uses
}

/// The `KnownType` a `TypeRef` denotes, or `None` when it does not resolve
/// to one.
fn type_ref_base(t: &TypeRef) -> Option<KnownType> {
    base_of(type_ref_to_ir(t, Certainty::Known).as_ref())
}

// ---------------------------------------------------------------------
// Lattice
// ---------------------------------------------------------------------

/// Which certainty a `TypeRef` maps into.
#[derive(Clone, Copy)]
enum Certainty {
    Known,
    Inferred,
}

/// Certainty rank; the lattice only moves upward.
fn rank(t: &IrType) -> u8 {
    match t {
        IrType::Unknown(_) => 0,
        IrType::Inferred(_) => 1,
        IrType::Known(_) => 2,
    }
}

/// The `KnownType` behind a `Known`/`Inferred`, or `None` for `Unknown`.
fn base_of(t: Option<&IrType>) -> Option<KnownType> {
    match t? {
        IrType::Known(k) | IrType::Inferred(k) => Some(k.clone()),
        IrType::Unknown(_) => None,
    }
}

/// Evidence bookkeeping for one function's fixpoint.
#[derive(Default)]
struct Evidence {
    /// Ids whose evidence conflicted. They revert to `Unknown` and stay
    /// there, so re-derivation can never resurrect one of the conflicting
    /// types — which is also what keeps the fixpoint terminating.
    conflicted: HashSet<ValueId>,
    /// How many times inter-procedural evidence disagreed at equal rank,
    /// for the `TYPES_EVIDENCE_DISAGREEMENTS` metric.
    disagreements: u64,
    /// Ids whose value is a small scalar's encoding ([`encoded_values`]):
    /// a `Val`, which no evidence refines to the number it carries.
    encoded: HashSet<ValueId>,
}

/// Raise `types[id]` to `cand` iff `cand` is strictly higher certainty.
///
/// Monotonic (`Unknown < Inferred < Known`): an equal-rank candidate of the
/// *same* base never displaces the incumbent. The one exception is a genuine
/// conflict — an equal-rank candidate of a *different* base — which reverts
/// the binding to `Unknown` and freezes it there rather than silently
/// keeping whichever evidence arrived first. The fixpoint still terminates
/// and stays order-deterministic, because a frozen id never moves again.
///
/// A binding the recognizers already proved (`Known`) is never overwritten.
/// That is what keeps the `val_encode<u32>` idiom — a `u32` that is also
/// bit-shifted to build a `Val` — from registering as a conflict: the ABI
/// pins its operand `Known`, which outranks the arithmetic guess instead of
/// tying with it.
/// Whether a candidate names a type where the slot only says `Val`.
///
/// The same rule as [`Slot::join`]'s, one level down: `Val` is the top of
/// the Soroban type lattice, so `Known(Val)` — which the host ABI plants on
/// everything it returns — is the *weakest* true statement about a value
/// and must not outrank a specific type the module proved. Refining is
/// sound in this direction only: an `Address` is a `Val`, so taking the
/// `Address` contradicts nothing the ABI said.
fn refines_val(slot: &IrType, cand: &IrType) -> bool {
    matches!(base_of(Some(slot)), Some(KnownType::Val))
        && !matches!(base_of(Some(cand)), None | Some(KnownType::Val))
}

/// A container type refined by naming an element type the slot left
/// `Unknown`, keeping the slot's certainty. `None` when that is not what
/// the pair is.
fn refine_element(slot: &IrType, cand: &IrType) -> Option<IrType> {
    let rewrap = |k: KnownType| match slot {
        IrType::Known(_) => IrType::Known(k),
        _ => IrType::Inferred(k),
    };
    match (base_of(Some(slot))?, base_of(Some(cand))?) {
        (have @ KnownType::Vec(_), got @ KnownType::Vec(_))
        | (have @ KnownType::Option(_), got @ KnownType::Option(_)) => {
            let merged = merge_partial(&have, &got)?;
            (merged != have).then(|| rewrap(merged))
        }
        _ => None,
    }
}

/// Two types that agree wherever both say something, as the one saying
/// more — `None` when they disagree somewhere.
///
/// Only an `Option`, a `Vec` and a tuple have parts that can be partly
/// known here: `Option<?>` and `Option<u32>` are one type with less and
/// more said about it, not two. A rewritten `Option` helper's `None` arm
/// says nothing of the payload and its `Some` arm may not know it yet
/// either, so without this the merge and the return conflict and the
/// `Option` loses its type entirely. A `Vec` is the same case: the host
/// hands every vec back as `Vec<?>`, so a loop that pushes onto one merges
/// a `Vec<?>` arm with the `Vec<u32>` the return proves, and conflicted the
/// merge to `Val`. Every other pair merges only when equal.
fn merge_partial(a: &KnownType, b: &KnownType) -> Option<KnownType> {
    merge_partial_with(a, b, true)
}

/// [`merge_partial`], with the `Vec` case optional: `vecs` false merges two
/// different vecs no more than two different scalars. For witnesses that
/// are *different values* — the arguments separate callers pass — rather
/// than the values of one variable ([`Slot::join_with`]).
fn merge_partial_with(a: &KnownType, b: &KnownType, vecs: bool) -> Option<KnownType> {
    if a == b {
        return Some(a.clone());
    }
    let part = |x: &IrType, y: &IrType| -> Option<IrType> {
        match (base_of(Some(x)), base_of(Some(y))) {
            (None, _) => Some(y.clone()),
            (_, None) => Some(x.clone()),
            (Some(p), Some(q)) => {
                let m = merge_partial_with(&p, &q, vecs)?;
                Some(match x {
                    IrType::Known(_) => IrType::Known(m),
                    _ => IrType::Inferred(m),
                })
            }
        }
    };
    match (a, b) {
        (KnownType::Option(x), KnownType::Option(y)) => Some(KnownType::Option(Box::new(part(x, y)?))),
        (KnownType::Vec(x), KnownType::Vec(y)) if vecs => Some(KnownType::Vec(Box::new(part(x, y)?))),
        (KnownType::Tuple(xs), KnownType::Tuple(ys)) if xs.len() == ys.len() => Some(KnownType::Tuple(
            xs.iter().zip(ys).map(|(x, y)| part(x, y)).collect::<Option<_>>()?,
        )),
        _ => None,
    }
}

fn improve(
    types: &mut HashMap<ValueId, IrType>,
    ev: &mut Evidence,
    id: ValueId,
    cand: IrType,
) -> bool {
    // A conflicted id is a terminal `Unknown`: never resurrect a type for it.
    if ev.conflicted.contains(&id) {
        return false;
    }
    // An encoded number is the `Val`, never the number: its bits are the
    // payload shifted past a tag ("An encoded number is not the number").
    if ev.encoded.contains(&id) && base_of(Some(&cand)) != Some(KnownType::Val) {
        return false;
    }
    let cand_rank = rank(&cand);
    let slot = types.entry(id).or_insert(IrType::Unknown(
        sordec_common::UnknownReason::InsufficientEvidence,
    ));
    let slot_rank = rank(slot);
    if cand_rank > slot_rank {
        *slot = cand;
        return true;
    }
    // A container whose element type is still `Unknown` is refined by one
    // that names it, at the container's own certainty. This is not the
    // conflict the rule below catches: both sides agree it is a `Vec`, and
    // `Vec<Unknown>` is strictly less information than `Vec<Symbol>`.
    //
    // Without it a recognizer's `Vec<?>` outranks everything the elements
    // later prove, the element renders as `Val`, and a helper returning
    // the vec does not compile — the declared `Vec<Val>` against a
    // `vec![e, sym]` that is a `Vec<Symbol>`.
    if let Some(refined) = refine_element(slot, &cand) {
        *slot = refined;
        return true;
    }
    if refines_val(slot, &cand) {
        *slot = cand;
        return true;
    }
    // The mirror: a `Val` candidate against a slot that already names a
    // type adds nothing, so it is not the conflicting evidence the rule
    // below would take it for. Letting it through erased the named type —
    // which is the same mistake in the opposite direction.
    if refines_val(&cand, slot) {
        return false;
    }
    // The 32-bit word, signed only because wasm has no other: the `u32` is
    // the evidence, at the same certainty ([`unsigned_word`]).
    if cand_rank == slot_rank
        && let (Some(have), Some(got)) = (base_of(Some(&*slot)), base_of(Some(&cand)))
        && let Some(word) = unsigned_word(&have, &got)
    {
        if have == word {
            return false;
        }
        *slot = cand;
        return true;
    }
    // Likewise a candidate that says less of the same `Option`: the slot
    // already holds everything it says.
    if let (Some(have), Some(got)) = (base_of(Some(&*slot)), base_of(Some(&cand)))
        && have != got
        && merge_partial(&have, &got).as_ref() == Some(&have)
    {
        return false;
    }
    // Same certainty rank but a different base = conflicting evidence.
    if cand_rank == slot_rank && cand_rank > 0 && base_of(Some(&*slot)) != base_of(Some(&cand)) {
        *slot = IrType::Unknown(sordec_common::UnknownReason::InsufficientEvidence);
        ev.conflicted.insert(id);
        return true;
    }
    false
}

/// [`improve`], but *counting* the case where inter-procedural evidence
/// names a different type at the same certainty rank as the incumbent.
///
/// [`improve`] already handles that case correctly — it reverts the binding
/// to `Unknown` and freezes it. This wrapper exists only so the rate is
/// observable: the count feeds `TYPES_EVIDENCE_DISAGREEMENTS`, and a run
/// where it climbs sharply is the signal that call-site evidence has become
/// unreliable rather than merely sparse.
fn improve_tracked(
    types: &mut HashMap<ValueId, IrType>,
    ev: &mut Evidence,
    id: ValueId,
    cand: IrType,
) -> bool {
    if let Some(incumbent) = types.get(&id)
        && !ev.conflicted.contains(&id)
        && rank(&cand) == rank(incumbent)
        && rank(&cand) > 0
        && base_of(Some(&cand)) != base_of(Some(incumbent))
    {
        ev.disagreements += 1;
    }
    improve(types, ev, id, cand)
}

/// The first *numeric* base among two operand types, or `None`.
///
/// A logical Soroban type never qualifies: masking or shifting an `Address`
/// extracts a tag, so the logical type must not be carried onto the
/// arithmetic result. See [`KnownType::is_numeric`].
///
/// Two that differ only in sign give the unsigned one, as [`improve`]
/// resolves them: `count + i` where the wasm word typed `i` is `u32`
/// arithmetic.
fn numeric_base(lhs: Option<&IrType>, rhs: Option<&IrType>) -> Option<KnownType> {
    let numeric = |t: Option<&IrType>| base_of(t).filter(KnownType::is_numeric);
    match (numeric(lhs), numeric(rhs)) {
        (Some(a), Some(b)) => Some(unsigned_word(&a, &b).unwrap_or(a)),
        (a, b) => a.or(b),
    }
}

/// `u32`, when two types are the 32-bit word differing only in sign.
///
/// Wasm has one 32-bit integer and no signedness. Every such value starts
/// out `i32` — a literal is the `i32.const` it was loaded by, arithmetic on
/// it the `i32.add` that computed it — because that is the opcode's word,
/// not because anything said the value is signed. A `u32` comes from
/// evidence: the ABI, a `U32Val` encode, a host call's declared type. So
/// against an `i32` at the same certainty the `u32` is the one saying more,
/// as a named type says more than `Val` ([`refines_val`]). Without this the
/// two read as a conflict and the value loses its type altogether: `alloc`'s
/// loop counter, compared with a `count: u32` and stepped with `+ 1i32`,
/// was declared `Val`.
///
/// 32-bit only. The 64-bit word is also every `Val`'s bits, and an `i64`
/// there is not only the opcode's.
fn unsigned_word(a: &KnownType, b: &KnownType) -> Option<KnownType> {
    match (a, b) {
        (KnownType::I32, KnownType::U32) | (KnownType::U32, KnownType::I32) => Some(KnownType::U32),
        _ => None,
    }
}

/// A terse type description for the provenance note.
fn describe(t: &IrType) -> String {
    match t {
        IrType::Known(k) | IrType::Inferred(k) => format!("{k:?}"),
        IrType::Unknown(_) => "?".to_string(),
    }
}

// ---------------------------------------------------------------------
// contractspec TypeRef -> IrType
// ---------------------------------------------------------------------

/// Map a `contractspecv0` [`TypeRef`] to an [`IrType`] at the requested
/// certainty. `TypeRef::Unknown` yields `None` (nothing to seed).
fn type_ref_to_ir(t: &TypeRef, certainty: Certainty) -> Option<IrType> {
    let known = known_of_type_ref(t)?;
    Some(match certainty {
        Certainty::Known => IrType::Known(known),
        Certainty::Inferred => IrType::Inferred(known),
    })
}

/// The `KnownType` a `contractspecv0` type reference denotes, or `None`
/// when the spec referenced something we could not resolve.
///
/// Shared with [`crate::marshalling`], which needs the *declared* type of
/// an entrypoint parameter — the authoritative ABI answer — rather than
/// whatever this pass later infers about the binding.
pub(crate) fn known_of_type_ref(t: &TypeRef) -> Option<KnownType> {
    Some(match t {
        TypeRef::Primitive(p) => primitive_to_known(*p),
        TypeRef::Composite(c) => composite_to_known(c)?,
        TypeRef::UserDefined(id) => KnownType::UserDefined(*id),
        // An SDK type has no `KnownType`: the recovered-type vocabulary
        // covers what a *contract* declares, and this is something only
        // the protocol declares. The signature carries it; nothing in a
        // body needs to reason about it.
        TypeRef::Sdk(_) | TypeRef::Unknown(_) => return None,
    })
}

/// The spec primitive naming a recovered type, where one does.
///
/// The inverse of [`primitive_to_known`], for the recoveries that run
/// the other way: something in the body proves a type and the
/// *declaration* is what has to carry it. Composite and user-defined
/// types have no primitive to name them and return `None`.
pub(crate) fn primitive_of_known(k: &KnownType) -> Option<PrimitiveType> {
    Some(match k {
        KnownType::Val => PrimitiveType::Val,
        KnownType::Bool => PrimitiveType::Bool,
        KnownType::Unit => PrimitiveType::Void,
        KnownType::Error => PrimitiveType::Error,
        KnownType::U32 => PrimitiveType::U32,
        KnownType::I32 => PrimitiveType::I32,
        KnownType::U64 => PrimitiveType::U64,
        KnownType::I64 => PrimitiveType::I64,
        KnownType::Timepoint => PrimitiveType::Timepoint,
        KnownType::Duration => PrimitiveType::Duration,
        KnownType::U128 => PrimitiveType::U128,
        KnownType::I128 => PrimitiveType::I128,
        KnownType::U256 => PrimitiveType::U256,
        KnownType::I256 => PrimitiveType::I256,
        KnownType::Bytes => PrimitiveType::Bytes,
        KnownType::String => PrimitiveType::String,
        KnownType::Symbol => PrimitiveType::Symbol,
        KnownType::Address => PrimitiveType::Address,
        KnownType::MuxedAddress => PrimitiveType::MuxedAddress,
        _ => return None,
    })
}

pub(crate) fn primitive_to_known(p: PrimitiveType) -> KnownType {
    match p {
        PrimitiveType::Val => KnownType::Val,
        PrimitiveType::Bool => KnownType::Bool,
        PrimitiveType::Void => KnownType::Unit,
        PrimitiveType::Error => KnownType::Error,
        PrimitiveType::U32 => KnownType::U32,
        PrimitiveType::I32 => KnownType::I32,
        PrimitiveType::U64 => KnownType::U64,
        PrimitiveType::I64 => KnownType::I64,
        PrimitiveType::Timepoint => KnownType::Timepoint,
        PrimitiveType::Duration => KnownType::Duration,
        PrimitiveType::U128 => KnownType::U128,
        PrimitiveType::I128 => KnownType::I128,
        PrimitiveType::U256 => KnownType::U256,
        PrimitiveType::I256 => KnownType::I256,
        PrimitiveType::Bytes => KnownType::Bytes,
        PrimitiveType::String => KnownType::String,
        PrimitiveType::Symbol => KnownType::Symbol,
        PrimitiveType::Address => KnownType::Address,
        PrimitiveType::MuxedAddress => KnownType::MuxedAddress,
    }
}

/// Composite spec types nest `IrType`; a nested `TypeRef::Unknown` becomes a
/// nested `IrType::Unknown` (the uncertainty propagates inward, per the IR
/// design), so a composite is always mappable.
fn composite_to_known(c: &CompositeType) -> Option<KnownType> {
    let inner = |t: &TypeRef| {
        Box::new(
            known_of_type_ref(t)
                .map(IrType::Known)
                .unwrap_or(IrType::Unknown(
                    sordec_common::UnknownReason::InsufficientEvidence,
                )),
        )
    };
    Some(match c {
        CompositeType::Option(t) => KnownType::Option(inner(t)),
        CompositeType::Result(ok, err) => KnownType::Result(inner(ok), inner(err)),
        CompositeType::Vec(t) => KnownType::Vec(inner(t)),
        CompositeType::Map(k, v) => KnownType::Map(inner(k), inner(v)),
        CompositeType::Tuple(ts) => KnownType::Tuple(
            ts.iter()
                .map(|t| {
                    known_of_type_ref(t).map(IrType::Known).unwrap_or(IrType::Unknown(
                        sordec_common::UnknownReason::InsufficientEvidence,
                    ))
                })
                .collect(),
        ),
        CompositeType::BytesN(n) => KnownType::BytesN(*n),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{Arena, BlockId, FuncId, IrId, UnknownReason};
    use sordec_ir::{Binding, BufOpKind, FunctionParam, HighBlock, Region};

    fn unknown() -> IrType {
        IrType::Unknown(sordec_common::UnknownReason::InsufficientEvidence)
    }

    /// Run only the intra-procedural half: no inter-procedural evidence, so
    /// a single function can be tested without building a module around it.
    fn infer_isolated(func: &mut HighFunction) -> bool {
        infer_function(func, &SigTable::new(), true, &[], &HashSet::new(), false, &EncoderTable::default()).0
    }

    // ---- lattice ----

    #[test]
    fn lattice_only_upgrades() {
        let mut m = HashMap::new();
        let mut ev = Evidence::default();
        let id = ValueId::from_index(0);
        m.insert(id, unknown());
        // Unknown → Inferred upgrades.
        assert!(improve(&mut m, &mut ev, id, IrType::Inferred(KnownType::U64)));
        // Inferred → Inferred of the SAME base does not displace (stable).
        assert!(!improve(&mut m, &mut ev, id, IrType::Inferred(KnownType::U64)));
        assert_eq!(m[&id], IrType::Inferred(KnownType::U64));
        // Inferred → Known upgrades.
        assert!(improve(&mut m, &mut ev, id, IrType::Known(KnownType::U64)));
        // Known is never downgraded by a lower-rank candidate.
        assert!(!improve(&mut m, &mut ev, id, IrType::Inferred(KnownType::Bool)));
        assert_eq!(m[&id], IrType::Known(KnownType::U64));
    }

    /// `Val` is the top of the Soroban type lattice: every host object is
    /// one, so a `Val` witness carries no information against a witness
    /// that names a type. Two *named* types still conflict.
    #[test]
    fn val_is_the_lattice_top_not_a_leaf() {
        let addr = || Slot::Agreed(KnownType::Address);
        let val = || Slot::Agreed(KnownType::Val);
        assert_eq!(val().join(addr()), addr(), "Val yields to a named type");
        assert_eq!(addr().join(val()), addr(), "and in either order");
        assert_eq!(val().join(val()), val(), "Val with Val is still Val");
        assert_eq!(
            Slot::Agreed(KnownType::I64).join(addr()),
            Slot::Conflict,
            "two named types are a real disagreement"
        );
    }

    /// The same rule one level down. The host ABI plants `Known(Val)` on
    /// everything it returns, which must not outrank the specific type the
    /// rest of the module proved — otherwise a helper declares `Address`
    /// while its caller holds `Val`.
    #[test]
    fn a_named_type_refines_val_whatever_its_certainty() {
        let mut m = HashMap::new();
        let mut ev = Evidence::default();
        let id = ValueId::from_index(0);
        m.insert(id, IrType::Known(KnownType::Val));
        assert!(improve(&mut m, &mut ev, id, IrType::Inferred(KnownType::Address)));
        assert_eq!(m[&id], IrType::Inferred(KnownType::Address));
    }

    /// The half that matters: the refinement runs one way only. A `Val`
    /// candidate must not erase a type already named.
    #[test]
    fn val_never_displaces_a_named_type() {
        let mut m = HashMap::new();
        let mut ev = Evidence::default();
        let id = ValueId::from_index(0);
        m.insert(id, IrType::Inferred(KnownType::Address));
        improve(&mut m, &mut ev, id, IrType::Known(KnownType::Val));
        assert_eq!(
            m[&id],
            IrType::Known(KnownType::Val),
            "a higher certainty still wins outright — but see below"
        );
        // ...and at equal certainty it does not.
        let other = ValueId::from_index(1);
        m.insert(other, IrType::Inferred(KnownType::Address));
        improve(&mut m, &mut ev, other, IrType::Inferred(KnownType::Val));
        assert_eq!(m[&other], IrType::Inferred(KnownType::Address), "Val adds nothing");
    }

    /// `Vec<?>` → `Vec<Symbol>` is more information at the same certainty,
    /// not a conflict. A recogniser types a `vec_new` before its elements
    /// are read back, so without this the element stays `Unknown`, renders
    /// as `Val`, and a helper declared to return `Vec<Val>` is handed a
    /// `vec![e, sym]` that is a `Vec<Symbol>`.
    #[test]
    fn an_unknown_element_type_is_refined_not_rejected() {
        let mut m = HashMap::new();
        let mut ev = Evidence::default();
        let id = ValueId::from_index(0);
        let vec_unknown =
            IrType::Known(KnownType::Vec(Box::new(IrType::Unknown(sordec_common::UnknownReason::InsufficientEvidence))));
        m.insert(id, vec_unknown);
        let named = IrType::Inferred(KnownType::Vec(Box::new(IrType::Inferred(KnownType::Symbol))));
        assert!(improve(&mut m, &mut ev, id, named), "the element is named");
        // The container keeps the certainty it already had.
        assert!(
            matches!(&m[&id], IrType::Known(KnownType::Vec(inner))
                if matches!(**inner, IrType::Inferred(KnownType::Symbol))),
            "Known<Vec<Symbol>>, got {:?}",
            m[&id]
        );
    }

    /// The half that matters: a vec that already names its element is not
    /// re-opened, and a disagreement about the element is still a
    /// disagreement.
    #[test]
    fn a_named_element_type_is_not_displaced() {
        let mut m = HashMap::new();
        let mut ev = Evidence::default();
        let id = ValueId::from_index(0);
        let addrs = IrType::Inferred(KnownType::Vec(Box::new(IrType::Inferred(KnownType::Address))));
        m.insert(id, addrs.clone());
        let syms = IrType::Inferred(KnownType::Vec(Box::new(IrType::Inferred(KnownType::Symbol))));
        improve(&mut m, &mut ev, id, syms);
        assert_ne!(m[&id], addrs, "two element types at one rank is a conflict");
        assert!(matches!(m[&id], IrType::Unknown(_)), "so it reverts, got {:?}", m[&id]);
    }

    #[test]
    fn conflicting_inferences_revert_to_unknown_and_stick() {
        // Two same-rank inferences of different bases must NOT keep-first —
        // they revert the binding to Unknown, and that decision is sticky.
        // This is the T2-review behaviour (`ee054d5`); see [`improve`].
        let mut m = HashMap::new();
        let mut ev = Evidence::default();
        let id = ValueId::from_index(0);
        m.insert(id, unknown());
        assert!(improve(&mut m, &mut ev, id, IrType::Inferred(KnownType::U64)));
        // Conflict: reverts to Unknown (returns true — the slot changed).
        assert!(improve(&mut m, &mut ev, id, IrType::Inferred(KnownType::Address)));
        assert!(matches!(m[&id], IrType::Unknown(_)), "reverted to Unknown");
        assert!(ev.conflicted.contains(&id));
        // Sticky: not even a later Known resurrects a type.
        assert!(!improve(&mut m, &mut ev, id, IrType::Known(KnownType::U64)));
        assert!(matches!(m[&id], IrType::Unknown(_)), "still Unknown");
    }

    #[test]
    fn the_32_bit_word_s_sign_yields_to_u32() {
        // `i32` is the opcode's word; `u32` is evidence. Same certainty, so
        // not a conflict: the `u32` wins, and an `i32` after it says less.
        let mut m = HashMap::new();
        let mut ev = Evidence::default();
        let id = ValueId::from_index(0);
        m.insert(id, IrType::Inferred(KnownType::I32));
        assert!(improve(&mut m, &mut ev, id, IrType::Inferred(KnownType::U32)));
        assert_eq!(m[&id], IrType::Inferred(KnownType::U32));
        assert!(!improve(&mut m, &mut ev, id, IrType::Inferred(KnownType::I32)));
        assert_eq!(m[&id], IrType::Inferred(KnownType::U32));
        assert!(!ev.conflicted.contains(&id));
        assert_eq!(
            numeric_base(Some(&IrType::Inferred(KnownType::I32)), Some(&IrType::Known(KnownType::U32))),
            Some(KnownType::U32)
        );
    }

    #[test]
    fn a_wide_small_encode_is_handed_the_low_limb() {
        let v = ValueId::from_index(0);
        for (wide, limb) in [(KnownType::I128, KnownType::I64), (KnownType::U128, KnownType::U64)] {
            let op = KnownOp::ValEncodeSmall { ty: wide, value: v };
            assert_eq!(semantic_arg_types(&op), vec![(v, limb)]);
        }
        let op = KnownOp::ValEncodeSmall { ty: KnownType::U32, value: v };
        assert_eq!(semantic_arg_types(&op), vec![(v, KnownType::U32)], "a narrow payload is itself");
    }

    #[test]
    fn a_64_bit_sign_disagreement_is_still_a_conflict() {
        // The 64-bit word is every `Val`'s bits too; no side is the default.
        let mut m = HashMap::new();
        let mut ev = Evidence::default();
        let id = ValueId::from_index(0);
        m.insert(id, IrType::Inferred(KnownType::I64));
        assert!(improve(&mut m, &mut ev, id, IrType::Inferred(KnownType::U64)));
        assert!(matches!(m[&id], IrType::Unknown(_)));
    }

    // ---- expression rules ----

    #[test]
    fn literals_are_known() {
        assert_eq!(literal_type(&Literal::U64(7)), Some(KnownType::U64));
        assert_eq!(literal_type(&Literal::Bool(true)), Some(KnownType::Bool));
        assert_eq!(literal_type(&Literal::F64(1.0)), None); // no float type in Soroban
    }

    #[test]
    fn arithmetic_shares_operand_type_comparison_is_bool() {
        let u64t = IrType::Known(KnownType::U64);
        // Add with one known operand → Inferred(U64).
        assert_eq!(
            binary_result(BinaryOp::Add, Some(&u64t), Some(&unknown())),
            Some(IrType::Inferred(KnownType::U64))
        );
        // Comparison → bool regardless of operands.
        assert_eq!(
            binary_result(BinaryOp::Lt, Some(&u64t), None),
            Some(IrType::Inferred(KnownType::Bool))
        );
        // No known operand → nothing to say yet.
        assert_eq!(binary_result(BinaryOp::Add, None, None), None);
    }

    /// A bit count carries the **wasm** result type, not Rust's.
    /// `i64.clz` yields an `i64`; `i64::leading_zeros()` yields a `u32`,
    /// and `rust::expr::count_cast` is what bridges the two. Typing the
    /// binding `u32` here put Rust's answer on the IR and left the next
    /// instruction subtracting a `u32` from an `i64` with no cast to
    /// reach for.
    ///
    /// Only a numeric operand decides it. Without one there is nothing to
    /// carry, and `u32` is the safe fallback.
    #[test]
    fn bit_count_takes_the_operands_width_neg_preserves() {
        assert_eq!(
            unary_result(UnaryOp::Clz, Some(&IrType::Known(KnownType::U64))),
            Some(IrType::Inferred(KnownType::U64))
        );
        assert_eq!(
            unary_result(UnaryOp::Clz, None),
            Some(IrType::Inferred(KnownType::U32)),
            "no operand type to carry"
        );
        assert_eq!(
            unary_result(UnaryOp::Clz, Some(&IrType::Known(KnownType::Address))),
            Some(IrType::Inferred(KnownType::U32)),
            "a logical type is not a width"
        );
        assert_eq!(
            unary_result(UnaryOp::Neg, Some(&IrType::Known(KnownType::I128))),
            Some(IrType::Inferred(KnownType::I128))
        );
    }

    /// A constant arm takes the type the other arms agree on when it fits
    /// (`unwrap_or(0) + 1` folds its `None` arm to `1i64` beside a `u32`),
    /// and is all there is when they say nothing yet (a loop counter's
    /// back edge).
    #[test]
    fn a_constant_arm_takes_the_merges_type() {
        use crate::marshalling::test_support::{func_with, v};
        let b0 = BlockId::from_index(0);
        let b1 = BlockId::from_index(1);
        let f = func_with(
            vec![
                Expr::Literal(Literal::I64(1)),                              // v0
                Expr::Phi { incoming: vec![] },                              // v1 the u32
                Expr::Phi { incoming: vec![(b0, v(0)), (b1, v(1))] },       // v2
                Expr::Phi { incoming: vec![] },                              // v3 untyped
                Expr::Phi { incoming: vec![(b0, v(0)), (b1, v(3))] },       // v4
            ],
            vec![],
            vec![0],
        );
        let mut types: HashMap<ValueId, IrType> = HashMap::new();
        types.insert(v(0), IrType::Known(KnownType::I64));
        types.insert(v(1), IrType::Known(KnownType::U32));
        let Expr::Phi { incoming } = &f.bindings.get(v(2)).unwrap().expr else { unreachable!() };
        assert_eq!(phi_join_with_constants(&f, incoming, &types, false), Some(IrType::Inferred(KnownType::U32)));
        let Expr::Phi { incoming } = &f.bindings.get(v(4)).unwrap().expr else { unreachable!() };
        assert_eq!(
            phi_join_with_constants(&f, incoming, &types, false),
            Some(IrType::Inferred(KnownType::I64)),
            "nothing else typed: the constant is the evidence"
        );
    }

    /// `sum = phi [0i64, sum + x]`, returned through a copy typed `copy`:
    /// what the return encode leaves of `Ok(sum)`.
    fn returned_sum(copy: KnownType, entrypoint: bool) -> HighFunction {
        use crate::marshalling::test_support::{func_with, v};
        let (b0, b1) = (BlockId::from_index(0), BlockId::from_index(1));
        let mut f = func_with(
            vec![
                Expr::Literal(Literal::I64(0)),                                      // v0
                Expr::Phi { incoming: vec![] },                                      // v1 x
                Expr::Phi { incoming: vec![(b0, v(0)), (b1, v(3))] },               // v2 sum
                Expr::Binary { op: BinaryOp::Add, lhs: v(1), rhs: v(2) },          // v3
                Expr::Use(v(2)),                                                     // v4
            ],
            vec![],
            vec![0, 3, 4],
        );
        f.bindings.get_mut(v(0)).unwrap().ty = IrType::Known(KnownType::I64);
        f.bindings.get_mut(v(4)).unwrap().ty = IrType::Known(copy);
        if entrypoint {
            f.signature = Some(FunctionSignature { name: "wrapped".into(), inputs: vec![], outputs: vec![] });
        }
        f
    }

    /// The copy the spec typed names the merge before its constant arm
    /// votes, and the sum it is stepped by follows.
    #[test]
    fn a_returned_merge_is_the_declared_number() {
        use crate::marshalling::test_support::v;
        let mut f = returned_sum(KnownType::U64, true);
        infer_isolated(&mut f);
        assert_eq!(f.bindings.get(v(2)).unwrap().ty, IrType::Known(KnownType::U64));
        assert_eq!(f.bindings.get(v(3)).unwrap().ty, IrType::Inferred(KnownType::U64));
        assert_eq!(f.bindings.get(v(0)).unwrap().ty, IrType::Known(KnownType::I64), "the constant keeps its word");
    }

    /// No spec, or a copy typed wider than a packed scalar: the merge is
    /// left to the rounds.
    #[test]
    fn a_merge_without_the_spec_s_number_is_left_to_the_rounds() {
        use crate::marshalling::test_support::v;
        for (copy, entrypoint) in [(KnownType::U64, false), (KnownType::U128, true)] {
            let mut f = returned_sum(copy.clone(), entrypoint);
            infer_isolated(&mut f);
            assert_ne!(f.bindings.get(v(2)).unwrap().ty, IrType::Known(copy), "{entrypoint}");
        }
    }

    /// An inclusive range's `exhausted` flag: `flag = phi [start, i >= n]`,
    /// listed before its test, read as `flag & 1`, beside the step
    /// `i + (i < n)`. Both results are returned, so both are read.
    fn range_flag(start: i32) -> HighFunction {
        use crate::marshalling::test_support::{func_with, v};
        let (b0, b1) = (BlockId::from_index(0), BlockId::from_index(1));
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                                // v0 i
                Expr::Phi { incoming: vec![] },                                // v1 n
                Expr::Literal(Literal::I32(start)),                            // v2
                Expr::Phi { incoming: vec![(b0, v(2)), (b1, v(4))] },          // v3 flag
                Expr::Binary { op: BinaryOp::GeU, lhs: v(0), rhs: v(1) },      // v4
                Expr::Literal(Literal::I32(1)),                                // v5
                Expr::Binary { op: BinaryOp::BitAnd, lhs: v(3), rhs: v(5) },   // v6
                Expr::Binary { op: BinaryOp::LtU, lhs: v(0), rhs: v(1) },      // v7
                Expr::Binary { op: BinaryOp::Add, lhs: v(0), rhs: v(7) },      // v8
            ],
            vec![v(0), v(1)],
            vec![2, 4, 5, 6, 7, 8],
        );
        f.bindings.get_mut(v(0)).unwrap().ty = IrType::Known(KnownType::I32);
        f.bindings.get_mut(v(1)).unwrap().ty = IrType::Known(KnownType::I32);
        f.region = Region::Sequence(vec![Region::Basic(b0), Region::Return { values: vec![v(6), v(8)] }]);
        f.returns = vec![vec![v(6), v(8)]];
        f
    }

    /// The flag is a `bool`: its test is typed before the merge is joined,
    /// the `0` joins as `false`, and neither `flag & 1` nor `i + (i < n)`
    /// makes a number of a `bool` operand.
    #[test]
    fn a_flag_merged_from_false_and_a_test_is_a_bool() {
        use crate::marshalling::test_support::v;
        let mut f = range_flag(0);
        infer_isolated(&mut f);
        let ty = |i: u32| f.bindings.get(v(i)).unwrap().ty.clone();
        assert_eq!(ty(3), IrType::Inferred(KnownType::Bool));
        assert_eq!(ty(7), IrType::Inferred(KnownType::Bool));
        assert_eq!(ty(6), IrType::Inferred(KnownType::I32));
        assert_eq!(ty(8), IrType::Inferred(KnownType::I32));
    }

    /// A constant that is no `bool` beside a test does not make the merge
    /// one.
    #[test]
    fn a_merge_of_a_test_and_a_number_is_not_a_bool() {
        use crate::marshalling::test_support::v;
        let mut f = range_flag(5);
        infer_isolated(&mut f);
        assert_ne!(f.bindings.get(v(3)).unwrap().ty, IrType::Inferred(KnownType::Bool));
    }

    /// `d = val_decode(flag)`, `flag` a parameter typed as the declared
    /// type 5.
    fn decoded_flag() -> HighFunction {
        use crate::marshalling::test_support::{func_with, v};
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                                              // v0 flag
                Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { value: v(0) })), // v1
            ],
            vec![v(0)],
            vec![1],
        );
        f.bindings.get_mut(v(0)).unwrap().ty = IrType::Known(KnownType::UserDefined(TypeId::new(5)));
        f
    }

    /// An integer enum crosses as the `U32Val` of its discriminant, so its
    /// small decode is a `u32`.
    #[test]
    fn a_decoded_integer_enum_is_its_u32_discriminant() {
        use crate::marshalling::test_support::v;
        let mut f = decoded_flag();
        infer_function(&mut f, &SigTable::new(), true, &[], &HashSet::from([TypeId::new(5)]), false, &EncoderTable::default());
        assert_eq!(f.bindings.get(v(1)).unwrap().ty, IrType::Inferred(KnownType::U32));
    }

    /// A declared type that is no integer enum says nothing of the decode.
    #[test]
    fn a_decode_of_another_declared_type_is_left_untyped() {
        use crate::marshalling::test_support::v;
        let mut f = decoded_flag();
        infer_isolated(&mut f);
        assert!(matches!(f.bindings.get(v(1)).unwrap().ty, IrType::Unknown(_)));
    }

    /// `r = phi [a + b, load8_u p]`, the sum typed `i64`, the byte untyped;
    /// `width` is the read's.
    fn merge_with_a_read(width: sordec_ir::MemWidth) -> HighFunction {
        use crate::marshalling::test_support::{func_with, v};
        let (b0, b1) = (BlockId::from_index(0), BlockId::from_index(1));
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                                          // v0 a: i64
                Expr::Binary { op: BinaryOp::Add, lhs: v(0), rhs: v(0) },                 // v1
                Expr::Load { addr: v(0), offset: 17, width, signed: Some(false), ty: IrType::Known(KnownType::I64) }, // v2
                Expr::Phi { incoming: vec![(b0, v(1)), (b1, v(2))] },                    // v3
            ],
            vec![v(0)],
            vec![1, 2],
        );
        f.bindings.get_mut(v(0)).unwrap().ty = IrType::Known(KnownType::I64);
        f.region = Region::Sequence(vec![Region::Basic(b0), Region::Return { values: vec![v(3)] }]);
        f.returns = vec![vec![v(3)]];
        f
    }

    #[test]
    fn a_narrow_read_merged_with_a_number_is_that_number() {
        use crate::marshalling::test_support::v;
        let mut f = merge_with_a_read(sordec_ir::MemWidth::W1);
        infer_isolated(&mut f);
        assert_eq!(f.bindings.get(v(3)).unwrap().ty, IrType::Inferred(KnownType::I64));
        assert_eq!(f.bindings.get(v(2)).unwrap().ty, IrType::Inferred(KnownType::I64));
    }

    #[test]
    fn a_full_word_read_merged_with_a_number_may_be_a_val() {
        use crate::marshalling::test_support::v;
        let mut f = merge_with_a_read(sordec_ir::MemWidth::W8);
        infer_isolated(&mut f);
        assert!(matches!(f.bindings.get(v(2)).unwrap().ty, IrType::Unknown(_)));
    }

    /// A helper's slot: `phi [2, param]`. The constant decides nothing while
    /// the parameter waits for its callers, and decides alone after.
    #[test]
    fn a_constant_beside_a_helper_parameter_waits_for_its_callers() {
        use crate::marshalling::test_support::{func_with, v};
        let (b0, b1) = (BlockId::from_index(0), BlockId::from_index(1));
        let f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                         // v0 the parameter
                Expr::Literal(Literal::I64(2)),                         // v1
                Expr::Phi { incoming: vec![(b0, v(1)), (b1, v(0))] },   // v2
            ],
            vec![v(0)],
            vec![1],
        );
        let mut types: HashMap<ValueId, IrType> = HashMap::new();
        types.insert(v(1), IrType::Known(KnownType::I64));
        let Expr::Phi { incoming } = &f.bindings.get(v(2)).unwrap().expr else { unreachable!() };
        assert_eq!(phi_join_with_constants(&f, incoming, &types, true), None);
        assert_eq!(phi_join_with_constants(&f, incoming, &types, false), Some(IrType::Inferred(KnownType::I64)));
        // Once the callers say `Symbol`, the merge holds neither type.
        types.insert(v(0), IrType::Inferred(KnownType::Symbol));
        assert_eq!(phi_join_with_constants(&f, incoming, &types, false), None);
    }

    /// `r = phi [err, x]; return r` from a function declared `-> out`, `x`
    /// a `u64` parameter and `err` the constant contract error 1.
    fn result_merge(out: TypeRef) -> HighFunction {
        use crate::marshalling::test_support::{func_with, v};
        let (b0, b1) = (BlockId::from_index(0), BlockId::from_index(1));
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                         // v0 x
                Expr::Literal(Literal::I64((1 << 32) | 3)),             // v1 err
                Expr::Phi { incoming: vec![(b0, v(1)), (b1, v(0))] },   // v2 r
            ],
            vec![v(0)],
            vec![1],
        );
        f.signature = Some(FunctionSignature {
            name: "safe_add".into(),
            inputs: vec![FunctionParam { name: "x".into(), ty: TypeRef::Primitive(PrimitiveType::U64) }],
            outputs: vec![out],
        });
        f.region = Region::Sequence(vec![Region::Basic(b0), Region::Return { values: vec![v(2)] }]);
        f.returns = vec![vec![v(2)]];
        f
    }

    #[test]
    fn a_result_merge_whose_arms_are_ok_payloads_stays_the_result() {
        use crate::marshalling::test_support::v;
        let mut f = result_merge(TypeRef::Composite(CompositeType::Result(
            Box::new(TypeRef::Primitive(PrimitiveType::U64)),
            Box::new(TypeRef::Primitive(PrimitiveType::Error)),
        )));
        infer_isolated(&mut f);
        assert!(matches!(f.bindings.get(v(2)).unwrap().ty, IrType::Inferred(KnownType::Result(..))));
    }

    #[test]
    fn a_merge_of_another_type_still_conflicts() {
        use crate::marshalling::test_support::v;
        let mut f = result_merge(TypeRef::Composite(CompositeType::Result(
            Box::new(TypeRef::Primitive(PrimitiveType::Symbol)),
            Box::new(TypeRef::Primitive(PrimitiveType::Error)),
        )));
        infer_isolated(&mut f);
        assert!(matches!(f.bindings.get(v(2)).unwrap().ty, IrType::Unknown(_)));
    }

    #[test]
    fn phi_joins_agree_or_stay_unknown() {
        let mut types = HashMap::new();
        let (a, b, c) = (ValueId::from_index(1), ValueId::from_index(2), ValueId::from_index(3));
        types.insert(a, IrType::Known(KnownType::U64));
        types.insert(b, IrType::Inferred(KnownType::U64));
        types.insert(c, IrType::Known(KnownType::I64));
        // Agreeing arms → Inferred(shared).
        assert_eq!(
            phi_join(&[(BlockId::from_index(0), a), (BlockId::from_index(1), b)], &types),
            Some(IrType::Inferred(KnownType::U64))
        );
        // Conflicting arms → None (honestly Unknown).
        assert_eq!(
            phi_join(&[(BlockId::from_index(0), a), (BlockId::from_index(1), c)], &types),
            None
        );
        // An unresolved arm is skipped, not fatal: it carries no evidence,
        // so it cannot outvote an arm that carries some. Waiting for it
        // instead is what left 24 phis on `phoenix-vesting` untyped with a
        // `Known` arm in hand, and an untyped slot is not neutral — the
        // backend declares it `Val` and the assignments stop compiling. A
        // later conflict still reverts the id to `Unknown` for good, via
        // `Evidence::conflicted`, so the fixpoint is unaffected.
        assert_eq!(
            phi_join(&[(BlockId::from_index(0), a), (BlockId::from_index(1), ValueId::from_index(9))], &types),
            Some(IrType::Inferred(KnownType::U64))
        );
        // No resolved arm at all → still nothing to say.
        assert_eq!(
            phi_join(
                &[
                    (BlockId::from_index(0), ValueId::from_index(8)),
                    (BlockId::from_index(1), ValueId::from_index(9))
                ],
                &types
            ),
            None
        );
    }

    #[test]
    fn semantic_ops_pin_their_argument_types() {
        let (addr, sym, val) = (ValueId::from_index(1), ValueId::from_index(2), ValueId::from_index(3));
        // require_auth's receiver is an Address.
        assert_eq!(
            semantic_arg_types(&KnownOp::RequireAuth { address: addr }),
            vec![(addr, KnownType::Address)]
        );
        // A cross-contract call pins the callee address + function symbol.
        let invoke = KnownOp::InvokeContract {
            contract: addr,
            function: sym,
            resolved_callee: None,
            arg_count: None,
            resolved_args: None,
            interface: None,
            args: vec![],
        };
        assert_eq!(
            semantic_arg_types(&invoke),
            vec![(addr, KnownType::Address), (sym, KnownType::Symbol)]
        );
        // A val-encode pins the packed value to its tag payload type.
        assert_eq!(
            semantic_arg_types(&KnownOp::ValEncodeSmall { ty: KnownType::U64, value: val }),
            vec![(val, KnownType::U64)]
        );
        // obj_from_u64's scalar arg is u64; obj_to_u64's arg is a Val handle
        // (no informative scalar).
        assert_eq!(obj_from_scalar_type(ValObjectKind::ObjFromU64), Some(KnownType::U64));
        assert_eq!(obj_from_scalar_type(ValObjectKind::ObjToU64), None);
        // ed25519_verify pins its key and signature widths, not the message.
        let verify = KnownOp::CryptoOp { kind: CryptoOpKind::VerifySigEd25519, args: vec![addr, sym, val] };
        assert_eq!(
            semantic_arg_types(&verify),
            vec![(addr, KnownType::BytesN(32)), (val, KnownType::BytesN(64))]
        );
    }

    // ---- contractspec mapping ----

    #[test]
    fn type_ref_maps_primitive_composite_and_unknown() {
        assert_eq!(
            type_ref_to_ir(&TypeRef::Primitive(PrimitiveType::Address), Certainty::Known),
            Some(IrType::Known(KnownType::Address))
        );
        // Vec<Address> nests.
        let vec_addr = TypeRef::Composite(CompositeType::Vec(Box::new(TypeRef::Primitive(
            PrimitiveType::Address,
        ))));
        assert_eq!(
            type_ref_to_ir(&vec_addr, Certainty::Inferred),
            Some(IrType::Inferred(KnownType::Vec(Box::new(IrType::Known(KnownType::Address)))))
        );
        // Unknown spec ref seeds nothing.
        assert_eq!(
            type_ref_to_ir(&TypeRef::Unknown(UnknownReason::InsufficientEvidence), Certainty::Known),
            None
        );
    }

    // ---- inter-procedural ----

    /// Build a single-block function with the given id, bindings and return
    /// sites. Reuses `marshalling`'s fixture builder; only the fields it
    /// hardcodes (`id`, `returns`) are overridden.
    fn func_at(
        id: u32,
        exprs: Vec<Expr>,
        params: Vec<ValueId>,
        scheduled: Vec<u32>,
        returns: Vec<Vec<ValueId>>,
    ) -> HighFunction {
        let mut f = crate::marshalling::test_support::func_with(exprs, params, scheduled);
        f.id = FuncId::from_index(id);
        f.returns = returns;
        f
    }

    fn ty_of(ir: &HighIr, func: u32, value: u32) -> IrType {
        ir.functions
            .iter()
            .find(|f| f.id.index() == func)
            .expect("function")
            .bindings
            .get(ValueId::from_index(value))
            .expect("binding")
            .ty
            .clone()
    }

    #[test]
    fn a_dead_pure_binding_does_not_type_its_operands() {
        // Attestation's shape. A recognizer rewrote the tag check into
        // `has_tag(v0, …)` and left the raw `and v0, 255i64` behind with no
        // readers. Taking that as evidence types the parameter as the `i64`
        // it is at the bit level, which then beats the `BytesN<32>` the ABI
        // proves — `improve` will not displace an equal rank, so the dead
        // binding wins permanently.
        let callee = func_at(
            1,
            vec![
                Expr::Phi { incoming: vec![] },        // v0 the parameter
                Expr::Literal(Literal::I64(255)),     // v1
                Expr::Binary {                        // v2 — DEAD, unread
                    op: BinaryOp::BitAnd,
                    lhs: ValueId::from_index(0),
                    rhs: ValueId::from_index(1),
                },
            ],
            vec![ValueId::from_index(0)],
            vec![1, 2],
            vec![],
        );
        // One caller, passing a `Bytes`.
        let caller = func_at(
            0,
            vec![
                Expr::Literal(Literal::Bytes(vec![1, 2, 3])),
                Expr::Call {
                    target: FuncId::from_index(1),
                    args: vec![ValueId::from_index(0)],
                },
            ],
            vec![],
            vec![0, 1],
            vec![],
        );
        let mut ir = crate::marshalling::test_support::module(vec![caller, callee]);
        TypeInferPass.run(&mut ir);
        assert_eq!(
            ty_of(&ir, 1, 0),
            IrType::Inferred(KnownType::Bytes),
            "the live call site decides, not the dead mask"
        );
    }

    /// `func_0` returns `0i32` or `func_1(x)`, and `func_1` returns a
    /// comparison. The call is untyped until `func_1` settles, so the
    /// constant must not fix `func_0`'s return as the word first:
    /// import_ark_bn254's `func71`, which then conflicted for good.
    #[test]
    fn a_constant_return_waits_for_a_returned_call() {
        let v = ValueId::from_index;
        let caller = func_at(
            0,
            vec![
                Expr::Literal(Literal::I32(0)),                                // v0
                Expr::Call { target: FuncId::from_index(1), args: vec![] },   // v1
            ],
            vec![],
            vec![0, 1],
            vec![vec![v(0)], vec![v(1)]],
        );
        let callee = func_at(
            1,
            vec![
                Expr::Phi { incoming: vec![] },                               // v0
                Expr::Literal(Literal::I64(7)),                               // v1
                Expr::Binary { op: BinaryOp::Lt, lhs: v(0), rhs: v(1) },      // v2
            ],
            vec![],
            vec![1, 2],
            vec![vec![v(2)]],
        );
        let mut ir = crate::marshalling::test_support::module(vec![caller, callee]);
        TypeInferPass.run(&mut ir);
        assert_eq!(ty_of(&ir, 0, 1), IrType::Inferred(KnownType::Bool));
    }

    #[test]
    fn a_live_pure_binding_still_types_its_operands() {
        // The same shape with the mask *read*, so it is real code: the
        // filter must not have disabled backward propagation generally.
        let mut func = func_at(
            0,
            vec![
                Expr::Phi { incoming: vec![] },    // v0
                Expr::Literal(Literal::I64(255)),  // v1
                Expr::Binary {                     // v2 = v0 & v1
                    op: BinaryOp::BitAnd,
                    lhs: ValueId::from_index(0),
                    rhs: ValueId::from_index(1),
                },
            ],
            vec![],
            vec![1, 2],
            vec![vec![ValueId::from_index(2)]], // v2 is returned ⇒ live
        );
        func.params = vec![];
        let mut ir = crate::marshalling::test_support::module(vec![func]);
        TypeInferPass.run(&mut ir);
        assert_eq!(
            ty_of(&ir, 0, 0),
            IrType::Inferred(KnownType::I64),
            "a read mask is evidence about its operand"
        );
    }

    #[test]
    fn slot_join_is_a_three_point_lattice() {
        let i64s = || Slot::Agreed(KnownType::I64);
        let u64s = || Slot::Agreed(KnownType::U64);
        // Bottom is the identity.
        assert_eq!(Slot::Bottom.join(i64s()), i64s());
        assert_eq!(i64s().join(Slot::Bottom), i64s());
        // Agreement is idempotent; disagreement conflicts.
        assert_eq!(i64s().join(i64s()), i64s());
        assert_eq!(i64s().join(u64s()), Slot::Conflict);
        // Conflict absorbs, in both directions — once there is no sound
        // single type, no further witness can talk it back into one.
        assert_eq!(Slot::Conflict.join(i64s()), Slot::Conflict);
        assert_eq!(i64s().join(Slot::Conflict), Slot::Conflict);
        assert_eq!(Slot::Conflict.join(Slot::Bottom), Slot::Conflict);
        // An Unknown witness has not spoken: no evidence, not a conflict.
        assert_eq!(Slot::witness(Some(&unknown())), Slot::Bottom);
        assert_eq!(Slot::witness(None), Slot::Bottom);
        // Neither end of the lattice yields a type to apply.
        assert_eq!(Slot::Bottom.to_ir(Certainty::Inferred), None);
        assert_eq!(Slot::Conflict.to_ir(Certainty::Inferred), None);
    }

    /// The outlined `u64` encode, as function `id`:
    /// `r = phi [obj_from_u64(x), val_encode<u64>(x)]; return (0, r)`.
    fn u64_encoder(id: u32) -> HighFunction {
        let v = ValueId::from_index;
        let mut f = func_at(
            id,
            vec![
                Expr::Phi { incoming: vec![] }, // v0: x
                Expr::Semantic(SemanticOp::Known(KnownOp::ValObject {
                    kind: ValObjectKind::ObjFromU64,
                    args: vec![v(0)],
                })), // v1
                Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty: KnownType::U64, value: v(0) })), // v2
                Expr::Phi { incoming: vec![(BlockId::from_index(0), v(1)), (BlockId::from_index(1), v(2))] }, // v3
                Expr::Literal(Literal::I64(0)), // v4
            ],
            vec![v(0)],
            vec![1, 2, 4],
            vec![vec![v(4), v(3)]],
        );
        f.region =
            Region::Sequence(vec![Region::Basic(BlockId::from_index(0)), Region::Return { values: vec![v(4), v(3)] }]);
        f
    }

    /// A caller comparing the encoder's component with a `u64` is not
    /// evidence that the component is one: it stays a `Val`, and so does
    /// the merge the helper returns it from.
    #[test]
    fn an_encoded_number_is_not_refined_to_the_number() {
        let v = ValueId::from_index;
        // fn0(y) { t = fn1(y); return 5u64 == t.1 }
        let caller = func_at(
            0,
            vec![
                Expr::Phi { incoming: vec![] },                                 // v0: y
                Expr::Call { target: FuncId::from_index(1), args: vec![v(0)] }, // v1
                Expr::Project { value: v(1), index: 1 },                        // v2
                Expr::Literal(Literal::U64(5)),                                 // v3
                Expr::Binary { op: BinaryOp::Eq, lhs: v(3), rhs: v(2) },        // v4
            ],
            vec![v(0)],
            vec![1, 2, 3, 4],
            vec![vec![v(4)]],
        );
        let mut ir = crate::marshalling::test_support::module(vec![caller, u64_encoder(1)]);
        TypeInferPass.run(&mut ir);
        assert_eq!(base_of(Some(&ty_of(&ir, 0, 2))), Some(KnownType::Val), "the component is the encode");
        assert_eq!(base_of(Some(&ty_of(&ir, 1, 3))), Some(KnownType::Val), "the helper returns a Val");
        assert_eq!(ty_of(&ir, 1, 0), IrType::Known(KnownType::U64), "and encodes a u64");
    }

    /// A wrapper that only hands its parameter to the encoder takes the
    /// encoded type for it, though its caller holds a raw 64-bit word.
    #[test]
    fn a_wrapper_of_the_encoder_takes_the_number_it_encodes() {
        let v = ValueId::from_index;
        // fn2(p) { t = fn1(p); return (0, t.1) }
        let mut wrapper = func_at(
            2,
            vec![
                Expr::Phi { incoming: vec![] },                                 // v0: p
                Expr::Call { target: FuncId::from_index(1), args: vec![v(0)] }, // v1
                Expr::Project { value: v(1), index: 1 },                        // v2
                Expr::Literal(Literal::I64(0)),                                 // v3
            ],
            vec![v(0)],
            vec![1, 2, 3],
            vec![vec![v(3), v(2)]],
        );
        wrapper.region =
            Region::Sequence(vec![Region::Basic(BlockId::from_index(0)), Region::Return { values: vec![v(3), v(2)] }]);
        // fn0(w: i64) { fn2(w) }
        let mut caller = func_at(
            0,
            vec![Expr::Phi { incoming: vec![] }, Expr::Call { target: FuncId::from_index(2), args: vec![v(0)] }],
            vec![v(0)],
            vec![1],
            vec![],
        );
        caller.bindings.get_mut(v(0)).unwrap().ty = IrType::Inferred(KnownType::I64);
        let mut ir = crate::marshalling::test_support::module(vec![caller, u64_encoder(1), wrapper]);
        TypeInferPass.run(&mut ir);
        assert_eq!(ty_of(&ir, 2, 0), IrType::Known(KnownType::U64));
        assert_eq!(base_of(Some(&ty_of(&ir, 2, 2))), Some(KnownType::Val));
        assert_eq!(ty_of(&ir, 0, 0), IrType::Inferred(KnownType::I64), "the caller's word is cast, not retyped");
    }

    /// Inside the encoder, what it returns in its encoded component and the
    /// encodes that merge is made of; not its parameter, nor the status it
    /// returns beside them. An encode in a function that is not such a
    /// helper is left to the rules that type it today.
    #[test]
    fn the_encoder_s_returned_encodes_are_the_encoded_values() {
        let v = ValueId::from_index;
        let ir = crate::marshalling::test_support::module(vec![u64_encoder(1)]);
        let encoders = EncoderTable::build(&ir);
        let encoded = encoded_values(&ir.functions[0], &encoders);
        for id in [1, 2, 3] {
            assert!(encoded.contains(&v(id)), "v{id}");
        }
        for id in [0, 4] {
            assert!(!encoded.contains(&v(id)), "v{id}");
        }
        // The same body returning a loaded word instead of its parameter's
        // encode is not a recognised encoder: nothing in it is covered.
        let mut other = u64_encoder(1);
        other.bindings.get_mut(v(0)).unwrap().expr = Expr::GlobalGet { index: 0 };
        other.params = vec![];
        let ir = crate::marshalling::test_support::module(vec![other]);
        assert!(encoded_values(&ir.functions[0], &EncoderTable::build(&ir)).is_empty());
    }

    #[test]
    fn a_call_result_takes_the_callee_return_type() {
        // fn1() -> i64 { return 7i64 }   fn0() { v0 = fn1() }
        let callee = func_at(
            1,
            vec![Expr::Literal(Literal::I64(7))],
            vec![],
            vec![0],
            vec![vec![ValueId::from_index(0)]],
        );
        let caller = func_at(
            0,
            vec![Expr::Call { target: FuncId::from_index(1), args: vec![] }],
            vec![],
            vec![0],
            vec![],
        );
        let mut ir = crate::marshalling::test_support::module(vec![caller, callee]);
        assert!(TypeInferPass.run(&mut ir).changed);
        assert_eq!(
            ty_of(&ir, 0, 0),
            IrType::Inferred(KnownType::I64),
            "the call result is the callee's return type"
        );
    }

    /// `fn1() -> u32 { let c = <proven u32>; let n = c + 1i32; return n }`,
    /// `fn0() { v0 = fn1() }`, every binding seeded with the `i32` word.
    fn increment_helper() -> HighIr {
        let mut callee = func_at(
            1,
            vec![
                Expr::GlobalGet { index: 0 },                                                   // v0 the count
                Expr::Literal(Literal::I32(1)),                                                 // v1
                Expr::Binary { op: BinaryOp::Add, lhs: ValueId::from_index(0), rhs: ValueId::from_index(1) }, // v2
            ],
            vec![],
            vec![0, 1, 2],
            vec![vec![ValueId::from_index(2)]],
        );
        for (id, b) in callee.bindings.iter_mut() {
            b.ty = if id.index() == 0 { IrType::Known(KnownType::U32) } else { IrType::Inferred(KnownType::I32) };
        }
        let mut caller = func_at(0, vec![Expr::Call { target: FuncId::from_index(1), args: vec![] }], vec![], vec![0], vec![]);
        if let Some(b) = caller.bindings.get_mut(ValueId::from_index(0)) {
            b.ty = IrType::Inferred(KnownType::I32);
        }
        crate::marshalling::test_support::module(vec![caller, callee])
    }

    /// The SDK hands the host a frame buffer as `U32Val::from(ptr as u32)`;
    /// the address itself is not the `u32`.
    #[test]
    fn a_frame_address_encoded_for_the_host_stays_a_word() {
        let f = func_at(
            0,
            vec![
                Expr::GlobalGet { index: 0 },                                                                      // v0
                Expr::Literal(Literal::I32(16)),                                                                   // v1
                Expr::Binary { op: BinaryOp::Sub, lhs: ValueId::from_index(0), rhs: ValueId::from_index(1) }, // v2 frame
                Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall {
                    ty: KnownType::U32,
                    value: ValueId::from_index(2),
                })),                                                                                               // v3
            ],
            vec![],
            vec![0, 1, 2, 3],
            vec![vec![ValueId::from_index(3)]],
        );
        let mut ir = crate::marshalling::test_support::module(vec![f]);
        TypeInferPass.run(&mut ir);
        assert_ne!(ty_of(&ir, 0, 2), IrType::Known(KnownType::U32));
    }

    #[test]
    fn a_loop_counter_bounded_by_a_u32_is_a_u32() {
        // `account`'s `for i in 0..signatures.len()`, with the length
        // decoded by an `i64` shift: start and step are `i64` literals and
        // only the exit test against the `u32` length says what `i` is.
        let b = sordec_common::BlockId::from_index;
        let id = ValueId::from_index;
        let mut f = func_at(
            0,
            vec![
                Expr::Literal(Literal::I64(0)),                                     // v0 start
                Expr::Phi { incoming: vec![(b(0), id(0)), (b(1), id(3))] },         // v1 i
                Expr::Literal(Literal::I64(1)),                                     // v2
                Expr::Binary { op: BinaryOp::Add, lhs: id(1), rhs: id(2) },         // v3 i + 1
                Expr::Phi { incoming: vec![] },                                     // v4 len
                Expr::Binary { op: BinaryOp::Eq, lhs: id(4), rhs: id(1) },          // v5
            ],
            vec![],
            vec![0, 1, 2, 3, 4, 5],
            vec![],
        );
        f.bindings.get_mut(id(4)).unwrap().ty = IrType::Known(KnownType::U32);
        let mut ir = crate::marshalling::test_support::module(vec![f]);
        TypeInferPass.run(&mut ir);
        assert_eq!(ty_of(&ir, 0, 1), IrType::Inferred(KnownType::U32));
    }

    #[test]
    fn a_counter_with_a_negative_start_is_not_bounded_below() {
        let b = sordec_common::BlockId::from_index;
        let id = ValueId::from_index;
        let f = func_at(
            0,
            vec![
                Expr::Literal(Literal::I64(-1)),
                Expr::Phi { incoming: vec![(b(0), id(0)), (b(1), id(3))] },
                Expr::Literal(Literal::I64(1)),
                Expr::Binary { op: BinaryOp::Add, lhs: id(1), rhs: id(2) },
            ],
            vec![],
            vec![0, 1, 2, 3],
            vec![],
        );
        let Expr::Phi { incoming } = &f.bindings.get(id(1)).unwrap().expr else { unreachable!() };
        assert_eq!(counter_bounded_by_u32(&f, id(1), incoming, &HashMap::new()), None);
    }

    /// One function whose `v0..v(n-1)` are untyped parameters handed to
    /// the crypto op `kind`, which is `v(n)`; `ty` seeds `v0`.
    fn crypto_on_params(kind: CryptoOpKind, n: u32, ty: Option<IrType>) -> HighIr {
        let mut exprs: Vec<Expr> = (0..n).map(|_| Expr::Phi { incoming: vec![] }).collect();
        exprs.push(Expr::Semantic(SemanticOp::Known(KnownOp::CryptoOp {
            kind,
            args: (0..n).map(ValueId::from_index).collect(),
        })));
        let mut f = func_at(0, exprs, (0..n).map(ValueId::from_index).collect(), vec![n], vec![]);
        if let Some(ty) = ty {
            f.bindings.get_mut(ValueId::from_index(0)).unwrap().ty = ty;
        }
        crate::marshalling::test_support::module(vec![f])
    }

    #[test]
    fn a_hash_input_nothing_typed_is_the_bytes_the_host_takes() {
        let mut ir = crypto_on_params(CryptoOpKind::ComputeHashSha256, 1, None);
        TypeInferPass.run(&mut ir);
        assert_eq!(ty_of(&ir, 0, 0), IrType::Known(KnownType::Bytes));
        // A `Val` says less than the catalog and is refined by it.
        let mut ir = crypto_on_params(CryptoOpKind::ComputeHashKeccak256, 1, Some(IrType::Known(KnownType::Val)));
        TypeInferPass.run(&mut ir);
        assert_eq!(ty_of(&ir, 0, 0), IrType::Known(KnownType::Bytes));
    }

    #[test]
    fn a_hash_input_already_named_keeps_its_name() {
        // The catalog says "a bytes object", not its length: a `BytesN<32>`
        // handed to `sha256` is not widened.
        let mut ir =
            crypto_on_params(CryptoOpKind::ComputeHashSha256, 1, Some(IrType::Inferred(KnownType::BytesN(32))));
        TypeInferPass.run(&mut ir);
        assert_eq!(ty_of(&ir, 0, 0), IrType::Inferred(KnownType::BytesN(32)));
    }

    #[test]
    fn the_catalog_waits_for_a_width_that_arrives_late() {
        // fn1(x) { sha256(x) }, called by fn0 with a `BytesN<32>`. `x` is
        // typed from that call site only once the table is rebuilt, a round
        // after the catalog could first have said `Bytes`.
        let callee = func_at(
            1,
            vec![
                Expr::Phi { incoming: vec![] },
                Expr::Semantic(SemanticOp::Known(KnownOp::CryptoOp {
                    kind: CryptoOpKind::ComputeHashSha256,
                    args: vec![ValueId::from_index(0)],
                })),
            ],
            vec![ValueId::from_index(0)],
            vec![1],
            vec![],
        );
        let mut caller = func_at(
            0,
            vec![
                Expr::Phi { incoming: vec![] },
                Expr::Call { target: FuncId::from_index(1), args: vec![ValueId::from_index(0)] },
            ],
            vec![],
            vec![1],
            vec![],
        );
        caller.bindings.get_mut(ValueId::from_index(0)).unwrap().ty = IrType::Known(KnownType::BytesN(32));
        let mut ir = crate::marshalling::test_support::module(vec![caller, callee]);
        TypeInferPass.run(&mut ir);
        assert_eq!(ty_of(&ir, 1, 0), IrType::Inferred(KnownType::BytesN(32)));
    }

    #[test]
    fn the_catalog_types_objects_only_and_yields_to_a_pinned_width() {
        // `recover_key_ecdsa_secp256k1(digest, signature, recovery_id)`: the
        // two objects are bytes, the `U32Val` is the encoding, left alone.
        let mut ir = crypto_on_params(CryptoOpKind::RecoverKeyEcdsaSecp256k1, 3, None);
        TypeInferPass.run(&mut ir);
        assert_eq!(ty_of(&ir, 0, 0), IrType::Known(KnownType::Bytes));
        assert_eq!(ty_of(&ir, 0, 1), IrType::Known(KnownType::Bytes));
        assert!(matches!(ty_of(&ir, 0, 2), IrType::Unknown(_)));
        // `ed25519_verify`'s key and signature keep the widths the SDK's own
        // signature pins; only the message takes the catalog's `Bytes`.
        let mut ir = crypto_on_params(CryptoOpKind::VerifySigEd25519, 3, None);
        TypeInferPass.run(&mut ir);
        assert_eq!(ty_of(&ir, 0, 0), IrType::Known(KnownType::BytesN(32)));
        assert_eq!(ty_of(&ir, 0, 1), IrType::Known(KnownType::Bytes));
        assert_eq!(ty_of(&ir, 0, 2), IrType::Known(KnownType::BytesN(64)));
    }

    /// One function whose `v0..v(n-1)` are untyped parameters handed to
    /// the bytes op `kind`, which is `v(n)`; `ty` seeds `v0`.
    fn buf_on_params(kind: BufOpKind, n: u32, ty: Option<IrType>) -> HighIr {
        let mut exprs: Vec<Expr> = (0..n).map(|_| Expr::Phi { incoming: vec![] }).collect();
        exprs.push(Expr::Semantic(SemanticOp::Known(KnownOp::BufOp {
            kind,
            args: (0..n).map(ValueId::from_index).collect(),
        })));
        let mut f = func_at(0, exprs, (0..n).map(ValueId::from_index).collect(), vec![n], vec![]);
        if let Some(ty) = ty {
            f.bindings.get_mut(ValueId::from_index(0)).unwrap().ty = ty;
        }
        crate::marshalling::test_support::module(vec![f])
    }

    #[test]
    fn the_value_a_bytes_len_reads_is_the_bytes_the_host_takes() {
        let mut ir = buf_on_params(BufOpKind::BytesLen, 1, None);
        TypeInferPass.run(&mut ir);
        assert_eq!(ty_of(&ir, 0, 0), IrType::Known(KnownType::Bytes));
        // `bytes_get(bytes, index)`: the index is a `U32Val`, the encoding,
        // and is left alone.
        let mut ir = buf_on_params(BufOpKind::BytesGet, 2, None);
        TypeInferPass.run(&mut ir);
        assert_eq!(ty_of(&ir, 0, 0), IrType::Known(KnownType::Bytes));
        assert!(matches!(ty_of(&ir, 0, 1), IrType::Unknown(_)));
    }

    #[test]
    fn a_bytes_len_operand_already_named_keeps_its_width() {
        let mut ir = buf_on_params(BufOpKind::BytesLen, 1, Some(IrType::Inferred(KnownType::BytesN(96))));
        TypeInferPass.run(&mut ir);
        assert_eq!(ty_of(&ir, 0, 0), IrType::Inferred(KnownType::BytesN(96)));
        // A `Val` whose length a fixed-width decode checks stays the `Val`
        // its callers hand over (unlike a crypto op's, which is refined).
        let mut ir = buf_on_params(BufOpKind::BytesLen, 1, Some(IrType::Inferred(KnownType::Val)));
        TypeInferPass.run(&mut ir);
        assert_eq!(ty_of(&ir, 0, 0), IrType::Inferred(KnownType::Val));
        // `serialize_to_bytes` takes any `Val`: the catalog names no object.
        let mut ir = buf_on_params(BufOpKind::SerializeToBytes, 1, None);
        TypeInferPass.run(&mut ir);
        assert!(matches!(ty_of(&ir, 0, 0), IrType::Unknown(_)));
    }

    fn vec_of(t: IrType) -> KnownType {
        KnownType::Vec(Box::new(t))
    }

    #[test]
    fn an_unknown_element_type_merges_with_a_named_one() {
        let u32s = vec_of(IrType::Inferred(KnownType::U32));
        assert_eq!(merge_partial(&vec_of(unknown()), &u32s), Some(u32s.clone()));
        assert_eq!(merge_partial(&u32s, &vec_of(unknown())), Some(u32s.clone()));
        assert_eq!(
            merge_partial(&u32s, &vec_of(IrType::Known(KnownType::Address))),
            None,
            "two named element types still conflict"
        );
        // A loop's merge of the empty vec and the pushed one.
        let phi = Expr::Phi {
            incoming: vec![(BlockId::from_index(0), ValueId::from_index(0)), (BlockId::from_index(1), ValueId::from_index(1))],
        };
        let mut types = HashMap::new();
        types.insert(ValueId::from_index(0), IrType::Known(vec_of(unknown())));
        types.insert(ValueId::from_index(1), IrType::Inferred(u32s.clone()));
        let Expr::Phi { incoming } = &phi else { unreachable!() };
        assert_eq!(phi_join(incoming, &types), Some(IrType::Inferred(u32s)));
    }

    /// `v2 = phi [v0, v1]`, returned, with the arms typed as given.
    fn vec_merge(first: IrType, second: IrType) -> HighIr {
        let mut f = func_at(
            0,
            vec![
                Expr::Phi { incoming: vec![] },
                Expr::Phi { incoming: vec![] },
                Expr::Phi {
                    incoming: vec![
                        (BlockId::from_index(0), ValueId::from_index(0)),
                        (BlockId::from_index(0), ValueId::from_index(1)),
                    ],
                },
            ],
            vec![ValueId::from_index(0), ValueId::from_index(1)],
            vec![],
            vec![vec![ValueId::from_index(2)]],
        );
        f.bindings.get_mut(ValueId::from_index(0)).unwrap().ty = first;
        f.bindings.get_mut(ValueId::from_index(1)).unwrap().ty = second;
        crate::marshalling::test_support::module(vec![f])
    }

    #[test]
    fn an_untyped_vec_arm_takes_the_merges_element_type() {
        // The empty vec a loop starts from, and the vec it pushes onto.
        let mut ir = vec_merge(
            IrType::Known(vec_of(unknown())),
            IrType::Inferred(vec_of(IrType::Inferred(KnownType::U32))),
        );
        TypeInferPass.run(&mut ir);
        let u32s = vec_of(IrType::Inferred(KnownType::U32));
        assert_eq!(base_of(Some(&ty_of(&ir, 0, 2))), Some(u32s.clone()));
        assert_eq!(base_of(Some(&ty_of(&ir, 0, 0))), Some(u32s), "the empty vec is the same vec");
    }

    #[test]
    fn a_copy_named_vec_of_t_names_the_vec_it_copies() {
        // `v1 = v0` with `v0: Vec<?>` and `v1` returned as `Vec<u32>`.
        let mut f = func_at(
            0,
            vec![Expr::Phi { incoming: vec![] }, Expr::Use(ValueId::from_index(0))],
            vec![ValueId::from_index(0)],
            vec![1],
            vec![vec![ValueId::from_index(1)]],
        );
        let u32s = vec_of(IrType::Known(KnownType::U32));
        f.bindings.get_mut(ValueId::from_index(0)).unwrap().ty = IrType::Known(vec_of(unknown()));
        f.bindings.get_mut(ValueId::from_index(1)).unwrap().ty = IrType::Known(u32s.clone());
        let mut ir = crate::marshalling::test_support::module(vec![f]);
        TypeInferPass.run(&mut ir);
        assert_eq!(base_of(Some(&ty_of(&ir, 0, 0))), Some(u32s));
    }

    #[test]
    fn callers_passing_different_vecs_do_not_name_the_parameter() {
        // fn1(p) called with a `Vec<?>` by fn0 and a `Vec<Address>` by fn2:
        // two vecs built apart, and the first is not shown to be the second.
        let callee = func_at(1, vec![Expr::Phi { incoming: vec![] }], vec![ValueId::from_index(0)], vec![], vec![]);
        let caller = |id: u32, ty: KnownType| {
            let mut f = func_at(
                id,
                vec![
                    Expr::Phi { incoming: vec![] },
                    Expr::Call { target: FuncId::from_index(1), args: vec![ValueId::from_index(0)] },
                ],
                vec![],
                vec![1],
                vec![],
            );
            f.bindings.get_mut(ValueId::from_index(0)).unwrap().ty = IrType::Known(ty);
            f
        };
        let mut ir = crate::marshalling::test_support::module(vec![
            caller(0, vec_of(unknown())),
            callee,
            caller(2, vec_of(IrType::Known(KnownType::Address))),
        ]);
        TypeInferPass.run(&mut ir);
        assert!(
            !matches!(base_of(Some(&ty_of(&ir, 1, 0))), Some(KnownType::Vec(_))),
            "got {:?}",
            ty_of(&ir, 1, 0)
        );
    }

    /// fn`id`(v0) { fn`target`(v0) }, with `v0` typed `ty` (a parameter
    /// when `param`).
    fn forwards(id: u32, target: u32, ty: Option<KnownType>, param: bool) -> HighFunction {
        let mut f = func_at(
            id,
            vec![
                Expr::Phi { incoming: vec![] },
                Expr::Call { target: FuncId::from_index(target), args: vec![ValueId::from_index(0)] },
            ],
            if param { vec![ValueId::from_index(0)] } else { vec![] },
            vec![1],
            vec![],
        );
        if let Some(ty) = ty {
            f.bindings.get_mut(ValueId::from_index(0)).unwrap().ty = IrType::Known(ty);
        }
        f
    }

    #[test]
    fn a_fixed_width_value_handed_on_to_a_bytes_helper_keeps_its_width() {
        // fn0 holds a `BytesN<32>` and calls fn1(p), which hands `p` on to
        // fn2, whose parameter its body proved `Bytes`.
        let bytes_param = func_at(2, vec![Expr::Phi { incoming: vec![] }], vec![ValueId::from_index(0)], vec![], vec![]);
        let mut ir = crate::marshalling::test_support::module(vec![
            forwards(0, 1, Some(KnownType::BytesN(32)), false),
            forwards(1, 2, None, true),
            bytes_param,
        ]);
        ir.functions[2].bindings.get_mut(ValueId::from_index(0)).unwrap().ty = IrType::Known(KnownType::Bytes);
        TypeInferPass.run(&mut ir);
        assert_eq!(ty_of(&ir, 1, 0), IrType::Inferred(KnownType::BytesN(32)), "p is what every caller passes");
        assert_eq!(ty_of(&ir, 2, 0), IrType::Known(KnownType::Bytes));
    }

    #[test]
    fn callers_passing_bytes_and_a_fixed_width_make_a_bytes_parameter() {
        let callee = func_at(2, vec![Expr::Phi { incoming: vec![] }], vec![ValueId::from_index(0)], vec![], vec![]);
        let mut ir = crate::marshalling::test_support::module(vec![
            forwards(0, 2, Some(KnownType::BytesN(32)), false),
            forwards(1, 2, Some(KnownType::Bytes), false),
            callee,
        ]);
        TypeInferPass.run(&mut ir);
        assert_eq!(ty_of(&ir, 2, 0), IrType::Inferred(KnownType::Bytes));
        assert_eq!(ty_of(&ir, 0, 0), IrType::Known(KnownType::BytesN(32)), "the call widens it");
    }

    #[test]
    fn a_merge_of_bytes_and_a_fixed_width_still_conflicts() {
        assert_eq!(Slot::Agreed(KnownType::Bytes).join(Slot::Agreed(KnownType::BytesN(32))), Slot::Conflict);
    }

    #[test]
    fn a_merge_that_names_no_element_fills_no_arm() {
        let mut ir = vec_merge(IrType::Known(vec_of(unknown())), IrType::Known(vec_of(unknown())));
        TypeInferPass.run(&mut ir);
        assert_eq!(ty_of(&ir, 0, 0), IrType::Known(vec_of(unknown())));
    }

    /// `v1 = vec_<kind>(v0, v2)` with `v0` typed `receiver`; the result as
    /// the host types it, `Vec<?>`.
    fn vec_op_on(kind: sordec_ir::VecOpKind, receiver: IrType) -> HighIr {
        let mut f = func_at(
            0,
            vec![
                Expr::Phi { incoming: vec![] },
                Expr::Semantic(SemanticOp::Known(KnownOp::VecOp {
                    kind,
                    args: vec![ValueId::from_index(0), ValueId::from_index(2)],
                })),
                Expr::Phi { incoming: vec![] },
            ],
            vec![ValueId::from_index(0), ValueId::from_index(2)],
            vec![1],
            vec![vec![ValueId::from_index(1)]],
        );
        f.bindings.get_mut(ValueId::from_index(0)).unwrap().ty = receiver;
        f.bindings.get_mut(ValueId::from_index(1)).unwrap().ty = IrType::Known(vec_of(unknown()));
        crate::marshalling::test_support::module(vec![f])
    }

    #[test]
    fn a_pushed_vec_is_the_vec_it_was_pushed_onto() {
        let u32s = vec_of(IrType::Known(KnownType::U32));
        let mut ir = vec_op_on(sordec_ir::VecOpKind::PushBack, IrType::Known(u32s.clone()));
        TypeInferPass.run(&mut ir);
        assert_eq!(base_of(Some(&ty_of(&ir, 0, 1))), Some(u32s));
    }

    #[test]
    fn a_vec_op_names_its_result_only_from_a_vec_receiver() {
        // `vec_len` does not hand the vec back.
        let u32s = vec_of(IrType::Known(KnownType::U32));
        let mut ir = vec_op_on(sordec_ir::VecOpKind::Len, IrType::Known(u32s));
        TypeInferPass.run(&mut ir);
        assert_eq!(ty_of(&ir, 0, 1), IrType::Known(vec_of(unknown())));
        // A receiver known only as a `Val` says nothing of the elements.
        let mut ir = vec_op_on(sordec_ir::VecOpKind::Del, IrType::Known(KnownType::Val));
        TypeInferPass.run(&mut ir);
        assert_eq!(ty_of(&ir, 0, 1), IrType::Known(vec_of(unknown())));
    }

    /// `v3 = State { count: v0, owner: v1, memo: v2 }`, the struct declared
    /// `{ count: u32, owner: Address, memo: Bytes }`, with the field values
    /// typed as given, and the literal used.
    fn struct_literal(count: IrType, owner: IrType, memo: IrType) -> HighIr {
        use sordec_common::TypeId;
        use sordec_ir::{EnvCompatibility, SorobanFacts, StructField, TypeRegistry};
        let mut f = func_at(
            0,
            vec![
                Expr::Phi { incoming: vec![] },
                Expr::Phi { incoming: vec![] },
                Expr::Phi { incoming: vec![] },
                Expr::Struct {
                    fields: vec![
                        ("count".into(), ValueId::from_index(0)),
                        ("owner".into(), ValueId::from_index(1)),
                        ("memo".into(), ValueId::from_index(2)),
                    ],
                },
            ],
            (0..3).map(ValueId::from_index).collect(),
            vec![3],
            vec![vec![ValueId::from_index(3)]],
        );
        for (i, ty) in [count, owner, memo].into_iter().enumerate() {
            f.bindings.get_mut(ValueId::from_index(i as u32)).unwrap().ty = ty;
        }
        f.bindings.get_mut(ValueId::from_index(3)).unwrap().ty =
            IrType::Known(KnownType::UserDefined(TypeId::new(7)));
        let field = |name: &str, p| StructField { name: name.into(), ty: TypeRef::Primitive(p) };
        let mut m = crate::marshalling::test_support::module(vec![f]);
        m.soroban_facts = Some(SorobanFacts {
            functions: std::collections::BTreeMap::new(),
            types: TypeRegistry {
                structs: vec![StructDef {
                    id: TypeId::new(7),
                    name: "State".into(),
                    fields: vec![
                        field("count", PrimitiveType::U32),
                        field("owner", PrimitiveType::Address),
                        field("memo", PrimitiveType::Bytes),
                    ],
                }],
                ..Default::default()
            },
            contract_meta: std::collections::BTreeMap::new(),
            env_meta: EnvCompatibility::default(),
        });
        m
    }

    #[test]
    fn a_struct_literal_names_its_untyped_and_val_fields() {
        let mut ir = struct_literal(unknown(), IrType::Known(KnownType::Val), unknown());
        TypeInferPass.run(&mut ir);
        assert_eq!(ty_of(&ir, 0, 0), IrType::Inferred(KnownType::U32));
        assert_eq!(ty_of(&ir, 0, 1), IrType::Inferred(KnownType::Address));
        assert_eq!(ty_of(&ir, 0, 2), IrType::Inferred(KnownType::Bytes));
    }

    #[test]
    fn a_struct_field_value_with_a_type_of_its_own_keeps_it() {
        // A `BytesN<32>` stored in a `Bytes` field is the source's widening,
        // and a disagreement is evidence, not something to overwrite.
        let mut ir = struct_literal(
            IrType::Inferred(KnownType::I64),
            IrType::Known(KnownType::Address),
            IrType::Inferred(KnownType::BytesN(32)),
        );
        TypeInferPass.run(&mut ir);
        assert_eq!(ty_of(&ir, 0, 0), IrType::Inferred(KnownType::I64));
        assert_eq!(ty_of(&ir, 0, 2), IrType::Inferred(KnownType::BytesN(32)));
    }

    #[test]
    fn a_val_read_copied_into_an_address_is_an_address() {
        // `let v1 = read; v1.require_auth()`: the read is the host's `Val`,
        // the copy is proven an `Address`, and the read is that `Address`.
        let mut f = func_at(
            0,
            vec![
                Expr::Phi { incoming: vec![] },               // v0 the read
                Expr::Use(ValueId::from_index(0)),            // v1 its copy
                Expr::Semantic(SemanticOp::Known(KnownOp::RequireAuth { address: ValueId::from_index(1) })), // v2
            ],
            vec![],
            vec![0, 1, 2],
            vec![],
        );
        f.bindings.get_mut(ValueId::from_index(0)).unwrap().ty = IrType::Known(KnownType::Val);
        let mut ir = crate::marshalling::test_support::module(vec![f]);
        TypeInferPass.run(&mut ir);
        assert_eq!(ty_of(&ir, 0, 0), IrType::Inferred(KnownType::Address));
    }

    #[test]
    fn a_proven_number_plus_a_literal_is_that_number_proven() {
        let mut ir = increment_helper();
        TypeInferPass.run(&mut ir);
        assert_eq!(ty_of(&ir, 1, 2), IrType::Known(KnownType::U32), "`count + 1` is the count's type, not the word's");
    }

    #[test]
    fn a_call_to_a_helper_returning_a_proven_value_is_that_type() {
        let mut ir = increment_helper();
        TypeInferPass.run(&mut ir);
        assert_eq!(ty_of(&ir, 0, 0), IrType::Known(KnownType::U32), "the call is what the helper declares");
    }

    #[test]
    fn project_takes_the_matching_return_component() {
        // The `SretReturnPass` shape: a multi-value return read by picks.
        let callee = func_at(
            1,
            vec![Expr::Literal(Literal::I64(7)), Expr::Literal(Literal::U64(9))],
            vec![],
            vec![0, 1],
            vec![vec![ValueId::from_index(0), ValueId::from_index(1)]],
        );
        let caller = func_at(
            0,
            vec![
                Expr::Call { target: FuncId::from_index(1), args: vec![] },
                Expr::Project { value: ValueId::from_index(0), index: 0 },
                Expr::Project { value: ValueId::from_index(0), index: 1 },
            ],
            vec![],
            vec![0, 1, 2],
            vec![],
        );
        let mut ir = crate::marshalling::test_support::module(vec![caller, callee]);
        TypeInferPass.run(&mut ir);
        assert_eq!(ty_of(&ir, 0, 1), IrType::Inferred(KnownType::I64), "component 0");
        assert_eq!(ty_of(&ir, 0, 2), IrType::Inferred(KnownType::U64), "component 1");
        // A multi-value return has no single type, so the call itself stays
        // Unknown rather than being given one of the components'.
        assert!(matches!(ty_of(&ir, 0, 0), IrType::Unknown(_)));
    }

    /// Two callers, both passing an `i64`: the callee's parameter is that.
    fn two_callers(second_arg: Literal) -> HighIr {
        let callee = func_at(
            1,
            vec![Expr::Phi { incoming: vec![] }],
            vec![ValueId::from_index(0)],
            vec![],
            vec![],
        );
        let caller = |id: u32, lit: Literal| {
            func_at(
                id,
                vec![
                    Expr::Literal(lit),
                    Expr::Call {
                        target: FuncId::from_index(1),
                        args: vec![ValueId::from_index(0)],
                    },
                ],
                vec![],
                vec![0, 1],
                vec![],
            )
        };
        crate::marshalling::test_support::module(vec![
            caller(0, Literal::I64(1)),
            callee,
            caller(2, second_arg),
        ])
    }

    #[test]
    fn a_parameter_is_typed_from_agreeing_call_sites() {
        let mut ir = two_callers(Literal::I64(2));
        assert!(TypeInferPass.run(&mut ir).changed);
        assert_eq!(
            ty_of(&ir, 1, 0),
            IrType::Inferred(KnownType::I64),
            "both call sites pass i64, so the parameter is i64"
        );
    }

    #[test]
    fn disagreeing_call_sites_leave_the_parameter_unknown() {
        // The case that proves the join: taking the first witness would pin
        // `i64` onto a parameter one caller passes a `bool` to, and the
        // emitted signature would then be wrong rather than merely vague.
        let mut ir = two_callers(Literal::Bool(true));
        TypeInferPass.run(&mut ir);
        assert!(
            matches!(ty_of(&ir, 1, 0), IrType::Unknown(_)),
            "conflicting evidence has no sound single type, got {:?}",
            ty_of(&ir, 1, 0)
        );
    }

    #[test]
    fn disagreeing_call_sites_with_an_object_make_the_parameter_a_val() {
        // A `Symbol` crosses a call only as a `Val`, so a parameter one
        // caller hands a symbol to *is* a `Val`, whatever the other passes.
        let mut ir = two_callers(Literal::Symbol("approve".into()));
        TypeInferPass.run(&mut ir);
        assert!(
            matches!(ty_of(&ir, 1, 0), IrType::Inferred(KnownType::Val) | IrType::Known(KnownType::Val)),
            "an object among the witnesses proves the wire type, got {:?}",
            ty_of(&ir, 1, 0)
        );
    }

    #[test]
    fn mutual_recursion_terminates() {
        // fn0 calls fn1, fn1 calls fn0. The fixpoint is what makes this
        // safe: no SCC condensation, so a cycle must simply converge.
        let a = func_at(
            0,
            vec![Expr::Call { target: FuncId::from_index(1), args: vec![] }],
            vec![],
            vec![0],
            vec![],
        );
        let b = func_at(
            1,
            vec![Expr::Call { target: FuncId::from_index(0), args: vec![] }],
            vec![],
            vec![0],
            vec![],
        );
        let mut ir = crate::marshalling::test_support::module(vec![a, b]);
        // Neither returns anything, so there is nothing to learn — the point
        // is that asking terminates and stays honest.
        TypeInferPass.run(&mut ir);
        assert!(matches!(ty_of(&ir, 0, 0), IrType::Unknown(_)));
        assert!(matches!(ty_of(&ir, 1, 0), IrType::Unknown(_)));
    }

    // ---- end-to-end ----

    /// `fn add(u64, u64) -> u64 { v2 = v0 + v1; return v2 }`: params seed
    /// from the spec (`Known`), the sum propagates (`Inferred`), and the
    /// return type reaches the returned value.
    #[test]
    fn infers_params_and_arithmetic_end_to_end() {
        let prov = || Provenance::new("test", ProvenanceSource::Default, "seed");
        let mut bindings: Arena<ValueId, Binding> = Arena::default();
        let v0 = bindings.push(Binding::new(ValueId::from_index(0), unknown(), Expr::Phi { incoming: vec![] }, prov()));
        let v1 = bindings.push(Binding::new(ValueId::from_index(1), unknown(), Expr::Phi { incoming: vec![] }, prov()));
        let v2 = bindings.push(Binding::new(
            ValueId::from_index(2),
            unknown(),
            Expr::Binary { op: BinaryOp::Add, lhs: v0, rhs: v1 },
            prov(),
        ));

        let mut blocks: Arena<BlockId, HighBlock> = Arena::default();
        blocks.push(HighBlock { id: BlockId::from_index(0), bindings: vec![v2] });

        let sig = FunctionSignature {
            name: "add".to_string(),
            inputs: vec![
                FunctionParam { name: "a".to_string(), ty: TypeRef::Primitive(PrimitiveType::U64) },
                FunctionParam { name: "b".to_string(), ty: TypeRef::Primitive(PrimitiveType::U64) },
            ],
            outputs: vec![TypeRef::Primitive(PrimitiveType::U64)],
        };

        let mut func = HighFunction {
            id: FuncId::from_index(0),
            name: Some("add".to_string()),
            signature: Some(sig),
            aliases: Vec::new(),
            blocks,
            bindings,
            region: Region::Basic(BlockId::from_index(0)),
            params: vec![v0, v1],
            returns: vec![vec![v2]],
        };

        assert!(infer_isolated(&mut func), "types improved");
        assert_eq!(func.bindings.get(v0).unwrap().ty, IrType::Known(KnownType::U64), "param from spec");
        assert_eq!(func.bindings.get(v2).unwrap().ty, IrType::Inferred(KnownType::U64), "sum propagated");
        // Every improved binding carries a TypePropagation provenance entry.
        assert!(func
            .bindings
            .get(v2)
            .unwrap()
            .provenance()
            .iter()
            .any(|p| p.source == ProvenanceSource::TypePropagation));
    }
}
