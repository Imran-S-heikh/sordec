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

use std::collections::{HashMap, HashSet};

use sordec_common::{FuncId, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{
    BinaryOp, CompositeType, Expr, FunctionSignature, HighFunction, HighIr, IrType, KnownOp,
    KnownType, Literal, PrimitiveType, SemanticOp, TypeRef, UnaryOp, ValObjectKind, WasmOpcodeKind,
};

use crate::dataflow::{resolve_use, HighUseIndex};
use crate::effects::expr_effects;
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
        let mut disagreements: u64 = 0;
        for _ in 0..MAX_MODULE_ROUNDS {
            let mut round = false;
            // Counted fresh each round, not accumulated: the loop exits on a
            // round that changed nothing, so that round's count is the
            // settled one rather than a running total over rounds.
            disagreements = 0;
            for func in &mut ir.functions {
                let (func_changed, func_disagreements) = infer_function(func, &sigs);
                round |= func_changed;
                disagreements += func_disagreements;
            }
            let next = recompute_signatures(ir, &seed);
            if next != sigs {
                sigs = next;
                round = true;
            }
            changed |= round;
            if !round {
                break;
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
/// improvements back with `TypePropagation` provenance.
fn infer_function(func: &mut HighFunction, sigs: &SigTable) -> (bool, u64) {
    let mut types: HashMap<ValueId, IrType> =
        func.bindings.iter().map(|(id, b)| (id, b.ty.clone())).collect();
    // Structure does not change during inference, so this is built once.
    let uses = HighUseIndex::build(func);
    let mut ev = Evidence::default();

    seed_abi(func, &mut types, &mut ev);
    seed_params(func, sigs, &mut types, &mut ev);

    for _ in 0..MAX_ROUNDS {
        let mut round_changed = false;
        // Forward: each binding's type from its own expression.
        for (id, binding) in func.bindings.iter() {
            let cand = match &binding.expr {
                Expr::Phi { incoming } => phi_join_with_constants(func, incoming, &types),
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
        round_changed |= backward(func, &uses, &mut types, &mut ev);
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
        Expr::Call { target, .. } => match sigs.get(target)?.returns.as_slice() {
            [only] => only.to_ir(Certainty::Inferred),
            _ => None,
        },
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
            Expr::Binary { op, lhs, rhs } if is_arithmetic(*op) => {
                if let Some(base) = numeric_base(types.get(lhs), types.get(rhs)) {
                    changed |= improve(types, ev, *lhs, IrType::Inferred(base.clone()));
                    changed |= improve(types, ev, *rhs, IrType::Inferred(base));
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
                for (arg, ty) in semantic_arg_types(op) {
                    changed |= improve(types, ev, arg, IrType::Known(ty));
                }
            }
            _ => {}
        }
    }
    changed
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
        // Semantic ops are typed by the recognizers (host ABI); leave them.
        // Load/Store/GlobalGet/IndirectCall/Unknown stay for later waves.
        _ => None,
    }
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
            Some(_) => return None, // conflict
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
fn phi_join_with_constants(
    func: &HighFunction,
    incoming: &[(sordec_common::BlockId, ValueId)],
    types: &HashMap<ValueId, IrType>,
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
        // Val encode: the packed value IS the tag's payload type.
        K::ValEncodeSmall { ty, value } => vec![(*value, ty.clone())],
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
        _ => vec![],
    }
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
            | B::Rem
            | B::BitAnd
            | B::BitOr
            | B::BitXor
            | B::Shl
            | B::Shr
            | B::Rotl
            | B::Rotr
    )
}

fn is_comparison(op: BinaryOp) -> bool {
    use BinaryOp as B;
    matches!(op, B::Eq | B::Ne | B::Lt | B::Le | B::Gt | B::Ge | B::MulOverflows)
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
        match (self, other) {
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
            (Slot::Agreed(a), Slot::Agreed(b)) => {
                if a == b {
                    Slot::Agreed(a)
                } else {
                    Slot::Conflict
                }
            }
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

/// Recompute every non-ABI slot as a join over its witnesses.
///
/// Returns are witnessed by the function's own return sites; parameters by
/// every call site in the module that names it. Functions carrying a
/// `contractspecv0` signature keep the seeded ABI types untouched.
fn recompute_signatures(ir: &HighIr, seed: &SigTable) -> SigTable {
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
        for site in func.returns.iter().filter(|s| s.len() == arity) {
            for (index, (slot, value)) in slots.iter_mut().zip(site).enumerate() {
                let witness = Slot::witness(func.bindings.get(*value).map(|b| &b.ty));
                if let Some(n) = int_constant(func, *value) {
                    held[index].push((n, witness));
                    continue;
                }
                *slot = std::mem::replace(slot, Slot::Bottom).join(witness);
            }
        }
        for (slot, consts) in slots.iter_mut().zip(held) {
            let agrees = matches!(&*slot, Slot::Agreed(k) if consts.iter().all(|(n, w)| fits_constant(k, *n, w)));
            if !agrees {
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
        entry.returns = slots;
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
                *slot = std::mem::replace(slot, Slot::Bottom).join(witness);
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
        (KnownType::Vec(have), KnownType::Vec(got))
            if matches!(*have, IrType::Unknown(_)) && !matches!(*got, IrType::Unknown(_)) =>
        {
            Some(rewrap(KnownType::Vec(got)))
        }
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
fn numeric_base(lhs: Option<&IrType>, rhs: Option<&IrType>) -> Option<KnownType> {
    [base_of(lhs), base_of(rhs)]
        .into_iter()
        .flatten()
        .find(KnownType::is_numeric)
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

fn primitive_to_known(p: PrimitiveType) -> KnownType {
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
    use sordec_ir::{Binding, FunctionParam, HighBlock, Region};

    fn unknown() -> IrType {
        IrType::Unknown(sordec_common::UnknownReason::InsufficientEvidence)
    }

    /// Run only the intra-procedural half: no inter-procedural evidence, so
    /// a single function can be tested without building a module around it.
    fn infer_isolated(func: &mut HighFunction) -> bool {
        infer_function(func, &SigTable::new()).0
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
        assert_eq!(phi_join_with_constants(&f, incoming, &types), Some(IrType::Inferred(KnownType::U32)));
        let Expr::Phi { incoming } = &f.bindings.get(v(4)).unwrap().expr else { unreachable!() };
        assert_eq!(
            phi_join_with_constants(&f, incoming, &types),
            Some(IrType::Inferred(KnownType::I64)),
            "nothing else typed: the constant is the evidence"
        );
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
