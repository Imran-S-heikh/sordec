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
//! type only ever rises in certainty, and an equal-rank candidate never
//! displaces the incumbent. That guarantees the fixpoint terminates and is
//! order-deterministic. A binding the recognizers already proved (`Known`)
//! is never overwritten.
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

use std::collections::HashMap;

use sordec_common::{FuncId, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{
    BinaryOp, CompositeType, Expr, FunctionSignature, HighFunction, HighIr, IrType, KnownOp,
    KnownType, Literal, PrimitiveType, SemanticOp, TypeRef, UnaryOp, ValObjectKind,
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
    let mut disagreements: u64 = 0;

    seed_abi(func, &mut types);
    seed_params(func, sigs, &mut types, &mut disagreements);

    for _ in 0..MAX_ROUNDS {
        let mut round_changed = false;
        // Forward: each binding's type from its own expression.
        for (id, binding) in func.bindings.iter() {
            if let Some(cand) = infer_expr(&binding.expr, &types) {
                round_changed |= improve(&mut types, id, cand);
            }
            // Across a call: the callee's return components.
            if let Some(cand) = infer_call_result(func, &binding.expr, sigs) {
                round_changed |= improve_tracked(&mut types, id, cand, &mut disagreements);
            }
        }
        // Backward: uses constrain their operands / returned values.
        round_changed |= backward(func, &uses, &mut types);
        round_changed |= backward_calls(func, sigs, &mut types, &mut disagreements);
        round_changed |= backward_returns(func, sigs, &mut types, &mut disagreements);
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
        if let Some(binding) = func.bindings.get_mut(id)
            && rank(&cand) > rank(&binding.ty)
        {
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
    (changed, disagreements)
}

/// Seed the entry parameters and returned values from the `contractspecv0`
/// signature — the proven ABI boundary (`Known`).
fn seed_abi(func: &HighFunction, types: &mut HashMap<ValueId, IrType>) {
    let Some(sig) = &func.signature else {
        return;
    };
    // Parameters: positional against the entry block params (1 Val per
    // logical arg in the Soroban ABI).
    for (param, input) in func.params.iter().zip(&sig.inputs) {
        if let Some(ty) = type_ref_to_ir(&input.ty, Certainty::Known) {
            improve(types, *param, ty);
        }
    }
    seed_returns(func, sig, types);
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
    disagreements: &mut u64,
) {
    let Some(sig) = sigs.get(&func.id) else {
        return;
    };
    for (param, slot) in func.params.iter().zip(&sig.params) {
        if let Some(ty) = slot.to_ir(Certainty::Inferred) {
            improve_tracked(types, *param, ty, disagreements);
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
    disagreements: &mut u64,
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
                changed |= improve_tracked(types, *arg, ty, disagreements);
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
    disagreements: &mut u64,
) -> bool {
    let Some(sig) = sigs.get(&func.id) else {
        return false;
    };
    let mut changed = false;
    for site in func.returns.iter().filter(|s| s.len() == sig.returns.len()) {
        for (value, slot) in site.iter().zip(&sig.returns) {
            if let Some(ty) = slot.to_ir(Certainty::Inferred) {
                changed |= improve_tracked(types, *value, ty, disagreements);
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
) {
    for site in &func.returns {
        for (value, out) in site.iter().zip(&sig.outputs) {
            if let Some(ty) = type_ref_to_ir(out, Certainty::Inferred) {
                improve(types, *value, ty);
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
) -> bool {
    let mut changed = false;
    for (id, binding) in func.bindings.iter() {
        if uses.is_unused(id) && expr_effects(&binding.expr).is_pure_total() {
            continue;
        }
        match &binding.expr {
            // Arithmetic: both operands share the result's integer type.
            Expr::Binary { op, lhs, rhs } if is_arithmetic(*op) => {
                if let Some(base) = base_of(types.get(lhs)).or_else(|| base_of(types.get(rhs))) {
                    changed |= improve(types, *lhs, IrType::Inferred(base.clone()));
                    changed |= improve(types, *rhs, IrType::Inferred(base));
                }
            }
            // Comparison: the two operands share one type (the result is
            // `bool`, handled forward).
            Expr::Binary { op, lhs, rhs } if is_comparison(*op) => {
                if let Some(base) = base_of(types.get(lhs)).or_else(|| base_of(types.get(rhs))) {
                    changed |= improve(types, *lhs, IrType::Inferred(base.clone()));
                    changed |= improve(types, *rhs, IrType::Inferred(base));
                }
            }
            // Host-call arguments and conversions: back-type the operands
            // the recovered op's ABI pins (Mo's "host-call arguments" +
            // "conversions" categories).
            Expr::Semantic(SemanticOp::Known(op)) => {
                for (arg, ty) in semantic_arg_types(op) {
                    changed |= improve(types, arg, IrType::Inferred(ty));
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
        // Semantic ops are typed by the recognizers (host ABI); leave them.
        // Load/Store/GlobalGet/IndirectCall/Unknown stay for later waves.
        _ => None,
    }
}

/// Join the incoming edges of a phi: `Inferred(T)` when every resolved edge
/// agrees on base `T`, else `None` (arms disagree — honestly `Unknown`).
fn phi_join(
    incoming: &[(sordec_common::BlockId, ValueId)],
    types: &HashMap<ValueId, IrType>,
) -> Option<IrType> {
    let mut agreed: Option<KnownType> = None;
    for (_, value) in incoming {
        let base = base_of(types.get(value))?;
        match &agreed {
            None => agreed = Some(base),
            Some(prev) if *prev == base => {}
            Some(_) => return None, // conflict
        }
    }
    agreed.map(IrType::Inferred)
}

fn unary_result(op: UnaryOp, operand: Option<&IrType>) -> Option<IrType> {
    match op {
        // Sign/bit flips preserve the operand's numeric type.
        UnaryOp::Neg | UnaryOp::Not | UnaryOp::BitNot | UnaryOp::Abs => {
            base_of(operand).map(IrType::Inferred)
        }
        // Bit-count intrinsics yield u32.
        UnaryOp::Clz | UnaryOp::Ctz | UnaryOp::Popcnt => Some(IrType::Inferred(KnownType::U32)),
        // Float ops don't occur in Soroban; leave untyped.
        UnaryOp::Sqrt | UnaryOp::Floor | UnaryOp::Ceil | UnaryOp::Trunc => None,
    }
}

fn binary_result(op: BinaryOp, lhs: Option<&IrType>, rhs: Option<&IrType>) -> Option<IrType> {
    if is_comparison(op) {
        return Some(IrType::Inferred(KnownType::Bool));
    }
    // Arithmetic / bitwise: the result is the shared integer type of the
    // operands (whichever side is known).
    base_of(lhs).or_else(|| base_of(rhs)).map(IrType::Inferred)
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
    matches!(op, B::Eq | B::Ne | B::Lt | B::Le | B::Gt | B::Ge)
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
        for site in func.returns.iter().filter(|s| s.len() == arity) {
            for (slot, value) in slots.iter_mut().zip(site) {
                let witness = Slot::witness(func.bindings.get(*value).map(|b| &b.ty));
                *slot = std::mem::replace(slot, Slot::Bottom).join(witness);
            }
        }
        entry.returns = slots;
    }

    // Parameters: one pass over every call in the module.
    let mut evidence: HashMap<FuncId, Vec<Slot>> = ir
        .functions
        .iter()
        .filter(|f| f.signature.is_none())
        .map(|f| (f.id, vec![Slot::Bottom; f.params.len()]))
        .collect();
    for caller in &ir.functions {
        for (_, binding) in caller.bindings.iter() {
            let Expr::Call { target, args } = &binding.expr else {
                continue;
            };
            let Some(slots) = evidence.get_mut(target) else {
                continue;
            };
            for (slot, arg) in slots.iter_mut().zip(args) {
                let witness = Slot::witness(caller.bindings.get(*arg).map(|b| &b.ty));
                *slot = std::mem::replace(slot, Slot::Bottom).join(witness);
            }
        }
    }
    for (id, slots) in evidence {
        if let Some(entry) = table.get_mut(&id) {
            entry.params = slots;
        }
    }
    table
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

/// Raise `types[id]` to `cand` iff `cand` is strictly higher certainty.
/// Monotonic: equal rank never displaces the incumbent, so the fixpoint
/// converges and is order-deterministic.
fn improve(types: &mut HashMap<ValueId, IrType>, id: ValueId, cand: IrType) -> bool {
    let slot = types.entry(id).or_insert(IrType::Unknown(
        sordec_common::UnknownReason::InsufficientEvidence,
    ));
    if rank(&cand) > rank(slot) {
        *slot = cand;
        true
    } else {
        false
    }
}

/// [`improve`], but counting the case where inter-procedural evidence names
/// a *different* type at the same certainty rank as the incumbent.
///
/// `improve` deliberately never displaces an equal-rank type, so such a
/// disagreement is silently dropped. The alternative — lowering both to
/// `Unknown` — is arguably more honest but restructures what `improve`
/// means, so the rate was measured before paying for it: **17 across the
/// whole corpus**, against 7,736 inferred types. The conservative choice
/// costs essentially nothing, so the lattice stands as documented and this
/// counter is the guard that says so. A future run where it climbs is the
/// signal to revisit.
fn improve_tracked(
    types: &mut HashMap<ValueId, IrType>,
    id: ValueId,
    cand: IrType,
    disagreements: &mut u64,
) -> bool {
    if let Some(incumbent) = types.get(&id)
        && rank(&cand) == rank(incumbent)
        && rank(&cand) > 0
        && base_of(Some(&cand)) != base_of(Some(incumbent))
    {
        *disagreements += 1;
    }
    improve(types, id, cand)
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
        TypeRef::Unknown(_) => return None,
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
        IrType::Unknown(UnknownReason::InsufficientEvidence)
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
        let id = ValueId::from_index(0);
        m.insert(id, unknown());
        // Unknown → Inferred upgrades.
        assert!(improve(&mut m, id, IrType::Inferred(KnownType::U64)));
        // Inferred → Inferred of a different base does NOT displace (stable).
        assert!(!improve(&mut m, id, IrType::Inferred(KnownType::I64)));
        assert_eq!(m[&id], IrType::Inferred(KnownType::U64));
        // Inferred → Known upgrades.
        assert!(improve(&mut m, id, IrType::Known(KnownType::U64)));
        // Known is never downgraded.
        assert!(!improve(&mut m, id, IrType::Inferred(KnownType::Bool)));
        assert_eq!(m[&id], IrType::Known(KnownType::U64));
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

    #[test]
    fn bit_count_is_u32_neg_preserves() {
        assert_eq!(
            unary_result(UnaryOp::Clz, Some(&IrType::Known(KnownType::U64))),
            Some(IrType::Inferred(KnownType::U32))
        );
        assert_eq!(
            unary_result(UnaryOp::Neg, Some(&IrType::Known(KnownType::I128))),
            Some(IrType::Inferred(KnownType::I128))
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
        // An unresolved arm → None (wait for it).
        assert_eq!(
            phi_join(&[(BlockId::from_index(0), a), (BlockId::from_index(1), ValueId::from_index(9))], &types),
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
