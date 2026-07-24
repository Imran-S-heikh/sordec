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

use std::collections::HashMap;

use sordec_common::{Provenance, ProvenanceSource, ValueId};
use sordec_ir::{
    BinaryOp, CompositeType, Expr, FunctionSignature, HighFunction, HighIr, IrType, KnownType,
    Literal, PrimitiveType, TypeRef, UnaryOp,
};

use crate::pass::{Pass, PassResult};

/// Unique pipeline name of this pass.
pub const PASS_NAME: &str = "type-infer";

/// Bindings with a proven [`IrType::Known`] type.
const M_TYPES_KNOWN: &str = "types_known";
/// Bindings with a derived [`IrType::Inferred`] type.
const M_TYPES_INFERRED: &str = "types_inferred";
/// Bindings still [`IrType::Unknown`] after propagation.
const M_TYPES_UNKNOWN: &str = "types_unknown";

/// Safety bound on propagation rounds. The lattice is monotonic so this is
/// never the reason a run stops in practice; it caps a pathological input.
const MAX_ROUNDS: usize = 64;

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
        for func in &mut ir.functions {
            changed |= infer_function(func);
        }
        // Census the settled types (feeds the `coverage` typedness metric).
        for func in &ir.functions {
            for (_, binding) in func.bindings.iter() {
                match binding.ty {
                    IrType::Known(_) => result.metrics.increment(M_TYPES_KNOWN, 1),
                    IrType::Inferred(_) => result.metrics.increment(M_TYPES_INFERRED, 1),
                    IrType::Unknown(_) => result.metrics.increment(M_TYPES_UNKNOWN, 1),
                }
            }
        }
        result.changed = changed;
        result
    }
}

/// Infer types for one function to a fixpoint; return whether any binding's
/// type improved. Works on a `ValueId -> IrType` snapshot and writes the
/// improvements back with `TypePropagation` provenance.
fn infer_function(func: &mut HighFunction) -> bool {
    let mut types: HashMap<ValueId, IrType> =
        func.bindings.iter().map(|(id, b)| (id, b.ty.clone())).collect();

    seed_abi(func, &mut types);

    for _ in 0..MAX_ROUNDS {
        let mut round_changed = false;
        // Forward: each binding's type from its own expression.
        for (id, binding) in func.bindings.iter() {
            if let Some(cand) = infer_expr(&binding.expr, &types) {
                round_changed |= improve(&mut types, id, cand);
            }
        }
        // Backward: uses constrain their operands / returned values.
        round_changed |= backward(func, &mut types);
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
    changed
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
fn backward(func: &HighFunction, types: &mut HashMap<ValueId, IrType>) -> bool {
    let mut changed = false;
    for (_, binding) in func.bindings.iter() {
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

fn known_of_type_ref(t: &TypeRef) -> Option<KnownType> {
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

        assert!(infer_function(&mut func), "types improved");
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
