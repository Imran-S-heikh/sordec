//! Read a `#[contracttype]` enum's discriminant back as its variant.
//!
//! Once a struct field carries the type its struct declares, a unit enum
//! arrives typed — and the integer arithmetic the compiler does on it
//! stops being expressible. timelock's `check_time_bound` is
//!
//! ```rust,ignore
//! match time_bound.kind {
//!     TimeBoundKind::Before => ledger <= time_bound.timestamp,
//!     TimeBoundKind::After  => ledger >= time_bound.timestamp,
//! }
//! ```
//!
//! which rustc compiles branchlessly to a `select` on the low bit of the
//! discriminant. Reconstructed literally that is `kind & 1`, which does
//! not compile: there is no `BitAnd` between an enum and an integer, and
//! nothing in the IR to compare the enum against instead.
//!
//! ```text
//! eqz(kind & 1)                 →   kind == TimeBoundKind::Before
//! select(a, b, kind & 1)        →   select(a, b, kind == …::After)
//! (kind & 1) == 1               →   kind == TimeBoundKind::After
//! ```
//!
//! # Why the mask is the discriminant
//!
//! A `#[contracttype]` enum of unit variants is numbered from zero in
//! declaration order, so a mask that covers exactly the declared range
//! selects the whole discriminant and nothing else. That is the gate: the
//! mask must be `len - 1` for a power-of-two variant count. A wider mask
//! reads bits the discriminant does not have, and a narrower one reads
//! only part of it — in both cases the value is not the variant.
//!
//! The bare mask is a `bool` only when there are exactly two variants, so
//! that rewrite is restricted to those; with more, `kind & 3` is a number
//! and only a comparison against a specific value names a variant.

use sordec_common::{IrId, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{
    BinaryOp, Expr, HighFunction, HighIr, IrType, KnownType, UnaryOp, UnionDef,
};

use crate::dataflow::{resolve_use, trace_int};
use crate::metrics_catalog::MARSHALLING_ENUM_DISCRIMINANTS as M_DISC;
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-enum-discriminant";

/// Names the variant a discriminant test is really about.
#[derive(Debug, Default, Clone, Copy)]
pub struct EnumDiscriminantPass;

impl Pass<HighIr> for EnumDiscriminantPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let Some(facts) = ir.soroban_facts.as_ref() else {
            return result;
        };
        let unions: Vec<UnionDef> = facts.types.unions.clone();
        if unions.is_empty() {
            return result;
        }
        for func in &mut ir.functions {
            let tests: Vec<(ValueId, BinaryOp, ValueId, String, IrType)> =
                func.bindings.iter().filter_map(|(id, b)| test(func, &unions, id, &b.expr)).collect();
            for (id, op, value, name, ty) in tests {
                let variant = ValueId::from_index(func.bindings.len() as u32);
                func.bindings.push(sordec_ir::Binding::new(
                    variant,
                    ty,
                    Expr::Variant { name },
                    Provenance::new(PASS_NAME, ProvenanceSource::SdkPattern, "the variant this discriminant is"),
                ));
                for (_, block) in func.blocks.iter_mut() {
                    if let Some(pos) = block.bindings.iter().position(|v| *v == id) {
                        block.bindings.insert(pos, variant);
                        break;
                    }
                }
                if let Some(b) = func.bindings.get_mut(id) {
                    b.expr = Expr::Binary { op, lhs: value, rhs: variant };
                    b.ty = IrType::Inferred(KnownType::Bool);
                    b.add_provenance(Provenance::new(
                        PASS_NAME,
                        ProvenanceSource::SdkPattern,
                        "a test on the discriminant is a test on the variant",
                    ));
                    result.metrics.increment(M_DISC, 1);
                    result.changed = true;
                }
            }
        }
        result
    }
}

/// The variant comparison a binding really is: the operator, the enum
/// value, the variant's name, and the enum's type.
fn test(
    func: &HighFunction,
    unions: &[UnionDef],
    id: ValueId,
    expr: &Expr,
) -> Option<(ValueId, BinaryOp, ValueId, String, IrType)> {
    let named = |value: ValueId, index: usize, op: BinaryOp| {
        let (enum_value, def, ty) = discriminant(func, unions, value)?;
        let name = def.cases.get(index)?.name.clone();
        Some((id, op, enum_value, name, ty))
    };
    match expr {
        // `kind & mask == 0` is the first variant, however it is spelled.
        Expr::Unary { op: UnaryOp::Eqz, value } => named(*value, 0, BinaryOp::Eq),
        Expr::Binary { op: op @ (BinaryOp::Eq | BinaryOp::Ne), lhs, rhs } => {
            let (masked, konst) = [(*lhs, *rhs), (*rhs, *lhs)]
                .into_iter()
                .find_map(|(m, k)| trace_int(func, k).map(|n| (m, n)))?;
            named(masked, usize::try_from(konst).ok()?, *op)
        }
        // The bare mask, which is a `bool` only with two variants — the
        // caller of `discriminant` has already checked the mask covers
        // the range, so a two-case union masks to 0 or 1.
        Expr::Binary { op: BinaryOp::BitAnd, .. } => {
            let (enum_value, def, ty) = discriminant(func, unions, id)?;
            (def.cases.len() == 2).then_some(())?;
            Some((id, BinaryOp::Eq, enum_value, def.cases.get(1)?.name.clone(), ty))
        }
        _ => None,
    }
}

/// The enum whose whole discriminant `value` masks out.
fn discriminant<'a>(
    func: &HighFunction,
    unions: &'a [UnionDef],
    value: ValueId,
) -> Option<(ValueId, &'a UnionDef, IrType)> {
    let Expr::Binary { op: BinaryOp::BitAnd, lhs, rhs } =
        &func.bindings.get(resolve_use(func, value))?.expr
    else {
        return None;
    };
    let (enum_value, mask) = [(*lhs, *rhs), (*rhs, *lhs)]
        .into_iter()
        .find_map(|(v, m)| trace_int(func, m).map(|n| (resolve_use(func, v), n)))?;
    let ty = func.bindings.get(enum_value)?.ty.clone();
    let (IrType::Known(KnownType::UserDefined(id)) | IrType::Inferred(KnownType::UserDefined(id))) = ty
    else {
        return None;
    };
    let def = unions.iter().find(|u| u.id == id)?;
    // Unit variants only: a variant with a payload is not a number.
    if def.cases.is_empty() || def.cases.iter().any(|c| !c.fields.is_empty()) {
        return None;
    }
    // The mask covers the declared range exactly.
    let want = i128::try_from(def.cases.len().next_power_of_two() - 1).ok()?;
    (mask == want).then_some((enum_value, def, ty))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};
    use sordec_common::TypeId;
    use sordec_ir::{
        EnvCompatibility, Literal, SorobanFacts, TypeRegistry, UnionCase,
    };

    fn unions() -> Vec<UnionDef> {
        vec![UnionDef {
            id: TypeId::new(4),
            name: "TimeBoundKind".to_string(),
            cases: vec![
                UnionCase { name: "Before".to_string(), fields: vec![] },
                UnionCase { name: "After".to_string(), fields: vec![] },
            ],
        }]
    }

    /// `k & mask`, with `eqz` over it and the bare mask both present.
    fn shape(mask: i32, typed: bool) -> HighIr {
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                             // v0 the enum
                Expr::Literal(Literal::I32(mask)),                          // v1
                Expr::Binary { op: BinaryOp::BitAnd, lhs: v(0), rhs: v(1) }, // v2
                Expr::Unary { op: UnaryOp::Eqz, value: v(2) },               // v3
            ],
            vec![v(0)],
            vec![1, 2, 3],
        );
        if typed {
            f.bindings.get_mut(v(0)).unwrap().ty =
                IrType::Known(KnownType::UserDefined(TypeId::new(4)));
        }
        let mut m = module(vec![f]);
        m.soroban_facts = Some(SorobanFacts {
            functions: std::collections::BTreeMap::new(),
            types: TypeRegistry { unions: unions(), ..Default::default() },
            contract_meta: std::collections::BTreeMap::new(),
            env_meta: EnvCompatibility::default(),
        });
        m
    }

    #[test]
    fn a_discriminant_test_names_the_variant() {
        let mut m = shape(1, true);
        assert!(EnumDiscriminantPass.run(&mut m).changed);
        let f = &m.functions[0];
        // `eqz(k & 1)` is the first variant; the bare mask is the second.
        for (id, want) in [(v(3), "Before"), (v(2), "After")] {
            let Expr::Binary { op: BinaryOp::Eq, lhs, rhs } = &f.bindings.get(id).unwrap().expr else {
                panic!("a comparison against a variant");
            };
            assert_eq!(*lhs, v(0));
            assert!(matches!(&f.bindings.get(*rhs).unwrap().expr, Expr::Variant { name } if name == want));
        }
    }

    /// A mask that is not the whole discriminant reads something else.
    #[test]
    fn a_partial_mask_is_left_alone() {
        let mut m = shape(3, true);
        assert!(!EnumDiscriminantPass.run(&mut m).changed);
    }

    /// Without the type there is no enum to name.
    #[test]
    fn an_untyped_value_is_left_alone() {
        let mut m = shape(1, false);
        assert!(!EnumDiscriminantPass.run(&mut m).changed);
    }
}
