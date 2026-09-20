//! Give a recovered struct's field its declared type, and drop the decode
//! that stood in for it.
//!
//! [`super::udt_decode`] names the struct and turns the unpacked slots into
//! field accesses, but each field arrives as a `Val` and the derived
//! conversion decodes it where it is used:
//!
//! ```text
//! c = state.count          : Val          c = state.count   : u32
//! n = val_decode(c)                  →    n = c
//! w = wrap32(n)                           (the width fold's, now that
//!                                          `c` has a width)
//! ```
//!
//! The declaration already says what `state.count` is. Reading it at that
//! type is what the source did, and the decode is the derive regenerating
//! itself — the same relocation argument as every other elision here.
//!
//! Every field is read at its declared type. Only the *decode* is
//! scalar-only: a field holding an object — an `Address`, a `Vec`, a
//! nested struct — is not decoded by this instruction, and its own
//! recognizers own it. They need the type to do so, which is why the
//! typing is not gated the same way.

use sordec_common::{Provenance, ProvenanceSource, ValueId};
use sordec_ir::{Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, SemanticOp, StructDef};

use crate::dataflow::resolve_use;
use crate::metrics_catalog::MARSHALLING_FIELD_TYPES as M_FIELDS;
use crate::pass::{Pass, PassResult};
use crate::type_infer::known_of_type_ref;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-field-type";

/// Types a recovered struct's fields and folds their decodes.
#[derive(Debug, Default, Clone, Copy)]
pub struct FieldTypePass;

impl Pass<HighIr> for FieldTypePass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let Some(facts) = ir.soroban_facts.as_ref() else {
            return result;
        };
        let structs: Vec<StructDef> = facts.types.structs.clone();
        if structs.is_empty() {
            return result;
        }
        for func in &mut ir.functions {
            // Fields whose declared type is a scalar the `Val` decode is
            // the conversion for, and the decodes that read them.
            let fields: Vec<(ValueId, KnownType)> = func
                .bindings
                .iter()
                .filter_map(|(id, b)| {
                    let Expr::Field { base, field } = &b.expr else {
                        return None;
                    };
                    // Typed whatever the declaration says. Only the
                    // *decode* below is scalar-only: reading a field at
                    // its declared type is right for an `Address` or a
                    // `String` too, and it is what lets the recognizers
                    // that own those — the tag-guard elision in
                    // particular — see a type rather than a bare `Val`.
                    Some((id, declared(func, &structs, *base, field)?))
                })
                .filter(|(id, ty)| func.bindings.get(*id).is_some_and(|b| b.ty != IrType::Known(ty.clone())))
                .collect();
            let decodes: Vec<(ValueId, KnownType)> = func
                .bindings
                .iter()
                .filter_map(|(id, b)| {
                    let Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { value })) = &b.expr
                    else {
                        return None;
                    };
                    let target = resolve_use(func, *value);
                    let Expr::Field { base, field } = &func.bindings.get(target)?.expr else {
                        return None;
                    };
                    let ty = declared(func, &structs, *base, field)?;
                    small(&ty).then_some((id, ty))
                })
                .collect();
            if fields.is_empty() && decodes.is_empty() {
                continue;
            }
            for (id, ty) in fields {
                if let Some(b) = func.bindings.get_mut(id) {
                    b.ty = IrType::Known(ty);
                    b.add_provenance(Provenance::new(
                        PASS_NAME,
                        ProvenanceSource::SdkPattern,
                        "the type the struct declares for this field",
                    ));
                    result.changed = true;
                }
            }
            for (id, ty) in decodes {
                let Some(value) = func.bindings.get(id).and_then(|b| match &b.expr {
                    Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { value })) => {
                        Some(resolve_use(func, *value))
                    }
                    _ => None,
                }) else {
                    continue;
                };
                if let Some(b) = func.bindings.get_mut(id) {
                    b.expr = Expr::Use(value);
                    b.ty = IrType::Known(ty);
                    b.add_provenance(Provenance::new(
                        PASS_NAME,
                        ProvenanceSource::SdkPattern,
                        "the field is read at its declared type: the decode is the derive's",
                    ));
                    result.metrics.increment(M_FIELDS, 1);
                    result.changed = true;
                }
            }
        }
        result
    }
}

/// The declared type of `base.field`, when `base` is a recovered struct.
fn declared(
    func: &HighFunction,
    structs: &[StructDef],
    base: ValueId,
    field: &str,
) -> Option<KnownType> {
    let ty = &func.bindings.get(resolve_use(func, base))?.ty;
    let (IrType::Known(KnownType::UserDefined(id)) | IrType::Inferred(KnownType::UserDefined(id))) = ty
    else {
        return None;
    };
    let def = structs.iter().find(|s| s.id == *id)?;
    known_of_type_ref(&def.fields.iter().find(|f| f.name == field)?.ty)
}

/// Whether a `Val` of this type carries its whole payload in the tag word,
/// which is what `val_decode` unpacks.
fn small(ty: &KnownType) -> bool {
    matches!(
        ty,
        KnownType::U32 | KnownType::I32 | KnownType::U64 | KnownType::I64 | KnownType::Bool
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};
    use sordec_common::TypeId;
    use sordec_ir::{
        EnvCompatibility, PrimitiveType, SorobanFacts, StructField, TypeRef, TypeRegistry,
    };

    fn registry() -> Vec<StructDef> {
        vec![StructDef {
            id: TypeId::new(7),
            name: "State".to_string(),
            fields: vec![
                StructField { name: "count".to_string(), ty: TypeRef::Primitive(PrimitiveType::U32) },
                StructField {
                    name: "owner".to_string(),
                    ty: TypeRef::Primitive(PrimitiveType::Address),
                },
            ],
        }]
    }

    /// `s.count` decoded, and `s.owner` — an object — left alone.
    fn shape() -> HighIr {
        let field = |name: &str| Expr::Field { base: v(0), field: name.to_string() };
        let decode = |value| Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { value }));
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] }, // v0 the struct
                field("count"),                 // v1
                decode(v(1)),                   // v2
                field("owner"),                 // v3
                decode(v(3)),                   // v4
            ],
            vec![v(0)],
            vec![1, 2, 3, 4],
        );
        f.bindings.get_mut(v(0)).unwrap().ty = IrType::Known(KnownType::UserDefined(TypeId::new(7)));
        let mut m = module(vec![f]);
        m.soroban_facts = Some(SorobanFacts {
            functions: std::collections::BTreeMap::new(),
            types: TypeRegistry { structs: registry(), ..Default::default() },
            contract_meta: std::collections::BTreeMap::new(),
            env_meta: EnvCompatibility::default(),
        });
        m
    }

    #[test]
    fn a_scalar_field_is_read_at_its_declared_type() {
        let mut m = shape();
        assert!(FieldTypePass.run(&mut m).changed);
        let f = &m.functions[0];
        assert_eq!(f.bindings.get(v(1)).unwrap().ty, IrType::Known(KnownType::U32));
        assert!(matches!(f.bindings.get(v(2)).unwrap().expr, Expr::Use(x) if x == v(1)));
    }

    /// An `Address` field is not unpacked by this instruction.
    #[test]
    fn an_object_field_keeps_its_decode() {
        let mut m = shape();
        FieldTypePass.run(&mut m);
        assert!(matches!(
            m.functions[0].bindings.get(v(4)).unwrap().expr,
            Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { .. }))
        ));
    }

    #[test]
    fn the_pass_is_idempotent() {
        let mut m = shape();
        assert!(FieldTypePass.run(&mut m).changed);
        assert!(!FieldTypePass.run(&mut m).changed);
    }
}
