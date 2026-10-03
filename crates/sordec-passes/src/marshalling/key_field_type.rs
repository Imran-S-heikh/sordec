//! Type a synthesized key variant's fields from the values put in them.
//!
//! A module built with `strip = true` carries no `contractspecv0`, so
//! `recognizers::enum_key` recovers the key union from its own derived
//! converter: the variant *names* are rodata symbols in the switch and
//! the arm's case value is the discriminant. What the converter does not
//! carry is the fields' types, so each is synthesized
//! `Unknown(InsufficientEvidence)` — which the emitter renders `Val`:
//!
//! ```text
//! pub enum StorageKey { Allowance(Val, Val), Balance(Val), … }
//! …
//! .get(&StorageKey::Allowance(from.clone(), spender.clone()))
//! ```
//!
//! The declaration says `Val` and every construction site hands it an
//! `Address`. Both halves are right on their own: the type genuinely was
//! not in the binary, and the values genuinely are `Address`es.
//!
//! The values are the evidence the declaration lacks. Where every site
//! agrees on a field's type, that is the field's type — and the recovered
//! enum then reads as the source wrote it, `Allowance(Address, Address)`.
//!
//! ## What it will not do
//!
//! - **Touch a field the spec declared.** Only `Unknown` is filled; a
//!   module with a spec has nothing here to recover and nothing to
//!   second-guess.
//! - **Choose between disagreeing sites.** Two sites putting different
//!   types in one field means the field really is a `Val` (or that
//!   something upstream is wrong); either way picking one would be a
//!   guess, so the field stays as it is.
//! - **Fill from an unrecovered value.** An `Unknown` payload witnesses
//!   nothing.

use std::collections::BTreeMap;

use sordec_ir::{Expr, HighIr, IrType, SemanticOp, TypeRef};

use crate::pass::{Pass, PassResult};
use crate::type_infer::primitive_of_known;

/// Pass name.
pub const PASS_NAME: &str = "marshalling-key-field-type";

/// Synthesized key fields typed from their construction sites.
const M_TYPED: &str = "marshalling_key_fields_typed";
/// Fields left alone because the sites disagreed about the type.
const M_DISAGREED: &str = "marshalling_key_fields_disagreed";

/// Fills a synthesized key union's `Unknown` field types.
#[derive(Debug, Default, Clone, Copy)]
pub struct KeyFieldTypePass;

/// What the construction sites witnessed for one `(variant, position)`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Witness {
    One(sordec_ir::PrimitiveType),
    Disagreed,
}

impl Pass<HighIr> for KeyFieldTypePass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        if ir.soroban_facts.is_none() {
            return result;
        }
        let witnessed = witnesses(ir);
        if witnessed.is_empty() {
            return result;
        }

        let Some(facts) = ir.soroban_facts.as_mut() else {
            return result;
        };
        for union in &mut facts.types.unions {
            for case in &mut union.cases {
                for (index, field) in case.fields.iter_mut().enumerate() {
                    if !matches!(field, TypeRef::Unknown(_)) {
                        continue;
                    }
                    match witnessed.get(&(union.name.clone(), case.name.clone(), index)) {
                        Some(Witness::One(p)) => {
                            *field = TypeRef::Primitive(*p);
                            result.metrics.increment(M_TYPED, 1);
                            result.changed = true;
                        }
                        Some(Witness::Disagreed) => {
                            result.metrics.increment(M_DISAGREED, 1);
                        }
                        None => {}
                    }
                }
            }
        }
        result
    }
}

/// What every resolved key construction in the module puts in each
/// `(enum, variant, field position)`.
fn witnesses(ir: &HighIr) -> BTreeMap<(String, String, usize), Witness> {
    let mut out: BTreeMap<(String, String, usize), Witness> = BTreeMap::new();
    for func in &ir.functions {
        for (_, binding) in func.bindings.iter() {
            let Expr::Semantic(SemanticOp::Known(op)) = &binding.expr else {
                continue;
            };
            let Some(key) = resolved_key(op) else {
                continue;
            };
            for (index, value) in key.payload.iter().enumerate() {
                // Only a *primitive* witness. A user-defined or composite
                // payload type needs a `TypeId` that means the same thing
                // in this registry, and nothing here establishes that.
                let Some(p) = func
                    .bindings
                    .get(*value)
                    .and_then(|b| match &b.ty {
                        IrType::Known(k) | IrType::Inferred(k) => primitive_of_known(k),
                        IrType::Unknown(_) => None,
                    })
                else {
                    continue;
                };
                let slot = (key.enum_name.clone(), key.variant.clone(), index);
                out.entry(slot)
                    .and_modify(|w| {
                        if *w != Witness::One(p) {
                            *w = Witness::Disagreed;
                        }
                    })
                    .or_insert(Witness::One(p));
            }
        }
    }
    out
}

/// The recovered key a storage op names, where it names one.
fn resolved_key(op: &sordec_ir::KnownOp) -> Option<&sordec_ir::EnumKey> {
    use sordec_ir::KnownOp as K;
    match op {
        K::StorageGet { resolved_key, .. }
        | K::StorageSet { resolved_key, .. }
        | K::StorageHas { resolved_key, .. }
        | K::StorageRemove { resolved_key, .. }
        | K::StorageExtendTtl { resolved_key, .. } => resolved_key.as_ref(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};
    use sordec_common::{IrId, TypeId, UnknownReason};
    use sordec_ir::{
        EnumKey, KnownOp, KnownTier, Missing, PrimitiveType, SorobanFacts, StorageTier, UnionCase,
        UnionDef,
    };

    fn stripped_union() -> UnionDef {
        UnionDef {
            id: TypeId::from_index(0),
            name: "StorageKey".to_string(),
            cases: vec![UnionCase {
                name: "Balance".to_string(),
                fields: vec![TypeRef::Unknown(UnknownReason::InsufficientEvidence)],
            }],
        }
    }

    fn get_with(payload: Vec<sordec_common::ValueId>) -> Expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet {
            tier: StorageTier::Known(KnownTier::Persistent),
            durability: v(0),
            key: v(0),
            resolved_key: Some(EnumKey {
                enum_name: "StorageKey".to_string(),
                variant: "Balance".to_string(),
                payload,
            }),
            missing: Missing::Option,
        }))
    }

    fn with_union(mut ir: HighIr) -> HighIr {
        let mut facts = SorobanFacts::default();
        facts.types.unions.push(stripped_union());
        ir.soroban_facts = Some(facts);
        ir
    }

    /// The whole point: the declaration had no type and the construction
    /// site does.
    #[test]
    fn a_field_takes_the_type_its_sites_put_in_it() {
        let mut f = func_with(vec![Expr::Phi { incoming: vec![] }, get_with(vec![v(0)])], vec![], vec![1]);
        f.bindings.get_mut(v(0)).expect("the payload").ty =
            IrType::Known(sordec_ir::KnownType::Address);
        let mut ir = with_union(module(vec![f]));

        assert!(KeyFieldTypePass.run(&mut ir).changed);
        let field = &ir.soroban_facts.expect("facts").types.unions[0].cases[0].fields[0];
        assert!(
            matches!(field, TypeRef::Primitive(PrimitiveType::Address)),
            "typed from the site, got {field:?}"
        );
    }

    /// The half that matters: two sites disagreeing means the field really
    /// is untyped, and picking one would be a guess.
    #[test]
    fn disagreeing_sites_leave_the_field_alone() {
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },
                Expr::Phi { incoming: vec![] },
                get_with(vec![v(0)]),
                get_with(vec![v(1)]),
            ],
            vec![],
            vec![2, 3],
        );
        f.bindings.get_mut(v(0)).expect("a").ty = IrType::Known(sordec_ir::KnownType::Address);
        f.bindings.get_mut(v(1)).expect("b").ty = IrType::Known(sordec_ir::KnownType::U32);
        let mut ir = with_union(module(vec![f]));

        let result = KeyFieldTypePass.run(&mut ir);
        assert!(!result.changed, "nothing agreed");
        assert_eq!(result.metrics.get(M_DISAGREED), Some(1), "and it says why");
    }

    /// A field the spec declared is never second-guessed.
    #[test]
    fn a_declared_field_is_untouched() {
        let mut f = func_with(vec![Expr::Phi { incoming: vec![] }, get_with(vec![v(0)])], vec![], vec![1]);
        f.bindings.get_mut(v(0)).expect("the payload").ty =
            IrType::Known(sordec_ir::KnownType::Address);
        let mut ir = with_union(module(vec![f]));
        if let Some(facts) = ir.soroban_facts.as_mut() {
            facts.types.unions[0].cases[0].fields[0] = TypeRef::Primitive(PrimitiveType::U32);
        }

        assert!(!KeyFieldTypePass.run(&mut ir).changed, "the spec wins");
    }
}
