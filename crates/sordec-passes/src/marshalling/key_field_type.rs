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
//!
//! ## And then the keys are cut to size
//!
//! A key read out of a frame takes the word slots after its discriminant,
//! and the frame runs on past the key to whatever rustc laid out next.
//! `recognizers::enum_key` cuts the slot list to the variant's footprint —
//! but only when the field types say how wide it is, and a stripped
//! module's are `Unknown` when that runs. So token-v23-stripped's TTL bump
//! named `Allowance(from, spender, 0, from, spender, amount, …)`: nine
//! values for a two-field variant, the last seven being the allowance
//! record stored beside it.
//!
//! Once the fields are typed the footprint is known, and the same cut
//! applies. Only where every field is one word — then a slot is a field
//! and the first `n` slots are the `n` fields, exactly as the recogniser
//! would have taken them.

use std::collections::BTreeMap;

use sordec_ir::{Expr, HighIr, IrType, SemanticOp, TypeRef};

use crate::pass::{Pass, PassResult};
use crate::recognizers::enum_key::case_footprint;
use crate::type_infer::{primitive_of_known, primitive_to_known};

/// Pass name.
pub const PASS_NAME: &str = "marshalling-key-field-type";

/// Synthesized key fields typed from their construction sites.
const M_TYPED: &str = "marshalling_key_fields_typed";
/// Fields left alone because the sites disagreed about the type.
const M_DISAGREED: &str = "marshalling_key_fields_disagreed";
/// Frame loads typed from the key field they fill.
const M_LOADS_TYPED: &str = "marshalling_key_payload_loads_typed";
/// Frame-read keys cut back to their variant's now-known footprint.
const M_TRIMMED: &str = "marshalling_key_payloads_trimmed";

/// Fills a synthesized key union's `Unknown` field types.
#[derive(Debug, Default, Clone, Copy)]
pub struct KeyFieldTypePass;

/// What the construction sites witnessed for one `(variant, position)`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Witness {
    One(Field),
    Disagreed,
}

/// A field type a site can witness: a primitive, or `BytesN<N>`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Field {
    Primitive(sordec_ir::PrimitiveType),
    BytesN(u32),
}

impl Field {
    const VAL: Field = Field::Primitive(sordec_ir::PrimitiveType::Val);

    fn type_ref(self) -> TypeRef {
        match self {
            Field::Primitive(p) => TypeRef::Primitive(p),
            Field::BytesN(n) => TypeRef::Composite(sordec_ir::CompositeType::BytesN(n)),
        }
    }
}

impl Witness {
    /// This witness joined with another site's `ty`.
    ///
    /// A `Val` gives way to a concrete type rather than disagreeing with
    /// it. `Val` is what every type travels as, so a site holding one is a
    /// site whose type was not recovered, not one that put a different type
    /// in the field: `account` builds `Signer` from a `BytesN<32>` in its
    /// constructor and from a frame word typed only `Val` in
    /// `__check_auth`, and the source's field is `BytesN<32>`.
    fn join(self, ty: Field) -> Self {
        match self {
            Witness::One(seen) if seen == ty || ty == Field::VAL => Witness::One(seen),
            Witness::One(Field::VAL) => Witness::One(ty),
            _ => Witness::Disagreed,
        }
    }
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
                        Some(Witness::One(ty)) => {
                            *field = ty.type_ref();
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
        trim_payloads(ir, &mut result);
        type_payload_loads(ir, &mut result);
        result
    }
}

/// Type each untyped frame load a key puts in a now-typed field.
///
/// The field's type is what the source put there, so it is the type of
/// every value put there. Only a `Load` takes it: a load's type is whatever
/// its reader says, and nothing has said anything here but `Val`, while any
/// other value's `Val` was derived from its own definition and is not this
/// pass's to overrule. `account`'s `__check_auth` reads the signer's public
/// key out of the frame and so held it as a `Val`, which neither the key nor
/// the `ed25519_verify` it feeds would take.
fn type_payload_loads(ir: &mut HighIr, result: &mut PassResult) {
    let Some(facts) = ir.soroban_facts.as_ref() else {
        return;
    };
    let mut fields: BTreeMap<(String, String), Vec<sordec_ir::KnownType>> = BTreeMap::new();
    for union in &facts.types.unions {
        for case in &union.cases {
            let known = case.fields.iter().map(|f| match f {
                TypeRef::Composite(sordec_ir::CompositeType::BytesN(n)) => {
                    Some(sordec_ir::KnownType::BytesN(*n))
                }
                TypeRef::Primitive(p) if *p != sordec_ir::PrimitiveType::Val => {
                    Some(primitive_to_known(*p))
                }
                _ => None,
            });
            // A `None` stands for "leave it": kept positional.
            let known: Vec<_> = known.map(|k| k.unwrap_or(sordec_ir::KnownType::Val)).collect();
            fields.insert((union.name.clone(), case.name.clone()), known);
        }
    }
    for func in &mut ir.functions {
        let mut retype = Vec::new();
        for (_, binding) in func.bindings.iter() {
            let Expr::Semantic(SemanticOp::Known(op)) = &binding.expr else {
                continue;
            };
            let Some(key) = resolved_key(op) else {
                continue;
            };
            let Some(types) = fields.get(&(key.enum_name.clone(), key.variant.clone())) else {
                continue;
            };
            for (value, ty) in key.payload.iter().zip(types) {
                if *ty != sordec_ir::KnownType::Val {
                    retype.push((*value, ty.clone()));
                }
            }
        }
        for (value, ty) in retype {
            let Some(binding) = func.bindings.get_mut(value) else {
                continue;
            };
            let untyped = match &binding.ty {
                IrType::Known(k) | IrType::Inferred(k) => *k == sordec_ir::KnownType::Val,
                IrType::Unknown(_) => true,
            };
            if untyped && matches!(binding.expr, Expr::Load { .. }) {
                binding.ty = IrType::Inferred(ty);
                result.metrics.increment(M_LOADS_TYPED, 1);
                result.changed = true;
            }
        }
    }
}

/// Cut every resolved key whose payload runs past its variant's fields,
/// where each field is now known to be one frame word.
fn trim_payloads(ir: &mut HighIr, result: &mut PassResult) {
    let Some(facts) = ir.soroban_facts.as_ref() else {
        return;
    };
    let types = &facts.types;
    // (enum, variant) → field count, for variants whose every field is one
    // word wide.
    let mut one_word: BTreeMap<(String, String), usize> = BTreeMap::new();
    for union in &types.unions {
        for case in &union.cases {
            let each_one = case
                .fields
                .iter()
                .all(|f| case_footprint(types, std::slice::from_ref(f)) == Some(1));
            if each_one && !case.fields.is_empty() {
                one_word.insert((union.name.clone(), case.name.clone()), case.fields.len());
            }
        }
    }
    if one_word.is_empty() {
        return;
    }
    for func in &mut ir.functions {
        for (_, binding) in func.bindings.iter_mut() {
            let Expr::Semantic(SemanticOp::Known(op)) = &mut binding.expr else {
                continue;
            };
            let Some(key) = resolved_key_mut(op) else {
                continue;
            };
            let Some(&n) = one_word.get(&(key.enum_name.clone(), key.variant.clone())) else {
                continue;
            };
            if key.payload.len() <= n {
                continue;
            }
            let dropped = key.payload.len() - n;
            key.payload.truncate(n);
            binding.add_provenance(sordec_common::Provenance::new(
                PASS_NAME,
                sordec_common::ProvenanceSource::SdkPattern,
                format!(
                    "key cut to its variant's {n} one-word fields; the {dropped} frame slot(s) \
                     after them are what rustc laid out next, not the key"
                ),
            ));
            result.metrics.increment(M_TRIMMED, 1);
            result.changed = true;
        }
    }
}

/// [`resolved_key`], for rewriting.
fn resolved_key_mut(op: &mut sordec_ir::KnownOp) -> Option<&mut sordec_ir::EnumKey> {
    use sordec_ir::KnownOp as K;
    match op {
        K::StorageGet { resolved_key, .. }
        | K::StorageSet { resolved_key, .. }
        | K::StorageHas { resolved_key, .. }
        | K::StorageRemove { resolved_key, .. }
        | K::StorageExtendTtl { resolved_key, .. } => resolved_key.as_mut(),
        _ => None,
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
                // Only a primitive or `BytesN<N>` witness. A user-defined
                // or other composite payload type needs a `TypeId` (or an
                // element type) that means the same thing in this
                // registry, and nothing here establishes that.
                let Some(ty) = func
                    .bindings
                    .get(*value)
                    .and_then(|b| match &b.ty {
                        IrType::Known(k) | IrType::Inferred(k) => witness_type(k),
                        IrType::Unknown(_) => None,
                    })
                else {
                    continue;
                };
                let slot = (key.enum_name.clone(), key.variant.clone(), index);
                let joined = match out.remove(&slot) {
                    Some(w) => w.join(ty),
                    None => Witness::One(ty),
                };
                out.insert(slot, joined);
            }
        }
    }
    out
}

/// The field type a value of type `k` witnesses.
fn witness_type(k: &sordec_ir::KnownType) -> Option<Field> {
    match k {
        sordec_ir::KnownType::BytesN(n) => Some(Field::BytesN(*n)),
        k => primitive_of_known(k).map(Field::Primitive),
    }
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
            exported: true,
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

    /// `account`: one site puts a `BytesN<32>` in the field, another a frame
    /// word only typed `Val`. The `Val` is an unrecovered type, not a
    /// disagreement, and the frame load then takes the field's type.
    #[test]
    fn a_val_site_yields_and_its_load_takes_the_field_type() {
        let val = IrType::Known(sordec_ir::KnownType::Val);
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },
                Expr::Load { addr: v(0), offset: 24, width: sordec_ir::MemWidth::W8, signed: None, ty: val.clone() },
                get_with(vec![v(0)]),
                get_with(vec![v(1)]),
            ],
            vec![],
            vec![1, 2, 3],
        );
        f.bindings.get_mut(v(0)).expect("a").ty = IrType::Known(sordec_ir::KnownType::BytesN(32));
        f.bindings.get_mut(v(1)).expect("b").ty = val;
        let mut ir = with_union(module(vec![f]));

        let result = KeyFieldTypePass.run(&mut ir);
        assert_eq!(result.metrics.get(M_LOADS_TYPED), Some(1));
        let load = &ir.functions[0].bindings.get(v(1)).expect("the load").ty;
        assert!(
            matches!(load, IrType::Inferred(sordec_ir::KnownType::BytesN(32))),
            "got {load:?}"
        );
        let field = &ir.soroban_facts.expect("facts").types.unions[0].cases[0].fields[0];
        assert!(
            matches!(field, TypeRef::Composite(sordec_ir::CompositeType::BytesN(32))),
            "got {field:?}"
        );
    }

    /// A frame-read key that ran past its variant is cut back once the
    /// field is known to be one word: the extra slots were the frame's
    /// next occupant, not the key.
    #[test]
    fn an_overlong_key_is_cut_to_its_typed_fields() {
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },
                Expr::Literal(sordec_ir::Literal::I64(0)),
                get_with(vec![v(0), v(1)]),
            ],
            vec![],
            vec![1, 2],
        );
        f.bindings.get_mut(v(0)).expect("the payload").ty =
            IrType::Known(sordec_ir::KnownType::Address);
        let mut ir = with_union(module(vec![f]));

        let result = KeyFieldTypePass.run(&mut ir);
        assert_eq!(result.metrics.get(M_TRIMMED), Some(1));
        let get = ir.functions[0].bindings.get(v(2)).expect("the read");
        let Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet { resolved_key: Some(k), .. })) = &get.expr
        else {
            panic!("still a keyed read")
        };
        assert_eq!(k.payload, vec![v(0)], "one field, one value");
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
