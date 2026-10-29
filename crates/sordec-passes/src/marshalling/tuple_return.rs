//! A returned tuple or enum variant, recovered from the `Vec` it travels as.
//!
//! # The shape
//!
//! A Soroban tuple's wire form is a vec of its encoded components, so
//! `Ok((config, epoch, stats))` compiles to the SDK building a three-element
//! vec and handing it back:
//!
//! ```text
//! e = val_encode<u32>(epoch)
//! v = vec_new(config, e, stats)      →  v = (config, epoch, stats)
//! return v                               return Ok(v)
//! ```
//!
//! Left as a vec it is the right value with the wrong Rust type: the
//! function declares `Result<(MinterConfig, u32, MinterStats), Error>` and
//! returns `Vec<Val>`, which does not compile.
//!
//! # The rewrite
//!
//! The vec becomes [`Expr::Tuple`] of its elements, each with its `Val`
//! encode stripped, and takes the declared tuple type — as do the copies it
//! is renamed through on its way to the return. The emitter then wraps it in
//! `Ok` the way it wraps any other `Ok` payload.
//!
//! # Gates
//!
//! - **The spec declares a tuple**, bare or as a `Result`'s `Ok`.
//! - **The vec reaches a return** through renames and merges only.
//! - **Nothing else reads it**, nor any rename on the way: a vec that is
//!   also stored or passed somewhere is used as a vec there. A binding no
//!   block schedules and that is not a merge is residue an earlier rewrite
//!   left; it never runs, so it is no reader.
//! - **One element per component, each of the declared type** once its
//!   encode is stripped — by its own recovered type, or by the encode's,
//!   since this runs before general type inference. An element of neither
//!   declines the whole vec: a tuple with a guessed component is not one.
//!   Two elements still in their encoded form are read as what they
//!   encode, below.
//!
//! # Components still in their encoded form
//!
//! `(UsedTupleReturnElement { val: 1 }, 2)` reaches the vec as a map and a
//! constant word, neither of the declared type yet:
//!
//! - **A struct's derived encode** whose key table several structs share,
//!   so [`super::udt_encode`] could not tell which it was — it ran before
//!   the vec's elements were read back, and only the tuple names the
//!   component. Here the declared component picks the struct, the key
//!   table must fit it field for field, and the encode becomes its literal
//!   ([`super::udt_encode::rebuild_as`], under that pass's argument).
//! - **A constant word** whose low half is the declared small type's tag
//!   (`2 << 32 | U32Val`): by the encoding's definition it is that number,
//!   the same reading a returned constant gets
//!   ([`super::encode::encoded_constant`]). Only the raw word — a number
//!   found behind an encode is the value itself. And the raw word is
//!   never its literal number: `4294967300` in an `i64` position is a
//!   `U32Val`, not an `i64`, so a word that decodes to nothing declared
//!   declines the vec.
//!
//! Both are exact for the reason the tuple is: the spec says the vec is the
//! tuple's encoding, so its element at each position is the encoding of the
//! declared component, and each of these readings is that encoding's
//! inverse.
//!
//! # An enum variant, by the same route
//!
//! A `#[contracttype]` enum's variant travels as a vec too: the variant's
//! name as a symbol, then each value it carries, encoded. `UsedReturnEnum::
//! A(1)` returned is `vec![Symbol("A"), 1 << 32 | U32Val]`. Where the spec
//! declares the entrypoint returns the enum, a returned vec whose first
//! element is a constant symbol naming one of its variants, with exactly
//! as many elements after it as that variant carries values, is that
//! variant: [`Expr::Variant`] with the rest read as the tuple's components
//! are, against the variant's declared types.
//!
//! Exact: the spec says the vec is the enum's encoding, the derive writes
//! the variant's own name first and variant names are unique within an
//! enum, so the symbol picks the variant and the length confirms it; the
//! values after it are that variant's, in order, by the derive's layout.
//! A first element that is not a constant symbol, a name the enum does
//! not declare, a length that disagrees, or any value of another type
//! declines the vec.

use std::collections::HashSet;

use sordec_common::{IrId, Provenance, ProvenanceSource, TypeId, ValueId};
use sordec_ir::{
    CompositeType, Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Literal, SemanticOp, StructDef, TypeRef,
    UnionDef,
};

use super::encode::encoded_constant;
use super::udt_encode::{encoded_value, encodes, rebuild_as};
use crate::dataflow::high_uses::{HighUseIndex, HighUseSite};
use crate::dataflow::resolve_use;
use crate::metrics_catalog::{
    MARSHALLING_TUPLE_RETURNS_DECLINED as M_DECLINED, MARSHALLING_TUPLE_RETURNS_RECOVERED as M_RECOVERED,
    MARSHALLING_VARIANT_RETURNS_DECLINED as M_VARIANT_DECLINED,
    MARSHALLING_VARIANT_RETURNS_RECOVERED as M_VARIANT_RECOVERED,
};
use crate::pass::{Pass, PassResult};
use crate::type_infer::known_of_type_ref;
use crate::val_abi::decode_small_symbol;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-tuple-return";

/// Rewrites a returned `Vec` to the tuple or enum variant the spec
/// declares.
#[derive(Debug, Default, Clone, Copy)]
pub struct TupleReturnPass;

impl Pass<HighIr> for TupleReturnPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let (structs, unions): (Vec<StructDef>, Vec<UnionDef>) = ir
            .soroban_facts
            .as_ref()
            .map(|f| (f.types.structs.clone(), f.types.unions.clone()))
            .unwrap_or_default();
        let memory = &ir.memory;
        for func in &mut ir.functions {
            let Some(declared) = declared(func, &unions) else {
                continue;
            };
            let (recovered, declined) = match declared {
                Declared::Tuple(_) => (M_RECOVERED, M_DECLINED),
                Declared::Variant(_) => (M_VARIANT_RECOVERED, M_VARIANT_DECLINED),
            };
            let uses = HighUseIndex::build(func);
            for leaf in returned_vecs(func) {
                let planned = match declared {
                    Declared::Tuple(ref slots) => {
                        plan(func, memory, &structs, &uses, &leaf, slots).map(|c| (None, c))
                    }
                    Declared::Variant(def) => {
                        plan_variant(func, memory, &structs, &uses, &leaf, def).map(|(name, c)| (Some(name), c))
                    }
                };
                let Some((variant, components)) = planned else {
                    result.metrics.increment(declined, 1);
                    continue;
                };
                let Some(items) = settle(func, memory, &structs, leaf.vec, components) else {
                    result.metrics.increment(declined, 1);
                    continue;
                };
                let (expr, ty, note) = match (&declared, variant) {
                    (Declared::Variant(def), Some(name)) => (
                        Expr::Variant { name, payload: items },
                        IrType::Known(KnownType::UserDefined(def.id)),
                        "returned vec is the enum variant the spec declares",
                    ),
                    (Declared::Tuple(slots), _) => (
                        Expr::Tuple { items },
                        IrType::Known(KnownType::Tuple(slots.clone())),
                        "returned vec is the tuple the spec declares",
                    ),
                    (Declared::Variant(_), None) => continue,
                };
                if let Some(binding) = func.bindings.get_mut(leaf.vec) {
                    binding.expr = expr;
                    binding.ty = ty.clone();
                    binding.add_provenance(Provenance::new(PASS_NAME, ProvenanceSource::SdkPattern, note));
                }
                for &copy in &leaf.copies {
                    if let Some(binding) = func.bindings.get_mut(copy) {
                        binding.ty = ty.clone();
                    }
                }
                result.metrics.increment(recovered, 1);
                result.changed = true;
            }
        }
        result
    }
}

/// What the spec says a returned vec is.
enum Declared<'a> {
    /// A tuple, by its components' types.
    Tuple(Vec<IrType>),
    /// One variant of this `#[contracttype]` enum.
    Variant(&'a UnionDef),
}

/// What the function's spec says it returns, bare or as a `Result`'s `Ok`,
/// when that travels as a vec: a tuple, or an enum with variants.
fn declared<'a>(func: &HighFunction, unions: &'a [UnionDef]) -> Option<Declared<'a>> {
    let ty = match func.signature.as_ref()?.outputs.as_slice() {
        [TypeRef::Composite(CompositeType::Result(ok, _))] => ok.as_ref(),
        [one] => one,
        _ => return None,
    };
    match known_of_type_ref(ty)? {
        KnownType::Tuple(slots) if !slots.is_empty() => Some(Declared::Tuple(slots)),
        KnownType::UserDefined(id) => unions.iter().find(|u| u.id == id).map(Declared::Variant),
        _ => None,
    }
}

/// A vec constructor that reaches a return, and the renames it reaches it
/// through.
struct Leaf {
    vec: ValueId,
    copies: Vec<ValueId>,
    /// Every binding on the way, the merges included: the only readers the
    /// vec and its copies may have.
    chain: HashSet<ValueId>,
}

/// Every vec with recovered elements that a return hands back, following
/// renames and merges.
fn returned_vecs(func: &HighFunction) -> Vec<Leaf> {
    let mut leaves = Vec::new();
    let mut seen = HashSet::new();
    let mut work: Vec<(ValueId, Vec<ValueId>, HashSet<ValueId>)> = func
        .returns
        .iter()
        .filter_map(|site| match site.as_slice() {
            [one] => Some((*one, Vec::new(), HashSet::new())),
            _ => None,
        })
        .collect();
    while let Some((value, copies, mut chain)) = work.pop() {
        if !seen.insert(value) {
            continue;
        }
        chain.insert(value);
        match func.bindings.get(value).map(|b| &b.expr) {
            Some(Expr::Use(inner)) => {
                let mut copies = copies;
                copies.push(value);
                work.push((*inner, copies, chain));
            }
            Some(Expr::Phi { incoming }) => {
                for &(_, inner) in incoming {
                    work.push((inner, copies.clone(), chain.clone()));
                }
            }
            Some(Expr::Semantic(SemanticOp::Known(KnownOp::VecNew { elements: Some(_), .. }))) => {
                leaves.push(Leaf { vec: value, copies, chain });
            }
            _ => {}
        }
    }
    leaves
}

/// What one component is made of.
enum Component {
    /// The value behind its encode, already of the declared type.
    Value(ValueId),
    /// A struct's derived encode this struct's key table fits, not yet
    /// rewritten to the literal.
    Struct(ValueId, TypeId),
    /// A constant word in its encoded form, and the number it encodes.
    Word(Literal, KnownType),
}

/// Put each component in place: rewrite the struct encodes to their
/// literals and give each decoded word a binding of its own, scheduled
/// just before the vec. `None` if a rewrite planned does not apply, which
/// leaves the vec as it was.
fn settle(
    func: &mut HighFunction,
    memory: &sordec_ir::MemoryImage,
    structs: &[StructDef],
    vec: ValueId,
    components: Vec<Component>,
) -> Option<Vec<ValueId>> {
    let mut items = Vec::with_capacity(components.len());
    for component in components {
        let item = match component {
            Component::Value(v) => v,
            Component::Struct(at, id) => {
                let named = |f: &HighFunction| {
                    f.bindings.get(at).is_some_and(|b| {
                        matches!(b.expr, Expr::Struct { .. })
                            && b.ty == IrType::Known(KnownType::UserDefined(id))
                    })
                };
                // The same encode at two positions is rewritten once.
                if !named(func) && !rebuild_as(func, memory, structs, at, id) {
                    return None;
                }
                at
            }
            Component::Word(lit, ty) => {
                let fresh = ValueId::from_index(func.bindings.len() as u32);
                func.bindings.push(sordec_ir::Binding::new(
                    fresh,
                    IrType::Known(ty),
                    Expr::Literal(lit),
                    Provenance::new(
                        PASS_NAME,
                        ProvenanceSource::SdkPattern,
                        "a component stored as its encoded constant, decoded",
                    ),
                ));
                let block = func.blocks.iter_mut().find(|(_, b)| b.bindings.contains(&vec))?;
                let pos = block.1.bindings.iter().position(|v| *v == vec)?;
                block.1.bindings.insert(pos, fresh);
                fresh
            }
        };
        items.push(item);
    }
    Some(items)
}

/// The tuple's components, or `None` when a gate declines.
fn plan(
    func: &HighFunction,
    memory: &sordec_ir::MemoryImage,
    structs: &[StructDef],
    uses: &HighUseIndex,
    leaf: &Leaf,
    slots: &[IrType],
) -> Option<Vec<Component>> {
    let elements = returned_elements(func, uses, leaf)?;
    if elements.len() != slots.len() {
        return None;
    }
    components(func, memory, structs, elements, slots)
}

/// The variant the vec is, and the values it carries, or `None` when a
/// gate declines.
fn plan_variant(
    func: &HighFunction,
    memory: &sordec_ir::MemoryImage,
    structs: &[StructDef],
    uses: &HighUseIndex,
    leaf: &Leaf,
    def: &UnionDef,
) -> Option<(String, Vec<Component>)> {
    let (first, rest) = returned_elements(func, uses, leaf)?.split_first()?;
    let name = symbol_text(func, *first)?;
    let case = def.cases.iter().find(|c| c.name == name)?;
    if case.fields.len() != rest.len() {
        return None;
    }
    let slots = case
        .fields
        .iter()
        .map(|t| known_of_type_ref(t).map(IrType::Known))
        .collect::<Option<Vec<_>>>()?;
    Some((name, components(func, memory, structs, rest, &slots)?))
}

/// The text of a constant symbol: one the host builds from a string the
/// pipeline resolved, or a `SymbolSmall` word.
fn symbol_text(func: &HighFunction, value: ValueId) -> Option<String> {
    match &func.bindings.get(resolve_use(func, value))?.expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::SymbolNew { resolved: Some(text), .. })) => Some(text.clone()),
        Expr::Literal(Literal::I64(bits)) => decode_small_symbol(*bits as u64),
        Expr::Literal(Literal::U64(bits)) => decode_small_symbol(*bits),
        _ => None,
    }
}

/// The elements of a returned vec that nothing but the return reads.
fn returned_elements<'f>(func: &'f HighFunction, uses: &HighUseIndex, leaf: &Leaf) -> Option<&'f [ValueId]> {
    let Some(Expr::Semantic(SemanticOp::Known(KnownOp::VecNew { elements: Some(elements), .. }))) =
        func.bindings.get(leaf.vec).map(|b| &b.expr)
    else {
        return None;
    };
    // A binding no block schedules and no merge stands for — residue a
    // rewrite left behind — never runs, so it reads nothing.
    let scheduled: HashSet<ValueId> = func.blocks.iter().flat_map(|(_, b)| b.bindings.iter().copied()).collect();
    let runs = |user: &ValueId| {
        scheduled.contains(user) || matches!(func.bindings.get(*user).map(|b| &b.expr), Some(Expr::Phi { .. }))
    };
    let read_only_on_the_way = std::iter::once(leaf.vec).chain(leaf.copies.iter().copied()).all(|v| {
        uses.uses_of(v).iter().all(|site| match site {
            HighUseSite::Binding { user } => leaf.chain.contains(user) || !runs(user),
            HighUseSite::Return | HighUseSite::Region => true,
        })
    });
    read_only_on_the_way.then_some(elements.as_slice())
}

/// Each element read as the component its slot declares, or `None` if
/// any is not.
fn components(
    func: &HighFunction,
    memory: &sordec_ir::MemoryImage,
    structs: &[StructDef],
    elements: &[ValueId],
    slots: &[IrType],
) -> Option<Vec<Component>> {
    elements
        .iter()
        .zip(slots)
        .map(|(&element, slot)| {
            let want = base(slot)?;
            let item = encoded_value(func, element);
            // A 64-bit constant stored as the element itself, typed only as
            // the word its literal is, is the `Val` — tag and all — so only
            // its decode can make it a component. Behind an encode, a
            // number is the value.
            let raw_word = item == resolve_use(func, element)
                && func.bindings.get(item).is_some_and(|b| {
                    matches!(b.expr, Expr::Literal(Literal::I64(_) | Literal::U64(_)))
                        && matches!(base(&b.ty), None | Some(KnownType::I64 | KnownType::U64))
                });
            if raw_word {
                let lit = encoded_constant(func, element, &want)?;
                return Some(Component::Word(lit, want));
            }
            if component_type(func, element, item).as_ref() == Some(&want) {
                return Some(Component::Value(item));
            }
            if let KnownType::UserDefined(id) = want
                && encodes(func, memory, structs, item, id)
            {
                return Some(Component::Struct(item, id));
            }
            None
        })
        .collect()
}

/// What a component is, by its own type or, before type inference has run,
/// by the encode it was stored through: `val_encode<u32>(x)` says `x` is a
/// `u32` whatever else has been learned about it.
fn component_type(func: &HighFunction, element: ValueId, item: ValueId) -> Option<KnownType> {
    if let Some(ty) = func.bindings.get(item).and_then(|b| base(&b.ty)) {
        return Some(ty);
    }
    match func.bindings.get(resolve_use(func, element)).map(|b| &b.expr) {
        Some(Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty, value })))
            if resolve_use(func, *value) == item =>
        {
            Some(ty.clone())
        }
        _ => None,
    }
}

fn base(ty: &IrType) -> Option<KnownType> {
    match ty {
        IrType::Known(k) | IrType::Inferred(k) => Some(k.clone()),
        IrType::Unknown(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};
    use sordec_common::TypeId;
    use sordec_ir::{FunctionSignature, Literal, PrimitiveType};

    /// `(MinterConfig, u32)` as `Result`'s `Ok`.
    fn signature() -> FunctionSignature {
        FunctionSignature {
            name: "minter".to_string(),
            inputs: vec![],
            outputs: vec![TypeRef::Composite(CompositeType::Result(
                Box::new(TypeRef::Composite(CompositeType::Tuple(vec![
                    TypeRef::UserDefined(TypeId::new(3)),
                    TypeRef::Primitive(PrimitiveType::U32),
                ]))),
                Box::new(TypeRef::Primitive(PrimitiveType::Error)),
            ))],
        }
    }

    /// v0: the struct, v1: the count, v2: its encode, v3: the vec, v4: a
    /// rename of it, which is returned.
    fn minter(extra_reader: bool) -> HighFunction {
        let mut exprs = vec![
            Expr::Literal(Literal::I64(0)),
            Expr::Literal(Literal::I64(0)),
            Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty: KnownType::U32, value: v(1) })),
            Expr::Semantic(SemanticOp::Known(KnownOp::VecNew {
                vals_pos: v(0),
                len: v(0),
                elements: Some(vec![v(0), v(2)]),
            })),
            Expr::Use(v(3)),
        ];
        if extra_reader {
            exprs.push(Expr::Call { target: sordec_common::FuncId::new(1), args: vec![v(3)] });
        }
        let n = exprs.len() as u32;
        let mut func = func_with(exprs, vec![], (0..n).collect());
        func.bindings.get_mut(v(0)).unwrap().ty = IrType::Known(KnownType::UserDefined(TypeId::new(3)));
        func.signature = Some(signature());
        func.returns = vec![vec![v(4)]];
        func
    }

    #[test]
    fn a_returned_vec_is_the_declared_tuple() {
        let mut ir = module(vec![minter(false)]);
        let result = TupleReturnPass.run(&mut ir);
        assert!(result.changed);
        let func = &ir.functions[0];
        assert!(matches!(&func.bindings.get(v(3)).unwrap().expr, Expr::Tuple { items } if items == &[v(0), v(1)]));
        for id in [v(3), v(4)] {
            assert!(matches!(&func.bindings.get(id).unwrap().ty, IrType::Known(KnownType::Tuple(slots)) if slots.len() == 2));
        }
    }

    #[test]
    fn a_vec_read_elsewhere_stays_a_vec() {
        let mut ir = module(vec![minter(true)]);
        assert!(!TupleReturnPass.run(&mut ir).changed);
        assert!(matches!(
            &ir.functions[0].bindings.get(v(3)).unwrap().expr,
            Expr::Semantic(SemanticOp::Known(KnownOp::VecNew { .. }))
        ));
    }

    /// A reader no block schedules never runs: residue does not keep the
    /// vec a vec.
    #[test]
    fn an_unscheduled_reader_is_no_reader() {
        let mut func = minter(false);
        let id = ValueId::from_index(func.bindings.len() as u32);
        func.bindings.push(sordec_ir::Binding::new(
            id,
            IrType::Unknown(sordec_common::UnknownReason::InsufficientEvidence),
            Expr::Use(v(4)),
            Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
        ));
        let mut ir = module(vec![func]);
        assert!(TupleReturnPass.run(&mut ir).changed);
    }

    #[test]
    fn a_component_of_another_type_declines() {
        let mut func = minter(false);
        func.bindings.get_mut(v(1)).unwrap().ty = IrType::Inferred(KnownType::I64);
        let mut ir = module(vec![func]);
        assert!(!TupleReturnPass.run(&mut ir).changed);
    }

    // -----------------------------------------------------------------
    // Components still in their encoded form
    // -----------------------------------------------------------------

    /// `KEYS` at 2000 naming "count" and "last_incr", which `State` (7),
    /// `Twin` (8) share; `Other` (9) has different names.
    fn shared_keys(m: &mut HighIr) {
        use sordec_ir::{DataSegment, MemoryImage, SorobanFacts, StructField, TypeRegistry};
        let mut table = Vec::new();
        for (ptr, n) in [(2100u32, 5u32), (2110, 9)] {
            table.extend_from_slice(&ptr.to_le_bytes());
            table.extend_from_slice(&n.to_le_bytes());
        }
        m.memory = MemoryImage::from_segments(vec![
            DataSegment { offset: 2000, bytes: table },
            DataSegment { offset: 2100, bytes: b"count".to_vec() },
            DataSegment { offset: 2110, bytes: b"last_incr".to_vec() },
        ]);
        let def = |id: u32, name: &str, first: &str| StructDef {
            id: TypeId::new(id),
            name: name.to_string(),
            fields: vec![
                StructField { name: first.to_string(), ty: TypeRef::Primitive(PrimitiveType::U32) },
                StructField { name: "last_incr".to_string(), ty: TypeRef::Primitive(PrimitiveType::U32) },
            ],
        };
        m.soroban_facts = Some(SorobanFacts {
            functions: std::collections::BTreeMap::new(),
            types: TypeRegistry {
                structs: vec![def(7, "State", "count"), def(8, "Twin", "count"), def(9, "Other", "elsewhere")],
                ..Default::default()
            },
            contract_meta: std::collections::BTreeMap::new(),
            env_meta: sordec_ir::EnvCompatibility::default(),
        });
    }

    /// `return (Twin { .. }, 2u32)` as the vec of a map built from the
    /// shared key table and the constant word `word`.
    fn struct_and_word(first: u32, word: i64) -> HighIr {
        let enc = |value| Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty: KnownType::U32, value }));
        let store = |value, offset| Expr::Store { addr: v(0), value, offset, width: sordec_ir::MemWidth::W8 };
        let exprs = vec![
            Expr::Phi { incoming: vec![] },    // v0 frame
            Expr::Phi { incoming: vec![] },    // v1 count
            Expr::Phi { incoming: vec![] },    // v2 last_incr
            enc(v(1)),                         // v3
            store(v(3), 0),                    // v4
            enc(v(2)),                         // v5
            store(v(5), 8),                    // v6
            Expr::Literal(Literal::U32(2000)), // v7 keys
            Expr::Literal(Literal::U32(2)),    // v8 len
            Expr::Semantic(SemanticOp::Known(KnownOp::MapNew { keys_pos: v(7), vals_pos: v(0), len: v(8) })), // v9
            Expr::Literal(Literal::I64(word)), // v10
            Expr::Semantic(SemanticOp::Known(KnownOp::VecNew {
                vals_pos: v(0),
                len: v(0),
                elements: Some(vec![v(9), v(10)]),
            })), // v11
            Expr::Use(v(11)),                  // v12
        ];
        let mut func = func_with(exprs, vec![v(0), v(1), v(2)], (3..13).collect());
        func.bindings.get_mut(v(10)).unwrap().ty = IrType::Known(KnownType::I64);
        func.signature = Some(FunctionSignature {
            name: "pair".to_string(),
            inputs: vec![],
            outputs: vec![TypeRef::Composite(CompositeType::Tuple(vec![
                TypeRef::UserDefined(TypeId::new(first)),
                TypeRef::Primitive(PrimitiveType::U32),
            ]))],
        });
        func.returns = vec![vec![v(12)]];
        let mut m = module(vec![func]);
        shared_keys(&mut m);
        m
    }

    #[test]
    fn a_struct_encode_and_an_encoded_word_are_the_declared_components() {
        let mut ir = struct_and_word(8, (2 << 32) | 4);
        assert!(TupleReturnPass.run(&mut ir).changed);
        let func = &ir.functions[0];
        let Expr::Tuple { items } = &func.bindings.get(v(11)).unwrap().expr else {
            panic!("the vec is the tuple");
        };
        assert_eq!(items[0], v(9));
        let first = func.bindings.get(v(9)).unwrap();
        assert!(matches!(first.expr, Expr::Struct { .. }));
        assert_eq!(first.ty, IrType::Known(KnownType::UserDefined(TypeId::new(8))), "the declared one of the two");
        let second = func.bindings.get(items[1]).unwrap();
        assert!(matches!(second.expr, Expr::Literal(Literal::U32(2))), "{:?}", second.expr);
        assert!(func.blocks.iter().any(|(_, b)| b.bindings.contains(&items[1])), "the decoded word is scheduled");
    }

    /// A word whose tag is not the declared type's, or a struct the key
    /// table does not fit, declines the tuple and rewrites nothing.
    #[test]
    fn a_component_that_encodes_something_else_declines() {
        let mut ir = struct_and_word(8, (2 << 32) | 5);
        assert!(!TupleReturnPass.run(&mut ir).changed);
        assert!(matches!(
            ir.functions[0].bindings.get(v(9)).unwrap().expr,
            Expr::Semantic(SemanticOp::Known(KnownOp::MapNew { .. }))
        ));
        let mut ir = struct_and_word(9, (2 << 32) | 4);
        assert!(!TupleReturnPass.run(&mut ir).changed);
    }

    // -----------------------------------------------------------------
    // An enum variant
    // -----------------------------------------------------------------

    /// `enum UsedReturnEnum { A(u32), B(i64) }` (5), declared as the return;
    /// the returned vec is `[symbol, words..]`, through a rename.
    fn variant(symbol: Expr, words: &[i64]) -> HighIr {
        use sordec_ir::{SorobanFacts, TypeRegistry, UnionCase};
        let mut exprs = vec![symbol]; // v0
        exprs.extend(words.iter().map(|w| Expr::Literal(Literal::I64(*w)))); // v1..
        let n = exprs.len() as u32;
        exprs.push(Expr::Semantic(SemanticOp::Known(KnownOp::VecNew {
            vals_pos: v(0),
            len: v(0),
            elements: Some((0..n).map(v).collect()),
        }))); // vn
        exprs.push(Expr::Use(v(n))); // vn+1
        let mut func = func_with(exprs, vec![], (0..n + 2).collect());
        for i in 1..n {
            func.bindings.get_mut(v(i)).unwrap().ty = IrType::Known(KnownType::I64);
        }
        func.signature = Some(FunctionSignature {
            name: "ret".to_string(),
            inputs: vec![],
            outputs: vec![TypeRef::UserDefined(TypeId::new(5))],
        });
        func.returns = vec![vec![v(n + 1)]];
        let mut m = module(vec![func]);
        m.soroban_facts = Some(SorobanFacts {
            functions: std::collections::BTreeMap::new(),
            types: TypeRegistry {
                unions: vec![UnionDef {
                    id: TypeId::new(5),
                    name: "UsedReturnEnum".to_string(),
                    cases: vec![
                        UnionCase { name: "A".to_string(), fields: vec![TypeRef::Primitive(PrimitiveType::U32)] },
                        UnionCase { name: "B".to_string(), fields: vec![TypeRef::Primitive(PrimitiveType::I64)] },
                    ],
                    exported: true,
                }],
                ..Default::default()
            },
            contract_meta: std::collections::BTreeMap::new(),
            env_meta: sordec_ir::EnvCompatibility::default(),
        });
        m
    }

    fn symbol_new(text: &str) -> Expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::SymbolNew {
            lm_pos: v(0),
            len: v(0),
            resolved: Some(text.to_string()),
        }))
    }

    /// `"A"` as a `SymbolSmall` word: code 12, tag 14.
    const SMALL_A: i64 = (12 << 8) | 14;

    /// `vec![Symbol("A"), U32Val(1)]` returned as `UsedReturnEnum` is
    /// `UsedReturnEnum::A(1)`, whichever form the symbol takes.
    #[test]
    fn a_returned_vec_is_the_variant_its_symbol_names() {
        for symbol in [symbol_new("A"), Expr::Literal(Literal::I64(SMALL_A))] {
            let mut ir = variant(symbol, &[(1 << 32) | 4]);
            assert!(TupleReturnPass.run(&mut ir).changed);
            let func = &ir.functions[0];
            let vec = func.bindings.get(v(2)).unwrap();
            let Expr::Variant { name, payload } = &vec.expr else {
                panic!("the vec is the variant, got {:?}", vec.expr);
            };
            assert_eq!(name, "A");
            assert_eq!(vec.ty, IrType::Known(KnownType::UserDefined(TypeId::new(5))));
            assert!(matches!(func.bindings.get(payload[0]).unwrap().expr, Expr::Literal(Literal::U32(1))));
            assert_eq!(func.bindings.get(v(3)).unwrap().ty, vec.ty, "the rename takes the enum's type");
        }
    }

    /// A name the enum does not declare, a count of values the variant
    /// does not carry, or a value of another type: the vec stays a vec.
    #[test]
    fn a_vec_that_is_no_declared_variant_stays_a_vec() {
        for (symbol, words) in [
            (symbol_new("C"), vec![(1 << 32) | 4]),
            (symbol_new("A"), vec![(1 << 32) | 4, (2 << 32) | 4]),
            (symbol_new("A"), vec![]),
            (symbol_new("B"), vec![(1 << 32) | 4]),
            (Expr::Phi { incoming: vec![] }, vec![(1 << 32) | 4]),
        ] {
            let mut ir = variant(symbol, &words);
            assert!(!TupleReturnPass.run(&mut ir).changed, "{words:?}");
        }
    }
}
