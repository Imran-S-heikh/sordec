//! A returned tuple, recovered from the `Vec` it travels as.
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
//!   found behind an encode is the value itself.
//!
//! Both are exact for the reason the tuple is: the spec says the vec is the
//! tuple's encoding, so its element at each position is the encoding of the
//! declared component, and each of these readings is that encoding's
//! inverse.

use std::collections::HashSet;

use sordec_common::{IrId, Provenance, ProvenanceSource, TypeId, ValueId};
use sordec_ir::{
    CompositeType, Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Literal, SemanticOp, StructDef, TypeRef,
};

use super::encode::encoded_constant;
use super::udt_encode::{encoded_value, encodes, rebuild_as};
use crate::dataflow::high_uses::{HighUseIndex, HighUseSite};
use crate::dataflow::resolve_use;
use crate::metrics_catalog::{
    MARSHALLING_TUPLE_RETURNS_DECLINED as M_DECLINED, MARSHALLING_TUPLE_RETURNS_RECOVERED as M_RECOVERED,
};
use crate::pass::{Pass, PassResult};
use crate::type_infer::known_of_type_ref;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-tuple-return";

/// Rewrites a returned `Vec` to the tuple the spec declares.
#[derive(Debug, Default, Clone, Copy)]
pub struct TupleReturnPass;

impl Pass<HighIr> for TupleReturnPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let structs: Vec<StructDef> =
            ir.soroban_facts.as_ref().map(|f| f.types.structs.clone()).unwrap_or_default();
        let memory = &ir.memory;
        for func in &mut ir.functions {
            let Some(slots) = declared_tuple(func) else {
                continue;
            };
            let uses = HighUseIndex::build(func);
            for leaf in returned_vecs(func) {
                let Some(components) = plan(func, memory, &structs, &uses, &leaf, &slots) else {
                    result.metrics.increment(M_DECLINED, 1);
                    continue;
                };
                let Some(items) = settle(func, memory, &structs, leaf.vec, components) else {
                    result.metrics.increment(M_DECLINED, 1);
                    continue;
                };
                let ty = IrType::Known(KnownType::Tuple(slots.clone()));
                if let Some(binding) = func.bindings.get_mut(leaf.vec) {
                    binding.expr = Expr::Tuple { items };
                    binding.ty = ty.clone();
                    binding.add_provenance(Provenance::new(
                        PASS_NAME,
                        ProvenanceSource::SdkPattern,
                        "returned vec is the tuple the spec declares",
                    ));
                }
                for &copy in &leaf.copies {
                    if let Some(binding) = func.bindings.get_mut(copy) {
                        binding.ty = ty.clone();
                    }
                }
                result.metrics.increment(M_RECOVERED, 1);
                result.changed = true;
            }
        }
        result
    }
}

/// The components of the tuple the function's spec says it returns, bare or
/// as a `Result`'s `Ok`.
fn declared_tuple(func: &HighFunction) -> Option<Vec<IrType>> {
    let ty = match func.signature.as_ref()?.outputs.as_slice() {
        [TypeRef::Composite(CompositeType::Result(ok, _))] => ok.as_ref(),
        [one] => one,
        _ => return None,
    };
    match known_of_type_ref(ty)? {
        KnownType::Tuple(slots) if !slots.is_empty() => Some(slots),
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
                        "a tuple component stored as its encoded constant, decoded",
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
    let Some(Expr::Semantic(SemanticOp::Known(KnownOp::VecNew { elements: Some(elements), .. }))) =
        func.bindings.get(leaf.vec).map(|b| &b.expr)
    else {
        return None;
    };
    if elements.len() != slots.len() {
        return None;
    }
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
    if !read_only_on_the_way {
        return None;
    }
    elements
        .iter()
        .zip(slots)
        .map(|(&element, slot)| {
            let want = base(slot)?;
            let item = encoded_value(func, element);
            if component_type(func, element, item).as_ref() == Some(&want) {
                return Some(Component::Value(item));
            }
            if let KnownType::UserDefined(id) = want
                && encodes(func, memory, structs, item, id)
            {
                return Some(Component::Struct(item, id));
            }
            // Only the raw word: behind an encode, a number is the value.
            if item == resolve_use(func, element) {
                let lit = encoded_constant(func, element, &want)?;
                return Some(Component::Word(lit, want));
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
}
