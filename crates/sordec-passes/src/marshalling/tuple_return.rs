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
//!   also stored or passed somewhere is used as a vec there.
//! - **One element per component, each of the declared type** once its
//!   encode is stripped — by its own recovered type, or by the encode's,
//!   since this runs before general type inference. An element of neither
//!   declines the whole vec: a tuple with a guessed component is not one.

use std::collections::HashSet;

use sordec_common::{Provenance, ProvenanceSource, ValueId};
use sordec_ir::{CompositeType, Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, SemanticOp, TypeRef};

use super::udt_encode::encoded_value;
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
        for func in &mut ir.functions {
            let Some(slots) = declared_tuple(func) else {
                continue;
            };
            let uses = HighUseIndex::build(func);
            for leaf in returned_vecs(func) {
                let Some(items) = plan(func, &uses, &leaf, &slots) else {
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

/// The tuple's components, or `None` when a gate declines.
fn plan(func: &HighFunction, uses: &HighUseIndex, leaf: &Leaf, slots: &[IrType]) -> Option<Vec<ValueId>> {
    let Some(Expr::Semantic(SemanticOp::Known(KnownOp::VecNew { elements: Some(elements), .. }))) =
        func.bindings.get(leaf.vec).map(|b| &b.expr)
    else {
        return None;
    };
    if elements.len() != slots.len() {
        return None;
    }
    let read_only_on_the_way = std::iter::once(leaf.vec).chain(leaf.copies.iter().copied()).all(|v| {
        uses.uses_of(v).iter().all(|site| match site {
            HighUseSite::Binding { user } => leaf.chain.contains(user),
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
            let item = encoded_value(func, element);
            (component_type(func, element, item)? == base(slot)?).then_some(item)
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

    #[test]
    fn a_component_of_another_type_declines() {
        let mut func = minter(false);
        func.bindings.get_mut(v(1)).unwrap().ty = IrType::Inferred(KnownType::I64);
        let mut ir = module(vec![func]);
        assert!(!TupleReturnPass.run(&mut ir).changed);
    }
}
