//! A tuple struct built by the helper rustc outlines its encode into.
//!
//! # The shape
//!
//! `#[contracttype] struct Tally(pub u32, pub u32)` crosses the ABI as a
//! vec of its fields' `Val`s, in order. rustc outlines that encode into a
//! helper the encoders share, and the value placed where a `Tally` goes is
//! the helper's vec:
//!
//! ```text
//! fn func34(a: u32, b: u32) -> (i64, Vec<Val>) {
//!     (0, vec![U32Val(a), U32Val(b)])
//! }
//! p = Proposal { …, tally: func34(x, y).1, … }      ← expected `Tally`
//! return func34(x, y).1                              ← declared `Result<Tally, E>`
//! ```
//!
//! # The rewrite
//!
//! The component becomes the struct literal of the helper's arguments,
//! `Tally { 0: x, 1: y }`, typed `Tally`. A call nothing else reads is
//! dropped with it.
//!
//! # Why it is exact
//!
//! The derive encodes a tuple struct as the vec of its fields' encodings,
//! field `i` at element `i`, each by its declared type. The helper builds
//! exactly that from its arguments: element `i` is the small encode, as
//! field `i`'s declared type, of the argument it was handed — or the
//! argument itself, for a field that is an object, whose `Val` is its
//! handle. So the component is the encoding of the struct whose fields are
//! those arguments. The positions it reaches read it as that struct: a
//! struct literal's field declared that tuple struct, whose derive encodes
//! the field by the same rule, or the return of an entrypoint the spec
//! declares to return it (as `T` or a `Result`'s `Ok`), which the SDK's
//! wrapper encodes by the same rule. A store into memory reads the value
//! too; it is a hole, and what it stores is the same value whichever way
//! it is spelled. The helper's only effect is creating that vec, which the
//! derive creates again.
//!
//! # Gates
//!
//! - **The helper**: no spec, not exported; straight line; one return
//!   site, `(0, vec)`, the vec built from exactly the struct's field count
//!   of elements, element `i` the small encode of a parameter as field
//!   `i`'s declared scalar type, or a parameter itself where field `i` is
//!   declared an object; every other binding pure and total.
//! - **The component**: read only by struct literals in a field declared
//!   the tuple struct, by stores, by copies read the same way, and by
//!   merges flowing only into the return of an entrypoint declared to
//!   return it.

use std::collections::HashSet;

use sordec_common::{FuncId, Provenance, ProvenanceSource, TypeId, ValueId};
use sordec_ir::{
    Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Literal, Region, SemanticOp, StructDef, TypeRegistry,
};

use super::encode::declared_return_type;
use super::sret::emission_order;
use crate::dataflow::{resolve_use, trace_int};
use crate::effects::expr_effects;
use crate::metrics_catalog::MARSHALLING_TUPLE_STRUCT_ENCODES as M_ENCODES;
use crate::pass::{Pass, PassResult};
use crate::type_infer::known_of_type_ref;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-tuple-struct-encode";

/// Names the tuple struct an outlined encode helper builds.
#[derive(Debug, Default, Clone, Copy)]
pub struct TupleStructEncodePass;

/// One element of the helper's vec: the parameter it encodes, and the small
/// type it encodes it as (`None`: the parameter itself, an object).
type Element = (usize, Option<KnownType>);

impl Pass<HighIr> for TupleStructEncodePass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let Some(reg) = ir.soroban_facts.as_ref().map(|f| f.types.clone()) else {
            return result;
        };
        let tuples: Vec<&StructDef> = reg.structs.iter().filter(|s| is_tuple(s)).collect();
        if tuples.is_empty() {
            return result;
        }
        let helpers: Vec<(FuncId, Vec<Element>)> =
            ir.functions.iter().filter_map(|f| Some((f.id, helper_elements(f)?))).collect();
        if helpers.is_empty() {
            return result;
        }
        for func in &mut ir.functions {
            let plans = plan(func, &reg, &helpers);
            for (component, call, sid, fields) in plans {
                apply(func, component, call, sid, fields);
                result.metrics.increment(M_ENCODES, 1);
                result.changed = true;
            }
        }
        result
    }
}

/// A struct the spec records with positional fields `0`, `1`, ….
fn is_tuple(def: &StructDef) -> bool {
    !def.fields.is_empty() && def.fields.iter().enumerate().all(|(i, f)| f.name == i.to_string())
}

/// What each element of a helper's returned vec is, when the helper is the
/// outlined encode: `(0, vec![e0, e1, ..])`, straight line, otherwise pure.
fn helper_elements(func: &HighFunction) -> Option<Vec<Element>> {
    if func.signature.is_some() || func.name.is_some() {
        return None;
    }
    let [site] = func.returns.as_slice() else {
        return None;
    };
    let [zero, vec] = site.as_slice() else {
        return None;
    };
    if trace_int(func, *zero) != Some(0) {
        return None;
    }
    let mut straight = true;
    func.region.for_each_node(|node| match node {
        Region::Basic(_) | Region::Sequence(_) | Region::Return { .. } => {}
        _ => straight = false,
    });
    if !straight {
        return None;
    }
    let built = resolve_use(func, *vec);
    let Expr::Semantic(SemanticOp::Known(KnownOp::VecNew { elements: Some(els), .. })) = &func.bindings.get(built)?.expr
    else {
        return None;
    };
    for id in emission_order(func) {
        let expr = &func.bindings.get(id)?.expr;
        if id != built && !expr_effects(expr).is_pure_total() {
            return None;
        }
    }
    let param = |v: ValueId| func.params.iter().position(|p| *p == resolve_use(func, v));
    els.iter()
        .map(|e| {
            let e = resolve_use(func, *e);
            match &func.bindings.get(e)?.expr {
                Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty, value })) => {
                    Some((param(*value)?, Some(ty.clone())))
                }
                Expr::Phi { incoming } if incoming.is_empty() => Some((param(e)?, None)),
                _ => None,
            }
        })
        .collect()
}

/// Whether `ty` is a type whose `Val` is an object handle, not a small value.
fn is_object(ty: &KnownType) -> bool {
    matches!(
        ty,
        KnownType::Address
            | KnownType::Bytes
            | KnownType::BytesN(_)
            | KnownType::String
            | KnownType::Symbol
            | KnownType::Vec(_)
            | KnownType::Map(_, _)
            | KnownType::UserDefined(_)
            | KnownType::I128
            | KnownType::U128
    )
}

/// The struct the helper's elements encode, field by field, if `sid` is a
/// tuple struct with that many fields of those types.
fn matches_struct(reg: &TypeRegistry, sid: TypeId, elements: &[Element]) -> bool {
    let Some(def) = reg.structs.iter().find(|s| s.id == sid) else {
        return false;
    };
    is_tuple(def)
        && def.fields.len() == elements.len()
        && def.fields.iter().zip(elements).all(|(f, (_, enc))| {
            let Some(declared) = known_of_type_ref(&f.ty) else { return false };
            match enc {
                Some(small) => *small == declared,
                // An object is its own `Val`; a wide number is not, since
                // its `Val` is small when it fits.
                None => is_object(&declared) && !matches!(declared, KnownType::I128 | KnownType::U128),
            }
        })
}

type Planned = (ValueId, ValueId, TypeId, Vec<(String, ValueId)>);

fn plan(func: &HighFunction, reg: &TypeRegistry, helpers: &[(FuncId, Vec<Element>)]) -> Vec<Planned> {
    let order = emission_order(func);
    let phis: Vec<ValueId> =
        func.bindings.iter().filter(|(_, b)| matches!(b.expr, Expr::Phi { .. })).map(|(id, _)| id).collect();
    let live: Vec<ValueId> = order.iter().chain(&phis).copied().collect();
    let readers = |v: ValueId| -> Vec<ValueId> {
        live.iter()
            .copied()
            .filter(|id| {
                let mut reads = false;
                if let Some(b) = func.bindings.get(*id) {
                    b.expr.for_each_value_use(|u| reads |= u == v);
                }
                reads
            })
            .collect()
    };
    let region_reads = |v: ValueId| {
        let mut other = false;
        func.region.for_each_node(|node| match node {
            Region::If { cond, .. } => other |= *cond == v,
            Region::Switch { index, .. } => other |= *index == v,
            _ => {}
        });
        other
    };
    // The values flowing only into the return, and the struct the
    // entrypoint is declared to return there.
    let declared_struct = declared_return_type(func).and_then(|k| match k {
        KnownType::UserDefined(id) => Some(id),
        _ => None,
    });
    let mut returned: HashSet<ValueId> = HashSet::new();
    if declared_struct.is_some() {
        func.region.for_each_node(|node| {
            if let Region::Return { values } = node
                && let [one] = values.as_slice()
            {
                returned.insert(resolve_use(func, *one));
            }
        });
        let mut grew = true;
        while grew {
            grew = false;
            for id in returned.clone() {
                if let Some(Expr::Phi { incoming }) = func.bindings.get(id).map(|b| &b.expr) {
                    for (_, a) in incoming {
                        grew |= returned.insert(resolve_use(func, *a));
                    }
                }
            }
        }
    }

    let mut out = Vec::new();
    for &component in &order {
        let Some(Expr::Project { value: call, index: 1 }) = func.bindings.get(component).map(|b| &b.expr) else {
            continue;
        };
        let call = resolve_use(func, *call);
        let Some(Expr::Call { target, args }) = func.bindings.get(call).map(|b| &b.expr) else {
            continue;
        };
        let Some((_, elements)) = helpers.iter().find(|(id, _)| id == target) else {
            continue;
        };
        if region_reads(component) {
            continue;
        }
        // The struct every position reading it expects.
        let mut wanted: Option<TypeId> = None;
        let mut agree = |sid: TypeId| match wanted {
            None => {
                wanted = Some(sid);
                true
            }
            Some(w) => w == sid,
        };
        let mut ok = true;
        let mut pending = vec![component];
        let mut seen: HashSet<ValueId> = HashSet::new();
        while let Some(v) = pending.pop() {
            if !seen.insert(v) {
                continue;
            }
            for r in readers(v) {
                let Some(b) = func.bindings.get(r) else {
                    ok = false;
                    continue;
                };
                match &b.expr {
                    Expr::Store { value, addr, .. } if *value == v && *addr != v => {}
                    Expr::Use(_) if !region_reads(r) => pending.push(r),
                    Expr::Phi { .. } if returned.contains(&r) => {
                        ok &= declared_struct.is_some_and(&mut agree);
                    }
                    Expr::Struct { fields } => {
                        let sid = match &b.ty {
                            IrType::Known(KnownType::UserDefined(id)) | IrType::Inferred(KnownType::UserDefined(id)) => *id,
                            _ => {
                                ok = false;
                                continue;
                            }
                        };
                        let Some(def) = reg.structs.iter().find(|s| s.id == sid) else {
                            ok = false;
                            continue;
                        };
                        for (name, value) in fields {
                            if *value != v {
                                continue;
                            }
                            match def.fields.iter().find(|f| f.name == *name).and_then(|f| known_of_type_ref(&f.ty)) {
                                Some(KnownType::UserDefined(fid)) => ok &= agree(fid),
                                _ => ok = false,
                            }
                        }
                    }
                    _ => ok = false,
                }
            }
        }
        // Returned directly, with no merge between.
        if returned.contains(&component) {
            ok &= declared_struct.is_some_and(&mut agree);
        }
        let Some(sid) = wanted.filter(|_| ok) else {
            continue;
        };
        if !matches_struct(reg, sid, elements) {
            continue;
        }
        let Some(fields) = elements
            .iter()
            .enumerate()
            .map(|(i, (p, _))| Some((i.to_string(), *args.get(*p)?)))
            .collect::<Option<Vec<_>>>()
        else {
            continue;
        };
        out.push((component, call, sid, fields));
    }
    out
}

fn apply(func: &mut HighFunction, component: ValueId, call: ValueId, sid: TypeId, fields: Vec<(String, ValueId)>) {
    let note = |what: &str| Provenance::new(PASS_NAME, ProvenanceSource::SdkPattern, what.to_string());
    if let Some(b) = func.bindings.get_mut(component) {
        b.expr = Expr::Struct { fields };
        b.ty = IrType::Inferred(KnownType::UserDefined(sid));
        b.add_provenance(note(
            "tuple-struct-encode: the vec an outlined encode builds of its arguments is the tuple struct of them",
        ));
    }
    // The call, when nothing else reads what it returned.
    let order = emission_order(func);
    let mut read = false;
    for id in order.iter().copied().chain(func.bindings.iter().filter(|(_, b)| matches!(b.expr, Expr::Phi { .. })).map(|(id, _)| id)) {
        if let Some(b) = func.bindings.get(id) {
            b.expr.for_each_value_use(|u| read |= u == call);
        }
    }
    func.region.for_each_value_use(|u| read |= u == call);
    if !read && let Some(b) = func.bindings.get_mut(call) {
        b.expr = Expr::Literal(Literal::Unit);
        b.ty = IrType::Known(KnownType::Unit);
        b.add_provenance(note("tuple-struct-encode: the encode, its result now spelled as the struct"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};
    use sordec_common::{BlockId, IrId};
    use sordec_ir::{FunctionSignature, SorobanFacts, StructField, TypeRef};

    /// `fn func1(a, b) -> (i64, Vec) { (0, vec![U32Val(a), U32Val(b)]) }`,
    /// with element types `tys`.
    fn helper(tys: [KnownType; 2]) -> HighFunction {
        let [t0, t1] = tys;
        let exprs = vec![
            Expr::Phi { incoming: vec![] }, // v0 a
            Expr::Phi { incoming: vec![] }, // v1 b
            Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty: t0, value: v(0) })), // v2
            Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty: t1, value: v(1) })), // v3
            Expr::Literal(Literal::I32(0)),                                                    // v4 (pos)
            Expr::Semantic(SemanticOp::Known(KnownOp::VecNew {
                vals_pos: v(4),
                len: v(4),
                elements: Some(vec![v(2), v(3)]),
            })), // v5
            Expr::Literal(Literal::I64(0)), // v6
        ];
        let mut f = func_with(exprs, vec![v(0), v(1)], vec![2, 3, 4, 5, 6]);
        f.id = FuncId::from_index(1);
        f.returns = vec![vec![v(6), v(5)]];
        f.region = Region::Sequence(vec![Region::Basic(BlockId::from_index(0)), Region::Return { values: vec![v(6), v(5)] }]);
        f
    }

    /// `p = Outer { t: func1(x, y).1 }` in func0, `store` of the component too.
    fn caller() -> HighFunction {
        let exprs = vec![
            Expr::Phi { incoming: vec![] }, // v0 x
            Expr::Phi { incoming: vec![] }, // v1 y
            Expr::Call { target: FuncId::from_index(1), args: vec![v(0), v(1)] }, // v2
            Expr::Project { value: v(2), index: 1 }, // v3
            Expr::Struct { fields: vec![("t".into(), v(3))] }, // v4
            crate::marshalling::test_support::store(v(0), v(3), 8), // v5
        ];
        let mut f = func_with(exprs, vec![v(0), v(1)], vec![2, 3, 4, 5]);
        f.bindings.get_mut(v(4)).expect("struct").ty = IrType::Known(KnownType::UserDefined(TypeId::from_index(2)));
        f.region = Region::Sequence(vec![Region::Basic(BlockId::from_index(0)), Region::Return { values: vec![v(4)] }]);
        f
    }

    fn registry(field: KnownType) -> TypeRegistry {
        let prim = |k: &KnownType| match k {
            KnownType::U32 => TypeRef::Primitive(sordec_ir::PrimitiveType::U32),
            KnownType::I64 => TypeRef::Primitive(sordec_ir::PrimitiveType::I64),
            _ => TypeRef::Primitive(sordec_ir::PrimitiveType::Address),
        };
        let mut reg = TypeRegistry::default();
        reg.structs.push(StructDef {
            id: TypeId::from_index(1),
            name: "Tally".into(),
            fields: vec![
                StructField { name: "0".into(), ty: prim(&field) },
                StructField { name: "1".into(), ty: prim(&KnownType::U32) },
            ],
        });
        reg.structs.push(StructDef {
            id: TypeId::from_index(2),
            name: "Outer".into(),
            fields: vec![StructField { name: "t".into(), ty: TypeRef::UserDefined(TypeId::from_index(1)) }],
        });
        reg
    }

    fn ir(field: KnownType, helper_tys: [KnownType; 2]) -> HighIr {
        let mut ir = module(vec![caller(), helper(helper_tys)]);
        ir.soroban_facts = Some(SorobanFacts {
            functions: Default::default(),
            types: registry(field),
            contract_meta: Default::default(),
            env_meta: Default::default(),
        });
        ir
    }

    #[test]
    fn a_field_built_by_the_outlined_encode_is_the_tuple_struct() {
        let mut ir = ir(KnownType::U32, [KnownType::U32, KnownType::U32]);
        assert!(TupleStructEncodePass.run(&mut ir).changed);
        let f = &ir.functions[0];
        let b = f.bindings.get(v(3)).expect("component");
        assert!(
            matches!(&b.expr, Expr::Struct { fields } if fields == &vec![("0".to_string(), v(0)), ("1".to_string(), v(1))]),
            "{:?}",
            b.expr
        );
        assert_eq!(b.ty, IrType::Inferred(KnownType::UserDefined(TypeId::from_index(1))));
        assert!(matches!(f.bindings.get(v(2)).expect("call").expr, Expr::Literal(Literal::Unit)), "the call goes");
    }

    #[test]
    fn an_element_of_another_type_is_not_the_field() {
        // The helper encodes its first argument as an `i64`; the field is a `u32`.
        let mut ir = ir(KnownType::U32, [KnownType::I64, KnownType::U32]);
        assert!(!TupleStructEncodePass.run(&mut ir).changed);
    }

    #[test]
    fn a_component_read_as_something_else_is_left_alone() {
        let mut ir = ir(KnownType::U32, [KnownType::U32, KnownType::U32]);
        // Returned from a helper, not a field: no declared struct reads it.
        let f = &mut ir.functions[0];
        f.region = Region::Sequence(vec![Region::Basic(BlockId::from_index(0)), Region::Return { values: vec![v(3)] }]);
        f.bindings.get_mut(v(4)).expect("struct").expr = Expr::Literal(Literal::Unit);
        assert!(!TupleStructEncodePass.run(&mut ir).changed);
    }

    #[test]
    fn a_returned_component_is_the_declared_struct() {
        let mut ir = ir(KnownType::U32, [KnownType::U32, KnownType::U32]);
        let f = &mut ir.functions[0];
        f.region = Region::Sequence(vec![Region::Basic(BlockId::from_index(0)), Region::Return { values: vec![v(3)] }]);
        f.bindings.get_mut(v(4)).expect("struct").expr = Expr::Literal(Literal::Unit);
        f.name = Some("vote".into());
        f.signature = Some(FunctionSignature {
            name: "vote".into(),
            inputs: vec![],
            outputs: vec![TypeRef::UserDefined(TypeId::from_index(1))],
        });
        assert!(TupleStructEncodePass.run(&mut ir).changed);
    }
}
