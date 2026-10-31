//! A choice between two variants of an integer enum, made on their encodings.
//!
//! # The shape
//!
//! `#[contracttype] #[repr(u32)] enum Role { Member = 1, Council = 2 }`
//! crosses the ABI as the `U32Val` of its discriminant. Writing a `Role`
//! held in memory into a struct, rustc picks the encoding branchlessly:
//!
//! ```text
//! r = select(U32Val(1), U32Val(2), d == 1)
//! m = Member { role: r, .. }                  ← expected `Role`
//! ```
//!
//! # The rewrite
//!
//! Each constant becomes the variant it encodes, and the `select` the
//! choice between them: `role: if d == 1 { Role::Member } else {
//! Role::Council }`.
//!
//! # Why it is exact
//!
//! Arm by arm. When the condition holds the `select` yields `U32Val(1)`,
//! which is the encoding of exactly one `Role` — the variant whose
//! discriminant is `1`, since one enum's discriminants are distinct — and
//! otherwise `U32Val(2)`, likewise. The struct's derive encodes its `role`
//! field by that same rule, so the field holding `Member` when the
//! condition holds and `Council` otherwise encodes to the word the
//! `select` chose, on both paths. Nothing is assumed about `d`: the
//! condition is kept as it is.
//!
//! # Gates
//!
//! - **The position**: a struct literal's field declared an enum with
//!   integer discriminants; the `select` read by nothing else.
//! - **The arms**: two constant `U32Val`s, each the discriminant of one of
//!   that enum's variants.
//! - **The condition**: a comparison, or a value typed `bool`.

use sordec_common::{IrId, Provenance, ProvenanceSource, TypeId, ValueId};
use sordec_ir::{Binding, EnumDef, Expr, HighFunction, HighIr, IrType, KnownType, Literal, StructDef, WasmOpcodeKind};

use super::sret::emission_order;
use crate::dataflow::{block_containing, resolve_use};
use crate::metrics_catalog::MARSHALLING_ENUM_SELECTS as M_SELECTS;
use crate::pass::{Pass, PassResult};
use crate::type_infer::known_of_type_ref;
use crate::val_abi;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-enum-select";

/// Names the variants a `select` between their encodings chooses.
#[derive(Debug, Default, Clone, Copy)]
pub struct EnumSelectPass;

impl Pass<HighIr> for EnumSelectPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let Some(facts) = ir.soroban_facts.as_ref() else {
            return result;
        };
        let (structs, enums) = (facts.types.structs.clone(), facts.types.enums.clone());
        if enums.is_empty() {
            return result;
        }
        for func in &mut ir.functions {
            for site in plan(func, &structs, &enums) {
                apply(func, site);
                result.metrics.increment(M_SELECTS, 1);
                result.changed = true;
            }
        }
        result
    }
}

/// One `select` to rewrite.
struct Site {
    select: ValueId,
    cond: ValueId,
    /// The variants chosen when the condition holds, and otherwise.
    arms: [String; 2],
    enum_id: TypeId,
}

/// The discriminant a constant `U32Val` carries.
fn u32_val(func: &HighFunction, v: ValueId) -> Option<u32> {
    let bits = match &func.bindings.get(resolve_use(func, v))?.expr {
        Expr::Literal(Literal::I64(n)) => *n as u64,
        Expr::Literal(Literal::U64(n)) => *n,
        _ => return None,
    };
    (bits & 0xFFFF_FFFF == u64::from(val_abi::TAG_U32_VAL)).then_some((bits >> 32) as u32)
}

fn is_test(func: &HighFunction, v: ValueId) -> bool {
    func.bindings.get(resolve_use(func, v)).is_some_and(|b| {
        matches!(b.ty, IrType::Known(KnownType::Bool) | IrType::Inferred(KnownType::Bool))
            || matches!(&b.expr, Expr::Binary { op, .. } if op.is_comparison())
    })
}

fn plan(func: &HighFunction, structs: &[StructDef], enums: &[EnumDef]) -> Vec<Site> {
    let order = emission_order(func);
    let readers = |v: ValueId| -> usize {
        let mut n = 0;
        for id in &order {
            if let Some(b) = func.bindings.get(*id) {
                b.expr.for_each_value_use(|u| n += usize::from(u == v));
            }
        }
        for (_, b) in func.bindings.iter().filter(|(_, b)| matches!(b.expr, Expr::Phi { .. })) {
            b.expr.for_each_value_use(|u| n += usize::from(u == v));
        }
        func.region.for_each_value_use(|u| n += usize::from(u == v));
        n
    };
    let mut sites = Vec::new();
    for id in &order {
        let Some(b) = func.bindings.get(*id) else { continue };
        let Expr::Struct { fields } = &b.expr else { continue };
        let (IrType::Known(KnownType::UserDefined(sid)) | IrType::Inferred(KnownType::UserDefined(sid))) = &b.ty else {
            continue;
        };
        let Some(def) = structs.iter().find(|s| s.id == *sid) else { continue };
        for (name, value) in fields {
            let Some(KnownType::UserDefined(eid)) =
                def.fields.iter().find(|f| f.name == *name).and_then(|f| known_of_type_ref(&f.ty))
            else {
                continue;
            };
            let Some(en) = enums.iter().find(|e| e.id == eid) else { continue };
            let select = resolve_use(func, *value);
            if *value != select || readers(select) != 1 {
                continue;
            }
            let Some(Expr::Unknown { op_kind: WasmOpcodeKind::Select, args, .. }) = func.bindings.get(select).map(|b| &b.expr)
            else {
                continue;
            };
            let [t, f, c] = args.as_slice() else { continue };
            let case = |v: ValueId| {
                let k = u32_val(func, v)?;
                en.cases.iter().find(|c| c.value == k).map(|c| c.name.clone())
            };
            let (Some(tn), Some(fn_)) = (case(*t), case(*f)) else { continue };
            if !is_test(func, *c) || block_containing(func, select).is_none() {
                continue;
            }
            sites.push(Site { select, cond: *c, arms: [tn, fn_], enum_id: eid });
        }
    }
    sites
}

fn apply(func: &mut HighFunction, site: Site) {
    let Some(block) = block_containing(func, site.select) else { return };
    let ty = IrType::Known(KnownType::UserDefined(site.enum_id));
    let note = |what: &str| Provenance::new(PASS_NAME, ProvenanceSource::SdkPattern, what.to_string());
    let mut made = Vec::new();
    for name in site.arms {
        let id = ValueId::from_index(func.bindings.len() as u32);
        func.bindings.push(Binding::new(
            id,
            ty.clone(),
            Expr::Variant { name, payload: Vec::new() },
            note("enum-select: the variant whose discriminant the constant `U32Val` carries"),
        ));
        made.push(id);
    }
    if let Some(b) = func.blocks.get_mut(block)
        && let Some(pos) = b.bindings.iter().position(|x| *x == site.select)
    {
        b.bindings.splice(pos..pos, made.iter().copied());
    }
    if let Some(b) = func.bindings.get_mut(site.select) {
        b.expr = Expr::Select { cond: site.cond, if_true: made[0], if_false: made[1] };
        b.ty = IrType::Inferred(KnownType::UserDefined(site.enum_id));
        b.add_provenance(note("enum-select: a choice between two variants' encodings is the choice between the variants"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};
    use sordec_common::UnknownReason;
    use sordec_ir::{BinaryOp, EnumCase, SorobanFacts, StructField, TypeRef};

    fn u32val(k: u64) -> Expr {
        Expr::Literal(Literal::I64(((k << 32) | 4) as i64))
    }

    /// `m = Member { role: select(U32Val(t), U32Val(f), d == 1) }`.
    fn ir(t: u64, f: u64, cond_is_test: bool) -> HighIr {
        let exprs = vec![
            Expr::Phi { incoming: vec![] }, // v0 d
            Expr::Literal(Literal::I32(1)), // v1
            if cond_is_test {
                Expr::Binary { op: BinaryOp::Eq, lhs: v(0), rhs: v(1) }
            } else {
                Expr::Binary { op: BinaryOp::Add, lhs: v(0), rhs: v(1) }
            }, // v2
            u32val(t), // v3
            u32val(f), // v4
            Expr::Unknown { op_kind: WasmOpcodeKind::Select, args: vec![v(3), v(4), v(2)], reason: UnknownReason::UnsupportedPattern }, // v5
            Expr::Struct { fields: vec![("role".into(), v(5))] }, // v6
        ];
        let mut func = func_with(exprs, vec![v(0)], vec![1, 2, 3, 4, 5, 6]);
        func.bindings.get_mut(v(6)).expect("struct").ty = IrType::Known(KnownType::UserDefined(TypeId::from_index(2)));
        let mut ir = module(vec![func]);
        let mut types = sordec_ir::TypeRegistry::default();
        types.enums.push(EnumDef {
            id: TypeId::from_index(1),
            name: "Role".into(),
            cases: vec![EnumCase { name: "Member".into(), value: 1 }, EnumCase { name: "Council".into(), value: 2 }],
        });
        types.structs.push(StructDef {
            id: TypeId::from_index(2),
            name: "Member".into(),
            fields: vec![StructField { name: "role".into(), ty: TypeRef::UserDefined(TypeId::from_index(1)) }],
        });
        ir.soroban_facts = Some(SorobanFacts {
            functions: Default::default(),
            types,
            contract_meta: Default::default(),
            env_meta: Default::default(),
        });
        ir
    }

    #[test]
    fn a_select_between_two_variants_encodings_is_the_choice_between_them() {
        let mut ir = ir(1, 2, true);
        assert!(EnumSelectPass.run(&mut ir).changed);
        let f = &ir.functions[0];
        let Some(Expr::Select { cond, if_true, if_false }) = f.bindings.get(v(5)).map(|b| &b.expr) else {
            panic!("{:?}", f.bindings.get(v(5)).map(|b| &b.expr))
        };
        assert_eq!(*cond, v(2));
        let name = |x: ValueId| match f.bindings.get(x).map(|b| &b.expr) {
            Some(Expr::Variant { name, .. }) => name.clone(),
            other => panic!("{other:?}"),
        };
        assert_eq!((name(*if_true), name(*if_false)), ("Member".to_string(), "Council".to_string()));
    }

    #[test]
    fn a_constant_no_variant_carries_is_left_alone() {
        let mut ir = ir(1, 3, true);
        assert!(!EnumSelectPass.run(&mut ir).changed);
    }

    #[test]
    fn a_condition_that_is_no_test_is_left_alone() {
        let mut ir = ir(1, 2, false);
        assert!(!EnumSelectPass.run(&mut ir).changed);
    }
}
