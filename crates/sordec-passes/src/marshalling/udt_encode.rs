//! Recover a `#[contracttype]` struct *literal* — the construction side of
//! [`super::udt_decode`].
//!
//! # The shape
//!
//! `State { count, last_incr }` is one expression in the source. The
//! `TryIntoVal` that `#[contracttype]` derives writes each field's `Val`
//! into a frame slot and hands the host the slot array beside a key table
//! of the field names, in rodata:
//!
//! ```text
//! store fp+0  <- val_encode<U32>(a)                 KEYS = ["count", "last_incr"]
//! store fp+8  <- val_encode<U32>(b)
//! m = map_new_from_linear_memory(&KEYS, fp, 2)   →  m = State { count: a, last_incr: b }
//! ```
//!
//! # What this pass does
//!
//! It reads the same key table [`super::udt_decode`] reads, finds the one
//! declared struct whose field names are exactly those keys, and rewrites
//! the map construction to the struct literal, taking each field's value
//! from the slot store at its offset and stripping the `Val` encode from
//! it. The stores are then dead and the frame elision drops them, along
//! with the shadow-stack bracket that reserved the slots.
//!
//! # Why the rewrite is exact
//!
//! The re-emitted crate declares the struct with `#[contracttype]`, so
//! writing the literal regenerates the derived conversion: the key table,
//! the slot stores and this very host call. The same relocation argument
//! as every marshalling elision, in the direction the decode pass does not
//! cover.
//!
//! # Gates
//!
//! - **The keys name exactly one declared struct.** A table matching no
//!   struct, or more than one, is left alone — it may be a `Map` the source
//!   really built.
//! - **Every field has a slot.** The vals array is `len` slots at 8-byte
//!   stride from the base, and every one must hold a value proven at the
//!   construction point. A missing slot means the frame analysis lost the
//!   store, and half a literal is worse than none.
//! - **The field order is the declaration's.** The key table is sorted by
//!   the derive, so the literal is spelled in the struct's own order
//!   rather than the table's.

use sordec_common::{Provenance, ProvenanceSource, ValueId};
use sordec_ir::{
    Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, MemWidth, SemanticOp, StructDef,
};

use super::udt_decode::{raw_address, read_keys, struct_for};
use crate::dataflow::{canon_addr, facts_at, resolve_use};
use crate::dataflow::trace_bytes::trace_u32val;
use crate::metrics_catalog::MARSHALLING_UDT_ENCODES as M_ENCODES;
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-udt-encode";

/// Folds a derived struct encode into the struct literal it came from.
#[derive(Debug, Default, Clone, Copy)]
pub struct UdtEncodePass;

impl Pass<HighIr> for UdtEncodePass {
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
        let memory = ir.memory.clone();
        for func in &mut ir.functions {
            let literals: Vec<_> = func
                .bindings
                .iter()
                .filter_map(|(id, _)| literal_at(func, &memory, &structs, id))
                .collect();
            for literal in literals {
                if let Some(b) = func.bindings.get_mut(literal.at) {
                    b.expr = Expr::Struct { fields: literal.fields };
                    b.ty = literal.ty;
                    b.add_provenance(Provenance::new(
                        PASS_NAME,
                        ProvenanceSource::SdkPattern,
                        "the derived struct encode: its key table and slot stores, as the literal",
                    ));
                    result.metrics.increment(M_ENCODES, 1);
                    result.changed = true;
                }
            }
        }
        result
    }
}

/// One recovered construction: the value it binds, the struct it is, and
/// the field values it is made of.
struct Literal {
    at: ValueId,
    ty: IrType,
    fields: Vec<(String, ValueId)>,
}

/// The struct literal a map construction is, if it is one.
fn literal_at(
    func: &HighFunction,
    memory: &sordec_ir::MemoryImage,
    structs: &[StructDef],
    id: ValueId,
) -> Option<Literal> {
    let Expr::Semantic(SemanticOp::Known(KnownOp::MapNew { keys_pos, vals_pos, len })) =
        &func.bindings.get(id)?.expr
    else {
        return None;
    };
    let len = trace_u32val(func, *len)?;
    let keys = read_keys(memory, trace_u32val(func, *keys_pos)?, len)?;
    let def = struct_for(structs, &keys)?;
    // Where the slots live, and what each holds at the construction.
    let (base, start) = canon_addr(func, raw_address(func, *vals_pos));
    let facts = facts_at(func, id, base);
    let mut by_key = Vec::with_capacity(keys.len());
    for (i, key) in keys.iter().enumerate() {
        let offset = start.checked_add(u32::try_from(i).ok()?.checked_mul(8)?)?;
        let slot = facts.value_at(offset, MemWidth::W8)?;
        by_key.push((key.clone(), encoded_value(func, slot)));
    }
    // Spelled in the struct's declared order, not the key table's.
    let fields = def
        .fields
        .iter()
        .map(|f| by_key.iter().find(|(k, _)| *k == f.name).map(|(_, v)| (f.name.clone(), *v)))
        .collect::<Option<Vec<_>>>()?;
    Some(Literal { at: id, ty: IrType::Known(KnownType::UserDefined(def.id)), fields })
}

/// The value behind a field's `Val` encode. A field whose type is already
/// a `Val` — an object handle — is stored as itself and comes back
/// unchanged.
fn encoded_value(func: &HighFunction, slot: ValueId) -> ValueId {
    let value = resolve_use(func, slot);
    match func.bindings.get(value).map(|b| &b.expr) {
        Some(Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { value, .. }))) => {
            resolve_use(func, *value)
        }
        _ => value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};
    use sordec_common::TypeId;
    use sordec_ir::{
        DataSegment, EnvCompatibility, Literal, MemoryImage, PrimitiveType, SorobanFacts,
        StructField, TypeRef, TypeRegistry,
    };

    /// `KEYS` at 2000: two entries pointing at "count" (2100) and
    /// "last_incr" (2110).
    fn memory() -> MemoryImage {
        let mut table = Vec::new();
        for (ptr, n) in [(2100u32, 5u32), (2110, 9)] {
            table.extend_from_slice(&ptr.to_le_bytes());
            table.extend_from_slice(&n.to_le_bytes());
        }
        MemoryImage::from_segments(vec![
            DataSegment { offset: 2000, bytes: table },
            DataSegment { offset: 2100, bytes: b"count".to_vec() },
            DataSegment { offset: 2110, bytes: b"last_incr".to_vec() },
        ])
    }

    fn registry() -> Vec<StructDef> {
        vec![StructDef {
            id: TypeId::new(7),
            name: "State".to_string(),
            fields: vec![
                StructField { name: "count".to_string(), ty: TypeRef::Primitive(PrimitiveType::U32) },
                StructField {
                    name: "last_incr".to_string(),
                    ty: TypeRef::Primitive(PrimitiveType::U32),
                },
            ],
        }]
    }

    /// `store fp+0 <- enc(count); store fp+8 <- enc(last_incr);
    /// map_new(&KEYS, fp, len)`.
    fn encoder(len: u32) -> HighFunction {
        let enc = |value: ValueId| {
            Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty: KnownType::U32, value }))
        };
        let store = |value: ValueId, offset: u32| Expr::Store {
            addr: v(0),
            value,
            offset,
            width: MemWidth::W8,
        };
        func_with(
            vec![
                Expr::Phi { incoming: vec![] }, // v0 frame base
                Expr::Phi { incoming: vec![] }, // v1 count
                Expr::Phi { incoming: vec![] }, // v2 last_incr
                enc(v(1)),                      // v3
                store(v(3), 0),                 // v4
                enc(v(2)),                      // v5
                store(v(5), 8),                 // v6
                Expr::Literal(Literal::U32(2000)), // v7 keys
                Expr::Literal(Literal::U32(len)),  // v8 len
                Expr::Semantic(SemanticOp::Known(KnownOp::MapNew {
                    keys_pos: v(7),
                    vals_pos: v(0),
                    len: v(8),
                })), // v9
            ],
            vec![v(0), v(1), v(2)],
            vec![3, 4, 5, 6, 7, 8, 9],
        )
    }

    fn ir(f: HighFunction) -> HighIr {
        let mut m = module(vec![f]);
        m.memory = memory();
        m.soroban_facts = Some(SorobanFacts {
            functions: std::collections::BTreeMap::new(),
            types: TypeRegistry { structs: registry(), ..Default::default() },
            contract_meta: std::collections::BTreeMap::new(),
            env_meta: EnvCompatibility::default(),
        });
        m
    }

    #[test]
    fn a_key_table_and_its_slots_become_the_struct_literal() {
        let mut m = ir(encoder(2));
        assert!(UdtEncodePass.run(&mut m).changed);
        let binding = m.functions[0].bindings.get(v(9)).unwrap();
        let Expr::Struct { fields } = &binding.expr else {
            panic!("the construction is the literal, got {:?}", binding.expr);
        };
        assert_eq!(
            fields,
            &vec![("count".to_string(), v(1)), ("last_incr".to_string(), v(2))],
            "declared order, each value from behind its encode"
        );
        assert!(matches!(binding.ty, IrType::Known(KnownType::UserDefined(id)) if id == TypeId::new(7)));
    }

    /// A table whose length names no declared struct is a `Map` the source
    /// really built.
    #[test]
    fn a_table_that_names_no_struct_declines() {
        let mut m = ir(encoder(1));
        assert!(!UdtEncodePass.run(&mut m).changed);
    }

    #[test]
    fn the_pass_is_idempotent() {
        let mut m = ir(encoder(2));
        assert!(UdtEncodePass.run(&mut m).changed);
        assert!(!UdtEncodePass.run(&mut m).changed);
    }
}
