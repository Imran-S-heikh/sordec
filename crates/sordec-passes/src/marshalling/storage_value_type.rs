//! Type a storage read from what the contract writes under the same key.
//!
//! `Storage::get` is generic in its payload, and the wasm carries no trace
//! of the type parameter when nothing converts the read: increment_with_pause
//! reads the pause contract's address and hands it straight on, so the read
//! stays a `Val`, and `let pause = …get(&PAUSE).unwrap();` with no reader to
//! pin it does not compile (`type annotations needed`).
//!
//! The writes are the evidence. `initialize(pause: Address)` stores an
//! `Address` under `PAUSE`, and a key holds what is written to it — so the
//! read of `PAUSE` is an `Address`.
//!
//! ## The gate
//!
//! - **The same key, by what names it.** A resolved enum variant, or a
//!   constant symbol. A key computed at run time names nothing.
//! - **The same tier.** Instance and persistent `PAUSE` are different entries.
//! - **Every typed write agrees.** Two writes of different types under one
//!   key mean the entry is genuinely loosely typed; picking one would be a
//!   guess. An untyped write is no evidence either way.
//! - **Only a read still untyped.** A type the read already has — from its
//!   own conversion, or the spec — is never second-guessed.

use std::collections::HashMap;

use sordec_common::{Provenance, ProvenanceSource, ValueId};
use sordec_ir::{Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Literal, SemanticOp, StorageTier};

use super::sret::emission_order;
use crate::dataflow::resolve_use;
use crate::pass::{Pass, PassResult};
use crate::val_abi::decode_small_symbol;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-storage-value-type";

/// Reads typed from the writes under their key.
const M_TYPED: &str = "marshalling_storage_reads_typed";

/// Types untyped storage reads from the writes under the same key.
#[derive(Debug, Default, Clone, Copy)]
pub struct StorageValueTypePass;

/// What names a storage entry.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
enum Entry {
    Variant(String, String),
    Symbol(String),
}

impl Pass<HighIr> for StorageValueTypePass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        // `None` once two writes disagree.
        let mut written: HashMap<(String, Entry), Option<KnownType>> = HashMap::new();
        for func in &ir.functions {
            // Live writes only: a rewrite's unscheduled residue is no write.
            for id in emission_order(func) {
                let Some(b) = func.bindings.get(id) else { continue };
                let Expr::Semantic(SemanticOp::Known(KnownOp::StorageSet { tier, key, resolved_key, value, .. })) =
                    &b.expr
                else {
                    continue;
                };
                let (Some(t), Some(entry)) = (tier_name(tier), entry_of(func, *key, resolved_key)) else {
                    continue;
                };
                // An untyped write says nothing, for or against — an inlined
                // setter wrapper left behind with its parameter untyped is
                // not a disagreement.
                let Some(ty) = recovered(func.bindings.get(resolve_use(func, *value)).map(|b| &b.ty)) else {
                    continue;
                };
                let ty = Some(ty);
                written
                    .entry((t, entry))
                    .and_modify(|seen| {
                        if *seen != ty {
                            *seen = None;
                        }
                    })
                    .or_insert(ty);
            }
        }
        for func in &mut ir.functions {
            let reads: Vec<(ValueId, KnownType)> = func
                .bindings
                .iter()
                .filter_map(|(id, b)| {
                    let Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet { tier, key, resolved_key, .. })) =
                        &b.expr
                    else {
                        return None;
                    };
                    if !matches!(b.ty, IrType::Unknown(_) | IrType::Known(KnownType::Val) | IrType::Inferred(KnownType::Val)) {
                        return None;
                    }
                    // A read handed to a helper may be handed to its own
                    // conversion — the SDK's `TryFromVal`, outlined — which
                    // takes it raw; typing it would convert it twice.
                    if passed_to_a_helper(func, id) {
                        return None;
                    }
                    let k = (tier_name(tier)?, entry_of(func, *key, resolved_key)?);
                    Some((id, written.get(&k)?.clone()?))
                })
                .collect();
            for (id, ty) in reads {
                if let Some(b) = func.bindings.get_mut(id) {
                    b.ty = IrType::Inferred(ty);
                    b.add_provenance(Provenance::new(
                        PASS_NAME,
                        ProvenanceSource::TypePropagation,
                        "typed from every write under the same key and tier",
                    ));
                    result.metrics.increment(M_TYPED, 1);
                    result.changed = true;
                }
            }
        }
        result
    }
}

/// Whether a live call takes `read`, through any rename, as an argument.
fn passed_to_a_helper(func: &HighFunction, read: ValueId) -> bool {
    emission_order(func).into_iter().any(|id| {
        matches!(
            func.bindings.get(id).map(|b| &b.expr),
            Some(Expr::Call { args, .. }) if args.iter().any(|a| resolve_use(func, *a) == read)
        )
    })
}

/// A write's value type, when it is one worth naming.
fn recovered(ty: Option<&IrType>) -> Option<KnownType> {
    match ty? {
        IrType::Known(k) | IrType::Inferred(k) => match k {
            KnownType::Address
            | KnownType::Symbol
            | KnownType::String
            | KnownType::Bytes
            | KnownType::BytesN(_)
            | KnownType::I128
            | KnownType::U128
            | KnownType::U64
            | KnownType::I64
            | KnownType::U32
            | KnownType::I32
            | KnownType::Bool
            | KnownType::UserDefined(_) => Some(k.clone()),
            _ => None,
        },
        IrType::Unknown(_) => None,
    }
}

fn tier_name(tier: &StorageTier) -> Option<String> {
    match tier {
        StorageTier::Known(t) | StorageTier::Inferred(t) => Some(format!("{t:?}")),
        StorageTier::Unknown(_) => None,
    }
}

fn entry_of(func: &HighFunction, key: ValueId, resolved: &Option<sordec_ir::EnumKey>) -> Option<Entry> {
    if let Some(k) = resolved {
        return Some(Entry::Variant(k.enum_name.clone(), k.variant.clone()));
    }
    match &func.bindings.get(resolve_use(func, key))?.expr {
        Expr::Literal(Literal::Symbol(s)) => Some(Entry::Symbol(s.clone())),
        Expr::Literal(Literal::I64(bits)) => decode_small_symbol(*bits as u64).map(Entry::Symbol),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};
    use sordec_ir::{KnownTier, Missing};

    fn set(key: u32, value: u32) -> Expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::StorageSet {
            tier: StorageTier::Known(KnownTier::Instance),
            durability: v(0),
            key: v(key),
            resolved_key: None,
            value: v(value),
        }))
    }

    fn get(key: u32) -> Expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet {
            tier: StorageTier::Known(KnownTier::Instance),
            durability: v(0),
            key: v(key),
            resolved_key: None,
            missing: Missing::Unwrap,
        }))
    }

    fn shape(second_write: Option<KnownType>) -> HighIr {
        let mut exprs = vec![
            Expr::Phi { incoming: vec![] },                     // v0 the address
            Expr::Literal(Literal::Symbol("PAUSE".into())),     // v1
            set(1, 0),                                          // v2
            get(1),                                             // v3
        ];
        let mut sched = vec![1, 2, 3];
        if second_write.is_some() {
            exprs.push(Expr::Phi { incoming: vec![] }); // v4
            exprs.push(set(1, 4)); // v5
            sched.push(5);
        }
        let mut f = func_with(exprs, vec![v(0)], sched);
        f.bindings.get_mut(v(0)).unwrap().ty = IrType::Known(KnownType::Address);
        if let Some(t) = second_write {
            f.bindings.get_mut(v(4)).unwrap().ty = IrType::Known(t);
        }
        module(vec![f])
    }

    #[test]
    fn a_read_takes_the_type_written_under_its_key() {
        let mut ir = shape(None);
        assert!(StorageValueTypePass.run(&mut ir).changed);
        assert_eq!(ir.functions[0].bindings.get(v(3)).unwrap().ty, IrType::Inferred(KnownType::Address));
    }

    #[test]
    fn disagreeing_writes_leave_the_read_alone() {
        let mut ir = shape(Some(KnownType::U32));
        assert!(!StorageValueTypePass.run(&mut ir).changed);
    }
}
