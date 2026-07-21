//! The annotation vocabulary: recovered IR facts → compact `;;` labels.
//!
//! This is a *different presentation* of the same recovered facts that
//! `dump-hir`'s `pretty_hir` renders: that view spells full
//! `vN: ty = op(args)` expressions for debugging, whereas the WAT
//! annotator wants one terse operation label per line (`storage_get<…>
//! DataKey::Balance`). They deliberately share the provenance-source
//! vocabulary ([`ProvenanceSource::label`](sordec_common::ProvenanceSource::label))
//! so the recognition tags read identically across both outputs, but the
//! operation phrasing is owned here.

use sordec_ir::{
    ClientInterface, CompositeType, DispatchTable, EnumKey, FunctionSignature, KnownOp, KnownTier,
    PanicKind, PrimitiveType, StorageTier, TypeRef, TypeRegistry,
};
use sordec_common::{TypeId, ValueId};

/// Render a function signature as `fn name(p: T, …) -> R`, resolving all
/// user-defined types through `registry`. Shared by the module-header
/// interface banner and the per-function L1 header title.
#[must_use]
pub(crate) fn render_signature(sig: &FunctionSignature, registry: &TypeRegistry) -> String {
    let params: Vec<String> = sig
        .inputs
        .iter()
        .map(|p| format!("{}: {}", p.name, type_ref_label(&p.ty, registry)))
        .collect();
    let ret = match sig.outputs.as_slice() {
        [] => "()".to_string(),
        [one] => type_ref_label(one, registry),
        many => {
            let rendered: Vec<String> = many.iter().map(|t| type_ref_label(t, registry)).collect();
            format!("({})", rendered.join(", "))
        }
    };
    format!("fn {}({}) -> {ret}", sig.name, params.join(", "))
}

/// Compact label for a recognized Soroban operation, without the trailing
/// `[ProvenanceSource]` tag (the caller appends that).
#[must_use]
#[allow(clippy::too_many_lines)]
pub(crate) fn label_known_op(op: &KnownOp) -> String {
    match op {
        KnownOp::StorageGet {
            tier,
            key,
            resolved_key,
            ..
        } => format!("storage_get<{}> {}", tier_label(tier), key_label(*key, resolved_key)),
        KnownOp::StorageSet {
            tier,
            key,
            resolved_key,
            value,
            ..
        } => format!(
            "storage_set<{}> {} = {value}",
            tier_label(tier),
            key_label(*key, resolved_key)
        ),
        KnownOp::StorageHas {
            tier,
            key,
            resolved_key,
            ..
        } => format!("storage_has<{}> {}", tier_label(tier), key_label(*key, resolved_key)),
        KnownOp::StorageRemove {
            tier,
            key,
            resolved_key,
            ..
        } => format!("storage_remove<{}> {}", tier_label(tier), key_label(*key, resolved_key)),
        KnownOp::StorageExtendTtl {
            tier,
            key,
            resolved_key,
            resolved_threshold,
            resolved_extend_to,
            ..
        } => format!(
            "storage_extend_ttl<{}> {} threshold={} extend_to={}",
            tier_label(tier),
            key_label(*key, resolved_key),
            opt_u32(resolved_threshold),
            opt_u32(resolved_extend_to)
        ),
        KnownOp::StorageExtendTtlV2 {
            tier,
            key,
            resolved_key,
            ..
        } => format!(
            "storage_extend_ttl_v2<{}> {}",
            tier_label(tier),
            key_label(*key, resolved_key)
        ),
        KnownOp::ExtendCurrentContractInstanceAndCodeTtl {
            resolved_threshold,
            resolved_extend_to,
            ..
        } => format!(
            "extend_current_contract_instance_and_code_ttl threshold={} extend_to={}",
            opt_u32(resolved_threshold),
            opt_u32(resolved_extend_to)
        ),
        KnownOp::ExtendContractInstanceAndCodeTtl { .. } => {
            "extend_contract_instance_and_code_ttl".to_string()
        }
        KnownOp::ExtendContractInstanceTtl { .. } => "extend_contract_instance_ttl".to_string(),
        KnownOp::ExtendContractCodeTtl { .. } => "extend_contract_code_ttl".to_string(),
        KnownOp::ExtendContractInstanceAndCodeTtlV2 { .. } => {
            "extend_contract_instance_and_code_ttl_v2".to_string()
        }
        KnownOp::RequireAuth { address } => format!("require_auth({address})"),
        KnownOp::RequireAuthForArgs { address, .. } => format!("require_auth_for_args({address})"),
        KnownOp::AuthorizeAsCurrContract { .. } => "authorize_as_current_contract".to_string(),
        KnownOp::AddressConversion { kind, .. } => format!("address::{kind:?}"),
        KnownOp::InvokeContract {
            resolved_callee,
            arg_count,
            interface,
            ..
        } => format!(
            "invoke_contract{}{}{}",
            callee_label(resolved_callee),
            arity_label(arg_count),
            interface_label(interface)
        ),
        KnownOp::TryInvokeContract {
            resolved_callee,
            arg_count,
            interface,
            ..
        } => format!(
            "try_invoke_contract{}{}{}",
            callee_label(resolved_callee),
            arity_label(arg_count),
            interface_label(interface)
        ),
        KnownOp::PublishEvent { topics, .. } => format!("publish_event topics={}", topics.len()),
        KnownOp::GetCurrentContractAddress => "current_contract_address".to_string(),
        KnownOp::GetLedgerSequence => "ledger_sequence".to_string(),
        KnownOp::GetLedgerTimestamp => "ledger_timestamp".to_string(),
        KnownOp::GetLedgerProtocolVersion => "ledger_protocol_version".to_string(),
        KnownOp::GetLedgerNetworkId => "ledger_network_id".to_string(),
        KnownOp::GetMaxLiveUntilLedger => "max_live_until_ledger".to_string(),
        KnownOp::ValCompare { a, b } => format!("val_compare({a}, {b})"),
        KnownOp::PanicWithError { error } => format!("panic_with_error({error})"),
        KnownOp::CryptoOp { kind, .. } => format!("crypto::{kind:?}"),
        KnownOp::PrngOp { kind, .. } => format!("prng::{kind:?}"),
        KnownOp::TestOp { kind, .. } => format!("test::{kind:?}"),
        KnownOp::DeployOp { kind, .. } => format!("deploy::{kind:?}"),
        KnownOp::ValEncodeSmall { ty, value } => format!("val_encode<{ty:?}>({value})"),
        KnownOp::ValDecodeSmall { value } => format!("val_decode({value})"),
        KnownOp::ValTagCheck { value, tag } => format!("val_tag_check({value}, tag={tag:#04x})"),
        KnownOp::ValObject { kind, .. } => format!("val_obj::{kind:?}"),
        KnownOp::SymbolNew { resolved, .. } => format!("symbol_new({})", opt_str(resolved)),
        KnownOp::StringNew { resolved, .. } => format!("string_new({})", opt_str(resolved)),
        KnownOp::BytesNew { resolved, .. } => format!("bytes_new({})", opt_bytes(resolved)),
        KnownOp::VecNew { len, .. } => format!("vec_new(len={len})"),
        KnownOp::MapNew { len, .. } => format!("map_new(len={len})"),
        KnownOp::MapOp { kind, .. } => format!("map::{kind:?}"),
        KnownOp::VecOp { kind, .. } => format!("vec::{kind:?}"),
        KnownOp::BufOp { kind, .. } => format!("buf::{kind:?}"),
        KnownOp::SymbolDispatch { table, .. } => format!("symbol_dispatch {}", dispatch_label(table)),
    }
}

/// Label for a recovered source-level panic leaf.
#[must_use]
pub(crate) fn label_panic(kind: PanicKind) -> String {
    match kind {
        PanicKind::Bare => "panic!() [no error code]".to_string(),
        PanicKind::Unwrap => "panic!() [unwrap: tag-checked]".to_string(),
    }
}

fn tier_label(tier: &StorageTier) -> &'static str {
    match tier {
        StorageTier::Known(t) | StorageTier::Inferred(t) => known_tier_label(*t),
        StorageTier::Unknown(_) => "?",
    }
}

fn known_tier_label(tier: KnownTier) -> &'static str {
    match tier {
        KnownTier::Persistent => "persistent",
        KnownTier::Temporary => "temporary",
        KnownTier::Instance => "instance",
    }
}

fn key_label(key: ValueId, resolved: &Option<EnumKey>) -> String {
    match resolved {
        Some(k) => format!("{}::{}", k.enum_name, k.variant),
        None => key.to_string(),
    }
}

fn opt_u32(v: &Option<u32>) -> String {
    v.map_or_else(|| "?".to_string(), |n| n.to_string())
}

fn opt_str(v: &Option<String>) -> String {
    v.as_ref().map_or_else(|| "?".to_string(), |s| format!("{s:?}"))
}

fn opt_bytes(v: &Option<Vec<u8>>) -> String {
    v.as_ref().map_or_else(|| "?".to_string(), |b| format!("{b:02x?}"))
}

fn callee_label(callee: &Option<String>) -> String {
    callee
        .as_ref()
        .map_or_else(String::new, |c| format!(" {c}"))
}

fn arity_label(arg_count: &Option<u32>) -> String {
    arg_count.map_or_else(String::new, |n| format!("/{n}"))
}

fn interface_label(interface: &Option<ClientInterface>) -> String {
    match interface {
        Some(ClientInterface::Sep41Token) => " [SEP-41]".to_string(),
        None => String::new(),
    }
}

fn dispatch_label(table: &DispatchTable) -> String {
    let name = table.enum_name.as_deref().unwrap_or("");
    format!("{name}{{{}}}", table.cases.join(", "))
}

/// Render a [`TypeRef`] to a compact Rust-ish type name, resolving
/// user-defined types through the registry.
#[must_use]
pub(crate) fn type_ref_label(ty: &TypeRef, reg: &TypeRegistry) -> String {
    match ty {
        TypeRef::Primitive(p) => primitive_label(*p).to_string(),
        TypeRef::Composite(c) => composite_label(c, reg),
        TypeRef::UserDefined(id) => udt_name(reg, *id).unwrap_or("<udt>").to_string(),
        TypeRef::Unknown(_) => "?".to_string(),
    }
}

fn composite_label(c: &CompositeType, reg: &TypeRegistry) -> String {
    match c {
        CompositeType::Option(t) => format!("Option<{}>", type_ref_label(t, reg)),
        CompositeType::Result(t, e) => {
            format!("Result<{}, {}>", type_ref_label(t, reg), type_ref_label(e, reg))
        }
        CompositeType::Vec(t) => format!("Vec<{}>", type_ref_label(t, reg)),
        CompositeType::Map(k, v) => {
            format!("Map<{}, {}>", type_ref_label(k, reg), type_ref_label(v, reg))
        }
        CompositeType::Tuple(items) => {
            let inner: Vec<String> = items.iter().map(|t| type_ref_label(t, reg)).collect();
            format!("({})", inner.join(", "))
        }
        CompositeType::BytesN(n) => format!("BytesN<{n}>"),
    }
}

fn udt_name(reg: &TypeRegistry, id: TypeId) -> Option<&str> {
    reg.structs
        .iter()
        .find(|d| d.id == id)
        .map(|d| d.name.as_str())
        .or_else(|| reg.unions.iter().find(|d| d.id == id).map(|d| d.name.as_str()))
        .or_else(|| reg.enums.iter().find(|d| d.id == id).map(|d| d.name.as_str()))
        .or_else(|| reg.errors.iter().find(|d| d.id == id).map(|d| d.name.as_str()))
        .or_else(|| reg.events.iter().find(|d| d.id == id).map(|d| d.name.as_str()))
}

fn primitive_label(p: PrimitiveType) -> &'static str {
    match p {
        PrimitiveType::Val => "Val",
        PrimitiveType::Bool => "bool",
        PrimitiveType::Void => "()",
        PrimitiveType::Error => "Error",
        PrimitiveType::U32 => "u32",
        PrimitiveType::I32 => "i32",
        PrimitiveType::U64 => "u64",
        PrimitiveType::I64 => "i64",
        PrimitiveType::Timepoint => "Timepoint",
        PrimitiveType::Duration => "Duration",
        PrimitiveType::U128 => "u128",
        PrimitiveType::I128 => "i128",
        PrimitiveType::U256 => "U256",
        PrimitiveType::I256 => "I256",
        PrimitiveType::Bytes => "Bytes",
        PrimitiveType::String => "String",
        PrimitiveType::Symbol => "Symbol",
        PrimitiveType::Address => "Address",
        PrimitiveType::MuxedAddress => "MuxedAddress",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_ir::KnownType;

    #[test]
    fn storage_get_labels_tier_and_resolved_key() {
        let op = KnownOp::StorageGet {
            tier: StorageTier::Known(KnownTier::Persistent),
            durability: ValueId::new(1),
            key: ValueId::new(2),
            resolved_key: Some(EnumKey {
                enum_name: "DataKey".to_string(),
                variant: "Balance".to_string(),
                payload: vec![],
            }),
        };
        assert_eq!(label_known_op(&op), "storage_get<persistent> DataKey::Balance");
    }

    #[test]
    fn unresolved_key_falls_back_to_value_id() {
        let op = KnownOp::StorageHas {
            tier: StorageTier::Unknown(sordec_common::UnknownReason::UpstreamUnknown),
            durability: ValueId::new(1),
            key: ValueId::new(7),
            resolved_key: None,
        };
        assert_eq!(label_known_op(&op), "storage_has<?> v7");
    }

    #[test]
    fn grouped_ops_use_kind_debug_name() {
        let op = KnownOp::ValObject {
            kind: sordec_ir::ValObjectKind::ObjToU64,
            args: vec![ValueId::new(3)],
        };
        assert_eq!(label_known_op(&op), "val_obj::ObjToU64");
    }

    #[test]
    fn val_encode_carries_payload_type() {
        let op = KnownOp::ValEncodeSmall {
            ty: KnownType::U64,
            value: ValueId::new(4),
        };
        assert_eq!(label_known_op(&op), "val_encode<U64>(v4)");
    }

    #[test]
    fn composite_types_nest() {
        let reg = TypeRegistry::default();
        let ty = TypeRef::Composite(CompositeType::Vec(Box::new(TypeRef::Primitive(
            PrimitiveType::Address,
        ))));
        assert_eq!(type_ref_label(&ty, &reg), "Vec<Address>");
    }

    #[test]
    fn panic_kinds_distinguish() {
        assert_ne!(label_panic(PanicKind::Bare), label_panic(PanicKind::Unwrap));
    }
}
