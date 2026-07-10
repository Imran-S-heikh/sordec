//! Pretty-printer for [`HighIr`] — the text output of `sordec dump-hir`.
//!
//! Renders the mechanically-lowered high IR: every value as a typed
//! [`Binding`] with its expression and latest provenance note. At the L1
//! stage all types are `?` (unknown) and all host calls render as
//! `host:<module>:<name>` (unrecognized); as recognizers land, literals
//! and semantic operations replace the raw forms and the change shows up
//! here.
//!
//! # Output format
//!
//! ```text
//! function func_0 [exported as "add"] {
//!   ;; region: unstructured (entry bb0, structuring not yet run)
//!   bb0:
//!     v3: ? = i64.add(v1, v2)          ;; DataFlow: operator: Arithmetic
//!     v6: ? = host:l:put_contract_data(v4, v5)   ;; DataFlow: operator: Call
//!   ;; unscheduled bindings (block params / phis):
//!     v0: ? = phi [bb1 -> v9]          ;; DataFlow: block param
//! }
//! ```
//!
//! Control flow is not structured at the L1 layer, so the region is a
//! single `;; unstructured` banner rather than nested `if`/`loop`. Block
//! parameters (phi nodes) are not scheduled into any block's binding
//! list, so they render in a trailing "unscheduled" section.

use std::collections::HashSet;
use std::io::{self, Write};

use sordec_common::{IrId, ProvenanceSource, ValueId};
use sordec_ir::{
    BinaryOp, Binding, Expr, HighFunction, HighIr, IrType, KnownOp, KnownTier, KnownType, Literal,
    Region, SemanticOp, StorageTier, UnaryOp,
};
use sordec_passes::host_calls;

/// Render a [`HighIr`] to `out` as text.
///
/// # Errors
///
/// Returns the underlying [`io::Error`] when writing to `out` fails.
pub fn render_high_ir(out: &mut impl Write, high: &HighIr) -> io::Result<()> {
    if high.functions.is_empty() {
        writeln!(out, ";; (module has no local functions)")?;
        return Ok(());
    }
    for (i, func) in high.functions.iter().enumerate() {
        if i > 0 {
            writeln!(out)?;
        }
        render_function(out, func)?;
    }
    Ok(())
}

fn render_function(out: &mut impl Write, func: &HighFunction) -> io::Result<()> {
    match &func.name {
        Some(name) => writeln!(
            out,
            "function func_{} [exported as {name:?}] {{",
            func.id.index()
        )?,
        None => writeln!(out, "function func_{} {{", func.id.index())?,
    }

    render_region_banner(out, &func.region)?;

    // Bindings grouped by block, in block order. Track which bindings we
    // rendered so phis/unscheduled values can be shown afterward.
    let mut rendered: HashSet<ValueId> = HashSet::new();
    for (block_id, block) in func.blocks.iter() {
        writeln!(out, "  bb{}:", block_id.index())?;
        for &value_id in &block.bindings {
            if let Some(binding) = func.bindings.get(value_id) {
                render_binding(out, binding)?;
                rendered.insert(value_id);
            }
        }
    }

    // Bindings not scheduled into any block (block params / phis).
    let unscheduled: Vec<&Binding> = func
        .bindings
        .iter()
        .filter(|(id, _)| !rendered.contains(id))
        .map(|(_, b)| b)
        .collect();
    if !unscheduled.is_empty() {
        writeln!(out, "  ;; unscheduled bindings (block params / phis):")?;
        for binding in unscheduled {
            render_binding(out, binding)?;
        }
    }

    writeln!(out, "}}")?;
    Ok(())
}

fn render_region_banner(out: &mut impl Write, region: &Region) -> io::Result<()> {
    match region {
        Region::Unstructured { entry, .. } => writeln!(
            out,
            "  ;; region: unstructured (entry bb{}, structuring not yet run)",
            entry.index()
        ),
        // Structured regions arrive with the Phase-3 structuring pass;
        // until then this arm is unreachable in practice.
        _ => writeln!(out, "  ;; region: structured"),
    }
}

fn render_binding(out: &mut impl Write, binding: &Binding) -> io::Result<()> {
    write!(
        out,
        "    v{}: {} = ",
        binding.id.index(),
        ir_type_str(&binding.ty)
    )?;
    render_expr(out, &binding.expr)?;
    let prov = binding.latest_provenance();
    writeln!(
        out,
        "  ;; {}: {}",
        provenance_source_str(prov.source),
        prov.note
    )
}

fn render_expr(out: &mut impl Write, expr: &Expr) -> io::Result<()> {
    match expr {
        Expr::Semantic(SemanticOp::Known(op)) => render_known_op(out, op),
        Expr::Semantic(SemanticOp::Unknown {
            host_module,
            host_fn,
            args,
            ..
        }) => {
            match host_calls::resolve(host_module, host_fn) {
                Some(hc) => write!(out, "host:{}:{}", hc.module, hc.friendly_name)?,
                None => write!(out, "host:{host_module}:{host_fn}")?,
            }
            render_args(out, args)
        }
        Expr::Literal(lit) => render_literal(out, lit),
        Expr::Use(value) => write!(out, "v{}", value.index()),
        Expr::Unary { op, value } => write!(out, "{}(v{})", unary_str(*op), value.index()),
        Expr::Binary { op, lhs, rhs } => {
            write!(out, "{} v{}, v{}", binary_str(*op), lhs.index(), rhs.index())
        }
        Expr::Call { target, args } => {
            write!(out, "call func_{}", target.index())?;
            render_args(out, args)
        }
        Expr::IndirectCall {
            table,
            sig,
            callee,
            args,
        } => {
            write!(
                out,
                "call_indirect table={table} sig={sig} via v{}",
                callee.index()
            )?;
            render_args(out, args)
        }
        Expr::Phi { incoming } => {
            write!(out, "phi [")?;
            for (i, (block, value)) in incoming.iter().enumerate() {
                if i > 0 {
                    write!(out, ", ")?;
                }
                write!(out, "bb{} -> v{}", block.index(), value.index())?;
            }
            write!(out, "]")
        }
        Expr::GlobalGet { index } => write!(out, "global.get {index}"),
        Expr::Load { addr, offset, .. } => {
            write!(out, "load v{} offset={offset}", addr.index())
        }
        Expr::Store {
            addr,
            value,
            offset,
        } => write!(
            out,
            "store v{} <- v{} offset={offset}",
            addr.index(),
            value.index()
        ),
        Expr::Unknown { op_kind, args, .. } => {
            write!(out, "<unrecovered {op_kind:?}>")?;
            render_args(out, args)
        }
    }
}

/// Render a recognized [`KnownOp`]. The four Val-encoding ops (C1) get
/// dedicated forms; the other KnownOps keep the Debug fallback until
/// their own recognizers land and earn a rendering.
fn render_known_op(out: &mut impl Write, op: &KnownOp) -> io::Result<()> {
    use sordec_passes::val_abi;
    match op {
        KnownOp::ValEncodeSmall { ty, value } => {
            write!(out, "val_encode<{}>(v{})", known_type_str(ty), value.index())
        }
        KnownOp::ValDecodeSmall { value } => {
            write!(out, "val_decode(v{})", value.index())
        }
        KnownOp::ValTagCheck { value, tag } => {
            let name = val_abi::tag_name(*tag).unwrap_or("?");
            write!(out, "has_tag(v{}, {name})", value.index())
        }
        KnownOp::ValObject { kind, args } => {
            write!(out, "{}", val_abi::obj_kind_name(*kind))?;
            render_args(out, args)
        }
        // ---- Storage (C2) + TTL (C3) ----
        KnownOp::StorageGet { tier, key } => {
            write!(out, "storage_get<{}>(v{})", tier_str(tier), key.index())
        }
        KnownOp::StorageSet { tier, key, value } => write!(
            out,
            "storage_set<{}>(v{}, v{})",
            tier_str(tier),
            key.index(),
            value.index()
        ),
        KnownOp::StorageHas { tier, key } => {
            write!(out, "storage_has<{}>(v{})", tier_str(tier), key.index())
        }
        KnownOp::StorageRemove { tier, key } => {
            write!(out, "storage_remove<{}>(v{})", tier_str(tier), key.index())
        }
        KnownOp::StorageExtendTtl {
            tier,
            key,
            threshold,
            extend_to,
        } => write!(
            out,
            "extend_ttl<{}>(v{}, v{}, v{})",
            tier_str(tier),
            key.index(),
            threshold.index(),
            extend_to.index()
        ),
        KnownOp::StorageExtendTtlV2 {
            tier,
            key,
            extend_to,
            min_extension,
            max_extension,
        } => write!(
            out,
            "extend_ttl_v2<{}>(v{}, v{}, v{}, v{})",
            tier_str(tier),
            key.index(),
            extend_to.index(),
            min_extension.index(),
            max_extension.index()
        ),
        KnownOp::ExtendCurrentContractInstanceAndCodeTtl {
            threshold,
            extend_to,
        } => write!(
            out,
            "extend_instance_and_code_ttl(v{}, v{})",
            threshold.index(),
            extend_to.index()
        ),
        KnownOp::ExtendContractInstanceAndCodeTtl {
            contract,
            threshold,
            extend_to,
        } => write!(
            out,
            "extend_contract_instance_and_code_ttl(v{}, v{}, v{})",
            contract.index(),
            threshold.index(),
            extend_to.index()
        ),
        KnownOp::ExtendContractInstanceTtl {
            contract,
            threshold,
            extend_to,
        } => write!(
            out,
            "extend_contract_instance_ttl(v{}, v{}, v{})",
            contract.index(),
            threshold.index(),
            extend_to.index()
        ),
        KnownOp::ExtendContractCodeTtl {
            contract,
            threshold,
            extend_to,
        } => write!(
            out,
            "extend_contract_code_ttl(v{}, v{}, v{})",
            contract.index(),
            threshold.index(),
            extend_to.index()
        ),
        KnownOp::ExtendContractInstanceAndCodeTtlV2 {
            contract,
            extension_scope,
            extend_to,
            min_extension,
            max_extension,
        } => write!(
            out,
            "extend_contract_instance_and_code_ttl_v2(v{}, v{}, v{}, v{}, v{})",
            contract.index(),
            extension_scope.index(),
            extend_to.index(),
            min_extension.index(),
            max_extension.index()
        ),
        // ---- Auth + address (C4) ----
        KnownOp::RequireAuth { address } => write!(out, "require_auth(v{})", address.index()),
        KnownOp::RequireAuthForArgs { address, args } => {
            write!(out, "require_auth_for_args(v{}", address.index())?;
            for a in args {
                write!(out, ", v{}", a.index())?;
            }
            write!(out, ")")
        }
        KnownOp::AuthorizeAsCurrContract { auth_entries } => {
            write!(out, "authorize_as_curr_contract(v{})", auth_entries.index())
        }
        KnownOp::AddressConversion { kind, args } => {
            write!(out, "{}", val_abi::addr_kind_name(*kind))?;
            render_args(out, args)
        }
        // ---- Context (C15) + events (C14) + panic (C16-partial) ----
        KnownOp::GetCurrentContractAddress => write!(out, "get_current_contract_address()"),
        KnownOp::GetLedgerSequence => write!(out, "get_ledger_sequence()"),
        KnownOp::GetLedgerTimestamp => write!(out, "get_ledger_timestamp()"),
        KnownOp::GetLedgerProtocolVersion => write!(out, "get_ledger_protocol_version()"),
        KnownOp::GetLedgerNetworkId => write!(out, "get_ledger_network_id()"),
        KnownOp::GetMaxLiveUntilLedger => write!(out, "get_max_live_until_ledger()"),
        KnownOp::PublishEvent { topics, data } => {
            write!(out, "publish_event(")?;
            for t in topics {
                write!(out, "v{}, ", t.index())?;
            }
            write!(out, "v{})", data.index())
        }
        KnownOp::ValCompare { a, b } => write!(out, "val_cmp(v{}, v{})", a.index(), b.index()),
        KnownOp::PanicWithError { error } => {
            write!(out, "panic_with_error(v{})", error.index())
        }
        // ---- Linear-memory constructors ----
        // Resolved literals render as the recovered value; unresolved ones
        // show the raw (pos, len) operands the const-prop engine will later
        // resolve.
        KnownOp::SymbolNew {
            lm_pos,
            len,
            resolved,
        } => match resolved {
            Some(s) => write!(out, "symbol_new({s:?})"),
            None => write!(out, "symbol_new(v{}, v{})", lm_pos.index(), len.index()),
        },
        KnownOp::StringNew {
            lm_pos,
            len,
            resolved,
        } => match resolved {
            Some(s) => write!(out, "string_new({s:?})"),
            None => write!(out, "string_new(v{}, v{})", lm_pos.index(), len.index()),
        },
        KnownOp::BytesNew {
            lm_pos,
            len,
            resolved,
        } => match resolved {
            Some(bytes) => {
                write!(out, "bytes_new(0x")?;
                for b in bytes {
                    write!(out, "{b:02x}")?;
                }
                write!(out, ")")
            }
            None => write!(out, "bytes_new(v{}, v{})", lm_pos.index(), len.index()),
        },
        KnownOp::VecNew { vals_pos, len } => {
            write!(out, "vec_new(v{}, v{})", vals_pos.index(), len.index())
        }
        KnownOp::MapNew {
            keys_pos,
            vals_pos,
            len,
        } => write!(
            out,
            "map_new(v{}, v{}, v{})",
            keys_pos.index(),
            vals_pos.index(),
            len.index()
        ),
        // ---- Collections / bytes ----
        KnownOp::MapOp { kind, args } => render_call(out, val_abi::map_kind_name(*kind), args),
        KnownOp::VecOp { kind, args } => render_call(out, val_abi::vec_kind_name(*kind), args),
        KnownOp::BufOp { kind, args } => render_call(out, val_abi::buf_kind_name(*kind), args),
        // ---- Cross-contract calls ----
        KnownOp::InvokeContract {
            contract,
            function,
            args,
        } => {
            write!(out, "invoke_contract(v{}, v{}", contract.index(), function.index())?;
            for a in args {
                write!(out, ", v{}", a.index())?;
            }
            write!(out, ")")
        }
        KnownOp::TryInvokeContract {
            contract,
            function,
            args,
        } => {
            write!(
                out,
                "try_invoke_contract(v{}, v{}",
                contract.index(),
                function.index()
            )?;
            for a in args {
                write!(out, ", v{}", a.index())?;
            }
            write!(out, ")")
        }
        // The remaining KnownOps get dedicated renderings when their
        // recognizers land; until then an inspection-only Debug form.
        other => write!(out, "{other:?}"),
    }
}

fn render_args(out: &mut impl Write, args: &[ValueId]) -> io::Result<()> {
    if args.is_empty() {
        return Ok(());
    }
    write!(out, "(")?;
    for (i, arg) in args.iter().enumerate() {
        if i > 0 {
            write!(out, ", ")?;
        }
        write!(out, "v{}", arg.index())?;
    }
    write!(out, ")")
}

/// Render `name(v1, v2, …)`, keeping the parens for a nullary call —
/// unlike [`render_args`], which omits them (its callers suffix an
/// argument-less form onto identifiers, not calls).
fn render_call(out: &mut impl Write, name: &str, args: &[ValueId]) -> io::Result<()> {
    write!(out, "{name}")?;
    if args.is_empty() {
        return write!(out, "()");
    }
    render_args(out, args)
}

fn render_literal(out: &mut impl Write, lit: &Literal) -> io::Result<()> {
    match lit {
        Literal::I32(n) => write!(out, "{n}i32"),
        Literal::I64(n) => write!(out, "{n}i64"),
        Literal::U32(n) => write!(out, "{n}u32"),
        Literal::U64(n) => write!(out, "{n}u64"),
        Literal::F32(x) => write!(out, "{x}f32"),
        Literal::F64(x) => write!(out, "{x}f64"),
        Literal::Bool(b) => write!(out, "{b}"),
        Literal::Symbol(s) => write!(out, "symbol!({s:?})"),
        Literal::String(s) => write!(out, "{s:?}"),
        Literal::Bytes(b) => write!(out, "bytes[{}]", b.len()),
        Literal::Unit => write!(out, "()"),
    }
}

// ---------------------------------------------------------------------
// Type + operator name helpers
// ---------------------------------------------------------------------

/// Render an [`IrType`] with certainty markers: `?` for unknown,
/// `<type>?` for inferred, bare `<type>` for known. At L1 everything is
/// `?`; the other arms serve the type-recovery pass that lands later.
fn ir_type_str(ty: &IrType) -> String {
    match ty {
        IrType::Known(k) => known_type_str(k),
        IrType::Inferred(k) => format!("{}?", known_type_str(k)),
        IrType::Unknown(_) => "?".to_string(),
    }
}

/// Render a storage tier with certainty: `Known` → the name,
/// `Inferred` → `name?`, `Unknown` → `?`. Mirrors the `IrType`
/// certainty-marker convention.
fn tier_str(tier: &StorageTier) -> &'static str {
    match tier {
        StorageTier::Known(t) => known_tier_str(t),
        StorageTier::Inferred(t) => known_tier_inferred_str(t),
        StorageTier::Unknown(_) => "?",
    }
}

fn known_tier_str(t: &KnownTier) -> &'static str {
    match t {
        KnownTier::Persistent => "persistent",
        KnownTier::Temporary => "temporary",
        KnownTier::Instance => "instance",
    }
}

fn known_tier_inferred_str(t: &KnownTier) -> &'static str {
    match t {
        KnownTier::Persistent => "persistent?",
        KnownTier::Temporary => "temporary?",
        KnownTier::Instance => "instance?",
    }
}

fn known_type_str(k: &KnownType) -> String {
    match k {
        KnownType::Bool => "bool".to_string(),
        KnownType::Unit => "()".to_string(),
        KnownType::U32 => "u32".to_string(),
        KnownType::I32 => "i32".to_string(),
        KnownType::U64 => "u64".to_string(),
        KnownType::I64 => "i64".to_string(),
        KnownType::U128 => "u128".to_string(),
        KnownType::I128 => "i128".to_string(),
        KnownType::U256 => "u256".to_string(),
        KnownType::I256 => "i256".to_string(),
        KnownType::Symbol => "Symbol".to_string(),
        KnownType::String => "String".to_string(),
        KnownType::Bytes => "Bytes".to_string(),
        KnownType::BytesN(n) => format!("BytesN<{n}>"),
        KnownType::Address => "Address".to_string(),
        KnownType::MuxedAddress => "MuxedAddress".to_string(),
        KnownType::Timepoint => "Timepoint".to_string(),
        KnownType::Duration => "Duration".to_string(),
        KnownType::Error => "Error".to_string(),
        KnownType::Val => "Val".to_string(),
        KnownType::Option(inner) => format!("Option<{}>", ir_type_str(inner)),
        KnownType::Result(ok, err) => {
            format!("Result<{}, {}>", ir_type_str(ok), ir_type_str(err))
        }
        KnownType::Vec(inner) => format!("Vec<{}>", ir_type_str(inner)),
        KnownType::Map(key, val) => format!("Map<{}, {}>", ir_type_str(key), ir_type_str(val)),
        KnownType::Tuple(items) => {
            let inner: Vec<String> = items.iter().map(ir_type_str).collect();
            format!("({})", inner.join(", "))
        }
        KnownType::UserDefined(id) => format!("ty{}", id.index()),
    }
}

fn binary_str(op: BinaryOp) -> &'static str {
    match op {
        BinaryOp::Add => "add",
        BinaryOp::Sub => "sub",
        BinaryOp::Mul => "mul",
        BinaryOp::Div => "div",
        BinaryOp::Rem => "rem",
        BinaryOp::BitAnd => "and",
        BinaryOp::BitOr => "or",
        BinaryOp::BitXor => "xor",
        BinaryOp::Shl => "shl",
        BinaryOp::Shr => "shr",
        BinaryOp::Rotl => "rotl",
        BinaryOp::Rotr => "rotr",
        BinaryOp::Eq => "eq",
        BinaryOp::Ne => "ne",
        BinaryOp::Lt => "lt",
        BinaryOp::Le => "le",
        BinaryOp::Gt => "gt",
        BinaryOp::Ge => "ge",
    }
}

fn unary_str(op: UnaryOp) -> &'static str {
    match op {
        UnaryOp::Neg => "neg",
        UnaryOp::Not => "not",
        UnaryOp::BitNot => "bitnot",
        UnaryOp::Clz => "clz",
        UnaryOp::Ctz => "ctz",
        UnaryOp::Popcnt => "popcnt",
        UnaryOp::Abs => "abs",
        UnaryOp::Sqrt => "sqrt",
        UnaryOp::Floor => "floor",
        UnaryOp::Ceil => "ceil",
        UnaryOp::Trunc => "trunc",
    }
}

fn provenance_source_str(source: ProvenanceSource) -> &'static str {
    match source {
        ProvenanceSource::Metadata => "Metadata",
        ProvenanceSource::HostFunctionAbi => "HostFunctionAbi",
        ProvenanceSource::SdkPattern => "SdkPattern",
        ProvenanceSource::DataFlow => "DataFlow",
        ProvenanceSource::TypePropagation => "TypePropagation",
        ProvenanceSource::Default => "Default",
        ProvenanceSource::UpstreamRefinement => "UpstreamRefinement",
    }
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn render_to_string(f: impl FnOnce(&mut Vec<u8>) -> io::Result<()>) -> String {
        let mut buf = Vec::new();
        f(&mut buf).expect("write succeeds");
        String::from_utf8(buf).expect("utf-8")
    }

    fn v(idx: u32) -> ValueId {
        ValueId::from_index(idx)
    }

    #[test]
    fn literal_i64_renders_with_suffix() {
        let s = render_to_string(|w| render_expr(w, &Expr::Literal(Literal::I64(42))));
        assert_eq!(s, "42i64");
    }

    #[test]
    fn binary_add_renders() {
        let expr = Expr::Binary {
            op: BinaryOp::Add,
            lhs: v(1),
            rhs: v(2),
        };
        let s = render_to_string(|w| render_expr(w, &expr));
        assert_eq!(s, "add v1, v2");
    }

    #[test]
    fn use_renders_as_value_ref() {
        let s = render_to_string(|w| render_expr(w, &Expr::Use(v(7))));
        assert_eq!(s, "v7");
    }

    #[test]
    fn known_host_call_renders_friendly_name() {
        // ("l", "_") resolves to put_contract_data in the catalog.
        let expr = Expr::Semantic(SemanticOp::Unknown {
            host_module: "l".to_string(),
            host_fn: "_".to_string(),
            args: vec![v(1), v(2)],
            reason: sordec_common::UnknownReason::UnsupportedPattern,
        });
        let s = render_to_string(|w| render_expr(w, &expr));
        assert_eq!(s, "host:l:put_contract_data(v1, v2)");
    }

    #[test]
    fn unknown_host_call_renders_raw_name() {
        let expr = Expr::Semantic(SemanticOp::Unknown {
            host_module: "zz".to_string(),
            host_fn: "?".to_string(),
            args: vec![],
            reason: sordec_common::UnknownReason::UnsupportedPattern,
        });
        let s = render_to_string(|w| render_expr(w, &expr));
        assert_eq!(s, "host:zz:?");
    }

    #[test]
    fn phi_renders_incoming_edges() {
        let expr = Expr::Phi {
            incoming: vec![
                (sordec_common::BlockId::from_index(1), v(9)),
                (sordec_common::BlockId::from_index(2), v(10)),
            ],
        };
        let s = render_to_string(|w| render_expr(w, &expr));
        assert_eq!(s, "phi [bb1 -> v9, bb2 -> v10]");
    }

    #[test]
    fn unrecovered_renders_kind_and_args() {
        let expr = Expr::Unknown {
            op_kind: sordec_ir::WasmOpcodeKind::Conversion,
            args: vec![v(3)],
            reason: sordec_common::UnknownReason::UnsupportedPattern,
        };
        let s = render_to_string(|w| render_expr(w, &expr));
        assert_eq!(s, "<unrecovered Conversion>(v3)");
    }

    #[test]
    fn load_and_store_render_offsets() {
        let load = Expr::Load {
            addr: v(0),
            offset: 8,
            ty: IrType::Unknown(sordec_common::UnknownReason::InsufficientEvidence),
        };
        assert_eq!(
            render_to_string(|w| render_expr(w, &load)),
            "load v0 offset=8"
        );
        let store = Expr::Store {
            addr: v(0),
            value: v(1),
            offset: 16,
        };
        assert_eq!(
            render_to_string(|w| render_expr(w, &store)),
            "store v0 <- v1 offset=16"
        );
    }

    #[test]
    fn unknown_type_renders_question_mark() {
        assert_eq!(
            ir_type_str(&IrType::Unknown(
                sordec_common::UnknownReason::InsufficientEvidence
            )),
            "?"
        );
    }

    #[test]
    fn known_and_inferred_types_render() {
        assert_eq!(ir_type_str(&IrType::Known(KnownType::U32)), "u32");
        assert_eq!(ir_type_str(&IrType::Inferred(KnownType::Address)), "Address?");
        assert_eq!(
            known_type_str(&KnownType::Vec(Box::new(IrType::Known(KnownType::I128)))),
            "Vec<i128>"
        );
    }

    // --- C1 Val-op renderings ---

    #[test]
    fn val_encode_renders_with_payload_type() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall {
            ty: KnownType::U64,
            value: v(51),
        }));
        let s = render_to_string(|w| render_expr(w, &expr));
        assert_eq!(s, "val_encode<u64>(v51)");
    }

    #[test]
    fn val_decode_renders_without_type() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { value: v(34) }));
        let s = render_to_string(|w| render_expr(w, &expr));
        assert_eq!(s, "val_decode(v34)");
    }

    #[test]
    fn val_tag_check_renders_tag_name() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck {
            value: v(1),
            tag: 64,
        }));
        let s = render_to_string(|w| render_expr(w, &expr));
        assert_eq!(s, "has_tag(v1, U64Object)");
    }

    #[test]
    fn val_object_renders_conversion_name_and_args() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::ValObject {
            kind: sordec_ir::ValObjectKind::ObjFromU64,
            args: vec![v(49)],
        }));
        let s = render_to_string(|w| render_expr(w, &expr));
        assert_eq!(s, "obj_from_u64(v49)");
    }

    // --- C2 storage-op renderings ---

    #[test]
    fn storage_get_renders_known_tier() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet {
            tier: StorageTier::Known(KnownTier::Instance),
            key: v(92),
        }));
        let s = render_to_string(|w| render_expr(w, &expr));
        assert_eq!(s, "storage_get<instance>(v92)");
    }

    #[test]
    fn storage_set_renders_temporary_tier_and_two_args() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::StorageSet {
            tier: StorageTier::Known(KnownTier::Temporary),
            key: v(9),
            value: v(0),
        }));
        let s = render_to_string(|w| render_expr(w, &expr));
        assert_eq!(s, "storage_set<temporary>(v9, v0)");
    }

    #[test]
    fn storage_has_renders_unknown_tier_as_question_mark() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::StorageHas {
            tier: StorageTier::Unknown(sordec_common::UnknownReason::InsufficientEvidence),
            key: v(1),
        }));
        let s = render_to_string(|w| render_expr(w, &expr));
        assert_eq!(s, "storage_has<?>(v1)");
    }

    #[test]
    fn extend_ttl_renders_tier_and_three_args() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::StorageExtendTtl {
            tier: StorageTier::Known(KnownTier::Persistent),
            key: v(4),
            threshold: v(9),
            extend_to: v(14),
        }));
        let s = render_to_string(|w| render_expr(w, &expr));
        assert_eq!(s, "extend_ttl<persistent>(v4, v9, v14)");
    }

    #[test]
    fn extend_current_instance_ttl_renders_without_tier() {
        let expr = Expr::Semantic(SemanticOp::Known(
            KnownOp::ExtendCurrentContractInstanceAndCodeTtl {
                threshold: v(9),
                extend_to: v(14),
            },
        ));
        let s = render_to_string(|w| render_expr(w, &expr));
        assert_eq!(s, "extend_instance_and_code_ttl(v9, v14)");
    }

    // --- C4 auth + address renderings ---

    #[test]
    fn require_auth_renders() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::RequireAuth { address: v(6) }));
        let s = render_to_string(|w| render_expr(w, &expr));
        assert_eq!(s, "require_auth(v6)");
    }

    #[test]
    fn require_auth_for_args_renders_address_and_vec() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::RequireAuthForArgs {
            address: v(21),
            args: vec![v(33)],
        }));
        let s = render_to_string(|w| render_expr(w, &expr));
        assert_eq!(s, "require_auth_for_args(v21, v33)");
    }

    #[test]
    fn authorize_as_curr_contract_renders() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::AuthorizeAsCurrContract {
            auth_entries: v(8),
        }));
        let s = render_to_string(|w| render_expr(w, &expr));
        assert_eq!(s, "authorize_as_curr_contract(v8)");
    }

    #[test]
    fn address_conversion_renders_name_and_args() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::AddressConversion {
            kind: sordec_ir::AddressOpKind::GetIdFromMuxedAddress,
            args: vec![v(155)],
        }));
        let s = render_to_string(|w| render_expr(w, &expr));
        assert_eq!(s, "get_id_from_muxed_address(v155)");
    }

    // --- C15 context renderings ---

    #[test]
    fn nullary_ledger_accessors_render_as_calls() {
        for (op, expected) in [
            (KnownOp::GetCurrentContractAddress, "get_current_contract_address()"),
            (KnownOp::GetLedgerSequence, "get_ledger_sequence()"),
            (KnownOp::GetLedgerTimestamp, "get_ledger_timestamp()"),
            (KnownOp::GetMaxLiveUntilLedger, "get_max_live_until_ledger()"),
        ] {
            let expr = Expr::Semantic(SemanticOp::Known(op));
            let s = render_to_string(|w| render_expr(w, &expr));
            assert_eq!(s, expected);
        }
    }

    #[test]
    fn publish_event_renders_topics_and_data() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::PublishEvent {
            topics: vec![v(21)],
            data: v(33),
        }));
        let s = render_to_string(|w| render_expr(w, &expr));
        assert_eq!(s, "publish_event(v21, v33)");
    }

    #[test]
    fn val_compare_renders() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::ValCompare { a: v(10), b: v(12) }));
        let s = render_to_string(|w| render_expr(w, &expr));
        assert_eq!(s, "val_cmp(v10, v12)");
    }

    #[test]
    fn panic_with_error_renders() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::PanicWithError { error: v(4) }));
        let s = render_to_string(|w| render_expr(w, &expr));
        assert_eq!(s, "panic_with_error(v4)");
    }

    // --- linear-memory constructor renderings ---

    #[test]
    fn symbol_new_resolved_renders_text() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::SymbolNew {
            lm_pos: v(115),
            len: v(131),
            resolved: Some("transfer".to_string()),
        }));
        let s = render_to_string(|w| render_expr(w, &expr));
        assert_eq!(s, "symbol_new(\"transfer\")");
    }

    #[test]
    fn symbol_new_unresolved_renders_operands() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::SymbolNew {
            lm_pos: v(115),
            len: v(131),
            resolved: None,
        }));
        let s = render_to_string(|w| render_expr(w, &expr));
        assert_eq!(s, "symbol_new(v115, v131)");
    }

    #[test]
    fn string_new_resolved_renders_text() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::StringNew {
            lm_pos: v(1),
            len: v(2),
            resolved: Some("hello".to_string()),
        }));
        let s = render_to_string(|w| render_expr(w, &expr));
        assert_eq!(s, "string_new(\"hello\")");
    }

    #[test]
    fn bytes_new_resolved_renders_hex() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::BytesNew {
            lm_pos: v(1),
            len: v(2),
            resolved: Some(vec![0xde, 0xad, 0xbe, 0xef]),
        }));
        let s = render_to_string(|w| render_expr(w, &expr));
        assert_eq!(s, "bytes_new(0xdeadbeef)");
    }

    #[test]
    fn bytes_new_unresolved_renders_operands() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::BytesNew {
            lm_pos: v(7),
            len: v(8),
            resolved: None,
        }));
        let s = render_to_string(|w| render_expr(w, &expr));
        assert_eq!(s, "bytes_new(v7, v8)");
    }

    #[test]
    fn vec_new_renders_operands() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::VecNew {
            vals_pos: v(7),
            len: v(12),
        }));
        let s = render_to_string(|w| render_expr(w, &expr));
        assert_eq!(s, "vec_new(v7, v12)");
    }

    #[test]
    fn map_new_renders_three_operands() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::MapNew {
            keys_pos: v(3),
            vals_pos: v(4),
            len: v(5),
        }));
        let s = render_to_string(|w| render_expr(w, &expr));
        assert_eq!(s, "map_new(v3, v4, v5)");
    }

    // --- collections renderings ---

    #[test]
    fn map_op_renders_name_and_args() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::MapOp {
            kind: sordec_ir::MapOpKind::UnpackToLinearMemory,
            args: vec![v(1), v(2), v(3), v(4)],
        }));
        let s = render_to_string(|w| render_expr(w, &expr));
        assert_eq!(s, "map_unpack_to_linear_memory(v1, v2, v3, v4)");
    }

    #[test]
    fn vec_op_renders_name_and_args() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::VecOp {
            kind: sordec_ir::VecOpKind::Len,
            args: vec![v(9)],
        }));
        let s = render_to_string(|w| render_expr(w, &expr));
        assert_eq!(s, "vec_len(v9)");
    }

    #[test]
    fn buf_op_renders_name_and_args() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::BufOp {
            kind: sordec_ir::BufOpKind::SymbolIndexInLinearMemory,
            args: vec![v(1), v(2), v(3)],
        }));
        let s = render_to_string(|w| render_expr(w, &expr));
        assert_eq!(s, "symbol_index_in_linear_memory(v1, v2, v3)");
    }

    #[test]
    fn nullary_collection_op_keeps_parens() {
        // A nullary constructor still renders as a call, not a bare name.
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::MapOp {
            kind: sordec_ir::MapOpKind::New,
            args: vec![],
        }));
        let s = render_to_string(|w| render_expr(w, &expr));
        assert_eq!(s, "map_new()");
    }

    // --- cross-contract renderings ---

    #[test]
    fn invoke_contract_renders_contract_symbol_and_args_handle() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::InvokeContract {
            contract: v(1),
            function: v(2),
            args: vec![v(3)],
        }));
        let s = render_to_string(|w| render_expr(w, &expr));
        assert_eq!(s, "invoke_contract(v1, v2, v3)");
    }

    #[test]
    fn try_invoke_contract_renders() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::TryInvokeContract {
            contract: v(4),
            function: v(5),
            args: vec![v(6)],
        }));
        let s = render_to_string(|w| render_expr(w, &expr));
        assert_eq!(s, "try_invoke_contract(v4, v5, v6)");
    }
}
