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
}
