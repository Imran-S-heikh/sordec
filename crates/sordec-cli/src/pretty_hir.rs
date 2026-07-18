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
//!   ;; region: structured
//!   bb0:
//!     v3: ? = i64.add(v1, v2)          ;; DataFlow: operator: Arithmetic
//!     v6: ? = host:l:put_contract_data(v4, v5)   ;; DataFlow: operator: Call
//!   ;; unscheduled bindings (block params / phis):
//!     v0: ? = phi [bb1 -> v9]          ;; DataFlow: block param
//! }
//! ```
//!
//! Control flow is structured at the lowering boundary, but this
//! renderer still shows the flat block listing with a one-line region
//! banner — the nested `if`/`loop`/`match` rendering is the
//! structured-renderer work (A4/W5). Block parameters (phi nodes) are
//! not scheduled into any block's binding list, so they render in a
//! trailing "unscheduled" section.
//!
//! # Folded rendering (W3/B6)
//!
//! On the default (non-`--raw`) path, bindings the
//! [`InlinePlan`] treeification analysis classifies
//! `Inline(ExprOperand)` — pure-total, read exactly once by another
//! live binding — skip their own statement line and render nested
//! inside their consumer instead: `v6 = sub v4, 48i32` rather than a
//! separate `v5 = 48i32` line. De-clutter residue (`Dead`) is hidden
//! behind one honest count line. The single choke point for operand
//! text is [`FoldCtx::operand`] — every expression-position id goes
//! through it, which is what guarantees a skipped line always
//! reappears at its use site. Phi incomings are the deliberate
//! exception (per-edge transfer assignments, A1 DD2); the plan never
//! classifies a phi-consumed value `Inline`.

use std::collections::HashSet;
use std::io::{self, Write};

use sordec_common::{IrId, ProvenanceSource, ValueId};
use sordec_ir::{
    BinaryOp, Binding, DispatchTable, EnumKey, Expr, HighFunction, HighIr, IrType, KnownOp,
    KnownTier, KnownType, Literal, MemWidth, Region, SemanticOp, StorageTier, UnaryOp,
};
use sordec_passes::host_calls;
use sordec_passes::{InlineClass, InlinePlan, InlineSite};

/// Defensive recursion bound for folded rendering. Well-formed SSA
/// cannot cycle (an `Inline` chain is finite and single-use), so this
/// only fires on malformed IR — where the fallback prints the bare id
/// rather than overflowing the stack.
const MAX_FOLD_DEPTH: u16 = 256;

/// Rendering context for operand positions: the function (to resolve
/// folded bindings), the fold plan (absent on the `--raw` path), and
/// the current fold depth.
#[derive(Clone, Copy)]
struct FoldCtx<'a> {
    func: Option<&'a HighFunction>,
    plan: Option<&'a InlinePlan>,
    depth: u16,
}

impl FoldCtx<'_> {
    /// A context that never folds — every operand renders as `vN`.
    #[cfg(test)]
    fn plain() -> FoldCtx<'static> {
        FoldCtx {
            func: None,
            plan: None,
            depth: 0,
        }
    }

    /// Does `value`'s binding fold into its consumer instead of
    /// rendering its own line? The exact predicate the line-skip and
    /// operand rendering share.
    ///
    /// Renderer policy on top of the [`InlinePlan`] capability: only
    /// bindings still carrying their **single initial provenance
    /// entry** (the mechanical lowering's) fold. A binding any
    /// recognizer touched keeps its own line — its provenance note is
    /// the visible recognition surface (`;; SdkPattern: …`), and
    /// folding would erase it. The Phase-4 emitter applies its own
    /// policy (J3) over the same plan.
    fn folds(&self, value: ValueId) -> bool {
        self.plan.is_some_and(|plan| {
            matches!(
                plan.class(value),
                InlineClass::Inline(InlineSite::ExprOperand { .. })
            )
        }) && self
            .func
            .and_then(|f| f.bindings.get(value))
            .is_some_and(|b| b.provenance().len() == 1)
    }

    /// Operand text: `vN`, or the folded expression when `value`'s
    /// binding inlines (literals bare, everything else parenthesized).
    fn operand(&self, value: ValueId) -> String {
        if self.depth < MAX_FOLD_DEPTH
            && self.folds(value)
            && let Some(binding) = self.func.and_then(|f| f.bindings.get(value))
        {
            let deeper = FoldCtx {
                depth: self.depth + 1,
                ..*self
            };
            let mut buf: Vec<u8> = Vec::new();
            let ok = match &binding.expr {
                Expr::Literal(lit) => render_literal(&mut buf, lit).is_ok(),
                expr => {
                    buf.push(b'(');
                    let ok = render_expr(&mut buf, expr, &deeper).is_ok();
                    buf.push(b')');
                    ok
                }
            };
            if ok && let Ok(text) = String::from_utf8(buf) {
                return text;
            }
        }
        format!("v{}", value.index())
    }
}

/// Render a [`HighIr`] to `out` as text.
///
/// # Errors
///
/// Returns the underlying [`io::Error`] when writing to `out` fails.
pub fn render_high_ir(out: &mut impl Write, high: &HighIr, folded: bool) -> io::Result<()> {
    if high.functions.is_empty() {
        writeln!(out, ";; (module has no local functions)")?;
        return Ok(());
    }
    for (i, func) in high.functions.iter().enumerate() {
        if i > 0 {
            writeln!(out)?;
        }
        render_function(out, func, folded)?;
    }
    Ok(())
}

fn render_function(out: &mut impl Write, func: &HighFunction, folded: bool) -> io::Result<()> {
    match &func.name {
        // The SDK's deploy-time constructor export (D6). Distinguished
        // from ordinary contract methods — its `#[contractimpl]`
        // `__constructor` runs once at instantiation.
        Some(name) if name == "__constructor" => writeln!(
            out,
            "function func_{} [exported as {name:?} (constructor entrypoint)] {{",
            func.id.index()
        )?,
        Some(name) => writeln!(
            out,
            "function func_{} [exported as {name:?}] {{",
            func.id.index()
        )?,
        None => writeln!(out, "function func_{} {{", func.id.index())?,
    }

    render_region_banner(out, &func.region)?;

    let plan = folded.then(|| InlinePlan::build(func));
    let ctx = FoldCtx {
        func: Some(func),
        plan: plan.as_ref(),
        depth: 0,
    };

    // Bindings grouped by block, in block order. Track which bindings we
    // accounted for so phis/unscheduled values can be shown afterward.
    // A binding that folds renders nested inside its consumer instead
    // of on its own line.
    let mut rendered: HashSet<ValueId> = HashSet::new();
    for (block_id, block) in func.blocks.iter() {
        writeln!(out, "  bb{}:", block_id.index())?;
        for &value_id in &block.bindings {
            if let Some(binding) = func.bindings.get(value_id) {
                rendered.insert(value_id);
                if !ctx.folds(value_id) {
                    render_binding(out, binding, &ctx)?;
                }
            }
        }
    }

    // Bindings not scheduled into any block (block params / phis).
    // De-clutter residue hides behind the count line; folded bindings
    // render at their use site like their scheduled counterparts.
    let mut dead_hidden = 0usize;
    let unscheduled: Vec<&Binding> = func
        .bindings
        .iter()
        .filter(|(id, _)| !rendered.contains(id))
        .filter(|(id, _)| {
            match plan.as_ref().map(|p| p.class(*id)) {
                Some(InlineClass::Dead) => {
                    dead_hidden += 1;
                    false
                }
                Some(InlineClass::Inline(InlineSite::ExprOperand { .. })) => false,
                _ => true,
            }
        })
        .map(|(_, b)| b)
        .collect();
    if !unscheduled.is_empty() {
        writeln!(out, "  ;; unscheduled bindings (block params / phis):")?;
        for binding in unscheduled {
            render_binding(out, binding, &ctx)?;
        }
    }
    if dead_hidden > 0 {
        writeln!(
            out,
            "  ;; {dead_hidden} pruning-residue binding(s) hidden (--raw shows them)"
        )?;
    }

    writeln!(out, "}}")?;
    Ok(())
}

fn render_region_banner(out: &mut impl Write, region: &Region) -> io::Result<()> {
    match region {
        // Defensive fallback only (irreducible/malformed input) —
        // corpus-locked to zero and paired with a StructuringFallback
        // diagnostic.
        Region::Unstructured { entry, .. } => writeln!(
            out,
            "  ;; region: unstructured (entry bb{}, structuring fell back)",
            entry.index()
        ),
        // The banner records that structuring succeeded; the nested
        // if/loop/match rendering is the structured-renderer work (A4).
        _ => writeln!(out, "  ;; region: structured"),
    }
}

fn render_binding(out: &mut impl Write, binding: &Binding, ctx: &FoldCtx<'_>) -> io::Result<()> {
    write!(
        out,
        "    v{}: {} = ",
        binding.id.index(),
        ir_type_str(&binding.ty)
    )?;
    render_expr(out, &binding.expr, ctx)?;
    let prov = binding.latest_provenance();
    writeln!(
        out,
        "  ;; {}: {}",
        provenance_source_str(prov.source),
        prov.note
    )
}

fn render_expr(out: &mut impl Write, expr: &Expr, ctx: &FoldCtx<'_>) -> io::Result<()> {
    match expr {
        Expr::Semantic(SemanticOp::Known(op)) => render_known_op(out, op, ctx),
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
            render_args(out, args, ctx)
        }
        Expr::Literal(lit) => render_literal(out, lit),
        Expr::Use(value) => write!(out, "{}", ctx.operand(*value)),
        Expr::Unary { op, value } => {
            write!(out, "{}({})", unary_str(*op), ctx.operand(*value))
        }
        Expr::Binary { op, lhs, rhs } => write!(
            out,
            "{} {}, {}",
            binary_str(*op),
            ctx.operand(*lhs),
            ctx.operand(*rhs)
        ),
        Expr::Call { target, args } => {
            write!(out, "call func_{}", target.index())?;
            render_args(out, args, ctx)
        }
        Expr::IndirectCall {
            table,
            sig,
            callee,
            args,
        } => {
            write!(
                out,
                "call_indirect table={table} sig={sig} via {}",
                ctx.operand(*callee)
            )?;
            render_args(out, args, ctx)
        }
        // Phi incomings render as raw ids on purpose: they are
        // per-edge transfer assignments (A1 DD2), and the fold plan
        // never classifies a phi-consumed value `Inline`.
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
        Expr::Load {
            addr,
            offset,
            width,
            signed,
            ..
        } => {
            write!(
                out,
                "load{} {} offset={offset}",
                mem_suffix(*width, *signed),
                ctx.operand(*addr)
            )
        }
        Expr::Store {
            addr,
            value,
            offset,
            width,
        } => write!(
            out,
            "store{} {} <- {} offset={offset}",
            mem_suffix(*width, None),
            ctx.operand(*addr),
            ctx.operand(*value)
        ),
        Expr::Unknown { op_kind, args, .. } => {
            write!(out, "<unrecovered {op_kind:?}>")?;
            render_args(out, args, ctx)
        }
    }
}

/// Render a recognized [`KnownOp`]. The four Val-encoding ops (C1) get
/// dedicated forms; the other KnownOps keep the Debug fallback until
/// their own recognizers land and earn a rendering.
fn render_known_op(out: &mut impl Write, op: &KnownOp, ctx: &FoldCtx<'_>) -> io::Result<()> {
    use sordec_passes::val_abi;
    match op {
        KnownOp::ValEncodeSmall { ty, value } => {
            write!(
                out,
                "val_encode<{}>({})",
                known_type_str(ty),
                ctx.operand(*value)
            )
        }
        KnownOp::ValDecodeSmall { value } => {
            write!(out, "val_decode({})", ctx.operand(*value))
        }
        KnownOp::ValTagCheck { value, tag } => {
            let name = val_abi::tag_name(*tag).unwrap_or("?");
            write!(out, "has_tag({}, {name})", ctx.operand(*value))
        }
        KnownOp::ValObject { kind, args } => {
            write!(out, "{}", val_abi::obj_kind_name(*kind))?;
            render_args(out, args, ctx)
        }
        // ---- Storage (C2) + TTL (C3) ----
        KnownOp::StorageGet {
            tier,
            durability: _,
            key,
            resolved_key,
        } => {
            write!(
                out,
                "storage_get<{}>({})",
                tier_str(tier),
                key_str(key, resolved_key, ctx)
            )
        }
        KnownOp::StorageSet {
            tier,
            durability: _,
            key,
            resolved_key,
            value,
        } => write!(
            out,
            "storage_set<{}>({}, {})",
            tier_str(tier),
            key_str(key, resolved_key, ctx),
            ctx.operand(*value)
        ),
        KnownOp::StorageHas {
            tier,
            durability: _,
            key,
            resolved_key,
        } => {
            write!(
                out,
                "storage_has<{}>({})",
                tier_str(tier),
                key_str(key, resolved_key, ctx)
            )
        }
        KnownOp::StorageRemove {
            tier,
            durability: _,
            key,
            resolved_key,
        } => {
            write!(
                out,
                "storage_remove<{}>({})",
                tier_str(tier),
                key_str(key, resolved_key, ctx)
            )
        }
        KnownOp::StorageExtendTtl {
            tier,
            durability: _,
            key,
            resolved_key,
            threshold,
            extend_to,
            resolved_threshold,
            resolved_extend_to,
        } => write!(
            out,
            "extend_ttl<{}>({}, {}, {})",
            tier_str(tier),
            key_str(key, resolved_key, ctx),
            ttl_arg(*threshold, resolved_threshold, ctx),
            ttl_arg(*extend_to, resolved_extend_to, ctx)
        ),
        KnownOp::StorageExtendTtlV2 {
            tier,
            durability: _,
            key,
            resolved_key,
            extend_to,
            min_extension,
            max_extension,
        } => write!(
            out,
            "extend_ttl_v2<{}>({}, {}, {}, {})",
            tier_str(tier),
            key_str(key, resolved_key, ctx),
            ctx.operand(*extend_to),
            ctx.operand(*min_extension),
            ctx.operand(*max_extension)
        ),
        KnownOp::ExtendCurrentContractInstanceAndCodeTtl {
            threshold,
            extend_to,
            resolved_threshold,
            resolved_extend_to,
        } => write!(
            out,
            "extend_instance_and_code_ttl({}, {})",
            ttl_arg(*threshold, resolved_threshold, ctx),
            ttl_arg(*extend_to, resolved_extend_to, ctx)
        ),
        KnownOp::ExtendContractInstanceAndCodeTtl {
            contract,
            threshold,
            extend_to,
        } => write!(
            out,
            "extend_contract_instance_and_code_ttl({}, {}, {})",
            ctx.operand(*contract),
            ctx.operand(*threshold),
            ctx.operand(*extend_to)
        ),
        KnownOp::ExtendContractInstanceTtl {
            contract,
            threshold,
            extend_to,
        } => write!(
            out,
            "extend_contract_instance_ttl({}, {}, {})",
            ctx.operand(*contract),
            ctx.operand(*threshold),
            ctx.operand(*extend_to)
        ),
        KnownOp::ExtendContractCodeTtl {
            contract,
            threshold,
            extend_to,
        } => write!(
            out,
            "extend_contract_code_ttl({}, {}, {})",
            ctx.operand(*contract),
            ctx.operand(*threshold),
            ctx.operand(*extend_to)
        ),
        KnownOp::ExtendContractInstanceAndCodeTtlV2 {
            contract,
            extension_scope,
            extend_to,
            min_extension,
            max_extension,
        } => write!(
            out,
            "extend_contract_instance_and_code_ttl_v2({}, {}, {}, {}, {})",
            ctx.operand(*contract),
            ctx.operand(*extension_scope),
            ctx.operand(*extend_to),
            ctx.operand(*min_extension),
            ctx.operand(*max_extension)
        ),
        // ---- Auth + address (C4) ----
        KnownOp::RequireAuth { address } => {
            write!(out, "require_auth({})", ctx.operand(*address))
        }
        KnownOp::RequireAuthForArgs { address, args } => {
            write!(out, "require_auth_for_args({}", ctx.operand(*address))?;
            for a in args {
                write!(out, ", {}", ctx.operand(*a))?;
            }
            write!(out, ")")
        }
        KnownOp::AuthorizeAsCurrContract { auth_entries } => {
            write!(
                out,
                "authorize_as_curr_contract({})",
                ctx.operand(*auth_entries)
            )
        }
        KnownOp::AddressConversion { kind, args } => {
            write!(out, "{}", val_abi::addr_kind_name(*kind))?;
            render_args(out, args, ctx)
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
                write!(out, "{}, ", ctx.operand(*t))?;
            }
            write!(out, "{})", ctx.operand(*data))
        }
        KnownOp::ValCompare { a, b } => {
            write!(out, "val_cmp({}, {})", ctx.operand(*a), ctx.operand(*b))
        }
        KnownOp::PanicWithError { error } => {
            write!(out, "panic_with_error({})", ctx.operand(*error))
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
            None => write!(
                out,
                "symbol_new({}, {})",
                ctx.operand(*lm_pos),
                ctx.operand(*len)
            ),
        },
        KnownOp::StringNew {
            lm_pos,
            len,
            resolved,
        } => match resolved {
            Some(s) => write!(out, "string_new({s:?})"),
            None => write!(
                out,
                "string_new({}, {})",
                ctx.operand(*lm_pos),
                ctx.operand(*len)
            ),
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
            None => write!(
                out,
                "bytes_new({}, {})",
                ctx.operand(*lm_pos),
                ctx.operand(*len)
            ),
        },
        KnownOp::VecNew { vals_pos, len } => {
            write!(
                out,
                "vec_new({}, {})",
                ctx.operand(*vals_pos),
                ctx.operand(*len)
            )
        }
        KnownOp::MapNew {
            keys_pos,
            vals_pos,
            len,
        } => write!(
            out,
            "map_new({}, {}, {})",
            ctx.operand(*keys_pos),
            ctx.operand(*vals_pos),
            ctx.operand(*len)
        ),
        // ---- Collections / bytes ----
        KnownOp::MapOp { kind, args } => {
            render_call(out, val_abi::map_kind_name(*kind), args, ctx)
        }
        KnownOp::VecOp { kind, args } => {
            render_call(out, val_abi::vec_kind_name(*kind), args, ctx)
        }
        KnownOp::BufOp { kind, args } => {
            render_call(out, val_abi::buf_kind_name(*kind), args, ctx)
        }
        // ---- Enum dispatch (dispatcher pass) ----
        KnownOp::SymbolDispatch { sym, table, .. } => {
            render_symbol_dispatch(out, *sym, table, ctx)
        }
        // ---- Crypto / PRNG / test / deploy (abi-sweep) ----
        KnownOp::CryptoOp { kind, args } => {
            render_call(out, val_abi::crypto_kind_name(*kind), args, ctx)
        }
        KnownOp::PrngOp { kind, args } => {
            render_call(out, val_abi::prng_kind_name(*kind), args, ctx)
        }
        KnownOp::TestOp { kind, args } => {
            render_call(out, val_abi::test_kind_name(*kind), args, ctx)
        }
        KnownOp::DeployOp { kind, args } => {
            render_call(out, val_abi::deploy_kind_name(*kind), args, ctx)
        }
        // ---- Cross-contract calls ----
        KnownOp::InvokeContract {
            contract,
            function,
            args,
            resolved_callee,
            arg_count,
            resolved_args,
            interface: _,
        } => render_invoke(
            out,
            "invoke_contract",
            *contract,
            *function,
            args,
            resolved_callee,
            *arg_count,
            resolved_args,
            ctx,
        ),
        KnownOp::TryInvokeContract {
            contract,
            function,
            args,
            resolved_callee,
            arg_count,
            resolved_args,
            interface: _,
        } => render_invoke(
            out,
            "try_invoke_contract",
            *contract,
            *function,
            args,
            resolved_callee,
            *arg_count,
            resolved_args,
            ctx,
        ),
        // NOTE: this match is exhaustive over `KnownOp` — every variant
        // has a dedicated rendering. A new `KnownOp` must add its arm
        // here (a deliberate compile-time forcing function; there is no
        // Debug fallback to silently absorb it).
    }
}

/// Render a TTL ledger-count operand: the witnessed constant when the
/// `const-prop` pass resolved the `U32Val` (e.g. `518400`), else the raw
/// value id. The human duration (`30 days`) rides the binding's
/// provenance note, not the operand text.
fn ttl_arg(raw: ValueId, resolved: &Option<u32>, ctx: &FoldCtx<'_>) -> String {
    match resolved {
        Some(ledgers) => ledgers.to_string(),
        None => ctx.operand(raw),
    }
}

/// Render a recognized symbol-dispatch (enum-from-`Val` decode). The
/// looked-up symbol stays visible for traceability; the decoded variant
/// list renders as `EnumName::{Before | After}` when the enum was named
/// against the spec, or bare `{Before | After}` when only the rodata
/// cases are known (a stripped binary or no unique union match).
fn render_symbol_dispatch(
    out: &mut impl Write,
    sym: ValueId,
    table: &DispatchTable,
    ctx: &FoldCtx<'_>,
) -> io::Result<()> {
    let cases = table.cases.join(" | ");
    match &table.enum_name {
        Some(name) => write!(
            out,
            "symbol_dispatch({}) -> {name}::{{{cases}}}",
            ctx.operand(sym)
        ),
        None => write!(out, "symbol_dispatch({}) -> {{{cases}}}", ctx.operand(sym)),
    }
}

/// Render a storage key operand: the raw value id alone, or — when the
/// enum-key pass resolved it — annotated with the recognized variant
/// (`v30: DataKey::Admin`, `v15: DataKey::Allowance(v1, v2)`). The
/// value id stays visible for traceability back to the constructor
/// call.
fn key_str(key: &ValueId, resolved: &Option<EnumKey>, ctx: &FoldCtx<'_>) -> String {
    let Some(enum_key) = resolved else {
        return ctx.operand(*key);
    };
    // The key id itself stays a raw id even when its binding folds: it
    // is the traceability anchor back to the constructor call, and the
    // variant annotation, not the id, carries the meaning.
    let mut s = format!(
        "v{}: {}::{}",
        key.index(),
        enum_key.enum_name,
        enum_key.variant
    );
    if !enum_key.payload.is_empty() {
        s.push('(');
        for (i, p) in enum_key.payload.iter().enumerate() {
            if i > 0 {
                s.push_str(", ");
            }
            s.push_str(&ctx.operand(*p));
        }
        s.push(')');
    }
    s
}

/// WAT-style width suffix for a raw memory access. Full-width accesses
/// (`W4`/`W8` without sign extension) render bare — exactly the
/// pre-width output — so existing locks don't move; sub-word forms get
/// `8`/`16`/`32` plus `_s`/`_u` on sign-extending loads. (`i64.store32`
/// renders bare `store`: without the value's width the sub-word-ness is
/// not displayable, but the byte width stays faithful in the IR.)
fn mem_suffix(width: MemWidth, signed: Option<bool>) -> String {
    match signed {
        Some(s) => format!("{}_{}", width.bytes() * 8, if s { "s" } else { "u" }),
        None => match width {
            MemWidth::W1 => "8".to_string(),
            MemWidth::W2 => "16".to_string(),
            MemWidth::W4 | MemWidth::W8 => String::new(),
        },
    }
}

fn render_args(out: &mut impl Write, args: &[ValueId], ctx: &FoldCtx<'_>) -> io::Result<()> {
    if args.is_empty() {
        return Ok(());
    }
    write!(out, "(")?;
    for (i, arg) in args.iter().enumerate() {
        if i > 0 {
            write!(out, ", ")?;
        }
        write!(out, "{}", ctx.operand(*arg))?;
    }
    write!(out, ")")
}

/// Render `name(v1, v2, …)`, keeping the parens for a nullary call —
/// unlike [`render_args`], which omits them (its callers suffix an
/// argument-less form onto identifiers, not calls).
fn render_call(
    out: &mut impl Write,
    name: &str,
    args: &[ValueId],
    ctx: &FoldCtx<'_>,
) -> io::Result<()> {
    write!(out, "{name}")?;
    if args.is_empty() {
        return write!(out, "()");
    }
    render_args(out, args, ctx)
}

/// Render a cross-contract call: the callee renders as its recovered
/// name when the const-prop engine resolved it, else as the raw symbol
/// operand.
/// Render a cross-contract call. The args slot upgrades with the
/// client-call pass's evidence: full recovered elements as
/// `[v6, v9]`, arity-only as `vN: 3 args`, and the raw handle when
/// nothing is proven (exactly the pre-client-call output).
#[allow(clippy::too_many_arguments)]
fn render_invoke(
    out: &mut impl Write,
    name: &str,
    contract: ValueId,
    function: ValueId,
    args: &[ValueId],
    resolved_callee: &Option<String>,
    arg_count: Option<u32>,
    resolved_args: &Option<Vec<ValueId>>,
    ctx: &FoldCtx<'_>,
) -> io::Result<()> {
    write!(out, "{name}({}, ", ctx.operand(contract))?;
    match resolved_callee {
        Some(callee) => write!(out, "{callee:?}")?,
        None => write!(out, "{}", ctx.operand(function))?,
    }
    if let Some(elements) = resolved_args {
        write!(out, ", [")?;
        for (i, e) in elements.iter().enumerate() {
            if i > 0 {
                write!(out, ", ")?;
            }
            write!(out, "{}", ctx.operand(*e))?;
        }
        write!(out, "]")?;
    } else {
        for a in args {
            write!(out, ", {}", ctx.operand(*a))?;
            if let Some(n) = arg_count {
                write!(out, ": {n} arg{}", if n == 1 { "" } else { "s" })?;
            }
        }
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

    use sordec_common::{Arena, BlockId, FuncId};
    use sordec_ir::{HighBlock, HighFunction};

    fn render_to_string(f: impl FnOnce(&mut Vec<u8>) -> io::Result<()>) -> String {
        let mut buf = Vec::new();
        f(&mut buf).expect("write succeeds");
        String::from_utf8(buf).expect("utf-8")
    }

    fn v(idx: u32) -> ValueId {
        ValueId::from_index(idx)
    }

    /// A minimal single-block function with the given export name.
    fn named_fn(name: Option<&str>) -> HighFunction {
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        blocks.push(HighBlock {
            id: BlockId::from_index(0),
            bindings: vec![],
        });
        HighFunction {
            id: FuncId::from_index(3),
            name: name.map(str::to_string),
            signature: None,
            blocks,
            bindings: Arena::new(),
            region: Region::Unreachable,
            params: vec![],
            returns: vec![],
        }
    }

    fn header_line(func: &HighFunction) -> String {
        render_to_string(|w| render_function(w, func, false))
            .lines()
            .next()
            .unwrap()
            .to_string()
    }

    #[test]
    fn constructor_export_is_labeled() {
        let header = header_line(&named_fn(Some("__constructor")));
        assert_eq!(
            header,
            "function func_3 [exported as \"__constructor\" (constructor entrypoint)] {"
        );
    }

    #[test]
    fn ordinary_export_header_is_unchanged() {
        let header = header_line(&named_fn(Some("transfer")));
        assert_eq!(header, "function func_3 [exported as \"transfer\"] {");
    }

    #[test]
    fn literal_i64_renders_with_suffix() {
        let s = render_to_string(|w| {
            render_expr(w, &Expr::Literal(Literal::I64(42)), &FoldCtx::plain())
        });
        assert_eq!(s, "42i64");
    }

    #[test]
    fn binary_add_renders() {
        let expr = Expr::Binary {
            op: BinaryOp::Add,
            lhs: v(1),
            rhs: v(2),
        };
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
        assert_eq!(s, "add v1, v2");
    }

    #[test]
    fn use_renders_as_value_ref() {
        let s = render_to_string(|w| render_expr(w, &Expr::Use(v(7)), &FoldCtx::plain()));
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
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
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
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
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
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
        assert_eq!(s, "phi [bb1 -> v9, bb2 -> v10]");
    }

    #[test]
    fn unrecovered_renders_kind_and_args() {
        let expr = Expr::Unknown {
            op_kind: sordec_ir::WasmOpcodeKind::Conversion,
            args: vec![v(3)],
            reason: sordec_common::UnknownReason::UnsupportedPattern,
        };
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
        assert_eq!(s, "<unrecovered Conversion>(v3)");
    }

    #[test]
    fn load_and_store_render_offsets() {
        // Full-width accesses render exactly as before the width fields
        // landed — no suffix.
        let load = Expr::Load {
            addr: v(0),
            offset: 8,
            width: MemWidth::W8,
            signed: None,
            ty: IrType::Unknown(sordec_common::UnknownReason::InsufficientEvidence),
        };
        assert_eq!(
            render_to_string(|w| render_expr(w, &load, &FoldCtx::plain())),
            "load v0 offset=8"
        );
        let store = Expr::Store {
            addr: v(0),
            value: v(1),
            offset: 16,
            width: MemWidth::W8,
        };
        assert_eq!(
            render_to_string(|w| render_expr(w, &store, &FoldCtx::plain())),
            "store v0 <- v1 offset=16"
        );
    }

    #[test]
    fn subword_load_and_store_render_wat_suffixes() {
        let load = Expr::Load {
            addr: v(0),
            offset: 0,
            width: MemWidth::W1,
            signed: Some(false),
            ty: IrType::Unknown(sordec_common::UnknownReason::InsufficientEvidence),
        };
        assert_eq!(
            render_to_string(|w| render_expr(w, &load, &FoldCtx::plain())),
            "load8_u v0 offset=0"
        );
        let store = Expr::Store {
            addr: v(0),
            value: v(1),
            offset: 4,
            width: MemWidth::W2,
        };
        assert_eq!(
            render_to_string(|w| render_expr(w, &store, &FoldCtx::plain())),
            "store16 v0 <- v1 offset=4"
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
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
        assert_eq!(s, "val_encode<u64>(v51)");
    }

    #[test]
    fn val_decode_renders_without_type() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { value: v(34) }));
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
        assert_eq!(s, "val_decode(v34)");
    }

    #[test]
    fn val_tag_check_renders_tag_name() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck {
            value: v(1),
            tag: 64,
        }));
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
        assert_eq!(s, "has_tag(v1, U64Object)");
    }

    #[test]
    fn val_object_renders_conversion_name_and_args() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::ValObject {
            kind: sordec_ir::ValObjectKind::ObjFromU64,
            args: vec![v(49)],
        }));
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
        assert_eq!(s, "obj_from_u64(v49)");
    }

    // --- C2 storage-op renderings ---

    #[test]
    fn storage_get_renders_known_tier() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet {
            tier: StorageTier::Known(KnownTier::Instance),
            durability: v(93),
            key: v(92),
            resolved_key: None,
        }));
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
        assert_eq!(s, "storage_get<instance>(v92)");
    }

    #[test]
    fn storage_get_renders_resolved_enum_key() {
        // Unit variant: no payload parens.
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet {
            tier: StorageTier::Known(KnownTier::Instance),
            durability: v(93),
            key: v(92),
            resolved_key: Some(EnumKey {
                enum_name: "DataKey".to_string(),
                variant: "Admin".to_string(),
                payload: vec![],
            }),
        }));
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
        assert_eq!(s, "storage_get<instance>(v92: DataKey::Admin)");

        // Payload variant: values in slot order.
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet {
            tier: StorageTier::Known(KnownTier::Temporary),
            durability: v(93),
            key: v(15),
            resolved_key: Some(EnumKey {
                enum_name: "DataKey".to_string(),
                variant: "Allowance".to_string(),
                payload: vec![v(1), v(2)],
            }),
        }));
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
        assert_eq!(s, "storage_get<temporary>(v15: DataKey::Allowance(v1, v2))");
    }

    #[test]
    fn storage_set_renders_temporary_tier_and_two_args() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::StorageSet {
            tier: StorageTier::Known(KnownTier::Temporary),
            durability: v(10),
            key: v(9),
            resolved_key: None,
            value: v(0),
        }));
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
        assert_eq!(s, "storage_set<temporary>(v9, v0)");
    }

    #[test]
    fn storage_has_renders_unknown_tier_as_question_mark() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::StorageHas {
            tier: StorageTier::Unknown(sordec_common::UnknownReason::InsufficientEvidence),
            durability: v(2),
            key: v(1),
            resolved_key: None,
        }));
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
        assert_eq!(s, "storage_has<?>(v1)");
    }

    #[test]
    fn extend_ttl_renders_tier_and_three_args() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::StorageExtendTtl {
            tier: StorageTier::Known(KnownTier::Persistent),
            durability: v(5),
            key: v(4),
            resolved_key: None,
            threshold: v(9),
            extend_to: v(14),
            resolved_threshold: None,
            resolved_extend_to: None,
        }));
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
        assert_eq!(s, "extend_ttl<persistent>(v4, v9, v14)");
    }

    #[test]
    fn extend_ttl_renders_resolved_ledger_counts() {
        // const-prop filled the U32Val operands: show the counts, not vN.
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::StorageExtendTtl {
            tier: StorageTier::Known(KnownTier::Persistent),
            durability: v(5),
            key: v(4),
            resolved_key: None,
            threshold: v(9),
            extend_to: v(14),
            resolved_threshold: Some(501120),
            resolved_extend_to: Some(518400),
        }));
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
        assert_eq!(s, "extend_ttl<persistent>(v4, 501120, 518400)");
    }

    #[test]
    fn extend_current_instance_ttl_renders_without_tier() {
        let expr = Expr::Semantic(SemanticOp::Known(
            KnownOp::ExtendCurrentContractInstanceAndCodeTtl {
                threshold: v(9),
                extend_to: v(14),
                resolved_threshold: None,
                resolved_extend_to: None,
            },
        ));
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
        assert_eq!(s, "extend_instance_and_code_ttl(v9, v14)");
    }

    #[test]
    fn extend_current_instance_ttl_renders_resolved_counts() {
        let expr = Expr::Semantic(SemanticOp::Known(
            KnownOp::ExtendCurrentContractInstanceAndCodeTtl {
                threshold: v(9),
                extend_to: v(14),
                resolved_threshold: Some(103680),
                resolved_extend_to: Some(120960),
            },
        ));
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
        assert_eq!(s, "extend_instance_and_code_ttl(103680, 120960)");
    }

    // --- C4 auth + address renderings ---

    #[test]
    fn require_auth_renders() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::RequireAuth { address: v(6) }));
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
        assert_eq!(s, "require_auth(v6)");
    }

    #[test]
    fn require_auth_for_args_renders_address_and_vec() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::RequireAuthForArgs {
            address: v(21),
            args: vec![v(33)],
        }));
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
        assert_eq!(s, "require_auth_for_args(v21, v33)");
    }

    #[test]
    fn authorize_as_curr_contract_renders() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::AuthorizeAsCurrContract {
            auth_entries: v(8),
        }));
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
        assert_eq!(s, "authorize_as_curr_contract(v8)");
    }

    #[test]
    fn address_conversion_renders_name_and_args() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::AddressConversion {
            kind: sordec_ir::AddressOpKind::GetIdFromMuxedAddress,
            args: vec![v(155)],
        }));
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
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
            let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
            assert_eq!(s, expected);
        }
    }

    #[test]
    fn publish_event_renders_topics_and_data() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::PublishEvent {
            topics: vec![v(21)],
            data: v(33),
        }));
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
        assert_eq!(s, "publish_event(v21, v33)");
    }

    #[test]
    fn val_compare_renders() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::ValCompare { a: v(10), b: v(12) }));
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
        assert_eq!(s, "val_cmp(v10, v12)");
    }

    #[test]
    fn panic_with_error_renders() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::PanicWithError { error: v(4) }));
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
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
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
        assert_eq!(s, "symbol_new(\"transfer\")");
    }

    #[test]
    fn symbol_new_unresolved_renders_operands() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::SymbolNew {
            lm_pos: v(115),
            len: v(131),
            resolved: None,
        }));
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
        assert_eq!(s, "symbol_new(v115, v131)");
    }

    #[test]
    fn string_new_resolved_renders_text() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::StringNew {
            lm_pos: v(1),
            len: v(2),
            resolved: Some("hello".to_string()),
        }));
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
        assert_eq!(s, "string_new(\"hello\")");
    }

    #[test]
    fn bytes_new_resolved_renders_hex() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::BytesNew {
            lm_pos: v(1),
            len: v(2),
            resolved: Some(vec![0xde, 0xad, 0xbe, 0xef]),
        }));
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
        assert_eq!(s, "bytes_new(0xdeadbeef)");
    }

    #[test]
    fn bytes_new_unresolved_renders_operands() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::BytesNew {
            lm_pos: v(7),
            len: v(8),
            resolved: None,
        }));
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
        assert_eq!(s, "bytes_new(v7, v8)");
    }

    #[test]
    fn vec_new_renders_operands() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::VecNew {
            vals_pos: v(7),
            len: v(12),
        }));
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
        assert_eq!(s, "vec_new(v7, v12)");
    }

    #[test]
    fn map_new_renders_three_operands() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::MapNew {
            keys_pos: v(3),
            vals_pos: v(4),
            len: v(5),
        }));
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
        assert_eq!(s, "map_new(v3, v4, v5)");
    }

    // --- collections renderings ---

    #[test]
    fn map_op_renders_name_and_args() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::MapOp {
            kind: sordec_ir::MapOpKind::UnpackToLinearMemory,
            args: vec![v(1), v(2), v(3), v(4)],
        }));
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
        assert_eq!(s, "map_unpack_to_linear_memory(v1, v2, v3, v4)");
    }

    #[test]
    fn vec_op_renders_name_and_args() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::VecOp {
            kind: sordec_ir::VecOpKind::Len,
            args: vec![v(9)],
        }));
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
        assert_eq!(s, "vec_len(v9)");
    }

    #[test]
    fn buf_op_renders_name_and_args() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::BufOp {
            kind: sordec_ir::BufOpKind::SymbolIndexInLinearMemory,
            args: vec![v(1), v(2), v(3)],
        }));
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
        assert_eq!(s, "symbol_index_in_linear_memory(v1, v2, v3)");
    }

    #[test]
    fn symbol_dispatch_renders_named_enum() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::SymbolDispatch {
            sym: v(61),
            table_pos: v(69),
            len: v(70),
            table: DispatchTable {
                cases: vec!["Before".to_string(), "After".to_string()],
                enum_name: Some("TimeBoundKind".to_string()),
            },
        }));
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
        assert_eq!(s, "symbol_dispatch(v61) -> TimeBoundKind::{Before | After}");
    }

    #[test]
    fn symbol_dispatch_renders_bare_cases_when_enum_unnamed() {
        // No unique union match (or a stripped binary): cases are still
        // ground truth from rodata, but the enum stays unnamed.
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::SymbolDispatch {
            sym: v(61),
            table_pos: v(69),
            len: v(70),
            table: DispatchTable {
                cases: vec!["Before".to_string(), "After".to_string()],
                enum_name: None,
            },
        }));
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
        assert_eq!(s, "symbol_dispatch(v61) -> {Before | After}");
    }

    #[test]
    fn nullary_collection_op_keeps_parens() {
        // A nullary constructor still renders as a call, not a bare name.
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::MapOp {
            kind: sordec_ir::MapOpKind::New,
            args: vec![],
        }));
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
        assert_eq!(s, "map_new()");
    }

    // --- cross-contract renderings ---

    #[test]
    fn invoke_contract_renders_contract_symbol_and_args_handle() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::InvokeContract {
            contract: v(1),
            function: v(2),
            args: vec![v(3)],
            resolved_callee: None,
            arg_count: None,
            resolved_args: None,
            interface: None,
        }));
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
        assert_eq!(s, "invoke_contract(v1, v2, v3)");
    }

    #[test]
    fn try_invoke_contract_renders() {
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::TryInvokeContract {
            contract: v(4),
            function: v(5),
            args: vec![v(6)],
            resolved_callee: None,
            arg_count: None,
            resolved_args: None,
            interface: None,
        }));
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
        assert_eq!(s, "try_invoke_contract(v4, v5, v6)");
    }

    #[test]
    fn invoke_contract_renders_client_call_tiers() {
        // Arity-only tier: the raw handle stays visible, annotated.
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::InvokeContract {
            contract: v(1),
            function: v(2),
            args: vec![v(3)],
            resolved_callee: Some("transfer".to_string()),
            arg_count: Some(3),
            resolved_args: None,
            interface: Some(sordec_ir::ClientInterface::Sep41Token),
        }));
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
        assert_eq!(s, "invoke_contract(v1, \"transfer\", v3: 3 args)");

        // Full-elements tier: recovered values replace the handle.
        let expr = Expr::Semantic(SemanticOp::Known(KnownOp::InvokeContract {
            contract: v(1),
            function: v(2),
            args: vec![v(3)],
            resolved_callee: Some("balance".to_string()),
            arg_count: Some(1),
            resolved_args: Some(vec![v(6)]),
            interface: Some(sordec_ir::ClientInterface::Sep41Token),
        }));
        let s = render_to_string(|w| render_expr(w, &expr, &FoldCtx::plain()));
        assert_eq!(s, "invoke_contract(v1, \"balance\", [v6])");
    }
}
