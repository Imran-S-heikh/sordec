//! The typed client-call recognizer (spec D2.4).
//!
//! A cross-contract call reaches the host as `invoke_contract(contract,
//! symbol, args_vec)` with the argument vector an opaque `VecObject`
//! built by the SDK: element Vals stored into a shadow-stack array,
//! then `vec_new_from_linear_memory(ptr, len)` through a small wrapper
//! helper. This pass upgrades already-recognized
//! [`InvokeContract`](KnownOp::InvokeContract) /
//! [`TryInvokeContract`](KnownOp::TryInvokeContract) ops with what the
//! construction proves, in tiers — each tier independently gated,
//! never guessed:
//!
//! 1. **Arity** (`arg_count`): the vec constructor's `len` operand
//!    resolves to a constant. Holds on every corpus site.
//! 2. **Elements** (`resolved_args`): the element array is written in
//!    the same block as the vec construction, so the frame-facts
//!    tracker recovers every slot value (all-or-nothing). Holds where
//!    construction is block-local (dex's `balance`). **Tier 2b**
//!    (W7 D9): where the SDK's tuple→vec **copy loop** on multi-arg
//!    calls kills the block-local facts, the loop idiom is traced
//!    structurally back to the block that stored the source slots —
//!    Inferred-grade evidence, noted in provenance (see
//!    [`resolve_through_copy_loop`]). Sites matching neither honestly
//!    keep `resolved_args: None`.
//! 3. **Interface** (`interface`): the resolved callee name + arity
//!    match a known interface table
//!    ([`interfaces::sep41_lookup`](crate::interfaces::sep41_lookup)).
//!    Structural (Inferred-grade) evidence — the callee's code is not
//!    inspectable — recorded as such in the provenance note. This is
//!    D2.4's "when the callee interface is recoverable" tier; the
//!    Phase-3 emitter renders the matching `token::Client` form.
//!
//! Like `const-prop`/`enum-key`, bypasses the `is_recognized` skip
//! guard (its domain is already-`Known` ops with unresolved slots);
//! idempotent — a filled `arg_count` no longer matches.

use std::collections::HashMap;

use sordec_common::{
    BlockId, Diagnostic, FuncId, IrId, LiftDiagnosticCode, Location, ProvenanceSource, ValueId,
};
use sordec_ir::{
    BinaryOp, ClientInterface, Expr, HighFunction, HighIr, KnownOp, MemWidth, SemanticOp,
};

use super::wrappers::{chase_value, wrapper_params};
use super::{apply_rewrites, Rewrite};
use crate::dataflow::{
    block_containing, canon_addr, facts_at_end, facts_before, resolve_use, trace_int, CallIndex,
    Resolver,
};
use crate::effects::expr_effects;
use crate::interfaces::sep41_lookup;
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "client-call";

// Metric counter keys.
/// Invokes whose argument arity was proven.
const M_ARITY: &str = "client_arity_resolved";
/// Invokes whose full element list was recovered.
const M_ARGS: &str = "client_args_resolved";
/// Elements recovered by the tier-2b copy-loop trace (a subset of
/// [`M_ARGS`]).
const M_ARGS_LOOP: &str = "client_args_via_copy_loop";
/// Invokes matched against a known interface.
const M_IFACE: &str = "client_iface_matched";
/// Invokes whose args-vec construction stayed unproven (the
/// remaining-work signal).
const M_UNRESOLVED: &str = "client_unresolved";

/// Nesting cap for locating the `VecNew` op behind a wrapper call.
const WRAPPER_DEPTH: u32 = 2;
/// Sanity cap on a recovered arity — no real contract call carries
/// more; a larger "constant" is misidentified data.
const MAX_ARITY: u32 = 32;
/// Depth cap for peeling Val-encode/conversion wrappers off a pointer.
const PEEL_DEPTH: u32 = 8;

/// The typed client-call recognizer pass. Stateless between runs.
#[derive(Debug, Default, Clone, Copy)]
pub struct ClientCallPass;

impl Pass<HighIr> for ClientCallPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();

        // Phase A — read-only scan.
        let calls = CallIndex::build(ir);
        let mut resolver = Resolver::new(ir, &calls);
        let mut planned: HashMap<FuncId, Vec<Rewrite>> = HashMap::new();

        for func in &ir.functions {
            for (id, binding) in func.bindings.iter() {
                let Expr::Semantic(SemanticOp::Known(op)) = &binding.expr else {
                    continue;
                };
                let Some(handle) = unresolved_invoke_of(op) else {
                    continue;
                };
                match try_resolve_args(ir, &mut resolver, func, handle) {
                    Some(recovered) => {
                        let elements_resolved = recovered.elements.is_some();
                        let via_copy_loop = recovered.via_copy_loop;
                        let (upgraded, note, iface_matched) = upgrade(op, recovered);
                        if elements_resolved {
                            result.metrics.increment(M_ARGS, 1);
                        }
                        if via_copy_loop {
                            result.metrics.increment(M_ARGS_LOOP, 1);
                        }
                        if iface_matched {
                            result.metrics.increment(M_IFACE, 1);
                        }
                        planned.entry(func.id).or_default().push(Rewrite {
                            id,
                            expr: Expr::Semantic(SemanticOp::Known(upgraded)),
                            // The op's ABI result type was set at
                            // recognition; nothing to refine.
                            ty: None,
                            source: ProvenanceSource::SdkPattern,
                            note,
                            metric: M_ARITY,
                        });
                    }
                    None => {
                        result.metrics.increment(M_UNRESOLVED, 1);
                        result.diagnostics.push(
                            Diagnostic::warning(
                                LiftDiagnosticCode::UnresolvedCrossContractCallee,
                                "",
                            )
                            .at(Location::Value {
                                func: func.id,
                                value: id.index(),
                            }),
                        );
                    }
                }
            }
        }
        drop(resolver);

        // Phase B — apply per function.
        for (func_id, rewrites) in planned {
            for rw in &rewrites {
                result.metrics.increment(rw.metric, 1);
            }
            result.changed = true;
            if let Some(func) = ir.function_mut(func_id) {
                apply_rewrites(func, PASS_NAME, rewrites);
            }
        }
        result
    }
}

/// What one args-vec construction proved.
struct Recovered {
    arity: u32,
    elements: Option<Vec<ValueId>>,
    /// Elements came from the tier-2b copy-loop trace (Inferred-grade
    /// structural evidence, noted in provenance).
    via_copy_loop: bool,
}

/// The args-vec handle of an invoke op still awaiting arity recovery.
fn unresolved_invoke_of(op: &KnownOp) -> Option<ValueId> {
    match op {
        KnownOp::InvokeContract {
            args,
            arg_count: None,
            ..
        }
        | KnownOp::TryInvokeContract {
            args,
            arg_count: None,
            ..
        } => args.first().copied(),
        _ => None,
    }
}

/// Clone `op` with the recovered slots filled and the interface
/// matched; returns `(op, provenance note, interface_matched)`.
fn upgrade(op: &KnownOp, recovered: Recovered) -> (KnownOp, String, bool) {
    let mut upgraded = op.clone();
    let (KnownOp::InvokeContract {
        resolved_callee,
        arg_count,
        resolved_args,
        interface,
        ..
    }
    | KnownOp::TryInvokeContract {
        resolved_callee,
        arg_count,
        resolved_args,
        interface,
        ..
    }) = &mut upgraded
    else {
        unreachable!("cloned from an invoke variant");
    };

    *arg_count = Some(recovered.arity);
    let elements_note = match (&recovered.elements, recovered.via_copy_loop) {
        (Some(_), true) => ", elements traced through the copy loop (structural)",
        (Some(_), false) => ", elements recovered",
        (None, _) => ", elements unproven (multi-block construction)",
    };
    *resolved_args = recovered.elements;

    // Interface tier: callee name + arity, both required.
    let iface = resolved_callee
        .as_deref()
        .and_then(|callee| sep41_lookup(callee, recovered.arity));
    let iface_note = match iface {
        Some(f) => {
            *interface = Some(ClientInterface::Sep41Token);
            format!(", sep41 {} (callee+arity match, structural)", f.signature())
        }
        None => String::new(),
    };

    let note = format!(
        "client-call {} arg{}{elements_note}{iface_note}",
        recovered.arity,
        if recovered.arity == 1 { "" } else { "s" }
    );
    (upgraded, note, iface.is_some())
}

/// Resolve one args-vec handle: find its constructor, prove the arity,
/// and recover the elements when the construction is block-local.
fn try_resolve_args(
    ir: &HighIr,
    resolver: &mut Resolver<'_>,
    func: &HighFunction,
    handle: ValueId,
) -> Option<Recovered> {
    let terminal = chase_value(func, handle);
    let binding = func.bindings.get(terminal)?;

    // The construction site: a vec-wrapper call, or an inlined VecNew.
    let (site, ptr, len) = match &binding.expr {
        Expr::Call { target, args } => {
            let params = wrapper_params(ir, *target, WRAPPER_DEPTH, &|op| match op {
                KnownOp::VecNew { vals_pos, len } => Some(vec![*vals_pos, *len]),
                _ => None,
            })?;
            let [ptr_idx, len_idx] = params[..] else {
                return None;
            };
            (terminal, *args.get(ptr_idx)?, *args.get(len_idx)?)
        }
        Expr::Semantic(SemanticOp::Known(KnownOp::VecNew { vals_pos, len })) => {
            (terminal, *vals_pos, *len)
        }
        _ => return None,
    };

    // Tier 1 — arity from the constant length (crosses phis and
    // agreeing callers via the resolver's U32Val discipline).
    let arity = resolver.resolve_u32val(func.id, len)?;
    if arity > MAX_ARITY {
        return None;
    }

    // Tier 2 — elements from the frame facts at the construction site.
    // The pointer may arrive Val-encoded (inlined VecNew) — peel first.
    let (base, k) = canon_addr(func, peel_encode(func, ptr));
    let elements = (|| {
        if arity == 0 {
            // An empty vec has no elements to prove.
            return Some(Vec::new());
        }
        let block_id = block_containing(func, site)?;
        let block = func.blocks.get(block_id)?;
        let facts = facts_before(func, block, site, base);
        (0..arity)
            .map(|i| facts.value_at(k.checked_add(i.checked_mul(8)?)?, MemWidth::W8))
            .collect()
    })();

    // Tier 2b — trace the SDK's tuple→vec copy loop back to the block
    // that stored the source slots (W7 D9).
    let (elements, via_copy_loop) = match elements {
        Some(elements) => (Some(elements), false),
        None => match resolve_through_copy_loop(func, base, k, arity) {
            Some(elements) => (Some(elements), true),
            None => (None, false),
        },
    };

    Some(Recovered {
        arity,
        elements,
        via_copy_loop,
    })
}

/// Tier 2b (W7 D9): recover elements through the SDK's tuple→vec copy
/// loop.
///
/// Multi-arg client calls stage their element `Val`s in one frame
/// array, then a compiler-emitted loop copies them 8 bytes at a time
/// into the constructor's array:
/// `while (i != arity*8) { *(dst+i) = *(src+i); i += 8 }`. This tier
/// matches that idiom structurally — a lone W8 load/store pair over
/// the same induction phi (init 0, step +8, `!= arity*8` exit
/// witness), a pure-only loop block, and a single block writing the
/// source slots — and reads the source block's final frame facts.
/// **Inferred-grade** evidence (the loop's execution order is
/// structural, not proven against the CFG), recorded as such in the
/// provenance note, matching the interface tier's discipline.
fn resolve_through_copy_loop(
    func: &HighFunction,
    dst_root: ValueId,
    k_dst: u32,
    arity: u32,
) -> Option<Vec<ValueId>> {
    if arity == 0 {
        return None;
    }
    let (copy_block, shape) = func.blocks.iter().find_map(|(id, block)| {
        let shape = match_copy_block(func, block)?;
        (shape.dst_root == dst_root && shape.k_dst == k_dst).then_some((id, shape))
    })?;
    if !induction_covers_slots(func, shape.induction, arity) {
        return None;
    }
    let writer = single_source_writer(func, copy_block, shape.src_root, shape.k_src, arity)?;
    let facts = facts_at_end(func, func.blocks.get(writer)?, shape.src_root);
    (0..arity)
        .map(|i| facts.value_at(shape.k_src.checked_add(i.checked_mul(8)?)?, MemWidth::W8))
        .collect()
}

/// The decomposed copy-loop body: `*(dst_root + k_dst + i) =
/// *(src_root + k_src + i)` over induction value `i`.
struct CopyShape {
    src_root: ValueId,
    k_src: u32,
    dst_root: ValueId,
    k_dst: u32,
    induction: ValueId,
}

/// Match one block against the copy-loop body idiom: exactly one W8
/// load and one W8 store forwarding it, both indexed by the same
/// induction value, and nothing else but pure-total arithmetic.
fn match_copy_block(func: &HighFunction, block: &sordec_ir::HighBlock) -> Option<CopyShape> {
    let mut load: Option<(ValueId, ValueId, u32, ValueId)> = None;
    let mut store: Option<(ValueId, u32, ValueId, ValueId)> = None;
    for &id in &block.bindings {
        let binding = func.bindings.get(id)?;
        match &binding.expr {
            Expr::Load {
                addr,
                offset,
                width: MemWidth::W8,
                ..
            } => {
                if load.is_some() {
                    return None;
                }
                let (root, off, ind) = split_addr(func, *addr, *offset)?;
                load = Some((id, root, off, ind?));
            }
            Expr::Store {
                addr,
                value,
                offset,
                width: MemWidth::W8,
            } => {
                if store.is_some() {
                    return None;
                }
                let (root, off, ind) = split_addr(func, *addr, *offset)?;
                store = Some((root, off, ind?, *value));
            }
            expr => {
                if !expr_effects(expr).is_pure_total() {
                    return None;
                }
            }
        }
    }
    let (load_id, src_root, k_src, load_ind) = load?;
    let (dst_root, k_dst, store_ind, stored) = store?;
    if load_ind != store_ind || resolve_use(func, stored) != load_id {
        return None;
    }
    Some(CopyShape {
        src_root,
        k_src,
        dst_root,
        k_dst,
        induction: load_ind,
    })
}

/// Decompose an address (+ instruction-baked offset) into
/// `(root, constant offset, at-most-one non-constant induction term)`,
/// peeling `Add` chains. The induction side must resolve to a phi (the
/// loop-carried counter); a second non-constant term refuses.
fn split_addr(
    func: &HighFunction,
    addr: ValueId,
    baked: u32,
) -> Option<(ValueId, u32, Option<ValueId>)> {
    let mut current = addr;
    let mut offset = baked;
    let mut induction = None;
    for _ in 0..PEEL_DEPTH {
        let terminal = resolve_use(func, current);
        let Some(binding) = func.bindings.get(terminal) else {
            return Some((terminal, offset, induction));
        };
        let Expr::Binary {
            op: BinaryOp::Add,
            lhs,
            rhs,
        } = &binding.expr
        else {
            return Some((terminal, offset, induction));
        };
        let const_fold = [(lhs, rhs), (rhs, lhs)].into_iter().find_map(|(k, rest)| {
            let konst = u32::try_from(trace_int(func, *k)?).ok()?;
            Some((*rest, offset.checked_add(konst)?))
        });
        if let Some((rest, total)) = const_fold {
            offset = total;
            current = rest;
            continue;
        }
        if induction.is_some() {
            return None;
        }
        let (phi_side, rest) = [(lhs, rhs), (rhs, lhs)].into_iter().find(|(cand, _)| {
            func.bindings
                .get(resolve_use(func, **cand))
                .is_some_and(|b| matches!(b.expr, Expr::Phi { .. }))
        })?;
        induction = Some(resolve_use(func, *phi_side));
        current = *rest;
    }
    None
}

/// The induction value walks exactly the element slots: a two-input
/// phi with a constant-0 initial, an `i + 8` step, and an exit
/// comparison of `i` against `arity*8` somewhere in the function
/// (either polarity — rustc emits `ne` for continue-in-then loops and
/// `eq` for the rotated exit-in-then dual).
fn induction_covers_slots(func: &HighFunction, induction: ValueId, arity: u32) -> bool {
    let Some(binding) = func.bindings.get(induction) else {
        return false;
    };
    let Expr::Phi { incoming } = &binding.expr else {
        return false;
    };
    if incoming.len() != 2 {
        return false;
    }
    let resolved: Vec<ValueId> = incoming
        .iter()
        .map(|(_, v)| resolve_use(func, *v))
        .collect();
    let init_ok = resolved.iter().any(|&v| trace_int(func, v) == Some(0));
    let is_step = |v: ValueId| {
        func.bindings.get(v).is_some_and(|b| {
            matches!(
                &b.expr,
                Expr::Binary { op: BinaryOp::Add, lhs, rhs }
                    if (resolve_use(func, *lhs) == induction && trace_int(func, *rhs) == Some(8))
                        || (resolve_use(func, *rhs) == induction
                            && trace_int(func, *lhs) == Some(8))
            )
        })
    };
    let step_ok = resolved.iter().any(|&v| is_step(v));
    let bound = i128::from(arity) * 8;
    let bound_ok = func.bindings.iter().any(|(_, b)| {
        matches!(
            &b.expr,
            Expr::Binary { op: BinaryOp::Ne | BinaryOp::Eq, lhs, rhs }
                if (resolve_use(func, *lhs) == induction && trace_int(func, *rhs) == Some(bound))
                    || (resolve_use(func, *rhs) == induction
                        && trace_int(func, *lhs) == Some(bound))
        )
    });
    init_ok && step_ok && bound_ok
}

/// The single block (outside the copy loop) storing into the source
/// slot range — `None` when no block, or more than one, writes it.
fn single_source_writer(
    func: &HighFunction,
    copy_block: BlockId,
    src_root: ValueId,
    k_src: u32,
    arity: u32,
) -> Option<BlockId> {
    let end = k_src.checked_add(arity.checked_mul(8)?)?;
    let mut writer = None;
    for (block_id, block) in func.blocks.iter() {
        if block_id == copy_block {
            continue;
        }
        for &id in &block.bindings {
            let Some(binding) = func.bindings.get(id) else {
                continue;
            };
            let Expr::Store { addr, offset, .. } = &binding.expr else {
                continue;
            };
            let (root, off) = canon_addr(func, *addr);
            let total = off.checked_add(*offset)?;
            if root == src_root && total >= k_src && total < end {
                match writer {
                    None => writer = Some(block_id),
                    Some(existing) if existing == block_id => {}
                    Some(_) => return None,
                }
            }
        }
    }
    writer
}

/// Peel the C1 `ValEncodeSmall` wrapper and pure width conversions off
/// a pointer operand (the inlined-`VecNew` shape carries its `vals_pos`
/// as an encoded `U32Val`).
fn peel_encode(func: &HighFunction, value: ValueId) -> ValueId {
    let mut current = value;
    for _ in 0..PEEL_DEPTH {
        current = resolve_use(func, current);
        match func.bindings.get(current).map(|b| &b.expr) {
            Some(Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall {
                value: inner,
                ..
            }))) => current = *inner,
            Some(Expr::Unknown {
                op_kind: sordec_ir::WasmOpcodeKind::Conversion,
                args,
                ..
            }) if args.len() == 1 => current = args[0],
            _ => return current,
        }
    }
    current
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{Arena, BlockId, IrId, Provenance, UnknownReason};
    use sordec_ir::{
        Binding, HighBlock, IrType, Literal, MemoryImage, Region, WasmFacts,
    };

    /// Build a function with `n_params` leading params then `exprs`,
    /// all scheduled into one block in order.
    fn func(id: u32, name: Option<&str>, n_params: usize, exprs: Vec<Expr>) -> HighFunction {
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        let mut params = Vec::new();
        let mut scheduled = Vec::new();
        for _ in 0..n_params {
            let id = ValueId::from_index(bindings.len() as u32);
            bindings.push(Binding::new(
                id,
                IrType::Unknown(UnknownReason::InsufficientEvidence),
                Expr::Phi { incoming: vec![] },
                Provenance::new("test", ProvenanceSource::DataFlow, "param"),
            ));
            params.push(id);
        }
        for expr in exprs {
            let vid = ValueId::from_index(bindings.len() as u32);
            bindings.push(Binding::new(
                vid,
                IrType::Unknown(UnknownReason::InsufficientEvidence),
                expr,
                Provenance::new("test", ProvenanceSource::DataFlow, "seed"),
            ));
            scheduled.push(vid);
        }
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        blocks.push(HighBlock {
            id: BlockId::from_index(0),
            bindings: scheduled,
        });
        HighFunction {
            id: FuncId::from_index(id),
            name: name.map(str::to_string),
            signature: None,
            blocks,
            bindings,
            region: Region::Unreachable,
            params,
            returns: vec![],
        }
    }

    fn module(functions: Vec<HighFunction>) -> HighIr {
        HighIr {
            facts: WasmFacts {
                imports: vec![],
                exports: vec![],
                function_type_indices: vec![],
                custom_sections: vec![],
            },
            soroban_facts: None,
            functions,
            memory: MemoryImage::empty(),
        }
    }

    fn v(i: u32) -> ValueId {
        ValueId::from_index(i)
    }

    fn i32c(n: i32) -> Expr {
        Expr::Literal(Literal::I32(n))
    }

    fn i64c(n: i64) -> Expr {
        Expr::Literal(Literal::I64(n))
    }

    fn call(target: u32, args: Vec<ValueId>) -> Expr {
        Expr::Call {
            target: FuncId::from_index(target),
            args,
        }
    }

    fn store(addr: u32, value: u32, offset: u32) -> Expr {
        Expr::Store {
            addr: v(addr),
            value: v(value),
            offset,
            width: MemWidth::W8,
        }
    }

    fn invoke(contract: u32, function: u32, handle: u32, callee: Option<&str>) -> Expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::InvokeContract {
            contract: v(contract),
            function: v(function),
            args: vec![v(handle)],
            resolved_callee: callee.map(str::to_string),
            arg_count: None,
            resolved_args: None,
            interface: None,
        }))
    }

    /// The vec wrapper: `W(ptr, len)` containing a VecNew fed from its
    /// params.
    fn vec_wrapper(id: u32) -> HighFunction {
        func(
            id,
            None,
            2,
            vec![Expr::Semantic(SemanticOp::Known(KnownOp::VecNew {
                vals_pos: v(0),
                len: v(1),
            }))],
        )
    }

    fn run(ir: &mut HighIr) -> PassResult {
        ClientCallPass.run(ir)
    }

    fn invoke_op(ir: &HighIr, func: u32, id: u32) -> &KnownOp {
        match &ir.functions[func as usize].bindings.get(v(id)).unwrap().expr {
            Expr::Semantic(SemanticOp::Known(op)) => op,
            other => panic!("expected Known op, got {other:?}"),
        }
    }

    // --- the dex-balance shape: single-block, full recovery ---

    #[test]
    fn single_block_construction_recovers_everything() {
        // caller: v0 = frame (opaque); v1 = element val;
        // v2 = store [v0+0] <- v1; v3 = 1 (len); v4 = call W(v0, v3);
        // v5 = invoke(contract=v0, fn=v1, handle=v4, callee "balance")
        let caller = func(
            0,
            None,
            1,
            vec![
                i64c(77),
                store(0, 1, 0),
                i32c(1),
                call(1, vec![v(0), v(3)]),
                invoke(0, 1, 4, Some("balance")),
            ],
        );
        let mut ir = module(vec![caller, vec_wrapper(1)]);
        let result = run(&mut ir);
        assert!(result.changed);
        assert_eq!(result.metrics.get(M_ARITY), Some(1));
        assert_eq!(result.metrics.get(M_IFACE), Some(1));
        match invoke_op(&ir, 0, 5) {
            KnownOp::InvokeContract {
                arg_count,
                resolved_args,
                interface,
                ..
            } => {
                assert_eq!(*arg_count, Some(1));
                assert_eq!(*resolved_args, Some(vec![v(1)]));
                assert_eq!(*interface, Some(ClientInterface::Sep41Token));
            }
            other => panic!("unexpected {other:?}"),
        }
        let note = &ir.functions[0]
            .bindings
            .get(v(5))
            .unwrap()
            .latest_provenance()
            .note;
        assert!(note.contains("elements recovered"), "{note}");
        assert!(note.contains("sep41 balance(id)"), "{note}");
    }

    // --- the transfer shape: facts killed, arity survives ---

    #[test]
    fn killed_facts_degrade_to_arity_only() {
        // An opaque call between the element store and the wrapper call
        // (standing in for the SDK's copy loop living in other blocks).
        let caller = func(
            0,
            None,
            1,
            vec![
                i64c(77),
                store(0, 1, 0),
                call(2, vec![]), // killer
                i32c(3),
                call(1, vec![v(0), v(4)]),
                invoke(0, 1, 5, Some("transfer")),
            ],
        );
        let killer = func(2, None, 0, vec![]);
        let mut ir = module(vec![caller, vec_wrapper(1), killer]);
        let result = run(&mut ir);
        assert!(result.changed);
        match invoke_op(&ir, 0, 6) {
            KnownOp::InvokeContract {
                arg_count,
                resolved_args,
                interface,
                ..
            } => {
                assert_eq!(*arg_count, Some(3));
                assert_eq!(*resolved_args, None, "partial facts must not resolve");
                assert_eq!(*interface, Some(ClientInterface::Sep41Token));
            }
            other => panic!("unexpected {other:?}"),
        }
        let note = &ir.functions[0]
            .bindings
            .get(v(6))
            .unwrap()
            .latest_provenance()
            .note;
        assert!(note.contains("elements unproven"), "{note}");
        assert!(note.contains("sep41 transfer(from, to, amount)"), "{note}");
    }

    // --- negative gates ---

    #[test]
    fn non_wrapper_handle_stays_unresolved() {
        // The handle comes from a helper with no VecNew inside.
        let caller = func(
            0,
            None,
            0,
            vec![call(1, vec![]), invoke(0, 0, 1, Some("transfer"))],
        );
        let not_a_wrapper = func(1, None, 0, vec![i64c(0)]);
        let mut ir = module(vec![caller, not_a_wrapper]);
        let result = run(&mut ir);
        assert!(!result.changed);
        assert_eq!(result.metrics.get(M_UNRESOLVED), Some(1));
    }

    #[test]
    fn runtime_length_stays_unresolved() {
        // len = a parameter with no callers: not a constant.
        let caller = func(
            0,
            None,
            2,
            vec![call(1, vec![v(0), v(1)]), invoke(0, 0, 2, None)],
        );
        let mut ir = module(vec![caller, vec_wrapper(1)]);
        let result = run(&mut ir);
        assert!(!result.changed);
        assert_eq!(result.metrics.get(M_UNRESOLVED), Some(1));
    }

    #[test]
    fn unknown_callee_gets_arity_but_no_interface() {
        let caller = func(
            0,
            None,
            1,
            vec![
                i64c(77),
                store(0, 1, 0),
                i32c(1),
                call(1, vec![v(0), v(3)]),
                invoke(0, 1, 4, Some("swap")),
            ],
        );
        let mut ir = module(vec![caller, vec_wrapper(1)]);
        let result = run(&mut ir);
        assert!(result.changed);
        assert_eq!(result.metrics.get(M_IFACE), None);
        match invoke_op(&ir, 0, 5) {
            KnownOp::InvokeContract {
                arg_count,
                interface,
                ..
            } => {
                assert_eq!(*arg_count, Some(1));
                assert_eq!(*interface, None);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn arity_mismatch_gets_no_interface() {
        // "balance" with 2 args is not SEP-41 evidence.
        let caller = func(
            0,
            None,
            1,
            vec![
                i64c(1),
                store(0, 1, 0),
                i64c(2),
                store(0, 3, 8),
                i32c(2),
                call(1, vec![v(0), v(5)]),
                invoke(0, 1, 6, Some("balance")),
            ],
        );
        let mut ir = module(vec![caller, vec_wrapper(1)]);
        run(&mut ir);
        match invoke_op(&ir, 0, 7) {
            KnownOp::InvokeContract {
                arg_count,
                resolved_args,
                interface,
                ..
            } => {
                assert_eq!(*arg_count, Some(2));
                assert_eq!(*resolved_args, Some(vec![v(1), v(3)]));
                assert_eq!(*interface, None);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn inlined_vec_new_shape_resolves() {
        // No wrapper: the VecNew op sits directly in the caller.
        let caller = func(
            0,
            None,
            1,
            vec![
                i64c(77),
                store(0, 1, 0),
                i32c(1),
                Expr::Semantic(SemanticOp::Known(KnownOp::VecNew {
                    vals_pos: v(0),
                    len: v(3),
                })),
                invoke(0, 1, 4, Some("balance")),
            ],
        );
        let mut ir = module(vec![caller]);
        let result = run(&mut ir);
        assert!(result.changed, "{:?}", result.metrics);
        match invoke_op(&ir, 0, 5) {
            KnownOp::InvokeContract {
                arg_count,
                resolved_args,
                ..
            } => {
                assert_eq!(*arg_count, Some(1));
                assert_eq!(*resolved_args, Some(vec![v(1)]));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn try_invoke_is_upgraded_too() {
        let caller = func(
            0,
            None,
            1,
            vec![
                i64c(77),
                store(0, 1, 0),
                i32c(1),
                call(1, vec![v(0), v(3)]),
                Expr::Semantic(SemanticOp::Known(KnownOp::TryInvokeContract {
                    contract: v(0),
                    function: v(1),
                    args: vec![v(4)],
                    resolved_callee: Some("balance".to_string()),
                    arg_count: None,
                    resolved_args: None,
                    interface: None,
                })),
            ],
        );
        let mut ir = module(vec![caller, vec_wrapper(1)]);
        let result = run(&mut ir);
        assert!(result.changed);
        assert!(matches!(
            invoke_op(&ir, 0, 5),
            KnownOp::TryInvokeContract {
                arg_count: Some(1),
                interface: Some(ClientInterface::Sep41Token),
                ..
            }
        ));
    }

    #[test]
    fn second_run_is_idempotent() {
        let caller = func(
            0,
            None,
            1,
            vec![
                i64c(77),
                store(0, 1, 0),
                i32c(1),
                call(1, vec![v(0), v(3)]),
                invoke(0, 1, 4, Some("balance")),
            ],
        );
        let mut ir = module(vec![caller, vec_wrapper(1)]);
        assert!(run(&mut ir).changed);
        let second = run(&mut ir);
        assert!(!second.changed);
        assert_eq!(second.metrics.get(M_ARITY), None);
    }
}
