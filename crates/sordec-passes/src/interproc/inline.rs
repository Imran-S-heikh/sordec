//! Inline the SDK's one-expression wrapper helpers into their callers.
//!
//! rustc leaves the SDK's smallest helpers out of line. token-v23's
//! `func46` is the whole of `Storage::has` for one key:
//!
//! ```text
//! fn func46(key) -> bool {
//!     v3 = storage_has<instance>(key)
//!     return v3
//! }
//! ```
//!
//! and the contract's `read_administrator` calls it between building the
//! key and reading the value. Every recognizer has already done its work
//! *inside* that helper — the tier is proven, the key is resolved, the
//! `has` is flagged as the SDK's `Option` probe — and yet the caller still
//! sees an opaque `Call`. That opacity is what keeps the derived key
//! converter alive on every `get` site: [`crate::marshalling::key_construction`]
//! must refuse to elide a converter whose result flows into a call it
//! cannot see through, and the call it cannot see through is this one.
//!
//! Inlining moves the recognized operation, with every fact attached to
//! it, into the caller. The result is what the source wrote: the `has`
//! and the `get` side by side on one key, in one function.
//!
//! # What counts as a wrapper
//!
//! A helper with no `contractspecv0` signature whose body is straight-line
//! — no branch, no loop — and short, made only of expressions that can be
//! copied: literals, arithmetic, calls, host operations. No frame traffic
//! (a load or store means the body has state the caller cannot see) and
//! no recursion. It may return one value or none.
//!
//! # Why the copy is exact
//!
//! The bindings are copied in the callee's own emission order, parameters
//! renamed to the caller's arguments and everything else to fresh
//! bindings, and scheduled immediately before the call they replace. The
//! host effects happen at the same point in the same order; the returned
//! value is the same binding the callee returned. Provenance on every
//! copied binding names the helper it came from.
//!
//! # Placement
//!
//! Late: after every recognizer, inside the marshalling elision group.
//! Running early would also work but would change the shapes the
//! recognizers were built against; running late means each copied
//! operation carries its resolved facts, and the elisions that follow in
//! the same group see a caller that finally matches their patterns.

use std::collections::{HashMap, HashSet};

use sordec_common::{
    Diagnostic, FuncId, IrId, LiftDiagnosticCode, Location, Provenance, ProvenanceSource, ValueId,
};
use sordec_ir::{Binding, Expr, HighFunction, HighIr, IrType, Literal, Region};

use crate::marshalling::sret::emission_order;
use crate::metrics_catalog::INLINE_WRAPPER_CALLS as M_INLINED;
use crate::pass::{Pass, PassResult};

/// Pass name, also its provenance `pass` field.
pub const PASS_NAME: &str = "inline-wrappers";

/// Longest body that still counts as a wrapper. The SDK's thin helpers
/// are two to six bindings, and the slice constructors around twenty once
/// their three `U32Val` encodes are counted; the cap keeps a real function
/// from being duplicated into every caller.
const MAX_BODY: usize = 24;

/// Inlines straight-line SDK wrapper helpers into their callers.
#[derive(Debug, Default, Clone, Copy)]
pub struct WrapperInlinePass;

impl Pass<HighIr> for WrapperInlinePass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let wrappers: HashMap<FuncId, Wrapper> = ir
            .functions
            .iter()
            .filter_map(|f| classify(f).map(|w| (f.id, w)))
            .collect();
        if wrappers.is_empty() {
            return result;
        }
        let mut inlined = 0_i64;
        for func in &mut ir.functions {
            let sites: Vec<(ValueId, FuncId)> = func
                .bindings
                .iter()
                .filter_map(|(id, b)| match &b.expr {
                    Expr::Call { target, .. } if *target != func.id && wrappers.contains_key(target) => {
                        Some((id, *target))
                    }
                    _ => None,
                })
                .collect();
            for (call, target) in sites {
                if inline_site(func, call, &wrappers[&target]) {
                    inlined += 1;
                    result.diagnostics.push(
                        Diagnostic::info(
                            LiftDiagnosticCode::SdkFunctionIdentified,
                            format!("inlined wrapper func_{} at its call site", target.index()),
                        )
                        .at(Location::Value { func: func.id, value: call.index() }),
                    );
                }
            }
        }
        if inlined > 0 {
            result.metrics.increment(M_INLINED, inlined);
            result.changed = true;
        }
        result
    }
}

/// A helper's body, copied out so it can be pasted into callers while
/// they are borrowed mutably.
struct Wrapper {
    id: FuncId,
    params: Vec<ValueId>,
    /// `(id, type, expression)` in emission order, dependencies first.
    items: Vec<(ValueId, IrType, Expr)>,
    ret: Option<ValueId>,
}

fn classify(func: &HighFunction) -> Option<Wrapper> {
    if func.signature.is_some() {
        return None;
    }
    // Straight-line: only sequences, basic blocks and at most one return
    // at the tail.
    let mut returns: Vec<Vec<ValueId>> = Vec::new();
    let mut shape_ok = true;
    func.region.for_each_node(|node| match node {
        Region::Sequence(_) | Region::Basic(_) => {}
        Region::Return { values } => returns.push(values.clone()),
        _ => shape_ok = false,
    });
    if !shape_ok || returns.len() > 1 {
        return None;
    }
    let ret = match returns.first() {
        None => None,
        Some(values) if values.len() <= 1 => values.first().copied(),
        Some(_) => return None,
    };

    let scheduled = emission_order(func);
    if scheduled.is_empty() || scheduled.len() > MAX_BODY {
        return None;
    }
    let params: HashSet<ValueId> = func.params.iter().copied().collect();
    let mut known: HashSet<ValueId> = params.clone();
    let mut items: Vec<(ValueId, IrType, Expr)> = Vec::new();

    for id in scheduled {
        let binding = func.bindings.get(id)?;
        if !copyable(&binding.expr, func.id) {
            return None;
        }
        // Every value the expression reads must be a parameter, an
        // earlier body binding, or an unscheduled literal — which is
        // copied in ahead of its reader.
        let mut deps = Vec::new();
        binding.expr.for_each_value_use(|u| deps.push(u));
        for dep in deps {
            if known.contains(&dep) {
                continue;
            }
            let dep_binding = func.bindings.get(dep)?;
            match &dep_binding.expr {
                Expr::Literal(_) => {
                    items.push((dep, dep_binding.ty.clone(), dep_binding.expr.clone()));
                    known.insert(dep);
                }
                // A `Use` of something known is a rename; anything else is
                // state the body reaches without computing it here.
                Expr::Use(inner) if known.contains(inner) => {
                    items.push((dep, dep_binding.ty.clone(), dep_binding.expr.clone()));
                    known.insert(dep);
                }
                _ => return None,
            }
        }
        items.push((id, binding.ty.clone(), binding.expr.clone()));
        known.insert(id);
    }
    if let Some(r) = ret
        && !known.contains(&r)
    {
        return None;
    }
    Some(Wrapper { id: func.id, params: func.params.clone(), items, ret })
}

/// Whether an expression can be pasted into another function unchanged
/// apart from its operands.
fn copyable(expr: &Expr, this: FuncId) -> bool {
    match expr {
        Expr::Literal(_)
        | Expr::Use(_)
        | Expr::Unary { .. }
        | Expr::Binary { .. }
        | Expr::WideJoin { .. }
        | Expr::Field { .. }
        | Expr::Semantic(_) => true,
        Expr::Call { target, .. } => *target != this,
        // A width conversion or a select is a pure operator the lowering
        // has not given a typed spelling; copied verbatim it computes the
        // same value at the same point.
        Expr::Unknown {
            op_kind: sordec_ir::WasmOpcodeKind::Conversion | sordec_ir::WasmOpcodeKind::Select,
            ..
        } => true,
        // Frame traffic, globals, projections of multi-value calls,
        // phis and other unrecovered operators all reach state the
        // caller cannot see through a copy.
        Expr::Project { .. }
        | Expr::IndirectCall { .. }
        | Expr::Phi { .. }
        | Expr::GlobalGet { .. }
        | Expr::Load { .. }
        | Expr::Store { .. }
        | Expr::Unknown { .. } => false,
    }
}

/// Paste `w`'s body before `call` in `func`, renaming as described in
/// the module docs. Returns whether the site was inlined.
fn inline_site(func: &mut HighFunction, call: ValueId, w: &Wrapper) -> bool {
    let Some(Expr::Call { args, .. }) = func.bindings.get(call).map(|b| b.expr.clone()) else {
        return false;
    };
    if args.len() != w.params.len() {
        return false;
    }
    // A multi-value reader of a single-value wrapper is a shape this
    // does not understand.
    if func.bindings.iter().any(|(_, b)| matches!(&b.expr, Expr::Project { value, .. } if *value == call)) {
        return false;
    }
    let Some(block_pos) = func
        .blocks
        .iter()
        .find_map(|(bid, b)| b.bindings.iter().position(|v| *v == call).map(|p| (bid, p)))
    else {
        return false;
    };

    let mut map: HashMap<ValueId, ValueId> = w.params.iter().copied().zip(args.iter().copied()).collect();
    let mut fresh: Vec<ValueId> = Vec::new();
    for (id, ty, expr) in &w.items {
        let mut expr = expr.clone();
        let mut unmapped = false;
        expr.for_each_value_use_mut(|u| match map.get(u) {
            Some(m) => *u = *m,
            None => unmapped = true,
        });
        if unmapped {
            // Roll back nothing: fresh bindings are pushed but never
            // scheduled, so they are inert residue.
            return false;
        }
        let new_id = ValueId::from_index(func.bindings.len() as u32);
        func.bindings.push(Binding::new(
            new_id,
            ty.clone(),
            expr,
            Provenance::new(
                PASS_NAME,
                ProvenanceSource::SdkPattern,
                format!("inlined from wrapper func_{}", w.id.index()),
            ),
        ));
        map.insert(*id, new_id);
        fresh.push(new_id);
    }

    let (bid, pos) = block_pos;
    if let Some(block) = func.blocks.get_mut(bid) {
        for (k, id) in fresh.iter().enumerate() {
            block.bindings.insert(pos + k, *id);
        }
    }
    let (expr, ty) = match w.ret.and_then(|r| map.get(&r).copied()) {
        Some(r) => {
            let ty = func.bindings.get(r).map(|b| b.ty.clone());
            (Expr::Use(r), ty)
        }
        None => (Expr::Literal(Literal::Unit), Some(IrType::Known(sordec_ir::KnownType::Unit))),
    };
    if let Some(b) = func.bindings.get_mut(call) {
        b.expr = expr;
        if let Some(ty) = ty
            && matches!(b.ty, IrType::Unknown(_))
        {
            b.ty = ty;
        }
        b.add_provenance(Provenance::new(
            PASS_NAME,
            ProvenanceSource::SdkPattern,
            format!("call to wrapper func_{} replaced by its inlined body", w.id.index()),
        ));
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, load, module, v};
    use sordec_common::BlockId;
    use sordec_ir::{KnownOp, KnownTier, SemanticOp, StorageTier};

    fn has(key: ValueId, durability: ValueId) -> Expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::StorageHas {
            tier: StorageTier::Known(KnownTier::Instance),
            durability,
            key,
            resolved_key: None,
            probe: true,
        }))
    }

    /// token-v23's `func46`: a durability literal, the `has`, a rename,
    /// and a return of the rename.
    fn has_wrapper(id: u32) -> HighFunction {
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },   // v0 key
                Expr::Literal(Literal::I64(2)),   // v1 durability
                has(v(0), v(1)),                  // v2
                Expr::Use(v(2)),                  // v3
            ],
            vec![v(0)],
            vec![1, 2, 3],
        );
        f.id = FuncId::from_index(id);
        f.region = Region::Sequence(vec![
            Region::Basic(BlockId::from_index(0)),
            Region::Return { values: vec![v(3)] },
        ]);
        f
    }

    fn caller(id: u32, target: u32) -> HighFunction {
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] }, // v0 key
                Expr::Call { target: FuncId::from_index(target), args: vec![v(0)] }, // v1
                Expr::Unary { op: sordec_ir::UnaryOp::Not, value: v(1) }, // v2
            ],
            vec![v(0)],
            vec![1, 2],
        );
        f.id = FuncId::from_index(id);
        f
    }

    fn expr_at(ir: &HighIr, func: u32, value: u32) -> &Expr {
        &ir.function(FuncId::from_index(func)).unwrap().bindings.get(v(value)).unwrap().expr
    }

    #[test]
    fn a_storage_probe_wrapper_is_classified() {
        let w = classify(&has_wrapper(0)).expect("wrapper");
        assert_eq!(w.items.len(), 3);
        assert_eq!(w.ret, Some(v(3)));
    }

    #[test]
    fn a_branching_body_is_not_a_wrapper() {
        let mut f = has_wrapper(0);
        f.region = Region::Sequence(vec![
            Region::If {
                cond: v(2),
                then_region: Box::new(Region::Panic { kind: sordec_ir::PanicKind::Bare }),
                else_region: None,
            },
            Region::Return { values: vec![v(3)] },
        ]);
        assert!(classify(&f).is_none());
    }

    #[test]
    fn a_body_with_frame_traffic_is_not_a_wrapper() {
        let mut f = has_wrapper(0);
        f.bindings.get_mut(v(1)).unwrap().expr = load(v(0), 0);
        assert!(classify(&f).is_none());
    }

    #[test]
    fn the_call_becomes_the_inlined_operation() {
        let mut m = module(vec![has_wrapper(0), caller(1, 0)]);
        let r = WrapperInlinePass.run(&mut m);
        assert!(r.changed);
        assert_eq!(r.metrics.get(M_INLINED), Some(1));

        // The call is now a use of the copied rename, which uses the
        // copied `has`, whose key is the caller's own argument.
        let Expr::Use(ren) = expr_at(&m, 1, 1) else { panic!("call should become a use") };
        let Expr::Use(op) = expr_at(&m, 1, ren.index()) else { panic!("rename copied") };
        match expr_at(&m, 1, op.index()) {
            Expr::Semantic(SemanticOp::Known(KnownOp::StorageHas { key, durability, probe, .. })) => {
                assert_eq!(*key, v(0));
                assert!(*probe, "facts travel with the copy");
                assert!(matches!(expr_at(&m, 1, durability.index()), Expr::Literal(Literal::I64(2))));
            }
            other => panic!("expected the inlined has, got {other:?}"),
        }
        // Scheduled ahead of the (former) call.
        let block = &m.functions[1].blocks.get(BlockId::from_index(0)).unwrap().bindings;
        let call_pos = block.iter().position(|x| *x == v(1)).unwrap();
        assert!(block[..call_pos].contains(op));
    }

    #[test]
    fn the_pass_is_idempotent() {
        let mut m = module(vec![has_wrapper(0), caller(1, 0)]);
        assert!(WrapperInlinePass.run(&mut m).changed);
        assert!(!WrapperInlinePass.run(&mut m).changed);
    }
}
