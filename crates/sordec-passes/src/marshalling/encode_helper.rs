//! Helpers that do nothing but encode their argument.
//!
//! # The shape
//!
//! A number too wide for a small `Val` needs a host call to encode, so the
//! SDK's `IntoVal` for `u64` is a branch — and rustc outlines it into a
//! helper the entrypoints share:
//!
//! ```text
//! fn func1(x) {                              add:  return func1(a + b).1
//!     if x > 0x00FF_FFFF_FFFF_FFFF { r = obj_from_u64(x) }
//!     else                         { r = val_encode<u64>(x) }
//!     return (0, r)
//! }
//! ```
//!
//! [`super::encode`] collapses that branch where it sits inline in the
//! entrypoint. Outlined, the entrypoint returns a call's component, the
//! collapse never sees an encode, and the returned word stays typed as the
//! payload while the helper's own body says `Val`: one value in two
//! representations.
//!
//! This module only *recognises* such helpers ([`EncoderTable`]); the
//! passes that collapse encodes consult it where they would have seen the
//! encode inline.
//!
//! # Why a call is the encode
//!
//! A helper's return slot is an encoder of its parameter `p` as `T` when
//! every value the slot returns, on every path, is an encode of `p` as `T`
//! — the inline `obj_from_*`/`val_encode` pair, or the same slot of another
//! such helper called with `p`. Then the call's component *is*
//! `encode::<T>(arg)` on every path, which is exactly what the inline
//! collapse reads.
//!
//! # Gates
//!
//! - **A helper**: no spec signature, every return of the same arity.
//! - **Nothing else happens.** Every binding the helper runs is pure and
//!   total, or a call to another such helper — so a call whose results all
//!   collapsed may be dropped without losing an effect.
//! - **One parameter, one type** per slot, on every path.

use std::collections::HashMap;

use sordec_common::{FuncId, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Literal, Region, SemanticOp, ValObjectKind};

use super::sret::emission_order;
use crate::dataflow::resolve_use;
use crate::effects::expr_effects;

/// How deep a helper may call another to encode.
const MAX_DEPTH: usize = 4;

/// The encoder slots of every helper that only encodes: `slots[k]` is the
/// parameter index and type slot `k` returns the encode of, if it does.
#[derive(Debug, Default, Clone)]
pub(crate) struct EncoderTable {
    helpers: HashMap<FuncId, Vec<Option<(usize, KnownType)>>>,
}

impl EncoderTable {
    /// Recognise every encoding helper in `ir`.
    pub(crate) fn build(ir: &HighIr) -> Self {
        let mut table = EncoderTable::default();
        for _ in 0..MAX_DEPTH {
            let mut grew = false;
            for func in &ir.functions {
                if table.helpers.contains_key(&func.id) {
                    continue;
                }
                if let Some(slots) = classify(func, &table) {
                    table.helpers.insert(func.id, slots);
                    grew = true;
                }
            }
            if !grew {
                break;
            }
        }
        table
    }

    /// Whether `target` is a helper that only encodes.
    pub(crate) fn is_encoder(&self, target: FuncId) -> bool {
        self.helpers.contains_key(&target)
    }

    /// The payload and type `value` encodes when it is a call's component
    /// an encoder slot returns: `func1(x).1` is `encode::<u64>(x)`.
    pub(crate) fn encoded_by_call(&self, func: &HighFunction, value: ValueId) -> Option<(ValueId, KnownType)> {
        let (call, index) = match &func.bindings.get(resolve_use(func, value))?.expr {
            Expr::Project { value, index } => (resolve_use(func, *value), *index as usize),
            Expr::Call { .. } => (resolve_use(func, value), 0),
            _ => return None,
        };
        let Expr::Call { target, args } = &func.bindings.get(call)?.expr else { return None };
        let slots = self.helpers.get(target)?;
        // A bare call is the value of a one-slot helper only.
        if matches!(func.bindings.get(resolve_use(func, value))?.expr, Expr::Call { .. }) && slots.len() != 1 {
            return None;
        }
        let (param, ty) = slots.get(index)?.clone()?;
        Some((resolve_use(func, *args.get(param)?), ty))
    }
}

/// The encoder slots of `func`, when it is a helper that only encodes and
/// at least one slot is an encoder.
fn classify(func: &HighFunction, table: &EncoderTable) -> Option<Vec<Option<(usize, KnownType)>>> {
    if func.signature.is_some() {
        return None;
    }
    let mut sites: Vec<Vec<ValueId>> = Vec::new();
    func.region.for_each_node(|node| {
        if let Region::Return { values } = node {
            sites.push(values.clone());
        }
    });
    let arity = sites.first()?.len();
    if arity == 0 || sites.iter().any(|s| s.len() != arity) {
        return None;
    }
    // Nothing but pure, total work — and calls to helpers already known
    // to be only that.
    let clean = emission_order(func).into_iter().all(|id| {
        func.bindings.get(id).is_none_or(|b| match &b.expr {
            Expr::Call { target, .. } => table.is_encoder(*target),
            other => expr_effects(other).is_pure_total(),
        })
    });
    if !clean {
        return None;
    }
    let slots: Vec<Option<(usize, KnownType)>> = (0..arity)
        .map(|k| {
            let mut agreed: Option<(usize, KnownType)> = None;
            for site in &sites {
                for def in arms(func, site[k]) {
                    let (payload, ty) = inline_encode(func, def).or_else(|| table.encoded_by_call(func, def))?;
                    let param = func.params.iter().position(|p| *p == payload)?;
                    match &agreed {
                        None => agreed = Some((param, ty)),
                        Some(prev) if *prev == (param, ty.clone()) => {}
                        Some(_) => return None,
                    }
                }
            }
            agreed
        })
        .collect();
    slots.iter().any(Option::is_some).then_some(slots)
}

/// The definitions that produce `value`: a merge's arms, through merges.
fn arms(func: &HighFunction, value: ValueId) -> Vec<ValueId> {
    let mut out = Vec::new();
    let mut work = vec![resolve_use(func, value)];
    let mut seen = std::collections::HashSet::new();
    while let Some(v) = work.pop() {
        if !seen.insert(v) {
            continue;
        }
        match func.bindings.get(v).map(|b| &b.expr) {
            Some(Expr::Phi { incoming }) if !incoming.is_empty() => {
                work.extend(incoming.iter().map(|(_, a)| resolve_use(func, *a)));
            }
            _ => out.push(v),
        }
    }
    out
}

/// The payload and type of an inline encode: the small form or the
/// single-argument object constructor.
pub(crate) fn inline_encode(func: &HighFunction, value: ValueId) -> Option<(ValueId, KnownType)> {
    match &func.bindings.get(resolve_use(func, value))?.expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty, value })) => {
            Some((resolve_use(func, *value), ty.clone()))
        }
        Expr::Semantic(SemanticOp::Known(KnownOp::ValObject { kind, args })) if args.len() == 1 => {
            let ty = match kind {
                ValObjectKind::ObjFromU64 => KnownType::U64,
                ValObjectKind::ObjFromI64 => KnownType::I64,
                ValObjectKind::TimepointObjFromU64 => KnownType::Timepoint,
                ValObjectKind::DurationObjFromU64 => KnownType::Duration,
                _ => return None,
            };
            Some((resolve_use(func, args[0]), ty))
        }
        _ => None,
    }
}

/// Every call `func` runs to a helper that only encodes.
pub(crate) fn encoder_calls(func: &HighFunction, table: &EncoderTable) -> Vec<ValueId> {
    emission_order(func)
        .into_iter()
        .filter(|id| matches!(func.bindings.get(*id).map(|b| &b.expr), Some(Expr::Call { target, .. }) if table.is_encoder(*target)))
        .collect()
}

/// Drop each call in `calls` to an encoding helper that nothing reads any
/// more: the helper does nothing else, so the call has no effect left.
/// Returns how many it dropped.
pub(crate) fn elide_spent_calls(
    func: &mut HighFunction,
    table: &EncoderTable,
    calls: &[ValueId],
    pass: &'static str,
) -> usize {
    let mut dropped = 0;
    for &call in calls {
        let Some(Expr::Call { target, .. }) = func.bindings.get(call).map(|b| &b.expr) else { continue };
        if !table.is_encoder(*target) || live_readers(func, call) > 0 {
            continue;
        }
        if let Some(b) = func.bindings.get_mut(call) {
            b.expr = Expr::Literal(Literal::Unit);
            b.ty = IrType::Known(KnownType::Unit);
            b.add_provenance(Provenance::new(
                pass,
                ProvenanceSource::SdkPattern,
                "call to a return-encode helper, elided with its results",
            ));
            dropped += 1;
        }
    }
    dropped
}

/// Reads of `v` by code that runs. Live is what the region reads, what an
/// effect reads, and — transitively — what a live binding reads; a pure
/// binding read by nothing live is residue, however long its chain (the
/// status a call also returned, compared with a constant nobody tests).
fn live_readers(func: &HighFunction, v: ValueId) -> usize {
    let order = emission_order(func);
    let mut live: std::collections::HashSet<ValueId> = std::collections::HashSet::new();
    let mut work: Vec<ValueId> = Vec::new();
    func.region.for_each_value_use(|u| work.push(u));
    for id in &order {
        if let Some(b) = func.bindings.get(*id)
            && !expr_effects(&b.expr).is_pure_total()
        {
            work.push(*id);
        }
    }
    while let Some(id) = work.pop() {
        if !live.insert(id) {
            continue;
        }
        if let Some(b) = func.bindings.get(id) {
            b.expr.for_each_value_use(|u| work.push(u));
        }
    }
    let mut n = 0;
    for id in &live {
        if *id == v {
            continue;
        }
        if let Some(b) = func.bindings.get(*id) {
            b.expr.for_each_value_use(|u| n += usize::from(u == v));
        }
    }
    func.region.for_each_value_use(|u| n += usize::from(u == v));
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};
    use sordec_common::{BlockId, IrId};

    /// func 0: `r = phi [obj_from_u64(x), val_encode<u64>(x)]; return (0, r)`.
    fn encoder() -> HighFunction {
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] }, // v0: x
                Expr::Semantic(SemanticOp::Known(KnownOp::ValObject { kind: ValObjectKind::ObjFromU64, args: vec![v(0)] })), // v1
                Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty: KnownType::U64, value: v(0) })), // v2
                Expr::Phi { incoming: vec![(BlockId::from_index(0), v(1)), (BlockId::from_index(1), v(2))] }, // v3
                Expr::Literal(Literal::I64(0)), // v4
            ],
            vec![v(0)],
            vec![1, 2, 4],
        );
        f.region = Region::Sequence(vec![Region::Basic(BlockId::from_index(0)), Region::Return { values: vec![v(4), v(3)] }]);
        f
    }

    /// func 1, calling func 0: `t = func0(y); return t.1`.
    fn caller() -> HighFunction {
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                                  // v0: y
                Expr::Call { target: FuncId::from_index(0), args: vec![v(0)] },  // v1
                Expr::Project { value: v(1), index: 1 },                         // v2
            ],
            vec![v(0)],
            vec![1, 2],
        );
        f.id = FuncId::from_index(1);
        f.region = Region::Sequence(vec![Region::Basic(BlockId::from_index(0)), Region::Return { values: vec![v(2)] }]);
        f
    }

    #[test]
    fn a_helper_returning_its_argument_s_encode_is_an_encoder() {
        let ir = module(vec![encoder(), caller()]);
        let table = EncoderTable::build(&ir);
        assert!(table.is_encoder(FuncId::from_index(0)));
        assert_eq!(table.encoded_by_call(&ir.functions[1], v(2)), Some((v(0), KnownType::U64)));
        // The caller itself returns that encode of its own parameter.
        assert!(table.is_encoder(FuncId::from_index(1)));
    }

    #[test]
    fn a_helper_with_an_effect_is_not_an_encoder() {
        let mut helper = encoder();
        helper.bindings.get_mut(v(4)).unwrap().expr = Expr::Load {
            addr: v(0),
            offset: 0,
            width: sordec_ir::MemWidth::W8,
            signed: None,
            ty: IrType::Known(KnownType::I64),
        };
        let ir = module(vec![helper, caller()]);
        assert!(!EncoderTable::build(&ir).is_encoder(FuncId::from_index(0)));
    }

    #[test]
    fn arms_encoding_different_values_are_not_an_encoder() {
        let mut helper = encoder();
        helper.bindings.get_mut(v(2)).unwrap().expr =
            Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty: KnownType::U64, value: v(4) }));
        let ir = module(vec![helper, caller()]);
        assert!(!EncoderTable::build(&ir).is_encoder(FuncId::from_index(0)));
    }
}
