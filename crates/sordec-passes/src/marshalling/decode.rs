//! Collapse an SDK argument decode back to the parameter it decodes.
//!
//! ## The transform
//!
//! `contractspecv0` declares `add(a: u64, b: u64) -> u64`, so the emitted
//! entrypoint takes `a: u64`. The wasm does not: `a` arrives as a tagged
//! `Val` that the SDK's `u64: TryFromVal<Env, Val>` glue unpacks through a
//! helper writing `Result<u64, ConversionError>` into the caller's frame.
//! Reconstructed literally that is a call, two loads and a failure guard
//! wrapped around a value the source just called `a`:
//!
//! ```text
//! call decode(fp, a)          →   (nothing)
//! load fp+0   ← discriminant  →   0   (the Ok arm; the guard is then
//!                                      constant-false, and [`super::guard`]
//!                                      removes it)
//! load fp+8   ← payload       →   a
//! ```
//!
//! ## Why the callee must be classified first
//!
//! The out-parameter shape is not evidence of marshalling. token-v23's
//! `balance` calls `read_balance` with exactly the same call-plus-two-loads
//! silhouette, but `read_balance` reads storage and returns a real `i128`
//! — eliding *that* would delete the contract's logic and still compile.
//! [`classify`] is the discriminator: a decode helper computes its result
//! from its own `Val` argument and touches nothing else, which
//! [`crate::effects`] can prove.
//!
//! ## Gates
//!
//! Each declines rather than approximating:
//!
//! - **No host state.** The callee must read and write no storage, TTL,
//!   auth, event or PRNG state. One `storage_get` and it is real code.
//!   Note this is *not* total purity: the `obj_to_*` extractors trap on a
//!   tag mismatch, so a decode helper is built from trapping operations
//!   and demanding purity would reject every one of them.
//! - **The payload must come from the argument.** Every `Ok` arm's payload
//!   has to trace back to the helper's own `Val` parameter through decode
//!   operations only — `ValDecodeSmall` and the *scalar* `obj_to_*`
//!   unwraps. The `hi64`/`lo64` piece extractors are excluded on purpose:
//!   a single piece is not the whole value, and treating it as one would
//!   silently truncate an `i128`.
//! - **Declared type agreement.** Every tag the helper tests must denote
//!   the type `contractspecv0` declares for the argument being passed. A
//!   helper that accepts `AddressObject` fed a parameter declared `u64`
//!   means our picture is wrong somewhere, so nothing is elided.
//! - **Entry parameters only.** The collapse rests on the ABI guarantee
//!   that the host already validated this value against the spec. That
//!   guarantee exists for an entrypoint parameter and for nothing else.

use std::collections::HashMap;

use sordec_common::{FuncId, ValueId};
use sordec_ir::{
    Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Literal, SemanticOp, ValObjectKind,
};

use super::sret::{self, SretShape};
use super::{apply_elisions, metrics, Elision};
use crate::dataflow::{resolve_use, trace_int};
use crate::effects::expr_effects;
use crate::pass::{Pass, PassMetrics, PassResult};
use crate::type_infer::known_of_type_ref;
use crate::val_abi;

/// Pass name — also the provenance `pass` field for every elision.
pub const PASS_NAME: &str = "marshalling-decode-collapse";

/// Maximum decode-chain depth when tracing a payload back to its
/// parameter. Real chains are one or two links (`obj_to_u64(v)`,
/// `val_decode(v)`); the bound exists so a malformed cycle terminates.
const TRACE_DEPTH: u32 = 8;

/// A helper proven to be nothing but `T::try_from_val(env, val)`.
#[derive(Debug, Clone)]
pub(crate) struct DecodeHelper {
    /// Position of the out-pointer in the parameter list, so a caller
    /// matches arguments positionally rather than assuming a layout.
    out_index: usize,
    /// Position of the `Val` being decoded, likewise.
    val_index: usize,
    /// Slot holding the `Result` discriminant (`0` = Ok).
    disc_offset: u32,
    /// Slot holding the decoded payload.
    payload_offset: u32,
    /// Every tag the helper tests, so the caller can check them against
    /// the declared parameter type.
    tags: Vec<u8>,
}

/// The C1-elision pass: collapse argument decodes to their parameters.
#[derive(Debug, Default, Clone, Copy)]
pub struct ValDecodeCollapsePass;

impl Pass<HighIr> for ValDecodeCollapsePass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();

        // Classify every helper once, module-wide, before touching
        // anything: the decision is a property of the callee and several
        // callers may share one helper.
        let helpers: HashMap<FuncId, DecodeHelper> = ir
            .functions
            .iter()
            .filter_map(|f| classify(f).map(|h| (f.id, h)))
            .collect();
        if helpers.is_empty() {
            return result;
        }

        for func in &mut ir.functions {
            let (elisions, metrics) = plan(func, &helpers);
            if elisions.is_empty() {
                continue;
            }
            result.changed = true;
            for (key, value) in metrics.iter() {
                result.metrics.increment(key, value);
            }
            apply_elisions(func, PASS_NAME, elisions);
        }
        result
    }
}

// ---------------------------------------------------------------------
// Callee classification
// ---------------------------------------------------------------------

/// Is `func` an SDK `TryFromVal` decode helper? `None` when any gate
/// declines.
pub(crate) fn classify(func: &HighFunction) -> Option<DecodeHelper> {
    let shape = sret::analyze(func)?;
    // Exactly `(out, val)`: a decode reads one Val and writes one Result.
    if func.params.len() != 2 || shape.slots.len() != 2 {
        return None;
    }
    // The parameter that is not the out-pointer is the Val being decoded.
    let val_index = 1 - shape.out_index;
    let val_param = func.params[val_index];

    if !touches_no_host_state(func, &shape) {
        return None;
    }

    let (disc_offset, payload_offset) = discriminant_and_payload(func, &shape)?;
    let disc = shape.slot(disc_offset)?;
    let payload = shape.slot(payload_offset)?;

    // Every Ok arm's payload must come from the Val parameter.
    let mut saw_ok = false;
    for (disc_value, payload_value) in arms(func, disc, payload)? {
        match trace_int(func, disc_value) {
            Some(0) => {
                if !decodes_to(func, payload_value, val_param, TRACE_DEPTH) {
                    return None;
                }
                saw_ok = true;
            }
            // The Err arm carries a `ConversionError` constant; its
            // payload is irrelevant because the guard that reads it is
            // provably not taken.
            Some(1) => {}
            // Anything else is not a `Result` discriminant.
            _ => return None,
        }
    }
    if !saw_ok {
        return None;
    }

    let tags = tested_tags(func, val_param);
    if tags.is_empty() {
        return None;
    }

    Some(DecodeHelper {
        out_index: shape.out_index,
        val_index,
        disc_offset,
        payload_offset,
        tags,
    })
}

/// The callee must touch no host state: no storage, no TTLs, no auth, no
/// events, no PRNG, no cross-contract call. This is the gate that
/// separates marshalling from real code — `read_balance` fails it on its
/// `storage_get` alone.
///
/// Deliberately **not** `is_pure_total`. The `obj_to_*` extractors are
/// classified `TRAP` because they tag-validate their argument, and a
/// decode helper is *made of* those — requiring total purity would reject
/// every real decode. Trapping is precisely the behaviour we separately
/// prove unreachable via the declared-type agreement, so it must not also
/// be disqualifying here.
///
/// `Expr::Call` classifies as `WORST`, so a helper that calls another
/// function is conservatively rejected. That costs nothing today (the
/// corpus decode helpers are leaves) and keeps this from having to reason
/// about a callee's callees.
fn touches_no_host_state(func: &HighFunction, shape: &SretShape) -> bool {
    // Emitted bindings only, for the same reason [`sret::analyze`] scans
    // that set: unscheduled de-cluttering residue never runs.
    sret::emission_order(func).into_iter().all(|id| {
        if shape.store_bindings.contains(&id) {
            return true;
        }
        let Some(binding) = func.bindings.get(id) else {
            return true;
        };
        let effects = expr_effects(&binding.expr);
        !effects.reads_host && !effects.writes_host
    })
}

/// Which slot is the discriminant and which the payload.
///
/// The discriminant is the slot whose every arm is a small integer
/// literal; the payload is the other one. Decided by evidence rather than
/// by assuming offset 0, because the layout is rustc's choice.
fn discriminant_and_payload(func: &HighFunction, shape: &SretShape) -> Option<(u32, u32)> {
    let offsets: Vec<u32> = shape.slots.keys().copied().collect();
    let [a, b] = offsets[..] else { return None };
    let a_disc = all_arms_are_flags(func, shape.slot(a)?);
    let b_disc = all_arms_are_flags(func, shape.slot(b)?);
    match (a_disc, b_disc) {
        (true, false) => Some((a, b)),
        (false, true) => Some((b, a)),
        // Both or neither look like a discriminant — no honest answer.
        _ => None,
    }
}

/// Whether every arm of `value` resolves to `0` or `1`.
fn all_arms_are_flags(func: &HighFunction, value: ValueId) -> bool {
    match arms_of(func, value) {
        Some(values) => values
            .iter()
            .all(|v| matches!(trace_int(func, *v), Some(0 | 1))),
        None => false,
    }
}

/// The per-path values of `value`: a phi's incoming values, or the value
/// itself when it is not a phi.
fn arms_of(func: &HighFunction, value: ValueId) -> Option<Vec<ValueId>> {
    let id = resolve_use(func, value);
    let binding = func.bindings.get(id)?;
    Some(match &binding.expr {
        Expr::Phi { incoming } => incoming.iter().map(|(_, v)| *v).collect(),
        _ => vec![id],
    })
}

/// Pair the discriminant and payload values path by path.
///
/// Both slots are written on every return path, so when they are phis
/// their predecessor sets must agree — that agreement is what makes
/// "discriminant 0 implies this payload" a sound reading rather than a
/// cross-product guess.
fn arms(
    func: &HighFunction,
    disc: ValueId,
    payload: ValueId,
) -> Option<Vec<(ValueId, ValueId)>> {
    let disc_expr = &func.bindings.get(resolve_use(func, disc))?.expr;
    let payload_expr = &func.bindings.get(resolve_use(func, payload))?.expr;
    match (disc_expr, payload_expr) {
        (Expr::Phi { incoming: d }, Expr::Phi { incoming: p }) => {
            let by_block: HashMap<_, _> = p.iter().map(|(b, v)| (*b, *v)).collect();
            if d.len() != p.len() {
                return None;
            }
            d.iter()
                .map(|(block, dv)| by_block.get(block).map(|pv| (*dv, *pv)))
                .collect()
        }
        // A single-path helper: one arm, no pairing needed.
        (Expr::Phi { .. }, _) | (_, Expr::Phi { .. }) => None,
        _ => Some(vec![(disc, payload)]),
    }
}

/// Does `value` come from `param` through decode operations only?
fn decodes_to(func: &HighFunction, value: ValueId, param: ValueId, depth: u32) -> bool {
    if depth == 0 {
        return false;
    }
    let id = resolve_use(func, value);
    if id == param {
        return true;
    }
    let Some(binding) = func.bindings.get(id) else {
        return false;
    };
    match &binding.expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { value })) => {
            decodes_to(func, *value, param, depth - 1)
        }
        Expr::Semantic(SemanticOp::Known(KnownOp::ValObject { kind, args }))
            if is_scalar_unwrap(*kind) && args.len() == 1 =>
        {
            decodes_to(func, args[0], param, depth - 1)
        }
        _ => false,
    }
}

/// The `obj_to_*` conversions that yield a *whole* value.
///
/// Deliberately excludes the `hi64`/`lo64`/`hi_hi`… piece extractors: each
/// returns one limb of a wide value, so accepting them here would let a
/// 128-bit argument collapse to half of itself. Rejoining those limbs is a
/// separate transform.
fn is_scalar_unwrap(kind: ValObjectKind) -> bool {
    matches!(
        kind,
        ValObjectKind::ObjToU64
            | ValObjectKind::ObjToI64
            | ValObjectKind::TimepointObjToU64
            | ValObjectKind::DurationObjToU64
    )
}

/// Every tag tested against `param` in this function.
fn tested_tags(func: &HighFunction, param: ValueId) -> Vec<u8> {
    let mut tags = Vec::new();
    for (_, binding) in func.bindings.iter() {
        if let Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck { value, tag, .. })) =
            &binding.expr
            && resolve_use(func, *value) == param
            && !tags.contains(tag)
        {
            tags.push(*tag);
        }
    }
    tags
}

// ---------------------------------------------------------------------
// Call-site planning
// ---------------------------------------------------------------------

/// A decode whose results are still being consumed at the current point
/// of the walk.
struct Active {
    /// The call binding, neutralised once its results are bound.
    call: ValueId,
    /// The entrypoint parameter that was passed in.
    param: ValueId,
    /// The declared type of that parameter.
    declared: KnownType,
    helper: DecodeHelper,
    /// Whether any load has actually been rewritten against this call —
    /// the call is only elided when its results were.
    consumed: bool,
}

/// Plan every collapse in one caller.
fn plan(
    func: &HighFunction,
    helpers: &HashMap<FuncId, DecodeHelper>,
) -> (Vec<Elision>, PassMetrics) {
    let mut elisions = Vec::new();
    let mut metrics = PassMetrics::new();
    // Only an entrypoint carries the ABI guarantee the collapse rests on.
    if func.signature.is_none() {
        return (elisions, metrics);
    }

    // Frame pointer → the decode currently occupying it. Walking in
    // emission order matters: hello-add decodes two arguments through one
    // 16-byte frame, so the loads after the second call must bind to the
    // second call, not the first.
    let mut active: HashMap<ValueId, Active> = HashMap::new();
    // Decodes no longer current — displaced by a later decode into the
    // same frame, or invalidated. They still need their call neutralised
    // if their results were already rebound, so they must not simply be
    // dropped when they leave the map.
    let mut finished: Vec<Active> = Vec::new();

    for id in sret::emission_order(func) {
        let Some(binding) = func.bindings.get(id) else {
            continue;
        };
        match &binding.expr {
            Expr::Call { target, args } => {
                let (invalidate, claimed) = on_call(func, helpers, &active, id, *target, args);
                for frame in invalidate {
                    finished.extend(active.remove(&frame));
                }
                if let Some((frame, act)) = claimed {
                    finished.extend(active.insert(frame, act));
                }
            }
            Expr::Load { addr, offset, .. } => {
                let frame = resolve_use(func, *addr);
                let Some(act) = active.get_mut(&frame) else {
                    continue;
                };
                if *offset == act.helper.disc_offset {
                    act.consumed = true;
                    elisions.push(Elision {
                        id,
                        expr: Expr::Literal(ok_discriminant(&binding.ty)),
                        ty: None,
                        note: "decode-result discriminant is Ok: the host validated \
                               this argument against contractspecv0 before dispatch"
                            .to_string(),
                        metric: metrics::DECODE_COLLAPSED,
                    });
                } else if *offset == act.helper.payload_offset {
                    act.consumed = true;
                    elisions.push(Elision {
                        id,
                        expr: Expr::Use(act.param),
                        ty: Some(IrType::Known(act.declared.clone())),
                        note: format!(
                            "argument decode collapsed to its parameter ({})",
                            tag_list(&act.helper.tags)
                        ),
                        metric: metrics::DECODE_COLLAPSED,
                    });
                } else {
                    // A slot we did not account for — our picture of this
                    // frame is incomplete, so stop trusting it.
                    finished.extend(active.remove(&frame));
                }
            }
            // Any other write through a tracked frame invalidates it.
            Expr::Store { addr, .. } => {
                let frame = resolve_use(func, *addr);
                finished.extend(active.remove(&frame));
            }
            _ => {}
        }
    }

    // Neutralise every call whose results we actually rebound.
    finished.extend(active.into_values());
    for act in finished.into_iter().filter(|a| a.consumed) {
        elisions.push(Elision {
            id: act.call,
            expr: Expr::Literal(Literal::Unit),
            ty: Some(IrType::Known(KnownType::Unit)),
            note: "call to an argument-decode helper, elided with its results".to_string(),
            metric: metrics::DECODE_CALLS_ELIDED,
        });
    }
    for el in &elisions {
        metrics.increment(el.metric, 1);
    }
    (elisions, metrics)
}

/// Classify one call during the walk.
///
/// Returns the frames whose tracking must end, and — when this call is
/// itself an elidable decode — the frame it now claims together with the
/// state to track against it. The caller owns the map so that a displaced
/// entry is never silently dropped: hello-add decodes both arguments
/// through the same frame, so the first decode leaves the map while its
/// loads have already been rebound and its call still needs eliding.
fn on_call(
    func: &HighFunction,
    helpers: &HashMap<FuncId, DecodeHelper>,
    active: &HashMap<ValueId, Active>,
    id: ValueId,
    target: FuncId,
    args: &[ValueId],
) -> (Vec<ValueId>, Option<(ValueId, Active)>) {
    let mut invalidate: Vec<ValueId> = args
        .iter()
        .map(|a| resolve_use(func, *a))
        .filter(|a| active.contains_key(a))
        .collect();

    let Some(helper) = helpers.get(&target) else {
        return (invalidate, None);
    };
    if args.len() != 2 {
        return (invalidate, None);
    }
    let frame = resolve_use(func, args[helper.out_index]);
    let actual = resolve_use(func, args[helper.val_index]);
    let Some(declared) = declared_param_type(func, actual) else {
        return (invalidate, None);
    };
    // Every tag the helper tests must denote the declared type.
    if !helper
        .tags
        .iter()
        .all(|t| val_abi::tag_payload_type(*t).as_ref() == Some(&declared))
    {
        return (invalidate, None);
    }
    // This call now owns the frame, so it must not also be invalidated.
    invalidate.retain(|f| *f != frame);
    let act = Active {
        call: id,
        param: actual,
        declared,
        helper: helper.clone(),
        consumed: false,
    };
    (invalidate, Some((frame, act)))
}

/// The `contractspecv0` type of `value`, when it is one of this
/// entrypoint's parameters.
fn declared_param_type(func: &HighFunction, value: ValueId) -> Option<KnownType> {
    let sig = func.signature.as_ref()?;
    let index = func.params.iter().position(|p| *p == value)?;
    known_of_type_ref(&sig.inputs.get(index)?.ty)
}

/// A zero discriminant in the same width the load claimed, so the guard
/// comparing it keeps matching operand types.
fn ok_discriminant(ty: &IrType) -> Literal {
    match ty {
        IrType::Known(KnownType::I64 | KnownType::U64)
        | IrType::Inferred(KnownType::I64 | KnownType::U64) => Literal::I64(0),
        _ => Literal::I32(0),
    }
}

fn tag_list(tags: &[u8]) -> String {
    tags.iter()
        .map(|t| val_abi::tag_name(*t).unwrap_or("?"))
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, load, store, v};
    use sordec_common::IrId;
    use sordec_ir::{BinaryOp, FunctionParam, FunctionSignature, PrimitiveType, TypeRef};

    fn tag_check(value: ValueId, tag: u8) -> Expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck {
            value,
            tag,
            negated: false,
        }))
    }

    fn obj_to_u64(value: ValueId) -> Expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::ValObject {
            kind: ValObjectKind::ObjToU64,
            args: vec![value],
        }))
    }

    fn val_decode(value: ValueId) -> Expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { value }))
    }

    /// The hello-add `u64: TryFromVal<Env, Val>` helper: two tag-checked
    /// Ok arms and one Err arm, written into a two-slot out-parameter.
    pub(crate) fn u64_decode_helper() -> HighFunction {
        use sordec_common::BlockId;
        let bb = |i: u32| BlockId::from_index(i);
        func_with(
            vec![
                Expr::Phi { incoming: vec![] },              // v0 out-param
                Expr::Phi { incoming: vec![] },              // v1 the Val
                tag_check(v(1), val_abi::TAG_U64_OBJECT),    // v2
                obj_to_u64(v(1)),                            // v3 Ok payload A
                tag_check(v(1), val_abi::TAG_U64_SMALL),     // v4
                val_decode(v(1)),                            // v5 Ok payload B
                Expr::Literal(Literal::I64(0)),              // v6 Ok
                Expr::Literal(Literal::I64(1)),              // v7 Err
                Expr::Literal(Literal::I64(34_359_740_419)), // v8 error Val
                Expr::Phi {
                    incoming: vec![(bb(1), v(6)), (bb(2), v(6)), (bb(3), v(7))],
                }, // v9 discriminant
                Expr::Phi {
                    incoming: vec![(bb(1), v(3)), (bb(2), v(5)), (bb(3), v(8))],
                }, // v10 payload
                store(v(0), v(9), 0),                        // v11
                store(v(0), v(10), 8),                       // v12
            ],
            vec![v(0), v(1)],
            vec![2, 3, 4, 5, 6, 7, 8, 11, 12],
        )
    }

    #[test]
    fn the_sdk_decode_helper_is_classified() {
        let helper = classify(&u64_decode_helper()).expect("a pure Val decode");
        assert_eq!((helper.out_index, helper.val_index), (0, 1));
        assert_eq!(helper.disc_offset, 0);
        assert_eq!(helper.payload_offset, 8);
        assert_eq!(
            helper.tags,
            vec![val_abi::TAG_U64_OBJECT, val_abi::TAG_U64_SMALL]
        );
    }

    #[test]
    fn an_effectful_callee_is_never_a_decode_helper() {
        // The `read_balance` shape: same silhouette, but it reads storage.
        // Eliding this would delete contract logic and still compile,
        // which is exactly why the effect gate exists.
        let mut func = u64_decode_helper();
        let storage = Expr::Semantic(SemanticOp::Known(KnownOp::GetLedgerSequence));
        func.bindings.get_mut(v(3)).unwrap().expr = storage;
        assert!(
            classify(&func).is_none(),
            "an effectful body must not be classified as marshalling"
        );
    }

    #[test]
    fn a_payload_not_derived_from_the_argument_declines() {
        let mut func = u64_decode_helper();
        // Ok arm A now yields a constant instead of decoding the argument.
        func.bindings.get_mut(v(3)).unwrap().expr = Expr::Literal(Literal::I64(42));
        assert!(
            classify(&func).is_none(),
            "a payload that does not come from the argument is not a decode"
        );
    }

    #[test]
    fn a_piecewise_unwrap_is_not_a_scalar_decode() {
        // `obj_to_i128_hi64` yields one limb of a 128-bit value. Accepting
        // it here would collapse an i128 argument to half of itself.
        let mut func = u64_decode_helper();
        func.bindings.get_mut(v(3)).unwrap().expr =
            Expr::Semantic(SemanticOp::Known(KnownOp::ValObject {
                kind: ValObjectKind::ObjToI128Hi64,
                args: vec![v(1)],
            }));
        assert!(classify(&func).is_none(), "a limb extractor is not a whole decode");
    }

    /// The hello-add `add` entrypoint calling the helper twice through one
    /// frame — the case that makes emission order load-bearing.
    fn caller(param_ty: PrimitiveType) -> HighFunction {
        let mut func = func_with(
            vec![
                Expr::Phi { incoming: vec![] },  // v0 frame pointer
                Expr::Phi { incoming: vec![] },  // v1 param `a`
                Expr::Phi { incoming: vec![] },  // v2 param `b`
                Expr::Call { target: FuncId::from_index(0), args: vec![v(0), v(1)] }, // v3
                load(v(0), 0),                   // v4 disc  (first call)
                load(v(0), 8),                   // v5 value (first call) → a
                Expr::Call { target: FuncId::from_index(0), args: vec![v(0), v(2)] }, // v6
                load(v(0), 0),                   // v7 disc  (second call)
                load(v(0), 8),                   // v8 value (second call) → b
                Expr::Binary { op: BinaryOp::Add, lhs: v(5), rhs: v(8) }, // v9
            ],
            vec![v(1), v(2)],
            vec![3, 4, 5, 6, 7, 8, 9],
        );
        func.id = FuncId::from_index(1);
        func.signature = Some(FunctionSignature {
            name: "add".to_string(),
            inputs: vec![
                FunctionParam { name: "a".to_string(), ty: TypeRef::Primitive(param_ty) },
                FunctionParam { name: "b".to_string(), ty: TypeRef::Primitive(param_ty) },
            ],
            outputs: vec![TypeRef::Primitive(param_ty)],
        });
        func
    }

    fn helpers() -> HashMap<FuncId, DecodeHelper> {
        let mut m = HashMap::new();
        m.insert(FuncId::from_index(0), classify(&u64_decode_helper()).unwrap());
        m
    }

    #[test]
    fn each_load_binds_to_the_call_that_produced_it() {
        let func = caller(PrimitiveType::U64);
        let (elisions, _) = plan(&func, &helpers());
        let by_id: HashMap<ValueId, &Expr> =
            elisions.iter().map(|e| (e.id, &e.expr)).collect();

        // The first call's payload is `a`, the second's is `b` — the whole
        // point of walking in emission order.
        assert!(matches!(by_id.get(&v(5)), Some(Expr::Use(p)) if *p == v(1)));
        assert!(matches!(by_id.get(&v(8)), Some(Expr::Use(p)) if *p == v(2)));
        // Both discriminants are Ok.
        assert!(matches!(by_id.get(&v(4)), Some(Expr::Literal(Literal::I32(0)))));
        assert!(matches!(by_id.get(&v(7)), Some(Expr::Literal(Literal::I32(0)))));
        // Both calls are neutralised.
        assert!(matches!(by_id.get(&v(3)), Some(Expr::Literal(Literal::Unit))));
        assert!(matches!(by_id.get(&v(6)), Some(Expr::Literal(Literal::Unit))));
    }

    #[test]
    fn a_declared_type_that_disagrees_with_the_tags_declines() {
        // The helper tests U64 tags; the spec says the argument is an
        // Address. Something is wrong with our picture, so elide nothing.
        let func = caller(PrimitiveType::Address);
        let (elisions, _) = plan(&func, &helpers());
        assert!(elisions.is_empty(), "a tag/type disagreement must elide nothing");
    }

    #[test]
    fn a_helper_call_outside_an_entrypoint_is_left_alone() {
        // The collapse rests on the host having validated the argument
        // against the spec, which is only true for an ABI entrypoint.
        let mut func = caller(PrimitiveType::U64);
        func.signature = None;
        let (elisions, _) = plan(&func, &helpers());
        assert!(elisions.is_empty(), "only entrypoint parameters carry the guarantee");
    }

    #[test]
    fn second_run_reports_no_work() {
        let mut func = caller(PrimitiveType::U64);
        let helpers = helpers();
        let (first, _) = plan(&func, &helpers);
        assert!(!first.is_empty());
        apply_elisions(&mut func, PASS_NAME, first);
        let (second, _) = plan(&func, &helpers);
        assert!(second.is_empty(), "idempotent: the loads and calls are gone");
    }
}

/// Coverage accounting over the real corpus — what the elision *could*
/// reach, and why it declined the rest.
///
/// Not a lock. It exists because a pass that silently declines is
/// indistinguishable from a pass that has nothing to do, and the
/// difference is the entire remaining work list. Run it to size that
/// list:
///
///   cargo test -p sordec-passes --lib -- --ignored --nocapture sret_candidate_census
#[cfg(test)]
mod census {
    use super::*;
    use crate::marshalling::sret;
    use sordec_common::IrId as _;

    const FIXTURES: &[(&str, &[u8])] = &[
        ("hello-add", include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../samples/contracts/hello-add/hello-add.wasm"
        ))),
        ("token-v23", include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../samples/contracts/token-v23/token-v23.wasm"
        ))),
        ("timelock", include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../samples/contracts/timelock/timelock.wasm"
        ))),
        ("dex-liquidity-pool", include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../samples/contracts/dex-liquidity-pool/dex-liquidity-pool.wasm"
        ))),
        ("attestation", include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../samples/contracts/attestation/attestation.wasm"
        ))),
    ];

    fn build(wasm: &[u8]) -> sordec_ir::HighIr {
        use crate::lowering::LoweringStep as _;
        let parsed = sordec_frontend::parse(wasm).expect("parses");
        let mut lifted =
            crate::lift_with_waffle(wasm, &parsed.wasm_facts, parsed.soroban_facts.as_ref())
                .expect("lifts")
                .lifted;
        crate::default_lifted_pipeline().run(&mut lifted);
        let mut high = crate::LiftToHigh.lower(lifted).expect("lowers");
        crate::default_high_pipeline().run(&mut high);
        high
    }

    #[test]
    #[ignore = "diagnostic census over the corpus; run explicitly"]
    #[allow(clippy::print_stdout)]
    fn sret_candidate_census() {
        for (name, wasm) in FIXTURES {
            let high = build(wasm);
            let (mut helpers, mut wide, mut declined, mut not_sret) = (0, 0, 0, 0);
            let mut reasons: Vec<String> = Vec::new();

            for func in &high.functions {
                let Some(shape) = sret::analyze(func) else {
                    not_sret += 1;
                    continue;
                };
                if classify(func).is_some() {
                    helpers += 1;
                    continue;
                }
                // An sret shape we did not classify as marshalling. The
                // interesting bucket: these are the wide returns the
                // generalization has to reconstruct.
                let host = !touches_no_host_state(func, &shape);
                if host {
                    wide += 1;
                } else {
                    declined += 1;
                }
                reasons.push(format!(
                    "    func{:<3} slots={:?} params={} {}",
                    func.id.index(),
                    shape.slots.keys().collect::<Vec<_>>(),
                    func.params.len(),
                    if host { "touches host state -> WIDE RETURN" } else { "pure but unclassified" },
                ));
            }
            println!(
                "{name}: {} fns | {helpers} decode helper(s) | {wide} wide-return | \
                 {declined} pure-unclassified | {not_sret} not an sret shape",
                high.functions.len()
            );
            for reason in &reasons {
                println!("{reason}");
            }
        }
    }
}
