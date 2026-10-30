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
//! ## Two shapes, one meaning
//!
//! The silhouette above is untouched rustc output. [`crate::SretReturnPass`]
//! converts it at the lifted layer — out-parameter back into a real
//! multi-value return — so once that pass is wired the same helper arrives
//! looking like this instead, and the caller reads its halves as
//! [`Expr::Project`]s rather than loads:
//!
//! ```text
//! callee:  return (disc, payload)
//! caller:  t = decode(a);  t.0 ← discriminant;  t.1 ← payload
//! ```
//!
//! Both are recognized. The conversion cannot reach every helper (its own
//! gates decline some), so a module can hold both at once, and a pass that
//! understood only one would silently stop eliding whatever it converted —
//! emitting SDK glue as though the contract's author had written it.
//! [`HelperShape`] is the two-way split; every gate that decides
//! *marshalling versus logic* sits below it in [`decoding_tags`], shared.
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
//! - **Entry parameters, and helper parameters that only ever receive
//!   one.** The collapse rests on the ABI guarantee that the host already
//!   validated this value against the spec. That guarantee exists for an
//!   entrypoint parameter, and it survives a helper every one of whose
//!   callers hands it such a parameter untouched — the wrapper the compiler
//!   outlines around an entrypoint's body keeps the host's validation.
//!   [`guaranteed_params`] is that reading, module-wide; it needs the
//!   helper's callers to all be visible (not exported, not held by the
//!   function table when the module calls through one) and to agree.
//!   Nothing else carries the guarantee.

use std::collections::{HashMap, HashSet};

use sordec_common::{FuncId, ValueId};
use sordec_ir::{
    BinaryOp, BufOpKind, Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Literal, Region, SemanticOp,
    ValObjectKind,
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

/// How a helper hands its `Result` back, and therefore where the caller
/// reads it from.
///
/// Both shapes describe the *same* SDK glue. Which one a given helper
/// wears depends only on whether [`crate::SretReturnPass`] has run at the
/// lifted layer: it converts the out-parameter into a real multi-value
/// return, and cannot convert every helper (its own gates decline some),
/// so a module can contain both at once.
#[derive(Debug, Clone)]
enum HelperShape {
    /// Untouched rustc output: results are written through a
    /// caller-allocated pointer, and the caller reads them back with two
    /// `Load`s at these offsets.
    OutParam {
        /// Position of the out-pointer in the parameter list, so a caller
        /// matches arguments positionally rather than assuming a layout.
        out_index: usize,
        /// Slot holding the `Result` discriminant (`0` = Ok).
        disc_offset: u32,
        /// Slot holding the decoded payload.
        payload_offset: u32,
    },
    /// Post-conversion: results are the return's components, and the
    /// caller reads them with [`Expr::Project`].
    MultiValue {
        /// Component index of the `Result` discriminant.
        disc_index: usize,
        /// Component index of the decoded payload.
        payload_index: usize,
    },
    /// `T::try_from_val(env, val).ok()`: the helper hands back an `Option`,
    /// `Some` of its argument on the path where the tag check passed and
    /// `None` otherwise — the shape [`super::optional_out`] leaves behind.
    /// Its call sites keep the `Option`: a guaranteed argument makes it
    /// `Some(arg)`, any other keeps the call, typed `Option<T>`.
    Optional {
        /// The payload type every tag the helper tests names, when the
        /// tags name exactly one host object: a `BytesObject` may carry a
        /// `Bytes` or any `BytesN<N>`, a `VecObject` a `Vec<T>` or a
        /// `#[contracttype]`, and a word's `Some` still holds the raw `Val`
        /// until a decode unpacks it; then only a declared type at the
        /// call site can say what the value is.
        payload: Option<KnownType>,
        /// The `Some` bindings in the helper's own body, typed `Option<T>`
        /// too so the helper's return agrees with its call sites.
        some_arms: Vec<ValueId>,
    },
}

/// A helper proven to be nothing but `T::try_from_val(env, val)`.
#[derive(Debug, Clone)]
pub(crate) struct DecodeHelper {
    /// Where the results live; see [`HelperShape`].
    shape: HelperShape,
    /// Position of the `Val` being decoded in the parameter list.
    val_index: usize,
    /// Number of parameters a call site must pass, which differs between
    /// the two shapes because the converted form has no out-pointer.
    arity: usize,
    /// Every tag the helper tests, so the caller can check them against
    /// the declared parameter type.
    tags: Vec<u8>,
}

impl DecodeHelper {
    /// Which argument a call site hands the `Val` being decoded.
    pub(crate) fn val_index(&self) -> usize {
        self.val_index
    }

    /// Every tag this helper tests — what the decoded value's declared
    /// type has to agree with, and, where there is no declaration,
    /// what it is.
    pub(crate) fn tags(&self) -> &[u8] {
        &self.tags
    }
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

        // Helper parameters that carry an entrypoint's guarantee, read
        // once over the whole module before any function changes.
        let guaranteed = guaranteed_params(ir, &helpers);

        // No early return on an empty helper set: an inline decode (SDK 27)
        // needs no helper, and `plan` collapses those too.
        for func in &mut ir.functions {
            let (elisions, metrics) = plan(func, &helpers, &guaranteed);
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
///
/// The two shapes differ only in where the `Result` components are found —
/// caller memory, or the return's operands. Everything that *decides*
/// marshalling-versus-logic (no host state, every Ok payload traces to the
/// `Val` parameter, at least one tag tested) is shared below, so the two
/// paths cannot drift apart on the question that matters.
pub(crate) fn classify(func: &HighFunction) -> Option<DecodeHelper> {
    classify_out_param(func)
        .or_else(|| classify_multi_value(func))
        .or_else(|| classify_optional(func))
}

/// The untouched rustc shape: results written through an out-pointer.
fn classify_out_param(func: &HighFunction) -> Option<DecodeHelper> {
    let shape = sret::analyze(func)?;
    // Exactly `(out, val)`: a decode reads one Val and writes one Result.
    if func.params.len() != 2 || shape.slots.len() != 2 {
        return None;
    }
    // The parameter that is not the out-pointer is the Val being decoded.
    let val_index = 1 - shape.out_index;
    let val_param = func.params[val_index];

    if !touches_no_host_state(func, &shape.store_bindings) {
        return None;
    }

    let (disc_offset, payload_offset) = discriminant_and_payload(func, &shape)?;
    let disc = shape.slot(disc_offset)?;
    let payload = shape.slot(payload_offset)?;

    let tags = decoding_tags(func, val_param, arms(func, disc, payload)?)?;

    Some(DecodeHelper {
        shape: HelperShape::OutParam {
            out_index: shape.out_index,
            disc_offset,
            payload_offset,
        },
        val_index,
        arity: 2,
        tags,
    })
}

/// The converted shape: results are the components of a multi-value
/// return, because [`crate::SretReturnPass`] has already run.
///
/// Note the parameter count differs from [`classify_out_param`]'s — the
/// out-pointer is gone, so a decode helper here takes exactly the one
/// `Val` it decodes.
fn classify_multi_value(func: &HighFunction) -> Option<DecodeHelper> {
    let shape = sret::analyze_returns(func)?;
    if func.params.len() != 1 || shape.arity() != 2 {
        return None;
    }
    let val_param = func.params[0];

    // No stores to exempt: this shape has none.
    if !touches_no_host_state(func, &[]) {
        return None;
    }

    let disc_index = discriminant_component(func, &shape)?;
    let payload_index = 1 - disc_index;

    // One arm per return site, already paired — no phi walk needed, and
    // no cross-product to guard against.
    let paired: Vec<(ValueId, ValueId)> = shape
        .arms
        .iter()
        .map(|arm| (arm[disc_index], arm[payload_index]))
        .collect();
    let tags = decoding_tags(func, val_param, paired)?;

    Some(DecodeHelper {
        shape: HelperShape::MultiValue {
            disc_index,
            payload_index,
        },
        val_index: 0,
        arity: 1,
        tags,
    })
}

/// The `Option` shape: every return is `None`, or `Some` of a value that
/// comes from the one tag-checked parameter through decode operations
/// only, the helper touches no host state, and every tag it tests names
/// one payload type. The parameters beside the `Val` (an `Env` pointer,
/// scratch) are left alone: the call keeps them.
///
/// One host read is allowed: the length of the value being decoded, when
/// every `Some` sits on the side of a test `len == N` where it holds. That
/// is `BytesN::<N>::try_from_val(env, val).ok()` — the SDK converts to
/// `Bytes` (the tag check) and then accepts exactly the length `N` — so
/// the payload is a `BytesN<N>`, the one case where a bytes object's tag
/// alone could not say which type it is. A length read for anything else
/// is not this shape.
fn classify_optional(func: &HighFunction) -> Option<DecodeHelper> {
    if func.signature.is_some() {
        return None;
    }
    // The return sites as the region has them, like `analyze_returns`.
    let mut returns: Vec<Vec<ValueId>> = Vec::new();
    func.region.for_each_node(|node| {
        if let Region::Return { values } = node {
            returns.push(values.clone());
        }
    });
    if returns.is_empty() {
        return None;
    }
    let checked: Vec<usize> = (0..func.params.len())
        .filter(|i| !tested_tags(func, func.params[*i]).is_empty())
        .collect();
    let [val_index] = checked.as_slice() else {
        return None;
    };
    let val_param = func.params[*val_index];
    let lengths: Vec<ValueId> = sret::emission_order(func)
        .into_iter()
        .filter(|id| {
            matches!(
                func.bindings.get(*id).map(|b| &b.expr),
                Some(Expr::Semantic(SemanticOp::Known(KnownOp::BufOp { kind: BufOpKind::BytesLen, args })))
                    if args.len() == 1 && resolve_use(func, args[0]) == val_param
            )
        })
        .collect();
    let length = match lengths.as_slice() {
        [] => None,
        [one] => Some(*one),
        _ => return None,
    };
    if !touches_no_host_state(func, &lengths) {
        return None;
    }
    let mut some_arms = Vec::new();
    for values in &returns {
        let [value] = values.as_slice() else {
            return None;
        };
        for arm in arms_of(func, *value)? {
            let id = resolve_use(func, arm);
            match &func.bindings.get(id)?.expr {
                Expr::Optional { payload: None } => {}
                Expr::Optional { payload: Some(items) } => {
                    let [p] = items.as_slice() else {
                        return None;
                    };
                    if !decodes_to(func, *p, val_param, TRACE_DEPTH) {
                        return None;
                    }
                    some_arms.push(id);
                }
                _ => return None,
            }
        }
    }
    if some_arms.is_empty() {
        return None;
    }
    let tags = tested_tags(func, val_param);
    if tags.is_empty() {
        return None;
    }
    // The length gate, when there is a length read: only on a bytes object,
    // and only when it guards every `Some`.
    let fixed_length = match length {
        None => None,
        Some(len) if tags == [val_abi::TAG_BYTES_OBJECT] => Some(checked_length(func, len, &some_arms)?),
        Some(_) => return None,
    };
    let mut payload: Option<KnownType> = None;
    for tag in &tags {
        let named = val_abi::tag_payload_type(*tag)?;
        match &payload {
            None => payload = Some(named),
            Some(have) if *have == named => {}
            Some(_) => return None,
        }
    }
    // Only a tag that names one type can type the `Option` on its own, and
    // only a host object is the type its tag names as it stands: a word's
    // `Some` holds the raw `Val` until a decode operation unpacks it, and
    // that decode, not a type, is what the caller then needs.
    let ambiguous = tags
        .iter()
        .any(|t| matches!(*t, val_abi::TAG_BYTES_OBJECT | val_abi::TAG_VEC_OBJECT | val_abi::TAG_MAP_OBJECT));
    let host_object = payload.as_ref().is_some_and(|p| {
        matches!(p, KnownType::Address | KnownType::MuxedAddress | KnownType::Symbol | KnownType::String)
    });
    let payload = match fixed_length {
        Some(n) => Some(KnownType::BytesN(n)),
        None if ambiguous || !host_object => None,
        None => payload,
    };
    Some(DecodeHelper {
        shape: HelperShape::Optional { payload, some_arms },
        val_index: *val_index,
        arity: func.params.len(),
        tags,
    })
}

/// The `N` a length gate fixes: a test of `len` against the constant `N`
/// whose holding side — the `then` of `len == N`, the `else` of
/// `len != N` — contains every one of `some_arms`.
fn checked_length(func: &HighFunction, len: ValueId, some_arms: &[ValueId]) -> Option<u32> {
    let mut found = None;
    func.region.for_each_node(|node| {
        let Region::If { cond, then_region, else_region } = node else {
            return;
        };
        let Some(Expr::Binary { op: op @ (BinaryOp::Eq | BinaryOp::Ne), lhs, rhs }) =
            func.bindings.get(resolve_use(func, *cond)).map(|b| &b.expr)
        else {
            return;
        };
        let (l, r) = (resolve_use(func, *lhs), resolve_use(func, *rhs));
        let constant = if l == len {
            trace_int(func, r)
        } else if r == len {
            trace_int(func, l)
        } else {
            return;
        };
        let Some(n) = constant.and_then(|n| u32::try_from(n).ok()) else {
            return;
        };
        let holds = if *op == BinaryOp::Eq { Some(&**then_region) } else { else_region.as_deref() };
        let Some(holds) = holds else {
            return;
        };
        let mut inside: HashSet<ValueId> = HashSet::new();
        holds.for_each_node(|n| {
            if let Region::Basic(block) = n
                && let Some(b) = func.blocks.get(*block)
            {
                inside.extend(b.bindings.iter().copied());
            }
        });
        if some_arms.iter().all(|a| inside.contains(a)) {
            found = Some(n);
        }
    });
    found
}

/// The shared decision: every arm is an `Ok` whose payload traces back to
/// `val_param`, or an `Err` carrying a constant, and the helper tests at
/// least one tag. Returns those tags.
///
/// This is the gate that separates SDK glue from a real wide-returning
/// contract function, so both shapes route through it rather than each
/// re-deriving it.
fn decoding_tags(
    func: &HighFunction,
    val_param: ValueId,
    arms: Vec<(ValueId, ValueId)>,
) -> Option<Vec<u8>> {
    let mut saw_ok = false;
    for (disc_value, payload_value) in arms {
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
    Some(tags)
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
fn touches_no_host_state(func: &HighFunction, exempt: &[ValueId]) -> bool {
    // Emitted bindings only, for the same reason [`sret::analyze`] scans
    // that set: unscheduled de-cluttering residue never runs.
    sret::emission_order(func).into_iter().all(|id| {
        // The shape's own out-parameter stores, where it has any. The
        // multi-value shape passes an empty set — its components are
        // return operands, so there is nothing to write past.
        if exempt.contains(&id) {
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

/// Which component of a multi-value return is the discriminant.
///
/// Same evidence as [`discriminant_and_payload`] and for the same reason —
/// the discriminant is the one that is a small flag on every arm, and
/// which component that is remains rustc's choice, not ours. Decided here
/// over the arm rows directly, because this shape has no phi to consult.
fn discriminant_component(func: &HighFunction, shape: &sret::ReturnShape) -> Option<usize> {
    let is_flag = |index: usize| -> bool {
        shape.component(index).is_some_and(|values| {
            values
                .iter()
                .all(|v| matches!(trace_int(func, *v), Some(0 | 1)))
        })
    };
    match (is_flag(0), is_flag(1)) {
        (true, false) => Some(0),
        (false, true) => Some(1),
        // Both or neither look like a discriminant — no honest answer.
        _ => None,
    }
}

/// Whether every arm of `value` resolves to `0` or `1`.
///
/// **An empty arm set is not evidence.** `arms_of` returns `Some(vec![])`
/// for a zero-incoming phi, which is what an entrypoint parameter is at
/// this layer, and `[].iter().all(..)` is vacuously `true`. That made a
/// parameter indistinguishable from a discriminant, so
/// [`discriminant_and_payload`] saw `(true, true)` and declined every
/// helper whose payload slot holds its own `Val` argument unchanged —
/// exactly the `BytesN<N>::try_from_val` shape, which validates and passes
/// through rather than unwrapping. `attestation`'s `func_2`, shared by
/// `attest.signer` and `check.claimed`, is the witness.
fn all_arms_are_flags(func: &HighFunction, value: ValueId) -> bool {
    match arms_of(func, value) {
        Some(values) if !values.is_empty() => values
            .iter()
            .all(|v| matches!(trace_int(func, *v), Some(0 | 1))),
        _ => false,
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
    let payload_id = resolve_use(func, payload);
    let payload_expr = &func.bindings.get(payload_id)?.expr;
    // A parameter is one value on every path, though this layer spells it
    // as a phi with no incoming edges. `BytesN<N>::try_from_val` validates
    // its argument and passes it through unchanged, so its payload slot
    // holds exactly that.
    if func.params.contains(&payload_id)
        && let Expr::Phi { incoming: d } = disc_expr
    {
        return Some(d.iter().map(|(_, dv)| (*dv, payload_id)).collect());
    }
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

/// Which half of a decode's `Result` a caller is reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Half {
    Discriminant,
    Payload,
}

/// The elision that rebinds one half of a decode result.
///
/// Shared by all three sites that can read one — a `Load` from the frame,
/// a `Project` of a converted call, and a `Load` of a slot the converted
/// caller re-stored — so the provenance note and the metric cannot drift
/// between the two shapes.
fn rebind(id: ValueId, ty: &IrType, half: Half, act: &Active) -> Elision {
    match half {
        Half::Discriminant => Elision {
            id,
            expr: Expr::Literal(ok_discriminant(ty)),
            ty: None,
            note: "decode-result discriminant is Ok: the host validated \
                   this argument against contractspecv0 before dispatch"
                .to_string(),
            metric: metrics::DECODE_COLLAPSED,
        },
        Half::Payload => Elision {
            id,
            expr: Expr::Use(act.param),
            ty: Some(IrType::Known(act.declared.clone())),
            note: format!(
                "argument decode collapsed to its parameter ({})",
                tag_list(&act.helper.tags)
            ),
            metric: metrics::DECODE_COLLAPSED,
        },
    }
}

/// Which half a helper's component index or slot offset denotes, or
/// `None` for anything the shape does not account for.
fn half_of(helper: &DecodeHelper, key: SlotKey) -> Option<Half> {
    match (&helper.shape, key) {
        (
            HelperShape::OutParam {
                disc_offset,
                payload_offset,
                ..
            },
            SlotKey::Offset(offset),
        ) => {
            if offset == *disc_offset {
                Some(Half::Discriminant)
            } else if offset == *payload_offset {
                Some(Half::Payload)
            } else {
                None
            }
        }
        (
            HelperShape::MultiValue {
                disc_index,
                payload_index,
            },
            SlotKey::Component(index),
        ) => {
            if index == *disc_index {
                Some(Half::Discriminant)
            } else if index == *payload_index {
                Some(Half::Payload)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// How a caller addressed the half it is reading.
#[derive(Debug, Clone, Copy)]
enum SlotKey {
    /// Byte offset into the frame — the out-parameter shape.
    Offset(u32),
    /// Return component index — the converted shape.
    Component(usize),
}

/// Plan every collapse in one caller.
fn plan(
    func: &HighFunction,
    helpers: &HashMap<FuncId, DecodeHelper>,
    guaranteed: &Guaranteed,
) -> (Vec<Elision>, PassMetrics) {
    let mut elisions = Vec::new();
    let mut metrics = PassMetrics::new();
    // An `Option`-shaped decoder's own `Some` arms, typed as its call sites
    // will be.
    if let Some(helper) = helpers.get(&func.id)
        && let HelperShape::Optional { payload: Some(payload), some_arms } = &helper.shape
    {
        let ty = IrType::Inferred(KnownType::Option(Box::new(IrType::Inferred(payload.clone()))));
        for arm in some_arms {
            if let Some(binding) = func.bindings.get(*arm)
                && binding.ty != ty
            {
                elisions.push(Elision {
                    id: *arm,
                    expr: binding.expr.clone(),
                    ty: Some(ty.clone()),
                    note: format!(
                        "`Some` of a value whose tag this helper checked: the payload is the {} the tag names",
                        tag_list(&helper.tags)
                    ),
                    metric: metrics::DECODE_OPTION_TYPED,
                });
            }
        }
    }
    // Only an entrypoint carries the ABI guarantee the collapse rests on —
    // or a helper handed nothing but an entrypoint's parameters. The other
    // functions still see what an `Option`-shaped decoder hands back.
    if func.signature.is_none() && !guaranteed.keys().any(|(f, _)| *f == func.id) {
        for id in sret::emission_order(func) {
            let Some(Expr::Call { target, args }) = func.bindings.get(id).map(|b| &b.expr) else {
                continue;
            };
            if let Some(helper) = helpers.get(target)
                && let HelperShape::Optional { payload, .. } = &helper.shape
                && args.len() == helper.arity
                && let Claimed::Elided(el) =
                    optional_call(func, id, *target, args, payload.clone(), helper, guaranteed)
            {
                elisions.push(el);
            }
        }
        elisions.extend(host_decodes(func));
        for el in &elisions {
            metrics.increment(el.metric, 1);
        }
        return (elisions, metrics);
    }

    // Frame pointer → the decode currently occupying it. Walking in
    // emission order matters: hello-add decodes two arguments through one
    // 16-byte frame, so the loads after the second call must bind to the
    // second call, not the first.
    let mut active: HashMap<ValueId, Active> = HashMap::new();
    // Converted helpers hand their results back as `Project`s, so those
    // are tracked by the call's own id — no frame, and therefore none of
    // the aliasing bookkeeping the out-parameter shape needs.
    let mut by_call: HashMap<ValueId, Active> = HashMap::new();
    // `SretReturnPass` leaves the caller's stores in place, so a converted
    // decode still writes its components into the frame and may read them
    // back. This records which half each written slot holds, so those
    // read-backs collapse too — `SlotPromotionPass` forwards the payload
    // but declines the discriminant, whose i64 store is read as an i32.
    let mut restored: HashMap<(ValueId, u32), (ValueId, Half)> = HashMap::new();
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
                let (invalidate, claimed) = on_call(func, helpers, &active, id, *target, args, guaranteed);
                for frame in invalidate {
                    finished.extend(active.remove(&frame));
                    restored.retain(|(f, _), _| *f != frame);
                }
                match claimed {
                    Claimed::Frame(frame, act) => {
                        finished.extend(active.insert(frame, act));
                    }
                    Claimed::Call(act) => {
                        by_call.insert(id, act);
                    }
                    Claimed::Elided(el) => elisions.push(el),
                    Claimed::None => {}
                }
            }
            // A converted call's results, read straight out of SSA.
            Expr::Project { value, index } => {
                let call = resolve_use(func, *value);
                let Some(act) = by_call.get_mut(&call) else {
                    continue;
                };
                if let Some(half) = half_of(&act.helper, SlotKey::Component(*index as usize)) {
                    act.consumed = true;
                    elisions.push(rebind(id, &binding.ty, half, act));
                }
            }
            Expr::Load { addr, offset, .. } => {
                let frame = resolve_use(func, *addr);
                // A slot the converted caller wrote its own component into.
                if let Some((call, half)) = restored.get(&(frame, *offset))
                    && let Some(act) = by_call.get_mut(call)
                {
                    act.consumed = true;
                    elisions.push(rebind(id, &binding.ty, *half, act));
                    continue;
                }
                let Some(act) = active.get_mut(&frame) else {
                    continue;
                };
                match half_of(&act.helper, SlotKey::Offset(*offset)) {
                    Some(half) => {
                        act.consumed = true;
                        elisions.push(rebind(id, &binding.ty, half, act));
                    }
                    // A slot we did not account for — our picture of this
                    // frame is incomplete, so stop trusting it.
                    None => finished.extend(active.remove(&frame)),
                }
            }
            Expr::Store {
                addr,
                value,
                offset,
                ..
            } => {
                let frame = resolve_use(func, *addr);
                // The re-store `SretReturnPass` leaves behind: bookkeeping
                // for a value that is already in SSA. Recording which half
                // it holds is what lets the read-back collapse; the store
                // itself becomes dead once nothing reads the slot.
                if let Some((call, half)) = projected_half(func, &by_call, *value) {
                    restored.insert((frame, *offset), (call, half));
                    elisions.push(Elision {
                        id,
                        expr: Expr::Literal(Literal::Unit),
                        ty: Some(IrType::Known(KnownType::Unit)),
                        note: "shadow-stack write-back of a decode result already \
                               recovered as a return value"
                            .to_string(),
                        metric: metrics::DECODE_COLLAPSED,
                    });
                    continue;
                }
                // Any other write through a tracked frame invalidates it.
                finished.extend(active.remove(&frame));
                restored.retain(|(f, _), _| *f != frame);
            }
            _ => {}
        }
    }
    finished.extend(by_call.into_values());

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
    elisions.extend(inline_decodes(func, guaranteed));
    elisions.extend(host_decodes(func));
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
    guaranteed: &Guaranteed,
) -> (Vec<ValueId>, Claimed) {
    let mut invalidate: Vec<ValueId> = args
        .iter()
        .map(|a| resolve_use(func, *a))
        .filter(|a| active.contains_key(a))
        .collect();

    let Some(helper) = helpers.get(&target) else {
        return (invalidate, Claimed::None);
    };
    if args.len() != helper.arity {
        return (invalidate, Claimed::None);
    }
    if let HelperShape::Optional { payload, .. } = &helper.shape {
        return (invalidate, optional_call(func, id, target, args, payload.clone(), helper, guaranteed));
    }
    let actual = resolve_use(func, args[helper.val_index]);
    let Some(declared) = abi_param_type(func, actual, guaranteed) else {
        return (invalidate, Claimed::None);
    };
    // Every tag the helper tests must be able to *carry* the declared
    // type. `tag_carries` rather than `tag_payload_type == declared`: a
    // `BytesN<N>` argument arrives in a plain `BytesObject`, so the tag
    // denotes `Bytes` while the declaration says `BytesN(N)`, and equality
    // would reject a helper that agrees with us perfectly.
    if !helper.tags.iter().all(|t| val_abi::tag_carries(*t, &declared)) {
        return (invalidate, Claimed::None);
    }
    let act = Active {
        call: id,
        param: actual,
        declared,
        helper: helper.clone(),
        consumed: false,
    };
    match helper.shape {
        HelperShape::OutParam { out_index, .. } => {
            let frame = resolve_use(func, args[out_index]);
            // This call now owns the frame, so it must not also be
            // invalidated.
            invalidate.retain(|f| *f != frame);
            (invalidate, Claimed::Frame(frame, act))
        }
        // No frame to claim: the results come back in SSA.
        HelperShape::MultiValue { .. } => (invalidate, Claimed::Call(act)),
        // Handled above, where the call is rewritten on the spot.
        HelperShape::Optional { .. } => (invalidate, Claimed::None),
    }
}

/// What a call to an `Option`-shaped decoder becomes: `Some` of its
/// argument where the argument carries the ABI guarantee and every tag the
/// helper tests carries that type; otherwise the call it is, typed as the
/// `Option<T>` the tags name, so the value it hands back is the `T` the
/// caller then uses.
fn optional_call(
    func: &HighFunction,
    id: ValueId,
    target: FuncId,
    args: &[ValueId],
    payload: Option<KnownType>,
    helper: &DecodeHelper,
    guaranteed: &Guaranteed,
) -> Claimed {
    let option = |k: KnownType| IrType::Inferred(KnownType::Option(Box::new(IrType::Inferred(k))));
    let actual = resolve_use(func, args[helper.val_index]);
    if let Some(declared) = abi_param_type(func, actual, guaranteed)
        && helper.tags.iter().all(|t| val_abi::tag_carries(*t, &declared))
    {
        return Claimed::Elided(Elision {
            id,
            expr: Expr::Optional { payload: Some(vec![actual]) },
            ty: Some(option(declared)),
            note: format!(
                "argument decode collapsed to `Some` of its parameter ({})",
                tag_list(&helper.tags)
            ),
            metric: metrics::DECODE_COLLAPSED,
        });
    }
    let Some(payload) = payload else {
        return Claimed::None;
    };
    // A value the module has proved to be the payload already — a field of
    // a recovered struct, which the struct's own derive checked against its
    // declaration — passes every check the helper makes: the call is `Some`
    // of it.
    if matches!(func.bindings.get(actual).map(|b| &b.ty), Some(IrType::Known(k)) if *k == payload) {
        return Claimed::Elided(Elision {
            id,
            expr: Expr::Optional { payload: Some(vec![actual]) },
            ty: Some(option(payload)),
            note: format!(
                "decode of a value already proven to be the payload ({}): `Some` of it",
                tag_list(&helper.tags)
            ),
            metric: metrics::DECODE_COLLAPSED,
        });
    }
    let ty = option(payload);
    if func.bindings.get(id).is_some_and(|b| b.ty == ty) {
        return Claimed::None;
    }
    Claimed::Elided(Elision {
        id,
        expr: Expr::Call { target, args: args.to_vec() },
        ty: Some(ty),
        note: format!("the `Option` a decoder hands back, typed by the tags it tests ({})", tag_list(&helper.tags)),
        metric: metrics::DECODE_OPTION_TYPED,
    })
}

/// What a call claims when it is itself an elidable decode.
enum Claimed {
    /// Not a decode we can collapse.
    None,
    /// Rewritten on the spot: an `Option`-shaped decoder's call.
    Elided(Elision),
    /// Out-parameter shape: this call now owns the given frame pointer.
    Frame(ValueId, Active),
    /// Converted shape: tracked by the call's own id.
    Call(Active),
}

/// When `value` is a `Project` of a tracked converted decode, which call
/// it came from and which half it is.
fn projected_half(
    func: &HighFunction,
    by_call: &HashMap<ValueId, Active>,
    value: ValueId,
) -> Option<(ValueId, Half)> {
    let id = resolve_use(func, value);
    let Expr::Project { value: call, index } = &func.bindings.get(id)?.expr else {
        return None;
    };
    let call = resolve_use(func, *call);
    let act = by_call.get(&call)?;
    Some((call, half_of(&act.helper, SlotKey::Component(*index as usize))?))
}

/// The decode written inline rather than through a helper.
///
/// SDK 27 unpacks a `u32` argument where it is used: the tag check (which
/// [`super::guard`] removes) and a shift, `val_decode(a)`, with no call to
/// collapse. For a parameter `contractspecv0` declares `u32` or `i32` the
/// shift *is* the conversion the regenerated wrapper performs — those two
/// types have one encoding, whose payload is the high word — so the decode
/// is the parameter.
fn inline_decodes(func: &HighFunction, guaranteed: &Guaranteed) -> Vec<Elision> {
    sret::emission_order(func)
        .into_iter()
        .filter_map(|id| {
            let Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { value })) = &func.bindings.get(id)?.expr else {
                return None;
            };
            // A host result's decode is `host_decodes`'s.
            if typed_host_u32(func, resolve_use(func, *value)).is_some() {
                return None;
            }
            let param = resolve_use(func, *value);
            let declared = abi_param_type(func, param, guaranteed)?;
            matches!(declared, KnownType::U32 | KnownType::I32).then(|| Elision {
                id,
                expr: Expr::Use(param),
                ty: Some(IrType::Known(declared)),
                note: "inline argument decode collapsed to its parameter".to_string(),
                metric: metrics::DECODE_COLLAPSED,
            })
        })
        .collect()
}

/// The decode of a host result the SDK hands back already typed —
/// `e.ledger().sequence()` is a `u32` — is that result: the
/// backend spells the typed call, so a decode after it would decode twice
/// (`sequence >> 32` on the `u32` the call returns is `0`). As a
/// `ValDecodeSmall`, or as the `>> 32` it inlines to. No ABI is needed, so
/// helpers too.
fn host_decodes(func: &HighFunction) -> Vec<Elision> {
    sret::emission_order(func)
        .into_iter()
        .filter_map(|id| {
            let value = match &func.bindings.get(id)?.expr {
                Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { value })) => *value,
                Expr::Binary { op: sordec_ir::BinaryOp::ShrU, lhs, rhs }
                    if crate::dataflow::trace_int(func, *rhs) == Some(32) =>
                {
                    *lhs
                }
                _ => return None,
            };
            let value = resolve_use(func, value);
            let ty = typed_host_u32(func, value)?;
            Some(Elision {
                id,
                expr: Expr::Use(value),
                ty: Some(IrType::Known(ty)),
                note: "decode of a host result the SDK returns already typed: the result".to_string(),
                metric: metrics::DECODE_COLLAPSED,
            })
        })
        .collect()
}

/// The `u32` a host operation's typed SDK call returns, when `value` is
/// one: the ledger sequence or protocol version.
///
/// Not yet a length (`bytes.len()`, `vec.len()`), though the same holds of
/// it. A length is what a loop counter is compared against, and the counter
/// starts from a constant typed by its wasm word (`0i64`); a `u32` length
/// leaves the counter untyped and costs more errors than the hole it
/// removes. Measured on the held-out set: 119 error lines without lengths,
/// 129 with. Lengths come in with loop-counter typing.
fn typed_host_u32(func: &HighFunction, value: ValueId) -> Option<KnownType> {
    let Expr::Semantic(SemanticOp::Known(op)) = &func.bindings.get(value)?.expr else {
        return None;
    };
    let ty = match op {
        KnownOp::GetLedgerSequence | KnownOp::GetLedgerProtocolVersion => KnownType::U32,
        _ => return None,
    };
    matches!(ty, KnownType::U32 | KnownType::I32).then_some(ty)
}

/// Helper parameters that carry an entrypoint's ABI guarantee, with the
/// declared type each one carries. See [`guaranteed_params`].
type Guaranteed = HashMap<(FuncId, usize), KnownType>;

/// The `contractspecv0` type a helper's parameter is guaranteed to hold:
/// every call site hands it, untouched, an entrypoint's own declared
/// parameter — or a parameter of another helper this map already covers —
/// and all of them name one type. The host validated the entrypoint's value
/// against the spec, and a helper that only passes the value along keeps
/// that validation, so a decode it performs on the value collapses exactly
/// as it would in the entrypoint.
///
/// Only a helper whose callers are all visible: one with an ABI signature
/// is called by the host, and one the function table holds may be called
/// through it, so neither has a caller set the scan can close. A helper
/// that calls itself is skipped: its guarantee would rest on itself. A
/// decode helper is skipped too: its parameter is the raw `Val` it decodes,
/// which is what the collapse at its call sites retires. The map is a
/// fixed point, so a wrapper of a wrapper is covered too.
fn guaranteed_params(ir: &HighIr, helpers: &HashMap<FuncId, DecodeHelper>) -> Guaranteed {
    let has_indirect = ir
        .functions
        .iter()
        .any(|f| f.bindings.iter().any(|(_, b)| matches!(b.expr, Expr::IndirectCall { .. })));
    let table: Option<HashSet<FuncId>> = ir
        .facts
        .table_functions
        .as_ref()
        .map(|t| t.iter().map(|i| FuncId::new(*i)).collect());
    let complete = |f: &HighFunction| {
        f.signature.is_none() && (!has_indirect || table.as_ref().is_some_and(|t| !t.contains(&f.id)))
    };
    let mut sites: HashMap<FuncId, Vec<(FuncId, Vec<ValueId>)>> = HashMap::new();
    for caller in &ir.functions {
        for (_, binding) in caller.bindings.iter() {
            if let Expr::Call { target, args } = &binding.expr {
                sites.entry(*target).or_default().push((caller.id, args.clone()));
            }
        }
    }
    let by_id: HashMap<FuncId, &HighFunction> = ir.functions.iter().map(|f| (f.id, f)).collect();
    let mut out = Guaranteed::new();
    for _ in 0..8 {
        let mut changed = false;
        for func in &ir.functions {
            if !complete(func) || helpers.contains_key(&func.id) {
                continue;
            }
            let Some(calls) = sites.get(&func.id) else {
                continue;
            };
            if calls.iter().any(|(caller, _)| *caller == func.id) {
                continue;
            }
            for index in 0..func.params.len() {
                if out.contains_key(&(func.id, index)) {
                    continue;
                }
                let mut agreed: Option<KnownType> = None;
                let every_site = calls.iter().all(|(caller_id, args)| {
                    let Some(caller) = by_id.get(caller_id) else {
                        return false;
                    };
                    let Some(&arg) = args.get(index) else {
                        return false;
                    };
                    let Some(ty) = abi_param_type(caller, resolve_use(caller, arg), &out) else {
                        return false;
                    };
                    match &agreed {
                        None => {
                            agreed = Some(ty);
                            true
                        }
                        Some(have) => *have == ty,
                    }
                });
                if every_site && let Some(ty) = agreed {
                    out.insert((func.id, index), ty);
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
    out
}

/// The `contractspecv0` type `value` carries as a parameter of `func`:
/// declared, when `func` is an entrypoint, or guaranteed through its
/// callers, when it is a helper.
fn abi_param_type(func: &HighFunction, value: ValueId, guaranteed: &Guaranteed) -> Option<KnownType> {
    if let Some(declared) = declared_param_type(func, value) {
        return Some(declared);
    }
    let index = func.params.iter().position(|p| *p == value)?;
    guaranteed.get(&(func.id, index)).cloned()
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
    use crate::marshalling::test_support::{func_with, load, module, store, v};
    use sordec_common::{BlockId, IrId};
    use sordec_ir::{BinaryOp, FunctionParam, FunctionSignature, PrimitiveType, Region, TypeRef};

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

    /// The same helper after [`crate::SretReturnPass`] has run: the
    /// out-parameter is gone, and each arm returns its `(disc, payload)`
    /// pair directly. This is what `dump-hir` shows for hello-add's
    /// `func_0` once the staged pair is wired.
    fn u64_decode_helper_converted() -> HighFunction {
        let mut func = func_with(
            vec![
                Expr::Phi { incoming: vec![] },               // v0 the Val
                tag_check(v(0), val_abi::TAG_U64_OBJECT),     // v1
                obj_to_u64(v(0)),                             // v2 Ok payload A
                tag_check(v(0), val_abi::TAG_U64_SMALL),      // v3
                val_decode(v(0)),                             // v4 Ok payload B
                Expr::Literal(Literal::I64(0)),               // v5 Ok
                Expr::Literal(Literal::I64(1)),               // v6 Err
                Expr::Literal(Literal::I64(34_359_740_419)),  // v7 error Val
            ],
            vec![v(0)],
            vec![1, 2, 3, 4, 5, 6, 7],
        );
        // One return per arm, discriminant first — the shape the lifted
        // conversion produces and the structurer preserves.
        func.region = Region::Sequence(vec![
            Region::Basic(BlockId::from_index(0)),
            Region::Return {
                values: vec![v(5), v(2)],
            },
            Region::Return {
                values: vec![v(5), v(4)],
            },
            Region::Return {
                values: vec![v(6), v(7)],
            },
        ]);
        func
    }

    #[test]
    fn the_converted_decode_helper_is_classified() {
        let helper =
            classify(&u64_decode_helper_converted()).expect("a converted pure Val decode");
        assert_eq!(helper.val_index, 0);
        // One argument, not two — `sret` removed the out-pointer, and a
        // caller matching the old arity would never fire.
        assert_eq!(helper.arity, 1);
        let HelperShape::MultiValue {
            disc_index,
            payload_index,
        } = helper.shape
        else {
            panic!("the converted shape returns its components");
        };
        assert_eq!((disc_index, payload_index), (0, 1));
        assert_eq!(
            helper.tags,
            vec![val_abi::TAG_U64_OBJECT, val_abi::TAG_U64_SMALL]
        );
    }

    #[test]
    fn a_converted_effectful_callee_is_never_a_decode_helper() {
        // The `read_balance` shape in converted form: same multi-value
        // silhouette, but it reads host state. Eliding this would delete
        // contract logic and still compile — the effect gate has to apply
        // to both shapes, or converting a function would launder it past.
        let mut func = u64_decode_helper_converted();
        func.bindings.get_mut(v(2)).unwrap().expr =
            Expr::Semantic(SemanticOp::Known(KnownOp::GetLedgerSequence));
        assert!(
            classify(&func).is_none(),
            "a converted callee that reads host state is real code"
        );
    }

    #[test]
    fn a_single_component_return_is_not_an_sret_shape() {
        // An ordinary scalar helper. Admitting it would make every
        // one-value return in the module look like a candidate layout.
        let mut func = u64_decode_helper_converted();
        func.region = Region::Sequence(vec![
            Region::Basic(BlockId::from_index(0)),
            Region::Return { values: vec![v(2)] },
        ]);
        assert!(sret::analyze_returns(&func).is_none());
    }

    #[test]
    fn returns_disagreeing_on_arity_decline() {
        let mut func = u64_decode_helper_converted();
        func.region = Region::Sequence(vec![
            Region::Basic(BlockId::from_index(0)),
            Region::Return {
                values: vec![v(5), v(2)],
            },
            Region::Return { values: vec![v(6)] },
        ]);
        assert!(
            sret::analyze_returns(&func).is_none(),
            "positional components need every row the same width"
        );
    }

    #[test]
    fn the_sdk_decode_helper_is_classified() {
        let helper = classify(&u64_decode_helper()).expect("a pure Val decode");
        assert_eq!(helper.val_index, 1);
        assert_eq!(helper.arity, 2);
        let HelperShape::OutParam {
            out_index,
            disc_offset,
            payload_offset,
        } = helper.shape
        else {
            panic!("the untouched rustc shape is an out-parameter");
        };
        assert_eq!((out_index, disc_offset, payload_offset), (0, 0, 8));
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
        let (elisions, _) = plan(&func, &helpers(), &HashMap::new());
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
        let (elisions, _) = plan(&func, &helpers(), &HashMap::new());
        assert!(elisions.is_empty(), "a tag/type disagreement must elide nothing");
    }

    #[test]
    fn a_helper_call_outside_an_entrypoint_is_left_alone() {
        // The collapse rests on the host having validated the argument
        // against the spec, which is only true for an ABI entrypoint.
        let mut func = caller(PrimitiveType::U64);
        func.signature = None;
        let (elisions, _) = plan(&func, &helpers(), &HashMap::new());
        assert!(elisions.is_empty(), "only entrypoint parameters carry the guarantee");
    }

    /// `add(a, b)` as the compiler outlines it: the entrypoint hands its
    /// declared parameters, untouched, to a wrapper, and the wrapper calls
    /// the decoder. The wrapper's parameters carry the entrypoint's
    /// guarantee, so the decodes collapse there.
    fn entry_calling(wrapper: FuncId, param_ty: PrimitiveType) -> HighFunction {
        let mut func = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                          // v0 param `a`
                Expr::Phi { incoming: vec![] },                          // v1 param `b`
                Expr::Call { target: wrapper, args: vec![v(0), v(1)] }, // v2
            ],
            vec![v(0), v(1)],
            vec![2],
        );
        func.id = FuncId::from_index(3);
        func.signature = Some(FunctionSignature {
            name: "add".to_string(),
            inputs: vec![
                FunctionParam { name: "a".to_string(), ty: TypeRef::Primitive(param_ty) },
                FunctionParam { name: "b".to_string(), ty: TypeRef::Primitive(param_ty) },
            ],
            outputs: vec![],
        });
        func
    }

    /// The entrypoint's body, outlined: `caller` with no signature.
    fn wrapper() -> HighFunction {
        let mut func = caller(PrimitiveType::U64);
        func.signature = None;
        func.id = FuncId::from_index(2);
        func
    }

    /// A function calling through the table, with `held` the functions the
    /// table holds.
    fn table_caller(held: Vec<u32>) -> (HighFunction, Option<Vec<u32>>) {
        let mut func = func_with(
            vec![
                Expr::Literal(Literal::I32(0)), // v0
                Expr::IndirectCall { table: 0, sig: 0, callee: v(0), args: vec![] }, // v1
            ],
            vec![],
            vec![0, 1],
        );
        func.id = FuncId::from_index(4);
        (func, Some(held))
    }

    #[test]
    fn a_wrapper_handed_only_entrypoint_parameters_carries_the_guarantee() {
        let ir = module(vec![
            u64_decode_helper(),
            caller(PrimitiveType::U64),
            wrapper(),
            entry_calling(FuncId::from_index(2), PrimitiveType::U64),
        ]);
        let guaranteed = guaranteed_params(&ir, &helpers());
        assert_eq!(guaranteed.get(&(FuncId::from_index(2), 0)), Some(&KnownType::U64));
        assert_eq!(guaranteed.get(&(FuncId::from_index(2), 1)), Some(&KnownType::U64));

        let (elisions, _) = plan(&ir.functions[2], &helpers(), &guaranteed);
        let by_id: HashMap<ValueId, &Expr> = elisions.iter().map(|e| (e.id, &e.expr)).collect();
        assert!(matches!(by_id.get(&v(5)), Some(Expr::Use(p)) if *p == v(1)), "the wrapper's decode collapses");
        assert!(matches!(by_id.get(&v(3)), Some(Expr::Literal(Literal::Unit))));
    }

    #[test]
    fn a_wrapper_some_caller_hands_an_unknown_value_carries_no_guarantee() {
        // A second caller passes the wrapper constants, which are not an
        // entrypoint's parameters: the guarantee does not reach it.
        let mut other = func_with(
            vec![
                Expr::Literal(Literal::I64(7)),                                        // v0
                Expr::Literal(Literal::I64(8)),                                        // v1
                Expr::Call { target: FuncId::from_index(2), args: vec![v(0), v(1)] }, // v2
            ],
            vec![],
            vec![0, 1, 2],
        );
        other.id = FuncId::from_index(4);
        let ir = module(vec![
            u64_decode_helper(),
            caller(PrimitiveType::U64),
            wrapper(),
            entry_calling(FuncId::from_index(2), PrimitiveType::U64),
            other,
        ]);
        assert!(guaranteed_params(&ir, &helpers()).is_empty());
    }

    #[test]
    fn a_wrapper_the_function_table_holds_carries_no_guarantee() {
        for (held, expected) in [(vec![2], 0), (vec![4], 2)] {
            let (through_table, table) = table_caller(held);
            let mut ir = module(vec![
                u64_decode_helper(),
                caller(PrimitiveType::U64),
                wrapper(),
                entry_calling(FuncId::from_index(2), PrimitiveType::U64),
                through_table,
            ]);
            ir.facts.table_functions = table;
            assert_eq!(guaranteed_params(&ir, &helpers()).len(), expected, "table holds {:?}", ir.facts.table_functions);
        }
        // An unknown table beside an indirect call closes no caller set.
        let (through_table, _) = table_caller(vec![]);
        let mut ir = module(vec![
            u64_decode_helper(),
            caller(PrimitiveType::U64),
            wrapper(),
            entry_calling(FuncId::from_index(2), PrimitiveType::U64),
            through_table,
        ]);
        ir.facts.table_functions = None;
        assert!(guaranteed_params(&ir, &helpers()).is_empty());
    }

    /// `Address::try_from_val(env, v).ok()` as `optional_out` leaves it:
    /// `(scratch, val)`, a negated tag check, `None` on one path and
    /// `Some(val)` on the other, merged and returned.
    fn address_option_helper() -> HighFunction {
        let mut func = func_with(
            vec![
                Expr::Phi { incoming: vec![] }, // v0 scratch pointer
                Expr::Phi { incoming: vec![] }, // v1 the Val
                Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck {
                    value: v(1),
                    tag: val_abi::TAG_ADDRESS_OBJECT,
                    negated: true,
                })), // v2
                Expr::Optional { payload: None },             // v3
                Expr::Optional { payload: Some(vec![v(1)]) }, // v4
                Expr::Phi { incoming: vec![(BlockId::from_index(1), v(3)), (BlockId::from_index(2), v(4))] }, // v5
            ],
            vec![v(0), v(1)],
            vec![2, 3, 4],
        );
        func.region = Region::Sequence(vec![
            Region::Basic(BlockId::from_index(0)),
            Region::Return { values: vec![v(5)] },
        ]);
        func
    }

    #[test]
    fn the_option_shaped_decode_helper_is_classified() {
        let helper = classify(&address_option_helper()).expect("an Option-shaped decoder");
        assert_eq!(helper.val_index, 1);
        assert_eq!(helper.arity, 2);
        assert_eq!(helper.tags, vec![val_abi::TAG_ADDRESS_OBJECT]);
        assert!(
            matches!(&helper.shape, HelperShape::Optional { payload: Some(KnownType::Address), some_arms } if some_arms == &vec![v(4)]),
            "{:?}",
            helper.shape
        );
    }

    #[test]
    fn an_option_helper_whose_payload_is_not_its_argument_declines() {
        let mut func = address_option_helper();
        // `Some(scratch)`: the value handed back is not the checked Val.
        func.bindings.get_mut(v(4)).unwrap().expr = Expr::Optional { payload: Some(vec![v(0)]) };
        assert!(classify(&func).is_none());
    }

    #[test]
    fn an_option_decode_of_a_guaranteed_argument_is_some_of_it() {
        // An entrypoint declared `(a: Address)` calls the helper on `a`.
        let mut caller = func_with(
            vec![
                Expr::Phi { incoming: vec![] }, // v0 scratch
                Expr::Phi { incoming: vec![] }, // v1 param `a`
                Expr::Call { target: FuncId::from_index(0), args: vec![v(0), v(1)] }, // v2
            ],
            vec![v(0), v(1)],
            vec![2],
        );
        caller.id = FuncId::from_index(1);
        caller.signature = Some(FunctionSignature {
            name: "f".to_string(),
            inputs: vec![
                FunctionParam { name: "scratch".to_string(), ty: TypeRef::Primitive(PrimitiveType::U32) },
                FunctionParam { name: "a".to_string(), ty: TypeRef::Primitive(PrimitiveType::Address) },
            ],
            outputs: vec![],
        });
        let mut helpers = HashMap::new();
        helpers.insert(FuncId::from_index(0), classify(&address_option_helper()).unwrap());
        let (elisions, _) = plan(&caller, &helpers, &HashMap::new());
        let el = elisions.iter().find(|e| e.id == v(2)).expect("the call is rewritten");
        assert!(matches!(&el.expr, Expr::Optional { payload: Some(p) } if p == &vec![v(1)]), "{:?}", el.expr);
        assert!(
            matches!(&el.ty, Some(IrType::Inferred(KnownType::Option(inner))) if **inner == IrType::Inferred(KnownType::Address)),
            "{:?}",
            el.ty
        );
    }

    #[test]
    fn an_option_decode_of_any_other_value_is_typed_by_its_tags() {
        // A helper with no guarantee calls the decoder on a value it loaded.
        let mut caller = func_with(
            vec![
                Expr::Phi { incoming: vec![] }, // v0 scratch
                Expr::Phi { incoming: vec![] }, // v1 some Val
                Expr::Call { target: FuncId::from_index(0), args: vec![v(0), v(1)] }, // v2
            ],
            vec![v(0), v(1)],
            vec![2],
        );
        caller.id = FuncId::from_index(1);
        let mut helpers = HashMap::new();
        helpers.insert(FuncId::from_index(0), classify(&address_option_helper()).unwrap());
        let (elisions, _) = plan(&caller, &helpers, &HashMap::new());
        let el = elisions.iter().find(|e| e.id == v(2)).expect("the call is typed");
        assert!(matches!(&el.expr, Expr::Call { .. }), "the call stays: {:?}", el.expr);
        assert!(
            matches!(&el.ty, Some(IrType::Inferred(KnownType::Option(inner))) if **inner == IrType::Inferred(KnownType::Address)),
            "{:?}",
            el.ty
        );
        // And the helper's own `Some` arm agrees.
        let (own, _) = plan(&address_option_helper(), &helpers, &HashMap::new());
        assert!(own.iter().any(|e| e.id == v(4) && matches!(&e.ty, Some(IrType::Inferred(KnownType::Option(_))))));
    }

    /// `BytesN::<32>::try_from_val(env, v).ok()`: a negated bytes-object tag
    /// check, then `bytes_len(v) != 32`, `Some(v)` only past both. Blocks:
    /// bb0 the tag check, bb1 the length test, bb2 the `Some`. With
    /// `some_on_failing_side` the `Some` sits under `len != 32` instead.
    fn bytesn_option_helper(some_on_failing_side: bool) -> HighFunction {
        use sordec_ir::{BufOpKind, HighBlock};
        let mut func = func_with(
            vec![
                Expr::Phi { incoming: vec![] }, // v0 the Val
                Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck {
                    value: v(0),
                    tag: val_abi::TAG_BYTES_OBJECT,
                    negated: true,
                })), // v1
                Expr::Optional { payload: None }, // v2
                Expr::Semantic(SemanticOp::Known(KnownOp::BufOp { kind: BufOpKind::BytesLen, args: vec![v(0)] })), // v3
                Expr::Literal(Literal::U32(32)),                                  // v4
                Expr::Binary { op: BinaryOp::Ne, lhs: v(3), rhs: v(4) },          // v5
                Expr::Optional { payload: None },                                 // v6
                Expr::Optional { payload: Some(vec![v(0)]) },                     // v7
                Expr::Phi {
                    incoming: vec![
                        (BlockId::from_index(0), v(2)),
                        (BlockId::from_index(1), v(6)),
                        (BlockId::from_index(2), v(7)),
                    ],
                }, // v8
            ],
            vec![v(0)],
            vec![1, 2],
        );
        func.blocks.push(HighBlock { id: BlockId::from_index(1), bindings: vec![v(3), v(4), v(5), v(6)] });
        func.blocks.push(HighBlock { id: BlockId::from_index(2), bindings: vec![v(7)] });
        let some = Box::new(Region::Basic(BlockId::from_index(2)));
        let empty = Box::new(Region::Sequence(vec![]));
        let (then_region, else_region) = if some_on_failing_side { (some, Some(empty)) } else { (empty, Some(some)) };
        func.region = Region::Sequence(vec![
            Region::Basic(BlockId::from_index(0)),
            Region::If {
                cond: v(1),
                then_region: Box::new(Region::Sequence(vec![])),
                else_region: Some(Box::new(Region::Sequence(vec![
                    Region::Basic(BlockId::from_index(1)),
                    Region::If { cond: v(5), then_region, else_region },
                ]))),
            },
            Region::Return { values: vec![v(8)] },
        ]);
        func
    }

    #[test]
    fn a_length_checked_bytes_decoder_is_a_bytesn_decoder() {
        let helper = classify(&bytesn_option_helper(false)).expect("an Option-shaped decoder");
        assert!(
            matches!(&helper.shape, HelperShape::Optional { payload: Some(KnownType::BytesN(32)), .. }),
            "{:?}",
            helper.shape
        );
    }

    #[test]
    fn a_some_the_length_test_does_not_guard_declines() {
        assert!(classify(&bytesn_option_helper(true)).is_none());
    }

    #[test]
    fn a_decode_of_a_value_already_proven_the_payload_is_some_of_it() {
        // A helper decodes a value the module already proved is a `BytesN<32>`
        // (a field of a recovered struct).
        let mut caller = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                                   // v0 the field
                Expr::Call { target: FuncId::from_index(0), args: vec![v(0)] },   // v1
            ],
            vec![v(0)],
            vec![1],
        );
        caller.id = FuncId::from_index(1);
        caller.bindings.get_mut(v(0)).unwrap().ty = IrType::Known(KnownType::BytesN(32));
        let mut helpers = HashMap::new();
        helpers.insert(FuncId::from_index(0), classify(&bytesn_option_helper(false)).unwrap());
        let (elisions, _) = plan(&caller, &helpers, &HashMap::new());
        let el = elisions.iter().find(|e| e.id == v(1)).expect("the call is rewritten");
        assert!(matches!(&el.expr, Expr::Optional { payload: Some(p) } if p == &vec![v(0)]), "{:?}", el.expr);

        // Merely inferred, it is not proven: the call stays.
        caller.bindings.get_mut(v(0)).unwrap().ty = IrType::Inferred(KnownType::BytesN(32));
        let (elisions, _) = plan(&caller, &helpers, &HashMap::new());
        let el = elisions.iter().find(|e| e.id == v(1)).expect("the call is typed");
        assert!(matches!(&el.expr, Expr::Call { .. }), "{:?}", el.expr);
    }

    #[test]
    fn second_run_reports_no_work() {
        let mut func = caller(PrimitiveType::U64);
        let helpers = helpers();
        let (first, _) = plan(&func, &helpers, &HashMap::new());
        assert!(!first.is_empty());
        apply_elisions(&mut func, PASS_NAME, first);
        let (second, _) = plan(&func, &helpers, &HashMap::new());
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
                let host = !touches_no_host_state(func, &shape.store_bindings);
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

    /// `e.ledger().sequence() >> 32` decodes a value the typed SDK call
    /// already returns as a `u32`: the decode is the call.
    #[test]
    fn a_ledger_sequence_decode_is_the_sequence() {
        let f = crate::marshalling::test_support::func_with(
            vec![
                Expr::Semantic(SemanticOp::Known(KnownOp::GetLedgerSequence)), // v0
                Expr::Literal(Literal::I64(32)),                               // v1
                Expr::Binary { op: sordec_ir::BinaryOp::ShrU, lhs: crate::marshalling::test_support::v(0), rhs: crate::marshalling::test_support::v(1) }, // v2
            ],
            vec![],
            vec![0, 1, 2],
        );
        let elisions = host_decodes(&f);
        assert_eq!(elisions.len(), 1);
        assert!(matches!(elisions[0].expr, Expr::Use(x) if x == crate::marshalling::test_support::v(0)));
    }
}
