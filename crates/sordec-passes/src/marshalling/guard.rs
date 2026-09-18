//! Remove the argument type-check the source never wrote.
//!
//! The SDK checks every incoming argument before using it and traps on
//! mismatch. Three shapes reach us:
//!
//! ```text
//! if (eq disc, 1) { panic!() }        ← the decode-result guard, once
//!                                       [`super::decode`] has proved
//!                                       `disc` is the Ok constant
//! if !has_tag(a, AddressObject) { panic!() }   ← the direct tag guard
//! if bytes_len(a) != 32 { panic!() }  ← the `BytesN<N>` length guard,
//!                                       once
//!                                       [`crate::recognizers::val_packed_compare`]
//!                                       has unpacked the comparison
//! ```
//!
//! ## Why removing them preserves behaviour
//!
//! Not because the trap is unreachable — **because the trap moves**.
//!
//! It is tempting to argue that the host resolves `contractspecv0` and
//! marshals arguments to the declared types before dispatch, so the check
//! can never fire. That argument is false, and this module used to make
//! it. The Soroban host passes raw `Val`s to the exported function; it
//! never reads the contract spec. `cargo expand` on any fixture shows
//! where the conversion actually lives:
//!
//! ```text
//! pub fn invoke_raw(env: Env, arg_0: Val, …) -> Val {
//!     Attestation::attest(
//!         env.clone(),
//!         <_ as UnwrapOptimized>::unwrap_optimized(
//!             <_ as TryFromValForContractFn<…>>::try_from_val_for_contract_fn(&env, &arg_0),
//!         ),
//!         …
//! ```
//!
//! — in the SDK-generated dispatch wrapper, which rustc inlined into the
//! export. So the check we are looking at *is* that wrapper's, and
//! `unwrap_optimized` on wasm is `unreachable`, which is the trap.
//!
//! The reconstruction re-emits the declared signature inside
//! `#[contractimpl]`, so the macro regenerates that wrapper and that
//! conversion verbatim. Deleting the check from the body removes a
//! duplicate, not a behaviour: a caller passing a wrong-typed `Val` still
//! traps, in the regenerated wrapper, exactly as before.
//!
//! This is the stronger claim, and it is also the *narrower* one — which
//! is the point. It holds only for an **entrypoint parameter**, because
//! only an entrypoint gets a regenerated wrapper. A helper's checks have
//! nowhere to move to, and a check on an interior value may be a real
//! `if let` / `try_into` the author wrote. Both stay.
//!
//! ## What this pass is allowed to delete
//!
//! Only a guard whose taken arm is a trap and whose condition is one of:
//!
//! - a constant-false condition — the residue [`super::decode`] leaves
//!   behind, so this half deletes provably dead code and nothing else;
//! - a tag check on an entrypoint parameter whose tested tag *carries* the
//!   parameter's declared type ([`val_abi::tag_carries`]);
//! - a length check on an entrypoint parameter declared `BytesN<N>`, where
//!   the tested length is exactly `N`.
//!
//! The length shape is the second half of one `BytesN<N>::try_from_val`:
//! the tag check proves it is a `BytesObject`, the length check proves the
//! width. Both are regenerated together, so both go together — and a
//! length that *disagrees* with `N` means our picture is wrong, so it
//! stays.
//!
//! ## The honest caveat
//!
//! The relocation argument is sound, but it is still an argument about
//! generated code we do not re-read; `sordec-diffexec` is what actually
//! proves it. Every removal is therefore recorded as a diagnostic, not
//! silently.
//!
//! Scoring-wise the removal is neutral where it counts: `score-2.0.0`'s
//! T18 already excludes argument-decode panics as marshalling on *both*
//! sides, so no semantic fact is lost — only surplus control flow goes.

use std::collections::{HashMap, HashSet};

use sordec_common::{BlockId, Diagnostic, IrId, LiftDiagnosticCode, ValueId};
use sordec_ir::{
    BinaryOp, BufOpKind, Expr, HighFunction, HighIr, KnownOp, KnownType, Region, SemanticOp,
};

use super::metrics;
use crate::dataflow::{resolve_use, trace_int};
use crate::refine::debug_validate;
use crate::structuring::seq;
use crate::type_infer::known_of_type_ref;
use crate::val_abi;

/// Unique pipeline name of this pass.
pub const PASS_NAME: &str = "marshalling-arg-guard";

// Why one `Region::If` was not elided. Constants rather than literals
// repeated at the gate and again in [`report_declines`]: the wording *is*
// the key, so a typo in one of two copies would silently open a new bucket.
// Naming them keeps the original property — the reason reads at the site
// that enforces it — without the second copy. Same shape as
// [`crate::memory::sret`]'s decline constants, for the same reason.
/// The `If` has an else arm, so it is a two-way branch, not a guard.
const DECLINED_HAS_ELSE: &str = "the guard has an else arm";
/// The taken arm does real work rather than trapping.
const DECLINED_ARM_NOT_TRAP: &str = "the taken arm is not a bare trap";
/// A tag check whose trap arm is the match rather than the mismatch.
const DECLINED_TAG_NOT_NEGATED: &str = "tag check traps on the match, not the mismatch";
/// A tag check on something that is not a declared entrypoint parameter.
const DECLINED_TAG_NOT_PARAM: &str = "tag check on a value that is not an entrypoint parameter";
/// The tested tag does not carry the parameter's declared type.
const DECLINED_TAG_MISMATCH: &str = "tag does not carry the parameter's declared type";
/// An `Eq`/`Ne` whose operands do not both trace to constants.
const DECLINED_COMPARE_OPAQUE: &str = "comparison operands do not both trace to constants";
/// A constant comparison whose trap arm is genuinely taken.
const DECLINED_COMPARE_TAKEN: &str = "constant comparison whose trap arm is taken";
/// Not `bytes_len(p) != N` on a parameter declared `BytesN<N>`.
const DECLINED_LENGTH_UNMATCHED: &str = "not a length check on a BytesN parameter";
/// The condition is none of the three recognised shapes.
const DECLINED_SHAPE: &str = "condition is none of the three recognised shapes";
/// The same guard, written inside out — elidable, but by a rewrite this
/// pass does not yet perform.
const DECLINED_INVERTED_GUARD: &str = "elidable guard written inside out (trap is the successor)";

/// Which way round a guard is written.
///
/// The SDK's check reaches us in two shapes that mean the same thing, and
/// the second is 74% of what this pass declines:
///
/// ```text
/// if !ok { panic!() }          TrapIfTrue  — the trap is the taken arm
/// if ok { work; return }       TrapIfFalse — the trap is the successor
/// panic!()
/// ```
///
/// Every polarity test below reads this rather than assuming the first,
/// because reading the condition without knowing which arm traps is how a
/// guard gets deleted backwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sense {
    /// The trap runs when the condition holds.
    TrapIfTrue,
    /// The trap runs when it does not.
    TrapIfFalse,
}

/// Removes ABI argument type-checks.
#[derive(Debug, Default, Clone, Copy)]
pub struct ArgGuardElisionPass;

impl crate::pass::Pass<HighIr> for ArgGuardElisionPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> crate::pass::PassResult {
        let mut result = crate::pass::PassResult::default();
        let mut elided: i64 = 0;
        // Why each `Region::If` this pass looked at was left alone. Counted
        // rather than discarded so "it leaves ~150 behind" is a breakdown
        // instead of an impression — the move `memory::sret`'s census makes
        // one layer down.
        let mut declines: Vec<&'static str> = Vec::new();
        for func in &mut ir.functions {
            let empty = empty_blocks(func);
            let Found { guards, inverted } = collect_found(func, &empty, &mut declines);
            if guards.is_empty() && inverted.is_empty() {
                continue;
            }
            let before = elided;
            let region = std::mem::replace(&mut func.region, Region::Unreachable);
            let region = strip(region, &guards, &empty, &mut elided);
            func.region = strip_inverted(region, &inverted, &empty, &mut elided);
            // One diagnostic per guard actually removed — a reviewer sees
            // every site the unreachability argument was applied to.
            for note in guards.values().chain(inverted.values()).take((elided - before) as usize) {
                result.diagnostics.push(Diagnostic::info(
                    LiftDiagnosticCode::MarshallingGuardElided,
                    format!("{}{note}", func_prefix(func)),
                ));
            }
        }
        if elided > 0 {
            result.metrics.increment(metrics::GUARDS_ELIDED, elided);
            result.changed = true;
        }
        // Only from a settled invocation. This pass sits in a fixpoint
        // group and [`crate::pipeline::PipelineReport::metric_totals`]
        // *accumulates* a repeated pass's counters across every invocation,
        // so reporting unconditionally would count each surviving `If` once
        // per round — and, worse, weight it by how many rounds it happened
        // to survive. Reporting only when this round removed nothing gives
        // the steady-state picture, in which every bucket is multiplied by
        // the same number of settled rounds and the proportions are exact.
        //
        // A settled round always happens: the group terminates only when no
        // pass in it reports `changed`, so this pass is always run at least
        // once more after its last removal.
        if elided == 0 {
            report_declines(&declines, &mut result);
        }
        debug_validate(ir, PASS_NAME);
        result
    }
}

/// The elidable guards of one function, by sense.
#[derive(Default)]
struct Found {
    /// `if bad { trap }`: the condition, mapped to the note.
    guards: HashMap<ValueId, String>,
    /// `if ok { work } trap` with `work` never falling through: the
    /// condition, mapped to the note.
    inverted: HashMap<ValueId, String>,
}

/// Every condition value in `func` that is an elidable argument guard,
/// mapped to the note explaining why.
#[cfg(test)]
fn collect(
    func: &HighFunction,
    empty: &HashSet<BlockId>,
    declines: &mut Vec<&'static str>,
) -> HashMap<ValueId, String> {
    collect_found(func, empty, declines).guards
}

/// Both senses of elidable guard in `func`.
fn collect_found(func: &HighFunction, empty: &HashSet<BlockId>, declines: &mut Vec<&'static str>) -> Found {
    let mut found = Found::default();
    census(&func.region, func, empty, &mut found, declines);
    found
}

/// Walk the region tree, classifying every `If`.
///
/// Sibling-aware rather than [`Region::for_each_node`], because one of the
/// two guard senses is only visible from the enclosing `Sequence`: the trap
/// of an inverted guard is the `If`'s *successor*, not its arm.
fn census(
    region: &Region,
    func: &HighFunction,
    empty: &HashSet<BlockId>,
    guards: &mut Found,
    declines: &mut Vec<&'static str>,
) {
    if let Region::Sequence(items) = region {
        for (i, item) in items.iter().enumerate() {
            if let Region::If { cond, then_region, else_region } = item
                && else_region.is_none()
                && !is_trap(then_region, empty)
                && diverges(then_region)
                && is_trap(&Region::Sequence(items[i + 1..].to_vec()), empty)
            {
                // `if ok { work; return } trap` — the same guard as
                // `if !ok { trap }`, written inside out.
                classify_if(func, *cond, Sense::TrapIfFalse, guards, declines);
                census(then_region, func, empty, guards, declines);
                continue;
            }
            census(item, func, empty, guards, declines);
        }
        return;
    }
    if let Region::If { cond, then_region, else_region } = region {
        if let Some(else_region) = else_region {
            declines.push(DECLINED_HAS_ELSE);
            census(then_region, func, empty, guards, declines);
            census(else_region, func, empty, guards, declines);
            return;
        }
        if is_trap(then_region, empty) {
            classify_if(func, *cond, Sense::TrapIfTrue, guards, declines);
            return;
        }
        // A real two-way branch the author wrote lands here, which is what
        // makes the census a description of *every* branch rather than of
        // the guards alone.
        declines.push(DECLINED_ARM_NOT_TRAP);
        census(then_region, func, empty, guards, declines);
        return;
    }
    let mut nested = |r: &Region| census(r, func, empty, guards, declines);
    match region {
        Region::Scope { body, .. } | Region::Loop { body, .. } => nested(body),
        Region::Switch { arms, default, .. } => {
            for arm in arms {
                nested(&arm.body);
            }
            nested(default);
        }
        _ => {}
    }
}

/// Classify one guard-shaped `If`, recording the note or the refusal.
fn classify_if(
    func: &HighFunction,
    cond: ValueId,
    sense: Sense,
    found: &mut Found,
    declines: &mut Vec<&'static str>,
) {
    match classify_condition(func, cond, sense) {
        // An inverted guard is removed by splicing its arm into the parent
        // and dropping the trap after it ([`strip_inverted`]); the plain
        // one by deleting the node ([`strip`]).
        Ok(note) => match sense {
            Sense::TrapIfTrue => {
                found.guards.insert(cond, note);
            }
            Sense::TrapIfFalse => {
                found.inverted.insert(cond, note);
            }
        },
        Err(why) => declines.push(match sense {
            Sense::TrapIfTrue => why,
            // An inverted guard that fails the *content* gates is not
            // "inverted" in any interesting sense; report what refused it.
            Sense::TrapIfFalse => why,
        }),
    }
}

/// Whether `region` never falls through to its successor.
///
/// Conservative: `Break`, `Continue` and `Transfer` also leave, but they
/// leave to somewhere inside this function, so treating them as
/// fall-through keeps the inverted-guard shape to the case where the
/// successor is genuinely unreachable.
fn diverges(region: &Region) -> bool {
    match region {
        Region::Return { .. } | Region::Unreachable | Region::Panic { .. } => true,
        Region::Sequence(items) => items.last().is_some_and(diverges),
        Region::Scope { body, .. } => diverges(body),
        Region::If {
            then_region,
            else_region,
            ..
        } => else_region.as_ref().is_some_and(|e| diverges(e)) && diverges(then_region),
        _ => false,
    }
}

/// Fold the decline reasons into one metric per gate.
///
/// Keyed by the gate's own reason constant so the metric and the code that
/// enforces it cannot drift apart: adding a decline with a new constant and
/// no arm here lands in `OTHER` rather than silently joining a bucket it
/// does not belong to. `OTHER` reaching a non-zero count is therefore a
/// signal that this function is out of date.
fn report_declines(declines: &[&'static str], result: &mut crate::pass::PassResult) {
    use crate::metrics_catalog as mc;
    for reason in declines {
        let key = match *reason {
            DECLINED_HAS_ELSE => mc::MARSHALLING_GUARD_DECLINED_HAS_ELSE,
            DECLINED_ARM_NOT_TRAP => mc::MARSHALLING_GUARD_DECLINED_ARM_NOT_TRAP,
            DECLINED_TAG_NOT_NEGATED => mc::MARSHALLING_GUARD_DECLINED_TAG_NOT_NEGATED,
            DECLINED_TAG_NOT_PARAM => mc::MARSHALLING_GUARD_DECLINED_TAG_NOT_PARAM,
            DECLINED_TAG_MISMATCH => mc::MARSHALLING_GUARD_DECLINED_TAG_MISMATCH,
            DECLINED_COMPARE_OPAQUE => mc::MARSHALLING_GUARD_DECLINED_COMPARE_OPAQUE,
            DECLINED_COMPARE_TAKEN => mc::MARSHALLING_GUARD_DECLINED_COMPARE_TAKEN,
            DECLINED_LENGTH_UNMATCHED => mc::MARSHALLING_GUARD_DECLINED_LENGTH_UNMATCHED,
            DECLINED_SHAPE => mc::MARSHALLING_GUARD_DECLINED_SHAPE,
            DECLINED_INVERTED_GUARD => mc::MARSHALLING_GUARD_DECLINED_INVERTED,
            _ => mc::MARSHALLING_GUARD_DECLINED_OTHER,
        };
        result.metrics.increment(key, 1);
    }
}

/// The blocks of `func` that schedule no bindings.
///
/// Precomputed so [`is_trap`] can be a pure function of the region tree
/// plus this set: `strip` rebuilds `func.region` by value and cannot hold
/// a borrow of `func` at the same time.
pub(super) fn empty_blocks(func: &HighFunction) -> HashSet<BlockId> {
    func.blocks
        .iter()
        .filter(|(_, block)| block.bindings.is_empty())
        .map(|(id, _)| id)
        .collect()
}

/// A region that does nothing but trap.
///
/// Looks through a **binding-free** `Basic` block, because whether the
/// trap arm arrives as a bare `Panic` or as `Sequence([Basic(bb), Panic])`
/// is an accident of how the guard was structured — a `br_if` to the end
/// of an enclosing block leaves the empty block behind, a direct branch
/// does not. `digest_keccak` and `attest` in the attestation fixture carry
/// the same SDK tag guard in the two different shapes, and only the second
/// used to be recognized.
///
/// A `Basic` block that *does* schedule bindings is not looked through:
/// those bindings are work, and work before a trap is not "nothing but
/// trap". A `Basic` naming a block absent from `empty` is therefore
/// treated as non-empty — the conservative direction.
pub(super) fn is_trap(region: &Region, empty: &HashSet<BlockId>) -> bool {
    match region {
        Region::Unreachable | Region::Panic { .. } => true,
        Region::Sequence(items) => {
            let traps = items
                .iter()
                .any(|item| matches!(item, Region::Panic { .. } | Region::Unreachable));
            traps
                && items.iter().all(|item| match item {
                    Region::Unreachable | Region::Panic { .. } => true,
                    Region::Basic(b) => empty.contains(b),
                    _ => false,
                })
        }
        _ => false,
    }
}

/// Why `cond` is an elidable argument check, or which gate refused it.
///
/// Dispatching on the expression shape *first* is what lets each refusal
/// name a gate. The previous `or_else` chain tried all three shapes in turn
/// and could only report "none matched", which is the one answer that is
/// never actionable. Acceptance is unchanged: a `ValTagCheck` could only
/// ever match shape 2 and an `Expr::Binary` only shapes 1 and 3, so the
/// dispatch admits exactly the conditions the chain did.
///
/// Shapes 1 and 3 both key on `Expr::Binary`, so both are still tried. When
/// both refuse, the reason reported is the one that describes what the
/// condition *is*: a `bytes_len` operand means it was a length check that
/// did not line up, anything else means it was a comparison.
fn classify_condition(
    func: &HighFunction,
    cond: ValueId,
    sense: Sense,
) -> Result<String, &'static str> {
    let id = resolve_use(func, cond);
    let expr = &func.bindings.get(id).ok_or(DECLINED_SHAPE)?.expr;
    match expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck { .. })) => {
            classify_tag_check(func, expr, sense)
        }
        Expr::Binary {
            op: BinaryOp::Eq | BinaryOp::Ne,
            lhs,
            rhs,
        } => classify_constant_discriminant(func, expr, sense).or_else(|compare_why| {
            classify_length_check(func, expr, sense).map_err(|length_why| {
                let looks_like_a_length = bytes_len_of(func, *lhs).is_some()
                    || bytes_len_of(func, *rhs).is_some();
                if looks_like_a_length {
                    length_why
                } else {
                    compare_why
                }
            })
        }),
        _ => Err(DECLINED_SHAPE),
    }
}

/// Shape 1 — the decode-result guard, now comparing the Ok constant
/// against the Err discriminant, so the branch is provably not taken.
fn classify_constant_discriminant(
    func: &HighFunction,
    expr: &Expr,
    sense: Sense,
) -> Result<String, &'static str> {
    let Expr::Binary {
        op: op @ (BinaryOp::Eq | BinaryOp::Ne),
        lhs,
        rhs,
    } = expr
    else {
        return Err(DECLINED_SHAPE);
    };
    let (Some(l), Some(r)) = (trace_int(func, *lhs), trace_int(func, *rhs)) else {
        return Err(DECLINED_COMPARE_OPAQUE);
    };
    let holds = if *op == BinaryOp::Eq { l == r } else { l != r };
    // The trap is dead when the condition disagrees with the sense that
    // reaches it: `if c { trap }` needs `c` false, `if c { … } trap` needs
    // `c` true.
    let taken = holds == (sense == Sense::TrapIfTrue);
    if taken {
        return Err(DECLINED_COMPARE_TAKEN);
    }
    Ok("decode-failure guard on a constant-Ok discriminant: provably not taken".to_string())
}

/// Shape 2 — a direct tag check on an entry parameter.
/// The proven type of a value a struct decode typed: a field access on a
/// recovered struct, or the host operation's result the decode was the
/// proof of (a storage read typed as the struct it unpacks into).
///
/// Only `Known` counts, and only on those two shapes. A host result whose
/// type is merely the ABI's `Val` fails [`val_abi::tag_admits`] for every
/// object tag, so nothing is licensed by the operation alone.
fn recovered_field_type(func: &HighFunction, value: ValueId) -> Option<sordec_ir::KnownType> {
    let binding = func.bindings.get(value)?;
    let decoded = match &binding.expr {
        Expr::Field { .. } => true,
        Expr::Semantic(SemanticOp::Known(_)) => {
            matches!(&binding.ty, sordec_ir::IrType::Known(sordec_ir::KnownType::UserDefined(_)))
        }
        _ => false,
    };
    if !decoded {
        return None;
    }
    match &binding.ty {
        sordec_ir::IrType::Known(t) => Some(t.clone()),
        _ => None,
    }
}

fn classify_tag_check(
    func: &HighFunction,
    expr: &Expr,
    sense: Sense,
) -> Result<String, &'static str> {
    let Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck {
        value,
        tag,
        negated,
    })) = expr
    else {
        return Err(DECLINED_SHAPE);
    };
    // The trap must be the *mismatch* path. `if !has_tag { trap }` and
    // `if has_tag { … } trap` both say that; `if has_tag { trap }` says the
    // opposite and is somebody else's check.
    if *negated != (sense == Sense::TrapIfTrue) {
        return Err(DECLINED_TAG_NOT_NEGATED);
    }
    let value = resolve_use(func, *value);
    // A field of a recovered `#[contracttype]` struct carries the same
    // licence as an entrypoint parameter: the re-emitted struct derives
    // `TryFromVal`, which regenerates this exact check on this exact
    // field, so the trap is relocated into derived code.
    if let Some(field_ty) = recovered_field_type(func, value) {
        if !val_abi::tag_admits(*tag, &field_ty) {
            return Err(DECLINED_TAG_MISMATCH);
        }
        return Ok(format!(
            "tag check ({}) on a field the struct decode typed as {field_ty:?}: the derived \
             `TryFromVal` regenerates it",
            val_abi::tag_name(*tag).unwrap_or("?")
        ));
    }
    let declared = declared_param_type(func, value).ok_or(DECLINED_TAG_NOT_PARAM)?;
    // `tag_carries`, not `==`: a `BytesN<N>` parameter rides in a plain
    // `BytesObject`, so the tag denotes `Bytes` while the declaration says
    // `BytesN(N)` and an equality test would report a disagreement that
    // does not exist.
    if !val_abi::tag_carries(*tag, &declared) {
        return Err(DECLINED_TAG_MISMATCH);
    }
    Ok(format!(
        "argument tag check ({}) on a parameter contractspecv0 declares as {declared:?}: \
         `#[contractimpl]` regenerates it in the dispatch wrapper",
        val_abi::tag_name(*tag).unwrap_or("?")
    ))
}

/// Shape 3 — `bytes_len(p) != N` on a parameter declared `BytesN<N>`.
///
/// `BytesN<N>::try_from_val` is a `BytesObject` tag check followed by a
/// width check; shape 2 handles the first half and this the second. Both
/// are regenerated by `#[contractimpl]` from the same declared type, so
/// both may go — and neither may go without the declaration to justify it.
///
/// Reads a *payload* comparison, which is what
/// [`crate::recognizers::val_packed_compare`] leaves behind; the raw form
/// rustc emits (`bytes_len(p) & 0xFFFF_FFFF_0000_0000 != N << 32`) is
/// deliberately not matched here. Keeping the bit-twiddling in one place
/// means this gate reasons about lengths, not encodings.
///
/// A length that disagrees with `N` is **kept**: it means our picture of
/// the parameter is wrong, and the check is the evidence.
fn classify_length_check(
    func: &HighFunction,
    expr: &Expr,
    sense: Sense,
) -> Result<String, &'static str> {
    // `if len != N { trap }` and `if len == N { … } trap` are the same
    // check; anything else is not this shape.
    let wanted = match sense {
        Sense::TrapIfTrue => BinaryOp::Ne,
        Sense::TrapIfFalse => BinaryOp::Eq,
    };
    let Expr::Binary { op, lhs, rhs } = expr else {
        return Err(DECLINED_LENGTH_UNMATCHED);
    };
    if *op != wanted {
        return Err(DECLINED_LENGTH_UNMATCHED);
    }
    // Either operand may hold the length; the other must be the constant.
    for (len_side, const_side) in [(*lhs, *rhs), (*rhs, *lhs)] {
        let Some(param) = bytes_len_of(func, len_side) else {
            continue;
        };
        let Some(KnownType::BytesN(width)) = declared_param_type(func, param) else {
            continue;
        };
        let Some(tested) = trace_int(func, const_side) else {
            continue;
        };
        if tested != i128::from(width) {
            continue;
        }
        return Ok(format!(
            "argument length check (== {width}) on a parameter contractspecv0 declares as \
             BytesN<{width}>: `#[contractimpl]` regenerates it in the dispatch wrapper"
        ));
    }
    Err(DECLINED_LENGTH_UNMATCHED)
}

/// The value whose length `value` is, when `value` is a `bytes_len` of an
/// entrypoint parameter.
fn bytes_len_of(func: &HighFunction, value: ValueId) -> Option<ValueId> {
    let id = resolve_use(func, value);
    if (id.index() as usize) >= func.bindings.len() {
        return None;
    }
    let Expr::Semantic(SemanticOp::Known(KnownOp::BufOp {
        kind: BufOpKind::BytesLen,
        args,
    })) = &func.bindings.get(id)?.expr
    else {
        return None;
    };
    args.first().map(|a| resolve_use(func, *a))
}

/// `"fn <name>: "` when the function has a recovered name, so a
/// diagnostic points at a place rather than floating free.
fn func_prefix(func: &HighFunction) -> String {
    match func.signature.as_ref().map(|s| &s.name).or(func.name.as_ref()) {
        Some(name) => format!("fn {name}: "),
        None => format!("func{}: ", func.id.index()),
    }
}

/// The declared type of `value` when it is one of this entrypoint's
/// parameters.
fn declared_param_type(func: &HighFunction, value: ValueId) -> Option<KnownType> {
    let sig = func.signature.as_ref()?;
    let index = func.params.iter().position(|p| *p == value)?;
    known_of_type_ref(&sig.inputs.get(index)?.ty)
}

/// Bottom-up rewrite dropping every collected inverted guard:
///
/// ```text
/// if ok { work; return }        work; return
/// panic!()                 →
/// ```
///
/// The trap after the `If` is reached only when `ok` is false, because
/// `work` never falls through; the check it guards is the regenerated
/// argument conversion's, exactly as for [`strip`]. The arm is spliced
/// into the parent sequence and the trap is dropped with the check.
fn strip_inverted(
    region: Region,
    inverted: &HashMap<ValueId, String>,
    empty: &HashSet<BlockId>,
    elided: &mut i64,
) -> Region {
    if inverted.is_empty() {
        return region;
    }
    let mut recurse = |r: Region| strip_inverted(r, inverted, empty, elided);
    match region {
        Region::Sequence(items) => {
            let items: Vec<Region> = items.into_iter().map(&mut recurse).collect();
            let at = items.iter().enumerate().position(|(i, item)| {
                matches!(item, Region::If { cond, then_region, else_region: None }
                    if inverted.contains_key(cond)
                        && !is_trap(then_region, empty)
                        && diverges(then_region)
                        && is_trap(&Region::Sequence(items[i + 1..].to_vec()), empty))
            });
            let Some(at) = at else {
                return seq(items);
            };
            let mut items = items;
            items.truncate(at + 1);
            let Some(Region::If { then_region, .. }) = items.pop() else {
                unreachable!("position matched an If");
            };
            *elided += 1;
            items.push(*then_region);
            seq(items)
        }
        Region::Scope { out, body } => Region::Scope { out, body: Box::new(recurse(*body)) },
        Region::Loop { header, body, kind } => Region::Loop { header, body: Box::new(recurse(*body)), kind },
        Region::Switch { index, arms, default, dispatch } => Region::Switch {
            index,
            arms: arms
                .into_iter()
                .map(|mut arm| {
                    arm.body = recurse(arm.body);
                    arm
                })
                .collect(),
            default: Box::new(recurse(*default)),
            dispatch,
        },
        Region::If { cond, then_region, else_region } => Region::If {
            cond,
            then_region: Box::new(recurse(*then_region)),
            else_region: else_region.map(|e| Box::new(recurse(*e))),
        },
        leaf => leaf,
    }
}

/// Bottom-up rewrite dropping every collected guard. Mirrors
/// [`crate::refine::guard_clause`]'s shape so the tree stays in the
/// canonical no-nested-`Sequence` form.
pub(super) fn strip(
    region: Region,
    guards: &HashMap<ValueId, String>,
    empty: &HashSet<BlockId>,
    elided: &mut i64,
) -> Region {
    match region {
        Region::Sequence(items) => seq(items
            .into_iter()
            .map(|item| strip(item, guards, empty, elided))
            .collect()),
        Region::Scope { out, body } => Region::Scope {
            out,
            body: Box::new(strip(*body, guards, empty, elided)),
        },
        Region::Loop { header, body, kind } => Region::Loop {
            header,
            body: Box::new(strip(*body, guards, empty, elided)),
            kind,
        },
        Region::Switch {
            index,
            arms,
            default,
            dispatch,
        } => Region::Switch {
            index,
            arms: arms
                .into_iter()
                .map(|mut arm| {
                    arm.body = strip(arm.body, guards, empty, elided);
                    arm
                })
                .collect(),
            default: Box::new(strip(*default, guards, empty, elided)),
            dispatch,
        },
        Region::If {
            cond,
            then_region,
            else_region,
        } => {
            if else_region.is_none() && is_trap(&then_region, empty) && guards.contains_key(&cond) {
                *elided += 1;
                return seq(vec![]);
            }
            Region::If {
                cond,
                then_region: Box::new(strip(*then_region, guards, empty, elided)),
                else_region: else_region.map(|e| Box::new(strip(*e, guards, empty, elided))),
            }
        }
        leaf @ (Region::Basic(_)
        | Region::Break { .. }
        | Region::Continue { .. }
        | Region::Transfer { .. }
        | Region::Return { .. }
        | Region::Unreachable
        | Region::Panic { .. }
        | Region::Unstructured { .. }) => leaf,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, v};
    use sordec_ir::{
        CompositeType, FunctionParam, FunctionSignature, Literal, PanicKind, PrimitiveType,
        TypeRef,
    };

    /// An entrypoint whose parameters all have the same declared type.
    fn entry(exprs: Vec<Expr>, params: Vec<ValueId>, ty: PrimitiveType) -> HighFunction {
        let inputs = params.iter().map(|_| TypeRef::Primitive(ty)).collect();
        entry_typed(exprs, params, inputs)
    }

    /// An entrypoint with one declared `TypeRef` per parameter — needed for
    /// `BytesN<N>`, which is a composite rather than a primitive.
    fn entry_typed(
        exprs: Vec<Expr>,
        params: Vec<ValueId>,
        inputs: Vec<TypeRef>,
    ) -> HighFunction {
        let mut func = func_with(exprs, params, vec![]);
        func.signature = Some(FunctionSignature {
            name: "f".to_string(),
            inputs: inputs
                .into_iter()
                .map(|ty| FunctionParam {
                    name: "a".to_string(),
                    ty,
                })
                .collect(),
            outputs: vec![],
        });
        func
    }

    fn guarded(func: &mut HighFunction, cond: ValueId) {
        func.region = Region::If {
            cond,
            then_region: Box::new(Region::Unreachable),
            else_region: None,
        };
    }

    /// `collect` against the function's own empty-block set — what the
    /// pass does, without the caller having to recompute it.
    fn collect_guards(func: &HighFunction) -> HashMap<ValueId, String> {
        collect(func, &empty_blocks(func), &mut Vec::new())
    }

    /// The reasons `collect` recorded, in discovery order.
    fn collect_declines(func: &HighFunction) -> Vec<&'static str> {
        let mut declines = Vec::new();
        collect(func, &empty_blocks(func), &mut declines);
        declines
    }

    /// Every `Region::If` lands in exactly one bucket: elided, or one
    /// named decline. This is the invariant that makes the census readable
    /// as a breakdown rather than a pile of counters — and it is the one
    /// `memory::sret`'s first census failed, reporting 228-vs-9 when the
    /// truth was 0-vs-13 because a candidate could be counted twice.
    fn assert_every_if_is_accounted_for(func: &HighFunction) {
        let mut ifs = 0;
        func.region.for_each_node(|node| {
            if matches!(node, Region::If { .. }) {
                ifs += 1;
            }
        });
        let accepted = collect_guards(func).len();
        let declined = collect_declines(func).len();
        assert_eq!(
            ifs,
            accepted + declined,
            "every `If` must be either elided or declined exactly once \
             ({ifs} ifs, {accepted} accepted, {declined} declined)"
        );
    }

    #[test]
    fn a_constant_ok_discriminant_guard_is_removed() {
        let mut func = entry(
            vec![
                Expr::Literal(Literal::I32(0)), // v0 — the collapsed discriminant
                Expr::Literal(Literal::I32(1)), // v1
                Expr::Binary { op: BinaryOp::Eq, lhs: v(0), rhs: v(1) }, // v2
            ],
            vec![],
            PrimitiveType::U64,
        );
        guarded(&mut func, v(2));
        let guards = collect_guards(&func);
        assert_eq!(guards.len(), 1);
        let mut elided = 0;
        let region = strip(func.region.clone(), &guards, &empty_blocks(&func), &mut elided);
        assert_eq!(elided, 1);
        assert!(matches!(region, Region::Sequence(ref s) if s.is_empty()));
    }

    #[test]
    fn a_tag_guard_on_a_matching_entry_parameter_is_removed() {
        let mut func = entry(
            vec![
                Expr::Phi { incoming: vec![] }, // v0 — the parameter
                Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck {
                    value: v(0),
                    tag: val_abi::TAG_ADDRESS_OBJECT,
                    negated: true,
                })), // v1
            ],
            vec![v(0)],
            PrimitiveType::Address,
        );
        guarded(&mut func, v(1));
        assert_eq!(collect_guards(&func).len(), 1);
    }

    #[test]
    fn the_census_names_the_gate_that_refused() {
        // A tag check declared `u64` while the tag says Address: the
        // mismatch gate, not a generic "did not match".
        let mut func = entry(
            vec![
                Expr::Phi { incoming: vec![] },
                Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck {
                    value: v(0),
                    tag: val_abi::TAG_ADDRESS_OBJECT,
                    negated: true,
                })),
            ],
            vec![v(0)],
            PrimitiveType::U64,
        );
        guarded(&mut func, v(1));
        assert_eq!(collect_declines(&func), vec![DECLINED_TAG_MISMATCH]);
        assert_every_if_is_accounted_for(&func);
    }

    #[test]
    fn a_guard_whose_trap_arm_is_taken_is_not_a_dead_branch() {
        // `1 == 1` with a trap arm is a real failure path, and must be
        // filed as such rather than as an unrecognised shape — the two
        // call for opposite follow-up work.
        let mut func = entry(
            vec![
                Expr::Literal(Literal::I32(1)),
                Expr::Literal(Literal::I32(1)),
                Expr::Binary { op: BinaryOp::Eq, lhs: v(0), rhs: v(1) },
            ],
            vec![],
            PrimitiveType::U64,
        );
        guarded(&mut func, v(2));
        assert!(collect_guards(&func).is_empty());
        assert_eq!(collect_declines(&func), vec![DECLINED_COMPARE_TAKEN]);
        assert_every_if_is_accounted_for(&func);
    }

    #[test]
    fn an_elided_guard_is_not_also_counted_as_a_decline() {
        // The double-count that made `sret`'s first census unreadable.
        let mut func = entry(
            vec![
                Expr::Literal(Literal::I32(0)),
                Expr::Literal(Literal::I32(1)),
                Expr::Binary { op: BinaryOp::Eq, lhs: v(0), rhs: v(1) },
            ],
            vec![],
            PrimitiveType::U64,
        );
        guarded(&mut func, v(2));
        assert_eq!(collect_guards(&func).len(), 1);
        assert!(collect_declines(&func).is_empty());
        assert_every_if_is_accounted_for(&func);
    }

    #[test]
    fn a_tag_guard_that_disagrees_with_the_declared_type_stays() {
        let mut func = entry(
            vec![
                Expr::Phi { incoming: vec![] },
                Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck {
                    value: v(0),
                    tag: val_abi::TAG_ADDRESS_OBJECT,
                    negated: true,
                })),
            ],
            vec![v(0)],
            PrimitiveType::U64, // declared u64, tag says Address
        );
        guarded(&mut func, v(1));
        assert!(
            collect_guards(&func).is_empty(),
            "a disagreement means our picture is wrong — keep the check"
        );
    }

    #[test]
    fn a_tag_guard_on_a_non_parameter_stays() {
        // No ABI guarantee covers an interior value; this may be an
        // `if let` the author wrote.
        let mut func = entry(
            vec![
                Expr::Literal(Literal::I64(0)), // v0 — not a parameter
                Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck {
                    value: v(0),
                    tag: val_abi::TAG_ADDRESS_OBJECT,
                    negated: true,
                })),
            ],
            vec![],
            PrimitiveType::Address,
        );
        guarded(&mut func, v(1));
        assert!(collect_guards(&func).is_empty());
    }

    #[test]
    fn a_reachable_comparison_guard_stays() {
        // `0 == 0` is taken, so the trap is real: never remove it.
        let mut func = entry(
            vec![
                Expr::Literal(Literal::I32(0)),
                Expr::Literal(Literal::I32(0)),
                Expr::Binary { op: BinaryOp::Eq, lhs: v(0), rhs: v(1) },
            ],
            vec![],
            PrimitiveType::U64,
        );
        guarded(&mut func, v(2));
        assert!(collect_guards(&func).is_empty(), "a taken trap must survive");
    }

    #[test]
    fn a_guard_whose_arm_is_not_a_trap_stays() {
        let mut func = entry(
            vec![
                Expr::Literal(Literal::I32(0)),
                Expr::Literal(Literal::I32(1)),
                Expr::Binary { op: BinaryOp::Eq, lhs: v(0), rhs: v(1) },
            ],
            vec![],
            PrimitiveType::U64,
        );
        func.region = Region::If {
            cond: v(2),
            then_region: Box::new(Region::Return { values: vec![] }),
            else_region: None,
        };
        assert!(collect_guards(&func).is_empty(), "only bare traps are guards");
    }

    // ---- the `BytesN<N>` carrier tag (D1) ----

    fn bytes_n(n: u32) -> TypeRef {
        TypeRef::Composite(CompositeType::BytesN(n))
    }

    /// A negated `BytesObject` tag check on parameter `v0`.
    fn tag_guard_on_param(declared: TypeRef) -> HighFunction {
        let mut func = entry_typed(
            vec![
                Expr::Phi { incoming: vec![] }, // v0 — the parameter
                Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck {
                    value: v(0),
                    tag: val_abi::TAG_BYTES_OBJECT,
                    negated: true,
                })), // v1
            ],
            vec![v(0)],
            vec![declared],
        );
        guarded(&mut func, v(1));
        func
    }

    #[test]
    fn a_bytes_object_tag_guard_on_a_bytes_n_parameter_is_removed() {
        // A `BytesN<N>` rides in a plain `BytesObject`, so the tag denotes
        // `Bytes` while the declaration says `BytesN(N)`. Equality used to
        // read that as a disagreement and keep the guard.
        for width in [32u32, 64] {
            let func = tag_guard_on_param(bytes_n(width));
            assert_eq!(
                collect_guards(&func).len(),
                1,
                "BytesN<{width}> is carried by a BytesObject"
            );
        }
    }

    #[test]
    fn a_bytes_object_tag_guard_on_an_unrelated_parameter_still_stays() {
        let func = tag_guard_on_param(TypeRef::Primitive(PrimitiveType::Address));
        assert!(
            collect_guards(&func).is_empty(),
            "a real disagreement must still keep the check"
        );
    }

    // ---- looking through an empty `Basic` block (D2) ----

    /// The trap arm as it arrives when the guard was a `br_if` to the end
    /// of an enclosing block: an empty block, then the trap.
    fn trap_behind_block(bb: BlockId) -> Region {
        Region::Sequence(vec![
            Region::Basic(bb),
            Region::Panic {
                kind: PanicKind::Unwrap,
            },
        ])
    }

    #[test]
    fn a_trap_arm_behind_an_empty_block_is_still_a_trap() {
        // `digest_keccak`'s shape. `func_with` builds block 0 with the
        // `scheduled` list, and `entry_typed` passes an empty one, so
        // block 0 is exactly the binding-free block this looks through.
        let mut func = tag_guard_on_param(bytes_n(32));
        let bb = BlockId::from_index(0);
        assert!(empty_blocks(&func).contains(&bb), "block 0 must start empty");
        func.region = Region::If {
            cond: v(1),
            then_region: Box::new(trap_behind_block(bb)),
            else_region: None,
        };
        let guards = collect_guards(&func);
        assert_eq!(guards.len(), 1);
        let mut elided = 0;
        let region = strip(func.region.clone(), &guards, &empty_blocks(&func), &mut elided);
        assert_eq!(elided, 1);
        assert!(matches!(region, Region::Sequence(ref s) if s.is_empty()));
    }

    #[test]
    fn a_trap_arm_behind_a_block_that_does_work_is_not_a_trap() {
        // Work before a trap is not "nothing but trap" — the arm may be a
        // real error path the author wrote.
        let mut func = tag_guard_on_param(bytes_n(32));
        let bb = BlockId::from_index(0);
        func.blocks.get_mut(bb).unwrap().bindings.push(v(1));
        assert!(!empty_blocks(&func).contains(&bb));
        func.region = Region::If {
            cond: v(1),
            then_region: Box::new(trap_behind_block(bb)),
            else_region: None,
        };
        assert!(collect_guards(&func).is_empty());
    }

    // ---- the length half of `BytesN<N>::try_from_val` (D3) ----

    /// `if bytes_len(v0) != width { trap }` on a parameter declared
    /// `declared`.
    fn length_guard(width: i64, declared: TypeRef) -> HighFunction {
        let mut func = entry_typed(
            vec![
                Expr::Phi { incoming: vec![] }, // v0 — the parameter
                Expr::Semantic(SemanticOp::Known(KnownOp::BufOp {
                    kind: BufOpKind::BytesLen,
                    args: vec![v(0)],
                })), // v1
                Expr::Literal(Literal::U32(width as u32)), // v2
                Expr::Binary { op: BinaryOp::Ne, lhs: v(1), rhs: v(2) }, // v3
            ],
            vec![v(0)],
            vec![declared],
        );
        guarded(&mut func, v(3));
        func
    }

    #[test]
    fn a_matching_length_guard_on_a_bytes_n_parameter_is_removed() {
        for width in [32i64, 64] {
            let func = length_guard(width, bytes_n(width as u32));
            let guards = collect_guards(&func);
            assert_eq!(guards.len(), 1, "BytesN<{width}> declares this length");
            assert!(guards.values().next().unwrap().contains(&format!("BytesN<{width}>")));
        }
    }

    #[test]
    fn a_length_guard_that_disagrees_with_the_declared_width_stays() {
        // Testing 31 against a `BytesN<32>` parameter means our picture of
        // the parameter is wrong, and the check is the evidence.
        let func = length_guard(31, bytes_n(32));
        assert!(collect_guards(&func).is_empty());
    }

    #[test]
    fn a_length_guard_on_a_plain_bytes_parameter_stays() {
        // `Bytes` declares no width, so nothing regenerates this check —
        // it is `digest_keccak`'s `message.len() == 0`, real logic.
        let func = length_guard(0, TypeRef::Primitive(PrimitiveType::Bytes));
        assert!(collect_guards(&func).is_empty());
    }

    #[test]
    fn a_length_guard_on_a_non_parameter_stays() {
        let mut func = entry_typed(
            vec![
                Expr::Literal(Literal::I64(0)), // v0 — not a parameter
                Expr::Semantic(SemanticOp::Known(KnownOp::BufOp {
                    kind: BufOpKind::BytesLen,
                    args: vec![v(0)],
                })),
                Expr::Literal(Literal::U32(32)),
                Expr::Binary { op: BinaryOp::Ne, lhs: v(1), rhs: v(2) },
            ],
            vec![],
            vec![],
        );
        guarded(&mut func, v(3));
        assert!(collect_guards(&func).is_empty());
    }

    #[test]
    fn an_equality_length_comparison_is_not_a_guard() {
        // Only `!=` traps on mismatch. `==` guarding a trap would mean
        // "trap when the length IS right", which is not this idiom.
        let mut func = length_guard(32, bytes_n(32));
        func.bindings.get_mut(v(3)).unwrap().expr = Expr::Binary {
            op: BinaryOp::Eq,
            lhs: v(1),
            rhs: v(2),
        };
        assert!(collect_guards(&func).is_empty());
    }
}
