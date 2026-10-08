//! Bare-`panic!` / unwrap recognition (D8, Phase-2 C16/C17).
//!
//! rustc under `panic=abort` compiles every `panic!()`, failed
//! `.unwrap()`, and arithmetic-overflow check down to a guard branching
//! to a WASM `unreachable` (possibly behind panic-glue helper calls) —
//! the structurer and wave-1 refiners shape those into else-less
//! `if cond { … unreachable }` guards and hoisted-guard fallthrough
//! tails. This pass types the trap leaves as [`Region::Panic`] so the
//! renderer and the Phase-4 emitter can say `panic!()` where the source
//! panicked, instead of the anonymous `unreachable`:
//!
//! - **Guarded trap**: an `If` arm ending in [`Region::Unreachable`] —
//!   the else-less guard (D1's canonical output) or either arm of the
//!   D4-asymmetry residue whose condition would not flip. The leaf
//!   becomes `Panic` and the guard condition classifies it: a `Val` tag
//!   test ([`KnownOp::ValTagCheck`] or a raw `(x & 0xFF) ==/!= tag`
//!   comparison) marks an [`PanicKind::Unwrap`]; anything else a
//!   [`PanicKind::Bare`].
//! - **Fallthrough trap**: a sequence tail `[…, Unreachable]` with at
//!   least one preceding item — the hoisted-guard residue (`if ok {
//!   return }; unreachable`) and the panic-glue wrapper bodies
//!   (`call func_N; unreachable`). Always [`PanicKind::Bare`] — the
//!   guard, if any, tested the success path.
//!
//! A single-node `Unreachable` body (the terminal abort helper itself)
//! stays untyped — there is no evidence it is anything but the trap.
//! Trap paths whose blocks carry a [`KnownOp::PanicWithError`] binding
//! are skipped entirely: the host-call recognizer already typed those,
//! and the structured error code is visible at the call site.
//!
//! Every `Bare` conversion emits the [`PanicWithoutErrorCode`]
//! diagnostic (defined since Phase 2, first wired here). The pass
//! rewrites leaves only — conditions and bindings are untouched, so
//! renderer condition folding is unaffected.
//!
//! [`PanicWithoutErrorCode`]: LiftDiagnosticCode::PanicWithoutErrorCode

use sordec_common::{
    Diagnostic, FuncId, IrId, LiftDiagnosticCode, Location, ValueId,
};
use sordec_ir::{
    BinaryOp, Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Literal, PanicKind, Region,
    SemanticOp, UnaryOp,
};

use super::debug_validate;
use crate::dataflow::{resolve_use, trace_int};
use crate::pass::{Pass, PassResult};

/// Unique pipeline name of this pass.
pub const PASS_NAME: &str = "refine-panic-recover";

// Metric counter keys.
/// Trap leaves typed as bare `panic!()` sites.
const M_BARE: &str = "refine_bare_panics";
/// Trap leaves typed as unwrap-shaped (tag-checked) panics.
const M_UNWRAP: &str = "refine_unwraps";
/// Trap leaves typed as rustc's arithmetic overflow check.
const M_ARITH_OVERFLOW: &str = "refine_arith_overflows";
const M_DIVISION_GUARD: &str = "refine_division_guards";

/// What a re-run of this pass inside the elision group has to say. The
/// division guards it can only classify once the 128-bit division they
/// stand in front of has been recovered, which happens in that group; the
/// bare/unwrap split was settled on the first run and re-reporting it
/// would double every count.
pub const RESOLUTION_COUNTERS: &[&str] = &[M_DIVISION_GUARD];

/// The `Val` tag mask — a cond comparing `x & 0xFF` against a constant
/// is the SDK's small-vs-object tag dispatch, i.e. an unwrap shape.
const VAL_TAG_MASK: i64 = 0xFF;

/// The panic-recovery pass. Stateless; see the module docs.
#[derive(Debug, Default, Clone, Copy)]
pub struct PanicRecoverPass;

impl Pass<HighIr> for PanicRecoverPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let mut stats = Stats::default();
        for func in &mut ir.functions {
            let region = std::mem::replace(&mut func.region, Region::Unreachable);
            let func_id = func.id;
            func.region = recover(region, func, func_id, &mut stats, &mut result);
        }
        if stats.bare > 0 {
            result.metrics.increment(M_BARE, stats.bare);
            result.changed = true;
        }
        if stats.unwraps > 0 {
            result.metrics.increment(M_UNWRAP, stats.unwraps);
            result.changed = true;
        }
        if stats.division_guards > 0 {
            result.metrics.increment(M_DIVISION_GUARD, stats.division_guards);
        }
        if stats.arith_overflows > 0 {
            result.metrics.increment(M_ARITH_OVERFLOW, stats.arith_overflows);
            result.changed = true;
        }
        debug_validate(ir, PASS_NAME);
        result
    }
}

#[derive(Default)]
struct Stats {
    bare: i64,
    unwraps: i64,
    arith_overflows: i64,
    division_guards: i64,
}

/// Bottom-up rewrite: children first, then this node's own trap shapes.
fn recover(
    region: Region,
    func: &HighFunction,
    func_id: FuncId,
    stats: &mut Stats,
    result: &mut PassResult,
) -> Region {
    match region {
        Region::Sequence(items) => {
            let mut items: Vec<Region> = items
                .into_iter()
                .map(|item| recover(item, func, func_id, stats, result))
                .collect();
            // Fallthrough trap: `[…, Unreachable]` with a preceding
            // item. (A whole-body bare `Unreachable` never forms a
            // one-item Sequence — `seq` unwraps singletons — so the
            // preceding-item evidence is structural.)
            let tail_is_trap = items.len() >= 2
                && matches!(items.last(), Some(Region::Unreachable))
                && !panics_with_error(&items[..items.len() - 1], func);
            if tail_is_trap {
                // The guard that skips it can name it. `if ok { …;
                // return } panic!()` puts the trap on the `!ok` path,
                // which is how rustc writes a *signed* overflow check —
                // the sign-mask test reads "no overflow" and the
                // fall-through is the trap.
                let kind = items[..items.len() - 1]
                    .last()
                    .and_then(|prev| inverted_guard_kind(prev, func))
                    .unwrap_or(PanicKind::Bare);
                *items.last_mut().expect("checked non-empty") =
                    typed_panic(kind, None, func_id, stats, result);
            }
            Region::Sequence(items)
        }
        Region::Scope { out, body } => Region::Scope {
            out,
            body: Box::new(recover(*body, func, func_id, stats, result)),
        },
        Region::Loop { header, body, kind } => Region::Loop {
            header,
            body: Box::new(recover(*body, func, func_id, stats, result)),
            kind,
        },
        Region::If {
            cond,
            then_region,
            else_region,
        } => {
            let mut then_region = recover(*then_region, func, func_id, stats, result);
            let mut else_region =
                else_region.map(|e| Box::new(recover(*e, func, func_id, stats, result)));
            // Guarded trap, either arm: the else-less guard is D1's
            // canonical output; a trap still sitting in a two-armed
            // `if` (either side) is the D4-asymmetry residue where the
            // condition would not flip. Tag evidence on the condition
            // classifies both — `Eq`/`Ne` both count, so the negated
            // reading is covered.
            retype_trailing_trap(&mut then_region, cond, func, func_id, stats, result);
            if let Some(else_region) = &mut else_region {
                retype_trailing_trap(else_region, cond, func, func_id, stats, result);
            }
            Region::If {
                cond,
                then_region: Box::new(then_region),
                else_region,
            }
        }
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
                    arm.body = recover(arm.body, func, func_id, stats, result);
                    arm
                })
                .collect(),
            default: Box::new(recover(*default, func, func_id, stats, result)),
            dispatch,
        },
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

/// Retype the trailing `Unreachable` of an else-less guard's `then`
/// region (either the leaf itself or a sequence ending in one),
/// classified by the guard condition. Skips trap paths already typed by
/// the `PanicWithError` host-call recognizer.
///
/// ## Re-typing an already-`Bare` trap
///
/// [`recover`] walks children before parents, so an arm shaped
/// `Seq([Basic(…), Unreachable])` — a guard whose trap is reached through
/// panic glue, like rustc's overflow check calling `core::panicking` —
/// has already been typed `Bare` by the *fallthrough* rule below by the
/// time the enclosing `If` is judged. The guard condition is stronger
/// evidence than "this sequence ends in a trap", so it wins.
///
/// Deliberately restricted to upgrading into
/// [`PanicKind::ArithOverflow`]: re-typing `Bare` into `Unwrap` here
/// would also be defensible, but it would shift the bare/unwrap split
/// that `sordec-score`'s semantic category reads, and that is a separate
/// change with its own measurement.
fn retype_trailing_trap(
    then_region: &mut Region,
    cond: ValueId,
    func: &HighFunction,
    func_id: FuncId,
    stats: &mut Stats,
    result: &mut PassResult,
) {
    let kind = classify(cond, func);
    // Only an overflow classification may claim a trap the fallthrough
    // rule has already typed — see the doc comment.
    let retypes_bare = matches!(kind, PanicKind::ArithOverflow | PanicKind::DivisionGuard);
    if retypes_bare && is_bare_panic(then_region) {
        retract_bare(func_id, stats, result);
        *then_region = typed_panic(kind, Some(cond), func_id, stats, result);
        return;
    }
    let trap: &mut Region = match then_region {
        Region::Unreachable => then_region,
        Region::Sequence(items) => {
            let retyping = retypes_bare && items.last().is_some_and(is_bare_panic);
            if !(matches!(items.last(), Some(Region::Unreachable)) || retyping)
                || panics_with_error(&items[..items.len() - 1], func)
            {
                return;
            }
            if retyping {
                retract_bare(func_id, stats, result);
            }
            items.last_mut().expect("checked non-empty")
        }
        _ => return,
    };
    *trap = typed_panic(kind, Some(cond), func_id, stats, result);
}

/// Build the typed leaf, bump the counters, and emit the
/// `PanicWithoutErrorCode` diagnostic for bare sites.
fn typed_panic(
    kind: PanicKind,
    cond: Option<ValueId>,
    func_id: FuncId,
    stats: &mut Stats,
    result: &mut PassResult,
) -> Region {
    match kind {
        PanicKind::Bare => {
            stats.bare += 1;
            let location = match cond {
                Some(cond) => Location::Value {
                    func: func_id,
                    value: cond.index(),
                },
                None => Location::Function(func_id),
            };
            // Info, not warning: a typed bare panic is a successfully
            // recovered fact about the source (it used `panic!()`, not
            // `panic_with_error`), not a recovery miss.
            result.diagnostics.push(
                Diagnostic::info(LiftDiagnosticCode::PanicWithoutErrorCode, "").at(location),
            );
        }
        PanicKind::Unwrap => stats.unwraps += 1,
        PanicKind::ArithOverflow => stats.arith_overflows += 1,
        PanicKind::DivisionGuard => stats.division_guards += 1,
    }
    Region::Panic { kind }
}

/// Classify a guard condition: `Val` tag evidence marks the trap as an
/// unwrap; a carry/borrow test on one arithmetic binding marks it as
/// rustc's overflow check; a test on the operands of a division it stands
/// in front of marks it as that division's guard; anything else is a bare
/// panic.
fn classify(cond: ValueId, func: &HighFunction) -> PanicKind {
    if is_division_guard(func, cond) {
        return PanicKind::DivisionGuard;
    }
    classify_other(cond, func)
}

/// Whether this condition is one of the two checks rustc puts in front of
/// an integer division, tested against the operands of a division this
/// function actually performs.
///
/// ```text
/// eqz(d)                                   → d == 0
/// eqz(lo(n) | (hi(n) ^ i64::MIN))          → n == i128::MIN
/// ```
///
/// The second is only ever reached under `(lo(d) & hi(d)) == -1`, which is
/// `d == -1`; that outer branch carries no trap of its own and falls away
/// once this one does.
///
/// Requiring the tested value to be an operand of a *recovered* division
/// is what makes the elision safe: the reconstruction emits `n / d`, and
/// Rust's `/` panics on both conditions whatever the profile says. A
/// source that wrote its own `if d == 0 { panic!() }` in front of a
/// division would be mistaken for this and lose that line — the program
/// still traps in the same place, on the division, so what is lost is the
/// line and not the behaviour.
fn is_division_guard(func: &HighFunction, cond: ValueId) -> bool {
    let mut numerators = Vec::new();
    let mut divisors = Vec::new();
    for (_, b) in func.bindings.iter() {
        if let Expr::Binary { op: BinaryOp::Div | BinaryOp::Rem, lhs, rhs } = &b.expr {
            numerators.push(resolve_use(func, *lhs));
            divisors.push(resolve_use(func, *rhs));
        }
    }
    if divisors.is_empty() {
        return false;
    }
    let Some(expr) = func.bindings.get(resolve_use(func, cond)).map(|b| &b.expr) else {
        return false;
    };
    match expr {
        // `d == 0`, however the compiler spelled it.
        Expr::Unary { op: UnaryOp::Eqz, value } => zero_test(func, *value, &numerators, &divisors),
        Expr::Binary { op: BinaryOp::Eq, lhs, rhs } => {
            if let Some(other) = against(func, *lhs, *rhs, 0) {
                zero_test(func, other, &numerators, &divisors)
            } else if let Some(other) = against(func, *lhs, *rhs, -1) {
                // `(lo(d) & hi(d)) == -1` is `d == -1`, the other half of
                // the `MIN / -1` pair.
                all_ones(func, other, &divisors)
            } else {
                false
            }
        }
        _ => false,
    }
}

/// The operand compared against the constant `want`, if one is.
fn against(func: &HighFunction, lhs: ValueId, rhs: ValueId, want: i128) -> Option<ValueId> {
    [(lhs, rhs), (rhs, lhs)]
        .into_iter()
        .find_map(|(value, konst)| (trace_int(func, konst) == Some(want)).then_some(value))
}

/// Whether testing this value against zero is one of the two checks: the
/// divisor being zero, or the numerator being `i128::MIN`.
fn zero_test(
    func: &HighFunction,
    value: ValueId,
    numerators: &[ValueId],
    divisors: &[ValueId],
) -> bool {
    let tested = resolve_use(func, value);
    if divisors.contains(&tested) {
        return true;
    }
    // `lo(n) | (hi(n) ^ i64::MIN)`, in either operand order.
    let Some(Expr::Binary { op: BinaryOp::BitOr, lhs, rhs }) =
        func.bindings.get(tested).map(|b| &b.expr)
    else {
        return false;
    };
    [(*lhs, *rhs), (*rhs, *lhs)].into_iter().any(|(low, high)| {
        limb_of(func, low, UnaryOp::WideLo)
            .zip(min_xor(func, high))
            .is_some_and(|(a, b)| a == b && numerators.contains(&a))
    })
}

/// Whether this is `lo(d) & hi(d)` for a divisor `d` — all ones in both
/// halves is `d == -1`.
fn all_ones(func: &HighFunction, value: ValueId, divisors: &[ValueId]) -> bool {
    let Some(Expr::Binary { op: BinaryOp::BitAnd, lhs, rhs }) =
        func.bindings.get(resolve_use(func, value)).map(|b| &b.expr)
    else {
        return false;
    };
    [(*lhs, *rhs), (*rhs, *lhs)].into_iter().any(|(low, high)| {
        limb_of(func, low, UnaryOp::WideLo)
            .zip(limb_of(func, high, UnaryOp::WideHi))
            .is_some_and(|(a, b)| a == b && divisors.contains(&a))
    })
}

/// The value `half(x)` names, when it is that half of something.
fn limb_of(func: &HighFunction, value: ValueId, want: UnaryOp) -> Option<ValueId> {
    match &func.bindings.get(resolve_use(func, value))?.expr {
        Expr::Unary { op, value } if *op == want => Some(resolve_use(func, *value)),
        _ => None,
    }
}

/// The value `hi(x) ^ i64::MIN` names.
fn min_xor(func: &HighFunction, value: ValueId) -> Option<ValueId> {
    let Expr::Binary { op: BinaryOp::BitXor, lhs, rhs } =
        &func.bindings.get(resolve_use(func, value))?.expr
    else {
        return None;
    };
    [(*lhs, *rhs), (*rhs, *lhs)].into_iter().find_map(|(half, mask)| {
        (trace_int(func, mask) == Some(i128::from(i64::MIN))).then(|| limb_of(func, half, UnaryOp::WideHi))?
    })
}

fn classify_other(cond: ValueId, func: &HighFunction) -> PanicKind {
    // Through any `Use` chain: an elision that replaced a load with the
    // value it read leaves the guard's condition one alias away from the
    // expression that classifies it.
    let cond = resolve_use(func, cond);
    let Some(binding) = func.bindings.get(cond) else {
        return PanicKind::Bare;
    };
    match &binding.expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck { .. })) => PanicKind::Unwrap,
        // The 128-bit multiply's overflow flag, recovered from the
        // `__muloti4` out-pointer. It is rustc's own check by
        // construction — nothing else produces this expression.
        Expr::Binary { op: BinaryOp::MulOverflows, .. } => PanicKind::ArithOverflow,
        // The raw shape the tag-check recognizer leaves on i64-typed
        // paths: `(x & 0xFF) ==/!= tag`.
        Expr::Binary {
            op: BinaryOp::Eq | BinaryOp::Ne,
            lhs,
            rhs,
        } if is_tag_mask(func, *lhs) || is_tag_mask(func, *rhs) => PanicKind::Unwrap,
        Expr::Binary {
            op: BinaryOp::Lt | BinaryOp::Gt,
            lhs,
            rhs,
        } if is_overflow_test(func, *lhs, *rhs) => PanicKind::ArithOverflow,
        Expr::Binary { op: BinaryOp::Eq, lhs, rhs } if is_increment_overflow_test(func, *lhs, *rhs) => {
            PanicKind::ArithOverflow
        }
        _ => PanicKind::Bare,
    }
}

/// The kind a trailing trap takes from the guard that skips past it.
///
/// Only the overflow classification is read this way round, and only
/// off a comparison rustc does not write in the other direction: the
/// sign-mask test for a signed `+`/`-`, whose "no overflow" reading
/// guards the work and leaves the trap to fall through. Anything else
/// stays `Bare`, which is what a trailing trap was before.
fn inverted_guard_kind(prev: &Region, func: &HighFunction) -> Option<PanicKind> {
    let Region::If { cond, then_region, else_region: None } = prev else {
        return None;
    };
    if !super::is_terminating(then_region) {
        return None;
    }
    match &func.bindings.get(resolve_use(func, *cond))?.expr {
        Expr::Binary { op: BinaryOp::Ge | BinaryOp::Le, lhs, rhs }
            if is_overflow_test(func, *lhs, *rhs) =>
        {
            Some(PanicKind::ArithOverflow)
        }
        Expr::Binary { op: BinaryOp::Ne, lhs, rhs } if is_increment_overflow_test(func, *lhs, *rhs) => {
            Some(PanicKind::ArithOverflow)
        }
        _ => None,
    }
}

/// Whether comparing `x` against `y` is the overflow test of an unsigned
/// `v + 1`: `v` against all ones, where the function also computes `v + 1`.
///
/// LLVM folds the carry test `v + 1 <u v` to `v == MAX`, so the sum is no
/// longer one of the compared values and [`is_overflow_test`] cannot see
/// it. Derivation is still the discriminator: the compared value is one
/// addend of an increment the function performs.
fn is_increment_overflow_test(func: &HighFunction, x: ValueId, y: ValueId) -> bool {
    let all_ones = |c: ValueId| matches!(trace_int(func, c), Some(-1) | Some(0xFFFF_FFFF) | Some(0xFFFF_FFFF_FFFF_FFFF));
    let incremented = |v: ValueId| {
        func.bindings.iter().any(|(_, b)| {
            matches!(
                &b.expr,
                Expr::Binary { op: BinaryOp::Add, lhs, rhs }
                    if (resolve_use(func, *lhs) == v && trace_int(func, *rhs) == Some(1))
                        || (resolve_use(func, *rhs) == v && trace_int(func, *lhs) == Some(1))
            )
        })
    };
    let (x, y) = (resolve_use(func, x), resolve_use(func, y));
    (all_ones(y) && incremented(x)) || (all_ones(x) && incremented(y))
}

/// Whether comparing `x` against `y` is rustc's arithmetic overflow test.
///
/// Under `overflow-checks = true` rustc guards every `+`/`-` with a
/// wrapping op plus a comparison. The two shapes are not alike, and both
/// appear in the corpus:
///
/// ```text
/// s = a + b;  if s <u a { trap }      <- add carry: result vs own operand
/// if a <u b { trap };  d = a - b      <- sub borrow: the two operands
/// ```
///
/// **The discriminator is derivation, not shape.** A contract's own
/// `if balance < amount { … }` compares two values that no single
/// arithmetic binding relates, so it is not matched — which is the whole
/// safety of this classification, because the two read identically at the
/// comparison alone.
///
/// Deliberately requires the operands to be *the same binding's*, not
/// merely "some add exists nearby": the corpus census found 5 matches
/// against 122 comparison guards it declines.
fn is_overflow_test(func: &HighFunction, x: ValueId, y: ValueId) -> bool {
    let (x, y) = (resolve_use(func, x), resolve_use(func, y));
    // signed overflow — a sign-mask test against zero. The mask is built
    // from one addition or subtraction's own operands, so derivation is
    // still the discriminator.
    if (trace_int(func, y) == Some(0) && is_signed_overflow_mask(func, x))
        || (trace_int(func, x) == Some(0) && is_signed_overflow_mask(func, y))
    {
        return true;
    }
    // add carry — one side is the sum, the other is one of its addends.
    let carries = |sum: ValueId, addend: ValueId| {
        matches!(
            arith_operands(func, sum),
            Some((BinaryOp::Add, a, b)) if a == addend || b == addend
        )
    };
    if carries(x, y) || carries(y, x) {
        return true;
    }
    // sub borrow — the compared pair are the operands of one subtraction.
    //
    // Only on unsigned values: rustc's signed subtraction overflows by sign,
    // which the mask test above reads, so `a < b` before a signed `a - b` is
    // the author's own check. atomic_swap's `if amount_a < min_a_for_b {
    // panic!(..) }` precedes `amount_a - min_a_for_b` on `i128`s, and reading
    // it as the borrow test deleted it.
    let signed = |v: ValueId| {
        matches!(
            func.bindings.get(v).map(|b| &b.ty),
            Some(IrType::Known(KnownType::I128 | KnownType::I256) | IrType::Inferred(KnownType::I128 | KnownType::I256))
        )
    };
    if signed(x) || signed(y) {
        return false;
    }
    func.bindings.iter().any(|(_, binding)| {
        matches!(
            &binding.expr,
            Expr::Binary { op: BinaryOp::Sub, lhs, rhs }
                if resolve_use(func, *lhs) == x && resolve_use(func, *rhs) == y
        )
    })
}

/// Whether `mask` is rustc's signed-overflow sign mask for one `+`/`-`.
///
/// For signed integers the carry test does not work, and rustc emits the
/// textbook sign test instead, on the high limb of an `i128` as much as on
/// an `i64`:
///
/// ```text
/// s = a + b;  if ((s ^ a) & (s ^ b)) < 0 { trap }   <- both operands' signs
///                                                     differ from the sum's
/// s = a - b;  if ((a ^ b) & (a ^ s)) < 0 { trap }   <- operands' signs differ
///                                                     and the result's flipped
/// ```
///
/// Same rule as the unsigned shapes: the two xors must be built from *one*
/// arithmetic binding and its own operands. Any other and-of-xors is the
/// contract's arithmetic.
fn is_signed_overflow_mask(func: &HighFunction, mask: ValueId) -> bool {
    let Some(Expr::Binary { op: BinaryOp::BitAnd, lhs, rhs }) =
        func.bindings.get(mask).map(|b| &b.expr)
    else {
        return false;
    };
    let (Some(p), Some(q)) = (xor_pair(func, *lhs), xor_pair(func, *rhs)) else {
        return false;
    };
    let same = |x: (ValueId, ValueId), u: ValueId, w: ValueId| {
        (x.0 == u && x.1 == w) || (x.0 == w && x.1 == u)
    };
    // Every add/sub in the function whose operands and result account for
    // all four xor operands, in the shapes above (operand order free).
    func.bindings.iter().any(|(sum, binding)| {
        let Some((op, a, b)) = chain_operands(func, sum, &binding.expr) else {
            return false;
        };
        match (op, p.negated, q.negated) {
            // (s ^ a) & (s ^ b)
            (BinaryOp::Add, false, false) => {
                (same(p.pair, sum, a) && same(q.pair, sum, b))
                    || (same(p.pair, sum, b) && same(q.pair, sum, a))
            }
            // !(a ^ b) & (a ^ s) — the same test with the operand-sign
            // agreement written as a negation.
            (BinaryOp::Add, true, false) => {
                same(p.pair, a, b) && (same(q.pair, a, sum) || same(q.pair, b, sum))
            }
            (BinaryOp::Add, false, true) => {
                same(q.pair, a, b) && (same(p.pair, a, sum) || same(p.pair, b, sum))
            }
            // (a ^ b) & (a ^ s)
            (BinaryOp::Sub, false, false) => {
                (same(p.pair, a, b) && same(q.pair, a, sum))
                    || (same(q.pair, a, b) && same(p.pair, a, sum))
            }
            _ => false,
        }
    })
}

/// One side of the sign mask: an xor of two values, possibly complemented
/// (`xor x, -1`), which is how rustc spells "the signs agree".
struct XorPair {
    pair: (ValueId, ValueId),
    negated: bool,
}

fn xor_pair(func: &HighFunction, v: ValueId) -> Option<XorPair> {
    let Expr::Binary { op: BinaryOp::BitXor, lhs, rhs } =
        &func.bindings.get(resolve_use(func, v))?.expr
    else {
        return None;
    };
    if trace_int(func, *rhs) == Some(-1) {
        let inner = xor_pair(func, *lhs)?;
        return Some(XorPair { pair: inner.pair, negated: !inner.negated });
    }
    Some(XorPair {
        pair: (resolve_use(func, *lhs), resolve_use(func, *rhs)),
        negated: false,
    })
}

/// The operator and the two original operands of an add/sub, seeing
/// through the carry or borrow link rustc appends for the high limb of a
/// wide value: `(a + b) + carry` and `(a - b) - borrow` are the add and
/// the sub of `a` and `b`, and the overflow test is written against the
/// outer result.
fn chain_operands(
    func: &HighFunction,
    _sum: ValueId,
    expr: &Expr,
) -> Option<(BinaryOp, ValueId, ValueId)> {
    let Expr::Binary { op: op @ (BinaryOp::Add | BinaryOp::Sub), lhs, rhs } = expr else {
        return None;
    };
    let (x, y) = (resolve_use(func, *lhs), resolve_use(func, *rhs));
    if let Some(Expr::Binary { op: inner, lhs: a, rhs: b }) = func.bindings.get(x).map(|b| &b.expr)
        && inner == op
    {
        return Some((*op, resolve_use(func, *a), resolve_use(func, *b)));
    }
    Some((*op, x, y))
}

/// `value`'s arithmetic operator and its two resolved operands, when it is
/// an `Add` or `Sub`.
fn arith_operands(
    func: &HighFunction,
    value: ValueId,
) -> Option<(BinaryOp, ValueId, ValueId)> {
    let Expr::Binary {
        op: op @ (BinaryOp::Add | BinaryOp::Sub),
        lhs,
        rhs,
    } = &func.bindings.get(value)?.expr
    else {
        return None;
    };
    Some((*op, resolve_use(func, *lhs), resolve_use(func, *rhs)))
}

/// Undo the fallthrough rule's `Bare` typing of a trap that the guard
/// condition has since claimed.
///
/// [`recover`] walks children before parents, so the fallthrough rule has
/// already counted the trap *and* emitted its `PanicWithoutErrorCode`
/// diagnostic by the time the enclosing `If` re-classifies it. Both have
/// to come back, or `sordec coverage` reports a bare panic that the
/// emitted crate does not contain.
///
/// The diagnostic is identified by code plus location: the fallthrough
/// rule records `Location::Function` (it has no condition to point at),
/// while every condition-classified one records `Location::Value`. So the
/// last function-located entry for this function is exactly the one just
/// pushed.
fn retract_bare(func_id: FuncId, stats: &mut Stats, result: &mut PassResult) {
    stats.bare -= 1;
    let retracting = result.diagnostics.iter().rposition(|d| {
        d.code == LiftDiagnosticCode::PanicWithoutErrorCode.into()
            && d.location == Some(Location::Function(func_id))
    });
    if let Some(index) = retracting {
        result.diagnostics.remove(index);
    }
}

/// A trap leaf the fallthrough rule already typed as a bare panic.
fn is_bare_panic(region: &Region) -> bool {
    matches!(
        region,
        Region::Panic {
            kind: PanicKind::Bare
        }
    )
}

/// Is `value` an `x & 0xFF` masking of the `Val` tag byte?
fn is_tag_mask(func: &HighFunction, value: ValueId) -> bool {
    let Some(binding) = func.bindings.get(value) else {
        return false;
    };
    let Expr::Binary {
        op: BinaryOp::BitAnd,
        lhs,
        rhs,
    } = &binding.expr
    else {
        return false;
    };
    [lhs, rhs].into_iter().any(|&operand| {
        func.bindings.get(operand).is_some_and(|b| {
            matches!(
                b.expr,
                Expr::Literal(Literal::I64(VAL_TAG_MASK) | Literal::I32(0xFF))
            )
        })
    })
}

/// Does any `Basic` block in `items` schedule a `PanicWithError`
/// binding? Those trap paths are already typed at the host-call level.
fn panics_with_error(items: &[Region], func: &HighFunction) -> bool {
    let mut found = false;
    for item in items {
        item.for_each_node(|node| {
            if let Region::Basic(b) = node
                && !found
                && let Some(block) = func.blocks.get(*b)
            {
                found = block.bindings.iter().any(|&v| {
                    func.bindings.get(v).is_some_and(|binding| {
                        matches!(
                            binding.expr,
                            Expr::Semantic(SemanticOp::Known(KnownOp::PanicWithError { .. }))
                        )
                    })
                });
            }
        });
        if found {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{
        Arena, BlockId, IrId, Provenance, ProvenanceSource, UnknownReason,
    };
    use sordec_ir::{Binding, HighBlock, IrType, MemoryImage, WasmFacts, WasmOpcodeKind};

    fn v(i: u32) -> ValueId {
        ValueId::from_index(i)
    }
    fn bb(i: u32) -> BlockId {
        BlockId::from_index(i)
    }
    fn binding(id: u32, expr: Expr) -> Binding {
        Binding::new(
            v(id),
            IrType::Unknown(UnknownReason::UpstreamUnknown),
            expr,
            Provenance::new("test", ProvenanceSource::DataFlow, ""),
        )
    }

    /// One function: block 0 schedules `bindings`, region as given.
    fn func_of(bindings: Vec<Binding>, region: Region) -> HighFunction {
        let scheduled = bindings.iter().map(|b| b.id).collect();
        let mut arena: Arena<ValueId, Binding> = Arena::new();
        for b in bindings {
            arena.push(b);
        }
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        blocks.push(HighBlock {
            id: bb(0),
            bindings: scheduled,
        });
        HighFunction {
            id: FuncId::from_index(0),
            name: None,
            signature: None,
            aliases: Vec::new(),
            blocks,
            bindings: arena,
            region,
            params: vec![],
            returns: vec![],
        }
    }

    fn run_pass(func: HighFunction) -> (HighFunction, PassResult) {
        let mut ir = HighIr {
            facts: WasmFacts {
                imports: vec![],
                exports: vec![],
                function_type_indices: vec![],
                function_bodies: vec![],
                function_fingerprints: vec![],
                custom_sections: vec![],
            },
            soroban_facts: None,
            functions: vec![func],
            memory: MemoryImage::empty(),
        };
        let result = PanicRecoverPass.run(&mut ir);
        (ir.functions.pop().expect("one function"), result)
    }

    /// `q = n / d`, with `n` and `d` built from their halves so the
    /// guards have something to name. `cond` is the guard condition under
    /// test, at v10.
    fn division_with_guard(cond: Expr) -> HighFunction {
        let bindings = vec![
            binding(0, Expr::Phi { incoming: vec![] }), // n
            binding(1, Expr::Phi { incoming: vec![] }), // d
            binding(2, Expr::Unary { op: UnaryOp::WideLo, value: v(0) }),
            binding(3, Expr::Unary { op: UnaryOp::WideHi, value: v(0) }),
            binding(4, Expr::Unary { op: UnaryOp::WideLo, value: v(1) }),
            binding(5, Expr::Unary { op: UnaryOp::WideHi, value: v(1) }),
            binding(6, Expr::Literal(Literal::I64(i64::MIN))),
            binding(7, Expr::Literal(Literal::I64(-1))),
            binding(8, Expr::Binary { op: BinaryOp::BitXor, lhs: v(3), rhs: v(6) }),
            binding(9, Expr::Binary { op: BinaryOp::BitAnd, lhs: v(4), rhs: v(5) }),
            binding(10, cond),
            binding(11, Expr::Binary { op: BinaryOp::Div, lhs: v(0), rhs: v(1) }),
        ];
        func_of(
            bindings,
            Region::Sequence(vec![Region::Basic(bb(0)), guard(10, Region::Unreachable)]),
        )
    }

    fn kind_of(func: HighFunction) -> PanicKind {
        let (func, _) = run_pass(func);
        let mut found = PanicKind::Bare;
        func.region.for_each_node(|node| {
            if let Region::Panic { kind } = node {
                found = *kind;
            }
        });
        found
    }

    /// `a < b` in front of `a - b`: rustc's borrow test on unsigned values,
    /// and the author's own check on signed ones, which overflow by sign.
    fn compare_then_subtract(ty: KnownType) -> HighFunction {
        let mut a = binding(0, Expr::Phi { incoming: vec![] });
        let mut b = binding(1, Expr::Phi { incoming: vec![] });
        a.ty = IrType::Known(ty.clone());
        b.ty = IrType::Known(ty);
        let bindings = vec![
            a,
            b,
            binding(2, Expr::Binary { op: BinaryOp::Lt, lhs: v(0), rhs: v(1) }),
            binding(3, Expr::Binary { op: BinaryOp::Sub, lhs: v(0), rhs: v(1) }),
        ];
        func_of(bindings, Region::Sequence(vec![Region::Basic(bb(0)), guard(2, Region::Unreachable)]))
    }

    #[test]
    fn an_unsigned_compare_before_its_subtraction_is_the_borrow_check() {
        assert_eq!(kind_of(compare_then_subtract(KnownType::U64)), PanicKind::ArithOverflow);
    }

    /// atomic_swap's `if amount_a < min_a_for_b { panic!(..) }` on `i128`s:
    /// the author's check, kept.
    #[test]
    fn a_signed_compare_before_its_subtraction_is_the_authors() {
        assert_eq!(kind_of(compare_then_subtract(KnownType::I128)), PanicKind::Bare);
    }

    /// `d == 0` in front of `n / d`.
    #[test]
    fn a_divisor_zero_test_is_the_divisions_own_guard() {
        let kind = kind_of(division_with_guard(Expr::Unary { op: UnaryOp::Eqz, value: v(1) }));
        assert_eq!(kind, PanicKind::DivisionGuard);
    }

    /// `(lo(d) & hi(d)) == -1` is `d == -1`, the other half of the pair.
    #[test]
    fn a_divisor_minus_one_test_is_too() {
        let kind = kind_of(division_with_guard(Expr::Binary {
            op: BinaryOp::Eq,
            lhs: v(9),
            rhs: v(7),
        }));
        assert_eq!(kind, PanicKind::DivisionGuard);
    }

    /// `lo(n) | (hi(n) ^ i64::MIN) == 0` is `n == i128::MIN`.
    #[test]
    fn a_numerator_min_test_is_too() {
        let bindings_cond =
            Expr::Binary { op: BinaryOp::BitOr, lhs: v(2), rhs: v(8) };
        let mut func = division_with_guard(bindings_cond);
        // Wrap it in the `eqz` the guard actually tests.
        let id = ValueId::from_index(func.bindings.len() as u32);
        func.bindings.push(binding(
            IrId::index(id),
            Expr::Unary { op: UnaryOp::Eqz, value: v(10) },
        ));
        func.blocks.get_mut(bb(0)).unwrap().bindings.push(id);
        func.region = Region::Sequence(vec![
            Region::Basic(bb(0)),
            guard(IrId::index(id), Region::Unreachable),
        ]);
        assert_eq!(kind_of(func), PanicKind::DivisionGuard);
    }

    /// The same shape with no division in the function names nothing.
    #[test]
    fn a_zero_test_without_a_division_stays_bare() {
        let mut func = division_with_guard(Expr::Unary { op: UnaryOp::Eqz, value: v(1) });
        func.bindings.get_mut(v(11)).unwrap().expr = Expr::Phi { incoming: vec![] };
        assert_eq!(kind_of(func), PanicKind::Bare);
    }

    fn guard(cond: u32, then: Region) -> Region {
        Region::If {
            cond: v(cond),
            then_region: Box::new(then),
            else_region: None,
        }
    }

    /// `v0 = load-ish unknown; v1 = v0 & 255; v2 = v1 != 77` — the
    /// muxed-address tag guard shape.
    fn tag_guard_bindings() -> Vec<Binding> {
        vec![
            binding(
                0,
                Expr::Unknown {
                    op_kind: WasmOpcodeKind::Load,
                    args: vec![],
                    reason: UnknownReason::UpstreamUnknown,
                },
            ),
            binding(1, Expr::Literal(Literal::I64(255))),
            binding(
                2,
                Expr::Binary {
                    op: BinaryOp::BitAnd,
                    lhs: v(0),
                    rhs: v(1),
                },
            ),
            binding(3, Expr::Literal(Literal::I64(77))),
            binding(
                4,
                Expr::Binary {
                    op: BinaryOp::Ne,
                    lhs: v(2),
                    rhs: v(3),
                },
            ),
        ]
    }

    #[test]
    fn tag_checked_guard_types_an_unwrap() {
        let func = func_of(
            tag_guard_bindings(),
            Region::Sequence(vec![
                Region::Basic(bb(0)),
                guard(4, Region::Unreachable),
                Region::Return { values: vec![] },
            ]),
        );
        let (func, result) = run_pass(func);
        assert!(result.changed);
        assert_eq!(result.metrics.get(M_UNWRAP), Some(1));
        assert_eq!(result.metrics.get(M_BARE), None);
        assert!(result.diagnostics.is_empty(), "unwraps carry no diagnostic");
        let Region::Sequence(items) = &func.region else {
            panic!("root stays a sequence");
        };
        assert_eq!(
            items[1],
            guard(
                4,
                Region::Panic {
                    kind: PanicKind::Unwrap
                }
            )
        );
    }

    #[test]
    fn plain_guard_types_a_bare_panic_and_diagnoses() {
        // `if v1 { unreachable }` on a non-tag condition (a load).
        let func = func_of(
            vec![
                binding(0, Expr::Literal(Literal::I32(1))),
                binding(
                    1,
                    Expr::Binary {
                        op: BinaryOp::Eq,
                        lhs: v(0),
                        rhs: v(0),
                    },
                ),
            ],
            Region::Sequence(vec![
                Region::Basic(bb(0)),
                guard(1, Region::Unreachable),
                Region::Return { values: vec![] },
            ]),
        );
        let (_, result) = run_pass(func);
        assert_eq!(result.metrics.get(M_BARE), Some(1));
        assert_eq!(result.diagnostics.len(), 1);
        assert_eq!(
            result.diagnostics[0].code,
            sordec_common::DiagnosticCode::Lift(LiftDiagnosticCode::PanicWithoutErrorCode)
        );
    }

    #[test]
    fn guard_with_glue_call_keeps_the_call() {
        // dex shape: `if cond { call func_3; unreachable }` — the glue
        // call stays, only the trap leaf is typed.
        let func = func_of(
            vec![
                binding(0, Expr::Literal(Literal::I32(0))),
                binding(
                    1,
                    Expr::Binary {
                        op: BinaryOp::Eq,
                        lhs: v(0),
                        rhs: v(0),
                    },
                ),
            ],
            Region::Sequence(vec![
                Region::Basic(bb(0)),
                guard(
                    1,
                    Region::Sequence(vec![Region::Basic(bb(0)), Region::Unreachable]),
                ),
            ]),
        );
        // Second Basic(bb0) in the then-arm would be a DuplicateBasic;
        // give the trap path its own block.
        let mut func = func;
        func.blocks.push(HighBlock {
            id: bb(1),
            bindings: vec![],
        });
        let Region::Sequence(items) = &mut func.region else {
            unreachable!()
        };
        let Region::If { then_region, .. } = &mut items[1] else {
            unreachable!()
        };
        **then_region = Region::Sequence(vec![Region::Basic(bb(1)), Region::Unreachable]);

        let (func, result) = run_pass(func);
        assert_eq!(result.metrics.get(M_BARE), Some(1));
        let Region::Sequence(items) = &func.region else {
            panic!("root stays a sequence");
        };
        let Region::If { then_region, .. } = &items[1] else {
            panic!("guard survives");
        };
        assert_eq!(
            **then_region,
            Region::Sequence(vec![
                Region::Basic(bb(1)),
                Region::Panic {
                    kind: PanicKind::Bare
                }
            ])
        );
    }

    #[test]
    fn fallthrough_trap_after_hoisted_guard_types_bare() {
        // `if ok { return }; unreachable` — the hoisted-guard residue.
        let func = func_of(
            vec![
                binding(0, Expr::Literal(Literal::I32(1))),
                binding(
                    1,
                    Expr::Binary {
                        op: BinaryOp::Ne,
                        lhs: v(0),
                        rhs: v(0),
                    },
                ),
            ],
            Region::Sequence(vec![
                Region::Basic(bb(0)),
                guard(1, Region::Return { values: vec![] }),
                Region::Unreachable,
            ]),
        );
        let (func, result) = run_pass(func);
        assert_eq!(result.metrics.get(M_BARE), Some(1));
        let Region::Sequence(items) = &func.region else {
            panic!("root stays a sequence");
        };
        assert_eq!(
            *items.last().expect("tail"),
            Region::Panic {
                kind: PanicKind::Bare
            }
        );
    }

    #[test]
    fn else_arm_trap_types_too() {
        // The D4-asymmetry residue: `if c { break-ish } else
        // { unreachable }` — the condition would not flip, but the
        // else-arm trap is still a panic path.
        let func = func_of(
            tag_guard_bindings(),
            Region::Sequence(vec![
                Region::Basic(bb(0)),
                Region::If {
                    cond: v(4),
                    then_region: Box::new(Region::Return { values: vec![] }),
                    else_region: Some(Box::new(Region::Unreachable)),
                },
            ]),
        );
        let (func, result) = run_pass(func);
        assert_eq!(result.metrics.get(M_UNWRAP), Some(1));
        let Region::Sequence(items) = &func.region else {
            panic!("root stays a sequence");
        };
        let Region::If { else_region, .. } = &items[1] else {
            panic!("if survives");
        };
        assert_eq!(
            **else_region.as_ref().expect("else kept"),
            Region::Panic {
                kind: PanicKind::Unwrap
            }
        );
    }

    #[test]
    fn whole_body_bare_trap_stays_untyped() {
        // The terminal abort helper: body = a single Unreachable. No
        // evidence of a source panic — stays anonymous.
        let func = func_of(vec![], Region::Unreachable);
        let (func, result) = run_pass(func);
        assert!(!result.changed);
        assert_eq!(func.region, Region::Unreachable);
    }

    #[test]
    fn panic_with_error_path_is_left_to_the_recognizer() {
        // The trap path's block carries a PanicWithError binding — the
        // host-call recognizer already typed this panic, with its error
        // code; the region leaf stays.
        let func = func_of(
            vec![
                binding(0, Expr::Literal(Literal::I32(1))),
                binding(
                    1,
                    Expr::Semantic(SemanticOp::Known(KnownOp::PanicWithError { error: v(0) })),
                ),
            ],
            Region::Sequence(vec![Region::Basic(bb(0)), Region::Unreachable]),
        );
        let (func, result) = run_pass(func);
        assert!(!result.changed);
        let Region::Sequence(items) = &func.region else {
            panic!("root stays a sequence");
        };
        assert_eq!(*items.last().expect("tail"), Region::Unreachable);
    }

    #[test]
    fn second_run_is_idempotent() {
        let func = func_of(
            tag_guard_bindings(),
            Region::Sequence(vec![
                Region::Basic(bb(0)),
                guard(4, Region::Unreachable),
                Region::Return { values: vec![] },
            ]),
        );
        let (func, first) = run_pass(func);
        assert!(first.changed);
        let (_, second) = run_pass(func);
        assert!(!second.changed, "typed leaves never re-fire");
    }
}
