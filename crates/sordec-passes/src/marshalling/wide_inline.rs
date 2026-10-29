//! The SDK's 128-bit `TryFromVal`, inlined: its limbs are the value's.
//!
//! # The shape
//!
//! [`super::wide_codec`] collapses the decode when rustc outlines it into a
//! helper that stores the two limbs through an out-pointer. When rustc
//! inlines it instead — an entrypoint `fn f(v: i128)` that does nothing
//! but hand `v` on is the common case — the same limbs are computed on two
//! arms of the caller's own body and merged at the join:
//!
//! ```text
//! if has_tag(v, I128Object) {
//!     hi = obj_to_i128_hi64(v)               hi = wide_hi(v)
//!     lo = obj_to_i128_lo64(v)               lo = wide_lo(v)
//! } else {                               →
//!     hi = v >> 63                           hi = wide_hi(v)
//!     lo = val_decode(v)                     lo = wide_lo(v)
//! }
//! (lo, hi) merged at the join                the merge of one value: that value
//! ```
//!
//! Left alone, the merged limbs are typed as 64-bit words, the `v >> 63` is
//! read as an `i128` shift of the parameter, and a returned value comes back
//! as its low limb: a function declared to return `i128` returns `u64`.
//!
//! # Why it is exact
//!
//! Per limb, on the path that computes it. Where `v` is in the object form,
//! the host's piece extractors return the value's two halves. Where it is
//! in the small form, the `Val`'s 56-bit body *is* the value: `val_decode`
//! (the body shifted down) is its low limb, and for an `i128` the high limb
//! is the body's sign — `v >> 63`, an arithmetic shift of the word, whose
//! top bit is the body's top bit. So each limb read is `wide_lo(v)` or
//! `wide_hi(v)` on every path that evaluates it, and naming it so changes
//! nothing that is computed.
//!
//! The rewrite gives each half one binding, scheduled where `v` is defined,
//! and turns every limb read into a use of it. Both arms of a merge then
//! carry the same value, which is what lets the trivial-merge pass retire
//! it, and what lets [`super::wide_encode`] see a re-encode of the same
//! limbs and fold it back to `v`.
//!
//! # Gates
//!
//! - **The value is proven 128-bit at a boundary** — the evidence rule of
//!   [`super::wide_codec`]: an entrypoint parameter `contractspecv0`
//!   declares at that type, or a value another recognizer proved. That is
//!   also what makes "not the object form" mean "the small form": the host
//!   only hands over one of the two.
//! - **Every tag tested on it is one of the type's pair.** A value also
//!   tested for anything else is being read as something else.
//! - **Each limb sits in the arm of its form.** A small-form read (the
//!   decode, the shift) only where a tag test on the value has established
//!   the small form; an extractor only where one has established the
//!   object form. "Established" is read off the region: inside the arm of
//!   the test, or after a test whose other arm never falls through (the
//!   guarded `break` the structurer emits before it rebuilds the `else`).
//!   A `v >> 63` anywhere else is arithmetic on a `Val`, not a decode, and
//!   an extractor outside its arm could trap, which the value cannot. A
//!   function with a goto-style fragment is skipped whole: a position in
//!   it says nothing about the branch taken to reach it.
//! - **Extractor and type agree**, and `v >> 63` only for an `i128`: a
//!   `u128` in its small form has no high half to compute.
//! - **All or nothing per value.** One read that fails a gate leaves every
//!   read of that value as it was.
//! - **Not the outlined decoder itself**, whose stores [`super::wide_codec`]
//!   reads to recognize it.

use std::collections::{BTreeMap, HashMap};

use sordec_common::{BlockId, IrId, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{
    BinaryOp, Binding, Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Region, SemanticOp, UnaryOp,
    ValObjectKind,
};

use super::wide_codec::{limb_of, tested_tags, value_evidence, KnownType128, Limb};
use crate::dataflow::{resolve_use, trace_int};
use crate::metrics_catalog::MARSHALLING_WIDE_DECODES_INLINE as M_INLINE;
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-wide-inline-decode";

/// Names the limb reads of an inlined 128-bit decode as the value's halves.
#[derive(Debug, Default, Clone, Copy)]
pub struct WideInlineDecodePass;

impl Pass<HighIr> for WideInlineDecodePass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            if super::wide_codec::decoded_wide_type(func).is_some() {
                continue;
            }
            for plan in plans(func) {
                let count = plan.lo.len() + plan.hi.len();
                if apply(func, plan) {
                    result.metrics.increment(M_INLINE, count as i64);
                    result.changed = true;
                }
            }
        }
        result
    }
}

/// Which encoding of the value a path has established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Form {
    Small,
    Object,
}

/// One value's limb reads, every one of them proven.
struct Plan {
    val: ValueId,
    evidence: IrType,
    lo: Vec<ValueId>,
    hi: Vec<ValueId>,
}

fn plans(func: &HighFunction) -> Vec<Plan> {
    let block_of: HashMap<ValueId, BlockId> = func
        .blocks
        .iter()
        .flat_map(|(b, block)| block.bindings.iter().map(move |v| (*v, b)))
        .collect();
    // Limb reads by the value they read, in arena order. Only scheduled
    // bindings: one no block holds is never evaluated.
    let mut reads: BTreeMap<ValueId, Vec<(ValueId, Limb)>> = BTreeMap::new();
    for (id, binding) in func.bindings.iter() {
        if !block_of.contains_key(&id) {
            continue;
        }
        if let Some((val, limb)) = limb_read(func, id, &binding.expr) {
            reads.entry(val).or_default().push((id, limb));
        }
    }
    // A goto-style fragment can enter anywhere, so no position in it says
    // which branch was taken to get there.
    let mut unstructured = false;
    func.region.for_each_node(|n| unstructured |= matches!(n, Region::Unstructured { .. }));
    if reads.is_empty() || unstructured {
        return Vec::new();
    }
    let arms = arm_conditions(&func.region);
    let mut out = Vec::new();
    for (val, limbs) in reads {
        let tags = tested_tags(func, val);
        if tags.is_empty() {
            continue;
        }
        let Some(ty) = KnownType128::of_tags(&tags) else {
            continue;
        };
        let Some(evidence) = value_evidence(func, val, &ty.known(), &tags) else {
            continue;
        };
        let proven = |(id, limb): &(ValueId, Limb)| {
            let (form, limb_ty) = match *limb {
                Limb::Lo(None) => (Form::Small, None),
                Limb::Hi(None) if ty == KnownType128::I128 => (Form::Small, None),
                Limb::Lo(Some(t)) | Limb::Hi(Some(t)) => (Form::Object, Some(t)),
                _ => return false,
            };
            if limb_ty.is_some_and(|t| t != ty) {
                return false;
            }
            let Some(occurrences) = block_of.get(id).and_then(|b| arms.get(b)) else {
                return false;
            };
            !occurrences.is_empty() && occurrences.iter().all(|conds| form_on(func, conds, val, ty) == Some(form))
        };
        if !limbs.iter().all(proven) {
            continue;
        }
        let (lo, hi): (Vec<_>, Vec<_>) = limbs.iter().partition(|(_, l)| matches!(l, Limb::Lo(_)));
        out.push(Plan {
            val,
            evidence,
            lo: lo.into_iter().map(|(id, _)| id).collect(),
            hi: hi.into_iter().map(|(id, _)| id).collect(),
        });
    }
    out
}

/// The value a binding reads one limb of, and which limb, when it is one
/// of the decode's limb reads: the small decode, an object piece
/// extractor, or the arithmetic shift by 63 that is the small form's sign.
fn limb_read(func: &HighFunction, id: ValueId, expr: &Expr) -> Option<(ValueId, Limb)> {
    let subject = match expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { value })) => *value,
        Expr::Semantic(SemanticOp::Known(KnownOp::ValObject {
            kind:
                ValObjectKind::ObjToI128Lo64
                | ValObjectKind::ObjToI128Hi64
                | ValObjectKind::ObjToU128Lo64
                | ValObjectKind::ObjToU128Hi64,
            args,
        })) => {
            let [value] = args.as_slice() else { return None };
            *value
        }
        // Arithmetic only: a logical shift by 63 is the top bit, not the
        // sign extension.
        Expr::Binary { op: BinaryOp::Shr, lhs, rhs } if trace_int(func, *rhs) == Some(63) => *lhs,
        _ => return None,
    };
    let val = resolve_use(func, subject);
    match limb_of(func, id, val, 0) {
        limb @ (Limb::Lo(_) | Limb::Hi(_)) => Some((val, limb)),
        _ => None,
    }
}

/// For every block, the branch conditions that hold at each place the
/// region holds it: `(cond, true)` inside a `then` arm, `(cond, false)`
/// inside an `else` arm.
///
/// And after a branch one of whose arms never falls through — the guarded
/// `break` wasm spells most `if`/`else` chains with — the rest of the same
/// sequence is reached only through the other arm, so that arm's condition
/// holds there too. Nothing enters a sequence part-way: a `break` leaves
/// to the end of an enclosing scope, which lies outside the sequence that
/// holds it, and a transfer falls through to what follows.
fn arm_conditions(region: &Region) -> HashMap<BlockId, Vec<Vec<(ValueId, bool)>>> {
    fn walk(r: &Region, stack: &mut Vec<(ValueId, bool)>, out: &mut HashMap<BlockId, Vec<Vec<(ValueId, bool)>>>) {
        match r {
            Region::Basic(b) => out.entry(*b).or_default().push(stack.clone()),
            Region::Sequence(items) => {
                let depth = stack.len();
                for item in items {
                    walk(item, stack, out);
                    if let Region::If { cond, then_region, else_region } = item {
                        let else_leaves = else_region.as_deref().is_some_and(never_falls_through);
                        match (never_falls_through(then_region), else_leaves) {
                            (true, false) => stack.push((*cond, false)),
                            (false, true) => stack.push((*cond, true)),
                            _ => {}
                        }
                    }
                }
                stack.truncate(depth);
            }
            Region::Scope { body, .. } | Region::Loop { body, .. } => walk(body, stack, out),
            Region::If { cond, then_region, else_region } => {
                stack.push((*cond, true));
                walk(then_region, stack, out);
                stack.pop();
                if let Some(e) = else_region {
                    stack.push((*cond, false));
                    walk(e, stack, out);
                    stack.pop();
                }
            }
            Region::Switch { arms, default, .. } => {
                for a in arms {
                    walk(&a.body, stack, out);
                }
                walk(default, stack, out);
            }
            _ => {}
        }
    }
    let mut out = HashMap::new();
    walk(region, &mut Vec::new(), &mut out);
    out
}

/// Whether control never reaches the end of `r`: it always breaks,
/// continues, returns or traps first. Conservative — a scope, loop or
/// switch is taken to fall through, since a `break` may end it normally.
fn never_falls_through(r: &Region) -> bool {
    match r {
        Region::Break { .. }
        | Region::Continue { .. }
        | Region::Return { .. }
        | Region::Unreachable
        | Region::Panic { .. } => true,
        Region::Sequence(items) => items.iter().any(never_falls_through),
        Region::If { then_region, else_region, .. } => {
            never_falls_through(then_region) && else_region.as_deref().is_some_and(never_falls_through)
        }
        _ => false,
    }
}

/// The form of `val` the conditions establish: a tag test on it that holds
/// names its form, one that fails names the other (the value is proven to
/// be one of the two). `None` when no condition tests `val`, or when two
/// disagree.
fn form_on(func: &HighFunction, conds: &[(ValueId, bool)], val: ValueId, ty: KnownType128) -> Option<Form> {
    let (small, object) = ty.tags();
    let mut form = None;
    for (cond, then) in conds {
        let Some(Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck { value, tag, negated }))) =
            func.bindings.get(resolve_use(func, *cond)).map(|b| &b.expr)
        else {
            continue;
        };
        if resolve_use(func, *value) != val {
            continue;
        }
        let holds = *then != *negated;
        let here = match (*tag == small, *tag == object, holds) {
            (true, _, true) | (_, true, false) => Form::Small,
            (true, _, false) | (_, true, true) => Form::Object,
            _ => return None,
        };
        if form.replace(here).is_some_and(|f| f != here) {
            return None;
        }
    }
    form
}

/// One binding per half, where `val` is defined; every limb read becomes a
/// use of it. `false` when there is nowhere to schedule the halves.
fn apply(func: &mut HighFunction, plan: Plan) -> bool {
    let Some((block, at)) = definition_point(func, plan.val) else {
        return false;
    };
    let mut halves = Vec::new();
    for (reads, op, note) in [
        (&plan.lo, UnaryOp::WideLo, "the low limb of a 128-bit value, which its inlined decode reads"),
        (&plan.hi, UnaryOp::WideHi, "the high limb of a 128-bit value, which its inlined decode reads"),
    ] {
        if reads.is_empty() {
            continue;
        }
        let half = ValueId::from_index(func.bindings.len() as u32);
        func.bindings.push(Binding::new(
            half,
            IrType::Inferred(KnownType::I64),
            Expr::Unary { op, value: plan.val },
            Provenance::new(PASS_NAME, ProvenanceSource::SdkPattern, note),
        ));
        halves.push(half);
        for id in reads {
            if let Some(b) = func.bindings.get_mut(*id) {
                b.expr = Expr::Use(half);
                b.ty = IrType::Inferred(KnownType::I64);
                b.add_provenance(Provenance::new(
                    PASS_NAME,
                    ProvenanceSource::SdkPattern,
                    "one limb of an inlined 128-bit decode: the same half of the value",
                ));
            }
        }
    }
    if let Some(block) = func.blocks.get_mut(block) {
        for (i, half) in halves.into_iter().enumerate() {
            block.bindings.insert(at + i, half);
        }
    }
    // The decode was the proof of the value's type, as it is for the
    // outlined helper.
    if let Some(b) = func.bindings.get_mut(plan.val)
        && b.ty != plan.evidence
    {
        b.ty = plan.evidence;
    }
    true
}

/// Where a binding reading `val` can first be scheduled: the top of the
/// entry block for a parameter, right after the definition otherwise.
fn definition_point(func: &HighFunction, val: ValueId) -> Option<(BlockId, usize)> {
    if func.params.contains(&val) {
        return Some((first_block(&func.region)?, 0));
    }
    func.blocks.iter().find_map(|(b, block)| {
        block.bindings.iter().position(|v| *v == val).map(|pos| (b, pos + 1))
    })
}

/// The block the region enters first.
fn first_block(region: &Region) -> Option<BlockId> {
    match region {
        Region::Basic(b) => Some(*b),
        Region::Sequence(items) => items.first().and_then(first_block),
        Region::Scope { body, .. } => first_block(body),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};
    use crate::val_abi;
    use crate::TrivialPhiPass;
    use sordec_ir::{FunctionParam, FunctionSignature, HighBlock, Literal, PrimitiveType, TypeRef};

    fn bb(i: u32) -> BlockId {
        BlockId::from_index(i)
    }
    fn tag_check(value: ValueId, tag: u8) -> Expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck { value, tag, negated: false }))
    }
    fn obj(kind: ValObjectKind, value: ValueId) -> Expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::ValObject { kind, args: vec![value] }))
    }
    fn decode(value: ValueId) -> Expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { value }))
    }

    /// Where the small arm sits relative to the object test.
    #[derive(Clone, Copy)]
    enum Layout {
        /// The `else` arm.
        Else,
        /// After the test, whose object arm breaks out of the scope.
        AfterBreak,
        /// After the test, whose object arm falls through: on every path.
        AfterFallThrough,
        /// Before the test: on every path.
        Before,
    }

    fn i128_inline(declared: Option<PrimitiveType>, small_arm_guarded: bool) -> HighIr {
        i128_laid_out(declared, if small_arm_guarded { Layout::Else } else { Layout::Before })
    }

    /// `fn f(v: i128)`: the object arm extracts both pieces, the small arm
    /// decodes and sign-extends, and the two limbs merge at `bb3`.
    fn i128_laid_out(declared: Option<PrimitiveType>, layout: Layout) -> HighIr {
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                           // v0 v
                tag_check(v(0), val_abi::TAG_I128_OBJECT),                // v1
                obj(ValObjectKind::ObjToI128Hi64, v(0)),                  // v2
                obj(ValObjectKind::ObjToI128Lo64, v(0)),                  // v3
                Expr::Literal(Literal::I64(63)),                          // v4
                Expr::Binary { op: BinaryOp::Shr, lhs: v(0), rhs: v(4) }, // v5
                decode(v(0)),                                             // v6
                Expr::Phi { incoming: vec![(bb(1), v(3)), (bb(2), v(6))] }, // v7 lo
                Expr::Phi { incoming: vec![(bb(1), v(2)), (bb(2), v(5))] }, // v8 hi
            ],
            vec![v(0)],
            vec![1],
        );
        f.blocks.push(HighBlock { id: bb(1), bindings: vec![v(2), v(3)] });
        f.blocks.push(HighBlock { id: bb(2), bindings: vec![v(4), v(5), v(6)] });
        f.blocks.push(HighBlock { id: bb(3), bindings: vec![] });
        let arm = |b: u32, lo: u32, hi: u32| {
            Box::new(Region::Sequence(vec![
                Region::Basic(bb(b)),
                Region::Transfer { target: bb(3), transfer: vec![(v(7), v(lo)), (v(8), v(hi))] },
            ]))
        };
        let branch = Region::If { cond: v(1), then_region: arm(1, 3, 2), else_region: None };
        let leave = |b: u32, lo: u32, hi: u32| {
            Region::Sequence(vec![
                Region::Basic(bb(b)),
                Region::Break { target: bb(3), transfer: vec![(v(7), v(lo)), (v(8), v(hi))] },
            ])
        };
        let tail = [Region::Basic(bb(3)), Region::Return { values: vec![v(7)] }];
        let body = match layout {
            Layout::Else => vec![
                Region::Basic(bb(0)),
                Region::If { cond: v(1), then_region: arm(1, 3, 2), else_region: Some(arm(2, 6, 5)) },
            ],
            Layout::AfterBreak | Layout::AfterFallThrough => {
                let then_region = match layout {
                    Layout::AfterBreak => Box::new(leave(1, 3, 2)),
                    _ => arm(1, 3, 2),
                };
                vec![
                    Region::Basic(bb(0)),
                    Region::Scope {
                        out: bb(3),
                        body: Box::new(Region::Sequence(vec![
                            Region::If { cond: v(1), then_region, else_region: None },
                            leave(2, 6, 5),
                        ])),
                    },
                ]
            }
            Layout::Before => vec![Region::Basic(bb(0)), Region::Basic(bb(2)), branch],
        };
        f.region = Region::Sequence(body.into_iter().chain(tail).collect());
        f.signature = declared.map(|ty| FunctionSignature {
            name: "f".to_string(),
            inputs: vec![FunctionParam { name: "v".to_string(), ty: TypeRef::Primitive(ty) }],
            outputs: vec![],
        });
        module(vec![f])
    }

    fn expr(m: &HighIr, id: ValueId) -> &Expr {
        &m.functions[0].bindings.get(id).unwrap().expr
    }

    /// The half a limb read now names, as `(op, value)`.
    fn half(m: &HighIr, id: ValueId) -> Option<(UnaryOp, ValueId)> {
        let Expr::Use(h) = expr(m, id) else { return None };
        match expr(m, *h) {
            Expr::Unary { op, value } => Some((*op, *value)),
            _ => None,
        }
    }

    #[test]
    fn both_arms_of_an_inlined_i128_decode_read_the_value_halves() {
        let mut m = i128_inline(Some(PrimitiveType::I128), true);
        let r = WideInlineDecodePass.run(&mut m);
        assert!(r.changed);
        assert_eq!(r.metrics.get(M_INLINE), Some(4));
        for id in [v(3), v(6)] {
            assert_eq!(half(&m, id), Some((UnaryOp::WideLo, v(0))), "{id:?}");
        }
        for id in [v(2), v(5)] {
            assert_eq!(half(&m, id), Some((UnaryOp::WideHi, v(0))), "{id:?}");
        }
        // One binding per half, scheduled at the top of the entry block.
        let entry = &m.functions[0].blocks.get(bb(0)).unwrap().bindings;
        assert_eq!(entry.len(), 3);
        assert_eq!(m.functions[0].bindings.get(v(0)).unwrap().ty, IrType::Known(KnownType::I128));
    }

    /// Both arms now carry one value, so the merges are renames.
    #[test]
    fn the_merges_then_retire_to_the_halves() {
        let mut m = i128_inline(Some(PrimitiveType::I128), true);
        WideInlineDecodePass.run(&mut m);
        TrivialPhiPass.run(&mut m);
        let f = &m.functions[0];
        let mut returned = None;
        f.region.for_each_node(|n| {
            if let Region::Return { values } = n {
                returned = values.first().copied();
            }
        });
        let ret = returned.expect("a return");
        assert!(matches!(expr(&m, ret), Expr::Unary { op: UnaryOp::WideLo, value } if *value == v(0)));
    }

    /// The small-form reads outside the arm that tests for the small form:
    /// `v >> 63` there is arithmetic on a `Val`, so nothing of `v` moves.
    #[test]
    fn a_small_read_outside_its_arm_declines() {
        let mut m = i128_inline(Some(PrimitiveType::I128), false);
        assert!(!WideInlineDecodePass.run(&mut m).changed);
        assert!(matches!(expr(&m, v(3)), Expr::Semantic(_)), "all or nothing per value");
    }

    /// The structurer's guarded `break`: the object arm leaves the scope,
    /// so what follows the test runs only on the small form.
    #[test]
    fn a_small_arm_after_a_breaking_object_arm_is_the_small_form() {
        let mut m = i128_laid_out(Some(PrimitiveType::I128), Layout::AfterBreak);
        assert!(WideInlineDecodePass.run(&mut m).changed);
        assert_eq!(half(&m, v(6)), Some((UnaryOp::WideLo, v(0))));
        assert_eq!(half(&m, v(5)), Some((UnaryOp::WideHi, v(0))));
    }

    /// The same, but the object arm falls through into the small reads:
    /// they run on both forms, and are not a decode of either.
    #[test]
    fn a_small_arm_the_object_arm_falls_into_declines() {
        let mut m = i128_laid_out(Some(PrimitiveType::I128), Layout::AfterFallThrough);
        assert!(!WideInlineDecodePass.run(&mut m).changed);
    }

    /// Without a declared type nothing says the `Val` is one of the two
    /// forms, so "not the object" is not "the small form".
    #[test]
    fn an_undeclared_value_declines() {
        let mut m = i128_inline(None, true);
        assert!(!WideInlineDecodePass.run(&mut m).changed);
    }

    /// The declaration has to be the decode's type.
    #[test]
    fn a_mismatched_declaration_declines() {
        let mut m = i128_inline(Some(PrimitiveType::U128), true);
        assert!(!WideInlineDecodePass.run(&mut m).changed);
    }

    /// `fn f(v: u128)`: the small arm has no high half, so only the low
    /// limb merges.
    #[test]
    fn a_u128_decode_merging_its_low_limb_reads_the_value() {
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },               // v0 v
                tag_check(v(0), val_abi::TAG_U128_OBJECT),    // v1
                obj(ValObjectKind::ObjToU128Hi64, v(0)),      // v2
                obj(ValObjectKind::ObjToU128Lo64, v(0)),      // v3
                decode(v(0)),                                 // v4
                Expr::Phi { incoming: vec![(bb(1), v(3)), (bb(2), v(4))] }, // v5
            ],
            vec![v(0)],
            vec![1],
        );
        f.blocks.push(HighBlock { id: bb(1), bindings: vec![v(2), v(3)] });
        f.blocks.push(HighBlock { id: bb(2), bindings: vec![v(4)] });
        f.region = Region::Sequence(vec![
            Region::Basic(bb(0)),
            Region::If {
                cond: v(1),
                then_region: Box::new(Region::Basic(bb(1))),
                else_region: Some(Box::new(Region::Basic(bb(2)))),
            },
        ]);
        f.signature = Some(FunctionSignature {
            name: "f".to_string(),
            inputs: vec![FunctionParam { name: "v".to_string(), ty: TypeRef::Primitive(PrimitiveType::U128) }],
            outputs: vec![],
        });
        let mut m = module(vec![f.clone()]);
        assert!(WideInlineDecodePass.run(&mut m).changed);
        assert_eq!(half(&m, v(3)), Some((UnaryOp::WideLo, v(0))));
        assert_eq!(half(&m, v(4)), Some((UnaryOp::WideLo, v(0))));
        assert_eq!(half(&m, v(2)), Some((UnaryOp::WideHi, v(0))));

        // A `u128`'s small form has no sign to extend: a shift by 63 there
        // is not its high limb.
        f.bindings.push(Binding::new(
            v(6),
            IrType::Unknown(sordec_common::UnknownReason::InsufficientEvidence),
            Expr::Binary { op: BinaryOp::Shr, lhs: v(0), rhs: v(7) },
            Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
        ));
        f.bindings.push(Binding::new(
            v(7),
            IrType::Unknown(sordec_common::UnknownReason::InsufficientEvidence),
            Expr::Literal(Literal::I64(63)),
            Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
        ));
        f.blocks.get_mut(bb(2)).unwrap().bindings.extend([v(7), v(6)]);
        let mut m = module(vec![f]);
        assert!(!WideInlineDecodePass.run(&mut m).changed);
    }

    #[test]
    fn the_pass_is_idempotent() {
        let mut m = i128_inline(Some(PrimitiveType::I128), true);
        assert!(WideInlineDecodePass.run(&mut m).changed);
        assert!(!WideInlineDecodePass.run(&mut m).changed);
    }
}
