//! A helper that returns a `bool` returns it as a `bool`.
//!
//! # The shape
//!
//! rustc hands a `bool` back in an `i32` that is `0` or `1`. A helper the
//! source wrote as `fn is_claimed(e: &Env, index: u32) -> bool` arrives as
//!
//! ```text
//! fn func11(i) {                          fn func11(i) -> bool {
//!     if !has(k) { return 0 }                 if !has(k) { return false }
//!     r = phi [1, 0] on get(k)        →       r = phi [true, false] on get(k)
//!     return r                                return r
//! }                                       }
//! ```
//!
//! and every caller tests the word: `if func11(i) { .. }`, or — in an
//! entrypoint declared `-> bool` — returns it widened to the `Val`,
//! `extend_u32(func11(i))`. Typed as the word it travels in, the helper
//! returns an `i32`, and that entrypoint returns an `i64` where its
//! declaration says `bool`.
//!
//! # The rewrite
//!
//! The helper's returned constants become `false`/`true`, the merges they
//! flow through are typed `bool`, and so is every call's result. The type
//! pass carries it on from there, and [`super::bool_return`] folds the
//! widening the entrypoint returns.
//!
//! # Why it is exact
//!
//! Every value the helper returns is `0` or `1`: each returned value is the
//! constant `0` or `1`, a value already a `bool`, or a merge of those. And
//! every use of a call's result only asks whether it is zero — a branch on
//! it, an `eqz` of it — or widens it into the `Val` an entrypoint declared
//! `-> bool` returns, where `0` and `1` are the encodings of `false` and
//! `true`. Read as a `bool`, `0` is `false` and `1` is `true`, so no use
//! sees a different value.
//!
//! # Gates
//!
//! - **A helper.** No spec signature, and every return hands back one value.
//! - **Only `0`, `1` and `bool`s returned.** Every returned value is one of
//!   the two constants, a value typed `bool` (or built as one: a comparison,
//!   a negation), or a merge of those; at least one is a constant, or there
//!   is nothing to rewrite. Each constant and merge is read by nothing but
//!   the returns and the merges on the way to them.
//! - **Every call only tests it.** In every function, each live read of a
//!   call's result is a branch condition, an `eqz`, or an `extend_u32` that
//!   only an entrypoint declared `-> bool` returns. A signature changes, so
//!   it is every call site or none — and nothing at all when the module has
//!   an indirect call, whose callers cannot be seen.

use std::collections::HashSet;

use sordec_common::{FuncId, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{BinaryOp, Expr, HighFunction, HighIr, IrType, KnownType, Literal, Region, UnaryOp};

use crate::dataflow::resolve_use;
use crate::metrics_catalog::MARSHALLING_BOOL_HELPERS as M_HELPERS;
use crate::pass::{Pass, PassResult};
use crate::type_infer::known_of_type_ref;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-bool-helper";

/// Types a helper that returns only `0`, `1` and `bool`s as returning `bool`.
#[derive(Debug, Default, Clone, Copy)]
pub struct BoolHelperPass;

impl Pass<HighIr> for BoolHelperPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        if ir
            .functions
            .iter()
            .any(|f| f.bindings.iter().any(|(_, b)| matches!(b.expr, Expr::IndirectCall { .. })))
        {
            return result;
        }
        let plans: Vec<(usize, Plan)> = ir
            .functions
            .iter()
            .enumerate()
            .filter_map(|(at, f)| plan(f).map(|p| (at, p)))
            .filter(|(at, _)| every_call_tests(ir, ir.functions[*at].id))
            .collect();
        for (at, plan) in plans {
            let target = ir.functions[at].id;
            let helper = &mut ir.functions[at];
            for (id, b) in plan.constants {
                if let Some(binding) = helper.bindings.get_mut(id) {
                    binding.expr = Expr::Literal(Literal::Bool(b));
                    binding.ty = IrType::Known(KnownType::Bool);
                    binding.add_provenance(Provenance::new(
                        PASS_NAME,
                        ProvenanceSource::DataFlow,
                        "a helper returning only `0`, `1` and `bool`s, every caller testing it: the `bool`",
                    ));
                }
            }
            for id in plan.merges {
                if let Some(binding) = helper.bindings.get_mut(id) {
                    binding.ty = IrType::Inferred(KnownType::Bool);
                    binding.add_provenance(Provenance::new(
                        PASS_NAME,
                        ProvenanceSource::DataFlow,
                        "a merge of the `bool`s a helper returns",
                    ));
                }
            }
            for func in &mut ir.functions {
                let scheduled = scheduled(func);
                for (id, binding) in func.bindings.iter_mut() {
                    if matches!(binding.expr, Expr::Call { target: t, .. } if t == target) && scheduled.contains(&id) {
                        binding.ty = IrType::Inferred(KnownType::Bool);
                        binding.add_provenance(Provenance::new(
                            PASS_NAME,
                            ProvenanceSource::DataFlow,
                            "the call's helper returns a `bool`",
                        ));
                    }
                }
            }
            result.metrics.increment(M_HELPERS, 1);
            result.changed = true;
        }
        result
    }
}

/// What to rewrite in one helper: its returned constants (and the `bool`
/// each becomes) and the merges they flow through.
#[derive(Debug, Default)]
struct Plan {
    constants: Vec<(ValueId, bool)>,
    merges: Vec<ValueId>,
}

/// The rewrite for `func`, when it is a helper returning only `0`, `1`
/// and `bool`s.
fn plan(func: &HighFunction) -> Option<Plan> {
    if func.signature.is_some() {
        return None;
    }
    let mut returned = Vec::new();
    let mut arity_one = true;
    func.region.for_each_node(|node| {
        if let Region::Return { values } = node {
            match values.as_slice() {
                [one] => returned.push(resolve_use(func, *one)),
                _ => arity_one = false,
            }
        }
    });
    if !arity_one || returned.is_empty() {
        return None;
    }
    let mut plan = Plan::default();
    let mut seen = HashSet::new();
    let mut work = returned;
    while let Some(v) = work.pop() {
        if !seen.insert(v) {
            continue;
        }
        let b = func.bindings.get(v)?;
        if bool_like(func, v, 0) {
            continue;
        }
        match &b.expr {
            Expr::Literal(Literal::I32(n @ (0 | 1))) => plan.constants.push((v, *n == 1)),
            Expr::Phi { incoming } if !incoming.is_empty() => {
                plan.merges.push(v);
                work.extend(incoming.iter().map(|(_, a)| resolve_use(func, *a)));
            }
            _ => return None,
        }
    }
    if plan.constants.is_empty() {
        return None;
    }
    // Rewritten in place, so each must be read only on the way out.
    let chain: HashSet<ValueId> =
        plan.constants.iter().map(|(v, _)| *v).chain(plan.merges.iter().copied()).collect();
    let live = scheduled(func);
    for &v in &chain {
        if !read_only_by(func, &live, v, &chain) {
            return None;
        }
    }
    plan.constants.sort_unstable_by_key(|(v, _)| *v);
    plan.merges.sort_unstable();
    Some(plan)
}

/// A `bool` by type or by construction: a comparison, a negation, a test,
/// or a bitwise combination of `bool`s.
fn bool_like(func: &HighFunction, v: ValueId, depth: u32) -> bool {
    let Some(b) = func.bindings.get(v) else { return false };
    if matches!(b.ty, IrType::Known(KnownType::Bool) | IrType::Inferred(KnownType::Bool)) {
        return true;
    }
    if depth > 4 {
        return false;
    }
    match &b.expr {
        Expr::Literal(Literal::Bool(_)) | Expr::IsSome { .. } => true,
        Expr::Binary { op, lhs, rhs } => match op {
            op if op.is_comparison() => true,
            BinaryOp::BitAnd | BinaryOp::BitOr | BinaryOp::BitXor => {
                bool_like(func, resolve_use(func, *lhs), depth + 1) && bool_like(func, resolve_use(func, *rhs), depth + 1)
            }
            _ => false,
        },
        Expr::Unary { op: UnaryOp::Eqz | UnaryOp::Not, .. } => true,
        Expr::Use(inner) => bool_like(func, resolve_use(func, *inner), depth + 1),
        _ => false,
    }
}

/// Every binding the structured body schedules.
fn scheduled(func: &HighFunction) -> HashSet<ValueId> {
    let mut ids = HashSet::new();
    func.region.for_each_node(|node| {
        if let Region::Basic(b) = node
            && let Some(block) = func.blocks.get(*b)
        {
            ids.extend(block.bindings.iter().copied());
        }
    });
    ids
}

/// Nothing reads `v` but a return, a transfer into a merge in `chain`, or a
/// merge in `chain`. Pruning residue left unscheduled is not a reader; a
/// merge is, scheduled or not.
fn read_only_by(func: &HighFunction, live: &HashSet<ValueId>, v: ValueId, chain: &HashSet<ValueId>) -> bool {
    for (id, b) in func.bindings.iter() {
        let is_phi = matches!(b.expr, Expr::Phi { .. });
        if !(live.contains(&id) || is_phi) || chain.contains(&id) {
            continue;
        }
        let mut reads = false;
        b.expr.for_each_value_use(|u| reads |= resolve_use(func, u) == v);
        if reads {
            return false;
        }
    }
    // In the region: returns, and transfers whose destination is a merge
    // in the chain. A condition, a switch index or any other transfer is
    // a reader that would see the rewrite.
    let mut ok = true;
    func.region.for_each_node(|node| match node {
        Region::If { cond, .. } => ok &= resolve_use(func, *cond) != v,
        Region::Switch { index, .. } => ok &= resolve_use(func, *index) != v,
        Region::Break { transfer, .. } | Region::Continue { transfer, .. } | Region::Transfer { transfer, .. } => {
            for (dest, src) in transfer {
                if resolve_use(func, *src) == v && !chain.contains(dest) {
                    ok = false;
                }
            }
        }
        _ => {}
    });
    ok
}

/// Whether every live call to `target`, in every function, is read only
/// by a test of it.
fn every_call_tests(ir: &HighIr, target: FuncId) -> bool {
    let mut any = false;
    for func in &ir.functions {
        let live = scheduled(func);
        for (id, b) in func.bindings.iter() {
            if !matches!(b.expr, Expr::Call { target: t, .. } if t == target) || !live.contains(&id) {
                continue;
            }
            any = true;
            if !only_tested(func, &live, id, 0) {
                return false;
            }
        }
    }
    any
}

/// Every live read of `v` asks only whether it is zero, or widens it into
/// the `bool` an entrypoint returns.
fn only_tested(func: &HighFunction, live: &HashSet<ValueId>, v: ValueId, depth: u32) -> bool {
    if depth > 4 {
        return false;
    }
    for (id, b) in func.bindings.iter() {
        let is_phi = matches!(b.expr, Expr::Phi { .. });
        if !(live.contains(&id) || is_phi) {
            continue;
        }
        let mut reads = false;
        b.expr.for_each_value_use(|u| reads |= u == v);
        if !reads {
            continue;
        }
        let ok = match &b.expr {
            Expr::Use(_) => only_tested(func, live, id, depth + 1),
            Expr::Unary { op: UnaryOp::Eqz, .. } => true,
            Expr::Unary { op: UnaryOp::ExtendU32, .. } => returned_as_bool(func, live, id),
            _ => false,
        };
        if !ok {
            return false;
        }
    }
    let mut ok = true;
    func.region.for_each_node(|node| match node {
        Region::Switch { index, .. } => ok &= *index != v,
        Region::Return { values } => ok &= !values.contains(&v),
        Region::Break { transfer, .. } | Region::Continue { transfer, .. } | Region::Transfer { transfer, .. } => {
            ok &= transfer.iter().all(|(_, src)| *src != v);
        }
        _ => {}
    });
    ok
}

/// `w` is read by nothing but the returns of an entrypoint declared
/// `-> bool`, where the widened word is the `bool`'s encoding.
fn returned_as_bool(func: &HighFunction, live: &HashSet<ValueId>, w: ValueId) -> bool {
    let declared_bool = matches!(
        func.signature.as_ref().map(|s| s.outputs.as_slice()),
        Some([only]) if known_of_type_ref(only) == Some(KnownType::Bool)
    );
    if !declared_bool {
        return false;
    }
    let read_by_binding = func.bindings.iter().any(|(id, b)| {
        let mut reads = false;
        b.expr.for_each_value_use(|u| reads |= resolve_use(func, u) == w);
        reads && (live.contains(&id) || matches!(b.expr, Expr::Phi { .. }))
    });
    if read_by_binding {
        return false;
    }
    let mut only_returns = true;
    func.region.for_each_node(|node| match node {
        Region::If { cond, .. } => only_returns &= resolve_use(func, *cond) != w,
        Region::Switch { index, .. } => only_returns &= resolve_use(func, *index) != w,
        Region::Break { transfer, .. } | Region::Continue { transfer, .. } | Region::Transfer { transfer, .. } => {
            only_returns &= transfer.iter().all(|(_, src)| resolve_use(func, *src) != w);
        }
        _ => {}
    });
    only_returns
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};
    use sordec_common::{BlockId, IrId};
    use sordec_ir::{FunctionSignature, PrimitiveType, TypeRef};

    /// func 0, the helper: `r = phi [1, 0]; if c { return 0 } return r`.
    /// func 1, the entrypoint declared `-> out`: `return extend_u32(func0(x))`.
    fn shape(out: PrimitiveType) -> HighIr {
        let mut helper = func_with(
            vec![
                Expr::Phi { incoming: vec![] },  // v0: c
                Expr::Literal(Literal::I32(0)), // v1
                Expr::Literal(Literal::I32(1)), // v2
                Expr::Literal(Literal::I32(0)), // v3
                Expr::Phi { incoming: vec![(BlockId::from_index(0), v(2)), (BlockId::from_index(1), v(3))] }, // v4
            ],
            vec![v(0)],
            vec![1, 2, 3],
        );
        helper.region = Region::Sequence(vec![
            Region::Basic(BlockId::from_index(0)),
            Region::If {
                cond: v(0),
                then_region: Box::new(Region::Return { values: vec![v(1)] }),
                else_region: None,
            },
            Region::Return { values: vec![v(4)] },
        ]);
        let mut entry = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                              // v0: x
                Expr::Call { target: FuncId::from_index(0), args: vec![v(0)] }, // v1
                Expr::Unary { op: UnaryOp::ExtendU32, value: v(1) },         // v2
            ],
            vec![v(0)],
            vec![1, 2],
        );
        entry.id = FuncId::from_index(1);
        entry.signature = Some(FunctionSignature { name: "has_voted".into(), inputs: vec![], outputs: vec![TypeRef::Primitive(out)] });
        entry.region = Region::Sequence(vec![
            Region::Basic(BlockId::from_index(0)),
            Region::Return { values: vec![v(2)] },
        ]);
        module(vec![helper, entry])
    }

    #[test]
    fn a_helper_returning_zero_one_to_a_bool_entrypoint_returns_a_bool() {
        let mut ir = shape(PrimitiveType::Bool);
        assert!(BoolHelperPass.run(&mut ir).changed);
        let helper = &ir.functions[0];
        assert!(matches!(helper.bindings.get(v(1)).unwrap().expr, Expr::Literal(Literal::Bool(false))));
        assert!(matches!(helper.bindings.get(v(2)).unwrap().expr, Expr::Literal(Literal::Bool(true))));
        assert_eq!(helper.bindings.get(v(4)).unwrap().ty, IrType::Inferred(KnownType::Bool));
        assert_eq!(ir.functions[1].bindings.get(v(1)).unwrap().ty, IrType::Inferred(KnownType::Bool));
        assert!(!BoolHelperPass.run(&mut ir).changed, "idempotent");
    }

    #[test]
    fn a_result_widened_into_another_return_type_is_a_number() {
        // `-> u64`: the widened word is a count, not a flag.
        let mut ir = shape(PrimitiveType::U64);
        assert!(!BoolHelperPass.run(&mut ir).changed);
    }

    #[test]
    fn a_result_branched_on_is_tested() {
        let mut ir = shape(PrimitiveType::Bool);
        let entry = &mut ir.functions[1];
        entry.blocks.get_mut(BlockId::from_index(0)).unwrap().bindings = vec![v(1)];
        entry.region = Region::Sequence(vec![
            Region::Basic(BlockId::from_index(0)),
            Region::If { cond: v(1), then_region: Box::new(Region::Unreachable), else_region: None },
        ]);
        assert!(BoolHelperPass.run(&mut ir).changed);
    }

    #[test]
    fn a_result_used_in_arithmetic_is_left_alone() {
        let mut ir = shape(PrimitiveType::Bool);
        let entry = &mut ir.functions[1];
        entry.bindings.get_mut(v(2)).unwrap().expr =
            Expr::Binary { op: BinaryOp::Add, lhs: v(1), rhs: v(1) };
        assert!(!BoolHelperPass.run(&mut ir).changed);
    }

    #[test]
    fn a_helper_returning_two_is_left_alone() {
        let mut ir = shape(PrimitiveType::Bool);
        ir.functions[0].bindings.get_mut(v(3)).unwrap().expr = Expr::Literal(Literal::I32(2));
        assert!(!BoolHelperPass.run(&mut ir).changed);
    }

    #[test]
    fn a_constant_read_elsewhere_is_left_alone() {
        // `0` is also a loop counter's start: as `false` it would be a `bool`.
        let mut ir = shape(PrimitiveType::Bool);
        let helper = &mut ir.functions[0];
        helper.bindings.get_mut(v(0)).unwrap().expr = Expr::Phi { incoming: vec![(BlockId::from_index(0), v(1))] };
        assert!(!BoolHelperPass.run(&mut ir).changed);
    }
}
