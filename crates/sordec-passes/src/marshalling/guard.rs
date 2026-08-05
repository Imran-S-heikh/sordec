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
        for func in &mut ir.functions {
            let empty = empty_blocks(func);
            let guards = collect(func, &empty);
            if guards.is_empty() {
                continue;
            }
            let before = elided;
            let region = std::mem::replace(&mut func.region, Region::Unreachable);
            func.region = strip(region, &guards, &empty, &mut elided);
            // One diagnostic per guard actually removed — a reviewer sees
            // every site the unreachability argument was applied to.
            for note in guards.values().take((elided - before) as usize) {
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
        debug_validate(ir, PASS_NAME);
        result
    }
}

/// Every condition value in `func` that is an elidable argument guard,
/// mapped to the note explaining why.
fn collect(func: &HighFunction, empty: &HashSet<BlockId>) -> HashMap<ValueId, String> {
    let mut guards = HashMap::new();
    func.region.for_each_node(|node| {
        let Region::If {
            cond,
            then_region,
            else_region,
        } = node
        else {
            return;
        };
        // Only a guard: the taken arm traps and there is no else.
        if else_region.is_some() || !is_trap(then_region, empty) {
            return;
        }
        if let Some(note) = classify_condition(func, *cond) {
            guards.insert(*cond, note);
        }
    });
    guards
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

/// Why `cond` is an elidable argument check, or `None`.
fn classify_condition(func: &HighFunction, cond: ValueId) -> Option<String> {
    let id = resolve_use(func, cond);
    let expr = &func.bindings.get(id)?.expr;
    // Each shape is its own fallible function rather than an arm of one
    // `match`: shapes 1 and 3 both key on `Expr::Binary`, and a `?` inside
    // a match arm returns from the *whole* classifier, so an arm that
    // declines would silently prevent every later shape from being tried.
    classify_constant_discriminant(func, expr)
        .or_else(|| classify_tag_check(func, expr))
        .or_else(|| classify_length_check(func, expr))
}

/// Shape 1 — the decode-result guard, now comparing the Ok constant
/// against the Err discriminant, so the branch is provably not taken.
fn classify_constant_discriminant(func: &HighFunction, expr: &Expr) -> Option<String> {
    let Expr::Binary {
        op: op @ (BinaryOp::Eq | BinaryOp::Ne),
        lhs,
        rhs,
    } = expr
    else {
        return None;
    };
    let (l, r) = (trace_int(func, *lhs)?, trace_int(func, *rhs)?);
    let taken = if *op == BinaryOp::Eq { l == r } else { l != r };
    (!taken)
        .then(|| "decode-failure guard on a constant-Ok discriminant: provably not taken".to_string())
}

/// Shape 2 — a direct tag check on an entry parameter.
fn classify_tag_check(func: &HighFunction, expr: &Expr) -> Option<String> {
    let Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck {
        value,
        tag,
        negated,
    })) = expr
    else {
        return None;
    };
    // The trap arm must be the *mismatch* arm. `has_tag` guards trap when
    // the tag is absent, i.e. on the negated form.
    if !negated {
        return None;
    }
    let declared = declared_param_type(func, resolve_use(func, *value))?;
    // `tag_carries`, not `==`: a `BytesN<N>` parameter rides in a plain
    // `BytesObject`, so the tag denotes `Bytes` while the declaration says
    // `BytesN(N)` and an equality test would report a disagreement that
    // does not exist.
    val_abi::tag_carries(*tag, &declared).then(|| {
        format!(
            "argument tag check ({}) on a parameter contractspecv0 declares as {declared:?}: \
             `#[contractimpl]` regenerates it in the dispatch wrapper",
            val_abi::tag_name(*tag).unwrap_or("?")
        )
    })
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
fn classify_length_check(func: &HighFunction, expr: &Expr) -> Option<String> {
    let Expr::Binary {
        op: BinaryOp::Ne,
        lhs,
        rhs,
    } = expr
    else {
        return None;
    };
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
        return Some(format!(
            "argument length check (== {width}) on a parameter contractspecv0 declares as \
             BytesN<{width}>: `#[contractimpl]` regenerates it in the dispatch wrapper"
        ));
    }
    None
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
        collect(func, &empty_blocks(func))
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
