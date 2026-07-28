//! Remove the argument type-check the source never wrote.
//!
//! The SDK checks every incoming argument's tag before using it and traps
//! on mismatch. Two shapes reach us:
//!
//! ```text
//! if (eq disc, 1) { panic!() }        ← the decode-result guard, once
//!                                       [`super::decode`] has proved
//!                                       `disc` is the Ok constant
//! if !has_tag(a, AddressObject) { panic!() }   ← the direct tag guard
//! ```
//!
//! Neither appears in the source, and neither can fire: the host resolves
//! a contract's `contractspecv0` and marshals arguments to the declared
//! types *before* dispatch, so an entrypoint parameter's tag is settled
//! by the time the body runs. The check is the SDK being defensive about
//! a boundary the host already enforced.
//!
//! ## What this pass is allowed to delete
//!
//! Only a guard whose condition is one of the two shapes above **and**
//! whose taken arm is a bare trap. Concretely:
//!
//! - a constant-false condition — the residue [`super::decode`] leaves
//!   behind, so this half deletes provably dead code and nothing else;
//! - a tag check on an *entrypoint parameter* whose tested tag agrees
//!   with the parameter's declared type.
//!
//! A tag check on anything but an entry parameter stays: outside the ABI
//! boundary there is no host guarantee to lean on, and the check may be
//! a real `if let` / `try_into` the author wrote.
//!
//! ## The honest caveat
//!
//! This is a behavioural claim, not merely a cosmetic one — it asserts an
//! unreachable trap really is unreachable. The argument above is strong
//! but it is an argument; `sordec-diffexec` is what actually proves it.
//! Every removal is therefore recorded as a diagnostic, not silently.
//!
//! Scoring-wise the removal is neutral where it counts: `score-2.0.0`'s
//! T18 already excludes argument-decode panics as marshalling on *both*
//! sides, so no semantic fact is lost — only surplus control flow goes.

use std::collections::HashMap;

use sordec_common::{Diagnostic, IrId, LiftDiagnosticCode, ValueId};
use sordec_ir::{BinaryOp, Expr, HighFunction, HighIr, KnownOp, KnownType, Region, SemanticOp};

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
            let guards = collect(func);
            if guards.is_empty() {
                continue;
            }
            let before = elided;
            let region = std::mem::replace(&mut func.region, Region::Unreachable);
            func.region = strip(region, &guards, &mut elided);
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
fn collect(func: &HighFunction) -> HashMap<ValueId, String> {
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
        if else_region.is_some() || !is_trap(then_region) {
            return;
        }
        if let Some(note) = classify_condition(func, *cond) {
            guards.insert(*cond, note);
        }
    });
    guards
}

/// A region that does nothing but trap.
fn is_trap(region: &Region) -> bool {
    matches!(region, Region::Unreachable | Region::Panic { .. })
}

/// Why `cond` is an elidable argument check, or `None`.
fn classify_condition(func: &HighFunction, cond: ValueId) -> Option<String> {
    let id = resolve_use(func, cond);
    let expr = &func.bindings.get(id)?.expr;
    match expr {
        // Shape 1 — the decode-result guard, now comparing the Ok
        // constant against the Err discriminant.
        Expr::Binary {
            op: BinaryOp::Eq | BinaryOp::Ne,
            lhs,
            rhs,
        } => {
            let (l, r) = (trace_int(func, *lhs)?, trace_int(func, *rhs)?);
            let taken = match expr {
                Expr::Binary { op: BinaryOp::Eq, .. } => l == r,
                _ => l != r,
            };
            (!taken).then(|| {
                "decode-failure guard on a constant-Ok discriminant: provably not taken"
                    .to_string()
            })
        }
        // Shape 2 — a direct tag check on an entry parameter.
        Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck { value, tag, negated })) => {
            // The trap arm must be the *mismatch* arm. `has_tag` guards
            // trap when the tag is absent, i.e. on the negated form.
            if !negated {
                return None;
            }
            let declared = declared_param_type(func, resolve_use(func, *value))?;
            (val_abi::tag_payload_type(*tag).as_ref() == Some(&declared)).then(|| {
                format!(
                    "argument tag check ({}) on a parameter contractspecv0 declares \
                     as that type: the host marshals it before dispatch",
                    val_abi::tag_name(*tag).unwrap_or("?")
                )
            })
        }
        _ => None,
    }
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
fn strip(region: Region, guards: &HashMap<ValueId, String>, elided: &mut i64) -> Region {
    match region {
        Region::Sequence(items) => seq(items
            .into_iter()
            .map(|item| strip(item, guards, elided))
            .collect()),
        Region::Scope { out, body } => Region::Scope {
            out,
            body: Box::new(strip(*body, guards, elided)),
        },
        Region::Loop { header, body, kind } => Region::Loop {
            header,
            body: Box::new(strip(*body, guards, elided)),
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
                    arm.body = strip(arm.body, guards, elided);
                    arm
                })
                .collect(),
            default: Box::new(strip(*default, guards, elided)),
            dispatch,
        },
        Region::If {
            cond,
            then_region,
            else_region,
        } => {
            if else_region.is_none() && is_trap(&then_region) && guards.contains_key(&cond) {
                *elided += 1;
                return seq(vec![]);
            }
            Region::If {
                cond,
                then_region: Box::new(strip(*then_region, guards, elided)),
                else_region: else_region.map(|e| Box::new(strip(*e, guards, elided))),
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
        FunctionParam, FunctionSignature, Literal, PrimitiveType, TypeRef,
    };

    fn entry(exprs: Vec<Expr>, params: Vec<ValueId>, ty: PrimitiveType) -> HighFunction {
        let mut func = func_with(exprs, params.clone(), vec![]);
        func.signature = Some(FunctionSignature {
            name: "f".to_string(),
            inputs: params
                .iter()
                .map(|_| FunctionParam {
                    name: "a".to_string(),
                    ty: TypeRef::Primitive(ty),
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
        let guards = collect(&func);
        assert_eq!(guards.len(), 1);
        let mut elided = 0;
        let region = strip(func.region.clone(), &guards, &mut elided);
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
        assert_eq!(collect(&func).len(), 1);
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
            collect(&func).is_empty(),
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
        assert!(collect(&func).is_empty());
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
        assert!(collect(&func).is_empty(), "a taken trap must survive");
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
        assert!(collect(&func).is_empty(), "only bare traps are guards");
    }
}
