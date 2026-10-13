//! A cross-contract call's result, typed by the check made on it.
//!
//! `invoke_contract` hands back a raw `Val`. The client method the source
//! called converts it to the method's declared return type with
//! `T::try_from_val(env, &res).unwrap()`, and rustc inlines that conversion
//! into the caller — so the first thing the wasm does with the result is
//! test its tag and trap on anything else:
//!
//! ```text
//! r = invoke_contract(c, "add", [x, y])
//! if !has_tag(r, U32Val) { panic!() }       →   r: u32
//! ```
//!
//! The tag is the declared return type, and this pass records it on the
//! result. It is the evidence [`crate::marshalling::guard`] already accepts
//! for deleting that check (the regenerated client makes it again), so the
//! check and the type stand or fall together. With the type in place the
//! rest of the conversion reads as a `u32` — the mask rustc folds a decode
//! and re-encode into (`r & 0xFFFF_FFFF_0000_0004`) is
//! [`super::val_packed_compare`]'s identity — and the emitter can declare
//! the client the call goes through.
//!
//! ## Gates
//!
//! - **A call, not a `try_` call.** `try_invoke_contract` returns a
//!   `Result`, and its checks are on the `Ok` payload, not the call.
//! - **No known interface.** A SEP-41 call is typed by the standard it
//!   matched, and spelled through `token::Client`, not a declared client.
//! - **Every tag check on the result names one type.** A two-encoding type
//!   (`u64`'s small and object forms) tests both tags, and both name `u64`.
//!   Checks naming two different types decline: that is a branch on the
//!   result, not a conversion of it.
//! - **A type already proven stands.** A result some other recognizer
//!   proved to be something else is not overruled.

use sordec_common::{Provenance, ProvenanceSource, ValueId};
use sordec_ir::{Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, SemanticOp};

use crate::dataflow::resolve_use;
use crate::pass::{Pass, PassResult};
use crate::val_abi;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "call-result";

/// Call results typed by their tag checks.
const M_TYPED: &str = "call_results_typed";

/// Types a cross-contract call's result by the tag its conversion checks.
#[derive(Debug, Default, Clone, Copy)]
pub struct CallResultPass;

impl Pass<HighIr> for CallResultPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            let typed: Vec<(ValueId, KnownType)> = func
                .bindings
                .iter()
                .filter(|(_, b)| {
                    matches!(
                        &b.expr,
                        Expr::Semantic(SemanticOp::Known(KnownOp::InvokeContract { interface: None, .. }))
                    )
                })
                .filter_map(|(id, b)| {
                    let ty = checked_type(func, id)?;
                    // The ABI's bare `Val` is the weakest true statement
                    // about a call result, not a proof against this one.
                    let fresh = match &b.ty {
                        IrType::Known(have) => *have == KnownType::Val,
                        _ => true,
                    };
                    fresh.then_some((id, ty))
                })
                .collect();
            for (id, ty) in typed {
                let Some(binding) = func.bindings.get_mut(id) else {
                    continue;
                };
                binding.ty = IrType::Known(ty.clone());
                binding.add_provenance(Provenance::new(
                    PASS_NAME,
                    ProvenanceSource::SdkPattern,
                    format!("the client method's conversion checks the result as {ty:?}"),
                ));
                result.metrics.increment(M_TYPED, 1);
                result.changed = true;
            }
        }
        result
    }
}

/// The one type every tag check on `call`'s result names, or `None` when
/// there is no check or the checks disagree.
fn checked_type(func: &HighFunction, call: ValueId) -> Option<KnownType> {
    let mut named: Option<KnownType> = None;
    for (_, binding) in func.bindings.iter() {
        let Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck { value, tag, .. })) = &binding.expr else {
            continue;
        };
        if resolve_use(func, *value) != call {
            continue;
        }
        let ty = val_abi::tag_payload_type(*tag)?;
        match &named {
            None => named = Some(ty),
            Some(have) if *have == ty => {}
            Some(_) => return None,
        }
    }
    named
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};
    use sordec_ir::Literal;

    fn invoke() -> Expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::InvokeContract {
            contract: v(0),
            function: v(0),
            resolved_callee: Some("add".to_string()),
            arg_count: Some(0),
            resolved_args: Some(vec![]),
            interface: None,
            args: vec![],
        }))
    }

    fn check(tag: u8) -> Expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck { value: v(1), tag, negated: true }))
    }

    #[test]
    fn a_checked_result_takes_the_tag_s_type() {
        let mut ir = module(vec![func_with(
            vec![Expr::Literal(Literal::I64(0)), invoke(), check(val_abi::TAG_U32_VAL)],
            vec![],
            vec![0, 1, 2],
        )]);
        assert!(CallResultPass.run(&mut ir).changed);
        assert_eq!(ir.functions[0].bindings.get(v(1)).unwrap().ty, IrType::Known(KnownType::U32));
    }

    #[test]
    fn checks_naming_two_types_decline() {
        let mut ir = module(vec![func_with(
            vec![
                Expr::Literal(Literal::I64(0)),
                invoke(),
                check(val_abi::TAG_U32_VAL),
                check(val_abi::TAG_ADDRESS_OBJECT),
            ],
            vec![],
            vec![0, 1, 2, 3],
        )]);
        assert!(!CallResultPass.run(&mut ir).changed);
    }

    #[test]
    fn an_unchecked_result_is_left_alone() {
        let mut ir = module(vec![func_with(vec![Expr::Literal(Literal::I64(0)), invoke()], vec![], vec![0, 1])]);
        assert!(!CallResultPass.run(&mut ir).changed);
    }
}
