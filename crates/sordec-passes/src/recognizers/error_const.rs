//! The contract-error constant recognizer (spec D4.4's error substrate).
//!
//! A `#[contracterror]` value — the `Err(Error::Variant)` a contract
//! constructs — reaches the WASM boundary as a compile-time-constant
//! `Error` `Val`: `(code << 32) | TAG_ERROR`, with the error *type* in the
//! minor field. rustc folds the whole thing to a single integer literal, so
//! by the time the recognizers run it is an `Expr::Literal(I64/U64)` binding.
//! This pass decodes that constant and, when its code names exactly one
//! declared error variant, rewrites the binding to a
//! [`KnownOp::MakeError`] carrying the resolved [`ErrorVariant`] — so the
//! emitter can render `Error::Variant` (and wrap the return in `Err(..)`)
//! instead of a bare integer.
//!
//! ## Evidence gate (all required — leave the literal untouched otherwise)
//!
//! 1. **Registry gate.** `contractspecv0` declares at least one
//!    `#[contracterror]` enum. Without it (stripped builds) nothing is
//!    named — the same None-is-honest discipline as [`enum_key`].
//! 2. **ABI decode.** The constant is a small `Error` `Val` of
//!    `ScErrorType::Contract` (host error types are not user variants):
//!    [`val_abi::decode_contract_error`].
//! 3. **Unique variant.** The decoded code matches exactly one declared
//!    error variant ([`TypeRegistry::variant_by_value`]); a code no enum
//!    declares — or one two enums share — resolves to nothing and the
//!    literal is left as-is. This gate also makes a coincidental
//!    low-byte-`3` integer a non-event.
//!
//! Unlike [`enum_key`], the discriminant here is *witnessed* (it is the
//! literal's own bits, not a declaration-order inference), so a match is
//! `HostFunctionAbi`-grade. Idempotent: the rewritten binding is a
//! `Semantic(Known(_))`, which `is_recognized` skips on a second run.
//!
//! [`enum_key`]: super::enum_key
//! [`TypeRegistry::variant_by_value`]: sordec_ir::TypeRegistry::variant_by_value

use std::collections::HashMap;

use sordec_common::{FuncId, ProvenanceSource};
use sordec_ir::{ErrorVariant, Expr, HighIr, IrType, KnownOp, KnownType, Literal, SemanticOp};

use super::{apply_rewrites, is_recognized, Rewrite};
use crate::pass::{Pass, PassResult};
use crate::val_abi;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "error-const";

/// Constant Error `Val`s named as a declared `#[contracterror]` variant.
const M_ERROR_NAMED: &str = "error_const_named";

/// The contract-error constant recognizer. Stateless between runs.
#[derive(Debug, Default, Clone, Copy)]
pub struct ErrorConstPass;

impl Pass<HighIr> for ErrorConstPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();

        // Gate 1: no declared error enums (stripped builds, or a contract
        // with none) → nothing can be named. Stay silent and honest.
        let has_errors = ir
            .soroban_facts
            .as_ref()
            .is_some_and(|f| !f.types.errors.is_empty());
        if !has_errors {
            return result;
        }
        let types = &ir.soroban_facts.as_ref().expect("gated above").types;

        // Phase A — read-only scan: plan the rewrites per function.
        let mut planned: HashMap<FuncId, Vec<Rewrite>> = HashMap::new();
        for func in &ir.functions {
            for (id, binding) in func.bindings.iter() {
                if is_recognized(&binding.expr) {
                    continue; // already a semantic op (idempotency)
                }
                let Some(bits) = error_bits(&binding.expr) else {
                    continue;
                };
                // Gate 2 + 3: a Contract-type Error whose code names exactly
                // one declared variant.
                let Some(code) = val_abi::decode_contract_error(bits) else {
                    continue;
                };
                let Some((enum_name, variant)) = types.variant_by_value(code) else {
                    continue;
                };
                let note = format!("error-const {enum_name}::{variant} (contract error code {code})");
                planned.entry(func.id).or_default().push(Rewrite {
                    id,
                    expr: Expr::Semantic(SemanticOp::Known(KnownOp::MakeError {
                        code,
                        resolved: Some(ErrorVariant {
                            enum_name: enum_name.to_string(),
                            variant: variant.to_string(),
                        }),
                    })),
                    // The value is a Soroban `Error`; witnessed from its bits.
                    ty: Some(IrType::Known(KnownType::Error)),
                    source: ProvenanceSource::HostFunctionAbi,
                    note,
                    metric: M_ERROR_NAMED,
                });
            }
        }

        // Phase B — apply per function.
        for (func_id, rewrites) in planned {
            for rw in &rewrites {
                result.metrics.increment(rw.metric, 1);
            }
            result.changed = true;
            if let Some(func) = ir.function_mut(func_id) {
                apply_rewrites(func, PASS_NAME, rewrites);
            }
        }
        result
    }
}

/// The raw 64-bit `Val` pattern of a constant that could be an `Error`.
///
/// A contract `Error` `Val` for any non-zero code is `≥ 2^32` (the code
/// lives in the major field), so it is always an `i64`/`u64` literal — an
/// `i32` literal can only ever carry a code-0 error, which
/// [`TypeRegistry::variant_by_value`] resolves only if such a variant is
/// declared. Restricting to the 64-bit carriers keeps the false-positive
/// surface minimal.
fn error_bits(expr: &Expr) -> Option<u64> {
    match expr {
        Expr::Literal(Literal::I64(n)) => Some(*n as u64),
        Expr::Literal(Literal::U64(n)) => Some(*n),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{Arena, BlockId, IrId, Provenance, ProvenanceSource, UnknownReason, ValueId};
    use sordec_ir::{
        Binding, EnumCase, EnumDef, HighBlock, HighFunction, MemoryImage, Region, SorobanFacts,
        TypeRegistry, WasmFacts,
    };

    /// The Error `Val` bits for a `Contract`-type error `code`.
    fn contract_error_val(code: u32) -> i64 {
        ((u64::from(code) << 32) | u64::from(val_abi::TAG_ERROR)) as i64
    }

    /// A single-function module whose one block schedules `exprs`, over a
    /// registry declaring `errors` (`(name, code)` pairs on one `Error` enum).
    fn module(exprs: Vec<Expr>, errors: &[(&str, u32)]) -> HighIr {
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        let mut scheduled = Vec::new();
        for expr in exprs {
            let vid = ValueId::from_index(bindings.len() as u32);
            bindings.push(Binding::new(
                vid,
                IrType::Unknown(UnknownReason::InsufficientEvidence),
                expr,
                Provenance::new("test", ProvenanceSource::DataFlow, "seed"),
            ));
            scheduled.push(vid);
        }
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        blocks.push(HighBlock { id: BlockId::from_index(0), bindings: scheduled });
        let func = HighFunction {
            id: FuncId::from_index(0),
            name: None,
            signature: None,
            aliases: Vec::new(),
            blocks,
            bindings,
            region: Region::Unreachable,
            params: vec![],
            returns: vec![],
        };
        let errors = if errors.is_empty() {
            vec![]
        } else {
            vec![EnumDef {
                id: sordec_common::TypeId::from_index(0),
                name: "Error".to_string(),
                cases: errors
                    .iter()
                    .map(|(n, v)| EnumCase { name: (*n).to_string(), value: *v })
                    .collect(),
            }]
        };
        HighIr {
            facts: WasmFacts {
                imports: vec![],
                exports: vec![],
                function_type_indices: vec![],
                function_bodies: vec![],
                function_fingerprints: vec![],
                custom_sections: vec![],
            },
            soroban_facts: Some(SorobanFacts {
                types: TypeRegistry { errors, ..TypeRegistry::default() },
                ..SorobanFacts::default()
            }),
            functions: vec![func],
            memory: MemoryImage::from_segments(vec![]),
        }
    }

    fn op_at(ir: &HighIr, i: u32) -> Expr {
        ir.functions[0].bindings.get(ValueId::from_index(i)).unwrap().expr.clone()
    }

    #[test]
    fn decodes_a_contract_error_constant_to_its_variant() {
        // v0 = Err(Error::EmptyMessage) constant (code 1).
        let mut ir = module(
            vec![Expr::Literal(Literal::I64(contract_error_val(1)))],
            &[("EmptyMessage", 1), ("DigestMismatch", 2)],
        );
        let result = ErrorConstPass.run(&mut ir);
        assert!(result.changed);
        assert_eq!(result.metrics.get(M_ERROR_NAMED), Some(1));
        match op_at(&ir, 0) {
            Expr::Semantic(SemanticOp::Known(KnownOp::MakeError { code, resolved })) => {
                assert_eq!(code, 1);
                let v = resolved.expect("resolved variant");
                assert_eq!(v.enum_name, "Error");
                assert_eq!(v.variant, "EmptyMessage");
            }
            other => panic!("expected MakeError, got {other:?}"),
        }
        // The binding's type is upgraded to Error.
        let ty = &ir.functions[0].bindings.get(ValueId::from_index(0)).unwrap().ty;
        assert!(matches!(ty, IrType::Known(KnownType::Error)), "{ty:?}");
    }

    #[test]
    fn leaves_a_plain_integer_literal_alone() {
        // 42 is not an Error Val (low byte != TAG_ERROR).
        let mut ir = module(vec![Expr::Literal(Literal::I64(42))], &[("EmptyMessage", 1)]);
        let result = ErrorConstPass.run(&mut ir);
        assert!(!result.changed);
        assert!(matches!(op_at(&ir, 0), Expr::Literal(Literal::I64(42))));
    }

    #[test]
    fn leaves_an_undeclared_code_alone() {
        // Shaped like a Contract error (tag 3, minor 0) but code 9 is not
        // a declared variant — never guess; stays a literal.
        let mut ir = module(
            vec![Expr::Literal(Literal::I64(contract_error_val(9)))],
            &[("EmptyMessage", 1)],
        );
        let result = ErrorConstPass.run(&mut ir);
        assert!(!result.changed);
        assert!(matches!(op_at(&ir, 0), Expr::Literal(Literal::I64(_))));
    }

    #[test]
    fn without_declared_errors_the_pass_is_silent() {
        let mut ir = module(vec![Expr::Literal(Literal::I64(contract_error_val(1)))], &[]);
        let result = ErrorConstPass.run(&mut ir);
        assert!(!result.changed);
        assert!(matches!(op_at(&ir, 0), Expr::Literal(Literal::I64(_))));
    }

    #[test]
    fn second_run_is_idempotent() {
        let mut ir = module(
            vec![Expr::Literal(Literal::I64(contract_error_val(1)))],
            &[("EmptyMessage", 1)],
        );
        assert!(ErrorConstPass.run(&mut ir).changed);
        let second = ErrorConstPass.run(&mut ir);
        assert!(!second.changed);
        assert_eq!(second.metrics.get(M_ERROR_NAMED), None);
    }
}
