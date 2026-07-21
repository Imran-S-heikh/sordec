//! Terminal unrecognised-scan (spec E2).
//!
//! The recogniser passes rewrite the host calls they claim into
//! `SemanticOp::Known`. Anything left as `SemanticOp::Unknown` after the
//! whole pipeline is a host import **no** recogniser matched — the
//! definitional lift diagnostic. This pass runs last and emits one
//! [`LiftDiagnosticCode::UnrecognisedHostCall`] per surviving `Unknown`,
//! located at its binding.
//!
//! On a fully-recognised module (the entire corpus — guaranteed by the
//! zero-`host:` sweep) it emits nothing; its value is honest reporting
//! for out-of-catalog or future-protocol WASM. It never rewrites the IR
//! (`changed: false`, diagnostics-only), so it is safe as an idempotent
//! terminal step.

use sordec_common::{Diagnostic, IrId, LiftDiagnosticCode, Location};
use sordec_ir::{Expr, HighIr, SemanticOp};

use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field (though this pass adds no
/// provenance, only diagnostics).
pub const PASS_NAME: &str = "unrecognized-scan";

// Metric counter key.
/// Host imports that survived the whole pipeline unrecognised.
const M_UNRECOGNISED: &str = "unrecognised_host_call";

/// The terminal unrecognised-host-call scan. Stateless.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnrecognizedScanPass;

impl Pass<HighIr> for UnrecognizedScanPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &ir.functions {
            for (id, binding) in func.bindings.iter() {
                let Expr::Semantic(SemanticOp::Unknown {
                    host_module,
                    host_fn,
                    ..
                }) = &binding.expr
                else {
                    continue;
                };
                result.metrics.increment(M_UNRECOGNISED, 1);
                result.diagnostics.push(
                    Diagnostic::warning(
                        LiftDiagnosticCode::UnrecognisedHostCall,
                        format!(
                            "host:{host_module}:{host_fn} at v{} was not recognised by any pass",
                            id.index()
                        ),
                    )
                    .at(Location::Value {
                        func: func.id,
                        value: id.index(),
                    }),
                );
            }
        }
        // Diagnostics-only: the IR is unchanged, so `changed` stays false
        // (keeps a fixpoint group, if one ever wraps this, from spinning).
        result
    }
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{Arena, BlockId, FuncId, IrId, Provenance, ProvenanceSource, UnknownReason, ValueId};
    use sordec_ir::{Binding, HighBlock, HighFunction, IrType, KnownOp, MemoryImage, Region, WasmFacts};

    fn module(exprs: Vec<Expr>) -> HighIr {
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        for expr in exprs {
            let id = ValueId::from_index(bindings.len() as u32);
            bindings.push(Binding::new(
                id,
                IrType::Unknown(UnknownReason::InsufficientEvidence),
                expr,
                Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
            ));
        }
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        blocks.push(HighBlock {
            id: BlockId::from_index(0),
            bindings: vec![],
        });
        let func = HighFunction {
            id: FuncId::from_index(0),
            name: None,
            signature: None,
            blocks,
            bindings,
            region: Region::Unreachable,
            params: vec![],
            returns: vec![],
        };
        HighIr {
            facts: WasmFacts {
                imports: vec![],
                exports: vec![],
                function_type_indices: vec![],
                function_bodies: vec![],
                custom_sections: vec![],
            },
            soroban_facts: None,
            functions: vec![func],
            memory: MemoryImage::from_segments(vec![]),
        }
    }

    fn unknown_host(module_name: &str, name: &str) -> Expr {
        Expr::Semantic(SemanticOp::Unknown {
            host_module: module_name.to_string(),
            host_fn: name.to_string(),
            args: vec![],
            reason: UnknownReason::UnsupportedPattern,
        })
    }

    #[test]
    fn surviving_unknown_emits_one_diagnostic() {
        let mut ir = module(vec![unknown_host("z", "9")]);
        let result = UnrecognizedScanPass.run(&mut ir);

        assert!(!result.changed, "diagnostics-only, never rewrites");
        assert_eq!(result.metrics.get(M_UNRECOGNISED), Some(1));
        assert_eq!(result.diagnostics.len(), 1);
        let d = &result.diagnostics[0];
        assert_eq!(d.code.key(), "lift::unrecognised_host_call");
        assert_eq!(
            d.location,
            Some(Location::Value {
                func: FuncId::from_index(0),
                value: 0
            })
        );
        assert!(d.message.contains("host:z:9"));
    }

    #[test]
    fn recognized_ops_emit_nothing() {
        // A `Known` op (what every recogniser produces) is not a survivor.
        let mut ir = module(vec![Expr::Semantic(SemanticOp::Known(
            KnownOp::RequireAuth {
                address: ValueId::from_index(0),
            },
        ))]);
        let result = UnrecognizedScanPass.run(&mut ir);
        assert_eq!(result.metrics.get(M_UNRECOGNISED), None);
        assert!(result.diagnostics.is_empty());
    }
}
