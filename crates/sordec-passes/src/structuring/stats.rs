//! Structuring-fallback reporting (Phase-3 C2 diagnostics surface).
//!
//! Diagnostics-only `Pass<HighIr>`, first in the default high pipeline:
//! it walks every function's region tree and emits one
//! [`LiftDiagnosticCode::StructuringFallback`] warning per
//! [`Region::Unstructured`] the lowering boundary produced. On the
//! committed corpus the lock asserts this pass emits **nothing**
//! (kickoff K3 — on reducible rustc output a correct structurer never
//! fails); it exists so exotic input degrades loudly instead of
//! silently. It never rewrites the IR (`changed: false`), so it is a
//! safe idempotent head step. The A6 (W8) structuring coverage
//! metrics — per-function structured ratio, loop-kind breakdown,
//! labeled-exit census — live in the terminal
//! [`StructuringCensusPass`](super::StructuringCensusPass) instead,
//! which observes the *settled* region tree; this pass owns only the
//! node-level fallback count and its diagnostics.

use sordec_common::{Diagnostic, LiftDiagnosticCode, Location};
use sordec_ir::{HighIr, Region};

use crate::pass::{Pass, PassResult};

/// Unique pipeline name of this pass.
pub const PASS_NAME: &str = "structuring-stats";

// Metric counter key.
/// Functions whose control flow fell back to `Region::Unstructured`.
const M_FALLBACK: &str = "structuring_fallback";

/// The structuring-fallback reporting pass. Stateless; see the module
/// docs.
#[derive(Debug, Default, Clone, Copy)]
pub struct StructuringStatsPass;

impl Pass<HighIr> for StructuringStatsPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &ir.functions {
            func.region.for_each_node(|region| {
                let Region::Unstructured { entry, reason } = region else {
                    return;
                };
                result.metrics.increment(M_FALLBACK, 1);
                result.diagnostics.push(
                    Diagnostic::warning(
                        LiftDiagnosticCode::StructuringFallback,
                        format!(
                            "{} ({}) fell back to unstructured control flow at {entry}: {reason:?}",
                            func.name.as_deref().unwrap_or("unnamed function"),
                            func.id,
                        ),
                    )
                    .at(Location::Function(func.id)),
                );
            });
        }
        // Diagnostics/metrics only: `changed` stays false by definition.
        result
    }
}
