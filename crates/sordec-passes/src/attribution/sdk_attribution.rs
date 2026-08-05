//! The SDK-attribution scan: report what the catalogue recognises.
//!
//! Diagnostics and metrics only — it rewrites nothing. That is deliberate
//! for two reasons.
//!
//! **It makes coverage measurable before anything depends on it.** How much
//! of a contract the catalogue identifies is the number that decides
//! whether the rest of this approach is worth building, and it should be
//! readable without also changing the output it would be measured against.
//!
//! **It makes every identification reviewable.** Naming a body as SDK code
//! is what later licenses deleting it, and that claim is evidence-based
//! rather than proved: a fingerprint says two bodies are the same code up
//! to module-local indices, which is strong but is not a theorem about
//! behaviour. `ArgGuardElisionPass` set this precedent — it reports every
//! guard it removes rather than leaving a reviewer to diff two outputs —
//! and identification deserves the same treatment.

use sordec_common::{Diagnostic, IrId, LiftDiagnosticCode, Location};
use sordec_ir::HighIr;

use crate::attribution::identify;
use crate::pass::{Pass, PassResult};

/// Pass name, also its provenance `pass` field.
pub const PASS_NAME: &str = "sdk-attribution";

/// Local functions the catalogue recognised.
const M_IDENTIFIED: &str = "sdk_function_identified";

/// Local functions it did not.
const M_UNIDENTIFIED: &str = "sdk_function_unidentified";

/// Reports which function bodies the signature catalogue recognises.
///
/// Stateless and idempotent; safe anywhere in the manifest.
#[derive(Debug, Default, Clone, Copy)]
pub struct SdkAttributionPass;

impl Pass<HighIr> for SdkAttributionPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();

        for func in &ir.functions {
            let Some(entry) = identify(ir, func.id) else {
                result.metrics.increment(M_UNIDENTIFIED, 1);
                continue;
            };
            result.metrics.increment(M_IDENTIFIED, 1);
            result.diagnostics.push(
                Diagnostic::info(
                    LiftDiagnosticCode::SdkFunctionIdentified,
                    format!(
                        "func{} is {} ({}, {} instructions)",
                        func.id.index(),
                        entry.path,
                        entry.origin.as_str(),
                        entry.insns
                    ),
                )
                .at(Location::Function(func.id)),
            );
        }

        // Diagnostics-only: `changed` stays false so a fixpoint group
        // containing this pass cannot spin on it.
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{Arena, FuncId};
    use sordec_ir::{HighFunction, MemoryImage, Region, WasmFacts};

    fn func(id: u32) -> HighFunction {
        HighFunction {
            id: FuncId::from_index(id),
            name: None,
            signature: None,
            blocks: Arena::new(),
            bindings: Arena::new(),
            region: Region::Sequence(vec![]),
            params: vec![],
            returns: vec![],
        }
    }

    fn ir(fingerprints: Vec<Option<u128>>, count: u32) -> HighIr {
        HighIr {
            facts: WasmFacts {
                imports: vec![],
                exports: vec![],
                function_type_indices: vec![],
                function_bodies: vec![],
                function_fingerprints: fingerprints,
                custom_sections: vec![],
            },
            soroban_facts: None,
            functions: (0..count).map(func).collect(),
            memory: MemoryImage::empty(),
        }
    }

    #[test]
    fn an_unrecognised_module_reports_only_misses() {
        let mut m = ir(vec![Some(1), Some(2)], 2);
        let r = SdkAttributionPass.run(&mut m);
        assert_eq!(r.metrics.get(M_UNIDENTIFIED), Some(2));
        assert_eq!(r.metrics.get(M_IDENTIFIED), None);
        assert!(r.diagnostics.is_empty());
        assert!(!r.changed, "attribution must never rewrite the IR");
    }

    #[test]
    fn a_catalogued_body_is_reported() {
        let entry = *sordec_sigs::shipped_catalogue()
            .entries()
            .first()
            .expect("catalogue is populated");
        let mut m = ir(vec![Some(entry.fingerprint.to_u128())], 1);
        let r = SdkAttributionPass.run(&mut m);
        assert_eq!(r.metrics.get(M_IDENTIFIED), Some(1));
        assert_eq!(r.diagnostics.len(), 1);
        assert!(r.diagnostics[0].message.contains(entry.path));
        assert!(!r.changed);
    }

    /// Running twice must report the same thing: the pass may sit inside a
    /// group that iterates.
    #[test]
    fn the_pass_is_idempotent() {
        let mut m = ir(vec![Some(7)], 1);
        let first = SdkAttributionPass.run(&mut m);
        let second = SdkAttributionPass.run(&mut m);
        assert_eq!(
            first.metrics.get(M_UNIDENTIFIED),
            second.metrics.get(M_UNIDENTIFIED)
        );
    }
}
