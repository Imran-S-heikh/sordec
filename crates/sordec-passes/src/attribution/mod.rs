//! Identifying which function bodies came from the SDK rather than the
//! contract's author.
//!
//! # The question this answers
//!
//! A compiled Soroban contract is a blend of the author's code and the SDK
//! that rustc linked in, with nothing marking which is which. Everything
//! the decompiler deletes as "glue" rests on answering that, and until now
//! it has been answered by hand: a recognizer per idiom, each found by
//! reading emitted output, each carrying its own soundness argument.
//!
//! Measured on token-v23, the source's control flow is **33 tokens** and
//! the reconstruction's is **538**, with recall already at 1.0. Every token
//! the author wrote is recovered — the whole deficit is library code we
//! could not name and therefore could not remove.
//!
//! This module names it, by looking each body's fingerprint up in a
//! catalogue built from contracts whose source we hold. See `sordec-sigs`
//! for the fingerprint and the measurements behind it.
//!
//! # What identification is, and is not
//!
//! [`identify`] answers *"which library function is this body?"*. That is
//! general machinery and it is all this module does.
//!
//! It does not answer *"what should be emitted instead?"* — that is
//! per-function knowledge (a `Symbol` construction becomes a literal; a
//! storage read becomes a `SemanticOp`) and belongs to the passes that act
//! on it. Keeping the two apart is deliberate: the identification half is
//! reusable and testable on its own, and a wrong answer in the acting half
//! cannot be blamed on the recognising half.
//!
//! # Reach
//!
//! Trained on nine third-party modules from five organisations and tested
//! on the benchmark fixtures, which are held out of the catalogue:
//! **54.5% of library functions identified, zero false positives.**
//!
//! Two limits are worth stating rather than discovering later. Generic
//! functions instantiated at a type the corpus never saw will miss — a
//! generic compiled for two types is genuinely two bodies. And whole-body
//! identification cannot reach SDK code that rustc **inlined** into another
//! function, which on token-v23 is where **63% of the control flow lives**;
//! that needs IR-level idiom recognition, which is what the existing
//! hand-written recognizers already are. The two approaches compose.

mod sdk_attribution;

pub use sdk_attribution::{PASS_NAME, SdkAttributionPass};

use sordec_common::{FuncId, IrId};
use sordec_ir::HighIr;
use sordec_sigs::{Catalogue, Fingerprint, SigEntry};

/// The library function a body is, or `None` if it is unrecognised.
///
/// `None` is the overwhelmingly common answer and carries no suspicion: it
/// means the contract's own code, a library function absent from the
/// catalogue, or a body too small to identify safely. Callers must treat it
/// as "no information", never as "user code" — the catalogue's coverage is
/// about half, so absence of evidence is not evidence here.
///
/// Reads only `ir.facts`, so it is a pure function of the original module
/// bytes and stays correct however far the passes have rewritten the IR.
#[must_use]
pub fn identify(ir: &HighIr, func: FuncId) -> Option<&'static SigEntry> {
    identify_with(ir, func, sordec_sigs::shipped_catalogue())
}

/// [`identify`] against a caller-supplied catalogue, for tests.
#[must_use]
pub fn identify_with(ir: &HighIr, func: FuncId, catalogue: Catalogue) -> Option<&'static SigEntry> {
    // `HighFunction::id` is the *local* function index, which is exactly
    // how `function_fingerprints` is ordered — imports are not in either.
    // A short vector means the module predates fingerprinting or the facts
    // were hand-built in a test, so indexing must be checked rather than
    // assumed.
    let raw = (*ir.facts.function_fingerprints.get(func.index() as usize)?)?;
    catalogue.lookup(Fingerprint(raw))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_ir::WasmFacts;

    fn ir_with(fingerprints: Vec<Option<u128>>) -> HighIr {
        HighIr {
            facts: WasmFacts {
                imports: vec![],
                exports: vec![],
                function_type_indices: vec![],
                function_bodies: vec![],
                function_fingerprints: fingerprints,
                table_functions: None,
                custom_sections: vec![],
            },
            soroban_facts: None,
            functions: vec![],
            memory: sordec_ir::MemoryImage::empty(),
        }
    }

    #[test]
    fn an_unfingerprinted_body_identifies_as_nothing() {
        let ir = ir_with(vec![None]);
        assert!(identify(&ir, FuncId::from_index(0)).is_none());
    }

    /// Hand-built facts carry an empty vector; indexing it must not panic.
    #[test]
    fn a_short_fingerprint_vector_is_not_an_index_error() {
        let ir = ir_with(vec![]);
        assert!(identify(&ir, FuncId::from_index(9)).is_none());
    }

    #[test]
    fn a_fingerprint_absent_from_the_catalogue_identifies_as_nothing() {
        let ir = ir_with(vec![Some(0xdead_beef_dead_beef)]);
        assert!(identify(&ir, FuncId::from_index(0)).is_none());
    }

    /// A fingerprint the shipped catalogue does contain must resolve, and
    /// resolve to library code.
    #[test]
    fn a_catalogued_fingerprint_resolves() {
        let catalogue = sordec_sigs::shipped_catalogue();
        let first = catalogue.entries().first().expect("catalogue is populated");
        let ir = ir_with(vec![Some(first.fingerprint.to_u128())]);
        let hit = identify(&ir, FuncId::from_index(0)).expect("should resolve");
        assert_eq!(hit.path, first.path);
    }
}
