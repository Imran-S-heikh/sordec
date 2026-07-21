//! Semantic category: precision/recall over recovered Soroban-operation
//! facts.
//!
//! Placeholder: the real fact-extraction + precision/recall implementation
//! lands with the semantic stage. Until then this reports a perfect score
//! so the orchestration and report plumbing can be exercised end-to-end.

use crate::metrics;
use crate::report::CategoryScore;

/// Score the semantic category. Placeholder — returns a perfect, checked
/// score pending the real implementation.
pub(crate) fn evaluate(_reconstructed: &syn::File, _original: &syn::File) -> CategoryScore {
    CategoryScore::checked(1.0, metrics::SEMANTIC_WEIGHT)
        .with_note("semantic scoring not yet implemented")
}
