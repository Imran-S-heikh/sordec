//! Structure category: per-function control-flow-skeleton similarity.
//!
//! Placeholder: the real skeleton-tree similarity lands with the structure
//! stage. Until then this reports a perfect score so the orchestration and
//! report plumbing can be exercised end-to-end.

use crate::metrics;
use crate::report::CategoryScore;

/// Score the structure category. Placeholder — returns a perfect, checked
/// score pending the real implementation.
pub(crate) fn evaluate(_reconstructed: &syn::File, _original: &syn::File) -> CategoryScore {
    CategoryScore::checked(1.0, metrics::STRUCTURE_WEIGHT)
        .with_note("structure scoring not yet implemented")
}
