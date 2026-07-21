//! Interface category: public entrypoint signatures + `#[contracttype]`
//! shapes.
//!
//! Placeholder: the real F1-over-signatures implementation lands with the
//! interface stage. Until then this reports a perfect score so the
//! orchestration and report plumbing can be exercised end-to-end.

use crate::metrics;
use crate::report::CategoryScore;

/// Score the interface category. Placeholder — returns a perfect,
/// checked score pending the real implementation.
pub(crate) fn evaluate(_reconstructed: &syn::File, _original: &syn::File) -> CategoryScore {
    CategoryScore::checked(1.0, metrics::INTERFACE_WEIGHT)
        .with_note("interface scoring not yet implemented")
}
