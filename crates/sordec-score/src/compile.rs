//! Compilation category: does the reconstructed source `cargo check`
//! against `soroban-sdk`. The honest stand-in for "behavior" (K6).
//!
//! Opt-in — the real harness (a scratch crate + `cargo check`) lands with
//! the compilation stage and is gated behind `--check-compile`. Until then,
//! and whenever the check is not requested, the category is reported as
//! *unchecked* (excluded from the weighted mean) rather than scored zero.

use crate::metrics;
use crate::report::CategoryScore;

/// Score the compilation category. When `check_compile` is `false` the
/// category is unchecked; when `true` it is (for now) unchecked with a
/// note that the harness is not yet wired.
pub(crate) fn evaluate(
    _reconstructed: &syn::File,
    _original: &syn::File,
    check_compile: bool,
) -> CategoryScore {
    if check_compile {
        CategoryScore::unchecked(
            metrics::COMPILATION_WEIGHT,
            "compilation harness not yet implemented",
        )
    } else {
        CategoryScore::unchecked(metrics::COMPILATION_WEIGHT, "compile check not requested")
    }
}
