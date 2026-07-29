//! The single decision point for what to emit where the IR could not
//! recover a concrete fact — the "hole policy" seam.
//!
//! Every `Unknown` the Rust emitter meets routes through a [`HolePolicy`],
//! so the project-wide rule "never guess" (and the future, deliberate
//! decision to *start* guessing once a first honest version is measured
//! against the ≥90% bar) is a single swappable strategy rather than logic
//! scattered across the emitter. Phase 4 ships [`StrictNoGuess`]; a
//! best-effort policy can later be dropped in at this one seam without
//! touching any call site.
//!
//! ## Surfacing constraint
//!
//! `prettyplease` prints from a [`syn`] AST, and `syn` discards ordinary
//! `//` comments (they are lexer trivia, not AST nodes). So a hole cannot
//! carry a free-floating `// UNRECOVERED` note in the emitted source.
//! Holes are surfaced instead by:
//!
//! - the **fallback token itself** — an unresolved *type* becomes the
//!   ABI-universal `soroban_sdk::Val`, which visibly reads as "a Soroban
//!   value we did not refine" (the type-level counterpart of
//!   [`IrType::Unknown`](sordec_ir::IrType::Unknown)); and
//! - the **lift diagnostics** already emitted upstream at the same site.
//!
//! Expression-position holes (Phase 4 · W2) additionally carry their
//! reason as a `todo!("…")` **string literal**, which *does* survive
//! printing because it is part of the AST.

use proc_macro2::Literal;
use sordec_common::UnknownReason;
use syn::parse_quote;

/// Strategy for emitting IR facts the decompiler could not recover.
///
/// The only caller is the Rust emitter. The trait is object-safe so the
/// active policy can be chosen at run time (`&dyn HolePolicy`) and threaded
/// unchanged through the type mapping.
pub(crate) trait HolePolicy {
    /// The `syn::Type` to emit in place of a type the IR could not resolve.
    ///
    /// `reason`, when known, is the upstream [`UnknownReason`] recorded at
    /// the site; policies may branch on it. The return must be a real,
    /// compilable type.
    fn unknown_type(&self, reason: Option<&UnknownReason>) -> syn::Type;

    /// The `syn::Expr` to emit in place of a value the IR could not
    /// recover — an unrecognised operation, a raw memory access, a
    /// host-call whose idiom is not yet materialised.
    ///
    /// `label` is a short description of what was there (e.g. the
    /// recovered-op label, or the WASM opcode kind). It is carried into
    /// the emitted expression so the gap is visible in the source: a
    /// `todo!("…")` **string literal survives `prettyplease`** (a bare
    /// `//` comment would not), which is how W2 honours the "surface every
    /// hole" rule for expression-position gaps.
    fn unknown_expr(&self, label: &str) -> syn::Expr;
}

/// The Phase-4 launch policy: **never guess**.
///
/// An unresolved type degrades to `soroban_sdk::Val` — not a guessed
/// concrete type, but the honest statement that every value at the Soroban
/// ABI boundary *is* a `Val` and this one's refinement was not recovered.
pub(crate) struct StrictNoGuess;

impl HolePolicy for StrictNoGuess {
    fn unknown_type(&self, _reason: Option<&UnknownReason>) -> syn::Type {
        parse_quote!(soroban_sdk::Val)
    }

    fn unknown_expr(&self, label: &str) -> syn::Expr {
        // `todo!("<label>")`: diverges (`!`), so it type-checks in any
        // position, and the label is preserved verbatim as a string
        // literal. The `todo!` token here is quoted into the emitted AST,
        // not a real invocation in this crate, so `clippy::todo` does not
        // fire on it.
        let label = Literal::string(&escape_braces(label));
        parse_quote!(todo!(#label))
    }
}

/// Double every brace in a hole label.
///
/// `todo!` is `panic!`-shaped: its first argument is a **format string**, so
/// a brace in the label is read as the start of a placeholder and the
/// emitted crate fails to compile with `invalid format string` — not a hole,
/// a broken build. Labels quote recovered names, and recovered names contain
/// braces: timelock's dispatcher yields
/// `symbol_dispatch TimeBoundKind{Before, After}`.
///
/// Doubling is preferred over passing the label as an argument
/// (`todo!("{}", "…")`) because it keeps the emitted source reading as
/// `todo!("…")`, and over stripping braces because the label is evidence —
/// it should survive intact for a reader.
fn escape_braces(label: &str) -> String {
    if !label.contains(['{', '}']) {
        return label.to_string();
    }
    let mut out = String::with_capacity(label.len() + 8);
    for ch in label.chars() {
        match ch {
            '{' => out.push_str("{{"),
            '}' => out.push_str("}}"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_brace_in_a_label_is_doubled_so_the_crate_still_builds() {
        // The real witness: timelock's dispatcher recovers an enum with its
        // variants, and `todo!` reads the first brace as a placeholder.
        assert_eq!(
            escape_braces("symbol_dispatch TimeBoundKind{Before, After}"),
            "symbol_dispatch TimeBoundKind{{Before, After}}"
        );
        // Untouched when there is nothing to escape — most labels.
        assert_eq!(escape_braces("memory load"), "memory load");
    }

    #[test]
    fn the_emitted_literal_carries_the_escaped_form() {
        let expr = StrictNoGuess.unknown_expr("enum X{A}");
        let rendered = quote::quote!(#expr).to_string();
        assert!(
            rendered.contains("{{A}}"),
            "the hole must reach the source escaped, got {rendered}"
        );
    }
}
