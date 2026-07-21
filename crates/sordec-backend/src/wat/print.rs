//! Flat WAT disassembly with per-line byte offsets.
//!
//! Wraps [`wasmprinter`] in exactly the configuration the annotated-WAT
//! emitter needs and nothing else:
//!
//! - **Flat**, never folded ([`Config::fold_instructions`] is left off).
//!   Folded printing collapses instruction trees onto fewer lines, which
//!   destroys the one-instruction-per-line anchoring the annotator relies
//!   on (research finding R7).
//! - **`name_unnamed`** on, so the stripped fixtures (no `name` custom
//!   section) still get stable `$#funcN` identifiers to anchor against.
//! - **Offsets captured out-of-band** via [`Config::offsets_and_lines`],
//!   *not* printed inline ([`Config::print_offsets`] stays off) — inline
//!   `(;@N;)` markers would corrupt both the text and the annotation
//!   layer.
//!
//! [`Config::fold_instructions`]: wasmprinter::Config::fold_instructions
//! [`Config::offsets_and_lines`]: wasmprinter::Config::offsets_and_lines
//! [`Config::print_offsets`]: wasmprinter::Config::print_offsets

use crate::error::{BackendError, BackendResult};

/// One line of printed WAT together with the original-module byte offset
/// it disassembles from, when `wasmprinter` attributes one.
///
/// `text` retains its trailing newline, so concatenating every
/// [`PrintedLine::text`] in order reproduces the full disassembly
/// verbatim — the annotator inserts and appends whole lines around these
/// without ever re-slicing the printer's output.
#[derive(Debug, Clone)]
pub(crate) struct PrintedLine {
    /// Byte offset into the *original* WASM this line disassembles from,
    /// or `None` for structural lines (module open/close, blank lines)
    /// the printer emits without a source offset.
    pub offset: Option<usize>,
    /// The line's text, including its trailing `\n`.
    pub text: String,
}

/// Disassemble `wasm` to flat WAT, one [`PrintedLine`] per output line.
///
/// # Errors
///
/// Returns [`BackendError::Print`] if `wasmprinter` rejects the module
/// (malformed binary that nonetheless reached the backend).
pub(crate) fn print_flat(wasm: &[u8]) -> BackendResult<Vec<PrintedLine>> {
    let mut config = wasmprinter::Config::new();
    config.name_unnamed(true);

    let mut storage = String::new();
    let lines = config
        .offsets_and_lines(wasm, &mut storage)
        .map_err(|e| BackendError::Print(e.to_string()))?
        .map(|(offset, text)| PrintedLine {
            offset,
            text: text.to_string(),
        })
        .collect();
    Ok(lines)
}

/// Make `note` safe to embed in a `;;` line comment.
///
/// We emit full-line `;;` comments only, which run to end-of-line, so a
/// bare `;` inside the text is harmless and is left intact. Two things
/// are not safe and are neutralised:
///
/// - **newlines** would split one annotation across lines (and the extra
///   lines would not be comments), so `\n`/`\r` collapse to a space;
/// - **`;)`** would prematurely close a `(; … ;)` block comment should an
///   annotation ever be relocated into one — a space is inserted to break
///   the token while preserving readability.
///
/// Research finding R7.
pub(crate) fn sanitize(note: &str) -> String {
    note.replace(['\n', '\r'], " ").replace(";)", "; )")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal valid module: `(module)` with nothing in it.
    const EMPTY_MODULE: &[u8] = &[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

    #[test]
    fn print_flat_concatenation_is_verbatim_disassembly() {
        let lines = print_flat(EMPTY_MODULE).expect("empty module prints");
        assert!(!lines.is_empty(), "even `(module)` yields at least one line");

        // Concatenating the per-line texts must reproduce exactly what
        // wasmprinter would have handed back as one string.
        let rejoined: String = lines.iter().map(|l| l.text.as_str()).collect();
        let direct = wasmprinter::print_bytes(EMPTY_MODULE).expect("prints");
        assert_eq!(rejoined, direct);
    }

    #[test]
    fn print_flat_rejects_garbage() {
        let err = print_flat(b"not wasm").expect_err("garbage must not print");
        assert!(matches!(err, BackendError::Print(_)));
    }

    #[test]
    fn sanitize_neutralises_comment_terminators_and_newlines() {
        let out = sanitize("close ;) here\nand newline");
        assert!(!out.contains(";)"), "`;)` must not survive: {out}");
        assert!(!out.contains('\n'), "newlines must be flattened: {out}");
    }
}
