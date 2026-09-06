//! Diagnostic printing for `sordec` subcommands.
//!
//! Pipeline outputs (`ParseOutput`, `LiftOutput`, etc.) carry named
//! diagnostic artifacts backed by slices of non-fatal warning and info
//! [`Diagnostic`] events. After a subcommand finishes successfully, it
//! prints those diagnostics to stderr via [`print_diagnostics`] before
//! exiting. stderr (not stdout) keeps a subcommand's primary output
//! (JSON, IR text, etc.) on stdout pipe-friendly.
//!
//! v0 keeps this minimal: one line per diagnostic, severity-prefixed,
//! using the `Display` impl on [`Diagnostic`]. Future polish (colored
//! severity tags, structured JSON output for CI consumption, grouping
//! by code) can layer on top without changing the helper's signature.

use std::io::Write;

use sordec_common::Diagnostic;

/// Print every diagnostic in `diags` to a writer, one per line, using
/// the `Display` impl on [`Diagnostic`]. Returns the writer's I/O error
/// if any write fails.
///
/// This is the inner helper. CLI subcommands call [`print_diagnostics`]
/// (the convenience that targets `stderr`).
pub fn write_diagnostics<W: Write>(out: &mut W, diags: &[Diagnostic]) -> std::io::Result<()> {
    for d in diags {
        writeln!(out, "{d}")?;
    }
    Ok(())
}

/// Print every diagnostic in `diags` to `stderr`, one per line.
///
/// Errors from the underlying `stderr` write are silently ignored —
/// stderr being un-writable is a deeper problem the CLI has no way to
/// recover from, and surfacing it here would only obscure whatever
/// caused the inability to write in the first place.
pub fn print_diagnostics(diags: &[Diagnostic]) {
    let stderr = std::io::stderr();
    let mut handle = stderr.lock();
    let _ = write_diagnostics(&mut handle, diags);
}

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{
        Diagnostic, DiagnosticCode, Location, MetadataDiagnosticCode, Severity,
    };

    #[test]
    fn write_diagnostics_emits_one_line_per_entry() {
        let diags = vec![
            Diagnostic {
                severity: Severity::Warning,
                code: DiagnosticCode::Metadata(MetadataDiagnosticCode::DuplicateTypeName {
                    name: "Foo".to_string(),
                }),
                message: String::new(),
                location: Some(Location::CustomSection {
                    name: "contractspecv0".to_string(),
                }),
            },
            Diagnostic {
                severity: Severity::Info,
                code: DiagnosticCode::Metadata(MetadataDiagnosticCode::DuplicateFunctionName {
                    name: "do_stuff".to_string(),
                }),
                message: String::new(),
                location: None,
            },
        ];

        let mut buf: Vec<u8> = Vec::new();
        write_diagnostics(&mut buf, &diags).expect("writes succeed");
        let text = String::from_utf8(buf).expect("utf-8");

        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "got: {text:?}");
        assert!(lines[0].starts_with("[warning]"), "got: {}", lines[0]);
        assert!(lines[1].starts_with("[info]"), "got: {}", lines[1]);
        assert!(lines[0].contains("\"Foo\""));
        assert!(lines[1].contains("\"do_stuff\""));
    }

    #[test]
    fn write_diagnostics_with_empty_slice_writes_nothing() {
        let mut buf: Vec<u8> = Vec::new();
        write_diagnostics(&mut buf, &[]).expect("writes succeed");
        assert!(buf.is_empty());
    }
}
