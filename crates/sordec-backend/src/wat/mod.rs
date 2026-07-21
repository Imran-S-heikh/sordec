//! Annotated-WAT emitter.
//!
//! [`emit_annotated_wat`] disassembles a module to flat WAT and weaves in
//! the recovered semantics as `;;` comments, in three tiers:
//!
//! - **L1 — per-function header block** (before each `(func …)`): the
//!   complete, always-present list of that function's recovered facts.
//!   Sourced by a direct walk of the [`HighIr`], so nothing is ever lost.
//! - **L2 — inline callee name** (on each host `call` line): the friendly
//!   host-function name, read from the catalog by the callee index the
//!   printer emitted. Sound without any positional correlation.
//! - raw `module::name` fallback where the callee is not in the catalog.
//!
//! Site-specific detail (which storage key, which dispatch arm) lives in
//! the L1 header, where it is unambiguous — the emitter never guesses a
//! line-to-fact mapping it cannot prove.

mod annotate;
mod anchor;
mod banner;
mod extract;
mod facts;
mod print;

#[cfg(test)]
mod corpus_tests;

use std::fmt::Write as _;

use sordec_ir::{HighIr, Import, ImportKind, WasmFacts};

use crate::error::BackendResult;
use crate::wat::facts::FunctionFacts;

pub use extract::{extract_annotated_facts, AnnotatedFunction};

/// Emit annotated WAT for `high`, disassembled from its original `wasm`
/// bytes.
///
/// # Errors
///
/// Returns [`BackendError::Print`](crate::BackendError::Print) if
/// `wasmprinter` cannot disassemble `wasm`.
pub fn emit_annotated_wat(high: &HighIr, wasm: &[u8]) -> BackendResult<String> {
    let lines = print::print_flat(wasm)?;
    let module_facts = facts::recovered_facts(high);
    let anchors = anchor::anchor_functions(&lines, &high.facts);
    let import_count = anchor::func_import_count(&high.facts);
    let func_imports = collect_func_imports(&high.facts);

    // Per-line injection maps, indexed by printed-line position.
    let mut header_at: Vec<Option<usize>> = vec![None; lines.len()];
    let mut note_at: Vec<Option<String>> = vec![None; lines.len()];
    for anchor in &anchors {
        if module_facts.get(anchor.local_index).is_some() {
            header_at[anchor.header_line] = Some(anchor.local_index);
        }
        for site in anchor::host_call_sites(&lines, anchor, import_count) {
            note_at[site.line] = Some(callee_note(&func_imports, site.func_index));
        }
    }

    let mut out = String::new();
    for banner_line in banner::render(high) {
        out.push_str(&banner_line);
        out.push('\n');
    }
    for (i, printed) in lines.iter().enumerate() {
        if let Some(idx) = header_at[i] {
            emit_header_block(&mut out, &printed.text, &module_facts[idx]);
        }
        match &note_at[i] {
            Some(note) => emit_line_with_note(&mut out, &printed.text, note),
            None => out.push_str(&printed.text),
        }
    }
    Ok(out)
}

/// The function imports in function-index order: `func_imports[N]` is the
/// import a `call $#funcN` (`N < func_import_count`) targets.
fn collect_func_imports(facts: &WasmFacts) -> Vec<&Import> {
    facts
        .imports
        .iter()
        .filter(|i| matches!(i.kind, ImportKind::Func(_)))
        .collect()
}

/// Friendly, catalog-backed label for a host `call` site, falling back to
/// the raw `module::name` when the callee is not a recognised host import.
fn callee_note(func_imports: &[&Import], func_index: u32) -> String {
    let Some(import) = func_imports.get(func_index as usize) else {
        return "call (host import out of range)".to_string();
    };
    let note = match sordec_passes::resolve_host_call(&import.module, &import.name) {
        Some(host) => host.friendly_name.to_string(),
        None => format!("{}::{} (unrecognized host import)", import.module, import.name),
    };
    print::sanitize(&note)
}

/// Emit the L1 header block for `facts`, indented to match the `(func …)`
/// line it precedes.
fn emit_header_block(out: &mut String, header_line: &str, facts: &FunctionFacts) {
    let indent = leading_whitespace(header_line);
    let _ = writeln!(out, "{indent};; ── {} ──", print::sanitize(&facts.title));
    if facts.facts.is_empty() {
        let _ = writeln!(out, "{indent};;   (no recovered Soroban operations)");
        return;
    }
    for fact in &facts.facts {
        let _ = writeln!(out, "{indent};;   {}", print::sanitize(fact));
    }
}

/// Append a `;;` note to a printed line, preserving its trailing newline.
fn emit_line_with_note(out: &mut String, line_text: &str, note: &str) {
    let body = line_text.strip_suffix('\n').unwrap_or(line_text);
    let _ = writeln!(out, "{body}    ;; {note}");
}

fn leading_whitespace(text: &str) -> &str {
    &text[..text.len() - text.trim_start().len()]
}
