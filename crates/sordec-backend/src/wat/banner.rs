//! The module-header banner: leading `;;` lines summarising the contract.
//!
//! Rendered from the decoded Soroban metadata ([`SorobanFacts`]) plus the
//! raw module shape ([`WasmFacts`]) — the public interface from
//! `contractspecv0`, the protocol/SDK versions from `contractenvmetav0` /
//! `contractmetav0`, and import/export/function counts. This is the audit
//! reader's orientation header; the shape follows the legacy emitter's
//! banner (`_legacy/.../emit.rs`) but is rebuilt against v2 types.
//!
//! [`SorobanFacts`]: sordec_ir::SorobanFacts
//! [`WasmFacts`]: sordec_ir::WasmFacts

use sordec_ir::{HighIr, ImportKind, SorobanFacts};

use crate::wat::annotate;

const RULE: &str = ";; ════════════════════════ Soroban annotated WAT ════════════════════════";

/// Render the banner as a list of `;;` comment lines (no trailing
/// newlines — the caller joins them).
#[must_use]
pub(crate) fn render(high: &HighIr) -> Vec<String> {
    let mut lines = vec![
        RULE.to_string(),
        ";; Emitted by sordec. `;;` lines are recovered annotations, not original".to_string(),
        ";; source; the byte encoding is not round-tripped (see K5 acceptance).".to_string(),
        ";;".to_string(),
    ];

    match &high.soroban_facts {
        Some(facts) => render_interface(&mut lines, facts),
        None => lines.push(";;   (no contractspecv0 — stripped or non-Soroban module)".to_string()),
    }

    lines.push(";;".to_string());
    lines.push(render_shape(high));
    lines.push(RULE.to_string());
    lines
}

fn render_interface(lines: &mut Vec<String>, facts: &SorobanFacts) {
    lines.push(";; interface (from contractspecv0):".to_string());
    if facts.functions.is_empty() {
        lines.push(";;   (no contract functions)".to_string());
    }
    // `functions` is a BTreeMap, so iteration is name-sorted and stable.
    for sig in facts.functions.values() {
        lines.push(format!(";;   {}", annotate::render_signature(sig, &facts.types)));
    }

    if let Some(protocol) = &facts.env_meta.protocol {
        lines.push(format!(";; protocol: {protocol}"));
    }
    for (key, value) in &facts.contract_meta {
        lines.push(format!(";; {key}: {value}"));
    }
}

fn render_shape(high: &HighIr) -> String {
    let host_fns = high
        .facts
        .imports
        .iter()
        .filter(|i| matches!(i.kind, ImportKind::Func(_)))
        .count();
    format!(
        ";; module: {} imports ({host_fns} host fns) · {} exports · {} functions",
        high.facts.imports.len(),
        high.facts.exports.len(),
        high.functions.len(),
    )
}
