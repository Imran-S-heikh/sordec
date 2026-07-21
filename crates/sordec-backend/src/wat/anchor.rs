//! Anchor recovered facts to positions in the printed WAT.
//!
//! Two correlations, both driven by the E1 per-function body ranges
//! ([`WasmFacts::function_bodies`](sordec_ir::WasmFacts::function_bodies))
//! against the per-line byte offsets `wasmprinter` reports:
//!
//! - [`anchor_functions`] locates each local function's `(func …)` header
//!   line, so the emitter can inject that function's L1 header block; and
//! - [`host_call_sites`] locates the `call $#funcN` lines that target host
//!   imports, so the emitter can label them inline with the callee's
//!   friendly name.
//!
//! Both are sound without any ordinal correlation: a function is found by
//! the byte range its lines disassemble from, and a call's callee is read
//! from the `$#funcN` index the printer itself emitted.

use std::ops::Range;

use sordec_ir::{ByteRange, ImportKind, WasmFacts};

use crate::wat::print::PrintedLine;

/// Number of *function* imports — the size of the imported prefix of the
/// WASM function index space. A `call $#funcN` with `N < func_import_count`
/// targets a host import.
#[must_use]
pub(crate) fn func_import_count(facts: &WasmFacts) -> u32 {
    facts
        .imports
        .iter()
        .filter(|i| matches!(i.kind, ImportKind::Func(_)))
        .count()
        .try_into()
        .unwrap_or(u32::MAX)
}

/// Where a local function's disassembly sits in the printed-line vector.
#[derive(Debug, Clone)]
pub(crate) struct FunctionAnchor {
    /// Local (code-section) function index, 0-based — parallel to
    /// `facts.function_bodies` and to `HighIr::functions`.
    pub local_index: usize,
    /// Printed-line index of the enclosing `(func …)` header; the L1
    /// annotation block is inserted immediately *before* this line.
    pub header_line: usize,
    /// Printed-line range `[first, last)` whose byte offsets fall inside
    /// this function's body.
    pub body_lines: Range<usize>,
}

fn offset_in(range: &ByteRange, offset: usize) -> bool {
    let offset = offset as u64;
    offset >= range.start && offset < range.end
}

fn is_func_header(text: &str) -> bool {
    text.trim_start().starts_with("(func")
}

/// Build one [`FunctionAnchor`] per local function, in code order.
///
/// A function whose lines carry no byte offset is skipped rather than
/// mis-anchored; on rustc/LLVM output every instruction line is
/// offset-tagged (research finding R7), which the corpus test asserts.
#[must_use]
pub(crate) fn anchor_functions(lines: &[PrintedLine], facts: &WasmFacts) -> Vec<FunctionAnchor> {
    facts
        .function_bodies
        .iter()
        .enumerate()
        .filter_map(|(local_index, body)| {
            let in_body = |line: &PrintedLine| line.offset.is_some_and(|o| offset_in(body, o));
            let first = lines.iter().position(in_body)?;
            let last = lines.iter().rposition(in_body)? + 1;
            // Body ranges are disjoint and ordered, so the nearest `(func`
            // at-or-before the first in-range line is unambiguously this
            // function's header.
            let header_line = (0..=first)
                .rev()
                .find(|&i| is_func_header(&lines[i].text))
                .unwrap_or(first);
            Some(FunctionAnchor {
                local_index,
                header_line,
                body_lines: first..last,
            })
        })
        .collect()
}

/// A host-call instruction located in the printed WAT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HostCallSite {
    /// Printed-line index of the `call` instruction.
    pub line: usize,
    /// Module-global function index of the callee (`< func_import_count`).
    pub func_index: u32,
}

/// Parse a flat-printed `call N` line, returning the numeric callee index
/// `N`.
///
/// Only a bare `call` matters (never `call_indirect` / `return_call`).
/// With default (numeric) printing an unnamed callee prints as a bare
/// index; a `$name` callee (a module that kept its `name` section) is not
/// numeric and yields `None`, leaving that site unlabeled inline.
fn parse_call_target(text: &str) -> Option<u32> {
    let rest = text.trim_start().strip_prefix("call ")?;
    let token = rest.split_whitespace().next()?;
    token.parse().ok()
}

/// Host-call sites within one function's body, in printed (execution)
/// order.
#[must_use]
pub(crate) fn host_call_sites(
    lines: &[PrintedLine],
    anchor: &FunctionAnchor,
    func_import_count: u32,
) -> Vec<HostCallSite> {
    anchor
        .body_lines
        .clone()
        .filter_map(|line| {
            let index = parse_call_target(&lines[line].text)?;
            (index < func_import_count).then_some(HostCallSite {
                line,
                func_index: index,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(offset: Option<usize>, text: &str) -> PrintedLine {
        PrintedLine {
            offset,
            text: format!("{text}\n"),
        }
    }

    fn facts_with_bodies(bodies: Vec<(u64, u64)>) -> WasmFacts {
        WasmFacts {
            imports: vec![],
            exports: vec![],
            function_type_indices: vec![],
            function_bodies: bodies
                .into_iter()
                .map(|(start, end)| ByteRange { start, end })
                .collect(),
            custom_sections: vec![],
        }
    }

    #[test]
    fn anchors_header_before_first_in_range_line() {
        let lines = vec![
            line(None, "(module"),
            line(Some(10), "  (func (;0;) (type 0)"),
            line(Some(12), "    call 0"),
            line(Some(20), "    end)"),
            line(None, ")"),
        ];
        let facts = facts_with_bodies(vec![(10, 30)]);
        let anchors = anchor_functions(&lines, &facts);
        assert_eq!(anchors.len(), 1);
        assert_eq!(anchors[0].local_index, 0);
        assert_eq!(anchors[0].header_line, 1, "the `(func` line");
        assert_eq!(anchors[0].body_lines, 1..4);
    }

    #[test]
    fn parses_only_bare_host_calls() {
        assert_eq!(parse_call_target("    call 3"), Some(3));
        assert_eq!(parse_call_target("  call_indirect (type 0)"), None);
        assert_eq!(parse_call_target("    i64.add"), None);
    }

    #[test]
    fn host_call_sites_filter_by_import_count() {
        let lines = vec![
            line(Some(10), "  (func (;2;) (type 0)"),
            line(Some(12), "    call 0"), // host (< 2)
            line(Some(14), "    call 2"), // local (>= 2)
            line(Some(16), "    end)"),
        ];
        let facts = facts_with_bodies(vec![(10, 20)]);
        let anchor = &anchor_functions(&lines, &facts)[0];
        let sites = host_call_sites(&lines, anchor, 2);
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].func_index, 0);
        assert_eq!(sites[0].line, 1);
    }
}
