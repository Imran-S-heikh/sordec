//! Parse recovered facts back out of emitted annotated WAT.
//!
//! The inverse of the L1 header emission in [`super`]: it reads the
//! `;; ── fn … ──` header blocks and their `;;   <fact>` lines back into
//! structured form. The E4 acceptance gate asserts that
//! `extract_header_facts(emit(high))` reproduces exactly the fact set
//! [`recovered_facts`](super::facts::recovered_facts) put in — i.e. the
//! annotations are a lossless serialization of the recovered semantics,
//! checked as a test rather than asserted in prose.
//!
//! Only header-block lines are read. Banner `;;` lines (before the first
//! header) and inline `… ;; callee` notes (which do not start a line with
//! `;;`) are ignored: the header block is the complete, canonical record.

/// One function's recovered facts, as read back from emitted WAT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnotatedFunction {
    /// The header title (`fn … -> …` or an internal-helper form).
    pub title: String,
    /// Recovered-fact lines in emission order.
    pub facts: Vec<String>,
}

/// The sentinel emitted for a function with no recovered operations; it is
/// not a fact and is dropped on the way back in.
const EMPTY_SENTINEL: &str = "(no recovered Soroban operations)";

/// Read every L1 header block out of annotated `wat`, in emission order.
///
/// The inverse of the emitter's per-function header block: an audit tool
/// (or the E4 acceptance gate) can recover the structured fact set from
/// the text alone. Banner and inline notes are ignored — the header block
/// is the canonical, complete record.
#[must_use]
pub fn extract_annotated_facts(wat: &str) -> Vec<AnnotatedFunction> {
    let mut functions = Vec::new();
    let mut current: Option<AnnotatedFunction> = None;

    for line in wat.lines() {
        let trimmed = line.trim_start();
        if let Some(title) = parse_header(trimmed) {
            if let Some(finished) = current.take() {
                functions.push(finished);
            }
            current = Some(AnnotatedFunction {
                title,
                facts: Vec::new(),
            });
        } else if let Some(function) = current.as_mut() {
            match parse_fact(trimmed) {
                Some(fact) if fact != EMPTY_SENTINEL => function.facts.push(fact),
                Some(_) => {} // the empty sentinel — still part of the block
                None => functions.push(current.take().expect("current is Some")),
            }
        }
    }
    if let Some(finished) = current.take() {
        functions.push(finished);
    }
    functions
}

/// `;; ── <title> ──` → `<title>`.
fn parse_header(trimmed: &str) -> Option<String> {
    let body = trimmed.strip_prefix(";;")?.trim();
    let inner = body.strip_prefix("── ")?.strip_suffix(" ──")?;
    Some(inner.to_string())
}

/// A standalone `;; <fact>` comment line → `<fact>`. Returns `None` for any
/// line that does not begin (after indentation) with `;;`, which is what
/// terminates a header block.
fn parse_fact(trimmed: &str) -> Option<String> {
    Some(trimmed.strip_prefix(";;")?.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_header_blocks_and_ignores_banner_and_inline() {
        let wat = "\
;; banner line, not a fact
;;   fn foo() -> () (banner interface, no header rule)
(module
  ;; ── fn transfer(from: Address) -> () ──
  ;;   require_auth(v1) [HostFunctionAbi]
  ;;   storage_get<persistent> DataKey::Balance [SdkPattern]
  (func (;20;) (type 0)
    call 0    ;; require_auth
    unreachable)
  ;; ── fn #21 (internal) ──
  ;;   (no recovered Soroban operations)
  (func (;21;) (type 1))
)
";
        let extracted = extract_annotated_facts(wat);
        assert_eq!(extracted.len(), 2);
        assert_eq!(extracted[0].title, "fn transfer(from: Address) -> ()");
        assert_eq!(
            extracted[0].facts,
            vec![
                "require_auth(v1) [HostFunctionAbi]",
                "storage_get<persistent> DataKey::Balance [SdkPattern]",
            ]
        );
        // The inline `;; require_auth` note is NOT double-counted as a fact.
        assert!(!extracted[0].facts.iter().any(|f| f == "require_auth"));
        // Empty-sentinel function extracts with no facts.
        assert_eq!(extracted[1].title, "fn #21 (internal)");
        assert!(extracted[1].facts.is_empty());
    }
}
