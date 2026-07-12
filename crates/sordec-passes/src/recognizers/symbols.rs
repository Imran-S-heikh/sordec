//! Shared substrate for recognizing `#[contracttype]` enum/symbol
//! constructs.
//!
//! Two passes recover Soroban enums from the bytes rustc baked into
//! rodata: `enum-key` (storage-key enum *construction*, `DataKey::Admin`)
//! and `dispatcher` (enum-from-`Val` *decode*, `symbol_index_in_linear_memory`).
//! Both need to (a) validate raw rodata bytes as a Soroban `Symbol` and
//! (b) name a recovered variant set against the `contractspecv0` union
//! registry. Those two steps live here so the passes share one honest
//! implementation.

use std::collections::BTreeSet;

use sordec_ir::UnionDef;

/// Longest Soroban `Symbol` the SDK constructs from rodata: the `Symbol`
/// grammar caps identifiers at 32 characters.
pub(crate) const MAX_SYMBOL_LEN: usize = 32;

/// Validate raw rodata bytes as a Soroban `Symbol` identifier and return
/// the decoded text.
///
/// A `Symbol` is 1..=[`MAX_SYMBOL_LEN`] bytes of ASCII alphanumerics and
/// `_`. Returns `None` for an empty or oversized slice, non-UTF-8 bytes,
/// or any character outside the grammar — a rejected slice is never
/// guessed at, it simply fails to resolve.
pub(crate) fn valid_symbol_text(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() || bytes.len() > MAX_SYMBOL_LEN {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?;
    text.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        .then(|| text.to_string())
}

/// The set of case (variant) names a union declares.
pub(crate) fn union_case_set(union: &UnionDef) -> BTreeSet<String> {
    union.cases.iter().map(|c| c.name.clone()).collect()
}

/// Index of the unique `contractspecv0` union whose case-name set equals
/// `cases`.
///
/// Returns `None` when no union matches or more than one does (ambiguous
/// — never guess). The comparison is on the case *set*, not order, so a
/// recovered variant list names its enum regardless of the order it was
/// recovered in relative to the spec's declaration order.
pub(crate) fn unique_union_index_by_cases(
    unions: &[UnionDef],
    cases: &BTreeSet<String>,
) -> Option<usize> {
    let mut matches = unions
        .iter()
        .enumerate()
        .filter(|(_, u)| union_case_set(u) == *cases);
    let (idx, _) = matches.next()?;
    matches.next().is_none().then_some(idx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{IrId, TypeId};
    use sordec_ir::{UnionCase, UnionDef};

    fn union(name: &str, cases: &[&str]) -> UnionDef {
        UnionDef {
            id: TypeId::from_index(0),
            name: name.to_string(),
            cases: cases
                .iter()
                .map(|c| UnionCase {
                    name: c.to_string(),
                    fields: vec![],
                })
                .collect(),
        }
    }

    #[test]
    fn valid_symbol_text_accepts_grammar() {
        assert_eq!(valid_symbol_text(b"Before"), Some("Before".to_string()));
        assert_eq!(valid_symbol_text(b"Data_Key9"), Some("Data_Key9".to_string()));
    }

    #[test]
    fn valid_symbol_text_rejects_out_of_grammar() {
        assert_eq!(valid_symbol_text(b""), None);
        assert_eq!(valid_symbol_text(b"has space"), None);
        assert_eq!(valid_symbol_text(b"emoji\xF0\x9F\x98\x80"), None);
        assert_eq!(valid_symbol_text(&[0xff, 0xfe]), None);
        assert_eq!(valid_symbol_text(&[b'a'; MAX_SYMBOL_LEN + 1]), None);
    }

    #[test]
    fn unique_union_match_returns_index() {
        let unions = vec![union("DataKey", &["Admin", "Balance"]), union("Kind", &["A", "B"])];
        let set: BTreeSet<String> = ["A", "B"].iter().map(|s| s.to_string()).collect();
        assert_eq!(unique_union_index_by_cases(&unions, &set), Some(1));
    }

    #[test]
    fn no_match_and_ambiguous_match_both_refuse() {
        let ambiguous = vec![union("Kind1", &["A", "B"]), union("Kind2", &["B", "A"])];
        let set: BTreeSet<String> = ["A", "B"].iter().map(|s| s.to_string()).collect();
        // Two unions, identical case set → ambiguous → None.
        assert_eq!(unique_union_index_by_cases(&ambiguous, &set), None);
        // No union with this set → None.
        let other: BTreeSet<String> = ["X"].iter().map(|s| s.to_string()).collect();
        assert_eq!(unique_union_index_by_cases(&ambiguous, &other), None);
    }
}
