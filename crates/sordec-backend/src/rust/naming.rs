//! Value naming: the single authority mapping each [`ValueId`] to the
//! identifier it is emitted under.
//!
//! Every place that produces a value's name — its `let` binding, each read,
//! phi `let mut` declarations and their transfer assignments, hoisted
//! escaping-value declarations — goes through one [`ValueNames`] map built
//! once per function. Routing all of them through a single table is what
//! makes a value's name *consistent*: a name chosen for a binding is the
//! same at every use, so nothing drifts. (This mirrors
//! [`sig::param_idents`](super::sig::param_idents), already "the single
//! source of parameter names".)
//!
//! Consistency is also a correctness property for the scorer: its
//! `LetResolver` correlates a storage-key binding to its use site by name,
//! so a rename that stayed consistent leaves resolution unchanged.
//!
//! Names come from two sources, in priority order:
//!
//! 1. **Parameters** — the recovered signature identifier (`sig::param_idents`).
//! 2. **Everything else** — the SSA fallback `v{index}`.
//!
//! Structural *hints* (naming a storage read after its key, a ledger read
//! after the quantity it fetches) layer on top in [`base_hint`]; they are
//! never a guess — only unambiguous structure earns a word, and anything
//! un-nameable keeps its `v{index}`.

use std::collections::HashMap;

use quote::format_ident;
use syn::parse_quote;

use sordec_common::{IrId, ValueId};
use sordec_ir::{Binding, Expr, HighFunction, KnownOp, SemanticOp};

use crate::rust::sig;
use crate::rust::ty::ident;

/// The per-function value-name table. Built once by [`ValueNames::build`]
/// and consulted for every identifier the body emits.
pub(crate) struct ValueNames {
    map: HashMap<ValueId, syn::Ident>,
}

impl ValueNames {
    /// Build the name table for one function.
    ///
    /// Parameters take their recovered signature names; every other binding
    /// is assigned in ascending [`ValueId`] order (the arena's iteration
    /// order) so emission is deterministic. A binding earns a structural
    /// name from [`base_hint`] when one applies and is free; a hint that
    /// would collide with an already-taken name (a parameter, or an earlier
    /// hinted value) is disambiguated as `{base}_{index}`, keeping it unique
    /// and traceable to the SSA id. Values with no hint keep `v{index}`,
    /// which is unique by construction.
    pub(crate) fn build(func: &HighFunction) -> Self {
        let mut map: HashMap<ValueId, syn::Ident> = HashMap::new();
        let mut taken: HashMap<String, u32> = HashMap::new();

        // 1. Parameters reserve their names first.
        for (vid, name) in func.params.iter().copied().zip(sig::param_idents(func)) {
            taken.entry(name.to_string()).or_default();
            map.insert(vid, name);
        }

        // 2. Every other binding, in ascending-id order.
        for (vid, binding) in func.bindings.iter() {
            if map.contains_key(&vid) {
                continue; // a parameter
            }
            let name = match base_hint(func, binding) {
                Some(base) if !taken.contains_key(&base) => {
                    taken.insert(base.clone(), 0);
                    ident(&base)
                }
                // No hint, or the hint is taken: keep the unique SSA name.
                // A taken hint disambiguates as `{base}_{index}` rather than
                // silently reusing `v{index}`, so the intent still shows.
                Some(base) => ident(&format!("{base}_{}", vid.index())),
                None => value_fallback(vid),
            };
            map.insert(vid, name);
        }

        Self { map }
    }

    /// The identifier a value is emitted under. Falls back to `v{index}` for
    /// an id absent from the table (a should-not-happen case for valid SSA;
    /// handled rather than panicking).
    pub(crate) fn ident(&self, vid: ValueId) -> syn::Ident {
        self.map.get(&vid).cloned().unwrap_or_else(|| value_fallback(vid))
    }

    /// The value as a `syn::Expr` (a bare path to its identifier).
    pub(crate) fn expr(&self, vid: ValueId) -> syn::Expr {
        let name = self.ident(vid);
        parse_quote!(#name)
    }
}

/// The SSA fallback name for a value: `v{index}`.
fn value_fallback(vid: ValueId) -> syn::Ident {
    format_ident!("v{}", vid.index())
}

/// A structural name for the value a binding produces, or `None` when no
/// unambiguous structure applies.
///
/// Deliberately conservative: a word is earned only from structure that
/// *names itself* — the enum variant a storage slot is keyed by, or the
/// fixed quantity a ledger-context read fetches. No name is inferred from a
/// value's type alone (an `i128` is not assumed to be an `amount`): that
/// would be a guess, and the project's rule is never to mislead. Everything
/// unrecognised keeps its `v{index}`.
fn base_hint(func: &HighFunction, binding: &Binding) -> Option<String> {
    match &binding.expr {
        Expr::Semantic(SemanticOp::Known(op)) => known_op_hint(func, op),
        _ => None,
    }
}

/// How far to follow a chain of renames looking for the key's constant.
const MAX_RENAME_HOPS: usize = 8;

/// The word a storage key offers, when it names one unambiguously.
///
/// An enum key gives its variant. A **symbol** key gives its text, which
/// is the commoner shape by far — `const COUNTER: Symbol =
/// symbol_short!("COUNTER")` is how most contracts key their storage, and
/// naming only the enum case left every one of those reads as `vN`.
/// Measured across the held-out set before this: 28 named bindings out of
/// 9570.
///
/// The text is the author's own word for the slot, recovered from rodata
/// or a `SymbolSmall` constant, so it is structure rather than a guess —
/// the same licence the variant name has.
fn key_word(func: &HighFunction, key: ValueId) -> Option<String> {
    // Renames sit between the op and the constant, so follow them: the key
    // operand is rarely the literal binding itself.
    let mut key = key;
    for _ in 0..MAX_RENAME_HOPS {
        match func.bindings.get(key).map(|b| &b.expr) {
            Some(Expr::Use(inner)) => key = *inner,
            _ => break,
        }
    }
    match &func.bindings.get(key)?.expr {
        Expr::Literal(sordec_ir::Literal::Symbol(text)) => Some(snake(text)),
        Expr::Semantic(SemanticOp::Known(KnownOp::SymbolNew {
            resolved: Some(text),
            ..
        })) => Some(snake(text)),
        _ => None,
    }
}

/// The name a recovered host op lends the value it produces.
fn known_op_hint(func: &HighFunction, op: &KnownOp) -> Option<String> {
    match op {
        // A storage read is named after the slot it reads: the recovered
        // key variant (`DataKey::Balance` → `balance`). Only when the key
        // was actually resolved — an unresolved key has no honest name.
        KnownOp::StorageGet { resolved_key: Some(ek), .. } => Some(snake(&ek.variant)),
        KnownOp::StorageHas { resolved_key: Some(ek), .. } => {
            Some(format!("has_{}", snake(&ek.variant)))
        }
        // The same, for the commoner symbol-keyed form.
        KnownOp::StorageGet { key, .. } => key_word(func, *key),
        KnownOp::StorageHas { key, .. } => key_word(func, *key).map(|k| format!("has_{k}")),
        // A symbol is its own name.
        KnownOp::SymbolNew { resolved: Some(text), .. } => Some(snake(text)),
        // A cross-contract call is named for the function it invokes.
        KnownOp::InvokeContract { resolved_callee: Some(name), .. }
        | KnownOp::TryInvokeContract { resolved_callee: Some(name), .. } => Some(snake(name)),
        // Ledger context reads a single, well-known quantity.
        KnownOp::GetLedgerSequence => Some("sequence".to_string()),
        KnownOp::GetLedgerTimestamp => Some("timestamp".to_string()),
        KnownOp::GetLedgerProtocolVersion => Some("protocol_version".to_string()),
        KnownOp::GetLedgerNetworkId => Some("network_id".to_string()),
        KnownOp::GetMaxLiveUntilLedger => Some("max_live_until_ledger".to_string()),
        KnownOp::GetCurrentContractAddress => Some("current_contract_address".to_string()),
        _ => None,
    }
}

/// `PascalCase` → `snake_case`, ASCII only. A `_` is inserted before an
/// uppercase letter that begins a new word — one preceded by a lowercase or
/// digit, or one that starts a word after an acronym (the last capital of a
/// run, when a lowercase follows). Sufficient for `contractspecv0` variant
/// names, which are valid Rust identifiers by construction.
pub(crate) fn snake(pascal: &str) -> String {
    let chars: Vec<char> = pascal.chars().collect();
    let mut out = String::with_capacity(pascal.len() + 2);
    for (i, &c) in chars.iter().enumerate() {
        if c.is_ascii_uppercase() {
            let prev_wordish =
                i > 0 && (chars[i - 1].is_ascii_lowercase() || chars[i - 1].is_ascii_digit());
            let starts_word = i + 1 < chars.len() && chars[i + 1].is_ascii_lowercase();
            if i > 0 && (prev_wordish || starts_word) {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snake_converts_variant_names() {
        assert_eq!(snake("Balance"), "balance");
        assert_eq!(snake("Admin"), "admin");
        assert_eq!(snake("AllowanceValue"), "allowance_value");
        assert_eq!(snake("SetAdmin"), "set_admin");
        // Acronym boundary: the run's last capital starts the next word.
        assert_eq!(snake("HTTPServer"), "http_server");
        // Already-lower and single letters survive.
        assert_eq!(snake("A"), "a");
    }

    /// A context read names itself; these need no function to consult.
    /// A one-binding function whose only value is `key_expr`, for the
    /// naming gates that consult the key's producer.
    fn func_with_key(key_expr: Expr) -> HighFunction {
        use sordec_common::{Arena, BlockId, FuncId, Provenance, ProvenanceSource, UnknownReason};
        use sordec_ir::{Binding, HighBlock, IrType, Region};
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        bindings.push(Binding::new(
            ValueId::from_index(0),
            IrType::Unknown(UnknownReason::InsufficientEvidence),
            key_expr,
            Provenance::new("test", ProvenanceSource::DataFlow, "test"),
        ));
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        let block = BlockId::from_index(0);
        blocks.push(HighBlock { id: block, bindings: vec![ValueId::from_index(0)] });
        HighFunction {
            id: FuncId::from_index(0),
            name: None,
            signature: None,
            blocks,
            bindings,
            region: Region::Basic(block),
            params: vec![],
            returns: vec![],
        }
    }

    fn empty_func() -> HighFunction {
        func_with_key(Expr::Phi { incoming: vec![] })
    }

    #[test]
    fn ledger_ops_earn_names() {
        let func = empty_func();
        assert_eq!(
            known_op_hint(&func, &KnownOp::GetLedgerSequence).as_deref(),
            Some("sequence")
        );
        assert_eq!(
            known_op_hint(&func, &KnownOp::GetCurrentContractAddress).as_deref(),
            Some("current_contract_address")
        );
        assert_eq!(
            known_op_hint(&func, &KnownOp::GetLedgerNetworkId).as_deref(),
            Some("network_id")
        );
    }

    /// A storage read takes its word from the key. A key that names
    /// nothing — an unresolved value, not a constant — leaves the read
    /// unnamed rather than inventing one.
    #[test]
    fn a_storage_read_is_named_after_a_symbol_key() {
        let func = func_with_key(Expr::Literal(sordec_ir::Literal::Symbol("COUNTER".into())));
        let op = KnownOp::StorageGet {
            tier: sordec_ir::StorageTier::Known(sordec_ir::KnownTier::Instance),
            durability: ValueId::from_index(0),
            key: ValueId::from_index(0),
            resolved_key: None,
            missing: sordec_ir::Missing::Option,
        };
        assert_eq!(known_op_hint(&func, &op).as_deref(), Some("counter"));

        let opaque = func_with_key(Expr::Phi { incoming: vec![] });
        assert!(known_op_hint(&opaque, &op).is_none(), "no key, no name");
    }
}

