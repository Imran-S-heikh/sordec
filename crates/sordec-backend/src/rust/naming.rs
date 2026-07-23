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
use sordec_ir::HighFunction;

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
            let name = match base_hint(binding) {
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
/// unambiguous structure applies (Step-2 placeholder; filled next).
fn base_hint(_binding: &sordec_ir::Binding) -> Option<String> {
    None
}
