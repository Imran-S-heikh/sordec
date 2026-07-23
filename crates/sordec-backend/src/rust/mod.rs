//! Compilable-Rust emitter.
//!
//! Turns the recovered [`HighIr`] into a `src/lib.rs` source string via a
//! `syn` AST printed with `prettyplease`. Building the AST (rather than
//! formatting strings) makes syntactic validity structural: the emitter
//! cannot produce unparseable Rust.
//!
//! Phase 4 · W1 emits the *skeleton* — reconstructed `#[contracttype]`s,
//! the `#[contract]` / `#[contractimpl]` scaffold, and every function
//! signature with a `todo!()` body. Bodies (the region → expression walk)
//! land in W2 at the single body site in [`func`].

mod contract_type;
mod func;
mod hole;
mod scaffold;
mod sig;
mod ty;

use sordec_ir::{HighIr, TypeRegistry};

use crate::error::BackendResult;
use crate::rust::func::Emitted;
use crate::rust::hole::{HolePolicy, StrictNoGuess};

/// Emit compilable Rust (`src/lib.rs` contents) reconstructed from `high`.
///
/// The output is produced from a `syn` AST, so it always parses; a stripped
/// module (no `contractspecv0`) yields a `#![no_std]` module of free
/// functions with no contract scaffold.
///
/// # Errors
///
/// Currently infallible — the return type mirrors
/// [`emit_annotated_wat`](crate::emit_annotated_wat) and reserves space for
/// the fallible body emission added in a later wave.
pub fn emit_rust(high: &HighIr) -> BackendResult<String> {
    let policy = StrictNoGuess;
    let file = build_file(high, &policy);
    Ok(prettyplease::unparse(&file))
}

/// Generate the `Cargo.toml` for the reconstructed contract crate.
///
/// Companion to [`emit_rust`]; the CLI writes the two side by side so the
/// output directory is a buildable crate.
#[must_use]
pub fn emit_cargo_toml(high: &HighIr) -> String {
    scaffold::emit_cargo_toml(high)
}

/// Assemble the whole module as a `syn::File`.
fn build_file(high: &HighIr, policy: &dyn HolePolicy) -> syn::File {
    let types = high.soroban_facts.as_ref().map(|f| &f.types);

    // Reconstructed user-defined types (empty for a stripped module).
    let type_items = types
        .map(|reg| contract_type::contract_types(reg, policy))
        .unwrap_or_default();

    // Classify every function into a contract method or a free helper.
    let fallback_reg = TypeRegistry::default();
    let reg = types.unwrap_or(&fallback_reg);
    let mut methods: Vec<syn::ImplItemFn> = Vec::new();
    let mut free_fns: Vec<syn::Item> = Vec::new();
    for func in &high.functions {
        match func::emit_function(func, reg, policy) {
            Emitted::Method(m) => methods.push(*m),
            Emitted::Free(f) => free_fns.push(*f),
        }
    }

    // Order: imports · types · contract struct+impl · free helpers.
    let mut items: Vec<syn::Item> = Vec::new();
    if let Some(use_item) = scaffold::use_item(types, !methods.is_empty()) {
        items.push(use_item);
    }
    items.extend(type_items);
    if !methods.is_empty() {
        items.push(scaffold::contract_struct());
        items.push(scaffold::contract_impl(methods));
    }
    items.extend(free_fns);

    syn::File {
        shebang: None,
        attrs: vec![syn::parse_quote!(#![no_std])],
        items,
    }
}
