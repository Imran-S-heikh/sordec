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

mod body;
mod contract_type;
mod expr;
mod fold;
mod func;
mod hole;
mod idiom;
mod imports;
mod liveness;
mod naming;
mod scaffold;
mod sig;
mod ty;

use std::collections::HashSet;

use sordec_common::FuncId;
use sordec_ir::{Expr, HighIr, Region, TypeRegistry};

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

/// The functions the emitted module needs: every root, plus everything
/// reachable from one by a call the body actually emits.
///
/// Roots are the `contractspecv0` entrypoints (which become
/// `#[contractimpl]` methods) and any function carrying a recovered export
/// name — dropping a module export would change the reconstruction's
/// surface, which is not this filter's business.
///
/// Unreachable helpers are skipped at **emission**, never removed from the
/// IR: preserving everything recovered is the IR's job, and a view of it
/// is the right place to decide what a compilable crate needs. Marshalling
/// elision is what makes this load-bearing rather than cosmetic — once an
/// argument decode collapses to its parameter, the SDK's `TryFromVal`
/// helper has no callers at all, and emitting a dead helper full of
/// un-lowered `Val` holes fails `cargo check` for code nothing runs.
///
/// Reachability follows *emitted* calls, matching how [`liveness`] defines
/// use: a call sitting in an unscheduled binding is not in the output, so
/// it cannot keep a callee alive.
fn reachable_functions(high: &HighIr) -> HashSet<FuncId> {
    let mut reachable: HashSet<FuncId> = HashSet::new();
    let mut queue: Vec<FuncId> = high
        .functions
        .iter()
        .filter(|f| f.signature.is_some() || f.name.is_some())
        .map(|f| f.id)
        .collect();

    while let Some(id) = queue.pop() {
        if !reachable.insert(id) {
            continue;
        }
        let Some(func) = high.function(id) else {
            continue;
        };
        func.region.for_each_node(|node| {
            if let Region::Basic(b) = node
                && let Some(block) = func.blocks.get(*b)
            {
                for vid in &block.bindings {
                    if let Some(binding) = func.bindings.get(*vid)
                        && let Expr::Call { target, .. } = &binding.expr
                        && !reachable.contains(target)
                    {
                        queue.push(*target);
                    }
                }
            }
        });
    }
    reachable
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
    let reachable = reachable_functions(high);
    for func in &high.functions {
        if !reachable.contains(&func.id) {
            continue;
        }
        for emitted in func::emit_function(high, func, reg, policy) {
            match emitted {
                Emitted::Method(m) => methods.push(*m),
                Emitted::Free(f) => free_fns.push(*f),
            }
        }
    }

    // Assemble the body (types · contract struct+impl · free helpers) with
    // fully-qualified soroban paths, as each emitter piece produces them.
    let has_impl = !methods.is_empty();
    let mut body: Vec<syn::Item> = Vec::new();
    body.extend(type_items);
    if has_impl {
        body.push(scaffold::contract_struct());
        body.push(scaffold::contract_impl(methods));
    }
    body.extend(free_fns);

    // Collapse `soroban_sdk::…` paths to short names, then build the single
    // `use` merging the collected types/macros with the attribute macros the
    // scaffold needs (those are emitted bare, so must always be imported).
    let mut import_names = imports::collapse(&mut body);
    import_names.extend(scaffold::macro_imports(types, has_impl).iter().map(ToString::to_string));

    // Order: imports · body.
    let mut items: Vec<syn::Item> = Vec::new();
    if let Some(use_item) = imports::use_item(&import_names) {
        items.push(use_item);
    }
    items.extend(body);

    syn::File {
        shebang: None,
        attrs: vec![syn::parse_quote!(#![no_std])],
        items,
    }
}
