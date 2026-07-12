//! Pattern-recovery passes over `HighIr`.
//!
//! Each recognizer is a [`crate::Pass`]`<HighIr>` that matches a Soroban
//! SDK idiom in the lowered IR and rewrites the matching bindings into
//! [`sordec_ir::SemanticOp`]s, attaching provenance. Recognizers are
//! monotonic and idempotent (a second run over already-recognized IR
//! reports `changed: false`), so they compose in the fixpoint pipeline
//! group.
//!
//! One resident is not a recognizer: [`const_prop`] is an *upgrade*
//! pass that deliberately bypasses the shared [`is_recognized`] skip
//! guard — its domain is already-`Known` ops carrying an
//! honestly-unresolved slot (`tier: Unknown`, `resolved: None`), which
//! it refines in place. It obeys the same monotonicity and idempotency
//! contract (a filled slot no longer matches).
//!
//! The C-series recognizers land here as separate modules:
//!
//! - [`val_encoding`] (C1) — Soroban `Val` encode/decode/tag-check and
//!   object-conversion patterns.
//! - [`storage`] (C2+C3) — storage tier resolution + TTL extension
//!   calls (the `l`-module CRUD/TTL surface).
//! - [`auth`] (C4) — authorization primitives + address conversions
//!   (the `a`-module surface).
//! - [`context`] (C15+C14+C16-partial) — ledger accessors, event
//!   emission, `Val` comparison, and the `fail_with_error` panic
//!   primitive (the `x`-module surface).
//! - [`linear_memory`] — the `*_new_from_linear_memory` constructors
//!   (`Symbol`/`String`/`Bytes`/`Vec`/`Map`) across the `b`/`v`/`m`
//!   modules, resolving literal contents against the module's rodata.
//! - [`collections`] — the remaining `m`/`v`/`b` surface: every map,
//!   vec, and bytes/string/symbol host operation (52 functions).
//! - [`cross_contract`] — the `d`-module `call` / `try_call` pair
//!   (`env.invoke_contract` / `env.try_invoke_contract`).
//! - [`const_prop`] — the inter-procedural upgrade pass (see above).

pub mod abi_sweep;
pub mod auth;
pub mod auth_flow;
pub mod client_call;
pub mod collections;
pub mod const_prop;
pub mod context;
pub mod cross_contract;
pub mod enum_key;
pub mod linear_memory;
pub mod storage;
pub mod val_encoding;
pub(crate) mod wrappers;

pub use abi_sweep::AbiSweepPass;
pub use auth::AuthPass;
pub use auth_flow::AuthFlowPass;
pub use client_call::ClientCallPass;
pub use collections::CollectionsPass;
pub use const_prop::ConstPropPass;
pub use context::ContextPass;
pub use cross_contract::CrossContractPass;
pub use enum_key::EnumKeyPass;
pub use linear_memory::LinearMemoryPass;
pub use storage::StoragePass;
pub use val_encoding::ValEncodingPass;

use sordec_common::{Provenance, ProvenanceSource, ValueId};
use sordec_ir::{Expr, HighFunction, IrType, SemanticOp};

/// One planned binding rewrite, collected during a recognizer's
/// read-only scan and applied afterward. Scan-then-apply keeps the
/// borrow checker happy and separates matching from mutation.
pub(crate) struct Rewrite {
    /// Binding to rewrite.
    pub id: ValueId,
    /// Replacement expression (always a `Semantic(Known(_))`).
    pub expr: Expr,
    /// `None` = leave the binding's type unchanged (used when the
    /// pattern proves no type).
    pub ty: Option<IrType>,
    /// Provenance evidence category.
    pub source: ProvenanceSource,
    /// Provenance note naming the pattern + evidence.
    pub note: String,
    /// Metric counter key to increment for this rewrite.
    pub metric: &'static str,
}

/// A binding already carrying a recognized semantic op — recognizers
/// skip it (the shared idempotency guard: a second run over recognized
/// IR reports `changed: false`).
pub(crate) fn is_recognized(expr: &Expr) -> bool {
    matches!(expr, Expr::Semantic(SemanticOp::Known(_)))
}

/// Apply collected rewrites to a function: set the expression, upgrade
/// the type when one is provided, and append the provenance entry.
pub(crate) fn apply_rewrites(
    func: &mut HighFunction,
    pass_name: &'static str,
    rewrites: Vec<Rewrite>,
) {
    for rw in rewrites {
        if let Some(binding) = func.bindings.get_mut(rw.id) {
            binding.expr = rw.expr;
            if let Some(ty) = rw.ty {
                binding.ty = ty;
            }
            binding.add_provenance(Provenance::new(pass_name, rw.source, rw.note));
        }
    }
}
