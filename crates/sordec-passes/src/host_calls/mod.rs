//! Soroban host-function catalog and resolution.
//!
//! The Soroban runtime exposes ~190 host functions across 11 modules
//! (`a`, `b`, `c`, `d`, `i`, `l`, `m`, `p`, `t`, `v`, `x`). Each is
//! addressable from WASM by a `(module, name)` pair where both are
//! single-byte ASCII strings — for example `("l", "_")` is
//! `put_contract_data`. This module gives the rest of the codebase a
//! way to look up the friendly name from the byte-encoded pair.
//!
//! ## Source of truth
//!
//! The catalog is vendored from
//! [`soroban-env-common`'s](https://github.com/stellar/rs-soroban-env)
//! `env.json` spec file. The vendored copy lives next to this file as
//! `env.json` and provenance lives in `VENDORED_FROM`. **Never edit
//! `env.json` by hand** — re-vendor from a newer
//! `soroban-env-common` release.
//!
//! Current vendor: see [`CATALOG_VERSION`].
//!
//! ## Append-only invariant
//!
//! The Soroban host-function ABI is append-only across protocol
//! versions. New functions get added (with new `(module, name)`
//! pairs); existing entries are never renamed or removed. This means a
//! catalog vendored at protocol N covers every older protocol's
//! contracts cleanly. Newer-than-our-catalog contracts may have calls
//! we don't recognise — those fall back to a raw `host:<module>:<name>`
//! display, not an error.
//!
//! ## Why this lives in `sordec-passes`, not `sordec-common`
//!
//! The catalog is **analysis-layer data**, not a primitive type used
//! across the entire pipeline. Phase 2 pattern recovery passes
//! (storage-tier resolution, auth chain recognition, cross-contract
//! call recovery) all consume this catalog as their starting point.
//! `sordec-common` stays focused on cross-cutting types (newtype IDs,
//! Diagnostics, Provenance).

use std::sync::LazyLock;

use serde::Deserialize;

// ---------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------

/// One Soroban host function, resolved from the vendored catalog.
///
/// `module` and `name` are the byte-encoded WASM import identifiers
/// (single-character ASCII in practice). `friendly_name` is the
/// human-readable identifier from `soroban-env-common` (e.g.
/// `"put_contract_data"`).
///
/// `min_protocol` is the lowest Soroban protocol version that exposes
/// this function. Default `0` means "available since launch." Used by
/// future multi-version awareness; not consulted by today's renderer.
///
/// All fields are `&'static str` because the source `env.json` is
/// embedded into the binary via `include_str!`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HostCall {
    /// WASM import module name (e.g. `"l"` for ledger / storage).
    pub module: &'static str,
    /// WASM import name (e.g. `"_"` or `"0"`).
    pub name: &'static str,
    /// Friendly identifier in `soroban-env-common` (e.g.
    /// `"put_contract_data"`).
    pub friendly_name: &'static str,
    /// Long human-readable module name (e.g. `"ledger"` for `"l"`).
    pub module_name: &'static str,
    /// Lowest Soroban protocol version exposing this function.
    pub min_protocol: u32,
}

/// Identifier of the upstream `soroban-env-common` release whose
/// `env.json` we have vendored. Bump when re-vendoring; the catalog
/// tests use this implicitly via the catalog size assertion.
pub const CATALOG_VERSION: &str = "soroban-env-common 26.1.2";

/// Resolve a `(module, name)` byte-pair to a [`HostCall`].
///
/// Returns `None` when the pair is not in the catalog — this is a
/// Soroban-host call we have not vendored yet, or it's not a host call
/// at all (e.g. an import from a different module).
///
/// Implementation: linear scan over a `Vec<HostCall>` of ~190 entries.
/// Real contracts have fewer than a hundred host calls each, so the
/// total scan work per dump is small and well within "doesn't matter."
/// If a future profile flags this, swap for a hashmap with a custom
/// borrowing key.
#[must_use]
pub fn resolve(module: &str, name: &str) -> Option<&'static HostCall> {
    CATALOG
        .iter()
        .find(|hc| hc.module == module && hc.name == name)
}

/// Number of entries in the vendored catalog. Useful for sanity checks
/// in tests and for the future `sordec coverage` subcommand's
/// "% of host calls recognised" metric.
#[must_use]
pub fn catalog_size() -> usize {
    CATALOG.len()
}

/// Every entry in the vendored catalog, in `env.json` order.
///
/// Exists for totality proofs: consumers that claim to cover the whole
/// ABI surface (the `effects` classification table, coverage metrics)
/// iterate this to assert no entry was missed. Point lookups should
/// keep using [`resolve`].
#[must_use]
pub fn all() -> &'static [HostCall] {
    &CATALOG
}

// ---------------------------------------------------------------------
// Internal: parse env.json once, cache forever
// ---------------------------------------------------------------------

/// Schema for the top-level `env.json` document.
///
/// Mirrors the shape of `soroban-env-common`'s spec file. Any field
/// not listed here is silently ignored by serde — we only care about
/// what we use.
#[derive(Deserialize)]
struct EnvSpec {
    modules: Vec<EnvModule>,
}

#[derive(Deserialize)]
struct EnvModule {
    /// Long module name, e.g. `"ledger"` or `"context"`.
    name: String,
    /// Short module export — single ASCII char, e.g. `"l"` or `"x"`.
    /// This is what appears in WASM `import.module`.
    export: String,
    functions: Vec<EnvFunction>,
}

#[derive(Deserialize)]
struct EnvFunction {
    /// Function export — single ASCII char (or `_`), e.g. `"_"` or
    /// `"0"`. This is what appears in WASM `import.name`.
    export: String,
    /// Friendly Rust identifier, e.g. `"put_contract_data"`.
    name: String,
    /// Lowest protocol version exposing this function. Absent when
    /// the function has been available since launch (i.e. protocol 0).
    #[serde(default)]
    min_supported_protocol: u32,
}

const ENV_JSON: &str = include_str!("env.json");

static CATALOG: LazyLock<Vec<HostCall>> = LazyLock::new(|| {
    let spec: EnvSpec = serde_json::from_str(ENV_JSON)
        .expect("vendored host_calls/env.json must parse — re-vendor if upstream schema changed");

    let mut entries: Vec<HostCall> = Vec::new();
    for module in &spec.modules {
        // The `&'static str`s come from leaking heap allocations once
        // on first resolve. The data is parsed from `include_str!`'d
        // JSON which is itself `'static`, but serde allocates owned
        // `String`s — leak each unique identifier so we can hand out
        // `&'static str`s from the public surface.
        let module_export: &'static str = Box::leak(module.export.clone().into_boxed_str());
        let module_name: &'static str = Box::leak(module.name.clone().into_boxed_str());

        for func in &module.functions {
            let name: &'static str = Box::leak(func.export.clone().into_boxed_str());
            let friendly: &'static str = Box::leak(func.name.clone().into_boxed_str());

            let entry = HostCall {
                module: module_export,
                name,
                friendly_name: friendly,
                module_name,
                min_protocol: func.min_supported_protocol,
            };

            // Reject duplicate (module, name) pairs — would indicate
            // a corrupt or hand-edited catalog.
            assert!(
                !entries
                    .iter()
                    .any(|e| e.module == entry.module && e.name == entry.name),
                "host_calls catalog has duplicate (module={module_export:?}, name={name:?}) — \
                 env.json may be corrupt"
            );
            entries.push(entry);
        }
    }
    entries
});

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_has_expected_size() {
        // The 26.1.2 catalog has 192 entries. Assert a loose lower
        // bound so trivial version drift doesn't break the test, but
        // tight enough that an empty/truncated catalog would fail.
        let n = catalog_size();
        assert!(
            n >= 180,
            "catalog has {n} entries; expected >= 180 from soroban-env-common 26.1.2"
        );
    }

    #[test]
    fn resolve_known_storage_call_returns_friendly_name() {
        let hc = resolve("l", "_").expect("l._ is put_contract_data");
        assert_eq!(hc.module, "l");
        assert_eq!(hc.name, "_");
        assert_eq!(hc.friendly_name, "put_contract_data");
    }

    #[test]
    fn resolve_known_auth_call_returns_friendly_name() {
        let hc = resolve("a", "0").expect("a.0 is require_auth");
        assert_eq!(hc.friendly_name, "require_auth");
    }

    #[test]
    fn resolve_known_context_call_returns_friendly_name() {
        let hc = resolve("x", "_").expect("x._ is log_from_linear_memory");
        assert_eq!(hc.friendly_name, "log_from_linear_memory");
    }

    #[test]
    fn resolve_unknown_module_returns_none() {
        assert!(resolve("nonexistent_module", "_").is_none());
    }

    #[test]
    fn resolve_unknown_name_returns_none() {
        // Module letter "l" exists; `~` is not a valid name byte.
        assert!(resolve("l", "~").is_none());
    }

    #[test]
    fn every_entry_has_non_empty_module_and_name() {
        for hc in CATALOG.iter() {
            assert!(!hc.module.is_empty(), "found entry with empty module");
            assert!(!hc.name.is_empty(), "found entry with empty name");
            assert!(
                !hc.friendly_name.is_empty(),
                "found entry with empty friendly_name (module={}, name={})",
                hc.module,
                hc.name
            );
            assert!(
                !hc.module_name.is_empty(),
                "found entry with empty module_name (module={}, name={})",
                hc.module,
                hc.name
            );
        }
    }

    #[test]
    fn known_module_letters_are_present() {
        // Every Soroban host module should have at least one entry.
        // The set of module letters is itself stable across protocol
        // versions (new modules are exceedingly rare).
        for module_letter in ["a", "b", "c", "d", "i", "l", "m", "p", "v", "x"] {
            let any_entry = CATALOG.iter().any(|hc| hc.module == module_letter);
            assert!(any_entry, "no entries found for module letter {module_letter:?}");
        }
    }

    #[test]
    fn catalog_version_string_is_present() {
        // Smoke check that we updated the constant when re-vendoring.
        assert!(CATALOG_VERSION.contains("soroban-env-common"));
        assert!(CATALOG_VERSION.contains("26."));
    }

    #[test]
    fn all_len_equals_catalog_size_and_contains_known_entry() {
        assert_eq!(all().len(), catalog_size());
        assert!(
            all().iter().any(|hc| hc.module == "l" && hc.name == "_"),
            "put_contract_data must be enumerable via all()"
        );
    }
}
