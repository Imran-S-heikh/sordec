//! Module scaffold: the pieces that frame the emitted functions —
//! `use` imports, the `#[contract]` struct, the `#[contractimpl]` wrapper,
//! and the generated `Cargo.toml`.
//!
//! The `#[contract]` type name is not recorded in `contractspecv0` (the
//! spec carries function and type names, not the impl type), so it is
//! synthesized as `Contract`. Soroban type *paths* are emitted
//! fully-qualified (`soroban_sdk::Address`), so only the attribute macros
//! need importing; collapsing paths into the `use` list is a later
//! output-quality pass.

use syn::parse_quote;

use sordec_ir::{HighIr, TypeRegistry};

use crate::rust::ty::ident;

/// The synthesized `#[contract]` type name.
const CONTRACT_TYPE: &str = "Contract";

/// The attribute-macro names the emitted module needs
/// (`contract`/`contractimpl`/`contracttype`/…), driven by what was actually
/// reconstructed. These are merged with the type/macro names the
/// [`imports`](super::imports) collapse pass collects into one
/// `use soroban_sdk::{…}`; unlike type paths they are emitted bare
/// (`#[contract]`), so they must always be imported.
pub(crate) fn macro_imports(types: Option<&TypeRegistry>, has_impl: bool) -> Vec<syn::Ident> {
    let mut names: Vec<syn::Ident> = Vec::new();
    if has_impl {
        names.push(ident("contract"));
        names.push(ident("contractimpl"));
    }
    if let Some(t) = types {
        if !t.structs.is_empty() || !t.unions.is_empty() || !t.enums.is_empty() {
            names.push(ident("contracttype"));
        }
        if !t.errors.is_empty() {
            names.push(ident("contracterror"));
        }
        if !t.events.is_empty() {
            names.push(ident("contractevent"));
        }
    }
    names
}

/// `#[contract] pub struct Contract;`.
pub(crate) fn contract_struct() -> syn::Item {
    let name = ident(CONTRACT_TYPE);
    parse_quote! {
        #[contract]
        pub struct #name;
    }
}

/// `#[contractimpl] impl Contract { … }` over the emitted methods.
pub(crate) fn contract_impl(methods: Vec<syn::ImplItemFn>) -> syn::Item {
    let name = ident(CONTRACT_TYPE);
    parse_quote! {
        #[contractimpl]
        impl #name {
            #(#methods)*
        }
    }
}

/// The `[profile.release]` every contract in the corpus was built with, and which
/// the reconstruction must therefore be built with too.
///
/// Not cosmetic. Three of these change whether the crate behaves like the original
/// or loads at all:
///
/// - **`overflow-checks = true`** makes arithmetic trap instead of wrapping. Cargo's
///   release default is *off*, so omitting it means the reconstruction wraps
///   wherever the original trapped — a behavioural difference we introduced
///   ourselves, on every boundary input, in code that was otherwise correct.
/// - **`lto = true`** and **`codegen-units = 1`** devirtualise indirect calls. Without
///   them a module can carry a function table, and the Soroban host rejects such a
///   module outright because it disables the `reference-types` proposal. This is a
///   load blocker, not a tuning knob.
/// - **`panic = "abort"`** is what makes a `panic!` the trap a caller observes.
///
/// Recovered? No — profile flags are not recorded in `contractmetav0` and cannot
/// be. This block is an **assumption**, and it is labelled as one in the emitted
/// manifest. It is the right assumption for this corpus: all seven fixture sources
/// carry an identical block.
const RELEASE_PROFILE: &str = "\
[profile.release]
opt-level = \"z\"
overflow-checks = true
debug = 0
strip = \"symbols\"
debug-assertions = false
panic = \"abort\"
codegen-units = 1
lto = true
";

/// The soroban-sdk major the corpus targets, used only when nothing could be
/// recovered.
const FALLBACK_SDK_MAJOR: &str = "23";

/// Which `soroban-sdk` requirement the reconstruction should build against.
///
/// Recovered rather than chosen, because the SDK version changes what the contract
/// *does*: host functions, error codes, event layout and `Val` marshalling all moved
/// between protocols 21 and 23. A closed ladder with three rungs:
///
/// 1. **`rssdkver`** — an exact version, e.g. `"23.0.1#510d3feb…"`. Emitted as an
///    `=` requirement, *not* a caret. `"23.0.1"` alone is a caret requirement in
///    cargo's grammar and silently resolves to 23.5.3 the moment the registry is
///    reachable, quietly swapping the SDK — and therefore the behaviour — under a
///    contract that told us 23.0.1.
/// 2. **`env_meta.protocol`** — from `contractenvmetav0`, which the host *requires*,
///    so this rung is available for any wasm that can actually be loaded. Protocol
///    N implies soroban-sdk major N. A caret here is honest: we genuinely do not
///    know the patch.
/// 3. **Neither** — reachable only for a wasm stripped of both sections, which the
///    host would refuse to load anyway (`token-v23-stripped` is exactly this). A
///    manifest still has to name *some* version, so this rung guesses and the
///    emitted manifest says so.
fn sdk_requirement(high: &HighIr) -> SdkRequirement {
    let facts = high.soroban_facts.as_ref();

    if let Some(version) = facts
        .and_then(|f| f.contract_meta.get("rssdkver"))
        .and_then(|raw| sdk_semver(raw))
    {
        return SdkRequirement::Exact(version);
    }
    if let Some(major) = facts
        .and_then(|f| f.env_meta.protocol.as_deref())
        .and_then(|p| p.trim().parse::<u32>().ok())
    {
        return SdkRequirement::Major(major);
    }
    SdkRequirement::Unrecoverable
}

/// A recovered — or, at the last rung, guessed — soroban-sdk version.
#[derive(Debug, PartialEq, Eq)]
enum SdkRequirement {
    /// From `rssdkver`. Pinned exactly.
    Exact(String),
    /// From the protocol number. Major only.
    Major(u32),
    /// Nothing to go on.
    Unrecoverable,
}

impl SdkRequirement {
    /// The dependency line, plus a provenance comment when the version was not
    /// recovered.
    ///
    /// The comment is the point of the unrecovered case. Silently emitting a
    /// plausible version would make a guess indistinguishable from a recovered
    /// fact in the one artifact the user actually reads.
    fn dependency_lines(&self) -> String {
        match self {
            Self::Exact(version) => format!("soroban-sdk = \"={version}\"\n"),
            Self::Major(major) => format!(
                "# Major recovered from `contractenvmetav0`; the patch version was not\n\
                 # recorded in this wasm, so any {major}.x is accepted.\n\
                 soroban-sdk = \"^{major}\"\n"
            ),
            Self::Unrecoverable => format!(
                "# WARNING: the soroban-sdk version could NOT be recovered — this wasm\n\
                 # carries neither `rssdkver` nor a protocol number. The line below is a\n\
                 # guess at the corpus default and may not match what this contract was\n\
                 # built against.\n\
                 soroban-sdk = \"^{FALLBACK_SDK_MAJOR}\"\n"
            ),
        }
    }
}

/// A `Cargo.toml` for the reconstructed contract crate.
///
/// Three things here exist because their absence made the emitted crate unbuildable
/// or unfaithful, all found while building the behaviour harness:
///
/// - **`[profile.release]`** — see [`RELEASE_PROFILE`]. Its absence silently changes
///   overflow behaviour and can produce a module the host refuses to load.
/// - **`[workspace]`** — without it cargo refuses to build a crate that sits inside
///   another workspace, so the documented `--out-dir` path emitted a crate that
///   could not be built. Two tests had been hand-appending it to work around this.
/// - **An exact SDK pin** — see [`sdk_requirement`].
#[must_use]
pub(crate) fn emit_cargo_toml(high: &HighIr) -> String {
    let dependency = sdk_requirement(high).dependency_lines();
    format!(
        "[package]\n\
         name = \"reconstructed-contract\"\n\
         version = \"0.1.0\"\n\
         edition = \"2021\"\n\
         \n\
         [lib]\n\
         crate-type = [\"cdylib\"]\n\
         \n\
         [dependencies]\n\
         {dependency}\
         \n\
         # Assumed, not recovered: profile flags are not recorded in the wasm. These\n\
         # match every contract in our corpus. `overflow-checks` is the one that\n\
         # changes behaviour — without it, arithmetic wraps where the original\n\
         # trapped.\n\
         {RELEASE_PROFILE}\
         \n\
         # Opts out of any parent workspace, so this crate builds where it is written.\n\
         [workspace]\n"
    )
}

/// The leading semantic version in an `rssdkver` annotation, dropping any
/// `#<git-hash>` suffix.
///
/// `None` for anything that is not a plausible version, so a malformed annotation
/// falls through to the protocol rung rather than producing a requirement cargo
/// rejects. At least `major.minor`, with a numeric major.
fn sdk_semver(raw: &str) -> Option<String> {
    let candidate = raw.split('#').next()?.trim();
    let mut parts = candidate.split('.');
    let major_is_numeric = parts.next().is_some_and(|m| m.parse::<u32>().is_ok());
    if major_is_numeric && parts.next().is_some() {
        Some(candidate.to_owned())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macro_imports_are_minimal_by_need() {
        // Impl present, no user types → only the two impl macros.
        let names: Vec<String> = macro_imports(Some(&TypeRegistry::default()), true)
            .iter()
            .map(|i| i.to_string())
            .collect();
        assert!(names.contains(&"contract".to_string()), "{names:?}");
        assert!(names.contains(&"contractimpl".to_string()), "{names:?}");
        assert!(!names.contains(&"contracttype".to_string()), "{names:?}");
    }

    #[test]
    fn no_macro_imports_when_nothing_is_used() {
        assert!(macro_imports(None, false).is_empty());
    }

    #[test]
    fn sdk_version_parses_from_rssdkver() {
        assert_eq!(sdk_semver("23.0.1#510d3feb724c2b01").as_deref(), Some("23.0.1"));
        assert_eq!(sdk_semver("22.0.0").as_deref(), Some("22.0.0"));
    }

    #[test]
    fn a_malformed_rssdkver_falls_through_rather_than_emitting_garbage() {
        // Better to drop to the protocol rung than to write a requirement cargo
        // rejects, which would fail the build for a reason unrelated to recovery.
        assert_eq!(sdk_semver("unknown"), None);
        assert_eq!(sdk_semver("#abc123"), None);
        // A bare major is not a usable version requirement.
        assert_eq!(sdk_semver("23"), None);
    }
}
