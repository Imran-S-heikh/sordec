//! Recognizing macro-generated glue in expanded sources — what to discard,
//! and what to keep as ground truth.
//!
//! [`crate::expand`] produces the macro-expanded basis; this module makes it
//! *comparable*. Expanded Soroban source is mostly **not the contract**: the
//! SDK's `#[contract]` / `#[contractimpl]` / `#[contracttype]` macros emit
//! client structs, argument builders, invoke shims and ABI statics alongside
//! the author's code. Scored raw, all of it counts as work the decompiler
//! failed to reproduce.
//!
//! One pass does both halves of the job:
//!
//! - **Discard** the generated items, so the categories compare contracts
//!   rather than macro output.
//! - **Harvest** the spec-XDR byte strings on the way out. Those are the
//!   contract's declared ABI — the interface *ground truth* — and M3 (T10)
//!   scores against them instead of against `#[contractimpl]`, which
//!   expansion consumes.
//!
//! ## Why recognition is per-method, not per-item
//!
//! The generated `spec_xdr_*` functions live in `impl` blocks that are
//! indistinguishable, at the block level, from the author's own:
//!
//! ```text
//! impl Token { pub const fn spec_xdr_mint() -> [u8; 60] { *b"…" } }  // generated
//! impl Token { pub fn mint(e: Env, to: Address, amount: i128) { … } } // authored
//! ```
//!
//! and a single block can hold both. So `impl` blocks are filtered
//! *method-by-method* and dropped only if nothing survives.
//!
//! ## Why the const fn is the extraction anchor
//!
//! The `__SPEC_XDR_*` statics moved between SDK releases — 23.0.1 emits them
//! bare at module level, 23.5.3 wraps them in `__Contract__mint__spec`
//! modules — and the corpus currently expands the two sides under *different*
//! versions. The `pub const fn spec_xdr_*() -> [u8; N] { *b"…" }` form is
//! identical across both, so the bytes are read from there and both static
//! layouts are simply stripped.

use std::collections::{BTreeMap, BTreeSet};

use syn::{ImplItem, Item, Type};

/// Prefix marking every generated ABI static, in either SDK layout.
const SPEC_STATIC_PREFIX: &str = "__SPEC_XDR_";

/// Prefix marking the generated invoke shims and spec wrapper modules
/// (`__mint`, `__Contract__mint__spec`).
const GENERATED_MOD_PREFIX: &str = "__";

/// The generated const-fn family carrying the ABI bytes: `spec_xdr` on a
/// type or event, `spec_xdr_<entrypoint>` on the contract.
const SPEC_FN: &str = "spec_xdr";

/// Suffixes of the helper types the contract macros generate beside a
/// contract struct: `TokenClient`, `TokenArgs`.
const GENERATED_TYPE_SUFFIXES: [&str; 2] = ["Client", "Args"];

/// An expanded source with the macro glue removed and its ABI recovered.
pub(crate) struct Canonicalized {
    /// Glue-stripped AST — what the categories actually score.
    pub file: syn::File,
    /// ABI ground truth harvested while stripping: item name → spec-XDR
    /// bytes. Entrypoints are keyed by function name, `#[contracttype]` /
    /// `#[contractevent]` shapes by type name.
    pub spec: BTreeMap<String, Vec<u8>>,
}

impl Canonicalized {
    /// A short human-readable summary of what the ABI harvest recovered,
    /// or `None` when the source declared no ABI at all.
    pub(crate) fn abi_summary(&self) -> Option<String> {
        if self.spec.is_empty() {
            return None;
        }
        // Entrypoints are the contract's callable surface; the rest are the
        // type and event shapes it declares.
        let entrypoints = self
            .spec
            .keys()
            .filter(|name| !starts_uppercase(name))
            .count();
        let types = self.spec.len() - entrypoints;
        Some(format!(
            "ABI: {entrypoints} entrypoints, {types} types recovered"
        ))
    }
}

/// Whether a spec key names a type/event rather than an entrypoint. Rust
/// naming makes this unambiguous: types are `UpperCamel`, functions are
/// `snake_case` (including the SDK's own `__constructor`).
fn starts_uppercase(name: &str) -> bool {
    name.trim_start_matches('_')
        .chars()
        .next()
        .is_some_and(char::is_uppercase)
}

/// Strip macro-generated glue from an expanded source, harvesting the
/// spec-XDR bytes it carries.
pub(crate) fn canonicalize(file: syn::File) -> Canonicalized {
    // The paired-name check needs the full set of declared structs before any
    // filtering: `TokenClient` is glue only because `Token` is also present.
    let declared = declared_structs(&file.items);
    let mut spec = BTreeMap::new();
    let items = retain_items(file.items, &declared, &mut spec);

    Canonicalized {
        file: syn::File { items, ..file },
        spec,
    }
}

/// Every struct name declared anywhere in the tree, including nested modules.
fn declared_structs(items: &[Item]) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    collect_struct_names(items, &mut names);
    names
}

fn collect_struct_names(items: &[Item], names: &mut BTreeSet<String>) {
    for item in items {
        match item {
            Item::Struct(s) => {
                names.insert(s.ident.to_string());
            }
            Item::Mod(m) => {
                if let Some((_, inner)) = &m.content {
                    collect_struct_names(inner, names);
                }
            }
            _ => {}
        }
    }
}

/// Filter one item list, recursing into inline modules. Expansion preserves
/// the source's module tree, so the original's glue sits under `mod contract`
/// while our flat `lib.rs` keeps it at the top level — both must be reached.
fn retain_items(
    items: Vec<Item>,
    declared: &BTreeSet<String>,
    spec: &mut BTreeMap<String, Vec<u8>>,
) -> Vec<Item> {
    items
        .into_iter()
        .filter_map(|item| retain_item(item, declared, spec))
        .collect()
}

/// Keep one item, or `None` if the macros generated it.
fn retain_item(
    item: Item,
    declared: &BTreeSet<String>,
    spec: &mut BTreeMap<String, Vec<u8>>,
) -> Option<Item> {
    match item {
        // Invoke shims and (SDK ≥ 23.5) spec wrapper modules.
        Item::Mod(m) if m.ident.to_string().starts_with(GENERATED_MOD_PREFIX) => None,
        Item::Mod(mut m) => {
            if let Some((brace, inner)) = m.content.take() {
                m.content = Some((brace, retain_items(inner, declared, spec)));
            }
            Some(Item::Mod(m))
        }
        // ABI statics, in either layout. The bytes come from the const fn
        // these merely call, so nothing is lost by dropping them.
        Item::Static(s) if s.ident.to_string().starts_with(SPEC_STATIC_PREFIX) => None,
        // `TokenClient` / `TokenArgs`, but only alongside their `Token`.
        Item::Struct(s) if is_generated_helper(&s.ident.to_string(), declared) => None,
        Item::Impl(item_impl) => retain_impl(item_impl, declared, spec),
        other => Some(other),
    }
}

/// Filter an `impl` block method-by-method, harvesting any spec bytes it
/// carries. Returns `None` when the whole block is glue or is left empty.
fn retain_impl(
    mut item_impl: syn::ItemImpl,
    declared: &BTreeSet<String>,
    spec: &mut BTreeMap<String, Vec<u8>>,
) -> Option<Item> {
    let self_name = type_name(&item_impl.self_ty);

    // Whole-block glue: `impl TokenClient`, `impl TokenArgs`, and the SDK's
    // generated `impl Event for X`.
    if self_name
        .as_deref()
        .is_some_and(|name| is_generated_helper(name, declared))
    {
        return None;
    }
    if implements_sdk_event(&item_impl) {
        // Still harvest: the event's `spec_xdr` may live here.
        harvest_impl(&item_impl, self_name.as_deref(), spec);
        return None;
    }

    harvest_impl(&item_impl, self_name.as_deref(), spec);
    item_impl.items.retain(|impl_item| !is_spec_fn(impl_item));

    // An `impl` emptied by stripping carried nothing but glue. One left empty
    // by the macros themselves (`impl Token {}`) is equally uninformative.
    if item_impl.items.is_empty() {
        return None;
    }
    Some(Item::Impl(item_impl))
}

/// Record the spec-XDR bytes of every `spec_xdr*` const fn in a block.
///
/// `spec_xdr_<name>` names an entrypoint; a bare `spec_xdr` describes the
/// type the block is implemented on.
fn harvest_impl(
    item_impl: &syn::ItemImpl,
    self_name: Option<&str>,
    spec: &mut BTreeMap<String, Vec<u8>>,
) {
    for impl_item in &item_impl.items {
        let ImplItem::Fn(method) = impl_item else {
            continue;
        };
        let fn_name = method.sig.ident.to_string();
        let Some(key) = spec_key(&fn_name, self_name) else {
            continue;
        };
        if let Some(bytes) = byte_string_body(&method.block) {
            spec.insert(key, bytes);
        }
    }
}

/// The spec map key for a `spec_xdr*` function, or `None` if it is not one.
fn spec_key(fn_name: &str, self_name: Option<&str>) -> Option<String> {
    if fn_name == SPEC_FN {
        // `impl SetAdmin { const fn spec_xdr() }` describes `SetAdmin`.
        return self_name.map(ToOwned::to_owned);
    }
    // `spec_xdr_mint` → `mint`; `spec_xdr___constructor` → `__constructor`.
    fn_name
        .strip_prefix(SPEC_FN)
        .and_then(|rest| rest.strip_prefix('_'))
        .filter(|name| !name.is_empty())
        .map(ToOwned::to_owned)
}

/// Whether an impl item is one of the generated `spec_xdr*` functions.
fn is_spec_fn(impl_item: &ImplItem) -> bool {
    let ImplItem::Fn(method) = impl_item else {
        return false;
    };
    let name = method.sig.ident.to_string();
    // Exact match or the `spec_xdr_` prefix — never a merely similar name
    // like `specialize`.
    name == SPEC_FN || name.starts_with(&format!("{SPEC_FN}_"))
}

/// The single byte-string literal a generated spec fn returns:
/// `{ *b"\0\0…" }`. `None` for any other body, so an authored function that
/// happens to be named `spec_xdr` is not mined for bytes it does not have.
fn byte_string_body(block: &syn::Block) -> Option<Vec<u8>> {
    let [syn::Stmt::Expr(expr, _)] = block.stmts.as_slice() else {
        return None;
    };
    // The body is a dereferenced byte-string literal.
    let syn::Expr::Unary(unary) = expr else {
        return None;
    };
    if !matches!(unary.op, syn::UnOp::Deref(_)) {
        return None;
    }
    let syn::Expr::Lit(lit) = unary.expr.as_ref() else {
        return None;
    };
    match &lit.lit {
        syn::Lit::ByteStr(bytes) => Some(bytes.value()),
        _ => None,
    }
}

/// Whether `name` is a contract helper type generated beside its contract.
///
/// The paired-name check is what keeps this from over-reaching: `TokenClient`
/// is glue because `Token` is declared too. A user type called `FooClient`
/// with no `Foo` beside it is left alone.
fn is_generated_helper(name: &str, declared: &BTreeSet<String>) -> bool {
    GENERATED_TYPE_SUFFIXES.iter().any(|suffix| {
        name.strip_suffix(suffix)
            .is_some_and(|base| !base.is_empty() && declared.contains(base))
    })
}

/// Whether this block is the SDK's generated `impl Event for X`.
fn implements_sdk_event(item_impl: &syn::ItemImpl) -> bool {
    let Some((_, path, _)) = &item_impl.trait_ else {
        return false;
    };
    path.segments
        .last()
        .is_some_and(|segment| segment.ident == "Event")
}

/// The leaf name of an impl's self type: `TokenClient` from
/// `impl<'a> TokenClient<'a>`.
fn type_name(ty: &Type) -> Option<String> {
    match ty {
        Type::Path(type_path) => type_path
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canon(src: &str) -> Canonicalized {
        canonicalize(syn::parse_file(src).expect("source parses"))
    }

    /// Names of every function surviving canonicalization, including impl
    /// methods and items nested in modules.
    fn fn_names(file: &syn::File) -> Vec<String> {
        let mut names = Vec::new();
        collect(&file.items, &mut names);
        names.sort();
        return names;

        fn collect(items: &[Item], names: &mut Vec<String>) {
            for item in items {
                match item {
                    Item::Fn(f) => names.push(f.sig.ident.to_string()),
                    Item::Impl(i) => {
                        for impl_item in &i.items {
                            if let ImplItem::Fn(m) = impl_item {
                                names.push(m.sig.ident.to_string());
                            }
                        }
                    }
                    Item::Mod(m) => {
                        if let Some((_, inner)) = &m.content {
                            collect(inner, names);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    fn type_names(file: &syn::File) -> Vec<String> {
        let mut names: Vec<String> = file
            .items
            .iter()
            .filter_map(|item| match item {
                Item::Struct(s) => Some(s.ident.to_string()),
                _ => None,
            })
            .collect();
        names.sort();
        names
    }

    // -----------------------------------------------------------------
    // The load-bearing case: one impl block, both kinds of method.
    // -----------------------------------------------------------------

    #[test]
    fn a_mixed_impl_keeps_the_authored_method_and_drops_the_spec_fn() {
        // This is why recognition cannot work per-impl-block: expansion puts
        // generated and authored methods behind the same `impl Token`.
        let out = canon(
            r#"
            pub struct Token;
            impl Token {
                pub const fn spec_xdr_mint() -> [u8; 3usize] { *b"abc" }
                pub fn mint(e: Env, to: Address) { do_mint(e, to); }
            }
            "#,
        );
        assert_eq!(fn_names(&out.file), vec!["mint"]);
        assert_eq!(out.spec.get("mint").map(Vec::as_slice), Some(&b"abc"[..]));
    }

    // -----------------------------------------------------------------
    // Stripping rules
    // -----------------------------------------------------------------

    #[test]
    fn generated_modules_are_dropped_in_both_sdk_layouts() {
        // 23.0.1 emits `__mint`; 23.5.3 emits `__Contract__mint__spec`.
        let out = canon(
            r#"
            pub mod __mint { pub fn invoke_raw() {} }
            pub mod __Contract__mint__spec {
                pub static __SPEC_XDR_FN_MINT: [u8; 3usize] = Contract::spec_xdr_mint();
            }
            pub mod storage { pub fn read() {} }
            "#,
        );
        assert_eq!(
            fn_names(&out.file),
            vec!["read"],
            "user modules must survive"
        );
    }

    #[test]
    fn spec_statics_are_dropped_in_both_sdk_layouts() {
        let out = canon(
            r#"
            pub static __SPEC_XDR_FN_MINT: [u8; 3usize] = Token::spec_xdr_mint();
            pub static __SPEC_XDR_TYPE_DATAKEY: [u8; 3usize] = DataKey::spec_xdr();
            pub static REAL_CONSTANT: u32 = 7;
            "#,
        );
        let statics: Vec<String> = out
            .file
            .items
            .iter()
            .filter_map(|item| match item {
                Item::Static(s) => Some(s.ident.to_string()),
                _ => None,
            })
            .collect();
        assert_eq!(statics, vec!["REAL_CONSTANT"]);
    }

    #[test]
    fn client_and_args_are_dropped_only_beside_their_contract() {
        let out = canon(
            r#"
            pub struct Token;
            pub struct TokenClient<'a> { pub env: Env }
            pub struct TokenArgs;
            impl<'a> TokenClient<'a> { pub fn new(env: &Env) -> Self { todo!() } }
            impl TokenArgs { pub fn mint() {} }
            "#,
        );
        assert_eq!(type_names(&out.file), vec!["Token"]);
        assert!(fn_names(&out.file).is_empty(), "their impls go too");
    }

    #[test]
    fn a_lone_client_type_is_left_alone() {
        // No `Payment` struct, so `PaymentClient` is the author's own type —
        // the paired-name check is what prevents over-reach here.
        let out = canon(
            r#"
            pub struct PaymentClient { pub id: u32 }
            impl PaymentClient { pub fn settle(&self) {} }
            "#,
        );
        assert_eq!(type_names(&out.file), vec!["PaymentClient"]);
        assert_eq!(fn_names(&out.file), vec!["settle"]);
    }

    #[test]
    fn generated_event_impls_are_dropped_but_the_struct_stays() {
        let out = canon(
            r#"
            pub struct SetAdmin { admin: Address }
            impl soroban_sdk::Event for SetAdmin {
                fn topics(&self, env: &Env) -> Vec<Val> { todo!() }
            }
            "#,
        );
        assert_eq!(type_names(&out.file), vec!["SetAdmin"]);
        assert!(fn_names(&out.file).is_empty());
    }

    #[test]
    fn empty_impl_blocks_are_dropped() {
        let out = canon("pub struct Token;\nimpl Token {}\n");
        assert!(
            !out.file.items.iter().any(|i| matches!(i, Item::Impl(_))),
            "an empty impl carries no information"
        );
    }

    #[test]
    fn glue_nested_in_a_module_is_stripped_too() {
        // The original expands with everything under `mod contract`.
        let out = canon(
            r#"
            mod contract {
                pub struct Token;
                pub struct TokenClient<'a> { pub env: Env }
                pub mod __mint { pub fn invoke_raw() {} }
                impl Token {
                    pub const fn spec_xdr_mint() -> [u8; 3usize] { *b"xyz" }
                    pub fn mint() {}
                }
            }
            "#,
        );
        assert_eq!(fn_names(&out.file), vec!["mint"]);
        assert_eq!(out.spec.get("mint").map(Vec::as_slice), Some(&b"xyz"[..]));
    }

    // -----------------------------------------------------------------
    // Not over-reaching
    // -----------------------------------------------------------------

    #[test]
    fn a_similarly_named_authored_function_is_not_glue() {
        // `specialize` starts with "spec" but is not `spec_xdr`.
        let out = canon(
            r#"
            pub struct Token;
            impl Token {
                pub fn specialize(&self) {}
                pub fn spec_xdr_like_but_not(&self) {}
            }
            "#,
        );
        let names = fn_names(&out.file);
        assert!(names.contains(&"specialize".to_string()), "got {names:?}");
        assert!(out.spec.is_empty(), "nothing to harvest");
    }

    #[test]
    fn a_spec_fn_without_a_byte_string_body_yields_no_bytes() {
        // Stripped as glue by name, but nothing is invented for the map.
        let out = canon(
            r#"
            pub struct Token;
            impl Token { pub fn spec_xdr_mint() -> Vec<u8> { compute() } }
            "#,
        );
        assert!(out.spec.is_empty());
        assert!(fn_names(&out.file).is_empty());
    }

    // -----------------------------------------------------------------
    // Harvest
    // -----------------------------------------------------------------

    #[test]
    fn harvest_keys_entrypoints_and_types_distinctly() {
        let out = canon(
            r#"
            pub struct Token;
            pub struct DataKey;
            impl Token {
                pub const fn spec_xdr_transfer() -> [u8; 1usize] { *b"t" }
                pub const fn spec_xdr___constructor() -> [u8; 1usize] { *b"c" }
            }
            impl DataKey { pub const fn spec_xdr() -> [u8; 1usize] { *b"d" } }
            "#,
        );
        // A bare `spec_xdr` is keyed by the type it describes.
        let keys: Vec<&String> = out.spec.keys().collect();
        assert_eq!(keys, vec!["DataKey", "__constructor", "transfer"]);
        assert_eq!(out.spec["__constructor"], b"c".to_vec());
    }

    #[test]
    fn abi_summary_splits_entrypoints_from_types() {
        let out = canon(
            r#"
            pub struct Token;
            pub struct DataKey;
            impl Token {
                pub const fn spec_xdr_transfer() -> [u8; 1usize] { *b"t" }
                pub const fn spec_xdr___constructor() -> [u8; 1usize] { *b"c" }
            }
            impl DataKey { pub const fn spec_xdr() -> [u8; 1usize] { *b"d" } }
            "#,
        );
        assert_eq!(
            out.abi_summary().as_deref(),
            Some("ABI: 2 entrypoints, 1 types recovered")
        );
    }

    #[test]
    fn a_source_with_no_abi_summarizes_to_nothing() {
        let out = canon("pub fn helper(a: u32) -> u32 { a }");
        assert_eq!(out.abi_summary(), None);
        assert_eq!(fn_names(&out.file), vec!["helper"]);
    }

    // -----------------------------------------------------------------
    // Against real expanded output. Shells out to `cargo expand`, so
    // `#[ignore]`d out of the fast suite (the `compile`/`expand`
    // convention). Run with:
    //   cargo test -p sordec-score -- --ignored
    //
    // The cross-side comparison — our reconstruction's spec bytes against
    // the original's — needs the decompiler to produce a reconstruction,
    // and the scorer deliberately does not depend on the pipeline it
    // grades. That assertion is T10's acceptance criterion, where the
    // interface category starts scoring from these bytes.
    // -----------------------------------------------------------------

    #[test]
    #[ignore = "shells out to cargo expand against soroban-sdk (slow)"]
    fn the_real_token_v23_abi_is_recovered_from_expanded_output() {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../samples/contracts/token-v23/source/src");
        let expanded = crate::expand::expand(&fixture).expect("fixture must expand");
        let out = canonicalize(syn::parse_file(&expanded).expect("expanded output parses"));

        let entrypoints: Vec<&String> = out
            .spec
            .keys()
            .filter(|name| !starts_uppercase(name))
            .collect();
        assert_eq!(
            entrypoints.len(),
            13,
            "token-v23 declares 13 entrypoints, got: {entrypoints:?}"
        );

        // Spot-check one against the byte string the SDK actually emits, so
        // this fails loudly if the harvest ever starts returning the wrong
        // bytes rather than merely the wrong count.
        let mint = out.spec.get("mint").expect("mint entrypoint");
        assert!(
            mint.starts_with(b"\0\0\0\0\0\0\0\0\0\0\0\x04mint"),
            "unexpected mint spec bytes: {mint:?}"
        );

        // And the glue really is gone: no client, no invoke shims.
        assert!(
            !fn_names(&out.file)
                .iter()
                .any(|n| n.starts_with("spec_xdr")),
            "spec fns must not survive canonicalization"
        );
    }
}
