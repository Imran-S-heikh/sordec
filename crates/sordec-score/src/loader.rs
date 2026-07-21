//! Source loading + structural flattening.
//!
//! Turns a scoring input — a single `.rs` file **or** a source directory —
//! into one [`syn::File`] holding every in-scope, non-test item. This is
//! the "what is being compared" step; the semantic normalization of the
//! retained items (formatting, alpha-renaming, desugaring) is the
//! canonicalization step that runs after.
//!
//! ## Directory flattening
//!
//! A Soroban contract is usually several files (`lib.rs` + `contract.rs` +
//! `admin.rs` + …) wired together with `mod foo;` declarations. We don't
//! need faithful module *paths* to score — the interface / structure /
//! semantic extractors care about the *set* of items — so we collect every
//! `.rs` file under the directory, parse each, and merge their items into
//! one synthetic file. Files are visited in sorted order for determinism.
//! Because both sides go through the identical flattening, the comparison
//! stays fair even though module paths are not reconstructed.
//!
//! ## What is dropped (out of scope for scoring)
//!
//! - test code: `tests/` directories, `test.rs` / `tests.rs` / `build.rs`
//!   files, `#[cfg(test)]` / `#[test]` items, and `mod test` / `mod tests`.
//! - `use` and `extern crate` (import bookkeeping, not behavior).
//! - external `mod foo;` declarations (their file is merged separately).
//! - `contractmeta!` (build-tooling annotation; the legacy scorer dropped
//!   it too).
//!
//! Inner attributes (`#![no_std]` …) are dropped from the AST because they
//! do not affect any category; the compilation category works from the raw
//! source files, not this flattened AST, so it is unaffected.

use std::fs;
use std::path::{Path, PathBuf};

use quote::ToTokens;
use syn::Item;

use crate::error::ScoreError;

/// Load a scoring input into one flattened, test-stripped [`syn::File`].
///
/// `side` (`"reconstructed"` / `"original"`) attributes any parse or I/O
/// error to the right input.
///
/// # Errors
///
/// [`ScoreError::Io`] if a path can't be read; [`ScoreError::Parse`] if any
/// collected file is not parseable Rust.
pub fn load(path: &Path, side: &'static str) -> Result<syn::File, ScoreError> {
    if path.is_dir() {
        load_dir(path, side)
    } else {
        let text = read(path)?;
        Ok(strip_file(parse(&text, side)?))
    }
}

/// Collect + merge every non-test `.rs` file under `dir`.
fn load_dir(dir: &Path, side: &'static str) -> Result<syn::File, ScoreError> {
    let mut files = Vec::new();
    collect_rs_files(dir, &mut files)?;
    files.sort();

    let mut items = Vec::new();
    for file_path in &files {
        let text = read(file_path)?;
        let parsed = strip_file(parse(&text, side)?);
        items.extend(parsed.items);
    }

    Ok(syn::File {
        shebang: None,
        attrs: Vec::new(),
        items,
    })
}

/// Recursively gather library `.rs` files, skipping test scaffolding.
fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), ScoreError> {
    let entries = fs::read_dir(dir).map_err(|source| ScoreError::Io {
        path: dir.display().to_string(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| ScoreError::Io {
            path: dir.display().to_string(),
            source,
        })?;
        let path = entry.path();
        if path.is_dir() {
            if !is_test_dir(&path) {
                collect_rs_files(&path, out)?;
            }
        } else if is_library_rs(&path) {
            out.push(path);
        }
    }
    Ok(())
}

/// A `.rs` file that is not test scaffolding or a build script.
fn is_library_rs(path: &Path) -> bool {
    if path.extension().and_then(|e| e.to_str()) != Some("rs") {
        return false;
    }
    !matches!(
        path.file_name().and_then(|n| n.to_str()),
        Some("test.rs" | "tests.rs" | "build.rs")
    )
}

/// A directory that holds integration tests.
fn is_test_dir(path: &Path) -> bool {
    matches!(path.file_name().and_then(|n| n.to_str()), Some("tests"))
}

fn read(path: &Path) -> Result<String, ScoreError> {
    fs::read_to_string(path).map_err(|source| ScoreError::Io {
        path: path.display().to_string(),
        source,
    })
}

fn parse(text: &str, side: &'static str) -> Result<syn::File, ScoreError> {
    syn::parse_file(text).map_err(|source| ScoreError::Parse { side, source })
}

/// Drop out-of-scope top-level items and recurse into inline modules.
fn strip_file(mut file: syn::File) -> syn::File {
    file.attrs.clear();
    file.shebang = None;
    file.items = file.items.into_iter().filter_map(strip_item).collect();
    file
}

/// Filter one item, recursing into inline modules. Returns `None` for
/// items that are out of scope for scoring.
fn strip_item(item: Item) -> Option<Item> {
    match item {
        Item::Use(_) | Item::ExternCrate(_) => None,
        // External `mod foo;` — its file is merged separately.
        Item::Mod(m) if m.content.is_none() => None,
        // Test modules (`#[cfg(test)] mod …` or `mod test`/`mod tests`).
        Item::Mod(m) if is_test_mod(&m) => None,
        // Inline module with a body: keep it, but strip its contents too.
        Item::Mod(mut m) => {
            if let Some((brace, inner)) = m.content.take() {
                m.content = Some((brace, inner.into_iter().filter_map(strip_item).collect()));
            }
            Some(Item::Mod(m))
        }
        Item::Macro(mac) if is_contractmeta(&mac) => None,
        other if has_test_attr(item_attrs(&other)) => None,
        other => Some(other),
    }
}

/// Whether a module is test-only: a `#[cfg(test)]` attribute or the
/// conventional `test` / `tests` name.
fn is_test_mod(item_mod: &syn::ItemMod) -> bool {
    has_test_attr(&item_mod.attrs) || item_mod.ident == "test" || item_mod.ident == "tests"
}

/// Whether a `contractmeta!` invocation — a build-tooling annotation the
/// legacy scorer also dropped.
fn is_contractmeta(item_macro: &syn::ItemMacro) -> bool {
    item_macro
        .mac
        .path
        .segments
        .last()
        .is_some_and(|segment| segment.ident == "contractmeta")
}

/// Whether any attribute marks the item as test-only (`#[test]`,
/// `#[cfg(test)]`, `#[cfg_attr(test, …)]`). Salvaged from the legacy
/// scorer's `attrs_have_test_marker`.
fn has_test_attr(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("test")
            || ((attr.path().is_ident("cfg") || attr.path().is_ident("cfg_attr"))
                && attr.meta.to_token_stream().to_string().contains("test"))
    })
}

/// The attribute list of any item that can carry one (all the variants a
/// Soroban source uses). Returns an empty slice for the rare variants
/// without attributes.
fn item_attrs(item: &Item) -> &[syn::Attribute] {
    match item {
        Item::Const(i) => &i.attrs,
        Item::Enum(i) => &i.attrs,
        Item::ExternCrate(i) => &i.attrs,
        Item::Fn(i) => &i.attrs,
        Item::ForeignMod(i) => &i.attrs,
        Item::Impl(i) => &i.attrs,
        Item::Macro(i) => &i.attrs,
        Item::Mod(i) => &i.attrs,
        Item::Static(i) => &i.attrs,
        Item::Struct(i) => &i.attrs,
        Item::Trait(i) => &i.attrs,
        Item::TraitAlias(i) => &i.attrs,
        Item::Type(i) => &i.attrs,
        Item::Union(i) => &i.attrs,
        Item::Use(i) => &i.attrs,
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sordec_score_loader_{name}_{}_{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    fn fn_names(file: &syn::File) -> Vec<String> {
        file.items
            .iter()
            .filter_map(|item| match item {
                Item::Fn(f) => Some(f.sig.ident.to_string()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn single_file_drops_use_and_test_items() {
        let dir = scratch("single");
        let path = dir.join("lib.rs");
        fs::write(
            &path,
            r#"
            #![no_std]
            use soroban_sdk::contract;
            pub fn keep(a: u32) -> u32 { a }
            #[cfg(test)]
            mod test { fn helper() {} }
            #[test]
            fn dropped() {}
            "#,
        )
        .unwrap();

        let file = load(&path, "original").expect("load");
        assert_eq!(fn_names(&file), vec!["keep"]);
        // no `use`, no inner attrs survive
        assert!(file.attrs.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn directory_flattens_and_skips_test_files() {
        let dir = scratch("multi");
        let src = dir.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(
            src.join("lib.rs"),
            "mod contract;\nmod test;\npub fn root() {}\n",
        )
        .unwrap();
        fs::write(src.join("contract.rs"), "pub fn entry() {}\n").unwrap();
        // A unit-test file that must be skipped entirely.
        fs::write(src.join("test.rs"), "fn should_not_appear() {}\n").unwrap();
        // An integration-test dir that must be skipped.
        let tests = dir.join("tests");
        fs::create_dir_all(&tests).unwrap();
        fs::write(tests.join("it.rs"), "fn also_skipped() {}\n").unwrap();

        let file = load(&dir, "original").expect("load dir");
        let mut names = fn_names(&file);
        names.sort();
        assert_eq!(names, vec!["entry", "root"]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn directory_load_is_deterministic() {
        let dir = scratch("determinism");
        let src = dir.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("lib.rs"), "mod a; mod b;\n").unwrap();
        fs::write(src.join("a.rs"), "pub fn a1() {} pub fn a2() {}\n").unwrap();
        fs::write(src.join("b.rs"), "pub fn b1() {}\n").unwrap();

        let first = load(&dir, "original").expect("load 1");
        let second = load(&dir, "original").expect("load 2");
        assert_eq!(
            first.to_token_stream().to_string(),
            second.to_token_stream().to_string()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_path_is_io_error() {
        // `syn::File` isn't `Debug`, so match rather than `expect_err`.
        let result = load(Path::new("/no/such/path.rs"), "reconstructed");
        assert!(matches!(result, Err(ScoreError::Io { .. })));
    }
}
