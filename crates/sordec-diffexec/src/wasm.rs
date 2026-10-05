//! Reading just enough of a wasm module to know whether the host will load it.
//!
//! The Soroban host calls `check_meta_section` on *every* module load and
//! refuses anything without a `contractenvmetav0` section
//! (`soroban-env-host-23.0.1/src/vm/parsed_module.rs:301`, erroring at
//! `:481-484`). `Env::register` reports that by panicking, which is the wrong
//! shape for a harness whose whole discipline is to degrade with a reason rather
//! than die: `token-v23-stripped` has *zero* custom sections — the stripping took
//! `contractenvmetav0` and `contractspecv0` along with `contractmetav0` — so it is
//! a permanent behaviour exclusion, not a crash.
//!
//! Loadability is therefore decided from the bytes, before registration.
//!
//! The walk is a section id, a LEB128 payload length, and a payload; only custom
//! sections carry a name, and the name is all we want. Hand-rolled rather than
//! pulling in `wasmparser`, which would be the crate's second dependency for
//! forty lines of work. Lifted here from `tests/probe.rs`, where it was written
//! for B1 and already had a unit test.

/// The wasm section id that marks a custom section. Every other id is a known
/// section kind, which carries no name.
const CUSTOM_SECTION_ID: u8 = 0;

/// Bytes of magic + version at the head of a wasm module.
const WASM_HEADER_LEN: usize = 8;

/// The custom section the host requires. Its absence is a hard load failure.
pub const ENV_META_SECTION: &str = "contractenvmetav0";

/// The custom section carrying the contract's declared ABI.
pub const SPEC_SECTION: &str = "contractspecv0";

/// The wasm section id holding a module's exports.
const EXPORT_SECTION_ID: u8 = 7;

/// The export-kind byte marking a function export. Memories, tables and globals use
/// other values and are not entrypoints.
const EXPORT_KIND_FUNC: u8 = 0x00;

/// The export a contract's constructor is compiled to.
///
/// Present only when the contract declares one. Registering such a contract requires
/// its constructor arguments, which is why [`has_constructor`] exists.
pub const CONSTRUCTOR_EXPORT: &str = "__constructor";

/// Whether this contract has a constructor that must be supplied arguments at
/// registration.
///
/// Measured across the corpus: token-v22, token-v23 and dex-liquidity-pool all export
/// one, and **all three take arguments** — `(Address, u32, String, String)` for the
/// tokens, `(Address, Address)` for the pool. None is zero-arity.
///
/// So this deliberately does not try to recover the *arity*: doing so means walking
/// the export, function and type sections to reach a parameter count, and on this
/// corpus the answer is always "more than zero". A zero-argument constructor would be
/// skipped unnecessarily, which is the conservative direction, and the code to handle
/// it would ship unexercised. Arity-aware handling belongs with the input generation
/// that would supply the arguments anyway.
#[must_use]
pub fn has_constructor(wasm: &[u8]) -> bool {
    exported_functions(wasm)
        .iter()
        .any(|name| name == CONSTRUCTOR_EXPORT)
}

/// Whether the host will accept this module at all.
///
/// Cheap and total: a truncated or malformed module simply reports `false`
/// rather than erroring, because the host would reject it either way.
#[must_use]
pub fn is_loadable(wasm: &[u8]) -> bool {
    section_names(wasm).iter().any(|name| name == ENV_META_SECTION)
}

/// Custom-section names in a wasm module, in module order.
#[must_use]
pub fn section_names(wasm: &[u8]) -> Vec<String> {
    custom_sections(wasm).into_iter().map(|(name, _)| name).collect()
}

/// The contents of a named custom section.
///
/// `None` when the module has no such section. The first match wins; a module with
/// two sections of the same name is malformed and the host would reject it.
///
/// Used to compare a recompiled contract's declared ABI against the original's
/// without needing to invoke anything — `contractspecv0` is XDR, so byte equality
/// *is* ABI equality. That makes it the one equivalence check available for a
/// contract the harness cannot yet drive.
#[must_use]
pub fn custom_section<'wasm>(wasm: &'wasm [u8], name: &str) -> Option<&'wasm [u8]> {
    custom_sections(wasm)
        .into_iter()
        .find(|(section, _)| section == name)
        .map(|(_, contents)| contents)
}

/// Whether two modules carry the same code, ignoring custom sections.
///
/// Custom sections hold metadata and nothing the VM executes, so two modules that
/// agree on every other section behave identically. That is what lets
/// `token-v23-stripped` borrow `token-v23` as its behaviour oracle: stripping
/// removed `contractenvmetav0`, which the host refuses to load without, and
/// touched nothing else.
#[must_use]
pub fn same_code(a: &[u8], b: &[u8]) -> bool {
    let code = |wasm| -> Vec<(u8, &[u8])> {
        sections(wasm)
            .into_iter()
            .filter(|(id, _)| *id != CUSTOM_SECTION_ID)
            .collect()
    };
    a.get(..WASM_HEADER_LEN) == b.get(..WASM_HEADER_LEN) && code(a) == code(b)
}

/// Every custom section as `(name, contents)`, in module order.
fn custom_sections(wasm: &[u8]) -> Vec<(String, &[u8])> {
    sections(wasm)
        .into_iter()
        .filter(|(id, _)| *id == CUSTOM_SECTION_ID)
        .filter_map(|(_, payload)| split_custom_section(payload))
        .collect()
}

/// Names of the functions this module exports.
///
/// These are the contract's entrypoints: the host dispatches an invocation by
/// looking up an exported function by name, so this is the set of things that can be
/// called at all.
///
/// Returns an empty vector for a module with no export section or one that is
/// malformed — the host would reject such a module anyway, so there is nothing to
/// distinguish.
#[must_use]
pub fn exported_functions(wasm: &[u8]) -> Vec<String> {
    let Some((_, payload)) = sections(wasm).into_iter().find(|(id, _)| *id == EXPORT_SECTION_ID)
    else {
        return Vec::new();
    };

    let mut names = Vec::new();
    let mut cursor = 0usize;
    let Some((count, count_bytes)) = leb128(&payload[cursor..]) else {
        return names;
    };
    cursor += count_bytes;

    for _ in 0..count {
        // Each entry is a LEB128-prefixed name, a one-byte kind, then a LEB128 index.
        let Some((name_len, name_len_bytes)) = leb128(payload.get(cursor..).unwrap_or(&[])) else {
            break;
        };
        cursor += name_len_bytes;

        let Some(name_end) = cursor
            .checked_add(name_len as usize)
            .filter(|end| *end <= payload.len())
        else {
            break;
        };
        let name = String::from_utf8_lossy(&payload[cursor..name_end]).into_owned();
        cursor = name_end;

        let Some(&kind) = payload.get(cursor) else {
            break;
        };
        cursor += 1;

        let Some((_, index_bytes)) = leb128(payload.get(cursor..).unwrap_or(&[])) else {
            break;
        };
        cursor += index_bytes;

        if kind == EXPORT_KIND_FUNC {
            names.push(name);
        }
    }
    names
}

/// Every section as `(id, payload)`, in module order.
///
/// A truncated or malformed module stops the walk rather than erroring: such a module
/// is one the host would refuse, so there is no useful distinction to draw.
fn sections(wasm: &[u8]) -> Vec<(u8, &[u8])> {
    let mut found = Vec::new();
    let mut cursor = WASM_HEADER_LEN;

    while cursor < wasm.len() {
        let section_id = wasm[cursor];
        cursor += 1;

        let Some((payload_len, len_bytes)) = leb128(&wasm[cursor..]) else {
            break;
        };
        cursor += len_bytes;

        let Some(payload_end) = cursor
            .checked_add(payload_len as usize)
            .filter(|end| *end <= wasm.len())
        else {
            break;
        };

        found.push((section_id, &wasm[cursor..payload_end]));
        cursor = payload_end;
    }
    found
}

/// Split a custom section's complete payload into its name and its contents.
///
/// A custom section's payload begins with its own LEB128-prefixed name; everything
/// after that is the section's opaque content.
fn split_custom_section(payload: &[u8]) -> Option<(String, &[u8])> {
    let (name_len, name_len_bytes) = leb128(payload)?;
    let name_end = name_len_bytes.checked_add(name_len as usize)?;
    let name = payload.get(name_len_bytes..name_end)?;
    let contents = payload.get(name_end..)?;
    Some((String::from_utf8_lossy(name).into_owned(), contents))
}

/// Read a LEB128 `u32`, returning the value and the bytes consumed.
///
/// `None` on a truncated or over-long encoding, which callers treat as
/// end-of-module rather than an error — a malformed module is simply one we stop
/// reading.
fn leb128(bytes: &[u8]) -> Option<(u32, usize)> {
    let mut value = 0u32;
    let mut shift = 0;
    for (i, &byte) in bytes.iter().enumerate().take(5) {
        value |= u32::from(byte & 0x7f).checked_shl(shift)?;
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
        shift += 7;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// magic + version, then one custom section (id 0) named `name` carrying a
    /// single trailing payload byte.
    fn module_with_custom_section(name: &str) -> Vec<u8> {
        let mut wasm = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        let name_bytes = name.as_bytes();
        // payload = LEB128 name length + name + one content byte
        let payload_len = u8::try_from(1 + name_bytes.len() + 1).unwrap();
        wasm.push(CUSTOM_SECTION_ID);
        wasm.push(payload_len);
        wasm.push(u8::try_from(name_bytes.len()).unwrap());
        wasm.extend_from_slice(name_bytes);
        wasm.push(0x2a);
        wasm
    }

    #[test]
    fn section_names_reads_custom_sections() {
        let wasm = module_with_custom_section("meta");
        assert_eq!(section_names(&wasm), vec!["meta".to_owned()]);
    }

    #[test]
    fn a_known_section_kind_contributes_no_name() {
        // id 1 is the type section: a known kind, so it carries no name.
        let mut wasm = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        wasm.extend_from_slice(&[0x01, 0x01, 0x00]);
        assert!(section_names(&wasm).is_empty());
    }

    #[test]
    fn a_truncated_module_terminates_rather_than_looping() {
        let wasm = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x00, 0xff];
        let _ = section_names(&wasm);
    }

    #[test]
    fn a_named_custom_section_yields_its_contents() {
        let wasm = module_with_custom_section("meta");
        // `module_with_custom_section` appends exactly one content byte, 0x2a.
        assert_eq!(custom_section(&wasm, "meta"), Some(&[0x2a][..]));
        assert_eq!(custom_section(&wasm, "absent"), None);
        // Total on malformed input, like the rest of this module.
        assert_eq!(custom_section(&[], SPEC_SECTION), None);
    }

    #[test]
    fn function_exports_are_read_and_non_functions_skipped() {
        // magic + version, then an export section (id 7) with three entries: a
        // function, a memory (kind 2), and another function.
        let mut wasm = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        let mut payload = vec![0x03]; // three exports
        for (name, kind) in [("add", 0x00u8), ("memory", 0x02), ("__constructor", 0x00)] {
            payload.push(u8::try_from(name.len()).unwrap());
            payload.extend_from_slice(name.as_bytes());
            payload.push(kind);
            payload.push(0x00); // index
        }
        wasm.push(EXPORT_SECTION_ID);
        wasm.push(u8::try_from(payload.len()).unwrap());
        wasm.extend_from_slice(&payload);

        assert_eq!(
            exported_functions(&wasm),
            vec!["add".to_owned(), "__constructor".to_owned()],
            "the memory export is not an entrypoint"
        );
        assert!(has_constructor(&wasm));
    }

    #[test]
    fn same_code_ignores_custom_sections_and_nothing_else() {
        let bare = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        let with_meta = module_with_custom_section(ENV_META_SECTION);
        assert!(same_code(&bare, &with_meta), "metadata is not code");

        let mut with_export = bare.clone();
        with_export.extend_from_slice(&[EXPORT_SECTION_ID, 0x01, 0x00]);
        assert!(!same_code(&bare, &with_export), "an export section is code");
    }

    #[test]
    fn a_module_with_no_exports_has_no_constructor() {
        assert!(!has_constructor(&[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]));
        assert!(exported_functions(&[]).is_empty());
        // A truncated export section must terminate rather than loop or panic.
        let truncated = vec![
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, EXPORT_SECTION_ID, 0x02, 0x05, 0xff,
        ];
        let _ = exported_functions(&truncated);
    }

    #[test]
    fn loadability_turns_on_the_env_meta_section() {
        assert!(is_loadable(&module_with_custom_section(ENV_META_SECTION)));
        // The shape `token-v23-stripped` is in: sections, but not that one.
        assert!(!is_loadable(&module_with_custom_section(SPEC_SECTION)));
        // And the degenerate case — no sections at all — must not panic.
        assert!(!is_loadable(&[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]));
        assert!(!is_loadable(&[]));
    }
}
