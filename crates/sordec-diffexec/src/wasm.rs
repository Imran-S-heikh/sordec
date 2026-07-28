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
    let mut names = Vec::new();
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

        if section_id == CUSTOM_SECTION_ID
            && let Some(name) = custom_section_name(&wasm[cursor..payload_end])
        {
            names.push(name);
        }
        cursor = payload_end;
    }
    names
}

/// The name of a custom section, given its complete payload.
///
/// A custom section's payload begins with its own LEB128-prefixed name; the rest
/// is opaque content we have no interest in here.
fn custom_section_name(payload: &[u8]) -> Option<String> {
    let (name_len, name_len_bytes) = leb128(payload)?;
    let name = payload.get(name_len_bytes..name_len_bytes + name_len as usize)?;
    Some(String::from_utf8_lossy(name).into_owned())
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
    fn loadability_turns_on_the_env_meta_section() {
        assert!(is_loadable(&module_with_custom_section(ENV_META_SECTION)));
        // The shape `token-v23-stripped` is in: sections, but not that one.
        assert!(!is_loadable(&module_with_custom_section(SPEC_SECTION)));
        // And the degenerate case — no sections at all — must not panic.
        assert!(!is_loadable(&[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]));
        assert!(!is_loadable(&[]));
    }
}
