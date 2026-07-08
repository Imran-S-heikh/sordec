//! Vendored Soroban `Val` ABI: tag table, bit layout, and the
//! `i`-module conversion-function mapping.
//!
//! Soroban represents every runtime value crossing the host boundary as
//! a tagged 64-bit integer (`Val`). This module is the decompiler's
//! ground truth for that encoding — the constants the Val-encoding
//! recognizer matches against.
//!
//! ## Source of truth
//!
//! Hand-transcribed from `soroban-env-common` **26.1.2** (`src/val.rs`,
//! `src/num.rs`) and cross-checked against the vendored
//! `host_calls/env.json` (same release) for the conversion-function
//! export letters. Unlike the host-call catalog (191 entries → vendored
//! JSON), this is ~25 constants: a hand-written table with tests is the
//! right size. **Never edit without re-verifying upstream** — the
//! procedure is: read `val.rs`'s `Tag` enum and layout constants in the
//! new release, diff against this file, update the version cited here.
//!
//! ## The encoding
//!
//! Bit layout of the 64-bit `Val`:
//!
//! - bits 0-7 — the tag byte ([`TAG_BITS`] = 8)
//! - bits 8-63 — the body ([`BODY_BITS`] = 56)
//! - within the body: minor = bits 8-31 (24 bits), major = bits 32-63
//!   (32 bits)
//!
//! **Small values** (tags 0-14) carry their payload inline:
//! `(body << 8) | tag` for 56-bit-bodied types, or
//! `(value << 32) | tag` for `U32Val`/`I32Val` (payload in the major,
//! minor must be zero). **Object values** (tags 64-78) carry a 32-bit
//! host-side handle in the major.
//!
//! A u64 fits inline iff `< 2^56` ([`MAX_SMALL_U64`]); an i64 iff it
//! survives sign-extension through the 56-bit body (±2^55). Values
//! outside the range go through the `i`-module host calls
//! (`obj_from_u64` etc.) and come back as object handles.

use sordec_ir::{KnownType, ValObjectKind};

// ---------------------------------------------------------------------
// Bit layout
// ---------------------------------------------------------------------

/// Number of low bits holding the tag byte.
pub const TAG_BITS: u32 = 8;
/// Mask extracting the tag byte from a raw Val.
pub const TAG_MASK: u64 = 0xFF;
/// Number of body bits (64 − [`TAG_BITS`]).
pub const BODY_BITS: u32 = 56;
/// Number of major bits (upper portion of the body; bits 32-63).
pub const MAJOR_BITS: u32 = 32;
/// Number of minor bits (lower portion of the body; bits 8-31).
pub const MINOR_BITS: u32 = 24;

/// Largest u64 representable inline in a small Val (2^56 − 1).
pub const MAX_SMALL_U64: u64 = (1u64 << BODY_BITS) - 1;
/// Largest i64 representable inline (2^55 − 1).
pub const MAX_SMALL_I64: i64 = (1i64 << (BODY_BITS - 1)) - 1;
/// Smallest i64 representable inline (−2^55).
pub const MIN_SMALL_I64: i64 = -(1i64 << (BODY_BITS - 1));

// ---------------------------------------------------------------------
// Tag bytes — soroban-env-common `Tag` enum discriminants
// ---------------------------------------------------------------------

/// `false` — bare tag, zero body.
pub const TAG_FALSE: u8 = 0;
/// `true` — bare tag, zero body.
pub const TAG_TRUE: u8 = 1;
/// `()` — bare tag, zero body.
pub const TAG_VOID: u8 = 2;
/// Soroban error code (major = code, minor = type).
pub const TAG_ERROR: u8 = 3;
/// u32 inline in the major.
pub const TAG_U32_VAL: u8 = 4;
/// i32 inline in the major.
pub const TAG_I32_VAL: u8 = 5;
/// u64 inline in the 56-bit body.
pub const TAG_U64_SMALL: u8 = 6;
/// i64 inline in the 56-bit body (sign-extended).
pub const TAG_I64_SMALL: u8 = 7;
/// Timepoint (u64 seconds) inline.
pub const TAG_TIMEPOINT_SMALL: u8 = 8;
/// Duration (u64 seconds) inline.
pub const TAG_DURATION_SMALL: u8 = 9;
/// u128 whose value fits the 56-bit body.
pub const TAG_U128_SMALL: u8 = 10;
/// i128 whose value fits the sign-extended 56-bit body.
pub const TAG_I128_SMALL: u8 = 11;
/// u256 whose value fits the 56-bit body.
pub const TAG_U256_SMALL: u8 = 12;
/// i256 whose value fits the sign-extended 56-bit body.
pub const TAG_I256_SMALL: u8 = 13;
/// Symbol of ≤9 chars packed 6 bits per char into the body.
pub const TAG_SYMBOL_SMALL: u8 = 14;

/// `U64Object` — handle to a host-side u64.
pub const TAG_U64_OBJECT: u8 = 64;
/// `I64Object`.
pub const TAG_I64_OBJECT: u8 = 65;
/// `TimepointObject`.
pub const TAG_TIMEPOINT_OBJECT: u8 = 66;
/// `DurationObject`.
pub const TAG_DURATION_OBJECT: u8 = 67;
/// `U128Object`.
pub const TAG_U128_OBJECT: u8 = 68;
/// `I128Object`.
pub const TAG_I128_OBJECT: u8 = 69;
/// `U256Object`.
pub const TAG_U256_OBJECT: u8 = 70;
/// `I256Object`.
pub const TAG_I256_OBJECT: u8 = 71;
/// `BytesObject`.
pub const TAG_BYTES_OBJECT: u8 = 72;
/// `StringObject`.
pub const TAG_STRING_OBJECT: u8 = 73;
/// `SymbolObject`.
pub const TAG_SYMBOL_OBJECT: u8 = 74;
/// `VecObject`.
pub const TAG_VEC_OBJECT: u8 = 75;
/// `MapObject`.
pub const TAG_MAP_OBJECT: u8 = 76;
/// `AddressObject`.
pub const TAG_ADDRESS_OBJECT: u8 = 77;
/// `MuxedAddressObject`.
pub const TAG_MUXED_ADDRESS_OBJECT: u8 = 78;

// ---------------------------------------------------------------------
// Classification + naming
// ---------------------------------------------------------------------

/// True for tags whose payload lives inline in the Val (0..=14).
#[must_use]
pub fn is_small_tag(tag: u8) -> bool {
    tag <= TAG_SYMBOL_SMALL
}

/// True for tags whose body is a host-side object handle (64..=78).
#[must_use]
pub fn is_object_tag(tag: u8) -> bool {
    (TAG_U64_OBJECT..=TAG_MUXED_ADDRESS_OBJECT).contains(&tag)
}

/// True for any tag byte a well-formed Val can carry.
#[must_use]
pub fn is_valid_tag(tag: u8) -> bool {
    is_small_tag(tag) || is_object_tag(tag)
}

/// Upstream name of a tag byte, or `None` for invalid tags.
///
/// Names match `soroban-env-common`'s `Tag` variant names — useful for
/// renderer output and provenance notes.
#[must_use]
pub fn tag_name(tag: u8) -> Option<&'static str> {
    Some(match tag {
        TAG_FALSE => "False",
        TAG_TRUE => "True",
        TAG_VOID => "Void",
        TAG_ERROR => "Error",
        TAG_U32_VAL => "U32Val",
        TAG_I32_VAL => "I32Val",
        TAG_U64_SMALL => "U64Small",
        TAG_I64_SMALL => "I64Small",
        TAG_TIMEPOINT_SMALL => "TimepointSmall",
        TAG_DURATION_SMALL => "DurationSmall",
        TAG_U128_SMALL => "U128Small",
        TAG_I128_SMALL => "I128Small",
        TAG_U256_SMALL => "U256Small",
        TAG_I256_SMALL => "I256Small",
        TAG_SYMBOL_SMALL => "SymbolSmall",
        TAG_U64_OBJECT => "U64Object",
        TAG_I64_OBJECT => "I64Object",
        TAG_TIMEPOINT_OBJECT => "TimepointObject",
        TAG_DURATION_OBJECT => "DurationObject",
        TAG_U128_OBJECT => "U128Object",
        TAG_I128_OBJECT => "I128Object",
        TAG_U256_OBJECT => "U256Object",
        TAG_I256_OBJECT => "I256Object",
        TAG_BYTES_OBJECT => "BytesObject",
        TAG_STRING_OBJECT => "StringObject",
        TAG_SYMBOL_OBJECT => "SymbolObject",
        TAG_VEC_OBJECT => "VecObject",
        TAG_MAP_OBJECT => "MapObject",
        TAG_ADDRESS_OBJECT => "AddressObject",
        TAG_MUXED_ADDRESS_OBJECT => "MuxedAddressObject",
        _ => return None,
    })
}

/// Payload type implied by a small tag, or `None` for invalid /
/// object tags.
///
/// This is the Val-encoding recognizer's type source: a
/// `(x << 8) | 6` pack implies the packed value is a `u64`.
#[must_use]
pub fn small_tag_payload_type(tag: u8) -> Option<KnownType> {
    Some(match tag {
        TAG_FALSE | TAG_TRUE => KnownType::Bool,
        TAG_VOID => KnownType::Unit,
        TAG_ERROR => KnownType::Error,
        TAG_U32_VAL => KnownType::U32,
        TAG_I32_VAL => KnownType::I32,
        TAG_U64_SMALL => KnownType::U64,
        TAG_I64_SMALL => KnownType::I64,
        TAG_TIMEPOINT_SMALL => KnownType::Timepoint,
        TAG_DURATION_SMALL => KnownType::Duration,
        TAG_U128_SMALL => KnownType::U128,
        TAG_I128_SMALL => KnownType::I128,
        TAG_U256_SMALL => KnownType::U256,
        TAG_I256_SMALL => KnownType::I256,
        TAG_SYMBOL_SMALL => KnownType::Symbol,
        _ => return None,
    })
}

// ---------------------------------------------------------------------
// i-module conversion functions
// ---------------------------------------------------------------------

/// Map an `i`-module host import `(module, name)` pair to its
/// [`ValObjectKind`], or `None` when the function is not a Val
/// conversion (the `i`-module arithmetic ops) or not an `i`-module
/// import at all.
///
/// Export letters verified against the vendored
/// `host_calls/env.json` (soroban-env-common 26.1.2).
#[must_use]
pub fn obj_fn_kind(module: &str, name: &str) -> Option<ValObjectKind> {
    use ValObjectKind as K;
    if module != "i" {
        return None;
    }
    Some(match name {
        "_" => K::ObjFromU64,
        "0" => K::ObjToU64,
        "1" => K::ObjFromI64,
        "2" => K::ObjToI64,
        "3" => K::ObjFromU128Pieces,
        "4" => K::ObjToU128Lo64,
        "5" => K::ObjToU128Hi64,
        "6" => K::ObjFromI128Pieces,
        "7" => K::ObjToI128Lo64,
        "8" => K::ObjToI128Hi64,
        "9" => K::ObjFromU256Pieces,
        "a" => K::U256ValFromBeBytes,
        "b" => K::U256ValToBeBytes,
        "c" => K::ObjToU256HiHi,
        "d" => K::ObjToU256HiLo,
        "e" => K::ObjToU256LoHi,
        "f" => K::ObjToU256LoLo,
        "g" => K::ObjFromI256Pieces,
        "h" => K::I256ValFromBeBytes,
        "i" => K::I256ValToBeBytes,
        "j" => K::ObjToI256HiHi,
        "k" => K::ObjToI256HiLo,
        "l" => K::ObjToI256LoHi,
        "m" => K::ObjToI256LoLo,
        "D" => K::TimepointObjFromU64,
        "E" => K::TimepointObjToU64,
        "F" => K::DurationObjFromU64,
        "G" => K::DurationObjToU64,
        _ => return None,
    })
}

/// Friendly (snake-case, upstream) name of a conversion, for renderer
/// output and provenance notes.
#[must_use]
pub fn obj_kind_name(kind: ValObjectKind) -> &'static str {
    use ValObjectKind as K;
    match kind {
        K::ObjFromU64 => "obj_from_u64",
        K::ObjToU64 => "obj_to_u64",
        K::ObjFromI64 => "obj_from_i64",
        K::ObjToI64 => "obj_to_i64",
        K::ObjFromU128Pieces => "obj_from_u128_pieces",
        K::ObjToU128Lo64 => "obj_to_u128_lo64",
        K::ObjToU128Hi64 => "obj_to_u128_hi64",
        K::ObjFromI128Pieces => "obj_from_i128_pieces",
        K::ObjToI128Lo64 => "obj_to_i128_lo64",
        K::ObjToI128Hi64 => "obj_to_i128_hi64",
        K::ObjFromU256Pieces => "obj_from_u256_pieces",
        K::U256ValFromBeBytes => "u256_val_from_be_bytes",
        K::U256ValToBeBytes => "u256_val_to_be_bytes",
        K::ObjToU256HiHi => "obj_to_u256_hi_hi",
        K::ObjToU256HiLo => "obj_to_u256_hi_lo",
        K::ObjToU256LoHi => "obj_to_u256_lo_hi",
        K::ObjToU256LoLo => "obj_to_u256_lo_lo",
        K::ObjFromI256Pieces => "obj_from_i256_pieces",
        K::I256ValFromBeBytes => "i256_val_from_be_bytes",
        K::I256ValToBeBytes => "i256_val_to_be_bytes",
        K::ObjToI256HiHi => "obj_to_i256_hi_hi",
        K::ObjToI256HiLo => "obj_to_i256_hi_lo",
        K::ObjToI256LoHi => "obj_to_i256_lo_hi",
        K::ObjToI256LoLo => "obj_to_i256_lo_lo",
        K::TimepointObjFromU64 => "timepoint_obj_from_u64",
        K::TimepointObjToU64 => "timepoint_obj_to_u64",
        K::DurationObjFromU64 => "duration_obj_from_u64",
        K::DurationObjToU64 => "duration_obj_to_u64",
    }
}

/// Result type of a conversion, per the env.json ABI signatures.
///
/// `obj_from_*` / `*_from_be_bytes` return a Val (an object handle);
/// `obj_to_*` return the raw scalar (note `obj_to_i128_hi64` and
/// `obj_to_i256_hi_hi` return **i64** — the high word carries the
/// sign; the lower words are u64); `*_to_be_bytes` return Bytes.
#[must_use]
pub fn obj_kind_result_type(kind: ValObjectKind) -> KnownType {
    use ValObjectKind as K;
    match kind {
        K::ObjFromU64
        | K::ObjFromI64
        | K::ObjFromU128Pieces
        | K::ObjFromI128Pieces
        | K::ObjFromU256Pieces
        | K::ObjFromI256Pieces
        | K::U256ValFromBeBytes
        | K::I256ValFromBeBytes
        | K::TimepointObjFromU64
        | K::DurationObjFromU64 => KnownType::Val,

        K::ObjToU64
        | K::ObjToU128Lo64
        | K::ObjToU128Hi64
        | K::ObjToI128Lo64
        | K::ObjToU256HiHi
        | K::ObjToU256HiLo
        | K::ObjToU256LoHi
        | K::ObjToU256LoLo
        | K::ObjToI256HiLo
        | K::ObjToI256LoHi
        | K::ObjToI256LoLo
        | K::TimepointObjToU64
        | K::DurationObjToU64 => KnownType::U64,

        K::ObjToI64 | K::ObjToI128Hi64 | K::ObjToI256HiHi => KnownType::I64,

        K::U256ValToBeBytes | K::I256ValToBeBytes => KnownType::Bytes,
    }
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corpus_observed_tags_resolve() {
        // Tags seen in real corpus dumps (hello-add + token-v23).
        assert_eq!(tag_name(4), Some("U32Val"));
        assert_eq!(tag_name(6), Some("U64Small"));
        assert_eq!(tag_name(11), Some("I128Small"));
        assert_eq!(tag_name(64), Some("U64Object"));
        assert_eq!(tag_name(69), Some("I128Object"));
        assert_eq!(tag_name(73), Some("StringObject"));
        assert_eq!(tag_name(77), Some("AddressObject"));
    }

    #[test]
    fn tag_classification_boundaries() {
        // 14 is the last small tag; 15 (SmallCodeUpperBound) is a
        // marker, not a value tag. 63 (ObjectCodeLowerBound) and 79
        // (ObjectCodeUpperBound) likewise. 64 and 78 are the object
        // range ends.
        assert!(is_small_tag(0));
        assert!(is_small_tag(14));
        assert!(!is_small_tag(15));
        assert!(!is_object_tag(63));
        assert!(is_object_tag(64));
        assert!(is_object_tag(78));
        assert!(!is_object_tag(79));
        assert!(!is_valid_tag(15));
        assert!(!is_valid_tag(63));
        assert!(!is_valid_tag(79));
        assert!(!is_valid_tag(127)); // Tag::Bad
        assert_eq!(tag_name(15), None);
        assert_eq!(tag_name(79), None);
    }

    #[test]
    fn small_cutoffs_match_upstream() {
        assert_eq!(MAX_SMALL_U64, 72_057_594_037_927_935); // 2^56 - 1 (seen in corpus)
        assert_eq!(MAX_SMALL_I64, 36_028_797_018_963_967); // 2^55 - 1
        assert_eq!(MIN_SMALL_I64, -36_028_797_018_963_968); // -2^55
    }

    #[test]
    fn payload_types_for_packable_tags() {
        assert_eq!(small_tag_payload_type(4), Some(KnownType::U32));
        assert_eq!(small_tag_payload_type(6), Some(KnownType::U64));
        assert_eq!(small_tag_payload_type(7), Some(KnownType::I64));
        assert_eq!(small_tag_payload_type(11), Some(KnownType::I128));
        assert_eq!(small_tag_payload_type(64), None, "object tags carry handles, not payloads");
        assert_eq!(small_tag_payload_type(200), None);
    }

    #[test]
    fn every_conversion_export_maps_and_roundtrips_name() {
        // The full 28-entry table: every export letter maps, and the
        // friendly name matches the upstream env.json name.
        let table = [
            ("_", "obj_from_u64"),
            ("0", "obj_to_u64"),
            ("1", "obj_from_i64"),
            ("2", "obj_to_i64"),
            ("3", "obj_from_u128_pieces"),
            ("4", "obj_to_u128_lo64"),
            ("5", "obj_to_u128_hi64"),
            ("6", "obj_from_i128_pieces"),
            ("7", "obj_to_i128_lo64"),
            ("8", "obj_to_i128_hi64"),
            ("9", "obj_from_u256_pieces"),
            ("a", "u256_val_from_be_bytes"),
            ("b", "u256_val_to_be_bytes"),
            ("c", "obj_to_u256_hi_hi"),
            ("d", "obj_to_u256_hi_lo"),
            ("e", "obj_to_u256_lo_hi"),
            ("f", "obj_to_u256_lo_lo"),
            ("g", "obj_from_i256_pieces"),
            ("h", "i256_val_from_be_bytes"),
            ("i", "i256_val_to_be_bytes"),
            ("j", "obj_to_i256_hi_hi"),
            ("k", "obj_to_i256_hi_lo"),
            ("l", "obj_to_i256_lo_hi"),
            ("m", "obj_to_i256_lo_lo"),
            ("D", "timepoint_obj_from_u64"),
            ("E", "timepoint_obj_to_u64"),
            ("F", "duration_obj_from_u64"),
            ("G", "duration_obj_to_u64"),
        ];
        for (export, expected_name) in table {
            let kind = obj_fn_kind("i", export)
                .unwrap_or_else(|| panic!("i.{export} must map to a ValObjectKind"));
            assert_eq!(obj_kind_name(kind), expected_name, "for export {export:?}");
        }
    }

    #[test]
    fn conversion_table_agrees_with_vendored_catalog() {
        // Cross-check against host_calls: every conversion export must
        // resolve in the vendored env.json catalog under the same
        // friendly name. Guards against transcription drift between
        // this hand-written table and the vendored data.
        for export in [
            "_", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e",
            "f", "g", "h", "i", "j", "k", "l", "m", "D", "E", "F", "G",
        ] {
            let kind = obj_fn_kind("i", export).expect("maps");
            let catalog_entry = crate::host_calls::resolve("i", export)
                .unwrap_or_else(|| panic!("i.{export} must exist in the vendored catalog"));
            assert_eq!(
                catalog_entry.friendly_name,
                obj_kind_name(kind),
                "val_abi name for i.{export} drifted from the vendored catalog"
            );
        }
    }

    #[test]
    fn non_conversion_inputs_return_none() {
        assert_eq!(obj_fn_kind("l", "_"), None, "wrong module");
        assert_eq!(obj_fn_kind("i", "n"), None, "u256_add is arithmetic, not conversion");
        assert_eq!(obj_fn_kind("i", "zz"), None, "nonexistent export");
    }

    #[test]
    fn result_types_match_abi_signatures() {
        use sordec_ir::ValObjectKind as K;
        assert_eq!(obj_kind_result_type(K::ObjFromU64), KnownType::Val);
        assert_eq!(obj_kind_result_type(K::ObjToU64), KnownType::U64);
        // The sign-carrying high words return i64 per env.json.
        assert_eq!(obj_kind_result_type(K::ObjToI128Hi64), KnownType::I64);
        assert_eq!(obj_kind_result_type(K::ObjToI256HiHi), KnownType::I64);
        // ...but the lower words are u64.
        assert_eq!(obj_kind_result_type(K::ObjToI128Lo64), KnownType::U64);
        assert_eq!(obj_kind_result_type(K::U256ValToBeBytes), KnownType::Bytes);
    }
}
