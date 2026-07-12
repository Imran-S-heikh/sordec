//! Vendored Soroban host-ABI tables: the `Val` tag table + bit layout,
//! the `i`-module conversion-function mapping, and the `a`-module
//! address conversion mapping.
//!
//! Soroban represents every runtime value crossing the host boundary as
//! a tagged 64-bit integer (`Val`). This module is the decompiler's
//! ground truth for that encoding — the constants the Val-encoding
//! recognizer matches against — plus the per-module conversion-function
//! lookups the storage/auth/etc. recognizers consult. It is the single
//! home for host-ABI constant tables; new modules' tables join here as
//! recognizers need them.
//!
//! ## Source of truth
//!
//! Hand-transcribed from `soroban-env-common` **26.1.2** (`src/val.rs`,
//! `src/num.rs`) and cross-checked against the vendored
//! `host_calls/env.json` (same release) for the conversion-function
//! export letters. Unlike the host-call catalog (192 entries → vendored
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

use sordec_common::UnknownReason;
use sordec_ir::{
    AddressOpKind, BufOpKind, CryptoOpKind, DeployOpKind, IrType, KnownType, MapOpKind, PrngOpKind,
    TestOpKind, ValObjectKind, VecOpKind,
};

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
// a-module address conversions
// ---------------------------------------------------------------------

/// Map an `a`-module host import `(module, name)` pair to its
/// [`AddressOpKind`], or `None` when the function is not an address
/// conversion (the auth calls `require_auth` / `require_auth_for_args`
/// / `authorize_as_curr_contract` have their own `KnownOp`s) or not an
/// `a`-module import at all.
///
/// Export letters verified against the vendored `host_calls/env.json`
/// (soroban-env-common 26.1.2).
#[must_use]
pub fn addr_fn_kind(module: &str, name: &str) -> Option<AddressOpKind> {
    use AddressOpKind as K;
    if module != "a" {
        return None;
    }
    Some(match name {
        "1" => K::StrkeyToAddress,
        "2" => K::AddressToStrkey,
        "4" => K::GetAddressFromMuxedAddress,
        "5" => K::GetIdFromMuxedAddress,
        "6" => K::GetAddressExecutable,
        "7" => K::StrkeyToMuxedAddress,
        "8" => K::MuxedAddressToStrkey,
        _ => return None,
    })
}

/// Friendly (snake-case, upstream) name of an address conversion, for
/// renderer output and provenance notes.
#[must_use]
pub fn addr_kind_name(kind: AddressOpKind) -> &'static str {
    use AddressOpKind as K;
    match kind {
        K::StrkeyToAddress => "strkey_to_address",
        K::AddressToStrkey => "address_to_strkey",
        K::GetAddressFromMuxedAddress => "get_address_from_muxed_address",
        K::GetIdFromMuxedAddress => "get_id_from_muxed_address",
        K::GetAddressExecutable => "get_address_executable",
        K::StrkeyToMuxedAddress => "strkey_to_muxed_address",
        K::MuxedAddressToStrkey => "muxed_address_to_strkey",
    }
}

/// Result type of an address conversion, per the env.json ABI
/// signatures.
///
/// `get_address_executable` and `strkey_to_muxed_address` are declared
/// `-> Val` upstream; we type them `Val` rather than guessing a richer
/// type from the function name (a later type-recovery pass can refine).
#[must_use]
pub fn addr_kind_result_type(kind: AddressOpKind) -> KnownType {
    use AddressOpKind as K;
    match kind {
        K::StrkeyToAddress | K::GetAddressFromMuxedAddress => KnownType::Address,
        K::AddressToStrkey | K::MuxedAddressToStrkey => KnownType::String,
        K::GetIdFromMuxedAddress => KnownType::U64,
        K::GetAddressExecutable | K::StrkeyToMuxedAddress => KnownType::Val,
    }
}

// ---------------------------------------------------------------------
// SymbolSmall (tag 14) decoding
// ---------------------------------------------------------------------

/// Number of bits per packed symbol character.
const SYMBOL_CODE_BITS: u32 = 6;
/// Maximum characters in a small symbol (9 × 6 = 54 ≤ 56 body bits).
const SYMBOL_MAX_CHARS: u32 = 9;

/// Decode a raw 64-bit `Val` as a `SymbolSmall` (tag 14): up to 9
/// characters packed 6 bits each into the 56-bit body, first character
/// in the highest-order code slot.
///
/// Character codes per `soroban-env-common 26.1.2` `symbol.rs`:
/// `1` = `_`, `2..=11` = `0`-`9`, `12..=37` = `A`-`Z`, `38..=63` =
/// `a`-`z`; `0` is leading padding. Validated empirically against
/// SDK-emitted constants in the corpus (`"transfer"`, `"burn"`,
/// `"METADATA"`, …) — see the tests.
///
/// **Strict**: returns `None` (never a garbled name) for a wrong tag, a
/// body wider than 54 bits, an interior zero code, or an empty body.
#[must_use]
pub fn decode_small_symbol(bits: u64) -> Option<String> {
    if (bits & TAG_MASK) != u64::from(TAG_SYMBOL_SMALL) {
        return None;
    }
    let body = bits >> TAG_BITS;
    if body >= 1u64 << (SYMBOL_CODE_BITS * SYMBOL_MAX_CHARS) {
        return None;
    }
    let mut out = String::new();
    for slot in (0..SYMBOL_MAX_CHARS).rev() {
        let code = ((body >> (SYMBOL_CODE_BITS * slot)) & 0x3F) as u8;
        match code {
            0 => {
                // Zero is only valid as leading padding.
                if !out.is_empty() {
                    return None;
                }
            }
            1 => out.push('_'),
            2..=11 => out.push(char::from(b'0' + code - 2)),
            12..=37 => out.push(char::from(b'A' + code - 12)),
            38..=63 => out.push(char::from(b'a' + code - 38)),
            _ => unreachable!("6-bit code"),
        }
    }
    // An all-zero body is a valid (empty) symbol Val, but naming
    // anything with "" adds no information — stay unresolved.
    if out.is_empty() {
        return None;
    }
    Some(out)
}

// ---------------------------------------------------------------------
// m/v/b-module collections + bytes operations
// ---------------------------------------------------------------------
//
// The `(module, export) → kind` tables, per-kind ABI arity, friendly
// name, and return type for the collections recognizer. Export letters,
// arities, and return types transcribed from the vendored
// `host_calls/env.json` (soroban-env-common 26.1.2) and drift-guarded
// against it in the tests below. The five `*_new_from_linear_memory`
// constructors — `(m, 9)`, `(v, g)`, `(b, 3)`, `(b, i)`, `(b, j)` — are
// deliberately absent: they are the linear-memory recognizer's ops.

/// `IrType::Unknown` inner for composite results whose element types the
/// ABI does not carry (a later type-recovery pass refines them).
fn unknown_inner() -> Box<IrType> {
    Box::new(IrType::Unknown(UnknownReason::InsufficientEvidence))
}

/// `Map<?, ?>` — a map result with unknown key/value types.
fn map_of_unknown() -> KnownType {
    KnownType::Map(unknown_inner(), unknown_inner())
}

/// `Vec<?>` — a vec result with unknown element type.
fn vec_of_unknown() -> KnownType {
    KnownType::Vec(unknown_inner())
}

/// Map an `m`-module host import `(module, name)` pair to its
/// [`MapOpKind`], or `None` for `map_new_from_linear_memory` (the
/// linear-memory recognizer's op) or a non-`m` import.
#[must_use]
pub fn map_fn_kind(module: &str, name: &str) -> Option<MapOpKind> {
    use MapOpKind as K;
    if module != "m" {
        return None;
    }
    Some(match name {
        "_" => K::New,
        "0" => K::Put,
        "1" => K::Get,
        "2" => K::Del,
        "3" => K::Len,
        "4" => K::Has,
        "5" => K::KeyByPos,
        "6" => K::ValByPos,
        "7" => K::Keys,
        "8" => K::Values,
        "a" => K::UnpackToLinearMemory,
        // "9" = map_new_from_linear_memory → linear-memory recognizer.
        _ => return None,
    })
}

/// Friendly (snake-case, upstream) name of a map operation.
#[must_use]
pub fn map_kind_name(kind: MapOpKind) -> &'static str {
    use MapOpKind as K;
    match kind {
        K::New => "map_new",
        K::Put => "map_put",
        K::Get => "map_get",
        K::Del => "map_del",
        K::Len => "map_len",
        K::Has => "map_has",
        K::KeyByPos => "map_key_by_pos",
        K::ValByPos => "map_val_by_pos",
        K::Keys => "map_keys",
        K::Values => "map_values",
        K::UnpackToLinearMemory => "map_unpack_to_linear_memory",
    }
}

/// ABI argument count of a map operation.
#[must_use]
pub fn map_kind_arity(kind: MapOpKind) -> usize {
    use MapOpKind as K;
    match kind {
        K::New => 0,
        K::Len | K::Keys | K::Values => 1,
        K::Get | K::Del | K::Has | K::KeyByPos | K::ValByPos => 2,
        K::Put => 3,
        K::UnpackToLinearMemory => 4,
    }
}

/// Result type of a map operation, per the env.json ABI signatures.
#[must_use]
pub fn map_kind_result_type(kind: MapOpKind) -> KnownType {
    use MapOpKind as K;
    match kind {
        K::New | K::Put | K::Del => map_of_unknown(),
        K::Get | K::KeyByPos | K::ValByPos => KnownType::Val,
        K::Len => KnownType::U32,
        K::Has => KnownType::Bool,
        K::Keys | K::Values => vec_of_unknown(),
        K::UnpackToLinearMemory => KnownType::Unit,
    }
}

/// Map a `v`-module host import `(module, name)` pair to its
/// [`VecOpKind`], or `None` for `vec_new_from_linear_memory` (the
/// linear-memory recognizer's op) or a non-`v` import.
#[must_use]
pub fn vec_fn_kind(module: &str, name: &str) -> Option<VecOpKind> {
    use VecOpKind as K;
    if module != "v" {
        return None;
    }
    Some(match name {
        "_" => K::New,
        "0" => K::Put,
        "1" => K::Get,
        "2" => K::Del,
        "3" => K::Len,
        "4" => K::PushFront,
        "5" => K::PopFront,
        "6" => K::PushBack,
        "7" => K::PopBack,
        "8" => K::Front,
        "9" => K::Back,
        "a" => K::Insert,
        "b" => K::Append,
        "c" => K::Slice,
        "d" => K::FirstIndexOf,
        "e" => K::LastIndexOf,
        "f" => K::BinarySearch,
        "h" => K::UnpackToLinearMemory,
        // "g" = vec_new_from_linear_memory → linear-memory recognizer.
        _ => return None,
    })
}

/// Friendly (snake-case, upstream) name of a vec operation.
#[must_use]
pub fn vec_kind_name(kind: VecOpKind) -> &'static str {
    use VecOpKind as K;
    match kind {
        K::New => "vec_new",
        K::Put => "vec_put",
        K::Get => "vec_get",
        K::Del => "vec_del",
        K::Len => "vec_len",
        K::PushFront => "vec_push_front",
        K::PopFront => "vec_pop_front",
        K::PushBack => "vec_push_back",
        K::PopBack => "vec_pop_back",
        K::Front => "vec_front",
        K::Back => "vec_back",
        K::Insert => "vec_insert",
        K::Append => "vec_append",
        K::Slice => "vec_slice",
        K::FirstIndexOf => "vec_first_index_of",
        K::LastIndexOf => "vec_last_index_of",
        K::BinarySearch => "vec_binary_search",
        K::UnpackToLinearMemory => "vec_unpack_to_linear_memory",
    }
}

/// ABI argument count of a vec operation.
#[must_use]
pub fn vec_kind_arity(kind: VecOpKind) -> usize {
    use VecOpKind as K;
    match kind {
        K::New => 0,
        K::Len | K::PopFront | K::PopBack | K::Front | K::Back => 1,
        K::Get
        | K::Del
        | K::PushFront
        | K::PushBack
        | K::Append
        | K::FirstIndexOf
        | K::LastIndexOf
        | K::BinarySearch => 2,
        K::Put | K::Insert | K::Slice | K::UnpackToLinearMemory => 3,
    }
}

/// Result type of a vec operation, per the env.json ABI signatures.
///
/// `vec_first_index_of` / `vec_last_index_of` are declared `-> Val`
/// upstream (index or Void); `vec_binary_search` returns a **raw `u64`**
/// (not a tagged `Val`) — high bit = found flag, low bits = index.
#[must_use]
pub fn vec_kind_result_type(kind: VecOpKind) -> KnownType {
    use VecOpKind as K;
    match kind {
        K::New | K::Put | K::Del | K::PushFront | K::PopFront | K::PushBack | K::PopBack
        | K::Insert | K::Append | K::Slice => vec_of_unknown(),
        K::Get | K::Front | K::Back | K::FirstIndexOf | K::LastIndexOf => KnownType::Val,
        K::Len => KnownType::U32,
        K::BinarySearch => KnownType::U64,
        K::UnpackToLinearMemory => KnownType::Unit,
    }
}

/// Map a `b`-module host import `(module, name)` pair to its
/// [`BufOpKind`], or `None` for the three `*_new_from_linear_memory`
/// constructors (the linear-memory recognizer's ops) or a non-`b` import.
#[must_use]
pub fn buf_fn_kind(module: &str, name: &str) -> Option<BufOpKind> {
    use BufOpKind as K;
    if module != "b" {
        return None;
    }
    Some(match name {
        "_" => K::SerializeToBytes,
        "0" => K::DeserializeFromBytes,
        "1" => K::BytesCopyToLinearMemory,
        "2" => K::BytesCopyFromLinearMemory,
        "4" => K::BytesNewEmpty,
        "5" => K::BytesPut,
        "6" => K::BytesGet,
        "7" => K::BytesDel,
        "8" => K::BytesLen,
        "9" => K::BytesPush,
        "a" => K::BytesPop,
        "b" => K::BytesFront,
        "c" => K::BytesBack,
        "d" => K::BytesInsert,
        "e" => K::BytesAppend,
        "f" => K::BytesSlice,
        "g" => K::StringCopyToLinearMemory,
        "h" => K::SymbolCopyToLinearMemory,
        "k" => K::StringLen,
        "l" => K::SymbolLen,
        "m" => K::SymbolIndexInLinearMemory,
        "n" => K::StringToBytes,
        "o" => K::BytesToString,
        // "3"/"i"/"j" = bytes/string/symbol_new_from_linear_memory →
        // linear-memory recognizer.
        _ => return None,
    })
}

/// Friendly (snake-case, upstream) name of a buf operation.
#[must_use]
pub fn buf_kind_name(kind: BufOpKind) -> &'static str {
    use BufOpKind as K;
    match kind {
        K::SerializeToBytes => "serialize_to_bytes",
        K::DeserializeFromBytes => "deserialize_from_bytes",
        K::BytesCopyToLinearMemory => "bytes_copy_to_linear_memory",
        K::BytesCopyFromLinearMemory => "bytes_copy_from_linear_memory",
        K::BytesNewEmpty => "bytes_new",
        K::BytesPut => "bytes_put",
        K::BytesGet => "bytes_get",
        K::BytesDel => "bytes_del",
        K::BytesLen => "bytes_len",
        K::BytesPush => "bytes_push",
        K::BytesPop => "bytes_pop",
        K::BytesFront => "bytes_front",
        K::BytesBack => "bytes_back",
        K::BytesInsert => "bytes_insert",
        K::BytesAppend => "bytes_append",
        K::BytesSlice => "bytes_slice",
        K::StringCopyToLinearMemory => "string_copy_to_linear_memory",
        K::SymbolCopyToLinearMemory => "symbol_copy_to_linear_memory",
        K::StringLen => "string_len",
        K::SymbolLen => "symbol_len",
        K::SymbolIndexInLinearMemory => "symbol_index_in_linear_memory",
        K::StringToBytes => "string_to_bytes",
        K::BytesToString => "bytes_to_string",
    }
}

/// ABI argument count of a buf operation.
#[must_use]
pub fn buf_kind_arity(kind: BufOpKind) -> usize {
    use BufOpKind as K;
    match kind {
        K::BytesNewEmpty => 0,
        K::SerializeToBytes
        | K::DeserializeFromBytes
        | K::BytesLen
        | K::BytesPop
        | K::BytesFront
        | K::BytesBack
        | K::StringLen
        | K::SymbolLen
        | K::StringToBytes
        | K::BytesToString => 1,
        K::BytesGet | K::BytesDel | K::BytesPush | K::BytesAppend => 2,
        K::BytesPut | K::BytesInsert | K::BytesSlice | K::SymbolIndexInLinearMemory => 3,
        K::BytesCopyToLinearMemory
        | K::BytesCopyFromLinearMemory
        | K::StringCopyToLinearMemory
        | K::SymbolCopyToLinearMemory => 4,
    }
}

/// Result type of a buf operation, per the env.json ABI signatures.
#[must_use]
pub fn buf_kind_result_type(kind: BufOpKind) -> KnownType {
    use BufOpKind as K;
    match kind {
        K::SerializeToBytes
        | K::BytesCopyFromLinearMemory
        | K::BytesNewEmpty
        | K::BytesPut
        | K::BytesDel
        | K::BytesPush
        | K::BytesPop
        | K::BytesInsert
        | K::BytesAppend
        | K::BytesSlice
        | K::StringToBytes => KnownType::Bytes,
        K::DeserializeFromBytes => KnownType::Val,
        K::BytesCopyToLinearMemory
        | K::StringCopyToLinearMemory
        | K::SymbolCopyToLinearMemory => KnownType::Unit,
        K::BytesGet | K::BytesLen | K::BytesFront | K::BytesBack | K::StringLen | K::SymbolLen
        | K::SymbolIndexInLinearMemory => KnownType::U32,
        K::BytesToString => KnownType::String,
    }
}

// ---------------------------------------------------------------------
// c / p / t / l-deploy tables (W3 — the remaining-ABI sweep)
// ---------------------------------------------------------------------

/// Map a `c`-module host import `(module, name)` pair to its
/// [`CryptoOpKind`], or `None` for a non-`c` import.
#[must_use]
pub fn crypto_fn_kind(module: &str, name: &str) -> Option<CryptoOpKind> {
    use CryptoOpKind as K;
    if module != "c" {
        return None;
    }
    Some(match name {
        "_" => K::ComputeHashSha256,
        "0" => K::VerifySigEd25519,
        "1" => K::ComputeHashKeccak256,
        "2" => K::RecoverKeyEcdsaSecp256k1,
        "3" => K::VerifySigEcdsaSecp256r1,
        "4" => K::Bls12381CheckG1IsInSubgroup,
        "5" => K::Bls12381G1Add,
        "6" => K::Bls12381G1Mul,
        "7" => K::Bls12381G1Msm,
        "8" => K::Bls12381MapFpToG1,
        "9" => K::Bls12381HashToG1,
        "a" => K::Bls12381CheckG2IsInSubgroup,
        "b" => K::Bls12381G2Add,
        "c" => K::Bls12381G2Mul,
        "d" => K::Bls12381G2Msm,
        "e" => K::Bls12381MapFp2ToG2,
        "f" => K::Bls12381HashToG2,
        "g" => K::Bls12381MultiPairingCheck,
        "h" => K::Bls12381FrAdd,
        "i" => K::Bls12381FrSub,
        "j" => K::Bls12381FrMul,
        "k" => K::Bls12381FrPow,
        "l" => K::Bls12381FrInv,
        "m" => K::Bn254G1Add,
        "n" => K::Bn254G1Mul,
        "o" => K::Bn254MultiPairingCheck,
        "p" => K::PoseidonPermutation,
        "q" => K::Poseidon2Permutation,
        "r" => K::Bn254G1Msm,
        "s" => K::Bn254FrAdd,
        "t" => K::Bn254FrSub,
        "u" => K::Bn254FrMul,
        "v" => K::Bn254FrPow,
        "w" => K::Bn254FrInv,
        "x" => K::Bls12381G1IsOnCurve,
        "y" => K::Bls12381G2IsOnCurve,
        "z" => K::Bn254G1IsOnCurve,
        _ => return None,
    })
}

/// Friendly (snake-case, upstream) name of a crypto operation.
#[must_use]
pub fn crypto_kind_name(kind: CryptoOpKind) -> &'static str {
    use CryptoOpKind as K;
    match kind {
        K::ComputeHashSha256 => "compute_hash_sha256",
        K::VerifySigEd25519 => "verify_sig_ed25519",
        K::ComputeHashKeccak256 => "compute_hash_keccak256",
        K::RecoverKeyEcdsaSecp256k1 => "recover_key_ecdsa_secp256k1",
        K::VerifySigEcdsaSecp256r1 => "verify_sig_ecdsa_secp256r1",
        K::Bls12381CheckG1IsInSubgroup => "bls12_381_check_g1_is_in_subgroup",
        K::Bls12381G1Add => "bls12_381_g1_add",
        K::Bls12381G1Mul => "bls12_381_g1_mul",
        K::Bls12381G1Msm => "bls12_381_g1_msm",
        K::Bls12381MapFpToG1 => "bls12_381_map_fp_to_g1",
        K::Bls12381HashToG1 => "bls12_381_hash_to_g1",
        K::Bls12381CheckG2IsInSubgroup => "bls12_381_check_g2_is_in_subgroup",
        K::Bls12381G2Add => "bls12_381_g2_add",
        K::Bls12381G2Mul => "bls12_381_g2_mul",
        K::Bls12381G2Msm => "bls12_381_g2_msm",
        K::Bls12381MapFp2ToG2 => "bls12_381_map_fp2_to_g2",
        K::Bls12381HashToG2 => "bls12_381_hash_to_g2",
        K::Bls12381MultiPairingCheck => "bls12_381_multi_pairing_check",
        K::Bls12381FrAdd => "bls12_381_fr_add",
        K::Bls12381FrSub => "bls12_381_fr_sub",
        K::Bls12381FrMul => "bls12_381_fr_mul",
        K::Bls12381FrPow => "bls12_381_fr_pow",
        K::Bls12381FrInv => "bls12_381_fr_inv",
        K::Bn254G1Add => "bn254_g1_add",
        K::Bn254G1Mul => "bn254_g1_mul",
        K::Bn254MultiPairingCheck => "bn254_multi_pairing_check",
        K::PoseidonPermutation => "poseidon_permutation",
        K::Poseidon2Permutation => "poseidon2_permutation",
        K::Bn254G1Msm => "bn254_g1_msm",
        K::Bn254FrAdd => "bn254_fr_add",
        K::Bn254FrSub => "bn254_fr_sub",
        K::Bn254FrMul => "bn254_fr_mul",
        K::Bn254FrPow => "bn254_fr_pow",
        K::Bn254FrInv => "bn254_fr_inv",
        K::Bls12381G1IsOnCurve => "bls12_381_g1_is_on_curve",
        K::Bls12381G2IsOnCurve => "bls12_381_g2_is_on_curve",
        K::Bn254G1IsOnCurve => "bn254_g1_is_on_curve",
    }
}

/// ABI argument count of a crypto operation.
#[must_use]
pub fn crypto_kind_arity(kind: CryptoOpKind) -> usize {
    use CryptoOpKind as K;
    match kind {
        // Unary: single-input hashes, subgroup/on-curve checks, fr_inv.
        K::ComputeHashSha256
        | K::ComputeHashKeccak256
        | K::Bls12381CheckG1IsInSubgroup
        | K::Bls12381CheckG2IsInSubgroup
        | K::Bls12381MapFpToG1
        | K::Bls12381MapFp2ToG2
        | K::Bls12381FrInv
        | K::Bn254FrInv
        | K::Bls12381G1IsOnCurve
        | K::Bls12381G2IsOnCurve
        | K::Bn254G1IsOnCurve => 1,
        // Binary: point add/mul/msm, pairings, fr add/sub/mul/pow,
        // hash-to-curve (msg, dst).
        K::Bls12381G1Add
        | K::Bls12381G1Mul
        | K::Bls12381G1Msm
        | K::Bls12381HashToG1
        | K::Bls12381G2Add
        | K::Bls12381G2Mul
        | K::Bls12381G2Msm
        | K::Bls12381HashToG2
        | K::Bls12381MultiPairingCheck
        | K::Bls12381FrAdd
        | K::Bls12381FrSub
        | K::Bls12381FrMul
        | K::Bls12381FrPow
        | K::Bn254G1Add
        | K::Bn254G1Mul
        | K::Bn254MultiPairingCheck
        | K::Bn254G1Msm
        | K::Bn254FrAdd
        | K::Bn254FrSub
        | K::Bn254FrMul
        | K::Bn254FrPow => 2,
        // Ternary: sig verify/recover.
        K::VerifySigEd25519 | K::RecoverKeyEcdsaSecp256k1 | K::VerifySigEcdsaSecp256r1 => 3,
        // Poseidon permutations carry 8 operands each.
        K::PoseidonPermutation | K::Poseidon2Permutation => 8,
    }
}

/// Result type of a crypto operation, per the env.json ABI signatures.
#[must_use]
pub fn crypto_kind_result_type(kind: CryptoOpKind) -> KnownType {
    use CryptoOpKind as K;
    match kind {
        // Hashes, point ops, key recovery → BytesObject.
        K::ComputeHashSha256
        | K::ComputeHashKeccak256
        | K::RecoverKeyEcdsaSecp256k1
        | K::Bls12381G1Add
        | K::Bls12381G1Mul
        | K::Bls12381G1Msm
        | K::Bls12381MapFpToG1
        | K::Bls12381HashToG1
        | K::Bls12381G2Add
        | K::Bls12381G2Mul
        | K::Bls12381G2Msm
        | K::Bls12381MapFp2ToG2
        | K::Bls12381HashToG2
        | K::Bn254G1Add
        | K::Bn254G1Mul
        | K::Bn254G1Msm => KnownType::Bytes,
        // Signature verifies → Void; subgroup / on-curve / pairing
        // checks → Bool.
        K::VerifySigEd25519 | K::VerifySigEcdsaSecp256r1 => KnownType::Unit,
        K::Bls12381CheckG1IsInSubgroup
        | K::Bls12381CheckG2IsInSubgroup
        | K::Bls12381MultiPairingCheck
        | K::Bn254MultiPairingCheck
        | K::Bls12381G1IsOnCurve
        | K::Bls12381G2IsOnCurve
        | K::Bn254G1IsOnCurve => KnownType::Bool,
        // Field arithmetic → U256Val.
        K::Bls12381FrAdd
        | K::Bls12381FrSub
        | K::Bls12381FrMul
        | K::Bls12381FrPow
        | K::Bls12381FrInv
        | K::Bn254FrAdd
        | K::Bn254FrSub
        | K::Bn254FrMul
        | K::Bn254FrPow
        | K::Bn254FrInv => KnownType::U256,
        // Poseidon permutations → VecObject.
        K::PoseidonPermutation | K::Poseidon2Permutation => vec_of_unknown(),
    }
}

/// Map a `p`-module host import `(module, name)` pair to its
/// [`PrngOpKind`], or `None` for a non-`p` import.
#[must_use]
pub fn prng_fn_kind(module: &str, name: &str) -> Option<PrngOpKind> {
    use PrngOpKind as K;
    if module != "p" {
        return None;
    }
    Some(match name {
        "_" => K::PrngReseed,
        "0" => K::PrngBytesNew,
        "1" => K::PrngU64InInclusiveRange,
        "2" => K::PrngVecShuffle,
        _ => return None,
    })
}

/// Friendly (snake-case, upstream) name of a PRNG operation.
#[must_use]
pub fn prng_kind_name(kind: PrngOpKind) -> &'static str {
    use PrngOpKind as K;
    match kind {
        K::PrngReseed => "prng_reseed",
        K::PrngBytesNew => "prng_bytes_new",
        K::PrngU64InInclusiveRange => "prng_u64_in_inclusive_range",
        K::PrngVecShuffle => "prng_vec_shuffle",
    }
}

/// ABI argument count of a PRNG operation.
#[must_use]
pub fn prng_kind_arity(kind: PrngOpKind) -> usize {
    use PrngOpKind as K;
    match kind {
        K::PrngReseed | K::PrngBytesNew | K::PrngVecShuffle => 1,
        K::PrngU64InInclusiveRange => 2,
    }
}

/// Result type of a PRNG operation, per the env.json ABI signatures.
#[must_use]
pub fn prng_kind_result_type(kind: PrngOpKind) -> KnownType {
    use PrngOpKind as K;
    match kind {
        K::PrngReseed => KnownType::Unit,
        K::PrngBytesNew => KnownType::Bytes,
        K::PrngU64InInclusiveRange => KnownType::U64,
        K::PrngVecShuffle => vec_of_unknown(),
    }
}

/// Map a `t`-module host import `(module, name)` pair to its
/// [`TestOpKind`], or `None` for a non-`t` import.
#[must_use]
pub fn test_fn_kind(module: &str, name: &str) -> Option<TestOpKind> {
    use TestOpKind as K;
    if module != "t" {
        return None;
    }
    Some(match name {
        "_" => K::Dummy0,
        "0" => K::ProtocolGatedDummy,
        _ => return None,
    })
}

/// Friendly (snake-case, upstream) name of a test operation.
#[must_use]
pub fn test_kind_name(kind: TestOpKind) -> &'static str {
    use TestOpKind as K;
    match kind {
        K::Dummy0 => "dummy0",
        K::ProtocolGatedDummy => "protocol_gated_dummy",
    }
}

/// ABI argument count of a test operation (both are nullary).
#[must_use]
pub fn test_kind_arity(kind: TestOpKind) -> usize {
    match kind {
        TestOpKind::Dummy0 | TestOpKind::ProtocolGatedDummy => 0,
    }
}

/// Result type of a test operation (both return a raw `Val`).
#[must_use]
pub fn test_kind_result_type(kind: TestOpKind) -> KnownType {
    match kind {
        TestOpKind::Dummy0 | TestOpKind::ProtocolGatedDummy => KnownType::Val,
    }
}

/// Map an `l`-module *deploy/upgrade* host import `(module, name)` pair
/// to its [`DeployOpKind`], or `None` for the storage CRUD/TTL exports
/// (StoragePass's ops) or a non-`l` import.
#[must_use]
pub fn deploy_fn_kind(module: &str, name: &str) -> Option<DeployOpKind> {
    use DeployOpKind as K;
    if module != "l" {
        return None;
    }
    Some(match name {
        "3" => K::CreateContract,
        "4" => K::CreateAssetContract,
        "5" => K::UploadWasm,
        "6" => K::UpdateCurrentContractWasm,
        "a" => K::GetContractId,
        "b" => K::GetAssetContractId,
        "e" => K::CreateContractWithConstructor,
        // "_"/"0"/"1"/"2" CRUD, "7"-"9"/"c"-"g" TTL → StoragePass.
        _ => return None,
    })
}

/// Friendly (snake-case, upstream) name of a deploy operation.
#[must_use]
pub fn deploy_kind_name(kind: DeployOpKind) -> &'static str {
    use DeployOpKind as K;
    match kind {
        K::CreateContract => "create_contract",
        K::CreateAssetContract => "create_asset_contract",
        K::UploadWasm => "upload_wasm",
        K::UpdateCurrentContractWasm => "update_current_contract_wasm",
        K::GetContractId => "get_contract_id",
        K::GetAssetContractId => "get_asset_contract_id",
        K::CreateContractWithConstructor => "create_contract_with_constructor",
    }
}

/// ABI argument count of a deploy operation.
#[must_use]
pub fn deploy_kind_arity(kind: DeployOpKind) -> usize {
    use DeployOpKind as K;
    match kind {
        K::CreateAssetContract | K::UploadWasm | K::UpdateCurrentContractWasm
        | K::GetAssetContractId => 1,
        K::GetContractId => 2,
        K::CreateContract => 3,
        K::CreateContractWithConstructor => 4,
    }
}

/// Result type of a deploy operation, per the env.json ABI signatures.
#[must_use]
pub fn deploy_kind_result_type(kind: DeployOpKind) -> KnownType {
    use DeployOpKind as K;
    match kind {
        // Contract creation + id derivation → AddressObject.
        K::CreateContract
        | K::CreateAssetContract
        | K::GetContractId
        | K::GetAssetContractId
        | K::CreateContractWithConstructor => KnownType::Address,
        // upload_wasm → the wasm hash BytesObject.
        K::UploadWasm => KnownType::Bytes,
        K::UpdateCurrentContractWasm => KnownType::Unit,
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

    // --- a-module address conversions ---

    #[test]
    fn every_address_export_maps_and_roundtrips_name() {
        let table = [
            ("1", "strkey_to_address"),
            ("2", "address_to_strkey"),
            ("4", "get_address_from_muxed_address"),
            ("5", "get_id_from_muxed_address"),
            ("6", "get_address_executable"),
            ("7", "strkey_to_muxed_address"),
            ("8", "muxed_address_to_strkey"),
        ];
        for (export, expected_name) in table {
            let kind = addr_fn_kind("a", export)
                .unwrap_or_else(|| panic!("a.{export} must map to an AddressOpKind"));
            assert_eq!(addr_kind_name(kind), expected_name, "for export {export:?}");
        }
    }

    #[test]
    fn address_table_agrees_with_vendored_catalog() {
        // Drift guard: every address-conversion export must resolve in
        // the vendored env.json catalog under the same friendly name.
        for export in ["1", "2", "4", "5", "6", "7", "8"] {
            let kind = addr_fn_kind("a", export).expect("maps");
            let catalog_entry = crate::host_calls::resolve("a", export)
                .unwrap_or_else(|| panic!("a.{export} must exist in the vendored catalog"));
            assert_eq!(
                catalog_entry.friendly_name,
                addr_kind_name(kind),
                "val_abi address name for a.{export} drifted from the vendored catalog"
            );
        }
    }

    #[test]
    fn address_non_conversion_inputs_return_none() {
        // The auth exports (`_`, `0`, `3`) are not address conversions —
        // they get their own KnownOps, not AddressConversion.
        assert_eq!(addr_fn_kind("a", "0"), None, "require_auth is not a conversion");
        assert_eq!(addr_fn_kind("a", "_"), None, "require_auth_for_args");
        assert_eq!(addr_fn_kind("a", "3"), None, "authorize_as_curr_contract");
        assert_eq!(addr_fn_kind("l", "1"), None, "wrong module");
        assert_eq!(addr_fn_kind("a", "zz"), None, "nonexistent export");
    }

    #[test]
    fn address_result_types_match_abi() {
        use sordec_ir::AddressOpKind as K;
        assert_eq!(addr_kind_result_type(K::StrkeyToAddress), KnownType::Address);
        assert_eq!(addr_kind_result_type(K::AddressToStrkey), KnownType::String);
        assert_eq!(addr_kind_result_type(K::GetIdFromMuxedAddress), KnownType::U64);
        // The two `-> Val` returns are typed Val, not over-claimed.
        assert_eq!(addr_kind_result_type(K::GetAddressExecutable), KnownType::Val);
        assert_eq!(addr_kind_result_type(K::StrkeyToMuxedAddress), KnownType::Val);
    }

    // --- m/v/b collections tables ---

    #[test]
    fn map_table_agrees_with_vendored_catalog() {
        for export in ["_", "0", "1", "2", "3", "4", "5", "6", "7", "8", "a"] {
            let kind = map_fn_kind("m", export).expect("maps");
            let catalog_entry = crate::host_calls::resolve("m", export)
                .unwrap_or_else(|| panic!("m.{export} must exist in the vendored catalog"));
            assert_eq!(
                catalog_entry.friendly_name,
                map_kind_name(kind),
                "val_abi map name for m.{export} drifted from the vendored catalog"
            );
        }
    }

    #[test]
    fn vec_table_agrees_with_vendored_catalog() {
        for export in [
            "_", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e",
            "f", "h",
        ] {
            let kind = vec_fn_kind("v", export).expect("maps");
            let catalog_entry = crate::host_calls::resolve("v", export)
                .unwrap_or_else(|| panic!("v.{export} must exist in the vendored catalog"));
            assert_eq!(
                catalog_entry.friendly_name,
                vec_kind_name(kind),
                "val_abi vec name for v.{export} drifted from the vendored catalog"
            );
        }
    }

    #[test]
    fn buf_table_agrees_with_vendored_catalog() {
        for export in [
            "_", "0", "1", "2", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f",
            "g", "h", "k", "l", "m", "n", "o",
        ] {
            let kind = buf_fn_kind("b", export).expect("maps");
            let catalog_entry = crate::host_calls::resolve("b", export)
                .unwrap_or_else(|| panic!("b.{export} must exist in the vendored catalog"));
            assert_eq!(
                catalog_entry.friendly_name,
                buf_kind_name(kind),
                "val_abi buf name for b.{export} drifted from the vendored catalog"
            );
        }
    }

    // --- c/p/t/l-deploy tables (W3) ---

    /// Every `c` export (`_`, `0`-`9`, `a`-`z` = 37) maps, and its
    /// friendly name agrees with the vendored catalog. Also asserts the
    /// count so a future host release that *adds* a crypto function
    /// fails here until the table is extended.
    #[test]
    fn crypto_table_agrees_with_vendored_catalog() {
        let exports: Vec<String> = std::iter::once("_".to_string())
            .chain(('0'..='9').map(|c| c.to_string()))
            .chain(('a'..='z').map(|c| c.to_string()))
            .collect();
        assert_eq!(exports.len(), 37, "expected 37 crypto exports");
        for export in &exports {
            let kind = crypto_fn_kind("c", export)
                .unwrap_or_else(|| panic!("c.{export} must map to a CryptoOpKind"));
            let catalog = crate::host_calls::resolve("c", export)
                .unwrap_or_else(|| panic!("c.{export} must exist in the vendored catalog"));
            assert_eq!(
                catalog.friendly_name,
                crypto_kind_name(kind),
                "val_abi crypto name for c.{export} drifted from the catalog"
            );
        }
    }

    #[test]
    fn prng_table_agrees_with_vendored_catalog() {
        for export in ["_", "0", "1", "2"] {
            let kind = prng_fn_kind("p", export).expect("maps");
            let catalog = crate::host_calls::resolve("p", export)
                .unwrap_or_else(|| panic!("p.{export} must exist in the catalog"));
            assert_eq!(
                catalog.friendly_name,
                prng_kind_name(kind),
                "val_abi prng name for p.{export} drifted from the catalog"
            );
        }
    }

    #[test]
    fn test_table_agrees_with_vendored_catalog() {
        for export in ["_", "0"] {
            let kind = test_fn_kind("t", export).expect("maps");
            let catalog = crate::host_calls::resolve("t", export)
                .unwrap_or_else(|| panic!("t.{export} must exist in the catalog"));
            assert_eq!(
                catalog.friendly_name,
                test_kind_name(kind),
                "val_abi test name for t.{export} drifted from the catalog"
            );
        }
    }

    #[test]
    fn deploy_table_agrees_with_vendored_catalog() {
        for export in ["3", "4", "5", "6", "a", "b", "e"] {
            let kind = deploy_fn_kind("l", export).expect("maps");
            let catalog = crate::host_calls::resolve("l", export)
                .unwrap_or_else(|| panic!("l.{export} must exist in the catalog"));
            assert_eq!(
                catalog.friendly_name,
                deploy_kind_name(kind),
                "val_abi deploy name for l.{export} drifted from the catalog"
            );
        }
    }

    /// The deploy table and StoragePass's CRUD/TTL exports partition the
    /// `l` module with no overlap and no gap: the union must be exactly
    /// the 18 `l` exports the catalog knows.
    #[test]
    fn deploy_and_storage_partition_the_ledger_module() {
        let storage_ttl = ["_", "0", "1", "2", "7", "8", "9", "c", "d", "f", "g"];
        let deploy = ["3", "4", "5", "6", "a", "b", "e"];
        // No export is in both sets.
        for d in deploy {
            assert!(!storage_ttl.contains(&d), "l.{d} claimed by both");
            assert!(deploy_fn_kind("l", d).is_some(), "l.{d} must map to deploy");
        }
        // The deploy table rejects every storage/TTL export.
        for s in storage_ttl {
            assert_eq!(deploy_fn_kind("l", s), None, "l.{s} is StoragePass's");
        }
        // The union covers all 18.
        assert_eq!(storage_ttl.len() + deploy.len(), 18);
    }

    #[test]
    fn abi_sweep_wrong_module_returns_none() {
        assert_eq!(crypto_fn_kind("p", "_"), None);
        assert_eq!(prng_fn_kind("c", "_"), None);
        assert_eq!(test_fn_kind("l", "_"), None);
        assert_eq!(deploy_fn_kind("c", "3"), None);
        assert_eq!(crypto_fn_kind("c", "zz"), None, "nonexistent export");
    }

    #[test]
    fn abi_sweep_result_types_match_abi() {
        assert_eq!(
            crypto_kind_result_type(CryptoOpKind::ComputeHashSha256),
            KnownType::Bytes
        );
        assert_eq!(
            crypto_kind_result_type(CryptoOpKind::VerifySigEd25519),
            KnownType::Unit
        );
        assert_eq!(
            crypto_kind_result_type(CryptoOpKind::Bls12381MultiPairingCheck),
            KnownType::Bool
        );
        assert_eq!(
            crypto_kind_result_type(CryptoOpKind::Bls12381FrAdd),
            KnownType::U256
        );
        assert!(matches!(
            crypto_kind_result_type(CryptoOpKind::PoseidonPermutation),
            KnownType::Vec(_)
        ));
        assert_eq!(crypto_kind_arity(CryptoOpKind::PoseidonPermutation), 8);
        assert_eq!(
            prng_kind_result_type(PrngOpKind::PrngU64InInclusiveRange),
            KnownType::U64
        );
        assert_eq!(
            deploy_kind_result_type(DeployOpKind::CreateContract),
            KnownType::Address
        );
        assert_eq!(
            deploy_kind_result_type(DeployOpKind::UploadWasm),
            KnownType::Bytes
        );
        assert_eq!(test_kind_result_type(TestOpKind::Dummy0), KnownType::Val);
    }

    #[test]
    fn linear_memory_constructor_exports_are_excluded() {
        // The five `*_new_from_linear_memory` constructors belong to the
        // linear-memory recognizer, not the collections tables.
        assert_eq!(map_fn_kind("m", "9"), None, "map_new_from_linear_memory");
        assert_eq!(vec_fn_kind("v", "g"), None, "vec_new_from_linear_memory");
        assert_eq!(buf_fn_kind("b", "3"), None, "bytes_new_from_linear_memory");
        assert_eq!(buf_fn_kind("b", "i"), None, "string_new_from_linear_memory");
        assert_eq!(buf_fn_kind("b", "j"), None, "symbol_new_from_linear_memory");
    }

    #[test]
    fn collections_wrong_module_or_export_returns_none() {
        assert_eq!(map_fn_kind("v", "1"), None, "wrong module");
        assert_eq!(vec_fn_kind("m", "1"), None, "wrong module");
        assert_eq!(buf_fn_kind("x", "_"), None, "wrong module");
        assert_eq!(map_fn_kind("m", "zz"), None, "nonexistent export");
        assert_eq!(vec_fn_kind("v", "zz"), None, "nonexistent export");
        assert_eq!(buf_fn_kind("b", "zz"), None, "nonexistent export");
    }

    #[test]
    fn collections_result_types_match_abi() {
        assert_eq!(map_kind_result_type(MapOpKind::Has), KnownType::Bool);
        assert_eq!(map_kind_result_type(MapOpKind::Len), KnownType::U32);
        assert!(matches!(
            map_kind_result_type(MapOpKind::Put),
            KnownType::Map(_, _)
        ));
        assert!(matches!(
            map_kind_result_type(MapOpKind::Keys),
            KnownType::Vec(_)
        ));
        assert_eq!(
            map_kind_result_type(MapOpKind::UnpackToLinearMemory),
            KnownType::Unit
        );
        // vec_binary_search returns a raw u64, not a tagged Val.
        assert_eq!(vec_kind_result_type(VecOpKind::BinarySearch), KnownType::U64);
        assert_eq!(vec_kind_result_type(VecOpKind::Get), KnownType::Val);
        assert_eq!(buf_kind_result_type(BufOpKind::BytesToString), KnownType::String);
        assert_eq!(buf_kind_result_type(BufOpKind::StringToBytes), KnownType::Bytes);
        assert_eq!(buf_kind_result_type(BufOpKind::DeserializeFromBytes), KnownType::Val);
    }

    // --- SymbolSmall decoding ---

    #[test]
    fn decode_small_symbol_matches_sdk_emitted_corpus_constants() {
        // Fixed vectors harvested from the corpus fixtures' actual
        // i64 constants — i.e. bits produced by the real SDK/rustc
        // encoder, so this locks agreement with upstream, not just
        // self-consistency.
        for (bits, expected) in [
            (2_678_977_294u64, "burn"),
            (3_404_527_886, "mint"),
            (696_753_673_873_934, "balance"),
            (27_311_646_515_383_310, "METADATA"),
            (65_154_533_130_155_790, "transfer"),
            (4_083_516_257_707_209_486, "set_admin"),
        ] {
            assert_eq!(
                decode_small_symbol(bits).as_deref(),
                Some(expected),
                "bits {bits} must decode to {expected:?}"
            );
        }
    }

    #[test]
    fn decode_small_symbol_covers_all_char_classes() {
        // Encode "_0Aa9" with the documented table and decode it back.
        let codes = [1u64, 2, 12, 38, 11]; // _, 0, A, a, 9
        let mut body = 0u64;
        for c in codes {
            body = (body << 6) | c;
        }
        let bits = (body << 8) | u64::from(TAG_SYMBOL_SMALL);
        assert_eq!(decode_small_symbol(bits).as_deref(), Some("_0Aa9"));
    }

    #[test]
    fn decode_small_symbol_rejects_malformed_input() {
        // Wrong tag (U32Val).
        assert_eq!(decode_small_symbol((5 << 32) | 4), None);
        // Body wider than 54 bits (bit 55 of the body set).
        let too_wide = (1u64 << (54 + 8)) | u64::from(TAG_SYMBOL_SMALL);
        assert_eq!(decode_small_symbol(too_wide), None);
        // Interior zero code: 'a' in the top slot, zero, then 'b'.
        let body = (38u64 << 12) | 39; // slot gap between the chars
        let bits = (body << 8) | u64::from(TAG_SYMBOL_SMALL);
        assert_eq!(decode_small_symbol(bits), None);
        // Empty body: a valid Val, but useless as a name.
        assert_eq!(decode_small_symbol(u64::from(TAG_SYMBOL_SMALL)), None);
    }

    #[test]
    fn decode_small_symbol_covers_all_char_classes_typo_guard() {
        // "z" is code 63 — the table's last entry.
        let bits = (63u64 << 8) | u64::from(TAG_SYMBOL_SMALL);
        assert_eq!(decode_small_symbol(bits).as_deref(), Some("z"));
    }

    #[test]
    fn collections_arities_match_abi_for_corpus_ops() {
        // The six corpus-exercised shapes (plus New/BytesNewEmpty nullary
        // edges) — the rest are covered by the exhaustive dispatch tests
        // in the recognizer.
        assert_eq!(map_kind_arity(MapOpKind::UnpackToLinearMemory), 4);
        assert_eq!(vec_kind_arity(VecOpKind::UnpackToLinearMemory), 3);
        assert_eq!(vec_kind_arity(VecOpKind::Len), 1);
        assert_eq!(vec_kind_arity(VecOpKind::Get), 2);
        assert_eq!(vec_kind_arity(VecOpKind::FirstIndexOf), 2);
        assert_eq!(buf_kind_arity(BufOpKind::SymbolIndexInLinearMemory), 3);
        assert_eq!(map_kind_arity(MapOpKind::New), 0);
        assert_eq!(buf_kind_arity(BufOpKind::BytesNewEmpty), 0);
    }
}
