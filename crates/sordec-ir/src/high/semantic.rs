//! Semantic operations recovered by sordec passes.
//!
//! [`SemanticOp`] is the Phase 2+ output of pattern matchers that turn
//! sequences of WASM instructions into Soroban-level operations. Pattern
//! matchers add new [`Known`](SemanticOp::Known) variants over time;
//! [`Unknown`](SemanticOp::Unknown) is the honest fallback when no
//! pattern matched, recording the original host call and an
//! [`UnknownReason`] so the emitted Rust can flag it for the auditor.
//!
//! Variants in [`KnownOp`] expand as Phase 2 patterns land. The set
//! defined here covers the operations the architecture explicitly calls
//! out (storage, auth, cross-contract calls, events) and a few
//! always-present ledger / crypto primitives. New variants must come with
//! a corresponding pass.

use sordec_common::{UnknownReason, ValueId};

use super::storage::StorageTier;
use super::ty::KnownType;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Semantic operation associated with a binding.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum SemanticOp {
    /// Pattern matched a known Soroban operation.
    Known(KnownOp),

    /// Host call did not match any registered pattern. The fields preserve
    /// the original call site so emit can render a `// UNRECOVERED:`
    /// comment and the auditor can investigate.
    Unknown {
        /// Soroban host module letter (`"l"`, `"x"`, `"i"`, etc.).
        // JUSTIFY: Module names are arbitrary host-imported strings.
        host_module: String,
        /// Host function name as imported.
        // JUSTIFY: same as above.
        host_fn: String,
        /// Operand values to the host call, in original argument order.
        args: Vec<ValueId>,
        /// Why no pattern matched (no metadata, unsupported pattern, etc.).
        reason: UnknownReason,
    },
}

/// Soroban operations the decompiler knows how to recover.
///
/// This list is the inventory of pattern matchers Phase 2 implements; new
/// variants land alongside their detecting pass.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum KnownOp {
    // ---- Storage ----
    /// `env.storage().<tier>().get::<_>(&key)`.
    StorageGet {
        /// Which storage tier.
        tier: StorageTier,
        /// Key value.
        key: ValueId,
    },

    /// `env.storage().<tier>().set::<_>(&key, &value)`.
    StorageSet {
        /// Which storage tier.
        tier: StorageTier,
        /// Key value.
        key: ValueId,
        /// Value being stored.
        value: ValueId,
    },

    /// `env.storage().<tier>().has::<_>(&key)`.
    StorageHas {
        /// Which storage tier.
        tier: StorageTier,
        /// Key value.
        key: ValueId,
    },

    /// `env.storage().<tier>().remove::<_>(&key)`.
    StorageRemove {
        /// Which storage tier.
        tier: StorageTier,
        /// Key value.
        key: ValueId,
    },

    /// `env.storage().<tier>().extend_ttl(&key, threshold, extend_to)`.
    StorageExtendTtl {
        /// Which storage tier.
        tier: StorageTier,
        /// Key value.
        key: ValueId,
        /// Threshold ledger count.
        threshold: ValueId,
        /// New target ledger count.
        extend_to: ValueId,
    },

    // ---- Authorisation ----
    /// `address.require_auth()`.
    RequireAuth {
        /// Address required to authorise the current invocation.
        address: ValueId,
    },

    /// `address.require_auth_for_args(args)`.
    RequireAuthForArgs {
        /// Address required to authorise.
        address: ValueId,
        /// Args tuple bound to the authorisation.
        args: Vec<ValueId>,
    },

    // ---- Cross-contract calls ----
    /// `env.invoke_contract(contract, function, args)`.
    InvokeContract {
        /// Callee contract address.
        contract: ValueId,
        /// Function symbol (a `Symbol` value).
        function: ValueId,
        /// Argument vector.
        args: Vec<ValueId>,
    },

    /// `env.try_invoke_contract(contract, function, args)`.
    TryInvokeContract {
        /// Callee contract address.
        contract: ValueId,
        /// Function symbol.
        function: ValueId,
        /// Argument vector.
        args: Vec<ValueId>,
    },

    // ---- Events ----
    /// `env.events().publish(topics, data)`.
    PublishEvent {
        /// Event topics.
        topics: Vec<ValueId>,
        /// Event data payload.
        data: ValueId,
    },

    // ---- Ledger context ----
    /// `env.current_contract_address()`.
    GetCurrentContractAddress,
    /// `env.ledger().sequence()`.
    GetLedgerSequence,
    /// `env.ledger().timestamp()`.
    GetLedgerTimestamp,
    /// `env.ledger().protocol_version()`.
    GetLedgerProtocolVersion,
    /// `env.ledger().network_id()`.
    GetLedgerNetworkId,

    // ---- Crypto ----
    /// `env.crypto().sha256(input)`.
    Sha256 {
        /// Input bytes.
        input: ValueId,
    },
    /// `env.crypto().keccak256(input)`.
    Keccak256 {
        /// Input bytes.
        input: ValueId,
    },
    /// Verify an ed25519 signature.
    VerifyEd25519 {
        /// Public key.
        public_key: ValueId,
        /// Message bytes.
        message: ValueId,
        /// Signature bytes.
        signature: ValueId,
    },

    // ---- Val encoding (recognized by the C1 val-encoding pass) ----
    /// Guest-side small-value Val encode: `(value << shift) | tag`.
    ///
    /// Recognized from the inline bit-packing pattern the SDK compiles
    /// into guest code for values that fit the 56-bit small-Val body
    /// (or the 32-bit major for `U32Val`/`I32Val`). `ty` is the payload
    /// type derived from the tag byte — the binding-level certainty is
    /// `Inferred` because the evidence is structural, not ABI-proven.
    ValEncodeSmall {
        /// Payload type implied by the tag (e.g. `U64` for tag 6).
        ty: KnownType,
        /// The raw value being packed.
        value: ValueId,
    },

    /// Guest-side small-value Val decode: `value >> shift`, extracting
    /// the body from a tagged Val.
    ///
    /// Deliberately carries **no payload-type claim**: the lowering
    /// erases shift signedness (`shr_s` vs `shr_u` both lower to
    /// `BinaryOp::Shr`), so u64-vs-i64 is not determinable from the
    /// pattern alone. The type-recovery pass refines the binding's
    /// `IrType` later when flow context proves the payload type.
    ValDecodeSmall {
        /// The tagged Val being unpacked.
        value: ValueId,
    },

    /// Val tag test: `(value & 0xFF) == tag`.
    ///
    /// The SDK's small-vs-object dispatch guard. `tag` is the raw tag
    /// byte; resolve its name via the `val_abi` table in
    /// `sordec-passes` (kept out of this type so the IR layer carries
    /// no ABI tables).
    ValTagCheck {
        /// The Val whose tag byte is being tested.
        value: ValueId,
        /// Expected tag byte (see `soroban-env-common`'s `Tag` enum).
        tag: u8,
    },

    /// Host-side object-form Val conversion — one of the `i`-module
    /// (`int`) host calls that wrap or unwrap values too large for the
    /// small-Val inline encoding.
    ///
    /// ABI-proven recognition (the host-function identity *is* the
    /// semantic), so bindings carry `Known` certainty.
    ValObject {
        /// Which conversion this is.
        kind: ValObjectKind,
        /// Operands in original host-call argument order.
        args: Vec<ValueId>,
    },
}

/// The complete `i`-module (`int`) host-side Val conversion surface.
///
/// One variant per conversion host function, covering the full ABI (the
/// same "specialization is radical" rule as the 191-entry host-call
/// catalog). Each variant documents its `(module, export)` import pair
/// from `soroban-env-common 26.1.2`'s `env.json`. The
/// `(module, export) → ValObjectKind` mapping table lives in
/// `sordec-passes`' `val_abi` module — this enum is IR vocabulary only.
///
/// The `i`-module *arithmetic* functions (`u256_add` etc.) are
/// deliberately absent: those are wide-arithmetic operations (a separate
/// recognizer's scope), not Val conversions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ValObjectKind {
    /// `(i, _)` `obj_from_u64` — wrap a u64 into a `U64Object`.
    ObjFromU64,
    /// `(i, 0)` `obj_to_u64` — unwrap a `U64Object` to its u64.
    ObjToU64,
    /// `(i, 1)` `obj_from_i64` — wrap an i64 into an `I64Object`.
    ObjFromI64,
    /// `(i, 2)` `obj_to_i64` — unwrap an `I64Object` to its i64.
    ObjToI64,
    /// `(i, 3)` `obj_from_u128_pieces` — build a `U128Object` from
    /// `(hi, lo)` u64 pieces.
    ObjFromU128Pieces,
    /// `(i, 4)` `obj_to_u128_lo64` — low 64 bits of a `U128Object`.
    ObjToU128Lo64,
    /// `(i, 5)` `obj_to_u128_hi64` — high 64 bits of a `U128Object`.
    ObjToU128Hi64,
    /// `(i, 6)` `obj_from_i128_pieces` — build an `I128Object` from
    /// `(hi, lo)` pieces.
    ObjFromI128Pieces,
    /// `(i, 7)` `obj_to_i128_lo64` — low 64 bits of an `I128Object`.
    ObjToI128Lo64,
    /// `(i, 8)` `obj_to_i128_hi64` — high 64 bits of an `I128Object`.
    ObjToI128Hi64,
    /// `(i, 9)` `obj_from_u256_pieces` — build a `U256Object` from four
    /// u64 pieces.
    ObjFromU256Pieces,
    /// `(i, a)` `u256_val_from_be_bytes` — `U256Val` from a 32-byte
    /// big-endian `BytesObject`.
    U256ValFromBeBytes,
    /// `(i, b)` `u256_val_to_be_bytes` — 32-byte big-endian
    /// `BytesObject` from a `U256Val`.
    U256ValToBeBytes,
    /// `(i, c)` `obj_to_u256_hi_hi` — bits 192-255 of a `U256Object`.
    ObjToU256HiHi,
    /// `(i, d)` `obj_to_u256_hi_lo` — bits 128-191 of a `U256Object`.
    ObjToU256HiLo,
    /// `(i, e)` `obj_to_u256_lo_hi` — bits 64-127 of a `U256Object`.
    ObjToU256LoHi,
    /// `(i, f)` `obj_to_u256_lo_lo` — bits 0-63 of a `U256Object`.
    ObjToU256LoLo,
    /// `(i, g)` `obj_from_i256_pieces` — build an `I256Object` from four
    /// pieces.
    ObjFromI256Pieces,
    /// `(i, h)` `i256_val_from_be_bytes` — `I256Val` from a 32-byte
    /// big-endian `BytesObject`.
    I256ValFromBeBytes,
    /// `(i, i)` `i256_val_to_be_bytes` — 32-byte big-endian
    /// `BytesObject` from an `I256Val`.
    I256ValToBeBytes,
    /// `(i, j)` `obj_to_i256_hi_hi` — bits 192-255 of an `I256Object`.
    ObjToI256HiHi,
    /// `(i, k)` `obj_to_i256_hi_lo` — bits 128-191 of an `I256Object`.
    ObjToI256HiLo,
    /// `(i, l)` `obj_to_i256_lo_hi` — bits 64-127 of an `I256Object`.
    ObjToI256LoHi,
    /// `(i, m)` `obj_to_i256_lo_lo` — bits 0-63 of an `I256Object`.
    ObjToI256LoLo,
    /// `(i, D)` `timepoint_obj_from_u64` — wrap a u64 into a
    /// `TimepointObject`.
    TimepointObjFromU64,
    /// `(i, E)` `timepoint_obj_to_u64` — unwrap a `TimepointObject`.
    TimepointObjToU64,
    /// `(i, F)` `duration_obj_from_u64` — wrap a u64 into a
    /// `DurationObject`.
    DurationObjFromU64,
    /// `(i, G)` `duration_obj_to_u64` — unwrap a `DurationObject`.
    DurationObjToU64,
}
