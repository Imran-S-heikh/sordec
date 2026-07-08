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
    ///
    /// Host import `(l, 7)` `extend_contract_data_ttl`.
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

    /// `env.storage().instance().extend_ttl(threshold, extend_to)` —
    /// bumps the *current* contract's instance + code entries.
    ///
    /// Host import `(l, 8)` `extend_current_contract_instance_and_code_ttl`.
    /// No key and no tier: the target is implicitly the executing
    /// contract's instance/code ledger entries. This is the TTL call
    /// every SEP-41 token entrypoint makes.
    ExtendCurrentContractInstanceAndCodeTtl {
        /// Threshold ledger count.
        threshold: ValueId,
        /// New target ledger count.
        extend_to: ValueId,
    },

    /// Extend another contract's instance + code TTL.
    ///
    /// Host import `(l, 9)` `extend_contract_instance_and_code_ttl`.
    ExtendContractInstanceAndCodeTtl {
        /// Target contract address.
        contract: ValueId,
        /// Threshold ledger count.
        threshold: ValueId,
        /// New target ledger count.
        extend_to: ValueId,
    },

    /// Extend another contract's instance TTL only.
    ///
    /// Host import `(l, c)` `extend_contract_instance_ttl`
    /// (protocol 21+).
    ExtendContractInstanceTtl {
        /// Target contract address.
        contract: ValueId,
        /// Threshold ledger count.
        threshold: ValueId,
        /// New target ledger count.
        extend_to: ValueId,
    },

    /// Extend another contract's code TTL only.
    ///
    /// Host import `(l, d)` `extend_contract_code_ttl` (protocol 21+).
    ExtendContractCodeTtl {
        /// Target contract address.
        contract: ValueId,
        /// Threshold ledger count.
        threshold: ValueId,
        /// New target ledger count.
        extend_to: ValueId,
    },

    /// v2 data-entry TTL extension with explicit min/max bounds.
    ///
    /// Host import `(l, f)` `extend_contract_data_ttl_v2`
    /// (protocol 26+).
    StorageExtendTtlV2 {
        /// Which storage tier.
        tier: StorageTier,
        /// Key value.
        key: ValueId,
        /// New target ledger count.
        extend_to: ValueId,
        /// Minimum extension bound.
        min_extension: ValueId,
        /// Maximum extension bound.
        max_extension: ValueId,
    },

    /// v2 instance/code TTL extension with an explicit scope selector.
    ///
    /// Host import `(l, g)` `extend_contract_instance_and_code_ttl_v2`
    /// (protocol 26+). `extension_scope` is a raw
    /// `ContractTtlExtension` enum operand — decoding it to a typed
    /// scope is deferred until a fixture exercises this call.
    ExtendContractInstanceAndCodeTtlV2 {
        /// Target contract address.
        contract: ValueId,
        /// `ContractTtlExtension` scope selector (raw operand).
        extension_scope: ValueId,
        /// New target ledger count.
        extend_to: ValueId,
        /// Minimum extension bound.
        min_extension: ValueId,
        /// Maximum extension bound.
        max_extension: ValueId,
    },

    // ---- Authorisation ----
    /// `address.require_auth()`.
    RequireAuth {
        /// Address required to authorise the current invocation.
        address: ValueId,
    },

    /// `address.require_auth_for_args(args)`.
    ///
    /// Host import `(a, _)`. The host ABI passes a single `VecObject`
    /// handle for the args; `args` holds that one handle. Expanding it
    /// into the underlying argument list is the collections recognizer's
    /// job, not this one.
    RequireAuthForArgs {
        /// Address required to authorise.
        address: ValueId,
        /// Args tuple bound to the authorisation (a single `VecObject`
        /// handle until the collections recognizer expands it).
        args: Vec<ValueId>,
    },

    /// `env.authorize_as_current_contract(auth_entries)` — the current
    /// contract authorizes a set of sub-invocation entries as itself.
    ///
    /// Host import `(a, 3)`.
    AuthorizeAsCurrContract {
        /// `VecObject` handle of authorization entries.
        auth_entries: ValueId,
    },

    /// An `a`-module address conversion / query (strkey ↔ address,
    /// muxed-address decomposition, executable inspection).
    ///
    /// ABI-proven recognition — the host-function identity *is* the
    /// semantic — so bindings carry `Known` certainty. `kind` names the
    /// specific conversion; the `(module, export)` → kind mapping and
    /// per-kind ABI return type live in `sordec-passes`' `val_abi`
    /// module (this enum is IR vocabulary only).
    AddressConversion {
        /// Which conversion this is.
        kind: AddressOpKind,
        /// Operands in original host-call argument order.
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
    ///
    /// Host import `(x, 2)` `get_ledger_version` — Soroban's "ledger
    /// version" *is* its protocol version.
    GetLedgerProtocolVersion,
    /// `env.ledger().network_id()`.
    GetLedgerNetworkId,
    /// `env.ledger().max_live_until_ledger()` — the maximum ledger the
    /// current entry may live until. Host import `(x, 8)`.
    GetMaxLiveUntilLedger,

    /// Host three-way `Val` comparison — `(x, 0)` `obj_cmp(a, b)`
    /// returning `i64` (`-1` / `0` / `1`).
    ///
    /// Names the comparison primitive; higher-level `Ord` / `<`
    /// reconstruction from the surrounding branch context is a later
    /// refinement.
    ValCompare {
        /// Left operand.
        a: ValueId,
        /// Right operand.
        b: ValueId,
    },

    /// `panic_with_error!(env, error)` — host import `(x, 5)`
    /// `fail_with_error(error)`.
    ///
    /// The host-call form of a panic. Bare `panic!()` (which compiles
    /// to a control-flow `unreachable`) and formatted panics are the
    /// separate panic-recovery recognizer's scope.
    PanicWithError {
        /// The `Error` value the contract fails with.
        error: ValueId,
    },

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

    // ---- Linear-memory constructors (recognized by LinearMemoryPass) ----
    /// `symbol_new_from_linear_memory(lm_pos, len)` — host import `(b, j)`,
    /// returns a `SymbolObject`. Constructs a `Symbol` from bytes copied
    /// out of a linear-memory slice.
    ///
    /// `resolved` holds the interned symbol text when `(lm_pos, len)`
    /// trace to a constant rodata slice; it is `None` when the position or
    /// length is not a locally-provable constant (the corpus threads them
    /// through phi chains and helper parameters — a constant-propagation
    /// engine fills these in later). Following the `StorageTier`
    /// Known/Unknown honesty discipline, the op is always recognized (the
    /// host identity proves it); only the literal contents may be Unknown.
    SymbolNew {
        /// Linear-memory byte offset of the symbol bytes.
        lm_pos: ValueId,
        /// Number of bytes.
        len: ValueId,
        /// Recovered symbol text, or `None` when the slice is not a
        /// locally-provable constant.
        // JUSTIFY: Symbol contents are arbitrary user-supplied identifiers.
        resolved: Option<String>,
    },

    /// `string_new_from_linear_memory(lm_pos, len)` — host import `(b, i)`,
    /// returns a `StringObject`. See [`SymbolNew`](KnownOp::SymbolNew) for
    /// the `resolved` semantics.
    StringNew {
        /// Linear-memory byte offset of the string bytes.
        lm_pos: ValueId,
        /// Number of bytes.
        len: ValueId,
        /// Recovered string contents, or `None` when not a locally-provable
        /// constant.
        // JUSTIFY: String contents are arbitrary.
        resolved: Option<String>,
    },

    /// `bytes_new_from_linear_memory(lm_pos, len)` — host import `(b, 3)`,
    /// returns a `BytesObject`. See [`SymbolNew`](KnownOp::SymbolNew) for
    /// the `resolved` semantics.
    BytesNew {
        /// Linear-memory byte offset of the bytes.
        lm_pos: ValueId,
        /// Number of bytes.
        len: ValueId,
        /// Recovered byte literal, or `None` when not a locally-provable
        /// constant.
        resolved: Option<Vec<u8>>,
    },

    /// `vec_new_from_linear_memory(vals_pos, len)` — host import `(v, g)`,
    /// returns a `VecObject`. Builds a `Vec` from a contiguous array of
    /// `len` `Val`s in linear memory.
    ///
    /// No `resolved` field: the `Val`s live in a runtime stack buffer, not
    /// rodata, so the element contents are not literal-recoverable even
    /// with perfect tracing. This names the constructor shape; recovering
    /// the elements is the collections recognizer's separate scope.
    VecNew {
        /// Linear-memory byte offset of the `Val` array.
        vals_pos: ValueId,
        /// Element count (each `Val` is 8 bytes).
        len: ValueId,
    },

    /// `map_new_from_linear_memory(keys_pos, vals_pos, len)` — host import
    /// `(m, 9)`, returns a `MapObject`. Builds a `Map` from parallel
    /// `keys` and `vals` arrays of `len` `Val`s each.
    ///
    /// No `resolved` field, for the same reason as
    /// [`VecNew`](KnownOp::VecNew): the arrays are runtime stack data.
    MapNew {
        /// Linear-memory byte offset of the keys `Val` array.
        keys_pos: ValueId,
        /// Linear-memory byte offset of the vals `Val` array.
        vals_pos: ValueId,
        /// Element count of each array.
        len: ValueId,
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

/// The `a`-module (address) conversion / query surface, excluding the
/// authorization calls (`require_auth`, `require_auth_for_args`,
/// `authorize_as_curr_contract`) which have their own [`KnownOp`]
/// variants.
///
/// One variant per conversion host function, each documented with its
/// `(module, export)` import pair and protocol gate. Grouped under a
/// single [`KnownOp::AddressConversion`] the same way `i`-module
/// conversions group under [`ValObjectKind`]. The `(module, export) →
/// AddressOpKind` mapping lives in `sordec-passes`' `val_abi` module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum AddressOpKind {
    /// `(a, 1)` `strkey_to_address` — parse a strkey `Val` into an
    /// `AddressObject`.
    StrkeyToAddress,
    /// `(a, 2)` `address_to_strkey` — render an address as a strkey
    /// `StringObject`.
    AddressToStrkey,
    /// `(a, 4)` `get_address_from_muxed_address` — the underlying
    /// address of a muxed address (protocol 23+).
    GetAddressFromMuxedAddress,
    /// `(a, 5)` `get_id_from_muxed_address` — the u64 id multiplexed
    /// into a muxed address (protocol 23+).
    GetIdFromMuxedAddress,
    /// `(a, 6)` `get_address_executable` — the executable kind of an
    /// address, as a `Val` (protocol 23+).
    GetAddressExecutable,
    /// `(a, 7)` `strkey_to_muxed_address` — parse a strkey into a muxed
    /// address `Val` (protocol 26+).
    StrkeyToMuxedAddress,
    /// `(a, 8)` `muxed_address_to_strkey` — render a muxed address as a
    /// strkey `StringObject` (protocol 26+).
    MuxedAddressToStrkey,
}
