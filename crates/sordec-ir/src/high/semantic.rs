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

/// A storage key recognized as a `#[contracttype]` enum variant
/// constructed by the SDK's shared enum-constructor idiom
/// (`DataKey::Admin`-class keys).
///
/// Filled by the `enum-key` pass only when its full evidence gate
/// passed: the constructor helper's rodata variant texts exactly match
/// one `contractspecv0` union, the per-callsite discriminant is a
/// proven constant in range, and the payload footprint agrees with the
/// variant's field list. One link is structural rather than witnessed —
/// rustc assigns the stored tag values in declaration order for this
/// enum shape — so the naming is **Inferred-grade** evidence by
/// construction; the provenance note on the storage op records the
/// discriminant and the mapping. Following the `resolved_callee`
/// precedent, this is a retained slot on the consuming op: the
/// constructor `Call` binding itself is never rewritten (removing a
/// callsite would silently shrink `CallIndex` caller sets and unsound
/// the `Resolver`'s meets).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EnumKey {
    /// Enum type name from `contractspecv0` (e.g. `"DataKey"`).
    // JUSTIFY: Type names are arbitrary user-defined identifiers.
    pub enum_name: String,
    /// Variant name (e.g. `"Admin"`).
    // JUSTIFY: Variant names are arbitrary user-defined identifiers.
    pub variant: String,
    /// Caller-side SSA values stored into the variant's payload slots,
    /// in ascending slot-offset order. Empty for unit variants.
    pub payload: Vec<ValueId>,
}

/// A decoded symbol-dispatch table — the ground truth behind the SDK's
/// `#[contracttype]` enum-from-`Val` decoder.
///
/// The SDK decodes an enum by calling `symbol_index_in_linear_memory` with
/// a pointer to a rodata array of byte-slice descriptors (one per variant
/// name), then switching on the returned index. The `dispatcher` pass reads
/// that array out of linear memory and records it here.
///
/// `cases` is **witnessed** ground truth (the exact bytes rustc baked into
/// rodata), so it is always present when this table is produced — the pass
/// decodes all-or-nothing and leaves the site a plain `BufOp` if any entry
/// fails to resolve. `enum_name`, by contrast, follows the None-is-honest
/// discipline: it is filled only when exactly one `contractspecv0` union's
/// case set equals `cases`, and stays `None` for a stripped binary (no
/// spec) or an ambiguous match — never a guess.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DispatchTable {
    /// Variant names in table order. Index `i` is the value the host
    /// returns for `cases[i]`, matching the `br_table` arm order and the
    /// enum's declaration-order discriminants.
    // JUSTIFY: Variant names are arbitrary user-defined identifiers.
    pub cases: Vec<String>,
    /// Enum type name from `contractspecv0` when a unique union's case set
    /// equals `cases`; `None` when no spec, no match, or an ambiguous one.
    // JUSTIFY: Type names are arbitrary user-defined identifiers.
    pub enum_name: Option<String>,
}

/// A known contract interface a cross-contract call was matched
/// against, by callee name + argument arity (structural evidence — the
/// callee's actual code is not inspectable; the matching pass records
/// the evidence in provenance). One variant per interface the
/// decompiler knows; the Phase-3 emitter renders the matching typed
/// client (`token::Client::…`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ClientInterface {
    /// The SEP-41 token interface (CAP-46-6 / `soroban-sdk`
    /// `token::Interface`).
    Sep41Token,
}

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
        /// The raw durability operand from the original host call,
        /// retained so the constant-propagation engine can re-resolve a
        /// tier the intra-procedural recognizer left `Unknown` (the
        /// value is typically a helper-function parameter).
        durability: ValueId,
        /// Key value.
        key: ValueId,
        /// Recognized `#[contracttype]` enum-variant key
        /// (`DataKey::Admin`-class), filled by the `enum-key` pass when
        /// its evidence gate passes; `None` until proven. See
        /// [`EnumKey`].
        resolved_key: Option<EnumKey>,
    },

    /// `env.storage().<tier>().set::<_>(&key, &value)`.
    StorageSet {
        /// Which storage tier.
        tier: StorageTier,
        /// The raw durability operand from the original host call,
        /// retained so the constant-propagation engine can re-resolve a
        /// tier the intra-procedural recognizer left `Unknown` (the
        /// value is typically a helper-function parameter).
        durability: ValueId,
        /// Key value.
        key: ValueId,
        /// Recognized `#[contracttype]` enum-variant key
        /// (`DataKey::Admin`-class), filled by the `enum-key` pass when
        /// its evidence gate passes; `None` until proven. See
        /// [`EnumKey`].
        resolved_key: Option<EnumKey>,
        /// Value being stored.
        value: ValueId,
    },

    /// `env.storage().<tier>().has::<_>(&key)`.
    StorageHas {
        /// Which storage tier.
        tier: StorageTier,
        /// The raw durability operand from the original host call,
        /// retained so the constant-propagation engine can re-resolve a
        /// tier the intra-procedural recognizer left `Unknown` (the
        /// value is typically a helper-function parameter).
        durability: ValueId,
        /// Key value.
        key: ValueId,
        /// Recognized `#[contracttype]` enum-variant key
        /// (`DataKey::Admin`-class), filled by the `enum-key` pass when
        /// its evidence gate passes; `None` until proven. See
        /// [`EnumKey`].
        resolved_key: Option<EnumKey>,
    },

    /// `env.storage().<tier>().remove::<_>(&key)`.
    StorageRemove {
        /// Which storage tier.
        tier: StorageTier,
        /// The raw durability operand from the original host call,
        /// retained so the constant-propagation engine can re-resolve a
        /// tier the intra-procedural recognizer left `Unknown` (the
        /// value is typically a helper-function parameter).
        durability: ValueId,
        /// Key value.
        key: ValueId,
        /// Recognized `#[contracttype]` enum-variant key
        /// (`DataKey::Admin`-class), filled by the `enum-key` pass when
        /// its evidence gate passes; `None` until proven. See
        /// [`EnumKey`].
        resolved_key: Option<EnumKey>,
    },

    /// `env.storage().<tier>().extend_ttl(&key, threshold, extend_to)`.
    ///
    /// Host import `(l, 7)` `extend_contract_data_ttl`.
    StorageExtendTtl {
        /// Which storage tier.
        tier: StorageTier,
        /// The raw durability operand from the original host call,
        /// retained so the constant-propagation engine can re-resolve a
        /// tier the intra-procedural recognizer left `Unknown` (the
        /// value is typically a helper-function parameter).
        durability: ValueId,
        /// Key value.
        key: ValueId,
        /// Recognized `#[contracttype]` enum-variant key
        /// (`DataKey::Admin`-class), filled by the `enum-key` pass when
        /// its evidence gate passes; `None` until proven. See
        /// [`EnumKey`].
        resolved_key: Option<EnumKey>,
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
        /// The raw durability operand from the original host call,
        /// retained so the constant-propagation engine can re-resolve a
        /// tier the intra-procedural recognizer left `Unknown` (the
        /// value is typically a helper-function parameter).
        durability: ValueId,
        /// Key value.
        key: ValueId,
        /// Recognized `#[contracttype]` enum-variant key
        /// (`DataKey::Admin`-class), filled by the `enum-key` pass when
        /// its evidence gate passes; `None` until proven. See
        /// [`EnumKey`].
        resolved_key: Option<EnumKey>,
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
        /// Recovered callee function name, filled by the
        /// constant-propagation engine when `function` resolves to a
        /// symbol constant (a tag-14 `SymbolSmall` literal or a
        /// rodata-backed `SymbolNew`); `None` until proven.
        // JUSTIFY: Callee names are arbitrary contract identifiers.
        resolved_callee: Option<String>,
        /// Argument count recovered from the args-vec constructor's
        /// constant length by the `client-call` pass; `None` until
        /// proven.
        arg_count: Option<u32>,
        /// Per-element argument values recovered from the caller's
        /// frame slots, in vec order. `Some` only when EVERY element
        /// was proven (all-or-nothing — a partial list would
        /// misrepresent the call); `None` otherwise.
        resolved_args: Option<Vec<ValueId>>,
        /// Interface the call was matched against (callee name + arity
        /// against a known interface table — Inferred-grade structural
        /// evidence, recorded in provenance); `None` when no known
        /// interface fits.
        interface: Option<ClientInterface>,
        /// Argument vector.
        args: Vec<ValueId>,
    },

    /// `env.try_invoke_contract(contract, function, args)`.
    TryInvokeContract {
        /// Callee contract address.
        contract: ValueId,
        /// Function symbol.
        function: ValueId,
        /// Recovered callee function name, filled by the
        /// constant-propagation engine when `function` resolves to a
        /// symbol constant (a tag-14 `SymbolSmall` literal or a
        /// rodata-backed `SymbolNew`); `None` until proven.
        // JUSTIFY: Callee names are arbitrary contract identifiers.
        resolved_callee: Option<String>,
        /// Argument count recovered from the args-vec constructor's
        /// constant length by the `client-call` pass; `None` until
        /// proven.
        arg_count: Option<u32>,
        /// Per-element argument values recovered from the caller's
        /// frame slots, in vec order. `Some` only when EVERY element
        /// was proven (all-or-nothing — a partial list would
        /// misrepresent the call); `None` otherwise.
        resolved_args: Option<Vec<ValueId>>,
        /// Interface the call was matched against (callee name + arity
        /// against a known interface table — Inferred-grade structural
        /// evidence, recorded in provenance); `None` when no known
        /// interface fits.
        interface: Option<ClientInterface>,
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

    // ---- Crypto / PRNG / test / deploy (recognized by AbiSweepPass) ----
    /// A `c`-module (crypto) host operation.
    ///
    /// ABI-proven recognition — the host-function identity *is* the
    /// semantic — so bindings carry `Known` certainty. `kind` names the
    /// specific operation; the `(module, export) → CryptoOpKind`
    /// mapping, per-kind arity, and ABI return type live in
    /// `sordec-passes`' `val_abi` module (this enum is IR vocabulary
    /// only). Grouped under one op the same way `i`-module conversions
    /// group under [`ValObjectKind`] — the "specialization is radical"
    /// rule the whole ABI surface follows.
    CryptoOp {
        /// Which crypto operation this is.
        kind: CryptoOpKind,
        /// Operands in original host-call argument order.
        args: Vec<ValueId>,
    },

    /// A `p`-module (PRNG) host operation. Same conventions as
    /// [`CryptoOp`](KnownOp::CryptoOp).
    PrngOp {
        /// Which PRNG operation this is.
        kind: PrngOpKind,
        /// Operands in original host-call argument order.
        args: Vec<ValueId>,
    },

    /// A `t`-module (test) host operation. Same conventions as
    /// [`CryptoOp`](KnownOp::CryptoOp).
    TestOp {
        /// Which test operation this is.
        kind: TestOpKind,
        /// Operands in original host-call argument order.
        args: Vec<ValueId>,
    },

    /// An `l`-module *deploy/upgrade* host operation — the subset of the
    /// ledger module outside storage CRUD/TTL (contract creation, wasm
    /// upload/update, contract-id derivation). Same conventions as
    /// [`CryptoOp`](KnownOp::CryptoOp).
    DeployOp {
        /// Which deploy/upgrade operation this is.
        kind: DeployOpKind,
        /// Operands in original host-call argument order.
        args: Vec<ValueId>,
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

    // ---- Collections / bytes (recognized by the collections pass) ----
    /// An `m`-module (map) host operation.
    ///
    /// ABI-proven recognition — the host-function identity *is* the
    /// semantic — so bindings carry `Known` certainty. `kind` names the
    /// specific operation; the `(module, export) → MapOpKind` mapping and
    /// per-kind ABI arity / return type live in `sordec-passes`' `val_abi`
    /// module (this enum is IR vocabulary only).
    MapOp {
        /// Which map operation this is.
        kind: MapOpKind,
        /// Operands in original host-call argument order.
        args: Vec<ValueId>,
    },

    /// A `v`-module (vec) host operation. Same conventions as
    /// [`MapOp`](KnownOp::MapOp).
    VecOp {
        /// Which vec operation this is.
        kind: VecOpKind,
        /// Operands in original host-call argument order.
        args: Vec<ValueId>,
    },

    /// A `b`-module (buf: bytes / string / symbol) host operation. Same
    /// conventions as [`MapOp`](KnownOp::MapOp).
    BufOp {
        /// Which buf operation this is.
        kind: BufOpKind,
        /// Operands in original host-call argument order.
        args: Vec<ValueId>,
    },

    // ---- Enum dispatch (recognized by the dispatcher pass) ----
    /// `(b, m) symbol_index_in_linear_memory`, refined by the `dispatcher`
    /// pass into the SDK's `#[contracttype]` enum-from-`Val` decoder.
    ///
    /// The pass reads the rodata slice-descriptor table this call switches
    /// on and records the ordered variant list in [`DispatchTable`]
    /// (`SdkPattern` evidence, `Known` certainty by construction — the
    /// variant names are witnessed rodata bytes). A `BufOp` of this kind is
    /// rewritten into `SymbolDispatch` only when the table decodes
    /// all-or-nothing; otherwise it honestly stays a `BufOp`. The operand
    /// `sym`/`table_pos`/`len` fields preserve the original host-call
    /// arguments (nothing is discarded). Returns the matched variant index
    /// (`Known(U32)`, unchanged from the `BufOp` result type).
    ///
    /// Recovering the actual `match` arms from the surrounding `br_table`
    /// is control-flow structuring (Phase 3); this op names the enum and
    /// records the index→variant map only.
    SymbolDispatch {
        /// The `Symbol` being looked up (original argument 0).
        sym: ValueId,
        /// Linear-memory position of the slice-descriptor table (argument 1).
        table_pos: ValueId,
        /// Number of descriptors in the table (argument 2).
        len: ValueId,
        /// The decoded variant list and, when resolvable, the enum name.
        table: DispatchTable,
    },
}

/// The complete `i`-module (`int`) host-side Val conversion surface.
///
/// One variant per conversion host function, covering the full ABI (the
/// same "specialization is radical" rule as the 192-entry host-call
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

/// The complete `m`-module (map) host-operation surface, excluding
/// `map_new_from_linear_memory` `(m, 9)` — that constructor is the
/// linear-memory recognizer's [`KnownOp::MapNew`].
///
/// One variant per host function, each documented with its
/// `(module, export)` import pair from `soroban-env-common 26.1.2`'s
/// `env.json`. Grouped under a single [`KnownOp::MapOp`] the same way
/// `i`-module conversions group under [`ValObjectKind`]. The
/// `(module, export) → MapOpKind` mapping, per-kind arity, and ABI return
/// type live in `sordec-passes`' `val_abi` module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum MapOpKind {
    /// `(m, _)` `map_new` — empty map.
    New,
    /// `(m, 0)` `map_put` — insert/update a key; returns the new map.
    Put,
    /// `(m, 1)` `map_get` — value for a key (traps if absent).
    Get,
    /// `(m, 2)` `map_del` — remove a key; returns the new map.
    Del,
    /// `(m, 3)` `map_len` — entry count.
    Len,
    /// `(m, 4)` `map_has` — key-presence test.
    Has,
    /// `(m, 5)` `map_key_by_pos` — key at a position.
    KeyByPos,
    /// `(m, 6)` `map_val_by_pos` — value at a position.
    ValByPos,
    /// `(m, 7)` `map_keys` — all keys as a vec.
    Keys,
    /// `(m, 8)` `map_values` — all values as a vec.
    Values,
    /// `(m, a)` `map_unpack_to_linear_memory` — write the map's keys and
    /// values into two linear-memory `Val` arrays.
    UnpackToLinearMemory,
}

/// The complete `v`-module (vec) host-operation surface, excluding
/// `vec_new_from_linear_memory` `(v, g)` — the linear-memory recognizer's
/// [`KnownOp::VecNew`]. Same conventions as [`MapOpKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum VecOpKind {
    /// `(v, _)` `vec_new` — empty vec.
    New,
    /// `(v, 0)` `vec_put` — replace the element at an index.
    Put,
    /// `(v, 1)` `vec_get` — element at an index.
    Get,
    /// `(v, 2)` `vec_del` — remove the element at an index.
    Del,
    /// `(v, 3)` `vec_len` — element count.
    Len,
    /// `(v, 4)` `vec_push_front` — prepend an element.
    PushFront,
    /// `(v, 5)` `vec_pop_front` — drop the first element.
    PopFront,
    /// `(v, 6)` `vec_push_back` — append an element.
    PushBack,
    /// `(v, 7)` `vec_pop_back` — drop the last element.
    PopBack,
    /// `(v, 8)` `vec_front` — first element.
    Front,
    /// `(v, 9)` `vec_back` — last element.
    Back,
    /// `(v, a)` `vec_insert` — insert an element at an index.
    Insert,
    /// `(v, b)` `vec_append` — concatenate two vecs.
    Append,
    /// `(v, c)` `vec_slice` — sub-vec over `[start, end)`.
    Slice,
    /// `(v, d)` `vec_first_index_of` — first index of an element, or Void.
    FirstIndexOf,
    /// `(v, e)` `vec_last_index_of` — last index of an element, or Void.
    LastIndexOf,
    /// `(v, f)` `vec_binary_search` — binary search over a sorted vec.
    /// Returns a raw `u64` (not a `Val`): high bit = found flag, low bits
    /// = index.
    BinarySearch,
    /// `(v, h)` `vec_unpack_to_linear_memory` — write the vec's elements
    /// into a linear-memory `Val` array.
    UnpackToLinearMemory,
}

/// The complete `b`-module (buf: bytes / string / symbol) host-operation
/// surface, excluding the three `*_new_from_linear_memory` constructors
/// `(b, 3)` / `(b, i)` / `(b, j)` — the linear-memory recognizer's
/// [`KnownOp::BytesNew`] / [`KnownOp::StringNew`] / [`KnownOp::SymbolNew`].
/// Same conventions as [`MapOpKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum BufOpKind {
    /// `(b, _)` `serialize_to_bytes` — XDR-serialize any `Val`.
    SerializeToBytes,
    /// `(b, 0)` `deserialize_from_bytes` — XDR-deserialize to a `Val`.
    DeserializeFromBytes,
    /// `(b, 1)` `bytes_copy_to_linear_memory` — copy a bytes slice out to
    /// linear memory.
    BytesCopyToLinearMemory,
    /// `(b, 2)` `bytes_copy_from_linear_memory` — overwrite a bytes range
    /// from linear memory; returns the new bytes.
    BytesCopyFromLinearMemory,
    /// `(b, 4)` `bytes_new` — empty bytes. Named `BytesNewEmpty` to keep
    /// it distinct from the linear-memory constructor
    /// [`KnownOp::BytesNew`].
    BytesNewEmpty,
    /// `(b, 5)` `bytes_put` — replace the byte at an index.
    BytesPut,
    /// `(b, 6)` `bytes_get` — byte at an index.
    BytesGet,
    /// `(b, 7)` `bytes_del` — remove the byte at an index.
    BytesDel,
    /// `(b, 8)` `bytes_len` — byte count.
    BytesLen,
    /// `(b, 9)` `bytes_push` — append a byte.
    BytesPush,
    /// `(b, a)` `bytes_pop` — drop the last byte.
    BytesPop,
    /// `(b, b)` `bytes_front` — first byte.
    BytesFront,
    /// `(b, c)` `bytes_back` — last byte.
    BytesBack,
    /// `(b, d)` `bytes_insert` — insert a byte at an index.
    BytesInsert,
    /// `(b, e)` `bytes_append` — concatenate two bytes objects.
    BytesAppend,
    /// `(b, f)` `bytes_slice` — sub-bytes over `[start, end)`.
    BytesSlice,
    /// `(b, g)` `string_copy_to_linear_memory` — copy a string slice out
    /// to linear memory.
    StringCopyToLinearMemory,
    /// `(b, h)` `symbol_copy_to_linear_memory` — copy a symbol slice out
    /// to linear memory.
    SymbolCopyToLinearMemory,
    /// `(b, k)` `string_len` — string byte count.
    StringLen,
    /// `(b, l)` `symbol_len` — symbol byte count.
    SymbolLen,
    /// `(b, m)` `symbol_index_in_linear_memory` — index of a `Symbol`
    /// (bare `Symbol` arg, small or object form) within a linear-memory
    /// table of byte-slice descriptors; the SDK's symbol-dispatch helper.
    SymbolIndexInLinearMemory,
    /// `(b, n)` `string_to_bytes` — reinterpret a string as bytes
    /// (protocol 23+).
    StringToBytes,
    /// `(b, o)` `bytes_to_string` — reinterpret bytes as a string
    /// (protocol 23+).
    BytesToString,
}

/// The complete `c`-module (crypto) host-operation surface — hashing,
/// signature verification / recovery, and the BLS12-381 / BN254 /
/// Poseidon curve and field arithmetic. One variant per host function,
/// each documented with its `(module, export)` pair from
/// `soroban-env-common 26.1.2`'s `env.json`. Grouped under a single
/// [`KnownOp::CryptoOp`]; the `(module, export) → CryptoOpKind`
/// mapping, per-kind arity, and ABI return type live in
/// `sordec-passes`' `val_abi` module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum CryptoOpKind {
    /// `(c, _)` `compute_hash_sha256`.
    ComputeHashSha256,
    /// `(c, 0)` `verify_sig_ed25519`.
    VerifySigEd25519,
    /// `(c, 1)` `compute_hash_keccak256`.
    ComputeHashKeccak256,
    /// `(c, 2)` `recover_key_ecdsa_secp256k1`.
    RecoverKeyEcdsaSecp256k1,
    /// `(c, 3)` `verify_sig_ecdsa_secp256r1`.
    VerifySigEcdsaSecp256r1,
    /// `(c, 4)` `bls12_381_check_g1_is_in_subgroup`.
    Bls12381CheckG1IsInSubgroup,
    /// `(c, 5)` `bls12_381_g1_add`.
    Bls12381G1Add,
    /// `(c, 6)` `bls12_381_g1_mul`.
    Bls12381G1Mul,
    /// `(c, 7)` `bls12_381_g1_msm`.
    Bls12381G1Msm,
    /// `(c, 8)` `bls12_381_map_fp_to_g1`.
    Bls12381MapFpToG1,
    /// `(c, 9)` `bls12_381_hash_to_g1`.
    Bls12381HashToG1,
    /// `(c, a)` `bls12_381_check_g2_is_in_subgroup`.
    Bls12381CheckG2IsInSubgroup,
    /// `(c, b)` `bls12_381_g2_add`.
    Bls12381G2Add,
    /// `(c, c)` `bls12_381_g2_mul`.
    Bls12381G2Mul,
    /// `(c, d)` `bls12_381_g2_msm`.
    Bls12381G2Msm,
    /// `(c, e)` `bls12_381_map_fp2_to_g2`.
    Bls12381MapFp2ToG2,
    /// `(c, f)` `bls12_381_hash_to_g2`.
    Bls12381HashToG2,
    /// `(c, g)` `bls12_381_multi_pairing_check`.
    Bls12381MultiPairingCheck,
    /// `(c, h)` `bls12_381_fr_add`.
    Bls12381FrAdd,
    /// `(c, i)` `bls12_381_fr_sub`.
    Bls12381FrSub,
    /// `(c, j)` `bls12_381_fr_mul`.
    Bls12381FrMul,
    /// `(c, k)` `bls12_381_fr_pow`.
    Bls12381FrPow,
    /// `(c, l)` `bls12_381_fr_inv`.
    Bls12381FrInv,
    /// `(c, m)` `bn254_g1_add`.
    Bn254G1Add,
    /// `(c, n)` `bn254_g1_mul`.
    Bn254G1Mul,
    /// `(c, o)` `bn254_multi_pairing_check`.
    Bn254MultiPairingCheck,
    /// `(c, p)` `poseidon_permutation`.
    PoseidonPermutation,
    /// `(c, q)` `poseidon2_permutation`.
    Poseidon2Permutation,
    /// `(c, r)` `bn254_g1_msm`.
    Bn254G1Msm,
    /// `(c, s)` `bn254_fr_add`.
    Bn254FrAdd,
    /// `(c, t)` `bn254_fr_sub`.
    Bn254FrSub,
    /// `(c, u)` `bn254_fr_mul`.
    Bn254FrMul,
    /// `(c, v)` `bn254_fr_pow`.
    Bn254FrPow,
    /// `(c, w)` `bn254_fr_inv`.
    Bn254FrInv,
    /// `(c, x)` `bls12_381_g1_is_on_curve`.
    Bls12381G1IsOnCurve,
    /// `(c, y)` `bls12_381_g2_is_on_curve`.
    Bls12381G2IsOnCurve,
    /// `(c, z)` `bn254_g1_is_on_curve`.
    Bn254G1IsOnCurve,
}

/// The complete `p`-module (PRNG) host-operation surface. Same
/// conventions as [`CryptoOpKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum PrngOpKind {
    /// `(p, _)` `prng_reseed` — reseed the PRNG from a bytes value.
    PrngReseed,
    /// `(p, 0)` `prng_bytes_new` — a fresh `Bytes` of a given length.
    PrngBytesNew,
    /// `(p, 1)` `prng_u64_in_inclusive_range` — a `u64` in `[lo, hi]`.
    PrngU64InInclusiveRange,
    /// `(p, 2)` `prng_vec_shuffle` — a shuffled copy of a vec.
    PrngVecShuffle,
}

/// The complete `t`-module (test) host-operation surface — internal
/// dummy functions the host exposes for testing. Same conventions as
/// [`CryptoOpKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum TestOpKind {
    /// `(t, _)` `dummy0`.
    Dummy0,
    /// `(t, 0)` `protocol_gated_dummy`.
    ProtocolGatedDummy,
}

/// The `l`-module *deploy/upgrade* surface — the ledger exports outside
/// storage CRUD/TTL (which are [`KnownOp::StorageGet`] et al. and the
/// TTL ops). One variant per host function, each documented with its
/// `(module, export)` pair. Same conventions as [`CryptoOpKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum DeployOpKind {
    /// `(l, 3)` `create_contract` — deploy from a wasm hash + salt.
    CreateContract,
    /// `(l, 4)` `create_asset_contract` — deploy a Stellar Asset
    /// Contract from a serialized asset.
    CreateAssetContract,
    /// `(l, 5)` `upload_wasm` — upload wasm, returning its hash.
    UploadWasm,
    /// `(l, 6)` `update_current_contract_wasm` — hot-swap the executing
    /// contract's wasm.
    UpdateCurrentContractWasm,
    /// `(l, a)` `get_contract_id` — derive a contract id from deployer +
    /// salt.
    GetContractId,
    /// `(l, b)` `get_asset_contract_id` — derive a SAC id from a
    /// serialized asset.
    GetAssetContractId,
    /// `(l, e)` `create_contract_with_constructor` — deploy with
    /// constructor arguments (protocol 22+).
    CreateContractWithConstructor,
}
