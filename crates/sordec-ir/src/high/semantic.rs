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
}
