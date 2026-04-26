//! Soroban-aware types for the high IR.
//!
//! [`IrType`] tracks both *what* a value is and *how confident* we are.
//! Certainty is encoded structurally in the variants
//! ([`Known`](IrType::Known) / [`Inferred`](IrType::Inferred) /
//! [`Unknown`](IrType::Unknown)), not as a separate field. See
//! `docs/architecture.md` §1.

use sordec_common::{TypeId, UnknownReason};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Type of a high-IR binding, with explicit certainty.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum IrType {
    /// Type was proved (e.g. directly from `contractspecv0`, or by
    /// matching a host-function ABI signature).
    Known(KnownType),
    /// Type is the best inference from analysis but not provably correct.
    Inferred(KnownType),
    /// Type could not be determined; the [`UnknownReason`] explains why.
    Unknown(UnknownReason),
}

/// Concrete Soroban type when the IR layer has identified one.
///
/// Unlike [`crate::PrimitiveType`] (which mirrors `stellar-xdr` entries),
/// this is the *Soroban semantic* type the decompiled Rust will name. The
/// composite variants nest [`IrType`] (not just [`KnownType`]) because
/// even inside a `Vec`, the element type may itself be partly unknown
/// — and that uncertainty must propagate to the user.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum KnownType {
    // ---- Primitives ----
    /// Soroban `bool`.
    Bool,
    /// Unit (`()`).
    Unit,
    /// Soroban `u32`.
    U32,
    /// Soroban `i32`.
    I32,
    /// Soroban `u64`.
    U64,
    /// Soroban `i64`.
    I64,
    /// Soroban `u128`.
    U128,
    /// Soroban `i128`.
    I128,
    /// Soroban `u256`.
    U256,
    /// Soroban `i256`.
    I256,
    /// Soroban `Symbol` (short ASCII).
    Symbol,
    /// Variable-length `String`.
    String,
    /// Variable-length `Bytes`.
    Bytes,
    /// Fixed-length byte array `BytesN<N>`.
    BytesN(u32),
    /// Account or contract `Address`.
    Address,
    /// `MuxedAddress`.
    MuxedAddress,
    /// `Timepoint` (u64 seconds).
    Timepoint,
    /// `Duration` (u64 seconds).
    Duration,
    /// Soroban error code.
    Error,
    /// Generic Soroban tagged value. Used when we know the value is a
    /// `Val` but cannot determine which concrete type it tags.
    Val,

    // ---- Composites (may carry inner uncertainty) ----
    /// `Option<T>`.
    Option(Box<IrType>),
    /// `Result<T, E>`.
    Result(Box<IrType>, Box<IrType>),
    /// `Vec<T>`.
    Vec(Box<IrType>),
    /// `Map<K, V>`.
    Map(Box<IrType>, Box<IrType>),
    /// Heterogeneous tuple.
    Tuple(Vec<IrType>),

    // ---- User-defined ----
    /// Named contract type (struct/union/enum/error/event) by id into
    /// [`crate::TypeRegistry`].
    UserDefined(TypeId),
}
