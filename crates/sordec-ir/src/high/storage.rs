//! Storage tier classification for `env.storage()` operations.
//!
//! Soroban contracts have three storage tiers (persistent, temporary,
//! instance) selected by the `durability` argument to host calls. The
//! legacy decompiler hardcoded `.persistent()` everywhere — this type is
//! the foundation of the Phase 2 pass that fixes that bug by tracing the
//! durability argument back to its constant source.

use sordec_common::UnknownReason;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Which storage tier a `storage::*` operation targets, with certainty.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum StorageTier {
    /// Tier was proved from data flow (durability arg traced to a constant).
    Known(KnownTier),
    /// Tier is the best guess from analysis (e.g. surrounding context).
    Inferred(KnownTier),
    /// Tier could not be determined (e.g. durability arg is itself a
    /// runtime value); explanation in the [`UnknownReason`].
    Unknown(UnknownReason),
}

/// One of the three Soroban storage tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum KnownTier {
    /// Persistent storage: long-lived, paid by rent, survives reboots.
    Persistent,
    /// Temporary storage: cheaper, expires automatically.
    Temporary,
    /// Instance storage: bundled with the contract instance, paid as part
    /// of contract upload.
    Instance,
}
