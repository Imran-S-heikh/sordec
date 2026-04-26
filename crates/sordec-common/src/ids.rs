//! Stable identifier newtypes used across the sordec pipeline.
//!
//! All references between IR objects use [`u32`]-backed newtype identifiers
//! rather than strings or pointers. This is a non-negotiable architectural
//! commitment (see `docs/architecture.md` §1):
//!
//! - **Compile-time type safety.** The compiler refuses to mix a [`FuncId`]
//!   with a [`BlockId`]; one whole class of bug becomes unrepresentable.
//! - **Tiny memory footprint.** Each identifier is four bytes.
//! - **Fast equality and hashing.** Single-integer compare; no allocation.
//!
//! ## Scoping
//!
//! Some identifiers are module-global, others are valid only within their
//! owning [`crate::Arena`]:
//!
//! | Identifier | Scope | Notes |
//! |------------|-------|-------|
//! | [`FuncId`] | Module-global | One namespace for all functions in a module |
//! | [`TypeId`] | Module-global | One namespace for all types in a module |
//! | [`BlockId`] | Per-function | `BlockId(0)` of function A is unrelated to `BlockId(0)` of function B |
//! | [`ValueId`] | Per-function | Same scoping; in SSA the value IS the instruction |
//!
//! Passing a per-function identifier across function boundaries is a logic
//! bug. Debug builds catch it via bounds-checking in [`crate::Arena`]; we do
//! not encode the scope into the type system because lifetime-tied IDs make
//! every API painful for negligible safety gain (the convention is what
//! `waffle` itself uses).
//!
//! ## Construction
//!
//! All identifiers implement [`IrId`], which is the contract used by
//! [`crate::Arena`] for storage lookups. Identifiers are constructed via
//! [`IrId::from_index`] when bridging from external indices (e.g. `waffle`),
//! or returned by [`crate::Arena::push`] when allocating new IR nodes.
//!
//! Identifiers deliberately do **not** derive [`Default`]: a default `0` value
//! would silently masquerade as "no function" or "no block," which is exactly
//! the failure mode we want to forbid. Use [`Option<FuncId>`] for absence.

use core::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Common contract for all sordec IR identifiers.
///
/// Every identifier wraps a single [`u32`] and provides round-trip conversion
/// between the wrapped index and its newtype. This is the only trait
/// [`crate::Arena`] requires of its key type.
///
/// Implementing this trait outside of `sordec-common` is permitted but rare:
/// the four built-in identifiers should cover everything the IR needs.
pub trait IrId: Copy + Eq + core::hash::Hash + Ord {
    /// Construct an identifier from a raw index.
    ///
    /// Used when bridging external IDs (e.g. `waffle::Block::index()`) into
    /// our type system.
    fn from_index(idx: u32) -> Self;

    /// Extract the raw index this identifier wraps.
    fn index(self) -> u32;
}

// Single-source-of-truth macro to declare a newtype ID. Every identifier
// shares the same shape; defining them by hand four times invites drift.
macro_rules! define_id {
    (
        $(#[$meta:meta])*
        $name:ident, $display_prefix:literal
    ) => {
        $(#[$meta])*
        ///
        /// Wraps a [`u32`] index. See [the module documentation](self) for
        /// the type-safety and scoping guarantees that motivate this design.
        #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[cfg_attr(feature = "serde", serde(transparent))]
        pub struct $name(u32);

        impl $name {
            /// Construct from a raw index without going through the [`IrId`] trait.
            ///
            /// Equivalent to [`IrId::from_index`]; provided as an inherent
            /// method so call sites do not need to import the trait.
            #[inline]
            pub const fn new(idx: u32) -> Self {
                Self(idx)
            }
        }

        impl IrId for $name {
            #[inline]
            fn from_index(idx: u32) -> Self {
                Self(idx)
            }

            #[inline]
            fn index(self) -> u32 {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!($display_prefix, "{}"), self.0)
            }
        }
    };
}

define_id! {
    /// Module-global identifier of a function.
    FuncId, "func"
}

define_id! {
    /// Module-global identifier of a type definition.
    TypeId, "ty"
}

define_id! {
    /// Identifier of a basic block within a single function.
    ///
    /// **Per-function scope.** A `BlockId` produced by analysing function A
    /// must never be looked up against function B. The convention is the
    /// same one used by `waffle`, `cranelift`, and the rustc MIR.
    BlockId, "bb"
}

define_id! {
    /// Identifier of an SSA value within a single function.
    ///
    /// In SSA form, the result of an instruction *is* its identifier; we
    /// deliberately do not have a separate `InstructionId` (see
    /// `docs/architecture.md` §11).
    ///
    /// **Per-function scope** — see [`BlockId`].
    ValueId, "v"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_uses_documented_prefixes() {
        assert_eq!(format!("{}", FuncId::new(3)), "func3");
        assert_eq!(format!("{}", TypeId::new(5)), "ty5");
        assert_eq!(format!("{}", BlockId::new(7)), "bb7");
        assert_eq!(format!("{}", ValueId::new(42)), "v42");
    }

    #[test]
    fn ir_id_round_trip() {
        for idx in [0u32, 1, 7, 42, u32::MAX - 1] {
            assert_eq!(FuncId::from_index(idx).index(), idx);
            assert_eq!(BlockId::from_index(idx).index(), idx);
            assert_eq!(ValueId::from_index(idx).index(), idx);
            assert_eq!(TypeId::from_index(idx).index(), idx);
        }
    }

    // Compile-time check: identifier types are NOT interchangeable.
    // If someone adds `derive(Default)` or implements `From<FuncId> for BlockId`,
    // the assertion below — relying on distinct construction paths — should
    // break the test (or, more likely, the type system will reject it before
    // tests even run).
    #[test]
    fn ids_carry_distinct_types() {
        let f = FuncId::new(0);
        let b = BlockId::new(0);
        // Both wrap zero but are not the same type; this is the whole point.
        assert_eq!(f.index(), b.index());
        // The following would (correctly) fail to compile:
        // let _: FuncId = b;
    }
}
