//! Typed arena storage keyed by [`IrId`] newtypes.
//!
//! [`Arena<I, T>`] is a thin newtype around [`Vec<T>`] with two important
//! properties:
//!
//! - **Typed access.** Lookups are by an [`IrId`] (e.g. [`crate::ValueId`]).
//!   The arena's key type prevents indexing one arena with another's ID at
//!   compile time.
//! - **Append-only semantics.** [`Arena::push`] is the only way to add an
//!   item. There is no [`remove`](Vec::remove) operation: IRs we build are
//!   monotonic, so recycling slots would only invite use-after-free style
//!   bugs (the legacy tools that deal with deletion use `slotmap`-style
//!   generation counters; we deliberately do without).
//!
//! Implementing the arena ourselves rather than depending on `cranelift-entity`
//! or `slotmap` is justified: the API surface is ~30 lines of code, and the
//! third-party crates' extra features (recycling, generations, secondary
//! maps) are explicitly *not* what we want.
//!
//! ## Example
//!
//! ```
//! use sordec_common::{Arena, ValueId};
//!
//! let mut arena: Arena<ValueId, &'static str> = Arena::new();
//! let a = arena.push("hello");
//! let b = arena.push("world");
//!
//! assert_eq!(arena.len(), 2);
//! assert_eq!(arena.get(a), Some(&"hello"));
//! assert_eq!(arena.get(b), Some(&"world"));
//! ```

use core::marker::PhantomData;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::IrId;

/// Append-only typed storage keyed by an [`IrId`] newtype.
///
/// See the [module documentation](self) for design rationale.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Arena<I: IrId, T> {
    items: Vec<T>,
    #[cfg_attr(feature = "serde", serde(skip))]
    _id: PhantomData<fn() -> I>,
}

impl<I: IrId, T> Default for Arena<I, T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<I: IrId, T> Arena<I, T> {
    /// Create an empty arena.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            items: Vec::new(),
            _id: PhantomData,
        }
    }

    /// Allocate space for `capacity` items up front, avoiding reallocation
    /// for the first `capacity` [`push`](Self::push) calls.
    #[inline]
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            items: Vec::with_capacity(capacity),
            _id: PhantomData,
        }
    }

    /// Append `item` and return its newly-allocated identifier.
    ///
    /// Identifiers are allocated densely from `0`, so the returned ID also
    /// equals `arena.len() - 1` after this call.
    ///
    /// In debug builds, panics if pushing this item would overflow [`u32`];
    /// in practice no realistic decompilation produces 4 billion of any one
    /// IR object so this assertion exists purely to surface bugs early.
    #[inline]
    pub fn push(&mut self, item: T) -> I {
        debug_assert!(
            self.items.len() < u32::MAX as usize,
            "Arena<{}, _>: capacity overflow at u32::MAX entries",
            core::any::type_name::<I>()
        );
        let idx = self.items.len() as u32;
        self.items.push(item);
        I::from_index(idx)
    }

    /// Return the item with identifier `id`, or `None` if `id` is out of bounds.
    ///
    /// In debug builds an out-of-bounds lookup also fires a `debug_assert!`
    /// before returning `None`. This makes ID-leak bugs (e.g. passing a
    /// foreign function's [`crate::BlockId`] to this arena) loud during
    /// development while still degrading gracefully in release.
    #[inline]
    #[must_use]
    pub fn get(&self, id: I) -> Option<&T> {
        let idx = id.index() as usize;
        debug_assert!(
            idx < self.items.len(),
            "Arena<{}, _>::get: id {} out of bounds (len {})",
            core::any::type_name::<I>(),
            idx,
            self.items.len()
        );
        self.items.get(idx)
    }

    /// Mutable counterpart to [`get`](Self::get).
    #[inline]
    #[must_use]
    pub fn get_mut(&mut self, id: I) -> Option<&mut T> {
        let idx = id.index() as usize;
        debug_assert!(
            idx < self.items.len(),
            "Arena<{}, _>::get_mut: id {} out of bounds (len {})",
            core::any::type_name::<I>(),
            idx,
            self.items.len()
        );
        self.items.get_mut(idx)
    }

    /// Number of items in the arena.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the arena is empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Iterate over `(id, &item)` pairs in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (I, &T)> + '_ {
        self.items
            .iter()
            .enumerate()
            .map(|(idx, item)| (I::from_index(idx as u32), item))
    }

    /// Iterate over `(id, &mut item)` pairs in insertion order.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (I, &mut T)> + '_ {
        self.items
            .iter_mut()
            .enumerate()
            .map(|(idx, item)| (I::from_index(idx as u32), item))
    }

    /// Iterate over the identifiers in insertion order without yielding the items.
    pub fn ids(&self) -> impl Iterator<Item = I> + '_ {
        (0..self.items.len() as u32).map(I::from_index)
    }

    /// Iterate over the values directly, dropping identifiers.
    pub fn values(&self) -> impl Iterator<Item = &T> + '_ {
        self.items.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BlockId, ValueId};

    #[test]
    fn empty_arena_is_empty() {
        let arena: Arena<ValueId, u32> = Arena::new();
        assert_eq!(arena.len(), 0);
        assert!(arena.is_empty());
    }

    #[test]
    fn push_returns_dense_ids() {
        let mut arena: Arena<ValueId, &'static str> = Arena::new();
        let a = arena.push("alpha");
        let b = arena.push("beta");
        let c = arena.push("gamma");
        assert_eq!(a, ValueId::new(0));
        assert_eq!(b, ValueId::new(1));
        assert_eq!(c, ValueId::new(2));
    }

    #[test]
    fn get_round_trip() {
        let mut arena: Arena<BlockId, u32> = Arena::new();
        let mut ids = Vec::new();
        for i in 0..1000u32 {
            ids.push(arena.push(i * 7));
        }
        for (i, id) in ids.into_iter().enumerate() {
            assert_eq!(arena.get(id).copied(), Some(i as u32 * 7));
        }
    }

    #[test]
    fn get_mut_modifies_in_place() {
        let mut arena: Arena<ValueId, u32> = Arena::new();
        let id = arena.push(10);
        *arena.get_mut(id).unwrap() = 99;
        assert_eq!(arena.get(id).copied(), Some(99));
    }

    #[test]
    fn iter_yields_ids_in_insertion_order() {
        let mut arena: Arena<ValueId, char> = Arena::new();
        arena.push('a');
        arena.push('b');
        arena.push('c');

        let collected: Vec<(ValueId, char)> =
            arena.iter().map(|(id, ch)| (id, *ch)).collect();

        assert_eq!(
            collected,
            vec![
                (ValueId::new(0), 'a'),
                (ValueId::new(1), 'b'),
                (ValueId::new(2), 'c'),
            ]
        );
    }
}
