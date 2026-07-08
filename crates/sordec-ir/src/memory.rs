//! Module-level constant memory image: the WASM active data segments.
//!
//! Soroban guests bake compile-time constants — symbol names, string and
//! byte literals, `(pointer, length)` descriptor tables — into the WASM
//! **data section**, then hand the host a `(position, length)` pair into
//! linear memory (`symbol_new_from_linear_memory`, `bytes_new_from_linear_memory`,
//! …). Recovering those literals therefore requires the initialized-memory
//! bytes, which is what this type carries.
//!
//! [`MemoryImage`] is a **lift-time artifact**: `waffle` parses the active
//! data segments and resolves each segment's constant offset expression to
//! a plain byte offset, which the lifter captures here. It rides
//! [`crate::LiftedIr`] → [`crate::HighIr`] as module-level state (parallel
//! to `facts`), so a `Pass<HighIr>` recognizer can resolve a traced
//! `(pointer, length)` back to bytes via `sordec-passes`' `trace_bytes`.
//!
//! ## Scope
//!
//! Only **active** segments are modeled — `waffle` drops passive segments,
//! and Soroban emits its rodata as active segments, so this covers the
//! `(ptr, len)` → bytes use case. Segments are stored in module order;
//! [`MemoryImage::read`] honors overlay semantics (a later segment
//! overwrites an earlier one at the same offset) by searching last-first.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// One active WASM data segment: the constant bytes and the linear-memory
/// byte offset they initialize (offset already resolved from the segment's
/// constant offset expression by the lifter).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DataSegment {
    /// Byte offset in linear memory where `bytes` begins.
    pub offset: u32,
    /// The initialized bytes.
    pub bytes: Vec<u8>,
}

/// The initialized linear-memory image of a module: all active data
/// segments, in module order.
///
/// Empty for modules with no data section (e.g. `hello-add`). Query it
/// with [`read`](MemoryImage::read).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MemoryImage {
    segments: Vec<DataSegment>,
}

impl MemoryImage {
    /// An image with no segments (modules without a data section).
    #[inline]
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Build an image from active segments (in module order).
    #[inline]
    #[must_use]
    pub fn from_segments(segments: Vec<DataSegment>) -> Self {
        Self { segments }
    }

    /// Whether the image carries no segments.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    /// The active segments, in module order.
    #[inline]
    #[must_use]
    pub fn segments(&self) -> &[DataSegment] {
        &self.segments
    }

    /// The bytes of `[ptr, ptr + len)` if a single active segment fully
    /// covers that range; otherwise `None` (uninitialized memory, a read
    /// straddling two segments, or out of range).
    ///
    /// Segments are searched **last-first** so a later overlay at the same
    /// offset wins — matching how the WASM runtime applies them. All
    /// arithmetic is widened to `u64`, so `u32` position/length inputs can
    /// never overflow the bounds computation.
    #[must_use]
    pub fn read(&self, ptr: u32, len: u32) -> Option<&[u8]> {
        let ptr = u64::from(ptr);
        let end = ptr + u64::from(len); // both u32-widened; cannot overflow u64
        for seg in self.segments.iter().rev() {
            let seg_start = u64::from(seg.offset);
            let seg_end = seg_start + seg.bytes.len() as u64;
            if seg_start <= ptr && end <= seg_end {
                let lo = (ptr - seg_start) as usize;
                let hi = lo + len as usize;
                return Some(&seg.bytes[lo..hi]);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A segment `[100, 105)` holding "hello".
    fn image() -> MemoryImage {
        MemoryImage::from_segments(vec![DataSegment {
            offset: 100,
            bytes: b"hello".to_vec(),
        }])
    }

    #[test]
    fn read_full_segment() {
        assert_eq!(image().read(100, 5), Some(&b"hello"[..]));
    }

    #[test]
    fn read_interior_slice() {
        // "ell" at offset 101, len 3.
        assert_eq!(image().read(101, 3), Some(&b"ell"[..]));
    }

    #[test]
    fn read_zero_length_within_segment_is_empty() {
        assert_eq!(image().read(102, 0), Some(&b""[..]));
    }

    #[test]
    fn read_overrunning_end_returns_none() {
        // Starts inside but runs one byte past the segment end.
        assert_eq!(image().read(103, 3), None);
    }

    #[test]
    fn read_before_any_segment_returns_none() {
        assert_eq!(image().read(0, 1), None);
    }

    #[test]
    fn read_out_of_range_returns_none() {
        assert_eq!(image().read(1_000, 1), None);
    }

    #[test]
    fn empty_image_reads_none() {
        assert!(MemoryImage::empty().is_empty());
        assert_eq!(MemoryImage::empty().read(0, 0), None);
    }

    #[test]
    fn later_overlay_wins() {
        // Two segments at the same offset; the later one overlays.
        let img = MemoryImage::from_segments(vec![
            DataSegment {
                offset: 10,
                bytes: b"AAAA".to_vec(),
            },
            DataSegment {
                offset: 10,
                bytes: b"BBBB".to_vec(),
            },
        ]);
        assert_eq!(img.read(10, 4), Some(&b"BBBB"[..]));
    }

    #[test]
    fn read_at_high_offset_does_not_overflow() {
        // Offset near u32::MAX with a small length: bounds math is u64, so
        // this must not panic and must correctly miss (no covering segment).
        assert_eq!(image().read(u32::MAX, 4), None);
    }
}
