//! The `compiler_builtins` memory routines, named by fingerprint.
//!
//! # What these are
//!
//! rustc lowers `core::ptr::copy_nonoverlapping`, `core::ptr::copy` and
//! `core::ptr::write_bytes` — and every struct move or zeroing it emits
//! itself — to LLVM's `llvm.memcpy`, `llvm.memmove` and `llvm.memset`, and a
//! byte-slice comparison to `memcmp`/`bcmp`. On `wasm32v1-none` (and on
//! `wasm32-unknown-unknown` whenever the backend keeps the call), those
//! become calls to the C symbols, and the linker resolves them to the bodies in the toolchain's own
//! `libcompiler_builtins` rlib. A contract therefore carries a 500-instruction
//! byte loop for a line the source never wrote, and the decompiler printed
//! it as 57 holes, nine times over in the measured sets.
//!
//! # Why a fingerprint match proves the routine
//!
//! The entries below are not inferred from contracts. They are read from the
//! toolchains' own rlibs: `ar x` the archive, and `siggen builtins` on its
//! members prints each function's [`crate::fingerprint`] together with the
//! name the object's `linking` section gives it — the linker's own symbol
//! table, so the label is the toolchain's, not ours.
//!
//! A body matching an entry is that routine for three reasons:
//!
//! 1. **The fingerprint is the body.** It hashes every instruction verbatim
//!    except callee and global indices. These routines are leaves — no
//!    calls — so the only masked operand is the one `global.get` that
//!    `memcpy`/`memmove` use to address the `usize` scratch their unaligned
//!    path keeps in its own frame (`let mut out = 0usize` in
//!    `load_aligned_partial`); `memset` and `memcmp` have none. Everything else —
//!    every constant, offset, width, branch and the order of all of them —
//!    is the rlib's, byte for byte.
//! 2. **Linking does not change these bodies.** `compiler_builtins` is never
//!    part of LTO, and a leaf with no data references carries no relocation
//!    except that global. Measured, not assumed: all 19 copies in the
//!    measured sets (9 `memcpy`, 5 `memset`, 5 `memcmp`, built by rustc
//!    1.95.0 and 1.98.1) print, with call and global indices masked,
//!    exactly as the same toolchain's rlib member does.
//! 3. **No other code has these fingerprints.** None of them is in the
//!    SDK [`crate::catalogue`] (a unit test pins it), and the routine
//!    bodies are not generic — one monomorphic body per toolchain, which is
//!    why several toolchains share one entry.
//!
//! The caller still has to hold the masked global to the stack pointer and
//! the parameter count to three (all four routines take three); the fingerprint covers the instruction
//! stream, not the function type. That is the decompiler's gate, not this
//! table's: see the acting pass in `sordec-passes`.
//!
//! # What is deliberately absent
//!
//! - **The `extern "C"` symbols.** In 1.89 and later, `memcpy` is a
//!   five-instruction forwarder to the mangled body; its one call is masked
//!   and it carries no identity of its own. The body it forwards to is what
//!   is listed.
//!
//! `memcmp` and `bcmp` are one body in every toolchain read (`bcmp` is
//! `memcmp`), listed once as [`MemRoutine::Memcmp`]. Like `memset` it has
//! no masked operand at all, so a match is the rlib's body byte for byte.
//!
//! # Regenerating
//!
//! ```text
//! mkdir objs && cd objs
//! ar x ~/.rustup/toolchains/<tc>/lib/rustlib/wasm32v1-none/lib/libcompiler_builtins-*.rlib
//! cargo run -p sordec-sigs --bin siggen -- builtins *.o | grep -E ' (memcpy|memmove|memset|memcmp|bcmp)'
//! ```
//!
//! Toolchains read: 1.87, 1.89, 1.91, 1.95.0, 1.97 and 1.98.1, both
//! wasm32 targets where installed (they agree).

use crate::fingerprint::Fingerprint;

/// Which memory routine a body is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemRoutine {
    /// `memcpy(dest, src, n) -> dest`: copies `n` bytes forward; the
    /// regions must not overlap.
    Memcpy,
    /// `memmove(dest, src, n) -> dest`: copies `n` bytes as if through a
    /// temporary; the regions may overlap.
    Memmove,
    /// `memset(s, c, n) -> s`: writes `c as u8` to `n` bytes.
    Memset,
    /// `memcmp(s1, s2, n) -> c_int` (and `bcmp`, the same body): the
    /// difference of the first unequal bytes as unsigned, or 0.
    Memcmp,
}

impl MemRoutine {
    /// The C symbol the routine is linked under.
    #[must_use]
    pub const fn symbol(self) -> &'static str {
        match self {
            Self::Memcpy => "memcpy",
            Self::Memmove => "memmove",
            Self::Memset => "memset",
            Self::Memcmp => "memcmp",
        }
    }
}

/// One fingerprinted routine body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuiltinEntry {
    /// The masked structural fingerprint of the body.
    pub fingerprint: Fingerprint,
    /// What the body is.
    pub routine: MemRoutine,
    /// The toolchains whose rlib holds this exact body.
    pub toolchains: &'static str,
}

/// The routines, sorted by fingerprint.
pub static MEM_ROUTINES: &[BuiltinEntry] = &[
    BuiltinEntry {
        fingerprint: Fingerprint(0x0fe5_f4a8_a7ee_444d_f0b2_30bb_4afa_0863),
        routine: MemRoutine::Memcpy,
        toolchains: "1.89, 1.91",
    },
    BuiltinEntry {
        fingerprint: Fingerprint(0x2075_b56e_3fcd_589c_6929_b6b8_c9ba_3aa3),
        routine: MemRoutine::Memmove,
        toolchains: "1.91",
    },
    BuiltinEntry {
        fingerprint: Fingerprint(0x209a_6994_da31_9372_f17d_e54a_0f69_d66b),
        routine: MemRoutine::Memmove,
        toolchains: "1.89",
    },
    BuiltinEntry {
        fingerprint: Fingerprint(0x2437_4e70_2994_f1f5_55e5_2b94_8748_9b17),
        routine: MemRoutine::Memmove,
        toolchains: "1.98.1",
    },
    BuiltinEntry {
        fingerprint: Fingerprint(0x449b_63a9_1dc0_8fce_3ecd_bfd2_baa3_40f9),
        routine: MemRoutine::Memset,
        toolchains: "1.87, 1.89, 1.91, 1.95.0, 1.97, 1.98.1",
    },
    BuiltinEntry {
        fingerprint: Fingerprint(0x543c_b0a5_a2f4_859b_9e2b_21bc_8533_98f9),
        routine: MemRoutine::Memcpy,
        toolchains: "1.95.0, 1.97",
    },
    BuiltinEntry {
        fingerprint: Fingerprint(0x7809_ea8e_3d62_e913_ac0d_c92c_2f95_d968),
        routine: MemRoutine::Memcpy,
        toolchains: "1.98.1",
    },
    BuiltinEntry {
        fingerprint: Fingerprint(0x89cc_96e9_f838_0781_85d8_6cb0_5645_8a99),
        routine: MemRoutine::Memcmp,
        toolchains: "1.87, 1.89, 1.91, 1.95.0, 1.97, 1.98.1",
    },
    BuiltinEntry {
        fingerprint: Fingerprint(0xad28_58a2_664a_6947_f28a_f05f_bebf_ed47),
        routine: MemRoutine::Memcpy,
        toolchains: "1.87",
    },
    BuiltinEntry {
        fingerprint: Fingerprint(0xefce_ea98_43a6_4696_9205_a4a7_3cda_ee81),
        routine: MemRoutine::Memmove,
        toolchains: "1.95.0, 1.97",
    },
    BuiltinEntry {
        fingerprint: Fingerprint(0xfc7d_ee3c_2d3e_5e17_4e26_67fc_3d84_3d8e),
        routine: MemRoutine::Memmove,
        toolchains: "1.87",
    },
];

/// The routine a body with this fingerprint is, if any.
#[must_use]
pub fn mem_routine(fingerprint: Fingerprint) -> Option<&'static BuiltinEntry> {
    MEM_ROUTINES
        .binary_search_by(|e| e.fingerprint.cmp(&fingerprint))
        .ok()
        .and_then(|i| MEM_ROUTINES.get(i))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_is_sorted_and_free_of_duplicates() {
        assert!(MEM_ROUTINES.windows(2).all(|w| w[0].fingerprint < w[1].fingerprint));
    }

    #[test]
    fn every_entry_resolves_to_itself() {
        for e in MEM_ROUTINES {
            assert_eq!(mem_routine(e.fingerprint), Some(e));
        }
    }

    #[test]
    fn an_unlisted_fingerprint_is_nothing() {
        assert_eq!(mem_routine(Fingerprint(0xdead_beef)), None);
    }

    /// A body the SDK catalogue names must never also be a memory routine:
    /// the two tables decide different rewrites, and a shared key would
    /// leave the answer to whichever pass runs first.
    #[test]
    fn no_routine_shares_a_fingerprint_with_the_sdk_catalogue() {
        let sdk = crate::shipped_catalogue();
        for e in MEM_ROUTINES {
            assert!(sdk.lookup(e.fingerprint).is_none(), "{:?} is also in the SDK catalogue", e.routine);
        }
    }
}
