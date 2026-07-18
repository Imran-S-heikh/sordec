//! Effect/trap classification: what may each operation do?
//!
//! Code motion is the currency of Phase 3 — cleanup passes copy-propagate
//! and delete, treeification folds single-use bindings into consumers,
//! and control-flow refinement sinks or duplicates bindings across region
//! boundaries. None of that is sound without knowing what each operation
//! may observe or disturb. This module is the single source of truth:
//! an [`Effects`] vector per operation, over three state families
//! (guest linear memory, guest globals, mutable host state) plus traps.
//!
//! The project rule this module implements (Phase-3 kickoff, K4):
//! **nothing in a Soroban module is safely movable by default** — only
//! pure-total bindings move; everything else pins ordering.
//!
//! ## Sources of classification
//!
//! - **WASM operators** delegate to waffle's per-operator effect
//!   metadata ([`waffle::Operator::effects`]) — fine-grained enough to
//!   split trapping `i32.div_s` from pure `i32.add`. waffle reports
//!   `Call`/`CallIndirect` as "all effects" because it cannot know what
//!   a Soroban host import does; that boundary is exactly where…
//! - **…the host-call table** takes over: a hand-audited row for every
//!   one of the 192 vendored host functions
//!   ([`crate::host_calls::CATALOG_VERSION`]), with per-row reasoning
//!   comments on every non-obvious judgment.
//! - **Recognized semantic ops** ([`KnownOp`]) classify exhaustively —
//!   no wildcard arm, so a new variant forces a conscious row here.
//!
//! ## The two normative judgments (cited by rows below)
//!
//! 1. **Budget/metering traps are excluded from `may_trap` by
//!    definition.** Every host call (and every guest instruction)
//!    consumes budget; if exhaustion counted as a trap, nothing would be
//!    pure-total and the table would gate nothing. `may_trap` means
//!    *semantic* traps only: tag mismatch, out-of-bounds, div-by-zero,
//!    overflow, missing storage entry, explicit fail.
//! 2. **Soroban host objects are immutable** (`map_put` returns a *new*
//!    map; nothing mutates an existing handle), so reading an object's
//!    contents is NOT a `reads_host` effect — no operation can change
//!    what a held handle refers to. `reads_host`/`writes_host` are
//!    reserved for *mutable* host state: contract storage and TTLs, the
//!    auth tree, the event stream, PRNG state, deployed-code state.
//!
//! ## Fail-closed boundaries
//!
//! [`SemanticOp::Unknown`] classifies as [`Effects::WORST`] even though
//! its `(module, name)` strings could be looked up in the catalog: an
//! unclaimed host call is outside the recognition trust boundary, and
//! the store-forwarding discipline this module absorbed (see
//! [`crate::dataflow::frame_facts`]) has always failed closed there.
//! Revisit if a consumer measurably suffers — after `abi-sweep` the
//! remaining `Unknown`s on real corpora are a handful of sites.
//! Likewise [`Expr::Call`]/[`Expr::IndirectCall`] (intra-module callee
//! summaries are future work) and unrecognized operator kinds.
//!
//! ## Future relaxation (documented, deliberately not implemented)
//!
//! Soroban traps roll back the entire invocation, so "write before
//! trap" is arguably unobservable on-chain, and finer host axes (PRNG
//! vs. storage) would let more host pairs commute. Both relaxations
//! only pay off together and interact with `try_call` frames and
//! diagnostic events — parked until a refinement pass demonstrably
//! needs them. [`Effects::commutes_with`] is conservative until then.

use sordec_ir::{
    AddressOpKind, BufOpKind, CryptoOpKind, DeployOpKind, Expr, KnownOp, MapOpKind, PrngOpKind,
    SemanticOp, TestOpKind, ValObjectKind, VecOpKind, WasmOpcodeKind,
};
use waffle::SideEffect;

/// May-effect vector for one operation.
///
/// Every flag is a *may* over-approximation: setting a flag is always
/// sound; clearing one is a proof obligation (documented at the
/// classification site). `may_trap` excludes budget/metering exhaustion
/// — see the module docs' normative judgment #1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Effects {
    /// May abort the invocation with a semantic trap (tag mismatch,
    /// OOB, div-by-zero, overflow, missing entry, explicit fail).
    pub may_trap: bool,
    /// May read guest linear memory (WASM tables folded in — a sound
    /// over-approximation; rustc-emitted Soroban modules use tables only
    /// for `call_indirect` plumbing, which classifies WORST anyway).
    pub reads_memory: bool,
    /// May write guest linear memory (or tables; see `reads_memory`).
    pub writes_memory: bool,
    /// May read a guest WASM global (the shadow-stack pointer).
    pub reads_globals: bool,
    /// May write a guest WASM global.
    pub writes_globals: bool,
    /// May read *mutable* host state: contract storage/TTLs, auth tree,
    /// PRNG stream. Immutable host-object reads do NOT set this — see
    /// the module docs' normative judgment #2.
    pub reads_host: bool,
    /// May write mutable host state: storage/TTLs, auth consumption,
    /// event emission, PRNG advancement, deploys, cross-contract calls.
    pub writes_host: bool,
}

impl Effects {
    /// No effects at all: freely movable, duplicable, and deletable
    /// (modulo SSA data dependence and structural anchors — see
    /// [`expr_effects`]).
    pub const PURE: Effects = Effects {
        may_trap: false,
        reads_memory: false,
        writes_memory: false,
        reads_globals: false,
        writes_globals: false,
        reads_host: false,
        writes_host: false,
    };

    /// Every effect: the honest answer for anything unclassified.
    pub const WORST: Effects = Effects {
        may_trap: true,
        reads_memory: true,
        writes_memory: true,
        reads_globals: true,
        writes_globals: true,
        reads_host: true,
        writes_host: true,
    };

    /// Per-axis OR — the effect of executing both operations (in either
    /// order). Use to summarize ranges of bindings.
    #[must_use]
    pub const fn join(self, other: Effects) -> Effects {
        Effects {
            may_trap: self.may_trap || other.may_trap,
            reads_memory: self.reads_memory || other.reads_memory,
            writes_memory: self.writes_memory || other.writes_memory,
            reads_globals: self.reads_globals || other.reads_globals,
            writes_globals: self.writes_globals || other.writes_globals,
            reads_host: self.reads_host || other.reads_host,
            writes_host: self.writes_host || other.writes_host,
        }
    }

    /// True when no flag is set — K4's gate for unrestricted motion.
    #[must_use]
    pub const fn is_pure_total(self) -> bool {
        !(self.may_trap
            || self.reads_memory
            || self.writes_memory
            || self.reads_globals
            || self.writes_globals
            || self.reads_host
            || self.writes_host)
    }

    /// True when any write axis is set.
    #[must_use]
    pub const fn may_write(self) -> bool {
        self.writes_memory || self.writes_globals || self.writes_host
    }

    /// Effect-legality of swapping two *adjacent, data-independent*
    /// operations. Symmetric. Callers must separately enforce SSA data
    /// dependence and structural anchors (phis, block params).
    ///
    /// Pinned (returns `false`) when:
    /// 1. **both may trap** — *which* error a failing run returns is
    ///    consensus-observable, so trap order is semantics (hard rule,
    ///    not conservatism);
    /// 2. **trap vs. write** in either direction — conservative; see
    ///    the module docs' rollback-relaxation note;
    /// 3. **same-family read/write conflict** over {memory, globals,
    ///    host}.
    ///
    /// Consequences: pure-total commutes with everything; a trap-only
    /// op commutes with pure reads; effectively only pure-total moves
    /// past host ops — exactly K4, with headroom.
    #[must_use]
    pub const fn commutes_with(self, other: Effects) -> bool {
        if self.may_trap && other.may_trap {
            return false;
        }
        if (self.may_trap && other.may_write()) || (other.may_trap && self.may_write()) {
            return false;
        }
        // Per-family read/write conflicts.
        let memory = (self.writes_memory && (other.reads_memory || other.writes_memory))
            || (other.writes_memory && self.reads_memory);
        let globals = (self.writes_globals && (other.reads_globals || other.writes_globals))
            || (other.writes_globals && self.reads_globals);
        let host = (self.writes_host && (other.reads_host || other.writes_host))
            || (other.writes_host && self.reads_host);
        !(memory || globals || host)
    }

    /// Lossy summary in the kickoff's four-class vocabulary, for display
    /// and metrics only — motion decisions must use the predicates.
    /// Precedence: writes > trap > reads > pure.
    #[must_use]
    pub const fn class(self) -> EffectClass {
        if self.may_write() {
            EffectClass::Effectful
        } else if self.may_trap {
            EffectClass::Trapping
        } else if self.reads_memory || self.reads_globals || self.reads_host {
            EffectClass::ReadOnly
        } else {
            EffectClass::PureTotal
        }
    }
}

/// Display/metrics summary of an [`Effects`] vector (lossy — see
/// [`Effects::class`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EffectClass {
    /// No observable effect; freely movable.
    PureTotal,
    /// Reads some state family but writes nothing and cannot trap.
    ReadOnly,
    /// Writes some state family.
    Effectful,
    /// Cannot write, but may abort with a semantic trap.
    Trapping,
}

// ---------------------------------------------------------------------
// WASM operators (delegated to waffle)
// ---------------------------------------------------------------------

/// Effects of a raw WASM operator, via waffle's per-operator metadata.
///
/// `Call`/`CallIndirect` report [`Effects::WORST`] — waffle cannot know
/// host-import semantics; resolve the import and use
/// [`host_call_effects`] instead where possible.
#[must_use]
pub fn wasm_operator_effects(op: &waffle::Operator) -> Effects {
    let mut effects = Effects::PURE;
    for side_effect in op.effects() {
        // Exhaustive on purpose: `SideEffect` is not `#[non_exhaustive]`,
        // so a waffle upgrade that adds a variant fails loudly here
        // instead of silently under-classifying.
        match side_effect {
            SideEffect::Trap => effects.may_trap = true,
            SideEffect::ReadMem => effects.reads_memory = true,
            SideEffect::WriteMem => effects.writes_memory = true,
            SideEffect::ReadGlobal => effects.reads_globals = true,
            SideEffect::WriteGlobal => effects.writes_globals = true,
            // Tables fold into the memory axes (field docs on
            // `Effects::reads_memory` explain why that is sound).
            SideEffect::ReadTable => effects.reads_memory = true,
            SideEffect::WriteTable => effects.writes_memory = true,
            // Locals cannot occur: waffle's SSA `Operator` has no
            // local-op variants (the frontend resolves locals during SSA
            // construction). WORST-not-panic so a future waffle that
            // adds them degrades conservatively.
            SideEffect::ReadLocal | SideEffect::WriteLocal => return Effects::WORST,
            SideEffect::All => return Effects::WORST,
        }
    }
    effects
}

/// Coarse fallback for [`Expr::Unknown`], keyed by the preserved
/// [`WasmOpcodeKind`]. Fail-closed: kinds erase detail (`Arithmetic`
/// merges trapping div into pure add, `Conversion` merges trapping
/// truncations into pure extensions), so mixed kinds take the worst of
/// their members, and anything uncategorized is [`Effects::WORST`].
#[must_use]
pub fn opcode_kind_effects(kind: WasmOpcodeKind) -> Effects {
    const TRAP: Effects = Effects {
        may_trap: true,
        ..Effects::PURE
    };
    match kind {
        WasmOpcodeKind::Const
        | WasmOpcodeKind::Bitwise
        | WasmOpcodeKind::Comparison
        | WasmOpcodeKind::Unary
        | WasmOpcodeKind::Select
        | WasmOpcodeKind::Nop => Effects::PURE,
        // Arithmetic includes div/rem; Conversion includes the trapping
        // float→int truncations.
        WasmOpcodeKind::Arithmetic | WasmOpcodeKind::Conversion | WasmOpcodeKind::Unreachable => {
            TRAP
        }
        WasmOpcodeKind::Load => Effects {
            may_trap: true,
            reads_memory: true,
            ..Effects::PURE
        },
        WasmOpcodeKind::Store => Effects {
            may_trap: true,
            writes_memory: true,
            ..Effects::PURE
        },
        // memory.size reads; grow/copy/fill write (and trap) — the kind
        // merges them, so take the union.
        WasmOpcodeKind::MemoryOp => Effects {
            may_trap: true,
            reads_memory: true,
            writes_memory: true,
            ..Effects::PURE
        },
        WasmOpcodeKind::GlobalGet => Effects {
            reads_globals: true,
            ..Effects::PURE
        },
        WasmOpcodeKind::GlobalSet => Effects {
            writes_globals: true,
            ..Effects::PURE
        },
        WasmOpcodeKind::Call | WasmOpcodeKind::CallIndirect | WasmOpcodeKind::Other => {
            Effects::WORST
        }
        // `WasmOpcodeKind` is #[non_exhaustive] (foreign enum): future
        // kinds fail closed rather than guessing.
        _ => Effects::WORST,
    }
}

// ---------------------------------------------------------------------
// Host calls: the 192-row audited table
// ---------------------------------------------------------------------

/// Effects of a Soroban host function, by `(module, name)` import pair.
///
/// Covers the entire vendored catalog (a completeness test iterates
/// [`crate::host_calls::all`]); `None` means the pair is not a vendored
/// host function — callers treat that as [`Effects::WORST`].
#[must_use]
pub fn host_call_effects(module: &str, name: &str) -> Option<Effects> {
    match module {
        "x" => context_effects(name),
        "i" => int_effects(name),
        "l" => ledger_effects(name),
        "d" => call_effects(name),
        "a" => address_effects(name),
        "m" => map_effects(name),
        "v" => vec_effects(name),
        "b" => buf_effects(name),
        "c" => crate::val_abi::crypto_fn_kind(module, name).map(crypto_kind_effects),
        "p" => crate::val_abi::prng_fn_kind(module, name).map(prng_kind_effects),
        "t" => crate::val_abi::test_fn_kind(module, name).map(test_kind_effects),
        _ => None,
    }
}

/// Shorthand rows used throughout the table.
const TRAP: Effects = Effects {
    may_trap: true,
    ..Effects::PURE
};
const TRAP_READ_HOST: Effects = Effects {
    may_trap: true,
    reads_host: true,
    ..Effects::PURE
};
const TRAP_WRITE_HOST: Effects = Effects {
    may_trap: true,
    writes_host: true,
    ..Effects::PURE
};
const TRAP_RW_HOST: Effects = Effects {
    may_trap: true,
    reads_host: true,
    writes_host: true,
    ..Effects::PURE
};
const TRAP_READ_MEM: Effects = Effects {
    may_trap: true,
    reads_memory: true,
    ..Effects::PURE
};
const TRAP_WRITE_MEM: Effects = Effects {
    may_trap: true,
    writes_memory: true,
    ..Effects::PURE
};

/// `x` (context) module, 10 functions.
fn context_effects(name: &str) -> Option<Effects> {
    Some(match name {
        // log_from_linear_memory: reads the message/vals slices out of
        // guest memory and emits a diagnostic event. Diagnostic events
        // are non-consensus, but they are host output — classified as a
        // host write conservatively.
        "_" => Effects {
            may_trap: true,
            reads_memory: true,
            writes_host: true,
            ..Effects::PURE
        },
        // obj_cmp: structural comparison of two Vals; traps on invalid
        // Val bit-patterns.
        "0" => TRAP,
        // contract_event: appends to the event stream.
        "1" => TRAP_WRITE_HOST,
        // Invocation-constant context reads: fixed for the whole
        // invocation, nothing mid-invocation can change them, raw
        // results, no semantic trap → PURE (module docs, judgment #2
        // does not even apply — these are immutable within the frame).
        "2" | "3" | "4" | "6" | "7" | "8" => Effects::PURE,
        // fail_with_error: the explicit-trap host call.
        "5" => TRAP,
        _ => return None,
    })
}

/// `i` (int) module, 52 functions.
fn int_effects(name: &str) -> Option<Effects> {
    Some(match name {
        // Object constructors from RAW integers: no Val argument to
        // tag-validate, allocation of an immutable object → PURE.
        // (obj_from_u64/i64, u128/i128/u256/i256 pieces, timepoint,
        // duration.)
        "_" | "1" | "3" | "6" | "9" | "g" | "D" | "F" => Effects::PURE,
        // Everything else takes a Val/object argument and tag-validates
        // it (obj_to_* family, be-bytes conversions) or traps on
        // overflow/div-by-zero (u256/i256 arithmetic; the checked_*
        // variants still tag-validate their U256Val arguments).
        "0" | "2" | "4" | "5" | "7" | "8" | "a" | "b" | "c" | "d" | "e" | "f" | "h" | "i"
        | "j" | "k" | "l" | "m" | "n" | "o" | "p" | "q" | "r" | "s" | "t" | "u" | "v" | "w"
        | "x" | "y" | "z" | "A" | "B" | "C" | "E" | "G" | "H" | "I" | "J" | "K" | "L" | "M"
        | "N" | "O" => TRAP,
        _ => return None,
    })
}

/// `l` (ledger) module, 18 functions: storage CRUD + TTL + deploys.
fn ledger_effects(name: &str) -> Option<Effects> {
    Some(match name {
        // put/del write storage; get/has read it (get traps on missing).
        "_" | "2" => TRAP_WRITE_HOST,
        "0" | "1" => TRAP_READ_HOST,
        // TTL extensions read the current TTL and write the new one.
        "7" | "8" | "9" | "c" | "d" | "f" | "g" => TRAP_RW_HOST,
        // Deploys/uploads mutate deployed-code state (and read it for
        // existence checks). create_contract_with_constructor ("e")
        // additionally runs the constructor — a cross-contract call —
        // but the callee cannot touch OUR guest memory/globals, so the
        // axes stay host-only (same reasoning as the `d` module).
        "3" | "4" | "5" | "6" | "e" => TRAP_RW_HOST,
        // Contract-id derivations: deterministic hashing, no state.
        "a" | "b" => TRAP,
        _ => return None,
    })
}

/// `d` (call) module, 2 functions.
fn call_effects(name: &str) -> Option<Effects> {
    Some(match name {
        // The callee executes in its OWN instance: it can do anything to
        // host state but cannot touch the caller's linear memory or
        // globals — deliberately NOT `WORST` (and the store-forwarding
        // discipline absorbed from frame_facts depends on exactly this).
        // try_call ("0") keeps may_trap: it converts recoverable
        // contract errors, but internal host errors still abort.
        "_" | "0" => TRAP_RW_HOST,
        _ => return None,
    })
}

/// `a` (address) module, 10 functions.
fn address_effects(name: &str) -> Option<Effects> {
    Some(match name {
        // require_auth / require_auth_for_args / authorize_as_curr:
        // consume auth-tree entries and nonces — host read + write, trap
        // on auth failure.
        "_" | "0" | "3" => TRAP_RW_HOST,
        // Pure conversions/queries over immutable inputs; trap on
        // malformed strkeys / wrong object types (judgment #2: reading
        // object contents is not a host read).
        "1" | "2" | "4" | "5" | "6" | "7" | "8" => TRAP,
        _ => return None,
    })
}

/// `m` (map) module, 12 functions.
fn map_effects(name: &str) -> Option<Effects> {
    // map_new_from_linear_memory reads the parallel key/val arrays out
    // of guest memory; excluded from `MapOpKind` (linear-memory
    // recognizer's op), so row it here.
    if name == "9" {
        return Some(TRAP_READ_MEM);
    }
    crate::val_abi::map_fn_kind("m", name).map(map_kind_effects)
}

/// `v` (vec) module, 19 functions.
fn vec_effects(name: &str) -> Option<Effects> {
    // vec_new_from_linear_memory reads the Val array out of guest
    // memory; excluded from `VecOpKind`, so rowed here.
    if name == "g" {
        return Some(TRAP_READ_MEM);
    }
    crate::val_abi::vec_fn_kind("v", name).map(vec_kind_effects)
}

/// `b` (buf) module, 26 functions.
fn buf_effects(name: &str) -> Option<Effects> {
    // bytes/string/symbol_new_from_linear_memory read their contents out
    // of guest memory; excluded from `BufOpKind`, so rowed here.
    if matches!(name, "3" | "i" | "j") {
        return Some(TRAP_READ_MEM);
    }
    crate::val_abi::buf_fn_kind("b", name).map(buf_kind_effects)
}

// ---------------------------------------------------------------------
// Per-kind classifications (shared by the host table and `KnownOp`)
// ---------------------------------------------------------------------

/// Effects of a map operation.
fn map_kind_effects(kind: MapOpKind) -> Effects {
    match kind {
        // Allocation of an empty immutable map: nothing to validate.
        MapOpKind::New => Effects::PURE,
        // Writes the unpacked Vals into guest memory.
        MapOpKind::UnpackToLinearMemory => TRAP_WRITE_MEM,
        // Object-argument ops: tag-validate the handle; get/del/key/val
        // additionally trap on missing keys / out-of-range positions.
        // Reading map contents is not a host read (judgment #2).
        MapOpKind::Put
        | MapOpKind::Get
        | MapOpKind::Del
        | MapOpKind::Len
        | MapOpKind::Has
        | MapOpKind::KeyByPos
        | MapOpKind::ValByPos
        | MapOpKind::Keys
        | MapOpKind::Values => TRAP,
    }
}

/// Effects of a vec operation.
fn vec_kind_effects(kind: VecOpKind) -> Effects {
    match kind {
        // Allocation of an empty immutable vec: nothing to validate.
        VecOpKind::New => Effects::PURE,
        // Writes the unpacked Vals into guest memory.
        VecOpKind::UnpackToLinearMemory => TRAP_WRITE_MEM,
        // Object-argument ops: tag-validation + OOB traps. Reading vec
        // contents is not a host read (judgment #2).
        VecOpKind::Put
        | VecOpKind::Get
        | VecOpKind::Del
        | VecOpKind::Len
        | VecOpKind::PushFront
        | VecOpKind::PopFront
        | VecOpKind::PushBack
        | VecOpKind::PopBack
        | VecOpKind::Front
        | VecOpKind::Back
        | VecOpKind::Insert
        | VecOpKind::Append
        | VecOpKind::Slice
        | VecOpKind::FirstIndexOf
        | VecOpKind::LastIndexOf
        | VecOpKind::BinarySearch => TRAP,
    }
}

/// Effects of a buf (bytes/string/symbol) operation.
fn buf_kind_effects(kind: BufOpKind) -> Effects {
    match kind {
        // Allocation of an empty immutable byte array.
        BufOpKind::BytesNewEmpty => Effects::PURE,
        // Copy object contents INTO guest linear memory.
        BufOpKind::BytesCopyToLinearMemory
        | BufOpKind::StringCopyToLinearMemory
        | BufOpKind::SymbolCopyToLinearMemory => TRAP_WRITE_MEM,
        // Read guest linear memory (building/searching from a slice).
        BufOpKind::BytesCopyFromLinearMemory | BufOpKind::SymbolIndexInLinearMemory => {
            TRAP_READ_MEM
        }
        // Object-argument ops: tag-validation + OOB/format traps.
        BufOpKind::SerializeToBytes
        | BufOpKind::DeserializeFromBytes
        | BufOpKind::BytesPut
        | BufOpKind::BytesGet
        | BufOpKind::BytesDel
        | BufOpKind::BytesLen
        | BufOpKind::BytesPush
        | BufOpKind::BytesPop
        | BufOpKind::BytesFront
        | BufOpKind::BytesBack
        | BufOpKind::BytesInsert
        | BufOpKind::BytesAppend
        | BufOpKind::BytesSlice
        | BufOpKind::StringLen
        | BufOpKind::SymbolLen
        | BufOpKind::StringToBytes
        | BufOpKind::BytesToString => TRAP,
    }
}

/// Effects of a crypto operation: pure computation over immutable
/// inputs; every one traps on malformed input (bad point encodings,
/// wrong lengths, failed signature verification).
fn crypto_kind_effects(_kind: CryptoOpKind) -> Effects {
    TRAP
}

/// Effects of a PRNG operation: the PRNG stream is mutable host state.
fn prng_kind_effects(kind: PrngOpKind) -> Effects {
    match kind {
        // Reseed replaces the stream state (write; does not observe it).
        PrngOpKind::PrngReseed => TRAP_WRITE_HOST,
        // Generators observe AND advance the stream.
        PrngOpKind::PrngBytesNew
        | PrngOpKind::PrngU64InInclusiveRange
        | PrngOpKind::PrngVecShuffle => TRAP_RW_HOST,
    }
}

/// Effects of a test-module operation: host test internals, never
/// emitted by real contracts — not worth auditing, fail closed.
fn test_kind_effects(_kind: TestOpKind) -> Effects {
    Effects::WORST
}

/// Effects of a deploy/upgrade operation.
fn deploy_kind_effects(kind: DeployOpKind) -> Effects {
    match kind {
        // Mutate deployed-code / instance state.
        DeployOpKind::CreateContract
        | DeployOpKind::CreateAssetContract
        | DeployOpKind::UploadWasm
        | DeployOpKind::UpdateCurrentContractWasm
        | DeployOpKind::CreateContractWithConstructor => TRAP_RW_HOST,
        // Deterministic id derivations: hashing only.
        DeployOpKind::GetContractId | DeployOpKind::GetAssetContractId => TRAP,
    }
}

/// Effects of an `i`-module Val conversion.
fn val_object_kind_effects(kind: ValObjectKind) -> Effects {
    match kind {
        // Constructors from raw integers: PURE (see `int_effects`).
        ValObjectKind::ObjFromU64
        | ValObjectKind::ObjFromI64
        | ValObjectKind::ObjFromU128Pieces
        | ValObjectKind::ObjFromI128Pieces
        | ValObjectKind::ObjFromU256Pieces
        | ValObjectKind::ObjFromI256Pieces
        | ValObjectKind::TimepointObjFromU64
        | ValObjectKind::DurationObjFromU64 => Effects::PURE,
        // Extractors and byte-conversions tag-validate their argument.
        ValObjectKind::ObjToU64
        | ValObjectKind::ObjToI64
        | ValObjectKind::ObjToU128Lo64
        | ValObjectKind::ObjToU128Hi64
        | ValObjectKind::ObjToI128Lo64
        | ValObjectKind::ObjToI128Hi64
        | ValObjectKind::U256ValFromBeBytes
        | ValObjectKind::U256ValToBeBytes
        | ValObjectKind::ObjToU256HiHi
        | ValObjectKind::ObjToU256HiLo
        | ValObjectKind::ObjToU256LoHi
        | ValObjectKind::ObjToU256LoLo
        | ValObjectKind::I256ValFromBeBytes
        | ValObjectKind::I256ValToBeBytes
        | ValObjectKind::ObjToI256HiHi
        | ValObjectKind::ObjToI256HiLo
        | ValObjectKind::ObjToI256LoHi
        | ValObjectKind::ObjToI256LoLo
        | ValObjectKind::TimepointObjToU64
        | ValObjectKind::DurationObjToU64 => TRAP,
    }
}

/// Effects of an address conversion/query: pure over immutable inputs,
/// trap on malformed strkeys or wrong object types.
fn address_kind_effects(_kind: AddressOpKind) -> Effects {
    TRAP
}

// ---------------------------------------------------------------------
// Recognized semantic ops
// ---------------------------------------------------------------------

/// Effects of a recognized semantic operation.
///
/// Exhaustive — no wildcard arm. A new [`KnownOp`] variant fails to
/// compile until it gets a conscious row here (the same INVARIANT the
/// absorbed `frame_facts::known_op_writes_memory` carried: a variant
/// whose host function touches guest memory must say so).
#[must_use]
pub fn known_op_effects(op: &KnownOp) -> Effects {
    match op {
        // Storage CRUD (l._/0/1/2).
        KnownOp::StorageGet { .. } | KnownOp::StorageHas { .. } => TRAP_READ_HOST,
        KnownOp::StorageSet { .. } | KnownOp::StorageRemove { .. } => TRAP_WRITE_HOST,
        // TTL extensions (l.7/8/9/c/d/f/g): read + write TTL state.
        KnownOp::StorageExtendTtl { .. }
        | KnownOp::ExtendCurrentContractInstanceAndCodeTtl { .. }
        | KnownOp::ExtendContractInstanceAndCodeTtl { .. }
        | KnownOp::ExtendContractInstanceTtl { .. }
        | KnownOp::ExtendContractCodeTtl { .. }
        | KnownOp::StorageExtendTtlV2 { .. }
        | KnownOp::ExtendContractInstanceAndCodeTtlV2 { .. } => TRAP_RW_HOST,
        // Auth (a._/0/3).
        KnownOp::RequireAuth { .. }
        | KnownOp::RequireAuthForArgs { .. }
        | KnownOp::AuthorizeAsCurrContract { .. } => TRAP_RW_HOST,
        KnownOp::AddressConversion { kind, .. } => address_kind_effects(*kind),
        // Cross-contract (d._/0): callee cannot touch caller guest
        // memory — host axes only (see `call_effects`).
        KnownOp::InvokeContract { .. } | KnownOp::TryInvokeContract { .. } => TRAP_RW_HOST,
        // Events (x.1).
        KnownOp::PublishEvent { .. } => TRAP_WRITE_HOST,
        // Invocation-constant context reads (x.2/3/4/6/7/8).
        KnownOp::GetCurrentContractAddress
        | KnownOp::GetLedgerSequence
        | KnownOp::GetLedgerTimestamp
        | KnownOp::GetLedgerProtocolVersion
        | KnownOp::GetLedgerNetworkId
        | KnownOp::GetMaxLiveUntilLedger => Effects::PURE,
        // obj_cmp (x.0) / fail_with_error (x.5).
        KnownOp::ValCompare { .. } => TRAP,
        KnownOp::PanicWithError { .. } => TRAP,
        // Grouped ABI families.
        KnownOp::CryptoOp { kind, .. } => crypto_kind_effects(*kind),
        KnownOp::PrngOp { kind, .. } => prng_kind_effects(*kind),
        KnownOp::TestOp { kind, .. } => test_kind_effects(*kind),
        KnownOp::DeployOp { kind, .. } => deploy_kind_effects(*kind),
        KnownOp::MapOp { kind, .. } => map_kind_effects(*kind),
        KnownOp::VecOp { kind, .. } => vec_kind_effects(*kind),
        KnownOp::BufOp { kind, .. } => buf_kind_effects(*kind),
        KnownOp::ValObject { kind, .. } => val_object_kind_effects(*kind),
        // Guest-side bit-twiddling: recognized from inline shifts/masks,
        // no host interaction at all.
        KnownOp::ValEncodeSmall { .. }
        | KnownOp::ValDecodeSmall { .. }
        | KnownOp::ValTagCheck { .. } => Effects::PURE,
        // Linear-memory constructors (b.j/i/3, v.g, m.9) read guest
        // memory; SymbolDispatch is the recognized (b.m) lookup.
        KnownOp::SymbolNew { .. }
        | KnownOp::StringNew { .. }
        | KnownOp::BytesNew { .. }
        | KnownOp::VecNew { .. }
        | KnownOp::MapNew { .. }
        | KnownOp::SymbolDispatch { .. } => TRAP_READ_MEM,
    }
}

// ---------------------------------------------------------------------
// High-IR expressions
// ---------------------------------------------------------------------

/// Effects of one high-IR expression.
///
/// **Pure ≠ structurally movable**: [`Expr::Phi`] and [`Expr::Use`] are
/// pure-total here but schedule-anchored (a phi is a block parameter);
/// motion passes must gate on structure separately.
#[must_use]
pub fn expr_effects(expr: &Expr) -> Effects {
    match expr {
        Expr::Literal(_) | Expr::Use(_) | Expr::Phi { .. } => Effects::PURE,
        // All lowered unary operators are total (the trapping float→int
        // truncations never lower to `Unary`; they stay
        // `Unknown{Conversion}`) — pinned by test.
        Expr::Unary { .. } => Effects::PURE,
        // Integer div/rem trap (div-by-zero, MIN/-1). `BinaryOp` erases
        // signedness/width, so every Div/Rem is may_trap; the float-div
        // over-approximation costs nothing (the Soroban VM rejects float
        // opcodes in deployed contracts).
        Expr::Binary { op, .. } => match op {
            sordec_ir::BinaryOp::Div | sordec_ir::BinaryOp::Rem => TRAP,
            sordec_ir::BinaryOp::Add
            | sordec_ir::BinaryOp::Sub
            | sordec_ir::BinaryOp::Mul
            | sordec_ir::BinaryOp::BitAnd
            | sordec_ir::BinaryOp::BitOr
            | sordec_ir::BinaryOp::BitXor
            | sordec_ir::BinaryOp::Shl
            | sordec_ir::BinaryOp::Shr
            | sordec_ir::BinaryOp::Rotl
            | sordec_ir::BinaryOp::Rotr
            | sordec_ir::BinaryOp::Eq
            | sordec_ir::BinaryOp::Ne
            | sordec_ir::BinaryOp::Lt
            | sordec_ir::BinaryOp::Le
            | sordec_ir::BinaryOp::Gt
            | sordec_ir::BinaryOp::Ge => Effects::PURE,
        },
        // Intra-module callee summaries are future work — fail closed.
        Expr::Call { .. } | Expr::IndirectCall { .. } => Effects::WORST,
        Expr::GlobalGet { .. } => Effects {
            reads_globals: true,
            ..Effects::PURE
        },
        Expr::Load { .. } => TRAP_READ_MEM,
        Expr::Store { .. } => TRAP_WRITE_MEM,
        Expr::Semantic(SemanticOp::Known(op)) => known_op_effects(op),
        // Unclaimed host call: outside the recognition trust boundary —
        // fail closed even though (module, name) could be looked up.
        // See the module docs' "Fail-closed boundaries".
        Expr::Semantic(SemanticOp::Unknown { .. }) => Effects::WORST,
        Expr::Unknown { op_kind, .. } => opcode_kind_effects(*op_kind),
    }
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{UnknownReason, ValueId};
    use sordec_ir::{
        BinaryOp, DispatchTable, IrType, KnownTier, Literal, MemWidth, StorageTier, UnaryOp,
    };

    fn v(i: u32) -> ValueId {
        ValueId::new(i)
    }

    /// Decode the 7 axes from a bitmask — test-only enumeration helper.
    fn from_bits(bits: u8) -> Effects {
        Effects {
            may_trap: bits & 1 != 0,
            reads_memory: bits & 2 != 0,
            writes_memory: bits & 4 != 0,
            reads_globals: bits & 8 != 0,
            writes_globals: bits & 16 != 0,
            reads_host: bits & 32 != 0,
            writes_host: bits & 64 != 0,
        }
    }

    // --- Vocabulary ---

    #[test]
    fn pure_and_worst_constructors() {
        // Route through the runtime decoder so nothing const-folds.
        assert_eq!(Effects::PURE, from_bits(0));
        assert_eq!(Effects::WORST, from_bits(0b111_1111));
        let (pure, worst) = (from_bits(0), from_bits(0b111_1111));
        assert!(pure.is_pure_total() && !pure.may_write());
        assert!(!worst.is_pure_total() && worst.may_write() && worst.may_trap);
    }

    #[test]
    fn class_precedence() {
        assert_eq!(TRAP_WRITE_HOST.class(), EffectClass::Effectful);
        assert_eq!(TRAP_READ_HOST.class(), EffectClass::Trapping);
        assert_eq!(
            Effects {
                reads_globals: true,
                ..Effects::PURE
            }
            .class(),
            EffectClass::ReadOnly
        );
        assert_eq!(Effects::PURE.class(), EffectClass::PureTotal);
    }

    #[test]
    fn join_is_per_axis_or() {
        for bits in 0..128u8 {
            let e = from_bits(bits);
            assert_eq!(Effects::PURE.join(e), e);
            assert_eq!(e.join(Effects::WORST), Effects::WORST);
            assert_eq!(e.join(e), e);
        }
    }

    // --- Commutation ---

    #[test]
    fn commutes_is_symmetric_exhaustively() {
        for a_bits in 0..128u8 {
            for b_bits in 0..128u8 {
                let (a, b) = (from_bits(a_bits), from_bits(b_bits));
                assert_eq!(
                    a.commutes_with(b),
                    b.commutes_with(a),
                    "asymmetry at {a:?} vs {b:?}"
                );
            }
        }
    }

    #[test]
    fn pure_total_commutes_with_worst() {
        assert!(Effects::PURE.commutes_with(Effects::WORST));
        assert!(Effects::WORST.commutes_with(Effects::PURE));
    }

    #[test]
    fn trap_trap_pinned() {
        assert!(!TRAP.commutes_with(TRAP));
    }

    #[test]
    fn trap_vs_write_pinned_both_directions() {
        let write = Effects {
            writes_host: true,
            ..Effects::PURE
        };
        assert!(!TRAP.commutes_with(write));
        assert!(!write.commutes_with(TRAP));
    }

    #[test]
    fn write_vs_read_same_family_pinned() {
        let write_mem = Effects {
            writes_memory: true,
            ..Effects::PURE
        };
        let read_mem = Effects {
            reads_memory: true,
            ..Effects::PURE
        };
        assert!(!write_mem.commutes_with(read_mem));
        assert!(!write_mem.commutes_with(write_mem));
    }

    #[test]
    fn read_read_commutes() {
        let read_mem = Effects {
            reads_memory: true,
            ..Effects::PURE
        };
        let read_host = Effects {
            reads_host: true,
            ..Effects::PURE
        };
        assert!(read_mem.commutes_with(read_mem));
        assert!(read_mem.commutes_with(read_host));
    }

    #[test]
    fn trap_vs_pure_read_commutes() {
        let read = Effects {
            reads_globals: true,
            ..Effects::PURE
        };
        assert!(TRAP.commutes_with(read));
    }

    #[test]
    fn disjoint_family_writes_commute() {
        let write_globals = Effects {
            writes_globals: true,
            ..Effects::PURE
        };
        let write_host = Effects {
            writes_host: true,
            ..Effects::PURE
        };
        assert!(write_globals.commutes_with(write_host));
    }

    // --- WASM operator delegation ---

    #[test]
    fn wasm_operator_effects_spot_table() {
        use waffle::entity::EntityRef as _;
        use waffle::Operator as Op;
        let mem = waffle::Memory::new(0);
        let arg = waffle::MemoryArg {
            align: 0,
            offset: 0,
            memory: mem,
        };
        assert_eq!(wasm_operator_effects(&Op::I32Add), Effects::PURE);
        assert_eq!(wasm_operator_effects(&Op::I32DivS), TRAP);
        assert_eq!(wasm_operator_effects(&Op::I64RemU), TRAP);
        assert_eq!(wasm_operator_effects(&Op::I32TruncF64S), TRAP);
        assert_eq!(wasm_operator_effects(&Op::I32TruncSatF64S), Effects::PURE);
        assert_eq!(
            wasm_operator_effects(&Op::I64Load { memory: arg }),
            TRAP_READ_MEM
        );
        assert_eq!(
            wasm_operator_effects(&Op::I32Store8 { memory: arg }),
            TRAP_WRITE_MEM
        );
        assert_eq!(
            wasm_operator_effects(&Op::MemorySize { mem }),
            Effects {
                reads_memory: true,
                ..Effects::PURE
            }
        );
        assert_eq!(
            wasm_operator_effects(&Op::MemoryGrow { mem }),
            Effects {
                may_trap: true,
                writes_memory: true,
                ..Effects::PURE
            }
        );
        assert_eq!(
            wasm_operator_effects(&Op::MemoryCopy { dst_mem: mem, src_mem: mem }),
            Effects {
                may_trap: true,
                reads_memory: true,
                writes_memory: true,
                ..Effects::PURE
            }
        );
        let global = waffle::Global::new(0);
        assert_eq!(
            wasm_operator_effects(&Op::GlobalGet { global_index: global }),
            Effects {
                reads_globals: true,
                ..Effects::PURE
            }
        );
        assert_eq!(
            wasm_operator_effects(&Op::GlobalSet { global_index: global }),
            Effects {
                writes_globals: true,
                ..Effects::PURE
            }
        );
        assert_eq!(wasm_operator_effects(&Op::Select), Effects::PURE);
        assert_eq!(wasm_operator_effects(&Op::Unreachable), TRAP);
        assert_eq!(
            wasm_operator_effects(&Op::Call {
                function_index: waffle::Func::new(0)
            }),
            Effects::WORST
        );
        let table = waffle::Table::new(0);
        assert_eq!(
            wasm_operator_effects(&Op::TableGet { table_index: table }),
            TRAP_READ_MEM
        );
    }

    // --- Host table guards ---

    #[test]
    fn host_effects_cover_entire_catalog() {
        let mut classified = 0usize;
        for call in crate::host_calls::all() {
            assert!(
                host_call_effects(call.module, call.name).is_some(),
                "{}.{} ({}) has no effects row",
                call.module,
                call.name,
                call.friendly_name
            );
            classified += 1;
        }
        assert_eq!(classified, crate::host_calls::catalog_size());
    }

    #[test]
    fn host_effects_have_no_phantom_rows() {
        let candidates: Vec<String> = std::iter::once("_".to_string())
            .chain(('0'..='9').map(|c| c.to_string()))
            .chain(('a'..='z').map(|c| c.to_string()))
            .chain(('A'..='Z').map(|c| c.to_string()))
            .collect();
        for module in ["a", "b", "c", "d", "i", "l", "m", "p", "t", "v", "x", "q"] {
            for name in &candidates {
                if host_call_effects(module, name).is_some() {
                    assert!(
                        crate::host_calls::resolve(module, name).is_some(),
                        "effects table has a row for {module}.{name}, which is not in the catalog"
                    );
                }
            }
        }
    }

    #[test]
    fn host_pure_total_rows_are_exactly_the_audited_seventeen() {
        let mut pure: Vec<(&str, &str)> = crate::host_calls::all()
            .iter()
            .filter(|c| {
                host_call_effects(c.module, c.name)
                    .expect("covered")
                    .is_pure_total()
            })
            .map(|c| (c.module, c.name))
            .collect();
        pure.sort_unstable();
        let mut expected = vec![
            // x: invocation-constant context reads.
            ("x", "2"),
            ("x", "3"),
            ("x", "4"),
            ("x", "6"),
            ("x", "7"),
            ("x", "8"),
            // i: object constructors from raw integers.
            ("i", "_"),
            ("i", "1"),
            ("i", "3"),
            ("i", "6"),
            ("i", "9"),
            ("i", "g"),
            ("i", "D"),
            ("i", "F"),
            // Empty-container allocations.
            ("m", "_"),
            ("v", "_"),
            ("b", "4"),
        ];
        expected.sort_unstable();
        assert_eq!(pure, expected, "the audited PURE row set changed — audit consciously");
        assert_eq!(pure.len(), 17);
    }

    #[test]
    fn host_linear_memory_axes_are_exactly_the_audited_sets() {
        let mut writers: Vec<(&str, &str)> = Vec::new();
        let mut readers: Vec<(&str, &str)> = Vec::new();
        for call in crate::host_calls::all() {
            // The `t` (test) module is deliberately WORST (fail-closed,
            // not audited) — its axes are not linear-memory *claims*.
            // Pin that separately and exclude it from the audited sets.
            if call.module == "t" {
                assert_eq!(
                    host_call_effects(call.module, call.name),
                    Some(Effects::WORST),
                    "t-module rows must stay fail-closed WORST"
                );
                continue;
            }
            let effects = host_call_effects(call.module, call.name).expect("covered");
            if effects.writes_memory {
                writers.push((call.module, call.name));
            }
            if effects.reads_memory {
                readers.push((call.module, call.name));
            }
        }
        writers.sort_unstable();
        readers.sort_unstable();
        let mut expected_writers = vec![("b", "1"), ("b", "g"), ("b", "h"), ("m", "a"), ("v", "h")];
        expected_writers.sort_unstable();
        let mut expected_readers = vec![
            ("b", "2"),
            ("b", "3"),
            ("b", "i"),
            ("b", "j"),
            ("b", "m"),
            ("m", "9"),
            ("v", "g"),
            ("x", "_"),
        ];
        expected_readers.sort_unstable();
        assert_eq!(writers, expected_writers, "linear-memory WRITER set drifted");
        assert_eq!(readers, expected_readers, "linear-memory READER set drifted");
    }

    #[test]
    fn cross_contract_rows_do_not_write_guest_memory() {
        for (module, name) in [("d", "_"), ("d", "0"), ("l", "e")] {
            let effects = host_call_effects(module, name).expect("covered");
            assert!(!effects.writes_memory, "{module}.{name} must not write guest memory");
            assert!(!effects.writes_globals, "{module}.{name} must not write guest globals");
            assert!(effects.writes_host && effects.may_trap, "{module}.{name} host axes");
        }
    }

    // --- KnownOp ↔ host-table consistency ---

    #[test]
    fn grouped_kind_effects_agree_with_host_table() {
        use crate::val_abi as abi;
        for call in crate::host_calls::all() {
            let (m, n) = (call.module, call.name);
            let host = host_call_effects(m, n).expect("covered");
            let check = |label: &str, kind_effects: Option<Effects>| {
                if let Some(kind_effects) = kind_effects {
                    assert_eq!(
                        kind_effects, host,
                        "{label} kind effects for {m}.{n} disagree with the host row"
                    );
                }
            };
            check("map", abi::map_fn_kind(m, n).map(map_kind_effects));
            check("vec", abi::vec_fn_kind(m, n).map(vec_kind_effects));
            check("buf", abi::buf_fn_kind(m, n).map(buf_kind_effects));
            check("crypto", abi::crypto_fn_kind(m, n).map(crypto_kind_effects));
            check("prng", abi::prng_fn_kind(m, n).map(prng_kind_effects));
            check("test", abi::test_fn_kind(m, n).map(test_kind_effects));
            check("deploy", abi::deploy_fn_kind(m, n).map(deploy_kind_effects));
            check("obj", abi::obj_fn_kind(m, n).map(val_object_kind_effects));
            check("addr", abi::addr_fn_kind(m, n).map(address_kind_effects));
        }
    }

    #[test]
    fn individual_known_ops_agree_with_host_table() {
        let tier = || StorageTier::Known(KnownTier::Persistent);
        let cases: Vec<(KnownOp, &str, &str)> = vec![
            (
                KnownOp::StorageSet {
                    tier: tier(),
                    durability: v(0),
                    key: v(1),
                    resolved_key: None,
                    value: v(2),
                },
                "l",
                "_",
            ),
            (
                KnownOp::StorageHas {
                    tier: tier(),
                    durability: v(0),
                    key: v(1),
                    resolved_key: None,
                },
                "l",
                "0",
            ),
            (
                KnownOp::StorageGet {
                    tier: tier(),
                    durability: v(0),
                    key: v(1),
                    resolved_key: None,
                },
                "l",
                "1",
            ),
            (
                KnownOp::StorageRemove {
                    tier: tier(),
                    durability: v(0),
                    key: v(1),
                    resolved_key: None,
                },
                "l",
                "2",
            ),
            (
                KnownOp::StorageExtendTtl {
                    tier: tier(),
                    durability: v(0),
                    key: v(1),
                    resolved_key: None,
                    threshold: v(2),
                    extend_to: v(3),
                    resolved_threshold: None,
                    resolved_extend_to: None,
                },
                "l",
                "7",
            ),
            (
                KnownOp::ExtendCurrentContractInstanceAndCodeTtl {
                    threshold: v(0),
                    extend_to: v(1),
                    resolved_threshold: None,
                    resolved_extend_to: None,
                },
                "l",
                "8",
            ),
            (
                KnownOp::ExtendContractInstanceAndCodeTtl {
                    contract: v(0),
                    threshold: v(1),
                    extend_to: v(2),
                },
                "l",
                "9",
            ),
            (
                KnownOp::ExtendContractInstanceTtl {
                    contract: v(0),
                    threshold: v(1),
                    extend_to: v(2),
                },
                "l",
                "c",
            ),
            (
                KnownOp::ExtendContractCodeTtl {
                    contract: v(0),
                    threshold: v(1),
                    extend_to: v(2),
                },
                "l",
                "d",
            ),
            (
                KnownOp::StorageExtendTtlV2 {
                    tier: tier(),
                    durability: v(0),
                    key: v(1),
                    resolved_key: None,
                    extend_to: v(2),
                    min_extension: v(3),
                    max_extension: v(4),
                },
                "l",
                "f",
            ),
            (
                KnownOp::ExtendContractInstanceAndCodeTtlV2 {
                    contract: v(0),
                    extension_scope: v(1),
                    extend_to: v(2),
                    min_extension: v(3),
                    max_extension: v(4),
                },
                "l",
                "g",
            ),
            (KnownOp::RequireAuthForArgs { address: v(0), args: vec![v(1)] }, "a", "_"),
            (KnownOp::RequireAuth { address: v(0) }, "a", "0"),
            (KnownOp::AuthorizeAsCurrContract { auth_entries: v(0) }, "a", "3"),
            (
                KnownOp::InvokeContract {
                    contract: v(0),
                    function: v(1),
                    resolved_callee: None,
                    arg_count: None,
                    resolved_args: None,
                    interface: None,
                    args: vec![v(2)],
                },
                "d",
                "_",
            ),
            (
                KnownOp::TryInvokeContract {
                    contract: v(0),
                    function: v(1),
                    resolved_callee: None,
                    arg_count: None,
                    resolved_args: None,
                    interface: None,
                    args: vec![v(2)],
                },
                "d",
                "0",
            ),
            (KnownOp::PublishEvent { topics: vec![v(0)], data: v(1) }, "x", "1"),
            (KnownOp::ValCompare { a: v(0), b: v(1) }, "x", "0"),
            (KnownOp::PanicWithError { error: v(0) }, "x", "5"),
            (KnownOp::GetLedgerProtocolVersion, "x", "2"),
            (KnownOp::GetLedgerSequence, "x", "3"),
            (KnownOp::GetLedgerTimestamp, "x", "4"),
            (KnownOp::GetLedgerNetworkId, "x", "6"),
            (KnownOp::GetCurrentContractAddress, "x", "7"),
            (KnownOp::GetMaxLiveUntilLedger, "x", "8"),
            (
                KnownOp::BytesNew { lm_pos: v(0), len: v(1), resolved: None },
                "b",
                "3",
            ),
            (
                KnownOp::StringNew { lm_pos: v(0), len: v(1), resolved: None },
                "b",
                "i",
            ),
            (
                KnownOp::SymbolNew { lm_pos: v(0), len: v(1), resolved: None },
                "b",
                "j",
            ),
            (
                KnownOp::SymbolDispatch {
                    sym: v(0),
                    table_pos: v(1),
                    len: v(2),
                    table: DispatchTable { cases: vec![], enum_name: None },
                },
                "b",
                "m",
            ),
            (KnownOp::VecNew { vals_pos: v(0), len: v(1) }, "v", "g"),
            (
                KnownOp::MapNew { keys_pos: v(0), vals_pos: v(1), len: v(2) },
                "m",
                "9",
            ),
        ];
        for (op, module, name) in &cases {
            let host = host_call_effects(module, name)
                .unwrap_or_else(|| panic!("{module}.{name} must be in the host table"));
            assert_eq!(
                known_op_effects(op),
                host,
                "KnownOp for {module}.{name} disagrees with the host row"
            );
        }
    }

    #[test]
    fn guest_val_ops_are_pure_total() {
        use sordec_ir::KnownType;
        for op in [
            KnownOp::ValEncodeSmall { ty: KnownType::U64, value: v(0) },
            KnownOp::ValDecodeSmall { value: v(0) },
            KnownOp::ValTagCheck { value: v(0), tag: 6 },
        ] {
            assert!(known_op_effects(&op).is_pure_total(), "{op:?} must be pure");
        }
    }

    // --- Expr classifier ---

    #[test]
    fn expr_arms_match_table() {
        assert_eq!(expr_effects(&Expr::Literal(Literal::I64(1))), Effects::PURE);
        assert_eq!(expr_effects(&Expr::Use(v(0))), Effects::PURE);
        assert_eq!(
            expr_effects(&Expr::Phi { incoming: vec![] }),
            Effects::PURE
        );
        assert_eq!(
            expr_effects(&Expr::GlobalGet { index: 0 }),
            Effects {
                reads_globals: true,
                ..Effects::PURE
            }
        );
        assert_eq!(
            expr_effects(&Expr::Load {
                addr: v(0),
                offset: 0,
                width: MemWidth::W8,
                signed: None,
                ty: IrType::Unknown(UnknownReason::UpstreamUnknown),
            }),
            TRAP_READ_MEM
        );
        assert_eq!(
            expr_effects(&Expr::Store {
                addr: v(0),
                value: v(1),
                offset: 0,
                width: MemWidth::W8,
            }),
            TRAP_WRITE_MEM
        );
        assert_eq!(
            expr_effects(&Expr::Call {
                target: sordec_common::FuncId::new(0),
                args: vec![]
            }),
            Effects::WORST
        );
        assert_eq!(
            expr_effects(&Expr::IndirectCall {
                table: 0,
                sig: 0,
                callee: v(0),
                args: vec![]
            }),
            Effects::WORST
        );
        // Fail-closed even though (l, _) IS catalog-resolvable — locks
        // the trust-boundary decision.
        assert_eq!(
            expr_effects(&Expr::Semantic(SemanticOp::Unknown {
                host_module: "l".to_string(),
                host_fn: "_".to_string(),
                args: vec![],
                reason: UnknownReason::UpstreamUnknown,
            })),
            Effects::WORST
        );
        assert_eq!(
            expr_effects(&Expr::Semantic(SemanticOp::Known(KnownOp::RequireAuth {
                address: v(0)
            }))),
            TRAP_RW_HOST
        );
    }

    #[test]
    fn binary_div_rem_trap_all_else_pure() {
        let all = [
            BinaryOp::Add,
            BinaryOp::Sub,
            BinaryOp::Mul,
            BinaryOp::Div,
            BinaryOp::Rem,
            BinaryOp::BitAnd,
            BinaryOp::BitOr,
            BinaryOp::BitXor,
            BinaryOp::Shl,
            BinaryOp::Shr,
            BinaryOp::Rotl,
            BinaryOp::Rotr,
            BinaryOp::Eq,
            BinaryOp::Ne,
            BinaryOp::Lt,
            BinaryOp::Le,
            BinaryOp::Gt,
            BinaryOp::Ge,
        ];
        for op in all {
            let expr = Expr::Binary { op, lhs: v(0), rhs: v(1) };
            let expected = matches!(op, BinaryOp::Div | BinaryOp::Rem);
            assert_eq!(
                expr_effects(&expr).may_trap,
                expected,
                "trap classification for {op:?}"
            );
            assert!(!expr_effects(&expr).may_write());
        }
    }

    #[test]
    fn all_unary_ops_are_pure_total() {
        let all = [
            UnaryOp::Neg,
            UnaryOp::Not,
            UnaryOp::BitNot,
            UnaryOp::Clz,
            UnaryOp::Ctz,
            UnaryOp::Popcnt,
            UnaryOp::Abs,
            UnaryOp::Sqrt,
            UnaryOp::Floor,
            UnaryOp::Ceil,
            UnaryOp::Trunc,
        ];
        for op in all {
            let expr = Expr::Unary { op, value: v(0) };
            assert!(
                expr_effects(&expr).is_pure_total(),
                "UnaryOp::{op:?} must be pure-total (trapping truncations \
                 never lower to Unary)"
            );
        }
    }

    #[test]
    fn opcode_kind_writes_column_matches_frame_facts_legacy_table() {
        use WasmOpcodeKind as K;
        let writers = [K::Store, K::MemoryOp, K::Call, K::CallIndirect, K::Other];
        let non_writers = [
            K::Const,
            K::Arithmetic,
            K::Bitwise,
            K::Comparison,
            K::Unary,
            K::Conversion,
            K::Load,
            K::GlobalGet,
            K::GlobalSet,
            K::Select,
            K::Unreachable,
            K::Nop,
        ];
        for kind in writers {
            assert!(
                opcode_kind_effects(kind).writes_memory,
                "{kind:?} must keep the fail-closed writes_memory bit"
            );
        }
        for kind in non_writers {
            assert!(
                !opcode_kind_effects(kind).writes_memory,
                "{kind:?} must not write memory (legacy frame_facts column)"
            );
        }
        // New-axis spot checks the legacy predicate couldn't express.
        assert_eq!(opcode_kind_effects(K::Conversion), TRAP);
        assert_eq!(opcode_kind_effects(K::Arithmetic), TRAP);
        assert_eq!(opcode_kind_effects(K::Unreachable), TRAP);
        assert_eq!(
            opcode_kind_effects(K::GlobalSet),
            Effects {
                writes_globals: true,
                ..Effects::PURE
            }
        );
    }
}
