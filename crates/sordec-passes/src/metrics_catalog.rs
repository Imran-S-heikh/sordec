//! Canonical registry of the `PassMetrics` counter keys that the
//! `sordec coverage` recognition + headline sections surface (spec
//! F1–F8, plus the enum-key / TTL / dispatcher ratios).
//!
//! ## Why this module exists
//!
//! Each recognizer pass declares its counter keys as private `M_*`
//! `&'static str` consts next to the code that emits them (e.g.
//! `recognizers::storage::M_TIER_RESOLVED = "storage_tier_resolved"`).
//! The coverage reporter in `sordec-cli` must read those same counters
//! out of [`PipelineReport::metric_totals`](crate::PipelineReport::metric_totals)
//! by key — but it lives in a different crate and must **not** re-type
//! the key strings as literals scattered far from their owners. This
//! module is the one public place those keys are named, mirroring the
//! `val_abi` table idiom (one owner + a drift guard) already used for
//! the host-ABI constants.
//!
//! ## Drift protection
//!
//! The consts here mirror the passes' private `M_*` strings. That
//! mirror is guarded, not merely asserted by convention: the H1
//! coverage matrix (`sordec-driver/tests/coverage_matrix.rs`) routes
//! its per-key corpus assertions through these consts, and **every
//! ratio-bearing key is exercised by the corpus** (storage-tier /
//! enum-key / TTL by the tokens, client / dispatcher by dex + timelock).
//! So if a pass renames an emitted counter without updating its const
//! here, that fixture's `>= 1` assertion reads zero through the stale
//! catalog const and fails at test time — never as a silently-zero
//! coverage report. [`surfaced_keys`] backs a completeness check for
//! the count-only keys that carry no ratio.

// ---------------------------------------------------------------------
// Storage tiers (F1) + storage CRUD/TTL op counts
// ---------------------------------------------------------------------

/// `l`-module storage reads recognized (`get`).
pub const STORAGE_GET: &str = "storage_get";
/// `l`-module storage writes recognized (`set`).
pub const STORAGE_SET: &str = "storage_set";
/// `l`-module existence checks recognized (`has`).
pub const STORAGE_HAS: &str = "storage_has";
/// `l`-module deletes recognized (`remove`).
pub const STORAGE_REMOVE: &str = "storage_remove";
/// `l`-module TTL-extension calls recognized.
pub const STORAGE_EXTEND_TTL: &str = "storage_extend_ttl";
/// Storage ops whose durability tier resolved to a concrete tier
/// (F1 numerator).
pub const STORAGE_TIER_RESOLVED: &str = "storage_tier_resolved";
/// Storage ops whose durability arg stayed a typed `Unknown`
/// (F1 miss channel).
pub const STORAGE_TIER_UNKNOWN: &str = "storage_tier_unknown";

// ---------------------------------------------------------------------
// Enum storage keys (beyond-kickoff ratio)
// ---------------------------------------------------------------------

/// Enum storage keys named against the `#[contracttype]` spec.
pub const ENUM_KEY_NAMED: &str = "enum_key_named";
/// Enum storage keys the recognizer soundly declined to name.
pub const ENUM_KEY_UNRESOLVED: &str = "enum_key_unresolved";
/// Enum-key constructor sites matched (payload-carrying variants).
pub const ENUM_KEY_CTOR_MATCHED: &str = "enum_key_ctor_matched";

// ---------------------------------------------------------------------
// TTL amounts (beyond-kickoff ratio; D3)
// ---------------------------------------------------------------------

/// TTL ledger amounts resolved to a concrete value.
pub const TTL_RESOLVED: &str = "ttl_resolved";
/// TTL ledger amounts left unresolved (sound indirect-call decline).
pub const TTL_UNRESOLVED: &str = "ttl_unresolved";

// ---------------------------------------------------------------------
// Cross-contract client calls (F5)
// ---------------------------------------------------------------------

/// `d`-module `invoke_contract` sites recognized.
pub const INVOKE_CONTRACT: &str = "invoke_contract";
/// `d`-module `try_invoke_contract` sites recognized.
pub const TRY_INVOKE_CONTRACT: &str = "try_invoke_contract";
/// Invoke sites whose argument arity was recovered (F5 "typed"
/// numerator — structural typing, independent of interface tables).
pub const CLIENT_ARITY_RESOLVED: &str = "client_arity_resolved";
/// Invoke sites whose full argument element list was recovered.
pub const CLIENT_ARGS_RESOLVED: &str = "client_args_resolved";
/// Invoke sites matched to a known interface table (SEP-41 today).
pub const CLIENT_IFACE_MATCHED: &str = "client_iface_matched";
/// Invoke sites the client-call recognizer soundly declined.
pub const CLIENT_UNRESOLVED: &str = "client_unresolved";

// ---------------------------------------------------------------------
// Symbol dispatcher (beyond-kickoff ratio; C25/W4)
// ---------------------------------------------------------------------

/// Dispatcher sites whose index→variant case table was resolved.
pub const DISPATCHER_CASES_RESOLVED: &str = "dispatcher_cases_resolved";
/// Dispatcher enums named against the `#[contracttype]` spec.
pub const DISPATCHER_ENUM_NAMED: &str = "dispatcher_enum_named";
/// Dispatcher sites the recognizer soundly declined.
pub const DISPATCHER_UNRESOLVED: &str = "dispatcher_unresolved";

// ---------------------------------------------------------------------
// Auth patterns (F2) — counts only (misses surface as unrecognized host calls)
// ---------------------------------------------------------------------

/// `require_auth(addr)` sites recognized.
pub const REQUIRE_AUTH: &str = "require_auth";
/// `require_auth_for_args(addr, args)` sites recognized.
pub const REQUIRE_AUTH_FOR_ARGS: &str = "require_auth_for_args";
/// `authorize_as_current_contract` sites recognized.
pub const AUTHORIZE_AS_CURR_CONTRACT: &str = "authorize_as_curr_contract";
/// Address strkey/muxed conversions recognized.
pub const ADDRESS_CONVERSION: &str = "address_conversion";
/// Admin-from-instance-storage auth gates recognized (W1 auth-flow).
pub const AUTH_ADMIN_GATE: &str = "auth_admin_gate";

// ---------------------------------------------------------------------
// Events (F3) — count only (flavor split is Phase-3 emit)
// ---------------------------------------------------------------------

/// Event-emission host calls recognized.
pub const PUBLISH_EVENT: &str = "publish_event";

// ---------------------------------------------------------------------
// Collections (F4) — counts only (element expansion is W9-deferred)
// ---------------------------------------------------------------------

/// `vec![&env, …]`-shape constructors recognized.
pub const VEC_NEW: &str = "vec_new";
/// Vec host operations recognized.
pub const VEC_OP: &str = "vec_op";
/// `map![&env, …]`-shape constructors recognized.
pub const MAP_NEW: &str = "map_new";
/// Map host operations recognized.
pub const MAP_OP: &str = "map_op";
/// Bytes/String/Symbol buffer operations recognized.
pub const BUF_OP: &str = "buf_op";

// ---------------------------------------------------------------------
// Panics (F6) — count only (bare panic!/unwrap detection is Phase-3)
// ---------------------------------------------------------------------

/// `panic_with_error` / `fail_with_error` sites recognized.
pub const PANIC_WITH_ERROR: &str = "panic_with_error";

// ---------------------------------------------------------------------
// Val boilerplate collapse (F8) — counts only (denominator undefined by
// construction: a missed pure-bit-op pattern is indistinguishable from
// ordinary arithmetic; the dump e2e locks are the real guard)
// ---------------------------------------------------------------------

/// `Val` object conversions collapsed.
pub const VAL_OBJECT: &str = "val_object";
/// `Val` tag-check sequences collapsed.
pub const VAL_TAG_CHECK: &str = "val_tag_check";
/// Small-value `Val` encodes collapsed.
pub const VAL_ENCODE_SMALL: &str = "val_encode_small";
/// `U32Val` encodes collapsed.
pub const VAL_ENCODE_U32: &str = "val_encode_u32";
/// Small-value `Val` decodes collapsed.
pub const VAL_DECODE_SMALL: &str = "val_decode_small";
/// `Val` comparison host calls collapsed.
pub const VAL_COMPARE: &str = "val_compare";

// ---------------------------------------------------------------------
// Lifted-IR de-cluttering (Phase 3 W3). Registered here for the W8
// coverage surface; deliberately absent from `surfaced_keys()` until
// A6/F3 wires the structuring-metrics section.
// ---------------------------------------------------------------------

/// Alias uses rewritten to their terminal definition.
pub const DECLUTTER_ALIASES_RESOLVED: &str = "declutter_aliases_resolved";
/// Trivial block parameters removed (Braun-style pruning).
pub const DECLUTTER_PHIS_PRUNED: &str = "declutter_phis_pruned";
/// Edges retargeted past empty forwarding blocks.
pub const DECLUTTER_JUMPS_THREADED: &str = "declutter_jumps_threaded";
/// Unconditional branches to empty return blocks turned into `Return`
/// (tail-merge undo — the early-return shape guard recovery feeds on).
pub const DECLUTTER_RETURNS_INLINED: &str = "declutter_returns_inlined";
/// Unconditional branches to empty `Unreachable` blocks inlined.
pub const DECLUTTER_TRAPS_INLINED: &str = "declutter_traps_inlined";
/// Single-predecessor block pairs spliced.
pub const DECLUTTER_CHAINS_MERGED: &str = "declutter_chains_merged";
/// Unreachable blocks cleared to tombstones.
pub const DECLUTTER_DEAD_BLOCKS_CLEARED: &str = "declutter_dead_blocks_cleared";
/// Pure-total zero-use instructions removed from the schedule.
pub const DECLUTTER_DEAD_VALUES_UNSCHEDULED: &str = "declutter_dead_values_unscheduled";

// ---------------------------------------------------------------------
// Treeification analysis (Phase 3 B6). Same W8-surfacing status as the
// declutter keys above.
// ---------------------------------------------------------------------

/// Bindings classified `Inline` (pure-total, single live use).
pub const TREEIFY_INLINE: &str = "treeify_inline";
/// Single-live-use bindings pinned only by their effects — the
/// readability tax the K4 discipline pays.
pub const TREEIFY_PINNED_SINGLE_USE: &str = "treeify_pinned_single_use";
/// De-clutter residue bindings hidden as `Dead`.
pub const TREEIFY_DEAD_RESIDUE: &str = "treeify_dead_residue";

// ---------------------------------------------------------------------
// Control-flow structuring (Phase 3 C2). Same W8-surfacing status as
// the declutter keys above; the full structuring coverage set (A6)
// lands with W8.
// ---------------------------------------------------------------------

/// Functions whose control flow fell back to `Region::Unstructured` —
/// corpus-locked to zero (K3); non-zero only on exotic input.
pub const STRUCTURING_FALLBACK: &str = "structuring_fallback";

// ---------------------------------------------------------------------
// Region refinement (Phase 3 D-category, W6). Same W8-surfacing status
// as the declutter/structuring keys above.
// ---------------------------------------------------------------------

/// Guard conditions inverted into the canonical exit-in-`then` form.
pub const REFINE_POLARITY_FLIPPED: &str = "refine_polarity_flipped";
/// `else` bodies hoisted out from under a terminating `then` (guard
/// clauses recovered).
pub const REFINE_GUARDS_HOISTED: &str = "refine_guards_hoisted";
/// Break sites rewritten into an inline copy of a shared bare
/// terminator (LLVM's tail-merge undone).
pub const REFINE_TRAPS_INLINED: &str = "refine_traps_inlined";
/// Shared terminating out-blocks left labeled because they carry
/// bindings — the deferred full-duplication case (fresh-id minting
/// lands only if a real fixture shows this shape).
pub const REFINE_SHARED_TRAP_WITH_BINDINGS: &str = "refine_shared_trap_with_bindings";

// ---------------------------------------------------------------------
// Terminal unrecognized-host-call scan (headline denominator input)
// ---------------------------------------------------------------------

/// Host imports that survived the whole pipeline unrecognized — the
/// headline "host interactions" miss channel (spec E2).
pub const UNRECOGNISED_HOST_CALL: &str = "unrecognised_host_call";

/// The five resolved/miss counter pairs that define the headline
/// **deep-facts** ratio: `(resolved, unresolved)`. Membership is the
/// W7-locked set — storage-tier, enum-key, TTL, client (arity vs
/// unresolved), dispatcher. `const_prop_unresolved` is deliberately
/// excluded: it double-counts misses that already re-surface here as a
/// tier / key / TTL miss.
pub const DEEP_FACT_PAIRS: &[(&str, &str)] = &[
    (STORAGE_TIER_RESOLVED, STORAGE_TIER_UNKNOWN),
    (ENUM_KEY_NAMED, ENUM_KEY_UNRESOLVED),
    (TTL_RESOLVED, TTL_UNRESOLVED),
    (CLIENT_ARITY_RESOLVED, CLIENT_UNRESOLVED),
    (DISPATCHER_CASES_RESOLVED, DISPATCHER_UNRESOLVED),
];

/// Every counter key this module surfaces, for completeness checks.
/// Not exhaustive of *all* pass counters — only the ones the coverage
/// report renders (the abi-sweep crypto/prng/deploy op counts, symbol
/// construction, context accessors, and the const-prop internals are
/// intentionally absent, being either W9-deferred surfaces or internal
/// resolver signals).
#[must_use]
pub fn surfaced_keys() -> &'static [&'static str] {
    &[
        STORAGE_GET,
        STORAGE_SET,
        STORAGE_HAS,
        STORAGE_REMOVE,
        STORAGE_EXTEND_TTL,
        STORAGE_TIER_RESOLVED,
        STORAGE_TIER_UNKNOWN,
        ENUM_KEY_NAMED,
        ENUM_KEY_UNRESOLVED,
        ENUM_KEY_CTOR_MATCHED,
        TTL_RESOLVED,
        TTL_UNRESOLVED,
        INVOKE_CONTRACT,
        TRY_INVOKE_CONTRACT,
        CLIENT_ARITY_RESOLVED,
        CLIENT_ARGS_RESOLVED,
        CLIENT_IFACE_MATCHED,
        CLIENT_UNRESOLVED,
        DISPATCHER_CASES_RESOLVED,
        DISPATCHER_ENUM_NAMED,
        DISPATCHER_UNRESOLVED,
        REQUIRE_AUTH,
        REQUIRE_AUTH_FOR_ARGS,
        AUTHORIZE_AS_CURR_CONTRACT,
        ADDRESS_CONVERSION,
        AUTH_ADMIN_GATE,
        PUBLISH_EVENT,
        VEC_NEW,
        VEC_OP,
        MAP_NEW,
        MAP_OP,
        BUF_OP,
        PANIC_WITH_ERROR,
        VAL_OBJECT,
        VAL_TAG_CHECK,
        VAL_ENCODE_SMALL,
        VAL_ENCODE_U32,
        VAL_DECODE_SMALL,
        VAL_COMPARE,
        UNRECOGNISED_HOST_CALL,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn surfaced_keys_are_unique() {
        let all = surfaced_keys();
        let set: BTreeSet<&str> = all.iter().copied().collect();
        assert_eq!(set.len(), all.len(), "duplicate key in surfaced_keys()");
    }

    #[test]
    fn deep_fact_pairs_are_all_surfaced() {
        let set: BTreeSet<&str> = surfaced_keys().iter().copied().collect();
        for (resolved, unresolved) in DEEP_FACT_PAIRS {
            assert!(set.contains(resolved), "{resolved} missing from surfaced_keys");
            assert!(set.contains(unresolved), "{unresolved} missing from surfaced_keys");
        }
    }
}
