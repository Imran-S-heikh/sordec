//! Canonical registry of the `PassMetrics` counter keys that the
//! `sordec coverage` recognition + headline sections surface (spec
//! F1–F8, plus the enum-key / TTL / dispatcher ratios).
//!
//! ## Why this module exists
//!
//! Each recognizer pass declares its counter keys as private `M_*`
//! `&'static str` consts next to the code that emits them (e.g.
//! `recognizers::storage::M_TIER_RESOLVED = "storage_tier_resolved"`).
//! The coverage reporter in `sordec` must read those same counters
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
/// Unions recovered from their own derived converter, where the module
/// carries no `contractspecv0` to declare them.
pub const ENUM_KEY_UNIONS_SYNTHESIZED: &str = "enum_key_unions_synthesized";

// ---------------------------------------------------------------------
// Function specialization (undoing rustc's identical-code folding)
// ---------------------------------------------------------------------

/// Copies of compiler-merged helpers created, one per de-shared site.
pub const SPECIALIZE_CLONED: &str = "specialize_cloned";
/// Call sites retargeted onto a copy, or re-aritied by pinning.
pub const SPECIALIZE_RETARGETED: &str = "specialize_retargeted";
/// Parameters replaced by the constant their caller always passes.
pub const SPECIALIZE_PARAMS_PINNED: &str = "specialize_params_pinned";
/// Merged helpers left merged (cycle, budget, unpinnable region shape).
pub const SPECIALIZE_DECLINED: &str = "specialize_declined";
/// Candidates declined because the helper has more call sites than
/// `MAX_CALLSITE_FANOUT`. Shared SDK infrastructure looks exactly like a
/// folded source family from the inside; this is the line between them.
pub const SPECIALIZE_DECLINED_FANOUT: &str = "specialize_declined_fanout";
/// Candidates declined because their call sites could not be grouped by
/// the constants they pass.
pub const SPECIALIZE_DECLINED_GROUPING: &str = "specialize_declined_grouping";
/// Candidates declined because cloning them would exceed the growth
/// budget of one extra function per original.
pub const SPECIALIZE_DECLINED_BUDGET: &str = "specialize_declined_budget";
/// Candidates declined because no block dominates the readers of a pinned
/// constant, so the parameter cannot be replaced.
pub const SPECIALIZE_DECLINED_UNPINNABLE: &str = "specialize_declined_unpinnable";
/// Set when the whole pass was disabled because the module contains an
/// indirect call, so no caller set can be trusted. Module-wide: one
/// `call_indirect` anywhere costs every helper in the contract.
pub const SPECIALIZE_DISABLED_INDIRECT: &str = "specialize_disabled_indirect";

/// `has` calls proven to be the SDK's `Option` discriminant rather than a
/// source-level `.has()`.
pub const STORAGE_OPTION_PROBE: &str = "storage_option_probe";

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
/// `compiler_builtins` 128-bit runtime helpers identified by body shape
/// (`__multi3`, `__muloti4`, `__udivmodti4`, `__divti3`, the shifts).
pub const I128_BUILTINS_IDENTIFIED: &str = "i128_builtins_identified";
/// Calls into those helpers rewritten as 128-bit arithmetic.
pub const I128_BUILTIN_CALLS_REWRITTEN: &str = "i128_builtin_calls_rewritten";
/// Wide joins cancelled against their own limbs (and limbs against their
/// join) — the identities that let an `i128` flow through as one value.
pub const WIDE_FOLDED: &str = "wide_folded";
/// Packed `U32Val` comparisons rewritten to payload comparisons via the
/// major-field mask, or against a tagged constant — the exact shapes,
/// resting on no premise beyond the producer's ABI return type.
pub const VAL_PACKED_COMPARE_MASKED: &str = "val_packed_compare_masked";
/// Packed `U32Val` comparisons rewritten from an *ordered* comparison
/// against a `k << 32` boundary. Counted separately from the masked shape
/// because this one reads the wasm comparison as unsigned, which the
/// lowering no longer records — see `recognizers::val_packed_compare`.
pub const VAL_PACKED_COMPARE_ORDERED: &str = "val_packed_compare_ordered";
/// `Bool` Vals narrowed to a machine bool by the SDK's `== 1`. A `Bool`
/// Val has no body, so its bits *are* its value — exact by the encoding's
/// definition, which is why it is counted apart from the packed shapes.
pub const VAL_PACKED_COMPARE_BOOL: &str = "val_packed_compare_bool";

// ---------------------------------------------------------------------
// Lifted-IR de-cluttering (Phase 3 W3). Surfaced by the W8 structuring
// coverage section (A6/F3).
// ---------------------------------------------------------------------

/// Alias uses rewritten to their terminal definition.
pub const DECLUTTER_ALIASES_RESOLVED: &str = "declutter_aliases_resolved";
/// Trivial block parameters removed (Braun-style pruning).
pub const DECLUTTER_PHIS_PRUNED: &str = "declutter_phis_pruned";
/// Block parameters removed because nothing read them — the other half of
/// "insert maximally, prune back"; see `declutter::prune_dead_params`.
pub const DECLUTTER_DEAD_PARAMS_PRUNED: &str = "declutter_dead_params_pruned";
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
// Treeification analysis (Phase 3 B6). Surfaced by the W8 structuring
// coverage section (A6/F3).
// ---------------------------------------------------------------------

/// Bindings classified `Inline` (pure-total, single live use).
pub const TREEIFY_INLINE: &str = "treeify_inline";
/// Single-live-use bindings pinned only by their effects — the
/// readability tax the K4 discipline pays.
pub const TREEIFY_PINNED_SINGLE_USE: &str = "treeify_pinned_single_use";
/// De-clutter residue bindings hidden as `Dead`.
pub const TREEIFY_DEAD_RESIDUE: &str = "treeify_dead_residue";

// ---------------------------------------------------------------------
// Control-flow structuring (Phase 3 C2). Surfaced by the W8 structuring
// coverage section (A6/F3).
// ---------------------------------------------------------------------

/// Functions whose control flow fell back to `Region::Unstructured` —
/// corpus-locked to zero (K3); non-zero only on exotic input. This is a
/// *node-level* count (one per `Region::Unstructured`), emitted with a
/// diagnostic by `structuring::StructuringStatsPass`; the *function*-level
/// view is [`STRUCTURING_FUNCTIONS_STRUCTURED`] below.
pub const STRUCTURING_FALLBACK: &str = "structuring_fallback";

// ---------------------------------------------------------------------
// Structuring census (Phase 3 A6, W8). Emitted once over the settled
// region trees by `structuring::StructuringCensusPass` (the terminal
// pipeline pass), not per fixpoint iteration — these are census values,
// not rewrite-event counts.
// ---------------------------------------------------------------------

/// Local functions in the high IR — the `%functions_structured`
/// denominator.
pub const STRUCTURING_FUNCTIONS_TOTAL: &str = "structuring_functions_total";
/// Functions with zero `Region::Unstructured` nodes — the
/// `%functions_structured` numerator. Corpus-locked equal to
/// [`STRUCTURING_FUNCTIONS_TOTAL`] (K3).
pub const STRUCTURING_FUNCTIONS_STRUCTURED: &str = "structuring_functions_structured";
/// `Region::Loop` nodes tagged `LoopKind::WhileTop` — the only kind the
/// renderer prints as `while` (the loop→while recovery rate numerator).
pub const STRUCTURING_LOOPS_WHILE_TOP: &str = "structuring_loops_while_top";
/// `Region::Loop` nodes tagged `LoopKind::DoWhileBottom`.
pub const STRUCTURING_LOOPS_DO_WHILE_BOTTOM: &str = "structuring_loops_do_while_bottom";
/// `Region::Loop` nodes tagged `LoopKind::GuardedDoWhile`.
pub const STRUCTURING_LOOPS_GUARDED_DO_WHILE: &str = "structuring_loops_guarded_do_while";
/// `Region::Loop` nodes tagged `LoopKind::Infinite`.
pub const STRUCTURING_LOOPS_INFINITE: &str = "structuring_loops_infinite";
/// `Region::Loop` nodes left `LoopKind::Unclassified` — honestly
/// unproven loops the classifier declined to shape (never guessed).
pub const STRUCTURING_LOOPS_UNCLASSIFIED: &str = "structuring_loops_unclassified";
/// `Region::Switch` nodes — recovered `match` constructs. Corpus-locked
/// equal to the original `br_table` opcode count by the skeleton
/// cross-check.
pub const STRUCTURING_SWITCHES: &str = "structuring_switches";
/// `Region::Break` nodes in the final trees — the readability-tax meter.
/// Every break renders label-carrying (`break 'bbN`), so this is the
/// rendered labeled-break count.
pub const STRUCTURING_LABELED_BREAKS: &str = "structuring_labeled_breaks";
/// `Region::Continue` nodes in the final trees. An upper bound on
/// *rendered* labeled continues: `render_while` elides a `WhileTop`
/// loop's back-edge continue, which is still counted here.
pub const STRUCTURING_LABELED_CONTINUES: &str = "structuring_labeled_continues";

// ---------------------------------------------------------------------
// Region refinement (Phase 3 D-category, W6). Surfaced by the W8
// structuring coverage section (A6/F3).
// ---------------------------------------------------------------------

/// Guard conditions inverted into the canonical exit-in-`then` form.
pub const REFINE_POLARITY_FLIPPED: &str = "refine_polarity_flipped";
/// `else` bodies hoisted out from under a terminating `then` (guard
/// clauses recovered).
pub const REFINE_GUARDS_HOISTED: &str = "refine_guards_hoisted";
/// Break sites rewritten into an inline copy of a shared bare
/// terminator (LLVM's tail-merge undone).
pub const REFINE_TRAPS_INLINED: &str = "refine_traps_inlined";
/// Shared terminating out-blocks left labeled because their bindings
/// fail the D2-ext duplication gates (intra-block references or over
/// the size cap) — the remaining-work signal.
pub const REFINE_SHARED_TRAP_WITH_BINDINGS: &str = "refine_shared_trap_with_bindings";
/// Break sites rewritten into a fresh-id duplicate of a
/// binding-carrying shared trap block (W7 D2-ext).
pub const REFINE_TRAPS_DUPLICATED: &str = "refine_traps_duplicated";
/// Client-call element lists recovered by the tier-2b copy-loop trace
/// (W7 D9) — a subset of `client_args_resolved`.
pub const CLIENT_ARGS_VIA_COPY_LOOP: &str = "client_args_via_copy_loop";
/// Switches linked to a recovered `SymbolDispatch` table (W7 D6) — the
/// renderer/emitter names those arms by enum variant.
pub const REFINE_DISPATCH_LINKED: &str = "refine_dispatch_linked";
/// Trap leaves typed as bare `panic!()` sites (W7 D8) — each also
/// emits the `PanicWithoutErrorCode` diagnostic.
pub const REFINE_BARE_PANICS: &str = "refine_bare_panics";
/// Trap leaves typed as unwrap-shaped, tag-checked panics (W7 D8).
pub const REFINE_UNWRAPS: &str = "refine_unwraps";
/// Trap leaves typed as rustc's arithmetic overflow check — a guard the
/// source never wrote, which `#[contractimpl]` + `overflow-checks = true`
/// regenerate from the arithmetic itself.
pub const REFINE_ARITH_OVERFLOWS: &str = "refine_arith_overflows";
/// Loads from a literal address folded to the bytes the module's data
/// section puts there.
pub const REFINE_CONST_LOADS_FOLDED: &str = "refine_const_loads_folded";
/// Constant-address loads left alone because some store writes the same
/// bytes through a literal address — the `static mut` case, which the
/// initial image does not describe.
pub const REFINE_CONST_LOADS_MUTABLE: &str = "refine_const_loads_mutable";
/// Constant-address loads left alone because no one data segment covers
/// the width read: uninitialized memory, or a read across a boundary.
pub const REFINE_CONST_LOADS_UNCOVERED: &str = "refine_const_loads_uncovered";
/// Else-less, trap-armed guards this pass left standing, by the kind of
/// trap they hold.
///
/// The pass elides `ArithOverflow` and `DivisionGuard` and keeps the rest,
/// and counted only its removals — so a module where it removed nothing
/// read the same as one with no guards in it. These are the denominator.
/// A bare trap is the interesting bucket: the source wrote no branch at
/// all, so a guard carrying one is either a check rustc inserted that is
/// not yet classified, or a recogniser gap upstream.
pub const REFINE_OVERFLOW_GUARD_KEPT_BARE: &str = "refine_overflow_guard_kept_bare";
/// See [`REFINE_OVERFLOW_GUARD_KEPT_BARE`]: an `.unwrap()`-shaped trap,
/// which `marshalling::option_unwrap` owns rather than this pass.
pub const REFINE_OVERFLOW_GUARD_KEPT_UNWRAP: &str = "refine_overflow_guard_kept_unwrap";
/// See [`REFINE_OVERFLOW_GUARD_KEPT_BARE`]: any other classified trap.
pub const REFINE_OVERFLOW_GUARD_KEPT_OTHER: &str = "refine_overflow_guard_kept_other";
/// Arithmetic overflow guards removed — each also emits the
/// `MarshallingGuardElided` diagnostic, because deleting a *reachable*
/// trap is a behavioural claim resting on `overflow-checks = true`
/// regenerating it from the arithmetic we re-emit.
pub const REFINE_OVERFLOW_GUARDS_ELIDED: &str = "refine_overflow_guards_elided";
/// Switch arms structurally equal to their default, folded into the
/// wildcard (W7 D5).
pub const REFINE_SWITCH_ARMS_DEDUPED: &str = "refine_switch_arms_deduped";
/// Loops proven to a source shape and `LoopKind`-tagged (W7 D3).
pub const REFINE_LOOPS_CLASSIFIED: &str = "refine_loops_classified";
/// Labeled scopes whose only exit was a tail `Break` — i.e. falling off
/// their own end — elided along with that break. Structuring residue the
/// marshalling elision exposes when it folds a width dispatch.
pub const REFINE_SCOPES_FALLTHROUGH: &str = "refine_scopes_fallthrough";
/// `Break`s rewritten to a `Transfer` because they sat at a **tail exit** —
/// a position from which falling off the end reaches the same continuation
/// the break jumps to. Wasm spells `if`/`else` with forward branches and the
/// structurer reproduces them; these are the half that carry no information.
pub const REFINE_TAIL_EXIT_BREAKS: &str = "refine_tail_exit_breaks";
/// Scopes that kept their label because a real forward jump still names it.
/// The residue after tail-exit elision, and the sizing signal for whether an
/// `if`/`else` reconstruction is worth building.
pub const REFINE_SCOPES_LIVE_LABEL: &str = "refine_scopes_live_label";
/// Scopes whose guarded forward `Break` was recovered as an `else` arm,
/// deleting the label. Wasm spells `if`/`else` as a forward branch; this is
/// the half of that residue `REFINE_TAIL_EXIT_BREAKS` cannot reach.
pub const REFINE_SCOPE_TO_IF_ELSE: &str = "refine_scope_to_if_else";
/// Shared-else diamonds merged into one `&&` guard (W7 D7).
pub const REFINE_AND_MERGED: &str = "refine_and_merged";
/// Diamonds matching the D7 shape but blocked by the effect or
/// boolean-operand gate — the widening signal.
pub const REFINE_AND_MERGE_BLOCKED: &str = "refine_and_merge_blocked";

// ---------------------------------------------------------------------
// Marshalling elision
// ---------------------------------------------------------------------

/// Argument-decode results bound directly to the parameter they decode
/// (discriminant and payload loads both count).
pub const MARSHALLING_DECODE_COLLAPSED: &str = "marshalling_decode_collapsed";
/// 128-bit argument-decode results (discriminant, low limb, high limb)
/// rebound to the value, plus the type planted on that value.
pub const MARSHALLING_WIDE_DECODE_COLLAPSED: &str = "marshalling_wide_decode_collapsed";
/// 128-bit `IntoVal` helper calls collapsed to a wide join.
pub const MARSHALLING_WIDE_ENCODE_COLLAPSED: &str = "marshalling_wide_encode_collapsed";
/// 128-bit decode helper calls elided with their results.
pub const MARSHALLING_WIDE_CODEC_CALLS_ELIDED: &str = "marshalling_wide_codec_calls_elided";
/// Block-local frame loads forwarded from the store that reaches them,
/// on the high IR after the marshalling elisions.
pub const MARSHALLING_FRAME_LOADS_FORWARDED: &str = "marshalling_frame_loads_forwarded";
/// Calls to straight-line SDK wrapper helpers replaced by the inlined body.
pub const INLINE_WRAPPER_CALLS: &str = "inline_wrapper_calls";
/// Stores into a private shadow-stack frame that no load reads back.
pub const MARSHALLING_DEAD_FRAME_STORES: &str = "marshalling_dead_frame_stores";
/// Branches on a constant condition replaced by the arm they take.
pub const REFINE_CONST_BRANCHES_FOLDED: &str = "refine_const_branches_folded";
/// `#[contracttype]` struct unpacks recognised from their key table and
/// elided, the map value typed as the struct.
pub const MARSHALLING_UDT_DECODES_COLLAPSED: &str = "marshalling_udt_decodes_collapsed";
/// Frame-slot loads of an unpacked struct rewritten to field accesses.
pub const MARSHALLING_UDT_FIELDS_RECOVERED: &str = "marshalling_udt_fields_recovered";
/// Struct unpacks declined because the `(map, keys, frame, len)` operand
/// shape could not be read off the call.
pub const MARSHALLING_UDT_DECLINED_OPERANDS: &str = "marshalling_udt_declined_operands";
/// Struct unpacks declined because the key table could not be read out of
/// rodata — a runtime key array, or a position that did not resolve.
pub const MARSHALLING_UDT_DECLINED_KEYS: &str = "marshalling_udt_declined_keys";
/// Struct unpacks declined because no declared struct has exactly those
/// field names. The keys were read; nothing in the spec matches them.
pub const MARSHALLING_UDT_DECLINED_NO_STRUCT: &str = "marshalling_udt_declined_no_struct";
/// Struct unpacks declined because the map's provenance is not evidence of
/// the struct's type: not a host operation's result, not an entrypoint
/// parameter declared with it, and not a field of a struct already
/// recovered. This is the nested case when the outer struct was missed.
pub const MARSHALLING_UDT_DECLINED_EVIDENCE: &str = "marshalling_udt_declined_evidence";
/// Calls to a helper-shaped `#[contracttype]` struct decoder elided with
/// their out-parameter reads.
pub const MARSHALLING_UDT_HELPERS_COLLAPSED: &str = "marshalling_udt_helpers_collapsed";
/// Proven `Option` probes with a trapping None branch collapsed to
/// `.unwrap()` on the storage read.
pub const MARSHALLING_OPTIONS_UNWRAPPED: &str = "marshalling_options_unwrapped";
/// Calls to an SDK `Option` out-parameter storage helper replaced by the
/// `get(..).unwrap()` it makes.
pub const MARSHALLING_OPTION_HELPERS_COLLAPSED: &str = "marshalling_option_helpers_collapsed";
/// Helpers proven to return `Option<T>` through an out-parameter.
pub const MARSHALLING_OPTIONAL_OUT_HELPERS: &str = "marshalling_optional_out_helpers";
/// Call sites of those helpers whose every read of the result qualifies.
pub const MARSHALLING_OPTIONAL_OUT_SITES: &str = "marshalling_optional_out_sites";
/// Call sites of those helpers refused, for any reason.
pub const MARSHALLING_OPTIONAL_OUT_SITES_REFUSED: &str = "marshalling_optional_out_sites_refused";
/// Those helpers rewritten to return `Option<T>`, every call site with them.
pub const MARSHALLING_OPTIONAL_OUT_REWRITTEN: &str = "marshalling_optional_out_rewritten";
/// Helpers returning `(tag, value)` in two registers, the tag a different
/// constant on different paths.
pub const MARSHALLING_OPTIONAL_PAIR_HELPERS: &str = "marshalling_optional_pair_helpers";
/// Call sites of those helpers whose every read of the result qualifies.
pub const MARSHALLING_OPTIONAL_PAIR_SITES: &str = "marshalling_optional_pair_sites";
/// Call sites of those helpers refused, for any reason.
pub const MARSHALLING_OPTIONAL_PAIR_SITES_REFUSED: &str = "marshalling_optional_pair_sites_refused";
/// Those helpers rewritten to return `Option<T>`, every call site with them.
pub const MARSHALLING_OPTIONAL_PAIR_REWRITTEN: &str = "marshalling_optional_pair_rewritten";
/// Returned vecs rewritten to the tuple the spec declares.
pub const MARSHALLING_TUPLE_RETURNS_RECOVERED: &str = "marshalling_tuple_returns_recovered";
/// Returned vecs of a tuple-returning function left as vecs: read
/// elsewhere, or a component of another type.
pub const MARSHALLING_TUPLE_RETURNS_DECLINED: &str = "marshalling_tuple_returns_declined";
/// Decodes and re-encodes of a host length folded into the length.
pub const MARSHALLING_HOST_LEN_CODECS: &str = "marshalling_host_len_codecs";
/// 32-bit values whose single-mask re-encode was folded into the value.
pub const MARSHALLING_MASKED_ENCODES: &str = "marshalling_masked_encodes";
/// Arms of an inlined 128-bit encode folded into the value.
pub const MARSHALLING_WIDE_ENCODES_INLINE: &str = "marshalling_wide_encodes_inline";
/// Storage reads whose SDK `Option` branch folded into
/// `.unwrap_or(default)`.
pub const MARSHALLING_OPTION_DEFAULTS_RECOVERED: &str = "marshalling_option_defaults_recovered";
// Why an `unwrap_or` fold was declined. One of these fires for every
// `Option` branch the pass looked at and left alone, so they sum to the
// candidates it saw minus the ones it folded. Read them the way the
// `sret` ones are read: the gates are ordered, so an earlier bucket
// hides the ones after it, and a large count is not by itself a bug.
/// The branch tests the probe the other way round and has no `else`, so
/// the read is on the fall-through rather than on an arm. The early-return
/// sweep owns that shape and only when both sides return one value;
/// anything else falls between the two sweeps.
pub const MARSHALLING_OPTION_DEFAULT_DECLINED_READ_ON_FALL_THROUGH: &str =
    "marshalling_option_default_declined_read_on_fall_through";
/// The read's arm always traps, so the branch asserts rather than merges
/// and there is no value for a default to stand in for.
///
/// Measured on the held-out 25, all 10 are `if has(k) { panic!() }` — the
/// "already initialized" guard, which the emitter already spells
/// correctly. `marshalling::option_unwrap` takes the opposite polarity,
/// so a count here is not work either pass is missing. It exists so that
/// stays visible rather than inflating the control-flow bucket.
pub const MARSHALLING_OPTION_DEFAULT_DECLINED_ARM_ALWAYS_TRAPS: &str =
    "marshalling_option_default_declined_arm_always_traps";
/// The read's arm carries control flow that is not a trap guard, so there
/// is no one expression to fold the branch into.
pub const MARSHALLING_OPTION_DEFAULT_DECLINED_SOME_ARM_BRANCHES: &str =
    "marshalling_option_default_declined_some_arm_branches";
/// The `None` arm carries control flow, so it names no single default.
pub const MARSHALLING_OPTION_DEFAULT_DECLINED_NONE_ARM_BRANCHES: &str =
    "marshalling_option_default_declined_none_arm_branches";
/// An effectful binding on one of the arms besides the read, which the
/// fold would move onto the `None` path.
pub const MARSHALLING_OPTION_DEFAULT_DECLINED_ARM_HAS_EFFECTS: &str =
    "marshalling_option_default_declined_arm_has_effects";
/// The probe decides something besides this branch, so collapsing the
/// branch would leave the other use reading a value that no longer exists.
pub const MARSHALLING_OPTION_DEFAULT_DECLINED_PROBE_SHARED: &str =
    "marshalling_option_default_declined_probe_shared";
/// The arm holds no read of the probed entry, or more than one. Neither is
/// an `unwrap_or`: the first has nothing to default, the second would need
/// two.
pub const MARSHALLING_OPTION_DEFAULT_DECLINED_NOT_ONE_READ: &str =
    "marshalling_option_default_declined_not_one_read";
/// The merge is one this pass cannot address positionally — a phi with
/// other than two incoming edges, or both edges arriving from one arm.
pub const MARSHALLING_OPTION_DEFAULT_DECLINED_MERGE_SHAPE: &str =
    "marshalling_option_default_declined_merge_shape";
/// The branch merges nothing, so there is no value for a default to stand
/// in for. The `Option` is being tested, not read.
pub const MARSHALLING_OPTION_DEFAULT_DECLINED_NOTHING_MERGED: &str =
    "marshalling_option_default_declined_nothing_merged";
/// A struct default with a hoisted check on the arm: the default names no
/// single integer to evaluate the check against.
pub const MARSHALLING_OPTION_DEFAULT_DECLINED_STRUCT_WITH_CHECKS: &str =
    "marshalling_option_default_declined_struct_with_checks";
/// No single default reproduces every constant the other arm merged, so
/// there is no one expression to put in the `unwrap_or`.
pub const MARSHALLING_OPTION_DEFAULT_DECLINED_NO_COMMON_DEFAULT: &str =
    "marshalling_option_default_declined_no_common_default";
/// A hoisted check on the read's arm would fire with the read standing for
/// the default, so folding would trap where the original did not.
pub const MARSHALLING_OPTION_DEFAULT_DECLINED_CHECK_WOULD_FIRE: &str =
    "marshalling_option_default_declined_check_would_fire";
/// Storage reads whose SDK payload conversion folded into the read's type.
pub const MARSHALLING_TYPED_READS: &str = "marshalling_typed_reads";
/// `bool` <-> `Val` conversions folded into the `bool`.
pub const MARSHALLING_BOOL_CODECS: &str = "marshalling_bool_codecs";
/// Derived struct encodes folded back into the struct literal.
pub const MARSHALLING_UDT_ENCODES: &str = "marshalling_udt_encodes";
/// Pairs of limb selects read back as one 128-bit choice.
pub const REFINE_WIDE_SELECTS: &str = "refine_wide_selects";
/// Structs recovered from their own key table, where the module carries
/// no `contractspecv0` to declare them.
pub const MARSHALLING_UDT_STRUCTS_SYNTHESIZED: &str = "marshalling_udt_structs_synthesized";
/// Two-form scalar unpacks folded into the value they unpack.
pub const MARSHALLING_SCALAR_DECODES: &str = "marshalling_scalar_decodes";
/// Argument vectors of fully-resolved cross-contract calls, retired.
pub const MARSHALLING_CLIENT_ARG_VECS: &str = "marshalling_client_arg_vecs";
/// Struct-field decodes folded into the field's declared type.
pub const MARSHALLING_FIELD_TYPES: &str = "marshalling_field_types";
/// Entrypoint parameters whose declared type was read off the wrapper's
/// own conversion check, where the module carries no spec section.
pub const MARSHALLING_SPEC_PARAMS: &str = "marshalling_spec_params";
/// Struct fields whose declared type was read off the derived
/// conversion's own check, where the module carries no spec section.
pub const MARSHALLING_SPEC_FIELDS: &str = "marshalling_spec_fields";
/// Entrypoints recovered as returning nothing, because every return site
/// hands back the constant `Void`.
pub const MARSHALLING_SPEC_RETURNS: &str = "marshalling_spec_returns";
/// Call-site projections replaced by the callee's constant return.
pub const INTERPROC_CONST_RETURNS: &str = "interproc_const_returns";
/// Helpers whose two-register wide return was promoted to the value.
pub const INTERPROC_WIDE_RETURNS: &str = "interproc_wide_returns";
/// Limb OR trees read back as a test on the wide values.
pub const REFINE_WIDE_ZERO_TESTS: &str = "refine_wide_zero_tests";
/// Lexicographic half-comparisons read back as 128-bit comparisons.
pub const REFINE_WIDE_COMPARES: &str = "refine_wide_compares";
/// By-pointer struct arguments promoted to the struct.
pub const INTERPROC_STRUCT_ARGS: &str = "interproc_struct_args";
/// Discriminant tests read back as tests on the enum's variant.
pub const MARSHALLING_ENUM_DISCRIMINANTS: &str = "marshalling_enum_discriminants";
/// Enum decode-and-re-encode round trips folded back to the value.
pub const MARSHALLING_ENUM_ENCODES: &str = "marshalling_enum_encodes";
/// Helpers whose two-register wide parameter was promoted to the value.
pub const INTERPROC_WIDE_PARAMS: &str = "interproc_wide_params";
/// 128-bit sums and differences recovered from their limbs.
pub const REFINE_WIDE_ARITH: &str = "refine_wide_arith";
/// Half-merges given a merge of the whole value.
pub const REFINE_WIDE_PHIS: &str = "refine_wide_phis";
/// Merges only one value still reached, retired to renames of it.
pub const REFINE_TRIVIAL_PHIS: &str = "refine_trivial_phis";
/// `U32Val` encodes whose folded addend was recovered as arithmetic, and
/// stores of encodes named by their `u32`.
pub const MARSHALLING_FOLDED_ENCODES: &str = "marshalling_folded_encodes";
/// Narrowings of values already 32 bits wide, replaced by the values.
pub const REFINE_WIDTH_FOLDS: &str = "refine_width_folds";
/// Returned `select`s turned back into the `if`/`else` they compile from.
pub const REFINE_SELECTS_BRANCHED: &str = "refine_selects_branched";
/// Calls to an argument-decode helper neutralised once their results
/// were rebound.
pub const MARSHALLING_DECODE_CALLS_ELIDED: &str = "marshalling_decode_calls_elided";
/// Return-value encodes collapsed to the value, at the ABI boundary.
pub const MARSHALLING_ENCODE_COLLAPSED: &str = "marshalling_encode_collapsed";
/// Width-dispatch branches folded away once both arms were proven to
/// produce the same value.
pub const MARSHALLING_DISPATCH_FOLDED: &str = "marshalling_dispatch_folded";
/// SDK argument type-check guards removed — each also emits the
/// `MarshallingGuardElided` diagnostic, because deleting a trap is a
/// behavioural claim and should be reviewable without diffing outputs.
pub const MARSHALLING_GUARDS_ELIDED: &str = "marshalling_guards_elided";

// Why each `Region::If` the guard pass looked at was *not* elided. The pass
// could previously only report the guards it removed, so "it leaves ~150
// behind" was an impression rather than a work list — the same blind spot
// `memory::promote` and `memory::sret` had before their censuses, and in both
// of those cases the census overturned the standing assumption about where
// the work was. Every `Region::If` in the module lands in exactly one of
// these or in `MARSHALLING_GUARDS_ELIDED`, so the buckets and the removals
// sum to the total; a mismatch means a gate gained an arm here and lost one
// there.
/// The `If` has an else arm, so it is a two-way branch, not a guard.
pub const MARSHALLING_GUARD_DECLINED_HAS_ELSE: &str = "marshalling_guard_declined_has_else";
/// The taken arm does real work rather than trapping — includes the
/// `if ok { body } … panic!()` polarity, which is the guard inverted.
pub const MARSHALLING_GUARD_DECLINED_ARM_NOT_TRAP: &str =
    "marshalling_guard_declined_arm_not_trap";
/// A tag check whose trap arm is the *match*, not the mismatch.
pub const MARSHALLING_GUARD_DECLINED_TAG_NOT_NEGATED: &str =
    "marshalling_guard_declined_tag_not_negated";
/// A tag check on a value that is not one of this entrypoint's declared
/// parameters — a helper's check has no dispatch wrapper to move to.
pub const MARSHALLING_GUARD_DECLINED_TAG_NOT_PARAM: &str =
    "marshalling_guard_declined_tag_not_param";
/// The tested tag does not carry the parameter's declared type.
pub const MARSHALLING_GUARD_DECLINED_TAG_MISMATCH: &str =
    "marshalling_guard_declined_tag_mismatch";
/// An `Eq`/`Ne` whose operands do not both trace to constants — typically
/// because the trace ends in an unrecovered value.
pub const MARSHALLING_GUARD_DECLINED_COMPARE_OPAQUE: &str =
    "marshalling_guard_declined_compare_opaque";
/// A constant comparison whose trap arm *is* taken: a real failure path,
/// correctly kept.
pub const MARSHALLING_GUARD_DECLINED_COMPARE_TAKEN: &str =
    "marshalling_guard_declined_compare_taken";
/// Looked like a length check but is not `bytes_len(p) != N` on a parameter
/// declared `BytesN<N>`.
pub const MARSHALLING_GUARD_DECLINED_LENGTH_UNMATCHED: &str =
    "marshalling_guard_declined_length_unmatched";
/// The condition is none of the three recognised shapes.
pub const MARSHALLING_GUARD_DECLINED_SHAPE: &str = "marshalling_guard_declined_shape";
/// The same SDK guard written inside out — `if ok { work; return }` with the
/// trap as the successor. Passes every content gate; only the rewrite that
/// removes it is missing. This is the recoverable share of
/// `MARSHALLING_GUARD_DECLINED_ARM_NOT_TRAP`.
pub const MARSHALLING_GUARD_DECLINED_INVERTED: &str = "marshalling_guard_declined_inverted";
/// A gate declined without naming a bucket. Non-zero means this list is
/// stale, not that a new failure mode exists.
pub const MARSHALLING_GUARD_DECLINED_OTHER: &str = "marshalling_guard_declined_other";

/// Balanced shadow-stack prologue/epilogue brackets removed.
pub const MARSHALLING_FRAMES_ELIDED: &str = "marshalling_frames_elided";
/// Functions whose out-parameter was reconstructed as a real return
/// value — the wide-return recovery.
pub const MARSHALLING_WIDE_RETURNS_RECOVERED: &str = "marshalling_wide_returns_recovered";
/// Slot loads rebound to a component of the call that produced them.
pub const MARSHALLING_WIDE_LOADS_REBOUND: &str = "marshalling_wide_loads_rebound";

// ---------------------------------------------------------------------
// Shadow-stack memory promotion
// ---------------------------------------------------------------------

/// Functions whose read-only pointer parameter became scalar parameters.
pub const MEMORY_ARGS_PROMOTED: &str = "memory_args_promoted";

/// Loads moved out of a promoted callee and onto its call sites. Counted
/// per call site, because that is where the work lands.
pub const MEMORY_LOADS_HOISTED: &str = "memory_loads_hoisted";

/// Loads bound to a preceding store's value within one block, without any
/// escape analysis. Distinct from `MEMORY_LOADS_FORWARDED`, which counts
/// the ones `promote` retires as part of promoting a whole slot.
pub const MEMORY_LOADS_FORWARDED_LOCALLY: &str = "memory_loads_forwarded_locally";
/// Fixed-count frame-slot loops (the `[Val::VOID; N]` fill and the
/// element copy behind `vec![…]`) unrolled into straight-line stores.
pub const MEMORY_FILL_LOOPS_UNROLLED: &str = "memory_fill_loops_unrolled";

/// Functions whose `sret` out-parameter became a real multi-value return.
pub const MEMORY_SRET_CONVERTED: &str = "memory_sret_converted";
/// Shadow-stack slots promoted from linear memory to SSA values.
pub const MEMORY_SLOTS_PROMOTED: &str = "memory_slots_promoted";
/// Slots refused because two accesses at one offset disagree about width or
/// type — the bytes are being reinterpreted, not read as a variable.
pub const MEMORY_SLOT_REFUSED_CONFLICT: &str = "memory_slot_refused_conflict";
/// Slots refused because nothing writes them, so there is no value to
/// forward and no honest one to invent.
pub const MEMORY_SLOT_REFUSED_UNWRITTEN: &str = "memory_slot_refused_unwritten";
/// Slots refused because a callee can reach their bytes.
pub const MEMORY_SLOT_REFUSED_ESCAPED: &str = "memory_slot_refused_escaped";
/// Slots refused because some load is not dominated by a store to the same
/// slot: on at least one path the read comes first, and there is no value to
/// give it.
pub const MEMORY_SLOT_REFUSED_UNDOMINATED: &str = "memory_slot_refused_undominated";

// Why a frame was declined. `promote` rejects a frame **whole** — an
// address it cannot follow may alias any slot — so knowing which gate
// spoke is the difference between "the shadow stack is hard" and a
// specific pass to write next.
//
// These exist because the same census was taken by hand twice and went
// stale both times. A frame's escape kind decides which pass can unblock
// it: a callee that only *writes* through the pointer is `sret`'s, one
// that only *reads* is `argpromote`'s, and one that passes it onward is
// nobody's yet.
/// Frames declined because an address reached a callee that only writes
/// through it — `sret`'s territory.
pub const MEMORY_FRAME_DECLINED_WRITE_ONLY: &str = "memory_frame_declined_write_only";
/// A frame declined because an address was consumed by an operator that is
/// not a call — arithmetic `canon_addr` cannot fold, or a tag chain the
/// `U32Val` recogniser does not match.
pub const MEMORY_FRAME_DECLINED_ADDRESS_ARITH: &str = "memory_frame_declined_address_arith";
/// A frame declined because an address reached a host import other than
/// through a recognised `U32Val` position argument.
pub const MEMORY_FRAME_DECLINED_HOST_CALL: &str = "memory_frame_declined_host_call";
/// A frame declined because a terminator carried an address into a block
/// parameter, merging it with whatever the other edges bring.
pub const MEMORY_FRAME_DECLINED_BLOCK_PARAM: &str = "memory_frame_declined_block_param";
/// A frame declined because an address was stored as a value or aliased
/// into one.
pub const MEMORY_FRAME_DECLINED_STORED_AS_VALUE: &str = "memory_frame_declined_stored_as_value";
/// A frame declined because a callee's access through the pointer is not at
/// a constant offset from it — an indexed store, say. Bounding these needs
/// the index's range, which the IR does not carry.
pub const MEMORY_FRAME_DECLINED_OFFSET_NOT_CONST: &str =
    "memory_frame_declined_offset_not_const";
/// A frame declined because the pointer escapes the callee as well, so its
/// footprint is whatever the next callee does with it.
pub const MEMORY_FRAME_DECLINED_ESCAPES_AGAIN: &str = "memory_frame_declined_escapes_again";

// Why `sret` declined a candidate. The write-only frames above are its
// territory; these say which of its own gates then refused, which is the
// difference between "sret is the blocker" and knowing what to change.
//
// **A decline counts once per fixpoint iteration; a conversion counts once.**
// A refused function is re-examined and re-counted on every iteration, while
// a converted one is gone from the candidate set, so the ratio between
// `MEMORY_SRET_CONVERTED` and these is *not* a ratio of functions — divide a
// decline count by the iteration count before comparing them. Corpus-wide the
// distinct-function figures are 31 converted against 13 refused; the raw
// counters read 31 against 43.
/// `sret` candidates declined because a storing block does not dominate
/// every return — the `Result`/`Option` ABI, whose payload is written only
/// under its own tag.
pub const MEMORY_SRET_DECLINED_PATH_DEPENDENT: &str = "memory_sret_declined_path_dependent";
/// The two-slot form of the above: a discriminant at `+0` and one payload
/// word at `+8`, which is `Option<T>` or `Result<T, E>` returned by
/// pointer with a single-word payload.
///
/// Counted apart because it is the recoverable slice. Recovering it as a
/// sum type needs no invented value for the untaken path, which is the
/// design objection that stopped this item. Held-out: 45 of the 94
/// path-dependent refusals.
pub const MEMORY_SRET_DECLINED_PATH_DEPENDENT_TWO_SLOT: &str =
    "memory_sret_declined_path_dependent_two_slot";
/// `sret` candidates with no stores through the out-pointer at all: the
/// parameter is not an out-pointer.
///
/// **This is the "not a candidate" bucket, and it is the large one.** It
/// reported 9 while `NON_STORE_USE` reported 228, because the non-store gate
/// returned before this one was ever reached; ordering the gates so that
/// "is there an out-pointer" is answered first moved the 228 here, where the
/// two of them belong.
pub const MEMORY_SRET_DECLINED_NO_STORES: &str = "memory_sret_declined_no_stores";
/// `sret` candidates declined because the out-pointer reached an operator
/// that is not a store — most often another call.
///
/// Counts only candidates that really are out-pointers: something is stored
/// through this one *and* it escapes. Measured after that fix, corpus-wide:
/// **zero**. The forwarding cascade this bucket was thought to describe does
/// not exist on this corpus.
pub const MEMORY_SRET_DECLINED_NON_STORE_USE: &str = "memory_sret_declined_non_store_use";
/// `sret` candidates declined because the pointer itself was written to
/// memory rather than written through.
///
/// Enumerated late: the gate existed from the start but had no arm in
/// `report_declines`, so it spent its life in `OTHER`.
pub const MEMORY_SRET_DECLINED_STORED_AS_VALUE: &str = "memory_sret_declined_stored_as_value";
/// `sret` candidates refused by a `?` guard that names no gate — a malformed
/// or unmodelled operand shape.
///
/// Counted because these declines previously appeared in no bucket at all,
/// so the census's total was smaller than the number of refusals.
pub const MEMORY_SRET_DECLINED_UNREPORTED: &str = "memory_sret_declined_unreported";
/// `sret` candidates declined because the out-pointer is *read* as well as
/// written, so it is an in-out parameter rather than an out-parameter.
pub const MEMORY_SRET_DECLINED_READ: &str = "memory_sret_declined_read";
/// `sret` candidates declined because two stores hit one offset, making the
/// slot's value at return ambiguous.
pub const MEMORY_SRET_DECLINED_TWO_STORES: &str = "memory_sret_declined_two_stores";
/// `sret` candidates declined by a gate outside the enumerated ones.
pub const MEMORY_SRET_DECLINED_OTHER: &str = "memory_sret_declined_other";
/// Frames declined because an address reached a callee that only reads
/// through it — `argpromote`'s territory.
pub const MEMORY_FRAME_DECLINED_READ_ONLY: &str = "memory_frame_declined_read_only";
/// Frames declined because an address reached a callee that forwards it
/// onward, or that no analysis here can characterise.
pub const MEMORY_FRAME_DECLINED_OPAQUE: &str = "memory_frame_declined_opaque";
/// Frames declined for a reason other than a call: a stored-as-value
/// address, a returned one, or one that is branched on.
pub const MEMORY_FRAME_DECLINED_OTHER: &str = "memory_frame_declined_other";
/// Frames declined because two slots partially overlap, so a write to one
/// is a write to the other.
pub const MEMORY_FRAME_DECLINED_OVERLAP: &str = "memory_frame_declined_overlap";
/// Slot loads replaced by the value the slot held.
pub const MEMORY_LOADS_FORWARDED: &str = "memory_loads_forwarded";
/// Slot stores retired once their value was forwarded.
pub const MEMORY_STORES_REMOVED: &str = "memory_stores_removed";

// ---------------------------------------------------------------------
// Terminal unrecognized-host-call scan (headline denominator input)
// ---------------------------------------------------------------------

/// Host imports that survived the whole pipeline unrecognized — the
/// headline "host interactions" miss channel (spec E2).
pub const UNRECOGNISED_HOST_CALL: &str = "unrecognised_host_call";

// ---- Type recovery (the `type-infer` pass) ----
/// Bindings with a proven [`sordec_ir::IrType::Known`] type.
pub const TYPES_KNOWN: &str = "types_known";
/// Bindings with a propagation-derived [`sordec_ir::IrType::Inferred`] type.
pub const TYPES_INFERRED: &str = "types_inferred";
/// Bindings still [`sordec_ir::IrType::Unknown`] after propagation.
pub const TYPES_UNKNOWN: &str = "types_unknown";
/// Times inter-procedural evidence named a different type at the same
/// certainty rank as the incumbent, and was therefore dropped rather than
/// displacing it. A visible rate for a deliberately conservative choice;
/// see `type_infer::improve_tracked`.
pub const TYPES_EVIDENCE_DISAGREEMENTS: &str = "types_evidence_disagreements";

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
///
/// Grouped by coverage section: the recognition/headline keys (F1–F8)
/// first, then the structuring section keys (A6/W8) — declutter,
/// treeify, structuring fallback + census, and region refinement.
#[must_use]
pub fn surfaced_keys() -> &'static [&'static str] {
    &[
        // Recognition + headline (F1–F8).
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
        ENUM_KEY_UNIONS_SYNTHESIZED,
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
        VAL_PACKED_COMPARE_MASKED,
        VAL_PACKED_COMPARE_ORDERED,
        VAL_PACKED_COMPARE_BOOL,
        I128_BUILTINS_IDENTIFIED,
        I128_BUILTIN_CALLS_REWRITTEN,
        WIDE_FOLDED,
        UNRECOGNISED_HOST_CALL,
        // Structuring section — de-cluttering (W3).
        DECLUTTER_ALIASES_RESOLVED,
        DECLUTTER_PHIS_PRUNED,
        DECLUTTER_DEAD_PARAMS_PRUNED,
        DECLUTTER_JUMPS_THREADED,
        DECLUTTER_RETURNS_INLINED,
        DECLUTTER_TRAPS_INLINED,
        DECLUTTER_CHAINS_MERGED,
        DECLUTTER_DEAD_BLOCKS_CLEARED,
        DECLUTTER_DEAD_VALUES_UNSCHEDULED,
        // Structuring section — treeification (B6).
        TREEIFY_INLINE,
        TREEIFY_PINNED_SINGLE_USE,
        TREEIFY_DEAD_RESIDUE,
        // Structuring section — fallback + census (C2/A6).
        STRUCTURING_FALLBACK,
        // Type recovery (the `type-infer` pass).
        TYPES_KNOWN,
        TYPES_INFERRED,
        TYPES_UNKNOWN,
        TYPES_EVIDENCE_DISAGREEMENTS,
        STRUCTURING_FUNCTIONS_TOTAL,
        STRUCTURING_FUNCTIONS_STRUCTURED,
        STRUCTURING_LOOPS_WHILE_TOP,
        STRUCTURING_LOOPS_DO_WHILE_BOTTOM,
        STRUCTURING_LOOPS_GUARDED_DO_WHILE,
        STRUCTURING_LOOPS_INFINITE,
        STRUCTURING_LOOPS_UNCLASSIFIED,
        STRUCTURING_SWITCHES,
        STRUCTURING_LABELED_BREAKS,
        STRUCTURING_LABELED_CONTINUES,
        // Structuring section — region refinement (D-category).
        REFINE_POLARITY_FLIPPED,
        REFINE_GUARDS_HOISTED,
        REFINE_SCOPES_FALLTHROUGH,
        REFINE_TAIL_EXIT_BREAKS,
        REFINE_SCOPES_LIVE_LABEL,
        REFINE_SCOPE_TO_IF_ELSE,
        REFINE_TRAPS_INLINED,
        REFINE_SHARED_TRAP_WITH_BINDINGS,
        REFINE_TRAPS_DUPLICATED,
        CLIENT_ARGS_VIA_COPY_LOOP,
        REFINE_DISPATCH_LINKED,
        REFINE_BARE_PANICS,
        REFINE_UNWRAPS,
        REFINE_ARITH_OVERFLOWS,
        REFINE_OVERFLOW_GUARDS_ELIDED,
        REFINE_CONST_LOADS_FOLDED,
        REFINE_CONST_LOADS_MUTABLE,
        REFINE_CONST_LOADS_UNCOVERED,
        REFINE_OVERFLOW_GUARD_KEPT_BARE,
        REFINE_OVERFLOW_GUARD_KEPT_UNWRAP,
        REFINE_OVERFLOW_GUARD_KEPT_OTHER,
        REFINE_SWITCH_ARMS_DEDUPED,
        REFINE_LOOPS_CLASSIFIED,
        REFINE_AND_MERGED,
        REFINE_AND_MERGE_BLOCKED,
        // Marshalling elision.
        MARSHALLING_DECODE_COLLAPSED,
        MARSHALLING_WIDE_DECODE_COLLAPSED,
        MARSHALLING_WIDE_ENCODE_COLLAPSED,
        MARSHALLING_WIDE_CODEC_CALLS_ELIDED,
        MARSHALLING_FRAME_LOADS_FORWARDED,
        INLINE_WRAPPER_CALLS,
        MARSHALLING_DEAD_FRAME_STORES,
        REFINE_CONST_BRANCHES_FOLDED,
        MARSHALLING_UDT_DECODES_COLLAPSED,
        MARSHALLING_UDT_FIELDS_RECOVERED,
        MARSHALLING_UDT_HELPERS_COLLAPSED,
        MARSHALLING_OPTIONS_UNWRAPPED,
        MARSHALLING_OPTION_HELPERS_COLLAPSED,
        MARSHALLING_OPTIONAL_OUT_HELPERS,
        MARSHALLING_OPTIONAL_OUT_SITES,
        MARSHALLING_OPTIONAL_OUT_SITES_REFUSED,
        MARSHALLING_OPTIONAL_OUT_REWRITTEN,
        MARSHALLING_OPTIONAL_PAIR_HELPERS,
        MARSHALLING_OPTIONAL_PAIR_SITES,
        MARSHALLING_OPTIONAL_PAIR_SITES_REFUSED,
        MARSHALLING_OPTIONAL_PAIR_REWRITTEN,
        MARSHALLING_TUPLE_RETURNS_RECOVERED,
        MARSHALLING_TUPLE_RETURNS_DECLINED,
        MARSHALLING_HOST_LEN_CODECS,
        MARSHALLING_MASKED_ENCODES,
        MARSHALLING_WIDE_ENCODES_INLINE,
        MARSHALLING_OPTION_DEFAULTS_RECOVERED,
        MARSHALLING_OPTION_DEFAULT_DECLINED_READ_ON_FALL_THROUGH,
        MARSHALLING_OPTION_DEFAULT_DECLINED_ARM_ALWAYS_TRAPS,
        MARSHALLING_OPTION_DEFAULT_DECLINED_SOME_ARM_BRANCHES,
        MARSHALLING_OPTION_DEFAULT_DECLINED_NONE_ARM_BRANCHES,
        MARSHALLING_OPTION_DEFAULT_DECLINED_ARM_HAS_EFFECTS,
        MARSHALLING_OPTION_DEFAULT_DECLINED_PROBE_SHARED,
        MARSHALLING_OPTION_DEFAULT_DECLINED_NOT_ONE_READ,
        MARSHALLING_OPTION_DEFAULT_DECLINED_MERGE_SHAPE,
        MARSHALLING_OPTION_DEFAULT_DECLINED_NOTHING_MERGED,
        MARSHALLING_OPTION_DEFAULT_DECLINED_STRUCT_WITH_CHECKS,
        MARSHALLING_OPTION_DEFAULT_DECLINED_NO_COMMON_DEFAULT,
        MARSHALLING_OPTION_DEFAULT_DECLINED_CHECK_WOULD_FIRE,
        MARSHALLING_TYPED_READS,
        MARSHALLING_BOOL_CODECS,
        MARSHALLING_UDT_ENCODES,
        MARSHALLING_FIELD_TYPES,
        MARSHALLING_CLIENT_ARG_VECS,
        MARSHALLING_SCALAR_DECODES,
        MARSHALLING_UDT_STRUCTS_SYNTHESIZED,
        REFINE_WIDE_SELECTS,
        MARSHALLING_SPEC_PARAMS,
        MARSHALLING_SPEC_FIELDS,
        MARSHALLING_SPEC_RETURNS,
        MARSHALLING_ENUM_DISCRIMINANTS,
        MARSHALLING_ENUM_ENCODES,
        INTERPROC_CONST_RETURNS,
        INTERPROC_WIDE_RETURNS,
        INTERPROC_WIDE_PARAMS,
        INTERPROC_STRUCT_ARGS,
        REFINE_WIDE_ZERO_TESTS,
        REFINE_WIDE_COMPARES,
        REFINE_WIDE_ARITH,
        REFINE_WIDE_PHIS,
        REFINE_TRIVIAL_PHIS,
        MARSHALLING_FOLDED_ENCODES,
        REFINE_WIDTH_FOLDS,
        REFINE_SELECTS_BRANCHED,
        MARSHALLING_DECODE_CALLS_ELIDED,
        MARSHALLING_ENCODE_COLLAPSED,
        MARSHALLING_DISPATCH_FOLDED,
        MARSHALLING_GUARDS_ELIDED,
        MARSHALLING_GUARD_DECLINED_HAS_ELSE,
        MARSHALLING_GUARD_DECLINED_ARM_NOT_TRAP,
        MARSHALLING_GUARD_DECLINED_TAG_NOT_NEGATED,
        MARSHALLING_GUARD_DECLINED_TAG_NOT_PARAM,
        MARSHALLING_GUARD_DECLINED_TAG_MISMATCH,
        MARSHALLING_GUARD_DECLINED_COMPARE_OPAQUE,
        MARSHALLING_GUARD_DECLINED_COMPARE_TAKEN,
        MARSHALLING_GUARD_DECLINED_LENGTH_UNMATCHED,
        MARSHALLING_GUARD_DECLINED_SHAPE,
        MARSHALLING_GUARD_DECLINED_INVERTED,
        MARSHALLING_GUARD_DECLINED_OTHER,
        MARSHALLING_FRAMES_ELIDED,
        MARSHALLING_WIDE_RETURNS_RECOVERED,
        MARSHALLING_WIDE_LOADS_REBOUND,
        MEMORY_ARGS_PROMOTED,
        MEMORY_LOADS_HOISTED,
        MEMORY_LOADS_FORWARDED_LOCALLY,
        MEMORY_FILL_LOOPS_UNROLLED,
        MEMORY_SRET_CONVERTED,
        MEMORY_SLOTS_PROMOTED,
        MEMORY_FRAME_DECLINED_WRITE_ONLY,
        MEMORY_SRET_DECLINED_PATH_DEPENDENT,
        MEMORY_SRET_DECLINED_PATH_DEPENDENT_TWO_SLOT,
        MEMORY_SRET_DECLINED_NO_STORES,
        MEMORY_SRET_DECLINED_NON_STORE_USE,
        MEMORY_SRET_DECLINED_READ,
        MEMORY_SRET_DECLINED_TWO_STORES,
        MEMORY_SRET_DECLINED_OTHER,
        MEMORY_FRAME_DECLINED_READ_ONLY,
        MEMORY_FRAME_DECLINED_OPAQUE,
        MEMORY_FRAME_DECLINED_OTHER,
        MEMORY_FRAME_DECLINED_OVERLAP,
        MEMORY_LOADS_FORWARDED,
        MEMORY_STORES_REMOVED,
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
