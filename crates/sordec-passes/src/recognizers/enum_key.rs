//! The enum storage-key recognizer (C5-adjacent; spec D2.3's key
//! substrate).
//!
//! A `#[contracttype]` enum key (`DataKey::Admin`-class) reaches a
//! storage host call as an opaque `VecObject` built by **one shared
//! constructor helper**. The discriminant reaches that helper through
//! one of two channels, both verified on the corpus:
//!
//! - **By pointer** (mixed enums — token): the caller stores the
//!   discriminant (+ payload) into its shadow-stack frame and passes a
//!   pointer. No register-level channel ever sees the variant choice —
//!   it travels through memory, which is why this pass rides on
//!   [`frame_facts`](crate::dataflow::frame_facts) rather than the
//!   [`Resolver`](crate::dataflow::Resolver) alone.
//! - **By value** (all-unit enums — timelock, dex): the discriminant
//!   arrives in a register argument, resolvable by the `Resolver`.
//!
//! A storage op whose key is the enclosing helper's own *parameter*
//! (`is_initialized(key)`-class wrappers) is named by a **meet over
//! every caller's key argument** — all must construct the same
//! variant. A genuinely polymorphic helper (dex's `get_instance_value`
//! serving `TokenA`/`TokenB`/…, timelock's shared `has`) therefore
//! stays honestly unnamed; recovering those requires per-callsite
//! cloning, a structuring-era concern.
//!
//! ## Evidence gate (all parts required — bail otherwise, never guess)
//!
//! 1. **Constructor summary** (per helper `H`, memoized): `H` is
//!    non-exported; its entry block holds exactly one full-width
//!    param-relative load before any possible memory write (the
//!    discriminant slot); the symbol-wrapper callsites inside `H` have
//!    locally-constant `(pos, len)` args naming valid symbol texts in
//!    rodata.
//! 2. **Registry gate**: exactly one `contractspecv0` union whose
//!    case-name set equals the constructed text set. The spec section
//!    is authoritative for the enum name and variant names; without it
//!    (stripped builds) this pass recognizes nothing.
//! 3. **Per-callsite discriminant**: the caller's frame facts at the
//!    callsite yield a constant `d < |cases|` for the discriminant
//!    slot. One sole-caller hop is allowed when the pointer is the
//!    enclosing helper's own parameter.
//! 4. **Footprint cross-check**: payload facts behind the discriminant
//!    slot exist iff `cases[d]` has fields.
//!
//! The one non-witnessed link is *discriminant value → declaration
//! index* (rustc assigns tag values in declaration order for this enum
//! shape; a niche-optimized layout has no stored tag and simply fails
//! gate 3). It is cross-checked by gates 2 and 4 and recorded in every
//! provenance note — Inferred-grade evidence by construction, per the
//! [`EnumKey`] rustdoc.
//!
//! Like `const-prop`, this pass bypasses the `is_recognized` skip
//! guard: its domain is already-`Known` storage ops with
//! `resolved_key: None`. Idempotent — a filled slot no longer matches.

use std::collections::{BTreeSet, HashMap};

use sordec_common::{
    Diagnostic, FuncId, IrId, LiftDiagnosticCode, Location, ProvenanceSource, ValueId,
};
use sordec_ir::{EnumKey, Expr, HighFunction, HighIr, KnownOp, MemWidth, SemanticOp};

use super::symbols::{unique_union_index_by_cases, valid_symbol_text};
use super::{apply_rewrites, Rewrite};
use crate::dataflow::{
    block_containing, canon_addr, facts_before, may_write_memory, trace_int,
    trace_u32val, CallIndex, Resolver,
};
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "enum-key";

// Metric counter keys.
/// Storage ops whose key was named as an enum variant.
const M_KEY_NAMED: &str = "enum_key_named";
/// Distinct helpers that summarized as enum-key constructors.
const M_CTOR_MATCHED: &str = "enum_key_ctor_matched";
/// Constructor-shaped keys that stayed honestly unnamed (the
/// remaining-work signal).
const M_UNRESOLVED: &str = "enum_key_unresolved";

/// Nesting cap for locating the `SymbolNew` op behind a wrapper call
/// (the SDK's `Symbol::new` sits one or two tiny helpers deep).
const WRAPPER_DEPTH: u32 = 2;

/// The enum storage-key recognizer pass. Stateless between runs.
#[derive(Debug, Default, Clone, Copy)]
pub struct EnumKeyPass;

/// How a constructor helper receives the variant discriminant.
enum DiscChannel {
    /// Mixed enums (payload variants exist): the caller stores the
    /// discriminant (+ payload) into a frame slot and passes a pointer.
    ByPointer {
        /// Which parameter carries the variant-slot pointer.
        param: usize,
        /// Byte offset of the discriminant relative to that pointer.
        offset: u32,
        /// Exact width of the discriminant load.
        width: MemWidth,
    },
    /// All-unit enums (no payload anywhere): the discriminant travels
    /// by value in a register argument. No fixed position is recorded —
    /// at each callsite, exactly one distinct in-range constant must
    /// appear among the arguments (out-pointers are runtime stack
    /// addresses and never resolve to small constants).
    ByValue,
}

/// What one helper function proved to be, memoized per [`FuncId`].
struct CtorSummary {
    /// Index of the matched union in `soroban_facts.types.unions`.
    union_idx: usize,
    /// How the discriminant reaches the helper.
    disc: DiscChannel,
}

/// Outcome of inspecting one storage op's key.
enum Naming {
    /// Full evidence gate passed.
    Named(EnumKey, String),
    /// Constructor-shaped key, but some gate failed — count it.
    Unresolved,
    /// Not this pass's shape (symbol keys, literals, non-call chains).
    NotACandidate,
}

impl Pass<HighIr> for EnumKeyPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();

        // Gate 2 precondition: no spec section (stripped builds) or no
        // unions → nothing can be named; stay silent and honest.
        let has_unions = ir
            .soroban_facts
            .as_ref()
            .is_some_and(|f| !f.types.unions.is_empty());
        if !has_unions {
            return result;
        }

        // Phase A — read-only scan.
        let calls = CallIndex::build(ir);
        let mut resolver = Resolver::new(ir, &calls);
        let mut summaries: HashMap<FuncId, Option<CtorSummary>> = HashMap::new();
        let mut planned: HashMap<FuncId, Vec<Rewrite>> = HashMap::new();

        for func in &ir.functions {
            for (id, binding) in func.bindings.iter() {
                let Expr::Semantic(SemanticOp::Known(op)) = &binding.expr else {
                    continue;
                };
                let Some(key) = unresolved_key_of(op) else {
                    continue;
                };
                match try_name_key(ir, &calls, &mut resolver, &mut summaries, func, key) {
                    Naming::Named(enum_key, note) => {
                        planned.entry(func.id).or_default().push(Rewrite {
                            id,
                            expr: Expr::Semantic(SemanticOp::Known(with_resolved_key(
                                op, enum_key,
                            ))),
                            // The op's ABI result type was set at
                            // recognition; the key naming proves no type.
                            ty: None,
                            source: ProvenanceSource::SdkPattern,
                            note,
                            metric: M_KEY_NAMED,
                        });
                    }
                    Naming::Unresolved => {
                        result.metrics.increment(M_UNRESOLVED, 1);
                        result.diagnostics.push(
                            Diagnostic::warning(
                                LiftDiagnosticCode::UnrecognisedStoragePattern,
                                "",
                            )
                            .at(Location::Value {
                                func: func.id,
                                value: id.index(),
                            }),
                        );
                    }
                    Naming::NotACandidate => {}
                }
            }
        }
        let matched = summaries.values().filter(|s| s.is_some()).count();
        if matched > 0 {
            result
                .metrics
                .increment(M_CTOR_MATCHED, i64::try_from(matched).unwrap_or(i64::MAX));
        }
        drop(resolver);

        // Phase B — apply per function.
        for (func_id, rewrites) in planned {
            for rw in &rewrites {
                result.metrics.increment(rw.metric, 1);
            }
            result.changed = true;
            if let Some(func) = ir.function_mut(func_id) {
                apply_rewrites(func, PASS_NAME, rewrites);
            }
        }
        result
    }
}

/// The `key` operand of a storage op still awaiting naming.
fn unresolved_key_of(op: &KnownOp) -> Option<ValueId> {
    match op {
        KnownOp::StorageGet {
            key,
            resolved_key: None,
            ..
        }
        | KnownOp::StorageSet {
            key,
            resolved_key: None,
            ..
        }
        | KnownOp::StorageHas {
            key,
            resolved_key: None,
            ..
        }
        | KnownOp::StorageRemove {
            key,
            resolved_key: None,
            ..
        }
        | KnownOp::StorageExtendTtl {
            key,
            resolved_key: None,
            ..
        }
        | KnownOp::StorageExtendTtlV2 {
            key,
            resolved_key: None,
            ..
        } => Some(*key),
        _ => None,
    }
}

/// Clone `op` with its `resolved_key` slot filled.
fn with_resolved_key(op: &KnownOp, enum_key: EnumKey) -> KnownOp {
    let mut upgraded = op.clone();
    match &mut upgraded {
        KnownOp::StorageGet { resolved_key, .. }
        | KnownOp::StorageSet { resolved_key, .. }
        | KnownOp::StorageHas { resolved_key, .. }
        | KnownOp::StorageRemove { resolved_key, .. }
        | KnownOp::StorageExtendTtl { resolved_key, .. }
        | KnownOp::StorageExtendTtlV2 { resolved_key, .. } => {
            *resolved_key = Some(enum_key);
        }
        _ => unreachable!("cloned from a storage variant"),
    }
    upgraded
}

/// Recursion cap for the key walk: a storage helper's key parameter is
/// met over its callers, each of which may name its own constructor
/// callsite.
const KEY_MEET_DEPTH: u32 = 3;

/// Run the full evidence gate for one storage op's key operand.
fn try_name_key(
    ir: &HighIr,
    calls: &CallIndex,
    resolver: &mut Resolver<'_>,
    summaries: &mut HashMap<FuncId, Option<CtorSummary>>,
    func: &HighFunction,
    key: ValueId,
) -> Naming {
    try_name_key_at(ir, calls, resolver, summaries, func, key, KEY_MEET_DEPTH)
}

fn try_name_key_at(
    ir: &HighIr,
    calls: &CallIndex,
    resolver: &mut Resolver<'_>,
    summaries: &mut HashMap<FuncId, Option<CtorSummary>>,
    func: &HighFunction,
    key: ValueId,
    depth: u32,
) -> Naming {
    // A key that resolves to symbol text is const-prop's domain (named
    // via the literal rewrite), not an enum-constructor miss.
    if resolver.resolve_symbol_text(func.id, key).is_some() {
        return Naming::NotACandidate;
    }

    // Chase the key to its terminal producer (Use links + pure-rename
    // single-incoming phis).
    let terminal = chase_key(func, key);
    let Some(binding) = func.bindings.get(terminal) else {
        return Naming::NotACandidate;
    };

    // The key is this (non-exported) helper's own parameter — the
    // storage-op-in-a-wrapper shape (`is_initialized(key)`). Meet over
    // every caller: each must name its own key argument, and all must
    // agree on the variant. Exported functions and indirect-call
    // modules have incomplete caller sets; never meet those.
    if func.params.contains(&terminal) {
        if depth == 0 || func.name.is_some() || calls.has_indirect_calls() {
            return Naming::Unresolved;
        }
        let Some(param_idx) = func.params.iter().position(|p| *p == terminal) else {
            return Naming::Unresolved;
        };
        let callers = calls.callers_of(func.id);
        if callers.is_empty() {
            return Naming::NotACandidate;
        }
        let mut agreed: Option<(EnumKey, usize)> = None;
        for site in callers {
            let Some(caller) = ir.function(site.caller) else {
                return Naming::Unresolved;
            };
            let Some(Expr::Call { args, .. }) =
                caller.bindings.get(site.call).map(|b| &b.expr)
            else {
                return Naming::Unresolved;
            };
            let Some(arg) = args.get(param_idx) else {
                return Naming::Unresolved;
            };
            let named =
                try_name_key_at(ir, calls, resolver, summaries, caller, *arg, depth - 1);
            let Naming::Named(enum_key, _) = named else {
                return Naming::Unresolved;
            };
            match &agreed {
                None => agreed = Some((enum_key, callers.len())),
                Some((prev, _))
                    if prev.enum_name == enum_key.enum_name
                        && prev.variant == enum_key.variant => {}
                Some(_) => return Naming::Unresolved,
            }
        }
        let Some((enum_key, n)) = agreed else {
            return Naming::Unresolved;
        };
        // Payload value ids belong to the callers' frames — not
        // display-coherent here; record the variant alone.
        let note = format!(
            "enum-key {}::{} (key param, met over {n} caller{})",
            enum_key.enum_name,
            enum_key.variant,
            if n == 1 { "" } else { "s" }
        );
        return Naming::Named(
            EnumKey {
                enum_name: enum_key.enum_name,
                variant: enum_key.variant,
                payload: vec![],
            },
            note,
        );
    }

    let Expr::Call { target, args } = &binding.expr else {
        return Naming::NotACandidate;
    };

    // Gate 1 + 2: summarize the callee (memoized).
    let summary = summaries
        .entry(*target)
        .or_insert_with(|| summarize_ctor(ir, *target));
    let Some(summary) = summary else {
        return Naming::Unresolved;
    };
    let unions = &ir
        .soroban_facts
        .as_ref()
        .expect("gated at run() entry")
        .types
        .unions;
    let union = &unions[summary.union_idx];

    // Gate 3: per-callsite discriminant, through the channel the
    // constructor was proven to use.
    let (d, payload, channel_note) = match &summary.disc {
        DiscChannel::ByPointer { param, .. } => {
            let Some(ptr_arg) = args.get(*param) else {
                return Naming::Unresolved;
            };
            let Some(slots) = slot_values(ir, calls, func, terminal, *ptr_arg, summary, true)
            else {
                return Naming::Unresolved;
            };
            let Some(d) = trace_int(slots.owner(ir, func), slots.disc) else {
                return Naming::Unresolved;
            };
            // Payload value ids are only display-coherent in the
            // storage op's own function; after a sole-caller hop they
            // belong to the caller's frame — record the variant alone.
            let (payload, note) = if slots.hopped && !slots.payload.is_empty() {
                (vec![], "via caller frame slot, payload in caller frame")
            } else if slots.hopped {
                (slots.payload, "via caller frame slot")
            } else {
                (slots.payload, "via frame slot")
            };
            (d, payload, note)
        }
        DiscChannel::ByValue => {
            // Exactly one distinct in-range constant among the args is
            // the discriminant (out-pointers are runtime values and
            // never resolve). resolve_int crosses phis and agreeing
            // callers, so a wrapper that forwards its own parameter
            // resolves when all its callers agree.
            let mut candidates: BTreeSet<i128> = BTreeSet::new();
            for arg in args {
                if let Some(n) = resolver
                    .resolve_int(func.id, *arg)
                    .filter(|n| *n >= 0 && (*n as usize) < union.cases.len())
                {
                    candidates.insert(n);
                }
            }
            let mut iter = candidates.into_iter();
            let (Some(d), None) = (iter.next(), iter.next()) else {
                return Naming::Unresolved;
            };
            (d, vec![], "by value")
        }
    };
    let Ok(d) = usize::try_from(d) else {
        return Naming::Unresolved;
    };
    let Some(case) = union.cases.get(d) else {
        return Naming::Unresolved;
    };

    // Gate 4: payload footprint must agree with the variant's fields.
    // (The by-value channel carries no payload, so only unit variants
    // can pass here — exactly the all-unit-union case.)
    if case.fields.is_empty() != payload.is_empty() {
        return Naming::Unresolved;
    }

    let note = format!(
        "enum-key {}::{} (disc {d} {channel_note}, spec union matched, decl-order mapping)",
        union.name, case.name
    );
    Naming::Named(
        EnumKey {
            enum_name: union.name.clone(),
            variant: case.name.clone(),
            payload,
        },
        note,
    )
}

/// Where the frame facts for a callsite were found.
struct SlotValues {
    /// The discriminant slot's stored value.
    disc: ValueId,
    /// Payload slot values in ascending offset order (width-8 only).
    payload: Vec<ValueId>,
    /// Set when the facts came from the sole caller's frame rather
    /// than the storage op's own function.
    hopped: bool,
    /// The function owning `disc`/`payload` when `hopped`.
    hop_owner: Option<FuncId>,
}

impl SlotValues {
    /// The function whose bindings `disc` and `payload` refer to.
    fn owner<'a>(&self, ir: &'a HighIr, local: &'a HighFunction) -> &'a HighFunction {
        match self.hop_owner {
            Some(id) => ir.function(id).unwrap_or(local),
            None => local,
        }
    }
}

/// Read the discriminant + payload slots visible at `call_id`'s
/// position for the pointer argument `ptr_arg`. When the pointer is the
/// enclosing (non-exported) helper's own parameter and `allow_hop`,
/// steps once to the unique caller (`func_1`-style extend-TTL helpers).
fn slot_values(
    ir: &HighIr,
    calls: &CallIndex,
    func: &HighFunction,
    call_id: ValueId,
    ptr_arg: ValueId,
    summary: &CtorSummary,
    allow_hop: bool,
) -> Option<SlotValues> {
    let DiscChannel::ByPointer {
        offset: disc_offset,
        width: disc_width,
        ..
    } = summary.disc
    else {
        return None;
    };
    slot_values_at(ir, calls, func, call_id, ptr_arg, disc_offset, disc_width, allow_hop)
}

#[allow(clippy::too_many_arguments)]
fn slot_values_at(
    ir: &HighIr,
    calls: &CallIndex,
    func: &HighFunction,
    call_id: ValueId,
    ptr_arg: ValueId,
    disc_offset: u32,
    disc_width: MemWidth,
    allow_hop: bool,
) -> Option<SlotValues> {
    let (base, k) = canon_addr(func, ptr_arg);

    // Local frame facts at the callsite.
    if let Some(block_id) = block_containing(func, call_id) {
        let block = func.blocks.get(block_id)?;
        let facts = facts_before(func, block, call_id, base);
        let disc_at = k.checked_add(disc_offset)?;
        // Truncating read: rustc stores the enum head full-width but
        // the constructor reads the tag narrow. Sound here because the
        // resolved constant is range-checked against the union's case
        // count — a value truncation would change fails that gate.
        if let Some(disc) = facts.value_at_trunc(disc_at, disc_width) {
            let payload_from = disc_at.checked_add(disc_width.bytes())?;
            let mut payload = Vec::new();
            for (off, fact) in facts.iter() {
                if off < payload_from {
                    continue;
                }
                // A non-word slot behind the discriminant is a shape
                // this recognizer does not understand: fail closed.
                if fact.width != MemWidth::W8 {
                    return None;
                }
                payload.push(fact.value);
            }
            return Some(SlotValues {
                disc,
                payload,
                hopped: false,
                hop_owner: None,
            });
        }
    }

    // Sole-caller hop: the pointer is our own parameter, and exactly
    // one (complete, caller-set-sound) callsite exists.
    if !allow_hop || func.name.is_some() || calls.has_indirect_calls() {
        return None;
    }
    let param_idx = func.params.iter().position(|p| *p == base)?;
    let site = calls.sole_caller(func.id)?;
    let caller = ir.function(site.caller)?;
    let Expr::Call { args, .. } = &caller.bindings.get(site.call)?.expr else {
        return None;
    };
    let caller_ptr = *args.get(param_idx)?;
    // The callee saw [param + k + disc_offset]; fold `k` into the
    // offset for the caller-side read.
    let inner = slot_values_at(
        ir,
        calls,
        caller,
        site.call,
        caller_ptr,
        disc_offset.checked_add(k)?,
        disc_width,
        false,
    )?;
    Some(SlotValues {
        disc: inner.disc,
        payload: inner.payload,
        hopped: true,
        hop_owner: Some(site.caller),
    })
}

/// Chase a key operand through `Use` links and pure-rename phis to its
/// terminal producer (the shared
/// [`chase_value`](super::wrappers::chase_value)).
fn chase_key(func: &HighFunction, key: ValueId) -> ValueId {
    super::wrappers::chase_value(func, key)
}

/// Gates 1 + 2: prove `target` is an enum-key constructor and identify
/// which union it builds. `None` (memoized) when any part fails.
fn summarize_ctor(ir: &HighIr, target: FuncId) -> Option<CtorSummary> {
    let func = ir.function(target)?;
    // Exported functions are host-invocable; a key constructor is
    // always an internal helper.
    if func.name.is_some() {
        return None;
    }

    // (1a) The discriminant channel. Pointer mode: exactly one
    // full-width param-relative load in the entry block before anything
    // that may write memory (mixed enums — the caller passes a slot
    // pointer). No such load at all → value mode (all-unit enums — the
    // discriminant arrives in a register; gate 4 then only ever accepts
    // unit variants). An ambiguous double-load bails.
    let entry = func.blocks.iter().next().map(|(_, block)| block)?;
    let mut candidate: Option<(usize, u32, MemWidth)> = None;
    for &id in &entry.bindings {
        let binding = func.bindings.get(id)?;
        if let Expr::Load {
            addr,
            offset,
            width: width @ (MemWidth::W4 | MemWidth::W8),
            signed: None,
            ..
        } = &binding.expr
        {
            let (base, k) = canon_addr(func, *addr);
            if let Some(param_idx) = func.params.iter().position(|p| *p == base) {
                if candidate.is_some() {
                    // Two param-relative loads: ambiguous, bail.
                    return None;
                }
                candidate = Some((param_idx, k.checked_add(*offset)?, *width));
            }
        } else if may_write_memory(&binding.expr) {
            break;
        }
    }
    let disc = match candidate {
        Some((param, offset, width)) => DiscChannel::ByPointer {
            param,
            offset,
            width,
        },
        None if !func.params.is_empty() => DiscChannel::ByValue,
        None => return None,
    };

    // (1b) The variant texts this helper can construct, from the
    // symbol-wrapper callsites with locally-constant rodata slices.
    let mut texts: BTreeSet<String> = BTreeSet::new();
    for (_, binding) in func.bindings.iter() {
        match &binding.expr {
            Expr::Call { target: g, args } => {
                let Some((pos_param, len_param)) = wrapper_symbol_params(ir, *g, WRAPPER_DEPTH)
                else {
                    continue;
                };
                let (Some(pos_arg), Some(len_arg)) = (args.get(pos_param), args.get(len_param))
                else {
                    continue;
                };
                if let Some(text) = read_symbol_text(ir, func, *pos_arg, *len_arg) {
                    texts.insert(text);
                }
            }
            // The inlined shape: a directly-recognized SymbolNew.
            Expr::Semantic(SemanticOp::Known(KnownOp::SymbolNew { lm_pos, len, resolved })) => {
                if let Some(text) = resolved
                    .clone()
                    .or_else(|| read_symbol_text(ir, func, *lm_pos, *len))
                {
                    texts.insert(text);
                }
            }
            _ => {}
        }
    }
    if texts.is_empty() {
        return None;
    }

    // (2) Registry gate: exactly one union with this exact case set.
    let unions = &ir.soroban_facts.as_ref()?.types.unions;
    let union_idx = unique_union_index_by_cases(unions, &texts)?;

    Some(CtorSummary { union_idx, disc })
}

/// Resolve a `(pos, len)` pair at a callsite to symbol text in rodata.
fn read_symbol_text(
    ir: &HighIr,
    func: &HighFunction,
    pos: ValueId,
    len: ValueId,
) -> Option<String> {
    let pos = trace_u32val(func, pos)?;
    let len = trace_u32val(func, len)?;
    valid_symbol_text(ir.memory.read(pos, len)?)
}

/// Identify a symbol-constructor wrapper: a helper whose body (within
/// `depth` nested calls) contains a `SymbolNew` host op whose
/// `(lm_pos, len)` operands are fed positionally from the wrapper's own
/// parameters. Returns those parameter positions so a caller's constant
/// args can be read off directly. Thin adapter over the shared
/// [`wrapper_params`](super::wrappers::wrapper_params) search.
fn wrapper_symbol_params(ir: &HighIr, target: FuncId, depth: u32) -> Option<(usize, usize)> {
    let params = super::wrappers::wrapper_params(ir, target, depth, &|op| match op {
        KnownOp::SymbolNew { lm_pos, len, .. } => Some(vec![*lm_pos, *len]),
        _ => None,
    })?;
    match params[..] {
        [pos, len] => Some((pos, len)),
        _ => None,
    }
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{Arena, BlockId, IrId, Provenance, ProvenanceSource, UnknownReason};
    use sordec_ir::{
        Binding, DataSegment, HighBlock, IrType, KnownTier, Literal, MemoryImage, Region,
        SorobanFacts, StorageTier, TypeRegistry, UnionCase, UnionDef, WasmFacts,
    };

    // --- builders: multi-function modules with scheduled blocks ---

    /// Build a function with `n_params` leading params (empty-incoming
    /// phis) then `exprs`, all scheduled into one block in order.
    fn func(id: u32, name: Option<&str>, n_params: usize, exprs: Vec<Expr>) -> HighFunction {
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        let mut params = Vec::new();
        let mut scheduled = Vec::new();
        for _ in 0..n_params {
            let id = ValueId::from_index(bindings.len() as u32);
            bindings.push(Binding::new(
                id,
                IrType::Unknown(UnknownReason::InsufficientEvidence),
                Expr::Phi { incoming: vec![] },
                Provenance::new("test", ProvenanceSource::DataFlow, "param"),
            ));
            params.push(id);
        }
        for expr in exprs {
            let vid = ValueId::from_index(bindings.len() as u32);
            bindings.push(Binding::new(
                vid,
                IrType::Unknown(UnknownReason::InsufficientEvidence),
                expr,
                Provenance::new("test", ProvenanceSource::DataFlow, "seed"),
            ));
            scheduled.push(vid);
        }
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        blocks.push(HighBlock {
            id: BlockId::from_index(0),
            bindings: scheduled,
        });
        HighFunction {
            id: FuncId::from_index(id),
            name: name.map(str::to_string),
            signature: None,
            blocks,
            bindings,
            region: Region::Unreachable,
            params,
            returns: vec![],
        }
    }

    /// A module with a registry holding one `DataKey`-like union and
    /// rodata holding the packed variant names.
    fn module(functions: Vec<HighFunction>, unions: Vec<UnionDef>) -> HighIr {
        let facts = SorobanFacts {
            types: TypeRegistry {
                unions,
                ..TypeRegistry::default()
            },
            ..SorobanFacts::default()
        };
        HighIr {
            facts: WasmFacts {
                imports: vec![],
                exports: vec![],
                function_type_indices: vec![],
                custom_sections: vec![],
            },
            soroban_facts: Some(facts),
            functions,
            memory: MemoryImage::from_segments(vec![DataSegment {
                offset: 1000,
                // Packed like rustc's rodata: "State" @1000, "Admin" @1005.
                bytes: b"StateAdmin".to_vec(),
            }]),
        }
    }

    fn data_key_union() -> UnionDef {
        UnionDef {
            id: sordec_common::TypeId::from_index(0),
            name: "DataKey".to_string(),
            cases: vec![
                UnionCase {
                    name: "State".to_string(),
                    fields: vec![sordec_ir::TypeRef::Primitive(
                        sordec_ir::PrimitiveType::Address,
                    )],
                },
                UnionCase {
                    name: "Admin".to_string(),
                    fields: vec![],
                },
            ],
        }
    }

    fn v(i: u32) -> ValueId {
        ValueId::from_index(i)
    }

    fn i64c(n: i64) -> Expr {
        Expr::Literal(Literal::I64(n))
    }

    fn i32c(n: i32) -> Expr {
        Expr::Literal(Literal::I32(n))
    }

    fn call(target: u32, args: Vec<ValueId>) -> Expr {
        Expr::Call {
            target: FuncId::from_index(target),
            args,
        }
    }

    fn storage_get(key: u32) -> Expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet {
            tier: StorageTier::Known(KnownTier::Instance),
            durability: v(key),
            key: v(key),
            resolved_key: None,
        }))
    }

    /// The symbol wrapper: `f(pos, len)` containing a SymbolNew fed
    /// from its params.
    fn symbol_wrapper(id: u32) -> HighFunction {
        func(
            id,
            None,
            2,
            vec![Expr::Semantic(SemanticOp::Known(KnownOp::SymbolNew {
                lm_pos: v(0),
                len: v(1),
                resolved: None,
            }))],
        )
    }

    /// The constructor helper `H(ptr)`: entry-block discriminant load +
    /// two wrapper callsites with const (pos, len) slices for
    /// "State"/"Admin". `wrapper` is the wrapper's FuncId.
    fn ctor(id: u32, wrapper: u32) -> HighFunction {
        func(
            id,
            None,
            1,
            vec![
                // v1 = load [param+0] (the discriminant)
                Expr::Load {
                    addr: v(0),
                    offset: 0,
                    width: MemWidth::W8,
                    signed: None,
                    ty: IrType::Unknown(UnknownReason::InsufficientEvidence),
                },
                // "State" @ 1000 len 5
                i32c(1000),
                i32c(5),
                call(wrapper, vec![v(2), v(3)]),
                // "Admin" @ 1005 len 5
                i32c(1005),
                i32c(5),
                call(wrapper, vec![v(5), v(6)]),
            ],
        )
    }

    /// The caller: stores discriminant (+ optional payload) into its
    /// frame, calls the ctor, feeds the result to a storage op.
    /// Returns (function, storage-op binding id).
    fn caller_with(disc: i64, payload: bool, ctor_id: u32) -> (HighFunction, ValueId) {
        // v0 = frame base (opaque phi); v1 = disc const;
        // v2 = store v0 <- v1 offset=8; [v3 = payload val;
        // v4 = store v0 <- v3 offset=16;] vK = add v0, 8 (canon: k=8);
        // vC = call ctor(vK); vS = storage_get(vC)
        let mut exprs = vec![i64c(disc)];
        let mut next = 2u32; // v0 param... wait: n_params=1 → v0 param, exprs start at v1
        let mut body: Vec<Expr> = Vec::new();
        body.push(i64c(disc)); // v1
        body.push(Expr::Store {
            addr: v(0),
            value: v(1),
            offset: 8,
            width: MemWidth::W8,
        }); // v2
        let mut idx = 3;
        if payload {
            body.push(i64c(777)); // v3 payload value
            body.push(Expr::Store {
                addr: v(0),
                value: v(3),
                offset: 16,
                width: MemWidth::W8,
            }); // v4
            idx = 5;
        }
        body.push(i32c(8)); // v[idx]
        body.push(Expr::Binary {
            op: sordec_ir::BinaryOp::Add,
            lhs: v(0),
            rhs: v(idx),
        }); // v[idx+1]
        body.push(call(ctor_id, vec![v(idx + 1)])); // v[idx+2]
        body.push(storage_get(idx + 2)); // v[idx+3]
        let _ = (&mut exprs, &mut next);
        let f = func(0, None, 1, body);
        let storage_id = v(idx + 3);
        (f, storage_id)
    }

    fn run(ir: &mut HighIr) -> PassResult {
        EnumKeyPass.run(ir)
    }

    fn resolved_key_of(ir: &HighIr, func: u32, id: ValueId) -> Option<EnumKey> {
        match &ir
            .functions
            .get(func as usize)
            .unwrap()
            .bindings
            .get(id)
            .unwrap()
            .expr
        {
            Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet { resolved_key, .. })) => {
                resolved_key.clone()
            }
            other => panic!("expected StorageGet, got {other:?}"),
        }
    }

    // --- positive paths ---

    #[test]
    fn unit_variant_key_is_named() {
        let (caller, storage_id) = caller_with(1, false, 1);
        let mut ir = module(
            vec![caller, ctor(1, 2), symbol_wrapper(2)],
            vec![data_key_union()],
        );
        let result = run(&mut ir);
        assert!(result.changed);
        assert_eq!(result.metrics.get(M_KEY_NAMED), Some(1));
        assert_eq!(result.metrics.get(M_CTOR_MATCHED), Some(1));
        let key = resolved_key_of(&ir, 0, storage_id).expect("named");
        assert_eq!(key.enum_name, "DataKey");
        assert_eq!(key.variant, "Admin");
        assert!(key.payload.is_empty());
        // Provenance records the mapping assumption.
        let func = &ir.functions[0];
        let note = &func.bindings.get(storage_id).unwrap().latest_provenance().note;
        assert!(note.contains("decl-order mapping"), "{note}");
    }

    #[test]
    fn payload_variant_key_is_named_with_payload() {
        let (caller, storage_id) = caller_with(0, true, 1);
        let mut ir = module(
            vec![caller, ctor(1, 2), symbol_wrapper(2)],
            vec![data_key_union()],
        );
        let result = run(&mut ir);
        assert!(result.changed);
        let key = resolved_key_of(&ir, 0, storage_id).expect("named");
        assert_eq!(key.variant, "State");
        assert_eq!(key.payload, vec![v(3)]);
    }

    #[test]
    fn second_run_is_idempotent() {
        let (caller, _) = caller_with(1, false, 1);
        let mut ir = module(
            vec![caller, ctor(1, 2), symbol_wrapper(2)],
            vec![data_key_union()],
        );
        assert!(run(&mut ir).changed);
        let second = run(&mut ir);
        assert!(!second.changed);
        assert_eq!(second.metrics.get(M_KEY_NAMED), None);
    }

    // --- the by-value channel (all-unit unions) + param-key meet ---

    fn unit_union() -> UnionDef {
        UnionDef {
            id: sordec_common::TypeId::from_index(0),
            name: "DataKey".to_string(),
            cases: vec![
                UnionCase {
                    name: "State".to_string(),
                    fields: vec![],
                },
                UnionCase {
                    name: "Admin".to_string(),
                    fields: vec![],
                },
            ],
        }
    }

    /// A by-value constructor: `H(disc)` — no entry-block load, two
    /// symbol-wrapper callsites.
    fn by_value_ctor(id: u32, wrapper: u32) -> HighFunction {
        func(
            id,
            None,
            1,
            vec![
                i32c(1000),
                i32c(5),
                call(wrapper, vec![v(1), v(2)]),
                i32c(1005),
                i32c(5),
                call(wrapper, vec![v(4), v(5)]),
            ],
        )
    }

    #[test]
    fn by_value_discriminant_names_unit_variant() {
        // caller: v0 = 1i32; v1 = call ctor(v0); v2 = storage_get(v1)
        let caller = func(0, None, 0, vec![i32c(1), call(1, vec![v(0)]), storage_get(1)]);
        let mut ir = module(
            vec![caller, by_value_ctor(1, 2), symbol_wrapper(2)],
            vec![unit_union()],
        );
        let result = run(&mut ir);
        assert!(result.changed, "{:?}", result.metrics);
        let key = resolved_key_of(&ir, 0, v(2)).expect("named");
        assert_eq!(key.variant, "Admin");
        assert!(key.payload.is_empty());
    }

    #[test]
    fn param_key_meet_names_agreeing_callers() {
        // f0: storage helper with the key as its parameter; f3 + f4 both
        // pass ctor(1) → Admin. The meet agrees.
        let helper = func(0, None, 1, vec![storage_get(0)]);
        let caller_a = func(3, None, 0, vec![i32c(1), call(1, vec![v(0)]), call(0, vec![v(1)])]);
        let caller_b = func(4, None, 0, vec![i32c(1), call(1, vec![v(0)]), call(0, vec![v(1)])]);
        let mut ir = module(
            vec![helper, by_value_ctor(1, 2), symbol_wrapper(2), caller_a, caller_b],
            vec![unit_union()],
        );
        let result = run(&mut ir);
        assert!(result.changed, "{:?}", result.metrics);
        let key = resolved_key_of(&ir, 0, v(1)).expect("named via meet");
        assert_eq!(key.variant, "Admin");
        let note = &ir.functions[0]
            .bindings
            .get(v(1))
            .unwrap()
            .latest_provenance()
            .note;
        assert!(note.contains("met over 2 callers"), "{note}");
    }

    #[test]
    fn param_key_meet_refuses_disagreeing_callers() {
        // The timelock/dex shape: one polymorphic helper serving two
        // different variants — must stay honestly unnamed.
        let helper = func(0, None, 1, vec![storage_get(0)]);
        let caller_a = func(3, None, 0, vec![i32c(0), call(1, vec![v(0)]), call(0, vec![v(1)])]);
        let caller_b = func(4, None, 0, vec![i32c(1), call(1, vec![v(0)]), call(0, vec![v(1)])]);
        let mut ir = module(
            vec![helper, by_value_ctor(1, 2), symbol_wrapper(2), caller_a, caller_b],
            vec![unit_union()],
        );
        let result = run(&mut ir);
        assert!(!result.changed);
        assert!(resolved_key_of(&ir, 0, v(1)).is_none());
        assert_eq!(result.metrics.get(M_UNRESOLVED), Some(1));
    }

    #[test]
    fn by_value_ambiguous_arg_constants_stay_unnamed() {
        // Two distinct in-range constants among the ctor args: no way
        // to know which is the discriminant — bail.
        let caller = func(
            0,
            None,
            0,
            vec![i32c(0), i32c(1), call(1, vec![v(0), v(1)]), storage_get(2)],
        );
        let mut ir = module(
            vec![caller, by_value_ctor(1, 2), symbol_wrapper(2)],
            vec![unit_union()],
        );
        let result = run(&mut ir);
        assert!(!result.changed);
        assert_eq!(result.metrics.get(M_UNRESOLVED), Some(1));
    }

    // --- negative gates ---

    #[test]
    fn no_registry_recognizes_nothing() {
        let (caller, storage_id) = caller_with(1, false, 1);
        let mut ir = module(vec![caller, ctor(1, 2), symbol_wrapper(2)], vec![]);
        let result = run(&mut ir);
        assert!(!result.changed);
        assert!(resolved_key_of(&ir, 0, storage_id).is_none());
    }

    #[test]
    fn out_of_range_discriminant_stays_unnamed() {
        let (caller, storage_id) = caller_with(7, false, 1);
        let mut ir = module(
            vec![caller, ctor(1, 2), symbol_wrapper(2)],
            vec![data_key_union()],
        );
        let result = run(&mut ir);
        assert!(!result.changed);
        assert_eq!(result.metrics.get(M_UNRESOLVED), Some(1));
        assert!(resolved_key_of(&ir, 0, storage_id).is_none());
    }

    #[test]
    fn footprint_mismatch_stays_unnamed() {
        // Discriminant 1 = Admin (unit) but the caller wrote payload.
        let (caller, storage_id) = caller_with(1, true, 1);
        let mut ir = module(
            vec![caller, ctor(1, 2), symbol_wrapper(2)],
            vec![data_key_union()],
        );
        let result = run(&mut ir);
        assert!(!result.changed);
        assert_eq!(result.metrics.get(M_UNRESOLVED), Some(1));
        assert!(resolved_key_of(&ir, 0, storage_id).is_none());
    }

    #[test]
    fn ambiguous_union_match_stays_unnamed() {
        let mut twin = data_key_union();
        twin.name = "OtherKey".to_string();
        twin.id = sordec_common::TypeId::from_index(1);
        let (caller, storage_id) = caller_with(1, false, 1);
        let mut ir = module(
            vec![caller, ctor(1, 2), symbol_wrapper(2)],
            vec![data_key_union(), twin],
        );
        let result = run(&mut ir);
        assert!(!result.changed);
        assert!(resolved_key_of(&ir, 0, storage_id).is_none());
    }

    #[test]
    fn exported_ctor_is_not_summarized() {
        let (caller, storage_id) = caller_with(1, false, 1);
        let mut exported = ctor(1, 2);
        exported.name = Some("not_a_helper".to_string());
        let mut ir = module(
            vec![caller, exported, symbol_wrapper(2)],
            vec![data_key_union()],
        );
        let result = run(&mut ir);
        assert!(!result.changed);
        assert!(resolved_key_of(&ir, 0, storage_id).is_none());
    }

    #[test]
    fn intervening_call_before_ctor_kills_discriminant() {
        // A call between the discriminant store and the ctor call may
        // rewrite the frame: the fact must not survive.
        let body = vec![
            i64c(1),                       // v1
            Expr::Store {
                addr: v(0),
                value: v(1),
                offset: 8,
                width: MemWidth::W8,
            },                              // v2
            call(2, vec![]),               // v3: opaque call (the killer)
            i32c(8),                       // v4
            Expr::Binary {
                op: sordec_ir::BinaryOp::Add,
                lhs: v(0),
                rhs: v(4),
            },                              // v5
            call(1, vec![v(5)]),           // v6 = ctor call
            storage_get(6),                // v7
        ];
        let caller = func(0, None, 1, body);
        let mut ir = module(
            vec![caller, ctor(1, 2), symbol_wrapper(2)],
            vec![data_key_union()],
        );
        let result = run(&mut ir);
        assert!(!result.changed);
        assert_eq!(result.metrics.get(M_UNRESOLVED), Some(1));
    }

    #[test]
    fn non_call_key_is_not_a_candidate() {
        // A literal key (symbol-small) is const-prop's domain; the
        // unresolved counter must not fire.
        let f = func(0, None, 0, vec![i64c(42), storage_get(0)]);
        let mut ir = module(vec![f], vec![data_key_union()]);
        let result = run(&mut ir);
        assert!(!result.changed);
        assert_eq!(result.metrics.get(M_UNRESOLVED), None);
    }

    #[test]
    fn sole_caller_hop_resolves_forwarded_pointer() {
        // f0 (helper): takes ptr param, calls ctor with it, storage op
        // inside. f3 (its sole caller): stores disc 1 then calls f0.
        let helper = func(
            0,
            None,
            1,
            vec![
                call(1, vec![v(0)]), // v1 = ctor(param)
                storage_get(1),      // v2
            ],
        );
        let caller = func(
            3,
            None,
            1,
            vec![
                i64c(1), // v1
                Expr::Store {
                    addr: v(0),
                    value: v(1),
                    offset: 8,
                    width: MemWidth::W8,
                }, // v2
                i32c(8), // v3
                Expr::Binary {
                    op: sordec_ir::BinaryOp::Add,
                    lhs: v(0),
                    rhs: v(3),
                }, // v4
                call(0, vec![v(4)]), // v5
            ],
        );
        let mut ir = module(
            vec![helper, ctor(1, 2), symbol_wrapper(2), caller],
            vec![data_key_union()],
        );
        let result = run(&mut ir);
        assert!(result.changed, "{:?}", result.metrics);
        let key = resolved_key_of(&ir, 0, v(2)).expect("named through hop");
        assert_eq!(key.variant, "Admin");
    }
}
