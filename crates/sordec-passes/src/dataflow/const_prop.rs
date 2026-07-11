//! Inter-procedural constant resolution over `HighIr`.
//!
//! The intra-procedural tracers ([`trace_int`](super::trace_int),
//! [`trace_bytes()`](super::trace_bytes())) stop at the first phi or
//! function parameter. rustc, however, routinely threads the constants
//! recognizers need — storage durability tiers, linear-memory
//! positions, callee symbols — through phi chains and helper-function
//! parameters. This module is the engine that crosses those boundaries:
//!
//! - [`CallIndex`] — the module's first call graph: for every local
//!   function, the `Expr::Call` sites that target it.
//! - [`Resolver`] — a whole-module constant tracer that follows `Use`
//!   chains, meets over phi edges, binds helper parameters to the
//!   positional arguments of *all* their callers (caller → callee), and
//!   resolves a `Call` result to the meet of the callee's return sites
//!   (callee → caller).
//!
//! ## Soundness rules (each guards a concrete wrong-answer hole)
//!
//! - **Meet over paths**: a phi (or parameter) resolves only when every
//!   incoming edge (or every caller) resolves to the *same* literal.
//!   Disagreement or any unresolved path → `None`. Two independently-met
//!   facts conjoin soundly: if `pos = P` on every path and `len = L` on
//!   every path, then every execution carries exactly `(P, L)`.
//! - **Exported functions never resolve parameters**: an exported
//!   function (`name.is_some()` — recovered only from the export table)
//!   is host-invocable with arbitrary arguments, so its internal
//!   callers are not the complete caller set.
//! - **Indirect-call kill-switch**: `call_indirect` lowers to
//!   `Expr::Unknown { op_kind: CallIndirect }` and the element section
//!   is not modeled, so table-called functions have invisible callers.
//!   If the module contains *any* indirect call, parameter resolution
//!   is disabled module-wide. (Precise element-segment capture is a
//!   documented follow-up.)
//! - **A parameter whose entry block has predecessors** (entry used as
//!   a branch target) → `None`: meeting only the back-edge values would
//!   ignore the caller-supplied initial value.
//!
//! ## Termination and complexity
//!
//! Cycles (loop-carried phis, recursion) are detected with a
//! **path-scoped** visited set — inserted on entry, removed on exit —
//! so a value reached on two *different* acyclic paths (a phi diamond)
//! still resolves; re-entry on the *same* path returns `None`.
//! Completed results are **memoized** per `(function, value, flavor)`;
//! without the memo, chains of phi diamonds explore exponentially many
//! paths. Cycle-tainted `None`s are path-relative and never cached.
//! A depth cap ([`DEFAULT_RESOLVE_DEPTH`]) backstops pathological IR.

use std::collections::{HashMap, HashSet};

use sordec_common::{FuncId, IrId, ValueId};
use sordec_ir::{Expr, HighFunction, HighIr, KnownOp, KnownType, Literal, SemanticOp, WasmOpcodeKind};

use super::high::resolve_use;
use crate::val_abi::{decode_small_symbol, TAG_MASK, TAG_U32_VAL};

/// Defensive recursion bound for [`Resolver`] walks, mirroring
/// [`DEFAULT_MAX_DEPTH`](super::DEFAULT_MAX_DEPTH). Cycles are handled
/// by the path set; the cap backstops unforeseen pathologies.
pub const DEFAULT_RESOLVE_DEPTH: u32 = 128;

// ---------------------------------------------------------------------
// CallIndex
// ---------------------------------------------------------------------

/// One direct call site targeting some function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallSite {
    /// Function containing the call.
    pub caller: FuncId,
    /// The `Expr::Call` binding within the caller.
    pub call: ValueId,
}

/// Module-wide reverse call map: "which `Expr::Call` sites target this
/// function?" Built once per [`HighIr`] in a single scan; a
/// point-in-time snapshot (rebuild after mutating the IR).
///
/// Only *direct* local calls appear — host imports lower to
/// `Expr::Semantic`, never `Expr::Call`. Indirect calls are not
/// resolvable to targets at all; their presence anywhere in the module
/// is surfaced via [`has_indirect_calls`](Self::has_indirect_calls) so
/// consumers can disable caller-set-dependent reasoning.
#[derive(Debug, Clone)]
pub struct CallIndex {
    /// `callers[i]` = call sites targeting `FuncId(i)`. Dense because
    /// `FuncId`s are dense module-global indices.
    callers: Vec<Vec<CallSite>>,
    /// Whether any binding in the module is an unlowered
    /// `call_indirect` (or an `Expr::IndirectCall`).
    has_indirect: bool,
}

impl CallIndex {
    /// Build the index in one linear scan over every function's
    /// bindings. Out-of-range call targets are skipped defensively —
    /// malformed IR is the validator's concern, not ours.
    #[must_use]
    pub fn build(ir: &HighIr) -> Self {
        let mut callers: Vec<Vec<CallSite>> = vec![Vec::new(); ir.functions.len()];
        let mut has_indirect = false;
        for func in &ir.functions {
            for (call_id, binding) in func.bindings.iter() {
                match &binding.expr {
                    Expr::Call { target, .. } => {
                        if let Some(slot) = callers.get_mut(target.index() as usize) {
                            slot.push(CallSite {
                                caller: func.id,
                                call: call_id,
                            });
                        }
                    }
                    Expr::IndirectCall { .. }
                    | Expr::Unknown {
                        op_kind: WasmOpcodeKind::CallIndirect,
                        ..
                    } => has_indirect = true,
                    _ => {}
                }
            }
        }
        Self {
            callers,
            has_indirect,
        }
    }

    /// All call sites targeting `func`, or an empty slice for an
    /// unknown/uncalled function.
    #[must_use]
    pub fn callers_of(&self, func: FuncId) -> &[CallSite] {
        self.callers
            .get(func.index() as usize)
            .map_or(&[], Vec::as_slice)
    }

    /// The unique call site targeting `func`, if there is exactly one.
    #[must_use]
    pub fn sole_caller(&self, func: FuncId) -> Option<CallSite> {
        match self.callers_of(func) {
            [only] => Some(*only),
            _ => None,
        }
    }

    /// Whether the module contains any indirect call — if so, caller
    /// sets are incomplete and parameter resolution must not run.
    #[must_use]
    pub fn has_indirect_calls(&self) -> bool {
        self.has_indirect
    }
}

// ---------------------------------------------------------------------
// Resolver
// ---------------------------------------------------------------------

/// What a value is being resolved *as* — the two flavors decode
/// terminals differently and must never mix:
///
/// - [`RawInt`](Flavor::RawInt): the value is a plain machine integer
///   (e.g. a storage durability discriminant). `ValEncodeSmall` is NOT
///   peeled — a Val's payload is not the raw integer the ABI expects.
/// - [`U32Val`](Flavor::U32Val): the value is a Soroban `U32Val`
///   (linear-memory position/length). Terminals follow
///   [`trace_u32val`](super::trace_u32val) semantics exactly: 64-bit
///   literals are tag-checked and decoded, 32-bit literals are bare
///   offsets, and the C1 `ValEncodeSmall { ty: U32 }` wrapper is
///   peeled. Meets compare *decoded* u32s, so mixed representations
///   across callers still agree.
/// - [`SymbolText`](Flavor::SymbolText): the value is a Soroban
///   `Symbol` in an ABI-proven Symbol position. Terminals: a 64-bit
///   literal is strictly decoded as a tag-14 `SymbolSmall`; a
///   recognized `SymbolNew` op re-derives its text from rodata via its
///   own `(lm_pos, len)` operands (independent of whether its
///   `resolved` slot is filled — order-free). Meets compare the
///   decoded text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Flavor {
    RawInt,
    U32Val,
    SymbolText,
}

/// Inter-procedural constant resolver. Read-only over the IR; owns its
/// memoization state, so hold one per analysis phase and query freely.
#[derive(Debug)]
pub struct Resolver<'a> {
    ir: &'a HighIr,
    calls: &'a CallIndex,
    /// Completed results. `None` entries are only cached when the walk
    /// that produced them was cycle-free (cycle `None`s are
    /// path-relative).
    memo: HashMap<(FuncId, ValueId, Flavor), Option<Literal>>,
    /// The current DFS path (cycle detection). Insert on entry, remove
    /// on exit — NOT a global visited set.
    path: HashSet<(FuncId, ValueId, Flavor)>,
    depth: u32,
}

/// Internal walk result: the resolution plus whether a cycle or the
/// depth cap was encountered anywhere below (tainted results must not
/// be memoized).
type Walk = (Option<Literal>, bool);

impl<'a> Resolver<'a> {
    /// Create a resolver over a snapshot of the IR and its call index.
    #[must_use]
    pub fn new(ir: &'a HighIr, calls: &'a CallIndex) -> Self {
        Self {
            ir,
            calls,
            memo: HashMap::new(),
            path: HashSet::new(),
            depth: 0,
        }
    }

    /// Resolve `value` (in `func`) to a plain integer constant,
    /// crossing phi edges and helper-parameter boundaries. `None` when
    /// any path is non-constant, paths disagree, or a soundness guard
    /// fires. Does NOT decode Val wrappers (a Val payload is not the
    /// raw integer an ABI discriminant position expects) — use
    /// [`resolve_u32val`](Self::resolve_u32val) for `U32Val` operands.
    #[must_use]
    pub fn resolve_int(&mut self, func: FuncId, value: ValueId) -> Option<i128> {
        self.reset();
        let (lit, _) = self.walk(func, value, Flavor::RawInt);
        match lit? {
            Literal::I32(n) => Some(i128::from(n)),
            Literal::I64(n) => Some(i128::from(n)),
            Literal::U32(n) => Some(i128::from(n)),
            Literal::U64(n) => Some(i128::from(n)),
            _ => None,
        }
    }

    /// Resolve `value` (in `func`) to the `u32` it carries as a Soroban
    /// `U32Val`, with [`trace_u32val`](super::trace_u32val) terminal
    /// semantics extended across phis and calls.
    #[must_use]
    pub fn resolve_u32val(&mut self, func: FuncId, value: ValueId) -> Option<u32> {
        self.reset();
        let (lit, _) = self.walk(func, value, Flavor::U32Val);
        match lit? {
            Literal::U32(n) => Some(n),
            _ => None,
        }
    }

    /// Resolve a `(pointer, length)` pair (both `U32Val`s, in `func`)
    /// to the constant bytes it names in the module's rodata image.
    #[must_use]
    pub fn resolve_bytes(
        &mut self,
        func: FuncId,
        ptr: ValueId,
        len: ValueId,
    ) -> Option<Vec<u8>> {
        let pos = self.resolve_u32val(func, ptr)?;
        let length = self.resolve_u32val(func, len)?;
        self.ir.memory.read(pos, length).map(<[u8]>::to_vec)
    }

    /// Resolve `value` (in `func`) — an operand in an ABI-proven
    /// `Symbol` position — to its symbol text, whether it is a tag-14
    /// `SymbolSmall` constant or a rodata-backed `SymbolNew`, across
    /// phis and calls.
    #[must_use]
    pub fn resolve_symbol_text(&mut self, func: FuncId, value: ValueId) -> Option<String> {
        self.reset();
        let (lit, _) = self.walk(func, value, Flavor::SymbolText);
        match lit? {
            Literal::Symbol(text) => Some(text),
            _ => None,
        }
    }

    /// Reset per-query state. The path set is empty on clean exits by
    /// the insert/remove discipline; clearing defensively keeps a
    /// panicked or capped walk from poisoning the next query. The memo
    /// survives across queries (that is its purpose).
    fn reset(&mut self) {
        self.path.clear();
        self.depth = 0;
    }

    /// The recursive walk. Returns the resolved literal (normalized:
    /// `U32Val` flavor always yields `Literal::U32`) plus a taint flag.
    fn walk(&mut self, func_id: FuncId, value: ValueId, flavor: Flavor) -> Walk {
        // Depth cap — tainted, so nothing on this path gets memoized.
        if self.depth >= DEFAULT_RESOLVE_DEPTH {
            return (None, true);
        }

        let Some(func) = self.ir.function(func_id) else {
            return (None, false);
        };

        // Chase Use links to the terminal binding within this function.
        let terminal = resolve_use(func, value);
        // Bounds-check before Arena::get (debug_asserts on OOB ids).
        if (terminal.index() as usize) >= func.bindings.len() {
            return (None, false);
        }
        let key = (func_id, terminal, flavor);

        if let Some(cached) = self.memo.get(&key) {
            return (cached.clone(), false);
        }
        // Cycle: re-entered a node on the CURRENT path.
        if !self.path.insert(key) {
            return (None, true);
        }
        self.depth += 1;

        let result = self.walk_terminal(func, func_id, terminal, flavor);

        self.depth -= 1;
        self.path.remove(&key);
        // Memoize only untainted results — a cycle-relative or
        // depth-capped `None` may resolve fine from another path.
        if !result.1 {
            self.memo.insert(key, result.0.clone());
        }
        result
    }

    /// Resolve one terminal binding (post-`Use`-chase).
    fn walk_terminal(
        &mut self,
        func: &'a HighFunction,
        func_id: FuncId,
        terminal: ValueId,
        flavor: Flavor,
    ) -> Walk {
        let Some(binding) = func.bindings.get(terminal) else {
            return (None, false);
        };

        // Parameter check FIRST — before any phi handling. A parameter
        // whose entry block is also a branch target has a non-empty
        // incoming list; meeting only those back-edges would ignore the
        // caller-supplied initial value, so it must not take the plain
        // phi path.
        if func.params.contains(&terminal) {
            match &binding.expr {
                Expr::Phi { incoming } if incoming.is_empty() => {
                    return self.walk_param(func, func_id, terminal, flavor);
                }
                // Entry block has predecessors, or the param binding is
                // not the Phi shape the lowering guarantees: honest None.
                _ => return (None, false),
            }
        }

        match &binding.expr {
            Expr::Literal(lit) => (decode_terminal_literal(lit, flavor), false),

            // A recognized symbol constructor in a Symbol position:
            // re-derive the text from rodata via its own (lm_pos, len)
            // operands — independent of whether the op's `resolved`
            // slot has been filled, so upgrade ordering is a non-issue.
            Expr::Semantic(SemanticOp::Known(KnownOp::SymbolNew { lm_pos, len, .. }))
                if flavor == Flavor::SymbolText =>
            {
                let (pos, t1) = self.walk(func_id, *lm_pos, Flavor::U32Val);
                let (length, t2) = self.walk(func_id, *len, Flavor::U32Val);
                let taint = t1 || t2;
                let text = match (pos, length) {
                    (Some(Literal::U32(p)), Some(Literal::U32(l))) => self
                        .ir
                        .memory
                        .read(p, l)
                        .and_then(|bytes| String::from_utf8(bytes.to_vec()).ok()),
                    _ => None,
                };
                (text.map(Literal::Symbol), taint)
            }

            // The C1-recognized U32Val wrapper: peel for the U32Val
            // flavor only. In RawInt flavor a Val payload is not the
            // raw integer the ABI expects.
            Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall {
                ty: KnownType::U32,
                value: inner,
            })) if flavor == Flavor::U32Val => {
                let (lit, taint) = self.walk(func_id, *inner, Flavor::RawInt);
                let decoded = lit.and_then(|l| match l {
                    Literal::I32(n) => u32::try_from(n).ok(),
                    Literal::U32(n) => Some(n),
                    Literal::I64(n) => u32::try_from(n).ok(),
                    Literal::U64(n) => u32::try_from(n).ok(),
                    _ => None,
                });
                (decoded.map(Literal::U32), taint)
            }

            // Non-parameter phi: meet over every incoming edge.
            Expr::Phi { incoming } => {
                if incoming.is_empty() {
                    // A predecessor-less non-entry block param
                    // (unreachable block): nothing flows in.
                    return (None, false);
                }
                self.meet(
                    func_id,
                    incoming.iter().map(|(_, v)| *v).collect::<Vec<_>>(),
                    flavor,
                )
            }

            // A direct call: resolve as the callee's return value. The
            // callee's body is fully visible, so — unlike parameter
            // resolution — no exported/indirect guards are needed;
            // recursion is caught by the path set. The structural
            // guards below are permanent facts: untainted, memoizable.
            Expr::Call { target, .. } => {
                let Some(callee) = self.ir.function(*target) else {
                    return (None, false);
                };
                // Zero return sites = diverging; any site with other
                // than exactly one value means the Call binding is not
                // "the value" (multi-result projections lower to
                // Unknown). Honest None either way.
                if callee.returns.is_empty()
                    || callee.returns.iter().any(|values| values.len() != 1)
                {
                    return (None, false);
                }
                let callee_id = *target;
                let site_values: Vec<ValueId> =
                    callee.returns.iter().map(|values| values[0]).collect();
                // Meet over every return site with the caller's
                // unchanged flavor — taint and cycle discipline
                // inherited from `meet`.
                self.meet(callee_id, site_values, flavor)
            }

            _ => (None, false),
        }
    }

    /// Resolve a function parameter by meeting the positional argument
    /// every caller passes.
    fn walk_param(
        &mut self,
        func: &'a HighFunction,
        func_id: FuncId,
        param: ValueId,
        flavor: Flavor,
    ) -> Walk {
        // Exported functions are host-invocable with arbitrary args —
        // internal callers are not the complete caller set.
        if func.name.is_some() {
            return (None, false);
        }
        // Indirect calls make every caller set potentially incomplete.
        if self.calls.has_indirect_calls() {
            return (None, false);
        }
        let Some(index) = func.params.iter().position(|p| *p == param) else {
            return (None, false);
        };
        let callers = self.calls.callers_of(func_id);
        if callers.is_empty() {
            // Uncalled (dead, or an entrypoint that lost its export
            // name): no evidence.
            return (None, false);
        }

        // Collect each caller's positional argument, defensively.
        let mut args: Vec<(FuncId, ValueId)> = Vec::with_capacity(callers.len());
        for site in callers {
            let Some(caller_fn) = self.ir.function(site.caller) else {
                return (None, false);
            };
            if (site.call.index() as usize) >= caller_fn.bindings.len() {
                return (None, false);
            }
            let Some(call_binding) = caller_fn.bindings.get(site.call) else {
                return (None, false);
            };
            let Expr::Call { args: call_args, .. } = &call_binding.expr else {
                // The call binding was rewritten since the index was
                // built — stale snapshot; be honest.
                return (None, false);
            };
            // Arity mismatch (malformed IR) → honest None, never panic.
            let Some(arg) = call_args.get(index) else {
                return (None, false);
            };
            args.push((site.caller, *arg));
        }

        // Meet across callers (each resolved in its own function).
        let mut taint = false;
        let mut agreed: Option<Literal> = None;
        for (caller, arg) in args {
            let (lit, t) = self.walk(caller, arg, flavor);
            taint |= t;
            let Some(lit) = lit else {
                return (None, taint);
            };
            match &agreed {
                None => agreed = Some(lit),
                Some(prev) if *prev == lit => {}
                Some(_) => return (None, taint),
            }
        }
        (agreed, taint)
    }

    /// Meet over a set of same-function values: all must resolve to the
    /// same literal.
    fn meet(&mut self, func_id: FuncId, values: Vec<ValueId>, flavor: Flavor) -> Walk {
        let mut taint = false;
        let mut agreed: Option<Literal> = None;
        for value in values {
            let (lit, t) = self.walk(func_id, value, flavor);
            taint |= t;
            let Some(lit) = lit else {
                return (None, taint);
            };
            match &agreed {
                None => agreed = Some(lit),
                Some(prev) if *prev == lit => {}
                Some(_) => return (None, taint),
            }
        }
        (agreed, taint)
    }
}

/// Decode a terminal literal per flavor. `RawInt` passes integer
/// literals through untouched; `U32Val` applies the
/// [`trace_u32val`](super::trace_u32val) terminal rules and normalizes
/// to `Literal::U32` so meets compare decoded values.
fn decode_terminal_literal(lit: &Literal, flavor: Flavor) -> Option<Literal> {
    match flavor {
        Flavor::RawInt => match lit {
            Literal::I32(_) | Literal::I64(_) | Literal::U32(_) | Literal::U64(_) => {
                Some(lit.clone())
            }
            _ => None,
        },
        Flavor::U32Val => match lit {
            // 64-bit literals are raw Vals: tag-check then decode.
            Literal::I64(bits) => decode_u32val_bits(*bits as u64).map(Literal::U32),
            Literal::U64(bits) => decode_u32val_bits(*bits).map(Literal::U32),
            // 32-bit literals are bare (unwrapped) offsets.
            Literal::U32(n) => Some(Literal::U32(*n)),
            Literal::I32(n) => u32::try_from(*n).ok().map(Literal::U32),
            _ => None,
        },
        Flavor::SymbolText => match lit {
            // 64-bit literals are raw Vals: strict tag-14 decode.
            Literal::I64(bits) => decode_small_symbol(*bits as u64).map(Literal::Symbol),
            Literal::U64(bits) => decode_small_symbol(*bits).map(Literal::Symbol),
            // An already-decoded symbol literal passes through.
            Literal::Symbol(text) => Some(Literal::Symbol(text.clone())),
            _ => None,
        },
    }
}

/// Decode a raw 64-bit `Val` as a `U32Val` (tag byte 4; payload in the
/// major word). `None` on any other tag.
fn decode_u32val_bits(bits: u64) -> Option<u32> {
    if (bits & TAG_MASK) == u64::from(TAG_U32_VAL) {
        Some((bits >> 32) as u32)
    } else {
        None
    }
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{Arena, BlockId, Provenance, ProvenanceSource, UnknownReason};
    use sordec_ir::{
        Binding, DataSegment, HighBlock, IrType, MemoryImage, Region, WasmFacts,
    };

    // --- builders (the first multi-function synthetic IR in the repo) ---

    /// Build a function: `n_params` parameter bindings first (each
    /// `Phi { incoming: [] }`, listed in `params`), then `exprs` at the
    /// following ids. `name: Some(_)` marks it exported.
    fn func(id: u32, name: Option<&str>, n_params: usize, exprs: Vec<Expr>) -> HighFunction {
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        let mut params = Vec::new();
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
        }
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        blocks.push(HighBlock {
            id: BlockId::from_index(0),
            bindings: vec![],
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

    /// Assemble a whole-module `HighIr` from functions (positions must
    /// match each function's `FuncId`).
    fn module(functions: Vec<HighFunction>) -> HighIr {
        HighIr {
            facts: WasmFacts {
                imports: vec![],
                exports: vec![],
                function_type_indices: vec![],
                custom_sections: vec![],
            },
            soroban_facts: None,
            functions,
            memory: MemoryImage::empty(),
        }
    }

    fn v(i: u32) -> ValueId {
        ValueId::from_index(i)
    }

    fn f(i: u32) -> FuncId {
        FuncId::from_index(i)
    }

    fn i64c(n: i64) -> Expr {
        Expr::Literal(Literal::I64(n))
    }

    fn call(target: u32, args: Vec<ValueId>) -> Expr {
        Expr::Call {
            target: f(target),
            args,
        }
    }

    fn phi(incoming: Vec<(u32, u32)>) -> Expr {
        Expr::Phi {
            incoming: incoming
                .into_iter()
                .map(|(b, val)| (BlockId::from_index(b), v(val)))
                .collect(),
        }
    }

    /// The raw bits of a `U32Val` carrying `n`.
    fn u32val_bits(n: u32) -> i64 {
        (((n as u64) << 32) | u64::from(TAG_U32_VAL)) as i64
    }

    fn resolve_int(ir: &HighIr, func: u32, value: u32) -> Option<i128> {
        let calls = CallIndex::build(ir);
        Resolver::new(ir, &calls).resolve_int(f(func), v(value))
    }

    fn resolve_u32val(ir: &HighIr, func: u32, value: u32) -> Option<u32> {
        let calls = CallIndex::build(ir);
        Resolver::new(ir, &calls).resolve_u32val(f(func), v(value))
    }

    // --- intra-procedural shapes ---

    #[test]
    fn direct_literal_resolves() {
        let ir = module(vec![func(0, None, 0, vec![i64c(2)])]);
        assert_eq!(resolve_int(&ir, 0, 0), Some(2));
    }

    #[test]
    fn use_chain_resolves() {
        let ir = module(vec![func(
            0,
            None,
            0,
            vec![i64c(7), Expr::Use(v(0)), Expr::Use(v(1))],
        )]);
        assert_eq!(resolve_int(&ir, 0, 2), Some(7));
    }

    #[test]
    fn phi_chain_resolves() {
        // v0 = 5; v1 = phi[(bb1, v0)]; v2 = phi[(bb2, v1)]
        let ir = module(vec![func(
            0,
            None,
            0,
            vec![i64c(5), phi(vec![(1, 0)]), phi(vec![(2, 1)])],
        )]);
        assert_eq!(resolve_int(&ir, 0, 2), Some(5));
    }

    #[test]
    fn phi_merge_agreeing_paths_resolve() {
        // v0 = 3; v1 = 3; v2 = phi[(bb1, v0), (bb2, v1)]
        let ir = module(vec![func(
            0,
            None,
            0,
            vec![i64c(3), i64c(3), phi(vec![(1, 0), (2, 1)])],
        )]);
        assert_eq!(resolve_int(&ir, 0, 2), Some(3));
    }

    #[test]
    fn phi_merge_disagreeing_paths_return_none() {
        let ir = module(vec![func(
            0,
            None,
            0,
            vec![i64c(1), i64c(2), phi(vec![(1, 0), (2, 1)])],
        )]);
        assert_eq!(resolve_int(&ir, 0, 2), None);
    }

    #[test]
    fn diamond_phi_shared_node_resolves() {
        // Both diamond arms route through the SAME node v0 — a global
        // visited set would poison the second arm; the path-scoped set
        // must not.  v0 = 9; v1 = Use(v0); v2 = Use(v0);
        // v3 = phi[(bb1, v1), (bb2, v2)]
        let ir = module(vec![func(
            0,
            None,
            0,
            vec![
                i64c(9),
                Expr::Use(v(0)),
                Expr::Use(v(0)),
                phi(vec![(1, 1), (2, 2)]),
            ],
        )]);
        assert_eq!(resolve_int(&ir, 0, 3), Some(9));
    }

    #[test]
    fn deep_diamond_chain_terminates_quickly() {
        // 40 stacked diamonds: without memoization this explores 2^40
        // paths (an effective hang); with it, linear. Layout per level i
        // (values appended in order): the terminal literal sits at v0;
        // level i's phi at index 3i+3 merges two Uses of level i's
        // *previous* phi (or the literal).
        let mut exprs = vec![i64c(6)];
        let mut prev = 0u32; // index of the value both arms feed from
        for _ in 0..40 {
            let a = exprs.len() as u32;
            exprs.push(Expr::Use(v(prev)));
            let b = exprs.len() as u32;
            exprs.push(Expr::Use(v(prev)));
            let p = exprs.len() as u32;
            exprs.push(phi(vec![(1, a), (2, b)]));
            prev = p;
        }
        let ir = module(vec![func(0, None, 0, exprs)]);
        assert_eq!(resolve_int(&ir, 0, prev), Some(6));
    }

    #[test]
    fn loop_phi_cycle_returns_none() {
        // v0 = phi[(bb1, v1)]; v1 = Use(v0) — a loop-carried value with
        // no constant entry: must terminate with None.
        let ir = module(vec![func(
            0,
            None,
            0,
            vec![phi(vec![(1, 1)]), Expr::Use(v(0))],
        )]);
        assert_eq!(resolve_int(&ir, 0, 0), None);
    }

    // --- parameter resolution ---

    /// Helper module: f0 (helper, un-exported) has one param used as-is;
    /// callers are built by the caller of this fn.
    fn helper_with_param() -> HighFunction {
        func(0, None, 1, vec![])
    }

    #[test]
    fn param_from_sole_caller_resolves() {
        // f1: v0 = 2; v1 = call f0(v0). f0's param resolves to 2.
        let ir = module(vec![
            helper_with_param(),
            func(1, None, 0, vec![i64c(2), call(0, vec![v(0)])]),
        ]);
        assert_eq!(resolve_int(&ir, 0, 0), Some(2));
    }

    #[test]
    fn param_from_agreeing_callers_resolves() {
        let ir = module(vec![
            helper_with_param(),
            func(1, None, 0, vec![i64c(2), call(0, vec![v(0)])]),
            func(2, None, 0, vec![i64c(2), call(0, vec![v(0)])]),
        ]);
        assert_eq!(resolve_int(&ir, 0, 0), Some(2));
    }

    #[test]
    fn param_from_disagreeing_callers_returns_none() {
        let ir = module(vec![
            helper_with_param(),
            func(1, None, 0, vec![i64c(1), call(0, vec![v(0)])]),
            func(2, None, 0, vec![i64c(2), call(0, vec![v(0)])]),
        ]);
        assert_eq!(resolve_int(&ir, 0, 0), None);
    }

    #[test]
    fn param_with_no_callers_returns_none() {
        let ir = module(vec![helper_with_param()]);
        assert_eq!(resolve_int(&ir, 0, 0), None);
    }

    #[test]
    fn param_resolves_transitively_through_two_hops() {
        // f2 calls f1(7); f1 forwards its own param to f0. f0's param
        // resolves through both hops.
        let ir = module(vec![
            helper_with_param(),
            func(1, None, 1, vec![call(0, vec![v(0)])]),
            func(2, None, 0, vec![i64c(7), call(1, vec![v(0)])]),
        ]);
        assert_eq!(resolve_int(&ir, 0, 0), Some(7));
    }

    #[test]
    fn exported_function_param_never_resolves() {
        // f0 is exported ("balance") — host-invocable with arbitrary
        // args; the internal call must NOT be treated as the full
        // caller set.
        let ir = module(vec![
            func(0, Some("balance"), 1, vec![]),
            func(1, None, 0, vec![i64c(2), call(0, vec![v(0)])]),
        ]);
        assert_eq!(resolve_int(&ir, 0, 0), None);
    }

    #[test]
    fn indirect_call_kill_switch_disables_param_resolution() {
        // A call_indirect anywhere in the module → caller sets are
        // incomplete → param resolution off.
        let indirect = Expr::Unknown {
            op_kind: WasmOpcodeKind::CallIndirect,
            args: vec![],
            reason: UnknownReason::UnsupportedPattern,
        };
        let ir = module(vec![
            helper_with_param(),
            func(1, None, 0, vec![i64c(2), call(0, vec![v(0)]), indirect]),
        ]);
        assert_eq!(resolve_int(&ir, 0, 0), None);
    }

    #[test]
    fn param_with_incoming_edges_returns_none() {
        // A "param" whose Phi has incoming edges (entry block used as a
        // branch target): meeting only back-edges would be wrong.
        let mut helper = func(0, None, 0, vec![i64c(5), phi(vec![(0, 0)])]);
        helper.params = vec![v(1)]; // mark the phi as a param
        let ir = module(vec![
            helper,
            func(1, None, 0, vec![i64c(7), call(0, vec![v(0)])]),
        ]);
        assert_eq!(resolve_int(&ir, 0, 1), None);
    }

    #[test]
    fn arity_mismatch_caller_returns_none_without_panic() {
        // Caller passes zero args to a one-param helper (malformed IR).
        let ir = module(vec![
            helper_with_param(),
            func(1, None, 0, vec![call(0, vec![])]),
        ]);
        assert_eq!(resolve_int(&ir, 0, 0), None);
    }

    #[test]
    fn mutual_recursion_returns_none() {
        // f0(p) calls f1(p); f1(q) calls f0(q). Pure cycle, no constant
        // entry: must terminate with None.
        let ir = module(vec![
            func(0, None, 1, vec![call(1, vec![v(0)])]),
            func(1, None, 1, vec![call(0, vec![v(0)])]),
        ]);
        assert_eq!(resolve_int(&ir, 0, 0), None);
    }

    #[test]
    fn depth_cap_bounds_long_chains() {
        // A Use chain longer than the cap must yield None, not
        // overflow. resolve_use itself caps at 128, so build the chain
        // from phi links (each is one walk level).
        let mut exprs = vec![i64c(1)];
        for i in 0..200u32 {
            exprs.push(phi(vec![(1, i)]));
        }
        let last = exprs.len() as u32 - 1;
        let ir = module(vec![func(0, None, 0, exprs)]);
        assert_eq!(resolve_int(&ir, 0, last), None);
    }

    // --- u32val flavor discipline ---

    #[test]
    fn u32val_tagged_literal_decodes() {
        let ir = module(vec![func(0, None, 0, vec![i64c(u32val_bits(100))])]);
        assert_eq!(resolve_u32val(&ir, 0, 0), Some(100));
    }

    #[test]
    fn u32val_rejects_wrong_tag() {
        // Tag 6 (U64Small) must NOT decode as a position.
        let bits = (((100u64) << 32) | 6) as i64;
        let ir = module(vec![func(0, None, 0, vec![i64c(bits)])]);
        assert_eq!(resolve_u32val(&ir, 0, 0), None);
    }

    #[test]
    fn u32val_peels_val_encode_small() {
        let ir = module(vec![func(
            0,
            None,
            0,
            vec![
                Expr::Literal(Literal::I32(64)),
                Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall {
                    ty: KnownType::U32,
                    value: v(0),
                })),
            ],
        )]);
        assert_eq!(resolve_u32val(&ir, 0, 1), Some(64));
    }

    #[test]
    fn resolve_int_does_not_peel_val_encode_small() {
        // A Val payload is not the raw integer the durability ABI
        // expects — RawInt flavor must refuse the wrapper.
        let ir = module(vec![func(
            0,
            None,
            0,
            vec![
                Expr::Literal(Literal::I32(2)),
                Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall {
                    ty: KnownType::U32,
                    value: v(0),
                })),
            ],
        )]);
        assert_eq!(resolve_int(&ir, 0, 1), None);
    }

    #[test]
    fn mixed_representation_callers_meet_at_decoded_level() {
        // Caller 1 passes a raw tagged U32Val literal; caller 2 passes
        // the C1-recognized wrapper. Both carry 7 — the meet compares
        // decoded u32s and succeeds.
        let ir = module(vec![
            helper_with_param(),
            func(1, None, 0, vec![i64c(u32val_bits(7)), call(0, vec![v(0)])]),
            func(
                2,
                None,
                0,
                vec![
                    Expr::Literal(Literal::I32(7)),
                    Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall {
                        ty: KnownType::U32,
                        value: v(0),
                    })),
                    call(0, vec![v(1)]),
                ],
            ),
        ]);
        assert_eq!(resolve_u32val(&ir, 0, 0), Some(7));
    }

    #[test]
    fn resolve_bytes_crosses_call_boundary() {
        // The end-to-end shape the corpus has: a helper receives
        // (pos, len) as params; the caller passes constants; the rodata
        // holds the symbol text.
        let mut ir = module(vec![
            func(0, None, 2, vec![]),
            func(
                1,
                None,
                0,
                vec![
                    i64c(u32val_bits(100)),
                    i64c(u32val_bits(8)),
                    call(0, vec![v(0), v(1)]),
                ],
            ),
        ]);
        ir.memory = MemoryImage::from_segments(vec![DataSegment {
            offset: 100,
            bytes: b"transfer".to_vec(),
        }]);
        let calls = CallIndex::build(&ir);
        let mut r = Resolver::new(&ir, &calls);
        assert_eq!(
            r.resolve_bytes(f(0), v(0), v(1)),
            Some(b"transfer".to_vec())
        );
    }

    // --- CallIndex ---

    #[test]
    fn call_index_records_callers_and_sole_caller() {
        let ir = module(vec![
            helper_with_param(),
            func(1, None, 0, vec![i64c(1), call(0, vec![v(0)])]),
        ]);
        let idx = CallIndex::build(&ir);
        assert_eq!(idx.callers_of(f(0)).len(), 1);
        assert_eq!(
            idx.sole_caller(f(0)),
            Some(CallSite {
                caller: f(1),
                call: v(1),
            })
        );
        assert!(idx.callers_of(f(1)).is_empty());
        assert!(!idx.has_indirect_calls());
        // Out-of-range FuncId: empty slice, no panic.
        assert!(idx.callers_of(f(99)).is_empty());
    }

    #[test]
    fn call_index_flags_indirect_calls() {
        let indirect = Expr::Unknown {
            op_kind: WasmOpcodeKind::CallIndirect,
            args: vec![],
            reason: UnknownReason::UnsupportedPattern,
        };
        let ir = module(vec![func(0, None, 0, vec![indirect])]);
        assert!(CallIndex::build(&ir).has_indirect_calls());
    }

    // --- return-value resolution (callee → caller) ---

    /// Set a function's return sites from value indices.
    fn with_returns(mut f: HighFunction, sites: Vec<Vec<u32>>) -> HighFunction {
        f.returns = sites
            .into_iter()
            .map(|vals| vals.into_iter().map(v).collect())
            .collect();
        f
    }

    #[test]
    fn call_result_resolves_from_single_return_site() {
        // f0 returns const 5; f1 calls it.
        let f0 = with_returns(func(0, None, 0, vec![i64c(5)]), vec![vec![0]]);
        let f1 = func(1, None, 0, vec![call(0, vec![])]);
        let ir = module(vec![f0, f1]);
        assert_eq!(resolve_int(&ir, 1, 0), Some(5));
    }

    #[test]
    fn call_result_resolves_through_return_phi() {
        // The corpus shape: f0's body is `v0 = 5; v1 = phi[(bb0, v0)]`
        // and it returns v1.
        let f0 = with_returns(
            func(0, None, 0, vec![i64c(5), phi(vec![(0, 0)])]),
            vec![vec![1]],
        );
        let f1 = func(1, None, 0, vec![call(0, vec![])]);
        let ir = module(vec![f0, f1]);
        assert_eq!(resolve_int(&ir, 1, 0), Some(5));
    }

    #[test]
    fn call_result_meets_agreeing_return_sites() {
        let f0 = with_returns(
            func(0, None, 0, vec![i64c(3), i64c(3)]),
            vec![vec![0], vec![1]],
        );
        let f1 = func(1, None, 0, vec![call(0, vec![])]);
        let ir = module(vec![f0, f1]);
        assert_eq!(resolve_int(&ir, 1, 0), Some(3));
    }

    #[test]
    fn call_result_disagreeing_return_sites_return_none() {
        let f0 = with_returns(
            func(0, None, 0, vec![i64c(1), i64c(2)]),
            vec![vec![0], vec![1]],
        );
        let f1 = func(1, None, 0, vec![call(0, vec![])]);
        let ir = module(vec![f0, f1]);
        assert_eq!(resolve_int(&ir, 1, 0), None);
    }

    #[test]
    fn call_result_dead_site_disagreeing_returns_none() {
        // R7: a Return in an unreachable block still participates; a
        // disagreeing dead site conservatively forces None.
        let f0 = with_returns(
            func(0, None, 0, vec![i64c(7), i64c(9)]),
            vec![vec![0], vec![1]], // second site is "dead" but present
        );
        let f1 = func(1, None, 0, vec![call(0, vec![])]);
        let ir = module(vec![f0, f1]);
        assert_eq!(resolve_int(&ir, 1, 0), None);
    }

    #[test]
    fn call_result_zero_return_sites_returns_none() {
        // Diverging callee (no Return terminator).
        let f0 = func(0, None, 0, vec![i64c(5)]); // returns: []
        let f1 = func(1, None, 0, vec![call(0, vec![])]);
        let ir = module(vec![f0, f1]);
        assert_eq!(resolve_int(&ir, 1, 0), None);
    }

    #[test]
    fn call_result_multi_value_site_returns_none() {
        // A return site with two values → the Call binding is not "the
        // value".
        let f0 = with_returns(
            func(0, None, 0, vec![i64c(1), i64c(2)]),
            vec![vec![0, 1]],
        );
        let f1 = func(1, None, 0, vec![call(0, vec![])]);
        let ir = module(vec![f0, f1]);
        assert_eq!(resolve_int(&ir, 1, 0), None);
    }

    #[test]
    fn recursion_through_return_returns_none() {
        // f0 returns the result of calling itself — pure cycle.
        let f0 = with_returns(func(0, None, 0, vec![call(0, vec![])]), vec![vec![0]]);
        let ir = module(vec![f0]);
        assert_eq!(resolve_int(&ir, 0, 0), None);
    }

    #[test]
    fn u32val_resolves_through_return() {
        // A helper returns a U32Val const; the caller consumes it.
        let f0 = with_returns(
            func(0, None, 0, vec![i64c(u32val_bits(64))]),
            vec![vec![0]],
        );
        let f1 = func(1, None, 0, vec![call(0, vec![])]);
        let ir = module(vec![f0, f1]);
        assert_eq!(resolve_u32val(&ir, 1, 0), Some(64));
    }
}
