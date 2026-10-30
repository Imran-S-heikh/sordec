//! The SDK's inlined small-symbol encoder, folded to the literal it computes.
//!
//! # What this recognises
//!
//! `Symbol::try_from_val(&env, "Balance")` is one line of source. rustc
//! monomorphises and inlines it into a helper that looks like this:
//!
//! ```text
//! acc = 0
//! for c in bytes:
//!     if c == 95           { code = 1      }   // '_'
//!     else if (c-48)&255 < 10  { code = c-46 }  // '0'..'9' -> 2..=11
//!     else if (c-65)&255 < 26  { code = c-53 }  // 'A'..'Z' -> 12..=37
//!     else if (c-97)&255 > 25  { …host fallback… }
//!     else                 { code = c-59 }      // 'a'..'z' -> 38..=63
//!     acc = (acc << 6) | (code & 255)
//! return (acc << 8) | 14                        // tag 14 = SymbolSmall
//! ```
//!
//! On token-v23 that is **`func7`: thirteen control-flow constructs
//! reachable from ten of thirteen entrypoints — 130 of the module's 538
//! weighted structure tokens, 24% of the whole deficit, for a construct the
//! source spells with no control flow at all.**
//!
//! # Why the existing recognizers cannot see it
//!
//! [`super::linear_memory`] recognises `symbol_new_from_linear_memory`, the
//! **host call**. This encoder makes no host call on its fast path — it is
//! arithmetic over rodata — so there is no import to classify. It is the
//! same reason the signature catalogue misses it: `Symbol as TryFromVal` is
//! a generic whose body varies with the context it was instantiated into,
//! and two contracts built against one SDK version produce two different
//! bodies for it.
//!
//! So this is an *idiom* recognizer, keyed on what the code computes rather
//! than on what it is called.
//!
//! # What it folds, and why that is exact rather than approximate
//!
//! Every call site passes a **literal** `(pointer, length)` into rodata, so
//! the encoder's input is fixed at compile time and its output is a
//! constant. This is constant folding, not a behavioural claim: there is no
//! relocation argument to make and no trap to relocate, because for an
//! in-alphabet string of nine characters or fewer the loop cannot fail.
//!
//! The gate is the symbol alphabet — every byte in `[_0-9A-Za-z]`, at
//! most 32 of them. A string of nine characters or fewer takes the fast
//! path and the loop cannot fail; a longer one makes the encoder fall
//! back to the `symbol_new_from_linear_memory` host call, which builds
//! the same symbol as an object. Either way the helper's result *is* the
//! symbol for that string, and `Symbol::new(&env, "…")` — what the
//! folded op renders as — takes exactly the same two paths. A byte
//! outside the alphabet would make the host reject the string, so that
//! is where the pass declines.
//!
//! # A length the compiler baked into the helper
//!
//! When every call site passes the same length, the compiler propagates it
//! into the helper and drops the parameter: the helper takes only the
//! pointer, the loop runs to the constant, and the host fallback is handed
//! the constant. Four-letter variant names (`VarA`, `VarB`, `VarC`) build
//! exactly this. The call site then carries no length, so the length is
//! read from the helper itself — from the fallback's own host call,
//! `symbol_new_from_linear_memory(U32Val(ptr), U32Val(n))`, whose pointer
//! is the helper's one parameter and whose length is a constant word read
//! through its `U32Val` decode. That call builds the symbol from the same
//! slice the fast path packs, so `n` is the string's length.
//!
//! Gates, beyond the constant set: the helper takes exactly one parameter;
//! one such fallback names it, with one constant length (two disagreeing
//! fallbacks decline); and the fast path's loop bound — an equality test
//! against the literal `n` — is in the body as a second witness. Without
//! all three the call site is left alone, as before.
//!
//! # The encoder behind a one-call wrapper
//!
//! `Symbol::new(&env, "used_event_simple")` often reaches the encoder
//! through a helper of its own, `func3(ptr, len)`, which hands its two
//! parameters to the encoder unchanged and returns the encoder's symbol
//! component. Its call sites carry the literals; the encoder's own call
//! site, inside the wrapper, carries only parameters, so nothing folded.
//! A call of such a wrapper with a literal `(pointer, length)` is folded
//! to the same `Symbol::new(&env, "…")`.
//!
//! Why it is exact: the wrapper computes nothing else — every other
//! binding in it is pure and total, it has no branch, and each of its
//! returns hands back that one component — so the call's value is the
//! encoder's for that slice, which is the symbol (the argument above).
//! The gates are those conditions, the encoder taking the length as an
//! argument (not baked in), and the call site's literals passing the same
//! alphabet check as a direct call's.
//!
//! The result is self-checking in a way most recognizers are not: the
//! folded strings have to be readable identifiers. On token-v23 they come
//! out as `Balance`, `State`, `Admin`, `Allowance` — that contract's
//! `DataKey` variants. Nonsense here would mean the recognizer had matched
//! something that was not the encoder.

use sordec_common::{
    Diagnostic, FuncId, IrId, LiftDiagnosticCode, Location, Provenance, ProvenanceSource, ValueId,
};
use sordec_ir::{
    BinaryOp, Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Literal, MemoryImage, SemanticOp,
};

use crate::dataflow::trace_int;
use crate::pass::{Pass, PassResult};
use crate::val_abi::TAG_SYMBOL_SMALL;

/// Pass name, also its provenance `pass` field.
pub const PASS_NAME: &str = "symbol-encoder";

/// Call sites folded to a symbol literal.
const M_FOLDED: &str = "symbol_encoder_folded";

/// Call sites left alone because the string is not a small symbol.
const M_DECLINED: &str = "symbol_encoder_declined";

/// Longest symbol the host accepts. The *small* encoding holds nine (six
/// bits per character, eight reserved for the tag); beyond that the
/// encoder's fallback builds a `SymbolObject`, and the fold is still the
/// same symbol.
const MAX_SYMBOL_LEN: u32 = 32;

/// The character-code offsets the SDK's encoder subtracts, one per class.
///
/// These are the pass's signature. They are not round numbers and they are
/// not arbitrary: each is chosen so its character class lands contiguously
/// in the 6-bit code space (`'0'` at 2, `'A'` at 12, `'a'` at 38). Finding
/// all three in one body, together with the `SymbolSmall` tag, is what
/// identifies the encoder.
const CLASS_OFFSETS: [i128; 3] = [-46, -53, -59];

/// `'_'`, the one character the encoder tests for by equality.
const UNDERSCORE: i128 = 95;

/// Folds inlined small-symbol construction to the literal it computes.
#[derive(Debug, Default, Clone, Copy)]
pub struct SymbolEncoderPass;

impl Pass<HighIr> for SymbolEncoderPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();

        // Which functions are the encoder. Computed once: the scan is over
        // every binding of every function, and call sites are everywhere.
        // Each with the length the compiler baked into it, when it takes
        // only the pointer.
        let encoders: Vec<(FuncId, Option<u32>)> = ir
            .functions
            .iter()
            .filter(|f| is_symbol_encoder(f))
            .map(|f| (f.id, baked_length(f)))
            .collect();

        if encoders.is_empty() {
            return result;
        }
        // Helpers that only forward to an encoder taking its length.
        let wrappers: Vec<FuncId> = ir
            .functions
            .iter()
            .filter(|f| forwarding_wrapper(f, &encoders))
            .map(|f| f.id)
            .collect();

        // Collect first, rewrite second: resolving a call site reads the
        // caller's bindings, which cannot be borrowed while it is mutated.
        let mut folds: Vec<Fold> = Vec::new();
        let mut declined = 0_i64;

        let mut wrapped: Vec<(FuncId, ValueId, ValueId, ValueId, String)> = Vec::new();
        for func in &ir.functions {
            for (id, binding) in func.bindings.iter() {
                let Expr::Call { target, args } = &binding.expr else {
                    continue;
                };
                if wrappers.contains(target)
                    && let [pos, len] = args.as_slice()
                    && let Some(text) = resolve_call(func, &ir.memory, args, None)
                {
                    wrapped.push((func.id, id, *pos, *len, text));
                    continue;
                }
                let Some(&(_, baked)) = encoders.iter().find(|(f, _)| f == target) else {
                    continue;
                };
                match resolve_call(func, &ir.memory, args, baked) {
                    Some(text) => folds.push(Fold {
                        func: func.id,
                        call: id,
                        projections: projections_of(func, id),
                        lm_pos: args[0],
                        // `resolve_call` read the length from one or the other.
                        len: match (args.get(1), baked) {
                            (Some(len), _) => Ok(*len),
                            (None, n) => Err(n.unwrap_or_default()),
                        },
                        text,
                    }),
                    None => declined += 1,
                }
            }
        }

        for fold in folds {
            let Some(func) = ir.function_mut(fold.func) else {
                continue;
            };
            // A baked length has no operand at the call site; the folded op
            // records it as a literal planted just before the call.
            let len = match fold.len {
                Ok(len) => len,
                Err(n) => match plant_length(func, fold.call, n) {
                    Some(len) => len,
                    None => continue,
                },
            };

            // The encoder returns `(status, value)`: the fast path cannot
            // fail, so the status is the constant zero its `return` already
            // carries, and the value is the symbol. Each projection becomes
            // the constant it was always going to read.
            for (id, index) in &fold.projections {
                let Some(binding) = func.bindings.get_mut(*id) else {
                    continue;
                };
                // The value is a `Symbol` — say so here rather than leave
                // it to inference, which runs after the elision group and
                // so after the parameter evidence that reads these types
                // has been gathered. A helper taking this symbol is
                // otherwise typed by its body as taking a bare `Val`, and
                // the reconstruction does not compile.
                binding.ty = match index {
                    0 => IrType::Known(KnownType::I64),
                    _ => IrType::Known(KnownType::Symbol),
                };
                binding.expr = match index {
                    0 => Expr::Literal(Literal::I64(0)),
                    // Not a bare `Literal::Symbol`. `KnownOp::SymbolNew` is
                    // the representation the rest of the pipeline already
                    // reads — `EnumKeyPass` and `wrappers` trace a storage
                    // key back to exactly this op — and the emitter already
                    // renders a resolved one as `Symbol::new(&e, "…")`.
                    // Inventing a parallel encoding cost 0.18 of semantic
                    // score before this was corrected: the symbol rendered
                    // fine and every consumer downstream went blind.
                    _ => Expr::Semantic(SemanticOp::Known(KnownOp::SymbolNew {
                        lm_pos: fold.lm_pos,
                        len,
                        resolved: Some(fold.text.clone()),
                    })),
                };
                binding.add_provenance(Provenance::new(
                    PASS_NAME,
                    ProvenanceSource::SdkPattern,
                    format!("small-symbol encoder result: {:?}", fold.text),
                ));
            }

            // Then the call itself. Rewriting it to a pure literal — rather
            // than deleting it — is this codebase's elision idiom: nothing
            // leaves the arena, provenance is preserved, and the backend's
            // existing dead-`let` pass removes what no longer has a reader.
            // It is also what makes the callee unreachable, which is where
            // the structure win actually comes from: the emitter skips a
            // helper nothing calls, and the encoder's thirteen control-flow
            // constructs leave every entrypoint closure at once.
            if let Some(binding) = func.bindings.get_mut(fold.call) {
                binding.expr = Expr::Literal(Literal::Unit);
                binding.add_provenance(Provenance::new(
                    PASS_NAME,
                    ProvenanceSource::SdkPattern,
                    "inlined small-symbol encoder, constant-folded",
                ));
            }

            result.metrics.increment(M_FOLDED, 1);
            result.diagnostics.push(
                Diagnostic::info(
                    LiftDiagnosticCode::SdkFunctionIdentified,
                    format!("inlined symbol encoder folded to `{}`", fold.text),
                )
                .at(Location::Value {
                    func: fold.func,
                    value: fold.call.index(),
                }),
            );
            result.changed = true;
        }

        for (func, call, lm_pos, len, text) in wrapped {
            let Some(func) = ir.function_mut(func) else { continue };
            let Some(binding) = func.bindings.get_mut(call) else { continue };
            binding.ty = IrType::Known(KnownType::Symbol);
            binding.expr = Expr::Semantic(SemanticOp::Known(KnownOp::SymbolNew {
                lm_pos,
                len,
                resolved: Some(text.clone()),
            }));
            binding.add_provenance(Provenance::new(
                PASS_NAME,
                ProvenanceSource::SdkPattern,
                format!("a helper that only forwards to the small-symbol encoder, constant-folded: {text:?}"),
            ));
            result.metrics.increment(M_FOLDED, 1);
            result.changed = true;
        }

        if declined > 0 {
            result.metrics.increment(M_DECLINED, declined);
        }
        result
    }
}

/// Whether `func` is a wrapper "The encoder behind a one-call wrapper"
/// names: two parameters handed in order to an encoder that takes its
/// length, the encoder's symbol component returned on every path, and
/// nothing else but pure, total bindings and straight-line control flow.
fn forwarding_wrapper(func: &HighFunction, encoders: &[(FuncId, Option<u32>)]) -> bool {
    let [p0, p1] = func.params.as_slice() else { return false };
    if func.signature.is_some() {
        return false;
    }
    let mut straight = true;
    func.region.for_each_node(|r| {
        straight &= !matches!(
            r,
            sordec_ir::Region::If { .. }
                | sordec_ir::Region::Loop { .. }
                | sordec_ir::Region::Switch { .. }
                | sordec_ir::Region::Unstructured { .. }
                | sordec_ir::Region::Panic { .. }
                | sordec_ir::Region::Unreachable
        );
    });
    if !straight {
        return false;
    }
    let resolve = |v: ValueId| crate::dataflow::resolve_use(func, v);
    let mut call: Option<ValueId> = None;
    for (_, block) in func.blocks.iter() {
        for &id in &block.bindings {
            let Some(b) = func.bindings.get(id) else { return false };
            match &b.expr {
                Expr::Call { target, args } => {
                    let forwards = encoders.iter().any(|(f, baked)| f == target && baked.is_none())
                        && matches!(args.as_slice(), [a, b] if resolve(*a) == *p0 && resolve(*b) == *p1);
                    if !forwards || call.replace(id).is_some() {
                        return false;
                    }
                }
                other => {
                    if !crate::effects::expr_effects(other).is_pure_total() {
                        return false;
                    }
                }
            }
        }
    }
    let Some(call) = call else { return false };
    let mut returns = 0;
    let symbol = |v: ValueId| {
        matches!(func.bindings.get(resolve(v)).map(|b| &b.expr), Some(Expr::Project { value, index: 1 }) if resolve(*value) == call)
    };
    for site in &func.returns {
        match site.as_slice() {
            [x] if symbol(*x) => returns += 1,
            _ => return false,
        }
    }
    returns > 0
}

/// One call site ready to fold.
struct Fold {
    func: FuncId,
    call: ValueId,
    /// The `(binding, component index)` pairs reading this call's tuple.
    projections: Vec<(ValueId, u32)>,
    /// The call's rodata pointer and length, preserved so the folded
    /// `SymbolNew` still records where its text came from. A length the
    /// helper baked in has no operand: `Err(n)`, planted at the fold.
    lm_pos: ValueId,
    len: Result<ValueId, u32>,
    text: String,
}

/// Schedule the literal `n` just before `call`, for a folded `SymbolNew`
/// whose length the helper baked in. `None` when the call is not scheduled.
fn plant_length(func: &mut HighFunction, call: ValueId, n: u32) -> Option<ValueId> {
    let block = crate::dataflow::block_containing(func, call)?;
    let id = ValueId::from_index(func.bindings.len() as u32);
    func.bindings.push(sordec_ir::Binding::new(
        id,
        IrType::Known(KnownType::U32),
        Expr::Literal(Literal::U32(n)),
        Provenance::new(
            PASS_NAME,
            ProvenanceSource::SdkPattern,
            "the length the small-symbol encoder's host fallback is handed",
        ),
    ));
    let block = func.blocks.get_mut(block)?;
    let at = block.bindings.iter().position(|b| *b == call)?;
    block.bindings.insert(at, id);
    Some(id)
}

/// The string length the compiler baked into a one-parameter encoder: the
/// constant its host fallback is handed beside that parameter, confirmed by
/// the fast path's loop bound. `None` for an encoder that takes the length
/// as an argument, or whose body does not say it in both places.
fn baked_length(func: &HighFunction) -> Option<u32> {
    let [ptr] = func.params.as_slice() else { return None };
    let mut found: Option<u32> = None;
    for (_, b) in func.bindings.iter() {
        let Expr::Semantic(SemanticOp::Known(KnownOp::SymbolNew { lm_pos, len, .. })) = &b.expr else {
            continue;
        };
        if crate::marshalling::udt_decode::raw_address(func, *lm_pos) != *ptr {
            continue;
        }
        let n = encoded_constant_u32(func, *len)?;
        if found.is_some_and(|m| m != n) {
            return None;
        }
        found = Some(n);
    }
    let n = found?;
    let bound = func.bindings.iter().any(|(_, b)| match &b.expr {
        Expr::Binary { op: BinaryOp::Eq | BinaryOp::Ne, lhs, rhs } => [lhs, rhs]
            .iter()
            .any(|x| matches!(literal_of(func, **x), Some(m) if m == i128::from(n))),
        _ => false,
    });
    bound.then_some(n)
}

/// The `U32Val` payload of a constant word or of an encode of a constant —
/// the word read through its decode, never as its raw bits.
fn encoded_constant_u32(func: &HighFunction, value: ValueId) -> Option<u32> {
    match &func.bindings.get(crate::dataflow::resolve_use(func, value))?.expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty: KnownType::U32, .. }))
        | Expr::Literal(Literal::I64(_) | Literal::U64(_)) => crate::dataflow::trace_u32val(func, value),
        _ => None,
    }
}

/// The integer literal `value` names, through renames.
fn literal_of(func: &HighFunction, value: ValueId) -> Option<i128> {
    match &func.bindings.get(crate::dataflow::resolve_use(func, value))?.expr {
        Expr::Literal(lit) => literal_int(lit),
        _ => None,
    }
}

/// Every binding that projects a component out of `call`.
///
/// The encoder is multi-value, so its result is read through
/// [`Expr::Project`] rather than used directly. Those readers have to be
/// folded too — rewriting only the call would leave them projecting out of
/// a scalar.
fn projections_of(func: &HighFunction, call: ValueId) -> Vec<(ValueId, u32)> {
    func.bindings
        .iter()
        .filter_map(|(id, b)| match &b.expr {
            Expr::Project { value, index } if *value == call => Some((id, *index)),
            _ => None,
        })
        .collect()
}

/// Whether a function is the SDK's inlined small-symbol encoder.
///
/// Keyed on the constants it must contain: all three class offsets, the
/// `'_'` test, and the `SymbolSmall` tag. Requiring the whole set is what
/// makes this safe — any one of them appears in ordinary arithmetic, but a
/// body holding `-46`, `-53`, `-59`, `95` and `14` together is doing the
/// SDK's six-bit character packing and nothing else.
///
/// Deliberately *not* a structural match on the loop. The loop's shape
/// varies with inlining and optimisation; the constants are what the
/// algorithm is.
pub(crate) fn is_symbol_encoder(func: &HighFunction) -> bool {
    let mut offsets_seen = [false; CLASS_OFFSETS.len()];
    let mut underscore = false;
    let mut tag = false;

    for (_, binding) in func.bindings.iter() {
        let Expr::Literal(lit) = &binding.expr else {
            continue;
        };
        let Some(n) = literal_int(lit) else { continue };

        if n == UNDERSCORE {
            underscore = true;
        }
        if n == i128::from(TAG_SYMBOL_SMALL) {
            tag = true;
        }
        for (i, off) in CLASS_OFFSETS.iter().enumerate() {
            if n == *off {
                offsets_seen[i] = true;
            }
        }
    }

    underscore && tag && offsets_seen.iter().all(|b| *b)
}

/// The string a call site encodes, if it is a symbol the host accepts.
///
/// Returns `None` — decline, leave the call alone — when the arguments are
/// not literal, when the pointer does not resolve in rodata, or when the
/// bytes fall outside the symbol alphabet. The last case is the input the
/// host rejects, so there is no symbol to fold to.
fn resolve_call(func: &HighFunction, memory: &MemoryImage, args: &[ValueId], baked: Option<u32>) -> Option<String> {
    // `(env, pointer, length)` — the emitted signature threads `Env` first,
    // but the IR call carries only the wasm arguments. A helper with the
    // length baked in takes the pointer alone.
    let (pos, len) = match (args, baked) {
        ([pos, len], None) => (*pos, u32::try_from(trace_int(func, *len)?).ok()?),
        ([pos], Some(n)) => (*pos, n),
        _ => return None,
    };
    let pos = u32::try_from(trace_int(func, pos)?).ok()?;

    if len == 0 || len > MAX_SYMBOL_LEN {
        return None;
    }
    let bytes = memory.read(pos, len)?;
    if !bytes
        .iter()
        .all(|b| *b == b'_' || b.is_ascii_alphanumeric())
    {
        return None;
    }
    core::str::from_utf8(bytes).ok().map(str::to_owned)
}

/// The integer a literal holds, for the constant scan.
fn literal_int(lit: &Literal) -> Option<i128> {
    match lit {
        Literal::I32(n) => Some(i128::from(*n)),
        Literal::I64(n) => Some(i128::from(*n)),
        Literal::U32(n) => Some(i128::from(*n)),
        Literal::U64(n) => Some(i128::from(*n)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{Arena, BlockId, ProvenanceSource, UnknownReason};
    use sordec_ir::{Binding, DataSegment, HighBlock, IrType, Region, WasmFacts};

    fn v(i: u32) -> ValueId {
        ValueId::from_index(i)
    }

    fn seed(id: ValueId, expr: Expr) -> Binding {
        Binding::new(
            id,
            IrType::Unknown(UnknownReason::InsufficientEvidence),
            expr,
            Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
        )
    }

    fn function(id: u32, exprs: Vec<Expr>) -> HighFunction {
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        for expr in exprs {
            let vid = ValueId::from_index(bindings.len() as u32);
            bindings.push(seed(vid, expr));
        }
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        blocks.push(HighBlock {
            id: BlockId::from_index(0),
            bindings: vec![],
        });
        HighFunction {
            id: FuncId::from_index(id),
            name: None,
            signature: None,
            aliases: Vec::new(),
            blocks,
            bindings,
            region: Region::Unreachable,
            params: vec![],
            returns: vec![],
        }
    }

    /// The constants that identify the encoder: `'_'`, the three class
    /// offsets, and the `SymbolSmall` tag.
    fn encoder_body() -> Vec<Expr> {
        [UNDERSCORE, -46, -53, -59, i128::from(TAG_SYMBOL_SMALL)]
            .iter()
            .map(|n| Expr::Literal(Literal::I32(*n as i32)))
            .collect()
    }

    /// `[1000, 1007)` holds "Balance"; `[1010, 1024)` holds a name outside
    /// the symbol alphabet; `[1030, 1041)` holds an eleven-character name
    /// that only the host fallback can build; `[1050, 1083)` is one
    /// character too long for any symbol.
    fn memory() -> MemoryImage {
        MemoryImage::from_segments(vec![
            DataSegment { offset: 1000, bytes: b"Balance".to_vec() },
            DataSegment { offset: 1010, bytes: b"a-hyphenated!!".to_vec() },
            DataSegment { offset: 1030, bytes: b"TotalShares".to_vec() },
            DataSegment { offset: 1050, bytes: b"a".repeat(33) },
        ])
    }

    /// A caller holding `pos`, `len`, the call, and its two projections.
    fn caller(pos: i32, len: i32) -> HighFunction {
        function(
            1,
            vec![
                Expr::Literal(Literal::I32(pos)),
                Expr::Literal(Literal::I32(len)),
                Expr::Call { target: FuncId::from_index(0), args: vec![v(0), v(1)] },
                Expr::Project { value: v(2), index: 0 },
                Expr::Project { value: v(2), index: 1 },
            ],
        )
    }

    fn ir(functions: Vec<HighFunction>) -> HighIr {
        HighIr {
            facts: WasmFacts {
                imports: vec![],
                exports: vec![],
                function_type_indices: vec![],
                function_bodies: vec![],
                function_fingerprints: vec![],
                table_functions: None,
                custom_sections: vec![],
            },
            soroban_facts: None,
            functions,
            memory: memory(),
        }
    }

    fn expr_at(ir: &HighIr, func: u32, value: u32) -> &Expr {
        &ir.function(FuncId::from_index(func))
            .unwrap()
            .bindings
            .get(v(value))
            .unwrap()
            .expr
    }

    /// `fn func1(ptr, len) -> Val { encoder(ptr, len).1 }`, with `extra`
    /// scheduled beside the call.
    fn wrapper(extra: Option<Expr>) -> HighFunction {
        let mut exprs = vec![
            Expr::Phi { incoming: vec![] },
            Expr::Phi { incoming: vec![] },
            Expr::Call { target: FuncId::from_index(0), args: vec![v(0), v(1)] },
            Expr::Project { value: v(2), index: 1 },
        ];
        let mut scheduled = vec![v(2), v(3)];
        if let Some(e) = extra {
            exprs.push(e);
            scheduled.push(v(4));
        }
        let mut f = function(1, exprs);
        f.params = vec![v(0), v(1)];
        f.blocks.get_mut(BlockId::from_index(0)).unwrap().bindings = scheduled;
        f.region = Region::Basic(BlockId::from_index(0));
        f.returns = vec![vec![v(3)]];
        f
    }

    fn wrapper_caller() -> HighFunction {
        function(
            2,
            vec![
                Expr::Literal(Literal::I32(1000)),
                Expr::Literal(Literal::I32(7)),
                Expr::Call { target: FuncId::from_index(1), args: vec![v(0), v(1)] },
            ],
        )
    }

    /// A helper that only forwards to the encoder is the encoder at its
    /// call site.
    #[test]
    fn a_forwarding_wrapper_folds_at_its_literal_call_site() {
        let mut m = ir(vec![function(0, encoder_body()), wrapper(None), wrapper_caller()]);
        assert!(SymbolEncoderPass.run(&mut m).changed);
        match expr_at(&m, 2, 2) {
            Expr::Semantic(SemanticOp::Known(KnownOp::SymbolNew { resolved, .. })) => {
                assert_eq!(resolved.as_deref(), Some("Balance"));
            }
            other => panic!("expected a resolved SymbolNew, got {other:?}"),
        }
    }

    /// A wrapper that also writes memory does more than forward.
    #[test]
    fn a_wrapper_with_an_effect_is_left_alone() {
        let store = Expr::Store { addr: v(0), value: v(3), offset: 0, width: sordec_ir::MemWidth::W8 };
        let mut m = ir(vec![function(0, encoder_body()), wrapper(Some(store)), wrapper_caller()]);
        SymbolEncoderPass.run(&mut m);
        assert!(matches!(expr_at(&m, 2, 2), Expr::Call { .. }));
    }

    #[test]
    fn a_literal_call_site_folds_to_a_resolved_symbol() {
        let mut m = ir(vec![function(0, encoder_body()), caller(1000, 7)]);
        let r = SymbolEncoderPass.run(&mut m);

        assert!(r.changed);
        assert_eq!(r.metrics.get(M_FOLDED), Some(1));

        // The value component becomes the op the rest of the pipeline reads.
        match expr_at(&m, 1, 4) {
            Expr::Semantic(SemanticOp::Known(KnownOp::SymbolNew { resolved, .. })) => {
                assert_eq!(resolved.as_deref(), Some("Balance"));
            }
            other => panic!("expected a resolved SymbolNew, got {other:?}"),
        }
        // The status component is the zero the encoder's fast path returns.
        assert!(matches!(expr_at(&m, 1, 3), Expr::Literal(Literal::I64(0))));
        // And the call is gone, which is what makes the callee unreachable.
        assert!(matches!(expr_at(&m, 1, 2), Expr::Literal(Literal::Unit)));
    }

    /// The gate is the fast path's own precondition. A string the small
    /// alphabet cannot hold takes the host fallback at run time, so folding
    /// it would change behaviour.
    #[test]
    fn a_string_outside_the_small_alphabet_is_declined() {
        let mut m = ir(vec![function(0, encoder_body()), caller(1010, 14)]);
        let r = SymbolEncoderPass.run(&mut m);

        assert!(!r.changed);
        assert_eq!(r.metrics.get(M_DECLINED), Some(1));
        assert!(matches!(expr_at(&m, 1, 2), Expr::Call { .. }));
    }

    /// Past nine characters the encoder takes its host fallback, which
    /// builds the same symbol as an object — and so does the `Symbol::new`
    /// the folded op renders as. dex's `DataKey::TotalShares` is the
    /// corpus witness: declining it kept the whole encoder alive.
    #[test]
    fn a_string_longer_than_nine_characters_still_folds() {
        let mut m = ir(vec![function(0, encoder_body()), caller(1030, 11)]);
        let r = SymbolEncoderPass.run(&mut m);
        assert!(r.changed);
        match expr_at(&m, 1, 4) {
            Expr::Semantic(SemanticOp::Known(KnownOp::SymbolNew { resolved, .. })) => {
                assert_eq!(resolved.as_deref(), Some("TotalShares"));
            }
            other => panic!("expected a resolved SymbolNew, got {other:?}"),
        }
    }

    /// Thirty-two characters is the host's limit; beyond it there is no
    /// symbol to fold to.
    #[test]
    fn a_string_longer_than_any_symbol_is_declined() {
        let mut m = ir(vec![function(0, encoder_body()), caller(1050, 33)]);
        let r = SymbolEncoderPass.run(&mut m);
        assert!(!r.changed);
        assert_eq!(r.metrics.get(M_DECLINED), Some(1));
    }

    /// The signature is the whole constant set. A body holding only some of
    /// it is ordinary arithmetic and must not be treated as the encoder.
    #[test]
    fn a_partial_constant_set_is_not_the_encoder() {
        for missing in 0..5 {
            let mut body = encoder_body();
            body.remove(missing);
            let mut m = ir(vec![function(0, body), caller(1000, 7)]);
            let r = SymbolEncoderPass.run(&mut m);
            assert!(
                !r.changed,
                "dropping constant #{missing} must stop the match"
            );
        }
    }

    #[test]
    fn a_non_literal_argument_is_declined() {
        let mut m = ir(vec![
            function(0, encoder_body()),
            function(
                1,
                vec![
                    Expr::Phi { incoming: vec![] },
                    Expr::Literal(Literal::I32(7)),
                    Expr::Call { target: FuncId::from_index(0), args: vec![v(0), v(1)] },
                ],
            ),
        ]);
        let r = SymbolEncoderPass.run(&mut m);
        assert!(!r.changed);
        assert_eq!(r.metrics.get(M_DECLINED), Some(1));
    }

    #[test]
    fn a_module_without_the_encoder_is_untouched() {
        let mut m = ir(vec![
            function(0, vec![Expr::Literal(Literal::I32(1))]),
            caller(1000, 7),
        ]);
        let r = SymbolEncoderPass.run(&mut m);
        assert!(!r.changed);
        assert_eq!(r.metrics.get(M_FOLDED), None);
    }

    /// An encoder the compiler specialised to one length: it takes the
    /// pointer alone (v5), runs its loop to the constant (`eq v6, v7`), and
    /// hands the host fallback `U32Val(v5)` and the constant word
    /// `U32Val(len)`.
    fn baked_encoder(fallback_len: u32, bound: i32) -> HighFunction {
        let mut body = encoder_body();
        let word = (i64::from(fallback_len) << 32) | 4;
        body.extend([
            Expr::Phi { incoming: vec![] },                                        // v5  ptr
            Expr::Phi { incoming: vec![] },                                        // v6  i
            Expr::Literal(Literal::I32(bound)),                                    // v7
            Expr::Binary { op: BinaryOp::Eq, lhs: v(6), rhs: v(7) },               // v8
            Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty: KnownType::U32, value: v(5) })), // v9
            Expr::Literal(Literal::I64(word)),                                     // v10
            Expr::Semantic(SemanticOp::Known(KnownOp::SymbolNew { lm_pos: v(9), len: v(10), resolved: None })), // v11
        ]);
        let mut f = function(0, body);
        f.params = vec![v(5)];
        f
    }

    /// A caller handing the baked encoder only the pointer.
    fn pointer_only_caller(pos: i32) -> HighFunction {
        let mut f = function(
            1,
            vec![
                Expr::Literal(Literal::I32(pos)),
                Expr::Call { target: FuncId::from_index(0), args: vec![v(0)] },
                Expr::Project { value: v(1), index: 0 },
                Expr::Project { value: v(1), index: 1 },
            ],
        );
        f.blocks.iter_mut().next().unwrap().1.bindings = vec![v(0), v(1), v(2), v(3)];
        f
    }

    #[test]
    fn a_length_baked_into_the_encoder_is_read_from_its_fallback() {
        // "Bala" — the first four bytes of the `Balance` segment.
        let mut m = ir(vec![baked_encoder(4, 4), pointer_only_caller(1000)]);
        let r = SymbolEncoderPass.run(&mut m);
        assert!(r.changed);
        let Expr::Semantic(SemanticOp::Known(KnownOp::SymbolNew { resolved, len, .. })) = expr_at(&m, 1, 3) else {
            panic!("expected a resolved SymbolNew, got {:?}", expr_at(&m, 1, 3));
        };
        assert_eq!(resolved.as_deref(), Some("Bala"));
        // The planted length is the literal, scheduled before the call.
        let func = m.function(FuncId::from_index(1)).unwrap();
        assert!(matches!(func.bindings.get(*len).unwrap().expr, Expr::Literal(Literal::U32(4))));
        let order = &func.blocks.iter().next().unwrap().1.bindings;
        let at = |x: ValueId| order.iter().position(|b| *b == x).unwrap();
        assert!(at(*len) < at(v(1)));
    }

    /// The loop bound is the second witness: a fallback length the fast
    /// path does not also run to is not read.
    #[test]
    fn a_baked_length_without_the_loop_bound_is_declined() {
        let mut m = ir(vec![baked_encoder(4, 5), pointer_only_caller(1000)]);
        let r = SymbolEncoderPass.run(&mut m);
        assert!(!r.changed);
        assert!(matches!(expr_at(&m, 1, 1), Expr::Call { .. }));
    }

    /// A fallback built from something other than the parameter says
    /// nothing about the parameter's length.
    #[test]
    fn a_fallback_not_on_the_parameter_is_not_a_length() {
        let mut enc = baked_encoder(4, 4);
        enc.params = vec![v(6)];
        let mut m = ir(vec![enc, pointer_only_caller(1000)]);
        assert!(!SymbolEncoderPass.run(&mut m).changed);
    }

    /// A pointer-only call to an encoder that takes its length is not
    /// read either way.
    #[test]
    fn a_pointer_only_call_to_a_two_parameter_encoder_is_declined() {
        let mut m = ir(vec![function(0, encoder_body()), pointer_only_caller(1000)]);
        let r = SymbolEncoderPass.run(&mut m);
        assert!(!r.changed);
        assert_eq!(r.metrics.get(M_DECLINED), Some(1));
    }

    /// Passes may sit in a fixpoint group; a second run must find nothing
    /// left to do rather than re-fold.
    #[test]
    fn the_pass_is_idempotent() {
        let mut m = ir(vec![function(0, encoder_body()), caller(1000, 7)]);
        assert!(SymbolEncoderPass.run(&mut m).changed);
        assert!(!SymbolEncoderPass.run(&mut m).changed);
    }
}
