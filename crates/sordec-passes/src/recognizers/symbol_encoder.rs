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
//! The gate is exactly the fast path's own precondition — length ≤ 9 and
//! every byte in `[_0-9A-Za-z]`. A string that fails it takes the host
//! fallback at run time, so folding it would be wrong, and the pass
//! declines.
//!
//! The result is self-checking in a way most recognizers are not: the
//! folded strings have to be readable identifiers. On token-v23 they come
//! out as `Balance`, `State`, `Admin`, `Allowance` — that contract's
//! `DataKey` variants. Nonsense here would mean the recognizer had matched
//! something that was not the encoder.

use sordec_common::{
    Diagnostic, FuncId, IrId, LiftDiagnosticCode, Location, Provenance, ProvenanceSource, ValueId,
};
use sordec_ir::{Expr, HighFunction, HighIr, KnownOp, Literal, MemoryImage, SemanticOp};

use crate::dataflow::trace_int;
use crate::pass::{Pass, PassResult};
use crate::val_abi::TAG_SYMBOL_SMALL;

/// Pass name, also its provenance `pass` field.
pub const PASS_NAME: &str = "symbol-encoder";

/// Call sites folded to a symbol literal.
const M_FOLDED: &str = "symbol_encoder_folded";

/// Call sites left alone because the string is not a small symbol.
const M_DECLINED: &str = "symbol_encoder_declined";

/// Longest string the small encoding holds: six bits per character, eight
/// reserved for the tag, so nine characters fill a 64-bit `Val`.
const MAX_SMALL_LEN: u32 = 9;

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
        let encoders: Vec<FuncId> = ir
            .functions
            .iter()
            .filter(|f| is_symbol_encoder(f))
            .map(|f| f.id)
            .collect();

        if encoders.is_empty() {
            return result;
        }

        // Collect first, rewrite second: resolving a call site reads the
        // caller's bindings, which cannot be borrowed while it is mutated.
        let mut folds: Vec<Fold> = Vec::new();
        let mut declined = 0_i64;

        for func in &ir.functions {
            for (id, binding) in func.bindings.iter() {
                let Expr::Call { target, args } = &binding.expr else {
                    continue;
                };
                if !encoders.contains(target) {
                    continue;
                }
                match resolve_call(func, &ir.memory, args) {
                    Some(text) => folds.push(Fold {
                        func: func.id,
                        call: id,
                        projections: projections_of(func, id),
                        lm_pos: args[0],
                        len: args[1],
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

            // The encoder returns `(status, value)`: the fast path cannot
            // fail, so the status is the constant zero its `return` already
            // carries, and the value is the symbol. Each projection becomes
            // the constant it was always going to read.
            for (id, index) in &fold.projections {
                let Some(binding) = func.bindings.get_mut(*id) else {
                    continue;
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
                        len: fold.len,
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

        if declined > 0 {
            result.metrics.increment(M_DECLINED, declined);
        }
        result
    }
}

/// One call site ready to fold.
struct Fold {
    func: FuncId,
    call: ValueId,
    /// The `(binding, component index)` pairs reading this call's tuple.
    projections: Vec<(ValueId, u32)>,
    /// The call's rodata pointer and length, preserved so the folded
    /// `SymbolNew` still records where its text came from.
    lm_pos: ValueId,
    len: ValueId,
    text: String,
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
fn is_symbol_encoder(func: &HighFunction) -> bool {
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

/// The string a call site encodes, if it is one the fast path can hold.
///
/// Returns `None` — decline, leave the call alone — when the arguments are
/// not literal, when the pointer does not resolve in rodata, or when the
/// bytes fall outside what `symbol_short!` can represent. The last case is
/// not a failure: it is the input that makes the SDK take its host
/// fallback, so folding it would change behaviour.
fn resolve_call(func: &HighFunction, memory: &MemoryImage, args: &[ValueId]) -> Option<String> {
    // `(env, pointer, length)` — the emitted signature threads `Env` first,
    // but the IR call carries only the wasm arguments.
    let [pos, len] = args else { return None };
    let pos = u32::try_from(trace_int(func, *pos)?).ok()?;
    let len = u32::try_from(trace_int(func, *len)?).ok()?;

    if len == 0 || len > MAX_SMALL_LEN {
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

    /// `[1000, 1007)` holds "Balance"; `[1010, 1024)` holds a name too long
    /// for the small alphabet.
    fn memory() -> MemoryImage {
        MemoryImage::from_segments(vec![
            DataSegment { offset: 1000, bytes: b"Balance".to_vec() },
            DataSegment { offset: 1010, bytes: b"a-hyphenated!!".to_vec() },
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

    #[test]
    fn a_string_longer_than_nine_characters_is_declined() {
        let mut m = ir(vec![
            function(0, encoder_body()),
            // Ten bytes starting at 1010 are in-alphabet only for the first
            // one; length alone must decline it regardless.
            caller(1000, 10),
        ]);
        let r = SymbolEncoderPass.run(&mut m);
        assert!(!r.changed);
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

    /// Passes may sit in a fixpoint group; a second run must find nothing
    /// left to do rather than re-fold.
    #[test]
    fn the_pass_is_idempotent() {
        let mut m = ir(vec![function(0, encoder_body()), caller(1000, 7)]);
        assert!(SymbolEncoderPass.run(&mut m).changed);
        assert!(!SymbolEncoderPass.run(&mut m).changed);
    }
}
