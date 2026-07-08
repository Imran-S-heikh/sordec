//! The Soroban linear-memory constructor recognizer.
//!
//! Soroban builds `Symbol` / `String` / `Bytes` / `Vec` / `Map` host
//! objects from data laid out in WASM linear memory, via the
//! `*_new_from_linear_memory` host calls (modules `b`/`v`/`m`). This pass
//! turns those five opaque host calls into first-class [`KnownOp`]s.
//!
//! ## Op recognition vs. literal recovery
//!
//! Decoupled, exactly like the storage recognizer's op-vs-tier split. The
//! `(module, fn)` identity *proves* the operation from the ABI, so the
//! binding is always rewritten to the semantic op. Recovering the literal
//! *contents* (the symbol text, the byte literal) is a separate data-flow
//! question: the `(position, length)` operands are traced through
//! [`trace_bytes()`] against the module's captured rodata
//! ([`sordec_ir::MemoryImage`]). When they resolve to a constant, the
//! literal is filled in; when they don't — the common case on real
//! contracts, where the compiler threads the position through phi chains
//! and shared helpers — the op is recognized with honestly-unresolved
//! contents (`resolved: None`), to be completed by a later
//! constant-propagation engine.
//!
//! ## What it does NOT do
//!
//! - No `Vec`/`Map` *element* recovery. Those `Val`s live in a runtime
//!   stack buffer, not rodata, so they are not literal-recoverable; the
//!   ops name the shape only.
//! - No other `b`/`v`/`m` operations (`vec_get`, `map_put`, `bytes_len`,
//!   `symbol_index_in_linear_memory`, the `*_copy`/`*_unpack` transfers,
//!   …). Those are pure host dispatch — the collections/bytes recognizer's
//!   separate scope — and need none of this substrate.

use sordec_common::{ProvenanceSource, UnknownReason, ValueId};
use sordec_ir::{Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, MemoryImage, SemanticOp};

use super::{apply_rewrites, is_recognized, Rewrite};
use crate::dataflow::trace_bytes;
use crate::pass::{Pass, PassMetrics, PassResult};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "linear-memory";

// Per-op metric counter keys.
const M_SYMBOL_NEW: &str = "symbol_new";
const M_STRING_NEW: &str = "string_new";
const M_BYTES_NEW: &str = "bytes_new";
const M_VEC_NEW: &str = "vec_new";
const M_MAP_NEW: &str = "map_new";
/// How many recognized constructors got a resolved literal (0 on the
/// current corpus — the honest coverage signal for the down-payment).
const M_LITERAL_RESOLVED: &str = "linear_memory_literal_resolved";

/// The linear-memory constructor recognizer. Stateless.
#[derive(Debug, Default, Clone, Copy)]
pub struct LinearMemoryPass;

impl Pass<HighIr> for LinearMemoryPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        // Disjoint field borrows: read the module-level rodata (`memory`)
        // while mutating a *different* field (`functions`).
        let memory = &ir.memory;
        for func in &mut ir.functions {
            let (changed, metrics) = recognize_function(func, memory);
            result.changed |= changed;
            for (key, value) in metrics.iter() {
                result.metrics.increment(key, value);
            }
        }
        result
    }
}

fn recognize_function(func: &mut HighFunction, memory: &MemoryImage) -> (bool, PassMetrics) {
    let mut metrics = PassMetrics::new();
    let mut rewrites: Vec<Rewrite> = Vec::new();

    for (id, binding) in func.bindings.iter() {
        if is_recognized(&binding.expr) {
            continue;
        }
        let Some(matched) = try_linear_memory(func, memory, id, &binding.expr) else {
            continue;
        };
        metrics.increment(matched.rewrite.metric, 1);
        if matched.literal_resolved {
            metrics.increment(M_LITERAL_RESOLVED, 1);
        }
        rewrites.push(matched.rewrite);
    }

    let changed = !rewrites.is_empty();
    apply_rewrites(func, PASS_NAME, rewrites);
    (changed, metrics)
}

/// A matched constructor: the rewrite plus whether its literal resolved.
struct LinearMemoryMatch {
    rewrite: Rewrite,
    literal_resolved: bool,
}

/// The recognized shape of one constructor call.
struct Recognized {
    op: KnownOp,
    ty: KnownType,
    metric: &'static str,
    note: String,
    literal_resolved: bool,
}

/// Match a `*_new_from_linear_memory` host call and build its rewrite.
fn try_linear_memory(
    func: &HighFunction,
    memory: &MemoryImage,
    id: ValueId,
    expr: &Expr,
) -> Option<LinearMemoryMatch> {
    let Expr::Semantic(SemanticOp::Unknown {
        host_module,
        host_fn,
        args,
        ..
    }) = expr
    else {
        return None;
    };
    let r = classify(func, memory, host_module, host_fn, args)?;
    Some(LinearMemoryMatch {
        rewrite: Rewrite {
            id,
            expr: Expr::Semantic(SemanticOp::Known(r.op)),
            ty: Some(IrType::Known(r.ty)),
            source: ProvenanceSource::HostFunctionAbi,
            note: r.note,
            metric: r.metric,
        },
        literal_resolved: r.literal_resolved,
    })
}

/// Dispatch on `(module, export, arity)`. Returns `None` for any other
/// host call or a wrong arity (malformed IR), leaving it unrecognized.
fn classify(
    func: &HighFunction,
    memory: &MemoryImage,
    host_module: &str,
    host_fn: &str,
    args: &[ValueId],
) -> Option<Recognized> {
    match (host_module, host_fn, args.len()) {
        // ---- buf module: symbol / string / bytes constructors ----
        ("b", "j", 2) => {
            let resolved = resolve_text(func, memory, args[0], args[1]);
            let got = resolved.is_some();
            Some(Recognized {
                op: KnownOp::SymbolNew {
                    lm_pos: args[0],
                    len: args[1],
                    resolved,
                },
                ty: KnownType::Symbol,
                metric: M_SYMBOL_NEW,
                note: text_note("symbol_new", got),
                literal_resolved: got,
            })
        }
        ("b", "i", 2) => {
            let resolved = resolve_text(func, memory, args[0], args[1]);
            let got = resolved.is_some();
            Some(Recognized {
                op: KnownOp::StringNew {
                    lm_pos: args[0],
                    len: args[1],
                    resolved,
                },
                ty: KnownType::String,
                metric: M_STRING_NEW,
                note: text_note("string_new", got),
                literal_resolved: got,
            })
        }
        ("b", "3", 2) => {
            let resolved = trace_bytes(func, memory, args[0], args[1]);
            let got = resolved.is_some();
            Some(Recognized {
                op: KnownOp::BytesNew {
                    lm_pos: args[0],
                    len: args[1],
                    resolved,
                },
                ty: KnownType::Bytes,
                metric: M_BYTES_NEW,
                note: text_note("bytes_new", got),
                literal_resolved: got,
            })
        }
        // ---- vec / map bulk constructors (contents are runtime) ----
        ("v", "g", 2) => Some(Recognized {
            op: KnownOp::VecNew {
                vals_pos: args[0],
                len: args[1],
            },
            ty: KnownType::Vec(Box::new(IrType::Unknown(UnknownReason::InsufficientEvidence))),
            metric: M_VEC_NEW,
            note: "linear-memory vec_new (elements runtime, not rodata)".to_string(),
            literal_resolved: false,
        }),
        ("m", "9", 3) => Some(Recognized {
            op: KnownOp::MapNew {
                keys_pos: args[0],
                vals_pos: args[1],
                len: args[2],
            },
            ty: KnownType::Map(
                Box::new(IrType::Unknown(UnknownReason::InsufficientEvidence)),
                Box::new(IrType::Unknown(UnknownReason::InsufficientEvidence)),
            ),
            metric: M_MAP_NEW,
            note: "linear-memory map_new (elements runtime, not rodata)".to_string(),
            literal_resolved: false,
        }),
        _ => None,
    }
}

/// Resolve a `(pos, len)` pair to UTF-8 text (symbol / string contents),
/// or `None` when the slice is not a locally-provable constant or is not
/// valid UTF-8.
fn resolve_text(
    func: &HighFunction,
    memory: &MemoryImage,
    pos: ValueId,
    len: ValueId,
) -> Option<String> {
    let bytes = trace_bytes(func, memory, pos, len)?;
    String::from_utf8(bytes).ok()
}

/// Provenance note for a text/bytes constructor, recording whether the
/// literal was recovered.
fn text_note(op: &str, resolved: bool) -> String {
    if resolved {
        format!("linear-memory {op} (resolved)")
    } else {
        format!("linear-memory {op} (contents unresolved: non-constant pos/len)")
    }
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::val_abi::TAG_U32_VAL;
    use sordec_common::{Arena, BlockId, FuncId, IrId, Provenance};
    use sordec_ir::{Binding, DataSegment, HighBlock, Literal, Region};

    fn func_with(exprs: Vec<Expr>) -> HighFunction {
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        for expr in exprs {
            let id = ValueId::from_index(bindings.len() as u32);
            bindings.push(Binding::new(
                id,
                IrType::Unknown(UnknownReason::InsufficientEvidence),
                expr,
                Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
            ));
        }
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        blocks.push(HighBlock {
            id: BlockId::from_index(0),
            bindings: vec![],
        });
        HighFunction {
            id: FuncId::from_index(0),
            name: None,
            signature: None,
            blocks,
            bindings,
            region: Region::Unreachable,
        }
    }

    fn v(i: u32) -> ValueId {
        ValueId::from_index(i)
    }

    /// A `U32Val(n)` literal expression.
    fn u32val(n: u32) -> Expr {
        Expr::Literal(Literal::I64(
            (((n as u64) << 32) | u64::from(TAG_U32_VAL)) as i64,
        ))
    }

    fn host(module: &str, name: &str, args: Vec<ValueId>) -> Expr {
        Expr::Semantic(SemanticOp::Unknown {
            host_module: module.to_string(),
            host_fn: name.to_string(),
            args,
            reason: UnknownReason::UnsupportedPattern,
        })
    }

    /// Segment `[100, 108)` holding "transfer".
    fn image() -> MemoryImage {
        MemoryImage::from_segments(vec![DataSegment {
            offset: 100,
            bytes: b"transfer".to_vec(),
        }])
    }

    fn run(func: &mut HighFunction, memory: &MemoryImage) -> (bool, PassMetrics) {
        recognize_function(func, memory)
    }

    fn expr_at(func: &HighFunction, id: ValueId) -> &Expr {
        &func.bindings.get(id).unwrap().expr
    }

    // --- symbol_new: resolved + unresolved ---

    #[test]
    fn symbol_new_resolves_from_rodata() {
        // v0 pos=100; v1 len=8; v2 = symbol_new(v0, v1) → "transfer".
        let mut func = func_with(vec![u32val(100), u32val(8), host("b", "j", vec![v(0), v(1)])]);
        let (changed, metrics) = run(&mut func, &image());
        assert!(changed);
        assert_eq!(metrics.get(M_SYMBOL_NEW), Some(1));
        assert_eq!(metrics.get(M_LITERAL_RESOLVED), Some(1));
        match expr_at(&func, v(2)) {
            Expr::Semantic(SemanticOp::Known(KnownOp::SymbolNew { resolved, .. })) => {
                assert_eq!(resolved.as_deref(), Some("transfer"));
            }
            other => panic!("expected SymbolNew, got {other:?}"),
        }
        assert_eq!(
            func.bindings.get(v(2)).unwrap().ty,
            IrType::Known(KnownType::Symbol)
        );
    }

    #[test]
    fn symbol_new_recognized_with_unresolved_contents() {
        // Position is a phi (non-constant) — op still recognized, literal None.
        let mut func = func_with(vec![
            Expr::Phi { incoming: vec![] },
            u32val(8),
            host("b", "j", vec![v(0), v(1)]),
        ]);
        let (changed, metrics) = run(&mut func, &image());
        assert!(changed, "op recognized even when contents unresolved");
        assert_eq!(metrics.get(M_SYMBOL_NEW), Some(1));
        assert_eq!(metrics.get(M_LITERAL_RESOLVED), None);
        match expr_at(&func, v(2)) {
            Expr::Semantic(SemanticOp::Known(KnownOp::SymbolNew { resolved, .. })) => {
                assert_eq!(*resolved, None);
            }
            other => panic!("expected SymbolNew, got {other:?}"),
        }
    }

    #[test]
    fn string_new_resolves() {
        let mut func = func_with(vec![u32val(100), u32val(8), host("b", "i", vec![v(0), v(1)])]);
        let (_, metrics) = run(&mut func, &image());
        assert_eq!(metrics.get(M_STRING_NEW), Some(1));
        match expr_at(&func, v(2)) {
            Expr::Semantic(SemanticOp::Known(KnownOp::StringNew { resolved, .. })) => {
                assert_eq!(resolved.as_deref(), Some("transfer"));
            }
            other => panic!("expected StringNew, got {other:?}"),
        }
        assert_eq!(
            func.bindings.get(v(2)).unwrap().ty,
            IrType::Known(KnownType::String)
        );
    }

    #[test]
    fn bytes_new_resolves_raw_bytes() {
        // Read "trans" (offset 100, len 5).
        let mut func = func_with(vec![u32val(100), u32val(5), host("b", "3", vec![v(0), v(1)])]);
        let (_, metrics) = run(&mut func, &image());
        assert_eq!(metrics.get(M_BYTES_NEW), Some(1));
        match expr_at(&func, v(2)) {
            Expr::Semantic(SemanticOp::Known(KnownOp::BytesNew { resolved, .. })) => {
                assert_eq!(resolved.as_deref(), Some(&b"trans"[..]));
            }
            other => panic!("expected BytesNew, got {other:?}"),
        }
        assert_eq!(
            func.bindings.get(v(2)).unwrap().ty,
            IrType::Known(KnownType::Bytes)
        );
    }

    // --- vec / map: shape only, no resolved contents ---

    #[test]
    fn vec_new_recognized_without_contents() {
        let mut func = func_with(vec![u32val(0), u32val(3), host("v", "g", vec![v(0), v(1)])]);
        let (changed, metrics) = run(&mut func, &image());
        assert!(changed);
        assert_eq!(metrics.get(M_VEC_NEW), Some(1));
        assert_eq!(metrics.get(M_LITERAL_RESOLVED), None);
        assert!(matches!(
            expr_at(&func, v(2)),
            Expr::Semantic(SemanticOp::Known(KnownOp::VecNew { .. }))
        ));
        assert!(matches!(
            func.bindings.get(v(2)).unwrap().ty,
            IrType::Known(KnownType::Vec(_))
        ));
    }

    #[test]
    fn map_new_recognized_three_args() {
        let mut func = func_with(vec![
            u32val(0),
            u32val(8),
            u32val(2),
            host("m", "9", vec![v(0), v(1), v(2)]),
        ]);
        let (changed, metrics) = run(&mut func, &image());
        assert!(changed);
        assert_eq!(metrics.get(M_MAP_NEW), Some(1));
        match expr_at(&func, v(3)) {
            Expr::Semantic(SemanticOp::Known(KnownOp::MapNew {
                keys_pos,
                vals_pos,
                len,
            })) => {
                assert_eq!(*keys_pos, v(0));
                assert_eq!(*vals_pos, v(1));
                assert_eq!(*len, v(2));
            }
            other => panic!("expected MapNew, got {other:?}"),
        }
    }

    // --- non-matches ---

    #[test]
    fn wrong_arity_not_recognized() {
        // symbol_new needs 2 args; 1 is malformed → skip.
        let mut func = func_with(vec![u32val(100), host("b", "j", vec![v(0)])]);
        let (changed, _) = run(&mut func, &image());
        assert!(!changed);
    }

    #[test]
    fn other_buf_op_not_recognized() {
        // b.0 is not a linear-memory constructor (different buf op).
        let mut func = func_with(vec![u32val(0), host("b", "0", vec![v(0)])]);
        let (changed, _) = run(&mut func, &image());
        assert!(!changed);
    }

    #[test]
    fn non_bvm_module_not_recognized() {
        let mut func = func_with(vec![u32val(0), u32val(0), host("l", "_", vec![v(0), v(1)])]);
        let (changed, _) = run(&mut func, &image());
        assert!(!changed);
    }

    // --- idempotency + provenance ---

    #[test]
    fn second_run_reports_no_change() {
        let mut func = func_with(vec![u32val(100), u32val(8), host("b", "j", vec![v(0), v(1)])]);
        assert!(run(&mut func, &image()).0);
        assert!(!run(&mut func, &image()).0, "idempotent on rerun");
    }

    #[test]
    fn provenance_records_source_and_resolution() {
        let mut func = func_with(vec![u32val(100), u32val(8), host("b", "j", vec![v(0), v(1)])]);
        run(&mut func, &image());
        let prov = func.bindings.get(v(2)).unwrap().latest_provenance();
        assert_eq!(prov.source, ProvenanceSource::HostFunctionAbi);
        assert!(prov.note.contains("symbol_new"), "note: {}", prov.note);
        assert!(prov.note.contains("resolved"), "note: {}", prov.note);
    }

    #[test]
    fn unresolved_note_states_non_constant() {
        let mut func = func_with(vec![
            Expr::Phi { incoming: vec![] },
            u32val(8),
            host("b", "j", vec![v(0), v(1)]),
        ]);
        run(&mut func, &image());
        let prov = func.bindings.get(v(2)).unwrap().latest_provenance();
        assert!(prov.note.contains("unresolved"), "note: {}", prov.note);
    }
}
