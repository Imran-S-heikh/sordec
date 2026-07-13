//! The symbol-dispatch recognizer — the SDK's `#[contracttype]`
//! enum-from-`Val` decoder.
//!
//! To decode an enum out of a `Val`, the SDK calls
//! `symbol_index_in_linear_memory(sym, table_pos, len)`: `table_pos`
//! points at a rodata array of `len` byte-slice descriptors — one per
//! variant name — and the host returns the `u32` index of `sym` in that
//! array, which then drives a `br_table` (one arm per variant). The
//! `collections` pass already names the host call
//! ([`BufOpKind::SymbolIndexInLinearMemory`](sordec_ir::BufOpKind)); this
//! pass reads the descriptor table out of linear memory and refines the
//! op into [`KnownOp::SymbolDispatch`], recording the ordered variant
//! list and — when the `contractspecv0` registry names it — the enum.
//!
//! ## Evidence
//!
//! The variant list is **witnessed** ground truth (the exact rodata
//! bytes), so recognition is all-or-nothing: every descriptor must trace
//! to a locally-constant `(pos, len)` slice that passes the `Symbol`
//! grammar, or the site stays a plain `BufOp` (no partial/guessed list).
//! The enum *name* follows the None-is-honest discipline — filled only on
//! a unique union match (shared gate in [`super::symbols`]), left `None`
//! for a stripped binary or an ambiguous match.
//!
//! ## What it does NOT do
//!
//! It names the enum and records the index→variant map; it does **not**
//! fold the surrounding `br_table` into `match` arms. The branch cascade
//! is not present in `HighIr` (the lowering keeps no block terminators),
//! so reconstructing the `match` is control-flow structuring (Phase 3).

use std::collections::{BTreeSet, HashMap};

use sordec_common::{
    Diagnostic, FuncId, IrId, LiftDiagnosticCode, Location, ProvenanceSource, ValueId,
};
use sordec_ir::{
    BufOpKind, DispatchTable, Expr, HighFunction, HighIr, KnownOp, MemoryImage, SemanticOp,
};

use super::symbols::{unique_union_index_by_cases, valid_symbol_text};
use super::{apply_rewrites, Rewrite};
use crate::dataflow::trace_u32val;
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "dispatcher";

// Metric counter keys.
/// Dispatch sites whose rodata variant table fully decoded.
const M_CASES_RESOLVED: &str = "dispatcher_cases_resolved";
/// Decoded dispatch sites whose enum was named against the spec registry.
const M_ENUM_NAMED: &str = "dispatcher_enum_named";
/// `symbol_index_in_linear_memory` sites whose table did not decode (the
/// remaining-work signal).
const M_UNRESOLVED: &str = "dispatcher_unresolved";

/// A descriptor table larger than this is treated as garbage rather than
/// decoded. Real `#[contracttype]` enums are tiny; this only bounds a
/// pathological or non-constant `len`.
const MAX_DISPATCH_CASES: u32 = 256;

/// The symbol-dispatch recognizer pass. Stateless between runs.
#[derive(Debug, Default, Clone, Copy)]
pub struct DispatcherPass;

impl Pass<HighIr> for DispatcherPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();

        // Phase A — read-only scan (needs `ir.memory` + `ir.soroban_facts`
        // alongside each function, so it cannot borrow `ir` mutably yet).
        let unions = ir
            .soroban_facts
            .as_ref()
            .map(|f| f.types.unions.as_slice())
            .unwrap_or(&[]);
        let mut planned: HashMap<FuncId, Vec<Rewrite>> = HashMap::new();

        for func in &ir.functions {
            for (id, binding) in func.bindings.iter() {
                let Some((sym, table_pos, len)) = symbol_index_site(&binding.expr) else {
                    continue;
                };
                let Some(cases) = decode_dispatch_table(func, &ir.memory, table_pos, len) else {
                    result.metrics.increment(M_UNRESOLVED, 1);
                    result.diagnostics.push(
                        Diagnostic::warning(LiftDiagnosticCode::UnresolvedSymbolDispatch, "").at(
                            Location::Value {
                                func: func.id,
                                value: id.index(),
                            },
                        ),
                    );
                    continue;
                };
                let enum_name = name_enum(unions, &cases);
                if enum_name.is_some() {
                    result.metrics.increment(M_ENUM_NAMED, 1);
                }
                let note = dispatch_note(&cases, enum_name.as_deref());
                planned.entry(func.id).or_default().push(Rewrite {
                    id,
                    expr: Expr::Semantic(SemanticOp::Known(KnownOp::SymbolDispatch {
                        sym,
                        table_pos,
                        len,
                        table: DispatchTable { cases, enum_name },
                    })),
                    // The BufOp's ABI result type (U32) already stands; the
                    // table decode proves no new type.
                    ty: None,
                    source: ProvenanceSource::SdkPattern,
                    note,
                    metric: M_CASES_RESOLVED,
                });
            }
        }

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

/// Match a `SymbolIndexInLinearMemory` `BufOp` and return its
/// `(sym, table_pos, len)` operands. A `SymbolDispatch` (already refined)
/// does not match, so the pass is idempotent without an explicit guard.
fn symbol_index_site(expr: &Expr) -> Option<(ValueId, ValueId, ValueId)> {
    let Expr::Semantic(SemanticOp::Known(KnownOp::BufOp {
        kind: BufOpKind::SymbolIndexInLinearMemory,
        args,
    })) = expr
    else {
        return None;
    };
    match args[..] {
        [sym, table_pos, len] => Some((sym, table_pos, len)),
        // Malformed arity (the collections pass proves 3, but stay honest).
        _ => None,
    }
}

/// Decode the rodata slice-descriptor table into an ordered variant list.
///
/// The table is `count` 8-byte little-endian `(pos: u32, len: u32)`
/// descriptors at `table_pos`; each names a variant Symbol. Returns the
/// texts in table order (index i = the value the host returns for
/// `cases[i]`), or `None` if either operand is not a locally-provable
/// constant, the count is out of range, or any descriptor slice is not a
/// rodata-covered valid Symbol. All-or-nothing — never a partial list.
fn decode_dispatch_table(
    func: &HighFunction,
    memory: &MemoryImage,
    table_pos: ValueId,
    len: ValueId,
) -> Option<Vec<String>> {
    let base = trace_u32val(func, table_pos)?;
    let count = trace_u32val(func, len)?;
    if count == 0 || count > MAX_DISPATCH_CASES {
        return None;
    }
    let table = memory.read(base, count.checked_mul(8)?)?;
    let mut cases = Vec::with_capacity(count as usize);
    for entry in table.chunks_exact(8) {
        let pos = u32::from_le_bytes(entry[0..4].try_into().ok()?);
        let slen = u32::from_le_bytes(entry[4..8].try_into().ok()?);
        cases.push(valid_symbol_text(memory.read(pos, slen)?)?);
    }
    Some(cases)
}

/// Name the enum whose declared case set equals the recovered variant
/// list, via the shared registry gate. `None` when there is no spec, no
/// unique match, or an ambiguous one.
fn name_enum(unions: &[sordec_ir::UnionDef], cases: &[String]) -> Option<String> {
    let set: BTreeSet<String> = cases.iter().cloned().collect();
    let idx = unique_union_index_by_cases(unions, &set)?;
    Some(unions[idx].name.clone())
}

/// Provenance note for a dispatch rewrite: the resolved enum (or an
/// explicit "unnamed" marker) followed by the ordered `index=variant` map,
/// so the audit trail shows exactly what was decoded from rodata.
fn dispatch_note(cases: &[String], enum_name: Option<&str>) -> String {
    let map = cases
        .iter()
        .enumerate()
        .map(|(i, c)| format!("{i}={c}"))
        .collect::<Vec<_>>()
        .join(", ");
    match enum_name {
        Some(name) => format!("dispatcher {name} {{{map}}}"),
        None => format!("dispatcher <unnamed enum> {{{map}}}"),
    }
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{Arena, BlockId, IrId, Provenance, TypeId, UnknownReason};
    use sordec_ir::{
        Binding, DataSegment, HighBlock, IrType, KnownType, Literal, Region, SorobanFacts,
        TypeRegistry, UnionCase, UnionDef, WasmFacts, WasmOpcodeKind,
    };

    fn v(i: u32) -> ValueId {
        ValueId::from_index(i)
    }

    /// A single-block function whose bindings are `exprs` at ids `0..N`.
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
            params: vec![],
            returns: vec![],
        }
    }

    /// `symbol_index_in_linear_memory(sym=v0, table_pos, len)` at v3, with
    /// v0 a dummy symbol and v1/v2 constant `U32Val` offsets.
    fn dispatch_func(table_pos: u32, len: u32) -> HighFunction {
        func_with(vec![
            Expr::Literal(Literal::I64(0)), // v0 — dummy sym handle
            Expr::Literal(Literal::U32(table_pos)),
            Expr::Literal(Literal::U32(len)),
            buf_symbol_index(v(0), v(1), v(2)),
        ])
    }

    fn buf_symbol_index(sym: ValueId, table_pos: ValueId, len: ValueId) -> Expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::BufOp {
            kind: BufOpKind::SymbolIndexInLinearMemory,
            args: vec![sym, table_pos, len],
        }))
    }

    /// A rodata segment at `base` holding an 8-byte `(pos, len)` descriptor
    /// per case, followed by the case-name bytes they point at.
    fn table_segment(base: u32, cases: &[&str]) -> DataSegment {
        let names_start = base + (cases.len() as u32) * 8;
        let mut descriptors = Vec::new();
        let mut names = Vec::new();
        let mut cursor = names_start;
        for case in cases {
            descriptors.extend_from_slice(&cursor.to_le_bytes());
            descriptors.extend_from_slice(&(case.len() as u32).to_le_bytes());
            names.extend_from_slice(case.as_bytes());
            cursor += case.len() as u32;
        }
        descriptors.extend_from_slice(&names);
        DataSegment {
            offset: base,
            bytes: descriptors,
        }
    }

    fn union(name: &str, cases: &[&str]) -> UnionDef {
        UnionDef {
            id: TypeId::from_index(0),
            name: name.to_string(),
            cases: cases
                .iter()
                .map(|c| UnionCase {
                    name: c.to_string(),
                    fields: vec![],
                })
                .collect(),
        }
    }

    /// Assemble a module from one function, a rodata segment, and unions.
    fn module(func: HighFunction, segment: DataSegment, unions: Vec<UnionDef>) -> HighIr {
        HighIr {
            facts: WasmFacts {
                imports: vec![],
                exports: vec![],
                function_type_indices: vec![],
                custom_sections: vec![],
            },
            soroban_facts: Some(SorobanFacts {
                types: TypeRegistry {
                    unions,
                    ..TypeRegistry::default()
                },
                ..SorobanFacts::default()
            }),
            functions: vec![func],
            memory: MemoryImage::from_segments(vec![segment]),
        }
    }

    fn dispatch_at(ir: &HighIr, id: ValueId) -> Option<DispatchTable> {
        match &ir.functions[0].bindings.get(id).unwrap().expr {
            Expr::Semantic(SemanticOp::Known(KnownOp::SymbolDispatch { table, .. })) => {
                Some(table.clone())
            }
            _ => None,
        }
    }

    #[test]
    fn happy_path_decodes_cases_and_names_enum() {
        let mut ir = module(
            dispatch_func(1000, 2),
            table_segment(1000, &["Before", "After"]),
            vec![union("TimeBoundKind", &["Before", "After"])],
        );
        let result = DispatcherPass.run(&mut ir);

        assert!(result.changed);
        assert_eq!(result.metrics.get(M_CASES_RESOLVED), Some(1));
        assert_eq!(result.metrics.get(M_ENUM_NAMED), Some(1));
        assert_eq!(result.metrics.get(M_UNRESOLVED), None);

        let table = dispatch_at(&ir, v(3)).expect("rewritten to SymbolDispatch");
        assert_eq!(table.cases, vec!["Before".to_string(), "After".to_string()]);
        assert_eq!(table.enum_name.as_deref(), Some("TimeBoundKind"));

        // Original operands preserved, result type unchanged.
        match &ir.functions[0].bindings.get(v(3)).unwrap().expr {
            Expr::Semantic(SemanticOp::Known(KnownOp::SymbolDispatch {
                sym,
                table_pos,
                len,
                ..
            })) => {
                assert_eq!((*sym, *table_pos, *len), (v(0), v(1), v(2)));
            }
            other => panic!("expected SymbolDispatch, got {other:?}"),
        }
        let prov = ir.functions[0].bindings.get(v(3)).unwrap().latest_provenance();
        assert_eq!(prov.source, ProvenanceSource::SdkPattern);
        assert_eq!(prov.note, "dispatcher TimeBoundKind {0=Before, 1=After}");
    }

    #[test]
    fn cases_resolve_but_enum_unnamed_without_registry() {
        // No unions (e.g. a stripped binary): the rodata cases are still
        // ground truth, but nothing names the enum.
        let mut ir = module(
            dispatch_func(1000, 2),
            table_segment(1000, &["Before", "After"]),
            vec![],
        );
        let result = DispatcherPass.run(&mut ir);

        assert!(result.changed);
        assert_eq!(result.metrics.get(M_CASES_RESOLVED), Some(1));
        assert_eq!(result.metrics.get(M_ENUM_NAMED), None);
        let table = dispatch_at(&ir, v(3)).expect("rewritten");
        assert_eq!(table.cases, vec!["Before".to_string(), "After".to_string()]);
        assert_eq!(table.enum_name, None);
    }

    #[test]
    fn ambiguous_unions_leave_enum_unnamed() {
        let mut ir = module(
            dispatch_func(1000, 2),
            table_segment(1000, &["Before", "After"]),
            vec![
                union("TimeBoundKind", &["Before", "After"]),
                union("OtherKind", &["After", "Before"]),
            ],
        );
        let result = DispatcherPass.run(&mut ir);

        assert_eq!(result.metrics.get(M_CASES_RESOLVED), Some(1));
        assert_eq!(result.metrics.get(M_ENUM_NAMED), None);
        assert_eq!(dispatch_at(&ir, v(3)).unwrap().enum_name, None);
    }

    #[test]
    fn non_constant_table_position_refuses() {
        // v1 (table_pos) is a phi → not a locally-provable constant.
        let mut func = dispatch_func(1000, 2);
        func.bindings.get_mut(v(1)).unwrap().expr = Expr::Phi { incoming: vec![] };
        let mut ir = module(func, table_segment(1000, &["Before", "After"]), vec![]);
        let result = DispatcherPass.run(&mut ir);

        assert!(!result.changed);
        assert_eq!(result.metrics.get(M_CASES_RESOLVED), None);
        assert_eq!(result.metrics.get(M_UNRESOLVED), Some(1));
        assert!(dispatch_at(&ir, v(3)).is_none());
    }

    #[test]
    fn bad_symbol_entry_refuses_whole_table() {
        // Second descriptor points at bytes with a space — outside the
        // Symbol grammar. All-or-nothing: the whole site stays a BufOp.
        let mut ir = module(
            dispatch_func(1000, 2),
            table_segment(1000, &["Before", "bad name"]),
            vec![],
        );
        let result = DispatcherPass.run(&mut ir);

        assert!(!result.changed);
        assert_eq!(result.metrics.get(M_UNRESOLVED), Some(1));
        assert!(dispatch_at(&ir, v(3)).is_none());
    }

    #[test]
    fn table_read_out_of_bounds_refuses() {
        // len=4 but the segment only holds 2 descriptors → read overruns.
        let mut ir = module(
            dispatch_func(1000, 4),
            table_segment(1000, &["Before", "After"]),
            vec![],
        );
        let result = DispatcherPass.run(&mut ir);

        assert!(!result.changed);
        assert_eq!(result.metrics.get(M_UNRESOLVED), Some(1));
    }

    #[test]
    fn conversion_wrapped_position_resolves() {
        // The timelock shape: table_pos arrives as ValEncodeSmall<U32> over
        // an i64.extend_i32_u of the constant offset (an opaque Conversion
        // after lowering). The pass must still decode the table.
        let func = func_with(vec![
            Expr::Literal(Literal::I64(0)),        // v0 — sym
            Expr::Literal(Literal::I32(1000)),     // v1 — raw offset
            Expr::Unknown {                        // v2 — i32→i64 extend
                op_kind: WasmOpcodeKind::Conversion,
                args: vec![v(1)],
                reason: UnknownReason::UnsupportedPattern,
            },
            Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall {
                ty: KnownType::U32,
                value: v(2),
            })), // v3 — U32Val(1000)
            Expr::Literal(Literal::U32(2)),        // v4 — len
            buf_symbol_index(v(0), v(3), v(4)),    // v5
        ]);
        let mut ir = module(
            func,
            table_segment(1000, &["Before", "After"]),
            vec![union("TimeBoundKind", &["Before", "After"])],
        );
        let result = DispatcherPass.run(&mut ir);

        assert!(result.changed);
        let table = dispatch_at(&ir, v(5)).expect("decoded through the conversion");
        assert_eq!(table.enum_name.as_deref(), Some("TimeBoundKind"));
    }

    #[test]
    fn second_run_is_idempotent() {
        let mut ir = module(
            dispatch_func(1000, 2),
            table_segment(1000, &["Before", "After"]),
            vec![union("TimeBoundKind", &["Before", "After"])],
        );
        assert!(DispatcherPass.run(&mut ir).changed);
        let second = DispatcherPass.run(&mut ir);
        assert!(!second.changed, "already a SymbolDispatch, nothing to do");
        assert_eq!(second.metrics.get(M_CASES_RESOLVED), None);
    }
}
