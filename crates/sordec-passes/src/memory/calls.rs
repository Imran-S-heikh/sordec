//! Module-wide direct-call index for the **lifted** layer.
//!
//! Every pass in this module that changes a function's signature needs the
//! same three facts before it may touch anything:
//!
//! - which local function a `call` operator names,
//! - which call sites target a given callee, and
//! - whether the caller set can be trusted at all.
//!
//! [`crate::dataflow::CallIndex`] answers those questions over [`HighIr`],
//! built from `Expr::Call`. It cannot be reused here: this module runs
//! before lowering, where a call is still a `waffle::Operator::Call` naming
//! a raw WASM function index. So this is a deliberate mirror of that type
//! rather than a second, differently-shaped abstraction — same names, same
//! rules, one layer down.
//!
//! ## The index-space shift is the reason this is shared, not copied
//!
//! WASM puts every host import first in the function index space, so a
//! `call`'s `function_index` is **not** a local [`FuncId`]. [`super::sret`]
//! already spells out what happens when that shift is forgotten: the wrong
//! callee is named, "call sites stop matching their callee while the callee
//! is still rewritten, and the module quietly stops type-checking". That is
//! precisely the kind of arithmetic that must exist once.
//!
//! ## Why the caller set can be untrustworthy
//!
//! Two cases, both of which make "every call site" unknowable, and both of
//! which every consumer here must treat as a veto:
//!
//! - **Indirect calls.** A table-called function has callers no scan can
//!   see. Their presence anywhere in the module poisons the whole index —
//!   the same module-wide rule [`crate::dataflow::Resolver`] and
//!   [`crate::interproc::SpecializePass`] state.
//! - **Exports.** A host-invocable function's signature *is* the contract
//!   ABI. Its internal call sites are not the complete set, and re-aritying
//!   one would silently change what the contract accepts.
//!
//! The export guard is defensive rather than a fix for observed damage: on
//! this corpus every exported function takes and returns `Val`, never an
//! out-pointer, so nothing has ever reached it. It is here because the cost
//! of being wrong is a contract whose ABI changed without anyone noticing.

use std::collections::HashSet;

use sordec_common::{FuncId, IrId as _, ValueId};
use sordec_ir::{ExportKind, ImportKind, LiftedIr, LiftedValueDef, WasmOp};
use waffle::entity::EntityRef as _;

/// One direct call site targeting some function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CallSite {
    /// Function containing the call.
    pub caller: FuncId,
    /// The call operator's value id within the caller.
    pub call: ValueId,
}

/// Module-wide reverse call map over [`LiftedIr`].
///
/// A point-in-time snapshot: rebuild after mutating the IR. Consumers here
/// all follow the same discipline anyway — plan over an immutable module,
/// veto, then rewrite — so a single build per pass run is the whole
/// lifetime.
#[derive(Debug, Clone)]
pub(crate) struct CallIndex {
    /// How many of the module's imports are functions — the offset between
    /// WASM's global function index space and our local one.
    imported: u32,
    /// `callers[i]` = call sites targeting `FuncId(i)`.
    callers: Vec<Vec<CallSite>>,
    /// Whether any operator in the module is a `call_indirect`.
    has_indirect: bool,
    /// Local functions reachable from outside the module.
    exported: HashSet<FuncId>,
}

impl CallIndex {
    /// Build the index in one linear scan over every function's values.
    ///
    /// Out-of-range call targets are skipped rather than panicking:
    /// malformed IR is the validator's concern, and an index that names
    /// nothing cannot be rewritten anyway. This matches
    /// [`crate::dataflow::CallIndex::build`]'s handling.
    pub(crate) fn build(ir: &LiftedIr) -> Self {
        let imported = ir
            .facts
            .imports
            .iter()
            .filter(|i| matches!(i.kind, ImportKind::Func(_)))
            .count() as u32;

        let mut callers: Vec<Vec<CallSite>> = vec![Vec::new(); ir.functions.len()];
        let mut has_indirect = false;
        for func in &ir.functions {
            for (id, value) in func.values.iter() {
                let LiftedValueDef::Operator { op, .. } = &value.def else {
                    continue;
                };
                match &op.0 {
                    waffle::Operator::CallIndirect { .. } => has_indirect = true,
                    waffle::Operator::Call { .. } => {
                        let Some(target) = local_target(op, imported) else {
                            continue;
                        };
                        if let Some(slot) = callers.get_mut(target.index() as usize) {
                            slot.push(CallSite {
                                caller: func.id,
                                call: id,
                            });
                        }
                    }
                    _ => {}
                }
            }
        }

        let exported = ir
            .facts
            .exports
            .iter()
            .filter(|e| matches!(e.kind, ExportKind::Func))
            .filter_map(|e| e.index.checked_sub(imported))
            .map(FuncId::from_index)
            .collect();

        Self {
            imported,
            callers,
            has_indirect,
            exported,
        }
    }

    /// The callee of a direct call operator, as a **local** [`FuncId`], or
    /// `None` for a host import (which has no body here to rewrite) and for
    /// anything that is not a `call`.
    pub(crate) fn target(&self, op: &WasmOp) -> Option<FuncId> {
        local_target(op, self.imported)
    }

    /// All call sites targeting `func`, or an empty slice when nothing in
    /// the module calls it.
    pub(crate) fn sites_targeting(&self, func: FuncId) -> &[CallSite] {
        self.callers
            .get(func.index() as usize)
            .map_or(&[], Vec::as_slice)
    }

    /// Whether the module contains any indirect call — if so, no caller set
    /// is complete and no signature may be changed.
    pub(crate) fn has_indirect_calls(&self) -> bool {
        self.has_indirect
    }

    /// Whether `func` is reachable from outside the module, making its
    /// signature part of the contract ABI.
    pub(crate) fn is_exported(&self, func: FuncId) -> bool {
        self.exported.contains(&func)
    }
}

/// Shift a `call`'s WASM function index into our local [`FuncId`] space.
///
/// Free-standing so [`CallIndex::build`] can use it before `self` exists.
fn local_target(op: &WasmOp, imported: u32) -> Option<FuncId> {
    let waffle::Operator::Call { function_index } = &op.0 else {
        return None;
    };
    let global = function_index.index() as u32;
    // Below the import count is a host call: no body in this module.
    global.checked_sub(imported).map(FuncId::from_index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{block, func_with, op, v};
    use sordec_ir::{LiftedFunction, LiftedTerminator};

    fn call(index: u32, args: Vec<ValueId>) -> LiftedValueDef {
        op(
            waffle::Operator::Call {
                function_index: waffle::Func::from(index),
            },
            args,
        )
    }

    /// A module whose functions are `func_0` and `func_1`, with `imports`
    /// host imports ahead of them in the WASM index space.
    fn module(functions: Vec<LiftedFunction>, imports: usize, exports: Vec<u32>) -> LiftedIr {
        LiftedIr {
            facts: sordec_ir::WasmFacts {
                imports: (0..imports)
                    .map(|i| sordec_ir::Import {
                        index: i as u32,
                        module: "x".to_string(),
                        name: format!("{i}"),
                        kind: ImportKind::Func(0),
                    })
                    .collect(),
                exports: exports
                    .into_iter()
                    .map(|index| sordec_ir::Export {
                        name: format!("e{index}"),
                        kind: ExportKind::Func,
                        index,
                    })
                    .collect(),
                function_type_indices: vec![],
                function_bodies: vec![],
                function_fingerprints: vec![],
                custom_sections: vec![],
            },
            soroban_facts: None,
            functions,
            memory: sordec_ir::MemoryImage::empty(),
        }
    }

    /// `func_0` calls local `func_1`, which sits at WASM index 3 behind two
    /// host imports.
    fn caller_of_one() -> LiftedFunction {
        func_with(
            vec![call(3, vec![])],
            vec![block(0, vec![], vec![v(0)], LiftedTerminator::Return { values: vec![] })],
        )
    }

    fn leaf() -> LiftedFunction {
        let mut f = func_with(
            vec![],
            vec![block(0, vec![], vec![], LiftedTerminator::Return { values: vec![] })],
        );
        f.id = FuncId::from_index(1);
        f
    }

    #[test]
    fn shifts_past_host_imports() {
        let ir = module(vec![caller_of_one(), leaf()], 2, vec![]);
        let index = CallIndex::build(&ir);
        // WASM index 3 with 2 imports is local function 1, not 3.
        let sites = index.sites_targeting(FuncId::from_index(1));
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].caller, FuncId::from_index(0));
        assert!(index.sites_targeting(FuncId::from_index(3)).is_empty());
    }

    #[test]
    fn a_host_import_is_not_a_local_target() {
        // WASM index 1, with 2 imports, is host import #1.
        let f = func_with(
            vec![call(1, vec![])],
            vec![block(0, vec![], vec![v(0)], LiftedTerminator::Return { values: vec![] })],
        );
        let ir = module(vec![f], 2, vec![]);
        let index = CallIndex::build(&ir);
        assert!(index.sites_targeting(FuncId::from_index(0)).is_empty());
    }

    #[test]
    fn exports_shift_the_same_way() {
        // WASM export index 3, with 2 imports, is local function 1.
        let ir = module(vec![caller_of_one(), leaf()], 2, vec![3]);
        let index = CallIndex::build(&ir);
        assert!(index.is_exported(FuncId::from_index(1)));
        assert!(!index.is_exported(FuncId::from_index(0)));
    }

    #[test]
    fn an_indirect_call_anywhere_poisons_the_index() {
        let f = func_with(
            vec![op(
                waffle::Operator::CallIndirect {
                    sig_index: waffle::Signature::from(0),
                    table_index: waffle::Table::from(0),
                },
                vec![],
            )],
            vec![block(0, vec![], vec![v(0)], LiftedTerminator::Return { values: vec![] })],
        );
        let ir = module(vec![f], 0, vec![]);
        assert!(CallIndex::build(&ir).has_indirect_calls());
    }
}
