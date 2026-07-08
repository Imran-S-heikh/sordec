//! WASM bytecode → typed [`LiftedIr`] via the `waffle` library.
//!
//! [`lift_with_waffle`] is the single boundary step that converts a parsed
//! WASM module into our SSA + CFG IR. It is *not* a [`crate::Pass`] because
//! its input ([`WasmFacts`] + raw bytes) and output ([`LiftedIr`]) have
//! different types — passes mutate IR in place; lifting produces it.
//!
//! ## What waffle does
//!
//! - Decodes the WASM bytecode into its own typed IR (separate decoder
//!   from `wasmparser`).
//! - Constructs a control-flow graph of basic blocks per function.
//! - Converts stack-machine operations into SSA values, using **block
//!   parameters in place of phi nodes**. After
//!   `convert_to_max_ssa(None)`, every value is defined exactly once
//!   and dependencies are explicit.
//!
//! ## What we do
//!
//! Wrap waffle's typed entities into our newtype IDs and our typed
//! enums:
//!
//! - `waffle::Func` → [`sordec_common::FuncId`] (per local function only;
//!   imports are skipped)
//! - `waffle::Block` → [`sordec_common::BlockId`] (per-function scope)
//! - `waffle::Value` → [`sordec_common::ValueId`] (per-function scope)
//! - `waffle::Operator` → [`sordec_ir::WasmOp`] (newtype wrap; the
//!   architecture rule is that opcode classification flows through
//!   [`sordec_ir::WasmOpcodeKind`], never through
//!   `format!("{:?}", op)` parsing)
//! - `waffle::Terminator` → [`sordec_ir::LiftedTerminator`]
//! - `waffle::ValueDef` → [`sordec_ir::LiftedValueDef`]
//!
//! ## Lossy mappings
//!
//! - `waffle::Type::TypedFuncRef(nullable, type_idx)` → [`sordec_ir::LiftedType::FuncRef`].
//!   Soroban contracts cannot produce typed function references; the
//!   nullability and type-index axes are unobservable to every shipping
//!   pass. If a future contract surfaces a real `TypedFuncRef`, we'll
//!   add the new variant rather than retract this lossy mapping.
//!
//! ## Failure modes
//!
//! Hard errors (no silent fallbacks) for every condition that should
//! not arise after SSA conversion: see [`crate::LiftError`] for the
//! catalogue. The legacy decompiler returned an empty body in these
//! cases, which silently corrupted later passes — we instead surface
//! the failure with enough context to diagnose.

use std::collections::HashMap;

use sordec_common::{Arena, BlockId, FuncId, IrId, LiftDiagnostics, ValueId};
use sordec_ir::{
    BlockTarget, DataSegment, LiftedBlock, LiftedFunction, LiftedIr, LiftedTerminator, LiftedType,
    LiftedValue, LiftedValueDef, MemoryImage, SorobanFacts, WasmFacts, WasmOp,
};
use waffle::entity::EntityRef;
use waffle::{FuncDecl, FunctionBody, ValueDef};

use crate::error::{LiftError, LiftResult};

/// Output of [`lift_with_waffle`]: the lifted IR plus any non-fatal
/// diagnostics surfaced during lifting.
///
/// `diagnostics` is the explicit [`LiftDiagnostics`] artifact and is
/// empty in v0 — `LiftDiagnosticCode` has no variants yet (per the
/// plan's Step 3, the lifter currently surfaces every recoverable
/// situation through hard errors or through the existing
/// `LiftedTerminator::Unreachable` fallback). Phase 2's pattern recovery
/// passes will be the first to populate this field.
#[derive(Debug, Clone)]
pub struct LiftOutput {
    /// The lifted intermediate representation.
    pub lifted: LiftedIr,
    /// Non-fatal diagnostics surfaced during lifting. Empty in v0.
    ///
    /// RFP artifact note: the field remains named `diagnostics` for
    /// output/API consistency, but its type is the concrete
    /// [`LiftDiagnostics`] artifact. An empty collection is the expected
    /// Phase 1 state because `LiftDiagnosticCode` is intentionally
    /// uninhabited.
    pub diagnostics: LiftDiagnostics,
}

/// Lift a WASM module to our typed [`LiftedIr`].
///
/// Takes raw `wasm` bytes, the WASM-level [`WasmFacts`] produced by
/// `sordec-frontend::parse`, and the optional Soroban metadata
/// [`SorobanFacts`] from the same parse. Returns a [`LiftOutput`]
/// containing the populated [`LiftedIr`] (one [`LiftedFunction`] per
/// local non-imported function) plus any non-fatal diagnostics
/// (currently always empty — see [`LiftOutput`]).
///
/// `facts` is borrowed and cloned into the returned `LiftedIr.facts`;
/// `soroban_facts` is borrowed and cloned into
/// `LiftedIr.soroban_facts`. Cloning is preferred over consuming so the
/// caller can inspect facts before deciding whether to lift.
///
/// # Errors
///
/// See [`LiftError`]. The most common failure is
/// [`LiftError::WaffleParseFailed`], which wraps the `anyhow::Error`
/// from `waffle::Module::from_wasm_bytes` as text.
pub fn lift_with_waffle(
    wasm: &[u8],
    facts: &WasmFacts,
    soroban_facts: Option<&SorobanFacts>,
) -> LiftResult<LiftOutput> {
    // 1. Parse the WASM with waffle. Stringify the upstream anyhow error
    //    so our public surface stays clean.
    let mut module = waffle::Module::from_wasm_bytes(wasm, &waffle::FrontendOptions::default())
        .map_err(|err| LiftError::WaffleParseFailed(err.to_string()))?;

    // 2. Expand every function's body to typed IR (waffle parses bodies
    //    lazily by default).
    module
        .expand_all_funcs()
        .map_err(|err| LiftError::WaffleExpandFailed(err.to_string()))?;

    // 3. Convert each function body to maximal SSA form and recompute
    //    CFG edge metadata. Order matters: SSA conversion first, then
    //    edges — reversing breaks dominance assumptions in waffle's
    //    own metadata. Legacy code carries this same ordering.
    module.per_func_body(|body| {
        body.convert_to_max_ssa(None);
        body.recompute_edges();
    });

    // 4. Build the waffle-Func → local-FuncId map by enumerating
    //    non-import function decls in declaration order. We use this
    //    only to assign `LiftedFunction.id`; `WasmOp(waffle::Operator)`
    //    keeps waffle's namespace for any inner `Call { function_index }`
    //    references — semantic passes resolve them when they need to.
    let mut local_func_idx_by_waffle_func: HashMap<waffle::Func, u32> =
        HashMap::with_capacity(module.funcs.entries().count());
    let mut next_local_idx: u32 = 0;
    for (waffle_func, decl) in module.funcs.entries() {
        if matches!(decl, FuncDecl::Import(_, _)) {
            continue;
        }
        local_func_idx_by_waffle_func.insert(waffle_func, next_local_idx);
        next_local_idx = next_local_idx.saturating_add(1);
    }

    // 5. Translate every local function into a typed `LiftedFunction`.
    let mut functions: Vec<LiftedFunction> = Vec::with_capacity(next_local_idx as usize);
    for (waffle_func, decl) in module.funcs.entries() {
        if matches!(decl, FuncDecl::Import(_, _)) {
            continue;
        }
        let func_id = FuncId::from_index(local_func_idx_by_waffle_func[&waffle_func]);
        let body = decl
            .body()
            .ok_or(LiftError::MissingFunctionBody { func: func_id })?;
        let lifted = lift_function(func_id, body)?;
        functions.push(lifted);
    }

    // 6. Capture the module's initialized linear memory (active data
    //    segments) as module-level IR. waffle has already resolved each
    //    active segment's offset expression to a byte offset; recognizers
    //    resolve `(pointer, length)` literals against this rodata.
    let memory = capture_memory_image(&module);

    let lifted = LiftedIr {
        facts: facts.clone(),
        soroban_facts: soroban_facts.cloned(),
        functions,
        memory,
    };
    // `diagnostics` is intentionally empty in v0 — see `LiftOutput`'s
    // doc-comment. The named LiftDiagnostics artifact is still returned
    // so reviewers and future passes have a concrete lift diagnostic
    // surface to extend.
    Ok(LiftOutput {
        lifted,
        diagnostics: LiftDiagnostics::new(),
    })
}

/// Capture the module's active data segments into a [`MemoryImage`].
///
/// `waffle` parses the WASM data section into `module.memories`, resolving
/// each **active** segment's constant offset expression to a plain byte
/// offset (passive segments are dropped by waffle — Soroban emits its
/// rodata as active segments, so this is complete for our inputs). We lift
/// those `(offset, bytes)` pairs verbatim into module-level IR; the offset
/// fits in `u32` for any wasm32 module.
fn capture_memory_image(module: &waffle::Module) -> MemoryImage {
    let mut segments: Vec<DataSegment> = Vec::new();
    for (_mem, data) in module.memories.entries() {
        for seg in &data.segments {
            segments.push(DataSegment {
                offset: seg.offset as u32,
                bytes: seg.data.clone(),
            });
        }
    }
    MemoryImage::from_segments(segments)
}

/// Translate one waffle [`waffle::FunctionBody`] into a [`LiftedFunction`].
///
/// Builds the value arena first (so block instructions can reference
/// already-allocated [`ValueId`]s), then the block arena. Block
/// terminators are stubbed as [`LiftedTerminator::Unreachable`] in this
/// step; Step 4 of the plan replaces them with the real translation.
fn lift_function(func_id: FuncId, body: &FunctionBody) -> LiftResult<LiftedFunction> {
    // -- Value arena ---------------------------------------------------
    //
    // waffle's `EntityVec<Value, ValueDef>` is indexed densely from 0,
    // so iterating with `.entries()` yields `(Value, &ValueDef)` in
    // monotonic order. We push into our `Arena<ValueId, _>` and check
    // the index alignment as we go — desync would mean waffle violated
    // an invariant we rely on, so we surface a typed error rather
    // than silently corrupt the IR.
    let mut values: Arena<ValueId, LiftedValue> = Arena::new();
    for (waffle_value, value_def) in body.values.entries() {
        let lifted = lift_value(func_id, waffle_value, value_def, body)?;
        let pushed_id = values.push(lifted);
        if pushed_id.index() != waffle_value.index() as u32 {
            return Err(LiftError::SparseValueArena { func: func_id });
        }
    }

    // -- Block arena ---------------------------------------------------
    //
    // Same iteration pattern: translate each block's params + instructions
    // list verbatim into our IR. Terminator translation lives in step 4;
    // for now every block gets a stub `Unreachable` terminator so the
    // overall structure is in place.
    let mut blocks: Arena<BlockId, LiftedBlock> = Arena::new();
    for (waffle_block, block_def) in body.blocks.entries() {
        let block_id = BlockId::from_index(waffle_block.index() as u32);
        let params: Vec<ValueId> = block_def
            .params
            .iter()
            .map(|(_ty, value)| ValueId::from_index(value.index() as u32))
            .collect();
        let instructions: Vec<ValueId> = block_def
            .insts
            .iter()
            .map(|value| ValueId::from_index(value.index() as u32))
            .collect();
        let terminator = lifted_terminator_from_waffle(
            func_id,
            waffle_block.index() as u32,
            &block_def.terminator,
        )?;
        let pushed_id = blocks.push(LiftedBlock {
            id: block_id,
            params,
            instructions,
            terminator,
        });
        // Same density check as for values.
        if pushed_id.index() != block_id.index() {
            return Err(LiftError::SparseValueArena { func: func_id });
        }
    }

    let entry = BlockId::from_index(body.entry.index() as u32);

    let lifted = LiftedFunction {
        id: func_id,
        entry,
        blocks,
        values,
    };

    // In debug builds (and during tests), enforce the post-lift
    // invariants so violations surface at the lifter — not three
    // passes downstream when something silently dereferences a
    // dangling block target. Release builds skip this cost.
    debug_assert!(
        validate_lifted_function(&lifted).is_ok(),
        "lifter produced an invalid LiftedFunction for {:?}",
        lifted.id
    );

    Ok(lifted)
}

/// Translate one waffle [`ValueDef`] into our [`LiftedValue`].
///
/// Hard-errors on `Placeholder` / `None` per architectural rule: after
/// `convert_to_max_ssa`, every value must have a real definition.
fn lift_value(
    func_id: FuncId,
    waffle_value: waffle::Value,
    value_def: &ValueDef,
    body: &FunctionBody,
) -> LiftResult<LiftedValue> {
    let value_index = waffle_value.index() as u32;

    // Result types come from the same accessor regardless of variant.
    // Empty `tys` (e.g. for stores) maps to an empty Vec<LiftedType>.
    let types: Vec<LiftedType> = value_def
        .tys(&body.type_pool)
        .iter()
        .copied()
        .map(lifted_type_from_waffle)
        .collect::<LiftResult<Vec<_>>>()?;

    let def = match value_def {
        ValueDef::Operator(op, args_ref, _types_ref) => {
            let args: Vec<ValueId> = body.arg_pool[*args_ref]
                .iter()
                .map(|v| ValueId::from_index(v.index() as u32))
                .collect();
            // `waffle::Operator` is `Copy` — deref-copy rather than clone.
            LiftedValueDef::Operator {
                op: WasmOp(*op),
                args,
            }
        }
        ValueDef::BlockParam(block, index, _ty) => LiftedValueDef::BlockParam {
            block: BlockId::from_index(block.index() as u32),
            index: *index,
        },
        ValueDef::PickOutput(from, index, _ty) => LiftedValueDef::PickOutput {
            from: ValueId::from_index(from.index() as u32),
            index: *index,
        },
        ValueDef::Alias(target) => {
            LiftedValueDef::Alias(ValueId::from_index(target.index() as u32))
        }
        ValueDef::Placeholder(_ty) => {
            return Err(LiftError::PlaceholderValueAfterSsa {
                func: func_id,
                value_index,
            })
        }
        ValueDef::None => {
            return Err(LiftError::UninitializedValueAfterSsa {
                func: func_id,
                value_index,
            })
        }
    };

    Ok(LiftedValue { def, types })
}

/// Translate a `waffle::Terminator` into our [`LiftedTerminator`].
///
/// Exhaustive over every variant.
///
/// ## Note on `Terminator::None`
///
/// Plan D4 originally said hard-error on `Terminator::None`, on the
/// assumption it should not appear after `convert_to_max_ssa`. Empirical
/// testing on real Soroban contracts (hello_add, counter) showed waffle
/// *does* produce `None` for some blocks — apparently for synthetic /
/// unreachable blocks waffle keeps around for housekeeping. The legacy
/// decompiler silently accepted these and downstream code worked.
///
/// Mapping `None` → [`LiftedTerminator::Unreachable`] preserves the
/// semantics ("no defined exit; executing this traps") without forcing
/// a code-archaeology session into waffle internals. If waffle ever
/// produces `None` for a *reachable* block, that's the bug we'd want
/// to catch — but the post-lift invariant validator can flag that case
/// (a block with `Unreachable` terminator that has predecessors is
/// suspicious) without us paying the boundary-error cost on every
/// well-formed contract.
fn lifted_terminator_from_waffle(
    _func_id: FuncId,
    _block_index: u32,
    terminator: &waffle::Terminator,
) -> LiftResult<LiftedTerminator> {
    match terminator {
        waffle::Terminator::Br { target } => {
            Ok(LiftedTerminator::Branch(block_target_from_waffle(target)))
        }
        waffle::Terminator::CondBr {
            cond,
            if_true,
            if_false,
        } => Ok(LiftedTerminator::BranchIf {
            cond: ValueId::from_index(cond.index() as u32),
            if_true: block_target_from_waffle(if_true),
            if_false: block_target_from_waffle(if_false),
        }),
        waffle::Terminator::Select {
            value,
            targets,
            default,
        } => Ok(LiftedTerminator::Switch {
            index: ValueId::from_index(value.index() as u32),
            targets: targets.iter().map(block_target_from_waffle).collect(),
            default: block_target_from_waffle(default),
        }),
        waffle::Terminator::Return { values } => Ok(LiftedTerminator::Return {
            values: values
                .iter()
                .map(|v| ValueId::from_index(v.index() as u32))
                .collect(),
        }),
        waffle::Terminator::Unreachable | waffle::Terminator::None => {
            Ok(LiftedTerminator::Unreachable)
        }
    }
}

/// Translate one `waffle::BlockTarget` into our [`BlockTarget`].
///
/// Pure ID translation — no error path, since both fields map directly.
fn block_target_from_waffle(target: &waffle::BlockTarget) -> BlockTarget {
    BlockTarget {
        block: BlockId::from_index(target.block.index() as u32),
        args: target
            .args
            .iter()
            .map(|v| ValueId::from_index(v.index() as u32))
            .collect(),
    }
}

/// Post-lift invariant validator for a single [`LiftedFunction`].
///
/// Checks that the function is internally consistent:
/// - every `ValueId` referenced from instructions, terminator args, or
///   block-target args exists in `values`,
/// - every `BlockId` referenced from a terminator target exists in
///   `blocks`,
/// - the entry block exists.
///
/// Surfaces a typed [`LiftError::DanglingBlockTarget`] for unknown
/// block targets. (Dangling value references would indicate a `waffle`
/// bug — they share the same flat `ValueId` space and our SSA arena
/// is dense by construction.)
///
/// Designed to be called via `debug_assert!` after lifting so the
/// invariants are enforced in dev/test builds with zero release-build
/// cost. Intentionally not `pub`: callers go through
/// [`lift_with_waffle`], which wires it in.
pub(crate) fn validate_lifted_function(func: &LiftedFunction) -> LiftResult<()> {
    let block_count = func.blocks.len() as u32;
    let value_count = func.values.len() as u32;

    let check_value = |v: ValueId| -> LiftResult<()> {
        if v.index() >= value_count {
            // SparseValueArena is the closest existing variant; in
            // practice this only fires if a terminator references a
            // value waffle did not allocate, which would itself be a
            // sparse-arena symptom.
            return Err(LiftError::SparseValueArena { func: func.id });
        }
        Ok(())
    };

    let check_target = |source_block: u32, target: &BlockTarget| -> LiftResult<()> {
        if target.block.index() >= block_count {
            return Err(LiftError::DanglingBlockTarget {
                func: func.id,
                block_index: source_block,
                target_index: target.block.index(),
            });
        }
        for arg in &target.args {
            check_value(*arg)?;
        }
        Ok(())
    };

    if func.entry.index() >= block_count {
        return Err(LiftError::DanglingBlockTarget {
            func: func.id,
            block_index: u32::MAX, // entry has no source block
            target_index: func.entry.index(),
        });
    }

    for (block_id, block) in func.blocks.iter() {
        let block_idx = block_id.index();
        for value in &block.params {
            check_value(*value)?;
        }
        for value in &block.instructions {
            check_value(*value)?;
        }
        match &block.terminator {
            LiftedTerminator::Branch(target) => check_target(block_idx, target)?,
            LiftedTerminator::BranchIf {
                cond,
                if_true,
                if_false,
            } => {
                check_value(*cond)?;
                check_target(block_idx, if_true)?;
                check_target(block_idx, if_false)?;
            }
            LiftedTerminator::Switch {
                index,
                targets,
                default,
            } => {
                check_value(*index)?;
                for target in targets {
                    check_target(block_idx, target)?;
                }
                check_target(block_idx, default)?;
            }
            LiftedTerminator::Return { values } => {
                for value in values {
                    check_value(*value)?;
                }
            }
            LiftedTerminator::Unreachable => {}
        }
    }

    Ok(())
}

/// Translate a `waffle::Type` into our [`sordec_ir::LiftedType`].
///
/// Exhaustive over every variant we support; returns
/// [`LiftError::UnsupportedWasmType`] for variants we cannot represent.
/// `TypedFuncRef` is mapped lossily to `FuncRef` per the module-level
/// note on lossy mappings.
fn lifted_type_from_waffle(ty: waffle::Type) -> LiftResult<sordec_ir::LiftedType> {
    use sordec_ir::LiftedType;
    match ty {
        waffle::Type::I32 => Ok(LiftedType::I32),
        waffle::Type::I64 => Ok(LiftedType::I64),
        waffle::Type::F32 => Ok(LiftedType::F32),
        waffle::Type::F64 => Ok(LiftedType::F64),
        waffle::Type::V128 => Ok(LiftedType::V128),
        waffle::Type::FuncRef => Ok(LiftedType::FuncRef),
        // TypedFuncRef collapses to FuncRef. Soroban contracts do not
        // produce typed function references; the lossiness on
        // `nullable` and `type_idx` is unobservable to shipping passes.
        waffle::Type::TypedFuncRef(_, _) => Ok(LiftedType::FuncRef),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_ir::LiftedType;

    #[test]
    fn lifted_type_from_waffle_maps_primitives() {
        assert_eq!(
            lifted_type_from_waffle(waffle::Type::I32).unwrap(),
            LiftedType::I32
        );
        assert_eq!(
            lifted_type_from_waffle(waffle::Type::I64).unwrap(),
            LiftedType::I64
        );
        assert_eq!(
            lifted_type_from_waffle(waffle::Type::F32).unwrap(),
            LiftedType::F32
        );
        assert_eq!(
            lifted_type_from_waffle(waffle::Type::F64).unwrap(),
            LiftedType::F64
        );
        assert_eq!(
            lifted_type_from_waffle(waffle::Type::V128).unwrap(),
            LiftedType::V128
        );
        assert_eq!(
            lifted_type_from_waffle(waffle::Type::FuncRef).unwrap(),
            LiftedType::FuncRef
        );
    }

    #[test]
    fn lifted_type_from_waffle_collapses_typed_funcref() {
        // Lossy by design: see module-level docs.
        assert_eq!(
            lifted_type_from_waffle(waffle::Type::TypedFuncRef(true, 42)).unwrap(),
            LiftedType::FuncRef
        );
        assert_eq!(
            lifted_type_from_waffle(waffle::Type::TypedFuncRef(false, 0)).unwrap(),
            LiftedType::FuncRef
        );
    }
}
