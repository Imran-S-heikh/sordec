//! The mechanical `LiftedIr → HighIr` lowering.
//!
//! [`LiftToHigh`] is the phase-boundary [`crate::LoweringStep`] that turns
//! the SSA + CFG lifted form into the high IR that pattern-recovery
//! passes refine. Value lowering is deliberately **mechanical**: every
//! lifted value maps to a typed [`Binding`] one-to-one, with honest
//! fallbacks, and no semantic recognition or type inference happens here
//! — those are the `Pass<HighIr>` recognizers that run afterward.
//! Control flow is the one exception: the high IR carries no
//! terminators, so structuring runs at this boundary — the last point
//! where CFG edges still exist (see the control-flow note below).
//!
//! ## What each value becomes
//!
//! - Constants → [`Expr::Literal`].
//! - Arithmetic / bitwise / comparison operators → [`Expr::Binary`].
//! - Unary numeric operators → [`Expr::Unary`].
//! - Loads / stores / global reads → the matching raw [`Expr`] variant.
//! - Calls to local functions → [`Expr::Call`]; calls to host imports →
//!   [`Expr::Semantic`]`(`[`SemanticOp::Unknown`]`)` (a recognized
//!   host call that no pattern has claimed yet).
//! - Block parameters → [`Expr::Phi`] with incoming edges recovered from
//!   predecessor terminators.
//! - Everything else (conversions, `select`, SIMD, `memory.*`, …) →
//!   [`Expr::Unknown`] carrying the operator's [`WasmOpcodeKind`]. Never a
//!   panic, never a fabricated semantic.
//!
//! ## What it does NOT do
//!
//! - **Types.** Every binding gets [`IrType::Unknown`]. WASM machine
//!   types are not Soroban semantic types; guessing would be wrong. Type
//!   recovery is a later pass.
//! - **Control-flow interpretation.** Each function's [`Region`] comes
//!   from [`crate::structuring::structure`] over the lifted CFG (fresh
//!   [`CfgFacts`], post-declutter) — an exact translation, never a
//!   guess: loop classification, guard recovery, and `match` sugaring
//!   are refinement passes. Irreducible or malformed input (never real
//!   rustc output) degrades to [`Region::Unstructured`], surfaced as a
//!   `StructuringFallback` diagnostic by the structuring stats pass.
//! - **Recognition.** No `obj_from_*` collapse, no storage-tier
//!   resolution, etc. Those are the high-IR passes this lowering feeds.

use std::collections::HashMap;

use sordec_common::{
    Arena, BlockId, FuncId, IrId, Provenance, ProvenanceSource, UnknownReason, ValueId,
};
use sordec_ir::{
    Binding, BinaryOp, BlockTarget, Expr, ExportKind, FunctionParam, FunctionSignature, HighBlock,
    HighFunction, HighIr, ImportKind, Import, IrType, LiftedFunction, LiftedIr, LiftedTerminator,
    LiftedValue, LiftedValueDef, Literal, MemWidth, PrimitiveType, Region, SemanticOp,
    SorobanFacts, TypeRef, UnaryOp, WasmFacts, WasmOp, WasmOpcodeKind, CompositeType, SdkType};
use waffle::entity::EntityRef as _;

use crate::dataflow::CfgFacts;
use crate::lowering::{LoweringError, LoweringStep};
use crate::structuring::structure;

/// Name recorded on every binding's initial provenance and returned from
/// [`LoweringStep::name`].
const PASS_NAME: &str = "lift-to-high";

/// The mechanical `LiftedIr → HighIr` boundary lowering.
///
/// Stateless — construct with `LiftToHigh` and call
/// [`LoweringStep::lower`].
#[derive(Debug, Default, Clone, Copy)]
pub struct LiftToHigh;

impl LoweringStep for LiftToHigh {
    type Input = LiftedIr;
    type Output = HighIr;

    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn lower(&self, input: LiftedIr) -> Result<HighIr, LoweringError> {
        let LiftedIr {
            facts,
            soroban_facts,
            functions,
            memory,
        } = input;

        let high_functions = functions
            .iter()
            .map(|f| lower_function(f, &facts, soroban_facts.as_ref()))
            .collect();

        // `memory` is module-level rodata; per-function lowering never
        // touches it, so it moves through unchanged.
        Ok(HighIr {
            facts,
            soroban_facts,
            functions: high_functions,
            memory,
        })
    }
}

// ---------------------------------------------------------------------
// Per-function lowering
// ---------------------------------------------------------------------

/// Context threaded into per-value lowering: everything a single value's
/// `Expr` might need to disambiguate.
struct LowerCtx<'a> {
    /// Original WASM imports (for resolving host-call module/name).
    imports: &'a [Import],
    /// Count of `Func`-kind imports — splits the WASM function index
    /// space into imports (`< count`) vs locals (`>= count`).
    imported_func_count: u32,
    /// For each block, the incoming phi edges: `(predecessor block,
    /// args passed to that block's params)`. Built once per function.
    phi_edges: &'a HashMap<BlockId, Vec<(BlockId, Vec<ValueId>)>>,
}

fn lower_function(
    func: &LiftedFunction,
    facts: &WasmFacts,
    soroban_facts: Option<&SorobanFacts>,
) -> HighFunction {
    let imported_func_count = facts
        .imports
        .iter()
        .filter(|i| matches!(i.kind, ImportKind::Func(_)))
        .count() as u32;

    let name = recover_name(facts, func.id, imported_func_count);
    let arity = func
        .blocks
        .get(func.entry)
        .map_or(0, |entry| entry.params.len());
    let returns_a_value = func
        .blocks
        .iter()
        .any(|(_, b)| matches!(&b.terminator, LiftedTerminator::Return { values } if !values.is_empty()));
    let signature = name.as_deref().and_then(|n| {
        recover_signature(soroban_facts, n)
            .or_else(|| exported_signature(soroban_facts, n, arity, returns_a_value))
    });

    let phi_edges = build_phi_edges(func);
    let ctx = LowerCtx {
        imports: &facts.imports,
        imported_func_count,
        phi_edges: &phi_edges,
    };

    // Values → bindings, in arena order (dense ids preserved).
    let mut bindings: Arena<ValueId, Binding> = Arena::new();
    for (value_id, value) in func.values.iter() {
        bindings.push(lower_value(value_id, value, &ctx));
    }

    // LiftedBlock.instructions → HighBlock.bindings. Block params and
    // terminators do not appear here: params are separate bindings
    // (phi), and control flow lives in `region`.
    let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
    for (block_id, lblock) in func.blocks.iter() {
        blocks.push(HighBlock {
            id: block_id,
            bindings: lblock.instructions.clone(),
        });
    }

    // Structure the CFG at this boundary — the last point where
    // terminators exist. Facts are built fresh here: the declutter
    // passes have already reshaped the CFG, so any lift-time snapshot
    // would be stale (Region v2 design, DD9). Both fallback paths
    // preserve every block and binding — only structure is lost — and
    // the structuring stats pass turns them into diagnostics.
    let cfg = CfgFacts::build(func);
    let region = if cfg.is_reducible() {
        structure(func, &cfg).unwrap_or(Region::Unstructured {
            entry: func.entry,
            reason: UnknownReason::UnsupportedPattern,
        })
    } else {
        Region::Unstructured {
            entry: func.entry,
            reason: UnknownReason::IrreducibleControlFlow,
        }
    };

    // Function parameters = the ENTRY block's params, in order. Only the
    // entry block's params are function parameters — loop-header block
    // params are phi nodes, not arguments. This ordered list is what
    // lets inter-procedural analyses bind `Call.args[i]` to param `i`.
    let params = func
        .blocks
        .get(func.entry)
        .map(|entry| entry.params.clone())
        .unwrap_or_default();

    // Return sites, in block order. HighBlock carries no terminators
    // (control flow lives in `region`), so without this table a
    // callee's returned values would be invisible to inter-procedural
    // analyses. Recorded faithfully — arity guarding is the consumer's
    // job.
    let returns = func
        .blocks
        .iter()
        .filter_map(|(_, lblock)| match &lblock.terminator {
            LiftedTerminator::Return { values } => Some(values.clone()),
            _ => None,
        })
        .collect();

    HighFunction {
        id: func.id,
        name,
        signature,
        blocks,
        bindings,
        region,
        params,
        returns,
    }
}

/// Recover a local function's exported name from the WASM export table.
///
/// `func.id` is the local (non-import) index; exports carry the global
/// WASM function index, so we shift by `imported_func_count`.
fn recover_name(facts: &WasmFacts, func_id: FuncId, imported_func_count: u32) -> Option<String> {
    let global_index = func_id.index() + imported_func_count;
    facts
        .exports
        .iter()
        .find(|e| matches!(e.kind, ExportKind::Func) && e.index == global_index)
        .map(|e| e.name.clone())
}

/// Recover a function's Soroban signature from `contractspecv0`, keyed by
/// its exported name, with the types the protocol fixes filled in.
fn recover_signature(
    soroban_facts: Option<&SorobanFacts>,
    name: &str,
) -> Option<FunctionSignature> {
    let mut sig = soroban_facts?.functions.get(name).cloned()?;
    fill_reserved_types(&mut sig);
    Some(sig)
}

/// Name of the custom account interface's authorization entrypoint.
const CHECK_AUTH: &str = "__check_auth";

/// Position of `auth_contexts` in [`CHECK_AUTH`]'s signature.
const AUTH_CONTEXTS_INDEX: usize = 2;

/// Fill in parameter types the protocol fixes and the spec cannot carry.
///
/// A `contractspecv0` declares the contract's own types; an SDK type in a
/// signature therefore arrives as `Unknown(NoMetadata)` and renders as a
/// bare `Val`. For most parameters that is the honest answer. For one it
/// is not: `__check_auth` is reserved by the custom account interface,
/// whose third parameter is `Vec<Context>` for every contract that
/// implements it — so the type is known, just not from this binary.
///
/// This is the same standing as the SEP-41 table in
/// [`crate::interfaces`]: protocol knowledge, applied only where the
/// protocol is what decides. The shape is checked before it is filled, so
/// a function that merely shares the name is left alone.
fn fill_reserved_types(sig: &mut FunctionSignature) {
    if sig.name != CHECK_AUTH {
        return;
    }
    let Some(param) = sig.inputs.get_mut(AUTH_CONTEXTS_INDEX) else {
        return;
    };
    // Only an unresolved element type is filled. A spec that already names
    // one knows something we do not and keeps it.
    if let TypeRef::Composite(CompositeType::Vec(element)) = &mut param.ty
        && matches!(**element, TypeRef::Unknown(_))
    {
        **element = TypeRef::Sdk(SdkType::AuthContext);
    }
}

/// The signature an export implies when the module carries no
/// `contractspecv0`.
///
/// A Soroban contract is invoked *by exported name*: the host looks the
/// entrypoint up in the export table and hands it one `Val` per
/// argument. So the export table names every entrypoint and gives its
/// arity, and that is true of any deployed contract — the spec section
/// is metadata a build can strip, the export table is the calling
/// convention and cannot be.
///
/// What it does not give is types. Every parameter is recorded as the
/// ABI's `Val`, which is exactly what the wasm says and no more, and the
/// marshalling gates read the declaration rather than guess: a `Val`
/// admits no tag, so nothing is elided on the strength of a signature
/// recovered this way. The entrypoints are named, and the reconstruction
/// gets the `#[contractimpl]` wrapper the contract really has.
///
/// Only when the spec is missing entirely. A module that has one and
/// omits a function from it is telling us that function is not an
/// entrypoint, and inventing one would contradict the evidence.
fn exported_signature(
    soroban_facts: Option<&SorobanFacts>,
    name: &str,
    arity: usize,
    returns_a_value: bool,
) -> Option<FunctionSignature> {
    if soroban_facts.is_some_and(|f| !f.functions.is_empty()) {
        return None;
    }
    if !is_entrypoint_export(name) {
        return None;
    }
    let val = || TypeRef::Primitive(PrimitiveType::Val);
    Some(FunctionSignature {
        name: name.to_owned(),
        inputs: (0..arity)
            .map(|i| FunctionParam { name: format!("arg{i}"), ty: val() })
            .collect(),
        outputs: if returns_a_value { vec![val()] } else { vec![] },
    })
}

/// Whether an exported function name is a contract entrypoint rather
/// than linker furniture.
///
/// `_` is what the Rust wasm target exports for its entry shim, and
/// `__data_end` / `__heap_base` are the allocator's bounds — none is
/// callable as a contract function. `__constructor` looks like furniture
/// and is not: it is a Soroban entrypoint with a reserved name.
fn is_entrypoint_export(name: &str) -> bool {
    !matches!(name, "_" | "__data_end" | "__heap_base" | "memory")
}

/// Build the phi-edge map for a function in one forward pass: for each
/// block, the list of `(predecessor block, args)` flowing into it from
/// every terminator that targets it.
fn build_phi_edges(func: &LiftedFunction) -> HashMap<BlockId, Vec<(BlockId, Vec<ValueId>)>> {
    let mut edges: HashMap<BlockId, Vec<(BlockId, Vec<ValueId>)>> = HashMap::new();
    for (src, lblock) in func.blocks.iter() {
        for target in terminator_targets(&lblock.terminator) {
            edges
                .entry(target.block)
                .or_default()
                .push((src, target.args.clone()));
        }
    }
    edges
}

/// All block targets a terminator branches to (empty for `Return` /
/// `Unreachable`).
fn terminator_targets(term: &LiftedTerminator) -> Vec<&BlockTarget> {
    match term {
        LiftedTerminator::Branch(t) => vec![t],
        LiftedTerminator::BranchIf {
            if_true, if_false, ..
        } => vec![if_true, if_false],
        LiftedTerminator::Switch {
            targets, default, ..
        } => targets.iter().chain(std::iter::once(default)).collect(),
        LiftedTerminator::Return { .. } | LiftedTerminator::Unreachable => vec![],
    }
}

// ---------------------------------------------------------------------
// Per-value lowering
// ---------------------------------------------------------------------

fn lower_value(value_id: ValueId, value: &LiftedValue, ctx: &LowerCtx<'_>) -> Binding {
    let (expr, note) = lower_value_def(&value.def, ctx);
    // Every binding is `Unknown`-typed at this layer; a later type
    // recovery pass refines these. WASM machine types are not Soroban
    // semantic types, so we do not guess.
    let ty = IrType::Unknown(UnknownReason::InsufficientEvidence);
    let provenance = Provenance::new(PASS_NAME, ProvenanceSource::DataFlow, note);
    Binding::new(value_id, ty, expr, provenance)
}

/// Lower one value definition to an `Expr`, returning the expression and
/// a short provenance note describing what it lowered from.
fn lower_value_def(def: &LiftedValueDef, ctx: &LowerCtx<'_>) -> (Expr, String) {
    match def {
        LiftedValueDef::Alias(target) => (Expr::Use(*target), "alias".to_string()),

        // Multi-result projection. Rare in WASM as compiled by rustc, but
        // `memory::sret` creates one per component whenever it turns an
        // out-parameter back into a real return value, so this is a
        // first-class lowering rather than the honest hole it used to be.
        LiftedValueDef::PickOutput { from, index } => (
            Expr::Project {
                value: *from,
                index: *index,
            },
            format!("pick output {index}"),
        ),

        LiftedValueDef::BlockParam { block, index } => {
            let incoming = ctx
                .phi_edges
                .get(block)
                .map(|edges| {
                    edges
                        .iter()
                        .filter_map(|(pred, args)| {
                            args.get(*index as usize).map(|v| (*pred, *v))
                        })
                        .collect()
                })
                .unwrap_or_default();
            (Expr::Phi { incoming }, "block param".to_string())
        }

        LiftedValueDef::Operator { op, args } => {
            let expr = lower_operator(op, args, ctx);
            (expr, format!("operator: {:?}", op.kind()))
        }
    }
}

/// Lower a WASM operator to an `Expr`. Total: any operator with no
/// dedicated variant becomes `Expr::Unknown` carrying its kind.
fn lower_operator(op: &WasmOp, args: &[ValueId], ctx: &LowerCtx<'_>) -> Expr {
    use waffle::Operator as W;

    match &op.0 {
        // Constants → literals (bit-exact; floats reinterpret their bits).
        W::I32Const { value } => Expr::Literal(Literal::I32(*value as i32)),
        W::I64Const { value } => Expr::Literal(Literal::I64(*value as i64)),
        W::F32Const { value } => Expr::Literal(Literal::F32(f32::from_bits(*value))),
        W::F64Const { value } => Expr::Literal(Literal::F64(f64::from_bits(*value))),

        // Global read.
        W::GlobalGet { global_index } => Expr::GlobalGet {
            index: global_index.index() as u32,
        },

        // Direct call: local function or host import.
        W::Call { function_index } => lower_call(function_index.index(), args, ctx),

        // Loads: all share `{ memory: MemoryArg }`; addr is the sole operand.
        W::I32Load { memory }
        | W::I64Load { memory }
        | W::F32Load { memory }
        | W::F64Load { memory }
        | W::I32Load8S { memory }
        | W::I32Load8U { memory }
        | W::I32Load16S { memory }
        | W::I32Load16U { memory }
        | W::I64Load8S { memory }
        | W::I64Load8U { memory }
        | W::I64Load16S { memory }
        | W::I64Load16U { memory }
        | W::I64Load32S { memory }
        | W::I64Load32U { memory } => match (args.first(), load_shape(&op.0)) {
            (Some(addr), Some((width, signed))) => Expr::Load {
                addr: *addr,
                offset: memory.offset,
                width,
                signed,
                ty: IrType::Unknown(UnknownReason::InsufficientEvidence),
            },
            _ => unknown(op, args),
        },

        // Stores: `{ memory }`; addr + value operands.
        W::I32Store { memory }
        | W::I64Store { memory }
        | W::F32Store { memory }
        | W::F64Store { memory }
        | W::I32Store8 { memory }
        | W::I32Store16 { memory }
        | W::I64Store8 { memory }
        | W::I64Store16 { memory }
        | W::I64Store32 { memory } => match (args.first(), args.get(1), store_width(&op.0)) {
            (Some(addr), Some(value), Some(width)) => Expr::Store {
                addr: *addr,
                value: *value,
                offset: memory.offset,
                width,
            },
            _ => unknown(op, args),
        },

        // Everything else: try binary, then unary, then honest fallback.
        other => {
            if let Some(bin) = binary_op(other) {
                match (args.first(), args.get(1)) {
                    (Some(lhs), Some(rhs)) => Expr::Binary {
                        op: bin,
                        lhs: *lhs,
                        rhs: *rhs,
                    },
                    _ => unknown(op, args),
                }
            } else if let Some(un) = unary_op(other) {
                match args.first() {
                    Some(value) => Expr::Unary {
                        op: un,
                        value: *value,
                    },
                    None => unknown(op, args),
                }
            } else {
                unknown(op, args)
            }
        }
    }
}

/// Lower a direct `Call` by its global WASM function index.
fn lower_call(global_index: usize, args: &[ValueId], ctx: &LowerCtx<'_>) -> Expr {
    let imported = ctx.imported_func_count as usize;
    if global_index < imported {
        // Host import. Record the raw module/name; recognizers (and the
        // renderer via `host_calls::resolve`) turn these into friendly
        // names / KnownOps. Unrecognized-so-far, hence SemanticOp::Unknown.
        match ctx.imports.get(global_index) {
            Some(import) => Expr::Semantic(SemanticOp::Unknown {
                host_module: import.module.clone(),
                host_fn: import.name.clone(),
                args: args.to_vec(),
                reason: UnknownReason::UnsupportedPattern,
            }),
            None => Expr::Unknown {
                op_kind: WasmOpcodeKind::Call,
                args: args.to_vec(),
                reason: UnknownReason::UpstreamUnknown,
            },
        }
    } else {
        // Local function call.
        let local = (global_index - imported) as u32;
        Expr::Call {
            target: FuncId::from_index(local),
            args: args.to_vec(),
        }
    }
}

/// Honest fallback: an operator with no dedicated `Expr` variant.
fn unknown(op: &WasmOp, args: &[ValueId]) -> Expr {
    Expr::Unknown {
        op_kind: op.kind(),
        args: args.to_vec(),
        reason: UnknownReason::UnsupportedPattern,
    }
}

/// Map a load operator to its `(access width, sign extension)` pair.
/// `signed` is `Some` only for sub-word loads — full-width loads have
/// no extension to record. `None` for non-load operators.
fn load_shape(w: &waffle::Operator) -> Option<(MemWidth, Option<bool>)> {
    use waffle::Operator as W;
    Some(match w {
        W::I32Load { .. } | W::F32Load { .. } => (MemWidth::W4, None),
        W::I64Load { .. } | W::F64Load { .. } => (MemWidth::W8, None),
        W::I32Load8S { .. } | W::I64Load8S { .. } => (MemWidth::W1, Some(true)),
        W::I32Load8U { .. } | W::I64Load8U { .. } => (MemWidth::W1, Some(false)),
        W::I32Load16S { .. } | W::I64Load16S { .. } => (MemWidth::W2, Some(true)),
        W::I32Load16U { .. } | W::I64Load16U { .. } => (MemWidth::W2, Some(false)),
        W::I64Load32S { .. } => (MemWidth::W4, Some(true)),
        W::I64Load32U { .. } => (MemWidth::W4, Some(false)),
        _ => return None,
    })
}

/// Map a store operator to its access width. `None` for non-store
/// operators.
fn store_width(w: &waffle::Operator) -> Option<MemWidth> {
    use waffle::Operator as W;
    Some(match w {
        W::I32Store { .. } | W::F32Store { .. } | W::I64Store32 { .. } => MemWidth::W4,
        W::I64Store { .. } | W::F64Store { .. } => MemWidth::W8,
        W::I32Store8 { .. } | W::I64Store8 { .. } => MemWidth::W1,
        W::I32Store16 { .. } | W::I64Store16 { .. } => MemWidth::W2,
        _ => return None,
    })
}

/// Map a binary WASM operator to a [`BinaryOp`] (sign/width erased — the
/// surrounding binding type carries that). `None` for non-binary ops.
///
/// Mirrors the exhaustive structure of
/// [`WasmOp::kind`](sordec_ir::WasmOp::kind); a waffle bump that adds
/// operators surfaces here at compile time via the arms that name each
/// operator explicitly.
fn binary_op(w: &waffle::Operator) -> Option<BinaryOp> {
    use waffle::Operator as W;
    use BinaryOp as B;
    Some(match w {
        W::I32Add | W::I64Add | W::F32Add | W::F64Add => B::Add,
        W::I32Sub | W::I64Sub | W::F32Sub | W::F64Sub => B::Sub,
        W::I32Mul | W::I64Mul | W::F32Mul | W::F64Mul => B::Mul,
        W::I32DivS | W::I32DivU | W::I64DivS | W::I64DivU | W::F32Div | W::F64Div => B::Div,
        W::I32RemS | W::I32RemU | W::I64RemS | W::I64RemU => B::Rem,
        W::I32And | W::I64And => B::BitAnd,
        W::I32Or | W::I64Or => B::BitOr,
        W::I32Xor | W::I64Xor => B::BitXor,
        W::I32Shl | W::I64Shl => B::Shl,
        W::I32ShrS | W::I32ShrU | W::I64ShrS | W::I64ShrU => B::Shr,
        W::I32Rotl | W::I64Rotl => B::Rotl,
        W::I32Rotr | W::I64Rotr => B::Rotr,
        W::I32Eq | W::I64Eq | W::F32Eq | W::F64Eq => B::Eq,
        W::I32Ne | W::I64Ne | W::F32Ne | W::F64Ne => B::Ne,
        W::I32LtS | W::I32LtU | W::I64LtS | W::I64LtU | W::F32Lt | W::F64Lt => B::Lt,
        W::I32LeS | W::I32LeU | W::I64LeS | W::I64LeU | W::F32Le | W::F64Le => B::Le,
        W::I32GtS | W::I32GtU | W::I64GtS | W::I64GtU | W::F32Gt | W::F64Gt => B::Gt,
        W::I32GeS | W::I32GeU | W::I64GeS | W::I64GeU | W::F32Ge | W::F64Ge => B::Ge,
        _ => return None,
    })
}

/// Map a unary WASM operator to a [`UnaryOp`]. `None` for non-unary ops.
///
/// `Eqz` used to be left out here, on the grounds that it "has no faithful
/// unary shape without fabricating a zero operand". The objection was real
/// but aimed at the wrong target: this function cannot mint the zero
/// (one operator yields one `Expr`, with nowhere to schedule a second
/// binding), yet nothing forced the *representation* to be a comparison.
/// [`UnaryOp::Eqz`] names the opcode instead and leaves the Rust spelling
/// — `!x` on a boolean, `x == 0` on an integer — to the emitter, which is
/// where the operand's recovered type is known. It was the single largest
/// lifting gap on the corpus: 60 holes, 42 of them guarding an `if`.
///
/// `Nearest` still has no `UnaryOp` variant.
fn unary_op(w: &waffle::Operator) -> Option<UnaryOp> {
    use waffle::Operator as W;
    use UnaryOp as U;
    Some(match w {
        W::I32Eqz | W::I64Eqz => U::Eqz,
        W::I32Clz | W::I64Clz => U::Clz,
        W::I32Ctz | W::I64Ctz => U::Ctz,
        W::I32Popcnt | W::I64Popcnt => U::Popcnt,
        W::F32Abs | W::F64Abs => U::Abs,
        W::F32Neg | W::F64Neg => U::Neg,
        W::F32Sqrt | W::F64Sqrt => U::Sqrt,
        W::F32Floor | W::F64Floor => U::Floor,
        W::F32Ceil | W::F64Ceil => U::Ceil,
        W::F32Trunc | W::F64Trunc => U::Trunc,
        // The integer width moves, each named for what it does to the bits;
        // passes and the emitter need that, and "some conversion" cannot
        // tell a zero-extension from a sign-extension. Float conversions
        // (some of which trap) stay honest unknowns.
        W::I32WrapI64 => U::Wrap32,
        W::I64ExtendI32U => U::ExtendU32,
        W::I64ExtendI32S => U::ExtendS32,
        _ => return None,
    })
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_ir::{Export, LiftedBlock, LiftedType, MemoryImage};

    // --- synthetic IR builders ---

    fn facts_with(imports: Vec<Import>, exports: Vec<Export>) -> WasmFacts {
        WasmFacts {
            imports,
            exports,
            function_type_indices: vec![],
            function_bodies: vec![],
            function_fingerprints: vec![],
            custom_sections: vec![],
        }
    }

    fn func_import(module: &str, name: &str) -> Import {
        Import {
            index: 0,
            module: module.to_string(),
            name: name.to_string(),
            kind: ImportKind::Func(0),
        }
    }

    /// One-function `LiftedIr` from a list of value defs (single entry
    /// block, `Unreachable` terminator). `facts` supplies imports/exports.
    fn lifted_one_fn(facts: WasmFacts, defs: Vec<LiftedValueDef>) -> LiftedIr {
        lifted_one_fn_with_term(facts, defs, LiftedTerminator::Unreachable, vec![])
    }

    /// As above but with a custom entry-block terminator + block params,
    /// so phi edges can be exercised.
    fn lifted_one_fn_with_term(
        facts: WasmFacts,
        defs: Vec<LiftedValueDef>,
        terminator: LiftedTerminator,
        params: Vec<ValueId>,
    ) -> LiftedIr {
        let mut values: Arena<ValueId, LiftedValue> = Arena::new();
        let mut instructions = Vec::new();
        for def in defs {
            let is_param = matches!(def, LiftedValueDef::BlockParam { .. });
            let id = values.push(LiftedValue {
                def,
                types: vec![LiftedType::I64],
            });
            if !is_param {
                instructions.push(id);
            }
        }
        let mut blocks: Arena<BlockId, LiftedBlock> = Arena::new();
        blocks.push(LiftedBlock {
            id: BlockId::from_index(0),
            params,
            instructions,
            terminator,
        });
        LiftedIr {
            facts,
            soroban_facts: None,
            functions: vec![LiftedFunction {
                id: FuncId::from_index(0),
                entry: BlockId::from_index(0),
                blocks,
                values,
            }],
            memory: MemoryImage::empty(),
        }
    }

    fn op(w: waffle::Operator, args: Vec<ValueId>) -> LiftedValueDef {
        LiftedValueDef::Operator {
            op: WasmOp(w),
            args,
        }
    }

    fn v(idx: u32) -> ValueId {
        ValueId::from_index(idx)
    }

    /// Lower a single-function `LiftedIr` and return its bindings arena.
    fn lower_and_bindings(ir: LiftedIr) -> Arena<ValueId, Binding> {
        let high = LiftToHigh.lower(ir).expect("lowering succeeds");
        high.functions.into_iter().next().unwrap().bindings
    }

    // --- direct value-def mappings ---

    #[test]
    fn alias_lowers_to_use() {
        let ir = lifted_one_fn(
            facts_with(vec![], vec![]),
            vec![
                op(waffle::Operator::I32Const { value: 1 }, vec![]),
                LiftedValueDef::Alias(v(0)),
            ],
        );
        let b = lower_and_bindings(ir);
        assert!(matches!(b.get(v(1)).unwrap().expr, Expr::Use(t) if t == v(0)));
    }

    #[test]
    fn constants_lower_to_literals() {
        let ir = lifted_one_fn(
            facts_with(vec![], vec![]),
            vec![
                op(waffle::Operator::I32Const { value: 42 }, vec![]),
                op(waffle::Operator::I64Const { value: 99 }, vec![]),
            ],
        );
        let b = lower_and_bindings(ir);
        assert!(matches!(
            b.get(v(0)).unwrap().expr,
            Expr::Literal(Literal::I32(42))
        ));
        assert!(matches!(
            b.get(v(1)).unwrap().expr,
            Expr::Literal(Literal::I64(99))
        ));
    }

    #[test]
    fn arithmetic_lowers_to_binary_add() {
        let ir = lifted_one_fn(
            facts_with(vec![], vec![]),
            vec![
                op(waffle::Operator::I64Const { value: 1 }, vec![]),
                op(waffle::Operator::I64Const { value: 2 }, vec![]),
                op(waffle::Operator::I64Add, vec![v(0), v(1)]),
            ],
        );
        let b = lower_and_bindings(ir);
        assert!(matches!(
            b.get(v(2)).unwrap().expr,
            Expr::Binary {
                op: BinaryOp::Add,
                lhs,
                rhs
            } if lhs == v(0) && rhs == v(1)
        ));
    }

    #[test]
    fn comparison_lowers_to_binary_lt() {
        let ir = lifted_one_fn(
            facts_with(vec![], vec![]),
            vec![
                op(waffle::Operator::I64Const { value: 1 }, vec![]),
                op(waffle::Operator::I64Const { value: 2 }, vec![]),
                op(waffle::Operator::I64LtU, vec![v(0), v(1)]),
            ],
        );
        let b = lower_and_bindings(ir);
        assert!(matches!(
            b.get(v(2)).unwrap().expr,
            Expr::Binary { op: BinaryOp::Lt, .. }
        ));
    }

    #[test]
    fn eqz_lowers_to_a_unary_rather_than_a_hole() {
        // Supersedes `eqz_lowers_to_unknown_not_fabricated_compare`, which
        // pinned the fall-through to `Expr::Unknown`. That test's concern
        // was right — this lowering must not fabricate a zero operand it
        // has nowhere to schedule — but dropping the opcode on the floor
        // was the wrong way to honour it: 60 holes on the corpus, 42 of
        // them guarding an `if`. Naming the opcode fabricates nothing, and
        // the binding count below is what says so.
        for eqz in [waffle::Operator::I32Eqz, waffle::Operator::I64Eqz] {
            let ir = lifted_one_fn(
                facts_with(vec![], vec![]),
                vec![
                    op(waffle::Operator::I64Const { value: 7 }, vec![]),
                    op(eqz, vec![v(0)]),
                ],
            );
            let b = lower_and_bindings(ir);
            assert!(
                matches!(
                    b.get(v(1)).unwrap().expr,
                    Expr::Unary {
                        op: UnaryOp::Eqz,
                        ..
                    }
                ),
                "eqz must not fall through to Expr::Unknown"
            );
            assert_eq!(
                b.len(),
                2,
                "one operator still yields one binding — no synthesised zero"
            );
        }
    }

    #[test]
    fn load_lowers_with_offset() {
        let memory = waffle::MemoryArg {
            align: 3,
            offset: 8,
            memory: waffle::Memory::from(0),
        };
        let ir = lifted_one_fn(
            facts_with(vec![], vec![]),
            vec![
                op(waffle::Operator::I32Const { value: 0 }, vec![]),
                op(waffle::Operator::I64Load { memory }, vec![v(0)]),
            ],
        );
        let b = lower_and_bindings(ir);
        assert!(matches!(
            b.get(v(1)).unwrap().expr,
            Expr::Load {
                addr,
                offset: 8,
                width: MemWidth::W8,
                signed: None,
                ..
            } if addr == v(0)
        ));
    }

    #[test]
    fn subword_load_preserves_width_and_sign() {
        let memory = waffle::MemoryArg {
            align: 0,
            offset: 0,
            memory: waffle::Memory::from(0),
        };
        let ir = lifted_one_fn(
            facts_with(vec![], vec![]),
            vec![
                op(waffle::Operator::I32Const { value: 0 }, vec![]),
                op(waffle::Operator::I32Load8U { memory }, vec![v(0)]),
            ],
        );
        let b = lower_and_bindings(ir);
        assert!(matches!(
            b.get(v(1)).unwrap().expr,
            Expr::Load {
                width: MemWidth::W1,
                signed: Some(false),
                ..
            }
        ));
    }

    #[test]
    fn store_lowers_with_addr_and_value() {
        let memory = waffle::MemoryArg {
            align: 3,
            offset: 16,
            memory: waffle::Memory::from(0),
        };
        let ir = lifted_one_fn(
            facts_with(vec![], vec![]),
            vec![
                op(waffle::Operator::I32Const { value: 0 }, vec![]),
                op(waffle::Operator::I64Const { value: 7 }, vec![]),
                op(waffle::Operator::I64Store { memory }, vec![v(0), v(1)]),
            ],
        );
        let b = lower_and_bindings(ir);
        assert!(matches!(
            b.get(v(2)).unwrap().expr,
            Expr::Store {
                addr,
                value,
                offset: 16,
                width: MemWidth::W8,
            } if addr == v(0) && value == v(1)
        ));
    }

    #[test]
    fn subword_store_preserves_width() {
        let memory = waffle::MemoryArg {
            align: 0,
            offset: 0,
            memory: waffle::Memory::from(0),
        };
        let ir = lifted_one_fn(
            facts_with(vec![], vec![]),
            vec![
                op(waffle::Operator::I32Const { value: 0 }, vec![]),
                op(waffle::Operator::I64Const { value: 7 }, vec![]),
                op(waffle::Operator::I64Store32 { memory }, vec![v(0), v(1)]),
            ],
        );
        let b = lower_and_bindings(ir);
        assert!(matches!(
            b.get(v(2)).unwrap().expr,
            Expr::Store {
                width: MemWidth::W4,
                ..
            }
        ));
    }

    #[test]
    fn import_call_lowers_to_semantic_unknown() {
        // Function index 0 is the sole Func import → host call.
        let ir = lifted_one_fn(
            facts_with(vec![func_import("l", "_")], vec![]),
            vec![op(
                waffle::Operator::Call {
                    function_index: waffle::Func::new(0),
                },
                vec![v(0)],
            )],
        );
        let b = lower_and_bindings(ir);
        match &b.get(v(0)).unwrap().expr {
            Expr::Semantic(SemanticOp::Unknown {
                host_module,
                host_fn,
                ..
            }) => {
                assert_eq!(host_module, "l");
                assert_eq!(host_fn, "_");
            }
            other => panic!("expected Semantic::Unknown, got {other:?}"),
        }
    }

    #[test]
    fn local_call_lowers_to_call_with_shifted_target() {
        // One Func import (count 1); call to global index 1 → local 0.
        let ir = lifted_one_fn(
            facts_with(vec![func_import("l", "_")], vec![]),
            vec![op(
                waffle::Operator::Call {
                    function_index: waffle::Func::new(1),
                },
                vec![],
            )],
        );
        let b = lower_and_bindings(ir);
        assert!(matches!(
            b.get(v(0)).unwrap().expr,
            Expr::Call { target, .. } if target == FuncId::from_index(0)
        ));
    }

    #[test]
    fn integer_width_moves_lower_to_named_unary_ops() {
        for (w, expected) in [
            (waffle::Operator::I32WrapI64, UnaryOp::Wrap32),
            (waffle::Operator::I64ExtendI32U, UnaryOp::ExtendU32),
            (waffle::Operator::I64ExtendI32S, UnaryOp::ExtendS32),
        ] {
            let ir = lifted_one_fn(
                facts_with(vec![], vec![]),
                vec![op(waffle::Operator::I64Const { value: 5 }, vec![]), op(w, vec![v(0)])],
            );
            let b = lower_and_bindings(ir);
            assert!(matches!(b.get(v(1)).unwrap().expr, Expr::Unary { op, .. } if op == expected));
        }
    }

    #[test]
    fn float_conversion_lowers_to_unknown() {
        // A float conversion may trap and has no Expr variant: an honest
        // Unknown with its kind.
        let ir = lifted_one_fn(
            facts_with(vec![], vec![]),
            vec![
                op(waffle::Operator::F64Const { value: 5 }, vec![]),
                op(waffle::Operator::I64TruncF64S, vec![v(0)]),
            ],
        );
        let b = lower_and_bindings(ir);
        assert!(matches!(
            b.get(v(1)).unwrap().expr,
            Expr::Unknown {
                op_kind: WasmOpcodeKind::Conversion,
                ..
            }
        ));
    }

    #[test]
    fn block_param_lowers_to_phi_with_incoming_edges() {
        // v0 = block_param[0]; v1 = const; entry branches to itself
        // passing v1 → phi incoming should record (bb0, v1).
        let target = BlockTarget {
            block: BlockId::from_index(0),
            args: vec![v(1)],
        };
        let ir = lifted_one_fn_with_term(
            facts_with(vec![], vec![]),
            vec![
                LiftedValueDef::BlockParam {
                    block: BlockId::from_index(0),
                    index: 0,
                },
                op(waffle::Operator::I64Const { value: 3 }, vec![]),
            ],
            LiftedTerminator::Branch(target),
            vec![v(0)],
        );
        let b = lower_and_bindings(ir);
        match &b.get(v(0)).unwrap().expr {
            Expr::Phi { incoming } => {
                assert_eq!(incoming.len(), 1);
                assert_eq!(incoming[0], (BlockId::from_index(0), v(1)));
            }
            other => panic!("expected Phi, got {other:?}"),
        }
    }

    // --- structural invariants ---

    #[test]
    fn every_binding_has_provenance() {
        let ir = lifted_one_fn(
            facts_with(vec![], vec![]),
            vec![
                op(waffle::Operator::I64Const { value: 1 }, vec![]),
                op(waffle::Operator::I64Const { value: 2 }, vec![]),
                op(waffle::Operator::I64Add, vec![v(0), v(1)]),
            ],
        );
        let b = lower_and_bindings(ir);
        for (_, binding) in b.iter() {
            assert!(
                !binding.provenance().is_empty(),
                "binding {:?} has empty provenance",
                binding.id
            );
            assert_eq!(binding.latest_provenance().pass, PASS_NAME);
        }
    }

    #[test]
    fn every_binding_is_unknown_typed() {
        let ir = lifted_one_fn(
            facts_with(vec![], vec![]),
            vec![op(waffle::Operator::I64Const { value: 1 }, vec![])],
        );
        let b = lower_and_bindings(ir);
        assert!(matches!(b.get(v(0)).unwrap().ty, IrType::Unknown(_)));
    }

    #[test]
    fn region_is_structured_at_the_boundary() {
        // Single Unreachable-terminated block: the structurer runs
        // inside `lower_function` and emits the exact tree.
        let ir = lifted_one_fn(
            facts_with(vec![], vec![]),
            vec![op(waffle::Operator::I64Const { value: 1 }, vec![])],
        );
        let high = LiftToHigh.lower(ir).expect("lowering succeeds");
        let f = high.functions.into_iter().next().unwrap();
        assert_eq!(
            f.region,
            Region::Sequence(vec![
                Region::Basic(BlockId::from_index(0)),
                Region::Unreachable,
            ])
        );
    }

    #[test]
    fn irreducible_cfg_falls_back_to_unstructured() {
        // Two-entry loop: bb0 br_ifs into bb1/bb2, which branch to each
        // other — the canonical irreducible shape. WASM cannot express
        // this; the boundary must degrade honestly, not panic.
        let mut ir = lifted_one_fn_with_term(
            facts_with(vec![], vec![]),
            vec![op(waffle::Operator::I32Const { value: 1 }, vec![])],
            LiftedTerminator::BranchIf {
                cond: v(0),
                if_true: BlockTarget {
                    block: BlockId::from_index(1),
                    args: vec![],
                },
                if_false: BlockTarget {
                    block: BlockId::from_index(2),
                    args: vec![],
                },
            },
            vec![],
        );
        let func = &mut ir.functions[0];
        func.blocks.push(LiftedBlock {
            id: BlockId::from_index(1),
            params: vec![],
            instructions: vec![],
            terminator: LiftedTerminator::Branch(BlockTarget {
                block: BlockId::from_index(2),
                args: vec![],
            }),
        });
        func.blocks.push(LiftedBlock {
            id: BlockId::from_index(2),
            params: vec![],
            instructions: vec![],
            terminator: LiftedTerminator::Branch(BlockTarget {
                block: BlockId::from_index(1),
                args: vec![],
            }),
        });
        let high = LiftToHigh.lower(ir).expect("lowering still succeeds");
        let f = high.functions.into_iter().next().unwrap();
        assert_eq!(
            f.region,
            Region::Unstructured {
                entry: BlockId::from_index(0),
                reason: UnknownReason::IrreducibleControlFlow,
            }
        );
    }

    #[test]
    fn exported_function_recovers_name() {
        // Export "add" at global function index 0 (no imports).
        let facts = facts_with(
            vec![],
            vec![Export {
                name: "add".to_string(),
                kind: ExportKind::Func,
                index: 0,
            }],
        );
        let ir = lifted_one_fn(facts, vec![op(waffle::Operator::I64Const { value: 1 }, vec![])]);
        let high = LiftToHigh.lower(ir).expect("lowering succeeds");
        let f = high.functions.into_iter().next().unwrap();
        assert_eq!(f.name.as_deref(), Some("add"));
    }

    fn check_auth_sig(name: &str, element: TypeRef) -> FunctionSignature {
        FunctionSignature {
            name: name.to_owned(),
            inputs: vec![
                sordec_ir::FunctionParam {
                    name: "signature_payload".into(),
                    ty: TypeRef::Composite(CompositeType::BytesN(32)),
                },
                sordec_ir::FunctionParam {
                    name: "signature".into(),
                    ty: TypeRef::Composite(CompositeType::BytesN(64)),
                },
                sordec_ir::FunctionParam {
                    name: "auth_context".into(),
                    ty: TypeRef::Composite(CompositeType::Vec(Box::new(element))),
                },
            ],
            outputs: vec![],
        }
    }

    /// The spec cannot name an SDK type, so `auth_contexts` arrives as a
    /// `Vec` of nothing. The custom account interface fixes it.
    #[test]
    fn check_auths_context_vector_is_filled_from_the_protocol() {
        let mut sig = check_auth_sig(
            CHECK_AUTH,
            TypeRef::Unknown(sordec_common::UnknownReason::NoMetadata),
        );
        fill_reserved_types(&mut sig);
        assert!(
            matches!(
                &sig.inputs[AUTH_CONTEXTS_INDEX].ty,
                TypeRef::Composite(CompositeType::Vec(e))
                    if matches!(**e, TypeRef::Sdk(SdkType::AuthContext))
            ),
            "the element type the protocol fixes"
        );
    }

    /// Two ways this must not fire: on a function that merely shares the
    /// name's shape, and over a spec that already named the element —
    /// which knows something this rule does not.
    #[test]
    fn the_protocol_fill_is_narrow() {
        let mut other = check_auth_sig(
            "transfer",
            TypeRef::Unknown(sordec_common::UnknownReason::NoMetadata),
        );
        fill_reserved_types(&mut other);
        assert!(
            matches!(
                &other.inputs[AUTH_CONTEXTS_INDEX].ty,
                TypeRef::Composite(CompositeType::Vec(e)) if matches!(**e, TypeRef::Unknown(_))
            ),
            "another entrypoint is left alone"
        );

        let mut named =
            check_auth_sig(CHECK_AUTH, TypeRef::Primitive(sordec_ir::PrimitiveType::Address));
        fill_reserved_types(&mut named);
        assert!(
            matches!(
                &named.inputs[AUTH_CONTEXTS_INDEX].ty,
                TypeRef::Composite(CompositeType::Vec(e))
                    if matches!(**e, TypeRef::Primitive(sordec_ir::PrimitiveType::Address))
            ),
            "a spec that named the element keeps it"
        );
    }
}
