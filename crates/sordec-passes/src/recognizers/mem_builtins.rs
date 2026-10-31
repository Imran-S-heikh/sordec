//! The `compiler_builtins` memory routines, printed as what they are.
//!
//! # What this recognises
//!
//! rustc lowers `core::ptr::copy_nonoverlapping`, `core::ptr::copy` and
//! `core::ptr::write_bytes` — and the struct moves and zeroings it emits on
//! its own — to `memcpy`, `memmove` and `memset`, and the linker resolves
//! those to the toolchain's `compiler_builtins` bodies. `memcpy` alone is a
//! 500-instruction word-and-byte loop, and it decompiled as 57 holes in
//! every contract that links it: none of it is the author's, and none of it
//! can be read back as anything but loads and stores.
//!
//! Identification is by body fingerprint against
//! [`sordec_sigs::builtins`], a table read from the toolchains' own rlibs.
//! That module's docs carry the argument that a match *is* the routine:
//! the fingerprint hashes every instruction verbatim except the one
//! masked `global.get`, and the bodies survive linking unchanged.
//!
//! # What the rewrite is
//!
//! The function keeps its name, parameters and callers. Its body becomes
//! one operation and the return of its first parameter:
//!
//! ```text
//! memcpy(dst, src, n)   →  unsafe { core::ptr::copy_nonoverlapping(src as *const u8, dst as *mut u8, n as usize) }; dst
//! memmove(dst, src, n)  →  unsafe { core::ptr::copy(src as *const u8, dst as *mut u8, n as usize) }; dst
//! memset(dst, c, n)     →  unsafe { core::ptr::write_bytes(dst as *mut u8, c as u8, n as usize) }; dst
//! ```
//!
//! # Why it is exact
//!
//! Each routine's source (`compiler_builtins::mem`) is the primitive plus
//! the return: `memcpy` is `copy_forward(dest, src, n); dest`, `memmove`
//! picks `copy_forward` or `copy_backward` by overlap and returns `dest`,
//! `memset` is `set_bytes(s, c as u8, n); s`. The printed primitive moves
//! the same `n` bytes from the same addresses and the function returns the
//! same word:
//!
//! - `memcpy` has exactly `copy_nonoverlapping`'s contract — the regions
//!   must not overlap — and it is reached only through `llvm.memcpy`,
//!   which is what `copy_nonoverlapping` and rustc's own moves lower to and
//!   which carries that same precondition. On every call that meets it the
//!   forward copy and the primitive write the same bytes.
//! - `memmove` is defined for any overlap, as `core::ptr::copy` is.
//! - `memset` writes `c as u8`, which is the `as u8` printed.
//! - On wasm32 `usize` and pointers are 32 bits, so `n as usize` and the
//!   address casts keep every bit of the `i32` parameters.
//!
//! The one thing the original does that the primitive does not is touch a
//! `usize` of scratch in its own frame — `load_aligned_partial`'s `out`,
//! addressed below the stack pointer. That is a local of the routine; its
//! storage is dead when the routine returns, and no Rust caller can read
//! it.
//!
//! # Gates
//!
//! - The body's fingerprint is in [`sordec_sigs::builtins::MEM_ROUTINES`].
//! - The function is not an entrypoint (`signature` is `None`).
//! - Exactly three parameters, each a 32-bit integer. The fingerprint
//!   covers the instruction stream, not the function type; three
//!   parameters is the routine's type, and a matching stream with any
//!   other parameter count is some other function.
//! - Every return site returns one value.
//! - Every global the body reads is global 0, the stack pointer, and it
//!   writes none: the fingerprint masks which global the scratch is
//!   addressed from, and the argument above is about the stack.
//!
//! # Placement
//!
//! Last of the rewriting passes. Every analysis before it sees the
//! original body, which each already handles — as a callee whose reach
//! through its pointers it cannot bound — so introducing a new operation
//! there would mean auditing every pass that looks inside a callee. The
//! call-site analyses that *can* use the knowledge ask [`routine`] instead,
//! which reads only the fingerprint and so answers the same before and
//! after the body is replaced.

use sordec_common::{
    Diagnostic, FuncId, IrId, LiftDiagnosticCode, Location, Provenance, ProvenanceSource, ValueId,
};
use sordec_ir::{
    Binding, Expr, HighBlock, HighFunction, HighIr, IrType, KnownOp, KnownType, Region,
    SemanticOp, WasmOpcodeKind,
};
use sordec_sigs::{Fingerprint, MemRoutine};

use crate::metrics_catalog::{MEM_BUILTINS_DECLINED as M_DECLINED, MEM_BUILTINS_REWRITTEN as M_REWRITTEN};
use crate::pass::{Pass, PassResult};

/// Pass name, also its provenance `pass` field.
pub const PASS_NAME: &str = "mem-builtins";

/// Rewrites the bodies of the identified memory routines.
#[derive(Debug, Default, Clone, Copy)]
pub struct MemBuiltinPass;

impl Pass<HighIr> for MemBuiltinPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let found: Vec<(usize, MemRoutine, &'static str)> = ir
            .functions
            .iter()
            .enumerate()
            .filter_map(|(i, f)| {
                let entry = entry_of(ir, f)?;
                Some((i, entry.routine, entry.toolchains))
            })
            .collect();
        for (index, routine, toolchains) in found {
            let Some(func) = ir.functions.get_mut(index) else { continue };
            if already_rewritten(func) {
                continue;
            }
            let id = func.id;
            match gate(func) {
                Ok(()) => {
                    rewrite(func, routine, toolchains);
                    result.metrics.increment(M_REWRITTEN, 1);
                    result.changed = true;
                    result.diagnostics.push(
                        Diagnostic::info(
                            LiftDiagnosticCode::SdkFunctionIdentified,
                            format!(
                                "func_{} is compiler_builtins::{} (rustc {toolchains})",
                                id.index(),
                                routine.symbol()
                            ),
                        )
                        .at(Location::Function(id)),
                    );
                }
                Err(why) => {
                    result.metrics.increment(M_DECLINED, 1);
                    result.diagnostics.push(
                        Diagnostic::info(
                            LiftDiagnosticCode::SdkFunctionIdentified,
                            format!(
                                "func_{} has the body of compiler_builtins::{} but is left as is: {why}",
                                id.index(),
                                routine.symbol()
                            ),
                        )
                        .at(Location::Function(id)),
                    );
                }
            }
        }
        result
    }
}

/// The memory routine `target` is, by the fingerprint of its original body.
///
/// For the call-site analyses: it reads only facts fixed at parse time and
/// the parameter list, so it gives the same answer before and after this
/// pass replaces the body. `None` for anything that is not a three-parameter
/// helper with a listed fingerprint.
#[must_use]
pub(crate) fn routine(ir: &HighIr, target: FuncId) -> Option<MemRoutine> {
    let func = ir.function(target).filter(|f| f.id == target)?;
    let entry = entry_of(ir, func)?;
    (func.signature.is_none() && func.params.len() == 3).then_some(entry.routine)
}

/// The table entry for `func`'s original body.
fn entry_of(ir: &HighIr, func: &HighFunction) -> Option<&'static sordec_sigs::BuiltinEntry> {
    listed(&ir.facts, func.id)
}

/// The table entry for local function `id`'s body as parsed.
fn listed(facts: &sordec_ir::WasmFacts, id: FuncId) -> Option<&'static sordec_sigs::BuiltinEntry> {
    // `function_fingerprints` is indexed by local function index, which is
    // the function's `id`; a short vector means hand-built facts.
    let raw = (*facts.function_fingerprints.get(id.index() as usize)?)?;
    sordec_sigs::mem_routine(Fingerprint(raw))
}

/// Whether the body is already the one operation this pass plants.
fn already_rewritten(func: &HighFunction) -> bool {
    func.bindings.iter().any(|(_, b)| {
        matches!(
            b.expr,
            Expr::Semantic(SemanticOp::Known(KnownOp::MemCopy { .. } | KnownOp::MemFill { .. }))
        )
    })
}

fn gate(func: &HighFunction) -> Result<(), &'static str> {
    if func.signature.is_some() {
        return Err("it is an entrypoint");
    }
    if func.params.len() != 3 {
        return Err("it does not take three parameters");
    }
    let word = |id: &ValueId| {
        matches!(
            func.bindings.get(*id).map(|b| &b.ty),
            Some(IrType::Known(KnownType::I32 | KnownType::U32) | IrType::Inferred(KnownType::I32 | KnownType::U32))
        )
    };
    if !func.params.iter().all(word) {
        return Err("a parameter is not a 32-bit integer");
    }
    if func.returns.is_empty() || func.returns.iter().any(|r| r.len() != 1) {
        return Err("it does not return one value");
    }
    for (_, b) in func.bindings.iter() {
        match &b.expr {
            Expr::GlobalGet { index } if *index != 0 => return Err("it reads a global other than the stack pointer"),
            Expr::Unknown { op_kind: WasmOpcodeKind::GlobalSet, .. } => return Err("it writes a global"),
            _ => {}
        }
    }
    Ok(())
}

fn rewrite(func: &mut HighFunction, routine: MemRoutine, toolchains: &str) {
    let (dst, second, len) = (func.params[0], func.params[1], func.params[2]);
    let op = match routine {
        MemRoutine::Memcpy => KnownOp::MemCopy { dst, src: second, len, may_overlap: false },
        MemRoutine::Memmove => KnownOp::MemCopy { dst, src: second, len, may_overlap: true },
        MemRoutine::Memset => KnownOp::MemFill { dst, byte: second, len },
    };
    let id = ValueId::from_index(func.bindings.len() as u32);
    func.bindings.push(Binding::new(
        id,
        IrType::Known(KnownType::Unit),
        Expr::Semantic(SemanticOp::Known(op)),
        Provenance::new(
            PASS_NAME,
            ProvenanceSource::SdkPattern,
            format!(
                "the body is compiler_builtins::{} from rustc {toolchains}, identified by fingerprint",
                routine.symbol()
            ),
        ),
    ));
    let block = func.blocks.push(HighBlock { id: sordec_common::BlockId::from_index(func.blocks.len() as u32), bindings: vec![id] });
    func.region = Region::Sequence(vec![Region::Basic(block), Region::Return { values: vec![dst] }]);
    func.returns = vec![vec![dst]];
    if let Some(b) = func.bindings.get_mut(dst) {
        b.add_provenance(Provenance::new(
            PASS_NAME,
            ProvenanceSource::SdkPattern,
            format!("returned as {} returns its destination", routine.symbol()),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{Arena, BlockId, UnknownReason};
    use sordec_ir::{FunctionSignature, MemoryImage, WasmFacts};

    fn v(i: u32) -> ValueId {
        ValueId::from_index(i)
    }

    fn fp(routine: MemRoutine) -> u128 {
        sordec_sigs::builtins::MEM_ROUTINES
            .iter()
            .find(|e| e.routine == routine)
            .expect("the table lists every routine")
            .fingerprint
            .to_u128()
    }

    /// A stand-in for the routine's original body: three `i32` parameters,
    /// the stack-pointer read the scratch is addressed from, a loop-free
    /// byte store, and a return of the first parameter.
    fn routine_like(params: usize, param_ty: IrType) -> HighFunction {
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        let seed = || Provenance::new("seed", ProvenanceSource::DataFlow, "seed");
        let mut ids = Vec::new();
        for _ in 0..params {
            let id = v(bindings.len() as u32);
            bindings.push(Binding::new(id, param_ty.clone(), Expr::Phi { incoming: vec![] }, seed()));
            ids.push(id);
        }
        let sp = v(bindings.len() as u32);
        bindings.push(Binding::new(sp, IrType::Known(KnownType::I32), Expr::GlobalGet { index: 0 }, seed()));
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        let b0 = blocks.push(HighBlock { id: BlockId::from_index(0), bindings: vec![sp] });
        HighFunction {
            id: FuncId::from_index(0),
            name: None,
            signature: None,
            aliases: Vec::new(),
            blocks,
            bindings,
            region: Region::Sequence(vec![Region::Basic(b0), Region::Return { values: vec![v(0)] }]),
            params: ids,
            returns: vec![vec![v(0)]],
        }
    }

    fn module_of(func: HighFunction, fingerprint: Option<u128>) -> HighIr {
        HighIr {
            facts: WasmFacts {
                imports: vec![],
                exports: vec![],
                function_type_indices: vec![],
                function_bodies: vec![],
                function_fingerprints: vec![fingerprint],
                table_functions: None,
                custom_sections: vec![],
            },
            soroban_facts: None,
            functions: vec![func],
            memory: MemoryImage::empty(),
        }
    }

    fn i32_ty() -> IrType {
        IrType::Known(KnownType::I32)
    }

    /// The one operation the body was reduced to, if it was.
    fn planted(ir: &HighIr) -> Option<KnownOp> {
        let f = &ir.functions[0];
        let Region::Sequence(parts) = &f.region else { return None };
        let [Region::Basic(b), Region::Return { values }] = parts.as_slice() else { return None };
        assert_eq!(values, &vec![f.params[0]], "the routine returns its destination");
        let [only] = f.blocks.get(*b)?.bindings.as_slice() else { return None };
        match &f.bindings.get(*only)?.expr {
            Expr::Semantic(SemanticOp::Known(op)) => Some(op.clone()),
            _ => None,
        }
    }

    #[test]
    fn a_memcpy_body_becomes_one_nonoverlapping_copy() {
        let mut ir = module_of(routine_like(3, i32_ty()), Some(fp(MemRoutine::Memcpy)));
        let r = MemBuiltinPass.run(&mut ir);
        assert!(r.changed);
        assert!(matches!(
            planted(&ir),
            Some(KnownOp::MemCopy { dst, src, len, may_overlap: false }) if dst == v(0) && src == v(1) && len == v(2)
        ));
        let op = ir.functions[0].bindings.iter().last().map(|(_, b)| b.latest_provenance().pass);
        assert_eq!(op, Some(PASS_NAME));
        assert_eq!(routine(&ir, FuncId::from_index(0)), Some(MemRoutine::Memcpy));
    }

    #[test]
    fn a_memmove_body_becomes_a_copy_that_may_overlap() {
        let mut ir = module_of(routine_like(3, i32_ty()), Some(fp(MemRoutine::Memmove)));
        MemBuiltinPass.run(&mut ir);
        assert!(matches!(planted(&ir), Some(KnownOp::MemCopy { may_overlap: true, .. })));
    }

    #[test]
    fn a_memset_body_becomes_one_fill() {
        let mut ir = module_of(routine_like(3, IrType::Inferred(KnownType::U32)), Some(fp(MemRoutine::Memset)));
        MemBuiltinPass.run(&mut ir);
        assert!(matches!(
            planted(&ir),
            Some(KnownOp::MemFill { dst, byte, len }) if dst == v(0) && byte == v(1) && len == v(2)
        ));
    }

    #[test]
    fn a_second_run_changes_nothing() {
        let mut ir = module_of(routine_like(3, i32_ty()), Some(fp(MemRoutine::Memcpy)));
        MemBuiltinPass.run(&mut ir);
        let blocks = ir.functions[0].blocks.len();
        assert!(!MemBuiltinPass.run(&mut ir).changed);
        assert_eq!(ir.functions[0].blocks.len(), blocks);
    }

    fn untouched(ir: &mut HighIr) -> bool {
        let before = ir.functions[0].bindings.len();
        let r = MemBuiltinPass.run(ir);
        !r.changed && ir.functions[0].bindings.len() == before
    }

    #[test]
    fn a_body_without_a_listed_fingerprint_is_left() {
        assert!(untouched(&mut module_of(routine_like(3, i32_ty()), None)));
        assert!(untouched(&mut module_of(routine_like(3, i32_ty()), Some(0xdead_beef))));
        let mut ir = module_of(routine_like(3, i32_ty()), None);
        assert_eq!(routine(&ir, FuncId::from_index(0)), None);
        assert!(untouched(&mut ir));
    }

    #[test]
    fn the_same_stream_with_another_parameter_count_is_left() {
        let mut ir = module_of(routine_like(2, i32_ty()), Some(fp(MemRoutine::Memcpy)));
        assert_eq!(routine(&ir, FuncId::from_index(0)), None);
        assert!(untouched(&mut ir));
    }

    #[test]
    fn a_parameter_that_is_not_a_word_is_left() {
        let mut ir = module_of(routine_like(3, IrType::Known(KnownType::Val)), Some(fp(MemRoutine::Memcpy)));
        assert!(untouched(&mut ir));
        let mut ir = module_of(
            routine_like(3, IrType::Unknown(UnknownReason::InsufficientEvidence)),
            Some(fp(MemRoutine::Memcpy)),
        );
        assert!(untouched(&mut ir));
    }

    #[test]
    fn an_entrypoint_is_left() {
        let mut f = routine_like(3, i32_ty());
        f.signature = Some(FunctionSignature { name: "f".into(), inputs: vec![], outputs: vec![] });
        let mut ir = module_of(f, Some(fp(MemRoutine::Memcpy)));
        assert_eq!(routine(&ir, FuncId::from_index(0)), None);
        assert!(untouched(&mut ir));
    }

    #[test]
    fn a_scratch_addressed_from_another_global_is_left() {
        let mut f = routine_like(3, i32_ty());
        f.bindings.get_mut(v(3)).expect("the global read").expr = Expr::GlobalGet { index: 1 };
        assert!(untouched(&mut module_of(f, Some(fp(MemRoutine::Memcpy)))));
    }

    #[test]
    fn a_body_that_writes_a_global_is_left() {
        let mut f = routine_like(3, i32_ty());
        f.bindings.get_mut(v(3)).expect("the global read").expr = Expr::Unknown {
            op_kind: WasmOpcodeKind::GlobalSet,
            args: vec![v(0)],
            reason: UnknownReason::InsufficientEvidence,
        };
        assert!(untouched(&mut module_of(f, Some(fp(MemRoutine::Memcpy)))));
    }

    #[test]
    fn a_body_returning_two_values_is_left() {
        let mut f = routine_like(3, i32_ty());
        f.returns = vec![vec![v(0), v(1)]];
        assert!(untouched(&mut module_of(f, Some(fp(MemRoutine::Memcpy)))));
    }
}
