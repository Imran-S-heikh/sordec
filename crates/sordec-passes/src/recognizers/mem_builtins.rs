//! The `compiler_builtins` memory routines, printed as what they are.
//!
//! # What this recognises
//!
//! rustc lowers `core::ptr::copy_nonoverlapping`, `core::ptr::copy` and
//! `core::ptr::write_bytes` — and the struct moves and zeroings it emits on
//! its own — to `memcpy`, `memmove` and `memset`, and byte-slice comparisons
//! to `memcmp`/`bcmp`; the linker resolves those to the toolchain's
//! `compiler_builtins` bodies. `memcpy` alone is a
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
//! one operation and the return of its first parameter — or, for `memcmp`,
//! of the operation's value:
//!
//! ```text
//! memcpy(dst, src, n)   →  unsafe { core::ptr::copy_nonoverlapping(src as *const u8, dst as *mut u8, n as usize) }; dst
//! memmove(dst, src, n)  →  unsafe { core::ptr::copy(src as *const u8, dst as *mut u8, n as usize) }; dst
//! memset(dst, c, n)     →  unsafe { core::ptr::write_bytes(dst as *mut u8, c as u8, n as usize) }; dst
//! memcmp(a, b, n)       →  unsafe { zip(slice(a, n), slice(b, n)).find(|(x, y)| x != y).map_or(0, |(x, y)| x - y) }
//! ```
//!
//! And, earlier in the pipeline ([`MemBuiltinResultPass`]), a call's result
//! is read as the argument it is: `memcpy`, `memmove` and `memset` return
//! their destination, so `let p = memcpy(fp, src, 64); p + 8` is `fp + 8`,
//! an address the frame analyses can place.
//!
//! # Why it is exact
//!
//! Each routine's source (`compiler_builtins::mem`) is the primitive plus
//! the return: `memcpy` is `copy_forward(dest, src, n); dest`, `memmove`
//! picks `copy_forward` or `copy_backward` by overlap and returns `dest`,
//! `memset` is `set_bytes(s, c as u8, n); s`, `memcmp` is `compare_bytes`.
//! The printed primitive moves the same `n` bytes from the same addresses
//! and the function returns the same word:
//!
//! - `memcpy` is C's `memcpy`, whose contract is `copy_nonoverlapping`'s:
//!   the regions must not overlap. It is reached only through
//!   `llvm.memcpy`, which `copy_nonoverlapping` and rustc's own moves lower
//!   to. On every call that meets the contract, the forward copy and the
//!   primitive write the same bytes. One edge is stated rather than hidden:
//!   LLVM's `llvm.memcpy` also admits two *identical* regions, where the
//!   routine copies each byte onto itself and `copy_nonoverlapping` is
//!   undefined; `core::ptr::copy` is defined there too, and is the spelling
//!   to switch to if that case is ever seen to matter.
//! - `memmove` is defined for any overlap, as `core::ptr::copy` is.
//! - `memset` writes `c as u8`, which is the `as u8` printed.
//! - `memcmp` walks `i` from 0 and returns `a[i] as c_int - b[i] as c_int`
//!   at the first `a[i] != b[i]`, else 0; the iterator does the same walk
//!   on the same bytes, `i32::from(u8)` being `c_int::from(u8)`. The slices
//!   add one precondition, a non-null address, which every caller meets:
//!   `memcmp` is reached only from comparisons of Rust slices.
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
//! # The result as its argument: why it is exact, and its gates
//!
//! The routine's source returns its first parameter unchanged on every
//! path, and the body is that source (the fingerprint), so the call's value
//! *is* its first argument. Each binding that reads the call's value reads
//! the argument instead; the call stays, for its effect. The argument is
//! defined before the call and the call before every reader, so it is in
//! scope wherever the value was read.
//!
//! - Only `memcpy`, `memmove` and `memset`; `memcmp` returns a comparison.
//!   A call may reach the body through the `extern "C"` symbol, which from
//!   rustc 1.89 is a forwarder: one call of the body with its own three
//!   parameters in order, its value returned, nothing else — so it returns
//!   what the body returns. One level only.
//! - The call has three arguments.
//! - Only readers that are bindings, and not merges: a merge's input, a
//!   branch condition or a returned value keeps the call's value, which
//!   leaves the parallel copies on a merge's edges exactly as they were.
//!
//! # Placement
//!
//! The body rewrite runs last of the rewriting passes. Every analysis before it sees the
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

use crate::metrics_catalog::{
    MEM_BUILTINS_DECLINED as M_DECLINED, MEM_BUILTINS_REWRITTEN as M_REWRITTEN,
    MEM_BUILTIN_RESULTS_READ as M_RESULTS_READ,
};
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

/// Pass name of the call-result reading, also its provenance `pass` field.
pub const RESULT_PASS_NAME: &str = "mem-builtin-results";

/// Reads a call to `memcpy`, `memmove` or `memset` as returning the
/// destination it was handed. See the module docs.
#[derive(Debug, Default, Clone, Copy)]
pub struct MemBuiltinResultPass;

impl Pass<HighIr> for MemBuiltinResultPass {
    fn name(&self) -> &'static str {
        RESULT_PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let returns_dst: std::collections::HashSet<FuncId> =
            ir.functions.iter().map(|f| f.id).filter(|id| copy_or_fill(ir, *id)).collect();
        if returns_dst.is_empty() {
            return result;
        }
        let mut read = 0_i64;
        for func in &mut ir.functions {
            // The call's value -> its destination argument.
            let dst_of: std::collections::HashMap<ValueId, ValueId> = func
                .bindings
                .iter()
                .filter_map(|(id, b)| match &b.expr {
                    Expr::Call { target, args } if returns_dst.contains(target) && args.len() == 3 => {
                        Some((id, args[0]))
                    }
                    _ => None,
                })
                .collect();
            if dst_of.is_empty() {
                continue;
            }
            // A destination that is itself such a call's value is that
            // call's destination; the chain is as long as the calls.
            let resolve = |mut v: ValueId| {
                for _ in 0..dst_of.len() {
                    match dst_of.get(&v) {
                        Some(next) => v = *next,
                        None => break,
                    }
                }
                v
            };
            let ids: Vec<ValueId> = func.bindings.iter().map(|(id, _)| id).collect();
            for id in ids {
                let Some(binding) = func.bindings.get_mut(id) else { continue };
                if matches!(binding.expr, Expr::Phi { .. }) {
                    continue;
                }
                let mut changed = false;
                binding.expr.for_each_value_use_mut(|u| {
                    if dst_of.contains_key(u) {
                        *u = resolve(*u);
                        changed = true;
                    }
                });
                if changed {
                    binding.add_provenance(Provenance::new(
                        RESULT_PASS_NAME,
                        ProvenanceSource::SdkPattern,
                        "a memory routine's value read as the destination it returns",
                    ));
                    read += 1;
                }
            }
        }
        if read > 0 {
            result.metrics.increment(M_RESULTS_READ, read);
            result.changed = true;
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
    if func.signature.is_some() || func.params.len() != 3 {
        return None;
    }
    if let Some(entry) = entry_of(ir, func) {
        return Some(entry.routine);
    }
    // The `extern "C"` symbol rustc's calls are linked to is, from 1.89 on,
    // a forwarder to the mangled body: it hands its three parameters on in
    // order and returns what comes back, so it is the routine too. One
    // level only — that is the whole of the shape.
    let inner = forwarded(func)?;
    let body = ir.function(inner).filter(|f| f.id == inner && f.id != target)?;
    if body.signature.is_some() || body.params.len() != 3 {
        return None;
    }
    entry_of(ir, body).map(|e| e.routine)
}

/// The function `func` does nothing but call, with its own parameters in
/// order, returning that call's value: one call, nothing else scheduled but
/// renames, and a region of blocks and returns only — no branch, no trap.
fn forwarded(func: &HighFunction) -> Option<FuncId> {
    use crate::dataflow::resolve_use;
    let mut call = None;
    for id in crate::marshalling::sret::emission_order(func) {
        match &func.bindings.get(id)?.expr {
            Expr::Phi { .. } | Expr::Use(_) => {}
            Expr::Call { target, args } if call.is_none() => call = Some((id, *target, args.clone())),
            _ => return None,
        }
    }
    let (id, target, args) = call?;
    if !args.iter().map(|a| resolve_use(func, *a)).eq(func.params.iter().copied()) {
        return None;
    }
    if func.returns.is_empty() || !func.returns.iter().all(|r| matches!(r.as_slice(), [v] if resolve_use(func, *v) == id)) {
        return None;
    }
    let mut plain = true;
    func.region.for_each_node(|node| {
        plain &= matches!(node, Region::Basic(_) | Region::Sequence(_) | Region::Return { .. });
    });
    plain.then_some(target)
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

/// Whether `target` is a routine that copies or fills: one whose memory
/// effect is its destination written for the length and, for a copy, its
/// source read for as long. Not `memcmp`, which writes nothing.
#[must_use]
pub(crate) fn copy_or_fill(ir: &HighIr, target: FuncId) -> bool {
    matches!(routine(ir, target), Some(MemRoutine::Memcpy | MemRoutine::Memmove | MemRoutine::Memset))
}

/// Whether the body is already the one operation this pass plants.
fn already_rewritten(func: &HighFunction) -> bool {
    func.bindings.iter().any(|(_, b)| {
        matches!(
            b.expr,
            Expr::Semantic(SemanticOp::Known(
                KnownOp::MemCopy { .. } | KnownOp::MemFill { .. } | KnownOp::MemCompare { .. }
            ))
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
        MemRoutine::Memcmp => KnownOp::MemCompare { a: dst, b: second, len },
    };
    // `memcmp` returns its comparison, a `c_int`: the wasm function type
    // says `i32`, so the type is the ABI's, not inferred. The others return
    // nothing of their own.
    let (ty, returned) = match routine {
        MemRoutine::Memcmp => (IrType::Known(KnownType::I32), None),
        _ => (IrType::Known(KnownType::Unit), Some(dst)),
    };
    let id = ValueId::from_index(func.bindings.len() as u32);
    let returned = returned.unwrap_or(id);
    func.bindings.push(Binding::new(
        id,
        ty,
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
    func.region = Region::Sequence(vec![Region::Basic(block), Region::Return { values: vec![returned] }]);
    func.returns = vec![vec![returned]];
    if returned != dst {
        return;
    }
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

    /// func_1 `fn(a, b, c) -> call(func_0, args)`, the `extern "C"` shape.
    fn forwarder(args: [u32; 3], extra: bool) -> HighFunction {
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        let seed = || Provenance::new("seed", ProvenanceSource::DataFlow, "seed");
        for _ in 0..3 {
            let id = v(bindings.len() as u32);
            bindings.push(Binding::new(id, i32_ty(), Expr::Phi { incoming: vec![] }, seed()));
        }
        let call = Expr::Call { target: FuncId::from_index(0), args: args.iter().map(|a| v(*a)).collect() };
        bindings.push(Binding::new(v(3), i32_ty(), call, seed()));
        bindings.push(Binding::new(v(4), i32_ty(), Expr::GlobalGet { index: 0 }, seed()));
        let scheduled = if extra { vec![v(3), v(4)] } else { vec![v(3)] };
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        let b0 = blocks.push(HighBlock { id: BlockId::from_index(0), bindings: scheduled });
        HighFunction {
            id: FuncId::from_index(1),
            name: None,
            signature: None,
            aliases: Vec::new(),
            blocks,
            bindings,
            region: Region::Sequence(vec![Region::Basic(b0), Region::Return { values: vec![v(3)] }]),
            params: vec![v(0), v(1), v(2)],
            returns: vec![vec![v(3)]],
        }
    }

    #[test]
    fn a_forwarder_to_a_routine_is_the_routine() {
        let with = |f: HighFunction| {
            let mut ir = module_of(routine_like(3, i32_ty()), Some(fp(MemRoutine::Memcpy)));
            ir.functions.push(f);
            ir.facts.function_fingerprints.push(None);
            routine(&ir, FuncId::from_index(1))
        };
        assert_eq!(with(forwarder([0, 1, 2], false)), Some(MemRoutine::Memcpy));
        assert_eq!(with(forwarder([1, 0, 2], false)), None, "its parameters out of order");
        assert_eq!(with(forwarder([0, 1, 2], true)), None, "anything besides the call");
    }

    /// `memcmp` returns its comparison, not its first operand.
    #[test]
    fn a_memcmp_body_becomes_one_compare_it_returns() {
        let mut ir = module_of(routine_like(3, i32_ty()), Some(fp(MemRoutine::Memcmp)));
        assert!(MemBuiltinPass.run(&mut ir).changed);
        let f = &ir.functions[0];
        let Region::Sequence(parts) = &f.region else { panic!("a sequence") };
        let [Region::Basic(b), Region::Return { values }] = parts.as_slice() else { panic!("one block and a return") };
        let [only] = f.blocks.get(*b).expect("the block").bindings.as_slice() else { panic!("one binding") };
        assert_eq!(values, &vec![*only], "the comparison is what comes back");
        let op = f.bindings.get(*only).expect("the op");
        assert!(matches!(
            op.expr,
            Expr::Semantic(SemanticOp::Known(KnownOp::MemCompare { a, b, len })) if a == v(0) && b == v(1) && len == v(2)
        ));
        assert_eq!(op.ty, IrType::Known(KnownType::I32));
        assert!(!copy_or_fill(&ir, FuncId::from_index(0)), "a compare writes nothing");
    }

    /// func_0 the routine; func_1 `p = routine(fp, src, 16); q = p + 8; r = load q`.
    fn caller_of(routine: MemRoutine) -> HighIr {
        let mut callee = routine_like(3, i32_ty());
        callee.id = FuncId::from_index(0);
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        let seed = || Provenance::new("seed", ProvenanceSource::DataFlow, "seed");
        let exprs = vec![
            Expr::Phi { incoming: vec![] },                                                         // v0 fp
            Expr::Phi { incoming: vec![] },                                                         // v1 src
            Expr::Literal(sordec_ir::Literal::I32(16)),                                             // v2
            Expr::Call { target: FuncId::from_index(0), args: vec![v(0), v(1), v(2)] },             // v3
            Expr::Literal(sordec_ir::Literal::I32(8)),                                              // v4
            Expr::Binary { op: sordec_ir::BinaryOp::Add, lhs: v(3), rhs: v(4) },                    // v5
            Expr::Load { addr: v(5), offset: 0, width: sordec_ir::MemWidth::W8, signed: None, ty: i32_ty() }, // v6
        ];
        for expr in exprs {
            let id = v(bindings.len() as u32);
            bindings.push(Binding::new(id, i32_ty(), expr, seed()));
        }
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        let b0 = blocks.push(HighBlock { id: BlockId::from_index(0), bindings: (2..7).map(v).collect() });
        let caller = HighFunction {
            id: FuncId::from_index(1),
            name: None,
            signature: None,
            aliases: Vec::new(),
            blocks,
            bindings,
            region: Region::Sequence(vec![Region::Basic(b0), Region::Return { values: vec![v(3)] }]),
            params: vec![v(0), v(1)],
            returns: vec![vec![v(3)]],
        };
        let mut ir = module_of(callee, Some(fp(routine)));
        ir.functions.push(caller);
        ir.facts.function_fingerprints.push(None);
        ir
    }

    #[test]
    fn a_copy_s_value_is_read_as_its_destination() {
        for routine in [MemRoutine::Memcpy, MemRoutine::Memmove, MemRoutine::Memset] {
            let mut ir = caller_of(routine);
            assert!(MemBuiltinResultPass.run(&mut ir).changed);
            let f = &ir.functions[1];
            assert!(matches!(f.bindings.get(v(5)).expect("the address").expr, Expr::Binary { lhs, .. } if lhs == v(0)));
            assert!(matches!(f.bindings.get(v(3)).expect("the call").expr, Expr::Call { .. }), "the call stays");
            assert_eq!(f.region, Region::Sequence(vec![Region::Basic(BlockId::from_index(0)), Region::Return { values: vec![v(3)] }]), "a returned value is left");
            assert!(!MemBuiltinResultPass.run(&mut ir).changed, "idempotent");
        }
    }

    #[test]
    fn a_compare_s_value_or_an_unnamed_call_s_is_left() {
        let mut ir = caller_of(MemRoutine::Memcmp);
        assert!(!MemBuiltinResultPass.run(&mut ir).changed);
        let mut ir = caller_of(MemRoutine::Memcpy);
        ir.facts.function_fingerprints[0] = None;
        assert!(!MemBuiltinResultPass.run(&mut ir).changed);
        assert!(matches!(ir.functions[1].bindings.get(v(5)).expect("the address").expr, Expr::Binary { lhs, .. } if lhs == v(3)));
    }
}
