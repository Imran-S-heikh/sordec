//! Remove the shadow-stack prologue and epilogue.
//!
//! WASM's operand stack has no addresses, so anything rustc needs to point
//! at lives in a region of linear memory it manages itself. A global holds
//! the stack pointer; every function needing scratch space brackets its
//! body with:
//!
//! ```text
//! sp  = global.get 0        ← prologue
//! fp  = sp - 16
//! global.set 0, fp
//! …body…
//! global.set 0, fp + 16     ← epilogue
//! ```
//!
//! None of it is in the source. Once [`super::decode`] has bound the frame
//! slots back to the parameters they came from, `fp` has no consumers left
//! and the whole bracket is bookkeeping for scratch space nobody uses.
//!
//! ## The gate that makes this safe
//!
//! **`fp` must have no remaining reads outside the bracket itself.** A
//! function with genuinely stack-allocated data still reads `fp`, and its
//! frame stays exactly as it was — this pass is all-or-nothing per
//! function, never partial. That single condition is what separates "the
//! decode glue is gone, so the scratch space is unused" from "we deleted
//! a live stack pointer", and it is checked against the emitted body
//! rather than assumed from the shape.
//!
//! The prologue and epilogue must also be **balanced** — same global, same
//! frame size, subtracted on entry and added back on exit. An unbalanced
//! pair means the function does something to the stack pointer we have
//! not modelled, so nothing is touched.

use std::collections::HashMap;

use sordec_common::ValueId;
use sordec_ir::{
    BinaryOp, Expr, HighFunction, HighIr, IrType, KnownType, Literal, WasmOpcodeKind,
};

use super::{apply_elisions, metrics, Elision};
use crate::dataflow::{resolve_use, trace_int};
use crate::pass::{Pass, PassResult};

/// Unique pipeline name of this pass.
pub const PASS_NAME: &str = "marshalling-frame-elision";

/// Removes balanced, unused shadow-stack frames.
#[derive(Debug, Default, Clone, Copy)]
pub struct FrameElisionPass;

impl Pass<HighIr> for FrameElisionPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            let Some(frame) = find_unused_frame(func) else {
                continue;
            };
            result.changed = true;
            result.metrics.increment(metrics::FRAMES_ELIDED, 1);
            let elisions = frame
                .bindings
                .into_iter()
                .map(|id| Elision {
                    id,
                    expr: Expr::Literal(Literal::Unit),
                    ty: Some(IrType::Known(KnownType::Unit)),
                    note: format!(
                        "shadow-stack bookkeeping ({}-byte frame, no remaining reads)",
                        frame.size
                    ),
                    metric: metrics::FRAMES_ELIDED,
                })
                .collect();
            apply_elisions(func, PASS_NAME, elisions);
        }
        result
    }
}

/// The bindings making up one elidable frame bracket.
struct Frame {
    /// Every binding to neutralise: the global read, the pointer
    /// computation, both global writes, and the epilogue's `fp + size`.
    bindings: Vec<ValueId>,
    /// Frame size in bytes, for the audit note.
    size: i128,
}

/// Find `func`'s shadow-stack bracket, if it has one and nothing else
/// reads its pointer.
fn find_unused_frame(func: &HighFunction) -> Option<Frame> {
    let uses = read_counts(func);

    // Prologue: `fp = global.get G - size`.
    let (fp, sp, size) = func.bindings.iter().find_map(|(id, binding)| {
        let Expr::Binary {
            op: BinaryOp::Sub,
            lhs,
            rhs,
        } = &binding.expr
        else {
            return None;
        };
        let sp = resolve_use(func, *lhs);
        let global = func.bindings.get(sp)?;
        matches!(global.expr, Expr::GlobalGet { .. })
            .then(|| trace_int(func, *rhs).map(|size| (id, sp, size)))
            .flatten()
    })?;

    // The stack pointer read must feed nothing but the subtraction.
    if uses.get(&sp).copied().unwrap_or(0) != 1 {
        return None;
    }

    // The two `global.set`s, and the epilogue's restore arithmetic.
    let mut prologue_set = None;
    let mut epilogue_add = None;
    for (id, binding) in func.bindings.iter() {
        match &binding.expr {
            Expr::Unknown {
                op_kind: WasmOpcodeKind::GlobalSet,
                args,
                ..
            } if args.len() == 1 => {
                let arg = resolve_use(func, args[0]);
                if arg == fp {
                    prologue_set = Some(id);
                }
            }
            Expr::Binary {
                op: BinaryOp::Add,
                lhs,
                rhs,
            } if resolve_use(func, *lhs) == fp && trace_int(func, *rhs) == Some(size) => {
                epilogue_add = Some(id);
            }
            _ => {}
        }
    }
    let (prologue_set, epilogue_add) = (prologue_set?, epilogue_add?);

    // The restore must be consumed by exactly one `global.set`.
    let epilogue_set = func.bindings.iter().find_map(|(id, binding)| {
        matches!(
            &binding.expr,
            Expr::Unknown { op_kind: WasmOpcodeKind::GlobalSet, args, .. }
                if args.len() == 1 && resolve_use(func, args[0]) == epilogue_add
        )
        .then_some(id)
    })?;
    if uses.get(&epilogue_add).copied().unwrap_or(0) != 1 {
        return None;
    }

    // The gate: the frame pointer is read only by the bracket itself.
    if uses.get(&fp).copied().unwrap_or(0) != 2 {
        return None;
    }

    Some(Frame {
        bindings: vec![sp, fp, prologue_set, epilogue_add, epilogue_set],
        size,
    })
}

/// How many times each value is read by the code the backend emits: the
/// operands of every *scheduled* binding plus the region's structural
/// reads. This is deliberately the same accounting
/// `sordec-backend`'s `Liveness` performs, so "unread" here means exactly
/// "unread in the generated Rust" — counting unscheduled de-cluttering
/// residue would make every frame look live and elide nothing.
///
/// Scheduled bindings nothing live reads are residue too
/// ([`crate::dataflow::dead_residue`]): the emitter drops them, so their
/// operands are not reads either. An elided struct unpack leaves a chain of
/// them addressing the frame it no longer uses.
fn read_counts(func: &HighFunction) -> HashMap<ValueId, u32> {
    let mut uses: HashMap<ValueId, u32> = HashMap::new();
    let order = crate::marshalling::sret::emission_order(func);
    let dead = crate::dataflow::dead_residue(func, &order);
    for id in order {
        if dead.contains(&id) {
            continue;
        }
        if let Some(binding) = func.bindings.get(id) {
            binding
                .expr
                .for_each_value_use(|u| *uses.entry(resolve_use(func, u)).or_default() += 1);
        }
    }
    func.region
        .for_each_value_use(|u| *uses.entry(resolve_use(func, u)).or_default() += 1);
    uses
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, load, module, v};
    use sordec_common::{BlockId, IrId, Provenance, ProvenanceSource, UnknownReason};

    fn global_set(value: ValueId) -> Expr {
        Expr::Unknown {
            op_kind: WasmOpcodeKind::GlobalSet,
            args: vec![value],
            reason: sordec_common::UnknownReason::UnsupportedPattern,
        }
    }

    /// The bracket alone: nothing reads the frame pointer.
    fn bare_frame() -> HighFunction {
        func_with(
            vec![
                Expr::GlobalGet { index: 0 },                            // v0 sp
                Expr::Literal(Literal::I32(16)),                         // v1 size
                Expr::Binary { op: BinaryOp::Sub, lhs: v(0), rhs: v(1) }, // v2 fp
                global_set(v(2)),                                        // v3
                Expr::Literal(Literal::I32(16)),                         // v4
                Expr::Binary { op: BinaryOp::Add, lhs: v(2), rhs: v(4) }, // v5
                global_set(v(5)),                                        // v6
            ],
            vec![],
            vec![0, 1, 2, 3, 4, 5, 6],
        )
    }

    #[test]
    fn an_unused_balanced_frame_is_elided() {
        let func = bare_frame();
        let frame = find_unused_frame(&func).expect("a bare bracket is elidable");
        assert_eq!(frame.size, 16);
        assert_eq!(frame.bindings, vec![v(0), v(2), v(3), v(5), v(6)]);
    }

    #[test]
    fn a_frame_with_a_live_reader_is_left_alone() {
        // A function with genuinely stack-allocated data still loads
        // through `fp`; deleting its frame would break it.
        let mut func = bare_frame();
        let id = func.bindings.push(sordec_ir::Binding::new(
            v(7),
            IrType::Unknown(UnknownReason::InsufficientEvidence),
            load(v(2), 0),
            Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
        ));
        func.blocks
            .get_mut(BlockId::from_index(0))
            .unwrap()
            .bindings
            .push(id);
        assert!(
            find_unused_frame(&func).is_none(),
            "a live frame reader must block elision"
        );
    }

    #[test]
    fn an_unbalanced_frame_is_left_alone() {
        // Restores 32 against a 16-byte reservation — not a shape we model.
        let mut func = bare_frame();
        func.bindings.get_mut(v(4)).unwrap().expr = Expr::Literal(Literal::I32(32));
        assert!(
            find_unused_frame(&func).is_none(),
            "an unbalanced bracket must not be touched"
        );
    }

    #[test]
    fn a_function_without_a_frame_is_untouched() {
        let func = func_with(vec![Expr::Literal(Literal::I32(1))], vec![], vec![0]);
        assert!(find_unused_frame(&func).is_none());
    }

    #[test]
    fn second_run_reports_no_work() {
        let mut ir = module(vec![bare_frame()]);
        assert!(FrameElisionPass.run(&mut ir).changed);
        assert!(
            !FrameElisionPass.run(&mut ir).changed,
            "idempotent: the bracket is gone"
        );
    }
}
