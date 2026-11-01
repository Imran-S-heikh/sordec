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
//!
//! ## A function that never returns has no epilogue
//!
//! `panic!` after setting up a frame (an event published, then a failure)
//! leaves a prologue with no restore anywhere: rustc emits none, because no
//! path reaches a return. The prologue alone is then the whole bracket.
//!
//! ### Why it is exact
//!
//! The stack pointer is the module's own bookkeeping, observed only by
//! code of this instance that reads the global. With `fp` unread, the
//! function itself stores nothing in its frame; a callee (or an inlined
//! bracket) that reads the pointer places its own frame from it, and
//! placing it `size` bytes higher only overlaps those unused bytes — the
//! same argument that removes a balanced bracket. The one observer the
//! balanced case needs the epilogue for is whoever runs after this
//! function returns, and here nothing does: every path ends in a trap,
//! which ends the contract invocation and rolls back everything it did,
//! the instance's globals included. So the prologue's write is never
//! read by anything the source can see.
//!
//! ### Gates
//!
//! - `fp = global.get - size`, the global read feeding only that.
//! - No `global.set` of an `fp + size` anywhere, and the prologue's
//!   `global.set fp` the function's only `global.set`.
//! - `fp` read by nothing live but that `global.set`.
//! - The function never returns: no `return` anywhere in its region tree,
//!   and control cannot fall out of its root (the implicit return of a
//!   unit function).

use std::collections::HashMap;

use sordec_common::ValueId;
use sordec_ir::{
    BinaryOp, Expr, HighFunction, HighIr, IrType, KnownType, Literal, Region, WasmOpcodeKind,
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
                    note: if frame.never_restored {
                        format!(
                            "shadow-stack bookkeeping ({}-byte frame, no remaining reads, never restored: every path traps)",
                            frame.size
                        )
                    } else {
                        format!("shadow-stack bookkeeping ({}-byte frame, no remaining reads)", frame.size)
                    },
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
    /// No epilogue exists: the function never returns, so its bracket has
    /// only the prologue.
    never_restored: bool,
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

    // The two `global.set`s, and the epilogue's restore arithmetic: an
    // `fp + size` a `global.set` restores. Only that one — the body may
    // compute the same address for its own use (the end of an array that
    // ends the frame), and that one is a read like any other.
    let restores = |v: ValueId| {
        matches!(
            func.bindings.get(v).map(|b| &b.expr),
            Some(Expr::Binary { op: BinaryOp::Add, lhs, rhs })
                if resolve_use(func, *lhs) == fp && trace_int(func, *rhs) == Some(size)
        )
    };
    let mut prologue_set = None;
    let mut epilogue_add = None;
    let mut global_sets = 0usize;
    for (id, binding) in func.bindings.iter() {
        if let Expr::Unknown {
            op_kind: WasmOpcodeKind::GlobalSet,
            args,
            ..
        } = &binding.expr
        {
            global_sets += 1;
            if args.len() != 1 {
                continue;
            }
            let arg = resolve_use(func, args[0]);
            if arg == fp {
                prologue_set = Some(id);
            } else if restores(arg) {
                epilogue_add = Some(arg);
            }
        }
    }
    let prologue_set = prologue_set?;

    // No restore anywhere: the bracket is dead only when the function
    // can never return (see the module docs), the prologue's `global.set`
    // is the function's only one, and nothing but that set reads `fp`.
    let Some(epilogue_add) = epilogue_add else {
        if global_sets != 1 || uses.get(&fp).copied().unwrap_or(0) != 1 || !never_returns(&func.region) {
            return None;
        }
        return Some(Frame {
            bindings: vec![sp, fp, prologue_set],
            size,
            never_restored: true,
        });
    };

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
        never_restored: false,
    })
}

/// Whether every path through `region` ends in a trap: no `return` anywhere
/// in it, and control cannot fall out of its bottom (which, at a
/// function's root, is the implicit return of a unit function).
fn never_returns(region: &Region) -> bool {
    let mut returns = false;
    region.for_each_node(|n| returns |= matches!(n, Region::Return { .. }));
    !returns && !super::enum_match::falls_through(region)
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

    /// The body computing `fp + size` for itself — the end of an array
    /// that ends the frame — and reading it nowhere: the epilogue is the
    /// add a `global.set` restores, not that one.
    #[test]
    fn an_unread_end_of_frame_address_is_not_the_epilogue() {
        let mut func = bare_frame();
        let id = func.bindings.push(sordec_ir::Binding::new(
            v(7),
            IrType::Unknown(UnknownReason::InsufficientEvidence),
            Expr::Binary { op: BinaryOp::Add, lhs: v(2), rhs: v(4) },
            Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
        ));
        func.blocks.get_mut(BlockId::from_index(0)).unwrap().bindings.insert(4, id);
        let frame = find_unused_frame(&func).expect("the bracket is still bare");
        assert_eq!(frame.bindings, vec![v(0), v(2), v(3), v(5), v(6)]);
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

    /// A prologue and no restore: `fp = sp - 16; global.set fp`, then the
    /// body `region`.
    fn prologue_only(region: Region) -> HighFunction {
        let mut func = func_with(
            vec![
                Expr::GlobalGet { index: 0 },                            // v0 sp
                Expr::Literal(Literal::I32(16)),                         // v1 size
                Expr::Binary { op: BinaryOp::Sub, lhs: v(0), rhs: v(1) }, // v2 fp
                global_set(v(2)),                                        // v3
            ],
            vec![],
            vec![0, 1, 2, 3],
        );
        func.region = region;
        func
    }

    fn panics_after_block() -> Region {
        Region::Sequence(vec![
            Region::Basic(BlockId::from_index(0)),
            Region::Panic { kind: sordec_ir::PanicKind::Bare },
        ])
    }

    #[test]
    fn a_prologue_on_a_body_that_always_traps_is_elided() {
        let func = prologue_only(panics_after_block());
        let frame = find_unused_frame(&func).expect("nothing after the prologue returns");
        assert_eq!(frame.bindings, vec![v(0), v(2), v(3)]);
        assert!(frame.never_restored);
    }

    #[test]
    fn a_prologue_without_a_restore_on_a_body_that_returns_is_left_alone() {
        // Falling off the end of a unit function returns.
        let func = prologue_only(Region::Basic(BlockId::from_index(0)));
        assert!(find_unused_frame(&func).is_none());
        // So does an explicit return on one path.
        let func = prologue_only(Region::Sequence(vec![
            Region::Basic(BlockId::from_index(0)),
            Region::If {
                cond: v(1),
                then_region: Box::new(Region::Return { values: vec![] }),
                else_region: None,
            },
            Region::Panic { kind: sordec_ir::PanicKind::Bare },
        ]));
        assert!(find_unused_frame(&func).is_none());
    }

    #[test]
    fn a_trapping_prologue_whose_pointer_is_read_or_set_again_is_left_alone() {
        // `fp` read by the body.
        let mut func = prologue_only(panics_after_block());
        let id = func.bindings.push(sordec_ir::Binding::new(
            v(4),
            IrType::Unknown(UnknownReason::InsufficientEvidence),
            load(v(2), 0),
            Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
        ));
        func.blocks.get_mut(BlockId::from_index(0)).unwrap().bindings.push(id);
        assert!(find_unused_frame(&func).is_none());

        // A second `global.set` the bracket does not explain.
        let mut func = prologue_only(panics_after_block());
        let id = func.bindings.push(sordec_ir::Binding::new(
            v(4),
            IrType::Unknown(UnknownReason::InsufficientEvidence),
            global_set(v(1)),
            Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
        ));
        func.blocks.get_mut(BlockId::from_index(0)).unwrap().bindings.push(id);
        assert!(find_unused_frame(&func).is_none());
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
