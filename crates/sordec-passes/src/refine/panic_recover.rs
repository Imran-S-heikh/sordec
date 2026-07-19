//! Bare-`panic!` / unwrap recognition (D8, Phase-2 C16/C17).
//!
//! rustc under `panic=abort` compiles every `panic!()`, failed
//! `.unwrap()`, and arithmetic-overflow check down to a guard branching
//! to a WASM `unreachable` (possibly behind panic-glue helper calls) —
//! the structurer and wave-1 refiners shape those into else-less
//! `if cond { … unreachable }` guards and hoisted-guard fallthrough
//! tails. This pass types the trap leaves as [`Region::Panic`] so the
//! renderer and the Phase-4 emitter can say `panic!()` where the source
//! panicked, instead of the anonymous `unreachable`:
//!
//! - **Guarded trap**: an `If` arm ending in [`Region::Unreachable`] —
//!   the else-less guard (D1's canonical output) or either arm of the
//!   D4-asymmetry residue whose condition would not flip. The leaf
//!   becomes `Panic` and the guard condition classifies it: a `Val` tag
//!   test ([`KnownOp::ValTagCheck`] or a raw `(x & 0xFF) ==/!= tag`
//!   comparison) marks an [`PanicKind::Unwrap`]; anything else a
//!   [`PanicKind::Bare`].
//! - **Fallthrough trap**: a sequence tail `[…, Unreachable]` with at
//!   least one preceding item — the hoisted-guard residue (`if ok {
//!   return }; unreachable`) and the panic-glue wrapper bodies
//!   (`call func_N; unreachable`). Always [`PanicKind::Bare`] — the
//!   guard, if any, tested the success path.
//!
//! A single-node `Unreachable` body (the terminal abort helper itself)
//! stays untyped — there is no evidence it is anything but the trap.
//! Trap paths whose blocks carry a [`KnownOp::PanicWithError`] binding
//! are skipped entirely: the host-call recognizer already typed those,
//! and the structured error code is visible at the call site.
//!
//! Every `Bare` conversion emits the [`PanicWithoutErrorCode`]
//! diagnostic (defined since Phase 2, first wired here). The pass
//! rewrites leaves only — conditions and bindings are untouched, so
//! renderer condition folding is unaffected.
//!
//! [`PanicWithoutErrorCode`]: LiftDiagnosticCode::PanicWithoutErrorCode

use sordec_common::{
    Diagnostic, FuncId, IrId, LiftDiagnosticCode, Location, ValueId,
};
use sordec_ir::{
    BinaryOp, Expr, HighFunction, HighIr, KnownOp, Literal, PanicKind, Region, SemanticOp,
};

use super::debug_validate;
use crate::pass::{Pass, PassResult};

/// Unique pipeline name of this pass.
pub const PASS_NAME: &str = "refine-panic-recover";

// Metric counter keys.
/// Trap leaves typed as bare `panic!()` sites.
const M_BARE: &str = "refine_bare_panics";
/// Trap leaves typed as unwrap-shaped (tag-checked) panics.
const M_UNWRAP: &str = "refine_unwraps";

/// The `Val` tag mask — a cond comparing `x & 0xFF` against a constant
/// is the SDK's small-vs-object tag dispatch, i.e. an unwrap shape.
const VAL_TAG_MASK: i64 = 0xFF;

/// The panic-recovery pass. Stateless; see the module docs.
#[derive(Debug, Default, Clone, Copy)]
pub struct PanicRecoverPass;

impl Pass<HighIr> for PanicRecoverPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let mut stats = Stats::default();
        for func in &mut ir.functions {
            let region = std::mem::replace(&mut func.region, Region::Unreachable);
            let func_id = func.id;
            func.region = recover(region, func, func_id, &mut stats, &mut result);
        }
        if stats.bare > 0 {
            result.metrics.increment(M_BARE, stats.bare);
            result.changed = true;
        }
        if stats.unwraps > 0 {
            result.metrics.increment(M_UNWRAP, stats.unwraps);
            result.changed = true;
        }
        debug_validate(ir, PASS_NAME);
        result
    }
}

#[derive(Default)]
struct Stats {
    bare: i64,
    unwraps: i64,
}

/// Bottom-up rewrite: children first, then this node's own trap shapes.
fn recover(
    region: Region,
    func: &HighFunction,
    func_id: FuncId,
    stats: &mut Stats,
    result: &mut PassResult,
) -> Region {
    match region {
        Region::Sequence(items) => {
            let mut items: Vec<Region> = items
                .into_iter()
                .map(|item| recover(item, func, func_id, stats, result))
                .collect();
            // Fallthrough trap: `[…, Unreachable]` with a preceding
            // item. (A whole-body bare `Unreachable` never forms a
            // one-item Sequence — `seq` unwraps singletons — so the
            // preceding-item evidence is structural.)
            let tail_is_trap = items.len() >= 2
                && matches!(items.last(), Some(Region::Unreachable))
                && !panics_with_error(&items[..items.len() - 1], func);
            if tail_is_trap {
                *items.last_mut().expect("checked non-empty") =
                    typed_panic(PanicKind::Bare, None, func_id, stats, result);
            }
            Region::Sequence(items)
        }
        Region::Scope { out, body } => Region::Scope {
            out,
            body: Box::new(recover(*body, func, func_id, stats, result)),
        },
        Region::Loop { header, body, kind } => Region::Loop {
            header,
            body: Box::new(recover(*body, func, func_id, stats, result)),
            kind,
        },
        Region::If {
            cond,
            then_region,
            else_region,
        } => {
            let mut then_region = recover(*then_region, func, func_id, stats, result);
            let mut else_region =
                else_region.map(|e| Box::new(recover(*e, func, func_id, stats, result)));
            // Guarded trap, either arm: the else-less guard is D1's
            // canonical output; a trap still sitting in a two-armed
            // `if` (either side) is the D4-asymmetry residue where the
            // condition would not flip. Tag evidence on the condition
            // classifies both — `Eq`/`Ne` both count, so the negated
            // reading is covered.
            retype_trailing_trap(&mut then_region, cond, func, func_id, stats, result);
            if let Some(else_region) = &mut else_region {
                retype_trailing_trap(else_region, cond, func, func_id, stats, result);
            }
            Region::If {
                cond,
                then_region: Box::new(then_region),
                else_region,
            }
        }
        Region::Switch {
            index,
            arms,
            default,
            dispatch,
        } => Region::Switch {
            index,
            arms: arms
                .into_iter()
                .map(|mut arm| {
                    arm.body = recover(arm.body, func, func_id, stats, result);
                    arm
                })
                .collect(),
            default: Box::new(recover(*default, func, func_id, stats, result)),
            dispatch,
        },
        leaf @ (Region::Basic(_)
        | Region::Break { .. }
        | Region::Continue { .. }
        | Region::Transfer { .. }
        | Region::Return { .. }
        | Region::Unreachable
        | Region::Panic { .. }
        | Region::Unstructured { .. }) => leaf,
    }
}

/// Retype the trailing `Unreachable` of an else-less guard's `then`
/// region (either the leaf itself or a sequence ending in one),
/// classified by the guard condition. Skips trap paths already typed by
/// the `PanicWithError` host-call recognizer.
fn retype_trailing_trap(
    then_region: &mut Region,
    cond: ValueId,
    func: &HighFunction,
    func_id: FuncId,
    stats: &mut Stats,
    result: &mut PassResult,
) {
    let trap: &mut Region = match then_region {
        Region::Unreachable => then_region,
        Region::Sequence(items) => {
            if !matches!(items.last(), Some(Region::Unreachable))
                || panics_with_error(&items[..items.len() - 1], func)
            {
                return;
            }
            items.last_mut().expect("checked non-empty")
        }
        _ => return,
    };
    let kind = classify(cond, func);
    *trap = typed_panic(kind, Some(cond), func_id, stats, result);
}

/// Build the typed leaf, bump the counters, and emit the
/// `PanicWithoutErrorCode` diagnostic for bare sites.
fn typed_panic(
    kind: PanicKind,
    cond: Option<ValueId>,
    func_id: FuncId,
    stats: &mut Stats,
    result: &mut PassResult,
) -> Region {
    match kind {
        PanicKind::Bare => {
            stats.bare += 1;
            let location = match cond {
                Some(cond) => Location::Value {
                    func: func_id,
                    value: cond.index(),
                },
                None => Location::Function(func_id),
            };
            // Info, not warning: a typed bare panic is a successfully
            // recovered fact about the source (it used `panic!()`, not
            // `panic_with_error`), not a recovery miss.
            result.diagnostics.push(
                Diagnostic::info(LiftDiagnosticCode::PanicWithoutErrorCode, "").at(location),
            );
        }
        PanicKind::Unwrap => stats.unwraps += 1,
    }
    Region::Panic { kind }
}

/// Classify a guard condition: `Val` tag evidence marks the trap as an
/// unwrap; anything else is a bare panic.
fn classify(cond: ValueId, func: &HighFunction) -> PanicKind {
    let Some(binding) = func.bindings.get(cond) else {
        return PanicKind::Bare;
    };
    match &binding.expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck { .. })) => PanicKind::Unwrap,
        // The raw shape the tag-check recognizer leaves on i64-typed
        // paths: `(x & 0xFF) ==/!= tag`.
        Expr::Binary {
            op: BinaryOp::Eq | BinaryOp::Ne,
            lhs,
            rhs,
        } if is_tag_mask(func, *lhs) || is_tag_mask(func, *rhs) => PanicKind::Unwrap,
        _ => PanicKind::Bare,
    }
}

/// Is `value` an `x & 0xFF` masking of the `Val` tag byte?
fn is_tag_mask(func: &HighFunction, value: ValueId) -> bool {
    let Some(binding) = func.bindings.get(value) else {
        return false;
    };
    let Expr::Binary {
        op: BinaryOp::BitAnd,
        lhs,
        rhs,
    } = &binding.expr
    else {
        return false;
    };
    [lhs, rhs].into_iter().any(|&operand| {
        func.bindings.get(operand).is_some_and(|b| {
            matches!(
                b.expr,
                Expr::Literal(Literal::I64(VAL_TAG_MASK) | Literal::I32(0xFF))
            )
        })
    })
}

/// Does any `Basic` block in `items` schedule a `PanicWithError`
/// binding? Those trap paths are already typed at the host-call level.
fn panics_with_error(items: &[Region], func: &HighFunction) -> bool {
    let mut found = false;
    for item in items {
        item.for_each_node(|node| {
            if let Region::Basic(b) = node
                && !found
                && let Some(block) = func.blocks.get(*b)
            {
                found = block.bindings.iter().any(|&v| {
                    func.bindings.get(v).is_some_and(|binding| {
                        matches!(
                            binding.expr,
                            Expr::Semantic(SemanticOp::Known(KnownOp::PanicWithError { .. }))
                        )
                    })
                });
            }
        });
        if found {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{
        Arena, BlockId, IrId, Provenance, ProvenanceSource, UnknownReason,
    };
    use sordec_ir::{Binding, HighBlock, IrType, MemoryImage, WasmFacts, WasmOpcodeKind};

    fn v(i: u32) -> ValueId {
        ValueId::from_index(i)
    }
    fn bb(i: u32) -> BlockId {
        BlockId::from_index(i)
    }
    fn binding(id: u32, expr: Expr) -> Binding {
        Binding::new(
            v(id),
            IrType::Unknown(UnknownReason::UpstreamUnknown),
            expr,
            Provenance::new("test", ProvenanceSource::DataFlow, ""),
        )
    }

    /// One function: block 0 schedules `bindings`, region as given.
    fn func_of(bindings: Vec<Binding>, region: Region) -> HighFunction {
        let scheduled = bindings.iter().map(|b| b.id).collect();
        let mut arena: Arena<ValueId, Binding> = Arena::new();
        for b in bindings {
            arena.push(b);
        }
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        blocks.push(HighBlock {
            id: bb(0),
            bindings: scheduled,
        });
        HighFunction {
            id: FuncId::from_index(0),
            name: None,
            signature: None,
            blocks,
            bindings: arena,
            region,
            params: vec![],
            returns: vec![],
        }
    }

    fn run_pass(func: HighFunction) -> (HighFunction, PassResult) {
        let mut ir = HighIr {
            facts: WasmFacts {
                imports: vec![],
                exports: vec![],
                function_type_indices: vec![],
                custom_sections: vec![],
            },
            soroban_facts: None,
            functions: vec![func],
            memory: MemoryImage::empty(),
        };
        let result = PanicRecoverPass.run(&mut ir);
        (ir.functions.pop().expect("one function"), result)
    }

    fn guard(cond: u32, then: Region) -> Region {
        Region::If {
            cond: v(cond),
            then_region: Box::new(then),
            else_region: None,
        }
    }

    /// `v0 = load-ish unknown; v1 = v0 & 255; v2 = v1 != 77` — the
    /// muxed-address tag guard shape.
    fn tag_guard_bindings() -> Vec<Binding> {
        vec![
            binding(
                0,
                Expr::Unknown {
                    op_kind: WasmOpcodeKind::Load,
                    args: vec![],
                    reason: UnknownReason::UpstreamUnknown,
                },
            ),
            binding(1, Expr::Literal(Literal::I64(255))),
            binding(
                2,
                Expr::Binary {
                    op: BinaryOp::BitAnd,
                    lhs: v(0),
                    rhs: v(1),
                },
            ),
            binding(3, Expr::Literal(Literal::I64(77))),
            binding(
                4,
                Expr::Binary {
                    op: BinaryOp::Ne,
                    lhs: v(2),
                    rhs: v(3),
                },
            ),
        ]
    }

    #[test]
    fn tag_checked_guard_types_an_unwrap() {
        let func = func_of(
            tag_guard_bindings(),
            Region::Sequence(vec![
                Region::Basic(bb(0)),
                guard(4, Region::Unreachable),
                Region::Return { values: vec![] },
            ]),
        );
        let (func, result) = run_pass(func);
        assert!(result.changed);
        assert_eq!(result.metrics.get(M_UNWRAP), Some(1));
        assert_eq!(result.metrics.get(M_BARE), None);
        assert!(result.diagnostics.is_empty(), "unwraps carry no diagnostic");
        let Region::Sequence(items) = &func.region else {
            panic!("root stays a sequence");
        };
        assert_eq!(
            items[1],
            guard(
                4,
                Region::Panic {
                    kind: PanicKind::Unwrap
                }
            )
        );
    }

    #[test]
    fn plain_guard_types_a_bare_panic_and_diagnoses() {
        // `if v1 { unreachable }` on a non-tag condition (a load).
        let func = func_of(
            vec![
                binding(0, Expr::Literal(Literal::I32(1))),
                binding(
                    1,
                    Expr::Binary {
                        op: BinaryOp::Eq,
                        lhs: v(0),
                        rhs: v(0),
                    },
                ),
            ],
            Region::Sequence(vec![
                Region::Basic(bb(0)),
                guard(1, Region::Unreachable),
                Region::Return { values: vec![] },
            ]),
        );
        let (_, result) = run_pass(func);
        assert_eq!(result.metrics.get(M_BARE), Some(1));
        assert_eq!(result.diagnostics.len(), 1);
        assert_eq!(
            result.diagnostics[0].code,
            sordec_common::DiagnosticCode::Lift(LiftDiagnosticCode::PanicWithoutErrorCode)
        );
    }

    #[test]
    fn guard_with_glue_call_keeps_the_call() {
        // dex shape: `if cond { call func_3; unreachable }` — the glue
        // call stays, only the trap leaf is typed.
        let func = func_of(
            vec![
                binding(0, Expr::Literal(Literal::I32(0))),
                binding(
                    1,
                    Expr::Binary {
                        op: BinaryOp::Eq,
                        lhs: v(0),
                        rhs: v(0),
                    },
                ),
            ],
            Region::Sequence(vec![
                Region::Basic(bb(0)),
                guard(
                    1,
                    Region::Sequence(vec![Region::Basic(bb(0)), Region::Unreachable]),
                ),
            ]),
        );
        // Second Basic(bb0) in the then-arm would be a DuplicateBasic;
        // give the trap path its own block.
        let mut func = func;
        func.blocks.push(HighBlock {
            id: bb(1),
            bindings: vec![],
        });
        let Region::Sequence(items) = &mut func.region else {
            unreachable!()
        };
        let Region::If { then_region, .. } = &mut items[1] else {
            unreachable!()
        };
        **then_region = Region::Sequence(vec![Region::Basic(bb(1)), Region::Unreachable]);

        let (func, result) = run_pass(func);
        assert_eq!(result.metrics.get(M_BARE), Some(1));
        let Region::Sequence(items) = &func.region else {
            panic!("root stays a sequence");
        };
        let Region::If { then_region, .. } = &items[1] else {
            panic!("guard survives");
        };
        assert_eq!(
            **then_region,
            Region::Sequence(vec![
                Region::Basic(bb(1)),
                Region::Panic {
                    kind: PanicKind::Bare
                }
            ])
        );
    }

    #[test]
    fn fallthrough_trap_after_hoisted_guard_types_bare() {
        // `if ok { return }; unreachable` — the hoisted-guard residue.
        let func = func_of(
            vec![
                binding(0, Expr::Literal(Literal::I32(1))),
                binding(
                    1,
                    Expr::Binary {
                        op: BinaryOp::Ne,
                        lhs: v(0),
                        rhs: v(0),
                    },
                ),
            ],
            Region::Sequence(vec![
                Region::Basic(bb(0)),
                guard(1, Region::Return { values: vec![] }),
                Region::Unreachable,
            ]),
        );
        let (func, result) = run_pass(func);
        assert_eq!(result.metrics.get(M_BARE), Some(1));
        let Region::Sequence(items) = &func.region else {
            panic!("root stays a sequence");
        };
        assert_eq!(
            *items.last().expect("tail"),
            Region::Panic {
                kind: PanicKind::Bare
            }
        );
    }

    #[test]
    fn else_arm_trap_types_too() {
        // The D4-asymmetry residue: `if c { break-ish } else
        // { unreachable }` — the condition would not flip, but the
        // else-arm trap is still a panic path.
        let func = func_of(
            tag_guard_bindings(),
            Region::Sequence(vec![
                Region::Basic(bb(0)),
                Region::If {
                    cond: v(4),
                    then_region: Box::new(Region::Return { values: vec![] }),
                    else_region: Some(Box::new(Region::Unreachable)),
                },
            ]),
        );
        let (func, result) = run_pass(func);
        assert_eq!(result.metrics.get(M_UNWRAP), Some(1));
        let Region::Sequence(items) = &func.region else {
            panic!("root stays a sequence");
        };
        let Region::If { else_region, .. } = &items[1] else {
            panic!("if survives");
        };
        assert_eq!(
            **else_region.as_ref().expect("else kept"),
            Region::Panic {
                kind: PanicKind::Unwrap
            }
        );
    }

    #[test]
    fn whole_body_bare_trap_stays_untyped() {
        // The terminal abort helper: body = a single Unreachable. No
        // evidence of a source panic — stays anonymous.
        let func = func_of(vec![], Region::Unreachable);
        let (func, result) = run_pass(func);
        assert!(!result.changed);
        assert_eq!(func.region, Region::Unreachable);
    }

    #[test]
    fn panic_with_error_path_is_left_to_the_recognizer() {
        // The trap path's block carries a PanicWithError binding — the
        // host-call recognizer already typed this panic, with its error
        // code; the region leaf stays.
        let func = func_of(
            vec![
                binding(0, Expr::Literal(Literal::I32(1))),
                binding(
                    1,
                    Expr::Semantic(SemanticOp::Known(KnownOp::PanicWithError { error: v(0) })),
                ),
            ],
            Region::Sequence(vec![Region::Basic(bb(0)), Region::Unreachable]),
        );
        let (func, result) = run_pass(func);
        assert!(!result.changed);
        let Region::Sequence(items) = &func.region else {
            panic!("root stays a sequence");
        };
        assert_eq!(*items.last().expect("tail"), Region::Unreachable);
    }

    #[test]
    fn second_run_is_idempotent() {
        let func = func_of(
            tag_guard_bindings(),
            Region::Sequence(vec![
                Region::Basic(bb(0)),
                guard(4, Region::Unreachable),
                Region::Return { values: vec![] },
            ]),
        );
        let (func, first) = run_pass(func);
        assert!(first.changed);
        let (_, second) = run_pass(func);
        assert!(!second.changed, "typed leaves never re-fire");
    }
}
