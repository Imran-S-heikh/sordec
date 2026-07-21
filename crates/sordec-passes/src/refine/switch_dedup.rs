//! Switch arm/default dedup (D5).
//!
//! rustc lowers a `match` with a `_` arm into a `br_table` whose
//! default slot names the same target as one of the case slots (the
//! corpus shape: token and dex both emit `0 => { break 'bbN }` next to
//! `_ => { break 'bbN }`). The structurer already groups *case* slots
//! sharing a target into one multi-case arm, but the default is built
//! separately and never folded. This pass deletes every arm whose body
//! is structurally equal to the default's — the cases fall through to
//! `_`, restoring the source's single wildcard arm.
//!
//! Arm-vs-arm merging is deliberately absent: the structurer's
//! `(block, args)` slot grouping already collapses same-target cases,
//! and two *different* targets can only produce equal regions as equal
//! `Break`/`Transfer` leaves — which the same grouping already caught.
//!
//! Deleting an arm never orphans a block: an arm body equal to the
//! default cannot contain a [`Region::Basic`] (each block appears in
//! the tree exactly once — two copies would already violate the
//! validator's no-duplicate-`Basic` rule), so equal bodies are always
//! `Break`/`Transfer`-shaped leaves. The `Switch` node itself is never
//! removed — the skeleton cross-check counts one per original
//! `br_table`.

use sordec_ir::{HighIr, Region};

use super::debug_validate;
use crate::pass::{Pass, PassResult};

/// Unique pipeline name of this pass.
pub const PASS_NAME: &str = "refine-switch-dedup";

/// Metric counter key: arms folded into the default.
const M_DEDUPED: &str = "refine_switch_arms_deduped";

/// The switch-dedup pass. Stateless; see the module docs.
#[derive(Debug, Default, Clone, Copy)]
pub struct SwitchDedupPass;

impl Pass<HighIr> for SwitchDedupPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let mut deduped = 0i64;
        for func in &mut ir.functions {
            dedup(&mut func.region, &mut deduped);
        }
        if deduped > 0 {
            result.metrics.increment(M_DEDUPED, deduped);
            result.changed = true;
        }
        debug_validate(ir, PASS_NAME);
        result
    }
}

/// Recurse the region tree, folding default-equal arms on every switch.
/// Exhaustive on purpose — a new `Region` variant must decide its
/// children here.
fn dedup(region: &mut Region, deduped: &mut i64) {
    match region {
        Region::Sequence(items) => {
            for item in items {
                dedup(item, deduped);
            }
        }
        Region::Scope { body, .. } | Region::Loop { body, .. } => dedup(body, deduped),
        Region::If {
            then_region,
            else_region,
            ..
        } => {
            dedup(then_region, deduped);
            if let Some(else_region) = else_region {
                dedup(else_region, deduped);
            }
        }
        Region::Switch {
            arms, default, ..
        } => {
            for arm in arms.iter_mut() {
                dedup(&mut arm.body, deduped);
            }
            dedup(default, deduped);
            let before = arms.len();
            arms.retain(|arm| arm.body != **default);
            *deduped += (before - arms.len()) as i64;
        }
        Region::Basic(_)
        | Region::Break { .. }
        | Region::Continue { .. }
        | Region::Transfer { .. }
        | Region::Return { .. }
        | Region::Unreachable
        | Region::Panic { .. }
        | Region::Unstructured { .. } => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{
        Arena, BlockId, FuncId, IrId, Provenance, ProvenanceSource, UnknownReason, ValueId,
    };
    use sordec_ir::{
        Binding, Expr, HighBlock, HighFunction, IrType, Literal, MemoryImage, SwitchArm,
        WasmFacts,
    };

    fn v(i: u32) -> ValueId {
        ValueId::from_index(i)
    }
    fn bb(i: u32) -> BlockId {
        BlockId::from_index(i)
    }
    fn brk(target: u32) -> Region {
        Region::Break {
            target: bb(target),
            transfer: vec![],
        }
    }
    fn arm(cases: Vec<u32>, body: Region) -> SwitchArm {
        SwitchArm { cases, body }
    }

    /// One function scheduling `v0` (the selector) in block 0, with the
    /// given switch nested in the token-shaped `Scope` + tail.
    fn func_with_switch(arms: Vec<SwitchArm>, default: Region) -> HighFunction {
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        bindings.push(Binding::new(
            v(0),
            IrType::Unknown(UnknownReason::UpstreamUnknown),
            Expr::Literal(Literal::I32(0)),
            Provenance::new("test", ProvenanceSource::DataFlow, ""),
        ));
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        blocks.push(HighBlock {
            id: bb(0),
            bindings: vec![v(0)],
        });
        blocks.push(HighBlock {
            id: bb(1),
            bindings: vec![],
        });
        HighFunction {
            id: FuncId::from_index(0),
            name: None,
            signature: None,
            blocks,
            bindings,
            region: Region::Sequence(vec![
                Region::Scope {
                    out: bb(1),
                    body: Box::new(Region::Sequence(vec![
                        Region::Basic(bb(0)),
                        Region::Switch {
                            index: v(0),
                            arms,
                            default: Box::new(default),
                            dispatch: None,
                        },
                    ])),
                },
                Region::Basic(bb(1)),
                Region::Return { values: vec![] },
            ]),
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
                function_bodies: vec![],
                custom_sections: vec![],
            },
            soroban_facts: None,
            functions: vec![func],
            memory: MemoryImage::empty(),
        };
        let result = SwitchDedupPass.run(&mut ir);
        (ir.functions.pop().expect("one function"), result)
    }

    fn switch_arms(func: &HighFunction) -> &Vec<SwitchArm> {
        let Region::Sequence(items) = &func.region else {
            panic!("root is a sequence");
        };
        let Region::Scope { body, .. } = &items[0] else {
            panic!("first item is the scope");
        };
        let Region::Sequence(body_items) = &**body else {
            panic!("scope body is a sequence");
        };
        let Region::Switch { arms, .. } = &body_items[1] else {
            panic!("second item is the switch");
        };
        arms
    }

    #[test]
    fn default_equal_arm_folds_into_the_wildcard() {
        // The token/dex shape: `0 => { break 'bb1 }` next to
        // `_ => { break 'bb1 }`.
        let (func, result) = run_pass(func_with_switch(
            vec![
                arm(vec![0], brk(1)),
                arm(vec![1], Region::Return { values: vec![] }),
            ],
            brk(1),
        ));
        assert!(result.changed);
        assert_eq!(result.metrics.get(M_DEDUPED), Some(1));
        let arms = switch_arms(&func);
        assert_eq!(arms.len(), 1);
        assert_eq!(arms[0].cases, vec![1], "the distinct arm survives");
    }

    #[test]
    fn distinct_arms_are_kept() {
        let (func, result) = run_pass(func_with_switch(
            vec![
                arm(vec![0], Region::Return { values: vec![] }),
                arm(vec![1], Region::Unreachable),
            ],
            brk(1),
        ));
        assert!(!result.changed);
        assert_eq!(switch_arms(&func).len(), 2);
    }

    #[test]
    fn value_carrying_break_only_folds_on_equal_transfer() {
        // Same target, different phi transfer: NOT equal, kept.
        let carrying = Region::Break {
            target: bb(1),
            transfer: vec![(v(1), v(0))],
        };
        let mut func = func_with_switch(vec![arm(vec![0], carrying)], brk(1));
        func.bindings.push(Binding::new(
            v(1),
            IrType::Unknown(UnknownReason::UpstreamUnknown),
            Expr::Phi { incoming: vec![] },
            Provenance::new("test", ProvenanceSource::DataFlow, ""),
        ));
        let (func, result) = run_pass(func);
        assert!(!result.changed);
        assert_eq!(switch_arms(&func).len(), 1);
    }

    #[test]
    fn second_run_is_idempotent() {
        let (func, first) = run_pass(func_with_switch(
            vec![
                arm(vec![0], brk(1)),
                arm(vec![1], Region::Return { values: vec![] }),
            ],
            brk(1),
        ));
        assert!(first.changed);
        let (_, second) = run_pass(func);
        assert!(!second.changed, "nothing left equal to the default");
    }
}
