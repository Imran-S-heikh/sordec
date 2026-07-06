//! Reverse-use index: "who consumes this value?"
//!
//! The lifted IR natively stores only the backward direction — each
//! definition lists its operands (`LiftedValueDef::Operator { args }`).
//! Pattern recognizers also need the forward direction: given a
//! `ValueId`, every place that *reads* it. [`DefUseIndex`] provides
//! that map, built once per function in a single linear scan.
//!
//! ## Who needs this
//!
//! - **Auth-chain recognition (C4)**: the admin pattern
//!   `v = instance.get(Admin); require_auth(v)` may only collapse when
//!   `v` is consumed *solely* by that `require_auth` — [`DefUseIndex::sole_use`]
//!   is that check.
//! - **Val-encoding collapse (C1)**: an `obj_from_i64(x)` whose result
//!   feeds only a matching `obj_to_i64` is a round-trip no-op; proving
//!   "feeds only" requires the use set.
//! - **Allowance flow (C5)**: a comparison result feeding exactly one
//!   branch condition.
//! - **Dead-value detection**: after a pattern rewrite,
//!   [`DefUseIndex::is_unused`] identifies values that no longer matter.
//!
//! ## The snapshot rule
//!
//! **The index is a point-in-time snapshot of the function.** If a pass
//! mutates the `LiftedFunction` after building, queries return
//! pre-mutation answers. The intended usage pattern is:
//!
//! 1. `let index = DefUseIndex::build(&func);`
//! 2. Scan for patterns, collecting planned rewrites (read-only).
//! 3. Apply the rewrites.
//! 4. If another scan is needed (fixpoint iteration), **rebuild**.
//!
//! This matches how the fixpoint pipeline group drives recognizers —
//! each iteration re-runs the pass from scratch.
//!
//! ## What counts as a use
//!
//! - Operands of `Operator` defs (positionally recorded).
//! - The source of an `Alias` or `PickOutput` def.
//! - Everything a terminator reads: branch conditions, switch indices,
//!   return values, and block-target arguments.
//!
//! Block *parameters* are definitions (the SSA encoding of phi nodes),
//! never uses; the corresponding uses are the `BlockTarget::args` at
//! each predecessor's terminator.
//!
//! Defs that no block schedules still contribute their operand reads —
//! the index is conservative: anything referenced anywhere is counted.
//! Reachability analysis is a different (future) concern.

use sordec_common::{BlockId, IrId, ValueId};
use sordec_ir::{BlockTarget, LiftedFunction, LiftedTerminator, LiftedValueDef};

/// One place where a value is read.
///
/// `Terminator` deliberately carries only the block, not the role
/// (condition vs switch index vs return value vs target argument): the
/// role is fully recoverable by matching on that block's terminator,
/// which callers that care about it do anyway. Keeping the variant
/// lean avoids tripling the surface for information one `match` away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UseSite {
    /// Read as an operand of another value's definition.
    Value {
        /// The value whose definition reads it.
        user: ValueId,
        /// Zero-based operand position within the user's definition.
        /// For `Alias` and `PickOutput` (single-operand defs) this is 0.
        operand: u32,
    },
    /// Read by the terminator of a block: as a branch condition, a
    /// switch index, a return value, or a block-target argument.
    Terminator {
        /// The block whose terminator reads it.
        block: BlockId,
    },
}

/// Reverse-use map for one [`LiftedFunction`].
///
/// Build once with [`DefUseIndex::build`], query with
/// [`uses_of`](DefUseIndex::uses_of) and friends. See the module
/// documentation for the snapshot rule: the index does NOT track
/// mutations made to the function after building.
#[derive(Debug, Clone)]
pub struct DefUseIndex {
    /// `uses[i]` = all use sites of `ValueId(i)`, in deterministic
    /// order: value-def uses first (arena order, operands positional),
    /// then terminator uses (block arena order).
    ///
    /// Dense `Vec` rather than a map because `ValueId`s are dense
    /// arena indices. A CSR layout (flat vec + offsets) is the known
    /// optimization if profiling ever flags allocator pressure here.
    uses: Vec<Vec<UseSite>>,
}

impl DefUseIndex {
    /// Build the index for one function.
    ///
    /// Cost: one linear scan over all value definitions plus all block
    /// terminators — O(values + terminator operands).
    ///
    /// Defensive behaviour: an operand that references a `ValueId`
    /// outside the function's arena (malformed IR — the validator's
    /// job to flag, not ours) is silently skipped rather than
    /// panicking or growing the index.
    #[must_use]
    pub fn build(func: &LiftedFunction) -> Self {
        let mut uses: Vec<Vec<UseSite>> = vec![Vec::new(); func.values.len()];

        // Pass 1: operand reads from value definitions, in arena
        // order. Exhaustive match — a future `LiftedValueDef` variant
        // must be classified here or the build breaks (deliberately).
        for (user, value) in func.values.iter() {
            match &value.def {
                LiftedValueDef::Operator { args, .. } => {
                    for (pos, arg) in args.iter().enumerate() {
                        record(
                            &mut uses,
                            *arg,
                            UseSite::Value {
                                user,
                                operand: pos as u32,
                            },
                        );
                    }
                }
                LiftedValueDef::Alias(target) => {
                    record(&mut uses, *target, UseSite::Value { user, operand: 0 });
                }
                LiftedValueDef::PickOutput { from, .. } => {
                    record(&mut uses, *from, UseSite::Value { user, operand: 0 });
                }
                // A block parameter is a definition (SSA phi), not a use.
                LiftedValueDef::BlockParam { .. } => {}
            }
        }

        // Pass 2: terminator reads, in block arena order. Same
        // exhaustive-match rule as above.
        for (block, b) in func.blocks.iter() {
            let site = UseSite::Terminator { block };
            match &b.terminator {
                LiftedTerminator::Branch(target) => {
                    record_target(&mut uses, target, site);
                }
                LiftedTerminator::BranchIf {
                    cond,
                    if_true,
                    if_false,
                } => {
                    record(&mut uses, *cond, site);
                    record_target(&mut uses, if_true, site);
                    record_target(&mut uses, if_false, site);
                }
                LiftedTerminator::Switch {
                    index,
                    targets,
                    default,
                } => {
                    record(&mut uses, *index, site);
                    for target in targets {
                        record_target(&mut uses, target, site);
                    }
                    record_target(&mut uses, default, site);
                }
                LiftedTerminator::Return { values } => {
                    for value in values {
                        record(&mut uses, *value, site);
                    }
                }
                LiftedTerminator::Unreachable => {}
            }
        }

        Self { uses }
    }

    /// All use sites of `value`, in the deterministic order documented
    /// on [`DefUseIndex`]. Returns an empty slice for a `ValueId`
    /// outside the indexed function — a value that doesn't exist has
    /// no uses.
    #[must_use]
    pub fn uses_of(&self, value: ValueId) -> &[UseSite] {
        self.uses
            .get(value.index() as usize)
            .map_or(&[], Vec::as_slice)
    }

    /// Number of use sites of `value`. Counts occurrences, not
    /// distinct users: `I32Add(v1, v1)` contributes two uses of `v1`.
    #[must_use]
    pub fn use_count(&self, value: ValueId) -> usize {
        self.uses_of(value).len()
    }

    /// True when `value` has zero use sites.
    ///
    /// Conservative: a value referenced by an unscheduled definition
    /// still counts as used (see the module docs). Never claims
    /// "unused" for something referenced anywhere.
    #[must_use]
    pub fn is_unused(&self, value: ValueId) -> bool {
        self.uses_of(value).is_empty()
    }

    /// `Some(site)` iff `value` has exactly one use site.
    ///
    /// This is the "sole consumer" check that pattern collapses hinge
    /// on: the C4 admin-auth pair (`instance.get(Admin)` feeding one
    /// `require_auth`) and the C1 Val round-trip (`obj_from_i64`
    /// feeding one `obj_to_i64`) are only sound to collapse when the
    /// intermediate value does not escape anywhere else.
    #[must_use]
    pub fn sole_use(&self, value: ValueId) -> Option<UseSite> {
        match self.uses_of(value) {
            [site] => Some(*site),
            _ => None,
        }
    }
}

/// Record one use of `value`, silently skipping references outside the
/// indexed arena (malformed IR is the validator's concern, not ours).
fn record(uses: &mut [Vec<UseSite>], value: ValueId, site: UseSite) {
    if let Some(slot) = uses.get_mut(value.index() as usize) {
        slot.push(site);
    }
}

/// Record every block-target argument as a use at `site`.
fn record_target(uses: &mut [Vec<UseSite>], target: &BlockTarget, site: UseSite) {
    for arg in &target.args {
        record(uses, *arg, site);
    }
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{Arena, FuncId};
    use sordec_ir::{LiftedBlock, LiftedType, LiftedValue, WasmOp};

    /// Build a `LiftedFunction` from value defs and explicit blocks.
    ///
    /// Same shape as `trace_const`'s helper, extended with caller-
    /// supplied blocks so terminator uses can be exercised. Blocks are
    /// pushed in order; the first is the entry.
    fn func_with(defs: Vec<LiftedValueDef>, blocks_in: Vec<LiftedBlock>) -> LiftedFunction {
        let mut values: Arena<ValueId, LiftedValue> = Arena::new();
        for def in defs {
            values.push(LiftedValue {
                def,
                types: vec![LiftedType::I32],
            });
        }
        let mut blocks: Arena<BlockId, LiftedBlock> = Arena::new();
        for b in blocks_in {
            blocks.push(b);
        }
        LiftedFunction {
            id: FuncId::from_index(0),
            entry: BlockId::from_index(0),
            blocks,
            values,
        }
    }

    /// One empty block terminated by `term` — enough scaffold for
    /// terminator-use tests.
    fn block(term: LiftedTerminator) -> LiftedBlock {
        LiftedBlock {
            id: BlockId::from_index(0),
            params: vec![],
            instructions: vec![],
            terminator: term,
        }
    }

    fn unreachable_block() -> LiftedBlock {
        block(LiftedTerminator::Unreachable)
    }

    fn op(w: waffle::Operator, args: Vec<ValueId>) -> LiftedValueDef {
        LiftedValueDef::Operator {
            op: WasmOp(w),
            args,
        }
    }

    fn i32_const(value: u32) -> LiftedValueDef {
        op(waffle::Operator::I32Const { value }, vec![])
    }

    fn v(idx: u32) -> ValueId {
        ValueId::from_index(idx)
    }

    fn bb(idx: u32) -> BlockId {
        BlockId::from_index(idx)
    }

    // --- Value-def uses ---

    #[test]
    fn operator_args_recorded_with_positions() {
        // v0, v1 constants; v2 = I32Add(v0, v1)
        let func = func_with(
            vec![
                i32_const(1),
                i32_const(2),
                op(waffle::Operator::I32Add, vec![v(0), v(1)]),
            ],
            vec![unreachable_block()],
        );
        let index = DefUseIndex::build(&func);
        assert_eq!(
            index.uses_of(v(0)),
            &[UseSite::Value {
                user: v(2),
                operand: 0
            }]
        );
        assert_eq!(
            index.uses_of(v(1)),
            &[UseSite::Value {
                user: v(2),
                operand: 1
            }]
        );
    }

    #[test]
    fn same_value_twice_in_one_op_records_two_uses() {
        // v1 = I32Add(v0, v0) — two occurrences, two use entries.
        let func = func_with(
            vec![i32_const(7), op(waffle::Operator::I32Add, vec![v(0), v(0)])],
            vec![unreachable_block()],
        );
        let index = DefUseIndex::build(&func);
        assert_eq!(index.use_count(v(0)), 2);
        assert_eq!(
            index.uses_of(v(0)),
            &[
                UseSite::Value {
                    user: v(1),
                    operand: 0
                },
                UseSite::Value {
                    user: v(1),
                    operand: 1
                },
            ]
        );
    }

    #[test]
    fn alias_records_use() {
        let func = func_with(
            vec![i32_const(1), LiftedValueDef::Alias(v(0))],
            vec![unreachable_block()],
        );
        let index = DefUseIndex::build(&func);
        assert_eq!(
            index.uses_of(v(0)),
            &[UseSite::Value {
                user: v(1),
                operand: 0
            }]
        );
    }

    #[test]
    fn pick_output_records_use() {
        let func = func_with(
            vec![
                i32_const(1),
                LiftedValueDef::PickOutput {
                    from: v(0),
                    index: 0,
                },
            ],
            vec![unreachable_block()],
        );
        let index = DefUseIndex::build(&func);
        assert_eq!(
            index.uses_of(v(0)),
            &[UseSite::Value {
                user: v(1),
                operand: 0
            }]
        );
    }

    #[test]
    fn block_param_is_not_a_use() {
        // A BlockParam def references its block, but that's a def
        // relationship — nothing gets recorded as used.
        let func = func_with(
            vec![LiftedValueDef::BlockParam {
                block: bb(0),
                index: 0,
            }],
            vec![unreachable_block()],
        );
        let index = DefUseIndex::build(&func);
        assert!(index.is_unused(v(0)));
    }

    // --- Terminator uses ---

    #[test]
    fn branch_target_args_recorded() {
        let func = func_with(
            vec![i32_const(1)],
            vec![block(LiftedTerminator::Branch(BlockTarget {
                block: bb(0),
                args: vec![v(0)],
            }))],
        );
        let index = DefUseIndex::build(&func);
        assert_eq!(index.uses_of(v(0)), &[UseSite::Terminator { block: bb(0) }]);
    }

    #[test]
    fn branch_if_cond_and_both_targets_recorded() {
        // cond v0; if_true passes v1; if_false passes v2.
        let func = func_with(
            vec![i32_const(0), i32_const(1), i32_const(2)],
            vec![block(LiftedTerminator::BranchIf {
                cond: v(0),
                if_true: BlockTarget {
                    block: bb(0),
                    args: vec![v(1)],
                },
                if_false: BlockTarget {
                    block: bb(0),
                    args: vec![v(2)],
                },
            })],
        );
        let index = DefUseIndex::build(&func);
        for value in [v(0), v(1), v(2)] {
            assert_eq!(
                index.uses_of(value),
                &[UseSite::Terminator { block: bb(0) }],
                "expected one terminator use for {value:?}"
            );
        }
    }

    #[test]
    fn switch_index_targets_default_recorded() {
        // index v0; one target passing v1; default passing v2.
        let func = func_with(
            vec![i32_const(0), i32_const(1), i32_const(2)],
            vec![block(LiftedTerminator::Switch {
                index: v(0),
                targets: vec![BlockTarget {
                    block: bb(0),
                    args: vec![v(1)],
                }],
                default: BlockTarget {
                    block: bb(0),
                    args: vec![v(2)],
                },
            })],
        );
        let index = DefUseIndex::build(&func);
        for value in [v(0), v(1), v(2)] {
            assert_eq!(
                index.uses_of(value),
                &[UseSite::Terminator { block: bb(0) }],
                "expected one terminator use for {value:?}"
            );
        }
    }

    #[test]
    fn return_values_recorded() {
        let func = func_with(
            vec![i32_const(1), i32_const(2)],
            vec![block(LiftedTerminator::Return {
                values: vec![v(0), v(1)],
            })],
        );
        let index = DefUseIndex::build(&func);
        assert_eq!(index.uses_of(v(0)), &[UseSite::Terminator { block: bb(0) }]);
        assert_eq!(index.uses_of(v(1)), &[UseSite::Terminator { block: bb(0) }]);
    }

    // --- Query edge cases ---

    #[test]
    fn unused_value_reports_empty_unused_and_no_sole_use() {
        let func = func_with(vec![i32_const(1)], vec![unreachable_block()]);
        let index = DefUseIndex::build(&func);
        assert_eq!(index.uses_of(v(0)), &[] as &[UseSite]);
        assert_eq!(index.use_count(v(0)), 0);
        assert!(index.is_unused(v(0)));
        assert_eq!(index.sole_use(v(0)), None);
    }

    #[test]
    fn sole_use_some_iff_exactly_one() {
        // v0 used once (by v2); v1 used twice (by v3).
        let func = func_with(
            vec![
                i32_const(1),
                i32_const(2),
                LiftedValueDef::Alias(v(0)),
                op(waffle::Operator::I32Add, vec![v(1), v(1)]),
            ],
            vec![unreachable_block()],
        );
        let index = DefUseIndex::build(&func);
        assert_eq!(
            index.sole_use(v(0)),
            Some(UseSite::Value {
                user: v(2),
                operand: 0
            })
        );
        assert_eq!(index.sole_use(v(1)), None, "two uses is not a sole use");
    }

    #[test]
    fn dangling_query_and_dangling_operand_are_safe() {
        // The single def references v(99), which doesn't exist —
        // build must not panic, and querying v(99) returns empty.
        let func = func_with(
            vec![op(waffle::Operator::I32Add, vec![v(99), v(99)])],
            vec![unreachable_block()],
        );
        let index = DefUseIndex::build(&func);
        assert_eq!(index.uses_of(v(99)), &[] as &[UseSite]);
        assert!(index.is_unused(v(99)));
        assert_eq!(index.sole_use(v(99)), None);
    }

    #[test]
    fn ordering_is_deterministic_value_uses_before_terminator_uses() {
        // v0 is read both by v1's def and by the block terminator.
        // The documented order is value-def uses first, then
        // terminator uses.
        let func = func_with(
            vec![i32_const(1), LiftedValueDef::Alias(v(0))],
            vec![block(LiftedTerminator::Return { values: vec![v(0)] })],
        );
        let index = DefUseIndex::build(&func);
        assert_eq!(
            index.uses_of(v(0)),
            &[
                UseSite::Value {
                    user: v(1),
                    operand: 0
                },
                UseSite::Terminator { block: bb(0) },
            ]
        );
    }
}
