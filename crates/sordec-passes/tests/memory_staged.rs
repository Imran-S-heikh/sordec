//! Corpus lock for the staged shadow-stack passes.
//!
//! [`SretReturnPass`] and [`SlotPromotionPass`] are built and correct but
//! deliberately absent from [`sordec_passes::default_lifted_pipeline`] —
//! `sret` rewrites the Val-decode helper into a multi-value return, which
//! is the exact shape `marshalling`'s elision matches on, so wiring them
//! today costs hello-add its clean emission. See the `memory::promote`
//! module docs.
//!
//! Nothing else in the suite runs them end-to-end, so without this file
//! the pair could rot unnoticed while it waits. These tests pin the two
//! properties that were expensive to establish:
//!
//! 1. The pair produces a valid module — matched block-parameter arity,
//!    `validate_lifted`, and `validate_high` both after lowering and
//!    after the full high pipeline.
//! 2. **`ResolveAliasesPass` must sit inside the fixpoint group.**
//!    Promotion retires each forwarded load and leaves a
//!    `LiftedValueDef::Alias` tombstone whose readers still name it —
//!    a *used* alias, which is precisely the invariant the pass's
//!    once-up-front placement assumes nobody breaks. Left unresolved it
//!    becomes a used-but-unscheduled value, and the region validator
//!    reports `UseBeforeDef` two stages downstream, at whichever
//!    refinement pass happens to call `debug_validate` first.
//!
//! Test 2 is the negative half of test 1: it asserts the bug is still
//! reachable with the grouping undone, so the lock cannot silently
//! degrade into a tautology.

mod common;

use sordec_common::{IrId, ValueId};
use sordec_ir::{
    validate_high, validate_lifted, LiftedFunction, LiftedIr, LiftedValueDef,
};
use sordec_passes::{
    default_high_pipeline, for_each_target, lift_with_waffle, metrics_catalog as mc, LiftToHigh,
    LoweringStep, MergeBlockChainsPass, Pass, Pipeline, PruneTrivialPhisPass, ResolveAliasesPass,
    SlotPromotionPass, SretReturnPass, SweepDeadPass, ThreadTrivialJumpsPass,
};

use common::FIXTURES;

/// The de-cluttering pipeline with the staged pair appended, in LLVM's
/// SROA-then-mem2reg order.
///
/// `resolve_inside` selects where [`ResolveAliasesPass`] runs: inside the
/// fixpoint group (correct once promotion is present) or once up front
/// (correct only while it is absent). This is the whole subject of
/// `promotion_needs_alias_resolution_in_the_group`.
fn staged_pipeline(resolve_inside: bool) -> Pipeline<LiftedIr> {
    let passes: Vec<Box<dyn Pass<LiftedIr>>> = vec![
        Box::new(ResolveAliasesPass),
        Box::new(PruneTrivialPhisPass),
        Box::new(ThreadTrivialJumpsPass),
        Box::new(MergeBlockChainsPass),
        Box::new(SweepDeadPass),
        Box::new(SretReturnPass),
        Box::new(SlotPromotionPass),
    ];
    let group = if resolve_inside { 0..7 } else { 1..7 };
    Pipeline::new(passes, vec![group])
}

fn run_staged(wasm: &[u8], resolve_inside: bool) -> LiftedIr {
    let parsed = sordec_frontend::parse(wasm).expect("frontend parses fixture");
    let mut lifted = lift_with_waffle(wasm, &parsed.wasm_facts, parsed.soroban_facts.as_ref())
        .expect("lifter accepts fixture")
        .lifted;
    staged_pipeline(resolve_inside).run(&mut lifted);
    lifted
}

/// Every alias def that some reachable position still names.
///
/// This is the invariant `ResolveAliasesPass`'s placement rests on,
/// stated directly rather than through the `UseBeforeDef` it eventually
/// produces: an alias with live readers is fine only while it is still
/// scheduled, and promotion retires exactly the ones it creates.
fn used_aliases(func: &LiftedFunction) -> Vec<ValueId> {
    let aliases: Vec<ValueId> = func
        .values
        .iter()
        .filter(|(_, v)| matches!(v.def, LiftedValueDef::Alias(_)))
        .map(|(id, _)| id)
        .collect();
    if aliases.is_empty() {
        return Vec::new();
    }

    let scheduled: std::collections::HashSet<ValueId> = func
        .blocks
        .iter()
        .flat_map(|(_, b)| b.instructions.iter().copied())
        .collect();

    let mut used = Vec::new();
    for &alias in &aliases {
        if scheduled.contains(&alias) {
            continue; // still emitted; not the failure mode
        }
        let mut is_used = false;
        for (id, value) in func.values.iter() {
            if id == alias || !scheduled.contains(&id) {
                continue;
            }
            if let LiftedValueDef::Operator { args, .. } = &value.def {
                is_used |= args.contains(&alias);
            }
        }
        for (_, block) in func.blocks.iter() {
            for_each_target(&block.terminator, |t| {
                is_used |= t.args.contains(&alias);
            });
        }
        if is_used {
            used.push(alias);
        }
    }
    used
}

#[test]
fn staged_pair_produces_a_valid_module_across_the_corpus() {
    for (name, wasm) in FIXTURES {
        let lifted = run_staged(wasm, true);

        // 1. Block-parameter arity: promotion inserts a parameter in
        //    every reachable non-entry block and must wire every in-edge.
        for func in &lifted.functions {
            for (from, block) in func.blocks.iter() {
                for_each_target(&block.terminator, |t| {
                    let params = func.blocks.get(t.block).map_or(0, |b| b.params.len());
                    assert_eq!(
                        t.args.len(),
                        params,
                        "[{name}] fn{} bb{} -> bb{}: {} args for {params} params",
                        func.id.index(),
                        from.index(),
                        t.block.index(),
                        t.args.len(),
                    );
                });
            }
        }

        // 2. No alias survives with live readers (see `used_aliases`).
        for func in &lifted.functions {
            let stranded = used_aliases(func);
            assert!(
                stranded.is_empty(),
                "[{name}] fn{}: unresolved used aliases {stranded:?}",
                func.id.index(),
            );
        }

        // 3. Both validators, at both stages.
        validate_lifted(&lifted)
            .unwrap_or_else(|e| panic!("[{name}] lifted validator: {e:?}"));
        let mut high = LiftToHigh
            .lower(lifted)
            .unwrap_or_else(|e| panic!("[{name}] boundary lowering: {e:?}"));
        validate_high(&high)
            .unwrap_or_else(|e| panic!("[{name}] high validator after lowering: {e:?}"));
        let report = default_high_pipeline().run(&mut high);
        validate_high(&high)
            .unwrap_or_else(|e| panic!("[{name}] high validator after recovery: {e:?}"));

        // 4. The recognizer still sees through the conversion. `sret`
        //    rewrites the SDK decode helper into a multi-value return,
        //    which is the shape `marshalling::decode` matches on — if
        //    that recognition lapses, the helper stops being elided and
        //    is emitted as contract logic the author never wrote.
        if *name == "hello-add" {
            let collapsed = report
                .metric_totals()
                .into_iter()
                .find(|(key, _)| *key == mc::MARSHALLING_DECODE_COLLAPSED)
                .map_or(0, |(_, value)| value);
            assert!(
                collapsed > 0,
                "[{name}] the argument decode must still collapse once `sret` \
                 has converted the helper to a multi-value return",
            );
        }
    }
}

#[test]
fn promotion_needs_alias_resolution_in_the_group() {
    // The negative half. With `ResolveAliasesPass` back at its
    // once-up-front position, promotion's tombstones are never
    // re-resolved and strand their readers. If this ever stops finding
    // stranded aliases, promotion has changed how it retires loads and
    // the grouping requirement above needs re-deriving rather than
    // trusting.
    let stranded_fixtures: Vec<&str> = FIXTURES
        .iter()
        .filter(|(_, wasm)| {
            let lifted = run_staged(wasm, false);
            lifted.functions.iter().any(|f| !used_aliases(f).is_empty())
        })
        .map(|(name, _)| *name)
        .collect();

    assert!(
        !stranded_fixtures.is_empty(),
        "promotion no longer strands aliases when resolution runs once up \
         front — re-derive why the fixpoint grouping is required",
    );
}
