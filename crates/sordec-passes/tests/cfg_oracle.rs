//! Differential oracle for [`sordec_passes::CfgFacts`]: waffle's own
//! `cfg::CFGInfo` computed on the same function bodies.
//!
//! The lifter guarantees `BlockId(i)` mirrors waffle's `Block(i)` for
//! every local function (density asserts in `lift.rs`), so both
//! analyses can be compared by raw index. The waffle `Module` is
//! dropped inside `lift_with_waffle`, so this test re-runs the exact
//! preprocessing pipeline (`from_wasm_bytes` → `expand_all_funcs` →
//! `convert_to_max_ssa(None)` + `recompute_edges()`) to obtain live
//! `FunctionBody`s for `CFGInfo::new`.
//!
//! Compared per function, across every corpus fixture:
//!
//! - reverse postorder, **elementwise** (locks our successor
//!   enumeration order to waffle's `visit_targets` order),
//! - `rpo_pos` for every block (`None` ⇔ unreachable on both sides),
//! - immediate dominators, normalized to `Option` (waffle's
//!   `Block::invalid()` sentinel for entry/unreachable ⇔ our `None`),
//! - predecessor **sets** (waffle keeps duplicate edges; we
//!   deduplicate — the raw view lives in `for_each_target`).
//!
//! Additionally: `irreducible_edges()` must be empty on every corpus
//! function (WASM can only express reducible control flow — a witness
//! here is a lifter/analysis bug), and every `CfgFacts`/`LoopForest`
//! pair must satisfy the structural invariants checked by
//! `assert_cfg_wellformed`.

use std::collections::BTreeSet;

use sordec_common::{BlockId, IrId};
use sordec_ir::LiftedFunction;
use sordec_passes::{lift_with_waffle, CfgFacts, LoopForest};
use waffle::entity::EntityRef;

// ---------------------------------------------------------------------
// Corpus fixtures (paths mirror sordec-driver/tests/corpus.rs)
// ---------------------------------------------------------------------

const HELLO_ADD_WASM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/hello-add/hello-add.wasm"
));
const TOKEN_V22_WASM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/token-v22/token-v22.wasm"
));
const TOKEN_V23_WASM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/token-v23/token-v23.wasm"
));
const TOKEN_V23_STRIPPED_WASM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/token-v23-stripped/token-v23-stripped.wasm"
));
const TIMELOCK_WASM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/timelock/timelock.wasm"
));
const DEX_LIQUIDITY_POOL_WASM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/dex-liquidity-pool/dex-liquidity-pool.wasm"
));
const ATTESTATION_WASM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/attestation/attestation.wasm"
));

// ---------------------------------------------------------------------
// Drivers
// ---------------------------------------------------------------------

/// Lift `wasm` through our pipeline.
fn lift(wasm: &[u8]) -> Vec<LiftedFunction> {
    let parsed = sordec_frontend::parse(wasm).expect("frontend parses fixture");
    lift_with_waffle(wasm, &parsed.wasm_facts, parsed.soroban_facts.as_ref())
        .expect("lifter accepts fixture")
        .lifted
        .functions
}

/// The full differential comparison for one fixture.
fn assert_cfg_matches_waffle(wasm: &[u8], name: &str) {
    let functions = lift(wasm);

    // Waffle side: mirror the lifter's preprocessing exactly
    // (lift.rs steps 1–3) to get live FunctionBody values.
    let mut module = waffle::Module::from_wasm_bytes(wasm, &waffle::FrontendOptions::default())
        .expect("waffle parses fixture");
    module.expand_all_funcs().expect("waffle expands bodies");
    module.per_func_body(|body| {
        body.convert_to_max_ssa(None);
        body.recompute_edges();
    });

    // Pair non-import decls with lifted functions: FuncId order IS
    // non-import declaration order (lift.rs step 4).
    let bodies: Vec<&waffle::FunctionBody> = module
        .funcs
        .entries()
        .filter(|(_, decl)| !matches!(decl, waffle::FuncDecl::Import(_, _)))
        .map(|(_, decl)| decl.body().expect("non-import decl has a body"))
        .collect();
    assert_eq!(
        bodies.len(),
        functions.len(),
        "{name}: waffle body count must equal lifted function count"
    );

    for (func, body) in functions.iter().zip(&bodies) {
        compare_one_function(func, body, name);
    }
}

/// Compare our `CfgFacts` against waffle's `CFGInfo` for one function,
/// then check the structural invariants.
fn compare_one_function(func: &LiftedFunction, body: &waffle::FunctionBody, name: &str) {
    let ctx = format!("{name} fn {}", func.id);
    let n = func.blocks.len();
    assert_eq!(n, body.blocks.len(), "{ctx}: block count");

    let facts = CfgFacts::build(func);
    let info = waffle::cfg::CFGInfo::new(body);

    // Reverse postorder, elementwise.
    let ours: Vec<u32> = facts.rpo().iter().map(|b| b.index()).collect();
    let theirs: Vec<u32> = info.rpo.values().map(|b| b.index() as u32).collect();
    assert_eq!(ours, theirs, "{ctx}: rpo sequence");

    for i in 0..n {
        let our_block = BlockId::from_index(i as u32);
        let their_block = waffle::Block::new(i);

        // RPO position (None ⇔ unreachable).
        let their_pos = info.rpo_pos[their_block].map(|p| p.index() as u32);
        assert_eq!(facts.rpo_pos(our_block), their_pos, "{ctx}: rpo_pos(bb{i})");

        // Immediate dominator, sentinel-normalized. Waffle publishes
        // `Block::invalid()` for both the entry and unreachable blocks;
        // we publish `None` for both — so a uniform comparison works.
        let their_idom = if info.domtree[their_block].is_valid() {
            Some(info.domtree[their_block].index() as u32)
        } else {
            None
        };
        assert_eq!(
            facts.idom(our_block).map(|b| b.index()),
            their_idom,
            "{ctx}: idom(bb{i})"
        );

        // Predecessors as sets (waffle keeps edge multiplicity).
        let our_preds: BTreeSet<u32> = facts.preds(our_block).iter().map(|b| b.index()).collect();
        let their_preds: BTreeSet<u32> = info.preds[their_block]
            .iter()
            .map(|b| b.index() as u32)
            .collect();
        assert_eq!(our_preds, their_preds, "{ctx}: preds(bb{i})");
    }

    // WASM control flow is reducible by construction; a witness on
    // lifter output is a bug in the lifter or in this analysis.
    assert!(
        facts.irreducible_edges().is_empty(),
        "{ctx}: irreducibility witnesses on WASM-derived CFG: {:?}",
        facts.irreducible_edges()
    );

    assert_cfg_wellformed(&facts, &LoopForest::build(&facts), &ctx);
}

/// Structural invariants every `CfgFacts` + `LoopForest` pair must
/// satisfy, independent of the waffle comparison.
fn assert_cfg_wellformed(facts: &CfgFacts, forest: &LoopForest, ctx: &str) {
    let n = facts.num_blocks();
    let block = |i: usize| BlockId::from_index(i as u32);

    // RPO: entry-first, unique entries, consistent positions.
    if !facts.rpo().is_empty() {
        assert_eq!(facts.rpo()[0], facts.entry(), "{ctx}: rpo[0] must be the entry");
    }
    let mut in_rpo = vec![false; n];
    for (pos, &b) in facts.rpo().iter().enumerate() {
        assert!(!in_rpo[b.index() as usize], "{ctx}: duplicate rpo entry {b}");
        in_rpo[b.index() as usize] = true;
        assert_eq!(facts.rpo_pos(b), Some(pos as u32), "{ctx}: rpo_pos({b})");
        assert!(facts.is_reachable(b), "{ctx}: rpo entry {b} must be reachable");
    }
    for (i, present) in in_rpo.iter().enumerate() {
        if !present {
            let b = block(i);
            assert_eq!(facts.rpo_pos(b), None, "{ctx}: unreachable {b} has no rpo_pos");
            assert_eq!(facts.idom(b), None, "{ctx}: unreachable {b} has no idom");
            assert!(!facts.is_reachable(b), "{ctx}: {b} must report unreachable");
            assert!(!facts.dominates(b, b), "{ctx}: unreachable {b} never dominates");
        }
    }

    // Idoms: reachable, strictly earlier in RPO, strictly dominating.
    for &b in facts.rpo() {
        if b == facts.entry() {
            assert_eq!(facts.idom(b), None, "{ctx}: the entry has no idom");
            continue;
        }
        let d = facts.idom(b).unwrap_or_else(|| {
            panic!("{ctx}: reachable non-entry {b} must have an idom")
        });
        assert!(facts.is_reachable(d), "{ctx}: idom({b}) = {d} must be reachable");
        assert!(
            facts.rpo_pos(d) < facts.rpo_pos(b),
            "{ctx}: idom({b}) = {d} must precede it in rpo"
        );
        assert!(facts.dominates(d, b), "{ctx}: idom({b}) = {d} must dominate it");
        assert!(!facts.dominates(b, d), "{ctx}: {b} must not dominate its idom {d}");
        assert!(facts.dominates(facts.entry(), b), "{ctx}: entry dominates {b}");
    }

    // Dominator-tree children partition the reachable non-entry blocks.
    let mut child_appearances = vec![0usize; n];
    for i in 0..n {
        for &c in facts.dom_children(block(i)) {
            child_appearances[c.index() as usize] += 1;
            assert_eq!(
                facts.idom(c),
                Some(block(i)),
                "{ctx}: dom_children/idom disagree on {c}"
            );
        }
    }
    for &b in facts.rpo() {
        let expected = usize::from(b != facts.entry());
        assert_eq!(
            child_appearances[b.index() as usize], expected,
            "{ctx}: {b} must appear exactly {expected}x in dom_children"
        );
    }

    // Edge classification re-check.
    for e in facts.back_edges() {
        assert!(
            facts.rpo_pos(e.to) <= facts.rpo_pos(e.from) && facts.rpo_pos(e.to).is_some(),
            "{ctx}: back edge {e:?} must be retreating"
        );
        assert!(facts.dominates(e.to, e.from), "{ctx}: back edge {e:?} target must dominate");
    }
    for e in facts.irreducible_edges() {
        assert!(
            facts.rpo_pos(e.to) <= facts.rpo_pos(e.from) && facts.rpo_pos(e.to).is_some(),
            "{ctx}: witness {e:?} must be retreating"
        );
        assert!(!facts.dominates(e.to, e.from), "{ctx}: witness {e:?} must not dominate");
    }

    // Loop forest invariants.
    for (id, l) in forest.iter() {
        assert!(l.contains(l.header()), "{ctx}: loop {id:?} must contain its header");
        assert!(!l.latches().is_empty(), "{ctx}: loop {id:?} must have a latch");
        for &latch in l.latches() {
            assert!(l.contains(latch), "{ctx}: loop {id:?} must contain latch {latch}");
            assert!(
                facts.succs(latch).contains(&l.header()),
                "{ctx}: latch {latch} must branch to header {}",
                l.header()
            );
        }
        for &b in l.blocks() {
            assert!(facts.is_reachable(b), "{ctx}: loop member {b} must be reachable");
            assert!(
                facts.dominates(l.header(), b),
                "{ctx}: header {} must dominate member {b}",
                l.header()
            );
        }
        match l.parent() {
            Some(p) => {
                let parent = forest.get(p).unwrap_or_else(|| {
                    panic!("{ctx}: loop {id:?} parent {p:?} must resolve")
                });
                assert!(
                    l.blocks().len() < parent.blocks().len(),
                    "{ctx}: parent {p:?} must be a strict superset of {id:?}"
                );
                for &b in l.blocks() {
                    assert!(parent.contains(b), "{ctx}: parent {p:?} must contain member {b}");
                }
                assert_eq!(l.depth(), parent.depth() + 1, "{ctx}: depth of {id:?}");
                assert!(
                    parent.children().contains(&id),
                    "{ctx}: parent {p:?} must list {id:?} as a child"
                );
            }
            None => assert_eq!(l.depth(), 1, "{ctx}: root loop {id:?} has depth 1"),
        }
        for &c in l.children() {
            let child = forest
                .get(c)
                .unwrap_or_else(|| panic!("{ctx}: child {c:?} must resolve"));
            assert_eq!(child.parent(), Some(id), "{ctx}: child {c:?} parent link");
        }
        assert_eq!(
            forest.loop_headed_by(l.header()),
            Some(id),
            "{ctx}: header map for {id:?}"
        );
    }

    // `innermost` = the deepest loop containing the block.
    for i in 0..n {
        let b = block(i);
        let deepest = forest
            .iter()
            .filter(|(_, l)| l.contains(b))
            .max_by_key(|(_, l)| l.depth());
        match (forest.innermost(b), deepest) {
            (Some(id), Some((_, deepest_loop))) => {
                let inner = forest
                    .get(id)
                    .unwrap_or_else(|| panic!("{ctx}: innermost({b}) must resolve"));
                assert!(inner.contains(b), "{ctx}: innermost({b}) must contain it");
                assert_eq!(
                    inner.depth(),
                    deepest_loop.depth(),
                    "{ctx}: innermost({b}) must be the deepest containing loop"
                );
            }
            (None, None) => {}
            (got, want) => panic!(
                "{ctx}: innermost({b}) disagrees with loop membership \
                 (got {got:?}, containment says {:?})",
                want.map(|(id, _)| id)
            ),
        }
    }
}

/// Total loop count across a module — guards against a forest that
/// silently finds nothing.
fn total_loops(wasm: &[u8]) -> usize {
    lift(wasm)
        .iter()
        .map(|func| LoopForest::build(&CfgFacts::build(func)).len())
        .sum()
}

// ---------------------------------------------------------------------
// Per-fixture oracle tests
// ---------------------------------------------------------------------

#[test]
fn oracle_hello_add() {
    assert_cfg_matches_waffle(HELLO_ADD_WASM, "hello-add");
}

#[test]
fn oracle_token_v22() {
    assert_cfg_matches_waffle(TOKEN_V22_WASM, "token-v22");
}

#[test]
fn oracle_token_v23() {
    assert_cfg_matches_waffle(TOKEN_V23_WASM, "token-v23");
}

#[test]
fn oracle_token_v23_stripped() {
    assert_cfg_matches_waffle(TOKEN_V23_STRIPPED_WASM, "token-v23-stripped");
}

#[test]
fn oracle_timelock() {
    assert_cfg_matches_waffle(TIMELOCK_WASM, "timelock");
}

#[test]
fn oracle_dex_liquidity_pool() {
    assert_cfg_matches_waffle(DEX_LIQUIDITY_POOL_WASM, "dex-liquidity-pool");
}

#[test]
fn oracle_attestation() {
    assert_cfg_matches_waffle(ATTESTATION_WASM, "attestation");
}

// ---------------------------------------------------------------------
// Loop-presence sanity (the corpus census says these contain loops)
// ---------------------------------------------------------------------

#[test]
fn loops_present_in_dex_liquidity_pool() {
    let total = total_loops(DEX_LIQUIDITY_POOL_WASM);
    assert!(total > 0, "dex-liquidity-pool should contain natural loops, found none");
}

#[test]
fn loops_present_in_token_v23() {
    let total = total_loops(TOKEN_V23_WASM);
    assert!(total > 0, "token-v23 should contain natural loops, found none");
}
