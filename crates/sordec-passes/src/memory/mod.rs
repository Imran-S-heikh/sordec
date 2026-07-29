//! Shadow-stack memory promotion — turning linear-memory traffic back into
//! SSA values.
//!
//! WASM locals have no addresses and its value types are machine words, so
//! anything borrowable or wider than a word lives in linear memory, in a
//! compiler-managed *shadow stack*. Reconstructed literally that is opaque
//! `Load`/`Store` traffic through a pointer, which the Rust backend can only
//! render as holes. This module recovers it.
//!
//! ## The pattern, and its two halves
//!
//! Both halves are textbook, and neither is novel here:
//!
//! - **SROA** (scalar replacement of aggregates) — split one multi-byte
//!   frame slot into one scalar per field. LLVM requires this first because
//!   mem2reg cannot promote aggregates.
//! - **mem2reg** — replace each scalar's loads and stores with an SSA value,
//!   inserting phis where control flow merges.
//!
//! Ghidra does the same thing in its `Heritage` class, and its WASM plugin
//! detects the "C stack pointer" global first, exactly as [`frame`] does.
//!
//! ## Why this lives at the *lifted* layer
//!
//! Because phis do. `LiftedIr` is a real CFG whose block parameters are the
//! SSA encoding of phi nodes; `HighIr` has already been structured into a
//! region tree where phi transfers are baked into `Break`/`Transfer` nodes.
//! An earlier attempt at this transform ran on `HighIr` and had nowhere to
//! put the merge, so it bound reads to a definition that did not dominate
//! them and emitted Rust that did not compile. Every precedent — Ghidra,
//! LLVM, Hex-Rays — promotes memory during SSA work, before structuring.
//!
//! ## The insight that removes the hard part
//!
//! Minimal phi placement — dominance frontiers, Cytron, Braun's
//! `readVariable` recursion — is the difficult half of mem2reg, and this
//! module does none of it. The lift already calls
//! `convert_to_max_ssa`, so the CFG arrives in *maximal* SSA, and
//! [`crate::declutter::PruneTrivialPhisPass`] already implements Braun et
//! al.'s trivial-phi rule to minimise it back. So promotion inserts a block
//! parameter for the promoted slot **everywhere** — obviously correct, and
//! trivially reviewable — and the pass already sitting in the same fixpoint
//! group prunes it. Insert maximally, prune back, exactly as the lift does.
//!
//! ## Order
//!
//! [`frame`] identifies the bracket (analysis only). [`sret`] converts
//! out-parameters into real multi-value returns, which is what stops the
//! frame *escaping* into a callee — mem2reg's precondition. [`promote`]
//! then splits and promotes the slots that remain.

pub(crate) mod frame;
pub mod promote;
pub mod sret;

pub use promote::SlotPromotionPass;
pub use sret::SretReturnPass;

#[cfg(test)]
pub(crate) mod census {
    //! Corpus census for this module's analyses.
    //!
    //! Not a lock. It exists because an analysis that silently finds
    //! nothing is indistinguishable from one that has nothing to find, and
    //! the difference is the whole work list. Run with:
    //!
    //!   cargo test -p sordec-passes --lib -- --ignored --nocapture frame_census

    use sordec_common::IrId as _;
    use sordec_ir::LiftedFunction;

    macro_rules! fixture {
        ($name:literal) => {
            ($name, include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../samples/contracts/", $name, "/", $name, ".wasm"
            )).as_slice())
        };
    }

    pub(crate) const FIXTURES: &[(&str, &[u8])] = &[
        fixture!("hello-add"),
        fixture!("token-v23"),
        fixture!("timelock"),
        fixture!("dex-liquidity-pool"),
        fixture!("attestation"),
    ];

    /// Parse, lift and declutter — the state this module's passes see.
    pub(crate) fn lifted(wasm: &[u8]) -> Vec<LiftedFunction> {
        let parsed = sordec_frontend::parse(wasm).expect("parses");
        let mut lifted = crate::lift_with_waffle(wasm, &parsed.wasm_facts, parsed.soroban_facts.as_ref())
            .expect("lifts")
            .lifted;
        crate::default_lifted_pipeline().run(&mut lifted);
        lifted.functions
    }

    /// What the *real* lifted pipeline does on each fixture.
    ///
    /// Reports the pipeline's own counters rather than re-running a pass
    /// by hand, because a hand-run pass on already-processed IR measures a
    /// no-op and reads as "the pass does nothing".
    #[test]
    #[ignore = "corpus census; run explicitly"]
    #[allow(clippy::print_stdout)]
    fn pipeline_census() {
        use crate::metrics_catalog as keys;
        for (name, wasm) in FIXTURES {
            let parsed = sordec_frontend::parse(wasm).expect("parses");
            let mut ir = crate::lift_with_waffle(wasm, &parsed.wasm_facts, parsed.soroban_facts.as_ref())
                .expect("lifts")
                .lifted;
            let report = crate::default_lifted_pipeline().run(&mut ir);
            let totals = report.metric_totals();
            let get = |k: &str| totals.get(k).copied().unwrap_or(0);
            let frames = ir.functions.iter().filter(|f| super::frame::detect(f).is_some()).count();
            println!("{name}: frames left {frames}");
            println!(
                "{name}: sret {} · slots {} · loads {} · stores {} · valid {}",
                get(keys::MEMORY_SRET_CONVERTED),
                get(keys::MEMORY_SLOTS_PROMOTED),
                get(keys::MEMORY_LOADS_FORWARDED),
                get(keys::MEMORY_STORES_REMOVED),
                sordec_ir::validate_lifted(&ir).is_ok(),
            );
        }
    }

    #[test]
    #[ignore = "corpus census; run explicitly"]
    #[allow(clippy::print_stdout)]
    fn frame_census() {
        for (name, wasm) in FIXTURES {
            let functions = lifted(wasm);
            let total = functions.len();
            let mut sizes: Vec<(u32, u32)> = functions
                .iter()
                .filter_map(|f| super::frame::detect(f).map(|l| (f.id.index(), l.size)))
                .collect();
            sizes.sort_unstable();
            println!(
                "{name}: {} of {total} functions have a shadow-stack frame; sizes {:?}",
                sizes.len(),
                sizes.iter().map(|(_, s)| *s).collect::<Vec<_>>()
            );
        }
    }
}
