//! Differential execution: does our reconstruction *behave* like the original?
//!
//! Every other scored category compares source text — how closely the Rust we
//! emit resembles the Rust that was compiled away. This crate asks the question
//! the RFP actually asks: run the original wasm and our recompiled
//! reconstruction against the same inputs and see whether they do the same
//! thing.
//!
//! That distinction matters more than it sounds. Text similarity fights genuine
//! information loss — rustc deleted the names, the comments, the type structure,
//! and no amount of work brings them back. Behaviour lost nothing: the compiled
//! semantics are all still there in the bytes. So behaviour is the one dimension
//! where 100% is reachable in principle, which makes it worth measuring
//! properly.
//!
//! # Where this is in its build-out
//!
//! [`preflight`] holds the decisions and environment checks everything else rests
//! on. [`wasm`] decides whether the host will accept a module at all. [`exec`]
//! runs a contract and records the four observations; [`canon`] makes two
//! independently-registered contracts comparable; [`diff`] compares them.
//!
//! What is **not** here yet is recompilation of our emitter's output, which needs
//! the emitter to produce something that compiles.
//!
//! That is not a blocker on the rest, and the earlier assumption that it was cost
//! us the whole of M1–M3. Comparison needs a *second wasm*, not specifically our
//! wasm — so the harness is built and calibrated against B-sides we can produce
//! today: the shipped wasm against itself, the original source recompiled, and
//! deliberately mutated sources whose divergence class is known in advance. That
//! last one is the only B-side that can prove the comparator *detects* anything,
//! and it does not involve the emitter at all. Our emitter's output is simply the
//! B-side we cannot supply yet.
//!
//! See `plan/BEHAVIOR_HARNESS_PLAN.md` for the task sequence.
//!
//! # Shape of the eventual harness
//!
//! The source of truth is **the original wasm, not the original source**. That
//! choice is what lets this work on contracts pulled straight off-chain, where
//! no source exists — which is most of them, and the ones an auditor most wants
//! decompiled.
//!
//! Both contracts get registered in an in-process host (no network, no node),
//! invoked identically, and compared across four observations: the returned
//! value, the ordered event stream, the authorization tree, and the storage
//! snapshot. Those are reported separately rather than averaged — "events 94%,
//! storage 87%" tells you where to work in a way that "93%" does not.
//!
//! # Two rules the reporting has to keep
//!
//! **A match rate is meaningless without its coverage.** "99% behavioural
//! match" over three of thirty entrypoints is not a 99% result. Every figure
//! this crate produces travels with the fraction of the contract it was
//! measured over.
//!
//! **Mutual failure is not agreement.** Two contracts that both panic on
//! garbage input agree perfectly and demonstrate nothing. That outcome is
//! counted in its own bucket, never folded into a match rate.

pub mod canon;
pub mod diff;
pub mod exec;
pub mod preflight;
pub mod recompile;
pub mod wasm;
