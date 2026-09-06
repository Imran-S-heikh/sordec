//! Decompile a Soroban contract, and grade the result.
//!
//! This is the front door. The pipeline is split across nine crates — frontend,
//! IR, passes, backend, signature catalogue, scorer, differential-execution
//! harness — and almost nobody wants to assemble those by hand. Two entry points
//! cover what people actually do:
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let wasm = std::fs::read("contract.wasm")?;
//! let output = sordec::Driver::standard().run(&wasm)?;
//! println!("{}", output.rust);
//! # Ok(())
//! # }
//! ```
//!
//! [`Driver`] reconstructs; [`score_paths`] measures a reconstruction against
//! the original source. Everything here is a re-export — the implementations
//! live in `sordec-driver` and `sordec-score`, and depending on those crates
//! directly is equally supported. This crate adds the `sordec` binary and one
//! module that has nowhere else to live.
//!
//! # Re-exporting the scorer does not couple it to the pipeline
//!
//! `sordec-score` never inspects WASM or the decompiler's internals, so it
//! cannot flatter the pipeline it grades — that independence is a property of
//! the dependency graph, not a promise, and it survives being re-exported here
//! because a re-export adds no edge. This package already depended on both, and
//! deliberately: it is the only one entitled to, which is exactly why
//! [`behavior`] lives here and not in either of them.

pub use sordec_driver::{DecompileOutput, Driver, DriverError, DriverReport};
pub use sordec_score::{score_paths, ScoreOptions, ScoreReport};

pub mod behavior;
