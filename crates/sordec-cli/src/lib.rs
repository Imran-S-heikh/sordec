//! Library half of the `sordec` command-line package.
//!
//! Deliberately tiny. Everything the CLI does belongs in `main.rs` or in one of the
//! pipeline crates; this exists for the single piece that a *test binary* has to call
//! in-process, and that no other crate is allowed to hold.
//!
//! [`behavior`] maps a `sordec-diffexec` differential-execution run onto a
//! [`sordec_score::BehaviorInput`]. Those two crates must not know about each other —
//! that is what keeps the scoring instrument independent of the pipeline it grades —
//! so the mapping has to live in the one package that depends on both, which is this
//! one. The corpus benchmark needs it to report the `behavior` category, and cannot
//! obtain it by running the binary, because a [`ScoreReport`] cannot be deserialized
//! back from the CLI's JSON. See [`behavior`] for the full argument.
//!
//! [`ScoreReport`]: sordec_score::ScoreReport

pub mod behavior;
