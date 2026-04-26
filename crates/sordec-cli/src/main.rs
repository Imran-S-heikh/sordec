//! `sordec` — command-line interface to the Soroban decompiler.

// JUSTIFY: Phase 1.2 ships only a workspace scaffold; the real CLI
// (Task 4.4) replaces this `println!` with structured argv parsing and
// `tracing`-based diagnostics. Until then, a single placeholder line
// proves the binary builds and runs.
#[allow(clippy::print_stdout)]
fn main() {
    println!("sordec v0.1.0 — workspace scaffold");
}
