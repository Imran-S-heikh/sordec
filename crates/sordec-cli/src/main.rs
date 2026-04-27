//! `sordec` — command-line interface to the Soroban decompiler.

// `diagnostics` is foundation for upcoming subcommands (`dump-facts`,
// `dump-ir`). Its `pub fn`s aren't called from `main` yet, hence the
// allow; their unit tests exercise them.
#[allow(dead_code)]
mod diagnostics;

// JUSTIFY: Phase 1.2 ships only a workspace scaffold; the real CLI
// (next sub-task: `sordec dump-facts`/`dump-ir`) replaces this
// `println!` with structured argv parsing and a real subcommand
// surface. The `diagnostics` module is foundation for those
// subcommands — `print_diagnostics` is unused here but exercised by
// its own unit tests.
#[allow(clippy::print_stdout)]
fn main() {
    println!("sordec v0.1.0 — workspace scaffold");
}
