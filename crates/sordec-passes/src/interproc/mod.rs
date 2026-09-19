//! Inter-procedural transforms over [`HighIr`](sordec_ir::HighIr).
//!
//! Distinct from [`recognizers`](crate::recognizers), which *read* the IR
//! and name what they prove, and from [`declutter`](crate::declutter),
//! which cleans within one function. The passes here change the
//! **function boundary itself** — how many functions there are and what
//! crosses between them.
//!
//! They exist because rustc/LLVM moved that boundary first. Identical-code
//! folding merges source functions that differ only in a constant;
//! outlining splits ones that did not. Neither is recoverable by looking
//! harder at a single function, because the evidence a recognizer needs
//! has been pushed across a call edge and met with somebody else's.
//!
//! [`SpecializePass`] undoes the merging direction. Inlining (the
//! outlining direction) and dead-argument elimination belong here next.

pub mod const_return;
pub mod inline;
pub mod specialize;

pub use const_return::ConstReturnPass;
pub use inline::WrapperInlinePass;
pub use specialize::SpecializePass;
