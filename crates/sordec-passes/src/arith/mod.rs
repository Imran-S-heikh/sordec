//! Integer arithmetic wider than the machine word.
//!
//! WASM has one integer width the host understands, and rustc lowers
//! every `i128` the contract's author wrote into pairs of `i64` limbs:
//! two parameters, two return slots, two stores, and — for the
//! operations the two-limb form cannot express inline — a call into
//! `compiler_builtins`. The source wrote `a * b / c`; the binary carries
//! three helper calls, ten limb values and a loop.
//!
//! This module is where the pipeline stops seeing limbs:
//!
//! - [`I128BuiltinPass`] recognises the `compiler_builtins` runtime
//!   helpers by body and rewrites each call as one arithmetic expression
//!   over [`Expr::WideJoin`](sordec_ir::Expr::WideJoin) operands.
//! - [`WideFoldPass`] cancels a join against its own limbs, which is the
//!   identity that lets a decoded parameter flow through arithmetic and
//!   back into an encode without any limb reaching the output.
//!
//! Neither pass changes what the contract computes. A join is the value
//! the limbs already denoted, and the builtins are total functions with a
//! documented contract, so the rewrite is a change of spelling.

pub mod i128_builtins;
pub mod wide_fold;

pub use i128_builtins::I128BuiltinPass;
pub use wide_fold::WideFoldPass;
