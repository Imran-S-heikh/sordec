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
pub mod struct_arg;
pub mod symbol_args;
pub mod wide_param;
pub mod wide_promote;

pub use const_return::ConstReturnPass;
pub use inline::WrapperInlinePass;
pub use specialize::SpecializePass;
pub use struct_arg::StructArgPass;
pub use symbol_args::SymbolArgsPass;
pub use wide_param::WideParamPass;
pub use wide_promote::WideReturnPromotePass;


/// The functions some entrypoint can reach through scheduled calls.
///
/// Roots are the functions with an ABI signature or an export name; a
/// helper inlined at every site it had is in the module still, and its
/// own calls are not evidence about anyone's parameters.
pub(crate) fn live_functions(ir: &sordec_ir::HighIr) -> std::collections::HashSet<sordec_common::FuncId> {
    let mut live: std::collections::HashSet<sordec_common::FuncId> = ir
        .functions
        .iter()
        .filter(|f| f.signature.is_some() || f.name.is_some())
        .map(|f| f.id)
        .collect();
    let mut frontier: Vec<sordec_common::FuncId> = live.iter().copied().collect();
    while let Some(id) = frontier.pop() {
        let Some(func) = ir.function(id) else { continue };
        for v in crate::marshalling::sret::emission_order(func) {
            if let Some(sordec_ir::Expr::Call { target, .. }) = func.bindings.get(v).map(|b| &b.expr)
                && live.insert(*target)
            {
                frontier.push(*target);
            }
        }
    }
    live
}
