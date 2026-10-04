//! Give a helper back the wide value it takes in two registers.
//!
//! The mirror of [`super::wide_promote`]. WASM has no 128-bit type, so a
//! helper taking an `i128` takes its two halves, and every caller splits
//! one before the call:
//!
//! ```text
//! fn write_allowance(.., lo, hi, ..)        fn write_allowance(.., amount: i128, ..)
//! write_allowance(.., wide_lo(a),     →     write_allowance(.., a, ..)
//!                     wide_hi(a), ..)
//! ```
//!
//! Until the halves have a whole, nothing inside the helper can be read
//! at its real width. `write_allowance`'s `if amount > 0` is a `select`
//! over two unrelated parameters, so it stays a hole — and the branch it
//! guards keeps the polarity wasm gave it rather than the one the source
//! wrote, because there is no comparison to invert.
//!
//! # Why it is exact
//!
//! Per call site. Each passes the two halves of one value, so a
//! parameter taking that value has exactly what the pair had, and the
//! halves are recoverable from it by definition. The callee keeps naming
//! each half, now of its own parameter.
//!
//! # Gates
//!
//! - **Every caller agrees**, and there is at least one. A helper nothing
//!   calls says nothing about its own parameters, and one caller passing
//!   something else is passing something else.
//! - **Not an entrypoint.** A `contractspecv0` signature is the ABI, not
//!   a compiler choice, and its shape is not ours to change.
//! - **The pair is adjacent in the ABI order the callers use.** Rewriting
//!   argument lists is only safe while every site agrees on which two
//!   positions merge.

use std::collections::HashMap;

use sordec_common::{FuncId, IrId, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{Binding, Expr, HighFunction, HighIr, IrType, KnownType, Region, UnaryOp};

use crate::dataflow::resolve_use;
use crate::metrics_catalog::INTERPROC_WIDE_PARAMS as M_PARAMS;
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "interproc-wide-param";

/// Promotes a two-register wide parameter to the value itself.
#[derive(Debug, Default, Clone, Copy)]
pub struct WideParamPass;

/// Which two parameter positions are the halves.
#[derive(Clone, Copy)]
struct Halves {
    lo: usize,
    hi: usize,
}

impl Pass<HighIr> for WideParamPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let promoted: HashMap<FuncId, Halves> = candidates(ir);
        if promoted.is_empty() {
            return result;
        }
        for func in &mut ir.functions {
            if let Some(h) = promoted.get(&func.id).copied() {
                take_the_whole(func, h);
                result.metrics.increment(M_PARAMS, 1);
                result.changed = true;
            }
            join_at_calls(func, &promoted);
        }
        result
    }
}

/// Helpers every caller hands two halves of one value.
///
/// Only callers that can run vote: a scheduled call, in a function some
/// entrypoint reaches. A wrapper inlined at every site stays in the module
/// with its own calls still passing its raw parameters — atomic_swap's
/// `move_token` — and counting it vetoed every live caller's agreement.
fn candidates(ir: &HighIr) -> HashMap<FuncId, Halves> {
    let live = super::live_functions(ir);
    let mut seen: HashMap<FuncId, Option<Halves>> = HashMap::new();
    for caller in ir.functions.iter().filter(|f| live.contains(&f.id)) {
        for id in crate::marshalling::sret::emission_order(caller) {
            let Some(binding) = caller.bindings.get(id) else { continue };
            let Expr::Call { target, args } = &binding.expr else {
                continue;
            };
            let here = pair_in(caller, args);
            let slot = seen.entry(*target).or_insert(here);
            // Every site must name the same two positions.
            if slot.map(|s| (s.lo, s.hi)) != here.map(|h| (h.lo, h.hi)) {
                *slot = None;
            }
        }
    }
    ir.functions
        .iter()
        .filter(|f| f.signature.is_none())
        .filter_map(|f| {
            let h = (*seen.get(&f.id)?)?;
            // The positions have to exist, and be two distinct ones.
            (h.lo != h.hi && h.lo < f.params.len() && h.hi < f.params.len()).then_some((f.id, h))
        })
        .collect()
}

/// The one pair of argument positions carrying the halves of a value.
fn pair_in(func: &HighFunction, args: &[ValueId]) -> Option<Halves> {
    let mut found: Option<Halves> = None;
    for (i, a) in args.iter().enumerate() {
        let Some(whole) = half(func, *a, UnaryOp::WideLo) else {
            continue;
        };
        for (j, b) in args.iter().enumerate() {
            if half(func, *b, UnaryOp::WideHi) == Some(whole) {
                // More than one pair is ambiguous; say nothing.
                if found.replace(Halves { lo: i, hi: j }).is_some() {
                    return None;
                }
            }
        }
    }
    found
}

/// Callee side: one parameter, and each old one is a half of it.
fn take_the_whole(func: &mut HighFunction, h: Halves) {
    let note = Provenance::new(
        PASS_NAME,
        ProvenanceSource::DataFlow,
        "the value whose halves this helper was handed",
    );
    let (lo, hi) = (func.params[h.lo], func.params[h.hi]);
    let whole = ValueId::from_index(func.bindings.len() as u32);
    func.bindings.push(Binding::new(
        whole,
        IrType::Inferred(KnownType::I128),
        Expr::Phi { incoming: Vec::new() },
        note.clone(),
    ));
    for (id, op) in [(lo, UnaryOp::WideLo), (hi, UnaryOp::WideHi)] {
        if let Some(b) = func.bindings.get_mut(id) {
            b.expr = Expr::Unary { op, value: whole };
            b.add_provenance(note.clone());
        }
    }
    // The old parameters are ordinary bindings now, so they need a place
    // in the schedule: the top of the first block, where the parameter
    // they read is available and everything that reads them follows.
    if let Some(entry) = first_block(&func.region)
        && let Some(block) = func.blocks.get_mut(entry)
    {
        block.bindings.insert(0, hi);
        block.bindings.insert(0, lo);
    }
    func.params[h.lo] = whole;
    func.params.remove(h.hi);
}

/// The block the region enters first.
fn first_block(region: &Region) -> Option<sordec_common::BlockId> {
    match region {
        Region::Basic(b) => Some(*b),
        Region::Sequence(items) => items.iter().find_map(first_block),
        Region::Scope { body, .. } | Region::Loop { body, .. } => first_block(body),
        _ => None,
    }
}

/// Caller side: hand over the whole instead of the halves.
fn join_at_calls(func: &mut HighFunction, promoted: &HashMap<FuncId, Halves>) {
    let edits: Vec<(ValueId, Halves, ValueId)> = func
        .bindings
        .iter()
        .filter_map(|(id, b)| {
            let Expr::Call { target, args } = &b.expr else {
                return None;
            };
            let h = *promoted.get(target)?;
            let whole = half(func, *args.get(h.lo)?, UnaryOp::WideLo)?;
            (half(func, *args.get(h.hi)?, UnaryOp::WideHi)? == whole).then_some((id, h, whole))
        })
        .collect();
    for (id, h, whole) in edits {
        if let Some(Expr::Call { args, .. }) = func.bindings.get_mut(id).map(|b| &mut b.expr) {
            args[h.lo] = whole;
            args.remove(h.hi);
        }
    }
}

/// The value this is the named half of.
fn half(func: &HighFunction, value: ValueId, want: UnaryOp) -> Option<ValueId> {
    match &func.bindings.get(resolve_use(func, value))?.expr {
        Expr::Unary { op, value } if *op == want => Some(resolve_use(func, *value)),
        _ => None,
    }
}
