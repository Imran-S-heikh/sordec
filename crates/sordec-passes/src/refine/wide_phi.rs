//! Give a merged `i128` back its whole, when only its halves were merged.
//!
//! The third place the halves come apart, after a helper's return
//! ([`crate::WideReturnPromotePass`]) and its parameters
//! ([`crate::WideParamPass`]): a branch. Each arm has an `i128`, the arms
//! merge, and wasm merges two registers rather than one value.
//!
//! ```text
//! lo = phi[bb1 -> wide_lo(a), bb2 -> wide_lo(b)]      w  = phi[bb1 -> a, bb2 -> b]
//! hi = phi[bb1 -> wide_hi(a), bb2 -> wide_hi(b)]  →   lo = wide_lo(w)
//!                                                     hi = wide_hi(w)
//! ```
//!
//! This is what leaves dex's `get_deposit_amounts` comparing two
//! unrelated registers against zero, which is a hole, and the branch it
//! guards keeping the polarity wasm gave it because there is no
//! comparison to invert.
//!
//! # The surgery this needs
//!
//! A merge is a *block parameter*: the region's `Transfer`s name it as a
//! destination. So it cannot simply become an ordinary expression — the
//! first attempt at this pass did exactly that and the validator caught
//! it as `BadTransfer`. The assignments have to move: each transfer that
//! set the two halves now sets the whole instead, and the two old
//! parameters become ordinary bindings, scheduled at the top of the block
//! they were parameters of.
//!
//! # Why it is exact
//!
//! Per incoming edge. On the edge from `bb` the pair carries the halves
//! of one value, so a merge of those values has those halves on that
//! edge, and the halves of a value are recoverable from it by definition.
//! Every reader of either half still reads its own half.
//!
//! # Gates
//!
//! - **The same edges, and every edge agrees.** On each one the pair must
//!   be `wide_lo` and `wide_hi` of a single value.
//! - **Every assignment accounted for.** Each transfer naming one half
//!   must name the other, with halves of one value; a lone half means the
//!   pair is not what it looks like, and the rewrite is abandoned.
//! - **One partner each**, so a run cannot produce two merges naming the
//!   same half.

use std::collections::{HashMap, HashSet};

use sordec_common::{BlockId, IrId, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{Binding, Expr, HighFunction, HighIr, IrType, KnownType, Region, UnaryOp};

use crate::dataflow::resolve_use;
use crate::metrics_catalog::REFINE_WIDE_PHIS as M_PHIS;
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "refine-wide-phi";

/// Merges the whole where only the halves were merged.
#[derive(Debug, Default, Clone, Copy)]
pub struct WidePhiPass;

impl Pass<HighIr> for WidePhiPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            for Pair { lo, hi, incoming } in pairs(func) {
                let note = Provenance::new(
                    PASS_NAME,
                    ProvenanceSource::DataFlow,
                    "the value whose halves these two merges carried",
                );
                let whole = ValueId::from_index(func.bindings.len() as u32);
                func.bindings.push(Binding::new(
                    whole,
                    IrType::Inferred(KnownType::I128),
                    Expr::Phi { incoming },
                    note.clone(),
                ));
                // Move the assignments before touching the parameters: if
                // any transfer does not pair cleanly the whole rewrite is
                // off, and nothing has changed yet.
                let region = std::mem::replace(&mut func.region, Region::Unreachable);
                let (region, targets) = reassign(func, region, lo, hi, whole);
                func.region = region;
                let Some(targets) = targets else {
                    continue;
                };
                for (id, op) in [(lo, UnaryOp::WideLo), (hi, UnaryOp::WideHi)] {
                    if let Some(b) = func.bindings.get_mut(id) {
                        b.expr = Expr::Unary { op, value: whole };
                        b.add_provenance(note.clone());
                    }
                }
                // They are ordinary bindings now, so they need a place:
                // the top of the block they were parameters of.
                for target in targets {
                    if let Some(block) = func.blocks.get_mut(target) {
                        block.bindings.insert(0, hi);
                        block.bindings.insert(0, lo);
                        break;
                    }
                }
                result.metrics.increment(M_PHIS, 1);
                result.changed = true;
            }
        }
        result
    }
}

/// Rewrite every transfer that set the two halves to set the whole.
///
/// Returns the blocks those transfers targeted, or `None` when one of
/// them did not pair cleanly — in which case the region comes back
/// unchanged and the caller abandons the rewrite.
fn reassign(
    func: &HighFunction,
    region: Region,
    lo: ValueId,
    hi: ValueId,
    whole: ValueId,
) -> (Region, Option<HashSet<BlockId>>) {
    let mut targets = HashSet::new();
    let mut ok = true;
    let rebuilt = walk(func, region, lo, hi, whole, &mut targets, &mut ok);
    (rebuilt, ok.then_some(targets))
}

fn walk(
    func: &HighFunction,
    region: Region,
    lo: ValueId,
    hi: ValueId,
    whole: ValueId,
    targets: &mut HashSet<BlockId>,
    ok: &mut bool,
) -> Region {
    let recurse = |r: Region, ok: &mut bool, t: &mut HashSet<BlockId>| walk(func, r, lo, hi, whole, t, ok);
    let fix = |target: BlockId, transfer: Vec<(ValueId, ValueId)>, ok: &mut bool, t: &mut HashSet<BlockId>| {
        if !transfer.iter().any(|(d, _)| *d == lo || *d == hi) {
            return transfer;
        }
        let source = |want: ValueId| transfer.iter().find(|(d, _)| *d == want).map(|(_, s)| *s);
        let Some((src_lo, src_hi)) = source(lo).zip(source(hi)) else {
            *ok = false;
            return transfer;
        };
        let Some(value) = half(func, src_lo, UnaryOp::WideLo)
            .filter(|v| half(func, src_hi, UnaryOp::WideHi) == Some(*v))
        else {
            *ok = false;
            return transfer;
        };
        t.insert(target);
        let mut kept: Vec<(ValueId, ValueId)> =
            transfer.into_iter().filter(|(d, _)| *d != lo && *d != hi).collect();
        kept.push((whole, value));
        kept
    };
    match region {
        Region::Transfer { target, transfer } => {
            let transfer = fix(target, transfer, ok, targets);
            Region::Transfer { target, transfer }
        }
        Region::Break { target, transfer } => {
            let transfer = fix(target, transfer, ok, targets);
            Region::Break { target, transfer }
        }
        Region::Continue { target, transfer } => {
            let transfer = fix(target, transfer, ok, targets);
            Region::Continue { target, transfer }
        }
        Region::Sequence(items) => {
            Region::Sequence(items.into_iter().map(|i| recurse(i, ok, targets)).collect())
        }
        Region::Scope { out, body } => Region::Scope { out, body: Box::new(recurse(*body, ok, targets)) },
        Region::Loop { header, body, kind } => {
            Region::Loop { header, body: Box::new(recurse(*body, ok, targets)), kind }
        }
        Region::If { cond, then_region, else_region } => Region::If {
            cond,
            then_region: Box::new(recurse(*then_region, ok, targets)),
            else_region: else_region.map(|e| Box::new(recurse(*e, ok, targets))),
        },
        Region::Switch { index, arms, default, dispatch } => Region::Switch {
            index,
            arms: arms
                .into_iter()
                .map(|mut arm| {
                    arm.body = recurse(arm.body, ok, targets);
                    arm
                })
                .collect(),
            default: Box::new(recurse(*default, ok, targets)),
            dispatch,
        },
        leaf => leaf,
    }
}

/// One pair of half-merges and the values they carry, per edge.
struct Pair {
    lo: ValueId,
    hi: ValueId,
    incoming: Vec<(BlockId, ValueId)>,
}

/// Every pair of half-merges in `func`.
fn pairs(func: &HighFunction) -> Vec<Pair> {
    let phis: Vec<(ValueId, Vec<(BlockId, ValueId)>)> = func
        .bindings
        .iter()
        .filter_map(|(id, b)| match &b.expr {
            Expr::Phi { incoming } if !incoming.is_empty() => Some((id, incoming.clone())),
            _ => None,
        })
        .collect();
    let mut taken: HashSet<ValueId> = HashSet::new();
    let mut found = Vec::new();
    for (i, (lo, lo_in)) in phis.iter().enumerate() {
        if taken.contains(lo) {
            continue;
        }
        for (hi, hi_in) in &phis[i + 1..] {
            if taken.contains(hi) || lo_in.len() != hi_in.len() {
                continue;
            }
            // Either order: which of the two the arena happens to hold
            // first says nothing about which half it carries.
            let Some((low, high, wide)) = halves_of(func, lo_in, hi_in)
                .map(|w| (*lo, *hi, w))
                .or_else(|| halves_of(func, hi_in, lo_in).map(|w| (*hi, *lo, w)))
            else {
                continue;
            };
            taken.insert(low);
            taken.insert(high);
            found.push(Pair { lo: low, hi: high, incoming: wide });
            break;
        }
    }
    found
}

/// The values two merges carry the halves of, when every edge agrees.
fn halves_of(
    func: &HighFunction,
    lo_in: &[(BlockId, ValueId)],
    hi_in: &[(BlockId, ValueId)],
) -> Option<Vec<(BlockId, ValueId)>> {
    let by_block: HashMap<BlockId, ValueId> = hi_in.iter().copied().collect();
    (by_block.len() == hi_in.len()).then_some(())?;
    lo_in
        .iter()
        .map(|(block, lo)| {
            let whole = half(func, *lo, UnaryOp::WideLo)?;
            (half(func, *by_block.get(block)?, UnaryOp::WideHi)? == whole).then_some((*block, whole))
        })
        .collect()
}

/// The value this is the named half of.
fn half(func: &HighFunction, value: ValueId, want: UnaryOp) -> Option<ValueId> {
    match &func.bindings.get(resolve_use(func, value))?.expr {
        Expr::Unary { op, value } if *op == want => Some(resolve_use(func, *value)),
        _ => None,
    }
}
