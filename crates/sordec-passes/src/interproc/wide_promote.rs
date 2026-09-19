//! Give a helper back the wide value it returns in two registers.
//!
//! WASM has no 128-bit type, so a Rust helper returning an `i128` returns
//! its two halves. rustc picks multi-value where it can, and what reaches
//! us is a function of two `i64`s and a caller that puts them back
//! together:
//!
//! ```text
//! fn get_shares(..) -> (i64, i64) {       fn get_shares(..) -> i128 {
//!     let s = …;                  →           let s = …;
//!     return wide_lo(s), wide_hi(s)            return s
//! }                                       }
//!
//! let t = get_shares(..);                 let t = get_shares(..);
//! (t.1 as i128) << 64 | t.0 as u64        t
//! ```
//!
//! Left alone it costs twice: the helper's signature is wrong, and every
//! arithmetic and comparison the caller does on the value stays split
//! across its halves, where no recognizer can see it as one number. A
//! `i128` zero test compiled to `(lo | hi) == 0` is unreadable until the
//! halves have a whole to belong to.
//!
//! # The rewrite
//!
//! The callee returns the value its halves were taken from. At each call
//! site the projection that read a half becomes that half *of the call* —
//! `t.0` is `wide_lo(t)` — so nothing downstream changes meaning, and the
//! caller that immediately rejoins them meets the existing rule that a
//! join of a value's own limbs is the value.
//!
//! # Why it is exact
//!
//! Only a function whose every `return` yields `wide_lo(x)` and
//! `wide_hi(x)` of one `x`, in the same two positions, qualifies. The
//! halves are recoverable from the whole by definition, so a caller can
//! compute exactly what it could before. An entrypoint is never promoted:
//! its shape is the contract's ABI, not a compiler choice.

use std::collections::HashMap;

use sordec_common::{FuncId, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{Expr, HighFunction, HighIr, IrType, KnownType, Region, UnaryOp};

use crate::dataflow::resolve_use;
use crate::metrics_catalog::INTERPROC_WIDE_RETURNS as M_WIDE;
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "interproc-wide-promote";

/// Promotes a two-register wide return to the value itself.
#[derive(Debug, Default, Clone, Copy)]
pub struct WideReturnPromotePass;

/// Which returned position holds which half.
#[derive(Clone, Copy)]
struct Halves {
    lo: u32,
    hi: u32,
}

impl Pass<HighIr> for WideReturnPromotePass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let promoted: HashMap<FuncId, Halves> =
            ir.functions.iter().filter_map(|f| halves(f).map(|h| (f.id, h))).collect();
        if promoted.is_empty() {
            return result;
        }
        for func in &mut ir.functions {
            if let Some(h) = promoted.get(&func.id).copied() {
                narrow_returns(func, h);
                result.metrics.increment(M_WIDE, 1);
                result.changed = true;
            }
            // Every call site: the projection that read a half is that
            // half of the call.
            let reads: Vec<(ValueId, UnaryOp, ValueId)> = func
                .bindings
                .iter()
                .filter_map(|(id, b)| {
                    let Expr::Project { value, index } = &b.expr else {
                        return None;
                    };
                    let call = resolve_use(func, *value);
                    let Expr::Call { target, .. } = &func.bindings.get(call)?.expr else {
                        return None;
                    };
                    let h = promoted.get(target)?;
                    let op = match *index {
                        i if i == h.lo => UnaryOp::WideLo,
                        i if i == h.hi => UnaryOp::WideHi,
                        _ => return None,
                    };
                    Some((id, op, call))
                })
                .collect();
            let calls: Vec<ValueId> = reads.iter().map(|(_, _, c)| *c).collect();
            for (id, op, call) in reads {
                if let Some(b) = func.bindings.get_mut(id) {
                    b.expr = Expr::Unary { op, value: call };
                    b.add_provenance(Provenance::new(
                        PASS_NAME,
                        ProvenanceSource::DataFlow,
                        "half of the wide value the helper returns",
                    ));
                    result.changed = true;
                }
            }
            for call in calls {
                if let Some(b) = func.bindings.get_mut(call) {
                    b.ty = IrType::Inferred(KnownType::I128);
                }
            }
        }
        result
    }
}

/// The two positions a function returns one wide value's halves in, when
/// every `return` it has agrees on them.
fn halves(func: &HighFunction) -> Option<Halves> {
    // An entrypoint's shape is the ABI, not a compiler choice.
    if func.signature.is_some() {
        return None;
    }
    let mut sites: Vec<Vec<ValueId>> = Vec::new();
    func.region.for_each_node(|node| {
        if let Region::Return { values } = node {
            sites.push(values.clone());
        }
    });
    if sites.is_empty() || sites.iter().any(|v| v.len() != 2) {
        return None;
    }
    let mut found: Option<Halves> = None;
    for values in &sites {
        let ends = [limb(func, values[0])?, limb(func, values[1])?];
        let here = match ends {
            [(UnaryOp::WideLo, a), (UnaryOp::WideHi, b)] if a == b => Halves { lo: 0, hi: 1 },
            [(UnaryOp::WideHi, a), (UnaryOp::WideLo, b)] if a == b => Halves { lo: 1, hi: 0 },
            _ => return None,
        };
        match found {
            Some(prev) if prev.lo != here.lo => return None,
            _ => found = Some(here),
        }
    }
    found
}

/// The half a value is, and of what.
fn limb(func: &HighFunction, value: ValueId) -> Option<(UnaryOp, ValueId)> {
    match &func.bindings.get(resolve_use(func, value))?.expr {
        Expr::Unary { op: op @ (UnaryOp::WideLo | UnaryOp::WideHi), value } => {
            Some((*op, resolve_use(func, *value)))
        }
        _ => None,
    }
}

/// Rewrite every return site to yield the whole value.
fn narrow_returns(func: &mut HighFunction, h: Halves) {
    let whole = |func: &HighFunction, values: &[ValueId]| -> Option<ValueId> {
        limb(func, *values.get(h.lo as usize)?).map(|(_, x)| x)
    };
    let mut rewritten: Vec<Vec<ValueId>> = Vec::new();
    for values in &func.returns {
        match whole(func, values) {
            Some(x) => rewritten.push(vec![x]),
            None => rewritten.push(values.clone()),
        }
    }
    func.returns = rewritten;
    let region = std::mem::replace(&mut func.region, Region::Unreachable);
    func.region = retarget(func, region, h);
}

fn retarget(func: &HighFunction, region: Region, h: Halves) -> Region {
    let mut recurse = |r: Region| retarget(func, r, h);
    match region {
        Region::Return { values } if values.len() == 2 => {
            match limb(func, values[h.lo as usize]) {
                Some((_, x)) => Region::Return { values: vec![x] },
                None => Region::Return { values },
            }
        }
        Region::Sequence(items) => Region::Sequence(items.into_iter().map(&mut recurse).collect()),
        Region::Scope { out, body } => Region::Scope { out, body: Box::new(recurse(*body)) },
        Region::Loop { header, body, kind } => {
            Region::Loop { header, body: Box::new(recurse(*body)), kind }
        }
        Region::If { cond, then_region, else_region } => Region::If {
            cond,
            then_region: Box::new(recurse(*then_region)),
            else_region: else_region.map(|e| Box::new(recurse(*e))),
        },
        Region::Switch { index, arms, default, dispatch } => Region::Switch {
            index,
            arms: arms
                .into_iter()
                .map(|mut arm| {
                    arm.body = recurse(arm.body);
                    arm
                })
                .collect(),
            default: Box::new(recurse(*default)),
            dispatch,
        },
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};
    use sordec_common::{BlockId, IrId};

    /// A helper returning `(wide_lo(x), wide_hi(x))`, and a caller that
    /// projects both halves. `split` returns two unrelated values instead.
    fn shape(split: bool) -> HighIr {
        let mut helper = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                      // v0 the wide value
                Expr::Unary { op: UnaryOp::WideLo, value: v(0) },     // v1
                Expr::Unary { op: UnaryOp::WideHi, value: v(0) },     // v2
                Expr::Phi { incoming: vec![] },                      // v3 an unrelated value
            ],
            vec![v(0)],
            vec![1, 2],
        );
        let hi = if split { v(3) } else { v(2) };
        helper.region = Region::Sequence(vec![
            Region::Basic(BlockId::from_index(0)),
            Region::Return { values: vec![v(1), hi] },
        ]);
        helper.returns = vec![vec![v(1), hi]];
        let mut caller = func_with(
            vec![
                Expr::Call { target: FuncId::from_index(0), args: vec![] }, // v0
                Expr::Project { value: v(0), index: 0 },                    // v1
                Expr::Project { value: v(0), index: 1 },                    // v2
            ],
            vec![],
            vec![0, 1, 2],
        );
        caller.id = FuncId::from_index(1);
        let mut m = module(vec![helper, caller]);
        m.functions[0].id = FuncId::from_index(0);
        m
    }

    #[test]
    fn a_helper_returning_both_halves_returns_the_value() {
        let mut m = shape(false);
        assert!(WideReturnPromotePass.run(&mut m).changed);
        assert_eq!(m.functions[0].returns, vec![vec![v(0)]]);
        assert!(matches!(&m.functions[0].region, Region::Sequence(items)
            if matches!(&items[1], Region::Return { values } if values == &vec![v(0)])));
        // The caller reads each half of the call itself.
        let caller = &m.functions[1];
        assert!(matches!(caller.bindings.get(v(1)).unwrap().expr, Expr::Unary { op: UnaryOp::WideLo, value } if value == v(0)));
        assert!(matches!(caller.bindings.get(v(2)).unwrap().expr, Expr::Unary { op: UnaryOp::WideHi, value } if value == v(0)));
    }

    /// Two values that are not halves of one number are a real pair.
    #[test]
    fn a_helper_returning_two_unrelated_values_is_left_alone() {
        let mut m = shape(true);
        assert!(!WideReturnPromotePass.run(&mut m).changed);
    }

    #[test]
    fn the_pass_is_idempotent() {
        let mut m = shape(false);
        assert!(WideReturnPromotePass.run(&mut m).changed);
        assert!(!WideReturnPromotePass.run(&mut m).changed);
    }
}
