//! Retire a merge that only one value still reaches.
//!
//! A block parameter exists to merge values arriving along different edges.
//! When the elisions have deleted all but one of those edges — the constant
//! branch fold keeping one arm of an SDK `Option` branch is the common case —
//! the parameter merges nothing:
//!
//! ```text
//! let mut v26: i64;                 let v13 = get(&k).unwrap_or(0u32);
//! let v13 = get(&k).unwrap_or(0);   …  v13 …
//! v26 = v13;                  →
//! … v26 …
//! ```
//!
//! and it is worse than noise: it carries the type the lowering gave the
//! merge (`i64`, the wasm register), not the type of the one value it now
//! holds (`u32`), so arithmetic on it no longer behaves like the source's.
//!
//! # The rewrite
//!
//! A parameter every remaining transfer assigns the same value is replaced
//! by that value at every read, and its assignments are dropped; the
//! parameter itself is left unread. Transfers of the parameter to itself (a
//! loop that carries it unchanged) do not count as a second value — the
//! standard trivial-φ rule.
//!
//! # Why it is exact
//!
//! Every remaining edge into the merge carries that one value, so on every
//! path the parameter holds it. The value dominates the merge because the
//! only way to reach the merge is through its assignment.

use std::collections::{HashMap, HashSet};

use sordec_common::{Provenance, ProvenanceSource, ValueId};
use sordec_ir::{Expr, HighFunction, HighIr, Region};

use crate::dataflow::resolve_use;
use crate::metrics_catalog::REFINE_TRIVIAL_PHIS as M_RETIRED;
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "refine-trivial-phi";

/// Replaces the reads of single-source merges with their one value.
#[derive(Debug, Default, Clone, Copy)]
pub struct TrivialPhiPass;

impl Pass<HighIr> for TrivialPhiPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            // A merge nothing reads takes no assignments. The value is
            // still merged by the CFG, but the region need not say so,
            // and while it does the arms that feed it cannot be seen as
            // doing nothing — which is what keeps a branch alive after
            // the elisions have taken everything that read it.
            let unread = unread_phis(func);
            if !unread.is_empty() {
                let region = std::mem::replace(&mut func.region, Region::Unreachable);
                func.region = drop_assignments(region, &unread);
                for id in &unread {
                    if let Some(b) = func.bindings.get_mut(*id) {
                        b.expr = Expr::Phi { incoming: Vec::new() };
                        b.add_provenance(Provenance::new(
                            PASS_NAME,
                            ProvenanceSource::DataFlow,
                            "a merge nothing reads: its assignments are gone",
                        ));
                    }
                }
                result.changed = true;
            }
            let retired = plan(func);
            if retired.is_empty() {
                continue;
            }
            let phis: HashSet<ValueId> = retired.keys().copied().collect();
            let region = std::mem::replace(&mut func.region, Region::Unreachable);
            func.region = substitute(drop_assignments(region, &phis), &retired);
            let ids: Vec<ValueId> = func.bindings.iter().map(|(id, _)| id).collect();
            for id in ids {
                if let Some(b) = func.bindings.get_mut(id)
                    && !matches!(b.expr, Expr::Phi { .. })
                {
                    b.expr.for_each_value_use_mut(|u| {
                        if let Some(s) = retired.get(u) {
                            *u = *s;
                        }
                    });
                }
            }
            for site in &mut func.returns {
                for v in site.iter_mut() {
                    if let Some(s) = retired.get(v) {
                        *v = *s;
                    }
                }
            }
            for phi in retired.keys() {
                if let Some(b) = func.bindings.get_mut(*phi) {
                    b.add_provenance(Provenance::new(
                        PASS_NAME,
                        ProvenanceSource::DataFlow,
                        "merge reached by one value only: its reads now name that value",
                    ));
                }
                result.metrics.increment(M_RETIRED, 1);
                result.changed = true;
            }
        }
        result
    }
}

/// Each merge the region assigns exactly one value (itself aside), mapped
/// to that value.
fn plan(func: &HighFunction) -> HashMap<ValueId, ValueId> {
    let mut sources: HashMap<ValueId, HashSet<ValueId>> = HashMap::new();
    collect(&func.region, &mut sources);
    sources
        .into_iter()
        .filter_map(|(phi, srcs)| {
            if !matches!(func.bindings.get(phi).map(|b| &b.expr), Some(Expr::Phi { .. })) {
                return None;
            }
            let others: HashSet<ValueId> = srcs.into_iter().map(|s| resolve_use(func, s)).filter(|s| *s != phi).collect();
            let mut it = others.into_iter();
            match (it.next(), it.next()) {
                (Some(only), None) => Some((phi, only)),
                _ => None,
            }
        })
        .collect()
}

fn collect(region: &Region, sources: &mut HashMap<ValueId, HashSet<ValueId>>) {
    region.for_each_node(|node| {
        if let Region::Transfer { transfer, .. } | Region::Break { transfer, .. } | Region::Continue { transfer, .. } =
            node
        {
            for &(phi, source) in transfer {
                sources.entry(phi).or_default().insert(source);
            }
        }
    });
}

/// `region` with every read of a retired merge — conditions, selectors,
/// returned values, transfer sources — naming its one value instead.
fn substitute(region: Region, retired: &HashMap<ValueId, ValueId>) -> Region {
    let map = |v: ValueId| retired.get(&v).copied().unwrap_or(v);
    let sources = |transfer: Vec<(ValueId, ValueId)>| -> Vec<(ValueId, ValueId)> {
        transfer.into_iter().map(|(phi, src)| (phi, map(src))).collect()
    };
    let recurse = |r: Region| substitute(r, retired);
    match region {
        Region::Transfer { target, transfer } => Region::Transfer { target, transfer: sources(transfer) },
        Region::Break { target, transfer } => Region::Break { target, transfer: sources(transfer) },
        Region::Continue { target, transfer } => Region::Continue { target, transfer: sources(transfer) },
        Region::Return { values } => Region::Return { values: values.into_iter().map(map).collect() },
        Region::Sequence(items) => Region::Sequence(items.into_iter().map(recurse).collect()),
        Region::Scope { out, body } => Region::Scope { out, body: Box::new(recurse(*body)) },
        Region::Loop { header, body, kind } => Region::Loop { header, body: Box::new(recurse(*body)), kind },
        Region::If { cond, then_region, else_region } => Region::If {
            cond: map(cond),
            then_region: Box::new(recurse(*then_region)),
            else_region: else_region.map(|e| Box::new(recurse(*e))),
        },
        Region::Switch { index, arms, default, dispatch } => Region::Switch {
            index: map(index),
            arms: arms
                .into_iter()
                .map(|mut arm| {
                    arm.body = recurse(arm.body);
                    arm
                })
                .collect(),
            default: Box::new(recurse(*default)),
            dispatch: dispatch.map(map),
        },
        leaf => leaf,
    }
}

/// `region` with every assignment to a retired merge removed.
/// Merges no binding and no region node reads.
///
/// A `Transfer`'s destination is not a read of the merge — it is the
/// assignment this looks for — so the walk counts the sources only.
fn unread_phis(func: &HighFunction) -> HashSet<ValueId> {
    let mut read: HashSet<ValueId> = HashSet::new();
    let note = |func: &HighFunction, v: ValueId, read: &mut HashSet<ValueId>| {
        read.insert(v);
        read.insert(resolve_use(func, v));
    };
    for (_, b) in func.bindings.iter() {
        b.expr.for_each_value_use(|u| note(func, u, &mut read));
    }
    func.region.for_each_node(|node| match node {
        Region::If { cond, .. } => note(func, *cond, &mut read),
        Region::Switch { index, dispatch, .. } => {
            note(func, *index, &mut read);
            if let Some(d) = dispatch {
                note(func, *d, &mut read);
            }
        }
        Region::Return { values } => {
            for v in values {
                note(func, *v, &mut read);
            }
        }
        Region::Transfer { transfer, .. }
        | Region::Break { transfer, .. }
        | Region::Continue { transfer, .. } => {
            for (_, src) in transfer {
                note(func, *src, &mut read);
            }
        }
        _ => {}
    });
    func.bindings
        .iter()
        .filter(|(id, b)| {
            matches!(&b.expr, Expr::Phi { incoming } if !incoming.is_empty()) && !read.contains(id)
        })
        .map(|(id, _)| id)
        .collect()
}

fn drop_assignments(region: Region, retired: &HashSet<ValueId>) -> Region {
    let keep = |transfer: Vec<(ValueId, ValueId)>| -> Vec<(ValueId, ValueId)> {
        transfer.into_iter().filter(|(phi, _)| !retired.contains(phi)).collect()
    };
    let recurse = |r: Region| drop_assignments(r, retired);
    match region {
        Region::Transfer { target, transfer } => Region::Transfer { target, transfer: keep(transfer) },
        Region::Break { target, transfer } => Region::Break { target, transfer: keep(transfer) },
        Region::Continue { target, transfer } => Region::Continue { target, transfer: keep(transfer) },
        Region::Sequence(items) => Region::Sequence(items.into_iter().map(recurse).collect()),
        Region::Scope { out, body } => Region::Scope { out, body: Box::new(recurse(*body)) },
        Region::Loop { header, body, kind } => Region::Loop { header, body: Box::new(recurse(*body)), kind },
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
        leaf => leaf,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};
    use sordec_common::{BlockId, IrId};
    use sordec_ir::{IrType, KnownType, Literal};

    /// `v1 = 7u32; v2 = phi; <transfers>; return v2`.
    fn shape(transfers: Vec<(u32, u32)>) -> HighFunction {
        let mut f = func_with(
            vec![
                Expr::Literal(Literal::I64(3)),  // v0
                Expr::Literal(Literal::I64(7)),  // v1
                Expr::Phi { incoming: vec![] }, // v2
            ],
            vec![],
            vec![0, 1],
        );
        f.bindings.get_mut(v(1)).unwrap().ty = IrType::Known(KnownType::U32);
        let mut items = vec![Region::Basic(BlockId::from_index(0))];
        for (phi, src) in transfers {
            items.push(Region::Transfer { target: BlockId::from_index(1), transfer: vec![(v(phi), v(src))] });
        }
        items.push(Region::Return { values: vec![v(2)] });
        f.region = Region::Sequence(items);
        f
    }

    #[test]
    fn a_merge_one_value_reaches_is_read_as_that_value() {
        let mut m = module(vec![shape(vec![(2, 1)])]);
        assert!(TrivialPhiPass.run(&mut m).changed);
        let f = &m.functions[0];
        let mut returned = Vec::new();
        f.region.for_each_node(|n| {
            if let Region::Return { values } = n {
                returned.extend(values.iter().copied());
            }
        });
        assert_eq!(returned, vec![v(1)], "the return reads the value, not the merge");
        let mut assigns = 0;
        m.functions[0].region.for_each_node(|n| {
            if let Region::Transfer { transfer, .. } = n {
                assigns += transfer.len();
            }
        });
        assert_eq!(assigns, 0, "its assignment is gone");
    }

    #[test]
    fn a_merge_of_two_values_stays() {
        let mut m = module(vec![shape(vec![(2, 1), (2, 0)])]);
        assert!(!TrivialPhiPass.run(&mut m).changed);
    }

    /// A loop carrying the merge unchanged is not a second value.
    #[test]
    fn a_self_assignment_does_not_count() {
        let mut m = module(vec![shape(vec![(2, 1), (2, 2)])]);
        assert!(TrivialPhiPass.run(&mut m).changed);
    }
}
