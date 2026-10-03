//! Collapse the SDK's two-way muxed-address dispatch into
//! `to_muxed.address()`.
//!
//! A `MuxedAddress` parameter arrives as either of two object tags — a
//! plain `AddressObject` (77) or a `MuxedAddressObject` (78) — and the
//! SDK's `address()` inlines into a dispatch on which one it got:
//!
//! ```text
//! match (to_muxed as i32 & 255) - 77 {   ← the argument's tag check
//!     0 => is_muxed = 0,
//!     1 => is_muxed = 1,
//!     _ => unreachable,
//! }
//! …
//! if is_muxed == 0 { to = to_muxed }      ← a plain address is itself
//! else { to = get_address_from_muxed_address(to_muxed) }
//! ```
//!
//! Neither half compiles. `to_muxed as i32` casts a `MuxedAddress`, and
//! `to = to_muxed` puts a `MuxedAddress` where an `Address` goes. The
//! source wrote neither — it wrote `let to = to_muxed.address();`.
//!
//! ## Why the collapse is sound
//!
//! **The branch.** Its arms are `to_muxed` and the host's extraction of
//! the address *from* `to_muxed`. `MuxedAddress::address()` is defined as
//! exactly that choice, so the whole `if` is one call to it — and that is
//! how the backend spells the extraction. Nothing about the flag's value
//! needs checking for this: whichever arm runs, the result is
//! `to_muxed.address()`.
//!
//! **The dispatch.** It is the argument's type check — two tags allowed,
//! anything else traps — on an entrypoint parameter. That is the same
//! standing as every other argument guard `super::guard` removes:
//! `#[contractimpl]` regenerates it from the declared type, so the source
//! never wrote it. It is removed only alongside a branch the pass also
//! rewrites, and only on a parameter, so a dispatch with any other job is
//! left alone.

use std::collections::HashSet;

use sordec_common::{Provenance, ProvenanceSource, ValueId};
use sordec_ir::{
    AddressOpKind, BinaryOp, Expr, HighFunction, HighIr, KnownOp, Literal, Region, SemanticOp,
    UnaryOp,
};

use crate::dataflow::resolve_use;
use crate::pass::{Pass, PassResult};
use crate::val_abi::TAG_ADDRESS_OBJECT;

/// Pass name.
pub const PASS_NAME: &str = "marshalling-muxed-address";

/// Dispatches collapsed into `.address()`.
const M_COLLAPSED: &str = "marshalling_muxed_address_collapsed";

/// Rewrites the inlined `MuxedAddress::address()` back into the call.
#[derive(Debug, Default, Clone, Copy)]
pub struct MuxedAddressPass;

impl Pass<HighIr> for MuxedAddressPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            // Parameters whose extraction branch is found. Only these have
            // their tag dispatch removed.
            let mut collapsed: HashSet<ValueId> = HashSet::new();
            func.region.for_each_node(|node| {
                if let Some(m) = extraction_branch(func, node) {
                    collapsed.insert(m);
                }
            });
            collapsed.retain(|m| func.params.contains(m));
            if collapsed.is_empty() {
                continue;
            }
            let region = std::mem::replace(&mut func.region, Region::Unreachable);
            let mut count = 0_i64;
            func.region = rewrite(func, region, &collapsed, &mut count);
            if count > 0 {
                result.metrics.increment(M_COLLAPSED, count);
                result.changed = true;
                note_extractions(func, &collapsed);
            }
        }
        result
    }
}

/// The muxed parameter an `if` extracts the address of, when the `if` is
/// the `to_muxed` / `get_address_from_muxed_address(to_muxed)` choice.
fn extraction_branch(func: &HighFunction, node: &Region) -> Option<ValueId> {
    let Region::If {
        then_region,
        else_region: Some(else_region),
        ..
    } = node
    else {
        return None;
    };
    let (then_phi, then_src) = sole_transfer(then_region)?;
    let (else_phi, else_src) = sole_transfer(else_region)?;
    if then_phi != else_phi {
        return None;
    }
    let m = resolve_use(func, then_src);
    match &func.bindings.get(resolve_use(func, else_src))?.expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::AddressConversion {
            kind: AddressOpKind::GetAddressFromMuxedAddress,
            args,
        })) if args.first().is_some_and(|a| resolve_use(func, *a) == m) => Some(m),
        _ => None,
    }
}

/// The one phi transfer an arm makes, when it makes exactly one.
fn sole_transfer(region: &Region) -> Option<(ValueId, ValueId)> {
    let mut found = None;
    let mut count = 0;
    region.for_each_node(|n| {
        if let Region::Transfer { transfer, .. } = n {
            for pair in transfer {
                count += 1;
                found = Some(*pair);
            }
        }
    });
    (count == 1).then_some(found).flatten()
}

/// The parameter a `switch` dispatches on the object tag of, rebased so
/// that `AddressObject` is case 0 — `(m as i32 & 255) - 77`.
fn tag_dispatch(func: &HighFunction, index: ValueId) -> Option<ValueId> {
    let Expr::Binary { op: BinaryOp::Add, lhs, rhs } = &func.bindings.get(resolve_use(func, index))?.expr
    else {
        return None;
    };
    let offset = int_literal(func, *rhs)?;
    if offset != -i64::from(TAG_ADDRESS_OBJECT) {
        return None;
    }
    let Expr::Binary { op: BinaryOp::BitAnd, lhs: masked, rhs: mask } =
        &func.bindings.get(resolve_use(func, *lhs))?.expr
    else {
        return None;
    };
    if int_literal(func, *mask)? != 255 {
        return None;
    }
    match &func.bindings.get(resolve_use(func, *masked))?.expr {
        Expr::Unary { op: UnaryOp::Wrap32, value } => Some(resolve_use(func, *value)),
        _ => None,
    }
}

fn int_literal(func: &HighFunction, v: ValueId) -> Option<i64> {
    match &func.bindings.get(resolve_use(func, v))?.expr {
        Expr::Literal(Literal::I32(n)) => Some(i64::from(*n)),
        Expr::Literal(Literal::I64(n)) => Some(*n),
        _ => None,
    }
}

/// Whether a switch is the two-tag check: exactly cases 0 and 1, and a
/// default that traps.
fn is_two_tag_check(arms: &[sordec_ir::SwitchArm], default: &Region) -> bool {
    let mut cases: Vec<u32> = arms.iter().flat_map(|a| a.cases.iter().copied()).collect();
    cases.sort_unstable();
    cases == [0, 1] && matches!(default, Region::Unreachable | Region::Panic { .. })
}

/// Whether the flag a dispatch sets is read only by the one branch this
/// pass collapses.
///
/// token-v23's `transfer` reads it twice: once to pick the address, and
/// again to decide whether to read the muxed *id*. Removing the dispatch
/// then leaves the second reader with a flag nobody assigns — the
/// dispatch had another job, which is exactly the case the module doc
/// promises to leave alone.
fn flag_only_feeds_extraction(func: &HighFunction, arms: &[sordec_ir::SwitchArm]) -> bool {
    let flags: HashSet<ValueId> = arms
        .iter()
        .filter_map(|arm| sole_transfer(&arm.body).map(|(phi, _)| phi))
        .collect();
    let [flag] = flags.into_iter().collect::<Vec<_>>()[..] else {
        return false;
    };
    let readers = func
        .bindings
        .iter()
        .filter(|(_, b)| {
            let mut reads = false;
            b.expr.for_each_value_use(|v| reads |= v == flag);
            reads
        })
        .count();
    readers <= 1
}

fn rewrite(
    func: &HighFunction,
    region: Region,
    collapsed: &HashSet<ValueId>,
    count: &mut i64,
) -> Region {
    match region {
        Region::Switch { ref index, ref arms, ref default, .. }
            if is_two_tag_check(arms, default)
                && tag_dispatch(func, *index).is_some_and(|m| collapsed.contains(&m))
                && flag_only_feeds_extraction(func, arms) =>
        {
            Region::Sequence(vec![])
        }
        node @ Region::If { .. } if extraction_branch(func, &node).is_some_and(|m| collapsed.contains(&m)) => {
            let Region::If { else_region: Some(e), .. } = node else {
                unreachable!("extraction_branch matched an if with an else");
            };
            *count += 1;
            *e
        }
        Region::Sequence(items) => Region::Sequence(
            items
                .into_iter()
                .map(|i| rewrite(func, i, collapsed, count))
                .flat_map(|r| match r {
                    Region::Sequence(inner) => inner,
                    other => vec![other],
                })
                .collect(),
        ),
        Region::If { cond, then_region, else_region } => Region::If {
            cond,
            then_region: Box::new(rewrite(func, *then_region, collapsed, count)),
            else_region: else_region.map(|e| Box::new(rewrite(func, *e, collapsed, count))),
        },
        Region::Scope { out, body } => Region::Scope {
            out,
            body: Box::new(rewrite(func, *body, collapsed, count)),
        },
        Region::Loop { header, body, kind } => Region::Loop {
            header,
            body: Box::new(rewrite(func, *body, collapsed, count)),
            kind,
        },
        Region::Switch { index, arms, default, dispatch } => Region::Switch {
            index,
            arms: arms
                .into_iter()
                .map(|mut arm| {
                    let body = std::mem::replace(&mut arm.body, Region::Unreachable);
                    arm.body = rewrite(func, body, collapsed, count);
                    arm
                })
                .collect(),
            default: Box::new(rewrite(func, *default, collapsed, count)),
            dispatch,
        },
        leaf => leaf,
    }
}

/// Record the collapse on each extraction it now stands for.
fn note_extractions(func: &mut HighFunction, collapsed: &HashSet<ValueId>) {
    let ids: Vec<ValueId> = func
        .bindings
        .iter()
        .filter_map(|(id, b)| match &b.expr {
            Expr::Semantic(SemanticOp::Known(KnownOp::AddressConversion {
                kind: AddressOpKind::GetAddressFromMuxedAddress,
                args,
            })) if args.first().is_some_and(|a| collapsed.contains(&resolve_use(func, *a))) => Some(id),
            _ => None,
        })
        .collect();
    for id in ids {
        if let Some(b) = func.bindings.get_mut(id) {
            b.add_provenance(Provenance::new(
                PASS_NAME,
                ProvenanceSource::SdkPattern,
                "`MuxedAddress::address()`: the SDK's two-tag dispatch and its plain-address \
                 arm, collapsed into the call they implement",
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{module, v};
    use sordec_common::{Arena, BlockId, FuncId, IrId, UnknownReason};
    use sordec_ir::{Binding, HighBlock, IrType, SwitchArm};

    fn bb(i: u32) -> BlockId {
        BlockId::from_index(i)
    }

    /// `if flag == 0 { phi = m } else { phi = get_address_from_muxed(m) }`
    /// preceded by the two-tag dispatch that sets `flag`, with `extra_reader`
    /// adding a second binding that reads `flag`.
    fn shape(extra_reader: bool) -> sordec_ir::HighFunction {
        let mut exprs = vec![
            Expr::Phi { incoming: vec![] },                       // v0  m (param)
            Expr::Unary { op: UnaryOp::Wrap32, value: v(0) },     // v1
            Expr::Literal(Literal::I32(255)),                     // v2
            Expr::Binary { op: BinaryOp::BitAnd, lhs: v(1), rhs: v(2) }, // v3
            Expr::Literal(Literal::I32(-77)),                     // v4
            Expr::Binary { op: BinaryOp::Add, lhs: v(3), rhs: v(4) },    // v5 index
            Expr::Literal(Literal::I32(0)),                       // v6
            Expr::Literal(Literal::I32(1)),                       // v7
            Expr::Phi { incoming: vec![] },                       // v8  flag
            Expr::Unary { op: UnaryOp::Eqz, value: v(8) },        // v9  cond
            Expr::Semantic(SemanticOp::Known(KnownOp::AddressConversion {
                kind: AddressOpKind::GetAddressFromMuxedAddress,
                args: vec![v(0)],
            })),                                                  // v10
            Expr::Phi { incoming: vec![] },                       // v11 result
        ];
        if extra_reader {
            exprs.push(Expr::Binary { op: BinaryOp::Ne, lhs: v(8), rhs: v(6) }); // v12
        }
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        for expr in exprs {
            let id = ValueId::from_index(bindings.len() as u32);
            bindings.push(Binding::new(
                id,
                IrType::Unknown(UnknownReason::InsufficientEvidence),
                expr,
                Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
            ));
        }
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        blocks.push(HighBlock { id: bb(0), bindings: vec![v(1), v(2), v(3), v(4), v(5), v(6), v(7), v(9)] });
        blocks.push(HighBlock { id: bb(1), bindings: vec![v(10)] });
        let transfer = |phi: u32, src: u32| Region::Transfer { target: bb(2), transfer: vec![(v(phi), v(src))] };
        sordec_ir::HighFunction {
            id: FuncId::from_index(0),
            name: None,
            signature: None,
            aliases: Vec::new(),
            blocks,
            bindings,
            region: Region::Sequence(vec![
                Region::Basic(bb(0)),
                Region::Switch {
                    index: v(5),
                    arms: vec![
                        SwitchArm { cases: vec![0], body: transfer(8, 6) },
                        SwitchArm { cases: vec![1], body: transfer(8, 7) },
                    ],
                    default: Box::new(Region::Unreachable),
                    dispatch: None,
                },
                Region::If {
                    cond: v(9),
                    then_region: Box::new(transfer(11, 0)),
                    else_region: Some(Box::new(Region::Sequence(vec![
                        Region::Basic(bb(1)),
                        transfer(11, 10),
                    ]))),
                },
            ]),
            params: vec![v(0)],
            returns: vec![],
        }
    }

    fn has_switch(r: &Region) -> bool {
        let mut found = false;
        r.for_each_node(|n| found |= matches!(n, Region::Switch { .. }));
        found
    }

    fn has_if(r: &Region) -> bool {
        let mut found = false;
        r.for_each_node(|n| found |= matches!(n, Region::If { .. }));
        found
    }

    /// The whole inlined `address()` — dispatch and branch — becomes the
    /// extraction alone, which the backend spells `to_muxed.address()`.
    #[test]
    fn the_dispatch_and_branch_collapse_to_the_call() {
        let mut ir = module(vec![shape(false)]);
        assert!(MuxedAddressPass.run(&mut ir).changed);
        let f = &ir.functions[0];
        assert!(!has_if(&f.region), "the branch is gone");
        assert!(!has_switch(&f.region), "and so is the tag check");
    }

    /// The half that matters. When the flag the dispatch sets is read
    /// again — token-v23 reads it to decide whether to fetch the muxed id —
    /// the dispatch has another job and stays. The branch still collapses.
    #[test]
    fn a_flag_with_another_reader_keeps_its_dispatch() {
        let mut ir = module(vec![shape(true)]);
        assert!(MuxedAddressPass.run(&mut ir).changed);
        let f = &ir.functions[0];
        assert!(!has_if(&f.region), "the branch still collapses");
        assert!(has_switch(&f.region), "but the dispatch is kept");
    }
}
