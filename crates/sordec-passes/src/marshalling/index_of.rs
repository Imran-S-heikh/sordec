//! The `Option<u32>` a vec search hands back, read as one.
//!
//! # The shape
//!
//! `Vec::first_index_of` (and `last_index_of`) is the host's search,
//! converted on the way out:
//!
//! ```text
//! env.vec_first_index_of(self.obj, val).try_into_val(env).unwrap()  // -> Option<u32>
//! ```
//!
//! The host hands back `Void` when the item is absent and the index's
//! `U32Val` when it is there. The SDK's conversion is a test against
//! `Void`, then a tag check and a decode, and the source's
//! `if let Some(i) = v.first_index_of(&x) { v.remove(i) }` re-encodes the
//! index for `vec_del`:
//!
//! ```text
//! s = vec_first_index_of(v, x)
//! if s == Void { .. } else {
//!     if !has_tag(s, U32Val) { trap }
//!     i = val_decode(s)                      ← the u32
//!     .. vec_del(v, s & 0xFFFF_FFFF_0000_0004)
//! }
//! ```
//!
//! The emitter already spells the search as the SDK method and the `Void`
//! test as `is_none()`, so the search reads as the `Option<u32>` it is —
//! and the decode and the mask, left on the raw word, came out as a hole
//! and as an `Option<u32> & integer`.
//!
//! # The rewrite
//!
//! The search is typed `Option<u32>` (`Known`: the SDK method's return
//! type, which the emitter writes). On the present side of its `Void`
//! test, its decode becomes `s.unwrap()`, and the mask becomes the
//! `U32Val` of that unwrap. The `Void` test and the tag check stay.
//!
//! # Why it is exact
//!
//! The host's contract for both searches: the result is `Void` or the
//! `U32Val` of an index. So on the present side — inside the arm of an
//! `if` on `s == Void` (or `s != Void`) that runs when it is not `Void` —
//! `s` is a `U32Val`: tag `4` in its low byte, low 32 bits otherwise zero,
//! the index in the high 32. Then:
//!
//! - `val_decode(s)`, `s >> 32`, is the index: what `Some(i)` holds, and
//!   so `s.unwrap()`. It never traps there, since `s` is present.
//! - `s & 0xFFFF_FFFF_0000_0004` keeps the high 32 bits and bit 2, which
//!   is set (tag `4`) — `(i << 32) | 4`, the `U32Val` of `i`: the encode of
//!   the unwrap.
//!
//! # Gates
//!
//! - **The search**: `vec_first_index_of` or `vec_last_index_of`, not yet
//!   typed as anything but a word.
//! - **Every reader** is one of: a comparison with `Void` (`2`); a tag test;
//!   a decode or the mask above, each inside the present arm of an `if` on
//!   such a comparison; or a pure binding nothing reads. Anything else
//!   leaves the search alone, readers and all.

use std::collections::HashSet;

use sordec_common::{BlockId, IrId, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{
    BinaryOp, Binding, Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Region, SemanticOp, VecOpKind,
};

use super::sret::emission_order;
use crate::dataflow::{block_containing, resolve_use, trace_int};
use crate::effects::expr_effects;
use crate::metrics_catalog::MARSHALLING_INDEX_OF_OPTIONS as M_SEARCHES;
use crate::pass::{Pass, PassResult};
use crate::val_abi::TAG_VOID;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-index-of";

/// The mask that keeps a `U32Val`'s payload and its tag bit.
const U32VAL_MASK: i64 = 0xFFFF_FFFF_0000_0004_u64 as i64;

/// Reads a vec search's result as the `Option<u32>` the SDK makes of it.
#[derive(Debug, Default, Clone, Copy)]
pub struct IndexOfPass;

impl Pass<HighIr> for IndexOfPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            for site in plan(func) {
                apply(func, &site);
                result.metrics.increment(M_SEARCHES, 1);
                result.changed = true;
            }
        }
        result
    }
}

/// One search to read as an `Option<u32>`.
#[derive(Debug)]
struct Site {
    search: ValueId,
    /// Its decodes, each becoming the unwrap.
    decodes: Vec<ValueId>,
    /// Its masks, each becoming the `U32Val` of an unwrap.
    masks: Vec<ValueId>,
}

fn plan(func: &HighFunction) -> Vec<Site> {
    let order = emission_order(func);
    let mut sites = Vec::new();
    for &search in &order {
        let Some(b) = func.bindings.get(search) else { continue };
        if !matches!(
            b.expr,
            Expr::Semantic(SemanticOp::Known(KnownOp::VecOp {
                kind: VecOpKind::FirstIndexOf | VecOpKind::LastIndexOf,
                ..
            }))
        ) {
            continue;
        }
        // The host's `Val` result, or the word a comparison typed it as.
        if !matches!(
            b.ty,
            IrType::Unknown(_)
                | IrType::Known(KnownType::I64 | KnownType::U64 | KnownType::Val)
                | IrType::Inferred(KnownType::I64 | KnownType::U64 | KnownType::Val)
        ) {
            trace(func, search, "typed already");
            continue;
        }
        match plan_search(func, &order, search) {
            Ok(site) => sites.push(site),
            Err(why) => trace(func, search, why),
        }
    }
    sites
}

/// Print a refusal when `SORDEC_OPTION_TRACE` is set.
#[allow(clippy::print_stderr)]
fn trace(func: &HighFunction, search: ValueId, why: &str) {
    if std::env::var_os("SORDEC_OPTION_TRACE").is_some() {
        eprintln!("index-of: func_{} v{}: {why}", func.id.index(), search.index());
    }
}

fn plan_search(func: &HighFunction, order: &[ValueId], search: ValueId) -> Result<Site, &'static str> {
    let present = present_blocks(func, search);
    let in_present = |id: ValueId| block_containing(func, id).is_some_and(|b| present.contains(&b));
    let mut decodes = Vec::new();
    let mut masks = Vec::new();
    // Every binding that reads the search, scheduled or not.
    for (id, b) in func.bindings.iter() {
        let mut reads = false;
        b.expr.for_each_value_use(|u| reads |= resolve_use(func, u) == search);
        if !reads || id == search {
            continue;
        }
        match &b.expr {
            // A copy is the search itself: its readers are read through it
            // above (`resolve_use`), and the region's below.
            Expr::Use(_) => {}
            Expr::Binary { op: BinaryOp::Eq | BinaryOp::Ne, lhs, rhs } if is_void_test(func, *lhs, *rhs, search) => {}
            Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck { .. })) => {}
            Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { .. })) if in_present(id) => decodes.push(id),
            Expr::Binary { op: BinaryOp::BitAnd, lhs, rhs }
                if in_present(id)
                    && [(*lhs, *rhs), (*rhs, *lhs)].iter().any(|(s, m)| {
                        resolve_use(func, *s) == search && trace_int(func, *m) == Some(i128::from(U32VAL_MASK))
                    }) =>
            {
                masks.push(id);
            }
            other => {
                // Residue: a pure binding nothing reads.
                let mut read = order.iter().any(|r| {
                    let mut reads = false;
                    if let Some(rb) = func.bindings.get(*r) {
                        rb.expr.for_each_value_use(|u| reads |= u == id);
                    }
                    reads
                });
                func.region.for_each_value_use(|u| read |= u == id);
                if read || (order.contains(&id) && !expr_effects(other).is_pure_total()) {
                    return Err("read by something else");
                }
            }
        }
    }
    let mut region_reads = false;
    func.region.for_each_value_use(|u| region_reads |= resolve_use(func, u) == search);
    if region_reads {
        return Err("read by the control flow");
    }
    Ok(Site { search, decodes, masks })
}

/// `lhs` against `rhs` is the search compared with `Void`.
fn is_void_test(func: &HighFunction, lhs: ValueId, rhs: ValueId, search: ValueId) -> bool {
    [(lhs, rhs), (rhs, lhs)]
        .iter()
        .any(|(s, k)| resolve_use(func, *s) == search && trace_int(func, *k) == Some(i128::from(TAG_VOID)))
}

/// Every block inside an arm that runs only when the search is not `Void`:
/// the `else` of an `if s == Void`, the `then` of an `if s != Void`.
fn present_blocks(func: &HighFunction, search: ValueId) -> HashSet<BlockId> {
    let mut out = HashSet::new();
    func.region.for_each_node(|node| {
        let Region::If { cond, then_region, else_region } = node else { return };
        let Some(Expr::Binary { op, lhs, rhs }) = func.bindings.get(resolve_use(func, *cond)).map(|b| &b.expr) else {
            return;
        };
        if !is_void_test(func, *lhs, *rhs, search) {
            return;
        }
        let arm = match op {
            BinaryOp::Eq => else_region.as_deref(),
            BinaryOp::Ne => Some(&**then_region),
            _ => None,
        };
        if let Some(arm) = arm {
            arm.for_each_node(|r| {
                if let Region::Basic(b) = r {
                    out.insert(*b);
                }
            });
        }
    });
    out
}

fn prov(note: &str) -> Provenance {
    Provenance::new(PASS_NAME, ProvenanceSource::SdkPattern, note.to_string())
}

fn apply(func: &mut HighFunction, site: &Site) {
    let u32_ty = IrType::Known(KnownType::U32);
    if let Some(b) = func.bindings.get_mut(site.search) {
        b.ty = IrType::Known(KnownType::Option(Box::new(u32_ty.clone())));
        b.add_provenance(prov("the SDK's `Vec` search: the host's `Void` or index, as the `Option<u32>` it returns"));
    }
    for &d in &site.decodes {
        if let Some(b) = func.bindings.get_mut(d) {
            b.expr = Expr::Unwrap { value: site.search, index: 0, arity: 1 };
            b.ty = u32_ty.clone();
            b.add_provenance(prov("the index's decode where the search is present: the `Option`'s `unwrap()`"));
        }
    }
    for &m in &site.masks {
        let Some(block) = block_containing(func, m) else { continue };
        let unwrap = ValueId::from_index(func.bindings.len() as u32);
        func.bindings.push(Binding::new(
            unwrap,
            u32_ty.clone(),
            Expr::Unwrap { value: site.search, index: 0, arity: 1 },
            prov("the index, where the search is present: the `Option`'s `unwrap()`"),
        ));
        if let Some(b) = func.blocks.get_mut(block)
            && let Some(at) = b.bindings.iter().position(|x| *x == m)
        {
            b.bindings.insert(at, unwrap);
        }
        if let Some(b) = func.bindings.get_mut(m) {
            b.expr = Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty: KnownType::U32, value: unwrap }));
            b.ty = IrType::Inferred(KnownType::Val);
            b.add_provenance(prov("the search's `U32Val` masked to its payload and tag: the index's encode"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, v};
    use sordec_ir::Literal;

    fn search() -> Expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::VecOp {
            kind: VecOpKind::FirstIndexOf,
            args: vec![v(0), v(1)],
        }))
    }

    /// `s = first_index_of(v0, v1); if s == 2 { } else { d = decode(s);
    /// m = s & mask }`, with `extra` read in the present arm.
    fn shape(eq: BinaryOp, extra: Option<Expr>) -> HighFunction {
        let mut exprs = vec![
            Expr::Phi { incoming: vec![] },                                                // v0
            Expr::Phi { incoming: vec![] },                                                // v1
            search(),                                                                      // v2 s
            Expr::Literal(Literal::I64(2)),                                                // v3
            Expr::Binary { op: eq, lhs: v(2), rhs: v(3) },                                 // v4
            Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { value: v(2) })),    // v5
            Expr::Literal(Literal::I64(U32VAL_MASK)),                                      // v6
            Expr::Binary { op: BinaryOp::BitAnd, lhs: v(2), rhs: v(6) },                   // v7
        ];
        let mut present = vec![5, 6, 7];
        if let Some(e) = extra {
            exprs.push(e); // v8
            present.push(8);
        }
        let mut f = func_with(exprs, vec![v(0), v(1)], vec![2, 3, 4]);
        let b1 = BlockId::from_index(f.blocks.len() as u32);
        f.blocks.push(sordec_ir::HighBlock { id: b1, bindings: present.into_iter().map(v).collect() });
        let arm = Box::new(Region::Basic(b1));
        let (then_region, else_region) = match eq {
            BinaryOp::Eq => (Box::new(Region::Sequence(vec![])), Some(arm)),
            _ => (arm, None),
        };
        f.region = Region::Sequence(vec![
            Region::Basic(BlockId::from_index(0)),
            Region::If { cond: v(4), then_region, else_region },
        ]);
        f
    }

    fn run(mut f: HighFunction) -> (bool, HighFunction) {
        let mut ir = crate::marshalling::test_support::module(vec![f.clone()]);
        let changed = IndexOfPass.run(&mut ir).changed;
        f = ir.functions.remove(0);
        (changed, f)
    }

    #[test]
    fn a_search_is_the_option_and_its_decode_the_unwrap() {
        for eq in [BinaryOp::Eq, BinaryOp::Ne] {
            let (changed, f) = run(shape(eq, None));
            assert!(changed);
            let ty = &f.bindings.get(v(2)).unwrap().ty;
            assert_eq!(ty, &IrType::Known(KnownType::Option(Box::new(IrType::Known(KnownType::U32)))));
            assert!(matches!(f.bindings.get(v(5)).unwrap().expr, Expr::Unwrap { value, .. } if value == v(2)));
            let Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty: KnownType::U32, value })) =
                f.bindings.get(v(7)).unwrap().expr
            else {
                panic!("{:?}", f.bindings.get(v(7)))
            };
            assert!(matches!(f.bindings.get(value).unwrap().expr, Expr::Unwrap { .. }));
        }
    }

    #[test]
    fn a_search_read_by_something_else_is_left() {
        // `s + 1`: the word used as a number.
        let extra = Expr::Binary { op: BinaryOp::Add, lhs: v(2), rhs: v(3) };
        let mut f = shape(BinaryOp::Eq, Some(extra));
        // Something must read it, or it is residue.
        f.region = Region::Sequence(vec![
            Region::Basic(BlockId::from_index(0)),
            Region::If {
                cond: v(4),
                then_region: Box::new(Region::Sequence(vec![])),
                else_region: Some(Box::new(Region::Sequence(vec![
                    Region::Basic(BlockId::from_index(1)),
                    Region::Return { values: vec![v(8)] },
                ]))),
            },
        ]);
        let (changed, _) = run(f);
        assert!(!changed);
    }

    #[test]
    fn a_decode_outside_the_present_arm_is_left() {
        let mut f = shape(BinaryOp::Eq, None);
        // Both arms: the decode, returned, now also runs where the search
        // is `Void`.
        f.region = Region::Sequence(vec![
            Region::Basic(BlockId::from_index(0)),
            Region::Basic(BlockId::from_index(1)),
            Region::If { cond: v(4), then_region: Box::new(Region::Sequence(vec![])), else_region: None },
            Region::Return { values: vec![v(5)] },
        ]);
        let (changed, _) = run(f);
        assert!(!changed);
    }
}
