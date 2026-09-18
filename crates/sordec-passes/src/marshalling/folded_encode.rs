//! Recover `u32` arithmetic the compiler folded into a `Val` encoding.
//!
//! # The shape
//!
//! ```ignore
//! count += 1;
//! env.storage().instance().set(&COUNTER, &count);
//! ```
//!
//! stores `count + 1` as a `U32Val`, `((count + 1) << 32) | 4`. LLVM
//! distributes the shift over the addition and folds the constants, so what
//! reaches us is
//!
//! ```text
//! if count == 4294967295 { panic!() }      ← the overflow check of `+ 1`
//! v = (count << 32) + 0x1_0000_0004        ← encode(count + 1)
//! set(&COUNTER, v)
//! ```
//!
//! — an addition that is nowhere, a check guarding nothing, and a store of a
//! raw bit pattern.
//!
//! # The rewrites
//!
//! 1. **The encode.** `(x << 32) + C`, where `C`'s low byte is the `U32Val`
//!    tag and its high word is `k`, with `x` a recovered `u32`, is
//!    `encode_u32(x + k)`: the addition is materialised as `x + k`.
//! 2. **The check.** The branch `x == u32::MAX - k + 1 → panic` right before
//!    it is that addition's overflow check. It is relabelled as one
//!    ([`PanicKind::ArithOverflow`]), and the overflow-guard elision then
//!    removes it on its own documented argument: the emitted crate builds with
//!    `overflow-checks = true`, so `x + k` traps exactly where the check did.
//!    Only when nothing observable runs between the check and the addition,
//!    so the trap does not move past an effect.
//! 3. **The store.** `set(&k, encode(p))` stores what `set(&k, &p)` stores
//!    when `p` is a `u32`: the SDK's `IntoVal` for `u32` is that encode. The
//!    value operand becomes `p`. Only when `p` carries the encoded type —
//!    a mistyped payload would be encoded differently, which is why
//!    [`super::encode`] refuses this in general.

use std::collections::HashSet;

use sordec_common::{IrId, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{
    BinaryOp, Binding, Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Literal, PanicKind, Region,
    SemanticOp,
};

use super::sret::emission_order;
use crate::dataflow::{block_containing, resolve_use, trace_int};
use crate::effects::expr_effects;
use crate::metrics_catalog::MARSHALLING_FOLDED_ENCODES as M_FOLDED;
use crate::pass::{Pass, PassResult};
use crate::structuring::seq;
use crate::val_abi::TAG_U32_VAL;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-folded-encode";

/// Recovers arithmetic folded into `U32Val` encodes and the stores of them.
#[derive(Debug, Default, Clone, Copy)]
pub struct FoldedEncodePass;

impl Pass<HighIr> for FoldedEncodePass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            for site in encodes(func) {
                rewrite_encode(func, &site);
                result.metrics.increment(M_FOLDED, 1);
                result.changed = true;
            }
            let stores = stores_of_encodes(func);
            for (store, payload) in stores {
                if let Some(b) = func.bindings.get_mut(store)
                    && let Expr::Semantic(SemanticOp::Known(KnownOp::StorageSet { value, .. })) = &mut b.expr
                {
                    *value = payload;
                    b.add_provenance(Provenance::new(
                        PASS_NAME,
                        ProvenanceSource::SdkPattern,
                        "stored value named as the u32 the SDK's IntoVal encodes",
                    ));
                    result.metrics.increment(M_FOLDED, 1);
                    result.changed = true;
                }
            }
        }
        result
    }
}

/// One folded encode: `add = (x << 32) + C`.
struct Site {
    add: ValueId,
    x: ValueId,
    k: u32,
}

fn is_u32(func: &HighFunction, v: ValueId) -> bool {
    matches!(
        func.bindings.get(v).map(|b| &b.ty),
        Some(IrType::Known(KnownType::U32) | IrType::Inferred(KnownType::U32))
    )
}

fn encodes(func: &HighFunction) -> Vec<Site> {
    let mut sites = Vec::new();
    for id in emission_order(func) {
        let Some(Expr::Binary { op: BinaryOp::Add, lhs, rhs }) = func.bindings.get(id).map(|b| &b.expr) else {
            continue;
        };
        for (shifted, constant) in [(*lhs, *rhs), (*rhs, *lhs)] {
            let Some(c) = trace_int(func, constant) else {
                continue;
            };
            let Some(Expr::Binary { op: BinaryOp::Shl, lhs: x, rhs: by }) =
                func.bindings.get(resolve_use(func, shifted)).map(|b| &b.expr)
            else {
                continue;
            };
            let x = resolve_use(func, *x);
            if trace_int(func, *by) != Some(32) || !is_u32(func, x) {
                continue;
            }
            // The constant is itself a `U32Val`: tag in the low byte, a zero
            // minor field, the addend in the high word.
            let Ok(c) = u64::try_from(c) else {
                continue;
            };
            if c & 0xFF != u64::from(TAG_U32_VAL) || (c >> 8) & 0xFF_FFFF != 0 {
                continue;
            }
            sites.push(Site { add: id, x, k: (c >> 32) as u32 });
            break;
        }
    }
    sites
}

fn rewrite_encode(func: &mut HighFunction, site: &Site) {
    let mut fresh = Vec::new();
    let value = if site.k == 0 {
        site.x
    } else {
        let k = push(func, &mut fresh, IrType::Known(KnownType::U32), Expr::Literal(Literal::I64(i64::from(site.k))));
        push(
            func,
            &mut fresh,
            IrType::Known(KnownType::U32),
            Expr::Binary { op: BinaryOp::Add, lhs: site.x, rhs: k },
        )
    };
    schedule_before(func, site.add, &fresh);
    if let Some(b) = func.bindings.get_mut(site.add) {
        b.expr = Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty: KnownType::U32, value }));
        b.add_provenance(Provenance::new(
            PASS_NAME,
            ProvenanceSource::SdkPattern,
            "U32Val encode with the addend the compiler folded into its constant",
        ));
    }
    if site.k != 0 {
        relabel_overflow_check(func, site);
    }
}

fn push(func: &mut HighFunction, fresh: &mut Vec<ValueId>, ty: IrType, expr: Expr) -> ValueId {
    let id = ValueId::from_index(func.bindings.len() as u32);
    func.bindings.push(Binding::new(
        id,
        ty,
        expr,
        Provenance::new(PASS_NAME, ProvenanceSource::SdkPattern, "u32 addition folded into a U32Val encode"),
    ));
    fresh.push(id);
    id
}

fn schedule_before(func: &mut HighFunction, anchor: ValueId, fresh: &[ValueId]) {
    for (_, block) in func.blocks.iter_mut() {
        if let Some(pos) = block.bindings.iter().position(|v| *v == anchor) {
            for (i, id) in fresh.iter().enumerate() {
                block.bindings.insert(pos + i, *id);
            }
            return;
        }
    }
}

/// Relabel `if x == u32::MAX - k + 1 { panic }` before `site.add` as the
/// overflow check of `x + k`, when nothing with an effect runs between the
/// branch and the addition.
fn relabel_overflow_check(func: &mut HighFunction, site: &Site) {
    let bound = i128::from(u32::MAX) - i128::from(site.k) + 1;
    let Some(add_block) = block_containing(func, site.add) else {
        return;
    };
    let is_check = |func: &HighFunction, cond: ValueId| -> bool {
        let Some(Expr::Binary { op, lhs, rhs }) = func.bindings.get(resolve_use(func, cond)).map(|b| &b.expr) else {
            return false;
        };
        let (l, r) = (resolve_use(func, *lhs), resolve_use(func, *rhs));
        let constant = if l == site.x {
            *rhs
        } else if r == site.x {
            *lhs
        } else {
            return false;
        };
        let Some(c) = trace_int(func, constant) else {
            return false;
        };
        match op {
            BinaryOp::Eq if site.k == 1 => c == bound,
            BinaryOp::Ge if l == site.x => c == bound,
            BinaryOp::Gt if l == site.x => c == bound - 1,
            _ => false,
        }
    };
    let mut target = None;
    find_check(func, &func.region, add_block, site.add, &is_check, &mut target);
    let Some(cond) = target else {
        return;
    };
    let region = std::mem::replace(&mut func.region, Region::Unreachable);
    func.region = relabel(region, cond);
}

/// Find, in the sequence holding `add_block`, an else-less trap branch
/// satisfying `is_check` that is followed only by effect-free code up to the
/// addition.
fn find_check(
    func: &HighFunction,
    region: &Region,
    add_block: sordec_common::BlockId,
    add: ValueId,
    is_check: &dyn Fn(&HighFunction, ValueId) -> bool,
    found: &mut Option<ValueId>,
) {
    if found.is_some() {
        return;
    }
    match region {
        Region::Sequence(items) => {
            for (i, item) in items.iter().enumerate() {
                if let Region::If { cond, then_region, else_region: None } = item
                    && super::guard::is_trap(then_region, &super::guard::empty_blocks(func))
                    && is_check(func, *cond)
                    && quiet_until(func, &items[i + 1..], add_block, add)
                {
                    *found = Some(*cond);
                    return;
                }
                find_check(func, item, add_block, add, is_check, found);
            }
        }
        Region::Scope { body, .. } | Region::Loop { body, .. } => find_check(func, body, add_block, add, is_check, found),
        Region::If { then_region, else_region, .. } => {
            find_check(func, then_region, add_block, add, is_check, found);
            if let Some(e) = else_region {
                find_check(func, e, add_block, add, is_check, found);
            }
        }
        _ => {}
    }
}

/// Whether `items`, run in order, reach the addition in `add_block` through
/// straight-line code with no effect before it.
fn quiet_until(func: &HighFunction, items: &[Region], add_block: sordec_common::BlockId, add: ValueId) -> bool {
    let mut seen = HashSet::new();
    for item in items {
        match item {
            Region::Basic(b) => {
                let Some(block) = func.blocks.get(*b) else {
                    return false;
                };
                for id in &block.bindings {
                    if *b == add_block && (*id == add || seen.contains(id)) {
                        return true;
                    }
                    seen.insert(*id);
                    let Some(binding) = func.bindings.get(*id) else {
                        return false;
                    };
                    if !expr_effects(&binding.expr).is_pure_total() {
                        return false;
                    }
                }
            }
            Region::Transfer { .. } => {}
            _ => return false,
        }
    }
    false
}

fn relabel(region: Region, cond: ValueId) -> Region {
    let recurse = |r: Region| relabel(r, cond);
    match region {
        Region::If { cond: c, then_region, else_region: None } if c == cond => Region::If {
            cond: c,
            then_region: Box::new(overflow_panic(*then_region)),
            else_region: None,
        },
        Region::Sequence(items) => seq(items.into_iter().map(recurse).collect()),
        Region::Scope { out, body } => Region::Scope { out, body: Box::new(recurse(*body)) },
        Region::Loop { header, body, kind } => Region::Loop { header, body: Box::new(recurse(*body)), kind },
        Region::If { cond: c, then_region, else_region } => Region::If {
            cond: c,
            then_region: Box::new(recurse(*then_region)),
            else_region: else_region.map(|e| Box::new(recurse(*e))),
        },
        other => other,
    }
}

fn overflow_panic(region: Region) -> Region {
    match region {
        Region::Panic { .. } => Region::Panic { kind: PanicKind::ArithOverflow },
        Region::Sequence(items) => Region::Sequence(items.into_iter().map(overflow_panic).collect()),
        other => other,
    }
}

/// `set(&k, encode(p))` stores whose payload `p` is a recovered `u32`.
fn stores_of_encodes(func: &HighFunction) -> Vec<(ValueId, ValueId)> {
    emission_order(func)
        .into_iter()
        .filter_map(|id| {
            let Expr::Semantic(SemanticOp::Known(KnownOp::StorageSet { value, .. })) = &func.bindings.get(id)?.expr else {
                return None;
            };
            let Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty: KnownType::U32, value: p })) =
                &func.bindings.get(resolve_use(func, *value))?.expr
            else {
                return None;
            };
            is_u32(func, resolve_use(func, *p)).then_some((id, *p))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};
    use sordec_common::{BlockId, IrId};
    use sordec_ir::{KnownTier, StorageTier};

    /// `v0: u32; if v0 == u32::MAX { panic }; v3 = (v0 << 32) + 0x1_0000_0004;
    /// set(k, v3)`.
    fn shape(ty: KnownType) -> HighFunction {
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                                   // v0 count
                Expr::Literal(Literal::I64(32)),                                  // v1
                Expr::Binary { op: BinaryOp::Shl, lhs: v(0), rhs: v(1) },        // v2
                Expr::Literal(Literal::I64(0x1_0000_0004)),                       // v3
                Expr::Binary { op: BinaryOp::Add, lhs: v(2), rhs: v(3) },        // v4
                Expr::Literal(Literal::I64(i64::from(u32::MAX))),                 // v5
                Expr::Binary { op: BinaryOp::Eq, lhs: v(0), rhs: v(5) },         // v6
                Expr::Semantic(SemanticOp::Known(KnownOp::StorageSet {
                    tier: StorageTier::Known(KnownTier::Instance),
                    durability: v(1),
                    key: v(1),
                    resolved_key: None,
                    value: v(4),
                })), // v7
            ],
            vec![v(0)],
            vec![],
        );
        f.bindings.get_mut(v(0)).unwrap().ty = IrType::Known(ty);
        f.blocks.push(sordec_ir::HighBlock { id: BlockId::from_index(1), bindings: vec![v(2), v(4), v(7)] });
        f.blocks.get_mut(BlockId::from_index(0)).unwrap().bindings = vec![v(6)];
        f.region = Region::Sequence(vec![
            Region::Basic(BlockId::from_index(0)),
            Region::If {
                cond: v(6),
                then_region: Box::new(Region::Panic { kind: PanicKind::Bare }),
                else_region: None,
            },
            Region::Basic(BlockId::from_index(1)),
        ]);
        f
    }

    #[test]
    fn a_folded_increment_becomes_an_addition_and_its_check_an_overflow_check() {
        let mut m = module(vec![shape(KnownType::U32)]);
        assert!(FoldedEncodePass.run(&mut m).changed);
        let f = &m.functions[0];
        let Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { value: sum, .. })) =
            &f.bindings.get(v(4)).unwrap().expr
        else {
            panic!("the add is now an encode");
        };
        assert!(matches!(f.bindings.get(*sum).unwrap().expr, Expr::Binary { op: BinaryOp::Add, lhs, .. } if lhs == v(0)));
        let mut overflow = false;
        f.region.for_each_node(|n| overflow |= matches!(n, Region::Panic { kind: PanicKind::ArithOverflow }));
        assert!(overflow, "the check is labelled as the addition's overflow check");
        // The store names the u32.
        assert!(matches!(
            f.bindings.get(v(7)).unwrap().expr,
            Expr::Semantic(SemanticOp::Known(KnownOp::StorageSet { value, .. })) if value == *sum
        ));
    }

    /// Without a recovered `u32` the shift may be of anything.
    #[test]
    fn an_untyped_operand_is_left_alone() {
        let mut m = module(vec![shape(KnownType::I64)]);
        assert!(!FoldedEncodePass.run(&mut m).changed);
    }

    #[test]
    fn the_pass_is_idempotent() {
        let mut m = module(vec![shape(KnownType::U32)]);
        assert!(FoldedEncodePass.run(&mut m).changed);
        assert!(!FoldedEncodePass.run(&mut m).changed);
    }
}
