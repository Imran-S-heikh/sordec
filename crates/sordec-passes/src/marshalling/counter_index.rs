//! Read a loop's vector index kept as an encoded word beside its counter
//! as the encode of the counter.
//!
//! # The shape
//!
//! ```rust,ignore
//! for i in 0..signatures.len() {
//!     let signature = signatures.get_unchecked(i);
//!     if i > 0 {
//!         let prev_signature = signatures.get_unchecked(i - 1);
//!         ..
//!     }
//! }
//! ```
//!
//! `get_unchecked(i)` hands the host `U32Val(i)`, `i << 32 | 4`. rustc
//! strength-reduces it: next to the counter it keeps the word for `i - 1`,
//! starting at `U32Val(u32::MAX)` and stepping by `2³²` as the counter
//! steps by one, and adds `2³²` for the current element:
//!
//! ```text
//! i = 0 ; w = -4294967292                     ; 0xFFFF_FFFF_0000_0004
//! loop {
//!     .. e = vec_get(v, w + 4294967296) ..    ; U32Val(i)
//!     if i != 0 { p = vec_get(v, w) }         ; U32Val(i - 1)
//!     i = i + 1 ; w = w + 4294967296 ; continue
//! }
//! ```
//!
//! The index reaches the host as a word with no `u32` behind it, so the
//! read cannot be spelled `get_unchecked` and stays a gap.
//!
//! # The rewrite
//!
//! Each such index becomes the encode of the counter it is: `U32Val(i)`,
//! or `U32Val(i - 1)` under the test `i != 0`. The word and its steps stay
//! for whatever else reads them.
//!
//! # Why it is exact
//!
//! The counter `i` and the word `w` are two phis of one loop header,
//! assigned together on every edge into it: `0` and `W₀` on the one entry,
//! `i + 1` and `w + 2³²` on every way round. With `W₀`'s low word `4` (the
//! `U32Val` tag) and `c` its high word, induction over the edges gives
//! `w = (c + i mod 2³²) << 32 | 4` on every iteration, in 64-bit wrapping
//! arithmetic (adding `2³²` adds one to the high word modulo `2³²`, and
//! leaves the tag): `w` is `U32Val(c + i)`, `w + 2³²` is `U32Val(c + i + 1)`,
//! each modulo `2³²`. So an index of `w + k·2³²` (`k` 0 or 1) is
//! `U32Val(i + d)` with `d = c + k mod 2³²`:
//!
//! - `d = 0`: `U32Val(i)`;
//! - `d = 2³² − 1`: `U32Val(i − 1)` modulo `2³²`, which is `i - 1` without
//!   wrapping where `i ≠ 0` — so only inside the `then` of an `if i != 0`
//!   (or `i > 0` unsigned), where the emitted `i - 1` cannot underflow.
//!
//! Any other `d`, and the index is left.
//!
//! # Gates
//!
//! - A loop header with two phis, the counter and the word, and the
//!   function's region transfers into that header exactly the entry one
//!   (before the loop) and its `continue`s, each assigning both: `0` and a
//!   constant with low word `4` on entry, `i + 1` and `w + 2³²` on each
//!   `continue`.
//! - The index a `vec_get`'s, inside the loop body, of `w` or `w + 2³²`.
//! - `d` as above; for `d = 2³² − 1` the `vec_get` where the loop body
//!   has tested `i ≠ 0`: inside the `then` of an `if` on `i != 0`, `0 != i`
//!   or `i > 0` (unsigned); inside the `else` of an `if` on `i == 0` or
//!   `i.eqz()`; or after an `if i == 0 { .. }` with no `else` whose `then`
//!   never falls through, later in the same sequence (reached only by
//!   falling past the test).

use std::collections::HashSet;

use sordec_common::{BlockId, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{
    BinaryOp, Binding, Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Literal, Region, SemanticOp, VecOpKind,
};

use super::enum_match::blocks_in;
use crate::dataflow::{resolve_use, trace_int};
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-counter-index";

/// Indices rewritten.
const M_INDICES: &str = "marshalling_counter_indices";

const STEP: i128 = 1 << 32;

/// Reads a strength-reduced encoded index as the counter's encode.
#[derive(Debug, Default, Clone, Copy)]
pub struct CounterIndexPass;

impl Pass<HighIr> for CounterIndexPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            let mut loops = Vec::new();
            collect_loops(&func.region, &mut loops);
            for (header, body) in loops {
                for pair in pairs(func, header) {
                    for site in sites(func, &body, &pair) {
                        apply(func, &pair, site);
                        result.metrics.increment(M_INDICES, 1);
                        result.changed = true;
                    }
                }
            }
        }
        result
    }
}

fn collect_loops(region: &Region, out: &mut Vec<(BlockId, Region)>) {
    region.for_each_node(|n| {
        if let Region::Loop { header, body, .. } = n {
            out.push((*header, (**body).clone()));
        }
    });
}

/// A counter and the word beside it.
#[derive(Debug, Clone, Copy)]
struct Pair {
    /// The counter `i`.
    i: ValueId,
    /// The word `w`.
    w: ValueId,
    /// `c`: the high word of the word's entry value.
    c: u32,
}

/// Every transfer into `header` in the function's region tree: entry
/// `Transfer`s and `Continue`s.
/// The phi assignments of several transfers.
type Transfers = Vec<Vec<(ValueId, ValueId)>>;

fn transfers_into(region: &Region, header: BlockId) -> (Transfers, Transfers) {
    let mut entries = Vec::new();
    let mut continues = Vec::new();
    region.for_each_node(|n| match n {
        Region::Transfer { target, transfer } if *target == header => entries.push(transfer.clone()),
        Region::Continue { target, transfer } if *target == header => continues.push(transfer.clone()),
        Region::Break { target, transfer } if *target == header => entries.push(transfer.clone()),
        _ => {}
    });
    (entries, continues)
}

fn pairs(func: &HighFunction, header: BlockId) -> Vec<Pair> {
    let (entries, continues) = transfers_into(&func.region, header);
    let ([entry], false) = (entries.as_slice(), continues.is_empty()) else { return Vec::new() };
    let assigned = |t: &[(ValueId, ValueId)], phi: ValueId| -> Option<ValueId> {
        let mut it = t.iter().filter(|(p, _)| *p == phi);
        let (_, x) = it.next()?;
        it.next().is_none().then_some(*x)
    };
    // `x` is `phi + k`.
    let steps = |x: ValueId, phi: ValueId, k: i128| {
        matches!(func.bindings.get(resolve_use(func, x)).map(|b| &b.expr),
            Some(Expr::Binary { op: BinaryOp::Add, lhs, rhs })
                if (resolve_use(func, *lhs) == phi && trace_int(func, *rhs) == Some(k))
                    || (resolve_use(func, *rhs) == phi && trace_int(func, *lhs) == Some(k)))
    };
    let mut out = Vec::new();
    for (i, i0) in entry {
        if trace_int(func, *i0) != Some(0) {
            continue;
        }
        for (w, w0) in entry {
            if w == i {
                continue;
            }
            let Some(w0) = trace_int(func, *w0) else { continue };
            // The entry word as its 64 bits.
            let bits = (w0 as i64) as u64;
            if i128::from(w0 as i64) != w0 || bits & 0xFFFF_FFFF != 4 {
                continue;
            }
            let every = continues.iter().all(|t| {
                assigned(t, *i).is_some_and(|x| steps(x, *i, 1)) && assigned(t, *w).is_some_and(|x| steps(x, *w, STEP))
            });
            if every {
                out.push(Pair { i: *i, w: *w, c: (bits >> 32) as u32 });
            }
        }
    }
    out
}

/// One index to rewrite: the `vec_get` binding, the block it sits in, and
/// the counter offset `d` (`0` or `-1`).
#[derive(Debug)]
struct Site {
    get: ValueId,
    block: BlockId,
    minus_one: bool,
}

fn sites(func: &HighFunction, body: &Region, pair: &Pair) -> Vec<Site> {
    let in_body = blocks_in(body);
    let guarded = guarded_blocks(func, body, pair.i);
    let mut out = Vec::new();
    for b in &in_body {
        let Some(block) = func.blocks.get(*b) else { continue };
        for v in &block.bindings {
            let Some(Expr::Semantic(SemanticOp::Known(KnownOp::VecOp { kind: VecOpKind::Get, args }))) =
                func.bindings.get(*v).map(|b| &b.expr)
            else {
                continue;
            };
            let [_, index] = args.as_slice() else { continue };
            let index = resolve_use(func, *index);
            let k: u32 = if index == pair.w {
                0
            } else if matches!(func.bindings.get(index).map(|b| &b.expr),
                Some(Expr::Binary { op: BinaryOp::Add, lhs, rhs })
                    if (resolve_use(func, *lhs) == pair.w && trace_int(func, *rhs) == Some(STEP))
                        || (resolve_use(func, *rhs) == pair.w && trace_int(func, *lhs) == Some(STEP)))
            {
                1
            } else {
                continue;
            };
            match pair.c.wrapping_add(k) {
                0 => out.push(Site { get: *v, block: *b, minus_one: false }),
                u32::MAX if guarded.contains(b) => out.push(Site { get: *v, block: *b, minus_one: true }),
                _ => {}
            }
        }
    }
    out
}

/// The blocks of `body` inside the `then` of an `if` on `i != 0`.
fn guarded_blocks(func: &HighFunction, body: &Region, i: ValueId) -> HashSet<BlockId> {
    let nonzero = |cond: ValueId| {
        let Some(Expr::Binary { op, lhs, rhs }) = func.bindings.get(resolve_use(func, cond)).map(|b| &b.expr) else {
            return false;
        };
        let (l, r) = (resolve_use(func, *lhs), resolve_use(func, *rhs));
        match op {
            BinaryOp::Ne => (l == i && trace_int(func, r) == Some(0)) || (r == i && trace_int(func, l) == Some(0)),
            BinaryOp::GtU => l == i && trace_int(func, r) == Some(0),
            BinaryOp::LtU => r == i && trace_int(func, l) == Some(0),
            _ => false,
        }
    };
    let zero = |cond: ValueId| match func.bindings.get(resolve_use(func, cond)).map(|b| &b.expr) {
        Some(Expr::Binary { op: BinaryOp::Eq, lhs, rhs }) => {
            let (l, r) = (resolve_use(func, *lhs), resolve_use(func, *rhs));
            (l == i && trace_int(func, r) == Some(0)) || (r == i && trace_int(func, l) == Some(0))
        }
        Some(Expr::Unary { op: sordec_ir::UnaryOp::Eqz, value }) => resolve_use(func, *value) == i,
        _ => false,
    };
    let mut out = HashSet::new();
    body.for_each_node(|n| {
        // `if i == 0 { leave }` and then the rest of the sequence: reached
        // only where `i != 0`.
        if let Region::Sequence(items) = n {
            for (k, item) in items.iter().enumerate() {
                if let Region::If { cond, then_region, else_region: None } = item
                    && zero(*cond)
                    && !super::enum_match::falls_through(then_region)
                {
                    for rest in &items[k + 1..] {
                        out.extend(blocks_in(rest));
                    }
                }
            }
        }
        if let Region::If { cond, then_region, else_region } = n {
            if nonzero(*cond) {
                out.extend(blocks_in(then_region));
            } else if zero(*cond)
                && let Some(e) = else_region
            {
                out.extend(blocks_in(e));
            }
        }
    });
    out
}

fn apply(func: &mut HighFunction, pair: &Pair, site: Site) {
    let prov = |note: &str| Provenance::new(PASS_NAME, ProvenanceSource::SdkPattern, note.to_owned());
    let u32_ty = IrType::Inferred(KnownType::U32);
    let mut fresh = Vec::new();
    let counter = if site.minus_one {
        let one = ValueId::new(func.bindings.len() as u32);
        func.bindings.push(Binding::new(one, u32_ty.clone(), Expr::Literal(Literal::U32(1)), prov("one")));
        let sub = ValueId::new(func.bindings.len() as u32);
        func.bindings.push(Binding::new(
            sub,
            u32_ty.clone(),
            Expr::Binary { op: BinaryOp::Sub, lhs: pair.i, rhs: one },
            prov("the counter less one, under its test against zero"),
        ));
        fresh.extend([one, sub]);
        sub
    } else {
        pair.i
    };
    let enc = ValueId::new(func.bindings.len() as u32);
    func.bindings.push(Binding::new(
        enc,
        IrType::Inferred(KnownType::Val),
        Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty: KnownType::U32, value: counter })),
        prov("the index the word beside the counter encodes: the counter's `U32Val`"),
    ));
    fresh.push(enc);
    if let Some(b) = func.blocks.get_mut(site.block)
        && let Some(at) = b.bindings.iter().position(|x| *x == site.get)
    {
        for (n, v) in fresh.into_iter().enumerate() {
            b.bindings.insert(at + n, v);
        }
    }
    if let Some(b) = func.bindings.get_mut(site.get)
        && let Expr::Semantic(SemanticOp::Known(KnownOp::VecOp { args, .. })) = &mut b.expr
        && let Some(index) = args.get_mut(1)
    {
        *index = enc;
        b.add_provenance(prov(if site.minus_one {
            "index: the word beside the counter, `U32Val(i - 1)` where `i != 0`"
        } else {
            "index: the word beside the counter plus 2^32, `U32Val(i)`"
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{module, v};
    use sordec_common::{Arena, FuncId, IrId, UnknownReason};
    use sordec_ir::HighBlock;

    fn bb(i: u32) -> Region {
        Region::Basic(BlockId::from_index(i))
    }

    fn get(vec: u32, index: u32) -> Expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::VecOp { kind: VecOpKind::Get, args: vec![v(vec), v(index)] }))
    }

    /// `i = 0; w = W0; loop { e = v[w + 2^32]; if i != 0 { p = v[w] } i += 1; w += 2^32 }`,
    /// with `guard` false dropping the `if` (its block runs unguarded).
    fn looped(w0: i64, w_step: i64, guard: bool) -> HighFunction {
        let exprs = vec![
            Expr::Phi { incoming: vec![] },                                // v0 the vec
            Expr::Literal(Literal::I64(0)),                                // v1 i0
            Expr::Literal(Literal::I64(w0)),                               // v2 w0
            Expr::Phi { incoming: vec![] },                                // v3 i
            Expr::Phi { incoming: vec![] },                                // v4 w
            Expr::Literal(Literal::I64(1 << 32)),                          // v5
            Expr::Binary { op: BinaryOp::Add, lhs: v(4), rhs: v(5) },      // v6 w + 2^32
            get(0, 6),                                                     // v7 element i
            Expr::Literal(Literal::I64(0)),                                // v8
            Expr::Binary { op: BinaryOp::Ne, lhs: v(3), rhs: v(8) },       // v9 i != 0
            get(0, 4),                                                     // v10 element i - 1
            Expr::Literal(Literal::I64(1)),                                // v11
            Expr::Binary { op: BinaryOp::Add, lhs: v(3), rhs: v(11) },     // v12 i + 1
            Expr::Literal(Literal::I64(w_step)),                           // v13
            Expr::Binary { op: BinaryOp::Add, lhs: v(4), rhs: v(13) },     // v14 w + step
        ];
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        for (n, e) in exprs.into_iter().enumerate() {
            let id = ValueId::from_index(n as u32);
            bindings.push(Binding::new(
                id,
                IrType::Unknown(UnknownReason::InsufficientEvidence),
                e,
                Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
            ));
        }
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        for (n, ids) in [vec![1, 2], vec![5, 6, 7, 8, 9], vec![10], vec![11, 12, 13, 14]].into_iter().enumerate() {
            blocks.push(HighBlock { id: BlockId::from_index(n as u32), bindings: ids.into_iter().map(v).collect() });
        }
        let guarded = if guard {
            Region::If { cond: v(9), then_region: Box::new(bb(2)), else_region: None }
        } else {
            bb(2)
        };
        let region = Region::Sequence(vec![
            bb(0),
            Region::Transfer { target: BlockId::from_index(1), transfer: vec![(v(3), v(1)), (v(4), v(2))] },
            Region::Loop {
                header: BlockId::from_index(1),
                body: Box::new(Region::Sequence(vec![
                    bb(1),
                    guarded,
                    bb(3),
                    Region::Continue { target: BlockId::from_index(1), transfer: vec![(v(3), v(12)), (v(4), v(14))] },
                ])),
                kind: sordec_ir::LoopKind::Unclassified,
            },
        ]);
        HighFunction {
            id: FuncId::from_index(0),
            name: None,
            signature: None,
            aliases: Vec::new(),
            blocks,
            bindings,
            region,
            params: vec![v(0)],
            returns: vec![],
        }
    }

    /// The counter a `vec_get`'s index encodes, and whether less one.
    fn index_of(f: &HighFunction, get: u32) -> Option<(ValueId, bool)> {
        let Some(Expr::Semantic(SemanticOp::Known(KnownOp::VecOp { args, .. }))) = f.bindings.get(v(get)).map(|b| &b.expr)
        else {
            return None;
        };
        let Some(Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty: KnownType::U32, value }))) =
            f.bindings.get(args[1]).map(|b| &b.expr)
        else {
            return None;
        };
        match f.bindings.get(*value).map(|b| &b.expr) {
            Some(Expr::Binary { op: BinaryOp::Sub, lhs, .. }) => Some((*lhs, true)),
            _ => Some((*value, false)),
        }
    }

    const W0: i64 = -4_294_967_292; // U32Val(u32::MAX)

    #[test]
    fn both_indices_become_the_counters_encode() {
        let mut ir = module(vec![looped(W0, 1 << 32, true)]);
        assert!(CounterIndexPass.run(&mut ir).changed);
        let f = &ir.functions[0];
        assert_eq!(index_of(f, 7), Some((v(3), false)), "w + 2^32 is U32Val(i)");
        assert_eq!(index_of(f, 10), Some((v(3), true)), "w is U32Val(i - 1) under i != 0");
        assert!(!CounterIndexPass.run(&mut ir).changed, "idempotent");
    }

    #[test]
    fn the_previous_element_without_a_zero_test_is_left() {
        let mut ir = module(vec![looped(W0, 1 << 32, false)]);
        CounterIndexPass.run(&mut ir);
        let f = &ir.functions[0];
        assert_eq!(index_of(f, 7), Some((v(3), false)));
        assert_eq!(index_of(f, 10), None, "i - 1 could underflow at i = 0");
    }

    #[test]
    fn a_word_that_is_no_u32val_or_steps_otherwise_is_left() {
        // Low word 5: not the `U32Val` tag.
        let mut ir = module(vec![looped(W0 + 1, 1 << 32, true)]);
        assert!(!CounterIndexPass.run(&mut ir).changed);
        // Stepping by 2^33: two counts per round.
        let mut ir = module(vec![looped(W0, 1 << 33, true)]);
        assert!(!CounterIndexPass.run(&mut ir).changed);
    }

    #[test]
    fn a_word_starting_elsewhere_indexes_no_counter() {
        // `U32Val(5)` on entry: `w + 2^32` is `U32Val(i + 6)`, not the counter.
        let mut ir = module(vec![looped((5 << 32) | 4, 1 << 32, true)]);
        assert!(!CounterIndexPass.run(&mut ir).changed);
    }
}
