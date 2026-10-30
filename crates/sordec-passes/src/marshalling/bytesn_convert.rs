//! Fold the SDK's outlined `BytesN<N>::try_from_val` into the typed read
//! it converts.
//!
//! # The shape
//!
//! ```rust,ignore
//! let public_key: BytesN<32> = env.storage().instance().get(&DataKey::Owner).unwrap();
//! ```
//!
//! reads a `Val` and converts it. For a `BytesN` rustc outlines the
//! conversion into a helper writing a `Result` through an out-pointer, and
//! the `unwrap` is the caller testing it:
//!
//! ```text
//! helper(out, v):
//!     if !has_tag(v, BytesObject) { d = 1 }
//!     else if bytes_len(v) != N   { d = 1 }
//!     else { store out+8 <- v; d = 0 }
//!     store out+0 <- d
//!
//! caller:
//!     helper(f, read)
//!     if load(f+0) == 1 { panic!() }
//!     key = load(f+8)
//! ```
//!
//! What the caller ends up holding is the read itself, known to be a
//! `BytesN<N>`; it traps otherwise.
//!
//! ## Split in two, and handed the value's address
//!
//! `privacy_pools` builds the same conversion from two helpers: the first
//! is handed the *address* of the value, loads it, tests its tag, and on a
//! bytes object hands its own out-pointer and the value to the second,
//! which is `helper` above without the tag check:
//!
//! ```text
//! tag_half(out, env, p):                  caller:
//!     v = load p                              store f+8 <- read
//!     if has_tag(v, BytesObject) {            tag_half(f+16, env, f+8)
//!         length_half(out, v)                 if load(f+16) == 1 { panic!() }
//!     } else { store out+0 <- 1 }             key = load(f+24)
//! ```
//!
//! Path by path the pair writes what `helper` writes: `1` where the tag
//! fails, and past the tag, `1` or the value with `0` as the length
//! decides. The region of `tag_half` is that one test and its two ways and
//! nothing else, and it writes nothing but that `1`. The value it converts
//! is the one the caller stored at exactly the eight bytes it loads, with
//! nothing between the store and the call that may write them
//! ([`crate::dataflow::facts_at`]'s kill discipline), so the read the fold
//! types is the value converted. The length is accepted as the host's
//! `U32Val` or unpacked from it, `(len >> 32) as u32`: the same number.
//!
//! # The rewrite
//!
//! The read is typed `BytesN<N>`, the call goes, the discriminant read is
//! the constant `0` (so the constant-branch fold drops the `unwrap`'s
//! trap), and the payload read is the read.
//!
//! # Why it is exact
//!
//! The trap moves; it does not go away. The reconstruction prints the read
//! at `BytesN<N>`, and `Storage::get::<_, BytesN<N>>` runs this same
//! `try_from_val` on the host's `Val` and traps on the same two failures.
//! So only a storage read is folded: it is the one source whose typed
//! spelling performs the conversion the helper did.

use std::collections::HashMap;

use sordec_common::{FuncId, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{
    BinaryOp, BufOpKind, Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Literal, MemWidth,
    Region, SemanticOp, UnaryOp,
};

use super::sret::emission_order;
use crate::dataflow::{block_containing, resolve_use, trace_int};
use crate::effects::expr_effects;
use crate::pass::{Pass, PassResult};
use crate::val_abi::TAG_BYTES_OBJECT;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-bytesn-convert";

/// Call sites of an outlined `BytesN` conversion folded into the read.
const M_FOLDED: &str = "marshalling_bytesn_conversions_folded";

/// Folds outlined `BytesN<N>` conversions of storage reads.
#[derive(Debug, Default, Clone, Copy)]
pub struct BytesNConvertPass;

impl Pass<HighIr> for BytesNConvertPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let mut converters: HashMap<FuncId, Converter> = ir
            .functions
            .iter()
            .filter_map(|h| Some((h.id, Converter { width: converter_width(h, true)?, out: 0, value: 1, by_ref: None })))
            .collect();
        let lengths: HashMap<FuncId, u32> =
            ir.functions.iter().filter_map(|h| Some((h.id, converter_width(h, false)?))).collect();
        converters.extend(ir.functions.iter().filter_map(|h| Some((h.id, split_converter(h, &lengths)?))));
        if converters.is_empty() {
            return result;
        }
        for func in &mut ir.functions {
            let sites: Vec<Site> = emission_order(func)
                .into_iter()
                .filter_map(|id| site(func, id, &converters))
                .collect();
            for s in sites {
                apply(func, &s);
                result.metrics.increment(M_FOLDED, 1);
                result.changed = true;
            }
        }
        result
    }
}

/// An outlined `BytesN<N>::try_from_val`, and where its call takes what.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Converter {
    width: u32,
    /// The argument carrying the result's address.
    out: usize,
    /// The argument carrying the value — or, with `by_ref`, its address.
    value: usize,
    /// For a converter handed the value's address: the offset it reads the
    /// 8-byte value at.
    by_ref: Option<u32>,
}

/// `N`, when `h` is exactly the outlined `BytesN<N>::try_from_val` — or,
/// without `with_tag`, its length half: the same shape with no tag check, which
/// a split conversion calls once its own tag check has passed.
fn converter_width(h: &HighFunction, with_tag: bool) -> Option<u32> {
    let [out, v] = h.params[..] else {
        return None;
    };
    let order = emission_order(h);
    let mut tag_check = None;
    let mut len_check = None;
    let mut payload_store = None;
    let mut disc_store = None;
    for &id in &order {
        let b = h.bindings.get(id)?;
        match &b.expr {
            Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck { value, tag, negated: true }))
                if *tag == TAG_BYTES_OBJECT && resolve_use(h, *value) == v =>
            {
                tag_check = Some(id);
            }
            Expr::Binary { op: BinaryOp::Ne, lhs, rhs } => {
                let (len, n) = if is_len_of(h, *lhs, v) { (*lhs, *rhs) } else { (*rhs, *lhs) };
                if is_len_of(h, len, v) {
                    len_check = Some((id, u32::try_from(trace_int(h, n)?).ok()?));
                }
            }
            Expr::Store { addr, value, offset, width: MemWidth::W8 } if resolve_use(h, *addr) == out => {
                match offset {
                    8 if resolve_use(h, *value) == v => payload_store = Some(id),
                    0 => disc_store = Some((id, resolve_use(h, *value))),
                    _ => return None,
                }
            }
            Expr::Store { .. } | Expr::Call { .. } => return None,
            other => {
                let fx = expr_effects(other);
                // Reading the length and the tag is all it may do besides.
                if fx.writes_host || fx.writes_memory {
                    return None;
                }
            }
        }
    }
    if with_tag != tag_check.is_some() {
        return None;
    }
    let ((len_check, n), payload_store, (_, disc)) = (len_check?, payload_store?, disc_store?);

    // The discriminant is `0` only where the payload is stored, `1` on
    // every other path, and the store sits under both checks' passing arms.
    let Expr::Phi { incoming } = &h.bindings.get(disc)?.expr else {
        return None;
    };
    let ok_block = block_containing(h, payload_store)?;
    for (block, value) in incoming {
        let want = if *block == ok_block { 0 } else { 1 };
        if trace_int(h, *value)? != want {
            return None;
        }
    }
    match tag_check {
        Some(tag_check) => passes_both(&h.region, tag_check, len_check, ok_block),
        None => else_of(&h.region, len_check, ok_block),
    }
    .then_some(n)
}

/// The split form, handed the value's address:
///
/// ```text
/// helper(out, env, p):
///     v = load p
///     if has_tag(v, BytesObject) { length_half(out, v) }
///     else                       { store out+0 <- 1 }
/// ```
///
/// `length_half` is the length check of [`converter_width`] without its tag
/// check, so on every path the result is the one the whole conversion
/// writes: `1` where the tag fails, and where it passes, `1` or the value
/// with `0` as the length decides. The region is that one test and its two
/// ways, nothing else.
fn split_converter(h: &HighFunction, lengths: &HashMap<FuncId, u32>) -> Option<Converter> {
    let order = emission_order(h);
    let mut read = None;
    let mut check = None;
    let mut forward = None;
    let mut fail = None;
    for &id in &order {
        match &h.bindings.get(id)?.expr {
            Expr::Load { addr, offset, width: MemWidth::W8, .. } => {
                let (base, at) = crate::dataflow::canon_addr(h, *addr);
                let src = h.params.iter().position(|p| *p == base)?;
                if read.replace((id, src, at.checked_add(*offset)?)).is_some() {
                    return None;
                }
            }
            Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck { value, tag, negated }))
                if *tag == TAG_BYTES_OBJECT =>
            {
                if check.replace((id, resolve_use(h, *value), *negated)).is_some() {
                    return None;
                }
            }
            Expr::Call { target, args } => {
                let n = *lengths.get(target)?;
                if forward.replace((id, n, args.clone())).is_some() {
                    return None;
                }
            }
            Expr::Store { addr, value, offset: 0, width: MemWidth::W8 } if trace_int(h, *value) == Some(1) => {
                if fail.replace((id, resolve_use(h, *addr))).is_some() {
                    return None;
                }
            }
            other => {
                let fx = expr_effects(other);
                if fx.writes_host || fx.writes_memory || fx.reads_memory || fx.writes_globals {
                    return None;
                }
            }
        }
    }
    let ((_, src, offset), (check, tested, negated), (call, n, args), (store, out_ptr)) =
        (read?, check?, forward?, fail?);
    let v = resolve_use(h, read?.0);
    let out = h.params.iter().position(|p| *p == out_ptr)?;
    // The length half is handed the out-pointer and the value, in its
    // own order: out first.
    let [to, value] = args[..] else { return None };
    if tested != v || resolve_use(h, to) != out_ptr || resolve_use(h, value) != v || out == src {
        return None;
    }
    // One test, its two ways, and nothing else in the region.
    let mut ifs = 0usize;
    let mut plain = true;
    h.region.for_each_node(|node| match node {
        Region::If { .. } => ifs += 1,
        Region::Basic(_) | Region::Sequence(_) | Region::Return { .. } => {}
        _ => plain = false,
    });
    if !plain || ifs != 1 {
        return None;
    }
    let passes = |id: ValueId| side(&h.region, check, block_containing(h, id)?).map(|then| then != negated);
    (passes(call)? && !passes(store)?).then_some(Converter { width: n, out, value: src, by_ref: Some(offset) })
}

/// Which way the test `cond` went for `block` to run: `true` inside the
/// `then` of the `if` on it, `false` inside its `else` — or after it, in
/// the sequence holding it, when the `then` never falls through.
fn side(region: &Region, cond: ValueId, block: sordec_common::BlockId) -> Option<bool> {
    let holds = |r: &Region| {
        let mut hit = false;
        r.for_each_node(|n| hit |= matches!(n, Region::Basic(x) if *x == block));
        hit
    };
    let mut found = None;
    region.for_each_node(|node| {
        let Region::Sequence(items) = node else { return };
        for (i, item) in items.iter().enumerate() {
            let Region::If { cond: c, then_region, else_region } = item else { continue };
            if *c != cond {
                continue;
            }
            let after = leaves(then_region) && items[i + 1..].iter().any(holds);
            if holds(then_region) {
                found = Some(true);
            } else if else_region.as_deref().is_some_and(holds) || after {
                found = Some(false);
            }
        }
    });
    found
}

/// Whether control never falls out of the bottom of `region`.
fn leaves(region: &Region) -> bool {
    match region {
        Region::Return { .. } | Region::Panic { .. } | Region::Unreachable => true,
        Region::Sequence(items) => items.last().is_some_and(leaves),
        _ => false,
    }
}

/// Whether `ok` lies under the `else` of the branch on `cond`.
fn else_of(region: &Region, cond: ValueId, ok: sordec_common::BlockId) -> bool {
    let mut found = false;
    region.for_each_node(|node| {
        if let Region::If { cond: c, else_region: Some(e), .. } = node
            && *c == cond
        {
            e.for_each_node(|n| found |= matches!(n, Region::Basic(x) if *x == ok));
        }
    });
    found
}

/// Whether `value` is `bytes_len(v)`, through renames — or that length
/// unpacked from its `U32Val`, `(len >> 32) as u32`, which is the same
/// number.
fn is_len_of(h: &HighFunction, value: ValueId, v: ValueId) -> bool {
    let value = resolve_use(h, value);
    let unpacked = match h.bindings.get(value).map(|b| &b.expr) {
        Some(Expr::Unary { op: UnaryOp::Wrap32, value: shifted }) => match h.bindings.get(resolve_use(h, *shifted)).map(|b| &b.expr) {
            Some(Expr::Binary { op: BinaryOp::ShrU, lhs, rhs }) if trace_int(h, *rhs) == Some(32) => Some(resolve_use(h, *lhs)),
            _ => None,
        },
        _ => None,
    };
    matches!(
        h.bindings.get(unpacked.unwrap_or(value)).map(|b| &b.expr),
        Some(Expr::Semantic(SemanticOp::Known(KnownOp::BufOp { kind: BufOpKind::BytesLen, args })))
            if args.first().is_some_and(|a| resolve_use(h, *a) == v)
    )
}

/// Whether `ok` lies under the `else` of the tag check's branch and,
/// within it, under the `else` of the length check's.
fn passes_both(region: &Region, tag: ValueId, len: ValueId, ok: sordec_common::BlockId) -> bool {
    let holds = |r: &Region, b: sordec_common::BlockId| {
        let mut hit = false;
        r.for_each_node(|n| hit |= matches!(n, Region::Basic(x) if *x == b));
        hit
    };
    let mut found = false;
    region.for_each_node(|node| {
        let Region::If { cond, else_region: Some(tag_else), .. } = node else { return };
        if *cond != tag {
            return;
        }
        tag_else.for_each_node(|inner| {
            if let Region::If { cond, else_region: Some(len_else), .. } = inner
                && *cond == len
                && holds(len_else, ok)
            {
                found = true;
            }
        });
    });
    found
}

/// One call site to fold.
struct Site {
    call: ValueId,
    read: ValueId,
    width: u32,
    discs: Vec<ValueId>,
    payloads: Vec<ValueId>,
}

fn site(func: &HighFunction, call: ValueId, converters: &HashMap<FuncId, Converter>) -> Option<Site> {
    let Expr::Call { target, args } = &func.bindings.get(call)?.expr else {
        return None;
    };
    let conv = *converters.get(target)?;
    let width = conv.width;
    let (frame, value) = (*args.get(conv.out)?, *args.get(conv.value)?);
    let (base, at) = address(func, frame, 0);
    // Handed the value's address, the converter reads the eight bytes
    // there: the value the caller stored at exactly those bytes, with
    // nothing between that may write them.
    let read = match conv.by_ref {
        None => resolve_use(func, value),
        Some(offset) => {
            let (p, from) = crate::dataflow::canon_addr(func, value);
            let x = crate::dataflow::facts_at(func, call, p).value_at(from.checked_add(offset)?, MemWidth::W8)?;
            resolve_use(func, x)
        }
    };
    // A source whose typed spelling *is* the conversion: a storage read, or
    // an element of a vector already typed `Vec<BytesN<N>>` — whose `get`
    // runs this same `try_from_val` on the element.
    let typed_source = match &func.bindings.get(read)?.expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet { .. })) => true,
        Expr::Semantic(SemanticOp::Known(KnownOp::VecOp { kind: sordec_ir::VecOpKind::Get, args })) => {
            args.first().is_some_and(|v| vec_of_bytes_n(func, resolve_use(func, *v)) == Some(width))
        }
        _ => false,
    };
    if !typed_source {
        return None;
    }
    // The result's two words, read back after the call and before anything
    // writes them again — the slot is often reused by the next conversion.
    let order = emission_order(func);
    let from = order.iter().position(|v| *v == call)?;
    let mut discs = Vec::new();
    let mut payloads = Vec::new();
    for &id in &order[from + 1..] {
        let Some(b) = func.bindings.get(id) else { continue };
        match &b.expr {
            Expr::Load { addr, offset, .. } => {
                let (b2, o) = address(func, *addr, i64::from(*offset));
                if b2 != base {
                    continue;
                }
                if o == at {
                    discs.push(id);
                } else if o == at + 8 {
                    payloads.push(id);
                }
            }
            Expr::Store { addr, offset, .. } => {
                let (b2, o) = address(func, *addr, i64::from(*offset));
                if b2 == base && (at..at + 16).contains(&o) {
                    break;
                }
            }
            Expr::Call { args, .. } => {
                let writes_slot = args.iter().any(|a| {
                    let (b2, o) = address(func, *a, 0);
                    b2 == base && (at..at + 16).contains(&o)
                });
                if writes_slot {
                    break;
                }
            }
            _ => {}
        }
    }
    (!discs.is_empty() && !payloads.is_empty()).then_some(Site { call, read, width, discs, payloads })
}

/// `N`, when `v` is a `Vec<BytesN<N>>` — by its recovered type, or by the
/// spec declaring the entrypoint parameter it is.
fn vec_of_bytes_n(func: &HighFunction, v: ValueId) -> Option<u32> {
    let elem_n = |t: &IrType| match t {
        IrType::Known(KnownType::Vec(e)) | IrType::Inferred(KnownType::Vec(e)) => match &**e {
            IrType::Known(KnownType::BytesN(n)) | IrType::Inferred(KnownType::BytesN(n)) => Some(*n),
            _ => None,
        },
        _ => None,
    };
    if let Some(n) = func.bindings.get(v).and_then(|b| elem_n(&b.ty)) {
        return Some(n);
    }
    let index = func.params.iter().position(|p| *p == v)?;
    match &func.signature.as_ref()?.inputs.get(index)?.ty {
        sordec_ir::TypeRef::Composite(sordec_ir::CompositeType::Vec(e)) => match &**e {
            sordec_ir::TypeRef::Composite(sordec_ir::CompositeType::BytesN(n)) => Some(*n),
            _ => None,
        },
        _ => None,
    }
}

/// `value + offset` as a base and a constant displacement, folding
/// `base + k` — a slot passed as `frame + 64` and read back as
/// `load frame offset=64` is one address.
fn address(func: &HighFunction, value: ValueId, offset: i64) -> (ValueId, i64) {
    let v = resolve_use(func, value);
    if let Some(Expr::Binary { op: BinaryOp::Add, lhs, rhs }) = func.bindings.get(v).map(|b| &b.expr)
        && let Some(k) = trace_int(func, *rhs).and_then(|k| i64::try_from(k).ok())
    {
        return (resolve_use(func, *lhs), offset + k);
    }
    (v, offset)
}

fn apply(func: &mut HighFunction, s: &Site) {
    let note = |what: &str| {
        Provenance::new(
            PASS_NAME,
            ProvenanceSource::SdkPattern,
            format!("{what} of the outlined `BytesN<{}>::try_from_val`, folded into the typed read", s.width),
        )
    };
    let bytes_n = IrType::Known(KnownType::BytesN(s.width));
    if let Some(b) = func.bindings.get_mut(s.call) {
        b.expr = Expr::Literal(Literal::Unit);
        b.ty = IrType::Known(KnownType::Unit);
        b.add_provenance(note("the call"));
    }
    for &d in &s.discs {
        if let Some(b) = func.bindings.get_mut(d) {
            b.expr = Expr::Literal(Literal::I64(0));
            b.ty = IrType::Known(KnownType::I64);
            b.add_provenance(note("the `Ok` discriminant"));
        }
    }
    for &p in &s.payloads {
        if let Some(b) = func.bindings.get_mut(p) {
            b.expr = Expr::Use(s.read);
            b.ty = bytes_n.clone();
            b.add_provenance(note("the payload"));
        }
    }
    if let Some(b) = func.bindings.get_mut(s.read)
        && matches!(b.ty, IrType::Unknown(_) | IrType::Known(KnownType::Val) | IrType::Inferred(KnownType::Val))
    {
        b.ty = bytes_n;
        b.add_provenance(note("the read, typed"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{module, v};
    use sordec_common::{Arena, BlockId, IrId, UnknownReason};
    use sordec_ir::{Binding, HighBlock, KnownTier, Missing, StorageTier};

    fn bb(i: u32) -> BlockId {
        BlockId::from_index(i)
    }

    fn build(id: u32, exprs: Vec<Expr>, blocks: Vec<Vec<u32>>, region: Region, params: Vec<u32>) -> HighFunction {
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        for expr in exprs {
            let vid = ValueId::from_index(bindings.len() as u32);
            bindings.push(Binding::new(
                vid,
                IrType::Unknown(UnknownReason::InsufficientEvidence),
                expr,
                Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
            ));
        }
        let mut arena: Arena<BlockId, HighBlock> = Arena::new();
        for (i, b) in blocks.into_iter().enumerate() {
            arena.push(HighBlock { id: bb(i as u32), bindings: b.into_iter().map(v).collect() });
        }
        HighFunction {
            id: FuncId::from_index(id),
            name: None,
            signature: None,
            aliases: Vec::new(),
            blocks: arena,
            bindings,
            region,
            params: params.into_iter().map(v).collect(),
            returns: vec![],
        }
    }

    /// `helper(out, v)`: tag check, length 32 check, payload and
    /// discriminant stored.
    fn helper() -> HighFunction {
        let exprs = vec![
            Expr::Phi { incoming: vec![] }, // v0 out
            Expr::Phi { incoming: vec![] }, // v1 v
            Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck { value: v(1), tag: TAG_BYTES_OBJECT, negated: true })), // v2
            Expr::Semantic(SemanticOp::Known(KnownOp::BufOp { kind: BufOpKind::BytesLen, args: vec![v(1)] })), // v3
            Expr::Literal(Literal::U32(32)),                                        // v4
            Expr::Binary { op: BinaryOp::Ne, lhs: v(3), rhs: v(4) },               // v5
            Expr::Store { addr: v(0), value: v(1), offset: 8, width: MemWidth::W8 }, // v6
            Expr::Literal(Literal::I64(1)),                                         // v7
            Expr::Literal(Literal::I64(0)),                                         // v8
            Expr::Phi { incoming: vec![(bb(0), v(7)), (bb(1), v(7)), (bb(2), v(8))] }, // v9 d
            Expr::Store { addr: v(0), value: v(9), offset: 0, width: MemWidth::W8 }, // v10
        ];
        let to_d = |src: u32| Region::Transfer { target: bb(3), transfer: vec![(v(9), v(src))] };
        let region = Region::Sequence(vec![
            Region::Basic(bb(0)),
            Region::If {
                cond: v(2),
                then_region: Box::new(to_d(7)),
                else_region: Some(Box::new(Region::Sequence(vec![
                    Region::Basic(bb(1)),
                    Region::If {
                        cond: v(5),
                        then_region: Box::new(to_d(7)),
                        else_region: Some(Box::new(Region::Sequence(vec![Region::Basic(bb(2)), to_d(8)]))),
                    },
                ]))),
            },
            Region::Basic(bb(3)),
        ]);
        build(1, exprs, vec![vec![2, 7, 8], vec![3, 4, 5], vec![6], vec![10]], region, vec![0, 1])
    }

    /// A caller converting `source` and unwrapping the result.
    fn caller(source: Expr) -> HighFunction {
        let exprs = vec![
            Expr::Literal(Literal::I32(1024)), // v0 frame
            source,                            // v1
            Expr::Call { target: FuncId::from_index(1), args: vec![v(0), v(1)] }, // v2
            Expr::Load { addr: v(0), offset: 0, width: MemWidth::W8, signed: None, ty: IrType::Unknown(UnknownReason::InsufficientEvidence) }, // v3
            Expr::Load { addr: v(0), offset: 8, width: MemWidth::W8, signed: None, ty: IrType::Unknown(UnknownReason::InsufficientEvidence) }, // v4
        ];
        build(0, exprs, vec![vec![0, 1, 2, 3, 4]], Region::Basic(bb(0)), vec![])
    }

    fn storage_read() -> Expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet {
            tier: StorageTier::Known(KnownTier::Instance),
            durability: v(0),
            key: v(0),
            resolved_key: None,
            missing: Missing::Unwrap,
        }))
    }

    #[test]
    fn the_helper_is_recognised_with_its_width() {
        assert_eq!(converter_width(&helper(), true), Some(32));
        assert_eq!(converter_width(&helper(), false), None, "it has a tag check");
    }

    /// The point: the payload read is the storage read, now a `BytesN<32>`,
    /// and the discriminant is `Ok`.
    #[test]
    fn a_converted_storage_read_is_the_typed_read() {
        let mut ir = module(vec![caller(storage_read()), helper()]);
        assert!(BytesNConvertPass.run(&mut ir).changed);
        let f = &ir.functions[0];
        assert!(matches!(f.bindings.get(v(4)).map(|b| &b.expr), Some(Expr::Use(x)) if *x == v(1)));
        assert!(matches!(f.bindings.get(v(3)).map(|b| &b.expr), Some(Expr::Literal(Literal::I64(0)))));
        assert_eq!(f.bindings.get(v(1)).map(|b| b.ty.clone()), Some(IrType::Known(KnownType::BytesN(32))));
    }

    /// Anything but a storage read keeps its conversion: only the typed
    /// read re-performs it.
    #[test]
    fn a_value_that_is_not_a_storage_read_is_left_alone() {
        let mut ir = module(vec![caller(Expr::Phi { incoming: vec![] }), helper()]);
        assert!(!BytesNConvertPass.run(&mut ir).changed);
    }

    /// func_1 without its tag check, its length unpacked from the `U32Val`
    /// as privacy_pools' is: `if (len(v) >> 32) as u32 != 32 { d = 1 } else
    /// { store out+8 <- v; d = 0 }; store out <- d`.
    fn length_half() -> HighFunction {
        let exprs = vec![
            Expr::Phi { incoming: vec![] }, // v0 out
            Expr::Phi { incoming: vec![] }, // v1 v
            Expr::Semantic(SemanticOp::Known(KnownOp::BufOp { kind: BufOpKind::BytesLen, args: vec![v(1)] })), // v2
            Expr::Literal(Literal::I64(32)),                                        // v3
            Expr::Binary { op: BinaryOp::ShrU, lhs: v(2), rhs: v(3) },             // v4
            Expr::Unary { op: UnaryOp::Wrap32, value: v(4) },                       // v5
            Expr::Literal(Literal::I32(32)),                                        // v6
            Expr::Binary { op: BinaryOp::Ne, lhs: v(5), rhs: v(6) },               // v7
            Expr::Store { addr: v(0), value: v(1), offset: 8, width: MemWidth::W8 }, // v8
            Expr::Literal(Literal::I64(1)),                                         // v9
            Expr::Literal(Literal::I64(0)),                                         // v10
            Expr::Phi { incoming: vec![(bb(0), v(9)), (bb(1), v(10))] },            // v11 d
            Expr::Store { addr: v(0), value: v(11), offset: 0, width: MemWidth::W8 }, // v12
        ];
        let to_d = |src: u32| Region::Transfer { target: bb(2), transfer: vec![(v(11), v(src))] };
        let region = Region::Sequence(vec![
            Region::Basic(bb(0)),
            Region::If {
                cond: v(7),
                then_region: Box::new(to_d(9)),
                else_region: Some(Box::new(Region::Sequence(vec![Region::Basic(bb(1)), to_d(10)]))),
            },
            Region::Basic(bb(2)),
            Region::Return { values: vec![] },
        ]);
        build(2, exprs, vec![vec![2, 3, 4, 5, 6, 7, 9], vec![8, 10], vec![12]], region, vec![0, 1])
    }

    /// func_3, the tag half handed the value's address: `v = load p; if
    /// has_tag(v, Bytes) { func_2(out, v); return } store out <- 1`.
    /// `fail` is the constant the failing path stores.
    fn tag_half(fail: i64) -> HighFunction {
        let exprs = vec![
            Expr::Phi { incoming: vec![] }, // v0 out
            Expr::Phi { incoming: vec![] }, // v1 env
            Expr::Phi { incoming: vec![] }, // v2 p
            Expr::Load { addr: v(2), offset: 0, width: MemWidth::W8, signed: None, ty: IrType::Unknown(UnknownReason::InsufficientEvidence) }, // v3
            Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck { value: v(3), tag: TAG_BYTES_OBJECT, negated: false })), // v4
            Expr::Call { target: FuncId::from_index(2), args: vec![v(0), v(3)] },   // v5
            Expr::Literal(Literal::I64(fail)),                                      // v6
            Expr::Store { addr: v(0), value: v(6), offset: 0, width: MemWidth::W8 }, // v7
        ];
        let region = Region::Sequence(vec![
            Region::Basic(bb(0)),
            Region::If {
                cond: v(4),
                then_region: Box::new(Region::Sequence(vec![Region::Basic(bb(1)), Region::Return { values: vec![] }])),
                else_region: None,
            },
            Region::Basic(bb(2)),
            Region::Return { values: vec![] },
        ]);
        build(3, exprs, vec![vec![3, 4], vec![5], vec![6, 7]], region, vec![0, 1, 2])
    }

    /// A caller storing a storage read at `fp+8` and converting it through
    /// its address: `func_3(fp+16, env, fp+8)`, then reading the result.
    fn by_ref_caller() -> HighFunction {
        let exprs = vec![
            Expr::Phi { incoming: vec![] },    // v0 frame
            storage_read(),                    // v1
            Expr::Store { addr: v(0), value: v(1), offset: 8, width: MemWidth::W8 }, // v2
            Expr::Literal(Literal::I32(16)),   // v3
            Expr::Binary { op: BinaryOp::Add, lhs: v(0), rhs: v(3) }, // v4 fp+16
            Expr::Literal(Literal::I32(8)),    // v5
            Expr::Binary { op: BinaryOp::Add, lhs: v(0), rhs: v(5) }, // v6 fp+8
            Expr::Phi { incoming: vec![] },    // v7 env
            Expr::Call { target: FuncId::from_index(3), args: vec![v(4), v(7), v(6)] }, // v8
            Expr::Load { addr: v(0), offset: 16, width: MemWidth::W8, signed: None, ty: IrType::Unknown(UnknownReason::InsufficientEvidence) }, // v9
            Expr::Load { addr: v(0), offset: 24, width: MemWidth::W8, signed: None, ty: IrType::Unknown(UnknownReason::InsufficientEvidence) }, // v10
        ];
        build(0, exprs, vec![vec![1, 2, 3, 4, 5, 6, 8, 9, 10]], Region::Basic(bb(0)), vec![])
    }

    #[test]
    fn a_conversion_split_in_two_and_handed_the_address_is_recognised() {
        assert_eq!(converter_width(&length_half(), false), Some(32));
        assert_eq!(converter_width(&length_half(), true), None, "no tag check of its own");
        let lengths = HashMap::from([(FuncId::from_index(2), 32)]);
        assert_eq!(
            split_converter(&tag_half(1), &lengths),
            Some(Converter { width: 32, out: 0, value: 2, by_ref: Some(0) })
        );
        // The failing path must write the error the whole conversion does.
        assert_eq!(split_converter(&tag_half(0), &lengths), None);
        assert_eq!(split_converter(&tag_half(1), &HashMap::new()), None, "its call must be the length half");
    }

    #[test]
    fn a_storage_read_converted_through_its_address_is_the_typed_read() {
        let mut ir = module(vec![by_ref_caller(), helper(), length_half(), tag_half(1)]);
        assert!(BytesNConvertPass.run(&mut ir).changed);
        let f = &ir.functions[0];
        assert!(matches!(f.bindings.get(v(10)).map(|b| &b.expr), Some(Expr::Use(x)) if *x == v(1)));
        assert!(matches!(f.bindings.get(v(9)).map(|b| &b.expr), Some(Expr::Literal(Literal::I64(0)))));
        assert!(matches!(f.bindings.get(v(8)).map(|b| &b.expr), Some(Expr::Literal(Literal::Unit))));
        assert_eq!(f.bindings.get(v(1)).map(|b| b.ty.clone()), Some(IrType::Known(KnownType::BytesN(32))));
    }

    #[test]
    fn a_write_between_the_store_and_the_call_keeps_the_conversion() {
        // A call between them may write the bytes the converter reads.
        let mut f = by_ref_caller();
        f.bindings.push(Binding::new(
            v(11),
            IrType::Unknown(UnknownReason::InsufficientEvidence),
            Expr::Call { target: FuncId::from_index(9), args: vec![] },
            Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
        ));
        let entry = &mut f.blocks.get_mut(bb(0)).unwrap().bindings;
        let at = entry.iter().position(|b| *b == v(8)).unwrap();
        entry.insert(at, v(11));
        let mut ir = module(vec![f, helper(), length_half(), tag_half(1)]);
        assert!(!BytesNConvertPass.run(&mut ir).changed);
    }
}
