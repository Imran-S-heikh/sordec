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
    Region, SemanticOp,
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
        let converters: HashMap<FuncId, u32> =
            ir.functions.iter().filter_map(|h| Some((h.id, converter_width(h)?))).collect();
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

/// `N`, when `h` is exactly the outlined `BytesN<N>::try_from_val`.
fn converter_width(h: &HighFunction) -> Option<u32> {
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
    let (tag_check, (len_check, n), payload_store, (_, disc)) =
        (tag_check?, len_check?, payload_store?, disc_store?);

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
    passes_both(&h.region, tag_check, len_check, ok_block).then_some(n)
}

/// Whether `value` is `bytes_len(v)`, through renames.
fn is_len_of(h: &HighFunction, value: ValueId, v: ValueId) -> bool {
    matches!(
        h.bindings.get(resolve_use(h, value)).map(|b| &b.expr),
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

fn site(func: &HighFunction, call: ValueId, converters: &HashMap<FuncId, u32>) -> Option<Site> {
    let Expr::Call { target, args } = &func.bindings.get(call)?.expr else {
        return None;
    };
    let width = *converters.get(target)?;
    let [frame, value] = args[..] else {
        return None;
    };
    let frame = resolve_use(func, frame);
    let read = resolve_use(func, value);
    // A storage read: its typed spelling is the conversion.
    if !matches!(
        func.bindings.get(read).map(|b| &b.expr),
        Some(Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet { .. })))
    ) {
        return None;
    }
    // Every access to the frame is the result's two words, read back.
    let mut discs = Vec::new();
    let mut payloads = Vec::new();
    for id in emission_order(func) {
        let Some(b) = func.bindings.get(id) else { continue };
        match &b.expr {
            Expr::Load { addr, offset, .. } if resolve_use(func, *addr) == frame => match offset {
                0 => discs.push(id),
                8 => payloads.push(id),
                _ => return None,
            },
            Expr::Store { addr, .. } if resolve_use(func, *addr) == frame => return None,
            Expr::Call { args, .. } if id != call && args.iter().any(|a| resolve_use(func, *a) == frame) => {
                return None;
            }
            _ => {}
        }
    }
    (!discs.is_empty() && !payloads.is_empty()).then_some(Site { call, read, width, discs, payloads })
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
        assert_eq!(converter_width(&helper()), Some(32));
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
}
