//! A `Result` an entrypoint builds in its own frame, and the helper that
//! turns it into the entrypoint's `Val`.
//!
//! # The shape
//!
//! [`super::result_out`] takes a `Result` a helper writes into its caller's
//! frame. Here no helper writes it: the entrypoint matches on a
//! cross-contract call's outcome and builds its own `Result<u64, Error>`
//! in its frame, a tag byte at `+0`, an error byte at `+1` and the `u64` at
//! `+8`, each path writing its own payload and handing its tag to one
//! merge, which stores it:
//!
//! ```text
//! 'done: {                                     fn func3(p) -> Val {
//!     ...                                          if load8(p+0) != 1 {
//!     if ok { store fp+24 <- x; tag = 0;               r = func0(load(p+8)).1  // u64 → Val
//!             break 'done }                        } else {
//!     if overflow { store8 fp+17 <- 1;                 r = select(Error(1), Error(0),
//!                   tag = 1; break 'done }                        load8(p+1))
//!     store8 fp+17 <- 0; tag = 1                   }
//! }                                                return r
//! store8 fp+16 <- tag                          }
//! return func3(fp+16)
//! ```
//!
//! `func3` is the SDK's `IntoVal` for that `Result`. Left as it is, its
//! merge holds an error word on one side and a `Val` on the other, and the
//! entrypoint declared `-> Result<u64, Error>` returns an `i64`.
//!
//! # The rewrite
//!
//! Each path builds the `Result` the converter would have read back — on
//! the path above, `Ok(x)`, `Err(Error::from_contract_error(1))` and
//! `Err(Error::from_contract_error(0))` — a new merge carries it to the
//! converter's call, and the call becomes that merge. The stores are left
//! for the frame clean-up, which now finds nothing reading them, and the
//! converter, with no caller left, is not emitted.
//!
//! # Why it is exact
//!
//! Composition, path by path. Every path into the merge ends with one
//! block and then the edge, and assigns the tag a constant. Between the
//! merge and the converter's call the entrypoint only stores that tag; so
//! when the converter runs, the bytes it reads are the tag the path chose
//! and whatever that path's last block stored last at each slot. The
//! converter's test on the tag, evaluated at the path's constant, picks
//! its side:
//!
//! - **The `Ok` side** returns the encode, as `T`, of the eight bytes at
//!   the `Ok` slot — the helper encodes nothing but its argument
//!   ([`super::encode_helper`]). The path's last block stored `x` there,
//!   so the converter returned `x`'s encoding: the path built `Ok(x)`.
//! - **The `Err` side** returns one of two contract-error words, chosen by
//!   the error byte (or the one word, when there is no choice). The path's
//!   last block stored a constant there, so the converter returned that
//!   error: the path built `Err(e)`, and `Error::from_contract_error(code)`
//!   is that word's value.
//!
//! The entrypoint returns the converter's result, and the spec declares it
//! returns `Result<T, Error>` with the same `T`; the SDK's wrapper returns
//! `result.into_val(..)` for such an entrypoint, which is the same word.
//! Nothing else is lost: the converter only reads, and the bytes no longer
//! read are in the entrypoint's own frame, gone once it returns.
//!
//! # Gates
//!
//! - **The converter**: a helper (no spec) of one pointer parameter, whose
//!   body is one `if` on a byte read from the pointer compared with a
//!   constant, each side handing the merge it returns one value: component
//!   of a helper that only encodes, applied to an eight-byte read from the
//!   pointer, as `T`; or a select between two contract-error words by a
//!   byte read from the pointer, or one such word. Every other binding pure;
//!   the pointer read by nothing but those reads.
//! - **The call**: in the block a labeled scope exits to, right before a
//!   `return` of the call's value; before it in that block only pure
//!   bindings and one one-byte store of the tag at the converter's tag slot,
//!   after it only pure bindings and the shadow-stack epilogue.
//! - **The tag**: a merge every edge into it assigns a constant, each edge
//!   right after a block, inside that scope, targeting the call's block.
//! - **Each path**: on the side its tag picks, its last block stores the
//!   slot that side reads — eight bytes at the `Ok` slot, or a constant
//!   byte at the error slot — and after that store does nothing but pure
//!   work. A value stored for `Ok` that is already typed is typed `T`.
//! - **The entrypoint** declares `Result<T, Error>`, `T` the converter's
//!   `Ok` type and `Error` the SDK's own.

use std::collections::{HashMap, HashSet};

use sordec_common::{BlockId, FuncId, IrId, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{
    BinaryOp, Binding, CompositeType, Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, MemWidth,
    PrimitiveType, Region, SemanticOp, TypeRef, WasmOpcodeKind,
};

use super::encode_helper::EncoderTable;
use super::result_out::{branch_value, carry};
use super::sret::emission_order;
use crate::dataflow::{block_containing, canon_addr, resolve_use, trace_int};
use crate::effects::expr_effects;
use crate::metrics_catalog::MARSHALLING_RESULT_INLINE_REWRITTEN as M_REWRITTEN;
use crate::pass::{Pass, PassResult};
use crate::type_infer::known_of_type_ref;
use crate::val_abi::decode_contract_error;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-result-inline";

/// Rewrites a `Result` built in an entrypoint's frame and converted by a
/// helper to the `Result` itself.
#[derive(Debug, Default, Clone, Copy)]
pub struct ResultInlinePass;

impl Pass<HighIr> for ResultInlinePass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let encoders = EncoderTable::build(ir);
        let converters: HashMap<FuncId, Converter> =
            ir.functions.iter().filter_map(|f| classify(f, &encoders).map(|c| (f.id, c))).collect();
        if converters.is_empty() {
            return result;
        }
        for func in &mut ir.functions {
            let Some(ok_ty) = declared_ok(func) else { continue };
            let sites: Vec<Site> = emission_order(func)
                .into_iter()
                .filter_map(|call| {
                    let Expr::Call { target, .. } = &func.bindings.get(call)?.expr else { return None };
                    let conv = converters.get(target)?;
                    (conv.ok_ty == ok_ty).then_some(())?;
                    plan(func, call, conv)
                })
                .collect();
            for site in sites {
                apply(func, &site, &ok_ty);
                result.metrics.increment(M_REWRITTEN, 1);
                result.changed = true;
            }
        }
        result
    }
}

/// What a converter reads, and how it decides.
#[derive(Debug, Clone)]
struct Converter {
    /// The tag byte's offset from the pointer.
    tag: u32,
    /// The tag test: equality or inequality with this constant.
    test: (BinaryOp, i128),
    /// Whether the test's true side is the `Ok` side.
    ok_when_true: bool,
    /// The `Ok` payload's offset, and the type it is encoded as.
    ok: u32,
    ok_ty: KnownType,
    err: ErrSide,
}

/// The converter's `Err` side.
#[derive(Debug, Clone)]
enum ErrSide {
    /// One contract-error code.
    Code(u32),
    /// The code chosen by the byte at this offset: the first when it is
    /// nonzero, the second when it is zero.
    ByByte { at: u32, nonzero: u32, zero: u32 },
}

/// The `Ok` type an entrypoint declares in a `Result<T, Error>` with the
/// SDK's own error.
fn declared_ok(func: &HighFunction) -> Option<KnownType> {
    let [TypeRef::Composite(CompositeType::Result(ok, err))] = func.signature.as_ref()?.outputs.as_slice() else {
        return None;
    };
    if !matches!(err.as_ref(), TypeRef::Primitive(PrimitiveType::Error)) {
        return None;
    }
    known_of_type_ref(ok)
}

/// `func` as a converter, when it is one.
fn classify(func: &HighFunction, encoders: &EncoderTable) -> Option<Converter> {
    if func.signature.is_some() || func.name.is_some() {
        return None;
    }
    let [ptr] = func.params.as_slice() else { return None };
    let Region::Sequence(items) = &func.region else { return None };
    let (Region::Return { values }, body) = items.split_last()? else { return None };
    let [merged] = values.as_slice() else { return None };
    let mut branch = None;
    for item in body {
        match item {
            Region::Basic(_) => {}
            Region::If { cond, then_region, else_region: Some(e) } if branch.is_none() => {
                branch = Some((*cond, &**then_region, &**e));
            }
            _ => return None,
        }
    }
    let (cond, then_region, else_region) = branch?;
    if func.returns.iter().any(|r| r.as_slice() != [*merged]) {
        return None;
    }
    let read = |value: ValueId, width: MemWidth| -> Option<(ValueId, u32)> {
        let id = resolve_use(func, value);
        let Expr::Load { addr, offset, width: w, .. } = &func.bindings.get(id)?.expr else { return None };
        let (base, off) = canon_addr(func, *addr);
        (base == *ptr && *w == width).then_some((id, off.checked_add(*offset)?))
    };

    // The tag test.
    let Expr::Binary { op: op @ (BinaryOp::Eq | BinaryOp::Ne), lhs, rhs } = &func.bindings.get(resolve_use(func, cond))?.expr
    else {
        return None;
    };
    let (tag_load, tag) = read(*lhs, MemWidth::W1)?;
    let k = trace_int(func, *rhs)?;

    // The two sides.
    let mut loads: HashSet<ValueId> = HashSet::from([tag_load]);
    let mut calls: HashSet<ValueId> = HashSet::new();
    let mut ok_side = |value: ValueId, loads: &mut HashSet<ValueId>| -> Option<(u32, KnownType)> {
        let (payload, ty) = encoders.encoded_by_call(func, value)?;
        let (load, at) = read(payload, MemWidth::W8)?;
        loads.insert(load);
        if let Expr::Project { value: call, .. } = &func.bindings.get(resolve_use(func, value))?.expr {
            calls.insert(resolve_use(func, *call));
        }
        Some((at, ty))
    };
    let err_side = |value: ValueId, loads: &mut HashSet<ValueId>| -> Option<ErrSide> {
        let code = |v: ValueId| decode_contract_error(trace_int(func, v)? as u64);
        match &func.bindings.get(resolve_use(func, value))?.expr {
            Expr::Unknown { op_kind: WasmOpcodeKind::Select, args, .. } if args.len() == 3 => {
                let (load, at) = read(args[2], MemWidth::W1)?;
                loads.insert(load);
                Some(ErrSide::ByByte { at, nonzero: code(args[0])?, zero: code(args[1])? })
            }
            Expr::Select { cond, if_true, if_false } => {
                let (load, at) = read(*cond, MemWidth::W1)?;
                loads.insert(load);
                Some(ErrSide::ByByte { at, nonzero: code(*if_true)?, zero: code(*if_false)? })
            }
            Expr::Literal(_) => Some(ErrSide::Code(code(value)?)),
            _ => None,
        }
    };
    let then_value = branch_value(then_region, *merged)?;
    let else_value = branch_value(else_region, *merged)?;
    let (ok_when_true, (ok, ok_ty), err) = if let Some(ok) = ok_side(then_value, &mut loads) {
        (true, ok, err_side(else_value, &mut loads)?)
    } else {
        let ok = ok_side(else_value, &mut loads)?;
        (false, ok, err_side(then_value, &mut loads)?)
    };

    // Nothing else: every binding pure, but those reads and the encode
    // helper's call; the pointer read by nothing but those reads.
    for id in emission_order(func) {
        let expr = &func.bindings.get(id)?.expr;
        let fine = match expr {
            Expr::Load { .. } => loads.contains(&id),
            Expr::Call { .. } => calls.contains(&id),
            other => expr_effects(other).is_pure_total(),
        };
        if !fine {
            return None;
        }
    }
    let mut derived: HashSet<ValueId> = HashSet::from([*ptr]);
    for id in emission_order(func) {
        if let Some(Expr::Binary { op: BinaryOp::Add, lhs, rhs }) = func.bindings.get(id).map(|b| &b.expr)
            && derived.contains(&resolve_use(func, *lhs))
            && trace_int(func, *rhs).is_some()
        {
            derived.insert(id);
        }
    }
    for id in emission_order(func) {
        let Some(binding) = func.bindings.get(id) else { continue };
        if loads.contains(&id) || derived.contains(&id) || matches!(binding.expr, Expr::Use(_)) {
            continue;
        }
        let mut reads = false;
        binding.expr.for_each_value_use(|u| reads |= derived.contains(&resolve_use(func, u)));
        if reads {
            return None;
        }
    }
    let mut region_reads = false;
    func.region.for_each_value_use(|u| region_reads |= derived.contains(&resolve_use(func, u)));
    if region_reads {
        return None;
    }
    Some(Converter { tag, test: (*op, k), ok_when_true, ok, ok_ty, err })
}

/// One converter call ready to become the `Result` its paths built.
struct Site {
    call: ValueId,
    /// Each path: its last block, and what it built.
    paths: Vec<(BlockId, Built)>,
}

/// What one path built.
enum Built {
    Ok(ValueId),
    Err(u32),
}

/// The plan for the converter call `call`, when every gate holds.
fn plan(func: &HighFunction, call: ValueId, conv: &Converter) -> Option<Site> {
    let Expr::Call { args, .. } = &func.bindings.get(call)?.expr else { return None };
    let [arg] = args.as_slice() else { return None };
    let (base, slot) = canon_addr(func, *arg);
    let at = |off: u32| slot.checked_add(off);
    let merge = block_containing(func, call)?;
    let order = &func.blocks.get(merge)?.bindings;
    let pos = order.iter().position(|id| *id == call)?;

    // Before the call: pure work and the tag's store.
    let mut tag: Option<ValueId> = None;
    for id in &order[..pos] {
        let expr = &func.bindings.get(*id)?.expr;
        match expr {
            Expr::Store { addr, value, offset, width: MemWidth::W1 } if tag.is_none() => {
                let (b, o) = canon_addr(func, *addr);
                if b != base || o.checked_add(*offset)? != at(conv.tag)? {
                    return None;
                }
                tag = Some(resolve_use(func, *value));
            }
            other if expr_effects(other).is_pure_total() => {}
            _ => return None,
        }
    }
    // After it: pure work and the epilogue.
    for id in &order[pos + 1..] {
        let expr = &func.bindings.get(*id)?.expr;
        let epilogue = matches!(expr, Expr::Unknown { op_kind: WasmOpcodeKind::GlobalSet, .. });
        if !epilogue && !expr_effects(expr).is_pure_total() {
            return None;
        }
    }
    let tag = tag?;
    if !matches!(func.bindings.get(tag)?.expr, Expr::Phi { .. }) {
        return None;
    }
    // The call's value: returned right after its block, and read by
    // nothing else.
    if !returned_after(&func.region, merge, call) {
        return None;
    }
    let mut reads = 0;
    for (_, b) in func.bindings.iter() {
        b.expr.for_each_value_use(|u| reads += usize::from(u == call));
    }
    func.region.for_each_value_use(|u| reads += usize::from(u == call));
    if reads != 1 {
        return None;
    }

    // The tag's edges: each after a block, into the call's block.
    let mut edges: Vec<(BlockId, ValueId, BlockId)> = Vec::new();
    let mut stray = false;
    tag_edges(&func.region, tag, &mut edges, &mut stray);
    if stray || edges.is_empty() || edges.iter().any(|(_, _, target)| *target != merge) {
        return None;
    }
    let mut paths = Vec::with_capacity(edges.len());
    for (block, source, _) in edges {
        let t = trace_int(func, source)? & 0xff;
        let test = match conv.test.0 {
            BinaryOp::Eq => t == conv.test.1,
            _ => t != conv.test.1,
        };
        let built = if test == conv.ok_when_true {
            let (value, _) = last_store(func, block, base, at(conv.ok)?, MemWidth::W8)?;
            // The converter reads the word as `T`; a value already known
            // as anything else would be `Ok` of the wrong type.
            match &func.bindings.get(resolve_use(func, value))?.ty {
                IrType::Known(k) | IrType::Inferred(k) if *k != conv.ok_ty => return None,
                _ => {}
            }
            Built::Ok(value)
        } else {
            match conv.err {
                ErrSide::Code(code) => Built::Err(code),
                ErrSide::ByByte { at: byte, nonzero, zero } => {
                    let (value, _) = last_store(func, block, base, at(byte)?, MemWidth::W1)?;
                    Built::Err(if trace_int(func, value)? & 0xff != 0 { nonzero } else { zero })
                }
            }
        };
        paths.push((block, built));
    }
    Some(Site { call, paths })
}

/// Whether the region returns `call` itself right after `block`.
fn returned_after(region: &Region, block: BlockId, call: ValueId) -> bool {
    let mut found = false;
    region.for_each_node(|node| {
        let Region::Sequence(items) = node else { return };
        for pair in items.windows(2) {
            if let [Region::Basic(b), Region::Return { values }] = pair
                && *b == block
                && values.as_slice() == [call]
            {
                found = true;
            }
        }
    });
    found
}

/// Every edge assigning `tag`: the block right before it, the value, and
/// the edge's target. `stray` is set by an edge not right after a block.
fn tag_edges(region: &Region, tag: ValueId, out: &mut Vec<(BlockId, ValueId, BlockId)>, stray: &mut bool) {
    match region {
        Region::Sequence(items) => {
            for (i, item) in items.iter().enumerate() {
                if let Region::Break { target, transfer } | Region::Transfer { target, transfer } = item {
                    for (phi, source) in transfer {
                        if *phi != tag {
                            continue;
                        }
                        match i.checked_sub(1).map(|j| &items[j]) {
                            Some(Region::Basic(b)) => out.push((*b, *source, *target)),
                            _ => *stray = true,
                        }
                    }
                } else {
                    tag_edges(item, tag, out, stray);
                }
            }
        }
        Region::Scope { body, .. } | Region::Loop { body, .. } => tag_edges(body, tag, out, stray),
        Region::If { then_region, else_region, .. } => {
            tag_edges(then_region, tag, out, stray);
            if let Some(e) = else_region {
                tag_edges(e, tag, out, stray);
            }
        }
        Region::Switch { arms, default, .. } => {
            for arm in arms {
                tag_edges(&arm.body, tag, out, stray);
            }
            tag_edges(default, tag, out, stray);
        }
        Region::Break { transfer, .. } | Region::Continue { transfer, .. } | Region::Transfer { transfer, .. } => {
            *stray |= transfer.iter().any(|(phi, _)| *phi == tag);
        }
        _ => {}
    }
}

/// The value the last store in `block` writes at `base + at`, exactly
/// `width` wide, when everything after it in the block is pure.
fn last_store(func: &HighFunction, block: BlockId, base: ValueId, at: u32, width: MemWidth) -> Option<(ValueId, ValueId)> {
    let order = &func.blocks.get(block)?.bindings;
    for (i, id) in order.iter().enumerate().rev() {
        let expr = &func.bindings.get(*id)?.expr;
        match expr {
            Expr::Store { addr, value, offset, width: w } => {
                let (b, o) = canon_addr(func, *addr);
                if b != base || o.checked_add(*offset)? != at || *w != width {
                    return None;
                }
                let after_pure = order[i + 1..]
                    .iter()
                    .all(|later| func.bindings.get(*later).is_some_and(|l| expr_effects(&l.expr).is_pure_total()));
                return after_pure.then_some((*value, *id));
            }
            _ => continue,
        }
    }
    None
}

fn push(func: &mut HighFunction, expr: Expr, ty: IrType, note: &str) -> ValueId {
    let id = ValueId::from_index(func.bindings.len() as u32);
    func.bindings.push(Binding::new(id, ty, expr, Provenance::new(PASS_NAME, ProvenanceSource::SdkPattern, note)));
    id
}

/// Each path builds its `Result`; a merge carries it to the call, which
/// becomes the merge.
fn apply(func: &mut HighFunction, site: &Site, ok_ty: &KnownType) {
    let result_ty = KnownType::Result(
        Box::new(IrType::Known(ok_ty.clone())),
        Box::new(IrType::Known(KnownType::Error)),
    );
    let mut built: Vec<(BlockId, ValueId)> = Vec::new();
    for (block, what) in &site.paths {
        let mut new = Vec::new();
        let value = match what {
            Built::Ok(x) => push(
                func,
                Expr::Variant { name: "Ok".to_string(), payload: vec![*x] },
                IrType::Inferred(result_ty.clone()),
                "this path stored the `Ok` tag and its value in the frame the converter reads: `Ok(value)`",
            ),
            Built::Err(code) => {
                let e = push(
                    func,
                    Expr::Semantic(SemanticOp::Known(KnownOp::MakeError { code: *code, resolved: None })),
                    IrType::Known(KnownType::Error),
                    "the contract error the converter reads back for the byte this path stored",
                );
                new.push(e);
                push(
                    func,
                    Expr::Variant { name: "Err".to_string(), payload: vec![e] },
                    IrType::Inferred(result_ty.clone()),
                    "this path stored the `Err` tag and an error in the frame the converter reads: `Err(error)`",
                )
            }
        };
        new.push(value);
        if let Some(b) = func.blocks.get_mut(*block) {
            b.bindings.extend(new);
        }
        built.push((*block, value));
    }
    let merged = push(
        func,
        Expr::Phi { incoming: built.clone() },
        IrType::Inferred(result_ty.clone()),
        "the `Result` each path built, merged where the paths meet",
    );
    let by_block: HashMap<BlockId, ValueId> = built.into_iter().collect();
    carry(&mut func.region, &by_block, merged);
    if let Some(b) = func.bindings.get_mut(site.call) {
        b.expr = Expr::Use(merged);
        b.ty = IrType::Inferred(result_ty);
        b.add_provenance(Provenance::new(
            PASS_NAME,
            ProvenanceSource::SdkPattern,
            "the converter's call: the `Result` the paths built, which it would have encoded",
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{module, v};
    use sordec_common::{Arena, UnknownReason};
    use sordec_ir::{FunctionSignature, HighBlock, Literal, ValObjectKind};

    fn bb(i: u32) -> BlockId {
        BlockId::from_index(i)
    }

    /// A function over `exprs` (ids `0..N`), blocks laid out by `layout`.
    fn func(id: u32, exprs: Vec<Expr>, params: Vec<u32>, layout: Vec<Vec<u32>>, region: Region) -> HighFunction {
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        for expr in exprs {
            let vid = v(bindings.len() as u32);
            bindings.push(Binding::new(
                vid,
                IrType::Unknown(UnknownReason::InsufficientEvidence),
                expr,
                Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
            ));
        }
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        for (i, ids) in layout.into_iter().enumerate() {
            blocks.push(HighBlock { id: bb(i as u32), bindings: ids.into_iter().map(v).collect() });
        }
        let returns = {
            let mut r = Vec::new();
            region.for_each_node(|n| {
                if let Region::Return { values } = n {
                    r.push(values.clone());
                }
            });
            r
        };
        HighFunction {
            id: FuncId::from_index(id),
            name: None,
            signature: None,
            aliases: Vec::new(),
            blocks,
            bindings,
            region,
            params: params.into_iter().map(v).collect(),
            returns,
        }
    }

    fn load(addr: u32, offset: u32, width: MemWidth) -> Expr {
        Expr::Load { addr: v(addr), offset, width, signed: Some(false), ty: IrType::Unknown(UnknownReason::InsufficientEvidence) }
    }

    fn store(addr: u32, value: u32, offset: u32, width: MemWidth) -> Expr {
        Expr::Store { addr: v(addr), value: v(value), offset, width }
    }

    fn lit(n: i64) -> Expr {
        Expr::Literal(Literal::I64(n))
    }

    const ERR_1: i64 = (1 << 32) | 3;
    const ERR_0: i64 = 3;

    /// func 2: `r = x > MAX ? obj_from_u64(x) : val_encode<u64>(x); return (0, r)`.
    fn encoder() -> HighFunction {
        func(
            2,
            vec![
                Expr::Phi { incoming: vec![] }, // v0 x
                Expr::Semantic(SemanticOp::Known(KnownOp::ValObject { kind: ValObjectKind::ObjFromU64, args: vec![v(0)] })),
                Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty: KnownType::U64, value: v(0) })),
                Expr::Phi { incoming: vec![(bb(0), v(1)), (bb(0), v(2))] }, // v3
                lit(0),                                                     // v4
            ],
            vec![0],
            vec![vec![1, 2, 4]],
            Region::Sequence(vec![Region::Basic(bb(0)), Region::Return { values: vec![v(4), v(3)] }]),
        )
    }

    /// func 1, the converter: `load8(p) != 1 ? func2(load(p+8)).1 :
    /// select(ERR_1, ERR_0, load8(p+1))`.
    fn converter() -> HighFunction {
        func(
            1,
            vec![
                Expr::Phi { incoming: vec![] },                       // v0 p
                load(0, 0, MemWidth::W1),                             // v1 tag
                Expr::Literal(Literal::I32(1)),                       // v2
                Expr::Binary { op: BinaryOp::Ne, lhs: v(1), rhs: v(2) }, // v3
                load(0, 8, MemWidth::W8),                             // v4
                Expr::Call { target: FuncId::from_index(2), args: vec![v(4)] }, // v5
                Expr::Project { value: v(5), index: 1 },              // v6
                load(0, 1, MemWidth::W1),                             // v7
                lit(ERR_1),                                           // v8
                lit(ERR_0),                                           // v9
                Expr::Phi { incoming: vec![] },                       // v10 merged
                Expr::Unknown {
                    op_kind: WasmOpcodeKind::Select,
                    args: vec![v(8), v(9), v(7)],
                    reason: UnknownReason::UnsupportedPattern,
                }, // v11
            ],
            vec![0],
            vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9, 11], vec![]],
            Region::Sequence(vec![
                Region::Basic(bb(0)),
                Region::If {
                    cond: v(3),
                    then_region: Box::new(Region::Sequence(vec![
                        Region::Basic(bb(1)),
                        Region::Transfer { target: bb(3), transfer: vec![(v(10), v(6))] },
                    ])),
                    else_region: Some(Box::new(Region::Sequence(vec![
                        Region::Basic(bb(2)),
                        Region::Transfer { target: bb(3), transfer: vec![(v(10), v(11))] },
                    ]))),
                },
                Region::Basic(bb(3)),
                Region::Return { values: vec![v(10)] },
            ]),
        )
    }

    /// func 0, the entrypoint `-> Result<ok, Error>`: three paths into
    /// `'done`, each storing its payload and handing its tag over; then
    /// `store8 fp+16 <- tag; return func1(fp+16)`.
    fn entry(ok: PrimitiveType) -> HighFunction {
        let mut f = func(
            0,
            vec![
                Expr::Phi { incoming: vec![] },                       // v0 fp
                Expr::Phi { incoming: vec![] },                       // v1 x
                Expr::Phi { incoming: vec![] },                       // v2 c1
                Expr::Phi { incoming: vec![] },                       // v3 c2
                store(0, 1, 24, MemWidth::W8),                        // v4  Ok payload
                Expr::Literal(Literal::I32(0)),                       // v5  tag 0
                Expr::Literal(Literal::I32(1)),                       // v6
                store(0, 6, 17, MemWidth::W1),                        // v7  error byte 1
                Expr::Literal(Literal::I32(1)),                       // v8  tag 1
                Expr::Literal(Literal::I32(0)),                       // v9
                store(0, 9, 17, MemWidth::W1),                        // v10 error byte 0
                Expr::Literal(Literal::I32(1)),                       // v11 tag 1
                Expr::Literal(Literal::I32(16)),                      // v12
                Expr::Binary { op: BinaryOp::Add, lhs: v(0), rhs: v(12) }, // v13
                store(0, 20, 16, MemWidth::W1),                       // v14 the tag
                Expr::Call { target: FuncId::from_index(1), args: vec![v(13)] }, // v15
                Expr::Literal(Literal::Unit),                         // v16 spare
                Expr::Literal(Literal::Unit),                         // v17
                Expr::Literal(Literal::Unit),                         // v18
                Expr::Literal(Literal::Unit),                         // v19
                Expr::Phi { incoming: vec![] },                       // v20 tag merge
            ],
            vec![1],
            vec![vec![], vec![4, 5, 16], vec![6, 7, 8], vec![9, 10, 11], vec![12, 13, 19, 14, 15]],
            Region::Sequence(vec![
                Region::Basic(bb(0)),
                Region::Scope {
                    out: bb(4),
                    body: Box::new(Region::Sequence(vec![
                        Region::If {
                            cond: v(2),
                            then_region: Box::new(Region::Sequence(vec![
                                Region::Basic(bb(1)),
                                Region::Break { target: bb(4), transfer: vec![(v(20), v(5))] },
                            ])),
                            else_region: None,
                        },
                        Region::If {
                            cond: v(3),
                            then_region: Box::new(Region::Sequence(vec![
                                Region::Basic(bb(2)),
                                Region::Break { target: bb(4), transfer: vec![(v(20), v(8))] },
                            ])),
                            else_region: None,
                        },
                        Region::Basic(bb(3)),
                        Region::Transfer { target: bb(4), transfer: vec![(v(20), v(11))] },
                    ])),
                },
                Region::Basic(bb(4)),
                Region::Return { values: vec![v(15)] },
            ]),
        );
        f.signature = Some(FunctionSignature {
            name: "safe_add".to_string(),
            inputs: vec![],
            outputs: vec![TypeRef::Composite(CompositeType::Result(
                Box::new(TypeRef::Primitive(ok)),
                Box::new(TypeRef::Primitive(PrimitiveType::Error)),
            ))],
        });
        f
    }

    fn run(entry: HighFunction) -> (bool, HighIr) {
        let mut ir = module(vec![entry, converter(), encoder()]);
        let changed = ResultInlinePass.run(&mut ir).changed;
        (changed, ir)
    }

    #[test]
    fn each_path_builds_the_result_the_converter_would_read() {
        let (changed, ir) = run(entry(PrimitiveType::U64));
        assert!(changed);
        let f = &ir.functions[0];
        let Expr::Use(merged) = f.bindings.get(v(15)).unwrap().expr else {
            panic!("the call is the merge: {:?}", f.bindings.get(v(15)).unwrap().expr);
        };
        let Expr::Phi { incoming } = &f.bindings.get(merged).unwrap().expr else { panic!("a merge") };
        let built: HashMap<BlockId, &Expr> =
            incoming.iter().map(|(b, x)| (*b, &f.bindings.get(*x).unwrap().expr)).collect();
        assert!(matches!(built[&bb(1)], Expr::Variant { name, payload } if name == "Ok" && payload == &vec![v(1)]));
        let code = |b: u32| {
            let Expr::Variant { name, payload } = built[&bb(b)] else { panic!() };
            assert_eq!(name, "Err");
            match f.bindings.get(payload[0]).unwrap().expr {
                Expr::Semantic(SemanticOp::Known(KnownOp::MakeError { code, resolved: None })) => code,
                ref other => panic!("{other:?}"),
            }
        };
        assert_eq!(code(2), 1, "the error byte 1 picks the first word");
        assert_eq!(code(3), 0, "the error byte 0 picks the second");
        // Each edge carries its path's value into the merge.
        let mut carried = 0;
        f.region.for_each_node(|n| {
            if let Region::Break { transfer, .. } | Region::Transfer { transfer, .. } = n {
                carried += transfer.iter().filter(|(p, _)| *p == merged).count();
            }
        });
        assert_eq!(carried, 3);
    }

    #[test]
    fn a_declared_ok_type_other_than_the_encoded_one_is_refused() {
        assert!(!run(entry(PrimitiveType::I64)).0);
    }

    #[test]
    fn an_ok_value_of_another_type_is_refused() {
        let mut f = entry(PrimitiveType::U64);
        f.bindings.get_mut(v(1)).unwrap().ty = IrType::Known(KnownType::I64);
        assert!(!run(f).0);
    }

    #[test]
    fn a_tag_that_is_not_constant_is_refused() {
        let mut f = entry(PrimitiveType::U64);
        f.bindings.get_mut(v(8)).unwrap().expr = Expr::Phi { incoming: vec![] };
        assert!(!run(f).0);
    }

    /// The payload store must be the path's last word on that slot.
    #[test]
    fn a_store_after_the_payload_is_refused() {
        let mut f = entry(PrimitiveType::U64);
        f.bindings.get_mut(v(16)).unwrap().expr = store(0, 1, 0, MemWidth::W8);
        assert!(!run(f).0);
    }

    /// Between the merge and the converter only the tag's store may happen.
    #[test]
    fn an_effect_before_the_call_is_refused() {
        let mut f = entry(PrimitiveType::U64);
        f.bindings.get_mut(v(19)).unwrap().expr = Expr::Call { target: FuncId::from_index(2), args: vec![v(1)] };
        assert!(!run(f).0);
    }
}
