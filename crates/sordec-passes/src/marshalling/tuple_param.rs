//! A tuple argument unpacked into the frame: each slot is the element.
//!
//! # The shape
//!
//! `pub fn tuple2(arg: (u32, i64)) -> (u32, i64) { arg }`. A Soroban
//! tuple travels as a vec of its encoded elements, and the SDK's
//! conversion of the argument — inlined into the export — unpacks that
//! vec into a frame array and converts each element out of its slot:
//!
//! ```text
//! if !has_tag(arg, VecObject) { panic!() }
//! store fp+0 <- Void; store fp+8 <- Void              ← `[Val::VOID; 2]`
//! vec_unpack_to_linear_memory(arg, U32Val(fp), U32Val(2))
//! a = load fp+0; if !has_tag(a, U32Val) { panic!() }  ← element 0
//! b = load fp+8; the `i64`'s two-form decode of b     ← element 1
//! ```
//!
//! Left alone, the unpack is a host call the reconstruction cannot spell
//! and every slot read is a load of memory nothing visibly wrote, so the
//! element checks and decodes after them have no type to fold against.
//!
//! # The rewrite
//!
//! The unpack becomes the stores it performs: `store fp+8k <- arg.k` for
//! each element `k`, the element an [`Expr::Project`] of the parameter
//! typed as `contractspecv0` declares it. Nothing else is decided here.
//! The frame forwarder ([`super::forward`]) carries each store to the
//! loads it reaches, and the element's own checks and decode are then the
//! shapes [`super::guard`] and [`super::scalar_decode`] already own; they
//! accept an element of a declared tuple parameter ([`element_type`]) on
//! the same licence as the parameter itself. Once nothing reads the slots,
//! the frame collection takes the stores.
//!
//! # Why it is exact
//!
//! `vec_unpack_to_linear_memory(v, pos, n)` writes the `n` elements of
//! the vec `v`, each as its `Val`, to `pos`, `pos + 8`, …, and traps
//! unless `v` is a vec of exactly `n` elements. The spec declares the
//! parameter a tuple of `n` elements, and a tuple's wire form is the vec
//! of its elements' encodings in order, so the word written at
//! `pos + 8k` is the encoding of `arg.k` — which is what the planted store
//! writes, under the convention every declared parameter already follows:
//! a value typed as its spec type stands for the `Val` it arrives as, and
//! its decode collapses to it. Each store is the same width (8 bytes) at
//! the same address the unpack wrote, so memory afterwards holds exactly
//! what it held before, and a load the forwarder cannot prove reached
//! still reads it there.
//!
//! The unpack's trap is not removed but moved, by [`super::guard`]'s
//! argument one level down: the reconstruction declares `arg: (T0, ..)`
//! inside `#[contractimpl]`, so the regenerated dispatch wrapper runs the
//! tuple's `TryFromVal` — the `VecObject` check, this unpack and each
//! element's conversion — before the body runs.
//!
//! Which load reads which slot is not this pass's question. Whether a
//! store reaches a load — the store dominates it, nothing on any path
//! between may write the slot, the load reads exactly the slot's eight
//! bytes — is [`crate::dataflow::frame_facts`]'s, answered under the same
//! kill discipline as every other forwarded slot.
//!
//! # An element's tag byte
//!
//! An element the body never uses keeps only its conversion's check, and
//! for a type carried by one tag that check reads one byte:
//! `if load8(fp+8k) != 4 { trap }` for a `u32`. The frame forwarder takes
//! only whole-slot reads, so the byte is matched here: where the planted
//! store of `arg.k` reaches the read (on every path, nothing between may
//! write the slot — [`crate::dataflow::facts_at`]), the byte is the low
//! byte of `arg.k`'s encoding, its tag. When every use of it is
//! `byte != tag` with `tag` the one tag the element's declared type is
//! carried by, and every use of that comparison is a guard
//! `if c { trap }` with no else arm, the test is the element conversion's
//! check, which the regenerated wrapper makes: the guard is relocated as
//! the element's own tag guard is, and the read goes with it.
//!
//! # Gates
//!
//! - **An entrypoint parameter declared a tuple.** Only an entrypoint has
//!   a regenerated wrapper for the conversion to move into, and only the
//!   declaration says the vec is a tuple and what its elements are. Every
//!   element must have a type the spec names; the empty tuple travels as
//!   `Void`, not a vec, and is never unpacked.
//! - **The length is the arity.** The length operand is a `U32Val` whose
//!   payload is a constant equal to the tuple's arity — read through its
//!   decode, never as the raw word. A different count is a different
//!   conversion.
//! - **The position is an encoded address.** The position operand is the
//!   `U32Val` encode of a pointer, so the stores can be addressed through
//!   the pointer itself.
//! - **The unpack runs.** It is scheduled in a block; residue a rewrite
//!   left behind is not touched.

use sordec_common::{IrId, Provenance, ProvenanceSource, UnknownReason, ValueId};
use sordec_ir::{
    Binding, Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Literal, MemWidth, SemanticOp, VecOpKind,
};

use super::udt_decode::raw_address;
use crate::dataflow::{resolve_use, trace_u32val};
use crate::metrics_catalog::MARSHALLING_TUPLE_PARAMS_UNPACKED as M_UNPACKED;
use crate::pass::{Pass, PassResult};
use crate::type_infer::known_of_type_ref;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-tuple-param";

/// Bytes per `Val` slot in the unpacked array.
const SLOT: u32 = 8;

/// Rewrites a declared tuple parameter's unpack as the element stores it
/// performs.
#[derive(Debug, Default, Clone, Copy)]
pub struct TupleParamPass;

impl Pass<HighIr> for TupleParamPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            for unpack in plan(func) {
                if apply(func, &unpack) {
                    result.metrics.increment(M_UNPACKED, 1);
                    result.changed = true;
                }
            }
            if relocate_tag_bytes(func) {
                result.changed = true;
            }
        }
        result
    }
}

/// The element tag-byte checks ("An element's tag byte"), relocated:
/// their guards stripped and their reads made nothing. Whether anything
/// changed.
fn relocate_tag_bytes(func: &mut HighFunction) -> bool {
    if func.signature.is_none() {
        return false;
    }
    let uses = crate::dataflow::HighUseIndex::build(func);
    let traps = super::udt_decode::trap_guards(func);
    let mut guards: std::collections::HashMap<ValueId, String> = std::collections::HashMap::new();
    let mut reads: Vec<(ValueId, String)> = Vec::new();
    for (_, block) in func.blocks.iter() {
        for &id in &block.bindings {
            let Some(Expr::Load { addr, offset, width: MemWidth::W1, .. }) = func.bindings.get(id).map(|b| &b.expr)
            else {
                continue;
            };
            let (base, at) = crate::dataflow::canon_addr(func, *addr);
            let Some(at) = at.checked_add(*offset) else { continue };
            let Some(stored) = crate::dataflow::facts_at(func, id, base).value_at(at, MemWidth::W8) else {
                continue;
            };
            let Some(ty) = element_type(func, stored) else { continue };
            let Some(tag) = super::udt_decode::sole_tag(&ty) else { continue };
            let Some(conds) = super::udt_decode::derived_tag_check(func, &uses, &traps, id, tag) else {
                continue;
            };
            let what = crate::val_abi::tag_name(tag).unwrap_or("its tag");
            for cond in conds {
                guards.insert(
                    cond,
                    format!(
                        "a tuple parameter's element is checked to be a {what}: `#[contractimpl]` regenerates \
                         the conversion in the dispatch wrapper"
                    ),
                );
            }
            reads.push((id, format!("the tag byte of a tuple parameter's element, read only by its {what} check")));
        }
    }
    if reads.is_empty() {
        return false;
    }
    let empty = super::guard::empty_blocks(func);
    let region = std::mem::replace(&mut func.region, sordec_ir::Region::Unreachable);
    let mut stripped = 0_i64;
    func.region = super::guard::strip(region, &guards, &empty, &mut stripped);
    for (id, note) in reads {
        if let Some(b) = func.bindings.get_mut(id) {
            b.expr = Expr::Literal(Literal::Unit);
            b.ty = IrType::Known(KnownType::Unit);
            b.add_provenance(Provenance::new(PASS_NAME, ProvenanceSource::SdkPattern, note));
        }
    }
    true
}

/// The type `contractspecv0` declares for element `k` of a tuple
/// parameter, when `value` is that element: `arg.k`, with `arg` one of
/// this entrypoint's parameters declared a tuple.
///
/// The licence the element passes on is the parameter's own: the
/// regenerated wrapper converts the tuple, and converting a tuple converts
/// each element by its declared type — so an element's tag check and
/// decode are regenerated exactly as a scalar parameter's are.
pub(crate) fn element_type(func: &HighFunction, value: ValueId) -> Option<KnownType> {
    let Expr::Project { value: whole, index } = &func.bindings.get(resolve_use(func, value))?.expr else {
        return None;
    };
    let KnownType::Tuple(slots) = declared_param_type(func, resolve_use(func, *whole))? else {
        return None;
    };
    match slots.get(*index as usize)? {
        IrType::Known(k) => Some(k.clone()),
        _ => None,
    }
}

/// One unpack to rewrite.
struct Unpack {
    /// The unpack binding.
    id: ValueId,
    /// The tuple parameter.
    param: ValueId,
    /// The array's address, before its `U32Val` encode.
    addr: ValueId,
    /// Each element's declared type, in order.
    elements: Vec<KnownType>,
}

fn plan(func: &HighFunction) -> Vec<Unpack> {
    if func.signature.is_none() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (_, block) in func.blocks.iter() {
        for &id in &block.bindings {
            let Some(Expr::Semantic(SemanticOp::Known(KnownOp::VecOp {
                kind: VecOpKind::UnpackToLinearMemory,
                args,
            }))) = func.bindings.get(id).map(|b| &b.expr)
            else {
                continue;
            };
            let [vec, pos, len] = args.as_slice() else {
                continue;
            };
            let param = resolve_use(func, *vec);
            let Some(KnownType::Tuple(slots)) = declared_param_type(func, param) else {
                continue;
            };
            let Some(elements) = slots
                .iter()
                .map(|s| match s {
                    IrType::Known(k) => Some(k.clone()),
                    _ => None,
                })
                .collect::<Option<Vec<_>>>()
            else {
                continue;
            };
            if elements.is_empty() || encoded_u32(func, *len) != u32::try_from(elements.len()).ok() {
                continue;
            }
            let Some(addr) = encoded_address(func, *pos) else {
                continue;
            };
            out.push(Unpack { id, param, addr, elements });
        }
    }
    out
}

/// Plant `arg.k` and its store for each element just before the unpack,
/// which becomes nothing. `false` when the unpack is not where the plan
/// found it.
fn apply(func: &mut HighFunction, unpack: &Unpack) -> bool {
    let Some(block_id) = crate::dataflow::block_containing(func, unpack.id) else {
        return false;
    };
    let mut planted = Vec::with_capacity(unpack.elements.len() * 2);
    for (k, ty) in unpack.elements.iter().enumerate() {
        let Ok(index) = u32::try_from(k) else {
            return false;
        };
        let element = ValueId::from_index(func.bindings.len() as u32);
        func.bindings.push(Binding::new(
            element,
            IrType::Known(ty.clone()),
            Expr::Project { value: unpack.param, index },
            Provenance::new(
                PASS_NAME,
                ProvenanceSource::SdkPattern,
                format!("element {k} of a tuple parameter contractspecv0 declares, as its unpack writes it"),
            ),
        ));
        let store = ValueId::from_index(func.bindings.len() as u32);
        func.bindings.push(Binding::new(
            store,
            IrType::Unknown(UnknownReason::InsufficientEvidence),
            Expr::Store { addr: unpack.addr, value: element, offset: SLOT * index, width: MemWidth::W8 },
            Provenance::new(
                PASS_NAME,
                ProvenanceSource::SdkPattern,
                format!("slot {k} of the tuple parameter's unpack: the element's encoding"),
            ),
        ));
        planted.push(element);
        planted.push(store);
    }
    let Some(block) = func.blocks.get_mut(block_id) else {
        return false;
    };
    let Some(at) = block.bindings.iter().position(|b| *b == unpack.id) else {
        return false;
    };
    block.bindings.splice(at..at, planted);
    if let Some(b) = func.bindings.get_mut(unpack.id) {
        b.expr = Expr::Literal(Literal::Unit);
        b.ty = IrType::Known(KnownType::Unit);
        b.add_provenance(Provenance::new(
            PASS_NAME,
            ProvenanceSource::SdkPattern,
            "a declared tuple parameter's unpack, replaced by the element stores it performs: \
             `#[contractimpl]` regenerates the conversion in the dispatch wrapper",
        ));
    }
    true
}

/// The `U32Val` payload `value` encodes, when it is an encode of a
/// constant or a constant word of that tag — never a bare integer, which
/// is not what the host call is handed.
fn encoded_u32(func: &HighFunction, value: ValueId) -> Option<u32> {
    match &func.bindings.get(resolve_use(func, value))?.expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty: KnownType::U32, .. }))
        | Expr::Literal(Literal::I64(_) | Literal::U64(_)) => trace_u32val(func, value),
        _ => None,
    }
}

/// The pointer behind a `U32Val`-encoded position.
fn encoded_address(func: &HighFunction, value: ValueId) -> Option<ValueId> {
    match &func.bindings.get(resolve_use(func, value))?.expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty: KnownType::U32, .. })) => {
            Some(raw_address(func, value))
        }
        _ => None,
    }
}

/// The `contractspecv0` type of `value`, when it is one of this
/// entrypoint's parameters.
fn declared_param_type(func: &HighFunction, value: ValueId) -> Option<KnownType> {
    let sig = func.signature.as_ref()?;
    let index = func.params.iter().position(|p| *p == value)?;
    known_of_type_ref(&sig.inputs.get(index)?.ty)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, load, module, v};
    use crate::marshalling::forward::FrameForwardPass;
    use sordec_ir::{CompositeType, FunctionParam, FunctionSignature, PrimitiveType, TypeRef};

    fn tuple_sig(elements: Vec<PrimitiveType>) -> FunctionSignature {
        FunctionSignature {
            name: "tuple2".to_string(),
            inputs: vec![FunctionParam {
                name: "arg".to_string(),
                ty: TypeRef::Composite(CompositeType::Tuple(
                    elements.into_iter().map(TypeRef::Primitive).collect(),
                )),
            }],
            outputs: vec![],
        }
    }

    /// `arg` (v0), the frame pointer (v1), the array's encoded address and
    /// length, the unpack, then a load of each slot:
    ///
    /// ```text
    /// v0  arg                       (param)
    /// v1  fp                        (param)
    /// v2  val_encode<u32>(v1)
    /// v3  2 (the arity)
    /// v4  val_encode<u32>(v3)
    /// v5  vec_unpack_to_linear_memory(v0, v2, v4)
    /// v6  load fp+0
    /// v7  load fp+8
    /// ```
    fn unpacked(len: Expr, elements: Vec<PrimitiveType>) -> HighIr {
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },
                Expr::Phi { incoming: vec![] },
                Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty: KnownType::U32, value: v(1) })),
                len,
                Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty: KnownType::U32, value: v(3) })),
                Expr::Semantic(SemanticOp::Known(KnownOp::VecOp {
                    kind: VecOpKind::UnpackToLinearMemory,
                    args: vec![v(0), v(2), v(4)],
                })),
                load(v(1), 0),
                load(v(1), 8),
            ],
            vec![v(0), v(1)],
            vec![2, 3, 4, 5, 6, 7],
        );
        f.signature = Some(tuple_sig(elements));
        module(vec![f])
    }

    fn expr(ir: &HighIr, id: ValueId) -> &Expr {
        &ir.functions[0].bindings.get(id).expect("binding").expr
    }

    #[test]
    fn each_slot_read_after_the_unpack_is_the_element() {
        let mut ir = unpacked(Expr::Literal(Literal::I32(2)), vec![PrimitiveType::U32, PrimitiveType::I64]);
        assert!(TupleParamPass.run(&mut ir).changed);
        assert!(matches!(expr(&ir, v(5)), Expr::Literal(Literal::Unit)), "the unpack is gone");
        assert!(FrameForwardPass.run(&mut ir).changed);
        let func = &ir.functions[0];
        for (load, k, ty) in [(v(6), 0, KnownType::U32), (v(7), 1, KnownType::I64)] {
            let Expr::Use(element) = expr(&ir, load) else {
                panic!("slot {k} forwarded, got {:?}", expr(&ir, load));
            };
            assert!(matches!(expr(&ir, *element), Expr::Project { value, index } if *value == v(0) && *index == k));
            assert_eq!(func.bindings.get(*element).unwrap().ty, IrType::Known(ty.clone()));
            assert_eq!(element_type(func, load), Some(ty));
        }
    }

    /// `unpacked` with element 0 (`u32`) read only for its tag byte, under
    /// `if byte != tag { trap }`.
    fn tag_checked(tag: i64) -> HighIr {
        let mut ir = unpacked(Expr::Literal(Literal::I32(2)), vec![PrimitiveType::U32, PrimitiveType::I64]);
        let func = &mut ir.functions[0];
        func.bindings.get_mut(v(6)).unwrap().expr = Expr::Load {
            addr: v(1),
            offset: 0,
            width: MemWidth::W1,
            signed: Some(false),
            ty: IrType::Unknown(UnknownReason::InsufficientEvidence),
        };
        let mut push = |e: Expr| {
            let id = ValueId::from_index(func.bindings.len() as u32);
            func.bindings.push(Binding::new(
                id,
                IrType::Unknown(UnknownReason::InsufficientEvidence),
                e,
                Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
            ));
            id
        };
        let c = push(Expr::Literal(Literal::I64(tag)));
        let ne = push(Expr::Binary { op: sordec_ir::BinaryOp::Ne, lhs: v(6), rhs: c });
        let block = func.blocks.iter_mut().next().unwrap();
        block.1.bindings.extend([c, ne]);
        let b0 = block.0;
        func.region = sordec_ir::Region::Sequence(vec![
            sordec_ir::Region::Basic(b0),
            sordec_ir::Region::If {
                cond: ne,
                then_region: Box::new(sordec_ir::Region::Unreachable),
                else_region: None,
            },
        ]);
        ir
    }

    fn has_guard(ir: &HighIr) -> bool {
        let mut found = false;
        ir.functions[0].region.for_each_node(|r| found |= matches!(r, sordec_ir::Region::If { .. }));
        found
    }

    /// Element 0 is a `u32`, carried only by a `U32Val` (4): the byte test
    /// is its conversion's check, relocated with the guard.
    #[test]
    fn an_elements_tag_byte_check_is_relocated() {
        let mut ir = tag_checked(4);
        assert!(TupleParamPass.run(&mut ir).changed);
        assert!(matches!(expr(&ir, v(6)), Expr::Literal(Literal::Unit)));
        assert!(!has_guard(&ir));
    }

    /// A test against a tag the element's type is not carried by is not
    /// its conversion's check.
    #[test]
    fn a_tag_byte_test_against_another_tag_stays() {
        let mut ir = tag_checked(5);
        TupleParamPass.run(&mut ir);
        assert!(matches!(expr(&ir, v(6)), Expr::Load { .. }));
        assert!(has_guard(&ir));
    }

    #[test]
    fn a_length_word_reads_through_its_decode() {
        // `U32Val(2)` as the raw word the constant propagation leaves.
        let word = (2_i64 << 32) | 4;
        let mut ir = unpacked(Expr::Literal(Literal::I64(word)), vec![PrimitiveType::U32, PrimitiveType::I64]);
        // The literal stands in for the encode: hand it to the unpack directly.
        if let Some(Expr::Semantic(SemanticOp::Known(KnownOp::VecOp { args, .. }))) =
            ir.functions[0].bindings.get_mut(v(5)).map(|b| &mut b.expr)
        {
            args[2] = v(3);
        }
        assert!(TupleParamPass.run(&mut ir).changed);
    }

    #[test]
    fn a_length_other_than_the_arity_is_left_alone() {
        let mut ir = unpacked(Expr::Literal(Literal::I32(3)), vec![PrimitiveType::U32, PrimitiveType::I64]);
        assert!(!TupleParamPass.run(&mut ir).changed);
        assert!(matches!(expr(&ir, v(5)), Expr::Semantic(_)));
    }

    #[test]
    fn a_parameter_not_declared_a_tuple_is_left_alone() {
        let mut ir = unpacked(Expr::Literal(Literal::I32(2)), vec![PrimitiveType::U32, PrimitiveType::I64]);
        ir.functions[0].signature.as_mut().unwrap().inputs[0].ty = TypeRef::Composite(CompositeType::Vec(
            Box::new(TypeRef::Primitive(PrimitiveType::U32)),
        ));
        assert!(!TupleParamPass.run(&mut ir).changed);
    }

    #[test]
    fn a_helper_without_a_signature_is_left_alone() {
        let mut ir = unpacked(Expr::Literal(Literal::I32(2)), vec![PrimitiveType::U32, PrimitiveType::I64]);
        ir.functions[0].signature = None;
        assert!(!TupleParamPass.run(&mut ir).changed);
    }

    #[test]
    fn a_slot_written_after_the_unpack_reads_the_later_write() {
        let mut ir = unpacked(Expr::Literal(Literal::I32(2)), vec![PrimitiveType::U32, PrimitiveType::I64]);
        // A store of something else to slot 1 between the unpack and its load.
        let func = &mut ir.functions[0];
        let other = ValueId::from_index(func.bindings.len() as u32);
        func.bindings.push(Binding::new(
            other,
            IrType::Unknown(UnknownReason::InsufficientEvidence),
            Expr::Literal(Literal::I64(7)),
            Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
        ));
        let store = ValueId::from_index(func.bindings.len() as u32);
        func.bindings.push(Binding::new(
            store,
            IrType::Unknown(UnknownReason::InsufficientEvidence),
            crate::marshalling::test_support::store(v(1), other, 8),
            Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
        ));
        let block = func.blocks.iter_mut().next().unwrap().1;
        let at = block.bindings.iter().position(|b| *b == v(7)).unwrap();
        block.bindings.splice(at..at, [other, store]);
        assert!(TupleParamPass.run(&mut ir).changed);
        FrameForwardPass.run(&mut ir);
        assert!(matches!(expr(&ir, v(7)), Expr::Use(x) if *x == other), "{:?}", expr(&ir, v(7)));
        assert!(element_type(&ir.functions[0], v(7)).is_none());
    }

    #[test]
    fn the_pass_is_idempotent() {
        let mut ir = unpacked(Expr::Literal(Literal::I32(2)), vec![PrimitiveType::U32, PrimitiveType::I64]);
        assert!(TupleParamPass.run(&mut ir).changed);
        assert!(!TupleParamPass.run(&mut ir).changed);
    }
}
