//! The two-form unpack of a scalar whose type is already proven.
//!
//! # The shape
//!
//! A Soroban value of a 64-bit-or-wider scalar type has *two* legal
//! encodings — small, when the payload fits in the `Val`'s 56-bit body,
//! and an object handle when it does not — so the SDK's `TryFromVal`
//! tests both and unpacks whichever it finds. rustc inlines it wherever
//! such a value arrives, and the source's one line
//!
//! ```ignore
//! let ledger_timestamp = env.ledger().timestamp();
//! ```
//!
//! reaches us as a branch:
//!
//! ```text
//! v78 = get_ledger_timestamp()        : u64
//! if has_tag(v78, U64Small) {
//!     t = val_decode(v78)
//! } else {
//!     if !has_tag(v78, U64Object) { panic!() }
//!     t = obj_to_u64(v78)
//! }
//! ```
//!
//! [`super::typed_read`] folds the one-tag case (`U32Val`, `I32Val` —
//! types with a single encoding) and says why it declines this one: a
//! single check on one of two forms is not the conversion. This is the
//! other half.
//!
//! # Why it is exact
//!
//! Both arms produce the same thing: the scalar the `Val` carries. Which
//! encoding the host happened to use is not a fact about the contract,
//! and the value is of the proven type on either path — so naming the
//! subject in place of the unpack is naming what the unpack produced.
//! The branch is then two arms doing the same work, which nothing
//! downstream has to keep.
//!
//! The mismatch trap in the object arm is not this pass's to remove;
//! [`super::guard`] licenses it from the same proven type, for the same
//! reason (the SDK accessor is declared at that type and unwraps).
//!
//! # Gates
//!
//! - **The type is proven, not inferred.** `Known` on a host operation's
//!   result — what a recognizer read off the ABI — or the type
//!   `contractspecv0` declares for an element of a tuple parameter
//!   ([`super::tuple_param::element_type`]), whose conversion the
//!   regenerated wrapper runs as it does a scalar parameter's. An inferred type is
//!   our own reasoning about the code, and folding a conversion away on
//!   the strength of a guess would make the output disagree with the
//!   binary rather than with the source.
//! - **The unpack is the one that type implies.** `obj_to_u64` on a
//!   value proven `u64`. A different extractor means the value is being
//!   read as something else, and this is not the SDK's conversion.
//! - **Piece extractors are excluded.** `ObjToI128Lo64` and its
//!   siblings take *half* a value; [`super::wide_codec`] owns those, and
//!   treating one as the whole would silently truncate.
//!
//! # An entrypoint parameter
//!
//! The same unpack reaches us on a parameter: `fn test_u64(v: u64) -> u64`
//! that hands `v` straight back arrives as the branch above on the raw
//! argument, because rustc inlined the dispatch wrapper's conversion into
//! the export. The reconstruction declares `v: u64`, so `#[contractimpl]`
//! regenerates that conversion, and in the body `v` is already the number
//! — which is what each unpack computes.
//!
//! Why it is exact: the regenerated wrapper converts the argument before
//! the body runs and traps on any tag that is neither of the type's two
//! (the trap [`super::guard`] relocates there), so in the body the raw
//! argument is in one of the two forms, and both unpacks of it yield the
//! number `v` names. Each unpack is renamed only where the arm it sits in
//! has established the form it reads — the small decode where a tag test
//! on the parameter has shown the small form or ruled out the object form,
//! the extractor where one has shown the object form. A small decode of a
//! handle would be the handle's bits, and an extractor of a small value
//! would trap, so neither is renamed outside its arm.
//!
//! Gates: a function with a declared signature (an entrypoint — only it
//! gets a regenerated wrapper); the parameter declared one of the four
//! two-encoding scalars, and the extractor that type's; every place the
//! unpack is scheduled has its form established by the conditions around
//! it, read as [`super::wide_inline`] reads them; a function with a
//! goto-style fragment is skipped whole.

use std::collections::HashMap;

use sordec_common::{BlockId, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{
    Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Region, SemanticOp, ValObjectKind,
};

use super::wide_inline::{arm_conditions, form_on, Form};
use crate::dataflow::resolve_use;
use crate::type_infer::known_of_type_ref;
use crate::val_abi;
use crate::metrics_catalog::MARSHALLING_SCALAR_DECODES as M_DECODES;
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-scalar-decode";

/// Folds a proven scalar's two-form unpack into the value itself.
#[derive(Debug, Default, Clone, Copy)]
pub struct ScalarDecodePass;

impl Pass<HighIr> for ScalarDecodePass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            let declared = Declared::of(func);
            let folds: Vec<(ValueId, ValueId, KnownType, &'static str)> = func
                .bindings
                .iter()
                .filter_map(|(id, b)| unpacks(func, id, &b.expr, &declared).map(|(s, t, n)| (id, s, t, n)))
                .collect();
            for (id, subject, ty, note) in folds {
                let Some(binding) = func.bindings.get_mut(id) else {
                    continue;
                };
                binding.expr = Expr::Use(subject);
                binding.ty = IrType::Known(ty);
                binding.add_provenance(Provenance::new(PASS_NAME, ProvenanceSource::SdkPattern, note));
                result.metrics.increment(M_DECODES, 1);
                result.changed = true;
            }
        }
        result
    }
}

/// Provenance of a fold on a proven host result or tuple element.
const NOTE_PROVEN: &str = "one encoding of a value already proven to be this scalar: the value";
/// Provenance of a fold on a declared entrypoint parameter.
const NOTE_DECLARED: &str = "one encoding of a parameter contractspecv0 declares as this scalar, in the arm \
     its tag test establishes: the parameter the regenerated wrapper converts";

/// The subject and type an expression unpacks, when it unpacks one whose
/// type is already proven, with the provenance note saying how.
fn unpacks(
    func: &HighFunction,
    id: ValueId,
    expr: &Expr,
    declared: &Declared,
) -> Option<(ValueId, KnownType, &'static str)> {
    let subject = match expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { value })) => *value,
        Expr::Semantic(SemanticOp::Known(KnownOp::ValObject { kind, args })) => {
            let [value] = args.as_slice() else {
                return None;
            };
            // The extractor has to be the whole value's, and the one the
            // proven type implies.
            let whole = whole_value_extraction(*kind)?;
            let subject = resolve_use(func, *value);
            if proven(func, subject).is_some_and(|t| t == whole) {
                return Some((subject, whole, NOTE_PROVEN));
            }
            let declared_ty = declared.at(func, id, subject, Form::Object)?;
            return (declared_ty == whole).then_some((subject, whole, NOTE_DECLARED));
        }
        _ => return None,
    };
    let subject = resolve_use(func, subject);
    if let Some(ty) = proven(func, subject) {
        // A small decode is a shift, so it reads whatever the subject is; it
        // is the *proof* that the subject is a scalar that makes naming the
        // subject in its place right. Types with only one encoding are
        // `typed_read`'s.
        return two_encodings(&ty).then_some((subject, ty, NOTE_PROVEN));
    }
    let ty = declared.at(func, id, subject, Form::Small)?;
    Some((subject, ty, NOTE_DECLARED))
}

/// An entrypoint's parameters declared at a two-encoding scalar, and the
/// branch conditions around every block of its body.
#[derive(Default)]
struct Declared {
    types: HashMap<ValueId, KnownType>,
    block_of: HashMap<ValueId, BlockId>,
    arms: HashMap<BlockId, Vec<Vec<(ValueId, bool)>>>,
}

impl Declared {
    fn of(func: &HighFunction) -> Self {
        let Some(sig) = func.signature.as_ref() else {
            return Self::default();
        };
        let types: HashMap<ValueId, KnownType> = func
            .params
            .iter()
            .zip(&sig.inputs)
            .filter_map(|(p, input)| known_of_type_ref(&input.ty).map(|t| (*p, t)))
            .filter(|(_, t)| two_encodings(t))
            .collect();
        // A goto-style fragment can enter anywhere, so no position in it
        // says which branch was taken to get there.
        let mut unstructured = false;
        func.region.for_each_node(|n| unstructured |= matches!(n, Region::Unstructured { .. }));
        if types.is_empty() || unstructured {
            return Self::default();
        }
        let block_of = func
            .blocks
            .iter()
            .flat_map(|(b, block)| block.bindings.iter().map(move |v| (*v, b)))
            .collect();
        Self {
            types,
            block_of,
            arms: arm_conditions(&func.region),
        }
    }

    /// The type `subject` is declared at, when it is such a parameter and
    /// every place `read` is scheduled has established the `form` it reads.
    fn at(&self, func: &HighFunction, read: ValueId, subject: ValueId, form: Form) -> Option<KnownType> {
        let ty = self.types.get(&subject)?;
        let tags = scalar_tags(ty)?;
        let occurrences = self.arms.get(self.block_of.get(&read)?)?;
        let established = !occurrences.is_empty()
            && occurrences.iter().all(|conds| form_on(func, conds, subject, tags) == Some(form));
        established.then(|| ty.clone())
    }
}

/// The small and object tags of a two-encoding scalar.
fn scalar_tags(ty: &KnownType) -> Option<(u8, u8)> {
    Some(match ty {
        KnownType::U64 => (val_abi::TAG_U64_SMALL, val_abi::TAG_U64_OBJECT),
        KnownType::I64 => (val_abi::TAG_I64_SMALL, val_abi::TAG_I64_OBJECT),
        KnownType::Timepoint => (val_abi::TAG_TIMEPOINT_SMALL, val_abi::TAG_TIMEPOINT_OBJECT),
        KnownType::Duration => (val_abi::TAG_DURATION_SMALL, val_abi::TAG_DURATION_OBJECT),
        _ => return None,
    })
}

/// The type an object extractor pulls out whole, or `None` for the piece
/// extractors — half of a 128-bit value is not the value.
fn whole_value_extraction(kind: ValObjectKind) -> Option<KnownType> {
    Some(match kind {
        ValObjectKind::ObjToU64 => KnownType::U64,
        ValObjectKind::ObjToI64 => KnownType::I64,
        ValObjectKind::TimepointObjToU64 => KnownType::Timepoint,
        ValObjectKind::DurationObjToU64 => KnownType::Duration,
        _ => return None,
    })
}

/// Whether this type has both a small and an object encoding, so a
/// single tag check is not its conversion.
fn two_encodings(ty: &KnownType) -> bool {
    matches!(
        ty,
        KnownType::U64 | KnownType::I64 | KnownType::Timepoint | KnownType::Duration
    )
}

/// The type a recognizer proved for a host operation's result, or the
/// spec declares for an element of a tuple parameter.
///
/// Deliberately the same rule [`super::guard`] uses to licence the trap
/// beside this unpack: `Known`, and on a host operation — or the element,
/// whose conversion the regenerated wrapper runs as it does a scalar
/// parameter's. The two have to agree, or one would fold a conversion
/// whose trap the other keeps.
fn proven(func: &HighFunction, value: ValueId) -> Option<KnownType> {
    if let Some(element) = super::tuple_param::element_type(func, value) {
        return Some(element);
    }
    let binding = func.bindings.get(value)?;
    if !matches!(binding.expr, Expr::Semantic(SemanticOp::Known(_))) {
        return None;
    }
    match &binding.ty {
        IrType::Known(t) => Some(t.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};
    use sordec_ir::Binding;

    /// A host result typed `u64`, unpacked both ways.
    fn shape(proven_ty: Option<KnownType>, kind: ValObjectKind) -> HighIr {
        let mut f = func_with(
            vec![
                Expr::Semantic(SemanticOp::Known(KnownOp::GetLedgerTimestamp)), // v0
                Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { value: v(0) })), // v1
                Expr::Semantic(SemanticOp::Known(KnownOp::ValObject {
                    kind,
                    args: vec![v(0)],
                })), // v2
            ],
            vec![],
            vec![0, 1, 2],
        );
        if let Some(t) = proven_ty {
            f.bindings.get_mut(v(0)).expect("subject").ty = IrType::Known(t);
        }
        module(vec![f])
    }

    fn folded(m: &HighIr, id: ValueId) -> bool {
        matches!(
            m.functions[0].bindings.get(id).map(|b: &Binding| &b.expr),
            Some(Expr::Use(_))
        )
    }

    #[test]
    fn both_encodings_of_a_proven_scalar_are_the_value() {
        let mut m = shape(Some(KnownType::U64), ValObjectKind::ObjToU64);
        assert!(ScalarDecodePass.run(&mut m).changed);
        assert!(folded(&m, v(1)), "the small decode");
        assert!(folded(&m, v(2)), "the object unpack");
    }

    /// Nothing proved the type, so nothing licenses the fold.
    #[test]
    fn an_unproven_subject_keeps_its_unpack() {
        let mut m = shape(None, ValObjectKind::ObjToU64);
        assert!(!ScalarDecodePass.run(&mut m).changed);
    }

    /// Half of a 128-bit value is not the value.
    #[test]
    fn a_piece_extractor_is_left_alone() {
        let mut m = shape(Some(KnownType::I128), ValObjectKind::ObjToI128Lo64);
        ScalarDecodePass.run(&mut m);
        assert!(!folded(&m, v(2)));
    }

    /// Element `index` of a parameter declared `(u32, i64)`, unpacked
    /// both ways as an `i64`.
    fn element_shape(index: u32) -> HighIr {
        use sordec_ir::{CompositeType, FunctionParam, FunctionSignature, PrimitiveType, TypeRef};
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },       // v0 — the tuple
                Expr::Project { value: v(0), index }, // v1 — its element
                Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { value: v(1) })), // v2
                Expr::Semantic(SemanticOp::Known(KnownOp::ValObject {
                    kind: ValObjectKind::ObjToI64,
                    args: vec![v(1)],
                })), // v3
            ],
            vec![v(0)],
            vec![1, 2, 3],
        );
        f.signature = Some(FunctionSignature {
            name: "tuple2".to_string(),
            inputs: vec![FunctionParam {
                name: "arg".to_string(),
                ty: TypeRef::Composite(CompositeType::Tuple(vec![
                    TypeRef::Primitive(PrimitiveType::U32),
                    TypeRef::Primitive(PrimitiveType::I64),
                ])),
            }],
            outputs: vec![],
        });
        module(vec![f])
    }

    #[test]
    fn both_encodings_of_a_declared_tuple_element_are_the_element() {
        let mut m = element_shape(1);
        assert!(ScalarDecodePass.run(&mut m).changed);
        assert!(folded(&m, v(2)), "the small decode");
        assert!(folded(&m, v(3)), "the object unpack");
    }

    /// Element 0 is declared `u32`: `obj_to_i64` is not its conversion,
    /// and a `u32` has one encoding, so the small decode is not this
    /// pass's either.
    #[test]
    fn an_element_of_another_type_keeps_its_unpack() {
        let mut m = element_shape(0);
        assert!(!ScalarDecodePass.run(&mut m).changed);
    }

    /// An entrypoint `f(p: u64)` whose body is the inlined conversion:
    /// `if has_tag(p, U64Object) { obj_to_u64(p) } else { val_decode(p) }`.
    /// With `split` false, both unpacks sit in one block after the test
    /// instead, where no arm has established a form.
    fn declared_shape(split: bool) -> HighIr {
        use sordec_common::{BlockId, IrId};
        use sordec_ir::{FunctionParam, FunctionSignature, HighBlock, PrimitiveType, TypeRef};
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] }, // v0 — the parameter
                Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck {
                    value: v(0),
                    tag: val_abi::TAG_U64_OBJECT,
                    negated: false,
                })), // v1
                Expr::Semantic(SemanticOp::Known(KnownOp::ValObject {
                    kind: ValObjectKind::ObjToU64,
                    args: vec![v(0)],
                })), // v2
                Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { value: v(0) })), // v3
            ],
            vec![v(0)],
            vec![1],
        );
        let b = BlockId::from_index;
        if split {
            f.blocks.push(HighBlock { id: b(1), bindings: vec![v(2)] });
            f.blocks.push(HighBlock { id: b(2), bindings: vec![v(3)] });
            f.region = Region::Sequence(vec![
                Region::Basic(b(0)),
                Region::If {
                    cond: v(1),
                    then_region: Box::new(Region::Basic(b(1))),
                    else_region: Some(Box::new(Region::Basic(b(2)))),
                },
            ]);
        } else {
            f.blocks.push(HighBlock { id: b(1), bindings: vec![v(2), v(3)] });
            f.region = Region::Sequence(vec![Region::Basic(b(0)), Region::Basic(b(1))]);
        }
        f.signature = Some(FunctionSignature {
            name: "f".to_string(),
            inputs: vec![FunctionParam {
                name: "p".to_string(),
                ty: TypeRef::Primitive(PrimitiveType::U64),
            }],
            outputs: vec![],
        });
        module(vec![f])
    }

    #[test]
    fn each_arm_of_a_declared_parameters_conversion_is_the_parameter() {
        let mut m = declared_shape(true);
        assert!(ScalarDecodePass.run(&mut m).changed);
        assert!(folded(&m, v(2)), "the object unpack, in the object arm");
        assert!(folded(&m, v(3)), "the small decode, in the other arm");
        assert!(matches!(m.functions[0].bindings.get(v(3)).map(|b| &b.ty), Some(IrType::Known(KnownType::U64))));
    }

    /// Outside the arms nothing says which form the word is in: a small
    /// decode of a handle is the handle's bits, not the number.
    #[test]
    fn an_unpack_outside_its_arm_is_left_alone() {
        let mut m = declared_shape(false);
        assert!(!ScalarDecodePass.run(&mut m).changed);
    }

    /// A helper has no regenerated wrapper, so its parameter carries no
    /// declared type to name.
    #[test]
    fn a_parameter_without_a_declaration_keeps_its_unpacks() {
        let mut m = declared_shape(true);
        m.functions[0].signature = None;
        assert!(!ScalarDecodePass.run(&mut m).changed);
    }

    #[test]
    fn the_pass_is_idempotent() {
        let mut m = shape(Some(KnownType::U64), ValObjectKind::ObjToU64);
        assert!(ScalarDecodePass.run(&mut m).changed);
        assert!(!ScalarDecodePass.run(&mut m).changed);
    }
}
