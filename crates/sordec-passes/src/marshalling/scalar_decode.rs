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
//!   result — what a recognizer read off the ABI. An inferred type is
//!   our own reasoning about the code, and folding a conversion away on
//!   the strength of a guess would make the output disagree with the
//!   binary rather than with the source.
//! - **The unpack is the one that type implies.** `obj_to_u64` on a
//!   value proven `u64`. A different extractor means the value is being
//!   read as something else, and this is not the SDK's conversion.
//! - **Piece extractors are excluded.** `ObjToI128Lo64` and its
//!   siblings take *half* a value; [`super::wide_codec`] owns those, and
//!   treating one as the whole would silently truncate.

use sordec_common::{Provenance, ProvenanceSource, ValueId};
use sordec_ir::{
    Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, SemanticOp, ValObjectKind,
};

use crate::dataflow::resolve_use;
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
            let folds: Vec<(ValueId, ValueId, KnownType)> = func
                .bindings
                .iter()
                .filter_map(|(id, b)| unpacks(func, &b.expr).map(|(s, t)| (id, s, t)))
                .collect();
            for (id, subject, ty) in folds {
                let Some(binding) = func.bindings.get_mut(id) else {
                    continue;
                };
                binding.expr = Expr::Use(subject);
                binding.ty = IrType::Known(ty);
                binding.add_provenance(Provenance::new(
                    PASS_NAME,
                    ProvenanceSource::SdkPattern,
                    "one encoding of a value already proven to be this scalar: the value",
                ));
                result.metrics.increment(M_DECODES, 1);
                result.changed = true;
            }
        }
        result
    }
}

/// The subject and type an expression unpacks, when it unpacks one whose
/// type is already proven.
fn unpacks(func: &HighFunction, expr: &Expr) -> Option<(ValueId, KnownType)> {
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
            return (proven(func, subject)? == whole).then_some((subject, whole));
        }
        _ => return None,
    };
    let subject = resolve_use(func, subject);
    let ty = proven(func, subject)?;
    // A small decode is a shift, so it reads whatever the subject is; it
    // is the *proof* that the subject is a scalar that makes naming the
    // subject in its place right. Types with only one encoding are
    // `typed_read`'s.
    two_encodings(&ty).then_some((subject, ty))
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

/// The type a recognizer proved for a host operation's result.
///
/// Deliberately the same rule [`super::guard`] uses to licence the trap
/// beside this unpack: `Known`, and on a host operation. The two have to
/// agree, or one would fold a conversion whose trap the other keeps.
fn proven(func: &HighFunction, value: ValueId) -> Option<KnownType> {
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

    #[test]
    fn the_pass_is_idempotent() {
        let mut m = shape(Some(KnownType::U64), ValObjectKind::ObjToU64);
        assert!(ScalarDecodePass.run(&mut m).changed);
        assert!(!ScalarDecodePass.run(&mut m).changed);
    }
}
