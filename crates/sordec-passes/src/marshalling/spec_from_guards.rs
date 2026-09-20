//! Read an entrypoint's declared types off the checks its wrapper makes.
//!
//! When a build strips `contractspecv0`, the export table still names
//! every entrypoint and gives its arity ([`crate::lowering`] recovers
//! that), but every parameter is left as the ABI's bare `Val`. The types
//! are not gone, though — they are in the body, because
//! `#[contractimpl]` compiles the declaration into code:
//!
//! ```text
//! pub fn transfer(e: Env, from: Address, …)
//!
//! ;; and in the wasm, on entry:
//! if !has_tag(arg0, AddressObject) { panic!() }
//! ```
//!
//! That check exists *because* the parameter was declared `Address`, so
//! reading it back recovers the declaration rather than guessing at one.
//! A wider type is decoded by a helper instead of inline, and the same
//! reading applies: [`super::decode`] already classifies those helpers
//! and records the tags each one tests, so the argument a call site
//! hands one is declared whatever those tags denote.
//!
//! A **struct field** is read the same way, once [`super::udt_decode`]
//! has recovered the struct from its key table. The table gives the
//! field names and nothing else, so each field starts as a `Val`; the
//! derived conversion then checks it against the tag its declared type
//! implies, exactly as `#[contractimpl]` does for a parameter. Reading
//! that back is what lets [`super::field_type`] and [`super::guard`]
//! retire the check.
//! The return type is recoverable the same way. A wasm entrypoint always
//! hands the host one `Val`: one that is always the constant `Void` is a
//! function the source wrote as returning nothing, and one that is
//! always a value of a recovered type, or that type packed into a `Val`,
//! is a function returning that type.
//!
//! # What this unlocks
//!
//! The declaration is what the marshalling gates read. Until a parameter
//! has one, [`super::guard`] cannot licence the very check that revealed
//! it — a `Val` admits no tag — so a stripped contract kept every
//! argument conversion as though the author had written it. With the
//! type recovered the same relocation argument applies as anywhere else:
//! the reconstruction declares `arg0: Address`, and `#[contractimpl]`
//! regenerates the check in the dispatch wrapper.
//!
//! # Gates
//!
//! - **No spec section at all.** A module that has one and declares a
//!   parameter `Val` is telling us it is a `Val`; the body cannot
//!   overrule the ABI. This runs only where there is no ABI to overrule.
//! - **The mismatch traps.** `#[contractimpl]`'s conversion panics when
//!   the tag is wrong, and rustc writes that either way round: `if
//!   !has_tag { panic }`, or `if has_tag { work } else { panic }`, or
//!   `if has_tag { work; return } panic!()`. All three are the
//!   conversion. A tag check whose both sides carry real code is a
//!   contract inspecting a `Val` it was handed, and says nothing about
//!   how that value was declared.
//! - **Every check agrees.** A parameter has one declared type. Two tags
//!   denoting different types means this is not the wrapper's conversion,
//!   and nothing is recovered — a `u64` tested against both its small and
//!   its object form agrees, because both denote `u64`.
//! - **Only a parameter still declared `Val`.** Anything else already has
//!   a declaration, from the spec or from an earlier run of this pass.

use std::collections::HashMap;

use std::collections::BTreeMap;

use sordec_common::{FuncId, TypeId, ValueId};
use sordec_ir::{
    Expr, FunctionSignature, HighFunction, HighIr, IrType, KnownOp, KnownType, PrimitiveType,
    Region, SemanticOp, TypeRef,
};

use super::decode::{self, DecodeHelper};
use super::wide_codec;
use crate::dataflow::{resolve_use, trace_int};
use crate::metrics_catalog::{
    MARSHALLING_SPEC_FIELDS as M_FIELDS, MARSHALLING_SPEC_PARAMS as M_PARAMS,
    MARSHALLING_SPEC_RETURNS as M_RETURNS,
};
use crate::pass::{Pass, PassResult};
use crate::type_infer::primitive_of_known;
use crate::val_abi::{tag_payload_type, TAG_VOID};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-spec-from-guards";

/// Recovers declared entrypoint types from the wrapper's own checks.
#[derive(Debug, Default, Clone, Copy)]
pub struct SpecFromGuardsPass;

impl Pass<HighIr> for SpecFromGuardsPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        // With a spec in hand the declaration is the spec's, and a body
        // cannot contradict it.
        if ir
            .soroban_facts
            .as_ref()
            .is_some_and(|f| !f.functions.is_empty())
        {
            return result;
        }
        // One classification for the module, as the elision pass does:
        // a helper is a helper wherever it is called from.
        let helpers: HashMap<FuncId, DecodeHelper> = ir
            .functions
            .iter()
            .filter_map(|f| decode::classify(f).map(|h| (f.id, h)))
            .collect();
        // The 128-bit decodes are their own family, classified by
        // `wide_codec` because a limb pair is not one `Ok` payload.
        let wide: HashMap<FuncId, (usize, KnownType)> = ir
            .functions
            .iter()
            .filter_map(|f| wide_codec::decoded_wide_type(f).map(|t| (f.id, t)))
            .collect();
        // The registry is shared, and what it learns here is what the
        // per-function walk below reads types out of.
        for (id, field, prim) in field_types(ir, &helpers, &wide) {
            let Some(facts) = ir.soroban_facts.as_mut() else {
                continue;
            };
            let Some(def) = facts.types.structs.iter_mut().find(|s| s.id == id) else {
                continue;
            };
            let Some(slot) = def.fields.iter_mut().find(|f| f.name == field) else {
                continue;
            };
            if !matches!(slot.ty, TypeRef::Unknown(_)) {
                continue;
            }
            slot.ty = TypeRef::Primitive(prim);
            result.metrics.increment(M_FIELDS, 1);
            result.changed = true;
        }
        for func in &mut ir.functions {
            let Some(sig) = func.signature.as_ref() else {
                continue;
            };
            if sig.inputs.len() != func.params.len() {
                continue;
            }
            let mut evidence = conversion_checks(func);
            evidence.extend(decoded_arguments(func, &helpers));
            evidence.extend(wide_arguments(func, &wide));
            let recovered: Vec<Option<PrimitiveType>> = func
                .params
                .iter()
                .map(|p| declared_by(&evidence, *p))
                .collect();
            let returned = returned_type(func);
            let Some(sig) = func.signature.as_mut() else {
                continue;
            };
            apply(sig, &recovered, returned, &mut result);
        }
        result
    }
}

/// What every conversion check on a recovered struct's field says its
/// type is: `(the struct, the field, the type)`.
///
/// Only fields still declared `Unknown`, which is what a struct
/// recovered from its key table starts with — a declared field has a
/// declaration, and a check cannot overrule one.
fn field_types(
    ir: &HighIr,
    helpers: &HashMap<FuncId, DecodeHelper>,
    wide: &HashMap<FuncId, (usize, KnownType)>,
) -> Vec<(TypeId, String, PrimitiveType)> {
    let mut seen: BTreeMap<(TypeId, String), Option<KnownType>> = BTreeMap::new();
    for func in &ir.functions {
        let mut evidence = conversion_checks(func);
        // A field wide enough to need a helper is decoded by one, just
        // as a parameter is.
        evidence.extend(decoded_arguments(func, helpers));
        evidence.extend(wide_arguments(func, wide));
        for (value, ty) in evidence {
            let Some((id, field)) = field_of(func, value) else {
                continue;
            };
            let slot = seen.entry((id, field)).or_insert_with(|| Some(ty.clone()));
            // One declared type per field, as for a parameter.
            if slot.as_ref() != Some(&ty) {
                *slot = None;
            }
        }
    }
    seen.into_iter()
        .filter_map(|((id, field), ty)| Some((id, field, primitive_of_known(&ty?)?)))
        .collect()
}

/// The struct and field name a value is an access of, when the struct is
/// one the registry knows.
fn field_of(func: &HighFunction, value: ValueId) -> Option<(TypeId, String)> {
    let Expr::Field { base, field } = &func.bindings.get(value)?.expr else {
        return None;
    };
    let base = func.bindings.get(resolve_use(func, *base))?;
    match &base.ty {
        IrType::Known(KnownType::UserDefined(id)) | IrType::Inferred(KnownType::UserDefined(id)) => {
            Some((*id, field.clone()))
        }
        _ => None,
    }
}

/// Write what was recovered into the signature, counting each change.
fn apply(
    sig: &mut FunctionSignature,
    recovered: &[Option<PrimitiveType>],
    returned: Option<PrimitiveType>,
    result: &mut PassResult,
) {
    for (input, prim) in sig.inputs.iter_mut().zip(recovered) {
        let Some(prim) = prim else { continue };
        if !matches!(input.ty, TypeRef::Primitive(PrimitiveType::Val)) {
            continue;
        }
        input.ty = TypeRef::Primitive(*prim);
        result.metrics.increment(M_PARAMS, 1);
        result.changed = true;
    }
    if !matches!(sig.outputs.as_slice(), [TypeRef::Primitive(PrimitiveType::Val)]) {
        return;
    }
    match returned {
        // `Void` is the host's spelling of "nothing", not a type the
        // source named.
        Some(PrimitiveType::Void) => sig.outputs.clear(),
        Some(prim) => sig.outputs = vec![TypeRef::Primitive(prim)],
        None => return,
    }
    result.metrics.increment(M_RETURNS, 1);
    result.changed = true;
}

/// The type every piece of evidence about this parameter agrees on.
fn declared_by(evidence: &[(ValueId, KnownType)], param: ValueId) -> Option<PrimitiveType> {
    let mut named: Option<KnownType> = None;
    for (_, ty) in evidence.iter().filter(|(v, _)| *v == param) {
        // One declared type, or nothing. Two is evidence against the
        // reading, not a choice between them. Both encodings of one
        // type agree, which is the small/object pair every wide type
        // has.
        if named.get_or_insert_with(|| ty.clone()) != ty {
            return None;
        }
    }
    primitive_of_known(&named?)
}

/// The tags each decode helper tests, against the argument it was
/// handed.
fn decoded_arguments(
    func: &HighFunction,
    helpers: &HashMap<FuncId, DecodeHelper>,
) -> Vec<(ValueId, KnownType)> {
    decoded(func, |target| helpers.get(target).map(DecodeHelper::val_index), |target, _| {
        helpers
            .get(target)
            .map(|h| h.tags().iter().filter_map(|t| tag_payload_type(*t)).collect())
            .unwrap_or_default()
    })
}

/// The 128-bit type each wide decode helper reads, against the argument
/// it was handed.
fn wide_arguments(
    func: &HighFunction,
    wide: &HashMap<FuncId, (usize, KnownType)>,
) -> Vec<(ValueId, KnownType)> {
    decoded(func, |target| wide.get(target).map(|(i, _)| *i), |target, _| {
        wide.get(target).map(|(_, ty)| vec![ty.clone()]).unwrap_or_default()
    })
}

/// Walk the calls, pairing the argument a classified helper decodes with
/// the types that helper proves it has.
fn decoded(
    func: &HighFunction,
    index: impl Fn(&FuncId) -> Option<usize>,
    types: impl Fn(&FuncId, usize) -> Vec<KnownType>,
) -> Vec<(ValueId, KnownType)> {
    let mut out = Vec::new();
    for (_, binding) in func.bindings.iter() {
        let Expr::Call { target, args } = &binding.expr else {
            continue;
        };
        let Some(i) = index(target) else { continue };
        let Some(arg) = args.get(i) else { continue };
        let value = resolve_use(func, *arg);
        out.extend(types(target, i).into_iter().map(|ty| (value, ty)));
    }
    out
}

/// Every tag check sitting where `#[contractimpl]` puts its conversion:
/// the branch it controls traps on the mismatch.
fn conversion_checks(func: &HighFunction) -> Vec<(ValueId, KnownType)> {
    let mut found = Vec::new();
    collect(func, &func.region, &mut found);
    found
}

fn collect(func: &HighFunction, region: &Region, out: &mut Vec<(ValueId, KnownType)>) {
    match region {
        Region::Sequence(items) => {
            for (i, item) in items.iter().enumerate() {
                // `if ok { work; return } … panic!()` — the mismatch
                // trap closes the function rather than sitting in an
                // arm. The match path has to leave, or the trap is not
                // the mismatch's.
                if let Region::If { cond, then_region, else_region: None } = item
                    && terminates(then_region)
                    && items[i + 1..].last().is_some_and(traps)
                    && let Some((value, tag, false)) = tag_check(func, *cond)
                {
                    push(out, value, tag);
                }
                collect(func, item, out);
            }
        }
        Region::If { cond, then_region, else_region } => {
            if let Some((value, tag, negated)) = tag_check(func, *cond) {
                let trapping = if negated {
                    traps(then_region)
                } else {
                    else_region.as_deref().is_some_and(traps)
                };
                if trapping {
                    push(out, value, tag);
                }
            }
            collect(func, then_region, out);
            if let Some(e) = else_region {
                collect(func, e, out);
            }
        }
        Region::Scope { body, .. } | Region::Loop { body, .. } => collect(func, body, out),
        Region::Switch { arms, default, .. } => {
            for arm in arms {
                collect(func, &arm.body, out);
            }
            collect(func, default, out);
        }
        Region::Basic(_)
        | Region::Break { .. }
        | Region::Continue { .. }
        | Region::Transfer { .. }
        | Region::Return { .. }
        | Region::Unreachable
        | Region::Panic { .. }
        | Region::Unstructured { .. } => {}
    }
}

/// Record what a tag says about a value, where it says anything.
fn push(out: &mut Vec<(ValueId, KnownType)>, value: ValueId, tag: u8) {
    if let Some(ty) = tag_payload_type(tag) {
        out.push((value, ty));
    }
}

/// Whether reaching this region means trapping.
fn traps(region: &Region) -> bool {
    match region {
        Region::Panic { .. } => true,
        Region::Sequence(items) => items.last().is_some_and(traps),
        _ => false,
    }
}

/// Whether control never falls out of this region into what follows.
fn terminates(region: &Region) -> bool {
    match region {
        Region::Panic { .. }
        | Region::Return { .. }
        | Region::Break { .. }
        | Region::Continue { .. }
        | Region::Unreachable => true,
        Region::Sequence(items) => items.last().is_some_and(terminates),
        _ => false,
    }
}

/// The `(subject, tag, negated)` a value is a tag check of.
fn tag_check(func: &HighFunction, value: ValueId) -> Option<(ValueId, u8, bool)> {
    match &func.bindings.get(resolve_use(func, value))?.expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck { value, tag, negated })) => {
            Some((resolve_use(func, *value), *tag, *negated))
        }
        _ => None,
    }
}

/// The type every return site agrees this entrypoint hands back.
///
/// A wasm entrypoint always returns one `Val` because the host's calling
/// convention says so, so the `Val` in the signature says nothing. What
/// the function puts in it does: a recovered value of a known type, that
/// type packed into a small `Val`, or the constant `Void`, which is how
/// the SDK spells a function that returns nothing.
fn returned_type(func: &HighFunction) -> Option<PrimitiveType> {
    let mut named: Option<PrimitiveType> = None;
    for values in &func.returns {
        let [value] = values.as_slice() else {
            return None;
        };
        let prim = returned_one(func, *value)?;
        if *named.get_or_insert(prim) != prim {
            return None;
        }
    }
    named
}

/// What one returned value says the return type is.
fn returned_one(func: &HighFunction, value: ValueId) -> Option<PrimitiveType> {
    if trace_int(func, value) == Some(i128::from(TAG_VOID)) {
        return Some(PrimitiveType::Void);
    }
    let binding = func.bindings.get(resolve_use(func, value))?;
    // Packed on the way out: the tag names the type.
    if let Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty, .. })) = &binding.expr {
        return primitive_of_known(ty);
    }
    // Or already recovered, the encode having collapsed into it.
    match &binding.ty {
        sordec_ir::IrType::Known(t) => {
            primitive_of_known(t).filter(|p| !matches!(p, PrimitiveType::Val))
        }
        _ => None,
    }
}
