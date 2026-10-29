//! Per-function emission: `contractspecv0` methods vs synthesized free fns.

use syn::parse_quote;

use sordec_ir::{HighFunction, HighIr, TypeRegistry};

use crate::rust::hole::HolePolicy;
use crate::rust::{body, sig};

/// One function rendered either as a contract method or a free function.
pub(crate) enum Emitted {
    /// A public method for the `#[contractimpl] impl` block.
    Method(Box<syn::ImplItemFn>),
    /// A top-level free function (an internal helper).
    Free(Box<syn::Item>),
}

/// Emit one function. A function present in `contractspecv0`
/// (`signature.is_some()`) becomes a public contract method; every other
/// function becomes a free helper. The body is the region → `syn` walk
/// ([`body::emit_body`]); `high` is needed to resolve call targets to
/// their emitted names.
pub(crate) fn emit_function(
    high: &HighIr,
    func: &HighFunction,
    reg: &TypeRegistry,
    policy: &dyn HolePolicy,
) -> Vec<Emitted> {
    let block = body::emit_body(high, func, reg, policy);
    if func.signature.is_none() {
        let signature = sig::helper_signature(func, reg, policy);
        return vec![Emitted::Free(Box::new(parse_quote!(#signature #block)))];
    }
    let signature = sig::spec_signature(func, reg, policy);
    let mut out = vec![Emitted::Method(Box::new(parse_quote!(pub #signature #block)))];
    // One method per name the linker merged onto this body. The source
    // wrote each of them separately, so emitting one and dropping the rest
    // loses entrypoints the contract really has; the body is shared
    // because it is genuinely identical.
    //
    // Printed against the alias's own declaration, though: the code is one,
    // but what it returns is read through each signature. `val` and `woid`
    // both hand back the word `2` — `Val::VOID` for the `-> Val` one, and
    // the `Void` a `-> ()` function returns for the other, which is nothing.
    for alias in &func.aliases {
        let signature = sig::spec_signature_of(alias, func, reg, policy);
        let mut as_alias = func.clone();
        as_alias.signature = Some(alias.clone());
        as_alias.aliases.clear();
        let block = body::emit_body(high, &as_alias, reg, policy);
        out.push(Emitted::Method(Box::new(parse_quote!(pub #signature #block))));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use quote::ToTokens;
    use sordec_common::{Arena, BlockId, FuncId, IrId, Provenance, ProvenanceSource, ValueId};
    use sordec_ir::{
        Binding, Expr, FunctionSignature, HighBlock, IrType, KnownType, Literal, MemoryImage, PrimitiveType, Region,
        TypeRef, WasmFacts,
    };

    fn signature(name: &str, outputs: Vec<TypeRef>) -> FunctionSignature {
        FunctionSignature { name: name.into(), inputs: vec![], outputs }
    }

    /// One entrypoint whose body returns the word `2`, declared `sig`, with
    /// `aliases` sharing the body. Each emitted method, as text.
    fn emitted(sig: FunctionSignature, aliases: Vec<FunctionSignature>) -> Vec<String> {
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        let two = ValueId::new(0);
        bindings.push(Binding::new(
            two,
            IrType::Known(KnownType::I64),
            Expr::Literal(Literal::I64(2)),
            Provenance::new("test", ProvenanceSource::DataFlow, "test"),
        ));
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        let b0 = BlockId::from_index(0);
        blocks.push(HighBlock { id: b0, bindings: vec![two] });
        let func = HighFunction {
            id: FuncId::from_index(0),
            name: Some(sig.name.clone()),
            signature: Some(sig),
            aliases,
            blocks,
            bindings,
            region: Region::Sequence(vec![Region::Basic(b0), Region::Return { values: vec![two] }]),
            params: vec![],
            returns: vec![vec![two]],
        };
        let high = HighIr {
            facts: WasmFacts {
                imports: vec![],
                exports: vec![],
                function_type_indices: vec![],
                function_bodies: vec![],
                function_fingerprints: vec![],
                table_functions: None,
                custom_sections: vec![],
            },
            soroban_facts: None,
            functions: vec![func],
            memory: MemoryImage::empty(),
        };
        let policy = crate::rust::hole::StrictNoGuess;
        emit_function(&high, &high.functions[0], &TypeRegistry::default(), &policy)
            .into_iter()
            .map(|e| match e {
                Emitted::Method(m) => m.to_token_stream().to_string(),
                Emitted::Free(f) => f.to_token_stream().to_string(),
            })
            .collect()
    }

    #[test]
    fn a_val_return_spells_the_constant_as_the_val() {
        let out = emitted(signature("val", vec![TypeRef::Primitive(PrimitiveType::Val)]), vec![]);
        assert!(out[0].contains("Val :: VOID . to_val ()"), "{}", out[0]);
        assert!(!out[0].contains("2i64"), "{}", out[0]);
    }

    #[test]
    fn a_unit_return_returns_nothing() {
        let out = emitted(signature("void_fn", vec![TypeRef::Primitive(PrimitiveType::Void)]), vec![]);
        assert!(!out[0].contains("2i64"), "{}", out[0]);
        assert!(out[0].ends_with("{ }"), "{}", out[0]);
    }

    #[test]
    fn a_merged_body_is_printed_against_each_alias_s_own_declaration() {
        let out = emitted(
            signature("val", vec![TypeRef::Primitive(PrimitiveType::Val)]),
            vec![signature("woid", vec![])],
        );
        assert_eq!(out.len(), 2);
        assert!(out[0].contains("Val :: VOID . to_val ()"), "{}", out[0]);
        assert!(out[1].contains("fn woid"), "{}", out[1]);
        assert!(out[1].ends_with("{ }"), "{}", out[1]);
    }

    /// A helper whose `Val` parameter flows into a merge typed `merge`, whose
    /// other arm is the constant `7` typed `other`.
    fn val_into_merge(merge: KnownType, other: KnownType) -> String {
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        let prov = || Provenance::new("test", ProvenanceSource::DataFlow, "test");
        bindings.push(Binding::new(ValueId::new(0), IrType::Inferred(KnownType::Val), Expr::Phi { incoming: vec![] }, prov()));
        let (b0, b1) = (BlockId::from_index(0), BlockId::from_index(1));
        bindings.push(Binding::new(
            ValueId::new(1),
            IrType::Inferred(merge),
            Expr::Phi { incoming: vec![(b0, ValueId::new(0)), (b0, ValueId::new(2))] },
            prov(),
        ));
        bindings.push(Binding::new(ValueId::new(2), IrType::Known(other), Expr::Literal(Literal::I64(7)), prov()));
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        blocks.push(HighBlock { id: b0, bindings: vec![] });
        blocks.push(HighBlock { id: b1, bindings: vec![] });
        let func = HighFunction {
            id: FuncId::from_index(0),
            name: None,
            signature: None,
            aliases: vec![],
            blocks,
            bindings,
            region: Region::Sequence(vec![
                Region::Scope {
                    out: b1,
                    body: Box::new(Region::Sequence(vec![
                        Region::Basic(b0),
                        Region::Break { target: b1, transfer: vec![(ValueId::new(1), ValueId::new(0))] },
                    ])),
                },
                Region::Basic(b1),
                Region::Return { values: vec![ValueId::new(1)] },
            ]),
            params: vec![ValueId::new(0)],
            returns: vec![vec![ValueId::new(1)]],
        };
        let high = HighIr {
            facts: WasmFacts {
                imports: vec![],
                exports: vec![],
                function_type_indices: vec![],
                function_bodies: vec![],
                function_fingerprints: vec![],
                table_functions: None,
                custom_sections: vec![],
            },
            soroban_facts: None,
            functions: vec![func],
            memory: MemoryImage::empty(),
        };
        let policy = crate::rust::hole::StrictNoGuess;
        match emit_function(&high, &high.functions[0], &TypeRegistry::default(), &policy).remove(0) {
            Emitted::Method(m) => m.to_token_stream().to_string(),
            Emitted::Free(f) => f.to_token_stream().to_string(),
        }
    }

    #[test]
    fn a_val_merged_into_a_word_beside_a_number_is_its_bits() {
        let out = val_into_merge(KnownType::I64, KnownType::I64);
        assert!(out.contains("arg0 . get_payload () as i64"), "{out}");
        let out = val_into_merge(KnownType::U64, KnownType::U64);
        assert!(out.contains("arg0 . get_payload ()"), "{out}");
    }

    #[test]
    fn a_word_merge_of_vals_only_is_left_alone() {
        // Every other arm a `Val` too: the number type came from what they
        // encode, which is a wrong type, not a word.
        let out = val_into_merge(KnownType::U64, KnownType::Val);
        assert!(!out.contains("get_payload"), "{out}");
    }

    #[test]
    fn a_val_merged_into_a_val_is_itself() {
        let out = val_into_merge(KnownType::Val, KnownType::I64);
        assert!(!out.contains("get_payload"), "{out}");
    }

    /// The caller (func 0) hands its `Val` parameter to func 1, whose `i64`
    /// parameter its own body tag-checks when `checked`.
    fn val_into_helper(checked: bool) -> String {
        let prov = || Provenance::new("test", ProvenanceSource::DataFlow, "test");
        let b0 = BlockId::from_index(0);
        let mut caller_bindings: Arena<ValueId, Binding> = Arena::new();
        caller_bindings.push(Binding::new(ValueId::new(0), IrType::Inferred(KnownType::Val), Expr::Phi { incoming: vec![] }, prov()));
        caller_bindings.push(Binding::new(
            ValueId::new(1),
            IrType::Known(KnownType::Unit),
            Expr::Call { target: FuncId::from_index(1), args: vec![ValueId::new(0)] },
            prov(),
        ));
        let mut caller_blocks: Arena<BlockId, HighBlock> = Arena::new();
        caller_blocks.push(HighBlock { id: b0, bindings: vec![ValueId::new(1)] });
        let caller = HighFunction {
            id: FuncId::from_index(0),
            name: None,
            signature: None,
            aliases: vec![],
            blocks: caller_blocks,
            bindings: caller_bindings,
            region: Region::Basic(b0),
            params: vec![ValueId::new(0)],
            returns: vec![],
        };
        let mut callee_bindings: Arena<ValueId, Binding> = Arena::new();
        callee_bindings.push(Binding::new(ValueId::new(0), IrType::Inferred(KnownType::I64), Expr::Phi { incoming: vec![] }, prov()));
        callee_bindings.push(Binding::new(
            ValueId::new(1),
            IrType::Inferred(KnownType::Bool),
            if checked {
                Expr::Semantic(sordec_ir::SemanticOp::Known(sordec_ir::KnownOp::ValTagCheck {
                    value: ValueId::new(0),
                    tag: 69,
                    negated: false,
                }))
            } else {
                Expr::Literal(Literal::Bool(true))
            },
            prov(),
        ));
        let mut callee_blocks: Arena<BlockId, HighBlock> = Arena::new();
        callee_blocks.push(HighBlock { id: b0, bindings: vec![ValueId::new(1)] });
        let callee = HighFunction {
            id: FuncId::from_index(1),
            name: None,
            signature: None,
            aliases: vec![],
            blocks: callee_blocks,
            bindings: callee_bindings,
            region: Region::Basic(b0),
            params: vec![ValueId::new(0)],
            returns: vec![],
        };
        let high = HighIr {
            facts: WasmFacts {
                imports: vec![],
                exports: vec![],
                function_type_indices: vec![],
                function_bodies: vec![],
                function_fingerprints: vec![],
                table_functions: None,
                custom_sections: vec![],
            },
            soroban_facts: None,
            functions: vec![caller, callee],
            memory: MemoryImage::empty(),
        };
        let policy = crate::rust::hole::StrictNoGuess;
        match emit_function(&high, &high.functions[0], &TypeRegistry::default(), &policy).remove(0) {
            Emitted::Method(m) => m.to_token_stream().to_string(),
            Emitted::Free(f) => f.to_token_stream().to_string(),
        }
    }

    #[test]
    fn a_val_handed_to_a_parameter_its_helper_tag_checks_is_its_bits() {
        let out = val_into_helper(true);
        assert!(out.contains("arg0 . get_payload () as i64"), "{out}");
    }

    #[test]
    fn a_val_handed_to_a_plain_number_parameter_is_not_converted() {
        let out = val_into_helper(false);
        assert!(!out.contains("get_payload"), "{out}");
    }

    #[test]
    fn another_return_type_keeps_the_word() {
        let out = emitted(signature("count", vec![TypeRef::Primitive(PrimitiveType::I64)]), vec![]);
        assert!(out[0].contains("2i64"), "{}", out[0]);
    }
}
