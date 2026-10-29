//! The contract-error constant recognizer (spec D4.4's error substrate).
//!
//! A `#[contracterror]` value — the `Err(Error::Variant)` a contract
//! constructs — reaches the WASM boundary as a compile-time-constant
//! `Error` `Val`: `(code << 32) | TAG_ERROR`, with the error *type* in the
//! minor field. rustc folds the whole thing to a single integer literal, so
//! by the time the recognizers run it is an `Expr::Literal(I64/U64)` binding.
//! This pass decodes that constant and, when its code names exactly one
//! declared error variant, rewrites the binding to a
//! [`KnownOp::MakeError`] carrying the resolved [`ErrorVariant`] — so the
//! emitter can render `Error::Variant` (and wrap the return in `Err(..)`)
//! instead of a bare integer.
//!
//! ## Evidence gate (all required — leave the literal untouched otherwise)
//!
//! 1. **Registry gate.** `contractspecv0` declares at least one
//!    `#[contracterror]` enum. Without it (stripped builds) nothing is
//!    named — the same None-is-honest discipline as [`enum_key`].
//! 2. **ABI decode.** The constant is a small `Error` `Val` of
//!    `ScErrorType::Contract` (host error types are not user variants):
//!    [`val_abi::decode_contract_error`].
//! 3. **Unique variant.** The decoded code matches exactly one declared
//!    error variant ([`TypeRegistry::variant_by_value`]); a code no enum
//!    declares — or one two enums share — resolves to nothing and the
//!    literal is left as-is. This gate also makes a coincidental
//!    low-byte-`3` integer a non-event.
//!
//! ## A panic's error whose code no single enum names
//!
//! The argument of `panic_with_error!` is an `Error` by the host ABI —
//! `fail_with_error` takes nothing else — so a constant read only there is
//! one even when gate 3 cannot name its variant: a code two enums declare,
//! or one no enum declares. It becomes [`KnownOp::MakeError`] with no
//! variant, which the emitter spells `Error::from_contract_error(code)`.
//! Exact: that is the `Error` with this type and code, the same bits, and
//! `panic_with_error!` hands it to the host unchanged whichever enum the
//! source named. Gates 1 and 2 still hold; only gate 3 is replaced, by the
//! position.
//!
//! ## A returned error the declared `Result` names
//!
//! A constant that only flows into the function's return, directly or
//! through the merges before it, in an entrypoint the spec declares
//! `-> Result<T, E>`, is read by the host as that `Result`: an `Error` `Val`
//! is its `Err`. So the declared `E` names the variant even when the code
//! alone does not — two enums declaring the same code, the case gate 3
//! refuses. `E` a declared error enum: its variant with that code, when it
//! has one. `E` the SDK's own `Error`: `Error::from_contract_error(code)`.
//! The emitter then wraps the arm as `Err(..)`, as it does any error.
//!
//! Unlike [`enum_key`], the discriminant here is *witnessed* (it is the
//! literal's own bits, not a declaration-order inference), so a match is
//! `HostFunctionAbi`-grade. Idempotent: the rewritten binding is a
//! `Semantic(Known(_))`, which `is_recognized` skips on a second run.
//!
//! [`enum_key`]: super::enum_key
//! [`TypeRegistry::variant_by_value`]: sordec_ir::TypeRegistry::variant_by_value

use std::collections::HashMap;

use sordec_common::{FuncId, ProvenanceSource};
use sordec_ir::{ErrorVariant, Expr, HighIr, IrType, KnownOp, KnownType, Literal, SemanticOp};

use super::{apply_rewrites, is_recognized, Rewrite};
use crate::pass::{Pass, PassResult};
use crate::val_abi;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "error-const";

/// Constant Error `Val`s named as a declared `#[contracterror]` variant.
const M_ERROR_NAMED: &str = "error_const_named";

/// Constant Error `Val`s a panic raises, whose code no single enum names.
const M_ERROR_UNNAMED: &str = "error_const_panic_unnamed";

/// The contract-error constant recognizer. Stateless between runs.
#[derive(Debug, Default, Clone, Copy)]
pub struct ErrorConstPass;

impl Pass<HighIr> for ErrorConstPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();

        // Gate 1: no declared error enums (stripped builds, or a contract
        // with none) → nothing can be named. Stay silent and honest.
        let has_errors = ir
            .soroban_facts
            .as_ref()
            .is_some_and(|f| !f.types.errors.is_empty());
        if !has_errors {
            return result;
        }
        let types = &ir.soroban_facts.as_ref().expect("gated above").types;

        // Phase A — read-only scan: plan the rewrites per function.
        let mut planned: HashMap<FuncId, Vec<Rewrite>> = HashMap::new();
        for func in &ir.functions {
            for (id, binding) in func.bindings.iter() {
                if is_recognized(&binding.expr) {
                    continue; // already a semantic op (idempotency)
                }
                let Some(bits) = error_bits(&binding.expr) else {
                    continue;
                };
                // Gate 2 + 3: a Contract-type Error whose code names exactly
                // one declared variant.
                let Some(code) = val_abi::decode_contract_error(bits) else {
                    continue;
                };
                let named = types.variant_by_value(code).or_else(|| {
                    returned_error_type(func)
                        .filter(|_| only_returned(func, id))
                        .and_then(|e| match e {
                            DeclaredError::Enum(enum_id) => types
                                .errors
                                .iter()
                                .find(|d| d.id == enum_id)
                                .and_then(|d| d.cases.iter().find(|c| c.value == code).map(|c| (d.name.as_str(), c.name.as_str()))),
                            DeclaredError::Sdk => None,
                        })
                });
                let sdk_error_return = named.is_none()
                    && matches!(returned_error_type(func), Some(DeclaredError::Sdk))
                    && only_returned(func, id);
                let Some((enum_name, variant)) = named else {
                    if only_panicked(func, id) || sdk_error_return {
                        planned.entry(func.id).or_default().push(Rewrite {
                            id,
                            expr: Expr::Semantic(SemanticOp::Known(KnownOp::MakeError { code, resolved: None })),
                            ty: Some(IrType::Known(KnownType::Error)),
                            source: ProvenanceSource::HostFunctionAbi,
                            note: format!(
                                "error-const: contract error code {code}, the argument of a panic; \
                                 no single declared enum names it"
                            ),
                            metric: M_ERROR_UNNAMED,
                        });
                    }
                    continue;
                };
                let note = format!("error-const {enum_name}::{variant} (contract error code {code})");
                planned.entry(func.id).or_default().push(Rewrite {
                    id,
                    expr: Expr::Semantic(SemanticOp::Known(KnownOp::MakeError {
                        code,
                        resolved: Some(ErrorVariant {
                            enum_name: enum_name.to_string(),
                            variant: variant.to_string(),
                        }),
                    })),
                    // The value is a Soroban `Error`; witnessed from its bits.
                    ty: Some(IrType::Known(KnownType::Error)),
                    source: ProvenanceSource::HostFunctionAbi,
                    note,
                    metric: M_ERROR_NAMED,
                });
            }
        }

        // Phase B — apply per function.
        for (func_id, rewrites) in planned {
            for rw in &rewrites {
                result.metrics.increment(rw.metric, 1);
            }
            result.changed = true;
            if let Some(func) = ir.function_mut(func_id) {
                apply_rewrites(func, PASS_NAME, rewrites);
            }
        }
        result
    }
}

/// The `E` of the `Result<T, E>` an entrypoint's spec declares it returns.
enum DeclaredError {
    /// A declared `#[contracterror]` enum.
    Enum(sordec_common::TypeId),
    /// The SDK's own `Error`.
    Sdk,
}

fn returned_error_type(func: &sordec_ir::HighFunction) -> Option<DeclaredError> {
    let [out] = func.signature.as_ref()?.outputs.as_slice() else {
        return None;
    };
    let KnownType::Result(_, err) = crate::type_infer::known_of_type_ref(out)? else {
        return None;
    };
    match *err {
        IrType::Known(KnownType::UserDefined(id)) | IrType::Inferred(KnownType::UserDefined(id)) => {
            Some(DeclaredError::Enum(id))
        }
        IrType::Known(KnownType::Error) | IrType::Inferred(KnownType::Error) => Some(DeclaredError::Sdk),
        _ => None,
    }
}

/// Whether `id` flows only into the function's return: every reader is a
/// merge that itself flows only there, or the return.
fn only_returned(func: &sordec_ir::HighFunction, id: sordec_common::ValueId) -> bool {
    use sordec_ir::Region;
    // The merges that reach a return, and the values returned.
    let mut returned: std::collections::HashSet<sordec_common::ValueId> = std::collections::HashSet::new();
    func.region.for_each_node(|node| {
        if let Region::Return { values } = node {
            returned.extend(values.iter().copied());
        }
    });
    let mut chain: std::collections::HashSet<sordec_common::ValueId> = returned.clone();
    let mut grew = true;
    while grew {
        grew = false;
        for (m, b) in func.bindings.iter() {
            if let Expr::Phi { incoming } = &b.expr
                && chain.contains(&m)
            {
                for (_, a) in incoming {
                    grew |= chain.insert(*a);
                }
            }
        }
    }
    if !chain.contains(&id) {
        return false;
    }
    // Every binding reading a chain member (other than the merges that
    // carry it) must itself be in the chain; nothing else reads `id`.
    for (reader, b) in func.bindings.iter() {
        let mut reads = false;
        b.expr.for_each_value_use(|u| reads |= u == id);
        if reads && !(chain.contains(&reader) && matches!(b.expr, Expr::Phi { .. })) {
            return false;
        }
    }
    // In the region: returns, and transfers into a chain merge.
    let mut ok = true;
    func.region.for_each_node(|node| match node {
        Region::If { cond, .. } => ok &= *cond != id,
        Region::Switch { index, .. } => ok &= *index != id,
        Region::Break { transfer, .. } | Region::Continue { transfer, .. } | Region::Transfer { transfer, .. } => {
            for (dest, src) in transfer {
                if *src == id && !chain.contains(dest) {
                    ok = false;
                }
            }
        }
        _ => {}
    });
    ok
}

/// Whether every live reader of `id` is a `panic_with_error` raising it.
fn only_panicked(func: &sordec_ir::HighFunction, id: sordec_common::ValueId) -> bool {
    let scheduled: std::collections::HashSet<sordec_common::ValueId> =
        func.blocks.iter().flat_map(|(_, b)| b.bindings.iter().copied()).collect();
    let mut panics = 0;
    for (reader, b) in func.bindings.iter() {
        let mut reads = false;
        b.expr.for_each_value_use(|u| reads |= u == id);
        if !reads {
            continue;
        }
        if !scheduled.contains(&reader) && !matches!(b.expr, Expr::Phi { .. }) {
            continue;
        }
        match &b.expr {
            Expr::Semantic(SemanticOp::Known(KnownOp::PanicWithError { error })) if *error == id => panics += 1,
            _ => return false,
        }
    }
    let mut region_reads = false;
    func.region.for_each_value_use(|u| region_reads |= u == id);
    panics > 0 && !region_reads
}

/// The raw 64-bit `Val` pattern of a constant that could be an `Error`.
///
/// A contract `Error` `Val` for any non-zero code is `≥ 2^32` (the code
/// lives in the major field), so it is always an `i64`/`u64` literal — an
/// `i32` literal can only ever carry a code-0 error, which
/// [`TypeRegistry::variant_by_value`] resolves only if such a variant is
/// declared. Restricting to the 64-bit carriers keeps the false-positive
/// surface minimal.
fn error_bits(expr: &Expr) -> Option<u64> {
    match expr {
        Expr::Literal(Literal::I64(n)) => Some(*n as u64),
        Expr::Literal(Literal::U64(n)) => Some(*n),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{Arena, BlockId, IrId, Provenance, ProvenanceSource, UnknownReason, ValueId};
    use sordec_ir::{
        Binding, EnumCase, EnumDef, HighBlock, HighFunction, MemoryImage, Region, SorobanFacts,
        TypeRegistry, WasmFacts,
    };

    /// The Error `Val` bits for a `Contract`-type error `code`.
    fn contract_error_val(code: u32) -> i64 {
        ((u64::from(code) << 32) | u64::from(val_abi::TAG_ERROR)) as i64
    }

    /// A single-function module whose one block schedules `exprs`, over a
    /// registry declaring `errors` (`(name, code)` pairs on one `Error` enum).
    fn module(exprs: Vec<Expr>, errors: &[(&str, u32)]) -> HighIr {
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        let mut scheduled = Vec::new();
        for expr in exprs {
            let vid = ValueId::from_index(bindings.len() as u32);
            bindings.push(Binding::new(
                vid,
                IrType::Unknown(UnknownReason::InsufficientEvidence),
                expr,
                Provenance::new("test", ProvenanceSource::DataFlow, "seed"),
            ));
            scheduled.push(vid);
        }
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        blocks.push(HighBlock { id: BlockId::from_index(0), bindings: scheduled });
        let func = HighFunction {
            id: FuncId::from_index(0),
            name: None,
            signature: None,
            aliases: Vec::new(),
            blocks,
            bindings,
            region: Region::Unreachable,
            params: vec![],
            returns: vec![],
        };
        let errors = if errors.is_empty() {
            vec![]
        } else {
            vec![EnumDef {
                id: sordec_common::TypeId::from_index(0),
                name: "Error".to_string(),
                cases: errors
                    .iter()
                    .map(|(n, v)| EnumCase { name: (*n).to_string(), value: *v })
                    .collect(),
            }]
        };
        HighIr {
            facts: WasmFacts {
                imports: vec![],
                exports: vec![],
                function_type_indices: vec![],
                function_bodies: vec![],
                function_fingerprints: vec![],
                table_functions: None,
                custom_sections: vec![],
            },
            soroban_facts: Some(SorobanFacts {
                types: TypeRegistry { errors, ..TypeRegistry::default() },
                ..SorobanFacts::default()
            }),
            functions: vec![func],
            memory: MemoryImage::from_segments(vec![]),
        }
    }

    fn op_at(ir: &HighIr, i: u32) -> Expr {
        ir.functions[0].bindings.get(ValueId::from_index(i)).unwrap().expr.clone()
    }

    #[test]
    fn decodes_a_contract_error_constant_to_its_variant() {
        // v0 = Err(Error::EmptyMessage) constant (code 1).
        let mut ir = module(
            vec![Expr::Literal(Literal::I64(contract_error_val(1)))],
            &[("EmptyMessage", 1), ("DigestMismatch", 2)],
        );
        let result = ErrorConstPass.run(&mut ir);
        assert!(result.changed);
        assert_eq!(result.metrics.get(M_ERROR_NAMED), Some(1));
        match op_at(&ir, 0) {
            Expr::Semantic(SemanticOp::Known(KnownOp::MakeError { code, resolved })) => {
                assert_eq!(code, 1);
                let v = resolved.expect("resolved variant");
                assert_eq!(v.enum_name, "Error");
                assert_eq!(v.variant, "EmptyMessage");
            }
            other => panic!("expected MakeError, got {other:?}"),
        }
        // The binding's type is upgraded to Error.
        let ty = &ir.functions[0].bindings.get(ValueId::from_index(0)).unwrap().ty;
        assert!(matches!(ty, IrType::Known(KnownType::Error)), "{ty:?}");
    }

    fn panic_of(v: u32) -> Expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::PanicWithError { error: ValueId::from_index(v) }))
    }

    #[test]
    fn a_panic_s_error_no_enum_names_is_the_sdk_error_with_its_code() {
        // Code 9 is declared by no enum, but `panic_with_error` takes an
        // `Error` and nothing else.
        let mut ir = module(
            vec![Expr::Literal(Literal::I64(contract_error_val(9))), panic_of(0)],
            &[("EmptyMessage", 1)],
        );
        let result = ErrorConstPass.run(&mut ir);
        assert_eq!(result.metrics.get(M_ERROR_UNNAMED), Some(1));
        assert!(matches!(
            op_at(&ir, 0),
            Expr::Semantic(SemanticOp::Known(KnownOp::MakeError { code: 9, resolved: None }))
        ));
    }

    #[test]
    fn an_unnamed_code_read_anywhere_else_is_left_alone() {
        // The constant is also returned: not only a panic's argument.
        let mut ir = module(
            vec![
                Expr::Literal(Literal::I64(contract_error_val(9))),
                panic_of(0),
                Expr::Use(ValueId::from_index(0)),
            ],
            &[("EmptyMessage", 1)],
        );
        ErrorConstPass.run(&mut ir);
        assert!(matches!(op_at(&ir, 0), Expr::Literal(Literal::I64(_))));
    }

    /// `fn f() -> Result<u64, E> { r = phi [err, 7]; return r }`, with two
    /// enums declaring code 1: `Error` (id 0, from `module`) and `MyError`
    /// (id 1). `err_ty` is `E`.
    fn returned_error(err_ty: sordec_ir::TypeRef) -> HighIr {
        use sordec_ir::{CompositeType, FunctionSignature, PrimitiveType, TypeRef};
        let mut ir = module(
            vec![
                Expr::Literal(Literal::I64(contract_error_val(1))), // v0 err
                Expr::Literal(Literal::I64(7)),                     // v1
                Expr::Phi {
                    incoming: vec![(BlockId::from_index(1), ValueId::from_index(0)), (BlockId::from_index(2), ValueId::from_index(1))],
                }, // v2
            ],
            &[("Overflow", 1)],
        );
        if let Some(facts) = ir.soroban_facts.as_mut() {
            facts.types.errors.push(EnumDef {
                id: sordec_common::TypeId::from_index(1),
                name: "MyError".to_string(),
                cases: vec![EnumCase { name: "Overflow".to_string(), value: 1 }],
            });
        }
        let f = &mut ir.functions[0];
        f.signature = Some(FunctionSignature {
            name: "f".to_string(),
            inputs: vec![],
            outputs: vec![TypeRef::Composite(CompositeType::Result(
                Box::new(TypeRef::Primitive(PrimitiveType::U64)),
                Box::new(err_ty),
            ))],
        });
        f.region = Region::Return { values: vec![ValueId::from_index(2)] };
        ir
    }

    #[test]
    fn a_returned_error_shared_by_two_enums_is_the_declared_enum_s() {
        let mut ir = returned_error(sordec_ir::TypeRef::UserDefined(sordec_common::TypeId::from_index(1)));
        ErrorConstPass.run(&mut ir);
        match op_at(&ir, 0) {
            Expr::Semantic(SemanticOp::Known(KnownOp::MakeError { code: 1, resolved: Some(v) })) => {
                assert_eq!((v.enum_name.as_str(), v.variant.as_str()), ("MyError", "Overflow"));
            }
            other => panic!("expected MyError::Overflow, got {other:?}"),
        }
    }

    #[test]
    fn a_returned_error_of_the_sdk_error_type_is_the_sdk_error() {
        let mut ir = returned_error(sordec_ir::TypeRef::Primitive(sordec_ir::PrimitiveType::Error));
        ErrorConstPass.run(&mut ir);
        assert!(matches!(
            op_at(&ir, 0),
            Expr::Semantic(SemanticOp::Known(KnownOp::MakeError { code: 1, resolved: None }))
        ));
    }

    #[test]
    fn an_error_constant_also_read_elsewhere_is_left_alone() {
        let mut ir = returned_error(sordec_ir::TypeRef::UserDefined(sordec_common::TypeId::from_index(1)));
        // A comparison reads it too: not only the return.
        let f = &mut ir.functions[0];
        let cmp = f.bindings.push(Binding::new(
            ValueId::from_index(3),
            IrType::Unknown(UnknownReason::InsufficientEvidence),
            Expr::Binary { op: sordec_ir::BinaryOp::Eq, lhs: ValueId::from_index(0), rhs: ValueId::from_index(1) },
            Provenance::new("test", ProvenanceSource::DataFlow, "seed"),
        ));
        f.blocks.get_mut(BlockId::from_index(0)).unwrap().bindings.push(cmp);
        ErrorConstPass.run(&mut ir);
        assert!(matches!(op_at(&ir, 0), Expr::Literal(Literal::I64(_))));
    }

    #[test]
    fn leaves_a_plain_integer_literal_alone() {
        // 42 is not an Error Val (low byte != TAG_ERROR).
        let mut ir = module(vec![Expr::Literal(Literal::I64(42))], &[("EmptyMessage", 1)]);
        let result = ErrorConstPass.run(&mut ir);
        assert!(!result.changed);
        assert!(matches!(op_at(&ir, 0), Expr::Literal(Literal::I64(42))));
    }

    #[test]
    fn leaves_an_undeclared_code_alone() {
        // Shaped like a Contract error (tag 3, minor 0) but code 9 is not
        // a declared variant — never guess; stays a literal.
        let mut ir = module(
            vec![Expr::Literal(Literal::I64(contract_error_val(9)))],
            &[("EmptyMessage", 1)],
        );
        let result = ErrorConstPass.run(&mut ir);
        assert!(!result.changed);
        assert!(matches!(op_at(&ir, 0), Expr::Literal(Literal::I64(_))));
    }

    #[test]
    fn without_declared_errors_the_pass_is_silent() {
        let mut ir = module(vec![Expr::Literal(Literal::I64(contract_error_val(1)))], &[]);
        let result = ErrorConstPass.run(&mut ir);
        assert!(!result.changed);
        assert!(matches!(op_at(&ir, 0), Expr::Literal(Literal::I64(_))));
    }

    #[test]
    fn second_run_is_idempotent() {
        let mut ir = module(
            vec![Expr::Literal(Literal::I64(contract_error_val(1)))],
            &[("EmptyMessage", 1)],
        );
        assert!(ErrorConstPass.run(&mut ir).changed);
        let second = ErrorConstPass.run(&mut ir);
        assert!(!second.changed);
        assert_eq!(second.metrics.get(M_ERROR_NAMED), None);
    }
}
