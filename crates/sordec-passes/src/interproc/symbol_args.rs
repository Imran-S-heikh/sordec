//! Decode a raw `SymbolSmall` argument where a sibling call site proves
//! the position is a symbol.
//!
//! An SDK event helper takes the event name as its first argument. The
//! guest sometimes builds it (`Symbol::new(&e, "approve")`) and sometimes
//! hands over the packed constant directly, and both reach the same
//! parameter:
//!
//! ```text
//! func33(e, symbol!("approve"), from, spender)   ← a proven Symbol
//! func33(e, 65154533130155790,  from, to)        ← the same thing, packed
//! ```
//!
//! [`crate::val_abi::decode_small_symbol`] reads the
//! second back exactly, and the pipeline already uses it — but only in a
//! position the ABI proves is a symbol
//! ([`Flavor::SymbolText`](crate::dataflow::const_prop)). A helper's
//! parameter is not such a position, so these literals stay raw, the
//! parameter's callers disagree about its type, and it settles `Unknown`:
//! emitted as a `Val` while one caller passes a `Symbol`, which is a type
//! error in both directions at once.
//!
//! ## What proves the position
//!
//! **A sibling call site.** A parameter has one type; if any caller
//! provably passes a `Symbol` there, the position is a symbol position in
//! the program as written, and a tag-14 literal at the same index is that
//! symbol. This is agreement between call sites, not a reading of the
//! literal's bits on their own — which is the part that would be a guess,
//! because a small integer can decode (`270` is `"_"`) and plenty of
//! contracts hold small integers.
//!
//! So the gate is deliberately *not* "this literal looks like a symbol".
//! Nothing is decoded on a parameter every caller passes a literal to,
//! however symbol-shaped those literals are — unless the callee proves it.
//!
//! **The callee storing it as a `Val`.** A parameter the callee writes,
//! unconverted, into the array `vec_new_from_linear_memory` reads is a raw
//! `Val`: the SDK encodes an integer before storing it, so the bits that
//! arrive are already tagged. Read as a `Val`, a tag-14 literal is a
//! `SymbolSmall` exactly — `270` there is `"_"`, not the integer 270, which
//! would have arrived encoded. token-v22's `burn` event helper takes its
//! name this way from every caller, so no sibling exists to witness it, and
//! the literal reached the vector as an `i64` and published as a number.
//!
//! ## What it does not do
//!
//! It does not touch the parameter's own type. Once the literals read as
//! symbols the call sites agree, and `type_infer`'s existing witness over
//! call sites settles it — one fact in one place rather than two.

use std::collections::{HashMap, HashSet};

use sordec_common::{FuncId, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{Expr, HighIr, IrType, KnownOp, KnownType, Literal, SemanticOp};

use crate::dataflow::resolve_use;
use crate::marshalling::sret::emission_order;
use crate::pass::{Pass, PassResult};
use crate::val_abi::decode_small_symbol;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "interproc-symbol-args";

/// Literals read back as the symbol a sibling call site proves them to be.
const M_DECODED: &str = "interproc_symbol_args_decoded";
/// Positions where a packed literal was found but no sibling proved the
/// position, so it was left raw.
const M_UNWITNESSED: &str = "interproc_symbol_args_unwitnessed";

/// Decodes packed symbol arguments witnessed by a sibling call site.
#[derive(Debug, Default, Clone, Copy)]
pub struct SymbolArgsPass;

impl Pass<HighIr> for SymbolArgsPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let witnessed = witnessed_positions(ir);
        let stored_as_val = val_positions(ir);
        // Collected over an immutable view: the rewrite is per function,
        // but the evidence spans the module.
        let mut planned: HashMap<FuncId, Vec<(ValueId, String, &'static str)>> = HashMap::new();
        for caller in &ir.functions {
            for (_, binding) in caller.bindings.iter() {
                let Expr::Call { target, args } = &binding.expr else {
                    continue;
                };
                for (index, arg) in args.iter().enumerate() {
                    let Some(text) = packed_symbol(caller, *arg) else {
                        continue;
                    };
                    let why = if witnessed.contains(&(*target, index)) {
                        "a sibling call site passes a proven `Symbol` at this parameter, so the \
                         position is a symbol"
                    } else if stored_as_val.contains(&(*target, index)) {
                        "the callee stores this parameter unconverted into a host vector, so \
                         its bits are a `Val`, and this one is tagged `SymbolSmall`"
                    } else {
                        result.metrics.increment(M_UNWITNESSED, 1);
                        continue;
                    };
                    let id = resolve_use(caller, *arg);
                    planned.entry(caller.id).or_default().push((id, text, why));
                }
            }
        }

        for func in &mut ir.functions {
            let Some(rewrites) = planned.get(&func.id) else {
                continue;
            };
            for (id, text, why) in rewrites {
                let Some(binding) = func.bindings.get_mut(*id) else {
                    continue;
                };
                // Idempotent: a literal already read as a symbol is not
                // matched by `packed_symbol`, so this cannot run twice.
                binding.expr = Expr::Literal(Literal::Symbol(text.clone()));
                binding.ty = IrType::Known(KnownType::Symbol);
                binding.add_provenance(Provenance::new(
                    PASS_NAME,
                    ProvenanceSource::SdkPattern,
                    format!("packed `SymbolSmall` read as `{text}`: {why}"),
                ));
                result.metrics.increment(M_DECODED, 1);
                result.changed = true;
            }
        }
        result
    }
}

/// `(callee, parameter index)` pairs where some call site passes a value
/// already proven to be a `Symbol`.
fn witnessed_positions(ir: &HighIr) -> HashSet<(FuncId, usize)> {
    let mut out = HashSet::new();
    for caller in &ir.functions {
        for (_, binding) in caller.bindings.iter() {
            let Expr::Call { target, args } = &binding.expr else {
                continue;
            };
            for (index, arg) in args.iter().enumerate() {
                if proven_symbol(caller, *arg) {
                    out.insert((*target, index));
                }
            }
        }
    }
    out
}

/// `(callee, parameter index)` pairs where the callee stores the parameter,
/// unconverted, as an element of a vector it builds — which makes the
/// parameter's bits a `Val`. Live bindings only: an unscheduled one is
/// residue that no longer describes the program.
fn val_positions(ir: &HighIr) -> HashSet<(FuncId, usize)> {
    let mut out = HashSet::new();
    for func in &ir.functions {
        let params: HashMap<ValueId, usize> =
            func.params.iter().enumerate().map(|(index, p)| (*p, index)).collect();
        for id in emission_order(func) {
            let Some(Expr::Semantic(SemanticOp::Known(KnownOp::VecNew {
                elements: Some(elements),
                ..
            }))) = func.bindings.get(id).map(|b| &b.expr)
            else {
                continue;
            };
            for element in elements {
                if let Some(&index) = params.get(&resolve_use(func, *element)) {
                    out.insert((func.id, index));
                }
            }
        }
    }
    out
}

/// Whether `value` is already a `Symbol` — a decoded literal, or anything
/// the pipeline typed as one.
fn proven_symbol(func: &sordec_ir::HighFunction, value: ValueId) -> bool {
    // Through the rename. An inlined wrapper leaves the recognised symbol
    // one `Use` away, and this pass runs before `type_infer` carries a
    // type across that alias — so reading the alias's own type sees
    // `Unknown` and the witness is lost.
    let Some(binding) = func.bindings.get(resolve_use(func, value)) else {
        return false;
    };
    if matches!(binding.expr, Expr::Literal(Literal::Symbol(_))) {
        return true;
    }
    matches!(
        binding.ty,
        IrType::Known(KnownType::Symbol) | IrType::Inferred(KnownType::Symbol)
    )
}

/// The symbol a raw 64-bit literal packs, when it packs one.
///
/// Only a raw literal: an already-decoded `Literal::Symbol` is not a
/// candidate (which is what makes the pass idempotent), and a value
/// computed at runtime is not a literal at all.
fn packed_symbol(func: &sordec_ir::HighFunction, value: ValueId) -> Option<String> {
    match &func.bindings.get(resolve_use(func, value))?.expr {
        Expr::Literal(Literal::I64(bits)) => decode_small_symbol(*bits as u64),
        Expr::Literal(Literal::U64(bits)) => decode_small_symbol(*bits),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};
    use sordec_common::IrId;

    /// `"transfer"` as the SDK packs it — the constant the corpus carries.
    const TRANSFER: i64 = 65_154_533_130_155_790;

    /// `func_with` hands every function id 0; a two-function module needs
    /// them distinct or a rewrite planned for one lands on the other.
    fn at(index: u32, mut func: sordec_ir::HighFunction) -> sordec_ir::HighFunction {
        func.id = FuncId::from_index(index);
        func
    }

    fn call(target: u32, args: Vec<ValueId>) -> Expr {
        Expr::Call {
            target: FuncId::from_index(target),
            args,
        }
    }

    /// One call site passes a proven `Symbol`, another the packed
    /// constant. The position is a symbol position, so the constant reads
    /// back as one.
    #[test]
    fn a_sibling_call_site_proves_the_position() {
        let caller = func_with(
            vec![
                Expr::Literal(Literal::Symbol("approve".into())), // v0
                call(1, vec![v(0)]),                              // v1
                Expr::Literal(Literal::I64(TRANSFER)),            // v2
                call(1, vec![v(2)]),                              // v3
            ],
            vec![],
            (0..4).collect(),
        );
        let callee = at(1, func_with(vec![Expr::Phi { incoming: vec![] }], vec![v(0)], vec![0]));
        let mut ir = module(vec![caller, callee]);

        assert!(SymbolArgsPass.run(&mut ir).changed, "the position is witnessed");
        let f = ir.functions.first().expect("the caller");
        assert!(
            matches!(
                &f.bindings.get(v(2)).expect("the constant").expr,
                Expr::Literal(Literal::Symbol(s)) if s == "transfer"
            ),
            "read back as its symbol, got {:?}",
            f.bindings.get(v(2)).map(|b| &b.expr)
        );
    }

    /// The half that matters. With no sibling proving the position, a
    /// symbol-shaped literal is just an integer — `270` decodes to `"_"`,
    /// and contracts hold small integers.
    #[test]
    fn an_unwitnessed_position_is_left_raw() {
        let caller = func_with(
            vec![
                Expr::Literal(Literal::I64(TRANSFER)), // v0
                call(1, vec![v(0)]),                   // v1
            ],
            vec![],
            (0..2).collect(),
        );
        let callee = at(1, func_with(vec![Expr::Phi { incoming: vec![] }], vec![v(0)], vec![0]));
        let mut ir = module(vec![caller, callee]);

        let result = SymbolArgsPass.run(&mut ir);
        assert!(!result.changed, "nothing proves this is a symbol");
        assert_eq!(result.metrics.get(M_UNWITNESSED), Some(1), "and it says so");
    }

    /// No sibling at all — every caller passes the literal — but the callee
    /// stores the parameter unconverted into the vector it builds, which
    /// makes its bits a `Val`. token-v22's `burn` event helper.
    #[test]
    fn a_parameter_stored_into_a_vector_is_a_val() {
        let caller = func_with(
            vec![
                Expr::Literal(Literal::I64(TRANSFER)), // v0
                call(1, vec![v(0)]),                   // v1
            ],
            vec![],
            (0..2).collect(),
        );
        let callee = at(
            1,
            func_with(
                vec![
                    Expr::Phi { incoming: vec![] }, // v0, the parameter
                    Expr::Literal(Literal::I32(16)), // v1
                    Expr::Literal(Literal::I32(1)),  // v2
                    Expr::Semantic(SemanticOp::Known(KnownOp::VecNew {
                        vals_pos: v(1),
                        len: v(2),
                        elements: Some(vec![v(0)]),
                    })), // v3
                ],
                vec![v(0)],
                (0..4).collect(),
            ),
        );
        let mut ir = module(vec![caller, callee]);

        assert!(SymbolArgsPass.run(&mut ir).changed, "the callee proves the position");
        let f = ir.functions.first().expect("the caller");
        assert!(
            matches!(
                &f.bindings.get(v(0)).expect("the constant").expr,
                Expr::Literal(Literal::Symbol(s)) if s == "transfer"
            ),
            "read back as its symbol, got {:?}",
            f.bindings.get(v(0)).map(|b| &b.expr)
        );
    }

    /// A second run finds nothing: the decoded literal is no longer a
    /// candidate.
    #[test]
    fn the_pass_is_idempotent() {
        let caller = func_with(
            vec![
                Expr::Literal(Literal::Symbol("approve".into())),
                call(1, vec![v(0)]),
                Expr::Literal(Literal::I64(TRANSFER)),
                call(1, vec![v(2)]),
            ],
            vec![],
            (0..4).collect(),
        );
        let callee = at(1, func_with(vec![Expr::Phi { incoming: vec![] }], vec![v(0)], vec![0]));
        let mut ir = module(vec![caller, callee]);
        assert!(SymbolArgsPass.run(&mut ir).changed);
        assert!(!SymbolArgsPass.run(&mut ir).changed);
    }
}
