//! Drop a narrowing of a value that is already 32 bits wide.
//!
//! A `u32` spends its life in a 64-bit wasm register, so the code that
//! uses it narrows it first: `i32.wrap_i64`. Once the pipeline has named
//! the value — a typed storage read, a decoded `u32` argument — the
//! narrowing is a cast of a `u32` to its own width:
//!
//! ```text
//! let counter = e.storage().persistent().get(&key);   // u32
//! let v34 = (counter as u32);                    →    (gone; `counter`)
//! ```
//!
//! The low 32 bits of a register holding a 32-bit value are that value, so
//! the narrowing is replaced by the value itself. Only a value whose type a
//! pass proved or inferred as `u32` or `i32` qualifies; an untyped one may
//! be a genuine 64-bit quantity.

use sordec_common::{Provenance, ProvenanceSource};
use sordec_ir::{Expr, HighIr, IrType, KnownType, UnaryOp};

use crate::dataflow::resolve_use;
use crate::metrics_catalog::REFINE_WIDTH_FOLDS as M_FOLDED;
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "refine-width-fold";

/// Replaces narrowings of 32-bit values with the values.
#[derive(Debug, Default, Clone, Copy)]
pub struct WidthFoldPass;

impl Pass<HighIr> for WidthFoldPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            let folds: Vec<_> = func
                .bindings
                .iter()
                .filter_map(|(id, b)| {
                    let Expr::Unary { op: UnaryOp::Wrap32, value } = &b.expr else {
                        return None;
                    };
                    // The operand or what it renames: a decode collapsed to
                    // a parameter carries the parameter's declared type
                    // before type inference has reached the parameter.
                    let narrow = |v: sordec_common::ValueId| {
                        func.bindings.get(v).map(|b| b.ty.clone()).filter(|ty| {
                            matches!(
                                ty,
                                IrType::Known(KnownType::U32 | KnownType::I32)
                                    | IrType::Inferred(KnownType::U32 | KnownType::I32)
                            )
                        })
                    };
                    let target = resolve_use(func, *value);
                    let ty = narrow(*value).or_else(|| narrow(target))?;
                    Some((id, target, ty))
                })
                .collect();
            for (id, value, ty) in folds {
                if let Some(b) = func.bindings.get_mut(id) {
                    b.expr = Expr::Use(value);
                    b.ty = ty;
                    b.add_provenance(Provenance::new(
                        PASS_NAME,
                        ProvenanceSource::DataFlow,
                        "narrowing of a value already 32 bits wide: the value",
                    ));
                    result.metrics.increment(M_FOLDED, 1);
                    result.changed = true;
                }
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};

    fn shape(ty: IrType) -> HighIr {
        let mut f = func_with(
            vec![Expr::Phi { incoming: vec![] }, Expr::Unary { op: UnaryOp::Wrap32, value: v(0) }],
            vec![v(0)],
            vec![1],
        );
        f.bindings.get_mut(v(0)).unwrap().ty = ty;
        module(vec![f])
    }

    #[test]
    fn narrowing_a_u32_is_the_u32() {
        let mut m = shape(IrType::Known(KnownType::U32));
        assert!(WidthFoldPass.run(&mut m).changed);
        assert!(matches!(m.functions[0].bindings.get(v(1)).unwrap().expr, Expr::Use(x) if x == v(0)));
    }

    /// A 64-bit value's low half is not the value.
    #[test]
    fn narrowing_a_wide_value_stays() {
        let mut m = shape(IrType::Known(KnownType::I64));
        assert!(!WidthFoldPass.run(&mut m).changed);
    }
}
