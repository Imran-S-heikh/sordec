//! Expression emission: one [`Binding`]'s [`Expr`] → a `syn::Expr`.
//!
//! ANF means every operand is an atomic value reference (a parameter name
//! or `vN`), so binary/unary expressions need no parenthesisation. The
//! fully-recovered arithmetic/logic/call forms render as real Rust;
//! everything whose source-level idiom is not yet materialised — host
//! calls, raw memory, globals, indirect calls, unrecovered ops — routes
//! through the [`HolePolicy`] as a `todo!("…")` hole (a later wave
//! replaces these with method chains).

use sordec_common::{FuncId, IrId};
use sordec_ir::{BinaryOp, Binding, Expr, HighIr, Literal, SemanticOp, UnaryOp};
use syn::parse_quote;

use crate::rust::body::FnCtx;
use crate::rust::{idiom, sig, ty};
use crate::wat::annotate;

/// The right-hand side expression for one binding.
pub(crate) fn binding_expr(ctx: &FnCtx, binding: &Binding) -> syn::Expr {
    match &binding.expr {
        Expr::Literal(lit) => literal_expr(ctx, lit),
        Expr::Use(v) => ctx.value_ref(*v),
        Expr::Unary { op, value } => unary_expr(*op, ctx.value_ref(*value)),
        Expr::Binary { op, lhs, rhs } => {
            binary_expr(*op, ctx.value_ref(*lhs), ctx.value_ref(*rhs))
        }
        Expr::Call { target, args } => {
            let path = callee_path(ctx.high, *target);
            // Every emitted function takes `Env` as its leading parameter,
            // so every internal call threads it as the first argument.
            let env = ctx.env();
            let a: Vec<syn::Expr> = args.iter().map(|v| ctx.value_ref(*v)).collect();
            parse_quote!(#path(#env, #(#a),*))
        }
        // A recovered Soroban op renders as its idiomatic method chain when
        // the idiom table can build one honestly; otherwise it is a labeled
        // hole (an unmapped op, or an `Unknown` storage tier).
        Expr::Semantic(SemanticOp::Known(known)) => idiom::known_op_expr(ctx, known)
            .unwrap_or_else(|| ctx.policy.unknown_expr(&annotate::label_known_op(known))),
        Expr::Semantic(op @ SemanticOp::Unknown { .. }) => {
            ctx.policy.unknown_expr(&semantic_label(op))
        }
        Expr::Load { .. } => ctx.policy.unknown_expr("memory load"),
        Expr::Store { .. } => ctx.policy.unknown_expr("memory store"),
        Expr::GlobalGet { index } => ctx.policy.unknown_expr(&format!("global.get {index}")),
        Expr::IndirectCall { .. } => ctx.policy.unknown_expr("indirect call"),
        // A phi never reaches here (phis are `let mut` declarations, not
        // scheduled bindings); handled honestly if the invariant slips.
        Expr::Phi { .. } => ctx.policy.unknown_expr("phi"),
        Expr::Unknown { op_kind, .. } => {
            ctx.policy.unknown_expr(&format!("unrecovered {op_kind:?}"))
        }
    }
}

/// The call path for a target function: a `contractspecv0` function is a
/// method on `Contract`; an internal helper is a free function. Shares
/// `sig`'s naming so call sites match the emitted definitions.
fn callee_path(high: &HighIr, target: FuncId) -> syn::Path {
    match high.function(target) {
        Some(f) => match &f.signature {
            Some(spec) => {
                let m = ty::ident(&spec.name);
                parse_quote!(Contract::#m)
            }
            None => {
                let n = sig::helper_name(f);
                parse_quote!(#n)
            }
        },
        None => {
            let n = ty::ident(&format!("func{}", target.index()));
            parse_quote!(#n)
        }
    }
}

/// A short label for a recovered/unrecovered host operation, reusing the
/// WAT annotator's vocabulary so the two outputs describe an op the same way.
fn semantic_label(op: &SemanticOp) -> String {
    match op {
        SemanticOp::Known(known) => annotate::label_known_op(known),
        SemanticOp::Unknown {
            host_module,
            host_fn,
            ..
        } => format!("{host_module}::{host_fn}"),
    }
}

fn literal_expr(ctx: &FnCtx, lit: &Literal) -> syn::Expr {
    match lit {
        Literal::I32(n) => {
            let n = *n;
            parse_quote!(#n)
        }
        Literal::I64(n) => {
            let n = *n;
            parse_quote!(#n)
        }
        Literal::U32(n) => {
            let n = *n;
            parse_quote!(#n)
        }
        Literal::U64(n) => {
            let n = *n;
            parse_quote!(#n)
        }
        Literal::Bool(b) => {
            if *b {
                parse_quote!(true)
            } else {
                parse_quote!(false)
            }
        }
        Literal::Unit => parse_quote!(()),
        // Soroban forbids floats in contracts, so these should not occur;
        // hole them rather than risk a non-finite token.
        Literal::F32(_) | Literal::F64(_) => ctx.policy.unknown_expr("float literal"),
        // Symbol/String/Bytes construction needs the `Env`; recovered as a
        // host idiom in a later wave.
        Literal::Symbol(s) => ctx.policy.unknown_expr(&format!("Symbol {s:?}")),
        Literal::String(s) => ctx.policy.unknown_expr(&format!("String {s:?}")),
        Literal::Bytes(_) => ctx.policy.unknown_expr("Bytes literal"),
    }
}

fn unary_expr(op: UnaryOp, v: syn::Expr) -> syn::Expr {
    match op {
        UnaryOp::Neg => parse_quote!(-#v),
        // Rust `!` is both logical and bitwise not; the operand type picks.
        UnaryOp::Not | UnaryOp::BitNot => parse_quote!(!#v),
        UnaryOp::Clz => parse_quote!(#v.leading_zeros()),
        UnaryOp::Ctz => parse_quote!(#v.trailing_zeros()),
        UnaryOp::Popcnt => parse_quote!(#v.count_ones()),
        UnaryOp::Abs => parse_quote!(#v.abs()),
        UnaryOp::Sqrt => parse_quote!(#v.sqrt()),
        UnaryOp::Floor => parse_quote!(#v.floor()),
        UnaryOp::Ceil => parse_quote!(#v.ceil()),
        UnaryOp::Trunc => parse_quote!(#v.trunc()),
    }
}

fn binary_expr(op: BinaryOp, l: syn::Expr, r: syn::Expr) -> syn::Expr {
    match op {
        BinaryOp::Add => parse_quote!(#l + #r),
        BinaryOp::Sub => parse_quote!(#l - #r),
        BinaryOp::Mul => parse_quote!(#l * #r),
        BinaryOp::Div => parse_quote!(#l / #r),
        BinaryOp::Rem => parse_quote!(#l % #r),
        BinaryOp::BitAnd => parse_quote!(#l & #r),
        BinaryOp::BitOr => parse_quote!(#l | #r),
        BinaryOp::BitXor => parse_quote!(#l ^ #r),
        BinaryOp::Shl => parse_quote!(#l << #r),
        BinaryOp::Shr => parse_quote!(#l >> #r),
        BinaryOp::Rotl => parse_quote!(#l.rotate_left(#r)),
        BinaryOp::Rotr => parse_quote!(#l.rotate_right(#r)),
        BinaryOp::Eq => parse_quote!(#l == #r),
        BinaryOp::Ne => parse_quote!(#l != #r),
        BinaryOp::Lt => parse_quote!(#l < #r),
        BinaryOp::Le => parse_quote!(#l <= #r),
        BinaryOp::Gt => parse_quote!(#l > #r),
        BinaryOp::Ge => parse_quote!(#l >= #r),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quote::ToTokens;

    fn render(e: &syn::Expr) -> String {
        e.to_token_stream().to_string()
    }

    #[test]
    fn binary_ops_render_as_operators() {
        // Compare through the same renderer so token spacing is normalised.
        let cases = [
            (BinaryOp::Add, "a + b"),
            (BinaryOp::Rem, "a % b"),
            (BinaryOp::BitXor, "a ^ b"),
            (BinaryOp::Shl, "a << b"),
            (BinaryOp::Eq, "a == b"),
            (BinaryOp::Ge, "a >= b"),
        ];
        for (op, expected) in cases {
            let got = binary_expr(op, parse_quote!(a), parse_quote!(b));
            let want: syn::Expr = syn::parse_str(expected).unwrap();
            assert_eq!(render(&got), render(&want), "{op:?}");
        }
    }

    #[test]
    fn rotate_and_bitcount_render_as_methods() {
        assert_eq!(
            render(&binary_expr(BinaryOp::Rotl, parse_quote!(a), parse_quote!(b))),
            render(&syn::parse_str::<syn::Expr>("a.rotate_left(b)").unwrap()),
        );
        assert_eq!(
            render(&unary_expr(UnaryOp::Clz, parse_quote!(x))),
            render(&syn::parse_str::<syn::Expr>("x.leading_zeros()").unwrap()),
        );
    }

    #[test]
    fn unary_neg_and_not_render_as_operators() {
        assert_eq!(render(&unary_expr(UnaryOp::Neg, parse_quote!(x))), render(&parse_quote!(-x)));
        assert_eq!(render(&unary_expr(UnaryOp::Not, parse_quote!(x))), render(&parse_quote!(!x)));
    }
}
