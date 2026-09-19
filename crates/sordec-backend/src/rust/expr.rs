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
use sordec_ir::{BinaryOp, Binding, Expr, HighIr, IrType, KnownType, Literal, SemanticOp, UnaryOp};
use syn::parse_quote;

use crate::rust::body::FnCtx;
use crate::rust::{idiom, sig, ty};
use crate::wat::annotate;

/// `Owner::Variant`, when this value is a named variant of a type the
/// registry can name.
fn variant_path(ctx: &FnCtx, value: sordec_common::ValueId) -> Option<syn::Path> {
    let binding = ctx.func.bindings.get(ctx.fold_target(value))?;
    let Expr::Variant { name } = &binding.expr else {
        return None;
    };
    let owner = match &binding.ty {
        IrType::Known(KnownType::UserDefined(id)) | IrType::Inferred(KnownType::UserDefined(id)) => {
            ctx.reg.name_of(*id)?
        }
        _ => return None,
    };
    let owner = ty::ident(owner);
    let variant = ty::ident(name);
    Some(parse_quote!(#owner::#variant))
}

/// `value` as a suffix-free integer literal, when it is an integer
/// constant and `against` carries a known integer type to infer from.
fn unsuffixed(ctx: &FnCtx, value: sordec_common::ValueId, against: sordec_common::ValueId) -> Option<syn::Expr> {
    let other = ctx.func.bindings.get(ctx.fold_target(against))?;
    if !matches!(
        other.ty,
        IrType::Known(
            KnownType::I32 | KnownType::I64 | KnownType::U32 | KnownType::U64 | KnownType::U128 | KnownType::I128
        ) | IrType::Inferred(
            KnownType::I32 | KnownType::I64 | KnownType::U32 | KnownType::U64 | KnownType::U128 | KnownType::I128
        )
    ) {
        return None;
    }
    let binding = ctx.func.bindings.get(ctx.fold_target(value))?;
    let n: i128 = match &binding.expr {
        Expr::Literal(Literal::I32(n)) => i128::from(*n),
        Expr::Literal(Literal::I64(n)) => i128::from(*n),
        Expr::Literal(Literal::U32(n)) => i128::from(*n),
        Expr::Literal(Literal::U64(n)) => i128::from(*n),
        _ => return None,
    };
    // Only when the constant actually fits the type it would take. A
    // value that does not fit is evidence the two sides disagree about
    // what they hold — an encoded `Val` against a decoded bound, say —
    // and dropping the suffix would turn a type error into a range error
    // without making either side more true.
    let fits = match base_of(&other.ty) {
        Some(KnownType::I32) => i32::try_from(n).is_ok(),
        Some(KnownType::U32) => u32::try_from(n).is_ok(),
        Some(KnownType::I64) => i64::try_from(n).is_ok(),
        Some(KnownType::U64) => u64::try_from(n).is_ok(),
        _ => true,
    };
    if !fits {
        return None;
    }
    let lit = proc_macro2::Literal::i128_unsuffixed(n);
    let rendered: syn::Expr = parse_quote!(#lit);
    Some(if n < 0 { parse_quote!((#rendered)) } else { rendered })
}

/// The `KnownType` behind a type, whatever its certainty.
fn base_of(ty: &IrType) -> Option<KnownType> {
    match ty {
        IrType::Known(k) | IrType::Inferred(k) => Some(k.clone()),
        IrType::Unknown(_) => None,
    }
}

/// The index-of chain being tested for absence, when one side is such a
/// lookup and the other is the `Void` tag the host returns for "no match".
fn index_of_absence(
    ctx: &FnCtx,
    lhs: sordec_common::ValueId,
    rhs: sordec_common::ValueId,
) -> Option<syn::Expr> {
    const TAG_VOID: i128 = 2;
    [(lhs, rhs), (rhs, lhs)].into_iter().find_map(|(lookup, tag)| {
        let marker = ctx.func.bindings.get(ctx.fold_target(tag))?;
        let n = match &marker.expr {
            Expr::Literal(Literal::I32(n)) => i128::from(*n),
            Expr::Literal(Literal::I64(n)) => i128::from(*n),
            Expr::Literal(Literal::U32(n)) => i128::from(*n),
            Expr::Literal(Literal::U64(n)) => i128::from(*n),
            _ => return None,
        };
        (n == TAG_VOID).then_some(())?;
        let binding = ctx.func.bindings.get(ctx.fold_target(lookup))?;
        matches!(
            &binding.expr,
            Expr::Semantic(SemanticOp::Known(sordec_ir::KnownOp::VecOp {
                kind: sordec_ir::VecOpKind::FirstIndexOf | sordec_ir::VecOpKind::LastIndexOf,
                ..
            }))
        )
        .then(|| ctx.value_ref(lookup))
    })
}

/// The right-hand side expression for one binding.
pub(crate) fn binding_expr(ctx: &FnCtx, binding: &Binding) -> syn::Expr {
    match &binding.expr {
        Expr::Literal(lit) => literal_expr(ctx, lit, &binding.ty),
        Expr::Use(v) => ctx.value_ref(*v),
        Expr::Unary { op: op @ (UnaryOp::Wrap32 | UnaryOp::ExtendU32 | UnaryOp::ExtendS32), value } => {
            width_move(*op, ctx.value_ref(*value), &binding.ty)
        }
        Expr::Unary { op, value } => {
            unary_expr(*op, ctx.value_ref(*value), ctx.is_boolean(*value))
        }
        // An index-of result tested against `Tag::Void` is the SDK's own
        // "not found": the host returns Void when the element is absent,
        // and the SDK turns that into `None`. This is how `Vec::contains`
        // and friends compile.
        Expr::Binary { op: op @ (BinaryOp::Eq | BinaryOp::Ne), lhs, rhs }
            if index_of_absence(ctx, *lhs, *rhs).is_some() =>
        {
            let found = index_of_absence(ctx, *lhs, *rhs).expect("checked by the guard");
            match op {
                BinaryOp::Eq => parse_quote!(#found.is_none()),
                _ => parse_quote!(#found.is_some()),
            }
        }
        Expr::Binary { op, lhs, rhs } => {
            // A constant compared against a typed operand prints without
            // its suffix and takes the type from the comparison, which is
            // where Rust gets it too. The lowering has to pick a
            // signedness to record a `i64.const`'s bits; against a `u64`
            // that choice would not compile, and it was never a claim
            // about the value.
            let (l, r) = match op {
                BinaryOp::Eq | BinaryOp::Ne | BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt
                | BinaryOp::Ge => (unsuffixed(ctx, *lhs, *rhs), unsuffixed(ctx, *rhs, *lhs)),
                _ => (None, None),
            };
            binary_expr(
                *op,
                l.unwrap_or_else(|| ctx.value_ref(*lhs)),
                r.unwrap_or_else(|| ctx.value_ref(*rhs)),
            )
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
        // A component of a multi-value return, rendered `v.N`. The
        // producer is a call whose emitted signature is a tuple, so the
        // index is a real Rust field access.
        Expr::Project { value, index } => {
            let base = ctx.value_ref(*value);
            let field = syn::Index::from(*index as usize);
            parse_quote!(#base.#field)
        }
        // Two limbs read as one 128-bit integer. This spelling is the
        // fallback for a join the fold pass could not cancel against its
        // own limbs; the sign of the high limb is what the shift-and-or
        // preserves, and the low limb is masked through `u64` so its sign
        // bit does not smear into the high half.
        Expr::WideJoin { lo, hi } => {
            let lo = ctx.value_ref(*lo);
            let hi = ctx.value_ref(*hi);
            let wide = wide_type(&binding.ty);
            parse_quote!((((#hi as #wide) << 64) | (#lo as u64 as #wide)))
        }
        Expr::Field { base, field } => {
            let base = ctx.value_ref(*base);
            let field = ty::ident(field);
            parse_quote!(#base.#field)
        }
        // The construction side: `Name { field: value, .. }`. The struct is
        // named by the binding's type, so a value whose type the registry
        // cannot name has no literal to print.
        Expr::Struct { fields } => {
            let name = match &binding.ty {
                IrType::Known(KnownType::UserDefined(id)) | IrType::Inferred(KnownType::UserDefined(id)) => {
                    ctx.reg.name_of(*id)
                }
                _ => None,
            };
            match name {
                Some(name) => {
                    let path = ty::ident(name);
                    let items: Vec<syn::FieldValue> = fields
                        .iter()
                        .map(|(field, value)| {
                            let field = ty::ident(field);
                            let value = ctx.value_ref(*value);
                            parse_quote!(#field: #value)
                        })
                        .collect();
                    parse_quote!(#path { #(#items),* })
                }
                None => ctx.policy.unknown_expr("struct literal of an unnamed type"),
            }
        }
        // `Name::Variant`, the enum named by the binding's type.
        Expr::Variant { name: _ } => match variant_path(ctx, binding.id) {
            Some(path) => parse_quote!(#path),
            None => ctx.policy.unknown_expr("variant of an unnamed type"),
        },
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

/// An integer literal's Rust suffix, taken from the type the pipeline
/// *recovered* for the binding rather than from the WASM opcode that
/// produced it.
///
/// WASM has no signed/unsigned distinction in its value types — `i64`
/// there means "64 bits", and the signedness lives in the *operators*.
/// So the `Literal` variant records how the constant was encoded, not
/// what the source called it, and emitting its suffix verbatim makes
/// every constant compared against a recovered `u64` a type error
/// (`v21 > 72057594037927935i64` where `v21: u64`).
///
/// The recovered type is the better answer whenever there is one, and
/// reinterpreting is lossless: the cast preserves the bit pattern, which
/// is exactly what the original WASM compared.
fn int_literal(n: i128, ty: &IrType) -> Option<syn::Expr> {
    let known = match ty {
        IrType::Known(k) | IrType::Inferred(k) => k,
        IrType::Unknown(_) => return None,
    };
    Some(match known {
        KnownType::U32 => {
            let v = n as u32;
            parse_quote!(#v)
        }
        KnownType::I32 => {
            let v = n as i32;
            parse_quote!(#v)
        }
        KnownType::U64 => {
            let v = n as u64;
            parse_quote!(#v)
        }
        KnownType::I64 => {
            let v = n as i64;
            parse_quote!(#v)
        }
        // A constant compared against or combined with a recovered wide
        // value: the wasm carried one limb, the source wrote the whole
        // number, and a small constant's other limb is its sign extension.
        KnownType::I128 => {
            parse_quote!(#n)
        }
        KnownType::U128 => {
            let v = n as u128;
            parse_quote!(#v)
        }
        // Everything else is either not an integer or not something a raw
        // WASM constant can stand in for (`Address` is a handle). Fall
        // back to the encoded form.
        _ => return None,
    })
}

/// A literal binding printed where it is read. A negative number is
/// parenthesised: the renderer applies methods and casts to operands, and
/// `-5i64.checked_mul(x)` is `-(5i64.checked_mul(x))`.
pub(crate) fn literal_ref(ctx: &FnCtx, binding: &Binding) -> syn::Expr {
    let Expr::Literal(lit) = &binding.expr else {
        return ctx.policy.unknown_expr("literal");
    };
    let rendered = literal_expr(ctx, lit, &binding.ty);
    // Judged on what prints: the recovered type may reinterpret the bits.
    let negative = quote::ToTokens::to_token_stream(&rendered).to_string().starts_with('-');
    if negative { parse_quote!((#rendered)) } else { rendered }
}

fn literal_expr(ctx: &FnCtx, lit: &Literal, ty: &IrType) -> syn::Expr {
    match lit {
        Literal::I32(n) => {
            let n = *n;
            int_literal(i128::from(n), ty).unwrap_or_else(|| parse_quote!(#n))
        }
        Literal::I64(n) => {
            let n = *n;
            int_literal(i128::from(n), ty).unwrap_or_else(|| parse_quote!(#n))
        }
        Literal::U32(n) => {
            let n = *n;
            int_literal(i128::from(n), ty).unwrap_or_else(|| parse_quote!(#n))
        }
        Literal::U64(n) => {
            let n = *n;
            int_literal(i128::from(n), ty).unwrap_or_else(|| parse_quote!(#n))
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
        // A *small* symbol needs no `Env`: `symbol_short!` is a const macro
        // that packs up to nine characters of `[_0-9A-Za-z]` into the Val's
        // bits at compile time, which is exactly the encoding the recovered
        // literal came from. Anything outside that — longer, or a character
        // the small alphabet cannot hold — really does need
        // `Symbol::new(&env, …)` and stays a hole until an `Env` is in
        // scope to hand it.
        Literal::Symbol(s) if is_small_symbol(s) => {
            let lit = syn::LitStr::new(s, proc_macro2::Span::call_site());
            parse_quote!(soroban_sdk::symbol_short!(#lit))
        }
        Literal::Symbol(s) => ctx.policy.unknown_expr(&format!("Symbol {s:?}")),
        Literal::String(s) => ctx.policy.unknown_expr(&format!("String {s:?}")),
        Literal::Bytes(_) => ctx.policy.unknown_expr("Bytes literal"),
    }
}

/// Whether a symbol fits soroban's *small* encoding, which
/// `symbol_short!` can build with no `Env`.
///
/// The SDK packs each character into six bits and reserves the low eight
/// for the tag, leaving room for nine. The alphabet is exactly
/// `[_0-9A-Za-z]` — the encoder maps `_` to 1, digits to 2..=11, uppercase
/// to 12..=37 and lowercase to 38..=63, and has no code for anything else.
///
/// Both halves matter: a tenth character overflows the payload, and a
/// character outside the alphabet is what makes the SDK fall back to
/// building a heap `SymbolObject` through the host instead.
fn is_small_symbol(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 9
        && s.bytes().all(|b| b == b'_' || b.is_ascii_alphanumeric())
}

fn unary_expr(op: UnaryOp, v: syn::Expr, operand_is_bool: bool) -> syn::Expr {
    match op {
        UnaryOp::Neg => parse_quote!(-#v),
        // Rust `!` is both logical and bitwise not; the operand type picks.
        UnaryOp::Not | UnaryOp::BitNot => parse_quote!(!#v),
        // One wasm opcode, two Rust operators. `!` is the right spelling
        // only for a boolean — on an integer Rust's `!` is the bitwise
        // complement, a different value — so an unproven type takes the
        // literal reading, which is what `eqz` means on a wasm value type.
        UnaryOp::Eqz if operand_is_bool => parse_quote!(!#v),
        UnaryOp::Eqz => parse_quote!(#v == 0),
        UnaryOp::Clz => parse_quote!(#v.leading_zeros()),
        UnaryOp::Ctz => parse_quote!(#v.trailing_zeros()),
        UnaryOp::Popcnt => parse_quote!(#v.count_ones()),
        UnaryOp::Abs => parse_quote!(#v.abs()),
        UnaryOp::Sqrt => parse_quote!(#v.sqrt()),
        UnaryOp::Floor => parse_quote!(#v.floor()),
        UnaryOp::Ceil => parse_quote!(#v.ceil()),
        UnaryOp::Trunc => parse_quote!(#v.trunc()),
        // Limbs of a 128-bit value: `as i64` truncates to the low word,
        // and the arithmetic shift brings the high word down with its sign.
        UnaryOp::WideLo => parse_quote!((#v as i64)),
        UnaryOp::WideHi => parse_quote!(((#v >> 64) as i64)),
        // Width moves, spelled by what they do to the bits; the operand's
        // own Rust type does not matter to either cast chain.
        UnaryOp::Wrap32 => parse_quote!((#v as i32)),
        UnaryOp::ExtendU32 => parse_quote!((#v as u32 as i64)),
        UnaryOp::ExtendS32 => parse_quote!((#v as i32 as i64)),
    }
}

/// A width move rendered at the type the pipeline recovered for its
/// result: the low half of a `u64` reads as `u32`, a zero-extended `u32`
/// as `u64`. The cast chain fixes the bits whatever the operand's Rust type.
fn width_move(op: UnaryOp, v: syn::Expr, ty: &IrType) -> syn::Expr {
    let unsigned = |k: KnownType| matches!(ty, IrType::Known(t) | IrType::Inferred(t) if *t == k);
    match op {
        UnaryOp::Wrap32 if unsigned(KnownType::U32) => parse_quote!((#v as u32)),
        UnaryOp::ExtendU32 if unsigned(KnownType::U64) => parse_quote!((#v as u32 as u64)),
        UnaryOp::ExtendS32 if unsigned(KnownType::U64) => parse_quote!((#v as i32 as i64 as u64)),
        other => unary_expr(other, v, false),
    }
}

/// The Rust spelling of a wide binding's type: `u128` when the pipeline
/// proved or inferred it, `i128` otherwise — Soroban's amounts are signed,
/// so that is the default the join is typed with too.
fn wide_type(ty: &IrType) -> syn::Type {
    match ty {
        IrType::Known(KnownType::U128) | IrType::Inferred(KnownType::U128) => parse_quote!(u128),
        _ => parse_quote!(i128),
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
        BinaryOp::MulOverflows => parse_quote!(#l.checked_mul(#r).is_none()),
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
            render(&unary_expr(UnaryOp::Clz, parse_quote!(x), false)),
            render(&syn::parse_str::<syn::Expr>("x.leading_zeros()").unwrap()),
        );
    }

    #[test]
    fn unary_neg_and_not_render_as_operators() {
        assert_eq!(render(&unary_expr(UnaryOp::Neg, parse_quote!(x), false)), render(&parse_quote!(-x)));
        assert_eq!(render(&unary_expr(UnaryOp::Not, parse_quote!(x), true)), render(&parse_quote!(!x)));
    }

    #[test]
    fn eqz_renders_by_the_operand_type() {
        // One wasm opcode, two Rust operators. Getting this backwards is
        // not a style slip: Rust's `!` on an integer is the bitwise
        // complement, so `!n` and `n == 0` are different values.
        assert_eq!(
            render(&unary_expr(UnaryOp::Eqz, parse_quote!(flag), true)),
            render(&parse_quote!(!flag)),
            "a boolean operand is a logical negation"
        );
        assert_eq!(
            render(&unary_expr(UnaryOp::Eqz, parse_quote!(n), false)),
            render(&syn::parse_str::<syn::Expr>("n == 0").unwrap()),
            "an integer operand is a comparison against zero"
        );
    }
}
