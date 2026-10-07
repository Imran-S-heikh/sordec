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
    unsuffixed_against(ctx, value, &other.ty)
}

/// An integer handed to a parameter of the same width and the other
/// signedness, cast. Wasm integers carry no sign — a frame address is an
/// `i32` to the arithmetic that made it and a `u32` to the host call it
/// feeds — so the cast keeps every bit, and only Rust needed it written.
pub(crate) fn sign_cast(ctx: &FnCtx, v: sordec_common::ValueId, want: &IrType) -> Option<syn::Expr> {
    let width = |k: &KnownType| match k {
        KnownType::I32 | KnownType::U32 => Some(32),
        KnownType::I64 | KnownType::U64 => Some(64),
        _ => None,
    };
    let (IrType::Known(to) | IrType::Inferred(to)) = want else { return None };
    let b = ctx.func.bindings.get(ctx.fold_target(v))?;
    // An untyped narrowing is still an `i32`: it is printed `as i32`.
    let narrowed = KnownType::I32;
    let from = match (&b.ty, &b.expr) {
        (IrType::Known(k) | IrType::Inferred(k), _) => k,
        (IrType::Unknown(_), Expr::Unary { op: sordec_ir::UnaryOp::Wrap32, .. }) => &narrowed,
        _ => return None,
    };
    if from == to || width(from)? != width(to)? {
        return None;
    }
    let x = ctx.value_ref(v);
    let ty = crate::rust::ty::ir_type(want, ctx.reg, ctx.policy);
    Some(parse_quote!((#x as #ty)))
}

/// A `bool` assigned where an integer goes: it is `0` or `1` in the wasm,
/// which is what the cast yields.
pub(crate) fn bool_to_int(ctx: &FnCtx, v: sordec_common::ValueId, want: &IrType) -> Option<syn::Expr> {
    let (IrType::Known(to) | IrType::Inferred(to)) = want else { return None };
    if !matches!(to, KnownType::I32 | KnownType::U32 | KnownType::I64 | KnownType::U64) {
        return None;
    }
    if !bool_like(ctx, ctx.fold_target(v), 0) {
        return None;
    }
    let x = ctx.value_ref(v);
    let ty = crate::rust::ty::ir_type(want, ctx.reg, ctx.policy);
    Some(parse_quote!((#x as #ty)))
}

/// A `bool` by type, or by construction: a comparison, or a bitwise
/// combination of `bool`s — whatever it has been typed.
fn bool_like(ctx: &FnCtx, v: sordec_common::ValueId, depth: u32) -> bool {
    if ctx.is_boolean(v) {
        return true;
    }
    if depth > 4 {
        return false;
    }
    match ctx.func.bindings.get(v).map(|b| &b.expr) {
        Some(Expr::Binary { op, lhs, rhs }) => match op {
            BinaryOp::Eq | BinaryOp::Ne | BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => true,
            BinaryOp::BitAnd | BinaryOp::BitOr | BinaryOp::BitXor => {
                bool_like(ctx, ctx.fold_target(*lhs), depth + 1) && bool_like(ctx, ctx.fold_target(*rhs), depth + 1)
            }
            _ => false,
        },
        Some(Expr::Unary { op: sordec_ir::UnaryOp::Eqz, .. }) => true,
        _ => false,
    }
}

/// A negative constant compared for equality with an unsigned value,
/// written as the unsigned number with the same bits.
fn same_bits(ctx: &FnCtx, value: sordec_common::ValueId, against: sordec_common::ValueId) -> Option<syn::Expr> {
    let other = ctx.func.bindings.get(ctx.fold_target(against))?;
    let binding = ctx.func.bindings.get(ctx.fold_target(value))?;
    let unsigned = match &other.ty {
        IrType::Known(k) | IrType::Inferred(k) => k.clone(),
        IrType::Unknown(_) => return None,
    };
    let lit = match (&binding.expr, unsigned) {
        (Expr::Literal(Literal::I32(n)), KnownType::U32) if *n < 0 => {
            proc_macro2::Literal::u32_unsuffixed(*n as u32)
        }
        (Expr::Literal(Literal::I64(n)), KnownType::U64) if *n < 0 => {
            proc_macro2::Literal::u64_unsuffixed(*n as u64)
        }
        (Expr::Literal(Literal::I64(n)), KnownType::U32) if *n < 0 && i32::try_from(*n).is_ok() => {
            proc_macro2::Literal::u32_unsuffixed(*n as i32 as u32)
        }
        _ => return None,
    };
    Some(parse_quote!(#lit))
}

/// `value` as a suffix-free integer literal, inferred against a type
/// rather than against another value in this function.
///
/// The call-argument case needs this form: the type to match lives on the
/// *callee's* parameter, in another function's bindings entirely.
/// Whether a read's recovered type is a *struct* payload rather than the
/// `Option` around it.
///
/// Only a struct. A number has an obvious default and the source very
/// often wrote `.unwrap_or(0)` — other_custom_types does, and unwrapping it
/// cost that contract 0.039 by adding a fact the source never spelled. A
/// `#[contracttype]` struct has no such default, so a body that uses one
/// as its payload got there through `.unwrap()` or a `Some` arm, both of
/// which `.unwrap()` matches under the probe that guards the read.
fn is_bare_payload(ty: &IrType) -> bool {
    matches!(ty, IrType::Known(KnownType::UserDefined(_)) | IrType::Inferred(KnownType::UserDefined(_)))
}

pub(crate) fn unsuffixed_against(
    ctx: &FnCtx,
    value: sordec_common::ValueId,
    against: &IrType,
) -> Option<syn::Expr> {
    // A `bool` is `0` or `1` in the wasm, and a constant one of those
    // standing where a `bool` goes is that `bool`.
    if matches!(against, IrType::Known(KnownType::Bool) | IrType::Inferred(KnownType::Bool)) {
        let binding = ctx.func.bindings.get(ctx.fold_target(value))?;
        return match &binding.expr {
            Expr::Literal(Literal::I32(0) | Literal::I64(0) | Literal::U32(0) | Literal::U64(0)) => {
                Some(parse_quote!(false))
            }
            Expr::Literal(Literal::I32(1) | Literal::I64(1) | Literal::U32(1) | Literal::U64(1)) => {
                Some(parse_quote!(true))
            }
            _ => None,
        };
    }
    if !matches!(
        *against,
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
    let fits = match base_of(against) {
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

/// One expression as the short text a hole label carries.
fn operand_text(expr: &syn::Expr) -> String {
    prettyplease::unparse(&syn::parse_quote!(
        fn f() {
            #expr;
        }
    ))
    .lines()
    .nth(1)
    .map(|l| l.trim().trim_end_matches(';').to_string())
    .unwrap_or_default()
}

/// `+N` for a non-zero memarg offset, empty for zero — the common case,
/// where printing `+0` would be noise.
fn offset_suffix(offset: u32) -> String {
    if offset == 0 {
        String::new()
    } else {
        format!("+{offset}")
    }
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

/// An operand of a width move, as the bits the wasm moved.
///
/// A host object is one `Val` word on the wire, and reading its tag — the
/// SDK's argument checks do, `(m as i32 & 255) - 77` — reads those bits.
/// Rust will not cast an `Address` to an integer, but the SDK hands the
/// word out: `to_val().get_payload()` is exactly what the wasm read.
fn raw_bits(ctx: &FnCtx, value: sordec_common::ValueId) -> syn::Expr {
    let v = ctx.value_ref(value);
    let object = matches!(
        ctx.func.bindings.get(value).map(|b| &b.ty),
        Some(
            IrType::Known(
                KnownType::Address | KnownType::MuxedAddress | KnownType::Symbol | KnownType::Vec(_) | KnownType::Map(_, _)
            ) | IrType::Inferred(
                KnownType::Address | KnownType::MuxedAddress | KnownType::Symbol | KnownType::Vec(_) | KnownType::Map(_, _)
            )
        )
    );
    if object { parse_quote!(#v.to_val().get_payload()) } else { v }
}

/// A raw constant handed to a `Val`, spelled as the `Val` it is.
///
/// The wasm moves a `Val` as its 64 bits, so a constant flowing into one
/// is already encoded: `2` is `Void`, not the integer two. Spelled as an
/// integer it is a type error; converted with `into_val` it would be the
/// wrong value. `Val::from_payload` takes the bits as they are.
///
/// The merge must be a `Val`: typed one, or untyped (it is declared `Val`)
/// with another input that is one.
pub(crate) fn val_constant(ctx: &FnCtx, value: sordec_common::ValueId, phi: sordec_common::ValueId) -> Option<syn::Expr> {
    let is_val = |t: &IrType| matches!(t, IrType::Known(KnownType::Val) | IrType::Inferred(KnownType::Val));
    let merge = ctx.func.bindings.get(phi)?;
    let a_val = is_val(&merge.ty)
        || (matches!(merge.ty, IrType::Unknown(_))
            && matches!(&merge.expr, Expr::Phi { incoming } if incoming.iter().any(|(_, v)| {
                ctx.func.bindings.get(ctx.fold_target(*v)).is_some_and(|b| is_val(&b.ty))
            })));
    if !a_val {
        return None;
    }
    let binding = ctx.func.bindings.get(ctx.fold_target(value))?;
    if !matches!(binding.ty, IrType::Known(KnownType::I64) | IrType::Inferred(KnownType::I64) | IrType::Unknown(_)) {
        return None;
    }
    let bits: u64 = match &binding.expr {
        Expr::Literal(Literal::I64(n)) => *n as u64,
        Expr::Literal(Literal::U64(n)) => *n,
        _ => return None,
    };
    Some(if bits == 2 {
        parse_quote!(soroban_sdk::Val::VOID.into())
    } else {
        let lit = proc_macro2::Literal::u64_suffixed(bits);
        parse_quote!(soroban_sdk::Val::from_payload(#lit))
    })
}

/// The right-hand side expression for one binding.
pub(crate) fn binding_expr(ctx: &FnCtx, binding: &Binding) -> syn::Expr {
    match &binding.expr {
        Expr::Literal(lit) => literal_expr(ctx, lit, &binding.ty),
        Expr::Use(v) => ctx.value_ref(*v),
        Expr::Unary { op: op @ (UnaryOp::Wrap32 | UnaryOp::ExtendU32 | UnaryOp::ExtendS32), value } => {
            width_move(*op, raw_bits(ctx, *value), &binding.ty)
        }
        // Rust's bit-counting methods return `u32` whatever the receiver's
        // width; the wasm opcode returns the operand's own type. The cast
        // is the whole difference, and without it a `clz` on an `i64` is
        // an `i64 - u32` one line later — which is what nine of the
        // corpus's remaining type errors were.
        Expr::Unary { op: op @ (UnaryOp::Clz | UnaryOp::Ctz | UnaryOp::Popcnt), value } => {
            let counted = unary_expr(*op, ctx.value_ref(*value), false);
            count_cast(counted, &binding.ty)
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
            //
            // Arithmetic the same way, and for the same reason: `count + 1`
            // on a `u32` reaches us as `count + 1i64`, the constant still the
            // wasm word it was loaded as.
            let (l, r) = match op {
                // Equality compares bits, so a negative constant against an
                // unsigned value is the same bits read unsigned: the `+ 1`
                // overflow test `count == -1i32` on a `u32` is `u32::MAX`.
                BinaryOp::Eq | BinaryOp::Ne => (
                    unsuffixed(ctx, *lhs, *rhs).or_else(|| same_bits(ctx, *lhs, *rhs)),
                    unsuffixed(ctx, *rhs, *lhs)
                        .or_else(|| same_bits(ctx, *rhs, *lhs))
                        // Equality on bits survives a sign change: the right
                        // side takes the left's signedness.
                        .or_else(|| {
                            ctx.func
                                .bindings
                                .get(ctx.fold_target(*lhs))
                                .and_then(|b| sign_cast(ctx, *rhs, &b.ty))
                        }),
                ),
                BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt
                | BinaryOp::Ge | BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul => {
                    (unsuffixed(ctx, *lhs, *rhs), unsuffixed(ctx, *rhs, *lhs))
                }
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
            let env = ctx.env_borrow();
            // A constant argument takes the *callee's* parameter type, not
            // the width of the wasm word it was loaded as. Both sides of a
            // helper call come from the same module, so a mismatch here is
            // ours: the parameter is typed by whatever proved it (a rodata
            // position and length are `u32` by the host ABI) while the
            // argument literal is still the raw `i32` the const carried,
            // which rustc reports as "arguments to this function are
            // incorrect". Rendering the constant without a suffix lets it
            // take the parameter's type, and the range check in
            // `unsuffixed_against` keeps a genuine disagreement visible
            // rather than converting it into a silent wrap.
            let a: Vec<syn::Expr> = args
                .iter()
                .enumerate()
                .map(|(i, v)| {
                    let want = callee_param_type(ctx, *target, i);
                    want.as_ref()
                        .and_then(|ty| unsuffixed_against(ctx, *v, ty))
                        .or_else(|| want.as_ref().and_then(|ty| val_coerced(ctx, *v, ty)))
                        .or_else(|| want.as_ref().and_then(|ty| sign_cast(ctx, *v, ty)))
                        .unwrap_or_else(|| ctx.arg_ref(*v))
                })
                .collect();
            parse_quote!(#path(#env, #(#a),*))
        }
        // A recovered Soroban op renders as its idiomatic method chain when
        // the idiom table can build one honestly; otherwise it is a labeled
        // hole (an unmapped op, or an `Unknown` storage tier).
        // A storage read the pipeline has typed as its bare payload — the
        // `i128` a balance is, the `AllowanceValue` an allowance is — while
        // the op still says `Missing::Option`. The two contradict each
        // other, and the payload type is the one the rest of the body was
        // built against: the read is shifted, field-accessed, assigned to
        // the payload. Rust cannot do that with an `Option`, so the source
        // did not either — at this point the value is present, which is
        // what `.unwrap()` says.
        Expr::Semantic(SemanticOp::Known(
            known @ sordec_ir::KnownOp::StorageGet { missing: sordec_ir::Missing::Option, .. },
        )) if is_bare_payload(&binding.ty) => match idiom::known_op_expr(ctx, known) {
            Some(read) => parse_quote!(#read.unwrap()),
            None => ctx.policy.unknown_expr(&annotate::label_known_op(known)),
        },
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
        // The `Option` a helper hands back. Components move into it, so
        // one read again later is cloned, as for any by-value position.
        Expr::Optional { payload: None } => parse_quote!(None),
        Expr::Optional { payload: Some(values) } => match values.as_slice() {
            [one] => {
                let one = ctx.arg_ref(*one);
                parse_quote!(Some(#one))
            }
            many => {
                let many: Vec<syn::Expr> = many.iter().map(|v| ctx.arg_ref(*v)).collect();
                parse_quote!(Some((#(#many),*)))
            }
        },
        Expr::IsSome { value } => {
            let value = ctx.value_ref(*value);
            parse_quote!(#value.is_some())
        }
        // Presence is proven where this sits. `unwrap` takes the `Option`
        // by value, so one read again later is cloned first.
        Expr::Unwrap { value, index, arity } => {
            let value = ctx.arg_ref(*value);
            if *arity == 1 {
                parse_quote!(#value.unwrap())
            } else {
                let field = syn::Index::from(*index as usize);
                parse_quote!(#value.unwrap().#field)
            }
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
        // The `if`/`else` the source wrote, which the compiler computed
        // both arms of. Rendered as the expression it is — parenthesized
        // nowhere, because `syn` prints an `if` in expression position
        // correctly and a `let` binding is where these land.
        Expr::Select { cond, if_true, if_false } => {
            let c = ctx.value_ref(*cond);
            let (t, f) = (ctx.value_ref(*if_true), ctx.value_ref(*if_false));
            parse_quote!(if #c { #t } else { #f })
        }
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
        // A raw memory access names its address and, for a store, the
        // value it writes.
        //
        // `todo!("memory store")` discards both, which loses the only thing
        // a reader could use — *which* slot took *what* — and leaves the
        // address arithmetic above it with no reader at all: 564 of the
        // held-out set's emitted bindings are unread for exactly this
        // reason, and rustc warns about every one. Naming the operands
        // keeps the fact and the binding together.
        Expr::Load { addr, offset, width, .. } => ctx.policy.unknown_expr(&format!(
            "load {}{} width {}",
            operand_text(&ctx.value_ref(*addr)),
            offset_suffix(*offset),
            width.bytes()
        )),
        Expr::Store { addr, value, offset, width } => ctx.policy.unknown_expr(&format!(
            "store {}{} <- {} width {}",
            operand_text(&ctx.value_ref(*addr)),
            offset_suffix(*offset),
            operand_text(&ctx.value_ref(*value)),
            width.bytes()
        )),
        Expr::GlobalGet { index } => ctx.policy.unknown_expr(&format!("global.get {index}")),
        Expr::IndirectCall { .. } => ctx.policy.unknown_expr("indirect call"),
        // A phi never reaches here (phis are `let mut` declarations, not
        // scheduled bindings); handled honestly if the invariant slips.
        Expr::Phi { .. } => ctx.policy.unknown_expr("phi"),
        // Same argument as the memory holes above: an unrecovered operator
        // that drops its operands tells a reader nothing and orphans the
        // bindings that computed them. `GlobalSet` is the shadow-stack
        // bracket and by far the commonest of these.
        Expr::Unknown { op_kind, args, .. } => {
            let operands = args
                .iter()
                .map(|a| operand_text(&ctx.value_ref(*a)))
                .collect::<Vec<_>>()
                .join(", ");
            ctx.policy.unknown_expr(&if operands.is_empty() {
                format!("unrecovered {op_kind:?}")
            } else {
                format!("unrecovered {op_kind:?}({operands})")
            })
        }
    }
}

/// The declared type of `target`'s parameter at position `index`.
///
/// `None` whenever the callee, the parameter or its binding cannot be
/// resolved — an argument then renders exactly as it did before, which is
/// the honest fallback for a call we cannot line up.
/// A recovered value handed to a `Val` parameter, converted on the way in.
///
/// A helper taking a `Val` takes the host representation; the caller holds
/// the recovered thing, and passing it straight through is a type error.
///
/// Both sides must be *recovered*. A parameter that is merely `Unknown`
/// also prints as `Val`, but it is not evidence of anything — coercing
/// against it was measured at +2 error lines, because it converts
/// arguments at sites that were already right. What makes this fire is the
/// typing in `type_infer`'s backward rule for a mixed vec, not a guess
/// here.
///
/// The trait is written with its parameters spelled out: the bare method
/// needs its target type pinned from context, and supplying that is the
/// point of the call.
fn val_coerced(ctx: &FnCtx, v: sordec_common::ValueId, want: &IrType) -> Option<syn::Expr> {
    if !matches!(want, IrType::Known(KnownType::Val) | IrType::Inferred(KnownType::Val)) {
        return None;
    }
    match &ctx.func.bindings.get(v)?.ty {
        IrType::Known(KnownType::Val) | IrType::Inferred(KnownType::Val) => None,
        IrType::Unknown(_) => None,
        _ => {
            let x = ctx.arg_ref(v);
            let e = ctx.env_borrow();
            Some(parse_quote!(
                soroban_sdk::IntoVal::<soroban_sdk::Env, soroban_sdk::Val>::into_val(&#x, #e)
            ))
        }
    }
}

fn callee_param_type(ctx: &FnCtx, target: FuncId, index: usize) -> Option<IrType> {
    let callee = ctx.high.function(target)?;
    let param = *callee.params.get(index)?;
    Some(callee.bindings.get(param)?.ty.clone())
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
/// A bit count cast back to the type the binding was recovered as.
///
/// `u32` needs nothing — that is what Rust already gives. An unrecovered
/// type gets nothing either: inventing a cast onto a value we could not
/// type would turn a visible gap into a silent one.
fn count_cast(counted: syn::Expr, ty: &IrType) -> syn::Expr {
    let base = match ty {
        IrType::Known(k) | IrType::Inferred(k) => k,
        IrType::Unknown(_) => return counted,
    };
    match base {
        KnownType::U32 => counted,
        KnownType::I32 => parse_quote!((#counted as i32)),
        KnownType::I64 => parse_quote!((#counted as i64)),
        KnownType::U64 => parse_quote!((#counted as u64)),
        _ => counted,
    }
}

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
