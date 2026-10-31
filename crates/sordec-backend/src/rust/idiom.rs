//! The Soroban idiom table: recovered [`KnownOp`]s → the SDK method chains
//! the source wrote.
//!
//! This vocabulary is shared with the scorer by contract (K4): the chains
//! built here are exactly the shapes
//! [`sordec-score`'s extractor](../../../sordec-score/src/extract.rs)
//! keys on, so a correctly-recovered op *scores* correct. The mapping is
//! deliberately limited to the source-level operations that appear in real
//! contract source **and** that the scorer tracks (storage, auth, events,
//! ledger context, SEP-41 cross-contract calls, `panic_with_error!`).
//!
//! ABI-marshalling residue (val encode/decode, obj conversions, tag
//! checks) and every other op return `None` — they stay `todo!()` holes
//! ([`super::expr`]), honestly, until a later wave elides or recovers them.
//! An `Unknown` storage tier also returns `None`: naming a tier we did not
//! prove would be a guess (K2), and so is an unresolved `SymbolNew`.
//!
//! ## Two rules the crypto/prng chains depend on
//!
//! **Spell the chain unbroken.** The scorer keys a crypto/prng fact on the
//! *receiver* being a method call named `crypto` / `prng`
//! (`extract::receiver_keyed_fact`), and that matcher does no
//! cosmetic-stripping and no let-resolution. `(#e.crypto()).sha256(..)`,
//! a hoisted `let c = #e.crypto();`, and the UFCS form all score zero.
//! `ctx.env()` returning the bare ident `e` is what keeps this safe.
//!
//! **One op, one chain.** Semantic is a multiset comparison, and
//! attestation's source has `crypto:sha256` twice. Inlining a recovered
//! op at each use site instead of binding it once would report three and
//! cost precision; the emitter's one-`let`-per-binding shape is what keeps
//! the counts honest.

use quote::format_ident;
use syn::parse_quote;

use sordec_ir::{
    BufOpKind, ClientInterface, CryptoOpKind, DeployOpKind, EnumKey, KnownOp, KnownTier, PrngOpKind,
    StorageTier, ValObjectKind, VecOpKind, KnownType, IrType};

use crate::rust::body::FnCtx;
use crate::rust::ty::ident;

/// A value typed as a `Vec`, which has its own `len()`.
fn typed_vec(ctx: &FnCtx, v: sordec_common::ValueId) -> bool {
    matches!(
        ctx.func.bindings.get(v).map(|b| &b.ty),
        Some(IrType::Known(KnownType::Vec(_)) | IrType::Inferred(KnownType::Vec(_)))
    )
}

/// Whether `v` is typed as a vec of the SDK's `InvokerContractAuthEntry`,
/// the type `authorize_as_current_contract` takes.
fn entries_vec(ctx: &FnCtx, v: sordec_common::ValueId) -> bool {
    let Some(IrType::Known(KnownType::Vec(element)) | IrType::Inferred(KnownType::Vec(element))) =
        ctx.func.bindings.get(v).map(|b| &b.ty)
    else {
        return false;
    };
    let (IrType::Known(KnownType::UserDefined(id)) | IrType::Inferred(KnownType::UserDefined(id))) = element.as_ref()
    else {
        return false;
    };
    ctx.reg.sdk_module(*id) == Some("auth") && ctx.reg.name_of(*id) == Some("InvokerContractAuthEntry")
}

/// `vec_get(v, i)` with `i` a literal `U32Val`, as `v.get_unchecked(n)`.
///
/// The general `Get` stays a hole (see [`known_op_expr`]): its index is an
/// encoded `Val`, and decoding it wrong is off by 2³². A literal one decodes
/// exactly — tag 4 in the low word, the `u32` above it — and the host's
/// `vec_get` traps out of range just as `get_unchecked` does, so the chain
/// is the call. `account`'s `args.get(2)` is `vec_get(args, 0x2_0000_0004)`.
///
/// A receiver the IR has not typed as a `Vec` goes through `Val`, as
/// `len()` does ([`converted_to_val`]), and its element is then a `Val`;
/// where the binding is typed (`i128`, the amount the source converts the
/// argument to), the element is converted to it.
pub(crate) fn vec_get_at_literal(
    ctx: &FnCtx,
    op: &KnownOp,
    result: sordec_common::ValueId,
) -> Option<syn::Expr> {
    let KnownOp::VecOp { kind: VecOpKind::Get, args } = op else {
        return None;
    };
    let [recv, index] = args.as_slice() else {
        return None;
    };
    let n = literal_index(ctx, *index)?;
    let eb = ctx.env_borrow();
    let v = ctx.value_ref(*recv);
    if converted_to_val(ctx, op).is_none() {
        return Some(parse_quote!(#v.get_unchecked(#n)));
    }
    let element: syn::Expr = parse_quote!(
        soroban_sdk::IntoVal::<soroban_sdk::Env, soroban_sdk::Vec<soroban_sdk::Val>>::into_val(
            &soroban_sdk::IntoVal::<soroban_sdk::Env, soroban_sdk::Val>::into_val(&#v, #eb),
            #eb,
        ).get_unchecked(#n)
    );
    let typed = matches!(
        ctx.func.bindings.get(result).map(|b| &b.ty),
        Some(IrType::Known(k) | IrType::Inferred(k)) if *k != KnownType::Val
    );
    if !typed {
        return Some(element);
    }
    let ty = ctx.value_type(result);
    Some(parse_quote!(soroban_sdk::IntoVal::<soroban_sdk::Env, #ty>::into_val(&#element, #eb)))
}

/// The `u32` a raw `U32Val` word carries: tag 4 in the low word, the value
/// above it. `None` for any other word.
fn u32_val_payload(raw: i64) -> Option<u32> {
    (raw & 0xFFFF_FFFF == 4).then_some(())?;
    u32::try_from(raw >> 32).ok()
}

/// The `u32` an index operand carries when it is a literal `U32Val`.
fn literal_index(ctx: &FnCtx, index: sordec_common::ValueId) -> Option<u32> {
    match ctx.func.bindings.get(index).map(|b| &b.expr) {
        Some(sordec_ir::Expr::Literal(sordec_ir::Literal::I64(raw))) => u32_val_payload(*raw),
        _ => None,
    }
}

/// The operand whose chain converts it into a `Val` before using it —
/// `IntoVal::<Env, Val>::into_val(&x, e)` — or `None` when the op's chain
/// converts none.
///
/// Three chains do: `len()` and a literal-index `get` on a receiver the IR
/// has not typed as a `Vec` ([`known_op_expr`], [`vec_get_at_literal`]),
/// and `authorize_as_current_contract` on entries typed neither a `Vec`
/// nor a `Val`. Each treats the operand as the `Val` the host call was
/// handed, which is what lets the body annotate an untyped hole read only
/// this way as one (`FnCtx::converted_to_val_only`): without it, the
/// hole's `!` falls back to `()`, and `()` is not the value the host read.
///
/// The three renderers decide whether to convert by calling this, so what
/// the body annotates and what the chain prints cannot drift apart.
pub(crate) fn converted_to_val(ctx: &FnCtx, op: &KnownOp) -> Option<sordec_common::ValueId> {
    match op {
        KnownOp::VecOp { kind: VecOpKind::Len, args } => {
            let recv = *args.first()?;
            (!typed_vec(ctx, recv)).then_some(recv)
        }
        KnownOp::VecOp { kind: VecOpKind::Get, args } => {
            let [recv, index] = args.as_slice() else {
                return None;
            };
            literal_index(ctx, *index)?;
            (!typed_vec(ctx, *recv)).then_some(*recv)
        }
        KnownOp::AuthorizeAsCurrContract { auth_entries } => {
            let typed = matches!(
                ctx.func.bindings.get(*auth_entries).map(|b| &b.ty),
                Some(
                    IrType::Known(KnownType::Vec(_) | KnownType::Val)
                        | IrType::Inferred(KnownType::Vec(_) | KnownType::Val)
                )
            );
            (!typed).then_some(*auth_entries)
        }
        _ => None,
    }
}

/// The operand an op's chain hands to an SDK method generic in
/// `IntoVal<Env, Val>` as it is: the value `storage().set(&k, &v)` stores,
/// the data `events().publish(t, d)` publishes.
///
/// Nothing at such a position pins the operand's type, so an untyped hole
/// read only there falls back to `()` — "depends on never type fallback".
/// The host receives the operand as a `Val`, the `Val` the wasm passed:
/// [`converted_to_val`]'s reasoning, without a conversion in the chain,
/// since `IntoVal<Env, Val>` of a `Val` is the identity.
///
/// The key is left out: [`key_expr`] may print a resolved key that does
/// not read the operand, and a topic list goes through `Topics`, not
/// `IntoVal`.
pub(crate) fn generic_val_operand(op: &KnownOp) -> Option<sordec_common::ValueId> {
    match op {
        KnownOp::StorageSet { value, .. } => Some(*value),
        KnownOp::PublishEvent { data, .. } => Some(*data),
        _ => None,
    }
}

/// The method chain for a recovered op, or `None` when it cannot be
/// rendered honestly (an unmapped op, or an `Unknown` storage tier).
pub(crate) fn known_op_expr(ctx: &FnCtx, op: &KnownOp) -> Option<syn::Expr> {
    let e = ctx.env();
    let eb = ctx.env_borrow();
    match op {
        // ---- Collections ----
        //
        // Only the operations whose SDK spelling is unambiguous. The rest
        // stay holes rather than guess a method: a wrong chain is worse
        // than an honest `todo!()`, because the scorer's extractor reads
        // these chains as facts.
        // `vec![&e, a, b, c]`. Only once every element is recovered — a
        // constructor with an unrecovered buffer stays a hole, because a
        // vector printed shorter than the contract builds is a wrong fact,
        // not a partial one.
        KnownOp::VecNew {
            elements: Some(values),
            ..
        } => {
            let (items, converted) = vec_items(ctx, values);
            let e = ctx.env_borrow();
            // Elements none of which has a recovered type, each bound as an
            // unannotated hole (an unrecovered load or operator), leave rustc
            // nothing to type the vec by: a macro over them falls back on
            // `()` for the element type. The hole policy names an
            // unrecovered type `Val`, so that is said outright. Anything
            // else — a merge, a parameter, a call's result — already has a
            // type in the emitted Rust.
            let untyped = !values.is_empty()
                && values.iter().all(|v| {
                    let Some(b) = ctx.func.bindings.get(ctx.fold_target(*v)) else { return false };
                    !matches!(b.ty, IrType::Known(_) | IrType::Inferred(_))
                        && matches!(b.expr, sordec_ir::Expr::Load { .. } | sordec_ir::Expr::Unknown { .. })
                });
            if untyped {
                return Some(parse_quote!(soroban_sdk::Vec::<soroban_sdk::Val>::from_array(#e, [#(#items),*])));
            }
            if converted {
                // `Vec::from_array`, not the macro: a macro's tokens are
                // opaque to `imports::collapse`, so a qualified path
                // written inside `vec![…]` can never shorten, and the
                // module is required to carry none. The array form puts
                // the conversions somewhere the collapser can see.
                Some(parse_quote!(soroban_sdk::Vec::from_array(#e, [#(#items),*])))
            } else {
                Some(parse_quote!(soroban_sdk::vec![#e, #(#items),*]))
            }
        }
        // `Vec::new(&e)` is the SDK's one call of the bare `vec_new`; the
        // element type is the binding's, which the `let` spells.
        KnownOp::VecOp { kind: VecOpKind::New, args } if args.is_empty() => {
            Some(parse_quote!(soroban_sdk::Vec::new(#eb)))
        }
        KnownOp::VecOp { kind, args } => {
            let v = ctx.value_ref(*args.first()?);
            let arg = |i: usize| args.get(i).map(|a| ctx.value_ref(*a));
            match kind {
                // `Len` is safe because the packed-compare recognizer
                // decodes the bound it is compared against: `len() > 10`
                // arrives as `vec_len(v) > (11 << 32) - 1` and is rewritten
                // to `> 10` before this runs. `Get` and the pushes are
                // still absent — their operands are encoded `Val`s with no
                // such recognizer, and a chain that reads like the source
                // while being wrong by 2^32 is worse than a hole.
                // A receiver not typed as a `Vec` is the `Val` the host call
                // was handed — untyped, or a `#[contracttype]` enum, which
                // encodes as a vec its decode reads the length of. `vec_len`
                // traps unless it is a vec, and so does the conversion that
                // makes it one here. Through `Val`, since only `Val`
                // converts to a `Vec`.
                VecOpKind::Len if converted_to_val(ctx, op).is_some() => Some(parse_quote!(
                    soroban_sdk::IntoVal::<soroban_sdk::Env, soroban_sdk::Vec<soroban_sdk::Val>>::into_val(
                        &soroban_sdk::IntoVal::<soroban_sdk::Env, soroban_sdk::Val>::into_val(&#v, #eb),
                        #eb,
                    ).len()
                )),
                VecOpKind::Len => Some(parse_quote!(#v.len())),
                VecOpKind::FirstIndexOf => {
                    let x = arg(1)?;
                    Some(parse_quote!(#v.first_index_of(&#x)))
                }
                VecOpKind::LastIndexOf => {
                    let x = arg(1)?;
                    Some(parse_quote!(#v.last_index_of(&#x)))
                }
                _ => None,
            }
        }
        // ---- Storage ----
        KnownOp::StorageGet { tier, key, resolved_key, missing, .. } => {
            let tier = tier_method(tier)?;
            let k = key_expr(ctx, *key, resolved_key);
            Some(match missing {
                sordec_ir::Missing::Option => parse_quote!(#e.storage().#tier().get(&#k)),
                // Present is spelled as the `if let` that binds it; see
                // `option_read`. Read anywhere else, the probe has already
                // proved the entry is there, which is what `unwrap` says.
                sordec_ir::Missing::Unwrap | sordec_ir::Missing::Present(_) => {
                    parse_quote!(#e.storage().#tier().get(&#k).unwrap())
                }
                sordec_ir::Missing::Or(default) => {
                    let d = ctx.value_ref(*default);
                    parse_quote!(#e.storage().#tier().get(&#k).unwrap_or(#d))
                }
            })
        }
        KnownOp::StorageSet { tier, key, resolved_key, value, .. } => {
            let tier = tier_method(tier)?;
            let k = key_expr(ctx, *key, resolved_key);
            let v = ctx.value_ref(*value);
            Some(parse_quote!(#e.storage().#tier().set(&#k, &#v)))
        }
        // A proven SDK `Option` probe is not a call the source made — the
        // `get` it guards is. Spelling it would report a `.has()` the
        // author never wrote, so decline for the same reason an unproven
        // tier declines: we will not name what we know is not there.
        KnownOp::StorageHas { probe: true, .. } => None,
        KnownOp::StorageHas { tier, key, resolved_key, .. } => {
            let tier = tier_method(tier)?;
            let k = key_expr(ctx, *key, resolved_key);
            Some(parse_quote!(#e.storage().#tier().has(&#k)))
        }
        KnownOp::StorageRemove { tier, key, resolved_key, .. } => {
            let tier = tier_method(tier)?;
            let k = key_expr(ctx, *key, resolved_key);
            Some(parse_quote!(#e.storage().#tier().remove(&#k)))
        }
        KnownOp::StorageExtendTtl {
            tier,
            key,
            resolved_key,
            threshold,
            extend_to,
            resolved_threshold,
            resolved_extend_to,
            ..
        } => {
            let tier = tier_method(tier)?;
            let k = key_expr(ctx, *key, resolved_key);
            let t = ledger_count(ctx, *threshold, *resolved_threshold);
            let x = ledger_count(ctx, *extend_to, *resolved_extend_to);
            Some(parse_quote!(#e.storage().#tier().extend_ttl(&#k, #t, #x)))
        }
        KnownOp::ExtendCurrentContractInstanceAndCodeTtl {
            threshold,
            extend_to,
            resolved_threshold,
            resolved_extend_to,
        } => {
            let t = ledger_count(ctx, *threshold, *resolved_threshold);
            let x = ledger_count(ctx, *extend_to, *resolved_extend_to);
            // Instance TTL extension takes no key (matches the scorer's
            // `instance().extend_ttl(threshold, amount)` special case).
            Some(parse_quote!(#e.storage().instance().extend_ttl(#t, #x)))
        }

        // ---- Authorisation ----
        KnownOp::RequireAuth { address } => {
            let a = ctx.value_ref(*address);
            Some(parse_quote!(#a.require_auth()))
        }
        // The host takes the arguments as a `Vec<Val>`. A vec of typed
        // elements — `vec![&e, 1i32, 2i32]` — is the same host object, and
        // `to_vals` is the SDK's view of it as one: no conversion, no copy.
        KnownOp::RequireAuthForArgs { address, args } => {
            let a = ctx.value_ref(*address);
            let args: Vec<syn::Expr> = args
                .iter()
                .map(|v| {
                    let x = ctx.value_ref(*v);
                    if vec_of_named(ctx, *v) { parse_quote!(#x.to_vals()) } else { x }
                })
                .collect();
            Some(parse_quote!(#a.require_auth_for_args(#(#args),*)))
        }
        // No recovered type spells `Vec<InvokerContractAuthEntry>`: what
        // reaches here is the vec the entries encode to (`vec![Symbol
        // "Contract", map]` per entry), so it is decoded at the call. The
        // parameter type pins `from_val`'s target, and the host receives the
        // same `Val` either way.
        KnownOp::AuthorizeAsCurrContract { auth_entries } => {
            let entries = ctx.value_ref(*auth_entries);
            // Unless the vec was recovered as the entries themselves: then
            // it is the parameter's type, and goes as it is.
            if entries_vec(ctx, *auth_entries) {
                return Some(parse_quote!(#e.authorize_as_current_contract(#entries)));
            }
            let val: syn::Expr = if converted_to_val(ctx, op).is_some() {
                parse_quote!(soroban_sdk::IntoVal::<soroban_sdk::Env, soroban_sdk::Val>::into_val(&#entries, #eb))
            } else if typed_vec(ctx, *auth_entries) {
                parse_quote!(#entries.to_val())
            } else {
                // Typed `Val` already.
                entries
            };
            Some(parse_quote!(#e.authorize_as_current_contract(soroban_sdk::FromVal::from_val(#eb, &#val))))
        }

        // ---- Events ----
        KnownOp::PublishEvent { topics, data } => {
            // The topics are the vector itself — `Topics` is implemented for
            // `Vec<T>` — never a tuple around it, which would publish one
            // topic that is a vector.
            let topics = ctx.arg_ref(*topics);
            let data = ctx.value_ref(*data);
            Some(parse_quote!(#e.events().publish(#topics, #data)))
        }
        // The struct literal the source built, published. Values by
        // `arg_ref`: a field takes its value by move, so one read again
        // later is cloned here, as for any other by-value position.
        KnownOp::PublishContractEvent { event, fields } => {
            let name = ident(event);
            let inits: Vec<proc_macro2::TokenStream> = fields
                .iter()
                .map(|(field, value)| {
                    let f = ident(field);
                    match value {
                        Some(v) => {
                            let v = ctx.arg_ref(*v);
                            quote::quote!(#f: #v)
                        }
                        None => quote::quote!(#f: None),
                    }
                })
                .collect();
            Some(parse_quote!(#name { #(#inits),* }.publish(#eb)))
        }
        KnownOp::MuxedAddressId { muxed } => {
            let m = ctx.value_ref(*muxed);
            Some(parse_quote!(#m.id()))
        }

        // ---- Cross-contract (SEP-41 client) ----
        KnownOp::InvokeContract {
            contract,
            resolved_callee: Some(callee),
            interface: Some(ClientInterface::Sep41Token),
            resolved_args,
            args,
            ..
        } => {
            let c = ctx.value_ref(*contract);
            let method = ident(callee);
            let call_args = resolved_args.as_ref().unwrap_or(args);
            let a: Vec<syn::Expr> = call_args.iter().map(|v| ctx.value_ref(*v)).collect();
            Some(parse_quote!(soroban_sdk::token::Client::new(#eb, &#c).#method(#(&#a),*)))
        }

        // ---- Cross-contract (a client declared from its call sites) ----
        // See [`super::client`]: the method is declared only when every call
        // to it agrees on one signature, and a call it does not declare
        // stays a hole.
        KnownOp::InvokeContract {
            contract,
            resolved_callee: Some(callee),
            interface: None,
            resolved_args: Some(args),
            ..
        } if super::client::declares(ctx.high, ctx.reg, ctx.policy, callee) => {
            let c = ctx.value_ref(*contract);
            let method = ident(callee);
            let client = ident(super::client::CLIENT);
            let a: Vec<syn::Expr> = args.iter().map(|v| ctx.value_ref(*v)).collect();
            Some(parse_quote!(#client::new(#eb, &#c).#method(#(&#a),*)))
        }

        // ---- Address conversions ----
        // `MuxedAddress::address()`. The SDK method, not the bare host
        // function: on a muxed value that wraps a plain address the host
        // call is not even reached, and the method handles both — which is
        // what lets `marshalling::muxed_address` collapse the SDK's own
        // two-way dispatch into this one call.
        KnownOp::AddressConversion {
            kind: sordec_ir::AddressOpKind::GetAddressFromMuxedAddress,
            args,
        } => {
            let m = ctx.value_ref(*args.first()?);
            Some(parse_quote!(#m.address()))
        }

        // ---- Ledger context ----
        KnownOp::GetLedgerSequence => Some(parse_quote!(#e.ledger().sequence())),
        KnownOp::GetLedgerTimestamp => Some(parse_quote!(#e.ledger().timestamp())),
        KnownOp::GetLedgerProtocolVersion => Some(parse_quote!(#e.ledger().protocol_version())),
        KnownOp::GetLedgerNetworkId => Some(parse_quote!(#e.ledger().network_id())),
        KnownOp::GetMaxLiveUntilLedger => Some(parse_quote!(#e.ledger().max_live_until_ledger())),
        KnownOp::GetCurrentContractAddress => Some(parse_quote!(#e.current_contract_address())),

        // ---- Deploy ----
        // The SDK's deployer methods are these host calls with their
        // operands unchanged, so each prints as the method once every
        // operand already has the type the method takes; an untyped `Val`
        // would need a conversion the binary does not show.
        KnownOp::DeployOp {
            kind: DeployOpKind::UpdateCurrentContractWasm,
            args,
        } => {
            let [hash] = args[..] else { return None };
            if !has_type(ctx.func, hash, |t| matches!(t, KnownType::BytesN(32))) {
                return None;
            }
            let hash = ctx.arg_ref(hash);
            Some(parse_quote!(#e.deployer().update_current_contract_wasm(#hash)))
        }
        // `create_contract_with_constructor(deployer, wasm_hash, salt, args)`
        // is `DeployerWithAddress::deploy_v2`; `with_current_contract`
        // passes the current contract's address as the deployer, so a
        // deployer that is that address reads as the source writes it.
        KnownOp::DeployOp {
            kind: DeployOpKind::CreateContractWithConstructor,
            args,
        } => {
            if !deploy_typed(ctx.func, args) {
                return None;
            }
            let [deployer, wasm_hash, salt, ctor_args] = args[..] else { return None };
            let current = is_current_address(ctx.func, deployer);
            let (wasm_hash, salt, ctor_args) = (ctx.arg_ref(wasm_hash), ctx.arg_ref(salt), ctx.arg_ref(ctor_args));
            if current {
                Some(parse_quote!(#e.deployer().with_current_contract(#salt).deploy_v2(#wasm_hash, #ctor_args)))
            } else {
                let deployer = ctx.arg_ref(deployer);
                Some(parse_quote!(#e.deployer().with_address(#deployer, #salt).deploy_v2(#wasm_hash, #ctor_args)))
            }
        }

        // ---- Host panic ----
        KnownOp::PanicWithError { error } => {
            let err = ctx.value_ref(*error);
            Some(parse_quote!(soroban_sdk::panic_with_error!(#e, #err)))
        }

        // ---- Recovered contract-error constant ----
        // A resolved `#[contracterror]` variant renders as its path; an
        // unresolved code falls through to an honest hole (the pass only
        // ever produces resolved variants today).
        // No single declared enum names the code: the SDK's own `Error`
        // with that contract code, the same bits.
        KnownOp::MakeError { code, resolved: None } => {
            let code = proc_macro2::Literal::u32_unsuffixed(*code);
            Some(parse_quote!(soroban_sdk::Error::from_contract_error(#code)))
        }
        KnownOp::MakeError { resolved: Some(ev), .. } => {
            let enum_name = ident(&ev.enum_name);
            let variant = ident(&ev.variant);
            Some(parse_quote!(#enum_name::#variant))
        }

        // ---- Crypto ----
        // `Hash<N>` is unwrapped with `to_bytes()` rather than the
        // source's `.into()`. `.into()` needs a target type from context,
        // and one of the corpus sites has none: `check` binds the digest
        // only to feed an op that is still a hole, so `let v = …into();`
        // is an unconstrained `Into` and fails to infer. `to_bytes()`
        // names `BytesN<N>` outright, compiles in every position, and is
        // fact-identical to the scorer (`crypto:sha256` is keyed on the
        // `.crypto()` receiver, and the trailing method is ignored).
        KnownOp::CryptoOp {
            kind: CryptoOpKind::ComputeHashSha256,
            args,
        } => {
            let data = ctx.value_ref(*args.first()?);
            Some(parse_quote!(#e.crypto().sha256(&#data).to_bytes()))
        }
        KnownOp::CryptoOp {
            kind: CryptoOpKind::ComputeHashKeccak256,
            args,
        } => {
            let data = ctx.value_ref(*args.first()?);
            Some(parse_quote!(#e.crypto().keccak256(&#data).to_bytes()))
        }
        // Returns `()` and traps on failure, so it lands in statement
        // position — no binding, no conversion.
        KnownOp::CryptoOp {
            kind: CryptoOpKind::VerifySigEd25519,
            args,
        } => {
            let [key, msg_id, sig] = args[..] else { return None };
            let (key, msg, sig) = (ctx.value_ref(key), ctx.value_ref(msg_id), ctx.value_ref(sig));
            // The message is `&Bytes`. A fixed-size `BytesN` handed to it is
            // the same host object, and the SDK converts with `into` — what
            // `simple_account` writes, `&signature_payload.into()`.
            let fixed = matches!(
                ctx.func.bindings.get(msg_id).map(|b| &b.ty),
                Some(IrType::Known(KnownType::BytesN(_)) | IrType::Inferred(KnownType::BytesN(_)))
            );
            if fixed {
                Some(parse_quote!(#e.crypto().ed25519_verify(&#key, &#msg.into(), &#sig)))
            } else {
                Some(parse_quote!(#e.crypto().ed25519_verify(&#key, &#msg, &#sig)))
            }
        }

        // ---- Comparison ----
        // `obj_cmp` is the host's total order on two objects, as -1/0/1.
        // The SDK's `Ord` for its object types calls exactly that, and
        // `Ordering` casts to the same three values, so the cast is the
        // call. Only for two operands of one such type: an untyped `Val`
        // has no `Ord`, and the hole is the honest answer then.
        KnownOp::ValCompare { a, b } => {
            let ty = |v| match ctx.func.bindings.get(v).map(|b| &b.ty) {
                Some(IrType::Known(t) | IrType::Inferred(t))
                    if matches!(
                        t,
                        KnownType::Address
                            | KnownType::Symbol
                            | KnownType::String
                            | KnownType::Bytes
                            | KnownType::BytesN(_)
                    ) =>
                {
                    Some(t)
                }
                _ => None,
            };
            if ty(*a).is_none() || ty(*a) != ty(*b) {
                return None;
            }
            let (a, b) = (ctx.value_ref(*a), ctx.value_ref(*b));
            Some(parse_quote!((#a.cmp(&#b) as i64)))
        }

        // ---- 256-bit numbers and their bytes ----
        // `U256::from_be_bytes(&e, &bytes)` is `u256_val_from_be_bytes` and
        // nothing else, and `to_be_bytes` is `u256_val_to_be_bytes` (the
        // same for `I256`). Spelled only when the operand is already typed
        // as the SDK's parameter: a `Bytes`, or a `BytesN` whose borrow
        // converts to one, for the constructor; the number itself for
        // `to_be_bytes`. An untyped operand stays a hole rather than claim
        // a conversion nothing proved.
        //
        // The host returns the number's `U256Val`, and that `Val` is what
        // the binding holds (`val_abi::obj_kind_result_type`): `to_val`
        // hands back exactly that word, so the spelling is the value the
        // IR names, not a conversion of it.
        KnownOp::ValObject { kind: kind @ (ValObjectKind::U256ValFromBeBytes | ValObjectKind::I256ValFromBeBytes), args } => {
            let [bytes] = args[..] else { return None };
            let number: syn::Path = match kind {
                ValObjectKind::U256ValFromBeBytes => parse_quote!(soroban_sdk::U256),
                _ => parse_quote!(soroban_sdk::I256),
            };
            let b = ctx.value_ref(bytes);
            match ctx.func.bindings.get(ctx.fold_target(bytes)).map(|b| &b.ty) {
                Some(IrType::Known(KnownType::Bytes) | IrType::Inferred(KnownType::Bytes)) => {
                    Some(parse_quote!(#number::from_be_bytes(#eb, &#b).to_val()))
                }
                Some(IrType::Known(KnownType::BytesN(_)) | IrType::Inferred(KnownType::BytesN(_))) => {
                    Some(parse_quote!(#number::from_be_bytes(#eb, &soroban_sdk::Bytes::from(&#b)).to_val()))
                }
                _ => None,
            }
        }
        KnownOp::ValObject { kind: kind @ (ValObjectKind::U256ValToBeBytes | ValObjectKind::I256ValToBeBytes), args } => {
            let [number] = args[..] else { return None };
            let want = match kind {
                ValObjectKind::U256ValToBeBytes => KnownType::U256,
                _ => KnownType::I256,
            };
            let typed = matches!(
                ctx.func.bindings.get(ctx.fold_target(number)).map(|b| &b.ty),
                Some(IrType::Known(t) | IrType::Inferred(t)) if *t == want
            );
            if !typed {
                return None;
            }
            let n = ctx.value_ref(number);
            Some(parse_quote!(#n.to_be_bytes()))
        }

        // ---- PRNG ----
        KnownOp::PrngOp {
            kind: PrngOpKind::PrngU64InInclusiveRange,
            args,
        } => {
            let [lo, hi] = args[..] else { return None };
            let (lo, hi) = (ctx.value_ref(lo), ctx.value_ref(hi));
            Some(parse_quote!(#e.prng().gen_range(#lo..=#hi)))
        }

        // ---- Buffers ----
        // Fact-neutral to the scorer (`len` is deliberately outside the
        // semantic vocabulary — see `sordec-score`'s T17 note), so this is
        // compile-gate and structure work: it is what lets a recovered
        // `message.len() == 0` read as the source line instead of a hole.
        //
        // A `Val` operand (a decoder's argument, read before it is typed)
        // is converted first: `Bytes::try_from_val` fails exactly where the
        // host's length call traps, on anything but a bytes object.
        KnownOp::BufOp {
            kind: BufOpKind::BytesLen,
            args,
        } => {
            let operand = *args.first()?;
            let bytes = ctx.value_ref(operand);
            let is_val = ctx.func.bindings.get(ctx.fold_target(operand)).is_some_and(|b| {
                matches!(b.ty, IrType::Known(KnownType::Val) | IrType::Inferred(KnownType::Val))
            });
            if is_val {
                return Some(parse_quote!(
                    <soroban_sdk::Bytes as soroban_sdk::TryFromVal<soroban_sdk::Env, soroban_sdk::Val>>::try_from_val(#eb, &#bytes)
                        .unwrap()
                        .len()
                ));
            }
            Some(parse_quote!(#bytes.len()))
        }

        // ---- Linear-memory constructors ----
        // Only when the slice resolved to real text (K2): an unresolved
        // one would have to invent the contents.
        //
        // Written fully qualified deliberately. `imports::collapse` only
        // shortens a two-segment `soroban_sdk::X`, and a module may also
        // locally define a colliding `Symbol`, so the qualified path is
        // the spelling that always compiles.
        KnownOp::SymbolNew {
            resolved: Some(text),
            ..
        } => {
            let lit = syn::LitStr::new(text, proc_macro2::Span::call_site());
            Some(parse_quote!(soroban_sdk::Symbol::new(#eb, #lit)))
        }
        // `String::from_str` hands the host the literal's bytes with
        // `string_new_from_linear_memory`; `resolved` holds exactly those
        // bytes (strict UTF-8, never lossy), so the call is the same one.
        KnownOp::StringNew {
            resolved: Some(text),
            ..
        } => {
            let lit = syn::LitStr::new(text, proc_macro2::Span::call_site());
            Some(parse_quote!(soroban_sdk::String::from_str(#eb, #lit)))
        }
        // `Bytes::from_slice` hands the host the slice's bytes with
        // `bytes_new_from_linear_memory`, and `resolved` holds exactly the
        // bytes the binary's call reads.
        KnownOp::BytesNew {
            resolved: Some(bytes),
            ..
        } => {
            let items = bytes.iter().map(|b| syn::LitInt::new(&format!("{b:#04x}"), proc_macro2::Span::call_site()));
            Some(parse_quote!(soroban_sdk::Bytes::from_slice(#eb, &[#(#items),*])))
        }

        // ---- Guest memory routines ----
        // The body of `memcpy`/`memmove`/`memset`, as the `core` primitive
        // rustc lowers to that call. The operands are the routine's own
        // 32-bit parameters; on wasm32 `as usize` and the cast to a pointer
        // keep every bit, and `as u8` is the routine's own `c as u8`.
        // `memcpy` prints as `copy` too: LLVM's `memcpy` admits two identical
        // regions, where `copy_nonoverlapping` would be undefined and `copy`
        // writes what the routine writes. On every other call they agree.
        KnownOp::MemCopy { dst, src, len, .. } => {
            let (d, s, n) = (ctx.value_ref(*dst), ctx.value_ref(*src), ctx.value_ref(*len));
            Some(parse_quote!(unsafe { core::ptr::copy(#s as *const u8, #d as *mut u8, #n as usize) }))
        }
        KnownOp::MemFill { dst, byte, len } => {
            let (d, b, n) = (ctx.value_ref(*dst), ctx.value_ref(*byte), ctx.value_ref(*len));
            Some(parse_quote!(unsafe { core::ptr::write_bytes(#d as *mut u8, #b as u8, #n as usize) }))
        }
        // No `core` primitive returns `memcmp`'s value, so the routine's own
        // loop, as an iterator: the first unequal pair's difference, each
        // byte unsigned, or 0. Read through slices, whose one precondition
        // beyond the routine's — a non-null address — every caller meets:
        // `memcmp` is reached only from slice comparisons.
        KnownOp::MemCompare { a, b, len } => {
            let (a, b, n) = (ctx.value_ref(*a), ctx.value_ref(*b), ctx.value_ref(*len));
            Some(parse_quote!(unsafe {
                core::iter::zip(
                    core::slice::from_raw_parts(#a as *const u8, #n as usize),
                    core::slice::from_raw_parts(#b as *const u8, #n as usize),
                )
                .find(|(x, y)| x != y)
                .map_or(0i32, |(x, y)| i32::from(*x) - i32::from(*y))
            }))
        }

        // Everything else stays an honest hole (later waves).
        _ => None,
    }
}

/// Whether [`known_op_expr`]'s chain for `op` renders **none** of the
/// operands the IR records for it.
///
/// Almost every lowering reads its operands, so almost every op answers
/// `false`. The exception is a linear-memory constructor whose contents
/// resolved: `symbol_new(lm_pos, len)` becomes
/// `Symbol::new(&e, "attestation_domain")`, which names the recovered text
/// and never mentions the pointer or the length.
///
/// [`super::liveness`] needs this. It counts reads from the IR, so without
/// it the discarded `lm_pos` keeps a whole chain of address arithmetic
/// alive — and that chain is unrecovered, so it emits as `todo!()` and the
/// entrypoint panics before reaching the `Symbol::new` that made the chain
/// dead in the first place. `attestation`'s `domain` is the witness.
///
/// **Any lowering added above that drops operands must be listed here.**
/// The pairing is checked by `an_operand_dropping_lowering_is_declared`.
pub(crate) fn ignores_operands(op: &KnownOp) -> bool {
    matches!(
        op,
        KnownOp::SymbolNew { resolved: Some(_), .. }
            | KnownOp::StringNew { resolved: Some(_), .. }
            | KnownOp::BytesNew { resolved: Some(_), .. }
    )
}

/// The values the chain for `op` prints, when that is narrower than the
/// operands the IR records. `None` means every operand is read: the op is
/// not in the family below, or it will not render as a chain at all.
///
/// The storage family is why this exists. Its chains print the tier as a
/// method name, never the durability value; a key the enum-key pass named
/// as its variant, never the converter result; a TTL amount the recognizer
/// resolved as the number. Counting those as reads left a dead
/// `let v9 = ();` and `let v15 = 1i64;` above every storage call.
pub(crate) fn rendered_operands(
    func: &sordec_ir::HighFunction,
    op: &KnownOp,
) -> Option<Vec<sordec_common::ValueId>> {
    use sordec_common::ValueId;
    let key_reads = |key: ValueId, resolved: &Option<EnumKey>| -> Vec<ValueId> {
        match resolved {
            Some(ek) => ek.payload.clone(),
            None => vec![key],
        }
    };
    // Mirrors [`ledger_count`].
    let amount = |operand: ValueId, resolved: Option<u32>| -> Vec<ValueId> {
        if resolved.is_some() {
            return Vec::new();
        }
        match func.bindings.get(operand).map(|b| &b.expr) {
            Some(sordec_ir::Expr::Semantic(sordec_ir::SemanticOp::Known(KnownOp::ValEncodeSmall {
                ty: sordec_ir::KnownType::U32,
                value,
            }))) => vec![*value],
            _ => vec![operand],
        }
    };
    match op {
        KnownOp::StorageGet { tier, key, resolved_key, missing, .. } => {
            tier_method(tier)?;
            let mut reads = key_reads(*key, resolved_key);
            if let sordec_ir::Missing::Or(default) = missing {
                reads.push(*default);
            }
            Some(reads)
        }
        KnownOp::StorageSet { tier, key, resolved_key, value, .. } => {
            tier_method(tier)?;
            let mut reads = key_reads(*key, resolved_key);
            reads.push(*value);
            Some(reads)
        }
        KnownOp::StorageHas { probe: false, tier, key, resolved_key, .. }
        | KnownOp::StorageRemove { tier, key, resolved_key, .. } => {
            tier_method(tier)?;
            Some(key_reads(*key, resolved_key))
        }
        KnownOp::StorageExtendTtl {
            tier,
            key,
            resolved_key,
            threshold,
            extend_to,
            resolved_threshold,
            resolved_extend_to,
            ..
        } => {
            tier_method(tier)?;
            let mut reads = key_reads(*key, resolved_key);
            reads.extend(amount(*threshold, *resolved_threshold));
            reads.extend(amount(*extend_to, *resolved_extend_to));
            Some(reads)
        }
        KnownOp::ExtendCurrentContractInstanceAndCodeTtl {
            threshold,
            extend_to,
            resolved_threshold,
            resolved_extend_to,
        } => {
            let mut reads = amount(*threshold, *resolved_threshold);
            reads.extend(amount(*extend_to, *resolved_extend_to));
            Some(reads)
        }
        // `with_current_contract` names no deployer: the current address
        // it stands for is not read.
        KnownOp::DeployOp {
            kind: DeployOpKind::CreateContractWithConstructor,
            args,
        } if deploy_typed(func, args) && is_current_address(func, args[0]) => Some(args[1..].to_vec()),
        _ => None,
    }
}

/// Whether `value`'s recovered type, known or inferred, is one `want` accepts.
fn has_type(
    func: &sordec_ir::HighFunction,
    value: sordec_common::ValueId,
    want: impl Fn(&KnownType) -> bool,
) -> bool {
    matches!(
        func.bindings.get(value).map(|b| &b.ty),
        Some(IrType::Known(t) | IrType::Inferred(t)) if want(t)
    )
}

/// `create_contract_with_constructor`'s four operands each carry the type
/// `deploy_v2` and its deployer take: `(Address, BytesN<32>, BytesN<32>, Vec<_>)`.
fn deploy_typed(func: &sordec_ir::HighFunction, args: &[sordec_common::ValueId]) -> bool {
    let [deployer, wasm_hash, salt, ctor_args] = args[..] else { return false };
    has_type(func, deployer, |t| matches!(t, KnownType::Address))
        && has_type(func, wasm_hash, |t| matches!(t, KnownType::BytesN(32)))
        && has_type(func, salt, |t| matches!(t, KnownType::BytesN(32)))
        && has_type(func, ctor_args, |t| matches!(t, KnownType::Vec(_)))
}

/// Whether `value` is the current contract's address, through renames.
fn is_current_address(func: &sordec_ir::HighFunction, mut value: sordec_common::ValueId) -> bool {
    loop {
        match func.bindings.get(value).map(|b| &b.expr) {
            Some(sordec_ir::Expr::Use(inner)) => value = *inner,
            Some(sordec_ir::Expr::Semantic(sordec_ir::SemanticOp::Known(KnownOp::GetCurrentContractAddress))) => {
                return true;
            }
            _ => return false,
        }
    }
}

/// The tier method (`persistent`/`instance`/`temporary`), or `None` for an
/// `Unknown` tier — naming an unproven tier would be a guess (K2).
/// `Inferred` is evidence-based, not a default, so it is emitted.
/// The `Option`-returning read an `if let Some(..)` tests: `get(&k)` with
/// the payload type spelled when it was recovered.
///
/// `Storage::get` is generic in its payload, and the pattern binding pins
/// nothing — `if let Some(b) = …get(&k) { b >> 64 }` is `type annotations
/// needed`. So the turbofish carries the type, written as the source writes
/// it: the key's enum by name when the key was resolved, `_` otherwise.
pub(crate) fn option_read(
    ctx: &FnCtx,
    op: &KnownOp,
    payload: Option<syn::Type>,
) -> Option<syn::Expr> {
    let KnownOp::StorageGet { tier, key, resolved_key, .. } = op else {
        return None;
    };
    let e = ctx.env();
    let tier = tier_method(tier)?;
    let k = key_expr(ctx, *key, resolved_key);
    Some(match payload {
        Some(ty) => {
            let key_ty: syn::Type = match resolved_key {
                Some(ek) => {
                    let name = ident(&ek.enum_name);
                    parse_quote!(#name)
                }
                None => parse_quote!(_),
            };
            parse_quote!(#e.storage().#tier().get::<#key_ty, #ty>(&#k))
        }
        None => parse_quote!(#e.storage().#tier().get(&#k)),
    })
}

fn tier_method(tier: &StorageTier) -> Option<syn::Ident> {
    let known = match tier {
        StorageTier::Known(t) | StorageTier::Inferred(t) => t,
        StorageTier::Unknown(_) => return None,
    };
    Some(match known {
        KnownTier::Persistent => format_ident!("persistent"),
        KnownTier::Temporary => format_ident!("temporary"),
        KnownTier::Instance => format_ident!("instance"),
    })
}

/// A TTL ledger count as the source wrote it. The operand is a `U32Val`;
/// the SDK method takes the `u32` inside it. The count the TTL recognizer
/// witnessed prints as that number; otherwise a recognized `U32Val`
/// encode prints its payload, and only an operand that is neither prints
/// as the raw value.
fn ledger_count(ctx: &FnCtx, operand: sordec_common::ValueId, resolved: Option<u32>) -> syn::Expr {
    if let Some(n) = resolved {
        return parse_quote!(#n);
    }
    let payload = ctx
        .func
        .bindings
        .get(operand)
        .and_then(|b| match &b.expr {
            sordec_ir::Expr::Semantic(sordec_ir::SemanticOp::Known(KnownOp::ValEncodeSmall {
                ty: sordec_ir::KnownType::U32,
                value,
            })) => Some(*value),
            _ => None,
        });
    ctx.value_ref(payload.unwrap_or(operand))
}

/// The storage key: the recovered `Enum::Variant(payload)` when the
/// enum-key pass named it, else the raw key value reference.
fn key_expr(ctx: &FnCtx, key: sordec_common::ValueId, resolved: &Option<EnumKey>) -> syn::Expr {
    let Some(ek) = resolved else {
        return ctx.value_ref(key);
    };
    let enum_name = ident(&ek.enum_name);
    let variant = ident(&ek.variant);
    if ek.payload.is_empty() {
        parse_quote!(#enum_name::#variant)
    } else {
        // `arg_ref`, not `value_ref`: a payload is *moved* into the
        // variant, so a value the function reads again afterwards has to be
        // cloned here — `DataKey::Shares(to)` followed by any later use of
        // `to` is dex-liquidity-pool's last compile error. The same rule
        // every other by-value position already goes through.
        // A machine-word field the value has the other sign of is cast: the
        // wasm word carries no sign, so the cast keeps every bit.
        let fields = variant_fields(ctx, ek);
        let payload: Vec<syn::Expr> = ek
            .payload
            .iter()
            .enumerate()
            .map(|(i, v)| {
                fields
                    .as_ref()
                    .filter(|f| f.len() == ek.payload.len())
                    .and_then(|f| crate::rust::expr::machine_word(&f[i]))
                    .and_then(|want| crate::rust::expr::sign_cast(ctx, *v, &want))
                    .unwrap_or_else(|| ctx.arg_ref(*v))
            })
            .collect();
        // A variant whose single declared field is a struct is handed that
        // struct, not the struct's fields. On the wire there is no
        // difference — the recogniser reads the flattened map and hands
        // back one value per field — but `DataKey::Allowance(from, spender)`
        // is two arguments to a variant that takes one.
        if let Some(fields) = struct_payload_fields(ctx, ek, payload.len()) {
            let struct_name = ident(&fields.0);
            let names: Vec<syn::Ident> = fields.1.iter().map(|f| ident(f)).collect();
            return parse_quote!(
                #enum_name::#variant(#struct_name { #(#names: #payload),* })
            );
        }
        parse_quote!(#enum_name::#variant(#(#payload),*))
    }
}

/// The declared field types of a key variant, when the enum is known.
fn variant_fields(ctx: &FnCtx, ek: &EnumKey) -> Option<Vec<sordec_ir::TypeRef>> {
    let case = ctx
        .reg
        .unions
        .iter()
        .find(|u| u.name == ek.enum_name)?
        .cases
        .iter()
        .find(|c| c.name == ek.variant)?;
    Some(case.fields.clone())
}

/// Whether `v` prints as a vec of some named element type other than
/// `Val`: one that is not yet the `Vec<Val>` a host argument takes.
fn vec_of_named(ctx: &FnCtx, v: sordec_common::ValueId) -> bool {
    let at = ctx.fold_target(v);
    matches!(
        ctx.func.bindings.get(at).map(|b| &b.ty),
        Some(IrType::Known(KnownType::Vec(inner)) | IrType::Inferred(KnownType::Vec(inner)))
            if matches!(inner.as_ref(), IrType::Known(k) | IrType::Inferred(k) if *k != KnownType::Val)
    )
}

/// A vec's elements, with the conversion a mixed one needs.
///
/// `soroban_sdk::vec!` builds a `Vec<T>` from an array, so every element
/// has to be the same `T`. Where the recovered types agree that is what
/// they are, and the elements render plainly. Where they do not — an event
/// topic vec holding a `Symbol` and two `Address`es — the vec is a
/// `Vec<Val>` and each element converts into one.
///
/// A value we could not type is left alone: it renders as a hole, whose
/// `!` already coerces to anything, and converting it would claim a
/// conversion of nothing.
///
/// The path is written out in full; [`crate::rust::imports`] shortens it
/// and adds the `use` when it collapses the module's paths.
fn vec_items(ctx: &FnCtx, values: &[sordec_common::ValueId]) -> (Vec<syn::Expr>, bool) {
    // An untyped element counts as a `Val`, because that is what it is
    // emitted as — the hole policy names an unrecovered type `Val`, and a
    // parameter carrying one is declared `Val` in the helper's signature.
    // Reading it as "no information" instead let a vec of
    // `Val, Address, Address` look uniform, and `vec!` then picked
    // `Address`.
    let base = |v: &sordec_common::ValueId| match ctx.func.bindings.get(*v).map(|b| &b.ty) {
        Some(IrType::Known(k) | IrType::Inferred(k)) => k.clone(),
        _ => KnownType::Val,
    };
    let known: Vec<KnownType> = values.iter().map(&base).collect();
    let mixed = known.windows(2).any(|w| w[0] != w[1]);
    let items = values
        .iter()
        .map(|v| {
            let x = ctx.arg_ref(*v);
            match base(v) {
                k if mixed && k != KnownType::Val => {
                    // `into_val` takes `&Env`; `env_borrow` is the one that
                    // spells the borrow where this function owns its env
                    // and the bare name where it was handed a reference.
                    let e = ctx.env_borrow();
                    parse_quote!(
                        soroban_sdk::IntoVal::<soroban_sdk::Env, soroban_sdk::Val>::into_val(
                            &#x, #e
                        )
                    )
                }
                _ => x,
            }
        })
        .collect();
    (items, mixed)
}

/// The struct a key variant's single declared field names, and that
/// struct's field names in declared order — when the recovered payload has
/// exactly one value per field.
///
/// `None` for every other shape: a variant with loose fields, a payload
/// whose arity disagrees with the struct's, or a field type that is not a
/// declared struct. Each of those would be a guess about which value goes
/// where, and a key assembled wrongly reads a different storage slot.
fn struct_payload_fields(
    ctx: &FnCtx,
    ek: &EnumKey,
    payload_len: usize,
) -> Option<(String, Vec<String>)> {
    let case = ctx
        .reg
        .unions
        .iter()
        .find(|u| u.name == ek.enum_name)?
        .cases
        .iter()
        .find(|c| c.name == ek.variant)?;
    let [sordec_ir::TypeRef::UserDefined(id)] = case.fields.as_slice() else {
        return None;
    };
    let def = ctx.reg.structs.iter().find(|s| s.id == *id)?;
    (def.fields.len() == payload_len).then(|| {
        (
            def.name.clone(),
            def.fields.iter().map(|f| f.name.clone()).collect(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::UnknownReason;

    #[test]
    fn known_and_inferred_tiers_name_the_method() {
        assert_eq!(
            tier_method(&StorageTier::Known(KnownTier::Persistent)).unwrap().to_string(),
            "persistent"
        );
        // Inferred is evidence-based, not a default guess — it is emitted.
        assert_eq!(
            tier_method(&StorageTier::Inferred(KnownTier::Instance)).unwrap().to_string(),
            "instance"
        );
        assert_eq!(
            tier_method(&StorageTier::Known(KnownTier::Temporary)).unwrap().to_string(),
            "temporary"
        );
    }

    #[test]
    fn a_literal_index_decodes_only_from_a_u32_val() {
        // `account`'s `args.get(2)`.
        assert_eq!(u32_val_payload(0x2_0000_0004), Some(2));
        assert_eq!(u32_val_payload(4), Some(0));
        assert_eq!(u32_val_payload(0xFFFF_FFFF_0000_0004_u64 as i64), None, "negative: not a u32");
        assert_eq!(u32_val_payload(0x2_0000_0005), None, "another tag");
        assert_eq!(u32_val_payload(2), None, "a bare integer is not the encoded index");
    }

    #[test]
    fn unknown_tier_is_a_hole_not_a_guess() {
        // K2: naming an unproven tier would be a guess, so the whole op
        // falls back to a hole (`known_op_expr` returns `None`).
        assert!(tier_method(&StorageTier::Unknown(UnknownReason::NoMetadata)).is_none());
    }
}
