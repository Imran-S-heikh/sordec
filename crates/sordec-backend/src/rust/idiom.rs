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
    BufOpKind, ClientInterface, CryptoOpKind, EnumKey, KnownOp, KnownTier, PrngOpKind, StorageTier,
    VecOpKind,
};

use crate::rust::body::FnCtx;
use crate::rust::ty::ident;

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
            let items: Vec<syn::Expr> = values.iter().map(|v| ctx.arg_ref(*v)).collect();
            let e = ctx.env_borrow();
            Some(parse_quote!(soroban_sdk::vec![#e, #(#items),*]))
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
                sordec_ir::Missing::Unwrap => parse_quote!(#e.storage().#tier().get(&#k).unwrap()),
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
        KnownOp::RequireAuthForArgs { address, args } => {
            let a = ctx.value_ref(*address);
            let args: Vec<syn::Expr> = args.iter().map(|v| ctx.value_ref(*v)).collect();
            Some(parse_quote!(#a.require_auth_for_args(#(#args),*)))
        }
        KnownOp::AuthorizeAsCurrContract { auth_entries } => {
            let entries = ctx.value_ref(*auth_entries);
            Some(parse_quote!(#e.authorize_as_current_contract(#entries)))
        }

        // ---- Events ----
        KnownOp::PublishEvent { topics, data } => {
            let topics: Vec<syn::Expr> = topics.iter().map(|v| ctx.value_ref(*v)).collect();
            let data = ctx.value_ref(*data);
            // Topics are a tuple. The trailing comma is what makes a single
            // topic the 1-tuple `(t,)` Soroban's `Topics` needs, rather than
            // a parenthesised expression `(t)`; it is equally valid for the
            // multi-topic `(a, b,)` and zero-topic `()` forms.
            Some(parse_quote!(#e.events().publish((#(#topics,)*), #data)))
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

        // ---- Ledger context ----
        KnownOp::GetLedgerSequence => Some(parse_quote!(#e.ledger().sequence())),
        KnownOp::GetLedgerTimestamp => Some(parse_quote!(#e.ledger().timestamp())),
        KnownOp::GetLedgerProtocolVersion => Some(parse_quote!(#e.ledger().protocol_version())),
        KnownOp::GetLedgerNetworkId => Some(parse_quote!(#e.ledger().network_id())),
        KnownOp::GetMaxLiveUntilLedger => Some(parse_quote!(#e.ledger().max_live_until_ledger())),
        KnownOp::GetCurrentContractAddress => Some(parse_quote!(#e.current_contract_address())),

        // ---- Host panic ----
        KnownOp::PanicWithError { error } => {
            let err = ctx.value_ref(*error);
            Some(parse_quote!(soroban_sdk::panic_with_error!(#e, #err)))
        }

        // ---- Recovered contract-error constant ----
        // A resolved `#[contracterror]` variant renders as its path; an
        // unresolved code falls through to an honest hole (the pass only
        // ever produces resolved variants today).
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
            let [key, msg, sig] = args[..] else { return None };
            let (key, msg, sig) = (ctx.value_ref(key), ctx.value_ref(msg), ctx.value_ref(sig));
            Some(parse_quote!(#e.crypto().ed25519_verify(&#key, &#msg, &#sig)))
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
        KnownOp::BufOp {
            kind: BufOpKind::BytesLen,
            args,
        } => {
            let bytes = ctx.value_ref(*args.first()?);
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
    matches!(op, KnownOp::SymbolNew { resolved: Some(_), .. })
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
        _ => None,
    }
}

/// The tier method (`persistent`/`instance`/`temporary`), or `None` for an
/// `Unknown` tier — naming an unproven tier would be a guess (K2).
/// `Inferred` is evidence-based, not a default, so it is emitted.
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
        let payload: Vec<syn::Expr> = ek.payload.iter().map(|v| ctx.arg_ref(*v)).collect();
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
    fn unknown_tier_is_a_hole_not_a_guess() {
        // K2: naming an unproven tier would be a guess, so the whole op
        // falls back to a hole (`known_op_expr` returns `None`).
        assert!(tier_method(&StorageTier::Unknown(UnknownReason::NoMetadata)).is_none());
    }
}
