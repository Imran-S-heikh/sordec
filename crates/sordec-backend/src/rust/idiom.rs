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
//! prove would be a guess (K2).

use quote::format_ident;
use syn::parse_quote;

use sordec_ir::{ClientInterface, EnumKey, KnownOp, KnownTier, StorageTier};

use crate::rust::body::FnCtx;
use crate::rust::ty::ident;

/// The method chain for a recovered op, or `None` when it cannot be
/// rendered honestly (an unmapped op, or an `Unknown` storage tier).
pub(crate) fn known_op_expr(ctx: &FnCtx, op: &KnownOp) -> Option<syn::Expr> {
    let e = ctx.env();
    match op {
        // ---- Storage ----
        KnownOp::StorageGet { tier, key, resolved_key, .. } => {
            let tier = tier_method(tier)?;
            let k = key_expr(ctx, *key, resolved_key);
            Some(parse_quote!(#e.storage().#tier().get(&#k)))
        }
        KnownOp::StorageSet { tier, key, resolved_key, value, .. } => {
            let tier = tier_method(tier)?;
            let k = key_expr(ctx, *key, resolved_key);
            let v = ctx.value_ref(*value);
            Some(parse_quote!(#e.storage().#tier().set(&#k, &#v)))
        }
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
        KnownOp::StorageExtendTtl { tier, key, resolved_key, threshold, extend_to, .. } => {
            let tier = tier_method(tier)?;
            let k = key_expr(ctx, *key, resolved_key);
            let t = ctx.value_ref(*threshold);
            let x = ctx.value_ref(*extend_to);
            Some(parse_quote!(#e.storage().#tier().extend_ttl(&#k, #t, #x)))
        }
        KnownOp::ExtendCurrentContractInstanceAndCodeTtl { threshold, extend_to, .. } => {
            let t = ctx.value_ref(*threshold);
            let x = ctx.value_ref(*extend_to);
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
            Some(parse_quote!(#e.events().publish((#(#topics),*), #data)))
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
            Some(parse_quote!(soroban_sdk::token::Client::new(&#e, &#c).#method(#(&#a),*)))
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

        // Everything else stays an honest hole (later waves).
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
        let payload: Vec<syn::Expr> = ek.payload.iter().map(|v| ctx.value_ref(*v)).collect();
        parse_quote!(#enum_name::#variant(#(#payload),*))
    }
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
