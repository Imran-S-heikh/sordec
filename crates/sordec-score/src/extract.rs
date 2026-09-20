//! Source-side semantic-fact extraction.
//!
//! Walks each function body and recognizes the SDK's fixed, idiomatic
//! method chains — the source-side analogue of the pipeline's recognizers —
//! emitting [`SemanticFact`]s. A per-function [`LetResolver`] threads
//! `let`-bound values through so a storage key written the idiomatic way
//! (`let key = DataKey::Balance(addr); … .get(&key)`) resolves to its
//! variant path even though it is used more than once.

use std::collections::HashMap;

use syn::visit::{self, Visit};
use syn::{Block, Expr, ImplItem, Item};

use crate::canon;
use crate::facts::{AuthKind, LedgerKind, PanicKind, SemanticFact, StorageOp, Tier};

/// Extract every semantic fact from a source file.
pub(crate) fn extract(file: &syn::File) -> Vec<SemanticFact> {
    let mut bodies = Vec::new();
    for item in &file.items {
        collect_bodies(item, &mut bodies);
    }
    let mut facts = Vec::new();
    for body in bodies {
        let resolver = LetResolver::build(body);
        let mut visitor = SemanticVisitor {
            facts: &mut facts,
            resolver: &resolver,
        };
        visitor.visit_block(body);
    }
    facts
}

/// Gather every function body (free functions + impl methods, recursing
/// into inline modules).
fn collect_bodies<'a>(item: &'a Item, out: &mut Vec<&'a Block>) {
    match item {
        Item::Fn(item_fn) => out.push(&item_fn.block),
        Item::Impl(item_impl) => {
            for impl_item in &item_impl.items {
                if let ImplItem::Fn(method) = impl_item {
                    out.push(&method.block);
                }
            }
        }
        Item::Mod(item_mod) => {
            if let Some((_, items)) = &item_mod.content {
                for nested in items {
                    collect_bodies(nested, out);
                }
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------
// Let-binding resolution
// ---------------------------------------------------------------------

/// Function-scoped `let ident = expr` bindings, used to resolve a value
/// (a storage key, a client) back to its constructing expression.
struct LetResolver<'a> {
    bindings: HashMap<String, &'a Expr>,
}

impl<'a> LetResolver<'a> {
    fn build(block: &'a Block) -> Self {
        let mut collector = BindingCollector {
            bindings: HashMap::new(),
        };
        collector.visit_block(block);
        Self {
            bindings: collector.bindings,
        }
    }

    /// Resolve a key argument to its `Enum::Variant` path, following local
    /// bindings and peeling cosmetic wrappers. `None` when it is not a
    /// locally-provable variant constructor.
    fn resolve_key(&self, arg: &'a Expr) -> Option<String> {
        let mut expr = canon::cosmetic_strip(arg);
        for _ in 0..MAX_RESOLVE_HOPS {
            if let Some(path) = canon::enum_variant_path(expr) {
                return Some(path);
            }
            let bound = single_ident(expr).and_then(|name| self.bindings.get(&name))?;
            expr = canon::cosmetic_strip(bound);
        }
        None
    }

    /// Resolve an expression to its final bound form (cosmetic wrappers
    /// peeled, local bindings followed).
    fn resolve_expr(&self, expr: &'a Expr) -> &'a Expr {
        let mut current = canon::cosmetic_strip(expr);
        for _ in 0..MAX_RESOLVE_HOPS {
            match single_ident(current).and_then(|name| self.bindings.get(&name)) {
                Some(bound) => current = canon::cosmetic_strip(bound),
                None => break,
            }
        }
        current
    }
}

/// Cap on binding-resolution hops, guarding against a `let a = b; let b = a`
/// cycle.
const MAX_RESOLVE_HOPS: usize = 8;

/// The single identifier of a bare path expression (`key`), or `None`.
fn single_ident(expr: &Expr) -> Option<String> {
    if let Expr::Path(expr_path) = expr
        && expr_path.qself.is_none()
        && expr_path.path.segments.len() == 1
    {
        return Some(expr_path.path.segments[0].ident.to_string());
    }
    None
}

/// Collects `let ident = expr` bindings across a function body (last
/// binding of a name wins).
struct BindingCollector<'a> {
    bindings: HashMap<String, &'a Expr>,
}

impl<'a> Visit<'a> for BindingCollector<'a> {
    fn visit_local(&mut self, node: &'a syn::Local) {
        if let syn::Pat::Ident(pat_ident) = &node.pat
            && let Some(init) = &node.init
        {
            self.bindings
                .insert(pat_ident.ident.to_string(), &init.expr);
        }
        visit::visit_local(self, node);
    }
}

// ---------------------------------------------------------------------
// Fact extraction
// ---------------------------------------------------------------------

struct SemanticVisitor<'a> {
    facts: &'a mut Vec<SemanticFact>,
    resolver: &'a LetResolver<'a>,
}

impl<'a> Visit<'a> for SemanticVisitor<'a> {
    fn visit_expr_method_call(&mut self, node: &'a syn::ExprMethodCall) {
        if let Some(fact) = self.method_fact(node) {
            self.facts.push(fact);
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_macro(&mut self, node: &'a syn::Macro) {
        if let Some(segment) = node.path.segments.last() {
            match segment.ident.to_string().as_str() {
                // An *argument-less* `panic!()` is an arg-decode trap, not a
                // Soroban operation, and carries no fact — see `PanicKind` for
                // why, and why the rule is symmetric.
                "panic" if !node.tokens.is_empty() => {
                    self.facts.push(SemanticFact::Panic(PanicKind::Bare));
                }
                "panic" => {}
                // Always authored: it carries an error operand by construction.
                "panic_with_error" => self.facts.push(SemanticFact::Panic(PanicKind::WithError)),
                _ => {}
            }
        }
        visit::visit_macro(self, node);
    }
}

impl<'a> SemanticVisitor<'a> {
    fn method_fact(&self, node: &'a syn::ExprMethodCall) -> Option<SemanticFact> {
        if let Some(fact) = receiver_keyed_fact(node) {
            return Some(fact);
        }

        let method = node.method.to_string();
        match method.as_str() {
            "require_auth" => Some(SemanticFact::Auth(AuthKind::RequireAuth)),
            "require_auth_for_args" => Some(SemanticFact::Auth(AuthKind::RequireAuthForArgs)),
            "authorize_as_current_contract" => {
                Some(SemanticFact::Auth(AuthKind::AuthorizeAsCurrentContract))
            }
            "publish" => Some(SemanticFact::Event),
            "unwrap" | "expect" => Some(SemanticFact::Panic(PanicKind::Unwrap)),
            "current_contract_address" => {
                Some(SemanticFact::Ledger(LedgerKind::CurrentContractAddress))
            }
            "get" | "set" | "has" | "remove" | "extend_ttl" => {
                let tier = storage_tier(&node.receiver)?;
                let op = storage_op(&method);
                let key = self.storage_key(op, tier, node);
                Some(SemanticFact::Storage { op, tier, key })
            }
            "sequence" | "timestamp" if receiver_is_ledger(&node.receiver) => {
                Some(SemanticFact::Ledger(if method == "sequence" {
                    LedgerKind::Sequence
                } else {
                    LedgerKind::Timestamp
                }))
            }
            other if !is_cosmetic(other) && self.is_client_receiver(&node.receiver) => {
                Some(SemanticFact::CrossContract {
                    method: other.to_string(),
                })
            }
            _ => None,
        }
    }

    /// The resolved storage key for a CRUD/TTL op. Instance TTL extension
    /// takes no key (`instance().extend_ttl(threshold, amount)`); every
    /// other op keys on its first argument.
    fn storage_key(
        &self,
        op: StorageOp,
        tier: Tier,
        node: &'a syn::ExprMethodCall,
    ) -> Option<String> {
        if matches!(op, StorageOp::ExtendTtl) && matches!(tier, Tier::Instance) {
            return None;
        }
        self.resolver.resolve_key(node.args.first()?)
    }

    /// Whether a method-call receiver is (or resolves to) a generated
    /// `*Client::new(...)`.
    fn is_client_receiver(&self, receiver: &'a Expr) -> bool {
        is_client_constructor(self.resolver.resolve_expr(receiver))
    }
}

/// The tier of a `…storage().<tier>()` receiver chain, or `None`.
fn storage_tier(receiver: &Expr) -> Option<Tier> {
    let Expr::MethodCall(tier_call) = receiver else {
        return None;
    };
    let tier = match tier_call.method.to_string().as_str() {
        "persistent" => Tier::Persistent,
        "instance" => Tier::Instance,
        "temporary" => Tier::Temporary,
        _ => return None,
    };
    match tier_call.receiver.as_ref() {
        Expr::MethodCall(storage_call) if storage_call.method == "storage" => Some(tier),
        _ => None,
    }
}

/// Whether a receiver is a `…ledger()` chain.
fn receiver_is_ledger(receiver: &Expr) -> bool {
    matches!(receiver, Expr::MethodCall(call) if call.method == "ledger")
}

/// Facts identified by the **host module their receiver names** rather than by
/// the called method: `….events().<anything>`, `env.crypto().<op>`,
/// `env.prng().<op>`.
///
/// Keying on the method name alone missed whole APIs. SDK v23's
/// `#[contractevent]` emits `SetAdmin { … }.publish(&e)`, but v22's
/// `TokenUtils` has **one named method per event** —
/// `TokenUtils::new(&e).events().mint(admin, to, amount)`. token-v22's seven
/// emissions produced *zero* facts, so the five our reconstruction correctly
/// recovered scored as fabrications against an original credited with none.
/// Crypto and PRNG have the same shape: an open-ended set of operation names
/// hanging off one stable receiver.
///
/// Consulted **before** the method-name match in [`SemanticVisitor::method_fact`],
/// which prevents double-firing with the `"publish"` arm and sidesteps an
/// ordering hazard: the storage arm runs `storage_tier(&node.receiver)?`, whose
/// `?` returns from `method_fact` entirely, so a host op named `get` or `set`
/// would otherwise yield *nothing* rather than falling through.
fn receiver_keyed_fact(node: &syn::ExprMethodCall) -> Option<SemanticFact> {
    let Expr::MethodCall(receiver) = node.receiver.as_ref() else {
        return None;
    };
    let op = || node.method.to_string();
    match receiver.method.to_string().as_str() {
        "events" => Some(SemanticFact::Event),
        "crypto" => Some(SemanticFact::Crypto { op: op() }),
        "prng" => Some(SemanticFact::Prng { op: op() }),
        _ => None,
    }
}

/// Whether an expression is a `*Client::new(...)` constructor call.
fn is_client_constructor(expr: &Expr) -> bool {
    let Expr::Call(call) = expr else {
        return false;
    };
    let Expr::Path(func) = call.func.as_ref() else {
        return false;
    };
    let segments: Vec<String> = func
        .path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect();
    let last_is_new = segments.last().is_some_and(|name| name == "new");
    let has_client = segments.iter().any(|name| name.ends_with("Client"));
    last_is_new && has_client
}

fn storage_op(method: &str) -> StorageOp {
    match method {
        "get" => StorageOp::Get,
        "set" => StorageOp::Set,
        "has" => StorageOp::Has,
        "remove" => StorageOp::Remove,
        "extend_ttl" => StorageOp::ExtendTtl,
        // `storage_op` is only called for the five matched names.
        other => unreachable!("not a storage op: {other}"),
    }
}

fn is_cosmetic(method: &str) -> bool {
    matches!(method, "clone" | "into" | "as_ref" | "to_owned" | "borrow")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts_of(src: &str) -> Vec<String> {
        let file: syn::File = syn::parse_str(src).expect("source parses");
        let mut keys: Vec<String> = extract(&file).iter().map(|f| f.key_with(true)).collect();
        keys.sort();
        keys
    }

    #[test]
    fn resolves_a_multi_use_storage_key_through_a_local() {
        let keys = facts_of(
            r#"
            fn read(e: Env, addr: Address) -> i128 {
                let key = DataKey::Balance(addr);
                let v = e.storage().persistent().get::<DataKey, i128>(&key);
                e.storage().persistent().extend_ttl(&key, 1, 2);
                0
            }
            "#,
        );
        assert!(keys.contains(&"storage:get:persistent:DataKey::Balance".to_string()));
        assert!(keys.contains(&"storage:extend_ttl:persistent:DataKey::Balance".to_string()));
    }

    #[test]
    fn instance_extend_ttl_has_no_key() {
        let keys = facts_of(
            r#"
            fn bump(e: Env) {
                e.storage().instance().extend_ttl(100, 200);
            }
            "#,
        );
        assert_eq!(keys, vec!["storage:extend_ttl:instance:?".to_string()]);
    }

    #[test]
    fn recognizes_auth_event_and_panic() {
        let keys = facts_of(
            r#"
            fn f(admin: Address, e: Env) {
                admin.require_auth();
                SetAdmin { admin }.publish(&e);
                if true { panic!("no"); }
            }
            "#,
        );
        assert!(keys.contains(&"auth:require_auth".to_string()));
        assert!(keys.contains(&"event".to_string()));
        assert!(keys.contains(&"panic:bare".to_string()));
    }

    /// Count of `"event"` facts — the tests below assert on counts rather than
    /// membership, because a double-count is invisible to `contains`.
    fn event_count(src: &str) -> usize {
        facts_of(src).iter().filter(|key| *key == "event").count()
    }

    #[test]
    fn v22_token_utils_events_are_recognized() {
        // SDK v22 has one *named method per event*, so keying on the method
        // name alone saw none of these. token-v22's seven emissions produced
        // zero facts, which scored our five correctly-recovered events as
        // fabrications against an original credited with none.
        assert_eq!(
            event_count(
                r#"
                fn f(e: Env, admin: Address, to: Address, amount: i128) {
                    TokenUtils::new(&e).events().mint(admin, to, amount);
                    TokenUtils::new(&e).events().transfer(admin, to, amount);
                }
                "#
            ),
            2
        );
    }

    #[test]
    fn v23_contractevent_publish_is_still_recognized() {
        // The other spelling: a `#[contractevent]` struct literal receiver,
        // which is *not* an `.events()` call, so it needs the `"publish"` arm.
        assert_eq!(
            event_count(r#"fn f(e: Env, admin: Address) { SetAdmin { admin }.publish(&e); }"#),
            1
        );
    }

    #[test]
    fn an_events_publish_chain_yields_exactly_one_fact() {
        // T16's original concern, pinned rather than reasoned about: this form
        // matches *both* rules — receiver is `.events()` and the method is
        // `publish` — so it is the one shape that could double-count.
        assert_eq!(
            event_count(r#"fn f(e: Env, t: Symbol, d: i128) { e.events().publish((t,), d); }"#),
            1
        );
    }

    #[test]
    fn crypto_ops_are_recognized_and_named() {
        // Named, unlike `Event`: sha256 and keccak256 are different security
        // properties and must not compare equal. The name is recoverable —
        // the pipeline already identifies these as `crypto::ComputeHashSha256`
        // and friends.
        let keys = facts_of(
            r#"
            fn f(env: Env, m: Bytes, signer: BytesN<32>, sig: BytesN<64>) {
                env.crypto().sha256(&m);
                env.crypto().keccak256(&m);
                env.crypto().ed25519_verify(&signer, &m, &sig);
            }
            "#,
        );
        assert!(keys.contains(&"crypto:sha256".to_string()), "{keys:?}");
        assert!(keys.contains(&"crypto:keccak256".to_string()), "{keys:?}");
        assert!(
            keys.contains(&"crypto:ed25519_verify".to_string()),
            "{keys:?}"
        );
    }

    #[test]
    fn different_crypto_ops_do_not_compare_equal() {
        let sha = facts_of(r#"fn f(e: Env, m: Bytes) { e.crypto().sha256(&m); }"#);
        let keccak = facts_of(r#"fn f(e: Env, m: Bytes) { e.crypto().keccak256(&m); }"#);
        assert_ne!(sha, keccak);
    }

    #[test]
    fn prng_ops_are_recognized() {
        let keys = facts_of(r#"fn f(e: Env, lo: u64, hi: u64) { e.prng().gen_range(lo..=hi); }"#);
        assert_eq!(keys, vec!["prng:gen_range".to_string()]);
    }

    #[test]
    fn an_unrecovered_hole_is_not_a_recovered_fact() {
        // Our emitter has no lowering for crypto host calls yet, so it emits
        // `todo!("crypto::ComputeHashSha256")` — an honest admission of
        // non-recovery. Counting that as a recovered fact would credit us for
        // work not done, the same self-scoring that inflated structure ~10x
        // before T7. The hole names the op, so this is cheap to get wrong.
        let keys = facts_of(r#"fn f() { let _v = todo!("crypto::ComputeHashSha256"); }"#);
        assert!(
            keys.is_empty(),
            "a `todo!` hole must never score as recovery, got {keys:?}"
        );
    }

    #[test]
    fn an_attestation_shaped_contract_yields_five_facts() {
        // The driving fixture, in miniature: 4 crypto + 1 prng. Before T17
        // this contract extracted *zero* facts and read as doing nothing.
        let keys = facts_of(
            r#"
            fn digest(env: Env, m: Bytes) -> BytesN<32> { env.crypto().sha256(&m).into() }
            fn digest_keccak(env: Env, m: Bytes) -> BytesN<32> { env.crypto().keccak256(&m).into() }
            fn attest(env: Env, s: BytesN<32>, m: Bytes, g: BytesN<64>) {
                env.crypto().ed25519_verify(&s, &m, &g);
            }
            fn check(env: Env, m: Bytes) -> BytesN<32> { env.crypto().sha256(&m).into() }
            fn challenge(env: Env, lo: u64, hi: u64) -> u64 { env.prng().gen_range(lo..=hi) }
            "#,
        );
        assert_eq!(keys.len(), 5, "{keys:?}");
    }

    #[test]
    fn a_method_on_a_non_events_receiver_is_not_an_event() {
        // The rule keys on the receiver being `.events()`, not on any method
        // called `mint` anywhere.
        assert_eq!(
            event_count(r#"fn f(e: Env, c: Address) { some_helper(&e).mint(c, 1); }"#),
            0
        );
    }

    #[test]
    fn panic_macro_is_recognized_but_its_expanded_call_is_not() {
        // This asymmetry is *why* the semantic category stays on the
        // pre-expansion basis (score-2.0.0 T9, `BasisProfile::rfp_default`).
        //
        // Panics are recognized only in macro form, via `visit_macro`.
        // `cargo expand` rewrites `panic!()` into a `::core::panicking::*`
        // call this extractor cannot see, so scoring semantic on expanded
        // input silently drops the fact — and drops it from *both* sides
        // indiscriminately, hiding our 60 token-v23 traps and the original's 5
        // authored panics alike.
        //
        // T18 lands on the same precision (0.9091) by a different and much
        // narrower route, so the distinction is worth being precise about: it
        // drops only *argument-less* `panic!()`, and the original's authored
        // panics stay in the denominator as recall misses. The expanded basis
        // would have scored recall 0.526 by deleting the things we failed to
        // recover; T18 scores 0.465 by keeping them and marking them missed.
        // Stricter, not more forgiving.
        let macro_form = facts_of(r#"fn f() { panic!("boom"); }"#);
        assert!(
            macro_form.contains(&"panic:bare".to_string()),
            "the macro form must be recognized: {macro_form:?}"
        );

        let expanded_form = facts_of(r#"fn f() { ::core::panicking::panic_explicit(); }"#);
        assert!(
            !expanded_form.iter().any(|key| key.starts_with("panic:")),
            "expanded panics are invisible to this vocabulary: {expanded_form:?}"
        );

        // When `extract` learns the post-expansion forms, this assertion
        // fails. That is deliberate: the semantic basis decision must be
        // re-argued at that point, not silently inherited. (T16 investigated
        // and left it alone — the pre-expansion basis already keeps the macros
        // visible, so there was nothing to teach.)
    }

    #[test]
    fn an_authored_panic_is_a_fact_but_a_bare_trap_is_not() {
        // T18. A bare `panic!()` is an arg-decode trap the compiler inlined
        // out of the SDK's `try_from_val` — marshalling, not a Soroban
        // operation. token-v23 emits 60 of them against the source's 5
        // authored panics, and both used to key as `panic:bare`, so our traps
        // were credited as recovering their panics.
        assert!(facts_of(r#"fn f() { panic!("insufficient balance"); }"#)
            .contains(&"panic:bare".to_string()));
        assert!(facts_of(r#"fn f(x: i128) { panic!("negative: {}", x); }"#)
            .contains(&"panic:bare".to_string()));

        assert!(
            facts_of(r#"fn f() { panic!(); }"#).is_empty(),
            "a bare trap must not be fact-bearing"
        );
    }

    #[test]
    fn the_bare_panic_rule_is_symmetric() {
        // Not a filter on our own output: it is a property of the macro, so
        // an *original* writing a bare `panic!()` gets no fact either. Pinned
        // because a rule that raises our score is exactly the one a later
        // reader should be able to check is even-handed.
        let mixed = r#"
            fn f(e: Env, a: Address) {
                a.require_auth();
                panic!();
                panic!("real");
            }
        "#;
        let keys = facts_of(mixed);
        assert_eq!(
            keys.iter().filter(|k| *k == "panic:bare").count(),
            1,
            "only the authored panic counts: {keys:?}"
        );
        assert!(keys.contains(&"auth:require_auth".to_string()));
    }

    #[test]
    fn panic_with_error_is_always_authored() {
        // Untouched by T18: it carries an error operand by construction, so
        // there is no argument-less form to confuse with a trap.
        assert!(
            facts_of(r#"fn f(e: Env) { panic_with_error!(&e, Error::Overflow); }"#)
                .contains(&"panic:with_error".to_string())
        );
    }

    #[test]
    fn cross_contract_needs_a_client_receiver() {
        // `.transfer` on a token client is a cross-contract call…
        let client = facts_of(
            r#"
            fn f(e: Env, token: Address, from: Address, to: Address, amount: i128) {
                token::Client::new(&e, &token).transfer(&from, &to, &amount);
            }
            "#,
        );
        assert!(client.contains(&"xcall:transfer".to_string()));

        // …but a same-named method on a non-client is not.
        let not_client = facts_of(
            r#"
            fn f(thing: Thing) { thing.transfer(1); }
            "#,
        );
        assert!(!not_client.iter().any(|k| k.starts_with("xcall")));
    }

    #[test]
    fn cross_contract_resolves_a_bound_client() {
        let keys = facts_of(
            r#"
            fn f(e: Env, sell_token: Address, to: Address) {
                let client = token::Client::new(&e, &sell_token);
                let bal = client.balance(&to);
            }
            "#,
        );
        assert!(keys.contains(&"xcall:balance".to_string()));
    }

    #[test]
    fn a_swapped_tier_changes_the_fact() {
        let persistent =
            facts_of("fn f(e: Env, k: DataKey) { e.storage().persistent().set(&k, &1); }");
        let instance = facts_of("fn f(e: Env, k: DataKey) { e.storage().instance().set(&k, &1); }");
        assert_ne!(persistent, instance);
    }
}
