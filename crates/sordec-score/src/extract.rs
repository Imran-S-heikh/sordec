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
            self.bindings.insert(pat_ident.ident.to_string(), &init.expr);
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
                "panic" => self.facts.push(SemanticFact::Panic(PanicKind::Bare)),
                "panic_with_error" => self.facts.push(SemanticFact::Panic(PanicKind::WithError)),
                _ => {}
            }
        }
        visit::visit_macro(self, node);
    }
}

impl<'a> SemanticVisitor<'a> {
    fn method_fact(&self, node: &'a syn::ExprMethodCall) -> Option<SemanticFact> {
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
    matches!(
        method,
        "clone" | "into" | "as_ref" | "to_owned" | "borrow"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts_of(src: &str) -> Vec<String> {
        let file: syn::File = syn::parse_str(src).expect("source parses");
        let mut keys: Vec<String> = extract(&file).iter().map(SemanticFact::key).collect();
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
        let persistent = facts_of("fn f(e: Env, k: DataKey) { e.storage().persistent().set(&k, &1); }");
        let instance = facts_of("fn f(e: Env, k: DataKey) { e.storage().instance().set(&k, &1); }");
        assert_ne!(persistent, instance);
    }
}
