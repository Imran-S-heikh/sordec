//! Call graph and entrypoint reachability for the structure category (M4).
//!
//! Structure is scored per **ABI entrypoint**, over the *closure* of code that
//! entrypoint can reach — not per named function. That choice is forced by what
//! survives compilation: entrypoint names are exported and recorded in the
//! spec-XDR, but the names and boundaries of internal helpers are not in the
//! binary at all. rustc inlines a three-line helper out of existence, and the
//! decompiler can only invent a name for whatever function bodies remain. So a
//! metric that compares helpers *by name* is measuring the debug info, not the
//! reconstruction — measurably so: `token-v23` and the same binary with its
//! name section stripped score 0.0522 and 0.0045 under the name-keyed
//! algorithm, an 11.6x swing on identical control flow.
//!
//! This module supplies the other half of the fix. It answers two questions and
//! nothing else:
//!
//! - what functions does this source declare, under keys that don't collide?
//! - what is reachable from this entrypoint, in a deterministic order?
//!
//! It does not extract tokens and does not score. [`crate::structure`] joins a
//! closure to the per-function token streams.
//!
//! ## Owner-qualified keys
//!
//! Functions are keyed `Owner::method` for impl methods and `name` for free
//! functions. Bare names are not unique in practice: `token-v23`'s
//! reconstruction declares **21** functions sharing a bare name (`clone`,
//! `cmp`, `fmt` across derived impls) and the original declares 9. Keyed by
//! bare name they clobber each other in the map, and — worse for a call graph —
//! every call edge to `clone` would route to whichever body happened to win.
//!
//! ## Ambiguity is dropped, never guessed
//!
//! Call *sites* only carry a bare name (`self.helper()`, `Self::helper()`,
//! `helper()`). When that name maps to exactly one declared function the edge
//! is followed; when it maps to several the edge is **dropped**. An unresolved
//! call contributes nothing rather than a guess, which keeps the closure a
//! lower bound on reachability instead of a plausible-looking fiction. Calls to
//! functions with no body here at all — the SDK, host functions — are dropped
//! by the same rule, which is also correct for scoring: they contribute no
//! control flow we are being asked to reproduce.

use std::collections::{BTreeMap, VecDeque};

use syn::visit::{self, Visit};
use syn::{ImplItem, Item};

use crate::canon;

/// An owner-qualified function key: `Owner::method`, or `name` for a free
/// function.
pub(crate) type FnKey = String;

/// One declared function: its body, and the bare names it calls in source
/// order.
struct Node<'a> {
    body: &'a syn::Block,
    calls: Vec<String>,
}

/// The declared functions of one source, plus their call edges.
pub(crate) struct CallGraph<'a> {
    fns: BTreeMap<FnKey, Node<'a>>,
    /// Bare name → every key carrying it. Resolution consults this; a name with
    /// more than one candidate is ambiguous and resolves to nothing.
    by_name: BTreeMap<String, Vec<FnKey>>,
}

impl<'a> CallGraph<'a> {
    /// Build the graph for one parsed source, recursing through inline modules.
    pub(crate) fn build(file: &'a syn::File) -> Self {
        let mut graph = Self {
            fns: BTreeMap::new(),
            by_name: BTreeMap::new(),
        };
        for item in &file.items {
            graph.collect_item(item, None);
        }
        graph
    }

    fn collect_item(&mut self, item: &'a Item, owner: Option<&str>) {
        match item {
            Item::Fn(f) => self.insert(owner, &f.sig.ident, &f.block),
            Item::Impl(imp) => {
                let owner = canon::normalize_type(&imp.self_ty);
                for impl_item in &imp.items {
                    if let ImplItem::Fn(m) = impl_item {
                        self.insert(Some(&owner), &m.sig.ident, &m.block);
                    }
                }
            }
            Item::Mod(m) => {
                if let Some((_, items)) = &m.content {
                    for nested in items {
                        self.collect_item(nested, owner);
                    }
                }
            }
            _ => {}
        }
    }

    fn insert(&mut self, owner: Option<&str>, ident: &syn::Ident, body: &'a syn::Block) {
        let bare = ident.to_string();
        let key: FnKey = match owner {
            Some(owner) => format!("{owner}::{bare}"),
            None => bare.clone(),
        };
        let mut calls = CallVisitor { calls: Vec::new() };
        calls.visit_block(body);
        // A key is `Owner::method`, so a true duplicate means the same method
        // declared twice (a `#[cfg]` pair, say). Last wins, and the name index
        // must not gain a second entry for it.
        if self.fns.insert(key.clone(), Node { body, calls: calls.calls }).is_none() {
            self.by_name.entry(bare).or_default().push(key);
        }
    }

    /// The single function declared under this bare name, or `None` when the
    /// name is undeclared or ambiguous.
    pub(crate) fn resolve(&self, bare: &str) -> Option<&FnKey> {
        match self.by_name.get(bare)?.as_slice() {
            [only] => Some(only),
            _ => None,
        }
    }

    /// This function's body, if it is declared here.
    pub(crate) fn body(&self, key: &FnKey) -> Option<&'a syn::Block> {
        self.fns.get(key).map(|node| node.body)
    }

    /// Every function reachable from the entrypoint named `root`, in
    /// breadth-first discovery order with `root` first.
    ///
    /// BFS discovery order — rather than the declaration or alphabetical order
    /// — is the only ordering derived from the call structure itself, so it is
    /// stable across the two sides even though their helper *names* have
    /// nothing to do with each other.
    ///
    /// Each function appears **once**, however many times it is called.
    /// Splicing a callee in at every call site was measured and is worse: it
    /// multiplies a shared helper by its call count, inflating `token-v23`'s
    /// `transfer` from 8 tokens to 843 and dropping the category from 0.053 to
    /// 0.028. A helper called ten times is one piece of structure, not ten.
    ///
    /// Returns empty when `root` is undeclared or ambiguous.
    pub(crate) fn closure(&self, root: &str) -> Vec<&FnKey> {
        let Some(start) = self.resolve(root) else {
            return Vec::new();
        };
        let mut order = vec![start];
        let mut seen: BTreeMap<&FnKey, ()> = BTreeMap::from([(start, ())]);
        let mut queue = VecDeque::from([start]);

        while let Some(key) = queue.pop_front() {
            let Some(node) = self.fns.get(key) else {
                continue;
            };
            for callee in &node.calls {
                // Unresolvable: undeclared (SDK/host) or ambiguous. Dropped.
                let Some(next) = self.resolve(callee) else {
                    continue;
                };
                if seen.insert(next, ()).is_none() {
                    order.push(next);
                    queue.push_back(next);
                }
            }
        }
        order
    }

    /// How many declared functions share their bare name with another. A
    /// diagnostic for the structure report, not an input to any score.
    pub(crate) fn ambiguous_names(&self) -> usize {
        self.by_name.values().filter(|keys| keys.len() > 1).count()
    }
}

/// Collects the bare callee name of every call in a body, in preorder.
///
/// Both call forms reduce to a bare name: `helper()` and `Self::helper()` via
/// the path's last segment, `self.helper()` via the method ident. That is all a
/// call site carries — resolution to a declared function is
/// [`CallGraph::resolve`]'s job.
struct CallVisitor {
    calls: Vec<String>,
}

impl<'ast> Visit<'ast> for CallVisitor {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*node.func
            && let Some(seg) = path.path.segments.last()
        {
            self.calls.push(seg.ident.to_string());
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        self.calls.push(node.method.to_string());
        visit::visit_expr_method_call(self, node);
    }

    /// Do not descend into an item declared inside a body. A nested `fn` is
    /// collected as its own node by [`CallGraph::collect_item`] only if it is
    /// declared at item level; one nested inside a body is not part of the
    /// enclosing function's control flow unless it is also called, and the call
    /// edge covers that case.
    fn visit_item(&mut self, _: &'ast Item) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    fn graph(src: &str) -> syn::File {
        syn::parse_str(src).expect("parse")
    }

    #[test]
    fn free_functions_key_bare_and_link() {
        let file = graph("fn a() { b(); } fn b() {}");
        let g = CallGraph::build(&file);
        assert_eq!(g.closure("a"), vec![&"a".to_owned(), &"b".to_owned()]);
    }

    #[test]
    fn impl_methods_are_owner_qualified() {
        let file = graph("struct T; impl T { fn go(&self) { self.helper(); } fn helper(&self) {} }");
        let g = CallGraph::build(&file);
        assert_eq!(
            g.closure("go"),
            vec![&"T::go".to_owned(), &"T::helper".to_owned()]
        );
    }

    #[test]
    fn ambiguous_call_edge_is_dropped_not_guessed() {
        // Two `clone`s: a call to `clone` must not pick one.
        let file = graph(
            "struct A; struct B;
             impl A { fn clone(&self) { deep(); } }
             impl B { fn clone(&self) {} }
             fn deep() {}
             fn go() { thing.clone(); }",
        );
        let g = CallGraph::build(&file);
        assert_eq!(g.resolve("clone"), None);
        assert_eq!(g.closure("go"), vec![&"go".to_owned()]);
        assert_eq!(g.ambiguous_names(), 1);
    }

    #[test]
    fn unknown_callees_are_dropped() {
        let file = graph("fn go(e: Env) { e.storage().persistent().get(k); }");
        let g = CallGraph::build(&file);
        assert_eq!(g.closure("go"), vec![&"go".to_owned()]);
    }

    #[test]
    fn direct_recursion_terminates() {
        let file = graph("fn go(n: u32) { go(n - 1); }");
        let g = CallGraph::build(&file);
        assert_eq!(g.closure("go"), vec![&"go".to_owned()]);
    }

    #[test]
    fn mutual_recursion_terminates_and_visits_once() {
        let file = graph("fn a() { b(); } fn b() { a(); }");
        let g = CallGraph::build(&file);
        assert_eq!(g.closure("a"), vec![&"a".to_owned(), &"b".to_owned()]);
    }

    #[test]
    fn diamond_visits_shared_helper_once() {
        let file = graph("fn root() { l(); r(); } fn l() { s(); } fn r() { s(); } fn s() {}");
        let g = CallGraph::build(&file);
        assert_eq!(
            g.closure("root"),
            vec![
                &"root".to_owned(),
                &"l".to_owned(),
                &"r".to_owned(),
                &"s".to_owned()
            ]
        );
    }

    #[test]
    fn order_is_breadth_first_not_declaration_order() {
        // `deep` is declared before `near` but discovered after it.
        let file = graph("fn root() { near(); } fn deep() {} fn near() { deep(); }");
        let g = CallGraph::build(&file);
        assert_eq!(
            g.closure("root"),
            vec![&"root".to_owned(), &"near".to_owned(), &"deep".to_owned()]
        );
    }

    #[test]
    fn inline_modules_are_traversed() {
        let file = graph("mod inner { pub fn helper() {} } fn go() { helper(); }");
        let g = CallGraph::build(&file);
        assert_eq!(
            g.closure("go"),
            vec![&"go".to_owned(), &"helper".to_owned()]
        );
    }

    #[test]
    fn nested_item_fn_is_not_an_edge_of_its_enclosing_body() {
        // `inner` is declared inside `go` but never called: not reachable.
        let file = graph("fn go() { fn inner() { leaf(); } } fn leaf() {}");
        let g = CallGraph::build(&file);
        assert_eq!(g.closure("go"), vec![&"go".to_owned()]);
    }

    #[test]
    fn unresolvable_root_yields_empty_closure() {
        let file = graph("fn a() {}");
        let g = CallGraph::build(&file);
        assert!(g.closure("missing").is_empty());
    }

    #[test]
    fn body_is_retrievable_for_a_declared_key() {
        let file = graph("fn a() { let _ = 1; }");
        let g = CallGraph::build(&file);
        let key = g.resolve("a").expect("declared").clone();
        assert_eq!(g.body(&key).expect("body").stmts.len(), 1);
    }
}
