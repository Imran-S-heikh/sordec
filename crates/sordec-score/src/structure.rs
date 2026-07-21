//! Structure category: per-function control-flow-skeleton similarity.
//!
//! Each function is reduced to a preorder token stream of its control-flow
//! constructs — branches and loops, plus the `return` / `break` / `continue`
//! leaves — with straight-line code dropped. Two functions are compared by
//! blending an ordered (LCS) similarity with a multiset similarity of those
//! tokens; the category score is the average over the union of function
//! names, so a missing or extra function contributes `0`.
//!
//! ## Branch unification (the `?`/`match`/`if let` equivalence)
//!
//! `if`, `if let`, and `match` are all emitted as a single `branch:N` token
//! where `N` is the number of arms (`if` without else = 1, `if`/`if let`
//! with else = 2, `match` = arm count). This makes the decompiler's choice
//! between an `if let … else` and a two-arm `match` — the same Option/Result
//! branch — cost nothing, without fragile desugaring detection. The `?`
//! operator is deliberately *not* a skeleton node: it is ubiquitous and its
//! `match`-desugaring is the emitter's to align, so counting it would create
//! spurious mismatches.
//!
//! Loops keep their kind (`loop:while` / `loop:for` / `loop:loop`) because
//! recovering the loop *kind* is exactly what the Phase 3 structurer does,
//! and the scorer should measure that fidelity.

use std::collections::{BTreeMap, BTreeSet};

use syn::visit::{self, Visit};
use syn::{ImplItem, Item};

use crate::metrics;
use crate::report::CategoryScore;
use crate::simil;

/// How much the ordered (LCS) similarity counts vs the multiset similarity
/// when comparing two function skeletons.
const SEQUENCE_WEIGHT: f64 = 0.6;
const MULTISET_WEIGHT: f64 = 0.4;

/// Score the structure category.
pub(crate) fn evaluate(reconstructed: &syn::File, original: &syn::File) -> CategoryScore {
    let recon = skeletons(reconstructed);
    let orig = skeletons(original);

    let names: BTreeSet<&String> = recon.keys().chain(orig.keys()).collect();
    if names.is_empty() {
        return CategoryScore::checked(1.0, metrics::STRUCTURE_WEIGHT)
            .with_note("no functions to compare");
    }

    let mut total = 0.0;
    let mut low = Vec::new();
    for name in &names {
        let sim = match (recon.get(*name), orig.get(*name)) {
            (Some(a), Some(b)) => function_similarity(a, b),
            // Present on only one side — a missing or invented function.
            _ => 0.0,
        };
        total += sim;
        if sim < 0.75 {
            low.push(format!("{name}({sim:.2})"));
        }
    }
    let score = total / names.len() as f64;

    let mut category = CategoryScore::checked(score, metrics::STRUCTURE_WEIGHT).with_note(format!(
        "{} functions ({} original, {} reconstructed)",
        names.len(),
        orig.len(),
        recon.len()
    ));
    if !low.is_empty() {
        low.sort_unstable();
        let shown = low.len().min(8);
        let mut list = low[..shown].join(", ");
        if low.len() > 8 {
            list.push_str(&format!(", … (+{})", low.len() - 8));
        }
        category = category.with_note(format!("low-similarity: {list}"));
    }
    category
}

/// Blend the ordered and multiset similarities of two skeleton streams.
fn function_similarity(a: &[String], b: &[String]) -> f64 {
    let seq = simil::sequence_similarity(a, b);
    let bag = simil::multiset_similarity(&simil::multiset(a), &simil::multiset(b));
    SEQUENCE_WEIGHT * seq + MULTISET_WEIGHT * bag
}

/// Map every function (free functions + all impl methods, recursing into
/// inline modules) to its control-flow-skeleton token stream, keyed by name.
fn skeletons(file: &syn::File) -> BTreeMap<String, Vec<String>> {
    let mut map = BTreeMap::new();
    for item in &file.items {
        collect_item(item, &mut map);
    }
    map
}

fn collect_item(item: &Item, map: &mut BTreeMap<String, Vec<String>>) {
    match item {
        Item::Fn(item_fn) => {
            map.insert(item_fn.sig.ident.to_string(), skeleton_of(&item_fn.block));
        }
        Item::Impl(item_impl) => {
            for impl_item in &item_impl.items {
                if let ImplItem::Fn(method) = impl_item {
                    map.insert(method.sig.ident.to_string(), skeleton_of(&method.block));
                }
            }
        }
        Item::Mod(item_mod) => {
            if let Some((_, items)) = &item_mod.content {
                for nested in items {
                    collect_item(nested, map);
                }
            }
        }
        _ => {}
    }
}

/// The preorder control-flow-skeleton token stream of one function body.
fn skeleton_of(block: &syn::Block) -> Vec<String> {
    let mut visitor = SkeletonVisitor { tokens: Vec::new() };
    visitor.visit_block(block);
    visitor.tokens
}

/// Collects control-flow tokens in source (preorder) order. Relies on
/// `syn::visit` to recurse through every nested expression — `if` inside a
/// `let` initializer, `match` inside a call argument, and so on.
struct SkeletonVisitor {
    tokens: Vec<String>,
}

impl<'ast> Visit<'ast> for SkeletonVisitor {
    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        // `if` and `if let` unify with `match` as `branch:N`.
        let arity = if node.else_branch.is_some() { 2 } else { 1 };
        self.tokens.push(format!("branch:{arity}"));
        visit::visit_expr_if(self, node);
    }

    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        self.tokens.push(format!("branch:{}", node.arms.len()));
        visit::visit_expr_match(self, node);
    }

    fn visit_expr_while(&mut self, node: &'ast syn::ExprWhile) {
        // covers `while` and `while let`.
        self.tokens.push("loop:while".to_string());
        visit::visit_expr_while(self, node);
    }

    fn visit_expr_for_loop(&mut self, node: &'ast syn::ExprForLoop) {
        self.tokens.push("loop:for".to_string());
        visit::visit_expr_for_loop(self, node);
    }

    fn visit_expr_loop(&mut self, node: &'ast syn::ExprLoop) {
        self.tokens.push("loop:loop".to_string());
        visit::visit_expr_loop(self, node);
    }

    fn visit_expr_return(&mut self, node: &'ast syn::ExprReturn) {
        self.tokens.push("return".to_string());
        visit::visit_expr_return(self, node);
    }

    fn visit_expr_break(&mut self, node: &'ast syn::ExprBreak) {
        self.tokens.push("break".to_string());
        visit::visit_expr_break(self, node);
    }

    fn visit_expr_continue(&mut self, node: &'ast syn::ExprContinue) {
        self.tokens.push("continue".to_string());
        visit::visit_expr_continue(self, node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(src: &str) -> syn::File {
        syn::parse_str(src).expect("source parses")
    }

    #[test]
    fn identical_structure_scores_one() {
        let f = file(
            r#"
            fn g(x: i128) -> i128 {
                if x < 0 { return 0; }
                let mut total = 0;
                for i in 0..x { total += i; }
                total
            }
            "#,
        );
        assert!((evaluate(&f, &f).score - 1.0).abs() < 1e-9);
    }

    #[test]
    fn if_let_else_matches_two_arm_match() {
        // The core equivalence: `if let Some … else` == two-arm `match`.
        let if_let = file(
            r#"
            fn g(o: Option<i128>) -> i128 {
                if let Some(v) = o { v } else { 0 }
            }
            "#,
        );
        let matched = file(
            r#"
            fn g(o: Option<i128>) -> i128 {
                match o { Some(v) => v, None => 0 }
            }
            "#,
        );
        assert!((evaluate(&if_let, &matched).score - 1.0).abs() < 1e-9);
    }

    #[test]
    fn a_dropped_guard_lowers_the_score() {
        let with_guard = file(
            r#"
            fn g(x: i128) -> i128 {
                if x < 0 { return 0; }
                x
            }
            "#,
        );
        let without = file("fn g(x: i128) -> i128 { x }");
        assert!(evaluate(&without, &with_guard).score < 1.0);
    }

    #[test]
    fn a_missing_function_contributes_zero() {
        let two = file("fn a() { if true {} } fn b() { for _ in 0..1 {} }");
        let one = file("fn a() { if true {} }");
        let score = evaluate(&one, &two).score;
        // `a` matches (1.0), `b` missing (0.0) → average 0.5.
        assert!((score - 0.5).abs() < 1e-9, "score was {score}");
    }

    #[test]
    fn loop_kind_is_distinguished() {
        let while_loop = file("fn g() { while true {} }");
        let for_loop = file("fn g() { for _ in 0..1 {} }");
        assert!(evaluate(&while_loop, &for_loop).score < 1.0);
    }
}
