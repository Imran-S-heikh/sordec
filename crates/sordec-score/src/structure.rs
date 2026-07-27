//! Structure category: per-entrypoint control-flow-skeleton similarity.
//!
//! One skeleton is built per **ABI entrypoint**, covering the closure of code
//! that entrypoint can reach, and the category score is the mean over the
//! *original's* entrypoints. Each function in the closure contributes a
//! preorder token stream of its control-flow constructs — branches and loops,
//! plus the `return` / `break` / `continue` leaves — with straight-line code
//! dropped; the streams are concatenated in call-graph BFS order and compared
//! by blending an ordered (LCS) similarity with a multiset similarity.
//!
//! ## Why the entrypoint, and not the function (score-2.0.0 T13c)
//!
//! Until T13c this category averaged over the **union of function names** on
//! both sides, scoring `0` for any name present on only one side. That
//! measures the binary's debug info rather than the reconstruction: internal
//! helper names and boundaries are not in the wasm at all — rustc inlines a
//! small helper out of existence, and the decompiler can only invent `funcN`
//! for whatever bodies remain.
//!
//! The cost was measured. `token-v23` scored **0.0522** and *the same binary
//! with its name section stripped* scored **0.0045** — an 11.6x swing on
//! identical control flow. Scoring per entrypoint over closures, both read
//! **0.0578**, because nothing in the comparison depends on a name the
//! compiler did not preserve.
//!
//! Entrypoints are the one anchor that does survive: they are exported and
//! recorded in the contract's spec-XDR. So they are the unit, they are the
//! denominator (an entrypoint we failed to emit scores `0` — recovering one of
//! thirteen perfectly must not read as perfect), and everything below them is
//! flattened. [`crate::closure`] supplies the reachability; this module
//! supplies the tokens and the comparison.
//!
//! What this deliberately does **not** reward is decomposition: merging five
//! helpers into one entrypoint body, or splitting one into five, compares
//! equal. That is the point — the wasm does not record which the author wrote.
//! Emitting control flow the source does not have still costs full score.
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
//! ## Loop unification (score-2.0.0 T13b)
//!
//! `while`, `for`, and `loop` all emit a single `loop` token. The governing
//! rule for this vocabulary is **score what survives compilation, don't score
//! what doesn't**: a token earns its place only if the information it carries
//! is actually in the wasm.
//!
//! Loop *kind* is not. `for i in 0..n`, `while i < n`, and `loop { … break }`
//! all lower to near-identical counted loops once LLVM is done; only the
//! iterator protocol (`for x in collection`) leaves a partial fingerprint, and
//! reading it back is a guess. Emitting three distinct tokens made guessing
//! wrong a *full* miss on information the decompiler cannot recover — the
//! scorer marking down an honest reconstruction for the compiler's choices.
//!
//! Loop *presence* and *position* do survive, and still count in full: a
//! dropped loop, an invented one, or a loop and a branch in the wrong order
//! all cost score. Branch *arity* survives too (a `match` is a `br_table`
//! whose size is visible), so `branch:N` stays exact — this is a targeted
//! collapse, not a general softening.
//!
//! **Known limitation:** the stream is flat preorder with no enter/exit
//! markers, so it records the *sequence* of constructs but not their
//! *containment* — a nested loop and two sequential loops both reduce to
//! `[loop, loop]`. Containment does survive compilation and arguably should
//! be scored; encoding it is a separate vocabulary change, tracked in
//! `plan/M4_STRUCTURE_DESIGN.md` §7 and pinned by
//! `containment_depth_is_not_encoded_known_limitation`.

use std::collections::BTreeSet;

use syn::visit::{self, Visit};

use crate::closure::CallGraph;
use crate::interface;
use crate::report::CategoryScore;
use crate::simil;
use crate::spec;

/// How much the ordered (LCS) similarity counts vs the multiset similarity
/// when comparing two function skeletons.
const SEQUENCE_WEIGHT: f64 = 0.6;
const MULTISET_WEIGHT: f64 = 0.4;

/// Score the structure category.
///
/// `spec` is the harvested spec-XDR pair when the category is running on the
/// macro-expanded basis, mirroring [`crate::interface::evaluate`]. It is the
/// ABI ground truth and takes precedence; `None` — the pre-expansion basis —
/// falls back to the attribute extractor. Only the *original's* half is read:
/// the entrypoint set is the thing being reproduced, so it comes from the
/// source of truth, not from what we happened to emit.
pub(crate) fn evaluate(
    reconstructed: &syn::File,
    original: &syn::File,
    spec: Option<(&spec::SpecMap, &spec::SpecMap)>,
) -> CategoryScore {
    let abi = match spec {
        Some((_, orig_spec)) => spec::abi(orig_spec),
        None => interface::extract(original),
    };
    // Both extractors namespace entrypoints `"fn name"` (see `spec::render`).
    let entrypoints: BTreeSet<String> = abi
        .keys()
        .filter_map(|key| key.strip_prefix("fn "))
        .map(str::to_owned)
        .collect();

    score_entrypoints(reconstructed, original, &entrypoints)
}

/// The category score over an explicit entrypoint set.
///
/// Split out from [`evaluate`] so the algorithm can be tested without
/// synthesizing spec-XDR bytes or `#[contractimpl]` boilerplate around every
/// fixture — the entrypoint set is an input, not something to reverse-engineer
/// from the test source.
fn score_entrypoints(
    reconstructed: &syn::File,
    original: &syn::File,
    entrypoints: &BTreeSet<String>,
) -> CategoryScore {
    if entrypoints.is_empty() {
        // No declared ABI: nothing was compared, which is not the same as
        // everything matching (score-2.0.0 T8).
        return CategoryScore::unchecked("no ABI entrypoints — nothing to measure");
    }

    let recon = CallGraph::build(reconstructed);
    let orig = CallGraph::build(original);

    let mut total = 0.0;
    let mut measured = 0usize;
    let mut missing = 0usize;
    let mut flowless = 0usize;
    let mut low = Vec::new();
    for name in entrypoints {
        // Unresolvable covers both "we never emitted it" and "we emitted
        // several things by that name": in either case we cannot identify the
        // entrypoint, and guessing which body is meant would be worse than
        // scoring the miss.
        //
        // Note this stays a 0 even when the original entrypoint carries no
        // control flow. "We did not emit it" is never "nothing to measure" —
        // the absence is itself the finding.
        let Some(_) = recon.resolve(name) else {
            missing += 1;
            measured += 1;
            low.push(format!("{name}(0.00)"));
            continue;
        };

        let (ours, theirs) = (stream(&recon, name), stream(&orig, name));
        if ours.is_empty() && theirs.is_empty() {
            // Neither side has control flow here, so this entrypoint tells us
            // nothing about reconstruction quality. Drop it from *both* the
            // numerator and the denominator, the same way an absent ABI kind
            // drops out of `interface` — a contract is neither penalized nor
            // credited for what it does not have.
            flowless += 1;
            continue;
        }

        let sim = function_similarity(&ours, &theirs);
        total += sim;
        measured += 1;
        if sim < 0.75 {
            low.push(format!("{name}({sim:.2})"));
        }
    }

    if measured == 0 {
        // Every entrypoint was straight-line on both sides: the category
        // compared nothing at all, which is not the same as comparing
        // everything successfully (score-2.0.0 T8). Reporting 1.0 here would
        // be a false perfect that appears exactly when the emitter improves —
        // once marshalling elision lands and we stop inventing branches.
        return CategoryScore::unchecked(
            "no entrypoint carries control flow on either side — nothing to measure",
        );
    }

    let mut category = CategoryScore::checked(total / measured as f64).with_note(format!(
        "{} entrypoints ({missing} unreconstructed, {flowless} without control flow)",
        entrypoints.len()
    ));
    // An ambiguous bare name makes `closure` drop that call edge, so the
    // reachable set — and the score with it — is a lower bound. Say so rather
    // than let the number read as complete.
    let (recon_ambiguous, orig_ambiguous) = (recon.ambiguous_names(), orig.ambiguous_names());
    if recon_ambiguous > 0 || orig_ambiguous > 0 {
        category = category.with_note(format!(
            "ambiguous names ({orig_ambiguous} original, {recon_ambiguous} reconstructed) — \
             their call edges are dropped, so this is a lower bound"
        ));
    }
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

/// The flattened control-flow skeleton of everything `entrypoint` reaches:
/// each reachable function's tokens, concatenated in call-graph BFS order.
///
/// Function boundaries vanish here on purpose. rustc decides which helpers
/// survive as separate bodies, so scoring the split would grade the compiler's
/// choices rather than the reconstruction's fidelity.
fn stream(graph: &CallGraph<'_>, entrypoint: &str) -> Vec<String> {
    graph
        .closure(entrypoint)
        .into_iter()
        .filter_map(|key| graph.body(key))
        .flat_map(skeleton_of)
        .collect()
}

/// Blend the ordered and multiset similarities of two skeleton streams.
fn function_similarity(a: &[String], b: &[String]) -> f64 {
    let seq = simil::sequence_similarity(a, b);
    let bag = simil::multiset_similarity(&simil::multiset(a), &simil::multiset(b));
    SEQUENCE_WEIGHT * seq + MULTISET_WEIGHT * bag
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

    // The three loop forms unify as `loop`: the kind does not survive
    // optimization, so scoring it would grade a guess (see the module doc).

    fn visit_expr_while(&mut self, node: &'ast syn::ExprWhile) {
        // covers `while` and `while let`.
        self.tokens.push("loop".to_string());
        visit::visit_expr_while(self, node);
    }

    fn visit_expr_for_loop(&mut self, node: &'ast syn::ExprForLoop) {
        self.tokens.push("loop".to_string());
        visit::visit_expr_for_loop(self, node);
    }

    fn visit_expr_loop(&mut self, node: &'ast syn::ExprLoop) {
        self.tokens.push("loop".to_string());
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

    fn eps(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|n| (*n).to_owned()).collect()
    }

    /// Score with an explicit entrypoint set, bypassing ABI extraction.
    fn score(recon: &str, orig: &str, entrypoints: &[&str]) -> CategoryScore {
        score_entrypoints(&file(recon), &file(orig), &eps(entrypoints))
    }

    fn assert_perfect(recon: &str, orig: &str, entrypoints: &[&str]) {
        let s = score(recon, orig, entrypoints);
        assert!(s.checked, "must be measurable");
        assert!((s.score - 1.0).abs() < 1e-9, "score was {}", s.score);
    }

    // ----------------------------------------------------------------
    // Vocabulary: what costs score and what does not
    // ----------------------------------------------------------------

    #[test]
    fn identical_structure_scores_one() {
        let src = "fn g(x: i128) -> i128 {
            if x < 0 { return 0; }
            let mut total = 0;
            for i in 0..x { total += i; }
            total
        }";
        assert_perfect(src, src, &["g"]);
    }

    #[test]
    fn if_let_else_matches_two_arm_match() {
        // The core equivalence: `if let Some … else` == two-arm `match`.
        assert_perfect(
            "fn g(o: Option<i128>) -> i128 { if let Some(v) = o { v } else { 0 } }",
            "fn g(o: Option<i128>) -> i128 { match o { Some(v) => v, None => 0 } }",
            &["g"],
        );
    }

    #[test]
    fn a_dropped_guard_lowers_the_score() {
        let s = score(
            "fn g(x: i128) -> i128 { x }",
            "fn g(x: i128) -> i128 { if x < 0 { return 0; } x }",
            &["g"],
        );
        assert!(s.score < 1.0);
    }

    #[test]
    fn loop_kind_is_unified() {
        // T13b: the kind does not survive optimization, so recovering `while`
        // where the source wrote `for` must cost nothing.
        assert_perfect(
            "fn g() { while true {} }",
            "fn g() { for _ in 0..1 {} }",
            &["g"],
        );
        // `loop { break; }` carries a `break`, so compare against a `while`
        // that breaks too — otherwise this measures the `break`, not the kind.
        assert_perfect(
            "fn g() { loop { break; } }",
            "fn g() { while true { break; } }",
            &["g"],
        );
    }

    #[test]
    fn loop_presence_still_counts() {
        // The collapse must not become "loops are free".
        let s = score(
            "fn g(n: u32) { work(); }",
            "fn g(n: u32) { for _ in 0..n { work(); } }",
            &["g"],
        );
        assert!(s.score < 1.0);
    }

    #[test]
    fn loop_ordering_still_counts() {
        // A loop inside a branch and a branch inside a loop are different
        // control flow, and the preorder stream sees it.
        let s = score(
            "fn g() { if x { for _ in 0..2 {} } }",
            "fn g() { for _ in 0..2 { if x {} } }",
            &["g"],
        );
        assert!(s.score < 1.0);
    }

    #[test]
    fn containment_depth_is_not_encoded_known_limitation() {
        // KNOWN LIMITATION, pinned deliberately so it cannot be "fixed" by
        // accident without a decision. The skeleton is a flat *preorder*
        // stream with no enter/exit markers, so it records the sequence of
        // constructs but not which contains which.
        //
        // Containment does survive compilation, so by this module's governing
        // rule it *should* be scored; encoding it is a separate vocabulary
        // change tracked in `plan/M4_STRUCTURE_DESIGN.md` §7. Predates M4 —
        // the old `loop:for` tokens had the same blind spot.
        assert_perfect(
            "fn g() { for _ in 0..2 { for _ in 0..2 { if x {} } } }",
            "fn g() { for _ in 0..2 {} for _ in 0..2 {} if x {} }",
            &["g"],
        );
    }

    // ----------------------------------------------------------------
    // T13c: the unit is the entrypoint closure, not the named function
    // ----------------------------------------------------------------

    #[test]
    fn helper_names_do_not_affect_the_score() {
        // The headline property. Internal names are not in the wasm, so the
        // decompiler's invented `func7` must cost exactly nothing against the
        // source's `check_amount`. Under the old name-keyed algorithm this
        // pair scored 0; it is why token-v23 and token-v23-stripped differed
        // 11.6x on identical control flow.
        assert_perfect(
            "fn g(x: i128) { func7(x); } fn func7(x: i128) { if x < 0 {} }",
            "fn g(x: i128) { check_amount(x); } fn check_amount(x: i128) { if x < 0 {} }",
            &["g"],
        );
    }

    #[test]
    fn inlining_a_helper_scores_the_same_as_calling_it() {
        // rustc decides which helpers survive as separate bodies. Recovering
        // an inlined branch in the entrypoint must equal the source's call out
        // to a helper holding the same branch.
        assert_perfect(
            "fn g(x: i128) { if x < 0 {} }",
            "fn g(x: i128) { check(x); } fn check(x: i128) { if x < 0 {} }",
            &["g"],
        );
    }

    #[test]
    fn a_helper_called_twice_is_counted_once() {
        // Splicing at every call site was measured and rejected: it multiplies
        // a shared helper by its call count. The closure visits each function
        // once, so two calls and one inlined copy agree.
        assert_perfect(
            "fn g() { if x {} }",
            "fn g() { h(); h(); } fn h() { if x {} }",
            &["g"],
        );
    }

    #[test]
    fn a_function_outside_the_abi_is_not_scored() {
        // Helpers no longer auto-zero: an unreachable function that only one
        // side declares is not part of any entrypoint's closure, so it cannot
        // drag the score down.
        assert_perfect(
            "fn g() { if x {} }",
            "fn g() { if x {} } fn unrelated() { for _ in 0..9 { if y {} } }",
            &["g"],
        );
    }

    #[test]
    fn spurious_control_flow_still_costs() {
        // Boundary-agnostic is not lenient. Emitting branches the source does
        // not have — un-elided Val-marshalling, in practice — is a real miss.
        let s = score(
            "fn g(x: i128) { if !is_i128(a) {} if !ok(b) {} if x < 0 {} }",
            "fn g(x: i128) { if x < 0 {} }",
            &["g"],
        );
        assert!(s.score < 1.0, "score was {}", s.score);
    }

    #[test]
    fn a_missing_entrypoint_scores_zero() {
        let s = score("fn other() {}", "fn g() { if x {} }", &["g"]);
        assert!(s.checked);
        assert!(s.score.abs() < 1e-9, "score was {}", s.score);
    }

    #[test]
    fn an_ambiguous_entrypoint_scores_zero() {
        // Two bodies named `g`: we cannot tell which is the entrypoint, and
        // guessing would be worse than scoring the miss.
        let s = score(
            "struct A; struct B; impl A { fn g() { if x {} } } impl B { fn g() {} }",
            "fn g() { if x {} }",
            &["g"],
        );
        assert!(s.score.abs() < 1e-9, "score was {}", s.score);
        assert!(
            s.notes.iter().any(|n| n.contains("ambiguous names")),
            "an ambiguity must be reported, notes: {:?}",
            s.notes
        );
    }

    #[test]
    fn a_missing_entrypoint_is_reported_in_the_notes() {
        let s = score("fn other() {}", "fn g() {}", &["g"]);
        assert!(
            s.notes.iter().any(|n| n.contains("1 unreconstructed")),
            "notes: {:?}",
            s.notes
        );
    }

    // ----------------------------------------------------------------
    // Degenerate inputs
    // ----------------------------------------------------------------

    #[test]
    fn no_entrypoints_is_unchecked_not_perfect() {
        // Nothing to compare is not a perfect comparison (score-2.0.0 T8).
        let f = file("pub struct S { x: u32 }");
        let s = evaluate(&f, &f, None);
        assert!(!s.checked, "a 0-entrypoint comparison must not be checked");
        assert_ne!(s.score, 1.0);
    }

    #[test]
    fn an_all_straight_line_contract_is_unchecked() {
        // T13d. Per *entrypoint*, empty-vs-empty is a genuine match — the
        // reconstruction reproduced the absent control flow exactly. Per
        // *category*, a contract with no control flow anywhere gave structure
        // nothing to compare, and reporting 1.0 would be a false perfect
        // (score-2.0.0 T8). This is the hello-add `add` case, and the false
        // perfect would appear precisely when the emitter improves enough to
        // stop inventing branches.
        let src = "fn add(a: u64, b: u64) -> u64 { a + b }";
        let s = score(src, src, &["add"]);
        assert!(!s.checked, "nothing was compared, so nothing is perfect");
        assert_ne!(s.score, 1.0);
    }

    #[test]
    fn a_straight_line_entrypoint_drops_out_of_the_mean() {
        // Dropped from the numerator *and* the denominator, so it neither
        // penalizes nor inflates. `flow` alone decides the score; if `plain`
        // contributed a free 1.0 the mean would be pulled up to ~0.75.
        let s = score(
            "fn plain(a: u64) -> u64 { a } fn flow(x: i128) { if x < 0 {} if x > 9 {} }",
            "fn plain(a: u64) -> u64 { a } fn flow(x: i128) { if x < 0 {} }",
            &["plain", "flow"],
        );
        let flow_only = score(
            "fn flow(x: i128) { if x < 0 {} if x > 9 {} }",
            "fn flow(x: i128) { if x < 0 {} }",
            &["flow"],
        );
        assert!(s.checked);
        assert!(
            (s.score - flow_only.score).abs() < 1e-9,
            "{} != {}",
            s.score,
            flow_only.score
        );
        assert!(
            s.notes.iter().any(|n| n.contains("1 without control flow")),
            "notes: {:?}",
            s.notes
        );
    }

    #[test]
    fn a_missing_entrypoint_scores_zero_even_with_no_control_flow() {
        // The drop-out is for entrypoints we *emitted* that turned out to have
        // nothing to compare. Failing to emit one is never "nothing to
        // measure" — the absence is itself the finding.
        let s = score("fn other() {}", "fn plain(a: u64) -> u64 { a }", &["plain"]);
        assert!(s.checked, "a missing entrypoint is a measurement, not a gap");
        assert!(s.score.abs() < 1e-9, "score was {}", s.score);
    }

    // ----------------------------------------------------------------
    // Entrypoint resolution
    // ----------------------------------------------------------------

    #[test]
    fn entrypoints_come_from_contractimpl_on_the_source_basis() {
        // The `spec == None` arm: pre-expansion, the ABI is the attributes.
        // The spec-XDR arm needs real XDR bytes and is covered end-to-end by
        // the expanded-basis calibration test and the corpus benchmark.
        let f = file(
            "#[contract] pub struct T;
             #[contractimpl] impl T { pub fn go(x: i128) { if x < 0 {} } }",
        );
        let s = evaluate(&f, &f, None);
        assert!(s.checked, "contractimpl entrypoints must be found");
        assert!((s.score - 1.0).abs() < 1e-9);
        assert!(s.notes.iter().any(|n| n.contains("1 entrypoints")), "notes: {:?}", s.notes);
    }

    #[test]
    fn a_plain_function_is_not_an_entrypoint() {
        // Without `#[contractimpl]` there is no ABI, so there is nothing to
        // measure — not a perfect score.
        let f = file("fn helper() { if x {} }");
        assert!(!evaluate(&f, &f, None).checked);
    }
}
