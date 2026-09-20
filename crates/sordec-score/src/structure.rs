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
//! ## Why there is no glue denylist (score-2.0.0 T14′)
//!
//! Macro-generated code is excluded **by the direction of travel**, not by a
//! name list. Generated glue sits *upstream* of the ABI — the `__mint` invoke
//! shim calls the user's `mint`, never the reverse — so a closure walked
//! downward from an entrypoint cannot reach it. That holds without knowing any
//! of the SDK's generated names, which is why it does not need maintaining
//! against SDK releases the way a denylist would.
//!
//! Verified rather than assumed:
//! `no_macro_glue_is_reachable_from_any_entrypoint` expands every corpus
//! fixture and checks each entrypoint's closure against the name patterns
//! `crate::glue` recognizes. It matters because `glue::canonicalize` cannot
//! strip everything — `#[contracttype]`'s `TryFromVal`/`IntoVal` impls are
//! written on *user-declared* types, so they survive into the graph and would
//! be scored as reconstruction if anything reached them. Nothing does.
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
//! ## Containment (score-2.0.0 T13f)
//!
//! Leaving a construct's body emits an `end` token, so the otherwise-flat
//! preorder stream encodes which construct contains which:
//!
//! ```text
//! for { for { if } }   ->  [loop, loop, branch:1, end:branch:1, end:loop, end:loop]
//! for {} for {} if {}  ->  [loop, end:loop, loop, end:loop, branch:1, end:branch:1]
//! ```
//!
//! Containment survives compilation — a nested loop really is different
//! control flow from two sequential ones — so by the rule above it counts.
//! Until T13f the two forms compared *equal*.
//!
//! **Close markers rather than depth tags** (`branch:1@2`), because absolute
//! depth is brittle against the one thing our emitter does everywhere: wrapping
//! real code in an extra marshalling guard. That turns the source's
//! `branch:1@0` into our `branch:1@1` and mismatches *every descendant* even
//! when the inner structure is perfect. As a close-marked stream the same
//! wrapper is a **local insertion** of two tokens, which the LCS half absorbs
//! while still charging for it.
//!
//! Only the ordered half of the blend sees the markers; the multiset half and
//! the token census read content tokens only (see [`content`]).

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

/// Prefix of the token marking the end of a construct's body, making the
/// otherwise-flat preorder stream encode *containment* (score-2.0.0 T13f).
///
/// The marker mirrors the token it closes — `end:loop`, `end:branch:2` — rather
/// than being a bare `end`. A generic marker would be matchable between *any*
/// two constructs, so `branch:2` against `branch:1` would score 0 on the open
/// token but still match on the close, handing an arity mismatch partial credit
/// it does not deserve. Mirroring keeps a mismatch a mismatch while still
/// encoding the nesting.
const CLOSE: &str = "end:";

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
        // Structure reads only the `"fn "` keys, so names never enter it.
        Some((_, orig_spec)) => spec::abi(orig_spec, true),
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
    let mut census = TokenCensus::default();
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
            // Its control flow is wholly unrecovered — a recall miss, and the
            // census must see it as one rather than as an absent comparison.
            census.observe(&[], &stream(&orig, name));
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

        census.observe(&ours, &theirs);
        trace_streams(name, &ours, &theirs);
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
    if let Some(note) = census.note() {
        category = category.with_note(note);
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

/// Control-flow token totals across the measured entrypoints.
///
/// The score alone says `0.0480` and nothing about what to do with it. This
/// decomposes it into the two facts that actually differ: how much of the
/// original's control flow we recovered (recall), and how much of what we
/// emitted is real (precision). On the corpus those read ~0.87 and ~0.04 —
/// we recover essentially all the real structure and bury it in 20x more
/// marshalling, which is an emitter problem, not a scoring one.
#[derive(Default)]
struct TokenCensus {
    orig: usize,
    recon: usize,
    overlap: usize,
}

impl TokenCensus {
    fn observe(&mut self, ours: &[String], theirs: &[String]) {
        // Content tokens only — see `content`.
        let (ours, theirs) = (content(ours), content(theirs));
        self.orig += theirs.len();
        self.recon += ours.len();
        self.overlap += simil::multiset_overlap(&simil::multiset(&theirs), &simil::multiset(&ours));
    }

    /// The census as a report note, or `None` when no tokens were seen at all
    /// — reachable when every measured entrypoint was straight-line in the
    /// original and missing from the reconstruction.
    fn note(&self) -> Option<String> {
        let prf = simil::prf(self.overlap, self.recon, self.orig)?;
        let mut note = format!(
            "control flow: precision={} recall={} ({} original tokens, {} reconstructed)",
            simil::render_ratio(prf.precision),
            simil::render_ratio(prf.recall),
            self.orig,
            self.recon
        );
        if self.orig > 0 {
            // `2·o/(o+r)` is the best Sorensen-Dice attainable at this token
            // ratio even with perfect recall. The category score is a mean of
            // per-entrypoint blends rather than one global Dice, so this is an
            // indicator of headroom and not a strict bound — hence `~`. Its
            // point survives the imprecision: while bloat is this high, no
            // change to the scoring algorithm gets past roughly here.
            let (o, r) = (self.orig as f64, self.recon as f64);
            note.push_str(&format!(
                " — bloat {:.1}x, dice ceiling ~{:.4}",
                r / o,
                2.0 * o / (o + r)
            ));
        }
        Some(note)
    }
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
///
/// The two halves deliberately read *different* views of the stream, because
/// they answer different questions:
///
/// - the **ordered** half sees the [`CLOSE`] markers, so it is sensitive to
///   which construct contains which — "is this the same control-flow *shape*";
/// - the **multiset** half sees content tokens only — "are the same constructs
///   present, and how many". Feeding markers into the bag would make [`CLOSE`]
///   the most common token by far and dilute that comparison into noise.
fn function_similarity(a: &[String], b: &[String]) -> f64 {
    let seq = simil::sequence_similarity(a, b);
    let (ca, cb) = (content(a), content(b));
    let bag = simil::multiset_similarity(&simil::multiset(&ca), &simil::multiset(&cb));
    SEQUENCE_WEIGHT * seq + MULTISET_WEIGHT * bag
}

/// The two token streams an entrypoint's number is computed from,
/// printed when `SORDEC_SCORE_STREAMS` is set.
///
/// Every structure figure in the report is a summary of these, and
/// working back from a summary to the construct that caused it is
/// guesswork. Reading them out is how a surplus `if` gets found.
#[allow(clippy::print_stderr)]
fn trace_streams(name: &str, ours: &[String], theirs: &[String]) {
    if std::env::var_os("SORDEC_SCORE_STREAMS").is_some() {
        eprintln!("[streams] {name}\n  ours:   {ours:?}\n  theirs: {theirs:?}");
    }
}

/// A skeleton stream with the [`CLOSE`] markers removed.
///
/// Shared by the multiset half of [`function_similarity`] and by
/// [`TokenCensus`], so the two cannot drift on what counts as a token. The
/// census in particular *must* stay on content tokens: markers roughly double
/// every stream, which would silently restate the published bloat ratio and the
/// emitter target derived from it.
fn content(tokens: &[String]) -> Vec<String> {
    tokens.iter().filter(|t| !t.starts_with(CLOSE)).cloned().collect()
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

impl SkeletonVisitor {
    /// Push `token`, descend into its body, then push the mirrored close
    /// marker — the bracketing that encodes containment.
    fn open(&mut self, token: String, descend: impl FnOnce(&mut Self)) {
        self.tokens.push(token.clone());
        descend(self);
        self.tokens.push(format!("{CLOSE}{token}"));
    }
}

impl<'ast> Visit<'ast> for SkeletonVisitor {
    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        // `if` and `if let` unify with `match` as `branch:N`.
        let arity = if node.else_branch.is_some() { 2 } else { 1 };
        self.open(format!("branch:{arity}"), |v| visit::visit_expr_if(v, node));
    }

    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        self.open(format!("branch:{}", node.arms.len()), |v| {
            visit::visit_expr_match(v, node)
        });
    }

    // The three loop forms unify as `loop`: the kind does not survive
    // optimization, so scoring it would grade a guess (see the module doc).

    fn visit_expr_while(&mut self, node: &'ast syn::ExprWhile) {
        // covers `while` and `while let`.
        self.open("loop".to_owned(), |v| visit::visit_expr_while(v, node));
    }

    fn visit_expr_for_loop(&mut self, node: &'ast syn::ExprForLoop) {
        self.open("loop".to_owned(), |v| visit::visit_expr_for_loop(v, node));
    }

    fn visit_expr_loop(&mut self, node: &'ast syn::ExprLoop) {
        self.open("loop".to_owned(), |v| visit::visit_expr_loop(v, node));
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
    fn containment_is_encoded() {
        // T13f. This test previously pinned the *opposite* — nested and
        // sequential compared equal, because the stream had no close markers.
        // Containment survives compilation, so by this module's governing rule
        // it counts, and the two must now differ.
        let s = score(
            "fn g() { for _ in 0..2 { for _ in 0..2 { if x {} } } }",
            "fn g() { for _ in 0..2 {} for _ in 0..2 {} if x {} }",
            &["g"],
        );
        assert!(
            s.score < 1.0,
            "nested and sequential must not compare equal, got {}",
            s.score
        );
    }

    #[test]
    fn a_branch_arity_mismatch_still_costs_everything() {
        // The reason close markers mirror their open token. With a generic
        // `end`, `branch:2` against `branch:1` would score 0 on the open token
        // but still match on the close, handing an arity mismatch partial
        // credit. Mirrored, both halves miss and it stays a full mismatch.
        let s = score(
            "fn g(x: i128) { if x < 0 {} else {} }",
            "fn g(x: i128) { if x < 0 {} }",
            &["g"],
        );
        assert!(
            s.score.abs() < 1e-9,
            "an arity mismatch must not earn marker credit, got {}",
            s.score
        );
    }

    #[test]
    fn containment_leaves_the_multiset_half_alone() {
        // The bag asks "which constructs, how many" — a question nesting does
        // not change. Both sides here have loop x2 + branch:1, so only the
        // ordered half may differ, which bounds the penalty: the score must
        // stay at or above the multiset weight.
        let s = score(
            "fn g() { for _ in 0..2 { for _ in 0..2 { if x {} } } }",
            "fn g() { for _ in 0..2 {} for _ in 0..2 {} if x {} }",
            &["g"],
        );
        assert!(
            s.score >= MULTISET_WEIGHT,
            "identical construct bags must still earn the multiset half, got {}",
            s.score
        );
    }

    #[test]
    fn an_extra_enclosing_guard_does_not_wreck_inner_structure() {
        // The property that chose close markers over depth tags. Our emitter
        // wraps real code in marshalling guards constantly; under depth
        // tagging every descendant's token would shift and mismatch. As a
        // local two-token insertion the inner structure still scores.
        let s = score(
            "fn g(x: i128) { if tag_ok { if x < 0 {} if x > 9 {} } }",
            "fn g(x: i128) { if x < 0 {} if x > 9 {} }",
            &["g"],
        );
        assert!(
            s.score > 0.5,
            "a single wrapper must not destroy correct inner structure, got {}",
            s.score
        );
    }

    #[test]
    fn identity_is_still_exactly_one_with_markers() {
        // Markers are additive and symmetric, so identity must be untouched.
        let src = "fn g(n: u32) {
            for _ in 0..n { if a { for _ in 0..2 { if b {} } } else { return; } }
        }";
        assert_perfect(src, src, &["g"]);
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
    // T13e: the control-flow token census
    // ----------------------------------------------------------------

    fn census_note(s: &CategoryScore) -> Option<&String> {
        s.notes.iter().find(|n| n.starts_with("control flow:"))
    }

    #[test]
    fn the_census_reports_precision_recall_and_bloat() {
        // Original has one branch; we recover it and invent three more. So
        // recall is perfect and precision is 1/4, with 4x bloat.
        let s = score(
            "fn g(x: i128) { if a {} if b {} if c {} if x < 0 {} }",
            "fn g(x: i128) { if x < 0 {} }",
            &["g"],
        );
        let note = census_note(&s).expect("census note");
        assert!(note.contains("1 original tokens"), "{note}");
        assert!(note.contains("4 reconstructed"), "{note}");
        assert!(note.contains("recall=1.0000"), "{note}");
        assert!(note.contains("precision=0.2500"), "{note}");
        assert!(note.contains("bloat 4.0x"), "{note}");
        // 2*1/(1+4) = 0.4
        assert!(note.contains("ceiling ~0.4000"), "{note}");
    }

    #[test]
    fn a_missing_entrypoint_counts_against_recall() {
        // Its control flow is wholly unrecovered, which is a recall miss —
        // not an absent comparison to be quietly skipped.
        let s = score("fn other() {}", "fn g(x: i128) { if x < 0 {} }", &["g"]);
        let note = census_note(&s).expect("census note");
        assert!(note.contains("1 original tokens"), "{note}");
        assert!(note.contains("0 reconstructed"), "{note}");
        assert!(note.contains("recall=0.0000"), "{note}");
    }

    #[test]
    fn an_undefined_ratio_renders_not_applicable() {
        // Nothing reconstructed means precision has no denominator. It is
        // undefined, not 0.0000 — the distinction `simil::render_ratio` exists
        // to preserve.
        let s = score("fn other() {}", "fn g(x: i128) { if x < 0 {} }", &["g"]);
        let note = census_note(&s).expect("census note");
        assert!(note.contains("precision=n/a"), "{note}");
    }

    #[test]
    fn the_census_is_omitted_when_no_tokens_were_seen() {
        // `plain` is straight-line in the original and missing from the
        // reconstruction: measured (it scores 0) but contributing no tokens
        // either way, so there is nothing for a census to report.
        let s = score("fn other() {}", "fn plain(a: u64) -> u64 { a }", &["plain"]);
        assert!(s.checked);
        assert!(census_note(&s).is_none(), "notes: {:?}", s.notes);
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

    // ----------------------------------------------------------------
    // T14': macro glue is unreachable from an entrypoint closure
    // ----------------------------------------------------------------

    /// Whether an owner-qualified key names macro-generated code, judged by
    /// the constants `glue` already owns so the two cannot drift apart.
    ///
    /// `entrypoints` is checked first and wins: the harvested ABI is the
    /// ground truth for what is user surface. The SDK's `__constructor` is a
    /// real entrypoint that happens to start with the generated-name prefix,
    /// so a purely lexical rule would misread it as glue.
    fn is_generated(key: &str, entrypoints: &[String]) -> bool {
        let (owner, method) = key
            .split_once("::")
            .map_or((None, key), |(o, m)| (Some(o), m));
        if entrypoints.iter().any(|e| e == method) {
            return false;
        }
        let generated_owner = owner.is_some_and(|o| {
            o.starts_with(crate::glue::GENERATED_MOD_PREFIX)
                || crate::glue::GENERATED_TYPE_SUFFIXES
                    .iter()
                    .any(|suffix| o.ends_with(suffix))
        });
        generated_owner
            || method.starts_with(crate::glue::SPEC_FN)
            || method.starts_with(crate::glue::GENERATED_MOD_PREFIX)
            // `#[contracttype]` conversions survive canonicalization: their
            // self-type is user-declared, so `glue` cannot tell them apart
            // from the user's own impls. If one were reachable, it would be
            // scored as if we had reconstructed it.
            || matches!(method, "try_from_val" | "into_val" | "invoke_raw")
    }

    /// The claim T14 was going to enforce with a denylist, tested instead.
    ///
    /// Structure walks *downward* from each ABI entrypoint, and generated glue
    /// sits *upstream* — the `__mint` invoke shim calls the user's `mint`, not
    /// the reverse — so a downward closure should never reach it. That makes a
    /// denylist unnecessary, but "should" is an argument, not evidence: this
    /// runs the real expanded corpus and checks.
    ///
    /// If it ever fails it names the fixture, entrypoint and offending key,
    /// which is precisely the input a narrowly-scoped denylist would need.
    #[test]
    #[ignore = "shells out to cargo expand against soroban-sdk (slow)"]
    fn no_macro_glue_is_reachable_from_any_entrypoint() {
        // Every corpus fixture with distinct source. `token-v23-stripped`
        // vendors the same source as `token-v23` — only its wasm differs — so
        // expanding it again would test nothing new.
        const FIXTURES: [&str; 6] = [
            "hello-add",
            "token-v22",
            "token-v23",
            "timelock",
            "dex-liquidity-pool",
            "attestation",
        ];

        for fixture in FIXTURES {
            let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../samples/contracts")
                .join(fixture)
                .join("source/src");
            let expanded = crate::expand::expand(&dir)
                .unwrap_or_else(|e| panic!("{fixture} must expand: {e}"));
            let out = crate::glue::canonicalize(
                syn::parse_file(&expanded).expect("expanded output parses"),
            );
            let graph = CallGraph::build(&out.file);

            let entrypoints: Vec<String> = spec::abi(&out.spec, true)
                .keys()
                .filter_map(|key| key.strip_prefix("fn "))
                .map(str::to_owned)
                .collect();
            assert!(
                !entrypoints.is_empty(),
                "{fixture}: no entrypoints harvested — the check would pass vacuously"
            );

            for entrypoint in &entrypoints {
                for key in graph.closure(entrypoint) {
                    assert!(
                        !is_generated(key, &entrypoints),
                        "{fixture}: entrypoint `{entrypoint}` reaches generated code `{key}` — \
                         glue is being scored as reconstruction, and T14's denylist is needed \
                         after all (see plan/M4_STRUCTURE_DESIGN.md §5.2)"
                    );
                }
            }
        }
    }

    #[test]
    fn a_plain_function_is_not_an_entrypoint() {
        // Without `#[contractimpl]` there is no ABI, so there is nothing to
        // measure — not a perfect score.
        let f = file("fn helper() { if x {} }");
        assert!(!evaluate(&f, &f, None).checked);
    }
}
