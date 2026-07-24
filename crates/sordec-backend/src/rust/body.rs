//! Function-body emission: the `Region` tree → a `syn::Block`.
//!
//! The compilable counterpart of `pretty_hir`'s `render_region`
//! (`sordec-cli`): the same recursion over [`Region`], but it builds a
//! `syn::Block` of real statements rather than debug text. Two things make
//! it *compilable* rather than a debug view:
//!
//! - **SSA destruction.** Phi bindings are block parameters assigned
//!   across edges via [`PhiTransfer`](sordec_ir::PhiTransfer) lists. Each
//!   phi that receives a value is declared once as a `let mut` hoisted to
//!   the top of the body (which dominates every use), and each transfer
//!   becomes an assignment. Deferred initialisation relies on Rust's
//!   definite-assignment analysis — sound for valid SSA.
//! - **Every binding is a statement.** ANF means operands are always
//!   atomic value references, so each scheduled binding emits as
//!   `let vN = <expr>;` with no re-nesting or precedence concerns. (Inlining
//!   for readability is a later output-quality pass.)
//!
//! Host-call idioms, `while`/`for` sugar, and meaningful names are later
//! waves; here loops are faithful labeled `loop`s and unrecovered
//! expressions are holes via the [`HolePolicy`].

use std::collections::{HashMap, HashSet};

use syn::parse_quote;

use sordec_common::{BlockId, IrId, ValueId};
use sordec_ir::{Expr, HighFunction, HighIr, IrType, KnownType, Region, TypeRegistry};

use crate::rust::expr;
use crate::rust::hole::HolePolicy;
use crate::rust::liveness::{self, Liveness};
use crate::rust::naming::ValueNames;
use crate::rust::sig;
use crate::rust::ty::ir_type;

/// Codegen context for one function body: the IR it walks plus the
/// value-naming environment. Threaded (by shared reference) through the
/// region walk and the expression mapping.
pub(crate) struct FnCtx<'a> {
    /// The whole module — needed to resolve call targets to their emitted
    /// names.
    pub(crate) high: &'a HighIr,
    /// The function whose body is being emitted.
    pub(crate) func: &'a HighFunction,
    /// User-defined type registry (empty for a stripped module).
    pub(crate) reg: &'a TypeRegistry,
    /// The active hole strategy.
    pub(crate) policy: &'a dyn HolePolicy,
    /// The single source of every value's emitted identifier (parameters,
    /// hinted locals, and the `vN` fallback). See [`ValueNames`].
    names: ValueNames,
    /// Read counts, driving dead-binding cleanup. See [`Liveness`].
    liveness: Liveness,
    /// Non-phi values whose uses escape the lexical block that defines them
    /// (dominance holds, lexical scope does not). Declared once at the body
    /// top and assigned at their definition site, so they stay in scope at
    /// every use. See [`escaping_values`].
    escaping: HashSet<ValueId>,
}

/// Emit the body of `func` as a `syn::Block`.
pub(crate) fn emit_body(
    high: &HighIr,
    func: &HighFunction,
    reg: &TypeRegistry,
    policy: &dyn HolePolicy,
) -> syn::Block {
    let ctx = FnCtx::new(high, func, reg, policy);
    let mut stmts = ctx.phi_declarations();
    stmts.extend(ctx.escaping_declarations());
    ctx.region_stmts(&func.region, &mut stmts);
    parse_quote!({ #(#stmts)* })
}

impl<'a> FnCtx<'a> {
    fn new(
        high: &'a HighIr,
        func: &'a HighFunction,
        reg: &'a TypeRegistry,
        policy: &'a dyn HolePolicy,
    ) -> Self {
        let names = ValueNames::build(func);
        let liveness = Liveness::build(func);
        let escaping = escaping_values(func);
        Self {
            high,
            func,
            reg,
            policy,
            names,
            liveness,
            escaping,
        }
    }

    /// The synthesized `Env` value every function carries as its leading
    /// parameter (see `sig::env_param`). Host idioms root on it.
    pub(crate) fn env(&self) -> syn::Expr {
        parse_quote!(e)
    }

    /// Render a `ValueId` as an expression, via the one naming authority.
    pub(crate) fn value_ref(&self, vid: ValueId) -> syn::Expr {
        self.names.expr(vid)
    }

    /// The identifier a `ValueId` is bound and referenced under.
    fn value_ident(&self, vid: ValueId) -> syn::Ident {
        self.names.ident(vid)
    }

    /// `let mut vP: T;` for every phi that receives a value across some
    /// edge, hoisted to the body top. Order is the region's pre-order
    /// first-occurrence, so emission is deterministic.
    fn phi_declarations(&self) -> Vec<syn::Stmt> {
        let mut seen: HashSet<ValueId> = HashSet::new();
        let mut targets: Vec<ValueId> = Vec::new();
        self.func.region.for_each_node(|node| {
            let transfer = match node {
                Region::Break { transfer, .. }
                | Region::Continue { transfer, .. }
                | Region::Transfer { transfer, .. } => transfer,
                _ => return,
            };
            for &(phi, _source) in transfer {
                if seen.insert(phi) {
                    targets.push(phi);
                }
            }
        });
        targets
            .into_iter()
            .map(|vid| {
                let name = self.value_ident(vid);
                let ty = match self.func.bindings.get(vid) {
                    Some(b) => ir_type(&b.ty, self.reg, self.policy),
                    None => self.policy.unknown_type(None),
                };
                parse_quote!(let mut #name: #ty;)
            })
            .collect()
    }

    /// `let vN: T;` for every value whose uses escape its defining scope,
    /// hoisted to the body top so it is in scope at every use; the value is
    /// assigned once at its definition site (see [`Self::basic_block_stmts`]).
    /// No `mut` — single assignment. Sorted for deterministic emission.
    fn escaping_declarations(&self) -> Vec<syn::Stmt> {
        let mut ids: Vec<ValueId> = self.escaping.iter().copied().collect();
        ids.sort_by_key(|v| v.index());
        ids.into_iter()
            .map(|vid| {
                let name = self.value_ident(vid);
                let ty = match self.func.bindings.get(vid) {
                    Some(b) => ir_type(&b.ty, self.reg, self.policy),
                    None => self.policy.unknown_type(None),
                };
                parse_quote!(let #name: #ty;)
            })
            .collect()
    }

    /// A region as its own braced block (a branch arm, loop body, scope).
    fn region_block(&self, region: &Region) -> syn::Block {
        let mut stmts = Vec::new();
        self.region_stmts(region, &mut stmts);
        parse_quote!({ #(#stmts)* })
    }

    /// Append the statements for one region node to `out`. Exhaustive on
    /// `Region` — a new variant must be given an emission here.
    fn region_stmts(&self, region: &Region, out: &mut Vec<syn::Stmt>) {
        match region {
            Region::Basic(b) => self.basic_block_stmts(*b, out),
            Region::Sequence(items) => {
                for item in items {
                    self.region_stmts(item, out);
                }
            }
            Region::Scope { out: label_blk, body } => {
                let label = block_label(*label_blk);
                let block = self.region_block(body);
                out.push(parse_quote!(#label: #block));
            }
            Region::If {
                cond,
                then_region,
                else_region,
            } => {
                let c = self.value_ref(*cond);
                let then_block = self.region_block(then_region);
                out.push(match else_region {
                    Some(er) => {
                        let else_block = self.region_block(er);
                        parse_quote!(if #c #then_block else #else_block)
                    }
                    None => parse_quote!(if #c #then_block),
                });
            }
            Region::Loop { header, body, .. } => {
                let label = block_label(*header);
                let block = self.region_block(body);
                out.push(parse_quote!(#label: loop #block));
            }
            Region::Switch {
                index,
                arms,
                default,
                ..
            } => {
                // W2 matches the raw integer selector; the dispatch-table
                // enum rendering is a host-idiom concern (later wave).
                let scrutinee = self.value_ref(*index);
                let mut match_arms: Vec<syn::Arm> = Vec::new();
                for arm in arms {
                    let pats: Vec<syn::Pat> = arm
                        .cases
                        .iter()
                        .map(|&c| {
                            let lit = proc_macro2::Literal::u32_unsuffixed(c);
                            parse_quote!(#lit)
                        })
                        .collect();
                    let body_block = self.region_block(&arm.body);
                    match_arms.push(parse_quote!(#(#pats)|* => #body_block));
                }
                let default_block = self.region_block(default);
                match_arms.push(parse_quote!(_ => #default_block));
                out.push(parse_quote!(match #scrutinee { #(#match_arms)* }));
            }
            Region::Break { target, transfer } => {
                self.emit_transfers(transfer, out);
                let label = block_label(*target);
                out.push(parse_quote!(break #label;));
            }
            Region::Continue { target, transfer } => {
                self.emit_transfers(transfer, out);
                let label = block_label(*target);
                out.push(parse_quote!(continue #label;));
            }
            Region::Transfer { transfer, .. } => self.emit_transfers(transfer, out),
            Region::Return { values } => out.push(self.return_stmt(values)),
            Region::Unreachable => out.push(parse_quote!(unreachable!();)),
            Region::Panic { .. } => out.push(parse_quote!(panic!();)),
            Region::Unstructured { entry, .. } => {
                let hole = self
                    .policy
                    .unknown_expr(&format!("unstructured control flow from bb{}", entry.index()));
                out.push(parse_quote!(#hole;));
            }
        }
    }

    /// The scheduled bindings of a basic block as `let vN = <expr>;`
    /// statements. Phi bindings are skipped — they are declared as
    /// `let mut` and assigned via transfers.
    fn basic_block_stmts(&self, b: BlockId, out: &mut Vec<syn::Stmt>) {
        let Some(block) = self.func.blocks.get(b) else {
            return;
        };
        for &vid in &block.bindings {
            let Some(binding) = self.func.bindings.get(vid) else {
                continue;
            };
            if matches!(binding.expr, Expr::Phi { .. }) {
                continue;
            }
            let value = expr::binding_expr(self, binding);
            // A value that is never read binds nothing: keep it only as a
            // statement when it carries an effect (a host call, a trap),
            // and drop it entirely when it is pure. A read value binds
            // normally — assigning a body-top-hoisted escapee, or a plain
            // inline `let`.
            if self.liveness.is_unused(vid) {
                // Escaping ⇒ read in a sibling scope ⇒ not unused, so an
                // eliminated value never leaves a hoisted decl unassigned.
                debug_assert!(!self.escaping.contains(&vid), "escaping value must be used");
                if liveness::is_effectful(&binding.expr) {
                    out.push(parse_quote!(#value;));
                }
            } else {
                let name = self.value_ident(vid);
                if self.escaping.contains(&vid) {
                    out.push(parse_quote!(#name = #value;));
                } else {
                    out.push(parse_quote!(let #name = #value;));
                }
            }
        }
    }

    /// Phi assignments for one edge: `vP = <source>;` per transfer pair.
    fn emit_transfers(&self, transfer: &[(ValueId, ValueId)], out: &mut Vec<syn::Stmt>) {
        for &(phi, source) in transfer {
            let lhs = self.value_ident(phi);
            let rhs = self.value_ref(source);
            out.push(parse_quote!(#lhs = #rhs;));
        }
    }

    fn return_stmt(&self, values: &[ValueId]) -> syn::Stmt {
        match values {
            [] => parse_quote!(return;),
            [one] => {
                let v = self.return_expr(*one);
                parse_quote!(return #v;)
            }
            many => {
                let vs: Vec<syn::Expr> = many.iter().map(|v| self.value_ref(*v)).collect();
                parse_quote!(return (#(#vs),*);)
            }
        }
    }

    /// The expression for a single returned value, wrapping it in `Ok`/`Err`
    /// when the function returns a `Result` and the value's recovered type
    /// says which. Four cases, all honoring never-guess:
    ///
    /// - an `Error` value → `Err(v)` (the recovered `#[contracterror]`);
    /// - an already-`Result` value → returned bare (a propagated `Result`,
    ///   which Rust returns without re-wrapping);
    /// - an `Unknown` value (a hole) → returned bare — a diverging `todo!`
    ///   compiles under any return type, and claiming `Ok` for a value we did
    ///   not recover would be a guess;
    /// - any other recovered payload → `Ok(v)`, or `Ok(())` when the `Ok`
    ///   type is unit.
    fn return_expr(&self, vid: ValueId) -> syn::Expr {
        let v = self.value_ref(vid);
        let Some(ok_ty) = sig::result_ok_type(self.func) else {
            return v; // not a Result-returning entrypoint
        };
        match self.func.bindings.get(vid).map(|b| &b.ty) {
            Some(IrType::Known(KnownType::Error) | IrType::Inferred(KnownType::Error)) => {
                parse_quote!(Err(#v))
            }
            Some(IrType::Known(KnownType::Result(..)) | IrType::Inferred(KnownType::Result(..)))
            | Some(IrType::Unknown(_))
            | None => v,
            Some(_) if sig::is_unit(ok_ty) => parse_quote!(Ok(())),
            Some(_) => parse_quote!(Ok(#v)),
        }
    }
}

/// The Rust lifetime label a block's scope/loop is named by: `'bb{index}`.
fn block_label(bid: BlockId) -> syn::Lifetime {
    syn::Lifetime::new(&format!("'bb{}", bid.index()), proc_macro2::Span::call_site())
}

/// The non-phi values whose uses escape the lexical block that defines
/// them, and so must be hoisted to a scope that dominates every use.
///
/// A `let` in a structured block is visible only in that block and its
/// nested blocks, but the CFG lets a value defined in one block be used in
/// any block it *dominates* — including a later sibling, once the defining
/// block's `{}` has closed. Such a value escapes. (Phis are handled
/// separately; function parameters are always in scope and never escape.)
fn escaping_values(func: &HighFunction) -> HashSet<ValueId> {
    let mut analysis = EscapeAnalysis::default();
    analysis.walk(func, &func.region, ROOT_SCOPE);
    analysis.finish()
}

/// Root lexical scope: the function body block itself.
const ROOT_SCOPE: usize = 0;

/// Assigns a lexical-scope id to every region and records, per value, the
/// scope it is defined in and the scopes it is read in — the inputs to the
/// escape test.
struct EscapeAnalysis {
    /// `parent[s]` is scope `s`'s enclosing scope; the root is its own parent.
    parent: Vec<usize>,
    /// Non-phi value → the scope of the `Basic` block that defines it.
    def_scope: HashMap<ValueId, usize>,
    /// Every `(value read, scope of the read)` pair.
    uses: Vec<(ValueId, usize)>,
}

impl Default for EscapeAnalysis {
    fn default() -> Self {
        Self {
            parent: vec![ROOT_SCOPE], // root's parent is itself
            def_scope: HashMap::new(),
            uses: Vec::new(),
        }
    }
}

impl EscapeAnalysis {
    /// Open a fresh child scope of `parent` and return its id.
    fn child_of(&mut self, parent: usize) -> usize {
        let id = self.parent.len();
        self.parent.push(parent);
        id
    }

    /// Record `region`'s defs and uses at lexical scope `scope`. Only the
    /// scope-opening variants (`Scope`/`If`/`Loop`/`Switch`) start a new
    /// child scope; a `Sequence` shares its parent's scope. Exhaustive on
    /// purpose — a new `Region` variant must be classified here.
    fn walk(&mut self, func: &HighFunction, region: &Region, scope: usize) {
        match region {
            Region::Basic(b) => {
                let Some(block) = func.blocks.get(*b) else {
                    return;
                };
                for &vid in &block.bindings {
                    let Some(binding) = func.bindings.get(vid) else {
                        continue;
                    };
                    binding.expr.for_each_value_use(|u| self.uses.push((u, scope)));
                    if !matches!(binding.expr, Expr::Phi { .. }) {
                        self.def_scope.insert(vid, scope);
                    }
                }
            }
            Region::Sequence(items) => {
                for item in items {
                    self.walk(func, item, scope);
                }
            }
            Region::Scope { body, .. } => {
                let inner = self.child_of(scope);
                self.walk(func, body, inner);
            }
            Region::If { cond, then_region, else_region } => {
                self.uses.push((*cond, scope));
                let t = self.child_of(scope);
                self.walk(func, then_region, t);
                if let Some(er) = else_region {
                    let e = self.child_of(scope);
                    self.walk(func, er, e);
                }
            }
            Region::Loop { body, .. } => {
                let inner = self.child_of(scope);
                self.walk(func, body, inner);
            }
            Region::Switch { index, arms, default, dispatch } => {
                self.uses.push((*index, scope));
                if let Some(d) = dispatch {
                    self.uses.push((*d, scope));
                }
                for arm in arms {
                    let s = self.child_of(scope);
                    self.walk(func, &arm.body, s);
                }
                let s = self.child_of(scope);
                self.walk(func, default, s);
            }
            Region::Break { transfer, .. }
            | Region::Continue { transfer, .. }
            | Region::Transfer { transfer, .. } => {
                for &(_phi, source) in transfer {
                    self.uses.push((source, scope));
                }
            }
            Region::Return { values } => {
                for &v in values {
                    self.uses.push((v, scope));
                }
            }
            Region::Unreachable | Region::Panic { .. } | Region::Unstructured { .. } => {}
        }
    }

    /// A value escapes if any use is in a scope not visible from its
    /// definition — i.e. `def_scope` is not an ancestor-or-equal of the use
    /// scope. Values with no recorded def (phis, parameters) never escape.
    fn finish(self) -> HashSet<ValueId> {
        let mut escaping = HashSet::new();
        for (value, use_scope) in &self.uses {
            if let Some(&def) = self.def_scope.get(value)
                && !self.is_ancestor_or_equal(def, *use_scope)
            {
                escaping.insert(*value);
            }
        }
        escaping
    }

    /// Whether scope `ancestor` encloses `scope` (or is it) — walk the
    /// parent chain to the root.
    fn is_ancestor_or_equal(&self, ancestor: usize, mut scope: usize) -> bool {
        loop {
            if scope == ancestor {
                return true;
            }
            let parent = self.parent[scope];
            if parent == scope {
                return false; // reached the root without meeting `ancestor`
            }
            scope = parent;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(i: u32) -> ValueId {
        ValueId::new(i)
    }

    #[test]
    fn a_value_used_in_a_sibling_scope_escapes() {
        // The token pattern: defined in one scope, used in a later sibling.
        let mut a = EscapeAnalysis::default();
        let bb7 = a.child_of(ROOT_SCOPE);
        let bb9 = a.child_of(ROOT_SCOPE);
        a.def_scope.insert(v(32), bb7);
        a.uses.push((v(32), bb9));
        assert!(a.finish().contains(&v(32)));
    }

    #[test]
    fn a_value_used_in_its_own_or_a_nested_scope_does_not_escape() {
        let mut a = EscapeAnalysis::default();
        let outer = a.child_of(ROOT_SCOPE);
        let inner = a.child_of(outer);
        a.def_scope.insert(v(10), outer);
        a.uses.push((v(10), outer)); // same scope
        a.uses.push((v(10), inner)); // nested — a nested block sees the outer let
        assert!(!a.finish().contains(&v(10)));
    }

    #[test]
    fn root_scope_values_never_escape() {
        let mut a = EscapeAnalysis::default();
        let child = a.child_of(ROOT_SCOPE);
        a.def_scope.insert(v(1), ROOT_SCOPE);
        a.uses.push((v(1), child)); // root dominates every scope
        assert!(!a.finish().contains(&v(1)));
    }

    #[test]
    fn a_value_with_no_recorded_def_is_never_escaping() {
        // Phis and parameters have no `def_scope` entry.
        let mut a = EscapeAnalysis::default();
        let child = a.child_of(ROOT_SCOPE);
        a.uses.push((v(7), child));
        assert!(a.finish().is_empty());
    }
}
