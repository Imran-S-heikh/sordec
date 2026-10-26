//! Function-body emission: the `Region` tree → a `syn::Block`.
//!
//! The compilable counterpart of `pretty_hir`'s `render_region`
//! (`sordec`): the same recursion over [`Region`], but it builds a
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
use sordec_ir::{
    BinaryOp, Binding, Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Region, SemanticOp,
    TypeRegistry,
};

use crate::rust::expr;
use crate::rust::fold::Fold;
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
    /// Renames and literals printed at their reads. See [`Fold`].
    fold: Fold,
    /// Read counts, driving dead-binding cleanup. See [`Liveness`].
    liveness: Liveness,
    /// Non-phi values whose uses escape the lexical block that defines them
    /// (dominance holds, lexical scope does not). Declared once at the body
    /// top and assigned at their definition site, so they stay in scope at
    /// every use. See [`escaping_values`].
    escaping: HashSet<ValueId>,
    /// Branches spelled `if let Some(v) = get(&k)`: the probe each tests →
    /// the read its present arm binds. Neither is a statement of its own —
    /// the probe is the `if let`, and the read is its pattern.
    if_lets: HashMap<ValueId, ValueId>,
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
    tail_expression(&mut stmts);
    parse_quote!({ #(#stmts)* })
}

/// Turn a trailing `return <expr>;` into a tail expression, and drop a
/// trailing bare `return;`.
///
/// The wasm says `return`, so the body walk faithfully emits one — but Rust
/// says the same thing with a tail expression, and that is what source is
/// written in. The difference is not cosmetic in two ways:
///
/// - `sordec-score`'s structure skeleton counts `syn::ExprReturn` as a
///   control-flow token, so an explicit `return` the source never wrote is
///   surplus control flow measured against the original. 205 of the 206
///   returns the corpus currently emits are trailing.
/// - clippy's `needless_return` fires on the current output, and the
///   reconstruction is a deliverable.
///
/// Applied to the **outermost** statement list only, which is what makes it
/// safe without any analysis: an early `return` inside an `if` arm or a
/// labeled scope is a nested statement and never reaches here (a `Scope`
/// becomes one `label: { … }` statement, see [`FnCtx::region_stmts`]). A body
/// whose last region is a trap ends in `panic!();` / `unreachable!();` and is
/// left alone.
fn tail_expression(stmts: &mut Vec<syn::Stmt>) {
    // A trailing `if`/`else` whose every arm ends in a return is the
    // source's `if c { a } else { b }` in tail position: each arm's return
    // becomes its tail value and the `if` becomes the body's.
    if let Some(syn::Stmt::Expr(syn::Expr::If(branch), _)) = stmts.last()
        && every_arm_returns(branch)
    {
        let Some(syn::Stmt::Expr(syn::Expr::If(mut branch), _)) = stmts.pop() else {
            return;
        };
        arms_to_tail(&mut branch);
        stmts.push(syn::Stmt::Expr(syn::Expr::If(branch), None));
        return;
    }
    // Only a *semicolon-terminated* `return`, i.e. one in statement
    // position. `Stmt::Expr(_, None)` is already a tail expression.
    let Some(syn::Stmt::Expr(syn::Expr::Return(ret), Some(_))) = stmts.last() else {
        return;
    };
    let returned = ret.expr.clone();
    stmts.pop();
    // `return;` leaves nothing behind: the unit value is the block's own.
    if let Some(expr) = returned {
        stmts.push(syn::Stmt::Expr(*expr, None));
    }
}

impl<'a> FnCtx<'a> {
    fn new(
        high: &'a HighIr,
        func: &'a HighFunction,
        reg: &'a TypeRegistry,
        policy: &'a dyn HolePolicy,
    ) -> Self {
        let names = ValueNames::build(func);
        let fold = Fold::build(func);
        let escaping = escaping_values(func, &fold);
        let if_lets = if_let_reads(func);
        let mut ctx = Self {
            high,
            func,
            reg,
            policy,
            names,
            // Provisional: every binding live. Only naming and rendering
            // are consulted while settling, and neither reads liveness.
            liveness: Liveness::build(func),
            escaping,
            fold,
            if_lets,
        };
        ctx.liveness = ctx.settle_liveness();
        // The escape set was taken before liveness settled. A value whose
        // only reader is dropped along the way is read by nothing, and a
        // hoisted declaration exists solely to keep a value in scope for a
        // reader in a sibling scope — with no reader there is nothing to
        // keep it in scope for, and the declaration would never be
        // assigned.
        ctx.escaping.retain(|v| !ctx.liveness.is_unused(*v));
        ctx
    }

    /// Recount reads until the dead set stops growing.
    ///
    /// Dropping a binding can make its operands dead in turn, so one count
    /// is not enough. Each round asks the *real* renderer whether a binding
    /// would survive — `expr::binding_expr` plus [`Self::is_hole_expr`],
    /// exactly what [`Self::basic_block_stmts`] will ask later — so the set
    /// this computes cannot drift from the set that actually gets emitted.
    ///
    /// Terminates because `dead` only grows and is bounded by the binding
    /// count.
    fn settle_liveness(&self) -> Liveness {
        let mut dead: HashSet<ValueId> = HashSet::new();
        loop {
            let liveness = Liveness::build_excluding(self.func, &dead, &self.fold);
            let mut grew = false;
            self.func.region.for_each_node(|node| {
                let Region::Basic(b) = node else { return };
                let Some(block) = self.func.blocks.get(*b) else {
                    return;
                };
                for &vid in &block.bindings {
                    if dead.contains(&vid) || self.escaping.contains(&vid) {
                        continue;
                    }
                    let Some(binding) = self.func.bindings.get(vid) else {
                        continue;
                    };
                    if matches!(binding.expr, Expr::Phi { .. }) || !liveness.is_unused(vid) {
                        continue;
                    }
                    let value = expr::binding_expr(self, binding);
                    if !liveness::survives_unused(&binding.expr, Self::is_hole_expr(&value)) {
                        dead.insert(vid);
                        grew = true;
                    }
                }
            });
            if !grew {
                return liveness;
            }
        }
    }

    /// The synthesized `Env` value every function carries as its leading
    /// parameter (see `sig::env_param`). Host idioms root on it.
    pub(crate) fn env(&self) -> syn::Expr {
        parse_quote!(e)
    }

    /// Render a `ValueId` as an expression, via the one naming authority:
    /// a rename reads as what it renames, a literal prints in place (see
    /// [`Fold`]).
    /// One argument of an internal call: the value, cloned when handing
    /// it over would move something the caller still reads.
    ///
    /// Every emitted helper takes its arguments by value, which is what
    /// the wasm says — the SDK's handle types are passed as one machine
    /// word — but Rust reads that as a move, and a caller that uses the
    /// value again after the call no longer owns it. rustc reports it as
    /// `use of moved value` and the crate does not build. The source
    /// avoids it by taking `&Env` and `&Address` in its helpers; a clone
    /// gets the same program without having to decide, per parameter,
    /// which side of the boundary a reference would sit on.
    ///
    /// Only where it is needed and only where it is safe: a value read
    /// once is read by this call and moves freely, a `Copy` type never
    /// moves at all, and a value whose type we never recovered is left
    /// alone — `todo!()` has no type for a method to resolve against.
    pub(crate) fn arg_ref(&self, vid: ValueId) -> syn::Expr {
        let rendered = self.value_ref(vid);
        if !self.moved_away(vid) {
            return rendered;
        }
        parse_quote!(#rendered.clone())
    }

    /// The `Env` as an internal call's leading argument, and as any
    /// argument a host idiom takes it by reference.
    ///
    /// Every helper takes `&Env`, so this is the borrow — written as
    /// `&e` where this function owns its own (an entrypoint, which
    /// `#[contractimpl]` hands the value) and as the bare name where it
    /// was handed a reference already.
    pub(crate) fn env_borrow(&self) -> syn::Expr {
        let e = self.env();
        if self.func.signature.is_some() {
            parse_quote!(&#e)
        } else {
            e
        }
    }

    /// Whether handing this value to a call would move it away from a
    /// reader that still needs it.
    fn moved_away(&self, vid: ValueId) -> bool {
        let target = self.fold.target(vid);
        if self.liveness.reads(target) <= 1 {
            return false;
        }
        matches!(
            self.func.bindings.get(target).map(|b| &b.ty),
            Some(IrType::Known(t) | IrType::Inferred(t)) if !is_copy(t)
        )
    }

    /// What a reference to `vid` names after renames are followed.
    pub(crate) fn fold_target(&self, vid: ValueId) -> ValueId {
        self.fold.target(vid)
    }

    pub(crate) fn value_ref(&self, vid: ValueId) -> syn::Expr {
        let target = self.fold.target(vid);
        if self.fold.is_literal(target)
            && let Some(binding) = self.func.bindings.get(target)
        {
            return expr::literal_ref(self, binding);
        }
        self.names.expr(target)
    }

    /// Whether `vid`'s recovered type is `bool`.
    ///
    /// Asked only by [`UnaryOp::Eqz`](sordec_ir::UnaryOp::Eqz), which is one
    /// opcode covering two Rust operators: `!flag` on a boolean and `n == 0`
    /// on an integer. Both readings are always *valid Rust*, so an
    /// unrecovered type has to pick one, and `== 0` is the safe default —
    /// it is what `eqz` means on the wasm value types, and rendering `!` on
    /// an integer would silently emit a bitwise complement instead.
    pub(crate) fn is_boolean(&self, vid: ValueId) -> bool {
        matches!(
            self.func.bindings.get(vid).map(|b| &b.ty),
            Some(IrType::Known(KnownType::Bool) | IrType::Inferred(KnownType::Bool))
        )
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
                let ty = self.value_type(vid);
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
                let ty = self.value_type(vid);
                parse_quote!(let #name: #ty;)
            })
            .collect()
    }

    /// Whether `contractspecv0` declares this function as returning nothing.
    ///
    /// Only a spec'd function answers `true`: a helper's return arity is
    /// recovered from its body, so its returned value is all the evidence
    /// there is and dropping it would delete a real result.
    fn returns_nothing_by_abi(&self) -> bool {
        self.func
            .signature
            .as_ref()
            .is_some_and(|sig| sig.outputs.is_empty())
    }

    /// Whether `vid`'s recovered type is one it is safe to annotate a hole
    /// with: a type whose ABI and wasm-machine representations coincide.
    ///
    /// Only `i32` and `i64`, because those two *are* the wasm value types. A
    /// recovered `u32` does not coincide — a `u32` travels inside an i64
    /// `Val`, so the value beside the hole is being masked and shifted as an
    /// i64 while the IR calls it `u32`. Same for `Address`, `Bytes`,
    /// `Symbol`, `i128`: each is an object handle or a pair at the machine
    /// level. Annotating those pins the ABI type onto machine-level code and
    /// relocates the error instead of removing it.
    ///
    /// Measured, since the first two guesses were wrong: annotating every
    /// hole cost +150 errors (`Unknown` renders as `Val`, overriding types
    /// rustc had already inferred from use sites); annotating every recovered
    /// type cost attestation 8 and timelock 6; annotating only the coinciding
    /// two is worth -66.
    /// A hole whose recovered type is a host-object handle — an `Address`,
    /// a `Symbol` — and which nothing does machine arithmetic on.
    ///
    /// The documented objection to annotating these is that the value
    /// beside the hole is masked and shifted as an `i64` while the IR calls
    /// it an `Address`, so pinning the ABI type relocates the error. That
    /// holds only where the hole's value *is* masked and shifted. A hole
    /// that is only ever passed along — cloned into a call that wants an
    /// `Address` — has no machine-level reader to contradict, and without
    /// the annotation `let v = todo!()` has nothing to infer from.
    fn has_handle_type_untouched(&self, vid: ValueId) -> bool {
        // A map or vec counts too: an SDK generic it is handed to (the
        // event data `publish` takes) pins nothing, and the never-type
        // fallback then makes the hole `()`.
        let handle = matches!(
            self.func.bindings.get(vid).map(|b| &b.ty),
            Some(
                IrType::Known(
                    KnownType::Address
                        | KnownType::Symbol
                        | KnownType::String
                        | KnownType::Bytes
                        | KnownType::BytesN(_)
                        | KnownType::Map(_, _)
                        | KnownType::Vec(_)
                ) | IrType::Inferred(
                    KnownType::Address
                        | KnownType::Symbol
                        | KnownType::String
                        | KnownType::Bytes
                        | KnownType::BytesN(_)
                        | KnownType::Map(_, _)
                        | KnownType::Vec(_)
                )
            )
        );
        // `==` against a value of the same handle type is the type's own
        // `PartialEq`, not a machine reader: `account` compares the
        // signer's `Address` with the current contract's.
        let base = |v: ValueId| match self.func.bindings.get(v).map(|b| &b.ty) {
            Some(IrType::Known(k) | IrType::Inferred(k)) => Some(k),
            _ => None,
        };
        let same_handle = |a: ValueId, b: ValueId| base(a).is_some() && base(a) == base(b);
        // A reader nothing reads is the residue of a recognized check
        // (`v & 255` beside the tag test that replaced it), not a reader.
        handle
            && !self.func.bindings.iter().any(|(id, b)| match &b.expr {
                _ if self.liveness.is_unused(id) => false,
                Expr::Binary { op: BinaryOp::Eq | BinaryOp::Ne, lhs, rhs } if same_handle(*lhs, *rhs) => false,
                Expr::Binary { lhs, rhs, .. } => *lhs == vid || *rhs == vid,
                Expr::Unary { value, .. } => *value == vid,
                _ => false,
            })
    }

    /// The machine type of an untyped memory read that only arithmetic and
    /// comparisons read: `i64` for an 8-byte read, `i32` for a full 4-byte
    /// one. Left untyped, the hole's `!` falls back to `()` and every one
    /// of those readers fails (`() == i32`). A read anything else consumes
    /// may be a host handle, which the width says nothing about, and is
    /// left to inference.
    fn raw_load_word(&self, vid: ValueId) -> Option<syn::Type> {
        let b = self.func.bindings.get(vid)?;
        if !matches!(b.ty, IrType::Unknown(_)) {
            return None;
        }
        let ty: syn::Type = match &b.expr {
            // The word the opcode produced, recorded at lowering; failing
            // that, what the width alone settles.
            Expr::Load { width, signed, ty, .. } => match (ty, width, signed) {
                (IrType::Known(KnownType::I32), ..) => parse_quote!(i32),
                (IrType::Known(KnownType::I64), ..) => parse_quote!(i64),
                (_, sordec_ir::MemWidth::W8, _) => parse_quote!(i64),
                (_, sordec_ir::MemWidth::W4, None) => parse_quote!(i32),
                _ => return None,
            },
            // An unrecovered small-value decode is the word the shift leaves.
            Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { .. })) => parse_quote!(i64),
            _ => return None,
        };
        // Live readers only: a rename a rewrite left unscheduled is read by
        // nothing and is not a reader, but a merge is.
        let scheduled: HashSet<ValueId> =
            self.func.blocks.iter().flat_map(|(_, b)| b.bindings.iter().copied()).collect();
        let mut readers = 0;
        let mut only_arith = true;
        for (id, r) in self.func.bindings.iter() {
            let mut reads = false;
            r.expr.for_each_value_use(|u| reads |= u == vid);
            if !reads {
                continue;
            }
            let live = scheduled.contains(&id) || matches!(r.expr, Expr::Phi { .. });
            // Arithmetic in the wide sense: binary ops, a zero test
            // (`x == 0` is `eqz`), and the integer width moves.
            // An unrecovered operation reading it is a hole: it prints as a
            // `todo!()` and consumes no type, so it says nothing either way.
            let arith = matches!(
                r.expr,
                Expr::Binary { .. }
                    | Expr::Unknown { .. }
                    | Expr::Unary {
                        op: sordec_ir::UnaryOp::Eqz
                            | sordec_ir::UnaryOp::BitNot
                            | sordec_ir::UnaryOp::Wrap32
                            | sordec_ir::UnaryOp::ExtendU32
                            | sordec_ir::UnaryOp::ExtendS32,
                        ..
                    }
            );
            if !live || self.liveness.is_unused(id) && !arith {
                continue;
            }
            readers += 1;
            only_arith &= arith;
        }
        let mut region_reads = 0;
        self.func.region.for_each_value_use(|u| region_reads += usize::from(u == vid));
        // A 4-byte word tested by a branch is tested as one: `cond_ref`
        // writes `!= 0` for it, so the read is integer arithmetic too.
        let region_ok = region_reads == 0 || self.is_word_load(vid);
        ((readers > 0 || region_reads > 0) && only_arith && region_ok).then_some(ty)
    }

    /// An untyped full 4-byte memory read: a 32-bit word, which no `Val`
    /// (always 8 bytes) can be.
    fn is_word_load(&self, vid: ValueId) -> bool {
        matches!(
            self.func.bindings.get(vid),
            Some(Binding {
                ty: IrType::Unknown(_),
                expr: Expr::Load { width: sordec_ir::MemWidth::W4, signed: None, .. },
                ..
            })
        )
    }

    fn has_machine_type(&self, vid: ValueId) -> bool {
        matches!(
            self.func.bindings.get(vid).map(|b| &b.ty),
            Some(
                IrType::Known(
                    KnownType::I32
                        | KnownType::I64
                        | KnownType::U32
                        | KnownType::U64
                        | KnownType::Bool
                ) | IrType::Inferred(
                    KnownType::I32
                        | KnownType::I64
                        | KnownType::U32
                        | KnownType::U64
                        | KnownType::Bool
                )
            )
        )
    }

    /// A branch condition, as Rust spells it.
    ///
    /// Wasm's `if`/`br_if` branch when the operand is **nonzero**, and the
    /// IR records that faithfully: the condition is whatever integer the
    /// test was applied to. Rust has no such coercion, so a condition that
    /// is not already `bool` needs the comparison written out —
    /// `let v31 = v29 & 1i32; if v31 {}` is rustc's `expected bool, found
    /// i32`, and the low-bit mask is the shape it most often takes.
    ///
    /// This is a language-surface adaptation, not a repair: nothing in the
    /// IR is wrong, the two languages simply spell the same test
    /// differently. Only machine integers are adapted. A condition still
    /// typed `Unknown` renders as `Val`, and `Val != 0` is not true either
    /// — inventing a comparison there would assert a shape we have not
    /// recovered, so it is left alone to fail visibly.
    fn cond_ref(&self, vid: ValueId) -> syn::Expr {
        let expr = self.value_ref(vid);
        if self.is_machine_integer(vid) || self.is_untyped_arithmetic(vid) || self.is_word_load(vid) {
            parse_quote!(#expr != 0)
        } else {
            expr
        }
    }

    /// A result of integer arithmetic not typed as an integer: an integer,
    /// whatever its width, so the truth test is `!= 0` on it as on a typed
    /// one. Untyped, or typed `bool` by the branch that tests it — which
    /// arithmetic in Rust never yields.
    fn is_untyped_arithmetic(&self, vid: ValueId) -> bool {
        // Through renames: the branch often tests a copy of the result.
        let mut at = vid;
        for _ in 0..8 {
            match self.func.bindings.get(at).map(|b| &b.expr) {
                Some(Expr::Use(next)) => at = *next,
                _ => break,
            }
        }
        let Some(b) = self.func.bindings.get(at) else { return false };
        // On `bool`s the bitwise operators are the logical ones, so a
        // `bool`-typed `a | b` is a `bool`; only arithmetic proper is not.
        if matches!(b.ty, IrType::Known(KnownType::Bool) | IrType::Inferred(KnownType::Bool)) {
            return matches!(
                b.expr,
                Expr::Binary {
                    op: sordec_ir::BinaryOp::Add
                        | sordec_ir::BinaryOp::Sub
                        | sordec_ir::BinaryOp::Mul
                        | sordec_ir::BinaryOp::Shl
                        | sordec_ir::BinaryOp::Shr,
                    ..
                }
            );
        }
        // Untyped, a bitwise op on a `bool` operand is logical as well:
        // `(a != 0) | (b < c)` is a `bool` whatever it has been typed.
        if let Expr::Binary {
            op: sordec_ir::BinaryOp::BitAnd | sordec_ir::BinaryOp::BitOr | sordec_ir::BinaryOp::BitXor,
            lhs,
            rhs,
        } = &b.expr
            && (self.is_boolean(*lhs) || self.is_boolean(*rhs))
        {
            return false;
        }
        matches!(b.ty, IrType::Unknown(_)) && matches!(
                b.expr,
                Expr::Binary {
                    op: sordec_ir::BinaryOp::Add
                        | sordec_ir::BinaryOp::Sub
                        | sordec_ir::BinaryOp::Mul
                        | sordec_ir::BinaryOp::BitAnd
                        | sordec_ir::BinaryOp::BitOr
                        | sordec_ir::BinaryOp::BitXor
                        | sordec_ir::BinaryOp::Shl
                        | sordec_ir::BinaryOp::Shr,
                    ..
                }
            )
    }

    /// Whether a binding is an integer the wasm truth test was applied to
    /// — `bool` deliberately excluded, being already a condition.
    fn is_machine_integer(&self, vid: ValueId) -> bool {
        matches!(
            self.func.bindings.get(vid).map(|b| &b.ty),
            Some(
                IrType::Known(
                    KnownType::I32 | KnownType::I64 | KnownType::U32 | KnownType::U64
                ) | IrType::Inferred(
                    KnownType::I32 | KnownType::I64 | KnownType::U32 | KnownType::U64
                )
            )
        )
    }

    /// The recovered type of a binding, degrading through the hole policy.
    pub(crate) fn value_type(&self, vid: ValueId) -> syn::Type {
        match self.func.bindings.get(vid) {
            Some(b) => ir_type(&b.ty, self.reg, self.policy),
            None => self.policy.unknown_type(None),
        }
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
            } if self.if_lets.contains_key(cond) => {
                let read = self.if_lets[cond];
                let header = self.if_let_header(read);
                let then_block = self.region_block(then_region);
                out.push(match else_region {
                    Some(er) => {
                        let else_block = self.region_block(er);
                        parse_quote!(if let #header #then_block else #else_block)
                    }
                    None => parse_quote!(if let #header #then_block),
                });
            }
            Region::If {
                cond,
                then_region,
                else_region,
            } => {
                let c = self.cond_ref(*cond);
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
            if self.if_lets.contains_key(&vid) || self.if_lets.values().any(|r| *r == vid) {
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
                if liveness::survives_unused(&binding.expr, Self::is_hole_expr(&value)) {
                    out.push(parse_quote!(#value;));
                }
            } else {
                let name = self.value_ident(vid);
                if self.escaping.contains(&vid) {
                    // The hoisted declaration already carries the type.
                    out.push(parse_quote!(#name = #value;));
                } else if Self::is_hole_expr(&value)
                    && let Some(ty) = self.raw_load_word(vid)
                {
                    // An untyped memory read nothing reads but arithmetic is
                    // the machine word its width says; see `raw_load_word`.
                    out.push(parse_quote!(let #name: #ty = #value;));
                } else if Self::is_hole_expr(&value)
                    && (self.has_machine_type(vid) || self.has_handle_type_untouched(vid))
                {
                    // `todo!(…)` has type `!`, so an unannotated `let` leaves
                    // the binding's type to inference. Where the uses pin it,
                    // inference does *better* than we can — it reads the
                    // actual use sites. Where they do not, the never-type
                    // fallback makes the binding `()` and every use then
                    // fails (`() - i32`).
                    //
                    // So annotate only a machine-level `i32` — see
                    // `has_machine_type` for why that is the one safe case.
                    // Measured: annotating unconditionally cost +150 errors
                    // (`Unknown` renders as `Val`, forced onto values rustc
                    // had inferred correctly), and annotating every recovered
                    // type still cost the two smallest fixtures 14 between
                    // them.
                    let ty = self.value_type(vid);
                    out.push(parse_quote!(let #name: #ty = #value;));
                } else if Self::reads_a_recovered_type(binding) {
                    // `Storage::get` is generic in its payload, so nothing
                    // at the use site pins it when the value only flows
                    // into field accesses — `let b = …get(&k).unwrap();
                    // b.amount` is `type annotations needed`. This is the
                    // narrow case the broad experiment in the branch above
                    // was not: the type came from the contract's own spec,
                    // and the call genuinely cannot be inferred without it.
                    let ty = self.value_type(vid);
                    out.push(parse_quote!(let #name: #ty = #value;));
                } else {
                    out.push(parse_quote!(let #name = #value;));
                }
            }
        }
    }

    /// `Some(v) = …get::<K, T>(&k)`, the head of an `if let` — the pattern
    /// binds the read's own name, so every reader on the arm finds it.
    fn if_let_header(&self, read: ValueId) -> proc_macro2::TokenStream {
        let Some(binding) = self.func.bindings.get(read) else {
            let hole = self.policy.unknown_expr("if-let read");
            return quote::quote!(Some(_) = #hole);
        };
        let payload = (!matches!(binding.ty, IrType::Unknown(_))).then(|| self.value_type(read));
        let get = match &binding.expr {
            Expr::Semantic(SemanticOp::Known(op)) => crate::rust::idiom::option_read(self, op, payload),
            _ => None,
        }
        .unwrap_or_else(|| self.policy.unknown_expr("if-let read"));
        if self.liveness.is_unused(read) {
            quote::quote!(Some(_) = #get)
        } else {
            let name = self.value_ident(read);
            quote::quote!(Some(#name) = #get)
        }
    }

    /// A generic SDK read whose payload type came from the contract's
    /// declared types. Only a `UserDefined` type qualifies: it is one the
    /// reconstruction also declares, so naming it cannot conflict with
    /// what rustc would have inferred.
    ///
    /// An SDK handle type too — `Address`, `Symbol`, the byte types: the
    /// SDK's own, so naming it cannot conflict either, and a read handed
    /// straight on (an address only a placeholder call consumes) has
    /// nothing else to pin it.
    fn reads_a_recovered_type(binding: &Binding) -> bool {
        let named = |k: &KnownType| {
            matches!(
                k,
                KnownType::UserDefined(_)
                    | KnownType::Address
                    | KnownType::Symbol
                    | KnownType::String
                    | KnownType::Bytes
                    | KnownType::BytesN(_)
                    | KnownType::Bool
                    | KnownType::U32
                    | KnownType::I32
                    | KnownType::U64
                    | KnownType::I64
                    | KnownType::U128
                    | KnownType::I128
            )
        };
        matches!(&binding.ty, IrType::Known(k) | IrType::Inferred(k) if named(k)) && matches!(
            binding.expr,
            Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet { .. }))
        )
    }

    /// Whether an emitted value is one of the hole policy's `todo!(…)`
    /// expressions.
    ///
    /// Asked of the rendered expression rather than of the IR node, so the
    /// answer cannot drift from what [`super::hole::HolePolicy`] actually
    /// emits: the set of expression kinds that become holes lives in
    /// `expr.rs`, and duplicating it here is exactly the kind of second copy
    /// that goes stale.
    fn is_hole_expr(value: &syn::Expr) -> bool {
        matches!(value, syn::Expr::Macro(m) if m.mac.path.is_ident("todo"))
    }

    /// Phi assignments for one edge: `vP = <source>;` per transfer pair.
    fn emit_transfers(&self, transfer: &[(ValueId, ValueId)], out: &mut Vec<syn::Stmt>) {
        for &(phi, source) in transfer {
            let lhs = self.value_ident(phi);
            // A constant flowing into a merge takes the merge's type, the
            // same rule a call argument already follows: the variable is
            // declared from what the merge proved (`let mut v109: u64;`)
            // while the literal still carries the wasm word it was loaded
            // as (`0i64`). Unsuffixed, it takes the declared type — and
            // only when it fits, so a real disagreement stays visible.
            let rhs = self
                .func
                .bindings
                .get(phi)
                .and_then(|b| {
                    self.result_wrapped(source, &b.ty)
                        .or_else(|| expr::unsuffixed_against(self, source, &b.ty))
                        .or_else(|| expr::val_constant(self, source, phi))
                        .or_else(|| expr::sign_cast(self, source, &b.ty))
                        .or_else(|| self.val_merge_input(source, phi))
                        .or_else(|| expr::bool_to_int(self, source, &b.ty))
                })
                .unwrap_or_else(|| self.value_ref(source));
            out.push(parse_quote!(#lhs = #rhs;));
        }
    }

    /// A host object merged into a `Val` — declared one, or untyped and so
    /// declared one — converted on the way in: the merge holds the encoded
    /// word, `Option<Address>` as its `Val` with the `Void` beside it.
    fn val_merge_input(&self, source: ValueId, phi: ValueId) -> Option<syn::Expr> {
        let merge = self.func.bindings.get(phi)?;
        if !matches!(
            merge.ty,
            IrType::Unknown(_) | IrType::Known(KnownType::Val) | IrType::Inferred(KnownType::Val)
        ) {
            return None;
        }
        let src = self.func.bindings.get(self.fold_target(source))?;
        let object = matches!(
            &src.ty,
            IrType::Known(
                KnownType::Address
                    | KnownType::Symbol
                    | KnownType::String
                    | KnownType::Bytes
                    | KnownType::BytesN(_)
                    | KnownType::Vec(_)
                    | KnownType::Map(_, _)
            ) | IrType::Inferred(
                KnownType::Address
                    | KnownType::Symbol
                    | KnownType::String
                    | KnownType::Bytes
                    | KnownType::BytesN(_)
                    | KnownType::Vec(_)
                    | KnownType::Map(_, _)
            )
        );
        if object {
            let x = self.arg_ref(source);
            let e = self.env_borrow();
            return Some(parse_quote!(soroban_sdk::IntoVal::<soroban_sdk::Env, soroban_sdk::Val>::into_val(&#x, #e)));
        }
        // The constant beside such an object is its encoding already.
        let has_object_input = matches!(&merge.expr, Expr::Phi { incoming } if incoming.iter().any(|(_, v)| {
            self.func.bindings.get(self.fold_target(*v)).is_some_and(|b| matches!(
                &b.ty,
                IrType::Known(KnownType::Address | KnownType::Symbol | KnownType::String | KnownType::Bytes)
                    | IrType::Inferred(KnownType::Address | KnownType::Symbol | KnownType::String | KnownType::Bytes)
            ))
        }));
        if has_object_input && let Expr::Literal(sordec_ir::Literal::I64(bits)) = src.expr {
            return Some(if bits == 2 {
                parse_quote!(soroban_sdk::Val::VOID.into())
            } else {
                let lit = proc_macro2::Literal::u64_suffixed(bits as u64);
                parse_quote!(soroban_sdk::Val::from_payload(#lit))
            });
        }
        // A computed 64-bit word beside them is a `Val` built by hand — a
        // small symbol assembled as `(chars << 8) | 14` — and is those bits.
        if has_object_input
            && matches!(&src.ty, IrType::Known(KnownType::I64 | KnownType::U64) | IrType::Inferred(KnownType::I64 | KnownType::U64))
        {
            let x = self.value_ref(source);
            return Some(parse_quote!(soroban_sdk::Val::from_payload(#x as u64)));
        }
        None
    }

    /// A value merged into the function's `Result`, wrapped the way a
    /// returned one is ([`Self::return_expr`]): the merge *is* the returned
    /// value, collected from several paths before one `return`. An error
    /// goes in as `Err(e)`; the `Void` a `Result<(), E>` encodes `Ok` as
    /// goes in as `Ok(())`. Anything else is left to the other rules.
    fn result_wrapped(&self, source: ValueId, merge_ty: &IrType) -> Option<syn::Expr> {
        if !matches!(merge_ty, IrType::Known(KnownType::Result(..)) | IrType::Inferred(KnownType::Result(..))) {
            return None;
        }
        let ok_ty = sig::result_ok_type(self.func)?;
        let binding = self.func.bindings.get(source)?;
        match &binding.ty {
            IrType::Known(KnownType::Error) | IrType::Inferred(KnownType::Error) => {
                let v = self.value_ref(source);
                Some(parse_quote!(Err(#v)))
            }
            _ if sig::is_unit(ok_ty)
                && matches!(binding.expr, Expr::Literal(sordec_ir::Literal::I64(2))) =>
            {
                Some(parse_quote!(Ok(())))
            }
            // The `Ok` payload itself, typed as the `Result`'s `Ok` side.
            IrType::Known(k) | IrType::Inferred(k)
                if matches!(merge_ty, IrType::Known(KnownType::Result(ok, _)) | IrType::Inferred(KnownType::Result(ok, _))
                    if matches!(&**ok, IrType::Known(o) | IrType::Inferred(o) if o == k)) =>
            {
                let v = self.value_ref(source);
                Some(parse_quote!(Ok(#v)))
            }
            _ => None,
        }
    }

    /// The single type a helper (no spec) is emitted returning.
    fn helper_return_type(&self) -> Option<IrType> {
        if self.func.signature.is_some() {
            return None;
        }
        match sig::helper_return_site(self.func)?.as_slice() {
            [one] => self.func.bindings.get(*one).map(|b| b.ty.clone()),
            _ => None,
        }
    }

    fn return_stmt(&self, values: &[ValueId]) -> syn::Stmt {
        // A spec'd entrypoint declaring no output returns nothing, whatever
        // the wasm hands back. The SDK's exported wrapper always returns a
        // `Val` — `Void` for a Rust `fn … -> ()` — so a faithful body walk
        // produces `return <the Void>;` against a signature with no return
        // type. The ABI is authoritative about the arity, so the value is
        // dropped: `contractspecv0` says this function returns nothing, and
        // `__constructor` is the corpus witness.
        if values.len() == 1 && self.returns_nothing_by_abi() {
            return parse_quote!(return;);
        }
        match values {
            [] => parse_quote!(return;),
            [one] => {
                // A helper's constant return takes the type the function
                // returns, as a merge's constant input does.
                let v = self
                    .helper_return_type()
                    .and_then(|ty| {
                        expr::unsuffixed_against(self, *one, &ty).or_else(|| expr::sign_cast(self, *one, &ty))
                    })
                    .unwrap_or_else(|| self.return_expr(*one));
                parse_quote!(return #v;)
            }
            // Each element is declared by its binding's type (`sig::
            // helper_return`), and a flag typed as the wasm word it travels
            // in is still printed as the comparison it is: cast it back.
            many => {
                let vs: Vec<syn::Expr> = many
                    .iter()
                    .map(|v| {
                        self.func
                            .bindings
                            .get(*v)
                            .and_then(|b| expr::bool_to_int(self, *v, &b.ty))
                            .unwrap_or_else(|| self.value_ref(*v))
                    })
                    .collect();
                parse_quote!(return (#(#vs),*);)
            }
        }
    }

    /// A returned `Vec` spread back into the tuple the spec declares.
    ///
    /// A Soroban tuple's wire form **is** a vec of its components, so a
    /// function returning `(i128, i128)` returns a two-element vec and the
    /// SDK's encoder is what built it. Handed back as a vec it is the right
    /// value with the wrong Rust type, which is `dex-liquidity-pool`'s last
    /// compile error, twice.
    ///
    /// Only when the spec says tuple *and* the value is a vec: a function
    /// that really returns a `Vec` is left alone, and so is one whose value
    /// we could not type — spreading an unrecovered value would invent an
    /// arity.
    ///
    /// `get_unchecked` rather than `get(i).unwrap()`: the arity comes from
    /// the contract's own declared ABI, so an index inside it is not a
    /// claim that needs an `unwrap` to stand behind — and `unwrap` would
    /// read as a panic the source never wrote.
    fn tuple_unpacked(&self, vid: ValueId) -> syn::Expr {
        let v = self.value_ref(vid);
        let Some(arity) = sig::declared_tuple_arity(self.func) else {
            return v;
        };
        if !self.emits_a_vec(vid) {
            return v;
        }
        let items: Vec<syn::Expr> = (0..arity)
            .map(|i| {
                let i = proc_macro2::Literal::u32_unsuffixed(i);
                parse_quote!(#v.get_unchecked(#i))
            })
            .collect();
        parse_quote!((#(#items),*))
    }

    /// Whether the Rust this binding emits is a `Vec`.
    ///
    /// Its *recovered* type is not the question: the ABI seeds the returned
    /// value with the tuple the spec declares, so it already reads
    /// `(i128, i128)` while the expression that produces it is a call to a
    /// helper emitting `Vec<i128>`. What the destructure needs to know is
    /// which of the two the Rust actually is — and for a call that is the
    /// callee's own emitted return type, which is the helper's returned
    /// binding.
    ///
    /// Anything else says no. A multi-value call already renders as a real
    /// Rust tuple, and indexing one would not compile.
    fn emits_a_vec(&self, vid: ValueId) -> bool {
        let is_vec = |ty: Option<&IrType>| {
            matches!(
                ty,
                Some(IrType::Known(KnownType::Vec(_)) | IrType::Inferred(KnownType::Vec(_)))
            )
        };
        match self.func.bindings.get(vid).map(|b| &b.expr) {
            Some(Expr::Call { target, .. }) => {
                let Some(callee) = self.high.function(*target) else {
                    return false;
                };
                match callee.returns.as_slice() {
                    [one] => match one.as_slice() {
                        [value] => is_vec(callee.bindings.get(*value).map(|b| &b.ty)),
                        _ => false,
                    },
                    _ => false,
                }
            }
            _ => is_vec(self.func.bindings.get(vid).map(|b| &b.ty)),
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
        let v = self.tuple_unpacked(vid);
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

/// Whether `branch` has an `else` and every arm, through `else if` chains,
/// ends in a `return` — so the whole `if` can be the tail value.
fn every_arm_returns(branch: &syn::ExprIf) -> bool {
    let ends_in_return = |stmts: &[syn::Stmt]| match stmts.last() {
        Some(syn::Stmt::Expr(syn::Expr::Return(_), Some(_))) => true,
        Some(syn::Stmt::Expr(syn::Expr::If(inner), _)) => every_arm_returns(inner),
        _ => false,
    };
    let Some((_, else_branch)) = &branch.else_branch else {
        return false;
    };
    ends_in_return(&branch.then_branch.stmts)
        && match else_branch.as_ref() {
            syn::Expr::Block(block) => ends_in_return(&block.block.stmts),
            syn::Expr::If(inner) => every_arm_returns(inner),
            _ => false,
        }
}

/// Turn every arm's trailing `return` into its tail value.
fn arms_to_tail(branch: &mut syn::ExprIf) {
    tail_expression(&mut branch.then_branch.stmts);
    if let Some((_, else_branch)) = &mut branch.else_branch {
        match else_branch.as_mut() {
            syn::Expr::Block(block) => tail_expression(&mut block.block.stmts),
            syn::Expr::If(inner) => arms_to_tail(inner),
            _ => {}
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
fn escaping_values(func: &HighFunction, fold: &Fold) -> HashSet<ValueId> {
    let mut analysis = EscapeAnalysis::default();
    analysis.walk(func, &func.region, ROOT_SCOPE);
    // Judge each read by the value it prints as, as the renderer will.
    analysis.uses = analysis
        .uses
        .into_iter()
        .filter_map(|(value, scope)| fold.reads(value).map(|v| (v, scope)))
        .collect();
    analysis.finish()
}

/// The `if let` branches in this body: probe → the read it binds.
///
/// Keyed on what the region tree actually holds — a read marked present
/// whose branch is not there (a later rewrite moved it) is spelled where
/// it stands, with the `unwrap` its proven presence allows.
fn if_let_reads(func: &HighFunction) -> HashMap<ValueId, ValueId> {
    let mut conds = HashSet::new();
    func.region.for_each_node(|node| {
        if let Region::If { cond, .. } = node {
            conds.insert(*cond);
        }
    });
    func.bindings
        .iter()
        .filter_map(|(id, b)| match &b.expr {
            Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet {
                missing: sordec_ir::Missing::Present(probe),
                ..
            })) if conds.contains(probe) => Some((*probe, id)),
            _ => None,
        })
        .collect()
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
                    liveness::rendered_reads(func, binding, |u| self.uses.push((u, scope)));
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

/// Whether a recovered type is `Copy`, so handing it to a call is not a
/// move.
///
/// The scalars and `Val` are; every SDK handle type carries an `Env`
/// beside its host handle and is `Clone` only. A composite or
/// user-defined type is a `#[contracttype]`, which derives `Clone`.
fn is_copy(ty: &KnownType) -> bool {
    matches!(
        ty,
        KnownType::Bool
            | KnownType::Unit
            | KnownType::U32
            | KnownType::I32
            | KnownType::U64
            | KnownType::I64
            | KnownType::U128
            | KnownType::I128
            | KnownType::U256
            | KnownType::I256
            | KnownType::Timepoint
            | KnownType::Duration
            | KnownType::Error
            | KnownType::Val
    )
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

