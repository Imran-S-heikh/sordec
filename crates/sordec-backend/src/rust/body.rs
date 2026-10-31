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
use crate::rust::idiom;
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
    /// Payload bindings a `match` arm's pattern binds (see
    /// [`variant_patterns`]): `p` in `E::X(p) => ..`. Each is the pattern,
    /// not a statement of its own.
    pattern_bound: HashSet<ValueId>,
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
        let pattern_bound = variant_patterns(func, reg);
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
            pattern_bound,
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

    /// Whether `contractspecv0` declares this function as returning nothing:
    /// no output, or the one output `()` (`-> ()` written out).
    ///
    /// Only a spec'd function answers `true`: a helper's return arity is
    /// recovered from its body, so its returned value is all the evidence
    /// there is and dropping it would delete a real result.
    fn returns_nothing_by_abi(&self) -> bool {
        self.func
            .signature
            .as_ref()
            .is_some_and(|sig| matches!(sig.outputs.as_slice(), [] | [sordec_ir::TypeRef::Primitive(sordec_ir::PrimitiveType::Void)]))
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
        Some(match self.raw_load_kind(vid)? {
            KnownType::I32 => parse_quote!(i32),
            _ => parse_quote!(i64),
        })
    }

    /// The integer type a gap's `let` is annotated with by [`Self::raw_load_word`]
    /// — `i32` or `i64` — when it is printed with one, so an operator reading it
    /// knows the type Rust will see. A hoisted (escaping) declaration is
    /// typed elsewhere and answers `None`.
    pub(crate) fn hole_word_type(&self, vid: ValueId) -> Option<KnownType> {
        if self.escaping.contains(&vid) {
            return None;
        }
        self.raw_load_kind(vid)
    }

    fn raw_load_kind(&self, vid: ValueId) -> Option<KnownType> {
        let b = self.func.bindings.get(vid)?;
        if !matches!(b.ty, IrType::Unknown(_)) {
            return None;
        }
        let ty = match &b.expr {
            // The word the opcode produced, recorded at lowering; failing
            // that, what the width alone settles.
            Expr::Load { width, signed, ty, .. } => match (ty, width, signed) {
                (IrType::Known(KnownType::I32), ..) => KnownType::I32,
                (IrType::Known(KnownType::I64), ..) => KnownType::I64,
                (_, sordec_ir::MemWidth::W8, _) => KnownType::I64,
                (_, sordec_ir::MemWidth::W4, None) => KnownType::I32,
                _ => return None,
            },
            // An unrecovered small-value decode is the word the shift leaves.
            Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { .. })) => KnownType::I64,
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

    /// A hole the IR has typed as a 128-bit integer, read only as one: by
    /// its limbs (`wide_lo`/`wide_hi`), or by arithmetic and comparisons
    /// whose other operand is the same 128-bit type or a literal.
    ///
    /// An `i128` is two words at the machine level, so it is not among the
    /// machine types above; but these readers are what the wide passes
    /// print *for* an `i128` (`(v as i64)`, `((v >> 64) as i64)`, `v <= 0`),
    /// never a word masked as one. Left bare, the cast `v as i64` has no
    /// type to cast from: "type annotations needed". The type printed is
    /// the one the IR holds, and every reader the annotation constrains is
    /// one that takes it; a region read (a return, a condition, a merge's
    /// input) or any other reader leaves the hole to inference.
    fn read_as_wide_integer(&self, vid: ValueId) -> bool {
        let wide = |v: ValueId| {
            matches!(
                self.func.bindings.get(self.fold_target(v)).map(|b| &b.ty),
                Some(IrType::Known(KnownType::I128 | KnownType::U128) | IrType::Inferred(KnownType::I128 | KnownType::U128))
            )
        };
        if !wide(vid) {
            return false;
        }
        let literal = |v: ValueId| {
            matches!(self.func.bindings.get(self.fold_target(v)).map(|b| &b.expr), Some(Expr::Literal(_)))
        };
        let (readers, other) = self.emitted_readers(vid);
        !other
            && !readers.is_empty()
            && readers.iter().all(|r| match self.func.bindings.get(*r).map(|b| &b.expr) {
                Some(Expr::Unary { op: sordec_ir::UnaryOp::WideLo | sordec_ir::UnaryOp::WideHi, value }) => {
                    self.fold.reads(*value) == Some(vid)
                }
                // A comparison with a literal prints the literal bare
                // (`v <= 0`); arithmetic may print its suffix, so it needs
                // a 128-bit operand on the other side.
                Some(Expr::Binary { op, lhs, rhs })
                    if op.is_comparison()
                        || matches!(
                            op,
                            BinaryOp::Add
                                | BinaryOp::Sub
                                | BinaryOp::Mul
                                | BinaryOp::Div
                                | BinaryOp::Rem
                                | BinaryOp::MulOverflows
                        ) =>
                {
                    let other_ok = |o: ValueId| wide(o) || (op.is_comparison() && literal(o));
                    match (self.fold.reads(*lhs) == Some(vid), self.fold.reads(*rhs) == Some(vid)) {
                        (true, true) => true,
                        (true, false) => other_ok(*rhs),
                        (false, true) => other_ok(*lhs),
                        (false, false) => false,
                    }
                }
                _ => false,
            })
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
                        | sordec_ir::BinaryOp::Shr
                        | sordec_ir::BinaryOp::ShrU,
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
                        | sordec_ir::BinaryOp::Shr
                        | sordec_ir::BinaryOp::ShrU,
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
                dispatch: Some(d),
            } if d == index && variant_union(self.func, self.reg, *index).is_some() => {
                out.push(self.variant_match(*index, arms, default));
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
            if self.pattern_bound.contains(&vid) {
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
                } else if (Self::is_hole_expr(&value) || Self::is_empty_vec(binding))
                    && (self.has_machine_type(vid) || self.has_handle_type_untouched(vid))
                {
                    // `todo!(…)` has type `!`, so an unannotated `let` leaves
                    // the binding's type to inference. Where the uses pin it,
                    // inference does *better* than we can — it reads the
                    // actual use sites. Where they do not, the never-type
                    // fallback makes the binding `()` and every use then
                    // fails (`() - i32`).
                    //
                    // So this branch annotates only a machine word (see
                    // `has_machine_type`) or a handle nothing does arithmetic
                    // on (`has_handle_type_untouched`); the branches below
                    // annotate only for a reader that cannot infer the type.
                    // Measured: annotating unconditionally cost +150 errors
                    // (`Unknown` renders as `Val`, forced onto values rustc
                    // had inferred correctly), and annotating every recovered
                    // type still cost the two smallest fixtures 14 between
                    // them.
                    let ty = self.value_type(vid);
                    out.push(parse_quote!(let #name: #ty = #value;));
                } else if Self::is_hole_expr(&value)
                    && (self.converted_to_val_only(vid)
                        || self.read_as_declared_struct(vid)
                        || self.read_as_wide_integer(vid))
                {
                    // Annotated for what reads it, not for being a hole:
                    // a reader that cannot infer the type — a conversion
                    // through `Val`, a field access — and the type the IR
                    // already holds. See the two predicates.
                    let ty = self.value_type(vid);
                    out.push(parse_quote!(let #name: #ty = #value;));
                } else if Self::reads_a_recovered_type(binding) {
                    // `Storage::get` is generic in its payload, so nothing
                    // at the use site pins it when the value only flows
                    // into field accesses — `let b = …get(&k).unwrap();
                    // b.amount` is `type annotations needed`. This is the
                    // narrow case the broad experiment recorded in the
                    // machine-type branch was not: the type came from the
                    // contract's own spec, and the call genuinely cannot be
                    // inferred without it.
                    let ty = self.value_type(vid);
                    out.push(parse_quote!(let #name: #ty = #value;));
                } else {
                    out.push(parse_quote!(let #name = #value;));
                }
            }
        }
    }

    /// The bindings the emitted body reads `vid` in — through renames, as
    /// [`Liveness`] counts reads — and whether anything else reads it.
    ///
    /// A reader dropped as dead is not one, and neither is a reader that
    /// renders as a hole: `todo!("…")` names its operands inside a string
    /// and reads none of them. "Anything else" is a read the region makes
    /// itself (a condition, a return, a merge's input), a merge, or an
    /// `if let` — each pins a type of its own, which the callers here do
    /// not look at.
    fn emitted_readers(&self, vid: ValueId) -> (Vec<ValueId>, bool) {
        let mut readers = Vec::new();
        let mut other = false;
        self.func.region.for_each_value_use(|u| other |= self.fold.reads(u) == Some(vid));
        self.func.region.for_each_node(|node| {
            let Region::Basic(b) = node else { return };
            let Some(block) = self.func.blocks.get(*b) else {
                return;
            };
            for &id in &block.bindings {
                let Some(r) = self.func.bindings.get(id) else {
                    continue;
                };
                let mut reads = false;
                liveness::rendered_reads(self.func, r, |u| reads |= self.fold.reads(u) == Some(vid));
                if !reads {
                    continue;
                }
                if matches!(r.expr, Expr::Phi { .. })
                    || self.if_lets.contains_key(&id)
                    || self.if_lets.values().any(|read| *read == id)
                {
                    other = true;
                    continue;
                }
                let hole = Self::is_hole_expr(&expr::binding_expr(self, r));
                if hole || self.liveness.is_unused(id) && !liveness::survives_unused(&r.expr, hole) {
                    continue;
                }
                readers.push(id);
            }
        });
        (readers, other)
    }

    /// An untyped hole whose every emitted reader converts it into a `Val`
    /// first ([`idiom::converted_to_val`]): `len()` on a receiver the IR
    /// has not typed as a `Vec`, spelled
    /// `IntoVal::<Env, Vec<Val>>::into_val(&IntoVal::<Env, Val>::into_val(&v, e), e).len()`.
    ///
    /// `into_val` is generic in what it converts, so nothing at that reader
    /// pins the hole's type; the `!` of `todo!()` falls back to `()`, which
    /// rustc rejects ("depends on never type fallback"). Annotating it `Val`
    /// is exact: an untyped value is printed `Val` everywhere else, the
    /// reader already treats it as the `Val` the host call was handed, and
    /// `into_val` of a `Val` into a `Val` is the identity.
    ///
    /// The same holds for a reader that hands the hole straight to a method
    /// generic in `IntoVal<Env, Val>` — the value `storage().set` stores,
    /// the data `events().publish` publishes ([`idiom::generic_val_operand`]).
    ///
    /// Keyed on the reader, not on the hole — annotating holes as such was
    /// measured to cost errors (see the comment in the machine-type branch
    /// of `basic_block_stmts`). Any other reader that prints it, or a read
    /// by the region, leaves the hole alone: that reader may pin a type of
    /// its own.
    fn converted_to_val_only(&self, vid: ValueId) -> bool {
        let renders_as_val = match self.func.bindings.get(vid).map(|b| &b.ty) {
            Some(IrType::Unknown(reason)) => self.policy.unknown_word(reason).is_none(),
            Some(IrType::Known(KnownType::Val) | IrType::Inferred(KnownType::Val)) => true,
            _ => false,
        };
        if !renders_as_val {
            return false;
        }
        let (readers, other) = self.emitted_readers(vid);
        !other
            && !readers.is_empty()
            && readers.iter().all(|r| match self.func.bindings.get(*r).map(|b| &b.expr) {
                Some(Expr::Semantic(SemanticOp::Known(op))) => {
                    idiom::converted_to_val(self, op).and_then(|x| self.fold.reads(x)) == Some(vid)
                        || idiom::generic_val_operand(op).and_then(|x| self.fold.reads(x)) == Some(vid)
                }
                _ => false,
            })
    }

    /// A hole the IR has typed as one of the contract's declared structs,
    /// and which the body reads only by its fields: `let v72 =
    /// todo!("vec::Get");` then `v72.min_recv`.
    ///
    /// rustc must know a receiver's type at a field access, and a `todo!()`
    /// gives it none, so the access is "type annotations needed". The type
    /// printed is the one the IR holds, not one chosen here.
    ///
    /// Exact by its own gates, whatever pass produced the reads: the type
    /// is a struct the reconstruction declares (looked up among the
    /// structs, so an enum, union, error or event sharing the id space
    /// never qualifies), every emitted reader is a field access naming a
    /// field that struct declares, and nothing else reads the value — not
    /// the region (a return, a condition, a merge's input), a merge, or an
    /// `if let`. So every use the annotation constrains is one it
    /// satisfies. Requiring *only* field reads is also what keeps out
    /// arithmetic on the value, including arithmetic behind a rename: a
    /// rename the IR typed differently is not folded ([`Fold`]) and prints
    /// as its own `let`, which is a reader that is not a field access.
    fn read_as_declared_struct(&self, vid: ValueId) -> bool {
        let Some(IrType::Known(KnownType::UserDefined(id)) | IrType::Inferred(KnownType::UserDefined(id))) =
            self.func.bindings.get(vid).map(|b| &b.ty)
        else {
            return false;
        };
        let Some(def) = self.reg.structs.iter().find(|s| s.id == *id) else {
            return false;
        };
        let (readers, other) = self.emitted_readers(vid);
        !other
            && !readers.is_empty()
            && readers.iter().all(|r| {
                matches!(
                    self.func.bindings.get(*r).map(|b| &b.expr),
                    Some(Expr::Field { base, field })
                        if self.fold.reads(*base) == Some(vid) && def.fields.iter().any(|f| f.name == *field)
                )
            })
    }

    /// A switch on an enum value's variant as the `match` it is:
    /// `match v { E::X(p) => { .. } E::Y => { .. } _ => { .. } }`.
    ///
    /// Each case is a variant's position among the enum's declared cases
    /// (see `Region::Switch::dispatch`); an arm's payload bindings are its
    /// pattern's names, `_` where the arm binds none or nothing reads it.
    /// An arm of several cases matches them all, ignoring their payloads.
    /// The default arm is the variants no arm names: written as that
    /// variant when there is exactly one, `_` otherwise.
    fn variant_match(&self, index: ValueId, arms: &[sordec_ir::SwitchArm], default: &Region) -> syn::Stmt {
        let union = variant_union(self.func, self.reg, index).expect("checked by the caller");
        let owner = crate::rust::ty::ident(&union.name);
        let pattern = |case: usize, binders: &HashMap<u32, ValueId>| -> syn::Pat {
            let Some(variant) = union.cases.get(case) else {
                return parse_quote!(_);
            };
            let name = crate::rust::ty::ident(&variant.name);
            if variant.fields.is_empty() {
                return parse_quote!(#owner::#name);
            }
            let parts: Vec<syn::Pat> = (0..variant.fields.len())
                .map(|k| match binders.get(&(k as u32)) {
                    Some(v) if !self.liveness.is_unused(*v) => {
                        let id = self.value_ident(*v);
                        parse_quote!(#id)
                    }
                    _ => parse_quote!(_),
                })
                .collect();
            parse_quote!(#owner::#name(#(#parts),*))
        };
        let scrutinee = self.value_ref(index);
        let mut named: HashSet<usize> = HashSet::new();
        let mut match_arms: Vec<syn::Arm> = Vec::new();
        for arm in arms {
            let binders: HashMap<u32, ValueId> = if arm.cases.len() == 1 {
                arm_payloads(self.func, &arm.body, index)
                    .into_iter()
                    .filter(|v| self.pattern_bound.contains(v))
                    .filter_map(|v| match &self.func.bindings.get(v)?.expr {
                        Expr::VariantPayload { index: k, .. } => Some((*k, v)),
                        _ => None,
                    })
                    .collect()
            } else {
                HashMap::new()
            };
            let pats: Vec<syn::Pat> = arm
                .cases
                .iter()
                .map(|&c| {
                    named.insert(c as usize);
                    pattern(c as usize, &binders)
                })
                .collect();
            let body_block = self.region_block(&arm.body);
            match_arms.push(parse_quote!(#(#pats)|* => #body_block));
        }
        let rest: Vec<usize> = (0..union.cases.len()).filter(|c| !named.contains(c)).collect();
        // Every variant named: the match is exhaustive, and a trapping
        // default would be an unreachable pattern.
        if rest.is_empty() && matches!(default, Region::Unreachable) {
            return parse_quote!(match #scrutinee { #(#match_arms)* });
        }
        let default_block = self.region_block(default);
        match rest.as_slice() {
            [only] => {
                let pat = pattern(*only, &HashMap::new());
                match_arms.push(parse_quote!(#pat => #default_block));
            }
            _ => match_arms.push(parse_quote!(_ => #default_block)),
        }
        parse_quote!(match #scrutinee { #(#match_arms)* })
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
        // The stored `Val` itself, read whole and handed on: named too, or a
        // reader typed as a number would have `get` decode the `Val` as one.
        let raw_val = matches!(&binding.ty, IrType::Known(KnownType::Val) | IrType::Inferred(KnownType::Val))
            && matches!(
                binding.expr,
                Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet { missing: sordec_ir::Missing::Unwrap, .. }))
            );
        raw_val
            || matches!(&binding.ty, IrType::Known(k) | IrType::Inferred(k) if named(k))
                && matches!(binding.expr, Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet { .. })))
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

    /// `Vec::new(&e)`: generic in its element as a hole is in its whole
    /// type, so it is annotated on the same terms one was.
    fn is_empty_vec(binding: &sordec_ir::Binding) -> bool {
        matches!(
            &binding.expr,
            Expr::Semantic(sordec_ir::SemanticOp::Known(sordec_ir::KnownOp::VecOp {
                kind: sordec_ir::VecOpKind::New,
                args,
            })) if args.is_empty()
        )
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
                        .or_else(|| self.word_merge_input(source, phi).and_then(|_| expr::val_bits(self, source, &b.ty)))
                        .or_else(|| expr::bool_to_int(self, source, &b.ty))
                })
                .unwrap_or_else(|| self.value_ref(source));
            out.push(parse_quote!(#lhs = #rhs;));
        }
    }

    /// A merge that is the machine word for a reason of its own: another of
    /// its arms is a number, not a `Val`. Its `Val` arms hand it their bits
    /// ([`expr::val_bits`]); a merge whose every arm is a `Val` and typed as
    /// a number has its type from what the `Val` encodes, and is left to
    /// fail visibly.
    fn word_merge_input(&self, source: ValueId, phi: ValueId) -> Option<()> {
        let Expr::Phi { incoming } = &self.func.bindings.get(phi)?.expr else { return None };
        let number = |t: &IrType| {
            matches!(
                t,
                IrType::Known(KnownType::I64 | KnownType::U64 | KnownType::I32 | KnownType::U32)
                    | IrType::Inferred(KnownType::I64 | KnownType::U64 | KnownType::I32 | KnownType::U32)
            )
        };
        incoming
            .iter()
            .any(|(_, v)| *v != source && self.func.bindings.get(self.fold_target(*v)).is_some_and(|b| number(&b.ty)))
            .then_some(())
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
    /// An error value: the SDK's `Error`, or one of the contract's own
    /// `#[contracterror]` enums. Neither is ever a `Result`'s `Ok` payload
    /// — the spec has no way to declare an error enum as a value type — so
    /// in a function returning a `Result`, a value of either is its `Err`.
    fn is_error_type(&self, ty: &IrType) -> bool {
        match ty {
            IrType::Known(KnownType::Error) | IrType::Inferred(KnownType::Error) => true,
            IrType::Known(KnownType::UserDefined(id)) | IrType::Inferred(KnownType::UserDefined(id)) => {
                self.reg.errors.iter().any(|d| d.id == *id)
            }
            _ => false,
        }
    }

    fn result_wrapped(&self, source: ValueId, merge_ty: &IrType) -> Option<syn::Expr> {
        if !matches!(merge_ty, IrType::Known(KnownType::Result(..)) | IrType::Inferred(KnownType::Result(..))) {
            return None;
        }
        let ok_ty = sig::result_ok_type(self.func)?;
        let binding = self.func.bindings.get(source)?;
        match &binding.ty {
            ty if self.is_error_type(ty) => {
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
                    .or_else(|| expr::val_returned_constant(self, *one))
                    .unwrap_or_else(|| self.return_expr(*one));
                parse_quote!(return #v;)
            }
            // Each element is declared by its binding's type (`sig::
            // helper_return`), and a flag typed as the wasm word it travels
            // in is still printed as the comparison it is: cast it back.
            //
            // The declaration is one site's; another site's element may be
            // the same word in the other sign (`u64` from an object decode
            // beside an `i64` shift), so it is cast to the declared type —
            // all of its bits kept.
            many => {
                let declared: Option<Vec<IrType>> = if self.func.signature.is_some() {
                    None
                } else {
                    sig::helper_return_site(self.func)
                        .filter(|s| s.len() == many.len())
                        .and_then(|s| s.iter().map(|v| self.func.bindings.get(*v).map(|b| b.ty.clone())).collect())
                };
                let vs: Vec<syn::Expr> = many
                    .iter()
                    .enumerate()
                    .map(|(i, v)| {
                        let want = declared.as_ref().and_then(|d| d.get(i));
                        self.func
                            .bindings
                            .get(*v)
                            .and_then(|b| expr::bool_to_int(self, *v, &b.ty))
                            .or_else(|| {
                                let b = self.func.bindings.get(*v)?;
                                let ty = want.filter(|t| **t != b.ty)?;
                                expr::unsuffixed_against(self, *v, ty).or_else(|| expr::sign_cast(self, *v, ty))
                            })
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
            Some(ty) if self.is_error_type(ty) => parse_quote!(Err(#v)),
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

/// The declared enum with payloads a switch selects the variant of, when
/// `index` is a value typed as one.
fn variant_union<'r>(func: &HighFunction, reg: &'r TypeRegistry, index: ValueId) -> Option<&'r sordec_ir::UnionDef> {
    let (IrType::Known(KnownType::UserDefined(id)) | IrType::Inferred(KnownType::UserDefined(id))) =
        &func.bindings.get(index)?.ty
    else {
        return None;
    };
    reg.unions.iter().find(|u| u.id == *id)
}

/// The [`Expr::VariantPayload`] bindings of `value` an arm opens with: the
/// leading bindings of its first block.
fn arm_payloads(func: &HighFunction, body: &Region, value: ValueId) -> Vec<ValueId> {
    let first = match body {
        Region::Basic(b) => Some(*b),
        Region::Sequence(items) => match items.first() {
            Some(Region::Basic(b)) => Some(*b),
            _ => None,
        },
        _ => None,
    };
    let Some(block) = first.and_then(|b| func.blocks.get(b)) else {
        return Vec::new();
    };
    block
        .bindings
        .iter()
        .copied()
        .take_while(|v| {
            matches!(func.bindings.get(*v).map(|b| &b.expr), Some(Expr::VariantPayload { value: x, .. }) if *x == value)
        })
        .collect()
}

/// The payload bindings a `match` arm's pattern binds: those an arm of one
/// case opens with, of that case's variant, at a component the variant
/// declares, on a switch [`FnCtx::variant_match`] prints as a `match`. Any
/// other has no pattern to stand in and prints as the hole it is.
fn variant_patterns(func: &HighFunction, reg: &TypeRegistry) -> HashSet<ValueId> {
    let mut bound = HashSet::new();
    func.region.for_each_node(|node| {
        let Region::Switch { index, arms, dispatch: Some(d), .. } = node else { return };
        if d != index {
            return;
        }
        let Some(union) = variant_union(func, reg, *index) else { return };
        for arm in arms {
            let [case] = arm.cases.as_slice() else { continue };
            let Some(variant) = union.cases.get(*case as usize) else { continue };
            let mut seen: HashSet<u32> = HashSet::new();
            for v in arm_payloads(func, &arm.body, *index) {
                if let Some(Expr::VariantPayload { variant: name, index: k, .. }) = func.bindings.get(v).map(|b| &b.expr)
                    && *name == variant.name
                    && (*k as usize) < variant.fields.len()
                    && seen.insert(*k)
                {
                    bound.insert(v);
                }
            }
        }
    });
    bound
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

    /// The emitted body of a one-block helper whose parameter is `v0` and
    /// whose bindings are `exprs` from `v1` on, all scheduled in order;
    /// `tail` follows the block.
    fn emitted(exprs: Vec<(IrType, Expr)>, tail: Vec<Region>, reg: &TypeRegistry) -> String {
        emitted_returning(exprs, tail, reg, vec![])
    }

    fn emitted_returning(
        exprs: Vec<(IrType, Expr)>,
        tail: Vec<Region>,
        reg: &TypeRegistry,
        returns: Vec<Vec<ValueId>>,
    ) -> String {
        use quote::ToTokens;
        use sordec_common::{Arena, FuncId, Provenance, ProvenanceSource};
        use sordec_ir::{HighBlock, MemoryImage, WasmFacts};

        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        let param = (IrType::Known(KnownType::I32), Expr::Phi { incoming: vec![] });
        for (ty, expr) in std::iter::once(param).chain(exprs) {
            let id = v(bindings.len() as u32);
            bindings.push(Binding::new(id, ty, expr, Provenance::new("test", ProvenanceSource::DataFlow, "test")));
        }
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        let b0 = BlockId::from_index(0);
        blocks.push(HighBlock { id: b0, bindings: (1..bindings.len() as u32).map(v).collect() });
        let region = if tail.is_empty() {
            Region::Basic(b0)
        } else {
            Region::Sequence(std::iter::once(Region::Basic(b0)).chain(tail).collect())
        };
        let func = HighFunction {
            id: FuncId::from_index(0),
            name: None,
            signature: None,
            aliases: Vec::new(),
            blocks,
            bindings,
            region,
            params: vec![v(0)],
            returns,
        };
        let high = HighIr {
            facts: WasmFacts {
                imports: vec![],
                exports: vec![],
                function_type_indices: vec![],
                function_bodies: vec![],
                function_fingerprints: vec![],
                table_functions: None,
                custom_sections: vec![],
            },
            soroban_facts: None,
            functions: vec![func],
            memory: MemoryImage::empty(),
        };
        let policy = crate::rust::hole::StrictNoGuess;
        emit_body(&high, &high.functions[0], reg, &policy).to_token_stream().to_string()
    }

    fn untyped() -> IrType {
        IrType::Unknown(sordec_common::UnknownReason::InsufficientEvidence)
    }

    /// `load arg0 width 8`, which the emitter cannot render: a hole.
    fn wide_load() -> Expr {
        Expr::Load { addr: v(0), offset: 0, width: sordec_ir::MemWidth::W8, signed: None, ty: untyped() }
    }

    /// A memory write of `value`: a hole too, kept because it writes.
    fn store(value: u32) -> Expr {
        Expr::Store { addr: v(0), value: v(value), offset: 0, width: sordec_ir::MemWidth::W8 }
    }

    fn known(op: KnownOp) -> Expr {
        Expr::Semantic(SemanticOp::Known(op))
    }

    fn vec_len(recv: u32) -> Expr {
        known(KnownOp::VecOp { kind: sordec_ir::VecOpKind::Len, args: vec![v(recv)] })
    }

    fn mask(value: u32, literal: u32) -> Expr {
        Expr::Binary { op: BinaryOp::BitAnd, lhs: v(value), rhs: v(literal) }
    }

    fn i64_lit(n: i64) -> (IrType, Expr) {
        (IrType::Known(KnownType::I64), Expr::Literal(sordec_ir::Literal::I64(n)))
    }

    fn ret(value: u32) -> Region {
        Region::Return { values: vec![v(value)] }
    }

    /// `DataKey::Temp(<payload>)` read by a `has`, the variant declaring a
    /// field of `declared` and the payload being `wrap32(arg)`.
    /// `enum E { A, B(S) }`, `struct S { x: i64 }`, and a switch on `v0`'s
    /// variant whose `B` arm opens with its payload and reads `S.x`.
    #[test]
    fn a_switch_on_an_enum_values_variant_prints_as_a_match_binding_the_payload() {
        use sordec_common::{Arena, FuncId, Provenance, ProvenanceSource, TypeId};
        use sordec_ir::{HighBlock, MemoryImage, StructDef, StructField, SwitchArm, TypeRef, UnionCase, UnionDef, WasmFacts};
        use quote::ToTokens;

        let mut reg = TypeRegistry::default();
        reg.unions.push(UnionDef {
            id: TypeId::new(0),
            name: "E".into(),
            cases: vec![
                UnionCase { name: "A".into(), fields: vec![] },
                UnionCase { name: "B".into(), fields: vec![TypeRef::UserDefined(TypeId::new(1))] },
            ],
            exported: true,
        });
        reg.structs.push(StructDef {
            id: TypeId::new(1),
            name: "S".into(),
            fields: vec![StructField { name: "x".into(), ty: TypeRef::Primitive(sordec_ir::PrimitiveType::I64) }],
        });
        let exprs = vec![
            (IrType::Known(KnownType::UserDefined(TypeId::new(0))), Expr::Phi { incoming: vec![] }),
            (
                IrType::Known(KnownType::UserDefined(TypeId::new(1))),
                Expr::VariantPayload { value: v(0), variant: "B".into(), index: 0 },
            ),
            (IrType::Known(KnownType::I64), Expr::Field { base: v(1), field: "x".into() }),
            i64_lit(0),
        ];
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        for (ty, expr) in exprs {
            let id = v(bindings.len() as u32);
            bindings.push(Binding::new(id, ty, expr, Provenance::new("test", ProvenanceSource::DataFlow, "test")));
        }
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        for (i, b) in [vec![], vec![v(1), v(2)], vec![v(3)]].into_iter().enumerate() {
            blocks.push(HighBlock { id: BlockId::from_index(i as u32), bindings: b });
        }
        let region = Region::Switch {
            index: v(0),
            arms: vec![SwitchArm {
                cases: vec![1],
                body: Region::Sequence(vec![Region::Basic(BlockId::from_index(1)), ret(2)]),
            }],
            default: Box::new(Region::Sequence(vec![Region::Basic(BlockId::from_index(2)), ret(3)])),
            dispatch: Some(v(0)),
        };
        let func = HighFunction {
            id: FuncId::from_index(0),
            name: None,
            signature: None,
            aliases: Vec::new(),
            blocks,
            bindings,
            region: Region::Sequence(vec![Region::Basic(BlockId::from_index(0)), region]),
            params: vec![v(0)],
            returns: vec![vec![v(2)], vec![v(3)]],
        };
        let high = HighIr {
            facts: WasmFacts {
                imports: vec![],
                exports: vec![],
                function_type_indices: vec![],
                function_bodies: vec![],
                function_fingerprints: vec![],
                table_functions: None,
                custom_sections: vec![],
            },
            soroban_facts: None,
            functions: vec![func],
            memory: MemoryImage::empty(),
        };
        let policy = crate::rust::hole::StrictNoGuess;
        let body = emit_body(&high, &high.functions[0], &reg, &policy).to_token_stream().to_string();
        let arg = body.split("match ").nth(1).and_then(|r| r.split_whitespace().next()).unwrap_or_default().to_string();
        assert!(body.contains(&format!("match {arg} {{ E :: B (v1) =>")), "{body}");
        assert!(body.contains("v1 . x"), "{body}");
        // The one variant no arm names is the default's.
        assert!(body.contains("E :: A =>"), "{body}");
        // The payload is the pattern's, never a statement of its own.
        assert!(!body.contains("todo !"), "{body}");
        assert!(!body.contains("let v1"), "{body}");
    }

    fn key_with_payload(declared: sordec_ir::PrimitiveType) -> String {
        use sordec_ir::{EnumKey, KnownTier, StorageTier};
        let mut reg = TypeRegistry::default();
        reg.unions.push(sordec_ir::UnionDef {
            id: sordec_common::TypeId::new(3),
            name: "DataKey".to_string(),
            cases: vec![sordec_ir::UnionCase {
                name: "Temp".to_string(),
                fields: vec![sordec_ir::TypeRef::Primitive(declared)],
            }],
            exported: true,
        });
        let has = known(KnownOp::StorageHas {
            tier: StorageTier::Known(KnownTier::Temporary),
            durability: v(0),
            key: v(0),
            resolved_key: Some(EnumKey {
                enum_name: "DataKey".to_string(),
                variant: "Temp".to_string(),
                payload: vec![v(1)],
            }),
            probe: false,
        });
        emitted(
            vec![
                (untyped(), Expr::Unary { op: sordec_ir::UnaryOp::Wrap32, value: v(0) }),
                (IrType::Known(KnownType::Bool), has),
            ],
            vec![ret(2)],
            &reg,
        )
    }

    #[test]
    fn a_variant_payload_of_the_other_sign_is_cast_to_the_declared_field() {
        let out = key_with_payload(sordec_ir::PrimitiveType::U32);
        assert!(out.contains("Temp (v1 as u32)") || out.contains("Temp ((v1 as u32))"), "{out}");
    }

    #[test]
    fn a_variant_payload_of_the_declared_sign_is_left_alone() {
        let out = key_with_payload(sordec_ir::PrimitiveType::I32);
        assert!(out.contains("Temp (v1)"), "{out}");
    }

    /// `v1 op 4` where `v1` is typed as the declared type `id`, which the
    /// registry holds as an integer enum, an error enum, or not at all.
    fn ordered_on(op: BinaryOp, kind: &str) -> String {
        let id = sordec_common::TypeId::new(5);
        let mut reg = TypeRegistry::default();
        let def = sordec_ir::EnumDef {
            id,
            name: "Flag".to_string(),
            cases: vec![sordec_ir::EnumCase { name: "A".to_string(), value: 0 }],
        };
        match kind {
            "enum" => reg.enums.push(def),
            "error" => reg.errors.push(def),
            _ => {}
        }
        emitted(
            vec![
                (IrType::Known(KnownType::UserDefined(id)), Expr::Unary { op: sordec_ir::UnaryOp::Wrap32, value: v(0) }),
                (IrType::Known(KnownType::U32), Expr::Literal(sordec_ir::Literal::U32(4))),
                (IrType::Known(KnownType::Bool), Expr::Binary { op, lhs: v(1), rhs: v(2) }),
            ],
            vec![ret(3)],
            &reg,
        )
    }

    #[test]
    fn an_ordering_of_an_integer_enum_compares_its_discriminant() {
        let out = packed(&ordered_on(BinaryOp::GtU, "enum"));
        assert!(out.contains("(v1asu32)>4"), "{out}");
    }

    #[test]
    fn an_equality_of_an_integer_enum_is_left_alone() {
        let out = packed(&ordered_on(BinaryOp::Eq, "enum"));
        assert!(!out.contains("asu32"), "{out}");
    }

    #[test]
    fn an_ordering_of_a_non_enum_or_an_error_enum_is_left_alone() {
        for kind in ["error", "none"] {
            let out = packed(&ordered_on(BinaryOp::GtU, kind));
            assert!(!out.contains("(v1asu32)"), "{kind}: {out}");
        }
    }

    /// `wrap32` of a binding typed `ty`, returned.
    fn wrapped(ty: IrType) -> String {
        emitted(
            vec![
                (ty, Expr::Use(v(0))),
                (IrType::Known(KnownType::I32), Expr::Unary { op: sordec_ir::UnaryOp::Wrap32, value: v(1) }),
            ],
            vec![ret(2)],
            &TypeRegistry::default(),
        )
    }

    #[test]
    fn a_width_move_of_a_val_reads_its_bits() {
        let out = packed(&wrapped(IrType::Known(KnownType::Val)));
        assert!(out.contains("(v1.get_payload()asi32)"), "{out}");
    }

    #[test]
    fn a_width_move_of_an_integer_is_a_plain_cast() {
        let out = packed(&wrapped(IrType::Known(KnownType::I64)));
        assert!(out.contains("(v1asi32)") && !out.contains("get_payload"), "{out}");
    }

    /// `addr.require_auth_for_args(v)`, `v` a vec typed `Vec<element>`.
    fn auth_for_args(element: IrType) -> String {
        emitted(
            vec![
                (IrType::Known(KnownType::Address), Expr::Use(v(0))),
                (
                    IrType::Inferred(KnownType::Vec(Box::new(element))),
                    known(KnownOp::VecNew { vals_pos: v(0), len: v(0), elements: Some(vec![]) }),
                ),
                (IrType::Known(KnownType::Unit), known(KnownOp::RequireAuthForArgs { address: v(1), args: vec![v(2)] })),
            ],
            vec![],
            &TypeRegistry::default(),
        )
    }

    /// The host takes a `Vec<Val>`: a vec of `i32`s is handed over as the
    /// same object viewed as one.
    #[test]
    fn a_typed_vec_of_auth_args_is_viewed_as_vals() {
        let out = packed(&auth_for_args(IrType::Known(KnownType::I32)));
        assert!(out.contains("require_auth_for_args(v2.to_vals())"), "{out}");
    }

    #[test]
    fn a_vec_of_vals_or_of_nothing_named_is_passed_as_it_is() {
        for element in [IrType::Known(KnownType::Val), untyped()] {
            let out = packed(&auth_for_args(element));
            assert!(out.contains("require_auth_for_args(v2)"), "{out}");
        }
    }

    /// `U256::from_be_bytes(&e, &b)` / `u.to_be_bytes()` over an operand
    /// typed `operand`, the result returned.
    fn u256_conversion(kind: sordec_ir::ValObjectKind, operand: IrType, result: KnownType) -> String {
        emitted(
            vec![
                (operand, Expr::Use(v(0))),
                (IrType::Known(result), known(KnownOp::ValObject { kind, args: vec![v(1)] })),
            ],
            vec![ret(2)],
            &TypeRegistry::default(),
        )
    }

    #[test]
    fn a_number_from_typed_bytes_is_the_sdk_constructor() {
        use sordec_ir::ValObjectKind as K;
        let out = packed(&u256_conversion(K::U256ValFromBeBytes, IrType::Known(KnownType::Bytes), KnownType::Val));
        assert!(out.contains("U256::from_be_bytes(e,&v1).to_val()"), "{out}");
        let out = packed(&u256_conversion(K::I256ValFromBeBytes, IrType::Inferred(KnownType::BytesN(32)), KnownType::Val));
        assert!(out.contains("I256::from_be_bytes(e,&soroban_sdk::Bytes::from(&v1)).to_val()"), "{out}");
        let out = packed(&u256_conversion(K::U256ValToBeBytes, IrType::Known(KnownType::U256), KnownType::Bytes));
        assert!(out.contains("v1.to_be_bytes()"), "{out}");
    }

    /// An operand nothing typed — or typed as something else — keeps the
    /// hole: the SDK method takes a `&Bytes` / a `U256`, and nothing says
    /// this value is one.
    #[test]
    fn an_untyped_operand_keeps_the_conversion_a_hole() {
        use sordec_ir::ValObjectKind as K;
        for operand in [untyped(), IrType::Known(KnownType::Val)] {
            let out = packed(&u256_conversion(K::U256ValFromBeBytes, operand.clone(), KnownType::Val));
            assert!(!out.contains("from_be_bytes") && out.contains("todo!"), "{out}");
        }
        let out = packed(&u256_conversion(K::U256ValToBeBytes, IrType::Known(KnownType::I256), KnownType::Bytes));
        assert!(!out.contains("to_be_bytes()") && out.contains("todo!"), "{out}");
    }

    /// The text with its spaces removed, so a check does not depend on
    /// token spacing.
    fn packed(s: &str) -> String {
        s.chars().filter(|c| !c.is_whitespace()).collect()
    }

    fn lit_i32(n: i32) -> (IrType, Expr) {
        (IrType::Known(KnownType::I32), Expr::Literal(sordec_ir::Literal::I32(n)))
    }

    /// `arg0 op 8` with `arg0: i32`, returned.
    fn on_the_param(op: BinaryOp) -> String {
        emitted(
            vec![lit_i32(8), (untyped(), Expr::Binary { op, lhs: v(0), rhs: v(1) })],
            vec![ret(2)],
            &TypeRegistry::default(),
        )
    }

    /// `i32.shr_u` on a value printed as an `i32`: the operand is reread as
    /// the `u32` the opcode sees, and the result comes back as the `i32`
    /// the rest of the body was printed against.
    #[test]
    fn a_logical_shift_on_a_signed_operand_is_reread_unsigned() {
        let out = packed(&on_the_param(BinaryOp::ShrU));
        assert!(out.contains("((arg0asu32)>>8") && out.contains(")asi32"), "{out}");
    }

    /// `i32.shr_s` on an `i32` is the arithmetic shift Rust's `>>` already
    /// is: printed bare.
    #[test]
    fn an_arithmetic_shift_on_a_signed_operand_is_printed_bare() {
        let out = packed(&on_the_param(BinaryOp::Shr));
        assert!(out.contains("arg0>>8"), "{out}");
        assert!(!out.contains("asu32"), "{out}");
    }

    /// An unsigned ordering compares both sides reread, and yields the
    /// `bool` as it is: nothing to cast back.
    #[test]
    fn an_unsigned_ordering_on_signed_operands_rereads_both_sides() {
        let out = packed(&emitted(
            vec![
                lit_i32(8),
                (untyped(), Expr::Binary { op: BinaryOp::Add, lhs: v(0), rhs: v(1) }),
                (untyped(), Expr::Binary { op: BinaryOp::LtU, lhs: v(0), rhs: v(2) }),
            ],
            vec![ret(3)],
            &TypeRegistry::default(),
        ));
        assert!(out.contains("(arg0asu32)<(v2asu32)"), "{out}");
        assert!(!out.contains(")asi32"), "{out}");
    }

    /// A signed division on a value printed unsigned is the mirror case.
    #[test]
    fn a_signed_division_on_an_unsigned_operand_is_reread_signed() {
        let seq = (IrType::Known(KnownType::U32), known(KnownOp::GetLedgerSequence));
        let signed = packed(&emitted(
            vec![seq.clone(), lit_i32(2), (untyped(), Expr::Binary { op: BinaryOp::Div, lhs: v(1), rhs: v(2) })],
            vec![ret(3)],
            &TypeRegistry::default(),
        ));
        assert!(signed.contains("((sequenceasi32)/2)asu32"), "{signed}");
        let unsigned = packed(&emitted(
            vec![seq, lit_i32(2), (untyped(), Expr::Binary { op: BinaryOp::DivU, lhs: v(1), rhs: v(2) })],
            vec![ret(3)],
            &TypeRegistry::default(),
        ));
        assert!(unsigned.contains("/2"), "{unsigned}");
        assert!(!unsigned.contains("asi32"), "{unsigned}");
    }

    /// A memory-read gap read only by arithmetic is printed `let v1: i64 =
    /// todo!(..)`, so to Rust it is an `i64`: `i64.shr_u` on it rereads it
    /// as the `u64` the opcode sees, and a signed `>>` would be wrong for
    /// values with the top bit set.
    #[test]
    fn a_logical_shift_on_an_annotated_load_gap_is_reread_unsigned() {
        let out = packed(&emitted(
            vec![(untyped(), wide_load()), lit_i32(8), (untyped(), Expr::Binary { op: BinaryOp::ShrU, lhs: v(1), rhs: v(2) })],
            vec![ret(3)],
            &TypeRegistry::default(),
        ));
        assert!(out.contains("letv1:i64=todo!"), "{out}");
        assert!(out.contains("((v1asu64)>>8i32)asi64"), "{out}");
    }

    /// With no operand's printed type known there is nothing to disagree
    /// with, and the operator is printed bare as before: the gap here is
    /// also returned as it is, so it is not annotated and takes its type
    /// from use.
    #[test]
    fn a_sign_bearing_operator_on_untyped_operands_is_printed_bare() {
        let out = packed(&emitted(
            vec![(untyped(), wide_load()), lit_i32(8), (untyped(), Expr::Binary { op: BinaryOp::ShrU, lhs: v(1), rhs: v(2) })],
            vec![Region::Return { values: vec![v(3), v(1)] }],
            &TypeRegistry::default(),
        ));
        assert!(!out.contains("letv1:i64"), "{out}");
        assert!(out.contains("v1>>8"), "{out}");
        assert!(!out.contains("asu"), "{out}");
    }

    /// A 32-bit operand against a 64-bit constant: one operator has one
    /// width, so a recovered type is wrong, and a cast would hide that
    /// from rustc. Printed bare.
    #[test]
    fn a_sign_bearing_operator_whose_operands_disagree_on_width_is_printed_bare() {
        let out = packed(&emitted(
            vec![i64_lit(5), (untyped(), Expr::Binary { op: BinaryOp::LtU, lhs: v(0), rhs: v(1) })],
            vec![ret(2)],
            &TypeRegistry::default(),
        ));
        assert!(out.contains("arg0<5"), "{out}");
        assert!(!out.contains("asu"), "{out}");
    }

    /// An unannotated placeholder takes the other side's type by itself:
    /// the typed operand is reread, the placeholder is left as it is. (The
    /// placeholder is also returned as it is, so nothing annotates it.)
    #[test]
    fn a_placeholder_operand_is_not_cast() {
        let out = packed(&emitted(
            vec![(untyped(), wide_load()), (untyped(), Expr::Binary { op: BinaryOp::LtU, lhs: v(0), rhs: v(1) })],
            vec![Region::Return { values: vec![v(2), v(1)] }],
            &TypeRegistry::default(),
        ));
        assert!(!out.contains("letv1:i64"), "{out}");
        assert!(out.contains("(arg0asu32)<v1"), "{out}");
    }

    /// An annotated 4-byte gap is an `i32` to Rust: an unsigned ordering
    /// against an `i32` rereads both sides.
    #[test]
    fn an_unsigned_ordering_against_an_annotated_word_gap_rereads_both() {
        let word = Expr::Load { addr: v(0), offset: 0, width: sordec_ir::MemWidth::W4, signed: None, ty: untyped() };
        let out = packed(&emitted(
            vec![(untyped(), word), (untyped(), Expr::Binary { op: BinaryOp::LtU, lhs: v(0), rhs: v(1) })],
            vec![ret(2)],
            &TypeRegistry::default(),
        ));
        assert!(out.contains("letv1:i32=todo!"), "{out}");
        assert!(out.contains("(arg0asu32)<(v1asu32)"), "{out}");
    }

    /// Two constants pin no type between them, so both carry the suffix.
    #[test]
    fn two_constants_under_an_unsigned_ordering_keep_their_suffixes() {
        let out = packed(&emitted(
            vec![lit_i32(2), lit_i32(-1), (untyped(), Expr::Binary { op: BinaryOp::LtU, lhs: v(1), rhs: v(2) })],
            vec![ret(3)],
            &TypeRegistry::default(),
        ));
        assert!(out.contains("2u32<4294967295u32"), "{out}");
    }

    /// `v1 & -2i32` with `v1: u32` is the same 32 bits as `v1 & 4294967294`.
    fn masked(operand: KnownType) -> String {
        masked_with(operand, -2)
    }

    fn masked_with(operand: KnownType, n: i32) -> String {
        let phi = (IrType::Known(operand), Expr::Phi { incoming: vec![] });
        let lit = (IrType::Known(KnownType::I32), Expr::Literal(sordec_ir::Literal::I32(n)));
        emitted(
            vec![phi, lit, (IrType::Known(KnownType::U32), mask(1, 2)), (untyped(), store(3))],
            vec![],
            &TypeRegistry::default(),
        )
    }

    #[test]
    fn a_negative_mask_on_an_unsigned_word_is_the_same_bits_unsigned() {
        let out = masked(KnownType::U32);
        assert!(out.contains("4294967294") && !out.contains("- 2"), "{out}");
    }

    /// `v1 <op> -256i64` with `v1: u32`.
    fn wide_negative(op: BinaryOp) -> String {
        let phi = (IrType::Known(KnownType::U32), Expr::Phi { incoming: vec![] });
        let lit = (IrType::Known(KnownType::I64), Expr::Literal(sordec_ir::Literal::I64(-256)));
        emitted(
            vec![
                phi,
                lit,
                (IrType::Known(KnownType::U32), Expr::Binary { op, lhs: v(1), rhs: v(2) }),
                (untyped(), store(3)),
            ],
            vec![],
            &TypeRegistry::default(),
        )
    }

    #[test]
    fn a_wide_negative_mask_may_be_cut_for_and_but_not_for_or() {
        assert!(wide_negative(BinaryOp::BitAnd).contains("4294967040"));
        for op in [BinaryOp::BitOr, BinaryOp::BitXor] {
            let out = wide_negative(op);
            assert!(!out.contains("4294967040") && out.contains("256i64"), "{out}");
        }
    }

    /// `(x == 2) << 1` and `1 << (x == 2)`: the test is the `0` or `1` the
    /// opcode shifts, in the other operand's type, and the order is kept.
    #[test]
    fn a_shifted_test_is_cast_to_the_shift_s_width() {
        let shifted = |lhs: u32, rhs: u32| {
            emitted(
                vec![
                    (IrType::Known(KnownType::I32), Expr::Phi { incoming: vec![] }), // v1 x
                    (IrType::Known(KnownType::I32), Expr::Literal(sordec_ir::Literal::I32(2))), // v2
                    (IrType::Inferred(KnownType::Bool), Expr::Binary { op: BinaryOp::Eq, lhs: v(1), rhs: v(2) }), // v3
                    (IrType::Known(KnownType::I32), Expr::Literal(sordec_ir::Literal::I32(1))), // v4
                    (IrType::Inferred(KnownType::I32), Expr::Binary { op: BinaryOp::Shl, lhs: v(lhs), rhs: v(rhs) }), // v5
                    (untyped(), store(5)),
                ],
                vec![],
                &TypeRegistry::default(),
            )
        };
        let out = shifted(3, 4);
        assert!(out.contains("as i32) << 1i32"), "{out}");
        let out = shifted(4, 3);
        assert!(out.contains("1i32 << (") && out.trim_end().contains("as i32)"), "{out}");
    }

    /// `i + (i < n)` and `i * flag`, with `i: u32`: the test is the `0` or
    /// `1` the wasm added, in `i`'s type. Two integers stay as they were.
    #[test]
    fn a_test_beside_an_integer_is_cast_to_its_type() {
        let out = emitted(
            vec![
                (IrType::Known(KnownType::U32), Expr::Phi { incoming: vec![] }), // v1 i
                (IrType::Known(KnownType::U32), Expr::Phi { incoming: vec![] }), // v2 n
                (IrType::Inferred(KnownType::Bool), Expr::Binary { op: BinaryOp::LtU, lhs: v(1), rhs: v(2) }), // v3
                (IrType::Known(KnownType::U32), Expr::Binary { op: BinaryOp::Add, lhs: v(1), rhs: v(3) }), // v4
                (untyped(), store(4)),
                (IrType::Known(KnownType::U32), Expr::Binary { op: BinaryOp::Add, lhs: v(1), rhs: v(2) }), // v6
                (untyped(), store(6)),
            ],
            vec![],
            &TypeRegistry::default(),
        );
        assert!(out.contains("(v3 as u32)"), "{out}");
        assert!(out.contains("v1 + v2"), "{out}");
    }

    #[test]
    fn a_small_flag_on_an_unsigned_word_takes_the_words_type() {
        let out = masked_with(KnownType::U32, 1);
        assert!(out.contains("v1 & 1") && !out.contains("1i32"), "{out}");
    }

    #[test]
    fn a_negative_mask_on_a_signed_word_stays_negative() {
        let out = masked(KnownType::I32);
        assert!(out.contains("(- 2)") && !out.contains("4294967294"), "{out}");
    }

    /// A helper whose declared pair is `(i64, i64)` (the first return site)
    /// returning `(0, <u64>)` at another site: the `u64` is cast to the
    /// declared `i64`, keeping its bits.
    fn pair_return(second: KnownType) -> String {
        let exprs = vec![
            (IrType::Known(KnownType::I64), Expr::Phi { incoming: vec![] }), // v1 declared
            (IrType::Known(second), Expr::Phi { incoming: vec![] }),         // v2 returned
        ];
        emitted_returning(
            exprs,
            vec![Region::Return { values: vec![v(1), v(2)] }],
            &TypeRegistry::default(),
            vec![vec![v(1), v(1)]],
        )
    }

    #[test]
    fn a_pair_element_of_the_other_sign_is_cast_to_the_declared_type() {
        let out = pair_return(KnownType::U64);
        assert!(out.contains("(v2 as i64)"), "{out}");
    }

    /// A `u32` element against a declared `i64` is a different width, not a
    /// sign: no cast.
    #[test]
    fn a_pair_element_of_another_width_is_not_cast() {
        let out = pair_return(KnownType::U32);
        assert!(!out.contains(" as "), "{out}");
    }

    #[test]
    fn a_pair_element_of_the_declared_type_is_left_alone() {
        let out = pair_return(KnownType::I64);
        assert!(!out.contains(" as "), "{out}");
    }

    // ---- a hole only a conversion through `Val` reads ----

    #[test]
    fn a_hole_read_only_through_val_is_annotated_val() {
        // The element's tag check and its spill are holes, and the one
        // reader that prints it is `len()` through `Val`. Left bare, the
        // `!` falls back to `()`.
        let body = emitted(
            vec![(untyped(), wide_load()), (untyped(), store(1)), (IrType::Known(KnownType::U32), vec_len(1))],
            vec![],
            &TypeRegistry::default(),
        );
        assert!(body.contains("let v1 : soroban_sdk :: Val = todo !"), "{body}");
        assert!(body.contains("into_val (& v1"), "the reader converts it:\n{body}");
    }

    /// `storage().persistent().set(&v0, &v1)`, with `v1` an unread-elsewhere
    /// 8-byte load.
    fn stored(value: u32) -> Expr {
        known(KnownOp::StorageSet {
            tier: sordec_ir::StorageTier::Known(sordec_ir::KnownTier::Persistent),
            durability: v(0),
            key: v(0),
            resolved_key: None,
            value: v(value),
        })
    }

    #[test]
    fn a_hole_only_stored_is_annotated_val() {
        // `set` is generic in `IntoVal<Env, Val>`: nothing pins the hole,
        // and the `!` would fall back to `()`.
        let body = emitted(vec![(untyped(), wide_load()), (IrType::Known(KnownType::Unit), stored(1))], vec![], &TypeRegistry::default());
        assert!(body.contains("let v1 : soroban_sdk :: Val = todo !"), "{body}");
    }

    /// `v1: i128 = vec::Get` (a hole), then the readers `exprs` add.
    fn wide_hole_read_by(readers: Vec<(IrType, Expr)>, returned: Vec<u32>) -> String {
        let get = known(KnownOp::VecOp { kind: sordec_ir::VecOpKind::Get, args: vec![v(0), v(0)] });
        let mut exprs = vec![(IrType::Known(KnownType::I128), get)];
        exprs.extend(readers);
        let tail = vec![Region::Return { values: returned.into_iter().map(v).collect() }];
        emitted(exprs, tail, &TypeRegistry::default())
    }

    #[test]
    fn a_wide_hole_read_by_its_limbs_is_annotated() {
        let lo = Expr::Unary { op: sordec_ir::UnaryOp::WideLo, value: v(1) };
        let le = Expr::Binary { op: BinaryOp::Le, lhs: v(1), rhs: v(3) };
        let body = wide_hole_read_by(vec![
            (IrType::Inferred(KnownType::I64), lo),
            i64_lit(0),
            (IrType::Inferred(KnownType::Bool), le),
        ], vec![2, 4]);
        assert!(body.contains("let v1 : i128 = todo !"), "{body}");
    }

    #[test]
    fn a_wide_hole_masked_as_a_word_is_left_to_inference() {
        let body = wide_hole_read_by(vec![i64_lit(255), (IrType::Inferred(KnownType::I64), mask(1, 2))], vec![3]);
        assert!(!body.contains("let v1 : i128"), "{body}");
    }

    #[test]
    fn a_hole_stored_and_read_otherwise_is_left_to_inference() {
        // A second reader, arithmetic, may pin a type of its own.
        let body = emitted(
            vec![
                (untyped(), wide_load()),
                (IrType::Known(KnownType::Unit), stored(1)),
                i64_lit(255),
                (IrType::Known(KnownType::I64), mask(1, 3)),
            ],
            vec![ret(4)],
            &TypeRegistry::default(),
        );
        assert!(!body.contains("let v1 : soroban_sdk :: Val"), "{body}");
    }

    /// The body of `func0(v0: arg)`, which calls `func1(v0)`, a helper
    /// whose one parameter is typed `param`.
    fn call_body(arg: IrType, param: IrType) -> String {
        use quote::ToTokens;
        use sordec_common::{Arena, FuncId, Provenance, ProvenanceSource};
        use sordec_ir::{HighBlock, MemoryImage, WasmFacts};
        let func = |id: u32, exprs: Vec<(IrType, Expr)>| {
            let mut bindings: Arena<ValueId, Binding> = Arena::new();
            for (ty, expr) in exprs {
                let at = v(bindings.len() as u32);
                bindings.push(Binding::new(at, ty, expr, Provenance::new("test", ProvenanceSource::DataFlow, "test")));
            }
            let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
            blocks.push(HighBlock { id: BlockId::from_index(0), bindings: (1..bindings.len() as u32).map(v).collect() });
            HighFunction {
                id: FuncId::from_index(id),
                name: None,
                signature: None,
                aliases: Vec::new(),
                blocks,
                bindings,
                region: Region::Basic(BlockId::from_index(0)),
                params: vec![v(0)],
                returns: vec![],
            }
        };
        let call = Expr::Call { target: sordec_common::FuncId::from_index(1), args: vec![v(0)] };
        let high = HighIr {
            facts: WasmFacts {
                imports: vec![],
                exports: vec![],
                function_type_indices: vec![],
                function_bodies: vec![],
                function_fingerprints: vec![],
                table_functions: None,
                custom_sections: vec![],
            },
            soroban_facts: None,
            functions: vec![
                func(0, vec![(arg, Expr::Phi { incoming: vec![] }), (untyped(), call)]),
                func(1, vec![(param, Expr::Phi { incoming: vec![] })]),
            ],
            memory: MemoryImage::empty(),
        };
        let policy = crate::rust::hole::StrictNoGuess;
        emit_body(&high, &high.functions[0], &TypeRegistry::default(), &policy).to_token_stream().to_string()
    }

    #[test]
    fn a_fixed_width_argument_to_a_bytes_parameter_is_widened() {
        let body = call_body(IrType::Known(KnownType::BytesN(32)), IrType::Inferred(KnownType::Bytes));
        assert!(body.contains("soroban_sdk :: Bytes :: from ("), "{body}");
    }

    #[test]
    fn only_a_fixed_width_argument_to_a_bytes_parameter_is_widened() {
        for (arg, param) in [
            (IrType::Known(KnownType::Bytes), IrType::Inferred(KnownType::Bytes)),
            (IrType::Known(KnownType::BytesN(32)), IrType::Inferred(KnownType::BytesN(32))),
            (IrType::Known(KnownType::BytesN(32)), untyped()),
        ] {
            let body = call_body(arg, param);
            assert!(!body.contains("Bytes :: from"), "{body}");
        }
    }

    #[test]
    fn a_literal_index_get_through_val_annotates_its_receiver() {
        // `get(2)` on a receiver not typed as a `Vec`.
        let get = known(KnownOp::VecOp { kind: sordec_ir::VecOpKind::Get, args: vec![v(1), v(2)] });
        let body = emitted(
            vec![(untyped(), wide_load()), i64_lit(0x2_0000_0004), (IrType::Known(KnownType::Val), get)],
            vec![],
            &TypeRegistry::default(),
        );
        assert!(body.contains("let v1 : soroban_sdk :: Val = todo !"), "{body}");
        assert!(body.contains("into_val (& v1"), "{body}");
        assert!(body.contains("get_unchecked (2"), "{body}");
    }

    #[test]
    fn authorization_entries_through_val_are_annotated() {
        let auth = known(KnownOp::AuthorizeAsCurrContract { auth_entries: v(1) });
        let body = emitted(
            vec![(untyped(), wide_load()), (IrType::Known(KnownType::Unit), auth)],
            vec![],
            &TypeRegistry::default(),
        );
        assert!(body.contains("let v1 : soroban_sdk :: Val = todo !"), "{body}");
        assert!(body.contains("authorize_as_current_contract"), "{body}");
    }

    /// A vec recovered as the SDK's auth entries goes to the host call as
    /// it is, and an empty one is `Vec::new`, annotated as a hole would be.
    #[test]
    fn auth_entries_typed_as_the_sdks_go_as_they_are() {
        let reg = TypeRegistry {
            unions: vec![sordec_ir::UnionDef {
                id: sordec_common::TypeId::new(0),
                name: "InvokerContractAuthEntry".to_string(),
                cases: vec![],
                exported: false,
            }],
            imported: vec![sordec_ir::ImportedType { id: sordec_common::TypeId::new(0), module: "auth".to_string() }],
            ..Default::default()
        };
        let entries =
            IrType::Known(KnownType::Vec(Box::new(IrType::Known(KnownType::UserDefined(sordec_common::TypeId::new(0))))));
        let body = emitted(
            vec![
                (entries, known(KnownOp::VecOp { kind: sordec_ir::VecOpKind::New, args: vec![] })),
                (IrType::Known(KnownType::Unit), known(KnownOp::AuthorizeAsCurrContract { auth_entries: v(1) })),
            ],
            vec![],
            &reg,
        );
        assert!(
            body.contains("let v1 : soroban_sdk :: Vec < soroban_sdk :: auth :: InvokerContractAuthEntry > = soroban_sdk :: Vec :: new"),
            "{body}"
        );
        assert!(body.contains("authorize_as_current_contract (v1)"), "{body}");
    }

    #[test]
    fn a_hole_another_reader_prints_is_left_to_inference() {
        // `v1 & 255` reads it too, and pins what the conversion does not.
        // (The length is stored, so it is read: an unread one would leave
        // the mask the only reader, which `raw_load_word` types.)
        let body = emitted(
            vec![
                (untyped(), wide_load()),
                (IrType::Known(KnownType::U32), vec_len(1)),
                (untyped(), store(2)),
                i64_lit(255),
                (IrType::Inferred(KnownType::I64), mask(1, 4)),
                (untyped(), store(5)),
            ],
            vec![],
            &TypeRegistry::default(),
        );
        assert!(body.contains("let v1 = todo !"), "{body}");
    }

    #[test]
    fn a_hole_a_recovered_call_reads_is_left_to_inference() {
        // An auth check on it: a recovered chain, but one that takes it as
        // a type of its own, not as a `Val`.
        let auth = known(KnownOp::RequireAuth { address: v(1) });
        let body = emitted(
            vec![
                (untyped(), wide_load()),
                (IrType::Known(KnownType::U32), vec_len(1)),
                (untyped(), store(2)),
                (IrType::Known(KnownType::Unit), auth),
            ],
            vec![],
            &TypeRegistry::default(),
        );
        assert!(body.contains("v1 . require_auth ()"), "{body}");
        assert!(body.contains("let v1 = todo !"), "{body}");
    }

    #[test]
    fn a_hole_the_region_returns_is_left_to_inference() {
        let body = emitted(
            vec![(untyped(), wide_load()), (IrType::Known(KnownType::U32), vec_len(1))],
            vec![ret(1)],
            &TypeRegistry::default(),
        );
        assert!(body.contains("let v1 = todo !"), "{body}");
    }

    #[test]
    fn a_hole_a_branch_tests_is_left_to_inference() {
        let branch = Region::If {
            cond: v(1),
            then_region: Box::new(Region::Return { values: vec![] }),
            else_region: None,
        };
        let body = emitted(
            vec![(untyped(), wide_load()), (IrType::Known(KnownType::U32), vec_len(1)), (untyped(), store(2))],
            vec![branch],
            &TypeRegistry::default(),
        );
        assert!(body.contains("if v1"), "{body}");
        assert!(body.contains("let v1 = todo !"), "{body}");
    }

    // ---- a hole read as a declared struct ----

    fn registry_with_struct(id: u32, name: &str) -> TypeRegistry {
        let mut reg = TypeRegistry::default();
        reg.structs.push(sordec_ir::StructDef {
            id: sordec_common::TypeId::new(id),
            name: name.to_string(),
            fields: vec![sordec_ir::StructField {
                name: "min_recv".to_string(),
                ty: sordec_ir::TypeRef::Primitive(sordec_ir::PrimitiveType::I128),
            }],
        });
        reg
    }

    /// `let v1 = todo!("vec::Get"); … v1.<field>` (stored, so read), with
    /// `v1` typed as the user-defined id 7; `extra` follows the field read.
    fn struct_read(field: &str, extra: Vec<(IrType, Expr)>, tail: Vec<Region>, reg: &TypeRegistry) -> String {
        let get = known(KnownOp::VecOp { kind: sordec_ir::VecOpKind::Get, args: vec![v(0), v(0)] });
        let mut exprs = vec![
            (IrType::Known(KnownType::UserDefined(sordec_common::TypeId::new(7))), get),
            (IrType::Known(KnownType::I128), Expr::Field { base: v(1), field: field.to_string() }),
            (untyped(), store(2)),
        ];
        exprs.extend(extra);
        emitted(exprs, tail, reg)
    }

    #[test]
    fn a_hole_whose_fields_are_read_takes_its_declared_struct() {
        let body = struct_read("min_recv", vec![], vec![], &registry_with_struct(7, "SwapSpec"));
        assert!(body.contains("let v1 : SwapSpec = todo !"), "{body}");
        assert!(body.contains("v1 . min_recv"), "{body}");
    }

    #[test]
    fn a_struct_the_registry_cannot_name_is_not_annotated() {
        // It would print as `Val`, which has no field to read.
        let body = struct_read("min_recv", vec![], vec![], &registry_with_struct(8, "Other"));
        assert!(body.contains("let v1 = todo !"), "{body}");
    }

    #[test]
    fn a_type_that_is_not_a_struct_is_not_annotated() {
        // An enum shares the id space; it has no fields to read.
        let mut reg = TypeRegistry::default();
        reg.enums.push(sordec_ir::EnumDef {
            id: sordec_common::TypeId::new(7),
            name: "Kind".to_string(),
            cases: vec![sordec_ir::EnumCase { name: "A".to_string(), value: 0 }],
        });
        let body = struct_read("min_recv", vec![], vec![], &reg);
        assert!(body.contains("let v1 = todo !"), "{body}");
    }

    #[test]
    fn a_field_the_struct_lacks_is_not_annotated() {
        let body = struct_read("amount", vec![], vec![], &registry_with_struct(7, "SwapSpec"));
        assert!(body.contains("let v1 = todo !"), "{body}");
    }

    #[test]
    fn a_struct_hole_also_returned_is_not_annotated() {
        let body = struct_read("min_recv", vec![], vec![ret(1)], &registry_with_struct(7, "SwapSpec"));
        assert!(body.contains("let v1 = todo !"), "{body}");
    }

    #[test]
    fn a_struct_arithmetic_reads_is_not_annotated() {
        // The tag word masked beside the decode: annotating would move the
        // error onto `SwapSpec & 255`, not remove it.
        let body = struct_read(
            "min_recv",
            vec![i64_lit(255), (IrType::Inferred(KnownType::I64), mask(1, 4)), (untyped(), store(5))],
            vec![],
            &registry_with_struct(7, "SwapSpec"),
        );
        assert!(body.contains("let v1 = todo !"), "{body}");
    }

    #[test]
    fn a_struct_arithmetic_reads_behind_a_rename_is_not_annotated() {
        // A rename the IR typed differently is not folded: it prints as its
        // own `let`, and the mask reads that.
        let body = struct_read(
            "min_recv",
            vec![
                (IrType::Inferred(KnownType::I64), Expr::Use(v(1))),
                i64_lit(255),
                (IrType::Inferred(KnownType::I64), mask(4, 5)),
                (untyped(), store(6)),
            ],
            vec![],
            &registry_with_struct(7, "SwapSpec"),
        );
        assert!(body.contains("let v4 = v1"), "the rename prints:\n{body}");
        assert!(body.contains("let v1 = todo !"), "{body}");
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

    // ---- a word placed in a `bool` field ----

    fn registry_with_flag(ty: sordec_ir::PrimitiveType) -> TypeRegistry {
        let mut reg = TypeRegistry::default();
        reg.structs.push(sordec_ir::StructDef {
            id: sordec_common::TypeId::new(7),
            name: "Test".to_string(),
            fields: vec![sordec_ir::StructField { name: "b".to_string(), ty: sordec_ir::TypeRef::Primitive(ty) }],
        });
        reg
    }

    /// `Test { b: v1 }` with `v1` a byte read back as `value_ty`, the struct
    /// stored so it is read.
    fn flag_struct(value_ty: IrType, field: sordec_ir::PrimitiveType) -> String {
        let exprs = vec![
            (value_ty, Expr::Load { addr: v(0), offset: 12, width: sordec_ir::MemWidth::W1, signed: None, ty: untyped() }),
            (
                IrType::Known(KnownType::UserDefined(sordec_common::TypeId::new(7))),
                Expr::Struct { fields: vec![("b".to_string(), v(1))] },
            ),
            (untyped(), store(2)),
        ];
        emitted(exprs, vec![], &registry_with_flag(field))
    }

    #[test]
    fn a_word_in_a_bool_field_is_its_test() {
        let body = flag_struct(IrType::Inferred(KnownType::I32), sordec_ir::PrimitiveType::Bool);
        assert!(body.contains("b : (v1 != 0)"), "{body}");
    }

    #[test]
    fn a_word_in_a_number_field_is_the_word() {
        let body = flag_struct(IrType::Inferred(KnownType::I32), sordec_ir::PrimitiveType::I32);
        assert!(body.contains("b : v1"), "{body}");
        assert!(!body.contains("!= 0"), "{body}");
    }

    #[test]
    fn an_untyped_value_in_a_bool_field_is_left_alone() {
        let body = flag_struct(untyped(), sordec_ir::PrimitiveType::Bool);
        assert!(!body.contains("!= 0"), "{body}");
    }

    /// A tuple struct is built and read the way it is declared:
    /// `Pair(v1, v2)` and `v3.1`, never through the `_0`, `_1` names its
    /// spec fields would otherwise become.
    #[test]
    fn a_tuple_struct_is_built_and_read_positionally() {
        let mut reg = TypeRegistry::default();
        let u32_field = |name: &str| sordec_ir::StructField {
            name: name.to_string(),
            ty: sordec_ir::TypeRef::Primitive(sordec_ir::PrimitiveType::U32),
        };
        reg.structs.push(sordec_ir::StructDef {
            id: sordec_common::TypeId::new(7),
            name: "Pair".to_string(),
            fields: vec![u32_field("0"), u32_field("1")],
        });
        let word = || Expr::Load { addr: v(0), offset: 0, width: sordec_ir::MemWidth::W4, signed: None, ty: untyped() };
        let exprs = vec![
            (IrType::Known(KnownType::U32), word()),
            (IrType::Known(KnownType::U32), word()),
            (
                IrType::Known(KnownType::UserDefined(sordec_common::TypeId::new(7))),
                Expr::Struct { fields: vec![("0".to_string(), v(1)), ("1".to_string(), v(2))] },
            ),
            (IrType::Known(KnownType::U32), Expr::Field { base: v(3), field: "1".to_string() }),
            (untyped(), store(4)),
        ];
        let body = emitted(exprs, vec![], &reg);
        assert!(body.contains("Pair (v1 , v2)"), "{body}");
        assert!(body.contains("v3 . 1"), "{body}");
        assert!(!body.contains("_0") && !body.contains("_1"), "{body}");
    }

    /// A variant carrying values prints them as its tuple: `Kind::A(v1)`;
    /// a unit one prints its path alone.
    #[test]
    fn a_variant_prints_the_values_it_carries() {
        let mut reg = TypeRegistry::default();
        reg.unions.push(sordec_ir::UnionDef {
            id: sordec_common::TypeId::new(5),
            name: "Kind".to_string(),
            cases: vec![
                sordec_ir::UnionCase {
                    name: "A".to_string(),
                    fields: vec![sordec_ir::TypeRef::Primitive(sordec_ir::PrimitiveType::U32)],
                },
                sordec_ir::UnionCase { name: "B".to_string(), fields: vec![] },
            ],
            exported: true,
        });
        let kind = IrType::Known(KnownType::UserDefined(sordec_common::TypeId::new(5)));
        let exprs = vec![
            (untyped(), Expr::Load { addr: v(0), offset: 0, width: sordec_ir::MemWidth::W4, signed: None, ty: untyped() }),
            (kind.clone(), Expr::Variant { name: "A".to_string(), payload: vec![v(1)] }),
            (untyped(), store(2)),
            (kind, Expr::Variant { name: "B".to_string(), payload: vec![] }),
            (untyped(), store(4)),
        ];
        let body = emitted(exprs, vec![], &reg);
        assert!(body.contains("Kind :: A (v1)"), "{body}");
        assert!(body.contains("Kind :: B"), "{body}");
        assert!(!body.contains("Kind :: B ("), "{body}");
    }
}
