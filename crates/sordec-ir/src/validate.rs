//! IR invariant validation.
//!
//! Each IR layer has structural invariants that passes are responsible
//! for preserving. The functions in this module check those invariants;
//! they are called from tests and from the corpus locks, and are
//! designed to be usable from a `debug_assert!` in the pass driver.
//!
//! Validation produces a [`Result`]: a failure-mode struct rather than a
//! panic. This makes the validator usable from a future
//! `ValidationPass` (in CI or under a `--validate` CLI flag) and from
//! tests that want to assert specific failure modes.
//!
//! ## What is checked where
//!
//! [`validate_lifted`] checks the SSA + CFG form: dangling value/block
//! references. (The lifter also runs a per-function, `LiftError`-typed
//! version *during* lifting — `sordec-passes`'s internal
//! `validate_lifted_function` — which cannot live here because it runs
//! before a whole [`LiftedIr`] exists and reports lift-specific
//! diagnostics.)
//!
//! [`validate_high`] checks the structured form. Two properties beyond
//! reference integrity, both of which the W6/W7 refinement passes will
//! rewrite the region tree against:
//!
//! - **Label enclosure**: every [`crate::Region::Break`] names an
//!   enclosing [`crate::Region::Scope`]'s `out`, and every
//!   [`crate::Region::Continue`] an enclosing [`crate::Region::Loop`]'s
//!   `header`. A splice that re-nests a subtree past its label is caught
//!   here.
//! - **Region-order dominance**: walking the tree in emission order,
//!   every value read is already defined. Phi bindings are seeded as
//!   defined everywhere (the emit layer materializes them as mutable
//!   locals assigned via [`crate::PhiTransfer`], J4); the ordering that
//!   matters is that each transfer *source* is defined before its
//!   branch. This is the invariant Rust emission actually needs — CFG
//!   dominance does not survive restructuring for free.
//!
//! "Every reachable block appears in the region tree" needs the lifted
//! CFG to know what *is* reachable, so it lives in the structuring
//! corpus lock, not here (which sees only the high IR).

use std::collections::HashSet;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use sordec_common::{BlockId, FuncId, IrId, ValueId};

use crate::{Binding, Expr, HighBlock, HighFunction, HighIr, KnownOp, LiftedFunction, LiftedIr,
    LiftedTerminator, Region, SemanticOp};

// Bounds-safe arena lookups. `Arena::get` fires a `debug_assert!` on an
// out-of-bounds id, but detecting exactly those references is the
// validator's job — so check the length first and only index when it is
// safe.
fn get_binding(func: &HighFunction, v: ValueId) -> Option<&Binding> {
    ((v.index() as usize) < func.bindings.len())
        .then(|| func.bindings.get(v))
        .flatten()
}
fn get_block(func: &HighFunction, b: BlockId) -> Option<&HighBlock> {
    ((b.index() as usize) < func.blocks.len())
        .then(|| func.blocks.get(b))
        .flatten()
}

/// Validation contract implemented by every IR layer.
///
/// Implementing this trait lets the pass-manager hook validation
/// generically:
///
/// ```ignore
/// // In sordec-passes::Pipeline:
/// for pass in &self.passes {
///     pass.run(ir);
///     debug_assert!(ir.validate().is_ok(), "pass {} broke an invariant", pass.name());
/// }
/// ```
pub trait Validate {
    /// Run all invariant checks. `Ok(())` if every invariant holds.
    fn validate(&self) -> Result<(), ValidateError>;
}

impl Validate for LiftedIr {
    #[inline]
    fn validate(&self) -> Result<(), ValidateError> {
        validate_lifted(self)
    }
}

impl Validate for HighIr {
    #[inline]
    fn validate(&self) -> Result<(), ValidateError> {
        validate_high(self)
    }
}

// ---------------------------------------------------------------------
// Lifted IR
// ---------------------------------------------------------------------

/// Validate every invariant of a [`LiftedIr`]: every value and block
/// referenced from instructions, block params, terminator conditions,
/// and terminator targets resolves in its enclosing function.
///
/// # Errors
///
/// Returns the first [`ValidateError::DanglingValue`] /
/// [`ValidateError::DanglingBlock`] encountered.
pub fn validate_lifted(ir: &LiftedIr) -> Result<(), ValidateError> {
    for func in &ir.functions {
        validate_lifted_function(func)?;
    }
    Ok(())
}

/// Validate one lifted function's reference integrity. Exposed so
/// callers holding a single [`LiftedFunction`] (before a whole
/// [`LiftedIr`] is assembled, or in tests) can reuse it.
///
/// # Errors
///
/// Returns the first dangling reference encountered.
pub fn validate_lifted_function(func: &LiftedFunction) -> Result<(), ValidateError> {
    let value_count = func.values.len() as u32;
    let block_count = func.blocks.len() as u32;

    let check_value = |v: ValueId| -> Result<(), ValidateError> {
        if v.index() >= value_count {
            return Err(ValidateError::DanglingValue {
                function: func.id,
                value: v,
            });
        }
        Ok(())
    };
    let check_block = |b: BlockId| -> Result<(), ValidateError> {
        if b.index() >= block_count {
            return Err(ValidateError::DanglingBlock {
                function: func.id,
                block: b,
            });
        }
        Ok(())
    };
    let check_target = |t: &crate::BlockTarget| -> Result<(), ValidateError> {
        check_block(t.block)?;
        for &arg in &t.args {
            check_value(arg)?;
        }
        Ok(())
    };

    check_block(func.entry)?;
    for (_id, block) in func.blocks.iter() {
        for &v in &block.params {
            check_value(v)?;
        }
        for &v in &block.instructions {
            check_value(v)?;
        }
        match &block.terminator {
            LiftedTerminator::Branch(t) => check_target(t)?,
            LiftedTerminator::BranchIf {
                cond,
                if_true,
                if_false,
            } => {
                check_value(*cond)?;
                check_target(if_true)?;
                check_target(if_false)?;
            }
            LiftedTerminator::Switch {
                index,
                targets,
                default,
            } => {
                check_value(*index)?;
                for t in targets {
                    check_target(t)?;
                }
                check_target(default)?;
            }
            LiftedTerminator::Return { values } => {
                for &v in values {
                    check_value(v)?;
                }
            }
            LiftedTerminator::Unreachable => {}
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------
// High IR
// ---------------------------------------------------------------------

/// Validate every invariant of a [`HighIr`]. See the [module
/// docs](self) for the properties checked.
///
/// # Errors
///
/// Returns the first invariant violation encountered.
pub fn validate_high(ir: &HighIr) -> Result<(), ValidateError> {
    for func in &ir.functions {
        validate_high_function(func)?;
    }
    Ok(())
}

fn validate_high_function(func: &HighFunction) -> Result<(), ValidateError> {
    // Binding-level invariants (constructor-enforced, but in-place
    // mutation could break them): non-empty provenance, resolvable
    // operands.
    for (id, binding) in func.bindings.iter() {
        if binding.provenance().is_empty() {
            return Err(ValidateError::EmptyProvenance {
                function: func.id,
                value: id,
            });
        }
        let mut dangling = None;
        binding.expr.for_each_value_use(|u| {
            if dangling.is_none() && get_binding(func, u).is_none() {
                dangling = Some(u);
            }
        });
        if let Some(value) = dangling {
            return Err(ValidateError::DanglingValue {
                function: func.id,
                value,
            });
        }
    }

    // Region structure: reference integrity, no duplicate leaves, label
    // enclosure, transfer integrity, dispatch tagging.
    let mut seen_basic: HashSet<BlockId> = HashSet::new();
    let mut stack: Vec<Enclosing> = Vec::new();
    check_region_structure(func, &func.region, &mut stack, &mut seen_basic)?;

    // Region-order dominance (linear emission-order walk).
    check_region_dominance(func)?;

    Ok(())
}

/// An enclosing labeled construct, for the [`Region::Break`] /
/// [`Region::Continue`] enclosure check.
enum Enclosing {
    Scope(BlockId),
    Loop(BlockId),
}

fn check_region_structure(
    func: &HighFunction,
    region: &Region,
    stack: &mut Vec<Enclosing>,
    seen_basic: &mut HashSet<BlockId>,
) -> Result<(), ValidateError> {
    let block_exists = |b: BlockId| get_block(func, b).is_some();
    let value_exists = |v: ValueId| get_binding(func, v).is_some();
    let dangling_block = |b: BlockId| ValidateError::DanglingBlock {
        function: func.id,
        block: b,
    };
    let dangling_value = |v: ValueId| ValidateError::DanglingValue {
        function: func.id,
        value: v,
    };

    match region {
        Region::Basic(b) => {
            if !block_exists(*b) {
                return Err(dangling_block(*b));
            }
            if !seen_basic.insert(*b) {
                return Err(ValidateError::DuplicateBasic {
                    function: func.id,
                    block: *b,
                });
            }
        }
        Region::Sequence(items) => {
            for item in items {
                check_region_structure(func, item, stack, seen_basic)?;
            }
        }
        Region::Scope { out, body } => {
            if !block_exists(*out) {
                return Err(dangling_block(*out));
            }
            stack.push(Enclosing::Scope(*out));
            check_region_structure(func, body, stack, seen_basic)?;
            stack.pop();
        }
        Region::If {
            cond,
            then_region,
            else_region,
        } => {
            if !value_exists(*cond) {
                return Err(dangling_value(*cond));
            }
            check_region_structure(func, then_region, stack, seen_basic)?;
            if let Some(else_region) = else_region {
                check_region_structure(func, else_region, stack, seen_basic)?;
            }
        }
        Region::Loop {
            header,
            body,
            kind: _,
        } => {
            if !block_exists(*header) {
                return Err(dangling_block(*header));
            }
            stack.push(Enclosing::Loop(*header));
            check_region_structure(func, body, stack, seen_basic)?;
            stack.pop();
        }
        Region::Switch {
            index,
            arms,
            default,
            dispatch,
        } => {
            if !value_exists(*index) {
                return Err(dangling_value(*index));
            }
            if let Some(d) = dispatch {
                if !value_exists(*d) {
                    return Err(dangling_value(*d));
                }
                let is_dispatch = get_binding(func, *d).is_some_and(|b| {
                    matches!(
                        b.expr,
                        Expr::Semantic(SemanticOp::Known(KnownOp::SymbolDispatch { .. }))
                    )
                });
                if !is_dispatch {
                    return Err(ValidateError::Other(format!(
                        "func {} switch dispatch points at {} which is not a SymbolDispatch",
                        func.id, d
                    )));
                }
            }
            for arm in arms {
                check_region_structure(func, &arm.body, stack, seen_basic)?;
            }
            check_region_structure(func, default, stack, seen_basic)?;
        }
        Region::Break { target, transfer } => {
            let enclosed = stack
                .iter()
                .any(|e| matches!(e, Enclosing::Scope(out) if out == target));
            if !enclosed {
                return Err(ValidateError::UnenclosedLabel {
                    function: func.id,
                    block: *target,
                });
            }
            check_transfer(func, *target, transfer)?;
        }
        Region::Continue { target, transfer } => {
            let enclosed = stack
                .iter()
                .any(|e| matches!(e, Enclosing::Loop(header) if header == target));
            if !enclosed {
                return Err(ValidateError::UnenclosedLabel {
                    function: func.id,
                    block: *target,
                });
            }
            check_transfer(func, *target, transfer)?;
        }
        Region::Transfer { target, transfer } => {
            if !block_exists(*target) {
                return Err(dangling_block(*target));
            }
            check_transfer(func, *target, transfer)?;
        }
        Region::Return { values } => {
            for &v in values {
                if !value_exists(v) {
                    return Err(dangling_value(v));
                }
            }
        }
        Region::Unreachable | Region::Panic { .. } => {}
        Region::Unstructured { entry, reason: _ } => {
            // Defensive fallback: preserve the entry reference but do not
            // recurse — there is no structured subtree to check.
            if !block_exists(*entry) {
                return Err(dangling_block(*entry));
            }
        }
    }
    Ok(())
}

/// Check one branch edge's [`crate::PhiTransfer`]: each left side is a
/// distinct [`Expr::Phi`] binding, each source resolves.
fn check_transfer(
    func: &HighFunction,
    _target: BlockId,
    transfer: &[(ValueId, ValueId)],
) -> Result<(), ValidateError> {
    let mut seen: HashSet<ValueId> = HashSet::new();
    for &(phi, source) in transfer {
        if get_binding(func, source).is_none() {
            return Err(ValidateError::DanglingValue {
                function: func.id,
                value: source,
            });
        }
        let is_phi =
            get_binding(func, phi).is_some_and(|b| matches!(b.expr, Expr::Phi { .. }));
        if !is_phi || !seen.insert(phi) {
            return Err(ValidateError::BadTransfer {
                function: func.id,
                value: phi,
            });
        }
    }
    Ok(())
}

/// Linear emission-order dominance walk.
///
/// The structurer linearizes blocks in dominator order, so a
/// single left-to-right pass with a monotonically growing `defined`
/// set is sound (a valid tree never reads a value defined later in the
/// walk) and flags exactly the emission-order violations a mis-ordered
/// refinement rewrite would introduce. Phi bindings and function params
/// seed the set: they materialize as mutable locals available
/// throughout the function, so what matters is that each transfer
/// *source* — the value assigned into a phi — is defined before its
/// branch.
fn check_region_dominance(func: &HighFunction) -> Result<(), ValidateError> {
    let mut defined: HashSet<ValueId> = HashSet::new();
    for &p in &func.params {
        defined.insert(p);
    }
    for (id, binding) in func.bindings.iter() {
        if matches!(binding.expr, Expr::Phi { .. }) {
            defined.insert(id);
        }
    }
    walk_dominance(func, &func.region, &mut defined)
}

fn walk_dominance(
    func: &HighFunction,
    region: &Region,
    defined: &mut HashSet<ValueId>,
) -> Result<(), ValidateError> {
    let require = |v: ValueId, defined: &HashSet<ValueId>| -> Result<(), ValidateError> {
        if defined.contains(&v) {
            Ok(())
        } else {
            Err(ValidateError::UseBeforeDef {
                function: func.id,
                value: v,
            })
        }
    };

    match region {
        Region::Basic(b) => {
            if let Some(block) = get_block(func, *b) {
                for &vid in &block.bindings {
                    let Some(binding) = get_binding(func, vid) else {
                        continue;
                    };
                    // A scheduled binding's operands must be defined
                    // first — except a phi, whose incoming values flow
                    // via transfers (pre-defined by construction).
                    if !matches!(binding.expr, Expr::Phi { .. }) {
                        let mut bad = None;
                        binding.expr.for_each_value_use(|u| {
                            if bad.is_none() && !defined.contains(&u) {
                                bad = Some(u);
                            }
                        });
                        if let Some(v) = bad {
                            return Err(ValidateError::UseBeforeDef {
                                function: func.id,
                                value: v,
                            });
                        }
                    }
                    defined.insert(vid);
                }
            }
        }
        Region::Sequence(items) => {
            for item in items {
                walk_dominance(func, item, defined)?;
            }
        }
        Region::Scope { out: _, body } => walk_dominance(func, body, defined)?,
        Region::If {
            cond,
            then_region,
            else_region,
        } => {
            require(*cond, defined)?;
            walk_dominance(func, then_region, defined)?;
            if let Some(else_region) = else_region {
                walk_dominance(func, else_region, defined)?;
            }
        }
        Region::Loop {
            header: _,
            body,
            kind: _,
        } => walk_dominance(func, body, defined)?,
        Region::Switch {
            index,
            arms,
            default,
            dispatch,
        } => {
            require(*index, defined)?;
            if let Some(d) = dispatch {
                require(*d, defined)?;
            }
            for arm in arms {
                walk_dominance(func, &arm.body, defined)?;
            }
            walk_dominance(func, default, defined)?;
        }
        Region::Break { target: _, transfer }
        | Region::Continue { target: _, transfer }
        | Region::Transfer { target: _, transfer } => {
            for &(_phi, source) in transfer {
                require(source, defined)?;
            }
        }
        Region::Return { values } => {
            for &v in values {
                require(v, defined)?;
            }
        }
        Region::Unreachable | Region::Panic { .. } | Region::Unstructured { .. } => {}
    }
    Ok(())
}

/// Reason a [`Validate::validate`] call failed.
///
/// `#[non_exhaustive]` so additional structural checks can land in
/// future passes without breaking downstream matchers.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ValidateError {
    /// A `ValueId` was referenced but no binding for it exists in the
    /// enclosing function.
    DanglingValue {
        /// Function in which the dangling reference appears.
        function: FuncId,
        /// The unresolved value id.
        value: ValueId,
    },

    /// A `BlockId` was referenced but no block for it exists.
    DanglingBlock {
        /// Function in which the dangling reference appears.
        function: FuncId,
        /// The unresolved block id.
        block: BlockId,
    },

    /// A binding had an empty `provenance` vector, violating the
    /// non-empty invariant.
    EmptyProvenance {
        /// Function containing the offending binding.
        function: FuncId,
        /// The binding's value id.
        value: ValueId,
    },

    /// A `Region::Basic` leaf named the same block as an earlier one —
    /// the structurer must reference each block exactly once (trap-block
    /// duplication, when it lands, stamps provenance on the copy).
    DuplicateBasic {
        /// Function containing the duplicate.
        function: FuncId,
        /// The block referenced more than once.
        block: BlockId,
    },

    /// A `Region::Break`/`Continue` named a `target` with no matching
    /// enclosing `Scope`/`Loop` on the label stack.
    UnenclosedLabel {
        /// Function containing the unenclosed branch.
        function: FuncId,
        /// The label target that resolves to no enclosing construct.
        block: BlockId,
    },

    /// A `PhiTransfer` left side was not a distinct `Expr::Phi` binding.
    BadTransfer {
        /// Function containing the bad transfer.
        function: FuncId,
        /// The offending transfer-target value.
        value: ValueId,
    },

    /// A value was read before it was defined in region emission order.
    UseBeforeDef {
        /// Function containing the ordering violation.
        function: FuncId,
        /// The value used before its definition.
        value: ValueId,
    },

    /// Some IR-layer-specific invariant failed; the message describes which.
    /// Used as a catch-all while the validator is being fleshed out.
    // JUSTIFY: free-form diagnostic; not load-bearing logic.
    Other(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Binding, HighBlock, IrType};
    use sordec_common::{Arena, Provenance, ProvenanceSource, UnknownReason};

    fn bb(i: u32) -> BlockId {
        BlockId::new(i)
    }
    fn v(i: u32) -> ValueId {
        ValueId::new(i)
    }
    fn prov() -> Provenance {
        Provenance::new("test", ProvenanceSource::Default, "")
    }
    fn binding(id: u32, expr: Expr) -> Binding {
        Binding::new(
            v(id),
            IrType::Unknown(UnknownReason::UpstreamUnknown),
            expr,
            prov(),
        )
    }

    /// A function from bindings + blocks + a region root, entry-less
    /// params. Bindings are pushed in id order (dense).
    fn func(bindings: Vec<Binding>, blocks: Vec<HighBlock>, region: Region) -> HighFunction {
        let mut b_arena: Arena<ValueId, Binding> = Arena::new();
        for b in bindings {
            b_arena.push(b);
        }
        let mut blk_arena: Arena<BlockId, HighBlock> = Arena::new();
        for b in blocks {
            blk_arena.push(b);
        }
        HighFunction {
            id: FuncId::new(0),
            name: None,
            signature: None,
            blocks: blk_arena,
            bindings: b_arena,
            region,
            params: vec![],
            returns: vec![],
        }
    }

    fn block(id: u32, bindings: Vec<u32>) -> HighBlock {
        HighBlock {
            id: bb(id),
            bindings: bindings.into_iter().map(v).collect(),
        }
    }

    /// A well-formed single-block function: `v0 = literal; return v0`.
    fn straight_line() -> HighFunction {
        func(
            vec![binding(0, Expr::Literal(crate::Literal::I64(1)))],
            vec![block(0, vec![0])],
            Region::Sequence(vec![
                Region::Basic(bb(0)),
                Region::Return { values: vec![v(0)] },
            ]),
        )
    }

    #[test]
    fn well_formed_function_validates() {
        assert_eq!(validate_high_function(&straight_line()), Ok(()));
    }

    #[test]
    fn break_without_enclosing_scope_is_unenclosed() {
        let f = func(
            vec![binding(0, Expr::Literal(crate::Literal::I64(1)))],
            vec![block(0, vec![0])],
            Region::Sequence(vec![
                Region::Basic(bb(0)),
                Region::Break {
                    target: bb(9),
                    transfer: vec![],
                },
            ]),
        );
        assert_eq!(
            validate_high_function(&f),
            Err(ValidateError::UnenclosedLabel {
                function: FuncId::new(0),
                block: bb(9),
            })
        );
    }

    #[test]
    fn break_inside_matching_scope_validates() {
        let f = func(
            vec![binding(0, Expr::Literal(crate::Literal::I64(1)))],
            vec![block(0, vec![0]), block(1, vec![])],
            Region::Sequence(vec![
                Region::Scope {
                    out: bb(1),
                    body: Box::new(Region::Sequence(vec![
                        Region::Basic(bb(0)),
                        Region::Break {
                            target: bb(1),
                            transfer: vec![],
                        },
                    ])),
                },
                Region::Basic(bb(1)),
            ]),
        );
        assert_eq!(validate_high_function(&f), Ok(()));
    }

    #[test]
    fn duplicate_basic_is_rejected() {
        let f = func(
            vec![binding(0, Expr::Literal(crate::Literal::I64(1)))],
            vec![block(0, vec![0])],
            Region::Sequence(vec![Region::Basic(bb(0)), Region::Basic(bb(0))]),
        );
        assert_eq!(
            validate_high_function(&f),
            Err(ValidateError::DuplicateBasic {
                function: FuncId::new(0),
                block: bb(0),
            })
        );
    }

    #[test]
    fn transfer_into_non_phi_is_bad() {
        // v0 is a literal, not a phi — a transfer naming it as a target
        // is malformed.
        let f = func(
            vec![
                binding(0, Expr::Literal(crate::Literal::I64(1))),
                binding(1, Expr::Literal(crate::Literal::I64(2))),
            ],
            vec![block(0, vec![0, 1]), block(1, vec![])],
            Region::Sequence(vec![
                Region::Scope {
                    out: bb(1),
                    body: Box::new(Region::Sequence(vec![
                        Region::Basic(bb(0)),
                        Region::Break {
                            target: bb(1),
                            transfer: vec![(v(0), v(1))],
                        },
                    ])),
                },
                Region::Basic(bb(1)),
            ]),
        );
        assert_eq!(
            validate_high_function(&f),
            Err(ValidateError::BadTransfer {
                function: FuncId::new(0),
                value: v(0),
            })
        );
    }

    #[test]
    fn use_before_def_is_caught() {
        // v1 = v0 + v0 is scheduled, but v0 is defined *after* it.
        let f = func(
            vec![
                binding(
                    0,
                    Expr::Binary {
                        op: crate::BinaryOp::Add,
                        lhs: v(2),
                        rhs: v(2),
                    },
                ),
                binding(1, Expr::Literal(crate::Literal::I64(1))),
                binding(2, Expr::Literal(crate::Literal::I64(2))),
            ],
            // Block schedules v0 (reads v2) BEFORE v2.
            vec![block(0, vec![0, 2])],
            Region::Sequence(vec![
                Region::Basic(bb(0)),
                Region::Return { values: vec![v(0)] },
            ]),
        );
        assert_eq!(
            validate_high_function(&f),
            Err(ValidateError::UseBeforeDef {
                function: FuncId::new(0),
                value: v(2),
            })
        );
    }

    #[test]
    fn loop_carried_phi_read_is_legal() {
        // A phi read inside the loop body before the back-edge transfer
        // is fine — the phi is a function-scoped mutable local.
        let f = func(
            vec![
                binding(0, Expr::Phi { incoming: vec![] }),
                binding(
                    1,
                    Expr::Binary {
                        op: crate::BinaryOp::Add,
                        lhs: v(0),
                        rhs: v(0),
                    },
                ),
            ],
            vec![block(0, vec![1])],
            Region::Loop {
                header: bb(0),
                body: Box::new(Region::Sequence(vec![
                    Region::Basic(bb(0)),
                    Region::Continue {
                        target: bb(0),
                        transfer: vec![(v(0), v(1))],
                    },
                ])),
                kind: crate::LoopKind::Unclassified,
            },
        );
        assert_eq!(validate_high_function(&f), Ok(()));
    }

    #[test]
    fn dangling_value_in_return_is_caught() {
        let f = func(
            vec![binding(0, Expr::Literal(crate::Literal::I64(1)))],
            vec![block(0, vec![0])],
            Region::Sequence(vec![
                Region::Basic(bb(0)),
                Region::Return { values: vec![v(7)] },
            ]),
        );
        assert_eq!(
            validate_high_function(&f),
            Err(ValidateError::DanglingValue {
                function: FuncId::new(0),
                value: v(7),
            })
        );
    }

    #[test]
    fn lifted_validator_flags_dangling_block_target() {
        use crate::{BlockTarget, LiftedBlock, LiftedFunction, LiftedType, LiftedValue,
            LiftedValueDef};
        let mut values: Arena<ValueId, LiftedValue> = Arena::new();
        values.push(LiftedValue {
            def: LiftedValueDef::Operator {
                op: crate::WasmOp(waffle::Operator::I32Const { value: 1 }),
                args: vec![],
            },
            types: vec![LiftedType::I32],
        });
        let mut blocks: Arena<BlockId, LiftedBlock> = Arena::new();
        blocks.push(LiftedBlock {
            id: bb(0),
            params: vec![],
            instructions: vec![v(0)],
            terminator: LiftedTerminator::Branch(BlockTarget {
                block: bb(5), // does not exist
                args: vec![],
            }),
        });
        let func = LiftedFunction {
            id: FuncId::new(0),
            entry: bb(0),
            blocks,
            values,
        };
        assert_eq!(
            validate_lifted_function(&func),
            Err(ValidateError::DanglingBlock {
                function: FuncId::new(0),
                block: bb(5),
            })
        );
    }
}
