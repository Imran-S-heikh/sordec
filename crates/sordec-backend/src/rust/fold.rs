//! Which references print as something other than their own name.
//!
//! The body walk binds every scheduled value as `let vN = …;` and refers to
//! it by name, which is exact and also noisy: a rename the lowering left
//! behind (`let v12 = v25;`) and a constant bound only to be read once
//! (`let v44 = 0i128; … unwrap_or(v44)`) are both lines the source never
//! had. This table folds exactly those two cases at the point of
//! reference:
//!
//! - **Renames.** A `Use` of another value of the same type is read as that
//!   value. The rename's own `let` is then unread and pure, so the
//!   dead-binding cleanup drops it.
//! - **Integer and boolean literals.** Printed where they are read. A
//!   literal carries no operation, so nothing the scorer counts can be
//!   duplicated by printing it more than once.
//!
//! Nothing that performs an operation is folded — that is what keeps the
//! "one op, one chain" rule of [`super::idiom`] intact.
//!
//! Every consumer that reasons about reads — [`super::liveness`], the
//! escape analysis in [`super::body`], and the renderer itself — goes
//! through [`Fold::reads`], so the three cannot disagree about which value
//! a reference names.

use std::collections::{HashMap, HashSet};

use sordec_common::ValueId;
use sordec_ir::{Expr, HighFunction, IrType, Literal};

/// How far a chain of renames is followed.
const MAX_CHAIN: usize = 16;

/// The folding table for one function.
pub(crate) struct Fold {
    /// Rename → the value it renames, chains already followed.
    alias: HashMap<ValueId, ValueId>,
    /// Values that print as their literal wherever they are read.
    literal: HashSet<ValueId>,
}

impl Fold {
    /// Build the table for `func`.
    pub(crate) fn build(func: &HighFunction) -> Self {
        let params: HashSet<ValueId> = func.params.iter().copied().collect();
        let literal: HashSet<ValueId> = func
            .bindings
            .iter()
            .filter(|(id, b)| {
                !params.contains(id)
                    && matches!(
                        b.expr,
                        Expr::Literal(Literal::I32(_) | Literal::I64(_) | Literal::U32(_) | Literal::U64(_) | Literal::Bool(_))
                    )
            })
            .map(|(id, _)| id)
            .collect();
        let mut alias = HashMap::new();
        for (id, binding) in func.bindings.iter() {
            if params.contains(&id) {
                continue;
            }
            let Expr::Use(mut target) = binding.expr else {
                continue;
            };
            let mut steps = 0;
            while let Some(Expr::Use(next)) = func.bindings.get(target).map(|b| &b.expr) {
                steps += 1;
                if steps > MAX_CHAIN || params.contains(&target) {
                    break;
                }
                target = *next;
            }
            if target == id {
                continue;
            }
            let Some(target_binding) = func.bindings.get(target) else {
                continue;
            };
            if same_type(&binding.ty, &target_binding.ty) {
                alias.insert(id, target);
            }
        }
        Self { alias, literal }
    }

    /// The value a reference to `vid` reads, or `None` when it prints as a
    /// literal and reads nothing.
    pub(crate) fn reads(&self, vid: ValueId) -> Option<ValueId> {
        let target = self.alias.get(&vid).copied().unwrap_or(vid);
        (!self.literal.contains(&target)).then_some(target)
    }

    /// The value a reference to `vid` names: its rename target, or itself.
    pub(crate) fn target(&self, vid: ValueId) -> ValueId {
        self.alias.get(&vid).copied().unwrap_or(vid)
    }

    /// Whether a reference to `vid` prints as a literal.
    pub(crate) fn is_literal(&self, vid: ValueId) -> bool {
        self.literal.contains(&self.target(vid))
    }
}

/// Whether a rename may be read as its target without changing what type
/// the reference has: the same type, or a rename with none of its own.
fn same_type(rename: &IrType, target: &IrType) -> bool {
    match (rename, target) {
        (IrType::Unknown(_), _) => true,
        (IrType::Known(a) | IrType::Inferred(a), IrType::Known(b) | IrType::Inferred(b)) => a == b,
        _ => rename == target,
    }
}
