//! Reverse-use index over `HighIr`: "who reads this binding?"
//!
//! The `HighIr` counterpart of [`crate::dataflow::DefUseIndex`]. Reads
//! come from three surfaces:
//!
//! - **other bindings' expressions** (operands, phi incomings, semantic
//!   op slots — via the exhaustive [`sordec_ir::Expr::for_each_value_use`]);
//! - **the function's return sites** (`HighFunction::returns` — the
//!   lifted `Return` terminators, otherwise invisible at this layer);
//! - **the region tree** (via [`sordec_ir::Region::for_each_value_use`]:
//!   `If` conditions, `Switch` indices, transfer sources, region
//!   returns). Empty while the region is still
//!   [`sordec_ir::Region::Unstructured`] — consumers that reason about
//!   deadness must stay conservative there (see
//!   [`crate::dataflow::InlinePlan`]).
//!
//! Same snapshot rule as `DefUseIndex`: the index reflects the function
//! at build time; rebuild after mutating.

use sordec_common::{IrId, ValueId};
use sordec_ir::HighFunction;

/// One place where a binding's value is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HighUseSite {
    /// Read by another binding's expression (operand, phi incoming,
    /// semantic-op slot).
    Binding {
        /// The binding whose expression reads it.
        user: ValueId,
    },
    /// Read by a function return site (`HighFunction::returns`).
    Return,
    /// Read by the region tree (condition, switch index, transfer
    /// source, region return).
    Region,
}

/// Reverse-use map for one [`HighFunction`]. Build once with
/// [`HighUseIndex::build`]; see the module docs for what counts as a
/// use and for the snapshot rule.
#[derive(Debug, Clone)]
pub struct HighUseIndex {
    /// `uses[i]` = all use sites of `ValueId(i)`, in deterministic
    /// order: binding uses first (arena order), then return-site uses,
    /// then region uses (pre-order).
    uses: Vec<Vec<HighUseSite>>,
}

impl HighUseIndex {
    /// Build the index for one function in a single linear scan.
    #[must_use]
    pub fn build(func: &HighFunction) -> Self {
        let mut uses: Vec<Vec<HighUseSite>> = vec![Vec::new(); func.bindings.len()];
        let record = |value: ValueId, site: HighUseSite, uses: &mut Vec<Vec<HighUseSite>>| {
            if let Some(slot) = uses.get_mut(value.index() as usize) {
                slot.push(site);
            }
        };

        for (user, binding) in func.bindings.iter() {
            binding
                .expr
                .for_each_value_use(|value| record(value, HighUseSite::Binding { user }, &mut uses));
        }
        for site_values in &func.returns {
            for &value in site_values {
                record(value, HighUseSite::Return, &mut uses);
            }
        }
        func.region
            .for_each_value_use(|value| record(value, HighUseSite::Region, &mut uses));

        Self { uses }
    }

    /// All use sites of `value` (empty for an id outside the arena).
    #[must_use]
    pub fn uses_of(&self, value: ValueId) -> &[HighUseSite] {
        self.uses
            .get(value.index() as usize)
            .map_or(&[], Vec::as_slice)
    }

    /// Number of use sites (occurrences, not distinct users).
    #[must_use]
    pub fn use_count(&self, value: ValueId) -> usize {
        self.uses_of(value).len()
    }

    /// True when `value` has zero recorded use sites.
    #[must_use]
    pub fn is_unused(&self, value: ValueId) -> bool {
        self.uses_of(value).is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{Arena, BlockId, FuncId, Provenance, ProvenanceSource, UnknownReason};
    use sordec_ir::{Binding, Expr, HighBlock, IrType, Literal, Region};

    fn v(idx: u32) -> ValueId {
        ValueId::from_index(idx)
    }

    fn binding(id: ValueId, expr: Expr) -> Binding {
        Binding::new(
            id,
            IrType::Unknown(UnknownReason::UpstreamUnknown),
            expr,
            Provenance {
                pass: "test",
                source: ProvenanceSource::DataFlow,
                note: String::new(),
            },
        )
    }

    fn func_with(exprs: Vec<Expr>, returns: Vec<Vec<ValueId>>, region: Region) -> HighFunction {
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        for (i, expr) in exprs.into_iter().enumerate() {
            bindings.push(binding(v(i as u32), expr));
        }
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        blocks.push(HighBlock {
            id: BlockId::from_index(0),
            bindings: bindings.ids().collect(),
        });
        HighFunction {
            id: FuncId::from_index(0),
            name: None,
            signature: None,
            blocks,
            bindings,
            region,
            params: vec![],
            returns,
        }
    }

    #[test]
    fn binding_return_and_region_sites_recorded_in_order() {
        // v0 literal; v1 = Use(v0); return v0; region If cond v0.
        let func = func_with(
            vec![Expr::Literal(Literal::I32(1)), Expr::Use(v(0))],
            vec![vec![v(0)]],
            Region::If {
                cond: v(0),
                then_region: Box::new(Region::Unreachable),
                else_region: None,
            },
        );
        let index = HighUseIndex::build(&func);
        assert_eq!(
            index.uses_of(v(0)),
            &[
                HighUseSite::Binding { user: v(1) },
                HighUseSite::Return,
                HighUseSite::Region,
            ]
        );
        assert!(index.is_unused(v(1)));
    }

    #[test]
    fn phi_incomings_count_as_uses() {
        let func = func_with(
            vec![
                Expr::Literal(Literal::I32(1)),
                Expr::Phi {
                    incoming: vec![(BlockId::from_index(0), v(0))],
                },
            ],
            vec![],
            Region::Unstructured {
                entry: BlockId::from_index(0),
                reason: UnknownReason::UpstreamUnknown,
            },
        );
        let index = HighUseIndex::build(&func);
        assert_eq!(index.use_count(v(0)), 1);
    }

    #[test]
    fn unstructured_region_contributes_no_uses() {
        let func = func_with(
            vec![Expr::Literal(Literal::I32(1))],
            vec![],
            Region::Unstructured {
                entry: BlockId::from_index(0),
                reason: UnknownReason::UpstreamUnknown,
            },
        );
        let index = HighUseIndex::build(&func);
        assert!(index.is_unused(v(0)));
    }
}
