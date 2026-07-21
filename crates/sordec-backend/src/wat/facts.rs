//! Extract the recovered-fact set the annotations carry.
//!
//! [`recovered_facts`] walks each function's structured region in
//! emission order and renders every recognized semantic operation, typed
//! panic, and surviving unknown into a compact line. The result is the
//! single source of truth for two consumers:
//!
//! - the emitter's per-function **L1 header block** (a complete,
//!   always-present list — no recovered fact is ever dropped), and
//! - the **E4 extractor** test, which parses the emitted `;;` lines back
//!   and asserts they reproduce exactly this set (lossless annotation).
//!
//! Producing both from one function keeps them from drifting.

use sordec_common::IrId;
use sordec_ir::{Binding, Expr, HighFunction, HighIr, Region, SemanticOp, TypeRegistry};

use crate::wat::annotate;

/// Recovered facts for one function, ready to render as a header block.
#[derive(Debug, Clone)]
pub(crate) struct FunctionFacts {
    /// Header title line, e.g. `fn transfer(from: Address, to: Address,
    /// amount: i128) -> ()`, or an internal-helper form when the function
    /// is not in the contract spec.
    pub title: String,
    /// Recovered-fact lines in emission order, each already carrying its
    /// `[ProvenanceSource]` tag where one applies.
    pub facts: Vec<String>,
}

/// Recover the fact set for every local function, in module (code) order —
/// positionally parallel to [`WasmFacts::function_bodies`](sordec_ir::WasmFacts::function_bodies)
/// and thus to the emitter's function anchors.
pub(crate) fn recovered_facts(high: &HighIr) -> Vec<FunctionFacts> {
    let empty_registry = TypeRegistry::default();
    let registry = high
        .soroban_facts
        .as_ref()
        .map_or(&empty_registry, |s| &s.types);

    // Imported functions occupy the low WASM function indices; a local
    // function's printed `$#funcN` name uses the module-global index, so
    // unnamed-helper titles must add the import offset to match.
    let import_offset = high
        .facts
        .imports
        .iter()
        .filter(|i| matches!(i.kind, sordec_ir::ImportKind::Func(_)))
        .count() as u32;

    high.functions
        .iter()
        .map(|func| FunctionFacts {
            title: function_title(func, registry, import_offset),
            facts: function_facts(func),
        })
        .collect()
}

fn function_title(func: &HighFunction, registry: &TypeRegistry, import_offset: u32) -> String {
    match &func.signature {
        Some(sig) => annotate::render_signature(sig, registry),
        None => {
            // Reference the module-global function index the printer marks
            // as `(func (;N;) …)`, so header and body cross-reference.
            let global = import_offset + func.id.index();
            match &func.name {
                Some(name) => format!("fn {name} (#{global})"),
                None => format!("fn #{global} (internal)"),
            }
        }
    }
}

/// Collect the recovered facts of one function, in region-emission order.
fn function_facts(func: &HighFunction) -> Vec<String> {
    let mut facts = Vec::new();
    func.region.for_each_node(|region| match region {
        Region::Basic(block_id) => {
            if let Some(block) = func.blocks.get(*block_id) {
                for &value in &block.bindings {
                    if let Some(binding) = func.bindings.get(value)
                        && let Some(fact) = binding_fact(binding)
                    {
                        facts.push(fact);
                    }
                }
            }
        }
        Region::Panic { kind } => facts.push(annotate::label_panic(*kind)),
        _ => {}
    });
    facts
}

/// Render one binding as a recovered fact, or `None` when the binding
/// carries no audit-relevant recovery (raw arithmetic, loads, phis, …).
fn binding_fact(binding: &Binding) -> Option<String> {
    match &binding.expr {
        Expr::Semantic(SemanticOp::Known(op)) => {
            let tag = binding.latest_provenance().source.label();
            Some(format!("{} [{tag}]", annotate::label_known_op(op)))
        }
        Expr::Semantic(SemanticOp::Unknown {
            host_module,
            host_fn,
            reason,
            ..
        }) => Some(format!("unrecognized: {host_module}::{host_fn} ({reason:?})")),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{
        Arena, BlockId, FuncId, Provenance, ProvenanceSource, UnknownReason, ValueId,
    };
    use sordec_ir::{HighBlock, IrType, KnownOp, KnownTier, MemoryImage, StorageTier, WasmFacts};

    fn high_with(func: HighFunction) -> HighIr {
        HighIr {
            facts: WasmFacts {
                imports: vec![],
                exports: vec![],
                function_type_indices: vec![],
                function_bodies: vec![],
                custom_sections: vec![],
            },
            soroban_facts: None,
            functions: vec![func],
            memory: MemoryImage::empty(),
        }
    }

    #[test]
    fn walk_collects_known_ops_in_block_order_with_tag() {
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        let get = KnownOp::StorageGet {
            tier: StorageTier::Known(KnownTier::Persistent),
            durability: ValueId::new(0),
            key: ValueId::new(1),
            resolved_key: None,
        };
        let vid = bindings.push(Binding::new(
            ValueId::new(0),
            IrType::Unknown(UnknownReason::UpstreamUnknown),
            Expr::Semantic(SemanticOp::Known(get)),
            Provenance::new("test", ProvenanceSource::SdkPattern, "matched"),
        ));
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        let bid = blocks.push(HighBlock {
            id: BlockId::new(0),
            bindings: vec![vid],
        });

        let func = HighFunction {
            id: FuncId::new(0),
            name: Some("test_fn".to_string()),
            signature: None,
            blocks,
            bindings,
            region: Region::Basic(bid),
            params: vec![],
            returns: vec![],
        };

        let facts = recovered_facts(&high_with(func));
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].title, "fn test_fn (#0)");
        assert_eq!(facts[0].facts, vec!["storage_get<persistent> v1 [SdkPattern]"]);
    }
}
