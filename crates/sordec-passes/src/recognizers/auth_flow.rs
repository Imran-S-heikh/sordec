//! The auth-flow recognizer: admin-gate annotation (spec D2.3's
//! `get(Admin) → require_auth` flow).
//!
//! The SEP-41 admin gate compiles to `let admin = read_administrator();
//! admin.require_auth()` — a `require_auth` whose address operand is
//! the value read from **instance storage under a unit-variant enum
//! key** (`DataKey::Admin`). With the enum-key pass having named the
//! key, this pass closes the loop: it walks the `require_auth`
//! address operand backwards — across helper returns — and, when
//! **every** value-producing path terminates at the *same*
//! `storage_get` op with `tier: Known(Instance)` and a resolved
//! unit-variant key, annotates the `require_auth` binding.
//!
//! ## Walk discipline (meet, mirroring the `Resolver`'s soundness rules)
//!
//! - A phi resolves only when every incoming edge reaches the same
//!   storage-get binding; a `Call` resolves as the meet over the
//!   callee's single-value return sites. Function-diverging paths (the
//!   unwrap-panic arm of `read_administrator`) have no return site and
//!   drop out structurally.
//! - A parameter terminal fails the walk — an address handed in by the
//!   caller (plain `require_auth(from)`) is ordinary auth, not an
//!   admin gate. No caller-set reasoning happens at all, so the
//!   exported/indirect guards are not needed here.
//! - Cycles are path-scoped; a depth cap backstops pathological IR.
//!
//! The pass is **provenance-only**: the op stays `RequireAuth` (that
//! *is* the semantic — Phase 3 structuring consumes the address chain
//! itself), so per the pass conventions it always reports
//! `changed: false` and is fixpoint-neutral. Idempotency comes from
//! skipping bindings already annotated by this pass.

use std::collections::HashSet;

use sordec_common::{FuncId, IrId, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{EnumKey, Expr, HighIr, KnownOp, KnownTier, SemanticOp, StorageTier};

use crate::dataflow::resolve_use;
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field for every annotation.
pub const PASS_NAME: &str = "auth-flow";

/// `require_auth` sites proven to be admin gates.
const M_ADMIN_GATE: &str = "auth_admin_gate";

/// Depth cap for the address walk (mirrors the resolver's discipline).
const WALK_DEPTH: u32 = 64;

/// The auth-flow recognizer pass. Stateless between runs.
#[derive(Debug, Default, Clone, Copy)]
pub struct AuthFlowPass;

impl Pass<HighIr> for AuthFlowPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();

        // Phase A — read-only: collect (function, binding, note) for
        // every require_auth whose address walks to an admin-key get.
        let mut planned: Vec<(FuncId, ValueId, String)> = Vec::new();
        for func in &ir.functions {
            for (id, binding) in func.bindings.iter() {
                let Expr::Semantic(SemanticOp::Known(KnownOp::RequireAuth { address })) =
                    &binding.expr
                else {
                    continue;
                };
                // Idempotency: already annotated by this pass.
                if binding.provenance().iter().any(|p| p.pass == PASS_NAME) {
                    continue;
                }
                let mut path = HashSet::new();
                let Some((get_fn, get_id)) =
                    walk_to_get(ir, func.id, *address, &mut path, WALK_DEPTH)
                else {
                    continue;
                };
                let Some(enum_key) = admin_key_of(ir, get_fn, get_id) else {
                    continue;
                };
                planned.push((
                    func.id,
                    id,
                    format!(
                        "admin gate: address = storage_get<instance>({}::{})",
                        enum_key.enum_name, enum_key.variant
                    ),
                ));
            }
        }

        // Phase B — provenance-only application: no expr/type change,
        // so `changed` stays false per the pass conventions.
        for (func_id, id, note) in planned {
            if let Some(binding) = ir
                .function_mut(func_id)
                .and_then(|func| func.bindings.get_mut(id))
            {
                binding.add_provenance(Provenance::new(
                    PASS_NAME,
                    ProvenanceSource::SdkPattern,
                    note,
                ));
                result.metrics.increment(M_ADMIN_GATE, 1);
            }
        }
        result
    }
}

/// Meet-walk an address operand to the unique `storage_get` binding
/// every value-producing path terminates at. `None` on any
/// disagreement, parameter terminal, cycle-only path, or non-get
/// terminal.
fn walk_to_get(
    ir: &HighIr,
    func_id: FuncId,
    value: ValueId,
    path: &mut HashSet<(FuncId, ValueId)>,
    depth: u32,
) -> Option<(FuncId, ValueId)> {
    if depth == 0 {
        return None;
    }
    let func = ir.function(func_id)?;
    let terminal = resolve_use(func, value);
    if (terminal.index() as usize) >= func.bindings.len() {
        return None;
    }
    // A parameter is caller-supplied: plain auth, not an admin gate.
    // (Params are empty-incoming phis; check before the phi arm.)
    if func.params.contains(&terminal) {
        return None;
    }
    if !path.insert((func_id, terminal)) {
        // Re-entered a node on the current path: cycle, no value.
        return None;
    }
    let result = (|| {
        match &func.bindings.get(terminal)?.expr {
            Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet { .. })) => {
                Some((func_id, terminal))
            }
            Expr::Phi { incoming } if !incoming.is_empty() => meet(
                ir,
                incoming.iter().map(|(_, v)| (func_id, *v)),
                path,
                depth - 1,
            ),
            Expr::Call { target, .. } => {
                let callee = ir.function(*target)?;
                // Zero return sites = diverging; multi-value sites mean
                // the Call binding is not "the value".
                if callee.returns.is_empty()
                    || callee.returns.iter().any(|values| values.len() != 1)
                {
                    return None;
                }
                let callee_id = *target;
                meet(
                    ir,
                    callee.returns.iter().map(|values| (callee_id, values[0])),
                    path,
                    depth - 1,
                )
            }
            _ => None,
        }
    })();
    path.remove(&(func_id, terminal));
    result
}

/// Meet a set of (function, value) sources: all must walk to the same
/// storage-get binding.
fn meet(
    ir: &HighIr,
    sources: impl Iterator<Item = (FuncId, ValueId)>,
    path: &mut HashSet<(FuncId, ValueId)>,
    depth: u32,
) -> Option<(FuncId, ValueId)> {
    let mut agreed: Option<(FuncId, ValueId)> = None;
    for (func_id, value) in sources {
        let got = walk_to_get(ir, func_id, value, path, depth)?;
        match agreed {
            None => agreed = Some(got),
            Some(prev) if prev == got => {}
            Some(_) => return None,
        }
    }
    agreed
}

/// The resolved unit-variant key of an instance-tier `storage_get`
/// binding, or `None` when the get doesn't qualify as an admin read
/// (wrong tier, unresolved key, payload variant).
fn admin_key_of(ir: &HighIr, func_id: FuncId, get_id: ValueId) -> Option<EnumKey> {
    let func = ir.function(func_id)?;
    let Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet {
        tier: StorageTier::Known(KnownTier::Instance),
        resolved_key: Some(enum_key),
        ..
    })) = &func.bindings.get(get_id)?.expr
    else {
        return None;
    };
    enum_key.payload.is_empty().then(|| enum_key.clone())
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{Arena, BlockId, UnknownReason};
    use sordec_ir::{
        Binding, HighBlock, HighFunction, IrType, Literal, MemoryImage, Region, WasmFacts,
    };

    fn func(id: u32, name: Option<&str>, n_params: usize, exprs: Vec<Expr>) -> HighFunction {
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        let mut params = Vec::new();
        for _ in 0..n_params {
            let id = ValueId::from_index(bindings.len() as u32);
            bindings.push(Binding::new(
                id,
                IrType::Unknown(UnknownReason::InsufficientEvidence),
                Expr::Phi { incoming: vec![] },
                Provenance::new("test", ProvenanceSource::DataFlow, "param"),
            ));
            params.push(id);
        }
        for expr in exprs {
            let vid = ValueId::from_index(bindings.len() as u32);
            bindings.push(Binding::new(
                vid,
                IrType::Unknown(UnknownReason::InsufficientEvidence),
                expr,
                Provenance::new("test", ProvenanceSource::DataFlow, "seed"),
            ));
        }
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        blocks.push(HighBlock {
            id: BlockId::from_index(0),
            bindings: vec![],
        });
        HighFunction {
            id: FuncId::from_index(id),
            name: name.map(str::to_string),
            signature: None,
            blocks,
            bindings,
            region: Region::Unreachable,
            params,
            returns: vec![],
        }
    }

    fn module(functions: Vec<HighFunction>) -> HighIr {
        HighIr {
            facts: WasmFacts {
                imports: vec![],
                exports: vec![],
                function_type_indices: vec![],
                custom_sections: vec![],
            },
            soroban_facts: None,
            functions,
            memory: MemoryImage::empty(),
        }
    }

    fn v(i: u32) -> ValueId {
        ValueId::from_index(i)
    }

    fn with_returns(mut f: HighFunction, sites: Vec<Vec<u32>>) -> HighFunction {
        f.returns = sites
            .into_iter()
            .map(|vals| vals.into_iter().map(v).collect())
            .collect();
        f
    }

    fn admin_get(tier: KnownTier, key: Option<EnumKey>) -> Expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet {
            tier: StorageTier::Known(tier),
            durability: v(0),
            key: v(0),
            resolved_key: key,
        }))
    }

    fn unit_key() -> EnumKey {
        EnumKey {
            enum_name: "DataKey".to_string(),
            variant: "Admin".to_string(),
            payload: vec![],
        }
    }

    fn require_auth(address: u32) -> Expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::RequireAuth { address: v(address) }))
    }

    fn call(target: u32, args: Vec<ValueId>) -> Expr {
        Expr::Call {
            target: FuncId::from_index(target),
            args,
        }
    }

    fn run(ir: &mut HighIr) -> PassResult {
        AuthFlowPass.run(ir)
    }

    fn gate_note(ir: &HighIr, func: u32, id: u32) -> Option<String> {
        ir.functions[func as usize]
            .bindings
            .get(v(id))
            .unwrap()
            .provenance()
            .iter()
            .find(|p| p.pass == PASS_NAME)
            .map(|p| p.note.clone())
    }

    /// The corpus shape: f0 = read_administrator (get + return through
    /// a phi), f1 requires auth on its result.
    fn admin_module(tier: KnownTier, key: Option<EnumKey>) -> HighIr {
        // f0: v0 = literal (key stand-in); v1 = get; v2 = phi[(bb, v1)]
        let helper = with_returns(
            func(
                0,
                None,
                0,
                vec![
                    Expr::Literal(Literal::I64(0)),
                    admin_get(tier, key),
                    Expr::Phi {
                        incoming: vec![(BlockId::from_index(1), v(1))],
                    },
                ],
            ),
            vec![vec![2]],
        );
        // f1: v0 = call f0; v1 = require_auth(v0)
        let entry = func(1, Some("mint"), 0, vec![call(0, vec![]), require_auth(0)]);
        module(vec![helper, entry])
    }

    #[test]
    fn admin_gate_is_annotated() {
        let mut ir = admin_module(KnownTier::Instance, Some(unit_key()));
        let result = run(&mut ir);
        assert!(!result.changed, "provenance-only pass must not report change");
        assert_eq!(result.metrics.get(M_ADMIN_GATE), Some(1));
        let note = gate_note(&ir, 1, 1).expect("annotated");
        assert_eq!(
            note,
            "admin gate: address = storage_get<instance>(DataKey::Admin)"
        );
    }

    #[test]
    fn second_run_does_not_duplicate() {
        let mut ir = admin_module(KnownTier::Instance, Some(unit_key()));
        run(&mut ir);
        let result = run(&mut ir);
        assert_eq!(result.metrics.get(M_ADMIN_GATE), None);
        let notes = ir.functions[1]
            .bindings
            .get(v(1))
            .unwrap()
            .provenance()
            .iter()
            .filter(|p| p.pass == PASS_NAME)
            .count();
        assert_eq!(notes, 1);
    }

    #[test]
    fn non_instance_tier_is_not_a_gate() {
        let mut ir = admin_module(KnownTier::Persistent, Some(unit_key()));
        run(&mut ir);
        assert!(gate_note(&ir, 1, 1).is_none());
    }

    #[test]
    fn unresolved_key_is_not_a_gate() {
        let mut ir = admin_module(KnownTier::Instance, None);
        run(&mut ir);
        assert!(gate_note(&ir, 1, 1).is_none());
    }

    #[test]
    fn payload_variant_is_not_a_gate() {
        let mut ir = admin_module(
            KnownTier::Instance,
            Some(EnumKey {
                enum_name: "DataKey".to_string(),
                variant: "Balance".to_string(),
                payload: vec![v(9)],
            }),
        );
        run(&mut ir);
        assert!(gate_note(&ir, 1, 1).is_none());
    }

    #[test]
    fn param_address_is_plain_auth() {
        // require_auth(param) — transfer's shape; never annotated.
        let f = func(0, Some("transfer"), 1, vec![require_auth(0)]);
        let mut ir = module(vec![f]);
        let result = run(&mut ir);
        assert_eq!(result.metrics.get(M_ADMIN_GATE), None);
    }

    #[test]
    fn disagreeing_return_sites_refuse() {
        // Helper with two return sites: one the get, one a literal.
        let helper = with_returns(
            func(
                0,
                None,
                0,
                vec![
                    Expr::Literal(Literal::I64(0)),
                    admin_get(KnownTier::Instance, Some(unit_key())),
                    Expr::Literal(Literal::I64(7)),
                ],
            ),
            vec![vec![1], vec![2]],
        );
        let entry = func(1, Some("mint"), 0, vec![call(0, vec![]), require_auth(0)]);
        let mut ir = module(vec![helper, entry]);
        run(&mut ir);
        assert!(gate_note(&ir, 1, 1).is_none());
    }

    #[test]
    fn diverging_helper_returns_refuse() {
        // A return-less (diverging) callee provides no value.
        let helper = func(
            0,
            None,
            0,
            vec![admin_get(KnownTier::Instance, Some(unit_key()))],
        );
        let entry = func(1, Some("mint"), 0, vec![call(0, vec![]), require_auth(0)]);
        let mut ir = module(vec![helper, entry]);
        run(&mut ir);
        assert!(gate_note(&ir, 1, 1).is_none());
    }
}
