//! Shared wrapper-identification utilities for recognizers.
//!
//! rustc leaves the SDK's tiny constructor helpers un-inlined: a
//! "wrapper" is a helper whose body (possibly through one or two more
//! nested helpers) bottoms out in a recognized host op — `SymbolNew`
//! for `Symbol::new`, `VecNew` for the args/key vec builders — with
//! the op's interesting operands fed **positionally from the wrapper's
//! own parameters**. Identifying the wrapper and the param positions
//! lets a caller-side pass read constant arguments straight off the
//! callsite (`enum-key` reads rodata `(pos, len)` slices;
//! `client-call` reads the args-vec `(ptr, len)`).
//!
//! Two pieces live here:
//!
//! - [`wrapper_params`] — the nested-wrapper search, parameterized by
//!   an op matcher so each recognizer names the op family it cares
//!   about.
//! - [`operand_param`] — the cycle-tolerant walk mapping one operand
//!   back to a parameter position (peeling `ValEncodeSmall`, pure
//!   width conversions, and meeting over phi edges).

use std::collections::HashSet;

use sordec_common::{FuncId, ValueId};
use sordec_ir::{Expr, HighFunction, HighIr, KnownOp, SemanticOp, WasmOpcodeKind};

use crate::dataflow::resolve_use;

/// Walk depth for [`operand_param`] — the SDK's `Symbol::new` threads
/// its `(pos, len)` through long phi chains and width conversions.
const PARAM_WALK_DEPTH: u32 = 64;

/// Identify a constructor wrapper: a non-exported helper whose body
/// (within `depth` nested calls) contains a `KnownOp` accepted by
/// `matcher`, with every matcher-returned operand fed positionally from
/// the wrapper's own parameters. Returns those parameter positions in
/// the matcher's operand order, so a caller's constant args can be
/// read off the callsite directly.
///
/// `matcher` returns the operands that must map to parameters (e.g.
/// `SymbolNew → [lm_pos, len]`, `VecNew → [vals_pos, len]`) or `None`
/// for ops of no interest.
pub(crate) fn wrapper_params(
    ir: &HighIr,
    target: FuncId,
    depth: u32,
    matcher: &dyn Fn(&KnownOp) -> Option<Vec<ValueId>>,
) -> Option<Vec<usize>> {
    let func = ir.function(target)?;
    // Exported functions are host-invocable entry points, never SDK
    // constructor wrappers.
    if func.name.is_some() {
        return None;
    }
    for (_, binding) in func.bindings.iter() {
        match &binding.expr {
            Expr::Semantic(SemanticOp::Known(op)) => {
                let Some(operands) = matcher(op) else {
                    continue;
                };
                let params: Option<Vec<usize>> = operands
                    .iter()
                    .map(|operand| operand_param(func, *operand))
                    .collect();
                if let Some(params) = params {
                    return Some(params);
                }
            }
            Expr::Call { target: inner, args } if depth > 0 => {
                let Some(inner_params) = wrapper_params(ir, *inner, depth - 1, matcher) else {
                    continue;
                };
                // Map the nested wrapper's parameter positions through
                // this callsite's arguments back to our own parameters.
                let params: Option<Vec<usize>> = inner_params
                    .iter()
                    .map(|idx| args.get(*idx).and_then(|a| operand_param(func, *a)))
                    .collect();
                if let Some(params) = params {
                    return Some(params);
                }
            }
            _ => {}
        }
    }
    None
}

/// Outcome of one [`operand_param_walk`] arm.
enum ParamWalk {
    /// Resolved to this parameter position.
    Param(usize),
    /// Re-entered a node on the current path: a purely-cyclic
    /// loop-carried arm, which contributes no value of its own.
    Cycle,
    /// Non-parameter terminal.
    Fail,
}

/// Which of `func`'s parameters feeds `operand`. Peels the C1
/// `ValEncodeSmall` U32Val wrapper and pure width conversions, and
/// meets over phi edges (every non-cyclic incoming path must reach the
/// *same* parameter) — the SDK's `Symbol::new` small/long dual path
/// rejoins its original `(pos, len)` through exactly such phis, with a
/// loop-carried back edge from the small-symbol packing loop. A pure
/// cycle arm (`x = phi(p, …→x)`) carries the value unchanged and is
/// skipped; any *transforming* back edge (`x+1`, a load, …) fails the
/// arm before the cycle closes, keeping the meet conservative.
pub(crate) fn operand_param(func: &HighFunction, operand: ValueId) -> Option<usize> {
    let mut path = HashSet::new();
    match operand_param_walk(func, operand, PARAM_WALK_DEPTH, &mut path) {
        ParamWalk::Param(idx) => Some(idx),
        ParamWalk::Cycle | ParamWalk::Fail => None,
    }
}

fn operand_param_walk(
    func: &HighFunction,
    operand: ValueId,
    depth: u32,
    path: &mut HashSet<ValueId>,
) -> ParamWalk {
    if depth == 0 {
        return ParamWalk::Fail;
    }
    let current = resolve_use(func, operand);
    if let Some(idx) = func.params.iter().position(|p| *p == current) {
        return ParamWalk::Param(idx);
    }
    if !path.insert(current) {
        return ParamWalk::Cycle;
    }
    let result = match func.bindings.get(current).map(|b| &b.expr) {
        Some(Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { value, .. }))) => {
            operand_param_walk(func, *value, depth - 1, path)
        }
        // A pure numeric width conversion of the same value (the
        // i32→i64 extend before Val-encoding).
        Some(Expr::Unknown {
            op_kind: WasmOpcodeKind::Conversion,
            args,
            ..
        }) if args.len() == 1 => operand_param_walk(func, args[0], depth - 1, path),
        Some(Expr::Phi { incoming }) if !incoming.is_empty() => {
            let mut agreed: Option<usize> = None;
            let mut failed = false;
            for (_, value) in incoming {
                match operand_param_walk(func, *value, depth - 1, path) {
                    ParamWalk::Param(idx) => match agreed {
                        None => agreed = Some(idx),
                        Some(prev) if prev == idx => {}
                        Some(_) => {
                            failed = true;
                            break;
                        }
                    },
                    ParamWalk::Cycle => {}
                    ParamWalk::Fail => {
                        failed = true;
                        break;
                    }
                }
            }
            match (failed, agreed) {
                (false, Some(idx)) => ParamWalk::Param(idx),
                // All arms cyclic: nothing flows in.
                (false, None) => ParamWalk::Cycle,
                (true, _) => ParamWalk::Fail,
            }
        }
        _ => ParamWalk::Fail,
    };
    path.remove(&current);
    result
}
