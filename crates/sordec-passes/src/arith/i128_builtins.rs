//! The `compiler_builtins` 128-bit integer runtime, recovered as arithmetic.
//!
//! # What this recognises
//!
//! `desired_a * reserve_b / reserve_a` is one line of source. Under
//! `overflow-checks = true`, rustc compiles the `i128` multiply into a call
//! to `__muloti4` — a product plus an overflow flag handed back through a
//! pointer — and the divide into `__divti3`, which strips signs, calls
//! `__udivmodti4` (a 176-byte-frame long division that itself calls the
//! shift helpers `__ashlti3`/`__lshrti3` and `__multi3`), and re-signs the
//! quotient. Every one of those helpers is emitted into the contract's
//! wasm as an ordinary function.
//!
//! On dex-liquidity-pool that family is **seven functions and ~135 of the
//! module's 537 weighted structure tokens, 25% of the whole deficit**, for
//! constructs the source spells with no control flow at all.
//!
//! # Why body-shape rather than a fingerprint
//!
//! The signature catalogue cannot name these: they are not SDK code, so
//! the corpus builder classifies their crate as nothing and drops them.
//! They are also *not* generic — each is one monomorphic body with a fixed
//! ABI — which makes a structural match unusually safe here. The gate for
//! each helper is its arity, its return arity, the constants its algorithm
//! cannot avoid (`0xFFFF_FFFF` and `32` for the limb split, `64` and a
//! complementary count — `63 - n`, or `0 - n` mod 64 — for the shift
//! decomposition, two `clz`s for the division's normalisation),
//! and a *closed* call set: a division helper may call only the shift
//! helpers and the multiply. A body holding any host operation is refused
//! outright — the runtime touches no ledger.
//!
//! # What the rewrite is, and why it is exact
//!
//! Each call becomes one expression over [`Expr::WideJoin`] operands:
//!
//! ```text
//! t = __multi3(a_lo, a_hi, b_lo, b_hi)      p = wide(a_lo,a_hi) * wide(b_lo,b_hi)
//! t.0, t.1                             →    wide_lo(p), wide_hi(p)
//!
//! t = __muloti4(a…, b…, &flag)              p = a * b;   ovf = a.checked_mul(b).is_none()
//! load flag                            →    ovf
//!
//! t = __divti3(a…, b…)                 →    q = wide(a) / wide(b)
//! ```
//!
//! The builtins are total functions with a documented contract, so this is
//! a change of spelling, not of value. The one behavioural edge is the
//! overflow flag: `__muloti4` reports it, the caller traps on it, and the
//! re-emitted `a * b` regenerates exactly that trap under the emitted
//! crate's `overflow-checks = true` — the same relocation argument the
//! 64-bit overflow-guard elision rests on, applied through
//! [`BinaryOp::MulOverflows`] so the panic classifier can see it.
//!
//! Division by zero and `MIN / -1` are checked by the *caller* before the
//! helper is entered, and those guards are left where they are: they are
//! real branches until the panic classifier proves them rustc's, which is
//! a separate step.
//!
//! # What it does not touch
//!
//! Call sites *inside* another identified builtin are left alone — the
//! helper becomes unreachable once its own callers are rewritten, and
//! rewriting its body would be work the emitter never prints. The shift
//! helpers are identified only so the division's call set can be closed;
//! a direct `x << n` on an `i128` is not rewritten yet.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use sordec_common::{
    Diagnostic, FuncId, IrId, LiftDiagnosticCode, Location, Provenance, ProvenanceSource, ValueId,
};
use sordec_ir::{
    BinaryOp, Binding, Expr, HighFunction, HighIr, IrType, KnownType, Literal, UnaryOp,
};

use crate::dataflow::resolve_use;
use crate::metrics_catalog::{
    I128_BUILTIN_CALLS_REWRITTEN as M_REWRITTEN, I128_BUILTINS_IDENTIFIED as M_IDENTIFIED,
};
use crate::pass::{Pass, PassResult};

/// Pass name, also its provenance `pass` field.
pub const PASS_NAME: &str = "i128-builtins";

/// Which runtime helper a body is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Builtin {
    /// `__multi3`: wrapping 128-bit multiply.
    Multi3,
    /// `__muloti4`: signed multiply with an overflow flag through a pointer.
    Muloti4,
    /// `__ashlti3` / `__lshrti3` / `__ashrti3`: 128-bit shift by a word.
    Shift,
    /// `__udivmodti4`: unsigned divide returning quotient and remainder.
    Udivmodti4,
    /// `__divti3` / `__modti3`: signed divide or remainder.
    Signed(BinaryOp),
    /// `__udivti3` / `__umodti3`: unsigned divide or remainder.
    Unsigned(BinaryOp),
}

impl Builtin {
    fn symbol(self) -> &'static str {
        match self {
            Builtin::Multi3 => "__multi3",
            Builtin::Muloti4 => "__muloti4",
            Builtin::Shift => "__ashlti3/__lshrti3",
            Builtin::Udivmodti4 => "__udivmodti4",
            Builtin::Signed(BinaryOp::Rem) => "__modti3",
            Builtin::Signed(_) => "__divti3",
            Builtin::Unsigned(BinaryOp::Rem) => "__umodti3",
            Builtin::Unsigned(_) => "__udivti3",
        }
    }
}

/// Recognises the 128-bit runtime helpers and rewrites their calls.
#[derive(Debug, Default, Clone, Copy)]
pub struct I128BuiltinPass;

impl Pass<HighIr> for I128BuiltinPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let builtins = identify(ir);
        if builtins.is_empty() {
            return result;
        }
        for (id, kind) in &builtins {
            result.diagnostics.push(
                Diagnostic::info(
                    LiftDiagnosticCode::SdkFunctionIdentified,
                    format!("func_{} is compiler_builtins::{}", id.index(), kind.symbol()),
                )
                .at(Location::Function(*id)),
            );
        }
        result.metrics.increment(M_IDENTIFIED, builtins.len() as i64);

        let mut rewritten = 0_i64;
        for func in &mut ir.functions {
            if builtins.contains_key(&func.id) {
                continue;
            }
            let sites: Vec<(ValueId, Builtin)> = func
                .bindings
                .iter()
                .filter_map(|(id, b)| match &b.expr {
                    Expr::Call { target, .. } => builtins.get(target).map(|k| (id, *k)),
                    _ => None,
                })
                .collect();
            for (call, kind) in sites {
                if rewrite_site(func, call, kind) {
                    rewritten += 1;
                }
            }
        }
        if rewritten > 0 {
            result.metrics.increment(M_REWRITTEN, rewritten);
            result.changed = true;
        }
        result
    }
}

// ---------------------------------------------------------------------
// Identification
// ---------------------------------------------------------------------

/// The facts about a body the gates read, computed once.
struct Shape {
    params: usize,
    /// Return arity when every return site agrees, else `None`.
    ret_arity: Option<usize>,
    calls: BTreeSet<FuncId>,
    /// Any host operation, indirect call, or unknown host call.
    host: bool,
    literals: BTreeSet<i128>,
    clz: usize,
    muls: usize,
    xors: usize,
    shifts: usize,
    /// `0 - x`: how a shift helper spells `64 - n` when wasm's shift
    /// count is taken mod 64.
    negations: usize,
    stores: usize,
    /// Component indices this body projects out of each callee's result.
    projections: BTreeMap<FuncId, BTreeSet<u32>>,
}

fn shape_of(func: &HighFunction) -> Shape {
    let mut s = Shape {
        params: func.params.len(),
        ret_arity: None,
        calls: BTreeSet::new(),
        host: false,
        literals: BTreeSet::new(),
        clz: 0,
        muls: 0,
        xors: 0,
        shifts: 0,
        negations: 0,
        stores: 0,
        projections: BTreeMap::new(),
    };
    let mut arities: BTreeSet<usize> = func.returns.iter().map(Vec::len).collect();
    if arities.len() == 1 {
        s.ret_arity = arities.pop_first();
    }
    // Only what the function still executes. The sret conversion leaves
    // the helper's original result stores in the arena unscheduled, and
    // counting that residue as a store would refuse every helper it
    // converted — which is all of them.
    let scheduled: std::collections::HashSet<ValueId> =
        func.blocks.iter().flat_map(|(_, b)| b.bindings.iter().copied()).collect();
    for (id, b) in func.bindings.iter() {
        if let Expr::Literal(lit) = &b.expr {
            if let Some(n) = literal_int(lit) {
                s.literals.insert(n);
            }
            continue;
        }
        if !scheduled.contains(&id) {
            continue;
        }
        match &b.expr {
            Expr::Call { target, .. } => {
                s.calls.insert(*target);
            }
            Expr::IndirectCall { .. } | Expr::Semantic(_) => s.host = true,
            Expr::Unary { op: UnaryOp::Clz, .. } => s.clz += 1,
            Expr::Binary { op: BinaryOp::Mul, .. } => s.muls += 1,
            Expr::Binary { op: BinaryOp::BitXor, .. } => s.xors += 1,
            Expr::Binary { op: BinaryOp::Shl | BinaryOp::Shr, .. } => s.shifts += 1,
            Expr::Binary { op: BinaryOp::Sub, lhs, .. }
                if matches!(
                    func.bindings.get(resolve_use(func, *lhs)).map(|b| &b.expr),
                    Some(Expr::Literal(Literal::I32(0) | Literal::I64(0)))
                ) =>
            {
                s.negations += 1;
            }
            Expr::Store { .. } => s.stores += 1,
            Expr::Project { value, index } => {
                if let Some(Expr::Call { target, .. }) =
                    func.bindings.get(resolve_use(func, *value)).map(|b| &b.expr)
                {
                    s.projections.entry(*target).or_default().insert(*index);
                }
            }
            _ => {}
        }
    }
    s
}

/// Every function that is one of the runtime helpers.
///
/// Leaves first (the multiply and the shifts call nothing), then the
/// helpers whose call sets must close over the leaves. Each gate is the
/// conjunction described in the module docs; a body failing any clause is
/// simply not a builtin.
fn identify(ir: &HighIr) -> HashMap<FuncId, Builtin> {
    let shapes: Vec<(FuncId, Shape)> = ir.functions.iter().map(|f| (f.id, shape_of(f))).collect();
    let mut found: HashMap<FuncId, Builtin> = HashMap::new();

    for (id, s) in &shapes {
        if s.host || !s.calls.is_empty() || s.stores > 0 {
            continue;
        }
        if s.params == 4
            && s.ret_arity == Some(2)
            && s.muls >= 4
            && s.literals.contains(&32)
            && s.literals.contains(&0xFFFF_FFFF)
        {
            found.insert(*id, Builtin::Multi3);
        } else if s.params == 3
            && s.ret_arity == Some(2)
            && s.shifts >= 3
            && s.literals.contains(&64)
            // `63 - n` in one build, `0 - n` (the same count mod 64) in
            // another: rustc 1.97's `__lshrti3` has no 63 at all.
            && (s.literals.contains(&63) || s.negations >= 1)
        {
            found.insert(*id, Builtin::Shift);
        }
    }

    let is = |found: &HashMap<FuncId, Builtin>, id: &FuncId, want: Builtin| {
        found.get(id).is_some_and(|k| *k == want)
    };

    for (id, s) in &shapes {
        if s.host || s.params != 4 || !s.ret_arity.is_some_and(|n| n >= 2) || s.clz < 2 {
            continue;
        }
        if !s.literals.contains(&63) || !s.literals.contains(&64) {
            continue;
        }
        if s.calls.iter().all(|c| is(&found, c, Builtin::Multi3) || is(&found, c, Builtin::Shift)) {
            found.insert(*id, Builtin::Udivmodti4);
        }
    }

    for (id, s) in &shapes {
        if s.host || s.ret_arity != Some(2) || s.calls.len() != 1 {
            continue;
        }
        let callee = *s.calls.iter().next().expect("one call");
        if s.params == 5 && is(&found, &callee, Builtin::Multi3) && s.stores >= 1 && s.xors >= 1 {
            found.insert(*id, Builtin::Muloti4);
        } else if s.params == 4 && is(&found, &callee, Builtin::Udivmodti4) {
            // Quotient limbs are components 0/1 of the divmod result,
            // remainder limbs 2/3; which the wrapper reads says whether it
            // is the divide or the modulo. The sign fix-up is what makes
            // it the signed variant.
            let reads = s.projections.get(&callee);
            let op = if reads.is_some_and(|r| r.contains(&2) || r.contains(&3)) {
                BinaryOp::Rem
            } else {
                BinaryOp::Div
            };
            let kind = if s.xors >= 1 { Builtin::Signed(op) } else { Builtin::Unsigned(op) };
            found.insert(*id, kind);
        }
    }
    found
}

/// The integer a literal holds, for the constant scan.
fn literal_int(lit: &Literal) -> Option<i128> {
    match lit {
        Literal::I32(n) => Some(i128::from(*n)),
        Literal::I64(n) => Some(i128::from(*n)),
        Literal::U32(n) => Some(i128::from(*n)),
        Literal::U64(n) => Some(i128::from(*n)),
        _ => None,
    }
}

// ---------------------------------------------------------------------
// Rewriting
// ---------------------------------------------------------------------

/// Rewrite one call site. Returns whether anything changed.
fn rewrite_site(func: &mut HighFunction, call: ValueId, kind: Builtin) -> bool {
    let Some(Expr::Call { args, .. }) = func.bindings.get(call).map(|b| b.expr.clone()) else {
        return false;
    };
    let (op, wide, flag_ptr) = match kind {
        Builtin::Multi3 if args.len() >= 4 => (BinaryOp::Mul, KnownType::I128, None),
        Builtin::Muloti4 if args.len() >= 5 => (BinaryOp::Mul, KnownType::I128, Some(args[4])),
        Builtin::Signed(op) if args.len() >= 4 => (op, KnownType::I128, None),
        Builtin::Unsigned(op) if args.len() >= 4 => (op, KnownType::U128, None),
        // The divmod itself, called directly: a `u128` `/` or `%` whose
        // wrapper rustc inlined. Quotient components only; a remainder
        // reader would need both results, which is not seen yet.
        Builtin::Udivmodti4 if args.len() >= 4 => (BinaryOp::Div, KnownType::U128, None),
        _ => return false,
    };
    let (a_lo, a_hi, b_lo, b_hi) = (args[0], args[1], args[2], args[3]);

    // A remainder reader of a plain divide (or vice versa) is a shape this
    // pass does not claim to understand; leave the call.
    let projections: Vec<(ValueId, u32)> = func
        .bindings
        .iter()
        .filter_map(|(id, b)| match &b.expr {
            Expr::Project { value, index } if resolve_use(func, *value) == call => Some((id, *index)),
            _ => None,
        })
        .collect();
    if projections.iter().any(|(_, i)| *i > 1) {
        return false;
    }

    let wide_ty = IrType::Inferred(wide);
    let ja = push(func, Expr::WideJoin { lo: a_lo, hi: a_hi }, wide_ty.clone(), "left operand, joined from its limbs");
    let jb = push(func, Expr::WideJoin { lo: b_lo, hi: b_hi }, wide_ty.clone(), "right operand, joined from its limbs");
    let result = push(
        func,
        Expr::Binary { op, lhs: ja, rhs: jb },
        wide_ty,
        "128-bit arithmetic the runtime helper computed",
    );
    let mut fresh = vec![ja, jb, result];
    let overflow = flag_ptr.map(|_| {
        let ov = push(
            func,
            Expr::Binary { op: BinaryOp::MulOverflows, lhs: ja, rhs: jb },
            IrType::Inferred(KnownType::Bool),
            "the overflow flag the helper wrote through its pointer",
        );
        fresh.push(ov);
        ov
    });
    schedule_before(func, call, &fresh);

    for (id, index) in projections {
        let op = if index == 0 { UnaryOp::WideLo } else { UnaryOp::WideHi };
        if let Some(b) = func.bindings.get_mut(id) {
            b.expr = Expr::Unary { op, value: result };
            b.ty = IrType::Inferred(KnownType::I64);
            b.add_provenance(Provenance::new(
                PASS_NAME,
                ProvenanceSource::SdkPattern,
                "limb of the recovered 128-bit result",
            ));
        }
    }
    if let (Some(ptr), Some(ov)) = (flag_ptr, overflow) {
        for load in flag_loads(func, call, ptr) {
            if let Some(b) = func.bindings.get_mut(load) {
                b.expr = Expr::Use(ov);
                b.ty = IrType::Inferred(KnownType::Bool);
                b.add_provenance(Provenance::new(
                    PASS_NAME,
                    ProvenanceSource::SdkPattern,
                    "overflow flag read back from the helper's out-pointer",
                ));
            }
        }
    }
    if let Some(b) = func.bindings.get_mut(call) {
        b.expr = Expr::Literal(Literal::Unit);
        b.add_provenance(Provenance::new(
            PASS_NAME,
            ProvenanceSource::SdkPattern,
            format!("compiler_builtins::{} call, recovered as arithmetic", kind.symbol()),
        ));
    }
    true
}

/// Append a binding to the arena; the caller schedules it.
fn push(func: &mut HighFunction, expr: Expr, ty: IrType, note: &str) -> ValueId {
    let id = ValueId::from_index(func.bindings.len() as u32);
    func.bindings.push(Binding::new(
        id,
        ty,
        expr,
        Provenance::new(PASS_NAME, ProvenanceSource::SdkPattern, note),
    ));
    id
}

/// Schedule `fresh` immediately before `anchor` in whichever block holds
/// it. Same-block placement keeps the dominance the validator checks:
/// the operands are the call's own arguments, defined before it.
fn schedule_before(func: &mut HighFunction, anchor: ValueId, fresh: &[ValueId]) {
    for (_, block) in func.blocks.iter_mut() {
        if let Some(pos) = block.bindings.iter().position(|v| *v == anchor) {
            for (k, id) in fresh.iter().enumerate() {
                block.bindings.insert(pos + k, *id);
            }
            return;
        }
    }
}

/// The loads that read the overflow flag back through `ptr`.
///
/// Same block, after the call, and before any later call that passes the
/// same pointer — a frame slot is reused freely, and the flag a load reads
/// is the one the most recent writer left. A load elsewhere is taken only
/// when it is the sole such load in the function, so there is nothing to
/// confuse it with.
fn flag_loads(func: &HighFunction, call: ValueId, ptr: ValueId) -> Vec<ValueId> {
    let slot = canon_addr(func, ptr, 0);
    let reads_flag = |id: ValueId| match &func.bindings.get(id).map(|b| &b.expr) {
        Some(Expr::Load { addr, offset, .. }) => canon_addr(func, *addr, *offset) == slot,
        _ => false,
    };
    let passes_ptr = |id: ValueId| match &func.bindings.get(id).map(|b| &b.expr) {
        Some(Expr::Call { args, .. }) => args.iter().any(|a| canon_addr(func, *a, 0) == slot),
        _ => false,
    };
    let mut found = Vec::new();
    for (_, block) in func.blocks.iter() {
        let Some(pos) = block.bindings.iter().position(|v| *v == call) else {
            continue;
        };
        for id in &block.bindings[pos + 1..] {
            if passes_ptr(*id) {
                break;
            }
            if reads_flag(*id) {
                found.push(*id);
            }
        }
        break;
    }
    if found.is_empty() {
        let all: Vec<ValueId> = func.bindings.iter().map(|(id, _)| id).filter(|id| reads_flag(*id)).collect();
        if all.len() == 1 {
            found = all;
        }
    }
    found
}

/// `(base, byte offset)` for an address, so `add fp, 220` passed as an
/// argument and `load fp offset=220` name the same slot. Only a constant
/// added to a base folds; anything else is its own base.
fn canon_addr(func: &HighFunction, addr: ValueId, offset: u32) -> (ValueId, i128) {
    let addr = resolve_use(func, addr);
    if let Some(Expr::Binary { op: BinaryOp::Add, lhs, rhs }) = func.bindings.get(addr).map(|b| &b.expr) {
        if let Some(n) = crate::dataflow::trace_int(func, *rhs) {
            return (resolve_use(func, *lhs), n + i128::from(offset));
        }
        if let Some(n) = crate::dataflow::trace_int(func, *lhs) {
            return (resolve_use(func, *rhs), n + i128::from(offset));
        }
    }
    (addr, i128::from(offset))
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use sordec_common::{Arena, BlockId, UnknownReason};
    use sordec_ir::{HighBlock, MemWidth, MemoryImage, Region, WasmFacts};

    pub(crate) fn v(i: u32) -> ValueId {
        ValueId::from_index(i)
    }

    fn lit(n: i64) -> Expr {
        Expr::Literal(Literal::I64(n))
    }

    /// A function with `n_params` leading params, then `exprs`, all in one
    /// block; every return site returns the last `ret` bindings.
    pub(crate) fn function(id: u32, n_params: usize, exprs: Vec<Expr>) -> HighFunction {
        function_returning(id, n_params, exprs, 0)
    }

    pub(crate) fn function_returning(
        id: u32,
        n_params: usize,
        exprs: Vec<Expr>,
        ret: usize,
    ) -> HighFunction {
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        let mut params = Vec::new();
        let mut scheduled = Vec::new();
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
            scheduled.push(vid);
        }
        let returns = if ret == 0 {
            vec![]
        } else {
            vec![scheduled[scheduled.len() - ret..].to_vec()]
        };
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        blocks.push(HighBlock { id: BlockId::from_index(0), bindings: scheduled });
        HighFunction {
            id: FuncId::from_index(id),
            name: None,
            signature: None,
            aliases: Vec::new(),
            blocks,
            bindings,
            region: Region::Basic(BlockId::from_index(0)),
            params,
            returns,
        }
    }

    pub(crate) fn ir(functions: Vec<HighFunction>) -> HighIr {
        HighIr {
            facts: WasmFacts {
                imports: vec![],
                exports: vec![],
                function_type_indices: vec![],
                function_bodies: vec![],
                function_fingerprints: vec![],
                custom_sections: vec![],
            },
            soroban_facts: None,
            functions,
            memory: MemoryImage::empty(),
        }
    }

    /// A `__multi3` silhouette: four params, the limb split constants,
    /// four partial products, two results.
    fn multi3(id: u32) -> HighFunction {
        let mul = |a, b| Expr::Binary { op: BinaryOp::Mul, lhs: v(a), rhs: v(b) };
        function_returning(
            id,
            4,
            vec![
                lit(32),
                lit(0xFFFF_FFFF),
                mul(0, 2),
                mul(0, 3),
                mul(1, 2),
                mul(1, 3),
                Expr::Binary { op: BinaryOp::Add, lhs: v(6), rhs: v(7) },
                Expr::Binary { op: BinaryOp::Add, lhs: v(8), rhs: v(9) },
            ],
            2,
        )
    }

    /// A `__muloti4` silhouette: five params, calls the multiply, xors the
    /// signs, stores the flag through the last param, two results.
    fn muloti4(id: u32, multi: u32) -> HighFunction {
        function_returning(
            id,
            5,
            vec![
                lit(0),
                lit(1),
                Expr::Binary { op: BinaryOp::BitXor, lhs: v(1), rhs: v(3) },
                Expr::Call { target: FuncId::from_index(multi), args: vec![v(0), v(1), v(2), v(3)] },
                Expr::Project { value: v(8), index: 0 },
                Expr::Project { value: v(8), index: 1 },
                Expr::Store { addr: v(4), value: v(6), offset: 0, width: MemWidth::W1 },
            ],
            2,
        )
        .with_returns(vec![vec![v(9), v(10)]])
    }

    trait WithReturns {
        fn with_returns(self, r: Vec<Vec<ValueId>>) -> Self;
    }
    impl WithReturns for HighFunction {
        fn with_returns(mut self, r: Vec<Vec<ValueId>>) -> Self {
            self.returns = r;
            self
        }
    }

    /// A caller: limbs in v0..v3, a flag slot address in v4, the call,
    /// its two projections, the flag load, and a use of each.
    fn caller(id: u32, target: u32, with_flag: bool) -> HighFunction {
        let mut args = vec![v(0), v(1), v(2), v(3)];
        if with_flag {
            args.push(v(4));
        }
        function(
            id,
            5,
            vec![
                Expr::Call { target: FuncId::from_index(target), args },
                Expr::Project { value: v(5), index: 0 },
                Expr::Project { value: v(5), index: 1 },
                Expr::Load { addr: v(4), offset: 0, width: MemWidth::W1, signed: None, ty: IrType::Unknown(UnknownReason::InsufficientEvidence) },
            ],
        )
    }

    fn expr_at(ir: &HighIr, func: u32, value: u32) -> &Expr {
        &ir.function(FuncId::from_index(func)).unwrap().bindings.get(v(value)).unwrap().expr
    }

    /// A `__lshrti3` silhouette as rustc 1.97 builds it: limbs in v0/v1, the
    /// count in v2, the complementary count spelled `0 - n` (wasm shifts
    /// mod 64) where older builds wrote `63 - n`.
    fn lshr_without_63(id: u32) -> HighFunction {
        let bin = |op, a, b| Expr::Binary { op, lhs: v(a), rhs: v(b) };
        function_returning(
            id,
            3,
            vec![
                lit(64),                       // v3
                lit(0),                        // v4
                bin(BinaryOp::Sub, 4, 2),      // v5: 0 - n
                bin(BinaryOp::Shl, 1, 5),      // v6
                bin(BinaryOp::Shr, 0, 2),      // v7
                bin(BinaryOp::BitOr, 6, 7),    // v8
                bin(BinaryOp::Shr, 1, 2),      // v9
            ],
            2,
        )
    }

    #[test]
    fn a_shift_helper_spelling_the_complement_as_a_negation_is_identified() {
        let m = ir(vec![lshr_without_63(0)]);
        assert_eq!(identify(&m).get(&FuncId::from_index(0)), Some(&Builtin::Shift));
    }

    /// Neither `63` nor a negation: three shifts and a `64` alone are not
    /// the helper.
    #[test]
    fn a_shift_helper_needs_its_complementary_count() {
        let mut f = lshr_without_63(0);
        f.bindings.get_mut(v(5)).unwrap().expr =
            Expr::Binary { op: BinaryOp::Add, lhs: v(4), rhs: v(2) };
        assert!(identify(&ir(vec![f])).is_empty());
    }

    #[test]
    fn the_multiply_helper_is_identified_by_shape() {
        let m = ir(vec![multi3(0)]);
        let found = identify(&m);
        assert_eq!(found.get(&FuncId::from_index(0)), Some(&Builtin::Multi3));
    }

    /// Without the limb-split constants it is just a function with four
    /// multiplies in it.
    #[test]
    fn a_multiply_without_the_limb_split_is_not_the_helper() {
        let mut f = multi3(0);
        f.bindings.get_mut(v(5)).unwrap().expr = lit(7);
        let m = ir(vec![f]);
        assert!(identify(&m).is_empty());
    }

    #[test]
    fn a_body_touching_the_host_is_never_a_builtin() {
        let mut f = multi3(0);
        f.bindings.get_mut(v(4)).unwrap().expr = Expr::Semantic(sordec_ir::SemanticOp::Unknown {
            host_module: "l".into(),
            host_fn: "_".into(),
            reason: UnknownReason::InsufficientEvidence,
            args: vec![],
        });
        let m = ir(vec![f]);
        assert!(identify(&m).is_empty());
    }

    #[test]
    fn a_multiply_call_becomes_a_product_over_joined_limbs() {
        let mut m = ir(vec![multi3(0), caller(1, 0, false)]);
        let r = I128BuiltinPass.run(&mut m);
        assert!(r.changed);
        assert_eq!(r.metrics.get(M_REWRITTEN), Some(1));

        // The call is gone; the projections are limbs of a product.
        assert!(matches!(expr_at(&m, 1, 5), Expr::Literal(Literal::Unit)));
        let Expr::Unary { op: UnaryOp::WideLo, value: p } = expr_at(&m, 1, 6) else {
            panic!("low projection should be a low limb");
        };
        assert!(matches!(expr_at(&m, 1, 7), Expr::Unary { op: UnaryOp::WideHi, value } if value == p));
        let Expr::Binary { op: BinaryOp::Mul, lhs, rhs } = expr_at(&m, 1, p.index()) else {
            panic!("the product should be a multiply");
        };
        assert!(matches!(expr_at(&m, 1, lhs.index()), Expr::WideJoin { lo, hi } if *lo == v(0) && *hi == v(1)));
        assert!(matches!(expr_at(&m, 1, rhs.index()), Expr::WideJoin { lo, hi } if *lo == v(2) && *hi == v(3)));

        // The fresh bindings are scheduled ahead of the (now dead) call.
        let block = &m.functions[1].blocks.get(BlockId::from_index(0)).unwrap().bindings;
        let call_pos = block.iter().position(|x| *x == v(5)).unwrap();
        assert!(block[..call_pos].contains(p), "product must be scheduled before its former call");
    }

    #[test]
    fn the_overflow_helper_yields_a_product_and_a_flag() {
        let mut m = ir(vec![multi3(0), muloti4(1, 0), caller(2, 1, true)]);
        let r = I128BuiltinPass.run(&mut m);
        assert_eq!(r.metrics.get(M_IDENTIFIED), Some(2));
        // The caller's flag load now reads the overflow test.
        let Expr::Use(flag) = expr_at(&m, 2, 8) else {
            panic!("flag load should be replaced");
        };
        assert!(matches!(expr_at(&m, 2, flag.index()), Expr::Binary { op: BinaryOp::MulOverflows, .. }));
        assert!(matches!(m.functions[2].bindings.get(*flag).unwrap().ty, IrType::Inferred(KnownType::Bool)));
    }

    /// Sites inside the helpers themselves are left alone — the bodies
    /// become unreachable, and rewriting them is work nobody prints.
    #[test]
    fn calls_inside_a_builtin_are_not_rewritten() {
        let mut m = ir(vec![multi3(0), muloti4(1, 0)]);
        let r = I128BuiltinPass.run(&mut m);
        assert!(!r.changed);
        assert!(matches!(expr_at(&m, 1, 8), Expr::Call { .. }));
    }

    #[test]
    fn the_pass_is_idempotent() {
        let mut m = ir(vec![multi3(0), caller(1, 0, false)]);
        assert!(I128BuiltinPass.run(&mut m).changed);
        assert!(!I128BuiltinPass.run(&mut m).changed);
    }
}
