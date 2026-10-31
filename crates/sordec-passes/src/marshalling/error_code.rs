//! An entrypoint's `Err` whose error code is only known at run time.
//!
//! # The shape
//!
//! A helper returning `Result<T, E>` hands its error to the entrypoint as a
//! 32-bit code — the discriminant of the `#[contracterror]` value it built —
//! and the entrypoint's `?` passes it on. On the way out the SDK turns the
//! code into the `Error` `Val` the host reads, and since the code is not a
//! constant on every path, rustc builds the `Val` with arithmetic:
//!
//! ```text
//! c = phi [load fp+112, load fp+116, 5, 5, 6]     ← the codes, path by path
//! r = (((c - 1) as u32 as u64) << 32) + Error(1)  ← the `Val` of code `c`
//! ret = phi [r, ok]
//! return ret
//! ```
//!
//! `Error(1)` is the constant `Error` `Val` of contract code `1`, which the
//! error-constant recognizer has already named as a variant. Left as it is,
//! the reconstruction adds an `Error` to an integer.
//!
//! # The rewrite
//!
//! `r` becomes `c`, the error itself: each constant code among `c`'s arms
//! becomes the declared error variant it is, and each word read from memory
//! is read as the declared error type. The emitter then returns `Err(c)`.
//!
//! ```text
//! c = phi [load fp+112 : E, load fp+116 : E, E::ProposalClosed, …]
//! ret = phi [Err(c), Ok(..)]
//! ```
//!
//! # Why it is exact
//!
//! The arithmetic. An `Error` `Val` of contract code `k` is `(k << 32) | 3`:
//! tag `3`, error type `Contract` (zero) in the minor field, the code in
//! the top 32 bits. `((c + k0) mod 2^32) << 32` has its low 32 bits zero,
//! so adding `(k << 32) | 3` never reaches the tag and wraps the top 32
//! bits: the sum is `(((c + k0 + k) mod 2^32) << 32) | 3`, which with
//! `k0 + k ≡ 0 (mod 2^32)` is `(c << 32) | 3` — the `Error` of contract
//! code `c`, for every `c`. The same holds for `(c << 32) | 3` written
//! with an `or`.
//!
//! The boundary. That value reaches nothing but the entrypoint's return,
//! and the spec declares the entrypoint returns `Result<T, E>`. The SDK's
//! wrapper returns `result.into_val(..)` for such an entrypoint, and an
//! `Err(e)` converts to `Error::from_contract_error(e as u32)`: the same
//! word exactly when `e`'s discriminant is `c`. So the path returned
//! `Err(e)` with `e` the `E` whose discriminant is `c`:
//!
//! - where `c` is a constant, the variant declaring that code — refused
//!   when `E` declares none, since then no `E` has that encoding; with the
//!   SDK's own `Error` as `E`, `Error::from_contract_error(c)`;
//! - where `c` is a 4-byte word read from memory, that word *is* the
//!   discriminant of the `E` the helper wrote there: a `#[contracterror]`
//!   enum is `#[repr(u32)]`, and the SDK converts it by that discriminant.
//!   The read is typed `E`; its value is still the read, unchanged.
//!
//! # A helper on the way out
//!
//! The same arithmetic sits in the helper rustc outlines the SDK's
//! `Result` conversion into, when the entrypoint returns what the helper
//! returns: `func30(p)` reads a `Result<i128, E>` its caller wrote into a
//! frame — the tag word, the code word, the `i128` — and builds the
//! `Error` `Val` of the code it reads on one side. The helper's word is
//! the entrypoint's word, so the helper's `Err` side is rewritten exactly
//! as an entrypoint's would be, against the `Result<T, E>` the entrypoint
//! at the top of the chain declares ([`declared_result`]).
//!
//! Why it is exact: every caller of the helper does nothing with its
//! result but return it, up to an entrypoint whose spec declares
//! `Result<T, E>`; so the helper's returned word reaches the host as that
//! entrypoint's, and the boundary argument above holds for it word for
//! word. The helper comes to return the `Result` (its other side is the
//! `T` the emitter wraps as `Ok`), so its callers must be all of them.
//!
//! # Gates
//!
//! - **The entrypoint**: a spec signature returning one `Result<T, E>`,
//!   `E` a declared `#[contracterror]` enum or the SDK's `Error`. Or a
//!   helper (no spec, not exported) every direct caller of which only
//!   returns its result, up to [`CHAIN_DEPTH`] calls to such an
//!   entrypoint, all agreeing on one `Result`; and no indirect call may
//!   reach it ([`CallIndex::caller_set_complete`]).
//! - **The value**: the sum above, `k0 + k ≡ 0 (mod 2^32)`, flowing only
//!   into the return — read by nothing but merges that themselves flow
//!   only there, and the return.
//! - **The code**: `c` and the merges behind it are read by nothing but
//!   the arithmetic above and each other; every arm is a constant, or a
//!   4-byte read from memory, or a value already typed `E`. Anything
//!   computed is refused: the code would then be a number, not an `E`.
//!
//! An arm something else reads too is not retyped where it stands. The
//! same word is often the error on one path and a field of the `Ok` value
//! on the other — a helper's `Result` in memory, its first word read once
//! before the branch on its tag. So the arm is read again, right after
//! itself, at the declared type: a second read of the same address with
//! nothing between, the same word; or, for a constant, the variant
//! itself. The merge takes the new arm; every other reader keeps the old.

use std::collections::{HashMap, HashSet};

use sordec_common::{FuncId, IrId, Provenance, ProvenanceSource, TypeId, ValueId};
use sordec_ir::{
    BinaryOp, Binding, ErrorVariant, Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Literal, MemWidth, Region,
    SemanticOp, TypeRegistry, UnaryOp,
};

use super::result_out::declared_result;
use super::sret::emission_order;
use crate::dataflow::{resolve_use, trace_int, CallIndex};
use crate::metrics_catalog::MARSHALLING_ERROR_CODES_RETURNED as M_RETURNED;
use crate::pass::{Pass, PassResult};
use crate::val_abi;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-error-code";

/// How many helper calls a returned value may climb to reach an entrypoint
/// ([`declared_result`]).
const CHAIN_DEPTH: usize = 4;

/// Returns the error a run-time code names as the entrypoint's `Err`.
#[derive(Debug, Default, Clone, Copy)]
pub struct ErrorCodeReturnPass;

impl Pass<HighIr> for ErrorCodeReturnPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let Some(reg) = ir.soroban_facts.as_ref().map(|f| f.types.clone()) else {
            return result;
        };
        // Each function's declared `Result`: its own spec's, or — for a
        // helper whose result every caller only returns — the one the
        // entrypoint at the top of that chain declares.
        let calls = CallIndex::build(ir);
        let declared: HashMap<FuncId, Declared> = ir
            .functions
            .iter()
            .filter_map(|f| {
                let ty = declared_result(ir, &calls, f.id, CHAIN_DEPTH)?;
                Some((f.id, declared_error(&ty, &reg)?))
            })
            .collect();
        for func in &mut ir.functions {
            let Some(declared) = declared.get(&func.id).cloned() else {
                continue;
            };
            let plans = plan(func, &declared);
            for plan in plans {
                apply(func, &declared, plan);
                result.metrics.increment(M_RETURNED, 1);
                result.changed = true;
            }
        }
        result
    }
}

/// The `E` an entrypoint's `Result<T, E>` names, as the reconstruction
/// spells it.
#[derive(Debug, Clone)]
struct Declared {
    /// The type an `E` value is given: the declared enum, or `Error`.
    ty: KnownType,
    /// The declared enum's `(name, cases)`, or `None` for the SDK's `Error`.
    cases: Option<(String, Vec<(String, u32)>)>,
}

impl Declared {
    /// The constant of contract code `code`, or `None` when `E` declares no
    /// variant with it.
    fn constant(&self, code: u32) -> Option<Expr> {
        let resolved = match &self.cases {
            Some((enum_name, cases)) => {
                let (variant, _) = cases.iter().find(|(_, value)| *value == code)?;
                Some(ErrorVariant { enum_name: enum_name.clone(), variant: variant.clone() })
            }
            None => None,
        };
        Some(Expr::Semantic(SemanticOp::Known(KnownOp::MakeError { code, resolved })))
    }
}

fn declared_error(result: &KnownType, reg: &TypeRegistry) -> Option<Declared> {
    let KnownType::Result(_, err) = result else {
        return None;
    };
    let by_id = |id: TypeId| {
        let def = reg.errors.iter().find(|d| d.id == id)?;
        Some(Declared {
            ty: KnownType::UserDefined(id),
            cases: Some((def.name.clone(), def.cases.iter().map(|c| (c.name.clone(), c.value)).collect())),
        })
    };
    match **err {
        IrType::Known(KnownType::UserDefined(id)) | IrType::Inferred(KnownType::UserDefined(id)) => by_id(id),
        // The spec erases a `#[contracterror]` enum to `Error`; the
        // reconstruction names it back when the contract declares exactly
        // one (the emitter's `result_error`), and then `E` is that enum.
        IrType::Known(KnownType::Error) | IrType::Inferred(KnownType::Error) => match reg.sole_error_enum() {
            Some(name) => by_id(reg.errors.iter().find(|d| d.name == name)?.id),
            None if reg.errors.is_empty() => Some(Declared { ty: KnownType::Error, cases: None }),
            None => None,
        },
        _ => None,
    }
}

/// One returned error to rewrite.
#[derive(Debug)]
struct Plan {
    /// The arithmetic building the `Error` `Val`.
    value: ValueId,
    /// The constant `Error` `Val` it adds, when nothing else reads it.
    addend: Option<ValueId>,
    /// The code.
    code: ValueId,
    /// The merges behind the code.
    merges: Vec<ValueId>,
    /// The constant arms, with their codes.
    constants: Vec<(ValueId, u32)>,
    /// The arms read from memory.
    reads: Vec<ValueId>,
    /// The arms something else reads too, read again for the merge.
    shared: HashSet<ValueId>,
}

fn plan(func: &HighFunction, declared: &Declared) -> Vec<Plan> {
    let order = emission_order(func);
    let phis: Vec<ValueId> =
        func.bindings.iter().filter(|(_, b)| matches!(b.expr, Expr::Phi { .. })).map(|(id, _)| id).collect();
    let live: Vec<ValueId> = order.iter().chain(&phis).copied().collect();
    // Who reads `v`: live bindings, and whether the region reads it other
    // than to return it or hand it to a merge (a condition, an index).
    let readers = |v: ValueId| -> (Vec<ValueId>, bool) {
        let mut by = Vec::new();
        for &id in &live {
            let mut reads = false;
            if let Some(b) = func.bindings.get(id) {
                b.expr.for_each_value_use(|u| reads |= u == v);
            }
            if reads {
                by.push(id);
            }
        }
        let mut other = false;
        func.region.for_each_node(|node| match node {
            Region::If { cond, .. } => other |= *cond == v,
            Region::Switch { index, .. } => other |= *index == v,
            _ => {}
        });
        (by, other)
    };

    // The values that flow only into the return: the returned values, and
    // the arms of the merges among them.
    let mut returned: HashSet<ValueId> = HashSet::new();
    func.region.for_each_node(|node| {
        if let Region::Return { values } = node
            && let [one] = values.as_slice()
        {
            returned.insert(resolve_use(func, *one));
        }
    });
    let mut grew = true;
    while grew {
        grew = false;
        for id in returned.clone() {
            if let Some(Expr::Phi { incoming }) = func.bindings.get(id).map(|b| &b.expr) {
                for (_, a) in incoming {
                    grew |= returned.insert(resolve_use(func, *a));
                }
            }
        }
    }
    let flows_only_out = |v: ValueId| {
        let (by, other) = readers(v);
        !other
            && by.iter().all(|r| {
                returned.contains(r)
                    && matches!(func.bindings.get(*r).map(|b| &b.expr), Some(Expr::Phi { .. } | Expr::Use(_)))
            })
    };

    let mut plans = Vec::new();
    let mut ids: Vec<ValueId> = returned.iter().copied().collect();
    ids.sort_unstable();
    for value in ids {
        let Some((word_reader, code, addend)) = error_of_code(func, value) else {
            continue;
        };
        if !flows_only_out(value) {
            continue;
        }
        // The addend goes with the arithmetic when nothing else reads it.
        let addend = addend.filter(|a| readers(*a).0.iter().all(|r| *r == value) && !readers(*a).1);
        let Some(arms) = code_arms(func, code, word_reader, &readers) else {
            continue;
        };
        // An arm read again must be scheduled, to be read again after it.
        if arms.shared.iter().any(|a| crate::dataflow::block_containing(func, *a).is_none()) {
            continue;
        }
        let mut ok = true;
        let mut constants = Vec::new();
        let mut reads = Vec::new();
        for arm in arms.leaves {
            let b = func.bindings.get(arm);
            match b.map(|b| (&b.expr, &b.ty)) {
                Some((Expr::Literal(Literal::I32(n)), _)) => match declared.constant(*n as u32) {
                    Some(_) => constants.push((arm, *n as u32)),
                    None => ok = false,
                },
                Some((Expr::Literal(Literal::U32(n)), _)) => match declared.constant(*n) {
                    Some(_) => constants.push((arm, *n)),
                    None => ok = false,
                },
                Some((Expr::Load { width: MemWidth::W4, .. }, _)) => reads.push(arm),
                Some((_, IrType::Known(k) | IrType::Inferred(k))) if *k == declared.ty => {}
                _ => ok = false,
            }
        }
        if !ok {
            continue;
        }
        plans.push(Plan { value, addend, code, merges: arms.merges, constants, reads, shared: arms.shared });
    }
    plans
}

/// `(c + k0) as u32 as u64 << 32` plus the constant `Error` `Val` of code
/// `k`, `k0 + k ≡ 0 (mod 2^32)` — or `(c as u32 as u64) << 32 | 3`. Returns
/// the binding that reads `c`, `c`, and the constant's binding.
fn error_of_code(func: &HighFunction, value: ValueId) -> Option<(ValueId, ValueId, Option<ValueId>)> {
    let expr_of = |v: ValueId| func.bindings.get(resolve_use(func, v)).map(|b| &b.expr);
    let (op, lhs, rhs) = match expr_of(value)? {
        Expr::Binary { op: op @ (BinaryOp::Add | BinaryOp::BitOr), lhs, rhs } => (*op, *lhs, *rhs),
        _ => return None,
    };
    [(lhs, rhs), (rhs, lhs)].into_iter().find_map(|(shifted, constant)| {
        let k = contract_error_code(func, constant)?;
        let Expr::Binary { op: BinaryOp::Shl, lhs: widened, rhs: by } = expr_of(shifted)? else {
            return None;
        };
        if trace_int(func, *by) != Some(32) {
            return None;
        }
        let Expr::Unary { op: UnaryOp::ExtendU32, value: word } = expr_of(*widened)? else {
            return None;
        };
        let word = resolve_use(func, *word);
        let (reader, code, k0) = match &func.bindings.get(word)?.expr {
            Expr::Binary { op: BinaryOp::Add, lhs, rhs } => [(*lhs, *rhs), (*rhs, *lhs)]
                .into_iter()
                .find_map(|(c, n)| Some((word, resolve_use(func, c), trace_int(func, n)?)))?,
            _ => (resolve_use(func, *widened), word, 0),
        };
        // `|` adds only where the bits do not overlap: the code `0`'s `3`.
        if op == BinaryOp::BitOr && (k0 != 0 || k != 0) {
            return None;
        }
        if (k0 + i128::from(k)).rem_euclid(1 << 32) != 0 {
            return None;
        }
        let addend = resolve_use(func, constant);
        let named = matches!(
            func.bindings.get(addend).map(|b| &b.expr),
            Some(Expr::Semantic(SemanticOp::Known(KnownOp::MakeError { .. })) | Expr::Literal(_))
        );
        Some((reader, code, named.then_some(addend)))
    })
}

/// The contract code of a constant `Error` `Val`: a recognised one, or a
/// literal whose bits decode as a `Contract`-type error.
fn contract_error_code(func: &HighFunction, value: ValueId) -> Option<u32> {
    match &func.bindings.get(resolve_use(func, value))?.expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::MakeError { code, .. })) => Some(*code),
        Expr::Literal(Literal::I64(n)) => val_abi::decode_contract_error(*n as u64),
        Expr::Literal(Literal::U64(n)) => val_abi::decode_contract_error(*n),
        _ => None,
    }
}

/// The code's arms: the merges behind `code`, the values they merge, and
/// which of those something else reads too.
struct Arms {
    merges: Vec<ValueId>,
    leaves: Vec<ValueId>,
    shared: HashSet<ValueId>,
}

/// Walk `code` through merges, each read by nothing but `reader` (the
/// arithmetic) or another of them. A leaf read by anything else is
/// `shared`.
fn code_arms(
    func: &HighFunction,
    code: ValueId,
    reader: ValueId,
    readers: &dyn Fn(ValueId) -> (Vec<ValueId>, bool),
) -> Option<Arms> {
    let mut merges: Vec<ValueId> = Vec::new();
    let mut leaves: Vec<ValueId> = Vec::new();
    let mut stack = vec![code];
    let mut seen: HashSet<ValueId> = HashSet::new();
    while let Some(v) = stack.pop() {
        let v = resolve_use(func, v);
        if !seen.insert(v) {
            continue;
        }
        match &func.bindings.get(v)?.expr {
            Expr::Phi { incoming } if !incoming.is_empty() => {
                merges.push(v);
                stack.extend(incoming.iter().map(|(_, a)| *a));
            }
            Expr::Phi { .. } => return None, // a parameter: a number, not an `E`
            _ => leaves.push(v),
        }
        if merges.len() + leaves.len() > 64 {
            return None;
        }
    }
    let inside: HashSet<ValueId> = merges.iter().copied().chain([reader]).collect();
    let outside = |v: ValueId| {
        let (by, other) = readers(v);
        other || by.iter().any(|r| !inside.contains(r))
    };
    if merges.iter().any(|m| outside(*m)) {
        return None;
    }
    let shared = leaves.iter().copied().filter(|l| outside(*l)).collect();
    Some(Arms { merges, leaves, shared })
}

fn apply(func: &mut HighFunction, declared: &Declared, plan: Plan) {
    let note = |what: &str| Provenance::new(PASS_NAME, ProvenanceSource::SdkPattern, what.to_string());
    let e_ty = IrType::Inferred(declared.ty.clone());
    // Each arm as the declared error: its own binding, or a new one read
    // right after it when something else reads it too.
    let mut moved: HashMap<ValueId, ValueId> = HashMap::new();
    let arms: Vec<(ValueId, Expr, IrType, &str)> = plan
        .constants
        .iter()
        .filter_map(|&(arm, code)| {
            Some((arm, declared.constant(code)?, IrType::Known(declared.ty.clone()), "error-code: a constant code, as the declared error"))
        })
        .chain(plan.reads.iter().filter_map(|&arm| {
            let expr = func.bindings.get(arm)?.expr.clone();
            Some((arm, expr, e_ty.clone(), "error-code: the code of the error the entrypoint returns, read as the declared error"))
        }))
        .collect();
    for (arm, expr, ty, why) in arms {
        if plan.shared.contains(&arm) {
            let Some(block) = crate::dataflow::block_containing(func, arm) else { continue };
            let new = ValueId::from_index(func.bindings.len() as u32);
            func.bindings.push(Binding::new(new, ty, expr, note(why)));
            if let Some(b) = func.blocks.get_mut(block)
                && let Some(pos) = b.bindings.iter().position(|x| *x == arm)
            {
                b.bindings.insert(pos + 1, new);
            }
            moved.insert(arm, new);
        } else if let Some(b) = func.bindings.get_mut(arm) {
            b.expr = expr;
            b.ty = ty;
            b.add_provenance(note(why));
        }
    }
    // The merges take the arms read again, on their edges too.
    let merges: HashSet<ValueId> = plan.merges.iter().copied().collect();
    for &m in &plan.merges {
        let resolved: Vec<(usize, ValueId)> = match func.bindings.get(m).map(|b| &b.expr) {
            Some(Expr::Phi { incoming }) => {
                incoming.iter().enumerate().map(|(i, (_, a))| (i, resolve_use(func, *a))).collect()
            }
            _ => Vec::new(),
        };
        if let Some(b) = func.bindings.get_mut(m) {
            if let Expr::Phi { incoming } = &mut b.expr {
                for (i, a) in resolved {
                    if let Some(new) = moved.get(&a) {
                        incoming[i].1 = *new;
                    }
                }
            }
            b.ty = e_ty.clone();
            b.add_provenance(note("error-code: the code of the error the entrypoint returns, as the declared error"));
        }
    }
    let resolved: HashMap<ValueId, ValueId> = func
        .bindings
        .iter()
        .map(|(id, _)| id)
        .filter_map(|id| {
            let r = resolve_use(func, id);
            moved.get(&r).map(|new| (id, *new))
        })
        .collect();
    retarget(&mut func.region, &merges, &resolved);
    let code = moved.get(&plan.code).copied().unwrap_or(plan.code);
    let lone = plan.merges.is_empty() && plan.constants.len() == 1;
    if let Some(b) = func.bindings.get_mut(plan.value) {
        b.expr = Expr::Use(code);
        b.ty = if lone { IrType::Known(declared.ty.clone()) } else { e_ty.clone() };
        b.add_provenance(note(
            "error-code: `(c << 32) | 3` built by arithmetic is the Error of code `c`: the entrypoint's `Err`",
        ));
    }
    if let Some(addend) = plan.addend
        && let Some(b) = func.bindings.get_mut(addend)
    {
        b.expr = Expr::Literal(Literal::Unit);
        b.ty = IrType::Known(KnownType::Unit);
        b.add_provenance(note("error-code: the constant the arithmetic added, read by nothing now"));
    }
}

/// Point every edge into one of `merges` that hands it a value in `moved`
/// at the value it moved to.
fn retarget(region: &mut Region, merges: &HashSet<ValueId>, moved: &HashMap<ValueId, ValueId>) {
    match region {
        Region::Sequence(items) => items.iter_mut().for_each(|r| retarget(r, merges, moved)),
        Region::Scope { body, .. } | Region::Loop { body, .. } => retarget(body, merges, moved),
        Region::If { then_region, else_region, .. } => {
            retarget(then_region, merges, moved);
            if let Some(e) = else_region {
                retarget(e, merges, moved);
            }
        }
        Region::Switch { arms, default, .. } => {
            retarget(default, merges, moved);
            for arm in arms {
                retarget(&mut arm.body, merges, moved);
            }
        }
        Region::Break { transfer, .. } | Region::Continue { transfer, .. } | Region::Transfer { transfer, .. } => {
            for (dest, src) in transfer.iter_mut() {
                if merges.contains(dest)
                    && let Some(new) = moved.get(src)
                {
                    *src = *new;
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};
    use sordec_common::{BlockId, UnknownReason};
    use sordec_ir::{CompositeType, EnumCase, EnumDef, FunctionSignature, PrimitiveType, SorobanFacts, TypeRef};

    fn error_val(code: u32) -> Expr {
        Expr::Literal(Literal::I64(((u64::from(code) << 32) | 3) as i64))
    }

    fn load4(addr: u32) -> Expr {
        Expr::Load {
            addr: v(addr),
            offset: 0,
            width: MemWidth::W4,
            signed: None,
            ty: IrType::Unknown(UnknownReason::InsufficientEvidence),
        }
    }

    /// `c = phi [5, load]; r = ((c - 1) as u32 as u64 << 32) + Error(k);
    /// return r`, in an entrypoint returning `Result<u32, err>`.
    fn entry(k: u32, err: TypeRef) -> HighIr {
        let exprs = vec![
            Expr::Phi { incoming: vec![] },                                                    // v0 a pointer
            Expr::Literal(Literal::I32(5)),                                                    // v1
            load4(0),                                                                          // v2
            Expr::Phi { incoming: vec![(BlockId::from_index(0), v(1)), (BlockId::from_index(0), v(2))] }, // v3 c
            Expr::Literal(Literal::I32(-1)),                                                   // v4
            Expr::Binary { op: BinaryOp::Add, lhs: v(3), rhs: v(4) },                          // v5
            Expr::Unary { op: UnaryOp::ExtendU32, value: v(5) },                               // v6
            Expr::Literal(Literal::I64(32)),                                                   // v7
            Expr::Binary { op: BinaryOp::Shl, lhs: v(6), rhs: v(7) },                          // v8
            error_val(k),                                                                      // v9
            Expr::Binary { op: BinaryOp::Add, lhs: v(8), rhs: v(9) },                          // v10
        ];
        let mut f = func_with(exprs, vec![v(0)], vec![1, 2, 4, 5, 6, 7, 8, 9, 10]);
        f.region = Region::Sequence(vec![
            Region::Basic(BlockId::from_index(0)),
            Region::Return { values: vec![v(10)] },
        ]);
        f.returns = vec![vec![v(10)]];
        f.name = Some("vote".into());
        f.signature = Some(FunctionSignature {
            name: "vote".into(),
            inputs: vec![],
            outputs: vec![TypeRef::Composite(CompositeType::Result(
                Box::new(TypeRef::Primitive(PrimitiveType::U32)),
                Box::new(err),
            ))],
        });
        let mut ir = module(vec![f]);
        let mut types = TypeRegistry::default();
        types.errors.push(EnumDef {
            id: TypeId::from_index(1),
            name: "MyError".into(),
            cases: vec![EnumCase { name: "First".into(), value: 1 }, EnumCase { name: "Closed".into(), value: 5 }],
        });
        ir.soroban_facts = Some(SorobanFacts {
            functions: Default::default(),
            types,
            contract_meta: Default::default(),
            env_meta: Default::default(),
        });
        ir
    }

    fn sdk_error() -> TypeRef {
        TypeRef::Primitive(PrimitiveType::Error)
    }

    fn expr(ir: &HighIr, id: u32) -> &Expr {
        &ir.functions[0].bindings.get(v(id)).expect("binding").expr
    }

    fn ty(ir: &HighIr, id: u32) -> &IrType {
        &ir.functions[0].bindings.get(v(id)).expect("binding").ty
    }

    #[test]
    fn a_run_time_code_is_the_returned_error() {
        let mut ir = entry(1, sdk_error());
        let r = ErrorCodeReturnPass.run(&mut ir);
        assert!(r.changed);
        assert!(matches!(expr(&ir, 10), Expr::Use(c) if *c == v(3)), "{:?}", expr(&ir, 10));
        let mine = KnownType::UserDefined(TypeId::from_index(1));
        assert_eq!(ty(&ir, 3), &IrType::Inferred(mine.clone()), "the merge is the error");
        assert_eq!(ty(&ir, 2), &IrType::Inferred(mine), "the read is the error");
        assert!(
            matches!(expr(&ir, 1), Expr::Semantic(SemanticOp::Known(KnownOp::MakeError { code: 5, resolved: Some(r) })) if r.variant == "Closed"),
            "{:?}",
            expr(&ir, 1)
        );
        assert!(matches!(expr(&ir, 9), Expr::Literal(Literal::Unit)), "the addend goes");
    }

    #[test]
    fn an_offset_that_does_not_cancel_is_not_the_code() {
        // `- 1` with `Error(2)`: the sum is the error of `c + 1`.
        let mut ir = entry(2, sdk_error());
        assert!(!ErrorCodeReturnPass.run(&mut ir).changed);
    }

    #[test]
    fn a_constant_code_the_enum_does_not_declare_is_refused() {
        let mut ir = entry(1, sdk_error());
        if let Some(b) = ir.functions[0].bindings.get_mut(v(1)) {
            b.expr = Expr::Literal(Literal::I32(7));
        }
        assert!(!ErrorCodeReturnPass.run(&mut ir).changed);
    }

    #[test]
    fn a_helper_is_not_the_boundary() {
        let mut ir = entry(1, sdk_error());
        ir.functions[0].signature = None;
        ir.functions[0].name = None;
        assert!(!ErrorCodeReturnPass.run(&mut ir).changed);
    }

    /// `entry`'s function as a helper (`func_1`), called by an entrypoint
    /// (`func_0`) declaring `Result<u32, err>` that `returned` decides:
    /// `r = func_1(p); return r` when true, `r = func_1(p); return 0`
    /// otherwise.
    fn helper_under_entry(err: TypeRef, returned: bool) -> HighIr {
        let mut ir = entry(1, err);
        let mut helper = ir.functions.remove(0);
        let sig = helper.signature.take();
        helper.name = None;
        helper.id = sordec_common::FuncId::from_index(1);
        let mut top = func_with(
            vec![
                Expr::Phi { incoming: vec![] },
                Expr::Call { target: helper.id, args: vec![v(0)] },
                Expr::Literal(Literal::I64(0)),
            ],
            vec![v(0)],
            vec![1, 2],
        );
        let out = if returned { v(1) } else { v(2) };
        top.region = Region::Sequence(vec![Region::Basic(BlockId::from_index(0)), Region::Return { values: vec![out] }]);
        top.returns = vec![vec![out]];
        top.name = Some("vote".into());
        top.signature = sig;
        ir.functions = vec![top, helper];
        ir
    }

    #[test]
    fn a_helper_every_caller_returns_takes_the_entrypoints_error() {
        let mut ir = helper_under_entry(sdk_error(), true);
        assert!(ErrorCodeReturnPass.run(&mut ir).changed);
        let f = &ir.functions[1];
        assert!(matches!(&f.bindings.get(v(10)).expect("binding").expr, Expr::Use(c) if *c == v(3)));
        let mine = KnownType::UserDefined(TypeId::from_index(1));
        assert_eq!(f.bindings.get(v(2)).expect("binding").ty, IrType::Inferred(mine), "the read is the error");
    }

    #[test]
    fn a_helper_whose_result_is_not_returned_is_left() {
        let mut ir = helper_under_entry(sdk_error(), false);
        assert!(!ErrorCodeReturnPass.run(&mut ir).changed);
    }

    #[test]
    fn a_code_read_elsewhere_is_left_alone() {
        // The merge also feeds a store: the code is a number someone uses.
        let mut ir = entry(1, sdk_error());
        let f = &mut ir.functions[0];
        let id = v(f.bindings.len() as u32);
        f.bindings.push(sordec_ir::Binding::new(
            id,
            IrType::Unknown(UnknownReason::InsufficientEvidence),
            crate::marshalling::test_support::store(v(0), v(3), 0),
            Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
        ));
        if let Some(block) = f.blocks.get_mut(BlockId::from_index(0)) {
            block.bindings.push(id);
        }
        assert!(!ErrorCodeReturnPass.run(&mut ir).changed);
    }

    #[test]
    fn a_read_something_else_reads_is_read_again_for_the_merge() {
        // The word is also stored (a field of the `Ok` value, on the other
        // path): it keeps its type and reader, and the merge takes a
        // second read of the same address.
        let mut ir = entry(1, sdk_error());
        let f = &mut ir.functions[0];
        let id = v(f.bindings.len() as u32);
        f.bindings.push(sordec_ir::Binding::new(
            id,
            IrType::Unknown(UnknownReason::InsufficientEvidence),
            crate::marshalling::test_support::store(v(0), v(2), 8),
            Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
        ));
        if let Some(block) = f.blocks.get_mut(BlockId::from_index(0)) {
            block.bindings.push(id);
        }
        assert!(ErrorCodeReturnPass.run(&mut ir).changed);
        let f = &ir.functions[0];
        assert!(matches!(ty(&ir, 2), IrType::Unknown(_)), "the shared read keeps its type");
        let Some(Expr::Phi { incoming }) = f.bindings.get(v(3)).map(|b| &b.expr) else { panic!() };
        let again = incoming[1].1;
        assert_ne!(again, v(2));
        assert!(matches!(expr(&ir, again.index()), Expr::Load { width: MemWidth::W4, .. }));
        let block = &f.blocks.get(BlockId::from_index(0)).expect("block").bindings;
        let at = block.iter().position(|x| *x == v(2)).expect("scheduled");
        assert_eq!(block.get(at + 1), Some(&again), "read again right after itself");
    }

    #[test]
    fn a_value_read_by_more_than_the_return_is_left_alone() {
        let mut ir = entry(1, sdk_error());
        ir.functions[0].region = Region::Sequence(vec![
            Region::Basic(BlockId::from_index(0)),
            Region::If {
                cond: v(10),
                then_region: Box::new(Region::Unreachable),
                else_region: None,
            },
            Region::Return { values: vec![v(10)] },
        ]);
        assert!(!ErrorCodeReturnPass.run(&mut ir).changed);
    }
}
