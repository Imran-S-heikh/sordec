//! Pass a struct to a helper as a struct, not as a pointer to a frame.
//!
//! A Rust struct too big for a register is passed by reference, so
//!
//! ```rust,ignore
//! write_offer(&e, &Offer { seller, sell_token, buy_token, sell_price, buy_price })
//! ```
//!
//! compiles to five stores into the caller's frame and a call taking the
//! frame's address. Reconstructed literally that is five `todo!("memory
//! store")` lines and a call whose argument is an integer — in
//! `single_offer`'s `create`, the whole body of the source's one
//! expression.
//!
//! # What proves the layout
//!
//! Not the layout. Rust does not promise field order in memory, so
//! matching offsets against a declared struct's fields would be a guess.
//!
//! The callee says it instead. Its own body builds the Soroban map from
//! the key table the derive emitted, so [`super::super::marshalling::udt_encode`]
//! has already named the struct *and* which field each value belongs to —
//! and each of those values is a load from the incoming pointer at a fixed
//! offset. Reading that back gives `offset → field` from the contract's
//! own metadata:
//!
//! ```text
//! fn func_8(p) -> Offer {              fn func_8(p: Offer) -> Offer {
//!     v6  = load   p+0                     v6  = p.seller
//!     v12 = load32 p+24            →       v12 = p.sell_price
//!     …                                    …
//!     return Offer { seller: v6, … }       return p
//! }
//! ```
//!
//! # The rewrite
//!
//! The callee takes the struct: each load becomes a field access and the
//! literal it fed becomes the parameter itself. Each caller builds the
//! literal from the slots it was about to store, and the stores are left
//! for the frame elision to collect.
//!
//! # Gates
//!
//! - **The parameter is the struct and nothing else.** Every reader of it
//!   must be one of the loads that feed the literal. A pointer that is
//!   also passed on, compared, or read at an offset the literal does not
//!   use is doing something this pass cannot see.
//! - **The caller has every slot.** All of them, proven at the call by the
//!   frame facts. Half a literal is not a literal.
//! - **Every caller has every slot.** The callee's parameter changes type,
//!   so it is every call site or none: a call left passing the pointer to
//!   a function that now takes the struct would hand it the frame's
//!   address as the struct (inlined, the struct *is* that address). A
//!   callee with a site that cannot build its literal yet waits for a
//!   later round, when the frame facts there may be complete. A forwarder
//!   handing its own promoted parameter on is such a site already.
//!
//! # A field read narrower than it was written
//!
//! rustc copies a struct by words: a `u32` last field at offset 24 is
//! written with the 8-byte store that copies bytes 24..32, and read by the
//! callee as the 4 bytes at 24. Wasm memory is little-endian, so those 4
//! bytes are the low half of the stored word: the field is
//! `wrap32(stored)`. Why it is exact: that is what the load reads, byte for
//! byte. Gates: a 4-byte read at the very offset of an 8-byte store; any
//! other width mismatch still leaves the slot unproven.

use std::collections::HashMap;

use sordec_common::{FuncId, IrId, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{Expr, HighFunction, HighIr, IrType, MemWidth, UnaryOp};

use crate::dataflow::{canon_addr, facts_at, resolve_use};
use crate::metrics_catalog::INTERPROC_STRUCT_ARGS as M_ARGS;
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "interproc-struct-arg";

/// Turns a by-pointer struct argument into the struct.
#[derive(Debug, Default, Clone, Copy)]
pub struct StructArgPass;

/// One parameter that is a struct behind a pointer.
#[derive(Clone)]
struct ByPointer {
    /// Index of the pointer parameter.
    param: usize,
    /// The struct the callee builds from it.
    ty: IrType,
    /// Where each field is read from, and what it is called.
    slots: Vec<(u32, MemWidth, String)>,
}

impl Pass<HighIr> for StructArgPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let mut promoted: HashMap<FuncId, ByPointer> =
            ir.functions.iter().filter_map(|f| by_pointer(f).map(|p| (f.id, p))).collect();
        if promoted.is_empty() {
            return result;
        }
        // A helper between the caller and the one that reads the struct
        // only passes the pointer along, so it is the same struct. Closed
        // over: `write_offer` forwards to the derived conversion, and the
        // entrypoint calls `write_offer`.
        loop {
            let found: Vec<(FuncId, ByPointer)> = ir
                .functions
                .iter()
                .filter(|f| !promoted.contains_key(&f.id))
                .filter_map(|f| forwarder(f, &promoted).map(|p| (f.id, p)))
                .collect();
            if found.is_empty() {
                break;
            }
            promoted.extend(found);
        }
        // Every call site or none ("Every caller has every slot"). A
        // forwarder stands for what it forwards to, so one whose onward
        // callee is withdrawn goes too; repeated until nothing is short.
        loop {
            let short: Vec<FuncId> = promoted
                .keys()
                .copied()
                .filter(|target| {
                    let stands = ir
                        .functions
                        .iter()
                        .find(|g| g.id == *target)
                        .is_some_and(|g| by_pointer(g).is_some() || forwarder(g, &promoted).is_some());
                    !stands || ir.functions.iter().any(|f| !every_site_builds(f, *target, &promoted))
                })
                .collect();
            if short.is_empty() {
                break;
            }
            for target in short {
                promoted.remove(&target);
            }
        }
        let promoted = promoted;
        if promoted.is_empty() {
            return result;
        }
        for func in &mut ir.functions {
            if let Some(plan) = promoted.get(&func.id).cloned() {
                take_the_struct(func, &plan);
                result.metrics.increment(M_ARGS, 1);
                result.changed = true;
            }
            if build_at_calls(func, &promoted) {
                result.changed = true;
            }
        }
        result
    }
}

/// The struct a function's pointer parameter stands for, if it is one.
fn by_pointer(func: &HighFunction) -> Option<ByPointer> {
    // Exactly one struct literal, and it is what the function returns.
    let mut literals = func.bindings.iter().filter(|(_, b)| matches!(b.expr, Expr::Struct { .. }));
    let (literal, binding) = literals.next()?;
    if literals.next().is_some() {
        return None;
    }
    let Expr::Struct { fields } = &binding.expr else {
        return None;
    };
    // Every field is a load from one parameter at a fixed offset.
    let mut base = None;
    let mut slots = Vec::with_capacity(fields.len());
    let mut readers = vec![literal];
    for (name, value) in fields {
        let id = resolve_use(func, *value);
        let Expr::Load { addr, offset, width, .. } = &func.bindings.get(id)?.expr else {
            return None;
        };
        let addr = resolve_use(func, *addr);
        if *base.get_or_insert(addr) != addr {
            return None;
        }
        slots.push((*offset, *width, name.clone()));
        readers.push(id);
    }
    let base = base?;
    let param = func.params.iter().position(|p| *p == base)?;
    // Nothing else may read the pointer: another reader is a use of the
    // frame this pass is about to stop passing.
    let pointer = func.params[param];
    let clean = !func.bindings.iter().any(|(id, b)| {
        if readers.contains(&id) {
            return false;
        }
        let mut reads = false;
        b.expr.for_each_value_use(|u| reads |= resolve_use(func, u) == pointer);
        reads
    });
    let mut in_region = false;
    func.region.for_each_value_use(|u| in_region |= resolve_use(func, u) == pointer);
    (clean && !in_region).then_some(ByPointer { param, ty: binding.ty.clone(), slots })
}

/// A parameter whose every reader is a call passing it on to a function
/// already known to want the struct there.
fn forwarder(func: &HighFunction, promoted: &HashMap<FuncId, ByPointer>) -> Option<ByPointer> {
    (0..func.params.len()).find_map(|index| {
        let pointer = func.params[index];
        let mut plan: Option<&ByPointer> = None;
        for (_, b) in func.bindings.iter() {
            let mut reads = false;
            b.expr.for_each_value_use(|u| reads |= resolve_use(func, u) == pointer);
            if !reads {
                continue;
            }
            let Expr::Call { target, args } = &b.expr else {
                return None;
            };
            let onward = promoted.get(target)?;
            // Passed at the position that wants the struct, and only
            // there: an argument that is also the pointer elsewhere in
            // the same call is doing something else.
            if args.iter().filter(|a| resolve_use(func, **a) == pointer).count() != 1
                || args.get(onward.param).map(|a| resolve_use(func, *a)) != Some(pointer)
            {
                return None;
            }
            if plan.get_or_insert(onward).ty != onward.ty {
                return None;
            }
        }
        let mut in_region = false;
        func.region.for_each_value_use(|u| in_region |= resolve_use(func, u) == pointer);
        if in_region {
            return None;
        }
        plan.map(|p| ByPointer { param: index, ty: p.ty.clone(), slots: p.slots.clone() })
    })
}

/// Callee side: the parameter is the struct, and its loads are fields.
fn take_the_struct(func: &mut HighFunction, plan: &ByPointer) {
    let note = Provenance::new(
        PASS_NAME,
        ProvenanceSource::SdkPattern,
        "the struct this pointer stood for, as the callee's own metadata names it",
    );
    let pointer = func.params[plan.param];
    let rewrites: Vec<(ValueId, String)> = func
        .bindings
        .iter()
        .filter_map(|(id, b)| {
            let Expr::Load { addr, offset, width, .. } = &b.expr else {
                return None;
            };
            (resolve_use(func, *addr) == pointer).then_some(())?;
            plan.slots
                .iter()
                .find(|(off, w, _)| off == offset && w == width)
                .map(|(_, _, name)| (id, name.clone()))
        })
        .collect();
    for (id, field) in rewrites {
        if let Some(b) = func.bindings.get_mut(id) {
            b.expr = Expr::Field { base: pointer, field };
            b.add_provenance(note.clone());
        }
    }
    let literal: Vec<ValueId> = func
        .bindings
        .iter()
        .filter(|(_, b)| matches!(b.expr, Expr::Struct { .. }))
        .map(|(id, _)| id)
        .collect();
    for id in literal {
        if let Some(b) = func.bindings.get_mut(id) {
            b.expr = Expr::Use(pointer);
            b.add_provenance(note.clone());
        }
    }
    if let Some(b) = func.bindings.get_mut(pointer) {
        b.ty = plan.ty.clone();
        b.add_provenance(note);
    }
}

/// Caller side: build the literal the stores were for.
fn build_at_calls(func: &mut HighFunction, promoted: &HashMap<FuncId, ByPointer>) -> bool {
    let plans: Vec<(ValueId, ByPointer, ValueId)> = func
        .bindings
        .iter()
        .filter_map(|(id, b)| {
            let Expr::Call { target, args } = &b.expr else {
                return None;
            };
            let plan = promoted.get(target)?;
            Some((id, plan.clone(), *args.get(plan.param)?))
        })
        .collect();
    let mut changed = false;
    for (call, plan, pointer) in plans {
        let Some(slots) = site_slots(func, call, pointer, &plan) else {
            continue;
        };
        let mut fields = Vec::with_capacity(slots.len());
        for (name, slot) in slots {
            let value = match slot {
                SlotValue::Whole(v) => v,
                // The low half of a wider store ("A field read narrower
                // than it was written").
                SlotValue::Low32(v) => {
                    let low = ValueId::from_index(func.bindings.len() as u32);
                    func.bindings.push(sordec_ir::Binding::new(
                        low,
                        IrType::Unknown(sordec_common::UnknownReason::InsufficientEvidence),
                        Expr::Unary { op: UnaryOp::Wrap32, value: v },
                        Provenance::new(
                            PASS_NAME,
                            ProvenanceSource::SdkPattern,
                            "the 4-byte field read as the low half of the 8-byte word stored there",
                        ),
                    ));
                    schedule_before(func, call, low);
                    low
                }
            };
            fields.push((name, value));
        }
        let literal = ValueId::from_index(func.bindings.len() as u32);
        func.bindings.push(sordec_ir::Binding::new(
            literal,
            plan.ty.clone(),
            Expr::Struct { fields },
            Provenance::new(
                PASS_NAME,
                ProvenanceSource::SdkPattern,
                "the struct these frame slots were filled for",
            ),
        ));
        schedule_before(func, call, literal);
        if let Some(Expr::Call { args, .. }) = func.bindings.get_mut(call).map(|b| &mut b.expr) {
            args[plan.param] = literal;
            changed = true;
        }
    }
    changed
}

/// Schedule `value` just before `at`.
fn schedule_before(func: &mut HighFunction, at: ValueId, value: ValueId) {
    for (_, block) in func.blocks.iter_mut() {
        if let Some(pos) = block.bindings.iter().position(|v| *v == at) {
            block.bindings.insert(pos, value);
            break;
        }
    }
}

/// What one slot of a call site's literal is.
enum SlotValue {
    /// The value stored there, at the width it is read.
    Whole(ValueId),
    /// The low 4 bytes of an 8-byte value stored there.
    Low32(ValueId),
}

/// Each field of the literal the call at `call` passes through `pointer`,
/// when the frame facts there prove every slot.
fn site_slots(func: &HighFunction, call: ValueId, pointer: ValueId, plan: &ByPointer) -> Option<Vec<(String, SlotValue)>> {
    let (base, start) = canon_addr(func, pointer);
    let facts = facts_at(func, call, base);
    plan.slots
        .iter()
        .map(|(offset, width, name)| {
            let at = start.checked_add(*offset)?;
            let slot = match facts.value_at(at, *width) {
                Some(v) => SlotValue::Whole(resolve_use(func, v)),
                None if *width == MemWidth::W4 && facts.value_at(at, MemWidth::W8).is_some() => {
                    SlotValue::Low32(resolve_use(func, facts.value_at(at, MemWidth::W8)?))
                }
                None => return None,
            };
            Some((name.clone(), slot))
        })
        .collect()
}

/// Whether every call in `func` to `target` can be handed the struct: it
/// builds the literal from its frame, or passes on a parameter of its own
/// that already stands for the same struct.
fn every_site_builds(func: &HighFunction, target: FuncId, promoted: &HashMap<FuncId, ByPointer>) -> bool {
    let Some(plan) = promoted.get(&target) else {
        return true;
    };
    func.bindings.iter().all(|(id, b)| {
        let Expr::Call { target: t, args } = &b.expr else {
            return true;
        };
        if *t != target {
            return true;
        }
        let Some(&pointer) = args.get(plan.param) else {
            return false;
        };
        let own = resolve_use(func, pointer);
        let forwarded = promoted
            .get(&func.id)
            .is_some_and(|mine| func.params.get(mine.param) == Some(&own) && mine.ty == plan.ty);
        forwarded || site_slots(func, id, pointer, plan).is_some()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};
    use sordec_common::{BlockId, TypeId, UnknownReason};
    use sordec_ir::{BinaryOp, KnownType, Literal, Region};

    fn struct_ty() -> IrType {
        IrType::Known(KnownType::UserDefined(TypeId::new(3)))
    }

    fn load(addr: ValueId, offset: u32) -> Expr {
        Expr::Load {
            addr,
            offset,
            width: MemWidth::W8,
            signed: None,
            ty: IrType::Unknown(UnknownReason::InsufficientEvidence),
        }
    }

    /// A callee that loads two slots off its pointer into a literal, and
    /// a caller that stores two values there and calls it. `leaks` adds a
    /// second reader of the pointer.
    fn shape(leaks: bool) -> HighIr {
        let mut exprs = vec![
            Expr::Phi { incoming: vec![] }, // v0 pointer param
            load(v(0), 0),                  // v1
            load(v(0), 8),                  // v2
            Expr::Struct { fields: vec![("a".into(), v(1)), ("b".into(), v(2))] }, // v3
        ];
        let mut sched = vec![1, 2, 3];
        if leaks {
            exprs.push(Expr::Binary { op: BinaryOp::Add, lhs: v(0), rhs: v(0) }); // v4
            sched.push(4);
        }
        let mut callee = func_with(exprs, vec![v(0)], sched);
        callee.bindings.get_mut(v(3)).unwrap().ty = struct_ty();
        callee.region = Region::Sequence(vec![
            Region::Basic(BlockId::from_index(0)),
            Region::Return { values: vec![v(3)] },
        ]);
        callee.returns = vec![vec![v(3)]];

        let mut caller = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                                     // v0 frame
                Expr::Phi { incoming: vec![] },                                     // v1 a
                Expr::Phi { incoming: vec![] },                                     // v2 b
                Expr::Store { addr: v(0), value: v(1), offset: 0, width: MemWidth::W8 }, // v3
                Expr::Store { addr: v(0), value: v(2), offset: 8, width: MemWidth::W8 }, // v4
                Expr::Call { target: FuncId::from_index(0), args: vec![v(0)] },      // v5
                Expr::Literal(Literal::Unit),                                        // v6
            ],
            vec![v(0), v(1), v(2)],
            vec![3, 4, 5, 6],
        );
        caller.id = FuncId::from_index(1);
        caller.region = Region::Sequence(vec![
            Region::Basic(BlockId::from_index(0)),
            Region::Return { values: vec![] },
        ]);
        let mut m = module(vec![callee, caller]);
        m.functions[0].id = FuncId::from_index(0);
        m
    }

    #[test]
    fn the_pointer_becomes_the_struct_on_both_sides() {
        let mut m = shape(false);
        assert!(StructArgPass.run(&mut m).changed);
        let callee = &m.functions[0];
        assert_eq!(callee.bindings.get(v(0)).unwrap().ty, struct_ty());
        assert!(matches!(&callee.bindings.get(v(1)).unwrap().expr, Expr::Field { field, .. } if field == "a"));
        assert!(matches!(callee.bindings.get(v(3)).unwrap().expr, Expr::Use(x) if x == v(0)));
        // The caller passes the literal its stores were filling.
        let caller = &m.functions[1];
        let Expr::Call { args, .. } = &caller.bindings.get(v(5)).unwrap().expr else {
            panic!("still a call");
        };
        let Expr::Struct { fields } = &caller.bindings.get(args[0]).unwrap().expr else {
            panic!("the argument is the literal");
        };
        assert_eq!(fields, &vec![("a".to_string(), v(1)), ("b".to_string(), v(2))]);
    }

    /// A pointer something else reads is doing more than standing for the
    /// struct.
    #[test]
    fn a_pointer_with_another_reader_is_left_alone() {
        let mut m = shape(true);
        assert!(!StructArgPass.run(&mut m).changed);
    }

    /// A second caller that stores only the first slot cannot build the
    /// literal, so neither side changes: the callee would otherwise take
    /// the struct while that caller hands it a frame address.
    #[test]
    fn a_callee_one_caller_cannot_build_for_is_left_alone() {
        let mut m = shape(false);
        let mut short = m.functions[1].clone();
        short.id = FuncId::from_index(2);
        short.blocks.get_mut(BlockId::from_index(0)).unwrap().bindings.retain(|b| *b != v(4));
        m.functions.push(short);
        assert!(!StructArgPass.run(&mut m).changed);
        assert!(matches!(m.functions[0].bindings.get(v(1)).unwrap().expr, Expr::Load { .. }));
        assert!(matches!(&m.functions[1].bindings.get(v(5)).unwrap().expr, Expr::Call { args, .. } if args[0] == v(0)));
    }

    /// The callee reads its second field as 4 bytes where the caller
    /// stored 8: the field is the low half of the stored word.
    #[test]
    fn a_field_read_narrower_than_stored_is_the_low_half() {
        let mut m = shape(false);
        if let Expr::Load { width, .. } = &mut m.functions[0].bindings.get_mut(v(2)).unwrap().expr {
            *width = MemWidth::W4;
        }
        assert!(StructArgPass.run(&mut m).changed);
        let caller = &m.functions[1];
        let Expr::Call { args, .. } = &caller.bindings.get(v(5)).unwrap().expr else { panic!("still a call") };
        let Expr::Struct { fields } = &caller.bindings.get(args[0]).unwrap().expr else { panic!("the literal") };
        assert_eq!(fields[0], ("a".to_string(), v(1)));
        assert!(matches!(
            caller.bindings.get(fields[1].1).unwrap().expr,
            Expr::Unary { op: UnaryOp::Wrap32, value } if value == v(2)
        ));
    }

    #[test]
    fn the_pass_is_idempotent() {
        let mut m = shape(false);
        assert!(StructArgPass.run(&mut m).changed);
        assert!(!StructArgPass.run(&mut m).changed);
    }
}
