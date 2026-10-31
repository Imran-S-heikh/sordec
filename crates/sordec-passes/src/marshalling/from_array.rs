//! `Vec::from_array`'s element loops, run to their end.
//!
//! # The shape
//!
//! `vec![&e, a, b, c]` is `Vec::from_array(&e, [a, b, c])`, which the SDK
//! (27.x, `vec.rs`) writes as
//!
//! ```text
//! let mut tmp: [Val; N] = [Val::VOID.to_val(); N];          // fill
//! for (dst, src) in tmp.iter_mut().zip(items.iter()) {      // copy
//!     *dst = src.into_val(env)
//! }
//! env.vec_new_from_slice(&tmp)
//! ```
//!
//! In a function too big for rustc to inline into, neither loop is
//! unrolled and the zip's constructor stays a call. Each `vec!` then
//! arrives as
//!
//! ```text
//! store fp+2584 <- a; store fp+2592 <- b; store fp+2600 <- c   // items
//! store fp+0 <- 2; store fp+8 <- 2; store fp+16 <- 2           // fill (VOID)
//! t = zip(fp, fp+24, fp+2584, fp+2608)                         // a 6-tuple
//! n = t.5 saturating- t.4; dst = t.0 + t.4*8; src = t.2 + t.4*8
//! loop { if n == 0 { <the rest of the function> }
//!        store dst <- into_val(src); n -= 1; dst += 8; src += 8 }
//! ```
//!
//! and the rest of the function nests inside the loop's exit: a Poseidon
//! parameter table of 64 such vectors is 64 loops deep, every store a
//! hole, the frame never private because the zip is handed its pointers.
//!
//! # The rewrite
//!
//! The loop is run, here, from the values its entry hands it, and replaced
//! by what it did: one load and one store per element, straight-line, in
//! the order it did them, followed by the code after the loop. The zip
//! call the entry read its bounds from is replaced by the values it
//! returns. What remains is the shape [`super::vec_elements`] reads — an
//! element array filled by plain stores before `vec_new_from_linear_memory`
//! — and the frame forwarding then reads each element as the value stored
//! into `items` before the loop.
//!
//! A loop the run can finish whose body only writes constants — the fill
//! loop of a vector too long for the lifted unroller — is the same rewrite.
//!
//! # Why it is exact
//!
//! It is the loop's own execution, on values that every run of the
//! function shares. Each value the run computes is a constant, an existing
//! binding plus a constant (`fp + 2584`), or the word a load the rewrite
//! emits reads; arithmetic is done at the width the program says (a
//! literal's own width, 32 bits for an address), and an address minus an
//! address of the same base is the constant between them whatever the base
//! is. So every run takes the same branches, makes the same number of
//! trips and touches the same addresses — and the emitted loads and stores
//! are those accesses, at those addresses, widths and values, in that
//! order. Nothing else the loop did is observable: its counters and
//! pointers are read by nothing after it.
//!
//! A call the run steps into is a helper evaluated on the same values
//! (`zip`'s constructor; the `into_val` that hands back the word behind its
//! pointer). Its own frame lives below the shadow-stack pointer, a region
//! no address of the caller's reaches; it may write and read that frame,
//! must read only what it wrote there, and must leave the stack pointer as
//! it found it. (A `global.set` of a value computed from the stack pointer
//! is read as setting the stack pointer: the lifted operator does not carry
//! its global's index — the reading [`super::frame`] makes of the same
//! bracket.) A write to the caller's memory, a host call, or anything
//! the run cannot compute stops the run. A read of the caller's memory
//! inside the loop is a load the rewrite emits at that point. So such a
//! call is its result and its reads.
//!
//! A call before the loop whose result the entry reads is evaluated the
//! same way, where it stands, and replaced by the value it returns (each
//! component, for a tuple). A read it makes of the caller's memory is the
//! value stored at exactly those bytes on every path to the call, with
//! nothing between that may write them ([`crate::dataflow::facts_at`], the
//! facts the frame forwarding reads); a read with no such store stops the
//! run. Writing nothing the caller can see, the call is that value.
//!
//! Everything the loop defined — its merges, its blocks' bindings — goes
//! with it, and so does an unscheduled, unread rename of anything the
//! rewrite replaced: neither is emitted, and both would otherwise count as
//! readers of the values they name.
//!
//! # Gates
//!
//! - **The loop's shape**: entered by a transfer right before it; its body
//!   is the header block, an `if` whose arm is the code after the loop —
//!   which always leaves and never goes round again — then straight-line
//!   blocks and the back edge.
//! - **The run**: only literals, integer arithmetic, comparisons, selects,
//!   loads and stores at computed addresses, and calls to straight-line
//!   helpers that pass the rules above; at most [`MAX_TRIPS`] trips; a
//!   stored value is a constant or a word, never an address.
//! - **A vector's buffer**: every access is a whole 8-byte `Val`, and every
//!   store writes `Val::VOID` or a word into the element buffer of a
//!   `vec_new_from_linear_memory` in the code after the loop. A loop that
//!   runs but builds something else — a byte reversal, say — stays: its
//!   accesses spelled out one by one are more holes, not fewer.
//! - **What leaves**: nothing the loop defines is read after it; a folded
//!   tuple call has no reader but its components, and every folded value is
//!   a constant, a binding, or a binding plus a constant.

use std::collections::{HashMap, HashSet};

use sordec_common::{BlockId, FuncId, IrId, Provenance, ProvenanceSource, UnknownReason, ValueId};
use sordec_ir::{
    BinaryOp, Binding, Expr, HighFunction, HighIr, IrType, KnownType, Literal, MemWidth, Region, UnaryOp,
    WasmOpcodeKind,
};

use crate::dataflow::resolve_use;
use crate::effects::expr_effects;
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-from-array";

/// Trips a loop may make. `vec_new_from_linear_memory`'s element arrays
/// the pipeline recovers hold at most 64 (`vec_elements`' own bound).
const MAX_TRIPS: usize = 64;

/// How deep helper calls are followed.
const MAX_DEPTH: usize = 4;

/// Bindings a helper evaluation may run.
const MAX_STEPS: usize = 512;

/// Loops replaced by their run.
const M_RUN: &str = "from_array_loops_run";

/// Runs `Vec::from_array`'s fill and copy loops to their end.
#[derive(Debug, Default, Clone, Copy)]
pub struct FromArrayLoopPass;

impl Pass<HighIr> for FromArrayLoopPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for index in 0..ir.functions.len() {
            let mut refused: HashSet<BlockId> = HashSet::new();
            while let Some(func) = ir.functions.get(index) {
                let Some((root, plan)) = next_run(ir, func, &refused) else { break };
                if !reads_nothing_it_defined(func, &root, &plan) {
                    refused.insert(plan.header);
                    continue;
                }
                let Some(func) = ir.functions.get_mut(index) else { break };
                apply(func, root, &plan);
                result.metrics.increment(M_RUN, 1);
                result.changed = true;
            }
        }
        result
    }
}

// ---------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------

/// Where an address points from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Base {
    /// A binding of the function whose loop is run.
    Caller(ValueId),
    /// The shadow-stack pointer as the outermost helper call found it.
    Stack,
}

/// A value the run computed.
#[derive(Debug, Clone, PartialEq)]
enum Sym {
    /// An integer, at the width the program computes it.
    Int { bits: i64, wide: bool },
    /// A 32-bit address, `base + off`.
    Addr { base: Base, off: i64 },
    /// The value of an existing binding of the caller, unchanged.
    Opaque(ValueId),
    /// The word the emitted load at this index of the effects reads.
    Loaded(usize),
    /// A multi-value return.
    Tuple(Vec<Sym>),
    /// A binding with no value (an elided one).
    Unit,
}

impl Sym {
    fn int(bits: i64, wide: bool) -> Self {
        Self::Int { bits: if wide { bits } else { i64::from(bits as i32) }, wide }
    }
}

/// A memory access the loop made on the caller's memory, in order.
#[derive(Debug, Clone)]
enum Effect {
    Load { base: ValueId, off: u32, width: MemWidth, signed: Option<bool>, ty: IrType },
    Store { base: ValueId, off: u32, width: MemWidth, value: Sym },
}

/// The loop's run, and what replaces it.
struct Plan {
    header: BlockId,
    /// The block the code after the loop starts with; the effects are
    /// scheduled at its top.
    exit_block: BlockId,
    effects: Vec<Effect>,
    /// Calls the entry read, and the value each returned.
    folded: Vec<(ValueId, Sym)>,
    /// Everything the loop defines.
    defined: HashSet<ValueId>,
    trips: usize,
}

// ---------------------------------------------------------------------
// Finding a loop
// ---------------------------------------------------------------------

/// The function's region with the first loop that runs replaced by the
/// code after it, and the plan.
fn next_run(ir: &HighIr, func: &HighFunction, refused: &HashSet<BlockId>) -> Option<(Region, Plan)> {
    let mut plan: Option<Plan> = None;
    let root = rebuild(&func.region, &mut |entry, lp| {
        if plan.is_some() {
            return None;
        }
        let (p, rest) = plan_loop(ir, func, refused, entry, lp)?;
        plan = Some(p);
        Some(rest)
    })?;
    Some((root, plan?))
}

type LoopRun<'a> = dyn FnMut(&Region, &Region) -> Option<Vec<Region>> + 'a;

/// `region` with the first loop `run` accepts — entered by the transfer
/// just before it — replaced, with that transfer, by the regions `run`
/// returns.
fn rebuild(region: &Region, run: &mut LoopRun<'_>) -> Option<Region> {
    match region {
        Region::Sequence(items) => {
            for (i, item) in items.iter().enumerate() {
                if let (Region::Loop { header, .. }, Some(entry)) = (item, i.checked_sub(1).map(|j| &items[j]))
                    && matches!(entry, Region::Transfer { target, .. } if target == header)
                    && let Some(rest) = run(entry, item)
                {
                    let mut out: Vec<Region> = items[..i - 1].to_vec();
                    out.push(Region::Sequence(rest));
                    out.extend(items[i + 1..].iter().cloned());
                    return Some(Region::Sequence(out));
                }
                if let Some(new) = rebuild(item, run) {
                    let mut out = items.clone();
                    out[i] = new;
                    return Some(Region::Sequence(out));
                }
            }
            None
        }
        Region::Scope { out, body } => rebuild(body, run).map(|b| Region::Scope { out: *out, body: Box::new(b) }),
        Region::If { cond, then_region, else_region } => {
            if let Some(t) = rebuild(then_region, run) {
                return Some(Region::If { cond: *cond, then_region: Box::new(t), else_region: else_region.clone() });
            }
            let e = rebuild(else_region.as_deref()?, run)?;
            Some(Region::If { cond: *cond, then_region: then_region.clone(), else_region: Some(Box::new(e)) })
        }
        Region::Loop { header, body, kind } => {
            rebuild(body, run).map(|b| Region::Loop { header: *header, body: Box::new(b), kind: *kind })
        }
        Region::Switch { index, arms, default, dispatch } => {
            for (k, arm) in arms.iter().enumerate() {
                if let Some(b) = rebuild(&arm.body, run) {
                    let mut arms = arms.clone();
                    arms[k].body = b;
                    return Some(Region::Switch { index: *index, arms, default: default.clone(), dispatch: *dispatch });
                }
            }
            let d = rebuild(default, run)?;
            Some(Region::Switch { index: *index, arms: arms.clone(), default: Box::new(d), dispatch: *dispatch })
        }
        _ => None,
    }
}

/// Whether control never falls out of the bottom of `region`. A loop is
/// left only by a break or a return, never by falling out of it.
fn leaves(region: &Region) -> bool {
    match region {
        Region::Return { .. }
        | Region::Break { .. }
        | Region::Continue { .. }
        | Region::Panic { .. }
        | Region::Unreachable
        | Region::Loop { .. } => true,
        Region::Sequence(items) => items.last().is_some_and(leaves),
        Region::Scope { body, .. } => leaves(body),
        Region::If { then_region, else_region: Some(e), .. } => leaves(then_region) && leaves(e),
        _ => false,
    }
}

/// Whether anything in `region` goes round the loop at `header` again.
fn goes_to(region: &Region, header: BlockId) -> bool {
    let mut found = false;
    region.for_each_node(|node| found |= matches!(node, Region::Continue { target, .. } if *target == header));
    found
}

/// Run `lp` from `entry`: the plan and the code after the loop, when the
/// shape and the run pass.
fn plan_loop(
    ir: &HighIr,
    func: &HighFunction,
    refused: &HashSet<BlockId>,
    entry: &Region,
    lp: &Region,
) -> Option<(Plan, Vec<Region>)> {
    let Region::Loop { header, body, .. } = lp else { return None };
    if refused.contains(header) {
        return None;
    }
    let Region::Transfer { transfer: entered, .. } = entry else { return None };
    let Region::Sequence(items) = body.as_ref() else { return None };
    let [Region::Basic(h), Region::If { cond, then_region, else_region: None }, middle @ .., Region::Continue { target, transfer: back }] =
        items.as_slice()
    else {
        trace(func, *header, &format!("body shape: {:?}", items.iter().map(region_name).collect::<Vec<_>>()));
        return None;
    };
    if h != header || target != header || !leaves(then_region) || goes_to(then_region, *header) {
        trace(func, *header, "not the loop shape");
        return None;
    }
    let body_blocks: Vec<BlockId> =
        middle.iter().map(|r| if let Region::Basic(b) = r { Some(*b) } else { None }).collect::<Option<_>>()?;
    let exit_items: Vec<Region> = match then_region.as_ref() {
        Region::Sequence(xs) => xs.clone(),
        other => vec![other.clone()],
    };
    let Some(Region::Basic(exit_block)) = exit_items.first() else { return None };

    let phis: Vec<ValueId> = entered.iter().map(|(p, _)| *p).collect();
    let mut back_phis: Vec<ValueId> = back.iter().map(|(p, _)| *p).collect();
    let mut sorted = phis.clone();
    sorted.sort();
    back_phis.sort();
    if sorted != back_phis {
        return None;
    }
    let mut defined: HashSet<ValueId> = phis.iter().copied().collect();
    for b in std::iter::once(header).chain(body_blocks.iter()) {
        defined.extend(func.blocks.get(*b)?.bindings.iter().copied());
    }

    let mut m = Machine {
        ir,
        func,
        defined: &defined,
        effects: Vec::new(),
        folded: Vec::new(),
        memory_ok: false,
        site: None,
        steps: 0,
    };
    // The entry's values: computed without touching memory, so a call the
    // run steps into here is a value.
    let mut env: HashMap<ValueId, Sym> = HashMap::new();
    for (phi, source) in entered {
        let Some(s) = m.read(&env, *source, 0) else {
            trace(func, *header, &format!("entry value of v{} not computed", phi.index()));
            return None;
        };
        env.insert(*phi, s);
    }
    m.memory_ok = true;
    let mut trips = 0;
    loop {
        m.block(&mut env, *header)?;
        let Some(Sym::Int { bits, .. }) = m.read(&env, *cond, 0) else {
            trace(func, *header, &format!("condition not computed on trip {trips}: {:?}", m.read(&env, *cond, 0)));
            return None;
        };
        if bits != 0 {
            break;
        }
        if trips == MAX_TRIPS {
            return None;
        }
        trips += 1;
        for b in &body_blocks {
            if m.block(&mut env, *b).is_none() {
                trace(func, *header, &format!("body block {} not run on trip {trips}", b.index()));
                return None;
            }
        }
        let next: Vec<(ValueId, Sym)> =
            back.iter().map(|(p, s)| m.read(&env, *s, 0).map(|v| (*p, v))).collect::<Option<_>>()?;
        env.retain(|v, _| !defined.contains(v));
        env.extend(next);
    }
    // Every stored value is something the rewrite can name.
    for e in &m.effects {
        if let Effect::Store { value, .. } = e
            && !matches!(value, Sym::Int { .. } | Sym::Opaque(_) | Sym::Loaded(_))
        {
            return None;
        }
    }
    if m.effects.is_empty() {
        return None;
    }
    // What the loop fills is a vector's element buffer: every access is a
    // whole `Val`, and every store lands in the buffer a
    // `vec_new_from_linear_memory` after the loop hands the host — as
    // `Val::VOID` (the fill) or as a word (the copy). Any other loop is
    // left as it is, however well it runs.
    let buffers = element_buffers(func, then_region);
    let fills_a_vec = m.effects.iter().all(|e| match e {
        Effect::Load { width, .. } => *width == MemWidth::W8,
        Effect::Store { base, off, width, value } => {
            *width == MemWidth::W8
                && matches!(value, Sym::Int { bits: 2, wide: true } | Sym::Opaque(_) | Sym::Loaded(_))
                && buffers.iter().any(|(b, start, count)| {
                    b == base && *off >= *start && u64::from(*off) + 8 <= u64::from(*start) + 8 * u64::from(*count)
                })
        }
    });
    if !fills_a_vec {
        trace(func, *header, "not a vector's element buffer");
        return None;
    }
    trace(func, *header, &format!("ran {trips} trips, {} accesses", m.effects.len()));
    let folded = std::mem::take(&mut m.folded);
    // A folded call is read only through its components, each of which
    // the rewrite can name.
    for (call, value) in &folded {
        if !matches!(value, Sym::Tuple(_)) {
            // A single value: the call itself becomes it.
            if !nameable(value) {
                return None;
            }
            continue;
        }
        if !only_projected(func, *call) {
            return None;
        }
        for (_, b) in func.bindings.iter() {
            if let Expr::Project { value: v, index } = &b.expr
                && *v == *call
            {
                let Sym::Tuple(items) = value else { return None };
                if !nameable(items.get(*index as usize)?) {
                    return None;
                }
            }
        }
    }
    let effects = m.effects;
    Some((Plan { header: *header, exit_block: *exit_block, effects, folded, defined, trips }, exit_items))
}

/// Why a loop was not run, printed when `SORDEC_FROM_ARRAY_TRACE` is set.
#[allow(clippy::print_stderr)]
fn trace(func: &HighFunction, header: BlockId, why: &str) {
    if std::env::var_os("SORDEC_FROM_ARRAY_TRACE").is_some() {
        eprintln!("from_array: func_{} loop {}: {why}", func.id.index(), header.index());
    }
}

fn region_name(r: &Region) -> &'static str {
    match r {
        Region::Basic(_) => "basic",
        Region::Sequence(_) => "sequence",
        Region::Scope { .. } => "scope",
        Region::If { .. } => "if",
        Region::Loop { .. } => "loop",
        Region::Switch { .. } => "switch",
        Region::Break { .. } => "break",
        Region::Continue { .. } => "continue",
        Region::Transfer { .. } => "transfer",
        Region::Return { .. } => "return",
        Region::Unreachable => "unreachable",
        Region::Panic { .. } => "panic",
        Region::Unstructured { .. } => "unstructured",
    }
}

/// Whether a folded value can be written as an expression of the caller:
/// a constant, a binding, or a binding plus a constant.
fn nameable(s: &Sym) -> bool {
    matches!(s, Sym::Int { .. } | Sym::Opaque(_) | Sym::Addr { base: Base::Caller(_), off: 0.. })
}

/// Every `vec_new_from_linear_memory` scheduled in `region` whose buffer
/// is a constant offset from a base and whose length is a constant: the
/// base, the first byte and the element count.
fn element_buffers(func: &HighFunction, region: &Region) -> Vec<(ValueId, u32, u32)> {
    use sordec_ir::{KnownOp, SemanticOp};
    let mut out = Vec::new();
    region.for_each_node(|node| {
        let Region::Basic(b) = node else { return };
        let Some(block) = func.blocks.get(*b) else { return };
        for id in &block.bindings {
            let Some(Expr::Semantic(SemanticOp::Known(KnownOp::VecNew { vals_pos, len, elements: None }))) =
                func.bindings.get(*id).map(|b| &b.expr)
            else {
                continue;
            };
            let Some(count) = crate::dataflow::trace_u32val(func, *len) else { continue };
            let (base, start) =
                crate::dataflow::canon_addr(func, crate::recognizers::client_call::peel_encode(func, *vals_pos));
            out.push((base, start, count));
        }
    });
    out
}

/// Whether every reader of `call` is a component read.
fn only_projected(func: &HighFunction, call: ValueId) -> bool {
    let mut ok = true;
    for (_, b) in func.bindings.iter() {
        if matches!(b.expr, Expr::Project { value, .. } if value == call) {
            continue;
        }
        b.expr.for_each_value_use(|u| ok &= u != call);
    }
    func.region.for_each_value_use(|u| ok &= u != call);
    ok
}

/// Whether nothing the loop defined is read in `root` — the function's
/// region with the loop replaced.
fn reads_nothing_it_defined(func: &HighFunction, root: &Region, plan: &Plan) -> bool {
    let gone = |v: ValueId| plan.defined.contains(&v);
    let mut clean = true;
    root.for_each_value_use(|u| clean &= !gone(u));
    root.for_each_node(|node| {
        let Region::Basic(b) = node else { return };
        let Some(block) = func.blocks.get(*b) else { return };
        for id in &block.bindings {
            if let Some(binding) = func.bindings.get(*id) {
                binding.expr.for_each_value_use(|u| clean &= !gone(u));
            }
        }
    });
    clean
}

// ---------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------

struct Machine<'a> {
    ir: &'a HighIr,
    func: &'a HighFunction,
    /// What the loop defines: read only from the run's own values.
    defined: &'a HashSet<ValueId>,
    effects: Vec<Effect>,
    folded: Vec<(ValueId, Sym)>,
    /// Whether the caller's memory may be accessed (inside the loop).
    memory_ok: bool,
    /// The call before the loop being evaluated, while it is: a read of the
    /// caller's memory there is the value stored at those bytes.
    site: Option<ValueId>,
    steps: usize,
}

/// One helper call being evaluated.
struct Frame<'f> {
    func: &'f HighFunction,
    env: HashMap<ValueId, Sym>,
}

/// The helper calls' shared view of the shadow stack: the pointer and
/// what they wrote below it.
#[derive(Default)]
struct Stack {
    sp: i64,
    slots: HashMap<i64, (Sym, MemWidth)>,
}

impl Machine<'_> {
    /// Run one of the loop's blocks.
    fn block(&mut self, env: &mut HashMap<ValueId, Sym>, block: BlockId) -> Option<()> {
        let ids = self.func.blocks.get(block)?.bindings.clone();
        for id in ids {
            let b = self.func.bindings.get(id)?;
            let value = match &b.expr {
                Expr::Store { addr, value, offset, width } => {
                    let a = self.read(env, *addr, 0)?;
                    let v = self.read(env, *value, 0)?;
                    let (base, off) = caller_address(&a, *offset)?;
                    if !self.memory_ok {
                        return None;
                    }
                    self.effects.push(Effect::Store { base, off, width: *width, value: v });
                    Sym::Unit
                }
                Expr::Load { addr, offset, width, signed, ty } => {
                    let a = self.read(env, *addr, 0)?;
                    let (base, off) = caller_address(&a, *offset)?;
                    self.load(base, off, *width, *signed, ty.clone())?
                }
                Expr::Call { target, args } => {
                    let args: Vec<Sym> = args.iter().map(|a| self.read(env, *a, 0)).collect::<Option<_>>()?;
                    let mut stack = Stack::default();
                    self.call(*target, args, &mut stack, 0)?
                }
                // Anything else is computed when read; one that cannot be
                // stops the run only if something reads it, unless it has
                // an effect of its own.
                other if expr_effects(other).is_pure_total() => continue,
                Expr::Literal(_) | Expr::Use(_) | Expr::Binary { .. } | Expr::Unary { .. } | Expr::Project { .. } => {
                    continue;
                }
                _ => return None,
            };
            env.insert(id, value);
        }
        Some(())
    }

    /// The word a load of the caller's memory reads, as an emitted load.
    fn load(&mut self, base: ValueId, off: u32, width: MemWidth, signed: Option<bool>, ty: IrType) -> Option<Sym> {
        if !self.memory_ok {
            // A call before the loop reads what its caller stored there, at
            // exactly those bytes, with nothing between that may write them
            // — the facts the frame forwarding reads.
            let site = self.site?;
            let stored = crate::dataflow::facts_at(self.func, site, base).value_at(off, width)?;
            return self.read(&HashMap::new(), stored, 1);
        }
        self.effects.push(Effect::Load { base, off, width, signed, ty });
        Some(Sym::Loaded(self.effects.len() - 1))
    }

    /// The value of `v` in the caller: the run's own value, or computed
    /// from the bindings before the loop.
    fn read(&mut self, env: &HashMap<ValueId, Sym>, v: ValueId, depth: usize) -> Option<Sym> {
        if let Some(s) = env.get(&v) {
            return Some(s.clone());
        }
        let r = resolve_use(self.func, v);
        if let Some(s) = env.get(&r) {
            return Some(s.clone());
        }
        if depth > 32 {
            return None;
        }
        let b = self.func.bindings.get(r)?;
        let computed = match &b.expr {
            Expr::Literal(lit) => literal(lit),
            Expr::Binary { op, lhs, rhs } => {
                let (l, r2) = (self.read(env, *lhs, depth + 1)?, self.read(env, *rhs, depth + 1)?);
                binary(*op, &l, &r2)
            }
            Expr::Unary { op, value } => unary(*op, &self.read(env, *value, depth + 1)?),
            Expr::Select { cond, if_true, if_false } => {
                let c = self.read(env, *cond, depth + 1)?;
                self.read(env, if truth(&c)? { *if_true } else { *if_false }, depth + 1)
            }
            Expr::Unknown { op_kind: WasmOpcodeKind::Select, args, .. } if args.len() == 3 => {
                let c = self.read(env, args[2], depth + 1)?;
                self.read(env, if truth(&c)? { args[0] } else { args[1] }, depth + 1)
            }
            Expr::Project { value, index } => {
                let call = resolve_use(self.func, *value);
                let tuple = self.fold_call(env, call, depth)?;
                let Sym::Tuple(items) = tuple else { return None };
                items.get(*index as usize).cloned()
            }
            Expr::Call { .. } if !self.defined.contains(&r) => {
                self.fold_call(env, r, depth).filter(|s| !matches!(s, Sym::Tuple(_)))
            }
            _ => None,
        };
        match computed {
            Some(s) => Some(s),
            // A loop value the run did not compute stops it.
            None if self.defined.contains(&r) => None,
            // A binding before the loop the run cannot compute stands for
            // itself — the value it has on every trip, whatever it is.
            None => Some(Sym::Opaque(r)),
        }
    }

    /// The value a call before the loop returns, evaluated without
    /// touching the caller's memory; recorded so the call can be replaced.
    fn fold_call(&mut self, env: &HashMap<ValueId, Sym>, call: ValueId, depth: usize) -> Option<Sym> {
        if let Some((_, s)) = self.folded.iter().find(|(c, _)| *c == call) {
            return Some(s.clone());
        }
        let Expr::Call { target, args } = &self.func.bindings.get(call)?.expr else { return None };
        let args: Vec<Sym> = args.iter().map(|a| self.read(env, *a, depth + 1)).collect::<Option<_>>()?;
        let (saved, saved_site) = (self.memory_ok, self.site);
        self.memory_ok = false;
        self.site = Some(call);
        let mut stack = Stack::default();
        let out = self.call(*target, args, &mut stack, 0);
        self.memory_ok = saved;
        self.site = saved_site;
        let out = out?;
        self.folded.push((call, out.clone()));
        Some(out)
    }

    /// Evaluate a straight-line helper on `args`.
    fn call(&mut self, target: FuncId, args: Vec<Sym>, stack: &mut Stack, depth: usize) -> Option<Sym> {
        if depth >= MAX_DEPTH {
            return None;
        }
        let callee = self.ir.function(target)?;
        if callee.signature.is_some() || callee.params.len() != args.len() {
            trace(self.func, BlockId::from_index(0), &format!("helper func_{} takes {} arguments, given {}", target.index(), callee.params.len(), args.len()));
            return None;
        }
        let mut frame = Frame { func: callee, env: callee.params.iter().copied().zip(args).collect() };
        let entry_sp = stack.sp;
        let out = self.region(&mut frame, &callee.region, stack, depth);
        if out.is_none() {
            trace(self.func, BlockId::from_index(0), &format!("helper func_{} not evaluated", target.index()));
        }
        (stack.sp == entry_sp).then_some(out?)
    }

    /// Run a helper's straight-line region; the value its return hands
    /// back.
    fn region(&mut self, frame: &mut Frame<'_>, region: &Region, stack: &mut Stack, depth: usize) -> Option<Sym> {
        let items: &[Region] = match region {
            Region::Sequence(items) => items,
            other => std::slice::from_ref(other),
        };
        let (last, before) = items.split_last()?;
        for item in before {
            match item {
                Region::Basic(b) => {
                    if self.helper_block(frame, *b, stack, depth).is_none() {
                        trace(frame.func, *b, "helper block not run");
                        return None;
                    }
                }
                Region::Transfer { transfer, .. } => {
                    let values: Vec<(ValueId, Sym)> = transfer
                        .iter()
                        .map(|(p, s)| self.helper_read(frame, *s).map(|v| (*p, v)))
                        .collect::<Option<_>>()?;
                    frame.env.extend(values);
                }
                other => {
                    trace(frame.func, BlockId::from_index(0), &format!("helper region {}", region_name(other)));
                    return None;
                }
            }
        }
        let Region::Return { values } = last else {
            trace(frame.func, BlockId::from_index(0), &format!("helper ends in {}", region_name(last)));
            return None;
        };
        let out: Option<Vec<Sym>> = values.iter().map(|v| self.helper_read(frame, *v)).collect();
        let Some(mut out) = out else {
            let got: Vec<Option<Sym>> = values.iter().map(|v| self.helper_read(frame, *v)).collect();
            trace(frame.func, BlockId::from_index(0), &format!("helper returns {got:?}"));
            return None;
        };
        match out.len() {
            0 => Some(Sym::Unit),
            1 => out.pop(),
            _ => Some(Sym::Tuple(out)),
        }
    }

    fn helper_block(&mut self, frame: &mut Frame<'_>, block: BlockId, stack: &mut Stack, depth: usize) -> Option<()> {
        let func = frame.func;
        for &id in &func.blocks.get(block)?.bindings {
            self.steps += 1;
            if self.steps > MAX_STEPS * MAX_TRIPS {
                return None;
            }
            let b = func.bindings.get(id)?;
            let value = match &b.expr {
                Expr::GlobalGet { index: 0 } => Some(Sym::Addr { base: Base::Stack, off: stack.sp }),
                Expr::Unknown { op_kind: WasmOpcodeKind::GlobalSet, args, .. } => {
                    let [v] = args.as_slice() else { return None };
                    let Sym::Addr { base: Base::Stack, off } = self.helper_read(frame, *v)? else { return None };
                    stack.sp = off;
                    Some(Sym::Unit)
                }
                Expr::Store { addr, value, offset, width } => {
                    let a = self.helper_read(frame, *addr);
                    let v = self.helper_read(frame, *value);
                    let (Some(Sym::Addr { base: Base::Stack, off }), Some(v)) = (a.clone(), v.clone()) else {
                        trace(func, block, &format!("helper store v{}: address {a:?}, value {v:?}", id.index()));
                        return None;
                    };
                    let at = off.checked_add(i64::from(*offset))?;
                    // Its own frame, below the pointer it found.
                    if at + i64::from(width.bytes()) > 0 {
                        return None;
                    }
                    let end = at + i64::from(width.bytes());
                    stack.slots.retain(|o, (_, w)| *o + i64::from(w.bytes()) <= at || *o >= end);
                    stack.slots.insert(at, (v, *width));
                    Some(Sym::Unit)
                }
                Expr::Load { addr, offset, width, signed, ty } => match self.helper_read(frame, *addr)? {
                    Sym::Addr { base: Base::Stack, off } => {
                        let at = off.checked_add(i64::from(*offset))?;
                        match stack.slots.get(&at) {
                            Some((v, w)) if w == width => Some(v.clone()),
                            _ => {
                                trace(func, block, &format!("helper load v{} of an unwritten stack slot {at}", id.index()));
                                return None;
                            }
                        }
                    }
                    a => {
                        let (base, off) = caller_address(&a, *offset)?;
                        Some(self.load(base, off, *width, *signed, ty.clone())?)
                    }
                },
                Expr::Call { target, args } => {
                    let args: Vec<Sym> = args.iter().map(|a| self.helper_read(frame, *a)).collect::<Option<_>>()?;
                    Some(self.call(*target, args, stack, depth + 1)?)
                }
                Expr::Literal(Literal::Unit) => Some(Sym::Unit),
                other => {
                    let computed = self.helper_read(frame, id);
                    if computed.is_none() && !expr_effects(other).is_pure_total() {
                        trace(func, block, &format!("helper binding v{} not evaluated: {other:?}", id.index()));
                        return None;
                    }
                    computed
                }
            };
            if let Some(v) = value {
                frame.env.insert(id, v);
            }
        }
        Some(())
    }

    /// A helper's value: computed from its parameters and earlier bindings.
    fn helper_read(&mut self, frame: &Frame<'_>, v: ValueId) -> Option<Sym> {
        self.helper_value(frame, v, 0)
    }

    fn helper_value(&mut self, frame: &Frame<'_>, v: ValueId, depth: usize) -> Option<Sym> {
        if depth > 32 {
            return None;
        }
        if let Some(s) = frame.env.get(&v) {
            return Some(s.clone());
        }
        let b = frame.func.bindings.get(v)?;
        match &b.expr {
            Expr::Use(inner) => self.helper_value(frame, *inner, depth + 1),
            Expr::Literal(lit) => literal(lit),
            Expr::Binary { op, lhs, rhs } => {
                let (l, r) = (self.helper_value(frame, *lhs, depth + 1)?, self.helper_value(frame, *rhs, depth + 1)?);
                binary(*op, &l, &r)
            }
            Expr::Unary { op, value } => unary(*op, &self.helper_value(frame, *value, depth + 1)?),
            Expr::Select { cond, if_true, if_false } => {
                let c = self.helper_value(frame, *cond, depth + 1)?;
                self.helper_value(frame, if truth(&c)? { *if_true } else { *if_false }, depth + 1)
            }
            Expr::Unknown { op_kind: WasmOpcodeKind::Select, args, .. } if args.len() == 3 => {
                let c = self.helper_value(frame, args[2], depth + 1)?;
                self.helper_value(frame, if truth(&c)? { args[0] } else { args[1] }, depth + 1)
            }
            Expr::Project { value, index } => {
                let Sym::Tuple(items) = self.helper_value(frame, *value, depth + 1)? else { return None };
                items.get(*index as usize).cloned()
            }
            _ => None,
        }
    }
}

/// `(base, offset)` of a caller address, when it is one this rewrite can
/// spell as `store base <- … offset=k`.
fn caller_address(a: &Sym, offset: u32) -> Option<(ValueId, u32)> {
    let (base, off) = match a {
        Sym::Addr { base: Base::Caller(b), off } => (*b, *off),
        Sym::Opaque(b) => (*b, 0),
        _ => return None,
    };
    let at = off.checked_add(i64::from(offset))?;
    Some((base, u32::try_from(at).ok()?))
}

fn literal(lit: &Literal) -> Option<Sym> {
    Some(match lit {
        Literal::I32(n) => Sym::int(i64::from(*n), false),
        Literal::U32(n) => Sym::int(i64::from(*n), false),
        Literal::I64(n) => Sym::int(*n, true),
        Literal::U64(n) => Sym::int(*n as i64, true),
        Literal::Bool(b) => Sym::int(i64::from(*b), false),
        Literal::Unit => Sym::Unit,
        _ => return None,
    })
}

/// Which way a select (wasm's `select a b c`: `c != 0 ? a : b`) goes.
fn truth(c: &Sym) -> Option<bool> {
    let Sym::Int { bits, .. } = c else { return None };
    Some(*bits != 0)
}

fn unary(op: UnaryOp, x: &Sym) -> Option<Sym> {
    match (op, x) {
        (UnaryOp::Eqz, Sym::Int { bits, .. }) => Some(Sym::int(i64::from(*bits == 0), false)),
        _ => None,
    }
}

/// `l op r`, at the width the operands carry. An address is a 32-bit
/// value; an existing binding plus a 32-bit constant is an address.
fn binary(op: BinaryOp, l: &Sym, r: &Sym) -> Option<Sym> {
    use BinaryOp as B;
    match (l, r) {
        (Sym::Int { bits: a, wide: wa }, Sym::Int { bits: b, wide: wb }) if wa == wb => int_binary(op, *a, *b, *wa),
        // `fp + k`, either way round.
        (Sym::Opaque(v), Sym::Int { bits: k, wide: false }) | (Sym::Int { bits: k, wide: false }, Sym::Opaque(v))
            if op == B::Add =>
        {
            Some(Sym::Addr { base: Base::Caller(*v), off: *k })
        }
        (Sym::Addr { base, off }, Sym::Int { bits: k, wide: false }) | (Sym::Int { bits: k, wide: false }, Sym::Addr { base, off })
            if op == B::Add =>
        {
            Some(Sym::Addr { base: *base, off: off.checked_add(*k)? })
        }
        (Sym::Addr { base, off }, Sym::Int { bits: k, wide: false }) if op == B::Sub => {
            Some(Sym::Addr { base: *base, off: off.checked_sub(*k)? })
        }
        // Two addresses from one base differ by the constant between them,
        // and compare as their offsets do — modulo 2^32, as the words do.
        // A binding standing for itself is its own address plus nothing.
        _ => {
            let ((x, a), (y, b)) = (address(l)?, address(r)?);
            if x != y {
                return None;
            }
            let d = a.checked_sub(b)?;
            match op {
                B::Sub => Some(Sym::int(d, false)),
                B::Eq => Some(Sym::int(i64::from(d as i32 == 0), false)),
                B::Ne => Some(Sym::int(i64::from(d as i32 != 0), false)),
                _ => None,
            }
        }
    }
}

/// `(base, offset)` of a value read as an address.
fn address(s: &Sym) -> Option<(Base, i64)> {
    match s {
        Sym::Addr { base, off } => Some((*base, *off)),
        Sym::Opaque(v) => Some((Base::Caller(*v), 0)),
        _ => None,
    }
}

fn int_binary(op: BinaryOp, a: i64, b: i64, wide: bool) -> Option<Sym> {
    use BinaryOp as B;
    let bits = if wide { 64 } else { 32 };
    let (ua, ub) = if wide { (a as u64, b as u64) } else { (u64::from(a as u32), u64::from(b as u32)) };
    let flag = |x: bool| Some(Sym::int(i64::from(x), false));
    let shift = (b as u64 % bits) as u32;
    Some(match op {
        B::Add => Sym::int(a.wrapping_add(b), wide),
        B::Sub => Sym::int(a.wrapping_sub(b), wide),
        B::Mul => Sym::int(a.wrapping_mul(b), wide),
        B::BitAnd => Sym::int(a & b, wide),
        B::BitOr => Sym::int(a | b, wide),
        B::BitXor => Sym::int(a ^ b, wide),
        B::Shl => Sym::int(if wide { a.wrapping_shl(shift) } else { i64::from((a as i32).wrapping_shl(shift)) }, wide),
        B::ShrU => Sym::int((ua >> shift) as i64, wide),
        B::Shr => Sym::int(if wide { a >> shift } else { i64::from((a as i32) >> shift) }, wide),
        B::Eq => return flag(ua == ub),
        B::Ne => return flag(ua != ub),
        B::LtU => return flag(ua < ub),
        B::LeU => return flag(ua <= ub),
        B::GtU => return flag(ua > ub),
        B::GeU => return flag(ua >= ub),
        B::Lt => return flag(signed(a, wide) < signed(b, wide)),
        B::Le => return flag(signed(a, wide) <= signed(b, wide)),
        B::Gt => return flag(signed(a, wide) > signed(b, wide)),
        B::Ge => return flag(signed(a, wide) >= signed(b, wide)),
        _ => return None,
    })
}

fn signed(x: i64, wide: bool) -> i64 {
    if wide { x } else { i64::from(x as i32) }
}

// ---------------------------------------------------------------------
// The rewrite
// ---------------------------------------------------------------------

fn new_binding(func: &mut HighFunction, ty: IrType, expr: Expr, note: String) -> ValueId {
    let id = ValueId::from_index(func.bindings.len() as u32);
    func.bindings.push(Binding::new(id, ty, expr, Provenance::new(PASS_NAME, ProvenanceSource::DataFlow, note)));
    id
}

fn literal_binding(func: &mut HighFunction, bits: i64, wide: bool, note: &str) -> ValueId {
    let (ty, lit) = if wide {
        (KnownType::I64, Literal::I64(bits))
    } else {
        (KnownType::I32, Literal::I32(bits as i32))
    };
    new_binding(func, IrType::Known(ty), Expr::Literal(lit), note.to_string())
}

/// `value` as an expression to put at binding `at`: a literal, a rename,
/// or a binding plus a literal scheduled just before `at`.
fn name_value(func: &mut HighFunction, at: ValueId, value: &Sym, note: &str) -> Option<Expr> {
    Some(match value {
        Sym::Int { bits, wide } => Expr::Literal(if *wide { Literal::I64(*bits) } else { Literal::I32(*bits as i32) }),
        Sym::Opaque(v) | Sym::Addr { base: Base::Caller(v), off: 0 } => Expr::Use(*v),
        Sym::Addr { base: Base::Caller(v), off } if *off > 0 => {
            let k = literal_binding(func, *off, false, note);
            let home = func.blocks.iter().find_map(|(bid, b)| b.bindings.contains(&at).then_some(bid));
            if let Some(block) = home
                && let Some(b) = func.blocks.get_mut(block)
                && let Some(pos) = b.bindings.iter().position(|x| *x == at)
            {
                b.bindings.insert(pos, k);
            }
            Expr::Binary { op: BinaryOp::Add, lhs: *v, rhs: k }
        }
        _ => return None,
    })
}

fn apply(func: &mut HighFunction, root: Region, plan: &Plan) {
    func.region = root;
    // What the loop defined is gone with it — its merges too, which would
    // otherwise go on reading the values its entry handed them. Nothing
    // reads any of it (`reads_nothing_it_defined`).
    for id in &plan.defined {
        if let Some(b) = func.bindings.get_mut(*id) {
            b.expr = Expr::Literal(Literal::Unit);
            b.ty = IrType::Known(KnownType::Unit);
            b.add_provenance(Provenance::new(PASS_NAME, ProvenanceSource::DataFlow, "defined by a loop replaced by its run"));
        }
    }
    let note = format!(
        "the loop at block {} run from its entry: {} trips, its accesses in order",
        plan.header.index(),
        plan.trips
    );

    // The calls the entry read, as the values they return.
    for (call, value) in &plan.folded {
        if !matches!(value, Sym::Tuple(_)) {
            let call_note = "a call evaluated on its arguments and the values its caller stored where it reads, \
                             which writes no memory of its caller: the value it returns";
            if let Some(expr) = name_value(func, *call, value, call_note)
                && let Some(b) = func.bindings.get_mut(*call)
            {
                b.expr = expr;
                b.add_provenance(Provenance::new(PASS_NAME, ProvenanceSource::DataFlow, call_note));
            }
            continue;
        }
        let Sym::Tuple(items) = value else { continue };
        let projections: Vec<(ValueId, u32)> = func
            .bindings
            .iter()
            .filter_map(|(id, b)| match &b.expr {
                Expr::Project { value, index } if *value == *call => Some((id, *index)),
                _ => None,
            })
            .collect();
        for (p, index) in projections {
            let Some(item) = items.get(index as usize) else { continue };
            let call_note = format!("component {index} of a call evaluated on its arguments, which writes no memory of its caller");
            let Some(expr) = name_value(func, p, item, &call_note) else { continue };
            if let Some(b) = func.bindings.get_mut(p) {
                b.expr = expr;
                b.add_provenance(Provenance::new(PASS_NAME, ProvenanceSource::DataFlow, call_note));
            }
        }
        if let Some(b) = func.bindings.get_mut(*call) {
            b.expr = Expr::Literal(Literal::Unit);
            b.ty = IrType::Known(KnownType::Unit);
            b.add_provenance(Provenance::new(
                PASS_NAME,
                ProvenanceSource::DataFlow,
                "a call with no effect on its caller, replaced by the values it returns",
            ));
        }
    }

    // A rename of a component the rewrite replaced, left from an earlier
    // pass, scheduled nowhere and read by nothing, still counts as a reader
    // of that component ([`crate::dataflow::dead_residue`] keeps every
    // unscheduled binding, for block parameters' sake). It emits nothing;
    // retired, the component is as unread as it is.
    retire_unread_renames(func);

    // The loop's accesses, at the top of the code after it.
    let mut emitted: Vec<ValueId> = Vec::new();
    let mut loaded: HashMap<usize, ValueId> = HashMap::new();
    for (i, effect) in plan.effects.iter().enumerate() {
        match effect {
            Effect::Load { base, off, width, signed, ty } => {
                let id = new_binding(
                    func,
                    IrType::Unknown(UnknownReason::InsufficientEvidence),
                    Expr::Load { addr: *base, offset: *off, width: *width, signed: *signed, ty: ty.clone() },
                    note.clone(),
                );
                loaded.insert(i, id);
                emitted.push(id);
            }
            Effect::Store { base, off, width, value } => {
                let v = match value {
                    Sym::Int { bits, wide } => {
                        let k = literal_binding(func, *bits, *wide, &note);
                        emitted.push(k);
                        k
                    }
                    Sym::Opaque(v) => *v,
                    Sym::Loaded(j) => match loaded.get(j) {
                        Some(v) => *v,
                        None => continue,
                    },
                    _ => continue,
                };
                let id = new_binding(
                    func,
                    IrType::Known(KnownType::Unit),
                    Expr::Store { addr: *base, value: v, offset: *off, width: *width },
                    note.clone(),
                );
                emitted.push(id);
            }
        }
    }
    if let Some(block) = func.blocks.get_mut(plan.exit_block) {
        block.bindings.splice(0..0, emitted);
    }
}

fn retire_unread_renames(func: &mut HighFunction) {
    // Everything this rewrite replaced carries its provenance last: the
    // loop's own bindings, the folded call and its components.
    let mut replaced: HashSet<ValueId> = HashSet::new();
    for (id, b) in func.bindings.iter() {
        if b.provenance().last().is_some_and(|p| p.pass == PASS_NAME) {
            replaced.insert(id);
        }
    }
    let scheduled: HashSet<ValueId> = func.blocks.iter().flat_map(|(_, b)| b.bindings.iter().copied()).collect();
    let mut read: HashSet<ValueId> = HashSet::new();
    for (_, b) in func.bindings.iter() {
        b.expr.for_each_value_use(|u| {
            read.insert(u);
        });
    }
    func.region.for_each_value_use(|u| {
        read.insert(u);
    });
    let retire: Vec<ValueId> = func
        .bindings
        .iter()
        .filter(|(id, b)| {
            matches!(b.expr, Expr::Use(x) if replaced.contains(&x)) && !scheduled.contains(id) && !read.contains(id)
        })
        .map(|(id, _)| id)
        .collect();
    for id in retire {
        if let Some(b) = func.bindings.get_mut(id) {
            b.expr = Expr::Literal(Literal::Unit);
            b.ty = IrType::Known(KnownType::Unit);
            b.add_provenance(Provenance::new(
                PASS_NAME,
                ProvenanceSource::DataFlow,
                "an unscheduled, unread rename of a value the loop's run replaced",
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, load, module, store, v};
    use sordec_common::Arena;
    use sordec_ir::{HighBlock, LoopKind};

    fn b(i: u32) -> BlockId {
        BlockId::from_index(i)
    }

    fn lit32(n: i32) -> Expr {
        Expr::Literal(Literal::I32(n))
    }

    fn add(l: u32, r: u32) -> Expr {
        Expr::Binary { op: BinaryOp::Add, lhs: v(l), rhs: v(r) }
    }

    /// A function over `exprs`, its bindings split into blocks.
    fn function(exprs: Vec<Expr>, params: Vec<ValueId>, blocks: Vec<Vec<u32>>, region: Region) -> HighFunction {
        let mut f = func_with(exprs, params, vec![]);
        let mut arena: Arena<BlockId, HighBlock> = Arena::new();
        for (i, ids) in blocks.into_iter().enumerate() {
            arena.push(HighBlock { id: b(i as u32), bindings: ids.into_iter().map(v).collect() });
        }
        f.blocks = arena;
        f.region = region;
        f
    }

    /// `items` at `fp+64..`, a three-slot `tmp` at `fp+0`, and the copy
    /// loop `while n != 0 { *dst = conv(src); … }`, its bounds read from a
    /// call to the zip constructor `func_1`; the code after it builds the
    /// vec from `tmp`. With `through_helper`, each element goes through
    /// `func_2` (the `into_val` that reads the word behind its pointer);
    /// without, it is a plain load.
    fn caller(through_helper: bool, trips_from_zip: bool) -> HighFunction {
        let conv = if through_helper {
            Expr::Call { target: FuncId::from_index(2), args: vec![v(21)] }
        } else {
            load(v(21), 0)
        };
        let n0 = if trips_from_zip { Expr::Project { value: v(9), index: 5 } } else { Expr::Phi { incoming: vec![] } };
        function(
            vec![
                Expr::Phi { incoming: vec![] },                    // v0 fp
                lit32(64),                                         // v1
                add(0, 1),                                         // v2 items = fp+64
                Expr::Phi { incoming: vec![] },                    // v3 a
                store(v(2), v(3), 0),                              // v4
                Expr::Phi { incoming: vec![] },                    // v5 b
                store(v(2), v(5), 8),                              // v6
                lit32(16),                                         // v7
                add(0, 7),                                         // v8 tmp end = fp+16
                Expr::Call { target: FuncId::from_index(1), args: vec![v(0), v(8), v(2), v(18)] }, // v9 zip
                Expr::Project { value: v(9), index: 0 },           // v10 dst0
                Expr::Project { value: v(9), index: 2 },           // v11 src0
                n0,                                                // v12 n0
                Expr::Phi { incoming: vec![] },                    // v13 n
                Expr::Phi { incoming: vec![] },                    // v14 dst
                Expr::Phi { incoming: vec![] },                    // v15 src
                Expr::Unary { op: UnaryOp::Eqz, value: v(13) },    // v16 cond
                lit32(2),                                          // v17 count
                add(0, 28),                                        // v18 items end = fp+80
                Expr::Semantic(sordec_ir::SemanticOp::Known(sordec_ir::KnownOp::VecNew {
                    vals_pos: v(0),
                    len: v(17),
                    elements: None,
                })),                                               // v19
                lit32(8),                                          // v20
                Expr::Use(v(15)),                                  // v21 src (for conv)
                conv,                                              // v22 word
                store(v(14), v(22), 0),                            // v23
                lit32(-1),                                         // v24
                add(13, 24),                                       // v25 n - 1
                add(14, 20),                                       // v26 dst + 8
                add(15, 20),                                       // v27 src + 8
                lit32(80),                                         // v28
            ],
            vec![v(0), v(3), v(5)],
            vec![vec![1, 2, 4, 6, 7, 8, 18, 9, 10, 11, 12], vec![16], vec![17, 19], vec![21, 22, 23, 24, 25, 26, 27]],
            Region::Sequence(vec![
                Region::Basic(b(0)),
                Region::Transfer { target: b(1), transfer: vec![(v(13), v(12)), (v(14), v(10)), (v(15), v(11))] },
                Region::Loop {
                    header: b(1),
                    kind: LoopKind::Unclassified,
                    body: Box::new(Region::Sequence(vec![
                        Region::Basic(b(1)),
                        Region::If {
                            cond: v(16),
                            then_region: Box::new(Region::Sequence(vec![
                                Region::Basic(b(2)),
                                Region::Return { values: vec![v(19)] },
                            ])),
                            else_region: None,
                        },
                        Region::Basic(b(3)),
                        Region::Continue {
                            target: b(1),
                            transfer: vec![(v(13), v(25)), (v(14), v(26)), (v(15), v(27))],
                        },
                    ])),
                },
            ]),
        )
    }

    /// The zip constructor: `(a, b, c, d, 0, min((b - a) / 8, (d - c) / 8))`,
    /// one of the lengths through its own frame, as rustc leaves it.
    fn zip() -> HighFunction {
        let mut f = function(
            vec![
                Expr::Phi { incoming: vec![] },                    // v0 a
                Expr::Phi { incoming: vec![] },                    // v1 b
                Expr::Phi { incoming: vec![] },                    // v2 c
                Expr::Phi { incoming: vec![] },                    // v3 d
                Expr::GlobalGet { index: 0 },                      // v4 sp
                lit32(16),                                         // v5
                Expr::Binary { op: BinaryOp::Sub, lhs: v(4), rhs: v(5) }, // v6 frame
                Expr::Unknown { op_kind: WasmOpcodeKind::GlobalSet, args: vec![v(6)], reason: UnknownReason::UnsupportedPattern }, // v7
                Expr::Store { addr: v(6), value: v(0), offset: 8, width: MemWidth::W4 }, // v8
                Expr::Store { addr: v(6), value: v(1), offset: 12, width: MemWidth::W4 }, // v9
                Expr::Load { addr: v(6), offset: 8, width: MemWidth::W4, signed: None, ty: IrType::Unknown(UnknownReason::InsufficientEvidence) }, // v10
                Expr::Load { addr: v(6), offset: 12, width: MemWidth::W4, signed: None, ty: IrType::Unknown(UnknownReason::InsufficientEvidence) }, // v11
                lit32(3),                                          // v12
                Expr::Binary { op: BinaryOp::Sub, lhs: v(11), rhs: v(10) }, // v13
                Expr::Binary { op: BinaryOp::ShrU, lhs: v(13), rhs: v(12) }, // v14 len a
                Expr::Binary { op: BinaryOp::Sub, lhs: v(3), rhs: v(2) },   // v15
                Expr::Binary { op: BinaryOp::ShrU, lhs: v(15), rhs: v(12) }, // v16 len b
                Expr::Binary { op: BinaryOp::LtU, lhs: v(16), rhs: v(14) }, // v17
                Expr::Unknown { op_kind: WasmOpcodeKind::Select, args: vec![v(16), v(14), v(17)], reason: UnknownReason::UnsupportedPattern }, // v18
                Expr::Binary { op: BinaryOp::Add, lhs: v(6), rhs: v(5) }, // v19
                Expr::Unknown { op_kind: WasmOpcodeKind::GlobalSet, args: vec![v(19)], reason: UnknownReason::UnsupportedPattern }, // v20
                lit32(0),                                          // v21
            ],
            vec![v(0), v(1), v(2), v(3)],
            vec![(4..=21).collect()],
            Region::Sequence(vec![
                Region::Basic(b(0)),
                Region::Return { values: vec![v(0), v(1), v(2), v(3), v(21), v(18)] },
            ]),
        );
        f.id = FuncId::from_index(1);
        f
    }

    /// `into_val` for a handle: the word behind the pointer, through an
    /// inner helper (`func_3`) returning `(0, word)`.
    fn deref_outer() -> HighFunction {
        let mut f = function(
            vec![
                Expr::Phi { incoming: vec![] },                                  // v0 p
                Expr::Call { target: FuncId::from_index(3), args: vec![v(0)] }, // v1
                Expr::Project { value: v(1), index: 1 },                         // v2
            ],
            vec![v(0)],
            vec![vec![1, 2]],
            Region::Sequence(vec![Region::Basic(b(0)), Region::Return { values: vec![v(2)] }]),
        );
        f.id = FuncId::from_index(2);
        f
    }

    fn deref_inner() -> HighFunction {
        let mut f = function(
            vec![
                Expr::Phi { incoming: vec![] }, // v0 p
                load(v(0), 0),                  // v1
                Expr::Literal(Literal::I64(0)), // v2
            ],
            vec![v(0)],
            vec![vec![1, 2]],
            Region::Sequence(vec![Region::Basic(b(0)), Region::Return { values: vec![v(2), v(1)] }]),
        );
        f.id = FuncId::from_index(3);
        f
    }

    fn ir(caller: HighFunction) -> HighIr {
        module(vec![caller, zip(), deref_outer(), deref_inner()])
    }

    fn stores(func: &HighFunction, block: BlockId) -> Vec<(ValueId, u32, ValueId)> {
        func.blocks
            .get(block)
            .unwrap()
            .bindings
            .iter()
            .filter_map(|id| match &func.bindings.get(*id).unwrap().expr {
                Expr::Store { addr, offset, value, .. } => Some((*addr, *offset, *value)),
                _ => None,
            })
            .collect()
    }

    /// The copy runs two trips — the zip's shorter side — and leaves two
    /// loads of `items` and two stores into `tmp`, ahead of the vec, with
    /// the loop gone and the zip call replaced by its values.
    #[test]
    fn the_copy_loop_becomes_its_loads_and_stores() {
        for through_helper in [false, true] {
            let mut m = ir(caller(through_helper, true));
            assert!(FromArrayLoopPass.run(&mut m).changed, "helper: {through_helper}");
            let f = &m.functions[0];
            assert!(matches!(&f.region, Region::Sequence(items) if !items.iter().any(|r| matches!(r, Region::Loop { .. }))));
            let s = stores(f, b(2));
            assert_eq!(s.len(), 2, "{s:?}");
            for (k, (addr, offset, value)) in s.iter().enumerate() {
                assert_eq!((*addr, *offset), (v(0), 8 * k as u32), "into tmp");
                let Expr::Load { addr, offset, .. } = &f.bindings.get(*value).unwrap().expr else {
                    panic!("a load of items");
                };
                assert_eq!((*addr, *offset), (v(0), 64 + 8 * k as u32));
            }
            assert!(matches!(f.bindings.get(v(9)).unwrap().expr, Expr::Literal(Literal::Unit)), "zip folded");
            assert!(matches!(f.bindings.get(v(10)).unwrap().expr, Expr::Use(x) if x == v(0)));
        }
    }

    /// A trip count the run cannot compute — here a parameter — leaves
    /// the loop alone.
    #[test]
    fn a_loop_whose_count_is_unknown_stays() {
        let mut m = ir(caller(false, false));
        assert!(!FromArrayLoopPass.run(&mut m).changed);
        assert!(matches!(&m.functions[0].region, Region::Sequence(items) if items.iter().any(|r| matches!(r, Region::Loop { .. }))));
    }

    /// A loop that runs but writes past the buffer the vec after it reads
    /// builds something else: it stays.
    #[test]
    fn a_loop_writing_outside_the_vec_buffer_stays() {
        let mut f = caller(false, true);
        f.bindings.get_mut(v(17)).unwrap().expr = lit32(1); // a one-element vec
        let mut m = ir(f);
        assert!(!FromArrayLoopPass.run(&mut m).changed);
    }

    /// A helper that writes its caller's memory is not a value: the run
    /// stops.
    #[test]
    fn a_helper_writing_its_callers_memory_stops_the_run() {
        let mut m = ir(caller(true, true));
        // The inner helper now also stores through its pointer.
        let inner = &mut m.functions[3];
        let id = ValueId::from_index(inner.bindings.len() as u32);
        inner.bindings.push(Binding::new(
            id,
            IrType::Known(KnownType::Unit),
            store(v(0), v(2), 0),
            Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
        ));
        inner.blocks.get_mut(b(0)).unwrap().bindings.push(id);
        assert!(!FromArrayLoopPass.run(&mut m).changed);
    }

    /// The code after the loop reading the loop's counter keeps the loop.
    #[test]
    fn a_counter_read_after_the_loop_keeps_it() {
        let mut f = caller(false, true);
        f.region = match f.region {
            Region::Sequence(mut items) => {
                if let Some(Region::Loop { body, .. }) = items.get_mut(2)
                    && let Region::Sequence(xs) = body.as_mut()
                    && let Some(Region::If { then_region, .. }) = xs.get_mut(1)
                {
                    **then_region = Region::Sequence(vec![
                        Region::Basic(b(2)),
                        Region::Return { values: vec![v(14)] },
                    ]);
                }
                Region::Sequence(items)
            }
            other => other,
        };
        let mut m = ir(f);
        assert!(!FromArrayLoopPass.run(&mut m).changed);
    }
}
