//! Fold a loop whose start is constant into the value it exits with.
//!
//! # The shape
//!
//! `Symbol::new(&env, "V2")` builds its symbol with a loop over the
//! string's bytes. When the call is inlined into an entrypoint rather than
//! outlined into a helper, the loop sits in the entrypoint itself, and
//! nothing about it varies from one run to the next:
//!
//! ```text
//! i = -2; acc = 0                       // the string's length, negated
//! loop {
//!     if i == 0 { r = acc << 8 | 14; break }          // SymbolSmall
//!     c = load8(i + 1048578)                           // "V2" in rodata
//!     if c is not [0-9A-Za-z] { r = symbol_new(..); break }
//!     acc = acc << 6 | (c + k) & 255; i += 1
//! }
//! v = vec![r]                    →      r = symbol_short!("V2")
//! ```
//!
//! The helper form is folded by [`crate::recognizers::symbol_encoder`],
//! which matches the helper by its constants and reads the string at each
//! call site. Inlined, there is no call site: the loop's start state, its
//! bytes and its exit are all in the one function.
//!
//! # The rewrite
//!
//! The loop is run, here, on its own constants. When it reaches its exit
//! without having done anything but arithmetic and reads of the module's
//! data, the value it hands to the code after it is a constant word; the
//! loop goes, the code after it stays in place, and the word is scheduled
//! where that code begins — read through its decode, never as a number.
//! Above, `r` is the `SymbolSmall` word of `"V2"`, so it becomes the symbol
//! `"V2"`, which the passes after this one read as the variant name it is.
//!
//! Only a word that is a symbol is named, and only where the loop says so
//! itself: the exit must also be reachable from the loop's own fallback,
//! which hands the same merge `Symbol::new` of the same text. That arm is
//! what proves the merge holds a `Val` rather than a number — a constant
//! word whose low byte happens to read as a symbol tag is otherwise just a
//! number, and printing it as a symbol would change it.
//!
//! # Why it is exact
//!
//! It is the loop's own execution. Every value the run reads is a literal,
//! a value computed from literals on the same run, or a byte of the
//! module's data — so every run of the function computes the same values,
//! takes the same branches and leaves at the same place with the same
//! values. Nothing on that path writes memory, calls, or traps, so dropping
//! the loop drops no effect; the paths it did not take never run. The code
//! after the loop reads nothing the loop computed except the value its
//! exit receives, and that is now the symbol whose encoding is the word the
//! run found: a small symbol's `Val` is exactly its packed characters and
//! tag, so `symbol_short!` of the decoded text is the same bits.
//!
//! Arithmetic is done at the width the program says: a literal's own
//! width, a load's result type, and the width moves (`wrap`, `extend`) —
//! never a type a pass inferred. Two operands of different widths stop the
//! run.
//!
//! The one assumption is the one every rodata reader in this pipeline
//! makes ([`super::const_load`], symbol-text recovery): the bytes read are
//! still what the data segment put there. As there, the part that can be
//! proven is: no store through a constant address anywhere in the module
//! touches them, and each read lies inside one segment.
//!
//! # Gates
//!
//! - **The loop's shape**: its body is a labeled scope followed by the
//!   code after the loop, which starts with the scope's exit block, ends
//!   by leaving (a return, a break outward, a panic) and never goes round
//!   again. Inside the scope, every exit goes to that exit block, back to
//!   the loop's header, or somewhere else inside the scope — no return,
//!   no break further out.
//! - **A constant start**: every value the header receives is given on the
//!   way in, by the transfer just before the loop, and each is a literal
//!   or computed from literals.
//! - **The run**: only literals, integer arithmetic, comparisons, width
//!   moves, selects and loads of the module's data, on the path taken;
//!   anything else stops it. At most [`MAX_ITERATIONS`] trips round and
//!   [`MAX_STEPS`] bindings run.
//! - **What leaves**: a 64-bit word that decodes as a small symbol, at a
//!   merge another edge of the loop hands a symbol of the same text. Nothing
//!   else the loop computed is read after it.

use std::collections::{HashMap, HashSet};

use sordec_common::{BlockId, IrId, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{
    BinaryOp, Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Literal, MemWidth, MemoryImage, Region,
    SemanticOp, UnaryOp,
};

use super::const_load::{overlaps, width_bytes, written_constants};
use crate::dataflow::resolve_use;
use crate::val_abi::decode_small_symbol;
use crate::metrics_catalog::REFINE_CONST_LOOPS_FOLDED as M_FOLDED;
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field for every fold.
pub const PASS_NAME: &str = "refine-const-loop";

/// Trips round a loop the run will make before giving up. A symbol is at
/// most 32 characters, and a constant loop worth folding is short.
const MAX_ITERATIONS: usize = 64;

/// Bindings the run will execute before giving up.
const MAX_STEPS: usize = 4096;

/// How deep a value defined before the loop may be computed from others.
const MAX_DEPTH: usize = 16;

/// Folds loops whose start is constant into the values they exit with.
#[derive(Debug, Default, Clone, Copy)]
pub struct ConstLoopFoldPass;

impl Pass<HighIr> for ConstLoopFoldPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let written = written_constants(ir);
        let memory = &ir.memory;
        for func in &mut ir.functions {
            let mut refused: HashSet<BlockId> = HashSet::new();
            while let Some((root, plan)) = next_fold(func, memory, &written, &refused) {
                if !read_only_at_exit(func, &root, &plan) {
                    refused.insert(plan.header);
                    continue;
                }
                apply(func, root, &plan);
                result.metrics.increment(M_FOLDED, 1);
                result.changed = true;
            }
        }
        if result.changed {
            super::debug_validate(ir, PASS_NAME);
        }
        result
    }
}

/// One loop the run finished, and what replaces it.
struct Plan {
    header: BlockId,
    exit: BlockId,
    /// The symbols the exit receives, as the run found them.
    folds: Vec<(ValueId, String)>,
    /// Everything the loop defines: its blocks' bindings and the merges
    /// its edges assign.
    defined: HashSet<ValueId>,
    iterations: usize,
}

/// The function's region with the first loop that runs to completion
/// replaced by the code after it, and the plan for its values.
fn next_fold(
    func: &HighFunction,
    memory: &MemoryImage,
    written: &[(u32, u32)],
    refused: &HashSet<BlockId>,
) -> Option<(Region, Plan)> {
    let mut plan: Option<Plan> = None;
    let root = rebuild(&func.region, &mut |entry, lp| {
        if plan.is_some() {
            return None;
        }
        let (p, rest) = plan_loop(func, memory, written, refused, entry, lp)?;
        plan = Some(p);
        Some(rest)
    })?;
    Some((root, plan?))
}

/// Asked of each loop with the region just before it (the transfer that
/// enters it, when there is one): the regions to put in its place, if it
/// folds.
type LoopFold<'a> = dyn FnMut(Option<&Region>, &Region) -> Option<Vec<Region>> + 'a;

/// `region` with the first loop `fold` accepts replaced by the regions it
/// returns, and the transfer that entered the loop dropped; `None` if no
/// loop in it was accepted.
fn rebuild(region: &Region, fold: &mut LoopFold<'_>) -> Option<Region> {
    match region {
        Region::Sequence(items) => {
            for (i, item) in items.iter().enumerate() {
                if let Region::Loop { header, .. } = item {
                    let entry = i.checked_sub(1).map(|j| &items[j]);
                    if let Some(rest) = fold(entry, item) {
                        let enters = entry.is_some_and(|e| matches!(e, Region::Transfer { target, .. } if target == header));
                        let mut out: Vec<Region> = items[..i - usize::from(enters)].to_vec();
                        out.push(Region::Sequence(rest));
                        out.extend(items[i + 1..].iter().cloned());
                        return Some(Region::Sequence(out));
                    }
                }
                if let Some(new) = rebuild(item, fold) {
                    let mut out = items.clone();
                    out[i] = new;
                    return Some(Region::Sequence(out));
                }
            }
            None
        }
        Region::Scope { out, body } => {
            rebuild(body, fold).map(|b| Region::Scope { out: *out, body: Box::new(b) })
        }
        Region::If { cond, then_region, else_region } => {
            if let Some(t) = rebuild(then_region, fold) {
                return Some(Region::If { cond: *cond, then_region: Box::new(t), else_region: else_region.clone() });
            }
            let e = rebuild(else_region.as_deref()?, fold)?;
            Some(Region::If { cond: *cond, then_region: then_region.clone(), else_region: Some(Box::new(e)) })
        }
        Region::Loop { header, body, kind } => {
            rebuild(body, fold).map(|b| Region::Loop { header: *header, body: Box::new(b), kind: *kind })
        }
        Region::Switch { index, arms, default, dispatch } => {
            for (k, arm) in arms.iter().enumerate() {
                if let Some(b) = rebuild(&arm.body, fold) {
                    let mut arms = arms.clone();
                    arms[k].body = b;
                    return Some(Region::Switch { index: *index, arms, default: default.clone(), dispatch: *dispatch });
                }
            }
            let d = rebuild(default, fold)?;
            Some(Region::Switch { index: *index, arms: arms.clone(), default: Box::new(d), dispatch: *dispatch })
        }
        _ => None,
    }
}

/// Run `lp` from the transfer `entry` that enters it; the plan and the
/// code after the loop, when every gate but the last holds.
fn plan_loop(
    func: &HighFunction,
    memory: &MemoryImage,
    written: &[(u32, u32)],
    refused: &HashSet<BlockId>,
    entry: Option<&Region>,
    lp: &Region,
) -> Option<(Plan, Vec<Region>)> {
    let Region::Loop { header, body, .. } = lp else { return None };
    if refused.contains(header) {
        return None;
    }
    let Region::Sequence(items) = body.as_ref() else { return None };
    let (scope, rest) = items.split_first()?;
    let Region::Scope { out: exit, .. } = scope else { return None };
    if !matches!(rest.first(), Some(Region::Basic(b)) if b == exit) || !leaves(rest) || goes_to(rest, *header) {
        return None;
    }

    let mut shape = Shape::default();
    if !shape.walk(scope, *header, *exit, &mut Vec::new()) || !shape.falls_inside() {
        return None;
    }
    let entered: Vec<(ValueId, ValueId)> = match entry {
        Some(Region::Transfer { target, transfer }) if target == header => transfer.clone(),
        _ => Vec::new(),
    };
    if shape.header_phis.iter().any(|p| !entered.iter().any(|(q, _)| q == p)) {
        return None;
    }

    let mut defined: HashSet<ValueId> = HashSet::new();
    for block in &shape.blocks {
        defined.extend(func.blocks.get(*block)?.bindings.iter().copied());
    }
    defined.extend(shape.phis.iter().copied());
    defined.extend(entered.iter().map(|(p, _)| *p));

    let mut run = Run { func, memory, written, defined: &defined, env: HashMap::new(), steps: 0 };
    let mut start = Vec::with_capacity(entered.len());
    for (phi, source) in &entered {
        start.push((*phi, run.read(*source, 0)?));
    }
    run.env.extend(start);

    let mut iterations = 0;
    loop {
        for phi in &shape.exit_phis {
            run.env.remove(phi);
        }
        match run.region(scope)? {
            Flow::Next => break,
            Flow::Continue(h) if h == *header => {
                iterations += 1;
                if iterations > MAX_ITERATIONS {
                    return None;
                }
            }
            Flow::Continue(_) | Flow::Break(_) => return None,
        }
    }
    // Each value the exit received, named when it is a symbol another of
    // the loop's own edges hands the same merge.
    let folds: Vec<(ValueId, String)> = shape
        .exit_phis
        .iter()
        .filter_map(|p| {
            let word = run.env.get(p)?;
            let text = word.wide.then(|| decode_small_symbol(word.bits)).flatten()?;
            let witnessed = shape
                .exit_arms
                .iter()
                .any(|(q, source)| q == p && symbol_text(func, *source).as_deref() == Some(text.as_str()));
            witnessed.then_some((*p, text))
        })
        .collect();
    if folds.is_empty() {
        return None;
    }
    Some((Plan { header: *header, exit: *exit, folds, defined, iterations }, rest.to_vec()))
}

/// Whether nothing the loop defined is read in `root` — the function's
/// region with the loop replaced — except the values its exit receives.
fn read_only_at_exit(func: &HighFunction, root: &Region, plan: &Plan) -> bool {
    let folded: HashSet<ValueId> = plan.folds.iter().map(|(p, _)| *p).collect();
    let gone = |v: ValueId| plan.defined.contains(&v) && !folded.contains(&v);
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

/// The text of a symbol built from a string the pipeline resolved.
fn symbol_text(func: &HighFunction, value: ValueId) -> Option<String> {
    match &func.bindings.get(resolve_use(func, value))?.expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::SymbolNew { resolved: Some(text), .. })) => Some(text.clone()),
        Expr::Literal(Literal::Symbol(text)) => Some(text.clone()),
        _ => None,
    }
}

/// Install `root` and turn each symbol the exit receives into its literal,
/// scheduled first in the exit block.
fn apply(func: &mut HighFunction, root: Region, plan: &Plan) {
    func.region = root;
    let mut scheduled = Vec::with_capacity(plan.folds.len());
    for (phi, text) in &plan.folds {
        let Some(binding) = func.bindings.get_mut(*phi) else { continue };
        binding.expr = Expr::Literal(Literal::Symbol(text.clone()));
        binding.ty = IrType::Known(KnownType::Symbol);
        binding.add_provenance(Provenance::new(
            PASS_NAME,
            ProvenanceSource::DataFlow,
            format!(
                "the symbol {text:?} the loop at block {} exits with, run from its constant start \
                 ({} trips round; data segments assumed read-only, as rodata recovery assumes)",
                plan.header.index(),
                plan.iterations,
            ),
        ));
        scheduled.push(*phi);
    }
    if let Some(block) = func.blocks.get_mut(plan.exit) {
        block.bindings.splice(0..0, scheduled);
    }
}

/// Whether control never falls out of the bottom of `items`.
fn leaves(items: &[Region]) -> bool {
    fn leaves_one(region: &Region) -> bool {
        match region {
            Region::Return { .. }
            | Region::Break { .. }
            | Region::Panic { .. }
            | Region::Unreachable => true,
            Region::Sequence(items) => items.last().is_some_and(leaves_one),
            Region::Scope { body, .. } => leaves_one(body),
            Region::If { then_region, else_region: Some(e), .. } => leaves_one(then_region) && leaves_one(e),
            _ => false,
        }
    }
    items.last().is_some_and(leaves_one)
}

/// Whether any region in `items` continues the loop at `header`.
fn goes_to(items: &[Region], header: BlockId) -> bool {
    let mut found = false;
    for item in items {
        item.for_each_node(|node| {
            found |= matches!(node, Region::Continue { target, .. } if *target == header);
        });
    }
    found
}

/// What the scope inside a loop is made of.
#[derive(Default)]
struct Shape {
    /// Every block it runs.
    blocks: Vec<BlockId>,
    /// Every merge an edge inside it assigns.
    phis: HashSet<ValueId>,
    /// The merges the edges back to the header assign.
    header_phis: HashSet<ValueId>,
    /// The merges the edges to the exit block assign, in first-seen order.
    exit_phis: Vec<ValueId>,
    /// Every `(merge, value)` pair an edge to the exit block assigns.
    exit_arms: Vec<(ValueId, ValueId)>,
    /// Fall-through targets not yet known to lie inside the scope: a
    /// nested loop's entry names its header before the walk reaches it.
    falls_to: Vec<BlockId>,
}

impl Shape {
    /// Record one edge's merges.
    fn assign(&mut self, target: BlockId, transfer: &[(ValueId, ValueId)], header: BlockId, exit: BlockId) {
        for (phi, source) in transfer {
            self.phis.insert(*phi);
            if target == header {
                self.header_phis.insert(*phi);
            }
            if target == exit {
                self.exit_arms.push((*phi, *source));
                if !self.exit_phis.contains(phi) {
                    self.exit_phis.push(*phi);
                }
            }
        }
    }

    /// Whether every fall-through target left open by [`Shape::walk`] is a
    /// block of the scope.
    fn falls_inside(&self) -> bool {
        self.falls_to.iter().all(|t| self.blocks.contains(t))
    }

    /// Record `region`'s blocks and merges; `false` when an edge leaves
    /// for anywhere but the exit, the header, or a label inside the scope,
    /// or the scope returns. `labels` holds the scopes and loops entered
    /// on the way down.
    fn walk(&mut self, region: &Region, header: BlockId, exit: BlockId, labels: &mut Vec<BlockId>) -> bool {
        match region {
            Region::Basic(b) => {
                self.blocks.push(*b);
                true
            }
            Region::Sequence(items) => items.iter().all(|i| self.walk(i, header, exit, labels)),
            Region::Scope { out, body } => {
                labels.push(*out);
                let ok = self.walk(body, header, exit, labels);
                labels.pop();
                ok
            }
            Region::If { then_region, else_region, .. } => {
                self.walk(then_region, header, exit, labels)
                    && else_region.as_deref().is_none_or(|e| self.walk(e, header, exit, labels))
            }
            Region::Loop { header: inner, body, .. } => {
                labels.push(*inner);
                let ok = self.walk(body, header, exit, labels);
                labels.pop();
                ok
            }
            Region::Switch { arms, default, .. } => {
                arms.iter().all(|a| self.walk(&a.body, header, exit, labels)) && self.walk(default, header, exit, labels)
            }
            Region::Break { target, transfer } => {
                self.assign(*target, transfer, header, exit);
                *target == exit || labels.contains(target)
            }
            Region::Transfer { target, transfer } => {
                self.assign(*target, transfer, header, exit);
                if *target != exit && !labels.contains(target) {
                    self.falls_to.push(*target);
                }
                true
            }
            Region::Continue { target, transfer } => {
                self.assign(*target, transfer, header, exit);
                *target == header || labels.contains(target)
            }
            Region::Panic { .. } | Region::Unreachable => true,
            Region::Return { .. } | Region::Unstructured { .. } => false,
        }
    }
}

/// Where control goes after a region has run.
enum Flow {
    /// On to whatever follows.
    Next,
    /// Out of the scope labeled by this block.
    Break(BlockId),
    /// Back to the header of the loop labeled by this block.
    Continue(BlockId),
}

/// A machine word: its bits, and whether it is 64 bits wide or 32.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Word {
    bits: u64,
    wide: bool,
}

impl Word {
    fn new(bits: u64, wide: bool) -> Self {
        Word { bits: if wide { bits } else { bits & 0xffff_ffff }, wide }
    }

    fn flag(b: bool) -> Self {
        Word::new(u64::from(b), false)
    }

    /// The bits read as a two's-complement number of this width.
    fn signed(self) -> i64 {
        if self.wide {
            self.bits as i64
        } else {
            i64::from(self.bits as u32 as i32)
        }
    }

}

/// One run of a loop's scope.
struct Run<'a> {
    func: &'a HighFunction,
    memory: &'a MemoryImage,
    written: &'a [(u32, u32)],
    /// Values the loop defines: readable only once the run has set them.
    defined: &'a HashSet<ValueId>,
    env: HashMap<ValueId, Word>,
    steps: usize,
}

impl Run<'_> {
    /// Run `region`; `None` when the run cannot go on exactly.
    fn region(&mut self, region: &Region) -> Option<Flow> {
        match region {
            Region::Basic(b) => {
                let block = self.func.blocks.get(*b)?;
                for id in &block.bindings {
                    self.steps += 1;
                    if self.steps > MAX_STEPS {
                        return None;
                    }
                    let expr = &self.func.bindings.get(*id)?.expr;
                    if matches!(expr, Expr::Literal(Literal::Unit)) {
                        continue;
                    }
                    let word = self.compute(expr, 0)?;
                    self.env.insert(*id, word);
                }
                Some(Flow::Next)
            }
            Region::Sequence(items) => {
                for item in items {
                    match self.region(item)? {
                        Flow::Next => {}
                        other => return Some(other),
                    }
                }
                Some(Flow::Next)
            }
            Region::Scope { out, body } => match self.region(body)? {
                Flow::Break(target) if target == *out => Some(Flow::Next),
                other => Some(other),
            },
            Region::If { cond, then_region, else_region } => {
                if self.read(*cond, 0)?.bits != 0 {
                    self.region(then_region)
                } else {
                    match else_region {
                        Some(e) => self.region(e),
                        None => Some(Flow::Next),
                    }
                }
            }
            Region::Loop { header, body, .. } => {
                let mut trips = 0;
                loop {
                    match self.region(body)? {
                        Flow::Continue(h) if h == *header => {
                            trips += 1;
                            if trips > MAX_ITERATIONS {
                                return None;
                            }
                        }
                        Flow::Next => return None,
                        other => return Some(other),
                    }
                }
            }
            Region::Break { target, transfer } => {
                self.assign(transfer)?;
                Some(Flow::Break(*target))
            }
            Region::Continue { target, transfer } => {
                self.assign(transfer)?;
                Some(Flow::Continue(*target))
            }
            Region::Transfer { transfer, .. } => {
                self.assign(transfer)?;
                Some(Flow::Next)
            }
            Region::Switch { .. }
            | Region::Return { .. }
            | Region::Unreachable
            | Region::Panic { .. }
            | Region::Unstructured { .. } => None,
        }
    }

    /// An edge's merge assignments, all sources read before any is set.
    fn assign(&mut self, transfer: &[(ValueId, ValueId)]) -> Option<()> {
        let mut values = Vec::with_capacity(transfer.len());
        for (phi, source) in transfer {
            values.push((*phi, self.read(*source, 0)?));
        }
        self.env.extend(values);
        Some(())
    }

    /// The word `value` holds: what the run set it to, or — for a value
    /// defined before the loop — what its definition computes.
    fn read(&self, value: ValueId, depth: usize) -> Option<Word> {
        if let Some(word) = self.env.get(&value) {
            return Some(*word);
        }
        if self.defined.contains(&value) || depth >= MAX_DEPTH {
            return None;
        }
        let expr = &self.func.bindings.get(value)?.expr;
        self.compute(expr, depth + 1)
    }

    /// The word `expr` computes, when it is one the run can compute exactly.
    fn compute(&self, expr: &Expr, depth: usize) -> Option<Word> {
        let read = |v: ValueId| self.read(v, depth);
        match expr {
            Expr::Literal(lit) => literal(lit),
            Expr::Use(v) => read(*v),
            Expr::Unary { op, value } => {
                let x = read(*value)?;
                match op {
                    UnaryOp::Eqz => Some(Word::flag(x.bits == 0)),
                    UnaryOp::Not if x.bits <= 1 => Some(Word::flag(x.bits == 0)),
                    UnaryOp::Wrap32 if x.wide => Some(Word::new(x.bits, false)),
                    UnaryOp::ExtendU32 if !x.wide => Some(Word::new(x.bits, true)),
                    UnaryOp::ExtendS32 if !x.wide => Some(Word::new(x.signed() as u64, true)),
                    _ => None,
                }
            }
            Expr::Binary { op, lhs, rhs } => binary(*op, read(*lhs)?, read(*rhs)?),
            Expr::Select { cond, if_true, if_false } => {
                let (t, f) = (read(*if_true)?, read(*if_false)?);
                Some(if read(*cond)?.bits != 0 { t } else { f })
            }
            Expr::Load { addr, offset, width, signed, ty } => {
                let base = read(*addr)?;
                if base.wide {
                    return None;
                }
                let at = (base.bits as u32).checked_add(*offset)?;
                let n = u32::from(width_bytes(*width));
                if overlaps(self.written, at, n) {
                    return None;
                }
                let bytes = self.memory.read(at, n)?;
                let mut buf = [0u8; 8];
                buf[..bytes.len()].copy_from_slice(bytes);
                let raw = u64::from_le_bytes(buf);
                let bits = 8 * n;
                let value = if *signed == Some(true) && bits < 64 {
                    let shift = 64 - bits;
                    (((raw << shift) as i64) >> shift) as u64
                } else {
                    raw
                };
                let wide = match ty {
                    IrType::Known(k) | IrType::Inferred(k) => match k {
                        KnownType::I64 | KnownType::U64 => true,
                        KnownType::I32 | KnownType::U32 | KnownType::Bool => false,
                        _ => *width == MemWidth::W8,
                    },
                    IrType::Unknown(_) => *width == MemWidth::W8,
                };
                if *width == MemWidth::W8 && !wide {
                    return None;
                }
                Some(Word::new(value, wide))
            }
            _ => None,
        }
    }
}

/// A literal's word, at the width its own variant names.
fn literal(lit: &Literal) -> Option<Word> {
    match lit {
        Literal::I32(n) => Some(Word::new(u64::from(*n as u32), false)),
        Literal::U32(n) => Some(Word::new(u64::from(*n), false)),
        Literal::I64(n) => Some(Word::new(*n as u64, true)),
        Literal::U64(n) => Some(Word::new(*n, true)),
        Literal::Bool(b) => Some(Word::flag(*b)),
        _ => None,
    }
}

/// `l op r` at the operands' common width; `None` when the widths differ
/// or the operator is one the run does not compute.
fn binary(op: BinaryOp, l: Word, r: Word) -> Option<Word> {
    if l.wide != r.wide {
        return None;
    }
    let wide = l.wide;
    let bits: u64 = if wide { 64 } else { 32 };
    let word = |x: u64| Some(Word::new(x, wide));
    match op {
        BinaryOp::Add => word(l.bits.wrapping_add(r.bits)),
        BinaryOp::Sub => word(l.bits.wrapping_sub(r.bits)),
        BinaryOp::Mul => word(l.bits.wrapping_mul(r.bits)),
        BinaryOp::BitAnd => word(l.bits & r.bits),
        BinaryOp::BitOr => word(l.bits | r.bits),
        BinaryOp::BitXor => word(l.bits ^ r.bits),
        BinaryOp::Shl => word(l.bits << (r.bits % bits)),
        BinaryOp::ShrU => word(l.bits >> (r.bits % bits)),
        BinaryOp::Shr => word((l.signed() >> (r.bits % bits)) as u64),
        BinaryOp::Eq => Some(Word::flag(l.bits == r.bits)),
        BinaryOp::Ne => Some(Word::flag(l.bits != r.bits)),
        BinaryOp::LtU => Some(Word::flag(l.bits < r.bits)),
        BinaryOp::LeU => Some(Word::flag(l.bits <= r.bits)),
        BinaryOp::GtU => Some(Word::flag(l.bits > r.bits)),
        BinaryOp::GeU => Some(Word::flag(l.bits >= r.bits)),
        BinaryOp::Lt => Some(Word::flag(l.signed() < r.signed())),
        BinaryOp::Le => Some(Word::flag(l.signed() <= r.signed())),
        BinaryOp::Gt => Some(Word::flag(l.signed() > r.signed())),
        BinaryOp::Ge => Some(Word::flag(l.signed() >= r.signed())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{module, v};
    use sordec_common::{Arena, FuncId, UnknownReason};
    use sordec_ir::{Binding, DataSegment, HighBlock, LoopKind};

    fn bb(i: u32) -> BlockId {
        BlockId::from_index(i)
    }

    fn lit32(n: i32) -> Expr {
        Expr::Literal(Literal::I32(n))
    }

    fn lit64(n: i64) -> Expr {
        Expr::Literal(Literal::I64(n))
    }

    fn bin(op: BinaryOp, lhs: u32, rhs: u32) -> Expr {
        Expr::Binary { op, lhs: v(lhs), rhs: v(rhs) }
    }

    /// The bytes the loop packs: `"AB"` at 1000, then filler to 1200.
    const AT: i32 = 1000;

    /// The small-symbol encoder over two upper-case letters, inlined:
    ///
    /// ```text
    /// bb0: v0 = start; v1 = 0i64                     → v2 = v0, v3 = v1
    /// loop bb1 { 'bb3: {
    ///   bb1: v4 = eqz v2
    ///   if v4 { bb2: v8 = v3 << 8 | 14; break 'bb3 (v9 = v8) }
    ///   else  { bb4: c = load8(v2 + AT+2); code = (c + 203) & 255
    ///           acc = v3 << 6 | code; i = v2 + 1
    ///           if c == 0 { bb5: v27 = Symbol::new(fallback); break 'bb3 (v9 = v27) }
    ///           continue bb1 (v2 = i, v3 = acc) } }
    ///   bb3: v28 = (); v29 = v9; return v29 }
    /// ```
    fn packer(start: Expr, fallback: &str) -> HighFunction {
        let exprs = vec![
            start,                                                 // v0
            lit64(0),                                              // v1
            Expr::Phi { incoming: vec![] },                        // v2 i
            Expr::Phi { incoming: vec![] },                        // v3 acc
            Expr::Unary { op: UnaryOp::Eqz, value: v(2) },         // v4
            lit64(8),                                              // v5
            bin(BinaryOp::Shl, 3, 5),                              // v6
            lit64(14),                                             // v7
            bin(BinaryOp::BitOr, 6, 7),                            // v8
            Expr::Phi { incoming: vec![] },                        // v9 exit
            lit32(AT + 2),                                         // v10
            bin(BinaryOp::Add, 2, 10),                             // v11
            Expr::Load {
                addr: v(11),
                offset: 0,
                width: MemWidth::W1,
                signed: Some(false),
                ty: IrType::Known(KnownType::I32),
            }, // v12
            lit32(203),                                            // v13
            bin(BinaryOp::Add, 12, 13),                            // v14
            Expr::Unary { op: UnaryOp::ExtendU32, value: v(14) },  // v15
            lit64(255),                                            // v16
            bin(BinaryOp::BitAnd, 15, 16),                         // v17
            lit64(6),                                              // v18
            bin(BinaryOp::Shl, 3, 18),                             // v19
            bin(BinaryOp::BitOr, 19, 17),                          // v20
            lit32(1),                                              // v21
            bin(BinaryOp::Add, 2, 21),                             // v22
            lit32(0),                                              // v23
            bin(BinaryOp::Eq, 12, 23),                             // v24
            lit32(AT),                                             // v25
            lit32(2),                                              // v26
            Expr::Semantic(SemanticOp::Known(KnownOp::SymbolNew {
                lm_pos: v(25),
                len: v(26),
                resolved: Some(fallback.to_string()),
            })), // v27
            Expr::Literal(Literal::Unit),                          // v28 spare
            Expr::Use(v(9)),                                       // v29
            Expr::Literal(Literal::Unit),                          // v30 a retired store
            lit32(0),                                              // v31
        ];
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        for expr in exprs {
            let id = v(bindings.len() as u32);
            bindings.push(Binding::new(
                id,
                IrType::Unknown(UnknownReason::InsufficientEvidence),
                expr,
                Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
            ));
        }
        let layout: Vec<Vec<u32>> = vec![
            vec![0, 1],
            vec![4],
            vec![5, 6, 7, 8, 30],
            vec![31, 28, 29],
            (10..=24).collect(),
            vec![25, 26, 27],
        ];
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        for (i, ids) in layout.into_iter().enumerate() {
            blocks.push(HighBlock { id: bb(i as u32), bindings: ids.into_iter().map(v).collect() });
        }
        let scope = Region::Scope {
            out: bb(3),
            body: Box::new(Region::Sequence(vec![
                Region::Basic(bb(1)),
                Region::If {
                    cond: v(4),
                    then_region: Box::new(Region::Sequence(vec![
                        Region::Basic(bb(2)),
                        Region::Break { target: bb(3), transfer: vec![(v(9), v(8))] },
                    ])),
                    else_region: Some(Box::new(Region::Sequence(vec![
                        Region::Basic(bb(4)),
                        Region::If {
                            cond: v(24),
                            then_region: Box::new(Region::Sequence(vec![
                                Region::Basic(bb(5)),
                                Region::Break { target: bb(3), transfer: vec![(v(9), v(27))] },
                            ])),
                            else_region: None,
                        },
                        Region::Continue { target: bb(1), transfer: vec![(v(2), v(22)), (v(3), v(20))] },
                    ]))),
                },
            ])),
        };
        let region = Region::Sequence(vec![
            Region::Basic(bb(0)),
            Region::Transfer { target: bb(1), transfer: vec![(v(2), v(0)), (v(3), v(1))] },
            Region::Loop {
                header: bb(1),
                body: Box::new(Region::Sequence(vec![
                    scope,
                    Region::Basic(bb(3)),
                    Region::Return { values: vec![v(29)] },
                ])),
                kind: LoopKind::Unclassified,
            },
        ]);
        HighFunction {
            id: FuncId::from_index(0),
            name: None,
            signature: None,
            aliases: Vec::new(),
            blocks,
            bindings,
            region,
            params: vec![],
            returns: vec![vec![v(29)]],
        }
    }

    fn ir(functions: Vec<HighFunction>) -> HighIr {
        let mut m = module(functions);
        let mut bytes = b"AB".to_vec();
        bytes.resize(200, b'A');
        m.memory = MemoryImage::from_segments(vec![DataSegment { offset: AT as u32, bytes }]);
        m
    }

    fn has_loop(func: &HighFunction) -> bool {
        let mut found = false;
        func.region.for_each_node(|n| found |= matches!(n, Region::Loop { .. }));
        found
    }

    fn folds(func: HighFunction) -> bool {
        let mut m = ir(vec![func]);
        let changed = ConstLoopFoldPass.run(&mut m).changed;
        assert_eq!(changed, !has_loop(&m.functions[0]));
        changed
    }

    #[test]
    fn a_loop_from_a_constant_start_is_the_symbol_it_exits_with() {
        let mut m = ir(vec![packer(lit32(-2), "AB")]);
        let r = ConstLoopFoldPass.run(&mut m);
        assert!(r.changed);
        assert_eq!(r.metrics.get(M_FOLDED), Some(1));
        let f = &m.functions[0];
        assert!(!has_loop(f), "the loop is gone: {:?}", f.region);
        let exit = f.bindings.get(v(9)).unwrap();
        assert!(matches!(&exit.expr, Expr::Literal(Literal::Symbol(t)) if t == "AB"), "{:?}", exit.expr);
        assert_eq!(exit.ty, IrType::Known(KnownType::Symbol));
        // Scheduled where the code after the loop begins, ahead of its reader.
        assert_eq!(f.blocks.get(bb(3)).unwrap().bindings.first(), Some(&v(9)));
        // And the transfer that entered the loop goes with it.
        let mut transfers = 0;
        f.region.for_each_node(|n| transfers += usize::from(matches!(n, Region::Transfer { .. })));
        assert_eq!(transfers, 0);
        // A second run finds nothing left.
        assert!(!ConstLoopFoldPass.run(&mut m).changed);
    }

    /// The word decodes as `"AB"`; a fallback naming anything else does
    /// not say the merge holds that symbol.
    #[test]
    fn a_symbol_the_loop_does_not_also_name_is_left_alone() {
        assert!(!folds(packer(lit32(-2), "XY")));
    }

    #[test]
    fn a_start_that_is_not_constant_is_left_alone() {
        assert!(!folds(packer(Expr::Phi { incoming: vec![] }, "AB")));
    }

    #[test]
    fn an_effect_on_the_path_stops_the_run() {
        let mut f = packer(lit32(-2), "AB");
        f.bindings.get_mut(v(30)).unwrap().expr = Expr::Store { addr: v(10), value: v(8), offset: 0, width: MemWidth::W8 };
        assert!(!folds(f));
    }

    /// The code after the loop reading a value the loop computed, other
    /// than what the exit receives, keeps the loop.
    #[test]
    fn a_loop_value_read_after_the_loop_keeps_the_loop() {
        let mut f = packer(lit32(-2), "AB");
        f.bindings.get_mut(v(28)).unwrap().expr = Expr::Use(v(12));
        assert!(!folds(f));
    }

    /// Bytes some store writes through a constant address are not constant.
    #[test]
    fn bytes_a_constant_store_writes_are_not_read() {
        let mut f = packer(lit32(-2), "AB");
        f.bindings.get_mut(v(28)).unwrap().expr =
            Expr::Store { addr: v(31), value: v(31), offset: AT as u32, width: MemWidth::W1 };
        assert!(!folds(f));
    }

    /// A loop that does not reach its exit within the bound is not run out.
    #[test]
    fn a_loop_past_the_bound_is_left_alone() {
        assert!(!folds(packer(lit32(1), "AB")));
    }

    /// Operands of two widths are not one operation the run can do.
    #[test]
    fn mixed_widths_stop_the_run() {
        let mut f = packer(lit32(-2), "AB");
        f.bindings.get_mut(v(21)).unwrap().expr = lit64(1);
        assert!(!folds(f));
    }
}
