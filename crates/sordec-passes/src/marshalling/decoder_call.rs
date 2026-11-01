//! Drop the check a host-built value's outlined decoder makes, when the
//! decoder succeeds on every value of the type.
//!
//! # The shape
//!
//! ```rust,ignore
//! match context {
//!     Context::CreateContractHostFn(_) => return Err(AccError::NotEnoughSigners),
//!     ..
//! }
//! ```
//!
//! `__check_auth` is handed `Vec<Context>`, and matching an element decodes
//! it: the SDK's derived `TryFromVal` unpacks the variant's payload and
//! decodes each field. For `CreateContractHostFnContext.executable`, a
//! `ContractExecutable`, rustc outlines that field's decode into a helper
//! returning `Option` (its `Result`), and the caller traps on `None`:
//!
//! ```text
//! r = call decode(c.executable)        decode(x):
//! if !r.is_some() { panic!() }             if !has_tag(x, VecObject) { return None }
//!                                          state = (x, 0, vec_len(x))
//!                                          s = next(state)?  ; is a symbol, else None
//!                                          if symbol_index(s, ["Wasm"]) != 0 { return None }
//!                                          if len - idx > 1 { return None }
//!                                          p = next(state)?
//!                                          Some(decode_bytesn32(p)?)
//! ```
//!
//! `ContractExecutable` has one variant, so rustc emits no switch on the
//! lookup — the existing enum passes (`enum_match`, `enum_iter`) key on
//! one — and the decode stays a call with its trap, the helper and the
//! iterator it calls kept alive by it.
//!
//! # The rewrite
//!
//! The call, the test of its result and the trap go. The helper is then
//! called by nothing and is not emitted, nor are the helpers only it calls.
//!
//! # Why it is exact
//!
//! The value is built by the host, so it is a well-formed value of its
//! declared type on every run: the host hands `__check_auth` the contexts
//! of the invocation it is authorizing, each the host's own encoding of
//! the SDK's `Context`, and the argument is a field of a variant's payload
//! of such an element, reached through the declared types (each link a
//! field or payload whose declaration is the next link's type).
//!
//! On every well-formed value the helper returns `Some` and leaves nothing
//! behind. That is not read off its shape: it is *run*. A small evaluator
//! executes the helper's region tree — and those of the helpers it calls —
//! on each well-formed value of the type: per variant, a vector holding
//! the variant's name as a symbol and its payload (a `BytesN<N>` as a
//! bytes object of `N` bytes, an `Address` as an address object). Every
//! branch condition must evaluate to a definite answer; the one fact the
//! type leaves open, whether a symbol is held small or as an object (the
//! host accepts both), forks the run and both ways must succeed. The ops
//! it knows are modelled by their definitions: a tag test by the value's
//! tag, `vec_len` and `bytes_len` by the length (the IR names them as the
//! decoded `u32`), `vec_get` at an index below the length by the element
//! (above it the host would trap, so the run is refused), the symbol
//! lookup by the name's position in the rodata table (absent, the host
//! would trap: refused), whose raw `U32Val` a comparison must answer the
//! same as its decoded position, `Some`/`None`/`is_some`/`unwrap` as
//! written (an `unwrap` of `None` traps: refused), and integer arithmetic
//! and comparison only where every width and signedness agrees (operands
//! in `0..2³¹`, or `0..2³²` for an unsigned comparison). Memory is
//! tracked as written: the stack pointer is an address relative to its
//! value on entry, each store records its bytes, a load reads back
//! exactly what one store wrote or is unknown. A run is refused on
//! anything else that may trap or write — an op it does not model, a
//! loop, a store at or above the entry stack pointer (the caller's
//! memory), a stack pointer not restored on return, a trap reached.
//!
//! So on every run of the original the call returns `Some`, the trap it
//! guards never fires, and the only memory it wrote is stack below the
//! caller's, which nothing reads once it returns: removing the call, its
//! test and the trap changes nothing. The reconstruction's typed `match`
//! regenerates the same derived decode inside the SDK, as every
//! marshalling elision relocates its decode.
//!
//! # Gates
//!
//! - **The site.** `r = call H(x)` scheduled in a function whose spec
//!   takes `Vec<Context>` (`__check_auth`); `x` a chain of field and
//!   variant-payload reads ending at a `vec_get` of that parameter, typed
//!   `Context` (the auth table's, imported from the SDK), each link's type
//!   the previous link's declaration; `x`'s declared type a registered
//!   enum each of whose variants has at most one payload of a type the
//!   evaluator builds (`BytesN<N>`, `Address`).
//! - **The test.** Every live reader of `r` is a pure test (`is_some`,
//!   `!`, comparison, `select`) whose only other readers are more such
//!   tests or the condition of an `if c { trap }` with no `else`; with
//!   `r` = `Some(_)` each such condition evaluates to `false`.
//! - **The helper.** The evaluator's run above, for every variant: each
//!   path returns `Some`, the stack pointer is back to its entry value, no
//!   store reached the caller's memory, at most four calls deep, no
//!   recursion, a bounded number of steps.

use std::collections::{BTreeMap, HashMap, HashSet};

use sordec_common::{FuncId, IrId, TypeId, ValueId};
use sordec_ir::{
    BinaryOp, BufOpKind, CompositeType, Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Literal,
    PrimitiveType, Region, SdkType, SemanticOp, TypeRef, TypeRegistry, UnaryOp, VecOpKind, WasmOpcodeKind,
};

use super::enum_match::scheduled;
use super::udt_decode::read_keys;
use super::{apply_elisions, Elision};
use crate::dataflow::resolve_use;
use crate::effects::expr_effects;
use crate::pass::{Pass, PassResult};
use crate::val_abi;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-decoder-call";

/// Decode calls dropped.
const M_CALLS: &str = "marshalling_decoder_calls_dropped";

/// The name the auth table registers `__check_auth`'s element type under.
const CONTEXT: &str = super::auth_entries::CONTEXT;

/// Calls deep the evaluator follows.
const MAX_DEPTH: usize = 4;
/// Bindings and region nodes one run may execute.
const MAX_STEPS: usize = 20_000;

/// Drops a host-built value's always-succeeding decode call.
#[derive(Debug, Default, Clone, Copy)]
pub struct DecoderCallPass;

impl Pass<HighIr> for DecoderCallPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let Some(facts) = ir.soroban_facts.as_ref() else {
            return result;
        };
        let types = facts.types.clone();
        let Some(context) = context_union(&types) else {
            return result;
        };
        // The proof for each (helper, enum) pair, run once.
        let mut proven: HashMap<(FuncId, TypeId), bool> = HashMap::new();
        let mut plans: Vec<(usize, Vec<Site>)> = Vec::new();
        for (i, func) in ir.functions.iter().enumerate() {
            if !takes_auth_contexts(func) {
                continue;
            }
            let sites: Vec<Site> = candidates(func, &types, context)
                .into_iter()
                .filter(|s| *proven.entry((s.helper, s.union)).or_insert_with(|| succeeds(ir, s.helper, &types, s.union)))
                .collect();
            if !sites.is_empty() {
                plans.push((i, sites));
            }
        }
        for (i, sites) in plans {
            let func = &mut ir.functions[i];
            for site in sites {
                apply(func, &types, site);
                result.metrics.increment(M_CALLS, 1);
                result.changed = true;
            }
        }
        result
    }
}

/// Trace printed when `SORDEC_ENUM_TRACE` is set.
#[allow(clippy::print_stderr)]
fn trace(why: &str) {
    if std::env::var_os("SORDEC_ENUM_TRACE").is_some() {
        eprintln!("decoder-call: {why}");
    }
}

/// The SDK's `Context`, as the auth table registered it (imported, so not
/// a type of the contract's own).
fn context_union(types: &TypeRegistry) -> Option<TypeId> {
    let u = types.unions.iter().find(|u| u.name == CONTEXT)?;
    types.imported.iter().any(|t| t.id == u.id).then_some(u.id)
}

fn takes_auth_contexts(f: &HighFunction) -> bool {
    auth_param(f).is_some()
}

/// The parameter the spec declares `Vec<Context>`.
fn auth_param(f: &HighFunction) -> Option<ValueId> {
    let sig = f.signature.as_ref()?;
    let i = sig.inputs.iter().position(|p| {
        matches!(&p.ty, TypeRef::Composite(CompositeType::Vec(e)) if matches!(**e, TypeRef::Sdk(SdkType::AuthContext)))
    })?;
    f.params.get(i).copied()
}

// ---------------------------------------------------------------------
// The site
// ---------------------------------------------------------------------

/// One call to drop.
#[derive(Debug)]
struct Site {
    call: ValueId,
    helper: FuncId,
    union: TypeId,
    /// The pure tests reading the call's result, each with the constant it
    /// is on `Some`.
    chain: Vec<(ValueId, Literal)>,
    /// The conditions of the `if c { trap }` guards to remove.
    guards: HashSet<ValueId>,
}

/// The declared type of `x`, when `x` is a chain of field and payload
/// reads ending at an element of the auth-contexts parameter.
fn host_built(func: &HighFunction, types: &TypeRegistry, context: TypeId, x: ValueId) -> Option<TypeId> {
    let x = resolve_use(func, x);
    match &func.bindings.get(x)?.expr {
        Expr::Field { base, field } => {
            let s = host_built(func, types, context, *base)?;
            let def = types.structs.iter().find(|d| d.id == s)?;
            match &def.fields.iter().find(|f| &f.name == field)?.ty {
                TypeRef::UserDefined(t) => Some(*t),
                _ => None,
            }
        }
        Expr::VariantPayload { value, variant, index } => {
            let u = host_built(func, types, context, *value)?;
            let def = types.unions.iter().find(|d| d.id == u)?;
            match def.cases.iter().find(|c| &c.name == variant)?.fields.get(*index as usize)? {
                TypeRef::UserDefined(t) => Some(*t),
                _ => None,
            }
        }
        Expr::Semantic(SemanticOp::Known(KnownOp::VecOp { kind: VecOpKind::Get, args })) => {
            let [vec, _] = args.as_slice() else { return None };
            (Some(resolve_use(func, *vec)) == auth_param(func)
                && matches!(func.bindings.get(x)?.ty, IrType::Known(KnownType::UserDefined(t)) if t == context))
            .then_some(context)
        }
        _ => None,
    }
}

/// Who reads each value in the emitted code: every live scheduled binding,
/// the expressions folded into them, and the region tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reader {
    Binding(ValueId),
    Region,
}

fn live_readers(func: &HighFunction) -> HashMap<ValueId, Vec<Reader>> {
    let order = super::sret::emission_order(func);
    let dead = crate::dataflow::dead_residue(func, &order);
    let scheduled: HashSet<ValueId> = order.iter().copied().collect();
    let mut readers: HashMap<ValueId, Vec<Reader>> = HashMap::new();
    let mut seen: HashSet<ValueId> = HashSet::new();
    let mut work: Vec<ValueId> = order.iter().copied().filter(|v| !dead.contains(v)).collect();
    while let Some(user) = work.pop() {
        if !seen.insert(user) {
            continue;
        }
        let Some(b) = func.bindings.get(user) else { continue };
        b.expr.for_each_value_use(|u| {
            readers.entry(u).or_default().push(Reader::Binding(user));
            // A folded operand is part of its reader's expression.
            if !scheduled.contains(&u) && !matches!(func.bindings.get(u).map(|b| &b.expr), Some(Expr::Phi { .. })) {
                work.push(u);
            }
        });
    }
    func.region.for_each_value_use(|u| readers.entry(u).or_default().push(Reader::Region));
    readers
}

fn candidates(func: &HighFunction, types: &TypeRegistry, context: TypeId) -> Vec<Site> {
    let readers = live_readers(func);
    let mut guards_of: HashMap<ValueId, usize> = HashMap::new();
    collect_guards(&func.region, &mut guards_of);
    let mut out = Vec::new();
    for (_, call) in scheduled(func) {
        let Some(Expr::Call { target, args }) = func.bindings.get(call).map(|b| &b.expr) else { continue };
        let [x] = args.as_slice() else { continue };
        let Some(union) = host_built(func, types, context, *x) else { continue };
        if !types.unions.iter().any(|u| u.id == union) {
            continue;
        }
        let Some((chain, guards)) = tests(func, &readers, &guards_of, call) else {
            trace(&format!("func_{}: {call:?}: its result is read by more than its test", func.id.index()));
            continue;
        };
        out.push(Site { call, helper: *target, union, chain, guards });
    }
    out
}

/// `if c { trap }` with no `else`, by condition (counting repeats).
fn collect_guards(region: &Region, out: &mut HashMap<ValueId, usize>) {
    region.for_each_node(|n| {
        if let Region::If { cond, then_region, else_region: None } = n
            && traps(then_region)
        {
            *out.entry(*cond).or_default() += 1;
        }
    });
}

/// A region that does nothing but trap: blocks, then a trap.
fn traps(r: &Region) -> bool {
    match r {
        Region::Unreachable | Region::Panic { .. } => true,
        Region::Sequence(items) => {
            items.last().is_some_and(traps) && items.iter().all(|i| matches!(i, Region::Basic(_)) || traps(i))
        }
        _ => false,
    }
}

/// The pure tests of `call`'s result and the guards they feed, each test
/// evaluated with the result `Some`; `None` when anything else reads it.
#[allow(clippy::type_complexity)]
fn tests(
    func: &HighFunction,
    readers: &HashMap<ValueId, Vec<Reader>>,
    guards_of: &HashMap<ValueId, usize>,
    call: ValueId,
) -> Option<(Vec<(ValueId, Literal)>, HashSet<ValueId>)> {
    let mut chain: Vec<ValueId> = Vec::new();
    let mut guards: HashSet<ValueId> = HashSet::new();
    let mut work = vec![call];
    let mut seen = HashSet::new();
    while let Some(v) = work.pop() {
        if !seen.insert(v) {
            continue;
        }
        for r in readers.get(&v).map(Vec::as_slice).unwrap_or_default() {
            match r {
                Reader::Binding(u) => {
                    let pure_test = matches!(
                        func.bindings.get(*u).map(|b| &b.expr),
                        Some(
                            Expr::IsSome { .. }
                                | Expr::Use(_)
                                | Expr::Unary { op: UnaryOp::Not | UnaryOp::Eqz, .. }
                                | Expr::Binary { .. }
                                | Expr::Select { .. }
                        )
                    );
                    if !pure_test {
                        return None;
                    }
                    if !chain.contains(u) {
                        chain.push(*u);
                    }
                    work.push(*u);
                }
                // A region read only as a whole guard's condition, every
                // region read of it one.
                Reader::Region => {
                    if v == call {
                        return None;
                    }
                    let region_reads = readers[&v].iter().filter(|r| **r == Reader::Region).count();
                    if guards_of.get(&v).copied().unwrap_or(0) != region_reads {
                        return None;
                    }
                    guards.insert(v);
                }
            }
        }
    }
    if guards.is_empty() {
        return None;
    }
    // Each test, with the result `Some(_)`: a definite constant; each guard
    // condition `false`.
    let machine = Machine::new_bare();
    let mut env: Env = HashMap::new();
    env.insert(call, Abs::Opt(Some(Box::new(Abs::Unknown))));
    let st = State::entry();
    let mut out = Vec::new();
    for v in &chain {
        let lit = match machine.eval(func, *v, &env, &st).ok()? {
            Abs::Bool(b) => Literal::Bool(b),
            Abs::Int(_) => Literal::Unit,
            _ => return None,
        };
        if guards.contains(v) && !matches!(lit, Literal::Bool(false)) {
            return None;
        }
        out.push((*v, lit));
    }
    Some((out, guards))
}

fn apply(func: &mut HighFunction, types: &TypeRegistry, site: Site) {
    let name = types.unions.iter().find(|u| u.id == site.union).map_or("?", |u| u.name.as_str()).to_owned();
    let mut elisions = vec![Elision {
        id: site.call,
        expr: Expr::Literal(Literal::Unit),
        ty: Some(IrType::Known(KnownType::Unit)),
        note: format!(
            "`{name}`'s derived decode, outlined (func_{}): it returns `Some` on every value of the type, and this one the host built",
            site.helper.index()
        ),
        metric: M_CALLS,
    }];
    for (v, lit) in site.chain {
        let unit = matches!(lit, Literal::Unit);
        elisions.push(Elision {
            id: v,
            expr: Expr::Literal(lit),
            ty: unit.then_some(IrType::Known(KnownType::Unit)),
            note: format!("the test of `{name}`'s decode, which always succeeds here"),
            metric: M_CALLS,
        });
    }
    apply_elisions(func, PASS_NAME, elisions);
    let region = std::mem::replace(&mut func.region, Region::Sequence(Vec::new()));
    func.region = drop_guards(region, &site.guards);
}

fn drop_guards(region: Region, guards: &HashSet<ValueId>) -> Region {
    let rec = |r: Region| drop_guards(r, guards);
    match region {
        Region::Sequence(items) => Region::Sequence(items.into_iter().map(rec).collect()),
        Region::Scope { out, body } => Region::Scope { out, body: Box::new(rec(*body)) },
        Region::Loop { header, body, kind } => Region::Loop { header, body: Box::new(rec(*body)), kind },
        Region::Switch { index, arms, default, dispatch } => Region::Switch {
            index,
            arms: arms.into_iter().map(|a| sordec_ir::SwitchArm { cases: a.cases, body: rec(a.body) }).collect(),
            default: Box::new(rec(*default)),
            dispatch,
        },
        Region::If { cond, then_region, else_region } => {
            if guards.contains(&cond) && else_region.is_none() && traps(&then_region) {
                return Region::Sequence(Vec::new());
            }
            Region::If { cond, then_region: Box::new(rec(*then_region)), else_region: else_region.map(|e| Box::new(rec(*e))) }
        }
        leaf => leaf,
    }
}

// ---------------------------------------------------------------------
// The evaluator
// ---------------------------------------------------------------------

/// One node of the well-formed input value.
#[derive(Debug, Clone, PartialEq)]
enum Node {
    /// A vector object of these nodes.
    Vec(Vec<usize>),
    /// A symbol of this text, small or an object.
    Symbol(String),
    /// A bytes object of this many bytes.
    Bytes(u32),
    /// An object carried whole by one tag (an address).
    Object(u8),
}

/// An abstract value.
#[derive(Debug, Clone, PartialEq)]
enum Abs {
    Unknown,
    Int(i128),
    Bool(bool),
    /// An address this many bytes from the stack pointer's value when the
    /// outermost call was entered.
    Ptr(i64),
    /// A host value: a node of the input.
    Val(usize),
    /// `val_encode<u32>(k)`.
    U32Val(u32),
    /// What `symbol_index_in_linear_memory` returns for a name at this
    /// position: the raw `U32Val`, though the IR may read it decoded.
    Lookup(u32),
    Opt(Option<Box<Abs>>),
}

type Env = HashMap<ValueId, Abs>;

#[derive(Debug, Clone)]
struct State {
    /// Bytes written, by offset from the entry stack pointer: width, value.
    mem: BTreeMap<i64, (u32, Abs)>,
    /// The stack pointer global.
    global: Abs,
    /// Decided symbol forms, by node: `true` small, `false` object.
    small: HashMap<usize, bool>,
}

impl State {
    fn entry() -> Self {
        State { mem: BTreeMap::new(), global: Abs::Ptr(0), small: HashMap::new() }
    }
}

/// Why a run stopped short.
#[derive(Debug)]
enum Stop {
    Refuse(String),
    /// A symbol node's form decides the next step: run both.
    Fork(usize),
}

fn refuse<T>(why: impl Into<String>) -> Result<T, Stop> {
    Err(Stop::Refuse(why.into()))
}

/// One binding's effect on the run.
enum Step {
    Bind(Abs),
    Store { at: i64, width: u32, value: Abs },
    SetGlobal(Abs),
    Call { target: FuncId, args: Vec<Abs> },
    Nothing,
}

#[derive(Debug, Clone, PartialEq)]
enum Outcome {
    Fallthrough,
    Break(sordec_common::BlockId),
    Return(Abs),
    Trap,
}

struct Machine<'a> {
    ir: Option<&'a HighIr>,
    nodes: Vec<Node>,
    steps: std::cell::Cell<usize>,
    stack: std::cell::RefCell<Vec<FuncId>>,
}

/// Whether `helper` returns `Some` on every well-formed value of `union`.
fn succeeds(ir: &HighIr, helper: FuncId, types: &TypeRegistry, union: TypeId) -> bool {
    let Some(def) = types.unions.iter().find(|u| u.id == union) else { return false };
    if def.cases.is_empty() {
        return false;
    }
    for case in &def.cases {
        let mut nodes = vec![Node::Vec(Vec::new()), Node::Symbol(case.name.clone())];
        let mut elems = vec![1];
        for field in &case.fields {
            let node = match field {
                TypeRef::Composite(CompositeType::BytesN(n)) => Node::Bytes(*n),
                TypeRef::Primitive(PrimitiveType::Address) => Node::Object(val_abi::TAG_ADDRESS_OBJECT),
                _ => {
                    trace(&format!("{}::{}: a payload the evaluator does not build", def.name, case.name));
                    return false;
                }
            };
            elems.push(nodes.len());
            nodes.push(node);
        }
        nodes[0] = Node::Vec(elems);
        let m = Machine { ir: Some(ir), nodes, steps: 0.into(), stack: Vec::new().into() };
        match m.call(helper, vec![Abs::Val(0)], State::entry()) {
            Ok(runs) if runs.iter().all(|(st, r)| st.global == Abs::Ptr(0) && matches!(r, Abs::Opt(Some(_)))) => {}
            Ok(_) => {
                trace(&format!("func_{}: on {}::{} a path returns other than `Some`", helper.index(), def.name, case.name));
                return false;
            }
            Err(why) => {
                trace(&format!("func_{} on {}::{}: {why}", helper.index(), def.name, case.name));
                return false;
            }
        }
    }
    true
}

impl Machine<'_> {
    /// A machine with no module: evaluates pure expressions only.
    fn new_bare() -> Machine<'static> {
        Machine { ir: None, nodes: Vec::new(), steps: 0.into(), stack: Vec::new().into() }
    }

    fn tick(&self) -> Result<(), Stop> {
        self.steps.set(self.steps.get() + 1);
        if self.steps.get() > MAX_STEPS {
            return refuse("too many steps");
        }
        Ok(())
    }

    /// Run `target` on `args` from `st`: every way it can return, with the
    /// state it leaves and the value it returns.
    fn call(&self, target: FuncId, args: Vec<Abs>, st: State) -> Result<Vec<(State, Abs)>, String> {
        let ir = self.ir.ok_or("no module")?;
        {
            let stack = self.stack.borrow();
            if stack.len() >= MAX_DEPTH || stack.contains(&target) {
                return Err(format!("func_{}: too deep or recursive", target.index()));
            }
        }
        let f = ir.function(target).ok_or("no such function")?;
        if f.params.len() != args.len() {
            return Err(format!("func_{}: arity", target.index()));
        }
        let env: Env = f.params.iter().copied().zip(args).collect();
        self.stack.borrow_mut().push(target);
        let runs = self.exec(f, &f.region, env, st);
        self.stack.borrow_mut().pop();
        let runs = runs.map_err(|s| match s {
            Stop::Refuse(why) => format!("func_{}: {why}", target.index()),
            Stop::Fork(_) => "an unresolved fork".to_owned(),
        })?;
        let mut out = Vec::new();
        for (_, st, outcome) in runs {
            match outcome {
                Outcome::Return(v) => out.push((st, v)),
                Outcome::Trap => return Err(format!("func_{}: a path traps", target.index())),
                other => return Err(format!("func_{}: ends in {other:?}", target.index())),
            }
        }
        Ok(out)
    }

    fn exec(&self, f: &HighFunction, region: &Region, env: Env, st: State) -> Result<Vec<(Env, State, Outcome)>, Stop> {
        self.tick()?;
        match region {
            Region::Basic(b) => self.block(f, *b, 0, env, st),
            Region::Sequence(items) => {
                let mut live = vec![(env, st)];
                let mut done = Vec::new();
                for item in items {
                    let mut next = Vec::new();
                    for (e, s) in live {
                        for (e2, s2, o) in self.exec(f, item, e, s)? {
                            if o == Outcome::Fallthrough {
                                next.push((e2, s2));
                            } else {
                                done.push((e2, s2, o));
                            }
                        }
                    }
                    live = next;
                }
                done.extend(live.into_iter().map(|(e, s)| (e, s, Outcome::Fallthrough)));
                Ok(done)
            }
            Region::Scope { out, body } => Ok(self
                .exec(f, body, env, st)?
                .into_iter()
                .map(|(e, s, o)| match o {
                    Outcome::Break(t) if t == *out => (e, s, Outcome::Fallthrough),
                    other => (e, s, other),
                })
                .collect()),
            Region::If { cond, then_region, else_region } => match self.eval(f, *cond, &env, &st) {
                Ok(Abs::Bool(true)) => self.exec(f, then_region, env, st),
                Ok(Abs::Bool(false)) => match else_region {
                    Some(e) => self.exec(f, e, env, st),
                    None => Ok(vec![(env, st, Outcome::Fallthrough)]),
                },
                Ok(other) => refuse(format!("condition {cond:?} is {other:?}")),
                Err(Stop::Fork(n)) => self.fork(n, st, |s| self.exec(f, region, env.clone(), s)),
                Err(e) => Err(e),
            },
            Region::Break { target, transfer } => {
                let env = self.transfer(f, transfer, env, &st)?;
                Ok(vec![(env, st, Outcome::Break(*target))])
            }
            Region::Transfer { transfer, .. } => {
                let env = self.transfer(f, transfer, env, &st)?;
                Ok(vec![(env, st, Outcome::Fallthrough)])
            }
            Region::Return { values } => {
                let v = match values.as_slice() {
                    [] => Abs::Unknown,
                    [v] => self.eval(f, *v, &env, &st)?,
                    _ => return refuse("several return values"),
                };
                Ok(vec![(env, st, Outcome::Return(v))])
            }
            Region::Unreachable | Region::Panic { .. } => Ok(vec![(env, st, Outcome::Trap)]),
            Region::Loop { .. } | Region::Continue { .. } | Region::Switch { .. } | Region::Unstructured { .. } => {
                refuse("a loop or switch")
            }
        }
    }

    fn fork<T>(&self, node: usize, st: State, mut run: impl FnMut(State) -> Result<Vec<T>, Stop>) -> Result<Vec<T>, Stop> {
        if st.small.contains_key(&node) {
            return refuse("a fork on a decided symbol");
        }
        let mut out = Vec::new();
        for small in [true, false] {
            let mut s = st.clone();
            s.small.insert(node, small);
            out.extend(run(s)?);
        }
        Ok(out)
    }

    fn transfer(&self, f: &HighFunction, transfer: &[(ValueId, ValueId)], mut env: Env, st: &State) -> Result<Env, Stop> {
        let values: Vec<(ValueId, Abs)> =
            transfer.iter().map(|(phi, x)| Ok((*phi, self.eval(f, *x, &env, st)?))).collect::<Result<_, Stop>>()?;
        env.extend(values);
        Ok(env)
    }

    /// Execute block `b` from its `from`-th binding.
    fn block(&self, f: &HighFunction, b: sordec_common::BlockId, from: usize, mut env: Env, mut st: State) -> Result<Vec<(Env, State, Outcome)>, Stop> {
        let Some(block) = f.blocks.get(b) else { return refuse("no such block") };
        for (i, v) in block.bindings.iter().enumerate().skip(from) {
            self.tick()?;
            // Everything a step reads is evaluated before it changes
            // anything, so a fork can rerun the step from the same state.
            let step = match self.step(f, *v, &env, &st) {
                Ok(step) => step,
                Err(Stop::Fork(n)) => return self.fork(n, st, |s| self.block(f, b, i, env.clone(), s)),
                Err(e) => return Err(e),
            };
            match step {
                Step::Bind(x) => {
                    env.insert(*v, x);
                }
                Step::Store { at, width, value } => {
                    st.mem.retain(|k, (kw, _)| *k + i64::from(*kw) <= at || at + i64::from(width) <= *k);
                    st.mem.insert(at, (width, value));
                }
                Step::SetGlobal(x) => st.global = x,
                Step::Nothing => {}
                Step::Call { target, args } => {
                    let runs = self.call(target, args, st).map_err(Stop::Refuse)?;
                    let mut out = Vec::new();
                    for (s, r) in runs {
                        let mut e = env.clone();
                        e.insert(*v, r);
                        out.extend(self.block(f, b, i + 1, e, s)?);
                    }
                    return Ok(out);
                }
            }
        }
        Ok(vec![(env, st, Outcome::Fallthrough)])
    }

    /// What binding `v` does, read off the current state without changing it.
    fn step(&self, f: &HighFunction, v: ValueId, env: &Env, st: &State) -> Result<Step, Stop> {
        let Some(binding) = f.bindings.get(v) else { return refuse("no such binding") };
        Ok(match &binding.expr {
            Expr::Store { addr, value, offset, width } => {
                let Abs::Ptr(p) = self.eval(f, *addr, env, st)? else { return refuse("a store not into the stack") };
                let at = p + i64::from(*offset);
                let w = width.bytes();
                if at + i64::from(w) > 0 {
                    return refuse("a store into the caller's memory");
                }
                Step::Store { at, width: w, value: self.eval(f, *value, env, st)? }
            }
            Expr::Load { addr, offset, width, .. } => Step::Bind(match self.eval(f, *addr, env, st)? {
                Abs::Ptr(p) => match st.mem.get(&(p + i64::from(*offset))) {
                    Some((w, x)) if *w == width.bytes() => x.clone(),
                    _ => Abs::Unknown,
                },
                _ => Abs::Unknown,
            }),
            Expr::GlobalGet { index: 0 } => Step::Bind(st.global.clone()),
            Expr::Unknown { op_kind: WasmOpcodeKind::GlobalSet, args, .. } => {
                let [x] = args.as_slice() else { return refuse("a global.set's arity") };
                let x = self.eval(f, *x, env, st)?;
                if !matches!(x, Abs::Ptr(_)) {
                    return refuse("a global.set of something not the stack pointer");
                }
                Step::SetGlobal(x)
            }
            Expr::Call { target, args } => Step::Call {
                target: *target,
                args: args.iter().map(|a| self.eval(f, *a, env, st)).collect::<Result<Vec<_>, _>>()?,
            },
            Expr::Phi { .. } => Step::Nothing,
            expr => Step::Bind(self.eval_expr(f, v, expr, env, st)?),
        })
    }

    /// The value of `v`: as executed, or (a folded operand) evaluated in
    /// place when it reads no memory and writes nothing.
    fn eval(&self, f: &HighFunction, v: ValueId, env: &Env, st: &State) -> Result<Abs, Stop> {
        if let Some(x) = env.get(&v) {
            return Ok(x.clone());
        }
        let Some(binding) = f.bindings.get(v) else { return refuse("no such binding") };
        match &binding.expr {
            Expr::Phi { .. } => Ok(Abs::Unknown),
            Expr::Load { .. } | Expr::Store { .. } | Expr::Call { .. } | Expr::GlobalGet { .. } | Expr::Unknown { .. } => {
                refuse(format!("{v:?} read where it was not run"))
            }
            expr => {
                self.tick()?;
                self.eval_expr(f, v, expr, env, st)
            }
        }
    }

    fn eval_expr(&self, f: &HighFunction, id: ValueId, expr: &Expr, env: &Env, st: &State) -> Result<Abs, Stop> {
        let ev = |x: &ValueId| self.eval(f, *x, env, st);
        let unknown_if_pure = || {
            let e = expr_effects(expr);
            if e.may_trap || e.writes_memory || e.writes_globals || e.writes_host || e.reads_host {
                refuse(format!("an op the evaluator does not model: {expr:?}"))
            } else {
                Ok(Abs::Unknown)
            }
        };
        Ok(match expr {
            Expr::Literal(l) => match l {
                Literal::I32(x) => Abs::Int(i128::from(*x)),
                Literal::I64(x) => Abs::Int(i128::from(*x)),
                Literal::U32(x) => Abs::Int(i128::from(*x)),
                Literal::U64(x) => Abs::Int(i128::from(*x)),
                Literal::Bool(b) => Abs::Bool(*b),
                _ => Abs::Unknown,
            },
            Expr::Use(x) => ev(x)?,
            Expr::Unary { op, value } => match (op, ev(value)?) {
                (UnaryOp::Not, Abs::Bool(b)) => Abs::Bool(!b),
                (UnaryOp::Eqz, Abs::Int(x)) => Abs::Bool(x == 0),
                (UnaryOp::Eqz, Abs::Bool(b)) => Abs::Bool(!b),
                (UnaryOp::Wrap32 | UnaryOp::ExtendU32, Abs::Int(x)) if small(x) => Abs::Int(x),
                _ => Abs::Unknown,
            },
            Expr::Binary { op, lhs, rhs } => binary(*op, ev(lhs)?, ev(rhs)?),
            Expr::Select { cond, if_true, if_false } => match ev(cond)? {
                Abs::Bool(true) => ev(if_true)?,
                Abs::Bool(false) => ev(if_false)?,
                _ => Abs::Unknown,
            },
            Expr::IsSome { value } => match ev(value)? {
                Abs::Opt(o) => Abs::Bool(o.is_some()),
                _ => Abs::Unknown,
            },
            Expr::Unwrap { value, index: 0, arity: 1 } => match ev(value)? {
                Abs::Opt(Some(x)) => *x,
                Abs::Opt(None) => return refuse("an unwrap of None"),
                _ => Abs::Unknown,
            },
            Expr::Optional { payload: None } => Abs::Opt(None),
            Expr::Optional { payload: Some(p) } => match p.as_slice() {
                [x] => Abs::Opt(Some(Box::new(ev(x)?))),
                _ => Abs::Unknown,
            },
            Expr::Semantic(SemanticOp::Known(op)) => return self.known(f, id, op, env, st, expr),
            _ => return unknown_if_pure(),
        })
    }

    fn known(&self, f: &HighFunction, id: ValueId, op: &KnownOp, env: &Env, st: &State, expr: &Expr) -> Result<Abs, Stop> {
        let ev = |x: &ValueId| self.eval(f, *x, env, st);
        let node = |x: &ValueId| -> Result<Option<(usize, &Node)>, Stop> {
            Ok(match ev(x)? {
                Abs::Val(n) => self.nodes.get(n).map(|node| (n, node)),
                _ => None,
            })
        };
        Ok(match op {
            KnownOp::ValTagCheck { value, tag, negated } => {
                let Some((n, node)) = node(value)? else { return Ok(Abs::Unknown) };
                let has = match node {
                    Node::Vec(_) => *tag == val_abi::TAG_VEC_OBJECT,
                    Node::Bytes(_) => *tag == val_abi::TAG_BYTES_OBJECT,
                    Node::Object(t) => tag == t,
                    Node::Symbol(_) => match (*tag, st.small.get(&n)) {
                        (val_abi::TAG_SYMBOL_SMALL, Some(s)) => *s,
                        (val_abi::TAG_SYMBOL_OBJECT, Some(s)) => !*s,
                        (val_abi::TAG_SYMBOL_SMALL | val_abi::TAG_SYMBOL_OBJECT, None) => return Err(Stop::Fork(n)),
                        _ => false,
                    },
                };
                Abs::Bool(has != *negated)
            }
            KnownOp::ValEncodeSmall { ty: KnownType::U32, value } => match ev(value)? {
                Abs::Int(k) => u32::try_from(k).map_or(Abs::Unknown, Abs::U32Val),
                _ => Abs::Unknown,
            },
            KnownOp::VecOp { kind: VecOpKind::Len, args } => match args.as_slice() {
                [x] if declared_u32(f, id) => match node(x)? {
                    Some((_, Node::Vec(e))) => Abs::Int(e.len() as i128),
                    _ => return refuse("vec_len of a value not a vector"),
                },
                _ => return refuse("vec_len not named the u32 length"),
            },
            KnownOp::VecOp { kind: VecOpKind::Get, args } => {
                let [x, i] = args.as_slice() else { return refuse("vec_get's arity") };
                let (Some((_, Node::Vec(e))), Abs::U32Val(k)) = (node(x)?, ev(i)?) else {
                    return refuse("vec_get of an unknown vector or index");
                };
                match e.get(k as usize) {
                    Some(n) => Abs::Val(*n),
                    None => return refuse("vec_get past the end traps"),
                }
            }
            KnownOp::BufOp { kind: BufOpKind::BytesLen, args } => match args.as_slice() {
                [x] if declared_u32(f, id) => match node(x)? {
                    Some((_, Node::Bytes(n))) => Abs::Int(i128::from(*n)),
                    _ => return refuse("bytes_len of a value not bytes"),
                },
                _ => return refuse("bytes_len not named the u32 length"),
            },
            KnownOp::BufOp { kind: BufOpKind::SymbolIndexInLinearMemory, args } => {
                let [s, pos, len] = args.as_slice() else { return refuse("symbol_index's arity") };
                let (Some((_, Node::Symbol(name))), Abs::U32Val(pos), Abs::U32Val(len)) = (node(s)?, ev(pos)?, ev(len)?)
                else {
                    return refuse("symbol_index of an unknown symbol or table");
                };
                let Some(ir) = self.ir else { return refuse("no module") };
                let Some(names) = read_keys(&ir.memory, pos, len) else { return refuse("an unreadable table") };
                match names.iter().position(|n| n == name) {
                    Some(i) => Abs::Lookup(i as u32),
                    None => return refuse("a symbol the table lacks traps"),
                }
            }
            _ => {
                let e = expr_effects(expr);
                if e.may_trap || e.writes_memory || e.writes_globals || e.writes_host || e.reads_host {
                    return refuse(format!("a host op the evaluator does not model: {op:?}"));
                }
                Abs::Unknown
            }
        })
    }
}

/// Whether binding `id` is typed the decoded `u32`: a host length the IR
/// names `len()`, not the raw `U32Val`.
fn declared_u32(f: &HighFunction, id: ValueId) -> bool {
    f.bindings.get(id).is_some_and(|b| matches!(b.ty, IrType::Known(KnownType::U32)))
}

/// In `0..2³¹`: the same number at every width and signedness.
fn small(x: i128) -> bool {
    (0..1 << 31).contains(&x)
}

/// In `0..2³²`: the same unsigned number at 32 and 64 bits.
fn unsigned(x: i128) -> bool {
    (0..1 << 32).contains(&x)
}

fn binary(op: BinaryOp, a: Abs, b: Abs) -> Abs {
    use BinaryOp as B;
    // A lookup's position is read either as the host's raw `U32Val` or as
    // the position itself; a comparison decides only if both agree.
    if let Abs::Lookup(i) = a {
        let raw = (i128::from(i) << 32) | i128::from(val_abi::TAG_U32_VAL);
        let (x, y) = (binary(op, Abs::Int(raw), b.clone()), binary(op, Abs::Int(i128::from(i)), b));
        return if x == y && matches!(x, Abs::Bool(_)) { x } else { Abs::Unknown };
    }
    if let Abs::Lookup(_) = b {
        return match op.swapped() {
            Some(sw) => binary(sw, b, a),
            None => Abs::Unknown,
        };
    }
    match (op, a, b) {
        (B::Add, Abs::Ptr(p), Abs::Int(k)) | (B::Add, Abs::Int(k), Abs::Ptr(p)) if small(k.abs()) => Abs::Ptr(p + k as i64),
        (B::Sub, Abs::Ptr(p), Abs::Int(k)) if small(k.abs()) => Abs::Ptr(p - k as i64),
        (B::Add, Abs::Int(x), Abs::Int(y)) if small(x) && small(y) && small(x + y) => Abs::Int(x + y),
        (B::Sub, Abs::Int(x), Abs::Int(y)) if small(x) && small(y) && x >= y => Abs::Int(x - y),
        (B::Eq | B::Ne | B::LtU | B::LeU | B::GtU | B::GeU, Abs::Int(x), Abs::Int(y)) if unsigned(x) && unsigned(y) => {
            Abs::Bool(compare(op, x, y))
        }
        (B::Lt | B::Le | B::Gt | B::Ge, Abs::Int(x), Abs::Int(y)) if small(x) && small(y) => Abs::Bool(compare(op, x, y)),
        (B::Eq, Abs::Bool(x), Abs::Bool(y)) => Abs::Bool(x == y),
        (B::Ne, Abs::Bool(x), Abs::Bool(y)) => Abs::Bool(x != y),
        _ => Abs::Unknown,
    }
}

fn compare(op: BinaryOp, x: i128, y: i128) -> bool {
    use BinaryOp as B;
    match op {
        B::Eq => x == y,
        B::Ne => x != y,
        B::Lt | B::LtU => x < y,
        B::Le | B::LeU => x <= y,
        B::Gt | B::GtU => x > y,
        _ => x >= y,
    }
}

trait Swapped {
    fn swapped(self) -> Option<BinaryOp>;
}

impl Swapped for BinaryOp {
    /// The comparison with its operands exchanged.
    fn swapped(self) -> Option<BinaryOp> {
        use BinaryOp as B;
        Some(match self {
            B::Eq => B::Eq,
            B::Ne => B::Ne,
            B::Lt => B::Gt,
            B::Le => B::Ge,
            B::Gt => B::Lt,
            B::Ge => B::Le,
            B::LtU => B::GtU,
            B::LeU => B::GeU,
            B::GtU => B::LtU,
            B::GeU => B::LeU,
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{module, v};
    use sordec_common::{Arena, BlockId, IrId, Provenance, ProvenanceSource, UnknownReason};
    use sordec_ir::{Binding, HighBlock, MemWidth, UnionCase, UnionDef};

    fn known(op: KnownOp) -> Expr {
        Expr::Semantic(SemanticOp::Known(op))
    }

    fn tag(value: u32, tag: u8, negated: bool) -> Expr {
        known(KnownOp::ValTagCheck { value: v(value), tag, negated })
    }

    fn bb(i: u32) -> Region {
        Region::Basic(BlockId::from_index(i))
    }

    /// A function of `blocks` (each a list of expressions, numbered on from
    /// `v0`, the one parameter) and `region`. `u32s` are typed `u32`.
    fn build(id: u32, blocks: Vec<Vec<Expr>>, region: Region, u32s: &[u32]) -> HighFunction {
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        let mut arena_blocks: Arena<BlockId, HighBlock> = Arena::new();
        let push = |bindings: &mut Arena<ValueId, Binding>, expr: Expr| {
            let id = ValueId::from_index(bindings.len() as u32);
            let ty = if u32s.contains(&id.index()) {
                IrType::Known(KnownType::U32)
            } else {
                IrType::Unknown(UnknownReason::InsufficientEvidence)
            };
            bindings.push(Binding::new(id, ty, expr, Provenance::new("seed", ProvenanceSource::DataFlow, "seed")))
        };
        let param = push(&mut bindings, Expr::Phi { incoming: vec![] });
        for (i, exprs) in blocks.into_iter().enumerate() {
            let ids = exprs.into_iter().map(|e| push(&mut bindings, e)).collect();
            arena_blocks.push(HighBlock { id: BlockId::from_index(i as u32), bindings: ids });
        }
        HighFunction {
            id: FuncId::from_index(id),
            name: None,
            signature: None,
            aliases: Vec::new(),
            blocks: arena_blocks,
            bindings,
            region,
            params: vec![param],
            returns: vec![],
        }
    }

    /// `ContractExecutable`-like: one variant, `Wasm(BytesN<32>)`.
    fn registry() -> TypeRegistry {
        TypeRegistry {
            unions: vec![UnionDef {
                id: TypeId::new(0),
                name: "Exec".into(),
                cases: vec![UnionCase {
                    name: "Wasm".into(),
                    fields: vec![TypeRef::Composite(CompositeType::BytesN(32))],
                }],
                exported: false,
            }],
            ..TypeRegistry::default()
        }
    }

    /// The decoder: `x` a vector of two, element 0 a symbol in either form,
    /// element 1 bytes of 32, then `Some(element 1)`; `None` otherwise.
    /// `object_fails` makes the symbol-object form return `None` too.
    fn decoder(object_fails: bool) -> HighFunction {
        let none = || Expr::Optional { payload: None };
        let lit = |k: i64| Expr::Literal(Literal::I64(k));
        let blocks = vec![
            // b0: v1 has_tag(x, Vec)
            vec![tag(0, val_abi::TAG_VEC_OBJECT, false)],
            // b1: v2 len, v3 2, v4 len == 2, v5 0, v6 U32Val(0), v7 e0, v8 has_tag(e0, SymObj)
            vec![
                known(KnownOp::VecOp { kind: VecOpKind::Len, args: vec![v(0)] }),
                lit(2),
                Expr::Binary { op: BinaryOp::Eq, lhs: v(2), rhs: v(3) },
                lit(0),
                known(KnownOp::ValEncodeSmall { ty: KnownType::U32, value: v(5) }),
                known(KnownOp::VecOp { kind: VecOpKind::Get, args: vec![v(0), v(6)] }),
                tag(7, val_abi::TAG_SYMBOL_OBJECT, false),
            ],
            // b2: v9 !has_tag(e0, SymSmall)
            vec![tag(7, val_abi::TAG_SYMBOL_SMALL, true)],
            // b3: v10 1, v11 U32Val(1), v12 e1, v13 bytes_len(e1), v14 32, v15 len == 32
            vec![
                lit(1),
                known(KnownOp::ValEncodeSmall { ty: KnownType::U32, value: v(10) }),
                known(KnownOp::VecOp { kind: VecOpKind::Get, args: vec![v(0), v(11)] }),
                known(KnownOp::BufOp { kind: BufOpKind::BytesLen, args: vec![v(12)] }),
                lit(32),
                Expr::Binary { op: BinaryOp::Eq, lhs: v(13), rhs: v(14) },
            ],
            // b4: v16 Some(e1)
            vec![Expr::Optional { payload: Some(vec![v(12)]) }],
            // b5: v17 None
            vec![none()],
        ];
        let ret = |x: u32| Region::Return { values: vec![v(x)] };
        let none_ret = Region::Sequence(vec![bb(5), ret(17)]);
        let object_arm = if object_fails { none_ret.clone() } else { Region::Sequence(vec![]) };
        let region = Region::Sequence(vec![
            bb(0),
            Region::If {
                cond: v(1),
                then_region: Box::new(Region::Sequence(vec![
                    bb(1),
                    Region::If {
                        cond: v(4),
                        then_region: Box::new(Region::Sequence(vec![
                            Region::If {
                                cond: v(8),
                                then_region: Box::new(object_arm),
                                else_region: Some(Box::new(Region::Sequence(vec![
                                    bb(2),
                                    Region::If { cond: v(9), then_region: Box::new(none_ret.clone()), else_region: None },
                                ]))),
                            },
                            bb(3),
                            Region::If {
                                cond: v(15),
                                then_region: Box::new(Region::Sequence(vec![bb(4), ret(16)])),
                                else_region: None,
                            },
                            none_ret.clone(),
                        ])),
                        else_region: None,
                    },
                    none_ret.clone(),
                ])),
                else_region: None,
            },
            none_ret,
        ]);
        build(0, blocks, region, &[2, 13])
    }

    #[test]
    fn a_decoder_that_succeeds_on_every_value_is_proven() {
        let ir = module(vec![decoder(false)]);
        assert!(succeeds(&ir, FuncId::from_index(0), &registry(), TypeId::new(0)));
    }

    #[test]
    fn a_decoder_that_fails_on_one_symbol_form_is_not() {
        // The host accepts a symbol object as well as a small symbol; a
        // decoder answering `None` for one of them may fail here.
        let ir = module(vec![decoder(true)]);
        assert!(!succeeds(&ir, FuncId::from_index(0), &registry(), TypeId::new(0)));
    }

    #[test]
    fn a_length_not_named_the_u32_is_not_read() {
        // `vec_len`'s raw `U32Val` is not the length; only a binding the IR
        // types `u32` is.
        let mut f = decoder(false);
        f.bindings.get_mut(v(2)).unwrap().ty = IrType::Unknown(UnknownReason::InsufficientEvidence);
        let ir = module(vec![f]);
        assert!(!succeeds(&ir, FuncId::from_index(0), &registry(), TypeId::new(0)));
    }

    #[test]
    fn a_decoder_that_writes_its_callers_memory_is_not() {
        // `store (global.get 0) + 8 <- 0` is above the entry stack pointer.
        let mut f = decoder(false);
        let base = f.bindings.len() as u32;
        let mk = |e: Expr| Binding::new(
            ValueId::from_index(0),
            IrType::Unknown(UnknownReason::InsufficientEvidence),
            e,
            Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
        );
        let ids: Vec<ValueId> = [
            Expr::GlobalGet { index: 0 },
            Expr::Literal(Literal::I64(0)),
            Expr::Store { addr: v(base), value: v(base + 1), offset: 8, width: MemWidth::W8 },
        ]
        .into_iter()
        .map(|e| {
            let id = ValueId::from_index(f.bindings.len() as u32);
            let mut b = mk(e);
            b.id = id;
            f.bindings.push(b)
        })
        .collect();
        f.blocks.get_mut(BlockId::from_index(0)).unwrap().bindings.extend(ids);
        let ir = module(vec![f]);
        assert!(!succeeds(&ir, FuncId::from_index(0), &registry(), TypeId::new(0)));
    }

    #[test]
    fn a_comparison_of_a_lookup_decides_only_where_raw_and_position_agree() {
        // Position 0: raw `U32Val` 4. `<= u32::MAX` holds both ways; `== 0`
        // holds of the position but not of the raw word.
        assert_eq!(binary(BinaryOp::LeU, Abs::Lookup(0), Abs::Int(4_294_967_295)), Abs::Bool(true));
        assert_eq!(binary(BinaryOp::Eq, Abs::Lookup(0), Abs::Int(0)), Abs::Unknown);
        assert_eq!(binary(BinaryOp::GeU, Abs::Int(4_294_967_295), Abs::Lookup(0)), Abs::Bool(true));
    }

    #[test]
    fn integer_ops_decide_only_where_every_width_agrees() {
        assert_eq!(binary(BinaryOp::Sub, Abs::Int(2), Abs::Int(1)), Abs::Int(1));
        // Below zero the width decides the bits.
        assert_eq!(binary(BinaryOp::Sub, Abs::Int(1), Abs::Int(2)), Abs::Unknown);
        // A negative literal compares differently at 32 and 64 bits.
        assert_eq!(binary(BinaryOp::LtU, Abs::Int(1), Abs::Int(-1)), Abs::Unknown);
        assert_eq!(binary(BinaryOp::Lt, Abs::Int(1), Abs::Int(3_000_000_000)), Abs::Unknown);
    }

    /// `__check_auth`-like caller: `r = call H(x); c = !is_some(r); if c { panic }`.
    fn caller(x: Expr, extra_read: bool) -> HighFunction {
        let mut blocks = vec![vec![
            x,                                                              // v1
            Expr::Call { target: FuncId::from_index(0), args: vec![v(1)] }, // v2
            Expr::IsSome { value: v(2) },                                   // v3
            Expr::Unary { op: UnaryOp::Not, value: v(3) },                  // v4
        ]];
        if extra_read {
            blocks[0].push(Expr::Unwrap { value: v(2), index: 0, arity: 1 }); // v5
        }
        let region = Region::Sequence(vec![
            bb(0),
            Region::If {
                cond: v(4),
                then_region: Box::new(Region::Panic { kind: sordec_ir::PanicKind::Bare }),
                else_region: None,
            },
            Region::Return { values: if extra_read { vec![v(5)] } else { vec![] } },
        ]);
        build(1, blocks, region, &[])
    }

    #[test]
    fn a_test_that_only_guards_a_trap_is_false_on_some() {
        let f = caller(Expr::Literal(Literal::Unit), false);
        let readers = live_readers(&f);
        let mut guards_of = HashMap::new();
        collect_guards(&f.region, &mut guards_of);
        let (chain, guards) = tests(&f, &readers, &guards_of, v(2)).expect("the test guards the trap alone");
        assert_eq!(guards, HashSet::from([v(4)]));
        assert!(chain.iter().any(|(id, lit)| *id == v(4) && matches!(lit, Literal::Bool(false))));
    }

    #[test]
    fn a_result_read_beyond_its_test_is_left() {
        let f = caller(Expr::Literal(Literal::Unit), true);
        let readers = live_readers(&f);
        let mut guards_of = HashMap::new();
        collect_guards(&f.region, &mut guards_of);
        assert!(tests(&f, &readers, &guards_of, v(2)).is_none());
    }

    #[test]
    fn a_value_not_built_by_the_host_is_not_proven() {
        // A parameter (no spec here) is no element of the auth contexts.
        let f = caller(Expr::Literal(Literal::Unit), false);
        assert_eq!(host_built(&f, &registry(), TypeId::new(9), v(0)), None);
        assert_eq!(host_built(&f, &registry(), TypeId::new(9), v(1)), None);
    }

    #[test]
    fn dropping_the_guard_removes_only_it() {
        let f = caller(Expr::Literal(Literal::Unit), false);
        let region = drop_guards(f.region.clone(), &HashSet::from([v(4)]));
        let mut ifs = 0;
        region.for_each_node(|n| ifs += usize::from(matches!(n, Region::If { .. })));
        assert_eq!(ifs, 0);
        let kept = drop_guards(f.region, &HashSet::from([v(3)]));
        let mut ifs = 0;
        kept.for_each_node(|n| ifs += usize::from(matches!(n, Region::If { .. })));
        assert_eq!(ifs, 1);
    }
}
