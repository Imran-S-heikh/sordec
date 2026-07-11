//! Layer 3 of the IR pipeline: structured, typed, semantic-aware.
//!
//! [`HighIr`] is what `sordec-backend` consumes to produce annotated WAT
//! and compilable Rust. It is the result of all pattern recognition,
//! structuring, and type inference passes:
//!
//! - Control flow is captured as recursive [`Region`]s rather than a flat
//!   block graph.
//! - Each binding carries a typed [`Expr`] and a [`IrType`] (with
//!   explicit `Known`/`Inferred`/`Unknown` certainty).
//! - Every binding carries an append-only [`Provenance`] vector
//!   recording every pass that touched it.
//!
//! Construction of `HighIr` happens via the boundary lowering step in the
//! `sordec-passes` driver (see `LoweringStep`); subsequent passes mutate
//! it in place via [`Pass`](https://example.invalid)`<HighIr>`.

pub mod expr;
pub mod region;
pub mod semantic;
pub mod storage;
pub mod ty;

pub use expr::{BinaryOp, Expr, Literal, UnaryOp};
pub use region::Region;
pub use semantic::{
    AddressOpKind, BufOpKind, KnownOp, MapOpKind, SemanticOp, ValObjectKind, VecOpKind,
};
pub use storage::{KnownTier, StorageTier};
pub use ty::{IrType, KnownType};

use sordec_common::{Arena, BlockId, FuncId, IrId, Provenance, ValueId};

use crate::{FunctionSignature, MemoryImage, SorobanFacts, WasmFacts};

#[cfg(feature = "serde")]
use serde::Serialize;

// NOTE on `serde`: the high IR is intentionally `Serialize`-only.
// `Binding::provenance` contains `Provenance`, whose `pass` field is
// `&'static str`; making the chain `Deserialize` would require
// `'de: 'static`, which is essentially never satisfiable. We do not
// have a current need to deserialise high IR — JSON dumps are an
// inspection output — so we accept the asymmetry rather than weaken
// the types.

/// Top-level high IR for a whole module.
///
/// Owns the [`WasmFacts`] for emit-time annotations and the lifted IR is
/// not preserved here — once we have HighIr the lifted form is no longer
/// needed for code generation (passes that need it can keep references
/// during their own analyses).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct HighIr {
    /// Frontend-decoded facts about the original WASM module.
    pub facts: WasmFacts,

    /// Decoded Soroban metadata, threaded through from the lift step.
    /// `None` for modules without a `contractspecv0` custom section.
    /// The Rust emitter consults this for type-name reconstruction and
    /// `#[contracttype]` placement.
    pub soroban_facts: Option<SorobanFacts>,

    /// Local (non-imported) functions in module order.
    pub functions: Vec<HighFunction>,

    /// Initialized linear-memory image (the WASM active data segments),
    /// threaded through unchanged from [`crate::LiftedIr`] by the boundary
    /// lowering. Linear-memory recognizers read this module-level rodata
    /// to resolve `(pointer, length)` literals. [`MemoryImage::empty`] for
    /// modules with no data section.
    pub memory: MemoryImage,
}

impl HighIr {
    /// Look up a function by its module-global [`FuncId`].
    #[inline]
    #[must_use]
    pub fn function(&self, id: FuncId) -> Option<&HighFunction> {
        self.functions.get(id.index() as usize)
    }

    /// Mutable counterpart to [`function`](Self::function).
    #[inline]
    #[must_use]
    pub fn function_mut(&mut self, id: FuncId) -> Option<&mut HighFunction> {
        self.functions.get_mut(id.index() as usize)
    }
}

/// One function in the high IR.
///
/// `region` is the structured control-flow tree; `blocks` is the
/// underlying linear basic-block storage that regions reference. Both are
/// present because the structured form may reference each block from
/// multiple region positions.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct HighFunction {
    /// Module-global function identifier.
    pub id: FuncId,

    /// Recovered name (from `contractspecv0` or the WASM export section).
    /// `None` when the function is internal and unnamed.
    // JUSTIFY: Names recovered from metadata are arbitrary identifiers.
    pub name: Option<String>,

    /// Soroban signature recovered from `contractspecv0`. `None` when the
    /// function is not in the contract spec (e.g. a compiler-generated
    /// helper).
    pub signature: Option<FunctionSignature>,

    /// Underlying basic blocks. Regions reference these by id; passes
    /// may add or rewrite block contents but the structured `region`
    /// remains the source of truth for emission order.
    pub blocks: Arena<BlockId, HighBlock>,

    /// All bindings (typed value definitions) in this function.
    pub bindings: Arena<ValueId, Binding>,

    /// Structured control-flow root.
    pub region: Region,

    /// The function's parameters, in declaration order: the binding ids
    /// of the *entry block's* block params (each an
    /// [`Expr::Phi`](crate::Expr::Phi) with no intra-procedural
    /// incoming edges). Preserved from the lifted entry block by the
    /// boundary lowering — WASM erases parameter identity otherwise —
    /// so inter-procedural analyses can bind a caller's positional
    /// `Call` arguments to these ids, and the emitter can name them.
    /// Empty for a nullary function.
    pub params: Vec<ValueId>,

    /// The function's return sites, in block order: for every
    /// `Return` terminator in the lifted CFG, the values it returned.
    /// Preserved by the boundary lowering (`HighBlock` carries no
    /// terminators, so returns would otherwise be invisible) so
    /// inter-procedural analyses can resolve a caller's `Call` result
    /// from the callee's returned values, and the emitter can type the
    /// function result. Faithful record: 0-value and multi-value sites
    /// appear as-is; consumers guard on arity. Empty for a function
    /// with no reachable-or-not `Return` (diverging).
    pub returns: Vec<Vec<ValueId>>,
}

/// One basic block in the high IR.
///
/// HighBlock has no terminator: structured control flow lives in
/// [`Region`]. A block is just an ordered list of binding ids that
/// should be emitted in the surrounding region's straight-line
/// position.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct HighBlock {
    /// Identifier of this block within the enclosing function.
    pub id: BlockId,

    /// Bindings to emit, in execution order. Each id must resolve in the
    /// enclosing function's `bindings` arena.
    pub bindings: Vec<ValueId>,
}

/// One typed, expression-valued binding in the high IR.
///
/// The `provenance` field is **private**. The only ways to mutate it are
/// [`Binding::add_provenance`] (append) and the constructor (initial entry).
/// Direct assignment `binding.provenance = ...` would silently drop the
/// audit trail and is therefore prevented at compile time.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct Binding {
    /// Stable identifier of this binding (matches the arena key).
    pub id: ValueId,

    /// Inferred or known type of the value.
    pub ty: IrType,

    /// Expression producing the value.
    pub expr: Expr,

    /// Append-only audit trail. Latest entry is the most recent pass
    /// that touched this binding.
    provenance: Vec<Provenance>,
}

impl Binding {
    /// Construct a new binding with one initial provenance entry.
    ///
    /// The provenance is mandatory at construction time so that the
    /// `Vec<Provenance>` is non-empty by invariant.
    #[inline]
    #[must_use]
    pub fn new(id: ValueId, ty: IrType, expr: Expr, initial_provenance: Provenance) -> Self {
        Self {
            id,
            ty,
            expr,
            provenance: vec![initial_provenance],
        }
    }

    /// Append a provenance entry recording the most recent refinement.
    ///
    /// Passes call this when they update a binding's `ty` or `expr`. The
    /// vector is monotonically growing — entries are never removed or
    /// reordered.
    #[inline]
    pub fn add_provenance(&mut self, provenance: Provenance) {
        self.provenance.push(provenance);
    }

    /// Read the full provenance chain in chronological order.
    #[inline]
    #[must_use]
    pub fn provenance(&self) -> &[Provenance] {
        &self.provenance
    }

    /// Read the most recent provenance entry.
    ///
    /// Panics if the binding has no provenance, which would itself
    /// indicate a programmer bug — the constructor enforces a non-empty
    /// vector.
    #[inline]
    #[must_use]
    pub fn latest_provenance(&self) -> &Provenance {
        self.provenance
            .last()
            .expect("Binding::provenance vector must be non-empty by invariant")
    }
}
