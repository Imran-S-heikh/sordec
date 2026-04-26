# sordec — Architectural Design

This document is the canonical reference for the IR type system, pass infrastructure, and pipeline design. It supersedes informal discussion notes.

Every decision here was research-validated against production decompilers (Ghidra, Hex-Rays, Binary Ninja, RetDec, angr) and compiler infrastructure (LLVM, rustc, Cranelift, waffle).

The guiding principle: **the system should fail loudly at compile time, not silently at runtime**. We refuse silent guessing, redundant state, and weakly-typed identifiers.

---

## 1. Stable identifiers

All references between IR objects use newtype-wrapped `u32` IDs.

```rust
// In sordec-common/src/ids.rs

/// Module-global function identifier.
pub struct FuncId(u32);

/// Module-global type identifier.
pub struct TypeId(u32);

/// Block identifier — only valid within its owning FunctionBody.
/// Passing a BlockId from one function to another is undefined behavior;
/// debug builds catch this via arena bounds checks.
pub struct BlockId(u32);

/// SSA value identifier — only valid within its owning FunctionBody.
/// In SSA form, an instruction's result IS its identifier;
/// instructions and values are not separately identified.
pub struct ValueId(u32);
```

**Display impls** produce human-readable output: `FuncId(3) → "func3"`, `BlockId(7) → "bb7"`, `ValueId(42) → "v42"`.

**Standard derives**: `Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord`.

**No `InstructionId`** — in SSA, the instruction's name IS its result value. Instructions that produce no value (e.g., stores) still get a `ValueId` for reference, with type `Unit`.

---

## 2. Certainty: encoded structurally, not as a separate field

We do not have a standalone `Certainty` enum. Certainty is encoded in the variants of each type that can be uncertain.

```rust
pub enum IrType {
    Known(KnownType),         // proved from metadata or by analysis
    Inferred(KnownType),      // best guess from analysis
    Unknown(UnknownReason),   // could not determine
}

pub enum SemanticOp {
    Known(KnownOp),                    // we recognize this operation
    Unknown {                          // opaque host call
        host_module: String,
        host_fn: String,
        args: Vec<ValueId>,
        reason: UnknownReason,
    },
}

pub enum StorageTier {
    Known(KnownTier),         // proved from data flow
    Inferred(KnownTier),      // probably this tier
    Unknown,                  // can't determine
}
```

**Why structural and not as a separate field**: a separate `certainty` field can drift out of sync with the underlying type variant. The variant IS the source of truth. Pattern matching on the variant gives the certainty for free.

---

## 3. UnknownReason: forces explicit failure modes

Every `Unknown` carries why it's unknown. This makes debugging tractable and forces passes to be honest.

```rust
pub enum UnknownReason {
    /// Metadata did not include this entity.
    NoMetadata,

    /// Host function not present in our known-ABI table.
    UnrecognizedHostCall { module: String, name: String },

    /// WASM instruction sequence didn't match any known pattern.
    UnsupportedPattern,

    /// Analysis ran but evidence was inconclusive.
    InsufficientEvidence,

    /// Upstream data was Unknown; we could not propagate further.
    UpstreamUnknown,
}
```

Forbidden: a default `Unknown` constructor with no reason. Every Unknown must say WHY.

---

## 4. Provenance: append-only audit trail

Each binding (each typed value in the IR) carries a `Vec<Provenance>` — a chronological record of every pass that touched it.

```rust
pub struct Provenance {
    /// Which pass set or refined this. Compile-time string from the Pass impl.
    pub pass: &'static str,

    /// Category of how the information was obtained.
    pub source: ProvenanceSource,

    /// Optional human-readable context. Cow lets passes use static strings
    /// (zero allocation) when the message is fixed, String when formatted.
    pub note: std::borrow::Cow<'static, str>,
}

pub enum ProvenanceSource {
    /// Direct from contractspecv0 / contractmetav0 / contractenvmetav0.
    Metadata,

    /// Known Soroban host function ABI (e.g., `ledger.put_contract_data`).
    HostFunctionAbi,

    /// SDK-aware pattern matcher (e.g., "val-encode-u64").
    SdkPattern,

    /// SSA value tracing / use-def chains.
    DataFlow,

    /// Type unification from multiple uses.
    TypePropagation,

    /// Last-resort default. Should be RARE; prefer Unknown.
    Default,

    /// This entry refines an earlier provenance (chain marker).
    UpstreamRefinement,
}
```

**Refinement rule**: when a pass modifies a binding's type, expression, or operation, it APPENDS a new `Provenance` entry. Earlier entries are preserved. Helper: `binding.latest_provenance() -> &Provenance`.

**Why a Vec, not a single value**: full audit trail enables answering "why did we infer this?" by reading the chain. Memory cost is bounded (typically 1-3 entries per binding).

---

## 5. Three IR layers as distinct types

```rust
// Output of sordec-frontend (parser + metadata decoder)
pub struct WasmFacts { ... }

// Output of waffle lifting + our wrapping (in sordec-ir)
pub struct LiftedIr { ... }

// Refined through passes; what backend emits from (in sordec-ir)
pub struct HighIr { ... }
```

**Why three distinct types and not one refined type**: the type system enforces "you can only run this pass on this layer." A pass declared as `Pass<HighIr>` cannot be accidentally applied to a `LiftedIr`. Single-type designs require runtime checks for the same guarantee — we prefer compile-time.

**Layer responsibilities**:
- `WasmFacts`: parsed sections, imports, exports, custom sections, decoded metadata. No analysis.
- `LiftedIr`: SSA + CFG, close to WASM operators, function/block/value IDs assigned. No semantic recovery.
- `HighIr`: structured control flow (if/loop/match), recovered semantic operations, refined types. Backend reads this.

---

## 6. Mutation in place

Passes operate on `&mut Ir` and mutate. Returning new IRs per pass is impractical at scale (would copy the entire IR per pass).

This is universal practice across LLVM, rustc, Cranelift, Ghidra, and waffle.

For debugging "what did this pass change?", we provide opt-in JSON serialization between passes; we do not pay for it by default.

---

## 7. The Pass trait

The minimal contract every analysis or transformation pass must implement.

```rust
pub trait Pass<Ir> {
    /// Unique compile-time pass name. Used for diagnostics and logging.
    /// MUST be unique across all passes in any pipeline that contains this one.
    /// The Pipeline panics at construction if duplicates are detected.
    fn name(&self) -> &'static str;

    /// Run the pass on the IR.
    ///
    /// MUST be monotonic: refinements only ADD information or REPLACE Unknown
    /// with Inferred/Known, never the reverse. Never contradict prior passes.
    ///
    /// MUST be safe to call multiple times: passes are run in fixpoint loops
    /// and may be invoked repeatedly until no further changes occur.
    fn run(&self, ir: &mut Ir) -> PassResult;
}

pub struct PassResult {
    /// True iff the pass modified the IR's structure, types, expressions,
    /// or operations in a way that could affect another pass.
    /// Provenance/notes/metrics changes do NOT count.
    /// Used by the Pipeline to detect fixpoint termination.
    pub changed: bool,

    /// Optional named counters for diagnostics. Convention: keys like
    /// "unknowns_reduced", "dead_blocks_removed". String keys are accepted
    /// because metrics are diagnostic-only and never drive control flow.
    pub metrics: PassMetrics,

    /// Free-form human-readable notes for debugging.
    pub notes: Vec<String>,
}

pub struct PassMetrics {
    counters: std::collections::HashMap<&'static str, i64>,
}
```

**No `dependencies()` method**: dependencies are implicit in the Pipeline manifest order. The author of the manifest is responsible for correct ordering. This matches rustc, Cranelift, Ghidra, angr — all use manifests, not topological sort over string IDs.

**Pass configuration**: lives as struct fields on the pass implementor, not in the trait.

```rust
struct StorageTierPass { strict_mode: bool }
impl Pass<HighIr> for StorageTierPass { ... }
```

---

## 8. Pipeline: ordered passes with fixpoint groups

```rust
pub struct Pipeline<Ir> {
    /// Hand-ordered list of passes. The order IS the dependency declaration.
    pub passes: Vec<Box<dyn Pass<Ir>>>,

    /// Index ranges of consecutive passes that loop together until fixpoint.
    /// Passes outside any range run exactly once in declaration order.
    pub fixpoint_groups: Vec<std::ops::Range<usize>>,
}

impl<Ir> Pipeline<Ir> {
    /// Construct a pipeline. Panics if pass names are not unique
    /// or if fixpoint_groups overlap or contain out-of-bounds ranges.
    pub fn new(
        passes: Vec<Box<dyn Pass<Ir>>>,
        fixpoint_groups: Vec<std::ops::Range<usize>>,
    ) -> Self { ... }

    /// Execute the pipeline. Within fixpoint groups, passes loop until
    /// none return `changed: true`.
    pub fn run(&self, ir: &mut Ir) -> PipelineReport { ... }
}

pub struct PipelineReport {
    pub passes_run: usize,
    pub fixpoint_iterations: Vec<usize>,
    pub per_pass: Vec<(/* name */ &'static str, PassResult)>,
}
```

---

## 9. Lowering steps: explicit phase transitions

A "lowering" converts IR from one layer to another (e.g., `LiftedIr → HighIr`). Lowerings are NOT regular passes; they don't fit the `Pass<Ir>` trait because they produce a different type.

```rust
pub trait LoweringStep {
    type Input;
    type Output;
    fn name(&self) -> &'static str;
    fn lower(&self, input: Self::Input) -> Result<Self::Output, LoweringError>;
}
```

A lowering runs exactly once at a phase boundary. The Driver wires them in:

```rust
// In sordec-driver

pub struct Driver {
    lifted_pipeline: Pipeline<LiftedIr>,
    lower_to_high: Box<dyn LoweringStep<Input = LiftedIr, Output = HighIr>>,
    high_pipeline: Pipeline<HighIr>,
}

impl Driver {
    pub fn run(&self, wasm: &[u8]) -> Result<Output> {
        let facts = sordec_frontend::parse(wasm)?;
        let mut lifted = sordec_passes::lift_with_waffle(&facts)?;
        let lifted_report = self.lifted_pipeline.run(&mut lifted);

        let mut high = self.lower_to_high.lower(lifted)?;
        let high_report = self.high_pipeline.run(&mut high);

        sordec_backend::emit(&high)
    }
}
```

---

## 10. Invariants and validation

Each IR layer has invariants. Debug builds enforce them with `debug_assert!` after each pass; release builds skip the cost.

**LiftedIr invariants**:
- Every block has exactly one terminator.
- Every `ValueId` referenced has a definition.
- Every `BlockId` in a terminator's targets exists in the function.
- The CFG entry block is reachable.

**HighIr invariants**:
- All control flow is structured (no raw branch terminators outside loops/conditionals).
- Every binding's `provenance` is non-empty.
- `Unknown` variants always carry an `UnknownReason`.

A future `ValidationPass` can be added to enforce these in CI; for Phase 1 we rely on `debug_assert!`.

---

## 11. What we explicitly rejected

Documented to prevent re-litigation:

| Rejected | Reason |
|----------|--------|
| Numeric confidence scores (0-100, f32) | No production decompiler uses them. "0.73" tells nobody anything. |
| Standalone `Certainty` enum field | Redundant with type variants; risks drift. |
| Bayesian / weighted combining math | Hard to calibrate; never used in shipped tools. |
| Per-evidence base scores | Same — categorical sources are sufficient. |
| Fine-grained `Evidence` enum | Provenance + ProvenanceSource is enough. |
| `dependencies()` on Pass trait | rustc/Cranelift/Ghidra/angr all reject string-dep graphs. |
| Topological sort by pass name | Footgun: typos compile, cycles fail at runtime. |
| Analysis vs Transformation distinction | LLVM-only. We don't have analyses to cache yet. |
| "Preserved analyses" mechanism | Same — analyses don't exist. |
| Global pass registry singleton | LLVM-legacy regret (init-order hell). |
| Per-pass config in trait methods | rustc lesson: store in struct fields. |
| Strings as IR identifiers | Replaced by newtype `u32` IDs. |
| `_ => default` fallbacks anywhere | Replaced by `Unknown` variants with `UnknownReason`. |
| Single-IR-with-maturity-flags | Replaced by three distinct IR types. |
| Returning new IR per pass | Doesn't scale; mutate in place. |
| `InstructionId` distinct from `ValueId` | Same in SSA. |
| Lifetime-encoded ID scoping | Painful; document convention instead. |
| `LoweringStep` as a `Pass` | Different type signature; explicit phase boundary. |

---

## 12. Crate ownership of types

| Type | Crate | Notes |
|------|-------|-------|
| `FuncId`, `BlockId`, `ValueId`, `TypeId` | `sordec-common` | Shared by every layer |
| `Certainty` (none — encoded in variants) | — | Not a standalone type |
| `Provenance`, `ProvenanceSource` | `sordec-common` | Shared infrastructure |
| `UnknownReason` | `sordec-common` | Shared infrastructure |
| `WasmFacts` and decoded metadata types | `sordec-frontend` | Layer 1 |
| `LiftedIr`, `LiftedFunction`, `LiftedBlock`, `LiftedValue`, `WasmOp` | `sordec-ir` | Layer 2 |
| `HighIr`, `HighFunction`, `HighBlock`, `Binding`, `Expr`, `IrType`, `SemanticOp`, `StorageTier`, `Region` | `sordec-ir` | Layer 3 |
| `Pass`, `PassResult`, `PassMetrics`, `Pipeline`, `LoweringStep`, `Driver` | split — trait in `sordec-passes`, Driver in `sordec-driver` | |
