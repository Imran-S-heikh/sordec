//! Top-level pipeline orchestrator.
//!
//! [`Driver`] wires the frontend, the lifted-IR pipeline, the boundary
//! lowering, the high-IR pipeline, and the backend into a single
//! sequenced operation. It owns nothing except references and pipeline
//! structures; per-run state lives on the IR values it threads through.
//!
//! ## Pipeline progress
//!
//! As of Task 1.5, [`Driver::run`] now:
//!
//! 1. Calls `sordec_frontend::parse(wasm)` to produce typed
//!    [`sordec_ir::WasmFacts`] (Task 1.4).
//! 2. Calls `sordec_passes::lift_with_waffle(wasm, &facts)` to produce
//!    [`sordec_ir::LiftedIr`] (Task 1.5).
//! 3. Runs `self.lifted_pipeline.run(&mut lifted)` — this currently
//!    runs zero passes because semantic recovery lives in Phase 2.
//! 4. Returns [`DriverError::NotYetWired`] when it would otherwise
//!    invoke the boundary lowering: no [`sordec_passes::LoweringStep`]
//!    implementor exists yet, and the [`sordec_backend`] emitters
//!    likewise have not been written.
//!
//! After Task 1.5, the front half of the pipeline runs end-to-end on a
//! real contract; the back half (lowering, high-IR passes, emit) lands
//! in subsequent tasks.

use sordec_common::Diagnostic;
use sordec_frontend::FrontendError;
use sordec_ir::{HighIr, LiftedIr};
use sordec_passes::{LiftError, LoweringError, LoweringStep, Pipeline, PipelineReport};

/// End-to-end decompilation driver.
///
/// Construct via [`Driver::new`] with the three pipeline pieces. Each
/// `Driver` is reusable across many `run` invocations.
pub struct Driver {
    lifted_pipeline: Pipeline<LiftedIr>,
    lower: Box<dyn LoweringStep<Input = LiftedIr, Output = HighIr>>,
    high_pipeline: Pipeline<HighIr>,
}

impl Driver {
    /// Build a driver from its three components.
    #[must_use]
    pub fn new(
        lifted_pipeline: Pipeline<LiftedIr>,
        lower: Box<dyn LoweringStep<Input = LiftedIr, Output = HighIr>>,
        high_pipeline: Pipeline<HighIr>,
    ) -> Self {
        Self {
            lifted_pipeline,
            lower,
            high_pipeline,
        }
    }

    /// Decompile a WASM module from raw bytes.
    ///
    /// # Sequence
    ///
    /// 1. `sordec_frontend::parse(wasm)` → [`sordec_ir::WasmFacts`]
    ///    (implemented).
    /// 2. `sordec_passes::lift_with_waffle(wasm, &facts)` →
    ///    [`LiftedIr`] (implemented).
    /// 3. `self.lifted_pipeline.run(&mut lifted)` — lifted-IR passes
    ///    (currently empty; Phase 2 fills them in).
    /// 4. `self.lower.lower(lifted)` → [`HighIr`] — **not yet wired**;
    ///    surfaces [`DriverError::NotYetWired`].
    /// 5. `self.high_pipeline.run(&mut high)` — high-IR passes (Phase
    ///    2-3).
    /// 6. `sordec_backend::emit(&high)` → [`DecompileOutput`] (Phase
    ///    3-4).
    ///
    /// # Errors
    ///
    /// - [`DriverError::Frontend`] when `wasmparser` rejects the input
    ///   or Soroban metadata fails to decode.
    /// - [`DriverError::Lift`] when `waffle` rejects the input or our
    ///   IR-shape invariants are violated post-SSA.
    /// - [`DriverError::NotYetWired`] when the front half completes
    ///   successfully but the back half is not yet implemented.
    /// - [`DriverError::Lowering`] (future) once a [`LoweringStep`]
    ///   implementor exists.
    pub fn run(&self, wasm: &[u8]) -> Result<DecompileOutput, DriverError> {
        // Stage 1: parse WASM + decode Soroban metadata.
        let parse_output = sordec_frontend::parse(wasm)?;

        // Stage 2: lift to typed SSA + CFG.
        let lift_output = sordec_passes::lift_with_waffle(
            wasm,
            &parse_output.wasm_facts,
            parse_output.soroban_facts.as_ref(),
        )?;
        let mut lifted = lift_output.lifted;

        // Stage 3: run the lifted-IR pipeline. With zero passes
        // registered today, this is a no-op; the call is preserved so
        // the wiring stays exercised when real passes land.
        let _lifted_report = self.lifted_pipeline.run(&mut lifted);

        // Stages 4-6 require a `LoweringStep` implementor and a
        // backend, neither of which exist yet. Surface a typed error
        // rather than silently producing an empty output.
        //
        // Diagnostics gap (acknowledged, not yet fixed): stages 1 and 2
        // produce `parse_output.diagnostics` and `lift_output.diagnostics`,
        // which we don't surface to the caller because we error out
        // here. `DriverReport` already has a `diagnostics` field for
        // when this changes — when the back half of the pipeline lands
        // and `run` can return `Ok`, populate it as
        // `parse_output.diagnostics.into_iter().chain(lift_output.diagnostics).collect()`.
        // Until then, callers who need diagnostics should call
        // `sordec_frontend::parse` and `sordec_passes::lift_with_waffle`
        // directly — the CLI's `dump-facts` / `dump-ir` subcommands will
        // do exactly that in the next sub-task.
        Err(DriverError::NotYetWired)
    }

    /// Number of passes in the lifted-IR pipeline. Useful for tests and
    /// CLI introspection.
    #[inline]
    #[must_use]
    pub fn lifted_pass_count(&self) -> usize {
        self.lifted_pipeline.len()
    }

    /// Number of passes in the high-IR pipeline.
    #[inline]
    #[must_use]
    pub fn high_pass_count(&self) -> usize {
        self.high_pipeline.len()
    }

    /// Name of the boundary lowering step, for diagnostics.
    #[inline]
    #[must_use]
    pub fn lowering_name(&self) -> &'static str {
        self.lower.name()
    }
}

/// Output of a successful [`Driver::run`].
///
/// Currently a placeholder. The backend that populates these fields
/// does not yet exist.
#[derive(Debug, Default, Clone)]
pub struct DecompileOutput {
    /// Annotated WebAssembly Text. Empty until the WAT emitter lands.
    pub wat: String,

    /// Compilable Rust source. Empty until the Rust emitter lands.
    pub rust: String,

    /// Per-stage diagnostics from the pipeline.
    pub report: Option<DriverReport>,
}

/// Per-run diagnostics combining both pipelines and the lowering step.
#[derive(Debug, Default, Clone)]
pub struct DriverReport {
    /// Non-fatal diagnostics surfaced by the frontend, lifter, and
    /// passes during this run. Concatenated in declaration order so
    /// callers can print them sequentially.
    pub diagnostics: Vec<Diagnostic>,
    /// Report from the lifted-IR pipeline.
    pub lifted: Option<PipelineReport>,
    /// Report from the high-IR pipeline.
    pub high: Option<PipelineReport>,
}

/// Reason a [`Driver::run`] invocation failed.
///
/// `#[non_exhaustive]` so future stages (backend, structuring failures)
/// can add their own variants without breaking matchers.
#[non_exhaustive]
#[derive(Debug)]
pub enum DriverError {
    /// The frontend (parser + Soroban metadata decoder) reported an
    /// error.
    Frontend(FrontendError),

    /// The lifter (`waffle` integration) reported an error.
    Lift(LiftError),

    /// The driver successfully completed everything that is
    /// implemented (parse, lift, lifted-pipeline) but the rest of the
    /// pipeline (lowering, high-pipeline, emit) is not yet wired.
    NotYetWired,

    /// The phase-boundary lowering reported an error. Reachable only
    /// once a [`LoweringStep`] implementor exists; today this variant
    /// is unreachable from [`Driver::run`].
    Lowering(LoweringError),
}

impl From<FrontendError> for DriverError {
    fn from(err: FrontendError) -> Self {
        Self::Frontend(err)
    }
}

impl From<LiftError> for DriverError {
    fn from(err: LiftError) -> Self {
        Self::Lift(err)
    }
}

impl From<LoweringError> for DriverError {
    fn from(err: LoweringError) -> Self {
        Self::Lowering(err)
    }
}
