//! Top-level pipeline orchestrator.
//!
//! [`Driver`] wires the frontend, the lifted-IR pipeline, the boundary
//! lowering, the high-IR pipeline, and the backend into a single
//! sequenced operation. It owns nothing except references and pipeline
//! structures; per-run state lives on the IR values it threads through.
//!
//! Phase 1.2 ships the [`Driver`] structure and constructor. The
//! [`Driver::run`] method is a `todo!()` stub: the frontend, lifting
//! pass, and backend that it would call do not yet exist as functions.
//! Tasks 1.3 (pass infrastructure now done), 1.4 (frontend), 1.5
//! (waffle integration), and the eventual backend will fill in the
//! body. The signature is locked in now so downstream code can target
//! it.

use sordec_ir::{HighIr, LiftedIr};
use sordec_passes::{LoweringError, LoweringStep, Pipeline, PipelineReport};

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
    /// Sequence (will be wired up across tasks 1.4/1.5 and the
    /// eventual backend):
    ///
    /// 1. `sordec_frontend::parse(wasm)` → [`WasmFacts`].
    /// 2. Lifting pass: [`WasmFacts`] → [`LiftedIr`] (waffle adapter).
    /// 3. `self.lifted_pipeline.run(&mut lifted)` (lifted-IR passes).
    /// 4. `self.lower.lower(lifted)` → [`HighIr`] (phase boundary).
    /// 5. `self.high_pipeline.run(&mut high)` (high-IR passes).
    /// 6. `sordec_backend::emit(&high)` → [`DecompileOutput`].
    ///
    /// # Errors
    ///
    /// Returns a [`DriverError`] if any stage fails. The current stub
    /// always returns `Err(DriverError::NotYetWired)`; once the
    /// frontend and backend land, this will instead surface their
    /// errors.
    pub fn run(&self, _wasm: &[u8]) -> Result<DecompileOutput, DriverError> {
        // Phase 1.2 ships only the type signature. The body is
        // intentionally a stub; implementation lands in subsequent
        // tasks. Surrounding tests / callers should not yet rely on
        // a successful return.
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
/// Phase 1.2 leaves this as a placeholder struct: the backend that
/// populates these fields does not yet exist. Concrete fields land
/// alongside the WAT and Rust emitters.
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
    /// Report from the lifted-IR pipeline.
    pub lifted: Option<PipelineReport>,
    /// Report from the high-IR pipeline.
    pub high: Option<PipelineReport>,
}

/// Reason a [`Driver::run`] invocation failed.
///
/// `#[non_exhaustive]` so future stages (frontend, backend) can add
/// their own variants without breaking matchers.
#[non_exhaustive]
#[derive(Debug)]
pub enum DriverError {
    /// The driver's body is still a stub. Phase 1.2 ships the
    /// signature only; remove this variant once Tasks 1.4/1.5/backend
    /// fill in the body.
    NotYetWired,

    /// The phase-boundary lowering reported an error.
    Lowering(LoweringError),
}

impl From<LoweringError> for DriverError {
    fn from(err: LoweringError) -> Self {
        Self::Lowering(err)
    }
}
