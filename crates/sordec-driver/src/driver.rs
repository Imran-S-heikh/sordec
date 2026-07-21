//! Top-level pipeline orchestrator.
//!
//! [`Driver`] wires the frontend, the lifted-IR pipeline, the boundary
//! lowering, the high-IR pipeline, and the backend into a single
//! sequenced operation. It owns nothing except references and pipeline
//! structures; per-run state lives on the IR values it threads through.
//!
//! ## Pipeline
//!
//! [`Driver::run`] executes the whole decompilation end-to-end:
//!
//! 1. `sordec_frontend::parse(wasm)` → typed [`sordec_ir::WasmFacts`].
//! 2. `sordec_passes::lift_with_waffle(wasm, &facts)` →
//!    [`sordec_ir::LiftedIr`].
//! 3. `self.lifted_pipeline.run(&mut lifted)` — the de-cluttering
//!    passes.
//! 4. `self.lower.lower(lifted)` → [`HighIr`] (the `LiftToHigh`
//!    boundary lowering).
//! 5. `self.high_pipeline.run(&mut high)` — structuring + semantic
//!    recovery.
//! 6. `sordec_backend::emit_annotated_wat(&high, wasm)` → the annotated
//!    WAT on [`DecompileOutput::wat`]. (Rust emit — [`DecompileOutput::rust`]
//!    — is Phase 4; empty for now.)
//!
//! [`Driver::standard`] builds this with the default pipelines; the CLI's
//! `decompile` command is a thin wrapper over it.

use sordec_backend::BackendError;
use sordec_common::Diagnostic;
use sordec_frontend::FrontendError;
use sordec_ir::{HighIr, LiftedIr};
use sordec_passes::{
    default_high_pipeline, default_lifted_pipeline, LiftError, LiftToHigh, LoweringError,
    LoweringStep, Pipeline, PipelineReport,
};

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

    /// Build the standard decompilation driver: the default lifted-IR
    /// de-cluttering pipeline, the [`LiftToHigh`] boundary lowering, and
    /// the default high-IR recovery pipeline. This is the exact pipeline
    /// the CLI's `decompile` command runs (and the Phase-4 emitters will
    /// extend).
    #[must_use]
    pub fn standard() -> Self {
        Self::new(
            default_lifted_pipeline(),
            Box::new(LiftToHigh),
            default_high_pipeline(),
        )
    }

    /// Decompile a WASM module from raw bytes into a [`DecompileOutput`]
    /// (annotated WAT today; Rust source in Phase 4).
    ///
    /// # Sequence
    ///
    /// 1. `sordec_frontend::parse(wasm)` → [`sordec_ir::WasmFacts`].
    /// 2. `sordec_passes::lift_with_waffle(wasm, &facts)` → [`LiftedIr`].
    /// 3. `self.lifted_pipeline.run(&mut lifted)` — de-cluttering passes.
    /// 4. `self.lower.lower(lifted)` → [`HighIr`].
    /// 5. `self.high_pipeline.run(&mut high)` — structuring + recovery.
    /// 6. `sordec_backend::emit_annotated_wat(&high, wasm)` → the
    ///    annotated WAT.
    ///
    /// Non-fatal diagnostics from every stage are collected, in pipeline
    /// order, onto [`DriverReport::diagnostics`].
    ///
    /// # Errors
    ///
    /// - [`DriverError::Frontend`] when `wasmparser` rejects the input or
    ///   Soroban metadata fails to decode.
    /// - [`DriverError::Lift`] when `waffle` rejects the input or an
    ///   IR-shape invariant is violated post-SSA.
    /// - [`DriverError::Lowering`] when the boundary lowering rejects the
    ///   lifted IR.
    /// - [`DriverError::Backend`] when the emitter cannot disassemble the
    ///   module.
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

        // Stage 3: de-cluttering pipeline on the lifted IR.
        let lifted_report = self.lifted_pipeline.run(&mut lifted);

        // Stage 4: boundary lowering LiftedIr → HighIr.
        let mut high = self.lower.lower(lifted)?;

        // Stage 5: high-IR pipeline (structuring + semantic recovery).
        let high_report = self.high_pipeline.run(&mut high);

        // Stage 6: emit annotated WAT (Rust emit is Phase 4).
        let wat = sordec_backend::emit_annotated_wat(&high, wasm)?;

        // Surface every non-fatal diagnostic in pipeline order.
        let mut diagnostics = parse_output.diagnostics.into_vec();
        diagnostics.extend(lift_output.diagnostics.into_vec());
        diagnostics.extend(lifted_report.diagnostics().cloned());
        diagnostics.extend(high_report.diagnostics().cloned());

        Ok(DecompileOutput {
            wat,
            rust: String::new(),
            report: Some(DriverReport {
                diagnostics,
                lifted: Some(lifted_report),
                high: Some(high_report),
            }),
        })
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
/// `#[non_exhaustive]` so future stages can add their own variants
/// without breaking matchers.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum DriverError {
    /// The frontend (parser + Soroban metadata decoder) reported an
    /// error.
    #[error("frontend error: {0}")]
    Frontend(#[from] FrontendError),

    /// The lifter (`waffle` integration) reported an error.
    #[error("lift error: {0}")]
    Lift(#[from] LiftError),

    /// The phase-boundary lowering rejected the lifted IR.
    // `LoweringError` derives `Debug` but not `std::error::Error`, so it
    // can't be a `#[from]`/`#[source]` field — format via `Debug` and
    // provide the conversion by hand below.
    #[error("lowering error: {0:?}")]
    Lowering(LoweringError),

    /// The backend could not emit output (WAT disassembly failed).
    #[error("backend error: {0}")]
    Backend(#[from] BackendError),
}

impl From<LoweringError> for DriverError {
    fn from(err: LoweringError) -> Self {
        Self::Lowering(err)
    }
}
