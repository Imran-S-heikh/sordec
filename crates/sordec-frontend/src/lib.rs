//! Frontend: parse raw WASM bytes and decode Soroban metadata.
//!
//! Single public entry point: [`parse`]. Hand it the bytes of a `.wasm`
//! file and you get back a [`WasmFacts`] (the WASM-level structure) plus
//! an `Option<`[`SorobanFacts`]`>` (the decoded Soroban metadata, or
//! `None` for generic WASM / stripped contracts).
//!
//! `WasmFacts` and `SorobanFacts` are peer types: WASM structure and
//! Soroban semantics are conceptually different layers and are returned
//! separately.
//!
//! Internally split into two modules:
//!
//! - `wasm` handles the standard WASM walk via `wasmparser`.
//! - `metadata` decodes the `contractspecv0` / `contractenvmetav0` /
//!   `contractmetav0` custom sections via `soroban-spec`, `soroban-meta`,
//!   and `stellar-xdr`.
//!
//! Both modules are private. The public API is intentionally small.
//!
//! ## Failure modes
//!
//! Every error returned by the frontend is a [`FrontendError`] variant.
//! Where the legacy decompiler used `unwrap_or_default()` on malformed
//! sections, this crate surfaces a typed error so the caller can decide
//! how to handle the failure. See the variants of [`FrontendError`] for
//! the full list.
//!
//! ## Example
//!
//! ```
//! use sordec_frontend::{parse, FrontendError};
//!
//! // The minimum valid WASM module: magic bytes + version.
//! let minimal_wasm: &[u8] = &[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
//!
//! let output = parse(minimal_wasm).expect("minimal WASM should parse");
//! assert!(output.wasm_facts.imports.is_empty());
//! assert!(output.wasm_facts.exports.is_empty());
//! // No `contractspecv0` section → not a Soroban contract.
//! assert!(output.soroban_facts.is_none());
//! assert!(output.diagnostics.is_empty());
//!
//! // Empty input is a typed error, not silent success.
//! assert!(matches!(parse(&[]), Err(FrontendError::Empty)));
//! ```

pub mod error;

mod metadata;
mod wasm;

pub use error::{FrontendError, FrontendResult};

// Re-export the IR types the frontend produces so most callers do not
// have to depend on `sordec-ir` directly.
pub use sordec_ir::{
    ByteRange, CompositeType, CustomSection, EnumCase, EnumDef, EnvCompatibility, EventDef,
    EventParam, EventParamLocation, Export, ExportKind, FunctionParam, FunctionSignature, Import,
    ImportKind, PrimitiveType, SorobanFacts, StructDef, StructField, TypeRef, TypeRegistry,
    UnionCase, UnionDef, WasmFacts,
};

// Re-export the diagnostic types so callers can match on them without
// pulling `sordec-common` into their import lists.
pub use sordec_common::{Diagnostic, DiagnosticCode, MetadataDiagnosticCode, Severity};

/// Output of [`parse`]: WASM-level facts, optional Soroban-level facts,
/// and the non-fatal diagnostics collected during parsing and metadata
/// decoding.
///
/// All three fields are independent. `wasm_facts` is always populated.
/// `soroban_facts` is `None` for non-Soroban WASM and for stripped
/// contracts. `diagnostics` is a `Vec` of structured warning/info events
/// — empty for clean inputs.
#[derive(Debug, Clone)]
pub struct ParseOutput {
    /// WASM-level structure: imports, exports, function-type-indices,
    /// custom sections.
    pub wasm_facts: WasmFacts,
    /// Decoded Soroban metadata when present, or `None` for non-Soroban
    /// or stripped contracts.
    pub soroban_facts: Option<SorobanFacts>,
    /// Non-fatal diagnostics surfaced during parsing or metadata
    /// decoding. Inspect `severity` to filter; `code` for typed
    /// matching.
    pub diagnostics: Vec<Diagnostic>,
}

/// Parse a WASM module and decode its Soroban metadata.
///
/// Returns a [`ParseOutput`] containing:
/// - The WASM-level [`WasmFacts`] (always populated on success).
/// - The Soroban [`SorobanFacts`] when the input contains a
///   `contractspecv0` section (`None` for generic WASM and for
///   contracts that have been aggressively stripped).
/// - A `Vec<`[`Diagnostic`]`>` accumulating non-fatal warnings and info
///   surfaced during parsing or metadata decoding.
///
/// # Errors
///
/// See [`FrontendError`] for the catalogue. The most common failures are
/// [`FrontendError::Empty`] for an empty slice, [`FrontendError::InvalidWasm`]
/// when `wasmparser` rejects the bytes, and [`FrontendError::MalformedSpec`]
/// when a `contractspecv0` section is present but cannot be decoded.
///
/// Conditions that previously errored but can now degrade with a Warning
/// diagnostic — `UnresolvedTypeReference`, `DuplicateTypeName`,
/// `DuplicateFunctionName`, `MalformedContractMeta` — appear in
/// `output.diagnostics` rather than as `Err` returns.
pub fn parse(wasm: &[u8]) -> FrontendResult<ParseOutput> {
    let wasm_facts = wasm::parse_module(wasm)?;
    let mut diagnostics: Vec<Diagnostic> = Vec::new();
    let soroban_facts = metadata::decode_metadata(&wasm_facts.custom_sections, &mut diagnostics)?;
    Ok(ParseOutput {
        wasm_facts,
        soroban_facts,
        diagnostics,
    })
}
