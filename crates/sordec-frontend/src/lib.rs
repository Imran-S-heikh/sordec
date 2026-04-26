//! Frontend: parse raw WASM bytes and decode Soroban metadata.
//!
//! Single public entry point: [`parse`]. Hand it the bytes of a `.wasm`
//! file and you get back a fully populated [`WasmFacts`] — including the
//! decoded `SorobanMetadata` for Soroban contracts, or `None` for
//! generic WASM modules.
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
//! let facts = parse(minimal_wasm).expect("minimal WASM should parse");
//! assert!(facts.imports.is_empty());
//! assert!(facts.exports.is_empty());
//! // No `contractspecv0` section → not a Soroban contract.
//! assert!(facts.metadata.is_none());
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
    ImportKind, PrimitiveType, SorobanMetadata, StructDef, StructField, TypeRef, TypeRegistry,
    UnionCase, UnionDef, WasmFacts,
};

/// Parse a WASM module and decode its Soroban metadata.
///
/// On success, the returned [`WasmFacts`] always contains the parsed
/// imports/exports/function-type-indices/custom-sections. Its `metadata`
/// field is `Some(SorobanMetadata)` when the input contained a
/// `contractspecv0` custom section, and `None` for generic WASM.
///
/// # Errors
///
/// See [`FrontendError`] for the catalogue. The most common failures are
/// [`FrontendError::Empty`] for an empty slice, [`FrontendError::InvalidWasm`]
/// when `wasmparser` rejects the bytes, and [`FrontendError::MalformedSpec`]
/// when a `contractspecv0` section is present but cannot be decoded.
pub fn parse(wasm: &[u8]) -> FrontendResult<WasmFacts> {
    let mut facts = wasm::parse_module(wasm)?;
    facts.metadata = metadata::decode_metadata(&facts.custom_sections)?;
    Ok(facts)
}
