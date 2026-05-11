//! WASM-binary walk: produces a [`WasmFacts`] with raw fields populated.
//!
//! This module handles only the standard WASM side: imports, exports,
//! function-type indices, and custom sections (raw bytes). The
//! `metadata` field is left as `None` here; [`crate::metadata`] fills it
//! in later from the custom-section bytes.
//!
//! We rely on `wasmparser` to do the binary decoding. The job of this
//! file is to translate `wasmparser`'s API into our typed
//! [`ImportKind`] / [`ExportKind`] / [`CustomSection`] shape (the legacy
//! decompiler stored these as strings, which we deliberately avoid).

use sordec_ir::{ByteRange, CustomSection, Export, ExportKind, Import, ImportKind, WasmFacts};
use wasmparser::{ExternalKind, Parser, Payload, TypeRef};

use crate::error::{FrontendError, FrontendResult};

/// Walk the WASM module and extract the raw fields of [`WasmFacts`].
///
/// On success, `metadata` is `None`. The metadata decoder fills it in
/// based on the custom-section bytes.
pub(crate) fn parse_module(wasm: &[u8]) -> FrontendResult<WasmFacts> {
    if wasm.is_empty() {
        return Err(FrontendError::Empty);
    }

    let mut imports = Vec::<Import>::new();
    let mut exports = Vec::<Export>::new();
    let mut function_type_indices = Vec::<u32>::new();
    let mut custom_sections = Vec::<CustomSection>::new();
    let mut import_index: u32 = 0;

    for payload in Parser::new(0).parse_all(wasm) {
        let payload = payload?;
        match payload {
            // Imports — translate `wasmparser::TypeRef` exhaustively into our typed `ImportKind`.
            Payload::ImportSection(reader) => {
                for import in reader {
                    let import = import?;
                    imports.push(Import {
                        index: import_index,
                        module: import.module.to_string(),
                        name: import.name.to_string(),
                        kind: import_kind_from_type_ref(import.ty),
                    });
                    import_index = import_index.saturating_add(1);
                }
            }

            // Function section — list of type indices, one per local function.
            Payload::FunctionSection(reader) => {
                for type_idx in reader {
                    function_type_indices.push(type_idx?);
                }
            }

            // Exports — translate `wasmparser::ExternalKind` exhaustively into our typed `ExportKind`.
            Payload::ExportSection(reader) => {
                for export in reader {
                    let export = export?;
                    exports.push(Export {
                        name: export.name.to_string(),
                        kind: export_kind_from_external_kind(export.kind),
                        index: export.index,
                    });
                }
            }

            // Custom sections — preserve name, byte range, and raw bytes for
            // downstream metadata decoding (Soroban) and analysis.
            Payload::CustomSection(section) => {
                let range = section.range();
                debug_assert!(
                    range.start <= range.end,
                    "wasmparser yielded a custom section whose end < start"
                );
                custom_sections.push(CustomSection {
                    name: section.name().to_string(),
                    byte_range: ByteRange {
                        start: range.start as u64,
                        end: range.end as u64,
                    },
                    bytes: section.data().to_vec(),
                });
            }

            // Sections we deliberately do not consume in detail. We only
            // care about their presence (most do not contribute to
            // `WasmFacts` — the Lifted IR pass will revisit the binary
            // for code-section bodies).
            Payload::TypeSection(_)
            | Payload::TableSection(_)
            | Payload::MemorySection(_)
            | Payload::TagSection(_)
            | Payload::GlobalSection(_)
            | Payload::StartSection { .. }
            | Payload::ElementSection(_)
            | Payload::DataSection(_)
            | Payload::DataCountSection { .. }
            | Payload::CodeSectionStart { .. }
            | Payload::CodeSectionEntry(_)
            | Payload::Version { .. }
            | Payload::End(_) => {}

            // We deliberately ignore component-model and module-linking
            // payloads; this frontend only handles core WASM modules
            // produced by the Soroban toolchain. Adding handling would
            // be a deliberate widening of scope, not a routine fix.
            _ => {}
        }
    }

    Ok(WasmFacts {
        imports,
        exports,
        function_type_indices,
        custom_sections,
    })
}

/// Translate `wasmparser::TypeRef` into our typed [`ImportKind`].
///
/// Exhaustive over `TypeRef` variants — if `wasmparser` adds a new
/// variant in a future bump we want a compile error, not silent data loss.
fn import_kind_from_type_ref(type_ref: TypeRef) -> ImportKind {
    match type_ref {
        TypeRef::Func(type_idx) => ImportKind::Func(type_idx),
        TypeRef::Table(_) => ImportKind::Table,
        TypeRef::Memory(_) => ImportKind::Memory,
        TypeRef::Global(_) => ImportKind::Global,
        TypeRef::Tag(_) => ImportKind::Tag,
    }
}

/// Translate `wasmparser::ExternalKind` into our typed [`ExportKind`].
///
/// Exhaustive — same reasoning as [`import_kind_from_type_ref`]. We
/// preserve `ExportKind::Tag` rather than silently miscategorising
/// exception-tag exports as functions; Soroban contracts do not use
/// tags but the frontend must not lie about non-Soroban WASM either.
fn export_kind_from_external_kind(kind: ExternalKind) -> ExportKind {
    match kind {
        ExternalKind::Func => ExportKind::Func,
        ExternalKind::Table => ExportKind::Table,
        ExternalKind::Memory => ExportKind::Memory,
        ExternalKind::Global => ExportKind::Global,
        ExternalKind::Tag => ExportKind::Tag,
    }
}
