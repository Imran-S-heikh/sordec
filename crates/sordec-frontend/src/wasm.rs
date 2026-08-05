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

use sordec_ir::{
    ByteRange, CustomSection, Export, ExportKind, Import, ImportKind, WasmFacts,
};
use sordec_sigs::{Fingerprint, fingerprint_module};
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
    let mut function_bodies = Vec::<ByteRange>::new();
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

            // Code-section bodies — record each local function's byte
            // range so the emitter can anchor annotations to the printed
            // WAT. Bodies appear in declaration order, parallel to
            // `function_type_indices`. We keep only the span here; the
            // Lifted IR pass revisits the binary for the actual bytecode.
            Payload::CodeSectionEntry(body) => {
                let range = body.range();
                debug_assert!(
                    range.start <= range.end,
                    "wasmparser yielded a function body whose end < start"
                );
                function_bodies.push(ByteRange {
                    start: range.start as u64,
                    end: range.end as u64,
                });
            }

            // Sections we deliberately do not consume in detail. We only
            // care about their presence (most do not contribute to
            // `WasmFacts`).
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
            | Payload::Version { .. }
            | Payload::End(_) => {}

            // We deliberately ignore component-model and module-linking
            // payloads; this frontend only handles core WASM modules
            // produced by the Soroban toolchain. Adding handling would
            // be a deliberate widening of scope, not a routine fix.
            _ => {}
        }
    }

    // Fingerprints are computed after the walk rather than inside it: a
    // body's fingerprint needs the *complete* import list to tell a host
    // call from a module-local one, and while a valid module orders imports
    // before code, nothing here should depend on that.
    // Delegates to `sordec-sigs` rather than reimplementing the walk: two
    // copies of the normalisation rules would be two keyspaces, and they
    // would diverge silently as a catalogue that stops matching. A body
    // that cannot be fingerprinted yields `None` rather than failing the
    // parse — identification is an enhancement, and a genuinely malformed
    // code section fails later in the lifter with a better error.
    let function_fingerprints = fingerprint_module(wasm)
        .map(|v| v.into_iter().map(|f| f.map(Fingerprint::to_u128)).collect())
        .unwrap_or_default();

    Ok(WasmFacts {
        imports,
        exports,
        function_type_indices,
        function_bodies,
        function_fingerprints,
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

#[cfg(test)]
mod fingerprint_tests {
    use super::*;

    /// The shipped fixture carries no names; its labelled rebuild carries
    /// 46. Their code sections are byte-identical, so **the fingerprints
    /// must be identical too** — that is what proves identification reads
    /// code rather than symbols, and is the regression that would catch a
    /// label leaking from the oracle into the decompile path.
    #[test]
    fn fingerprints_ignore_the_name_section() {
        let stripped = std::fs::read("../../samples/contracts/token-v23/token-v23.wasm")
            .expect("fixture present");
        let labelled_path = format!(
            "{}/.cache/sordec/oracle/wasm/fixture-token-v23__soroban_token_contract.wasm",
            std::env::var("HOME").unwrap_or_default()
        );
        let Ok(labelled) = std::fs::read(&labelled_path) else {
            // The oracle corpus is a development artefact, not committed.
            // Skip rather than fail on a machine that has not built it.
            return;
        };

        let a = parse_module(&stripped).expect("stripped parses");
        let b = parse_module(&labelled).expect("labelled parses");

        assert_eq!(
            a.function_fingerprints, b.function_fingerprints,
            "a name section must not change a single fingerprint"
        );
        assert!(
            a.function_fingerprints.iter().any(Option::is_some),
            "the fixture should fingerprint at least one body"
        );
    }
}
