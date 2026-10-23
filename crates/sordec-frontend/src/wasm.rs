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

/// The four bytes every WASM module starts with: `\0asm`.
const WASM_MAGIC: &[u8] = b"\0asm";

/// Render the first four bytes for a "this is not WASM" message.
///
/// Printable ASCII comes out as a quoted string, because the mistake is
/// usually recognisable at a glance — `"#!/u"` is a script, `"<htm"` is an
/// error page, `"\x7fELF"` is a native binary. Anything else falls back to hex.
fn describe_leading_bytes(wasm: &[u8]) -> String {
    let head = &wasm[..wasm.len().min(WASM_MAGIC.len())];
    if head.len() < WASM_MAGIC.len() {
        return format!("only {} byte(s)", head.len());
    }
    if head.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
        format!("{:?}", String::from_utf8_lossy(head))
    } else {
        let hex: Vec<String> = head.iter().map(|b| format!("{b:#04x}")).collect();
        format!("[{}]", hex.join(" "))
    }
}

/// Walk the WASM module and extract the raw fields of [`WasmFacts`].
///
/// On success, `metadata` is `None`. The metadata decoder fills it in
/// based on the custom-section bytes.
pub(crate) fn parse_module(wasm: &[u8]) -> FrontendResult<WasmFacts> {
    if wasm.is_empty() {
        return Err(FrontendError::Empty);
    }
    if !wasm.starts_with(WASM_MAGIC) {
        return Err(FrontendError::NotWasm {
            found: describe_leading_bytes(wasm),
        });
    }

    let mut imports = Vec::<Import>::new();
    let mut exports = Vec::<Export>::new();
    let mut function_type_indices = Vec::<u32>::new();
    let mut function_bodies = Vec::<ByteRange>::new();
    let mut custom_sections = Vec::<CustomSection>::new();
    // `Some` until an element item cannot be read; see `table_functions`.
    let mut table_functions: Option<Vec<u32>> = Some(Vec::new());
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

            // Element segments — every function any of them declares, the
            // complete set a `call_indirect` can reach.
            Payload::ElementSection(reader) => {
                for element in reader {
                    let element = element?;
                    let Some(found) = table_functions.as_mut() else { break };
                    if !element_functions(&element.items, found)? {
                        table_functions = None;
                    }
                }
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
        table_functions,
        custom_sections,
    })
}

/// Append the functions one element segment declares to `found`. `false`
/// when an item is anything but `ref.func` or `ref.null` — a `global.get`,
/// say — whose function this parser cannot name.
fn element_functions(items: &wasmparser::ElementItems<'_>, found: &mut Vec<u32>) -> FrontendResult<bool> {
    match items {
        wasmparser::ElementItems::Functions(reader) => {
            for index in reader.clone() {
                found.push(index?);
            }
        }
        wasmparser::ElementItems::Expressions(_, reader) => {
            for expr in reader.clone() {
                let mut ops = expr?.get_operators_reader();
                match ops.read()? {
                    wasmparser::Operator::RefFunc { function_index } => found.push(function_index),
                    wasmparser::Operator::RefNull { .. } => {}
                    _ => return Ok(false),
                }
            }
        }
    }
    Ok(true)
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
mod magic_tests {
    use super::*;

    /// The wrong file is the commonest mistake, and the message has to be
    /// readable. `wasmparser` reports this by pretty-printing two byte arrays
    /// across ten lines; we say it in one, and name what we found so the user
    /// recognises their own mistake.
    #[test]
    fn a_non_wasm_input_is_named_as_such_in_one_line() {
        let err = parse_module(b"not wasm at all").expect_err("must reject");
        let msg = err.to_string();

        assert!(matches!(err, FrontendError::NotWasm { .. }), "{err:?}");
        assert_eq!(msg.lines().count(), 1, "must stay one line: {msg}");
        assert!(msg.contains("not a WASM file"), "{msg}");
        assert!(msg.contains(r#""not ""#), "should quote what it found: {msg}");
    }

    /// Non-printable leading bytes fall back to hex rather than mojibake.
    #[test]
    fn unprintable_leading_bytes_render_as_hex() {
        let err = parse_module(&[0x7f, 0x45, 0x4c, 0x00]).expect_err("must reject");
        let msg = err.to_string();
        assert!(msg.contains("0x7f"), "{msg}");
        assert_eq!(msg.lines().count(), 1, "{msg}");
    }

    /// Shorter than the magic number is its own case: there is nothing to
    /// compare, and "found 2 bytes" is more use than a truncated quote.
    #[test]
    fn a_truncated_input_says_how_short_it_was() {
        let err = parse_module(b"\0a").expect_err("must reject");
        assert!(err.to_string().contains("only 2 byte(s)"), "{err}");
    }

    /// The guard must not reject real modules — the magic number is the only
    /// thing it looks at, and the corpus starts with it.
    #[test]
    fn a_real_module_passes_the_guard() {
        let wasm = std::fs::read("../../samples/contracts/hello-add/hello-add.wasm")
            .expect("fixture present");
        assert!(wasm.starts_with(WASM_MAGIC));
        parse_module(&wasm).expect("the guard must not reject a real module");
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

#[cfg(test)]
mod table_tests {
    use super::*;

    /// Two `() -> ()` functions, a two-slot funcref table, and optionally
    /// an active element segment putting function 1 in slot 0.
    fn module(with_element: bool) -> Vec<u8> {
        let mut m = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        m.extend([0x01, 0x04, 0x01, 0x60, 0x00, 0x00]); // type: () -> ()
        m.extend([0x03, 0x03, 0x02, 0x00, 0x00]); // two functions of type 0
        m.extend([0x04, 0x04, 0x01, 0x70, 0x00, 0x02]); // funcref table, min 2
        if with_element {
            // active, table 0, offset i32.const 0, [func 1]
            m.extend([0x09, 0x07, 0x01, 0x00, 0x41, 0x00, 0x0b, 0x01, 0x01]);
        }
        m.extend([0x0a, 0x07, 0x02, 0x02, 0x00, 0x0b, 0x02, 0x00, 0x0b]); // two empty bodies
        m
    }

    #[test]
    fn an_element_segment_names_the_functions_a_table_can_hold() {
        let facts = parse_module(&module(true)).expect("valid module");
        assert_eq!(facts.table_functions, Some(vec![1]));
    }

    #[test]
    fn no_element_segment_means_no_function_can_be_called_indirectly() {
        let facts = parse_module(&module(false)).expect("valid module");
        assert_eq!(facts.table_functions, Some(vec![]));
    }
}
