//! Reading a **labelled** contract build — the catalogue's source of truth.
//!
//! # The oracle
//!
//! Deployed Soroban contracts are name-stripped: of 43 mainnet modules
//! sampled, exactly one carried a `name` section. So the shipped decompiler
//! can never read symbol names, and nothing in this module runs on a real
//! contract.
//!
//! It runs at *development* time instead, on a rebuild of a contract whose
//! source we hold:
//!
//! ```text
//! cargo build --release --target wasm32v1-none \
//!   --config 'profile.release.strip=false' --config 'profile.release.debug=1'
//! ```
//!
//! That rebuild's code section is **byte-identical** to the stripped
//! artefact — verified on `token-v23`: 46 bodies, same SHA-256 over the
//! concatenated bodies — while additionally carrying a `name` section. The
//! same bytes, with the answers attached. That is what makes a catalogue
//! possible: fingerprint the bodies here, where their identity is known,
//! and look them up later where it is not.
//!
//! # The invariant this module must never break
//!
//! Names read here may travel into a **catalogue**, never into a decompile.
//! `samples/contracts/token-v23-stripped` exists to catch a violation: it
//! has no custom sections at all, so any output that depends on a name will
//! visibly differ from its labelled twin.

use std::collections::BTreeMap;

use wasmparser::{KnownCustom, Name, Parser, Payload, TypeRef};

use crate::{
    SigError,
    catalogue::CrateOrigin,
    fingerprint::{Fingerprint, HostImports, fingerprint},
};

/// One function from a labelled build, with its identity resolved.
#[derive(Debug, Clone)]
pub struct LabelledFunction {
    /// WASM function index, counting imports first.
    pub index: u32,
    /// The mangled symbol from the `name` section.
    pub symbol: String,
    /// Which library it belongs to, or `None` for the contract's own code.
    pub origin: Option<CrateOrigin>,
    /// Its fingerprint, or `None` if the body is below the size gate.
    pub fingerprint: Option<Fingerprint>,
    /// Instruction count, for catalogue weighting and diagnostics.
    pub insns: u16,
}

/// Everything the generator needs from one labelled module.
#[derive(Debug, Clone, Default)]
pub struct LabelledModule {
    /// Locally defined functions, in declaration order.
    pub functions: Vec<LabelledFunction>,
}

impl LabelledModule {
    /// Functions attributable to a known library.
    pub fn library_functions(&self) -> impl Iterator<Item = &LabelledFunction> {
        self.functions.iter().filter(|f| f.origin.is_some())
    }
}

/// Strip a Rust symbol's trailing generic-instantiation hash.
///
/// `..._$GT$8into_val17hb1f2...E` becomes `..._$GT$8into_val`. The hash
/// distinguishes monomorphisations *within* one crate graph and is
/// different in every build, so leaving it on would make every entry
/// build-specific and every lookup miss.
///
/// Note this deliberately merges instantiations under one path: a generic
/// compiled for two types is genuinely two bodies and will produce two
/// fingerprints, both legitimately naming the same source function.
#[must_use]
pub fn strip_instantiation_hash(symbol: &str) -> &str {
    // Legacy rustc mangling ends `17h<16 hex digits>E`.
    let Some(head) = symbol.strip_suffix('E') else {
        return symbol;
    };
    let Some(cut) = head.len().checked_sub(19) else {
        return symbol;
    };
    let tail = &head[cut..];
    if tail.starts_with("17h") && tail[3..].bytes().all(|b| b.is_ascii_hexdigit()) {
        &head[..cut]
    } else {
        symbol
    }
}

/// Parse a labelled build.
///
/// # Errors
///
/// [`SigError::Decode`] if the module is malformed, or
/// [`SigError::NoNameSection`] if it carries no function names — which
/// means it was not built with `strip=false` and cannot serve as an oracle.
pub fn read_labelled(wasm: &[u8]) -> Result<LabelledModule, SigError> {
    let mut host_names = Vec::<String>::new();
    let mut bodies = Vec::<(usize, usize)>::new();
    let mut names = BTreeMap::<u32, String>::new();

    for payload in Parser::new(0).parse_all(wasm) {
        match payload? {
            Payload::ImportSection(reader) => {
                for import in reader {
                    let import = import?;
                    // Only function imports occupy the function index space
                    // that a `call` immediate indexes into.
                    if matches!(import.ty, TypeRef::Func(_)) {
                        host_names.push(format!("{}.{}", import.module, import.name));
                    }
                }
            }
            Payload::CodeSectionEntry(body) => {
                let range = body.range();
                bodies.push((range.start, range.end));
            }
            Payload::CustomSection(section) => {
                if let KnownCustom::Name(reader) = section.as_known() {
                    for subsection in reader {
                        if let Name::Function(map) = subsection? {
                            for naming in map {
                                let naming = naming?;
                                names.insert(naming.index, naming.name.to_owned());
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    if names.is_empty() {
        return Err(SigError::NoNameSection);
    }

    let hosts = HostImports::new(host_names);
    let import_count = hosts.len() as u32;

    let mut functions = Vec::with_capacity(bodies.len());
    for (i, (start, end)) in bodies.into_iter().enumerate() {
        let index = import_count + i as u32;
        let Some(symbol) = names.get(&index) else {
            // A body with no name in an otherwise-named module: nothing to
            // attribute it to, so it cannot enter the catalogue.
            continue;
        };
        let body_bytes = wasm.get(start..end).unwrap_or_default();
        let fingerprint = fingerprint(body_bytes, &hosts)?;
        let insns = instruction_count(body_bytes)?;

        functions.push(LabelledFunction {
            index,
            symbol: strip_instantiation_hash(symbol).to_owned(),
            origin: CrateOrigin::classify(symbol),
            fingerprint,
            insns,
        });
    }

    Ok(LabelledModule { functions })
}

/// Instruction count of a body, saturating at `u16::MAX`.
fn instruction_count(body_bytes: &[u8]) -> Result<u16, SigError> {
    let body = wasmparser::FunctionBody::new(wasmparser::BinaryReader::new(body_bytes, 0));
    let mut n: u16 = 0;
    for op in body.get_operators_reader()? {
        op?;
        n = n.saturating_add(1);
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instantiation_hash_is_stripped() {
        assert_eq!(
            strip_instantiation_hash("_ZN60_$LT$U$GT$8into_val17hb1f2c3d4e5f60718E"),
            "_ZN60_$LT$U$GT$8into_val"
        );
    }

    #[test]
    fn a_symbol_without_a_hash_is_untouched() {
        assert_eq!(
            strip_instantiation_hash("_ZN11soroban_sdk7storage3get"),
            "_ZN11soroban_sdk7storage3get"
        );
        // Ends in `E` but the tail is not a hash.
        assert_eq!(strip_instantiation_hash("some_nameE"), "some_nameE");
    }

    #[test]
    fn short_symbols_do_not_panic() {
        assert_eq!(strip_instantiation_hash(""), "");
        assert_eq!(strip_instantiation_hash("E"), "E");
        assert_eq!(strip_instantiation_hash("17hE"), "17hE");
    }

    #[test]
    fn a_stripped_module_is_rejected_as_an_oracle() {
        // Minimal valid module: magic + version, no name section.
        let wasm = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        assert!(matches!(
            read_labelled(&wasm),
            Err(SigError::NoNameSection)
        ));
    }
}
