//! The masked structural fingerprint of a WASM function body.
//!
//! # What this is for
//!
//! rustc inlines the Soroban SDK into every contract it compiles. The
//! decompiler's largest remaining problem is telling that SDK code apart
//! from the code the contract's author actually wrote, so the former can be
//! deleted and re-spelled as a library call. A fingerprint that survives
//! re-linking is how a body gets *identified* rather than guessed at from
//! its shape.
//!
//! # Why masking, and what the alternative measured
//!
//! Hashing a function body verbatim does not work, and the reason is
//! specific rather than general. Measured over two contracts built against
//! the same SDK, of the ten library functions present in both:
//!
//! - **raw byte hash: 1 / 10 matched**
//! - **masked fingerprint: 8 / 10 matched**
//!
//! Eight of the nine mismatched pairs were **the same length**, and every
//! differing byte sat immediately after a `call` opcode. `Symbol as
//! TryFromVal` is 262 bytes and differed in *one*. Those bytes are
//! module-local function indices: each module numbers its own functions, so
//! the same SDK code points at a different index in every binary it is
//! linked into. Nothing about the code changed.
//!
//! The two that legitimately failed to match are worth naming, because they
//! bound what this can ever do: `Storage::has_internal` differed in a real
//! constant (a durability argument), and `IntoVal` was one generic
//! instantiated at two different types — 146 bytes against 298. Neither is
//! a masking failure; they are genuinely different code.
//!
//! # The normalisation rules
//!
//! Everything is hashed **verbatim** except four operators whose immediates
//! are module-local rather than structural:
//!
//! | operator | treatment | why |
//! |---|---|---|
//! | `call` to an import | the import's `module.name` | host-import names are stable across modules *and* SDK versions |
//! | `call` to a local | a constant tag | the callee index is assigned per module |
//! | `call_indirect` | a constant tag | type and table indices are per module |
//! | `global.get` / `global.set` | a constant tag | global indices are per module |
//!
//! Kept deliberately: memory offsets (a struct field offset is structural),
//! `i32`/`i64` constants (tag values and widths are structural), block
//! signatures, and `br_table` target lists. Masking those was not necessary
//! to reach 8/10 and each one carries real identity.
//!
//! Resolving host calls to their import *name* rather than masking them is
//! what lets a catalogue built against one SDK version match a contract
//! built against another: a catalogue generated on SDK 20.5.0 scored 47.6%
//! against an SDK 23.0.1 contract.
//!
//! # Stability
//!
//! The hash is an explicit FNV-1a-128 over the normalised stream. It is
//! **not** `std::collections::hash_map::DefaultHasher`, whose output is
//! documented as unstable across Rust releases — a catalogue keyed on an
//! unstable hash would go silently wrong on a toolchain bump rather than
//! loudly wrong.
//!
//! For the same reason the verbatim arm hashes the instruction's **raw
//! bytes** rather than any `wasmparser` type: `wasmparser` gives us correct
//! instruction boundaries, which is the hard part, but its enum layout is
//! its own business and must not leak into a persisted key.

use wasmparser::{BinaryReader, FunctionBody, Operator};

use crate::SigError;

/// FNV-1a 128-bit offset basis, from the FNV reference parameters.
const FNV_OFFSET_BASIS: u128 = 0x6c62_272e_07bb_0142_62b8_2175_6295_c58d;

/// FNV-1a 128-bit prime, from the FNV reference parameters.
const FNV_PRIME: u128 = 0x0000_0000_0100_0000_0000_0000_0000_013b;

/// Fewest instructions a body may have and still be fingerprinted.
///
/// Short bodies carry too little structure to identify: measured across two
/// contracts, fingerprints drawn from spans under ten bytes were unique
/// only 80–83% of the time, while everything at ten bytes or more was
/// **100%** unique. Four instructions is the conservative reading of that
/// boundary.
pub const MIN_INSTRUCTIONS: usize = 4;

/// Fewest instructions a body must have that are **not** masked.
///
/// Raw length is the wrong gate, and a measured false positive is what
/// showed it. These three bodies are byte-distinct, semantically unrelated,
/// and fingerprint identically:
///
/// ```text
/// 00 2000 109c80808000 10a280808000 0b   dex::get_balance_a
/// 00 2000 109e80808000 10a280808000 0b   dex::get_balance_b
/// 00 2000 108782808000 10a182808000 0b   soroban_sdk::ledger::Ledger::sequence
/// ```
///
/// Each is `local.get 0; call <local>; call <local>; end` — four
/// instructions, clearing [`MIN_INSTRUCTIONS`], of which **two are calls
/// whose target is deliberately masked**. The callee is the only thing
/// telling them apart, and erasing it is the entire point of the design.
/// What is left carries no identity, so the catalogue matched a liquidity
/// pool's balance getter to a ledger-sequence accessor.
///
/// So the real question is not "how long is this body" but "how much of it
/// still says something after normalisation". A body must clear both gates.
///
/// Note this cannot be fixed by resolving local callees instead: their
/// indices are precisely what varies between modules. It could be fixed by
/// fingerprinting callees recursively, which is a much larger design and
/// buys little — bodies this trivial are not worth identifying.
pub const MIN_UNMASKED_INSTRUCTIONS: usize = 4;

/// A masked structural fingerprint of one function body.
///
/// Equality is the whole interface: two bodies with the same fingerprint
/// are the same code up to module-local indices. The inner value is
/// exposed so generated catalogues can be written as literals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fingerprint(pub u128);

impl Fingerprint {
    /// The raw 128-bit value, for serialising into a generated catalogue.
    #[must_use]
    pub const fn to_u128(self) -> u128 {
        self.0
    }
}

impl core::fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:032x}", self.0)
    }
}

/// The host functions a module imports, in import order.
///
/// A WASM function index below `len()` refers to an import; at or above it,
/// to a locally defined function. That boundary is what lets [`fingerprint`]
/// tell a stable host call from a module-local one.
#[derive(Debug, Clone, Default)]
pub struct HostImports {
    /// `module.name` per imported *function*, in import order.
    names: Vec<String>,
}

impl HostImports {
    /// Build from `module.name` pairs, in the order the WASM import section
    /// declares them. Only function imports may be included: memories,
    /// tables and globals do not occupy the function index space.
    #[must_use]
    pub fn new(names: Vec<String>) -> Self {
        Self { names }
    }

    /// The stable name of an imported function, or `None` if `index` refers
    /// to a locally defined one.
    #[must_use]
    pub fn resolve(&self, index: u32) -> Option<&str> {
        self.names.get(index as usize).map(String::as_str)
    }

    /// How many function imports the module has.
    #[must_use]
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// Whether the module imports no functions at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

/// Incremental FNV-1a-128.
struct Fnv1a(u128);

impl Fnv1a {
    const fn new() -> Self {
        Self(FNV_OFFSET_BASIS)
    }

    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 ^= b as u128;
            self.0 = self.0.wrapping_mul(FNV_PRIME);
        }
    }

    const fn finish(self) -> Fingerprint {
        Fingerprint(self.0)
    }
}

/// Synthetic tags for the masked operators.
///
/// These are our own byte strings rather than `wasmparser` names so that a
/// dependency bump cannot silently repartition a persisted keyspace. The
/// leading `\x00` cannot begin a real instruction encoding, so a tag can
/// never collide with a verbatim-hashed span.
mod tag {
    /// A call whose target is defined in this module.
    pub const CALL_LOCAL: &[u8] = b"\x00call.local";
    /// A call through the function table.
    pub const CALL_INDIRECT: &[u8] = b"\x00call.indirect";
    /// A read or write of a module global.
    pub const GLOBAL: &[u8] = b"\x00global";
    /// Precedes the resolved name of an imported host function.
    pub const CALL_HOST: &[u8] = b"\x00call.host:";
}

/// Fingerprint one function body.
///
/// `body_bytes` is the body exactly as it appears in the code section —
/// local declarations followed by the instruction stream — which is what
/// `wasmparser` hands back for a `CodeSectionEntry`. `hosts` supplies the
/// import boundary so host calls can be resolved to stable names.
///
/// Returns `Ok(None)` when the body is shorter than [`MIN_INSTRUCTIONS`],
/// which is a decision not to identify it rather than a failure.
///
/// # Errors
///
/// [`SigError::Decode`] if `wasmparser` cannot read the instruction stream,
/// which means the bytes are not a well-formed function body.
pub fn fingerprint(
    body_bytes: &[u8],
    hosts: &HostImports,
) -> Result<Option<Fingerprint>, SigError> {
    let body = FunctionBody::new(BinaryReader::new(body_bytes, 0));

    // Collect operators with their offsets first: an instruction's verbatim
    // span runs from its own offset to the next one, so the stream has to be
    // windowed rather than folded. Bodies are at most a few kilobytes.
    let mut ops: Vec<(Operator<'_>, usize)> = Vec::new();
    for item in body.get_operators_reader()?.into_iter_with_offsets() {
        ops.push(item?);
    }

    if ops.len() < MIN_INSTRUCTIONS {
        return Ok(None);
    }

    let mut hasher = Fnv1a::new();
    // How many instructions survive normalisation with their identity
    // intact. A stream that is mostly masked tags hashes the same as any
    // other stream of the same shape — see [`MIN_UNMASKED_INSTRUCTIONS`].
    let mut unmasked = 0_usize;
    for (i, (op, start)) in ops.iter().enumerate() {
        // The last instruction runs to the end of the body; every other one
        // stops where its successor begins.
        let end = ops.get(i + 1).map_or(body_bytes.len(), |(_, next)| *next);
        let span = body_bytes.get(*start..end).unwrap_or_default();

        match op {
            Operator::Call { function_index } => match hosts.resolve(*function_index) {
                // A host import: its name is stable across modules and SDK
                // versions, and is the only thing distinguishing one host
                // call from another once the index is gone.
                // A host import names a specific operation, so it survives
                // normalisation and counts toward the body's identity.
                Some(name) => {
                    hasher.write(tag::CALL_HOST);
                    hasher.write(name.as_bytes());
                    unmasked += 1;
                }
                // A module-local callee: the index is an artefact of this
                // module's layout and carries no identity.
                None => hasher.write(tag::CALL_LOCAL),
            },
            Operator::CallIndirect { .. } => hasher.write(tag::CALL_INDIRECT),
            Operator::GlobalGet { .. } | Operator::GlobalSet { .. } => hasher.write(tag::GLOBAL),
            // Everything else is structural and hashed exactly as encoded.
            _ => {
                hasher.write(span);
                unmasked += 1;
            }
        }
    }

    if unmasked < MIN_UNMASKED_INSTRUCTIONS {
        return Ok(None);
    }

    Ok(Some(hasher.finish()))
}

/// Fingerprint every local function body in a module, in declaration order.
///
/// Works on a **stripped** module: it reads only the import and code
/// sections, never names. `None` marks a body that declined the size gates.
///
/// This is the shared implementation. The frontend calls it so a decompile
/// and the `siggen` tooling cannot drift apart — two copies of the
/// normalisation rules would be two keyspaces, and the divergence would
/// show up as a catalogue that silently stops matching.
///
/// # Errors
///
/// [`SigError::Decode`] if `wasmparser` rejects the module.
pub fn fingerprint_module(wasm: &[u8]) -> Result<Vec<Option<Fingerprint>>, SigError> {
    use wasmparser::{Parser, Payload, TypeRef};

    let mut host_names = Vec::<String>::new();
    let mut bodies = Vec::<(usize, usize)>::new();

    for payload in Parser::new(0).parse_all(wasm) {
        match payload? {
            Payload::ImportSection(reader) => {
                for import in reader {
                    let import = import?;
                    // Only function imports occupy the index space a `call`
                    // immediate indexes into.
                    if matches!(import.ty, TypeRef::Func(_)) {
                        host_names.push(format!("{}.{}", import.module, import.name));
                    }
                }
            }
            Payload::CodeSectionEntry(body) => {
                let r = body.range();
                bodies.push((r.start, r.end));
            }
            _ => {}
        }
    }

    let hosts = HostImports::new(host_names);
    bodies
        .into_iter()
        .map(|(start, end)| fingerprint(wasm.get(start..end).unwrap_or_default(), &hosts))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `(module (func ...))` compiled to a bare body: locals count, then
    /// instructions, then `end`. Built by hand so the tests do not depend
    /// on a WAT assembler.
    fn body(instructions: &[u8]) -> Vec<u8> {
        let mut v = vec![0x00]; // zero local declarations
        v.extend_from_slice(instructions);
        v.push(0x0b); // end
        v
    }

    /// `local.get 0; local.get 1; i64.add; drop` — four instructions plus
    /// `end`, comfortably over the size gate.
    fn arithmetic() -> Vec<u8> {
        body(&[0x20, 0x00, 0x20, 0x01, 0x7c, 0x1a])
    }

    #[test]
    fn identical_bodies_agree() {
        let hosts = HostImports::default();
        let a = fingerprint(&arithmetic(), &hosts).unwrap();
        let b = fingerprint(&arithmetic(), &hosts).unwrap();
        assert_eq!(a, b);
        assert!(a.is_some());
    }

    #[test]
    fn different_bodies_differ() {
        let hosts = HostImports::default();
        // i64.sub (0x7d) where the other has i64.add (0x7c).
        let other = body(&[0x20, 0x00, 0x20, 0x01, 0x7d, 0x1a]);
        assert_ne!(
            fingerprint(&arithmetic(), &hosts).unwrap(),
            fingerprint(&other, &hosts).unwrap()
        );
    }

    /// The headline property: the same code linked into two modules that
    /// number their functions differently must fingerprint alike.
    #[test]
    fn local_call_index_is_masked() {
        let hosts = HostImports::default();
        let call_7 = body(&[0x20, 0x00, 0x20, 0x01, 0x10, 0x07, 0x1a]);
        let call_92 = body(&[0x20, 0x00, 0x20, 0x01, 0x10, 0xdc, 0x00, 0x1a]);
        assert_eq!(
            fingerprint(&call_7, &hosts).unwrap(),
            fingerprint(&call_92, &hosts).unwrap(),
            "a module-local callee index must not reach the fingerprint"
        );
    }

    /// Host calls are the opposite case: two different host functions are
    /// two different behaviours and must not collapse together.
    #[test]
    fn host_calls_are_distinguished_by_name() {
        let hosts = HostImports::new(vec!["l.7".into(), "m.9".into()]);
        let call_l7 = body(&[0x20, 0x00, 0x20, 0x01, 0x10, 0x00, 0x1a]);
        let call_m9 = body(&[0x20, 0x00, 0x20, 0x01, 0x10, 0x01, 0x1a]);
        assert_ne!(
            fingerprint(&call_l7, &hosts).unwrap(),
            fingerprint(&call_m9, &hosts).unwrap(),
            "distinct host imports must not share a fingerprint"
        );
    }

    /// The same host function reached through different import indices —
    /// which is what happens when two modules import in a different order —
    /// must still agree.
    #[test]
    fn host_call_survives_reordered_imports() {
        let first = HostImports::new(vec!["l.7".into(), "m.9".into()]);
        let second = HostImports::new(vec!["m.9".into(), "l.7".into()]);
        let call_idx0 = body(&[0x20, 0x00, 0x20, 0x01, 0x10, 0x00, 0x1a]);
        let call_idx1 = body(&[0x20, 0x00, 0x20, 0x01, 0x10, 0x01, 0x1a]);
        assert_eq!(
            fingerprint(&call_idx0, &first).unwrap(),
            fingerprint(&call_idx1, &second).unwrap(),
            "the same host import must agree regardless of its index"
        );
    }

    #[test]
    fn global_index_is_masked() {
        let hosts = HostImports::default();
        let g0 = body(&[0x20, 0x00, 0x20, 0x01, 0x23, 0x00, 0x1a]);
        let g5 = body(&[0x20, 0x00, 0x20, 0x01, 0x23, 0x05, 0x1a]);
        assert_eq!(
            fingerprint(&g0, &hosts).unwrap(),
            fingerprint(&g5, &hosts).unwrap()
        );
    }

    /// Constants are kept: a tag value is identity, not noise.
    #[test]
    fn constants_are_structural() {
        let hosts = HostImports::default();
        let tag_14 = body(&[0x20, 0x00, 0x42, 0x0e, 0x84, 0x1a]);
        let tag_11 = body(&[0x20, 0x00, 0x42, 0x0b, 0x84, 0x1a]);
        assert_ne!(
            fingerprint(&tag_14, &hosts).unwrap(),
            fingerprint(&tag_11, &hosts).unwrap(),
            "a differing constant is a differing function"
        );
    }

    #[test]
    fn short_bodies_are_declined() {
        let hosts = HostImports::default();
        // `local.get 0; end` — two instructions, under the gate.
        assert_eq!(fingerprint(&body(&[0x20, 0x00]), &hosts).unwrap(), None);
    }

    /// Regression for a **measured false positive**: a catalogue built from
    /// third-party contracts matched `dex::get_balance_a` and
    /// `get_balance_b` to `soroban_sdk::ledger::Ledger::sequence`.
    ///
    /// All three are `local.get 0; call <local>; call <local>; end`. That
    /// clears the raw-length gate, but two of the four instructions are
    /// calls whose target is masked, so nothing discriminating is left.
    /// These are the real bodies, byte for byte.
    #[test]
    fn a_body_that_is_mostly_masked_calls_is_declined() {
        let hosts = HostImports::default();
        let get_balance_a = hex(b"002000109c8080800010a2808080000b");
        let get_balance_b = hex(b"002000109e8080800010a2808080000b");
        let ledger_sequence = hex(b"00200010878280800010a1828080000b");

        for (label, bytes) in [
            ("dex::get_balance_a", &get_balance_a),
            ("dex::get_balance_b", &get_balance_b),
            ("Ledger::sequence", &ledger_sequence),
        ] {
            assert_eq!(
                fingerprint(bytes, &hosts).unwrap(),
                None,
                "{label} carries no identity once its callees are masked and must be declined"
            );
        }
    }

    /// The same shape becomes identifiable once the calls are to *host*
    /// imports, which are named rather than masked — confirming the gate
    /// counts discriminating content and not merely instructions.
    #[test]
    fn the_same_shape_survives_when_the_calls_are_host_imports() {
        let hosts = HostImports::new(vec!["l.7".into(), "m.9".into()]);
        // local.get 0; call 0; call 1; end
        let with_host_calls = body(&[0x20, 0x00, 0x10, 0x00, 0x10, 0x01]);
        assert!(fingerprint(&with_host_calls, &hosts).unwrap().is_some());
    }

    fn hex(s: &[u8]) -> Vec<u8> {
        s.chunks(2)
            .map(|p| {
                u8::from_str_radix(std::str::from_utf8(p).expect("ascii"), 16).expect("hex digits")
            })
            .collect()
    }

    #[test]
    fn malformed_body_is_an_error() {
        let hosts = HostImports::default();
        // 0xff is not a valid opcode.
        assert!(fingerprint(&body(&[0xff, 0xff, 0xff, 0xff]), &hosts).is_err());
    }

    /// Pins the hash construction itself. If this changes, every generated
    /// catalogue is invalidated and must be regenerated — which is exactly
    /// the event this test exists to make loud.
    ///
    /// The expected value is **not** this implementation's output copied
    /// back in; it was computed independently from the published FNV-1a-128
    /// parameters:
    ///
    /// ```text
    /// h = 0x6c62272e07bb014262b821756295c58d
    /// for b in b"sordec": h = ((h ^ b) * 0x1000000000000000000013B) mod 2**128
    /// ```
    ///
    /// A test that pins whatever the code happens to produce would pass
    /// against a wrong implementation.
    #[test]
    fn hash_matches_the_fnv_specification() {
        let mut h = Fnv1a::new();
        h.write(b"sordec");
        assert_eq!(
            h.finish().to_string(),
            "87a8109db03c64bf6f4fd5a9f7f0af35",
            "FNV-1a-128 output changed; regenerate all catalogues"
        );
    }
}
