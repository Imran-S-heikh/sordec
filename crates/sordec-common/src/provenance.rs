//! Audit trail for refinements applied to the IR.
//!
//! Every IR binding carries a `Vec<Provenance>` recording which pass set
//! or refined it, what kind of evidence it used, and a free-form note for
//! human readers. This is the *only* mechanism by which we explain "why
//! did the decompiler emit this?" — see `docs/architecture.md` §4.
//!
//! ## Why a vector, not a single value
//!
//! Refinement is monotonic — passes either replace `Unknown` with
//! `Inferred`/`Known`, or refine `Inferred` with stronger evidence. Each
//! refinement appends a new entry rather than overwriting the previous
//! one. Reading the chain answers "how did we get from the raw lift to
//! this conclusion?"
//!
//! Memory cost is bounded: typical bindings accumulate one to three
//! entries over the entire pipeline.
//!
//! ## Why categorical sources, not numeric scores
//!
//! Production decompilers (Ghidra, Hex-Rays, Binary Ninja) all reject
//! numeric confidence in favour of categorical provenance. "Came from
//! `contractspecv0`" is actionable; "0.73 confidence" is not. See
//! `docs/architecture.md` §11 for the rejected alternatives.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

// NOTE on `serde`: `Provenance` is intentionally `Serialize`-only.
// The `pass` field is `&'static str` (the compile-time pass name);
// deserialising it would require `'de: 'static`, which is almost never
// satisfiable. We do not have a use case for deserialising provenance
// — it is an output for inspection — so we keep the precise type and
// skip the round-trip.

/// Single record describing how one piece of IR information was derived.
///
/// Construct with [`Provenance::new`]. Append (never overwrite) onto the
/// `Vec<Provenance>` carried by each IR binding.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct Provenance {
    /// Name of the pass that produced this entry. Conventionally the same
    /// `&'static str` returned from the pass's `Pass::name()` method.
    pub pass: &'static str,

    /// Categorical bucket describing the *kind* of evidence used.
    pub source: ProvenanceSource,

    /// Optional human-readable context. We use `String` rather than
    /// `Cow<'static, str>` here despite most call sites supplying static
    /// literals: the saved allocation is trivial, and `Cow` interacts
    /// awkwardly with `Deserialize<'de>` lifetime inference.
    // JUSTIFY: Free-form diagnostic text. No structured form would
    // capture pass-author intent better than a string.
    pub note: String,
}

impl Provenance {
    /// Build a new provenance entry. Helper that takes any string-like
    /// argument so call sites remain terse.
    #[inline]
    #[must_use]
    pub fn new(
        pass: &'static str,
        source: ProvenanceSource,
        note: impl Into<String>,
    ) -> Self {
        Self {
            pass,
            source,
            note: note.into(),
        }
    }
}

/// Categorical classification of where a provenance entry's evidence came from.
///
/// Each variant corresponds to a *kind* of analysis or input, not a
/// specific instance. The matching `note` field on [`Provenance`] carries
/// the specifics (which host function, which pattern name, etc).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ProvenanceSource {
    /// Decoded from a Soroban custom section
    /// (`contractspecv0`, `contractmetav0`, or `contractenvmetav0`).
    Metadata,

    /// Determined from a known Soroban host-function ABI table — e.g.,
    /// `ledger.put_contract_data` is a storage write.
    HostFunctionAbi,

    /// Recognised by an SDK-aware multi-instruction pattern matcher
    /// (e.g. `"val-encode-u64"`, `"storage-set-persistent"`).
    SdkPattern,

    /// Derived from SSA value tracing or use-def analysis.
    DataFlow,

    /// Type unification across multiple uses agreed on a result.
    TypePropagation,

    /// Last-resort default. Should be rare; prefer leaving the value
    /// `Unknown` over emitting a `Default` provenance.
    Default,

    /// Marker indicating this entry refines an earlier provenance. Used
    /// when a later pass strengthens an `Inferred` to `Known` based on
    /// prior `Inferred` evidence.
    UpstreamRefinement,
}

impl ProvenanceSource {
    /// Stable, human-readable tag for this evidence bucket.
    ///
    /// Used verbatim by every renderer that surfaces provenance (the
    /// `dump-hir` view and the annotated-WAT emitter), so the recognition
    /// vocabulary reads identically across outputs. The strings are part
    /// of the tool's contract — changing one changes annotated output.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            ProvenanceSource::Metadata => "Metadata",
            ProvenanceSource::HostFunctionAbi => "HostFunctionAbi",
            ProvenanceSource::SdkPattern => "SdkPattern",
            ProvenanceSource::DataFlow => "DataFlow",
            ProvenanceSource::TypePropagation => "TypePropagation",
            ProvenanceSource::Default => "Default",
            ProvenanceSource::UpstreamRefinement => "UpstreamRefinement",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provenance_constructor_accepts_str_or_string() {
        let from_str = Provenance::new("test_pass", ProvenanceSource::Metadata, "from spec");
        assert_eq!(from_str.note, "from spec");

        let from_string = Provenance::new(
            "test_pass",
            ProvenanceSource::SdkPattern,
            String::from("matched val-encode-u64"),
        );
        assert_eq!(from_string.note, "matched val-encode-u64");
    }
}
