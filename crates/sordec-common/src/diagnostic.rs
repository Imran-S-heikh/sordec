//! Non-fatal warnings and information collected during pipeline operations.
//!
//! Every layer of the sordec pipeline (parser, metadata decoder, lifter,
//! pattern recovery passes, lowering, emit) can encounter situations that
//! are *not* fatal — recovered with a degraded result, or simply worth
//! noting — but that the caller should know about. Those are
//! [`Diagnostic`]s.
//!
//! ## Migration principle (when does an `Err` become a [`Diagnostic`]?)
//!
//! > A failure becomes a [`Severity::Warning`] [`Diagnostic`] iff the
//! > frontend (or any layer) can produce a well-formed (if reduced) IR
//! > that downstream passes can consume *without further special-casing*.
//! > Otherwise it stays a fatal `Err`.
//!
//! Recovered-with-placeholder is a Warning. Corrupt-input-cannot-proceed
//! is an `Err`. Future contributors should classify new variants by this
//! rule, not by ad-hoc mimicry of existing variants.
//!
//! ## Diagnostics ≠ Provenance
//!
//! sordec already has [`crate::Provenance`] for tracking refinements
//! per-binding. Diagnostics and Provenance look superficially similar
//! (both carry "what happened during a pass" information) but their
//! domains are distinct:
//!
//! - **Provenance** is the audit trail consumed by passes — structured
//!   per-binding, machine-readable, lives *inside* IR data.
//! - **Diagnostics** are the side channel surfaced to humans —
//!   structured per-event, printable, lives *alongside* IR data.
//!
//! In v0 they coexist without cross-reference. Don't merge them.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::ids::{BlockId, FuncId};

// ---------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------

/// How seriously to treat a [`Diagnostic`].
///
/// `Error` is reserved for the rare case where a fatal error wants to
/// also surface a structured diagnostic record (today: never used; kept
/// for symmetry and future use). `Warning` indicates we recovered with a
/// degraded result. `Info` indicates we noticed something worth knowing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Severity {
    /// Fatal-level diagnostic accompanying an `Err` return. Reserved;
    /// not emitted in v0.
    Error,
    /// Recovered with a degraded result. The output is still usable but
    /// loses some fidelity (e.g. an unresolved type fell back to a
    /// placeholder).
    Warning,
    /// Noticed something worth knowing. The output is unaffected.
    Info,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Error => f.write_str("error"),
            Self::Warning => f.write_str("warning"),
            Self::Info => f.write_str("info"),
        }
    }
}

// ---------------------------------------------------------------------
// Location
// ---------------------------------------------------------------------

/// Where in the input a diagnostic applies, at the pragmatic granularity
/// the relevant pipeline layer can offer.
///
/// **Layer constraint** (not enforced by the type system): metadata-layer
/// diagnostics only ever use [`Location::CustomSection`]. Lift-layer
/// diagnostics use [`Location::Function`], [`Location::Block`], or
/// [`Location::Value`]. Don't mix.
///
/// Byte-level spans are intentionally absent in v0; `CustomSection` and
/// `Function`-id-level granularity is enough for the diagnostics we
/// currently emit. If span-level highlighting becomes necessary, the
/// enum is `#[non_exhaustive]` and can grow.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Location {
    /// A WASM custom section identified by name (e.g. `contractspecv0`).
    /// Used by metadata-layer diagnostics.
    CustomSection {
        /// Section name as it appears in the WASM custom section header.
        name: String,
    },
    /// A specific function in the lifted IR.
    Function(FuncId),
    /// A specific basic block within a function.
    Block {
        /// Function the block belongs to.
        func: FuncId,
        /// Block within that function.
        block: BlockId,
    },
    /// A specific SSA value within a function.
    Value {
        /// Function the value belongs to.
        func: FuncId,
        /// Raw value index (`waffle::Value::index()`-equivalent — we use
        /// the raw `u32` because lift diagnostics may fire before our
        /// typed `ValueId` mapping is established).
        value: u32,
    },
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CustomSection { name } => write!(f, "in custom section {name:?}"),
            Self::Function(func) => write!(f, "in {func}"),
            Self::Block { func, block } => write!(f, "in {func} {block}"),
            Self::Value { func, value } => write!(f, "in {func} v{value}"),
        }
    }
}

// ---------------------------------------------------------------------
// Per-layer code enums
// ---------------------------------------------------------------------

/// Codes for diagnostics emitted while decoding Soroban metadata custom
/// sections (`contractspecv0`, `contractmetav0`, `contractenvmetav0`).
///
/// Variants here correspond to recoverable conditions during metadata
/// decoding. Truly fatal conditions (malformed `contractspecv0`,
/// invalid UTF-8 in identifiers) remain in [`crate`]'s consumers'
/// `FrontendError` enum — see the migration principle in the module
/// documentation.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum MetadataDiagnosticCode {
    /// `contractspecv0` referenced a user-defined type by name, but no
    /// declaration was found. Recovery: the reference falls back to a
    /// placeholder type with [`crate::UnknownReason::NoMetadata`].
    UnresolvedTypeReference {
        /// Name of the missing type as it appeared in the spec.
        name: String,
    },
    /// `contractspecv0` declared the same user-defined type more than
    /// once. Recovery: the first declaration is kept; later ones are
    /// dropped.
    DuplicateTypeName {
        /// The duplicated type name.
        name: String,
    },
    /// `contractspecv0` declared the same function name more than once.
    /// Recovery: the first declaration is kept; later ones are dropped.
    DuplicateFunctionName {
        /// The duplicated function name.
        name: String,
    },
    /// `contractmetav0` payload could not be decoded as a sequence of
    /// `ScMetaEntry` values. Recovery: the contract metadata key/value
    /// map falls back to empty. The protocol-version compatibility data
    /// from `contractenvmetav0` is unaffected by this diagnostic.
    MalformedContractMeta {
        /// Reason the payload could not be decoded (XDR or framing
        /// error from the underlying decoder).
        reason: String,
    },
}

impl fmt::Display for MetadataDiagnosticCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnresolvedTypeReference { name } => {
                write!(f, "metadata::unresolved_type_reference: type {name:?} referenced but not declared")
            }
            Self::DuplicateTypeName { name } => {
                write!(f, "metadata::duplicate_type_name: type {name:?} declared more than once; first declaration kept")
            }
            Self::DuplicateFunctionName { name } => {
                write!(f, "metadata::duplicate_function_name: function {name:?} declared more than once; first declaration kept")
            }
            Self::MalformedContractMeta { reason } => {
                write!(f, "metadata::malformed_contract_meta: {reason}; contract_meta map left empty")
            }
        }
    }
}

/// Codes for diagnostics emitted during the WASM → SSA + CFG lift.
///
/// No variants are defined yet — the lifter currently surfaces every
/// recoverable situation through the existing `LiftedTerminator::Unreachable`
/// fallback (for `waffle::Terminator::None`) or through hard `LiftError`
/// variants for true SSA-invariant violations. Phase 2's pattern recovery
/// work will be the first to add variants here.
///
/// The empty enum is intentional: it pre-establishes the structural slot
/// in [`DiagnosticCode`] so callers don't have to plumb a new outer
/// variant when the first lift diagnostic lands.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum LiftDiagnosticCode {}

impl fmt::Display for LiftDiagnosticCode {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Uninhabited — match against `&self` is exhaustive with no arms.
        match *self {}
    }
}

// ---------------------------------------------------------------------
// DiagnosticCode (the outer enum)
// ---------------------------------------------------------------------

/// All diagnostic codes the pipeline can emit, namespaced by layer.
///
/// `Parse(...)` is intentionally absent today — the WASM-section parser
/// has no migrated diagnostics yet. The enum is `#[non_exhaustive]`, so
/// adding a `Parse(ParseDiagnosticCode)` variant later is API-additive.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum DiagnosticCode {
    /// A diagnostic emitted while decoding Soroban metadata custom
    /// sections.
    Metadata(MetadataDiagnosticCode),
    /// A diagnostic emitted during WASM-to-IR lifting. Currently always
    /// uninhabited; reserved for Phase 2 pattern recovery.
    Lift(LiftDiagnosticCode),
}

impl fmt::Display for DiagnosticCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Metadata(c) => c.fmt(f),
            Self::Lift(c) => c.fmt(f),
        }
    }
}

impl From<MetadataDiagnosticCode> for DiagnosticCode {
    fn from(c: MetadataDiagnosticCode) -> Self {
        Self::Metadata(c)
    }
}

impl From<LiftDiagnosticCode> for DiagnosticCode {
    fn from(c: LiftDiagnosticCode) -> Self {
        Self::Lift(c)
    }
}

// ---------------------------------------------------------------------
// Diagnostic
// ---------------------------------------------------------------------

/// One non-fatal note from the pipeline.
///
/// Diagnostics are returned alongside successful pipeline outputs (in
/// `ParseOutput`, `LiftOutput`, etc.). They are NOT used for fatal
/// errors — those still flow through `Result::Err`.
///
/// See the module documentation for the rule that governs when
/// something becomes a [`Diagnostic`] vs a fatal error.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Diagnostic {
    /// How seriously to treat this diagnostic.
    pub severity: Severity,
    /// Typed code identifying which condition was observed.
    pub code: DiagnosticCode,
    /// Human-readable elaboration. The `code` carries the structured
    /// information; `message` is for additional free-form context that
    /// would be awkward to encode as enum fields (file offsets,
    /// truncated payload bytes, etc.).
    pub message: String,
    /// Where in the input this diagnostic applies, if known.
    pub location: Option<Location>,
}

impl Diagnostic {
    /// Build a `Warning` diagnostic with the given code and message.
    ///
    /// The most common construction site; pulled out as a helper so
    /// metadata-decoder call sites stay readable.
    pub fn warning(code: impl Into<DiagnosticCode>, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            code: code.into(),
            message: message.into(),
            location: None,
        }
    }

    /// Build an `Info` diagnostic with the given code and message.
    pub fn info(code: impl Into<DiagnosticCode>, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Info,
            code: code.into(),
            message: message.into(),
            location: None,
        }
    }

    /// Attach a [`Location`] to this diagnostic. Builder-style for
    /// readable construction at the emit site.
    #[must_use]
    pub fn at(mut self, location: Location) -> Self {
        self.location = Some(location);
        self
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.severity, self.code)?;
        if !self.message.is_empty() {
            write!(f, ": {}", self.message)?;
        }
        if let Some(loc) = &self.location {
            write!(f, " ({loc})")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    // `IrId` brings `from_index` into scope for constructing test IDs.
    use crate::ids::IrId;

    #[test]
    fn severity_display_matches_expectations() {
        assert_eq!(Severity::Error.to_string(), "error");
        assert_eq!(Severity::Warning.to_string(), "warning");
        assert_eq!(Severity::Info.to_string(), "info");
    }

    #[test]
    fn location_display_for_each_variant() {
        assert_eq!(
            Location::CustomSection {
                name: "contractspecv0".to_string()
            }
            .to_string(),
            r#"in custom section "contractspecv0""#
        );
        assert_eq!(
            Location::Function(FuncId::from_index(7)).to_string(),
            "in func7"
        );
        assert_eq!(
            Location::Block {
                func: FuncId::from_index(3),
                block: BlockId::from_index(2)
            }
            .to_string(),
            "in func3 bb2"
        );
        assert_eq!(
            Location::Value {
                func: FuncId::from_index(3),
                value: 42
            }
            .to_string(),
            "in func3 v42"
        );
    }

    #[test]
    fn metadata_diagnostic_display_includes_code_and_payload() {
        let d = Diagnostic::warning(
            MetadataDiagnosticCode::UnresolvedTypeReference {
                name: "MyEnum".to_string(),
            },
            "",
        )
        .at(Location::CustomSection {
            name: "contractspecv0".to_string(),
        });

        let s = d.to_string();
        assert!(s.starts_with("[warning]"), "got: {s}");
        assert!(s.contains("metadata::unresolved_type_reference"), "got: {s}");
        assert!(s.contains(r#""MyEnum""#), "got: {s}");
        assert!(s.contains("contractspecv0"), "got: {s}");
    }

    #[test]
    fn diagnostic_warning_helper_sets_severity_correctly() {
        let d = Diagnostic::warning(
            MetadataDiagnosticCode::DuplicateTypeName {
                name: "Foo".to_string(),
            },
            "deduped",
        );
        assert_eq!(d.severity, Severity::Warning);
        assert!(matches!(
            &d.code,
            DiagnosticCode::Metadata(MetadataDiagnosticCode::DuplicateTypeName { name }) if name == "Foo"
        ));
    }

    #[test]
    fn diagnostic_info_helper_sets_severity_correctly() {
        let d = Diagnostic::info(
            MetadataDiagnosticCode::DuplicateFunctionName {
                name: "do_stuff".to_string(),
            },
            "",
        );
        assert_eq!(d.severity, Severity::Info);
    }

    #[test]
    fn metadata_diagnostic_code_into_diagnostic_code_works() {
        let inner = MetadataDiagnosticCode::DuplicateTypeName {
            name: "Bar".to_string(),
        };
        let outer: DiagnosticCode = inner.clone().into();
        assert_eq!(outer, DiagnosticCode::Metadata(inner));
    }

    // A full serde round-trip test would require a serializer crate as a
    // dev-dependency (e.g. `serde_json`), which we don't pull in just for
    // tests. The `cfg_attr(feature = "serde", derive(Serialize,
    // Deserialize))` on each public type still gets type-checked when the
    // workspace is built with `--features serde`; that's the compile-time
    // guard. Functional round-trip coverage lives in callers that already
    // pull in a serializer (e.g. the CLI's JSON dump in a later sub-task).
}
