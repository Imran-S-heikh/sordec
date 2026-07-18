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

/// Codes for diagnostics emitted while parsing raw WASM structure.
///
/// No variants are defined yet — the Phase 1 parser still treats
/// malformed WASM as a fatal frontend error and has not migrated any
/// recoverable parser conditions into diagnostics. The empty enum is
/// intentional: it reserves the parse-layer taxonomy slot so
/// [`DiagnosticCode::Parse`] can exist as a stable public artifact.
///
/// RFP artifact note: an empty enum here is not a missing parser
/// diagnostic implementation. It records that Phase 1 has a concrete
/// parse diagnostic taxonomy slot, even though no recoverable
/// parse-level conditions exist yet.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ParseDiagnosticCode {}

impl ParseDiagnosticCode {
    /// Stable `parse::snake_case` identifier. Uninhabited today.
    #[must_use]
    pub fn key(&self) -> &'static str {
        // Uninhabited — match against `&self` is exhaustive with no arms.
        match *self {}
    }
}

impl fmt::Display for ParseDiagnosticCode {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Uninhabited — match against `&self` is exhaustive with no arms.
        match *self {}
    }
}

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

impl MetadataDiagnosticCode {
    /// Stable, payload-free `metadata::snake_case` identifier for
    /// per-code aggregation.
    #[must_use]
    pub fn key(&self) -> &'static str {
        match self {
            Self::UnresolvedTypeReference { .. } => "metadata::unresolved_type_reference",
            Self::DuplicateTypeName { .. } => "metadata::duplicate_type_name",
            Self::DuplicateFunctionName { .. } => "metadata::duplicate_function_name",
            Self::MalformedContractMeta { .. } => "metadata::malformed_contract_meta",
        }
    }
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

/// Codes for diagnostics emitted during WASM → IR lift and Phase-2
/// pattern recovery.
///
/// This is the **recognition taxonomy**: one code per situation the
/// pipeline can produce valid IR for but could not fully recover — a
/// host call it does not recognize, a slot it could not resolve to a
/// constant, a construct whose recogniser is deferred. Every variant is
/// documented and `Display`-able so the set is a stable spec; the subset
/// with a live emission site is noted per-variant. Variants carry no
/// payload — the specific function / value / host name rides on the
/// [`Diagnostic`]'s [`Location`] and `message`, and [`key`](Self::key)
/// gives a stable payload-free identifier for per-code aggregation.
///
/// Codes are only *emitted* where a recogniser actually gives up; a
/// documented-but-unemitted variant lands its emission when its feature
/// does (`#[non_exhaustive]` keeps that additive).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum LiftDiagnosticCode {
    // ---- Emitted today (W6) ----
    /// A host import survived the whole recognition pipeline unmatched —
    /// no recogniser claimed its `(module, name)`. Emitted by the
    /// terminal unrecognised-scan over surviving `SemanticOp::Unknown`
    /// bindings. On a fully-recognised module (the whole corpus) this
    /// never fires; it is the definitional lift diagnostic for
    /// out-of-catalog or future-protocol WASM.
    UnrecognisedHostCall,
    /// A storage operation's durability argument was not a provable
    /// constant, so its tier stayed `Unknown`. Emitted by the storage
    /// recogniser.
    NonConstantDurabilityArg,
    /// A storage key was constructed by the `#[contracttype]` enum idiom
    /// but could not be named against a `contractspecv0` union (no spec,
    /// ambiguous match, or a polymorphic helper). Emitted by the
    /// `enum-key` recogniser.
    UnrecognisedStoragePattern,
    /// A TTL `extend_ttl` ledger amount (`threshold` / `extend_to`) did
    /// not resolve to a constant. Emitted by the `ttl` recogniser.
    NonConstantTtlAmount,
    /// A cross-contract call could not be typed against a known interface
    /// — its callee symbol or arity did not resolve. Emitted by the
    /// `client-call` recogniser.
    UnresolvedCrossContractCallee,
    /// A `symbol_index_in_linear_memory` enum-dispatch table could not be
    /// decoded from rodata (non-constant table position/length, or a
    /// descriptor that failed the `Symbol` grammar). Emitted by the
    /// `dispatcher` recogniser.
    UnresolvedSymbolDispatch,

    /// A function's control flow could not be structured and fell back
    /// to `Region::Unstructured` — irreducible or malformed input at the
    /// `LiftToHigh` boundary. Emitted by the structuring stats pass;
    /// never expected on real compiler output (WASM cannot express
    /// irreducible control flow), and corpus-locked to zero.
    StructuringFallback,

    // ---- Taxonomy, not yet emitted (lands with its feature) ----
    /// A `Symbol`/`String`/`Bytes` linear-memory literal position was not
    /// a provable constant. Not yet emitted — the linear-memory
    /// recogniser records `resolved: None` inline today.
    NonConstantSymbolArg,
    /// A cross-contract call resolved its callee but the contract had no
    /// `contractspecv0` interface to type the client against. Not yet
    /// emitted — folded into [`UnresolvedCrossContractCallee`] for now.
    ContractSpecMissingForClient,
    /// A `Result` `Ok`/`Err` tag could not be disambiguated. Not yet
    /// emitted — result-tag recovery (C18) is deferred.
    AmbiguousResultTag,
    /// A widened-integer (`i128`/`u128`/…) arithmetic sequence could not
    /// be fused into a single operation. Not yet emitted — wide-int
    /// fusion (C19) is deferred.
    WidenedIntegerFusionFailed,
    /// An event's topic vector shape could not be recovered. Not yet
    /// emitted — topic-vec expansion (C14) is emit-side.
    EventTopicShapeUnknown,
    /// An auth-context call's argument shape did not match the expected
    /// `require_auth_for_args` form. Not yet emitted — reserved for
    /// auth-context refinement.
    AuthContextArgsMismatch,
    /// A PRNG host call fell outside the recognised `p`-module catalog.
    /// Not yet emitted — such a call currently surfaces via
    /// [`UnrecognisedHostCall`]; reserved for a specific PRNG diagnostic.
    UnrecognisedPrngCall,
    /// A crypto host call fell outside the recognised `c`-module catalog.
    /// Not yet emitted — see [`UnrecognisedPrngCall`].
    UnrecognisedCryptoCall,
    /// A `panic!` lowered to a bare `unreachable` with no structured
    /// error code. Not yet emitted — bare-panic recovery (C16) is
    /// deferred.
    PanicWithoutErrorCode,
}

impl LiftDiagnosticCode {
    /// Stable, payload-free identifier for this code — used as the
    /// aggregation key in coverage's per-code counts and as the `Display`
    /// prefix. Format `lift::snake_case`.
    #[must_use]
    pub fn key(&self) -> &'static str {
        match self {
            Self::UnrecognisedHostCall => "lift::unrecognised_host_call",
            Self::NonConstantDurabilityArg => "lift::non_constant_durability_arg",
            Self::UnrecognisedStoragePattern => "lift::unrecognised_storage_pattern",
            Self::NonConstantTtlAmount => "lift::non_constant_ttl_amount",
            Self::UnresolvedCrossContractCallee => "lift::unresolved_cross_contract_callee",
            Self::UnresolvedSymbolDispatch => "lift::unresolved_symbol_dispatch",
            Self::NonConstantSymbolArg => "lift::non_constant_symbol_arg",
            Self::ContractSpecMissingForClient => "lift::contract_spec_missing_for_client",
            Self::AmbiguousResultTag => "lift::ambiguous_result_tag",
            Self::StructuringFallback => "lift::structuring_fallback",
            Self::WidenedIntegerFusionFailed => "lift::widened_integer_fusion_failed",
            Self::EventTopicShapeUnknown => "lift::event_topic_shape_unknown",
            Self::AuthContextArgsMismatch => "lift::auth_context_args_mismatch",
            Self::UnrecognisedPrngCall => "lift::unrecognised_prng_call",
            Self::UnrecognisedCryptoCall => "lift::unrecognised_crypto_call",
            Self::PanicWithoutErrorCode => "lift::panic_without_error_code",
        }
    }

    /// One-line human description (without the `key` prefix).
    fn description(&self) -> &'static str {
        match self {
            Self::UnrecognisedHostCall => "host call survived recognition unmatched",
            Self::NonConstantDurabilityArg => {
                "storage tier unresolved — durability argument is not a constant"
            }
            Self::UnrecognisedStoragePattern => {
                "storage key enum could not be named against the contract spec"
            }
            Self::NonConstantTtlAmount => "TTL ledger amount did not resolve to a constant",
            Self::UnresolvedCrossContractCallee => {
                "cross-contract call could not be typed against a known interface"
            }
            Self::UnresolvedSymbolDispatch => {
                "symbol-dispatch table could not be decoded from rodata"
            }
            Self::NonConstantSymbolArg => "linear-memory literal position is not a constant",
            Self::ContractSpecMissingForClient => "no contract spec to type the client call",
            Self::AmbiguousResultTag => "Result Ok/Err tag could not be disambiguated",
            Self::StructuringFallback => "control flow fell back to unstructured",
            Self::WidenedIntegerFusionFailed => "wide-integer arithmetic could not be fused",
            Self::EventTopicShapeUnknown => "event topic vector shape not recovered",
            Self::AuthContextArgsMismatch => "auth-context argument shape did not match",
            Self::UnrecognisedPrngCall => "PRNG host call outside the recognised catalog",
            Self::UnrecognisedCryptoCall => "crypto host call outside the recognised catalog",
            Self::PanicWithoutErrorCode => "bare panic without a structured error code",
        }
    }
}

impl fmt::Display for LiftDiagnosticCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.key(), self.description())
    }
}

// ---------------------------------------------------------------------
// DiagnosticCode (the outer enum)
// ---------------------------------------------------------------------

/// All diagnostic codes the pipeline can emit, namespaced by layer.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum DiagnosticCode {
    /// A diagnostic emitted while parsing raw WASM structure. Currently
    /// uninhabited; reserved for future recoverable parser conditions.
    Parse(ParseDiagnosticCode),
    /// A diagnostic emitted while decoding Soroban metadata custom
    /// sections.
    Metadata(MetadataDiagnosticCode),
    /// A diagnostic emitted during WASM-to-IR lifting. Currently always
    /// uninhabited; reserved for Phase 2 pattern recovery.
    Lift(LiftDiagnosticCode),
}

impl DiagnosticCode {
    /// Stable, payload-free `<layer>::snake_case` identifier for per-code
    /// aggregation (coverage's diagnostic counts key on this, not on the
    /// payload-bearing [`Display`](fmt::Display)).
    #[must_use]
    pub fn key(&self) -> &'static str {
        match self {
            Self::Parse(c) => c.key(),
            Self::Metadata(c) => c.key(),
            Self::Lift(c) => c.key(),
        }
    }
}

impl fmt::Display for DiagnosticCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(c) => c.fmt(f),
            Self::Metadata(c) => c.fmt(f),
            Self::Lift(c) => c.fmt(f),
        }
    }
}

impl From<ParseDiagnosticCode> for DiagnosticCode {
    fn from(c: ParseDiagnosticCode) -> Self {
        Self::Parse(c)
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
// Diagnostic artifact wrappers
// ---------------------------------------------------------------------

/// Frontend diagnostic artifact returned by `sordec-frontend`.
///
/// This is intentionally a thin wrapper around a shared stream of typed
/// [`Diagnostic`] events. Phase 1 metadata warnings also live here and
/// are distinguished by [`DiagnosticCode::Metadata`]; raw parser
/// diagnostics will use [`DiagnosticCode::Parse`] when recoverable
/// parser conditions exist.
///
/// RFP artifact note: this is the concrete `ParseDiagnostics` artifact.
/// It deliberately does not split metadata and parse events into
/// separate storage yet; the typed [`DiagnosticCode`] namespace is the
/// Phase 1 separation boundary. Keep it thin unless future diagnostics
/// need phase-specific fields.
///
/// Serialization note: `serde(transparent)` keeps existing JSON as a
/// plain diagnostics array (`[]` for clean inputs), not an object wrapper.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct ParseDiagnostics(Vec<Diagnostic>);

impl ParseDiagnostics {
    /// Create an empty parse diagnostic collection.
    #[must_use]
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Wrap an existing vector of diagnostic events.
    #[must_use]
    pub fn from_vec(events: Vec<Diagnostic>) -> Self {
        Self(events)
    }

    /// Borrow the diagnostic events as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[Diagnostic] {
        &self.0
    }

    /// Consume the wrapper and return the underlying vector.
    #[must_use]
    pub fn into_vec(self) -> Vec<Diagnostic> {
        self.0
    }

    /// Iterate over diagnostic events.
    pub fn iter(&self) -> std::slice::Iter<'_, Diagnostic> {
        self.0.iter()
    }

    /// Return the number of diagnostic events.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Return `true` when no diagnostic events were emitted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<Diagnostic>> for ParseDiagnostics {
    fn from(events: Vec<Diagnostic>) -> Self {
        Self::from_vec(events)
    }
}

impl AsRef<[Diagnostic]> for ParseDiagnostics {
    fn as_ref(&self) -> &[Diagnostic] {
        self.as_slice()
    }
}

impl IntoIterator for ParseDiagnostics {
    type Item = Diagnostic;
    type IntoIter = std::vec::IntoIter<Diagnostic>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a ParseDiagnostics {
    type Item = &'a Diagnostic;
    type IntoIter = std::slice::Iter<'a, Diagnostic>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Lifter diagnostic artifact returned by `sordec-passes`.
///
/// The collection is intentionally empty in Phase 1 because
/// [`LiftDiagnosticCode`] has no variants yet. Keeping this as a named
/// artifact makes the lift-layer output explicit while leaving room for
/// Phase 2 recovery passes to add non-fatal events.
///
/// RFP artifact note: this is the concrete `LiftDiagnostics` artifact.
/// Empty output in Phase 1 is expected, not a placeholder failure: the
/// lifter currently reports unrecoverable invariant violations as
/// `LiftError` and has no recoverable lift warning cases yet.
///
/// Serialization note: `serde(transparent)` preserves the same array
/// shape if lift diagnostics are serialized by future callers.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct LiftDiagnostics(Vec<Diagnostic>);

impl LiftDiagnostics {
    /// Create an empty lift diagnostic collection.
    #[must_use]
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Wrap an existing vector of diagnostic events.
    #[must_use]
    pub fn from_vec(events: Vec<Diagnostic>) -> Self {
        Self(events)
    }

    /// Borrow the diagnostic events as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[Diagnostic] {
        &self.0
    }

    /// Consume the wrapper and return the underlying vector.
    #[must_use]
    pub fn into_vec(self) -> Vec<Diagnostic> {
        self.0
    }

    /// Iterate over diagnostic events.
    pub fn iter(&self) -> std::slice::Iter<'_, Diagnostic> {
        self.0.iter()
    }

    /// Return the number of diagnostic events.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Return `true` when no diagnostic events were emitted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<Diagnostic>> for LiftDiagnostics {
    fn from(events: Vec<Diagnostic>) -> Self {
        Self::from_vec(events)
    }
}

impl AsRef<[Diagnostic]> for LiftDiagnostics {
    fn as_ref(&self) -> &[Diagnostic] {
        self.as_slice()
    }
}

impl IntoIterator for LiftDiagnostics {
    type Item = Diagnostic;
    type IntoIter = std::vec::IntoIter<Diagnostic>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a LiftDiagnostics {
    type Item = &'a Diagnostic;
    type IntoIter = std::slice::Iter<'a, Diagnostic>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
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

    #[test]
    fn parse_diagnostics_new_is_empty() {
        let diagnostics = ParseDiagnostics::new();
        assert!(diagnostics.is_empty());
        assert_eq!(diagnostics.len(), 0);
        assert!(diagnostics.as_slice().is_empty());
    }

    #[test]
    fn parse_diagnostics_from_vec_preserves_events() {
        let event = Diagnostic::warning(
            MetadataDiagnosticCode::DuplicateFunctionName {
                name: "mint".to_string(),
            },
            "first declaration kept",
        );
        let diagnostics = ParseDiagnostics::from_vec(vec![event.clone()]);

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics.as_slice(), std::slice::from_ref(&event));
        assert_eq!(diagnostics.iter().count(), 1);
        assert_eq!(diagnostics.into_vec(), vec![event]);
    }

    #[test]
    fn lift_code_display_prefixes_key_then_description() {
        let c = LiftDiagnosticCode::NonConstantDurabilityArg;
        assert_eq!(c.key(), "lift::non_constant_durability_arg");
        assert_eq!(
            c.to_string(),
            "lift::non_constant_durability_arg: storage tier unresolved — durability argument is not a constant"
        );
        // A "not yet emitted" taxonomy variant still Displays + keys.
        assert_eq!(
            LiftDiagnosticCode::StructuringFallback.key(),
            "lift::structuring_fallback"
        );
    }

    #[test]
    fn lift_code_keys_are_unique_and_lift_prefixed() {
        use std::collections::HashSet;
        let all = [
            LiftDiagnosticCode::UnrecognisedHostCall,
            LiftDiagnosticCode::NonConstantDurabilityArg,
            LiftDiagnosticCode::UnrecognisedStoragePattern,
            LiftDiagnosticCode::NonConstantTtlAmount,
            LiftDiagnosticCode::UnresolvedCrossContractCallee,
            LiftDiagnosticCode::UnresolvedSymbolDispatch,
            LiftDiagnosticCode::NonConstantSymbolArg,
            LiftDiagnosticCode::ContractSpecMissingForClient,
            LiftDiagnosticCode::AmbiguousResultTag,
            LiftDiagnosticCode::StructuringFallback,
            LiftDiagnosticCode::WidenedIntegerFusionFailed,
            LiftDiagnosticCode::EventTopicShapeUnknown,
            LiftDiagnosticCode::AuthContextArgsMismatch,
            LiftDiagnosticCode::UnrecognisedPrngCall,
            LiftDiagnosticCode::UnrecognisedCryptoCall,
            LiftDiagnosticCode::PanicWithoutErrorCode,
        ];
        let keys: HashSet<&str> = all.iter().map(|c| c.key()).collect();
        assert_eq!(keys.len(), all.len(), "keys must be unique");
        assert!(all.iter().all(|c| c.key().starts_with("lift::")));
    }

    #[test]
    fn diagnostic_code_key_dispatches_to_layer() {
        let lift: DiagnosticCode = LiftDiagnosticCode::UnresolvedSymbolDispatch.into();
        assert_eq!(lift.key(), "lift::unresolved_symbol_dispatch");
        let meta: DiagnosticCode = MetadataDiagnosticCode::DuplicateTypeName {
            name: "DataKey".to_string(),
        }
        .into();
        assert_eq!(meta.key(), "metadata::duplicate_type_name");
    }

    #[test]
    fn lift_warning_carries_code_and_location() {
        let d = Diagnostic::warning(
            LiftDiagnosticCode::NonConstantTtlAmount,
            "extend_ttl amount v9 not a constant",
        )
        .at(Location::Value {
            func: FuncId::from_index(1),
            value: 9,
        });
        assert_eq!(d.severity, Severity::Warning);
        assert_eq!(d.code.key(), "lift::non_constant_ttl_amount");
        assert_eq!(
            d.location,
            Some(Location::Value {
                func: FuncId::from_index(1),
                value: 9
            })
        );
    }

    #[test]
    fn lift_diagnostics_new_is_empty() {
        let diagnostics = LiftDiagnostics::new();
        assert!(diagnostics.is_empty());
        assert_eq!(diagnostics.len(), 0);
        assert!(diagnostics.as_slice().is_empty());
    }

    #[test]
    fn lift_diagnostics_from_vec_preserves_events() {
        let event = Diagnostic::info(
            MetadataDiagnosticCode::MalformedContractMeta {
                reason: "test".to_string(),
            },
            "metadata map left empty",
        );
        let diagnostics = LiftDiagnostics::from_vec(vec![event.clone()]);

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics.as_slice(), std::slice::from_ref(&event));
        assert_eq!((&diagnostics).into_iter().count(), 1);
        assert_eq!(diagnostics.into_vec(), vec![event]);
    }

    // A full serde round-trip test would require a serializer crate as a
    // dev-dependency (e.g. `serde_json`), which we don't pull in just for
    // tests. The `cfg_attr(feature = "serde", derive(Serialize,
    // Deserialize))` on each public type still gets type-checked when the
    // workspace is built with `--features serde`; that's the compile-time
    // guard. Functional round-trip coverage lives in callers that already
    // pull in a serializer (e.g. the CLI's JSON dump in a later sub-task).
}
