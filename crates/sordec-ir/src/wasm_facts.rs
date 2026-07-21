//! Layer 1 of the IR pipeline: parsed-but-not-analysed WASM facts.
//!
//! [`WasmFacts`] is the output of the frontend (`sordec-frontend`). It is a
//! straightforward typed mirror of the WASM module structure plus, for
//! Soroban contracts, the decoded contents of the three custom sections
//! (`contractspecv0`, `contractenvmetav0`, `contractmetav0`).
//!
//! The crucial type-safety improvement over the legacy IR is that
//! references to user-defined types use [`TypeId`] rather than `String`.
//! Names still appear (we keep them for emitting the recovered Rust), but
//! they are stored once on the type definition; references are by id.
//!
//! Nothing in this module performs analysis. CFG construction, SSA, and
//! semantic recovery happen in later layers.

use std::collections::BTreeMap;

use sordec_common::{TypeId, UnknownReason};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Top-level facts extracted from a Soroban WASM module — the WASM-level
/// structure only.
///
/// Constructed by `sordec-frontend`. Consumed (read-only) by the lifter
/// and pattern passes — every later IR layer keeps a reference back to
/// the originating `WasmFacts` for export-name lookups, type resolution,
/// and emit-time annotations.
///
/// Soroban-specific decoded metadata lives in [`SorobanFacts`], which is
/// returned alongside `WasmFacts` from the frontend's `parse` function.
/// They are peer types, not nested — `WasmFacts` describes generic WASM
/// structure; `SorobanFacts` describes the Soroban contract surface.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WasmFacts {
    /// Functions imported from the host (Soroban env). Indexed by import
    /// index, which is what WASM function indices `< imports.len()` refer to.
    pub imports: Vec<Import>,

    /// Items exported by this module (functions, memories, tables, globals).
    pub exports: Vec<Export>,

    /// For each *local* (non-imported) function in declaration order, the
    /// index into the type section describing its signature.
    pub function_type_indices: Vec<u32>,

    /// Byte range `[start, end)` of each *local* function's code-section
    /// body, in declaration order — parallel to [`function_type_indices`].
    /// Recovered from `wasmparser`'s `FunctionBody::range()`. Empty for
    /// modules with no code section.
    ///
    /// The annotated-WAT emitter uses these to anchor per-function
    /// annotations to the offsets `wasmprinter` reports for the printed
    /// text; nothing at parse time interprets them.
    pub function_bodies: Vec<ByteRange>,

    /// Custom sections in declaration order. Soroban contracts contain at
    /// least one (`contractspecv0`); generic WASM may have none.
    pub custom_sections: Vec<CustomSection>,
}

/// One imported item from the WASM `import` section.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Import {
    /// Position of the import in the import section. Used to map back to
    /// `wasmparser`-style import indices.
    pub index: u32,
    /// Module name as written in the WASM. For Soroban host imports this
    /// is a single ASCII letter (`"l"`, `"x"`, `"i"`, etc.).
    // JUSTIFY: Module names are arbitrary strings per the WASM spec. We
    // cannot replace this with a TypeId or other newtype.
    pub module: String,
    /// Item name within the module. For Soroban this is a short
    /// ASCII identifier (`"0"`, `"_"`, etc.).
    // JUSTIFY: see `module` above.
    pub name: String,
    /// What kind of item is being imported.
    pub kind: ImportKind,
}

/// What kind of WASM item an [`Import`] refers to.
///
/// Storage of detailed table/memory/global metadata is deferred until a
/// pass actually needs it; the discriminant alone is enough for the
/// frontend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ImportKind {
    /// Imported function. The wrapped value is the function's type index.
    Func(u32),
    /// Imported table. We do not store table type details at this layer.
    Table,
    /// Imported memory.
    Memory,
    /// Imported global.
    Global,
    /// Imported exception tag.
    Tag,
}

/// One exported item from the WASM `export` section.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Export {
    /// Name as it appears to callers of the contract.
    // JUSTIFY: Export names are arbitrary user-supplied strings.
    pub name: String,
    /// Discriminant — which item kind this export refers to.
    pub kind: ExportKind,
    /// Index into the appropriate index space (functions, memories, etc.).
    pub index: u32,
}

/// What kind of WASM item an [`Export`] refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ExportKind {
    /// Exported function (e.g. a public contract method).
    Func,
    /// Exported memory (typically just `"memory"`).
    Memory,
    /// Exported table.
    Table,
    /// Exported global (e.g. `"__data_end"`, `"__heap_base"`).
    Global,
    /// Exported exception tag. Soroban contracts do not use these, but
    /// non-Soroban WASM may; we preserve the kind so the frontend never
    /// has to silently mis-classify a tag as a function.
    Tag,
}

/// One custom section from the WASM module.
///
/// We retain the raw bytes so passes that did not anticipate a particular
/// section can still inspect it. Soroban-recognised sections are also
/// decoded into [`SorobanFacts`].
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CustomSection {
    /// Section name (e.g. `"contractspecv0"`, `".debug_info"`).
    // JUSTIFY: Custom-section names are unbounded. Cannot use a typed enum
    // because we want to surface unknown sections, not silently drop them.
    pub name: String,
    /// Byte offsets `[start, end)` of the section in the original WASM.
    /// Useful for emitting "raw bytes lifted from offset X" annotations.
    pub byte_range: ByteRange,
    /// Section payload (without the WASM section header).
    pub bytes: Vec<u8>,
}

/// Half-open byte interval `[start, end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ByteRange {
    /// First byte (inclusive).
    pub start: u64,
    /// One past the last byte (exclusive).
    pub end: u64,
}

// -------------------------------------------------------------------
// Decoded Soroban metadata
// -------------------------------------------------------------------

/// Soroban metadata recovered from the contract's custom sections.
///
/// All cross-references between user-defined types use [`TypeId`].
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SorobanFacts {
    /// Function signatures keyed by their exported name.
    // JUSTIFY: Map keys are user-supplied export names, not symbols we
    // assign ids to. A typed key would force a separate name registry
    // and double the lookup cost for negligible safety gain.
    pub functions: BTreeMap<String, FunctionSignature>,

    /// User-defined type registry. Each entry has a stable [`TypeId`].
    pub types: TypeRegistry,

    /// Free-form key/value pairs from `contractmetav0` (SDK version,
    /// compiler version, etc).
    // JUSTIFY: Keys are user-supplied strings (e.g. "rssdkver"). No typed
    // enum can encode arbitrary build-tooling annotations.
    pub contract_meta: BTreeMap<String, String>,

    /// Protocol/environment compatibility info from `contractenvmetav0`.
    pub env_meta: EnvCompatibility,
}

/// Environment compatibility facts from `contractenvmetav0`.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EnvCompatibility {
    /// Soroban protocol version (e.g. `"21"` or `"26"`).
    // JUSTIFY: stellar-xdr stores this as a user-supplied string.
    // We preserve its original form so `contractenvmetav0` can be
    // round-tripped if needed.
    pub protocol: Option<String>,
    /// Pre-release identifier; usually `None` for shipped contracts.
    // JUSTIFY: see `protocol`.
    pub pre_release: Option<String>,
}

/// Signature of a contract-callable function.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FunctionSignature {
    /// Function name as exported. Soroban requires this to be at most
    /// nine ASCII characters; we keep it as `String` for flexibility.
    // JUSTIFY: Names are arbitrary user-defined identifiers.
    pub name: String,
    /// Parameters in declaration order.
    pub inputs: Vec<FunctionParam>,
    /// Return types. Multiple return values are exotic but allowed by the
    /// Soroban spec; the common case has zero or one.
    pub outputs: Vec<TypeRef>,
}

/// One parameter of a function signature.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FunctionParam {
    /// Parameter name as written in the original Rust source. Recovered
    /// from `contractspecv0` (where Soroban embeds it for tooling).
    // JUSTIFY: Names are arbitrary user-defined identifiers.
    pub name: String,
    /// Parameter type.
    pub ty: TypeRef,
}

/// A type reference: a primitive, a composite, a user-defined type by id,
/// or a recovery placeholder when the spec referenced something we couldn't
/// resolve.
///
/// The `Unknown` variant is the minimum-viable degradation for an
/// `UnresolvedTypeReference` warning — it preserves "a type was here, we
/// don't know which" so downstream emit doesn't drop the whole containing
/// declaration. Carriers of this variant always pair it with an
/// [`UnknownReason`] so the cause is auditable.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum TypeRef {
    /// One of the Soroban primitive types.
    Primitive(PrimitiveType),
    /// A composite type built from other types.
    Composite(CompositeType),
    /// A user-defined struct/union/enum/error/event by id.
    UserDefined(TypeId),
    /// Recovery placeholder: the spec referenced a type we couldn't
    /// resolve. The `UnknownReason` records why; the diagnostic emitted
    /// at the same site carries the human-readable context.
    Unknown(UnknownReason),
}

/// Soroban primitive types.
///
/// Mirrors [`stellar_xdr::ScSpecTypeDef`]'s primitive variants
/// (everything except `Option`, `Result`, `Vec`, `Map`, `Tuple`, `BytesN`,
/// `Udt`, which are composite or user-defined). Listing them as a
/// dedicated enum lets passes pattern-match exhaustively rather than
/// going through stringified type names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum PrimitiveType {
    /// Generic Soroban tagged value.
    Val,
    /// Boolean.
    Bool,
    /// Unit (`()` in Rust, `void` elsewhere).
    Void,
    /// Soroban error code.
    Error,
    /// Unsigned 32-bit.
    U32,
    /// Signed 32-bit.
    I32,
    /// Unsigned 64-bit.
    U64,
    /// Signed 64-bit.
    I64,
    /// Soroban `Timepoint` (u64 seconds).
    Timepoint,
    /// Soroban `Duration` (u64 seconds).
    Duration,
    /// Unsigned 128-bit.
    U128,
    /// Signed 128-bit.
    I128,
    /// Unsigned 256-bit.
    U256,
    /// Signed 256-bit.
    I256,
    /// Variable-length byte array.
    Bytes,
    /// UTF-8 string.
    String,
    /// Soroban `Symbol` (short ASCII).
    Symbol,
    /// Account or contract address.
    Address,
    /// Address with optional muxed ID.
    MuxedAddress,
}

/// Composite types: parameterised by their constituent types.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum CompositeType {
    /// `Option<T>`.
    Option(Box<TypeRef>),
    /// `Result<T, E>`.
    Result(Box<TypeRef>, Box<TypeRef>),
    /// Homogeneous `Vec<T>`.
    Vec(Box<TypeRef>),
    /// `Map<K, V>`.
    Map(Box<TypeRef>, Box<TypeRef>),
    /// Heterogeneous tuple.
    Tuple(Vec<TypeRef>),
    /// Fixed-length byte array `BytesN<N>`.
    BytesN(u32),
}

/// All user-defined types in the contract, keyed by id.
///
/// Each entry's `name` is the original Rust identifier; lookups by name
/// happen during decoding and are not preserved on the registry itself
/// (we go through [`TypeId`] for any subsequent reference).
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TypeRegistry {
    /// `#[contracttype]` structs.
    pub structs: Vec<StructDef>,
    /// `#[contracttype]` enums with payload (Rust unions).
    pub unions: Vec<UnionDef>,
    /// `#[contracttype]` C-style enums (discriminant-only).
    pub enums: Vec<EnumDef>,
    /// `#[contracterror]` error enums.
    pub errors: Vec<EnumDef>,
    /// `#[contractevent]` event types.
    pub events: Vec<EventDef>,
}

/// Soroban struct definition.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct StructDef {
    /// Stable identifier within the type registry.
    pub id: TypeId,
    // JUSTIFY: Names are arbitrary identifiers; required for emit.
    /// Original Rust type name.
    pub name: String,
    /// Fields in declaration order.
    pub fields: Vec<StructField>,
}

/// One field of a [`StructDef`].
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct StructField {
    /// Field name.
    // JUSTIFY: Names are arbitrary identifiers; required for emit.
    pub name: String,
    /// Field type.
    pub ty: TypeRef,
}

/// Soroban union (Rust enum with payloads).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct UnionDef {
    /// Stable identifier within the type registry.
    pub id: TypeId,
    /// Original Rust type name.
    // JUSTIFY: Names are arbitrary identifiers; required for emit.
    pub name: String,
    /// Variants in declaration order.
    pub cases: Vec<UnionCase>,
}

/// One variant of a [`UnionDef`].
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct UnionCase {
    /// Variant name.
    // JUSTIFY: Names are arbitrary identifiers; required for emit.
    pub name: String,
    /// Tuple-style payload types. Empty for void-only variants.
    pub fields: Vec<TypeRef>,
}

/// Soroban C-style enum (also used for error enums).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EnumDef {
    /// Stable identifier within the type registry.
    pub id: TypeId,
    /// Original Rust type name.
    // JUSTIFY: Names are arbitrary identifiers; required for emit.
    pub name: String,
    /// Variants in declaration order.
    pub cases: Vec<EnumCase>,
}

/// One variant of an [`EnumDef`] — name plus discriminant value.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EnumCase {
    /// Variant name.
    // JUSTIFY: Names are arbitrary identifiers; required for emit.
    pub name: String,
    /// Numeric discriminant assigned by the user (Soroban requires `u32`).
    pub value: u32,
}

/// Soroban `#[contractevent]` definition.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EventDef {
    /// Stable identifier within the type registry.
    pub id: TypeId,
    /// Original Rust type name.
    // JUSTIFY: Names are arbitrary identifiers; required for emit.
    pub name: String,
    /// Static topic prefix (the symbols that always lead the event).
    // JUSTIFY: Topic names are arbitrary user-supplied symbols.
    pub prefix_topics: Vec<String>,
    /// Indexed and data parameters in declaration order.
    pub params: Vec<EventParam>,
    /// Data-encoding format identifier as recorded in `contractspecv0`.
    // JUSTIFY: Stored as a free-form string per the Soroban spec; no typed
    // enum exists for this field upstream.
    pub data_format: String,
}

/// One parameter of an [`EventDef`].
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EventParam {
    /// Parameter name.
    // JUSTIFY: Names are arbitrary identifiers; required for emit.
    pub name: String,
    /// Parameter type.
    pub ty: TypeRef,
    /// Whether the parameter is indexed (topic) or carried in event data.
    pub location: EventParamLocation,
}

/// Where an [`EventParam`] is encoded in the emitted event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum EventParamLocation {
    /// Parameter goes into the topic list (indexed).
    Topic,
    /// Parameter goes into the data payload.
    Data,
}
