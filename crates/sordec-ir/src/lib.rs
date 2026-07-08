//! Typed intermediate representations for the sordec pipeline.
//!
//! Three distinct IR layers, each owning its own type:
//!
//! 1. [`WasmFacts`] — parsed WASM module + decoded Soroban metadata.
//!    Output of `sordec-frontend`.
//! 2. [`LiftedIr`] — SSA + CFG, close to WASM operators. Output of the
//!    lifting pass over `WasmFacts`.
//! 3. [`HighIr`] — structured control flow (if/loop/match), recovered
//!    semantic operations, refined types. Input to `sordec-backend`.
//!
//! See `docs/architecture.md` for the design rationale.
//!
//! ## Feature flags
//!
//! - `serde` — enables `Serialize`/`Deserialize` derives on every public
//!   type. Off by default; pass `--features serde` to dump IR for
//!   inspection.

pub mod high;
pub mod lifted;
pub mod memory;
pub mod validate;
pub mod wasm_facts;

pub use high::{
    AddressOpKind, BinaryOp, Binding, Expr, HighBlock, HighFunction, HighIr, IrType, KnownOp,
    KnownTier, KnownType, Literal, Region, SemanticOp, StorageTier, UnaryOp, ValObjectKind,
};
pub use lifted::{
    BlockTarget, LiftedBlock, LiftedFunction, LiftedIr, LiftedTerminator, LiftedType, LiftedValue,
    LiftedValueDef, WasmOp, WasmOpcodeKind,
};
pub use memory::{DataSegment, MemoryImage};
pub use validate::{validate_high, validate_lifted, Validate, ValidateError};
pub use wasm_facts::{
    ByteRange, CompositeType, CustomSection, EnumCase, EnumDef, EnvCompatibility, EventDef,
    EventParam, EventParamLocation, Export, ExportKind, FunctionParam, FunctionSignature, Import,
    ImportKind, PrimitiveType, SorobanFacts, StructDef, StructField, TypeRef, TypeRegistry,
    UnionCase, UnionDef, WasmFacts,
};
