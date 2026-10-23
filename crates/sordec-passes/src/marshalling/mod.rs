//! Marshalling elision — deleting the ABI glue the source never wrote.
//!
//! [`crate::recognizers::val_encoding`] (C1) *recognizes* Soroban's inlined
//! `Val` encode/decode scaffolding and stops there, by design: its module
//! docs disclaim elision and dead-binding removal. Recognition alone leaves
//! every marshalling node live, the backend renders each as a `todo!()`
//! hole, and the reconstruction carries roughly twenty-four times the
//! control flow the original source had. This module is the missing half.
//!
//! ## What is being undone
//!
//! Two rustc/SDK transforms, neither of which appears in the source:
//!
//! 1. **`TryFromVal` argument decoding.** A `u64` parameter does not arrive
//!    as a `u64` — it arrives as a tagged `Val` that the SDK unpacks
//!    through a helper writing `Result<T, ConversionError>` into the
//!    caller's frame. The source wrote `a`; the wasm carries a call, two
//!    memory loads, and a failure guard.
//! 2. **The shadow stack.** WASM has no addressable call stack, so rustc
//!    carves scratch space out of linear memory: read global 0, subtract
//!    the frame size, write it back on entry; add it back on exit. Pure
//!    bookkeeping.
//!
//! ## Discipline
//!
//! Inherited from [`crate::refine`], and load-bearing here because an
//! elision pass that guesses deletes *contract logic*, not just noise:
//!
//! - **Undo, never invent.** Every rewrite reverses a specific known
//!   transform. A shape we cannot prove is glue stays exactly as the
//!   recognizers left it.
//! - **Classify before eliding.** The out-parameter shape means
//!   marshalling in one function and a real wide return in another (see
//!   [`sret`]); the effect gate in [`decode::classify`] is what separates
//!   them. Blanket-matching the shape would silently delete
//!   `read_balance`.
//! - **Rewrite to pure, let the existing cleanup delete.** Nothing here
//!   removes bindings from the arena. Elided nodes are rewritten to
//!   `Literal(Unit)` / `Use(..)`, which the backend's dead-`let` pass
//!   already drops when unread — so the IR keeps a complete provenance
//!   trail of what was elided and why.
//! - **No-match means no elision.** Every gate declines rather than
//!   approximating.
//!
//! ## Order
//!
//! [`decode`] → [`encode`] → [`guard`] → [`frame`], as a fixpoint group,
//! because each one unblocks the next: collapsing a decode makes its
//! failure guard constant, collapsing a return encode makes the width
//! dispatch around it decide nothing, removing those guards makes the
//! frame pointer dead, and a dead frame pointer is what lets the prologue
//! and epilogue go. Running them in one direction to a fixpoint converges
//! because each strictly reduces the number of live marshalling bindings.

pub mod bool_codec;
pub mod bytesn_convert;
pub mod client_args;
pub mod contract_event;
pub mod decode;
pub mod enum_discriminant;
pub mod enum_encode;
pub mod field_type;
pub mod encode;
pub mod frame;
pub mod guard;
pub mod key_construction;
pub mod key_field_type;
pub mod muxed_address;
pub mod option_default;
pub mod option_if_let;
pub mod option_probe;
pub mod vec_elements;
pub mod option_sret;
pub mod optional_out;
pub mod optional_pair;
pub mod option_unwrap;
pub mod spec_from_guards;
pub mod residual_probe;
pub mod storage_value_type;
pub mod tuple_return;
pub mod dead_store;
pub mod folded_encode;
pub mod forward;
pub(crate) mod sret;
pub mod scalar_decode;
pub mod typed_read;
pub mod udt_decode;
pub mod udt_encode;
pub mod wide_codec;
pub mod wide_return;

pub use bool_codec::BoolCodecPass;
pub use bytesn_convert::BytesNConvertPass;
pub use client_args::ClientArgVecPass;
pub use contract_event::ContractEventPass;
pub use dead_store::DeadFrameStorePass;
pub use decode::ValDecodeCollapsePass;
pub use enum_discriminant::EnumDiscriminantPass;
pub use enum_encode::EnumEncodePass;
pub use field_type::FieldTypePass;
pub use encode::ValEncodeCollapsePass;
pub use folded_encode::FoldedEncodePass;
pub use forward::FrameForwardPass;
pub use scalar_decode::ScalarDecodePass;
pub use typed_read::TypedReadPass;
pub use udt_decode::UdtDecodePass;
pub use udt_encode::UdtEncodePass;
pub use wide_codec::WideCodecPass;
pub use frame::FrameElisionPass;
pub use guard::ArgGuardElisionPass;
pub use key_construction::KeyConstructionElisionPass;
pub use key_field_type::KeyFieldTypePass;
pub use muxed_address::MuxedAddressPass;
pub use option_default::OptionDefaultPass;
pub use option_if_let::OptionIfLetPass;
pub use option_probe::OptionProbePass;
pub use vec_elements::VecElementsPass;
pub use tuple_return::TupleReturnPass;
pub mod host_len;
pub use host_len::HostLenPass;
pub mod masked_encode;
pub use masked_encode::MaskedEncodePass;
pub mod wide_encode;
pub use wide_encode::WideEncodePass;
pub mod option_param;
pub use option_param::OptionParamPass;
pub mod bool_return;
pub use bool_return::BoolReturnPass;
pub use residual_probe::ResidualProbePass;
pub use option_sret::OptionSretPass;
pub use optional_out::OptionalOutParamPass;
pub use optional_pair::OptionalPairPass;
pub use option_unwrap::OptionUnwrapPass;
pub use spec_from_guards::SpecFromGuardsPass;
pub use storage_value_type::StorageValueTypePass;
pub use wide_return::WideReturnPass;

use sordec_common::{Provenance, ProvenanceSource, ValueId};
use sordec_ir::{Expr, HighFunction, IrType};

/// One planned binding rewrite, collected during a read-only scan and
/// applied afterward — the same scan-then-apply split the recognizers
/// use, kept separate from [`crate::recognizers::Rewrite`] because that
/// type documents an invariant this module deliberately breaks: an
/// elision's replacement is a *pure* expression (`Use` / `Literal`), not
/// a `Semantic(Known(_))`. Sharing the type would make its doc comment a
/// lie and would silently opt these rewrites into the recognizers'
/// `is_recognized` idempotency guard, which keys on exactly that variant.
pub(crate) struct Elision {
    /// Binding to rewrite.
    pub id: ValueId,
    /// Replacement expression — pure, so the backend's dead-`let` pass
    /// drops it once nothing reads it.
    pub expr: Expr,
    /// `None` leaves the binding's type unchanged.
    pub ty: Option<IrType>,
    /// Provenance note naming what was elided and on what evidence.
    pub note: String,
    /// Metric counter key to increment.
    pub metric: &'static str,
}

/// Apply collected elisions: set the expression, upgrade the type when one
/// is given, and append the audit entry. The binding stays in the arena —
/// preservation is the IR's job, and the provenance trail is what makes an
/// elision reviewable after the fact.
pub(crate) fn apply_elisions(
    func: &mut HighFunction,
    pass_name: &'static str,
    elisions: Vec<Elision>,
) {
    for el in elisions {
        if let Some(binding) = func.bindings.get_mut(el.id) {
            binding.expr = el.expr;
            if let Some(ty) = el.ty {
                binding.ty = ty;
            }
            binding.add_provenance(Provenance::new(
                pass_name,
                ProvenanceSource::SdkPattern,
                el.note,
            ));
        }
    }
}

/// Short aliases for this module's counter keys. The names themselves are
/// declared once in [`crate::metrics_catalog`], which is what
/// `sordec coverage` reads and what the catalog-completeness test checks.
pub(crate) mod metrics {
    pub(crate) use crate::metrics_catalog::{
        MARSHALLING_DEAD_FRAME_STORES as DEAD_FRAME_STORES,
        MARSHALLING_DECODE_CALLS_ELIDED as DECODE_CALLS_ELIDED,
        MARSHALLING_DECODE_COLLAPSED as DECODE_COLLAPSED,
        MARSHALLING_DISPATCH_FOLDED as DISPATCH_FOLDED,
        MARSHALLING_ENCODE_COLLAPSED as ENCODE_COLLAPSED,
        MARSHALLING_FRAME_LOADS_FORWARDED as FRAME_LOADS_FORWARDED,
        MARSHALLING_FRAMES_ELIDED as FRAMES_ELIDED,
        MARSHALLING_GUARDS_ELIDED as GUARDS_ELIDED,
        MARSHALLING_OPTIONS_UNWRAPPED as OPTIONS_UNWRAPPED,
        MARSHALLING_OPTION_DEFAULT_DECLINED_ARM_ALWAYS_TRAPS as OPTION_DEFAULT_ARM_ALWAYS_TRAPS,
        MARSHALLING_OPTION_DEFAULT_DECLINED_ARM_HAS_EFFECTS as OPTION_DEFAULT_ARM_HAS_EFFECTS,
        MARSHALLING_OPTION_DEFAULT_DECLINED_CHECK_WOULD_FIRE as OPTION_DEFAULT_CHECK_WOULD_FIRE,
        MARSHALLING_OPTION_DEFAULT_DECLINED_MERGE_SHAPE as OPTION_DEFAULT_MERGE_SHAPE,
        MARSHALLING_OPTION_DEFAULT_DECLINED_NOTHING_MERGED as OPTION_DEFAULT_NOTHING_MERGED,
        MARSHALLING_OPTION_DEFAULT_DECLINED_NOT_ONE_READ as OPTION_DEFAULT_NOT_ONE_READ,
        MARSHALLING_OPTION_DEFAULT_DECLINED_NONE_ARM_BRANCHES as OPTION_DEFAULT_NONE_ARM_BRANCHES,
        MARSHALLING_OPTION_DEFAULT_DECLINED_NO_COMMON_DEFAULT as OPTION_DEFAULT_NO_COMMON_DEFAULT,
        MARSHALLING_OPTION_DEFAULT_DECLINED_PROBE_SHARED as OPTION_DEFAULT_PROBE_SHARED,
        MARSHALLING_OPTION_DEFAULT_DECLINED_READ_ON_FALL_THROUGH as OPTION_DEFAULT_READ_ON_FALL_THROUGH,
        MARSHALLING_OPTION_DEFAULT_DECLINED_SOME_ARM_BRANCHES as OPTION_DEFAULT_SOME_ARM_BRANCHES,
        MARSHALLING_OPTION_DEFAULT_DECLINED_STRUCT_WITH_CHECKS as OPTION_DEFAULT_STRUCT_WITH_CHECKS,
        MARSHALLING_UDT_DECODES_COLLAPSED as UDT_DECODES_COLLAPSED,
        MARSHALLING_UDT_DECLINED_EVIDENCE as UDT_DECLINED_EVIDENCE,
        MARSHALLING_UDT_DECLINED_KEYS as UDT_DECLINED_KEYS,
        MARSHALLING_UDT_DECLINED_NO_STRUCT as UDT_DECLINED_NO_STRUCT,
        MARSHALLING_UDT_DECLINED_OPERANDS as UDT_DECLINED_OPERANDS,
        MARSHALLING_UDT_FIELDS_RECOVERED as UDT_FIELDS_RECOVERED,
        MARSHALLING_UDT_HELPERS_COLLAPSED as UDT_HELPERS_COLLAPSED,
        MARSHALLING_UDT_STRUCTS_SYNTHESIZED as UDT_STRUCTS_SYNTHESIZED,
        MARSHALLING_WIDE_CODEC_CALLS_ELIDED as WIDE_CODEC_CALLS_ELIDED,
        MARSHALLING_WIDE_DECODE_COLLAPSED as WIDE_DECODE_COLLAPSED,
        MARSHALLING_WIDE_ENCODE_COLLAPSED as WIDE_ENCODE_COLLAPSED,
        MARSHALLING_WIDE_LOADS_REBOUND as WIDE_LOADS_REBOUND,
        MARSHALLING_WIDE_RETURNS_RECOVERED as WIDE_RETURNS_RECOVERED,
    };
}

#[cfg(test)]
pub(crate) mod test_support {
    use sordec_common::{
        Arena, BlockId, FuncId, IrId, Provenance, ProvenanceSource, UnknownReason, ValueId,
    };
    use sordec_ir::{
        Binding, Expr, HighBlock, HighFunction, HighIr, IrType, MemWidth, MemoryImage, Region,
        WasmFacts,
    };

    pub(crate) fn v(i: u32) -> ValueId {
        ValueId::from_index(i)
    }

    pub(crate) fn store(addr: ValueId, value: ValueId, offset: u32) -> Expr {
        Expr::Store {
            addr,
            value,
            offset,
            width: MemWidth::W8,
        }
    }

    pub(crate) fn load(addr: ValueId, offset: u32) -> Expr {
        Expr::Load {
            addr,
            offset,
            width: MemWidth::W8,
            signed: None,
            ty: IrType::Unknown(UnknownReason::InsufficientEvidence),
        }
    }

    /// A single-block `HighFunction` over `exprs` (ids `0..N`), with
    /// `params` as the parameter list and `scheduled` as the block's
    /// binding order. The region is one `Basic` block, so
    /// [`super::sret::emission_order`] sees exactly `scheduled`.
    pub(crate) fn func_with(
        exprs: Vec<Expr>,
        params: Vec<ValueId>,
        scheduled: Vec<u32>,
    ) -> HighFunction {
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        for expr in exprs {
            let id = ValueId::from_index(bindings.len() as u32);
            bindings.push(Binding::new(
                id,
                IrType::Unknown(UnknownReason::InsufficientEvidence),
                expr,
                Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
            ));
        }
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        let block_id = BlockId::from_index(0);
        blocks.push(HighBlock {
            id: block_id,
            bindings: scheduled.into_iter().map(v).collect(),
        });
        HighFunction {
            id: FuncId::from_index(0),
            name: None,
            signature: None,
            aliases: Vec::new(),
            blocks,
            bindings,
            region: Region::Basic(block_id),
            params,
            returns: vec![],
        }
    }

    /// A one-function module, for the pass-level tests.
    pub(crate) fn module(functions: Vec<HighFunction>) -> HighIr {
        HighIr {
            facts: WasmFacts {
                imports: vec![],
                exports: vec![],
                function_type_indices: vec![],
                function_bodies: vec![],
                function_fingerprints: vec![],
                table_functions: None,
                custom_sections: vec![],
            },
            soroban_facts: None,
            functions,
            memory: MemoryImage::empty(),
        }
    }
}
