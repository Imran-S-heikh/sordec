//! Shared builders for hand-constructed [`LiftedFunction`] test fixtures.
//!
//! The declutter and structuring unit tests exercise their code on small
//! synthetic CFGs. These helpers keep that construction terse and
//! uniform; they were extracted once a sixth test module was about to
//! copy-paste the same `func_with` boilerplate the five declutter
//! modules already carried.
//!
//! Every synthetic value is typed [`LiftedType::I32`]: the code under
//! test never inspects value types, and a single type keeps fixtures
//! focused on the CFG/data-flow shape being asserted.

use sordec_common::{Arena, BlockId, FuncId, ValueId};
use sordec_ir::{
    BlockTarget, LiftedBlock, LiftedFunction, LiftedTerminator, LiftedType, LiftedValue,
    LiftedValueDef, WasmOp,
};

/// [`ValueId`] from a raw index.
pub(crate) fn v(idx: u32) -> ValueId {
    ValueId::new(idx)
}

/// [`BlockId`] from a raw index.
pub(crate) fn bb(idx: u32) -> BlockId {
    BlockId::new(idx)
}

/// Operator definition from a raw waffle operator and its operands.
pub(crate) fn op(w: waffle::Operator, args: Vec<ValueId>) -> LiftedValueDef {
    LiftedValueDef::Operator {
        op: WasmOp(w),
        args,
    }
}

/// `i32.const` definition — the workhorse pure value.
pub(crate) fn i32_const(value: u32) -> LiftedValueDef {
    op(waffle::Operator::I32Const { value }, vec![])
}

/// Block-parameter definition: `block`'s `index`-th parameter.
pub(crate) fn param(block: u32, index: u32) -> LiftedValueDef {
    LiftedValueDef::BlockParam {
        block: bb(block),
        index,
    }
}

/// Branch target carrying `args` into `block`'s parameters.
pub(crate) fn target(block: u32, args: Vec<ValueId>) -> BlockTarget {
    BlockTarget {
        block: bb(block),
        args,
    }
}

/// Block from raw parts.
pub(crate) fn block(
    id: u32,
    params: Vec<ValueId>,
    instructions: Vec<ValueId>,
    term: LiftedTerminator,
) -> LiftedBlock {
    LiftedBlock {
        id: bb(id),
        params,
        instructions,
        terminator: term,
    }
}

/// Function from raw defs + blocks. The first block is the entry and the
/// function gets id 0; value ids are dense in `defs` order.
pub(crate) fn func_with(defs: Vec<LiftedValueDef>, blocks_in: Vec<LiftedBlock>) -> LiftedFunction {
    let mut values: Arena<ValueId, LiftedValue> = Arena::new();
    for def in defs {
        values.push(LiftedValue {
            def,
            types: vec![LiftedType::I32],
        });
    }
    let mut blocks: Arena<BlockId, LiftedBlock> = Arena::new();
    for b in blocks_in {
        blocks.push(b);
    }
    LiftedFunction {
        id: FuncId::new(0),
        entry: bb(0),
        blocks,
        values,
    }
}
