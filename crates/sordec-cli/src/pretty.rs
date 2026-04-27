//! Pretty-printer for [`LiftedIr`] — produces waffle-style text output
//! consumed by `sordec dump-ir`.
//!
//! # Output format
//!
//! ```text
//! function func_<id> [exported as "<name>"] {
//!   bb<id>(v<id>: <type>, v<id>: <type>):
//!     v<id> = <op>(v<id>, v<id>)
//!     v<id> = block_param[<n>]
//!     <terminator>
//!
//!   bb<id>:
//!     ...
//! }
//! ```
//!
//! Operator names use the `Display` impl on [`sordec_ir::WasmOp`], which
//! today is a `Debug`-fallback rendering of the inner `waffle::Operator`.
//! That output is **not stable across `waffle` releases** — never
//! snapshot-test it. Phase 2 polish replaces the fallback with a real
//! Display catalog of common opcodes.
//!
//! # Why this lives in `sordec-cli`
//!
//! Only the CLI consumes it today, and the format will evolve as
//! semantic recovery layers in (sub-task #3 changes value rendering to
//! emit recovered host-call names in place of `call $import_5(...)`).
//! When a second non-CLI consumer materialises (e.g. an LSP server),
//! promoting the printer to `sordec-ir` is straightforward.

use std::collections::BTreeMap;
use std::io::{self, Write};

use sordec_common::{BlockId, IrId, ValueId};
use sordec_ir::{
    BlockTarget, ExportKind, ImportKind, LiftedBlock, LiftedFunction, LiftedIr,
    LiftedTerminator, LiftedType, LiftedValue, LiftedValueDef, WasmFacts,
};

// ---------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------

/// Options that control rendering verbosity.
#[derive(Debug, Clone, Default)]
pub struct RenderOptions {
    /// Prepend a module-info header (imports/exports counts + metadata
    /// presence) before rendering functions.
    pub with_header: bool,
}

/// Render a [`LiftedIr`] to `out` in waffle-style text form.
///
/// # Errors
///
/// Returns the underlying [`io::Error`] when writing to `out` fails.
pub fn render_lifted_ir(
    out: &mut impl Write,
    lifted: &LiftedIr,
    options: &RenderOptions,
) -> io::Result<()> {
    if options.with_header {
        render_module_header(out, lifted)?;
        writeln!(out)?;
    }

    if lifted.functions.is_empty() {
        writeln!(out, ";; (module has no local functions)")?;
        return Ok(());
    }

    let exports = build_exports_by_local_idx(&lifted.facts);
    for (i, func) in lifted.functions.iter().enumerate() {
        if i > 0 {
            writeln!(out)?;
        }
        render_function(out, func, &exports)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Internal helpers — one per render concern
// ---------------------------------------------------------------------

/// Build `local_func_idx → exported_name` for the export annotations on
/// function headers. Walks `WasmFacts.exports` once per render.
fn build_exports_by_local_idx(facts: &WasmFacts) -> BTreeMap<u32, &str> {
    // Imports come first in the WASM function index space; subtract
    // them off to recover local-function index. Same logic as the
    // lifter uses to assign FuncIds.
    let imported_funcs = facts
        .imports
        .iter()
        .filter(|i| matches!(i.kind, ImportKind::Func(_)))
        .count() as u32;

    facts
        .exports
        .iter()
        .filter_map(|e| match e.kind {
            ExportKind::Func => e
                .index
                .checked_sub(imported_funcs)
                .map(|local| (local, e.name.as_str())),
            _ => None,
        })
        .collect()
}

fn render_module_header(out: &mut impl Write, lifted: &LiftedIr) -> io::Result<()> {
    let f = &lifted.facts;
    let import_funcs = f
        .imports
        .iter()
        .filter(|i| matches!(i.kind, ImportKind::Func(_)))
        .count();
    let export_funcs = f
        .exports
        .iter()
        .filter(|e| matches!(e.kind, ExportKind::Func))
        .count();

    writeln!(out, ";; module")?;
    writeln!(
        out,
        ";;   imports: {} ({} {}, {} other)",
        f.imports.len(),
        import_funcs,
        if import_funcs == 1 { "function" } else { "functions" },
        f.imports.len() - import_funcs,
    )?;
    writeln!(
        out,
        ";;   exports: {} ({} {}, {} other)",
        f.exports.len(),
        export_funcs,
        if export_funcs == 1 { "function" } else { "functions" },
        f.exports.len() - export_funcs,
    )?;
    writeln!(out, ";;   local functions: {}", lifted.functions.len())?;
    writeln!(
        out,
        ";;   metadata: {}",
        if lifted.soroban_facts.is_some() {
            "present"
        } else {
            "absent"
        }
    )?;
    Ok(())
}

fn render_function(
    out: &mut impl Write,
    func: &LiftedFunction,
    exports: &BTreeMap<u32, &str>,
) -> io::Result<()> {
    let id_idx = func.id.index();
    if let Some(name) = exports.get(&id_idx) {
        writeln!(out, "function func_{id_idx} [exported as {name:?}] {{")?;
    } else {
        writeln!(out, "function func_{id_idx} {{")?;
    }

    let mut first = true;
    for (block_id, block) in func.blocks.iter() {
        if !first {
            writeln!(out)?;
        }
        first = false;
        render_block(out, block_id, block, func)?;
    }

    writeln!(out, "}}")?;
    Ok(())
}

fn render_block(
    out: &mut impl Write,
    block_id: BlockId,
    block: &LiftedBlock,
    func: &LiftedFunction,
) -> io::Result<()> {
    write!(out, "  bb{}", block_id.index())?;
    if !block.params.is_empty() {
        write!(out, "(")?;
        for (i, &param_id) in block.params.iter().enumerate() {
            if i > 0 {
                write!(out, ", ")?;
            }
            // Look up the param's type from its LiftedValue. Block
            // params produce zero or one type; if missing, show "?".
            let ty_str = func
                .values
                .get(param_id)
                .and_then(|v| v.types.first())
                .map_or("?", lifted_type_str);
            write!(out, "v{}: {}", param_id.index(), ty_str)?;
        }
        write!(out, ")")?;
    }
    writeln!(out, ":")?;

    for &value_id in &block.instructions {
        let value = func
            .values
            .get(value_id)
            .expect("LiftedIr invariant: instruction value id resolves");
        write!(out, "    ")?;
        render_value_def(out, value_id, value)?;
        writeln!(out)?;
    }

    write!(out, "    ")?;
    render_terminator(out, &block.terminator)?;
    writeln!(out)?;
    Ok(())
}

fn render_value_def(
    out: &mut impl Write,
    value_id: ValueId,
    value: &LiftedValue,
) -> io::Result<()> {
    write!(out, "v{} = ", value_id.index())?;
    match &value.def {
        LiftedValueDef::Operator { op, args } => {
            // `WasmOp::Display` is currently a Debug fallback; this
            // produces noisy but readable output. Replaced with a
            // proper Display catalog in Phase 2.
            write!(out, "{op}")?;
            if !args.is_empty() {
                write!(out, "(")?;
                for (i, arg) in args.iter().enumerate() {
                    if i > 0 {
                        write!(out, ", ")?;
                    }
                    write!(out, "v{}", arg.index())?;
                }
                write!(out, ")")?;
            }
        }
        LiftedValueDef::BlockParam { block: _, index } => {
            write!(out, "block_param[{index}]")?;
        }
        LiftedValueDef::PickOutput { from, index } => {
            write!(out, "pick{index} v{}", from.index())?;
        }
        LiftedValueDef::Alias(other) => {
            write!(out, "alias v{}", other.index())?;
        }
    }
    Ok(())
}

fn render_terminator(out: &mut impl Write, term: &LiftedTerminator) -> io::Result<()> {
    match term {
        LiftedTerminator::Branch(target) => {
            write!(out, "branch ")?;
            render_block_target(out, target)?;
        }
        LiftedTerminator::BranchIf {
            cond,
            if_true,
            if_false,
        } => {
            write!(out, "branch_if v{} \u{2192} ", cond.index())?;
            render_block_target(out, if_true)?;
            write!(out, ", else ")?;
            render_block_target(out, if_false)?;
        }
        LiftedTerminator::Switch {
            index,
            targets,
            default,
        } => {
            write!(out, "switch v{} [", index.index())?;
            for (i, t) in targets.iter().enumerate() {
                if i > 0 {
                    write!(out, ", ")?;
                }
                render_block_target(out, t)?;
            }
            write!(out, "] default ")?;
            render_block_target(out, default)?;
        }
        LiftedTerminator::Return { values } => {
            write!(out, "return")?;
            for (i, v) in values.iter().enumerate() {
                if i == 0 {
                    write!(out, " ")?;
                } else {
                    write!(out, ", ")?;
                }
                write!(out, "v{}", v.index())?;
            }
        }
        LiftedTerminator::Unreachable => {
            write!(out, "unreachable")?;
        }
    }
    Ok(())
}

fn render_block_target(out: &mut impl Write, target: &BlockTarget) -> io::Result<()> {
    write!(out, "bb{}", target.block.index())?;
    if !target.args.is_empty() {
        write!(out, "(")?;
        for (i, v) in target.args.iter().enumerate() {
            if i > 0 {
                write!(out, ", ")?;
            }
            write!(out, "v{}", v.index())?;
        }
        write!(out, ")")?;
    }
    Ok(())
}

fn lifted_type_str(ty: &LiftedType) -> &'static str {
    match ty {
        LiftedType::I32 => "i32",
        LiftedType::I64 => "i64",
        LiftedType::F32 => "f32",
        LiftedType::F64 => "f64",
        LiftedType::V128 => "v128",
        LiftedType::FuncRef => "funcref",
        LiftedType::ExternRef => "externref",
    }
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn render_to_string(f: impl FnOnce(&mut Vec<u8>) -> io::Result<()>) -> String {
        let mut buf = Vec::new();
        f(&mut buf).expect("write succeeds");
        String::from_utf8(buf).expect("utf-8")
    }

    #[test]
    fn lifted_type_str_covers_every_variant() {
        // Update this test if a new LiftedType variant lands.
        assert_eq!(lifted_type_str(&LiftedType::I32), "i32");
        assert_eq!(lifted_type_str(&LiftedType::I64), "i64");
        assert_eq!(lifted_type_str(&LiftedType::F32), "f32");
        assert_eq!(lifted_type_str(&LiftedType::F64), "f64");
        assert_eq!(lifted_type_str(&LiftedType::V128), "v128");
        assert_eq!(lifted_type_str(&LiftedType::FuncRef), "funcref");
        assert_eq!(lifted_type_str(&LiftedType::ExternRef), "externref");
    }

    #[test]
    fn render_terminator_branch_no_args() {
        let target = BlockTarget {
            block: BlockId::from_index(2),
            args: Vec::new(),
        };
        let term = LiftedTerminator::Branch(target);
        let s = render_to_string(|w| render_terminator(w, &term));
        assert_eq!(s, "branch bb2");
    }

    #[test]
    fn render_terminator_branch_with_args() {
        let target = BlockTarget {
            block: BlockId::from_index(7),
            args: vec![ValueId::from_index(3), ValueId::from_index(5)],
        };
        let term = LiftedTerminator::Branch(target);
        let s = render_to_string(|w| render_terminator(w, &term));
        assert_eq!(s, "branch bb7(v3, v5)");
    }

    #[test]
    fn render_terminator_branch_if() {
        let term = LiftedTerminator::BranchIf {
            cond: ValueId::from_index(9),
            if_true: BlockTarget {
                block: BlockId::from_index(1),
                args: vec![ValueId::from_index(2)],
            },
            if_false: BlockTarget {
                block: BlockId::from_index(3),
                args: Vec::new(),
            },
        };
        let s = render_to_string(|w| render_terminator(w, &term));
        assert_eq!(s, "branch_if v9 \u{2192} bb1(v2), else bb3");
    }

    #[test]
    fn render_terminator_switch() {
        let term = LiftedTerminator::Switch {
            index: ValueId::from_index(0),
            targets: vec![
                BlockTarget {
                    block: BlockId::from_index(1),
                    args: Vec::new(),
                },
                BlockTarget {
                    block: BlockId::from_index(2),
                    args: Vec::new(),
                },
            ],
            default: BlockTarget {
                block: BlockId::from_index(3),
                args: Vec::new(),
            },
        };
        let s = render_to_string(|w| render_terminator(w, &term));
        assert_eq!(s, "switch v0 [bb1, bb2] default bb3");
    }

    #[test]
    fn render_terminator_return_with_one_value() {
        let term = LiftedTerminator::Return {
            values: vec![ValueId::from_index(3)],
        };
        let s = render_to_string(|w| render_terminator(w, &term));
        assert_eq!(s, "return v3");
    }

    #[test]
    fn render_terminator_return_with_two_values() {
        let term = LiftedTerminator::Return {
            values: vec![ValueId::from_index(1), ValueId::from_index(2)],
        };
        let s = render_to_string(|w| render_terminator(w, &term));
        assert_eq!(s, "return v1, v2");
    }

    #[test]
    fn render_terminator_return_no_values() {
        let term = LiftedTerminator::Return { values: Vec::new() };
        let s = render_to_string(|w| render_terminator(w, &term));
        assert_eq!(s, "return");
    }

    #[test]
    fn render_terminator_unreachable() {
        let term = LiftedTerminator::Unreachable;
        let s = render_to_string(|w| render_terminator(w, &term));
        assert_eq!(s, "unreachable");
    }

    #[test]
    fn render_value_def_block_param() {
        let value = LiftedValue {
            def: LiftedValueDef::BlockParam {
                block: BlockId::from_index(0),
                index: 2,
            },
            types: vec![LiftedType::I64],
        };
        let s = render_to_string(|w| render_value_def(w, ValueId::from_index(5), &value));
        assert_eq!(s, "v5 = block_param[2]");
    }

    #[test]
    fn render_value_def_alias() {
        let value = LiftedValue {
            def: LiftedValueDef::Alias(ValueId::from_index(7)),
            types: vec![LiftedType::I64],
        };
        let s = render_to_string(|w| render_value_def(w, ValueId::from_index(3), &value));
        assert_eq!(s, "v3 = alias v7");
    }

    #[test]
    fn render_value_def_pick_output() {
        let value = LiftedValue {
            def: LiftedValueDef::PickOutput {
                from: ValueId::from_index(7),
                index: 1,
            },
            types: vec![LiftedType::I32],
        };
        let s = render_to_string(|w| render_value_def(w, ValueId::from_index(8), &value));
        assert_eq!(s, "v8 = pick1 v7");
    }

    #[test]
    fn render_block_target_with_no_args() {
        let target = BlockTarget {
            block: BlockId::from_index(4),
            args: Vec::new(),
        };
        let s = render_to_string(|w| render_block_target(w, &target));
        assert_eq!(s, "bb4");
    }

    #[test]
    fn render_block_target_with_args() {
        let target = BlockTarget {
            block: BlockId::from_index(4),
            args: vec![ValueId::from_index(0), ValueId::from_index(1)],
        };
        let s = render_to_string(|w| render_block_target(w, &target));
        assert_eq!(s, "bb4(v0, v1)");
    }
}
