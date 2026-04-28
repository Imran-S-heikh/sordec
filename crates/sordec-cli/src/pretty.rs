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
    BlockTarget, ExportKind, Import, ImportKind, LiftedBlock, LiftedFunction, LiftedIr,
    LiftedTerminator, LiftedType, LiftedValue, LiftedValueDef, WasmFacts,
};
use sordec_passes::host_calls;
use waffle::entity::EntityRef as _;

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

    let ctx = RenderContext::from_facts(&lifted.facts);
    for (i, func) in lifted.functions.iter().enumerate() {
        if i > 0 {
            writeln!(out)?;
        }
        render_function(out, func, &ctx)?;
    }
    Ok(())
}

/// Module-wide rendering context threaded through every helper. Holds
/// everything an inner formatter might need to disambiguate a value
/// reference: the import table for resolving `Call` operators, the
/// export table for annotating function headers, and the count of
/// imported functions for deciding "import vs local" in a single
/// `Call { function_index }`.
struct RenderContext<'a> {
    /// Original WASM imports — used to resolve `Call` operators that
    /// target imported (host) functions.
    imports: &'a [Import],
    /// Map from local function index to the export name (if exported).
    /// Built once per render from `WasmFacts.exports`.
    exports_by_local_idx: BTreeMap<u32, &'a str>,
    /// Number of imports of kind `Func`. Used to split the WASM
    /// function index space into "import" (`< imported_func_count`)
    /// vs "local" (`>= imported_func_count`).
    imported_func_count: u32,
}

impl<'a> RenderContext<'a> {
    fn from_facts(facts: &'a WasmFacts) -> Self {
        let imported_func_count = facts
            .imports
            .iter()
            .filter(|i| matches!(i.kind, ImportKind::Func(_)))
            .count() as u32;

        let exports_by_local_idx = facts
            .exports
            .iter()
            .filter_map(|e| match e.kind {
                ExportKind::Func => e
                    .index
                    .checked_sub(imported_func_count)
                    .map(|local| (local, e.name.as_str())),
                _ => None,
            })
            .collect();

        Self {
            imports: &facts.imports,
            exports_by_local_idx,
            imported_func_count,
        }
    }
}

// ---------------------------------------------------------------------
// Internal helpers — one per render concern
// ---------------------------------------------------------------------

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
    ctx: &RenderContext<'_>,
) -> io::Result<()> {
    let id_idx = func.id.index();
    if let Some(name) = ctx.exports_by_local_idx.get(&id_idx) {
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
        render_block(out, block_id, block, func, ctx)?;
    }

    writeln!(out, "}}")?;
    Ok(())
}

fn render_block(
    out: &mut impl Write,
    block_id: BlockId,
    block: &LiftedBlock,
    func: &LiftedFunction,
    ctx: &RenderContext<'_>,
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
        render_value_def(out, value_id, value, ctx)?;
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
    ctx: &RenderContext<'_>,
) -> io::Result<()> {
    write!(out, "v{} = ", value_id.index())?;
    match &value.def {
        LiftedValueDef::Operator { op, args } => {
            // Special-case the `Call` operator so we render
            // `host:l:put_contract_data(...)` for imported (host)
            // calls and `call func_<n>(...)` for local-function
            // calls, instead of the noisy `Call { function_index:
            // funcN }` Debug fallback. Other operators stay on
            // `WasmOp::Display`'s Debug fallback for v0.
            if let waffle::Operator::Call { function_index } = op.0 {
                render_call_target(out, function_index, ctx)?;
                render_arg_list(out, args)?;
            } else {
                write!(out, "{op}")?;
                render_arg_list(out, args)?;
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

/// Render the target portion of a direct `Call` (i.e. before the args).
///
/// - Imported function (waffle index `< imported_func_count`): looks
///   up the import in `WasmFacts.imports` and tries to resolve a
///   friendly name from the Soroban host-call catalog. Output:
///   `host:<module>:<friendly>` when known, `host:<module>:<raw>`
///   otherwise.
/// - Local function: `call func_<local_idx>`.
/// - Defensive fallback for an out-of-range function index (which
///   should never occur on valid WASM): `call func_<idx>` using the
///   raw waffle index.
fn render_call_target(
    out: &mut impl Write,
    function_index: waffle::Func,
    ctx: &RenderContext<'_>,
) -> io::Result<()> {
    let idx = function_index.index();
    let imported_count = ctx.imported_func_count as usize;

    if idx < imported_count {
        // Imported (host) function call.
        if let Some(import) = ctx.imports.get(idx) {
            match host_calls::resolve(&import.module, &import.name) {
                Some(hc) => write!(out, "host:{}:{}", hc.module, hc.friendly_name),
                None => write!(out, "host:{}:{}", import.module, import.name),
            }
        } else {
            // Out-of-range — defensive; should not happen on valid
            // WASM where `imported_func_count == imports.len()`.
            write!(out, "call func_{idx}")
        }
    } else {
        // Local function call.
        let local_idx = idx - imported_count;
        write!(out, "call func_{local_idx}")
    }
}

/// Render an arg list `(v0, v1, v2)` or empty (no parens) when there
/// are no args. Shared between the Call branch and the default
/// operator branch above.
fn render_arg_list(out: &mut impl Write, args: &[ValueId]) -> io::Result<()> {
    if args.is_empty() {
        return Ok(());
    }
    write!(out, "(")?;
    for (i, arg) in args.iter().enumerate() {
        if i > 0 {
            write!(out, ", ")?;
        }
        write!(out, "v{}", arg.index())?;
    }
    write!(out, ")")?;
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

    /// Build a render context with no imports or exports — suitable
    /// for tests that don't exercise the Call-rendering branch.
    fn empty_context() -> RenderContext<'static> {
        RenderContext {
            imports: &[],
            exports_by_local_idx: BTreeMap::new(),
            imported_func_count: 0,
        }
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
        let ctx = empty_context();
        let s = render_to_string(|w| render_value_def(w, ValueId::from_index(5), &value, &ctx));
        assert_eq!(s, "v5 = block_param[2]");
    }

    #[test]
    fn render_value_def_alias() {
        let value = LiftedValue {
            def: LiftedValueDef::Alias(ValueId::from_index(7)),
            types: vec![LiftedType::I64],
        };
        let ctx = empty_context();
        let s = render_to_string(|w| render_value_def(w, ValueId::from_index(3), &value, &ctx));
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
        let ctx = empty_context();
        let s = render_to_string(|w| render_value_def(w, ValueId::from_index(8), &value, &ctx));
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

    // --- Call rendering: imported (host) functions and local functions ---

    /// Build a single-import context: function index 0 maps to the
    /// supplied (module, name) host import. Useful for testing the
    /// imported-call rendering path.
    fn ctx_with_one_import(module: &str, name: &str) -> RenderContext<'static> {
        // Box::leak here is a test-only convenience to satisfy the
        // 'a == 'static lifetime; production callers always pass a
        // borrow of an owned `WasmFacts`.
        let imports = Box::leak(Box::new(vec![sordec_ir::Import {
            index: 0,
            module: module.to_string(),
            name: name.to_string(),
            kind: sordec_ir::ImportKind::Func(0),
        }]));
        RenderContext {
            imports: imports.as_slice(),
            exports_by_local_idx: BTreeMap::new(),
            imported_func_count: 1,
        }
    }

    #[test]
    fn render_value_def_call_to_imported_function_uses_friendly_name() {
        // Function index 0 is an import. The context has one import
        // mapped to (module="l", name="_") which the catalog resolves
        // to `put_contract_data`. Output should be the friendly form.
        let value = LiftedValue {
            def: LiftedValueDef::Operator {
                op: sordec_ir::WasmOp(waffle::Operator::Call {
                    function_index: waffle::Func::new(0),
                }),
                args: vec![ValueId::from_index(2), ValueId::from_index(3)],
            },
            types: vec![LiftedType::I64],
        };

        let ctx = ctx_with_one_import("l", "_");
        let s = render_to_string(|w| render_value_def(w, ValueId::from_index(7), &value, &ctx));
        assert_eq!(s, "v7 = host:l:put_contract_data(v2, v3)");
    }

    #[test]
    fn render_value_def_call_to_unknown_imported_function_uses_raw_name() {
        // Function index 0 is an import, but the (module, name) pair
        // isn't in our catalog. Should fall back to the raw form
        // `host:<module>:<raw>(...)`.
        let value = LiftedValue {
            def: LiftedValueDef::Operator {
                op: sordec_ir::WasmOp(waffle::Operator::Call {
                    function_index: waffle::Func::new(0),
                }),
                args: vec![],
            },
            types: vec![LiftedType::I64],
        };

        let ctx = ctx_with_one_import("zz", "?");
        let s = render_to_string(|w| render_value_def(w, ValueId::from_index(0), &value, &ctx));
        assert_eq!(s, "v0 = host:zz:?");
    }

    #[test]
    fn render_value_def_call_to_local_function_renders_as_call_func() {
        // Function index 5 is past the imported_func_count of 0, so
        // it's a local function — local index = 5 - 0 = 5.
        let value = LiftedValue {
            def: LiftedValueDef::Operator {
                op: sordec_ir::WasmOp(waffle::Operator::Call {
                    function_index: waffle::Func::new(5),
                }),
                args: vec![ValueId::from_index(1)],
            },
            types: vec![LiftedType::I64],
        };

        let ctx = empty_context();
        let s = render_to_string(|w| render_value_def(w, ValueId::from_index(8), &value, &ctx));
        assert_eq!(s, "v8 = call func_5(v1)");
    }

    #[test]
    fn render_value_def_call_to_local_function_subtracts_imported_count() {
        // Function index 3 with imported_func_count=2 ⇒ local idx=1.
        let value = LiftedValue {
            def: LiftedValueDef::Operator {
                op: sordec_ir::WasmOp(waffle::Operator::Call {
                    function_index: waffle::Func::new(3),
                }),
                args: vec![],
            },
            types: vec![LiftedType::I64],
        };
        let imports = Box::leak(Box::new(vec![
            sordec_ir::Import {
                index: 0,
                module: "l".to_string(),
                name: "_".to_string(),
                kind: sordec_ir::ImportKind::Func(0),
            },
            sordec_ir::Import {
                index: 1,
                module: "a".to_string(),
                name: "0".to_string(),
                kind: sordec_ir::ImportKind::Func(0),
            },
        ]));
        let ctx = RenderContext {
            imports: imports.as_slice(),
            exports_by_local_idx: BTreeMap::new(),
            imported_func_count: 2,
        };

        let s = render_to_string(|w| render_value_def(w, ValueId::from_index(0), &value, &ctx));
        assert_eq!(s, "v0 = call func_1");
    }
}
