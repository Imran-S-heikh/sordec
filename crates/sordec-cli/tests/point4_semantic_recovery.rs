//! Point 4 deliverable tests: user-visible baseline semantic recovery.
//!
//! The Phase 1 semantic surface is host-call recovery: `dump-ir` renders
//! friendly Soroban host names and `coverage` scores recognized versus
//! unrecognized host calls.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use assert_cmd::Command;
use predicates::prelude::*;

const EMPTY_WASM_MODULE: &[u8] = b"\0asm\x01\0\0\0";

fn leb_u32(mut value: u32) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    out
}

fn wasm_name(name: &str) -> Vec<u8> {
    let mut out = leb_u32(name.len() as u32);
    out.extend_from_slice(name.as_bytes());
    out
}

fn section(id: u8, payload: Vec<u8>) -> Vec<u8> {
    let mut out = vec![id];
    out.extend(leb_u32(payload.len() as u32));
    out.extend(payload);
    out
}

fn vec_payload(items: Vec<Vec<u8>>) -> Vec<u8> {
    let mut out = leb_u32(items.len() as u32);
    for item in items {
        out.extend(item);
    }
    out
}

fn module(sections: Vec<Vec<u8>>) -> Vec<u8> {
    let mut out = EMPTY_WASM_MODULE.to_vec();
    for section in sections {
        out.extend(section);
    }
    out
}

fn type_section() -> Vec<u8> {
    // One function type: [] -> [].
    section(1, vec_payload(vec![vec![0x60, 0x00, 0x00]]))
}

fn import_func(module_name: &str, name: &str, type_index: u32) -> Vec<u8> {
    let mut out = wasm_name(module_name);
    out.extend(wasm_name(name));
    out.push(0x00);
    out.extend(leb_u32(type_index));
    out
}

fn import_section(entries: Vec<Vec<u8>>) -> Vec<u8> {
    section(2, vec_payload(entries))
}

fn function_section(local_function_count: u32) -> Vec<u8> {
    let mut out = leb_u32(local_function_count);
    for _ in 0..local_function_count {
        out.extend(leb_u32(0));
    }
    section(3, out)
}

fn export_section(import_count: u32) -> Vec<u8> {
    let mut entry = wasm_name("run");
    entry.push(0x00);
    entry.extend(leb_u32(import_count));
    section(7, vec_payload(vec![entry]))
}

fn func_body(call_indices: &[u32]) -> Vec<u8> {
    let mut body = vec![0x00];
    for index in call_indices {
        body.push(0x10);
        body.extend(leb_u32(*index));
    }
    body.push(0x0b);

    let mut out = leb_u32(body.len() as u32);
    out.extend(body);
    out
}

fn code_section(call_indices: &[u32]) -> Vec<u8> {
    section(10, vec_payload(vec![func_body(call_indices)]))
}

fn host_call_wasm(imports: &[(&str, &str)], call_indices: &[u32]) -> Vec<u8> {
    module(vec![
        type_section(),
        import_section(
            imports
                .iter()
                .map(|(module, name)| import_func(module, name, 0))
                .collect(),
        ),
        function_section(1),
        export_section(imports.len() as u32),
        code_section(call_indices),
    ])
}

fn no_host_call_wasm() -> Vec<u8> {
    module(vec![
        type_section(),
        function_section(1),
        export_section(0),
        code_section(&[]),
    ])
}

fn write_temp_wasm(label: &str, wasm: &[u8]) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "sordec-point4-{label}-{}-{nanos}.wasm",
        std::process::id()
    ));
    std::fs::write(&path, wasm).expect("write temporary synthetic wasm");
    path
}

fn mixed_known_unknown_wasm() -> Vec<u8> {
    host_call_wasm(&[("l", "_"), ("a", "0"), ("zz", "?")], &[0, 1, 1, 2, 2, 3])
}

fn all_core_module_examples_wasm() -> Vec<u8> {
    let imports = [
        ("x", "_"),
        ("i", "_"),
        ("m", "_"),
        ("v", "_"),
        ("l", "_"),
        ("d", "_"),
        ("b", "_"),
        ("c", "_"),
        ("a", "0"),
        ("t", "_"),
        ("p", "_"),
    ];
    let calls: Vec<u32> = (0..imports.len() as u32).collect();
    host_call_wasm(&imports, &calls)
}

#[test]
fn dump_ir_renders_known_host_calls_as_friendly_names_and_unknown_as_raw() {
    let wasm = mixed_known_unknown_wasm();
    let path = write_temp_wasm("mixed-dump-ir", &wasm);

    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-ir"])
        .arg(&path)
        .assert()
        .success()
        .stdout(predicate::str::contains("host:l:put_contract_data"))
        .stdout(predicate::str::contains("host:a:require_auth"))
        .stdout(predicate::str::contains("host:zz:?"))
        .stdout(predicate::str::contains("call func_0"))
        .stderr(predicate::str::is_empty());

    let _ = std::fs::remove_file(path);
}

#[test]
fn dump_ir_renders_friendly_names_for_every_core_host_module_example() {
    let wasm = all_core_module_examples_wasm();
    let path = write_temp_wasm("all-modules-dump-ir", &wasm);

    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-ir"])
        .arg(&path)
        .assert()
        .success()
        .stdout(predicate::str::contains("host:x:log_from_linear_memory"))
        .stdout(predicate::str::contains("host:i:obj_from_u64"))
        .stdout(predicate::str::contains("host:m:map_new"))
        .stdout(predicate::str::contains("host:v:vec_new"))
        .stdout(predicate::str::contains("host:l:put_contract_data"))
        .stdout(predicate::str::contains("host:d:call"))
        .stdout(predicate::str::contains("host:b:serialize_to_bytes"))
        .stdout(predicate::str::contains("host:c:compute_hash_sha256"))
        .stdout(predicate::str::contains("host:a:require_auth"))
        .stdout(predicate::str::contains("host:t:dummy0"))
        .stdout(predicate::str::contains("host:p:prng_reseed"))
        .stderr(predicate::str::is_empty());

    let _ = std::fs::remove_file(path);
}

#[test]
fn coverage_json_scores_mixed_known_unknown_host_calls() {
    let wasm = mixed_known_unknown_wasm();
    let path = write_temp_wasm("mixed-coverage-json", &wasm);

    let out = Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["coverage", "--json"])
        .arg(&path)
        .assert()
        .success()
        .stderr(predicate::str::is_empty())
        .get_output()
        .stdout
        .clone();

    let v: serde_json::Value = serde_json::from_slice(&out).expect("coverage JSON parses");
    assert_eq!(v["host_calls"]["total"], 5);
    assert_eq!(v["host_calls"]["recognized"], 3);
    assert_eq!(v["host_calls"]["ratio"].as_f64(), Some(0.6));
    assert_eq!(v["host_calls"]["unrecognized"][0]["module"], "zz");
    assert_eq!(v["host_calls"]["unrecognized"][0]["name"], "?");
    assert_eq!(v["host_calls"]["unrecognized"][0]["count"], 2);
    assert_eq!(v["operators"]["call_to_import"], 5);
    assert_eq!(v["operators"]["call_to_local"], 1);

    let _ = std::fs::remove_file(path);
}

#[test]
fn coverage_json_scores_all_core_module_examples_as_fully_recognized() {
    let wasm = all_core_module_examples_wasm();
    let path = write_temp_wasm("all-modules-coverage-json", &wasm);

    let out = Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["coverage", "--json"])
        .arg(&path)
        .assert()
        .success()
        .stderr(predicate::str::is_empty())
        .get_output()
        .stdout
        .clone();

    let v: serde_json::Value = serde_json::from_slice(&out).expect("coverage JSON parses");
    assert_eq!(v["host_calls"]["total"], 11);
    assert_eq!(v["host_calls"]["recognized"], 11);
    assert_eq!(v["host_calls"]["ratio"].as_f64(), Some(1.0));
    assert!(
        v["host_calls"]["unrecognized"]
            .as_array()
            .expect("unrecognized is an array")
            .is_empty()
    );

    let _ = std::fs::remove_file(path);
}

#[test]
fn coverage_text_lists_unrecognized_host_calls_and_counts() {
    let wasm = mixed_known_unknown_wasm();
    let path = write_temp_wasm("mixed-coverage-text", &wasm);

    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["coverage"])
        .arg(&path)
        .assert()
        .success()
        .stdout(predicate::str::contains("3 / 5 recognized"))
        .stdout(predicate::str::contains("unrecognized:"))
        .stdout(predicate::str::contains("host:zz:? (\u{00d7}2)"))
        .stderr(predicate::str::is_empty());

    let _ = std::fs::remove_file(path);
}

#[test]
fn coverage_json_uses_null_ratio_when_there_are_no_host_calls() {
    let wasm = no_host_call_wasm();
    let path = write_temp_wasm("no-host-calls", &wasm);

    let out = Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["coverage", "--json"])
        .arg(&path)
        .assert()
        .success()
        .stderr(predicate::str::is_empty())
        .get_output()
        .stdout
        .clone();

    let v: serde_json::Value = serde_json::from_slice(&out).expect("coverage JSON parses");
    assert_eq!(v["host_calls"]["total"], 0);
    assert!(v["host_calls"]["ratio"].is_null());
    assert_eq!(v["operators"]["call_to_import"], 0);
    assert_eq!(v["operators"]["call_to_local"], 0);

    let _ = std::fs::remove_file(path);
}
