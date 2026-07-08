//! End-to-end tests for `sordec dump-hir`.
//!
//! Asserts structural anchors of the HighIr rendering — function
//! scaffolding, the unstructured-region banner, provenance notes, and
//! host-call rendering. Exact expression text is not snapshotted (the
//! lowering will grow as recognizers land).

use assert_cmd::Command;
use predicates::prelude::*;

const HELLO_ADD: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/hello-add/hello-add.wasm"
);

const TOKEN_V23: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/token-v23/token-v23.wasm"
);

#[test]
fn dump_hir_on_hello_add_emits_high_ir_scaffolding() {
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-hir", HELLO_ADD])
        .assert()
        .success()
        // Function scaffolding and the (mechanically-lowered) region
        // banner must appear.
        .stdout(predicate::str::contains("function func_"))
        .stdout(predicate::str::contains("region: unstructured"))
        // Every binding carries a provenance note from the lowering.
        .stdout(predicate::str::contains(";; DataFlow:"))
        // hello-add is clean — no diagnostics.
        .stderr(predicate::str::is_empty());
}

#[test]
fn dump_hir_on_hello_add_names_the_exported_function() {
    // hello-add exports `add`; the lowering recovers the name onto the
    // HighFunction and the renderer prints it.
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-hir", HELLO_ADD])
        .assert()
        .success()
        .stdout(predicate::str::contains("[exported as \"add\"]"));
}

#[test]
fn dump_hir_raw_renders_unrecognized_host_calls() {
    // Under `--raw` (no recognizer pipeline), host calls render as
    // `host:<module>:<name>` via SemanticOp::Unknown. The storage-write
    // primitive (`l._` = put_contract_data) is universal. On the default
    // path this is recognized as `storage_set` — see
    // `dump_hir_raw_flag_preserves_raw_storage_calls`.
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-hir", "--raw", TOKEN_V23])
        .assert()
        .success()
        .stdout(predicate::str::contains("host:l:put_contract_data"))
        .stderr(predicate::str::is_empty());
}

#[test]
fn dump_hir_on_hello_add_recognizes_val_ops() {
    // The default path runs the C1 Val-encoding recognizer. hello-add's
    // dispatcher + `add` exercise all four pattern families: small
    // encode, decode, tag check, and object conversion.
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-hir", HELLO_ADD])
        .assert()
        .success()
        .stdout(predicate::str::contains("val_encode<u64>"))
        .stdout(predicate::str::contains("has_tag("))
        .stdout(predicate::str::contains("obj_from_u64"))
        // Provenance for a recognized bit-pattern is SdkPattern.
        .stdout(predicate::str::contains(";; SdkPattern: val-encode"))
        .stderr(predicate::str::is_empty());
}

#[test]
fn dump_hir_raw_flag_shows_unrecognized_lowering() {
    // `--raw` skips the recognizer pipeline: the encode chain must show
    // as raw `shl` / bit-or ops, and NOT as a recognized `val_encode`.
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-hir", "--raw", HELLO_ADD])
        .assert()
        .success()
        .stdout(predicate::str::contains("shl "))
        .stdout(predicate::str::contains("val_encode").not())
        .stdout(predicate::str::contains("has_tag").not())
        .stderr(predicate::str::is_empty());
}

#[test]
fn dump_hir_on_token_v23_recognizes_i128_object_conversions() {
    // token-v23's i128 codec helpers use the object-form conversions;
    // C1 recognizes them by host-function identity (Known certainty).
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-hir", TOKEN_V23])
        .assert()
        .success()
        .stdout(predicate::str::contains("obj_from_i128_pieces"))
        .stdout(predicate::str::contains("obj_to_i128_hi64"))
        .stdout(predicate::str::contains(";; HostFunctionAbi:"))
        .stderr(predicate::str::is_empty());
}

const TIMELOCK: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/timelock/timelock.wasm"
);

#[test]
fn dump_hir_on_token_v23_resolves_all_three_storage_tiers() {
    // The C2 storage recognizer resolves the durability constant into a
    // named tier. token-v23's source uses all three: instance (admin),
    // persistent (balances), temporary (allowances) — the exact bug the
    // legacy hardcoded-persistent decompiler got wrong.
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-hir", TOKEN_V23])
        .assert()
        .success()
        .stdout(predicate::str::contains("storage_get<instance>"))
        .stdout(predicate::str::contains("storage_get<persistent>"))
        .stdout(predicate::str::contains("storage_get<temporary>"))
        // Provenance records the tier evidence.
        .stdout(predicate::str::contains("durability const"))
        .stderr(predicate::str::is_empty());
}

#[test]
fn dump_hir_on_token_v23_shows_honest_unknown_tier() {
    // rustc hoists some storage ops into helpers that take the tier as a
    // parameter; those sites resolve to an honest `<?>` rather than a
    // guess. This locks the no-guessing behavior.
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-hir", TOKEN_V23])
        .assert()
        .success()
        .stdout(predicate::str::contains("storage_has<?>"))
        .stdout(predicate::str::contains("tier=unknown"));
}

#[test]
fn dump_hir_on_timelock_recognizes_storage() {
    // timelock uses instance storage (has(Init), balance get/set).
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-hir", TIMELOCK])
        .assert()
        .success()
        .stdout(predicate::str::contains("storage_"))
        .stderr(predicate::str::is_empty());
}

#[test]
fn dump_hir_raw_flag_preserves_raw_storage_calls() {
    // `--raw` skips recognition: storage calls show as raw host imports,
    // not as recognized `storage_*` ops.
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-hir", "--raw", TOKEN_V23])
        .assert()
        .success()
        .stdout(predicate::str::contains("host:l:put_contract_data"))
        .stdout(predicate::str::contains("storage_set").not());
}

const DEX: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/dex-liquidity-pool/dex-liquidity-pool.wasm"
);

#[test]
fn dump_hir_recognizes_require_auth_across_corpus() {
    // require_auth is the universal auth primitive — every fixture has
    // it. C4 turns the opaque host call into a first-class semantic op.
    for wasm in [TOKEN_V23, TIMELOCK, DEX] {
        Command::cargo_bin("sordec")
            .expect("sordec binary builds")
            .args(["dump-hir", wasm])
            .assert()
            .success()
            .stdout(predicate::str::contains("require_auth("));
    }
}

#[test]
fn dump_hir_on_token_v23_recognizes_muxed_address_conversions() {
    // token-v23's `transfer` takes a MuxedAddress and decomposes it.
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-hir", TOKEN_V23])
        .assert()
        .success()
        .stdout(predicate::str::contains("get_address_from_muxed_address"))
        .stdout(predicate::str::contains("get_id_from_muxed_address"))
        .stderr(predicate::str::is_empty());
}

#[test]
fn dump_hir_raw_flag_preserves_raw_auth_calls() {
    // `--raw` skips recognition: auth calls show as raw host imports,
    // and the recognizer's provenance note is absent. (A plain
    // `require_auth(` substring check won't do — the raw form
    // `host:a:require_auth(...)` contains it.)
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-hir", "--raw", TOKEN_V23])
        .assert()
        .success()
        .stdout(predicate::str::contains("host:a:require_auth"))
        .stdout(predicate::str::contains("HostFunctionAbi: auth require_auth").not());
}

#[test]
fn dump_hir_with_missing_file_exits_three() {
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-hir", "/tmp/sordec-dump-hir-does-not-exist.wasm"])
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains("could not read"));
}

#[test]
fn dump_hir_with_garbage_input_exits_one() {
    let tmp = std::env::temp_dir().join("sordec-test-dump-hir-garbage.wasm");
    std::fs::write(&tmp, b"definitely not WASM").expect("write tmp");

    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-hir"])
        .arg(&tmp)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("parse failed"));

    let _ = std::fs::remove_file(&tmp);
}
