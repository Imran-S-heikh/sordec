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
fn dump_hir_on_token_v23_recognizes_events_and_ledger() {
    // The C15 context recognizer turns contract_event into publish_event
    // and the ledger accessors into named calls.
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-hir", TOKEN_V23])
        .assert()
        .success()
        .stdout(predicate::str::contains("publish_event("))
        .stdout(predicate::str::contains("get_ledger_sequence()"))
        .stderr(predicate::str::is_empty());
}

#[test]
fn dump_hir_on_timelock_recognizes_context() {
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-hir", TIMELOCK])
        .assert()
        .success()
        .stdout(predicate::str::contains("get_current_contract_address()"))
        .stdout(predicate::str::contains("get_ledger_timestamp()"))
        .stderr(predicate::str::is_empty());
}

#[test]
fn dump_hir_on_dex_recognizes_val_compare() {
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-hir", DEX])
        .assert()
        .success()
        .stdout(predicate::str::contains("get_current_contract_address()"))
        .stdout(predicate::str::contains("val_cmp("));
}

#[test]
fn dump_hir_clears_all_x_module_calls_on_default_path() {
    // After C15, no raw host:x:* call survives the default pipeline on
    // any corpus fixture (none use the deferred log_from_linear_memory).
    for wasm in [TOKEN_V23, TIMELOCK, DEX] {
        Command::cargo_bin("sordec")
            .expect("sordec binary builds")
            .args(["dump-hir", wasm])
            .assert()
            .success()
            .stdout(predicate::str::contains("host:x:").not());
    }
}

#[test]
fn dump_hir_raw_flag_preserves_raw_context_calls() {
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-hir", "--raw", TOKEN_V23])
        .assert()
        .success()
        .stdout(predicate::str::contains("host:x:contract_event"))
        .stdout(predicate::str::contains("publish_event(").not());
}

#[test]
fn dump_hir_recognizes_linear_memory_constructors() {
    // The linear-memory pass turns symbol_new/vec_new/map_new_from_linear_memory
    // into named constructor ops. token-v23 exercises all three.
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-hir", TOKEN_V23])
        .assert()
        .success()
        .stdout(predicate::str::contains("symbol_new("))
        .stdout(predicate::str::contains("vec_new("))
        .stdout(predicate::str::contains("map_new("))
        .stderr(predicate::str::is_empty());
}

#[test]
fn dump_hir_recognizes_symbol_new_across_corpus() {
    // Every contract that builds a >9-char symbol uses
    // symbol_new_from_linear_memory; the pass names it in all of them.
    for wasm in [TOKEN_V23, TIMELOCK, DEX] {
        Command::cargo_bin("sordec")
            .expect("sordec binary builds")
            .args(["dump-hir", wasm])
            .assert()
            .success()
            .stdout(predicate::str::contains("symbol_new("));
    }
}

#[test]
fn dump_hir_clears_raw_constructor_calls_on_default_path() {
    // After recognition, the five `*_new_from_linear_memory` host calls no
    // longer appear as raw `host:` imports on the default path. (Other
    // b/v/m ops — vec_get, map_unpack, symbol_index — are a separate
    // recognizer's scope and may still appear.)
    for wasm in [TOKEN_V23, TIMELOCK, DEX] {
        Command::cargo_bin("sordec")
            .expect("sordec binary builds")
            .args(["dump-hir", wasm])
            .assert()
            .success()
            .stdout(predicate::str::contains("host:b:symbol_new_from_linear_memory").not())
            .stdout(predicate::str::contains("host:v:vec_new_from_linear_memory").not())
            .stdout(predicate::str::contains("host:m:map_new_from_linear_memory").not());
    }
}

#[test]
fn dump_hir_raw_flag_preserves_raw_constructor_calls() {
    // `--raw` skips recognition: the constructor shows as its raw host
    // import, not the recognized `symbol_new(` form.
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-hir", "--raw", TOKEN_V23])
        .assert()
        .success()
        .stdout(predicate::str::contains("host:b:symbol_new_from_linear_memory"));
}

#[test]
fn dump_hir_on_timelock_recognizes_collections_ops() {
    // timelock is the fixture exercising the vec accessors, symbol
    // dispatch, and map unpack — the collections recognizer names all of
    // them.
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-hir", TIMELOCK])
        .assert()
        .success()
        .stdout(predicate::str::contains("vec_len("))
        .stdout(predicate::str::contains("vec_get("))
        .stdout(predicate::str::contains("vec_first_index_of("))
        .stdout(predicate::str::contains("symbol_index_in_linear_memory("))
        .stdout(predicate::str::contains("map_unpack_to_linear_memory("))
        .stderr(predicate::str::is_empty());
}

#[test]
fn dump_hir_on_token_v23_recognizes_map_unpack() {
    // Every token fixture decodes its metadata map via map_unpack.
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-hir", TOKEN_V23])
        .assert()
        .success()
        .stdout(predicate::str::contains("map_unpack_to_linear_memory("));
}

#[test]
fn dump_hir_clears_all_collections_host_calls_on_default_path() {
    // After the collections pass, no raw m/v/b host call survives the
    // default pipeline on any corpus fixture.
    for wasm in [TOKEN_V23, TIMELOCK, DEX] {
        Command::cargo_bin("sordec")
            .expect("sordec binary builds")
            .args(["dump-hir", wasm])
            .assert()
            .success()
            .stdout(predicate::str::contains("host:m:").not())
            .stdout(predicate::str::contains("host:v:").not())
            .stdout(predicate::str::contains("host:b:").not());
    }
}

#[test]
fn dump_hir_raw_flag_preserves_raw_collections_calls() {
    // `--raw` skips recognition. (A plain `vec_len(` substring check
    // won't do for the negative — the raw form `host:v:vec_len(...)`
    // contains it — so assert the absence of the recognition-only
    // provenance note instead.)
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-hir", "--raw", TIMELOCK])
        .assert()
        .success()
        .stdout(predicate::str::contains("host:v:vec_len"))
        .stdout(predicate::str::contains("collections vec_len").not());
}

#[test]
fn dump_hir_recognizes_cross_contract_calls() {
    // dex and timelock both drive token::Client calls, which compile to
    // the d-module `call` host import.
    for wasm in [DEX, TIMELOCK] {
        Command::cargo_bin("sordec")
            .expect("sordec binary builds")
            .args(["dump-hir", wasm])
            .assert()
            .success()
            .stdout(predicate::str::contains("invoke_contract("));
    }
}

#[test]
fn dump_hir_names_storage_key_through_return() {
    // The const-prop return arm reaches the METADATA DataKey symbol,
    // which lives in a constant-returning helper and flows to a storage
    // op through the call result — the measured return-propagation win.
    for wasm in [TOKEN_V22, TOKEN_V23, TOKEN_V23_STRIPPED] {
        Command::cargo_bin("sordec")
            .expect("sordec binary builds")
            .args(["dump-hir", wasm])
            .assert()
            .success()
            .stdout(predicate::str::contains("symbol!(\"METADATA\")"))
            .stdout(predicate::str::contains("const-prop key symbol \"METADATA\""));
    }
}

#[test]
fn dump_hir_names_cross_contract_callees() {
    // The const-prop engine decodes the tag-14 callee symbols in the
    // ABI-typed Symbol position: dex drives token.transfer and
    // token.balance, timelock drives token.transfer. (Measured corpus
    // wins — all three cross-contract calls in the corpus are named.)
    // The named callee is visible in the invoke rendering; the
    // displayed provenance note is now the client-call pass's (it
    // touches the binding last — see
    // `dump_hir_types_cross_contract_client_calls`), so this test
    // asserts the rendering, not the note.
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-hir", DEX])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"transfer\","))
        .stdout(predicate::str::contains("\"balance\","));

    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-hir", TIMELOCK])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"transfer\","));
}

#[test]
fn dump_hir_raw_flag_preserves_raw_cross_contract_calls() {
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-hir", "--raw", DEX])
        .assert()
        .success()
        .stdout(predicate::str::contains("host:d:call"))
        .stdout(predicate::str::contains("invoke_contract(").not());
}

#[test]
fn dump_hir_types_cross_contract_client_calls() {
    // W2/D2.4: invoke ops are typed against the SEP-41 interface by
    // callee name + arity. dex `balance` is a single-block
    // construction, so its element list is fully recovered; the
    // multi-arg `transfer` sites build the vec via an out-of-block
    // copy loop, so they carry arity + interface but keep the raw
    // handle (elements honestly unproven).
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-hir", DEX])
        .assert()
        .success()
        // Full-element tier (balance/1).
        .stdout(predicate::str::contains("\"balance\", [v"))
        .stdout(predicate::str::contains(
            "sep41 balance(id) (callee+arity match, structural)",
        ))
        // Arity tier (transfer/3).
        .stdout(predicate::str::contains("\"transfer\", v"))
        .stdout(predicate::str::contains("3 args"))
        .stdout(predicate::str::contains(
            "sep41 transfer(from, to, amount)",
        ));

    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-hir", TIMELOCK])
        .assert()
        .success()
        .stdout(predicate::str::contains("3 args"))
        .stdout(predicate::str::contains(
            "sep41 transfer(from, to, amount)",
        ));
}

#[test]
fn dump_hir_raw_flag_shows_no_client_call_typing() {
    // Under `--raw` neither the arity/element tiers nor the interface
    // match appear (no recognizer pipeline runs).
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-hir", "--raw", DEX])
        .assert()
        .success()
        .stdout(predicate::str::contains("client-call").not())
        .stdout(predicate::str::contains("sep41").not());
}

const TOKEN_V22: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/token-v22/token-v22.wasm"
);

const TOKEN_V23_STRIPPED: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/token-v23-stripped/token-v23-stripped.wasm"
);

#[test]
fn dump_hir_names_enum_storage_keys_on_both_tokens() {
    // The enum-key recognizer (W1/D2.3 substrate): DataKey variants
    // built by the shared constructor helper are named on the storage
    // ops, across all three channels the token exercises — unit
    // variant (Admin, instance), one-payload (Balance, persistent),
    // two-payload (Allowance, temporary).
    for wasm in [TOKEN_V22, TOKEN_V23] {
        Command::cargo_bin("sordec")
            .expect("sordec binary builds")
            .args(["dump-hir", wasm])
            .assert()
            .success()
            .stdout(predicate::str::contains("storage_get<instance>(v30: DataKey::Admin)"))
            .stdout(predicate::str::contains(": DataKey::Balance(v"))
            .stdout(predicate::str::contains(": DataKey::Allowance(v"))
            // The provenance note records the evidence chain, including
            // the decl-order mapping assumption.
            .stdout(predicate::str::contains(
                "enum-key DataKey::Admin (disc 3 via frame slot, spec union matched, decl-order mapping)",
            ));
    }
}

#[test]
fn dump_hir_names_enum_storage_keys_by_value_on_timelock_and_dex() {
    // All-unit DataKey enums pass the discriminant by value; the
    // monomorphic sites name (timelock claim's Balance get + remove,
    // dex's TokenA getter). The shared polymorphic helpers (timelock's
    // has serving Init AND Balance, dex's getter serving TokenB..Shares)
    // must stay honestly unnamed — the meet refuses disagreement.
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-hir", TIMELOCK])
        .assert()
        .success()
        .stdout(predicate::str::contains("storage_get<instance>(v182: DataKey::Balance)"))
        .stdout(predicate::str::contains("storage_remove<instance>(v163: DataKey::Balance)"))
        .stdout(predicate::str::contains(": DataKey::Init").not());

    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-hir", DEX])
        .assert()
        .success()
        .stdout(predicate::str::contains(": DataKey::TokenA"))
        .stdout(predicate::str::contains(": DataKey::TokenB").not());
}

#[test]
fn dump_hir_stripped_token_names_no_enum_keys() {
    // The honesty lock: without a contractspecv0 section there is no
    // union registry, so the enum-key pass recognizes nothing — no
    // guessed names, ever.
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-hir", TOKEN_V23_STRIPPED])
        .assert()
        .success()
        .stdout(predicate::str::contains("DataKey::").not())
        .stdout(predicate::str::contains("admin gate:").not());
}

#[test]
fn dump_hir_annotates_admin_gates_on_both_tokens() {
    // The D2.3 flow: require_auth whose address is the instance-storage
    // admin read carries the admin-gate annotation (mint + set_admin);
    // param-auth sites (transfer etc.) never do. `--raw` shows neither.
    for wasm in [TOKEN_V22, TOKEN_V23] {
        Command::cargo_bin("sordec")
            .expect("sordec binary builds")
            .args(["dump-hir", wasm])
            .assert()
            .success()
            .stdout(predicate::str::contains(
                "admin gate: address = storage_get<instance>(DataKey::Admin)",
            ));
    }

    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-hir", "--raw", TOKEN_V22])
        .assert()
        .success()
        .stdout(predicate::str::contains("admin gate:").not())
        .stdout(predicate::str::contains("DataKey::").not());
}

#[test]
fn dump_hir_recognizes_every_host_call_across_the_corpus() {
    // The Phase 2 recognition milestone: with all seven recognizers
    // registered, no raw `host:` call of any module survives the default
    // pipeline on any corpus fixture — every host interaction renders as
    // a named semantic op.
    for wasm in [
        HELLO_ADD,
        TOKEN_V22,
        TOKEN_V23,
        TOKEN_V23_STRIPPED,
        TIMELOCK,
        DEX,
    ] {
        Command::cargo_bin("sordec")
            .expect("sordec binary builds")
            .args(["dump-hir", wasm])
            .assert()
            .success()
            .stdout(predicate::str::contains("host:").not());
    }
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
