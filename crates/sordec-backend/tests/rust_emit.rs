//! Corpus gates for the compilable-Rust emitter (Phase 4 · W1 skeleton).
//!
//! The Rust counterpart of `wat_gates.rs`. W1 emits the module *skeleton*
//! (reconstructed types + scaffold + signatures with `todo!()` bodies), so
//! the load-bearing invariant is **structural validity**: every fixture
//! emits, and every emission re-parses as a Rust file. Bodies arrive in a
//! later wave; the acceptance shape locked here is the frame they drop into.

mod common;

use sordec_backend::{emit_cargo_toml, emit_rust};

/// Structural-validity gate: every fixture emits, and the emitted source is
/// syntactically valid Rust (parses via `syn`). This is W1's headline
/// acceptance — the emitter cannot produce unparseable output.
#[test]
fn every_fixture_emits_parseable_rust() {
    for (name, wasm) in common::fixtures() {
        let high = common::build_high(wasm);
        let src = emit_rust(&high).unwrap_or_else(|e| panic!("{name}: emit failed: {e}"));
        assert!(!src.is_empty(), "{name}: produced output");
        syn::parse_file(&src)
            .unwrap_or_else(|e| panic!("{name}: emitted Rust did not parse: {e}\n---\n{src}"));
    }
}

/// Emission is byte-for-byte deterministic (a scorer/regression prerequisite).
#[test]
fn emission_is_deterministic() {
    let high = common::build_high(common::TOKEN_V23);
    assert_eq!(
        emit_rust(&high).expect("emits"),
        emit_rust(&high).expect("emits"),
        "emission must be deterministic",
    );
}

/// hello-add reconstructs its `#[contract]` scaffold and its one spec
/// method — now with a **real body** (W2), not a `todo!()` stub. Asserted
/// by robust markers (SSA-destructed phi, a helper call threading a
/// parameter name, structured control flow, an explicit return) rather
/// than a brittle full-file snapshot.
#[test]
fn hello_add_emits_a_real_add_body() {
    let (_, wasm) = common::fixtures()[0];
    let src = emit_rust(&common::build_high(wasm)).expect("emits");

    assert!(src.starts_with("#![no_std]"), "no_std module attribute:\n{src}");
    assert!(src.contains("#[contract]\npub struct Contract;"), "contract struct:\n{src}");
    // The synthesized `Env` leads the signature (host ops root on it).
    // `Env` is imported and written short after the R3 collapse pass.
    assert!(
        src.contains("pub fn add(e: Env, a: u64, b: u64) -> u64 {"),
        "spec method signature with env:\n{src}"
    );
    // SSA destruction: a hoisted `let mut` phi, assigned and returned.
    assert!(src.contains("let mut v"), "phi hoisted as let mut:\n{src}");
    assert!(src.contains("return v"), "explicit return of a value:\n{src}");
    // A helper call threading the env and a recovered parameter name.
    assert!(src.contains("func0(e, v5, a)"), "call threads env + param `a`:\n{src}");
    // Structured control flow survived the walk.
    assert!(src.contains("if v"), "if present:\n{src}");
    assert!(src.contains("break 'bb"), "labeled break present:\n{src}");
    // Host-call sites are honest holes carrying their recovered label.
    assert!(src.contains("todo!(\"memory load\")"), "host/memory hole labeled:\n{src}");
}

/// The idiom table (P5): token-v23's storage/auth/event ops render as the
/// exact SDK method chains the scorer's extractor recognises (K4).
#[test]
fn token_v23_emits_soroban_idioms() {
    let src = emit_rust(&common::build_high(common::TOKEN_V23)).expect("emits");

    // Storage across all three tiers, keyed by the recovered enum variants.
    assert!(src.contains("e.storage().persistent().get(&DataKey::Balance"), "persistent get:\n{src}");
    assert!(src.contains("e.storage().instance().get(&DataKey::Admin"), "instance get:\n{src}");
    assert!(src.contains("e.storage().temporary().get(&DataKey::Allowance"), "temporary get:\n{src}");
    assert!(src.contains(".set(&DataKey::"), "a keyed set:\n{src}");
    // Auth, events, ledger context.
    assert!(src.contains(".require_auth()"), "require_auth:\n{src}");
    // R1: topics are a tuple. A single topic must render the 1-tuple
    // `(t,)` (trailing comma), not the parenthesised expr `(t)`.
    assert!(
        src.lines()
            .any(|l| l.contains(".events().publish((") && l.contains(",),")),
        "single-topic publish renders a 1-tuple:\n{src}"
    );
}

/// R2: local temporaries are named from unambiguous structure — a storage
/// read takes the name of the enum variant it is keyed by, a ledger read the
/// quantity it fetches. The name is used consistently (the binding and its
/// reads all agree), which is what keeps the scorer's key-resolution correct.
#[test]
fn token_v23_names_locals_from_structure() {
    let src = emit_rust(&common::build_high(common::TOKEN_V23)).expect("emits");

    // Storage reads named after their resolved key variant.
    assert!(
        src.contains("let admin = e.storage().instance().get(&DataKey::Admin)"),
        "storage read named `admin`:\n{src}"
    );
    assert!(
        src.contains("let balance = e.storage().persistent().get(&DataKey::Balance"),
        "storage read named `balance`:\n{src}"
    );
    // A ledger-context read named after the quantity it returns.
    assert!(src.contains("let sequence = e.ledger().sequence()"), "ledger read named:\n{src}");
    // The name is consistent at the use site, not just the binding.
    assert!(src.contains("return admin;"), "named local reused at its use:\n{src}");
}

/// R3: a value that is never read is not bound. An unused *effectful*
/// expression (a unit-returning idiom, an unused helper call) is re-emitted
/// as a bare statement so its effect survives; the dead `let vN =` name is
/// gone. Nothing that carries an effect is dropped.
#[test]
fn token_v23_eliminates_dead_bindings() {
    let src = emit_rust(&common::build_high(common::TOKEN_V23)).expect("emits");

    // No unit-returning idiom is bound to a dead name any more...
    for chain in [".set(", ".require_auth()", "events().publish("] {
        assert!(
            !src.lines().any(|l| {
                let t = l.trim_start();
                t.starts_with("let ") && t.contains(chain)
            }),
            "dead `let` binding a unit idiom (`{chain}`) should be gone:\n{src}"
        );
    }
    // ...but the effect itself is still emitted, as a statement.
    assert!(
        src.lines().any(|l| l.trim_start().starts_with("e.storage().instance().set(")),
        "storage set retained as a statement:\n{src}"
    );
    assert!(
        src.lines().any(|l| l.trim_start().ends_with(".require_auth();")),
        "require_auth retained as a statement:\n{src}"
    );
}

/// Values whose uses cross a structured scope boundary are hoisted:
/// declared (typed, no initializer, no `mut`) at the body top and assigned
/// at their def site, so they stay in scope at the later use. This clears
/// the `E0425 cannot find value` class the W3 compile measurement flagged.
/// (`let mut vN: T;` are phis; a plain `let vN: T;` is a hoisted escapee.)
#[test]
fn escaping_values_are_hoisted() {
    let src = emit_rust(&common::build_high(common::TOKEN_V23)).expect("emits");
    let has_hoisted_escapee = src.lines().any(|line| {
        let t = line.trim();
        t.starts_with("let v") && t.contains(':') && !t.contains('=') && t.ends_with(';')
    });
    assert!(has_hoisted_escapee, "expected a hoisted escaping-value decl:\n{src}");
}

/// R3: soroban-sdk type paths are collapsed into a single `use` list and
/// written short in the body; the only `soroban_sdk::` left is the import
/// line itself. Keeps the emitted source reading like hand-written Soroban.
#[test]
fn token_v23_collapses_soroban_imports() {
    let src = emit_rust(&common::build_high(common::TOKEN_V23)).expect("emits");

    assert!(src.contains("use soroban_sdk::{"), "single soroban_sdk use list:\n{src}");
    // Common types are imported, so bodies/signatures write them short.
    assert!(src.contains("e: Env"), "Env written short:\n{src}");
    assert!(src.contains(": Address"), "Address written short:\n{src}");
    // The `use` line is the only place a `soroban_sdk::` prefix survives.
    for line in src.lines().filter(|l| l.contains("soroban_sdk::")) {
        assert!(line.trim_start().starts_with("use soroban_sdk::{"), "stray qualified path:\n{line}");
    }
}

/// Every fixture emits real body statements — the emitter is past the W1
/// `todo!()`-stub skeleton across the whole corpus.
#[test]
fn every_fixture_emits_real_bodies() {
    for (name, wasm) in common::fixtures() {
        let src = emit_rust(&common::build_high(wasm)).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(src.contains("let "), "{name}: expected real body statements");
    }
}

/// S2b (D4.4): a `Result<T, Error>` entrypoint reconstructs its Ok/Err
/// returns. attestation's `digest_keccak` recovers the error constant as
/// `Error::EmptyMessage` and wraps the guard return as `Err(..)`; an
/// unrecovered value is never given a fake `Ok`.
#[test]
fn attestation_reconstructs_result_returns() {
    let src = emit_rust(&common::build_high(common::ATTESTATION)).expect("emits");

    // The #[contracterror] enum + the Result return type still reconstruct;
    // the Result error side is the user enum (the ABI-erased generic `Error`
    // resolves to the sole declared error enum), so `Err(Error::Variant)`
    // type-checks and no `soroban_sdk::Error` import collides with the enum.
    assert!(src.contains("#[contracterror]"), "contracterror enum:\n{src}");
    assert!(src.contains("-> Result<BytesN<32>, Error>"), "Result return type:\n{src}");
    let use_line = src.lines().find(|l| l.contains("use soroban_sdk::{")).unwrap_or("");
    assert!(!use_line.contains("Error"), "user `Error` enum must not collide with an import:\n{use_line}");
    // The Err constant is decoded to its variant and wrapped in Err(..).
    assert!(src.contains("= Error::EmptyMessage;"), "error constant named:\n{src}");
    assert!(
        src.lines().any(|l| l.trim() == "return Err(v6);" || l.trim().starts_with("return Err(")),
        "guard return wrapped in Err:\n{src}"
    );
    // Honesty: a Result body must not manufacture `.unwrap()`/`.expect()`
    // (phantom panic facts the original never had).
    assert!(!src.contains(".unwrap()"), "no phantom unwrap in Result body:\n{src}");
    assert!(!src.contains(".expect("), "no phantom expect in Result body:\n{src}");
}

/// Measurement (not a gate): emit attestation as a crate and `cargo check`
/// it. This is W5's honest deliverable — with S2b the `Result` entrypoints
/// type-check their returns; unrecovered host ops remain diverging `todo!`
/// holes, so the crate is expected to **compile**. Slow + toolchain-dependent:
///   cargo test -p sordec-backend -- --ignored --nocapture attestation_cargo_check
#[test]
#[ignore = "shells out to cargo check against soroban-sdk (slow, toolchain-dependent)"]
#[allow(clippy::print_stdout)]
fn attestation_cargo_check() {
    let high = common::build_high(common::ATTESTATION);
    let rust = emit_rust(&high).expect("emits");
    let cargo_toml = emit_cargo_toml(&high);

    let dir = std::env::temp_dir().join(format!("sordec-w5-check-{}", std::process::id()));
    let src = dir.join("src");
    std::fs::create_dir_all(&src).expect("scratch dir");
    std::fs::write(dir.join("Cargo.toml"), format!("{cargo_toml}\n[workspace]\n")).unwrap();
    std::fs::write(src.join("lib.rs"), &rust).unwrap();

    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let output = std::process::Command::new(cargo)
        .args(["check", "--offline", "--quiet", "--manifest-path"])
        .arg(dir.join("Cargo.toml"))
        .output();

    match output {
        Ok(out) if out.status.success() => println!("attestation cargo check: PASS"),
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let errors = stderr
                .lines()
                .filter(|l| l.trim_start().starts_with("error"))
                .count();
            println!("attestation cargo check: PARTIAL — {errors} error line(s). First diagnostics:");
            for line in stderr
                .lines()
                .filter(|l| {
                    let t = l.trim_start();
                    t.starts_with("error") || t.starts_with("-->")
                })
                .take(12)
            {
                println!("  {}", line.trim());
            }
        }
        Err(e) => println!("attestation cargo check: UNAVAILABLE ({e})"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Measurement (not a gate): emit token-v23 as a crate and run
/// `cargo check` against the cached `soroban-sdk`, reporting the outcome.
/// This is W3's honest "compile rate measured" deliverable — expected
/// **partial** while ABI-marshalling residue and `Unknown` types remain.
/// Slow + toolchain-dependent, so `#[ignore]`d out of the fast suite:
///   cargo test -p sordec-backend -- --ignored --nocapture
#[test]
#[ignore = "shells out to cargo check against soroban-sdk (slow, toolchain-dependent)"]
// This test's entire purpose is to *report* a measurement to the operator.
#[allow(clippy::print_stdout)]
fn token_v23_cargo_check_rate() {
    let high = common::build_high(common::TOKEN_V23);
    let rust = emit_rust(&high).expect("emits");
    let cargo_toml = emit_cargo_toml(&high);

    let dir = std::env::temp_dir().join(format!("sordec-w3-check-{}", std::process::id()));
    let src = dir.join("src");
    std::fs::create_dir_all(&src).expect("scratch dir");
    // Append a `[workspace]` table so cargo treats this as standalone.
    std::fs::write(dir.join("Cargo.toml"), format!("{cargo_toml}\n[workspace]\n")).unwrap();
    std::fs::write(src.join("lib.rs"), &rust).unwrap();

    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let output = std::process::Command::new(cargo)
        .args(["check", "--offline", "--quiet", "--manifest-path"])
        .arg(dir.join("Cargo.toml"))
        .output();

    match output {
        Ok(out) if out.status.success() => println!("token-v23 cargo check: PASS"),
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let errors = stderr
                .lines()
                .filter(|l| l.trim_start().starts_with("error"))
                .count();
            println!("token-v23 cargo check: PARTIAL — {errors} error line(s). First diagnostics:");
            for line in stderr
                .lines()
                .filter(|l| {
                    let t = l.trim_start();
                    t.starts_with("error") || t.starts_with("-->")
                })
                .take(12)
            {
                println!("  {}", line.trim());
            }
        }
        Err(e) => println!("token-v23 cargo check: UNAVAILABLE ({e})"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The generated `Cargo.toml` is a buildable cdylib crate manifest pinning
/// the SDK version recovered from the contract's own metadata.
#[test]
fn hello_add_cargo_toml_is_a_cdylib_crate() {
    let (_, wasm) = common::fixtures()[0];
    let manifest = emit_cargo_toml(&common::build_high(wasm));
    assert!(manifest.contains("crate-type = [\"cdylib\"]"), "{manifest}");
    assert!(manifest.contains("soroban-sdk = "), "{manifest}");
    // parseable as TOML-ish: has the three required tables.
    for table in ["[package]", "[lib]", "[dependencies]"] {
        assert!(manifest.contains(table), "missing {table}:\n{manifest}");
    }
}

/// Type reconstruction lands on the canonical benchmark: token-v23's
/// `#[contracttype]` definitions come back with the right shape.
#[test]
fn token_v23_reconstructs_contract_types() {
    let high = common::build_high(common::TOKEN_V23);
    let src = emit_rust(&high).expect("emits");

    assert!(src.contains("#[contracttype]"), "has contracttype defs:\n{src}");
    // The DataKey enum: mixed unit + payload variants, exactly as in source.
    // Soroban types are imported and written short after the R3 collapse.
    assert!(src.contains("pub enum DataKey"), "DataKey enum present:\n{src}");
    assert!(src.contains("Balance(Address)"), "payload variant:\n{src}");
    assert!(src.contains("Admin,"), "unit variant:\n{src}");
}
