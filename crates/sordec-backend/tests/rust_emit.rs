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
/// method, with the ABI marshalling elided. Asserted by robust markers
/// rather than a brittle full-file snapshot.
///
/// This test previously pinned the *un-elided* shape — a `func0(e, v5, a)`
/// spill call and `todo!("memory load")` holes. Those were the SDK's
/// `TryFromVal` glue reconstructed literally, and deleting them is the
/// whole point of `sordec_passes::marshalling`, so the markers moved with
/// the behaviour they describe.
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
    // SSA destruction: a hoisted `let mut` phi, assigned and yielded.
    assert!(src.contains("let mut v"), "phi hoisted as let mut:\n{src}");

    // The arguments read as themselves: each decode collapsed to the
    // parameter it decodes, and the rename it left folds into its reader,
    // so the addition names `a` and `b` directly.
    assert!(
        src.contains("b + a") || src.contains("a + b"),
        "the parameters are read directly, not decoded:\n{src}"
    );
    assert!(!src.contains("func0("), "the decode helper has no callers:\n{src}");
    assert!(!src.contains("fn func0"), "and is not emitted at all:\n{src}");

    // The contract's own logic survives, and *only* it: the source is
    // `a + b`, so that is the whole body.
    assert!(src.contains(" + "), "the addition survives:\n{src}");

    // Nothing in the entrypoint is a hole any more.
    assert!(!src.contains("todo!"), "no unrecovered holes remain:\n{src}");

    // Zero control flow, which is what the source has. Three separate
    // shapes had to go, and each is worth naming because each is a
    // *compiler*-inserted construct the source never wrote:
    //
    // - the overflow guard rustc emits under `overflow-checks = true`
    //   (`refine::overflow_guard`) — relocated, not removed: our emitted
    //   manifest pins the same flag, so rustc regenerates it from the
    //   `a + b` above;
    // - the merge scope left behind when the return-value width dispatch
    //   folded, whose single `break` was a fallthrough
    //   (`refine::scope_fallthrough`);
    // - the explicit `return`, where Rust source writes a tail expression.
    //
    // This assertion is the acceptance test for hello-add's `structure`
    // category: with the original at zero tokens too, the category reports
    // `unchecked` rather than 0.0000.
    for token in ["if ", "match ", "loop ", "while ", "break", "continue", "return"] {
        assert!(
            !src.contains(token),
            "hello-add's source has no control flow; found `{token}`:\n{src}"
        );
    }
    assert!(!src.contains("panic!()"), "the overflow trap is elided:\n{src}");
    // Its panic-glue helpers go with it — nothing calls them any more.
    assert!(!src.contains("fn func2"), "panic glue is unreachable:\n{src}");
}

/// The headline gate for the marshalling work: hello-add's reconstruction
/// **compiles**, with zero errors rather than a reported rate.
///
/// `#[ignore]`d like its siblings — it shells out to `cargo` against the
/// cached SDK. Run with:
///
///   cargo test -p sordec-backend -- --ignored --nocapture hello_add_cargo_check
#[test]
#[ignore = "shells out to cargo; run explicitly"]
fn hello_add_cargo_check() {
    let (_, wasm) = common::fixtures()[0];
    let report = common::cargo_check_emitted(wasm);
    assert_eq!(
        report.error_lines, 0,
        "hello-add must compile clean; cargo said:\n{}",
        report.output
    );
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
    // Written verbatim: the emitted manifest now carries its own `[workspace]`, so
    // this no longer has to patch one in to make the crate standalone.
    std::fs::write(dir.join("Cargo.toml"), &cargo_toml).unwrap();
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

/// Measurement (not a gate): the **corpus compile rate** — how many
/// fixtures emit a crate that `cargo check` accepts, and how far the rest
/// are from it.
///
/// The per-fixture checks above each answer one question and stop. This
/// answers the one that gets quoted ("2 of 7"), which until now had to be
/// reassembled by hand from separate runs — and a number nobody can
/// reproduce in one command is a number that drifts. Error *lines*, not
/// distinct errors: it is a progress signal, so the only properties that
/// matter are that it is honest and comparable run to run.
///
///   cargo test -p sordec-backend -- --ignored --nocapture compile_rate
#[test]
#[ignore = "shells out to cargo check per fixture (slow, toolchain-dependent)"]
// This test's entire purpose is to *report* a measurement to the operator.
#[allow(clippy::print_stdout)]
fn corpus_compile_rate() {
    let mut passing = 0usize;
    let mut total_errors = 0usize;
    let fixtures = common::fixtures();
    println!("\nfixture               cargo check");
    for (name, wasm) in &fixtures {
        let report = common::cargo_check_emitted(wasm);
        if report.error_lines == 0 {
            passing += 1;
            println!("{name:<21} PASS");
        } else {
            total_errors += report.error_lines;
            println!("{name:<21} {} error line(s)", report.error_lines);
        }
    }
    println!(
        "\ncompile rate: {passing} of {} · {total_errors} error line(s) across the rest",
        fixtures.len()
    );
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
    // Written verbatim — see the note in the w5 check above.
    std::fs::write(dir.join("Cargo.toml"), &cargo_toml).unwrap();
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

/// Every emitted manifest carries the `[profile.release]` the corpus was built
/// with, and says that it is assumed rather than recovered.
///
/// Not cosmetic. `overflow-checks` defaults *off* in a release build while every
/// corpus contract sets it on, so a manifest without it produces a crate that wraps
/// where the original trapped — a divergence we would have introduced ourselves.
/// `lto` and `codegen-units = 1` are what stop LLVM emitting a function table, which
/// the Soroban host rejects outright because it disables `reference-types`, making
/// their absence a *load* failure rather than a slow build.
#[test]
fn every_emitted_manifest_carries_the_corpus_release_profile() {
    for (name, wasm) in common::fixtures() {
        let manifest = emit_cargo_toml(&common::build_high(wasm));
        for flag in [
            "overflow-checks = true",
            "lto = true",
            "codegen-units = 1",
            "panic = \"abort\"",
        ] {
            assert!(manifest.contains(flag), "{name} is missing {flag}:\n{manifest}");
        }
        assert!(
            manifest.contains("Assumed, not recovered"),
            "{name}: the profile is a guess and must say so:\n{manifest}"
        );
    }
}

/// Every emitted manifest opts out of a parent workspace.
///
/// Without this, the documented `sordec decompile --out-dir out/` path writes a
/// crate cargo refuses to build whenever the output lands inside a workspace. Two
/// tests in this file used to hand-append `[workspace]` to get around exactly that;
/// they no longer need to.
#[test]
fn every_emitted_manifest_opts_out_of_a_parent_workspace() {
    for (name, wasm) in common::fixtures() {
        let manifest = emit_cargo_toml(&common::build_high(wasm));
        assert!(manifest.contains("[workspace]"), "{name}:\n{manifest}");
    }
}

/// Every emitted manifest is valid TOML with the tables cargo needs.
///
/// The manifest carries provenance comments and a multi-line dependency block, which
/// substring assertions cannot prove well-formed. Parsing catches a malformed
/// manifest here rather than as a mystifying cargo failure much later.
#[test]
fn every_emitted_manifest_is_valid_toml() {
    for (name, wasm) in common::fixtures() {
        let manifest = emit_cargo_toml(&common::build_high(wasm));
        let parsed: toml::Table = manifest
            .parse()
            .unwrap_or_else(|e| panic!("{name}: emitted manifest is not TOML: {e}\n{manifest}"));
        for table in ["package", "lib", "dependencies", "profile", "workspace"] {
            assert!(parsed.contains_key(table), "{name}: no [{table}]:\n{manifest}");
        }
    }
}

/// The SDK version is recovered per contract, and pinned exactly when it is known.
///
/// All three rungs of the ladder are exercised by real fixtures rather than
/// hand-built facts, which is the point: hello-add is a protocol-21 contract, so the
/// old hardcoded `"23"` fallback emitted the wrong SDK major for it outright.
#[test]
fn the_sdk_version_is_recovered_per_contract_and_pinned() {
    let expected = [
        // rssdkver present → exact pin. Note hello-add is *not* 23.
        ("hello-add", "soroban-sdk = \"=21.7.7\""),
        ("token-v22", "soroban-sdk = \"=22.0.11\""),
        ("token-v23", "soroban-sdk = \"=23.0.1\""),
    ];
    let fixtures = common::fixtures();

    for (name, requirement) in expected {
        let (_, wasm) = fixtures
            .iter()
            .find(|(fixture, _)| *fixture == name)
            .unwrap_or_else(|| panic!("fixture {name} missing"));
        let manifest = emit_cargo_toml(&common::build_high(wasm));
        assert!(
            manifest.contains(requirement),
            "{name}: expected `{requirement}`:\n{manifest}"
        );
    }
}

/// A wasm with no recoverable version says so in the manifest rather than
/// presenting a guess as a fact.
///
/// `token-v23-stripped` carries no custom sections at all — the stripping took
/// `contractenvmetav0` and `contractspecv0` along with `contractmetav0` — so both
/// rungs of the ladder come up empty. A manifest must still name some version, and
/// the one artifact the user actually opens is where that guess has to be labelled.
#[test]
fn an_unrecoverable_sdk_version_is_labelled_a_guess() {
    let fixtures = common::fixtures();
    let (_, wasm) = fixtures
        .iter()
        .find(|(name, _)| *name == "token-v23-stripped")
        .expect("stripped fixture present");
    let manifest = emit_cargo_toml(&common::build_high(wasm));

    assert!(manifest.contains("could NOT be recovered"), "{manifest}");
    assert!(manifest.contains("guess"), "{manifest}");
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
