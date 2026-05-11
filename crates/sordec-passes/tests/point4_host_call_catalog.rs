//! Point 4 deliverable tests: baseline Soroban host-call catalog recovery.
//!
//! These tests validate the semantic-recovery seed data: every vendored
//! `(module, export)` pair from `env.json` must resolve to a friendly
//! Soroban host-call name, while unknown pairs must degrade cleanly.

use std::collections::BTreeSet;

use serde::Deserialize;
use sordec_passes::{CATALOG_VERSION, catalog_size, resolve_host_call};

const ENV_JSON: &str = include_str!("../src/host_calls/env.json");

#[derive(Debug, Deserialize)]
struct EnvSpec {
    modules: Vec<EnvModule>,
}

#[derive(Debug, Deserialize)]
struct EnvModule {
    name: String,
    export: String,
    functions: Vec<EnvFunction>,
}

#[derive(Debug, Deserialize)]
struct EnvFunction {
    export: String,
    name: String,
    #[serde(default)]
    min_supported_protocol: u32,
}

fn env_spec() -> EnvSpec {
    serde_json::from_str(ENV_JSON).expect("vendored env.json parses")
}

fn catalog_pairs() -> Vec<(String, String, String, String, u32)> {
    let mut pairs = Vec::new();
    for module in env_spec().modules {
        for function in module.functions {
            pairs.push((
                module.export.clone(),
                function.export,
                function.name,
                module.name.clone(),
                function.min_supported_protocol,
            ));
        }
    }
    pairs
}

#[test]
fn vendored_catalog_resolves_every_env_json_entry() {
    let pairs = catalog_pairs();

    assert_eq!(
        catalog_size(),
        pairs.len(),
        "catalog_size must match the vendored env.json entry count"
    );
    assert_eq!(
        pairs.len(),
        192,
        "soroban-env-common 26.1.2 has 192 host calls"
    );

    for (module, name, friendly_name, module_name, min_protocol) in pairs {
        let resolved = resolve_host_call(&module, &name)
            .unwrap_or_else(|| panic!("missing host call {module}:{name}"));
        assert_eq!(resolved.module, module);
        assert_eq!(resolved.name, name);
        assert_eq!(resolved.friendly_name, friendly_name);
        assert_eq!(resolved.module_name, module_name);
        assert_eq!(resolved.min_protocol, min_protocol);
    }
}

#[test]
fn vendored_catalog_has_unique_module_name_pairs() {
    let mut seen = BTreeSet::new();

    for (module, name, _friendly_name, _module_name, _min_protocol) in catalog_pairs() {
        assert!(
            seen.insert((module.clone(), name.clone())),
            "duplicate host-call pair {module}:{name}"
        );
    }
}

#[test]
fn core_module_examples_cover_every_vendored_host_module() {
    let examples = [
        ("x", "_", "log_from_linear_memory"),
        ("i", "_", "obj_from_u64"),
        ("m", "_", "map_new"),
        ("v", "_", "vec_new"),
        ("l", "_", "put_contract_data"),
        ("d", "_", "call"),
        ("b", "_", "serialize_to_bytes"),
        ("c", "_", "compute_hash_sha256"),
        ("a", "0", "require_auth"),
        ("t", "_", "dummy0"),
        ("p", "_", "prng_reseed"),
    ];

    for (module, name, friendly) in examples {
        let resolved = resolve_host_call(module, name)
            .unwrap_or_else(|| panic!("expected known host call {module}:{name}"));
        assert_eq!(resolved.friendly_name, friendly);
    }
}

#[test]
fn unknown_pairs_return_none_without_false_positive() {
    assert!(resolve_host_call("l", "~").is_none());
    assert!(resolve_host_call("unknown", "_").is_none());
    assert!(resolve_host_call("zz", "?").is_none());
}

#[test]
fn deterministic_known_pair_matrix_resolves_repeatedly() {
    let pairs = catalog_pairs();

    for seed in 0..4096usize {
        let (module, name, friendly_name, _module_name, _min_protocol) = &pairs[seed % pairs.len()];
        let resolved = resolve_host_call(module, name)
            .unwrap_or_else(|| panic!("seed {seed} failed to resolve {module}:{name}"));
        assert_eq!(resolved.friendly_name, friendly_name);
    }
}

#[test]
fn deterministic_unknown_pair_matrix_does_not_false_positive() {
    for seed in 0..4096usize {
        let module = format!("zz{seed}");
        let name = format!("?{seed}");
        assert!(
            resolve_host_call(&module, &name).is_none(),
            "seed {seed} unexpectedly resolved unknown host pair {module}:{name}"
        );
    }
}

#[test]
fn catalog_version_tracks_vendored_source() {
    assert_eq!(CATALOG_VERSION, "soroban-env-common 26.1.2");
}
