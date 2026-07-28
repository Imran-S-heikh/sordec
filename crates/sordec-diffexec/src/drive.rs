//! Building the calls that drive a contract, from its own declared ABI.
//!
//! Both sides of a differential run must be invoked with *identical*
//! arguments, and those arguments have to come from somewhere. This module
//! reads `contractspecv0` out of the original wasm and turns each declared
//! entrypoint into a list of [`Call`]s.
//!
//! ## Scope, stated rather than implied
//!
//! Only entrypoints whose every parameter is a **scalar** are drivable
//! here: `bool`, `u32`, `i32`, `u64`, `i64`, `u128`, `i128`. An
//! `Address`, `Symbol`, `Vec`, `Map`, or user-defined type needs values
//! constructed against a live host, which is a larger task.
//!
//! That limit is load-bearing to report honestly, because it is *not*
//! small: virtually every real Soroban entrypoint takes an `Address`. A
//! harness that quietly skipped them and published the pass rate over
//! what remained would be reporting on the stateless-arithmetic slice
//! while sounding like it covered the contract. So every skip is recorded
//! with its reason and [`DrivePlan`] always answers `drivable of total`.
//!
//! ## Determinism
//!
//! Two runs must produce byte-identical calls or the comparison is
//! meaningless. Values come from a fixed boundary table plus a
//! fixed-seed LCG — never a clock, never the ambient RNG.
//!
//! ## Boundary choices that are doing real work
//!
//! The tables are not decoration. `u64` includes 2^56 - 1 and 2^56, which
//! straddle the point where Soroban switches a value from a small `Val`
//! body to an object handle — the exact branch the emitter's return-encode
//! collapse removes. Signed types include `MIN`/`MAX`, so an arithmetic
//! reconstruction that wraps where the original traps fails on the first
//! case rather than never.

use soroban_sdk::xdr::{
    Limited, Limits, ReadXdr, ScSpecEntry, ScSpecFunctionV0, ScSpecTypeDef, ScVal,
};

use crate::exec::Call;
use crate::preflight::Unavailable;
use crate::wasm;

/// How many calls to generate per drivable entrypoint.
///
/// Enough to reach every boundary in the longest table with room for
/// seeded values; small enough that a corpus run stays interactive, since
/// each call executes twice in a fresh host.
const CASES_PER_FN: usize = 12;

/// One declared entrypoint and what can be done with it.
#[derive(Debug, Clone)]
pub struct Entrypoint {
    /// Exported name.
    pub name: String,
    /// Calls to drive it with. Empty when it was skipped.
    pub calls: Vec<Call>,
    /// Why it was skipped, when it was. `None` for a drivable entrypoint.
    pub skipped: Option<String>,
}

/// Every entrypoint a contract declares, with per-entrypoint coverage.
#[derive(Debug, Clone)]
pub struct DrivePlan {
    /// In declaration order.
    pub entrypoints: Vec<Entrypoint>,
}

impl DrivePlan {
    /// Every call across every drivable entrypoint, in declaration order.
    #[must_use]
    pub fn calls(&self) -> Vec<Call> {
        self.entrypoints
            .iter()
            .flat_map(|e| e.calls.iter().cloned())
            .collect()
    }

    /// Entrypoints that could be driven.
    #[must_use]
    pub fn drivable(&self) -> usize {
        self.entrypoints.iter().filter(|e| e.skipped.is_none()).count()
    }

    /// Entrypoints the contract declares.
    #[must_use]
    pub fn total(&self) -> usize {
        self.entrypoints.len()
    }

    /// The honest denominator, plus why anything was left out.
    ///
    /// Rendered even when everything was drivable, so a reader never has
    /// to infer coverage from the absence of a caveat.
    #[must_use]
    pub fn coverage(&self) -> String {
        let mut note = format!(
            "{} of {} entrypoints drivable",
            self.drivable(),
            self.total()
        );
        let mut reasons: Vec<String> = self
            .entrypoints
            .iter()
            .filter_map(|e| e.skipped.as_ref().map(|why| format!("{}: {why}", e.name)))
            .collect();
        if !reasons.is_empty() {
            reasons.sort();
            note.push_str(" (skipped — ");
            note.push_str(&reasons.join("; "));
            note.push(')');
        }
        note
    }
}

/// Read `wasm`'s declared ABI and plan how to drive each entrypoint.
///
/// # Errors
///
/// [`Unavailable`] when the module carries no `contractspecv0`, which is
/// the case for a stripped contract: without a declared ABI there are no
/// signatures to build arguments against.
pub fn plan(wasm: &[u8]) -> Result<DrivePlan, Unavailable> {
    let Some(spec) = wasm::custom_section(wasm, wasm::SPEC_SECTION) else {
        return Err(Unavailable {
            reason: format!(
                "wasm has no `{}` section, so its entrypoint signatures are unknown \
                 and no arguments can be constructed",
                wasm::SPEC_SECTION
            ),
        });
    };

    let mut entrypoints = Vec::new();
    let mut reader = Limited::new(spec, Limits::none());
    // The section is a concatenation of entries; read until it runs out.
    while let Ok(entry) = ScSpecEntry::read_xdr(&mut reader) {
        if let ScSpecEntry::FunctionV0(function) = entry {
            let name = function.name.to_utf8_string_lossy();
            // Registration invokes the constructor; it is not an
            // entrypoint a caller drives.
            if name == wasm::CONSTRUCTOR_EXPORT {
                continue;
            }
            entrypoints.push(plan_function(&name, &function));
        }
    }

    Ok(DrivePlan { entrypoints })
}

/// Plan one entrypoint: generate its calls, or record why not.
fn plan_function(name: &str, function: &ScSpecFunctionV0) -> Entrypoint {
    let mut tables = Vec::with_capacity(function.inputs.len());
    for input in function.inputs.iter() {
        match values_for(&input.type_) {
            Some(values) => tables.push(values),
            None => {
                return Entrypoint {
                    name: name.to_string(),
                    calls: Vec::new(),
                    skipped: Some(format!(
                        "parameter `{}` is {}, which needs a value constructed \
                         against a live host",
                        input.name.to_utf8_string_lossy(),
                        type_name(&input.type_),
                    )),
                };
            }
        }
    }

    // Offset each parameter's index by its position so the cases sweep the
    // tables against each other. Advancing them in lockstep would only
    // ever test the diagonal — every argument at its own boundary
    // simultaneously — and miss `(MAX, 1)`, which is what actually
    // overflows.
    let calls = (0..CASES_PER_FN)
        .map(|case| {
            let args = tables
                .iter()
                .enumerate()
                .map(|(position, table)| table[(case + position) % table.len()].clone())
                .collect();
            Call::new(name, args)
        })
        .collect();

    Entrypoint {
        name: name.to_string(),
        calls,
        skipped: None,
    }
}

/// Candidate values for a parameter type, or `None` when it is not a
/// scalar this module can construct.
fn values_for(ty: &ScSpecTypeDef) -> Option<Vec<ScVal>> {
    let mut rng = Lcg::new(ty_seed(ty));
    Some(match ty {
        ScSpecTypeDef::Bool => vec![ScVal::Bool(false), ScVal::Bool(true)],
        ScSpecTypeDef::U32 => {
            let mut v = vec![0, 1, 2, u32::MAX - 1, u32::MAX];
            v.extend((0..4).map(|_| rng.next() as u32));
            v.into_iter().map(ScVal::U32).collect()
        }
        ScSpecTypeDef::I32 => {
            let mut v = vec![0, 1, -1, i32::MIN, i32::MAX];
            v.extend((0..4).map(|_| rng.next() as i32));
            v.into_iter().map(ScVal::I32).collect()
        }
        ScSpecTypeDef::U64 => {
            // 2^56 - 1 and 2^56 straddle the small-Val/object boundary.
            let mut v = vec![0, 1, 2, (1 << 56) - 1, 1 << 56, u64::MAX - 1, u64::MAX];
            v.extend((0..4).map(|_| rng.next()));
            v.into_iter().map(ScVal::U64).collect()
        }
        ScSpecTypeDef::I64 => {
            let mut v = vec![0, 1, -1, (1 << 55) - 1, 1 << 55, i64::MIN, i64::MAX];
            v.extend((0..4).map(|_| rng.next() as i64));
            v.into_iter().map(ScVal::I64).collect()
        }
        ScSpecTypeDef::Timepoint => [0u64, 1, 1_700_000_000, u64::MAX]
            .into_iter()
            .map(|n| ScVal::Timepoint(soroban_sdk::xdr::TimePoint(n)))
            .collect(),
        ScSpecTypeDef::Duration => [0u64, 1, 86_400, u64::MAX]
            .into_iter()
            .map(|n| ScVal::Duration(soroban_sdk::xdr::Duration(n)))
            .collect(),
        ScSpecTypeDef::U128 => [0u128, 1, u128::from(u64::MAX), u128::MAX]
            .into_iter()
            .map(u128_val)
            .collect(),
        ScSpecTypeDef::I128 => [0i128, 1, -1, i128::from(i64::MIN), i128::MAX, i128::MIN]
            .into_iter()
            .map(i128_val)
            .collect(),
        _ => return None,
    })
}

fn u128_val(n: u128) -> ScVal {
    ScVal::U128(soroban_sdk::xdr::UInt128Parts {
        hi: (n >> 64) as u64,
        lo: n as u64,
    })
}

fn i128_val(n: i128) -> ScVal {
    ScVal::I128(soroban_sdk::xdr::Int128Parts {
        hi: (n >> 64) as i64,
        lo: n as u64,
    })
}

/// A stable per-type seed, so a `u64` parameter draws the same values in
/// every contract and every run.
fn ty_seed(ty: &ScSpecTypeDef) -> u64 {
    match ty {
        ScSpecTypeDef::U32 => 0x9E37_79B9,
        ScSpecTypeDef::I32 => 0x85EB_CA6B,
        ScSpecTypeDef::U64 => 0xC2B2_AE35,
        ScSpecTypeDef::I64 => 0x27D4_EB2F,
        _ => 0x1656_67B1,
    }
}

/// The name to report when declining a type.
fn type_name(ty: &ScSpecTypeDef) -> &'static str {
    match ty {
        ScSpecTypeDef::Address => "an Address",
        ScSpecTypeDef::MuxedAddress => "a MuxedAddress",
        ScSpecTypeDef::Symbol => "a Symbol",
        ScSpecTypeDef::String => "a String",
        ScSpecTypeDef::Bytes | ScSpecTypeDef::BytesN(_) => "a Bytes value",
        ScSpecTypeDef::Vec(_) => "a Vec",
        ScSpecTypeDef::Map(_) => "a Map",
        ScSpecTypeDef::Option(_) => "an Option",
        ScSpecTypeDef::Result(_) => "a Result",
        ScSpecTypeDef::Tuple(_) => "a tuple",
        ScSpecTypeDef::Udt(_) => "a user-defined type",
        ScSpecTypeDef::Val => "an untyped Val",
        _ => "a type this generator does not construct",
    }
}

/// A fixed-increment linear congruential generator (Knuth's MMIX
/// constants). Deterministic by construction — the whole harness rests on
/// two runs producing identical inputs.
struct Lcg(u64);

impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_tables_include_the_val_encoding_boundary() {
        // 2^56 is where Soroban stops packing a u64 into the Val body and
        // hands out an object handle. The emitter collapses that branch,
        // so a case on each side of it is what proves the collapse right.
        let values = values_for(&ScSpecTypeDef::U64).expect("u64 is a scalar");
        assert!(values.contains(&ScVal::U64((1 << 56) - 1)));
        assert!(values.contains(&ScVal::U64(1 << 56)));
    }

    #[test]
    fn signed_tables_include_the_overflow_boundaries() {
        let values = values_for(&ScSpecTypeDef::I64).expect("i64 is a scalar");
        assert!(values.contains(&ScVal::I64(i64::MIN)));
        assert!(values.contains(&ScVal::I64(i64::MAX)));
    }

    #[test]
    fn a_non_scalar_parameter_is_declined_with_a_reason() {
        assert!(values_for(&ScSpecTypeDef::Address).is_none());
        assert_eq!(type_name(&ScSpecTypeDef::Address), "an Address");
    }

    #[test]
    fn generation_is_deterministic() {
        let a = values_for(&ScSpecTypeDef::U64).unwrap();
        let b = values_for(&ScSpecTypeDef::U64).unwrap();
        assert_eq!(a, b, "two runs must produce identical inputs");
    }

    #[test]
    fn arguments_sweep_rather_than_advance_in_lockstep() {
        // Two u64 parameters must not always carry the same value — the
        // diagonal never produces `(MAX, 1)`, which is the case that
        // overflows.
        let f = ScSpecFunctionV0 {
            doc: "".try_into().unwrap(),
            name: "add".try_into().unwrap(),
            inputs: vec![
                soroban_sdk::xdr::ScSpecFunctionInputV0 {
                    doc: "".try_into().unwrap(),
                    name: "a".try_into().unwrap(),
                    type_: ScSpecTypeDef::U64,
                },
                soroban_sdk::xdr::ScSpecFunctionInputV0 {
                    doc: "".try_into().unwrap(),
                    name: "b".try_into().unwrap(),
                    type_: ScSpecTypeDef::U64,
                },
            ]
            .try_into()
            .unwrap(),
            outputs: vec![ScSpecTypeDef::U64].try_into().unwrap(),
        };
        let planned = plan_function("add", &f);
        assert!(planned.skipped.is_none());
        assert_eq!(planned.calls.len(), CASES_PER_FN);
        assert!(
            planned.calls.iter().any(|c| c.args[0] != c.args[1]),
            "parameters must not move in lockstep"
        );
    }

    #[test]
    fn coverage_names_what_was_skipped() {
        let plan = DrivePlan {
            entrypoints: vec![
                Entrypoint { name: "add".into(), calls: vec![], skipped: None },
                Entrypoint {
                    name: "transfer".into(),
                    calls: vec![],
                    skipped: Some("parameter `to` is an Address".into()),
                },
            ],
        };
        let coverage = plan.coverage();
        assert!(coverage.starts_with("1 of 2 entrypoints drivable"));
        assert!(coverage.contains("transfer: parameter `to` is an Address"));
    }
}
