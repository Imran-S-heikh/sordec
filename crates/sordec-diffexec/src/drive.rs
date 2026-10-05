//! Building the calls that drive a contract, from its own declared ABI.
//!
//! Both sides of a differential run must be invoked with *identical*
//! arguments, and those arguments have to come from somewhere. This module
//! reads `contractspecv0` out of the original wasm and turns each declared
//! entrypoint into a list of [`Call`]s.
//!
//! ## Scope, stated rather than implied
//!
//! Every argument is built as XDR, which is the value itself and needs no
//! live host, so both sides receive byte-identical inputs. Covered: the
//! scalars, `Address` and `MuxedAddress` (a fixed set of harness accounts,
//! [`ACCOUNTS`]), `String`, `Symbol`, `Bytes`, `BytesN<N>`, `Option`,
//! `Vec`, `Map`, tuples, and the contract's own `#[contracttype]` structs,
//! unions and integer enums, read from the same spec section.
//!
//! Still declined: `Result`, an untyped `Val`, an error enum as an input,
//! and a type nested deeper than [`MAX_DEPTH`]. Every skip is recorded with
//! its reason and [`DrivePlan`] always answers `drivable of total`, so a
//! report never reads as covering more of the contract than it drove.
//!
//! An argument the harness builds is not necessarily one the contract can
//! *use*: an `Address` parameter that the contract calls as a token is
//! handed an account, the call traps on both sides, and the comparison
//! buckets it as a trivial agreement rather than a match.
//!
//! ## The constructor
//!
//! Registration runs `__constructor`, so its arguments are planned like any
//! entrypoint's but only the first case is kept: a contract is constructed
//! once per session. [`DrivePlan::constructor_args`] hands them to
//! [`crate::exec::Session::register_with`].
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

use std::collections::BTreeMap;

use soroban_sdk::xdr::{
    AccountId, Limited, Limits, MuxedEd25519Account, PublicKey, ReadXdr, ScAddress, ScBytes, ScMap,
    ScMapEntry, ScSpecEntry, ScSpecFunctionV0, ScSpecTypeDef, ScSpecUdtUnionCaseV0, ScString,
    ScSymbol, ScVal, ScVec, Uint256,
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

/// How many times the whole call list runs against one session.
///
/// State only flows forward through a session. In a single pass, an
/// entrypoint declared before the one that creates its state — `transfer`
/// before `mint` in the token — only ever sees an empty ledger, fails on
/// both sides, and tests nothing. A second pass replays every call against
/// the state the first one left behind.
pub const ROUNDS: usize = 2;

/// How deep a generated value may nest. A recursive `#[contracttype]` would
/// otherwise never terminate.
pub const MAX_DEPTH: usize = 4;

/// The accounts the harness passes wherever an `Address` is declared, by
/// role label.
///
/// Three, so a call taking two addresses sees both "same party" and
/// "different parties" as the cases sweep. The labels double as
/// [`crate::canon::AddressBook`] roles, so an argument swap between the two
/// sides surfaces as `user_0` against `user_1`.
pub const ACCOUNTS: [&str; 3] = ["user_0", "user_1", "user_2"];

/// The muxed id the harness attaches to its one muxed address.
const MUXED_ID: u64 = 7;

/// The account address the harness passes for role `label`.
///
/// The key bytes spell the label, so the address is the same in every run and
/// on both sides, and the accounts sort in label order — the liquidity pool's
/// constructor requires `token_a < token_b`.
#[must_use]
pub fn account(label: &str) -> ScAddress {
    ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
        account_key(label),
    ))))
}

fn account_key(label: &str) -> [u8; 32] {
    let mut key = [0u8; 32];
    for (slot, byte) in key
        .iter_mut()
        .zip(b"sordec-account:".iter().chain(label.as_bytes()))
    {
        *slot = *byte;
    }
    key
}

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
    /// The constructor, when the contract declares one, planned with at most
    /// one call. Not counted among the entrypoints: a caller never drives it.
    pub constructor: Option<Entrypoint>,
    /// In declaration order.
    pub entrypoints: Vec<Entrypoint>,
}

impl DrivePlan {
    /// Every call across every drivable entrypoint, in declaration order,
    /// repeated [`ROUNDS`] times.
    #[must_use]
    pub fn calls(&self) -> Vec<Call> {
        let round: Vec<Call> = self
            .entrypoints
            .iter()
            .flat_map(|e| e.calls.iter().cloned())
            .collect();
        round
            .iter()
            .cycle()
            .take(round.len() * ROUNDS)
            .cloned()
            .collect()
    }

    /// The arguments to register the contract with.
    ///
    /// Empty when there is no constructor.
    ///
    /// # Errors
    ///
    /// Why the constructor's arguments could not be built. Nothing can run
    /// then, since registration is what invokes it.
    pub fn constructor_args(&self) -> Result<Vec<ScVal>, String> {
        let Some(constructor) = &self.constructor else {
            return Ok(Vec::new());
        };
        if let Some(why) = &constructor.skipped {
            return Err(format!("`{}`: {why}", wasm::CONSTRUCTOR_EXPORT));
        }
        Ok(constructor
            .calls
            .first()
            .map(|call| call.args.clone())
            .unwrap_or_default())
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

    // The section is a concatenation of entries; read until it runs out.
    // Read whole before planning: a function can name a type declared after it.
    let mut entries = Vec::new();
    let mut reader = Limited::new(spec, Limits::none());
    while let Ok(entry) = ScSpecEntry::read_xdr(&mut reader) {
        entries.push(entry);
    }
    let types = Types::from_spec(&entries);

    let mut constructor = None;
    let mut entrypoints = Vec::new();
    for entry in &entries {
        let ScSpecEntry::FunctionV0(function) = entry else {
            continue;
        };
        let name = function.name.to_utf8_string_lossy();
        let mut planned = plan_function(&name, function, &types);
        // Registration invokes the constructor, once per session; it is not
        // an entrypoint a caller drives.
        if name == wasm::CONSTRUCTOR_EXPORT {
            planned.calls.truncate(1);
            constructor = Some(planned);
        } else {
            entrypoints.push(planned);
        }
    }

    Ok(DrivePlan {
        constructor,
        entrypoints,
    })
}

/// Plan one entrypoint: generate its calls, or record why not.
fn plan_function(name: &str, function: &ScSpecFunctionV0, types: &Types) -> Entrypoint {
    let mut tables = Vec::with_capacity(function.inputs.len());
    for input in function.inputs.iter() {
        match values_for(&input.type_, types) {
            Some(values) if !values.is_empty() => tables.push(values),
            _ => {
                return Entrypoint {
                    name: name.to_string(),
                    calls: Vec::new(),
                    skipped: Some(format!(
                        "parameter `{}` is {}, which this generator does not construct",
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
        .map(|case| Call::new(name, sweep(&tables, case)))
        .collect();

    Entrypoint {
        name: name.to_string(),
        calls,
        skipped: None,
    }
}

/// The spec's own `#[contracttype]` definitions, which a `Udt` parameter
/// names.
#[derive(Debug, Default)]
struct Types {
    by_name: BTreeMap<String, ScSpecEntry>,
}

impl Types {
    fn from_spec(entries: &[ScSpecEntry]) -> Self {
        let by_name = entries
            .iter()
            .filter_map(|entry| {
                let name = match entry {
                    ScSpecEntry::UdtStructV0(s) => s.name.to_utf8_string_lossy(),
                    ScSpecEntry::UdtUnionV0(u) => u.name.to_utf8_string_lossy(),
                    ScSpecEntry::UdtEnumV0(e) => e.name.to_utf8_string_lossy(),
                    _ => return None,
                };
                Some((name, entry.clone()))
            })
            .collect();
        Self { by_name }
    }
}

/// Candidate values for a parameter type, or `None` when it is not one
/// this module can construct.
fn values_for(ty: &ScSpecTypeDef, types: &Types) -> Option<Vec<ScVal>> {
    values_at(ty, types, 0)
}

fn values_at(ty: &ScSpecTypeDef, types: &Types, depth: usize) -> Option<Vec<ScVal>> {
    if depth > MAX_DEPTH {
        return None;
    }
    if let Some(scalars) = scalar_values(ty) {
        return Some(scalars);
    }
    let inner = |ty: &ScSpecTypeDef| values_at(ty, types, depth + 1).filter(|v| !v.is_empty());
    Some(match ty {
        ScSpecTypeDef::Address => ACCOUNTS
            .iter()
            .map(|label| ScVal::Address(account(label)))
            .collect(),
        // A `MuxedAddress` parameter accepts a plain address too; one muxed
        // case reaches the branch that reads the id.
        ScSpecTypeDef::MuxedAddress => {
            let mut v: Vec<ScVal> = ACCOUNTS[..2]
                .iter()
                .map(|label| ScVal::Address(account(label)))
                .collect();
            v.push(ScVal::Address(ScAddress::MuxedAccount(
                MuxedEd25519Account {
                    id: MUXED_ID,
                    ed25519: Uint256(account_key(ACCOUNTS[2])),
                },
            )));
            v
        }
        ScSpecTypeDef::String => ["", "a", "sordec-harness"]
            .into_iter()
            .map(|s| Some(ScVal::String(ScString(s.try_into().ok()?))))
            .collect::<Option<_>>()?,
        ScSpecTypeDef::Symbol => ["a", "sordec", "Abc_123"]
            .into_iter()
            .map(|s| Some(ScVal::Symbol(ScSymbol(s.try_into().ok()?))))
            .collect::<Option<_>>()?,
        ScSpecTypeDef::Bytes => [vec![], vec![0], (0..32).collect::<Vec<u8>>()]
            .into_iter()
            .map(bytes_val)
            .collect::<Option<_>>()?,
        ScSpecTypeDef::BytesN(n) => {
            let n = n.n as usize;
            [
                vec![0; n],
                vec![0xff; n],
                (0..n).map(|i| (i * 37 + 1) as u8).collect(),
            ]
            .into_iter()
            .map(bytes_val)
            .collect::<Option<_>>()?
        }
        ScSpecTypeDef::Option(option) => {
            let some = inner(&option.value_type)?;
            vec![ScVal::Void, some[0].clone(), some[1 % some.len()].clone()]
        }
        ScSpecTypeDef::Vec(vec) => {
            let items = inner(&vec.element_type)?;
            let n = items.len();
            [
                vec![],
                vec![items[0].clone()],
                vec![items[1 % n].clone(), items[2 % n].clone()],
            ]
            .into_iter()
            .map(vec_val)
            .collect::<Option<_>>()?
        }
        ScSpecTypeDef::Map(map) => {
            let keys = inner(&map.key_type)?;
            let values = inner(&map.value_type)?;
            [vec![], vec![(keys[0].clone(), values[0].clone())]]
                .into_iter()
                .map(map_val)
                .collect::<Option<_>>()?
        }
        ScSpecTypeDef::Tuple(tuple) => {
            let tables: Vec<Vec<ScVal>> =
                tuple.value_types.iter().map(inner).collect::<Option<_>>()?;
            (0..3)
                .map(|case| vec_val(sweep(&tables, case)))
                .collect::<Option<_>>()?
        }
        ScSpecTypeDef::Udt(udt) => {
            udt_values(types.by_name.get(&udt.name.to_utf8_string_lossy())?, &inner)?
        }
        _ => return None,
    })
}

/// Values for one `#[contracttype]`, encoded the way the SDK encodes it.
fn udt_values(
    entry: &ScSpecEntry,
    inner: &dyn Fn(&ScSpecTypeDef) -> Option<Vec<ScVal>>,
) -> Option<Vec<ScVal>> {
    match entry {
        // A tuple struct (fields `0`, `1`, …) is a vector; a named one is a map
        // keyed by field name, which the host requires sorted.
        ScSpecEntry::UdtStructV0(s) => {
            let names: Vec<String> = s
                .fields
                .iter()
                .map(|f| f.name.to_utf8_string_lossy())
                .collect();
            let tables: Vec<Vec<ScVal>> = s
                .fields
                .iter()
                .map(|f| inner(&f.type_))
                .collect::<Option<_>>()?;
            let tuple = names.iter().all(|n| n.chars().all(|c| c.is_ascii_digit()));
            (0..3)
                .map(|case| {
                    let values = sweep(&tables, case);
                    if tuple {
                        return vec_val(values);
                    }
                    let mut fields: Vec<(ScVal, ScVal)> = names
                        .iter()
                        .zip(values)
                        .map(|(name, value)| {
                            Some((
                                ScVal::Symbol(ScSymbol(name.as_str().try_into().ok()?)),
                                value,
                            ))
                        })
                        .collect::<Option<_>>()?;
                    fields.sort_by(|a, b| a.0.cmp(&b.0));
                    map_val(fields)
                })
                .collect()
        }
        // A union case is a vector: its name, then its payload.
        ScSpecEntry::UdtUnionV0(u) => u
            .cases
            .iter()
            .enumerate()
            .map(|(index, case)| {
                let (name, payload) = match case {
                    ScSpecUdtUnionCaseV0::VoidV0(v) => (v.name.to_utf8_string_lossy(), Vec::new()),
                    ScSpecUdtUnionCaseV0::TupleV0(t) => {
                        let tables: Vec<Vec<ScVal>> =
                            t.type_.iter().map(inner).collect::<Option<_>>()?;
                        (t.name.to_utf8_string_lossy(), sweep(&tables, index))
                    }
                };
                let mut items = vec![ScVal::Symbol(ScSymbol(name.as_str().try_into().ok()?))];
                items.extend(payload);
                vec_val(items)
            })
            .collect(),
        ScSpecEntry::UdtEnumV0(e) => {
            Some(e.cases.iter().map(|case| ScVal::U32(case.value)).collect())
        }
        _ => None,
    }
}

/// One value from each table, offset by position — the same sweep
/// [`plan_function`] applies to a call's arguments.
fn sweep(tables: &[Vec<ScVal>], case: usize) -> Vec<ScVal> {
    tables
        .iter()
        .enumerate()
        .map(|(position, table)| table[(case + position) % table.len()].clone())
        .collect()
}

fn bytes_val(bytes: Vec<u8>) -> Option<ScVal> {
    Some(ScVal::Bytes(ScBytes(bytes.try_into().ok()?)))
}

fn vec_val(items: Vec<ScVal>) -> Option<ScVal> {
    Some(ScVal::Vec(Some(ScVec(items.try_into().ok()?))))
}

fn map_val(entries: Vec<(ScVal, ScVal)>) -> Option<ScVal> {
    let entries: Vec<ScMapEntry> = entries
        .into_iter()
        .map(|(key, val)| ScMapEntry { key, val })
        .collect();
    Some(ScVal::Map(Some(ScMap(entries.try_into().ok()?))))
}

/// Candidate values for a scalar type, or `None` when `ty` is not one.
fn scalar_values(ty: &ScSpecTypeDef) -> Option<Vec<ScVal>> {
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
        let values = values_for(&ScSpecTypeDef::U64, &Types::default()).expect("u64 is a scalar");
        assert!(values.contains(&ScVal::U64((1 << 56) - 1)));
        assert!(values.contains(&ScVal::U64(1 << 56)));
    }

    #[test]
    fn signed_tables_include_the_overflow_boundaries() {
        let values = values_for(&ScSpecTypeDef::I64, &Types::default()).expect("i64 is a scalar");
        assert!(values.contains(&ScVal::I64(i64::MIN)));
        assert!(values.contains(&ScVal::I64(i64::MAX)));
    }

    #[test]
    fn an_unsupported_parameter_is_declined_with_a_reason() {
        assert!(values_for(&ScSpecTypeDef::Val, &Types::default()).is_none());
        assert_eq!(type_name(&ScSpecTypeDef::Val), "an untyped Val");
    }

    #[test]
    fn addresses_are_the_harness_accounts_in_label_order() {
        let values = values_for(&ScSpecTypeDef::Address, &Types::default()).unwrap();
        let expected: Vec<ScVal> = ACCOUNTS
            .iter()
            .map(|l| ScVal::Address(account(l)))
            .collect();
        assert_eq!(values, expected);
        // The liquidity pool's constructor rejects `token_a >= token_b`.
        assert!(account(ACCOUNTS[0]) < account(ACCOUNTS[1]));
    }

    #[test]
    fn a_struct_is_a_map_with_sorted_field_keys() {
        use soroban_sdk::xdr::{ScSpecTypeUdt, ScSpecUdtStructFieldV0, ScSpecUdtStructV0};
        let field = |name: &str| ScSpecUdtStructFieldV0 {
            doc: "".try_into().unwrap(),
            name: name.try_into().unwrap(),
            type_: ScSpecTypeDef::U32,
        };
        let entry = ScSpecEntry::UdtStructV0(ScSpecUdtStructV0 {
            doc: "".try_into().unwrap(),
            lib: "".try_into().unwrap(),
            name: "Bound".try_into().unwrap(),
            // Declared out of order: the encoding must not follow declaration.
            fields: vec![field("timestamp"), field("kind")].try_into().unwrap(),
        });
        let types = Types::from_spec(&[entry]);
        let ty = ScSpecTypeDef::Udt(ScSpecTypeUdt {
            name: "Bound".try_into().unwrap(),
        });
        let values = values_for(&ty, &types).expect("a struct of scalars is constructible");
        let ScVal::Map(Some(map)) = &values[0] else {
            panic!("a named struct encodes as a map: {:?}", values[0]);
        };
        let keys: Vec<&ScVal> = map.0.iter().map(|e| &e.key).collect();
        assert_eq!(
            keys,
            [
                &ScVal::Symbol(ScSymbol("kind".try_into().unwrap())),
                &ScVal::Symbol(ScSymbol("timestamp".try_into().unwrap()))
            ]
        );
    }

    #[test]
    fn every_call_runs_once_per_round() {
        let call = Call::new("f", vec![]);
        let plan = DrivePlan {
            constructor: None,
            entrypoints: vec![Entrypoint {
                name: "f".into(),
                calls: vec![call.clone()],
                skipped: None,
            }],
        };
        assert_eq!(plan.calls(), vec![call; ROUNDS]);
        assert_eq!(plan.constructor_args(), Ok(vec![]));
    }

    #[test]
    fn generation_is_deterministic() {
        let a = values_for(&ScSpecTypeDef::U64, &Types::default()).unwrap();
        let b = values_for(&ScSpecTypeDef::U64, &Types::default()).unwrap();
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
        let planned = plan_function("add", &f, &Types::default());
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
            constructor: None,
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
