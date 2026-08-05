//! The signature catalogue: fingerprint → the library function it names.
//!
//! # Why the table is generated Rust rather than a data file
//!
//! The catalogue is built offline from labelled contract rebuilds (see the
//! crate docs) and compiled straight in. That buys three things a runtime
//! data file does not: no I/O and no failure mode at lookup time, no way
//! for a stale file to disagree with the binary that reads it, and the
//! table participates in `cargo check` — a malformed entry is a build
//! error rather than a mystery at run time.
//!
//! # The fail-closed gate
//!
//! [`CatalogueBuilder`] enforces the invariant the whole design rests on:
//! **a fingerprint claimed by two different functions is dropped, not
//! arbitrated.** There is no tie-break, no most-recently-seen, no
//! preferring the longer body. Identification decides what the decompiler
//! deletes; a wrong answer there corrupts output, while a missing answer
//! only leaves surplus code we were emitting anyway. The asymmetry is the
//! whole argument, and it is why zero false positives held across fourteen
//! measured runs.
//!
//! Deduplication is by *path*, not by occurrence: the same function found
//! in six corpus contracts is one entry, not a conflict.

use crate::fingerprint::Fingerprint;

/// Which library a catalogued function came from.
///
/// Kept coarse on purpose. The decompiler's decisions turn on "is this the
/// author's code or something linked in", and a finer split would invite
/// callers to reason about crate boundaries that inlining has already
/// erased.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CrateOrigin {
    /// `soroban_sdk` — the contract-facing SDK.
    Sdk,
    /// `soroban_env_common` — shared host/guest ABI types.
    EnvCommon,
    /// `soroban_env_guest` — the guest-side host-function bindings.
    EnvGuest,
    /// Rust's `core`.
    Core,
    /// Rust's `alloc`.
    Alloc,
}

impl CrateOrigin {
    /// The crate name as it appears in a mangled symbol, for generation and
    /// for diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sdk => "soroban_sdk",
            Self::EnvCommon => "soroban_env_common",
            Self::EnvGuest => "soroban_env_guest",
            Self::Core => "core",
            Self::Alloc => "alloc",
        }
    }

    /// Classify a demangled or mangled symbol path.
    ///
    /// Returns `None` for anything not attributable to a known library,
    /// which is the common case: it is the contract author's own code.
    #[must_use]
    pub fn classify(symbol: &str) -> Option<Self> {
        // Order matters: `soroban_env_guest` and `soroban_env_common` both
        // contain `soroban_env`, and an `impl` block can name several
        // crates in one symbol, so the most specific wins.
        if symbol.contains("soroban_env_guest") {
            Some(Self::EnvGuest)
        } else if symbol.contains("soroban_env_common") {
            Some(Self::EnvCommon)
        } else if symbol.contains("soroban_sdk") {
            Some(Self::Sdk)
        } else if symbol.starts_with("_ZN5alloc") || symbol.contains("alloc..") {
            Some(Self::Alloc)
        } else if symbol.starts_with("_ZN4core") || symbol.contains("core..") {
            Some(Self::Core)
        } else {
            None
        }
    }
}

/// One catalogued library function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigEntry {
    /// The masked structural fingerprint of the function's body.
    pub fingerprint: Fingerprint,
    /// The library path, e.g.
    /// `soroban_sdk::symbol::Symbol as TryFromVal`. Generic-instantiation
    /// hashes are stripped during generation, so one path may legitimately
    /// have several fingerprints — a generic compiled for two types is two
    /// different bodies.
    pub path: &'static str,
    /// Which library the function belongs to.
    pub origin: CrateOrigin,
    /// Instruction count of the body this was taken from, for diagnostics
    /// and for ranking a match's weight.
    pub insns: u16,
}

/// A sorted, binary-searchable set of [`SigEntry`].
#[derive(Debug, Clone, Copy)]
pub struct Catalogue {
    entries: &'static [SigEntry],
}

impl Catalogue {
    /// Wrap a table that is already sorted by fingerprint.
    ///
    /// # Panics
    ///
    /// In debug builds, if `entries` is not sorted — [`lookup`](Self::lookup)
    /// binary-searches and would silently miss otherwise. Generated tables
    /// are sorted by construction; this catches a hand-edited one.
    #[must_use]
    pub fn new(entries: &'static [SigEntry]) -> Self {
        debug_assert!(
            entries.windows(2).all(|w| w[0].fingerprint < w[1].fingerprint),
            "catalogue must be sorted by fingerprint and free of duplicates"
        );
        Self { entries }
    }

    /// The library function with this fingerprint, if any.
    #[must_use]
    pub fn lookup(&self, fingerprint: Fingerprint) -> Option<&'static SigEntry> {
        self.entries
            .binary_search_by(|e| e.fingerprint.cmp(&fingerprint))
            .ok()
            .map(|i| &self.entries[i])
    }

    /// How many functions the catalogue names.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the catalogue is empty — true before the first generation.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every entry, in fingerprint order.
    #[must_use]
    pub fn entries(&self) -> &'static [SigEntry] {
        self.entries
    }
}

/// An owned catalogue entry, as collected during generation.
///
/// The shipped [`SigEntry`] borrows `'static` strings from generated code;
/// this is its counterpart while the table is still being built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedEntry {
    /// See [`SigEntry::fingerprint`].
    pub fingerprint: Fingerprint,
    /// See [`SigEntry::path`].
    pub path: String,
    /// See [`SigEntry::origin`].
    pub origin: CrateOrigin,
    /// See [`SigEntry::insns`].
    pub insns: u16,
}

/// Accumulates observations and applies the fail-closed ambiguity gate.
///
/// Feed it every library function found in every corpus contract, in any
/// order; [`build`](Self::build) returns the entries safe to ship.
#[derive(Debug, Default)]
pub struct CatalogueBuilder {
    /// Every distinct path claiming each fingerprint, plus the first
    /// observation's payload.
    seen: std::collections::BTreeMap<Fingerprint, Observed>,
}

#[derive(Debug)]
struct Observed {
    paths: std::collections::BTreeSet<String>,
    origin: CrateOrigin,
    insns: u16,
}

/// What generation discarded, and why.
///
/// Reported rather than silently dropped: a rising `ambiguous` count means
/// the fingerprint is losing discriminating power and the normalisation
/// rules need revisiting, which is invisible if the number is not surfaced.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BuildStats {
    /// Distinct fingerprints observed.
    pub observed: usize,
    /// Fingerprints dropped because two or more paths claimed them.
    pub ambiguous: usize,
    /// Entries in the resulting catalogue.
    pub kept: usize,
}

impl CatalogueBuilder {
    /// Start an empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one library function observed in a labelled build.
    ///
    /// Seeing the same path at the same fingerprint repeatedly — which is
    /// normal, the SDK appears in every contract — collapses to one entry.
    pub fn observe(&mut self, fingerprint: Fingerprint, path: &str, origin: CrateOrigin, insns: u16) {
        self.seen
            .entry(fingerprint)
            .and_modify(|o| {
                o.paths.insert(path.to_owned());
            })
            .or_insert_with(|| Observed {
                paths: std::iter::once(path.to_owned()).collect(),
                origin,
                insns,
            });
    }

    /// Apply the ambiguity gate and return the shippable entries, sorted by
    /// fingerprint.
    ///
    /// Any fingerprint claimed by more than one path is dropped outright.
    #[must_use]
    pub fn build(self) -> (Vec<OwnedEntry>, BuildStats) {
        let observed = self.seen.len();
        let mut ambiguous = 0;
        let mut entries = Vec::with_capacity(observed);

        for (fingerprint, o) in self.seen {
            let Some(path) = o.paths.iter().next() else {
                continue;
            };
            if o.paths.len() > 1 {
                ambiguous += 1;
                continue;
            }
            entries.push(OwnedEntry {
                fingerprint,
                path: path.clone(),
                origin: o.origin,
                insns: o.insns,
            });
        }

        // BTreeMap iteration is already fingerprint-ordered; state it rather
        // than rely on it, since `Catalogue::new` asserts on the property.
        entries.sort_by_key(|e| e.fingerprint);
        let kept = entries.len();
        (entries, BuildStats { observed, ambiguous, kept })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(n: u128) -> Fingerprint {
        Fingerprint(n)
    }

    #[test]
    fn repeated_observation_of_one_path_is_one_entry() {
        let mut b = CatalogueBuilder::new();
        for _ in 0..6 {
            b.observe(fp(1), "soroban_sdk::storage::Instance::get", CrateOrigin::Sdk, 40);
        }
        let (entries, stats) = b.build();
        assert_eq!(entries.len(), 1);
        assert_eq!(stats.ambiguous, 0);
        assert_eq!(stats.kept, 1);
    }

    /// The gate the whole design rests on: two functions, one fingerprint,
    /// nothing ships.
    #[test]
    fn ambiguous_fingerprint_drops_both() {
        let mut b = CatalogueBuilder::new();
        b.observe(fp(7), "soroban_sdk::a::one", CrateOrigin::Sdk, 12);
        b.observe(fp(7), "soroban_sdk::b::two", CrateOrigin::Sdk, 12);
        let (entries, stats) = b.build();
        assert!(entries.is_empty(), "an ambiguous fingerprint must not ship");
        assert_eq!(stats.ambiguous, 1);
        assert_eq!(stats.kept, 0);
    }

    #[test]
    fn one_ambiguity_does_not_poison_its_neighbours() {
        let mut b = CatalogueBuilder::new();
        b.observe(fp(1), "sdk::good::first", CrateOrigin::Sdk, 20);
        b.observe(fp(2), "sdk::bad::a", CrateOrigin::Sdk, 20);
        b.observe(fp(2), "sdk::bad::b", CrateOrigin::Sdk, 20);
        b.observe(fp(3), "sdk::good::second", CrateOrigin::Sdk, 20);
        let (entries, stats) = b.build();
        assert_eq!(entries.len(), 2);
        assert_eq!(stats.observed, 3);
        assert_eq!(stats.ambiguous, 1);
    }

    #[test]
    fn output_is_sorted_for_binary_search() {
        let mut b = CatalogueBuilder::new();
        for n in [9_u128, 3, 7, 1] {
            b.observe(fp(n), &format!("sdk::f{n}"), CrateOrigin::Sdk, 10);
        }
        let (entries, _) = b.build();
        assert!(entries.windows(2).all(|w| w[0].fingerprint < w[1].fingerprint));
    }

    #[test]
    fn lookup_finds_and_misses() {
        static TABLE: &[SigEntry] = &[
            SigEntry {
                fingerprint: Fingerprint(10),
                path: "sdk::ten",
                origin: CrateOrigin::Sdk,
                insns: 5,
            },
            SigEntry {
                fingerprint: Fingerprint(20),
                path: "sdk::twenty",
                origin: CrateOrigin::EnvCommon,
                insns: 9,
            },
        ];
        let c = Catalogue::new(TABLE);
        assert_eq!(c.lookup(Fingerprint(20)).map(|e| e.path), Some("sdk::twenty"));
        assert!(c.lookup(Fingerprint(15)).is_none());
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn origin_classification() {
        assert_eq!(
            CrateOrigin::classify("_ZN11soroban_sdk7storage8Instance3get"),
            Some(CrateOrigin::Sdk)
        );
        assert_eq!(
            CrateOrigin::classify("_ZN18soroban_env_common3val3Val7has_tag"),
            Some(CrateOrigin::EnvCommon)
        );
        // Most specific wins: this names both guest and common.
        assert_eq!(
            CrateOrigin::classify("_ZN84_$LT$soroban_env_guest..guest..Guest$u20$as$u20$soroban_env_common"),
            Some(CrateOrigin::EnvGuest)
        );
        assert_eq!(CrateOrigin::classify("_ZN4core6result13unwrap_failed"), Some(CrateOrigin::Core));
        // The contract author's own code is the important negative.
        assert_eq!(
            CrateOrigin::classify("_ZN22soroban_token_contract9allowance14read_allowance"),
            None
        );
    }
}
