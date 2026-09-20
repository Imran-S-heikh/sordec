//! The source-level semantic-fact vocabulary.
//!
//! [`SemanticFact`] is a normalized, operand-light record of a recovered
//! Soroban operation, deliberately mirroring the pipeline's `KnownOp`
//! categories (`sordec-ir`'s `high::semantic`) so a source-side fact
//! multiset is comparable with what the recognizers recover. Facts are
//! compared by their [`SemanticFact::key_with`] — a canonical string — so two
//! facts are "the same" exactly when their keys are equal. Storage facts
//! carry their tier and (when resolvable) their key path, so a swapped tier
//! or an unrecovered storage key is a real semantic miss.

/// A recovered Soroban operation, extracted from source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SemanticFact {
    /// A storage CRUD/TTL operation on a durability tier.
    Storage {
        /// Which storage operation.
        op: StorageOp,
        /// The durability tier the chain named.
        tier: Tier,
        /// The `#[contracttype]` enum-variant key path (`DataKey::Balance`)
        /// when resolvable; `None` when the key is not a locally-provable
        /// variant constructor.
        key: Option<String>,
    },
    /// An authorization requirement.
    Auth(AuthKind),
    /// An event publication: anything invoked on `….events()` (covering SDK
    /// v22's `TokenUtils::new(&e).events().mint(…)` as well as
    /// `e.events().publish(…)`), or a `#[contractevent]` struct's `.publish`.
    ///
    /// Deliberately **unnamed** — every event compares equal to every other.
    /// Carrying the name would discriminate better, and the v22 API hands one
    /// over for free, but our emitter recovers `publish((v28,), v29)`: an
    /// opaque topic value with no recoverable name. Naming events would turn
    /// today's correct matches into mismatches, penalising the scorer for what
    /// the *emitter* cannot yet recover. Revisit if topic symbols become
    /// recoverable.
    Event,
    /// A cross-contract call whose receiver is a generated `*Client`. The
    /// method is the callee entrypoint name (a SEP-41 method, or another
    /// known client method).
    CrossContract {
        /// The called method name.
        method: String,
    },
    /// A panic / trap.
    Panic(PanicKind),
    /// A ledger-context query.
    Ledger(LedgerKind),
    /// A cryptographic host operation — anything invoked on `env.crypto()`
    /// (`sha256`, `keccak256`, `ed25519_verify`, …).
    ///
    /// Unlike [`SemanticFact::Event`], the operation **is** named: `sha256`
    /// and `keccak256` are different security properties and must not compare
    /// equal, and the name is genuinely recoverable — the pipeline already
    /// identifies these as `crypto::ComputeHashSha256` and friends. `String`
    /// rather than an enum because the SDK's op set is open-ended.
    Crypto {
        /// The called host operation, e.g. `sha256`.
        op: String,
    },
    /// A PRNG host operation — anything invoked on `env.prng()`
    /// (`gen_range`, `shuffle`, …). Named for the same reason as
    /// [`SemanticFact::Crypto`].
    Prng {
        /// The called host operation, e.g. `gen_range`.
        op: String,
    },
}

/// Storage operation kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StorageOp {
    /// `get`.
    Get,
    /// `set`.
    Set,
    /// `has`.
    Has,
    /// `remove`.
    Remove,
    /// `extend_ttl`.
    ExtendTtl,
}

/// Storage durability tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tier {
    /// `persistent()`.
    Persistent,
    /// `instance()`.
    Instance,
    /// `temporary()`.
    Temporary,
}

/// Authorization kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthKind {
    /// `require_auth`.
    RequireAuth,
    /// `require_auth_for_args`.
    RequireAuthForArgs,
    /// `authorize_as_current_contract`.
    AuthorizeAsCurrentContract,
}

/// Panic / trap kind.
///
/// An **argument-less** `panic!()` produces *no fact at all* (score-2.0.0
/// T18). It is an arg-decode trap the compiler inlined out of the SDK's
/// `try_from_val`, not a Soroban operation the contract performs — the same
/// marshalling-vs-semantics line `sordec-ir`'s `KnownOp` already draws, and
/// the one T17 followed when it kept `ValTagCheck` / `VecOp` / `MapOp` out of
/// this vocabulary.
///
/// The rule is **symmetric**: a *source* that writes a bare `panic!()` also
/// yields nothing. It is not a filter on our own output.
///
/// Before this, both spellings keyed as `panic:bare`, so token-v23's 60
/// emitted traps were credited as recovering the source's 5 authored
/// `panic!("insufficient balance")`-style panics — overlap the reconstruction
/// had not earned.
///
/// The traps are not thereby hidden. They are control flow, so the
/// **structure** category still counts every one of them, and its token census
/// reports the resulting bloat. Each category measures what it is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PanicKind {
    /// `panic!(…)` **with** arguments — an authored panic.
    Bare,
    /// `panic_with_error!(...)`.
    WithError,
    /// `.unwrap()` / `.expect(...)`.
    Unwrap,
}

impl SemanticFact {
    /// Whether this fact is one a reconstruction could recover at all.
    ///
    /// A fact scores a reconstruction on what it recovered from a
    /// binary. A fact whose *only* evidence the compiler deletes is not
    /// a thing to recover — scoring it marks a reconstruction down for
    /// the build's settings, which is the compiler's doing and not the
    /// decompiler's. Such a fact is dropped from **both** sides, the
    /// same discipline every category here already applies to what it
    /// cannot measure: an absent ABI kind drops out of `interface`'s
    /// mean, an entrypoint with no control flow on either side drops out
    /// of `structure`'s, and an unmeasurable category renormalises out
    /// of the overall rather than scoring zero.
    ///
    /// One fact qualifies today. [`PanicKind::Bare`] is an authored
    /// `panic!("…")`, and the message is the whole of what distinguishes
    /// it from the argument-less trap that yields no fact — so with the
    /// message gone there is nothing left to recognise. It is gone:
    /// across the four corpus contracts that write them, **0 of 24**
    /// distinct multi-word panic messages appear anywhere in the
    /// deployed wasm. A `no_std` release build with Soroban's panic
    /// handler drops the formatting machinery and the strings with it.
    ///
    /// `panic_with_error!` is *not* in the same position and still
    /// counts: its error code is a real value in the binary, and
    /// recovering it is recovering the contract's error surface. Nor is
    /// `.unwrap()`, whose trap is guarded by a check we do recover.
    pub(crate) fn is_recoverable(&self) -> bool {
        !matches!(self, SemanticFact::Panic(PanicKind::Bare))
    }
}

/// Ledger-context query kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LedgerKind {
    /// `current_contract_address`.
    CurrentContractAddress,
    /// `ledger().sequence()`.
    Sequence,
    /// `ledger().timestamp()`.
    Timestamp,
}

impl SemanticFact {
    /// The canonical comparison key for this fact. Equal keys mean equal
    /// facts for precision/recall.
    /// The comparison key, optionally without the *type* half of a
    /// storage key's name.
    ///
    /// A storage key reads `DataKey::Admin`: an enum's name and one of
    /// its variants. The variant is compiled into the contract — it is
    /// the rodata symbol the derived converter builds — but the enum's
    /// own name lives only in `contractspecv0`. Strip that section and
    /// the name is nowhere in the module, so a reconstruction has to
    /// synthesize one, and every storage fact it recovers perfectly
    /// then reads as both a miss and a false positive against the
    /// original's.
    ///
    /// `type_names: false` drops the qualifier from **both** sides, so
    /// the comparison is on what the module actually records: which
    /// variant, at which tier, under which operation. Callers pass it
    /// when the module declared no ABI; see `ScoreOptions::abi_declared`.
    pub(crate) fn key_with(&self, type_names: bool) -> String {
        match self {
            SemanticFact::Storage { op, tier, key } => format!(
                "storage:{}:{}:{}",
                op.token(),
                tier.token(),
                match key.as_deref() {
                    None => "?",
                    Some(k) if type_names => k,
                    // `DataKey::Allowance` -> `Allowance`.
                    Some(k) => k.rsplit("::").next().unwrap_or(k),
                }
            ),
            SemanticFact::Auth(kind) => format!("auth:{}", kind.token()),
            SemanticFact::Event => "event".to_string(),
            SemanticFact::CrossContract { method } => format!("xcall:{method}"),
            SemanticFact::Panic(kind) => format!("panic:{}", kind.token()),
            SemanticFact::Ledger(kind) => format!("ledger:{}", kind.token()),
            SemanticFact::Crypto { op } => format!("crypto:{op}"),
            SemanticFact::Prng { op } => format!("prng:{op}"),
        }
    }
}

impl StorageOp {
    fn token(self) -> &'static str {
        match self {
            StorageOp::Get => "get",
            StorageOp::Set => "set",
            StorageOp::Has => "has",
            StorageOp::Remove => "remove",
            StorageOp::ExtendTtl => "extend_ttl",
        }
    }
}

impl Tier {
    fn token(self) -> &'static str {
        match self {
            Tier::Persistent => "persistent",
            Tier::Instance => "instance",
            Tier::Temporary => "temporary",
        }
    }
}

impl AuthKind {
    fn token(self) -> &'static str {
        match self {
            AuthKind::RequireAuth => "require_auth",
            AuthKind::RequireAuthForArgs => "require_auth_for_args",
            AuthKind::AuthorizeAsCurrentContract => "authorize_as_current_contract",
        }
    }
}

impl PanicKind {
    fn token(self) -> &'static str {
        match self {
            PanicKind::Bare => "bare",
            PanicKind::WithError => "with_error",
            PanicKind::Unwrap => "unwrap",
        }
    }
}

impl LedgerKind {
    fn token(self) -> &'static str {
        match self {
            LedgerKind::CurrentContractAddress => "current_contract_address",
            LedgerKind::Sequence => "sequence",
            LedgerKind::Timestamp => "timestamp",
        }
    }
}
