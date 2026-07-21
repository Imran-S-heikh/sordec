//! The source-level semantic-fact vocabulary.
//!
//! [`SemanticFact`] is a normalized, operand-light record of a recovered
//! Soroban operation, deliberately mirroring the pipeline's `KnownOp`
//! categories (`sordec-ir`'s `high::semantic`) so a source-side fact
//! multiset is comparable with what the recognizers recover. Facts are
//! compared by their [`SemanticFact::key`] — a canonical string — so two
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
    /// An event publication (`events().publish` or a `#[contractevent]`
    /// struct's `.publish`).
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PanicKind {
    /// `panic!(...)`.
    Bare,
    /// `panic_with_error!(...)`.
    WithError,
    /// `.unwrap()` / `.expect(...)`.
    Unwrap,
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
    pub(crate) fn key(&self) -> String {
        match self {
            SemanticFact::Storage { op, tier, key } => format!(
                "storage:{}:{}:{}",
                op.token(),
                tier.token(),
                key.as_deref().unwrap_or("?")
            ),
            SemanticFact::Auth(kind) => format!("auth:{}", kind.token()),
            SemanticFact::Event => "event".to_string(),
            SemanticFact::CrossContract { method } => format!("xcall:{method}"),
            SemanticFact::Panic(kind) => format!("panic:{}", kind.token()),
            SemanticFact::Ledger(kind) => format!("ledger:{}", kind.token()),
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
