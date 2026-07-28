//! Running a contract in an in-process host and recording what it did.
//!
//! One [`Session`] owns one host and one registered contract. Both sides of a
//! comparison get their own session, seeded identically — which is what lets the
//! two runs be compared at all, and is cheaper to reason about than registering
//! both contracts in a shared host and then having to tell their addresses apart.
//!
//! # The four observations
//!
//! Every call records four things, kept separate and never blended into one
//! number: the returned value, the events published, the authorizations
//! required, and the contract's storage. "events 94%, storage 87%" tells you
//! where to work; a single "93%" does not.
//!
//! Everything is captured as XDR ([`ScVal`] and friends) rather than as the SDK's
//! `Val`. That is not incidental: a `Val` is a tagged word whose object payloads
//! are *handles into the host it came from*, so two `Val`s from two hosts can
//! carry the same logical value and still compare unequal. XDR is the value
//! itself.
//!
//! # Determinism
//!
//! Ledger sequence, timestamp and protocol version are pinned to the constants
//! below, so nothing observable depends on wall-clock time or on which host was
//! built first. The base PRNG seed needs no attention here — the SDK already
//! zeroes it when it constructs an `Env` (`soroban-sdk-23.5.3/src/env.rs:591`),
//! along with fixing the source account.

use soroban_sdk::testutils::{Events as _, Ledger as _};
use soroban_sdk::xdr::{LedgerEntry, LedgerKey, ScAddress, ScVal};
use soroban_sdk::{Address, Env, InvokeError, Symbol, TryFromVal, Val};

use crate::preflight::Unavailable;
use crate::wasm;

/// The ledger protocol version every session pins.
///
/// 23 because `soroban-env-host`'s `MIN_LEDGER_PROTOCOL_VERSION` constrains the
/// *ledger* to 23 while still admitting older *contracts* — B1 measured a
/// protocol-21 contract running on a protocol-23 host — so one host version runs
/// the whole corpus and the corpus does not fragment by protocol.
pub const PROTOCOL_VERSION: u32 = 23;

/// The ledger sequence number every session pins.
///
/// Any fixed value works; a contract reading `ledger().sequence()` must simply
/// read the *same* value on both sides.
pub const LEDGER_SEQUENCE: u32 = 1_000;

/// The ledger timestamp every session pins.
///
/// Fixed rather than current-time, or a contract comparing a stored deadline
/// against `now` would take a different branch depending on when the suite ran.
/// `timelock` does exactly that.
pub const LEDGER_TIMESTAMP: u64 = 1_700_000_000;

/// One invocation to perform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    /// The exported function name.
    pub function: String,
    /// Arguments, in declaration order.
    pub args: Vec<ScVal>,
}

impl Call {
    /// A call to `function` with `args`.
    #[must_use]
    pub fn new(function: impl Into<String>, args: Vec<ScVal>) -> Self {
        Self {
            function: function.into(),
            args,
        }
    }
}

/// How an invocation ended.
///
/// The distinction between the two failure variants is behaviourally real and
/// must not be flattened: a contract that returns error code 4 and one that traps
/// are doing different things, and a decompiler that turns the first into the
/// second has changed the contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The call returned a value.
    Value(ScVal),
    /// The call failed with a contract error code — `#[contracterror]` or
    /// `panic_with_error!`.
    ContractError(u32),
    /// The call trapped: a bare `panic!`, a host-function failure, or a runtime
    /// error. `InvokeError::Abort` carries no code, by construction.
    Aborted,
    /// An argument could not be converted into the host, so the call was never
    /// attempted. A harness fault rather than a contract observation — reported
    /// so it can never be mistaken for a behavioural difference.
    ArgumentRejected(String),
}

impl Outcome {
    /// Whether this outcome is a failure of any kind.
    ///
    /// Used to recognise the case where *both* sides failed, which is agreement
    /// that demonstrates nothing and is bucketed separately.
    #[must_use]
    pub fn is_failure(&self) -> bool {
        !matches!(self, Self::Value(_))
    }
}

/// One published event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedEvent {
    /// Address of the contract that published it.
    pub contract: ScVal,
    /// Event topics, in order.
    pub topics: Vec<ScVal>,
    /// Event data.
    pub data: ScVal,
}

/// One address's authorization tree for a call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedAuth {
    /// The address whose authorization was required.
    pub address: ScVal,
    /// What it authorized.
    pub invocation: AuthNode,
}

/// A node in an authorization tree.
///
/// Shape matters as much as content: `require_auth` and `require_auth_for_args`
/// produce different trees for the same call, and that difference is observable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthNode {
    /// A contract function that called `require_auth[_for_args]`.
    Contract {
        /// Address of the contract whose function was authorized.
        contract: ScVal,
        /// The function name, as an `ScVal::Symbol`.
        function: ScVal,
        /// The arguments the authorization covers — *not* necessarily the
        /// invocation's own arguments, which is the whole point of
        /// `require_auth_for_args`.
        args: Vec<ScVal>,
        /// Authorizations originating from this one.
        sub_invocations: Vec<AuthNode>,
    },
    /// A contract-creation host function.
    ///
    /// Rendered rather than structured: no fixture in the corpus authorizes a
    /// deployment, so a structured form would ship unexercised. The rendering is
    /// derived and deterministic, so it compares correctly.
    CreateContract {
        /// Debug rendering of the creation arguments.
        rendered: String,
        /// Authorizations originating from this one.
        sub_invocations: Vec<AuthNode>,
    },
}

/// One ledger entry after a call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedEntry {
    /// The entry's key.
    pub key: LedgerKey,
    /// The entry itself.
    pub entry: LedgerEntry,
    /// Time-to-live, when the entry kind has one. A differing TTL is a real
    /// behavioural difference — it decides when the entry is archived.
    pub ttl: Option<u32>,
}

/// Everything one call produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// How the call ended.
    pub outcome: Outcome,
    /// Events published *by this call*, not cumulatively.
    pub events: Vec<ObservedEvent>,
    /// Authorizations this call required.
    pub auths: Vec<ObservedAuth>,
    /// Full contract storage after the call. Cumulative by nature: storage is
    /// state, and the state a call leaves behind is what the next call sees.
    pub storage: Vec<ObservedEntry>,
}

/// A host with one contract registered in it.
pub struct Session {
    env: Env,
    contract: Address,
    /// How many events the host had published by the end of the previous call,
    /// so each call reports only its own. `events().all()` is cumulative.
    events_seen: usize,
}

/// Names the session by what it is running, not by dumping the host.
///
/// Hand-written rather than derived: an `Env`'s own `Debug` renders the whole
/// budget and storage map, which turns a one-line assertion failure into pages.
impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("contract", &self.contract)
            .field("events_seen", &self.events_seen)
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Register `wasm` in a freshly seeded host.
    ///
    /// # Errors
    ///
    /// [`Unavailable`] when the module cannot be registered — checked from the bytes
    /// first, because `Env::register` reports both of these by *panicking*, and a
    /// harness whose discipline is to degrade with a reason cannot have the SDK abort
    /// a corpus run halfway through.
    ///
    /// Two cases, both found on real fixtures:
    ///
    /// - **No `contractenvmetav0`.** The host checks this on every module load
    ///   (`parsed_module.rs:301`) and refuses without it. `token-v23-stripped` has no
    ///   custom sections at all.
    /// - **A constructor.** Registration runs `__constructor`, and it takes
    ///   arguments on every corpus contract that has one, so registering with none
    ///   fails inside the VM with `MismatchingParameterLen`. Supplying them needs
    ///   input generation.
    ///
    /// A module malformed in some *other* way will still panic inside the SDK. That
    /// has not been observed, and pre-validating the whole module format to rule it
    /// out would mean reimplementing the host's verifier.
    pub fn register(wasm: &[u8]) -> Result<Self, Unavailable> {
        if !wasm::is_loadable(wasm) {
            return Err(Unavailable {
                reason: format!(
                    "wasm has no `{}` section, which the host requires on every \
                     module load, so this contract can never be executed",
                    wasm::ENV_META_SECTION
                ),
            });
        }
        if wasm::has_constructor(wasm) {
            return Err(Unavailable {
                reason: format!(
                    "contract exports `{}`, which registration invokes; every corpus \
                     contract with one takes arguments, so registering without them \
                     fails in the VM. Supplying them needs input generation.",
                    wasm::CONSTRUCTOR_EXPORT
                ),
            });
        }

        let env = Env::default();
        env.ledger().set_protocol_version(PROTOCOL_VERSION);
        env.ledger().set_sequence_number(LEDGER_SEQUENCE);
        env.ledger().set_timestamp(LEDGER_TIMESTAMP);

        let contract = env.register(wasm, ());
        Ok(Self {
            env,
            contract,
            events_seen: 0,
        })
    }

    /// The registered contract's address.
    ///
    /// The caller binds this to [`crate::canon::SELF_LABEL`] in its
    /// [`AddressBook`](crate::canon::AddressBook) so the two sides' differing
    /// addresses compare equal.
    #[must_use]
    pub fn contract_address(&self) -> ScAddress {
        // `From<&Address> for ScVal` yields `ScVal::Address`, always.
        match ScVal::from(&self.contract) {
            ScVal::Address(address) => address,
            other => unreachable!("an Address must convert to ScVal::Address, got {other:?}"),
        }
    }

    /// Treat every `require_auth` as satisfied.
    ///
    /// Authorizations are still *recorded* — this is what makes the auth tree
    /// observable at all, since without it an auth-requiring call fails before it
    /// does anything and both sides trivially agree.
    pub fn mock_all_auths(&self) {
        self.env.mock_all_auths();
    }

    /// Perform `call` and record what happened.
    #[must_use]
    pub fn call(&mut self, call: &Call) -> Observation {
        let args = match self.host_args(&call.args) {
            Ok(args) => args,
            Err(reason) => {
                return Observation {
                    outcome: Outcome::ArgumentRejected(reason),
                    events: Vec::new(),
                    auths: Vec::new(),
                    storage: self.storage(),
                };
            }
        };

        let function = Symbol::new(&self.env, &call.function);
        let outcome = self.invoke(&function, args);

        Observation {
            outcome,
            events: self.new_events(),
            auths: self.auths(),
            storage: self.storage(),
        }
    }

    /// Convert XDR arguments into host values.
    fn host_args(&self, args: &[ScVal]) -> Result<soroban_sdk::Vec<Val>, String> {
        let mut host_args = soroban_sdk::Vec::new(&self.env);
        for (index, arg) in args.iter().enumerate() {
            let val = Val::try_from_val(&self.env, arg)
                .map_err(|_| format!("argument {index} ({arg:?}) is not representable in the host"))?;
            host_args.push_back(val);
        }
        Ok(host_args)
    }

    /// Invoke and classify the result.
    fn invoke(&self, function: &Symbol, args: soroban_sdk::Vec<Val>) -> Outcome {
        // `InvokeError` for the error type rather than a contract-specific
        // `#[contracterror]`: the harness is generic over contracts and cannot
        // know their error enums. Both `Err` arms carry an `InvokeError`, so they
        // collapse to one classification.
        let result = self
            .env
            .try_invoke_contract::<Val, InvokeError>(&self.contract, function, args);

        match result {
            Ok(Ok(value)) => match ScVal::try_from_val(&self.env, &value) {
                Ok(scval) => Outcome::Value(scval),
                Err(_) => Outcome::ArgumentRejected(
                    "the returned value is not representable as XDR".to_owned(),
                ),
            },
            // `T = Val` converts infallibly, so this arm is unreachable in
            // practice; classified rather than `unreachable!` so a future `T`
            // cannot turn it into a panic.
            Ok(Err(_)) => {
                Outcome::ArgumentRejected("the returned value could not be converted".to_owned())
            }
            Err(Ok(error) | Err(error)) => match error {
                InvokeError::Contract(code) => Outcome::ContractError(code),
                InvokeError::Abort => Outcome::Aborted,
            },
        }
    }

    /// Events published since the previous call.
    fn new_events(&mut self) -> Vec<ObservedEvent> {
        let all = self.env.events().all();
        let fresh: Vec<ObservedEvent> = all
            .iter()
            .skip(self.events_seen)
            .map(|(contract, topics, data)| ObservedEvent {
                contract: ScVal::from(&contract),
                topics: topics
                    .iter()
                    .map(|topic| self.to_xdr(&topic))
                    .collect(),
                data: self.to_xdr(&data),
            })
            .collect();
        self.events_seen = all.len() as usize;
        fresh
    }

    /// Authorizations recorded for the most recent top-level invocation.
    fn auths(&self) -> Vec<ObservedAuth> {
        self.env
            .auths()
            .into_iter()
            .map(|(address, invocation)| ObservedAuth {
                address: ScVal::from(&address),
                invocation: self.auth_node(&invocation),
            })
            .collect()
    }

    /// Convert one authorization-tree node.
    fn auth_node(&self, node: &soroban_sdk::testutils::AuthorizedInvocation) -> AuthNode {
        use soroban_sdk::testutils::AuthorizedFunction;

        let sub_invocations = node
            .sub_invocations
            .iter()
            .map(|sub| self.auth_node(sub))
            .collect();

        match &node.function {
            AuthorizedFunction::Contract((contract, function, args)) => AuthNode::Contract {
                contract: ScVal::from(contract),
                function: self.to_xdr(&function.to_val()),
                args: args.iter().map(|arg| self.to_xdr(&arg)).collect(),
                sub_invocations,
            },
            AuthorizedFunction::CreateContractHostFn(args) => AuthNode::CreateContract {
                rendered: format!("{args:?}"),
                sub_invocations,
            },
            AuthorizedFunction::CreateContractV2HostFn(args) => AuthNode::CreateContract {
                rendered: format!("{args:?}"),
                sub_invocations,
            },
        }
    }

    /// The full ledger-entry set, with TTLs.
    fn storage(&self) -> Vec<ObservedEntry> {
        self.env
            .to_ledger_snapshot()
            .ledger_entries
            .into_iter()
            .map(|(key, (entry, ttl))| ObservedEntry {
                key: *key,
                entry: *entry,
                ttl,
            })
            .collect()
    }

    /// A host value as XDR.
    ///
    /// A value the host produced is representable by construction; the fallback
    /// keeps this total rather than introducing a panic path into observation
    /// capture, where a panic would lose the whole comparison.
    fn to_xdr(&self, value: &Val) -> ScVal {
        ScVal::try_from_val(&self.env, value).unwrap_or(ScVal::Void)
    }
}
