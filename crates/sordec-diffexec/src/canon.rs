//! Making two independently-registered contracts' observations comparable.
//!
//! Addresses are the one part of an observation that legitimately differs between
//! two runs while meaning the same thing: register the same wasm in two hosts and
//! it lands at whatever address that host hands out. Any observation mentioning
//! the contract's own address — a returned `current_contract_address()`, an event
//! source, a storage key — would then differ for a reason that is not a
//! behavioural difference.
//!
//! # Normalise, never skip
//!
//! The tempting shortcut is to drop address-typed fields from the comparison.
//! That would blind the harness to the single most valuable class of bug a
//! decompiler produces: a swapped argument, money sent to the wrong party. So
//! addresses are rewritten, not removed, and the rewrite is *role-based*.
//!
//! # Why role-based, and not first-appearance
//!
//! Labelling addresses in order of first appearance is the obvious approach and
//! it is wrong. If side A emits `(alice, bob)` and side B emits `(bob, alice)`,
//! first-appearance labelling assigns `addr_0`/`addr_1` to whichever came first
//! *on that side* — and both sides render as `(addr_0, addr_1)`. The swap
//! disappears exactly where it matters.
//!
//! An [`AddressBook`] instead binds a label to each address the harness *chose*
//! (`self` for the contract under test; `user_0`, `token_a`, … once generation
//! lands), and both sides are rewritten through the same role→label mapping. A
//! swap then shows up as `user_0` where the other side has `user_1`.
//!
//! Addresses the harness did not supply — ones a contract generated itself — have
//! no role to key on, so they fall back to first-appearance labelling and are
//! counted in [`Canonicalized::unbound`] so a report can say how much of the
//! comparison rests on the weaker rule.
//!
//! # Type-preserving rewrite
//!
//! A label is substituted as a *synthetic address*, not as a symbol or a string,
//! so an `ScVal::Address` stays an `ScVal::Address` and a type change can never
//! masquerade as a match. The synthetic bytes are derived from the label, so they
//! are identical across sides and across runs.

use std::collections::BTreeMap;

use soroban_sdk::xdr::{
    ContractDataEntry, ContractExecutable, Hash, LedgerEntry, LedgerEntryData, LedgerKey,
    LedgerKeyContractData, ScAddress, ScContractInstance, ScMap, ScMapEntry, ScVal, ScVec,
};

use crate::exec::{AuthNode, ObservedAuth, ObservedEntry, ObservedEvent, Observation, Outcome};

/// Byte prefix of every synthetic address, so a canonicalised address is
/// recognisable in a raw diff and cannot collide with a real contract hash.
const SYNTHETIC_PREFIX: &[u8] = b"sordec-canon:";

/// The label given to the contract currently under test.
pub const SELF_LABEL: &str = "self";

/// A role→address mapping, shared by both sides of a comparison.
///
/// Built by the harness from the addresses it controls. Both sides are
/// canonicalised through the *same* book, which is what makes an argument swap
/// visible — see the module docs.
#[derive(Debug, Clone, Default)]
pub struct AddressBook {
    /// Role label for each address the harness bound.
    labels: BTreeMap<ScAddress, String>,
}

impl AddressBook {
    /// An empty book.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind `address` to `label`.
    ///
    /// Re-binding an address replaces its label; the last binding wins. A book is
    /// built once per side before any call runs, so this is a setup operation
    /// rather than something a comparison mutates.
    pub fn bind(&mut self, label: impl Into<String>, address: ScAddress) {
        self.labels.insert(address, label.into());
    }

    /// The label bound to `address`, if any.
    #[must_use]
    pub fn label_of(&self, address: &ScAddress) -> Option<&str> {
        self.labels.get(address).map(String::as_str)
    }

    /// How many addresses are bound.
    #[must_use]
    pub fn len(&self) -> usize {
        self.labels.len()
    }

    /// Whether no address is bound.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.labels.is_empty()
    }
}

/// The synthetic address a label canonicalises to.
///
/// Deterministic in the label alone, so the two sides of a comparison produce
/// identical bytes without coordinating. Truncation of a long label is harmless:
/// labels are harness-chosen and short, and a collision would only ever merge two
/// roles the harness itself named the same.
#[must_use]
pub fn synthetic_address(label: &str) -> ScAddress {
    let mut bytes = [0u8; 32];
    let prefix_len = SYNTHETIC_PREFIX.len().min(bytes.len());
    bytes[..prefix_len].copy_from_slice(&SYNTHETIC_PREFIX[..prefix_len]);

    let label_bytes = label.as_bytes();
    let room = bytes.len() - prefix_len;
    let take = label_bytes.len().min(room);
    bytes[prefix_len..prefix_len + take].copy_from_slice(&label_bytes[..take]);

    ScAddress::Contract(Hash(bytes).into())
}

/// Whether a ledger entry is host or registration bookkeeping rather than state
/// the contract authored.
///
/// Measured on hello-add, which stores nothing: a single `add(2,3)` leaves
/// **three** ledger entries behind, none of them written by the contract. All
/// three are excluded — see [`Canonicalizer::storage`] for the reasoning on each.
fn is_bookkeeping(entry: &ObservedEntry) -> bool {
    // The wasm itself. Different on the two sides by definition.
    if matches!(entry.key, LedgerKey::ContractCode(_)) {
        return true;
    }
    let LedgerKey::ContractData(key) = &entry.key else {
        return false;
    };
    match &key.key {
        // The host's authorization replay-protection nonce.
        ScVal::LedgerKeyNonce(_) => true,
        // The instance entry — bookkeeping only while its storage map is empty.
        ScVal::LedgerKeyContractInstance => instance_storage_is_empty(&entry.entry),
        _ => false,
    }
}

/// Whether a contract-instance entry carries no `env.storage().instance()` state.
///
/// A non-instance entry answers `false`: there is no instance map to be empty, so
/// it is not bookkeeping on these grounds.
fn instance_storage_is_empty(entry: &LedgerEntry) -> bool {
    let LedgerEntryData::ContractData(data) = &entry.data else {
        return false;
    };
    let ScVal::ContractInstance(instance) = &data.val else {
        return false;
    };
    instance.storage.as_ref().is_none_or(|map| map.0.is_empty())
}

/// A canonicalising rewriter, carrying the fallback state for addresses the book
/// does not know.
///
/// One rewriter is used for a whole side, so first-appearance numbering of unbound
/// addresses is stable across every call in that side's sequence.
#[derive(Debug)]
pub struct Canonicalizer<'book> {
    book: &'book AddressBook,
    /// Labels invented for addresses the book did not bind, in order of first
    /// appearance within this side.
    invented: BTreeMap<ScAddress, String>,
}

/// What a side's canonicalisation rested on, so a report can qualify it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Canonicalized {
    /// Addresses matched to a harness-supplied role. Comparison over these is
    /// swap-detecting.
    pub bound: usize,
    /// Addresses labelled by first appearance because no role was known. A swap
    /// confined entirely to these is not guaranteed to be visible.
    pub unbound: usize,
}

impl<'book> Canonicalizer<'book> {
    /// A rewriter over `book`.
    #[must_use]
    pub fn new(book: &'book AddressBook) -> Self {
        Self {
            book,
            invented: BTreeMap::new(),
        }
    }

    /// What this rewriter has relied on so far.
    #[must_use]
    pub fn accounting(&self) -> Canonicalized {
        Canonicalized {
            bound: self.book.len(),
            unbound: self.invented.len(),
        }
    }

    /// Rewrite every address inside `value` through the book.
    #[must_use]
    pub fn value(&mut self, value: &ScVal) -> ScVal {
        match value {
            ScVal::Address(address) => ScVal::Address(self.address(address)),
            ScVal::Vec(Some(items)) => {
                let rewritten: Vec<ScVal> = items.0.iter().map(|v| self.value(v)).collect();
                // A `ScVec` is a length-bounded vector; the input was already
                // within bounds and rewriting preserves length, so the
                // conversion cannot fail. Falling back to the original rather
                // than unwrapping keeps this total.
                rewritten
                    .try_into()
                    .map_or_else(|_| value.clone(), |v: ScVec| ScVal::Vec(Some(v)))
            }
            ScVal::Map(Some(entries)) => {
                let rewritten: Vec<ScMapEntry> = entries
                    .0
                    .iter()
                    .map(|entry| ScMapEntry {
                        key: self.value(&entry.key),
                        val: self.value(&entry.val),
                    })
                    .collect();
                rewritten
                    .try_into()
                    .map_or_else(|_| value.clone(), |m: ScMap| ScVal::Map(Some(m)))
            }
            // Everything else is a scalar or an opaque byte string: no address
            // can hide inside it, so it passes through untouched.
            other => other.clone(),
        }
    }

    /// Canonicalise a whole observation.
    ///
    /// Addresses are rewritten throughout. Storage additionally has two things
    /// removed that differ between the two sides *by construction* and are not
    /// behaviour — see [`Self::storage`].
    #[must_use]
    pub fn observation(&mut self, observation: &Observation) -> Observation {
        Observation {
            outcome: self.outcome(&observation.outcome),
            events: observation
                .events
                .iter()
                .map(|event| ObservedEvent {
                    contract: self.value(&event.contract),
                    topics: event.topics.iter().map(|t| self.value(t)).collect(),
                    data: self.value(&event.data),
                })
                .collect(),
            auths: observation
                .auths
                .iter()
                .map(|auth| ObservedAuth {
                    address: self.value(&auth.address),
                    invocation: self.auth_node(&auth.invocation),
                })
                .collect(),
            storage: self.storage(&observation.storage),
        }
    }

    /// Canonicalise an outcome. Only [`Outcome::Value`] can carry an address.
    #[must_use]
    pub fn outcome(&mut self, outcome: &Outcome) -> Outcome {
        match outcome {
            Outcome::Value(value) => Outcome::Value(self.value(value)),
            other => other.clone(),
        }
    }

    /// Canonicalise an authorization tree.
    #[must_use]
    pub fn auth_node(&mut self, node: &AuthNode) -> AuthNode {
        match node {
            AuthNode::Contract {
                contract,
                function,
                args,
                sub_invocations,
            } => AuthNode::Contract {
                contract: self.value(contract),
                function: function.clone(),
                args: args.iter().map(|arg| self.value(arg)).collect(),
                sub_invocations: sub_invocations.iter().map(|s| self.auth_node(s)).collect(),
            },
            AuthNode::CreateContract {
                rendered,
                sub_invocations,
            } => AuthNode::CreateContract {
                rendered: rendered.clone(),
                sub_invocations: sub_invocations.iter().map(|s| self.auth_node(s)).collect(),
            },
        }
    }

    /// Canonicalise a storage snapshot.
    ///
    /// Two exclusions, both mandatory, both because the thing excluded differs
    /// between the sides *by construction* rather than because the contracts
    /// behave differently:
    ///
    /// 1. **`ContractCode` entries are dropped.** They hold the wasm itself. The
    ///    original and the reconstruction are different bytes — that is the entire
    ///    premise of the exercise — so comparing them would report a divergence on
    ///    every contract, forever, while saying nothing about behaviour.
    /// 2. **The instance entry's `executable` hash is flattened.** Registering a
    ///    contract writes a `ContractData` entry keyed
    ///    `ScVal::LedgerKeyContractInstance` whose value embeds the code hash.
    ///    Same problem. The instance entry is *kept*, because its `storage` map is
    ///    `env.storage().instance()` — genuinely contract-authored state — and
    ///    only the executable's hash is neutralised. `StellarAsset` executables
    ///    pass through unflattened: "is a Stellar asset" versus "has wasm" is a
    ///    real difference, and neither side's is a hash.
    ///
    /// 3. **An empty contract-instance entry is dropped.** Registering *any*
    ///    contract writes that entry whether or not the contract ever touches
    ///    storage, so keeping it would make the storage tuple look exercised on a
    ///    contract that stores nothing — and then hand it a free 1.0 for matching
    ///    registration bookkeeping. That is the diluting free match T13d removed
    ///    from the structure category, and it does not get to come back here. An
    ///    instance entry with a *non-empty* `storage` map is real
    ///    `env.storage().instance()` state and is kept.
    /// 4. **Authorization nonce entries are dropped.** The host writes an
    ///    `ScVal::LedgerKeyNonce` entry as replay protection; the nonce is
    ///    PRNG-derived and the entry is not contract-authored. A difference in
    ///    authorization behaviour is real, but the *auth* tuple reports it
    ///    legibly — as a tree — where storage would report it as an opaque
    ///    64-bit number. Measuring it twice, once unreadably, adds noise.
    ///
    /// Together these are why hello-add — which stores nothing — correctly reports
    /// storage as *not exercised* despite leaving three ledger entries behind.
    ///
    /// Classic-Stellar entry kinds (accounts, trustlines, offers) are passed
    /// through untouched: a contract host cannot create them, so they are not
    /// reachable here and inventing handling for them would ship unexercised.
    #[must_use]
    pub fn storage(&mut self, entries: &[ObservedEntry]) -> Vec<ObservedEntry> {
        entries
            .iter()
            .filter(|entry| !is_bookkeeping(entry))
            .map(|entry| ObservedEntry {
                key: self.ledger_key(&entry.key),
                entry: self.ledger_entry(&entry.entry),
                ttl: entry.ttl,
            })
            .collect()
    }

    /// Rewrite the addresses in a ledger key.
    fn ledger_key(&mut self, key: &LedgerKey) -> LedgerKey {
        match key {
            LedgerKey::ContractData(data) => LedgerKey::ContractData(LedgerKeyContractData {
                contract: self.address(&data.contract),
                key: self.value(&data.key),
                durability: data.durability,
            }),
            other => other.clone(),
        }
    }

    /// Rewrite the addresses in a ledger entry, flattening any embedded code
    /// hash.
    fn ledger_entry(&mut self, entry: &LedgerEntry) -> LedgerEntry {
        let LedgerEntryData::ContractData(data) = &entry.data else {
            return entry.clone();
        };
        LedgerEntry {
            last_modified_ledger_seq: entry.last_modified_ledger_seq,
            data: LedgerEntryData::ContractData(ContractDataEntry {
                ext: data.ext.clone(),
                contract: self.address(&data.contract),
                key: self.value(&data.key),
                durability: data.durability,
                val: self.instance_aware_value(&data.val),
            }),
            ext: entry.ext.clone(),
        }
    }

    /// Like [`Self::value`], but additionally flattens the code hash inside a
    /// contract-instance value. See [`Self::storage`] for why.
    fn instance_aware_value(&mut self, value: &ScVal) -> ScVal {
        let ScVal::ContractInstance(instance) = value else {
            return self.value(value);
        };
        let executable = match &instance.executable {
            ContractExecutable::Wasm(_) => ContractExecutable::Wasm(Hash([0u8; 32])),
            other => other.clone(),
        };
        let storage = instance.storage.as_ref().and_then(|map| {
            let rewritten: Vec<ScMapEntry> = map
                .0
                .iter()
                .map(|entry| ScMapEntry {
                    key: self.value(&entry.key),
                    val: self.value(&entry.val),
                })
                .collect();
            rewritten.try_into().ok()
        });
        ScVal::ContractInstance(ScContractInstance {
            executable,
            storage,
        })
    }

    /// Rewrite a bare address.
    #[must_use]
    pub fn address(&mut self, address: &ScAddress) -> ScAddress {
        if let Some(label) = self.book.label_of(address) {
            return synthetic_address(label);
        }
        // Unbound: first appearance decides the number. Deliberately *not* keyed
        // on the address bytes, which differ between hosts by construction.
        let next = self.invented.len();
        let label = self
            .invented
            .entry(address.clone())
            .or_insert_with(|| format!("unbound_{next}"))
            .clone();
        synthetic_address(&label)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::xdr::{
        ContractDataDurability, ExtensionPoint, LedgerEntryExt, LedgerKeyContractCode, ScNonceKey,
    };

    fn contract_address(byte: u8) -> ScAddress {
        ScAddress::Contract(Hash([byte; 32]).into())
    }

    fn address_val(byte: u8) -> ScVal {
        ScVal::Address(contract_address(byte))
    }

    #[test]
    fn a_bound_address_canonicalises_to_its_role() {
        let mut book = AddressBook::new();
        book.bind(SELF_LABEL, contract_address(1));
        let mut canon = Canonicalizer::new(&book);

        assert_eq!(canon.address(&contract_address(1)), synthetic_address(SELF_LABEL));
    }

    #[test]
    fn two_hosts_with_different_addresses_agree_after_canonicalisation() {
        // The core reason this module exists: the same contract registered in two
        // hosts lands at two addresses and must still compare equal.
        let mut book_a = AddressBook::new();
        book_a.bind(SELF_LABEL, contract_address(0xaa));
        let mut book_b = AddressBook::new();
        book_b.bind(SELF_LABEL, contract_address(0xbb));

        let a = Canonicalizer::new(&book_a).value(&address_val(0xaa));
        let b = Canonicalizer::new(&book_b).value(&address_val(0xbb));
        assert_eq!(a, b);
    }

    #[test]
    fn a_swap_between_bound_roles_survives_canonicalisation() {
        // The failure that first-appearance labelling would hide. Both sides know
        // the same two roles; B returns them in the other order.
        let mut book = AddressBook::new();
        book.bind("user_0", contract_address(1));
        book.bind("user_1", contract_address(2));

        let pair = |first: u8, second: u8| {
            let items: ScVec = vec![address_val(first), address_val(second)].try_into().unwrap();
            Canonicalizer::new(&book).value(&ScVal::Vec(Some(items)))
        };

        assert_ne!(
            pair(1, 2),
            pair(2, 1),
            "an argument swap between known roles must not canonicalise away"
        );
    }

    #[test]
    fn addresses_nested_in_maps_and_vecs_are_rewritten() {
        let mut book = AddressBook::new();
        book.bind(SELF_LABEL, contract_address(7));
        let mut canon = Canonicalizer::new(&book);

        let entries: ScMap = vec![ScMapEntry {
            key: ScVal::U32(1),
            val: ScVal::Vec(Some(vec![address_val(7)].try_into().unwrap())),
        }]
        .try_into()
        .unwrap();

        let rewritten = canon.value(&ScVal::Map(Some(entries)));
        let expected_leaf = ScVal::Address(synthetic_address(SELF_LABEL));
        let ScVal::Map(Some(out)) = &rewritten else {
            panic!("map must stay a map: {rewritten:?}");
        };
        let ScVal::Vec(Some(inner)) = &out.0[0].val else {
            panic!("nested vec must stay a vec");
        };
        assert_eq!(inner.0[0], expected_leaf);
    }

    #[test]
    fn an_unbound_address_is_numbered_by_first_appearance_and_counted() {
        let book = AddressBook::new();
        let mut canon = Canonicalizer::new(&book);

        let first = canon.address(&contract_address(9));
        let second = canon.address(&contract_address(8));
        // Stable within a side: asking again returns the same label.
        assert_eq!(canon.address(&contract_address(9)), first);
        assert_ne!(first, second);

        // And the weaker rule is accounted for rather than silently applied.
        assert_eq!(canon.accounting(), Canonicalized { bound: 0, unbound: 2 });
    }

    #[test]
    fn a_scalar_passes_through_untouched() {
        let book = AddressBook::new();
        let mut canon = Canonicalizer::new(&book);
        assert_eq!(canon.value(&ScVal::U32(42)), ScVal::U32(42));
        assert_eq!(canon.value(&ScVal::Void), ScVal::Void);
        assert_eq!(canon.value(&ScVal::Bool(true)), ScVal::Bool(true));
    }

    /// A `ContractData` entry with the given key and value.
    fn data_entry(key: ScVal, val: ScVal) -> ObservedEntry {
        let contract = contract_address(1);
        ObservedEntry {
            key: LedgerKey::ContractData(LedgerKeyContractData {
                contract: contract.clone(),
                key: key.clone(),
                durability: ContractDataDurability::Persistent,
            }),
            entry: LedgerEntry {
                last_modified_ledger_seq: 0,
                data: LedgerEntryData::ContractData(ContractDataEntry {
                    ext: ExtensionPoint::V0,
                    contract,
                    key,
                    durability: ContractDataDurability::Persistent,
                    val,
                }),
                ext: LedgerEntryExt::V0,
            },
            ttl: Some(5095),
        }
    }

    fn instance_entry(storage: Option<ScMap>) -> ObservedEntry {
        data_entry(
            ScVal::LedgerKeyContractInstance,
            ScVal::ContractInstance(ScContractInstance {
                executable: ContractExecutable::Wasm(Hash([0xab; 32])),
                storage,
            }),
        )
    }

    #[test]
    fn registration_bookkeeping_is_not_contract_storage() {
        // Measured on hello-add, which stores nothing and still leaves three
        // entries behind. All three must drop out, or a contract with no storage
        // collects a free match for agreeing about its own bookkeeping.
        let book = AddressBook::new();
        let mut canon = Canonicalizer::new(&book);

        let entries = vec![
            data_entry(ScVal::LedgerKeyNonce(ScNonceKey { nonce: 42 }), ScVal::Void),
            instance_entry(None),
            ObservedEntry {
                key: LedgerKey::ContractCode(LedgerKeyContractCode {
                    hash: Hash([0xcd; 32]),
                }),
                ..instance_entry(None)
            },
        ];

        assert!(
            canon.storage(&entries).is_empty(),
            "nonce, empty instance and code entries are all bookkeeping"
        );
    }

    #[test]
    fn an_instance_entry_with_real_state_is_kept() {
        // The other half: `env.storage().instance()` state is genuine behaviour
        // and lives in the very entry the previous test discards when empty.
        let book = AddressBook::new();
        let mut canon = Canonicalizer::new(&book);

        let storage: ScMap = vec![ScMapEntry {
            key: ScVal::U32(1),
            val: ScVal::U32(2),
        }]
        .try_into()
        .unwrap();

        assert_eq!(canon.storage(&[instance_entry(Some(storage))]).len(), 1);
    }

    #[test]
    fn a_kept_instance_entry_has_its_code_hash_flattened() {
        // The original and the reconstruction are different bytes by definition,
        // so an embedded wasm hash would diverge on every contract forever.
        let book = AddressBook::new();
        let mut canon = Canonicalizer::new(&book);

        let storage: ScMap = vec![ScMapEntry {
            key: ScVal::U32(1),
            val: ScVal::U32(2),
        }]
        .try_into()
        .unwrap();
        let kept = canon.storage(&[instance_entry(Some(storage))]);

        let LedgerEntryData::ContractData(data) = &kept[0].entry.data else {
            panic!("must stay a ContractData entry");
        };
        let ScVal::ContractInstance(instance) = &data.val else {
            panic!("must stay a contract instance");
        };
        assert_eq!(
            instance.executable,
            ContractExecutable::Wasm(Hash([0u8; 32])),
            "the code hash must be flattened, not preserved"
        );
        assert!(instance.storage.is_some(), "but the instance state must survive");
    }

    #[test]
    fn a_synthetic_address_is_label_determined_and_prefixed() {
        assert_eq!(synthetic_address("self"), synthetic_address("self"));
        assert_ne!(synthetic_address("self"), synthetic_address("user_0"));
        let ScAddress::Contract(contract_id) = synthetic_address("self") else {
            panic!("synthetic addresses are contract addresses");
        };
        // `ContractId` wraps `Hash`, which wraps the 32 bytes.
        assert!(contract_id.0.0.starts_with(SYNTHETIC_PREFIX));
    }
}
