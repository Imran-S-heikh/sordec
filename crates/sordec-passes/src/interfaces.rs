//! Known contract-interface tables for cross-contract call typing.
//!
//! D2.4 asks the recognizer to "collapse generic `invoke_contract`
//! into typed client calls **when the callee interface is
//! recoverable**". The callee's code is not inspectable — its address
//! is a runtime value — so recoverability means matching the call's
//! *shape* against interfaces the decompiler knows: today, the
//! **SEP-41 token interface** (SEP-0041, standardized as CAP-46-6 and
//! shipped as `soroban_sdk::token::Interface` / `TokenClient`), the
//! interface the RFP names explicitly.
//!
//! A match requires **both** the resolved callee name and the
//! recovered argument arity — a name alone is not evidence (any
//! contract may export a `transfer` with a different signature, but a
//! name+arity collision with different semantics is deliberate
//! obfuscation, not SDK output). The match is structural
//! (Inferred-grade); the annotating pass records the evidence in
//! provenance.

/// One function of a known interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceFn {
    /// Exported function name.
    pub name: &'static str,
    /// `(name, type)` pairs in declaration order, per the standard.
    pub params: &'static [(&'static str, &'static str)],
    /// Return type, `None` for unit.
    pub ret: Option<&'static str>,
}

impl InterfaceFn {
    /// The `name(param, param, …)` display form used in provenance
    /// notes.
    #[must_use]
    pub fn signature(&self) -> String {
        let params: Vec<&str> = self.params.iter().map(|(n, _)| *n).collect();
        format!("{}({})", self.name, params.join(", "))
    }
}

/// The SEP-41 token interface, in SEP declaration order.
///
/// Source: SEP-0041 "Soroban Token Interface" / CAP-46-6. `mint`,
/// `set_admin`, `set_authorized`, `clawback` are *admin* extensions of
/// the common `StellarAssetClient`, not part of SEP-41 proper — they
/// are deliberately absent (matching against a superset would claim
/// more than the standard defines).
static SEP41_TOKEN: &[InterfaceFn] = &[
    InterfaceFn {
        name: "allowance",
        params: &[("from", "Address"), ("spender", "Address")],
        ret: Some("i128"),
    },
    InterfaceFn {
        name: "approve",
        params: &[
            ("from", "Address"),
            ("spender", "Address"),
            ("amount", "i128"),
            ("expiration_ledger", "u32"),
        ],
        ret: None,
    },
    InterfaceFn {
        name: "balance",
        params: &[("id", "Address")],
        ret: Some("i128"),
    },
    InterfaceFn {
        name: "transfer",
        params: &[("from", "Address"), ("to", "Address"), ("amount", "i128")],
        ret: None,
    },
    InterfaceFn {
        name: "transfer_from",
        params: &[
            ("spender", "Address"),
            ("from", "Address"),
            ("to", "Address"),
            ("amount", "i128"),
        ],
        ret: None,
    },
    InterfaceFn {
        name: "burn",
        params: &[("from", "Address"), ("amount", "i128")],
        ret: None,
    },
    InterfaceFn {
        name: "burn_from",
        params: &[
            ("spender", "Address"),
            ("from", "Address"),
            ("amount", "i128"),
        ],
        ret: None,
    },
    InterfaceFn {
        name: "decimals",
        params: &[],
        ret: Some("u32"),
    },
    InterfaceFn {
        name: "name",
        params: &[],
        ret: Some("String"),
    },
    InterfaceFn {
        name: "symbol",
        params: &[],
        ret: Some("String"),
    },
];

/// Look up a SEP-41 token function by callee name **and** argument
/// arity. Both must match — see the module docs for why name-only is
/// not accepted.
#[must_use]
pub fn sep41_lookup(name: &str, arity: u32) -> Option<&'static InterfaceFn> {
    SEP41_TOKEN
        .iter()
        .find(|f| f.name == name && f.params.len() as u32 == arity)
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corpus_calls_match() {
        let transfer = sep41_lookup("transfer", 3).expect("transfer/3");
        assert_eq!(transfer.signature(), "transfer(from, to, amount)");
        let balance = sep41_lookup("balance", 1).expect("balance/1");
        assert_eq!(balance.signature(), "balance(id)");
    }

    #[test]
    fn arity_mismatch_is_a_miss() {
        // A `transfer` with the wrong arity is NOT SEP-41 evidence.
        assert_eq!(sep41_lookup("transfer", 2), None);
        assert_eq!(sep41_lookup("transfer", 4), None);
    }

    #[test]
    fn unknown_name_is_a_miss() {
        assert_eq!(sep41_lookup("swap", 3), None);
        // Admin extensions are deliberately not SEP-41.
        assert_eq!(sep41_lookup("mint", 2), None);
        assert_eq!(sep41_lookup("set_admin", 1), None);
    }

    #[test]
    fn nullary_functions_match_at_zero() {
        assert!(sep41_lookup("decimals", 0).is_some());
        assert!(sep41_lookup("name", 0).is_some());
        assert!(sep41_lookup("symbol", 0).is_some());
        assert_eq!(sep41_lookup("decimals", 1), None);
    }

    #[test]
    fn every_entry_is_unique_by_name_and_arity() {
        for (i, a) in SEP41_TOKEN.iter().enumerate() {
            for b in &SEP41_TOKEN[i + 1..] {
                assert!(
                    a.name != b.name || a.params.len() != b.params.len(),
                    "duplicate: {}/{}",
                    a.name,
                    a.params.len()
                );
            }
        }
    }
}
