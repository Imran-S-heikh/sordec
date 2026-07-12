#![no_std]
//! A minimal signature-attestation contract for the sordec corpus.
//!
//! Purpose-built (not vendored) to exercise host surfaces the SEP-41
//! token / timelock / AMM fixtures do not touch: the `c` (crypto) and
//! `p` (prng) modules, a `#[contracterror]` enum with `Result`
//! returns, and a long (`> 9` char) `Symbol` that compiles to
//! `Symbol::new_from_linear_memory` rather than the inline small-symbol
//! path. Deliberately storage-free — the point is the host-call
//! surface, not persistence.

use soroban_sdk::{contract, contracterror, contractimpl, Bytes, BytesN, Env, Symbol};

/// Errors surfaced to callers, encoded as a Soroban `Error` value.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    /// The message to attest was empty.
    EmptyMessage = 1,
    /// The provided digest did not match the recomputed one.
    DigestMismatch = 2,
}

#[contract]
pub struct Attestation;

#[contractimpl]
impl Attestation {
    /// SHA-256 digest of a message — exercises `c._`
    /// `compute_hash_sha256`.
    pub fn digest(env: Env, message: Bytes) -> BytesN<32> {
        env.crypto().sha256(&message).into()
    }

    /// Keccak-256 digest guarded by a `#[contracterror]` `Result` path
    /// — exercises `c.1` `compute_hash_keccak256` plus the error
    /// encoding.
    pub fn digest_keccak(env: Env, message: Bytes) -> Result<BytesN<32>, Error> {
        if message.len() == 0 {
            return Err(Error::EmptyMessage);
        }
        Ok(env.crypto().keccak256(&message).into())
    }

    /// Verify an ed25519 signature over a message — exercises `c.0`
    /// `verify_sig_ed25519`. Traps on an invalid signature per the host
    /// ABI (the host returns `Void` on success).
    pub fn attest(env: Env, signer: BytesN<32>, message: Bytes, signature: BytesN<64>) {
        env.crypto().ed25519_verify(&signer, &message, &signature);
    }

    /// Recompute a message's SHA-256 digest and compare it to a claimed
    /// one — a second `#[contracterror]` path returning `Ok(())` /
    /// `Err(DigestMismatch)`.
    pub fn check(env: Env, message: Bytes, claimed: BytesN<32>) -> Result<(), Error> {
        let actual: BytesN<32> = env.crypto().sha256(&message).into();
        if actual == claimed {
            Ok(())
        } else {
            Err(Error::DigestMismatch)
        }
    }

    /// A PRNG challenge nonce in `[lo, hi]` — exercises `p.1`
    /// `prng_u64_in_inclusive_range`.
    pub fn challenge(env: Env, lo: u64, hi: u64) -> u64 {
        env.prng().gen_range(lo..=hi)
    }

    /// The attestation domain tag — a `> 9`-char `Symbol`, forcing
    /// `Symbol::new_from_linear_memory` (`b.j`) rather than the inline
    /// small-symbol encoding.
    pub fn domain(env: Env) -> Symbol {
        Symbol::new(&env, "attestation_domain")
    }
}
