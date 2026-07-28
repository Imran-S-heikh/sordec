// Divergence class: time-to-live.
//
// TTL decides when an entry is archived, so it is behaviour rather than metadata.
// Source has 12 `extend_ttl` sites on token-v23 against the 1 we emit, one of those
// a `todo!("storage_extend_ttl<?> …")` hole — this is under-recovery we can already
// measure.
//
// The threshold is deliberately far larger than a fresh entry's remaining TTL, so
// the extension definitely fires. A threshold below it would make `extend_ttl` a
// no-op on both sides and the vector would prove nothing.
#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env};

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn put_and_extend(env: Env, x: u32) {
        let key = symbol_short!("k");
        env.storage().persistent().set(&key, &x);
        env.storage().persistent().extend_ttl(&key, 2_000_000, 2_000_000);
    }
}
