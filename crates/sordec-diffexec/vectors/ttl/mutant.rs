// Mutation: extends to a different ledger. Same key, same value, same tier.
#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env};

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn put_and_extend(env: Env, x: u32) {
        let key = symbol_short!("k");
        env.storage().persistent().set(&key, &x);
        env.storage().persistent().extend_ttl(&key, 3_000_000, 3_000_000);
    }
}
