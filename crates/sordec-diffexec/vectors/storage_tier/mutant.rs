// Mutation: the other tier. The value stored is identical; where it lives is not.
#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env};

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn put(env: Env, x: u32) {
        env.storage().instance().set(&symbol_short!("k"), &x);
    }
}
