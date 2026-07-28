// Mutation: the same two numbers, moved across the topic/data boundary. An
// indexer filtering on topics sees a different event; a naive comparison that
// concatenated topics and data would see none.
#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env};

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn emit(env: Env) {
        env.events().publish((symbol_short!("tag"),), (1u32, 2u32));
    }
}
