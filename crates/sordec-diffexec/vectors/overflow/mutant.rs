// Mutation: the strength-reduced form a decompiler naturally emits, because this
// is what the compiler put in the wasm. Recovering the shift is *correct* at the
// instruction level and *wrong* at the semantic level.
#![no_std]
use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn scale(x: u32) -> u32 {
        x << 2
    }
}
