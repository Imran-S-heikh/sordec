// Mutation: sender and recipient exchanged. Identical control flow, identical
// value, identical event count — and the opposite transfer.
#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn transfer(env: Env, from: Address, to: Address, amount: u32) {
        env.events().publish((symbol_short!("xfer"), to, from), amount);
    }
}
