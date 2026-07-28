// Divergence class: swapped arguments — money to the wrong party.
//
// The reason `canon` labels addresses by role rather than by order of first
// appearance. Under first-appearance labelling both sides below render as
// `(addr_0, addr_1)` and this vector passes while the bug ships. It is here to make
// sure that never becomes true again.
#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn transfer(env: Env, from: Address, to: Address, amount: u32) {
        env.events().publish((symbol_short!("xfer"), from, to), amount);
    }
}
