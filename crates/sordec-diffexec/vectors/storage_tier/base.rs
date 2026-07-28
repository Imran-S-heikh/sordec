// Divergence class: storage tier.
//
// `instance()` and `persistent()` differ in lifetime, archival and cost. We emit
// `lift::non_constant_durability_arg` on token-v23, so the tier is something our
// pipeline can genuinely lose.
#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env};

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn put(env: Env, x: u32) {
        env.storage().persistent().set(&symbol_short!("k"), &x);
    }
}
