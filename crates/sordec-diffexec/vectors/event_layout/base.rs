// Divergence class: event topic layout.
//
// `EventParamLocation::Topic` is recovered in our IR but not emitted
// (`contract_type.rs::event_item`), so this is a known gap. It is also invisible to
// a return-value comparison — the call returns nothing either way — which is
// exactly why events are their own tuple.
#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env};

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn emit(env: Env) {
        env.events().publish((symbol_short!("tag"), 1u32), 2u32);
    }
}
