// Divergence class: return value.
//
// The simplest possible difference, and the baseline for the whole corpus: if the
// comparator cannot see this, nothing else it reports means anything.
#![no_std]
use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn compute(x: u32) -> u32 {
        x + 1
    }
}
