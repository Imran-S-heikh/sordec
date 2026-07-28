// Mutation: adds 2 instead of 1. Same signature, same control flow, same
// everything a source-text metric would look at.
#![no_std]
use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn compute(x: u32) -> u32 {
        x + 2
    }
}
