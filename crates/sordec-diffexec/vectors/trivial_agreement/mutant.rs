// A different contract with a different message. Under `panic = "abort"` both
// become an unreachable trap carrying no code, so the two are indistinguishable
// from outside — agreement that proves nothing about whether recovery worked.
#![no_std]
use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn always_fails(_x: u32) -> u32 {
        panic!("mutant cannot handle this either, differently")
    }
}
