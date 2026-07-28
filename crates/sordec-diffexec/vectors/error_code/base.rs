// Divergence class: error codes are observable.
//
// Two different codes must compare unequal. We emit 37
// `lift::panic_without_error_code` diagnostics on token-v23 and bare `panic!()` in
// the output, so losing or confusing a code is a live failure mode for us, not a
// hypothetical one.
#![no_std]
use soroban_sdk::{contract, contracterror, contractimpl};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    First = 1,
    Second = 2,
}

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn check(x: u32) -> Result<u32, Error> {
        if x == 0 {
            return Err(Error::First);
        }
        Ok(x)
    }
}
