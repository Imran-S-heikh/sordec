// Mutation: the other code. Same control flow, same failure, different meaning to
// any caller matching on it.
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
            return Err(Error::Second);
        }
        Ok(x)
    }
}
