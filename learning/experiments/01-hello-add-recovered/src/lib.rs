#![no_std]
use soroban_sdk::{contract, contractimpl, contractmeta};
contractmeta!(key = "rssdkver", val = "21.7.7#5da789c50b18a4c2be53394138212fed56f0dfc4");
contractmeta!(key = "rsver", val = "1.91.1");
#[contract]
pub struct Contract;
#[contractimpl]
impl Contract {
    pub fn add(a: u64, b: u64) -> u64 {
        a + b
    }
}
