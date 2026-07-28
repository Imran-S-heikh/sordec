// Not a divergence class — the control that keeps the match rate honest.
//
// Two contracts that both panic on garbage input agree perfectly and demonstrate
// nothing. This pair *differs* in source and still agrees observationally, which is
// the trap: folded into a match rate it reads as recovery. It must land in its own
// bucket and score nothing.
#![no_std]
use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn always_fails(_x: u32) -> u32 {
        panic!("base cannot handle this")
    }
}
