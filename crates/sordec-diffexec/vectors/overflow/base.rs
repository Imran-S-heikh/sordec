// Divergence class: overflow semantics.
//
// This is the class Inferara's decompiler shipped: their output emitted `count << 2`
// where the original had `count * 4`, so it "no longer traps on overflow inputs
// where the original wrapped". Under `overflow-checks = true` the multiply is a
// checked operation and traps; the shift is not and silently drops the high bits.
//
// Nothing in the source text distinguishes these two as clearly as the runtime
// does, which is the entire argument for measuring behaviour.
#![no_std]
use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn scale(x: u32) -> u32 {
        x * 4
    }
}
