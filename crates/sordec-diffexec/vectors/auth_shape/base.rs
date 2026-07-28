// Divergence class: authorization tree shape.
//
// `require_auth` and `require_auth_for_args` authorize different things and produce
// different `env.auths()` trees. The call succeeds either way under
// `mock_all_auths`, so nothing but the auth tuple can see this.
#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn act(_env: Env, user: Address, _amount: u32) {
        user.require_auth();
    }
}
