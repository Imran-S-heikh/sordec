// Mutation: authorizes a specific argument list rather than the invocation's own.
// A signer who approved one is not thereby approving the other.
#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env, IntoVal};

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn act(env: Env, user: Address, amount: u32) {
        user.require_auth_for_args((amount,).into_val(&env));
    }
}
