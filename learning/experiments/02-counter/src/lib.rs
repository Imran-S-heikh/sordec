#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Symbol, symbol_short};

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Counter(Address),
    Admin,
}

#[contract]
pub struct CounterContract;

#[contractimpl]
impl CounterContract {
    pub fn __constructor(env: Env, admin: Address) {
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    pub fn increment(env: Env, user: Address) -> u32 {
        user.require_auth();

        let key = DataKey::Counter(user.clone());
        let count: u32 = env.storage().persistent().get(&key).unwrap_or(0);
        let new_count = count + 1;
        env.storage().persistent().set(&key, &new_count);

        env.events().publish(
            (symbol_short!("increment"), user),
            new_count,
        );

        new_count
    }

    pub fn get_count(env: Env, user: Address) -> u32 {
        let key = DataKey::Counter(user);
        env.storage().persistent().get(&key).unwrap_or(0)
    }

    pub fn get_admin(env: Env) -> Address {
        env.storage().instance().get(&DataKey::Admin).unwrap()
    }
}
