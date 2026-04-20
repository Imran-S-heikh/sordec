#![no_std]
use soroban_sdk::{
    contract, contractimpl, contractmeta, contracttype, Address, Env, Symbol, Vec,
};
contractmeta!(key = "rssdkver", val = "21.7.7#5da789c50b18a4c2be53394138212fed56f0dfc4");
contractmeta!(key = "rsver", val = "1.91.1");
#[contracttype]
#[derive(Clone, Debug)]
pub enum DataKey {
    Counter(Address),
    Admin,
}
#[contract]
pub struct Contract;
#[contractimpl]
impl Contract {
    pub fn get_admin(env: Env) -> Address {
        let v1 = 1;
        let v2 = 0;
        let v3 = func1(v1, v2);
        let v4 = 2;
        let v5 = func2(v3, v4);
        let v6 = v5 == 0;
        if v6 {
            let v14 = func7();
            return core::default::Default::default();
        } else {
            let v17 = v3;
            let v8 = 2;
            let v9 = env.storage().persistent().get(&v8);
            let v10 = 255;
            let v11 = v9 & v10;
            let v12 = 77;
            let v13 = v11 == v12;
            if v13 {
                let v16 = v9;
                let v0 = v16;
                return v0;
            } else {
                return core::default::Default::default();
            }
        }
    }
    pub fn get_count(env: Env, user: Address) -> u32 {
        env.storage().persistent().get(&user)
    }
    pub fn increment(env: Env, user: Address) -> u32 {
        env.storage().persistent().get(&user)
    }
    pub fn __constructor(env: Env, admin: Address) {
        let v2 = 255;
        let v3 = admin & v2;
        let v4 = 77;
        let v5 = v3 == v4;
        let summary_4_vector = Vec::<Val>::new(&env);
        let summary_5_symbol = Symbol::new(&env, "recovered");
        if v5 {
            let v12 = admin;
            let v6 = 1;
            let v8 = func1(v6, v12);
            let v9 = 2;
            env.storage().persistent().set(&v12, &v9);
            let v11 = 2;
            let v0 = v11;
            return v0;
        } else {
            return;
        }
    }
}
