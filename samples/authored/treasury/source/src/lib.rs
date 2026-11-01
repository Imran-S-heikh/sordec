//! A community treasury.
//!
//! Members deposit a token, propose payments or setting changes, and vote
//! with a weight that depends on their role. Once the voting period is over
//! anyone can close a proposal; the admin executes the ones that passed.
#![no_std]

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, log, panic_with_error,
    symbol_short, token, xdr::ToXdr, Address, Bytes, BytesN, Env, IntoVal, Map, String, Symbol,
    Val, Vec,
};

const DAY_IN_LEDGERS: u32 = 17_280;
const INSTANCE_BUMP: u32 = 7 * DAY_IN_LEDGERS;
const INSTANCE_THRESHOLD: u32 = INSTANCE_BUMP - DAY_IN_LEDGERS;
const ENTRY_BUMP: u32 = 30 * DAY_IN_LEDGERS;
const ENTRY_THRESHOLD: u32 = ENTRY_BUMP - DAY_IN_LEDGERS;
const VOTE_TTL: u32 = DAY_IN_LEDGERS;
const BPS: u32 = 10_000;
const MAX_MEMBERS: u32 = 20;
const TREASURY: Symbol = symbol_short!("TREASURY");

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotMember = 1,
    AlreadyMember = 2,
    TooManyMembers = 3,
    ProposalNotFound = 4,
    ProposalClosed = 5,
    AlreadyVoted = 6,
    VotingNotOver = 7,
    NotPassed = 8,
    InvalidAmount = 9,
    Overflow = 10,
    InsufficientFunds = 11,
    InvalidQuorum = 12,
}

/// How much a member's vote counts.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Role {
    Member = 1,
    Council = 2,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    Open,
    Passed,
    Rejected,
    Executed,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Payment {
    pub to: Address,
    pub amount: i128,
}

/// What a proposal does once it is executed.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Action {
    Pay(Payment),
    SetQuorum(u32),
    AddMember(Address),
    Memo,
}

/// Weighted votes for and against.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Tally(pub u32, pub u32);

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proposal {
    pub id: u32,
    pub proposer: Address,
    pub title: String,
    pub action: Action,
    pub tally: Tally,
    pub status: Status,
    pub deadline: u64,
    pub digest: BytesN<32>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Member {
    pub role: Role,
    pub joined: u64,
    pub votes_cast: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub token: Address,
    pub quorum_bps: u32,
    pub voting_period: u64,
    pub fee_bps: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VoteKey {
    pub proposal: u32,
    pub voter: Address,
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    Config,
    NextId,
    Members,
    Member(Address),
    Deposit(Address),
    Proposal(u32),
    Voted(VoteKey),
}

#[contractevent(topics = ["TREASURY", "proposed"], data_format = "single-value")]
pub struct Proposed {
    #[topic]
    pub proposer: Address,
    pub id: u32,
}

#[contractevent]
pub struct VoteCast {
    #[topic]
    pub id: u32,
    #[topic]
    pub voter: Address,
    pub approve: bool,
    pub weight: u32,
}

#[contractevent(data_format = "vec")]
pub struct Executed {
    #[topic]
    pub id: u32,
    pub status: Status,
    pub paid: i128,
}

trait Weight {
    fn weight(&self) -> u32;
}

impl Weight for Member {
    fn weight(&self) -> u32 {
        match self.role {
            Role::Member => 1,
            Role::Council => 3,
        }
    }
}

fn bump_instance(env: &Env) {
    env.storage()
        .instance()
        .extend_ttl(INSTANCE_THRESHOLD, INSTANCE_BUMP);
}

fn bump_entry<K: IntoVal<Env, Val>>(env: &Env, key: &K) {
    env.storage()
        .persistent()
        .extend_ttl(key, ENTRY_THRESHOLD, ENTRY_BUMP);
}

fn admin(env: &Env) -> Address {
    env.storage().instance().get(&DataKey::Admin).unwrap()
}

fn config(env: &Env) -> Config {
    env.storage().instance().get(&DataKey::Config).unwrap()
}

fn members(env: &Env) -> Vec<Address> {
    env.storage()
        .instance()
        .get(&DataKey::Members)
        .unwrap_or(Vec::new(env))
}

fn member(env: &Env, who: &Address) -> Result<Member, Error> {
    let key = DataKey::Member(who.clone());
    match env.storage().persistent().get::<_, Member>(&key) {
        Some(m) => {
            bump_entry(env, &key);
            Ok(m)
        }
        None => Err(Error::NotMember),
    }
}

fn proposal(env: &Env, id: u32) -> Result<Proposal, Error> {
    env.storage()
        .persistent()
        .get(&DataKey::Proposal(id))
        .ok_or(Error::ProposalNotFound)
}

fn save_proposal(env: &Env, p: &Proposal) {
    let key = DataKey::Proposal(p.id);
    env.storage().persistent().set(&key, p);
    bump_entry(env, &key);
}

fn enroll(env: &Env, who: Address, role: Role) -> Result<u32, Error> {
    let key = DataKey::Member(who.clone());
    if env.storage().persistent().has(&key) {
        return Err(Error::AlreadyMember);
    }
    let mut all = members(env);
    if all.len() >= MAX_MEMBERS {
        return Err(Error::TooManyMembers);
    }
    all.push_back(who.clone());
    env.storage().instance().set(&DataKey::Members, &all);
    let info = Member {
        role,
        joined: env.ledger().timestamp(),
        votes_cast: 0,
    };
    env.storage().persistent().set(&key, &info);
    bump_entry(env, &key);
    Ok(all.len())
}

fn fee_of(amount: i128, fee_bps: u32) -> Result<i128, Error> {
    amount
        .checked_mul(fee_bps as i128)
        .map(|x| x / BPS as i128)
        .ok_or(Error::Overflow)
}

fn total_weight(env: &Env) -> u32 {
    let mut total = 0u32;
    for who in members(env).iter() {
        if let Some(m) = env
            .storage()
            .persistent()
            .get::<_, Member>(&DataKey::Member(who))
        {
            total += m.weight();
        }
    }
    total
}

fn digest_of(env: &Env, title: &String, action: &Action) -> BytesN<32> {
    let mut data = Bytes::new(env);
    data.append(&title.clone().to_xdr(env));
    data.append(&action.clone().to_xdr(env));
    env.crypto().sha256(&data).to_bytes()
}

fn check_action(action: &Action) -> Result<(), Error> {
    match action {
        Action::Pay(p) if p.amount <= 0 => Err(Error::InvalidAmount),
        Action::SetQuorum(q) if *q == 0 || *q > BPS => Err(Error::InvalidQuorum),
        _ => Ok(()),
    }
}

#[contract]
pub struct Treasury;

#[contractimpl]
impl Treasury {
    pub fn __constructor(
        env: Env,
        admin: Address,
        token: Address,
        quorum_bps: u32,
        voting_period: u64,
    ) {
        if quorum_bps == 0 || quorum_bps > BPS {
            panic_with_error!(&env, Error::InvalidQuorum);
        }
        let config = Config {
            token,
            quorum_bps,
            voting_period,
            fee_bps: 25,
        };
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Config, &config);
        env.storage().instance().set(&DataKey::NextId, &1u32);
        if enroll(&env, admin, Role::Council).is_err() {
            panic_with_error!(&env, Error::AlreadyMember);
        }
    }

    pub fn add_member(env: Env, who: Address, role: Role) -> Result<u32, Error> {
        admin(&env).require_auth();
        bump_instance(&env);
        enroll(&env, who, role)
    }

    pub fn remove_member(env: Env, who: Address) -> Result<(), Error> {
        admin(&env).require_auth();
        let key = DataKey::Member(who.clone());
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotMember);
        }
        env.storage().persistent().remove(&key);
        let mut all = members(&env);
        if let Some(i) = all.first_index_of(&who) {
            all.remove(i);
        }
        env.storage().instance().set(&DataKey::Members, &all);
        Ok(())
    }

    pub fn deposit(env: Env, from: Address, amount: i128) -> Result<i128, Error> {
        from.require_auth();
        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }
        let cfg = config(&env);
        token::Client::new(&env, &cfg.token).transfer(
            &from,
            &env.current_contract_address(),
            &amount,
        );
        let key = DataKey::Deposit(from.clone());
        let total = env
            .storage()
            .persistent()
            .update(&key, |old: Option<i128>| old.unwrap_or(0) + amount);
        bump_entry(&env, &key);
        env.events()
            .publish((TREASURY, symbol_short!("deposit"), from), amount);
        Ok(total)
    }

    pub fn propose(
        env: Env,
        proposer: Address,
        title: String,
        action: Action,
    ) -> Result<u32, Error> {
        proposer.require_auth();
        member(&env, &proposer)?;
        check_action(&action)?;
        let cfg = config(&env);
        let id: u32 = env.storage().instance().get(&DataKey::NextId).unwrap_or(1);
        let next = id.checked_add(1).ok_or(Error::Overflow)?;
        let digest = digest_of(&env, &title, &action);
        let p = Proposal {
            id,
            proposer: proposer.clone(),
            title,
            action,
            tally: Tally(0, 0),
            status: Status::Open,
            deadline: env.ledger().timestamp() + cfg.voting_period,
            digest,
        };
        save_proposal(&env, &p);
        env.storage().instance().set(&DataKey::NextId, &next);
        bump_instance(&env);
        log!(&env, "proposal {} by {}", id, proposer);
        Proposed { proposer, id }.publish(&env);
        Ok(id)
    }

    pub fn vote(env: Env, voter: Address, id: u32, approve: bool) -> Result<Tally, Error> {
        voter.require_auth_for_args((id, approve).into_val(&env));
        let mut m = member(&env, &voter)?;
        let mut p = proposal(&env, id)?;
        if p.status != Status::Open || env.ledger().timestamp() > p.deadline {
            return Err(Error::ProposalClosed);
        }
        let key = DataKey::Voted(VoteKey {
            proposal: id,
            voter: voter.clone(),
        });
        if env.storage().temporary().has(&key) {
            return Err(Error::AlreadyVoted);
        }
        env.storage().temporary().set(&key, &true);
        env.storage().temporary().extend_ttl(&key, VOTE_TTL, VOTE_TTL);

        let weight = m.weight();
        if approve {
            p.tally.0 += weight;
        } else {
            p.tally.1 += weight;
        }
        m.votes_cast += 1;
        let member_key = DataKey::Member(voter.clone());
        env.storage().persistent().set(&member_key, &m);
        save_proposal(&env, &p);
        VoteCast {
            id,
            voter,
            approve,
            weight,
        }
        .publish(&env);
        Ok(p.tally)
    }

    pub fn finalize(env: Env, id: u32) -> Result<Status, Error> {
        let mut p = proposal(&env, id)?;
        if p.status != Status::Open {
            return Err(Error::ProposalClosed);
        }
        if env.ledger().timestamp() <= p.deadline {
            return Err(Error::VotingNotOver);
        }
        let cfg = config(&env);
        let total = total_weight(&env) as u64;
        let needed = (total * cfg.quorum_bps as u64 + (BPS as u64 - 1)) / BPS as u64;
        let Tally(yes, no) = p.tally;
        p.status = if yes as u64 >= needed && yes > no {
            Status::Passed
        } else {
            Status::Rejected
        };
        save_proposal(&env, &p);
        Ok(p.status)
    }

    pub fn execute(env: Env, id: u32) -> Result<i128, Error> {
        admin(&env).require_auth();
        let mut p = proposal(&env, id)?;
        match p.status {
            Status::Passed => {}
            Status::Open => return Err(Error::VotingNotOver),
            Status::Rejected | Status::Executed => return Err(Error::NotPassed),
        }
        let mut cfg = config(&env);
        let paid = match p.action.clone() {
            Action::Pay(pay) => {
                let client = token::Client::new(&env, &cfg.token);
                let here = env.current_contract_address();
                let fee = fee_of(pay.amount, cfg.fee_bps)?;
                let needed = pay.amount.checked_add(fee).ok_or(Error::Overflow)?;
                if client.balance(&here) < needed {
                    return Err(Error::InsufficientFunds);
                }
                client.transfer(&here, &pay.to, &pay.amount);
                pay.amount
            }
            Action::SetQuorum(q) => {
                cfg.quorum_bps = q;
                env.storage().instance().set(&DataKey::Config, &cfg);
                0
            }
            Action::AddMember(who) => {
                enroll(&env, who, Role::Member)?;
                0
            }
            Action::Memo => 0,
        };
        p.status = Status::Executed;
        save_proposal(&env, &p);
        Executed {
            id,
            status: p.status,
            paid,
        }
        .publish(&env);
        Ok(paid)
    }

    pub fn get_proposal(env: Env, id: u32) -> Option<Proposal> {
        env.storage().persistent().get(&DataKey::Proposal(id))
    }

    pub fn get_members(env: Env) -> Vec<Address> {
        members(&env)
    }

    pub fn roles(env: Env) -> Map<Address, Role> {
        let mut out = Map::new(&env);
        for who in members(&env).iter() {
            if let Ok(m) = member(&env, &who) {
                out.set(who, m.role);
            }
        }
        out
    }

    pub fn deposited(env: Env, who: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Deposit(who))
            .unwrap_or(0)
    }

    pub fn status_counts(env: Env) -> Map<Symbol, u32> {
        let next: u32 = env.storage().instance().get(&DataKey::NextId).unwrap_or(1);
        let mut counts = Map::new(&env);
        let mut id = 1;
        while id < next {
            if let Ok(p) = proposal(&env, id) {
                let name = match p.status {
                    Status::Open => symbol_short!("open"),
                    Status::Passed => symbol_short!("passed"),
                    Status::Rejected => symbol_short!("rejected"),
                    Status::Executed => symbol_short!("executed"),
                };
                let n = counts.get(name.clone()).unwrap_or(0);
                counts.set(name, n + 1);
            }
            id += 1;
        }
        counts
    }

    pub fn council_size(env: Env) -> u32 {
        members(&env)
            .iter()
            .filter(|who| matches!(member(&env, who), Ok(m) if m.role == Role::Council))
            .count() as u32
    }

    pub fn quote_fee(env: Env, amounts: Vec<i128>) -> Result<(i128, i128), Error> {
        let cfg = config(&env);
        let mut gross = 0i128;
        let mut fees = 0i128;
        for a in amounts.iter() {
            if a <= 0 {
                return Err(Error::InvalidAmount);
            }
            gross = gross.checked_add(a).ok_or(Error::Overflow)?;
            fees = fees.checked_add(fee_of(a, cfg.fee_bps)?).ok_or(Error::Overflow)?;
        }
        Ok((gross, fees))
    }

    pub fn name(env: Env) -> String {
        String::from_str(&env, "Community Treasury")
    }

    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        admin(&env).require_auth();
        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }
}
