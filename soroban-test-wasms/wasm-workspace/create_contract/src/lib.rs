#![no_std]
use soroban_sdk::{contractimpl, Bytes, BytesN, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    // Note that anyone can create a contract here with any salt, so a users call to
    // this could be frontrun and the same salt taken.
    pub fn create(e: Env, wasm_hash: BytesN<32>, salt: Bytes) {
        e.deployer().with_current_contract(&salt).deploy(&wasm_hash);
    }
}
