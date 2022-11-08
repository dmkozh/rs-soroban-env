use crate::native_contract::base_types::Map;
use soroban_env_common::{TryIntoVal, xdr::ScAddress};
use soroban_native_sdk_macros::contracttype;

#[contracttype]
pub struct AllowanceDataKey {
    pub from: ScAddress,
    pub spender: ScAddress,
}

#[contracttype]
pub struct BalanceValue {
    pub amount: i128,
    pub authorized: bool,
}

#[contracttype]
pub enum DataKey {
    Allowance(AllowanceDataKey),
    Balance(ScAddress),
    Admin,
    Metadata,
}
