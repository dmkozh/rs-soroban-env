use crate::host::Host;
use crate::native_contract::base_types::Vec;
use crate::HostError;
use soroban_env_common::xdr::ScAddress;
use soroban_env_common::{CheckedEnv, Symbol, TryIntoVal};

pub(crate) fn incr_allow(
    e: &Host,
    from: ScAddress,
    to: ScAddress,
    amount: i128,
) -> Result<(), HostError> {
    let mut topics = Vec::new(e)?;
    topics.push(&Symbol::from_str("incr_allow"))?;
    topics.push(&from)?;
    topics.push(&to)?;
    e.contract_event(topics.into(), amount.try_into_val(e)?)?;
    Ok(())
}

pub(crate) fn decr_allow(
    e: &Host,
    from: ScAddress,
    to: ScAddress,
    amount: i128,
) -> Result<(), HostError> {
    let mut topics = Vec::new(e)?;
    topics.push(&Symbol::from_str("decr_allow"))?;
    topics.push(&from)?;
    topics.push(&to)?;
    e.contract_event(topics.into(), amount.try_into_val(e)?)?;
    Ok(())
}

pub(crate) fn transfer(
    e: &Host,
    from: ScAddress,
    to: ScAddress,
    amount: i128,
) -> Result<(), HostError> {
    let mut topics = Vec::new(e)?;
    topics.push(&Symbol::from_str("transfer"))?;
    topics.push(&from)?;
    topics.push(&to)?;
    e.contract_event(topics.into(), amount.try_into_val(e)?)?;
    Ok(())
}

pub(crate) fn mint(
    e: &Host,
    admin: ScAddress,
    to: ScAddress,
    amount: i128,
) -> Result<(), HostError> {
    let mut topics = Vec::new(e)?;
    topics.push(&Symbol::from_str("mint"))?;
    topics.push(&admin)?;
    topics.push(&to)?;
    e.contract_event(topics.into(), amount.try_into_val(e)?)?;
    Ok(())
}

pub(crate) fn clawback(
    e: &Host,
    admin: ScAddress,
    from: ScAddress,
    amount: i128,
) -> Result<(), HostError> {
    let mut topics = Vec::new(e)?;
    topics.push(&Symbol::from_str("clawback"))?;
    topics.push(&admin)?;
    topics.push(&from)?;
    e.contract_event(topics.into(), amount.try_into_val(e)?)?;
    Ok(())
}

pub(crate) fn set_auth(
    e: &Host,
    admin: ScAddress,
    id: ScAddress,
    authorize: bool,
) -> Result<(), HostError> {
    let mut topics = Vec::new(e)?;
    topics.push(&Symbol::from_str("set_auth"))?;
    topics.push(&admin)?;
    topics.push(&id)?;
    e.contract_event(topics.into(), authorize.try_into_val(e)?)?;
    Ok(())
}

pub(crate) fn set_admin(
    e: &Host,
    admin: ScAddress,
    new_admin: ScAddress,
) -> Result<(), HostError> {
    let mut topics = Vec::new(e)?;
    topics.push(&Symbol::from_str("set_admin"))?;
    topics.push(&admin)?;
    e.contract_event(topics.into(), new_admin.try_into_val(e)?)?;
    Ok(())
}

pub(crate) fn burn(e: &Host, from: ScAddress, amount: i128) -> Result<(), HostError> {
    let mut topics = Vec::new(e)?;
    topics.push(&Symbol::from_str("burn"))?;
    topics.push(&from)?;
    e.contract_event(topics.into(), amount.try_into_val(e)?)?;
    Ok(())
}
