// This is a built-in account 'contract'. This is not actually a contract, as
// it doesn't need to be directly invoked. But semantically this is analagous
// to a generic smart wallet contract that supports authentication and blanket
// context authorization.
use crate::host::metered_clone::MeteredClone;
use crate::host::Host;
use crate::native_contract::{
    base_types::{BytesN, Map},
    contract_error::ContractError,
};
use crate::{err, HostError};
use core::cmp::Ordering;
use soroban_env_common::xdr::{Hash, ScAccountId, ThresholdIndexes, Uint256};
use soroban_env_common::{CheckedEnv, RawVal, Symbol, TryFromVal, TryIntoVal};

use crate::native_contract::base_types::Vec as HostVec;

const MAX_ACCOUNT_SIGNATURES: u32 = 20;

use soroban_env_common::xdr::AccountId;
use soroban_native_sdk_macros::contracttype;

#[derive(Clone)]
#[contracttype]
pub enum Signature {
    Ed25519(BytesN<64>),
    Account(HostVec),
}

#[derive(Clone)]
#[contracttype]
pub struct AccountEd25519Signature {
    pub public_key: BytesN<32>,
    pub signature: BytesN<64>,
}

pub(crate) fn check_account_authentication(
    host: &Host,
    account_id: &ScAccountId,
    payload: &[u8],
    signature_args: Vec<RawVal>,
) -> Result<(), HostError> {
    if signature_args.len() != 1 {
        return Err(err!(
            host,
            ContractError::AuthenticationError,
            "incorrect number of signature args: {} != 1",
            signature_args.len() as u32
        ));
    }
    let signature: Signature = signature_args[0].try_into_val(host).map_err(|_| {
        host.err_status_msg(
            ContractError::AuthenticationError,
            "incompatible signature format",
        )
    })?;

    match &account_id {
        ScAccountId::BuiltinClassicAccount(acc_id) => {
            check_classic_account_authentication(host, payload, acc_id, signature)
        }
        ScAccountId::BuiltinEd25519(public_key) => {
            check_ed25519_authentication(host, payload, public_key, signature)
        }
        ScAccountId::GenericAccount(_) => Err(host.err_status(ContractError::InternalError)),
        ScAccountId::BuiltinInvoker => Err(host.err_status(ContractError::InternalError)),
    }
}

fn check_ed25519_authentication(
    host: &Host,
    payload: &[u8],
    public_key: &Hash,
    signature: Signature,
) -> Result<(), HostError> {
    if let Signature::Ed25519(signature) = signature {
        let public_key = host.ed25519_pub_key_from_bytes(&public_key.0)?;
        let signature = host.signature_from_obj_input("ed25519_sig", signature.into())?;
        host.verify_sig_ed25519_internal(payload, &public_key, &signature)
    } else {
        Err(host.err_status_msg(
            ContractError::AuthenticationError,
            "incompatible ed25519 signature format",
        ))
    }
}

fn check_classic_account_authentication(
    host: &Host,
    payload: &[u8],
    account_id: &AccountId,
    signature: Signature,
) -> Result<(), HostError> {
    let sigs = if let Signature::Account(sigs) = signature {
        sigs
    } else {
        return Err(host.err_status_msg(
            ContractError::AuthenticationError,
            "incompatible account signature format",
        ));
    };

    // Check if there is too many signatures: there shouldn't be more
    // signatures then the amount of account signers.
    if sigs.len()? > MAX_ACCOUNT_SIGNATURES {
        return Err(err!(
            host,
            ContractError::AuthenticationError,
            "too many account signers: {} > {}",
            sigs.len()?,
            MAX_ACCOUNT_SIGNATURES
        ));
    }
    let payload_obj = host.add_host_object(payload.to_vec())?.to_object();
    let account = host.load_account(account_id.metered_clone(host.budget_ref())?)?;
    let mut prev_pk: Option<BytesN<32>> = None;
    let mut weight = 0u32;
    for i in 0..sigs.len()? {
        let sig: AccountEd25519Signature = sigs.get(i)?;
        // Cannot take multiple signatures from the same key
        if let Some(prev) = prev_pk {
            if prev.compare(&sig.public_key)? != Ordering::Less {
                return Err(err!(
                    host,
                    ContractError::AuthenticationError,
                    "public keys are not ordered: {} >= {}",
                    prev,
                    sig.public_key
                ));
            }
        }

        host.verify_sig_ed25519(
            payload_obj.clone(),
            sig.public_key.clone().into(),
            sig.signature.into(),
        )?;

        let signer_weight =
            host.get_signer_weight_from_account(Uint256(sig.public_key.to_array()?), &account)?;
        // 0 weight indicates that signer doesn't belong to this account. Treat
        // this as an error to indicate a bug in signatures, even if another
        // signers would have enough weight.
        if signer_weight == 0 {
            return Err(err!(
                host,
                ContractError::AuthenticationError,
                "signer '{}' does not belong to account",
                sig.public_key
            ));
        }
        // Overflow isn't possible here as
        // 255 * MAX_ACCOUNT_SIGNATURES is < u32::MAX.
        weight += signer_weight as u32;
        prev_pk = Some(sig.public_key);
    }
    let threshold = account.thresholds.0[ThresholdIndexes::Med as usize];
    if weight < threshold as u32 {
        Err(err!(
            host,
            ContractError::AuthenticationError,
            "signature weight is lower than threshold: {} < {}",
            weight,
            threshold as u32
        ))
    } else {
        Ok(())
    }
}
