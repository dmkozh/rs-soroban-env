use crate::{test::util::generate_bytes_array, Host, HostError, LedgerInfo};
use ed25519_dalek::{Keypair, Signer};
use rand::thread_rng;
use soroban_env_common::xdr::{
    self, AccountId, AuthorizedInvocation, ContractAuth, Hash, HashIdPreimage,
    HashIdPreimageContractAuth, PublicKey, ScAddress, ScObject, ScVal, ScVec, Uint256,
};
use soroban_env_common::{EnvBase, RawVal, TryFromVal, TryIntoVal};

use crate::native_contract::base_types::BytesN;

pub(crate) use crate::native_contract::base_types::Vec as HostVec;

use super::account_contract::AccountEd25519Signature;
use super::base_types::Address;

impl HostVec {
    pub(crate) fn from_array(host: &Host, vals: &[RawVal]) -> Result<Self, HostError> {
        let mut res = HostVec::new(host)?;
        for val in vals {
            res.push_raw(val.clone())?;
        }
        Ok(res)
    }
}

#[macro_export]
macro_rules! host_vec {
    ($host:expr $(,)?) => {
        HostVec::new($host).unwrap()
    };
    ($host:expr, $($x:expr),+ $(,)?) => {
        HostVec::from_array($host, &[$($x.try_into_val($host).unwrap()),+]).unwrap()
    };
}

pub(crate) fn generate_keypair() -> Keypair {
    Keypair::generate(&mut thread_rng())
}

pub(crate) fn generate_bytes(host: &Host) -> BytesN<32> {
    BytesN::<32>::try_from_val(
        host,
        &host.bytes_new_from_slice(&generate_bytes_array()).unwrap(),
    )
    .unwrap()
}

pub(crate) fn keypair_to_account_id(key: &Keypair) -> AccountId {
    AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
        key.public.to_bytes(),
    )))
}

pub(crate) fn account_to_address(host: &Host, account_id: AccountId) -> Address {
    Address::try_from_val(
        host,
        &host
            .add_host_object(ScAddress::ClassicAccount(account_id))
            .unwrap(),
    )
    .unwrap()
}

pub(crate) fn contract_id_to_address(host: &Host, contract_id: [u8; 32]) -> Address {
    Address::try_from_val(
        host,
        &host
            .add_host_object(ScAddress::Contract(Hash(contract_id)))
            .unwrap(),
    )
    .unwrap()
}

pub(crate) enum TestSigner<'a> {
    ClassicAccountInvoker(AccountId),
    ContractInvoker(Hash),
    ClassicAccount(ClassicAccountSigner<'a>),
    GenericAccount(GenericAccountSigner<'a>),
}

pub(crate) struct GenericAccountSigner<'a> {
    pub(crate) id: Hash,
    pub(crate) sign: Box<dyn Fn(&[u8]) -> HostVec + 'a>,
}

pub(crate) struct ClassicAccountSigner<'a> {
    pub(crate) account_id: AccountId,
    pub(crate) signers: Vec<&'a Keypair>,
}

impl<'a> TestSigner<'a> {
    pub(crate) fn classic_account(kp: &'a Keypair) -> Self {
        TestSigner::ClassicAccount(ClassicAccountSigner {
            account_id: keypair_to_account_id(kp),
            signers: vec![kp],
        })
    }

    pub(crate) fn classic_account_with_multisig(
        account_id: &AccountId,
        mut signers: Vec<&'a Keypair>,
    ) -> Self {
        signers.sort_by_key(|k| k.public.as_bytes());
        TestSigner::ClassicAccount(ClassicAccountSigner {
            account_id: account_id.clone(),
            signers,
        })
    }

    pub(crate) fn account_id(&self) -> AccountId {
        match self {
            TestSigner::ClassicAccountInvoker(acc_id) => acc_id.clone(),
            TestSigner::ClassicAccount(ClassicAccountSigner {
                account_id,
                signers: _,
            }) => account_id.clone(),
            TestSigner::GenericAccount(_) => panic!("not supported"),
            TestSigner::ContractInvoker(_) => panic!("not supported"),
        }
    }

    fn sign(&self, host: &Host, payload: &[u8]) -> ScVec {
        let signature_args = match self {
            TestSigner::ClassicAccountInvoker(_) => host_vec![host],
            TestSigner::ClassicAccount(account_signer) => {
                let mut signatures = HostVec::new(&host).unwrap();
                for key in &account_signer.signers {
                    signatures
                        .push(&sign_payload_for_account(host, key, payload))
                        .unwrap();
                }
                host_vec![host, signatures]
            }
            TestSigner::GenericAccount(signer) => (signer.sign)(payload),
            TestSigner::ContractInvoker(_) => host_vec![host],
        };
        host.call_args_to_scvec(signature_args.into()).unwrap()
    }

    pub(crate) fn address(&self, host: &Host) -> Address {
        let sc_address = match self {
            TestSigner::ClassicAccountInvoker(acc_id) => ScAddress::ClassicAccount(acc_id.clone()),
            TestSigner::ClassicAccount(acc) => ScAddress::ClassicAccount(acc.account_id.clone()),
            TestSigner::GenericAccount(signer) => ScAddress::Contract(signer.id.clone()),
            TestSigner::ContractInvoker(contract_id) => ScAddress::Contract(contract_id.clone()),
        };
        Address::try_from_val(host, &host.add_host_object(sc_address).unwrap()).unwrap()
    }
}

pub(crate) fn authorize_single_invocation_with_nonce(
    host: &Host,
    signer: &TestSigner,
    contract_id: &BytesN<32>,
    function_name: &str,
    args: HostVec,
    nonce: Option<u64>,
) {
    let sc_address = signer.address(host).to_sc_address().unwrap();
    let address = match signer {
        TestSigner::ClassicAccountInvoker(_) => None,
        TestSigner::ClassicAccount(_) | TestSigner::GenericAccount(_) => Some(sc_address.clone()),
        TestSigner::ContractInvoker(_) => {
            // Nothing need to be authorized for contract invoker here.
            return;
        }
    };

    let invocation = AuthorizedInvocation {
        contract_id: contract_id.to_vec().try_into().unwrap(),
        function_name: function_name.try_into().unwrap(),
        args: host.call_args_to_scvec(args.into()).unwrap(),
        sub_invocations: Default::default(),
    };

    let signature_payload_preimage = HashIdPreimage::ContractAuth(HashIdPreimageContractAuth {
        network_id: host
            .with_ledger_info(|li: &LedgerInfo| Ok(li.network_id.clone()))
            .unwrap()
            .try_into()
            .unwrap(),
        invocation: invocation.clone(),
    });
    let signature_payload = host.metered_hash_xdr(&signature_payload_preimage).unwrap();
    let signature_args = signer.sign(host, &signature_payload);
    let auth_entry = ContractAuth {
        address,
        invocation,
        signature_args,
        nonce,
    };

    host.set_authorization_entries(vec![auth_entry]).unwrap();
}

pub(crate) fn authorize_single_invocation(
    host: &Host,
    signer: &TestSigner,
    contract_id: &BytesN<32>,
    function_name: &str,
    args: HostVec,
) {
    let nonce = match signer {
        TestSigner::ClassicAccountInvoker(_) => None,
        TestSigner::ClassicAccount(_) | TestSigner::GenericAccount(_) => Some(
            host.read_nonce(
                &Hash(contract_id.to_vec().clone().try_into().unwrap()),
                &signer.address(host).to_sc_address().unwrap(),
            )
            .unwrap(),
        ),
        TestSigner::ContractInvoker(_) => {
            return;
        }
    };
    authorize_single_invocation_with_nonce(host, signer, contract_id, function_name, args, nonce);
}

fn sign_payload_for_account(
    host: &Host,
    signer: &Keypair,
    payload: &[u8],
) -> AccountEd25519Signature {
    AccountEd25519Signature {
        public_key: BytesN::<32>::try_from_val(
            host,
            &host
                .bytes_new_from_slice(&signer.public.to_bytes())
                .unwrap(),
        )
        .unwrap(),
        signature: BytesN::<64>::try_from_val(
            host,
            &host
                .bytes_new_from_slice(&signer.sign(payload).to_bytes())
                .unwrap(),
        )
        .unwrap(),
    }
}

pub(crate) fn sign_payload_for_ed25519(
    host: &Host,
    signer: &Keypair,
    payload: &[u8],
) -> BytesN<64> {
    BytesN::<64>::try_from_val(
        host,
        &host
            .bytes_new_from_slice(&signer.sign(payload).to_bytes())
            .unwrap(),
    )
    .unwrap()
}
