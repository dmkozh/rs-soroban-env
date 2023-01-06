use std::{convert::TryInto, rc::Rc};

use crate::{
    auth::{AuthorizationManager, RecordedSignaturePayload},
    budget::{AsBudget, Budget},
    host::{Frame, TestContractFrame},
    host_vec,
    native_contract::{
        contract_error::ContractError,
        testutils::{
            generate_bytes, generate_keypair, sign_payload_for_ed25519, signer_to_account_id,
            signer_to_id_bytes, AccountAuthBuilder, AccountSigner, GenericAccountSigner, HostVec,
            TestSigner,
        },
        token::test_token::TestToken,
    },
    storage::{test_storage::MockSnapshotSource, Storage},
    test::util::generate_bytes_array,
    Host, HostError, LedgerInfo,
};
use ed25519_dalek::Keypair;
use soroban_env_common::{
    xdr::{self, AccountFlags, ScAccount, ScAccountId, ScVec, Uint256},
    xdr::{
        AccountEntry, AccountEntryExt, AccountEntryExtensionV1, AccountEntryExtensionV1Ext,
        AccountEntryExtensionV2, AccountEntryExtensionV2Ext, AccountId, AlphaNum12, AlphaNum4,
        Asset, AssetCode12, AssetCode4, Hash, HostFunctionType, LedgerEntryData, LedgerKey,
        Liabilities, PublicKey, ScAddress, ScStatusType, SequenceNumber, SignerKey, Thresholds,
        TrustLineEntry, TrustLineEntryExt, TrustLineEntryV1, TrustLineEntryV1Ext, TrustLineFlags,
    },
    RawVal,
};
use soroban_env_common::{CheckedEnv, EnvBase, Symbol, TryFromVal, TryIntoVal};
use soroban_test_wasms::SIMPLE_ACCOUNT_CONTRACT;

use crate::native_contract::base_types::{Bytes, BytesN};

fn convert_bytes(host: &Host, bytes: &[u8]) -> Bytes {
    Bytes::try_from_val(host, host.bytes_new_from_slice(bytes).unwrap()).unwrap()
}

struct TokenTest {
    host: Host,
    admin_key: Keypair,
    issuer_key: Keypair,
    user_key: Keypair,
    user_key_2: Keypair,
    user_key_3: Keypair,
    user_key_4: Keypair,
    asset_code: [u8; 4],
}

impl TokenTest {
    fn setup() -> Self {
        let host = Host::test_host_with_recording_footprint();
        host.set_ledger_info(LedgerInfo {
            protocol_version: 20,
            sequence_number: 123,
            timestamp: 123456,
            network_passphrase: vec![1, 2, 3, 4],
            base_reserve: 5_000_000,
        });
        Self {
            host,
            admin_key: generate_keypair(),
            issuer_key: generate_keypair(),
            user_key: generate_keypair(),
            user_key_2: generate_keypair(),
            user_key_3: generate_keypair(),
            user_key_4: generate_keypair(),
            asset_code: [0_u8; 4],
        }
    }

    fn default_token_with_admin_id(&self, new_admin: &ScAddress) -> TestToken {
        let issuer_id = signer_to_account_id(&self.host, &self.issuer_key);
        self.create_classic_account(
            &issuer_id,
            vec![(&self.issuer_key, 100)],
            10_000_000,
            1,
            [1, 0, 0, 0],
            None,
            None,
            0,
        );

        let asset = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(self.asset_code),
            issuer: issuer_id.clone(),
        });

        let token = TestToken::new_from_asset(&self.host, asset.clone());

        if let ScAddress::ClassicAccount(new_admin_id) = new_admin.clone() {
            if new_admin_id == issuer_id {
                return token;
            }
        }

        let issuer = TestSigner::account(&issuer_id, vec![&self.issuer_key]);
        token.set_admin(&issuer, new_admin.clone()).unwrap();
        token
    }

    fn default_token(&self, admin: &TestSigner) -> TestToken {
        self.default_token_with_admin_id(&admin.address())
    }

    fn get_native_balance(&self, account_id: &AccountId) -> i64 {
        let account = self.host.load_account(account_id.clone()).unwrap();
        account.balance
    }

    fn get_classic_trustline_balance(&self, key: &LedgerKey) -> i64 {
        self.host
            .with_mut_storage(|s| match s.get(key, self.host.as_budget()).unwrap().data {
                LedgerEntryData::Trustline(trustline) => Ok(trustline.balance),
                _ => unreachable!(),
            })
            .unwrap()
    }

    fn create_classic_account(
        &self,
        account_id: &AccountId,
        signers: Vec<(&Keypair, u32)>,
        balance: i64,
        num_sub_entries: u32,
        thresholds: [u8; 4],
        // (buying, selling) liabilities
        liabilities: Option<(i64, i64)>,
        // (num_sponsored, num_sponsoring) counts
        sponsorships: Option<(u32, u32)>,
        flags: u32,
    ) {
        let key = self.host.to_account_key(account_id.clone().into());
        let account_id = match &key {
            LedgerKey::Account(acc) => acc.account_id.clone(),
            _ => unreachable!(),
        };
        let mut acc_signers = vec![];
        for (signer, weight) in signers {
            acc_signers.push(soroban_env_common::xdr::Signer {
                key: SignerKey::Ed25519(
                    self.host
                        .to_u256(signer_to_id_bytes(&self.host, signer).into())
                        .unwrap(),
                ),
                weight,
            });
        }
        let ext = if sponsorships.is_some() || liabilities.is_some() {
            AccountEntryExt::V1(AccountEntryExtensionV1 {
                liabilities: if let Some((buying, selling)) = liabilities {
                    Liabilities { buying, selling }
                } else {
                    Liabilities {
                        buying: 0,
                        selling: 0,
                    }
                },
                ext: if let Some((num_sponsored, num_sponsoring)) = sponsorships {
                    AccountEntryExtensionV1Ext::V2(AccountEntryExtensionV2 {
                        num_sponsored,
                        num_sponsoring,
                        signer_sponsoring_i_ds: Default::default(),
                        ext: AccountEntryExtensionV2Ext::V0 {},
                    })
                } else {
                    AccountEntryExtensionV1Ext::V0
                },
            })
        } else {
            AccountEntryExt::V0
        };
        let acc_entry = AccountEntry {
            account_id,
            balance: balance,
            seq_num: SequenceNumber(0),
            num_sub_entries,
            inflation_dest: None,
            flags,
            home_domain: Default::default(),
            thresholds: Thresholds(thresholds),
            signers: acc_signers.try_into().unwrap(),
            ext,
        };

        self.host
            .add_ledger_entry(
                key,
                Host::ledger_entry_from_data(LedgerEntryData::Account(acc_entry)),
            )
            .unwrap();
    }

    fn create_classic_trustline(
        &self,
        account_id: &AccountId,
        issuer: &AccountId,
        asset_code: &[u8],
        balance: i64,
        limit: i64,
        flags: u32,
        // (buying, selling) liabilities
        liabilities: Option<(i64, i64)>,
    ) -> LedgerKey {
        let asset = match asset_code.len() {
            4 => {
                let mut code = [0_u8; 4];
                code.copy_from_slice(asset_code);
                self.host.create_asset_4(code, issuer.clone())
            }
            12 => {
                let mut code = [0_u8; 12];
                code.copy_from_slice(asset_code);
                self.host.create_asset_12(code, issuer.clone())
            }
            _ => unreachable!(),
        };
        let key = self
            .host
            .to_trustline_key(account_id.clone(), asset.clone());
        let ext = if let Some((buying, selling)) = liabilities {
            TrustLineEntryExt::V1({
                TrustLineEntryV1 {
                    liabilities: Liabilities { buying, selling },
                    ext: TrustLineEntryV1Ext::V0,
                }
            })
        } else {
            TrustLineEntryExt::V0
        };
        let trustline_entry = TrustLineEntry {
            account_id: account_id.clone(),
            asset,
            balance,
            limit,
            flags,
            ext,
        };

        self.host
            .add_ledger_entry(
                key.clone(),
                Host::ledger_entry_from_data(LedgerEntryData::Trustline(trustline_entry)),
            )
            .unwrap();

        key
    }

    fn run_from_contract<T, F>(
        &self,
        contract_id_bytes: &BytesN<32>,
        f: F,
    ) -> Result<RawVal, HostError>
    where
        T: Into<RawVal>,
        F: FnOnce() -> Result<T, HostError>,
    {
        self.host.with_frame(
            Frame::TestContract(TestContractFrame::new(
                Hash(contract_id_bytes.to_array().unwrap()),
                Symbol::from_str("foo"),
            )),
            || {
                let res = f();
                match res {
                    Ok(v) => Ok(v.into()),
                    Err(e) => Err(e),
                }
            },
        )
    }

    fn run_from_account<T, F>(&self, account_id: AccountId, f: F) -> Result<RawVal, HostError>
    where
        T: Into<RawVal>,
        F: FnOnce() -> Result<T, HostError>,
    {
        self.host.set_source_account(account_id);
        self.host.with_frame(
            Frame::HostFunction(HostFunctionType::InvokeContract),
            || {
                let res = f();
                match res {
                    Ok(v) => Ok(v.into()),
                    Err(e) => Err(e),
                }
            },
        )
    }
}

fn to_contract_err(e: HostError) -> ContractError {
    assert!(e.status.is_type(ScStatusType::ContractError));
    num_traits::FromPrimitive::from_u32(e.status.get_code()).unwrap()
}

#[test]
fn test_native_token_smart_roundtrip() {
    let test = TokenTest::setup();

    let account_id = signer_to_account_id(&test.host, &test.user_key);
    test.create_classic_account(
        &account_id,
        vec![(&test.user_key, 100)],
        100_000_000,
        1,
        [1, 0, 0, 0],
        None,
        None,
        0,
    );
    let token = TestToken::new_from_asset(&test.host, Asset::Native);
    let expected_token_id = test.host.get_contract_id_from_asset(Asset::Native).unwrap();

    assert_eq!(token.id.to_vec(), expected_token_id.0.to_vec());

    assert_eq!(token.symbol().unwrap().to_vec(), b"native".to_vec());
    assert_eq!(token.decimals().unwrap(), 7);
    assert_eq!(token.name().unwrap().to_vec(), b"native".to_vec());

    let user = TestSigner::account(&account_id, vec![&test.user_key]);

    // Also can't set a new admin (and there is no admin in the first place).
    assert!(token.set_admin(&user, user.address()).is_err());

    assert_eq!(test.get_native_balance(&account_id), 100_000_000);
    assert_eq!(token.balance(user.address()).unwrap(), 100_000_000);
}

fn test_classic_asset_init(asset_code: &[u8]) {
    let test = TokenTest::setup();

    let account_id = signer_to_account_id(&test.host, &test.user_key);
    let issuer_id = signer_to_account_id(&test.host, &test.admin_key);

    test.create_classic_account(
        &account_id,
        vec![(&test.user_key, 100)],
        10_000_000,
        1,
        [1, 0, 0, 0],
        None,
        None,
        0,
    );

    let trustline_key = test.create_classic_trustline(
        &account_id,
        &issuer_id,
        asset_code,
        10_000_000,
        100_000_000,
        TrustLineFlags::AuthorizedFlag as u32,
        None,
    );
    let asset = if asset_code.len() == 4 {
        let mut code = [0_u8; 4];
        code.clone_from_slice(asset_code);
        Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(code),
            issuer: issuer_id.clone(),
        })
    } else {
        let mut code = [0_u8; 12];
        code.clone_from_slice(asset_code);
        Asset::CreditAlphanum12(AlphaNum12 {
            asset_code: AssetCode12(code),
            issuer: issuer_id.clone(),
        })
    };
    let token = TestToken::new_from_asset(&test.host, asset.clone());
    let expected_token_id = test.host.get_contract_id_from_asset(asset).unwrap();
    assert_eq!(token.id.to_vec(), expected_token_id.0.to_vec());

    assert_eq!(token.symbol().unwrap().to_vec(), asset_code.to_vec());
    assert_eq!(token.decimals().unwrap(), 7);
    assert_eq!(
        token.name().unwrap().to_vec(),
        [
            asset_code.to_vec(),
            b":".to_vec(),
            test.admin_key.public.to_bytes().to_vec()
        ]
        .concat()
        .to_vec()
    );

    let user = TestSigner::account(&account_id, vec![&test.user_key]);

    assert_eq!(
        test.get_classic_trustline_balance(&trustline_key),
        10_000_000
    );
    assert_eq!(token.balance(user.address()).unwrap(), 10_000_000);
}

#[test]
fn test_classic_asset4_smart_init() {
    test_classic_asset_init(&[0, 'a' as u8, 'b' as u8, 255]);
}

#[test]
fn test_classic_asset12_smart_init() {
    test_classic_asset_init(&[255, 0, 0, 127, b'a', b'b', b'c', 1, 2, 3, 4, 5]);
}

#[test]
fn test_direct_transfer() {
    let test = TokenTest::setup();
    let admin = TestSigner::Ed25519(&test.admin_key);
    let token = test.default_token(&admin);

    let user = TestSigner::Ed25519(&test.user_key);
    let user_2 = TestSigner::Ed25519(&test.user_key_2);
    token.mint(&admin, user.address(), 100_000_000).unwrap();
    assert_eq!(token.balance(user.address()).unwrap(), 100_000_000);
    assert_eq!(token.balance(user_2.address()).unwrap(), 0);

    // Transfer some balance from user 1 to user 2.
    token.xfer(&user, user_2.address(), 9_999_999).unwrap();
    assert_eq!(token.balance(user.address()).unwrap(), 90_000_001);
    assert_eq!(token.balance(user_2.address()).unwrap(), 9_999_999);

    // Can't transfer more than the balance from user 2.
    assert_eq!(
        to_contract_err(
            token
                .xfer(&user_2, user.address(), 10_000_000,)
                .err()
                .unwrap()
        ),
        ContractError::BalanceError
    );

    // Transfer some balance back from user 2 to user 1.
    token.xfer(&user_2, user.address(), 999_999).unwrap();
    assert_eq!(token.balance(user.address()).unwrap(), 91_000_000);
    assert_eq!(token.balance(user_2.address()).unwrap(), 9_000_000);
}

#[test]
fn test_transfer_with_allowance() {
    let test = TokenTest::setup();
    let admin = TestSigner::Ed25519(&test.admin_key);
    let token = test.default_token(&admin);

    let user = TestSigner::Ed25519(&test.user_key);
    let user_2 = TestSigner::Ed25519(&test.user_key_2);
    let user_3 = TestSigner::Ed25519(&test.user_key_3);
    token.mint(&admin, user.address(), 100_000_000).unwrap();
    assert_eq!(token.balance(user.address()).unwrap(), 100_000_000);
    assert_eq!(token.balance(user_2.address()).unwrap(), 0);
    assert_eq!(
        token.allowance(user.address(), user_3.address()).unwrap(),
        0
    );

    // Allow 10_000_000 units of token to be transferred from user by user 3.
    token
        .incr_allow(&user, user_3.address(), 10_000_000)
        .unwrap();

    assert_eq!(
        token.allowance(user.address(), user_3.address()).unwrap(),
        10_000_000
    );

    // Transfer 5_000_000 of allowance to user 2.
    token
        .xfer_from(&user_3, user.address(), user_2.address(), 6_000_000)
        .unwrap();
    assert_eq!(token.balance(user.address()).unwrap(), 94_000_000);
    assert_eq!(token.balance(user_2.address()).unwrap(), 6_000_000);
    assert_eq!(token.balance(user_3.address()).unwrap(), 0);
    assert_eq!(
        token.allowance(user.address(), user_3.address()).unwrap(),
        4_000_000
    );

    // Can't transfer more than remaining allowance.
    assert_eq!(
        to_contract_err(
            token
                .xfer_from(&user_3, user.address(), user_3.address(), 4_000_001,)
                .err()
                .unwrap()
        ),
        ContractError::AllowanceError
    );
    // Decrease allow by more than what's left. This will set the allowance to 0
    token
        .decr_allow(&user, user_3.address(), 10_000_000)
        .unwrap();

    assert_eq!(
        token.allowance(user.address(), user_3.address()).unwrap(),
        0
    );

    token
        .incr_allow(&user, user_3.address(), 4_000_000)
        .unwrap();
    // Transfer the remaining allowance to user 3.
    token
        .xfer_from(&user_3, user.address(), user_3.address(), 4_000_000)
        .unwrap();

    assert_eq!(token.balance(user.address()).unwrap(), 90_000_000);
    assert_eq!(token.balance(user_2.address()).unwrap(), 6_000_000);
    assert_eq!(token.balance(user_3.address()).unwrap(), 4_000_000);
    assert_eq!(
        token.allowance(user.address(), user_3.address()).unwrap(),
        0
    );

    // Can't transfer anything at all now.
    assert_eq!(
        to_contract_err(
            token
                .xfer_from(&user_3, user.address(), user_3.address(), 1,)
                .err()
                .unwrap()
        ),
        ContractError::AllowanceError
    );

    // Allow 1_000_000 units of token to be transferred from user by user 3.
    token
        .incr_allow(&user, user_3.address(), 1_000_000)
        .unwrap();

    assert_eq!(
        token.allowance(user.address(), user_3.address()).unwrap(),
        1_000_000
    );
    // Reset temp storage, now allowance is gone and transfer is impossible.
    test.host.reset_temp_storage();
    assert_eq!(
        token.allowance(user.address(), user_3.address()).unwrap(),
        0
    );
    assert_eq!(
        to_contract_err(
            token
                .xfer_from(&user_3, user.address(), user_3.address(), 1,)
                .err()
                .unwrap()
        ),
        ContractError::AllowanceError
    );
}

#[test]
fn test_burn() {
    let test = TokenTest::setup();
    let admin = TestSigner::Ed25519(&test.admin_key);
    let token = test.default_token(&admin);

    let user = TestSigner::Ed25519(&test.user_key);
    let user_2 = TestSigner::Ed25519(&test.user_key_2);

    token.mint(&admin, user.address(), 100_000_000).unwrap();
    assert_eq!(token.balance(user.address()).unwrap(), 100_000_000);
    assert_eq!(token.balance(user_2.address()).unwrap(), 0);
    assert_eq!(
        token.allowance(user.address(), user_2.address()).unwrap(),
        0
    );

    // Allow 10_000_000 units of token to be transferred from user by user 3.
    token
        .incr_allow(&user, user_2.address(), 10_000_000)
        .unwrap();

    assert_eq!(
        token.allowance(user.address(), user_2.address()).unwrap(),
        10_000_000
    );

    // Burn 5_000_000 of allowance from user.
    token.burn_from(&user_2, user.address(), 6_000_000).unwrap();
    assert_eq!(token.balance(user.address()).unwrap(), 94_000_000);

    assert_eq!(token.balance(user_2.address()).unwrap(), 0);
    assert_eq!(
        token.allowance(user.address(), user_2.address()).unwrap(),
        4_000_000
    );

    // Can't burn more than remaining allowance.
    assert_eq!(
        to_contract_err(
            token
                .burn_from(&user_2, user.address(), 4_000_001,)
                .err()
                .unwrap()
        ),
        ContractError::AllowanceError
    );

    // Burn the remaining allowance to user 3.
    token.burn_from(&user_2, user.address(), 4_000_000).unwrap();

    assert_eq!(token.balance(user.address()).unwrap(), 90_000_000);
    assert_eq!(token.balance(user_2.address()).unwrap(), 0);
    assert_eq!(
        token.allowance(user.address(), user_2.address()).unwrap(),
        0
    );

    // Now call burn
    token.burn(&user, 45_000_000).unwrap();

    assert_eq!(token.balance(user.address()).unwrap(), 45_000_000);

    // Deauthorize the balance of `user` and then try to burn.
    token.set_auth(&admin, user.address(), false).unwrap();

    // Can't burn while deauthorized
    assert_eq!(
        to_contract_err(token.burn(&user, 100,).err().unwrap()),
        ContractError::BalanceDeauthorizedError
    );

    // Authorize the balance of `user` and then burn.
    token.set_auth(&admin, user.address(), true).unwrap();

    token.burn(&user, 1_000_000).unwrap();

    assert_eq!(token.balance(user.address()).unwrap(), 44_000_000);
}

#[test]
fn test_cannot_burn_native() {
    let test = TokenTest::setup();
    let token = TestToken::new_from_asset(&test.host, Asset::Native);
    let user_acc_id = signer_to_account_id(&test.host, &test.user_key);

    let user = TestSigner::account(&user_acc_id, vec![&test.user_key]);
    let user2 = TestSigner::Ed25519(&test.user_key_2);

    test.create_classic_account(
        &user_acc_id,
        vec![(&test.user_key, 100)],
        100_000_000,
        1,
        [1, 0, 0, 0],
        None,
        None,
        0,
    );

    assert_eq!(token.balance(user.address()).unwrap(), 100_000_000);

    assert_eq!(
        to_contract_err(token.burn(&user, 1,).err().unwrap()),
        ContractError::OperationNotSupportedError
    );

    token.incr_allow(&user, user2.address(), 100).unwrap();

    assert_eq!(
        to_contract_err(token.burn_from(&user2, user.address(), 1,).err().unwrap()),
        ContractError::OperationNotSupportedError
    );
}

#[test]
fn test_token_authorization() {
    let test = TokenTest::setup();
    let admin = TestSigner::Ed25519(&test.admin_key);
    let token = test.default_token(&admin);

    let user = TestSigner::Ed25519(&test.user_key);
    let user_2 = TestSigner::Ed25519(&test.user_key_2);
    token.mint(&admin, user.address(), 100_000_000).unwrap();
    token.mint(&admin, user_2.address(), 200_000_000).unwrap();

    assert!(token.authorized(user.address()).unwrap());

    // Deauthorize the balance of `user`.
    token.set_auth(&admin, user.address(), false).unwrap();

    assert!(!token.authorized(user.address()).unwrap());
    // Make sure neither outgoing nor incoming balance transfers are possible.
    assert_eq!(
        to_contract_err(token.xfer(&user, user_2.address(), 1).err().unwrap()),
        ContractError::BalanceDeauthorizedError
    );
    assert_eq!(
        to_contract_err(token.xfer(&user_2, user.address(), 1).err().unwrap()),
        ContractError::BalanceDeauthorizedError
    );

    // Authorize the balance of `user`.
    token.set_auth(&admin, user.address(), true).unwrap();

    assert!(token.authorized(user.address()).unwrap());
    // Make sure balance transfers are possible now.
    token.xfer(&user, user_2.address(), 1).unwrap();
    token.xfer(&user_2, user.address(), 1).unwrap();
}

#[test]
fn test_clawback() {
    let test = TokenTest::setup();
    let admin = TestSigner::Ed25519(&test.admin_key);
    let token = test.default_token(&admin);

    let user = TestSigner::Ed25519(&test.user_key);
    token.mint(&admin, user.address(), 100_000_000).unwrap();

    assert_eq!(token.balance(user.address()).unwrap(), 100_000_000);

    token.clawback(&admin, user.address(), 40_000_000).unwrap();

    assert_eq!(token.balance(user.address()).unwrap(), 60_000_000);

    // Can't clawback more than the balance
    assert_eq!(
        to_contract_err(
            token
                .clawback(&admin, user.address(), 60_000_001,)
                .err()
                .unwrap()
        ),
        ContractError::BalanceError
    );

    // Clawback everything else
    token.clawback(&admin, user.address(), 60_000_000).unwrap();
    assert_eq!(token.balance(user.address()).unwrap(), 0);
}

#[test]
fn test_set_admin() {
    let test = TokenTest::setup();
    let admin = TestSigner::Ed25519(&test.admin_key);
    let token = test.default_token(&admin);
    let new_admin = TestSigner::Ed25519(&test.user_key);

    // Give admin rights to the new admin.
    token.set_admin(&admin, new_admin.address()).unwrap();

    // Make sure admin functions are unavailable to the old admin.
    assert_eq!(
        to_contract_err(token.set_admin(&admin, new_admin.address(),).err().unwrap()),
        ContractError::UnauthorizedError
    );
    assert_eq!(
        to_contract_err(token.mint(&admin, new_admin.address(), 1).err().unwrap()),
        ContractError::UnauthorizedError
    );
    assert_eq!(
        to_contract_err(
            token
                .clawback(&admin, new_admin.address(), 1)
                .err()
                .unwrap()
        ),
        ContractError::UnauthorizedError
    );
    assert_eq!(
        to_contract_err(
            token
                .set_auth(&admin, new_admin.address(), false,)
                .err()
                .unwrap()
        ),
        ContractError::UnauthorizedError
    );
    assert_eq!(
        to_contract_err(
            token
                .set_auth(&admin, new_admin.address(), true)
                .err()
                .unwrap()
        ),
        ContractError::UnauthorizedError
    );

    // The admin functions are now available to the new admin.
    token.mint(&new_admin, admin.address(), 1).unwrap();
    token.clawback(&new_admin, admin.address(), 1).unwrap();
    token.set_auth(&new_admin, admin.address(), false).unwrap();
    token.set_auth(&new_admin, admin.address(), true).unwrap();

    // Return the admin rights to the old admin
    token.set_admin(&new_admin, admin.address()).unwrap();
    // Make sure old admin can now perform admin operations
    token.mint(&admin, new_admin.address(), 1).unwrap();
}

#[test]
fn test_account_spendable_balance() {
    let test = TokenTest::setup();
    let token = TestToken::new_from_asset(&test.host, Asset::Native);
    let user_acc_id = signer_to_account_id(&test.host, &test.user_key);
    let user_addr = ScAddress::ClassicAccount(user_acc_id.clone());

    test.create_classic_account(
        &user_acc_id,
        vec![(&test.user_key, 100)],
        100_000_000,
        1,
        [1, 0, 0, 0],
        None,
        None,
        0,
    );

    assert_eq!(token.balance(user_addr.clone()).unwrap(), 100_000_000);
    // base reserve = 5_000_000
    // signer + account = 3 base reserves
    assert_eq!(token.spendable(user_addr.clone()).unwrap(), 85_000_000);
}

#[test]
fn test_trustline_auth() {
    let test = TokenTest::setup();
    // the admin is the issuer_key
    let admin_acc_id = signer_to_account_id(&test.host, &test.issuer_key);
    let user_acc_id = signer_to_account_id(&test.host, &test.user_key);

    test.create_classic_account(
        &admin_acc_id,
        vec![(&test.admin_key, 100)],
        10_000_000,
        1,
        [1, 0, 0, 0],
        None,
        None,
        0,
    );
    test.create_classic_account(
        &user_acc_id,
        vec![(&test.user_key, 100)],
        10_000_000,
        1,
        [1, 0, 0, 0],
        None,
        None,
        0,
    );

    let admin = TestSigner::account(&admin_acc_id, vec![&test.issuer_key]);
    let user = TestSigner::account(&user_acc_id, vec![&test.user_key]);
    let token = test.default_token_with_admin_id(&admin.address());

    // create a trustline for user_acc so the issuer can mint into it
    test.create_classic_trustline(
        &user_acc_id,
        &admin_acc_id,
        &test.asset_code,
        0,
        10000,
        TrustLineFlags::AuthorizedFlag as u32,
        Some((0, 0)),
    );

    //mint some token to the user
    token.mint(&admin, user.address(), 1000).unwrap();

    assert_eq!(token.balance(user.address()).unwrap(), 1000);

    // transfer 1 back to the issuer (which gets burned)
    token.xfer(&user, admin.address(), 1).unwrap();

    assert_eq!(token.balance(user.address()).unwrap(), 999);
    assert_eq!(token.balance(admin.address()).unwrap(), i64::MAX.into());

    // try to deauthorize trustline, but fail because RevocableFlag is not set
    // on the issuer
    assert_eq!(
        to_contract_err(token.set_auth(&admin, user.address(), false).err().unwrap()),
        ContractError::OperationNotSupportedError
    );

    // Add RevocableFlag to the issuer
    test.create_classic_account(
        &admin_acc_id,
        vec![(&test.admin_key, 100)],
        10_000_000,
        1,
        [1, 0, 0, 0],
        None,
        None,
        AccountFlags::RevocableFlag as u32,
    );

    // trustline should be deauthorized now.

    token.set_auth(&admin, user.address(), false).unwrap();

    // transfer should fail from deauthorized trustline
    assert_eq!(
        to_contract_err(token.xfer(&user, admin.address(), 1).err().unwrap()),
        ContractError::BalanceDeauthorizedError
    );

    // mint should also fail for the same reason
    assert_eq!(
        to_contract_err(token.mint(&admin, user.address(), 1000).err().unwrap()),
        ContractError::BalanceDeauthorizedError
    );

    // Now authorize trustline
    token.set_auth(&admin, user.address(), true).unwrap();

    // Balance operations are possible now.
    token.incr_allow(&user, admin.address(), 500).unwrap();
    token
        .xfer_from(&admin, user.address(), admin.address(), 500)
        .unwrap();
    token.mint(&admin, user.address(), 1).unwrap();

    assert_eq!(token.balance(user.address()).unwrap(), 500);

    // try to clawback
    assert_eq!(
        to_contract_err(token.clawback(&admin, user.address(), 10).err().unwrap()),
        ContractError::BalanceError
    );

    // set TrustlineClawbackEnabledFlag on trustline
    // Also add selling liabilities to test spendable balance
    test.create_classic_trustline(
        &user_acc_id,
        &admin_acc_id,
        &test.asset_code,
        500,
        10000,
        TrustLineFlags::TrustlineClawbackEnabledFlag as u32,
        Some((0, 10)),
    );

    token.clawback(&admin, user.address(), 10).unwrap();

    assert_eq!(token.balance(user.address()).unwrap(), 490);
    assert_eq!(token.spendable(user.address()).unwrap(), 480);
}

#[test]
fn test_account_invoker_auth_with_issuer_admin() {
    let test = TokenTest::setup();
    let admin_acc = signer_to_account_id(&test.host, &test.issuer_key);
    let user_acc = signer_to_account_id(&test.host, &test.user_key);

    test.create_classic_account(
        &admin_acc,
        vec![(&test.admin_key, 100)],
        10_000_000,
        1,
        [1, 0, 0, 0],
        None,
        None,
        0,
    );
    test.create_classic_account(
        &user_acc,
        vec![(&test.user_key, 100)],
        10_000_000,
        1,
        [1, 0, 0, 0],
        None,
        None,
        0,
    );

    let admin_address = ScAddress::ClassicAccount(admin_acc.clone());
    let user_address = ScAddress::ClassicAccount(user_acc.clone());
    let token = test.default_token_with_admin_id(&admin_address);
    // create a trustline for user_acc so the issuer can mint into it
    test.create_classic_trustline(
        &user_acc,
        &admin_acc,
        &test.asset_code,
        0,
        10000,
        TrustLineFlags::AuthorizedFlag as u32,
        Some((0, 0)),
    );

    // Admin invoker can perform admin operation.
    test.run_from_account(admin_acc.clone(), || {
        token.mint(
            &TestSigner::ClassicAccountInvoker,
            user_address.clone(),
            1000,
        )
    })
    .unwrap();

    // Make another succesful call.
    test.run_from_account(admin_acc.clone(), || {
        token.mint(
            &TestSigner::ClassicAccountInvoker,
            admin_address.clone(),
            2000,
        )
    })
    .unwrap();

    assert_eq!(token.balance(user_address.clone()).unwrap(), 1000);
    assert_eq!(
        token.balance(admin_address.clone()).unwrap(),
        i64::MAX.into()
    );

    // User invoker can't perform admin operation.
    assert_eq!(
        to_contract_err(
            test.run_from_account(user_acc.clone(), || {
                token.mint(
                    &TestSigner::ClassicAccountInvoker,
                    user_address.clone(),
                    1000,
                )
            })
            .err()
            .unwrap()
        ),
        ContractError::UnauthorizedError
    );

    // Perform transfers based on the invoker id.
    test.run_from_account(user_acc.clone(), || {
        token.xfer(
            &TestSigner::ClassicAccountInvoker,
            admin_address.clone(),
            500,
        )
    })
    .unwrap();

    test.run_from_account(admin_acc.clone(), || {
        token.xfer(
            &TestSigner::ClassicAccountInvoker,
            user_address.clone(),
            800,
        )
    })
    .unwrap();

    assert_eq!(token.balance(user_address.clone()).unwrap(), 1300);
    assert_eq!(
        token.balance(admin_address.clone()).unwrap(),
        i64::MAX.into()
    );

    // Contract invoker can't perform unauthorized admin operation.
    let contract_id = generate_bytes_array();
    let contract_invoker = TestSigner::ContractInvoker(Hash(contract_id.clone()));
    let contract_id_bytes = BytesN::<32>::try_from_val(
        &test.host,
        test.host.bytes_new_from_slice(&contract_id).unwrap(),
    )
    .unwrap();
    assert_eq!(
        to_contract_err(
            test.run_from_contract(&contract_id_bytes, || {
                token.mint(&contract_invoker, user_address.clone(), 1000)
            })
            .err()
            .unwrap()
        ),
        ContractError::UnauthorizedError
    );
}

#[test]
fn test_contract_invoker_auth() {
    let test = TokenTest::setup();

    let admin_contract_id = generate_bytes_array();
    let user_contract_id = generate_bytes_array();
    let admin_contract_invoker = TestSigner::ContractInvoker(Hash(admin_contract_id.clone()));
    let user_contract_invoker = TestSigner::ContractInvoker(Hash(user_contract_id.clone()));
    let admin_contract_address = ScAddress::Contract(Hash(admin_contract_id.clone()));
    let user_contract_address = ScAddress::Contract(Hash(user_contract_id.clone()));
    let admin_contract_id_bytes = BytesN::<32>::try_from_val(
        &test.host,
        test.host.bytes_new_from_slice(&admin_contract_id).unwrap(),
    )
    .unwrap();
    let user_contract_id_bytes = BytesN::<32>::try_from_val(
        &test.host,
        test.host.bytes_new_from_slice(&user_contract_id).unwrap(),
    )
    .unwrap();
    let token = test.default_token_with_admin_id(&admin_contract_address);

    test.run_from_contract(&admin_contract_id_bytes, || {
        token.mint(&admin_contract_invoker, user_contract_address.clone(), 1000)
    })
    .unwrap();

    // Make another succesful call
    test.run_from_contract(&admin_contract_id_bytes, || {
        token.mint(
            &admin_contract_invoker,
            admin_contract_address.clone(),
            2000,
        )
    })
    .unwrap();

    assert_eq!(token.balance(user_contract_address.clone()).unwrap(), 1000);
    assert_eq!(token.balance(admin_contract_address.clone()).unwrap(), 2000);

    // User contract invoker can't perform admin operation.
    assert_eq!(
        to_contract_err(
            test.run_from_contract(&user_contract_id_bytes, || {
                token.mint(&user_contract_invoker, user_contract_address.clone(), 1000)
            })
            .err()
            .unwrap()
        ),
        ContractError::UnauthorizedError
    );

    // Also don't allow an incorrect contract invoker (not a contract error, should
    // be some auth error)
    assert!(test
        .run_from_contract(&user_contract_id_bytes, || {
            token.mint(&admin_contract_invoker, user_contract_address.clone(), 1000)
        })
        .is_err());

    // Perform transfers based on the invoker id.
    test.run_from_contract(&user_contract_id_bytes, || {
        token.xfer(&user_contract_invoker, admin_contract_address.clone(), 500)
    })
    .unwrap();

    test.run_from_contract(&admin_contract_id_bytes, || {
        token.xfer(&admin_contract_invoker, user_contract_address.clone(), 800)
    })
    .unwrap();

    assert_eq!(token.balance(user_contract_address.clone()).unwrap(), 1300);
    assert_eq!(token.balance(admin_contract_address.clone()).unwrap(), 1700);

    // Account invoker can't perform unauthorized admin operation.
    let acc_invoker = TestSigner::ClassicAccountInvoker;
    assert_eq!(
        to_contract_err(
            test.run_from_account(signer_to_account_id(&test.host, &test.admin_key), || {
                token.mint(&acc_invoker, user_contract_address.clone(), 1000)
            })
            .err()
            .unwrap()
        ),
        ContractError::UnauthorizedError
    );
}

// #[test]
// fn test_auth_rejected_with_incorrect_nonce() {
//     let test = TokenTest::setup();
//     let admin = TestSigner::Ed25519(&test.admin_key);
//     let token = test.default_token(&admin);
//     let user = TestSigner::Ed25519(&test.user_key);
//     let user_2 = TestSigner::Ed25519(&test.user_key_2);

//     token
//         .mint(
//             &admin,
//             token.nonce(admin.get_address()).unwrap(),
//             user.get_address(),
//             100_000_000,
//         )
//         .unwrap();

//     // Bump user's nonce and approve some amount to cover xfer_from below.
//     token
//         .approve(
//             &user,
//             0,
//             user_2.get_address(),
//             1000,
//         )
//         .unwrap();

//     assert_eq!(
//         to_contract_err(
//             token
//                 .xfer(
//                     &user,
//                     2,
//                     user_2.get_address(),
//                     1000
//                 )
//                 .err()
//                 .unwrap()
//         ),
//         ContractError::NonceError
//     );

//     assert_eq!(
//         to_contract_err(
//             token
//                 .approve(
//                     &user,
//                     2,
//                     user_2.get_address(),
//                     1000
//                 )
//                 .err()
//                 .unwrap()
//         ),
//         ContractError::NonceError
//     );
//     assert_eq!(
//         to_contract_err(
//             token
//                 .xfer_from(
//                     &user_2,
//                     1,
//                     user.get_address(),
//                     user_2.get_address(),
//                     100
//                 )
//                 .err()
//                 .unwrap()
//         ),
//         ContractError::NonceError
//     );
//     assert_eq!(
//         to_contract_err(
//             token
//                 .mint(
//                     &admin,
//                     2,
//                     user.get_address(),
//                     10_000_000,
//                 )
//                 .err()
//                 .unwrap()
//         ),
//         ContractError::NonceError
//     );
//     assert_eq!(
//         to_contract_err(
//             token
//                 .burn(
//                     &admin,
//                     2,
//                     user.get_address(),
//                     10_000_000,
//                 )
//                 .err()
//                 .unwrap()
//         ),
//         ContractError::NonceError
//     );
//     assert_eq!(
//         to_contract_err(
//             token
//                 .set_admin(
//                     &admin,
//                     2,
//                     user.get_address()
//                 )
//                 .err()
//                 .unwrap()
//         ),
//         ContractError::NonceError
//     );
// }

// #[test]
// fn test_auth_rejected_with_incorrect_signer() {
//     let test = TokenTest::setup();
//     let admin = TestSigner::Ed25519(&test.admin_key);
//     let token = test.default_token(&admin);
//     let user = TestSigner::Ed25519(&test.user_key);

//     // let admin_acc = AccountAuthBuilder::new(self.host, user)
//     //     .add_invocation(
//     //         &self.id,
//     //         "mint",
//     //         host_vec![self.host, to.clone(), amount.clone()],
//     //     )
//     //     .build();

//     assert!(self
//         .host
//         .call(
//             token.id.clone().into(),
//             Symbol::from_str("mint").into(),
//             host_vec![self.host, admin_acc, to, amount].into(),
//         )
//         .is_err());
// }

#[test]
fn test_auth_rejected_for_incorrect_function_name() {
    let test = TokenTest::setup();
    let admin = TestSigner::Ed25519(&test.admin_key);
    let token = test.default_token(&admin);
    let user = TestSigner::Ed25519(&test.user_key);

    let amount = 1000;
    let admin_acc = AccountAuthBuilder::new(&test.host, &admin)
        .add_invocation(
            &token.id,
            "burn",
            host_vec![&test.host, user.address(), amount.clone()],
        )
        .build();

    assert!(test
        .host
        .call(
            token.id.clone().into(),
            Symbol::from_str("mint").into(),
            host_vec![&test.host, admin_acc, user.address(), amount].into(),
        )
        .is_err());
}

#[test]
fn test_auth_rejected_for_incorrect_function_args() {
    let test = TokenTest::setup();
    let admin = TestSigner::Ed25519(&test.admin_key);
    let token = test.default_token(&admin);
    let user = TestSigner::Ed25519(&test.user_key);

    let admin_acc = AccountAuthBuilder::new(&test.host, &admin)
        .add_invocation(
            &token.id,
            "mint",
            host_vec![&test.host, user.address(), 1000],
        )
        .build();

    assert!(test
        .host
        .call(
            token.id.clone().into(),
            Symbol::from_str("mint").into(),
            host_vec![&test.host, admin_acc, user.address(), 1_000_000].into(),
        )
        .is_err());
}

#[test]
fn test_classic_account_multisig_auth() {
    let test = TokenTest::setup();

    let account_id = signer_to_account_id(&test.host, &test.user_key);
    test.create_classic_account(
        &account_id,
        vec![
            (&test.user_key_2, u32::MAX),
            (&test.user_key_3, 60),
            (&test.user_key_4, 59),
        ],
        100_000_000,
        1,
        // NB: first threshold is in fact weight of account_id signature.
        [40, 10, 100, 150],
        None,
        None,
        0,
    );
    let token = TestToken::new_from_asset(&test.host, Asset::Native);
    let receiver = TestSigner::Ed25519(&test.user_key).address();

    // Success: account weight (60) + 40 = 100
    token
        .xfer(
            &TestSigner::account(&account_id, vec![&test.user_key, &test.user_key_3]),
            receiver.clone(),
            100,
        )
        .unwrap();

    // Success: 1 high weight signer (u32::MAX)
    token
        .xfer(
            &TestSigner::account(&account_id, vec![&test.user_key_2]),
            receiver.clone(),
            100,
        )
        .unwrap();

    // Success: 60 + 59 > 100, no account signature
    token
        .xfer(
            &TestSigner::account(&account_id, vec![&test.user_key_3, &test.user_key_4]),
            receiver.clone(),
            100,
        )
        .unwrap();

    // Success: 40 + 60 + 59 > 100
    token
        .xfer(
            &TestSigner::account(
                &account_id,
                vec![&test.user_key, &test.user_key_3, &test.user_key_4],
            ),
            receiver.clone(),
            100,
        )
        .unwrap();

    // Success: all signers
    token
        .xfer(
            &TestSigner::account(
                &account_id,
                vec![
                    &test.user_key,
                    &test.user_key_2,
                    &test.user_key_3,
                    &test.user_key_4,
                ],
            ),
            receiver.clone(),
            100,
        )
        .unwrap();

    // Failure: only account weight (40)
    assert_eq!(
        to_contract_err(
            token
                .xfer(
                    &TestSigner::account(&account_id, vec![&test.user_key]),
                    receiver.clone(),
                    100,
                )
                .err()
                .unwrap()
        ),
        ContractError::AuthenticationError
    );

    // Failure: 40 + 59 < 100
    assert_eq!(
        to_contract_err(
            token
                .xfer(
                    &TestSigner::account(&account_id, vec![&test.user_key, &test.user_key_4]),
                    receiver.clone(),
                    100,
                )
                .err()
                .unwrap()
        ),
        ContractError::AuthenticationError
    );

    // Failure: 60 < 100, duplicate signatures
    assert_eq!(
        to_contract_err(
            token
                .xfer(
                    &TestSigner::account(&account_id, vec![&test.user_key_3, &test.user_key_3]),
                    receiver.clone(),
                    100,
                )
                .err()
                .unwrap()
        ),
        ContractError::AuthenticationError
    );

    // Failure: 60 + 59 > 100, duplicate signatures
    assert_eq!(
        to_contract_err(
            token
                .xfer(
                    &TestSigner::account(
                        &account_id,
                        vec![&test.user_key_3, &test.user_key_4, &test.user_key_3],
                    ),
                    receiver.clone(),
                    100,
                )
                .err()
                .unwrap()
        ),
        ContractError::AuthenticationError
    );

    // Failure: 60 < 100 and incorrect signer
    assert_eq!(
        to_contract_err(
            token
                .xfer(
                    &TestSigner::account(&account_id, vec![&test.user_key_3, &test.admin_key],),
                    receiver.clone(),
                    100,
                )
                .err()
                .unwrap()
        ),
        ContractError::AuthenticationError
    );

    // Failure: 60 + 59 > 100, but have incorrect signer
    assert_eq!(
        to_contract_err(
            token
                .xfer(
                    &TestSigner::account(
                        &account_id,
                        vec![&test.user_key_3, &test.user_key_4, &test.admin_key],
                    ),
                    receiver.clone(),
                    100,
                )
                .err()
                .unwrap()
        ),
        ContractError::AuthenticationError
    );

    // Failure: too many signatures (even though weight would be enough after
    // deduplication).
    let mut too_many_sigs = vec![];
    for _ in 0..21 {
        too_many_sigs.push(&test.user_key_2);
    }
    assert_eq!(
        to_contract_err(
            token
                .xfer(
                    &TestSigner::account(&account_id, too_many_sigs,),
                    receiver.clone(),
                    100,
                )
                .err()
                .unwrap()
        ),
        ContractError::AuthenticationError
    );

    // Failure: out of order signers
    let mut out_of_order_signers = vec![
        &test.user_key,
        &test.user_key_2,
        &test.user_key_3,
        &test.user_key_4,
    ];
    out_of_order_signers.sort_by_key(|k| k.public.as_bytes());
    out_of_order_signers.swap(1, 2);
    assert_eq!(
        to_contract_err(
            token
                .xfer(
                    &TestSigner::Account(AccountSigner {
                        account_id: account_id,
                        signers: out_of_order_signers,
                    }),
                    receiver.clone(),
                    100,
                )
                .err()
                .unwrap()
        ),
        ContractError::AuthenticationError
    );
}

#[test]
fn test_negative_amounts_are_not_allowed() {
    let test = TokenTest::setup();
    let admin = TestSigner::Ed25519(&test.admin_key);
    let token = test.default_token(&admin);

    let user = TestSigner::Ed25519(&test.user_key);
    let user_2 = TestSigner::Ed25519(&test.user_key_2);
    token.mint(&admin, user.address(), 100_000_000).unwrap();

    assert_eq!(
        to_contract_err(token.mint(&admin, user.address(), -1,).err().unwrap()),
        ContractError::NegativeAmountError
    );

    assert_eq!(
        to_contract_err(token.clawback(&admin, user.address(), -1,).err().unwrap()),
        ContractError::NegativeAmountError
    );

    assert_eq!(
        to_contract_err(token.xfer(&user, user_2.address(), -1).err().unwrap()),
        ContractError::NegativeAmountError
    );

    assert_eq!(
        to_contract_err(token.incr_allow(&user, user_2.address(), -1).err().unwrap()),
        ContractError::NegativeAmountError
    );

    assert_eq!(
        to_contract_err(token.decr_allow(&user, user_2.address(), -1).err().unwrap()),
        ContractError::NegativeAmountError
    );

    // Approve some balance before doing the negative xfer_from.
    token.incr_allow(&user, user_2.address(), 10_000).unwrap();

    assert_eq!(
        to_contract_err(
            token
                .xfer_from(&user_2, user.address(), user_2.address(), -1,)
                .err()
                .unwrap()
        ),
        ContractError::NegativeAmountError
    );
}

fn test_native_token_classic_balance_boundaries(
    test: &TokenTest,
    user: &TestSigner,
    account_id: &AccountId,
    init_balance: i64,
    expected_min_balance: i64,
    expected_max_balance: i64,
) {
    let token = TestToken::new_from_asset(&test.host, Asset::Native);

    let new_balance_key = generate_keypair();
    let new_balance_acc = signer_to_account_id(&test.host, &new_balance_key);
    let new_balance_signer = TestSigner::account(&new_balance_acc, vec![&new_balance_key]);
    test.create_classic_account(
        &new_balance_acc,
        vec![(&new_balance_key, 100)],
        10_000_000,
        0,
        [1, 0, 0, 0],
        None,
        None,
        0,
    );

    // Try to do xfer that would leave balance lower than min.
    assert_eq!(
        to_contract_err(
            token
                .xfer(
                    &user,
                    new_balance_signer.address(),
                    (init_balance - expected_min_balance + 1).into(),
                )
                .err()
                .unwrap()
        ),
        ContractError::BalanceError
    );

    // now transfer spendable balance
    token
        .xfer(
            &user,
            new_balance_signer.address(),
            (init_balance - expected_min_balance).into(),
        )
        .unwrap();
    assert_eq!(test.get_native_balance(account_id), expected_min_balance);

    // now transfer back
    token
        .xfer(
            &new_balance_signer,
            user.address(),
            (init_balance - expected_min_balance).into(),
        )
        .unwrap();

    // Create an account with balance close to i64::MAX and transfer it
    // to the account being tested. That's not a realistic scenario
    // given limited XLM supply, but that's the only way to
    // cover max_balance.
    let large_balance_key = generate_keypair();
    let large_balance_acc = signer_to_account_id(&test.host, &large_balance_key);
    let large_balance_signer = TestSigner::account(&large_balance_acc, vec![&large_balance_key]);
    test.create_classic_account(
        &large_balance_acc,
        vec![(&large_balance_key, 100)],
        i64::MAX,
        0,
        [1, 0, 0, 0],
        None,
        None,
        0,
    );

    // Transferring a balance that would exceed
    // expected_max_balance shouldn't be possible.
    assert_eq!(
        to_contract_err(
            token
                .xfer(
                    &large_balance_signer,
                    user.address(),
                    (expected_max_balance - init_balance + 1).into(),
                )
                .err()
                .unwrap()
        ),
        ContractError::BalanceError
    );

    // ...but transferring exactly up to expected_max_balance should be
    // possible.
    token
        .xfer(
            &large_balance_signer,
            user.address(),
            (expected_max_balance - init_balance).into(),
        )
        .unwrap();

    assert_eq!(test.get_native_balance(account_id), expected_max_balance);
}

#[test]
fn test_native_token_classic_balance_boundaries_simple() {
    let test = TokenTest::setup();

    let account_id = signer_to_account_id(&test.host, &test.user_key);
    let user = TestSigner::account(&account_id, vec![&test.user_key]);
    // Account with no liabilities/sponsorships.
    test.create_classic_account(
        &account_id,
        vec![(&test.user_key, 100)],
        100_000_000,
        5,
        [1, 0, 0, 0],
        None,
        None,
        0,
    );
    // Min balance should be
    // (2 (account) + 5 (subentries)) * base_reserve = 35_000_000.
    test_native_token_classic_balance_boundaries(
        &test,
        &user,
        &account_id,
        100_000_000,
        35_000_000,
        i64::MAX,
    );
}

#[test]
fn test_native_token_classic_balance_boundaries_with_liabilities() {
    let test = TokenTest::setup();
    let account_id = signer_to_account_id(&test.host, &test.user_key);
    let user = TestSigner::account(&account_id, vec![&test.user_key]);
    test.create_classic_account(
        &account_id,
        vec![(&test.user_key, 100)],
        1_000_000_000,
        8,
        [1, 0, 0, 0],
        Some((300_000_000, 500_000_000)),
        None,
        0,
    );
    // Min balance should be
    // (2 (account) + 8 (subentries)) * base_reserve + 500_000_000 (selling
    // liabilities) = 550_000_000.
    // Max balance should be i64::MAX - 300_000_000 (buying liabilities).
    test_native_token_classic_balance_boundaries(
        &test,
        &user,
        &account_id,
        1_000_000_000,
        550_000_000,
        i64::MAX - 300_000_000,
    );
}

#[test]
fn test_native_token_classic_balance_boundaries_with_sponsorships() {
    let test = TokenTest::setup();
    let account_id = signer_to_account_id(&test.host, &test.user_key);
    let user = TestSigner::account(&account_id, vec![&test.user_key]);
    test.create_classic_account(
        &account_id,
        vec![(&test.user_key, 100)],
        100_000_000,
        5,
        [1, 0, 0, 0],
        None,
        Some((3, 6)),
        0,
    );
    // Min balance should be
    // (2 (account) + 5 (subentries) + (6 sponsoring - 3 sponsored)) * base_reserve
    // = 50_000_000.
    test_native_token_classic_balance_boundaries(
        &test,
        &user,
        &account_id,
        100_000_000,
        50_000_000,
        i64::MAX,
    );
}

#[test]
fn test_native_token_classic_balance_boundaries_with_sponsorships_and_liabilities() {
    let test = TokenTest::setup();
    let account_id = signer_to_account_id(&test.host, &test.user_key);
    let user = TestSigner::account(&account_id, vec![&test.user_key]);
    test.create_classic_account(
        &account_id,
        vec![(&test.user_key, 100)],
        1_000_000_000,
        5,
        [1, 0, 0, 0],
        Some((300_000_000, 500_000_000)),
        Some((3, 6)),
        0,
    );
    // Min balance should be
    // (2 (account) + 5 (subentries) + (6 sponsoring - 3 sponsored)) * base_reserve
    // + 500_000_000 = 550_000_000.
    // Max balance should be i64::MAX - 300_000_000 (buying liabilities).
    test_native_token_classic_balance_boundaries(
        &test,
        &user,
        &account_id,
        1_000_000_000,
        550_000_000,
        i64::MAX - 300_000_000,
    );
}

#[test]
fn test_native_token_classic_balance_boundaries_with_large_values() {
    let test = TokenTest::setup();
    let account_id = signer_to_account_id(&test.host, &test.user_key);
    let user = TestSigner::account(&account_id, vec![&test.user_key]);
    test.create_classic_account(
        &account_id,
        vec![(&test.user_key, 100)],
        i64::MAX - i64::MAX / 4,
        u32::MAX,
        [1, 0, 0, 0],
        Some((i64::MAX / 4, i64::MAX / 5)),
        Some((0, u32::MAX)),
        0,
    );
    test_native_token_classic_balance_boundaries(
        &test,
        &user,
        &account_id,
        i64::MAX - i64::MAX / 4,
        (2 /* account */ + u32::MAX as i64 /* sub-entries */ + u32::MAX as i64/* sponsoring - sponsored */)
            * 5_000_000
            + i64::MAX / 5, /* Selling liabilities */
        i64::MAX - i64::MAX / 4, /* Buying liabilities */
    );
}

fn test_wrapped_asset_classic_balance_boundaries(
    init_balance: i64,
    expected_min_balance: i64,
    expected_max_balance: i64,
    // (buying, selling) liabilities
    liabilities: Option<(i64, i64)>,
    limit: i64,
) {
    let test = TokenTest::setup();
    let account_id = signer_to_account_id(&test.host, &test.user_key);
    let user = TestSigner::account(&account_id, vec![&test.user_key]);
    test.create_classic_account(
        &account_id,
        vec![(&test.user_key, 100)],
        10_000_000,
        0,
        [1, 0, 0, 0],
        None,
        None,
        0,
    );

    let account_id2 = signer_to_account_id(&test.host, &test.user_key_2);
    let user2 = TestSigner::account(&account_id2, vec![&test.user_key_2]);
    test.create_classic_account(
        &account_id2,
        vec![(&test.user_key_2, 100)],
        10_000_000,
        0,
        [1, 0, 0, 0],
        None,
        None,
        0,
    );

    let issuer_id = signer_to_account_id(&test.host, &test.admin_key);
    let issuer = TestSigner::account(&issuer_id, vec![&test.admin_key]);
    test.create_classic_account(
        &issuer_id,
        vec![(&test.admin_key, 100)],
        10_000_000,
        0,
        [1, 0, 0, 0],
        None,
        None,
        0,
    );

    let trustline_key = test.create_classic_trustline(
        &account_id,
        &issuer_id,
        &[255; 12],
        init_balance,
        limit,
        TrustLineFlags::AuthorizedFlag as u32,
        liabilities,
    );

    let trustline_key2 = test.create_classic_trustline(
        &account_id2,
        &issuer_id,
        &[255; 12],
        0,
        limit,
        TrustLineFlags::AuthorizedFlag as u32,
        Some((0, 0)),
    );

    let token = TestToken::new_from_asset(
        &test.host,
        Asset::CreditAlphanum12(AlphaNum12 {
            asset_code: AssetCode12([255; 12]),
            issuer: AccountId(PublicKey::PublicKeyTypeEd25519(
                test.host.to_u256_from_account(&issuer_id).unwrap(),
            )),
        }),
    );
    // Try to do transfer that would leave balance lower than min.
    assert_eq!(
        to_contract_err(
            token
                .xfer(
                    &user,
                    user2.address(),
                    (init_balance - expected_min_balance + 1).into(),
                )
                .err()
                .unwrap()
        ),
        ContractError::BalanceError
    );

    // Send spendable balance
    token
        .xfer(
            &user,
            user2.address(),
            (init_balance - expected_min_balance).into(),
        )
        .unwrap();
    assert_eq!(
        test.get_classic_trustline_balance(&trustline_key),
        expected_min_balance
    );

    assert_eq!(
        test.get_classic_trustline_balance(&trustline_key2),
        init_balance - expected_min_balance
    );

    // Send back
    token
        .xfer(
            &user2,
            user.address(),
            (init_balance - expected_min_balance).into(),
        )
        .unwrap();

    // Minting amount that would exceed expected_max_balance
    // shouldn't be possible.
    assert_eq!(
        to_contract_err(
            token
                .mint(
                    &issuer,
                    user.address(),
                    (expected_max_balance - init_balance + 1).into(),
                )
                .err()
                .unwrap()
        ),
        ContractError::BalanceError
    );

    // ...but transferring exactly up to expected_max_balance should be
    // possible.
    token
        .mint(
            &issuer,
            user.address(),
            (expected_max_balance - init_balance).into(),
        )
        .unwrap();

    assert_eq!(
        test.get_classic_trustline_balance(&trustline_key),
        expected_max_balance
    );
    assert_eq!(test.get_classic_trustline_balance(&trustline_key2), 0);
}

#[test]
fn test_asset_token_classic_balance_boundaries_simple() {
    test_wrapped_asset_classic_balance_boundaries(100_000_000, 0, i64::MAX, None, i64::MAX);
}

#[test]
fn test_asset_token_classic_balance_boundaries_with_trustline_limit() {
    test_wrapped_asset_classic_balance_boundaries(100_000_000, 0, 200_000_000, None, 200_000_000);
}

#[test]
fn test_asset_token_classic_balance_boundaries_with_liabilities() {
    test_wrapped_asset_classic_balance_boundaries(
        100_000_000,
        300_000,
        i64::MAX - 500_000,
        Some((500_000, 300_000)),
        i64::MAX,
    );
}

#[test]
fn test_asset_token_classic_balance_boundaries_with_limit_and_liabilities() {
    test_wrapped_asset_classic_balance_boundaries(
        100_000_000,
        300_000,
        150_000_000, /* = 200_000_000 (limit) - 50_000_000 (buying liabilities) */
        Some((50_000_000, 300_000)),
        200_000_000,
    );
}

#[test]
fn test_asset_token_classic_balance_boundaries_large_values() {
    test_wrapped_asset_classic_balance_boundaries(
        i64::MAX - i64::MAX / 5,
        i64::MAX / 4,
        i64::MAX - i64::MAX / 5,
        Some((i64::MAX / 5, i64::MAX / 4)),
        i64::MAX,
    );
}

#[test]
fn test_classic_transfers_not_possible_for_unauthorized_asset() {
    let test = TokenTest::setup();
    let account_id = signer_to_account_id(&test.host, &test.user_key);
    let user = TestSigner::account(&account_id, vec![&test.user_key]);
    test.create_classic_account(
        &account_id,
        vec![(&test.user_key, 100)],
        10_000_000,
        0,
        [1, 0, 0, 0],
        None,
        None,
        0,
    );

    let issuer_id = signer_to_account_id(&test.host, &test.admin_key);

    let trustline_key = test.create_classic_trustline(
        &account_id,
        &issuer_id,
        &[255; 4],
        100_000_000,
        i64::MAX,
        TrustLineFlags::AuthorizedFlag as u32,
        None,
    );

    assert_eq!(
        test.get_classic_trustline_balance(&trustline_key),
        100_000_000
    );

    let token = TestToken::new_from_asset(
        &test.host,
        Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([255; 4]),
            issuer: AccountId(PublicKey::PublicKeyTypeEd25519(
                test.host.to_u256_from_account(&issuer_id).unwrap(),
            )),
        }),
    );

    // Authorized to xfer
    token.xfer(&user, user.address(), 1_i128).unwrap();

    // Override the trustline authorization flag.
    let trustline_key = test.create_classic_trustline(
        &account_id,
        &issuer_id,
        &[255; 4],
        100_000_000,
        i64::MAX,
        0,
        None,
    );

    // No longer authorized
    assert_eq!(
        to_contract_err(token.xfer(&user, user.address(), 1_i128,).err().unwrap()),
        ContractError::BalanceDeauthorizedError
    );

    // Trustline balance stays the same.
    assert_eq!(
        test.get_classic_trustline_balance(&trustline_key),
        100_000_000
    );
}

fn simple_account_sign_fn<'a>(
    host: &'a Host,
    kp: &'a Keypair,
) -> Box<dyn Fn(&[u8]) -> HostVec + 'a> {
    Box::new(|payload: &[u8]| -> HostVec {
        let signature = sign_payload_for_ed25519(host, kp, payload);
        host_vec![host, signature]
    })
}

#[test]
fn test_custom_account_auth() {
    let test = TokenTest::setup();
    let admin_kp = generate_keypair();
    let account_contract_id_obj = test
        .host
        .register_test_contract_wasm(SIMPLE_ACCOUNT_CONTRACT)
        .unwrap();
    let account_contract_id = test
        .host
        .hash_from_obj_input("account_contract_id", account_contract_id_obj)
        .unwrap();

    let admin = TestSigner::GenericAccount(GenericAccountSigner {
        id: account_contract_id.clone(),
        sign: simple_account_sign_fn(&test.host, &admin_kp),
    });

    let admin_public_key = BytesN::<32>::try_from_val(
        &test.host,
        test.host
            .bytes_new_from_slice(admin_kp.public.as_bytes().as_slice())
            .unwrap(),
    )
    .unwrap();
    // Initialize the admin account
    test.host
        .call(
            account_contract_id_obj.clone(),
            Symbol::from_str("init"),
            host_vec![&test.host, admin_public_key.clone()].into(),
        )
        .unwrap();

    let token = test.default_token(&admin);
    let user_address = TestSigner::Ed25519(&test.user_key).address();
    token.mint(&admin, user_address.clone(), 100).unwrap();
    assert_eq!(token.balance(user_address.clone()).unwrap(), 100);

    // Create a signer for the new admin, but not yet set its key as the account
    // owner.
    let new_admin_kp = generate_keypair();
    let new_admin = TestSigner::GenericAccount(GenericAccountSigner {
        id: account_contract_id.clone(),
        sign: simple_account_sign_fn(&test.host, &new_admin_kp),
    });
    let new_admin_public_key = BytesN::<32>::try_from_val(
        &test.host,
        test.host
            .bytes_new_from_slice(new_admin_kp.public.as_bytes().as_slice())
            .unwrap(),
    )
    .unwrap();
    // The new signer can't authorize admin ops.
    assert!(token.mint(&new_admin, user_address.clone(), 100).is_err());

    // Create account for the 'set_owner' invocation with the current owner signature.
    let admin_acc = AccountAuthBuilder::new(&test.host, &admin)
        .add_invocation(
            &BytesN::<32>::try_from_val(&test.host, account_contract_id_obj).unwrap(),
            "set_owner",
            host_vec![&test.host, new_admin_public_key.clone()].into(),
        )
        .build();

    // Change the owner of the account.
    test.host
        .call(
            account_contract_id_obj.clone(),
            Symbol::from_str("set_owner"),
            host_vec![&test.host, admin_acc, new_admin_public_key].into(),
        )
        .unwrap();

    // Now the token ops should work with the signatures from the new admin
    // account owner.
    token.mint(&new_admin, user_address.clone(), 100).unwrap();
    assert_eq!(token.balance(user_address.clone()).unwrap(), 200);

    // And they shouldn't work with the old owner signatures.
    assert!(token.mint(&admin, user_address.clone(), 100).is_err());
}

#[test]
fn test_recording_auth_for_token() {
    let snapshot_source = Rc::<MockSnapshotSource>::new(MockSnapshotSource::new());
    let storage = Storage::with_recording_footprint(snapshot_source);
    let budget = Budget::default();
    let host = Host::with_storage_and_budget(
        storage,
        budget.clone(),
        AuthorizationManager::new_recording(budget),
    );
    host.set_ledger_info(Default::default());

    let admin_acc_id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
        generate_bytes_array(),
    )));
    let admin_address = ScAddress::ClassicAccount(admin_acc_id.clone());
    let admin_account = ScAccount {
        account_id: ScAccountId::BuiltinClassicAccount(admin_acc_id.clone()),
        invocations: vec![].try_into().unwrap(),
        signature_args: ScVec(vec![].try_into().unwrap()),
    };
    let token = TestToken::new_from_asset(
        &host,
        Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([0; 4]),
            issuer: admin_acc_id.clone(),
        }),
    );

    let user = ScAddress::Contract(Hash(generate_bytes_array()));
    let args_vec = host_vec![&host, admin_account, user.clone(), 100_i128];

    host.call(
        token.id.clone().into(),
        Symbol::from_str("mint"),
        args_vec.clone().into(),
    )
    .unwrap();
    let recorded_payloads = host.get_recorded_account_signature_payloads().unwrap();

    assert_eq!(
        recorded_payloads,
        vec![RecordedSignaturePayload {
            account_address: admin_address.clone(),
            invocations: vec![xdr::AuthorizedInvocation {
                call_stack: vec![xdr::ContractInvocation {
                    contract_id: Hash(token.id.to_array().unwrap()),
                    function_name: "mint".try_into().unwrap(),
                }]
                .try_into()
                .unwrap(),
                top_args: ScVec(
                    vec![
                        user.try_into_val(&host)
                            .unwrap()
                            .try_into_val(&host)
                            .unwrap(),
                        <i128 as soroban_env_common::IntoVal<Host, RawVal>>::into_val(
                            100_i128, &host
                        )
                        .try_into_val(&host)
                        .unwrap(),
                    ]
                    .try_into()
                    .unwrap()
                ),
                nonce: Some(0),
            }]
        }]
    );
}
