use std::{convert::TryInto, rc::Rc};

use crate::{
    budget::Budget,
    host_vec,
    native_contract::{
        base_types::BigInt,
        testutils::{
            generate_bytes, generate_keypair, sign_args, signer_to_id_bytes, AccountSigner,
            HostVec, TestSigner,
        },
        token::{
            public_types::{Ed25519Signature, Identifier, Signature, TokenMetadata},
            test_token::TestToken,
        },
    },
    storage::{test_storage::MockSnapshotSource, Storage},
    Host, LedgerInfo,
};
use ed25519_dalek::Keypair;
use soroban_env_common::{
    xdr::{
        AccountEntry, AccountEntryExt, AccountEntryExtensionV1, AccountEntryExtensionV1Ext,
        AccountEntryExtensionV2, AccountEntryExtensionV2Ext, AccountId, AlphaNum12, AlphaNum4,
        Asset, AssetCode12, AssetCode4, LedgerEntry, LedgerEntryData, LedgerEntryExt, LedgerKey,
        Liabilities, PublicKey, SequenceNumber, SignerKey, Thresholds, TrustLineEntry,
        TrustLineEntryExt, TrustLineEntryV1, TrustLineEntryV1Ext, TrustLineFlags,
    },
    Status,
};
use soroban_env_common::{CheckedEnv, EnvBase, Symbol, TryFromVal, TryIntoVal};

use crate::native_contract::base_types::{Bytes, BytesN};

struct TokenTest {
    host: Host,
    admin_key: Keypair,
    user_key: Keypair,
    user_key_2: Keypair,
    user_key_3: Keypair,
    user_key_4: Keypair,
}

impl TokenTest {
    fn setup() -> Self {
        let snapshot_source = Rc::<MockSnapshotSource>::new(MockSnapshotSource::new());
        let storage = Storage::with_recording_footprint(snapshot_source);
        let host = Host::with_storage_and_budget(storage, Budget::default());
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
            user_key: generate_keypair(),
            user_key_2: generate_keypair(),
            user_key_3: generate_keypair(),
            user_key_4: generate_keypair(),
        }
    }

    fn default_smart_token(&self, admin: &TestSigner) -> TestToken {
        let token = TestToken::new(&self.host);
        token
            .init_token(
                admin.get_identifier(&self.host),
                TokenMetadata {
                    name: self.convert_bytes(b"abcd"),
                    symbol: self.convert_bytes(b"123xyz"),
                    decimals: 8,
                },
            )
            .unwrap();
        token
    }

    fn get_native_balance(&self, account_id: &BytesN<32>) -> i64 {
        let account = self.host.load_account(account_id.clone().into()).unwrap();
        account.balance
    }

    fn get_classic_trustline_balance(&self, key: &LedgerKey) -> i64 {
        self.host
            .visit_storage(|s| match s.get(key).unwrap().data {
                LedgerEntryData::Trustline(trustline) => Ok(trustline.balance),
                _ => unreachable!(),
            })
            .unwrap()
    }

    fn create_classic_account(
        &self,
        account_id_bytes: &BytesN<32>,
        signers: Vec<(&Keypair, u32)>,
        balance: i64,
        num_sub_entries: u32,
        thresholds: [u8; 4],
        // (buying, selling) liabilities
        liabilities: Option<(i64, i64)>,
        // (num_sponsored, num_sponsoring) counts
        sponsorships: Option<(u32, u32)>,
    ) {
        let key = self
            .host
            .to_account_key(account_id_bytes.clone().into())
            .unwrap();
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
            flags: 0,
            home_domain: Default::default(),
            thresholds: Thresholds(thresholds),
            signers: acc_signers.try_into().unwrap(),
            ext,
        };

        self.host
            .add_ledger_entry(
                key,
                LedgerEntry {
                    last_modified_ledger_seq: 0,
                    data: LedgerEntryData::Account(acc_entry),
                    ext: LedgerEntryExt::V0,
                },
            )
            .unwrap();
    }

    fn create_classic_trustline(
        &self,
        account_id_bytes: &BytesN<32>,
        issuer_id_bytes: &BytesN<32>,
        asset_code: &[u8],
        balance: i64,
        limit: i64,
        authorized: bool,
        // (buying, selling) liabilities
        liabilities: Option<(i64, i64)>,
    ) -> LedgerKey {
        let asset_code_bytes = Bytes::try_from_val(
            &self.host,
            self.host.bytes_new_from_slice(asset_code).unwrap(),
        )
        .unwrap();
        let key = self
            .host
            .to_trustline_key(
                account_id_bytes.clone().into(),
                asset_code_bytes.into(),
                issuer_id_bytes.clone().into(),
            )
            .unwrap();
        let (account_id, asset) = match &key {
            LedgerKey::Trustline(trustline_key) => (
                trustline_key.account_id.clone(),
                trustline_key.asset.clone(),
            ),
            _ => unreachable!(),
        };
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
            account_id,
            asset,
            balance,
            limit, // TODO: Check if we need to enforce this
            flags: if authorized {
                TrustLineFlags::AuthorizedFlag as u32
            } else {
                0
            },
            ext,
        };

        self.host
            .add_ledger_entry(
                key.clone(),
                LedgerEntry {
                    last_modified_ledger_seq: 0,
                    data: LedgerEntryData::Trustline(trustline_entry),
                    ext: LedgerEntryExt::V0,
                },
            )
            .unwrap();

        key
    }

    fn convert_bytes(&self, bytes: &[u8]) -> Bytes {
        Bytes::try_from_val(&self.host, self.host.bytes_new_from_slice(bytes).unwrap()).unwrap()
    }
}

#[test]
fn test_smart_token_init_and_balance() {
    let test = TokenTest::setup();
    let token = TestToken::new(&test.host);
    let admin = TestSigner::Ed25519(&test.admin_key);
    let token_metadata = TokenMetadata {
        name: test.convert_bytes(&[0, 0, b'a']),
        symbol: test.convert_bytes(&[255, 123, 0, b'a']),
        decimals: 0xffffffff,
    };
    token
        .init_token(admin.get_identifier(&test.host), token_metadata.clone())
        .unwrap();

    // Make sure double initialization is not possible.
    assert!(token
        .init_token(admin.get_identifier(&test.host), token_metadata.clone())
        .is_err());

    assert_eq!(token.name().unwrap().to_vec(), vec![0, 0, b'a']);
    assert_eq!(token.symbol().unwrap().to_vec(), vec![255, 123, 0, b'a']);
    assert_eq!(token.decimals().unwrap(), 0xffffffff);

    let user = TestSigner::Ed25519(&test.user_key);

    assert_eq!(
        token
            .balance(user.get_identifier(&test.host))
            .unwrap()
            .to_i64(),
        0
    );
    assert_eq!(
        token
            .nonce(admin.get_identifier(&test.host))
            .unwrap()
            .to_i64(),
        0
    );

    token
        .mint(
            &admin,
            BigInt::from_u64(&test.host, 0).unwrap(),
            user.get_identifier(&test.host),
            BigInt::from_u64(&test.host, 10_000_000).unwrap(),
        )
        .unwrap();

    assert_eq!(
        token
            .balance(user.get_identifier(&test.host))
            .unwrap()
            .to_i64(),
        10_000_000
    );
    assert_eq!(
        token
            .nonce(admin.get_identifier(&test.host))
            .unwrap()
            .to_i64(),
        1
    );
}

#[test]
fn test_native_token_smart_roundtrip() {
    let test = TokenTest::setup();

    let account_id = signer_to_id_bytes(&test.host, &test.user_key);
    test.create_classic_account(
        &account_id,
        vec![(&test.user_key, 100)],
        100_000_000,
        1,
        [1, 0, 0, 0],
        None,
        None,
    );
    let token = TestToken::new_wrapped(&test.host, Asset::Native);
    let expected_token_id = BytesN::<32>::try_from_val(
        &test.host,
        test.host.get_contract_id_from_asset(Asset::Native).unwrap(),
    )
    .unwrap();

    assert_eq!(token.id.to_vec(), expected_token_id.to_vec());

    assert_eq!(token.symbol().unwrap().to_vec(), b"native".to_vec());
    assert_eq!(token.decimals().unwrap(), 7);
    assert_eq!(token.name().unwrap().to_vec(), b"native".to_vec());

    let user = TestSigner::account(&account_id, vec![&test.user_key]);

    // Wrapped token can't be initialized as regular token.
    assert!(token
        .init_token(
            user.get_identifier(&test.host),
            TokenMetadata {
                name: test.convert_bytes(b"native"),
                symbol: test.convert_bytes(b"native"),
                decimals: 7,
            },
        )
        .is_err());
    // Also can't set a new admin (and there is no admin in the first place).
    assert!(token
        .set_admin(
            &user,
            BigInt::from_u64(&test.host, 0).unwrap(),
            user.get_identifier(&test.host)
        )
        .is_err());

    assert_eq!(test.get_native_balance(&account_id), 100_000_000);
    assert_eq!(
        token
            .balance(user.get_identifier(&test.host))
            .unwrap()
            .to_i64(),
        0
    );
    assert_eq!(
        token
            .nonce(user.get_identifier(&test.host))
            .unwrap()
            .to_i64(),
        0
    );

    token
        .to_smart(&user, BigInt::from_u64(&test.host, 0).unwrap(), 10_000_000)
        .unwrap();

    assert_eq!(test.get_native_balance(&account_id), 90_000_000);
    assert_eq!(
        token
            .balance(user.get_identifier(&test.host))
            .unwrap()
            .to_i64(),
        10_000_000
    );
    assert_eq!(
        token
            .nonce(user.get_identifier(&test.host))
            .unwrap()
            .to_i64(),
        1
    );

    token
        .to_classic(&user, BigInt::from_u64(&test.host, 1).unwrap(), 5_000_000)
        .unwrap();

    assert_eq!(test.get_native_balance(&account_id), 95_000_000);
    assert_eq!(
        token
            .balance(user.get_identifier(&test.host))
            .unwrap()
            .to_i64(),
        5_000_000
    );
    assert_eq!(
        token
            .nonce(user.get_identifier(&test.host))
            .unwrap()
            .to_i64(),
        2
    );

    // Make sure negative amounts are not allowed in smart/classic conversions.
    assert!(token
        .to_smart(
            &user,
            token.nonce(user.get_identifier(&test.host)).unwrap(),
            i64::MIN,
        )
        .is_err());
    assert!(token
        .to_classic(
            &user,
            token.nonce(user.get_identifier(&test.host)).unwrap(),
            -1,
        )
        .is_err());

    // Also cover potential overflows
    assert!(token
        .to_smart(
            &user,
            token.nonce(user.get_identifier(&test.host)).unwrap(),
            i64::MAX,
        )
        .is_err());
    assert!(token
        .to_classic(
            &user,
            token.nonce(user.get_identifier(&test.host)).unwrap(),
            i64::MAX,
        )
        .is_err());
}

fn test_classic_asset_roundtrip(asset_code: &[u8]) {
    let test = TokenTest::setup();

    let account_id = signer_to_id_bytes(&test.host, &test.user_key);
    let issuer_id = signer_to_id_bytes(&test.host, &test.admin_key);

    test.create_classic_account(
        &account_id,
        vec![(&test.user_key, 100)],
        10_000_000,
        1,
        [1, 0, 0, 0],
        None,
        None,
    );

    let trustline_key = test.create_classic_trustline(
        &account_id,
        &issuer_id,
        asset_code,
        10_000_000,
        100_000_000,
        true,
        None,
    );
    let asset = if asset_code.len() == 4 {
        let mut code = [0_u8; 4];
        code.clone_from_slice(asset_code);
        Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(code),
            issuer: AccountId(PublicKey::PublicKeyTypeEd25519(
                test.host.to_u256(issuer_id.clone().into()).unwrap(),
            )),
        })
    } else {
        let mut code = [0_u8; 12];
        code.clone_from_slice(asset_code);
        Asset::CreditAlphanum12(AlphaNum12 {
            asset_code: AssetCode12(code),
            issuer: AccountId(PublicKey::PublicKeyTypeEd25519(
                test.host.to_u256(issuer_id.clone().into()).unwrap(),
            )),
        })
    };
    let token = TestToken::new_wrapped(&test.host, asset.clone());
    let expected_token_id = BytesN::<32>::try_from_val(
        &test.host,
        test.host.get_contract_id_from_asset(asset).unwrap(),
    )
    .unwrap();
    assert_eq!(token.id.to_vec(), expected_token_id.to_vec());

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

    // Wrapped token can't be initialized as regular token.
    assert!(token
        .init_token(
            user.get_identifier(&test.host),
            TokenMetadata {
                name: test.convert_bytes(b"native"),
                symbol: test.convert_bytes(b"native"),
                decimals: 7,
            },
        )
        .is_err());

    assert_eq!(
        test.get_classic_trustline_balance(&trustline_key),
        10_000_000
    );
    assert_eq!(
        token
            .balance(user.get_identifier(&test.host))
            .unwrap()
            .to_i64(),
        0
    );
    assert_eq!(
        token
            .nonce(user.get_identifier(&test.host))
            .unwrap()
            .to_i64(),
        0
    );

    token
        .to_smart(&user, BigInt::from_u64(&test.host, 0).unwrap(), 1_000_000)
        .unwrap();

    assert_eq!(
        test.get_classic_trustline_balance(&trustline_key),
        9_000_000
    );
    assert_eq!(
        token
            .balance(user.get_identifier(&test.host))
            .unwrap()
            .to_i64(),
        1_000_000
    );
    assert_eq!(
        token
            .nonce(user.get_identifier(&test.host))
            .unwrap()
            .to_i64(),
        1
    );

    token
        .to_classic(&user, BigInt::from_u64(&test.host, 1).unwrap(), 500_000)
        .unwrap();

    assert_eq!(
        test.get_classic_trustline_balance(&trustline_key),
        9_500_000
    );
    assert_eq!(
        token
            .balance(user.get_identifier(&test.host))
            .unwrap()
            .to_i64(),
        500_000
    );
    assert_eq!(
        token
            .nonce(user.get_identifier(&test.host))
            .unwrap()
            .to_i64(),
        2
    );

    // Make sure negative amounts are not allowed in smart/classic conversions.
    assert!(token
        .to_smart(
            &user,
            token.nonce(user.get_identifier(&test.host)).unwrap(),
            -1,
        )
        .is_err());
    assert!(token
        .to_classic(
            &user,
            token.nonce(user.get_identifier(&test.host)).unwrap(),
            i64::MIN,
        )
        .is_err());

    // Also cover potential overflows
    assert!(token
        .to_smart(
            &user,
            token.nonce(user.get_identifier(&test.host)).unwrap(),
            i64::MAX,
        )
        .is_err());
    assert!(token
        .to_classic(
            &user,
            token.nonce(user.get_identifier(&test.host)).unwrap(),
            i64::MAX,
        )
        .is_err());
}

#[test]
fn test_classic_asset4_smart_roundtrip() {
    test_classic_asset_roundtrip(&[0, 'a' as u8, 'b' as u8, 255]);
}

#[test]
fn test_classic_asset12_smart_roundtrip() {
    test_classic_asset_roundtrip(&[255, 0, 0, 127, b'a', b'b', b'c', 1, 2, 3, 4, 5]);
}

#[test]
fn test_direct_transfer() {
    let test = TokenTest::setup();
    let admin = TestSigner::Ed25519(&test.admin_key);
    let token = test.default_smart_token(&admin);

    let user = TestSigner::Ed25519(&test.user_key);
    let user_2 = TestSigner::Ed25519(&test.user_key_2);
    token
        .mint(
            &admin,
            token.nonce(admin.get_identifier(&test.host)).unwrap(),
            user.get_identifier(&test.host),
            BigInt::from_u64(&test.host, 100_000_000).unwrap(),
        )
        .unwrap();
    assert_eq!(
        token
            .balance(user.get_identifier(&test.host))
            .unwrap()
            .to_i64(),
        100_000_000
    );
    assert_eq!(
        token
            .balance(user_2.get_identifier(&test.host))
            .unwrap()
            .to_i64(),
        0
    );

    // Transfer some balance from user 1 to user 2.
    token
        .xfer(
            &user,
            token.nonce(user.get_identifier(&test.host)).unwrap(),
            user_2.get_identifier(&test.host),
            BigInt::from_u64(&test.host, 9_999_999).unwrap(),
        )
        .unwrap();
    assert_eq!(
        token
            .balance(user.get_identifier(&test.host))
            .unwrap()
            .to_i64(),
        90_000_001
    );
    assert_eq!(
        token
            .balance(user_2.get_identifier(&test.host))
            .unwrap()
            .to_i64(),
        9_999_999
    );

    // Can't transfer more than the balance from user 2.
    assert!(token
        .xfer(
            &user_2,
            token.nonce(user_2.get_identifier(&test.host)).unwrap(),
            user.get_identifier(&test.host),
            BigInt::from_u64(&test.host, 10_000_000).unwrap(),
        )
        .is_err());

    // Transfer some balance back from user 2 to user 1.
    token
        .xfer(
            &user_2,
            token.nonce(user_2.get_identifier(&test.host)).unwrap(),
            user.get_identifier(&test.host),
            BigInt::from_u64(&test.host, 999_999).unwrap(),
        )
        .unwrap();
    assert_eq!(
        token
            .balance(user.get_identifier(&test.host))
            .unwrap()
            .to_i64(),
        91_000_000
    );
    assert_eq!(
        token
            .balance(user_2.get_identifier(&test.host))
            .unwrap()
            .to_i64(),
        9_000_000
    );
}

#[test]
fn test_transfer_with_allowance() {
    let test = TokenTest::setup();
    let admin = TestSigner::Ed25519(&test.admin_key);
    let token = test.default_smart_token(&admin);

    let user = TestSigner::Ed25519(&test.user_key);
    let user_2 = TestSigner::Ed25519(&test.user_key_2);
    let user_3 = TestSigner::Ed25519(&test.user_key_3);
    token
        .mint(
            &admin,
            token.nonce(admin.get_identifier(&test.host)).unwrap(),
            user.get_identifier(&test.host),
            BigInt::from_u64(&test.host, 100_000_000).unwrap(),
        )
        .unwrap();
    assert_eq!(
        token
            .balance(user.get_identifier(&test.host))
            .unwrap()
            .to_i64(),
        100_000_000
    );
    assert_eq!(
        token
            .balance(user_2.get_identifier(&test.host))
            .unwrap()
            .to_i64(),
        0
    );
    assert_eq!(
        token
            .allowance(
                user.get_identifier(&test.host),
                user_3.get_identifier(&test.host)
            )
            .unwrap()
            .to_i64(),
        0
    );

    // Allow 10_000_000 units of token to be transferred from user by user 3.
    token
        .approve(
            &user,
            token.nonce(user.get_identifier(&test.host)).unwrap(),
            user_3.get_identifier(&test.host),
            BigInt::from_u64(&test.host, 10_000_000).unwrap(),
        )
        .unwrap();

    assert_eq!(
        token
            .allowance(
                user.get_identifier(&test.host),
                user_3.get_identifier(&test.host)
            )
            .unwrap()
            .to_i64(),
        10_000_000
    );

    // Transfer 5_000_000 of allowance to user 2.
    token
        .xfer_from(
            &user_3,
            token.nonce(user_3.get_identifier(&test.host)).unwrap(),
            user.get_identifier(&test.host),
            user_2.get_identifier(&test.host),
            BigInt::from_u64(&test.host, 6_000_000).unwrap(),
        )
        .unwrap();
    assert_eq!(
        token
            .balance(user.get_identifier(&test.host))
            .unwrap()
            .to_i64(),
        94_000_000
    );
    assert_eq!(
        token
            .balance(user_2.get_identifier(&test.host))
            .unwrap()
            .to_i64(),
        6_000_000
    );
    assert_eq!(
        token
            .balance(user_3.get_identifier(&test.host))
            .unwrap()
            .to_i64(),
        0
    );
    assert_eq!(
        token
            .allowance(
                user.get_identifier(&test.host),
                user_3.get_identifier(&test.host)
            )
            .unwrap()
            .to_i64(),
        4_000_000
    );

    // Can't transfer more than remaining allowance.
    assert!(token
        .xfer_from(
            &user_3,
            token.nonce(user_3.get_identifier(&test.host)).unwrap(),
            user.get_identifier(&test.host),
            user_3.get_identifier(&test.host),
            BigInt::from_u64(&test.host, 4_000_001).unwrap(),
        )
        .is_err());

    // Transfer the remaining allowance to user 3.
    token
        .xfer_from(
            &user_3,
            token.nonce(user_3.get_identifier(&test.host)).unwrap(),
            user.get_identifier(&test.host),
            user_3.get_identifier(&test.host),
            BigInt::from_u64(&test.host, 4_000_000).unwrap(),
        )
        .unwrap();

    assert_eq!(
        token
            .balance(user.get_identifier(&test.host))
            .unwrap()
            .to_i64(),
        90_000_000
    );
    assert_eq!(
        token
            .balance(user_2.get_identifier(&test.host))
            .unwrap()
            .to_i64(),
        6_000_000
    );
    assert_eq!(
        token
            .balance(user_3.get_identifier(&test.host))
            .unwrap()
            .to_i64(),
        4_000_000
    );
    assert_eq!(
        token
            .allowance(
                user.get_identifier(&test.host),
                user_3.get_identifier(&test.host)
            )
            .unwrap()
            .to_i64(),
        0
    );

    // Can't transfer anything at all now.
    assert!(token
        .xfer_from(
            &user_3,
            token.nonce(user_3.get_identifier(&test.host)).unwrap(),
            user.get_identifier(&test.host),
            user_3.get_identifier(&test.host),
            BigInt::from_u64(&test.host, 1).unwrap(),
        )
        .is_err());
}

#[test]
fn test_freeze_and_unfreeze() {
    let test = TokenTest::setup();
    let admin = TestSigner::Ed25519(&test.admin_key);
    let token = test.default_smart_token(&admin);

    let user = TestSigner::Ed25519(&test.user_key);
    let user_2 = TestSigner::Ed25519(&test.user_key_2);
    token
        .mint(
            &admin,
            token.nonce(admin.get_identifier(&test.host)).unwrap(),
            user.get_identifier(&test.host),
            BigInt::from_u64(&test.host, 100_000_000).unwrap(),
        )
        .unwrap();
    token
        .mint(
            &admin,
            token.nonce(admin.get_identifier(&test.host)).unwrap(),
            user_2.get_identifier(&test.host),
            BigInt::from_u64(&test.host, 200_000_000).unwrap(),
        )
        .unwrap();

    assert!(!token.is_frozen(user.get_identifier(&test.host)).unwrap());

    // Freeze the balance of `user`.
    token
        .freeze(
            &admin,
            token.nonce(admin.get_identifier(&test.host)).unwrap(),
            user.get_identifier(&test.host),
        )
        .unwrap();

    assert!(token.is_frozen(user.get_identifier(&test.host)).unwrap());
    // Make sure neither outgoing nor incoming balance transfers are possible.
    // TODO: find a better way to check for exact error in HostError
    assert!(token
        .xfer(
            &user,
            token.nonce(user.get_identifier(&test.host)).unwrap(),
            user_2.get_identifier(&test.host),
            BigInt::from_u64(&test.host, 1).unwrap()
        )
        .is_err());
    assert!(token
        .xfer(
            &user_2,
            token.nonce(user.get_identifier(&test.host)).unwrap(),
            user.get_identifier(&test.host),
            BigInt::from_u64(&test.host, 1).unwrap()
        )
        .is_err());

    // Unfreeze the balance of `user`.
    token
        .unfreeze(
            &admin,
            token.nonce(admin.get_identifier(&test.host)).unwrap(),
            user.get_identifier(&test.host),
        )
        .unwrap();

    assert!(!token.is_frozen(user.get_identifier(&test.host)).unwrap());
    // Make sure balance transfers are possible now.
    token
        .xfer(
            &user,
            token.nonce(user.get_identifier(&test.host)).unwrap(),
            user_2.get_identifier(&test.host),
            BigInt::from_u64(&test.host, 1).unwrap(),
        )
        .unwrap();
    token
        .xfer(
            &user_2,
            token.nonce(user_2.get_identifier(&test.host)).unwrap(),
            user.get_identifier(&test.host),
            BigInt::from_u64(&test.host, 1).unwrap(),
        )
        .unwrap();
}

#[test]
fn test_burn() {
    let test = TokenTest::setup();
    let admin = TestSigner::Ed25519(&test.admin_key);
    let token = test.default_smart_token(&admin);

    let user = TestSigner::Ed25519(&test.user_key);
    token
        .mint(
            &admin,
            token.nonce(admin.get_identifier(&test.host)).unwrap(),
            user.get_identifier(&test.host),
            BigInt::from_u64(&test.host, 100_000_000).unwrap(),
        )
        .unwrap();

    assert_eq!(
        token
            .balance(user.get_identifier(&test.host))
            .unwrap()
            .to_i64(),
        100_000_000
    );

    token
        .burn(
            &admin,
            token.nonce(admin.get_identifier(&test.host)).unwrap(),
            user.get_identifier(&test.host),
            BigInt::from_u64(&test.host, 40_000_000).unwrap(),
        )
        .unwrap();

    assert_eq!(
        token
            .balance(user.get_identifier(&test.host))
            .unwrap()
            .to_i64(),
        60_000_000
    );

    // Can't burn more than the balance
    assert!(token
        .burn(
            &admin,
            token.nonce(admin.get_identifier(&test.host)).unwrap(),
            user.get_identifier(&test.host),
            BigInt::from_u64(&test.host, 60_000_001).unwrap(),
        )
        .is_err());

    // Burn everything else
    token
        .burn(
            &admin,
            token.nonce(admin.get_identifier(&test.host)).unwrap(),
            user.get_identifier(&test.host),
            BigInt::from_u64(&test.host, 60_000_000).unwrap(),
        )
        .unwrap();
    assert_eq!(
        token
            .balance(user.get_identifier(&test.host))
            .unwrap()
            .to_i64(),
        0
    );
}

#[test]
fn test_set_admin() {
    let test = TokenTest::setup();
    let admin = TestSigner::Ed25519(&test.admin_key);
    let token = test.default_smart_token(&admin);
    let new_admin = TestSigner::Ed25519(&test.user_key);

    // Give admin rights to the new admin.
    token
        .set_admin(
            &admin,
            token.nonce(admin.get_identifier(&test.host)).unwrap(),
            new_admin.get_identifier(&test.host),
        )
        .unwrap();

    // Make sure admin functions are unavailable to the old admin.
    assert!(token
        .set_admin(
            &admin,
            token.nonce(admin.get_identifier(&test.host)).unwrap(),
            new_admin.get_identifier(&test.host),
        )
        .is_err());
    assert!(token
        .mint(
            &admin,
            token.nonce(admin.get_identifier(&test.host)).unwrap(),
            new_admin.get_identifier(&test.host),
            BigInt::from_u64(&test.host, 1).unwrap()
        )
        .is_err());
    assert!(token
        .burn(
            &admin,
            token.nonce(admin.get_identifier(&test.host)).unwrap(),
            new_admin.get_identifier(&test.host),
            BigInt::from_u64(&test.host, 1).unwrap()
        )
        .is_err());
    assert!(token
        .freeze(
            &admin,
            token.nonce(admin.get_identifier(&test.host)).unwrap(),
            new_admin.get_identifier(&test.host),
        )
        .is_err());
    assert!(token
        .unfreeze(
            &admin,
            token.nonce(admin.get_identifier(&test.host)).unwrap(),
            new_admin.get_identifier(&test.host),
        )
        .is_err());

    // The admin functions are now available to the new admin.
    token
        .mint(
            &new_admin,
            token.nonce(new_admin.get_identifier(&test.host)).unwrap(),
            admin.get_identifier(&test.host),
            BigInt::from_u64(&test.host, 1).unwrap(),
        )
        .unwrap();
    token
        .burn(
            &new_admin,
            token.nonce(new_admin.get_identifier(&test.host)).unwrap(),
            admin.get_identifier(&test.host),
            BigInt::from_u64(&test.host, 1).unwrap(),
        )
        .unwrap();
    token
        .freeze(
            &new_admin,
            token.nonce(new_admin.get_identifier(&test.host)).unwrap(),
            admin.get_identifier(&test.host),
        )
        .unwrap();
    token
        .unfreeze(
            &new_admin,
            token.nonce(new_admin.get_identifier(&test.host)).unwrap(),
            admin.get_identifier(&test.host),
        )
        .unwrap();

    // Return the admin rights to the old admin
    token
        .set_admin(
            &new_admin,
            token.nonce(new_admin.get_identifier(&test.host)).unwrap(),
            admin.get_identifier(&test.host),
        )
        .unwrap();
    // Make sure old admin can now perform admin operations
    token
        .mint(
            &admin,
            token.nonce(admin.get_identifier(&test.host)).unwrap(),
            new_admin.get_identifier(&test.host),
            BigInt::from_u64(&test.host, 1).unwrap(),
        )
        .unwrap();
}

#[test]
fn test_contract_signatures_do_not_work_outside_of_contract_call() {
    // TODO: we still need a positive test for contract auth.
    let test = TokenTest::setup();
    let contract_signer = TestSigner::Contract(generate_bytes(&test.host));
    let user = TestSigner::Ed25519(&test.user_key);
    let token = test.default_smart_token(&contract_signer);

    assert!(token
        .mint(
            &contract_signer,
            BigInt::from_u64(&test.host, 0).unwrap(),
            user.get_identifier(&test.host),
            BigInt::from_u64(&test.host, 1000).unwrap(),
        )
        .is_err());
}

#[test]
fn test_auth_rejected_with_incorrect_nonce() {
    let test = TokenTest::setup();
    let admin = TestSigner::Ed25519(&test.admin_key);
    let token = test.default_smart_token(&admin);
    let user = TestSigner::Ed25519(&test.user_key);
    let user_2 = TestSigner::Ed25519(&test.user_key_2);

    token
        .mint(
            &admin,
            token.nonce(admin.get_identifier(&test.host)).unwrap(),
            user.get_identifier(&test.host),
            BigInt::from_u64(&test.host, 100_000_000).unwrap(),
        )
        .unwrap();

    // Bump user's nonce and approve some amount to cover xfer_from below.
    token
        .approve(
            &user,
            BigInt::from_u64(&test.host, 0).unwrap(),
            user_2.get_identifier(&test.host),
            BigInt::from_u64(&test.host, 1000).unwrap(),
        )
        .unwrap();

    assert!(token
        .xfer(
            &user,
            BigInt::from_u64(&test.host, 2).unwrap(),
            user_2.get_identifier(&test.host),
            BigInt::from_u64(&test.host, 1000).unwrap()
        )
        .is_err());

    assert!(token
        .approve(
            &user,
            BigInt::from_u64(&test.host, 2).unwrap(),
            user_2.get_identifier(&test.host),
            BigInt::from_u64(&test.host, 1000).unwrap()
        )
        .is_err());
    assert!(token
        .xfer_from(
            &user_2,
            BigInt::from_u64(&test.host, 1).unwrap(),
            user.get_identifier(&test.host),
            user_2.get_identifier(&test.host),
            BigInt::from_u64(&test.host, 100).unwrap()
        )
        .is_err());
    assert!(token
        .mint(
            &admin,
            BigInt::from_u64(&test.host, 2).unwrap(),
            user.get_identifier(&test.host),
            BigInt::from_u64(&test.host, 10_000_000).unwrap(),
        )
        .is_err());
    assert!(token
        .burn(
            &admin,
            BigInt::from_u64(&test.host, 2).unwrap(),
            user.get_identifier(&test.host),
            BigInt::from_u64(&test.host, 10_000_000).unwrap(),
        )
        .is_err());
    assert!(token
        .set_admin(
            &admin,
            BigInt::from_u64(&test.host, 2).unwrap(),
            user.get_identifier(&test.host)
        )
        .is_err());
}

#[test]
fn test_auth_rejected_with_incorrect_signer() {
    let test = TokenTest::setup();
    let admin = TestSigner::Ed25519(&test.admin_key);
    let token = test.default_smart_token(&admin);
    let user = TestSigner::Ed25519(&test.user_key);

    let nonce = BigInt::from_u64(&test.host, 0).unwrap();
    let amount = BigInt::from_u64(&test.host, 1000).unwrap();
    let user_signature = sign_args(
        &test.host,
        &user,
        "mint",
        &token.id,
        host_vec![
            &test.host,
            admin.get_identifier(&test.host),
            nonce.clone(),
            user.get_identifier(&test.host),
            amount.clone(),
        ],
    );
    // Replace public key in the user signature to imitate admin signature.
    let signature = Signature::Ed25519(Ed25519Signature {
        public_key: match admin.get_identifier(&test.host) {
            Identifier::Ed25519(id) => id,
            _ => unreachable!(),
        },
        signature: match user_signature {
            Signature::Ed25519(signature) => signature.signature,
            _ => unreachable!(),
        },
    });

    let res: Status = test
        .host
        .try_call(
            token.id.clone().into(),
            Symbol::from_str("mint").into(),
            host_vec![
                &test.host,
                signature,
                nonce,
                user.get_identifier(&test.host),
                amount
            ]
            .into(),
        )
        .unwrap()
        .try_into_val(&test.host)
        .unwrap();
    assert_ne!(res, Status::OK);
}

#[test]
fn test_auth_rejected_for_incorrect_function_name() {
    let test = TokenTest::setup();
    let admin = TestSigner::Ed25519(&test.admin_key);
    let token = test.default_smart_token(&admin);
    let user = TestSigner::Ed25519(&test.user_key);

    let nonce = BigInt::from_u64(&test.host, 0).unwrap();
    let amount = BigInt::from_u64(&test.host, 1000).unwrap();
    let signature = sign_args(
        &test.host,
        &admin,
        "burn",
        &token.id,
        host_vec![
            &test.host,
            admin.get_identifier(&test.host),
            nonce.clone(),
            user.get_identifier(&test.host),
            amount.clone(),
        ],
    );

    let res: Status = test
        .host
        .try_call(
            token.id.clone().into(),
            Symbol::from_str("mint").into(),
            host_vec![
                &test.host,
                signature,
                nonce,
                user.get_identifier(&test.host),
                amount
            ]
            .into(),
        )
        .unwrap()
        .try_into_val(&test.host)
        .unwrap();
    assert_ne!(res, Status::OK);
}

#[test]
fn test_auth_rejected_for_incorrect_function_args() {
    let test = TokenTest::setup();
    let admin = TestSigner::Ed25519(&test.admin_key);
    let token = test.default_smart_token(&admin);
    let user = TestSigner::Ed25519(&test.user_key);

    let nonce = BigInt::from_u64(&test.host, 0).unwrap();
    let signature = sign_args(
        &test.host,
        &admin,
        "mint",
        &token.id,
        host_vec![
            &test.host,
            admin.get_identifier(&test.host),
            nonce.clone(),
            user.get_identifier(&test.host),
            BigInt::from_u64(&test.host, 1000).unwrap(),
        ],
    );

    let res: Status = test
        .host
        .try_call(
            token.id.clone().into(),
            Symbol::from_str("mint").into(),
            host_vec![
                &test.host,
                signature,
                nonce,
                user.get_identifier(&test.host),
                // call with 1000000 amount instead of 1000 that was signed.
                BigInt::from_u64(&test.host, 1_000_000).unwrap(),
            ]
            .into(),
        )
        .unwrap()
        .try_into_val(&test.host)
        .unwrap();
    assert_ne!(res, Status::OK);
}

#[test]
fn test_classic_account_multisig_auth() {
    let test = TokenTest::setup();

    let account_id = signer_to_id_bytes(&test.host, &test.user_key);
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
    );
    let account_ident = Identifier::Account(account_id.clone());
    let token = TestToken::new_wrapped(&test.host, Asset::Native);

    // Success: account weight (60) + 40 = 100
    token
        .to_smart(
            &TestSigner::account(&account_id, vec![&test.user_key, &test.user_key_3]),
            token.nonce(account_ident.clone()).unwrap(),
            100,
        )
        .unwrap();

    // Success: 1 high weight signer (u32::MAX)
    token
        .to_smart(
            &TestSigner::account(&account_id, vec![&test.user_key_2]),
            token.nonce(account_ident.clone()).unwrap(),
            100,
        )
        .unwrap();

    // Success: 60 + 59 > 100, no account signature
    token
        .to_smart(
            &TestSigner::account(&account_id, vec![&test.user_key_3, &test.user_key_4]),
            token.nonce(account_ident.clone()).unwrap(),
            100,
        )
        .unwrap();

    // Success: 40 + 60 + 59 > 100
    token
        .to_smart(
            &TestSigner::account(
                &account_id,
                vec![&test.user_key, &test.user_key_3, &test.user_key_4],
            ),
            token.nonce(account_ident.clone()).unwrap(),
            100,
        )
        .unwrap();

    // Success: all signers
    token
        .to_smart(
            &TestSigner::account(
                &account_id,
                vec![
                    &test.user_key,
                    &test.user_key_2,
                    &test.user_key_3,
                    &test.user_key_4,
                ],
            ),
            token.nonce(account_ident.clone()).unwrap(),
            100,
        )
        .unwrap();

    // Failure: only account weight (40)
    assert!(token
        .to_smart(
            &TestSigner::account(&account_id, vec![&test.user_key]),
            token.nonce(account_ident.clone()).unwrap(),
            100,
        )
        .is_err());

    // Failure: 40 + 59 < 100
    assert!(token
        .to_smart(
            &TestSigner::account(&account_id, vec![&test.user_key, &test.user_key_4]),
            token.nonce(account_ident.clone()).unwrap(),
            100,
        )
        .is_err());

    // Failure: 60 < 100, duplicate signatures
    assert!(token
        .to_smart(
            &TestSigner::account(&account_id, vec![&test.user_key_3, &test.user_key_3]),
            token.nonce(account_ident.clone()).unwrap(),
            100,
        )
        .is_err());

    // Failure: 60 + 59 > 100, duplicate signatures
    assert!(token
        .to_smart(
            &TestSigner::account(
                &account_id,
                vec![&test.user_key_3, &test.user_key_4, &test.user_key_3],
            ),
            token.nonce(account_ident.clone()).unwrap(),
            100,
        )
        .is_err());

    // Failure: too many signatures (even though weight would be enough after
    // deduplication).
    let mut too_many_sigs = vec![];
    for _ in 0..21 {
        too_many_sigs.push(&test.user_key_2);
    }
    assert!(token
        .to_smart(
            &TestSigner::account(&account_id, too_many_sigs,),
            token.nonce(account_ident.clone()).unwrap(),
            100,
        )
        .is_err());

    // Failure: out of order signers
    let mut out_of_order_signers = vec![
        &test.user_key,
        &test.user_key_2,
        &test.user_key_3,
        &test.user_key_4,
    ];
    out_of_order_signers.sort_by_key(|k| k.public.as_bytes());
    out_of_order_signers.swap(1, 2);
    assert!(token
        .to_smart(
            &TestSigner::Account(AccountSigner {
                account_id: account_id.clone(),
                signers: out_of_order_signers,
            }),
            token.nonce(account_ident.clone()).unwrap(),
            100,
        )
        .is_err());
}

#[test]
fn test_negative_amounts_are_not_allowed() {
    let test = TokenTest::setup();
    let admin = TestSigner::Ed25519(&test.admin_key);
    let token = test.default_smart_token(&admin);

    let user = TestSigner::Ed25519(&test.user_key);
    let user_2 = TestSigner::Ed25519(&test.user_key_2);
    token
        .mint(
            &admin,
            token.nonce(admin.get_identifier(&test.host)).unwrap(),
            user.get_identifier(&test.host),
            BigInt::from_u64(&test.host, 100_000_000).unwrap(),
        )
        .unwrap();

    assert!(token
        .mint(
            &admin,
            token.nonce(admin.get_identifier(&test.host)).unwrap(),
            user.get_identifier(&test.host),
            BigInt::from_i64(&test.host, -1).unwrap(),
        )
        .is_err());

    assert!(token
        .burn(
            &admin,
            token.nonce(admin.get_identifier(&test.host)).unwrap(),
            user.get_identifier(&test.host),
            BigInt::from_i64(&test.host, -1).unwrap(),
        )
        .is_err());

    assert!(token
        .xfer(
            &user,
            token.nonce(user.get_identifier(&test.host)).unwrap(),
            user_2.get_identifier(&test.host),
            BigInt::from_i64(&test.host, -1).unwrap(),
        )
        .is_err());

    assert!(token
        .approve(
            &user,
            token.nonce(user.get_identifier(&test.host)).unwrap(),
            user_2.get_identifier(&test.host),
            BigInt::from_i64(&test.host, -1).unwrap(),
        )
        .is_err());

    // Approve some balance before doing the negative xfer_from.
    token
        .approve(
            &user,
            token.nonce(user.get_identifier(&test.host)).unwrap(),
            user_2.get_identifier(&test.host),
            BigInt::from_i64(&test.host, 10_000).unwrap(),
        )
        .unwrap();

    assert!(token
        .xfer_from(
            &user_2,
            token.nonce(user_2.get_identifier(&test.host)).unwrap(),
            user.get_identifier(&test.host),
            user_2.get_identifier(&test.host),
            BigInt::from_i64(&test.host, -1).unwrap(),
        )
        .is_err());
}

fn test_native_token_classic_balance_boundaries(
    test: &TokenTest,
    user: &TestSigner,
    account_id: &BytesN<32>,
    init_balance: i64,
    expected_min_balance: i64,
    expected_max_balance: i64,
) {
    let token = TestToken::new_wrapped(&test.host, Asset::Native);
    // Try to do smart conversion that would leave balance lower than min.
    assert!(token
        .to_smart(
            &user,
            token.nonce(user.get_identifier(&test.host)).unwrap(),
            init_balance - expected_min_balance + 1,
        )
        .is_err());

    // Now convert everything but min balance to smart.
    token
        .to_smart(
            &user,
            token.nonce(user.get_identifier(&test.host)).unwrap(),
            init_balance - expected_min_balance,
        )
        .unwrap();
    assert_eq!(test.get_native_balance(account_id), expected_min_balance);

    // Converting to smart is no longer possible.
    assert!(token
        .to_smart(
            &user,
            token.nonce(user.get_identifier(&test.host)).unwrap(),
            1,
        )
        .is_err());

    // Create an account with smart balance close to i64::MAX and transfer it
    // to the account being tested. That's not a realistic scenario
    // given limited XLM supply, but that's the only way to
    // cover max_balance.
    let large_balance_key = generate_keypair();
    let large_balance_acc = signer_to_id_bytes(&test.host, &large_balance_key);
    let large_balance_signer = TestSigner::account(&large_balance_acc, vec![&large_balance_key]);
    test.create_classic_account(
        &large_balance_acc,
        vec![(&large_balance_key, 100)],
        i64::MAX,
        0,
        [1, 0, 0, 0],
        None,
        None,
    );
    token
        .to_smart(
            &large_balance_signer,
            token
                .nonce(large_balance_signer.get_identifier(&test.host))
                .unwrap(),
            i64::MAX - 10_000_000,
        )
        .unwrap();
    token
        .xfer(
            &large_balance_signer,
            token
                .nonce(large_balance_signer.get_identifier(&test.host))
                .unwrap(),
            user.get_identifier(&test.host),
            BigInt::from_u64(&test.host, i64::MAX as u64 - 10_000_000).unwrap(),
        )
        .unwrap();

    // User balance should be now i64::MAX - 10_000_000 +
    // init_balance - expected_min_balance, which we expect to exceed
    // i64::MAX and hence exceed expected_max_balance.
    // Transferring the balance to classic that would exceed
    // expected_max_balance shouldn't be possible.
    assert!(token
        .to_classic(
            &user,
            token.nonce(user.get_identifier(&test.host)).unwrap(),
            expected_max_balance - expected_min_balance + 1
        )
        .is_err());
    // ...but transferring exactly up to expected_max_balance should be
    // possible.
    token
        .to_classic(
            &user,
            token.nonce(user.get_identifier(&test.host)).unwrap(),
            expected_max_balance - expected_min_balance,
        )
        .unwrap();

    assert_eq!(test.get_native_balance(account_id), expected_max_balance);
}

#[test]
fn test_native_token_classic_balance_boundaries_simple() {
    let test = TokenTest::setup();

    let account_id = signer_to_id_bytes(&test.host, &test.user_key);
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
    let account_id = signer_to_id_bytes(&test.host, &test.user_key);
    let user = TestSigner::account(&account_id, vec![&test.user_key]);
    test.create_classic_account(
        &account_id,
        vec![(&test.user_key, 100)],
        1_000_000_000,
        8,
        [1, 0, 0, 0],
        Some((300_000_000, 500_000_000)),
        None,
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
    let account_id = signer_to_id_bytes(&test.host, &test.user_key);
    let user = TestSigner::account(&account_id, vec![&test.user_key]);
    test.create_classic_account(
        &account_id,
        vec![(&test.user_key, 100)],
        100_000_000,
        5,
        [1, 0, 0, 0],
        None,
        Some((3, 6)),
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
    let account_id = signer_to_id_bytes(&test.host, &test.user_key);
    let user = TestSigner::account(&account_id, vec![&test.user_key]);
    test.create_classic_account(
        &account_id,
        vec![(&test.user_key, 100)],
        1_000_000_000,
        5,
        [1, 0, 0, 0],
        Some((300_000_000, 500_000_000)),
        Some((3, 6)),
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
    let account_id = signer_to_id_bytes(&test.host, &test.user_key);
    let user = TestSigner::account(&account_id, vec![&test.user_key]);
    test.create_classic_account(
        &account_id,
        vec![(&test.user_key, 100)],
        i64::MAX,
        u32::MAX,
        [1, 0, 0, 0],
        Some((i64::MAX / 4, i64::MAX / 5)),
        Some((0, u32::MAX)),
    );
    test_native_token_classic_balance_boundaries(
        &test,
        &user,
        &account_id,
        i64::MAX,
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
    let account_id = signer_to_id_bytes(&test.host, &test.user_key);
    let user = TestSigner::account(&account_id, vec![&test.user_key]);
    test.create_classic_account(
        &account_id,
        vec![(&test.user_key, 100)],
        10_000_000,
        0,
        [1, 0, 0, 0],
        None,
        None,
    );

    let issuer_id = signer_to_id_bytes(&test.host, &test.admin_key);
    let issuer = TestSigner::account(&issuer_id, vec![&test.admin_key]);
    test.create_classic_account(
        &issuer_id,
        vec![(&test.admin_key, 100)],
        10_000_000,
        0,
        [1, 0, 0, 0],
        None,
        None,
    );

    let trustline_key = test.create_classic_trustline(
        &account_id,
        &issuer_id,
        &[255; 12],
        init_balance,
        limit,
        true,
        liabilities,
    );
    let token = TestToken::new_wrapped(
        &test.host,
        Asset::CreditAlphanum12(AlphaNum12 {
            asset_code: AssetCode12([255; 12]),
            issuer: AccountId(PublicKey::PublicKeyTypeEd25519(
                test.host.to_u256(issuer_id.clone().into()).unwrap(),
            )),
        }),
    );
    // Try to do smart conversion that would leave balance lower than min.
    assert!(token
        .to_smart(
            &user,
            token.nonce(user.get_identifier(&test.host)).unwrap(),
            init_balance - expected_min_balance + 1,
        )
        .is_err());

    // Now convert everything but min balance to smart.
    token
        .to_smart(
            &user,
            token.nonce(user.get_identifier(&test.host)).unwrap(),
            init_balance - expected_min_balance,
        )
        .unwrap();
    assert_eq!(
        test.get_classic_trustline_balance(&trustline_key),
        expected_min_balance
    );

    // Converting to smart is no longer possible.
    assert!(token
        .to_smart(
            &user,
            token.nonce(user.get_identifier(&test.host)).unwrap(),
            1,
        )
        .is_err());

    // Mint a large amount of token in smart.
    token
        .mint(
            &issuer,
            token.nonce(issuer.get_identifier(&test.host)).unwrap(),
            user.get_identifier(&test.host),
            BigInt::from_u64(&test.host, u64::MAX).unwrap(),
        )
        .unwrap();

    // Transferring the balance to classic that would exceed
    // expected_max_balance shouldn't be possible.
    if expected_max_balance - expected_min_balance < i64::MAX {
        assert!(token
            .to_classic(
                &user,
                token.nonce(user.get_identifier(&test.host)).unwrap(),
                expected_max_balance - expected_min_balance + 1
            )
            .is_err());
    }

    // ...but transferring exactly up to expected_max_balance should be
    // possible.
    token
        .to_classic(
            &user,
            token.nonce(user.get_identifier(&test.host)).unwrap(),
            expected_max_balance - expected_min_balance,
        )
        .unwrap();

    assert_eq!(
        test.get_classic_trustline_balance(&trustline_key),
        expected_max_balance
    );
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
fn test_asset_token_classic_balance_boundaries_with_limit_lower_than_liabilities() {
    test_wrapped_asset_classic_balance_boundaries(
        100_000_000,
        300_000,
        200_000_000,
        Some((500_000, 300_000)),
        200_000_000,
    );
}

#[test]
fn test_asset_token_classic_balance_boundaries_with_limit_higher_than_liabilities() {
    test_wrapped_asset_classic_balance_boundaries(
        100_000_000,
        300_000,
        i64::MAX - 500_000,
        Some((500_000, 300_000)),
        i64::MAX - 200_000,
    );
}

#[test]
fn test_asset_token_classic_balance_boundaries_large_values() {
    test_wrapped_asset_classic_balance_boundaries(
        i64::MAX,
        i64::MAX / 4,
        i64::MAX - i64::MAX / 5,
        Some((i64::MAX / 5, i64::MAX / 4)),
        i64::MAX,
    );
}

#[test]
fn test_smart_tokens_dont_support_classic_ops() {
    let test = TokenTest::setup();
    let admin = TestSigner::Ed25519(&test.admin_key);
    let token = test.default_smart_token(&admin);
    let account_id = signer_to_id_bytes(&test.host, &test.user_key);
    let user = TestSigner::account(&account_id, vec![&test.user_key]);
    test.create_classic_account(
        &account_id,
        vec![(&test.user_key, 100)],
        10_000_000,
        0,
        [1, 0, 0, 0],
        None,
        None,
    );

    token
        .mint(
            &admin,
            token.nonce(admin.get_identifier(&test.host)).unwrap(),
            user.get_identifier(&test.host),
            BigInt::from_u64(&test.host, 100_000).unwrap(),
        )
        .unwrap();

    assert!(token
        .to_classic(
            &user,
            token.nonce(user.get_identifier(&test.host)).unwrap(),
            1
        )
        .is_err());
    assert!(token
        .to_smart(
            &user,
            token.nonce(user.get_identifier(&test.host)).unwrap(),
            1
        )
        .is_err());
}
