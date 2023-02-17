use std::collections::HashMap;

use ed25519_dalek::Keypair;
use soroban_env_common::xdr::{
    AccountId, AddressWithNonce, AuthorizedInvocation, ContractAuth, HashIdPreimage,
    HashIdPreimageContractAuth, PublicKey, ScAddress, ScVec, Uint256,
};
use soroban_native_sdk_macros::contracttype;
use soroban_test_wasms::AUTH_TEST_CONTRACT;

use crate::auth::RecordedAuthPayload;
use crate::native_contract::base_types::{BytesN, Map};
use crate::native_contract::testutils::{
    create_account, generate_keypair, sign_payload_for_account,
};
use crate::xdr::Hash;
use crate::{host_vec, Host, LedgerInfo};
use soroban_env_common::{Env, Symbol, TryIntoVal};

use crate::native_contract::base_types::Vec as HostVec;

#[derive(Clone)]
#[contracttype]
pub struct ContractTreeNode {
    pub id: BytesN<32>,
    pub need_auth: HostVec,
    pub children: HostVec,
}

struct AuthTreeTest {
    host: Host,
    keys: Vec<Keypair>,
    contracts: Vec<BytesN<32>>,
    last_nonces: HashMap<(Vec<u8>, Vec<u8>), u64>,
}

struct SetupNode {
    contract_id: BytesN<32>,
    need_auth: Vec<bool>,
    children: Vec<SetupNode>,
}

struct SignNode {
    contract_id: BytesN<32>,
    children: Vec<SignNode>,
}

impl SetupNode {
    fn new(contract_id: &BytesN<32>, need_auth: Vec<bool>, children: Vec<SetupNode>) -> Self {
        Self {
            contract_id: contract_id.clone(),
            need_auth,
            children,
        }
    }
}

impl SignNode {
    fn new(contract_id: &BytesN<32>, children: Vec<SignNode>) -> Self {
        Self {
            contract_id: contract_id.clone(),
            children,
        }
    }
}

// This test uses `AuthContract::tree_fn` to build various authorization trees.
impl AuthTreeTest {
    fn setup(signer_cnt: usize, contract_cnt: usize) -> Self {
        let host = Host::test_host_with_recording_footprint();
        let mut accounts = vec![];
        for _ in 0..signer_cnt {
            accounts.push(generate_keypair());
        }
        for account in &accounts {
            create_account(
                &host,
                &AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
                    account.public.to_bytes(),
                ))),
                vec![(&account, 1)],
                100_000_000,
                1,
                [1, 0, 0, 0],
                None,
                None,
                0,
            )
        }
        let mut contracts = vec![];
        for _ in 0..contract_cnt {
            let contract_id_obj = host
                .register_test_contract_wasm(AUTH_TEST_CONTRACT)
                .unwrap();
            contracts.push(contract_id_obj.try_into_val(&host).unwrap());
        }
        Self {
            host,
            keys: accounts,
            contracts,
            last_nonces: Default::default(),
        }
    }

    // Runs the test for the given setup in enforcing mode. `sign_payloads` 
    // contain should contain a vec of `SignNode` inputs for every signer in the
    // setup. The nodes then are mapped to the respective `ContractAuth` entries.
    fn test_enforcing(
        &mut self,
        root: &SetupNode,
        sign_payloads: Vec<Vec<SignNode>>,
        success: bool,
    ) {
        let addresses = self.get_addresses();
        let tree = self.convert_setup_tree(&root);
        let mut contract_auth = vec![];

        self.last_nonces.clear();

        for address_id in 0..self.keys.len() {
            let sc_address = self.key_to_sc_address(&self.keys[address_id]);
            let mut next_nonce = HashMap::<Vec<u8>, u64>::new();
            for sign_root in &sign_payloads[address_id] {
                let contract_id_vec = sign_root.contract_id.to_vec();
                let nonce = if let Some(nonce) = next_nonce.get(&contract_id_vec) {
                    *nonce
                } else {
                    let nonce = self
                        .host
                        .read_nonce(
                            &Hash(contract_id_vec.clone().try_into().unwrap()),
                            &sc_address,
                        )
                        .unwrap();
                    self.last_nonces.insert(
                        (
                            contract_id_vec.clone(),
                            self.keys[address_id].public.as_bytes().to_vec(),
                        ),
                        nonce,
                    );
                    nonce
                };
                next_nonce.insert(contract_id_vec, nonce + 1);
                let root_invocation = self.convert_sign_node(sign_root);
                let payload_preimage = HashIdPreimage::ContractAuth(HashIdPreimageContractAuth {
                    network_id: self
                        .host
                        .with_ledger_info(|li: &LedgerInfo| Ok(li.network_id.clone()))
                        .unwrap()
                        .try_into()
                        .unwrap(),
                    invocation: root_invocation.clone(),
                    nonce,
                });
                let payload = self.host.metered_hash_xdr(&payload_preimage).unwrap();
                let signature_args = host_vec![
                    &self.host,
                    host_vec![
                        &self.host,
                        sign_payload_for_account(&self.host, &self.keys[address_id], &payload)
                    ]
                ];
                contract_auth.push(ContractAuth {
                    address_with_nonce: Some(AddressWithNonce {
                        address: sc_address.clone(),
                        nonce,
                    }),
                    root_invocation,
                    signature_args: self.host.call_args_to_scvec(signature_args.into()).unwrap(),
                });
            }
        }

        self.host.set_authorization_entries(contract_auth).unwrap();
        assert_eq!(
            self.host
                .call(
                    root.contract_id.clone().into(),
                    Symbol::from_str("tree_fn"),
                    host_vec![&self.host, addresses, tree].into(),
                )
                .is_ok(),
            success
        );
    }

    // Verifies that nonces for the given contract_id+signer pairs are increased
    // by the expected value.
    fn verify_nonce_increments(&self, expected_increments: Vec<(&BytesN<32>, &Keypair, u64)>) {
        for (contract_id, key, expected_increment) in expected_increments {
            let nonce_increment = if let Some(last_nonce) = self
                .last_nonces
                .get(&(contract_id.to_vec().clone(), key.public.as_bytes().to_vec()))
            {
                let curr_nonce = self
                    .host
                    .read_nonce(
                        &Hash(contract_id.to_vec().try_into().unwrap()),
                        &self.key_to_sc_address(key),
                    )
                    .unwrap();
                curr_nonce - last_nonce
            } else {
                0
            };
            assert_eq!(nonce_increment, expected_increment);
        }
    }

    // Runs `tree_fn` corresponding to the provided setup in recordind mode and
    // returns the recorded payloads.
    fn run_recording(&self, root: &SetupNode) -> Vec<RecordedAuthPayload> {
        let addresses = self.get_addresses();
        let tree = self.convert_setup_tree(&root);
        self.host.switch_to_recording_auth();
        self.host
            .call(
                root.contract_id.clone().into(),
                Symbol::from_str("tree_fn"),
                host_vec![&self.host, addresses, tree].into(),
            )
            .unwrap();
        self.host.get_recorded_auth_payloads().unwrap()
    }

    fn key_to_sc_address(&self, key: &Keypair) -> ScAddress {
        ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
            key.public.to_bytes(),
        ))))
    }

    fn get_addresses(&self) -> HostVec {
        let mut addresses = HostVec::new(&self.host).unwrap();
        for key in &self.keys {
            let sc_address = self.key_to_sc_address(key);
            addresses
                .push(&self.host.add_host_object(sc_address).unwrap())
                .unwrap();
        }

        addresses
    }

    fn convert_sign_node(&self, root: &SignNode) -> AuthorizedInvocation {
        let mut sub_invocations = vec![];
        for c in &root.children {
            sub_invocations.push(self.convert_sign_node(c));
        }

        AuthorizedInvocation {
            contract_id: root.contract_id.to_vec().try_into().unwrap(),
            function_name: "tree_fn".to_string().try_into().unwrap(),
            args: ScVec::default(),
            sub_invocations: sub_invocations.try_into().unwrap(),
        }
    }

    fn convert_setup_tree(&self, root: &SetupNode) -> ContractTreeNode {
        let mut children = HostVec::new(&self.host).unwrap();
        for c in &root.children {
            children.push(&self.convert_setup_tree(c)).unwrap();
        }
        let mut need_auth = HostVec::new(&self.host).unwrap();
        for n in &root.need_auth {
            need_auth.push(n).unwrap();
        }
        ContractTreeNode {
            id: root.contract_id.clone(),
            need_auth,
            children,
        }
    }
}

#[test]
fn test_single_authorized_call() {
    let mut test = AuthTreeTest::setup(1, 2);
    let setup = SetupNode::new(&test.contracts[0], vec![true], vec![]);
    let expected_sign_payloads = vec![vec![SignNode::new(&test.contracts[0], vec![])]];
    assert_eq!(
        test.run_recording(&setup),
        vec![RecordedAuthPayload {
            address: Some(test.key_to_sc_address(&test.keys[0])),
            nonce: Some(0),
            invocation: test.convert_sign_node(&expected_sign_payloads[0][0])
        }]
    );

    // Correct call
    test.test_enforcing(&setup, expected_sign_payloads, true);
    test.verify_nonce_increments(vec![(&test.contracts[0], &test.keys[0], 1)]);

    // Correct call with an extra top-level payload
    test.test_enforcing(
        &setup,
        vec![vec![
            SignNode::new(&test.contracts[1], vec![]),
            SignNode::new(&test.contracts[0], vec![]),
        ]],
        true,
    );
    test.verify_nonce_increments(vec![
        (&test.contracts[0], &test.keys[0], 1),
        (&test.contracts[1], &test.keys[0], 0),
    ]);

    // Correct call with extra sub-contract payload
    test.test_enforcing(
        &setup,
        vec![vec![SignNode::new(
            &test.contracts[0],
            vec![SignNode::new(&test.contracts[1], vec![])],
        )]],
        true,
    );
    test.verify_nonce_increments(vec![
        (&test.contracts[0], &test.keys[0], 1),
        (&test.contracts[1], &test.keys[0], 0),
    ]);

    // Failing scenarios
    // Nothing signed
    test.test_enforcing(&setup, vec![vec![]], false);
    // Wrong contract
    test.test_enforcing(
        &setup,
        vec![vec![SignNode::new(&test.contracts[1], vec![])]],
        false,
    );
    // Smoke test nonces for one failing scenario - there is really no way
    // nonces are incremented unless the rollback logic is broken.
    test.verify_nonce_increments(vec![
        (&test.contracts[0], &test.keys[0], 0),
        (&test.contracts[1], &test.keys[0], 0),
    ]);
    // Correct contract called from a wrong contract
    test.test_enforcing(
        &setup,
        vec![vec![SignNode::new(
            &test.contracts[1],
            vec![SignNode::new(&test.contracts[0], vec![])],
        )]],
        false,
    );
}

#[test]
fn test_single_authorized_call_for_multiple_addresses() {
    let mut test = AuthTreeTest::setup(2, 2);
    let setup = SetupNode::new(&test.contracts[0], vec![true, true], vec![]);
    let expected_sign_payloads = vec![
        vec![SignNode::new(&test.contracts[0], vec![])],
        vec![SignNode::new(&test.contracts[0], vec![])],
    ];
    assert_eq!(
        test.run_recording(&setup),
        vec![
            RecordedAuthPayload {
                address: Some(test.key_to_sc_address(&test.keys[0])),
                nonce: Some(0),
                invocation: test.convert_sign_node(&expected_sign_payloads[0][0])
            },
            RecordedAuthPayload {
                address: Some(test.key_to_sc_address(&test.keys[1])),
                nonce: Some(0),
                invocation: test.convert_sign_node(&expected_sign_payloads[1][0])
            }
        ]
    );

    // Correct call
    test.test_enforcing(&setup, expected_sign_payloads, true);
    test.verify_nonce_increments(vec![
        (&test.contracts[0], &test.keys[0], 1),
        (&test.contracts[0], &test.keys[1], 1),
    ]);

    // Failing scenarios
    // Partially signed
    test.test_enforcing(
        &setup,
        vec![vec![], vec![SignNode::new(&test.contracts[0], vec![])]],
        false,
    );
    // Wrong contract
    test.test_enforcing(
        &setup,
        vec![
            vec![SignNode::new(&test.contracts[1], vec![])],
            vec![SignNode::new(&test.contracts[0], vec![])],
        ],
        false,
    );
    // Correct contract called from a wrong contract
    test.test_enforcing(
        &setup,
        vec![
            vec![SignNode::new(
                &test.contracts[1],
                vec![SignNode::new(&test.contracts[0], vec![])],
            )],
            vec![SignNode::new(&test.contracts[0], vec![])],
        ],
        false,
    );
}

#[test]
fn test_single_authorization_for_one_address_among_multiple() {
    let mut test = AuthTreeTest::setup(2, 2);
    let setup = SetupNode::new(&test.contracts[0], vec![false, true], vec![]);
    let expected_sign_payloads = vec![vec![], vec![SignNode::new(&test.contracts[0], vec![])]];
    assert_eq!(
        test.run_recording(&setup),
        vec![RecordedAuthPayload {
            address: Some(test.key_to_sc_address(&test.keys[1])),
            nonce: Some(0),
            invocation: test.convert_sign_node(&expected_sign_payloads[1][0])
        }]
    );

    // Correct call
    test.test_enforcing(&setup, expected_sign_payloads, true);
    test.verify_nonce_increments(vec![
        (&test.contracts[0], &test.keys[0], 0),
        (&test.contracts[0], &test.keys[1], 1),
    ]);
    // Correct call with both signatures, but only second address auth is needed
    test.test_enforcing(
        &setup,
        vec![
            vec![SignNode::new(&test.contracts[0], vec![])],
            vec![SignNode::new(&test.contracts[0], vec![])],
        ],
        true,
    );
    test.verify_nonce_increments(vec![
        (&test.contracts[0], &test.keys[0], 0),
        (&test.contracts[0], &test.keys[1], 1),
    ]);
    // Correct call with an unused extra contract signature
    test.test_enforcing(
        &setup,
        vec![
            vec![SignNode::new(&test.contracts[1], vec![])],
            vec![SignNode::new(&test.contracts[0], vec![])],
        ],
        true,
    );
    test.verify_nonce_increments(vec![
        (&test.contracts[0], &test.keys[1], 1),
        (&test.contracts[1], &test.keys[1], 0),
    ]);

    // Failing scenarios
    // Wrong address signed (first instead of second)
    test.test_enforcing(
        &setup,
        vec![vec![SignNode::new(&test.contracts[0], vec![])], vec![]],
        false,
    );
}

#[test]
fn test_single_authorized_call_tree() {
    let mut test = AuthTreeTest::setup(1, 5);
    // Tree edges (everything needs to be authorized): A->(B, C), B->(D, C), C->(E, D)
    let setup = SetupNode::new(
        &test.contracts[0],
        vec![true],
        vec![
            SetupNode::new(
                &test.contracts[1],
                vec![true],
                vec![
                    SetupNode::new(&test.contracts[3], vec![true], vec![]),
                    SetupNode::new(&test.contracts[2], vec![true], vec![]),
                ],
            ),
            SetupNode::new(
                &test.contracts[2],
                vec![true],
                vec![
                    SetupNode::new(&test.contracts[4], vec![true], vec![]),
                    SetupNode::new(&test.contracts[3], vec![true], vec![]),
                ],
            ),
        ],
    );
    assert_eq!(
        test.run_recording(&setup),
        vec![RecordedAuthPayload {
            address: Some(test.key_to_sc_address(&test.keys[0])),
            nonce: Some(0),
            invocation: test.convert_sign_node(&SignNode::new(
                &test.contracts[0],
                vec![
                    SignNode::new(
                        &test.contracts[1],
                        vec![
                            SignNode::new(&test.contracts[3], vec![]),
                            SignNode::new(&test.contracts[2], vec![]),
                        ],
                    ),
                    SignNode::new(
                        &test.contracts[2],
                        vec![
                            SignNode::new(&test.contracts[4], vec![]),
                            SignNode::new(&test.contracts[3], vec![]),
                        ],
                    ),
                ],
            ))
        }]
    );

    // Correct call
    test.test_enforcing(
        &setup,
        vec![vec![SignNode::new(
            &test.contracts[0],
            vec![
                SignNode::new(
                    &test.contracts[2],
                    vec![
                        SignNode::new(&test.contracts[3], vec![]),
                        SignNode::new(&test.contracts[4], vec![]),
                    ],
                ),
                SignNode::new(
                    &test.contracts[1],
                    vec![
                        SignNode::new(&test.contracts[2], vec![]),
                        SignNode::new(&test.contracts[3], vec![]),
                    ],
                ),
            ],
        )]],
        true,
    );
    test.verify_nonce_increments(vec![
        (&test.contracts[0], &test.keys[0], 1),
        (&test.contracts[1], &test.keys[0], 0),
        (&test.contracts[2], &test.keys[0], 0),
        (&test.contracts[3], &test.keys[0], 0),
        (&test.contracts[4], &test.keys[0], 0),
    ]);

    // Correct call with some extra authorizations
    test.test_enforcing(
        &setup,
        vec![vec![
            SignNode::new(
                &test.contracts[0],
                vec![
                    SignNode::new(
                        &test.contracts[1],
                        vec![
                            SignNode::new(&test.contracts[2], vec![]),
                            SignNode::new(&test.contracts[3], vec![]),
                            SignNode::new(&test.contracts[4], vec![]),
                        ],
                    ),
                    SignNode::new(
                        &test.contracts[2],
                        vec![
                            SignNode::new(&test.contracts[3], vec![]),
                            SignNode::new(&test.contracts[4], vec![]),
                        ],
                    ),
                    SignNode::new(&test.contracts[3], vec![]),
                ],
            ),
            SignNode::new(&test.contracts[0], vec![]),
        ]],
        true,
    );
    test.verify_nonce_increments(vec![
        (&test.contracts[0], &test.keys[0], 1),
        (&test.contracts[1], &test.keys[0], 0),
        (&test.contracts[2], &test.keys[0], 0),
        (&test.contracts[3], &test.keys[0], 0),
        (&test.contracts[4], &test.keys[0], 0),
    ]);

    // Failing scenarios
    // Incorrect call due to a missing invocation
    test.test_enforcing(
        &setup,
        vec![vec![SignNode::new(
            &test.contracts[0],
            vec![
                SignNode::new(
                    &test.contracts[1],
                    vec![SignNode::new(&test.contracts[2], vec![])],
                ),
                SignNode::new(
                    &test.contracts[2],
                    vec![
                        SignNode::new(&test.contracts[3], vec![]),
                        SignNode::new(&test.contracts[4], vec![]),
                    ],
                ),
            ],
        )]],
        false,
    );

    // Incorrect call due to mismatching node
    test.test_enforcing(
        &setup,
        vec![vec![SignNode::new(
            &test.contracts[0],
            vec![
                SignNode::new(
                    &test.contracts[4], // Should have been 1
                    vec![
                        // Invocation order shouldn't matter here and purposely
                        // doesn't match the call tree order
                        SignNode::new(&test.contracts[2], vec![]),
                        SignNode::new(&test.contracts[3], vec![]),
                    ],
                ),
                SignNode::new(
                    &test.contracts[2],
                    vec![
                        SignNode::new(&test.contracts[3], vec![]),
                        SignNode::new(&test.contracts[4], vec![]),
                    ],
                ),
            ],
        )]],
        false,
    );

    // Incorrect call due to extra empty root node - this is where the order
    // matters
    test.test_enforcing(
        &setup,
        vec![vec![
            SignNode::new(&test.contracts[0], vec![]),
            SignNode::new(
                &test.contracts[0],
                vec![
                    SignNode::new(
                        &test.contracts[1],
                        vec![
                            // Invocation order shouldn't matter here and purposely
                            // doesn't match the call tree order
                            SignNode::new(&test.contracts[2], vec![]),
                            SignNode::new(&test.contracts[3], vec![]),
                        ],
                    ),
                    SignNode::new(
                        &test.contracts[2],
                        vec![
                            SignNode::new(&test.contracts[3], vec![]),
                            SignNode::new(&test.contracts[4], vec![]),
                        ],
                    ),
                ],
            ),
        ]],
        false,
    );
}

#[test]
fn test_two_authorized_trees() {
    let mut test = AuthTreeTest::setup(1, 5);
    let setup = SetupNode::new(
        &test.contracts[0],
        vec![false],
        vec![
            SetupNode::new(
                &test.contracts[1],
                vec![true],
                vec![
                    SetupNode::new(&test.contracts[3], vec![true], vec![]),
                    SetupNode::new(&test.contracts[2], vec![true], vec![]),
                ],
            ),
            SetupNode::new(
                &test.contracts[2],
                vec![true],
                vec![
                    SetupNode::new(&test.contracts[4], vec![true], vec![]),
                    SetupNode::new(&test.contracts[3], vec![true], vec![]),
                ],
            ),
        ],
    );

    assert_eq!(
        test.run_recording(&setup),
        vec![
            RecordedAuthPayload {
                address: Some(test.key_to_sc_address(&test.keys[0])),
                nonce: Some(0),
                invocation: test.convert_sign_node(&SignNode::new(
                    &test.contracts[1],
                    vec![
                        SignNode::new(&test.contracts[3], vec![]),
                        SignNode::new(&test.contracts[2], vec![]),
                    ],
                ),)
            },
            RecordedAuthPayload {
                address: Some(test.key_to_sc_address(&test.keys[0])),
                nonce: Some(0),
                invocation: test.convert_sign_node(&SignNode::new(
                    &test.contracts[2],
                    vec![
                        SignNode::new(&test.contracts[4], vec![]),
                        SignNode::new(&test.contracts[3], vec![]),
                    ],
                ),)
            }
        ]
    );

    // Correct call
    test.test_enforcing(
        &setup,
        vec![vec![
            SignNode::new(
                &test.contracts[1],
                vec![
                    SignNode::new(&test.contracts[2], vec![]),
                    SignNode::new(&test.contracts[3], vec![]),
                ],
            ),
            SignNode::new(
                &test.contracts[2],
                vec![
                    SignNode::new(&test.contracts[3], vec![]),
                    SignNode::new(&test.contracts[4], vec![]),
                ],
            ),
        ]],
        true,
    );
    test.verify_nonce_increments(vec![
        (&test.contracts[0], &test.keys[0], 0),
        (&test.contracts[1], &test.keys[0], 1),
        (&test.contracts[2], &test.keys[0], 1),
        (&test.contracts[3], &test.keys[0], 0),
        (&test.contracts[4], &test.keys[0], 0),
    ]);

    // Failing scenarios
    // Top-level authorization instead of 2 trees
    test.test_enforcing(
        &setup,
        vec![vec![SignNode::new(
            &test.contracts[0],
            vec![
                SignNode::new(
                    &test.contracts[1],
                    vec![
                        SignNode::new(&test.contracts[2], vec![]),
                        SignNode::new(&test.contracts[3], vec![]),
                    ],
                ),
                SignNode::new(
                    &test.contracts[2],
                    vec![
                        SignNode::new(&test.contracts[3], vec![]),
                        SignNode::new(&test.contracts[4], vec![]),
                    ],
                ),
            ],
        )]],
        false,
    );
}

#[test]
fn test_three_authorized_trees() {
    let mut test = AuthTreeTest::setup(1, 5);

    let setup = SetupNode::new(
        &test.contracts[0],
        vec![false],
        vec![
            SetupNode::new(
                &test.contracts[1],
                vec![false],
                vec![
                    SetupNode::new(&test.contracts[3], vec![true], vec![]),
                    SetupNode::new(&test.contracts[2], vec![true], vec![]),
                ],
            ),
            SetupNode::new(
                &test.contracts[2],
                vec![true],
                vec![
                    SetupNode::new(&test.contracts[4], vec![true], vec![]),
                    SetupNode::new(&test.contracts[3], vec![true], vec![]),
                ],
            ),
        ],
    );

    assert_eq!(
        test.run_recording(&setup),
        vec![
            RecordedAuthPayload {
                address: Some(test.key_to_sc_address(&test.keys[0])),
                nonce: Some(0),
                invocation: test.convert_sign_node(&SignNode::new(&test.contracts[3], vec![]),)
            },
            RecordedAuthPayload {
                address: Some(test.key_to_sc_address(&test.keys[0])),
                nonce: Some(0),
                invocation: test.convert_sign_node(&SignNode::new(&test.contracts[2], vec![]),)
            },
            RecordedAuthPayload {
                address: Some(test.key_to_sc_address(&test.keys[0])),
                nonce: Some(1),
                invocation: test.convert_sign_node(&SignNode::new(
                    &test.contracts[2],
                    vec![
                        SignNode::new(&test.contracts[4], vec![]),
                        SignNode::new(&test.contracts[3], vec![]),
                    ],
                ),)
            }
        ]
    );

    // Correct call
    test.test_enforcing(
        &setup,
        vec![vec![
            SignNode::new(&test.contracts[2], vec![]),
            SignNode::new(
                &test.contracts[2],
                vec![
                    SignNode::new(&test.contracts[3], vec![]),
                    SignNode::new(&test.contracts[4], vec![]),
                ],
            ),
            SignNode::new(&test.contracts[3], vec![]),
        ]],
        true,
    );
    test.verify_nonce_increments(vec![
        (&test.contracts[0], &test.keys[0], 0),
        (&test.contracts[1], &test.keys[0], 0),
        (&test.contracts[2], &test.keys[0], 2),
        (&test.contracts[3], &test.keys[0], 1),
        (&test.contracts[4], &test.keys[0], 0),
    ]);

    // Failing scenarios
    // Top-level tree instead of 3 trees
    test.test_enforcing(
        &setup,
        vec![vec![SignNode::new(
            &test.contracts[0],
            vec![
                SignNode::new(
                    &test.contracts[1],
                    vec![
                        SignNode::new(&test.contracts[2], vec![]),
                        SignNode::new(&test.contracts[3], vec![]),
                    ],
                ),
                SignNode::new(
                    &test.contracts[2],
                    vec![
                        SignNode::new(&test.contracts[3], vec![]),
                        SignNode::new(&test.contracts[4], vec![]),
                    ],
                ),
            ],
        )]],
        false,
    );

    // 2 trees instead of 3
    test.test_enforcing(
        &setup,
        vec![vec![
            SignNode::new(
                &test.contracts[1],
                vec![
                    SignNode::new(&test.contracts[2], vec![]),
                    SignNode::new(&test.contracts[3], vec![]),
                ],
            ),
            SignNode::new(
                &test.contracts[2],
                vec![
                    SignNode::new(&test.contracts[3], vec![]),
                    SignNode::new(&test.contracts[4], vec![]),
                ],
            ),
        ]],
        false,
    );

    // Incorrect order - this is a bit of an edge case, but if there are
    // multiple invocations that are absolutely identical, we just resolve
    // them one-by-one in the same order as they are provided in the transaction
    // and the order here is different from the actual call order (contract 2
    // without sub-invocations happens *before* the contract 2 call with
    // sub-invocations, while the payload comes *after* it).
    test.test_enforcing(
        &setup,
        vec![vec![
            SignNode::new(
                &test.contracts[2],
                vec![
                    SignNode::new(&test.contracts[3], vec![]),
                    SignNode::new(&test.contracts[4], vec![]),
                ],
            ),
            SignNode::new(&test.contracts[2], vec![]),
            SignNode::new(&test.contracts[3], vec![]),
        ]],
        false,
    );
}

#[test]
fn test_multi_address_trees() {
    let mut test = AuthTreeTest::setup(3, 5);
    let setup = SetupNode::new(
        &test.contracts[0],
        vec![true, false, true],
        vec![
            SetupNode::new(
                &test.contracts[1],
                vec![true, true, false],
                vec![
                    SetupNode::new(&test.contracts[3], vec![false, true, true], vec![]),
                    SetupNode::new(&test.contracts[2], vec![true, false, false], vec![]),
                ],
            ),
            SetupNode::new(
                &test.contracts[2],
                vec![true, true, false],
                vec![
                    SetupNode::new(&test.contracts[4], vec![true, false, true], vec![]),
                    SetupNode::new(&test.contracts[3], vec![true, true, true], vec![]),
                ],
            ),
        ],
    );

    assert_eq!(
        test.run_recording(&setup),
        vec![
            RecordedAuthPayload {
                address: Some(test.key_to_sc_address(&test.keys[0])),
                nonce: Some(0),
                invocation: test.convert_sign_node(&SignNode::new(
                    &test.contracts[0],
                    vec![
                        SignNode::new(
                            &test.contracts[1],
                            vec![SignNode::new(&test.contracts[2], vec![])],
                        ),
                        SignNode::new(
                            &test.contracts[2],
                            vec![
                                SignNode::new(&test.contracts[4], vec![]),
                                SignNode::new(&test.contracts[3], vec![]),
                            ],
                        ),
                    ],
                ),)
            },
            RecordedAuthPayload {
                address: Some(test.key_to_sc_address(&test.keys[2])),
                nonce: Some(0),
                invocation: test.convert_sign_node(&SignNode::new(
                    &test.contracts[0],
                    vec![
                        SignNode::new(&test.contracts[3], vec![]),
                        SignNode::new(&test.contracts[4], vec![]),
                        SignNode::new(&test.contracts[3], vec![]),
                    ],
                ))
            },
            RecordedAuthPayload {
                address: Some(test.key_to_sc_address(&test.keys[1])),
                nonce: Some(0),
                invocation: test.convert_sign_node(&SignNode::new(
                    &test.contracts[1],
                    vec![SignNode::new(&test.contracts[3], vec![])],
                ),)
            },
            RecordedAuthPayload {
                address: Some(test.key_to_sc_address(&test.keys[1])),
                nonce: Some(0),
                invocation: test.convert_sign_node(&SignNode::new(
                    &test.contracts[2],
                    vec![SignNode::new(&test.contracts[3], vec![])],
                ),)
            },
        ]
    );

    // Correct call
    test.test_enforcing(
        &setup,
        vec![
            vec![SignNode::new(
                &test.contracts[0],
                vec![
                    SignNode::new(
                        &test.contracts[1],
                        vec![SignNode::new(&test.contracts[2], vec![])],
                    ),
                    SignNode::new(
                        &test.contracts[2],
                        vec![
                            SignNode::new(&test.contracts[3], vec![]),
                            SignNode::new(&test.contracts[4], vec![]),
                        ],
                    ),
                ],
            )],
            vec![
                SignNode::new(
                    &test.contracts[2],
                    vec![SignNode::new(&test.contracts[3], vec![])],
                ),
                SignNode::new(
                    &test.contracts[1],
                    vec![SignNode::new(&test.contracts[3], vec![])],
                ),
            ],
            vec![SignNode::new(
                &test.contracts[0],
                vec![
                    SignNode::new(&test.contracts[3], vec![]),
                    SignNode::new(&test.contracts[3], vec![]),
                    SignNode::new(&test.contracts[4], vec![]),
                ],
            )],
        ],
        true,
    );
    test.verify_nonce_increments(vec![
        // account 0
        (&test.contracts[0], &test.keys[0], 1),
        (&test.contracts[1], &test.keys[0], 0),
        (&test.contracts[2], &test.keys[0], 0),
        (&test.contracts[3], &test.keys[0], 0),
        (&test.contracts[4], &test.keys[0], 0),
        // account 1
        (&test.contracts[0], &test.keys[1], 0),
        (&test.contracts[1], &test.keys[1], 1),
        (&test.contracts[2], &test.keys[1], 1),
        (&test.contracts[3], &test.keys[1], 0),
        (&test.contracts[4], &test.keys[1], 0),
        // account 2
        (&test.contracts[0], &test.keys[2], 1),
        (&test.contracts[1], &test.keys[2], 0),
        (&test.contracts[2], &test.keys[2], 0),
        (&test.contracts[3], &test.keys[2], 0),
        (&test.contracts[4], &test.keys[2], 0),
    ]);

    // Failing scenarios
    // Missing one call for address[2]
    test.test_enforcing(
        &setup,
        vec![
            vec![SignNode::new(
                &test.contracts[0],
                vec![
                    SignNode::new(
                        &test.contracts[1],
                        vec![SignNode::new(&test.contracts[2], vec![])],
                    ),
                    SignNode::new(
                        &test.contracts[2],
                        vec![
                            SignNode::new(&test.contracts[3], vec![]),
                            SignNode::new(&test.contracts[4], vec![]),
                        ],
                    ),
                ],
            )],
            vec![
                SignNode::new(
                    &test.contracts[1],
                    vec![SignNode::new(&test.contracts[3], vec![])],
                ),
                SignNode::new(
                    &test.contracts[2],
                    vec![SignNode::new(&test.contracts[3], vec![])],
                ),
            ],
            vec![SignNode::new(
                &test.contracts[0],
                vec![
                    SignNode::new(&test.contracts[3], vec![]),
                    SignNode::new(&test.contracts[4], vec![]),
                ],
            )],
        ],
        false,
    );
}
