use crate::budget::AsBudget;
use crate::host_object::MuxedScAddress;
use crate::storage::Storage;
use crate::xdr::{LedgerKey, MuxedEd25519Account, ScAddress, ScErrorCode, ScErrorType, Uint256};
use crate::{Host, HostError};
use soroban_env_common::{AddressObject, Env, MuxedAddressObject, Symbol, TryFromVal, TryIntoVal};
use soroban_test_wasms::{
    CONTRACT_STORAGE, CONTRACT_STORAGE_P26, CONTRACT_STORAGE_WITH_VALS, INVOKE_CONTRACT,
};

// Note: Tests for the old Footprint type methods (footprint_record_access,
// footprint_enforce_access, etc.) have been removed as the Footprint type
// no longer exists. Access enforcement is now done inline in Storage methods.

fn storage_fn_name(host: &Host, fn_name: &str, storage: &str) -> Symbol {
    Symbol::try_from_val(host, &format!("{}_{}", fn_name, storage).as_str()).unwrap()
}

fn test_storage(host: &Host, contract_id: AddressObject, storage: &str) {
    let key_1 = Symbol::try_from_small_str("key_1").unwrap();
    let key_2 = Symbol::try_from_val(host, &"this_is_key_2").unwrap();
    // Check that the key is not in the storage yet
    assert_eq!(
        bool::try_from_val(
            host,
            &host
                .call(
                    contract_id,
                    storage_fn_name(&host, "has", storage),
                    test_vec![host, key_1].into(),
                )
                .unwrap()
        )
        .unwrap(),
        false
    );
    // Put a key to storage and verify it's there
    host.call(
        contract_id,
        storage_fn_name(host, "put", storage),
        test_vec![host, key_1, 1234_u64].into(),
    )
    .unwrap();

    assert_eq!(
        bool::try_from_val(
            host,
            &host
                .call(
                    contract_id,
                    storage_fn_name(host, "has", storage),
                    test_vec![host, key_1].into(),
                )
                .unwrap()
        )
        .unwrap(),
        true
    );

    let max_live_until_ledger: u32 = host.max_live_until_ledger().unwrap();
    let ledger_seq: u32 = host.get_ledger_sequence().unwrap().into();
    let max_extend = max_live_until_ledger - ledger_seq;
    let threshold: u32 = 1;

    // Smoke test extend
    let extend_args = if storage == "instance" {
        test_vec![host, threshold, max_extend]
    } else {
        test_vec![host, key_1, threshold, max_extend]
    };

    host.call(
        contract_id,
        storage_fn_name(host, "extend", storage),
        extend_args.into(),
    )
    .unwrap();

    let extend_args_past_max = if storage == "instance" {
        test_vec![host, threshold, max_extend + 1]
    } else {
        test_vec![host, key_1, threshold, max_extend + 1]
    };

    if storage == "temporary" {
        assert!(host
            .call(
                contract_id,
                storage_fn_name(host, "extend", storage),
                extend_args_past_max.into(),
            )
            .is_err());
    } else {
        host.call(
            contract_id,
            storage_fn_name(host, "extend", storage),
            extend_args_past_max.into(),
        )
        .unwrap();
    }

    // Put another key and verify it's there
    host.call(
        contract_id,
        storage_fn_name(host, "put", storage),
        test_vec![host, key_2, u64::MAX].into(),
    )
    .unwrap();
    assert_eq!(
        bool::try_from_val(
            host,
            &host
                .call(
                    contract_id,
                    storage_fn_name(host, "has", storage),
                    test_vec![
                        host,
                        // Use a new object to sanity-check that comparison
                        // happens based on value.
                        Symbol::try_from_val(host, &"this_is_key_2").unwrap(),
                    ]
                    .into(),
                )
                .unwrap()
        )
        .unwrap(),
        true
    );

    // Get values for both keys

    assert_eq!(
        u64::try_from_val(
            host,
            &host
                .call(
                    contract_id,
                    storage_fn_name(host, "get", storage),
                    test_vec![host, key_1].into(),
                )
                .unwrap()
        )
        .unwrap(),
        1234_u64
    );
    assert_eq!(
        u64::try_from_val(
            host,
            &host
                .call(
                    contract_id,
                    storage_fn_name(host, "get", storage),
                    test_vec![host, key_2].into(),
                )
                .unwrap()
        )
        .unwrap(),
        u64::MAX
    );

    // Update value for key 2 and check it
    host.call(
        contract_id,
        storage_fn_name(host, "put", storage),
        test_vec![host, key_2, 4321_u64].into(),
    )
    .unwrap();
    assert_eq!(
        u64::try_from_val(
            host,
            &host
                .call(
                    contract_id,
                    storage_fn_name(host, "get", storage),
                    test_vec![host, key_2].into(),
                )
                .unwrap()
        )
        .unwrap(),
        4321_u64
    );

    // Delete entry for key 1
    host.call(
        contract_id,
        storage_fn_name(host, "del", storage),
        test_vec![host, key_1].into(),
    )
    .unwrap();
    // Delete again - that's a no-op, but it shouldn't fail either.
    host.call(
        contract_id,
        storage_fn_name(host, "del", storage),
        test_vec![host, key_1].into(),
    )
    .unwrap();
    // Only the second key is now present
    assert_eq!(
        bool::try_from_val(
            host,
            &host
                .call(
                    contract_id,
                    storage_fn_name(host, "has", storage),
                    test_vec![host, key_1].into(),
                )
                .unwrap()
        )
        .unwrap(),
        false
    );
    assert_eq!(
        bool::try_from_val(
            host,
            &host
                .call(
                    contract_id,
                    storage_fn_name(host, "has", storage),
                    test_vec![host, key_2].into(),
                )
                .unwrap()
        )
        .unwrap(),
        true
    );
}

#[test]
fn test_persistent_storage() {
    let host = observe_host!(Host::test_host_with_recording_footprint());
    let contract_id = host.register_test_contract_wasm(CONTRACT_STORAGE);
    test_storage(&host, contract_id, "persistent");
}

#[test]
fn test_temp_storage() {
    let host = observe_host!(Host::test_host_with_recording_footprint());
    let contract_id = host.register_test_contract_wasm(CONTRACT_STORAGE);
    test_storage(&host, contract_id, "temporary");
}

#[test]
fn test_instance_storage() {
    let host = observe_host!(Host::test_host_with_recording_footprint());
    let contract_id = host.register_test_contract_wasm(CONTRACT_STORAGE);
    test_storage(&host, contract_id, "instance");
}

#[test]
fn test_nested_bump() {
    let host = observe_host!(Host::test_host_with_recording_footprint());
    let invoke_contract_id = host.register_test_contract_wasm(INVOKE_CONTRACT);
    let storage_contract_id = host.register_test_contract_wasm(CONTRACT_STORAGE);

    let contract_id_hash = host.contract_id_from_address(storage_contract_id).unwrap();
    let storage_key: std::rc::Rc<LedgerKey> = host
        .contract_instance_ledger_key(&contract_id_hash)
        .unwrap();
    host.with_mut_storage(|s: &mut Storage| {
        let entry = s.map.get(&storage_key, host.as_budget()).unwrap().unwrap();
        let v = entry.current_ttl().unwrap();
        assert_eq!(v, 4095);
        Ok(())
    })
    .unwrap();

    host.call(
        invoke_contract_id,
        Symbol::try_from_val(&*host, &"invoke_storage").unwrap(),
        test_vec![
            &*host,
            storage_contract_id,
            &Symbol::try_from_val(&*host, &"extend_instance").unwrap(),
            5000u32,
            5000u32
        ]
        .into(),
    )
    .unwrap();

    host.with_mut_storage(|s: &mut Storage| {
        let entry = s.map.get(&storage_key, host.as_budget()).unwrap().unwrap();
        let v = entry.current_ttl().unwrap();
        // The inner call adds 10 to the extend_to parameter
        assert_eq!(v, 5010);
        Ok(())
    })
    .unwrap()
}

#[test]
fn test_muxed_account_is_not_allowed_as_storage_key() {
    let host = Host::test_host_with_recording_footprint();
    let contract_id = host.register_test_contract_wasm(CONTRACT_STORAGE_WITH_VALS);
    let muxed_address = MuxedScAddress(ScAddress::MuxedAccount(MuxedEd25519Account {
        id: 123,
        ed25519: Uint256([10; 32]),
    }));
    let muxed_address_val = host.add_host_object(muxed_address.clone()).unwrap();

    let run_test = |storage: &str| {
        // Muxed address can't be used as a storage key.
        if storage != "instance" {
            // For instance storage we allow checking for presence of
            // MuxedAddress as ledger key, so there won't be a storage error
            // in a test.
            // We still don't allow storing the MuxedAddresses, so there is no
            // real risk for the users.
            assert!(HostError::result_matches_err(
                host.call(
                    contract_id,
                    storage_fn_name(&host, "get", storage),
                    test_vec![&host, muxed_address_val].into(),
                ),
                (ScErrorType::Storage, ScErrorCode::InvalidInput)
            ));
        }

        assert!(HostError::result_matches_err(
            host.call(
                contract_id,
                storage_fn_name(&host, "put", storage),
                test_vec![&host, muxed_address_val, 1234_u64].into(),
            ),
            (ScErrorType::Storage, ScErrorCode::InvalidInput)
        ));
        // But it can be used as a value
        assert!(host
            .call(
                contract_id,
                storage_fn_name(&host, "put", storage),
                test_vec![&host, 1234_u64, muxed_address_val].into(),
            )
            .is_ok());
        let v = host
            .call(
                contract_id,
                storage_fn_name(&host, "get", storage),
                test_vec![&host, 1234_u64].into(),
            )
            .unwrap();
        let addr_obj = MuxedAddressObject::try_from_val(&host, &v).unwrap();
        let addr = host
            .visit_obj(addr_obj, |addr: &MuxedScAddress| Ok(addr.clone()))
            .unwrap();
        assert_eq!(addr, muxed_address);
    };
    run_test("persistent");
    run_test("temporary");
    run_test("instance");
}

#[test]
fn test_storage_mix() {
    // This makes sure the keyspaces are not mixed between storage types.
    let host = observe_host!(Host::test_host_with_recording_footprint());
    host.with_budget(|b| {
        b.reset_unlimited().unwrap();
        Ok(())
    })
    .unwrap();
    let contract_id = host.register_test_contract_wasm(CONTRACT_STORAGE);
    test_storage(&host, contract_id, "persistent");
    test_storage(&host, contract_id, "temporary");
    test_storage(&host, contract_id, "instance");
}

#[test]
#[should_panic(
    expected = "called `Result::unwrap()` on an `Err` value: Error(Budget, ExceededLimit)"
)]
fn test_large_persistent_value() {
    let host = observe_host!(Host::test_host_with_recording_footprint());
    let contract_id = host.register_test_contract_wasm(CONTRACT_STORAGE);
    let key_1 = Symbol::try_from_small_str("key_1").unwrap();

    let bytes = vec![0u8; 100000000];
    let _ = host.try_call(
        contract_id,
        storage_fn_name(&host, "put", "persistent"),
        test_vec![&*host, key_1, bytes].into(),
    );
}

#[test]
#[should_panic(
    expected = "called `Result::unwrap()` on an `Err` value: Error(Budget, ExceededLimit)"
)]
fn test_large_instance_value() {
    let host = observe_host!(Host::test_host_with_recording_footprint());
    let contract_id = host.register_test_contract_wasm(CONTRACT_STORAGE);
    let key_1 = Symbol::try_from_small_str("key_1").unwrap();

    let bytes = vec![0u8; 100000000];
    let _ = host.try_call(
        contract_id,
        storage_fn_name(&host, "put", "instance"),
        test_vec![&*host, key_1, bytes].into(),
    );
}

#[test]
#[should_panic(
    expected = "called `Result::unwrap()` on an `Err` value: Error(Budget, ExceededLimit)"
)]
fn test_large_persistent_key() {
    let host = observe_host!(Host::test_host_with_recording_footprint());
    let contract_id = host.register_test_contract_wasm(CONTRACT_STORAGE);

    let key = vec![0u8; 100000000];
    let _ = host.try_call(
        contract_id,
        storage_fn_name(&host, "put", "persistent"),
        test_vec![&*host, key, 1_u64].into(),
    );
}

#[test]
#[should_panic(
    expected = "called `Result::unwrap()` on an `Err` value: Error(Budget, ExceededLimit)"
)]
fn test_large_instance_key() {
    let host = observe_host!(Host::test_host_with_recording_footprint());
    let contract_id = host.register_test_contract_wasm(CONTRACT_STORAGE);

    let key = vec![0u8; 100000000];
    let _ = host.try_call(
        contract_id,
        storage_fn_name(&host, "put", "instance"),
        test_vec![&*host, key, 1_u64].into(),
    );
}

/// Tests that multiple storage modifications at the same frame depth work correctly.
/// This exercises the copy-on-write semantics and verifies that we don't create
/// duplicate frames in the entry and TTL stacks when performing multiple operations
/// on the same key within a single contract call.
#[test]
fn test_stress_storage_same_frame_depth() {
    let host = observe_host!(Host::test_host_with_recording_footprint());
    let contract_id = host.register_test_contract_wasm(CONTRACT_STORAGE_P26);

    let stress_storage_fn = Symbol::try_from_val(&*host, &"stress_storage").unwrap();
    let key = Symbol::try_from_small_str("stresskey").unwrap();

    // Test temporary storage (storage_type = 0)
    host.call(
        contract_id,
        stress_storage_fn,
        test_vec![&*host, 0_u32, key].into(),
    )
    .expect("stress_storage for temporary should succeed");

    // Test persistent storage (storage_type = 1)
    host.call(
        contract_id,
        stress_storage_fn,
        test_vec![&*host, 1_u32, key].into(),
    )
    .expect("stress_storage for persistent should succeed");

    // Test instance storage (storage_type = 2)
    host.call(
        contract_id,
        stress_storage_fn,
        test_vec![&*host, 2_u32, key].into(),
    )
    .expect("stress_storage for instance should succeed");
}
