use crate::{
    budget::Budget,
    host::metered_hash::MeteredHashMap,
    storage::StorageLedgerEntryData,
    xdr::{
        ContractCostType, ContractDataDurability, ContractId, Hash, LedgerKey,
        LedgerKeyContractData, ScAddress, ScVal,
    },
    HostError, Val,
};
use std::rc::Rc;

fn create_unlimited_budget() -> Budget {
    Budget::default()
}

fn create_limited_budget(limit: u64) -> Budget {
    let budget = Budget::default();
    budget.reset_limits(limit, limit).unwrap();
    budget
}

fn make_ledger_key(id: u64) -> Rc<LedgerKey> {
    Rc::new(LedgerKey::ContractData(LedgerKeyContractData {
        contract: ScAddress::Contract(ContractId(Hash([0u8; 32]))),
        key: ScVal::U64(id),
        durability: ContractDataDurability::Persistent,
    }))
}

/// Creates a test entry data tuple: (StorageLedgerEntryData, Option<u32>)
fn make_cache_entry(val: u64) -> Option<(StorageLedgerEntryData, Option<u32>)> {
    // Using Val::from_u32 for simplicity - this represents the cached value
    Some((
        StorageLedgerEntryData::ContractData(Val::from_u32(val as u32).into()),
        Some(1000),
    ))
}

#[test]
fn test_metered_hash_map_basic_operations() -> Result<(), HostError> {
    let budget = create_unlimited_budget();
    let mut map: MeteredHashMap<Rc<LedgerKey>, Option<(StorageLedgerEntryData, Option<u32>)>> =
        MeteredHashMap::new();

    // Test len on empty map
    assert_eq!(map.len(), 0);

    // Test put
    map.insert(make_ledger_key(1), make_cache_entry(100), &budget)?;
    assert_eq!(map.len(), 1);

    // Test get
    let result = map.get(&make_ledger_key(1), &budget)?;
    assert!(result.is_some());
    let entry = result.unwrap();
    assert!(matches!(
        entry,
        Some((StorageLedgerEntryData::ContractData(_), _))
    ));

    // Test get non-existent key
    assert!(map.get(&make_ledger_key(999), &budget)?.is_none());

    // Test contains_key
    assert!(map.contains_key(&make_ledger_key(1), &budget)?);
    assert!(!map.contains_key(&make_ledger_key(999), &budget)?);

    // Test put overwrites
    map.insert(make_ledger_key(1), make_cache_entry(200), &budget)?;
    let result = map.get(&make_ledger_key(1), &budget)?;
    assert!(result.is_some());
    assert_eq!(map.len(), 1);

    // Test multiple entries
    map.insert(make_ledger_key(2), make_cache_entry(300), &budget)?;
    map.insert(make_ledger_key(3), make_cache_entry(400), &budget)?;
    assert_eq!(map.len(), 3);

    Ok(())
}

#[test]
fn test_metered_hash_map_upsert() -> Result<(), HostError> {
    let budget = create_unlimited_budget();
    let mut map: MeteredHashMap<Rc<LedgerKey>, Option<(StorageLedgerEntryData, Option<u32>)>> =
        MeteredHashMap::new();

    // Test upsert on non-existent key (inserts)
    map.upsert(&make_ledger_key(1), make_cache_entry(100), &budget)?;
    assert_eq!(map.len(), 1);

    // Test upsert on existing key (updates)
    map.upsert(
        &make_ledger_key(1),
        Some((
            StorageLedgerEntryData::ContractData(Val::from_u32(999).into()),
            Some(1000),
        )),
        &budget,
    )?;
    let result = map.get(&make_ledger_key(1), &budget)?;
    assert!(result.is_some());
    assert_eq!(map.len(), 1); // Still only 1 entry

    Ok(())
}

#[test]
fn test_metered_hash_map_remove() -> Result<(), HostError> {
    let budget = create_unlimited_budget();
    let mut map: MeteredHashMap<Rc<LedgerKey>, Option<(StorageLedgerEntryData, Option<u32>)>> =
        MeteredHashMap::new();

    map.insert(make_ledger_key(1), make_cache_entry(100), &budget)?;
    map.insert(make_ledger_key(2), make_cache_entry(200), &budget)?;
    assert_eq!(map.len(), 2);

    // Test remove existing key
    let removed = map.remove(&make_ledger_key(1), &budget)?;
    assert!(removed.is_some());
    assert_eq!(map.len(), 1);
    assert!(!map.contains_key(&make_ledger_key(1), &budget)?);

    // Test remove non-existent key
    let removed = map.remove(&make_ledger_key(99), &budget)?;
    assert!(removed.is_none());
    assert_eq!(map.len(), 1);

    Ok(())
}

#[test]
fn test_metered_hash_map_iter() -> Result<(), HostError> {
    let budget = create_unlimited_budget();
    let mut map: MeteredHashMap<Rc<LedgerKey>, Option<(StorageLedgerEntryData, Option<u32>)>> =
        MeteredHashMap::new();

    map.insert(make_ledger_key(1), make_cache_entry(100), &budget)?;
    map.insert(make_ledger_key(2), make_cache_entry(200), &budget)?;
    map.insert(make_ledger_key(3), make_cache_entry(300), &budget)?;

    // Test iter - collects entries (order not guaranteed)
    // Note: iter() no longer takes budget and is not metered (returns references)
    let entries: Vec<_> = map.iter().collect();
    assert_eq!(entries.len(), 3);

    Ok(())
}

#[test]
fn test_metered_hash_map_metered_clone() -> Result<(), HostError> {
    let budget = create_unlimited_budget();
    let mut map: MeteredHashMap<Rc<LedgerKey>, Option<(StorageLedgerEntryData, Option<u32>)>> =
        MeteredHashMap::new();

    map.insert(make_ledger_key(1), make_cache_entry(100), &budget)?;
    map.insert(make_ledger_key(2), make_cache_entry(200), &budget)?;

    // Clone the map
    let cloned = map.metered_clone(&budget)?;

    // Verify clone has same contents
    assert_eq!(cloned.len(), 2);
    assert!(cloned.get(&make_ledger_key(1), &budget)?.is_some());
    assert!(cloned.get(&make_ledger_key(2), &budget)?.is_some());

    Ok(())
}

#[test]
fn test_metered_hash_map_budget_consumption() -> Result<(), HostError> {
    let budget = create_unlimited_budget();
    let mut map: MeteredHashMap<Rc<LedgerKey>, Option<(StorageLedgerEntryData, Option<u32>)>> =
        MeteredHashMap::new();

    // Record initial budget
    let initial_cpu = budget
        .get_cpu_insns_consumed()
        .expect("budget should be available");

    // Perform some operations
    map.insert(make_ledger_key(1), make_cache_entry(100), &budget)?;
    map.get(&make_ledger_key(1), &budget)?;
    map.contains_key(&make_ledger_key(1), &budget)?;

    // Verify budget was consumed
    let final_cpu = budget
        .get_cpu_insns_consumed()
        .expect("budget should be available");
    assert!(
        final_cpu > initial_cpu,
        "Budget should be consumed for hash operations"
    );

    Ok(())
}

#[test]
fn test_metered_hash_map_iter_does_not_charge_budget() -> Result<(), HostError> {
    let budget = create_unlimited_budget();
    let mut map: MeteredHashMap<Rc<LedgerKey>, Option<(StorageLedgerEntryData, Option<u32>)>> =
        MeteredHashMap::new();

    for i in 0..10 {
        map.insert(make_ledger_key(i), make_cache_entry(i * 100), &budget)?;
    }

    // Record budget before iter
    let before_iter = budget
        .get_cpu_insns_consumed()
        .expect("budget should be available");

    // Call iter which should NOT charge (returns references only)
    let _entries: Vec<_> = map.iter().collect();

    // Verify budget was NOT consumed
    let after_iter = budget
        .get_cpu_insns_consumed()
        .expect("budget should be available");
    assert_eq!(
        after_iter, before_iter,
        "iter() should NOT charge for accessing entries (returns references)"
    );

    Ok(())
}

#[test]
fn test_metered_hash_map_budget_exhaustion() {
    // Create a budget with very limited resources
    let budget = create_limited_budget(100);
    let mut map: MeteredHashMap<Rc<LedgerKey>, Option<(StorageLedgerEntryData, Option<u32>)>> =
        MeteredHashMap::new();

    // Try to perform operations that should exhaust budget
    let mut ops_succeeded = 0;
    for i in 0..1000 {
        if map
            .insert(make_ledger_key(i), make_cache_entry(i * 100), &budget)
            .is_ok()
        {
            ops_succeeded += 1;
        } else {
            break;
        }
    }

    // Some operations should fail due to budget exhaustion
    assert!(
        ops_succeeded < 1000,
        "Budget should be exhausted before completing all operations"
    );
}

#[test]
fn test_metered_hash_map_hash_cost_type() -> Result<(), HostError> {
    let budget = create_unlimited_budget();
    let mut map: MeteredHashMap<Rc<LedgerKey>, Option<(StorageLedgerEntryData, Option<u32>)>> =
        MeteredHashMap::new();

    // Get initial count for the hash cost type
    let initial_count = budget
        .get_tracker(ContractCostType::ChaCha20DrawBytes)
        .unwrap()
        .iterations;

    // Perform operations that require hashing
    map.insert(make_ledger_key(1), make_cache_entry(100), &budget)?;
    map.get(&make_ledger_key(1), &budget)?;
    map.contains_key(&make_ledger_key(1), &budget)?;

    // Verify hash cost type was charged
    let final_count = budget
        .get_tracker(ContractCostType::ChaCha20DrawBytes)
        .unwrap()
        .iterations;
    assert!(
        final_count > initial_count,
        "ChaCha20DrawBytes should be charged for hash operations"
    );

    Ok(())
}
