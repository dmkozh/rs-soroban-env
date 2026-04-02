use crate::{budget::Budget, xdr::ContractCostType, HostError};
use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
};

// We approximate the cost of Rust's default hasher (SIP-1-3) using ChaCha20DrawBytes,
// since both are of a similar order of magnitude. This cost type is used for:
// 1. Tracing operations charged against the shadow budget
// 2. MeteredHashMap operations for per-frame contract data caching
//
// This approximation may slightly overcharge, which is acceptable to prevent
// hash operations from becoming a DoS vector.
const HASH_COST_TYPE: ContractCostType = ContractCostType::ChaCha20DrawBytes;

#[derive(Default)]
pub(crate) struct CountingHasher {
    count: usize,
    hasher: std::collections::hash_map::DefaultHasher,
}

impl CountingHasher {
    pub(crate) fn count(&self) -> usize {
        self.count
    }
}

impl Hasher for CountingHasher {
    fn finish(&self) -> u64 {
        self.hasher.finish()
    }

    fn write(&mut self, bytes: &[u8]) {
        self.count = self.count.saturating_add(bytes.len());
        self.hasher.write(bytes);
    }
}

pub(crate) trait MeteredHash: Hash {
    fn metered_hash(&self, hasher: &mut CountingHasher, budget: &Budget) -> Result<(), HostError> {
        <Self as Hash>::hash(self, hasher);
        budget.charge(HASH_COST_TYPE, Some(hasher.count() as u64))?;
        Ok(())
    }
}

impl<T: Hash> MeteredHash for T {}

impl std::io::Write for CountingHasher {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.count = self.count.saturating_add(buf.len());
        self.hasher.write(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

use crate::{budget::AsBudget, host::declared_size::DeclaredSizeForMetering};

/// A metered hash map that wraps `std::collections::HashMap` with budget
/// charging.
///
/// This is minimalistic on purpose and only supports the operations needed by
/// the storage layer. Specifically, clones and key removal are not supported as
/// they are not needed. This can be extended in the future if necessary, though
/// keep in mind that this is implementation not going to be efficient for
/// representing persistent data structures.
pub(crate) struct MeteredHashMap<K, V> {
    map: HashMap<K, V>,
}

impl<K, V> Default for MeteredHashMap<K, V> {
    fn default() -> Self {
        Self {
            map: HashMap::new(),
        }
    }
}

/// Hash implementation is only necessary for tracing where we need to hash the
/// entire storage state deterministically.
impl<K, V> std::hash::Hash for MeteredHashMap<K, V>
where
    K: std::hash::Hash + Eq + Ord,
    V: std::hash::Hash,
{
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let mut entries: Vec<_> = self.map.iter().collect();
        entries.sort_by(|a, b| a.0.cmp(b.0));
        for (k, v) in entries {
            k.hash(state);
            v.hash(state);
        }
    }
}

impl<K, V> MeteredHashMap<K, V>
where
    K: Hash + Eq,
{
    /// Creates a new empty metered hash map.
    pub(crate) fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    // Checks if the map is empty. This is O(1) and not metered.
    // Allowing dead code here as it's used in some feature-gated cases only,
    // but it is useful in non-recording mode as well.
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Returns the number of entries in the map.
    /// This is O(1) and not metered.
    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }

    /// Returns an iterator over the map entries. This is a hash map, so the
    /// iteration order is not deterministic.
    /// Not metered so be careful when using this in recording mode.
    #[cfg(any(test, feature = "testutils", feature = "recording_mode"))]
    pub(crate) fn iter_non_metered(&self) -> impl Iterator<Item = (&K, &V)> {
        self.map.iter()
    }

    /// Consumes the map and returns an iterator over owned key-value pairs.
    /// Used by production code that consumes the map (during finalization).
    /// This is not metered and thus relies on the caller to use the results in
    /// metered operations.
    pub(crate) fn into_iter_non_metered(self) -> impl Iterator<Item = (K, V)> {
        self.map.into_iter()
    }

    /// Returns a mutable iterator over the map entries.
    /// This function is not metered as it only returns references. Make sure
    /// that the iteration is somehow bounded otherwise (e.g. every entry
    /// access is metered, or the amount of iterations has a strict bound).
    pub(crate) fn iter_mut_unmetered(&mut self) -> impl Iterator<Item = (&K, &mut V)> {
        self.map.iter_mut()
    }

    /// Removes a key from the map.
    /// Test-only method for manipulating storage in tests, hence unmetered.
    #[cfg(test)]
    pub(crate) fn remove(&mut self, key: &K) -> Option<V> {
        self.map.remove(key)
    }
}

impl<K, V> MeteredHashMap<K, V>
where
    K: Hash + Eq + DeclaredSizeForMetering,
    V: DeclaredSizeForMetering,
{
    const ENTRY_SIZE: u64 = K::DECLARED_SIZE + V::DECLARED_SIZE;

    fn charge_hash(budget: &Budget) -> Result<(), HostError> {
        budget.charge(HASH_COST_TYPE, Some(K::DECLARED_SIZE_FOR_HASH))?;
        budget.charge(ContractCostType::MemCmp, Some(K::DECLARED_SIZE_FOR_HASH))
    }

    /// Gets a reference to a value in the map.
    pub(crate) fn get<B: AsBudget>(&self, key: &K, budget: &B) -> Result<Option<&V>, HostError> {
        Self::charge_hash(budget.as_budget())?;
        Ok(self.map.get(key))
    }

    /// Returns a mutable reference to a value in the map.
    pub(crate) fn get_mut<B: AsBudget>(
        &mut self,
        key: &K,
        budget: &B,
    ) -> Result<Option<&mut V>, HostError> {
        Self::charge_hash(budget.as_budget())?;
        Ok(self.map.get_mut(key))
    }

    /// Inserts a key-value pair into the map. Unlike MeteredOrdMap, this mutates
    /// in place rather than creating a new map.
    /// Charges for hash lookup and data movement.
    pub(crate) fn insert<B: AsBudget>(
        &mut self,
        key: K,
        value: V,
        budget: &B,
    ) -> Result<(), HostError> {
        Self::charge_hash(budget.as_budget())?;
        budget
            .as_budget()
            .charge(ContractCostType::MemCpy, Some(Self::ENTRY_SIZE))?;
        self.map.insert(key, value);
        Ok(())
    }

    /// Inserts a key-value pair and returns a mutable reference to the value.
    /// This avoids a separate get_mut call after insert.
    /// Charges for hash lookup and data movement.
    #[cfg(any(test, feature = "recording_mode"))]
    pub(crate) fn insert_and_get_mut<B: AsBudget>(
        &mut self,
        key: K,
        value: V,
        budget: &B,
    ) -> Result<&mut V, HostError> {
        Self::charge_hash(budget.as_budget())?;
        budget
            .as_budget()
            .charge(ContractCostType::MemCpy, Some(Self::ENTRY_SIZE))?;
        Ok(self.map.entry(key).or_insert(value))
    }
}
