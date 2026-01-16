use crate::{
    budget::Budget,
    host::metered_xdr::metered_write_xdr,
    xdr::{ContractCostType, WriteXdr},
    HostError,
};
use std::hash::{Hash, Hasher};

// Technically we should be metering the cost of the hash function used, but
// this codepath is used only for charging the costs of tracing against the
// shadow budget, and we do not want to add a cost type to the protocol just
// for this purpose (it's not protocol-visible at all).
//
// In practice, Rust's default hasher is SIP-1-3 which is of a similar order
// of magnitude as a ChaCha20 round, so this is a reasonable approximation.
// It's also fine if we overcharge here, since again this is only used to
// ensure that if the hashing code is ever called _outside_ the shadow budget
// it's not a free operation / DoS vector.
const HASH_COST_TYPE: ContractCostType = ContractCostType::ChaCha20DrawBytes;

#[derive(Default)]
pub struct CountingHasher {
    count: usize,
    hasher: std::collections::hash_map::DefaultHasher,
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

pub(crate) trait MeteredHash {
    fn metered_hash(&self, hasher: &mut CountingHasher, budget: &Budget) -> Result<(), HostError>;
}

impl<T: Hash> MeteredHash for T {
    fn metered_hash(&self, hasher: &mut CountingHasher, budget: &Budget) -> Result<(), HostError> {
        self.hash(hasher);
        budget.charge(HASH_COST_TYPE, Some(hasher.count as u64))?;
        Ok(())
    }
}

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

pub(crate) trait MeteredHashXdr {
    fn metered_hash_xdr(
        &self,
        hasher: &mut CountingHasher,
        budget: &Budget,
    ) -> Result<(), HostError>;
}

impl<T: WriteXdr> MeteredHashXdr for T {
    fn metered_hash_xdr(
        &self,
        hasher: &mut CountingHasher,
        budget: &Budget,
    ) -> Result<(), HostError> {
        let mut buf = Vec::default();
        metered_write_xdr(budget, self, &mut buf)?;
        buf.metered_hash(hasher, budget)?;
        budget.charge(HASH_COST_TYPE, Some(hasher.count as u64))
    }
}

use std::collections::HashMap;

use crate::{
    budget::AsBudget,
    host::{declared_size::DeclaredSizeForMetering, metered_clone::MeteredClone},
};

/// A metered hash map that wraps `std::collections::HashMap` with budget charging.
/// Used for per-frame caching during contract execution where the immutable ordered
/// map would be too expensive due to copy-on-write semantics.
#[allow(dead_code)]
#[derive(Clone)]
pub struct MeteredHashMap<K, V> {
    pub(crate) map: HashMap<K, V>,
}

impl<K, V> Default for MeteredHashMap<K, V> {
    fn default() -> Self {
        Self {
            map: HashMap::new(),
        }
    }
}

impl<K, V> std::hash::Hash for MeteredHashMap<K, V>
where
    K: std::hash::Hash + Eq + Ord,
    V: std::hash::Hash,
{
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Sort keys to ensure deterministic hashing regardless of iteration order
        let mut entries: Vec<_> = self.map.iter().collect();
        entries.sort_by(|a, b| a.0.cmp(b.0));
        for (k, v) in entries {
            k.hash(state);
            v.hash(state);
        }
    }
}

#[allow(dead_code)]
impl<K, V> MeteredHashMap<K, V>
where
    K: Hash + Eq + DeclaredSizeForMetering + MeteredClone,
    V: DeclaredSizeForMetering + MeteredClone,
{
    const ENTRY_SIZE: u64 = K::DECLARED_SIZE + V::DECLARED_SIZE;

    /// Creates a new empty metered hash map.
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    /// Returns the number of entries in the map.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Returns true if the map is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Charges for hash computation based on key size.
    fn charge_hash<B: AsBudget>(&self, budget: &B) -> Result<(), HostError> {
        // Charge for computing the hash of the key
        budget
            .as_budget()
            .charge(HASH_COST_TYPE, Some(K::DECLARED_SIZE))
    }

    /// Charges for accessing/copying entries.
    fn charge_access<B: AsBudget>(&self, count: usize, budget: &B) -> Result<(), HostError> {
        budget.as_budget().charge(
            ContractCostType::MemCpy,
            Some(Self::ENTRY_SIZE.saturating_mul(count as u64)),
        )
    }

    /// Gets a reference to a value in the map.
    pub fn get<B: AsBudget>(&self, key: &K, budget: &B) -> Result<Option<&V>, HostError> {
        self.charge_hash(budget)?;
        self.charge_access(1, budget)?;
        Ok(self.map.get(key))
    }

    /// Checks if the map contains a key.
    pub fn contains_key<B: AsBudget>(&self, key: &K, budget: &B) -> Result<bool, HostError> {
        self.charge_hash(budget)?;
        Ok(self.map.contains_key(key))
    }

    /// Inserts a key-value pair into the map. Unlike MeteredOrdMap, this mutates
    /// in place rather than creating a new map.
    pub fn insert<B: AsBudget>(&mut self, key: K, value: V, budget: &B) -> Result<(), HostError> {
        self.charge_hash(budget)?;
        self.charge_access(1, budget)?;
        self.map.insert(key, value);
        Ok(())
    }

    /// Removes a key from the map.
    pub fn remove<B: AsBudget>(&mut self, key: &K, budget: &B) -> Result<Option<V>, HostError> {
        self.charge_hash(budget)?;
        self.charge_access(1, budget)?;
        Ok(self.map.remove(key))
    }

    /// Returns an iterator over the map entries.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.map.iter()
    }

    /// Clones the map with metering.
    pub fn metered_clone<B: AsBudget>(&self, budget: &B) -> Result<Self, HostError> {
        self.charge_access(self.map.len(), budget)?;
        Ok(Self {
            map: self.map.clone(),
        })
    }
}
