use crate::{
    budget::Budget,
    host::metered_xdr::metered_write_xdr,
    xdr::{ContractCostType, WriteXdr},
    HostError,
};
use std::hash::{Hash, Hasher};

// We approximate the cost of Rust's default hasher (SIP-1-3) using ChaCha20DrawBytes,
// since both are of a similar order of magnitude. This cost type is used for:
// 1. Tracing operations charged against the shadow budget
// 2. MeteredHashMap operations for per-frame contract data caching
//
// This approximation may slightly overcharge, which is acceptable to prevent
// hash operations from becoming a DoS vector.
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
        buf.metered_hash(hasher, budget)
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

    /// Gets a mutable reference to a value in the map.
    pub fn get_mut<B: AsBudget>(
        &mut self,
        key: &K,
        budget: &B,
    ) -> Result<Option<&mut V>, HostError> {
        self.charge_hash(budget)?;
        self.charge_access(1, budget)?;
        Ok(self.map.get_mut(key))
    }

    /// Checks if the map contains a key.
    pub fn contains_key<B: AsBudget>(&self, key: &K, budget: &B) -> Result<bool, HostError> {
        self.charge_hash(budget)?;
        self.charge_access(1, budget)?;
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
    /// Charges for accessing all entries upfront.
    pub fn iter<B: AsBudget>(
        &self,
        budget: &B,
    ) -> Result<impl Iterator<Item = (&K, &V)>, HostError> {
        self.charge_access(self.map.len(), budget)?;
        Ok(self.map.iter())
    }

    /// Consumes the map and returns an iterator over owned entries.
    /// This is used for draining the cache at frame exit.
    /// Charges for accessing all entries upfront.
    pub fn into_iter<B: AsBudget>(
        self,
        budget: &B,
    ) -> Result<impl Iterator<Item = (K, V)>, HostError> {
        self.charge_access(self.map.len(), budget)?;
        Ok(self.map.into_iter())
    }

    /// Clones the map with metering.
    /// Charges for shallow copy of all entries plus substructure of keys/values.
    pub fn metered_clone<B: AsBudget>(&self, budget: &B) -> Result<Self, HostError> {
        self.charge_access(self.map.len(), budget)?;
        // Charge for substructure of each entry
        for (k, v) in self.map.iter() {
            k.charge_for_substructure(budget.as_budget())?;
            v.charge_for_substructure(budget.as_budget())?;
        }
        Ok(Self {
            map: self.map.clone(),
        })
    }

    /// Returns a mutable reference to an entry in the map, inserting a default
    /// value if the key is not present. Unlike `insert`, this avoids cloning
    /// the key when the entry already exists.
    ///
    /// The `default_fn` closure is only called (and the key is only cloned)
    /// if the key is not already in the map.
    pub fn get_or_insert_with<B, F>(
        &mut self,
        key: &K,
        budget: &B,
        default_fn: F,
    ) -> Result<&mut V, HostError>
    where
        B: AsBudget,
        F: FnOnce() -> Result<V, HostError>,
        K: Clone,
    {
        self.charge_hash(budget)?;
        self.charge_access(1, budget)?;

        // Check if key exists first to avoid unnecessary clone
        if self.map.contains_key(key) {
            // Key exists - get mutable reference without cloning key
            Ok(self.map.get_mut(key).expect("key just checked"))
        } else {
            // Key doesn't exist - clone key and insert
            let value = default_fn()?;
            Ok(self.map.entry(key.clone()).or_insert(value))
        }
    }

    /// Inserts or updates a value in the map. Unlike `insert`, this only
    /// clones the key when inserting a new entry.
    pub fn upsert<B: AsBudget>(&mut self, key: &K, value: V, budget: &B) -> Result<(), HostError>
    where
        K: Clone,
    {
        self.charge_hash(budget)?;
        self.charge_access(1, budget)?;

        // Check if key exists first to avoid unnecessary clone
        if let Some(v) = self.map.get_mut(key) {
            *v = value;
        } else {
            self.map.insert(key.clone(), value);
        }
        Ok(())
    }
}
