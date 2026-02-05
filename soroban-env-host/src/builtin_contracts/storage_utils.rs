use crate::{Host, HostError, StorageType, Val};

impl Host {
    /// Tries to get contract data, returning None if not found.
    /// This is more efficient than has+get as it avoids a redundant lookup.
    pub(crate) fn try_get_contract_data(
        &self,
        k: Val,
        t: StorageType,
    ) -> Result<Option<Val>, HostError> {
        match t {
            StorageType::Temporary | StorageType::Persistent => {
                self.try_get_contract_data_from_ledger(k, t)
            }
            StorageType::Instance => {
                self.with_instance_storage(|s| Ok(s.map.get(&k, self)?.copied()))
            }
        }
    }
}
