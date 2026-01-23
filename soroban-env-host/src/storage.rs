//! This module contains the [Storage] type and its supporting types, which
//! provide the [Host](crate::Host) with access to durable ledger entries.
//!
//! For more details, see the [Env](crate::Env) data access functions:
//!   - [Env::has_contract_data](crate::Env::has_contract_data)
//!   - [Env::get_contract_data](crate::Env::get_contract_data)
//!   - [Env::put_contract_data](crate::Env::put_contract_data)
//!   - [Env::del_contract_data](crate::Env::del_contract_data)

use std::cell::RefCell;
use std::rc::Rc;

use crate::budget::AsBudget;
use crate::host::metered_clone::{MeteredClone, MeteredIterator};
use crate::host::metered_hash::MeteredHashMap;
use crate::{
    budget::Budget,
    host::metered_map::MeteredOrdMap,
    ledger_info::get_key_durability,
    xdr::{
        ContractDataDurability, LedgerEntry, LedgerKey, ScContractInstance, ScErrorCode,
        ScErrorType, ScVal,
    },
    Env, Error, Host, HostError, Val,
};

pub type FootprintMap = MeteredOrdMap<Rc<LedgerKey>, AccessType, Budget>;
/// Entry with optional live_until ledger for snapshot source compatibility.
/// Used by the SnapshotSource trait at the external interface boundary.
pub type EntryWithLiveUntil = (Rc<LedgerEntry>, Option<u32>);
/// Storage map type using CachedEntry for unified format with per-frame caches.
/// This enables zero-copy frame-to-frame cache propagation.
pub type StorageMap = MeteredHashMap<Rc<LedgerKey>, Option<CachedEntry>>;
/// Map from LedgerKey to optional LedgerEntry with live_until.
/// Used to track initial and final ledger state for computing ledger changes.
/// This avoids the need for Val<->ScVal conversions in get_ledger_changes.
pub type LedgerEntryMap = MeteredHashMap<Rc<LedgerKey>, Option<EntryWithLiveUntil>>;

/// Unified cache entry for all ledger entry types.
/// 
/// This enum provides a uniform representation for cached ledger entries:
/// - `ContractData`: Stores the value as `Val` (host value) with its TTL. The `Val` form
///   avoids repeated ScVal<->Val conversions on each read/write from contract code.
/// - `Entry`: Stores other entry types (ContractCode, Account, Trustline) as a RefCell
///   for in-place mutation, with optional live_until for ContractCode entries.
/// 
/// `None` in the containing `Option<CachedEntry>` represents a deleted or non-existent entry.
#[derive(Clone)]
pub enum CachedEntry {
    /// Contract data entry: (value, live_until_ledger)
    ContractData(Val, u32),
    /// Other entry types: (entry, optional live_until for ContractCode)
    /// Uses Rc<RefCell<_>> for in-place mutation and fast Rc cloning between maps.
    Entry(Rc<RefCell<LedgerEntry>>, Option<u32>),
}

impl CachedEntry {
    /// Returns the live_until ledger for this entry.
    pub fn live_until(&self) -> Option<u32> {
        match self {
            CachedEntry::ContractData(_, live_until) => Some(*live_until),
            CachedEntry::Entry(_, live_until) => *live_until,
        }
    }

    /// Returns a reference to the entry if this is an Entry variant.
    /// Returns None for ContractData variant.
    pub fn get_entry(&self) -> Option<Rc<RefCell<LedgerEntry>>> {
        match self {
            CachedEntry::ContractData(_, _) => None,
            CachedEntry::Entry(entry, _) => Some(Rc::clone(entry)),
        }
    }

    /// Reconstructs a LedgerEntry from this CachedEntry given the key.
    /// For Entry variant, clones the inner entry.
    /// For ContractData variant, builds a new LedgerEntry from the key and value.
    pub fn to_ledger_entry(
        &self,
        key: &LedgerKey,
        host: &Host,
    ) -> Result<LedgerEntry, HostError> {
        use crate::xdr::{ContractDataEntry, LedgerEntryData, LedgerEntryExt, LedgerKeyContractData};
        match self {
            CachedEntry::Entry(entry, _) => Ok(entry.borrow().clone()),
            CachedEntry::ContractData(val, _) => {
                // Reconstruct the LedgerEntry from key and value
                if let LedgerKey::ContractData(LedgerKeyContractData {
                    contract,
                    key: data_key,
                    durability,
                }) = key
                {
                    let sc_val = host.from_host_val(*val)?;
                    Ok(LedgerEntry {
                        last_modified_ledger_seq: 0,
                        data: LedgerEntryData::ContractData(ContractDataEntry {
                            ext: crate::xdr::ExtensionPoint::V0,
                            contract: contract.clone(),
                            key: data_key.clone(),
                            durability: *durability,
                            val: sc_val,
                        }),
                        ext: LedgerEntryExt::V0,
                    })
                } else {
                    Err(host.err(
                        ScErrorType::Storage,
                        ScErrorCode::InternalError,
                        "ContractData cached entry has non-ContractData key",
                        &[],
                    ))
                }
            }
        }
    }

    /// Creates a CachedEntry from an EntryWithLiveUntil.
    /// For ContractData entries, converts the ScVal to Val for efficient access.
    /// For other entry types (ContractCode, Account, Trustline), stores as Entry.
    pub fn from_entry_with_live_until(
        entry: &Rc<LedgerEntry>,
        live_until: Option<u32>,
        host: &Host,
    ) -> Result<Self, HostError> {
        use crate::xdr::LedgerEntryData;
        match &entry.data {
            LedgerEntryData::ContractData(contract_data) => {
                // ContractData entries must have a live_until ledger
                let live_until_ledger = live_until.ok_or_else(|| {
                    HostError::from(Error::from_type_and_code(
                        ScErrorType::Storage,
                        ScErrorCode::InternalError,
                    ))
                })?;
                // Convert ScVal to Val for efficient access
                let val = host.to_valid_host_val(&contract_data.val)?;
                Ok(CachedEntry::ContractData(val, live_until_ledger))
            }
            _ => {
                // Other entry types are stored as Entry variant
                Ok(CachedEntry::Entry(
                    Rc::new(RefCell::new((*entry.as_ref()).clone())),
                    live_until,
                ))
            }
        }
    }
}

impl std::hash::Hash for CachedEntry {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
        match self {
            CachedEntry::ContractData(val, live_until) => {
                val.get_payload().hash(state);
                live_until.hash(state);
            }
            CachedEntry::Entry(entry, live_until) => {
                // Hash the Rc pointer address for determinism
                Rc::as_ptr(entry).hash(state);
                live_until.hash(state);
            }
        }
    }
}

/// Unified storage cache type used for both global storage and per-frame caches.
/// Maps ledger keys to optional cached entries, where `None` represents deleted/non-existent.
pub type StorageCache = MeteredHashMap<Rc<LedgerKey>, Option<CachedEntry>>;

/// The in-memory instance storage of the current running contract. Initially
/// contains entries from the `ScMap` of the corresponding `ScContractInstance`
/// contract data entry.
#[derive(Clone, Hash)]
pub(crate) struct InstanceStorageMap {
    pub(crate) map: MeteredOrdMap<Val, Val, Host>,
    pub(crate) is_modified: bool,
}

impl InstanceStorageMap {
    pub(crate) fn from_map(map: Vec<(Val, Val)>, host: &Host) -> Result<Self, HostError> {
        Ok(Self {
            map: MeteredOrdMap::from_map(map, host)?,
            is_modified: false,
        })
    }

    pub(crate) fn from_instance_xdr(
        instance: &ScContractInstance,
        host: &Host,
    ) -> Result<Self, HostError> {
        Self::from_map(
            instance.storage.as_ref().map_or_else(
                || Ok(vec![]),
                |m| {
                    m.iter()
                        .map(|i| {
                            Ok((
                                host.to_valid_host_val(&i.key)?,
                                host.to_valid_host_val(&i.val)?,
                            ))
                        })
                        .metered_collect::<Result<Vec<(Val, Val)>, HostError>>(host)?
                },
            )?,
            host,
        )
    }
}

/// A helper type used by [Footprint] to designate which ways
/// a given [LedgerKey] is accessed, or is allowed to be accessed,
/// in a given transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum AccessType {
    /// When in [FootprintMode::Recording], indicates that the [LedgerKey] is only read.
    /// When in [FootprintMode::Enforcing], indicates that the [LedgerKey] is only _allowed_ to be read.
    ReadOnly,
    /// When in [FootprintMode::Recording], indicates that the [LedgerKey] is written (and also possibly read)
    /// When in [FootprintMode::Enforcing], indicates that the [LedgerKey] is _allowed_ to be written (and also allowed to be read).
    ReadWrite,
}
/// A helper type used by [FootprintMode::Recording] to provide access
/// to a stable read-snapshot of a ledger.
/// The snapshot is expected to have access to all the persistent entries,
/// including the archived entries. It also is allowed (but doesn't have to) to
/// return expired temporary entries.
pub trait SnapshotSource {
    /// Returns the ledger entry for the key and its live_until ledger if entry
    /// exists, or `None` otherwise.
    fn get(&self, key: &Rc<LedgerKey>) -> Result<Option<EntryWithLiveUntil>, HostError>;
}

/// A wrapper around LedgerEntryMap that implements SnapshotSource.
/// Used for providing init/final ledger entries to get_ledger_changes.
pub struct LedgerEntryMapSnapshotSource<'a> {
    pub budget: &'a Budget,
    pub map: &'a LedgerEntryMap,
}

impl SnapshotSource for LedgerEntryMapSnapshotSource<'_> {
    fn get(&self, key: &Rc<LedgerKey>) -> Result<Option<EntryWithLiveUntil>, HostError> {
        match self.map.get(key, self.budget)? {
            Some(Some(entry_with_live_until)) => Ok(Some(entry_with_live_until.clone())),
            Some(None) | None => Ok(None),
        }
    }
}

/// Describes the total set of [LedgerKey]s that a given transaction
/// will access, as well as the [AccessType] governing each key.
///
/// A [Footprint] must be provided in order to run a transaction that
/// accesses any [LedgerKey]s in [FootprintMode::Enforcing]. If a
/// transaction has an unknown [Footprint] it can be calculated by
/// running a "preflight" execution in [FootprintMode::Recording],
/// against a suitably fresh [SnapshotSource].
// Notes on metering: covered by the underneath `MeteredOrdMap`.
#[derive(Clone, Default, Hash)]
pub struct Footprint(pub FootprintMap);

impl Footprint {
    #[cfg(any(test, feature = "recording_mode"))]
    pub(crate) fn record_access(
        &mut self,
        key: &Rc<LedgerKey>,
        ty: AccessType,
        budget: &Budget,
    ) -> Result<(), HostError> {
        if let Some(existing) = self.0.get::<Rc<LedgerKey>>(key, budget)? {
            match (existing, ty) {
                (AccessType::ReadOnly, AccessType::ReadOnly) => Ok(()),
                (AccessType::ReadOnly, AccessType::ReadWrite) => {
                    // The only interesting case is an upgrade
                    // from previously-read-only to read-write.
                    self.0 = self.0.insert(Rc::clone(key), ty, budget)?;
                    Ok(())
                }
                (AccessType::ReadWrite, AccessType::ReadOnly) => Ok(()),
                (AccessType::ReadWrite, AccessType::ReadWrite) => Ok(()),
            }
        } else {
            self.0 = self.0.insert(Rc::clone(key), ty, budget)?;
            Ok(())
        }
    }

    pub(crate) fn enforce_access(
        &mut self,
        key: &Rc<LedgerKey>,
        ty: AccessType,
        budget: &Budget,
    ) -> Result<(), HostError> {
        // `ExceededLimit` is not the most precise term here, but footprint has
        // to be externally supplied in a similar fashion to budget and it's
        // also representing an execution resource limit (number of ledger
        // entries to access), so it might be considered 'exceeded'.
        // This also helps distinguish access errors from the values simply
        // being  missing from storage (but with a valid footprint).
        if let Some(existing) = self.0.get::<Rc<LedgerKey>>(key, budget)? {
            match (existing, ty) {
                (AccessType::ReadOnly, AccessType::ReadOnly) => Ok(()),
                (AccessType::ReadOnly, AccessType::ReadWrite) => {
                    Err((ScErrorType::Storage, ScErrorCode::ExceededLimit).into())
                }
                (AccessType::ReadWrite, AccessType::ReadOnly) => Ok(()),
                (AccessType::ReadWrite, AccessType::ReadWrite) => Ok(()),
            }
        } else {
            Err((ScErrorType::Storage, ScErrorCode::ExceededLimit).into())
        }
    }
}

#[derive(Clone, Default)]
pub(crate) enum FootprintMode {
    #[cfg(any(test, feature = "recording_mode"))]
    Recording(Rc<dyn SnapshotSource>),
    #[default]
    Enforcing,
}

/// A special-purpose map from [LedgerKey]s to [LedgerEntry]s. Represents a
/// transactional batch of contract IO from and to durable storage, while
/// partitioning that IO between concurrently executing groups of contracts
/// through the use of IO [Footprint]s.
///
/// Specifically: access to each [LedgerKey] is mediated by the [Footprint],
/// which may be in either [FootprintMode::Recording] or
/// [FootprintMode::Enforcing] mode.
///
/// [FootprintMode::Recording] mode is used to calculate [Footprint]s during
/// "preflight" execution of a contract. Once calculated, a recorded [Footprint]
/// can be provided to "real" execution, which always runs in
/// [FootprintMode::Enforcing] mode and enforces partitioned access.
#[derive(Clone, Default)]
pub struct Storage {
    pub footprint: Footprint,
    pub(crate) mode: FootprintMode,
    pub map: StorageMap,
}

// Notes on metering: all storage operations: `put`, `get`, `del`, `has` are
// covered by the underlying [MeteredOrdMap] and the [Footprint]'s own map.
impl Storage {
    /// Only a subset of Stellar's XDR ledger key or entry types are supported
    /// by Soroban: accounts, trustlines, contract code and data. The rest are
    /// never used by stellar-core when interacting with the Soroban host, nor
    /// does the Soroban host ever generate any. Therefore the storage system
    /// will reject them with [ScErrorCode::InternalError] if they ever occur.
    pub fn check_supported_ledger_entry_type(le: &LedgerEntry) -> Result<(), HostError> {
        use crate::xdr::LedgerEntryData::*;
        match le.data {
            Account(_) | Trustline(_) | ContractData(_) | ContractCode(_) => Ok(()),
            Offer(_) | Data(_) | ClaimableBalance(_) | LiquidityPool(_) | ConfigSetting(_)
            | Ttl(_) => Err((ScErrorType::Storage, ScErrorCode::InternalError).into()),
        }
    }

    /// Only a subset of Stellar's XDR ledger key or entry types are supported
    /// by Soroban: accounts, trustlines, contract code and data. The rest are
    /// never used by stellar-core when interacting with the Soroban host, nor
    /// does the Soroban host ever generate any. Therefore the storage system
    /// will reject them with [ScErrorCode::InternalError] if they ever occur.
    pub fn check_supported_ledger_key_type(lk: &LedgerKey) -> Result<(), HostError> {
        use LedgerKey::*;
        match lk {
            Account(_) | Trustline(_) | ContractData(_) | ContractCode(_) => Ok(()),
            Offer(_) | Data(_) | ClaimableBalance(_) | LiquidityPool(_) | ConfigSetting(_)
            | Ttl(_) => Err((ScErrorType::Storage, ScErrorCode::InternalError).into()),
        }
    }

    /// Constructs a new [Storage] in [FootprintMode::Enforcing] using a
    /// given [Footprint] and a storage map populated with all the keys
    /// listed in the [Footprint].
    pub fn with_enforcing_footprint_and_map(footprint: Footprint, map: StorageMap) -> Self {
        Self {
            mode: FootprintMode::Enforcing,
            footprint,
            map,
        }
    }

    /// Constructs a new [Storage] in [FootprintMode::Recording] using a
    /// given [SnapshotSource].
    #[cfg(any(test, feature = "recording_mode"))]
    pub fn with_recording_footprint(src: Rc<dyn SnapshotSource>) -> Self {
        Self {
            mode: FootprintMode::Recording(src),
            footprint: Footprint::default(),
            map: Default::default(),
        }
    }

    // Helper function the next 3 `get`-variants funnel into.
    // Returns the raw CachedEntry from the map.
    fn try_get_cached_entry(
        &mut self,
        key: &Rc<LedgerKey>,
        host: &Host,
    ) -> Result<Option<CachedEntry>, HostError> {
        let _span = tracy_span!("storage get");
        Self::check_supported_ledger_key_type(key)?;
        self.prepare_read_only_access(key, host)?;
        match self.map.get(key, host.budget_ref())? {
            // Key has to be in the storage map at this point due to
            // `prepare_read_only_access`.
            None => Err((ScErrorType::Storage, ScErrorCode::InternalError).into()),
            Some(entry_option) => Ok(entry_option.clone()),
        }
    }

    /// Internal helper to get a CachedEntry with error decoration.
    pub(crate) fn try_get_cached(
        &mut self,
        key: &Rc<LedgerKey>,
        host: &Host,
        key_val: Option<Val>,
    ) -> Result<Option<CachedEntry>, HostError> {
        self.try_get_cached_entry(key, host)
            .map_err(|e| host.decorate_storage_error(e, key.as_ref(), key_val))
    }

    /// Returns the cached entry, or an error if not found.
    pub(crate) fn get_cached(
        &mut self,
        key: &Rc<LedgerKey>,
        host: &Host,
        key_val: Option<Val>,
    ) -> Result<CachedEntry, HostError> {
        self.try_get_cached(key, host, key_val)?
            .ok_or_else(|| (ScErrorType::Storage, ScErrorCode::MissingValue).into())
            .map_err(|e| host.decorate_storage_error(e, key.as_ref(), key_val))
    }

    /// Returns the Rc<RefCell<LedgerEntry>> for an entry, allowing direct
    /// in-place modification. Only works for entries stored as CachedEntry::Entry.
    /// Returns None if the key is not found or if it's a ContractData entry.
    /// Returns an error if the entry was deleted.
    pub(crate) fn get_entry_rc(
        &mut self,
        key: &Rc<LedgerKey>,
        host: &Host,
        key_val: Option<Val>,
    ) -> Result<(Rc<RefCell<LedgerEntry>>, Option<u32>), HostError> {
        let cached = self.try_get_cached(key, host, key_val)?
            .ok_or_else(|| (ScErrorType::Storage, ScErrorCode::MissingValue).into())
            .map_err(|e: HostError| host.decorate_storage_error(e, key.as_ref(), key_val))?;

        match cached {
            CachedEntry::Entry(entry_rc, live_until) => Ok((entry_rc, live_until)),
            CachedEntry::ContractData(_, _) => Err(host.err(
                ScErrorType::Storage,
                ScErrorCode::InternalError,
                "get_entry_rc called on ContractData entry",
                &[],
            )),
        }
    }

    // Helper to convert CachedEntry to EntryWithLiveUntil for legacy interface.
    // This requires materializing ContractData entries back to LedgerEntry.
    fn cached_entry_to_entry_with_live_until(
        &self,
        cached: &CachedEntry,
        key: &Rc<LedgerKey>,
        host: &Host,
    ) -> Result<EntryWithLiveUntil, HostError> {
        match cached {
            CachedEntry::ContractData(val, live_until) => {
                // Convert Val back to ScVal and build LedgerEntry
                let sc_val = host.from_host_val(*val)?;
                let (contract, key_scval, durability) = match key.as_ref() {
                    LedgerKey::ContractData(data) => (
                        data.contract.metered_clone(host)?,
                        data.key.metered_clone(host)?,
                        data.durability,
                    ),
                    _ => {
                        return Err(host.err(
                            ScErrorType::Storage,
                            ScErrorCode::InternalError,
                            "expected ContractData ledger key",
                            &[],
                        ));
                    }
                };
                let entry = LedgerEntry {
                    last_modified_ledger_seq: 0,
                    data: crate::xdr::LedgerEntryData::ContractData(
                        crate::xdr::ContractDataEntry {
                            contract,
                            key: key_scval,
                            val: sc_val,
                            durability,
                            ext: crate::xdr::ExtensionPoint::V0,
                        },
                    ),
                    ext: crate::xdr::LedgerEntryExt::V0,
                };
                Ok((Rc::new(entry), Some(*live_until)))
            }
            CachedEntry::Entry(entry_rc, live_until) => {
                // Clone the entry from the RefCell
                let entry = Rc::new(entry_rc.borrow().clone());
                Ok((entry, *live_until))
            }
        }
    }

    // Legacy helper for backward compatibility during refactor.
    fn try_get_full_helper(
        &mut self,
        key: &Rc<LedgerKey>,
        host: &Host,
    ) -> Result<Option<EntryWithLiveUntil>, HostError> {
        let cached = self.try_get_cached_entry(key, host)?;
        match cached {
            Some(entry) => {
                let result = self.cached_entry_to_entry_with_live_until(&entry, key, host)?;
                Ok(Some(result))
            }
            None => Ok(None),
        }
    }

    pub(crate) fn try_get_full(
        &mut self,
        key: &Rc<LedgerKey>,
        host: &Host,
        key_val: Option<Val>,
    ) -> Result<Option<EntryWithLiveUntil>, HostError> {
        let res = self
            .try_get_full_helper(key, host)
            .map_err(|e| host.decorate_storage_error(e, key.as_ref(), key_val))?;
        Ok(res)
    }

    pub(crate) fn get(
        &mut self,
        key: &Rc<LedgerKey>,
        host: &Host,
        key_val: Option<Val>,
    ) -> Result<Rc<LedgerEntry>, HostError> {
        self.try_get_full(key, host, key_val)?
            .ok_or_else(|| (ScErrorType::Storage, ScErrorCode::MissingValue).into())
            .map(|e| e.0)
            .map_err(|e| host.decorate_storage_error(e, key.as_ref(), key_val))
    }

    // Like `get`, but distinguishes between missing values (return `Ok(None)`)
    // and out-of-footprint values or errors (`Err(...)`).
    #[allow(dead_code)]
    pub(crate) fn try_get(
        &mut self,
        key: &Rc<LedgerKey>,
        host: &Host,
        key_val: Option<Val>,
    ) -> Result<Option<Rc<LedgerEntry>>, HostError> {
        self.try_get_full(key, host, key_val)
            .map(|ok| ok.map(|pair| pair.0))
    }

    /// Attempts to retrieve the [LedgerEntry] associated with a given
    /// [LedgerKey] and its live until ledger (if applicable) in the [Storage],
    /// returning an error if the key is not found.
    ///
    /// Live until ledgers only exist for `ContractData` and `ContractCode`
    /// ledger entries and are `None` for all the other entry kinds.
    ///
    /// In [FootprintMode::Recording] mode, records the read [LedgerKey] in the
    /// [Footprint] as [AccessType::ReadOnly] (unless already recorded as
    /// [AccessType::ReadWrite]) and reads through to the underlying
    /// [SnapshotSource], if the [LedgerKey] has not yet been loaded.
    ///
    /// In [FootprintMode::Enforcing] mode, succeeds only if the read
    /// [LedgerKey] has been declared in the [Footprint].
    pub(crate) fn get_with_live_until_ledger(
        &mut self,
        key: &Rc<LedgerKey>,
        host: &Host,
        key_val: Option<Val>,
    ) -> Result<EntryWithLiveUntil, HostError> {
        self.try_get_full(key, host, key_val)
            .and_then(|maybe_entry| {
                maybe_entry.ok_or_else(|| (ScErrorType::Storage, ScErrorCode::MissingValue).into())
            })
            .map_err(|e| host.decorate_storage_error(e, key.as_ref(), key_val))
    }

    /// Records or enforces a write access for the given key without actually
    /// modifying the storage map. This is used by the data cache to handle
    /// footprint tracking when writes are deferred.
    #[allow(dead_code)]
    pub(crate) fn record_write_access(
        &mut self,
        key: &Rc<LedgerKey>,
        host: &Host,
        key_val: Option<Val>,
    ) -> Result<(), HostError> {
        Self::check_supported_ledger_key_type(key)?;
        #[cfg(any(test, feature = "recording_mode"))]
        self.handle_maybe_expired_entry(&key, host)?;

        let ty = AccessType::ReadWrite;
        match &self.mode {
            #[cfg(any(test, feature = "recording_mode"))]
            FootprintMode::Recording(_) => {
                self.footprint.record_access(key, ty, host.budget_ref())?;
            }
            FootprintMode::Enforcing => {
                self.footprint
                    .enforce_access(key, ty, host.budget_ref())
                    .map_err(|e| host.decorate_storage_error(e, key.as_ref(), key_val))?;
            }
        };
        Ok(())
    }

    // Helper function for putting CachedEntry directly into the map.
    fn put_cached_entry_helper(
        &mut self,
        key: &Rc<LedgerKey>,
        val: Option<CachedEntry>,
        host: &Host,
    ) -> Result<(), HostError> {
        Self::check_supported_ledger_key_type(key)?;
        #[cfg(any(test, feature = "recording_mode"))]
        self.handle_maybe_expired_entry(&key, host)?;

        let ty = AccessType::ReadWrite;
        match &self.mode {
            #[cfg(any(test, feature = "recording_mode"))]
            FootprintMode::Recording(_) => {
                self.footprint.record_access(key, ty, host.budget_ref())?;
            }
            FootprintMode::Enforcing => {
                self.footprint.enforce_access(key, ty, host.budget_ref())?;
            }
        };
        self.map.insert(Rc::clone(key), val, host.budget_ref())?;
        Ok(())
    }

    /// Puts a CachedEntry directly into the storage map.
    pub(crate) fn put_cached(
        &mut self,
        key: &Rc<LedgerKey>,
        val: Option<CachedEntry>,
        host: &Host,
        key_val: Option<Val>,
    ) -> Result<(), HostError> {
        self.put_cached_entry_helper(key, val, host)
            .map_err(|e| host.decorate_storage_error(e, key.as_ref(), key_val))
    }

    // Legacy helper that converts EntryWithLiveUntil to CachedEntry.
    fn put_opt_helper(
        &mut self,
        key: &Rc<LedgerKey>,
        val: Option<EntryWithLiveUntil>,
        host: &Host,
    ) -> Result<(), HostError> {
        let cached = match val {
            Some((entry, live_until)) => {
                Self::check_supported_ledger_entry_type(&entry)?;
                Some(CachedEntry::from_entry_with_live_until(&entry, live_until, host)?)
            }
            None => None,
        };
        self.put_cached_entry_helper(key, cached, host)
    }

    fn put_opt(
        &mut self,
        key: &Rc<LedgerKey>,
        val: Option<EntryWithLiveUntil>,
        host: &Host,
        key_val: Option<Val>,
    ) -> Result<(), HostError> {
        self.put_opt_helper(key, val, host)
            .map_err(|e| host.decorate_storage_error(e, key.as_ref(), key_val))
    }

    /// Attempts to write to the [LedgerEntry] associated with a given
    /// [LedgerKey] in the [Storage].
    ///
    /// In [FootprintMode::Recording] mode, records the written [LedgerKey] in
    /// the [Footprint] as [AccessType::ReadWrite].
    ///
    /// In [FootprintMode::Enforcing] mode, succeeds only if the written
    /// [LedgerKey] has been declared in the [Footprint] as
    /// [AccessType::ReadWrite].
    pub(crate) fn put(
        &mut self,
        key: &Rc<LedgerKey>,
        val: &Rc<LedgerEntry>,
        live_until_ledger: Option<u32>,
        host: &Host,
        key_val: Option<Val>,
    ) -> Result<(), HostError> {
        let _span = tracy_span!("storage put");
        self.put_opt(key, Some((val.clone(), live_until_ledger)), host, key_val)
    }

    /// Attempts to delete the [LedgerEntry] associated with a given [LedgerKey]
    /// in the [Storage].
    ///
    /// In [FootprintMode::Recording] mode, records the deleted [LedgerKey] in
    /// the [Footprint] as [AccessType::ReadWrite].
    ///
    /// In [FootprintMode::Enforcing] mode, succeeds only if the deleted
    /// [LedgerKey] has been declared in the [Footprint] as
    /// [AccessType::ReadWrite].
    pub(crate) fn del(
        &mut self,
        key: &Rc<LedgerKey>,
        host: &Host,
        key_val: Option<Val>,
    ) -> Result<(), HostError> {
        let _span = tracy_span!("storage del");
        self.put_opt(key, None, host, key_val)
            .map_err(|e| host.decorate_storage_error(e, key.as_ref(), key_val))
    }

    /// Attempts to determine the presence of a [LedgerEntry] associated with a
    /// given [LedgerKey] in the [Storage], returning `Ok(true)` if an entry
    /// with the key exists and `Ok(false)` if it does not.
    ///
    /// In [FootprintMode::Recording] mode, records the access and reads-through
    /// to the underlying [SnapshotSource].
    ///
    /// In [FootprintMode::Enforcing] mode, succeeds only if the access has been
    /// declared in the [Footprint].
    pub(crate) fn has(
        &mut self,
        key: &Rc<LedgerKey>,
        host: &Host,
        key_val: Option<Val>,
    ) -> Result<bool, HostError> {
        let _span = tracy_span!("storage has");
        Ok(self.try_get_full(key, host, key_val)?.is_some())
    }

    /// Extends `key` to live `extend_to` ledgers from now (not counting the
    /// current ledger) if the current `live_until_ledger_seq` for the entry is
    /// `threshold` ledgers or less away from the current ledger.
    ///
    /// If attempting to extend an entry past `Host::max_live_until_ledger()`
    /// - if the entry is `Persistent`, the entries's new
    ///   `live_until_ledger_seq` is clamped to it.
    /// - if the entry is `Temporary`, returns error.
    ///
    /// This operation is only defined within a host as it relies on ledger
    /// state.
    ///
    /// This operation does not modify any ledger entries, but does change the
    /// internal storage
    pub(crate) fn extend_ttl(
        &mut self,
        host: &Host,
        key: Rc<LedgerKey>,
        threshold: u32,
        extend_to: u32,
        key_val: Option<Val>,
    ) -> Result<(), HostError> {
        let _span = tracy_span!("extend key");
        Self::check_supported_ledger_key_type(&key)?;

        if threshold > extend_to {
            return Err(host.err(
                ScErrorType::Storage,
                ScErrorCode::InvalidInput,
                "threshold must be <= extend_to",
                &[threshold.into(), extend_to.into()],
            ));
        }
        #[cfg(any(test, feature = "recording_mode"))]
        self.handle_maybe_expired_entry(&key, host)?;

        // Extending deleted/non-existing/out-of-footprint entries will result in
        // an error.
        let (_entry, old_live_until) = self.get_with_live_until_ledger(&key, &host, key_val)?;
        let old_live_until = old_live_until.ok_or_else(|| {
            host.err(
                ScErrorType::Storage,
                ScErrorCode::InternalError,
                "trying to extend invalid entry",
                &[],
            )
        })?;

        let ledger_seq: u32 = host.get_ledger_sequence()?.into();
        if old_live_until < ledger_seq {
            return Err(host.err(
                ScErrorType::Storage,
                ScErrorCode::InternalError,
                "accessing no-longer-live entry",
                &[old_live_until.into(), ledger_seq.into()],
            ));
        }

        let mut new_live_until = host.with_ledger_info(|li| {
            li.sequence_number.checked_add(extend_to).ok_or_else(|| {
                // overflowing here means a misconfiguration of the network (the
                // ttl is too large), in which case we immediately flag it as an
                // unrecoverable `InternalError`, even though the source is
                // external to the host.
                HostError::from(Error::from_type_and_code(
                    ScErrorType::Context,
                    ScErrorCode::InternalError,
                ))
            })
        })?;

        if new_live_until > host.max_live_until_ledger()? {
            if let Some(durability) = get_key_durability(&key) {
                if matches!(durability, ContractDataDurability::Persistent) {
                    new_live_until = host.max_live_until_ledger()?;
                } else {
                    //  for `Temporary` entries TTL has to be exact - most of
                    //  the time entry has to live until the exact specified
                    //  ledger, or else something bad would happen (e.g. nonce
                    //  expiring before the corresponding signature, thus
                    //  allowing replay and double spend).
                    return Err(host.err(
                        ScErrorType::Storage,
                        ScErrorCode::InvalidAction,
                        "trying to extend past max live_until ledger",
                        &[new_live_until.into()],
                    ));
                }
            } else {
                return Err(host.err(
                    ScErrorType::Storage,
                    ScErrorCode::InternalError,
                    "durability is missing",
                    &[],
                ));
            }
        }

        if new_live_until > old_live_until && old_live_until.saturating_sub(ledger_seq) <= threshold
        {
            // Get the current cached entry and update its live_until
            let cached = self.get_cached(&key, host, key_val)?;
            let updated_cached = match cached {
                CachedEntry::ContractData(val, _) => {
                    CachedEntry::ContractData(val, new_live_until)
                }
                CachedEntry::Entry(entry_rc, _) => {
                    CachedEntry::Entry(entry_rc, Some(new_live_until))
                }
            };
            self.map.insert(
                key,
                Some(updated_cached),
                host.budget_ref(),
            )?;
        }
        Ok(())
    }

    #[cfg(any(test, feature = "recording_mode"))]
    /// Returns `true` if the key exists in the snapshot and is live w.r.t
    /// the current ledger sequence.
    pub(crate) fn is_key_live_in_snapshot(
        &self,
        host: &Host,
        key: &Rc<LedgerKey>,
    ) -> Result<bool, HostError> {
        match &self.mode {
            FootprintMode::Recording(snapshot) => {
                let snapshot_value = snapshot.get(key)?;
                if let Some((_, live_until_ledger)) = snapshot_value {
                    if let Some(live_until_ledger) = live_until_ledger {
                        let current_ledger_sequence =
                            host.with_ledger_info(|li| Ok(li.sequence_number))?;
                        Ok(live_until_ledger >= current_ledger_sequence)
                    } else {
                        // Non-Soroban entries are always live.
                        Ok(true)
                    }
                } else {
                    // Key is not in the snapshot.
                    Ok(false)
                }
            }
            FootprintMode::Enforcing => Err(host.err(
                ScErrorType::Storage,
                ScErrorCode::InternalError,
                "trying to get snapshot value in enforcing mode",
                &[],
            )),
        }
    }

    // Test-only helper for getting the cached entry directly from the storage map,
    // without the footprint management and autorestoration.
    #[cfg(any(test, feature = "testutils"))]
    pub(crate) fn get_from_map(
        &self,
        key: &Rc<LedgerKey>,
        host: &Host,
    ) -> Result<Option<CachedEntry>, HostError> {
        match self.map.get(key, host.budget_ref())? {
            Some(entry_option) => Ok(entry_option.clone()),
            None => Ok(None),
        }
    }

    fn prepare_read_only_access(
        &mut self,
        key: &Rc<LedgerKey>,
        host: &Host,
    ) -> Result<(), HostError> {
        let ty = AccessType::ReadOnly;
        match self.mode {
            #[cfg(any(test, feature = "recording_mode"))]
            FootprintMode::Recording(ref src) => {
                self.footprint.record_access(key, ty, host.budget_ref())?;
                // In recording mode we treat the map as a cache
                // that misses read-through to the underlying src.
                if !self
                    .map
                    .contains_key(key, host.budget_ref())?
                {
                    // Get from snapshot and convert to CachedEntry
                    let value = src.get(&key)?;
                    let cached = match value {
                        Some((entry, live_until)) => {
                            Some(CachedEntry::from_entry_with_live_until(&entry, live_until, host)?)
                        }
                        None => None,
                    };
                    self.map.insert(key.clone(), cached, host.budget_ref())?;
                }
                self.footprint.record_access(key, ty, host.budget_ref())?;
                self.handle_maybe_expired_entry(key, host)?;
            }
            FootprintMode::Enforcing => {
                self.footprint.enforce_access(key, ty, host.budget_ref())?;
            }
        };
        Ok(())
    }

    #[cfg(any(test, feature = "recording_mode"))]
    fn handle_maybe_expired_entry(
        &mut self,
        key: &Rc<LedgerKey>,
        host: &Host,
    ) -> Result<(), HostError> {
        host.with_ledger_info(|li| {
            let budget = host.budget_ref();
            if let Some(Some(cached_entry)) = self.map.get(key, host.budget_ref())? {
                let live_until = cached_entry.live_until();
                if let Some(durability) = get_key_durability(key.as_ref()) {
                    let live_until = live_until.ok_or_else(|| {
                        host.err(
                            ScErrorType::Storage,
                            ScErrorCode::InternalError,
                            "unexpected contract entry without TTL",
                            &[],
                        )
                    })?;
                    if live_until < li.sequence_number {
                        match durability {
                            ContractDataDurability::Temporary => {
                                self.map.insert(key.clone(), None, budget)?;
                            }
                            ContractDataDurability::Persistent => {
                                self.footprint
                                    .record_access(key, AccessType::ReadWrite, budget)?;
                                let new_live_until = li
                                    .min_live_until_ledger_checked(
                                        ContractDataDurability::Persistent,
                                    )
                                    .ok_or_else(|| {
                                        host.err(ScErrorType::Storage,
                                        ScErrorCode::InternalError,
                                        "persistent entry TTL overflow, ledger is mis-configured",
                                        &[],)
                                    })?;
                                // Update the live_until in the cached entry
                                let updated = match cached_entry.clone() {
                                    CachedEntry::ContractData(val, _) => {
                                        CachedEntry::ContractData(val, new_live_until)
                                    }
                                    CachedEntry::Entry(entry_rc, _) => {
                                        CachedEntry::Entry(entry_rc, Some(new_live_until))
                                    }
                                };
                                self.map.insert(key.clone(), Some(updated), budget)?;
                            }
                        };
                    }
                }
            }
            Ok(())
        })
    }

    #[cfg(any(test, feature = "testutils"))]
    pub(crate) fn reset_footprint(&mut self) {
        self.footprint = Footprint::default();
    }

    /// Merges entries from a source cache into this storage's map.
    /// This is used for zero-copy propagation of cache entries between frames.
    /// Each entry is moved (not cloned) from the source iterator.
    #[allow(dead_code)]
    pub(crate) fn merge_from_cache<I>(
        &mut self,
        entries: I,
        budget: &Budget,
    ) -> Result<(), HostError>
    where
        I: Iterator<Item = (Rc<LedgerKey>, Option<CachedEntry>)>,
    {
        for (key, cached_entry) in entries {
            self.map.insert(key, cached_entry, budget)?;
        }
        Ok(())
    }
}

fn get_key_type_string_for_error(lk: &LedgerKey) -> &str {
    match lk {
        LedgerKey::ContractData(cd) => match cd.key {
            ScVal::LedgerKeyContractInstance => "contract instance",
            ScVal::LedgerKeyNonce(_) => "nonce",
            _ => "contract data key",
        },
        LedgerKey::ContractCode(_) => "contract code",
        LedgerKey::Account(_) => "account",
        LedgerKey::Trustline(_) => "account trustline",
        // This shouldn't normally trigger, but it's safer to just return
        // a safe default instead of an error in case if new key types are
        // accessed.
        _ => "ledger key",
    }
}

impl Host {
    fn decorate_storage_error(
        &self,
        err: HostError,
        lk: &LedgerKey,
        key_val: Option<Val>,
    ) -> HostError {
        let mut err = err;
        self.with_debug_mode_allowing_new_objects(
            || {
                if !err.error.is_type(ScErrorType::Storage) {
                    return Ok(());
                }
                if !err.error.is_code(ScErrorCode::ExceededLimit)
                    && !err.error.is_code(ScErrorCode::MissingValue)
                {
                    return Ok(());
                }

                let key_type_str = get_key_type_string_for_error(lk);
                // Accessing an entry outside of the footprint is a non-recoverable error, thus
                // there is no way to observe the object pool being changed (host will continue
                // propagating an error until there are no frames left and control is never
                // returned to guest). This allows us to build a nicer error message.
                // For the missing values we unfortunately can only safely use the existing `Val`s
                // to enhance errors.
                let can_create_new_objects = err.error.is_code(ScErrorCode::ExceededLimit);
                let args = self
                    .get_args_for_error(lk, key_val, can_create_new_objects)
                    .unwrap_or_else(|_| vec![]);
                if err.error.is_code(ScErrorCode::ExceededLimit) {
                    err = self.err(
                        ScErrorType::Storage,
                        ScErrorCode::ExceededLimit,
                        format!("trying to access {} outside of the footprint", key_type_str)
                            .as_str(),
                        args.as_slice(),
                    );
                } else if err.error.is_code(ScErrorCode::MissingValue) {
                    err = self.err(
                        ScErrorType::Storage,
                        ScErrorCode::MissingValue,
                        format!("trying to get non-existing value for {}", key_type_str).as_str(),
                        args.as_slice(),
                    );
                }

                Ok(())
            },
            true,
        );
        err
    }

    fn get_args_for_error(
        &self,
        lk: &LedgerKey,
        key_val: Option<Val>,
        can_create_new_objects: bool,
    ) -> Result<Vec<Val>, HostError> {
        let mut res = vec![];
        match lk {
            LedgerKey::ContractData(cd) => {
                if can_create_new_objects {
                    let address_val = self
                        .add_host_object(cd.contract.metered_clone(self.as_budget())?)?
                        .into();
                    res.push(address_val);
                }
                match &cd.key {
                    ScVal::LedgerKeyContractInstance => (),
                    ScVal::LedgerKeyNonce(n) => {
                        if can_create_new_objects {
                            res.push(self.add_host_object(n.nonce)?.into());
                        }
                    }
                    _ => {
                        if let Some(key) = key_val {
                            res.push(key);
                        }
                    }
                }
            }
            LedgerKey::ContractCode(c) => {
                if can_create_new_objects {
                    res.push(
                        self.add_host_object(self.scbytes_from_hash(&c.hash)?)?
                            .into(),
                    );
                }
            }
            LedgerKey::Account(_) | LedgerKey::Trustline(_) => {
                if can_create_new_objects {
                    res.push(self.account_address_from_key(lk)?)
                }
            }
            // This shouldn't normally trigger, but it's safer to just return
            // a safe default instead of an error in case if new key types are
            // accessed.
            _ => (),
        };
        Ok(res)
    }
}

#[cfg(any(test, feature = "recording_mode"))]
pub(crate) fn is_persistent_key(key: &LedgerKey) -> bool {
    match key {
        LedgerKey::ContractData(k) => {
            matches!(k.durability, ContractDataDurability::Persistent)
        }
        LedgerKey::ContractCode(_) => true,
        _ => false,
    }
}
