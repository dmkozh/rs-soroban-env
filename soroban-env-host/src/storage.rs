//! This module contains the [Storage] type and its supporting types, which
//! provide the [Host](crate::Host) with access to durable ledger entries.
//!
//! For more details, see the [Env](crate::Env) data access functions:
//!   - [Env::has_contract_data](crate::Env::has_contract_data)
//!   - [Env::get_contract_data](crate::Env::get_contract_data)
//!   - [Env::put_contract_data](crate::Env::put_contract_data)
//!   - [Env::del_contract_data](crate::Env::del_contract_data)

use std::rc::Rc;

use crate::budget::AsBudget;
use crate::host::metered_clone::{MeteredAlloc, MeteredClone, MeteredIterator};
use crate::{
    budget::Budget,
    host::metered_map::MeteredOrdMap,
    xdr::{
        ContractDataDurability, Hash, LedgerEntry, LedgerKey, LedgerKeyContractData, ScAddress,
        ScContractInstance, ScErrorCode, ScErrorType, ScVal,
    },
    Env, Error, Host, HostError, Val,
};

/// A storage key that optimizes comparison for contract data keys.
///
/// During contract execution, contract data keys are represented using
/// `Hash + Val + durability` which compares much faster than
/// `ScAddress + ScVal + durability` in the XDR `LedgerKey::ContractData`.
///
/// Keys originating from external sources (e.g. e2e_invoke) are converted
/// to the appropriate variant via `from_ledger_key` so comparison is consistent.
///
/// Note: StorageKey intentionally does not implement Ord/PartialOrd because
/// Val comparison for ContractData keys requires Host context (for object Vals).
/// All comparison goes through `Compare<StorageKey> for Host` or
/// `Compare<StorageKey> for Budget`.

#[derive(Clone, Hash, Debug)]
pub enum StorageKey {
    /// Contract data: hot path, uses Val for fast comparison.
    ContractData {
        contract_id: Hash,
        key: Val,
        durability: ContractDataDurability,
    },
    /// Contract instance: just needs contract_id.
    ContractInstance { contract_id: Hash },
    /// Everything else (Account, Trustline, ContractCode, or external ContractData).
    Other(LedgerKey),
}

impl StorageKey {
    /// Convert this `StorageKey` back to a `LedgerKey`.
    ///
    /// For `ContractData`, this requires the host to convert `Val` -> `ScVal`.
    /// For `ContractInstance` and `Other`, no host conversion is needed.
    pub fn to_ledger_key(&self, host: &Host) -> Result<Rc<LedgerKey>, HostError> {
        match self {
            StorageKey::ContractData {
                contract_id,
                key,
                durability,
            } => {
                let sc_val = host.from_host_val(*key)?;
                Rc::metered_new(
                    LedgerKey::ContractData(LedgerKeyContractData {
                        contract: ScAddress::Contract(contract_id.metered_clone(host.as_budget())?.into()),
                        key: sc_val,
                        durability: *durability,
                    }),
                    host.as_budget(),
                )
            }
            StorageKey::ContractInstance { contract_id } => Rc::metered_new(
                LedgerKey::ContractData(LedgerKeyContractData {
                    contract: ScAddress::Contract(contract_id.metered_clone(host.as_budget())?.into()),
                    key: ScVal::LedgerKeyContractInstance,
                    durability: ContractDataDurability::Persistent,
                }),
                host.as_budget(),
            ),
            StorageKey::Other(lk) => Rc::metered_new(lk.metered_clone(host.as_budget())?, host.as_budget()),
        }
    }

    /// Returns a reference to the inner `LedgerKey` if this is a `StorageKey::Other`.
    /// Returns `None` for `ContractData` and `ContractInstance` variants.
    pub fn as_ledger_key(&self) -> Option<&LedgerKey> {
        match self {
            StorageKey::Other(lk) => Some(lk),
            _ => None,
        }
    }

    /// Creates a `StorageKey` from a `LedgerKey` using the Host to convert
    /// `ScVal` keys to `Val` for ContractData entries. This ensures all
    /// ContractData keys use the fast `ContractData` variant consistently.
    pub fn from_ledger_key(lk: LedgerKey, host: &Host) -> Result<Self, HostError> {
        match lk {
            LedgerKey::ContractData(ref cd) => {
                match &cd.key {
                    ScVal::LedgerKeyContractInstance => {
                        // Instance key: extract contract hash
                        match &cd.contract {
                            ScAddress::Contract(id) => Ok(StorageKey::ContractInstance {
                                contract_id: id.0.metered_clone(host.as_budget())?,
                            }),
                            _ => Ok(StorageKey::Other(lk)),
                        }
                    }
                    // Nonce keys are internal (used for auth) and don't go
                    // through the contract Val path — keep as Other.
                    ScVal::LedgerKeyNonce(_) => Ok(StorageKey::Other(lk)),
                    _ => {
                        // Regular contract data: convert ScVal to Val.
                        match &cd.contract {
                            ScAddress::Contract(id) => {
                                let val = host.to_host_val(&cd.key)?;
                                // Reject muxed addresses (not representable in XDR footprint).
                                if val.get_tag() == crate::Tag::MuxedAddressObject {
                                    return Err(
                                        (ScErrorType::Storage, ScErrorCode::InvalidInput).into()
                                    );
                                }
                                Ok(StorageKey::ContractData {
                                    contract_id: id.0.metered_clone(host.as_budget())?,
                                    key: val,
                                    durability: cd.durability,
                                })
                            }
                            _ => Ok(StorageKey::Other(lk)),
                        }
                    }
                }
            }
            _ => Ok(StorageKey::Other(lk)),
        }
    }

    /// Get the durability of the key, if applicable.
    pub fn get_durability(&self) -> Option<ContractDataDurability> {
        match self {
            StorageKey::ContractData { durability, .. } => Some(*durability),
            StorageKey::ContractInstance { .. } => Some(ContractDataDurability::Persistent),
            StorageKey::Other(lk) => crate::ledger_info::get_key_durability(lk),
        }
    }
}

pub type FootprintMap = MeteredOrdMap<Rc<StorageKey>, AccessType, Host>;
pub type EntryWithLiveUntil = (Rc<LedgerEntry>, Option<u32>);
pub type StorageMap = MeteredOrdMap<Rc<StorageKey>, Option<EntryWithLiveUntil>, Host>;
/// LedgerKey-based maps returned by try_finish for external consumers.
pub type LedgerKeyEntryMap = MeteredOrdMap<Rc<LedgerKey>, Option<EntryWithLiveUntil>, Budget>;
pub type LedgerKeyFootprintMap = MeteredOrdMap<Rc<LedgerKey>, AccessType, Budget>;

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
                        .metered_collect::<Result<Vec<(Val, Val)>, HostError>>(host.as_budget())?
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
        key: &Rc<StorageKey>,
        ty: AccessType,
        host: &Host,
    ) -> Result<(), HostError> {
        if let Some(existing) = self.0.get::<Rc<StorageKey>>(key, host)? {
            match (existing, ty) {
                (AccessType::ReadOnly, AccessType::ReadOnly) => Ok(()),
                (AccessType::ReadOnly, AccessType::ReadWrite) => {
                    self.0 = self.0.insert(Rc::clone(key), ty, host)?;
                    Ok(())
                }
                (AccessType::ReadWrite, AccessType::ReadOnly) => Ok(()),
                (AccessType::ReadWrite, AccessType::ReadWrite) => Ok(()),
            }
        } else {
            self.0 = self.0.insert(Rc::clone(key), ty, host)?;
            Ok(())
        }
    }

    pub(crate) fn enforce_access(
        &mut self,
        key: &Rc<StorageKey>,
        ty: AccessType,
        host: &Host,
    ) -> Result<(), HostError> {
        if let Some(existing) = self.0.get::<Rc<StorageKey>>(key, host)? {
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

/// Helper struct holding common state for TTL extension operations.
struct TtlExtensionInfo {
    entry: Rc<LedgerEntry>,
    old_live_until: u32,
    current_ttl: u32,
    max_live_until: u32,
}

impl TtlExtensionInfo {
    fn max_network_extension(&self) -> u32 {
        self.max_live_until.saturating_sub(self.old_live_until)
    }
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

    /// Check that a [StorageKey] is a supported type. For `Other` variant,
    /// delegates to [check_supported_ledger_key_type].
    pub fn check_supported_storage_key_type(sk: &StorageKey) -> Result<(), HostError> {
        match sk {
            StorageKey::ContractData { .. } | StorageKey::ContractInstance { .. } => Ok(()),
            StorageKey::Other(lk) => Self::check_supported_ledger_key_type(lk),
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
    fn try_get_full_helper(
        &mut self,
        key: &Rc<StorageKey>,
        host: &Host,
    ) -> Result<Option<EntryWithLiveUntil>, HostError> {
        let _span = tracy_span!("storage get");
        Self::check_supported_storage_key_type(key)?;
        self.prepare_read_only_access(key, host)?;
        match self.map.get::<Rc<StorageKey>>(key, host)? {
            // Key has to be in the storage map at this point due to
            // `prepare_read_only_access`.
            None => Err((ScErrorType::Storage, ScErrorCode::InternalError).into()),
            Some(pair_option) => Ok(pair_option.clone()),
        }
    }

    pub(crate) fn try_get_full(
        &mut self,
        key: &Rc<StorageKey>,
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
        key: &Rc<StorageKey>,
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
    pub(crate) fn try_get(
        &mut self,
        key: &Rc<StorageKey>,
        host: &Host,
        key_val: Option<Val>,
    ) -> Result<Option<Rc<LedgerEntry>>, HostError> {
        self.try_get_full(key, host, key_val)
            .map(|ok| ok.map(|pair| pair.0))
    }

    /// Attempts to retrieve the [LedgerEntry] associated with a given
    /// [StorageKey] and its live until ledger (if applicable) in the [Storage],
    /// returning an error if the key is not found.
    ///
    /// Live until ledgers only exist for `ContractData` and `ContractCode`
    /// ledger entries and are `None` for all the other entry kinds.
    ///
    /// In [FootprintMode::Recording] mode, records the read key in the
    /// [Footprint] as [AccessType::ReadOnly] (unless already recorded as
    /// [AccessType::ReadWrite]) and reads through to the underlying
    /// [SnapshotSource], if the key has not yet been loaded.
    ///
    /// In [FootprintMode::Enforcing] mode, succeeds only if the read
    /// key has been declared in the [Footprint].
    pub(crate) fn get_with_live_until_ledger(
        &mut self,
        key: &Rc<StorageKey>,
        host: &Host,
        key_val: Option<Val>,
    ) -> Result<EntryWithLiveUntil, HostError> {
        self.try_get_full(key, host, key_val)
            .and_then(|maybe_entry| {
                maybe_entry.ok_or_else(|| (ScErrorType::Storage, ScErrorCode::MissingValue).into())
            })
            .map_err(|e| host.decorate_storage_error(e, key.as_ref(), key_val))
    }

    // Helper function `put` and `del` funnel into.
    fn put_opt_helper(
        &mut self,
        key: &Rc<StorageKey>,
        val: Option<EntryWithLiveUntil>,
        host: &Host,
    ) -> Result<(), HostError> {
        Self::check_supported_storage_key_type(key)?;
        if let Some(le) = &val {
            Self::check_supported_ledger_entry_type(&le.0)?;
        }
        #[cfg(any(test, feature = "recording_mode"))]
        self.handle_maybe_expired_entry(&key, host)?;

        let ty = AccessType::ReadWrite;
        match &self.mode {
            #[cfg(any(test, feature = "recording_mode"))]
            FootprintMode::Recording(_) => {
                self.footprint.record_access(key, ty, host)?;
            }
            FootprintMode::Enforcing => {
                self.footprint.enforce_access(key, ty, host)?;
            }
        };
        self.map = self.map.insert(Rc::clone(key), val, host)?;
        Ok(())
    }

    fn put_opt(
        &mut self,
        key: &Rc<StorageKey>,
        val: Option<EntryWithLiveUntil>,
        host: &Host,
        key_val: Option<Val>,
    ) -> Result<(), HostError> {
        self.put_opt_helper(key, val, host)
            .map_err(|e| host.decorate_storage_error(e, key.as_ref(), key_val))
    }

    /// Attempts to write to the [LedgerEntry] associated with a given
    /// [StorageKey] in the [Storage].
    ///
    /// In [FootprintMode::Recording] mode, records the written key in
    /// the [Footprint] as [AccessType::ReadWrite].
    ///
    /// In [FootprintMode::Enforcing] mode, succeeds only if the written
    /// key has been declared in the [Footprint] as
    /// [AccessType::ReadWrite].
    pub(crate) fn put(
        &mut self,
        key: &Rc<StorageKey>,
        val: &Rc<LedgerEntry>,
        live_until_ledger: Option<u32>,
        host: &Host,
        key_val: Option<Val>,
    ) -> Result<(), HostError> {
        let _span = tracy_span!("storage put");
        self.put_opt(key, Some((val.clone(), live_until_ledger)), host, key_val)
    }

    /// Attempts to delete the [LedgerEntry] associated with a given [StorageKey]
    /// in the [Storage].
    ///
    /// In [FootprintMode::Recording] mode, records the deleted key in
    /// the [Footprint] as [AccessType::ReadWrite].
    ///
    /// In [FootprintMode::Enforcing] mode, succeeds only if the deleted
    /// key has been declared in the [Footprint] as
    /// [AccessType::ReadWrite].
    pub(crate) fn del(
        &mut self,
        key: &Rc<StorageKey>,
        host: &Host,
        key_val: Option<Val>,
    ) -> Result<(), HostError> {
        let _span = tracy_span!("storage del");
        self.put_opt(key, None, host, key_val)
            .map_err(|e| host.decorate_storage_error(e, key.as_ref(), key_val))
    }

    /// Attempts to determine the presence of a [LedgerEntry] associated with a
    /// given [StorageKey] in the [Storage], returning `Ok(true)` if an entry
    /// with the key exists and `Ok(false)` if it does not.
    ///
    /// In [FootprintMode::Recording] mode, records the access and reads-through
    /// to the underlying [SnapshotSource].
    ///
    /// In [FootprintMode::Enforcing] mode, succeeds only if the access has been
    /// declared in the [Footprint].
    pub(crate) fn has(
        &mut self,
        key: &Rc<StorageKey>,
        host: &Host,
        key_val: Option<Val>,
    ) -> Result<bool, HostError> {
        let _span = tracy_span!("storage has");
        Ok(self.try_get_full(key, host, key_val)?.is_some())
    }

    /// Common setup for TTL extension operations. Returns the entry info
    /// needed to compute and apply the TTL extension.
    fn prepare_extend_ttl(
        &mut self,
        host: &Host,
        key: &Rc<StorageKey>,
        extend_to: u32,
        key_val: Option<Val>,
    ) -> Result<TtlExtensionInfo, HostError> {
        Self::check_supported_storage_key_type(key)?;

        #[cfg(any(test, feature = "recording_mode"))]
        self.handle_maybe_expired_entry(key, host)?;

        // Extending deleted/non-existing/out-of-footprint entries will result in
        // an error.
        let (entry, old_live_until) = self.get_with_live_until_ledger(key, host, key_val)?;
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

        let max_live_until = host.max_live_until_ledger()?;

        let durability = key.get_durability().ok_or_else(|| {
            host.err(
                ScErrorType::Storage,
                ScErrorCode::InternalError,
                "durability is missing",
                &[],
            )
        })?;
        let max_ttl = max_live_until.saturating_sub(ledger_seq);
        if matches!(durability, ContractDataDurability::Temporary) && extend_to > max_ttl {
            //  for `Temporary` entries TTL has to be exact - most of
            //  the time entry has to live until the exact specified
            //  ledger, or else something bad would happen (e.g. nonce
            //  expiring before the corresponding signature, thus
            //  allowing replay and double spend).
            return Err(host.err(
                ScErrorType::Storage,
                ScErrorCode::InvalidAction,
                "trying to extend temporary entry past max TTL allowed by network: {} > {}",
                &[extend_to.into(), max_ttl.into()],
            ));
        }
        let current_ttl = old_live_until.saturating_sub(ledger_seq);
        Ok(TtlExtensionInfo {
            entry,
            old_live_until,
            current_ttl,
            max_live_until,
        })
    }

    /// Updates the storage map with a new live_until value if it extends the TTL.
    fn apply_ttl_extension(
        &mut self,
        host: &Host,
        key: Rc<StorageKey>,
        ttl_ext_info: TtlExtensionInfo,
        new_live_until: u32,
    ) -> Result<(), HostError> {
        if new_live_until > ttl_ext_info.old_live_until {
            self.map = self.map.insert(
                key,
                Some((ttl_ext_info.entry, Some(new_live_until))),
                host,
            )?;
        }
        Ok(())
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
    /// internal storage.
    pub(crate) fn extend_ttl(
        &mut self,
        host: &Host,
        key: Rc<StorageKey>,
        threshold: u32,
        extend_to: u32,
        key_val: Option<Val>,
    ) -> Result<(), HostError> {
        let _span = tracy_span!("extend key");

        if threshold > extend_to {
            return Err(host.err(
                ScErrorType::Storage,
                ScErrorCode::InvalidInput,
                "threshold must be <= extend_to",
                &[threshold.into(), extend_to.into()],
            ));
        }

        let ttl_ext_info = self.prepare_extend_ttl(host, &key, extend_to, key_val)?;

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

        // Clamp persistent entries to max network TTL (temporary entries
        // wouldn't get here).
        new_live_until = new_live_until.min(ttl_ext_info.max_live_until);

        if ttl_ext_info.current_ttl <= threshold {
            self.apply_ttl_extension(host, key, ttl_ext_info, new_live_until)?;
        }
        Ok(())
    }

    /// Extends TTL of a ledger entry with min/max extension controls.
    ///
    /// The function extends the TTL to be up to `extend_to` ledgers from
    /// current ledger. The TTL extension only actually happens if the
    /// amount of extension ledgers is at least `min_extension`; otherwise this
    /// function is a no-op. The amount of extension ledgers will not exceed
    /// `max_extension` ledgers.
    ///
    /// If attempting to extend an entry past `Host::max_live_until_ledger()`
    /// - if the entry is `Persistent`, the entry's new
    ///   `live_until_ledger_seq` is clamped to it.
    /// - if the entry is `Temporary`, returns error.
    ///
    /// This operation is only defined within a host as it relies on ledger
    /// state.
    ///
    /// This operation does not modify any ledger entries, but does change the
    /// internal storage.
    pub(crate) fn extend_ttl_v2(
        &mut self,
        host: &Host,
        key: Rc<StorageKey>,
        extend_to: u32,
        min_extension: u32,
        max_extension: u32,
        key_val: Option<Val>,
    ) -> Result<(), HostError> {
        let _span = tracy_span!("extend key v2");

        if max_extension < min_extension {
            return Err(host.err(
                ScErrorType::Storage,
                ScErrorCode::InvalidInput,
                "max_extension must be >= min_extension",
                &[max_extension.into(), min_extension.into()],
            ));
        }

        let ttl_ext_info = self.prepare_extend_ttl(host, &key, extend_to, key_val)?;

        // Compute the initial TTL extension and clamp to not exceed
        // network/argument limits
        let ttl_ext_init = extend_to.saturating_sub(ttl_ext_info.current_ttl);
        let ttl_ext_final = ttl_ext_init
            .min(max_extension)
            .min(ttl_ext_info.max_network_extension());

        // If final extension < min_extension, return without changes
        if ttl_ext_final < min_extension {
            return Ok(());
        }

        let new_live_until = ttl_ext_info
            .old_live_until
            .checked_add(ttl_ext_final)
            .ok_or_else(|| {
                // overflowing here means a misconfiguration of the network (the
                // ttl is too large), in which case we immediately flag it as an
                // unrecoverable `InternalError`, even though the source is
                // external to the host.
                HostError::from(Error::from_type_and_code(
                    ScErrorType::Context,
                    ScErrorCode::InternalError,
                ))
            })?;

        self.apply_ttl_extension(host, key, ttl_ext_info, new_live_until)
    }

    #[cfg(any(test, feature = "recording_mode"))]
    /// Returns `true` if the key exists in the snapshot and is live w.r.t
    /// the current ledger sequence.
    pub(crate) fn is_key_live_in_snapshot(
        &self,
        host: &Host,
        key: &Rc<StorageKey>,
    ) -> Result<bool, HostError> {
        match &self.mode {
            FootprintMode::Recording(snapshot) => {
                // Convert StorageKey to LedgerKey to query the SnapshotSource.
                let lk = key.to_ledger_key(host)?;
                let snapshot_value = snapshot.get(&lk)?;
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

    // Test-only helper for getting the value directly from the storage map,
    // without the footprint management and autorestoration.
    #[cfg(any(test, feature = "testutils"))]
    pub(crate) fn get_from_map(
        &self,
        key: &Rc<StorageKey>,
        host: &Host,
    ) -> Result<Option<EntryWithLiveUntil>, HostError> {
        match self.map.get::<Rc<StorageKey>>(key, host)? {
            Some(pair_option) => Ok(pair_option.clone()),
            None => Ok(None),
        }
    }

    fn prepare_read_only_access(
        &mut self,
        key: &Rc<StorageKey>,
        host: &Host,
    ) -> Result<(), HostError> {
        let ty = AccessType::ReadOnly;
        match self.mode {
            #[cfg(any(test, feature = "recording_mode"))]
            FootprintMode::Recording(ref src) => {
                self.footprint.record_access(key, ty, host)?;
                // In recording mode we treat the map as a cache
                // that misses read-through to the underlying src.
                if !self
                    .map
                    .contains_key::<Rc<StorageKey>>(key, host)?
                {
                    // Convert StorageKey to LedgerKey to query the SnapshotSource.
                    let lk = key.to_ledger_key(host)?;
                    let value = src.get(&lk)?;
                    self.map = self.map.insert(key.clone(), value, host)?;
                }
                self.footprint.record_access(key, ty, host)?;
                self.handle_maybe_expired_entry(key, host)?;
            }
            FootprintMode::Enforcing => {
                self.footprint.enforce_access(key, ty, host)?;
            }
        };
        Ok(())
    }

    #[cfg(any(test, feature = "recording_mode"))]
    fn handle_maybe_expired_entry(
        &mut self,
        key: &Rc<StorageKey>,
        host: &Host,
    ) -> Result<(), HostError> {
        host.with_ledger_info(|li| {
            if let Some(Some((entry, live_until))) =
                self.map.get::<Rc<StorageKey>>(key, host)?
            {
                if let Some(durability) = key.get_durability() {
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
                                self.map = self.map.insert(key.clone(), None, host)?;
                            }
                            ContractDataDurability::Persistent => {
                                self.footprint
                                    .record_access(key, AccessType::ReadWrite, host)?;
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
                                self.map = self.map.insert(
                                    key.clone(),
                                    Some((entry.clone(), Some(new_live_until))),
                                    host,
                                )?;
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
}

fn get_storage_key_type_string_for_error(sk: &StorageKey) -> &str {
    match sk {
        StorageKey::ContractData { .. } => "contract data key",
        StorageKey::ContractInstance { .. } => "contract instance",
        StorageKey::Other(lk) => match lk {
            LedgerKey::ContractData(cd) => match cd.key {
                ScVal::LedgerKeyContractInstance => "contract instance",
                ScVal::LedgerKeyNonce(_) => "nonce",
                _ => "contract data key",
            },
            LedgerKey::ContractCode(_) => "contract code",
            LedgerKey::Account(_) => "account",
            LedgerKey::Trustline(_) => "account trustline",
            _ => "ledger key",
        },
    }
}

impl Host {
    pub(crate) fn decorate_storage_error(
        &self,
        err: HostError,
        sk: &StorageKey,
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

                let key_type_str = get_storage_key_type_string_for_error(sk);
                let can_create_new_objects = err.error.is_code(ScErrorCode::ExceededLimit);
                let args = self
                    .get_args_for_storage_key_error(sk, key_val, can_create_new_objects)
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

    fn get_args_for_storage_key_error(
        &self,
        sk: &StorageKey,
        key_val: Option<Val>,
        can_create_new_objects: bool,
    ) -> Result<Vec<Val>, HostError> {
        let mut res = vec![];
        match sk {
            StorageKey::ContractData {
                contract_id, key, ..
            } => {
                if can_create_new_objects {
                    let address_val = self
                        .add_host_object(ScAddress::Contract(contract_id.clone().into()))?
                        .into();
                    res.push(address_val);
                }
                if let Some(key) = key_val {
                    res.push(key);
                } else {
                    res.push(*key);
                }
            }
            StorageKey::ContractInstance { contract_id } => {
                if can_create_new_objects {
                    let address_val = self
                        .add_host_object(ScAddress::Contract(contract_id.clone().into()))?
                        .into();
                    res.push(address_val);
                }
            }
            StorageKey::Other(lk) => {
                return self.get_args_for_error(lk, key_val, can_create_new_objects);
            }
        }
        Ok(res)
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
            _ => (),
        };
        Ok(res)
    }
}

#[cfg(any(test, feature = "recording_mode"))]
pub(crate) fn is_persistent_storage_key(key: &StorageKey) -> bool {
    match key {
        StorageKey::ContractData { durability, .. } => {
            matches!(durability, ContractDataDurability::Persistent)
        }
        StorageKey::ContractInstance { .. } => true,
        StorageKey::Other(lk) => match lk {
            LedgerKey::ContractData(k) => {
                matches!(k.durability, ContractDataDurability::Persistent)
            }
            LedgerKey::ContractCode(_) => true,
            _ => false,
        },
    }
}

// Keep the old function as well for use in e2e_invoke.
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
