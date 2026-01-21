use core::cmp::min;
use std::rc::Rc;

use crate::{
    budget::AsBudget,
    err,
    host::metered_clone::{MeteredAlloc, MeteredClone},
    storage::{CachedEntry, InstanceStorageMap, Storage, StorageCache},
    vm::VersionedContractCodeCostInputs,
    xdr::{
        AccountEntry, AccountId, Asset, BytesM, ContractCodeEntry, ContractDataDurability,
        ContractDataEntry, ContractExecutable, ContractId, ContractIdPreimage, ExtensionPoint,
        Hash, HashIdPreimage, HashIdPreimageContractId, LedgerEntry, LedgerEntryData,
        LedgerEntryExt, LedgerKey, LedgerKeyAccount, LedgerKeyContractCode, LedgerKeyContractData,
        LedgerKeyTrustLine, PublicKey, ScAddress, ScContractInstance, ScErrorCode, ScErrorType,
        ScMap, ScVal, Signer, SignerKey, ThresholdIndexes, TrustLineAsset, Uint256,
    },
    AddressObject, Env, Error, ErrorHandler, Host, HostError, StorageType, U32Val, Val,
};

impl Host {
    pub(crate) fn with_mut_storage<F, U>(&self, f: F) -> Result<U, HostError>
    where
        F: FnOnce(&mut Storage) -> Result<U, HostError>,
    {
        f(&mut *self.try_borrow_storage_mut()?)
    }

    /// Immutable accessor to the instance storage of the currently running
    /// contract.
    /// Performs lazy initialization of instance storage on access.
    pub(crate) fn with_instance_storage<F, U>(&self, f: F) -> Result<U, HostError>
    where
        F: FnOnce(&InstanceStorageMap) -> Result<U, HostError>,
    {
        self.with_current_context_mut(|ctx| {
            self.maybe_init_instance_storage(ctx)?;
            f(ctx.storage.as_ref().ok_or_else(|| {
                self.err(
                    ScErrorType::Context,
                    ScErrorCode::InternalError,
                    "missing instance storage",
                    &[],
                )
            })?)
        })
    }

    /// Mutable accessor to the instance storage of the currently running
    /// contract.
    /// Performs lazy initialization of instance storage on access.
    pub(crate) fn with_mut_instance_storage<F, U>(&self, f: F) -> Result<U, HostError>
    where
        F: FnOnce(&mut InstanceStorageMap) -> Result<U, HostError>,
    {
        self.with_current_context_mut(|ctx| {
            self.maybe_init_instance_storage(ctx)?;
            let storage = ctx.storage.as_mut().ok_or_else(|| {
                self.err(
                    ScErrorType::Context,
                    ScErrorCode::InternalError,
                    "missing instance storage",
                    &[],
                )
            })?;
            // Consider any mutable access to be modifying the instance storage.
            // This way we would provide consistent footprint (RO for read-only
            // ops using `with_instance_storage` and RW for potentially
            // mutating ops using `with_mut_instance_storage`).
            storage.is_modified = true;
            f(storage)
        })
    }

    /// Immutable accessor to the data cache of the current frame.
    /// Returns None if there is no current frame.
    pub(crate) fn try_with_data_cache<F, U>(&self, f: F) -> Result<Option<U>, HostError>
    where
        F: FnOnce(&StorageCache) -> Result<U, HostError>,
    {
        let Ok(context_guard) = self.0.context_stack.try_borrow() else {
            return Err(self.err(
                ScErrorType::Context,
                ScErrorCode::InternalError,
                "context is already borrowed",
                &[],
            ));
        };
        if let Some(ctx) = context_guard.last() {
            Ok(Some(f(&ctx.data_cache)?))
        } else {
            Ok(None)
        }
    }

    /// Mutable accessor to the data cache of the current frame.
    /// Returns None if there is no current frame.
    pub(crate) fn try_with_mut_data_cache<F, U>(&self, f: F) -> Result<Option<U>, HostError>
    where
        F: FnOnce(&mut StorageCache) -> Result<U, HostError>,
    {
        let Ok(mut context_guard) = self.0.context_stack.try_borrow_mut() else {
            return Err(self.err(
                ScErrorType::Context,
                ScErrorCode::InternalError,
                "context is already borrowed",
                &[],
            ));
        };
        if let Some(ctx) = context_guard.last_mut() {
            Ok(Some(f(&mut ctx.data_cache)?))
        } else {
            Ok(None)
        }
    }

    /// Looks up a key in the cache chain: current frame → parent frame (if same contract) → None.
    /// Returns:
    /// - `Ok(Some(Some(entry)))` if found with a value
    /// - `Ok(Some(None))` if found but marked as deleted
    /// - `Ok(None)` if not found in any cache (should fall through to storage)
    pub(crate) fn lookup_in_cache_chain(
        &self,
        key: &Rc<LedgerKey>,
    ) -> Result<Option<Option<CachedEntry>>, HostError> {
        let budget = self.budget_ref();

        let Ok(context_guard) = self.0.context_stack.try_borrow() else {
            return Err(self.err(
                ScErrorType::Context,
                ScErrorCode::InternalError,
                "context is already borrowed",
                &[],
            ));
        };

        let stack = &*context_guard;
        let len = stack.len();

        if len == 0 {
            return Ok(None);
        }

        // Check current frame's cache
        let current_ctx = &stack[len - 1];
        if let Some(entry) = current_ctx.data_cache.get(key, budget)? {
            return Ok(Some(entry.clone()));
        }

        // Check parent frame's cache if it's the same contract
        if len >= 2 {
            let parent_ctx = &stack[len - 2];
            let current_contract_id = current_ctx.frame.contract_id();
            let parent_contract_id = parent_ctx.frame.contract_id();

            // Only check parent cache if same contract (e.g., internal call or recursion)
            if current_contract_id.is_some()
                && current_contract_id == parent_contract_id
            {
                if let Some(entry) = parent_ctx.data_cache.get(key, budget)? {
                    return Ok(Some(entry.clone()));
                }
            }
        }

        Ok(None)
    }

    pub(crate) fn contract_instance_ledger_key(
        &self,
        contract_id: &ContractId,
    ) -> Result<Rc<LedgerKey>, HostError> {
        let contract_id = contract_id.metered_clone(self)?;
        Rc::metered_new(
            LedgerKey::ContractData(LedgerKeyContractData {
                key: ScVal::LedgerKeyContractInstance,
                durability: ContractDataDurability::Persistent,
                contract: ScAddress::Contract(contract_id),
            }),
            self,
        )
    }

    pub(crate) fn extract_contract_instance_from_ledger_entry(
        &self,
        entry: &LedgerEntry,
    ) -> Result<ScContractInstance, HostError> {
        match &entry.data {
            LedgerEntryData::ContractData(e) => match &e.val {
                ScVal::ContractInstance(instance) => instance.metered_clone(self),
                _ => Err(self.err(
                    ScErrorType::Storage,
                    ScErrorCode::InternalError,
                    "ledger entry for contract instance does not contain contract instance",
                    &[],
                )),
            },
            _ => Err(self.err(
                ScErrorType::Storage,
                ScErrorCode::InternalError,
                "expected ContractData ledger entry",
                &[],
            )),
        }
    }

    // Notes on metering: retrieving from storage covered. Rest are free.
    pub(crate) fn retrieve_contract_instance_from_storage(
        &self,
        key: &Rc<LedgerKey>,
    ) -> Result<ScContractInstance, HostError> {
        let entry = self.try_borrow_storage_mut()?.get(key, self, None)?;
        self.extract_contract_instance_from_ledger_entry(&entry)
    }

    pub(crate) fn contract_code_ledger_key(
        &self,
        wasm_hash: &Hash,
    ) -> Result<Rc<LedgerKey>, HostError> {
        let wasm_hash = wasm_hash.metered_clone(self)?;
        Rc::metered_new(
            LedgerKey::ContractCode(LedgerKeyContractCode { hash: wasm_hash }),
            self,
        )
    }

    pub(crate) fn retrieve_wasm_from_storage(
        &self,
        wasm_hash: &Hash,
    ) -> Result<(BytesM, VersionedContractCodeCostInputs), HostError> {
        let key = self.contract_code_ledger_key(wasm_hash)?;
        match &self.try_borrow_storage_mut()?.get(&key, self, None)?.data {
            LedgerEntryData::ContractCode(e) => {
                let code = e.code.metered_clone(self)?;
                let costs = match &e.ext {
                    crate::xdr::ContractCodeEntryExt::V0 => VersionedContractCodeCostInputs::V0 {
                        wasm_bytes: code.len(),
                    },
                    crate::xdr::ContractCodeEntryExt::V1(v1) => {
                        VersionedContractCodeCostInputs::V1(
                            v1.cost_inputs.metered_clone(self.as_budget())?,
                        )
                    }
                };
                Ok((code, costs))
            }
            _ => Err(err!(
                self,
                (ScErrorType::Storage, ScErrorCode::InternalError),
                "expected ContractCode ledger entry",
                *wasm_hash
            )),
        }
    }

    pub(crate) fn wasm_exists(&self, wasm_hash: &Hash) -> Result<bool, HostError> {
        let key = self.contract_code_ledger_key(wasm_hash)?;
        self.try_borrow_storage_mut()?.has(&key, self, None)
    }

    // Stores the contract instance specified with its parts (executable and
    // storage).
    // When either of parts is `None`, the old value is preserved (when
    // existent).
    // `executable` has to be present for newly created contract instances.
    // Notes on metering: `from_host_obj` and `put` to storage covered, rest are free.
    pub(crate) fn store_contract_instance(
        &self,
        executable: Option<ContractExecutable>,
        instance_storage: Option<ScMap>,
        contract_id: ContractId,
        key: &Rc<LedgerKey>,
    ) -> Result<(), HostError> {
        if self.try_borrow_storage_mut()?.has(key, self, None)? {
            let (current, live_until_ledger) = self
                .try_borrow_storage_mut()?
                .get_with_live_until_ledger(key, self, None)?;
            let mut current = (*current).metered_clone(self)?;

            if let LedgerEntryData::ContractData(ref mut entry) = current.data {
                if let ScVal::ContractInstance(ref mut instance) = entry.val {
                    if let Some(executable) = executable {
                        instance.executable = executable;
                    }
                    if let Some(storage) = instance_storage {
                        instance.storage = Some(storage);
                    }
                } else {
                    return Err(self.err(
                        ScErrorType::Storage,
                        ScErrorCode::InternalError,
                        "expected ScVal::ContractInstance for contract instance",
                        &[],
                    ));
                }
            } else {
                return Err(self.err(
                    ScErrorType::Storage,
                    ScErrorCode::InternalError,
                    "expected DataEntry for contract instance",
                    &[],
                ));
            }

            self.try_borrow_storage_mut()?.put(
                &key,
                &Rc::metered_new(current, self)?,
                live_until_ledger,
                self,
                None,
            )?;
        } else {
            let data = ContractDataEntry {
                contract: ScAddress::Contract(contract_id.metered_clone(self)?),
                key: ScVal::LedgerKeyContractInstance,
                val: ScVal::ContractInstance(ScContractInstance {
                    executable: executable.ok_or_else(|| {
                        self.err(
                            ScErrorType::Context,
                            ScErrorCode::InternalError,
                            "can't initialize contract without executable",
                            &[],
                        )
                    })?,
                    storage: instance_storage,
                }),
                durability: ContractDataDurability::Persistent,
                ext: ExtensionPoint::V0,
            };
            self.try_borrow_storage_mut()?.put(
                key,
                &Host::new_contract_data(self, data)?,
                Some(self.get_min_live_until_ledger(ContractDataDurability::Persistent)?),
                self,
                None,
            )?;
        }
        Ok(())
    }

    pub(crate) fn extend_contract_code_ttl_from_contract_id(
        &self,
        instance_key: Rc<LedgerKey>,
        threshold: u32,
        extend_to: u32,
    ) -> Result<(), HostError> {
        match self
            .retrieve_contract_instance_from_storage(&instance_key)?
            .executable
        {
            ContractExecutable::Wasm(wasm_hash) => {
                let key = self.contract_code_ledger_key(&wasm_hash)?;
                self.try_borrow_storage_mut()?
                    .extend_ttl(self, key, threshold, extend_to, None)?;
            }
            ContractExecutable::StellarAsset => {}
        }
        Ok(())
    }

    pub(crate) fn extend_contract_instance_ttl_from_contract_id(
        &self,
        instance_key: Rc<LedgerKey>,
        threshold: u32,
        extend_to: u32,
    ) -> Result<(), HostError> {
        self.try_borrow_storage_mut()?.extend_ttl(
            self,
            instance_key.metered_clone(self)?,
            threshold,
            extend_to,
            None,
        )?;
        Ok(())
    }

    // metering: covered by components
    pub(crate) fn get_full_contract_id_preimage(
        &self,
        init_preimage: ContractIdPreimage,
    ) -> Result<HashIdPreimage, HostError> {
        Ok(HashIdPreimage::ContractId(HashIdPreimageContractId {
            network_id: self
                .hash_from_bytesobj_input("network_id", self.get_ledger_network_id()?)?,
            contract_id_preimage: init_preimage,
        }))
    }

    // notes on metering: `get` from storage is covered. Rest are free.
    pub(crate) fn load_account(&self, account_id: AccountId) -> Result<AccountEntry, HostError> {
        let acc = self.to_account_key(account_id)?;
        self.with_mut_storage(|storage| match &storage.get(&acc, self, None)?.data {
            LedgerEntryData::Account(ae) => ae.metered_clone(self),
            e => Err(err!(
                self,
                (ScErrorType::Storage, ScErrorCode::InternalError),
                "ledger entry is not account",
                e.name()
            )),
        })
    }

    pub(crate) fn to_account_key(&self, account_id: AccountId) -> Result<Rc<LedgerKey>, HostError> {
        Rc::metered_new(LedgerKey::Account(LedgerKeyAccount { account_id }), self)
    }

    pub(crate) fn create_asset_4(&self, asset_code: [u8; 4], issuer: AccountId) -> Asset {
        use crate::xdr::{AlphaNum4, AssetCode4};
        Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(asset_code),
            issuer,
        })
    }

    pub(crate) fn create_asset_12(&self, asset_code: [u8; 12], issuer: AccountId) -> Asset {
        use crate::xdr::{AlphaNum12, AssetCode12};
        Asset::CreditAlphanum12(AlphaNum12 {
            asset_code: AssetCode12(asset_code),
            issuer,
        })
    }

    pub(crate) fn to_trustline_key(
        &self,
        account_id: AccountId,
        asset: TrustLineAsset,
    ) -> Result<Rc<LedgerKey>, HostError> {
        Rc::metered_new(
            LedgerKey::Trustline(LedgerKeyTrustLine { account_id, asset }),
            self,
        )
    }

    pub(crate) fn get_signer_weight_from_account(
        &self,
        target_signer: Uint256,
        account: &AccountEntry,
    ) -> Result<u8, HostError> {
        if account.account_id
            == AccountId(PublicKey::PublicKeyTypeEd25519(
                target_signer.metered_clone(self)?,
            ))
        {
            // Target signer is the master key, so return the master weight
            let Some(threshold) = account
                .thresholds
                .0
                .get(ThresholdIndexes::MasterWeight as usize)
            else {
                return Err(self.error(
                    (ScErrorType::Value, ScErrorCode::InternalError).into(),
                    "unexpected thresholds-array size",
                    &[],
                ));
            };
            Ok(*threshold)
        } else {
            // Target signer is not the master key, so search the account signers
            let signers: &Vec<Signer> = account.signers.as_ref();
            for signer in signers {
                if let SignerKey::Ed25519(ref this_signer) = signer.key {
                    if &target_signer == this_signer {
                        // Clamp the weight at 255. Stellar protocol before v10
                        // allowed weights to exceed 255, but the max threshold
                        // is 255, hence there is no point in having a larger
                        // weight.
                        let weight = min(signer.weight, u8::MAX as u32);
                        // We've found the target signer in the account signers, so return the weight
                        return weight.try_into().map_err(|_| {
                            self.err(
                                ScErrorType::Auth,
                                ScErrorCode::ArithDomain,
                                "signer weight does not fit in u8",
                                &[U32Val::from(weight).to_val()],
                            )
                        });
                    }
                }
            }
            // We didn't find the target signer, return 0 weight to indicate that.
            Ok(0u8)
        }
    }

    pub(crate) fn new_contract_data(
        &self,
        data: ContractDataEntry,
    ) -> Result<Rc<LedgerEntry>, HostError> {
        Rc::metered_new(
            LedgerEntry {
                // This is modified to the appropriate value on the core side during
                // commiting the ledger transaction.
                last_modified_ledger_seq: 0,
                data: LedgerEntryData::ContractData(data),
                ext: LedgerEntryExt::V0,
            },
            self,
        )
    }

    pub(crate) fn new_contract_code(
        &self,
        data: ContractCodeEntry,
    ) -> Result<Rc<LedgerEntry>, HostError> {
        Rc::metered_new(
            LedgerEntry {
                // This is modified to the appropriate value on the core side during
                // commiting the ledger transaction.
                last_modified_ledger_seq: 0,
                data: LedgerEntryData::ContractCode(data),
                ext: LedgerEntryExt::V0,
            },
            self,
        )
    }

    /// Provides read-only access to a ledger entry via a callback.
    /// The entry is loaded into the per-frame cache if not already present.
    /// Use this for read-only access to Account/Trustline/ContractCode entries.
    /// Returns an error if called with a ContractData key.
    #[allow(dead_code)]
    pub(crate) fn with_ledger_entry<F, R>(
        &self,
        key: &Rc<LedgerKey>,
        f: F,
    ) -> Result<R, HostError>
    where
        F: FnOnce(&LedgerEntry) -> Result<R, HostError>,
    {
        use crate::storage::CachedEntry;
        use std::cell::RefCell;

        let budget = self.budget_ref();

        // Try to get from per-frame cache first
        if let Some(cached) = self
            .try_with_data_cache(|cache| Ok(cache.get(key, budget)?.cloned()))?
            .flatten()
        {
            match cached {
                Some(CachedEntry::Entry(entry_rc, _)) => {
                    return f(&entry_rc.borrow());
                }
                Some(CachedEntry::ContractData(_, _)) => {
                    return Err(self.err(
                        ScErrorType::Storage,
                        ScErrorCode::InternalError,
                        "expected Entry, got ContractData in cache",
                        &[],
                    ));
                }
                None => {
                    return Err(self.err(
                        ScErrorType::Storage,
                        ScErrorCode::MissingValue,
                        "entry was deleted",
                        &[],
                    ));
                }
            }
        }

        // Cache miss - read from storage and cache it
        let (entry, live_until) = self
            .try_borrow_storage_mut()?
            .get_with_live_until_ledger(key, self, None)?;

        // Cache the entry for future access
        let entry_refcell = Rc::new(RefCell::new((*entry).clone()));
        self.try_with_mut_data_cache(|cache| {
            cache.insert(
                key.metered_clone(budget)?,
                Some(CachedEntry::Entry(entry_refcell.clone(), live_until)),
                budget,
            )
        })?;

        let result = f(&entry_refcell.borrow());
        result
    }

    /// Provides mutable access to a ledger entry via a callback.
    /// The entry is loaded into the per-frame cache if not already present.
    /// Modifications made through the callback will be persisted when the frame exits.
    /// If there is no frame context, modifications are written directly to storage.
    /// Use this for in-place mutation of Account/Trustline/ContractCode entries.
    /// Returns an error if called with a ContractData key.
    pub(crate) fn modify_ledger_entry<F, R>(
        &self,
        key: &Rc<LedgerKey>,
        f: F,
    ) -> Result<R, HostError>
    where
        F: FnOnce(&mut LedgerEntry) -> Result<R, HostError>,
    {
        use crate::storage::CachedEntry;
        use std::cell::RefCell;

        // Guard: this method is for non-contract-data entries only
        if matches!(key.as_ref(), LedgerKey::ContractData(_)) {
            return Err(self.err(
                ScErrorType::Storage,
                ScErrorCode::InternalError,
                "modify_ledger_entry should not be used for ContractData",
                &[],
            ));
        }

        let budget = self.budget_ref();

        // Record write access to footprint
        self.try_borrow_storage_mut()?
            .record_write_access(key, self, None)?;

        // Check if we have a frame context
        let has_frame = self.try_with_data_cache(|_| Ok(()))?.is_some();

        if has_frame {
            // Try to get from per-frame cache first
            if let Some(cached) = self
                .try_with_data_cache(|cache| Ok(cache.get(key, budget)?.cloned()))?
                .flatten()
            {
                match cached {
                    Some(CachedEntry::Entry(entry_rc, _)) => {
                        return f(&mut entry_rc.borrow_mut());
                    }
                    Some(CachedEntry::ContractData(_, _)) => {
                        return Err(self.err(
                            ScErrorType::Storage,
                            ScErrorCode::InternalError,
                            "expected Entry, got ContractData in cache",
                            &[],
                        ));
                    }
                    None => {
                        return Err(self.err(
                            ScErrorType::Storage,
                            ScErrorCode::MissingValue,
                            "entry was deleted",
                            &[],
                        ));
                    }
                }
            }

            // Cache miss - read from storage and cache it
            let (entry, live_until) = self
                .try_borrow_storage_mut()?
                .get_with_live_until_ledger(key, self, None)?;

            // Cache the entry for future access
            let entry_refcell = Rc::new(RefCell::new((*entry).clone()));
            self.try_with_mut_data_cache(|cache| {
                cache.insert(
                    key.metered_clone(budget)?,
                    Some(CachedEntry::Entry(entry_refcell.clone(), live_until)),
                    budget,
                )
            })?;

            let result = f(&mut entry_refcell.borrow_mut());
            result
        } else {
            // No frame context - read from storage, modify, write back
            let (entry, live_until) = self
                .try_borrow_storage_mut()?
                .get_with_live_until_ledger(key, self, None)?;

            let mut modified_entry = (*entry).metered_clone(self)?;
            let result = f(&mut modified_entry)?;

            self.try_borrow_storage_mut()?.put(
                key,
                &Rc::metered_new(modified_entry, self)?,
                live_until,
                self,
                None,
            )?;

            Ok(result)
        }
    }

    pub(crate) fn contract_id_from_scaddress(
        &self,
        address: ScAddress,
    ) -> Result<ContractId, HostError> {
        match address {
            ScAddress::Contract(contract_id) => Ok(contract_id),
            _ => Err(self.err(
                ScErrorType::Object,
                ScErrorCode::InvalidInput,
                "not a contract address",
                &[],
            )),
        }
    }

    pub(crate) fn contract_id_from_address(
        &self,
        address: AddressObject,
    ) -> Result<ContractId, HostError> {
        self.visit_obj(address, |addr: &ScAddress| {
            self.contract_id_from_scaddress(addr.metered_clone(self)?)
        })
    }

    /// Puts contract data into the per-frame cache instead of directly to storage.
    /// The cache will be flushed to storage when the frame successfully exits.
    /// This avoids expensive immutable map mutations on each write.
    /// If there is no frame context, falls back to direct storage write.
    pub(super) fn put_contract_data_into_ledger(
        &self,
        k: Val,
        v: Val,
        t: StorageType,
    ) -> Result<(), HostError> {
        let durability: ContractDataDurability = t.try_into()?;
        let key = self.storage_key_from_val(k, durability)?;

        // Check if we have a frame context (for caching)
        let has_frame = self.try_with_data_cache(|_| Ok(()))?.is_some();

        if !has_frame {
            // No frame context - use direct storage write (legacy behavior)
            return self.put_contract_data_into_storage_direct(k, v, t);
        }

        // Record/enforce footprint access. This is needed even though we're
        // writing to cache because:
        // 1. In recording mode, we need to record that this key will be written
        // 2. In enforcing mode, we need to verify the key is in the footprint
        self.try_borrow_storage_mut()?
            .record_write_access(&key, self, Some(k))?;

        // Determine the live_until_ledger:
        // - If entry exists in cache, preserve its live_until_ledger
        // - If entry exists in storage, get its live_until_ledger
        // - Otherwise use min live_until for new entries
        let budget = self.budget_ref();
        let live_until_from_cache = self.try_with_data_cache(|cache| {
            if let Some(Some(entry)) = cache.get(&key, budget)? {
                if let CachedEntry::ContractData(_, live_until) = entry {
                    return Ok(Some(*live_until));
                }
            }
            Ok(None)
        })?.flatten();

        let live_until_ledger = match live_until_from_cache {
            Some(lul) => lul,
            None => {
                // Check storage for existing entry's live_until
                if self.try_borrow_storage_mut()?.has(&key, self, Some(k))? {
                    let (_, lul) = self
                        .try_borrow_storage_mut()?
                        .get_with_live_until_ledger(&key, self, Some(k))?;
                    lul.unwrap_or(self.get_min_live_until_ledger(durability)?)
                } else {
                    // New entry - use minimum live_until
                    self.get_min_live_until_ledger(durability)?
                }
            }
        };

        // Write to cache - store Val directly to avoid repeated conversions
        let budget = self.budget_ref();
        self.try_with_mut_data_cache(|cache| {
            cache.insert(
                key.metered_clone(budget)?,
                Some(CachedEntry::ContractData(v, live_until_ledger)),
                budget,
            )
        })?;
        Ok(())
    }

    /// Direct storage write without caching (legacy behavior for when no frame context exists).
    fn put_contract_data_into_storage_direct(
        &self,
        k: Val,
        v: Val,
        t: StorageType,
    ) -> Result<(), HostError> {
        let durability: ContractDataDurability = t.try_into()?;
        let key = self.storage_key_from_val(k, durability)?;
        if self.try_borrow_storage_mut()?.has(&key, self, Some(k))? {
            let (current, live_until_ledger) = self
                .try_borrow_storage_mut()?
                .get_with_live_until_ledger(&key, self, Some(k))?;
            let mut current = (*current).metered_clone(self)?;
            match current.data {
                LedgerEntryData::ContractData(ref mut entry) => {
                    entry.val = self.from_host_val(v)?;
                }
                _ => {
                    return Err(self.err(
                        ScErrorType::Storage,
                        ScErrorCode::InternalError,
                        "expected DataEntry",
                        &[],
                    ));
                }
            }
            self.try_borrow_storage_mut()?.put(
                &key,
                &Rc::metered_new(current, self)?,
                live_until_ledger,
                self,
                Some(k),
            )?;
        } else {
            let data = ContractDataEntry {
                contract: ScAddress::Contract(self.get_current_contract_id_internal()?),
                key: self.from_host_val(k)?,
                val: self.from_host_val(v)?,
                durability,
                ext: ExtensionPoint::V0,
            };
            self.try_borrow_storage_mut()?.put(
                &key,
                &Host::new_contract_data(self, data)?,
                Some(self.get_min_live_until_ledger(durability)?),
                self,
                Some(k),
            )?;
        }
        Ok(())
    }

    /// Gets contract data, checking the cache chain (current frame → parent frame
    /// if same contract → global storage).
    pub(super) fn get_contract_data_from_ledger(
        &self,
        k: Val,
        t: StorageType,
    ) -> Result<Val, HostError> {
        let durability: ContractDataDurability = t.try_into()?;
        let key = self.storage_key_from_val(k, durability)?;

        // Check cache chain: current frame → parent frame (if same contract)
        if let Some(entry) = self.lookup_in_cache_chain(&key)? {
            match entry {
                Some(CachedEntry::ContractData(val, _)) => {
                    // Found in cache with a value - Val is already in host format
                    return Ok(val);
                }
                Some(CachedEntry::Entry(..)) => {
                    // Wrong type in cache - should not happen for contract data
                    return Err(self.err(
                        ScErrorType::Storage,
                        ScErrorCode::InternalError,
                        "unexpected entry type in cache",
                        &[],
                    ));
                }
                None => {
                    // Entry was deleted in cache
                    return Err(self.err(
                        ScErrorType::Storage,
                        ScErrorCode::MissingValue,
                        "contract data entry was deleted",
                        &[k],
                    ));
                }
            }
        }

        // Cache miss - read from storage
        let entry = self.try_borrow_storage_mut()?.get(&key, self, Some(k))?;
        match &entry.data {
            LedgerEntryData::ContractData(e) => self.to_valid_host_val(&e.val),
            _ => Err(self.err(
                ScErrorType::Storage,
                ScErrorCode::InternalError,
                "expected contract data ledger entry",
                &[],
            )),
        }
    }

    /// Deletes contract data by marking it as deleted in the per-frame cache.
    /// If there is no frame context, deletes directly from storage.
    pub(super) fn del_contract_data_from_ledger(
        &self,
        k: Val,
        t: StorageType,
    ) -> Result<(), HostError> {
        let durability: ContractDataDurability = t.try_into()?;
        let key = self.storage_key_from_val(k, durability)?;

        // Check if we have a frame context
        let has_frame = self.try_with_data_cache(|_| Ok(()))?.is_some();

        if !has_frame {
            // No frame context - use direct storage delete
            self.try_borrow_storage_mut()?.del(&key, self, Some(k))?;
            return Ok(());
        }

        // Record/enforce footprint access for deletion
        self.try_borrow_storage_mut()?
            .record_write_access(&key, self, Some(k))?;

        // Mark as deleted in cache (None value indicates deletion)
        let budget = self.budget_ref();
        self.try_with_mut_data_cache(|cache| {
            cache.insert(
                key.metered_clone(budget)?,
                None,  // None indicates deleted entry
                budget,
            )
        })?;
        Ok(())
    }

    /// Checks if contract data exists, checking the cache chain (current frame →
    /// parent frame if same contract → global storage).
    pub(super) fn has_contract_data_in_ledger(
        &self,
        k: Val,
        t: StorageType,
    ) -> Result<bool, HostError> {
        let durability: ContractDataDurability = t.try_into()?;
        let key = self.storage_key_from_val(k, durability)?;

        // Check cache chain: current frame → parent frame (if same contract)
        if let Some(entry) = self.lookup_in_cache_chain(&key)? {
            // Found in cache - check if it has a value (Some = exists, None = deleted)
            return Ok(entry.is_some());
        }

        // Cache miss - check storage
        self.try_borrow_storage_mut()?.has(&key, self, Some(k))
    }

    /// Extends the TTL for contract data, checking the cache chain first.
    /// If the entry is found in the cache chain, updates the current frame's cache.
    /// If there is no frame context or the entry is not cached, extends via storage.
    pub(super) fn extend_contract_data_ttl_in_ledger(
        &self,
        k: Val,
        t: StorageType,
        threshold: u32,
        extend_to: u32,
    ) -> Result<(), HostError> {
        let durability: ContractDataDurability = t.try_into()?;
        let key = self.storage_key_from_val(k, durability)?;

        // Check cache chain for the entry
        let cached_entry = self.lookup_in_cache_chain(&key)?;

        if let Some(Some(CachedEntry::ContractData(val, current_live_until))) = cached_entry {
            // Entry is in cache chain - compute new live_until and update current frame's cache
            let ledger_seq: u32 = self.get_ledger_sequence()?.into();

            // Check if extension is needed (threshold check)
            if current_live_until.saturating_sub(ledger_seq) > threshold {
                // TTL is already above threshold, no extension needed
                return Ok(());
            }

            // Compute new live_until
            let mut new_live_until = self.with_ledger_info(|li| {
                li.sequence_number.checked_add(extend_to).ok_or_else(|| {
                    HostError::from(Error::from_type_and_code(
                        ScErrorType::Context,
                        ScErrorCode::InternalError,
                    ))
                })
            })?;

            // Clamp to max
            if new_live_until > self.max_live_until_ledger()? {
                if matches!(durability, ContractDataDurability::Persistent) {
                    new_live_until = self.max_live_until_ledger()?;
                } else {
                    return Err(self.err(
                        ScErrorType::Storage,
                        ScErrorCode::InvalidAction,
                        "new live_until for temp entry exceeds max",
                        &[],
                    ));
                }
            }

            // Update current frame's cache with new TTL
            let budget = self.budget_ref();
            self.try_with_mut_data_cache(|cache| {
                cache.insert(
                    key.metered_clone(budget)?,
                    Some(CachedEntry::ContractData(val, new_live_until)),
                    budget,
                )
            })?;
            Ok(())
        } else {
            // Entry not in cache or deleted - use storage directly
            self.try_borrow_storage_mut()?.extend_ttl(
                self,
                key,
                threshold,
                extend_to,
                Some(k),
            )
        }
    }
}

#[cfg(any(test, feature = "testutils"))]
use crate::crypto;
#[cfg(any(test, feature = "testutils"))]
use crate::storage::{AccessType, EntryWithLiveUntil, Footprint};

#[cfg(any(test, feature = "testutils"))]
impl Host {
    /// Writes an arbitrary ledger entry to storage.
    pub fn add_ledger_entry(
        &self,
        key: &Rc<LedgerKey>,
        val: &Rc<soroban_env_common::xdr::LedgerEntry>,
        live_until_ledger: Option<u32>,
    ) -> Result<(), HostError> {
        self.with_mut_storage(|storage| storage.put(key, val, live_until_ledger, self, None))
    }

    /// Reads an arbitrary ledger entry from the storage.
    ///
    /// Returns `None` if the entry does not exist.
    pub fn get_ledger_entry(
        &self,
        key: &Rc<LedgerKey>,
    ) -> Result<Option<EntryWithLiveUntil>, HostError> {
        self.with_mut_storage(|storage| storage.try_get_full(key, self, None))
    }

    /// Returns all the ledger entries stored in the storage as key-value pairs.
    #[allow(clippy::type_complexity)]
    pub fn get_stored_entries(
        &self,
    ) -> Result<Vec<(Rc<LedgerKey>, Option<CachedEntry>)>, HostError> {
        self.with_mut_storage(|storage| {
            Ok(storage
                .map
                .iter(self.as_budget())?
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect())
        })
    }

    // Performs the necessary setup to access the provided ledger key/entry in
    // enforcing storage mode.
    pub fn setup_storage_entry(
        &self,
        key: Rc<LedgerKey>,
        val: Option<(Rc<soroban_env_common::xdr::LedgerEntry>, Option<u32>)>,
        access_type: AccessType,
    ) -> Result<(), HostError> {
        self.with_mut_storage(|storage| {
            storage
                .footprint
                .record_access(&key, access_type, self.as_budget())?;
            // Convert to CachedEntry format
            let cached = match val {
                Some((entry, live_until)) => {
                    Some(CachedEntry::from_entry_with_live_until(&entry, live_until, self)?)
                }
                None => None,
            };
            storage.map.insert(key, cached, self.as_budget())?;
            Ok(())
        })
    }

    // Performs the necessary setup to access all the entries in provided
    // footprint in enforcing mode.
    // "testutils" are not covered by budget metering.
    pub fn setup_storage_footprint(&self, footprint: Footprint) -> Result<(), HostError> {
        for (key, access_type) in footprint.0.map {
            self.setup_storage_entry(key, None, access_type)?;
        }
        Ok(())
    }

    // Checks whether the given contract has a special 'dummy' executable
    // that marks contracts created with `register_test_contract`.
    pub(crate) fn is_test_contract_executable(
        &self,
        contract_id: &ContractId,
    ) -> Result<bool, HostError> {
        let key = self.contract_instance_ledger_key(contract_id)?;
        let instance = self.retrieve_contract_instance_from_storage(&key)?;
        let test_contract_executable = ContractExecutable::Wasm(
            crypto::sha256_hash_from_bytes(&[], self)?
                .try_into()
                .map_err(|_| {
                    self.err(
                        ScErrorType::Value,
                        ScErrorCode::InternalError,
                        "unexpected hash length",
                        &[],
                    )
                })?,
        );
        Ok(test_contract_executable == instance.executable)
    }

    #[cfg(test)]
    pub(crate) fn create_tl_asset_4(
        &self,
        asset_code: [u8; 4],
        issuer: AccountId,
    ) -> TrustLineAsset {
        use crate::xdr::{AlphaNum4, AssetCode4};
        TrustLineAsset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(asset_code),
            issuer,
        })
    }

    #[cfg(test)]
    pub(crate) fn create_tl_asset_12(
        &self,
        asset_code: [u8; 12],
        issuer: AccountId,
    ) -> TrustLineAsset {
        use crate::xdr::{AlphaNum12, AssetCode12};
        TrustLineAsset::CreditAlphanum12(AlphaNum12 {
            asset_code: AssetCode12(asset_code),
            issuer,
        })
    }
}
