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

use crate::host::metered_clone::{
    charge_shallow_copy, MeteredAlloc, MeteredClone, MeteredIterator,
};
use crate::host::metered_hash::MeteredHashMap;
use crate::host::metered_map::MeteredOrdMap;
use crate::{
    budget::Budget,
    ledger_info::get_key_durability,
    xdr::{
        ContractDataDurability, LedgerEntry, LedgerKey, ScContractInstance, ScErrorCode,
        ScErrorType, ScVal,
    },
    Env, Host, HostError, Val,
};

/// Computes the new live_until ledger for a TTL extension.
/// Returns `Ok(Some(new_live_until))` if extension should happen, `Ok(None)` if no extension needed.
/// Handles overflow check, max clamping for Persistent entries, and validation.
fn compute_extended_live_until(
    host: &Host,
    key: &LedgerKey,
    old_live_until: u32,
    threshold: u32,
    extend_to: u32,
    max_live_until: u32,
) -> Result<Option<u32>, HostError> {
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
            host.err(
                ScErrorType::Context,
                ScErrorCode::InternalError,
                "TTL extension overflow",
                &[],
            )
        })
    })?;

    if new_live_until > max_live_until {
        if let Some(durability) = get_key_durability(key) {
            if matches!(durability, ContractDataDurability::Persistent) {
                new_live_until = max_live_until;
            } else {
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

    // Only extend if new_live_until is greater and we're within threshold
    if new_live_until > old_live_until && old_live_until.saturating_sub(ledger_seq) <= threshold {
        Ok(Some(new_live_until))
    } else {
        Ok(None)
    }
}

/// Entry with optional live_until ledger for snapshot source compatibility.
/// Used by the SnapshotSource trait at the external interface boundary.
pub type EntryWithLiveUntil = (Rc<LedgerEntry>, Option<u32>);
/// Map from LedgerKey to optional LedgerEntry with live_until.
/// Used to track initial and final ledger state for computing ledger changes.
pub(crate) type LedgerEntryMap = MeteredHashMap<Rc<LedgerKey>, Option<EntryWithLiveUntil>>;

/// A helper type used to designate which ways a given [LedgerKey] is accessed,
/// or is allowed to be accessed, in a given transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum AccessType {
    /// When in recording mode, indicates that the [LedgerKey] is only read.
    /// When in enforcing mode, indicates that the [LedgerKey] is only _allowed_ to be read.
    ReadOnly,
    /// When in recording mode, indicates that the [LedgerKey] is written (and also possibly read)
    /// When in enforcing mode, indicates that the [LedgerKey] is _allowed_ to be written (and also allowed to be read).
    ReadWrite,
}

/// A single frame's TTL modification for a storage entry.
/// Stored in a separate stack from entry values to allow TTL-only updates
/// without cloning entry data.
#[derive(Clone, Hash)]
pub(crate) struct EntryTTLFrame {
    /// The frame depth at which this TTL was set (0 = ledger state).
    pub(crate) depth: u32,
    /// The live_until ledger for this entry.
    pub(crate) live_until: u32,
}

/// A single frame's modification of a storage entry value.
/// Contains the frame depth at which this modification was made and the value.
/// TTL is stored separately in EntryTTLFrame.
#[derive(Clone)]
pub(crate) struct StorageEntryFrame {
    /// The frame depth at which this value was set (0 = ledger state).
    pub(crate) depth: u32,
    /// The value at this depth. None means deleted or non-existent.
    pub(crate) value: Option<StorageLedgerEntryData>,
}

impl std::hash::Hash for StorageEntryFrame {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.depth.hash(state);
        self.value.as_ref().map(|v| v.hash(state));
    }
}

/// A storage entry containing footprint access type and sparse stacks of values and TTLs.
///
/// Uses two separate stacks for copy-on-write semantics:
/// - `entry_stack`: Contains per-frame value modifications
/// - `ttl_stack`: Contains per-frame TTL modifications
///
/// This separation allows TTL-only updates (extend_ttl) to push frames to ttl_stack
/// without cloning entry data, which is especially important for ReadOnly entries.
///
/// Invariant: ReadOnly entries must never push frames onto entry_stack.
/// The entry_stack for ReadOnly entries should only have the initial depth-0 frame.
///
/// Both stacks are sparse: entries are only added when a write occurs at a new depth.
#[derive(Clone)]
pub(crate) struct StorageEntry {
    /// The access type from the footprint (ReadOnly or ReadWrite).
    pub(crate) access_type: AccessType,
    /// Sparse stack of per-frame values. entry_stack[0] is initial state at depth 0.
    /// entry_stack.last() is always the current value.
    pub(crate) entry_stack: Vec<StorageEntryFrame>,
    /// Sparse stack of per-frame TTLs. Empty for entries without TTL (Account, Trustline).
    /// ttl_stack[0] is initial TTL at depth 0, ttl_stack.last() is current TTL.
    pub(crate) ttl_stack: Vec<EntryTTLFrame>,
}

impl std::hash::Hash for StorageEntry {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.access_type.hash(state);
        self.entry_stack.hash(state);
        self.ttl_stack.hash(state);
    }
}

impl StorageEntry {
    /// Creates a new StorageEntry with initial value at depth 0.
    ///
    /// # Arguments
    /// * `access_type` - ReadOnly or ReadWrite access from footprint
    /// * `value` - Optional tuple of (data, live_until), None means entry doesn't exist
    pub(crate) fn new(
        access_type: AccessType,
        value: Option<(StorageLedgerEntryData, Option<u32>)>,
    ) -> Self {
        let (entry_value, ttl_stack) = match value {
            Some((data, Some(live_until))) => (
                Some(data),
                vec![EntryTTLFrame {
                    depth: 0,
                    live_until,
                }],
            ),
            Some((data, None)) => (Some(data), vec![]),
            None => (None, vec![]),
        };
        Self {
            access_type,
            entry_stack: vec![StorageEntryFrame {
                depth: 0,
                value: entry_value,
            }],
            ttl_stack,
        }
    }

    /// Sets the base frame (depth 0) value.
    /// Used for initializing storage entries from ledger data.
    ///
    /// # Arguments
    /// * `data` - The entry data to set
    /// * `live_until` - Optional TTL for the entry
    pub(crate) fn set_base_frame_value(
        &mut self,
        data: StorageLedgerEntryData,
        live_until: Option<u32>,
    ) {
        if let Some(frame) = self.entry_stack.first_mut() {
            frame.value = Some(data);
        }
        if let Some(lu) = live_until {
            if self.ttl_stack.is_empty() {
                self.ttl_stack.push(EntryTTLFrame {
                    depth: 0,
                    live_until: lu,
                });
            } else if let Some(ttl_frame) = self.ttl_stack.first_mut() {
                ttl_frame.live_until = lu;
            }
        }
    }

    /// Clears the base frame (depth 0) value, used for expired temp entries.
    /// Sets entry value to None and clears the TTL stack.
    #[cfg(any(test, feature = "recording_mode"))]
    fn clear_base_frame(&mut self) {
        if let Some(frame) = self.entry_stack.first_mut() {
            frame.value = None;
        }
        self.ttl_stack.clear();
    }

    /// Updates the base frame (depth 0) TTL for auto-restore.
    /// Sets new TTL and upgrades access to ReadWrite.
    #[cfg(any(test, feature = "recording_mode"))]
    fn auto_restore_base_frame(&mut self, new_live_until: u32) {
        self.access_type = AccessType::ReadWrite;
        if self.ttl_stack.is_empty() {
            self.ttl_stack.push(EntryTTLFrame {
                depth: 0,
                live_until: new_live_until,
            });
        } else if let Some(ttl_frame) = self.ttl_stack.first_mut() {
            ttl_frame.live_until = new_live_until;
        }
    }

    /// Returns the current entry value (from top of entry_stack).
    /// Entry stack is never empty - guaranteed by constructor creating depth-0 frame.
    pub(crate) fn current_entry(&self, host: &Host) -> Result<&StorageEntryFrame, HostError> {
        self.entry_stack.last().ok_or_else(|| {
            host.err(
                ScErrorType::Storage,
                ScErrorCode::InternalError,
                "storage entry_stack is unexpectedly empty",
                &[],
            )
        })
    }

    /// Returns a mutable reference to the current entry frame.
    /// Entry stack is never empty - guaranteed by constructor creating depth-0 frame.
    fn current_entry_mut(&mut self, host: &Host) -> Result<&mut StorageEntryFrame, HostError> {
        self.entry_stack.last_mut().ok_or_else(|| {
            host.err(
                ScErrorType::Storage,
                ScErrorCode::InternalError,
                "storage entry_stack is unexpectedly empty",
                &[],
            )
        })
    }

    /// Returns the current TTL value, or None if entry has no TTL.
    pub(crate) fn current_ttl(&self) -> Option<u32> {
        self.ttl_stack.last().map(|f| f.live_until)
    }

    /// Pushes a new TTL frame onto the TTL stack if needed.
    /// If the current top of ttl_stack is at the same depth, modifies in-place.
    /// Otherwise, pushes a new frame (metered).
    ///
    /// Invariant: new frame depth must be strictly greater than current top depth.
    fn push_ttl_frame(&mut self, live_until: u32, host: &Host) -> Result<(), HostError> {
        let depth = host.current_frame_depth()?;
        if let Some(curr) = self.ttl_stack.last_mut() {
            if curr.depth == depth {
                // Same depth: modify in-place
                curr.live_until = live_until;
                return Ok(());
            }
            // Invariant: new depth must be strictly greater than current depth
            if depth <= curr.depth {
                return Err(host.err(
                    ScErrorType::Storage,
                    ScErrorCode::InternalError,
                    "ttl_stack depth invariant violated: new depth not greater than current",
                    &[depth.into(), curr.depth.into()],
                ));
            }
        } else {
            // No TTL stack yet - this shouldn't happen for entries that have TTL
            // but we handle it by creating the initial frame
            charge_shallow_copy::<EntryTTLFrame>(1, host)?;
            self.ttl_stack.push(EntryTTLFrame { depth, live_until });
            return Ok(());
        }
        // Different depth: push new frame (metered)
        charge_shallow_copy::<EntryTTLFrame>(1, host)?;
        self.ttl_stack.push(EntryTTLFrame { depth, live_until });
        Ok(())
    }

    /// Pushes a new entry frame onto the entry stack.
    /// If the current top of entry_stack is at the same depth, modifies in-place.
    /// Otherwise, pushes a new frame (metered).
    ///
    /// Invariant: ReadOnly entries must never push new frames onto entry_stack.
    /// Returns InternalError if attempting to push a new frame for a ReadOnly entry.
    fn push_entry_frame(
        &mut self,
        value: Option<StorageLedgerEntryData>,
        host: &Host,
    ) -> Result<(), HostError> {
        let depth = host.current_frame_depth()?;
        let curr = self.current_entry_mut(host)?;
        if curr.depth == depth {
            // Same depth: modify in-place (no allocation needed)
            curr.value = value;
            return Ok(());
        }
        // Extract depth before ending the mutable borrow
        let curr_depth = curr.depth;
        // Different depth: need to push new frame
        // Invariant: ReadOnly entries must never push new frames
        if self.access_type == AccessType::ReadOnly {
            return Err(host.err(
                ScErrorType::Storage,
                ScErrorCode::InternalError,
                "cannot push entry frame for ReadOnly entry",
                &[],
            ));
        }
        // Invariant: new depth must be strictly greater than current depth
        if depth <= curr_depth {
            return Err(host.err(
                ScErrorType::Storage,
                ScErrorCode::InternalError,
                "entry_stack depth invariant violated: new depth not greater than current",
                &[depth.into(), curr_depth.into()],
            ));
        }
        // Push new frame (metered)
        charge_shallow_copy::<StorageEntryFrame>(1, host)?;
        self.entry_stack.push(StorageEntryFrame { depth, value });
        Ok(())
    }

    /// Clones the current entry value for copy-on-write.
    /// For Entry variant, clones the inner LedgerEntry (metered).
    /// For ContractData variant, just copies the Val (cheap).
    fn clone_current_value_for_write(
        &self,
        host: &Host,
    ) -> Result<Option<StorageLedgerEntryData>, HostError> {
        let curr = self.current_entry(host)?;
        match &curr.value {
            Some(data) => {
                let cloned = match data {
                    StorageLedgerEntryData::ContractData(val) => {
                        StorageLedgerEntryData::ContractData(*val)
                    }
                    StorageLedgerEntryData::Entry(entry_rc) => {
                        let cloned_entry = entry_rc.borrow().metered_clone(host)?;
                        StorageLedgerEntryData::Entry(Rc::metered_new(
                            RefCell::new(cloned_entry),
                            host,
                        )?)
                    }
                };
                Ok(Some(cloned))
            }
            None => Ok(None),
        }
    }

    /// Modifies the current entry value at the current frame depth via a callback.
    ///
    /// If the current top of entry_stack is at the same depth as the host's current frame,
    /// calls the callback directly with `&mut curr`.
    ///
    /// Otherwise, clones the current value (deep clone for Entry, shallow for ContractData),
    /// pushes a new frame, then calls the callback with `&mut new_frame`.
    ///
    /// This provides copy-on-write semantics: callbacks can simply modify in-place
    /// without worrying about frame management.
    ///
    /// Invariant: entry_stack must not be empty (guaranteed by constructor).
    /// Invariant: ReadOnly entries cannot push new frames (will error if depth differs).
    fn modify_entry_at_current_depth<F, R>(&mut self, host: &Host, f: F) -> Result<R, HostError>
    where
        F: FnOnce(&mut StorageEntryFrame) -> Result<R, HostError>,
    {
        let depth = host.current_frame_depth()?;
        let curr_depth = self.current_entry(host)?.depth;

        if curr_depth == depth {
            // Same depth: modify in-place
            let curr = self.current_entry_mut(host)?;
            return f(curr);
        }

        // Different depth: need copy-on-write
        // Invariant: ReadOnly entries cannot push new frames
        if self.access_type == AccessType::ReadOnly {
            return Err(host.err(
                ScErrorType::Storage,
                ScErrorCode::InternalError,
                "cannot modify ReadOnly entry at different depth",
                &[],
            ));
        }

        // Clone the value for copy-on-write
        let cloned_value = self.clone_current_value_for_write(host)?;

        // Push new frame with cloned value (metered)
        charge_shallow_copy::<StorageEntryFrame>(1, host)?;
        self.entry_stack.push(StorageEntryFrame {
            depth,
            value: cloned_value,
        });

        // Now modify the newly pushed frame
        let new_curr = self.current_entry_mut(host)?;
        f(new_curr)
    }

    /// Writes a value at the current frame depth.
    /// If the current top of entry_stack is at the same depth, modifies in-place.
    /// Otherwise, pushes a new frame onto the entry_stack (metered).
    ///
    /// Invariant: entry_stack must not be empty (guaranteed by constructor).
    /// Invariant: ReadOnly entries cannot push new frames.
    fn write_entry(
        &mut self,
        value: Option<StorageLedgerEntryData>,
        host: &Host,
    ) -> Result<(), HostError> {
        self.push_entry_frame(value, host)
    }

    /// Writes a value and TTL at the current depth.
    /// Takes (StorageLedgerEntryData, Option<u32>) tuple or None.
    fn write_value(
        &mut self,
        value: Option<(StorageLedgerEntryData, Option<u32>)>,
        host: &Host,
    ) -> Result<(), HostError> {
        match value {
            Some((data, Some(live_until))) => {
                self.write_entry(Some(data), host)?;
                self.push_ttl_frame(live_until, host)?;
            }
            Some((data, None)) => {
                self.write_entry(Some(data), host)?;
                // No TTL - leave ttl_stack unchanged
            }
            None => {
                self.write_entry(None, host)?;
                // For deleted entries, clear TTL by not updating it
            }
        }
        Ok(())
    }

    /// Puts or updates a ContractData Val at the entry stack top.
    /// If current value exists, preserves its live_until; otherwise uses min live_until from host.
    /// Uses modify_entry_at_current_depth for frame management.
    /// Returns InternalError if entry is an Entry (not ContractData).
    ///
    /// Invariant: entry_stack must not be empty (guaranteed by constructor).
    fn put_or_update_val(
        &mut self,
        val: Val,
        durability: ContractDataDurability,
        host: &Host,
    ) -> Result<(), HostError> {
        // Check if entry has current TTL - if so, we preserve it and don't need to push TTL frame
        let needs_ttl_update = match &self.current_entry(host)?.value {
            Some(StorageLedgerEntryData::ContractData(_)) => {
                // Entry exists: preserve existing TTL, no TTL frame push needed
                self.current_ttl().is_none()
            }
            Some(StorageLedgerEntryData::Entry(_)) => {
                return Err(host.err(
                    ScErrorType::Storage,
                    ScErrorCode::InternalError,
                    "put_or_update_val called on Entry instead of ContractData",
                    &[],
                ));
            }
            None => {
                // New entry: will need TTL
                true
            }
        };

        // Modify entry value
        self.modify_entry_at_current_depth(host, |frame| {
            frame.value = Some(StorageLedgerEntryData::ContractData(val));
            Ok(())
        })?;

        // Only push TTL frame if entry didn't have one
        if needs_ttl_update {
            let default_live_until = host.get_min_live_until_ledger(durability)?;
            self.push_ttl_frame(default_live_until, host)?;
        }
        Ok(())
    }

    /// Updates the TTL (live_until) of an entry.
    /// Pushes to ttl_stack only - no entry cloning occurs.
    /// This is the key optimization for ReadOnly entries.
    /// Returns InternalError if entry is None/deleted.
    ///
    /// Invariant: entry_stack must not be empty (guaranteed by constructor).
    fn update_ttl(&mut self, live_until: u32, host: &Host) -> Result<(), HostError> {
        // Verify entry exists
        if self.current_entry(host)?.value.is_none() {
            return Err(host.err(
                ScErrorType::Storage,
                ScErrorCode::InternalError,
                "cannot update TTL of deleted entry",
                &[],
            ));
        }
        // Push TTL frame - no entry cloning needed!
        self.push_ttl_frame(live_until, host)
    }

    /// Upgrades the entry from ReadOnly to ReadWrite access type.
    /// This is needed in recording mode when an entry that was initially loaded for
    /// reading needs to be modified.
    #[cfg(any(test, feature = "recording_mode"))]
    fn upgrade_to_read_write(&mut self) {
        self.access_type = AccessType::ReadWrite;
    }

    /// Modifies a LedgerEntry in-place via a callback.
    /// Uses modify_entry_at_current_depth for frame management and copy-on-write.
    /// Returns InternalError if entry is ContractData or None/deleted.
    ///
    /// Invariant: entry_stack must not be empty (guaranteed by constructor).
    fn modify_entry<F, R>(&mut self, host: &Host, f: F) -> Result<R, HostError>
    where
        F: FnOnce(&mut LedgerEntry) -> Result<R, HostError>,
    {
        self.modify_entry_at_current_depth(host, |frame| match &mut frame.value {
            Some(StorageLedgerEntryData::Entry(entry_rc)) => {
                let mut borrowed = entry_rc.borrow_mut();
                f(&mut borrowed)
            }
            Some(StorageLedgerEntryData::ContractData(_)) => Err(host.err(
                ScErrorType::Storage,
                ScErrorCode::InternalError,
                "cannot modify ContractData as LedgerEntry",
                &[],
            )),
            None => Err(host.err(
                ScErrorType::Storage,
                ScErrorCode::InternalError,
                "cannot modify deleted entry",
                &[],
            )),
        })
    }

    /// Helper to commit or rollback a single stack.
    /// The `allow_empty_after_rollback` parameter controls whether the stack can become
    /// empty after a rollback (true for ttl_stack, false for entry_stack).
    fn commit_or_rollback_stack<T>(
        stack: &mut Vec<T>,
        get_depth: impl Fn(&T) -> u32,
        set_depth: impl Fn(&mut T, u32),
        rollback: bool,
        depth: u32,
        host: &Host,
        stack_name: &str,
        allow_empty_after_rollback: bool,
    ) -> Result<(), HostError> {
        if stack.is_empty() {
            return Ok(());
        }

        let curr_depth = get_depth(stack.last().unwrap());

        // Invariant: entry depth must never exceed host frame depth
        if curr_depth > depth {
            return Err(host.err(
                ScErrorType::Storage,
                ScErrorCode::InternalError,
                &format!("storage {} depth exceeds host frame depth", stack_name),
                &[curr_depth.into(), depth.into()],
            ));
        }

        if curr_depth != depth {
            // This stack wasn't modified at the current depth, nothing to do
            return Ok(());
        }

        if rollback {
            // Rollback: pop the top frame to restore previous state.
            // For entry_stack: must have at least 2 frames (can't become empty)
            // For ttl_stack: can become empty if allow_empty_after_rollback is true
            if stack.len() < 2 && !allow_empty_after_rollback {
                return Err(host.err(
                    ScErrorType::Storage,
                    ScErrorCode::InternalError,
                    &format!("cannot rollback {} with only initial frame", stack_name),
                    &[],
                ));
            }
            stack.pop();
        } else {
            // Commit: decrement the depth of the current frame.
            if let Some(curr) = stack.last_mut() {
                if depth > 0 {
                    set_depth(curr, depth - 1);
                }
            }
            // After decrementing, check if we should merge with the frame below.
            if stack.len() >= 2 {
                let len = stack.len();
                let new_top_depth = get_depth(&stack[len - 1]);
                let below_depth = get_depth(&stack[len - 2]);
                if new_top_depth == below_depth {
                    // Merge: the top value supersedes the one below.
                    let top_frame = stack.pop().ok_or_else(|| {
                        host.err(
                            ScErrorType::Storage,
                            ScErrorCode::InternalError,
                            &format!("{} unexpectedly empty during merge", stack_name),
                            &[],
                        )
                    })?;
                    // Pop the frame below (which we're replacing)
                    stack.pop();
                    // Re-push the top frame
                    stack.push(top_frame);
                }
            }
        }
        Ok(())
    }

    /// Commits or rolls back changes at the current host frame depth.
    ///
    /// Operates on both entry_stack and ttl_stack independently:
    /// - On rollback: pops the top frame if it's at the current depth
    /// - On commit: decrements depth and optionally merges with frame below
    ///
    /// Invariant: entry_stack must not be empty (guaranteed by constructor).
    /// Invariant: current entry depth must never exceed host frame depth.
    fn commit_or_rollback(&mut self, rollback: bool, host: &Host) -> Result<(), HostError> {
        let depth = host.current_frame_depth()?;

        // Commit/rollback entry stack (cannot become empty)
        Self::commit_or_rollback_stack(
            &mut self.entry_stack,
            |f| f.depth,
            |f, d| f.depth = d,
            rollback,
            depth,
            host,
            "entry_stack",
            false, // entry_stack cannot become empty
        )?;

        // Commit/rollback TTL stack (can become empty after rollback)
        Self::commit_or_rollback_stack(
            &mut self.ttl_stack,
            |f| f.depth,
            |f, d| f.depth = d,
            rollback,
            depth,
            host,
            "ttl_stack",
            true, // ttl_stack can become empty
        )?;

        Ok(())
    }

    /// Resets the entry to a specified value at depth 0.
    /// Used for nonce reset in testutils.
    /// Clears both stacks and sets initial state.
    #[cfg(any(test, feature = "testutils"))]
    pub(crate) fn reset_to_none_at_depth_zero(&mut self) {
        self.entry_stack.clear();
        self.entry_stack.push(StorageEntryFrame {
            depth: 0,
            value: None,
        });
        self.ttl_stack.clear();
    }
}

/// The storage map type.
pub(crate) type StorageMap = MeteredHashMap<Rc<LedgerKey>, StorageEntry>;

/// The raw data portion of a storage entry, without TTL or access guard.
///
/// This enum provides a uniform representation for ledger entry data:
/// - `ContractData`: Stores the value as `Val`. The `Val` form avoids repeated
///   ScVal<->Val conversions on each read/write from contract code.
///   Contract instance is a special case stored as `Entry` instead.
/// - `Entry`: Stores other entry types (ContractCode, Account, Trustline,
///    contract instance) as a RefCell for in-place mutation.
#[derive(Clone)]
pub(crate) enum StorageLedgerEntryData {
    /// Contract data value (not instance).
    ContractData(Val),
    /// Other entry types: ContractCode, Account, Trustline, contract instance.
    /// Uses Rc<RefCell<_>> for in-place mutation and fast Rc cloning.
    Entry(Rc<RefCell<LedgerEntry>>),
}

impl StorageLedgerEntryData {
    /// Reconstructs a LedgerEntry from this StorageLedgerEntryData given the key.
    /// For Entry variant, clones the inner entry.
    /// For ContractData variant, builds a new LedgerEntry from the key and value.
    pub(crate) fn to_ledger_entry(
        &self,
        key: &LedgerKey,
        host: &Host,
    ) -> Result<LedgerEntry, HostError> {
        use crate::xdr::{
            ContractDataEntry, LedgerEntryData, LedgerEntryExt, LedgerKeyContractData,
        };
        match self {
            StorageLedgerEntryData::Entry(entry) => entry.borrow().metered_clone(host),
            StorageLedgerEntryData::ContractData(val) => {
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
                            contract: contract.metered_clone(host)?,
                            key: data_key.metered_clone(host)?,
                            durability: *durability,
                            val: sc_val,
                        }),
                        ext: LedgerEntryExt::V0,
                    })
                } else {
                    Err(host.err(
                        ScErrorType::Storage,
                        ScErrorCode::InternalError,
                        "ContractData storage entry has non-ContractData key",
                        &[],
                    ))
                }
            }
        }
    }

    /// Creates a StorageLedgerEntryData from a LedgerEntry.
    /// For ContractData entries (except contract instance data), converts the ScVal to Val.
    /// For contract instance data and other entry types, stores as Entry.
    pub(crate) fn from_ledger_entry(entry: &LedgerEntry, host: &Host) -> Result<Self, HostError> {
        use crate::xdr::LedgerEntryData;
        match &entry.data {
            LedgerEntryData::ContractData(contract_data) => {
                // Check if this is contract instance data or nonce data - these are not
                // Val-representable because LedgerKeyContractInstance and LedgerKeyNonce
                // cannot be converted to Val.
                if matches!(contract_data.key, ScVal::LedgerKeyContractInstance)
                    || matches!(contract_data.val, ScVal::ContractInstance(_))
                {
                    // Store as Entry - don't try to convert to Val
                    return Ok(StorageLedgerEntryData::Entry(Rc::metered_new(
                        RefCell::new(entry.metered_clone(host)?),
                        host,
                    )?));
                }

                // Convert ScVal to Val for efficient access
                let val = host.to_valid_host_val(&contract_data.val)?;
                Ok(StorageLedgerEntryData::ContractData(val))
            }
            _ => {
                // Other entry types are stored as Entry variant
                Ok(StorageLedgerEntryData::Entry(Rc::metered_new(
                    RefCell::new(entry.metered_clone(host)?),
                    host,
                )?))
            }
        }
    }
}

impl std::hash::Hash for StorageLedgerEntryData {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
        match self {
            StorageLedgerEntryData::ContractData(val) => {
                val.get_payload().hash(state);
            }
            StorageLedgerEntryData::Entry(entry) => {
                // Hash the Rc pointer address for determinism
                Rc::as_ptr(entry).hash(state);
            }
        }
    }
}

/// Optimized representation of a `LedgerEntry` in storage.
///
/// This enum provides a uniform representation for ledger entries:
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
            Some(Some((entry, live_until))) => Ok(Some((Rc::clone(entry), *live_until))),
            Some(None) | None => Ok(None),
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
/// through the use of access types stored in each [StorageEntry].
///
/// This unified implementation stores both access type information and per-entry
/// value stacks in a single map. Each entry tracks:
/// - Its access type (ReadOnly/ReadWrite)
/// - A sparse stack of values at different frame depths
///
/// Reading only requires a single map lookup, then reading `stack.last()`.
/// Writing checks if the top of stack is at current depth (modify in-place)
/// or pushes a new frame.
///
/// Access to each [LedgerKey] is mediated by the [FootprintMode],
/// which may be in either [FootprintMode::Recording] or
/// [FootprintMode::Enforcing] mode.
///
/// [FootprintMode::Recording] mode is used to calculate access types during
/// "preflight" execution of a contract. Once calculated, the recorded access types
/// can be provided to "real" execution, which always runs in
/// [FootprintMode::Enforcing] mode and enforces partitioned access.
#[derive(Clone, Default)]
pub struct Storage {
    pub(crate) mode: FootprintMode,
    /// The storage map containing access types and per-entry value stacks.
    pub(crate) map: StorageMap,
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
    /// pre-populated storage map.
    #[cfg(test)]
    pub(crate) fn with_enforcing_footprint_and_map(map: StorageMap) -> Self {
        Self {
            mode: FootprintMode::Enforcing,
            map,
        }
    }

    /// Constructs a new [Storage] in [FootprintMode::Enforcing] with a
    /// pre-populated storage map. The map should contain all entries from
    /// the transaction footprint with their access types set.
    pub(crate) fn with_enforcing_footprint_and_map_internal(map: StorageMap) -> Self {
        Self {
            mode: FootprintMode::Enforcing,
            map,
        }
    }

    /// Constructs a new [Storage] in [FootprintMode::Recording] using a
    /// given [SnapshotSource].
    #[cfg(any(test, feature = "recording_mode"))]
    pub fn with_recording_footprint(src: Rc<dyn SnapshotSource>) -> Self {
        Self {
            mode: FootprintMode::Recording(src),
            map: Default::default(),
        }
    }

    /// Canonical read accessor for storage entries.
    ///
    /// Handles key validation, recording-mode lazy loading, and expiration.
    /// Calls the callback with `Some((&StorageLedgerEntryData, Option<u32>))` if
    /// the entry exists, or `None` for deleted/non-existent entries.
    ///
    /// This is the single `self.map.get` call site for reads (besides test-only `get_from_map`).
    fn with_entry_for_read<F, R>(
        &mut self,
        key: &Rc<LedgerKey>,
        host: &Host,
        key_val: Option<Val>,
        f: F,
    ) -> Result<R, HostError>
    where
        F: FnOnce(Option<(&StorageLedgerEntryData, Option<u32>)>) -> Result<R, HostError>,
    {
        let _span = tracy_span!("storage get");
        Self::check_supported_ledger_key_type(key)?;
        // In recording mode, this loads from snapshot and handles expiration.
        #[cfg(any(test, feature = "recording_mode"))]
        self.maybe_prepare_recording_mode_access(key, host)?;
        // Single lookup path for both modes
        match self.map.get(key, host.budget_ref())? {
            None => {
                // Key not in map means it wasn't in the footprint
                Err(host.storage_error_exceeds_footprint(key, key_val))
            }
            Some(storage_entry) => {
                let frame = storage_entry.current_entry(host)?;
                match &frame.value {
                    Some(data) => f(Some((data, storage_entry.current_ttl()))),
                    None => f(None),
                }
            }
        }
    }

    /// Gets a contract data Val via callback.
    ///
    /// Returns InternalError if the entry is not a ContractData variant.
    pub(crate) fn with_contract_data_val<F, R>(
        &mut self,
        key: &Rc<LedgerKey>,
        host: &Host,
        key_val: Option<Val>,
        f: F,
    ) -> Result<R, HostError>
    where
        F: FnOnce(Option<Val>) -> Result<R, HostError>,
    {
        self.with_entry_for_read(key, host, key_val, |opt| match opt {
            Some((StorageLedgerEntryData::ContractData(val), _)) => f(Some(*val)),
            Some((StorageLedgerEntryData::Entry(_), _)) => Err(host.err(
                ScErrorType::Storage,
                ScErrorCode::InternalError,
                "expected ContractData, got Entry",
                &[],
            )),
            None => f(None),
        })
    }

    /// Gets a LedgerEntry via callback.
    ///
    /// For Entry variants, borrows from the internal `Rc<RefCell<LedgerEntry>>`.
    /// For ContractData variants, returns InternalError (use `with_contract_data_val` instead).
    pub(crate) fn with_ledger_entry<F, R>(
        &mut self,
        key: &Rc<LedgerKey>,
        host: &Host,
        key_val: Option<Val>,
        f: F,
    ) -> Result<R, HostError>
    where
        F: FnOnce(Option<&LedgerEntry>) -> Result<R, HostError>,
    {
        self.with_entry_for_read(key, host, key_val, |opt| match opt {
            Some((StorageLedgerEntryData::Entry(entry_rc), _)) => f(Some(&entry_rc.borrow())),
            Some((StorageLedgerEntryData::ContractData(_), _)) => Err(host.err(
                ScErrorType::Storage,
                ScErrorCode::InternalError,
                "expected Entry, got ContractData",
                &[],
            )),
            None => f(None),
        })
    }

    /// Gets a LedgerEntry Rc via callback (for cases needing ownership).
    ///
    /// For Entry variants, clones the `Rc<RefCell<LedgerEntry>>`.
    /// For ContractData variants, returns InternalError.
    pub(crate) fn with_ledger_entry_rc<F, R>(
        &mut self,
        key: &Rc<LedgerKey>,
        host: &Host,
        key_val: Option<Val>,
        f: F,
    ) -> Result<R, HostError>
    where
        F: FnOnce(Option<Rc<RefCell<LedgerEntry>>>) -> Result<R, HostError>,
    {
        self.with_entry_for_read(key, host, key_val, |opt| match opt {
            Some((StorageLedgerEntryData::Entry(entry_rc), _)) => f(Some(Rc::clone(entry_rc))),
            Some((StorageLedgerEntryData::ContractData(_), _)) => Err(host.err(
                ScErrorType::Storage,
                ScErrorCode::InternalError,
                "expected Entry, got ContractData",
                &[],
            )),
            None => f(None),
        })
    }

    /// Returns the live_until ledger for an entry, or None if the entry doesn't exist.
    /// Returns an error for out-of-footprint access or other storage errors.
    /// This is a test-only helper for TTL verification.
    #[cfg(any(test, feature = "testutils"))]
    pub(crate) fn get_live_until(
        &mut self,
        key: &Rc<LedgerKey>,
        host: &Host,
        key_val: Option<Val>,
    ) -> Result<Option<u32>, HostError> {
        self.with_entry_for_read(key, host, key_val, |opt| {
            Ok(opt.map(|(_, live_until)| live_until).flatten())
        })
    }

    /// Gets a ledger entry with its live_until for external interface use.
    ///
    /// This materializes ContractData entries back to LedgerEntry format.
    /// Use typed helpers (with_contract_data_val, with_ledger_entry) for internal code.
    #[cfg(any(test, feature = "testutils"))]
    pub(crate) fn try_get_full(
        &mut self,
        key: &Rc<LedgerKey>,
        host: &Host,
        key_val: Option<Val>,
    ) -> Result<Option<EntryWithLiveUntil>, HostError> {
        self.with_entry_for_read(key, host, key_val, |opt| match opt {
            Some((data, live_until)) => {
                let entry = data.to_ledger_entry(key, host)?;
                Ok(Some((Rc::metered_new(entry, host)?, live_until)))
            }
            None => Ok(None),
        })
    }

    /// Mode-agnostic entry access helper for write operations.
    ///
    /// Handles key validation, expired entry handling, mode dispatch, and access
    /// checking, then calls the callback with `&mut StorageEntry`.
    ///
    /// In recording mode, if the entry doesn't exist in the map, it loads from
    /// the snapshot and inserts it before calling the callback.
    ///
    /// Returns whatever the callback returns.
    fn with_mut_entry<F, R>(
        &mut self,
        key: &Rc<LedgerKey>,
        host: &Host,
        key_val: Option<Val>,
        f: F,
    ) -> Result<R, HostError>
    where
        F: FnOnce(&mut StorageEntry) -> Result<R, HostError>,
    {
        Self::check_supported_ledger_key_type(key)?;

        // In recording mode, this loads from snapshot and handles expiration.
        #[cfg(any(test, feature = "recording_mode"))]
        self.maybe_prepare_recording_mode_access(key, host)?;

        let budget = host.budget_ref();

        // Single lookup for both modes
        let storage_entry = self
            .map
            .get_mut(key, budget)?
            .ok_or_else(|| host.storage_error_exceeds_footprint(key, key_val))?;

        // In enforcing mode, check ReadWrite access.
        // In recording mode, upgrade to ReadWrite.
        match &self.mode {
            #[cfg(any(test, feature = "recording_mode"))]
            FootprintMode::Recording(_) => {
                storage_entry.upgrade_to_read_write();
            }
            FootprintMode::Enforcing => {
                if storage_entry.access_type == AccessType::ReadOnly {
                    return Err(host.storage_error_readonly(key, key_val));
                }
            }
        }
        f(storage_entry)
    }

    /// Puts or updates a ContractData Val in a single map lookup.
    /// If entry exists with a value, preserves its live_until; otherwise uses min live_until from host.
    /// Handles access enforcement and delegates to StorageEntry::put_or_update_val.
    pub(crate) fn put_or_update_val(
        &mut self,
        key: &Rc<LedgerKey>,
        val: Val,
        durability: ContractDataDurability,
        host: &Host,
        key_val: Option<Val>,
    ) -> Result<(), HostError> {
        self.with_mut_entry(key, host, key_val, |storage_entry| {
            storage_entry.put_or_update_val(val, durability, host)
        })
    }

    /// Modifies a LedgerEntry via a callback, handling the case where
    /// the entry doesn't exist. The callback receives `Some(&mut LedgerEntry)`
    /// if the entry exists, or `None` if it doesn't.
    ///
    /// Uses copy-on-write semantics when the entry exists.
    pub(crate) fn modify_entry<F, R>(
        &mut self,
        key: &Rc<LedgerKey>,
        host: &Host,
        key_val: Option<Val>,
        f: F,
    ) -> Result<R, HostError>
    where
        F: FnOnce(Option<&mut LedgerEntry>) -> Result<R, HostError>,
    {
        self.with_mut_entry(key, host, key_val, |storage_entry| {
            // Check if the entry value is None (deleted)
            if storage_entry.current_entry(host)?.value.is_none() {
                return f(None);
            }
            storage_entry.modify_entry(host, |entry| f(Some(entry)))
        })
    }

    // Helper function for putting entry data directly into the map.
    // Uses the storage map with per-entry stacks and lazy writes.
    fn put_storage_entry_helper(
        &mut self,
        key: &Rc<LedgerKey>,
        val: Option<(StorageLedgerEntryData, Option<u32>)>,
        host: &Host,
        key_val: Option<Val>,
    ) -> Result<(), HostError> {
        self.with_mut_entry(key, host, key_val, |storage_entry| {
            storage_entry.write_value(val, host)
        })
    }

    /// Puts entry data directly into the storage map.
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
        val: Option<(StorageLedgerEntryData, Option<u32>)>,
        host: &Host,
        key_val: Option<Val>,
    ) -> Result<(), HostError> {
        let _span = tracy_span!("storage put");
        self.put_storage_entry_helper(key, val, host, key_val)
    }

    /// Deletes an entry by marking it as deleted (None) in the storage map.
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
        self.put(key, None, host, key_val)
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
        self.with_entry_for_read(key, host, key_val, |opt| Ok(opt.is_some()))
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

        // In recording mode, this loads from snapshot and handles expiration.
        #[cfg(any(test, feature = "recording_mode"))]
        self.maybe_prepare_recording_mode_access(&key, host)?;

        let budget = host.budget_ref();
        let max_live_until = host.max_live_until_ledger()?;

        // Single lookup: get_mut to read live_until and potentially update
        let storage_entry = self.map.get_mut(&key, budget)?.ok_or_else(|| {
            // Key not in map means it wasn't in the footprint
            host.storage_error_exceeds_footprint(&key, key_val)
        })?;

        let frame = storage_entry.current_entry(host)?;
        if frame.value.is_none() {
            return Err(host.storage_error_missing_value(&key, key_val));
        }
        let old_live_until = storage_entry.current_ttl().ok_or_else(|| {
            host.err(
                ScErrorType::Storage,
                ScErrorCode::InternalError,
                "trying to extend invalid entry",
                &[],
            )
        })?;

        if let Some(new_live_until) = compute_extended_live_until(
            host,
            &key,
            old_live_until,
            threshold,
            extend_to,
            max_live_until,
        )? {
            storage_entry.update_ttl(new_live_until, host)?;
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

    // Test-only helper for getting the storage entry directly from the storage map,
    // without the footprint management and autorestoration.
    // Returns (entry, live_until) tuple.
    #[cfg(any(test, feature = "testutils"))]
    pub(crate) fn get_from_map(
        &self,
        key: &Rc<LedgerKey>,
        host: &Host,
    ) -> Result<Option<(StorageLedgerEntryData, Option<u32>)>, HostError> {
        match self.map.get(key, host.budget_ref())? {
            Some(storage_entry) => {
                let frame = storage_entry.current_entry(host)?;
                match &frame.value {
                    Some(entry) => Ok(Some((entry.clone(), storage_entry.current_ttl()))),
                    None => Ok(None),
                }
            }
            None => Ok(None),
        }
    }

    /// In recording mode: ensures the entry is in the storage map, handling
    /// snapshot loading and expiration logic in one pass.
    ///
    /// After this call, the entry will be in the map with its final state:
    /// - Expired temporary entries: None value, no TTL
    /// - Expired persistent entries: original value, auto-restored TTL, ReadWrite access
    /// - Live entries: original value and TTL
    /// - Non-existent entries: None value, no TTL
    #[cfg(any(test, feature = "recording_mode"))]
    fn maybe_prepare_recording_mode_access(
        &mut self,
        key: &Rc<LedgerKey>,
        host: &Host,
    ) -> Result<(), HostError> {
        let src = match &self.mode {
            FootprintMode::Recording(src) => Rc::clone(src),
            FootprintMode::Enforcing => return Ok(()),
        };

        let budget = host.budget_ref();

        // Check if entry is already in map
        if let Some(storage_entry) = self.map.get_mut(key, budget)? {
            return Self::handle_expiration_for_existing_entry(storage_entry, key, host);
        }

        // Entry not in map - load from snapshot and insert
        self.load_entry_from_snapshot(key, &src, host)
    }

    /// Handles expiration for an entry that's already in the storage map.
    /// Called when ledger sequence may have advanced since the entry was loaded.
    ///
    /// Ledger sequence can only advance between top-level calls in recording mode,
    /// so we verify the entry stack is at its base state (depth 0) and update it directly.
    #[cfg(any(test, feature = "recording_mode"))]
    fn handle_expiration_for_existing_entry(
        storage_entry: &mut StorageEntry,
        key: &Rc<LedgerKey>,
        host: &Host,
    ) -> Result<(), HostError> {
        let Some(durability) = get_key_durability(key.as_ref()) else {
            return Ok(());
        };

        let Some(live_until) = storage_entry.current_ttl() else {
            return Ok(());
        };

        // Check if current value is set (non-deleted entry)
        let frame = storage_entry.current_entry(host)?;
        if frame.value.is_none() {
            return Ok(());
        }

        // Capture the entry's current depth before the closure
        let entry_depth = frame.depth;

        host.with_ledger_info(|li| {
            if live_until >= li.sequence_number {
                // Entry is still live, nothing to do
                return Ok(());
            }

            // Entry has expired - verify entry is at its base state (only depth-0 frames).
            // If the entry has nested frames, something is wrong - the ledger sequence
            // shouldn't advance while an entry has uncommitted modifications.
            if entry_depth != 0 {
                return Err(host.err(
                    ScErrorType::Storage,
                    ScErrorCode::InternalError,
                    "entry expiration cannot occur with uncommitted modifications",
                    &[],
                ));
            }

            // Update base frame directly based on durability
            match durability {
                ContractDataDurability::Temporary => {
                    // Clear the base frame (treat as deleted)
                    storage_entry.clear_base_frame();
                }
                ContractDataDurability::Persistent => {
                    // Auto-restore: update base frame with new TTL
                    let new_live_until = li
                        .min_live_until_ledger_checked(ContractDataDurability::Persistent)
                        .ok_or_else(|| {
                            host.err(
                                ScErrorType::Storage,
                                ScErrorCode::InternalError,
                                "persistent entry TTL overflow, ledger is mis-configured",
                                &[],
                            )
                        })?;
                    storage_entry.auto_restore_base_frame(new_live_until);
                }
            }
            Ok(())
        })
    }

    /// Loads an entry from the snapshot and inserts it into the storage map.
    /// Handles expiration logic for the loaded entry.
    #[cfg(any(test, feature = "recording_mode"))]
    fn load_entry_from_snapshot(
        &mut self,
        key: &Rc<LedgerKey>,
        src: &Rc<dyn SnapshotSource>,
        host: &Host,
    ) -> Result<(), HostError> {
        let snapshot_value = src.get(key)?;
        let durability = get_key_durability(key.as_ref());

        // Compute final entry state based on snapshot value and expiration
        let (final_entry, access_type) =
            Self::compute_entry_state_from_snapshot(snapshot_value, durability, host)?;

        let storage_entry = StorageEntry::new(access_type, final_entry);
        self.map
            .insert(Rc::clone(key), storage_entry, host.budget_ref())?;
        Ok(())
    }

    /// Computes the final entry state from a snapshot value, handling expiration.
    #[cfg(any(test, feature = "recording_mode"))]
    fn compute_entry_state_from_snapshot(
        snapshot_value: Option<EntryWithLiveUntil>,
        durability: Option<ContractDataDurability>,
        host: &Host,
    ) -> Result<(Option<(StorageLedgerEntryData, Option<u32>)>, AccessType), HostError> {
        host.with_ledger_info(|li| {
            match snapshot_value {
                None => {
                    // Entry doesn't exist in snapshot - insert None with no TTL
                    Ok((None, AccessType::ReadOnly))
                }
                Some((ledger_entry, live_until_opt)) => {
                    // Check if entry is expired
                    match (durability, live_until_opt) {
                        (Some(dur), Some(live_until)) if live_until < li.sequence_number => {
                            // Entry is expired
                            Self::handle_expired_snapshot_entry(dur, &ledger_entry, li, host)
                        }
                        _ => {
                            // Entry is live (or doesn't have durability/TTL tracking)
                            let data =
                                StorageLedgerEntryData::from_ledger_entry(&ledger_entry, host)?;
                            Ok((Some((data, live_until_opt)), AccessType::ReadOnly))
                        }
                    }
                }
            }
        })
    }

    /// Handles an expired entry loaded from snapshot.
    #[cfg(any(test, feature = "recording_mode"))]
    fn handle_expired_snapshot_entry(
        durability: ContractDataDurability,
        ledger_entry: &LedgerEntry,
        li: &crate::LedgerInfo,
        host: &Host,
    ) -> Result<(Option<(StorageLedgerEntryData, Option<u32>)>, AccessType), HostError> {
        match durability {
            ContractDataDurability::Temporary => {
                // Expired temp entry: treat as non-existent
                Ok((None, AccessType::ReadOnly))
            }
            ContractDataDurability::Persistent => {
                // Expired persistent entry: auto-restore
                let new_live_until = li
                    .min_live_until_ledger_checked(ContractDataDurability::Persistent)
                    .ok_or_else(|| {
                        host.err(
                            ScErrorType::Storage,
                            ScErrorCode::InternalError,
                            "persistent entry TTL overflow, ledger is mis-configured",
                            &[],
                        )
                    })?;
                let data = StorageLedgerEntryData::from_ledger_entry(ledger_entry, host)?;
                Ok((Some((data, Some(new_live_until))), AccessType::ReadWrite))
            }
        }
    }

    /// Commits or rolls back all storage entries modified at the current depth.
    ///
    /// On rollback: for each entry where stack.last().depth == current_depth,
    /// pops the top frame to restore the previous state.
    ///
    /// On commit: for each entry where stack.last().depth == current_depth,
    /// decrements the depth (and merges with frame below if depths match).
    pub(crate) fn commit_or_rollback_frame(
        &mut self,
        rollback: bool,
        host: &Host,
    ) -> Result<(), HostError> {
        // Iterate over all entries and commit/rollback those at current depth
        for (_, entry) in self.map.iter_mut(host.budget_ref())? {
            entry.commit_or_rollback(rollback, host)?;
        }
        Ok(())
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

/// Returns a human-readable string describing the type of ledger key for error messages.
fn get_key_type_string_for_error(lk: &LedgerKey) -> &'static str {
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

use crate::budget::AsBudget;

impl Host {
    /// Creates an error for accessing a key outside of the footprint.
    /// Includes key type and key details in the error message.
    pub(crate) fn storage_error_exceeds_footprint(
        &self,
        lk: &LedgerKey,
        key_val: Option<Val>,
    ) -> HostError {
        let key_type_str = get_key_type_string_for_error(lk);
        // Use with_debug_mode_allowing_new_objects because ExceededLimit is non-recoverable,
        // so we can safely create new objects for the error message.
        let args = self
            .get_args_for_storage_error(lk, key_val, true)
            .unwrap_or_else(|_| vec![]);
        self.err(
            ScErrorType::Storage,
            ScErrorCode::ExceededLimit,
            &format!("trying to access {} outside of the footprint", key_type_str),
            args.as_slice(),
        )
    }

    /// Creates an error for trying to get a non-existing value.
    /// Includes key type and key details in the error message.
    pub(crate) fn storage_error_missing_value(
        &self,
        lk: &LedgerKey,
        key_val: Option<Val>,
    ) -> HostError {
        let key_type_str = get_key_type_string_for_error(lk);
        // For missing values we can only safely use existing Vals,
        // not create new objects.
        let args = self
            .get_args_for_storage_error(lk, key_val, false)
            .unwrap_or_else(|_| vec![]);
        self.err(
            ScErrorType::Storage,
            ScErrorCode::MissingValue,
            &format!("trying to get non-existing value for {}", key_type_str),
            args.as_slice(),
        )
    }

    /// Creates an error for trying to write to a read-only entry.
    /// Includes key type and key details in the error message.
    pub(crate) fn storage_error_readonly(&self, lk: &LedgerKey, key_val: Option<Val>) -> HostError {
        let key_type_str = get_key_type_string_for_error(lk);
        let args = self
            .get_args_for_storage_error(lk, key_val, true)
            .unwrap_or_else(|_| vec![]);
        self.err(
            ScErrorType::Storage,
            ScErrorCode::ExceededLimit,
            &format!("cannot write to read-only {}", key_type_str),
            args.as_slice(),
        )
    }

    /// Helper to get error arguments based on ledger key type.
    fn get_args_for_storage_error(
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
