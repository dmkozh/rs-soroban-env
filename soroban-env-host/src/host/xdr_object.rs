use core::cmp::Ordering;
use std::hash::{Hash, Hasher};
use std::ops::Deref;
use std::rc::Rc;

use crate::budget::{AsBudget, Budget};
use crate::host::metered_clone::{MeteredAlloc, MeteredClone};
use crate::xdr::ContractCostType;
use crate::{Compare, Host, HostError};

use super::declared_size::DeclaredSizeForMetering;

/// A wrapper around an XDR type `T` that caches the XDR-encoded byte size.
///
/// This enables O(1) budget charging for clone and compare operations:
/// instead of walking the type's substructure, we charge a single
/// MemAlloc+MemCpy (clone) or MemCmp (compare) based on the cached size.
///
/// Created when deserializing from XDR bytes (size known from input),
/// or via `compute_size` when building from Rust-side values.
#[derive(Debug)]
pub struct XdrObject<T> {
    inner: T,
    xdr_byte_size: u32,
}

impl<T> XdrObject<T> {
    /// Create from a value with known XDR byte size (e.g. just deserialized).
    pub fn new(inner: T, xdr_byte_size: u32) -> Self {
        Self {
            inner,
            xdr_byte_size,
        }
    }

    /// The cached XDR byte size.
    pub fn xdr_byte_size(&self) -> u32 {
        self.xdr_byte_size
    }
}

impl<T: Clone> Clone for XdrObject<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            xdr_byte_size: self.xdr_byte_size,
        }
    }
}

impl<T: Hash> Hash for XdrObject<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner.hash(state);
    }
}

impl<T> Deref for XdrObject<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.inner
    }
}

impl<T> AsRef<T> for XdrObject<T> {
    fn as_ref(&self) -> &T {
        &self.inner
    }
}

impl<T: std::fmt::Display> std::fmt::Display for XdrObject<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}

// --- Metering traits ---

impl<T: DeclaredSizeForMetering> DeclaredSizeForMetering for XdrObject<T> {
    const DECLARED_SIZE: u64 = T::DECLARED_SIZE + 4; // +4 for xdr_byte_size field
}

impl<T: Clone + DeclaredSizeForMetering> MeteredClone for XdrObject<T> {
    const IS_SHALLOW: bool = false;

    fn charge_for_substructure(&self, budget: &Budget) -> Result<(), HostError> {
        // Charge based on cached XDR size instead of walking substructure.
        budget.charge(ContractCostType::MemAlloc, Some(self.xdr_byte_size as u64))?;
        budget.charge(ContractCostType::MemCpy, Some(self.xdr_byte_size as u64))
    }
}

/// Compare<XdrObject<T>> charges a single MemCmp based on the cached
/// XDR size, then delegates to T::cmp for the actual comparison.
impl<T: Ord + DeclaredSizeForMetering> Compare<XdrObject<T>> for Budget {
    type Error = HostError;

    fn compare(&self, a: &XdrObject<T>, b: &XdrObject<T>) -> Result<Ordering, Self::Error> {
        let size = a.xdr_byte_size.max(b.xdr_byte_size) as u64;
        self.charge(ContractCostType::MemCmp, Some(size))?;
        Ok(a.inner.cmp(&b.inner))
    }
}

impl<T: Ord + DeclaredSizeForMetering> Compare<XdrObject<T>> for Host {
    type Error = HostError;

    fn compare(&self, a: &XdrObject<T>, b: &XdrObject<T>) -> Result<Ordering, Self::Error> {
        self.as_budget().compare(a, b)
    }
}

// Rc<XdrObject<T>> comparison delegates to XdrObject<T> comparison.
// (The blanket impl in soroban-env-common handles this for Compare<Rc<T>>.)

/// Create XdrObject by computing XDR size via serialization.
/// Use this when building from Rust-side values (not from XDR bytes).
pub fn xdr_object_from_value<T>(value: T, budget: &Budget) -> Result<XdrObject<T>, HostError>
where
    T: soroban_env_common::xdr::WriteXdr,
{
    use crate::DEFAULT_XDR_RW_LIMITS;
    // Compute size without metering (this is infrastructure overhead).
    let size = value
        .to_xdr(DEFAULT_XDR_RW_LIMITS)
        .map(|v| v.len() as u32)
        .unwrap_or(0);
    let _ = budget; // budget available if needed for future metering
    Ok(XdrObject::new(value, size))
}

/// Helper to create XdrObject from metered XDR deserialization.
#[allow(dead_code)]
pub fn metered_from_xdr_to_xdr_object<T>(
    bytes: &[u8],
    budget: &Budget,
) -> Result<XdrObject<T>, HostError>
where
    T: soroban_env_common::xdr::ReadXdr,
{
    let inner = crate::host::metered_xdr::metered_from_xdr_with_budget::<T>(bytes, budget)?;
    Ok(XdrObject::new(inner, bytes.len() as u32))
}

/// Helper to wrap in Rc with metering.
#[allow(dead_code)]
pub fn rc_metered_xdr_object<T: DeclaredSizeForMetering>(
    inner: T,
    xdr_byte_size: u32,
    budget: &Budget,
) -> Result<Rc<XdrObject<T>>, HostError> {
    Rc::metered_new(XdrObject::new(inner, xdr_byte_size), budget)
}
