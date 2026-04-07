#![allow(dead_code)]

use crate::{
    budget::{AsBudget, Budget},
    host::{
        metered_clone::{self, MeteredClone},
        metered_map::MeteredOrdMap,
        metered_vector::MeteredVector,
    },
    num::{I256, U256},
    xdr::{self, ContractCostType, ScErrorCode, ScErrorType, SCSYMBOL_LIMIT},
    AddressObject, BytesObject, Compare, DurationObject, DurationSmall, Host, HostError,
    I128Object, I128Small, I256Object, I256Small, I64Object, I64Small, MapObject,
    MuxedAddressObject, Object, StringObject, SymbolObject, SymbolSmall, SymbolStr,
    TimepointObject, TimepointSmall, TryFromVal, U128Object, U128Small, U256Object, U256Small,
    U64Object, U64Small, Val, VecObject,
};

pub(crate) type HostMap = MeteredOrdMap<Val, Val, Host>;
pub(crate) type HostVec = MeteredVector<Val>;

/// Cached metadata for a HostObject, computed at creation time.
/// Since HostObjects are immutable, these hints never go stale.
#[derive(Clone, Copy, Debug, Default, Hash)]
pub(crate) struct ObjectMeta {
    /// Approximate total XDR-encoded byte size of this object and all its
    /// owned data. Used to charge a single MemAlloc+MemCpy when converting
    /// Val→ScVal instead of per-element recursive charges.
    pub xdr_byte_size: u32,
    /// Maximum nesting depth. 0 for leaf objects, 1+ for containers.
    /// Enforced at creation time so runtime depth checks are unnecessary.
    pub depth: u32,
}

#[derive(Clone, Hash)]
pub(crate) enum HostObject {
    Vec(HostVec),
    Map(HostMap),
    U64(u64),
    I64(i64),
    TimePoint(xdr::TimePoint),
    Duration(xdr::Duration),
    U128(u128),
    I128(i128),
    U256(U256),
    I256(I256),
    Bytes(xdr::ScBytes),
    String(xdr::ScString),
    Symbol(xdr::ScSymbol),
    Address(xdr::ScAddress),
    MuxedAddress(MuxedScAddress),
}

impl std::fmt::Debug for HostObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Vec(arg0) => f.debug_tuple("Vec").field(&arg0.len()).finish(),
            Self::Map(arg0) => f.debug_tuple("Map").field(&arg0.len()).finish(),
            Self::U64(arg0) => f.debug_tuple("U64").field(arg0).finish(),
            Self::I64(arg0) => f.debug_tuple("I64").field(arg0).finish(),
            Self::TimePoint(arg0) => f.debug_tuple("TimePoint").field(arg0).finish(),
            Self::Duration(arg0) => f.debug_tuple("Duration").field(arg0).finish(),
            Self::U128(arg0) => f.debug_tuple("U128").field(arg0).finish(),
            Self::I128(arg0) => f.debug_tuple("I128").field(arg0).finish(),
            Self::U256(arg0) => f.debug_tuple("U256").field(arg0).finish(),
            Self::I256(arg0) => f.debug_tuple("I256").field(arg0).finish(),
            Self::Bytes(arg0) => f.debug_tuple("Bytes").field(arg0).finish(),
            Self::String(arg0) => f.debug_tuple("String").field(arg0).finish(),
            Self::Symbol(arg0) => f.debug_tuple("Symbol").field(arg0).finish(),
            Self::Address(arg0) => f.debug_tuple("Address").field(arg0).finish(),
            Self::MuxedAddress(arg0) => f.debug_tuple("MuxedAddress").field(arg0).finish(),
        }
    }
}

impl HostObject {
    // Temporarily performs a shallow comparison against a Val of the
    // associated small value type, returning None if the Val is of
    // the wrong type.
    pub(crate) fn try_compare_to_small(
        &self,
        budget: &Budget,
        rv: Val,
    ) -> Result<Option<core::cmp::Ordering>, HostError> {
        let res = match self {
            HostObject::U64(u) => {
                let Ok(small) = U64Small::try_from(rv) else {
                    return Ok(None);
                };
                let small: u64 = small.into();
                Some(budget.compare(u, &small)?)
            }
            HostObject::I64(i) => {
                let Ok(small) = I64Small::try_from(rv) else {
                    return Ok(None);
                };
                let small: i64 = small.into();
                Some(budget.compare(i, &small)?)
            }
            HostObject::TimePoint(tp) => {
                let Ok(small) = TimepointSmall::try_from(rv) else {
                    return Ok(None);
                };
                let small: u64 = small.into();
                Some(budget.compare(&tp.0, &small)?)
            }
            HostObject::Duration(d) => {
                let Ok(small) = DurationSmall::try_from(rv) else {
                    return Ok(None);
                };
                let small: u64 = small.into();
                Some(budget.compare(&d.0, &small)?)
            }
            HostObject::U128(u) => {
                let Ok(small) = U128Small::try_from(rv) else {
                    return Ok(None);
                };
                let small: u128 = small.into();
                Some(budget.compare(u, &small)?)
            }
            HostObject::I128(i) => {
                let Ok(small) = I128Small::try_from(rv) else {
                    return Ok(None);
                };
                let small: i128 = small.into();
                Some(budget.compare(i, &small)?)
            }
            HostObject::U256(u) => {
                let Ok(small) = U256Small::try_from(rv) else {
                    return Ok(None);
                };
                let small: U256 = small.into();
                Some(budget.compare(u, &small)?)
            }
            HostObject::I256(i) => {
                let Ok(small) = I256Small::try_from(rv) else {
                    return Ok(None);
                };
                let small: I256 = small.into();
                Some(budget.compare(i, &small)?)
            }
            HostObject::Symbol(s) => {
                let Ok(small) = SymbolSmall::try_from(rv) else {
                    return Ok(None);
                };
                let small: SymbolStr = small.into();
                let rhs: &[u8] = small.as_ref();
                Some(budget.compare(&s.as_vec().as_slice(), &rhs)?)
            }

            HostObject::Vec(_)
            | HostObject::Map(_)
            | HostObject::Bytes(_)
            | HostObject::String(_)
            | HostObject::Address(_)
            | HostObject::MuxedAddress(_) => None,
        };
        Ok(res)
    }

    /// Like `try_compare_to_small` but without budget charges.
    /// These are all trivial scalar comparisons that don't need metering.
    pub(crate) fn try_compare_to_small_unmetered(
        &self,
        rv: Val,
    ) -> Result<Option<core::cmp::Ordering>, HostError> {
        let res = match self {
            HostObject::U64(u) => {
                let Ok(small) = U64Small::try_from(rv) else {
                    return Ok(None);
                };
                let small: u64 = small.into();
                Some(u.cmp(&small))
            }
            HostObject::I64(i) => {
                let Ok(small) = I64Small::try_from(rv) else {
                    return Ok(None);
                };
                let small: i64 = small.into();
                Some(i.cmp(&small))
            }
            HostObject::TimePoint(tp) => {
                let Ok(small) = TimepointSmall::try_from(rv) else {
                    return Ok(None);
                };
                let small: u64 = small.into();
                Some(tp.0.cmp(&small))
            }
            HostObject::Duration(d) => {
                let Ok(small) = DurationSmall::try_from(rv) else {
                    return Ok(None);
                };
                let small: u64 = small.into();
                Some(d.0.cmp(&small))
            }
            HostObject::U128(u) => {
                let Ok(small) = U128Small::try_from(rv) else {
                    return Ok(None);
                };
                let small: u128 = small.into();
                Some(u.cmp(&small))
            }
            HostObject::I128(i) => {
                let Ok(small) = I128Small::try_from(rv) else {
                    return Ok(None);
                };
                let small: i128 = small.into();
                Some(i.cmp(&small))
            }
            HostObject::U256(u) => {
                let Ok(small) = U256Small::try_from(rv) else {
                    return Ok(None);
                };
                let small: U256 = small.into();
                Some(u.cmp(&small))
            }
            HostObject::I256(i) => {
                let Ok(small) = I256Small::try_from(rv) else {
                    return Ok(None);
                };
                let small: I256 = small.into();
                Some(i.cmp(&small))
            }
            HostObject::Symbol(s) => {
                let Ok(small) = SymbolSmall::try_from(rv) else {
                    return Ok(None);
                };
                let small: SymbolStr = small.into();
                let rhs: &[u8] = small.as_ref();
                Some(s.as_vec().as_slice().cmp(rhs))
            }

            HostObject::Vec(_)
            | HostObject::Map(_)
            | HostObject::Bytes(_)
            | HostObject::String(_)
            | HostObject::Address(_)
            | HostObject::MuxedAddress(_) => None,
        };
        Ok(res)
    }
}

pub(crate) trait HostObjectType: MeteredClone {
    type Wrapper: Into<Object>;
    fn new_from_handle(handle: u32) -> Self::Wrapper;
    fn inject(self, host: &Host) -> Result<HostObject, HostError>;
    fn try_extract(obj: &HostObject) -> Option<&Self>;
}

// Some host objects are "a slab of memory" which we want
// to treat fairly uniformly in memory-related host functions.
pub(crate) trait MemHostObjectType:
    HostObjectType + TryFrom<Vec<u8>, Error = xdr::Error> + Into<Vec<u8>>
{
    fn try_from_bytes(host: &Host, bytes: Vec<u8>) -> Result<Self, HostError>;
    fn as_byte_slice(&self) -> &[u8];
}

macro_rules! declare_host_object_type {
    ($TY:ty, $TAG:ident, $CASE:ident) => {
        impl HostObjectType for $TY {
            type Wrapper = $TAG;
            fn new_from_handle(handle: u32) -> Self::Wrapper {
                unsafe { $TAG::from_handle(handle) }
            }
            fn inject(self, _host: &Host) -> Result<HostObject, HostError> {
                Ok(HostObject::$CASE(self))
            }

            fn try_extract(obj: &HostObject) -> Option<&Self> {
                match obj {
                    HostObject::$CASE(v) => Some(v),
                    _ => None,
                }
            }
        }
    };
}

macro_rules! declare_mem_host_object_type {
    ($TY:ty, $TAG:ident, $CASE:ident) => {
        declare_host_object_type!($TY, $TAG, $CASE);
        impl MemHostObjectType for $TY {
            fn try_from_bytes(_host: &Host, bytes: Vec<u8>) -> Result<Self, HostError> {
                Self::try_from(bytes).map_err(Into::into)
            }

            fn as_byte_slice(&self) -> &[u8] {
                self.as_slice()
            }
        }
    };
}

// ${type of contained data}, ${object-wrapper common type}, ${case in HostObject}
declare_host_object_type!(HostMap, MapObject, Map);
declare_host_object_type!(HostVec, VecObject, Vec);
declare_host_object_type!(u64, U64Object, U64);
declare_host_object_type!(i64, I64Object, I64);
declare_host_object_type!(xdr::TimePoint, TimepointObject, TimePoint);
declare_host_object_type!(xdr::Duration, DurationObject, Duration);
declare_host_object_type!(u128, U128Object, U128);
declare_host_object_type!(i128, I128Object, I128);
declare_host_object_type!(U256, U256Object, U256);
declare_host_object_type!(I256, I256Object, I256);
declare_mem_host_object_type!(xdr::ScBytes, BytesObject, Bytes);
declare_mem_host_object_type!(xdr::ScString, StringObject, String);
declare_host_object_type!(xdr::ScSymbol, SymbolObject, Symbol);

impl HostObjectType for xdr::ScAddress {
    type Wrapper = AddressObject;
    fn new_from_handle(handle: u32) -> Self::Wrapper {
        unsafe { AddressObject::from_handle(handle) }
    }

    fn inject(self, host: &Host) -> Result<HostObject, HostError> {
        match &self {
            xdr::ScAddress::Account(_) | xdr::ScAddress::Contract(_) => {
                Ok(HostObject::Address(self))
            }
            _ => Err(host.err(
                ScErrorType::Object,
                ScErrorCode::InvalidInput,
                format!(
                    "encountered ScAddress variant not supported by AddressObject: {}",
                    self.discriminant()
                )
                .as_str(),
                &[],
            )),
        }
    }

    fn try_extract(obj: &HostObject) -> Option<&Self> {
        match obj {
            HostObject::Address(v) => Some(v),
            _ => None,
        }
    }
}

#[derive(Clone, Hash, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct MuxedScAddress(pub(crate) xdr::ScAddress);

impl HostObjectType for MuxedScAddress {
    type Wrapper = MuxedAddressObject;
    fn new_from_handle(handle: u32) -> Self::Wrapper {
        unsafe { MuxedAddressObject::from_handle(handle) }
    }

    fn inject(self, host: &Host) -> Result<HostObject, HostError> {
        match &self.0 {
            xdr::ScAddress::MuxedAccount(_) => Ok(HostObject::MuxedAddress(self)),
            _ => Err(host.err(
                ScErrorType::Object,
                ScErrorCode::InvalidInput,
                format!(
                    "encountered ScAddress variant not supported by AddressObject: {}",
                    self.0.discriminant()
                )
                .as_str(),
                &[],
            )),
        }
    }

    fn try_extract(obj: &HostObject) -> Option<&Self> {
        match obj {
            HostObject::MuxedAddress(v) => Some(v),
            _ => None,
        }
    }
}

impl MemHostObjectType for xdr::ScSymbol {
    fn try_from_bytes(host: &Host, bytes: Vec<u8>) -> Result<Self, HostError> {
        if bytes.len() as u64 > SCSYMBOL_LIMIT {
            return Err(host.err(
                ScErrorType::Value,
                ScErrorCode::InvalidInput,
                "slice is too long to be represented as Symbol",
                &[(bytes.len() as u32).into()],
            ));
        }
        for b in &bytes {
            SymbolSmall::validate_byte(*b).map_err(|_| {
                host.err(
                    ScErrorType::Value,
                    ScErrorCode::InvalidInput,
                    "byte is not allowed in Symbol",
                    &[(*b as u32).into()],
                )
            })?;
        }
        Self::try_from(bytes).map_err(Into::into)
    }
    fn as_byte_slice(&self) -> &[u8] {
        self.as_ref()
    }
}

// Objects come in two flavors: relative and absolute. They are differentiated
// by the low bit of the object handle: relative objects have 0, absolutes have
// 1. The remaining bits (left shifted by 1) are the index in a corresponding
// relative or absolute object table.
//
// Relative objects are the ones we pass to and from wasm/VM code, and are
// looked up in a per-VM-frame "relative objects" indirection table, to find an
// absolute object. Absolute objects are the underlying context-insensitive
// handles that point into the host object table (and so absolutes can also be
// used outside contexts, eg. in fields held in host objects themselves or while
// setting-up the host). Relative-to-absolute translation is done very close to
// the VM, when marshalling call args and return values (and host-function calls
// and returns). Host code should never see relative object handles, and if you
// ever try to look one up in the host object table, it will fail.
//
// The point of relative object handles is to isolate the objects seen by one VM
// from those seen by any other (and secondarily to avoid "system objects" like
// those allocated by the auth and event subsystems from perturbing object
// numbers seen by user code). User code should not perceive any objects other
// than ones they are specifically passed (or reachable through them). So their
// view of the world is limited to objects that made it into their relative
// object table.
//
// Also note: the relative/absolute object reference translation is _not_ done
// when running native contracts, either builtin or in local-testing mode, so
// you will not get identical object numbers in those cases. Since there is no
// real isolation between native contracts -- they can even dereference unsafe
// pointers if they want -- the lack of translation is not exactly making the
// security of native testing worse than it already is. But it does reduce the
// fidelity of VM-mode simulation in native testing mode. See
// https://github.com/stellar/rs-soroban-env/issues/1286 for a planned fix.

pub fn is_relative_object_handle(handle: u32) -> bool {
    handle & 1 == 0
}

pub fn handle_to_index(handle: u32) -> usize {
    (handle as usize) >> 1
}

pub fn index_to_handle(host: &Host, index: usize, relative: bool) -> Result<u32, HostError> {
    if let Ok(smaller) = u32::try_from(index) {
        if let Some(shifted) = smaller.checked_shl(1) {
            if relative {
                return Ok(shifted);
            } else {
                return Ok(shifted | 1);
            }
        }
    }
    Err(host.err_arith_overflow())
}

impl Host {
    pub(crate) fn relative_to_absolute(&self, val: Val) -> Result<Val, HostError> {
        if let Ok(obj) = Object::try_from(val) {
            let handle = obj.get_handle();
            return if is_relative_object_handle(handle) {
                let index = handle_to_index(handle);
                let abs_opt = self.with_current_frame_relative_object_table(|table| {
                    Ok(table.get(index).map(|x| *x))
                })?;
                match abs_opt {
                    Some(abs) if abs.to_val().get_tag() == val.get_tag() => Ok(abs.into()),
                    // User forged a type tag. This is _relatively_ harmless
                    // since we converted from relative to absolute and
                    // literally changed object references altogether while
                    // doing so -- i.e. we now have a correctly-typed absolute
                    // object reference we _could_ proceed to use as requested
                    // -- but a user passing an ill-typed relative object
                    // reference is probably either a bug or part of some
                    // strange type of attack, and in any case we _would_ signal
                    // this as an object-integrity type mismatch if we hadn't
                    // done the translation (eg. in native testing mode), so for
                    // symmetry sake we will return the same error here.
                    Some(_) => Err(self.err(
                        ScErrorType::Value,
                        ScErrorCode::InvalidInput,
                        "relative and absolute object types differ",
                        &[],
                    )),
                    // User is referring to something outside the bounds of
                    // their relative table, erroneously.
                    None => Err(self.err(
                        ScErrorType::Value,
                        ScErrorCode::InvalidInput,
                        "unknown relative object reference",
                        &[Val::from_u32(handle).to_val()],
                    )),
                }
            } else {
                // This also gets "invalid input" because it came from the user
                // VM: they tried to forge an absolute.
                Err(self.err(
                    ScErrorType::Value,
                    ScErrorCode::InvalidInput,
                    "relative_to_absolute given an absolute reference",
                    &[Val::from_u32(handle).to_val()],
                ))
            };
        }
        Ok(val)
    }

    pub(crate) fn absolute_to_relative(&self, val: Val) -> Result<Val, HostError> {
        if let Ok(obj) = Object::try_from(val) {
            let handle = obj.get_handle();
            return if is_relative_object_handle(handle) {
                // This gets "internal error" because we should never have found
                // ourselves in posession of a relative reference to return to
                // the user VM in the first place. Logic bug.
                Err(self.err(
                    ScErrorType::Context,
                    ScErrorCode::InternalError,
                    "absolute_to_relative given a relative reference",
                    // NB: we convert to a U32Val here otherwise the _events_ system
                    // will fault when trying to look up this argument as a relative
                    // object reference.
                    &[Val::from_u32(handle).to_val()],
                ))
            } else {
                // Push a new entry into the relative-objects vector.
                metered_clone::charge_heap_alloc::<Object>(1, self.as_budget())?;
                let index = self.with_current_frame_relative_object_table(|table| {
                    let index = table.len();
                    table.push(obj);
                    Ok(index)
                })?;
                let handle = index_to_handle(self, index, true)?;
                Ok(Object::from_handle_and_tag(handle, val.get_tag()).into())
            };
        }
        Ok(val)
    }

    /// Moves a value of some type implementing [`HostObjectType`] into the
    /// host's object array, returning the associated [`Object`] wrapper type
    /// containing the new object's handle.
    pub(crate) fn add_host_object<HOT: HostObjectType>(
        &self,
        hot: HOT,
    ) -> Result<HOT::Wrapper, HostError> {
        let _span = tracy_span!("add host object");
        let index = self.try_borrow_objects()?.len();
        let handle = index_to_handle(self, index, false)?;
        // charge for the new host object, which is just the amortized cost of a
        // single `HostObject` allocation
        metered_clone::charge_heap_alloc::<HostObject>(1, self.as_budget())?;
        let obj = HOT::inject(hot, self)?;
        let meta = self.compute_object_meta(&obj)?;
        // Enforce depth limit at creation time. This prevents construction
        // of objects too deep to safely recurse into during comparison,
        // cloning, or conversion.
        if meta.depth >= crate::DEFAULT_HOST_DEPTH_LIMIT {
            return Err(self.err(
                ScErrorType::Context,
                ScErrorCode::ExceededLimit,
                "host object depth exceeds limit",
                &[],
            ));
        }
        self.try_borrow_objects_mut()?.push((obj, meta));
        Ok(HOT::new_from_handle(handle))
    }

    pub(crate) fn visit_obj_untyped<F, U>(
        &self,
        obj: impl Into<Object>,
        f: F,
    ) -> Result<U, HostError>
    where
        F: FnOnce(&HostObject) -> Result<U, HostError>,
    {
        let _span = tracy_span!("visit host object");
        // `VisitObject` covers the cost of visiting an object. The actual cost
        // of the closure needs to be covered by the caller. Although each visit
        // does small amount of work -- getting the object handling and indexing
        // into the host object buffer, almost too little to bother charging for
        // -- it is ubiquitous and therefore we charge budget here for safety /
        // future proofing.
        self.charge_budget(ContractCostType::VisitObject, None)?;
        let r = self.try_borrow_objects()?;
        let obj: Object = obj.into();
        let handle: u32 = obj.get_handle();
        if is_relative_object_handle(handle) {
            // This should never happen: we should have translated a relative
            // object handle to an absolute before we got here.
            Err(self.err(
                ScErrorType::Object,
                ScErrorCode::InternalError,
                "looking up relative object",
                &[Val::from_u32(handle).to_val()],
            ))
        } else if let Some((obj, _meta)) = r.get(handle_to_index(handle)) {
            f(obj)
        } else {
            // Discard the broken object here instead of including
            // it in the error to avoid further attempts to interpret it.
            // e.g. if diagnostics are on, then this would immediately
            // begin recursing, attempting and failing to externalize
            // debug info for this very error. Store the u64 payload instead.
            let obj_payload = obj.as_val().get_payload();
            let payload_val = Val::try_from_val(self, &obj_payload)?;
            Err(self.err(
                ScErrorType::Value,
                ScErrorCode::InvalidInput,
                "unknown object reference",
                &[payload_val],
            ))
        }
    }

    // Notes on metering: object visiting part is covered by
    // [`Host::visit_obj_untyped`]. Closure needs to be metered separately.
    pub(crate) fn visit_obj<HOT: HostObjectType, F, U>(
        &self,
        obj: HOT::Wrapper,
        f: F,
    ) -> Result<U, HostError>
    where
        F: FnOnce(&HOT) -> Result<U, HostError>,
    {
        self.visit_obj_untyped(obj, |hobj| match HOT::try_extract(hobj) {
            // This should never happen: we should have rejected a mis-tagged
            // object handle before it got here.
            None => Err(self.err(
                xdr::ScErrorType::Object,
                xdr::ScErrorCode::InternalError,
                "object reference type does not match tag",
                &[],
            )),
            Some(hot) => f(hot),
        })
    }

    /// Returns the approximate XDR byte size for a Val.
    /// For inline values, returns a fixed size.
    /// For object handles, looks up the cached ObjectMeta.
    pub(crate) fn val_xdr_byte_size(&self, val: Val) -> Result<u32, HostError> {
        use crate::Tag;
        let tag = val.get_tag();
        if tag.is_object() {
            let obj: Object = val.try_into().map_err(|_| self.err(
                ScErrorType::Value,
                ScErrorCode::InternalError,
                "expected object val",
                &[],
            ))?;
            let handle = obj.get_handle();
            let r = self.try_borrow_objects()?;
            if let Some((_obj, meta)) = r.get(handle_to_index(handle)) {
                // Add 4 bytes for ScVal discriminant wrapping
                Ok(meta.xdr_byte_size.saturating_add(4))
            } else {
                Ok(8) // fallback
            }
        } else {
            // Inline Val — approximate XDR size based on tag
            Ok(match tag {
                Tag::False | Tag::True | Tag::Void => 4,
                Tag::U32Val | Tag::I32Val => 8,  // 4 disc + 4 val
                Tag::U64Small | Tag::I64Small => 12, // 4 disc + 8 val
                Tag::TimepointSmall | Tag::DurationSmall => 12,
                Tag::U128Small | Tag::I128Small => 20, // 4 disc + 16 val
                Tag::U256Small | Tag::I256Small => 36, // 4 disc + 32 val
                Tag::SymbolSmall => {
                    // Small symbols: up to 9 chars, XDR = 4 disc + 4 len + padded chars
                    12 // approximate
                }
                Tag::Error => 12, // 4 disc + 4 type + 4 code
                _ => 8, // conservative fallback for any other inline types
            })
        }
    }

    /// Returns the ObjectMeta for the given Val, or a default for inline vals.
    pub(crate) fn val_object_meta(&self, val: Val) -> Result<ObjectMeta, HostError> {
        if val.get_tag().is_object() {
            let obj: Object = val.try_into().map_err(|_| self.err(
                ScErrorType::Value,
                ScErrorCode::InternalError,
                "expected object val",
                &[],
            ))?;
            let handle = obj.get_handle();
            let r = self.try_borrow_objects()?;
            if let Some((_obj, meta)) = r.get(handle_to_index(handle)) {
                Ok(*meta)
            } else {
                Ok(ObjectMeta::default())
            }
        } else {
            Ok(ObjectMeta {
                xdr_byte_size: self.val_xdr_byte_size(val)?,
                depth: 0,
            })
        }
    }

    /// Compute ObjectMeta for a HostObject at creation time.
    fn compute_object_meta(&self, obj: &HostObject) -> Result<ObjectMeta, HostError> {
        match obj {
            // Leaf scalar objects — fixed XDR sizes, depth 0
            HostObject::U64(_) => Ok(ObjectMeta { xdr_byte_size: 8, depth: 0 }),
            HostObject::I64(_) => Ok(ObjectMeta { xdr_byte_size: 8, depth: 0 }),
            HostObject::U128(_) => Ok(ObjectMeta { xdr_byte_size: 16, depth: 0 }),
            HostObject::I128(_) => Ok(ObjectMeta { xdr_byte_size: 16, depth: 0 }),
            HostObject::U256(_) => Ok(ObjectMeta { xdr_byte_size: 32, depth: 0 }),
            HostObject::I256(_) => Ok(ObjectMeta { xdr_byte_size: 32, depth: 0 }),
            HostObject::TimePoint(_) => Ok(ObjectMeta { xdr_byte_size: 8, depth: 0 }),
            HostObject::Duration(_) => Ok(ObjectMeta { xdr_byte_size: 8, depth: 0 }),

            // Variable-length leaf objects — size from len, depth 0
            // XDR encoding: 4 (length) + padded-to-4 bytes
            HostObject::Bytes(b) => {
                let padded = ((b.len() + 3) / 4) * 4;
                Ok(ObjectMeta { xdr_byte_size: (4 + padded) as u32, depth: 0 })
            }
            HostObject::String(s) => {
                let padded = ((s.len() + 3) / 4) * 4;
                Ok(ObjectMeta { xdr_byte_size: (4 + padded) as u32, depth: 0 })
            }
            HostObject::Symbol(s) => {
                let padded = ((s.len() + 3) / 4) * 4;
                Ok(ObjectMeta { xdr_byte_size: (4 + padded) as u32, depth: 0 })
            }

            // Address: ScAddress is either Account(32 bytes) or Contract(32 bytes)
            // XDR: 4 (disc) + 4 (inner disc) + 32 (key) = 40
            HostObject::Address(_) => Ok(ObjectMeta { xdr_byte_size: 40, depth: 0 }),
            HostObject::MuxedAddress(_) => Ok(ObjectMeta { xdr_byte_size: 48, depth: 0 }),

            // Container objects — sum child sizes + overhead
            HostObject::Vec(v) => {
                // XDR: 4 (vec length) + sum of element sizes
                let r = self.try_borrow_objects()?;
                let mut total_size: u32 = 4; // vec length prefix
                let mut max_depth: u32 = 0;
                for val in v.iter() {
                    let child_meta = self.val_object_meta_from_table(&r, *val);
                    total_size = total_size.saturating_add(child_meta.xdr_byte_size).saturating_add(4); // +4 for ScVal disc
                    max_depth = max_depth.max(child_meta.depth);
                }
                Ok(ObjectMeta {
                    xdr_byte_size: total_size,
                    depth: max_depth.saturating_add(1),
                })
            }
            HostObject::Map(m) => {
                // XDR: 4 (vec length) + sum of entry sizes
                // Each entry: key ScVal + val ScVal
                let r = self.try_borrow_objects()?;
                let mut total_size: u32 = 4; // vec length prefix
                let mut max_depth: u32 = 0;
                for (k, v) in m.map.iter() {
                    let k_meta = self.val_object_meta_from_table(&r, *k);
                    let v_meta = self.val_object_meta_from_table(&r, *v);
                    // Each entry: key XDR + 4 disc + val XDR + 4 disc
                    total_size = total_size
                        .saturating_add(k_meta.xdr_byte_size).saturating_add(4)
                        .saturating_add(v_meta.xdr_byte_size).saturating_add(4);
                    max_depth = max_depth.max(k_meta.depth).max(v_meta.depth);
                }
                Ok(ObjectMeta {
                    xdr_byte_size: total_size,
                    depth: max_depth.saturating_add(1),
                })
            }
        }
    }

    /// Look up ObjectMeta for a Val from the already-borrowed objects table.
    /// For inline Vals, returns an approximate fixed size.
    fn val_object_meta_from_table(
        &self,
        objects: &[(HostObject, ObjectMeta)],
        val: Val,
    ) -> ObjectMeta {
        use crate::Tag;
        let tag = val.get_tag();
        if tag.is_object() {
            if let Ok(obj) = Object::try_from(val) {
                let handle = obj.get_handle();
                if let Some((_obj, meta)) = objects.get(handle_to_index(handle)) {
                    return *meta;
                }
            }
            ObjectMeta::default()
        } else {
            ObjectMeta {
                xdr_byte_size: match tag {
                    Tag::False | Tag::True | Tag::Void => 4,
                    Tag::U32Val | Tag::I32Val => 8,
                    Tag::U64Small | Tag::I64Small => 12,
                    Tag::TimepointSmall | Tag::DurationSmall => 12,
                    Tag::U128Small | Tag::I128Small => 20,
                    Tag::U256Small | Tag::I256Small => 36,
                    Tag::SymbolSmall => 12,
                    Tag::Error => 12,
                    _ => 8,
                },
                depth: 0,
            }
        }
    }
}
