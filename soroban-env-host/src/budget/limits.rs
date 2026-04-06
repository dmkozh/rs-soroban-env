use crate::{
    budget::{Budget, BudgetImpl},
    xdr::{Limits, ScErrorCode, ScErrorType},
    Error, HostError,
};

/// These constants are used to set limits on recursion and data length in the
/// context of XDR (de)serialization. They serve as safeguards against both
/// excessive stack allocation, which could cause an unrecoverable `SIGABRT`,
/// and excessive heap memory allocation.
pub const DEFAULT_XDR_RW_LIMITS: Limits = Limits {
    // recursion limit for reading and writing XDR structures.
    depth: 500,
    // Maximum byte length for a data structure during serialization and
    // deserialization to and from the XDR format.
    // **DO NOT** use the default length for de-serialization. Instead,
    // use the size of the input buffer (which should be much less than
    // the limit defined here).
    // The default 32 MB limit for serialization is the last-resort
    // sanity check. Serialization can't be easily tampered with (unlike
    // de-serialization) and is guarded by the budget both when the user
    // creates the objects to be serialized and when we allocate memory
    // to write these objects into.
    // We want to be pretty non-restrictive and let budget do its work for
    // deserialization. While 32 MB is much more data than we would ever
    // like to materialize, it is possible that the user would
    // just e.g. hash it without materializing, which seems like a much
    // more plausible scenario where this can be reached given high
    // enough memory/CPU instruction limits.
    len: 32 * 1024 * 1024,
};

/// - `DEFAULT_HOST_DEPTH_LIMIT`: This limit applies to the host environment. It
///   guards recursion paths involving the `Env` and `Budget`, particularly
///   during operations like conversion, comparison, and deep cloning. The limit
///   is strategically checked at critical recursion points, such as when
///   encountering a `Val`. As the actual stack usage can be higher,
///   `DEFAULT_HOST_DEPTH_LIMIT` is conservatively set to a lower value than the
///   XDR limit.
pub const DEFAULT_HOST_DEPTH_LIMIT: u32 = 100;

// These are some sane values, however the embedder should typically customize
// these to match the network config.
pub(crate) const DEFAULT_CPU_INSN_LIMIT: u64 = 100_000_000;
pub(crate) const DEFAULT_MEM_BYTES_LIMIT: u64 = 40 * 1024 * 1024; // 40MB

/// `DepthLimiter` is a trait designed for managing the depth of recursive operations.
/// It provides a mechanism to limit recursion depth, and defines the behavior upon
/// entering and leaving a recursion level.
impl BudgetImpl {
    pub(crate) fn enter(&mut self) -> Result<(), HostError> {
        if let Some(depth) = self.depth_limit.checked_sub(1) {
            self.depth_limit = depth;
        } else {
            return Err(Error::from_type_and_code(
                ScErrorType::Context,
                ScErrorCode::ExceededLimit,
            )
            .into());
        }
        Ok(())
    }

    // `leave` should be called in tandem with `enter` such that the depth
    // doesn't exceed the initial depth limit.
    fn leave(&mut self) -> Result<(), HostError> {
        self.depth_limit = self.depth_limit.checked_add(1).ok_or_else(|| {
            Error::from_type_and_code(ScErrorType::Context, ScErrorCode::InternalError)
        })?;
        Ok(())
    }
}

impl Budget {
    /// Depth-limited execution without requiring `&mut self` or cloning.
    /// Uses the interior mutability of Budget (UnsafeCell) to avoid
    /// the Rc clone overhead of `budget_cloned().with_limited_depth(...)`.
    pub(crate) fn with_limited_depth<T, F>(&self, f: F) -> Result<T, HostError>
    where
        F: FnOnce() -> Result<T, HostError>,
    {
        self.inner_mut().enter()?;
        let res = f();
        self.inner_mut().leave()?;
        res
    }
}
