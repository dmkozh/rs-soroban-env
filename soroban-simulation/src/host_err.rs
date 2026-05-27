//! Bridging [`HostError`] into `anyhow`.
//!
//! Since the zero-copy XDR decoding optimization, XDR types are backed by
//! `Rc<[u8]>` and are therefore `!Send + !Sync`. `HostError` embeds XDR (via its
//! event log), so it is `!Send + !Sync` too and cannot be stored inside an
//! `anyhow::Error` (which requires `Send + Sync`). This extension trait converts
//! a `Result<_, HostError>` into an `anyhow::Result` by capturing the error's
//! debug rendering (which includes the underlying error code).

use soroban_env_host::HostError;

pub(crate) trait MapHostError<T> {
    fn map_host_err(self) -> anyhow::Result<T>;
}

impl<T> MapHostError<T> for Result<T, HostError> {
    fn map_host_err(self) -> anyhow::Result<T> {
        self.map_err(|e| anyhow::anyhow!("{e:?}"))
    }
}
