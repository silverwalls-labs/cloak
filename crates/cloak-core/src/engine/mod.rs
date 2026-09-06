use std::collections::BTreeMap;
use std::io;
use std::marker::PhantomData;

use crate::config::{self, Config};
use crate::types::Stats;

/// Error constructing an [`Engine`].
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("failed to obtain entropy for digest key: {0}")]
    Entropy(#[from] config::DigestKeyError),
}

/// Compiled engine holding the resolved digest key and (in later sessions)
/// the compiled ruleset.
///
/// `Engine` is [`Send`] + [`Sync`] — it can be shared across threads, with
/// each thread owning its own [`Session`].
pub struct Engine {
    /// Resolved key for computing redaction digests. Used by sessions in S2+.
    #[allow(dead_code)]
    pub(crate) digest_key: [u8; 32],
    _config: Config,
}

impl Engine {
    /// Build an engine from the given configuration.
    pub fn new(config: &Config) -> Result<Self, BuildError> {
        let digest_key = config::resolve_digest_key(config.digest_key_env.as_deref())?;
        Ok(Self {
            digest_key,
            _config: config.clone(),
        })
    }

    /// Create a new per-stream session.
    pub fn session(&self) -> Session<'_> {
        Session {
            engine: self,
            bytes_processed: 0,
            _not_send: PhantomData,
        }
    }
}

/// Per-stream scanning state.
///
/// `Session` is **not** [`Send`] or [`Sync`] — it is bound to the thread
/// that created it.
///
/// **Why `!Send` (not just `!Sync`):** S3 will add carry-over buffers whose
/// correctness depends on push/finish being called from the same thread that
/// created the session (position-dependent mutable state). Allowing `Send`
/// now and restricting it in S3 would be a breaking API change for any
/// consumer that moves sessions between threads. The conservative choice is
/// `!Send + !Sync` from day one. Revisit for v0.2 bindings if cross-thread
/// move semantics are needed (`docs/06-embedding.md`).
pub struct Session<'e> {
    #[allow(dead_code)]
    engine: &'e Engine,
    bytes_processed: u64,
    /// Opt out of auto-Send/Sync. Raw pointers are neither Send nor Sync,
    /// so PhantomData<*const ()> infects the parent struct.
    _not_send: PhantomData<*const ()>,
}

/// Compile-time assertion: `Engine` must be `Send + Sync`.
/// Lives outside `#[cfg(test)]` so regressions are caught by `cargo check`.
#[allow(dead_code)]
const _: () = {
    fn assert_send_sync<T: Send + Sync>() {}
    fn _assert() {
        assert_send_sync::<Engine>();
    }
};

impl Session<'_> {
    /// Push a chunk of bytes through the engine.
    ///
    /// In S1 (zero rules compiled), this is a pure passthrough: every byte
    /// is written to `out` unchanged. In later sessions, matches will be
    /// detected and redacted, and trailing bytes may be withheld as carry-over.
    pub fn push(&mut self, chunk: &[u8], out: &mut impl io::Write) -> io::Result<()> {
        out.write_all(chunk)?;
        self.bytes_processed += chunk.len() as u64;
        Ok(())
    }

    /// Flush any carry-over, close open states, and return per-rule statistics.
    ///
    /// Consumes the session — no further pushes are possible after this call.
    /// The `out` parameter is unused in S1 but required by the API contract
    /// for carry-over flushing in S3.
    pub fn finish(self, _out: &mut impl io::Write) -> io::Result<Stats> {
        Ok(Stats {
            bytes_processed: self.bytes_processed,
            matches: BTreeMap::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_engine() -> Engine {
        let config = Config {
            digest_key_env: None, // force ephemeral, no env lookup
        };
        Engine::new(&config).unwrap()
    }

    #[test]
    fn push_passthrough() {
        let engine = test_engine();
        let mut session = engine.session();
        let input = b"hello world";
        let mut output = Vec::new();
        session.push(input, &mut output).unwrap();
        assert_eq!(output, input);
    }

    #[test]
    fn push_empty() {
        let engine = test_engine();
        let mut session = engine.session();
        let mut output = Vec::new();
        session.push(b"", &mut output).unwrap();
        assert!(output.is_empty());
    }

    #[test]
    fn push_binary() {
        let engine = test_engine();
        let mut session = engine.session();
        // All byte values 0x00..=0xFF, including invalid UTF-8.
        let input: Vec<u8> = (0..=255).collect();
        let mut output = Vec::new();
        session.push(&input, &mut output).unwrap();
        assert_eq!(output, input);
    }

    #[test]
    fn multiple_pushes() {
        let engine = test_engine();
        let mut session = engine.session();
        let mut output = Vec::new();
        session.push(b"chunk-1 ", &mut output).unwrap();
        session.push(b"chunk-2 ", &mut output).unwrap();
        session.push(b"chunk-3", &mut output).unwrap();
        assert_eq!(output, b"chunk-1 chunk-2 chunk-3");
    }

    #[test]
    fn finish_returns_stats() {
        let engine = test_engine();
        let mut session = engine.session();
        let mut output = Vec::new();
        session.push(b"twelve bytes", &mut output).unwrap();
        let stats = session.finish(&mut output).unwrap();
        assert_eq!(stats.bytes_processed, 12);
        assert!(stats.matches.is_empty());
        assert_eq!(stats.total_matches(), 0);
    }

    #[test]
    fn finish_empty_session() {
        let engine = test_engine();
        let session = engine.session();
        let mut output = Vec::new();
        let stats = session.finish(&mut output).unwrap();
        assert_eq!(stats.bytes_processed, 0);
    }
}
