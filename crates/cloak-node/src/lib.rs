//! `cloak-node` — native Node.js binding over `cloak-core` (E6).
//!
//! This crate compiles to a `.node` native addon via napi-rs. The
//! JS/TS-facing API (`createEngine`, config serialization, `Transform`
//! streams) lives in `js/` and wraps the classes exported here; this
//! layer is deliberately thin — all correctness lives in core
//! (docs/06-embedding.md).
//!
//! # Safety boundary
//!
//! One `unsafe` block: the lifetime erasure in `NapiEngine::session`.
//! `Session<'e>` borrows its `Engine`, but napi-rs classes must be
//! `'static` — so the session is stored as `Session<'static>` next to
//! an `Arc<Engine>` clone that pins the engine at a stable heap address
//! for at least as long as the session lives (field order in
//! `SessionInner` guarantees drop order). Same justification as
//! `crates/cloak-py/src/lib.rs` and `crates/cloak-wasm/src/lib.rs`.
//!
//! # Binding rules (docs/06-embedding.md §API parity)
//!
//! - Bytes in, bytes out: inputs are `Buffer` (N-API binary data);
//!   outputs are freshly-allocated `Buffer`. The JS wrapper coerces
//!   `string`/`Uint8Array` before calling into the native layer.
//! - No plaintext in stats — same rule as `MatchEvent` in core.
//! - No panic crosses the boundary: the `catch_unwind` feature on the
//!   `napi` crate wraps every `#[napi]`-exported function in
//!   `std::panic::catch_unwind` and converts panics to JS exceptions.
//!   This relies on the workspace-wide `panic = "unwind"` profile.

#![allow(unsafe_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use napi::bindgen_prelude::*;
use napi_derive::napi;

use cloak_core::{Config, Engine, Session, Stats};

/// Cap on the pre-allocated output buffer: redacted output tracks input
/// size (tags replace secrets roughly 1:1), but a hostile `len` must not
/// pre-allocate unbounded memory. Same reasoning as cloak-wasm's
/// output-capacity cap.
const OUTPUT_CAPACITY_CAP: usize = 64 * 1024;

// ── Stats conversion ──────────────────────────────────────────────

/// Per-stream statistics returned by `session.finish()` and `redact()`.
///
/// Field names are kept as snake_case (`bytes_processed`, not
/// `bytesProcessed`) for API parity with the WASM adapter — the
/// `#[napi(js_name)]` attributes override napi-rs's default camelCase
/// conversion.
#[napi(object)]
pub struct CloakStats {
    /// Total bytes pushed through the session.
    #[napi(js_name = "bytes_processed")]
    pub bytes_processed: i64,
    /// Per-rule match counts (rule-id → count).
    pub matches: HashMap<String, i64>,
}

fn stats_to_js(stats: &Stats) -> CloakStats {
    CloakStats {
        // u64 → i64: practical byte counts and match counts fit easily;
        // i64 maps cleanly to JS number (safe up to 2^53).
        bytes_processed: stats.bytes_processed as i64,
        matches: stats
            .matches
            .iter()
            .map(|(rule, count)| (rule.to_string(), *count as i64))
            .collect(),
    }
}

// ── Result types ──────────────────────────────────────────────────

/// Result of a one-shot `redact()` call.
#[napi(object)]
pub struct RedactResult {
    /// The redacted output bytes.
    pub output: Buffer,
    /// Per-stream statistics.
    pub stats: CloakStats,
}

/// Result of `session.finish()`.
#[napi(object)]
pub struct FinishResult {
    /// Remaining redacted output bytes (carry-over tail).
    pub output: Buffer,
    /// Per-stream statistics.
    pub stats: CloakStats,
}

// ── SessionInner ──────────────────────────────────────────────────

/// A session plus the `Arc` that keeps its engine alive.
struct SessionInner {
    // Declared first: struct fields drop in declaration order, so the
    // borrowing session is always dropped before the Arc that owns the
    // Engine it borrows.
    session: Session<'static>,
    _engine: Arc<Engine>,
}

// ── NapiEngine ────────────────────────────────────────────────────

/// Compiled cloak engine. Create sessions from it for streaming
/// redaction, or use `redact()` for one-shot convenience.
#[napi]
pub struct NapiEngine {
    /// `None` after `dispose()`. Interior mutability (Mutex) instead of
    /// `&mut self` on `dispose`: Node is single-threaded, so no real
    /// contention, but the Mutex lets `dispose` be `&self` — matching
    /// the cloak-py pattern and preventing napi-rs borrow conflicts.
    engine: Mutex<Option<Arc<Engine>>>,
}

impl NapiEngine {
    /// Clone the live engine `Arc`. The lock is held only for the clone,
    /// never across a scan.
    fn live(&self) -> napi::Result<Arc<Engine>> {
        self.engine
            .lock()
            .map_err(|_| napi::Error::from_reason("engine state lock poisoned"))?
            .clone()
            .ok_or_else(|| napi::Error::from_reason("engine disposed"))
    }
}

#[napi]
impl NapiEngine {
    /// Compile a TOML config into an engine. Empty string = defaults
    /// (digest key from `CLOAK_DIGEST_KEY`, ephemeral fallback).
    #[napi(constructor, catch_unwind)]
    pub fn new(config_toml: String) -> napi::Result<Self> {
        let config = Config::from_toml(&config_toml)
            .map_err(|e| napi::Error::from_reason(format!("invalid config: {e}")))?;
        let engine = Engine::new(&config)
            .map_err(|e| napi::Error::from_reason(format!("engine build failed: {e}")))?;
        Ok(Self {
            engine: Mutex::new(Some(Arc::new(engine))),
        })
    }

    /// One-shot redact: returns `{ output: Buffer, stats }`.
    #[napi(catch_unwind)]
    pub fn redact(&self, data: Buffer) -> napi::Result<RedactResult> {
        let engine = self.live()?;
        let input: &[u8] = &data;
        let mut out = Vec::with_capacity(input.len().min(OUTPUT_CAPACITY_CAP));
        let mut session = engine.session();
        session
            .push(input, &mut out)
            .map_err(|e| napi::Error::from_reason(format!("redact failed: {e}")))?;
        let stats = session
            .finish(&mut out)
            .map_err(|e| napi::Error::from_reason(format!("redact failed: {e}")))?;
        Ok(RedactResult {
            output: out.into(),
            stats: stats_to_js(&stats),
        })
    }

    /// Create a streaming session. The session holds the engine alive.
    #[napi(catch_unwind)]
    pub fn session(&self) -> napi::Result<NapiSession> {
        let engine = self.live()?;
        // SAFETY: `Session` only borrows `&Engine`. The Arc clone stored
        // alongside it in `SessionInner` pins the Engine at a stable heap
        // address for the session's whole lifetime, and the field order
        // drops the session before the Arc. Lifetime erasure mirrors
        // crates/cloak-py/src/lib.rs and crates/cloak-wasm/src/lib.rs.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let pinned: &'static Engine = unsafe { &*Arc::as_ptr(&engine) };
        Ok(NapiSession {
            inner: Some(SessionInner {
                session: pinned.session(),
                _engine: engine,
            }),
        })
    }

    /// Release the engine. Idempotent; refuses while sessions are live
    /// (mirrors cloak-py and cloakwasm_engine_free).
    #[napi(catch_unwind)]
    pub fn dispose(&self) -> napi::Result<()> {
        let mut guard = self
            .engine
            .lock()
            .map_err(|_| napi::Error::from_reason("engine state lock poisoned"))?;
        match guard.take() {
            None => Ok(()), // already disposed
            Some(engine) => {
                if Arc::strong_count(&engine) > 1 {
                    *guard = Some(engine);
                    return Err(napi::Error::from_reason(
                        "cannot dispose engine while in use: finish or abort \
                         live sessions first",
                    ));
                }
                Ok(())
            }
        }
    }
}

// ── NapiSession ───────────────────────────────────────────────────

/// Per-stream scanning session. Created via `engine.session()`.
#[napi]
pub struct NapiSession {
    /// `None` after `finish()`/`abort()` (consumed).
    inner: Option<SessionInner>,
}

#[napi]
impl NapiSession {
    /// Push a chunk; returns the bytes flushed by this push (may be
    /// empty while the carry-over window withholds a potential match).
    #[napi(catch_unwind)]
    pub fn push(&mut self, data: Buffer) -> napi::Result<Buffer> {
        let inner = self.inner.as_mut().ok_or_else(|| {
            napi::Error::from_reason("session already consumed (finished or aborted)")
        })?;
        let input: &[u8] = &data;
        let mut out = Vec::with_capacity(input.len().min(OUTPUT_CAPACITY_CAP));
        inner
            .session
            .push(input, &mut out)
            .map_err(|e| napi::Error::from_reason(format!("push failed: {e}")))?;
        Ok(out.into())
    }

    /// Flush the carry-over and consume the session: returns
    /// `{ output: Buffer, stats }`.
    #[napi(catch_unwind)]
    pub fn finish(&mut self) -> napi::Result<FinishResult> {
        let SessionInner { session, _engine } = self.inner.take().ok_or_else(|| {
            napi::Error::from_reason("session already consumed (finished or aborted)")
        })?;
        let mut out = Vec::new();
        let stats = session
            .finish(&mut out)
            .map_err(|e| napi::Error::from_reason(format!("finish failed: {e}")))?;
        Ok(FinishResult {
            output: out.into(),
            stats: stats_to_js(&stats),
        })
    }

    /// Drop the session without flushing. Idempotent.
    #[napi(catch_unwind)]
    pub fn abort(&mut self) {
        self.inner = None;
    }

    /// Whether the session has been consumed by `finish()`/`abort()`.
    #[napi(getter, catch_unwind)]
    pub fn consumed(&self) -> bool {
        self.inner.is_none()
    }
}
