//! `cloak-py` — native Python binding over `cloak-core` (E5).
//!
//! This crate compiles to the `cloak_py._native` extension module
//! (cdylib, abi3). The Python-facing API (`cloak_py.create_engine`,
//! `CloakEngine`, `CloakSession`, hooks) lives in `python/cloak_py/`
//! and wraps the two classes exported here; this layer is deliberately
//! thin — all correctness lives in core (docs/06-embedding.md).
//!
//! # Safety boundary
//!
//! One `unsafe` block: the lifetime erasure in `PyEngine::session`.
//! `Session<'e>` borrows its `Engine`, but a `#[pyclass]` must be
//! `'static` — so the session is stored as `Session<'static>` next to
//! an `Arc<Engine>` clone that pins the engine at a stable heap address
//! for at least as long as the session lives (field order in
//! `SessionInner` guarantees drop order). Same justification as the
//! handle-table lifetime transmute in `crates/cloak-wasm/src/lib.rs`.
//!
//! # Binding rules (docs/06-embedding.md §API parity)
//!
//! - Bytes in, bytes out: inputs are `&[u8]` borrowed from immutable
//!   Python `bytes` (the Python layer coerces `str`/`bytearray`/
//!   `memoryview`); outputs are freshly-allocated `bytes`.
//! - No plaintext in stats — same rule as `MatchEvent` in core.
//! - No panic crosses the boundary: pyo3 wraps every `#[pymethods]`
//!   entry in `catch_unwind` and raises `pyo3.PanicException` (a
//!   `BaseException` — panics are bugs, they must not be swallowed by
//!   `except Exception` handlers on the logging hot path). This relies
//!   on the workspace-wide `panic = "unwind"` profile.
//! - The GIL is released (`Python::detach`) for every scan: other
//!   Python threads make progress while `push`/`finish`/`redact` run.

#![allow(unsafe_code)]

use std::sync::{Arc, Mutex};

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};

use cloak_core::{Config, Engine, Session, Stats};

create_exception!(
    cloak_py._native,
    CloakError,
    PyException,
    "Raised for cloak engine/session errors: invalid config, engine \
     build failure, or lifecycle misuse (consumed session, disposed \
     engine)."
);

/// Cap on the pre-allocated output buffer: redacted output tracks input
/// size (tags replace secrets roughly 1:1), but a hostile `len` must not
/// pre-allocate unbounded memory. Same reasoning as cloak-wasm's
/// output-capacity cap.
const OUTPUT_CAPACITY_CAP: usize = 64 * 1024;

fn disposed_err() -> PyErr {
    CloakError::new_err("engine disposed")
}

fn consumed_err() -> PyErr {
    CloakError::new_err("session already consumed (finished or aborted)")
}

/// Convert core [`Stats`] to the `CloakStats` dict shape shared by all
/// bindings: `{"bytes_processed": int, "matches": {rule-id: count}}`.
fn stats_to_dict<'py>(py: Python<'py>, stats: &Stats) -> PyResult<Bound<'py, PyDict>> {
    let matches = PyDict::new(py);
    for (rule, count) in &stats.matches {
        matches.set_item(rule.to_string(), *count)?;
    }
    let dict = PyDict::new(py);
    dict.set_item("bytes_processed", stats.bytes_processed)?;
    dict.set_item("matches", matches)?;
    Ok(dict)
}

/// A session plus the `Arc` that keeps its engine alive.
struct SessionInner {
    // Declared first: struct fields drop in declaration order, so the
    // borrowing session is always dropped before the Arc that owns the
    // Engine it borrows.
    session: Session<'static>,
    _engine: Arc<Engine>,
}

/// Compiled cloak engine. Shareable across threads; sessions created
/// from it keep it alive (dispose refuses while any are live, and while
/// any scan is in flight).
#[pyclass(name = "Engine", module = "cloak_py._native")]
struct PyEngine {
    /// `None` after `dispose()`. Interior mutability instead of a
    /// `&mut self` `dispose`: a `&mut` method conflicts with any in-flight
    /// `&self` scan at pyo3's borrow-check level and surfaces as
    /// `RuntimeError: Already borrowed` — with the lock, an overlapping
    /// dispose instead raises a coherent `CloakError` (or waits for the
    /// clone and takes the Arc count check below).
    engine: Mutex<Option<Arc<Engine>>>,
}

impl PyEngine {
    /// Clone the live engine `Arc`. The lock is held only for the clone,
    /// never across a scan.
    fn live(&self) -> PyResult<Arc<Engine>> {
        self.engine
            .lock()
            .map_err(|_| CloakError::new_err("engine state lock poisoned"))?
            .clone()
            .ok_or_else(disposed_err)
    }
}

#[pymethods]
impl PyEngine {
    /// Compile a TOML config into an engine. Empty string = defaults
    /// (digest key from `CLOAK_DIGEST_KEY`, ephemeral fallback).
    #[new]
    fn new(config_toml: &str) -> PyResult<Self> {
        // Error messages mirror cloakwasm_engine_new so host-visible
        // diagnostics stay comparable across bindings.
        let config = Config::from_toml(config_toml)
            .map_err(|e| CloakError::new_err(format!("invalid config: {e}")))?;
        let engine = Engine::new(&config)
            .map_err(|e| CloakError::new_err(format!("engine build failed: {e}")))?;
        Ok(Self {
            engine: Mutex::new(Some(Arc::new(engine))),
        })
    }

    /// One-shot redact: returns `(bytes, stats_dict)`.
    fn redact<'py>(
        &self,
        py: Python<'py>,
        data: &[u8],
    ) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyDict>)> {
        let engine = self.live()?;
        let mut out = Vec::with_capacity(data.len().min(OUTPUT_CAPACITY_CAP));
        // GIL released for the whole scan. `data` borrows an immutable
        // Python `bytes` kept alive by the caller's argument reference.
        let stats = py
            .detach(|| -> std::io::Result<Stats> {
                let mut session = engine.session();
                session.push(data, &mut out)?;
                session.finish(&mut out)
            })
            .map_err(|e| CloakError::new_err(format!("redact failed: {e}")))?;
        Ok((PyBytes::new(py, &out), stats_to_dict(py, &stats)?))
    }

    /// Create a streaming session. The session holds the engine alive.
    fn session(&self) -> PyResult<PySession> {
        let engine = self.live()?;
        // SAFETY: `Session` only borrows `&Engine`. The Arc clone stored
        // alongside it in `SessionInner` pins the Engine at a stable heap
        // address for the session's whole lifetime, and the field order
        // drops the session before the Arc. Lifetime erasure mirrors
        // crates/cloak-wasm/src/lib.rs (handle-table sessions).
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let pinned: &'static Engine = unsafe { &*Arc::as_ptr(&engine) };
        Ok(PySession {
            inner: Some(SessionInner {
                session: pinned.session(),
                _engine: engine,
            }),
        })
    }

    /// Release the engine. Idempotent; refuses while sessions are live
    /// or a scan is in flight (mirrors cloakwasm_engine_free). Refusal
    /// raises `CloakError`, never pyo3's borrow-check `RuntimeError`.
    fn dispose(&self) -> PyResult<()> {
        let mut guard = self
            .engine
            .lock()
            .map_err(|_| CloakError::new_err("engine state lock poisoned"))?;
        match guard.take() {
            None => Ok(()), // already disposed
            Some(engine) => {
                // Count > 1: live sessions (their `SessionInner` holds a
                // clone) or an in-flight `redact`/`push`/`finish` holding
                // a transient clone. Safety never depends on this check —
                // the sessions' own clones keep the Engine alive — it
                // only surfaces leaks, mirroring cloak-wasm.
                if Arc::strong_count(&engine) > 1 {
                    *guard = Some(engine);
                    return Err(CloakError::new_err(
                        "cannot dispose engine while in use: finish or abort live sessions, \
                         and let in-flight scans complete first",
                    ));
                }
                Ok(())
            }
        }
    }
}

/// Per-stream scanning session. Movable across threads; pyo3's runtime
/// borrow checking rejects concurrent calls (`RuntimeError`), so a
/// session can never be scanned from two threads at once.
#[pyclass(name = "Session", module = "cloak_py._native")]
struct PySession {
    /// `None` after `finish()`/`abort()` (consumed).
    inner: Option<SessionInner>,
}

#[pymethods]
impl PySession {
    /// Push a chunk; returns the bytes flushed by this push (may be
    /// empty while the carry-over window withholds a potential match).
    fn push<'py>(&mut self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let inner = self.inner.as_mut().ok_or_else(consumed_err)?;
        let mut out = Vec::with_capacity(data.len().min(OUTPUT_CAPACITY_CAP));
        py.detach(|| inner.session.push(data, &mut out))
            .map_err(|e| CloakError::new_err(format!("push failed: {e}")))?;
        Ok(PyBytes::new(py, &out))
    }

    /// Flush the carry-over and consume the session: returns
    /// `(bytes, stats_dict)`.
    fn finish<'py>(
        &mut self,
        py: Python<'py>,
    ) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyDict>)> {
        // `_engine` stays on this frame, keeping the engine pinned while
        // the detached closure consumes the session.
        let SessionInner { session, _engine } = self.inner.take().ok_or_else(consumed_err)?;
        let (stats, out) = py
            .detach(move || -> std::io::Result<(Stats, Vec<u8>)> {
                let mut out = Vec::new();
                let stats = session.finish(&mut out)?;
                Ok((stats, out))
            })
            .map_err(|e| CloakError::new_err(format!("finish failed: {e}")))?;
        Ok((PyBytes::new(py, &out), stats_to_dict(py, &stats)?))
    }

    /// Drop the session without flushing. Idempotent.
    fn abort(&mut self) {
        self.inner = None;
    }

    /// Whether the session has been consumed by `finish()`/`abort()`.
    #[getter]
    fn consumed(&self) -> bool {
        self.inner.is_none()
    }
}

#[pymodule(name = "_native")]
fn native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyEngine>()?;
    m.add_class::<PySession>()?;
    m.add("CloakError", m.py().get_type::<CloakError>())?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
