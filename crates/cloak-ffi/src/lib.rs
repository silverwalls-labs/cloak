//! `cloak-ffi` — C ABI over `cloak-core` (E7).
//!
//! This crate compiles to a `staticlib` + `cdylib` pair whose exported
//! surface is described by the committed cbindgen header
//! (`include/cloak.h` — regenerated and diffed in CI). FFI embedders
//! (`cloak-go`, ctypes/cffi, any C caller) link one of the two and talk
//! to the functions below; this layer is deliberately thin — all
//! correctness lives in core (docs/06-embedding.md).
//!
//! # Safety boundary
//!
//! `cloak-core` stays `#![deny(unsafe_code)]`; the unsafe here is the
//! minimum a C ABI requires:
//!
//! - Pointer dereference for caller-provided `(ptr, len)` input pairs.
//! - `Arc` raw-pointer round-trips for the opaque engine handle, and the
//!   lifetime erasure that lets `Session<'e>` live in an opaque session
//!   handle (the session stores an `Arc<Engine>` clone that pins the
//!   engine — same pattern and justification as `crates/cloak-py`).
//! - `catch_unwind` at every entry point so no panic crosses the
//!   boundary (relies on the workspace-wide `panic = "unwind"` profile);
//!   panics surface as [`CLOAK_ERR_PANIC`].
//!
//! # Handle + ownership model (mirrors the header preamble)
//!
//! - Engine pointers come from [`cloak_engine_new`] and are released
//!   exactly once with [`cloak_engine_free`] — which *refuses* (engine
//!   stays valid) while sessions are live or scans are in flight.
//! - Session pointers come from [`cloak_session_new`] and are released
//!   exactly once with [`cloak_session_free`], including after
//!   [`cloak_session_finish`] (finish consumes the scanning state, not
//!   the pointer — misuse afterwards is an error, never UB).
//! - Every [`CloakBuf`] written through an out-parameter is owned by the
//!   caller and released exactly once with [`cloak_buf_free`].
//! - Errors are per-call: no global or thread-local error slot (a TLS
//!   slot would silently break under cgo, where consecutive calls from
//!   one goroutine may run on different OS threads). This is also what
//!   lets callers drop per-engine locking entirely.
//!
//! # Thread-safety contract
//!
//! An engine may be used from any number of threads concurrently —
//! except [`cloak_engine_free`], which must not run concurrently with
//! any other call on the same engine (the same rule as `free()`). A
//! session must be used by at most one thread at a time but may move
//! between threads; sessions of one engine may run concurrently with
//! each other and with [`cloak_redact`]. (Matches core: `Engine` is
//! `Send + Sync`, `Session` is `Send`.)

#![allow(unsafe_code)]
#![warn(missing_docs)]

use std::panic::{self, AssertUnwindSafe};
use std::ptr;
use std::sync::{Arc, Mutex};

use cloak_core::{Config, Engine, Session, Stats};

// ── Exported constants ──────────────────────────────────────────────

/// ABI version of this header/library pair. Bumped on any breaking
/// change to signatures, struct layout, or documented semantics.
/// Compare a binding's compile-time `CLOAK_ABI_VERSION` against the
/// runtime [`cloak_abi_version`] to catch a stale library.
pub const CLOAK_ABI_VERSION: u32 = 1;

/// Call succeeded.
pub const CLOAK_OK: i32 = 0;

/// Call failed; the message is in `*err_out` when one was provided.
pub const CLOAK_ERR: i32 = -1;

/// An internal panic was caught at the boundary (a bug — report it).
/// After this status from `cloak_engine_free`, the engine pointer must
/// be treated as invalid.
pub const CLOAK_ERR_PANIC: i32 = -2;

/// Cap on the pre-allocated output buffer: redacted output tracks input
/// size (tags replace secrets roughly 1:1), but a hostile `len` must not
/// pre-allocate unbounded memory. Same reasoning as cloak-wasm's
/// output-capacity cap (F10).
const OUTPUT_CAPACITY_CAP: usize = 64 * 1024;

// ── Opaque handle types ─────────────────────────────────────────────

/// Opaque engine handle. Created by [`cloak_engine_new`], released by
/// [`cloak_engine_free`]. Shareable across threads (see the crate-level
/// thread-safety contract).
pub struct CloakEngine {
    _private: [u8; 0],
}

/// Opaque session handle. Created by [`cloak_session_new`], released by
/// [`cloak_session_free`]. Single-thread-at-a-time, movable.
pub struct CloakSession {
    _private: [u8; 0],
}

// ── Byte buffer ─────────────────────────────────────────────────────

/// A cloak-allocated byte buffer returned through an out-parameter.
///
/// `ptr` is null if and only if `len == 0` — always check `len` before
/// dereferencing. Single owner: the caller, who must release each
/// buffer exactly once with [`cloak_buf_free`]. Never release `ptr`
/// with `free()`/`delete`.
///
/// The out-parameters of one call must not alias (two of them must
/// not point at the same `CloakBuf`): a later write overwrites the
/// earlier one, leaking its allocation and misattributing which
/// buffer holds which result.
///
/// Messages written into `err_out` parameters are UTF-8 but NOT
/// NUL-terminated — `len` is authoritative.
#[repr(C)]
pub struct CloakBuf {
    /// Pointer to the data bytes; null when `len == 0`.
    pub ptr: *mut u8,
    /// Length of the data in bytes.
    pub len: usize,
}

impl CloakBuf {
    const fn empty() -> Self {
        Self {
            ptr: ptr::null_mut(),
            len: 0,
        }
    }
}

/// Move a `Vec<u8>` into a caller-owned [`CloakBuf`].
///
/// `into_boxed_slice` guarantees capacity == len, so
/// [`cloak_buf_free`] can reconstruct the allocation from `(ptr, len)`
/// alone (same scheme as `cloakwasm_buf_free`).
fn buf_from_vec(v: Vec<u8>) -> CloakBuf {
    if v.is_empty() {
        // Empty results carry a null ptr — a dangling-but-aligned
        // pointer here would confuse null-checking callers.
        return CloakBuf::empty();
    }
    let len = v.len();
    // Box::into_raw (not as_mut_ptr + mem::forget): the returned pointer
    // keeps provenance over the whole allocation — the forget pattern
    // invalidates the pointer under Stacked Borrows (Miri-verified).
    let ptr = Box::into_raw(v.into_boxed_slice()).cast::<u8>();
    CloakBuf { ptr, len }
}

// ── Out-parameter helpers ───────────────────────────────────────────

/// Initialize an optional out-parameter to the empty buffer, so reading
/// it after the call is always defined — success or failure. Previous
/// contents are overwritten, never freed: do not pass an unfreed buffer
/// back in.
///
/// # Safety
///
/// `out` must be null or valid for a `CloakBuf` write.
unsafe fn init_out(out: *mut CloakBuf) {
    if !out.is_null() {
        // SAFETY: non-null per check; caller guarantees writability.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { out.write(CloakBuf::empty()) };
    }
}

/// Write an error message into `err_out` (no-op when null — the caller
/// opted out of messages; the status code still reports the failure).
///
/// # Safety
///
/// `err_out` must be null or valid for a `CloakBuf` write.
unsafe fn set_err(err_out: *mut CloakBuf, msg: impl Into<Vec<u8>>) {
    if !err_out.is_null() {
        // SAFETY: non-null per check; caller guarantees writability.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { err_out.write(buf_from_vec(msg.into())) };
    }
}

/// Borrow a caller-provided `(ptr, len)` input pair as a slice.
///
/// A pair with `len == 0` is valid with any pointer, including null
/// (`from_raw_parts` requires non-null even for empty slices). A null
/// pointer with a non-zero length is an error — impossible to express
/// in the WASM ABI, but free to construct in C.
///
/// # Safety
///
/// When `len > 0` and `ptr` is non-null, `ptr` must point to `len`
/// valid bytes that outlive the call.
unsafe fn input_slice<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], String> {
    if len == 0 {
        Ok(&[])
    } else if ptr.is_null() {
        Err("null pointer with non-zero length".to_string())
    } else {
        // SAFETY: non-null and len > 0 per checks; caller guarantees
        // the allocation is live for the call's duration.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
    }
}

// ── Panic shields ───────────────────────────────────────────────────

/// Panic shield shared by every status-returning entry point:
/// `Ok(())` ⇒ [`CLOAK_OK`], `Err(msg)` ⇒ [`CLOAK_ERR`] + message,
/// panic ⇒ [`CLOAK_ERR_PANIC`] + `"<op> panicked"`.
fn guarded(op: &str, err_out: *mut CloakBuf, f: impl FnOnce() -> Result<(), String>) -> i32 {
    match panic::catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => CLOAK_OK,
        Ok(Err(msg)) => {
            // SAFETY: err_out is null or valid per the call contract.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { set_err(err_out, msg) };
            CLOAK_ERR
        }
        Err(_) => {
            // SAFETY: err_out is null or valid per the call contract.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { set_err(err_out, format!("{op} panicked")) };
            CLOAK_ERR_PANIC
        }
    }
}

/// Panic shield for pointer-returning entry points: errors and panics
/// both return null, with the message (or `"<op> panicked"`) in
/// `err_out`.
fn guarded_ptr<T>(
    op: &str,
    err_out: *mut CloakBuf,
    f: impl FnOnce() -> Result<*mut T, String>,
) -> *mut T {
    match panic::catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(ptr)) => ptr,
        Ok(Err(msg)) => {
            // SAFETY: err_out is null or valid per the call contract.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { set_err(err_out, msg) };
            ptr::null_mut()
        }
        Err(_) => {
            // SAFETY: err_out is null or valid per the call contract.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { set_err(err_out, format!("{op} panicked")) };
            ptr::null_mut()
        }
    }
}

// ── Engine internals ────────────────────────────────────────────────

/// Clone the engine `Arc` for the duration of one call.
///
/// The transient clone is defense-in-depth: it makes an in-flight call
/// visible to [`cloak_engine_free`]'s strong-count check, so a free
/// that *observes* the call refuses instead of dropping the engine.
/// It is NOT a license to race — `Arc::increment_strong_count` itself
/// requires the count to stay ≥ 1 for the call, so a free that truly
/// wins the race is still UB. Hence the contract: `cloak_engine_free`
/// must not run concurrently with any other call on the same engine.
///
/// # Safety
///
/// `ptr` must be a live engine pointer obtained from
/// [`cloak_engine_new`] and not yet successfully freed.
unsafe fn engine_clone(ptr: *const CloakEngine) -> Arc<Engine> {
    let raw = ptr as *const Engine;
    // SAFETY: raw came from Arc::into_raw in cloak_engine_new; the
    // caller guarantees it is live (count ≥ 1) for this call.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { Arc::increment_strong_count(raw) };
    // SAFETY: the increment above is the reference this from_raw takes
    // ownership of; dropping the returned Arc undoes it.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { Arc::from_raw(raw) }
}

/// A session plus the `Arc` that keeps its engine alive.
struct SessionInner {
    // Declared first: struct fields drop in declaration order, so the
    // borrowing session is always dropped before the Arc that owns the
    // Engine it borrows.
    session: Session<'static>,
    _engine: Arc<Engine>,
}

/// Heap state behind an opaque [`CloakSession`] pointer.
///
/// The `Mutex<Option<…>>` makes misuse an error, never UB: a consumed
/// session (`None` after finish) reports `"session already consumed"`,
/// and a stray concurrent call from a second thread serializes on the
/// lock instead of racing the scanner (same pattern as cloak-py).
struct CloakSessionState {
    inner: Mutex<Option<SessionInner>>,
}

/// Serialize [`Stats`] to the JSON shape shared by all bindings:
/// `{"bytes_processed": n, "matches": {rule: count}, "near_misses": …}`
/// — `near_misses` omitted when empty (F13), exactly as cloak-wasm
/// ships it and every adapter already parses.
fn stats_json(stats: &Stats) -> Result<Vec<u8>, String> {
    serde_json::to_vec(stats).map_err(|e| format!("stats serialization failed: {e}"))
}

// ── Exported functions ──────────────────────────────────────────────

/// Returns [`CLOAK_ABI_VERSION`] for the loaded library. Never fails;
/// callable before anything else. Compare against the compile-time
/// constant from the header to catch a stale library.
#[unsafe(no_mangle)]
pub extern "C" fn cloak_abi_version() -> u32 {
    CLOAK_ABI_VERSION
}

/// Create a new engine from a TOML config string.
///
/// Returns an engine pointer, or null on failure with the message in
/// `*err_out` (when non-null). A `(NULL, 0)` config pair is the default
/// config: digest key from the `CLOAK_DIGEST_KEY` environment variable
/// (read from the *process* environment at construction time),
/// ephemeral-key fallback with a stderr warning.
///
/// Ownership of the returned engine transfers to the caller: release it
/// exactly once with [`cloak_engine_free`].
///
/// # Safety
///
/// `config_toml` must point to `config_len` valid bytes (UTF-8 TOML)
/// for the call's duration, or be any pointer when `config_len == 0`.
/// `err_out` must be null or valid for a [`CloakBuf`] write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cloak_engine_new(
    config_toml: *const u8,
    config_len: usize,
    err_out: *mut CloakBuf,
) -> *mut CloakEngine {
    // SAFETY: err_out is null or writable per the caller contract.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { init_out(err_out) };

    guarded_ptr("engine_new", err_out, || {
        // SAFETY: caller guarantees the (ptr, len) pair per the contract.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let bytes = unsafe { input_slice(config_toml, config_len) }?;
        let config_str =
            std::str::from_utf8(bytes).map_err(|e| format!("config is not valid UTF-8: {e}"))?;
        // Error messages mirror cloakwasm_engine_new / cloak-py so
        // host-visible diagnostics stay comparable across bindings.
        let config = Config::from_toml(config_str).map_err(|e| format!("invalid config: {e}"))?;
        let engine = Engine::new(&config).map_err(|e| format!("engine build failed: {e}"))?;
        Ok(Arc::into_raw(Arc::new(engine))
            .cast_mut()
            .cast::<CloakEngine>())
    })
}

/// Release an engine.
///
/// Refuses — returning [`CLOAK_ERR`] with the engine still valid and
/// usable — while sessions created from it are live or scans are in
/// flight (their clones hold the strong count above 1); finish or abort
/// them first, then retry. On [`CLOAK_OK`] the pointer is invalid.
/// `cloak_engine_free(NULL, …)` is a no-op returning [`CLOAK_OK`];
/// freeing the same engine twice is undefined behavior.
///
/// Must not run concurrently with any other call on the same engine
/// (the same rule as `free()`).
///
/// # Safety
///
/// `engine` must be null, or a live pointer from [`cloak_engine_new`]
/// not yet successfully freed. `err_out` must be null or valid for a
/// [`CloakBuf`] write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cloak_engine_free(
    engine: *mut CloakEngine,
    err_out: *mut CloakBuf,
) -> i32 {
    // SAFETY: err_out is null or writable per the caller contract.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { init_out(err_out) };
    if engine.is_null() {
        return CLOAK_OK;
    }

    guarded("engine_free", err_out, || {
        // SAFETY: engine came from Arc::into_raw in cloak_engine_new
        // (caller contract); this from_raw takes back that original
        // reference.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let arc = unsafe { Arc::from_raw(engine as *const Engine) };
        // Count > 1: live sessions (their `SessionInner` holds a clone)
        // or an in-flight call holding a transient clone. Put the
        // reference back — same allocation, the caller's pointer stays
        // valid — and refuse, mirroring cloak-py's dispose.
        if Arc::strong_count(&arc) > 1 {
            let _ = Arc::into_raw(arc);
            return Err(
                "cannot dispose engine while in use: finish or abort live sessions, \
                 and let in-flight scans complete first"
                    .to_string(),
            );
        }
        drop(arc);
        Ok(())
    })
}

/// One-shot redaction: scan a complete buffer with a fresh internal
/// session (equivalent to session → push → finish).
///
/// On success writes the redacted bytes into `*out` and, when
/// `stats_json_out` is non-null, the UTF-8 JSON stats object into
/// `*stats_json_out` (pass null to skip stats serialization). On
/// failure both are `{NULL, 0}` — always safe to pass to
/// [`cloak_buf_free`]. The caller owns every written buffer.
///
/// # Safety
///
/// `engine` must be a live pointer from [`cloak_engine_new`]. `input`
/// must point to `input_len` valid bytes for the call's duration, or be
/// any pointer when `input_len == 0`. `out`, `stats_json_out`, and
/// `err_out` must each be null or valid for a [`CloakBuf`] write
/// (`out` is required).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cloak_redact(
    engine: *const CloakEngine,
    input: *const u8,
    input_len: usize,
    out: *mut CloakBuf,
    stats_json_out: *mut CloakBuf,
    err_out: *mut CloakBuf,
) -> i32 {
    // SAFETY: each out-param is null or writable per the caller contract.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        init_out(err_out);
        init_out(out);
        init_out(stats_json_out);
    }

    guarded("redact", err_out, || {
        if out.is_null() {
            return Err("out must not be null".to_string());
        }
        if engine.is_null() {
            return Err("null engine pointer".to_string());
        }
        // SAFETY: caller guarantees the (ptr, len) pair per the contract.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let input = unsafe { input_slice(input, input_len) }?;
        // SAFETY: engine is live per the caller contract.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let engine = unsafe { engine_clone(engine) };

        let mut buf = Vec::with_capacity(input.len().min(OUTPUT_CAPACITY_CAP));
        let mut session = engine.session();
        session
            .push(input, &mut buf)
            .map_err(|e| format!("redact failed: {e}"))?;
        let stats = session
            .finish(&mut buf)
            .map_err(|e| format!("redact failed: {e}"))?;

        if !stats_json_out.is_null() {
            let json = stats_json(&stats)?;
            // SAFETY: non-null per check; writable per the caller contract.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { stats_json_out.write(buf_from_vec(json)) };
        }
        // SAFETY: non-null per check; writable per the caller contract.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { out.write(buf_from_vec(buf)) };
        Ok(())
    })
}

/// Create a streaming session from an engine.
///
/// Returns a session pointer, or null on failure with the message in
/// `*err_out`. The session holds a strong reference to its engine —
/// [`cloak_engine_free`] refuses while it is live. Ownership transfers
/// to the caller: release exactly once with [`cloak_session_free`],
/// including after [`cloak_session_finish`].
///
/// # Safety
///
/// `engine` must be a live pointer from [`cloak_engine_new`]. `err_out`
/// must be null or valid for a [`CloakBuf`] write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cloak_session_new(
    engine: *const CloakEngine,
    err_out: *mut CloakBuf,
) -> *mut CloakSession {
    // SAFETY: err_out is null or writable per the caller contract.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { init_out(err_out) };

    guarded_ptr("session_new", err_out, || {
        if engine.is_null() {
            return Err("null engine pointer".to_string());
        }
        // SAFETY: engine is live per the caller contract.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let engine = unsafe { engine_clone(engine) };
        // SAFETY: `Session` only borrows `&Engine`. The Arc clone stored
        // alongside it in `SessionInner` pins the Engine at a stable heap
        // address for the session's whole lifetime, and the field order
        // drops the session before the Arc. Lifetime erasure mirrors
        // crates/cloak-py/src/lib.rs.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let pinned: &'static Engine = unsafe { &*Arc::as_ptr(&engine) };
        let state = CloakSessionState {
            inner: Mutex::new(Some(SessionInner {
                session: pinned.session(),
                _engine: engine,
            })),
        };
        Ok(Box::into_raw(Box::new(state)).cast::<CloakSession>())
    })
}

/// Push a chunk through the session's scanner.
///
/// On success writes the bytes flushed by this push into `*out` — may
/// be `{NULL, 0}` while the carry-over window withholds a potential
/// match. On failure `*out` is `{NULL, 0}`. The caller owns the written
/// buffer. A `(NULL, 0)` input pair is a valid empty chunk.
///
/// # Safety
///
/// `session` must be a live pointer from [`cloak_session_new`]. `input`
/// must point to `input_len` valid bytes for the call's duration, or be
/// any pointer when `input_len == 0`. `out` and `err_out` must each be
/// null or valid for a [`CloakBuf`] write (`out` is required).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cloak_session_push(
    session: *mut CloakSession,
    input: *const u8,
    input_len: usize,
    out: *mut CloakBuf,
    err_out: *mut CloakBuf,
) -> i32 {
    // SAFETY: each out-param is null or writable per the caller contract.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        init_out(err_out);
        init_out(out);
    }

    guarded("push", err_out, || {
        if out.is_null() {
            return Err("out must not be null".to_string());
        }
        if session.is_null() {
            return Err("null session pointer".to_string());
        }
        // SAFETY: caller guarantees the (ptr, len) pair per the contract.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let input = unsafe { input_slice(input, input_len) }?;
        // SAFETY: session is live per the caller contract; shared access
        // is safe — mutation goes through the Mutex.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let state = unsafe { &*(session as *const CloakSessionState) };

        let mut guard = state
            .inner
            .lock()
            .map_err(|_| "session state lock poisoned".to_string())?;
        let inner = guard
            .as_mut()
            .ok_or_else(|| "session already consumed (finished or aborted)".to_string())?;

        let mut buf = Vec::with_capacity(input.len().min(OUTPUT_CAPACITY_CAP));
        inner
            .session
            .push(input, &mut buf)
            .map_err(|e| format!("push failed: {e}"))?;
        // SAFETY: non-null per check; writable per the caller contract.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { out.write(buf_from_vec(buf)) };
        Ok(())
    })
}

/// Finish the session: flush the carry-over and collect stats.
///
/// Always consumes the session's scanning state — success or failure —
/// so further push/finish calls return [`CLOAK_ERR`] (`"session already
/// consumed (finished or aborted)"`); the pointer itself stays valid
/// until [`cloak_session_free`], which is still required exactly once.
/// (Mirrors `cloakwasm_finish`, but misuse is an error, not UB.)
///
/// On success writes the final flushed bytes into `*out` and, when
/// `stats_json_out` is non-null, the UTF-8 JSON stats into
/// `*stats_json_out` (pass null to skip). The caller owns every written
/// buffer.
///
/// # Safety
///
/// `session` must be a live pointer from [`cloak_session_new`]. `out`,
/// `stats_json_out`, and `err_out` must each be null or valid for a
/// [`CloakBuf`] write (`out` is required).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cloak_session_finish(
    session: *mut CloakSession,
    out: *mut CloakBuf,
    stats_json_out: *mut CloakBuf,
    err_out: *mut CloakBuf,
) -> i32 {
    // SAFETY: each out-param is null or writable per the caller contract.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        init_out(err_out);
        init_out(out);
        init_out(stats_json_out);
    }

    guarded("finish", err_out, || {
        if out.is_null() {
            return Err("out must not be null".to_string());
        }
        if session.is_null() {
            return Err("null session pointer".to_string());
        }
        // SAFETY: session is live per the caller contract; shared access
        // is safe — mutation goes through the Mutex.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let state = unsafe { &*(session as *const CloakSessionState) };

        // take() BEFORE finishing: the scanning state is consumed even
        // when finish fails (the carry-over is dropped either way).
        let inner = state
            .inner
            .lock()
            .map_err(|_| "session state lock poisoned".to_string())?
            .take()
            .ok_or_else(|| "session already consumed (finished or aborted)".to_string())?;
        // `_engine` stays on this frame, keeping the engine pinned while
        // the moved session is consumed.
        let SessionInner { session, _engine } = inner;

        let mut buf = Vec::new();
        let stats = session
            .finish(&mut buf)
            .map_err(|e| format!("finish failed: {e}"))?;

        if !stats_json_out.is_null() {
            let json = stats_json(&stats)?;
            // SAFETY: non-null per check; writable per the caller contract.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { stats_json_out.write(buf_from_vec(json)) };
        }
        // SAFETY: non-null per check; writable per the caller contract.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { out.write(buf_from_vec(buf)) };
        Ok(())
    })
}

/// Release a session without finishing it (the abort path): drops the
/// session and any carry-over it holds — nothing is flushed — and lifts
/// the engine pin the session created. Also the required final release
/// after [`cloak_session_finish`].
///
/// `cloak_session_free(NULL)` is a no-op; freeing the same session
/// twice is undefined behavior.
///
/// # Safety
///
/// `session` must be null, or a pointer from [`cloak_session_new`] not
/// yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cloak_session_free(session: *mut CloakSession) {
    if session.is_null() {
        return;
    }
    // catch_unwind: Drop runs here — a panicking Drop must not cross
    // the boundary. Nothing to report through (no err_out by design:
    // freeing cannot meaningfully fail for a valid pointer).
    let _ = panic::catch_unwind(|| {
        // SAFETY: session came from Box::into_raw in cloak_session_new
        // (caller contract) and is freed exactly once.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        drop(unsafe { Box::from_raw(session as *mut CloakSessionState) });
    });
}

/// Release a [`CloakBuf`] previously written by any `cloak_*` function.
///
/// A `{NULL, 0}` buffer is a no-op — failure-path out-params are always
/// safe to pass here unconditionally. Freeing the same buffer twice is
/// undefined behavior.
///
/// # Safety
///
/// `buf` must be `{NULL, 0}` or exactly as written by a `cloak_*`
/// function, unmodified, and not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cloak_buf_free(buf: CloakBuf) {
    if buf.ptr.is_null() || buf.len == 0 {
        return;
    }
    // SAFETY: buf_from_vec built this from a boxed slice with
    // capacity == len; reconstruct and drop it. The raw slice pointer
    // is built directly (no intermediate `&mut [u8]`) so the free is
    // clean under Stacked Borrows.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        drop(Box::from_raw(ptr::slice_from_raw_parts_mut(
            buf.ptr, buf.len,
        )));
    }
}

// ── Boundary tests (the Miri/ASAN/LSAN gate surface) ────────────────

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Once;

    const KEY_VAR: &str = "CLOAK_DIGEST_KEY";
    const KEY_MATERIAL: &str = "cloak-ffi-unit-test-key";

    /// A GitHub token long enough to span chunk boundaries when split.
    const INPUT: &[u8] = b"token=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 done\n";
    /// Same token with a CRC-invalid checksum (F13 near-miss).
    const NEAR_MISS: &[u8] = b"token=ghp_AbCdEfGhIjKlMnOpQrStUvWxYz01232piBxf done\n";

    static INIT: Once = Once::new();

    fn init() {
        INIT.call_once(|| {
            // SAFETY: test-only; single dedicated var, set exactly once
            // before any engine is built, never removed.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { std::env::set_var(KEY_VAR, KEY_MATERIAL) };
        });
    }

    /// Full-catalog config outside Miri.
    #[cfg(not(miri))]
    fn test_config() -> String {
        "[redaction]\ndigest_key = \"env:CLOAK_DIGEST_KEY\"\n".to_string()
    }

    /// Under Miri, dense-DFA compilation is interpreted and brutally
    /// slow, so every rule except github-token is disabled. The
    /// boundary paths these tests pin (pointers, ownership, panic
    /// shield, Arc counts) are rule-count-independent.
    #[cfg(miri)]
    fn test_config() -> String {
        let mut s = String::from("[redaction]\ndigest_key = \"env:CLOAK_DIGEST_KEY\"\n\n");
        for spec in cloak_core::CATALOG {
            if spec.id != "github-token" {
                s.push_str(&format!("[rules.{}]\nenabled = false\n\n", spec.id));
            }
        }
        s.push_str(&format!(
            "[rules.{}]\nenabled = false\n\n",
            cloak_core::PEM_RULE_ID
        ));
        s
    }

    // ── Helpers ─────────────────────────────────────────────────────

    fn empty_buf() -> CloakBuf {
        CloakBuf::empty()
    }

    /// Read a `CloakBuf`'s bytes and free it.
    fn take_buf(buf: CloakBuf) -> Vec<u8> {
        if buf.len == 0 {
            assert!(buf.ptr.is_null(), "empty buffers must carry a null ptr");
            return Vec::new();
        }
        // SAFETY: buf was written by a cloak_* call; read before free.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let data = unsafe { std::slice::from_raw_parts(buf.ptr, buf.len).to_vec() };
        // SAFETY: freed exactly once, unmodified.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { cloak_buf_free(buf) };
        data
    }

    /// Read an error buffer as UTF-8 and free it.
    fn take_err(buf: CloakBuf) -> String {
        String::from_utf8(take_buf(buf)).expect("error messages must be UTF-8")
    }

    fn engine_new(config: &str) -> *mut CloakEngine {
        init();
        let mut err = empty_buf();
        // SAFETY: valid (ptr, len) from a &str; err is writable.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let engine = unsafe { cloak_engine_new(config.as_ptr(), config.len(), &mut err) };
        assert!(!engine.is_null(), "engine_new failed: {}", take_err(err));
        engine
    }

    fn test_engine() -> *mut CloakEngine {
        engine_new(&test_config())
    }

    fn engine_free(engine: *mut CloakEngine) -> (i32, String) {
        let mut err = empty_buf();
        // SAFETY: engine per test flow; err is writable.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let status = unsafe { cloak_engine_free(engine, &mut err) };
        (status, take_err(err))
    }

    fn session_new(engine: *const CloakEngine) -> *mut CloakSession {
        let mut err = empty_buf();
        // SAFETY: engine is live; err is writable.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let session = unsafe { cloak_session_new(engine, &mut err) };
        assert!(!session.is_null(), "session_new failed: {}", take_err(err));
        session
    }

    /// Push, asserting success; returns the flushed bytes.
    fn push_ok(session: *mut CloakSession, input: &[u8]) -> Vec<u8> {
        let (status, out, err) = push_raw(session, input.as_ptr(), input.len());
        assert_eq!(status, CLOAK_OK, "push failed: {err}");
        out
    }

    fn push_raw(session: *mut CloakSession, ptr: *const u8, len: usize) -> (i32, Vec<u8>, String) {
        let mut out = empty_buf();
        let mut err = empty_buf();
        // SAFETY: pointers per test flow; out/err are writable.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let status = unsafe { cloak_session_push(session, ptr, len, &mut out, &mut err) };
        (status, take_buf(out), take_err(err))
    }

    /// Finish, returning (status, output, stats-JSON, error).
    fn finish_raw(session: *mut CloakSession) -> (i32, Vec<u8>, Vec<u8>, String) {
        let mut out = empty_buf();
        let mut stats = empty_buf();
        let mut err = empty_buf();
        // SAFETY: session per test flow; outs are writable.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let status = unsafe { cloak_session_finish(session, &mut out, &mut stats, &mut err) };
        (status, take_buf(out), take_buf(stats), take_err(err))
    }

    /// One-shot redact, asserting success; returns (output, stats JSON).
    fn redact_ok(engine: *const CloakEngine, input: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut out = empty_buf();
        let mut stats = empty_buf();
        let mut err = empty_buf();
        // SAFETY: pointers per test flow; outs are writable.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let status = unsafe {
            cloak_redact(
                engine,
                input.as_ptr(),
                input.len(),
                &mut out,
                &mut stats,
                &mut err,
            )
        };
        assert_eq!(status, CLOAK_OK, "redact failed: {}", take_err(err));
        take_buf(err);
        (take_buf(out), take_buf(stats))
    }

    fn stats_value(json: &[u8]) -> serde_json::Value {
        serde_json::from_slice(json).expect("stats must be valid JSON")
    }

    // ── abi version ─────────────────────────────────────────────────

    #[test]
    fn abi_version_matches_constant() {
        assert_eq!(cloak_abi_version(), CLOAK_ABI_VERSION);
        assert_eq!(CLOAK_ABI_VERSION, 1);
    }

    // ── lifecycle + parity ──────────────────────────────────────────

    #[test]
    fn full_lifecycle_streamed_matches_one_shot() {
        let engine = test_engine();

        let (one_shot, stats_json) = redact_ok(engine, INPUT);
        assert!(
            one_shot.starts_with(b"token=[CLOAK:github-token:"),
            "token not redacted: {:?}",
            String::from_utf8_lossy(&one_shot)
        );
        let stats = stats_value(&stats_json);
        assert_eq!(stats["bytes_processed"], INPUT.len());
        assert_eq!(stats["matches"]["github-token"], 1);

        // Same input in three chunks must concatenate to the same bytes,
        // regardless of where the engine flushes internally.
        let session = session_new(engine);
        let mut streamed = Vec::new();
        for chunk in [&INPUT[..15], &INPUT[15..30], &INPUT[30..]] {
            streamed.extend_from_slice(&push_ok(session, chunk));
        }
        let (status, tail, finish_stats, err) = finish_raw(session);
        assert_eq!(status, CLOAK_OK, "finish failed: {err}");
        streamed.extend_from_slice(&tail);
        assert_eq!(streamed, one_shot);
        assert_eq!(stats_value(&finish_stats)["matches"]["github-token"], 1);

        // SAFETY: freed exactly once after finish.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { cloak_session_free(session) };
        let (status, err) = engine_free(engine);
        assert_eq!(status, CLOAK_OK, "engine_free failed: {err}");
    }

    #[test]
    fn engine_new_rejects_bad_configs() {
        init();

        let cases: &[(&[u8], &str)] = &[
            (&[0xFF, 0xFE], "config is not valid UTF-8"),
            (b"not toml at all [[[", "invalid config"),
            // Parses but fails validation inside Engine::new (inline
            // digest keys are rejected by cloak-core).
            (
                b"[redaction]\ndigest_key = \"inline-not-allowed\"\n",
                "engine build failed",
            ),
        ];
        for (config, want) in cases {
            let mut err = empty_buf();
            // SAFETY: valid (ptr, len); err is writable.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let engine = unsafe { cloak_engine_new(config.as_ptr(), config.len(), &mut err) };
            assert!(engine.is_null(), "config must be rejected: {want}");
            let msg = take_err(err);
            assert!(msg.contains(want), "want {want:?} in {msg:?}");
        }

        // err_out = NULL: message discarded, no crash, no leak (LSAN
        // proves the latter in CI).
        let bad = b"not toml at all [[[";
        // SAFETY: valid (ptr, len); null err_out is a documented opt-out.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let engine = unsafe { cloak_engine_new(bad.as_ptr(), bad.len(), ptr::null_mut()) };
        assert!(engine.is_null());
    }

    #[test]
    fn empty_pairs_with_null_ptr_are_valid() {
        init();

        // (null, 0) config = default config (ephemeral key fallback —
        // CLOAK_DIGEST_KEY is set by init() so the env path resolves).
        let mut err = empty_buf();
        // SAFETY: (null, 0) is a documented valid empty pair.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let engine = unsafe { cloak_engine_new(ptr::null(), 0, &mut err) };
        assert!(
            !engine.is_null(),
            "default config failed: {}",
            take_err(err)
        );

        // redact with (null, 0) must succeed as a no-op pass.
        let mut out = empty_buf();
        let mut err = empty_buf();
        // SAFETY: (null, 0) is a documented valid empty pair.
        let status =
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { cloak_redact(engine, ptr::null(), 0, &mut out, ptr::null_mut(), &mut err) };
        assert_eq!(status, CLOAK_OK, "redact failed: {}", take_err(err));
        assert_eq!(take_buf(out), Vec::<u8>::new());
        take_buf(err);

        // push with (null, 0) must be a valid empty chunk.
        let session = session_new(engine);
        let (status, out, err) = push_raw(session, ptr::null(), 0);
        assert_eq!(status, CLOAK_OK, "push failed: {err}");
        assert!(out.is_empty());
        let (status, out, _stats, err) = finish_raw(session);
        assert_eq!(status, CLOAK_OK, "finish failed: {err}");
        assert!(out.is_empty());
        // SAFETY: freed exactly once after finish.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { cloak_session_free(session) };

        let (status, err) = engine_free(engine);
        assert_eq!(status, CLOAK_OK, "engine_free failed: {err}");
    }

    #[test]
    fn null_with_nonzero_length_rejected() {
        let engine = test_engine();

        let mut out = empty_buf();
        let mut err = empty_buf();
        // SAFETY: documented error path — pointers are checked, not read.
        let status =
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { cloak_redact(engine, ptr::null(), 5, &mut out, ptr::null_mut(), &mut err) };
        assert_eq!(status, CLOAK_ERR);
        assert!(
            take_buf(out).is_empty(),
            "failed call must write {{NULL, 0}}"
        );
        assert!(take_err(err).contains("null pointer with non-zero length"));

        let (status, err) = engine_free(engine);
        assert_eq!(status, CLOAK_OK, "engine_free failed: {err}");
    }

    #[test]
    fn null_handles_error_not_crash() {
        init();

        // Null engine.
        let mut out = empty_buf();
        let mut err = empty_buf();
        // SAFETY: documented error path — null handles are checked first.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let status = unsafe {
            cloak_redact(
                ptr::null(),
                b"x".as_ptr(),
                1,
                &mut out,
                ptr::null_mut(),
                &mut err,
            )
        };
        assert_eq!(status, CLOAK_ERR);
        take_buf(out);
        assert!(take_err(err).contains("null engine pointer"));

        let mut err = empty_buf();
        // SAFETY: documented error path.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let session = unsafe { cloak_session_new(ptr::null(), &mut err) };
        assert!(session.is_null());
        assert!(take_err(err).contains("null engine pointer"));

        // Null session.
        let (status, _out, err) = push_raw(ptr::null_mut(), b"x".as_ptr(), 1);
        assert_eq!(status, CLOAK_ERR);
        assert!(err.contains("null session pointer"));

        let (status, _out, _stats, err) = finish_raw(ptr::null_mut());
        assert_eq!(status, CLOAK_ERR);
        assert!(err.contains("null session pointer"));

        // The two frees are documented null no-ops.
        let mut err = empty_buf();
        // SAFETY: null is a documented no-op.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let status = unsafe { cloak_engine_free(ptr::null_mut(), &mut err) };
        assert_eq!(status, CLOAK_OK);
        take_buf(err);
        // SAFETY: null is a documented no-op.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { cloak_session_free(ptr::null_mut()) };
    }

    #[test]
    fn null_out_param_rejected() {
        let engine = test_engine();
        let session = session_new(engine);

        let mut err = empty_buf();
        // SAFETY: documented error path — out is checked before use.
        let status =
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { cloak_session_push(session, b"x".as_ptr(), 1, ptr::null_mut(), &mut err) };
        assert_eq!(status, CLOAK_ERR);
        assert!(take_err(err).contains("out must not be null"));

        let mut err = empty_buf();
        // SAFETY: documented error path.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let status = unsafe {
            cloak_redact(
                engine,
                b"x".as_ptr(),
                1,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut err,
            )
        };
        assert_eq!(status, CLOAK_ERR);
        assert!(take_err(err).contains("out must not be null"));

        // The rejected calls must not have consumed the session.
        let (status, _out, _stats, err) = finish_raw(session);
        assert_eq!(status, CLOAK_OK, "finish failed: {err}");
        // SAFETY: freed exactly once after finish.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { cloak_session_free(session) };
        let (status, err) = engine_free(engine);
        assert_eq!(status, CLOAK_OK, "engine_free failed: {err}");
    }

    #[test]
    fn engine_free_refused_while_session_live() {
        let engine = test_engine();
        let session = session_new(engine);

        // Refused: the session's SessionInner holds an Arc clone.
        let (status, err) = engine_free(engine);
        assert_eq!(status, CLOAK_ERR);
        assert!(
            err.contains("cannot dispose engine while in use"),
            "unexpected: {err}"
        );

        // The engine must be fully usable after the refusal (the Arc
        // count was restored): both via the session and directly.
        let flushed = push_ok(session, b"hello world");
        assert!(flushed.is_empty(), "11 bytes sit in the carry-over window");
        let (one_shot, _stats) = redact_ok(engine, b"plain text");
        assert_eq!(one_shot, b"plain text");

        // A second refusal proves the first one restored the count
        // instead of leaking a decrement.
        let (status, err) = engine_free(engine);
        assert_eq!(status, CLOAK_ERR, "second refusal expected: {err}");

        let (status, out, _stats, err) = finish_raw(session);
        assert_eq!(status, CLOAK_OK, "finish failed: {err}");
        assert_eq!(out, b"hello world");
        // SAFETY: freed exactly once after finish.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { cloak_session_free(session) };

        // Now the free succeeds.
        let (status, err) = engine_free(engine);
        assert_eq!(status, CLOAK_OK, "engine_free failed: {err}");
    }

    #[test]
    fn session_free_aborts_and_lifts_engine_pin() {
        let engine = test_engine();
        let session = session_new(engine);

        // Bytes in the carry-over are dropped, never flushed.
        push_ok(session, INPUT);
        // SAFETY: live session, freed exactly once (abort path).
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { cloak_session_free(session) };

        let (status, err) = engine_free(engine);
        assert_eq!(status, CLOAK_OK, "engine_free failed: {err}");
    }

    #[test]
    fn session_consumed_on_finish_even_on_later_misuse() {
        let engine = test_engine();
        let session = session_new(engine);

        push_ok(session, INPUT);
        let (status, _out, _stats, err) = finish_raw(session);
        assert_eq!(status, CLOAK_OK, "finish failed: {err}");

        // Double finish: error, not UB.
        let (status, out, stats, err) = finish_raw(session);
        assert_eq!(status, CLOAK_ERR);
        assert!(out.is_empty() && stats.is_empty());
        assert_eq!(err, "session already consumed (finished or aborted)");

        // Push after finish: same error.
        let (status, _out, err) = push_raw(session, b"x".as_ptr(), 1);
        assert_eq!(status, CLOAK_ERR);
        assert_eq!(err, "session already consumed (finished or aborted)");

        // The pointer still requires exactly one free.
        // SAFETY: freed exactly once.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { cloak_session_free(session) };
        let (status, err) = engine_free(engine);
        assert_eq!(status, CLOAK_OK, "engine_free failed: {err}");
    }

    #[test]
    fn buf_free_null_and_empty_noop() {
        // SAFETY: {NULL, 0} is a documented no-op.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { cloak_buf_free(CloakBuf::empty()) };
        // A dangling-but-unread ptr with len 0 must also be a no-op —
        // the len check returns first.
        // SAFETY: ptr is never dereferenced when len == 0.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            cloak_buf_free(CloakBuf {
                ptr: ptr::NonNull::<u8>::dangling().as_ptr(),
                len: 0,
            })
        };
    }

    #[test]
    fn stats_json_shape_and_near_misses() {
        let engine = test_engine();

        // Valid token: a match, and NO near_misses key (omitted when
        // empty — adapters key nil-vs-absent semantics off this).
        let (_out, stats_json) = redact_ok(engine, INPUT);
        let stats = stats_value(&stats_json);
        assert_eq!(stats["matches"]["github-token"], 1);
        assert!(
            stats.get("near_misses").is_none(),
            "near_misses must be omitted when empty: {stats}"
        );

        // CRC-invalid token: passthrough + one near-miss (F13).
        let (out, stats_json) = redact_ok(engine, NEAR_MISS);
        assert_eq!(out, NEAR_MISS, "near-miss must pass through unredacted");
        let stats = stats_value(&stats_json);
        assert_eq!(stats["near_misses"]["github-token"], 1);
        assert_eq!(stats["bytes_processed"], NEAR_MISS.len());

        let (status, err) = engine_free(engine);
        assert_eq!(status, CLOAK_OK, "engine_free failed: {err}");
    }

    #[test]
    fn stats_out_null_is_allowed() {
        let engine = test_engine();

        let mut out = empty_buf();
        let mut err = empty_buf();
        // SAFETY: null stats_json_out is a documented opt-out.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let status = unsafe {
            cloak_redact(
                engine,
                INPUT.as_ptr(),
                INPUT.len(),
                &mut out,
                ptr::null_mut(),
                &mut err,
            )
        };
        assert_eq!(status, CLOAK_OK, "redact failed: {}", take_err(err));
        take_buf(err);
        assert!(take_buf(out).starts_with(b"token=[CLOAK:github-token:"));

        // Same for finish.
        let session = session_new(engine);
        push_ok(session, INPUT);
        let mut out = empty_buf();
        let mut err = empty_buf();
        // SAFETY: null stats_json_out is a documented opt-out.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let status = unsafe { cloak_session_finish(session, &mut out, ptr::null_mut(), &mut err) };
        assert_eq!(status, CLOAK_OK, "finish failed: {}", take_err(err));
        take_buf(err);
        take_buf(out);
        // SAFETY: freed exactly once after finish.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { cloak_session_free(session) };

        let (status, err) = engine_free(engine);
        assert_eq!(status, CLOAK_OK, "engine_free failed: {err}");
    }

    #[test]
    fn panic_is_caught_at_boundary() {
        // Exercises the exact production shields: a panic inside the
        // guarded body must surface as CLOAK_ERR_PANIC / null + message,
        // never unwind past the helper.
        let mut err = empty_buf();
        let status = guarded("test_op", &mut err, || panic!("boom"));
        assert_eq!(status, CLOAK_ERR_PANIC);
        assert_eq!(take_err(err), "test_op panicked");

        let mut err = empty_buf();
        let p: *mut CloakEngine = guarded_ptr("test_op", &mut err, || panic!("boom"));
        assert!(p.is_null());
        assert_eq!(take_err(err), "test_op panicked");
    }

    /// Byte-exactness of the boundary against direct core calls, over a
    /// sample of the real parity corpus. (The full 247-vector sweep runs
    /// in the C harness and the cloak-go suite against the same library;
    /// ignored under Miri — scan-heavy, and the full catalog build is
    /// interpreted.)
    #[test]
    #[cfg_attr(miri, ignore)]
    fn outputs_exact_against_core() {
        init();
        let config_toml = test_config();
        let engine = engine_new(&config_toml);

        let config = Config::from_toml(&config_toml).expect("test config parses");
        let core_engine = Engine::new(&config).expect("core engine builds");

        for v in cloak_core::vectors::all_vectors().iter().take(10) {
            let (ffi_out, _stats) = redact_ok(engine, v.input);

            let mut core_out = Vec::new();
            let mut session = core_engine.session();
            session.push(v.input, &mut core_out).expect("core push");
            session.finish(&mut core_out).expect("core finish");

            assert_eq!(
                ffi_out, core_out,
                "FFI output diverges from core for vector {}",
                v.name
            );
        }

        let (status, err) = engine_free(engine);
        assert_eq!(status, CLOAK_OK, "engine_free failed: {err}");
    }
}
