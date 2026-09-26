//! `cloak-wasm` — linear-memory ABI over `cloak-core`.
//!
//! This crate compiles to a single `.wasm` artifact (`cdylib`) targeting
//! `wasm32-wasip1`. Host adapters (Node, Python, Go, …) instantiate the
//! module via their WASM runtime and call the exported functions below.
//!
//! # Safety boundary
//!
//! All `unsafe` in the project is confined to this crate. `cloak-core`
//! remains `#![deny(unsafe_code)]`. The unsafe here is the minimum
//! required for a C-ABI / linear-memory interface:
//!
//! - Pointer dereference for input slices passed by the host.
//! - Lifetime transmute so `Session<'e>` can live in a handle table
//!   across FFI calls (engine outlives session by construction).
//! - `catch_unwind` to prevent panics crossing the WASM boundary.
//!
//! # Handle protocol
//!
//! Engines and sessions are stored in per-type handle tables and
//! referenced by opaque `u32` handles. A handle value of `0` is
//! reserved as an error sentinel — valid handles start at `1`.
//!
//! # Safety contract for callers
//!
//! All pointer-taking exports are `unsafe extern "C"` — the caller
//! (WASM host) is responsible for passing valid `(ptr, len)` pairs
//! obtained from [`cloakwasm_alloc`], and for freeing results via
//! [`cloakwasm_buf_free`].

#![allow(unsafe_code)]

use std::cell::RefCell;
use std::panic;

use cloak_core::{Config, Engine, Session, Stats};

// ── Handle table ────────────────────────────────────────────────────

/// Simple slab: index 0 is unused (sentinel), entries start at 1.
struct Slab<T> {
    entries: Vec<Option<T>>,
    free: Vec<u32>,
}

impl<T> Slab<T> {
    fn new() -> Self {
        Self {
            // Index 0 reserved — push a placeholder.
            entries: vec![None],
            free: Vec::new(),
        }
    }

    fn insert(&mut self, value: T) -> u32 {
        if let Some(idx) = self.free.pop() {
            self.entries[idx as usize] = Some(value);
            idx
        } else {
            let idx = self.entries.len() as u32;
            self.entries.push(Some(value));
            idx
        }
    }

    fn get(&self, handle: u32) -> Option<&T> {
        self.entries.get(handle as usize)?.as_ref()
    }

    fn get_mut(&mut self, handle: u32) -> Option<&mut T> {
        self.entries.get_mut(handle as usize)?.as_mut()
    }

    fn remove(&mut self, handle: u32) -> Option<T> {
        let entry = self.entries.get_mut(handle as usize)?;
        let value = entry.take()?;
        self.free.push(handle);
        Some(value)
    }
}

// ── Thread-local state ──────────────────────────────────────────────

/// Session wrapper that owns its output buffer and hides the lifetime.
///
/// # Safety
///
/// `session` is `Session<'static>` obtained by transmuting the lifetime
/// from `&Engine`. This is sound because:
/// 1. The engine lives in `ENGINES` at a stable slab index.
/// 2. `engine_handle` is recorded so `engine_free` can refuse to drop
///    an engine that still has live sessions.
/// 3. WASM is single-threaded — no concurrent mutation.
struct SessionState {
    /// Used by `engine_free` to refuse dropping an engine with live sessions.
    engine_handle: u32,
    session: Session<'static>,
    output: Vec<u8>,
}

thread_local! {
    static ENGINES: RefCell<Slab<Box<Engine>>> = RefCell::new(Slab::new());
    static SESSIONS: RefCell<Slab<SessionState>> = RefCell::new(Slab::new());
    static LAST_ERROR: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) };
    static LAST_STATS: RefCell<Option<Stats>> = const { RefCell::new(None) };
}

// ── Return type ─────────────────────────────────────────────────────

/// Flat result struct returned through linear memory.
///
/// The host reads `ptr` and `len` to access the data, then calls
/// [`cloakwasm_buf_free`] to release both the data and the struct.
#[repr(C)]
pub struct BufResult {
    /// Pointer to the data bytes.
    ptr: *mut u8,
    /// Length of the data in bytes.
    len: u32,
}

/// Allocate a `BufResult` on the heap from a `Vec<u8>`.
fn buf_result_from_vec(v: Vec<u8>) -> *mut BufResult {
    let len = v.len() as u32;
    let mut boxed = v.into_boxed_slice();
    let ptr = boxed.as_mut_ptr();
    std::mem::forget(boxed);

    let result = Box::new(BufResult { ptr, len });
    Box::into_raw(result)
}

// ── Error helpers ───────────────────────────────────────────────────

fn set_last_error(msg: impl Into<Vec<u8>>) {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = Some(msg.into());
    });
}

fn clear_last_error() {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = None;
    });
}

// ── Exported functions ──────────────────────────────────────────────

/// Allocate `size` bytes in the module's linear memory.
///
/// The host uses this to write config TOML or input chunks before
/// calling [`cloakwasm_engine_new`] or [`cloakwasm_push`].
#[unsafe(no_mangle)]
pub extern "C" fn cloakwasm_alloc(size: u32) -> *mut u8 {
    let layout = match std::alloc::Layout::from_size_align(size as usize, 1) {
        Ok(l) if l.size() > 0 => l,
        _ => return std::ptr::null_mut(),
    };
    // SAFETY: layout is non-zero and aligned.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { std::alloc::alloc(layout) }
}

/// Free memory previously returned by [`cloakwasm_alloc`].
///
/// # Safety
///
/// `ptr` must have been returned by [`cloakwasm_alloc`] with the same
/// `size`, and must not have been freed already.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cloakwasm_dealloc(ptr: *mut u8, size: u32) {
    if ptr.is_null() || size == 0 {
        return;
    }
    let layout = match std::alloc::Layout::from_size_align(size as usize, 1) {
        Ok(l) => l,
        Err(_) => return,
    };
    // SAFETY: caller guarantees ptr/size match a prior cloakwasm_alloc.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { std::alloc::dealloc(ptr, layout) };
}

/// Create a new engine from a TOML config string.
///
/// Returns a handle `> 0` on success, or `0` on error. On error, call
/// [`cloakwasm_last_error`] for the message.
///
/// # Safety
///
/// `config_ptr` must point to `config_len` valid bytes (a UTF-8 TOML
/// string allocated via [`cloakwasm_alloc`]).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cloakwasm_engine_new(config_ptr: *const u8, config_len: u32) -> u32 {
    clear_last_error();

    let result = panic::catch_unwind(|| {
        // SAFETY: caller guarantees valid ptr/len.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let config_bytes = unsafe { std::slice::from_raw_parts(config_ptr, config_len as usize) };

        let config_str = std::str::from_utf8(config_bytes)
            .map_err(|e| format!("config is not valid UTF-8: {e}"))?;

        let config = Config::from_toml(config_str).map_err(|e| format!("invalid config: {e}"))?;

        Engine::new(&config).map_err(|e| format!("engine build failed: {e}"))
    });

    match result {
        Ok(Ok(engine)) => ENGINES.with(|e| e.borrow_mut().insert(Box::new(engine))),
        Ok(Err(msg)) => {
            set_last_error(msg);
            0
        }
        Err(_) => {
            set_last_error("engine_new panicked");
            0
        }
    }
}

/// Free an engine and release its handle.
///
/// If any sessions created from this engine are still live, the call
/// is refused and the error is available via [`cloakwasm_last_error`].
/// Finish or drop all sessions before freeing the engine.
#[unsafe(no_mangle)]
pub extern "C" fn cloakwasm_engine_free(handle: u32) {
    let has_live_sessions = SESSIONS.with(|sessions| {
        sessions
            .borrow()
            .entries
            .iter()
            .any(|e| e.as_ref().is_some_and(|s| s.engine_handle == handle))
    });
    if has_live_sessions {
        set_last_error(format!(
            "engine {handle} still has live sessions; finish them first"
        ));
        return;
    }
    ENGINES.with(|e| {
        e.borrow_mut().remove(handle);
    });
}

/// Create a new scanning session from an engine.
///
/// Returns a session handle `> 0`, or `0` on error.
#[unsafe(no_mangle)]
pub extern "C" fn cloakwasm_session_new(engine_handle: u32) -> u32 {
    clear_last_error();

    let result = panic::catch_unwind(|| {
        ENGINES.with(|engines| {
            let engines = engines.borrow();
            let engine: &Engine = match engines.get(engine_handle) {
                Some(e) => e,
                None => {
                    set_last_error(format!("invalid engine handle: {engine_handle}"));
                    return 0;
                }
            };

            // SAFETY: The engine lives in the slab at a stable Box address.
            // We extend the borrow to 'static because:
            // 1. The engine won't be freed while sessions exist (caller contract).
            // 2. WASM is single-threaded — no concurrent mutation.
            // 3. The session is removed from SESSIONS before the engine is freed.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let engine_ref: &'static Engine = unsafe { &*(engine as *const Engine) };

            let session = engine_ref.session();
            let state = SessionState {
                engine_handle,
                session,
                output: Vec::new(),
            };

            SESSIONS.with(|sessions| sessions.borrow_mut().insert(state))
        })
    });

    match result {
        Ok(handle) => handle,
        Err(_) => {
            set_last_error("session_new panicked");
            0
        }
    }
}

/// Push a chunk of bytes through the session's scanner.
///
/// Returns a pointer to a [`BufResult`] containing the redacted output
/// bytes flushed by this push (may be empty if all bytes are carried
/// over). The caller must free the result with [`cloakwasm_buf_free`].
///
/// Returns null on error — call [`cloakwasm_last_error`].
///
/// # Safety
///
/// `in_ptr` must point to `in_len` valid bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cloakwasm_push(
    session_handle: u32,
    in_ptr: *const u8,
    in_len: u32,
) -> *mut BufResult {
    clear_last_error();

    let result = panic::catch_unwind(|| {
        // SAFETY: caller guarantees valid ptr/len.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let input = unsafe { std::slice::from_raw_parts(in_ptr, in_len as usize) };

        SESSIONS.with(|sessions| {
            let mut sessions = sessions.borrow_mut();
            let state = match sessions.get_mut(session_handle) {
                Some(s) => s,
                None => {
                    set_last_error(format!("invalid session handle: {session_handle}"));
                    return std::ptr::null_mut();
                }
            };

            state.output.clear();
            match state.session.push(input, &mut state.output) {
                Ok(()) => {
                    let out = std::mem::take(&mut state.output);
                    buf_result_from_vec(out)
                }
                Err(e) => {
                    set_last_error(format!("push failed: {e}"));
                    std::ptr::null_mut()
                }
            }
        })
    });

    match result {
        Ok(ptr) => ptr,
        Err(_) => {
            set_last_error("push panicked");
            std::ptr::null_mut()
        }
    }
}

/// Finish the session: flush carry-over and return redacted output.
///
/// The returned [`BufResult`] contains the final flushed bytes. Stats
/// are returned as a separate call to [`cloakwasm_finish_stats`] (JSON).
/// The session handle is consumed — do not reuse it after this call.
///
/// Returns null on error — call [`cloakwasm_last_error`].
#[unsafe(no_mangle)]
pub extern "C" fn cloakwasm_finish(session_handle: u32) -> *mut BufResult {
    clear_last_error();

    let result = panic::catch_unwind(|| {
        let state = SESSIONS.with(|sessions| sessions.borrow_mut().remove(session_handle));

        let mut state = match state {
            Some(s) => s,
            None => {
                set_last_error(format!("invalid session handle: {session_handle}"));
                return (std::ptr::null_mut(), None);
            }
        };

        state.output.clear();
        match state.session.finish(&mut state.output) {
            Ok(stats) => {
                let out = std::mem::take(&mut state.output);
                (buf_result_from_vec(out), Some(stats))
            }
            Err(e) => {
                set_last_error(format!("finish failed: {e}"));
                (std::ptr::null_mut(), None)
            }
        }
    });

    match result {
        Ok((ptr, stats)) => {
            // Stash stats as JSON in LAST_STATS for cloakwasm_finish_stats.
            if let Some(stats) = stats {
                LAST_STATS.with(|s| {
                    *s.borrow_mut() = Some(stats);
                });
            }
            ptr
        }
        Err(_) => {
            set_last_error("finish panicked");
            std::ptr::null_mut()
        }
    }
}

/// Retrieve stats from the most recent [`cloakwasm_finish`] call as JSON.
///
/// Returns a [`BufResult`] containing UTF-8 JSON, or null if no stats
/// are available. The caller must free the result with [`cloakwasm_buf_free`].
#[unsafe(no_mangle)]
pub extern "C" fn cloakwasm_finish_stats() -> *mut BufResult {
    LAST_STATS.with(|s| {
        let stats = s.borrow_mut().take();
        match stats {
            Some(stats) => {
                let json = serde_json::to_vec(&stats).unwrap_or_default();
                buf_result_from_vec(json)
            }
            None => std::ptr::null_mut(),
        }
    })
}

/// Free a [`BufResult`] and its data buffer.
///
/// Null-safe — passing null is a no-op.
///
/// # Safety
///
/// `result` must have been returned by a `cloakwasm_*` function and
/// must not have been freed already.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cloakwasm_buf_free(result: *mut BufResult) {
    if result.is_null() {
        return;
    }
    // SAFETY: result was allocated by buf_result_from_vec.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        let r = Box::from_raw(result);
        if !r.ptr.is_null() && r.len > 0 {
            // Reconstruct the boxed slice and drop it.
            let slice = std::slice::from_raw_parts_mut(r.ptr, r.len as usize);
            drop(Box::from_raw(slice as *mut [u8]));
        }
    }
}

/// Retrieve the last error message.
///
/// Returns a [`BufResult`] containing UTF-8 error text, or null if no
/// error occurred since the last successful call. The caller must free
/// the result with [`cloakwasm_buf_free`].
#[unsafe(no_mangle)]
pub extern "C" fn cloakwasm_last_error() -> *mut BufResult {
    LAST_ERROR.with(|e| {
        let err = e.borrow_mut().take();
        match err {
            Some(msg) => buf_result_from_vec(msg),
            None => std::ptr::null_mut(),
        }
    })
}

// ── Convenience: one-shot redaction ─────────────────────────────────

/// Redact a complete buffer in one call (no session lifecycle).
///
/// Equivalent to `engine.session() → push(all) → finish()`. Returns
/// the fully redacted output, or null on error.
///
/// # Safety
///
/// `in_ptr` must point to `in_len` valid bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cloakwasm_redact(
    engine_handle: u32,
    in_ptr: *const u8,
    in_len: u32,
) -> *mut BufResult {
    clear_last_error();

    let result = panic::catch_unwind(|| {
        // SAFETY: caller guarantees valid ptr/len.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let input = unsafe { std::slice::from_raw_parts(in_ptr, in_len as usize) };

        ENGINES.with(|engines| {
            let engines = engines.borrow();
            let engine: &Engine = match engines.get(engine_handle) {
                Some(e) => e,
                None => {
                    set_last_error(format!("invalid engine handle: {engine_handle}"));
                    return std::ptr::null_mut();
                }
            };

            let mut session = engine.session();
            let mut out = Vec::new();
            if let Err(e) = session.push(input, &mut out) {
                set_last_error(format!("redact push failed: {e}"));
                return std::ptr::null_mut();
            }
            match session.finish(&mut out) {
                Ok(stats) => {
                    LAST_STATS.with(|s| {
                        *s.borrow_mut() = Some(stats);
                    });
                    buf_result_from_vec(out)
                }
                Err(e) => {
                    set_last_error(format!("redact finish failed: {e}"));
                    std::ptr::null_mut()
                }
            }
        })
    });

    match result {
        Ok(ptr) => ptr,
        Err(_) => {
            set_last_error("redact panicked");
            std::ptr::null_mut()
        }
    }
}
