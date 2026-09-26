//! Parity tests: every vector in the cloak-core corpus must produce
//! identical output when run through the WASM module via wasmtime.
//!
//! The `.wasm` artifact path is read from `CLOAK_WASM_PATH` (set by CI)
//! or falls back to the standard release build output.

use std::path::PathBuf;
use std::sync::OnceLock;

use wasmtime::*;
use wasmtime_wasi::WasiCtxBuilder;
use wasmtime_wasi::p1::WasiP1Ctx;

use cloak_core::vectors;

// ── Constants ───────────────────────────────────────────────────────

const KEY_MATERIAL: &str = "integration-test-key";
const KEY_VAR: &str = "CLOAK_DIGEST_KEY";

/// Config TOML that reads the digest key from the WASI env var.
const CONFIG_TOML: &str = "\
[redaction]\n\
digest_key = \"env:CLOAK_DIGEST_KEY\"\n\
";

// ── Wasm module loading ─────────────────────────────────────────────

fn wasm_path() -> PathBuf {
    if let Ok(p) = std::env::var("CLOAK_WASM_PATH") {
        return PathBuf::from(p);
    }
    // Fallback: standard cargo build output.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.join("../../target/wasm32-wasip1/release/cloak_wasm.wasm")
}

/// Shared wasmtime engine (compilation is expensive — do it once).
fn wasm_engine() -> &'static wasmtime::Engine {
    static ENGINE: OnceLock<wasmtime::Engine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        let mut config = Config::new();
        config.wasm_simd(true);
        wasmtime::Engine::new(&config).expect("wasmtime engine")
    })
}

fn wasm_module() -> &'static Module {
    static MODULE: OnceLock<Module> = OnceLock::new();
    MODULE.get_or_init(|| {
        let path = wasm_path();
        assert!(
            path.exists(),
            "WASM artifact not found at {path:?}. Build with: \
             RUSTFLAGS=\"-Ctarget-feature=+simd128\" cargo build -p cloak-wasm \
             --target wasm32-wasip1 --release"
        );
        Module::from_file(wasm_engine(), &path).expect("compile .wasm module")
    })
}

// ── Helper: WASM instance with exports ──────────────────────────────

struct WasmCloak {
    store: Store<WasiP1Ctx>,
    instance: Instance,
}

impl WasmCloak {
    fn new() -> Self {
        let engine = wasm_engine();
        let module = wasm_module();

        let wasi = WasiCtxBuilder::new().env(KEY_VAR, KEY_MATERIAL).build_p1();

        let mut store = Store::new(engine, wasi);
        let mut linker = Linker::new(engine);
        wasmtime_wasi::p1::add_to_linker_sync(&mut linker, |ctx| ctx).expect("link WASI");

        let instance = linker.instantiate(&mut store, module).expect("instantiate");

        Self { store, instance }
    }

    // ── Export accessors ────────────────────────────────────────────

    fn alloc(&mut self, size: u32) -> u32 {
        let func = self
            .instance
            .get_typed_func::<u32, u32>(&mut self.store, "cloakwasm_alloc")
            .expect("cloakwasm_alloc export");
        func.call(&mut self.store, size).expect("alloc")
    }

    fn dealloc(&mut self, ptr: u32, size: u32) {
        let func = self
            .instance
            .get_typed_func::<(u32, u32), ()>(&mut self.store, "cloakwasm_dealloc")
            .expect("cloakwasm_dealloc export");
        func.call(&mut self.store, (ptr, size)).expect("dealloc");
    }

    fn engine_new(&mut self, config: &str) -> u32 {
        let (ptr, alloc_size) = self.write_bytes(config.as_bytes());
        let func = self
            .instance
            .get_typed_func::<(u32, u32), u32>(&mut self.store, "cloakwasm_engine_new")
            .expect("cloakwasm_engine_new export");
        let handle = func
            .call(&mut self.store, (ptr, config.len() as u32))
            .expect("engine_new call");
        self.dealloc(ptr, alloc_size);
        assert!(
            handle > 0,
            "engine_new failed: {}",
            self.last_error_string()
        );
        handle
    }

    fn engine_free(&mut self, handle: u32) {
        let func = self
            .instance
            .get_typed_func::<u32, ()>(&mut self.store, "cloakwasm_engine_free")
            .expect("cloakwasm_engine_free export");
        func.call(&mut self.store, handle).expect("engine_free");
    }

    fn session_new(&mut self, engine_handle: u32) -> u32 {
        let func = self
            .instance
            .get_typed_func::<u32, u32>(&mut self.store, "cloakwasm_session_new")
            .expect("cloakwasm_session_new export");
        let handle = func
            .call(&mut self.store, engine_handle)
            .expect("session_new call");
        assert!(
            handle > 0,
            "session_new failed: {}",
            self.last_error_string()
        );
        handle
    }

    fn push(&mut self, session: u32, input: &[u8]) -> Vec<u8> {
        let (ptr, alloc_size) = self.write_bytes(input);
        let func = self
            .instance
            .get_typed_func::<(u32, u32, u32), u32>(&mut self.store, "cloakwasm_push")
            .expect("cloakwasm_push export");
        let result_ptr = func
            .call(&mut self.store, (session, ptr, input.len() as u32))
            .expect("push call");
        self.dealloc(ptr, alloc_size);
        assert!(result_ptr != 0, "push failed: {}", self.last_error_string());
        let data = self.read_buf_result(result_ptr);
        self.buf_free(result_ptr);
        data
    }

    fn finish(&mut self, session: u32) -> Vec<u8> {
        let func = self
            .instance
            .get_typed_func::<u32, u32>(&mut self.store, "cloakwasm_finish")
            .expect("cloakwasm_finish export");
        let result_ptr = func.call(&mut self.store, session).expect("finish call");
        assert!(
            result_ptr != 0,
            "finish failed: {}",
            self.last_error_string()
        );
        let data = self.read_buf_result(result_ptr);
        self.buf_free(result_ptr);
        data
    }

    fn redact(&mut self, engine_handle: u32, input: &[u8]) -> Vec<u8> {
        let (ptr, alloc_size) = self.write_bytes(input);
        let func = self
            .instance
            .get_typed_func::<(u32, u32, u32), u32>(&mut self.store, "cloakwasm_redact")
            .expect("cloakwasm_redact export");
        let result_ptr = func
            .call(&mut self.store, (engine_handle, ptr, input.len() as u32))
            .expect("redact call");
        self.dealloc(ptr, alloc_size);
        assert!(
            result_ptr != 0,
            "redact failed: {}",
            self.last_error_string()
        );
        let data = self.read_buf_result(result_ptr);
        self.buf_free(result_ptr);
        data
    }

    fn buf_free(&mut self, ptr: u32) {
        let func = self
            .instance
            .get_typed_func::<u32, ()>(&mut self.store, "cloakwasm_buf_free")
            .expect("cloakwasm_buf_free export");
        func.call(&mut self.store, ptr).expect("buf_free");
    }

    fn last_error(&mut self) -> Option<Vec<u8>> {
        let func = self
            .instance
            .get_typed_func::<(), u32>(&mut self.store, "cloakwasm_last_error")
            .expect("cloakwasm_last_error export");
        let ptr = func.call(&mut self.store, ()).expect("last_error call");
        if ptr == 0 {
            return None;
        }
        let data = self.read_buf_result(ptr);
        self.buf_free(ptr);
        Some(data)
    }

    fn last_error_string(&mut self) -> String {
        self.last_error()
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_else(|| "(no error)".to_string())
    }

    // ── Linear memory helpers ───────────────────────────────────────

    fn memory(&mut self) -> Memory {
        self.instance
            .get_memory(&mut self.store, "memory")
            .expect("memory export")
    }

    /// Write bytes into WASM linear memory, returning (ptr, alloc_size).
    /// Use the returned alloc_size for dealloc — it may differ from data.len()
    /// when data is empty (1 byte is allocated for a valid pointer).
    fn write_bytes(&mut self, data: &[u8]) -> (u32, u32) {
        let alloc_size = data.len().max(1) as u32;
        let ptr = self.alloc(alloc_size);
        assert!(ptr != 0, "alloc returned null for {alloc_size} bytes");
        if data.is_empty() {
            return (ptr, alloc_size);
        }
        let mem = self.memory();
        mem.data_mut(&mut self.store)[ptr as usize..ptr as usize + data.len()]
            .copy_from_slice(data);
        (ptr, alloc_size)
    }

    fn read_buf_result(&mut self, result_ptr: u32) -> Vec<u8> {
        let mem = self.memory();
        let data = mem.data(&self.store);

        // BufResult is { ptr: u32, len: u32 } — 8 bytes at result_ptr.
        let data_ptr = u32::from_le_bytes(
            data[result_ptr as usize..result_ptr as usize + 4]
                .try_into()
                .unwrap(),
        );
        let data_len = u32::from_le_bytes(
            data[result_ptr as usize + 4..result_ptr as usize + 8]
                .try_into()
                .unwrap(),
        );

        if data_len == 0 {
            return Vec::new();
        }

        data[data_ptr as usize..data_ptr as usize + data_len as usize].to_vec()
    }
}

// ── Tests ───────────────────────────────────────────────────────────

/// Compute the expected digest key, mirroring core's KDF.
fn test_key() -> [u8; 32] {
    blake3::derive_key("cloak digest key", KEY_MATERIAL.as_bytes())
}

#[test]
fn every_vector_through_wasm() {
    let key = test_key();
    let mut cloak = WasmCloak::new();
    let engine = cloak.engine_new(CONFIG_TOML);

    for v in vectors::all_vectors() {
        let expected = vectors::expected_output(v, &key);
        let session = cloak.session_new(engine);
        let mut out = cloak.push(session, v.input);
        out.extend(cloak.finish(session));

        assert_eq!(
            out,
            expected,
            "vector `{}` output mismatch through WASM\n  input:    {:?}\n  got:      {:?}\n  expected: {:?}",
            v.name,
            String::from_utf8_lossy(v.input),
            String::from_utf8_lossy(&out),
            String::from_utf8_lossy(&expected),
        );
    }

    cloak.engine_free(engine);
}

#[test]
fn redact_convenience_matches_session() {
    let key = test_key();
    let mut cloak = WasmCloak::new();
    let engine = cloak.engine_new(CONFIG_TOML);

    for v in vectors::all_vectors() {
        let expected = vectors::expected_output(v, &key);
        let out = cloak.redact(engine, v.input);

        assert_eq!(
            out,
            expected,
            "vector `{}` redact() mismatch\n  got:      {:?}\n  expected: {:?}",
            v.name,
            String::from_utf8_lossy(&out),
            String::from_utf8_lossy(&expected),
        );
    }

    cloak.engine_free(engine);
}

#[test]
fn empty_input_passthrough() {
    let mut cloak = WasmCloak::new();
    let engine = cloak.engine_new(CONFIG_TOML);
    let out = cloak.redact(engine, b"");
    assert!(out.is_empty(), "empty input should produce empty output");
    cloak.engine_free(engine);
}

#[test]
fn clean_input_passthrough() {
    let mut cloak = WasmCloak::new();
    let engine = cloak.engine_new(CONFIG_TOML);

    let input = b"hello world, no secrets here\n";
    let out = cloak.redact(engine, input);
    assert_eq!(&out, input, "clean input should pass through unchanged");
    cloak.engine_free(engine);
}

#[test]
fn invalid_config_returns_error() {
    let mut cloak = WasmCloak::new();
    let func = cloak
        .instance
        .get_typed_func::<(u32, u32), u32>(&mut cloak.store, "cloakwasm_engine_new")
        .expect("cloakwasm_engine_new export");

    let bad_toml = b"not valid { toml";
    let (ptr, alloc_size) = cloak.write_bytes(bad_toml);
    let handle = func
        .call(&mut cloak.store, (ptr, bad_toml.len() as u32))
        .expect("call");
    cloak.dealloc(ptr, alloc_size);

    assert_eq!(handle, 0, "invalid config should return handle 0");

    let err = cloak.last_error_string();
    assert!(
        err.contains("invalid config") || err.contains("TOML"),
        "error should mention config: {err}"
    );
}

#[test]
fn invalid_handle_returns_error() {
    let mut cloak = WasmCloak::new();

    let func = cloak
        .instance
        .get_typed_func::<u32, u32>(&mut cloak.store, "cloakwasm_session_new")
        .expect("cloakwasm_session_new export");
    let handle = func.call(&mut cloak.store, 999).expect("call");
    assert_eq!(handle, 0, "invalid engine handle should fail");

    let err = cloak.last_error_string();
    assert!(err.contains("invalid engine handle"), "error: {err}");
}
