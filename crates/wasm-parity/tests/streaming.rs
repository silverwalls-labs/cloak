//! Chunk-boundary proptest: split vector inputs at random boundaries
//! and verify the WASM module produces identical output regardless of
//! chunking — same guarantee as cloak-core (docs/03).

use std::path::PathBuf;
use std::sync::OnceLock;

use proptest::prelude::*;
use wasmtime::{Config, Engine as WtEngine, Instance, Linker, Memory, Module, Store};
use wasmtime_wasi::WasiCtxBuilder;
use wasmtime_wasi::p1::WasiP1Ctx;

use cloak_core::vectors;

const KEY_MATERIAL: &str = "integration-test-key";
const KEY_VAR: &str = "CLOAK_DIGEST_KEY";

const CONFIG_TOML: &str = "\
[redaction]\n\
digest_key = \"env:CLOAK_DIGEST_KEY\"\n\
";

// ── Module loading (shared with parity.rs) ──────────────────────────

fn wasm_path() -> PathBuf {
    if let Ok(p) = std::env::var("CLOAK_WASM_PATH") {
        return PathBuf::from(p);
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.join("../../target/wasm32-wasip1/release/cloak_wasm.wasm")
}

fn wasm_engine() -> &'static WtEngine {
    static ENGINE: OnceLock<WtEngine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        let mut config = Config::new();
        config.wasm_simd(true);
        WtEngine::new(&config).expect("wasmtime engine")
    })
}

fn wasm_module() -> &'static Module {
    static MODULE: OnceLock<Module> = OnceLock::new();
    MODULE.get_or_init(|| {
        let path = wasm_path();
        assert!(path.exists(), "WASM artifact not found at {path:?}");
        Module::from_file(wasm_engine(), &path).expect("compile .wasm module")
    })
}

// ── Minimal WASM helper (duplicated for test isolation) ─────────────

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

    fn memory(&mut self) -> Memory {
        self.instance.get_memory(&mut self.store, "memory").unwrap()
    }

    fn alloc(&mut self, size: u32) -> u32 {
        self.instance
            .get_typed_func::<u32, u32>(&mut self.store, "cloakwasm_alloc")
            .unwrap()
            .call(&mut self.store, size)
            .unwrap()
    }

    fn dealloc(&mut self, ptr: u32, size: u32) {
        self.instance
            .get_typed_func::<(u32, u32), ()>(&mut self.store, "cloakwasm_dealloc")
            .unwrap()
            .call(&mut self.store, (ptr, size))
            .unwrap();
    }

    fn write_bytes(&mut self, data: &[u8]) -> (u32, u32) {
        let alloc_size = data.len().max(1) as u32;
        let ptr = self.alloc(alloc_size);
        if !data.is_empty() {
            let mem = self.memory();
            mem.data_mut(&mut self.store)[ptr as usize..ptr as usize + data.len()]
                .copy_from_slice(data);
        }
        (ptr, alloc_size)
    }

    fn read_buf_result(&mut self, result_ptr: u32) -> Vec<u8> {
        let mem = self.memory();
        let data = mem.data(&self.store);
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

    fn buf_free(&mut self, ptr: u32) {
        self.instance
            .get_typed_func::<u32, ()>(&mut self.store, "cloakwasm_buf_free")
            .unwrap()
            .call(&mut self.store, ptr)
            .unwrap();
    }

    fn engine_new(&mut self, config: &str) -> u32 {
        let (ptr, alloc_size) = self.write_bytes(config.as_bytes());
        let handle = self
            .instance
            .get_typed_func::<(u32, u32), u32>(&mut self.store, "cloakwasm_engine_new")
            .unwrap()
            .call(&mut self.store, (ptr, config.len() as u32))
            .unwrap();
        self.dealloc(ptr, alloc_size);
        assert!(handle > 0);
        handle
    }

    fn session_new(&mut self, engine: u32) -> u32 {
        let handle = self
            .instance
            .get_typed_func::<u32, u32>(&mut self.store, "cloakwasm_session_new")
            .unwrap()
            .call(&mut self.store, engine)
            .unwrap();
        assert!(handle > 0);
        handle
    }

    fn push(&mut self, session: u32, input: &[u8]) -> Vec<u8> {
        let (ptr, alloc_size) = self.write_bytes(input);
        let result = self
            .instance
            .get_typed_func::<(u32, u32, u32), u32>(&mut self.store, "cloakwasm_push")
            .unwrap()
            .call(&mut self.store, (session, ptr, input.len() as u32))
            .unwrap();
        self.dealloc(ptr, alloc_size);
        assert!(result != 0);
        let data = self.read_buf_result(result);
        self.buf_free(result);
        data
    }

    fn finish(&mut self, session: u32) -> Vec<u8> {
        let result = self
            .instance
            .get_typed_func::<u32, u32>(&mut self.store, "cloakwasm_finish")
            .unwrap()
            .call(&mut self.store, session)
            .unwrap();
        assert!(result != 0);
        let data = self.read_buf_result(result);
        self.buf_free(result);
        data
    }

    fn redact(&mut self, engine: u32, input: &[u8]) -> Vec<u8> {
        let (ptr, alloc_size) = self.write_bytes(input);
        let result = self
            .instance
            .get_typed_func::<(u32, u32, u32), u32>(&mut self.store, "cloakwasm_redact")
            .unwrap()
            .call(&mut self.store, (engine, ptr, input.len() as u32))
            .unwrap();
        self.dealloc(ptr, alloc_size);
        assert!(result != 0);
        let data = self.read_buf_result(result);
        self.buf_free(result);
        data
    }

    fn engine_free(&mut self, handle: u32) {
        self.instance
            .get_typed_func::<u32, ()>(&mut self.store, "cloakwasm_engine_free")
            .unwrap()
            .call(&mut self.store, handle)
            .unwrap();
    }
}

// ── Proptest: chunk-boundary invariant ──────────────────────────────

/// Subset of vectors for proptest (keeping runtime bounded).
fn proptest_vectors() -> Vec<&'static vectors::Vector> {
    let all = vectors::all_vectors();
    // Take every Nth vector to keep the test count manageable.
    all.into_iter()
        .enumerate()
        .filter(|(i, _)| i % 3 == 0)
        .map(|(_, v)| v)
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn chunked_push_matches_single_push(
        vector_idx in 0..proptest_vectors().len(),
        split_seed in proptest::collection::vec(0..100usize, 1..=5),
    ) {
        let vecs = proptest_vectors();
        let v = vecs[vector_idx];

        // Single-push baseline via redact().
        let mut cloak = WasmCloak::new();
        let engine = cloak.engine_new(CONFIG_TOML);
        let baseline = cloak.redact(engine, v.input);

        // Multi-push with random split points.
        let len = v.input.len();
        if len == 0 {
            cloak.engine_free(engine);
            return Ok(());
        }

        let mut points: Vec<usize> = split_seed
            .iter()
            .map(|s| s % len)
            .collect();
        points.sort_unstable();
        points.dedup();

        let session = cloak.session_new(engine);
        let mut chunked_out = Vec::new();
        let mut pos = 0;
        for &split in &points {
            if split > pos {
                chunked_out.extend(cloak.push(session, &v.input[pos..split]));
                pos = split;
            }
        }
        if pos < len {
            chunked_out.extend(cloak.push(session, &v.input[pos..]));
        }
        chunked_out.extend(cloak.finish(session));

        prop_assert_eq!(
            chunked_out,
            baseline,
            "chunk-boundary divergence for vector `{}`",
            v.name
        );

        cloak.engine_free(engine);
    }
}
