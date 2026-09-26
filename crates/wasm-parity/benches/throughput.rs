//! Native-vs-WASM throughput benchmark.
//!
//! Measures push() throughput for both the native `cloak-core` engine and
//! the WASM module running under wasmtime, using the same corpus.
//! Results form the first entry in `docs/benchmarks/wasm-vs-native.md`.

use std::path::PathBuf;
use std::sync::OnceLock;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use wasmtime::*;
use wasmtime_wasi::WasiCtxBuilder;
use wasmtime_wasi::p1::WasiP1Ctx;

const KEY_MATERIAL: &str = "bench-key";
const KEY_VAR: &str = "CLOAK_DIGEST_KEY";

const CONFIG_TOML: &str = "\
[redaction]\n\
digest_key = \"env:CLOAK_DIGEST_KEY\"\n\
";

// ── Corpus ──────────────────────────────────────────────────────────

/// Mixed corpus: clean text with embedded secrets (realistic workload).
fn corpus() -> Vec<u8> {
    let mut buf = Vec::new();
    // ~4 KiB of clean text with a few secrets.
    for _ in 0..20 {
        buf.extend_from_slice(
            b"INFO 2026-09-26T12:00:00Z request completed status=200 \
              user=alice@example.com latency=12ms\n",
        );
    }
    buf.extend_from_slice(b"DEBUG auth token=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 granted\n");
    for _ in 0..20 {
        buf.extend_from_slice(b"INFO 2026-09-26T12:00:01Z db query rows=42 duration=3ms\n");
    }
    buf.extend_from_slice(b"WARN key=AKIAIOSFODNN7EXAMPLE exposed\n");
    for _ in 0..20 {
        buf.extend_from_slice(b"INFO 2026-09-26T12:00:02Z response sent bytes=1024\n");
    }
    buf
}

// ── Native benchmark ────────────────────────────────────────────────

fn bench_native(c: &mut Criterion) {
    // Set up engine with deterministic key.
    // SAFETY: bench-only, single var, set once.
    unsafe { std::env::set_var(KEY_VAR, KEY_MATERIAL) };

    let config = cloak_core::Config {
        redaction: cloak_core::RedactionConfig {
            digest_key: format!("env:{KEY_VAR}"),
        },
        ..Default::default()
    };
    let engine = cloak_core::Engine::new(&config).expect("engine");
    let corpus = corpus();

    let mut group = c.benchmark_group("native");
    group.throughput(Throughput::Bytes(corpus.len() as u64));

    group.bench_function("push", |b| {
        b.iter(|| {
            let mut session = engine.session();
            let mut out = Vec::with_capacity(corpus.len());
            session.push(&corpus, &mut out).unwrap();
            session.finish(&mut out).unwrap();
            out
        });
    });

    group.finish();
}

// ── WASM benchmark ──────────────────────────────────────────────────

fn wasm_path() -> PathBuf {
    if let Ok(p) = std::env::var("CLOAK_WASM_PATH") {
        return PathBuf::from(p);
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.join("../../target/wasm32-wasip1/release/cloak_wasm.wasm")
}

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
        Module::from_file(wasm_engine(), &path).expect("compile .wasm")
    })
}

struct WasmBench {
    store: Store<WasiP1Ctx>,
    instance: Instance,
    cloak_engine: u32,
}

impl WasmBench {
    fn new() -> Self {
        let engine = wasm_engine();
        let module = wasm_module();

        let wasi = WasiCtxBuilder::new().env(KEY_VAR, KEY_MATERIAL).build_p1();

        let mut store = Store::new(engine, wasi);
        let mut linker = Linker::new(engine);
        wasmtime_wasi::p1::add_to_linker_sync(&mut linker, |ctx| ctx).expect("link WASI");
        let instance = linker.instantiate(&mut store, module).expect("instantiate");

        // Create engine once.
        let config_bytes = CONFIG_TOML.as_bytes();
        let alloc = instance
            .get_typed_func::<u32, u32>(&mut store, "cloakwasm_alloc")
            .unwrap();
        let ptr = alloc.call(&mut store, config_bytes.len() as u32).unwrap();

        let mem = instance.get_memory(&mut store, "memory").unwrap();
        mem.data_mut(&mut store)[ptr as usize..ptr as usize + config_bytes.len()]
            .copy_from_slice(config_bytes);

        let engine_new = instance
            .get_typed_func::<(u32, u32), u32>(&mut store, "cloakwasm_engine_new")
            .unwrap();
        let cloak_engine = engine_new
            .call(&mut store, (ptr, config_bytes.len() as u32))
            .unwrap();

        let dealloc = instance
            .get_typed_func::<(u32, u32), ()>(&mut store, "cloakwasm_dealloc")
            .unwrap();
        dealloc
            .call(&mut store, (ptr, config_bytes.len() as u32))
            .unwrap();

        assert!(cloak_engine > 0);

        Self {
            store,
            instance,
            cloak_engine,
        }
    }

    fn redact(&mut self, input: &[u8]) -> Vec<u8> {
        let alloc = self
            .instance
            .get_typed_func::<u32, u32>(&mut self.store, "cloakwasm_alloc")
            .unwrap();
        let ptr = alloc.call(&mut self.store, input.len() as u32).unwrap();

        let mem = self.instance.get_memory(&mut self.store, "memory").unwrap();
        mem.data_mut(&mut self.store)[ptr as usize..ptr as usize + input.len()]
            .copy_from_slice(input);

        let redact = self
            .instance
            .get_typed_func::<(u32, u32, u32), u32>(&mut self.store, "cloakwasm_redact")
            .unwrap();
        let result_ptr = redact
            .call(
                &mut self.store,
                (self.cloak_engine, ptr, input.len() as u32),
            )
            .unwrap();

        let dealloc = self
            .instance
            .get_typed_func::<(u32, u32), ()>(&mut self.store, "cloakwasm_dealloc")
            .unwrap();
        dealloc
            .call(&mut self.store, (ptr, input.len() as u32))
            .unwrap();

        // Read BufResult.
        let mem = self.instance.get_memory(&mut self.store, "memory").unwrap();
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
        let out = data[data_ptr as usize..data_ptr as usize + data_len as usize].to_vec();

        let buf_free = self
            .instance
            .get_typed_func::<u32, ()>(&mut self.store, "cloakwasm_buf_free")
            .unwrap();
        buf_free.call(&mut self.store, result_ptr).unwrap();

        out
    }
}

fn bench_wasm(c: &mut Criterion) {
    let path = wasm_path();
    if !path.exists() {
        eprintln!(
            "WASM artifact not found at {path:?} — skipping WASM benchmark. \
             Build with: RUSTFLAGS=\"-Ctarget-feature=+simd128\" cargo build \
             -p cloak-wasm --target wasm32-wasip1 --release"
        );
        return;
    }

    let mut bench = WasmBench::new();
    let corpus = corpus();

    let mut group = c.benchmark_group("wasm");
    group.throughput(Throughput::Bytes(corpus.len() as u64));

    group.bench_function("redact", |b| {
        b.iter(|| bench.redact(&corpus));
    });

    group.finish();
}

criterion_group!(benches, bench_native, bench_wasm);
criterion_main!(benches);
