# cloak-node (native) — native Node.js binding (E6)

Native [napi-rs](https://napi.rs) binding over `cloak-core`: the same
conceptual API as every cloak binding (`docs/06-embedding.md`), without
the WASM-runtime overhead of the [`cloak-node`
adapter](../../adapters/node/) — no linear-memory copies, no WASI
instantiation, direct `Buffer` I/O. Receipts:
[`docs/benchmarks/receipts-native-e6-node.md`](../../docs/benchmarks/receipts-native-e6-node.md).

Ships as **prebuilt `.node` binaries** (one per platform: linux
x86-64/aarch64, macos aarch64) built by the `cloak-node-prebuilds` CI
job. Never published to npm — install from CI artifacts, or build from
the repo:

```sh
cd crates/cloak-node
npm ci                         # installs @napi-rs/cli + dev deps
npm run build-native           # builds the .node binary (release)
npm run build                  # compiles js/ → dist/ (for npm pack)
```

### Installing the prebuilts

The `cloak-node-prebuilds` CI job uploads two artifacts per target:

- `cloak-node-prebuild-<target>` — the raw `.node` binary.
- `cloak-node-package-<target>` — a complete `npm pack` tarball
  (`cloak-node-native-0.1.0.tgz`) with that target's `.node`, the
  generated loader, and the compiled `dist/` wrapper already inside.

For a ready-to-run package, download the `cloak-node-package-*`
artifact matching your platform and install from the tarball:

```sh
npm install --no-save cloak-node-native-0.1.0.tgz
```

The tarball packed in the `cloak-node-parity` job is a smoke artifact
only — it carries whatever `.node` the (linux arm64) parity runner
built, so it is not platform-portable. Use the per-target package
artifacts instead. The `npm/<platform>/package.json` manifests are
scaffolding for a possible future npm-publish path (`optionalDependencies`
wiring); they are not part of the artifact distribution today.

The Linux prebuilts are linked against the napi cross toolchain's
glibc 2.17 sysroot (CI gates them at `GLIBC <= 2.28` — Node 22's own
Linux floor), so they load on every glibc system Node 22 supports.

**Runtime** requirement: Node >= 22 — the installed package is plain
ESM plus an addon requesting Node-API 9, which every Node 22.x
provides.

**Development** (this crate: `npm ci`, `build-native`, `npm test`)
needs a newer Node than the runtime floor: the type-stripping test
runner needs Node >= 22.6.0 (`--experimental-strip-types`), and the
locked `@napi-rs/cli` declares `^20.17.0 || ^22.13.0 || >= 23.5.0`.
CI runs Node 24 — use Node 24 for development.

## Usage

Bytes in, bytes out — `string` input is encoded as UTF-8 at the
boundary, output is always `Buffer` (binding rule #1,
`docs/06-embedding.md`):

```ts
import { createEngine } from "cloak-node-native";

const engine = createEngine({
  redaction: { digestKey: "env:CLOAK_DIGEST_KEY" },
});

// One-shot
const { output, stats } = engine.redact("token=ghp_AAAA...AAAA\n");

// Streaming (per-request/stream sessions are cheap)
const session = engine.session();
const flushed = session.push(chunk); // may withhold carry-over bytes
const { output: tail, stats: s } = session.finish(); // flush + per-rule counts

engine.dispose(); // refuses while sessions are live
```

### Transform stream (stdout/stderr hook)

```ts
import { createEngine, createCloakTransform } from "cloak-node-native";

const engine = createEngine();
const redactor = createCloakTransform(engine);
process.stdin.pipe(redactor).pipe(process.stdout);
```

### Web TransformStream

```ts
import { createEngine, createCloakTransformStream } from "cloak-node-native";

const engine = createEngine();
const redactor = createCloakTransformStream(engine);
const redacted = someReadable.pipeThrough(redactor);
```

## Errors

Expected failures (invalid config, engine build failure, lifecycle
misuse) throw `CloakError`. A Rust panic is a bug: napi-rs catches it
and converts it to a JS exception (relies on `panic = "unwind"` in the
workspace release profile).

`dispose()` refuses with `CloakError` while sessions are live; the
engine stays usable after a refusal. It is idempotent once released.

One stderr notice exists by design: when the config references a digest
key env var (the default references `CLOAK_DIGEST_KEY`) and that var is
not set, core prints
`cloak: <VAR> not set; using ephemeral digest key (correlation limited to this process)`
once at engine construction — a redaction-guarantee warning, not a Node
warning. Set the env var (or pass `env` to `createEngine`) to silence
it.

## Development

```sh
npm ci                                 # install dev deps
npm run build-native:debug             # debug build of native module + loader
npm test                               # parity vectors, streaming, config, transforms
CLOAK_DIGEST_KEY=bench-key \
  node --experimental-strip-types --no-warnings bench/throughput.ts
```

Always build through the `build-native` scripts — the bare
`npx napi build` command without `--platform --esm` does not generate
the loader (`index.js`/`index.d.ts`) that `js/` imports.

The parity fixture `test/fixtures/vectors.json` is generated from core
(`cargo run --example export-vectors -p cloak-core`) and checked for
staleness in CI, same as every adapter. The Rust layer (`src/lib.rs`)
has no Rust-side tests by design — all behavior is covered by the
node:test suite against the built module.
