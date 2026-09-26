# cloak-node — Embed cloak today (Node.js)

Node.js adapter for [cloak](https://github.com/silverwalls-labs/cloak) —
guarantee-grade secrets and PII redaction via WASM. Zero runtime
dependencies.

## Prerequisites

- **Node.js 24+** — uses `node:wasi` (preview1) for WASM instantiation
- **cloak WASM artifact** — built from the repo or downloaded from CI:
  ```sh
  RUSTFLAGS="-Ctarget-feature=+simd128" \
    cargo build -p cloak-wasm --target wasm32-wasip1 --release
  ```
  Set `CLOAK_WASM_PATH` to override the artifact location (defaults to
  `target/wasm32-wasip1/release/cloak_wasm.wasm` relative to the repo
  root).

## Quick start

```ts
import { createEngine } from './src/index.ts';

// Create an engine with a stable digest key for cross-run correlation.
const engine = await createEngine({
  redaction: { digestKey: 'env:CLOAK_DIGEST_KEY' },
});

// One-shot: string in, { output, stats } out.
const { output, stats } = engine.redact('token=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');
console.log(output.toString());
// → token=[CLOAK:github-token:xxxx]
console.log(stats.matches); // { 'github-token': 1 }

engine.dispose();
```

## Streaming

Use a `Transform` stream to redact a live stream (stdout/stderr hook):

```ts
import { createEngine, createCloakTransform } from './src/index.ts';

const engine = await createEngine({
  redaction: { digestKey: 'env:CLOAK_DIGEST_KEY' },
});

// Pipe: stdin → cloak → stdout
const redactor = createCloakTransform(engine);
process.stdin.pipe(redactor).pipe(process.stdout);
```

Or use the Web Streams API:

```ts
import { createEngine, createCloakTransformStream } from './src/index.ts';

const engine = await createEngine();
const transform = createCloakTransformStream(engine);
const redacted = someReadable.pipeThrough(transform);
```

## Configuration

Pass a JS object — it's serialized to TOML internally:

```ts
const engine = await createEngine({
  redaction: {
    digestKey: 'env:CLOAK_DIGEST_KEY',  // read from WASM env
  },
  rules: {
    'phone-intl': { enabled: false },   // disable a rule
  },
});
```

Or pass a raw TOML string:

```ts
const engine = await createEngine(
  '[redaction]\ndigest_key = "env:CLOAK_DIGEST_KEY"\n'
);
```

Or omit config entirely for the default (ephemeral key, all rules on):

```ts
const engine = await createEngine();
```

## Session lifecycle

For streaming (chunked) redaction, use sessions directly:

```ts
const session = engine.session();

const part1 = session.push('first chunk ');
const part2 = session.push('second chunk\n');
const { output: tail, stats } = session.finish();

const full = Buffer.concat([part1, part2, tail]);
console.log(`Processed ${stats.bytes_processed} bytes, ${Object.keys(stats.matches).length} rules matched`);
```

Abort a session without flushing (abandoned stream):

```ts
const session = engine.session();
session.push(someData);
session.abort(); // drops carry-over, releases handle
```

## Pino integration

### Simple destination (main thread)

Good for development and low-throughput deployments:

```ts
import pino from 'pino';
import { createEngine, createCloakTransform } from './src/index.ts';

const engine = await createEngine({
  redaction: { digestKey: 'env:CLOAK_DIGEST_KEY' },
});

const redactor = createCloakTransform(engine);
redactor.pipe(process.stdout);

const logger = pino({ level: 'info' }, redactor);

logger.info({ token: 'ghp_...' }, 'User authenticated');
// stdout: {"level":30,"msg":"User authenticated","token":"[CLOAK:github-token:xxxx]"}
```

### Production transport (worker thread)

Offloads redaction to a worker thread — zero event-loop impact:

```ts
import pino from 'pino';

const logger = pino({
  transport: {
    target: './examples/pino-transport.ts',
  },
});

logger.info({ secret: 'ghp_...' }, 'hello');
```

See [`examples/pino-transport.ts`](examples/pino-transport.ts) for the
transport implementation.

## API reference

### `createEngine(config?, env?): Promise<CloakEngine>`

Create a cloak engine. `config` is a `CloakConfig` object or a TOML
string. `env` overrides the environment variables visible to the WASM
module (defaults to `process.env`).

### `CloakEngine`

| Method | Description |
|---|---|
| `redact(input)` | One-shot redaction. Accepts `string \| Buffer \| Uint8Array`, returns `{ output: Buffer, stats: CloakStats }`. |
| `session()` | Create a streaming session. |
| `dispose()` | Free the engine. Fails if sessions are still live. |

### `CloakSession`

| Method | Description |
|---|---|
| `push(input)` | Push a chunk. Returns redacted bytes flushed (may be empty). |
| `finish()` | Flush and return `{ output: Buffer, stats: CloakStats }`. Consumes the session. |
| `abort()` | Drop without flushing. |

### `CloakStats`

```ts
interface CloakStats {
  bytes_processed: number;
  matches: Record<string, number>; // rule-id → count
}
```

### `createCloakTransform(engine): Transform`

Node.js `Transform` stream. Pipe input through it for streaming redaction.

### `createCloakTransformStream(engine): TransformStream<Uint8Array, Uint8Array>`

Web Streams API `TransformStream`. Use with `pipeThrough()`.

## Running tests

```sh
# Build the WASM artifact first
RUSTFLAGS="-Ctarget-feature=+simd128" \
  cargo build -p cloak-wasm --target wasm32-wasip1 --release

# Generate test vectors (only needed when rules change)
cargo run --example export-vectors -p cloak-core \
  > adapters/node/test/fixtures/vectors.json

# Run all tests
cd adapters/node
node --experimental-strip-types --no-warnings --test test/*.test.ts
```

## License

MIT — see [LICENSE](../../LICENSE).
