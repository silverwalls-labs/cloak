# cloak-ffi — C ABI over cloak-core (E7)

C ABI for [cloak](https://github.com/silverwalls-labs/cloak) —
guarantee-grade secrets and PII redaction behind a `staticlib` +
`cdylib` pair and a committed [cbindgen](https://github.com/mozilla/cbindgen)
header ([`include/cloak.h`](include/cloak.h)). This is the boundary
every non-WASM native binding builds on: `cloak-go` links the
staticlib; ctypes/cffi/dlopen consumers load the cdylib.

All correctness lives in `cloak-core` — this layer is pointer and
ownership plumbing only, and the full contract (ownership rules,
thread-safety, error model) is documented function-by-function in the
header itself.

## Build

```sh
cargo build -p cloak-ffi --release
# → target/release/libcloak_ffi.a  (staticlib)
# → target/release/libcloak_ffi.{so,dylib}  (cdylib)
```

CI uploads `cloak-ffi-<target>` artifacts (header + both libraries)
for x86_64/aarch64 Linux and aarch64 macOS; releases are cut manually
from those artifacts.

## The ABI in one screen

```c
uint32_t cloak_abi_version(void);                     /* == CLOAK_ABI_VERSION (1) */

CloakEngine *cloak_engine_new(config_toml, len, &err); /* NULL on error */
int32_t cloak_engine_free(engine, &err);  /* refuses while sessions live */

int32_t cloak_redact(engine, in, in_len, &out, &stats_json, &err);

CloakSession *cloak_session_new(engine, &err);
int32_t cloak_session_push(session, in, in_len, &out, &err);
int32_t cloak_session_finish(session, &out, &stats_json, &err);
void cloak_session_free(session);         /* abort path + post-finish release */

void cloak_buf_free(buf);                 /* every out-param buffer, exactly once */
```

Status codes: `CLOAK_OK` / `CLOAK_ERR` / `CLOAK_ERR_PANIC`. Errors are
**per-call out-parameters** — no global or thread-local error slot (TLS
breaks under cgo thread migration, and per-call errors are what let
bindings share one engine across threads without a serializing mutex).
Output is always a cloak-allocated `CloakBuf` freed with
`cloak_buf_free` — no callbacks. Stats cross as UTF-8 JSON
(`bytes_processed`, `matches`, `near_misses` omitted when empty — the
exact shape cloak-wasm ships).

Thread contract: an **engine** is freely shareable across threads
(`cloak_engine_free` excepted — same rule as `free()`); a **session**
is single-thread-at-a-time but movable.

## Header regeneration

The header is generated manually and committed; CI diffs it (and the
vendored twin at `crates/cloak-go/include/cloak.h`) against a fresh
generation:

```sh
cargo install cbindgen --version 0.29.4 --locked
cbindgen --config crates/cloak-ffi/cbindgen.toml --crate cloak-ffi \
    --output crates/cloak-ffi/include/cloak.h
cp crates/cloak-ffi/include/cloak.h crates/cloak-go/include/cloak.h
```

## Testing (the sanitizer gates live here)

`unsafe` enters the workspace in this crate, so the boundary tests are
blocking CI gates under Miri and ASAN/LSAN
(docs/03-guarantee-and-testing.md §deferred → active since E7):

```sh
cargo test -p cloak-ffi                        # boundary tests, stable
cargo +nightly-2026-09-05 miri test -p cloak-ffi
RUSTFLAGS="-Zsanitizer=address" \
  cargo +nightly-2026-09-05 test -p cloak-ffi --target aarch64-unknown-linux-gnu
```

Parity is proven by a minimal C harness
([`charness/parity.c`](charness/parity.c)) that runs the full
247-vector corpus through the staticlib — one-shot and streamed —
byte-for-byte:

```sh
cargo build -p cloak-ffi --release
cargo run --example export-vectors -p cloak-core > /tmp/vectors.json
cc -std=c99 -Wall -Wextra -Werror -Icrates/cloak-ffi/include \
   crates/cloak-ffi/charness/parity.c \
   target/release/libcloak_ffi.a -lm -ldl -lpthread -o /tmp/cloak-charness
CLOAK_DIGEST_KEY=integration-test-key /tmp/cloak-charness /tmp/vectors.json
# → parity ok: 247 vectors            (drop the -l flags on macOS)
```

## Versioning

`CLOAK_ABI_VERSION` (currently 1) is bumped on any breaking change to
signatures, struct layout, or documented semantics; compare the
header's compile-time constant against the runtime
`cloak_abi_version()` to catch a stale library. The crate version is
locked to cloak-core (docs/06-embedding.md §Versioning & CI).
