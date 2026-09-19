# cloak

A fast, guarantee-grade **secrets & structured-PII redactor** for observability
pipelines. Rust, streaming, SIMD-accelerated scanning.

```
app | cloak | collector
```

Secrets leak into logs — API keys, tokens, private keys, connection strings, plus
structured PII (emails, IPs, card numbers). Once they reach your Grafana/Loki stack
they are effectively published internally. cloak rewrites the stream before that
happens:

```
2026-09-06 ERROR retry failed key=[CLOAK:aws-access-key:9f3a] host=10.0.3.7
                                  └─ typed tag + deterministic digest: correlatable, never exposed
```

## Quickstart

From source — there is no crates.io package or prebuilt binary in v0.1
(Rust ≥ 1.98.1):

```sh
cargo install --locked --git https://github.com/silverwalls-labs/cloak cloak-cli
```

Installs the `cloak` binary. Pipe anything through it:

```sh
app 2>&1 | cloak                          # stdin → stdout, full default ruleset
cloak app.log > app.red.log               # file args feed the same engine
cloak --config cloak.toml < app.log       # per-rule enable/disable (TOML)
cloak --stats-format json < app.log       # per-rule match counts on stderr
```

Digests are keyed: set `CLOAK_DIGEST_KEY` to make the same secret produce the
same tag across runs and hosts (unset ⇒ ephemeral per-process key, digests not
correlatable). More in [examples/](examples/).

## Defense in depth

cloak is one engine deployed at three points of the pipeline:

```
┌─ app ──────────────┐    ┌─ node ─────────────┐    ┌─ ingestion ────────┐
│ code → cloak → out │ →  │ k8s log processor  │ →  │ Grafana Alloy /    │
│ (catch at source)  │    │ (catch the missed) │    │ stack (last line)  │
└────────────────────┘    └────────────────────┘    └────────────────────┘
  embeds natively in         pipe / sidecar            FFI / WASM
  Rust · Go · Node · Python
```

One engine (`cloak-core`), many frontends: the v0.1 CLI, then the v0.2 embedding
milestone ([design](docs/06-embedding.md)) — **WASM first** (one artifact, runs in
Go/wazero, Python/wasmtime, Node/WASI), then dedicated native bindings for
performance: Python (pyo3), Node.js (napi-rs), Go (C ABI/cgo) on demand.

Kubernetes deployment patterns (in-container pipe, sidecar over a shared
volume): [examples/k8s-log-processor.yaml](examples/k8s-log-processor.yaml).

## The contract

**Guaranteed detection, ruleset-relative**: if a pattern in the active ruleset
appears in the input — split across stream chunks, buried in invalid UTF-8 — it *is*
redacted. The guarantee is "the ruleset is honored, always", never "no secret ever
leaks" — read [what the guarantee is NOT](docs/03-guarantee-and-testing.md#what-the-guarantee-is-not)
before relying on it. One routine case to know: JSON structured logging escapes
`\n`, so a **multi-line PEM key inside a JSON string field is missed in v0.1**
(single-line tokens are unaffected — their bytes survive JSON escaping); an
opt-in decode layer is tracked as [ledger F11](docs/05-roadmap.md#follow-ups-ledger).

Precision stance: recall-first with **tuned, anchored rules** — no entropy
heuristics eating your trace IDs.

## Ruleset

16 rules, all enabled by default ([catalog + precision notes](docs/02-rules.md)):

| Group | Rules |
|---|---|
| Secrets (10) | `github-token` · `gitlab-token` · `npm-token` · `aws-access-key` · `aws-secret-key` · `gcp-api-key` · `pypi-token` · `azure-style-token` · `jwt` · `connection-string`¹ |
| PII (5) | `email` · `ipv4` · `ipv6` · `credit-card` · `phone-intl` |
| Stateful (1) | `pem-private-key` (multi-line, streaming) |

¹ redacts only the password span — scheme/user/host stay readable.

Per-rule toggles via `--config`:

```toml
# cloak.toml (v0.1 surface)
[redaction]
digest_key = "env:CLOAK_DIGEST_KEY"   # keyed digest; env-indirection, never inline

[rules.phone-intl]
enabled = false                       # every rule: on by default, opt-out
```

Exit codes: `0` clean (including downstream broken pipe), `1` operational error
(bad config path, malformed TOML, unknown rule, missing file), `2` usage error.
Stats and warnings go to **stderr** — stdout is exclusively the redacted payload.
With `--stats-format json`, parse the **last** stderr line (warnings may precede it).

## Performance

SIMD-accelerated scanning via `aho-corasick` (Teddy/AVX2/NEON). Every number
below traces to a committed
[criterion benchmark](docs/benchmarks/receipts-v0.1.md) — no mood-based
"blazingly fast."

| Metric | Number | Source |
|---|---|---|
| Clean-path throughput (single core) | 267–348 MiB/s (text/JSON, aarch64) | [receipts](docs/benchmarks/receipts-v0.1.md); nightly CI floor gate **≥ 250 MB/s** (green on aarch64; x86 shared-runner calibration pending) |
| Prefilter speedup vs naive scanner | ~58–75× | [receipts](docs/benchmarks/receipts-v0.1.md) |
| Memory | O(W) bounded (design + proptest) | Nightly soak on Linux CI (10 GB, RSS < 100 MB) |

## Known limitations (v0.1)

- **Escaped content is not decoded** — multi-line PEM inside JSON string fields
  is missed ([ledger F11](docs/05-roadmap.md#follow-ups-ledger), see the contract above).
- Two tracked engine bugs in rare configurations, documented in
  [03 §fuzzing](docs/03-guarantee-and-testing.md#4-fuzzing-cargo-fuzz):
  carry-over boundary × context-keyed rules in dense >2 KiB concatenations
  ([#27](https://github.com/silverwalls-labs/cloak/issues/27)) and an idempotence
  edge when adjacent matches are re-scanned
  ([#34](https://github.com/silverwalls-labs/cloak/issues/34)).

## Design

| Doc | Contents |
|---|---|
| [00-scope](docs/00-scope.md) | Problem, users, v0.1 scope, non-goals, acceptance criteria |
| [01-architecture](docs/01-architecture.md) | Workspace, byte-stream engine + carry-over, API, config, CLI |
| [02-rules](docs/02-rules.md) | v0.1 detector catalog, precision notes, redaction format |
| [03-guarantee-and-testing](docs/03-guarantee-and-testing.md) | The contract, threat model, property tests, fuzzing |
| [04-performance](docs/04-performance.md) | ≥ 250 MB/s floor, benchmark methodology, SIMD receipts protocol |
| [05-roadmap](docs/05-roadmap.md) | 8-session v0.1 plan, follow-ups ledger |
| [06-embedding](docs/06-embedding.md) | v0.2 bindings: WASM-first rollout, then pyo3 / napi-rs / C ABI — parity contract, 8-session split (one artifact each) |

Usage examples live in [examples/](examples/); release history in
[CHANGELOG.md](CHANGELOG.md).

## Security

cloak is a security tool — suspected vulnerabilities (guarantee bypasses,
plaintext leaks) go through [private disclosure](SECURITY.md), not public issues.

## License

[MIT](LICENSE)
