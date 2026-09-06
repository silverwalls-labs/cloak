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

## Defense in depth

cloak is one engine deployed at three points of the pipeline:

```
┌─ app ──────────────┐    ┌─ node ─────────────┐    ┌─ ingestion ────────┐
│ code → cloak → out │ →  │ k8s log processor  │ →  │ Grafana Alloy /    │
│ (catch at source)  │    │ (catch the missed) │    │ stack (last line)  │
└────────────────────┘    └────────────────────┘    └────────────────────┘
```

## The contract

**Guaranteed detection, ruleset-relative**: if a pattern in the active ruleset
appears in the input — split across stream chunks, buried in invalid UTF-8 — it *is*
redacted. The guarantee is "the ruleset is honored, always", never "no secret ever
leaks" — read [what the guarantee is NOT](docs/03-guarantee-and-testing.md#what-the-guarantee-is-not)
before relying on it.

Precision stance: recall-first with **tuned, anchored rules** — no entropy
heuristics eating your trace IDs.

## Status

**Design phase.** No code yet — the full design is agreed and documented:

| Doc | Contents |
|---|---|
| [00-scope](docs/00-scope.md) | Problem, users, v0.1 scope, non-goals, acceptance criteria |
| [01-architecture](docs/01-architecture.md) | Workspace, byte-stream engine + carry-over, API, config, CLI |
| [02-rules](docs/02-rules.md) | v0.1 detector catalog, precision notes, redaction format |
| [03-guarantee-and-testing](docs/03-guarantee-and-testing.md) | The contract, threat model, property tests, fuzzing |
| [04-performance](docs/04-performance.md) | ≥ 500 MB/s floor, benchmark methodology, SIMD receipts protocol |
| [05-roadmap](docs/05-roadmap.md) | 8-session v0.1 plan, follow-ups ledger |

## License

[MIT](LICENSE)
