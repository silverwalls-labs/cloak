# Examples

cloak is a pure pipe: stdin → stdout, redacted bytes out, everything else
(stats, warnings) on stderr. These examples assume the `cloak` binary is on
your `PATH` (see the [README quickstart](../README.md#quickstart)).

## Pipe basics

```sh
app 2>&1 | cloak                          # redact a live stream
cloak app.log > app.red.log               # file args feed the same engine
cloak a.log b.log > all.red.log           # multiple files, one session
cloak --config examples/cloak.toml < in   # per-rule enable/disable
```

Exit codes: `0` clean — including a broken pipe downstream, so
`app | cloak | head` never kills your app — `1` operational error (bad config,
missing file), `2` usage error.

## Stats

```sh
cloak --stats-format json < app.log > app.red.log
# stderr: {"bytes_processed":123,"matches":{"github-token":2,"npm-token":1}}
```

Stats go to stderr after the stream ends; stdout stays exclusively payload.
With `json`, parse the **last** stderr line — warnings (e.g. the ephemeral-key
notice) may precede it.

## Correlation: same secret, same tag

Digests are keyed BLAKE3, truncated to 16 bits. With a stable key, the same
secret yields the same `[CLOAK:rule:digest]` tag across runs and hosts — so you
can group by tag in Grafana without ever storing the plaintext:

```sh
export CLOAK_DIGEST_KEY="$(openssl rand -hex 32)"
echo 'key=AKIAIOSFODNN7EXAMPLE' | cloak    # key=[CLOAK:aws-access-key:xxxx]
echo 'key=AKIAIOSFODNN7EXAMPLE' | cloak    # same xxxx — correlatable
```

Unset the key and each process picks an ephemeral one: still redacted, no
cross-run correlation. Digests are hints (16 bits), not commitments.

## Kubernetes

[`k8s-log-processor.yaml`](k8s-log-processor.yaml) shows the two honest
deployment patterns for a stdin/stdout tool — an in-container pipe (redact
before the kubelet captures the stream) and a sidecar over a shared volume
(`tail -F … | cloak`; cloak never tails files itself).

No container image is published in v0.1 (tracked as ledger F9 for v0.2) —
build your own:

```dockerfile
FROM rust:1.98 AS build
RUN cargo install --locked --git https://github.com/silverwalls-labs/cloak cloak-cli

# slim, not distroless: the sidecar pattern needs `sh` and `tail` in the image
FROM debian:stable-slim
COPY --from=build /usr/local/cargo/bin/cloak /usr/local/bin/cloak
ENTRYPOINT ["/usr/local/bin/cloak"]
```

