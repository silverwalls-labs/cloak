# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
(0.x: minor bumps may break; **rule ids are stable from v0.1** — renaming one is
a breaking change).

## [Unreleased]

## [0.1.0] - 2026-09-19

First release: the `cloak` CLI and the `cloak-core` engine.

### Added

- **Streaming engine** (`cloak-core`): byte-stream redaction with bounded
  carry-over — chunking is invisible, output is byte-identical to a
  whole-buffer scan for any split, on valid UTF-8 or not
  ([the contract](docs/03-guarantee-and-testing.md#the-contract-precisely)).
- **16-rule catalog**: 10 secrets (`github-token`, `gitlab-token`, `npm-token`,
  `aws-access-key`, `aws-secret-key`, `gcp-api-key`, `pypi-token`,
  `azure-style-token`, `jwt`, `connection-string` — password span only),
  5 PII (`email`, `ipv4`, `ipv6`, `credit-card`, `phone-intl`), and streaming
  multi-line `pem-private-key`. CRC32 checksum validation for
  `github-token`(classic)/`npm-token`; Luhn for `credit-card`.
- **Correlation tags**: `[CLOAK:<rule-id>:<digest4>]` with keyed-BLAKE3 16-bit
  digests (`CLOAK_DIGEST_KEY`, env-indirection only) — same secret + same key
  ⇒ same tag, plaintext never escapes.
- **TOML config** (`--config`): per-rule enable/disable, digest-key source;
  unknown fields/rules are hard errors.
- **`cloak` CLI**: stdin/file args → stdout, `--stats-format text|json`
  (stderr), SIGPIPE-safe (broken pipe downstream exits 0).
- **Test suite proving the guarantee**: five tiers (unit / integration / e2e /
  fuzz / smoke) with chunk-boundary property tests, differential testing
  against a scalar reference oracle, digest-stability goldens, 3 fuzz targets,
  10 GB soak with RSS assertion, and `cargo-mutants` (nightly).
- **Staged CI**: smoke → full (linux x86-64 + aarch64 + macOS aarch64,
  `cargo-deny`, coverage gates) → nightly (extended fuzz, mutants, soak, bench
  gates).
- **Benchmarks with receipts**: criterion suite, nightly clean-path floor gate
  **≥ 250 MB/s single-core** (green on aarch64 CI; x86 shared-runner floor
  calibration is an open item), prefilter ~58–75× vs naive scalar scan
  ([receipts](docs/benchmarks/receipts-v0.1.md)).

### Known limitations

- Escaped content is not decoded: multi-line PEM inside JSON string fields is
  missed (opt-in decode layer tracked as ledger F11; single-line tokens are
  unaffected).
- Two tracked engine bugs on narrow inputs:
  [#27](https://github.com/silverwalls-labs/cloak/issues/27) (carry-over
  boundary × context-keyed rules in dense >2 KiB concatenations) and
  [#34](https://github.com/silverwalls-labs/cloak/issues/34) (idempotence edge
  when adjacent matches are re-scanned). Strict fuzz equivalence checks stay
  opt-in (`CLOAK_FUZZ_STRICT=1`) until both close.

[Unreleased]: https://github.com/silverwalls-labs/cloak/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/silverwalls-labs/cloak/releases/tag/v0.1.0
