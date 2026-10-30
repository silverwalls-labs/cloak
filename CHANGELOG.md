# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
(0.x: minor bumps may break; **rule ids are stable from v0.1** — renaming one is
a breaking change).

## [Unreleased]

### Fixed

- **#46** — PEM fused markers are now redacted. When a private-key END
  trailer and the next BEGIN header are fused without a newline,
  sharing 5–9 dashes at the junction, the second block's body was
  left in cleartext: the #44 shared-dash guard
  (`dashes_before` + `preceded_by_private_key_end`) rejected the
  fused BEGIN on every pass. The guard is removed from both
  `confirm_pem_begin` and the reference oracle — a fused anchor now
  confirms on pass 1 and its body redacts like any other block.
  Idempotence is preserved by the existing `[CLOAK:` prefix guard:
  pass 1 always places the tag immediately after the BEGIN line
  (normal close, F05 bail-out, or EOF), so pass 2 sees the tag where
  the body was and skips the block. The whole-buffer scan backs up to
  the fused anchor at each block close (`fused_begin_backup`, mirrored
  in the oracle) and the streaming post-close context threshold is
  relaxed by the marker dash width so a fused anchor straddling the
  carry is confirmed without re-emitting the shared dashes. The #44-era
  backward-context machinery (confirm-decision memo, `PEM_BACK_WINDOW`
  retention pin) is retained as a stability aid only —
  `confirm_pem_begin` no longer reads backward bytes.
- **#50** — jwt idempotence vs PEM markers (post-#44 variant): the
  greedy third-segment (signature) scan consumed the head of an
  adjacent `-----END <type>` / `-----BEGIN ` marker — dashes and
  `B/D/E/G/I/N` are all base64url — erasing the trailer bytes the #44
  shared-dash guard reads, so pass 2 confirmed a fused BEGIN that
  pass 1 had rejected. The scan now rolls back a trailing dash run
  (≥5) plus `END`/`BEGIN` marker word — the entire run, keeping
  `dashes_before` counts pass-stable — with a loosened arm (run ≥1,
  partial word) when the scan ends exactly at the 2048-byte cap,
  which can cut the junction anywhere. Mirrored in the reference
  oracle. Same class deferred for gitlab-token / pypi-token /
  gcp-api-key / credit-card (follow-up issue).
- **#49** — PEM streaming ≢ whole-buffer on nested/garbled markers
  (post-#44 variant): when the emission boundary landed between two
  PEM anchors, the later candidate's shared-dash pin could flush the
  boundary into the earlier (rejected) candidate's backward guard
  window — `confirm_pem_begin`'s guards fail open on missing backward
  bytes, so the next scan confirmed a fused BEGIN the whole-buffer
  pass rejects. PEM confirm decisions are now memoized by absolute
  anchor offset at their first resolvable evaluation and reused on
  every re-scan, making boundary placement irrelevant to the confirm
  outcome; `max_window` is floored at the PEM confirm window plus
  `PEM_BACK_WINDOW` so that first evaluation always sees the full
  guard context.
- **#44** — PEM shared-dash idempotence: `confirm_pem_begin` counts
  the dash run before a BEGIN anchor. 1–4 dashes (junction of 6–9)
  or none with a `-----END <private-key type>` trailer right before
  (junction of exactly 5) are fused markers — rejected on every
  pass. Junctions of ≥10 dashes are independent markers and redact
  normally. Fused blocks (junction 5–9) stay unredacted: a strict
  RFC 7468 reader cannot extract them; extraction-resistance for
  malformed headers is a separate decision (#46 — since resolved
  above: fused markers now redact). Strict fuzz
  equivalences are unconditional in CI. Also fixed in this PR (both
  found by the strict gates): PEM candidates re-derived at the
  emission boundary confirmed against truncated backward context —
  the boundary is now pinned `PEM_BACK_WINDOW` bytes behind every
  retained candidate; and `finish_pem` hashed the final carry past
  `PEM_BAIL_OUT`, diverging the bail-out digest from the oracle.
- **#34** — idempotence restored: backward/forward tag guards reject
  candidates fused to `[CLOAK:…]` tags, and the phone-intl greedy
  separator scan falls back to the longest valid match when adjacent
  numeric content inflates the digit count past the E.164 maximum.
- **#27** — carry-over context loss resolved: retained-span re-injection
  and truncated-context guards ensure streaming and whole-buffer modes
  agree on dense inputs beyond `max_window`.

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
- ~~Two tracked engine bugs (#27, #34)~~ — both fixed in [Unreleased].
  ~~Strict fuzz equivalence checks remain opt-in
  (`CLOAK_FUZZ_STRICT=1`) until the PEM shared-dash idempotence bug
  ([#44](https://github.com/silverwalls-labs/cloak/issues/44)) is
  fixed.~~ — #44 fixed in [Unreleased]; strict is now unconditional.

[Unreleased]: https://github.com/silverwalls-labs/cloak/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/silverwalls-labs/cloak/releases/tag/v0.1.0
