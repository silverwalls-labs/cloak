# Ruleset — cloak v0.1

> Prev: [architecture](01-architecture.md) · Next: [guarantee & testing](03-guarantee-and-testing.md)

## Design stance

**Recall-first with tuned rules.** Every rule is anchored (literal prefix/infix) and,
where possible, checksum- or structure-validated. No heuristic or entropy-based
matching in v0.1 — a generic entropy rule is a false-positive machine that eats
trace IDs and base64 payloads, and over-redaction silently destroys log value.
(Entropy detector = opt-in follow-up, see [roadmap](05-roadmap.md#follow-ups-ledger).)

Rule requirements — every rule MUST:

1. Declare ≥ 1 **literal anchor** for the prefilter (keeps the clean path fast).
2. Ship a **positive vector suite** (real-shaped synthetic secrets that must match,
   including chunk-boundary splits) and a **negative vector suite** (near-misses that
   must NOT match: truncated keys, wrong checksums, look-alike IDs).
3. Define its **max match window** `W` (bounds the carry-over buffer) — or declare
   itself stateful (PEM) with an explicit bail-out length.
4. Be individually disableable via config (`[rules.<id>] enabled = false`).

All rules are **on by default** (recall-first). The FP-risk column below tells
operators which ones to consider disabling per environment.

## Secret detectors

| Rule id | Anchor(s) | Confirm | FP risk |
|---|---|---|---|
| `aws-access-key` | `AKIA`, `ASIA` | `(AKIA\|ASIA)[0-9A-Z]{16}` | Low |
| `aws-secret-key` | `aws_secret`, `SecretAccessKey` (context-keyed) | key-context + 40-char base64 value | Low-med |
| `gcp-api-key` | `AIza` | `AIza[0-9A-Za-z_-]{35}` | Low |
| `azure-style-token` | context keys (`accountkey=`, `sig=` in SAS) | context + base64/urlenc value shape | Med |
| `github-token` | `ghp_`, `gho_`, `ghs_`, `ghu_`, `ghr_`, `github_pat_` | prefix + `[0-9A-Za-z_]{36,}` (+ checksum where format defines one) | Low |
| `gitlab-token` | `glpat-`, `glrt-`, `gldt-` | prefix + `[0-9A-Za-z_-]{20,}` | Low |
| `npm-token` | `npm_` | `npm_[0-9A-Za-z]{36}` | Low |
| `pypi-token` | `pypi-` | `pypi-AgEIcHlwaS5vcmc…` (macaroon prefix) | Low |
| `jwt` | `eyJ` | three dot-separated base64url segments, first two decode-shaped as JSON (`{"` prefix after decode of header) | Low-med |
| `connection-string` | `://` (+ scheme set: `postgres`, `postgresql`, `mysql`, `mongodb`, `redis`, `amqp`, `amqps`…) | `scheme://user:PASSWORD@host` — only the password span is redacted | Low |
| `pem-private-key` | `-----BEGIN` | stateful: `-----BEGIN (RSA \|EC \|DSA \|OPENSSH \|ENCRYPTED \|)PRIVATE KEY-----` … `-----END …-----`, multi-line, bounded bail-out (default 16 KiB) | ~0 |

Notes:
- `connection-string` redacts **only the credential span**, not the whole URL — host
  and scheme are debugging signal.
- `pem-private-key` is the reason the engine has carry-over + a stateful mode; only
  the key material between BEGIN/END is replaced (single tag), markers stay visible.
- `aws-secret-key` and `azure-style-token` are **context-keyed** (value shape alone
  is just base64): anchor on the key name, redact the value. This is the agreed
  precision trade — a bare 40-char base64 string without context is NOT matched.

## Structured-PII detectors

| Rule id | Anchor(s) | Confirm | FP risk |
|---|---|---|---|
| `email` | `@` | RFC-5322-practical: `local@domain.tld`, TLD ≥ 2 alpha | Low |
| `ipv4` | `.` digit-runs (prefilter on dotted-quad shape) | 4 octets, each 0–255, non-digit boundaries | Med — redacting IPs can hurt debugging; disable per env if needed |
| `ipv6` | `::`, `:` hex-runs | bounded RFC-4291 grammar (incl. `::` compression, v4-mapped) | Med |
| `credit-card` | digit runs 13–19 (with optional space/dash groups) | **Luhn checksum** + known IIN ranges (4x, 5[1-5], 34/37, 6011…) | Low (Luhn kills most) |
| `phone-intl` | `+` | **anchored international format ONLY**: `+` CC (1–3 digits) + 6–12 digits with optional separators (E.164-ish) | Med-high |

Hard constraints (agreed in scoping, do not relax without a new decision):

- **`phone-intl` must never match bare 10-digit strings.** Domestic-format matching
  (order IDs, timestamps, numeric ranges all collide) is explicitly forbidden. `+`
  anchor is mandatory.
- `ipv4`/`ipv6` ship enabled (recall-first) but are the documented first candidates
  for per-environment disabling.

## Redaction format

```
[CLOAK:<rule-id>:<digest4>]
e.g.  [CLOAK:github-token:9f3a]
```

### Digest scheme

- `digest4` = first 4 hex chars (16 bits) of **BLAKE3 keyed hash** of the exact
  matched bytes.
- **Keyed per deployment**: key from `CLOAK_DIGEST_KEY` (env indirection in config).
  Without the key, digests cannot be brute-forced offline against candidate secrets.
  If no key is configured, cloak generates an ephemeral per-process key and warns —
  correlation then only holds within one process lifetime.
- Same secret ⇒ same digest (within a key domain): "one secret, 40 occurrences" is
  visible in Grafana without exposure. 16 bits is for correlation, not identity —
  collisions are acceptable and expected.
- `MatchEvent`/stats never carry matched plaintext. The digest is the only residue.

Per-rule output templates (mask-only, custom formats) are a follow-up; the tag format
above is the fixed v0.1 default.

## Catalog governance

- Rule ids are stable identifiers (config keys, stats keys, tag content) — renaming
  is a breaking change.
- New rules require: anchor(s), vectors (positive incl. split-across-chunks,
  negative), window `W` or stateful declaration, FP-risk assessment in this file.
- Test-vector corpora live beside the rules (`cloak-core/src/rules/vectors/`) and are
  reused verbatim by the differential and property tests
  ([03](03-guarantee-and-testing.md)) and the match-heavy benchmark corpus
  ([04](04-performance.md)).
