# Security Policy

cloak is a redaction tool: its failure modes are security incidents for its
users. Suspected vulnerabilities are handled privately.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ |

## Reporting a vulnerability

**Do not open a public issue for a suspected vulnerability.**

Report privately via
[GitHub private vulnerability reporting](https://github.com/silverwalls-labs/cloak/security/advisories/new)
("Report a vulnerability" on the repository's Security tab). Include a minimal
reproducer where possible: input bytes (or a generator), config, chunking, and
the observed vs expected output.

- **Acknowledgement:** within 3 business days.
- **Coordinated disclosure:** we aim to ship a fix and publish an advisory
  within 90 days; we'll keep you updated and credit you unless you prefer
  otherwise.

## What counts as a vulnerability here

- **Guarantee violation** — input matching an *enabled* rule's specification
  passes through unredacted under any chunking or encoding covered by
  [the contract](docs/03-guarantee-and-testing.md#the-contract-precisely).
- **Plaintext leakage through side channels** — matched secret bytes escaping
  via digests, stats, warnings, error messages, or panics.
- **Resource-exhaustion on adversarial input** — unbounded memory (the engine
  promises O(W) carry-over) or non-termination.
- **Digest-key handling flaws** — key material logged, inline keys accepted,
  weak key derivation.

## Out of scope

- Secrets whose shape no enabled rule expresses — the guarantee is
  ruleset-relative by design
  ([what the guarantee is NOT](docs/03-guarantee-and-testing.md#what-the-guarantee-is-not)).
- Documented limitations: the escaped-content gap (ledger F11) and the publicly
  tracked engine bugs
  ([#27](https://github.com/silverwalls-labs/cloak/issues/27),
  [#34](https://github.com/silverwalls-labs/cloak/issues/34)).
- The repository's test vectors: they are **synthetic** tokens with valid
  checksums, not real credentials (see `.github/secret_scanning.yml`).
  New-rule proposals and false-positive reports are regular issues, not
  vulnerabilities.
