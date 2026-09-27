/**
 * Parity tests: every vector in the cloak-core corpus must produce
 * identical output when run through the WASM module from Node.js.
 *
 * Mirrors `crates/wasm-parity/tests/parity.rs` — same key material,
 * same vectors, same byte-exact assertion. The vectors are generated
 * from Rust via `cargo run --example export-vectors -p cloak-core`.
 */

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { createEngine, type CloakEngine } from "../src/index.ts";

// ── Constants ──────────────────────────────────────────────────────

/** Must match KEY_MATERIAL in export-vectors.rs and wasm-parity. */
const KEY_MATERIAL = "integration-test-key";

const CONFIG = {
  redaction: { digestKey: `env:CLOAK_DIGEST_KEY` },
} as const;

// ── Fixtures ───────────────────────────────────────────────────────

interface Vector {
  name: string;
  input: string; // hex
  expected: string; // hex
}

async function loadVectors(): Promise<Vector[]> {
  const thisDir = path.dirname(fileURLToPath(import.meta.url));
  const raw = await readFile(
    path.join(thisDir, "fixtures/vectors.json"),
    "utf-8",
  );
  return JSON.parse(raw) as Vector[];
}

// ── Tests ──────────────────────────────────────────────────────────

describe("parity — one-shot redact()", () => {
  let engine: CloakEngine;
  let vectors: Vector[];

  before(async () => {
    vectors = await loadVectors();
    engine = await createEngine(CONFIG, {
      CLOAK_DIGEST_KEY: KEY_MATERIAL,
    });
  });

  after(() => engine?.dispose());

  it("every vector produces byte-identical output", () => {
    for (const v of vectors) {
      const input = Buffer.from(v.input, "hex");
      const expected = Buffer.from(v.expected, "hex");
      const { output: actual } = engine.redact(input);

      assert.deepStrictEqual(
        actual,
        expected,
        `vector "${v.name}" output mismatch\n` +
          `  input:    ${input.toString()}\n` +
          `  got:      ${actual.toString()}\n` +
          `  expected: ${expected.toString()}`,
      );
    }
  });
});

describe("parity — streaming push+finish", () => {
  let engine: CloakEngine;
  let vectors: Vector[];

  before(async () => {
    vectors = await loadVectors();
    engine = await createEngine(CONFIG, {
      CLOAK_DIGEST_KEY: KEY_MATERIAL,
    });
  });

  after(() => engine?.dispose());

  it("every vector produces byte-identical output via session", () => {
    for (const v of vectors) {
      const input = Buffer.from(v.input, "hex");
      const expected = Buffer.from(v.expected, "hex");

      const session = engine.session();
      const pushed = session.push(input);
      const { output: flushed } = session.finish();
      const actual = Buffer.concat([pushed, flushed]);

      assert.deepStrictEqual(
        actual,
        expected,
        `vector "${v.name}" streaming mismatch\n` +
          `  input:    ${input.toString()}\n` +
          `  got:      ${actual.toString()}\n` +
          `  expected: ${expected.toString()}`,
      );
    }
  });
});

describe("parity — edge cases", () => {
  let engine: CloakEngine;

  before(async () => {
    engine = await createEngine(CONFIG, {
      CLOAK_DIGEST_KEY: KEY_MATERIAL,
    });
  });

  after(() => engine?.dispose());

  it("empty input produces empty output", () => {
    const { output } = engine.redact(Buffer.alloc(0));
    assert.equal(output.length, 0, "empty input should produce empty output");
  });

  it("clean input passes through unchanged", () => {
    const input = "hello world, no secrets here\n";
    const { output } = engine.redact(input);
    assert.equal(
      output.toString(),
      input,
      "clean input should pass through unchanged",
    );
  });

  it("string input accepted and redacted", () => {
    const input = "token=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";
    const { output } = engine.redact(input);
    assert.ok(
      output.toString().includes("[CLOAK:github-token:"),
      `string input not redacted: ${output.toString()}`,
    );
  });

  it("redact() returns stats", () => {
    const input = "token=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";
    const { stats } = engine.redact(input);
    assert.ok(stats.bytes_processed > 0, "bytes_processed should be > 0");
    assert.ok(
      stats.matches["github-token"] >= 1,
      "stats should report github-token match",
    );
  });
});
