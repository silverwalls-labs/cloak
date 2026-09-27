/**
 * Chunk-boundary invariant: split vector inputs at varying boundaries
 * and verify the WASM module produces identical output regardless of
 * chunking — same guarantee as cloak-core (docs/03).
 *
 * Mirrors `crates/wasm-parity/tests/streaming.rs`.
 */

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { createEngine, type CloakEngine } from "../src/index.ts";

// ── Constants ──────────────────────────────────────────────────────

const KEY_MATERIAL = "integration-test-key";
const CONFIG = {
  redaction: { digestKey: "env:CLOAK_DIGEST_KEY" },
} as const;

// ── Fixtures ───────────────────────────────────────────────────────

interface Vector {
  name: string;
  input: string;
  expected: string;
}

async function loadVectors(): Promise<Vector[]> {
  const thisDir = path.dirname(fileURLToPath(import.meta.url));
  const raw = await readFile(
    path.join(thisDir, "fixtures/vectors.json"),
    "utf-8",
  );
  return JSON.parse(raw) as Vector[];
}

// ── Helpers ────────────────────────────────────────────────────────

/**
 * Generate deterministic split points for a given input length and
 * seed. Returns 1–5 split points within [0, len).
 */
function splitPoints(len: number, seed: number): number[] {
  if (len === 0) return [];
  const count = (seed % 5) + 1;
  const points: number[] = [];
  for (let i = 0; i < count; i++) {
    points.push(((seed * (i + 7)) % len));
  }
  return [...new Set(points)].sort((a, b) => a - b);
}

// ── Tests ──────────────────────────────────────────────────────────

describe("streaming — chunk-boundary invariant", () => {
  let engine: CloakEngine;
  let vectors: Vector[];

  before(async () => {
    vectors = await loadVectors();
    engine = await createEngine(CONFIG, {
      CLOAK_DIGEST_KEY: KEY_MATERIAL,
    });
  });

  after(() => engine?.dispose());

  it("chunked push matches single-push for every vector", () => {
    for (const v of vectors) {
      const input = Buffer.from(v.input, "hex");
      if (input.length === 0) continue;

      // Baseline: one-shot redact.
      const { output: baseline } = engine.redact(input);

      // Chunked: split at multiple boundaries per vector.
      for (let seed = 0; seed < 10; seed++) {
        const points = splitPoints(input.length, seed);
        const session = engine.session();
        const parts: Buffer[] = [];

        let pos = 0;
        for (const split of points) {
          if (split > pos) {
            parts.push(session.push(input.subarray(pos, split)));
            pos = split;
          }
        }
        if (pos < input.length) {
          parts.push(session.push(input.subarray(pos)));
        }

        const { output: tail } = session.finish();
        parts.push(tail);

        const chunked = Buffer.concat(parts);
        assert.deepStrictEqual(
          chunked,
          baseline,
          `chunk-boundary divergence for vector "${v.name}" (seed=${seed})`,
        );
      }
    }
  });

  it("single-byte pushes produce same output", () => {
    // Take first 5 non-empty vectors for a thorough single-byte test.
    const samples = vectors.filter((v) => v.input.length > 0).slice(0, 5);

    for (const v of samples) {
      const input = Buffer.from(v.input, "hex");
      const { output: baseline } = engine.redact(input);

      const session = engine.session();
      const parts: Buffer[] = [];
      for (let i = 0; i < input.length; i++) {
        parts.push(session.push(input.subarray(i, i + 1)));
      }
      const { output: tail } = session.finish();
      parts.push(tail);

      const result = Buffer.concat(parts);
      assert.deepStrictEqual(
        result,
        baseline,
        `single-byte push divergence for vector "${v.name}"`,
      );
    }
  });
});
