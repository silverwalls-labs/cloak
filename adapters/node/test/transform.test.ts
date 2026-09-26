/**
 * Transform stream tests — both Node.js classic and Web Streams API.
 */

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { Readable, Writable } from "node:stream";
import { pipeline } from "node:stream/promises";

import {
  createEngine,
  createCloakTransform,
  createCloakTransformStream,
  type CloakEngine,
} from "../src/index.ts";

// ── Helpers ────────────────────────────────────────────────────────

/** Collect all data from a readable stream into a single Buffer. */
function collect(stream: Readable): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    stream.on("data", (chunk: Buffer) => chunks.push(chunk));
    stream.on("end", () => resolve(Buffer.concat(chunks)));
    stream.on("error", reject);
  });
}

const DIRTY_INPUT = "token=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\n";
const CLEAN_INPUT = "hello world, nothing secret here\n";

// ── Node.js Transform ──────────────────────────────────────────────

describe("createCloakTransform", () => {
  let engine: CloakEngine;

  before(async () => {
    engine = await createEngine(undefined, {
      CLOAK_DIGEST_KEY: "test-key",
    });
  });

  after(() => engine?.dispose());

  it("redacts through a piped stream", async () => {
    const transform = createCloakTransform(engine);
    const source = Readable.from([Buffer.from(DIRTY_INPUT)]);

    const out = await collect(source.pipe(transform));
    const text = out.toString();

    assert.ok(
      text.includes("[CLOAK:github-token:"),
      `expected redaction, got: ${text}`,
    );
    assert.ok(
      !text.includes("ghp_"),
      "plaintext token must not appear in output",
    );
  });

  it("passes clean input through unchanged", async () => {
    const transform = createCloakTransform(engine);
    const source = Readable.from([Buffer.from(CLEAN_INPUT)]);

    const out = await collect(source.pipe(transform));
    assert.equal(out.toString(), CLEAN_INPUT);
  });

  it("handles multi-chunk input", async () => {
    const transform = createCloakTransform(engine);
    const chunks = [
      Buffer.from("tok"),
      Buffer.from("en=ghp_AbCdEfGhIjKl"),
      Buffer.from("MnOpQrStUvWxYz01232piBxe\ndone\n"),
    ];
    const source = Readable.from(chunks);

    const out = await collect(source.pipe(transform));
    const text = out.toString();

    assert.ok(
      text.includes("[CLOAK:github-token:"),
      `multi-chunk not redacted: ${text}`,
    );
  });

  it("works with pipeline()", async () => {
    const transform = createCloakTransform(engine);
    const source = Readable.from([Buffer.from(DIRTY_INPUT)]);
    const chunks: Buffer[] = [];
    const sink = new Writable({
      write(chunk: Buffer, _enc, cb) {
        chunks.push(chunk);
        cb();
      },
    });

    await pipeline(source, transform, sink);

    const text = Buffer.concat(chunks).toString();
    assert.ok(
      text.includes("[CLOAK:github-token:"),
      `pipeline output not redacted: ${text}`,
    );
  });
});

// ── Web TransformStream ────────────────────────────────────────────

describe("createCloakTransformStream", () => {
  let engine: CloakEngine;

  before(async () => {
    engine = await createEngine(undefined, {
      CLOAK_DIGEST_KEY: "test-key",
    });
  });

  after(() => engine?.dispose());

  it("redacts through pipeThrough", async () => {
    const transform = createCloakTransformStream(engine);

    const source = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(DIRTY_INPUT));
        controller.close();
      },
    });

    const reader = source.pipeThrough(transform).getReader();
    const chunks: Uint8Array[] = [];
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
    }

    const text = Buffer.concat(chunks).toString();
    assert.ok(
      text.includes("[CLOAK:github-token:"),
      `web stream not redacted: ${text}`,
    );
  });

  it("passes clean input through unchanged", async () => {
    const transform = createCloakTransformStream(engine);

    const source = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(CLEAN_INPUT));
        controller.close();
      },
    });

    const reader = source.pipeThrough(transform).getReader();
    const chunks: Uint8Array[] = [];
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
    }

    const text = Buffer.concat(chunks).toString();
    assert.equal(text, CLEAN_INPUT);
  });
});
